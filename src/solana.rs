//! Solana payment backend, JSON-RPC client, and Solana Pay URI builder.
#![allow(dead_code, clippy::allow_attributes)]

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use reqwest::Client as HttpClient;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;

use crate::backend::PaymentBackend;
use crate::coin::Coin;
use crate::error::PaymentError;
use crate::store::PaymentStore;
use crate::types::{Health, NewSubaddress, Transfer};

/// Generate a cryptographically random 32-byte Ed25519 reference key encoded in Base58.
pub fn generate_solana_reference() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bs58::encode(bytes).into_string()
}

/// Build a standard Solana Pay payment URI according to the Solana Pay specification.
///
/// If `spl_token` is `None`, standard SOL payment URI is generated:
/// `solana:<recipient>?amount=<amount>&reference=<reference>&label=<label>`
///
/// If `spl_token` is `Some(mint)`, SPL token payment URI is generated:
/// `solana:<recipient>?amount=<amount>&spl-token=<spl_token>&reference=<reference>&label=<label>`
pub fn build_solana_pay_url(
    recipient: &str,
    amount: f64,
    reference: &str,
    spl_token: Option<&str>,
    label: &str,
) -> String {
    let mut params = Vec::new();
    if amount > 0.0 {
        params.push(format!("amount={amount}"));
    }
    if let Some(spl) = spl_token {
        params.push(format!("spl-token={spl}"));
    }
    params.push(format!("reference={reference}"));
    params.push(format!("label={label}"));

    if params.is_empty() {
        format!("solana:{recipient}")
    } else {
        format!("solana:{recipient}?{}", params.join("&"))
    }
}

/// Extract the base58 reference key parameter from a Solana Pay URI or query string.
pub fn extract_reference_param(uri: &str) -> Option<String> {
    let query = if let Some((_base, q)) = uri.split_once('?') {
        q
    } else {
        uri
    };
    for pair in query.split('&') {
        if let Some(val) = pair.strip_prefix("reference=") {
            let val = val.split('#').next().unwrap_or(val);
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// Parsed Solana transaction envelope returned by `getTransaction` with `encoding: "json"`.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code, clippy::allow_attributes)]
pub struct SolanaParsedTransaction {
    #[serde(default)]
    pub slot: u64,
    pub block_time: Option<i64>,
    #[serde(default)]
    pub meta: SolanaTransactionMeta,
    #[serde(default)]
    pub transaction: SolanaTransactionData,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code, clippy::allow_attributes)]
pub struct SolanaTransactionMeta {
    pub err: Option<serde_json::Value>,
    #[serde(default)]
    pub pre_balances: Vec<u64>,
    #[serde(default)]
    pub post_balances: Vec<u64>,
    #[serde(default)]
    pub pre_token_balances: Vec<SolanaTokenBalance>,
    #[serde(default)]
    pub post_token_balances: Vec<SolanaTokenBalance>,
    pub loaded_addresses: Option<SolanaLoadedAddresses>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code, clippy::allow_attributes)]
pub struct SolanaLoadedAddresses {
    #[serde(default)]
    pub writable: Vec<String>,
    #[serde(default)]
    pub readonly: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code, clippy::allow_attributes)]
pub struct SolanaTokenBalance {
    #[serde(default)]
    pub account_index: usize,
    pub mint: String,
    pub owner: Option<String>,
    #[serde(default)]
    pub ui_token_amount: SolanaUiTokenAmount,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code, clippy::allow_attributes)]
pub struct SolanaUiTokenAmount {
    #[serde(default)]
    pub amount: String,
    pub decimals: Option<u8>,
    pub ui_amount: Option<f64>,
    pub ui_amount_string: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code, clippy::allow_attributes)]
pub struct SolanaTransactionData {
    #[serde(default)]
    pub message: SolanaTransactionMessage,
    #[serde(default)]
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code, clippy::allow_attributes)]
pub struct SolanaTransactionMessage {
    #[serde(default, deserialize_with = "deserialize_account_keys")]
    pub account_keys: Vec<String>,
}

fn deserialize_account_keys<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum KeyOrObj {
        Str(String),
        Obj { pubkey: String },
    }
    let list = Vec::<KeyOrObj>::deserialize(deserializer)?;
    Ok(list
        .into_iter()
        .map(|k| match k {
            KeyOrObj::Str(s) => s,
            KeyOrObj::Obj { pubkey } => pubkey,
        })
        .collect())
}

impl SolanaParsedTransaction {
    /// Compute the net lamport balance delta for `address`.
    /// Returns 0 if the transaction failed with an error, or if post <= pre.
    #[allow(dead_code, clippy::allow_attributes)]
    pub fn native_balance_delta_for(&self, address: &str) -> u64 {
        if self.meta.err.is_some() {
            return 0;
        }
        let pos = self
            .transaction
            .message
            .account_keys
            .iter()
            .chain(
                self.meta
                    .loaded_addresses
                    .as_ref()
                    .map(|l| l.writable.iter())
                    .into_iter()
                    .flatten(),
            )
            .chain(
                self.meta
                    .loaded_addresses
                    .as_ref()
                    .map(|l| l.readonly.iter())
                    .into_iter()
                    .flatten(),
            )
            .position(|k| k == address);

        let Some(idx) = pos else {
            return 0;
        };
        let pre = self.meta.pre_balances.get(idx).copied().unwrap_or(0);
        let post = self.meta.post_balances.get(idx).copied().unwrap_or(0);
        post.saturating_sub(pre)
    }

    /// Compute the net SPL token atomic amount delta for a given `mint` and `owner`.
    /// Returns 0 if the transaction failed with an error, or if post <= pre.
    #[allow(dead_code, clippy::allow_attributes)]
    pub fn spl_token_balance_delta_for(&self, mint: &str, owner: &str) -> u64 {
        if self.meta.err.is_some() {
            return 0;
        }
        let is_match = |b: &SolanaTokenBalance| {
            if b.mint != mint {
                return false;
            }
            if b.owner.as_deref() == Some(owner) {
                return true;
            }
            let acc_key = self
                .transaction
                .message
                .account_keys
                .get(b.account_index)
                .map(|s| s.as_str());
            acc_key == Some(owner)
        };

        let post_amount: u64 = self
            .meta
            .post_token_balances
            .iter()
            .filter(|b| is_match(b))
            .map(|b| b.ui_token_amount.amount.parse::<u64>().unwrap_or(0))
            .sum();

        let pre_amount: u64 = self
            .meta
            .pre_token_balances
            .iter()
            .filter(|b| is_match(b))
            .map(|b| b.ui_token_amount.amount.parse::<u64>().unwrap_or(0))
            .sum();

        post_amount.saturating_sub(pre_amount)
    }
}

#[derive(Debug)]
struct SolanaClientState {
    on_primary: bool,
    primary_fail_streak: u32,
    primary_ok_streak: u32,
    active_remote_index: usize,
}

#[derive(Deserialize)]
struct RpcEnvelope {
    result: Option<serde_json::Value>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    #[allow(dead_code, clippy::allow_attributes)]
    code: Option<i64>,
    message: String,
}

/// Multi-remote Solana JSON-RPC client with sequential failover and hysteresis.
pub struct MultiRemoteSolanaClient {
    http: HttpClient,
    primary_url: String,
    remotes: Vec<String>,
    to_fallback_after: u32,
    to_primary_after: u32,
    state: Mutex<SolanaClientState>,
}

impl MultiRemoteSolanaClient {
    pub fn new(
        primary_url: String,
        remotes: Vec<String>,
        to_fallback_after: u32,
        to_primary_after: u32,
    ) -> Self {
        let http = HttpClient::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| HttpClient::new());
        Self {
            http,
            primary_url,
            remotes,
            to_fallback_after,
            to_primary_after,
            state: Mutex::new(SolanaClientState {
                on_primary: true,
                primary_fail_streak: 0,
                primary_ok_streak: 0,
                active_remote_index: 0,
            }),
        }
    }

    /// Single probe check for an RPC URL using `getSlot`.
    async fn probe_url(&self, url: &str) -> bool {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSlot",
            "params": [{ "commitment": "confirmed" }]
        });
        match self.http.post(url).json(&body).send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    return false;
                }
                match resp.json::<RpcEnvelope>().await {
                    Ok(env) => match env.result {
                        Some(serde_json::Value::Null) | None => false,
                        Some(_) => env.error.is_none(),
                    },
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }

    /// Refresh failover status: probe primary and switch/advance remotes as appropriate.
    pub async fn refresh_source(&self) -> Health {
        let primary_ok = self.probe_url(&self.primary_url).await;
        let mut s = self.state.lock().await;
        if primary_ok {
            s.primary_ok_streak += 1;
            s.primary_fail_streak = 0;
            if !s.on_primary && s.primary_ok_streak >= self.to_primary_after {
                s.on_primary = true;
                s.active_remote_index = 0;
                metrics::counter!("detection_source_switch_total", "coin" => "solana").increment(1);
                eprintln!("payments[solana]: detection source -> primary node");
            }
        } else {
            s.primary_fail_streak += 1;
            s.primary_ok_streak = 0;
            if s.on_primary
                && s.primary_fail_streak >= self.to_fallback_after
                && !self.remotes.is_empty()
            {
                s.on_primary = false;
                // Sequentially probe remotes to find the first healthy remote
                let mut found_healthy = false;
                for (idx, remote_url) in self.remotes.iter().enumerate() {
                    if self.probe_url(remote_url).await {
                        s.active_remote_index = idx;
                        found_healthy = true;
                        break;
                    }
                }
                if !found_healthy {
                    s.active_remote_index = 0;
                }
                metrics::counter!("detection_source_switch_total", "coin" => "solana").increment(1);
                eprintln!(
                    "payments[solana]: detection source -> remote [{}] {}",
                    s.active_remote_index, self.remotes[s.active_remote_index]
                );
            }
        }

        metrics::gauge!("detection_source", "coin" => "solana").set(if s.on_primary {
            0.0
        } else {
            1.0
        });

        if s.on_primary {
            if primary_ok {
                Health::Healthy
            } else {
                Health::Unreachable
            }
        } else {
            if self.remotes.is_empty() {
                return Health::Unreachable;
            }
            let active_idx = s.active_remote_index;
            let remote_url = &self.remotes[active_idx];
            if self.probe_url(remote_url).await {
                Health::Healthy
            } else {
                // Active remote failed, sequentially probe the other remotes
                let mut new_idx = None;
                for offset in 1..self.remotes.len() {
                    let probe_idx = (active_idx + offset) % self.remotes.len();
                    if self.probe_url(&self.remotes[probe_idx]).await {
                        new_idx = Some(probe_idx);
                        break;
                    }
                }
                if let Some(next_idx) = new_idx {
                    s.active_remote_index = next_idx;
                    eprintln!(
                        "payments[solana]: remote failover -> remote [{}] {}",
                        next_idx, self.remotes[next_idx]
                    );
                    Health::Healthy
                } else {
                    Health::Unreachable
                }
            }
        }
    }

    #[allow(dead_code, clippy::allow_attributes)]
    pub async fn health(&self) -> Health {
        self.refresh_source().await
    }

    async fn rpc_value(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<Option<serde_json::Value>, PaymentError> {
        let (on_primary, active_remote) = {
            let s = self.state.lock().await;
            (s.on_primary, s.active_remote_index)
        };

        let mut urls_to_try = Vec::new();
        if on_primary {
            urls_to_try.push((true, 0, self.primary_url.clone()));
            for (idx, r) in self.remotes.iter().enumerate() {
                urls_to_try.push((false, idx, r.clone()));
            }
        } else {
            if !self.remotes.is_empty() {
                let start = active_remote % self.remotes.len();
                for i in 0..self.remotes.len() {
                    let idx = (start + i) % self.remotes.len();
                    urls_to_try.push((false, idx, self.remotes[idx].clone()));
                }
            }
            urls_to_try.push((true, 0, self.primary_url.clone()));
        }

        let mut last_err = PaymentError::Rpc("solana rpc: no endpoints available".to_owned());
        for (is_pri, idx, url) in urls_to_try {
            match self.send_rpc(&url, method, &params).await {
                Ok(result) => {
                    let mut s = self.state.lock().await;
                    if is_pri && !s.on_primary {
                        s.on_primary = true;
                        s.active_remote_index = 0;
                    } else if !is_pri && (s.on_primary || s.active_remote_index != idx) {
                        s.on_primary = false;
                        s.active_remote_index = idx;
                    }
                    return Ok(result);
                }
                Err(e) => {
                    last_err = e;
                }
            }
        }
        Err(last_err)
    }

    async fn send_rpc(
        &self,
        url: &str,
        method: &str,
        params: &serde_json::Value,
    ) -> Result<Option<serde_json::Value>, PaymentError> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp = self
            .http
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|e| PaymentError::Rpc(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(PaymentError::Rpc(format!("HTTP status {}", resp.status())));
        }
        let envelope: RpcEnvelope = resp
            .json()
            .await
            .map_err(|e| PaymentError::Rpc(e.to_string()))?;
        if let Some(err) = envelope.error {
            return Err(PaymentError::Rpc(err.message));
        }
        match envelope.result {
            Some(serde_json::Value::Null) | None => Ok(None),
            Some(v) => Ok(Some(v)),
        }
    }

    /// Query current slot height from the Solana cluster.
    #[allow(dead_code, clippy::allow_attributes)]
    pub async fn get_slot(&self) -> Result<u64, PaymentError> {
        let val = self
            .rpc_value("getSlot", json!([{ "commitment": "confirmed" }]))
            .await?
            .ok_or_else(|| PaymentError::Rpc("empty result for getSlot".into()))?;
        serde_json::from_value::<u64>(val)
            .map_err(|e| PaymentError::Rpc(format!("failed to parse slot: {e}")))
    }

    /// Query recent transaction signatures that referenced `reference`.
    #[allow(dead_code, clippy::allow_attributes)]
    pub async fn get_signatures_for_address(
        &self,
        reference: &str,
        commitment: &str,
    ) -> Result<Vec<String>, PaymentError> {
        let params = json!([
            reference,
            {
                "commitment": commitment,
                "limit": 10
            }
        ]);
        let Some(val) = self.rpc_value("getSignaturesForAddress", params).await? else {
            return Ok(Vec::new());
        };
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum SignatureItem {
            Object { signature: String },
            String(String),
        }
        let items: Vec<SignatureItem> = serde_json::from_value(val)
            .map_err(|e| PaymentError::Rpc(format!("failed to parse signatures: {e}")))?;
        Ok(items
            .into_iter()
            .map(|item| match item {
                SignatureItem::Object { signature } => signature,
                SignatureItem::String(sig) => sig,
            })
            .collect())
    }

    /// Fetch and parse a confirmed transaction by signature.
    /// Returns `Ok(None)` if the transaction was not found.
    #[allow(dead_code, clippy::allow_attributes)]
    pub async fn get_transaction(
        &self,
        signature: &str,
        commitment: &str,
    ) -> Result<Option<SolanaParsedTransaction>, PaymentError> {
        let params = json!([
            signature,
            {
                "encoding": "json",
                "commitment": commitment,
                "maxSupportedTransactionVersion": 0
            }
        ]);
        let Some(val) = self.rpc_value("getTransaction", params).await? else {
            return Ok(None);
        };
        let tx = serde_json::from_value::<SolanaParsedTransaction>(val)
            .map_err(|e| PaymentError::Rpc(format!("failed to parse transaction: {e}")))?;
        Ok(Some(tx))
    }

    #[allow(dead_code, clippy::allow_attributes)]
    pub async fn on_primary(&self) -> bool {
        self.state.lock().await.on_primary
    }

    #[allow(dead_code, clippy::allow_attributes)]
    pub async fn active_remote_index(&self) -> usize {
        self.state.lock().await.active_remote_index
    }

    #[allow(dead_code, clippy::allow_attributes)]
    pub async fn current_endpoint(&self) -> String {
        let s = self.state.lock().await;
        if s.on_primary || self.remotes.is_empty() {
            self.primary_url.clone()
        } else {
            self.remotes[s.active_remote_index].clone()
        }
    }
}

/// Watch-only Solana payment wallet supporting native SOL and SPL tokens.
pub struct SolanaWallet {
    client: Arc<MultiRemoteSolanaClient>,
    recipient_address: String,
    coin: Coin,
    spl_mint: Option<String>,
    min_confirmations: u64,
    store: Arc<dyn PaymentStore>,
}

impl SolanaWallet {
    pub fn new_native(
        client: Arc<MultiRemoteSolanaClient>,
        recipient_address: String,
        coin: Coin,
        min_confirmations: u64,
        store: Arc<dyn PaymentStore>,
    ) -> Self {
        Self {
            client,
            recipient_address,
            coin,
            spl_mint: None,
            min_confirmations,
            store,
        }
    }

    pub fn new_native_with_store(
        client: Arc<MultiRemoteSolanaClient>,
        recipient_address: String,
        coin: Coin,
        min_confirmations: u64,
        store: Arc<dyn PaymentStore>,
    ) -> Self {
        Self::new_native(client, recipient_address, coin, min_confirmations, store)
    }

    pub fn new_spl(
        client: Arc<MultiRemoteSolanaClient>,
        recipient_address: String,
        coin: Coin,
        spl_mint: String,
        min_confirmations: u64,
        store: Arc<dyn PaymentStore>,
    ) -> Self {
        Self {
            client,
            recipient_address,
            coin,
            spl_mint: Some(spl_mint),
            min_confirmations,
            store,
        }
    }

    pub fn new_spl_with_store(
        client: Arc<MultiRemoteSolanaClient>,
        recipient_address: String,
        coin: Coin,
        spl_mint: String,
        min_confirmations: u64,
        store: Arc<dyn PaymentStore>,
    ) -> Self {
        Self::new_spl(
            client,
            recipient_address,
            coin,
            spl_mint,
            min_confirmations,
            store,
        )
    }

    pub fn coin_name(&self) -> &str {
        self.coin.as_str()
    }

    pub fn client(&self) -> &Arc<MultiRemoteSolanaClient> {
        &self.client
    }

    pub fn recipient_address(&self) -> &str {
        &self.recipient_address
    }

    pub fn spl_mint(&self) -> Option<&str> {
        self.spl_mint.as_deref()
    }
}

#[async_trait]
impl PaymentBackend for SolanaWallet {
    async fn new_subaddress(&self, _label: &str) -> Result<NewSubaddress, PaymentError> {
        let reference = generate_solana_reference();
        let solana_pay_url = build_solana_pay_url(
            &self.recipient_address,
            0.0,
            &reference,
            self.spl_mint.as_deref(),
            "socks.cat",
        );
        Ok(NewSubaddress {
            address: solana_pay_url,
            index: 0,
        })
    }

    async fn incoming_transfers(&self, _min_height: u64) -> Result<Vec<Transfer>, PaymentError> {
        self.client.refresh_source().await;

        let mut addresses = self.store.open_addresses(self.coin_name()).await?;
        if self.coin_name() == "sol" {
            if let Ok(extra) = self.store.open_addresses("solana").await {
                for a in extra {
                    if !addresses.contains(&a) {
                        addresses.push(a);
                    }
                }
            }
        }

        if addresses.is_empty() {
            return Ok(Vec::new());
        }

        let commitment = if self.min_confirmations >= 32 {
            "finalized"
        } else {
            "confirmed"
        };
        let current_slot = self.client.get_slot().await.unwrap_or(0);

        let quote_tasks = addresses.into_iter().filter_map(|stored_address| {
            let reference = extract_reference_param(&stored_address)?;
            // Validate that reference decodes to a valid 32-byte Ed25519 public key.
            // This prevents malformed/stale references from triggering RPC WrongSize errors.
            if let Ok(bytes) = bs58::decode(&reference).into_vec() {
                if bytes.len() != 32 {
                    return None;
                }
            } else {
                return None;
            }
            Some((stored_address, reference))
        });

        let futures = quote_tasks.into_iter().map(|(stored_address, reference)| {
            let client = Arc::clone(&self.client);
            let coin = self.coin_name().to_string();
            let spl_mint = self.spl_mint.clone();
            let recipient = self.recipient_address.clone();
            async move {
                let signatures = match client
                    .get_signatures_for_address(&reference, commitment)
                    .await
                {
                    Ok(sigs) => sigs,
                    Err(e) => {
                        eprintln!(
                            "payments[{coin}]: get_signatures_for_address({reference}) failed: {e}"
                        );
                        return Vec::new();
                    }
                };

                let mut transfers = Vec::new();
                for signature in signatures {
                    let tx = match client.get_transaction(&signature, commitment).await {
                        Ok(Some(tx)) => tx,
                        Ok(None) => continue,
                        Err(e) => {
                            eprintln!("payments[{coin}]: get_transaction({signature}) failed: {e}");
                            continue;
                        }
                    };

                    let delta = match &spl_mint {
                        Some(mint) => tx.spl_token_balance_delta_for(mint, &recipient),
                        None => tx.native_balance_delta_for(&recipient),
                    };

                    if delta > 0 {
                        let confs = if current_slot >= tx.slot {
                            current_slot - tx.slot + 1
                        } else {
                            1
                        };
                        transfers.push(Transfer {
                            txid: signature,
                            amount_atomic: delta,
                            address: stored_address.clone(),
                            height: tx.slot,
                            confirmations: confs,
                        });
                    }
                }
                transfers
            }
        });

        let results = futures::future::join_all(futures).await;
        let mut transfers = Vec::new();
        let mut seen_signatures = HashSet::new();
        for list in results {
            for transfer in list {
                if seen_signatures.insert(transfer.txid.clone()) {
                    transfers.push(transfer);
                }
            }
        }

        Ok(transfers)
    }

    async fn balance_atomic(&self) -> Result<Option<i64>, PaymentError> {
        Ok(None)
    }

    async fn health(&self) -> Health {
        self.client.health().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coin::SplTokenMeta;
    use crate::store::MockPaymentStore;

    #[test]
    fn test_generate_solana_reference_valid_base58() {
        let ref_key = generate_solana_reference();
        let decoded = bs58::decode(&ref_key).into_vec().expect("valid base58");
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_build_solana_pay_url() {
        let native_url = build_solana_pay_url(
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
            1.23456789,
            "4fYNw3dojWmQ4dFuTGcgPcvYJ8jUGe5hX427k9GgBwB",
            None,
            "socks.cat",
        );
        assert_eq!(
            native_url,
            "solana:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU?amount=1.23456789&reference=4fYNw3dojWmQ4dFuTGcgPcvYJ8jUGe5hX427k9GgBwB&label=socks.cat"
        );

        let spl_url = build_solana_pay_url(
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
            50.0,
            "4fYNw3dojWmQ4dFuTGcgPcvYJ8jUGe5hX427k9GgBwB",
            Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
            "socks.cat",
        );
        assert_eq!(
            spl_url,
            "solana:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU?amount=50&spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v&reference=4fYNw3dojWmQ4dFuTGcgPcvYJ8jUGe5hX427k9GgBwB&label=socks.cat"
        );

        let native_url_zero = build_solana_pay_url(
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
            0.0,
            "4fYNw3dojWmQ4dFuTGcgPcvYJ8jUGe5hX427k9GgBwB",
            None,
            "socks.cat",
        );
        assert_eq!(
            native_url_zero,
            "solana:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU?reference=4fYNw3dojWmQ4dFuTGcgPcvYJ8jUGe5hX427k9GgBwB&label=socks.cat"
        );

        let spl_url_zero = build_solana_pay_url(
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
            -1.0,
            "4fYNw3dojWmQ4dFuTGcgPcvYJ8jUGe5hX427k9GgBwB",
            Some("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
            "socks.cat",
        );
        assert_eq!(
            spl_url_zero,
            "solana:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU?spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v&reference=4fYNw3dojWmQ4dFuTGcgPcvYJ8jUGe5hX427k9GgBwB&label=socks.cat"
        );
    }

    #[test]
    fn test_parse_solana_native_transaction_balance_delta() {
        let tx_json = r#"{
            "slot": 123456,
            "meta": {
                "err": null,
                "preBalances": [1000000000, 5000000000],
                "postBalances": [995000000, 5005000000]
            },
            "transaction": {
                "message": {
                    "accountKeys": [
                        "Sender111111111111111111111111111111111111111",
                        "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
                    ]
                }
            }
        }"#;
        let tx: SolanaParsedTransaction = serde_json::from_str(tx_json).unwrap();
        assert!(tx.meta.err.is_none());
        let delta = tx.native_balance_delta_for("7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU");
        assert_eq!(delta, 5_000_000); // 0.005 SOL
    }

    #[test]
    fn test_parse_solana_spl_transaction_balance_delta() {
        let tx_json = r#"{
            "slot": 123456,
            "meta": {
                "err": null,
                "preBalances": [1000000000],
                "postBalances": [995000000],
                "preTokenBalances": [
                    {
                        "accountIndex": 1,
                        "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                        "owner": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                        "uiTokenAmount": { "amount": "10000000" }
                    }
                ],
                "postTokenBalances": [
                    {
                        "accountIndex": 1,
                        "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                        "owner": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
                        "uiTokenAmount": { "amount": "60000000" }
                    }
                ]
            },
            "transaction": {
                "message": {
                    "accountKeys": ["Sender"]
                }
            }
        }"#;
        let tx: SolanaParsedTransaction = serde_json::from_str(tx_json).unwrap();
        let delta = tx.spl_token_balance_delta_for(
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
        );
        assert_eq!(delta, 50_000_000); // 50.000000 USDC
    }

    async fn spawn_mock_solana_node(
        responses: std::sync::Arc<std::sync::atomic::AtomicBool>,
        slot: u64,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let responses = std::sync::Arc::clone(&responses);
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 4096];
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if !responses.load(std::sync::atomic::Ordering::SeqCst) {
                            let resp =
                                "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
                            let _ = stream.write_all(resp.as_bytes()).await;
                            break;
                        }

                        let body_str = String::from_utf8_lossy(&buf[..n]);
                        let resp_body = if body_str.contains("getSignaturesForAddress") {
                            let sig = if body_str
                                .contains("4fYNw3dojWmQ4dFuTGcgPcvYJ8jUGe5hX427k9GgBwB")
                            {
                                "sig123".to_string()
                            } else if let Some(val) =
                                body_str.split('"').find(|s| s.len() >= 32 && s.len() <= 44)
                            {
                                format!("sig_{val}")
                            } else {
                                "sig123".to_string()
                            };
                            format!(
                                r#"{{"jsonrpc":"2.0","id":1,"result":[{{"signature":"{sig}","slot":123}}]}}"#
                            )
                        } else if body_str.contains("getTransaction") {
                            r#"{"jsonrpc":"2.0","id":1,"result":{"slot":123,"meta":{"err":null,"preBalances":[1000000000,5000000000],"postBalances":[995000000,5005000000],"preTokenBalances":[{"accountIndex":1,"mint":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","owner":"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU","uiTokenAmount":{"amount":"10000000"}}],"postTokenBalances":[{"accountIndex":1,"mint":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v","owner":"7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU","uiTokenAmount":{"amount":"60000000"}}]},"transaction":{"message":{"accountKeys":["Sender","7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"]}}}}"#
                                .to_string()
                        } else {
                            format!(r#"{{"jsonrpc":"2.0","id":1,"result":{slot}}}"#)
                        };

                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            resp_body.len(),
                            resp_body
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                    }
                });
            }
        });
        (url, handle)
    }

    #[tokio::test]
    async fn test_multi_remote_solana_client_mock_rpc_and_failover() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let primary_ok = Arc::new(AtomicBool::new(true));
        let remote1_ok = Arc::new(AtomicBool::new(true));
        let remote2_ok = Arc::new(AtomicBool::new(true));

        let (primary_url, _h0) = spawn_mock_solana_node(Arc::clone(&primary_ok), 100).await;
        let (remote1_url, _h1) = spawn_mock_solana_node(Arc::clone(&remote1_ok), 200).await;
        let (remote2_url, _h2) = spawn_mock_solana_node(Arc::clone(&remote2_ok), 300).await;

        let client = MultiRemoteSolanaClient::new(
            primary_url,
            vec![remote1_url, remote2_url],
            2, // to_fallback_after
            2, // to_primary_after
        );

        // Initially healthy on primary
        assert_eq!(client.refresh_source().await, Health::Healthy);
        assert!(client.on_primary().await);
        assert_eq!(client.get_slot().await.unwrap(), 100);

        // Signatures query
        let sigs = client
            .get_signatures_for_address("4fYNw3dojWmQ4dFuTGcgPcvYJ8jUGe5hX427k9GgBwB", "confirmed")
            .await
            .unwrap();
        assert_eq!(sigs, vec!["sig123"]);

        // Transaction query
        let tx = client.get_transaction("sig123", "confirmed").await.unwrap();
        assert!(tx.is_some());
        assert_eq!(tx.unwrap().slot, 123);

        // Primary fails: probe 1 of 2 -> still on primary due to hysteresis
        primary_ok.store(false, Ordering::SeqCst);
        let _ = client.refresh_source().await;
        assert!(client.on_primary().await);

        // Primary fails: probe 2 of 2 -> fails over to remote 0
        let health = client.refresh_source().await;
        assert_eq!(health, Health::Healthy);
        assert!(!client.on_primary().await);
        assert_eq!(client.active_remote_index().await, 0);
        assert_eq!(client.get_slot().await.unwrap(), 200);

        // Remote 0 fails -> advances sequentially to remote 1
        remote1_ok.store(false, Ordering::SeqCst);
        let health = client.refresh_source().await;
        assert_eq!(health, Health::Healthy);
        assert!(!client.on_primary().await);
        assert_eq!(client.active_remote_index().await, 1);
        assert_eq!(client.get_slot().await.unwrap(), 300);

        // Primary recovers: probe 1 of 2 -> still on remote due to hysteresis
        primary_ok.store(true, Ordering::SeqCst);
        let _ = client.refresh_source().await;
        assert!(!client.on_primary().await);

        // Primary recovers: probe 2 of 2 -> swings back to primary
        let health = client.refresh_source().await;
        assert_eq!(health, Health::Healthy);
        assert!(client.on_primary().await);
        assert_eq!(client.active_remote_index().await, 0);
        assert_eq!(client.get_slot().await.unwrap(), 100);
    }

    #[tokio::test]
    async fn test_solana_wallet_new_subaddress_returns_solana_pay_uri() {
        let store = Arc::new(MockPaymentStore::new());
        let client = Arc::new(MultiRemoteSolanaClient::new(
            "https://api.mainnet-beta.solana.com".into(),
            vec![],
            3,
            3,
        ));
        let wallet = SolanaWallet::new_native(
            client,
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".into(),
            Coin::Solana,
            1,
            store,
        );
        let sub = wallet
            .new_subaddress("order-123")
            .await
            .expect("new_subaddress");
        assert!(sub
            .address
            .starts_with("solana:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU?"));
        assert!(sub.address.contains("reference="));
    }

    #[tokio::test]
    async fn test_solana_wallet_new_subaddress_spl_returns_solana_pay_uri() {
        let store = Arc::new(MockPaymentStore::new());
        let client = Arc::new(MultiRemoteSolanaClient::new(
            "https://api.mainnet-beta.solana.com".into(),
            vec![],
            3,
            3,
        ));
        let wallet = SolanaWallet::new_spl(
            client,
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".into(),
            Coin::SplToken(Arc::new(SplTokenMeta {
                coin: "usdc-sol".into(),
                symbol: "usdc".into(),
                display_name: "USDC (Solana)".into(),
                network_badge: "SPL".into(),
                mint_address: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
                decimals: 6,
                is_stable: true,
            })),
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
            1,
            store,
        );
        let sub = wallet
            .new_subaddress("order-456")
            .await
            .expect("new_subaddress");
        assert!(sub
            .address
            .starts_with("solana:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU?"));
        assert!(sub
            .address
            .contains("spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"));
        assert!(sub.address.contains("&reference="));
    }

    #[test]
    fn test_extract_reference_param() {
        assert_eq!(
            extract_reference_param("solana:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU?amount=0&reference=4fYNw3dojWmQ4dFuTGcgPcvYJ8jUGe5hX427k9GgBwB&label=socks.cat"),
            Some("4fYNw3dojWmQ4dFuTGcgPcvYJ8jUGe5hX427k9GgBwB".to_string())
        );
        assert_eq!(
            extract_reference_param(
                "solana:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU?reference=abc123"
            ),
            Some("abc123".to_string())
        );
        assert_eq!(
            extract_reference_param("reference=myref&other=1"),
            Some("myref".to_string())
        );
        assert_eq!(
            extract_reference_param(
                "solana:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU?amount=10"
            ),
            None
        );
    }

    #[tokio::test]
    async fn test_solana_wallet_balance_atomic_returns_none() {
        let store = Arc::new(MockPaymentStore::new());
        let client = Arc::new(MultiRemoteSolanaClient::new(
            "https://api.mainnet-beta.solana.com".into(),
            vec![],
            3,
            3,
        ));
        let wallet = SolanaWallet::new_native(
            client,
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".into(),
            Coin::Solana,
            1,
            store,
        );
        assert_eq!(wallet.balance_atomic().await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_send_rpc_non_2xx_returns_error() {
        use std::sync::atomic::AtomicBool;
        let responses = Arc::new(AtomicBool::new(false)); // server returns 500
        let (url, _h) = spawn_mock_solana_node(responses, 100).await;
        let client = MultiRemoteSolanaClient::new(url, vec![], 1, 1);
        let err = client.get_slot().await.unwrap_err();
        match err {
            PaymentError::Rpc(msg) => {
                assert!(
                    msg.contains("HTTP status 500"),
                    "expected HTTP 500 in {msg}"
                );
            }
            other => panic!("expected PaymentError::Rpc, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_solana_wallet_incoming_transfers_empty_when_no_quotes() {
        let store = Arc::new(MockPaymentStore::new());
        let client = Arc::new(MultiRemoteSolanaClient::new(
            "https://api.mainnet-beta.solana.com".into(),
            vec![],
            3,
            3,
        ));
        let wallet = SolanaWallet::new_native(
            client,
            "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU".into(),
            Coin::Solana,
            1,
            store,
        );
        let transfers = wallet.incoming_transfers(0).await.unwrap();
        assert!(transfers.is_empty());
    }

    #[test]
    fn test_solana_confirmations_and_commitment_calculation() {
        let min_confs_confirmed = 1;
        let commitment_confirmed = if min_confs_confirmed >= 32 {
            "finalized"
        } else {
            "confirmed"
        };
        assert_eq!(commitment_confirmed, "confirmed");

        let min_confs_finalized = 32;
        let commitment_finalized = if min_confs_finalized >= 32 {
            "finalized"
        } else {
            "confirmed"
        };
        assert_eq!(commitment_finalized, "finalized");

        // Real confirmations calculation
        let current_slot = 150;
        let tx_slot = 123;
        let confs = if current_slot >= tx_slot {
            current_slot - tx_slot + 1
        } else {
            1
        };
        assert_eq!(confs, 28);

        // Edge case: current_slot < tx.slot
        let early_slot = 120;
        let confs_early = if early_slot >= tx_slot {
            early_slot - tx_slot + 1
        } else {
            1
        };
        assert_eq!(confs_early, 1);
    }

    #[tokio::test]
    async fn test_solana_wallet_incoming_transfers_detects_delta_with_mock_store() {
        use std::sync::atomic::AtomicBool;
        let ok = Arc::new(AtomicBool::new(true));
        let (node_url, _h) = spawn_mock_solana_node(ok, 123).await;
        let client = Arc::new(MultiRemoteSolanaClient::new(node_url, vec![], 1, 1));

        let recipient = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
        let ref_key = generate_solana_reference();
        let solana_pay_url =
            format!("solana:{recipient}?amount=0.005&reference={ref_key}&label=socks.cat");

        let store = Arc::new(MockPaymentStore::new());
        store
            .open_addrs
            .lock()
            .unwrap()
            .insert("sol".to_string(), vec![solana_pay_url.clone()]);

        let wallet = SolanaWallet::new_native(client, recipient.into(), Coin::Solana, 1, store);

        let transfers = wallet.incoming_transfers(0).await.unwrap();
        let t = transfers
            .iter()
            .find(|t| t.address == solana_pay_url)
            .expect("should find transfer for quote");
        assert!(t.txid.starts_with("sig_") || t.txid == "sig123");
        assert_eq!(t.amount_atomic, 5_000_000);
        assert_eq!(t.address, solana_pay_url);
        assert_eq!(t.height, 123);
        assert_eq!(t.confirmations, 1);
    }

    #[tokio::test]
    async fn test_solana_wallet_incoming_transfers_calculates_real_confirmations_with_mock_store() {
        use std::sync::atomic::AtomicBool;
        let ok = Arc::new(AtomicBool::new(true));
        // Node slot is 132, transaction slot is 123 -> confirmations = 132 - 123 + 1 = 10
        let (node_url, _h) = spawn_mock_solana_node(ok, 132).await;
        let client = Arc::new(MultiRemoteSolanaClient::new(node_url, vec![], 1, 1));

        let recipient = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
        let ref_key = generate_solana_reference();
        let solana_pay_url =
            format!("solana:{recipient}?amount=0.005&reference={ref_key}&label=socks.cat");

        let store = Arc::new(MockPaymentStore::new());
        store
            .open_addrs
            .lock()
            .unwrap()
            .insert("sol".to_string(), vec![solana_pay_url.clone()]);

        let wallet = SolanaWallet::new_native(client, recipient.into(), Coin::Solana, 32, store);

        let transfers = wallet.incoming_transfers(0).await.unwrap();
        let t = transfers
            .iter()
            .find(|t| t.address == solana_pay_url)
            .expect("should find transfer for quote");
        assert!(t.txid.starts_with("sig_") || t.txid == "sig123");
        assert_eq!(t.height, 123);
        assert_eq!(t.confirmations, 10);
    }
}
