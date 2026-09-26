//! Watch-only Ethereum deposit backend.
//!
//! Ethereum is account-based, not UTXO, so there is no node-side wallet handing
//! out addresses. Instead we hold an **extended public key** (xpub, watch-only:
//! the server can derive deposit addresses but never spend) and derive a fresh
//! address per quote in-process with BIP32. Detection is a balance scan: for each
//! still-open quote, query `eth_getBalance` at a block `min_confirmations` deep,
//! so only sufficiently-confirmed funds are credited.
//!
//! The derivation index is drawn from a [`PaymentStore`] and the watched
//! addresses are read back from it, so both survive restarts (no in-memory
//! state to lose, no address reuse).
//!
//! `wallet_balance_atomic{coin="ethereum"}` is likewise built by summing
//! `eth_getBalance` over addresses read back from the store (the most-recently
//! derived ones, capped — see [`MAX_BALANCE_ADDRESSES`]) rather than any
//! node-side "wallet balance" concept, since there is no wallet daemon here.
//! Note this is *not* the same thing other coins' gauges report: it's the
//! visible on-chain total of addresses this service knows about, including
//! ones already credited, whose funds sit untouched unless/until an operator
//! sweeps them out-of-band. Addresses beyond the cap, or funds already swept
//! elsewhere, are invisible to it.

use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bip32::{ChildNumber, XPub};
use reqwest::Client as HttpClient;
use serde::Deserialize;
use serde_json::json;
use sha3::{Digest, Keccak256};
use tokio::sync::Mutex;

use crate::backend::PaymentBackend;
use crate::error::PaymentError;
use crate::store::PaymentStore;
use crate::types::{Health, NewSubaddress, Transfer};

#[derive(Debug)]
struct EthClientState {
    on_primary: bool,
    primary_fail_streak: u32,
    primary_ok_streak: u32,
    active_remote_index: usize,
}

/// Multi-remote Ethereum JSON-RPC client with sequential failover and hysteresis.
pub struct MultiRemoteEthClient {
    http: HttpClient,
    primary_url: String,
    remotes: Vec<String>,
    to_fallback_after: u32,
    to_primary_after: u32,
    state: Mutex<EthClientState>,
}

impl MultiRemoteEthClient {
    pub fn new(
        primary_url: String,
        remotes: Vec<String>,
        to_fallback_after: u32,
        to_primary_after: u32,
    ) -> Self {
        let http = HttpClient::builder()
            .build()
            .unwrap_or_else(|_| HttpClient::new());
        Self {
            http,
            primary_url,
            remotes,
            to_fallback_after,
            to_primary_after,
            state: Mutex::new(EthClientState {
                on_primary: true,
                primary_fail_streak: 0,
                primary_ok_streak: 0,
                active_remote_index: 0,
            }),
        }
    }

    /// Single probe check for an RPC URL using `eth_blockNumber`.
    async fn probe_url(&self, url: &str) -> bool {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": [] });
        match self.http.post(url).json(&body).send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    return false;
                }
                match resp.json::<RpcEnvelope>().await {
                    Ok(env) => env.error.is_none() && env.result.is_some(),
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
                metrics::counter!("detection_source_switch_total", "coin" => "ethereum")
                    .increment(1);
                eprintln!("payments[ethereum]: detection source -> primary node");
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
                metrics::counter!("detection_source_switch_total", "coin" => "ethereum")
                    .increment(1);
                eprintln!(
                    "payments[ethereum]: detection source -> remote [{}] {}",
                    s.active_remote_index, self.remotes[s.active_remote_index]
                );
            }
        }

        metrics::gauge!("detection_source", "coin" => "ethereum").set(if s.on_primary {
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
                        "payments[ethereum]: remote failover -> remote [{}] {}",
                        next_idx, self.remotes[next_idx]
                    );
                    Health::Healthy
                } else {
                    Health::Unreachable
                }
            }
        }
    }

    pub async fn health(&self) -> Health {
        self.refresh_source().await
    }

    pub async fn rpc(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<String, PaymentError> {
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

        let mut last_err = PaymentError::Rpc("ethereum rpc: no endpoints available".to_owned());
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
    ) -> Result<String, PaymentError> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let envelope: RpcEnvelope = self
            .http
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|e| PaymentError::Rpc(e.to_string()))?
            .json()
            .await
            .map_err(|e| PaymentError::Rpc(e.to_string()))?;
        if let Some(err) = envelope.error {
            return Err(PaymentError::Rpc(err.message));
        }
        envelope
            .result
            .ok_or_else(|| PaymentError::Rpc("ethereum rpc: empty result".to_owned()))
    }

    pub async fn block_number(&self) -> Result<u64, PaymentError> {
        let hex = self.rpc("eth_blockNumber", json!([])).await?;
        parse_hex_u128(&hex).map(|v| u64::try_from(v).unwrap_or(u64::MAX))
    }

    pub async fn balance_at(&self, address: &str, block: &str) -> Result<u128, PaymentError> {
        let hex = self.rpc("eth_getBalance", json!([address, block])).await?;
        parse_hex_u128(&hex)
    }

    pub async fn balance_of(
        &self,
        contract_address: &str,
        address: &str,
        block: &str,
    ) -> Result<u128, PaymentError> {
        let data = format!("0x70a08231{}", pad_address(address));
        let hex = self
            .rpc(
                "eth_call",
                json!([{ "to": contract_address, "data": data }, block]),
            )
            .await?;
        parse_hex_u128(&hex)
    }

    #[allow(dead_code, clippy::allow_attributes)]
    pub async fn on_primary(&self) -> bool {
        self.state.lock().await.on_primary
    }

    #[allow(dead_code, clippy::allow_attributes)]
    pub async fn active_remote_index(&self) -> usize {
        self.state.lock().await.active_remote_index
    }

    pub async fn current_endpoint(&self) -> String {
        let s = self.state.lock().await;
        if s.on_primary || self.remotes.is_empty() {
            self.primary_url.clone()
        } else {
            self.remotes[s.active_remote_index].clone()
        }
    }
}

/// A watch-only Ethereum deposit wallet reached over JSON-RPC.
pub struct EthereumWallet {
    client: Arc<MultiRemoteEthClient>,
    /// Receive-chain extended public key; child `i` is the address for HD index `i`.
    xpub: XPub,
    min_confirmations: u64,
    store: Arc<dyn PaymentStore>,
}

impl EthereumWallet {
    /// Build a watch-only wallet with a shared [`MultiRemoteEthClient`].
    pub fn new(
        client: Arc<MultiRemoteEthClient>,
        xpub: &str,
        min_confirmations: u64,
        store: Arc<dyn PaymentStore>,
    ) -> Result<Self, PaymentError> {
        let xpub = XPub::from_str(xpub.trim())
            .map_err(|e| PaymentError::Rpc(format!("invalid ethereum xpub: {e}")))?;
        Ok(Self {
            client,
            xpub,
            min_confirmations,
            store,
        })
    }

    /// Build a watch-only wallet from an xpub and an Ethereum JSON-RPC URL.
    /// The xpub must be the external receive-chain key (e.g. `m/44'/60'/0'/0`);
    /// deposit addresses are its non-hardened children.
    #[allow(dead_code, clippy::allow_attributes)]
    pub fn connect(
        url: &str,
        xpub: &str,
        min_confirmations: u64,
        store: Arc<dyn PaymentStore>,
    ) -> Result<Self, PaymentError> {
        let client = Arc::new(MultiRemoteEthClient::new(url.to_owned(), vec![], 3, 3));
        Self::new(client, xpub, min_confirmations, store)
    }

    /// Derive the deposit address for HD index `index`.
    fn address_for_index(&self, index: u32) -> Result<String, PaymentError> {
        derive_eth_address(&self.xpub, index)
    }

    async fn block_number(&self) -> Result<u64, PaymentError> {
        self.client.block_number().await
    }

    async fn balance_at(&self, address: &str, block: &str) -> Result<u128, PaymentError> {
        self.client.balance_at(address, block).await
    }

    #[allow(dead_code, clippy::allow_attributes)]
    pub fn client(&self) -> &Arc<MultiRemoteEthClient> {
        &self.client
    }
}

/// Cap on how many deposit addresses `balance_atomic` will scan, so a large
/// quote history can't blow up the number of `eth_getBalance` RPC calls made
/// per poll tick.
const MAX_BALANCE_ADDRESSES: i64 = 64;

/// Sum per-address wei balances into the `i64` the `wallet_balance_atomic`
/// gauge expects (every coin publishes atomic units as `i64`, matching
/// `payments::to_i64` for the u64-based coins). Wei totals never come close to
/// overflowing u128 (all of ETH's supply is ~1.2e26 wei, far under
/// `u128::MAX`), but the final cast to `i64` saturates defensively anyway.
fn sum_wei_to_i64<I: IntoIterator<Item = u128>>(balances: I) -> i64 {
    let total = balances
        .into_iter()
        .fold(0u128, |acc, wei| acc.saturating_add(wei));
    i64::try_from(total).unwrap_or(i64::MAX)
}

#[derive(Deserialize)]
struct RpcEnvelope {
    result: Option<String>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    message: String,
}

/// Left-pad a `0x`-prefixed 20-byte address to the 32-byte word `eth_call`
/// expects as a `balanceOf` argument, without the `0x` prefix.
pub(crate) fn pad_address(address: &str) -> String {
    let stripped = address.strip_prefix("0x").unwrap_or(address);
    format!("{stripped:0>64}")
}

/// Derive the deposit address for a non-hardened child of the receive xpub.
/// `pub` so other EVM modules can reuse it — an ERC-20 deposit address
/// is derived identically to a native ETH one, just watched via
/// `balanceOf` instead of `eth_getBalance`.
pub fn derive_eth_address(xpub: &XPub, index: u32) -> Result<String, PaymentError> {
    let child_number = ChildNumber::new(index, false)
        .map_err(|e| PaymentError::Rpc(format!("bad derivation index: {e}")))?;
    let child = xpub
        .derive_child(child_number)
        .map_err(|e| PaymentError::Rpc(format!("derive failed: {e}")))?;
    let point = child.public_key().to_encoded_point(false);
    Ok(eth_address_from_uncompressed(point.as_bytes()))
}

/// Ethereum address (lowercase, `0x`-prefixed) from a 65-byte uncompressed
/// secp256k1 public key (`0x04 || X || Y`): keccak256 of the 64-byte body, last
/// 20 bytes.
fn eth_address_from_uncompressed(uncompressed: &[u8]) -> String {
    let body = if uncompressed.len() == 65 {
        &uncompressed[1..]
    } else {
        uncompressed
    };
    let hash = Keccak256::digest(body);
    format!("0x{}", hex::encode(&hash[12..]))
}

/// Parse a `0x`-prefixed (or bare) hex integer into u128, saturating on overflow.
pub(crate) fn parse_hex_u128(s: &str) -> Result<u128, PaymentError> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s.trim());
    let trimmed = trimmed.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }
    u128::from_str_radix(trimmed, 16)
        .map_err(|e| PaymentError::Rpc(format!("bad hex from node: {e}")))
}

#[async_trait]
impl PaymentBackend for EthereumWallet {
    async fn new_subaddress(&self, _label: &str) -> Result<NewSubaddress, PaymentError> {
        let index = self.store.next_eth_hd_index().await?;
        let index_u32 =
            u32::try_from(index).map_err(|_| PaymentError::Rpc("eth hd index overflow".into()))?;
        let address = self.address_for_index(index_u32)?;
        Ok(NewSubaddress {
            address,
            index: u64::from(index_u32),
        })
    }

    async fn incoming_transfers(&self, _min_height: u64) -> Result<Vec<Transfer>, PaymentError> {
        self.client.refresh_source().await;
        let latest = self.block_number().await?;
        let target = latest.saturating_sub(self.min_confirmations);
        let block_param = if self.min_confirmations == 0 {
            "latest".to_owned()
        } else {
            format!("0x{target:x}")
        };

        let addresses = self.store.open_addresses("ethereum").await?;

        let mut transfers = Vec::new();
        for address in addresses {
            let wei = self.balance_at(&address, &block_param).await?;
            if wei > 0 {
                transfers.push(Transfer {
                    // Stable per-address id: idempotent crediting keys on txid, and
                    // each quote uses a fresh address, so one credit per quote.
                    txid: format!("eth:{address}"),
                    amount_atomic: u64::try_from(wei).unwrap_or(u64::MAX),
                    address,
                    height: target,
                    // Funds read at a block `min_confirmations` deep already meet
                    // the threshold; report it so the poller's gate passes.
                    confirmations: self.min_confirmations,
                });
            }
        }
        Ok(transfers)
    }

    /// Sum of `eth_getBalance("latest")` over the most-recently-derived
    /// deposit addresses (see [`MAX_BALANCE_ADDRESSES`] and the module docs
    /// for what this is/isn't). A per-address RPC failure is logged and
    /// skipped, not fatal — one bad address must not blank the whole gauge.
    async fn balance_atomic(&self) -> Result<Option<i64>, PaymentError> {
        let addresses = self.store.recent_addresses("ethereum", MAX_BALANCE_ADDRESSES).await?;
        if addresses.len() as i64 >= MAX_BALANCE_ADDRESSES {
            eprintln!(
                "payments[ethereum]: wallet_balance_atomic scan capped at \
                 {MAX_BALANCE_ADDRESSES} most-recent address(es); quote history may be larger"
            );
        }
        let mut balances = Vec::with_capacity(addresses.len());
        for address in &addresses {
            match self.balance_at(address, "latest").await {
                Ok(wei) => balances.push(wei),
                Err(e) => eprintln!("payments[ethereum]: balance_at({address}) failed: {e}"),
            }
        }
        Ok(Some(sum_wei_to_i64(balances)))
    }

    /// Reachability only (no lagging signal the way Bitcoin-family nodes
    /// have a headers/blocks pair) -- delegates to the MultiRemoteEthClient health check.
    async fn health(&self) -> Health {
        self.client.health().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MockPaymentStore;

    const WEI_PER_ETH: u128 = 1_000_000_000_000_000_000;

    #[test]
    fn address_from_generator_point() {
        // secp256k1 generator G is the public key for private key 1; its known
        // Ethereum address is 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf.
        let g = hex::decode(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
             483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        )
        .unwrap();
        assert_eq!(
            eth_address_from_uncompressed(&g),
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
    }

    #[test]
    fn parse_hex_u128_handles_prefix_and_empty() {
        assert_eq!(parse_hex_u128("0x0").unwrap(), 0);
        assert_eq!(parse_hex_u128("0x").unwrap(), 0);
        assert_eq!(
            parse_hex_u128("0xde0b6b3a7640000").unwrap(),
            WEI_PER_ETH
        );
        assert_eq!(parse_hex_u128("ff").unwrap(), 255);
        assert!(parse_hex_u128("0xzz").is_err());
    }

    #[test]
    fn sum_wei_to_i64_adds_known_per_address_balances() {
        let balances = vec![
            WEI_PER_ETH,     // 1 ETH
            WEI_PER_ETH / 2, // 0.5 ETH
            0,               // an empty/never-funded address
        ];
        let expected = WEI_PER_ETH + WEI_PER_ETH / 2;
        assert_eq!(sum_wei_to_i64(balances), expected as i64);
    }

    #[test]
    fn sum_wei_to_i64_empty_is_zero() {
        assert_eq!(sum_wei_to_i64(std::iter::empty()), 0);
    }

    #[test]
    fn sum_wei_to_i64_clamps_to_i64_max_on_overflow() {
        let balances = vec![u128::MAX, u128::MAX];
        assert_eq!(sum_wei_to_i64(balances), i64::MAX);
    }

    #[test]
    fn derivation_matches_known_answers() {
        // BIP32 test-vector-1 master xpub (seed 000102...0f). The Ethereum
        // addresses of its non-hardened children 0 and 1 are fixed known answers,
        // independently computed (secp256k1 public CKD -> keccak256 -> last 20).
        let xpub = XPub::from_str(
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        )
        .expect("test-vector xpub should parse");
        let a0 = derive_eth_address(&xpub, 0).unwrap();
        let a1 = derive_eth_address(&xpub, 1).unwrap();
        assert_eq!(a0, "0xaefbb50942817d8270bb9bd922aa5ca9cb06cdbf");
        assert_eq!(a1, "0x84f549a5be894f8faeb744952d2669fb55366798");
        // Deterministic and distinct per index.
        assert_eq!(a0, derive_eth_address(&xpub, 0).unwrap());
        assert_ne!(a0, a1);
    }

    async fn spawn_mock_eth_node(
        responses: Arc<std::sync::atomic::AtomicBool>,
        block_num_hex: &'static str,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let responses = Arc::clone(&responses);
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 4096];
                    let Ok(n) = stream.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    if !responses.load(std::sync::atomic::Ordering::SeqCst) {
                        let resp =
                            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
                        let _ = stream.write_all(resp.as_bytes()).await;
                        return;
                    }
                    let body_str = String::from_utf8_lossy(&buf[..n]);
                    let result_str = if body_str.contains("eth_getBalance") {
                        "0xde0b6b3a7640000"
                    } else {
                        block_num_hex
                    };
                    let body = format!(
                        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"{}\"}}",
                        result_str
                    );
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });
        (url, handle)
    }

    #[tokio::test]
    async fn multi_remote_failover_and_recovery() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let primary_ok = Arc::new(AtomicBool::new(true));
        let remote1_ok = Arc::new(AtomicBool::new(true));
        let remote2_ok = Arc::new(AtomicBool::new(true));

        let (primary_url, _h0) = spawn_mock_eth_node(Arc::clone(&primary_ok), "0x10").await;
        let (remote1_url, _h1) = spawn_mock_eth_node(Arc::clone(&remote1_ok), "0x20").await;
        let (remote2_url, _h2) = spawn_mock_eth_node(Arc::clone(&remote2_ok), "0x30").await;

        let client = MultiRemoteEthClient::new(
            primary_url,
            vec![remote1_url, remote2_url],
            2, // to_fallback_after
            2, // to_primary_after
        );

        // Initially healthy on primary
        assert_eq!(client.refresh_source().await, Health::Healthy);
        assert!(client.on_primary().await);
        assert_eq!(client.block_number().await.unwrap(), 16);

        // Primary fails: probe 1 of 2 -> still on primary due to hysteresis
        primary_ok.store(false, Ordering::SeqCst);
        let _ = client.refresh_source().await;
        assert!(client.on_primary().await);

        // Primary fails: probe 2 of 2 -> fails over to remote 0
        let health = client.refresh_source().await;
        assert_eq!(health, Health::Healthy);
        assert!(!client.on_primary().await);
        assert_eq!(client.active_remote_index().await, 0);
        assert_eq!(client.block_number().await.unwrap(), 32);

        // Remote 0 fails -> advances sequentially to remote 1
        remote1_ok.store(false, Ordering::SeqCst);
        let health = client.refresh_source().await;
        assert_eq!(health, Health::Healthy);
        assert!(!client.on_primary().await);
        assert_eq!(client.active_remote_index().await, 1);
        assert_eq!(client.block_number().await.unwrap(), 48);

        // Primary recovers: probe 1 of 2 -> still on remote due to hysteresis
        primary_ok.store(true, Ordering::SeqCst);
        let _ = client.refresh_source().await;
        assert!(!client.on_primary().await);

        // Primary recovers: probe 2 of 2 -> swings back to primary
        let health = client.refresh_source().await;
        assert_eq!(health, Health::Healthy);
        assert!(client.on_primary().await);
        assert_eq!(client.active_remote_index().await, 0);
        assert_eq!(client.block_number().await.unwrap(), 16);
    }

    #[tokio::test]
    async fn test_ethereum_wallet_new_subaddress_with_mock_store() {
        let store = Arc::new(MockPaymentStore::new());
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let wallet = EthereumWallet::connect("http://127.0.0.1:8545", xpub, 12, store).unwrap();

        let sub1 = wallet.new_subaddress("label1").await.unwrap();
        assert_eq!(sub1.index, 0);
        assert_eq!(sub1.address, "0xaefbb50942817d8270bb9bd922aa5ca9cb06cdbf");

        let sub2 = wallet.new_subaddress("label2").await.unwrap();
        assert_eq!(sub2.index, 1);
        assert_eq!(sub2.address, "0x84f549a5be894f8faeb744952d2669fb55366798");
    }

    #[tokio::test]
    async fn test_ethereum_wallet_incoming_transfers_and_balance_atomic_with_mock_store() {
        use std::sync::atomic::AtomicBool;
        let ok = Arc::new(AtomicBool::new(true));
        let (node_url, _h) = spawn_mock_eth_node(ok, "0x10").await;

        let store = Arc::new(MockPaymentStore::new());
        let addr = "0xaefbb50942817d8270bb9bd922aa5ca9cb06cdbf";
        store
            .open_addrs
            .lock()
            .unwrap()
            .insert("ethereum".to_string(), vec![addr.to_string()]);
        store
            .recent_addrs
            .lock()
            .unwrap()
            .insert("ethereum".to_string(), vec![addr.to_string()]);

        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let wallet = EthereumWallet::connect(&node_url, xpub, 2, store).unwrap();

        let transfers = wallet.incoming_transfers(0).await.unwrap();
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].address, addr);
        assert_eq!(transfers[0].amount_atomic, WEI_PER_ETH as u64);
        assert_eq!(transfers[0].confirmations, 2);

        let balance = wallet.balance_atomic().await.unwrap();
        assert_eq!(balance, Some(WEI_PER_ETH as i64));
    }
}
