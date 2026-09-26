//! Tron full-node client (thin, hand-rolled JSON-over-HTTP) — watch-only.
//!
//! Tron's full-node API is plain JSON-over-HTTP (`POST /wallet/...`), not a
//! JSON-RPC 2.0 envelope like the Bitcoin-family/Ethereum backends use, and
//! it has no Bitcoin-Core-style wallet/descriptor-import concept: any
//! address's balance can be queried directly, so this backend polls balances
//! the same way [`super::ethereum`]/[`super::erc20`] do, not the
//! import-then-watch model [`super::bitcoin`]/[`super::litecoin`]/
//! [`super::dogecoin`]/[`super::bitcoincash`] use.
//!
//! Confirmation safety deliberately does NOT replicate `ethereum.rs`'s
//! "read balance N blocks deep" trick: Tron's historical-balance-at-height
//! endpoint (`getaccountbalance`) requires non-default node configuration
//! (`storage.balance.history.lookup=true`) and is only served by a handful
//! of official nodes, so it isn't something an arbitrary operator's node can
//! be assumed to support. Instead this queries the **`walletsolidity`**
//! endpoints instead of `wallet` throughout — Tron's own solidified
//! (finalized, ~1 minute lag, irreversible) chain view, which is the
//! network's own documented recommendation for deposit crediting. This
//! makes a manual `min_confirmations` block-depth check unnecessary: a
//! nonzero balance read from `walletsolidity` is already final by
//! construction. `min_confirmations` is still accepted (for parity with
//! other coins) but unused.
//!
//! Tron uses the same curve/BIP44 derivation as Ethereum; deposit addresses
//! come from [`crate::deriver::derive_tron_address`]. Amounts are in SUN
//! (1 TRX = 1e6 SUN) already as an integer in the API response — no
//! float-to-atomic rounding needed, unlike the Bitcoin-family backends.

use std::sync::Arc;

use async_trait::async_trait;
use reqwest::Client as HttpClient;
use serde::Deserialize;
use serde_json::json;

use crate::backend::PaymentBackend;
use crate::coin::Coin;
use crate::deriver::derive_tron_address;
use crate::error::PaymentError;
use crate::store::PaymentStore;
use crate::types::{Health, NewSubaddress, Transfer};

/// Cap on how many deposit addresses `balance_atomic` will scan — mirrors
/// [`super::ethereum::MAX_BALANCE_ADDRESSES`].
const MAX_BALANCE_ADDRESSES: i64 = 64;

/// How stale `getnowblock`'s timestamp may be before `health()` reports the
/// node as lagging rather than healthy. Tron's block time is ~3s; 5 minutes
/// is a generous margin before treating the node as behind.
const MAX_BLOCK_STALENESS_SECS: i64 = 300;
/// Divisor used to translate a staleness duration into an approximate
/// "blocks behind" figure for `Health::Lagging`, matching Tron's ~3s block
/// time. Approximate by nature (`walletsolidity` has no `headers`/`blocks`
/// pair the way Bitcoin-family nodes do) — good enough for the metric's
/// purpose (rough operator-facing signal, not a precise count).
const APPROX_SECS_PER_BLOCK: i64 = 3;

pub struct TronWallet {
    http: HttpClient,
    url: String,
    xpub: String,
    coin: Coin,
    store: Arc<dyn PaymentStore>,
}

impl TronWallet {
    /// `url` is the full node's base URL (e.g. `https://api.trongrid.io`);
    /// endpoints are appended as `{url}/walletsolidity/...`.
    pub fn connect(
        url: &str,
        xpub: &str,
        coin: Coin,
        store: Arc<dyn PaymentStore>,
    ) -> Result<Self, PaymentError> {
        let http = HttpClient::builder()
            .build()
            .map_err(|e| PaymentError::Rpc(e.to_string()))?;
        Ok(Self {
            http,
            url: url.trim_end_matches('/').to_owned(),
            xpub: xpub.trim().to_owned(),
            coin,
            store,
        })
    }

    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<T, PaymentError> {
        self.http
            .post(format!("{}{path}", self.url))
            .json(&body)
            .send()
            .await
            .map_err(|e| PaymentError::Rpc(e.to_string()))?
            .json()
            .await
            .map_err(|e| PaymentError::Rpc(e.to_string()))
    }

    /// Solidified (finalized) SUN balance for `address`. A never-funded
    /// address returns `{}` from Tron's node (not an error, not a
    /// `balance` field at all — see module docs' link on this), which
    /// `#[serde(default)]` reads as zero.
    async fn solid_balance(&self, address: &str) -> Result<u64, PaymentError> {
        let account: GetAccountResp = self
            .post(
                "/walletsolidity/getaccount",
                json!({ "address": address, "visible": true }),
            )
            .await?;
        Ok(account.balance)
    }

    pub fn client(&self) -> &HttpClient {
        &self.http
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn coin(&self) -> &Coin {
        &self.coin
    }
}

#[derive(Deserialize, Default)]
struct GetAccountResp {
    #[serde(default)]
    balance: u64,
}

#[derive(Deserialize)]
struct NowBlockResp {
    block_header: BlockHeader,
}

#[derive(Deserialize)]
struct BlockHeader {
    raw_data: BlockHeaderRawData,
}

#[derive(Deserialize)]
struct BlockHeaderRawData {
    /// Block timestamp, milliseconds since the Unix epoch.
    timestamp: i64,
}

#[async_trait]
impl PaymentBackend for TronWallet {
    async fn new_subaddress(&self, _label: &str) -> Result<NewSubaddress, PaymentError> {
        let index = self.store.next_hd_index(self.coin.as_str()).await?;
        let index_u32 =
            u32::try_from(index).map_err(|_| PaymentError::Rpc("tron hd index overflow".into()))?;
        let address = derive_tron_address(&self.xpub, index_u32)?;
        Ok(NewSubaddress {
            address,
            index: u64::from(index_u32),
        })
    }

    async fn incoming_transfers(&self, _min_height: u64) -> Result<Vec<Transfer>, PaymentError> {
        let addresses = self.store.open_addresses(self.coin.as_str()).await?;
        let mut transfers = Vec::new();
        for address in addresses {
            let sun = self.solid_balance(&address).await?;
            if sun > 0 {
                transfers.push(Transfer {
                    // One fresh address per quote (same idempotency model as
                    // ethereum.rs/erc20.rs): one credit per quote.
                    txid: format!("tron:{address}"),
                    amount_atomic: sun,
                    address,
                    height: 0,
                    // Already solidified/final by construction (see module
                    // docs) -- there's no meaningful additional depth to
                    // report, so this reports 0 rather than fabricating a
                    // number; the poller gates on the balance being
                    // nonzero at all, not on this field, for this backend.
                    confirmations: 0,
                });
            }
        }
        Ok(transfers)
    }

    async fn balance_atomic(&self) -> Result<Option<i64>, PaymentError> {
        let addresses = self
            .store
            .recent_addresses(self.coin.as_str(), MAX_BALANCE_ADDRESSES)
            .await?;
        let mut total: u64 = 0;
        for address in &addresses {
            match self.solid_balance(address).await {
                Ok(sun) => total = total.saturating_add(sun),
                Err(e) => eprintln!("payments[tron]: solid_balance({address}) failed: {e}"),
            }
        }
        Ok(Some(i64::try_from(total).unwrap_or(i64::MAX)))
    }

    async fn health(&self) -> Health {
        let now: Result<NowBlockResp, PaymentError> =
            self.post("/walletsolidity/getnowblock", json!({})).await;
        let Ok(block) = now else {
            return Health::Unreachable;
        };
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let staleness_secs = (now_ms - block.block_header.raw_data.timestamp) / 1000;
        if staleness_secs > MAX_BLOCK_STALENESS_SECS {
            let approx_blocks = u64::try_from(staleness_secs / APPROX_SECS_PER_BLOCK).unwrap_or(0);
            return Health::Lagging(approx_blocks);
        }
        Health::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MockPaymentStore;

    // Standard BIP84 test vector zpub (also valid as xpub/hex for tron address derivation)
    const BTC_TESTVEC_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    #[test]
    fn get_account_resp_defaults_balance_on_empty_object() {
        // A never-funded address's getaccount response is `{}` -- must
        // deserialize to balance 0, not fail.
        let resp: GetAccountResp = serde_json::from_str("{}").unwrap();
        assert_eq!(resp.balance, 0);
    }

    #[test]
    fn get_account_resp_reads_balance_field() {
        let resp: GetAccountResp = serde_json::from_str(r#"{"balance":1500000}"#).unwrap();
        assert_eq!(resp.balance, 1_500_000);
    }

    #[test]
    fn now_block_resp_reads_nested_timestamp() {
        let raw = r#"{"block_header":{"raw_data":{"timestamp":1700000000000}}}"#;
        let resp: NowBlockResp = serde_json::from_str(raw).unwrap();
        assert_eq!(resp.block_header.raw_data.timestamp, 1_700_000_000_000);
    }

    #[tokio::test]
    async fn test_tron_wallet_new_subaddress_with_mock_store() {
        let store = Arc::new(MockPaymentStore::new());
        let wallet = TronWallet::connect(
            "https://api.trongrid.io",
            BTC_TESTVEC_ZPUB,
            Coin::Tron,
            store,
        )
        .unwrap();

        let sub1 = wallet.new_subaddress("label1").await.unwrap();
        assert_eq!(sub1.index, 0);
        assert!(sub1.address.starts_with('T'));

        let sub2 = wallet.new_subaddress("label2").await.unwrap();
        assert_eq!(sub2.index, 1);
        assert!(sub2.address.starts_with('T'));
        assert_ne!(sub1.address, sub2.address);
    }

    async fn spawn_mock_tron_node() -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 4096];
                    let Ok(n) = stream.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    let body_str = String::from_utf8_lossy(&buf[..n]);
                    let resp_body = if body_str.contains("/walletsolidity/getaccount") {
                        r#"{"balance":1500000}"#.to_string()
                    } else if body_str.contains("/walletsolidity/getnowblock") {
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_millis();
                        format!(r#"{{"block_header":{{"raw_data":{{"timestamp":{now_ms}}}}}}}"#)
                    } else {
                        "{}".to_string()
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        resp_body.len(),
                        resp_body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });
        (url, handle)
    }

    #[tokio::test]
    async fn test_tron_wallet_incoming_transfers_and_balance_atomic() {
        let (node_url, _h) = spawn_mock_tron_node().await;
        let store = Arc::new(MockPaymentStore::new());
        let addr = "TXYZop1234567890";
        store
            .open_addrs
            .lock()
            .unwrap()
            .insert("tron".to_string(), vec![addr.to_string()]);
        store
            .recent_addrs
            .lock()
            .unwrap()
            .insert("tron".to_string(), vec![addr.to_string()]);

        let wallet = TronWallet::connect(&node_url, BTC_TESTVEC_ZPUB, Coin::Tron, store).unwrap();

        let transfers = wallet.incoming_transfers(0).await.unwrap();
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].address, addr);
        assert_eq!(transfers[0].amount_atomic, 1_500_000);
        assert_eq!(transfers[0].txid, format!("tron:{addr}"));

        let balance = wallet.balance_atomic().await.unwrap();
        assert_eq!(balance, Some(1_500_000));

        let health = wallet.health().await;
        assert_eq!(health, Health::Healthy);
    }
}
