//! Watch-only Esplora (block-explorer REST) `PaymentBackend` for BTC/LTC.
//!
//! This is the "remote/nodeless" detection source in the failover design: it
//! never talks to a full node, only a public (or self-hosted) Esplora-style
//! REST API (the same one `mempool.space`/`blockstream.info` expose). Like
//! [`crate::deriver::derive_p2wpkh`] it holds a watch-only extended public
//! key (a BIP84 account zpub) and derives deposit addresses in-process
//! rather than asking a wallet daemon for one. Detection is a per-address
//! balance/tx scan over the quotes the service itself is tracking, so both
//! the derivation index and the watched addresses survive restarts without
//! any in-memory state.
//!
//! Confirmed balance for an address is `chain_stats.funded_txo_sum -
//! chain_stats.spent_txo_sum` (Esplora's confirmed running total);
//! `mempool_stats` (unconfirmed) is intentionally never counted here. Once an
//! address shows a positive confirmed balance, its confirmation depth is read
//! from the first confirmed transaction in `/address/<addr>/txs` (Esplora
//! returns that endpoint newest-first, mempool entries first, so this walks
//! it in order and takes the first entry whose `status.confirmed` is true).

use std::sync::Arc;

use async_trait::async_trait;
use bech32::Hrp;
use reqwest::Client as HttpClient;
use serde::Deserialize;

use crate::backend::PaymentBackend;
use crate::coin::Coin;
use crate::deriver;
use crate::error::PaymentError;
use crate::store::PaymentStore;
use crate::types::{to_i64, Health, NewSubaddress, Transfer};

/// A watch-only BTC/LTC deposit source reached over an Esplora-style REST API.
pub struct EsploraSource {
    http: HttpClient,
    /// Esplora API base URL, no trailing slash (e.g. `https://blockstream.info/api`).
    base: String,
    coin: Coin,
    /// Bech32 HRP for the address' network: `bc` (BTC) / `ltc` (LTC).
    hrp: Hrp,
    /// Watch-only BIP84 account zpub; deposit addresses are its `/0/i` children.
    zpub: String,
    /// Minimum confirmations before a transfer is considered payable.
    /// `incoming_transfers` reports each transfer's *actual* confirmation
    /// depth (from the funding tx's block height) and the shared poller
    /// (`poll_once`'s `min_confirmations` gate) enforces the threshold, so
    /// this field isn't read by this backend's own logic yet; kept for
    /// parity with the other watch-only backends and for a future source
    /// (e.g. failover selection) that needs the coin's configured depth
    /// without threading it through separately.
    #[allow(dead_code, clippy::allow_attributes)]
    min_conf: u64,
    store: Arc<dyn PaymentStore>,
    tip_cache: Arc<tokio::sync::Mutex<Option<(u64, std::time::Instant)>>>,
}

/// Cap on how many deposit addresses `balance_atomic` will scan, so a large
/// quote history can't blow up the number of Esplora requests made per poll
/// tick.
const MAX_BALANCE_ADDRESSES: i64 = 64;

impl EsploraSource {
    /// Build a watch-only Esplora source. `base` is the API root (no trailing
    /// slash needed, one is stripped if present); `zpub` is the BIP84 account
    /// extended public key for `coin`. Only Bitcoin and Litecoin are
    /// supported — any other coin is a configuration error.
    pub fn new(
        base: &str,
        coin: Coin,
        zpub: &str,
        min_conf: u64,
        store: Arc<dyn PaymentStore>,
    ) -> Result<Self, PaymentError> {
        let hrp = match coin {
            Coin::Bitcoin => Hrp::parse("bc"),
            Coin::Litecoin => Hrp::parse("ltc"),
            other => {
                return Err(PaymentError::Rpc(format!(
                    "esplora: unsupported coin {}",
                    other.as_str()
                )))
            }
        }
        .map_err(|e| PaymentError::Rpc(format!("esplora: invalid hrp: {e}")))?;
        let http = HttpClient::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| PaymentError::Rpc(e.to_string()))?;
        Ok(Self {
            http,
            base: base.trim_end_matches('/').to_owned(),
            coin,
            hrp,
            zpub: zpub.trim().to_owned(),
            min_conf,
            store,
            tip_cache: Arc::new(tokio::sync::Mutex::new(None)),
        })
    }

    /// `GET {base}/blocks/tip/height` — the current chain tip height. The
    /// response body is a bare integer, not JSON, so this is read as text and
    /// parsed directly.
    async fn tip_height(&self) -> Result<u64, PaymentError> {
        {
            let cache = self.tip_cache.lock().await;
            if let Some((height, when)) = *cache {
                if when.elapsed() < std::time::Duration::from_secs(30) {
                    return Ok(height);
                }
            }
        }
        let url = format!("{}/blocks/tip/height", self.base);
        let resp = match self.http.get(&url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                let cache = self.tip_cache.lock().await;
                if let Some((height, _)) = *cache {
                    return Ok(height);
                }
                return Err(PaymentError::Rpc(e.to_string()));
            }
        };
        if !resp.status().is_success() {
            let cache = self.tip_cache.lock().await;
            if let Some((height, _)) = *cache {
                return Ok(height);
            }
            return Err(PaymentError::Rpc(format!("HTTP status {}", resp.status())));
        }
        let text = resp
            .text()
            .await
            .map_err(|e| PaymentError::Rpc(e.to_string()))?;
        let height = text
            .trim()
            .parse::<u64>()
            .map_err(|e| PaymentError::Rpc(format!("esplora: bad tip height {text:?}: {e}")))?;
        let mut cache = self.tip_cache.lock().await;
        *cache = Some((height, std::time::Instant::now()));
        Ok(height)
    }

    /// `GET {base}/address/<address>` — confirmed + unconfirmed running totals.
    async fn address_stats(&self, address: &str) -> Result<AddressStats, PaymentError> {
        let url = format!("{}/address/{address}", self.base);
        self.http
            .get(&url)
            .send()
            .await
            .map_err(|e| PaymentError::Rpc(e.to_string()))?
            .error_for_status()
            .map_err(|e| PaymentError::Rpc(e.to_string()))?
            .json()
            .await
            .map_err(|e| PaymentError::Rpc(e.to_string()))
    }

    /// `GET {base}/address/<address>/txs` — that address' transactions.
    async fn address_txs(&self, address: &str) -> Result<Vec<EsploraTx>, PaymentError> {
        let url = format!("{}/address/{address}/txs", self.base);
        self.http
            .get(&url)
            .send()
            .await
            .map_err(|e| PaymentError::Rpc(e.to_string()))?
            .error_for_status()
            .map_err(|e| PaymentError::Rpc(e.to_string()))?
            .json()
            .await
            .map_err(|e| PaymentError::Rpc(e.to_string()))
    }

    /// Confirmations for `address`'s funding, at chain tip `tip`: the first
    /// confirmed transaction's `tip - block_height + 1`. If the address has no
    /// confirmed transaction at all (e.g. the response only has mempool
    /// entries — shouldn't happen when called only after `confirmed_sats() >
    /// 0`, but the API can race a reorg), this reports 0 confirmations rather
    /// than erroring, so the caller's confirmation gate simply defers the
    /// credit to a later poll instead of crediting on stale/wrong data.
    async fn first_funding_confirmations(
        &self,
        address: &str,
        tip: u64,
    ) -> Result<u64, PaymentError> {
        let txs = self.address_txs(address).await?;
        Ok(confirmations_from_txs(&txs, tip))
    }
}

/// Esplora's `chain_stats` / `mempool_stats` running totals (sats).
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct TxoSums {
    funded_txo_sum: u64,
    spent_txo_sum: u64,
}

/// `GET /address/<addr>` response, trimmed to the fields this backend needs.
/// Esplora's `mempool_stats` (unconfirmed running totals) is present in the
/// real response too, but this backend never counts it — it's simply left
/// off this struct and ignored by serde rather than parsed and unused.
#[derive(Debug, Deserialize)]
struct AddressStats {
    #[serde(default)]
    chain_stats: TxoSums,
}

impl AddressStats {
    /// Confirmed balance in sats: only `chain_stats` counts — `mempool_stats`
    /// (unconfirmed) must never be credited.
    fn confirmed_sats(&self) -> u64 {
        self.chain_stats
            .funded_txo_sum
            .saturating_sub(self.chain_stats.spent_txo_sum)
    }
}

/// One entry of `GET /address/<addr>/txs`, trimmed to `status`.
#[derive(Debug, Deserialize)]
struct EsploraTx {
    status: TxStatus,
}

#[derive(Debug, Deserialize)]
struct TxStatus {
    confirmed: bool,
    #[serde(default)]
    block_height: Option<u32>,
}

/// Pure helper behind [`EsploraSource::first_funding_confirmations`]: the
/// first confirmed tx's `tip - block_height + 1`, or 0 if none of `txs` is
/// confirmed.
fn confirmations_from_txs(txs: &[EsploraTx], tip: u64) -> u64 {
    txs.iter()
        .find_map(|t| {
            t.status
                .confirmed
                .then_some(t.status.block_height)
                .flatten()
        })
        .map(|height| tip.saturating_sub(u64::from(height)).saturating_add(1))
        .unwrap_or(0)
}

#[async_trait]
impl PaymentBackend for EsploraSource {
    async fn new_subaddress(&self, _label: &str) -> Result<NewSubaddress, PaymentError> {
        let index = self.store.next_hd_index(self.coin.as_str()).await?;
        let index_u32 = u32::try_from(index)
            .map_err(|_| PaymentError::Rpc("esplora hd index overflow".into()))?;
        let address = deriver::derive_p2wpkh(&self.zpub, self.hrp, index_u32)?;
        Ok(NewSubaddress {
            address,
            index: u64::from(index_u32),
        })
    }

    async fn incoming_transfers(&self, _min_height: u64) -> Result<Vec<Transfer>, PaymentError> {
        let tip = self.tip_height().await?;
        let addresses = self.store.open_addresses(self.coin.as_str()).await?;
        let mut transfers = Vec::new();
        for address in addresses {
            // Per-address tolerant, like `balance_atomic` below: when Esplora
            // is the PRIMARY source, one flaky address (rate-limit, transient
            // 5xx) must not abort detection for every other address that ticks
            // this round. Log and move on instead of `?`-propagating -- a tick
            // that skips one bad address and credits the rest is strictly
            // better than a tick that credits nothing.
            let stats = match self.address_stats(&address).await {
                Ok(stats) => stats,
                Err(e) => {
                    eprintln!(
                        "payments[{}]: address_stats({address}) failed, skipping this tick: {e}",
                        self.coin.as_str()
                    );
                    continue;
                }
            };
            let sats = stats.confirmed_sats();
            if sats == 0 {
                continue;
            }
            let confirmations = match self.first_funding_confirmations(&address, tip).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "payments[{}]: first_funding_confirmations({address}) failed, skipping this tick: {e}",
                        self.coin.as_str()
                    );
                    continue;
                }
            };
            transfers.push(Transfer {
                // Stable per-address id: idempotent crediting keys on txid,
                // and each quote uses a fresh address, so one credit per quote.
                txid: format!("{}:{address}", self.coin.as_str()),
                amount_atomic: sats,
                address,
                height: tip,
                confirmations,
            });
        }
        Ok(transfers)
    }

    /// Sum of confirmed sats over the most-recently-derived deposit addresses
    /// (see [`MAX_BALANCE_ADDRESSES`]). A per-address failure is logged and
    /// skipped, not fatal -- one bad address must not blank the whole gauge.
    async fn balance_atomic(&self) -> Result<Option<i64>, PaymentError> {
        let addresses = self
            .store
            .recent_addresses(self.coin.as_str(), MAX_BALANCE_ADDRESSES)
            .await?;
        if addresses.len() as i64 >= MAX_BALANCE_ADDRESSES {
            eprintln!(
                "payments[{}]: wallet_balance_atomic scan capped at \
                 {MAX_BALANCE_ADDRESSES} most-recent address(es); quote history may be larger",
                self.coin.as_str()
            );
        }
        let mut total: u64 = 0;
        for address in &addresses {
            match self.address_stats(address).await {
                Ok(stats) => total = total.saturating_add(stats.confirmed_sats()),
                Err(e) => {
                    let err_msg = e.to_string();
                    if err_msg.contains("429") || err_msg.contains("502") {
                        break;
                    }
                }
            }
        }
        Ok(Some(to_i64(total)))
    }

    /// `GET {base}/blocks/tip/height` reachable => `Healthy`, else `Unreachable`.
    /// An Esplora REST API has no meaningful "sync lag" signal the way a full
    /// node's `getblockchaininfo` does, so unlike the node backends this never
    /// reports `Lagging`.
    async fn health(&self) -> Health {
        match self.tip_height().await {
            Ok(_) => Health::Healthy,
            Err(_) => Health::Unreachable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MockPaymentStore;

    const BTC_TESTVEC_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    #[test]
    fn confirmed_balance_from_address_stats() {
        let j: AddressStats = serde_json::from_str(
            r#"{"address":"bc1q..","chain_stats":{"funded_txo_sum":150000,"spent_txo_sum":0},
                "mempool_stats":{"funded_txo_sum":0,"spent_txo_sum":0}}"#,
        )
        .unwrap();
        assert_eq!(j.confirmed_sats(), 150000);
    }

    #[test]
    fn confirmed_balance_subtracts_spent() {
        let j: AddressStats = serde_json::from_str(
            r#"{"chain_stats":{"funded_txo_sum":150000,"spent_txo_sum":50000},
                "mempool_stats":{"funded_txo_sum":0,"spent_txo_sum":0}}"#,
        )
        .unwrap();
        assert_eq!(j.confirmed_sats(), 100000);
    }

    #[test]
    fn confirmed_balance_ignores_mempool_stats() {
        // Unconfirmed inbound funds must never count toward confirmed_sats().
        let j: AddressStats = serde_json::from_str(
            r#"{"chain_stats":{"funded_txo_sum":0,"spent_txo_sum":0},
                "mempool_stats":{"funded_txo_sum":999999,"spent_txo_sum":0}}"#,
        )
        .unwrap();
        assert_eq!(j.confirmed_sats(), 0);
    }

    #[test]
    fn first_funding_confirmations_from_txs_fixture() {
        let txs: Vec<EsploraTx> = serde_json::from_str(
            r#"[
                {"status":{"confirmed":true,"block_height":800000,"block_hash":"h","block_time":1}}
            ]"#,
        )
        .unwrap();
        // tip - block_height + 1
        assert_eq!(confirmations_from_txs(&txs, 800009), 10);
    }

    #[test]
    fn first_funding_confirmations_skips_leading_mempool_entries() {
        // Esplora returns mempool entries first (newest-first ordering); the
        // helper must walk past them to the first confirmed entry.
        let txs: Vec<EsploraTx> = serde_json::from_str(
            r#"[
                {"status":{"confirmed":false}},
                {"status":{"confirmed":true,"block_height":100,"block_hash":"h","block_time":1}}
            ]"#,
        )
        .unwrap();
        assert_eq!(confirmations_from_txs(&txs, 105), 6);
    }

    #[test]
    fn first_funding_confirmations_all_unconfirmed_is_zero() {
        // A /txs response with only unconfirmed (mempool) entries must report
        // 0 confirmations rather than panicking or fabricating a height.
        let txs: Vec<EsploraTx> = serde_json::from_str(
            r#"[{"status":{"confirmed":false}},{"status":{"confirmed":false}}]"#,
        )
        .unwrap();
        assert_eq!(confirmations_from_txs(&txs, 800000), 0);
    }

    #[test]
    fn first_funding_confirmations_empty_txs_is_zero() {
        assert_eq!(confirmations_from_txs(&[], 800000), 0);
    }

    /// A minimal hand-rolled mock Esplora server: serves
    /// `/blocks/tip/height` as a bare-text tip, and per-address
    /// `/address/<addr>` + `/address/<addr>/txs`. `bad_address` always 500s
    /// on its `/address/<addr>` call (simulating a rate-limit/transient
    /// failure); every other address gets a funded, single-confirmation
    /// response.
    async fn spawn_mock_esplora(bad_address: String) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let bad_address = bad_address.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 8192];
                    let Ok(n) = stream.read(&mut buf).await else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&buf[..n]);
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_owned();

                    let (status, body) = if path == "/blocks/tip/height" {
                        ("200 OK", "100".to_owned())
                    } else if path.ends_with("/txs") {
                        (
                            "200 OK",
                            r#"[{"status":{"confirmed":true,"block_height":95,"block_hash":"h","block_time":1}}]"#
                                .to_owned(),
                        )
                    } else if path.starts_with("/address/") {
                        let requested = path.trim_start_matches("/address/");
                        if requested == bad_address {
                            (
                                "500 Internal Server Error",
                                "{\"error\":\"boom\"}".to_owned(),
                            )
                        } else {
                            (
                                "200 OK",
                                r#"{"chain_stats":{"funded_txo_sum":100000,"spent_txo_sum":0},
                                    "mempool_stats":{"funded_txo_sum":0,"spent_txo_sum":0}}"#
                                    .to_owned(),
                            )
                        }
                    } else {
                        ("404 Not Found", "{}".to_owned())
                    };

                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn incoming_transfers_skips_erroring_address_and_still_reports_others() {
        let store = Arc::new(MockPaymentStore::new());
        let bad_addr = "bad-addr".to_string();
        let good_addr = "good-addr".to_string();
        store.open_addrs.lock().unwrap().insert(
            "bitcoin".to_string(),
            vec![bad_addr.clone(), good_addr.clone()],
        );

        let mock_addr = spawn_mock_esplora(bad_addr.clone()).await;
        let base = format!("http://{mock_addr}");
        let source =
            EsploraSource::new(&base, Coin::Bitcoin, BTC_TESTVEC_ZPUB, 1, store.clone()).unwrap();

        let transfers = source.incoming_transfers(0).await.unwrap();
        assert!(
            transfers.iter().all(|t| t.address != bad_addr),
            "the erroring address must never appear as a transfer"
        );
        let good = transfers
            .iter()
            .find(|t| t.address == good_addr)
            .expect("the erroring address must be skipped, not abort the whole tick -- good_addr must still be reported");
        assert_eq!(good.amount_atomic, 100000);
    }

    #[tokio::test]
    async fn test_esplora_new_subaddress_and_balance() {
        let store = Arc::new(MockPaymentStore::new());
        let good_addr = "good-addr".to_string();
        store
            .recent_addrs
            .lock()
            .unwrap()
            .insert("bitcoin".to_string(), vec![good_addr]);

        let mock_addr = spawn_mock_esplora("other-bad".to_string()).await;
        let base = format!("http://{mock_addr}");
        let source =
            EsploraSource::new(&base, Coin::Bitcoin, BTC_TESTVEC_ZPUB, 1, store.clone()).unwrap();

        let sub = source.new_subaddress("order").await.unwrap();
        assert_eq!(sub.index, 0);
        assert_eq!(sub.address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");

        let bal = source.balance_atomic().await.unwrap();
        assert_eq!(bal, Some(100000));
    }
}
