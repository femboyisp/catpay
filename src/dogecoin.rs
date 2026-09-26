//! `dogecoind` client (thin, hand-rolled JSON-RPC) — watch-only.
//!
//! Dogecoin Core's RPC is Bitcoin-Core-shaped but several major versions
//! behind (1.14.x tracks roughly Bitcoin Core 0.16-era internals), so this
//! speaks its JSON-RPC directly over HTTP Basic auth rather than trusting
//! `corepc-client`'s typed surface — same rationale as [`crate::litecoin`].
//!
//! **Confirmed against a real node — Dogecoin Core 1.14.x has neither
//! descriptor-wallet RPCs nor multi-wallet support at all**
//! (`getdescriptorinfo`/`createwallet`/`listwallets` all return "Method not
//! found" — it predates Bitcoin Core 0.17, where those were introduced).
//! There is exactly one always-loaded default wallet and no `/wallet/<name>`
//! path. So unlike bitcoin/litecoin (which import one ranged
//! `pkh(<xpub>/0/*)` descriptor covering many future indices up front), this
//! backend imports each deposit address individually via `importaddress` at
//! the moment `new_subaddress` derives it — same fix as
//! [`crate::bitcoincash`], which has the identical incompatibility. That
//! also removes the fixed watched-range footgun the descriptor-based
//! backends have (an index past the pre-imported range would silently watch
//! nothing) — there is no range here, every derived address is imported
//! before it's ever handed to a customer. Amounts come back in DOGE (`f64`)
//! and are converted to koinu (1 DOGE = 1e8 koinu), the atomic unit the
//! crediting math expects.
//!
//! Dogecoin never deployed SegWit, so deposit addresses are legacy P2PKH
//! (`D...`, Base58Check version byte 30 — see [`crate::deriver::derive_p2pkh`]),
//! not the BIP84 scheme BTC/LTC use here. The account key must already be a
//! standard BIP32 `xpub` (`m/44'/3'/0'`) — Dogecoin wallets that export the
//! non-standard `dgub`/`dgpv` SLIP-132-style prefix instead need external
//! conversion first; this module does not (yet) handle that prefix the way
//! [`crate::deriver::to_descriptor_xpub`] handles `zpub`/`ypub`.

use std::sync::Arc;

use async_trait::async_trait;
use reqwest::Client as HttpClient;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;

use crate::backend::PaymentBackend;
use crate::coin::Coin;
use crate::deriver;
use crate::error::PaymentError;
use crate::store::PaymentStore;
use crate::types::{classify_health, to_i64, Health, NewSubaddress, Transfer};

/// Base58Check version byte for Dogecoin mainnet P2PKH addresses (`D...`),
/// from `dogecoin/dogecoin`'s `chainparams.cpp` (`CMainParams`,
/// `base58Prefixes[PUBKEY_ADDRESS] = 30`).
pub const DOGECOIN_MAINNET_VERSION_BYTE: u8 = 30;

/// Base58Check version byte for Dogecoin regtest/testnet P2PKH addresses
/// (`n...`) -- confirmed live against a real `dogecoind -regtest` node's own
/// `getnewaddress` output (decodes to version byte 111, same value Bitcoin
/// itself uses for testnet/regtest P2PKH -- Dogecoin's `CRegTestParams`
/// reuses it rather than defining a distinct one). Dev-only; production
/// nodes are always mainnet.
pub const DOGECOIN_REGTEST_VERSION_BYTE: u8 = 111;

/// A live Dogecoin Core node, reached over JSON-RPC (HTTP Basic auth),
/// watch-only: deposit addresses are derived in-process from a BIP44 xpub,
/// never minted by the node's own wallet.
pub struct DogecoinWallet {
    http: HttpClient,
    url: String,
    user: String,
    pass: String,
    /// Number of blocks the validated tip may trail the best-known header
    /// before `health()` reports `Lagging` instead of `Healthy`.
    tip_lag_blocks: u64,
    /// Watch-only BIP44 account xpub; deposit addresses are its `/0/i` children.
    xpub: String,
    /// Base58Check P2PKH version byte for whichever network this node is on
    /// -- `DOGECOIN_MAINNET_VERSION_BYTE` (default) or
    /// `DOGECOIN_REGTEST_VERSION_BYTE` (dev, via network config).
    version_byte: u8,
    coin: Coin,
    store: Arc<dyn PaymentStore>,
}

impl DogecoinWallet {
    /// Connect to a `dogecoind` JSON-RPC endpoint (user/pass auth).
    /// `tip_lag_blocks` is the max acceptable gap between the validated tip
    /// and the best-known header before `health()` reports the node as
    /// lagging. `store` provides the per-coin HD deposit-index counter
    /// (`store.next_hd_index`). Unlike the descriptor-based backends, there
    /// is nothing to bulk-import here — each deposit address is imported
    /// individually by `new_subaddress` (see module docs for why: Dogecoin
    /// Core has no descriptor-wallet or multi-wallet RPCs).
    #[allow(clippy::too_many_arguments, clippy::allow_attributes)]
    pub async fn connect_watch_only(
        url: &str,
        user: &str,
        pass: &str,
        xpub: &str,
        coin: Coin,
        tip_lag_blocks: u64,
        store: Arc<dyn PaymentStore>,
        version_byte: u8,
    ) -> Result<Self, PaymentError> {
        let http = HttpClient::builder()
            .build()
            .map_err(|e| PaymentError::Rpc(e.to_string()))?;
        Ok(Self {
            http,
            url: url.to_owned(),
            user: user.to_owned(),
            pass: pass.to_owned(),
            tip_lag_blocks,
            xpub: xpub.trim().to_owned(),
            version_byte,
            coin,
            store,
        })
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, PaymentError> {
        let body = json!({ "jsonrpc": "1.0", "id": "socks", "method": method, "params": params });
        let envelope: RpcEnvelope<T> = self
            .http
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.pass))
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
            .ok_or_else(|| PaymentError::Rpc("dogecoin rpc: empty result".to_owned()))
    }

    /// Same wire call as `call`, for RPCs that succeed with a `null` result
    /// (Bitcoin-Core-family "void" RPCs like `importaddress` always do) --
    /// only the RPC-level `error` field means failure here, unlike `call`,
    /// which treats a missing/null `result` as an error too (correct for
    /// every OTHER call this backend makes, which do return real data).
    async fn call_void(&self, method: &str, params: serde_json::Value) -> Result<(), PaymentError> {
        let body = json!({ "jsonrpc": "1.0", "id": "socks", "method": method, "params": params });
        let envelope: RpcEnvelope<serde_json::Value> = self
            .http
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.pass))
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
        Ok(())
    }

    /// Import one address into the node's watch-only wallet via the legacy
    /// `importaddress` RPC (see module docs: Dogecoin Core has no
    /// `importmulti`/`importdescriptors`-with-descriptor-checksum path, so
    /// this is one call per address, not one bulk range import).
    /// `rescan=false` — a fresh address has no history to find, and scanning
    /// would otherwise block on every single `new_subaddress` call.
    async fn import_address(&self, address: &str) -> Result<(), PaymentError> {
        self.call_void("importaddress", json!([address, "", false]))
            .await
            .map_err(|e| PaymentError::Rpc(format!("importaddress: {e}")))
    }
}

/// Derive the watch-only deposit address for HD index `index`, under
/// whichever network's version byte the caller passes.
fn derive_deposit_address(
    xpub: &str,
    version_byte: u8,
    index: u32,
) -> Result<String, PaymentError> {
    deriver::derive_p2pkh(xpub, version_byte, index)
}

#[derive(Deserialize)]
struct RpcEnvelope<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    message: String,
}

#[derive(Deserialize)]
struct ListSinceBlock {
    #[serde(default)]
    transactions: Vec<TxEntry>,
}

/// See `litecoin::BlockchainInfo`'s doc comment for why `blocks`/`headers`
/// are deliberately not `#[serde(default)]` — a malformed response must fail
/// to deserialize (-> `Unreachable`), not silently read as caught-up (`0/0`
/// -> `Healthy`, fail-open).
#[derive(Deserialize)]
struct BlockchainInfo {
    blocks: i64,
    headers: i64,
}

#[derive(Deserialize)]
struct TxEntry {
    #[serde(default)]
    category: String,
    #[serde(default)]
    amount: f64,
    #[serde(default)]
    address: String,
    #[serde(default)]
    txid: String,
    #[serde(default)]
    blockheight: u64,
    #[serde(default)]
    confirmations: i64,
}

/// Convert a positive DOGE amount to koinu (1 DOGE = 1e8), rounding to nearest.
fn doge_to_koinu(amount: f64) -> u64 {
    if amount.is_finite() && amount > 0.0 {
        (amount * 100_000_000.0).round() as u64
    } else {
        0
    }
}

#[async_trait]
impl PaymentBackend for DogecoinWallet {
    async fn new_subaddress(&self, _label: &str) -> Result<NewSubaddress, PaymentError> {
        let index = self.store.next_hd_index(self.coin.as_str()).await?;
        let index_u32 = u32::try_from(index)
            .map_err(|_| PaymentError::Rpc("dogecoin hd index overflow".into()))?;
        let address = derive_deposit_address(&self.xpub, self.version_byte, index_u32)?;
        // Import before handing the address to a customer -- an address the
        // node was never told to watch is a silent lost deposit.
        self.import_address(&address).await?;
        Ok(NewSubaddress {
            address,
            index: u64::from(index_u32),
        })
    }

    async fn incoming_transfers(&self, _min_height: u64) -> Result<Vec<Transfer>, PaymentError> {
        let listed: ListSinceBlock = self.call("listsinceblock", json!([])).await?;
        Ok(listed
            .transactions
            .into_iter()
            .filter(|t| t.category == "receive")
            .map(|t| Transfer {
                txid: t.txid,
                amount_atomic: doge_to_koinu(t.amount),
                address: t.address,
                height: t.blockheight,
                confirmations: u64::try_from(t.confirmations).unwrap_or(0),
            })
            .collect())
    }

    async fn balance_atomic(&self) -> Result<Option<i64>, PaymentError> {
        let doge: f64 = self.call("getbalance", json!([])).await?;
        Ok(Some(to_i64(doge_to_koinu(doge))))
    }

    async fn health(&self) -> Health {
        let info: BlockchainInfo = match self.call("getblockchaininfo", json!([])).await {
            Ok(info) => info,
            Err(_) => return Health::Unreachable,
        };
        classify_health(info.headers, info.blocks, self.tip_lag_blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MockPaymentStore;

    // Same BIP84 test-vector zpub the BTC/LTC backends use -- reused here
    // purely as an arbitrary valid extended key to exercise the descriptor
    // string and RPC plumbing; Dogecoin's own address math is verified
    // against a real published vector in `deriver`'s tests, not here.
    const TESTVEC_XPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    #[test]
    fn doge_to_koinu_rounds_and_floors() {
        assert_eq!(doge_to_koinu(1.0), 100_000_000);
        assert_eq!(doge_to_koinu(0.000_000_01), 1);
        assert_eq!(doge_to_koinu(0.0), 0);
        assert_eq!(doge_to_koinu(-1.0), 0);
        assert_eq!(doge_to_koinu(f64::NAN), 0);
        assert_eq!(doge_to_koinu(f64::INFINITY), 0);
    }

    #[test]
    fn blockchain_info_missing_fields_fails_to_deserialize() {
        assert!(serde_json::from_str::<BlockchainInfo>("{}").is_err());
        assert!(serde_json::from_str::<BlockchainInfo>(r#"{"blocks":100}"#).is_err());
        assert!(serde_json::from_str::<BlockchainInfo>(r#"{"headers":100}"#).is_err());
    }

    #[test]
    fn listsinceblock_keeps_only_receives() {
        let raw = r#"{"transactions":[
            {"category":"receive","amount":0.5,"address":"D1","txid":"t1","blockheight":42,"confirmations":3},
            {"category":"send","amount":-0.1,"address":"D2","txid":"t2","blockheight":42,"confirmations":3}
        ],"lastblock":"00"}"#;
        let listed: ListSinceBlock = serde_json::from_str(raw).unwrap();
        let recvs: Vec<_> = listed
            .transactions
            .into_iter()
            .filter(|t| t.category == "receive")
            .collect();
        assert_eq!(recvs.len(), 1);
        assert_eq!(recvs[0].txid, "t1");
        assert_eq!(doge_to_koinu(recvs[0].amount), 50_000_000);
    }

    #[test]
    fn derive_deposit_address_produces_d_prefixed_address() {
        let addr = derive_deposit_address(TESTVEC_XPUB, DOGECOIN_MAINNET_VERSION_BYTE, 0).unwrap();
        assert!(addr.starts_with('D'), "got {addr}");
    }

    #[test]
    fn derive_deposit_address_under_regtest_byte_produces_m_or_n_prefixed_address() {
        let addr = derive_deposit_address(TESTVEC_XPUB, DOGECOIN_REGTEST_VERSION_BYTE, 0).unwrap();
        assert!(addr.starts_with('m') || addr.starts_with('n'), "got {addr}");
    }

    async fn spawn_mock_dogecoind() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 8192];
                    let Ok(n) = stream.read(&mut buf).await else {
                        return;
                    };
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    let body = if req_str.contains("importaddress") {
                        r#"{"result":null,"error":null,"id":"socks"}"#
                    } else {
                        r#"{"result":null,"error":{"code":-1,"message":"unknown"},"id":"socks"}"#
                    };
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_dogecoin_wallet_new_subaddress_with_mock_store() {
        let server_addr = spawn_mock_dogecoind().await;
        let store = Arc::new(MockPaymentStore::new());
        let wallet = DogecoinWallet::connect_watch_only(
            &format!("http://{server_addr}"),
            "user",
            "pass",
            TESTVEC_XPUB,
            Coin::Dogecoin,
            5,
            store.clone(),
            DOGECOIN_MAINNET_VERSION_BYTE,
        )
        .await
        .unwrap();

        let sub1 = wallet.new_subaddress("order1").await.unwrap();
        assert_eq!(sub1.index, 0);
        assert!(sub1.address.starts_with('D'));

        let sub2 = wallet.new_subaddress("order2").await.unwrap();
        assert_eq!(sub2.index, 1);
        assert_ne!(sub2.address, sub1.address);
    }
}
