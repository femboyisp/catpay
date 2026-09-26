//! `litecoind` client (thin, hand-rolled JSON-RPC) — watch-only.
//!
//! Litecoin Core's RPC is Bitcoin-Core-shaped, but its response types drift from
//! the version `corepc-client` is generated against, so this speaks litecoind's
//! JSON-RPC directly over HTTP Basic auth and parses only the fields the poller
//! needs — robust against daemon drift. Amounts come back in LTC (`f64`) and are
//! converted to litoshi, the atomic unit the crediting math expects.
//!
//! This backend does not mint deposit addresses from the node's hot wallet
//! (`getnewaddress`). Instead it holds a watch-only BIP84 account zpub and
//! derives deposit addresses in-process via [`crate::deriver::derive_p2wpkh`]
//! — the exact computation [`crate::esplora::EsploraSource`] performs for the
//! same `(zpub, index)` — so the node source and the Esplora remote source
//! watch the identical address for a given HD index, keeping failover between
//! them transparent. On connect, the zpub is converted to a plain BIP32 xpub
//! (litecoind's descriptor parser rejects the SLIP-132 `zpub` prefix — see
//! [`crate::deriver::to_descriptor_xpub`]) and imported into the node's
//! wallet as a watch-only ranged descriptor (`wpkh(<xpub>/0/*)`, no private
//! keys) over a fixed index range, so `listsinceblock`/`getbalance` (used
//! unchanged by `incoming_transfers`/`balance_atomic`) pick up funds sent to
//! any address this service derives.

use std::sync::Arc;

use async_trait::async_trait;
use bech32::Hrp;
use reqwest::Client as HttpClient;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;

use crate::backend::PaymentBackend;
use crate::coin::Coin;
use crate::deriver;
use crate::error::PaymentError;
use crate::store::PaymentStore;
use crate::types::{classify_health, to_i64, Health, NewSubaddress, Transfer};

/// A live Litecoin Core node, reached over JSON-RPC (HTTP Basic auth),
/// watch-only: deposit addresses are derived in-process from a BIP84 zpub,
/// never minted by the node's own wallet.
pub struct LitecoinWallet {
    http: HttpClient,
    url: String,
    user: String,
    pass: String,
    /// Number of blocks the validated tip may trail the best-known header
    /// before `health()` reports `Lagging` instead of `Healthy`.
    tip_lag_blocks: u64,
    /// Watch-only BIP84 account zpub; deposit addresses are its `/0/i` children.
    zpub: String,
    /// Bech32 HRP for the address' network: `ltc` (mainnet LTC).
    hrp: Hrp,
    coin: Coin,
    store: Arc<dyn PaymentStore>,
    /// The `wpkh(<xpub>/0/*)` watch-only descriptor to import, computed once at
    /// connect (zpub converted to a plain xpub -- see
    /// [`crate::deriver::to_descriptor_xpub`]).
    descriptor: String,
    /// Whether the watch-only descriptor has been imported into the node's
    /// wallet yet. Best-effort at connect, retried by `health()`, so a
    /// litecoind that's unreachable at startup still gets imported (and is
    /// promoted back by the `FailoverBackend`) once it returns.
    imported: Mutex<bool>,
}

impl LitecoinWallet {
    /// Connect to a `litecoind` JSON-RPC endpoint (user/pass auth) and import
    /// `zpub` (converted to a plain BIP32 xpub — see
    /// [`crate::deriver::to_descriptor_xpub`]) as a watch-only descriptor, so
    /// the node's wallet tracks every deposit address this service will ever
    /// derive from it (`wpkh(<xpub>/0/*)`). `tip_lag_blocks` is the max acceptable gap
    /// between the validated tip and the best-known header before `health()`
    /// reports the node as lagging. `store` provides the per-coin HD deposit-index counter
    /// (`store.next_hd_index`).
    #[allow(clippy::too_many_arguments, clippy::allow_attributes)]
    pub async fn connect_watch_only(
        url: &str,
        user: &str,
        pass: &str,
        zpub: &str,
        hrp: Hrp,
        coin: Coin,
        tip_lag_blocks: u64,
        store: Arc<dyn PaymentStore>,
    ) -> Result<Self, PaymentError> {
        let http = HttpClient::builder()
            .build()
            .map_err(|e| PaymentError::Rpc(e.to_string()))?;
        let zpub = zpub.trim().to_owned();
        // litecoind's descriptor parser only accepts the raw BIP32 `xpub`
        // version bytes, not the SLIP-132 `zpub` display prefix -- see
        // `deriver::to_descriptor_xpub`. `wallet.zpub` stays the original
        // zpub; only the string handed to the node is converted. `hrp`
        // already carries the network ("ltc" mainnet vs "rltc" regtest), so it's
        // also the right signal for which descriptor-key prefix the node accepts.
        let descriptor_prefix = if hrp.as_str() == "rltc" {
            bip32::Prefix::TPUB
        } else {
            bip32::Prefix::XPUB
        };
        let descriptor_xpub = deriver::to_descriptor_xpub(&zpub, descriptor_prefix)?;
        let descriptor = watch_only_descriptor(&descriptor_xpub);
        let wallet = Self {
            http,
            url: url.to_owned(),
            user: user.to_owned(),
            pass: pass.to_owned(),
            tip_lag_blocks,
            zpub,
            hrp,
            coin,
            store,
            descriptor,
            imported: Mutex::new(false),
        };
        // Best-effort import now; not fatal if litecoind is unreachable at
        // startup -- `health()` retries `ensure_imported` and the
        // `FailoverBackend` promotes this source once the node is back (rather
        // than disabling litecoin's node arm for the whole process lifetime).
        if let Err(e) = wallet.ensure_imported().await {
            eprintln!(
                "payments[litecoin]: watch-only import deferred ({e}); \
                 will retry once the node is reachable"
            );
        }
        Ok(wallet)
    }

    /// Import the watch-only descriptor exactly once (idempotent; safe to call
    /// on every `health()` probe): returns early once imported, else runs the
    /// legacy `importmulti` path and records success under the lock.
    async fn ensure_imported(&self) -> Result<(), PaymentError> {
        let mut done = self.imported.lock().await;
        if *done {
            return Ok(());
        }
        self.import_watch_only_descriptor().await?;
        *done = true;
        Ok(())
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
            .ok_or_else(|| PaymentError::Rpc("litecoin rpc: empty result".to_owned()))
    }

    /// Import the watch-only descriptor into the node's wallet. litecoind
    /// (0.21.x) has no descriptor wallets -- `importdescriptors` errors with
    /// "not available for non-descriptor wallets" -- so this watches the range
    /// via a legacy wallet's `importmulti` `desc` entry instead, the supported
    /// way to watch a ranged descriptor with no spend keys. `getdescriptorinfo`
    /// resolves the checksummed descriptor, then `importmulti` registers
    /// `[0, DESCRIPTOR_RANGE_END]` as watch-only with no rescan
    /// (`timestamp: "now"` -- deposit addresses are always fresh). Idempotent:
    /// re-importing reports `success: true`, so it's safe on every retry.
    async fn import_watch_only_descriptor(&self) -> Result<(), PaymentError> {
        let info: serde_json::Value = self
            .call("getdescriptorinfo", json!([self.descriptor]))
            .await
            .map_err(|e| PaymentError::Rpc(format!("getdescriptorinfo: {e}")))?;
        let canonical = info
            .get("descriptor")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| PaymentError::Rpc("getdescriptorinfo: missing descriptor".to_owned()))?;
        let request = json!([{
            "desc": canonical,
            "range": [0, DESCRIPTOR_RANGE_END],
            "timestamp": "now",
            "watchonly": true,
            "keys": [],
        }]);
        let results: serde_json::Value = self
            .call("importmulti", json!([request, {"rescan": false}]))
            .await
            .map_err(|e| PaymentError::Rpc(format!("importmulti: {e}")))?;
        check_import_results(&results)
    }
}

/// The `wpkh(<xpub>/0/*)` external-chain watch-only ranged descriptor for
/// `xpub` (no checksum — `getdescriptorinfo` computes that separately).
/// `xpub` must already be in raw BIP32 form (see
/// [`crate::deriver::to_descriptor_xpub`]) — litecoind's descriptor parser
/// rejects the SLIP-132 `zpub` prefix.
fn watch_only_descriptor(xpub: &str) -> String {
    format!("wpkh({xpub}/0/*)")
}

/// Upper bound (inclusive) of the range imported for the watch-only
/// descriptor. `active: false` means this range is fixed at import time --
/// it is not extended automatically as new indexes are handed out -- so it
/// must comfortably exceed any index `store.next_hd_index` will ever
/// hand out for this coin. 5000 addresses (`0..=4999`) is ample headroom for
/// a single deposit-address sequence.
const DESCRIPTOR_RANGE_END: u32 = 4999;

/// Validate an `importdescriptors` response: every entry must report
/// `success: true`, else the import (partially) failed.
fn check_import_results(results: &serde_json::Value) -> Result<(), PaymentError> {
    let entries = results.as_array().ok_or_else(|| {
        PaymentError::Rpc("importdescriptors: unexpected response shape".to_owned())
    })?;
    for entry in entries {
        let ok = entry
            .get("success")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if !ok {
            return Err(PaymentError::Rpc(format!(
                "importdescriptors: import failed: {entry}"
            )));
        }
    }
    Ok(())
}

/// Derive the watch-only deposit address for HD index `index` — the same
/// computation [`crate::esplora::EsploraSource::new_subaddress`] performs for
/// the identical `(zpub, index)`, so the node and remote sources watch the
/// same address.
fn derive_deposit_address(zpub: &str, hrp: Hrp, index: u32) -> Result<String, PaymentError> {
    deriver::derive_p2wpkh(zpub, hrp, index)
}

/// Reject an HD index once it falls outside the range
/// `import_watch_only_descriptor` actually imported (`[0, DESCRIPTOR_RANGE_END]`,
/// `active: false`). Past that bound the node never rescans/extends the
/// descriptor on its own, so deriving an address anyway would hand out a
/// syntactically valid but UNWATCHED address: the node source would never
/// see a deposit sent there, would never report it unhealthy, and so would
/// never fail over to a source that could. Turning this into a loud error at
/// quote-creation time is far safer than a silent lost deposit.
fn check_index_in_range(index_u32: u32) -> Result<(), PaymentError> {
    if index_u32 > DESCRIPTOR_RANGE_END {
        return Err(PaymentError::Rpc(format!(
            "hd deposit index {index_u32} exceeds watched descriptor range {DESCRIPTOR_RANGE_END}; \
             re-import with a wider range"
        )));
    }
    Ok(())
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

/// The subset of `getblockchaininfo`'s response used by `health()`.
///
/// `blocks`/`headers` are deliberately NOT `#[serde(default)]` (unlike most
/// fields in this module): a litecoind response missing either one must fail
/// to deserialize -- which the `health()` match below turns into
/// `Health::Unreachable` -- rather than silently defaulting to `0/0`, which
/// `classify_health(0, 0, _)` reads as caught-up-with-itself and reports
/// `Healthy` (fail-OPEN). BTC's `getblockchaininfo` binding is already
/// fail-safe this way (typed non-`Option<i64>` fields), so this keeps LTC's
/// health check matching BTC's: a malformed/truncated response must never be
/// mistaken for a healthy node.
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

/// Convert a positive LTC amount to litoshi (1 LTC = 1e8), rounding to nearest.
fn ltc_to_litoshi(amount: f64) -> u64 {
    if amount.is_finite() && amount > 0.0 {
        (amount * 100_000_000.0).round() as u64
    } else {
        0
    }
}

#[async_trait]
impl PaymentBackend for LitecoinWallet {
    async fn new_subaddress(&self, _label: &str) -> Result<NewSubaddress, PaymentError> {
        let index = self.store.next_hd_index(self.coin.as_str()).await?;
        let index_u32 = u32::try_from(index)
            .map_err(|_| PaymentError::Rpc("litecoin hd index overflow".into()))?;
        check_index_in_range(index_u32)?;
        let address = derive_deposit_address(&self.zpub, self.hrp, index_u32)?;
        Ok(NewSubaddress {
            address,
            index: u64::from(index_u32),
        })
    }

    async fn incoming_transfers(&self, _min_height: u64) -> Result<Vec<Transfer>, PaymentError> {
        // `listsinceblock` with no args returns every wallet transaction.
        let listed: ListSinceBlock = self.call("listsinceblock", json!([])).await?;
        Ok(listed
            .transactions
            .into_iter()
            .filter(|t| t.category == "receive")
            .map(|t| Transfer {
                txid: t.txid,
                amount_atomic: ltc_to_litoshi(t.amount),
                address: t.address,
                height: t.blockheight,
                confirmations: u64::try_from(t.confirmations).unwrap_or(0),
            })
            .collect())
    }

    async fn balance_atomic(&self) -> Result<Option<i64>, PaymentError> {
        // `getbalance` with no args returns the wallet balance as a bare LTC
        // number. litecoind's RPC is Bitcoin-Core-shaped but its response
        // types drift from what `corepc-client` expects (see module docs);
        // this takes the plain figure rather than parsing `getbalances`'
        // nested `mine`/`watchonly` shape, which is the part most likely to
        // drift between daemon versions.
        let ltc: f64 = self.call("getbalance", json!([])).await?;
        Ok(Some(to_i64(ltc_to_litoshi(ltc))))
    }

    async fn health(&self) -> Health {
        let info: BlockchainInfo = match self.call("getblockchaininfo", json!([])).await {
            Ok(info) => info,
            Err(_) => return Health::Unreachable,
        };
        // Node reachable -- ensure the watch-only range is imported before
        // reporting healthy, so `incoming_transfers` sees deposits (and a
        // litecoind that was down at boot gets imported once it returns).
        if let Err(e) = self.ensure_imported().await {
            eprintln!("payments[litecoin]: watch-only import failed ({e}); node not yet usable");
            return Health::Unreachable;
        }
        // `headers` = best-known network height, `blocks` = validated tip.
        classify_health(info.headers, info.blocks, self.tip_lag_blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MockPaymentStore;

    // zpub of the BIP84 test mnemonic "abandon abandon ... about" at m/84'/0'/0'
    // — same vector `deriver`'s own tests use.
    const BTC_TESTVEC_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    #[test]
    fn ltc_to_litoshi_rounds_and_floors() {
        assert_eq!(ltc_to_litoshi(1.0), 100_000_000);
        assert_eq!(ltc_to_litoshi(0.000_000_01), 1);
        assert_eq!(ltc_to_litoshi(0.0), 0);
        assert_eq!(ltc_to_litoshi(-1.0), 0);
        assert_eq!(ltc_to_litoshi(f64::NAN), 0);
        assert_eq!(ltc_to_litoshi(f64::INFINITY), 0);
    }

    #[test]
    fn watch_only_descriptor_wraps_zpub_in_ranged_wpkh() {
        assert_eq!(
            watch_only_descriptor(BTC_TESTVEC_ZPUB),
            format!("wpkh({BTC_TESTVEC_ZPUB}/0/*)")
        );
    }

    #[test]
    fn check_import_results_ok_when_all_succeed() {
        let v: serde_json::Value = serde_json::from_str(r#"[{"success":true}]"#).unwrap();
        assert!(check_import_results(&v).is_ok());
    }

    #[test]
    fn check_import_results_errors_when_any_entry_fails() {
        let v: serde_json::Value = serde_json::from_str(
            r#"[{"success":true},{"success":false,"error":{"message":"bad desc"}}]"#,
        )
        .unwrap();
        assert!(check_import_results(&v).is_err());
    }

    #[test]
    fn check_import_results_errors_on_non_array_response() {
        let v: serde_json::Value = serde_json::from_str(r#"{"success":true}"#).unwrap();
        assert!(check_import_results(&v).is_err());
    }

    #[test]
    fn blockchain_info_parse_feeds_classify_health() {
        let raw = r#"{"blocks":100,"headers":110}"#;
        let info: BlockchainInfo = serde_json::from_str(raw).unwrap();
        assert_eq!(
            classify_health(info.headers, info.blocks, 5),
            Health::Lagging(10)
        );
    }

    #[test]
    fn blockchain_info_missing_fields_fails_to_deserialize() {
        let empty = serde_json::from_str::<BlockchainInfo>("{}");
        assert!(
            empty.is_err(),
            "a response missing blocks/headers must not silently deserialize to 0/0"
        );

        let missing_headers = serde_json::from_str::<BlockchainInfo>(r#"{"blocks":100}"#);
        assert!(missing_headers.is_err());

        let missing_blocks = serde_json::from_str::<BlockchainInfo>(r#"{"headers":100}"#);
        assert!(missing_blocks.is_err());
    }

    #[test]
    fn rpc_envelope_with_incomplete_blockchain_info_fails_to_deserialize() {
        let raw = r#"{"result":{"blocks":100},"error":null,"id":"socks"}"#;
        let env = serde_json::from_str::<RpcEnvelope<BlockchainInfo>>(raw);
        assert!(
            env.is_err(),
            "a truncated getblockchaininfo result must not deserialize into a usable BlockchainInfo"
        );
    }

    #[test]
    fn rpc_envelope_parses_bare_string_result() {
        let env: RpcEnvelope<String> =
            serde_json::from_str(r#"{"result":"ltc1qxyz","error":null,"id":"socks"}"#).unwrap();
        assert_eq!(env.result.unwrap(), "ltc1qxyz");
    }

    #[test]
    fn listsinceblock_keeps_only_receives() {
        let raw = r#"{"transactions":[
            {"category":"receive","amount":0.5,"address":"ltc1a","txid":"t1","blockheight":42,"confirmations":3},
            {"category":"send","amount":-0.1,"address":"ltc1b","txid":"t2","blockheight":42,"confirmations":3}
        ],"lastblock":"00"}"#;
        let listed: ListSinceBlock = serde_json::from_str(raw).unwrap();
        let recvs: Vec<_> = listed
            .transactions
            .into_iter()
            .filter(|t| t.category == "receive")
            .collect();
        assert_eq!(recvs.len(), 1);
        assert_eq!(recvs[0].txid, "t1");
        assert_eq!(ltc_to_litoshi(recvs[0].amount), 50_000_000);
    }

    #[test]
    fn getbalance_parses_bare_number() {
        let env: RpcEnvelope<f64> =
            serde_json::from_str(r#"{"result":12.5,"error":null,"id":"socks"}"#).unwrap();
        assert_eq!(env.result.unwrap(), 12.5);
        assert_eq!(ltc_to_litoshi(env.result.unwrap()), 1_250_000_000);
    }

    #[test]
    fn rpc_error_is_surfaced() {
        let env: RpcEnvelope<String> = serde_json::from_str(
            r#"{"result":null,"error":{"code":-5,"message":"Invalid address"},"id":"socks"}"#,
        )
        .unwrap();
        assert!(env.result.is_none());
        assert_eq!(env.error.unwrap().message, "Invalid address");
    }

    #[test]
    fn new_subaddress_derivation_matches_esplora_source() {
        let hrp = Hrp::parse("ltc").unwrap();
        let expected = "ltc1qcr8te4kr609gcawutmrza0j4xv80jy8z4nqduv";
        let got = derive_deposit_address(BTC_TESTVEC_ZPUB, hrp, 0).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn check_index_in_range_ok_at_and_below_bound_errs_above() {
        assert!(check_index_in_range(0).is_ok());
        assert!(check_index_in_range(DESCRIPTOR_RANGE_END).is_ok());
        let err = check_index_in_range(DESCRIPTOR_RANGE_END + 1)
            .expect_err("an index past the watched descriptor range must error, not derive");
        let msg = err.to_string();
        assert!(msg.contains(&(DESCRIPTOR_RANGE_END + 1).to_string()));
        assert!(msg.contains("exceeds watched descriptor range"));
    }

    #[tokio::test]
    async fn test_litecoin_wallet_new_subaddress_with_mock_store() {
        let store = Arc::new(MockPaymentStore::new());
        let hrp = Hrp::parse("ltc").unwrap();
        let wallet = LitecoinWallet::connect_watch_only(
            "http://127.0.0.1:19332",
            "user",
            "pass",
            BTC_TESTVEC_ZPUB,
            hrp,
            Coin::Litecoin,
            5,
            store.clone(),
        )
        .await
        .unwrap();

        let sub1 = wallet.new_subaddress("order1").await.unwrap();
        assert_eq!(sub1.index, 0);
        assert_eq!(sub1.address, "ltc1qcr8te4kr609gcawutmrza0j4xv80jy8z4nqduv");

        let sub2 = wallet.new_subaddress("order2").await.unwrap();
        assert_eq!(sub2.index, 1);
        assert_ne!(sub2.address, sub1.address);
    }
}
