//! Bitcoin Core JSON-RPC implementation of [`PaymentBackend`] — watch-only.
//!
//! `corepc-client` is a blocking client, so each RPC runs on a blocking thread
//! via [`tokio::task::spawn_blocking`]. Amounts come back in BTC (`f64`) and are
//! converted to satoshis — the atomic unit the crediting math expects.
//!
//! This backend does not mint deposit addresses from the node's hot wallet
//! (`getnewaddress`). Instead it holds a watch-only BIP84 account zpub and
//! derives deposit addresses in-process via [`crate::deriver::derive_p2wpkh`]
//! — the exact computation [`crate::esplora::EsploraSource`] performs for the
//! same `(zpub, index)` — so the node source and the Esplora remote source
//! watch the identical address for a given HD index, keeping failover between
//! them transparent. On connect, the zpub is converted to a plain BIP32 xpub
//! (Core's descriptor parser rejects the SLIP-132 `zpub` prefix — see
//! [`crate::deriver::to_descriptor_xpub`]) and imported into the node's
//! wallet as a watch-only ranged descriptor (`wpkh(<xpub>/0/*)`, no private
//! keys) over a fixed index range, so `listsinceblock`/`getbalances` (used
//! unchanged by `incoming_transfers`/`balance_atomic`) pick up funds sent to
//! any address this service derives.

use std::sync::Arc;

use async_trait::async_trait;
use bech32::Hrp;
use corepc_client::client_sync::v28::Client;
use corepc_client::client_sync::Auth;
use corepc_client::types::v28::{GetBalances, TransactionCategory};
use serde_json::json;
use tokio::sync::Mutex;

use crate::backend::PaymentBackend;
use crate::coin::Coin;
use crate::deriver;
use crate::error::PaymentError;
use crate::store::PaymentStore;
use crate::types::{classify_health, to_i64, Health, NewSubaddress, Transfer};

/// A live Bitcoin Core node reached over JSON-RPC (user/pass auth),
/// watch-only: deposit addresses are derived in-process from a BIP84 zpub,
/// never minted by the node's own wallet.
pub struct BitcoinWallet {
    client: Arc<Client>,
    /// Number of blocks the validated tip may trail the best-known header
    /// before `health()` reports `Lagging` instead of `Healthy`.
    tip_lag_blocks: u64,
    /// Watch-only BIP84 account zpub; deposit addresses are its `/0/i` children.
    zpub: String,
    /// Bech32 HRP for the address' network: `bc` (mainnet BTC).
    hrp: Hrp,
    coin: Coin,
    store: Arc<dyn PaymentStore>,
    /// The `wpkh(<xpub>/0/*)` watch-only descriptor to import, computed once at
    /// connect (the zpub is converted to a plain xpub -- see
    /// [`crate::deriver::to_descriptor_xpub`]).
    descriptor: String,
    /// Whether the watch-only descriptor has been imported into the node's
    /// wallet yet. The import is best-effort at connect and retried by
    /// `health()`, so a node that's unreachable at startup still gets its
    /// descriptor imported (and is promoted back by the `FailoverBackend`)
    /// once it comes up -- rather than being disabled for the process lifetime.
    imported: Mutex<bool>,
}

impl BitcoinWallet {
    /// Connect to a Bitcoin Core node's JSON-RPC endpoint and import `zpub`
    /// (converted to a plain BIP32 xpub — see [`crate::deriver::to_descriptor_xpub`])
    /// as a watch-only descriptor, so the node's wallet tracks every deposit
    /// address this service will ever derive from it (`wpkh(<xpub>/0/*)`).
    /// `tip_lag_blocks` is the max acceptable gap between the validated tip
    /// and the best-known header before `health()` reports the node as
    /// lagging. `store` provides the per-coin HD deposit-index counter
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
        let client = Client::new_with_auth(url, Auth::UserPass(user.to_owned(), pass.to_owned()))
            .map_err(|e| PaymentError::Rpc(e.to_string()))?;
        let client = Arc::new(client);
        let zpub = zpub.trim().to_owned();
        // Bitcoin Core's descriptor parser only accepts the raw BIP32 `xpub`
        // version bytes, not the SLIP-132 `zpub` display prefix -- see
        // `deriver::to_descriptor_xpub`. `self.zpub` below stays the
        // original zpub; only the string handed to the node is converted.
        // `hrp` already carries the network the caller wants ("bc" mainnet
        // vs "bcrt" regtest), so it's also the right signal for which descriptor-key
        // prefix a node on that network will actually accept.
        let descriptor_prefix = if hrp.as_str() == "bcrt" {
            bip32::Prefix::TPUB
        } else {
            bip32::Prefix::XPUB
        };
        let descriptor_xpub = deriver::to_descriptor_xpub(&zpub, descriptor_prefix)?;
        let descriptor = watch_only_descriptor(&descriptor_xpub);
        let wallet = Self {
            client,
            tip_lag_blocks,
            zpub,
            hrp,
            coin,
            store,
            descriptor,
            imported: Mutex::new(false),
        };
        // Best-effort import now, but do NOT fail construction if the node is
        // unreachable at startup: `health()` retries `ensure_imported`, and the
        // `FailoverBackend` promotes this source once the node is back. A hard
        // failure here would leave the backend with no node arm at all,
        // so a node merely down at boot would run nodeless for the whole
        // process lifetime -- the boot-degraded gap this closes.
        if let Err(e) = wallet.ensure_imported().await {
            eprintln!(
                "payments[bitcoin]: watch-only import deferred ({e}); \
                 will retry once the node is reachable"
            );
        }
        Ok(wallet)
    }

    /// Import the watch-only descriptor into the node's wallet exactly once.
    /// Idempotent and cheap to call on every `health()` probe: returns early
    /// once imported, else runs `getdescriptorinfo`+`importdescriptors` (which
    /// Core itself treats as idempotent) and records success under the lock.
    async fn ensure_imported(&self) -> Result<(), PaymentError> {
        let mut done = self.imported.lock().await;
        if *done {
            return Ok(());
        }
        let client = Arc::clone(&self.client);
        let descriptor = self.descriptor.clone();
        tokio::task::spawn_blocking(move || import_watch_only_descriptor(&client, &descriptor))
            .await
            .map_err(|e| PaymentError::Rpc(e.to_string()))??;
        *done = true;
        Ok(())
    }
}

/// The `wpkh(<xpub>/0/*)` external-chain watch-only ranged descriptor for
/// `xpub` (no checksum — `getdescriptorinfo` computes that separately).
/// `xpub` must already be in raw BIP32 form (see
/// [`crate::deriver::to_descriptor_xpub`]) — Core's descriptor parser
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

/// Import `descriptor` (as built by [`watch_only_descriptor`]) into the
/// node's wallet as a watch-only descriptor: `getdescriptorinfo` computes its
/// checksum, then `importdescriptors` imports `<descriptor>#<checksum>` as an
/// inactive, external (non-change) descriptor over `[0, DESCRIPTOR_RANGE_END]`
/// with no rescan (`timestamp: "now"` — deposit addresses are always fresh,
/// never used before this service derived them). `range` is required by Core
/// for a ranged descriptor (`.../0/*`) — omitting it makes the very first
/// `importdescriptors` call error out.
///
/// Both calls go through the generic untyped `Client::call`: the installed
/// `corepc-client` v0.16 (v28 RPC surface)'s typed `get_descriptor_info`
/// result (`corepc_types::v18::GetDescriptorInfo`) omits the `checksum` field
/// this needs, and its typed `ImportDescriptorsRequest`
/// (`corepc_client::client_sync::v21::ImportDescriptorsRequest`) only has
/// `desc`/`timestamp` fields — no `range`/`active`/`internal` — so neither
/// typed helper can express this request.
///
/// Re-importing the same descriptor is idempotent (Bitcoin Core reports
/// `success: true` for an already-imported descriptor), so this is safe to
/// run on every `connect_watch_only` call/restart.
fn import_watch_only_descriptor(client: &Client, descriptor: &str) -> Result<(), PaymentError> {
    let info: serde_json::Value = client
        .call("getdescriptorinfo", &[json!(descriptor)])
        .map_err(|e| PaymentError::Rpc(format!("getdescriptorinfo: {e}")))?;
    let checksum = info
        .get("checksum")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| PaymentError::Rpc("getdescriptorinfo: missing checksum".to_owned()))?;
    let request = json!([{
        "desc": format!("{descriptor}#{checksum}"),
        "range": [0, DESCRIPTOR_RANGE_END],
        "timestamp": "now",
        "active": false,
        "internal": false,
    }]);
    let results: serde_json::Value = client
        .call("importdescriptors", &[request])
        .map_err(|e| PaymentError::Rpc(format!("importdescriptors: {e}")))?;
    check_import_results(&results)
}

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

/// Convert a positive BTC amount to satoshis, rounding to the nearest sat.
fn btc_to_sats(amount: f64) -> u64 {
    if amount.is_finite() && amount > 0.0 {
        (amount * 100_000_000.0).round() as u64
    } else {
        0
    }
}

#[async_trait]
impl PaymentBackend for BitcoinWallet {
    async fn new_subaddress(&self, _label: &str) -> Result<NewSubaddress, PaymentError> {
        let index = self.store.next_hd_index(self.coin.as_str()).await?;
        let index_u32 = u32::try_from(index)
            .map_err(|_| PaymentError::Rpc("bitcoin hd index overflow".into()))?;
        check_index_in_range(index_u32)?;
        let address = derive_deposit_address(&self.zpub, self.hrp, index_u32)?;
        Ok(NewSubaddress {
            address,
            index: u64::from(index_u32),
        })
    }

    async fn incoming_transfers(&self, _min_height: u64) -> Result<Vec<Transfer>, PaymentError> {
        let client = Arc::clone(&self.client);
        let listed = tokio::task::spawn_blocking(move || client.list_since_block())
            .await
            .map_err(|e| PaymentError::Rpc(e.to_string()))?
            .map_err(|e| PaymentError::Rpc(e.to_string()))?;

        let transfers = listed
            .transactions
            .into_iter()
            .filter(|t| t.category == TransactionCategory::Receive)
            .map(|t| Transfer {
                txid: t.txid,
                amount_atomic: btc_to_sats(t.amount),
                address: t.address.unwrap_or_default(),
                height: t
                    .block_height
                    .and_then(|h| u64::try_from(h).ok())
                    .unwrap_or(0),
                confirmations: u64::try_from(t.confirmations).unwrap_or(0),
            })
            .collect();
        Ok(transfers)
    }

    async fn balance_atomic(&self) -> Result<Option<i64>, PaymentError> {
        let client = Arc::clone(&self.client);
        let balances: GetBalances = tokio::task::spawn_blocking(move || client.get_balances())
            .await
            .map_err(|e| PaymentError::Rpc(e.to_string()))?
            .map_err(|e| PaymentError::Rpc(e.to_string()))?;
        // `mine.trusted` is the confirmed, spendable balance (excludes
        // untrusted-pending/immature), the same "safe to count" balance
        // `getbalance`'s default args report.
        Ok(Some(to_i64(btc_to_sats(balances.mine.trusted))))
    }

    async fn health(&self) -> Health {
        let client = Arc::clone(&self.client);
        // Use the untyped `call` here, not the typed `get_blockchain_info()`:
        // the installed corepc v28 `GetBlockchainInfo` models `warnings` as a
        // `Vec<String>` (its shape from Core v29 on), but a Core v25 node
        // returns `warnings` as a plain string, so the typed call fails to
        // deserialize and `health()` would report a fully-synced node as
        // `Unreachable` on every probe -- permanently parking failover on the
        // remote source. Only `headers`/`blocks` are needed, and both are
        // stable across versions, so read them from the raw JSON instead.
        let raw = tokio::task::spawn_blocking(move || {
            client.call::<serde_json::Value>("getblockchaininfo", &[])
        })
        .await;
        // `headers` = best-known network height, `blocks` = validated tip; both
        // `i64` in `getblockchaininfo`'s response.
        let info = match raw {
            Ok(Ok(info)) => info,
            _ => return Health::Unreachable,
        };
        let (headers, blocks) = match (
            info.get("headers").and_then(serde_json::Value::as_i64),
            info.get("blocks").and_then(serde_json::Value::as_i64),
        ) {
            (Some(headers), Some(blocks)) => (headers, blocks),
            _ => return Health::Unreachable,
        };
        // Node reachable -- make sure the watch-only descriptor is imported
        // before reporting healthy, so `incoming_transfers` actually sees
        // deposits (and a node that was down at boot gets imported the moment
        // it returns, then promoted by the `FailoverBackend`).
        if let Err(e) = self.ensure_imported().await {
            eprintln!("payments[bitcoin]: watch-only import failed ({e}); node not yet usable");
            return Health::Unreachable;
        }
        classify_health(headers, blocks, self.tip_lag_blocks)
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
    fn btc_to_sats_rounds_and_floors() {
        assert_eq!(btc_to_sats(1.0), 100_000_000);
        assert_eq!(btc_to_sats(0.000_000_01), 1);
        assert_eq!(btc_to_sats(0.0), 0);
        assert_eq!(btc_to_sats(-1.0), 0);
        assert_eq!(btc_to_sats(f64::NAN), 0);
        assert_eq!(btc_to_sats(f64::INFINITY), 0);
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
    fn new_subaddress_derivation_matches_esplora_source() {
        let hrp = Hrp::parse("bc").unwrap();
        // BIP84 test vector: m/84'/0'/0'/0/0 -> bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
        let expected = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
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
    async fn test_bitcoin_wallet_new_subaddress_with_mock_store() {
        let store = Arc::new(MockPaymentStore::new());
        let hrp = Hrp::parse("bc").unwrap();
        let wallet = BitcoinWallet::connect_watch_only(
            "http://127.0.0.1:18443",
            "user",
            "pass",
            BTC_TESTVEC_ZPUB,
            hrp,
            Coin::Bitcoin,
            5,
            store.clone(),
        )
        .await
        .unwrap();

        let sub1 = wallet.new_subaddress("order1").await.unwrap();
        assert_eq!(sub1.index, 0);
        assert_eq!(sub1.address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");

        let sub2 = wallet.new_subaddress("order2").await.unwrap();
        assert_eq!(sub2.index, 1);
        assert_ne!(sub2.address, sub1.address);
    }
}
