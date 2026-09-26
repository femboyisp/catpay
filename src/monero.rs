//! `monero-wallet-rpc` client (thin, hand-rolled JSON-RPC).
//!
//! The typed `monero-rpc` crate (0.5.0, the latest published) can't decode
//! monerod v0.18 wallet responses, so this speaks the wallet's JSON-RPC directly
//! and parses only the fields the poller needs — robust against daemon drift.
//!
//! **Key custody:** the wallet this connects to holds only the account's
//! secret *view* key — the *spend* key lives on the operator's Trezor
//! hardware wallet and never touches this server. That means this process
//! (and `monero-wallet-rpc` itself) can watch incoming transfers and report
//! balances, but a compromised server can never move funds: detection and
//! spending are on physically separate trust boundaries.
//!
//! **Daemon failover:** `monero-wallet-rpc` has no `get_info` method (that's
//! a monerod-only RPC) — the wallet only ever tells you its own scanned
//! height (`get_height`), never the daemon's sync status. So the
//! local/remote daemon swing ([`DaemonSwing`]) probes the local `monerod`
//! directly (its own `get_info`, independent of whichever daemon the wallet
//! is currently pointed at via `set_daemon`), with the same
//! probe/hysteresis/flip shape as [`crate::failover::FailoverBackend`].

use std::sync::Arc;

use async_trait::async_trait;
use reqwest::Client as HttpClient;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;

use crate::backend::PaymentBackend;
use crate::coin::Coin;
use crate::error::PaymentError;
use crate::types::{classify_health, to_i64, Health, NewSubaddress, Transfer};

/// Default max acceptable gap between a daemon's own height and its target
/// height before [`RpcDaemonProbe`] reports `Lagging`. A literal for now
/// (Task 8 scope); Task 9 wires this from config the same way BTC/LTC read
/// `[payments.*.failover].tip_lag_blocks`.
const DEFAULT_TIP_LAG_BLOCKS: u64 = 3;

/// Default consecutive-probe hysteresis, matching `FailoverConfig`'s own
/// defaults (`default_failover_hysteresis`).
const DEFAULT_SWING_HYSTERESIS: u32 = 3;

/// Probes a daemon's reachability/sync status, independent of any
/// `MoneroWallet`. Exists as a trait (rather than a concrete method) so
/// [`DaemonSwing`]'s hysteresis can be unit-tested against a scripted
/// sequence, the same way `FailoverBackend`'s tests script
/// `PaymentBackend::health`.
#[async_trait]
trait DaemonProbe: Send + Sync {
    async fn probe(&self) -> Health;
}

/// Sends a daemon's `set_daemon` RPC via some wallet-rpc connection.
/// Factored out from [`MoneroWallet::switch_daemon`] as its own trait (rather
/// than `DaemonSwing` holding a reference back to the `MoneroWallet` that
/// owns it, which would be self-referential) so [`DaemonSwing`]'s flip
/// behavior is unit-testable with a recording mock.
#[async_trait]
trait DaemonSwitch: Send + Sync {
    async fn switch(&self, address: &str) -> Result<(), PaymentError>;
}

/// [`DaemonProbe`] that calls the real monerod `get_info` RPC directly
/// (*not* through `monero-wallet-rpc` — see the module doc for why).
struct RpcDaemonProbe {
    http: HttpClient,
    /// The daemon's JSON-RPC URL, derived from a bare `host:port` address by
    /// [`daemon_probe_url`] -- e.g. `http://127.0.0.1:18081/json_rpc`.
    url: String,
    tip_lag_blocks: u64,
}

/// Normalize a daemon address into the JSON-RPC URL [`RpcDaemonProbe`] posts
/// `get_info` to: add an `http://` scheme unless one is already present, and
/// append `/json_rpc` unless it's already there. `addr` is normally the bare
/// `host:port` form `with_daemon_swing`'s callers pass (and what `set_daemon`
/// itself needs -- see its doc), but a full URL passed by habit is tolerated
/// rather than silently producing a broken double path.
///
/// This exists specifically because the bare `host:port` address used for
/// `set_daemon` and the full URL a probe needs to POST to are two different
/// things derived from the *same* configured address -- conflating them (an
/// earlier version of this file stored a full URL in the field `set_daemon`
/// also read from) meant a successful swing to remote worked fine but the
/// swing back to local sent a malformed `.../json_rpc` string as
/// `set_daemon`'s `address` param, which the wallet-rpc rejects, which
/// rolled the flip back every single tick -- a silent, permanent stick on
/// remote. See `daemon_probe_url_*` tests and
/// `with_daemon_swing_probes_full_url_and_switches_bare_address` below.
fn daemon_probe_url(addr: &str) -> String {
    let trimmed = addr.trim_end_matches('/');
    let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_owned()
    } else {
        format!("http://{trimmed}")
    };
    if with_scheme.ends_with("/json_rpc") {
        with_scheme
    } else {
        format!("{with_scheme}/json_rpc")
    }
}

/// The `get_info` JSON-RPC request body [`RpcDaemonProbe`] sends -- pulled
/// into its own function so the exact method name/params shape is
/// unit-testable. This is the request half of the Task 8 review's Critical
/// finding: a wrong method name here would pass every response-parsing test
/// and only fail against a live daemon.
fn get_info_request() -> serde_json::Value {
    json!({ "jsonrpc": "2.0", "id": "0", "method": "get_info", "params": {} })
}

#[async_trait]
impl DaemonProbe for RpcDaemonProbe {
    async fn probe(&self) -> Health {
        let body = get_info_request();
        let sent = self.http.post(&self.url).json(&body).send().await;
        let parsed: Result<RpcEnvelope<GetInfo>, PaymentError> = match sent {
            Ok(resp) => resp
                .json()
                .await
                .map_err(|e| PaymentError::Rpc(e.to_string())),
            Err(e) => Err(PaymentError::Rpc(e.to_string())),
        };
        match parsed {
            Ok(RpcEnvelope {
                result: Some(info),
                error: None,
            }) => classify_daemon_health(info.height, info.target_height, self.tip_lag_blocks),
            _ => Health::Unreachable,
        }
    }
}

/// [`DaemonSwitch`] that POSTs `set_daemon` to a `monero-wallet-rpc`
/// endpoint. Holds its own `(http, url)` rather than borrowing the
/// `MoneroWallet` it swings, for the same self-reference reason as
/// [`DaemonSwitch`] itself — cheap, since `reqwest::Client` clones an `Arc`
/// internally and `url` is the same string `MoneroWallet` already has.
struct WalletRpcSwitch {
    http: HttpClient,
    wallet_rpc_url: String,
}

#[async_trait]
impl DaemonSwitch for WalletRpcSwitch {
    async fn switch(&self, address: &str) -> Result<(), PaymentError> {
        call_set_daemon(&self.http, &self.wallet_rpc_url, address).await
    }
}

/// Mutable hysteresis state behind [`DaemonSwing`]'s mutex: which daemon is
/// currently selected, and the current consecutive healthy/unhealthy streaks
/// for the local daemon's probe. Mirrors `failover::FoState`.
struct SwingState {
    /// `true` while the local daemon is selected; `false` while on remote.
    on_local: bool,
    local_ok_streak: u32,
    local_fail_streak: u32,
}

/// Swings a wallet's daemon between `local_addr` and `remote_addr` (via a
/// [`DaemonSwitch`]) based on a hysteresis-smoothed probe ([`DaemonProbe`])
/// of the **local** daemon's health — probed directly and independently of
/// whichever daemon the wallet currently happens to be pointed at, so the
/// decision never depends on (and can't oscillate with) the wallet's own
/// current selection. Same shape as
/// [`crate::failover::FailoverBackend`]'s hysteresis: `to_fallback_after`/
/// `to_primary_after` consecutive probes before a flip, same
/// `detection_source`/`detection_source_switch_total` metrics.
struct DaemonSwing {
    probe: Arc<dyn DaemonProbe>,
    switch: Arc<dyn DaemonSwitch>,
    local_addr: String,
    remote_addr: String,
    to_fallback_after: u32,
    to_primary_after: u32,
    state: Mutex<SwingState>,
}

impl DaemonSwing {
    /// One poll tick: probe the local daemon, update the hysteresis streaks,
    /// and — only on a confirmed flip (a streak crossing its threshold) —
    /// call `switch` with the newly-selected daemon's address; `set_daemon`
    /// is never called on a tick that doesn't flip. `state` stays locked for
    /// the whole probe-decide-switch sequence: switches are rare, and
    /// `signup::quote_status` can call `incoming_transfers` on this same
    /// wallet concurrently with the poller, so holding the lock across the
    /// `switch().await` is what stops two concurrent callers from deciding
    /// to flip at once (double-swinging) or disagreeing about `on_local`
    /// after only one of them's `set_daemon` actually lands. If `switch`
    /// itself fails, the flip is rolled back (state reverts to the previous
    /// selection) so `on_local` never desyncs from the wallet's real
    /// daemon — the same flip is simply retried next tick, since the streak
    /// that triggered it is still at/over threshold.
    async fn refresh(&self) {
        let healthy = matches!(self.probe.probe().await, Health::Healthy);
        let mut state = self.state.lock().await;
        if healthy {
            state.local_ok_streak += 1;
            state.local_fail_streak = 0;
        } else {
            state.local_fail_streak += 1;
            state.local_ok_streak = 0;
        }
        let was_on_local = state.on_local;
        if state.on_local && state.local_fail_streak >= self.to_fallback_after {
            state.on_local = false;
        } else if !state.on_local && state.local_ok_streak >= self.to_primary_after {
            state.on_local = true;
        }
        if was_on_local != state.on_local {
            let target = if state.on_local {
                &self.local_addr
            } else {
                &self.remote_addr
            };
            match self.switch.switch(target).await {
                Ok(()) => {
                    metrics::counter!("detection_source_switch_total",
                        "coin" => Coin::Monero.as_str().to_string())
                    .increment(1);
                    eprintln!(
                        "payments[monero]: detection source -> {}",
                        if state.on_local { "local" } else { "remote" }
                    );
                }
                Err(e) => {
                    // A silent rollback here is exactly how a permanently
                    // stuck swing (e.g. the bare-address/URL mixup this
                    // function's doc warns about) would hide in prod --
                    // always log it.
                    state.on_local = was_on_local;
                    eprintln!(
                        "payments[monero]: set_daemon to {target} failed ({e}); rolled back, \
                         staying on {}",
                        if was_on_local { "local" } else { "remote" }
                    );
                }
            }
        }
        metrics::gauge!("detection_source",
            "coin" => Coin::Monero.as_str().to_string())
        .set(if state.on_local { 0.0 } else { 1.0 });
    }
}

/// A live Monero wallet, reached over `monero-wallet-rpc`'s JSON-RPC endpoint.
pub struct MoneroWallet {
    http: HttpClient,
    /// Full JSON-RPC URL, e.g. `http://127.0.0.1:18083/json_rpc`.
    url: String,
    account_index: u32,
    swing: Option<DaemonSwing>,
}

impl MoneroWallet {
    /// Connect to a `monero-wallet-rpc` instance at `url`. Daemon failover is
    /// disabled by default -- call [`Self::with_daemon_swing`] to enable it.
    pub fn connect(url: &str, account_index: u32) -> Result<Self, PaymentError> {
        let http = HttpClient::builder()
            .build()
            .map_err(|e| PaymentError::Rpc(e.to_string()))?;
        Ok(Self {
            http,
            url: url.to_owned(),
            account_index,
            swing: None,
        })
    }

    /// Enable local/remote daemon failover: every `incoming_transfers` poll
    /// probes the local daemon directly (monerod's own `get_info`, *not*
    /// through this wallet-rpc — see the module doc) and swings this
    /// wallet's daemon (via `set_daemon`) to `remote_addr` after
    /// `to_fallback_after` consecutive unhealthy probes, back to
    /// `local_addr` after `to_primary_after` consecutive healthy ones.
    ///
    /// `local_addr`/`remote_addr` are **bare `host:port` daemon addresses**
    /// (e.g. `127.0.0.1:18081`) -- the same form `set_daemon`'s `address`
    /// param takes (see [`Self::switch_daemon`]'s doc), and what
    /// `MoneroConfig::local_daemon`/`remote_daemon` naturally hold. They're
    /// stored as-is and used directly as `set_daemon`'s target; the probe's
    /// own JSON-RPC URL is derived from `local_addr` via [`daemon_probe_url`],
    /// *not* stored as a second, separately-passed URL -- see that function's
    /// doc for why conflating the two forms was exactly the bug this shape
    /// fixes.
    ///
    /// Called from `main` via `payments::build_monero_backend`, which reads
    /// `remote_daemon`/`local_daemon` from config and only enables the swing
    /// when both are set.
    pub fn with_daemon_swing(
        mut self,
        local_addr: impl Into<String>,
        remote_addr: impl Into<String>,
    ) -> Self {
        let local_addr = local_addr.into();
        let probe = Arc::new(RpcDaemonProbe {
            http: self.http.clone(),
            url: daemon_probe_url(&local_addr),
            tip_lag_blocks: DEFAULT_TIP_LAG_BLOCKS,
        });
        let switch = Arc::new(WalletRpcSwitch {
            http: self.http.clone(),
            wallet_rpc_url: self.url.clone(),
        });
        self.swing = Some(DaemonSwing {
            probe,
            switch,
            local_addr,
            remote_addr: remote_addr.into(),
            to_fallback_after: DEFAULT_SWING_HYSTERESIS,
            to_primary_after: DEFAULT_SWING_HYSTERESIS,
            state: Mutex::new(SwingState {
                on_local: true,
                local_ok_streak: 0,
                local_fail_streak: 0,
            }),
        });
        self
    }

    /// Point the wallet at a different daemon via `set_daemon`
    /// (`{"address": <addr>}`), so subsequent RPCs (`get_height`,
    /// `get_transfers`, ...) are answered by the daemon at `address`.
    /// `address` is `set_daemon`'s bare `host:port` form -- the *same* form
    /// [`Self::with_daemon_swing`]'s `local_addr`/`remote_addr` take (they
    /// agree; `RpcDaemonProbe` derives its own full JSON-RPC URL from that
    /// bare form separately, via [`daemon_probe_url`], rather than either
    /// side reusing the other's representation). Called directly by callers
    /// who want manual control; the swing itself goes through
    /// [`WalletRpcSwitch`], which shares this same underlying RPC via
    /// [`call_set_daemon`].
    #[allow(dead_code, clippy::allow_attributes)]
    pub async fn switch_daemon(&self, address: &str) -> Result<(), PaymentError> {
        call_set_daemon(&self.http, &self.url, address).await
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, PaymentError> {
        let body = json!({ "jsonrpc": "2.0", "id": "0", "method": method, "params": params });
        let envelope: RpcEnvelope<T> = self
            .http
            .post(&self.url)
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
            .ok_or_else(|| PaymentError::Rpc("monero rpc: empty result".to_owned()))
    }
}

/// The `set_daemon` JSON-RPC request body [`call_set_daemon`] sends -- see
/// [`get_info_request`]'s doc comment for why this is its own function
/// rather than an inline literal.
fn set_daemon_request(address: &str) -> serde_json::Value {
    json!({ "jsonrpc": "2.0", "id": "0", "method": "set_daemon",
        "params": { "address": address } })
}

/// Shared implementation behind [`MoneroWallet::switch_daemon`] and
/// [`WalletRpcSwitch`]: POST `set_daemon` to a wallet-rpc endpoint. A free
/// function (not a `MoneroWallet` method) so `WalletRpcSwitch` can call it
/// without holding a reference back to the wallet it belongs to.
async fn call_set_daemon(
    http: &HttpClient,
    wallet_rpc_url: &str,
    address: &str,
) -> Result<(), PaymentError> {
    let body = set_daemon_request(address);
    let envelope: RpcEnvelope<serde_json::Value> = http
        .post(wallet_rpc_url)
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
    // The response is a plain `{"status":"OK"}`-shaped object; only its
    // presence (not its content) matters here.
    envelope
        .result
        .map(|_: serde_json::Value| ())
        .ok_or_else(|| PaymentError::Rpc("monero rpc: empty result".to_owned()))
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
struct CreateAddress {
    address: String,
    address_index: u32,
}

#[derive(Deserialize, Default)]
struct GetTransfers {
    /// Incoming transfers; absent (defaulted to empty) when there are none.
    #[serde(default, rename = "in")]
    incoming: Vec<TransferEntry>,
}

#[derive(Deserialize)]
struct GetBalance {
    /// Atomic units (piconero). This is the *total* balance: `get_balance`
    /// also returns `unlocked_balance` (spendable now, excludes outputs still
    /// inside the 10-block lock window), which reads lower than this field
    /// whenever a recent deposit hasn't unlocked yet.
    balance: u64,
}

#[derive(Deserialize)]
struct TransferEntry {
    txid: String,
    /// Atomic units (piconero).
    amount: u64,
    #[serde(default)]
    address: String,
    #[serde(default)]
    height: u64,
    #[serde(default)]
    confirmations: u64,
}

/// `get_height`'s response (`monero-wallet-rpc`): the wallet's own scanned
/// height. Used only for a bare reachability check in [`MoneroWallet::health`]
/// -- wallet-rpc has no way to tell us the daemon's sync target (see the
/// module doc), so that comparison isn't possible from this RPC alone.
#[derive(Deserialize)]
struct GetHeight {
    #[allow(dead_code, clippy::allow_attributes)]
    height: u64,
}

/// `get_info`'s response (a subset), from a **monerod** daemon RPC directly
/// -- `monero-wallet-rpc` does not have a `get_info` method. `height` is the
/// daemon's own blockchain height; `target_height` is the height it's
/// syncing towards, reported as `0` ("at tip") once fully synced rather than
/// `target_height == height`. See [`classify_daemon_health`], which handles
/// that without a special case. `#[serde(default)]` on `target_height`
/// since some daemon versions omit it entirely once synced.
#[derive(Deserialize)]
struct GetInfo {
    #[serde(default)]
    height: u64,
    #[serde(default)]
    target_height: u64,
}

/// Decide a daemon's [`Health`] from its own `get_info` response: `height`
/// (its blockchain height) vs `target_height` (the height it's syncing
/// towards), via [`crate::classify_health`]'s `headers`/`blocks` lag math --
/// no `target_height == 0` special case needed, because
/// `u64::try_from(0i64.saturating_sub(height as i64)).unwrap_or(0)` is `0`
/// for any `height >= 0` (the negative subtraction fails the `u64`
/// conversion and clamps to zero via `unwrap_or`), which is exactly the "at
/// tip" reading a fully-synced daemon should produce.
fn classify_daemon_health(height: u64, target_height: u64, threshold: u64) -> Health {
    classify_health(to_i64(target_height), to_i64(height), threshold)
}

#[async_trait]
impl PaymentBackend for MoneroWallet {
    async fn new_subaddress(&self, label: &str) -> Result<NewSubaddress, PaymentError> {
        let created: CreateAddress = self
            .call(
                "create_address",
                json!({ "account_index": self.account_index, "label": label }),
            )
            .await?;
        Ok(NewSubaddress {
            address: created.address,
            index: u64::from(created.address_index),
        })
    }

    async fn incoming_transfers(&self, _min_height: u64) -> Result<Vec<Transfer>, PaymentError> {
        // Best-effort daemon swing (no-op unless `with_daemon_swing` was
        // called): re-evaluate the local daemon's health once per poll tick,
        // before fetching transfers, so a poll after a flip hits whichever
        // daemon is now selected.
        if let Some(swing) = &self.swing {
            swing.refresh().await;
        }
        let transfers: GetTransfers = self
            .call(
                "get_transfers",
                json!({ "in": true, "account_index": self.account_index }),
            )
            .await?;
        Ok(transfers
            .incoming
            .into_iter()
            .map(|t| Transfer {
                txid: t.txid,
                amount_atomic: t.amount,
                address: t.address,
                height: t.height,
                confirmations: t.confirmations,
            })
            .collect())
    }

    async fn balance_atomic(&self) -> Result<Option<i64>, PaymentError> {
        let resp: GetBalance = self
            .call(
                "get_balance",
                json!({ "account_index": self.account_index }),
            )
            .await?;
        Ok(Some(to_i64(resp.balance)))
    }

    /// Bare reachability check: `monero-wallet-rpc` has no `get_info`
    /// (that's monerod-only, see the module doc), so this wallet-rpc
    /// connection alone can't tell whether the daemon it's pointed at is
    /// lagging -- only whether the wallet itself answers `get_height` at
    /// all. The lag-aware decision used for daemon failover lives in
    /// [`DaemonSwing`]/[`RpcDaemonProbe`], which probes a daemon's `get_info`
    /// directly.
    async fn health(&self) -> Health {
        match self.call::<GetHeight>("get_height", json!({})).await {
            Ok(_) => Health::Healthy,
            Err(_) => Health::Unreachable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn parses_create_address_v018() {
        let raw =
            r#"{"address":"8AJQ","address_index":2,"address_indices":[2],"addresses":["8AJQ"]}"#;
        let c: CreateAddress = serde_json::from_str(raw).unwrap();
        assert_eq!(c.address, "8AJQ");
        assert_eq!(c.address_index, 2);
    }

    #[test]
    fn empty_get_transfers_is_no_incoming() {
        let g: GetTransfers = serde_json::from_str("{}").unwrap();
        assert!(g.incoming.is_empty());
    }

    #[test]
    fn parses_incoming_transfer_entry() {
        let raw = r#"{"in":[{"txid":"abc","amount":1000000000000,"address":"8Asub","height":42,"confirmations":7,"fee":0}]}"#;
        let g: GetTransfers = serde_json::from_str(raw).unwrap();
        assert_eq!(g.incoming.len(), 1);
        let t = &g.incoming[0];
        assert_eq!(t.txid, "abc");
        assert_eq!(t.amount, 1_000_000_000_000);
        assert_eq!(t.confirmations, 7);
    }

    #[test]
    fn parses_get_balance_response() {
        let raw = r#"{"balance":1000000000000,"unlocked_balance":900000000000,
            "multisig_import_needed":false,"time_to_unlock":0}"#;
        let b: GetBalance = serde_json::from_str(raw).unwrap();
        assert_eq!(b.balance, 1_000_000_000_000);
    }

    #[test]
    fn rpc_error_is_surfaced() {
        let raw = r#"{"error":{"code":-13,"message":"No wallet file"},"result":null}"#;
        let env: RpcEnvelope<CreateAddress> = serde_json::from_str(raw).unwrap();
        assert!(env.result.is_none());
        assert_eq!(env.error.unwrap().message, "No wallet file");
    }

    // ---- classify_daemon_health(): get_info fixtures -> Health decision ----

    /// Real-shaped, fully-synced `get_info` response (extra fields present):
    /// `target_height: 0` ("at tip"), not `target_height == height`.
    const GET_INFO_SYNCED: &str = r#"{"height":3145000,"target_height":0,"status":"OK",
        "synchronized":true,"chain_type":"main"}"#;

    #[test]
    fn parses_get_info_response() {
        let i: GetInfo = serde_json::from_str(GET_INFO_SYNCED).unwrap();
        assert_eq!(i.height, 3_145_000);
        assert_eq!(i.target_height, 0);
    }

    #[test]
    fn get_info_missing_target_height_defaults_to_synced() {
        // Some daemon versions omit the field entirely when synced.
        let i: GetInfo = serde_json::from_str(r#"{"height":100,"status":"OK"}"#).unwrap();
        assert_eq!(i.target_height, 0);
    }

    #[test]
    fn synced_target_height_zero_is_healthy() {
        let i: GetInfo = serde_json::from_str(GET_INFO_SYNCED).unwrap();
        assert_eq!(
            classify_daemon_health(i.height, i.target_height, 3),
            Health::Healthy
        );
    }

    #[test]
    fn lag_over_threshold_is_lagging() {
        let raw = r#"{"height":3145000,"target_height":3145010,"status":"OK"}"#;
        let i: GetInfo = serde_json::from_str(raw).unwrap();
        assert_eq!(
            classify_daemon_health(i.height, i.target_height, 3),
            Health::Lagging(10)
        );
    }

    #[test]
    fn lag_at_threshold_is_still_healthy() {
        // Boundary: exactly at the threshold must not trip Lagging (matches
        // `classify_health`'s own boundary test in payments::mod).
        assert_eq!(
            classify_daemon_health(3_145_000, 3_145_003, 3),
            Health::Healthy
        );
    }

    #[test]
    fn small_lag_under_threshold_is_healthy() {
        assert_eq!(
            classify_daemon_health(3_145_000, 3_145_001, 3),
            Health::Healthy
        );
    }

    /// The brief's required error case: a failed daemon probe (as
    /// `RpcDaemonProbe` sees on a connection error, timeout, or a JSON-RPC
    /// `error` envelope) must decide `Health::Unreachable`. The envelope
    /// decode itself is the fixture-level proof of the shape `RpcDaemonProbe`
    /// actually receives from a real, unreachable/erroring daemon --
    /// `classify_daemon_health` is only reached once a probe *succeeds*, so
    /// this case never reaches it.
    #[test]
    fn rpc_error_envelope_is_no_result() {
        let raw = r#"{"error":{"code":-1,"message":"daemon unreachable"},"result":null}"#;
        let env: RpcEnvelope<GetInfo> = serde_json::from_str(raw).unwrap();
        assert!(env.result.is_none());
        assert_eq!(env.error.unwrap().message, "daemon unreachable");
    }

    // ---- get_info / set_daemon *request* shape ----
    //
    // The response-parsing tests above prove `GetInfo`/`RpcEnvelope` decode
    // correctly; they say nothing about whether `RpcDaemonProbe`/
    // `call_set_daemon` ever send a well-formed request in the first place --
    // a wrong method name would pass every one of those tests and only fail
    // against a live daemon (exactly the class of bug the Task 8 review's
    // Critical finding was). These pin the two request bodies directly.

    #[test]
    fn get_info_request_is_the_monerod_shape() {
        let body = get_info_request();
        assert_eq!(body["jsonrpc"], "2.0");
        assert_eq!(body["method"], "get_info");
        assert_eq!(body["params"], serde_json::json!({}));
    }

    #[test]
    fn set_daemon_request_carries_the_address() {
        let body = set_daemon_request("127.0.0.1:18081");
        assert_eq!(body["method"], "set_daemon");
        assert_eq!(
            body["params"],
            serde_json::json!({"address": "127.0.0.1:18081"})
        );
    }

    // ---- switch_daemon / set_daemon response shape ----

    #[test]
    fn set_daemon_response_parses_as_json_value() {
        // call_set_daemon deserializes the result as a bare `serde_json::Value`
        // -- confirm wallet-rpc's actual `{"status":"OK"}` shape round-trips
        // through the same `RpcEnvelope` decoding `call()`/`call_set_daemon`
        // both use.
        let raw = r#"{"result":{"status":"OK"}}"#;
        let env: RpcEnvelope<serde_json::Value> = serde_json::from_str(raw).unwrap();
        assert_eq!(env.result.unwrap(), serde_json::json!({"status": "OK"}));
    }

    #[test]
    fn connect_without_swing_disables_it() {
        let wallet = MoneroWallet::connect("http://127.0.0.1:18083/json_rpc", 0).unwrap();
        assert!(wallet.swing.is_none());
    }

    #[test]
    fn with_daemon_swing_starts_on_local() {
        // `local_addr`/`remote_addr` are the BARE `host:port` form
        // `set_daemon` needs -- see `daemon_probe_url`'s doc for why storing
        // a full URL here (what an earlier version did) was the bug.
        let wallet = MoneroWallet::connect("http://127.0.0.1:18083/json_rpc", 0)
            .unwrap()
            .with_daemon_swing("127.0.0.1:18081", "remote.example:18081");
        let swing = wallet.swing.as_ref().unwrap();
        assert_eq!(swing.local_addr, "127.0.0.1:18081");
        assert_eq!(swing.remote_addr, "remote.example:18081");
    }

    // ---- daemon_probe_url: bare address -> full JSON-RPC URL ----

    #[test]
    fn daemon_probe_url_adds_scheme_and_path_to_bare_address() {
        assert_eq!(
            daemon_probe_url("127.0.0.1:18081"),
            "http://127.0.0.1:18081/json_rpc"
        );
    }

    #[test]
    fn daemon_probe_url_is_tolerant_of_a_full_url_input() {
        // If an operator passes a full URL by habit, don't double up the path.
        assert_eq!(
            daemon_probe_url("http://127.0.0.1:18081/json_rpc"),
            "http://127.0.0.1:18081/json_rpc"
        );
    }

    #[test]
    fn daemon_probe_url_preserves_https_scheme() {
        assert_eq!(
            daemon_probe_url("https://remote.example:18081"),
            "https://remote.example:18081/json_rpc"
        );
    }

    // ---- DaemonSwing hysteresis: scripted probe + recording switch, no
    // live RPC. Mirrors failover::tests::ScriptedBackend. ----

    /// A [`DaemonProbe`] whose `probe()` pops the next entry from a fixed
    /// scripted sequence (sticking on the last entry once exhausted).
    struct ScriptedProbe {
        script: Vec<Health>,
        idx: AtomicUsize,
    }

    impl ScriptedProbe {
        fn new(script: Vec<Health>) -> Self {
            Self {
                script,
                idx: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl DaemonProbe for ScriptedProbe {
        async fn probe(&self) -> Health {
            let i = self.idx.fetch_add(1, Ordering::Relaxed);
            let last = self.script.len() - 1;
            self.script[i.min(last)]
        }
    }

    /// A [`DaemonSwitch`] that always succeeds and records every address it
    /// was asked to switch to, in order -- so tests can assert `set_daemon`
    /// was invoked with the right address at each flip.
    #[derive(Default)]
    struct RecordingSwitch {
        calls: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl DaemonSwitch for RecordingSwitch {
        async fn switch(&self, address: &str) -> Result<(), PaymentError> {
            self.calls.lock().await.push(address.to_owned());
            Ok(())
        }
    }

    /// A [`DaemonSwitch`] that always fails, to exercise the flip-rollback
    /// path.
    struct FailingSwitch;

    #[async_trait]
    impl DaemonSwitch for FailingSwitch {
        async fn switch(&self, _address: &str) -> Result<(), PaymentError> {
            Err(PaymentError::Rpc("set_daemon failed".to_owned()))
        }
    }

    fn test_swing(probe: Arc<dyn DaemonProbe>, switch: Arc<dyn DaemonSwitch>) -> DaemonSwing {
        DaemonSwing {
            probe,
            switch,
            local_addr: "local:18081".to_owned(),
            remote_addr: "remote:18081".to_owned(),
            to_fallback_after: 3,
            to_primary_after: 3,
            state: Mutex::new(SwingState {
                on_local: true,
                local_ok_streak: 0,
                local_fail_streak: 0,
            }),
        }
    }

    #[tokio::test]
    async fn stays_on_local_until_3_failures_then_flips_and_back() {
        use Health::{Healthy as H, Unreachable as U};
        let probe = Arc::new(ScriptedProbe::new(vec![H, H, U, U, U, H, H, H]));
        let switch = Arc::new(RecordingSwitch::default());
        let swing = test_swing(probe, Arc::clone(&switch) as Arc<dyn DaemonSwitch>);

        swing.refresh().await; // H
        swing.refresh().await; // H
        assert!(swing.state.lock().await.on_local);
        assert!(switch.calls.lock().await.is_empty());

        swing.refresh().await; // 1st U
        assert!(swing.state.lock().await.on_local);
        swing.refresh().await; // 2nd U
        assert!(swing.state.lock().await.on_local);
        swing.refresh().await; // 3rd U -> flip to remote
        assert!(!swing.state.lock().await.on_local);
        assert_eq!(switch.calls.lock().await.as_slice(), ["remote:18081"]);

        swing.refresh().await; // 1st H
        assert!(!swing.state.lock().await.on_local);
        swing.refresh().await; // 2nd H
        assert!(!swing.state.lock().await.on_local);
        swing.refresh().await; // 3rd H -> flip back to local
        assert!(swing.state.lock().await.on_local);
        assert_eq!(
            switch.calls.lock().await.as_slice(),
            ["remote:18081", "local:18081"]
        );
    }

    /// A single unhealthy probe (below the hysteresis threshold) must never
    /// trigger a `set_daemon` call -- the whole point of the streak.
    #[tokio::test]
    async fn single_failure_does_not_flip_or_call_switch() {
        use Health::{Healthy as H, Unreachable as U};
        let probe = Arc::new(ScriptedProbe::new(vec![H, U, H]));
        let switch = Arc::new(RecordingSwitch::default());
        let swing = test_swing(probe, Arc::clone(&switch) as Arc<dyn DaemonSwitch>);

        swing.refresh().await;
        swing.refresh().await;
        swing.refresh().await;

        assert!(swing.state.lock().await.on_local);
        assert!(switch.calls.lock().await.is_empty());
    }

    /// If the `set_daemon` RPC itself fails on a confirmed flip, `on_local`
    /// must roll back rather than desync from the wallet's real (unchanged)
    /// daemon.
    #[tokio::test]
    async fn failed_switch_rolls_back_on_local_state() {
        use Health::Unreachable as U;
        let probe = Arc::new(ScriptedProbe::new(vec![U, U, U]));
        let switch = Arc::new(FailingSwitch);
        let swing = test_swing(probe, switch);

        swing.refresh().await;
        swing.refresh().await;
        swing.refresh().await; // streak hits 3, switch to remote fails

        assert!(
            swing.state.lock().await.on_local,
            "on_local must stay true when the set_daemon RPC failed"
        );
    }

    // ---- end-to-end: with_daemon_swing's REAL RpcDaemonProbe/WalletRpcSwitch
    // over an actual (tiny, hand-rolled) HTTP server. `test_swing()` above
    // builds a `DaemonSwing` directly with already-bare addresses, so it
    // never exercises `with_daemon_swing`'s construction -- which is exactly
    // where the bare-address/full-URL mixup regression lived. This drives
    // the constructor path and the switch path together, over real sockets. ----

    /// A minimal single-purpose mock server: accepts JSON-RPC POSTs on any
    /// path, records `(path, body)` for every request, and replies `OK`
    /// (with a deliberately-lagging `get_info` so 3 probes reliably flip the
    /// swing). Good enough for tiny, entirely-local JSON payloads -- no new
    /// dependency needed for a hand-rolled HTTP/1.1 request/response.
    async fn spawn_recording_daemon(
        log: Arc<Mutex<Vec<(String, serde_json::Value)>>>,
    ) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let log = Arc::clone(&log);
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
                    let body_start = request.find("\r\n\r\n").map_or(request.len(), |i| i + 4);
                    let body: serde_json::Value =
                        serde_json::from_str(request[body_start..].trim_end_matches('\0'))
                            .unwrap_or(serde_json::Value::Null);
                    let method = body["method"].as_str().unwrap_or("").to_owned();
                    log.lock().await.push((path, body));
                    let resp_body = if method == "get_info" {
                        // Always-lagging so every probe reads `Lagging` (not
                        // `Healthy`) -- 3 consecutive ones cross the default
                        // hysteresis and flip.
                        serde_json::json!({"result": {"height": 100, "target_height": 999_999}})
                    } else {
                        serde_json::json!({"result": {"status": "OK"}})
                    };
                    let payload = resp_body.to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                        payload.len(),
                        payload
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn with_daemon_swing_probes_full_url_and_switches_bare_address() {
        let log: Arc<Mutex<Vec<(String, serde_json::Value)>>> = Arc::new(Mutex::new(Vec::new()));
        let addr = spawn_recording_daemon(Arc::clone(&log)).await;

        // One mock server plays both roles: `/wallet_rpc` is `monero-wallet-rpc`
        // (receives `set_daemon`), `/json_rpc` is `monerod` (receives `get_info`)
        // -- distinct paths on the same port, so a single bare `host:port`
        // exercises both derived-URL and passed-through-verbatim call sites.
        let local_bare = format!("127.0.0.1:{}", addr.port());
        let remote_bare = "remote.example:18081".to_owned();
        let wallet = MoneroWallet::connect(&format!("http://{local_bare}/wallet_rpc"), 0)
            .unwrap()
            .with_daemon_swing(local_bare.clone(), remote_bare.clone());
        let swing = wallet.swing.as_ref().unwrap();

        swing.refresh().await; // 1st lagging probe
        swing.refresh().await; // 2nd
        swing.refresh().await; // 3rd -> flips, calls set_daemon

        assert!(
            !swing.state.lock().await.on_local,
            "3 consecutive lagging probes must flip to remote"
        );

        let log = log.lock().await;
        // (a) the probe hit the derived full JSON-RPC URL's path.
        assert!(
            log.iter()
                .any(|(path, body)| path == "/json_rpc" && body["method"] == "get_info"),
            "RpcDaemonProbe must POST get_info to http://<local_addr>/json_rpc"
        );
        // (b) set_daemon (sent to the wallet-rpc endpoint) carries the BARE
        // remote address, not a `.../json_rpc`-suffixed URL.
        let set_daemon_call = log
            .iter()
            .find(|(_, body)| body["method"] == "set_daemon")
            .expect("a confirmed flip must call set_daemon");
        assert_eq!(set_daemon_call.0, "/wallet_rpc");
        assert_eq!(set_daemon_call.1["params"]["address"], remote_bare);
    }
}
