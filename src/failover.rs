//! `FailoverBackend`: a [`PaymentBackend`] that wraps a primary (node-backed)
//! source and a fallback (nodeless/remote) source, selecting between them by
//! the primary's health with hysteresis -- prefer the primary while it's
//! healthy, fall back to the remote source after `to_fallback_after`
//! consecutive primary failures, and switch back after `to_primary_after`
//! consecutive primary successes.
//!
//! This is the point of the failover design: both sources derive the same
//! deposit addresses (Task 6), so switching which one answers
//! `new_subaddress`/`incoming_transfers`/`balance_atomic` is transparent to
//! callers -- the same address comes back either way.
//!
//! Wired into `main` by `payments::build_bitcoin_backend`/
//! `build_litecoin_backend`, which construct this from config when both a
//! node and a remote source are available.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::backend::PaymentBackend;
use crate::coin::Coin;
use crate::error::PaymentError;
use crate::types::{Health, NewSubaddress, Transfer};

/// Mutable hysteresis state behind the mutex: which source is currently
/// selected, and the current consecutive success/failure streaks for the
/// primary's health probe.
struct FoState {
    /// `true` while the primary is selected; `false` while on the fallback.
    on_primary: bool,
    primary_fail_streak: u32,
    primary_ok_streak: u32,
}

/// A [`PaymentBackend`] that fails over from `primary` to `fallback` (and
/// back) based on the primary's [`Health`], with hysteresis so a single
/// flaky probe doesn't flap the selection.
pub struct FailoverBackend {
    primary: Arc<dyn PaymentBackend>,
    fallback: Arc<dyn PaymentBackend>,
    coin: Coin,
    /// Consecutive primary health-probe failures required to switch to the
    /// fallback.
    to_fallback_after: u32,
    /// Consecutive primary health-probe successes required to switch back to
    /// the primary.
    to_primary_after: u32,
    state: Mutex<FoState>,
}

impl FailoverBackend {
    pub fn new(
        primary: Arc<dyn PaymentBackend>,
        fallback: Arc<dyn PaymentBackend>,
        coin: Coin,
        to_fallback_after: u32,
        to_primary_after: u32,
    ) -> Self {
        Self {
            primary,
            fallback,
            coin,
            to_fallback_after,
            to_primary_after,
            state: Mutex::new(FoState {
                on_primary: true,
                primary_fail_streak: 0,
                primary_ok_streak: 0,
            }),
        }
    }

    /// Probe the primary's health, update the hysteresis streaks, and flip
    /// `on_primary` when a streak crosses its configured threshold. On a
    /// flip, increments `detection_source_switch_total{coin}` and logs;
    /// always publishes `detection_source{coin}` (0.0 = primary, 1.0 =
    /// fallback) so the current selection is observable regardless of
    /// whether this call changed it.
    async fn refresh_source(&self) {
        let healthy = matches!(self.primary.health().await, Health::Healthy);
        let mut s = self.state.lock().await;
        if healthy {
            s.primary_ok_streak += 1;
            s.primary_fail_streak = 0;
        } else {
            s.primary_fail_streak += 1;
            s.primary_ok_streak = 0;
        }
        let was = s.on_primary;
        if s.on_primary && s.primary_fail_streak >= self.to_fallback_after {
            s.on_primary = false;
        } else if !s.on_primary && s.primary_ok_streak >= self.to_primary_after {
            s.on_primary = true;
        }
        if was != s.on_primary {
            metrics::counter!("detection_source_switch_total", "coin" => self.coin.as_str().to_string())
                .increment(1);
            eprintln!(
                "payments[{}]: detection source -> {}",
                self.coin.as_str(),
                if s.on_primary { "node" } else { "remote" }
            );
        }
        metrics::gauge!("detection_source", "coin" => self.coin.as_str().to_string())
            .set(if s.on_primary { 0.0 } else { 1.0 });
    }

    /// The currently-selected source, cloned out from under the lock so
    /// callers never hold `state`'s mutex across an `.await` on the backend
    /// itself.
    async fn active(&self) -> Arc<dyn PaymentBackend> {
        let s = self.state.lock().await;
        if s.on_primary {
            Arc::clone(&self.primary)
        } else {
            Arc::clone(&self.fallback)
        }
    }

    /// Test-only accessor for the current selection.
    #[cfg(test)]
    pub(crate) async fn on_primary(&self) -> bool {
        self.state.lock().await.on_primary
    }
}

#[async_trait]
impl PaymentBackend for FailoverBackend {
    async fn new_subaddress(&self, label: &str) -> Result<NewSubaddress, PaymentError> {
        let source = self.active().await;
        match source.new_subaddress(label).await {
            Ok(sub) => Ok(sub),
            Err(e) => {
                let on_primary = self.state.lock().await.on_primary;
                if on_primary {
                    self.fallback.new_subaddress(label).await
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Re-evaluates the primary/fallback selection once per poll (before
    /// delegating), so each poll tick reacts to the primary's latest health.
    async fn incoming_transfers(&self, min_height: u64) -> Result<Vec<Transfer>, PaymentError> {
        self.refresh_source().await;
        let source = self.active().await;
        source.incoming_transfers(min_height).await
    }

    async fn balance_atomic(&self) -> Result<Option<i64>, PaymentError> {
        let source = self.active().await;
        match source.balance_atomic().await {
            Ok(v) => Ok(v),
            Err(e) => {
                let on_primary = self.state.lock().await.on_primary;
                if on_primary {
                    self.fallback.balance_atomic().await
                } else {
                    Err(e)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A `PaymentBackend` whose `health()` pops the next entry from a fixed
    /// scripted sequence (sticking on the last entry once exhausted), and
    /// whose `new_subaddress`/`incoming_transfers` return a fixed,
    /// source-identifying address/txid -- so tests can tell which of the two
    /// wrapped sources actually answered a delegated call, not just that
    /// *some* source did.
    struct ScriptedBackend {
        script: Vec<Health>,
        idx: AtomicUsize,
        address: &'static str,
        txid: &'static str,
    }

    impl ScriptedBackend {
        fn new(script: Vec<Health>, address: &'static str, txid: &'static str) -> Self {
            Self {
                script,
                idx: AtomicUsize::new(0),
                address,
                txid,
            }
        }

        fn always_healthy(address: &'static str, txid: &'static str) -> Self {
            Self::new(vec![Health::Healthy], address, txid)
        }
    }

    #[async_trait]
    impl PaymentBackend for ScriptedBackend {
        async fn new_subaddress(&self, _label: &str) -> Result<NewSubaddress, PaymentError> {
            Ok(NewSubaddress {
                address: self.address.to_string(),
                index: 0,
            })
        }
        async fn incoming_transfers(
            &self,
            _min_height: u64,
        ) -> Result<Vec<Transfer>, PaymentError> {
            Ok(vec![Transfer {
                txid: self.txid.to_string(),
                amount_atomic: 0,
                address: self.address.to_string(),
                height: 0,
                confirmations: 0,
            }])
        }
        async fn health(&self) -> Health {
            let i = self.idx.fetch_add(1, Ordering::Relaxed);
            let last = self.script.len() - 1;
            self.script[i.min(last)]
        }
    }

    #[tokio::test]
    async fn stays_on_primary_until_3_failures_then_switches_and_back() {
        use Health::{Healthy as H, Unreachable as U};
        let primary = Arc::new(ScriptedBackend::new(
            vec![H, H, U, U, U, H, H, H],
            "primary-addr",
            "from-primary",
        ));
        let fallback = Arc::new(ScriptedBackend::always_healthy(
            "fallback-addr",
            "from-fallback",
        ));
        let fo = FailoverBackend::new(primary, fallback, Coin::Bitcoin, 3, 3);

        fo.refresh_source().await; // H
        fo.refresh_source().await; // H
        assert!(fo.on_primary().await);

        fo.refresh_source().await; // 1st U
        assert!(fo.on_primary().await);
        fo.refresh_source().await; // 2nd U
        assert!(fo.on_primary().await);
        fo.refresh_source().await; // 3rd U -> fallback
        assert!(!fo.on_primary().await);

        fo.refresh_source().await; // 1st H
        assert!(!fo.on_primary().await);
        fo.refresh_source().await; // 2nd H
        assert!(!fo.on_primary().await);
        fo.refresh_source().await; // 3rd H -> back to primary
        assert!(fo.on_primary().await);
    }

    /// Routing: `incoming_transfers`' `refresh_source()`-first call and its
    /// subsequent delegation must both actually work -- not just "some
    /// source answers", but the *correct* source per the current hysteresis
    /// state. The two mocks return distinct, source-identifying txids/
    /// addresses precisely so a routing regression (e.g. delegating to the
    /// wrong `Arc`, or skipping `refresh_source()`) would fail this test
    /// rather than passing vacuously on `x == x`.
    ///
    /// The primary's health script is `[H, U, U, U]` with
    /// `to_fallback_after = 3`: the first `incoming_transfers` call
    /// consumes the `Healthy` entry (no flip, still on primary), and the
    /// next three each consume an `Unreachable` entry, flipping to the
    /// fallback exactly on the third. `new_subaddress` (which does not call
    /// `refresh_source`) is checked before and after that flip to confirm
    /// address routing follows the same selection.
    #[tokio::test]
    async fn incoming_transfers_and_new_subaddress_route_to_the_selected_source() {
        use Health::{Healthy as H, Unreachable as U};
        let primary = Arc::new(ScriptedBackend::new(
            vec![H, U, U, U],
            "primary-addr",
            "from-primary",
        ));
        let fallback = Arc::new(ScriptedBackend::always_healthy(
            "fallback-addr",
            "from-fallback",
        ));
        let fo = FailoverBackend::new(primary, fallback, Coin::Litecoin, 3, 3);

        // Starts on primary (before any refresh_source call).
        assert!(fo.on_primary().await);
        assert_eq!(
            fo.new_subaddress("acct").await.unwrap().address,
            "primary-addr"
        );

        // 1st incoming_transfers: refresh_source consumes Healthy -> stays
        // on primary -> delegates to the primary mock.
        let transfers = fo.incoming_transfers(0).await.unwrap();
        assert_eq!(transfers[0].txid, "from-primary");
        assert!(fo.on_primary().await);

        // 2nd and 3rd: consume the first two Unreachable entries -- fail
        // streak below threshold, still on primary.
        fo.incoming_transfers(0).await.unwrap();
        fo.incoming_transfers(0).await.unwrap();
        assert!(fo.on_primary().await);

        // 4th: consumes the 3rd consecutive Unreachable -> flips to
        // fallback, and this same call must delegate to the NEW selection
        // (post-flip), not the one from before refresh_source ran.
        let transfers = fo.incoming_transfers(0).await.unwrap();
        assert!(!fo.on_primary().await);
        assert_eq!(transfers[0].txid, "from-fallback");

        // new_subaddress routing also follows the flip.
        assert_eq!(
            fo.new_subaddress("acct").await.unwrap().address,
            "fallback-addr"
        );
    }
}
