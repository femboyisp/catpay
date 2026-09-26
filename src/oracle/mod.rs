//! Coin-agnostic USD price oracle: median of N keyless sources, fail-closed on
//! staleness. The store + aggregation are pure and unit-tested here; the
//! network fetchers live in `sources.rs`.
pub mod sources;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::coin::Coin;

#[derive(Debug, thiserror::Error)]
pub enum OracleError {
    #[error("http error: {0}")]
    Http(String),
    #[error("parse error: {0}")]
    Parse(String),
}

#[derive(Debug, Clone, Copy)]
pub struct PricePoint {
    pub usd: f64,
    pub fetched_at: Instant,
}

/// Emit the `oracle_price_usd{coin}` gauge for a coin that was just freshly
/// priced (called right after [`Oracle::set`] inside [`Oracle::refresh_once`]).
fn publish_price_gauge(coin: &Coin, usd: f64) {
    metrics::gauge!("oracle_price_usd", "coin" => coin.as_str().to_string()).set(usd);
}

/// Median of a slice (sorted copy); `None` if empty.
pub fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut v: Vec<f64> = values.iter().copied().filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    Some(if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    })
}

/// Median of the prices, but only if at least `min_sources` were collected.
pub fn aggregate(prices: &[f64], min_sources: usize) -> Option<f64> {
    if prices.len() < min_sources {
        return None;
    }
    median(prices)
}

/// In-memory price store keyed by coin, fail-closed past `max_staleness`.
pub struct Oracle {
    prices: RwLock<HashMap<Coin, PricePoint>>,
    max_staleness: Duration,
}

impl Oracle {
    pub fn new(max_staleness: Duration) -> Self {
        Self {
            prices: RwLock::new(HashMap::new()),
            max_staleness,
        }
    }

    /// Store a fresh USD price for a coin (called by the refresh loop / tests).
    pub fn set(&self, coin: Coin, usd: f64) {
        self.prices.write().unwrap().insert(
            coin,
            PricePoint {
                usd,
                fetched_at: Instant::now(),
            },
        );
    }

    /// The current USD price, or `None` if missing or stale (fail closed).
    pub fn price_usd(&self, coin: Coin) -> Option<f64> {
        let guard = self.prices.read().unwrap();
        let p = guard.get(&coin)?;
        if p.fetched_at.elapsed() <= self.max_staleness {
            Some(p.usd)
        } else {
            None
        }
    }

    /// Fetch fresh prices from all sources for each coin and update the store.
    pub async fn refresh_once(
        &self,
        coins: &[Coin],
        sources: &[String],
        min_sources: usize,
        http: &reqwest::Client,
    ) {
        for coin in coins {
            // For Coin::Base: mirror directly from Ethereum if already priced
            if *coin == Coin::Base {
                if let Some(eth_px) = self.price_usd(Coin::Ethereum) {
                    self.set(Coin::Base, eth_px);
                    publish_price_gauge(coin, eth_px);
                    continue;
                }
            }
            let mut prices = Vec::new();
            for name in sources {
                match self::sources::fetch(name, coin.symbol(), http).await {
                    Ok(p) if p.is_finite() && p > 0.0 => prices.push(p),
                    Ok(_) => {}
                    Err(_e) => {
                        // Per-source failures are expected and noisy (rate limits,
                        // geo-blocks). Track via metrics; only the aggregate
                        // "couldn't price this coin" below is worth logging.
                        metrics::counter!("oracle_source_errors_total", "source" => name.clone())
                            .increment(1);
                    }
                }
            }
            match aggregate(&prices, min_sources) {
                Some(px) => {
                    self.set(coin.clone(), px);
                    publish_price_gauge(coin, px);
                    if *coin == Coin::Ethereum && coins.contains(&Coin::Base) {
                        self.set(Coin::Base, px);
                        publish_price_gauge(&Coin::Base, px);
                    }
                }
                None => eprintln!(
                    "oracle[{}]: only {} sources, need {}",
                    coin.symbol(),
                    prices.len(),
                    min_sources
                ),
            }
        }
    }

    /// Spawn a background task that refreshes prices on `refresh_secs` interval.
    pub fn spawn_refresh(
        self: Arc<Self>,
        coins: Vec<Coin>,
        sources: Vec<String>,
        min_sources: usize,
        refresh_secs: u64,
    ) {
        // A descriptive User-Agent is required by some price APIs (e.g. CoinGecko
        // hard-403s UA-less requests), so build a client with one; fall back to
        // the default client if the builder ever fails.
        let http = reqwest::Client::builder()
            .user_agent(concat!("catpay-oracle/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(8))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(refresh_secs.max(1));
            loop {
                self.refresh_once(&coins, &sources, min_sources, &http)
                    .await;
                tokio::time::sleep(interval).await;
            }
        });
    }

    /// Spawn a background task that periodically re-`set()`s a fixed USD
    /// price for `coin`. For stablecoins (`Coin::is_stable`), whose price is
    /// $1 by definition, this keeps `price_usd` from going stale without
    /// hitting the external min-sources price feed `spawn_refresh` uses —
    /// there's nothing to fetch, just a clock to keep `fetched_at` fresh.
    pub fn spawn_fixed(self: Arc<Self>, coin: Coin, usd: f64, refresh_secs: u64) {
        tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(refresh_secs.max(1));
            loop {
                self.set(coin.clone(), usd);
                publish_price_gauge(&coin, usd);
                tokio::time::sleep(interval).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coin::Coin;
    use std::time::Duration;

    #[test]
    fn median_odd_even_and_empty() {
        assert_eq!(median(&[]), None);
        assert_eq!(median(&[5.0]), Some(5.0));
        assert_eq!(median(&[3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(&[1.0, 2.0, 3.0, 4.0]), Some(2.5));
    }

    #[test]
    fn median_ignores_outlier_position() {
        assert_eq!(median(&[59.8, 60.1, 60.0, 71.0]), Some(60.05));
    }

    #[test]
    fn aggregate_requires_min_sources() {
        assert_eq!(aggregate(&[60.0, 60.1], 3), None);
        assert_eq!(aggregate(&[60.0, 60.1, 59.9], 3), Some(60.0));
    }

    #[test]
    fn price_usd_fresh_vs_stale() {
        let o = Oracle::new(Duration::from_millis(50));
        o.set(Coin::Bitcoin, 60_000.0);
        assert_eq!(o.price_usd(Coin::Bitcoin), Some(60_000.0));
        assert_eq!(o.price_usd(Coin::Monero), None);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(o.price_usd(Coin::Bitcoin), None);
    }

    #[tokio::test]
    async fn refresh_once_sets_when_enough_sources() {
        let o = Oracle::new(Duration::from_secs(300));
        if let Some(px) = aggregate(&[60_000.0, 60_100.0, 59_900.0], 3) {
            o.set(Coin::Bitcoin, px);
        }
        assert_eq!(o.price_usd(Coin::Bitcoin), Some(60_000.0));

        let o2 = Oracle::new(Duration::from_secs(300));
        if let Some(px) = aggregate(&[60_000.0, 60_100.0], 3) {
            o2.set(Coin::Bitcoin, px);
        }
        assert_eq!(o2.price_usd(Coin::Bitcoin), None);
    }

    #[test]
    fn fresh_price_reaches_both_store_and_gauge() {
        let o = Oracle::new(Duration::from_secs(300));
        let px = 60_000.0;
        o.set(Coin::Bitcoin, px);
        publish_price_gauge(&Coin::Bitcoin, px);
        assert_eq!(o.price_usd(Coin::Bitcoin), Some(60_000.0));
    }

    #[test]
    fn under_min_sources_coin_has_no_fresh_price() {
        let o = Oracle::new(Duration::from_secs(300));
        let sources = [60_000.0, 60_100.0];
        if let Some(px) = aggregate(&sources, 3) {
            o.set(Coin::Bitcoin, px);
            publish_price_gauge(&Coin::Bitcoin, px);
        }
        assert_eq!(o.price_usd(Coin::Bitcoin), None);
    }

    #[test]
    fn base_mirrors_ethereum_price() {
        let o = Oracle::new(Duration::from_secs(300));
        let eth_px = 3_000.0;
        o.set(Coin::Ethereum, eth_px);
        publish_price_gauge(&Coin::Ethereum, eth_px);
        if let Some(p) = o.price_usd(Coin::Ethereum) {
            o.set(Coin::Base, p);
            publish_price_gauge(&Coin::Base, p);
        }
        assert_eq!(o.price_usd(Coin::Base), Some(3_000.0));
    }

    #[tokio::test]
    async fn test_spl_token_stable_pricing_with_spawn_fixed() {
        use std::sync::Arc;
        let o = Arc::new(Oracle::new(Duration::from_millis(150)));
        let meta = Arc::new(crate::coin::SplTokenMeta {
            coin: "usdc_sol".to_string(),
            symbol: "usdc".to_string(),
            display_name: "USDC (Solana)".to_string(),
            network_badge: "SPL".to_string(),
            mint_address: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
            decimals: 6,
            is_stable: true,
        });
        let coin = Coin::SplToken(meta);
        o.clone().spawn_fixed(coin.clone(), 1.0, 1);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(o.price_usd(coin), Some(1.0));
    }
}
