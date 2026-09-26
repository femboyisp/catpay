use crate::backend::PaymentBackend;
use crate::coin::Coin;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSubaddress {
    pub address: String,
    pub index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    pub txid: String,
    pub amount_atomic: u64,
    pub address: String,
    pub height: u64,
    pub confirmations: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Healthy,
    Unreachable,
    Lagging(u64),
}

pub fn classify_health(headers: i64, blocks: i64, threshold: u64) -> Health {
    let lag = u64::try_from(headers.saturating_sub(blocks)).unwrap_or(0);
    if lag > threshold {
        Health::Lagging(lag)
    } else {
        Health::Healthy
    }
}

pub fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[derive(Clone)]
pub struct PaymentService {
    pub coin: Coin,
    pub backend: Arc<dyn PaymentBackend>,
    pub min_confirmations: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_health_healthy() {
        assert_eq!(classify_health(100, 100, 5), Health::Healthy);
        assert_eq!(classify_health(105, 100, 5), Health::Healthy);
        assert_eq!(classify_health(100, 105, 5), Health::Healthy);
    }

    #[test]
    fn test_classify_health_lagging() {
        assert_eq!(classify_health(106, 100, 5), Health::Lagging(6));
        assert_eq!(classify_health(1000, 900, 10), Health::Lagging(100));
    }

    #[test]
    fn test_classify_health_saturating() {
        // If blocks is somehow ahead or negative math
        assert_eq!(classify_health(50, 100, 5), Health::Healthy);
    }

    #[test]
    fn test_to_i64() {
        assert_eq!(to_i64(100), 100);
        assert_eq!(to_i64(u64::MAX), i64::MAX);
    }
}
