use crate::error::PaymentError;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;

#[async_trait]
pub trait PaymentStore: Send + Sync {
    async fn next_hd_index(&self, coin: &str) -> Result<u64, PaymentError>;
    async fn next_eth_hd_index(&self) -> Result<u64, PaymentError>;
    async fn open_addresses(&self, coin: &str) -> Result<Vec<String>, PaymentError>;
    async fn recent_addresses(&self, coin: &str, limit: i64) -> Result<Vec<String>, PaymentError>;
}

/// In-memory mock store for unit tests.
#[derive(Default)]
pub struct MockPaymentStore {
    pub indices: Mutex<HashMap<String, u64>>,
    pub eth_index: Mutex<u64>,
    pub open_addrs: Mutex<HashMap<String, Vec<String>>>,
    pub recent_addrs: Mutex<HashMap<String, Vec<String>>>,
}

impl MockPaymentStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PaymentStore for MockPaymentStore {
    async fn next_hd_index(&self, coin: &str) -> Result<u64, PaymentError> {
        let mut map = self.indices.lock().unwrap();
        let cur = map.entry(coin.to_string()).or_insert(0);
        let ret = *cur;
        *cur += 1;
        Ok(ret)
    }

    async fn next_eth_hd_index(&self) -> Result<u64, PaymentError> {
        let mut cur = self.eth_index.lock().unwrap();
        let ret = *cur;
        *cur += 1;
        Ok(ret)
    }

    async fn open_addresses(&self, coin: &str) -> Result<Vec<String>, PaymentError> {
        let map = self.open_addrs.lock().unwrap();
        Ok(map.get(coin).cloned().unwrap_or_default())
    }

    async fn recent_addresses(&self, coin: &str, limit: i64) -> Result<Vec<String>, PaymentError> {
        let map = self.recent_addrs.lock().unwrap();
        let addrs = map.get(coin).cloned().unwrap_or_default();
        let take_n = if limit <= 0 { 0 } else { limit as usize };
        Ok(addrs.into_iter().take(take_n).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_store_indices() {
        let store = MockPaymentStore::new();

        assert_eq!(store.next_hd_index("btc").await.unwrap(), 0);
        assert_eq!(store.next_hd_index("btc").await.unwrap(), 1);
        assert_eq!(store.next_hd_index("ltc").await.unwrap(), 0);
        assert_eq!(store.next_hd_index("btc").await.unwrap(), 2);

        assert_eq!(store.next_eth_hd_index().await.unwrap(), 0);
        assert_eq!(store.next_eth_hd_index().await.unwrap(), 1);
        assert_eq!(store.next_eth_hd_index().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_mock_store_addresses() {
        let store = MockPaymentStore::new();

        assert!(store.open_addresses("btc").await.unwrap().is_empty());
        assert!(store.recent_addresses("btc", 10).await.unwrap().is_empty());

        store.open_addrs.lock().unwrap().insert(
            "btc".to_string(),
            vec!["addr1".to_string(), "addr2".to_string()],
        );
        store.recent_addrs.lock().unwrap().insert(
            "btc".to_string(),
            vec![
                "addr1".to_string(),
                "addr2".to_string(),
                "addr3".to_string(),
            ],
        );

        let open = store.open_addresses("btc").await.unwrap();
        assert_eq!(open, vec!["addr1", "addr2"]);

        let recent = store.recent_addresses("btc", 2).await.unwrap();
        assert_eq!(recent, vec!["addr1", "addr2"]);

        let recent_all = store.recent_addresses("btc", 10).await.unwrap();
        assert_eq!(recent_all, vec!["addr1", "addr2", "addr3"]);

        let recent_zero = store.recent_addresses("btc", 0).await.unwrap();
        assert!(recent_zero.is_empty());

        let recent_neg = store.recent_addresses("btc", -5).await.unwrap();
        assert!(recent_neg.is_empty());
    }
}
