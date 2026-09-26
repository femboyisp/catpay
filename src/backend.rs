use crate::error::PaymentError;
use crate::types::{Health, NewSubaddress, Transfer};
use async_trait::async_trait;

#[async_trait]
pub trait PaymentBackend: Send + Sync {
    async fn new_subaddress(&self, label: &str) -> Result<NewSubaddress, PaymentError>;
    async fn incoming_transfers(&self, min_height: u64) -> Result<Vec<Transfer>, PaymentError>;
    async fn balance_atomic(&self) -> Result<Option<i64>, PaymentError> {
        Ok(None)
    }
    async fn health(&self) -> Health {
        Health::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyBackend;

    #[async_trait]
    impl PaymentBackend for DummyBackend {
        async fn new_subaddress(&self, label: &str) -> Result<NewSubaddress, PaymentError> {
            Ok(NewSubaddress {
                address: format!("addr_{label}"),
                index: 42,
            })
        }

        async fn incoming_transfers(
            &self,
            _min_height: u64,
        ) -> Result<Vec<Transfer>, PaymentError> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn test_default_methods() {
        let backend = DummyBackend;
        assert_eq!(backend.balance_atomic().await.unwrap(), None);
        assert_eq!(backend.health().await, Health::Healthy);

        let subaddr = backend.new_subaddress("test").await.unwrap();
        assert_eq!(subaddr.address, "addr_test");
        assert_eq!(subaddr.index, 42);
    }
}
