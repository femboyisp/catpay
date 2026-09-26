//! `catpay`: standalone cryptocurrency payment, derivation, and verification engine.

pub mod backend;
pub mod coin;
pub mod deriver;
pub mod error;
pub mod store;
pub mod types;

pub use backend::PaymentBackend;
pub use coin::{Coin, EvmTokenMeta, SplTokenMeta};
pub use error::PaymentError;
pub use store::{MockPaymentStore, PaymentStore};
pub use types::{classify_health, Health, NewSubaddress, PaymentService, Transfer};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(version(), "0.1.0");
    }

    #[test]
    fn test_reexports() {
        let coin = Coin::Monero;
        assert_eq!(coin.as_str(), "monero");

        let err = PaymentError::Rpc("failed".into());
        assert_eq!(err.to_string(), "rpc error: failed");

        let health = classify_health(10, 10, 1);
        assert_eq!(health, Health::Healthy);
    }
}
