//! `catpay`: standalone cryptocurrency payment, derivation, and verification engine.

pub mod backend;
pub mod bitcoin;
pub mod bitcoincash;
pub mod coin;
pub mod deriver;
pub mod dogecoin;
pub mod electrum;
pub mod error;
pub mod esplora;
pub mod failover;
pub mod litecoin;
pub mod monero;
pub mod store;
pub mod types;

pub use backend::PaymentBackend;
pub use bitcoin::BitcoinWallet;
pub use bitcoincash::BitcoinCashWallet;
pub use coin::{Coin, EvmTokenMeta, SplTokenMeta};
pub use dogecoin::DogecoinWallet;
pub use electrum::{AddressFormat, ElectrumSource};
pub use error::PaymentError;
pub use esplora::EsploraSource;
pub use failover::FailoverBackend;
pub use litecoin::LitecoinWallet;
pub use monero::MoneroWallet;
pub use store::{MockPaymentStore, PaymentStore};
pub use types::{classify_health, to_i64, Health, NewSubaddress, PaymentService, Transfer};

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

        let fmt = AddressFormat::CashAddr;
        match fmt {
            AddressFormat::CashAddr => {}
            AddressFormat::Base58Check { .. } => panic!("unexpected format"),
        }
    }
}
