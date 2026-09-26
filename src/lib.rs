//! `catpay`: standalone cryptocurrency payment, derivation, and verification engine.

pub mod backend;
pub mod bitcoin;
pub mod bitcoincash;
pub mod coin;
pub mod deriver;
pub mod dogecoin;
pub mod electrum;
pub mod erc20;
pub mod error;
pub mod esplora;
pub mod ethereum;
pub mod evm;
pub mod failover;
pub mod litecoin;
pub mod mercury;
pub mod monero;
pub mod oracle;
pub mod solana;
pub mod store;
pub mod stripe;
pub mod tron;
pub mod types;

pub use backend::PaymentBackend;
pub use bitcoin::BitcoinWallet;
pub use bitcoincash::BitcoinCashWallet;
pub use coin::{Coin, EvmTokenMeta, SplTokenMeta};
pub use dogecoin::DogecoinWallet;
pub use electrum::{AddressFormat, ElectrumSource};
pub use erc20::Erc20Wallet;
pub use error::PaymentError;
pub use esplora::EsploraSource;
pub use ethereum::{EthereumWallet, MultiRemoteEthClient};
pub use evm::{derive_evm_address, EvmNativeWallet, EvmTokenWallet, MultiRemoteEvmClient};
pub use failover::FailoverBackend;
pub use litecoin::LitecoinWallet;
pub use mercury::{MercuryClient, MercuryTransaction, WireInstructions};
pub use monero::MoneroWallet;
pub use oracle::{aggregate, median, Oracle, OracleError, PricePoint};
pub use solana::{
    build_solana_pay_url, extract_reference_param, generate_solana_reference,
    MultiRemoteSolanaClient, SolanaWallet,
};
pub use store::{MockPaymentStore, PaymentStore};
pub use stripe::{
    CheckoutSessionResponse, CreateCheckoutParams, StripeCheckoutSession, StripeClient,
};
pub use tron::TronWallet;
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

        let ref_key = generate_solana_reference();
        assert!(!ref_key.is_empty());
        let sol_url = build_solana_pay_url("recipient", 1.0, &ref_key, None, "test");
        assert_eq!(extract_reference_param(&sol_url), Some(ref_key));
    }
}
