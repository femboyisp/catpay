use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct EvmTokenMeta {
    pub coin: String,
    pub symbol: String,
    pub display_name: String,
    pub network_badge: String,
    pub network: String,
    pub decimals: u8,
    pub is_stable: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub struct SplTokenMeta {
    pub coin: String,
    pub symbol: String,
    pub display_name: String,
    pub network_badge: String,
    pub mint_address: String,
    pub decimals: u8,
    pub is_stable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Coin {
    Monero,
    Bitcoin,
    Litecoin,
    Ethereum,
    Usdc,
    Usdt,
    Dogecoin,
    BitcoinCash,
    Tron,
    Bnb,
    Pol,
    Avax,
    Base,
    EvmToken(Arc<EvmTokenMeta>),
    Solana,
    SplToken(Arc<SplTokenMeta>),
}

impl Coin {
    pub fn as_str(&self) -> &str {
        match self {
            Coin::Monero => "monero",
            Coin::Bitcoin => "bitcoin",
            Coin::Litecoin => "litecoin",
            Coin::Ethereum => "ethereum",
            Coin::Usdc => "usdc",
            Coin::Usdt => "usdt",
            Coin::Dogecoin => "dogecoin",
            Coin::BitcoinCash => "bitcoincash",
            Coin::Tron => "tron",
            Coin::Bnb => "bnb",
            Coin::Pol => "pol",
            Coin::Avax => "avax",
            Coin::Base => "base",
            Coin::EvmToken(m) => m.coin.as_str(),
            Coin::Solana => "sol",
            Coin::SplToken(m) => m.coin.as_str(),
        }
    }

    pub fn symbol(&self) -> &str {
        match self {
            Coin::Monero => "xmr",
            Coin::Bitcoin => "btc",
            Coin::Litecoin => "ltc",
            Coin::Ethereum => "eth",
            Coin::Usdc => "usdc",
            Coin::Usdt => "usdt",
            Coin::Dogecoin => "doge",
            Coin::BitcoinCash => "bch",
            Coin::Tron => "trx",
            Coin::Bnb => "bnb",
            Coin::Pol => "pol",
            Coin::Avax => "avax",
            Coin::Base => "eth",
            Coin::EvmToken(m) => m.symbol.as_str(),
            Coin::Solana => "sol",
            Coin::SplToken(m) => m.symbol.as_str(),
        }
    }

    pub fn decimals(&self) -> u8 {
        match self {
            Coin::Monero => 12,
            Coin::Bitcoin | Coin::Litecoin | Coin::Dogecoin | Coin::BitcoinCash => 8,
            Coin::Tron | Coin::Usdc | Coin::Usdt => 6,
            Coin::Ethereum | Coin::Bnb | Coin::Pol | Coin::Avax | Coin::Base => 18,
            Coin::Solana => 9,
            Coin::EvmToken(m) => m.decimals,
            Coin::SplToken(m) => m.decimals,
        }
    }

    pub fn atomic_per_coin(&self) -> u128 {
        10u128.pow(self.decimals() as u32)
    }

    pub fn atomic_per_coin_u128(&self) -> u128 {
        10u128.pow(self.decimals() as u32)
    }

    pub fn is_stable(&self) -> bool {
        match self {
            Coin::Usdc | Coin::Usdt => true,
            Coin::EvmToken(m) => m.is_stable,
            Coin::SplToken(m) => m.is_stable,
            _ => false,
        }
    }

    pub fn display_name(&self) -> &str {
        match self {
            Coin::Monero => "Monero",
            Coin::Bitcoin => "Bitcoin",
            Coin::Litecoin => "Litecoin",
            Coin::Ethereum => "Ethereum",
            Coin::Usdc => "USD Coin (ERC-20)",
            Coin::Usdt => "Tether USD (ERC-20)",
            Coin::Dogecoin => "Dogecoin",
            Coin::BitcoinCash => "Bitcoin Cash",
            Coin::Tron => "Tron",
            Coin::Bnb => "BNB",
            Coin::Pol => "Polygon (POL)",
            Coin::Avax => "Avalanche (AVAX)",
            Coin::Base => "Base",
            Coin::EvmToken(m) => m.display_name.as_str(),
            Coin::Solana => "Solana",
            Coin::SplToken(m) => m.display_name.as_str(),
        }
    }

    pub fn network_badge(&self) -> Option<&str> {
        match self {
            Coin::Usdc | Coin::Usdt => Some("ERC-20"),
            Coin::Bnb => Some("BSC"),
            Coin::Pol => Some("Polygon"),
            Coin::Avax => Some("Avalanche"),
            Coin::Base => Some("Base"),
            Coin::EvmToken(m) => Some(m.network_badge.as_str()),
            Coin::Solana => Some("Solana"),
            Coin::SplToken(m) => Some(m.network_badge.as_str()),
            _ => None,
        }
    }

    pub fn network(&self) -> Option<&str> {
        match self {
            Coin::Monero => Some("monero"),
            Coin::Bitcoin => Some("bitcoin"),
            Coin::Litecoin => Some("litecoin"),
            Coin::Ethereum | Coin::Usdc | Coin::Usdt => Some("ethereum"),
            Coin::Dogecoin => Some("dogecoin"),
            Coin::BitcoinCash => Some("bitcoincash"),
            Coin::Tron => Some("tron"),
            Coin::Bnb => Some("bsc"),
            Coin::Pol => Some("polygon"),
            Coin::Avax => Some("avalanche"),
            Coin::Base => Some("base"),
            Coin::EvmToken(m) => Some(m.network.as_str()),
            Coin::Solana | Coin::SplToken(_) => Some("solana"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_core_coins() {
        let xmr = Coin::Monero;
        assert_eq!(xmr.as_str(), "monero");
        assert_eq!(xmr.symbol(), "xmr");
        assert_eq!(xmr.decimals(), 12);
        assert_eq!(xmr.atomic_per_coin(), 1_000_000_000_000);
        assert_eq!(xmr.display_name(), "Monero");
        assert_eq!(xmr.network(), Some("monero"));
        assert_eq!(xmr.network_badge(), None);
        assert!(!xmr.is_stable());

        let btc = Coin::Bitcoin;
        assert_eq!(btc.as_str(), "bitcoin");
        assert_eq!(btc.symbol(), "btc");
        assert_eq!(btc.decimals(), 8);
        assert_eq!(btc.atomic_per_coin(), 100_000_000);
        assert_eq!(btc.display_name(), "Bitcoin");
        assert_eq!(btc.network(), Some("bitcoin"));
        assert!(!btc.is_stable());

        let ltc = Coin::Litecoin;
        assert_eq!(ltc.as_str(), "litecoin");
        assert_eq!(ltc.symbol(), "ltc");
        assert_eq!(ltc.decimals(), 8);
        assert_eq!(ltc.atomic_per_coin(), 100_000_000);

        let eth = Coin::Ethereum;
        assert_eq!(eth.as_str(), "ethereum");
        assert_eq!(eth.symbol(), "eth");
        assert_eq!(eth.decimals(), 18);
        assert_eq!(eth.atomic_per_coin(), 1_000_000_000_000_000_000);
        assert_eq!(eth.atomic_per_coin_u128(), 1_000_000_000_000_000_000);

        let usdc = Coin::Usdc;
        assert_eq!(usdc.as_str(), "usdc");
        assert_eq!(usdc.symbol(), "usdc");
        assert_eq!(usdc.decimals(), 6);
        assert_eq!(usdc.atomic_per_coin(), 1_000_000);
        assert!(usdc.is_stable());
        assert_eq!(usdc.network_badge(), Some("ERC-20"));
        assert_eq!(usdc.network(), Some("ethereum"));

        let usdt = Coin::Usdt;
        assert_eq!(usdt.as_str(), "usdt");
        assert_eq!(usdt.symbol(), "usdt");
        assert_eq!(usdt.decimals(), 6);
        assert_eq!(usdt.atomic_per_coin(), 1_000_000);
        assert!(usdt.is_stable());

        let doge = Coin::Dogecoin;
        assert_eq!(doge.as_str(), "dogecoin");
        assert_eq!(doge.symbol(), "doge");
        assert_eq!(doge.decimals(), 8);

        let bch = Coin::BitcoinCash;
        assert_eq!(bch.as_str(), "bitcoincash");
        assert_eq!(bch.symbol(), "bch");
        assert_eq!(bch.decimals(), 8);

        let trx = Coin::Tron;
        assert_eq!(trx.as_str(), "tron");
        assert_eq!(trx.symbol(), "trx");
        assert_eq!(trx.decimals(), 6);

        let bnb = Coin::Bnb;
        assert_eq!(bnb.as_str(), "bnb");
        assert_eq!(bnb.symbol(), "bnb");
        assert_eq!(bnb.decimals(), 18);
        assert_eq!(bnb.network_badge(), Some("BSC"));
        assert_eq!(bnb.network(), Some("bsc"));

        let pol = Coin::Pol;
        assert_eq!(pol.as_str(), "pol");
        assert_eq!(pol.symbol(), "pol");
        assert_eq!(pol.decimals(), 18);
        assert_eq!(pol.network_badge(), Some("Polygon"));
        assert_eq!(pol.network(), Some("polygon"));

        let avax = Coin::Avax;
        assert_eq!(avax.as_str(), "avax");
        assert_eq!(avax.symbol(), "avax");
        assert_eq!(avax.decimals(), 18);
        assert_eq!(avax.network_badge(), Some("Avalanche"));
        assert_eq!(avax.network(), Some("avalanche"));

        let base = Coin::Base;
        assert_eq!(base.as_str(), "base");
        assert_eq!(base.symbol(), "eth");
        assert_eq!(base.decimals(), 18);
        assert_eq!(base.network_badge(), Some("Base"));
        assert_eq!(base.network(), Some("base"));

        let sol = Coin::Solana;
        assert_eq!(sol.as_str(), "sol");
        assert_eq!(sol.symbol(), "sol");
        assert_eq!(sol.decimals(), 9);
        assert_eq!(sol.atomic_per_coin(), 1_000_000_000);
        assert_eq!(sol.network_badge(), Some("Solana"));
        assert_eq!(sol.network(), Some("solana"));
    }

    #[test]
    fn test_custom_evm_and_spl_tokens() {
        let evm_meta = Arc::new(EvmTokenMeta {
            coin: "usdt-bsc".to_string(),
            symbol: "usdt".to_string(),
            display_name: "Tether (BSC)".to_string(),
            network_badge: "BEP-20".to_string(),
            network: "bsc".to_string(),
            decimals: 18,
            is_stable: true,
        });
        let evm_coin = Coin::EvmToken(evm_meta);
        assert_eq!(evm_coin.as_str(), "usdt-bsc");
        assert_eq!(evm_coin.symbol(), "usdt");
        assert_eq!(evm_coin.decimals(), 18);
        assert_eq!(evm_coin.atomic_per_coin(), 1_000_000_000_000_000_000);
        assert_eq!(evm_coin.display_name(), "Tether (BSC)");
        assert_eq!(evm_coin.network_badge(), Some("BEP-20"));
        assert_eq!(evm_coin.network(), Some("bsc"));
        assert!(evm_coin.is_stable());

        let spl_meta = Arc::new(SplTokenMeta {
            coin: "usdc-sol".to_string(),
            symbol: "usdc".to_string(),
            display_name: "USD Coin (Solana)".to_string(),
            network_badge: "SPL".to_string(),
            mint_address: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
            decimals: 6,
            is_stable: true,
        });
        let spl_coin = Coin::SplToken(spl_meta);
        assert_eq!(spl_coin.as_str(), "usdc-sol");
        assert_eq!(spl_coin.symbol(), "usdc");
        assert_eq!(spl_coin.decimals(), 6);
        assert_eq!(spl_coin.atomic_per_coin(), 1_000_000);
        assert_eq!(spl_coin.display_name(), "USD Coin (Solana)");
        assert_eq!(spl_coin.network_badge(), Some("SPL"));
        assert_eq!(spl_coin.network(), Some("solana"));
        assert!(spl_coin.is_stable());
    }

    #[test]
    fn test_serde_coin() {
        let btc = Coin::Bitcoin;
        let serialized = serde_json::to_string(&btc).expect("serialize");
        let deserialized: Coin = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(btc, deserialized);
    }
}
