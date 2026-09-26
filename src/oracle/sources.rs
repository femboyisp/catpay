//! Keyless public price-source adapters. Network fetches are coverage-excluded;
//! the pure `parse_*` fns are unit-tested against captured response shapes.
use serde_json::Value;

use super::OracleError;

#[allow(dead_code, clippy::allow_attributes)]
pub const SOURCE_NAMES: &[&str] = &[
    "coingecko",
    "coinbase",
    "kraken",
    "binance",
    "bitstamp",
    "kucoin",
    "bitfinex",
];

fn perr(msg: impl Into<String>) -> OracleError {
    OracleError::Parse(msg.into())
}

fn parse_err(e: serde_json::Error) -> OracleError {
    OracleError::Parse(e.to_string())
}

/// symbol ("btc") -> CoinGecko id ("bitcoin"). Extend as coins are added.
fn coingecko_id(symbol: &str) -> Option<&'static str> {
    match symbol {
        "btc" => Some("bitcoin"),
        "xmr" => Some("monero"),
        "ltc" => Some("litecoin"),
        "eth" => Some("ethereum"),
        "bnb" => Some("binancecoin"),
        "pol" | "matic" => Some("polygon-ecosystem-token"),
        "avax" => Some("avalanche-2"),
        "sol" => Some("solana"),
        _ => None,
    }
}

pub fn parse_coingecko(body: &str, id: &str) -> Result<f64, OracleError> {
    let v: Value = serde_json::from_str(body).map_err(parse_err)?;
    v.get(id)
        .and_then(|o| o.get("usd"))
        .and_then(Value::as_f64)
        .ok_or_else(|| perr("coingecko: missing usd"))
}

pub fn parse_coinbase(body: &str) -> Result<f64, OracleError> {
    let v: Value = serde_json::from_str(body).map_err(parse_err)?;
    v.get("data")
        .and_then(|d| d.get("amount"))
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| perr("coinbase: missing amount"))
}

pub fn parse_kraken(body: &str) -> Result<f64, OracleError> {
    let v: Value = serde_json::from_str(body).map_err(parse_err)?;
    let result = v
        .get("result")
        .and_then(Value::as_object)
        .ok_or_else(|| perr("kraken: no result"))?;
    let pair = result
        .values()
        .next()
        .ok_or_else(|| perr("kraken: empty result"))?;
    pair.get("c")
        .and_then(|c| c.get(0))
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| perr("kraken: missing close"))
}

pub fn parse_binance(body: &str) -> Result<f64, OracleError> {
    let v: Value = serde_json::from_str(body).map_err(parse_err)?;
    v.get("price")
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| perr("binance: missing price"))
}

pub fn parse_bitstamp(body: &str) -> Result<f64, OracleError> {
    let v: Value = serde_json::from_str(body).map_err(parse_err)?;
    v.get("last")
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| perr("bitstamp: missing last"))
}

pub fn parse_kucoin(body: &str) -> Result<f64, OracleError> {
    let v: Value = serde_json::from_str(body).map_err(parse_err)?;
    v.get("data")
        .and_then(|d| d.get("price"))
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| perr("kucoin: missing price"))
}

/// Bitfinex v2 ticker is a flat array; the last trade price is index 6.
pub fn parse_bitfinex(body: &str) -> Result<f64, OracleError> {
    let v: Value = serde_json::from_str(body).map_err(parse_err)?;
    v.get(6)
        .and_then(Value::as_f64)
        .ok_or_else(|| perr("bitfinex: missing last price"))
}

pub async fn fetch(source: &str, symbol: &str, http: &reqwest::Client) -> Result<f64, OracleError> {
    let upper = symbol.to_uppercase();
    let lower = symbol.to_lowercase();
    match source {
        "coingecko" => {
            let id = coingecko_id(&lower)
                .ok_or_else(|| perr(format!("coingecko: unsupported coin {lower}")))?;
            let url =
                format!("https://api.coingecko.com/api/v3/simple/price?ids={id}&vs_currencies=usd");
            let resp = http
                .get(&url)
                .send()
                .await
                .map_err(|e| OracleError::Http(e.to_string()))?;
            let body = resp
                .text()
                .await
                .map_err(|e| OracleError::Http(e.to_string()))?;
            parse_coingecko(&body, id)
        }
        "coinbase" => {
            let url = format!("https://api.coinbase.com/v2/prices/{upper}-USD/spot");
            let resp = http
                .get(&url)
                .send()
                .await
                .map_err(|e| OracleError::Http(e.to_string()))?;
            let body = resp
                .text()
                .await
                .map_err(|e| OracleError::Http(e.to_string()))?;
            parse_coinbase(&body)
        }
        "kraken" => {
            let pair = match upper.as_str() {
                "BTC" => "XBTUSD",
                "XMR" => "XMRUSD",
                "LTC" => "LTCUSD",
                "ETH" => "ETHUSD",
                "DOGE" => "XDGUSD",
                "BCH" => "BCHUSD",
                "SOL" => "SOLUSD",
                other => {
                    return Err(perr(format!("kraken: unsupported coin {other}")));
                }
            };
            let url = format!("https://api.kraken.com/0/public/Ticker?pair={pair}");
            let resp = http
                .get(&url)
                .send()
                .await
                .map_err(|e| OracleError::Http(e.to_string()))?;
            let body = resp
                .text()
                .await
                .map_err(|e| OracleError::Http(e.to_string()))?;
            parse_kraken(&body)
        }
        "binance" => {
            let pair = format!("{upper}USDT");
            let url = format!("https://api.binance.com/api/v3/ticker/price?symbol={pair}");
            let resp = http
                .get(&url)
                .send()
                .await
                .map_err(|e| OracleError::Http(e.to_string()))?;
            let body = resp
                .text()
                .await
                .map_err(|e| OracleError::Http(e.to_string()))?;
            parse_binance(&body)
        }
        "bitstamp" => {
            let pair = format!("{lower}usd");
            let url = format!("https://www.bitstamp.net/api/v2/ticker/{pair}/");
            let resp = http
                .get(&url)
                .send()
                .await
                .map_err(|e| OracleError::Http(e.to_string()))?;
            let body = resp
                .text()
                .await
                .map_err(|e| OracleError::Http(e.to_string()))?;
            parse_bitstamp(&body)
        }
        "kucoin" => {
            let pair = format!("{upper}-USDT");
            let url =
                format!("https://api.kucoin.com/api/v1/market/orderbook/level1?symbol={pair}");
            let resp = http
                .get(&url)
                .send()
                .await
                .map_err(|e| OracleError::Http(e.to_string()))?;
            let body = resp
                .text()
                .await
                .map_err(|e| OracleError::Http(e.to_string()))?;
            parse_kucoin(&body)
        }
        "bitfinex" => {
            let pair = match upper.as_str() {
                "DOGE" => "tDOGE:USD",
                "SOL" => "tSOLUSD",
                _ => {
                    return Err(perr(format!("bitfinex: unsupported coin {upper}")));
                }
            };
            let url = format!("https://api-pub.bitfinex.com/v2/ticker/{pair}");
            let resp = http
                .get(&url)
                .send()
                .await
                .map_err(|e| OracleError::Http(e.to_string()))?;
            let body = resp
                .text()
                .await
                .map_err(|e| OracleError::Http(e.to_string()))?;
            parse_bitfinex(&body)
        }
        other => Err(perr(format!("unknown source: {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_coinbase_ok() {
        let json = r#"{"data":{"base":"BTC","currency":"USD","amount":"65432.10"}}"#;
        assert_eq!(parse_coinbase(json).unwrap(), 65432.10);
    }

    #[test]
    fn parse_kraken_ok() {
        let json = r#"{"error":[],"result":{"XXBTZUSD":{"a":["65432.0"],"b":["65431.0"],"c":["65430.50","0.1"]}}}"#;
        assert_eq!(parse_kraken(json).unwrap(), 65430.50);
    }

    #[test]
    fn parse_binance_ok() {
        let json = r#"{"symbol":"BTCUSDT","price":"65435.00"}"#;
        assert_eq!(parse_binance(json).unwrap(), 65435.00);
    }

    #[test]
    fn parse_bitstamp_ok() {
        let json = r#"{"last":"65428.99","high":"66000.00"}"#;
        assert_eq!(parse_bitstamp(json).unwrap(), 65428.99);
    }

    #[test]
    fn parse_kucoin_ok() {
        let json = r#"{"code":"200000","data":{"price":"65431.25"}}"#;
        assert_eq!(parse_kucoin(json).unwrap(), 65431.25);
    }

    #[test]
    fn parse_coingecko_ok() {
        let json = r#"{"bitcoin":{"usd":65400.00}}"#;
        assert_eq!(parse_coingecko(json, "bitcoin").unwrap(), 65400.00);
    }

    #[test]
    fn test_coingecko_id_mappings() {
        assert_eq!(coingecko_id("btc"), Some("bitcoin"));
        assert_eq!(coingecko_id("xmr"), Some("monero"));
        assert_eq!(coingecko_id("ltc"), Some("litecoin"));
        assert_eq!(coingecko_id("eth"), Some("ethereum"));
        assert_eq!(coingecko_id("bnb"), Some("binancecoin"));
        assert_eq!(coingecko_id("pol"), Some("polygon-ecosystem-token"));
        assert_eq!(coingecko_id("matic"), Some("polygon-ecosystem-token"));
        assert_eq!(coingecko_id("avax"), Some("avalanche-2"));
        assert_eq!(coingecko_id("sol"), Some("solana"));
        assert_eq!(coingecko_id("unknown"), None);
    }

    #[test]
    fn test_parse_coingecko_bnb_pol_avax() {
        let json = r#"{"binancecoin":{"usd":580.50},"polygon-ecosystem-token":{"usd":0.42},"avalanche-2":{"usd":28.75}}"#;
        assert_eq!(parse_coingecko(json, "binancecoin").unwrap(), 580.50);
        assert_eq!(
            parse_coingecko(json, "polygon-ecosystem-token").unwrap(),
            0.42
        );
        assert_eq!(parse_coingecko(json, "avalanche-2").unwrap(), 28.75);
    }

    #[test]
    fn test_parse_coingecko_sol() {
        let json = r#"{"solana":{"usd":150.25}}"#;
        assert_eq!(parse_coingecko(json, "solana").unwrap(), 150.25);
    }

    #[test]
    fn parse_bitfinex_ok() {
        let json = r#"[2.5, 100, 2.6, 90, 0.1, 0.05, 155.45, 1000, 160, 150]"#;
        assert_eq!(parse_bitfinex(json).unwrap(), 155.45);
    }

    #[test]
    fn parse_errors_are_parse_errors() {
        assert!(matches!(
            parse_coinbase("not json"),
            Err(OracleError::Parse(_))
        ));
        assert!(matches!(
            parse_kraken(r#"{"result":{}}"#),
            Err(OracleError::Parse(_))
        ));
        assert!(matches!(parse_binance(r#"{}"#), Err(OracleError::Parse(_))));
        assert!(matches!(
            parse_bitstamp(r#"{}"#),
            Err(OracleError::Parse(_))
        ));
        assert!(matches!(parse_kucoin(r#"{}"#), Err(OracleError::Parse(_))));
        assert!(matches!(
            parse_coingecko(r#"{}"#, "bitcoin"),
            Err(OracleError::Parse(_))
        ));
        assert!(matches!(
            parse_bitfinex(r#"[]"#),
            Err(OracleError::Parse(_))
        ));
    }
}
