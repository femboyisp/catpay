# 🐾 catpay

A standalone, database-agnostic cryptocurrency payment, address derivation, and USD price oracle library for Rust.

`catpay` powers cryptocurrency checkout, deposit monitoring, and automated accounting across the `socks.cat` ecosystem and independent services. It is designed to be completely decoupled from any specific database or application schema: you provide an implementation of the simple [`PaymentStore`](#the-paymentstore-trait) trait, and `catpay` handles all cryptographic derivation, daemon RPC communication, and transaction verification.

---

## Features

- **Decoupled Architecture**: Zero database coupling. Storage of HD indices and active invoice addresses is abstracted through `PaymentStore`.
- **Comprehensive Coin Coverage**: First-class support for Monero, Bitcoin, Litecoin, Dogecoin, Bitcoin Cash, Ethereum, EVM networks, Solana, Tron, ERC-20, and SPL tokens.
- **Hierarchical Deterministic (HD) Derivation**: In-process derivation for BIP32/BIP84 (`wpkh`), CashAddr, Tron Base58Check, and Solana Ed25519 addresses.
- **Failover & High Availability**: Node-to-remote failover with configurable hysteresis (e.g., Bitcoin Core primary with Esplora fallback; Monero wallet RPC with `monerod` daemon-swing).
- **Multi-Source USD Price Oracle**: Keyless, real-time spot price aggregation with median calculation across Coinbase, Kraken, Binance, KuCoin, Bitfinex, Bitstamp, and CoinGecko.
- **Solana Pay**: Native support for Solana Pay transaction request URIs and unique reference tracking.
- **Hermetic Testing**: Includes [`MockPaymentStore`](#mockpaymentstore) and offline mock RPC utilities for zero-dependency integration testing.

---

## Supported Coins & Tokens

| Coin | Symbol | Derivation / Protocol | Decimals | Backend |
|---|---|---|---|---|
| **Monero** | `XMR` | Subaddresses (BIP-like / internal) | 12 | `MoneroWallet` (monero-wallet-rpc + daemon swing) |
| **Bitcoin** | `BTC` | BIP84 native SegWit (`bc1...`) | 8 | `BitcoinWallet` (Core RPC) / `EsploraSource` |
| **Litecoin** | `LTC` | BIP84 native SegWit (`ltc1...`) | 8 | `LitecoinWallet` / `EsploraSource` |
| **Dogecoin** | `DOGE` | Legacy P2PKH (`D...`) | 8 | `DogecoinWallet` / `ElectrumSource` |
| **Bitcoin Cash** | `BCH` | CashAddr P2PKH (`bitcoincash:...`) | 8 | `BitcoinCashWallet` / `ElectrumSource` |
| **Ethereum** | `ETH` | BIP32 / BIP44 (`0x...`) | 18 | `EthereumWallet` (`MultiRemoteEthClient`) |
| **BNB Smart Chain** | `BNB` | BIP44 EVM (`0x...`) | 18 | `EvmNativeWallet` |
| **Polygon** | `POL` | BIP44 EVM (`0x...`) | 18 | `EvmNativeWallet` |
| **Avalanche C-Chain** | `AVAX` | BIP44 EVM (`0x...`) | 18 | `EvmNativeWallet` |
| **Base** | `ETH` | BIP44 EVM (mirrors ETH spot rate) | 18 | `EvmNativeWallet` |
| **Tron** | `TRX` | Keccak-256 + Base58Check (`T...`) | 6 | `TronWallet` (Solidity Node RPC) |
| **Solana** | `SOL` | Solana Pay Reference / Ed25519 | 9 | `SolanaWallet` (`MultiRemoteSolanaClient`) |
| **ERC-20 Tokens** | `USDC`, `USDT`, etc. | EVM Token Contract | Token-defined | `Erc20Wallet` / `EvmTokenWallet` |
| **SPL Tokens** | `USDC`, etc. | SPL Mint Contract | Token-defined | `SolanaWallet` (SPL mode) |

---

## Architecture

```
                  ┌────────────────────────────────────────────────────────┐
                  │                         catpay                         │
                  │  - Derivation (BIP84, CashAddr, Tron, Solana Pay)      │
                  │  - Backends (BTC, XMR, ETH, SOL, LTC, DOGE, BCH, TRX)  │
                  │  - Oracle (Median spot pricing across 7+ exchanges)    │
                  │  - Trait: PaymentStore                                 │
                  │  - Trait: PaymentBackend & FailoverBackend             │
                  └───────────────────────────┬────────────────────────────┘
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      ▼                                               ▼
         ┌─────────────────────────┐                     ┌─────────────────────────┐
         │     socks-cat-api       │                     │       femboy-www        │
         │ - PostgresPaymentStore  │                     │ - SQLite / Redis Store  │
         │ - Quotes & proxy credit │                     │ - LIR / IPv6 invoices   │
         └─────────────────────────┘                     └─────────────────────────┘
```

---

## Core Traits

### The `PaymentBackend` Trait
All cryptocurrency implementations implement `PaymentBackend`:

```rust
use async_trait::async_trait;
use catpay::{Health, NewSubaddress, PaymentError, Transfer};

#[async_trait]
pub trait PaymentBackend: Send + Sync {
    /// Mint a new deposit address or subaddress labelled for tracing.
    async fn new_subaddress(&self, label: &str) -> Result<NewSubaddress, PaymentError>;

    /// Query all incoming confirmed transfers at or above `min_height`.
    async fn incoming_transfers(&self, min_height: u64) -> Result<Vec<Transfer>, PaymentError>;

    /// Current wallet balance in atomic units (optional).
    async fn balance_atomic(&self) -> Result<Option<i64>, PaymentError> { Ok(None) }

    /// Reachability and sync status of underlying daemons/RPC nodes.
    async fn health(&self) -> Health { Health::Healthy }
}
```

### The `PaymentStore` Trait
Backends that rely on monotonic HD wallet indices or address scanning delegate persistence through `PaymentStore`:

```rust
use async_trait::async_trait;
use catpay::PaymentError;

#[async_trait]
pub trait PaymentStore: Send + Sync {
    /// Monotonically increment and return the HD address derivation index for a coin.
    async fn next_hd_index(&self, coin: &str) -> Result<u64, PaymentError>;

    /// Monotonically increment and return the legacy Ethereum HD index.
    async fn next_eth_hd_index(&self) -> Result<u64, PaymentError>;

    /// Return all active/open deposit addresses currently awaiting payment.
    async fn open_addresses(&self, coin: &str) -> Result<Vec<String>, PaymentError>;

    /// Return recently derived addresses up to `limit` for balance aggregation.
    async fn recent_addresses(&self, coin: &str, limit: i64) -> Result<Vec<String>, PaymentError>;
}
```

---

## Usage & Examples

### 1. In-Process Address Derivation

`catpay::deriver` allows deterministic address generation from master extended public keys without needing a node connection:

```rust
use bech32::Hrp;
use catpay::deriver::{derive_cashaddr_p2pkh, derive_p2wpkh, derive_tron_address};

// Derive native SegWit Bitcoin address (BIP84) at index 0:
let hrp = Hrp::parse("bc").unwrap();
let zpub = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
let btc_addr = derive_p2wpkh(zpub, hrp, 0).unwrap();
println!("BTC Deposit Address: {btc_addr}");

// Derive Bitcoin Cash CashAddr:
let bch_xpub = "xpub6CatPayTest...";
let bch_addr = derive_cashaddr_p2pkh(bch_xpub, 0, "bitcoincash").unwrap();
println!("BCH Deposit Address: {bch_addr}");

// Derive Tron Address from an Ethereum-compatible xpub:
let eth_xpub = "xpub6CatPayEth...";
let tron_addr = derive_tron_address(eth_xpub, 0).unwrap();
println!("Tron Deposit Address: {tron_addr}");
```

---

### 2. Generating Solana Pay Invoices

`catpay` generates standard [Solana Pay](https://solanapay.com/) URLs and tracks transactions using unique Ed25519 reference public keys:

```rust
use catpay::solana::{build_solana_pay_url, generate_solana_reference};

let recipient = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
let reference = generate_solana_reference(); // random base58 reference key
let sol_amount = 0.5;

let pay_url = build_solana_pay_url(
    recipient,
    sol_amount,
    &reference,
    None, // None for native SOL, or Some(mint_pubkey) for SPL tokens
    "Order #1337"
);

println!("Scan QR to pay: {pay_url}");
```

---

### 3. Real-Time Multi-Source USD Price Oracle

`catpay::Oracle` queries multiple public keyless exchanges, computes the median price, and fails closed if data is stale:

```rust
use std::sync::Arc;
use std::time::Duration;
use catpay::coin::Coin;
use catpay::oracle::Oracle;

#[tokio::main]
async fn main() {
    // 5-minute staleness window
    let oracle = Arc::new(Oracle::new(Duration::from_secs(300)));

    let coins = vec![Coin::Bitcoin, Coin::Monero, Coin::Solana];
    let sources = vec![
        "coinbase".to_string(),
        "kraken".to_string(),
        "binance".to_string(),
        "coingecko".to_string(),
    ];

    // Spawn automatic background refresh every 60 seconds (requiring >= 2 sources)
    oracle.clone().spawn_refresh(coins, sources, 2, 60);

    // Retrieve spot price:
    if let Some(price) = oracle.price_usd(Coin::Bitcoin) {
        println!("Current BTC Price: ${:.2}", price);
    }
}
```

---

### 4. Implementing a Custom `PaymentStore`

Here is an example of implementing `PaymentStore` using an atomic in-memory or database backing:

```rust
use async_trait::async_trait;
use catpay::{PaymentError, PaymentStore};

pub struct MyDbStore {
    // Your DB pool / client
}

#[async_trait]
impl PaymentStore for MyDbStore {
    async fn next_hd_index(&self, coin: &str) -> Result<u64, PaymentError> {
        // Fetch and increment index from your SQL table / Redis
        Ok(1)
    }

    async fn next_eth_hd_index(&self) -> Result<u64, PaymentError> {
        Ok(1)
    }

    async fn open_addresses(&self, coin: &str) -> Result<Vec<String>, PaymentError> {
        // Return addresses for open orders/invoices in your database
        Ok(vec!["bc1q...".to_string()])
    }

    async fn recent_addresses(&self, coin: &str, limit: i64) -> Result<Vec<String>, PaymentError> {
        Ok(vec![])
    }
}
```

---

## Testing

Run unit and integration tests across all providers:

```bash
cargo test -p catpay
```

`catpay`'s test suite is 100% hermetic: unit tests for Esplora, Electrum, Solana, and EVM backends run with mock HTTP/RPC listeners and [`MockPaymentStore`](file:///home/zoa/projects/femboy/socks.cat/catpay/src/store.rs), requiring no external daemons or database setup.
