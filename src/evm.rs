//! Generalized EVM payment backends.
//!
//! Provides [`MultiRemoteEvmClient`] (a type alias for
//! [`super::ethereum::MultiRemoteEthClient`] for backward compatibility),
//! [`EvmNativeWallet`] for native gas-coin deposits (BNB, POL, AVAX, ETH,
//! etc.) and [`EvmTokenWallet`] for ERC-20/BEP-20 token deposits, all driven
//! by a shared `MultiRemoteEvmClient` per network.

use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bip32::XPub;

use crate::backend::PaymentBackend;
use crate::coin::Coin;
use crate::error::PaymentError;
use crate::ethereum::{derive_eth_address, MultiRemoteEthClient};
use crate::store::PaymentStore;
use crate::types::{Health, NewSubaddress, Transfer};

/// A generalized multi-remote EVM JSON-RPC client with sequential failover
/// and hysteresis — wraps the existing Ethereum client implementation.
///
/// `MultiRemoteEthClient` remains a valid alias pointing to the same type.
pub type MultiRemoteEvmClient = MultiRemoteEthClient;

/// Derive an EVM-compatible deposit address (secp256k1 BIP32, keccak256,
/// EIP-55) for a non-hardened child of the receive xpub at `index`.
///
/// This is identical to the Ethereum derivation — all EVM chains use the same
/// address format — but is re-exported here under the generic name so callers
/// can express intent without coupling to `ethereum.rs`.
#[allow(dead_code, clippy::allow_attributes)]
pub fn derive_evm_address(xpub: &str, index: u32) -> Result<String, PaymentError> {
    let xpub_parsed = XPub::from_str(xpub.trim())
        .map_err(|e| PaymentError::Rpc(format!("invalid evm xpub: {e}")))?;
    derive_eth_address(&xpub_parsed, index)
}

// ---------------------------------------------------------------------------
// EvmNativeWallet — watches a native gas coin via eth_getBalance
// ---------------------------------------------------------------------------

/// Cap on how many deposit addresses `balance_atomic` will scan.
const MAX_BALANCE_ADDRESSES: i64 = 64;

/// A watch-only EVM native-coin deposit wallet (ETH on Ethereum, BNB on BSC,
/// POL on Polygon, AVAX on Avalanche C-Chain, etc.) driven via
/// `eth_getBalance` over a shared [`MultiRemoteEvmClient`].
pub struct EvmNativeWallet {
    client: Arc<MultiRemoteEvmClient>,
    xpub: XPub,
    /// Coin identifier used for the store queries and synthesised txids
    /// (e.g. `"bnb"`, `"pol"`, `"avax"`, `"ethereum"`).
    coin: Coin,
    min_confirmations: u64,
    store: Arc<dyn PaymentStore>,
}

impl EvmNativeWallet {
    pub fn new(
        client: Arc<MultiRemoteEvmClient>,
        xpub: &str,
        coin: Coin,
        min_confirmations: u64,
        store: Arc<dyn PaymentStore>,
    ) -> Result<Self, PaymentError> {
        let xpub = XPub::from_str(xpub.trim())
            .map_err(|e| PaymentError::Rpc(format!("invalid {} xpub: {e}", coin.as_str())))?;
        Ok(Self {
            client,
            xpub,
            coin,
            min_confirmations,
            store,
        })
    }

    #[allow(dead_code, clippy::allow_attributes)]
    pub fn connect(
        url: &str,
        xpub: &str,
        coin: Coin,
        min_confirmations: u64,
        store: Arc<dyn PaymentStore>,
    ) -> Result<Self, PaymentError> {
        let client = Arc::new(MultiRemoteEvmClient::new(url.to_owned(), vec![], 3, 3));
        Self::new(client, xpub, coin, min_confirmations, store)
    }

    pub fn coin_name(&self) -> &str {
        self.coin.as_str()
    }

    fn address_for_index(&self, index: u32) -> Result<String, PaymentError> {
        derive_eth_address(&self.xpub, index)
    }

    #[allow(dead_code, clippy::allow_attributes)]
    pub fn client(&self) -> &Arc<MultiRemoteEvmClient> {
        &self.client
    }
}

#[async_trait]
impl PaymentBackend for EvmNativeWallet {
    async fn new_subaddress(&self, _label: &str) -> Result<NewSubaddress, PaymentError> {
        let coin_name = self.coin_name().to_owned();
        let index = if coin_name == "ethereum" {
            // Ethereum uses its own dedicated sequence for backward compat
            self.store.next_eth_hd_index().await?
        } else {
            self.store.next_hd_index(&coin_name).await?
        };
        let index_u32 = u32::try_from(index)
            .map_err(|_| PaymentError::Rpc(format!("{coin_name} hd index overflow")))?;
        let address = self.address_for_index(index_u32)?;
        Ok(NewSubaddress {
            address,
            index: u64::from(index_u32),
        })
    }

    async fn incoming_transfers(&self, _min_height: u64) -> Result<Vec<Transfer>, PaymentError> {
        self.client.refresh_source().await;
        let latest = self.client.block_number().await?;
        let target = latest.saturating_sub(self.min_confirmations);
        let block_param = if self.min_confirmations == 0 {
            "latest".to_owned()
        } else {
            format!("0x{target:x}")
        };

        let coin_name = self.coin_name().to_owned();
        let addresses = self.store.open_addresses(&coin_name).await?;

        let mut transfers = Vec::new();
        for address in addresses {
            let wei = self.client.balance_at(&address, &block_param).await?;
            if wei > 0 {
                transfers.push(Transfer {
                    txid: format!("{}:{address}", self.coin_name()),
                    amount_atomic: u64::try_from(wei).unwrap_or(u64::MAX),
                    address,
                    height: target,
                    confirmations: self.min_confirmations,
                });
            }
        }
        Ok(transfers)
    }

    async fn balance_atomic(&self) -> Result<Option<i64>, PaymentError> {
        let coin_name = self.coin_name().to_owned();
        let addresses = self
            .store
            .recent_addresses(&coin_name, MAX_BALANCE_ADDRESSES)
            .await?;
        if addresses.len() as i64 >= MAX_BALANCE_ADDRESSES {
            eprintln!(
                "payments[{}]: wallet_balance_atomic scan capped at \
                 {MAX_BALANCE_ADDRESSES} most-recent address(es)",
                self.coin_name()
            );
        }
        let mut total = 0u128;
        for address in &addresses {
            match self.client.balance_at(address, "latest").await {
                Ok(wei) => total = total.saturating_add(wei),
                Err(e) => eprintln!(
                    "payments[{}]: balance_at({address}) failed: {e}",
                    self.coin_name()
                ),
            }
        }
        Ok(Some(i64::try_from(total).unwrap_or(i64::MAX)))
    }

    async fn health(&self) -> Health {
        self.client.health().await
    }
}

// ---------------------------------------------------------------------------
// EvmTokenWallet — watches an ERC-20 / BEP-20 / etc. token via balanceOf
// ---------------------------------------------------------------------------

/// A watch-only EVM token deposit wallet (ERC-20, BEP-20, ARC-20 …) driven
/// via `eth_call(balanceOf)` over a shared [`MultiRemoteEvmClient`].
pub struct EvmTokenWallet {
    client: Arc<MultiRemoteEvmClient>,
    xpub: XPub,
    contract_address: String,
    coin: Coin,
    min_confirmations: u64,
    store: Arc<dyn PaymentStore>,
}

impl EvmTokenWallet {
    pub fn new(
        client: Arc<MultiRemoteEvmClient>,
        xpub: &str,
        contract_address: &str,
        coin: Coin,
        min_confirmations: u64,
        store: Arc<dyn PaymentStore>,
    ) -> Result<Self, PaymentError> {
        let xpub = XPub::from_str(xpub.trim())
            .map_err(|e| PaymentError::Rpc(format!("invalid {} xpub: {e}", coin.as_str())))?;
        Ok(Self {
            client,
            xpub,
            contract_address: contract_address.trim().to_ascii_lowercase(),
            coin,
            min_confirmations,
            store,
        })
    }

    #[allow(dead_code, clippy::allow_attributes)]
    pub fn connect(
        url: &str,
        xpub: &str,
        contract_address: &str,
        coin: Coin,
        min_confirmations: u64,
        store: Arc<dyn PaymentStore>,
    ) -> Result<Self, PaymentError> {
        let client = Arc::new(MultiRemoteEvmClient::new(url.to_owned(), vec![], 3, 3));
        Self::new(
            client,
            xpub,
            contract_address,
            coin,
            min_confirmations,
            store,
        )
    }

    pub fn coin_name(&self) -> &str {
        self.coin.as_str()
    }

    fn address_for_index(&self, index: u32) -> Result<String, PaymentError> {
        derive_eth_address(&self.xpub, index)
    }

    async fn balance_of(&self, address: &str, block: &str) -> Result<u128, PaymentError> {
        self.client
            .balance_of(&self.contract_address, address, block)
            .await
    }

    #[allow(dead_code, clippy::allow_attributes)]
    pub fn client(&self) -> &Arc<MultiRemoteEvmClient> {
        &self.client
    }
}

#[async_trait]
impl PaymentBackend for EvmTokenWallet {
    async fn new_subaddress(&self, _label: &str) -> Result<NewSubaddress, PaymentError> {
        let coin_name = self.coin_name().to_owned();
        let index = self.store.next_hd_index(&coin_name).await?;
        let index_u32 = u32::try_from(index)
            .map_err(|_| PaymentError::Rpc(format!("{coin_name} hd index overflow")))?;
        let address = self.address_for_index(index_u32)?;
        Ok(NewSubaddress {
            address,
            index: u64::from(index_u32),
        })
    }

    async fn incoming_transfers(&self, _min_height: u64) -> Result<Vec<Transfer>, PaymentError> {
        self.client.refresh_source().await;
        let latest = self.client.block_number().await?;
        let target = latest.saturating_sub(self.min_confirmations);
        let block_param = if self.min_confirmations == 0 {
            "latest".to_owned()
        } else {
            format!("0x{target:x}")
        };

        let coin_name = self.coin_name().to_owned();
        let addresses = self.store.open_addresses(&coin_name).await?;

        let mut transfers = Vec::new();
        for address in addresses {
            let atomic = self.balance_of(&address, &block_param).await?;
            if atomic > 0 {
                transfers.push(Transfer {
                    txid: format!("{}:{address}", self.coin_name()),
                    amount_atomic: u64::try_from(atomic).unwrap_or(u64::MAX),
                    address,
                    height: target,
                    confirmations: self.min_confirmations,
                });
            }
        }
        Ok(transfers)
    }

    async fn balance_atomic(&self) -> Result<Option<i64>, PaymentError> {
        let coin_name = self.coin_name().to_owned();
        let addresses = self
            .store
            .recent_addresses(&coin_name, MAX_BALANCE_ADDRESSES)
            .await?;
        if addresses.len() as i64 >= MAX_BALANCE_ADDRESSES {
            eprintln!(
                "payments[{}]: wallet_balance_atomic scan capped at {MAX_BALANCE_ADDRESSES} \
                 most-recent address(es); quote history may be larger",
                self.coin_name()
            );
        }
        let mut balances = Vec::with_capacity(addresses.len());
        for address in &addresses {
            match self.balance_of(address, "latest").await {
                Ok(v) => balances.push(v),
                Err(e) => eprintln!(
                    "payments[{}]: balance_of({address}) failed: {e}",
                    self.coin_name()
                ),
            }
        }
        let total = balances
            .into_iter()
            .fold(0u128, |acc, v| acc.saturating_add(v));
        Ok(Some(i64::try_from(total).unwrap_or(i64::MAX)))
    }

    async fn health(&self) -> Health {
        self.client.health().await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coin::EvmTokenMeta;
    use crate::store::MockPaymentStore;

    #[test]
    fn test_evm_address_derivation_standard_vector() {
        // Valid BIP32 xpub deriving child 0 matches standard EIP-55 address
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let addr0 = derive_evm_address(xpub, 0).expect("derives address");
        assert!(addr0.starts_with("0x"));
        assert_eq!(addr0.len(), 42);
        // Known answer from ethereum.rs test
        assert_eq!(addr0, "0xaefbb50942817d8270bb9bd922aa5ca9cb06cdbf");
    }

    #[test]
    fn derive_evm_address_produces_distinct_per_index() {
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let a0 = derive_evm_address(xpub, 0).unwrap();
        let a1 = derive_evm_address(xpub, 1).unwrap();
        assert_ne!(a0, a1);
        assert_eq!(a0, derive_evm_address(xpub, 0).unwrap()); // deterministic
    }

    #[test]
    fn derive_evm_address_rejects_invalid_xpub() {
        let result = derive_evm_address("not-an-xpub", 0);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_evm_native_wallet_new_subaddress_with_mock_store() {
        let store = Arc::new(MockPaymentStore::new());
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let wallet =
            EvmNativeWallet::connect("http://127.0.0.1:8545", xpub, Coin::Bnb, 15, store).unwrap();

        let sub1 = wallet.new_subaddress("label1").await.unwrap();
        assert_eq!(sub1.index, 0);
        assert_eq!(sub1.address, "0xaefbb50942817d8270bb9bd922aa5ca9cb06cdbf");

        let sub2 = wallet.new_subaddress("label2").await.unwrap();
        assert_eq!(sub2.index, 1);
        assert_eq!(sub2.address, "0x84f549a5be894f8faeb744952d2669fb55366798");
    }

    #[tokio::test]
    async fn test_evm_token_wallet_new_subaddress_with_mock_store() {
        let store = Arc::new(MockPaymentStore::new());
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let coin = Coin::EvmToken(Arc::new(EvmTokenMeta {
            coin: "usdt-bsc".into(),
            symbol: "usdt".into(),
            display_name: "Tether USD (BSC)".into(),
            network_badge: "BEP-20".into(),
            network: "bsc".into(),
            decimals: 18,
            is_stable: true,
        }));
        let wallet = EvmTokenWallet::connect(
            "http://127.0.0.1:8545",
            xpub,
            "0x55d398326f99059ff775485246999027b3197955",
            coin,
            15,
            store,
        )
        .unwrap();

        let sub1 = wallet.new_subaddress("label1").await.unwrap();
        assert_eq!(sub1.index, 0);
        assert_eq!(sub1.address, "0xaefbb50942817d8270bb9bd922aa5ca9cb06cdbf");

        let sub2 = wallet.new_subaddress("label2").await.unwrap();
        assert_eq!(sub2.index, 1);
        assert_eq!(sub2.address, "0x84f549a5be894f8faeb744952d2669fb55366798");
    }

    async fn spawn_mock_evm_node() -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 4096];
                    let Ok(n) = stream.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    let body_str = String::from_utf8_lossy(&buf[..n]);
                    let result_str = if body_str.contains("eth_call") {
                        "0xde0b6b3a7640000" // 1 token
                    } else if body_str.contains("eth_getBalance") {
                        "0x1bc16d674ec80000" // 2 native gas tokens
                    } else {
                        "0x20" // block 32
                    };
                    let body = format!(
                        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"{}\"}}",
                        result_str
                    );
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });
        (url, handle)
    }

    #[tokio::test]
    async fn test_evm_native_incoming_transfers_and_balance() {
        let (node_url, _h) = spawn_mock_evm_node().await;
        let store = Arc::new(MockPaymentStore::new());
        let addr = "0xaefbb50942817d8270bb9bd922aa5ca9cb06cdbf";
        store
            .open_addrs
            .lock()
            .unwrap()
            .insert("bnb".to_string(), vec![addr.to_string()]);
        store
            .recent_addrs
            .lock()
            .unwrap()
            .insert("bnb".to_string(), vec![addr.to_string()]);

        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let wallet = EvmNativeWallet::connect(&node_url, xpub, Coin::Bnb, 2, store).unwrap();

        let transfers = wallet.incoming_transfers(0).await.unwrap();
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].address, addr);
        assert_eq!(transfers[0].amount_atomic, 2_000_000_000_000_000_000);
        assert_eq!(transfers[0].confirmations, 2);

        let balance = wallet.balance_atomic().await.unwrap();
        assert_eq!(balance, Some(2_000_000_000_000_000_000));
    }

    #[tokio::test]
    async fn test_evm_token_incoming_transfers_and_balance() {
        let (node_url, _h) = spawn_mock_evm_node().await;
        let store = Arc::new(MockPaymentStore::new());
        let addr = "0xaefbb50942817d8270bb9bd922aa5ca9cb06cdbf";
        store
            .open_addrs
            .lock()
            .unwrap()
            .insert("usdt-bsc".to_string(), vec![addr.to_string()]);
        store
            .recent_addrs
            .lock()
            .unwrap()
            .insert("usdt-bsc".to_string(), vec![addr.to_string()]);

        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let coin = Coin::EvmToken(Arc::new(EvmTokenMeta {
            coin: "usdt-bsc".into(),
            symbol: "usdt".into(),
            display_name: "Tether USD (BSC)".into(),
            network_badge: "BEP-20".into(),
            network: "bsc".into(),
            decimals: 18,
            is_stable: true,
        }));
        let wallet = EvmTokenWallet::connect(
            &node_url,
            xpub,
            "0x55d398326f99059ff775485246999027b3197955",
            coin,
            2,
            store,
        )
        .unwrap();

        let transfers = wallet.incoming_transfers(0).await.unwrap();
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].address, addr);
        assert_eq!(transfers[0].amount_atomic, 1_000_000_000_000_000_000);
        assert_eq!(transfers[0].confirmations, 2);

        let balance = wallet.balance_atomic().await.unwrap();
        assert_eq!(balance, Some(1_000_000_000_000_000_000));
    }
}
