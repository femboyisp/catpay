//! Watch-only ERC-20 deposit backend (USDC, USDT, ...).
//!
//! Same watch-only-xpub shape as [`super::ethereum`]: a receive-chain xpub
//! derives one fresh address per quote, no node-side wallet, nothing here can
//! spend. The only real difference from native ETH is *how* a balance is
//! read: an ERC-20 token has no `eth_getBalance` entry, so detection calls
//! the token contract's `balanceOf(address)` via `eth_call` instead, and
//! amounts are token units (6 decimals for both USDC and USDT) rather than
//! wei (18 decimals).
//!
//! One `Erc20Wallet` instance is built per configured token (parameterized by
//! `contract_address` and `coin_name`) — USDC and USDT need no separate module,
//! just different config.

use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bip32::XPub;

use crate::backend::PaymentBackend;
use crate::error::PaymentError;
use crate::ethereum::{derive_eth_address, MultiRemoteEthClient};
use crate::store::PaymentStore;
use crate::types::{Health, NewSubaddress, Transfer};

/// Cap on how many deposit addresses `balance_atomic` will scan — mirrors
/// [`super::ethereum::MAX_BALANCE_ADDRESSES`].
const MAX_BALANCE_ADDRESSES: i64 = 64;

/// A watch-only ERC-20 deposit wallet reached over the same Ethereum
/// JSON-RPC endpoint a native ETH backend would use.
pub struct Erc20Wallet {
    client: Arc<MultiRemoteEthClient>,
    xpub: XPub,
    contract_address: String,
    /// Row key in `quotes.coin` / the `hd_index` table (e.g. `"usdc"`), and
    /// the `{coin}:` prefix on synthesized txids.
    coin_name: &'static str,
    min_confirmations: u64,
    store: Arc<dyn PaymentStore>,
}

impl Erc20Wallet {
    pub fn new(
        client: Arc<MultiRemoteEthClient>,
        xpub: &str,
        contract_address: &str,
        coin_name: &'static str,
        min_confirmations: u64,
        store: Arc<dyn PaymentStore>,
    ) -> Result<Self, PaymentError> {
        let xpub = XPub::from_str(xpub.trim())
            .map_err(|e| PaymentError::Rpc(format!("invalid {coin_name} xpub: {e}")))?;
        Ok(Self {
            client,
            xpub,
            contract_address: contract_address.trim().to_ascii_lowercase(),
            coin_name,
            min_confirmations,
            store,
        })
    }

    #[allow(dead_code, clippy::allow_attributes)]
    pub fn connect(
        url: &str,
        xpub: &str,
        contract_address: &str,
        coin_name: &'static str,
        min_confirmations: u64,
        store: Arc<dyn PaymentStore>,
    ) -> Result<Self, PaymentError> {
        let client = Arc::new(MultiRemoteEthClient::new(url.to_owned(), vec![], 3, 3));
        Self::new(
            client,
            xpub,
            contract_address,
            coin_name,
            min_confirmations,
            store,
        )
    }

    async fn block_number(&self) -> Result<u64, PaymentError> {
        self.client.block_number().await
    }

    /// `balanceOf(address)` at `block`, in the token's atomic units.
    async fn balance_of(&self, address: &str, block: &str) -> Result<u128, PaymentError> {
        self.client
            .balance_of(&self.contract_address, address, block)
            .await
    }

    fn address_for_index(&self, index: u32) -> Result<String, PaymentError> {
        derive_eth_address(&self.xpub, index)
    }

    #[allow(dead_code, clippy::allow_attributes)]
    pub fn client(&self) -> &Arc<MultiRemoteEthClient> {
        &self.client
    }
}

fn sum_to_i64<I: IntoIterator<Item = u128>>(balances: I) -> i64 {
    let total = balances
        .into_iter()
        .fold(0u128, |acc, v| acc.saturating_add(v));
    i64::try_from(total).unwrap_or(i64::MAX)
}

#[async_trait]
impl PaymentBackend for Erc20Wallet {
    async fn new_subaddress(&self, _label: &str) -> Result<NewSubaddress, PaymentError> {
        let index = self.store.next_hd_index(self.coin_name).await?;
        let index_u32 = u32::try_from(index)
            .map_err(|_| PaymentError::Rpc(format!("{} hd index overflow", self.coin_name)))?;
        let address = self.address_for_index(index_u32)?;
        Ok(NewSubaddress {
            address,
            index: u64::from(index_u32),
        })
    }

    async fn incoming_transfers(&self, _min_height: u64) -> Result<Vec<Transfer>, PaymentError> {
        self.client.refresh_source().await;
        let latest = self.block_number().await?;
        let target = latest.saturating_sub(self.min_confirmations);
        let block_param = if self.min_confirmations == 0 {
            "latest".to_owned()
        } else {
            format!("0x{target:x}")
        };

        let addresses = self.store.open_addresses(self.coin_name).await?;

        let mut transfers = Vec::new();
        for address in addresses {
            let atomic = self.balance_of(&address, &block_param).await?;
            if atomic > 0 {
                transfers.push(Transfer {
                    // One fresh address per quote, so one credit per quote —
                    // same idempotency model as the native ETH backend.
                    txid: format!("{}:{address}", self.coin_name),
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
        let addresses = self
            .store
            .recent_addresses(self.coin_name, MAX_BALANCE_ADDRESSES)
            .await?;
        if addresses.len() as i64 >= MAX_BALANCE_ADDRESSES {
            eprintln!(
                "payments[{}]: wallet_balance_atomic scan capped at {MAX_BALANCE_ADDRESSES} \
                 most-recent address(es); quote history may be larger",
                self.coin_name
            );
        }
        let mut balances = Vec::with_capacity(addresses.len());
        for address in &addresses {
            match self.balance_of(address, "latest").await {
                Ok(v) => balances.push(v),
                Err(e) => eprintln!(
                    "payments[{}]: balance_of({address}) failed: {e}",
                    self.coin_name
                ),
            }
        }
        Ok(Some(sum_to_i64(balances)))
    }

    /// Health check delegates to the shared MultiRemoteEthClient.
    async fn health(&self) -> Health {
        self.client.health().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethereum::{pad_address, parse_hex_u128};
    use crate::store::MockPaymentStore;

    #[test]
    fn pad_address_strips_prefix_and_pads_to_32_bytes() {
        let padded = pad_address("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
        assert_eq!(padded.len(), 64);
        assert!(padded.ends_with("7e5f4552091a69125d5dfcb7b8c2659029395bdf"));
        assert!(padded.starts_with(&"0".repeat(24)));
    }

    #[test]
    fn parse_hex_u128_handles_prefix_and_empty() {
        assert_eq!(parse_hex_u128("0x0").unwrap(), 0);
        assert_eq!(parse_hex_u128("0x").unwrap(), 0);
        assert_eq!(parse_hex_u128("0xf4240").unwrap(), 1_000_000); // 1 USDC (6dp)
        assert!(parse_hex_u128("0xzz").is_err());
    }

    #[test]
    fn sum_to_i64_adds_and_clamps() {
        assert_eq!(sum_to_i64(vec![1_000_000u128, 2_000_000]), 3_000_000);
        assert_eq!(sum_to_i64(std::iter::empty()), 0);
        assert_eq!(sum_to_i64(vec![u128::MAX, u128::MAX]), i64::MAX);
    }

    #[test]
    fn address_derivation_matches_ethereum_module() {
        // Same xpub, same index -> same address: an ERC-20 deposit address
        // is just a normal EOA address, derived identically to ETH's.
        let xpub = XPub::from_str(
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        )
        .unwrap();
        assert_eq!(
            derive_eth_address(&xpub, 0).unwrap(),
            "0xaefbb50942817d8270bb9bd922aa5ca9cb06cdbf"
        );
    }

    #[tokio::test]
    async fn test_erc20_wallet_new_subaddress_with_mock_store() {
        let store = Arc::new(MockPaymentStore::new());
        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let wallet = Erc20Wallet::connect(
            "http://127.0.0.1:8545",
            xpub,
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "usdc",
            6,
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

    async fn spawn_mock_erc20_node() -> (String, tokio::task::JoinHandle<()>) {
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
                        "0xf4240" // 1,000,000 = 1 USDC
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
    async fn test_erc20_wallet_incoming_transfers_and_balance_atomic_with_mock_store() {
        let (node_url, _h) = spawn_mock_erc20_node().await;

        let store = Arc::new(MockPaymentStore::new());
        let addr = "0xaefbb50942817d8270bb9bd922aa5ca9cb06cdbf";
        store
            .open_addrs
            .lock()
            .unwrap()
            .insert("usdc".to_string(), vec![addr.to_string()]);
        store
            .recent_addrs
            .lock()
            .unwrap()
            .insert("usdc".to_string(), vec![addr.to_string()]);

        let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        let wallet = Erc20Wallet::connect(
            &node_url,
            xpub,
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "usdc",
            2,
            store,
        )
        .unwrap();

        let transfers = wallet.incoming_transfers(0).await.unwrap();
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].address, addr);
        assert_eq!(transfers[0].amount_atomic, 1_000_000);
        assert_eq!(transfers[0].confirmations, 2);

        let balance = wallet.balance_atomic().await.unwrap();
        assert_eq!(balance, Some(1_000_000));
    }
}
