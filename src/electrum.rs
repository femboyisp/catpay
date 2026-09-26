//! Electrum-protocol watch-only source for Dogecoin/Bitcoin Cash — the
//! **remote fallback** alongside [`crate::dogecoin::DogecoinWallet`]/
//! [`crate::bitcoincash::BitcoinCashWallet`]'s node-backed primary, same
//! role [`crate::esplora::EsploraSource`] plays for BTC/LTC. Doge/BCH have
//! no Esplora-compatible public API (Esplora is Bitcoin/Liquid-only), so
//! this speaks the Electrum wire protocol instead: one JSON object per line
//! over a TCP(+TLS) socket, keyed by **scripthash** rather than address.
//!
//! A scripthash is `sha256(locking_script)`, byte-reversed, hex-encoded
//! (the standard Electrum/ElectrumX scheme — verified against the protocol
//! spec's own published example in this module's tests, independently
//! cross-checked against a second implementation before being trusted).
//! Both Dogecoin and Bitcoin Cash addresses here are P2PKH (`OP_DUP
//! OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG`) — same script shape as
//! classic Bitcoin P2PKH, so scripthash computation is identical for both
//! coins and only differs in *which* server they connect to. The account
//! xpub's `hash160` ([`crate::deriver::derive_p2pkh_hash160`]) is the one
//! shared derivation step; `AddressFormat` picks how it's displayed back to
//! the caller (Base58Check for Doge, CashAddr for BCH), matching each
//! coin's primary backend.
//!
//! One connection per RPC call (connect, send one line, read one line,
//! close) rather than a persistent connection — this backend is polled
//! occasionally, not held open, and it keeps reconnection/error handling
//! trivial.

use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::backend::PaymentBackend;
use crate::coin::Coin;
use crate::deriver;
use crate::error::PaymentError;
use crate::store::PaymentStore;
use crate::types::{to_i64, Health, NewSubaddress, Transfer};

/// How to render a `hash160` back into the address string shown to
/// customers and stored in quotes/store — must match the coin's
/// node-backed primary backend exactly, since both sources need to watch
/// the identical address.
#[derive(Clone, Copy)]
pub enum AddressFormat {
    /// Dogecoin: Base58Check, version byte 30.
    Base58Check { version_byte: u8 },
    /// Bitcoin Cash: CashAddr.
    CashAddr,
}

/// Cap on how many deposit addresses `balance_atomic` will scan.
const MAX_BALANCE_ADDRESSES: i64 = 64;

pub struct ElectrumSource {
    host: String,
    port: u16,
    use_tls: bool,
    xpub: String,
    format: AddressFormat,
    coin: Coin,
    store: Arc<dyn PaymentStore>,
}

impl ElectrumSource {
    /// `host_port` is `host:port` (e.g. `dogecoin.stackwallet.com:50022`).
    pub fn new(
        host_port: &str,
        use_tls: bool,
        xpub: &str,
        format: AddressFormat,
        coin: Coin,
        store: Arc<dyn PaymentStore>,
    ) -> Result<Self, PaymentError> {
        let (host, port) = host_port
            .rsplit_once(':')
            .ok_or_else(|| PaymentError::Rpc(format!("bad host:port '{host_port}'")))?;
        let port: u16 = port
            .parse()
            .map_err(|e| PaymentError::Rpc(format!("bad port in '{host_port}': {e}")))?;
        Ok(Self {
            host: host.to_owned(),
            port,
            use_tls,
            xpub: xpub.trim().to_owned(),
            format,
            coin,
            store,
        })
    }

    fn address_for(&self, h160: &[u8; 20]) -> Result<String, PaymentError> {
        match self.format {
            AddressFormat::Base58Check { version_byte } => {
                Ok(deriver::hash160_to_p2pkh_base58(h160, version_byte))
            }
            AddressFormat::CashAddr => deriver::hash160_to_cashaddr(h160, "bitcoincash"),
        }
    }

    /// Send one JSON-RPC request over a fresh connection, read one
    /// newline-delimited JSON response.
    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, PaymentError> {
        let request = json!({ "id": 1, "method": method, "params": params });
        let mut line = serde_json::to_vec(&request)
            .map_err(|e| PaymentError::Rpc(format!("electrum request encode: {e}")))?;
        line.push(b'\n');

        let raw = self.exchange(&line).await?;
        let envelope: RpcEnvelope<T> = serde_json::from_slice(&raw)
            .map_err(|e| PaymentError::Rpc(format!("electrum response decode: {e}")))?;
        if let Some(err) = envelope.error {
            return Err(PaymentError::Rpc(format!("electrum error: {err}")));
        }
        envelope
            .result
            .ok_or_else(|| PaymentError::Rpc("electrum: empty result".to_owned()))
    }

    async fn exchange(&self, request_line: &[u8]) -> Result<Vec<u8>, PaymentError> {
        let stream = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|e| PaymentError::Rpc(format!("electrum connect: {e}")))?;
        if self.use_tls {
            let connector = tls_connector()?;
            let server_name = rustls::pki_types::ServerName::try_from(self.host.clone())
                .map_err(|e| PaymentError::Rpc(format!("bad tls server name: {e}")))?;
            let mut tls = connector
                .connect(server_name, stream)
                .await
                .map_err(|e| PaymentError::Rpc(format!("electrum tls handshake: {e}")))?;
            tls.write_all(request_line)
                .await
                .map_err(|e| PaymentError::Rpc(format!("electrum write: {e}")))?;
            read_line(tls).await
        } else {
            let mut stream = stream;
            stream
                .write_all(request_line)
                .await
                .map_err(|e| PaymentError::Rpc(format!("electrum write: {e}")))?;
            read_line(stream).await
        }
    }
}

fn tls_connector() -> Result<tokio_rustls::TlsConnector, PaymentError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

/// Read bytes from `stream` until a `\n` (Electrum's message delimiter) or
/// EOF, capped so a misbehaving/malicious server can't exhaust memory.
const MAX_RESPONSE_BYTES: usize = 1_000_000;

async fn read_line<S: tokio::io::AsyncRead + Unpin>(stream: S) -> Result<Vec<u8>, PaymentError> {
    let mut reader = BufReader::new(stream);
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader
            .read(&mut byte)
            .await
            .map_err(|e| PaymentError::Rpc(format!("electrum read: {e}")))?;
        if n == 0 || byte[0] == b'\n' {
            break;
        }
        buf.push(byte[0]);
        if buf.len() > MAX_RESPONSE_BYTES {
            return Err(PaymentError::Rpc("electrum: response too large".to_owned()));
        }
    }
    Ok(buf)
}

#[derive(Deserialize)]
struct RpcEnvelope<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct GetBalanceResp {
    confirmed: u64,
    #[allow(dead_code, clippy::allow_attributes)]
    unconfirmed: u64,
}

#[derive(Deserialize)]
struct HistoryEntry {
    #[allow(dead_code, clippy::allow_attributes)]
    tx_hash: String,
    /// Block height, or <= 0 for mempool/unconfirmed (Electrum convention).
    height: i64,
}

/// Locking script bytes for a P2PKH `hash160`:
/// `OP_DUP OP_HASH160 <push 20> <hash160> OP_EQUALVERIFY OP_CHECKSIG`.
fn p2pkh_script(h160: &[u8; 20]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // push 20 bytes
    script.extend_from_slice(h160);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

/// Electrum scripthash: `sha256(script)`, byte-reversed, hex-encoded.
fn scripthash(h160: &[u8; 20]) -> String {
    let script = p2pkh_script(h160);
    let sha = Sha256::digest(script);
    let mut reversed: Vec<u8> = sha.to_vec();
    reversed.reverse();
    hex::encode(reversed)
}

#[async_trait]
impl PaymentBackend for ElectrumSource {
    async fn new_subaddress(&self, _label: &str) -> Result<NewSubaddress, PaymentError> {
        let index = self.store.next_hd_index(self.coin.as_str()).await?;
        let index_u32 = u32::try_from(index)
            .map_err(|_| PaymentError::Rpc("electrum hd index overflow".into()))?;
        let h160 = deriver::derive_p2pkh_hash160(&self.xpub, index_u32)?;
        let address = self.address_for(&h160)?;
        Ok(NewSubaddress {
            address,
            index: u64::from(index_u32),
        })
    }

    async fn incoming_transfers(&self, _min_height: u64) -> Result<Vec<Transfer>, PaymentError> {
        let addresses = self.store.open_addresses(self.coin.as_str()).await?;
        let mut transfers = Vec::new();
        for address in addresses {
            let Ok(h160) = address_to_hash160(&address, self.format) else {
                continue;
            };
            let sh = scripthash(&h160);
            let balance: GetBalanceResp = self
                .call("blockchain.scripthash.get_balance", json!([sh]))
                .await?;
            if balance.confirmed > 0 {
                let history: Vec<HistoryEntry> = self
                    .call("blockchain.scripthash.get_history", json!([sh]))
                    .await
                    .unwrap_or_default();
                let height = history
                    .iter()
                    .map(|h| h.height)
                    .filter(|&h| h > 0)
                    .max()
                    .and_then(|h| u64::try_from(h).ok())
                    .unwrap_or(0);
                transfers.push(Transfer {
                    txid: format!("{}:{address}", self.coin.as_str()),
                    amount_atomic: balance.confirmed,
                    address,
                    height,
                    // Electrum reports confirmed/unconfirmed balance, not a
                    // per-address confirmation depth directly -- a nonzero
                    // confirmed balance is itself the signal, so this
                    // reports 0 rather than fabricating a depth.
                    confirmations: 0,
                });
            }
        }
        Ok(transfers)
    }

    async fn balance_atomic(&self) -> Result<Option<i64>, PaymentError> {
        let addresses = self
            .store
            .recent_addresses(self.coin.as_str(), MAX_BALANCE_ADDRESSES)
            .await?;
        let mut total: u64 = 0;
        for address in &addresses {
            let Ok(h160) = address_to_hash160(address, self.format) else {
                continue;
            };
            let sh = scripthash(&h160);
            match self
                .call::<GetBalanceResp>("blockchain.scripthash.get_balance", json!([sh]))
                .await
            {
                Ok(b) => total = total.saturating_add(b.confirmed),
                Err(e) => eprintln!(
                    "payments[electrum:{}]: get_balance({address}) failed: {e}",
                    self.coin.as_str()
                ),
            }
        }
        Ok(Some(to_i64(total)))
    }

    async fn health(&self) -> Health {
        let ping: Result<serde_json::Value, PaymentError> =
            self.call("server.ping", json!([])).await;
        match ping {
            Ok(_) => Health::Healthy,
            Err(_) => Health::Unreachable,
        }
    }
}

/// Decode a display address back into its `hash160`, so a stored
/// quote address can be turned back into an Electrum scripthash.
fn address_to_hash160(address: &str, format: AddressFormat) -> Result<[u8; 20], PaymentError> {
    match format {
        AddressFormat::Base58Check { .. } => {
            let decoded = base58ck::decode_check(address)
                .map_err(|e| PaymentError::Rpc(format!("bad base58check address: {e}")))?;
            let h160 = decoded.get(1..21).ok_or_else(|| {
                PaymentError::Rpc("base58check address: short payload".to_owned())
            })?;
            h160.try_into()
                .map_err(|_| PaymentError::Rpc("base58check address: bad length".to_owned()))
        }
        AddressFormat::CashAddr => deriver::cashaddr_to_hash160(address),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MockPaymentStore;

    #[test]
    fn scripthash_matches_published_electrum_spec_vector() {
        // From electrumx's own protocol docs: script
        // 76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac ->
        // scripthash 8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161
        let h160: [u8; 20] = [
            0x62, 0xe9, 0x07, 0xb1, 0x5c, 0xbf, 0x27, 0xd5, 0x42, 0x53, 0x99, 0xeb, 0xf6, 0xf0,
            0xfb, 0x50, 0xeb, 0xb8, 0x8f, 0x18,
        ];
        assert_eq!(
            scripthash(&h160),
            "8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161"
        );
    }

    #[test]
    fn p2pkh_script_has_expected_shape() {
        let h160 = [0u8; 20];
        let script = p2pkh_script(&h160);
        assert_eq!(script[0], 0x76);
        assert_eq!(script[1], 0xa9);
        assert_eq!(script[2], 0x14);
        assert_eq!(script.len(), 25);
        assert_eq!(script[23], 0x88);
        assert_eq!(script[24], 0xac);
    }

    /// A minimal hand-rolled mock Electrum server: reads one newline-delimited
    /// JSON request, replies with a fixed `get_balance`/`server.ping` response
    /// depending on the method, over plain TCP.
    async fn spawn_mock_electrum(confirmed_sun: u64) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 8192];
                    let Ok(n) = stream.read(&mut buf).await else {
                        return;
                    };
                    let request: serde_json::Value =
                        match serde_json::from_slice(&buf[..n.min(buf.len())]) {
                            Ok(v) => v,
                            Err(_) => return,
                        };
                    let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
                    let body = if method == "blockchain.scripthash.get_balance" {
                        format!(
                            r#"{{"id":1,"result":{{"confirmed":{confirmed_sun},"unconfirmed":0}}}}"#
                        )
                    } else if method == "blockchain.scripthash.get_history" {
                        r#"{"id":1,"result":[{"tx_hash":"deadbeef","height":100}]}"#.to_owned()
                    } else {
                        r#"{"id":1,"result":"pong"}"#.to_owned()
                    };
                    let _ = stream.write_all(format!("{body}\n").as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn incoming_transfers_reads_balance_from_mock_electrum_server() {
        let store = Arc::new(MockPaymentStore::new());
        let address = crate::deriver::hash160_to_p2pkh_base58(&[0u8; 20], 30);
        store
            .open_addrs
            .lock()
            .unwrap()
            .insert("dogecoin".to_string(), vec![address.clone()]);

        let mock_addr = spawn_mock_electrum(150_000_000).await;
        let source = ElectrumSource::new(
            &mock_addr.to_string(),
            false,
            "xpub-placeholder-unused-by-incoming-transfers",
            AddressFormat::Base58Check { version_byte: 30 },
            Coin::Dogecoin,
            store,
        )
        .unwrap();

        let transfers = source.incoming_transfers(0).await.unwrap();
        let found = transfers
            .iter()
            .find(|t| t.address == address)
            .expect("mock-funded address must be reported as a transfer");
        assert_eq!(found.amount_atomic, 150_000_000);
    }

    const TESTVEC_XPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    #[tokio::test]
    async fn test_electrum_new_subaddress() {
        let store = Arc::new(MockPaymentStore::new());
        let source = ElectrumSource::new(
            "127.0.0.1:50001",
            false,
            TESTVEC_XPUB,
            AddressFormat::Base58Check { version_byte: 30 },
            Coin::Dogecoin,
            store,
        )
        .unwrap();

        let sub = source.new_subaddress("order").await.unwrap();
        assert_eq!(sub.index, 0);
        assert!(sub.address.starts_with('D'));
    }
}
