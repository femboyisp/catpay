//! Watch-only address derivation for supported cryptocurrency networks.
//!
//! Handles BIP84 (P2WPKH bech32), BIP44 (P2PKH Base58Check and CashAddr),
//! Ethereum/EVM, Tron, and descriptor extended public key conversions.
//!
//! Zero private keys: derives non-hardened children `/0/i` from account-level
//! extended public keys without network I/O or wallet state.

use std::str::FromStr;

use bech32::Hrp;
use bip32::{ChildNumber, Prefix, PublicKey as _, XPub};
use ripemd::Ripemd160;
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

use crate::error::PaymentError;

/// Derive the P2WPKH deposit address for external-chain index `index` from an
/// account-level BIP84 zpub (`m/84'/coin'/0'`). `hrp` = "bc" (BTC) / "ltc" (LTC).
pub fn derive_p2wpkh(account_zpub: &str, hrp: Hrp, index: u32) -> Result<String, PaymentError> {
    let acct = XPub::from_str(account_zpub.trim())
        .map_err(|e| PaymentError::Rpc(format!("invalid zpub: {e}")))?;
    let external = ChildNumber::new(0, false)
        .map_err(|e| PaymentError::Rpc(format!("bad derivation index: {e}")))?;
    let child_index = ChildNumber::new(index, false)
        .map_err(|e| PaymentError::Rpc(format!("bad derivation index: {e}")))?;
    let child = acct
        .derive_child(external) // external chain /0
        .and_then(|c| c.derive_child(child_index)) // /i
        .map_err(|e| PaymentError::Rpc(format!("derive failed: {e}")))?;
    let compressed = child.public_key().to_bytes(); // 33-byte compressed SEC1
    let sha = Sha256::digest(compressed);
    let h160 = Ripemd160::digest(sha); // 20-byte witness program
    bech32::segwit::encode_v0(hrp, &h160)
        .map_err(|e| PaymentError::Rpc(format!("bech32 encode: {e}")))
}

/// Derive the legacy P2PKH deposit address for external-chain index `index`
/// from an account-level BIP44 xpub (`m/44'/coin'/0'`), Base58Check-encoded
/// with `version_byte` (Dogecoin mainnet: 30 / `0x1e`; Bitcoin mainnet: 0).
pub fn derive_p2pkh(
    account_xpub: &str,
    version_byte: u8,
    index: u32,
) -> Result<String, PaymentError> {
    let h160 = derive_p2pkh_hash160(account_xpub, index)?;
    Ok(hash160_to_p2pkh_base58(&h160, version_byte))
}

/// The `/0/index` child's `hash160(compressed pubkey)` — the shared P2PKH
/// step behind [`derive_p2pkh`] and [`derive_cashaddr_p2pkh`].
pub fn derive_p2pkh_hash160(
    account_xpub: &str,
    index: u32,
) -> Result<[u8; 20], PaymentError> {
    let acct = XPub::from_str(account_xpub.trim())
        .map_err(|e| PaymentError::Rpc(format!("invalid extended pubkey: {e}")))?;
    let external = ChildNumber::new(0, false)
        .map_err(|e| PaymentError::Rpc(format!("bad derivation index: {e}")))?;
    let child_index = ChildNumber::new(index, false)
        .map_err(|e| PaymentError::Rpc(format!("bad derivation index: {e}")))?;
    let child = acct
        .derive_child(external)
        .and_then(|c| c.derive_child(child_index))
        .map_err(|e| PaymentError::Rpc(format!("derive failed: {e}")))?;
    let compressed = child.public_key().to_bytes();
    let sha = Sha256::digest(compressed);
    let h160 = Ripemd160::digest(sha);
    Ok(h160.into())
}

/// `hash160`, Base58Check-encoded with `version_byte`.
pub fn hash160_to_p2pkh_base58(h160: &[u8; 20], version_byte: u8) -> String {
    let mut payload = Vec::with_capacity(21);
    payload.push(version_byte);
    payload.extend_from_slice(h160);
    base58ck::encode_check(&payload)
}

/// Derive legacy P2PKH address from a compressed SEC1 public key,
/// Base58Check-encoded with `version_byte`.
pub fn p2pkh_address_from_pubkey(compressed_pubkey: &[u8], version_byte: u8) -> String {
    let sha = Sha256::digest(compressed_pubkey);
    let h160: [u8; 20] = Ripemd160::digest(sha).into();
    hash160_to_p2pkh_base58(&h160, version_byte)
}

/// Derive the CashAddr deposit address for external-chain index `index` from
/// an account-level BIP44 xpub (`m/44'/145'/0'`).
pub fn derive_cashaddr_p2pkh(
    account_xpub: &str,
    prefix: &str,
    index: u32,
) -> Result<String, PaymentError> {
    let h160 = derive_p2pkh_hash160(account_xpub, index)?;
    hash160_to_cashaddr(&h160, prefix)
}

/// `hash160`, CashAddr-encoded (P2PKH) under the given human-readable prefix
/// (`"bitcoincash"` for mainnet, `"bchreg"` for dev regtest).
pub fn hash160_to_cashaddr(h160: &[u8; 20], prefix: &str) -> Result<String, PaymentError> {
    use cashaddr::CashEnc;
    h160.encode(prefix, cashaddr::HashType::P2PKH)
        .map_err(|e| PaymentError::Rpc(format!("cashaddr encode: {e}")))
}

/// Decode a CashAddr string back into its `hash160` — the inverse of [`hash160_to_cashaddr`].
pub fn cashaddr_to_hash160(address: &str) -> Result<[u8; 20], PaymentError> {
    use cashaddr::Payload;
    let payload =
        Payload::from_str(address).map_err(|e| PaymentError::Rpc(format!("bad cashaddr: {e}")))?;
    let bytes: &[u8] = payload.as_ref();
    bytes
        .try_into()
        .map_err(|_| PaymentError::Rpc("cashaddr: unexpected hash length".to_owned()))
}

/// Ethereum address (lowercase, `0x`-prefixed) from a 65-byte uncompressed
/// secp256k1 public key (`0x04 || X || Y`): keccak256 of the 64-byte body, last 20 bytes.
pub fn eth_address_from_uncompressed(uncompressed: &[u8]) -> String {
    let body = if uncompressed.len() == 65 {
        &uncompressed[1..]
    } else {
        uncompressed
    };
    use sha3::Digest as _;
    let hash = Keccak256::digest(body);
    format!("0x{}", hex::encode(&hash[12..]))
}

/// Derive the Ethereum deposit address for a non-hardened child of the receive xpub.
pub fn derive_eth_address(xpub: &XPub, index: u32) -> Result<String, PaymentError> {
    let child_number = ChildNumber::new(index, false)
        .map_err(|e| PaymentError::Rpc(format!("bad derivation index: {e}")))?;
    let child = xpub
        .derive_child(child_number)
        .map_err(|e| PaymentError::Rpc(format!("derive failed: {e}")))?;
    let point = child.public_key().to_encoded_point(false);
    Ok(eth_address_from_uncompressed(point.as_bytes()))
}

/// Derive the deposit address for external-chain index `index` from an
/// account-level BIP44 xpub, in Tron's address format.
///
/// Tron uses the same curve and BIP44 derivation as Ethereum, and its
/// address is the Ethereum address's 20-byte keccak tail prefixed with
/// `0x41` and Base58Check-encoded.
pub fn derive_tron_address(account_xpub: &str, index: u32) -> Result<String, PaymentError> {
    let acct = XPub::from_str(account_xpub.trim())
        .map_err(|e| PaymentError::Rpc(format!("invalid extended pubkey: {e}")))?;
    let eth_hex = derive_eth_address(&acct, index)?;
    let h20 = hex::decode(eth_hex.trim_start_matches("0x"))
        .map_err(|e| PaymentError::Rpc(format!("bad eth address hex: {e}")))?;
    let mut payload = Vec::with_capacity(21);
    payload.push(0x41);
    payload.extend_from_slice(&h20);
    Ok(base58ck::encode_check(&payload))
}

/// Convert a SLIP-132 extended public key (`zpub`/`ypub`/`Ltub`/...) to a
/// plain BIP32 `xpub` (version bytes `0x0488B21E`) or `tpub`.
pub fn to_descriptor_xpub(
    account_ext_pubkey: &str,
    target: Prefix,
) -> Result<String, PaymentError> {
    let acct = XPub::from_str(account_ext_pubkey.trim())
        .map_err(|e| PaymentError::Rpc(format!("invalid extended pubkey: {e}")))?;
    Ok(acct.to_string(target))
}

#[cfg(test)]
mod tests {
    // zpub of the BIP84 test mnemonic "abandon abandon ... about" at m/84'/0'/0'
    const BTC_TESTVEC_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    // BIP32 spec's own "Test Vector 1" (seed 000102030405060708090a0b0c0d0e0f),
    // master key — published directly in bip-0032.mediawiki and reproduced
    // on the Bitcoin wiki alongside its legacy P2PKH address.
    const BIP32_TESTVEC1_MASTER_XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
    const BIP32_TESTVEC1_MASTER_ADDRESS: &str = "15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma";

    #[test]
    fn p2pkh_address_from_pubkey_matches_published_bip32_vector() {
        use bip32::PublicKey as _;
        use sha2::Digest as _;
        use std::str::FromStr as _;
        let acct = super::XPub::from_str(BIP32_TESTVEC1_MASTER_XPUB).unwrap();
        let compressed = acct.public_key().to_bytes();
        let sha = super::Sha256::digest(compressed);
        let h160: [u8; 20] = super::Ripemd160::digest(sha).into();
        assert_eq!(
            super::hash160_to_p2pkh_base58(&h160, 0),
            BIP32_TESTVEC1_MASTER_ADDRESS
        );
        assert_eq!(
            super::p2pkh_address_from_pubkey(&compressed, 0),
            BIP32_TESTVEC1_MASTER_ADDRESS
        );
    }

    #[test]
    fn derive_p2pkh_dogecoin_version_byte_produces_d_prefixed_address() {
        let addr = super::derive_p2pkh(BTC_TESTVEC_ZPUB, 30, 0).unwrap();
        assert!(addr.starts_with('D'), "got {addr}");
        assert!(base58ck::decode_check(&addr).is_ok());
    }

    #[test]
    fn cashaddr_p2pkh_matches_published_spec_vector() {
        let hash: [u8; 20] = [
            0xF5, 0xBF, 0x48, 0xB3, 0x97, 0xDA, 0xE7, 0x0B, 0xE8, 0x2B, 0x3C, 0xCA, 0x47, 0x93,
            0xF8, 0xEB, 0x2B, 0x6C, 0xDA, 0xC9,
        ];
        use cashaddr::CashEnc;
        let addr = hash
            .encode("bitcoincash", cashaddr::HashType::P2PKH)
            .unwrap();
        assert_eq!(
            addr,
            "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2"
        );
    }

    #[test]
    fn derive_cashaddr_p2pkh_produces_bitcoincash_prefixed_address() {
        let addr = super::derive_cashaddr_p2pkh(BTC_TESTVEC_ZPUB, "bitcoincash", 0).unwrap();
        assert!(addr.starts_with("bitcoincash:q"), "got {addr}");
    }

    #[test]
    fn derive_cashaddr_p2pkh_regtest_prefix_produces_bchreg_prefixed_address() {
        let addr = super::derive_cashaddr_p2pkh(BTC_TESTVEC_ZPUB, "bchreg", 0).unwrap();
        assert!(addr.starts_with("bchreg:q"), "got {addr}");
    }

    #[test]
    fn tron_encode_matches_published_eth_tron_address_pair() {
        let h20: [u8; 20] = [
            0x88, 0x40, 0xE6, 0xC5, 0x5B, 0x9A, 0xDA, 0x32, 0x6D, 0x21, 0x1D, 0x81, 0x8C, 0x34,
            0xA9, 0x94, 0xAE, 0xCE, 0xD8, 0x08,
        ];
        let mut payload = Vec::with_capacity(21);
        payload.push(0x41);
        payload.extend_from_slice(&h20);
        assert_eq!(
            base58ck::encode_check(&payload),
            "TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL"
        );
    }

    #[test]
    fn derive_tron_address_produces_t_prefixed_address() {
        let addr = super::derive_tron_address(BTC_TESTVEC_ZPUB, 0).unwrap();
        assert!(addr.starts_with('T'), "got {addr}");
    }

    #[test]
    fn derives_bip84_first_receive_address() {
        let a =
            super::derive_p2wpkh(BTC_TESTVEC_ZPUB, bech32::Hrp::parse("bc").unwrap(), 0).unwrap();
        assert_eq!(a, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        let a1 =
            super::derive_p2wpkh(BTC_TESTVEC_ZPUB, bech32::Hrp::parse("bc").unwrap(), 1).unwrap();
        assert_eq!(a1, "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
    }

    #[test]
    fn to_descriptor_xpub_swaps_version_bytes_only() {
        let converted = super::to_descriptor_xpub(BTC_TESTVEC_ZPUB, super::Prefix::XPUB).unwrap();
        assert!(converted.starts_with("xpub"));
        assert_eq!(
            converted,
            "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V"
        );
        let hrp = bech32::Hrp::parse("bc").unwrap();
        let via_zpub = super::derive_p2wpkh(BTC_TESTVEC_ZPUB, hrp, 0).unwrap();
        let via_xpub = super::derive_p2wpkh(&converted, hrp, 0).unwrap();
        assert_eq!(via_zpub, via_xpub);
        assert_eq!(via_zpub, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    }

    #[test]
    fn to_descriptor_xpub_regtest_prefix_produces_a_different_tpub_string() {
        let converted = super::to_descriptor_xpub(BTC_TESTVEC_ZPUB, super::Prefix::TPUB).unwrap();
        assert!(converted.starts_with("tpub"), "got {converted}");
        assert_eq!(
            converted,
            "tpubDCxX2sYFS5bDkSe5GKKYHjBW7tgyN1R3UchpLJvdbf54ohxeGRtd8MbDUe1cguVHe4vnK68DsuD5MXjxi9EXx16rb9EnNsaF5KT99CinaJz"
        );
        let hrp = bech32::Hrp::parse("bc").unwrap();
        let via_zpub = super::derive_p2wpkh(BTC_TESTVEC_ZPUB, hrp, 0).unwrap();
        let via_tpub = super::derive_p2wpkh(&converted, hrp, 0).unwrap();
        assert_eq!(via_zpub, via_tpub);
    }

    #[test]
    fn test_cashaddr_to_hash160_roundtrip() {
        let hash: [u8; 20] = [
            0xF5, 0xBF, 0x48, 0xB3, 0x97, 0xDA, 0xE7, 0x0B, 0xE8, 0x2B, 0x3C, 0xCA, 0x47, 0x93,
            0xF8, 0xEB, 0x2B, 0x6C, 0xDA, 0xC9,
        ];
        let addr = super::hash160_to_cashaddr(&hash, "bitcoincash").unwrap();
        let recovered = super::cashaddr_to_hash160(&addr).unwrap();
        assert_eq!(recovered, hash);
    }

    #[test]
    fn test_derive_eth_address() {
        use std::str::FromStr as _;
        let acct = super::XPub::from_str(BIP32_TESTVEC1_MASTER_XPUB).unwrap();
        let addr = super::derive_eth_address(&acct, 0).unwrap();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 42);
        assert_eq!(addr, "0xaefbb50942817d8270bb9bd922aa5ca9cb06cdbf");
    }
}
