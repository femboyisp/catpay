use catpay::mercury::{MercuryClient, MercuryTransaction};
use catpay::stripe::verify_stripe_signature;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;

#[test]
fn test_stripe_signature_verification() {
    let secret = "whsec_test_secret_key";
    let payload = b"{\"id\":\"evt_123\",\"type\":\"checkout.session.completed\"}";
    let now = Utc::now().timestamp();

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{}.", now).as_bytes());
    mac.update(payload);
    let sig_hex = hex::encode(mac.finalize().into_bytes());
    let sig_header = format!("t={},v1={}", now, sig_hex);

    let res = verify_stripe_signature(payload, &sig_header, secret, 300);
    assert!(res.is_ok(), "Signature verification must succeed for valid header");
}

#[test]
fn test_stripe_signature_verification_expired() {
    let secret = "whsec_test_secret_key";
    let payload = b"{\"id\":\"evt_123\",\"type\":\"checkout.session.completed\"}";
    let old_timestamp = Utc::now().timestamp() - 600; // 10 minutes ago, tolerance is 300s

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{}.", old_timestamp).as_bytes());
    mac.update(payload);
    let sig_hex = hex::encode(mac.finalize().into_bytes());
    let sig_header = format!("t={},v1={}", old_timestamp, sig_hex);

    let res = verify_stripe_signature(payload, &sig_header, secret, 300);
    assert!(res.is_err(), "Signature verification must fail for expired timestamp");
}

#[test]
fn test_stripe_signature_verification_invalid_sig() {
    let secret = "whsec_test_secret_key";
    let payload = b"{\"id\":\"evt_123\",\"type\":\"checkout.session.completed\"}";
    let now = Utc::now().timestamp();
    let sig_header = format!("t={},v1=000102030405060708090a0b0c0d0e0f", now);

    let res = verify_stripe_signature(payload, &sig_header, secret, 300);
    assert!(res.is_err(), "Signature verification must fail for invalid signature");
}

#[test]
fn test_mercury_wire_matching() {
    let client = MercuryClient::new(
        "mock_token".into(),
        "mock_acc".into(),
        "123456789".into(),
        "987654321".into(),
        "Femboy Cyber Networks LLC".into(),
    );
    let txs = vec![
        MercuryTransaction {
            id: "tx_1".into(),
            amount: 120.0,
            status: "posted".into(),
            note: Some("Payment for FCN-2026-0042".into()),
            bank_description: None,
            posted_at: Some(Utc::now()),
        }
    ];

    let matched = client.match_wire("FCN-2026-0042", 12000, &txs);
    assert!(matched.is_some(), "Should match wire by reference code");
    assert_eq!(matched.unwrap().id, "tx_1");
}

#[test]
fn test_mercury_wire_matching_bank_description() {
    let client = MercuryClient::new(
        "mock_token".into(),
        "mock_acc".into(),
        "123456789".into(),
        "987654321".into(),
        "Femboy Cyber Networks LLC".into(),
    );
    let txs = vec![
        MercuryTransaction {
            id: "tx_2".into(),
            amount: 500.0,
            status: "posted".into(),
            note: None,
            bank_description: Some("WIRE IN REF FCN-2026-0099 FROM CUSTOMER".into()),
            posted_at: Some(Utc::now()),
        }
    ];

    let matched = client.match_wire("fcn-2026-0099", 50000, &txs);
    assert!(matched.is_some(), "Should match wire case-insensitively in bank_description");
    assert_eq!(matched.unwrap().id, "tx_2");
}

#[test]
fn test_mercury_wire_matching_ignores_pending_or_amount_mismatch() {
    let client = MercuryClient::new(
        "mock_token".into(),
        "mock_acc".into(),
        "123456789".into(),
        "987654321".into(),
        "Femboy Cyber Networks LLC".into(),
    );
    let txs = vec![
        MercuryTransaction {
            id: "tx_pending".into(),
            amount: 120.0,
            status: "pending".into(),
            note: Some("Payment for FCN-2026-0042".into()),
            bank_description: None,
            posted_at: Some(Utc::now()),
        },
        MercuryTransaction {
            id: "tx_wrong_amt".into(),
            amount: 100.0,
            status: "posted".into(),
            note: Some("Payment for FCN-2026-0042".into()),
            bank_description: None,
            posted_at: Some(Utc::now()),
        },
    ];

    assert!(client.match_wire("FCN-2026-0042", 12000, &txs).is_none());
}

#[test]
fn test_mercury_generate_wire_instructions() {
    let client = MercuryClient::new(
        "mock_token".into(),
        "mock_acc".into(),
        "123456789".into(),
        "987654321".into(),
        "Femboy Cyber Networks LLC".into(),
    );
    let instructions = client.generate_wire_instructions("FCN-2026-0042", 12000);
    assert_eq!(instructions.beneficiary, "Femboy Cyber Networks LLC");
    assert_eq!(instructions.routing_number, "123456789");
    assert_eq!(instructions.account_number, "987654321");
    assert_eq!(instructions.reference_code, "FCN-2026-0042");
    assert_eq!(instructions.amount_cents, 12000);
    assert_eq!(instructions.currency, "USD");
}
