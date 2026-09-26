//! Stripe checkout sessions and webhook signature verification.

use crate::error::PaymentError;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

/// Parameters for creating a new Stripe checkout session.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CreateCheckoutParams {
    pub amount_cents: u64,
    pub currency: String,
    pub success_url: String,
    pub cancel_url: String,
    pub client_reference_id: Option<String>,
    pub item_name: String,
    pub metadata: Option<HashMap<String, String>>,
}

/// Response returned from creating a Stripe checkout session.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CheckoutSessionResponse {
    pub id: String,
    pub url: String,
}

/// Alias for [`CheckoutSessionResponse`].
pub type StripeCheckoutSession = CheckoutSessionResponse;

/// Stripe API client for generating checkout sessions and verifying webhooks.
#[derive(Debug, Clone)]
pub struct StripeClient {
    secret_key: String,
    webhook_secret: Option<String>,
    base_url: String,
    client: reqwest::Client,
}

impl StripeClient {
    /// Creates a new `StripeClient` with secret API key and optional webhook secret.
    pub fn new(secret_key: String, webhook_secret: Option<String>) -> Self {
        Self {
            secret_key,
            webhook_secret,
            base_url: "https://api.stripe.com".into(),
            client: reqwest::Client::new(),
        }
    }

    /// Overrides the Stripe API base URL (useful for testing and mock servers).
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Returns the webhook secret if configured.
    pub fn webhook_secret(&self) -> Option<&str> {
        self.webhook_secret.as_deref()
    }

    /// Verifies an incoming webhook signature using the client's configured webhook secret.
    pub fn verify_webhook_signature(
        &self,
        payload: &[u8],
        sig_header: &str,
        tolerance_seconds: i64,
    ) -> Result<(), PaymentError> {
        let secret = self.webhook_secret.as_deref().ok_or_else(|| {
            PaymentError::Rpc("stripe webhook secret is not configured".into())
        })?;
        verify_stripe_signature(payload, sig_header, secret, tolerance_seconds)
    }

    /// Creates a Stripe checkout session via `POST /v1/checkout/sessions`.
    pub async fn create_checkout_session(
        &self,
        params: &CreateCheckoutParams,
    ) -> Result<CheckoutSessionResponse, PaymentError> {
        let url = format!("{}/v1/checkout/sessions", self.base_url);
        let mut form_data = vec![
            ("mode".to_string(), "payment".to_string()),
            ("success_url".to_string(), params.success_url.clone()),
            ("cancel_url".to_string(), params.cancel_url.clone()),
            (
                "line_items[0][price_data][currency]".to_string(),
                params.currency.to_lowercase(),
            ),
            (
                "line_items[0][price_data][unit_amount]".to_string(),
                params.amount_cents.to_string(),
            ),
            (
                "line_items[0][price_data][product_data][name]".to_string(),
                params.item_name.clone(),
            ),
            ("line_items[0][quantity]".to_string(), "1".to_string()),
        ];

        if let Some(ref ref_id) = params.client_reference_id {
            form_data.push(("client_reference_id".to_string(), ref_id.clone()));
        }

        if let Some(ref meta) = params.metadata {
            for (k, v) in meta {
                form_data.push((format!("metadata[{k}]"), v.clone()));
            }
        }

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.secret_key)
            .form(&form_data)
            .send()
            .await
            .map_err(|e| PaymentError::Rpc(format!("stripe request error: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "<failed to read error body>".into());
            return Err(PaymentError::Rpc(format!(
                "stripe checkout session failed with status {status}: {body}"
            )));
        }

        #[derive(serde::Deserialize)]
        struct RawSession {
            id: String,
            url: Option<String>,
        }

        let session: RawSession = resp
            .json()
            .await
            .map_err(|e| PaymentError::Rpc(format!("failed to parse stripe response: {e}")))?;

        let session_url = session.url.ok_or_else(|| {
            PaymentError::Rpc("stripe checkout session response missing url".to_string())
        })?;

        Ok(CheckoutSessionResponse {
            id: session.id,
            url: session_url,
        })
    }
}

/// Constant-time slice comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut res = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        res |= x ^ y;
    }
    res == 0
}

/// Verifies a Stripe webhook signature (`Stripe-Signature` header).
///
/// Header format: `t=<timestamp>,v1=<sig1>,v1=<sig2>,...`
pub fn verify_stripe_signature(
    payload: &[u8],
    sig_header: &str,
    secret: &str,
    tolerance_seconds: i64,
) -> Result<(), PaymentError> {
    let mut timestamp: Option<i64> = None;
    let mut v1_signatures: Vec<&str> = Vec::new();

    for item in sig_header.split(',') {
        let mut parts = item.trim().splitn(2, '=');
        match (parts.next(), parts.next()) {
            (Some("t"), Some(val)) => {
                if let Ok(ts) = val.parse::<i64>() {
                    timestamp = Some(ts);
                }
            }
            (Some("v1"), Some(sig)) => {
                v1_signatures.push(sig);
            }
            _ => {}
        }
    }

    let timestamp = timestamp.ok_or_else(|| {
        PaymentError::Rpc("stripe signature header missing valid timestamp 't'".into())
    })?;

    if v1_signatures.is_empty() {
        return Err(PaymentError::Rpc(
            "stripe signature header missing 'v1' signature".into(),
        ));
    }

    if tolerance_seconds > 0 {
        let now = chrono::Utc::now().timestamp();
        if (now - timestamp).abs() > tolerance_seconds {
            return Err(PaymentError::Rpc(format!(
                "stripe signature timestamp {timestamp} outside tolerance of {tolerance_seconds}s (now: {now})"
            )));
        }
    }

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| PaymentError::Rpc(format!("failed to initialize hmac: {e}")))?;
    mac.update(format!("{}.", timestamp).as_bytes());
    mac.update(payload);
    let expected_sig = hex::encode(mac.finalize().into_bytes());

    let matched = v1_signatures
        .iter()
        .any(|sig| constant_time_eq(sig.as_bytes(), expected_sig.as_bytes()));

    if matched {
        Ok(())
    } else {
        Err(PaymentError::Rpc(
            "stripe webhook signature verification failed".into(),
        ))
    }
}
