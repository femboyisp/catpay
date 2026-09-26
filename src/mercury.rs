//! Mercury Bank wire instructions, transaction retrieval, and wire matching.

use crate::error::PaymentError;

/// A transaction returned by the Mercury Bank API.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MercuryTransaction {
    pub id: String,
    pub amount: f64,
    pub status: String,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default, alias = "bankDescription")]
    pub bank_description: Option<String>,
    #[serde(default, alias = "postedAt")]
    pub posted_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Domestic wire transfer instructions provided to customers.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WireInstructions {
    pub beneficiary: String,
    pub routing_number: String,
    pub account_number: String,
    pub reference_code: String,
    pub amount_cents: u64,
    pub currency: String,
}

/// Client for interacting with Mercury Bank API and generating wire instructions.
#[derive(Debug, Clone)]
pub struct MercuryClient {
    api_token: String,
    account_id: String,
    routing_number: String,
    account_number: String,
    beneficiary_name: String,
    base_url: String,
    client: reqwest::Client,
}

impl MercuryClient {
    /// Creates a new `MercuryClient` with the given API token and bank account details.
    pub fn new(
        api_token: String,
        account_id: String,
        routing_number: String,
        account_number: String,
        beneficiary_name: String,
    ) -> Self {
        Self {
            api_token,
            account_id,
            routing_number,
            account_number,
            beneficiary_name,
            base_url: "https://api.mercury.com".into(),
            client: reqwest::Client::new(),
        }
    }

    /// Overrides the Mercury API base URL (useful for testing and mock servers).
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    /// Returns the configured API token.
    pub fn api_token(&self) -> &str {
        &self.api_token
    }

    /// Returns the account ID.
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Returns the routing number.
    pub fn routing_number(&self) -> &str {
        &self.routing_number
    }

    /// Returns the account number.
    pub fn account_number(&self) -> &str {
        &self.account_number
    }

    /// Returns the beneficiary name.
    pub fn beneficiary_name(&self) -> &str {
        &self.beneficiary_name
    }

    /// Generates wire transfer instructions for a specific reference code and amount in cents.
    pub fn generate_wire_instructions(
        &self,
        reference_code: &str,
        amount_cents: u64,
    ) -> WireInstructions {
        WireInstructions {
            beneficiary: self.beneficiary_name.clone(),
            routing_number: self.routing_number.clone(),
            account_number: self.account_number.clone(),
            reference_code: reference_code.to_string(),
            amount_cents,
            currency: "USD".to_string(),
        }
    }

    /// Fetches transactions for the account from `GET /api/v1/account/{account_id}/transactions`.
    pub async fn get_incoming_transactions(
        &self,
    ) -> Result<Vec<MercuryTransaction>, PaymentError> {
        let url = format!(
            "{}/api/v1/account/{}/transactions",
            self.base_url, self.account_id
        );
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| PaymentError::Rpc(format!("mercury request error: {e}")))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp
                .text()
                .await
                .unwrap_or_else(|_| "<failed to read error body>".into());
            return Err(PaymentError::Rpc(format!(
                "mercury transactions request failed with status {status}: {body}"
            )));
        }

        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum MercuryTransactionsResponse {
            Wrapped { transactions: Vec<MercuryTransaction> },
            List(Vec<MercuryTransaction>),
        }

        let parsed: MercuryTransactionsResponse = resp
            .json()
            .await
            .map_err(|e| PaymentError::Rpc(format!("failed to parse mercury response: {e}")))?;

        let transactions = match parsed {
            MercuryTransactionsResponse::Wrapped { transactions } => transactions,
            MercuryTransactionsResponse::List(transactions) => transactions,
        };

        Ok(transactions)
    }

    /// Matches a posted incoming wire transaction by reference code and expected amount in cents.
    ///
    /// Checks `note` and `bank_description` case-insensitively for `reference_code`.
    pub fn match_wire<'a>(
        &self,
        reference_code: &str,
        expected_cents: u64,
        transactions: &'a [MercuryTransaction],
    ) -> Option<&'a MercuryTransaction> {
        let ref_clean = reference_code.trim().to_lowercase();
        if ref_clean.is_empty() {
            return None;
        }

        transactions.iter().find(|tx| {
            if !tx.status.eq_ignore_ascii_case("posted") {
                return false;
            }

            let tx_cents = (tx.amount * 100.0).round() as i64;
            if tx_cents <= 0 || tx_cents as u64 != expected_cents {
                return false;
            }

            let note_match = tx
                .note
                .as_ref()
                .map(|n| n.to_lowercase().contains(&ref_clean))
                .unwrap_or(false);

            let desc_match = tx
                .bank_description
                .as_ref()
                .map(|d| d.to_lowercase().contains(&ref_clean))
                .unwrap_or(false);

            note_match || desc_match
        })
    }
}
