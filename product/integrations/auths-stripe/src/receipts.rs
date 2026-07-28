//! Canonical linked receipts for exact Stripe refunds.

use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    decision::Decision,
    types::{DigestHex, Money, RefundResult, StripeVerifierConfiguration},
};

/// Product and Auths authorization receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Workflow.
    pub workflow_id: String,
    /// Exact action commitment when action derivation succeeded.
    pub action_digest: Option<DigestHex>,
    /// Evidence commitment.
    pub evidence_digest: DigestHex,
    /// Required configuration, not just its digest.
    pub required_configuration: StripeVerifierConfiguration,
    /// Configuration actually executed.
    pub executed_configuration: StripeVerifierConfiguration,
    /// Pure product decision.
    pub product_decision: Decision,
    /// Auths kernel class when reached.
    pub auths_decision: Option<String>,
    /// Auths stable code when reached.
    pub auths_code: Option<String>,
    /// Decision time.
    pub decided_at: u64,
}

impl DecisionReceipt {
    /// Returns a canonical commitment.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Provider execution receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Prior decision receipt.
    pub decision_receipt_digest: DigestHex,
    /// Exact action.
    pub action_digest: DigestHex,
    /// Idempotency key commitment.
    pub idempotency_key_digest: DigestHex,
    /// Stripe account commitment.
    pub stripe_account_digest: DigestHex,
    /// Pinned API version.
    pub stripe_api_version: String,
    /// Stripe request correlation.
    pub stripe_request_id: String,
    /// Refund identifier.
    pub refund_id: crate::types::RefundId,
    /// Exact amount.
    pub amount: Money,
    /// Initial provider status.
    pub status: String,
    /// Completion time.
    pub executed_at: u64,
}

impl ExecutionReceipt {
    /// Returns a canonical commitment.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Later provider observation receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Previous execution receipt.
    pub execution_receipt_digest: DigestHex,
    /// Refund identifier commitment.
    pub refund_id_digest: DigestHex,
    /// Observed status.
    pub status: String,
    /// Observation source.
    pub source: String,
    /// Observation time.
    pub observed_at: u64,
}

/// Closed receipt union.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "receipt", rename_all = "kebab-case")]
pub enum StripeReceipt {
    /// Decision.
    Decision(Box<DecisionReceipt>),
    /// Provider execution.
    Execution(Box<ExecutionReceipt>),
    /// Later observation.
    Observation(Box<ObservationReceipt>),
}

impl StripeReceipt {
    /// Returns canonical receipt bytes.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }
}

/// Builds a provider execution receipt from a verified action and result.
///
/// # Errors
///
/// Returns a canonicalization failure.
pub fn execution_receipt(
    schema: &str,
    decision_receipt_digest: DigestHex,
    action: &crate::types::ExactRefundActionV1,
    result: &RefundResult,
) -> Result<ExecutionReceipt, CanonicalError> {
    Ok(ExecutionReceipt {
        schema: schema.into(),
        decision_receipt_digest,
        action_digest: action.digest()?,
        idempotency_key_digest: crate::canonical::sha256(action.idempotency_key().as_bytes()),
        stripe_account_digest: crate::canonical::sha256(
            action.stripe_account_id().as_str().as_bytes(),
        ),
        stripe_api_version: action.stripe_api_version().into(),
        stripe_request_id: result.stripe_request_id.clone(),
        refund_id: result.refund_id.clone(),
        amount: result.amount.clone(),
        status: result.status.clone(),
        executed_at: result.observed_at,
    })
}
