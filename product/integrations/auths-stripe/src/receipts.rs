//! Canonical linked receipts for separate exact Stripe profiles.

use serde::{Deserialize, Serialize};

use crate::merchant::collect::{
    MerchantCollectionDecisionReceipt, MerchantCollectionObservationReceipt,
    MerchantCollectionTransitionReceipt,
};
use crate::{
    bounded::{
        AggregateBudgetSnapshot, BoundedRefundDecision, CONFIGURED_POLICY_PROVENANCE,
        StripeBoundedEvaluatorConfigurationV1, StripeBoundedRefundPolicyV1,
    },
    canonical::{CanonicalError, canonical_digest, canonical_json},
    decision::Decision,
    reservation::RefundReservationRecord,
    types::{DigestHex, Money, RefundResult, StripeVerifierConfiguration},
};

/// Immutable configured-policy eligibility receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedDecisionReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Workflow.
    pub workflow_id: String,
    /// Accurate configured-policy provenance.
    pub policy_provenance: String,
    /// Complete immutable configured policy.
    pub policy: StripeBoundedRefundPolicyV1,
    /// Canonical policy identity.
    pub policy_digest: DigestHex,
    /// Agent-selected exact refund.
    pub exact_action: crate::types::ExactRefundActionV1,
    /// Exact action commitment.
    pub action_digest: DigestHex,
    /// Fresh Stripe evidence.
    pub evidence: crate::types::RefundEvidenceV1,
    /// Evidence commitment.
    pub evidence_digest: DigestHex,
    /// Aggregate state used by the pure evaluator.
    pub aggregate_before: AggregateBudgetSnapshot,
    /// Required exact-refund configuration.
    pub required_exact_configuration: StripeVerifierConfiguration,
    /// Executed exact-refund configuration.
    pub executed_exact_configuration: StripeVerifierConfiguration,
    /// Required bounded evaluator configuration.
    pub required_bounded_configuration: StripeBoundedEvaluatorConfigurationV1,
    /// Executed bounded evaluator configuration.
    pub executed_bounded_configuration: StripeBoundedEvaluatorConfigurationV1,
    /// Canonical bounded configuration equality.
    pub bounded_configuration_equal: bool,
    /// Pure Stripe-local decision and arithmetic.
    pub bounded_decision: BoundedRefundDecision,
    /// Auths kernel decision when reached.
    pub auths_decision: Option<String>,
    /// Auths stable code when reached.
    pub auths_code: Option<String>,
    /// Decision time.
    pub decided_at: u64,
}

/// Complete inputs for one immutable bounded decision receipt.
pub struct BoundedDecisionReceiptInput {
    /// Workflow.
    pub workflow_id: String,
    /// Complete immutable configured policy.
    pub policy: StripeBoundedRefundPolicyV1,
    /// Canonical policy identity.
    pub policy_digest: DigestHex,
    /// Agent-selected exact refund.
    pub exact_action: crate::types::ExactRefundActionV1,
    /// Exact action commitment.
    pub action_digest: DigestHex,
    /// Fresh Stripe evidence.
    pub evidence: crate::types::RefundEvidenceV1,
    /// Evidence commitment.
    pub evidence_digest: DigestHex,
    /// Aggregate state used by the evaluator.
    pub aggregate_before: AggregateBudgetSnapshot,
    /// Required exact-refund configuration.
    pub required_exact_configuration: StripeVerifierConfiguration,
    /// Executed exact-refund configuration.
    pub executed_exact_configuration: StripeVerifierConfiguration,
    /// Required bounded evaluator configuration.
    pub required_bounded_configuration: StripeBoundedEvaluatorConfigurationV1,
    /// Executed bounded evaluator configuration.
    pub executed_bounded_configuration: StripeBoundedEvaluatorConfigurationV1,
    /// Pure bounded decision.
    pub bounded_decision: BoundedRefundDecision,
    /// Explicit decision time.
    pub decided_at: u64,
}

impl BoundedDecisionReceipt {
    /// Constructs an accurately labeled configured-policy receipt.
    #[must_use]
    pub fn new(input: BoundedDecisionReceiptInput) -> Self {
        let bounded_configuration_equal =
            input.required_bounded_configuration == input.executed_bounded_configuration;
        Self {
            schema: "auths.stripe.bounded-receipt/1".into(),
            workflow_id: input.workflow_id,
            policy_provenance: CONFIGURED_POLICY_PROVENANCE.into(),
            policy: input.policy,
            policy_digest: input.policy_digest,
            exact_action: input.exact_action,
            action_digest: input.action_digest,
            evidence: input.evidence,
            evidence_digest: input.evidence_digest,
            aggregate_before: input.aggregate_before,
            required_exact_configuration: input.required_exact_configuration,
            executed_exact_configuration: input.executed_exact_configuration,
            required_bounded_configuration: input.required_bounded_configuration,
            executed_bounded_configuration: input.executed_bounded_configuration,
            bounded_configuration_equal,
            bounded_decision: input.bounded_decision,
            auths_decision: None,
            auths_code: None,
            decided_at: input.decided_at,
        }
    }

    /// Canonical receipt commitment.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Durable aggregate reservation transition receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Prior bounded decision receipt.
    pub decision_receipt_digest: DigestHex,
    /// Complete public reservation state.
    pub reservation: RefundReservationRecord,
    /// Whether the credential had been requested at this transition.
    pub credential_requested: bool,
    /// Whether Stripe had been called at this transition.
    pub stripe_called: bool,
    /// Transition time.
    pub recorded_at: u64,
}

impl ReservationReceipt {
    /// Canonical receipt commitment.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

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
    /// Exact proof and bounded collection decision.
    MerchantCollectionDecision(Box<MerchantCollectionDecisionReceipt>),
    /// Merchant reservation/claim/provider transition.
    MerchantCollectionTransition(Box<MerchantCollectionTransitionReceipt>),
    /// Fresh merchant provider observation.
    MerchantCollectionObservation(Box<MerchantCollectionObservationReceipt>),
    /// Immutable configured-policy eligibility.
    BoundedDecision(Box<BoundedDecisionReceipt>),
    /// Durable aggregate reservation transition.
    Reservation(Box<ReservationReceipt>),
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
