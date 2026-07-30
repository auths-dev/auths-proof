//! Closed receipt family for Issuing purchase authorization.

#![allow(
    clippy::missing_errors_doc,
    clippy::struct_excessive_bools,
    reason = "receipts explicitly preserve independent security facts for audit"
)]

use serde::{Deserialize, Serialize};

use super::{PurchaseAuthorizationDecision, StripeExactPurchaseAuthorizationV1};
use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    issuing::{
        AgentProcurementIntentV1, PurchaseAggregateSnapshot,
        PurchaseAuthorizationProviderProjection, PurchaseReservationRecord,
        PurchaseWebhookEvidenceV1, StripeBoundedPurchasePolicyV1, StripePurchaseConfigurationV1,
    },
    types::DigestHex,
};

/// Proof, policy, signed-event, and bounded decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PurchaseAuthorizationDecisionReceipt {
    pub schema: String,
    pub workflow_id: String,
    pub policy_provenance: String,
    pub policy: StripeBoundedPurchasePolicyV1,
    pub policy_digest: DigestHex,
    pub exact_action: StripeExactPurchaseAuthorizationV1,
    pub action_digest: DigestHex,
    pub webhook_evidence: PurchaseWebhookEvidenceV1,
    pub webhook_evidence_digest: DigestHex,
    pub procurement_intent: Option<AgentProcurementIntentV1>,
    pub aggregate_before: PurchaseAggregateSnapshot,
    pub required_configuration: StripePurchaseConfigurationV1,
    pub executed_configuration: StripePurchaseConfigurationV1,
    pub configuration_equal: bool,
    pub auths_decision: String,
    pub auths_code: String,
    pub bounded_decision: Option<PurchaseAuthorizationDecision>,
    pub credential_requested: bool,
    pub provider_called: bool,
    pub elapsed_milliseconds: u64,
    pub decided_at: u64,
}

impl PurchaseAuthorizationDecisionReceipt {
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Atomic reservation and exact direct response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PurchaseAuthorizationTransitionReceipt {
    pub schema: String,
    pub decision_receipt_digest: DigestHex,
    pub action_digest: DigestHex,
    pub policy_digest: DigestHex,
    pub semantic_event: String,
    pub reservation: PurchaseReservationRecord,
    pub approved_response: bool,
    pub stripe_version_header: String,
    pub response_digest: DigestHex,
    pub capacity_held: bool,
    pub credential_requested: bool,
    pub provider_called: bool,
    pub elapsed_milliseconds: u64,
    pub recorded_at: u64,
}

impl PurchaseAuthorizationTransitionReceipt {
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Later provider observation and reconciliation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PurchaseAuthorizationObservationReceipt {
    pub schema: String,
    pub workflow_id: String,
    pub action_digest: DigestHex,
    pub policy_digest: DigestHex,
    pub decision_receipt_digest: DigestHex,
    pub provider: PurchaseAuthorizationProviderProjection,
    pub exact_amount_or_lower: bool,
    pub capacity_held_after: bool,
    pub reconciled: bool,
    pub residual_assumptions: Vec<String>,
    pub recorded_at: u64,
}

impl PurchaseAuthorizationObservationReceipt {
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Purchase-owned receipt union.
///
/// Adding another Stripe profile does not add variants here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "receipt")]
pub enum PurchaseAuthorizationReceipt {
    #[serde(rename = "purchase-authorization-decision")]
    Decision(Box<PurchaseAuthorizationDecisionReceipt>),
    #[serde(rename = "purchase-authorization-transition")]
    Transition(Box<PurchaseAuthorizationTransitionReceipt>),
    #[serde(rename = "purchase-authorization-observation")]
    Observation(Box<PurchaseAuthorizationObservationReceipt>),
}

impl PurchaseAuthorizationReceipt {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }
}
