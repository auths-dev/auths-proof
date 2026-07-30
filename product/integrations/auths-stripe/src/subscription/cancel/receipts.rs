//! Canonical receipts owned only by Subscription cancellation.

use serde::{Deserialize, Serialize};

use super::{
    StripeExactSubscriptionCancelV1, StripeSubscriptionCancelConfigurationV1,
    SubscriptionCancelDecision, SubscriptionCancelEvidenceV1, SubscriptionCancelProviderProjection,
    SubscriptionCancellationRecord,
};
use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    subscription::StripeBoundedSubscriptionPolicyV1,
    types::DigestHex,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCancelDecisionReceipt {
    pub schema: String,
    pub workflow_id: String,
    pub policy: StripeBoundedSubscriptionPolicyV1,
    pub policy_digest: DigestHex,
    pub exact_action: StripeExactSubscriptionCancelV1,
    pub action_digest: DigestHex,
    pub evidence: SubscriptionCancelEvidenceV1,
    pub evidence_digest: DigestHex,
    pub required_configuration: StripeSubscriptionCancelConfigurationV1,
    pub executed_configuration: StripeSubscriptionCancelConfigurationV1,
    pub configuration_equal: bool,
    pub auths_decision: String,
    pub auths_code: String,
    pub authorization_established: bool,
    pub bounded_decision: Option<SubscriptionCancelDecision>,
    pub release_intent_persisted: bool,
    pub credential_requested: bool,
    pub stripe_called: bool,
    pub decided_at: u64,
}

impl SubscriptionCancelDecisionReceipt {
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCancelTransitionReceipt {
    pub schema: String,
    pub decision_receipt_digest: DigestHex,
    pub action_digest: DigestHex,
    pub policy_digest: DigestHex,
    pub semantic_event: String,
    pub cancellation: SubscriptionCancellationRecord,
    pub liability_before_minor: u64,
    pub liability_released_minor: u64,
    pub liability_retained_minor: u64,
    pub credential_requested: bool,
    pub stripe_called: bool,
    pub provider_accepted: bool,
    pub recorded_at: u64,
}

impl SubscriptionCancelTransitionReceipt {
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCancelObservationReceipt {
    pub schema: String,
    pub workflow_id: String,
    pub action_digest: DigestHex,
    pub policy_digest: DigestHex,
    pub decision_receipt_digest: DigestHex,
    pub cancellation_id: DigestHex,
    pub provider: SubscriptionCancelProviderProjection,
    pub cancellation_scheduled: bool,
    pub terminal_cancellation_observed: bool,
    pub invoice_now: bool,
    pub prorate: bool,
    pub liability_released_minor: u64,
    pub liability_retained_minor: u64,
    pub reconciled: bool,
    pub downstream_deprovisioning_proven: bool,
    pub residual_assumptions: Vec<String>,
    pub recorded_at: u64,
}

impl SubscriptionCancelObservationReceipt {
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Closed receipt family. Create/modify cannot add variants.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "receipt")]
pub enum SubscriptionCancelReceipt {
    #[serde(rename = "subscription-cancel-decision")]
    Decision(Box<SubscriptionCancelDecisionReceipt>),
    #[serde(rename = "subscription-cancel-transition")]
    Transition(Box<SubscriptionCancelTransitionReceipt>),
    #[serde(rename = "subscription-cancel-observation")]
    Observation(Box<SubscriptionCancelObservationReceipt>),
}

impl SubscriptionCancelReceipt {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt_kind(receipt: &SubscriptionCancelReceipt) -> &'static str {
        match receipt {
            SubscriptionCancelReceipt::Decision(_) => "decision",
            SubscriptionCancelReceipt::Transition(_) => "transition",
            SubscriptionCancelReceipt::Observation(_) => "observation",
        }
    }

    #[test]
    fn receipt_family_is_closed_at_compile_time() {
        let _ = receipt_kind;
    }
}
