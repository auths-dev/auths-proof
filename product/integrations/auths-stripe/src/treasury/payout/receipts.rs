//! Closed receipt family for manual Payout.

#![allow(
    clippy::missing_errors_doc,
    clippy::struct_excessive_bools,
    reason = "receipts preserve independent audit boundary facts"
)]

use serde::{Deserialize, Serialize};

use super::{
    PayoutAggregateSnapshot, PayoutDecision, PayoutEvidenceV1, PayoutProviderProjection,
    PayoutReservationRecord, StripeBoundedPayoutPolicyV1, StripeExactPayoutV1,
    StripePayoutConfigurationV1,
};
use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    types::DigestHex,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PayoutDecisionReceipt {
    pub schema: String,
    pub workflow_id: String,
    pub policy_provenance: String,
    pub policy: StripeBoundedPayoutPolicyV1,
    pub policy_digest: DigestHex,
    pub action: StripeExactPayoutV1,
    pub action_digest: DigestHex,
    pub evidence: PayoutEvidenceV1,
    pub evidence_digest: DigestHex,
    pub aggregate_before: PayoutAggregateSnapshot,
    pub required_configuration: StripePayoutConfigurationV1,
    pub executed_configuration: StripePayoutConfigurationV1,
    pub configuration_equal: bool,
    pub auths_decision: String,
    pub auths_code: String,
    pub bounded_decision: Option<PayoutDecision>,
    pub credential_requested: bool,
    pub provider_called: bool,
    pub decided_at: u64,
}

impl PayoutDecisionReceipt {
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PayoutTransitionReceipt {
    pub schema: String,
    pub workflow_id: String,
    pub decision_receipt_digest: DigestHex,
    pub semantic_event: String,
    pub reservation: PayoutReservationRecord,
    pub critical_evidence_digest: Option<DigestHex>,
    pub provider: Option<PayoutProviderProjection>,
    pub credential_requested: bool,
    pub provider_called: bool,
    pub recorded_at: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PayoutObservationReceipt {
    pub schema: String,
    pub workflow_id: String,
    pub decision_receipt_digest: DigestHex,
    pub provider: PayoutProviderProjection,
    pub exact_provider_result: bool,
    pub capacity_held_after: bool,
    pub reconciled: bool,
    pub residual_assumptions: Vec<String>,
    pub recorded_at: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "receipt")]
pub enum PayoutReceipt {
    #[serde(rename = "payout-decision")]
    Decision(Box<PayoutDecisionReceipt>),
    #[serde(rename = "payout-transition")]
    Transition(Box<PayoutTransitionReceipt>),
    #[serde(rename = "payout-observation")]
    Observation(Box<PayoutObservationReceipt>),
}

impl PayoutReceipt {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }
}
