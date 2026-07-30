//! Closed receipt family for Connect Transfer.

#![allow(
    clippy::missing_errors_doc,
    clippy::struct_excessive_bools,
    reason = "receipts preserve independent audit boundary facts"
)]

use serde::{Deserialize, Serialize};

use super::{
    ConnectTransferAggregateSnapshot, ConnectTransferDecision, ConnectTransferEvidenceV1,
    ConnectTransferProviderProjection, ConnectTransferReservationRecord,
    StripeBoundedConnectTransferPolicyV1, StripeConnectTransferConfigurationV1,
    StripeExactConnectTransferV1,
};
use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    types::DigestHex,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectTransferDecisionReceipt {
    pub schema: String,
    pub workflow_id: String,
    pub policy_provenance: String,
    pub policy: StripeBoundedConnectTransferPolicyV1,
    pub policy_digest: DigestHex,
    pub action: StripeExactConnectTransferV1,
    pub action_digest: DigestHex,
    pub evidence: ConnectTransferEvidenceV1,
    pub evidence_digest: DigestHex,
    pub aggregate_before: ConnectTransferAggregateSnapshot,
    pub required_configuration: StripeConnectTransferConfigurationV1,
    pub executed_configuration: StripeConnectTransferConfigurationV1,
    pub configuration_equal: bool,
    pub auths_decision: String,
    pub auths_code: String,
    pub bounded_decision: Option<ConnectTransferDecision>,
    pub credential_requested: bool,
    pub provider_called: bool,
    pub decided_at: u64,
}

impl ConnectTransferDecisionReceipt {
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectTransferTransitionReceipt {
    pub schema: String,
    pub workflow_id: String,
    pub decision_receipt_digest: DigestHex,
    pub semantic_event: String,
    pub reservation: ConnectTransferReservationRecord,
    pub critical_evidence_digest: Option<DigestHex>,
    pub provider: Option<ConnectTransferProviderProjection>,
    pub credential_requested: bool,
    pub provider_called: bool,
    pub recorded_at: u64,
}

impl ConnectTransferTransitionReceipt {
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectTransferObservationReceipt {
    pub schema: String,
    pub workflow_id: String,
    pub decision_receipt_digest: DigestHex,
    pub provider: ConnectTransferProviderProjection,
    pub exact_provider_result: bool,
    pub capacity_held_after: bool,
    pub reconciled: bool,
    pub residual_assumptions: Vec<String>,
    pub recorded_at: u64,
}

impl ConnectTransferObservationReceipt {
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Connect-transfer-owned receipt union.
///
/// Other Stripe profiles never add variants here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "receipt")]
pub enum ConnectTransferReceipt {
    #[serde(rename = "connect-transfer-decision")]
    Decision(Box<ConnectTransferDecisionReceipt>),
    #[serde(rename = "connect-transfer-transition")]
    Transition(Box<ConnectTransferTransitionReceipt>),
    #[serde(rename = "connect-transfer-observation")]
    Observation(Box<ConnectTransferObservationReceipt>),
}

impl ConnectTransferReceipt {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }
}
