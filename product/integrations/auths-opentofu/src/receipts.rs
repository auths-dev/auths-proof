//! Linked privacy-aware OpenTofu receipts.

use serde::{Deserialize, Serialize};

use crate::{
    action::OpenTofuSavedPlanApplyV1,
    canonical::{canonical_digest, sha256},
    claim::ClaimRecord,
    decision::{Decision, EvaluationContext, evaluate},
    errors::CanonicalError,
    plan_projection::SavedPlanProjectionV1,
    types::{
        DigestHex, OpenTofuApplyResult, OpenTofuStateEvidenceV1, OpenTofuVerifierConfigurationV1,
    },
};

/// Decision receipt with demanded and executed verifier policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    pub schema: String,
    pub action_digest: DigestHex,
    pub evidence_digest: DigestHex,
    pub plan_projection_digest: DigestHex,
    pub required_configuration: OpenTofuVerifierConfigurationV1,
    pub executed_configuration: OpenTofuVerifierConfigurationV1,
    pub decision: Decision,
    pub auths_decision: Option<String>,
    pub auths_code: Option<String>,
    pub decided_at: u64,
}

impl DecisionReceipt {
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Saved-plan invocation and resulting state receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApplyReceipt {
    pub schema: String,
    pub decision_digest: DigestHex,
    pub action_digest: DigestHex,
    pub opaque_plan_digest: DigestHex,
    pub backend_commitment: DigestHex,
    pub workspace_commitment: DigestHex,
    pub result: OpenTofuApplyResult,
}

/// Fresh provider/state read-back receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservationReceipt {
    pub schema: String,
    pub action_digest: DigestHex,
    pub resulting_state_digest: DigestHex,
    pub provider_object_commitment: DigestHex,
    pub postconditions_match: bool,
    pub observed_at: u64,
}

/// Linked receipt variants.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum OpenTofuReceipt {
    Decision(Box<DecisionReceipt>),
    Claim(ClaimRecord),
    Apply(Box<ApplyReceipt>),
    Observation(ObservationReceipt),
}

#[allow(
    clippy::too_many_arguments,
    reason = "receipt construction exposes every verifier input"
)]
pub fn decision_receipt(
    action: &OpenTofuSavedPlanApplyV1,
    projection: &SavedPlanProjectionV1,
    evidence: &OpenTofuStateEvidenceV1,
    required_configuration: &OpenTofuVerifierConfigurationV1,
    executed_configuration: &OpenTofuVerifierConfigurationV1,
    request_audience: &str,
    now: u64,
) -> Result<DecisionReceipt, CanonicalError> {
    Ok(DecisionReceipt {
        schema: executed_configuration.receipt_schema_version().into(),
        action_digest: action.digest()?,
        evidence_digest: evidence.digest()?,
        plan_projection_digest: projection.digest()?,
        required_configuration: required_configuration.clone(),
        executed_configuration: executed_configuration.clone(),
        decision: evaluate(&EvaluationContext {
            action,
            projection,
            evidence,
            required_configuration,
            executed_configuration,
            request_audience,
            now,
        }),
        auths_decision: None,
        auths_code: None,
        decided_at: now,
    })
}

pub fn apply_receipt(
    decision_digest: DigestHex,
    action: &OpenTofuSavedPlanApplyV1,
    result: OpenTofuApplyResult,
) -> Result<ApplyReceipt, CanonicalError> {
    Ok(ApplyReceipt {
        schema: "auths.opentofu.apply-receipt/1".into(),
        decision_digest,
        action_digest: action.digest()?,
        opaque_plan_digest: action.opaque_plan_digest().clone(),
        backend_commitment: sha256(action.backend_identity().as_bytes()),
        workspace_commitment: sha256(action.workspace().as_bytes()),
        result,
    })
}

pub fn observation_receipt(
    action: &OpenTofuSavedPlanApplyV1,
    result: &OpenTofuApplyResult,
) -> Result<ObservationReceipt, CanonicalError> {
    Ok(ObservationReceipt {
        schema: "auths.opentofu.observation-receipt/1".into(),
        action_digest: action.digest()?,
        resulting_state_digest: result.resulting_state_digest.clone(),
        provider_object_commitment: result.provider_object_commitment.clone(),
        postconditions_match: result.postconditions_observed && result.converged,
        observed_at: result.finished_at,
    })
}
