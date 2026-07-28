//! Portable Kubernetes decision, execution, and observation receipts.

use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalError, canonical_digest},
    claim::ClaimRecord,
    decision::{Decision, EvaluationContext, evaluate},
    types::{
        DigestHex, KubernetesEvidenceV1, KubernetesRolloutResult, KubernetesVerifierConfiguration,
        KubernetesWorkloadRolloutV1,
    },
};

/// Decision receipt including both demanded and executed policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    pub schema: String,
    pub workflow_id: String,
    pub action_digest: DigestHex,
    pub evidence_digest: DigestHex,
    pub required_configuration: KubernetesVerifierConfiguration,
    pub executed_configuration: KubernetesVerifierConfiguration,
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

/// Kubernetes API and rollout observation receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub schema: String,
    pub decision_digest: DigestHex,
    pub action_digest: DigestHex,
    pub patch_digest: DigestHex,
    pub cluster_audience_commitment: DigestHex,
    pub namespace: String,
    pub deployment: String,
    pub resource_uid: String,
    pub result: KubernetesRolloutResult,
}

/// Linked receipt variants.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum KubernetesReceipt {
    Decision(Box<DecisionReceipt>),
    Claim(ClaimRecord),
    Execution(Box<ExecutionReceipt>),
}

/// Builds a complete pure decision receipt.
pub fn decision_receipt(
    action: &KubernetesWorkloadRolloutV1,
    evidence: &KubernetesEvidenceV1,
    required_configuration: &KubernetesVerifierConfiguration,
    executed_configuration: &KubernetesVerifierConfiguration,
    request_audience: &str,
    now: u64,
) -> Result<DecisionReceipt, CanonicalError> {
    Ok(DecisionReceipt {
        schema: executed_configuration.receipt_schema_version().into(),
        workflow_id: action.workflow_id().into(),
        action_digest: action.digest()?,
        evidence_digest: evidence.digest()?,
        required_configuration: required_configuration.clone(),
        executed_configuration: executed_configuration.clone(),
        decision: evaluate(&EvaluationContext {
            action,
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

/// Builds the effect receipt from verified inputs and authenticated observation.
pub fn execution_receipt(
    decision_digest: DigestHex,
    action: &KubernetesWorkloadRolloutV1,
    result: KubernetesRolloutResult,
) -> Result<ExecutionReceipt, CanonicalError> {
    Ok(ExecutionReceipt {
        schema: "auths.kubernetes.receipt/1".into(),
        decision_digest,
        action_digest: action.digest()?,
        patch_digest: action.patch_digest().clone(),
        cluster_audience_commitment: crate::canonical::sha256(action.cluster_audience().as_bytes()),
        namespace: action.namespace_name().to_string(),
        deployment: action.resource_name().to_string(),
        resource_uid: action.resource_uid().to_string(),
        result,
    })
}
