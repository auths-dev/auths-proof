//! Canonical vertical receipts separating authority, execution, and propagation.

use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    containment::{Decision, DecisionClass},
    executor::LocalPublication,
    types::{DigestHex, GitOid, NodeId, OpenPatchActionV1, VerifierConfiguration, WorkflowId},
    workflow::ExecutionLease,
};

/// Product decision receipt emitted even when Auths verification is not run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadicleDecisionReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Workflow.
    pub workflow_id: WorkflowId,
    /// Exact action body commitment, absent when preflight configuration
    /// validation fails before candidate or evidence acquisition.
    pub action_digest: Option<DigestHex>,
    /// Human workflow commitment.
    pub workflow_grant_digest: DigestHex,
    /// Required configuration selected by the grant/caller.
    pub required_configuration: VerifierConfiguration,
    /// Configuration actually loaded by the executor.
    pub executed_configuration: VerifierConfiguration,
    /// Required configuration commitment.
    pub required_configuration_digest: DigestHex,
    /// Executed configuration commitment.
    pub executed_configuration_digest: DigestHex,
    /// Radicle-specific containment result.
    pub product_decision: Decision,
    /// Auths kernel decision class, once the kernel ran.
    pub auths_decision: Option<DecisionClass>,
    /// Auths kernel result code, once the kernel ran.
    pub auths_code: Option<String>,
    /// Auths proof digest, only after successful verification.
    pub auths_proof_digest: Option<DigestHex>,
    /// Auths context digest, only after successful verification.
    pub auths_context_digest: Option<DigestHex>,
    /// Trusted decision time.
    pub decided_at: u64,
}

impl RadicleDecisionReceipt {
    /// Returns the canonical receipt commitment.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Receipt for the one irreversible local Radicle write.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadicleExecutionReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Decision receipt commitment.
    pub decision_receipt_digest: DigestHex,
    /// Durable at-most-once lease.
    pub execution_lease_digest: DigestHex,
    /// Locally proven Radicle result.
    pub publication: LocalPublication,
}

impl RadicleExecutionReceipt {
    /// Constructs a receipt around a sealed lease and the actual local result.
    #[must_use]
    pub fn new(
        schema: impl Into<String>,
        decision_receipt_digest: DigestHex,
        lease: &ExecutionLease,
        publication: LocalPublication,
    ) -> Self {
        Self {
            schema: schema.into(),
            decision_receipt_digest,
            execution_lease_digest: lease.lease_digest().clone(),
            publication,
        }
    }

    /// Returns the canonical receipt commitment.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Independent evidence that an announced revision reached another node.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadiclePropagationReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Execution receipt commitment.
    pub execution_receipt_digest: DigestHex,
    /// Independent observing node.
    pub observer_node_id: NodeId,
    /// Observed initial revision.
    pub revision_id: GitOid,
    /// Observed candidate commit.
    pub candidate_oid: GitOid,
    /// Observation time.
    pub observed_at: u64,
}

impl RadiclePropagationReceipt {
    /// Returns the canonical receipt commitment.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Closed receipt union accepted by sinks.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "receipt", rename_all = "kebab-case")]
pub enum RadicleReceipt {
    /// Product/Auths decision.
    Decision(Box<RadicleDecisionReceipt>),
    /// Local write.
    Execution(Box<RadicleExecutionReceipt>),
    /// Independent replication.
    Propagation(Box<RadiclePropagationReceipt>),
}

impl RadicleReceipt {
    /// Returns canonical receipt bytes.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }
}

/// Builds the decision receipt fields common to every outcome.
///
/// # Errors
///
/// Returns a canonicalization failure for configuration or action commitments.
pub fn decision_receipt(
    action: &OpenPatchActionV1,
    required_configuration: &VerifierConfiguration,
    executed_configuration: &VerifierConfiguration,
    product_decision: Decision,
    decided_at: u64,
) -> Result<RadicleDecisionReceipt, CanonicalError> {
    Ok(RadicleDecisionReceipt {
        schema: executed_configuration.receipt_schema().into(),
        workflow_id: action.workflow_id().clone(),
        action_digest: Some(action.digest()?),
        workflow_grant_digest: action.workflow_grant_digest().clone(),
        required_configuration: required_configuration.clone(),
        executed_configuration: executed_configuration.clone(),
        required_configuration_digest: required_configuration.digest()?,
        executed_configuration_digest: executed_configuration.digest()?,
        product_decision,
        auths_decision: None,
        auths_code: None,
        auths_proof_digest: None,
        auths_context_digest: None,
        decided_at,
    })
}

/// Builds a decision receipt for a failure proven before an exact action may
/// safely be derived.
///
/// # Errors
///
/// Returns a canonicalization failure for the grant or configurations.
pub fn preflight_decision_receipt(
    workflow_id: WorkflowId,
    workflow_grant_digest: DigestHex,
    required_configuration: VerifierConfiguration,
    executed_configuration: VerifierConfiguration,
    product_decision: Decision,
    decided_at: u64,
) -> Result<RadicleDecisionReceipt, CanonicalError> {
    Ok(RadicleDecisionReceipt {
        schema: executed_configuration.receipt_schema().into(),
        workflow_id,
        action_digest: None,
        workflow_grant_digest,
        required_configuration_digest: required_configuration.digest()?,
        executed_configuration_digest: executed_configuration.digest()?,
        required_configuration,
        executed_configuration,
        product_decision,
        auths_decision: None,
        auths_code: None,
        auths_proof_digest: None,
        auths_context_digest: None,
        decided_at,
    })
}
