//! Canonical GitHub decision and execution receipts.

#![allow(
    clippy::missing_errors_doc,
    reason = "all public receipt encoders return the single documented canonicalization error"
)]

use serde::{Deserialize, Serialize};

use crate::{
    canonical::{CanonicalError, canonical_digest, canonical_json},
    containment::Decision,
    evidence::PullRequestEvidence,
    types::{DigestHex, GitHubOperation, GitOid, RefName, VerifierConfiguration, WorkflowId},
    workflow::WorkflowStage,
};

/// Product/Auths decision recorded before any GitHub credential is requested.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubDecisionReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Workflow.
    pub workflow_id: WorkflowId,
    /// Workflow-grant commitment.
    pub workflow_grant_digest: DigestHex,
    /// Exact action commitment, absent only for preflight denial.
    pub action_digest: Option<DigestHex>,
    /// Auths proof commitment, once the Auths kernel ran.
    pub proof_digest: Option<DigestHex>,
    /// Auths trusted-context commitment, once available.
    pub trusted_context_digest: Option<DigestHex>,
    /// Required configuration selected by the grant/caller.
    pub required_configuration: VerifierConfiguration,
    /// Configuration actually loaded by the executor.
    pub executed_configuration: VerifierConfiguration,
    /// Required configuration commitment.
    pub required_configuration_digest: DigestHex,
    /// Executed configuration commitment.
    pub executed_configuration_digest: DigestHex,
    /// Fresh evidence commitment, once exact action derivation ran.
    pub evidence_digest: Option<DigestHex>,
    /// Product containment result.
    pub product_decision: Decision,
    /// Stable Auths kernel result code, once it ran.
    pub auths_code: Option<String>,
    /// Public executor identity.
    pub executor_identity: String,
    /// Trusted evaluation time.
    pub evaluated_at: u64,
}

impl GitHubDecisionReceipt {
    /// Canonical receipt commitment.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Branch postcondition proven after publication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedBranch {
    /// Repository immutable numeric identifier.
    pub repository_id: u64,
    /// Exact branch ref.
    pub branch_ref: RefName,
    /// Exact remote head.
    pub head_revision: GitOid,
}

/// Exact pull-request postcondition proven after creation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenedPullRequest {
    /// Immutable PR node identifier.
    pub node_id: crate::types::NodeId,
    /// Repository-local PR number.
    pub number: u64,
    /// Public GitHub URL.
    pub url: String,
    /// Exact base ref.
    pub base_ref: RefName,
    /// Exact head ref.
    pub head_ref: RefName,
    /// Exact head revision.
    pub head_revision: GitOid,
    /// Must be draft.
    pub draft: bool,
}

impl From<PullRequestEvidence> for OpenedPullRequest {
    fn from(evidence: PullRequestEvidence) -> Self {
        Self {
            node_id: evidence.node_id,
            number: evidence.number,
            url: evidence.url,
            base_ref: evidence.base_ref,
            head_ref: evidence.head_ref,
            head_revision: evidence.head_revision,
            draft: evidence.draft,
        }
    }
}

/// Observed result of one GitHub effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum ObservedGitHubState {
    /// Exact branch exists.
    Branch(PublishedBranch),
    /// Exact draft pull request exists.
    PullRequest(OpenedPullRequest),
}

/// Execution result distinct from authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionResult {
    /// Exact postcondition observed.
    Succeeded,
    /// Fresh reconciliation proved that the exact effect did not occur.
    NotApplied,
    /// GitHub explicitly rejected the operation.
    GitHubRejected,
    /// Outcome cannot be proven and reconciliation is required.
    ReconciliationRequired,
}

/// One reconciliation observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationEntry {
    /// Stable observation.
    pub result: ExecutionResult,
    /// Trusted observation time.
    pub observed_at: u64,
}

/// Receipt for one separately claimed GitHub effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubExecutionReceipt {
    /// Receipt schema.
    pub schema: String,
    /// Decision receipt commitment.
    pub decision_receipt_digest: DigestHex,
    /// Exact action commitment.
    pub action_digest: DigestHex,
    /// Durable claim identifier.
    pub claim_id: DigestHex,
    /// Expected workflow state before the claim.
    pub expected_prior_state: WorkflowStage,
    /// GitHub operation.
    pub operation: GitHubOperation,
    /// Observed exact postcondition.
    pub observed_state: Option<ObservedGitHubState>,
    /// Repository immutable numeric identifier.
    pub repository_id: u64,
    /// Result.
    pub result: ExecutionResult,
    /// Trusted execution time.
    pub executed_at: u64,
    /// Append-only reconciliation history.
    pub reconciliation_history: Vec<ReconciliationEntry>,
}

impl GitHubExecutionReceipt {
    /// Canonical receipt commitment.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Closed receipt union.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "receipt", rename_all = "kebab-case")]
pub enum GitHubReceipt {
    /// Pre-effect decision.
    Decision(Box<GitHubDecisionReceipt>),
    /// Post-claim execution.
    Execution(Box<GitHubExecutionReceipt>),
}

impl GitHubReceipt {
    /// Canonical receipt bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }

    /// Canonical receipt commitment.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Public signature envelope written by a credential-free receipt signer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGitHubReceipt {
    /// Receipt.
    pub receipt: GitHubReceipt,
    /// Public Ed25519 key in lowercase hex.
    pub signer_public_key: String,
    /// Ed25519 signature in lowercase hex.
    pub signature: String,
}

impl SignedGitHubReceipt {
    /// Canonical signed-envelope bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_json(self)
    }
}
