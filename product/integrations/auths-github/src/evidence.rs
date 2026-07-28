//! Fresh GitHub state committed into exact actions.

use serde::{Deserialize, Serialize};

use crate::{
    candidate::CandidateEvidence,
    canonical::{CanonicalError, canonical_digest},
    types::{DigestHex, GitOid, IssueResource, NodeId, RefName, RepositoryResource, WorkflowId},
};

/// Fresh repository identity evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryEvidence {
    /// Immutable numeric repository identifier.
    pub repository_id: u64,
    /// Immutable GraphQL node identifier.
    pub repository_node_id: NodeId,
    /// Current owner.
    pub owner: String,
    /// Current name.
    pub name: String,
}

/// Fresh issue evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueEvidence {
    /// Immutable repository identifier.
    pub repository_id: u64,
    /// Immutable issue node identifier.
    pub issue_node_id: NodeId,
    /// Repository-local issue number.
    pub issue_number: u64,
    /// True only while GitHub reports the issue open.
    pub open: bool,
}

/// Fresh Git reference evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefEvidence {
    /// Queried reference.
    pub ref_name: RefName,
    /// Exact head when present.
    pub revision: Option<GitOid>,
}

/// Existing pull request matching the deterministic workflow head/base pair.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequestEvidence {
    /// Immutable PR node identifier.
    pub node_id: NodeId,
    /// Repository-local PR number.
    pub number: u64,
    /// Public GitHub URL.
    pub url: String,
    /// Base ref.
    pub base_ref: RefName,
    /// Head ref.
    pub head_ref: RefName,
    /// Exact head revision.
    pub head_revision: GitOid,
    /// Draft state.
    pub draft: bool,
}

/// Complete fresh state used by containment and exact action derivation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubEvidence {
    /// Evidence schema.
    pub schema: String,
    /// Workflow.
    pub workflow_id: WorkflowId,
    /// Repository identity.
    pub repository: RepositoryEvidence,
    /// Issue identity and state.
    pub issue: IssueEvidence,
    /// Exact base ref state.
    pub base: RefEvidence,
    /// Derived target ref state.
    pub target: RefEvidence,
    /// Matching pull requests.
    pub matching_pull_requests: Vec<PullRequestEvidence>,
    /// Trusted candidate facts.
    pub candidate: CandidateEvidence,
    /// Approved repository automation policy commitment.
    pub repository_policy_digest: DigestHex,
    /// Trusted acquisition time.
    pub acquired_at: u64,
    /// Version-pinned source configuration.
    pub source_configuration: String,
}

impl GitHubEvidence {
    /// Canonical evidence commitment.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    /// Validates closed evidence shape.
    ///
    /// # Errors
    ///
    /// Rejects inconsistent identity, refs, source, or bounded collections.
    pub fn validate(
        &self,
        repository: &RepositoryResource,
        issue: &IssueResource,
        base_ref: &RefName,
        target_ref: &RefName,
    ) -> Result<(), EvidenceError> {
        if self.schema != "auths-github-evidence-v1"
            || self.workflow_id.as_str().is_empty()
            || self.repository.repository_id == 0
            || self.issue.repository_id == 0
            || self.issue.issue_number == 0
            || &self.base.ref_name != base_ref
            || &self.target.ref_name != target_ref
            || repository.repository_id() != issue.repository_id()
            || self.source_configuration.is_empty()
            || self.source_configuration.len() > 96
            || self.matching_pull_requests.len() > 32
        {
            return Err(EvidenceError);
        }
        Ok(())
    }
}

/// Invalid or over-broad evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid GitHub evidence")]
pub struct EvidenceError;
