//! Sealed execution input and locally stored Radicle publication.

use std::path::Path;

use auths_sdk::Authorized;
use serde::{Deserialize, Serialize};

use crate::{
    candidate::InspectedCandidate,
    profile::RadiclePatchCommand,
    types::{
        CandidateSubmission, CobId, GitOid, NodeId, RadicleDid, RadicleEvidenceV1, Rid, WorkflowId,
    },
    workflow::ExecutionLease,
};

/// Executor input constructible only after containment, Auths verification,
/// and an at-most-once durable claim all succeed.
pub struct VerifiedOpenPatchCommand {
    authorized: Authorized<RadiclePatchCommand>,
    candidate: InspectedCandidate,
    submission: CandidateSubmission,
    evidence: RadicleEvidenceV1,
    lease: ExecutionLease,
}

impl VerifiedOpenPatchCommand {
    pub(crate) const fn new(
        authorized: Authorized<RadiclePatchCommand>,
        candidate: InspectedCandidate,
        submission: CandidateSubmission,
        evidence: RadicleEvidenceV1,
        lease: ExecutionLease,
    ) -> Self {
        Self {
            authorized,
            candidate,
            submission,
            evidence,
            lease,
        }
    }

    /// Returns the isolated verified Git repository.
    #[must_use]
    pub fn repository_path(&self) -> &Path {
        self.candidate.repository_path()
    }

    /// Returns the exact candidate commit.
    #[must_use]
    pub const fn candidate_oid(&self) -> &GitOid {
        self.candidate.facts().candidate_oid()
    }

    /// Returns the exact granted base.
    #[must_use]
    pub const fn base_oid(&self) -> &GitOid {
        self.candidate.facts().base_oid()
    }

    /// Returns the exact patch title.
    #[must_use]
    pub fn patch_title(&self) -> &str {
        &self.submission.patch_title
    }

    /// Returns the exact non-interactive Radicle push messages.
    ///
    /// Radicle concatenates repeated `patch.message` push options with a blank
    /// line. Git forbids newline bytes inside one push option, so each bounded
    /// semantic paragraph is supplied separately.
    #[must_use]
    pub fn patch_messages(&self) -> [String; 4] {
        [
            self.submission.patch_title.clone(),
            self.submission.patch_body.clone(),
            format!(
                "Radicle-Issue: {}",
                self.authorized.command().action().issue_id()
            ),
            format!(
                "Auths-Workflow: {}",
                self.authorized.command().action().workflow_id()
            ),
        ]
    }

    /// Returns the exact repository.
    #[must_use]
    pub const fn rid(&self) -> &Rid {
        self.authorized.command().action().rid()
    }

    /// Returns the exact workflow identifier.
    #[must_use]
    pub const fn workflow_id(&self) -> &WorkflowId {
        self.authorized.command().action().workflow_id()
    }

    /// Returns the exact issue authorized by the action.
    #[must_use]
    pub const fn authorized_issue_id(&self) -> &CobId {
        self.authorized.command().action().issue_id()
    }

    /// Returns the signer identity observed before authorization.
    #[must_use]
    pub const fn signer_did(&self) -> &RadicleDid {
        self.evidence.executor_signer_did()
    }

    /// Returns the executor node observed before authorization.
    #[must_use]
    pub const fn node_id(&self) -> &NodeId {
        self.evidence.executor_node_id()
    }

    /// Returns the verified identity-declared canonical branch.
    #[must_use]
    pub fn default_branch(&self) -> &str {
        self.evidence.default_branch()
    }

    /// Returns the durable execution lease.
    #[must_use]
    pub const fn lease(&self) -> &ExecutionLease {
        &self.lease
    }

    pub(crate) fn into_materials(self) -> ExecutionMaterials {
        ExecutionMaterials {
            authorized: self.authorized,
            candidate: self.candidate,
            evidence: self.evidence,
            lease: self.lease,
        }
    }
}

pub(crate) struct ExecutionMaterials {
    pub authorized: Authorized<RadiclePatchCommand>,
    pub candidate: InspectedCandidate,
    pub evidence: RadicleEvidenceV1,
    pub lease: ExecutionLease,
}

/// Result proven immediately after the local Radicle write boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalPublication {
    /// Repository receiving the patch.
    pub rid: Rid,
    /// New patch collaborative-object identifier.
    pub patch_id: CobId,
    /// Initial patch revision identifier.
    pub revision_id: GitOid,
    /// Exact candidate commit stored by the revision.
    pub candidate_oid: GitOid,
    /// Actual Radicle signer.
    pub signer_did: RadicleDid,
    /// Actual Radicle node.
    pub node_id: NodeId,
    /// Trusted write completion time.
    pub stored_at: u64,
}
