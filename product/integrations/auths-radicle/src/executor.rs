//! Sealed execution input and locally stored Radicle publication.

use std::path::Path;

use auths_lifecycle::{ExecutionAuthorizationV1, ProviderCallAuthorizationV1};
use auths_sdk::Authorized;
use serde::{Deserialize, Serialize};

use crate::{
    candidate::InspectedCandidate,
    canonical::sha256,
    lifecycle::PROVIDER_CONTRACT_ID,
    profile::RadiclePatchCommand,
    types::DigestHex,
    types::{
        CandidateSubmission, CobId, GitOid, NodeId, RadicleDid, RadicleEvidenceV1, Rid, WorkflowId,
    },
};

/// Executor input constructible only after containment, Auths verification,
/// and an at-most-once durable claim all succeed.
pub struct VerifiedOpenPatchCommand {
    authorized: Authorized<RadiclePatchCommand>,
    candidate: InspectedCandidate,
    submission: CandidateSubmission,
    evidence: RadicleEvidenceV1,
    execution_authorization: ExecutionAuthorizationV1,
    provider_call_authorization: ProviderCallAuthorizationV1,
    claim_id: DigestHex,
}

impl VerifiedOpenPatchCommand {
    pub(crate) const fn new(
        authorized: Authorized<RadiclePatchCommand>,
        candidate: InspectedCandidate,
        submission: CandidateSubmission,
        evidence: RadicleEvidenceV1,
        execution_authorization: ExecutionAuthorizationV1,
        provider_call_authorization: ProviderCallAuthorizationV1,
        claim_id: DigestHex,
    ) -> Self {
        Self {
            authorized,
            candidate,
            submission,
            evidence,
            execution_authorization,
            provider_call_authorization,
            claim_id,
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

    /// Returns the durable shared-lifecycle claim commitment.
    #[must_use]
    pub const fn claim_id(&self) -> &DigestHex {
        &self.claim_id
    }

    /// Validates that both sealed lifecycle stages authorize this same call.
    #[must_use]
    pub fn lifecycle_authorization_matches(&self) -> bool {
        let Ok(action_digest) = self.authorized.command().action().digest() else {
            return false;
        };
        let Some(action_digest_bytes) = hex::decode(action_digest.as_str())
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        else {
            return false;
        };
        let mut claim_material = Vec::with_capacity(160);
        claim_material.extend_from_slice(b"AUTHS-RADICLE-CLAIM\x00\x01");
        claim_material.extend_from_slice(self.workflow_id().as_str().as_bytes());
        claim_material.extend_from_slice(action_digest.as_str().as_bytes());
        self.execution_authorization.provider_contract_id().as_str() == PROVIDER_CONTRACT_ID
            && self.execution_authorization.workflow_id()
                == self.provider_call_authorization.workflow_id()
            && self.execution_authorization.execution_id()
                == self.provider_call_authorization.execution_id()
            && self.execution_authorization.provider_request_digest()
                == self.provider_call_authorization.provider_request_digest()
            && self
                .execution_authorization
                .provider_request_digest()
                .bytes()
                == &action_digest_bytes
            && self.provider_call_authorization.revision() > self.execution_authorization.revision()
            && self.claim_id == sha256(&claim_material)
    }

    pub(crate) fn into_materials(self) -> ExecutionMaterials {
        ExecutionMaterials {
            authorized: self.authorized,
            candidate: self.candidate,
            evidence: self.evidence,
            execution_authorization: self.execution_authorization,
            provider_call_authorization: self.provider_call_authorization,
            claim_id: self.claim_id,
        }
    }
}

pub(crate) struct ExecutionMaterials {
    pub authorized: Authorized<RadiclePatchCommand>,
    pub candidate: InspectedCandidate,
    pub evidence: RadicleEvidenceV1,
    pub execution_authorization: ExecutionAuthorizationV1,
    pub provider_call_authorization: ProviderCallAuthorizationV1,
    pub claim_id: DigestHex,
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
