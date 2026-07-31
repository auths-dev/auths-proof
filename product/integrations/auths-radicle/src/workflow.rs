//! Domain-owned projection of shared publication state and post-commit
//! propagation progress.
//!
//! Durable reservation, attempt, outcome-unknown, and reconciliation
//! transitions live exclusively in `auths-lifecycle`. These types retain the
//! public Radicle workflow vocabulary without defining a second state machine.

use serde::{Deserialize, Serialize};

use crate::{
    executor::LocalPublication,
    types::{CobId, DigestHex, GitOid, WorkflowId},
};

/// Monotonic domain presentation stage.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowStage {
    /// Shared lifecycle capacity is held or reconciliation is required.
    Claimed,
    /// A patch/revision was committed locally by Radicle.
    Stored,
    /// The executor announced the committed revision.
    Announced,
    /// An independent observer found the revision.
    Replicated,
}

/// Public Radicle-shaped projection of authoritative shared lifecycle state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRecord {
    workflow_id: WorkflowId,
    action_digest: DigestHex,
    lease_digest: DigestHex,
    stage: WorkflowStage,
    patch_id: Option<CobId>,
    revision_id: Option<GitOid>,
    updated_at: u64,
}

impl WorkflowRecord {
    pub(crate) fn from_lifecycle(
        workflow_id: WorkflowId,
        action_digest: DigestHex,
        claim_id: DigestHex,
        stage: WorkflowStage,
        publication: Option<&LocalPublication>,
        updated_at: u64,
    ) -> Self {
        Self {
            workflow_id,
            action_digest,
            lease_digest: claim_id,
            stage,
            patch_id: publication.map(|value| value.patch_id.clone()),
            revision_id: publication.map(|value| value.revision_id.clone()),
            updated_at,
        }
    }

    /// Returns the workflow.
    #[must_use]
    pub const fn workflow_id(&self) -> &WorkflowId {
        &self.workflow_id
    }

    /// Returns the exact action commitment.
    #[must_use]
    pub const fn action_digest(&self) -> &DigestHex {
        &self.action_digest
    }

    /// Returns the farthest proven Radicle stage.
    #[must_use]
    pub const fn stage(&self) -> WorkflowStage {
        self.stage
    }

    /// Returns the patch identifier once local publication is committed.
    #[must_use]
    pub const fn patch_id(&self) -> Option<&CobId> {
        self.patch_id.as_ref()
    }

    /// Returns the initial revision identifier once local publication is
    /// committed.
    #[must_use]
    pub const fn revision_id(&self) -> Option<&GitOid> {
        self.revision_id.as_ref()
    }
}
