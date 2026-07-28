//! Sealed executor inputs constructible only after Auths verification and CAS.

use auths_sdk::Authorized;

use crate::{
    profile::GitHubCommand,
    types::{
        OpenDraftPullRequestAction, PublishBranchAction, RefName, RepositoryResource, WorkflowId,
    },
    workflow::ExecutionClaim,
};

/// Sealed exact branch publication.
pub struct VerifiedPublishBranch {
    authorized: Authorized<GitHubCommand>,
    claim: ExecutionClaim,
}

impl VerifiedPublishBranch {
    pub(crate) fn new(
        authorized: Authorized<GitHubCommand>,
        claim: ExecutionClaim,
    ) -> Result<Self, ExecutorError> {
        if !matches!(
            authorized.command().action(),
            crate::types::ExactGitHubAction::PublishBranch(_)
        ) || claim.operation() != crate::types::GitHubOperation::PublishBranch
        {
            return Err(ExecutorError);
        }
        Ok(Self { authorized, claim })
    }

    /// Exact authorized branch action.
    #[must_use]
    pub fn action(&self) -> &PublishBranchAction {
        match self.authorized.command().action() {
            crate::types::ExactGitHubAction::PublishBranch(action) => action,
            crate::types::ExactGitHubAction::OpenDraftPullRequest(_) => {
                unreachable!("constructor enforces branch action")
            }
        }
    }

    /// Durable effect claim.
    #[must_use]
    pub const fn claim(&self) -> &ExecutionClaim {
        &self.claim
    }

    /// Exact repository.
    #[must_use]
    pub fn repository(&self) -> &RepositoryResource {
        &self.action().repository
    }

    /// Exact executor-derived target ref.
    #[must_use]
    pub fn target_ref(&self) -> &RefName {
        &self.action().target_ref
    }

    /// Exact candidate SHA.
    #[must_use]
    pub fn candidate_revision(&self) -> &crate::types::GitOid {
        &self.action().candidate_revision
    }

    /// Workflow.
    #[must_use]
    pub fn workflow_id(&self) -> &WorkflowId {
        &self.action().workflow_id
    }
}

/// Sealed exact draft pull-request creation.
pub struct VerifiedOpenDraftPullRequest {
    authorized: Authorized<GitHubCommand>,
    claim: ExecutionClaim,
    exact_body: String,
}

impl VerifiedOpenDraftPullRequest {
    pub(crate) fn new(
        authorized: Authorized<GitHubCommand>,
        claim: ExecutionClaim,
        exact_body: String,
    ) -> Result<Self, ExecutorError> {
        if !matches!(
            authorized.command().action(),
            crate::types::ExactGitHubAction::OpenDraftPullRequest(_)
        ) || claim.operation() != crate::types::GitHubOperation::OpenDraftPullRequest
            || exact_body.is_empty()
            || exact_body.len() > 16 * 1024
        {
            return Err(ExecutorError);
        }
        Ok(Self {
            authorized,
            claim,
            exact_body,
        })
    }

    /// Exact authorized PR action.
    #[must_use]
    pub fn action(&self) -> &OpenDraftPullRequestAction {
        match self.authorized.command().action() {
            crate::types::ExactGitHubAction::OpenDraftPullRequest(action) => action,
            crate::types::ExactGitHubAction::PublishBranch(_) => {
                unreachable!("constructor enforces pull-request action")
            }
        }
    }

    /// Durable effect claim.
    #[must_use]
    pub const fn claim(&self) -> &ExecutionClaim {
        &self.claim
    }

    /// Exact deterministic PR body.
    #[must_use]
    pub fn exact_body(&self) -> &str {
        &self.exact_body
    }

    /// Exact repository.
    #[must_use]
    pub fn repository(&self) -> &RepositoryResource {
        &self.action().repository
    }
}

/// Sealed-command construction invariant failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("verified GitHub command does not match the claimed operation")]
pub struct ExecutorError;
