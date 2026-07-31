//! Stage-sealed executor inputs constructible only after Auths verification
//! and durable shared-lifecycle authorization.

use auths_lifecycle::{ExecutionAuthorizationV1, ProviderCallAuthorizationV1};
use auths_sdk::Authorized;

use crate::{
    profile::GitHubCommand,
    types::{
        OpenDraftPullRequestAction, PublishBranchAction, RefName, RepositoryResource, WorkflowId,
    },
};

/// Exact branch preparation available only after credential authorization.
pub struct VerifiedPublishBranch {
    authorized: Authorized<GitHubCommand>,
    execution_authorization: ExecutionAuthorizationV1,
}

impl VerifiedPublishBranch {
    pub(crate) fn new(
        authorized: Authorized<GitHubCommand>,
        execution_authorization: ExecutionAuthorizationV1,
    ) -> Result<Self, ExecutorError> {
        if !matches!(
            authorized.command().action(),
            crate::types::ExactGitHubAction::PublishBranch(_)
        ) {
            return Err(ExecutorError);
        }
        Ok(Self {
            authorized,
            execution_authorization,
        })
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

    /// Durable credential-stage authorization.
    #[must_use]
    pub const fn execution_authorization(&self) -> &ExecutionAuthorizationV1 {
        &self.execution_authorization
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

    pub(crate) fn authorize_provider_call(
        self,
        provider_authorization: ProviderCallAuthorizationV1,
    ) -> VerifiedPublishBranchCommand {
        VerifiedPublishBranchCommand {
            authorized: self.authorized,
            provider_authorization,
        }
    }
}

/// Exact branch command available only after durable provider-call entry.
pub struct VerifiedPublishBranchCommand {
    authorized: Authorized<GitHubCommand>,
    provider_authorization: ProviderCallAuthorizationV1,
}

impl VerifiedPublishBranchCommand {
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

    /// Exact repository.
    #[must_use]
    pub fn repository(&self) -> &RepositoryResource {
        &self.action().repository
    }

    /// Durable provider-call authorization.
    #[must_use]
    pub const fn provider_authorization(&self) -> &ProviderCallAuthorizationV1 {
        &self.provider_authorization
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
}

/// Exact draft-PR preparation available only after credential authorization.
pub struct VerifiedOpenDraftPullRequest {
    authorized: Authorized<GitHubCommand>,
    execution_authorization: ExecutionAuthorizationV1,
    exact_body: String,
}

impl VerifiedOpenDraftPullRequest {
    pub(crate) fn new(
        authorized: Authorized<GitHubCommand>,
        execution_authorization: ExecutionAuthorizationV1,
        exact_body: String,
    ) -> Result<Self, ExecutorError> {
        if !matches!(
            authorized.command().action(),
            crate::types::ExactGitHubAction::OpenDraftPullRequest(_)
        ) || exact_body.is_empty()
            || exact_body.len() > 16 * 1024
        {
            return Err(ExecutorError);
        }
        Ok(Self {
            authorized,
            execution_authorization,
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

    /// Durable credential-stage authorization.
    #[must_use]
    pub const fn execution_authorization(&self) -> &ExecutionAuthorizationV1 {
        &self.execution_authorization
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

    pub(crate) fn authorize_provider_call(
        self,
        provider_authorization: ProviderCallAuthorizationV1,
    ) -> VerifiedOpenDraftPullRequestCommand {
        VerifiedOpenDraftPullRequestCommand {
            authorized: self.authorized,
            provider_authorization,
            exact_body: self.exact_body,
        }
    }
}

/// Exact draft-PR command available only after durable provider-call entry.
pub struct VerifiedOpenDraftPullRequestCommand {
    authorized: Authorized<GitHubCommand>,
    provider_authorization: ProviderCallAuthorizationV1,
    exact_body: String,
}

impl VerifiedOpenDraftPullRequestCommand {
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

    /// Exact deterministic PR body.
    #[must_use]
    pub fn exact_body(&self) -> &str {
        &self.exact_body
    }

    /// Durable provider-call authorization.
    #[must_use]
    pub const fn provider_authorization(&self) -> &ProviderCallAuthorizationV1 {
        &self.provider_authorization
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
