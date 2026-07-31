//! Explicit effect and authority boundaries for the GitHub vertical.

#![allow(
    clippy::missing_errors_doc,
    reason = "each port has a closed, documented error type immediately below the interfaces"
)]

use std::{fmt, sync::Arc};

use auths_lifecycle::ExecutionAuthorizationV1;
use auths_sdk::Authorized;

use crate::{
    candidate::{CandidateError, CandidateSubmission, QuarantinedCandidate},
    evidence::{IssueEvidence, PullRequestEvidence, RefEvidence, RepositoryEvidence},
    executor::{VerifiedOpenDraftPullRequestCommand, VerifiedPublishBranchCommand},
    profile::GitHubCommand,
    receipts::{GitHubReceipt, OpenedPullRequest, PublishedBranch},
    types::{
        DigestHex, ExactGitHubAction, GitHubOperation, IssueResource, RefName, RepositoryResource,
    },
};

/// Trusted candidate-inspection boundary.
pub trait CandidateInspector: Send + Sync {
    /// Inspects one hostile bundle in a fresh quarantine.
    fn inspect(
        &self,
        submission: &CandidateSubmission,
        policy: &crate::types::CandidatePolicy,
        object_format: crate::types::ObjectFormat,
    ) -> Result<QuarantinedCandidate, CandidateError>;
}

/// Fresh, read-only GitHub evidence boundary.
pub trait GitHubReadPort: Send + Sync {
    /// Reads immutable/current repository identity.
    fn repository(
        &self,
        resource: &RepositoryResource,
    ) -> Result<RepositoryEvidence, GitHubReadError>;
    /// Reads issue identity and current state.
    fn issue(&self, resource: &IssueResource) -> Result<IssueEvidence, GitHubReadError>;
    /// Reads one exact ref or proves absence.
    fn ref_state(
        &self,
        repository: &RepositoryResource,
        ref_name: &RefName,
    ) -> Result<RefEvidence, GitHubReadError>;
    /// Reads pull requests matching exact head/base coordinates.
    fn matching_pull_requests(
        &self,
        repository: &RepositoryResource,
        head: &RefName,
        base: &RefName,
    ) -> Result<Vec<PullRequestEvidence>, GitHubReadError>;
}

/// Only GitHub write boundary.
pub trait GitHubWritePort: Send + Sync {
    /// Pushes the exact candidate SHA to the exact absent derived branch.
    fn publish_branch(
        &self,
        command: &VerifiedPublishBranchCommand,
        candidate: &QuarantinedCandidate,
        credential: &ScopedCredential,
    ) -> Result<PublishedBranch, GitHubWriteError>;
    /// Opens the exact deterministic draft pull request.
    fn open_draft_pull_request(
        &self,
        command: &VerifiedOpenDraftPullRequestCommand,
        credential: &ScopedCredential,
    ) -> Result<OpenedPullRequest, GitHubWriteError>;
}

/// Protected GitHub App credential boundary.
pub trait CredentialProvider: Send + Sync {
    /// Mints one short-lived repository-scoped installation credential.
    fn installation_credential(
        &self,
        authorization: &ExecutionAuthorizationV1,
        repository: &RepositoryResource,
        operation: GitHubOperation,
    ) -> Result<ScopedCredential, CredentialError>;
}

/// Executor-internal exact child-proof authorizer.
///
/// Implementations own the ephemeral workflow key and run the Auths kernel.
/// Public callers never provide child action proofs or mutation alternates.
pub trait ExactActionAuthorizer: Send + Sync {
    /// Authorizes one exact action after containment.
    fn authorize(
        &self,
        action: &ExactGitHubAction,
        now: u64,
    ) -> Result<ProofAuthorization, ProofError>;
}

/// Successful Auths kernel result and receipt commitments.
pub struct ProofAuthorization {
    /// Profile-decoded sealed command.
    pub authorized: Authorized<GitHubCommand>,
    /// Exact proof commitment.
    pub proof_digest: DigestHex,
    /// Trusted verifier-context commitment.
    pub context_digest: DigestHex,
}

/// Append-only signed receipt boundary.
pub trait ReceiptSink: Send + Sync {
    /// Signs, appends, and returns the canonical receipt commitment.
    fn append(&self, receipt: &GitHubReceipt) -> Result<DigestHex, ReceiptError>;
}

/// Trusted time boundary.
pub trait Clock: Send + Sync {
    /// Unix seconds.
    fn now(&self) -> Result<u64, ClockError>;
}

impl<T: CandidateInspector + ?Sized> CandidateInspector for Arc<T> {
    fn inspect(
        &self,
        submission: &CandidateSubmission,
        policy: &crate::types::CandidatePolicy,
        object_format: crate::types::ObjectFormat,
    ) -> Result<QuarantinedCandidate, CandidateError> {
        (**self).inspect(submission, policy, object_format)
    }
}

impl<T: GitHubReadPort + ?Sized> GitHubReadPort for Arc<T> {
    fn repository(
        &self,
        resource: &RepositoryResource,
    ) -> Result<RepositoryEvidence, GitHubReadError> {
        (**self).repository(resource)
    }

    fn issue(&self, resource: &IssueResource) -> Result<IssueEvidence, GitHubReadError> {
        (**self).issue(resource)
    }

    fn ref_state(
        &self,
        repository: &RepositoryResource,
        ref_name: &RefName,
    ) -> Result<RefEvidence, GitHubReadError> {
        (**self).ref_state(repository, ref_name)
    }

    fn matching_pull_requests(
        &self,
        repository: &RepositoryResource,
        head: &RefName,
        base: &RefName,
    ) -> Result<Vec<PullRequestEvidence>, GitHubReadError> {
        (**self).matching_pull_requests(repository, head, base)
    }
}

impl<T: GitHubWritePort + ?Sized> GitHubWritePort for Arc<T> {
    fn publish_branch(
        &self,
        command: &VerifiedPublishBranchCommand,
        candidate: &QuarantinedCandidate,
        credential: &ScopedCredential,
    ) -> Result<PublishedBranch, GitHubWriteError> {
        (**self).publish_branch(command, candidate, credential)
    }

    fn open_draft_pull_request(
        &self,
        command: &VerifiedOpenDraftPullRequestCommand,
        credential: &ScopedCredential,
    ) -> Result<OpenedPullRequest, GitHubWriteError> {
        (**self).open_draft_pull_request(command, credential)
    }
}

impl<T: CredentialProvider + ?Sized> CredentialProvider for Arc<T> {
    fn installation_credential(
        &self,
        authorization: &ExecutionAuthorizationV1,
        repository: &RepositoryResource,
        operation: GitHubOperation,
    ) -> Result<ScopedCredential, CredentialError> {
        (**self).installation_credential(authorization, repository, operation)
    }
}

impl<T: ExactActionAuthorizer + ?Sized> ExactActionAuthorizer for Arc<T> {
    fn authorize(
        &self,
        action: &ExactGitHubAction,
        now: u64,
    ) -> Result<ProofAuthorization, ProofError> {
        (**self).authorize(action, now)
    }
}

impl<T: ReceiptSink + ?Sized> ReceiptSink for Arc<T> {
    fn append(&self, receipt: &GitHubReceipt) -> Result<DigestHex, ReceiptError> {
        (**self).append(receipt)
    }
}

impl<T: Clock + ?Sized> Clock for Arc<T> {
    fn now(&self) -> Result<u64, ClockError> {
        (**self).now()
    }
}

/// Short-lived secret with intentionally redacted formatting and zeroing.
pub struct ScopedCredential {
    secret: Vec<u8>,
}

impl ScopedCredential {
    /// Wraps one non-empty short-lived secret.
    ///
    /// # Errors
    ///
    /// Rejects empty or excessively large credentials.
    pub fn from_secret(secret: impl Into<Vec<u8>>) -> Result<Self, CredentialError> {
        let secret = secret.into();
        if secret.is_empty() || secret.len() > 16 * 1024 {
            return Err(CredentialError::Invalid);
        }
        Ok(Self { secret })
    }

    pub(crate) fn expose(&self) -> Result<&str, CredentialError> {
        std::str::from_utf8(&self.secret).map_err(|_| CredentialError::Invalid)
    }
}

impl Drop for ScopedCredential {
    fn drop(&mut self) {
        self.secret.fill(0);
    }
}

impl fmt::Debug for ScopedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScopedCredential([REDACTED])")
    }
}

impl fmt::Display for ScopedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// Read-side GitHub failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GitHubReadError {
    /// GitHub proved the resource absent.
    #[error("GitHub resource not found")]
    NotFound,
    /// GitHub or transport unavailable.
    #[error("GitHub evidence unavailable")]
    Unavailable,
    /// Response is malformed or violates a hard limit.
    #[error("GitHub evidence malformed")]
    Malformed,
}

/// Write-side GitHub failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GitHubWriteError {
    /// GitHub explicitly rejected the operation before applying it.
    #[error("GitHub rejected the operation")]
    Rejected,
    /// Transport failed after submission and the result is ambiguous.
    #[error("GitHub operation result is ambiguous")]
    Ambiguous,
    /// Exact local postcondition validation failed.
    #[error("GitHub postcondition mismatch")]
    PostconditionMismatch,
    /// Local Git or API response malformed.
    #[error("GitHub write adapter failed")]
    Adapter,
}

/// Credential-broker failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CredentialError {
    /// Trusted credential configuration invalid.
    #[error("invalid GitHub App credential configuration")]
    Invalid,
    /// GitHub refused credential issuance.
    #[error("GitHub App credential rejected")]
    Rejected,
    /// Credential service unavailable.
    #[error("GitHub App credential unavailable")]
    Unavailable,
}

/// Auths exact-action proof failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProofError {
    /// Auths denied the exact action.
    #[error("Auths denied the exact GitHub action")]
    Denied,
    /// Auths lacked trustworthy context.
    #[error("Auths could not verify the exact GitHub action")]
    Indeterminate,
    /// Proof adapter failed.
    #[error("Auths proof adapter failed")]
    Adapter,
}

/// Receipt persistence/signing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("GitHub receipt sink unavailable")]
pub struct ReceiptError;

/// Trusted-clock failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("trusted clock unavailable")]
pub struct ClockError;
