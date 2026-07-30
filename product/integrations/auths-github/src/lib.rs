//! Exact, replay-safe Auths authorization for GitHub issue workflows.
//!
//! GitHub vocabulary, Git inspection, evidence acquisition, workflow claims,
//! credentials, receipts, and execution stay in this vertical package. The
//! Auths kernel remains unaware of Git and GitHub.

#![forbid(unsafe_code)]

pub mod adapters;
pub mod candidate;
pub mod canonical;
pub mod containment;
pub mod evidence;
pub mod executor;
pub mod policy;
pub mod ports;
pub mod profile;
pub mod receipts;
pub mod service;
#[cfg(any(test, feature = "fixture-support"))]
#[doc(hidden)]
pub mod test_support;
pub mod types;
pub mod workflow;

pub use candidate::{
    CandidateEvidence, CandidateSubmission, GitCandidateInspector, PathChange, QuarantinedCandidate,
};
pub use containment::{Decision, DecisionClass, DecisionCode, EvaluationContext, evaluate};
pub use evidence::{
    GitHubEvidence, IssueEvidence, PullRequestEvidence, RefEvidence, RepositoryEvidence,
};
pub use executor::{VerifiedOpenDraftPullRequest, VerifiedPublishBranch};
pub use profile::{GitHubCommand, GitHubIssueProfile};
pub use receipts::{
    GitHubDecisionReceipt, GitHubExecutionReceipt, GitHubReceipt, OpenedPullRequest,
    PublishedBranch, SignedGitHubReceipt,
};
pub use service::{
    ExecuteWorkflowRequest, GitHubIssueWorkflowService, ServiceDependencies, ServiceError,
    WorkflowOutcome, derive_open_pull_request_action, derive_publish_branch_action,
    deterministic_pull_request_body,
};
pub use types::{
    CandidatePolicy, DigestHex, ExactGitHubAction, ExecutorAudience, GitHubOperation, GitOid,
    IssueResource, NodeId, ObjectFormat, OpenDraftPullRequestAction, PublicationPolicy,
    PublishBranchAction, RefName, RepositoryName, RepositoryOwner, RepositoryResource,
    VerifierConfiguration, VerifierConfigurationInput, WorkflowGrant, WorkflowGrantInput,
    WorkflowId,
};
