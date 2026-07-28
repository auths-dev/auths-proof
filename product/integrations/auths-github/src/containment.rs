//! Pure GitHub issue-workflow containment.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use crate::{
    candidate::CandidateEvidence,
    evidence::GitHubEvidence,
    types::{
        ExactGitHubAction, OpenDraftPullRequestAction, PublishBranchAction, VerifierConfiguration,
        WorkflowGrant,
    },
};

/// Broad result class exposed to APIs and receipts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionClass {
    /// Every required fact and proof matches.
    Authorized,
    /// Complete evidence proves a mismatch.
    Denied,
    /// Trustworthy evidence is unavailable, stale, or ambiguous.
    Indeterminate,
}

/// Stable profile outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionCode {
    /// Every exact condition matched.
    Authorized,
    /// Auths workflow proof is invalid.
    WorkflowProofInvalid,
    /// Workflow expired.
    WorkflowExpired,
    /// Workflow was cancelled.
    WorkflowCancelled,
    /// Request audience differs.
    ExecutorAudienceMismatch,
    /// Immutable repository differs.
    RepositoryMismatch,
    /// Current owner/name differs.
    RepositoryRenamedOrTransferred,
    /// Issue identity differs.
    IssueMismatch,
    /// Issue is no longer open.
    IssueNotOpen,
    /// Base ref advanced or differs.
    BaseRevisionMismatch,
    /// Derived target already exists.
    BranchAlreadyExists,
    /// Matching PR already exists.
    PullRequestAlreadyExists,
    /// Candidate bundle is malformed.
    CandidateBundleMalformed,
    /// Candidate exceeded a hard or grant-selected limit.
    CandidateLimitExceeded,
    /// Candidate does not descend from the exact base.
    CandidateNotDescendant,
    /// Candidate includes a merge commit.
    MergeCommitDenied,
    /// Candidate includes an unsupported Git object or change.
    UnsupportedGitObject,
    /// Path is outside the allow set.
    PathNotAllowed,
    /// Path is explicitly denied.
    PathExplicitlyDenied,
    /// File mode is denied.
    FileModeDenied,
    /// Repository automation policy differs.
    RepositoryAutomationPolicyMismatch,
    /// Branch budget is exhausted.
    BranchBudgetExhausted,
    /// Pull-request budget is exhausted.
    PullRequestBudgetExhausted,
    /// Exact action was already completed.
    ActionReplay,
    /// Required evidence is missing.
    EvidenceMissing,
    /// Evidence is stale or from the future.
    EvidenceStale,
    /// Required and executed verifier configurations differ.
    VerifierConfigurationMismatch,
    /// Exact action differs from inspected facts or evidence.
    ExactActionMismatch,
    /// GitHub rejected an authorized operation.
    GitHubRejected,
    /// Result cannot be proven.
    ExecutionAmbiguous,
    /// Operator reconciliation is required.
    ReconciliationRequired,
}

impl DecisionCode {
    /// Stable kebab-case API code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::WorkflowProofInvalid => "workflow-proof-invalid",
            Self::WorkflowExpired => "workflow-expired",
            Self::WorkflowCancelled => "workflow-cancelled",
            Self::ExecutorAudienceMismatch => "executor-audience-mismatch",
            Self::RepositoryMismatch => "repository-mismatch",
            Self::RepositoryRenamedOrTransferred => "repository-renamed-or-transferred",
            Self::IssueMismatch => "issue-mismatch",
            Self::IssueNotOpen => "issue-not-open",
            Self::BaseRevisionMismatch => "base-revision-mismatch",
            Self::BranchAlreadyExists => "branch-already-exists",
            Self::PullRequestAlreadyExists => "pull-request-already-exists",
            Self::CandidateBundleMalformed => "candidate-bundle-malformed",
            Self::CandidateLimitExceeded => "candidate-limit-exceeded",
            Self::CandidateNotDescendant => "candidate-not-descendant",
            Self::MergeCommitDenied => "merge-commit-denied",
            Self::UnsupportedGitObject => "unsupported-git-object",
            Self::PathNotAllowed => "path-not-allowed",
            Self::PathExplicitlyDenied => "path-explicitly-denied",
            Self::FileModeDenied => "file-mode-denied",
            Self::RepositoryAutomationPolicyMismatch => "repository-automation-policy-mismatch",
            Self::BranchBudgetExhausted => "branch-budget-exhausted",
            Self::PullRequestBudgetExhausted => "pull-request-budget-exhausted",
            Self::ActionReplay => "action-replay",
            Self::EvidenceMissing => "evidence-missing",
            Self::EvidenceStale => "evidence-stale",
            Self::VerifierConfigurationMismatch => "verifier-configuration-mismatch",
            Self::ExactActionMismatch => "exact-action-mismatch",
            Self::GitHubRejected => "github-rejected",
            Self::ExecutionAmbiguous => "execution-ambiguous",
            Self::ReconciliationRequired => "reconciliation-required",
        }
    }
}

/// Pure product decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    /// Broad class.
    pub class: DecisionClass,
    /// Stable code.
    pub code: DecisionCode,
    /// Short, non-sensitive explanation.
    pub detail: String,
}

impl Decision {
    /// Authorized result.
    #[must_use]
    pub fn authorized() -> Self {
        Self {
            class: DecisionClass::Authorized,
            code: DecisionCode::Authorized,
            detail: "the exact GitHub action matches the workflow grant and fresh evidence".into(),
        }
    }

    /// Denied result.
    #[must_use]
    pub fn denied(code: DecisionCode, detail: impl Into<String>) -> Self {
        Self {
            class: DecisionClass::Denied,
            code,
            detail: detail.into(),
        }
    }

    /// Indeterminate result.
    #[must_use]
    pub fn indeterminate(code: DecisionCode, detail: impl Into<String>) -> Self {
        Self {
            class: DecisionClass::Indeterminate,
            code,
            detail: detail.into(),
        }
    }
}

/// Borrowed inputs to the pure containment decision.
pub struct EvaluationContext<'a> {
    /// Human-issued workflow grant.
    pub grant: &'a WorkflowGrant,
    /// Exact action that Auths will verify.
    pub action: &'a ExactGitHubAction,
    /// Trusted candidate facts.
    pub candidate: &'a CandidateEvidence,
    /// Fresh GitHub evidence.
    pub evidence: &'a GitHubEvidence,
    /// Configuration demanded by the grant/caller.
    pub required_configuration: &'a VerifierConfiguration,
    /// Configuration actually loaded by the executor.
    pub executed_configuration: &'a VerifierConfiguration,
    /// Exact runtime audience.
    pub request_audience: &'a str,
    /// Trusted Unix time.
    pub now: u64,
}

/// Evaluates one exact action without side effects.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "the fail-closed decision order remains linear for security review"
)]
pub fn evaluate(context: &EvaluationContext<'_>) -> Decision {
    if context.grant.validate().is_err()
        || context.required_configuration.validate().is_err()
        || context.executed_configuration.validate().is_err()
    {
        return Decision::denied(
            DecisionCode::VerifierConfigurationMismatch,
            "workflow or verifier configuration is invalid",
        );
    }
    if context.required_configuration != context.grant.required_configuration()
        || context.required_configuration != context.executed_configuration
    {
        return Decision::denied(
            DecisionCode::VerifierConfigurationMismatch,
            "required and executed verifier configurations differ",
        );
    }
    if context.request_audience != context.grant.executor_audience().as_str()
        || context.action.executor_audience() != context.grant.executor_audience()
    {
        return Decision::denied(
            DecisionCode::ExecutorAudienceMismatch,
            "the request does not address the configured executor",
        );
    }
    if context.now > context.grant.expires_at() {
        return Decision::denied(DecisionCode::WorkflowExpired, "the workflow grant expired");
    }
    let Some(age) = context.now.checked_sub(context.evidence.acquired_at) else {
        return Decision::indeterminate(
            DecisionCode::EvidenceStale,
            "GitHub evidence is ahead of the trusted clock",
        );
    };
    if age
        > context
            .executed_configuration
            .maximum_evidence_age_seconds()
    {
        return Decision::indeterminate(
            DecisionCode::EvidenceStale,
            "GitHub evidence exceeds the configured maximum age",
        );
    }
    if context.evidence.repository.repository_id != context.grant.repository().repository_id()
        || context.evidence.repository.repository_node_id
            != *context.grant.repository().repository_node_id()
    {
        return Decision::denied(
            DecisionCode::RepositoryMismatch,
            "fresh evidence identifies a different repository",
        );
    }
    if context.evidence.repository.owner != context.grant.repository().owner().as_str()
        || context.evidence.repository.name != context.grant.repository().name().as_str()
    {
        return Decision::denied(
            DecisionCode::RepositoryRenamedOrTransferred,
            "the repository owner or name changed after grant issuance",
        );
    }
    if context.evidence.issue.repository_id != context.grant.issue().repository_id()
        || context.evidence.issue.issue_node_id != *context.grant.issue().issue_node_id()
        || context.evidence.issue.issue_number != context.grant.issue().issue_number()
    {
        return Decision::denied(
            DecisionCode::IssueMismatch,
            "fresh evidence identifies a different issue",
        );
    }
    if !context.evidence.issue.open {
        return Decision::denied(
            DecisionCode::IssueNotOpen,
            "the bound GitHub issue is not open",
        );
    }
    if context.evidence.base.ref_name != *context.grant.base_ref()
        || context.evidence.base.revision.as_ref() != Some(context.grant.base_revision())
    {
        return Decision::denied(
            DecisionCode::BaseRevisionMismatch,
            "the bound base ref no longer points to the granted revision",
        );
    }
    if !digest_eq(
        &context.evidence.repository_policy_digest,
        context
            .executed_configuration
            .repository_automation_policy_digest(),
    ) {
        return Decision::indeterminate(
            DecisionCode::RepositoryAutomationPolicyMismatch,
            "the approved repository automation policy commitment changed",
        );
    }
    if context.candidate != &context.evidence.candidate
        || context.candidate.base_revision() != context.grant.base_revision()
        || context.action.repository() != context.grant.repository()
        || context.action.issue() != context.grant.issue()
        || context.action.workflow_id() != context.grant.workflow_id()
    {
        return Decision::denied(
            DecisionCode::ExactActionMismatch,
            "the action does not commit to the inspected workflow state",
        );
    }
    let Ok(evidence_digest) = context.evidence.digest() else {
        return Decision::indeterminate(
            DecisionCode::EvidenceMissing,
            "GitHub evidence could not be committed",
        );
    };
    let Ok(configuration_digest) = context.required_configuration.digest() else {
        return Decision::denied(
            DecisionCode::VerifierConfigurationMismatch,
            "required configuration could not be committed",
        );
    };
    let matches_action = match context.action {
        ExactGitHubAction::PublishBranch(action) => {
            check_branch(action, context, &evidence_digest, &configuration_digest)
        }
        ExactGitHubAction::OpenDraftPullRequest(action) => {
            check_pull_request(action, context, &evidence_digest, &configuration_digest)
        }
    };
    matches_action.unwrap_or_else(|decision| decision)
}

fn check_branch(
    action: &PublishBranchAction,
    context: &EvaluationContext<'_>,
    evidence_digest: &crate::types::DigestHex,
    configuration_digest: &crate::types::DigestHex,
) -> Result<Decision, Decision> {
    if context.evidence.target.revision.is_some() {
        return Err(Decision::denied(
            DecisionCode::BranchAlreadyExists,
            "the executor-derived proposal branch already exists",
        ));
    }
    let target = context
        .grant
        .target_ref()
        .map_err(|_| Decision::denied(DecisionCode::ExactActionMismatch, "invalid target ref"))?;
    let grant_digest = context.grant.digest().map_err(|_| {
        Decision::denied(
            DecisionCode::ExactActionMismatch,
            "workflow grant could not be committed",
        )
    })?;
    if action.workflow_grant_digest != grant_digest
        || action.base_ref != *context.grant.base_ref()
        || action.base_revision != *context.grant.base_revision()
        || action.target_ref != target
        || action.candidate_revision != *context.candidate.candidate_revision()
        || action.candidate_tree != *context.candidate.candidate_tree()
        || action.candidate_bundle_digest != *context.candidate.bundle_digest()
        || action.change_set_digest != *context.candidate.change_set_digest()
        || !digest_eq(&action.evidence_digest, evidence_digest)
        || !digest_eq(&action.verifier_configuration_digest, configuration_digest)
        || action.expires_at != context.grant.expires_at()
    {
        return Err(Decision::denied(
            DecisionCode::ExactActionMismatch,
            "branch action differs from inspected facts or fresh evidence",
        ));
    }
    Ok(Decision::authorized())
}

fn check_pull_request(
    action: &OpenDraftPullRequestAction,
    context: &EvaluationContext<'_>,
    evidence_digest: &crate::types::DigestHex,
    configuration_digest: &crate::types::DigestHex,
) -> Result<Decision, Decision> {
    if !context.evidence.matching_pull_requests.is_empty() {
        return Err(Decision::denied(
            DecisionCode::PullRequestAlreadyExists,
            "a matching pull request already exists",
        ));
    }
    let target = context
        .grant
        .target_ref()
        .map_err(|_| Decision::denied(DecisionCode::ExactActionMismatch, "invalid target ref"))?;
    let grant_digest = context.grant.digest().map_err(|_| {
        Decision::denied(
            DecisionCode::ExactActionMismatch,
            "workflow grant could not be committed",
        )
    })?;
    if action.workflow_grant_digest != grant_digest
        || action.base_ref != *context.grant.base_ref()
        || action.base_revision != *context.grant.base_revision()
        || action.head_ref != target
        || action.head_revision != *context.candidate.candidate_revision()
        || context.evidence.target.revision.as_ref() != Some(&action.head_revision)
        || action.exact_title != context.grant.pull_request_title()
        || !digest_eq(&action.evidence_digest, evidence_digest)
        || !digest_eq(&action.verifier_configuration_digest, configuration_digest)
        || action.expires_at != context.grant.expires_at()
    {
        return Err(Decision::denied(
            DecisionCode::ExactActionMismatch,
            "pull-request action differs from published branch or fresh evidence",
        ));
    }
    Ok(Decision::authorized())
}

fn digest_eq(left: &crate::types::DigestHex, right: &crate::types::DigestHex) -> bool {
    left.as_str()
        .as_bytes()
        .ct_eq(right.as_str().as_bytes())
        .into()
}

#[cfg(test)]
mod tests {
    use super::DecisionCode;

    #[test]
    fn outcome_codes_are_stable() {
        assert_eq!(
            DecisionCode::VerifierConfigurationMismatch.as_str(),
            "verifier-configuration-mismatch"
        );
        assert_eq!(
            DecisionCode::PullRequestBudgetExhausted.as_str(),
            "pull-request-budget-exhausted"
        );
    }
}
