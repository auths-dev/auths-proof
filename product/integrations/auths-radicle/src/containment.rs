//! Pure Radicle-specific containment checks.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use crate::{
    canonical::sha256,
    types::{
        CandidateFacts, CandidateSubmission, DigestHex, IssueAddressGrantV1, OpenPatchActionV1,
        RadicleEvidenceV1, VerifierConfiguration,
    },
};

/// High-level result class exposed to the product and demo.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionClass {
    /// Every exact condition is satisfied.
    Authorized,
    /// Complete evidence proves a policy mismatch.
    Denied,
    /// Safe authorization is impossible because evidence is incomplete or stale.
    Indeterminate,
}

/// Stable, closed decision code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionCode {
    /// All product-specific constraints matched.
    Authorized,
    /// A configuration object is invalid.
    InvalidConfiguration,
    /// Required and executed verifier configurations differ.
    VerifierConfigurationMismatch,
    /// The exact action does not commit to the required configuration.
    ActionConfigurationMismatch,
    /// The workflow grant commitment differs.
    WorkflowGrantMismatch,
    /// Workflow, repository, issue, or base identity differs.
    AddressMismatch,
    /// The evidence history cannot prove current state.
    EvidenceHistoryIncomplete,
    /// Too few configured peers synchronized successfully.
    EvidenceSynchronizationIncomplete,
    /// The evidence observation is stale or from the future.
    EvidenceStale,
    /// The evidence snapshot commitment differs.
    EvidenceSnapshotMismatch,
    /// The Radicle issue is closed.
    IssueClosed,
    /// The configured executor signer differs.
    SignerMismatch,
    /// The configured signer is a repository delegate.
    SignerIsDelegate,
    /// The candidate commitments differ.
    CandidateMismatch,
    /// Patch title, body, or issue trailer differs.
    PatchMetadataMismatch,
    /// A changed path is outside the grant.
    PathOutsideGrant,
    /// A changed path is explicitly denied.
    PathDenied,
    /// A workflow file, byte, or commit limit is exceeded.
    WorkflowLimitExceeded,
    /// The human workflow grant has expired.
    GrantExpired,
}

/// One pure product-specific decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Decision {
    /// Broad result class.
    pub class: DecisionClass,
    /// Stable machine-readable reason.
    pub code: DecisionCode,
    /// Short non-sensitive explanation.
    pub detail: String,
}

impl Decision {
    fn authorized() -> Self {
        Self {
            class: DecisionClass::Authorized,
            code: DecisionCode::Authorized,
            detail: "exact Radicle action is contained by the workflow grant".into(),
        }
    }

    fn denied(code: DecisionCode, detail: &'static str) -> Self {
        Self {
            class: DecisionClass::Denied,
            code,
            detail: detail.into(),
        }
    }

    fn indeterminate(code: DecisionCode, detail: &'static str) -> Self {
        Self {
            class: DecisionClass::Indeterminate,
            code,
            detail: detail.into(),
        }
    }
}

/// Borrowed inputs to the pure Radicle containment decision.
pub struct EvaluationContext<'a> {
    /// Human-issued vertical workflow constraints.
    pub grant: &'a IssueAddressGrantV1,
    /// Exact profile action that Auths will verify.
    pub action: &'a OpenPatchActionV1,
    /// Hostile request metadata whose commitments are in the exact action.
    pub submission: &'a CandidateSubmission,
    /// Facts produced by the trusted Git inspector.
    pub candidate: &'a CandidateFacts,
    /// Synchronized Radicle state.
    pub evidence: &'a RadicleEvidenceV1,
    /// Configuration selected by the caller/grant.
    pub required_configuration: &'a VerifierConfiguration,
    /// Configuration actually loaded by the executor.
    pub executed_configuration: &'a VerifierConfiguration,
    /// Exact Auths verifier audience used for this request.
    pub request_audience: &'a str,
    /// Trusted Unix time.
    pub now: u64,
}

/// Evaluates all Radicle-specific containment without side effects.
///
/// Authorization is fail-closed: a factual mismatch is denied, while stale or
/// incomplete distributed state is indeterminate. Neither result may reach a
/// signer or the Radicle write boundary.
#[must_use]
pub fn evaluate(context: &EvaluationContext<'_>) -> Decision {
    for check in [
        check_configuration,
        check_address,
        check_evidence,
        check_candidate,
        check_paths_and_limits,
    ] {
        if let Err(decision) = check(context) {
            return decision;
        }
    }
    Decision::authorized()
}

fn check_configuration(context: &EvaluationContext<'_>) -> Result<(), Decision> {
    if context.grant.validate().is_err()
        || context.required_configuration.validate().is_err()
        || context.executed_configuration.validate().is_err()
    {
        return Err(Decision::denied(
            DecisionCode::InvalidConfiguration,
            "workflow or verifier configuration is invalid",
        ));
    }
    if context.required_configuration != context.grant.required_configuration()
        || context.required_configuration != context.executed_configuration
    {
        return Err(Decision::denied(
            DecisionCode::VerifierConfigurationMismatch,
            "required and executed verifier configurations differ",
        ));
    }
    let Ok(required_configuration_digest) = context.required_configuration.digest() else {
        return Err(Decision::denied(
            DecisionCode::InvalidConfiguration,
            "required configuration could not be committed",
        ));
    };
    if !digest_eq(
        context.action.required_configuration_digest(),
        &required_configuration_digest,
    ) {
        return Err(Decision::denied(
            DecisionCode::ActionConfigurationMismatch,
            "exact action does not commit to the required verifier configuration",
        ));
    }
    let Ok(grant_digest) = context.grant.digest() else {
        return Err(Decision::denied(
            DecisionCode::WorkflowGrantMismatch,
            "workflow grant could not be committed",
        ));
    };
    if !digest_eq(context.action.workflow_grant_digest(), &grant_digest) {
        return Err(Decision::denied(
            DecisionCode::WorkflowGrantMismatch,
            "exact action commits to a different workflow grant",
        ));
    }
    Ok(())
}

fn check_address(context: &EvaluationContext<'_>) -> Result<(), Decision> {
    if context.action.workflow_id() != context.grant.workflow_id()
        || context.action.rid() != context.grant.rid()
        || context.action.issue_id() != context.grant.issue_id()
        || context.action.repository_identity_revision()
            != context.grant.repository_identity_revision()
        || context.action.canonical_base_oid() != context.grant.canonical_base_oid()
        || context.action.executor_audience() != context.grant.executor_audience()
        || context.request_audience != context.grant.executor_audience().as_str()
    {
        return Err(Decision::denied(
            DecisionCode::AddressMismatch,
            "action does not address the exact granted Radicle state",
        ));
    }
    if context.now > context.grant.expires_at() {
        return Err(Decision::denied(
            DecisionCode::GrantExpired,
            "human workflow grant has expired",
        ));
    }
    Ok(())
}

fn check_evidence(context: &EvaluationContext<'_>) -> Result<(), Decision> {
    if !context.evidence.issue_history_complete() {
        return Err(Decision::indeterminate(
            DecisionCode::EvidenceHistoryIncomplete,
            "local issue history is incomplete",
        ));
    }
    if context.evidence.synchronized_peers().iter().any(|peer| {
        !context
            .executed_configuration
            .observation_peers()
            .contains(peer)
    }) || context.evidence.synchronized_peers().len()
        < usize::from(context.executed_configuration.minimum_successful_peers())
    {
        return Err(Decision::indeterminate(
            DecisionCode::EvidenceSynchronizationIncomplete,
            "configured synchronization quorum was not observed",
        ));
    }
    let Some(evidence_age) = context.now.checked_sub(context.evidence.synchronized_at()) else {
        return Err(Decision::indeterminate(
            DecisionCode::EvidenceStale,
            "evidence timestamp is ahead of the trusted clock",
        ));
    };
    if evidence_age
        > context
            .executed_configuration
            .maximum_evidence_age_seconds()
    {
        return Err(Decision::indeterminate(
            DecisionCode::EvidenceStale,
            "evidence exceeds the configured maximum age",
        ));
    }
    if context.evidence.adapter_version() != context.executed_configuration.radicle_adapter() {
        return Err(Decision::denied(
            DecisionCode::VerifierConfigurationMismatch,
            "evidence adapter differs from the executed verifier configuration",
        ));
    }
    let Ok(evidence_digest) = context.evidence.digest() else {
        return Err(Decision::denied(
            DecisionCode::EvidenceSnapshotMismatch,
            "evidence snapshot could not be committed",
        ));
    };
    if !digest_eq(context.action.evidence_snapshot_digest(), &evidence_digest) {
        return Err(Decision::denied(
            DecisionCode::EvidenceSnapshotMismatch,
            "exact action commits to a different evidence snapshot",
        ));
    }
    if context.evidence.rid() != context.grant.rid()
        || context.evidence.issue_id() != context.grant.issue_id()
        || context.evidence.repository_identity_revision()
            != context.grant.repository_identity_revision()
        || context.evidence.canonical_head_oid() != context.grant.canonical_base_oid()
    {
        return Err(Decision::denied(
            DecisionCode::AddressMismatch,
            "evidence does not describe the exact granted Radicle state",
        ));
    }
    if !context.evidence.issue_open() {
        return Err(Decision::denied(
            DecisionCode::IssueClosed,
            "Radicle issue is closed",
        ));
    }
    if context.evidence.executor_signer_did() != context.grant.expected_signer_did()
        || context.action.signer_did() != context.grant.expected_signer_did()
    {
        return Err(Decision::denied(
            DecisionCode::SignerMismatch,
            "configured, observed, and authorized signer identities differ",
        ));
    }
    if context
        .evidence
        .delegates()
        .contains(context.grant.expected_signer_did())
    {
        return Err(Decision::denied(
            DecisionCode::SignerIsDelegate,
            "executor signer must not be a repository delegate",
        ));
    }
    Ok(())
}

fn check_candidate(context: &EvaluationContext<'_>) -> Result<(), Decision> {
    if &context.submission.base_oid != context.candidate.base_oid()
        || &context.submission.candidate_oid != context.candidate.candidate_oid()
        || context.candidate.base_oid() != context.grant.canonical_base_oid()
        || context.action.candidate_oid() != context.candidate.candidate_oid()
        || !digest_eq(
            context.action.candidate_bundle_digest(),
            context.candidate.bundle_digest(),
        )
        || !digest_eq(
            context.action.candidate_commit_set_digest(),
            context.candidate.commit_set_digest(),
        )
        || !digest_eq(
            context.action.candidate_tree_delta_digest(),
            context.candidate.tree_delta_digest(),
        )
    {
        return Err(Decision::denied(
            DecisionCode::CandidateMismatch,
            "candidate identity or content commitment differs",
        ));
    }
    let issue_reference = format!(
        "Radicle-Issue: {}\nAuths-Workflow: {}",
        context.grant.issue_id(),
        context.grant.workflow_id()
    );
    if invalid_patch_metadata(context.submission)
        || !digest_eq(
            context.action.patch_title_digest(),
            &sha256(context.submission.patch_title.as_bytes()),
        )
        || !digest_eq(
            context.action.patch_body_digest(),
            &sha256(context.submission.patch_body.as_bytes()),
        )
        || !digest_eq(
            context.action.issue_reference_digest(),
            &sha256(issue_reference.as_bytes()),
        )
    {
        return Err(Decision::denied(
            DecisionCode::PatchMetadataMismatch,
            "patch title, body, or deterministic issue reference differs",
        ));
    }
    Ok(())
}

fn check_paths_and_limits(context: &EvaluationContext<'_>) -> Result<(), Decision> {
    if context.candidate.changes().len()
        > usize::try_from(context.grant.maximum_changed_files()).unwrap_or(usize::MAX)
        || context.candidate.commit_oids().len()
            > usize::try_from(context.grant.maximum_commits()).unwrap_or(usize::MAX)
        || context
            .candidate
            .changed_bytes()
            .is_none_or(|bytes| bytes > context.grant.maximum_changed_bytes())
    {
        return Err(Decision::denied(
            DecisionCode::WorkflowLimitExceeded,
            "candidate exceeds a workflow file, byte, or commit limit",
        ));
    }
    for change in context.candidate.changes() {
        if context
            .grant
            .denied_path_prefixes()
            .iter()
            .any(|prefix| path_matches(change.path(), prefix))
        {
            return Err(Decision::denied(
                DecisionCode::PathDenied,
                "candidate changes an explicitly denied path",
            ));
        }
        if !context
            .grant
            .allowed_path_prefixes()
            .iter()
            .any(|prefix| path_matches(change.path(), prefix))
        {
            return Err(Decision::denied(
                DecisionCode::PathOutsideGrant,
                "candidate changes a path outside the workflow grant",
            ));
        }
    }
    Ok(())
}

fn invalid_patch_metadata(submission: &CandidateSubmission) -> bool {
    submission.patch_title.is_empty()
        || submission.patch_title.len() > 256
        || submission.patch_title.contains(['\r', '\n', '\0'])
        || submission.patch_body.len() > 16 * 1024
        || submission.patch_body.contains(['\r', '\n', '\0'])
}

fn path_matches(path: &str, configured_prefix: &str) -> bool {
    let prefix = configured_prefix
        .strip_suffix('/')
        .unwrap_or(configured_prefix);
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn digest_eq(left: &DigestHex, right: &DigestHex) -> bool {
    match (left.to_bytes(), right.to_bytes()) {
        (Ok(left), Ok(right)) => bool::from(left.ct_eq(&right)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{NOW, action, candidate, configuration, evidence, grant, submission};

    #[test]
    fn exact_vertical_constraints_authorize() {
        let required = configuration(30);
        let grant = grant(required.clone());
        let submission = submission();
        let candidate = candidate(&submission);
        let evidence = evidence(&grant, NOW);
        let action = action(&grant, &required, &submission, &candidate, &evidence);

        let decision = evaluate(&EvaluationContext {
            grant: &grant,
            action: &action,
            submission: &submission,
            candidate: &candidate,
            evidence: &evidence,
            required_configuration: &required,
            executed_configuration: &required,
            request_audience: required.executor_audience().as_str(),
            now: NOW,
        });

        assert_eq!(decision.class, DecisionClass::Authorized);
        assert_eq!(decision.code, DecisionCode::Authorized);
    }

    #[test]
    fn required_and_executed_configuration_drift_is_a_hard_denial() {
        let required = configuration(30);
        let executed = configuration(60);
        let grant = grant(required.clone());
        let submission = submission();
        let candidate = candidate(&submission);
        let evidence = evidence(&grant, NOW);
        let action = action(&grant, &required, &submission, &candidate, &evidence);

        let decision = evaluate(&EvaluationContext {
            grant: &grant,
            action: &action,
            submission: &submission,
            candidate: &candidate,
            evidence: &evidence,
            required_configuration: &required,
            executed_configuration: &executed,
            request_audience: required.executor_audience().as_str(),
            now: NOW,
        });

        assert_eq!(decision.class, DecisionClass::Denied);
        assert_eq!(decision.code, DecisionCode::VerifierConfigurationMismatch);
    }

    #[test]
    fn stale_distributed_evidence_is_indeterminate_not_denied() {
        let required = configuration(30);
        let grant = grant(required.clone());
        let submission = submission();
        let candidate = candidate(&submission);
        let evidence = evidence(&grant, NOW - 31);
        let action = action(&grant, &required, &submission, &candidate, &evidence);

        let decision = evaluate(&EvaluationContext {
            grant: &grant,
            action: &action,
            submission: &submission,
            candidate: &candidate,
            evidence: &evidence,
            required_configuration: &required,
            executed_configuration: &required,
            request_audience: required.executor_audience().as_str(),
            now: NOW,
        });

        assert_eq!(decision.class, DecisionClass::Indeterminate);
        assert_eq!(decision.code, DecisionCode::EvidenceStale);
    }
}
