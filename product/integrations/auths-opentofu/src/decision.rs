//! Pure saved-plan containment and freshness decision.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use crate::{
    action::{OpenTofuSavedPlanApplyV1, PermittedChangeSummaryV1},
    plan_projection::SavedPlanProjectionV1,
    types::{DigestHex, OpenTofuStateEvidenceV1, OpenTofuVerifierConfigurationV1, ResourceAction},
};

/// High-level product verdict.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionClass {
    Authorized,
    Denied,
    Indeterminate,
}

/// Stable OpenTofu-profile result code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionCode {
    Authorized,
    MalformedSourceBundle,
    UnsupportedProfile,
    ForbiddenOpenTofuFeature,
    DependencyNotPinned,
    PlanFailed,
    PlanArtifactMismatch,
    PlanProjectionMismatch,
    VerifierConfigurationMismatch,
    ActionConfigurationMismatch,
    EvidenceStale,
    BackendIdentityMismatch,
    WorkspaceMismatch,
    StateLineageMismatch,
    StateSerialMismatch,
    ChangeOutsideProfile,
    DestroyDenied,
    ReplacementDenied,
    AudienceMismatch,
    AuthsProofDenied,
    AuthsProofIndeterminate,
}

/// Side-effect-free decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Decision {
    pub class: DecisionClass,
    pub code: DecisionCode,
    pub stage: String,
    pub detail: String,
}

impl Decision {
    fn authorized() -> Self {
        Self {
            class: DecisionClass::Authorized,
            code: DecisionCode::Authorized,
            stage: "auths-kernel".into(),
            detail: "the exact saved plan matches fresh state evidence and verifier policy".into(),
        }
    }

    fn denied(code: DecisionCode, stage: &'static str, detail: &'static str) -> Self {
        Self {
            class: DecisionClass::Denied,
            code,
            stage: stage.into(),
            detail: detail.into(),
        }
    }

    pub(crate) fn proof_denied() -> Self {
        Self::denied(
            DecisionCode::AuthsProofDenied,
            "auths-kernel",
            "the Auths proof did not authorize the exact saved-plan action",
        )
    }

    pub(crate) fn proof_indeterminate() -> Self {
        Self {
            class: DecisionClass::Indeterminate,
            code: DecisionCode::AuthsProofIndeterminate,
            stage: "auths-kernel".into(),
            detail: "the Auths proof could not be verified conclusively".into(),
        }
    }
}

/// Borrowed pure-decision inputs.
pub struct EvaluationContext<'a> {
    pub action: &'a OpenTofuSavedPlanApplyV1,
    pub projection: &'a SavedPlanProjectionV1,
    pub evidence: &'a OpenTofuStateEvidenceV1,
    pub required_configuration: &'a OpenTofuVerifierConfigurationV1,
    pub executed_configuration: &'a OpenTofuVerifierConfigurationV1,
    pub request_audience: &'a str,
    pub now: u64,
}

/// Evaluates all pre-claim facts without resolving artifacts or credentials.
#[must_use]
pub fn evaluate(context: &EvaluationContext<'_>) -> Decision {
    for check in [
        check_configuration,
        check_time,
        check_identity,
        check_evidence,
        check_projection,
    ] {
        if let Err(decision) = check(context) {
            return decision;
        }
    }
    Decision::authorized()
}

fn check_configuration(context: &EvaluationContext<'_>) -> Result<(), Decision> {
    if context.action.validate().is_err()
        || context
            .projection
            .validate(context.executed_configuration)
            .is_err()
        || context.evidence.validate().is_err()
        || context.required_configuration.validate().is_err()
        || context.executed_configuration.validate().is_err()
    {
        return Err(Decision::denied(
            DecisionCode::UnsupportedProfile,
            "decode",
            "the action, plan projection, evidence, or configuration is invalid",
        ));
    }
    let Ok(required) = context.required_configuration.digest() else {
        return Err(Decision::denied(
            DecisionCode::VerifierConfigurationMismatch,
            "configuration",
            "the required configuration is not canonical",
        ));
    };
    let Ok(executed) = context.executed_configuration.digest() else {
        return Err(Decision::denied(
            DecisionCode::VerifierConfigurationMismatch,
            "configuration",
            "the executed configuration is not canonical",
        ));
    };
    if !digest_eq(&required, &executed) {
        return Err(Decision::denied(
            DecisionCode::VerifierConfigurationMismatch,
            "configuration",
            "required and executed verifier configurations differ",
        ));
    }
    if !digest_eq(context.action.required_configuration_digest(), &required) {
        return Err(Decision::denied(
            DecisionCode::ActionConfigurationMismatch,
            "configuration",
            "the action commits to a different verifier configuration",
        ));
    }
    if context.request_audience != context.action.executor_audience()
        || context.request_audience != context.executed_configuration.executor_audience()
    {
        return Err(Decision::denied(
            DecisionCode::AudienceMismatch,
            "audience",
            "the request addresses a different protected executor",
        ));
    }
    Ok(())
}

fn check_time(context: &EvaluationContext<'_>) -> Result<(), Decision> {
    if context.now > context.action.expires_at()
        || context
            .action
            .expires_at()
            .saturating_sub(context.action.planned_at())
            > context
                .executed_configuration
                .maximum_authorization_lifetime_seconds()
        || context.now.saturating_sub(context.action.planned_at())
            > context.executed_configuration.maximum_plan_age_seconds()
        || context.action.planned_at() != context.evidence.observed_at
    {
        return Err(Decision::denied(
            DecisionCode::EvidenceStale,
            "freshness",
            "the plan or authorization lifetime is outside configured bounds",
        ));
    }
    Ok(())
}

fn check_identity(context: &EvaluationContext<'_>) -> Result<(), Decision> {
    if !context
        .executed_configuration
        .allowed_opentofu_versions()
        .iter()
        .any(|version| version == context.action.opentofu_version())
    {
        return Err(Decision::denied(
            DecisionCode::UnsupportedProfile,
            "tool",
            "the plan was created by an unapproved OpenTofu version",
        ));
    }
    if !context
        .executed_configuration
        .allowed_backend_identities()
        .iter()
        .any(|identity| identity == context.action.backend_identity())
        || context.evidence.backend_identity != context.action.backend_identity()
    {
        return Err(Decision::denied(
            DecisionCode::BackendIdentityMismatch,
            "backend",
            "the configured backend differs from the planned backend",
        ));
    }
    if !context
        .executed_configuration
        .allowed_workspaces()
        .iter()
        .any(|workspace| workspace == context.action.workspace())
        || context.evidence.workspace != context.action.workspace()
    {
        return Err(Decision::denied(
            DecisionCode::WorkspaceMismatch,
            "workspace",
            "the selected workspace differs from the authorized workspace",
        ));
    }
    Ok(())
}

fn check_evidence(context: &EvaluationContext<'_>) -> Result<(), Decision> {
    if context.evidence.lock_held {
        return Err(Decision::denied(
            DecisionCode::EvidenceStale,
            "state-lock",
            "the backend state is locked by another operation",
        ));
    }
    if context.evidence.state_lineage != context.action.state_lineage() {
        return Err(Decision::denied(
            DecisionCode::StateLineageMismatch,
            "state",
            "the backend state lineage changed after planning",
        ));
    }
    if context.evidence.state_serial != context.action.state_serial()
        || !digest_eq(
            &context.evidence.state_digest,
            context.action.state_digest(),
        )
    {
        return Err(Decision::denied(
            DecisionCode::StateSerialMismatch,
            "state",
            "the backend state serial or canonical state digest changed",
        ));
    }
    if !digest_eq(
        &context.evidence.dependency_lock_digest,
        context.action.dependency_lock_digest(),
    ) || !digest_eq(
        &context.evidence.module_manifest_digest,
        context.action.module_manifest_digest(),
    ) {
        return Err(Decision::denied(
            DecisionCode::DependencyNotPinned,
            "dependencies",
            "provider or module commitments differ from the protected plan",
        ));
    }
    Ok(())
}

fn check_projection(context: &EvaluationContext<'_>) -> Result<(), Decision> {
    let Ok(digest) = context.projection.digest() else {
        return Err(Decision::denied(
            DecisionCode::PlanProjectionMismatch,
            "plan-projection",
            "the sanitized plan projection is not canonical",
        ));
    };
    if !digest_eq(&digest, context.action.plan_projection_digest()) {
        return Err(Decision::denied(
            DecisionCode::PlanProjectionMismatch,
            "plan-projection",
            "the sanitized plan projection differs from the authorized commitment",
        ));
    }
    let summary = summary(context.projection);
    if &summary != context.action.permitted_change_summary() {
        return Err(Decision::denied(
            DecisionCode::ChangeOutsideProfile,
            "plan-projection",
            "the public change summary does not match the committed plan projection",
        ));
    }
    Ok(())
}

fn summary(projection: &SavedPlanProjectionV1) -> PermittedChangeSummaryV1 {
    let mut result = PermittedChangeSummaryV1 {
        creates: 0,
        updates: 0,
        reads: 0,
        no_ops: 0,
    };
    for action in projection
        .resource_changes
        .iter()
        .flat_map(|change| &change.actions)
    {
        match action {
            ResourceAction::Create => result.creates = result.creates.saturating_add(1),
            ResourceAction::Update => result.updates = result.updates.saturating_add(1),
            ResourceAction::Read => result.reads = result.reads.saturating_add(1),
            ResourceAction::NoOp => result.no_ops = result.no_ops.saturating_add(1),
            ResourceAction::Delete => {}
        }
    }
    result
}

fn digest_eq(left: &DigestHex, right: &DigestHex) -> bool {
    bool::from(left.as_str().as_bytes().ct_eq(right.as_str().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{NOW, fixture};

    #[test]
    fn exact_saved_plan_is_authorized() {
        let fixture = fixture();
        assert_eq!(
            evaluate(&EvaluationContext {
                action: &fixture.action,
                projection: &fixture.projection,
                evidence: &fixture.evidence,
                required_configuration: &fixture.configuration,
                executed_configuration: &fixture.configuration,
                request_audience: fixture.configuration.executor_audience(),
                now: NOW,
            })
            .code,
            DecisionCode::Authorized
        );
    }

    #[test]
    fn held_backend_lock_is_never_fresh_evidence() {
        let fixture = fixture();
        let mut evidence = fixture.evidence.clone();
        evidence.lock_held = true;
        let decision = evaluate(&EvaluationContext {
            action: &fixture.action,
            projection: &fixture.projection,
            evidence: &evidence,
            required_configuration: &fixture.configuration,
            executed_configuration: &fixture.configuration,
            request_audience: fixture.configuration.executor_audience(),
            now: NOW,
        });
        assert_eq!(decision.code, DecisionCode::EvidenceStale);
        assert_eq!(decision.stage, "state-lock");
    }
}
