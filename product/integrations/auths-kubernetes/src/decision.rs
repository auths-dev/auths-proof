//! Pure Kubernetes rollout containment checks.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use crate::types::{
    AdmissionMode, KubernetesEvidenceV1, KubernetesVerifierConfiguration,
    KubernetesWorkloadRolloutV1,
};

/// High-level product verdict.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionClass {
    Authorized,
    Denied,
    Indeterminate,
}

/// Stable Kubernetes-profile result code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionCode {
    Authorized,
    MalformedAction,
    ActionBodyMismatch,
    AuthsProofDenied,
    AuthsProofIndeterminate,
    VerifierConfigurationMismatch,
    ActionConfigurationMismatch,
    AuthorizationExpired,
    EvidenceStale,
    ClusterAudienceMismatch,
    NamespaceIdentityMismatch,
    ResourceIdentityMismatch,
    ResourceVersionMismatch,
    DryRunMismatch,
    ManagedFieldConflict,
    MutableImageReference,
    ChangeOutsideProfile,
    ReplicaBoundExceeded,
    AudienceMismatch,
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
            detail: "the exact Deployment patch matches fresh cluster evidence and verifier policy"
                .into(),
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

    fn indeterminate(code: DecisionCode, stage: &'static str, detail: &'static str) -> Self {
        Self {
            class: DecisionClass::Indeterminate,
            code,
            stage: stage.into(),
            detail: detail.into(),
        }
    }

    pub(crate) fn proof_denied(code: &str) -> Self {
        if code == "action-body-mismatch" {
            Self::denied(
                DecisionCode::ActionBodyMismatch,
                "auths-kernel",
                "the exact action bytes differ from the signed authorization",
            )
        } else {
            Self::denied(
                DecisionCode::AuthsProofDenied,
                "auths-kernel",
                "the Auths proof did not authorize this exact rollout",
            )
        }
    }

    pub(crate) fn proof_indeterminate() -> Self {
        Self::indeterminate(
            DecisionCode::AuthsProofIndeterminate,
            "auths-kernel",
            "the Auths proof could not be verified conclusively",
        )
    }
}

/// Borrowed decision inputs.
pub struct EvaluationContext<'a> {
    pub action: &'a KubernetesWorkloadRolloutV1,
    pub evidence: &'a KubernetesEvidenceV1,
    pub required_configuration: &'a KubernetesVerifierConfiguration,
    pub executed_configuration: &'a KubernetesVerifierConfiguration,
    pub request_audience: &'a str,
    pub now: u64,
}

/// Evaluates the exact rollout without accessing credentials or Kubernetes.
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
        || context.required_configuration.validate().is_err()
        || context.executed_configuration.validate().is_err()
        || context.evidence.validate().is_err()
    {
        return Err(Decision::denied(
            DecisionCode::MalformedAction,
            "decode",
            "the action, evidence, or verifier configuration is invalid",
        ));
    }
    let required = context.required_configuration.digest().map_err(|_| {
        Decision::denied(
            DecisionCode::MalformedAction,
            "configuration",
            "required verifier configuration is not canonical",
        )
    })?;
    let executed = context.executed_configuration.digest().map_err(|_| {
        Decision::denied(
            DecisionCode::MalformedAction,
            "configuration",
            "executed verifier configuration is not canonical",
        )
    })?;
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
            "the request addresses a different executor",
        ));
    }
    Ok(())
}

fn check_time(context: &EvaluationContext<'_>) -> Result<(), Decision> {
    if context.now > context.action.expires_at()
        || context.action.expires_at() - context.action.observed_at()
            > context
                .executed_configuration
                .maximum_authorization_lifetime_seconds()
    {
        return Err(Decision::denied(
            DecisionCode::AuthorizationExpired,
            "time",
            "the exact rollout authorization expired or exceeds policy",
        ));
    }
    let age = context
        .now
        .checked_sub(context.evidence.observed_at)
        .ok_or_else(|| {
            Decision::indeterminate(
                DecisionCode::EvidenceStale,
                "evidence",
                "cluster evidence is from the future",
            )
        })?;
    if age
        > context
            .executed_configuration
            .maximum_evidence_age_seconds()
        || context.action.observed_at() != context.evidence.observed_at
    {
        return Err(Decision::indeterminate(
            DecisionCode::EvidenceStale,
            "evidence",
            "cluster evidence is too old",
        ));
    }
    Ok(())
}

fn check_identity(context: &EvaluationContext<'_>) -> Result<(), Decision> {
    if context.action.cluster_audience() != context.evidence.cluster_audience
        || context.action.cluster_audience() != context.executed_configuration.cluster_audience()
        || context.action.api_server_identity() != context.evidence.api_server_identity
    {
        return Err(Decision::denied(
            DecisionCode::ClusterAudienceMismatch,
            "cluster-identity",
            "cluster audience or API server identity differs",
        ));
    }
    if context.action.namespace_name() != &context.evidence.namespace_name
        || context.action.namespace_uid() != &context.evidence.namespace_uid
        || !context
            .executed_configuration
            .allows_namespace(context.action.namespace_name())
    {
        return Err(Decision::denied(
            DecisionCode::NamespaceIdentityMismatch,
            "namespace-identity",
            "namespace name or UID differs",
        ));
    }
    if context.action.resource_name() != &context.evidence.resource_name
        || context.action.resource_uid() != &context.evidence.resource_uid
        || !context
            .executed_configuration
            .allows_deployment(context.action.resource_name())
    {
        return Err(Decision::denied(
            DecisionCode::ResourceIdentityMismatch,
            "resource-identity",
            "Deployment name or UID differs",
        ));
    }
    if context.action.expected_resource_version() != context.evidence.resource_version {
        return Err(Decision::denied(
            DecisionCode::ResourceVersionMismatch,
            "resource-version",
            "Deployment resourceVersion changed after authorization",
        ));
    }
    Ok(())
}

fn check_evidence(context: &EvaluationContext<'_>) -> Result<(), Decision> {
    let evidence_digest = context.evidence.digest().map_err(|_| {
        Decision::indeterminate(
            DecisionCode::DryRunMismatch,
            "evidence",
            "cluster evidence cannot be canonicalized",
        )
    })?;
    if !digest_eq(context.action.evidence_digest(), &evidence_digest)
        || context.action.current_spec_digest() != &context.evidence.current_spec_digest
    {
        return Err(Decision::denied(
            DecisionCode::ResourceVersionMismatch,
            "current-state",
            "the action commits to different current Deployment state",
        ));
    }
    if context.action.dry_run_response_digest() != &context.evidence.dry_run_response_digest
        || !context.evidence.dry_run_warnings.is_empty()
    {
        return Err(Decision::denied(
            DecisionCode::DryRunMismatch,
            "dry-run",
            "server-side dry-run response or warnings differ",
        ));
    }
    if context.evidence.managed_field_conflict {
        return Err(Decision::denied(
            DecisionCode::ManagedFieldConflict,
            "managed-fields",
            "server-side apply would require field ownership takeover",
        ));
    }
    if context.executed_configuration.admission_mode() != AdmissionMode::DeterministicDemo {
        return Err(Decision::indeterminate(
            DecisionCode::DryRunMismatch,
            "admission",
            "the public demo requires deterministic admission policy",
        ));
    }
    Ok(())
}

fn check_projection(context: &EvaluationContext<'_>) -> Result<(), Decision> {
    let projection = context.action.projection();
    if projection.previous_image_digest != context.evidence.current_image
        || projection.previous_replicas != context.evidence.current_replicas
    {
        return Err(Decision::denied(
            DecisionCode::ChangeOutsideProfile,
            "change-projection",
            "the requested change starts from different workload state",
        ));
    }
    if projection.requested_replicas > context.executed_configuration.maximum_replicas()
        || projection.requested_replicas < context.executed_configuration.minimum_replicas()
    {
        return Err(Decision::denied(
            DecisionCode::ReplicaBoundExceeded,
            "replica-bounds",
            "requested replicas exceed the verifier grant",
        ));
    }
    projection
        .validate(context.executed_configuration)
        .map_err(|_| {
            Decision::denied(
                DecisionCode::ChangeOutsideProfile,
                "change-projection",
                "the patch changes a field outside the rollout profile",
            )
        })
}

fn digest_eq(left: &crate::types::DigestHex, right: &crate::types::DigestHex) -> bool {
    bool::from(left.as_str().as_bytes().ct_eq(right.as_str().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::fixture;

    #[test]
    fn exact_rollout_is_authorized() {
        let fixture = fixture();
        let decision = evaluate(&EvaluationContext {
            action: &fixture.action,
            evidence: &fixture.evidence,
            required_configuration: &fixture.configuration,
            executed_configuration: &fixture.configuration,
            request_audience: fixture.configuration.executor_audience(),
            now: fixture.now,
        });
        assert_eq!(decision.code, DecisionCode::Authorized);
    }

    #[test]
    fn configuration_mismatch_returns_both_inputs_and_denies() {
        let fixture = fixture();
        let changed = fixture.configuration_with_maximum_replicas(4);
        let result = crate::receipts::decision_receipt(
            &fixture.action,
            &fixture.evidence,
            &fixture.configuration,
            &changed,
            fixture.configuration.executor_audience(),
            fixture.now,
        )
        .unwrap();
        assert_eq!(
            result.decision.code,
            DecisionCode::VerifierConfigurationMismatch
        );
        assert_eq!(result.required_configuration, fixture.configuration);
        assert_eq!(result.executed_configuration, changed);
    }
}
