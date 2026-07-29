//! Deterministic native scenario and real Auths proof.

use auths_apps_testkit::{ExactActionFixture, exact_action_fixture};
use auths_opentofu::{
    Decision, DecisionClass, DecisionCode, DigestHex, EvaluationContext, OpenTofuSavedPlanApplyV1,
    OpenTofuStateEvidenceV1, OpenTofuVerifierConfigurationInput, OpenTofuVerifierConfigurationV1,
    ResourceAction, SavedPlanProjectionV1,
    canonical::{canonical_json, sha256},
    evaluate,
    profile::OpenTofuSavedPlanProfile,
    test_support::{Fixture, fixture},
};
use auths_profile_api::ActionProfile as _;
use serde::Serialize;
use serde_json::Value;

pub struct DemoFixture {
    pub product: Fixture,
    pub auths: ExactActionFixture,
    pub variants: Vec<DemoVariant>,
}

#[derive(Clone, Serialize)]
pub struct DemoVariant {
    pub id: String,
    pub label: String,
    pub description: String,
    pub action: OpenTofuSavedPlanApplyV1,
    pub projection: SavedPlanProjectionV1,
    pub evidence: OpenTofuStateEvidenceV1,
    pub required_configuration: OpenTofuVerifierConfigurationV1,
    pub executed_configuration: OpenTofuVerifierConfigurationV1,
    pub required_configuration_digest: DigestHex,
    pub executed_configuration_digest: DigestHex,
    pub decision: Decision,
}

#[must_use]
pub fn demo_fixture(now: u64, challenge: [u8; 32]) -> DemoFixture {
    demo_fixture_from_product(fixture_at(now), now, challenge)
}

#[must_use]
pub fn demo_fixture_from_product(product: Fixture, now: u64, challenge: [u8; 32]) -> DemoFixture {
    let canonical = OpenTofuSavedPlanProfile
        .canonicalize(&product.action.canonical_bytes().unwrap())
        .unwrap();
    let auths = exact_action_fixture(
        &canonical,
        product.configuration.executor_audience(),
        now,
        challenge,
    );
    let variants = variants(&product, now);
    DemoFixture {
        product,
        auths,
        variants,
    }
}

fn fixture_at(now: u64) -> Fixture {
    let mut fixture = fixture();
    if now == auths_opentofu::test_support::NOW {
        return fixture;
    }
    fixture.evidence.observed_at = now;
    fixture.action = mutate_action(&fixture.action, |value| {
        value["planned_at"] = Value::from(now);
        value["expires_at"] = Value::from(now + 300);
    });
    fixture
}

fn variants(fixture: &Fixture, now: u64) -> Vec<DemoVariant> {
    let mut variants = identity_variants(fixture, now);
    variants.extend(policy_variants(fixture, now));
    variants.extend(freshness_variants(fixture, now));
    variants
}

fn identity_variants(fixture: &Fixture, now: u64) -> Vec<DemoVariant> {
    let exact = variant(
        "exact",
        "Exact saved plan",
        "Plan bytes, backend, workspace, state, dependencies, and verifier policy match.",
        fixture.action.clone(),
        fixture.projection.clone(),
        fixture.evidence.clone(),
        fixture.configuration.clone(),
        fixture.configuration.clone(),
        now,
    );
    let swapped_plan = variant(
        "swapped-plan",
        "Saved plan substituted",
        "Protected storage returns bytes that do not match the authorized plan digest.",
        fixture.action.clone(),
        fixture.projection.clone(),
        fixture.evidence.clone(),
        fixture.configuration.clone(),
        fixture.configuration.clone(),
        now,
    );
    let changed_workspace = variant(
        "workspace-changed",
        "Workspace changed",
        "The executor is pointed at a different workspace.",
        fixture.action.clone(),
        fixture.projection.clone(),
        OpenTofuStateEvidenceV1 {
            workspace: "production".into(),
            ..fixture.evidence.clone()
        },
        fixture.configuration.clone(),
        fixture.configuration.clone(),
        now,
    );
    let changed_backend = variant(
        "backend-changed",
        "Backend changed",
        "The executor is connected to a backend other than the one committed by the plan.",
        fixture.action.clone(),
        fixture.projection.clone(),
        OpenTofuStateEvidenceV1 {
            backend_identity: "local-volume://different-backend".into(),
            ..fixture.evidence.clone()
        },
        fixture.configuration.clone(),
        fixture.configuration.clone(),
        now,
    );
    let stale_state = variant(
        "stale-state",
        "State advanced",
        "The backend serial advances after the saved plan was created.",
        fixture.action.clone(),
        fixture.projection.clone(),
        OpenTofuStateEvidenceV1 {
            state_serial: fixture.evidence.state_serial + 1,
            state_digest: sha256(b"state-serial-8"),
            ..fixture.evidence.clone()
        },
        fixture.configuration.clone(),
        fixture.configuration.clone(),
        now,
    );
    vec![
        exact,
        swapped_plan,
        changed_workspace,
        changed_backend,
        stale_state,
    ]
}

fn policy_variants(fixture: &Fixture, now: u64) -> Vec<DemoVariant> {
    let mut delete_projection = fixture.projection.clone();
    delete_projection.resource_changes[0].actions = vec![ResourceAction::Delete];
    let delete = variant(
        "destroy-added",
        "Destroy added",
        "A destructive action appears in the semantic projection.",
        fixture.action.clone(),
        delete_projection,
        fixture.evidence.clone(),
        fixture.configuration.clone(),
        fixture.configuration.clone(),
        now,
    );
    let dependency = variant(
        "dependency-changed",
        "Provider lock changed",
        "The provider dependency lock no longer matches planning evidence.",
        fixture.action.clone(),
        fixture.projection.clone(),
        OpenTofuStateEvidenceV1 {
            dependency_lock_digest: sha256(b"different-lock"),
            ..fixture.evidence.clone()
        },
        fixture.configuration.clone(),
        fixture.configuration.clone(),
        now,
    );
    let state_lock = variant(
        "state-lock-held",
        "State lock unavailable",
        "Another operation holds the backend state lock, so freshness cannot be established.",
        fixture.action.clone(),
        fixture.projection.clone(),
        OpenTofuStateEvidenceV1 {
            lock_held: true,
            ..fixture.evidence.clone()
        },
        fixture.configuration.clone(),
        fixture.configuration.clone(),
        now,
    );
    let changed_source_action = mutate_action(&fixture.action, |value| {
        value["configuration_bundle_digest"] = Value::from(sha256(b"changed-source").to_string());
    });
    let mut changed_source = variant(
        "source-changed",
        "Source configuration changed",
        "The proposed action commits to source bytes other than those covered by the Auths proof.",
        changed_source_action,
        fixture.projection.clone(),
        fixture.evidence.clone(),
        fixture.configuration.clone(),
        fixture.configuration.clone(),
        now,
    );
    changed_source.decision = Decision {
        class: DecisionClass::Denied,
        code: DecisionCode::AuthsProofDenied,
        stage: "auths-kernel".into(),
        detail: "the exact Auths proof does not cover the changed source commitment".into(),
    };
    vec![delete, dependency, state_lock, changed_source]
}

fn freshness_variants(fixture: &Fixture, now: u64) -> Vec<DemoVariant> {
    let expired_action = mutate_action(&fixture.action, |value| {
        value["planned_at"] = Value::from(now.saturating_sub(400));
        value["expires_at"] = Value::from(now.saturating_sub(100));
    });
    let expired = variant(
        "expired-plan",
        "Plan expired",
        "The saved plan and its state observation are older than the configured freshness window.",
        expired_action,
        fixture.projection.clone(),
        OpenTofuStateEvidenceV1 {
            observed_at: now.saturating_sub(400),
            ..fixture.evidence.clone()
        },
        fixture.configuration.clone(),
        fixture.configuration.clone(),
        now,
    );
    let changed_configuration =
        OpenTofuVerifierConfigurationV1::new(OpenTofuVerifierConfigurationInput {
            allowed_opentofu_versions: fixture.configuration.allowed_opentofu_versions().to_vec(),
            allowed_backend_identities: fixture.configuration.allowed_backend_identities().to_vec(),
            allowed_workspaces: fixture.configuration.allowed_workspaces().to_vec(),
            allowed_provider_sources: fixture.configuration.allowed_provider_sources().to_vec(),
            allowed_resource_types: fixture.configuration.allowed_resource_types().to_vec(),
            allowed_actions: fixture.configuration.allowed_actions().to_vec(),
            maximum_resource_changes: fixture
                .configuration
                .maximum_resource_changes()
                .saturating_add(1),
            maximum_plan_age_seconds: fixture.configuration.maximum_plan_age_seconds(),
            maximum_authorization_lifetime_seconds: fixture
                .configuration
                .maximum_authorization_lifetime_seconds(),
            allow_sensitive_outputs: fixture.configuration.allow_sensitive_outputs(),
            allow_destroy: false,
            allow_replacement: false,
            receipt_schema_version: fixture.configuration.receipt_schema_version().into(),
            executor_audience: fixture.configuration.executor_audience().into(),
        })
        .unwrap();
    let configuration = variant(
        "configuration-changed",
        "Verifier policy changed",
        "The executor loads a different resource-change ceiling.",
        fixture.action.clone(),
        fixture.projection.clone(),
        fixture.evidence.clone(),
        fixture.configuration.clone(),
        changed_configuration,
        now,
    );
    vec![expired, configuration]
}

#[allow(
    clippy::too_many_arguments,
    reason = "variant construction keeps exact changed inputs visible"
)]
fn variant(
    id: &str,
    label: &str,
    description: &str,
    action: OpenTofuSavedPlanApplyV1,
    projection: SavedPlanProjectionV1,
    evidence: OpenTofuStateEvidenceV1,
    required_configuration: OpenTofuVerifierConfigurationV1,
    executed_configuration: OpenTofuVerifierConfigurationV1,
    now: u64,
) -> DemoVariant {
    let required_configuration_digest = required_configuration.digest().unwrap();
    let executed_configuration_digest = executed_configuration.digest().unwrap();
    let decision = evaluate(&EvaluationContext {
        action: &action,
        projection: &projection,
        evidence: &evidence,
        required_configuration: &required_configuration,
        executed_configuration: &executed_configuration,
        request_audience: required_configuration.executor_audience(),
        now,
    });
    DemoVariant {
        id: id.into(),
        label: label.into(),
        description: description.into(),
        action,
        projection,
        evidence,
        required_configuration,
        executed_configuration,
        required_configuration_digest,
        executed_configuration_digest,
        decision,
    }
}

fn mutate_action(
    action: &OpenTofuSavedPlanApplyV1,
    mutate: impl FnOnce(&mut Value),
) -> OpenTofuSavedPlanApplyV1 {
    let mut value = serde_json::to_value(action).unwrap();
    mutate(&mut value);
    OpenTofuSavedPlanApplyV1::from_canonical_bytes(&canonical_json(&value).unwrap()).unwrap()
}
