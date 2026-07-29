//! Deterministic native scenario and real Auths proof.

use auths_apps_testkit::{ExactActionFixture, exact_action_fixture};
use auths_opentofu::{
    Decision, DigestHex, EvaluationContext, OpenTofuSavedPlanApplyV1, OpenTofuStateEvidenceV1,
    OpenTofuVerifierConfigurationV1, ResourceAction, SavedPlanProjectionV1,
    canonical::{canonical_json, sha256},
    evaluate,
    profile::OpenTofuSavedPlanProfile,
    test_support::{Fixture, configuration_with_maximum_resource_changes, fixture},
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
    let changed_configuration = configuration_with_maximum_resource_changes(5);
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
    vec![
        exact,
        swapped_plan,
        changed_workspace,
        stale_state,
        delete,
        dependency,
        configuration,
    ]
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
