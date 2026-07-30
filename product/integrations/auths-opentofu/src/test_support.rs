//! Deterministic OpenTofu product fixtures.

use crate::{
    action::{OpenTofuSavedPlanApplyInput, OpenTofuSavedPlanApplyV1, PermittedChangeSummaryV1},
    canonical::sha256,
    plan_projection::{ResourceChangeV1, SavedPlanProjectionV1},
    types::{
        DigestHex, OpenTofuStateEvidenceV1, OpenTofuVerifierConfigurationInput,
        OpenTofuVerifierConfigurationV1, PlanHandle, ResourceAction,
    },
};

pub const NOW: u64 = 1_800_000_000;
pub const PLAN_BYTES: &[u8] = b"opaque-opentofu-saved-plan-fixture-v1";

pub struct Fixture {
    pub action: OpenTofuSavedPlanApplyV1,
    pub projection: SavedPlanProjectionV1,
    pub evidence: OpenTofuStateEvidenceV1,
    pub configuration: OpenTofuVerifierConfigurationV1,
}

#[must_use]
pub fn configuration() -> OpenTofuVerifierConfigurationV1 {
    configuration_with_maximum_resource_changes(4)
}

#[must_use]
pub fn configuration_with_maximum_resource_changes(
    maximum_resource_changes: u32,
) -> OpenTofuVerifierConfigurationV1 {
    OpenTofuVerifierConfigurationV1::new(OpenTofuVerifierConfigurationInput {
        allowed_opentofu_versions: vec!["1.9.0".into()],
        allowed_backend_identities: vec!["s3://auths-demo-state".into()],
        allowed_workspaces: vec!["demo".into()],
        allowed_provider_sources: vec!["registry.opentofu.org/cloudflare/cloudflare".into()],
        allowed_resource_types: vec!["cloudflare_dns_record".into()],
        allowed_actions: vec![ResourceAction::Update],
        maximum_resource_changes,
        maximum_plan_age_seconds: 300,
        maximum_authorization_lifetime_seconds: 300,
        allow_sensitive_outputs: false,
        allow_destroy: false,
        allow_replacement: false,
        receipt_schema_version: "auths.opentofu.decision-receipt/1".into(),
        executor_audience: "https://opentofu.demo.auths.dev".into(),
    })
    .unwrap()
}

#[must_use]
pub fn fixture() -> Fixture {
    let configuration = configuration();
    let projection = SavedPlanProjectionV1 {
        format_version: "1.2".into(),
        terraform_version: "1.9.0".into(),
        resource_changes: vec![ResourceChangeV1 {
            address: "cloudflare_dns_record.auths_demo".into(),
            provider_source: "registry.opentofu.org/cloudflare/cloudflare".into(),
            resource_type: "cloudflare_dns_record".into(),
            resource_name: "auths_demo".into(),
            actions: vec![ResourceAction::Update],
            before_commitment: sha256(b"old TXT value"),
            after_commitment: sha256(b"authorized TXT value"),
            sensitive_paths: Vec::new(),
            unknown_paths: vec!["/id".into()],
            replacement_paths: Vec::new(),
        }],
        output_change_commitments: Vec::new(),
        checks_commitment: sha256(b"checks"),
        provider_configuration_commitment: sha256(b"provider-config"),
    };
    let evidence = OpenTofuStateEvidenceV1 {
        backend_identity: "s3://auths-demo-state".into(),
        workspace: "demo".into(),
        state_lineage: "49f802ac-26e0-4d98-b4dc-f93088785666".into(),
        state_serial: 7,
        state_digest: sha256(b"state-serial-7"),
        lock_held: false,
        dependency_lock_digest: sha256(b"dependency-lock"),
        module_manifest_digest: sha256(b"module-manifest"),
        planner_build_identity: "auths-protected-planner@sha256:fixture".into(),
        observed_at: NOW,
    };
    let action = OpenTofuSavedPlanApplyV1::new(OpenTofuSavedPlanApplyInput {
        executor_audience: configuration.executor_audience().into(),
        opentofu_version: "1.9.0".into(),
        platform: "linux_amd64".into(),
        backend_identity: evidence.backend_identity.clone(),
        workspace: evidence.workspace.clone(),
        state_lineage: evidence.state_lineage.clone(),
        state_serial: evidence.state_serial,
        state_digest: evidence.state_digest.clone(),
        configuration_bundle_digest: sha256(b"source-bundle"),
        variable_commitment: sha256(b"variables"),
        dependency_lock_digest: evidence.dependency_lock_digest.clone(),
        module_manifest_digest: evidence.module_manifest_digest.clone(),
        opaque_plan_digest: sha256(PLAN_BYTES),
        plan_projection_digest: projection.digest().unwrap(),
        plan_handle: PlanHandle::parse(sha256(PLAN_BYTES).as_str()[..32].to_owned()).unwrap(),
        permitted_change_summary: PermittedChangeSummaryV1 {
            creates: 0,
            updates: 1,
            reads: 0,
            no_ops: 0,
        },
        required_configuration: configuration.clone(),
        planned_at: NOW,
        expires_at: NOW + 300,
        nonce: DigestHex::parse("11".repeat(32)).unwrap(),
    })
    .unwrap();
    Fixture {
        action,
        projection,
        evidence,
        configuration,
    }
}
