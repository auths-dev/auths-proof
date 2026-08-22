//! Static protected qualification adapter for the OpenTofu profile family.

use auths_connections::{ProviderCredentialLease, QualificationProviderCallKind};
use auths_profile_kit::QualificationProfileStateFactV1;
use auths_profile_kit::{
    QualificationAdapterMetadata, QualificationCleanupEvidence, QualificationCollectedOperation,
    QualificationCollectionAdapter, QualificationCommonOperationInstanceEvidence,
    QualificationCommonReceiptClaims, QualificationEffect, QualificationHarnessError,
    QualificationOperationRole, QualificationPhaseClient, QualificationProtectedObserver,
    QualificationProtectedSetup, QualificationProtectedSetupInput, QualificationProviderTruth,
    QualificationRunContext, QualificationRunReference, QualificationScenarioProgramV1,
    QualificationSetupHandoffV1, QualificationTarget, QualificationVector,
    qualification_pre_admission_attempt_count,
    qualification_scenario_program as resolve_qualification_scenario_program,
};
use auths_profile_runtime::{ProfileReceiptInspection, ProfileRuntimeError};
use auths_stores::JournalRecordV1;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use minicbor::{Decoder, Encoder};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, path::Path};
use zeroize::Zeroizing;

const PLAN_TRANSPORT_ENVELOPE_VERSION: u8 = 1;
const MAX_PLAN_TRANSPORT_ENVELOPE_BYTES: usize = 258 * 1024 * 1024;

/// Runs the production profile receipt inspector through the qualification-only static port.
pub fn inspect_receipt_claims(
    profile: &str,
    inspection: ProfileReceiptInspection<'_>,
) -> Result<(), ProfileRuntimeError> {
    match profile {
        "auths.opentofu.plan-preflight/1" => {
            crate::local_agent::plans_create_inspect_receipt_claims(inspection)
        }
        "auths.opentofu.saved-plan-apply/1" => {
            crate::local_agent::saved_plans_apply_inspect_receipt_claims(inspection)
        }
        _ => Err(ProfileRuntimeError::Invalid),
    }
}

/// Reads one canonical protected prepared-plan snapshot without opening or
/// mutating the production store.
pub fn inspect_profile_state(
    profile: &str,
    journal: &[JournalRecordV1],
    store_bytes: &[u8],
) -> Result<Vec<QualificationProfileStateFactV1>, ProfileRuntimeError> {
    crate::local_agent::inspect_profile_state_for_qualification(profile, journal, store_bytes)
}

/// Runs only the provider-facing OpenTofu transport beneath a
/// ProviderProxy-owned durable root. Planning returns a transient envelope
/// containing the saved-plan bytes so the agent can import the same artifact
/// into its separately owned profile-state store before classification.
pub async fn call_provider_transport(
    profile: &str,
    command: &[u8],
    credential: &[u8],
    configuration: Option<&[u8]>,
    transport_root: &Path,
    now_unix_seconds: u64,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    match profile {
        "auths.opentofu.plan-preflight/1" => {
            let (provider_result, artifact) =
                crate::local_agent::plans_create_transport_from_bytes(
                    transport_root,
                    command,
                    credential,
                    configuration.ok_or(ProfileRuntimeError::Invalid)?,
                    now_unix_seconds,
                )
                .await?;
            encode_plan_transport_envelope(&provider_result, &artifact)
        }
        "auths.opentofu.saved-plan-apply/1" if configuration.is_some() => {
            crate::local_agent::saved_plans_apply_transport_from_bytes(
                transport_root,
                command,
                credential,
                now_unix_seconds,
            )
            .await
        }
        _ => Err(ProfileRuntimeError::Invalid),
    }
}

/// Runs the corresponding provider-read reconciliation query. Planning is
/// idempotently repeated and returns the same transient artifact envelope;
/// saved-plan apply returns `None` only for authoritative unchanged state.
pub async fn reconcile_provider_transport(
    profile: &str,
    command: &[u8],
    credential: &[u8],
    configuration: Option<&[u8]>,
    transport_root: &Path,
    now_unix_seconds: u64,
) -> Result<Option<Vec<u8>>, ProfileRuntimeError> {
    match profile {
        "auths.opentofu.plan-preflight/1" => call_provider_transport(
            profile,
            command,
            credential,
            configuration,
            transport_root,
            now_unix_seconds,
        )
        .await
        .map(Some),
        "auths.opentofu.saved-plan-apply/1" if configuration.is_some() => {
            crate::local_agent::saved_plans_apply_reconcile_transport_from_bytes(
                transport_root,
                command,
                credential,
                now_unix_seconds,
            )
            .await
        }
        _ => Err(ProfileRuntimeError::Invalid),
    }
}

/// Executes the exact generated-profile transport selected by the protected
/// qualification route registry.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_provider_transport(
    profile: &str,
    kind: QualificationProviderCallKind,
    command: &[u8],
    _profile_state: &[u8],
    credential: &ProviderCredentialLease,
    configuration: Option<&[u8]>,
    transport_root: &Path,
    _operation_id: &str,
    now_unix_seconds: u64,
    deadline: std::time::Instant,
) -> Result<Option<Vec<u8>>, ProfileRuntimeError> {
    let exposed = credential
        .expose(deadline)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    match kind {
        QualificationProviderCallKind::Execute => call_provider_transport(
            profile,
            command,
            exposed,
            configuration,
            transport_root,
            now_unix_seconds,
        )
        .await
        .map(Some),
        QualificationProviderCallKind::Reconcile => {
            reconcile_provider_transport(
                profile,
                command,
                exposed,
                configuration,
                transport_root,
                now_unix_seconds,
            )
            .await
        }
    }
}

/// Independently observes one provider-entered OpenTofu operation with the
/// protected runtime-read credential and ProviderObserver-owned workspace.
pub async fn observe_provider_truth(
    record: &JournalRecordV1,
    credential: &[u8],
    observer_root: &Path,
    now_unix_seconds: u64,
) -> Result<(QualificationEffect, Vec<u8>), ProfileRuntimeError> {
    crate::local_agent::observe_provider_truth_for_qualification(
        record,
        credential,
        observer_root,
        now_unix_seconds,
    )
    .await
}

/// Imports a transient planning artifact into the agent-owned durable store
/// and returns only the canonical provider result used by the normal observer.
pub fn import_provider_transport_result(
    profile: &str,
    agent_state_root: &Path,
    response: Vec<u8>,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    if profile != "auths.opentofu.plan-preflight/1" {
        return Ok(response);
    }
    let (provider_result, artifact) = decode_plan_transport_envelope(&response)?;
    crate::local_agent::import_plan_transport_artifact(
        agent_state_root,
        &provider_result,
        artifact,
    )?;
    Ok(provider_result)
}

fn encode_plan_transport_envelope(
    provider_result: &[u8],
    artifact: &[u8],
) -> Result<Vec<u8>, ProfileRuntimeError> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    encoder.array(3).map_err(|_| ProfileRuntimeError::Invalid)?;
    encoder
        .u8(PLAN_TRANSPORT_ENVELOPE_VERSION)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    encoder
        .bytes(provider_result)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    encoder
        .bytes(artifact)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    if bytes.len() > MAX_PLAN_TRANSPORT_ENVELOPE_BYTES {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(bytes)
}

fn decode_plan_transport_envelope(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ProfileRuntimeError> {
    if bytes.is_empty() || bytes.len() > MAX_PLAN_TRANSPORT_ENVELOPE_BYTES {
        return Err(ProfileRuntimeError::Invalid);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.array().map_err(|_| ProfileRuntimeError::Invalid)? != Some(3)
        || decoder.u8().map_err(|_| ProfileRuntimeError::Invalid)?
            != PLAN_TRANSPORT_ENVELOPE_VERSION
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    let provider_result = decoder
        .bytes()
        .map_err(|_| ProfileRuntimeError::Invalid)?
        .to_vec();
    let artifact = decoder
        .bytes()
        .map_err(|_| ProfileRuntimeError::Invalid)?
        .to_vec();
    if provider_result.is_empty()
        || artifact.is_empty()
        || decoder.position() != bytes.len()
        || encode_plan_transport_envelope(&provider_result, &artifact)? != bytes
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok((provider_result, artifact))
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpentofuProviderTruthFacts {
    workspace_sha256: String,
    plan_sha256: String,
    artifact_sha256: String,
    state_lineage_sha256: String,
    before_serial: u64,
    after_serial: u64,
    applied_marker_sha256: Option<String>,
    applied: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpentofuProviderMatrixContract {
    schema: String,
    artifact_encryption: String,
    artifact_key_policy: String,
    backend: String,
    backend_sha256: String,
    dependency_lock_sha256: String,
    dependency_mirror: String,
    dependency_mirror_sha256: String,
    module_pins: Vec<String>,
    provider_pins: Vec<String>,
    recovery_record: String,
    sandbox: OpentofuQualificationSandbox,
    tool_archive_sha256: String,
    tool_version: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpentofuQualificationSandbox {
    capabilities: Vec<String>,
    cpu_milliseconds: u64,
    egress_allowlist: Vec<String>,
    filesystem_policy: String,
    identity: String,
    memory_bytes: u64,
    mechanism: String,
    namespaces: Vec<String>,
    no_new_privileges: bool,
    pids: u16,
    seccomp_policy_sha256: String,
    wall_clock_milliseconds: u64,
}

/// Exact v1 prerequisite rows owned by the generated qualification contract.
#[must_use]
pub fn qualification_requirement_ids() -> &'static [&'static str] {
    &[
        "opentofu-apply-revalidation",
        "opentofu-artifact-storage",
        "opentofu-dependency-closure",
        "opentofu-lock-equality",
        "opentofu-preparation-atomicity",
        "opentofu-recovery-record",
        "opentofu-result-observation",
        "opentofu-sandbox",
        "opentofu-sandbox-closure",
        "opentofu-tool-identity",
    ]
}

/// SHA-256 of the exact canonical v1 requirement inventory bytes.
#[must_use]
pub const fn qualification_requirements_sha256() -> &'static str {
    "8e64f42708acfce90521a67abe36e6ddeadf796f2bb7a7aca9905f45858de06d"
}

/// Exact public receipt-claim roster required by the v1 OpenTofu family.
#[must_use]
pub fn qualification_receipt_claim_ids() -> &'static [&'static str] {
    &[
        "opentofu.artifact",
        "opentofu.dependency-closure",
        "opentofu.lock-closure",
        "opentofu.observation",
        "opentofu.pre-entry-recheck",
        "opentofu.preparation",
        "opentofu.provider-result",
        "opentofu.reconciliation",
        "opentofu.reservation",
        "opentofu.sandbox",
        "opentofu.sandbox-policy",
        "opentofu.tool-identity",
    ]
}

/// Exact executable provider-truth field roster.
#[must_use]
pub fn qualification_provider_truth_fields() -> &'static [&'static str] {
    &[
        "afterSerial",
        "applied",
        "appliedMarkerSha256",
        "artifactSha256",
        "beforeSerial",
        "planSha256",
        "stateLineageSha256",
        "workspaceSha256",
    ]
}

/// Raw provider-owned JSON field names forbidden from retained evidence.
#[must_use]
pub fn qualification_forbidden_evidence_fields() -> &'static [&'static str] {
    &["appliedMarker", "stateLineage"]
}

/// OpenTofu raw identifiers have no safe public byte-prefix detector in v1.
#[must_use]
pub fn qualification_redaction_prefixes() -> &'static [&'static str] {
    &[]
}

/// Exact provider-matrix row roster for the v1 launch.
#[must_use]
pub fn qualification_provider_matrix_rows() -> &'static [(
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
)] {
    &[(
        "opentofu-1.9.0",
        "opentofu",
        "1.9.0",
        "638dd3fb9ecfa6fd9f54a0024b195b12b407c51ccee6f83b18a75a8be79f8214",
        "linux-x86_64",
    )]
}

/// Exact atomic family phase roster shared by every v1 OpenTofu scenario.
#[must_use]
pub fn qualification_operation_plan()
-> &'static [(QualificationOperationRole, &'static str, bool, bool)] {
    &[
        (
            QualificationOperationRole::Preflight,
            "auths.opentofu.plan-preflight/1",
            true,
            false,
        ),
        (
            QualificationOperationRole::Effect,
            "auths.opentofu.saved-plan-apply/1",
            true,
            true,
        ),
    ]
}

/// Validates the exact Linux sandbox/tool/dependency/backend selection.
pub fn validate_provider_matrix_contract(
    bytes: &[u8],
    provider_version: &str,
    provider_artifact_sha256: &str,
) -> Result<(), QualificationHarnessError> {
    const TOOL_SHA256: &str = "638dd3fb9ecfa6fd9f54a0024b195b12b407c51ccee6f83b18a75a8be79f8214";
    if bytes.is_empty() || bytes.len() > 65_536 {
        return Err(QualificationHarnessError::Limit);
    }
    let contract: OpentofuProviderMatrixContract =
        serde_json::from_slice(bytes).map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if serde_json_canonicalizer::to_vec(&contract)
        .map_err(|_| QualificationHarnessError::ProviderTruth)?
        != bytes
        || contract.schema != "auths.opentofu.qualification-provider-contract/1"
        || provider_version != "1.9.0"
        || provider_artifact_sha256 != TOOL_SHA256
        || contract.tool_version != provider_version
        || contract.tool_archive_sha256 != TOOL_SHA256
        || contract.sandbox.mechanism != "linux-user-mount-network-namespaces-seccomp-cgroup-v2"
        || contract.sandbox.identity != "auths-tofu-qualification"
        || contract.sandbox.filesystem_policy != "readonly-input-empty-home-owner-only-output-v1"
        || !contract.sandbox.capabilities.is_empty()
        || contract.sandbox.cpu_milliseconds != 60_000
        || contract.sandbox.egress_allowlist.as_slice() != ["127.0.0.1:28443", "127.0.0.1:29443"]
        || contract.sandbox.memory_bytes != 536_870_912
        || contract.sandbox.namespaces.as_slice() != ["mount", "network", "pid", "user"]
        || !contract.sandbox.no_new_privileges
        || contract.sandbox.pids != 64
        || contract.sandbox.seccomp_policy_sha256
            != "b4c73b61ade1b9f96d7a6089a0b406c4cb6e8cdc85a4df5de994a283b4b0b857"
        || contract.sandbox.wall_clock_milliseconds != 300_000
        || contract.dependency_mirror != "https://127.0.0.1:28443/v1"
        || contract.dependency_mirror_sha256
            != "fca4566f8e3cd3b109364102e71ec10ae6fa4a3e0c8bcf7894c71a1797458ee1"
        || contract.dependency_lock_sha256
            != "26d49718e8ef09f1693391fd84bf8ffa06afbb78f43b187faa72b68a022fcc19"
        || contract.provider_pins.as_slice() != ["registry.opentofu.org/hashicorp/null@3.2.4"]
        || contract.module_pins.as_slice() != ["auths.local/qualification/resource@1.0.0"]
        || contract.artifact_encryption != "age-x25519-zstd-v1"
        || contract.artifact_key_policy != "environment-owned-rotatable-v1"
        || contract.backend != "https://127.0.0.1:29443/v1"
        || contract.backend_sha256
            != "81ecc7703df66664df2929a8ba2a50d3faca5f452f1344358a192184229bb50e"
        || contract.recovery_record != "auths.opentofu.operation-recovery/1"
    {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    Ok(())
}

/// Validates the domain-owned public provider-truth projection.
pub fn validate_provider_truth_facts(
    bytes: &[u8],
    effect: QualificationEffect,
) -> Result<(), QualificationHarnessError> {
    if bytes.is_empty() || bytes.len() > 65_536 {
        return Err(QualificationHarnessError::Limit);
    }
    let facts: OpentofuProviderTruthFacts =
        serde_json::from_slice(bytes).map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if serde_json_canonicalizer::to_vec(&facts)
        .map_err(|_| QualificationHarnessError::ProviderTruth)?
        != bytes
        || !digest(&facts.workspace_sha256)
        || !digest(&facts.plan_sha256)
        || !digest(&facts.artifact_sha256)
        || !digest(&facts.state_lineage_sha256)
        || facts.after_serial < facts.before_serial
        || facts
            .applied_marker_sha256
            .as_deref()
            .is_some_and(|value| !digest(value))
        || facts.applied != (effect == QualificationEffect::Applied)
        || facts.applied_marker_sha256.is_some() != facts.applied
        || (facts.applied && facts.after_serial <= facts.before_serial)
        || (!facts.applied && facts.after_serial != facts.before_serial)
    {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    Ok(())
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

const SCENARIOS: &[&str] = &[
    "opentofu-applied-marker",
    "opentofu-artifact-redaction",
    "opentofu-destructive-denial",
    "opentofu-lock-closure",
    "opentofu-plan-integrity",
    "opentofu-protected-plan",
    "opentofu-response-loss",
    "opentofu-sandbox",
    "opentofu-state-drift",
    "opentofu-tool-identity",
];

#[must_use]
pub const fn qualification_domain_scenario_ids() -> &'static [&'static str] {
    SCENARIOS
}

pub fn qualification_scenario_program(
    id: &str,
) -> Result<QualificationScenarioProgramV1, QualificationHarnessError> {
    resolve_qualification_scenario_program(
        include_bytes!("../../../conformance/v2/profile-qualification-common.json"),
        include_bytes!("../qualification/scenarios-v1.json"),
        "opentofu",
        id,
    )
    .map_err(|_| QualificationHarnessError::InvalidMetadata)
}

/// Qualification-only OpenTofu adapter over the installed generated client.
pub struct OpentofuQualificationAdapter;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpentofuQualificationSetupCredentialV1 {
    schema: String,
    backend_credential_base64url: String,
    dependency_lock: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpentofuQualificationObserverCredentialV1 {
    schema: String,
    backend_credential_base64url: String,
    connection_descriptor_base64url: String,
    configuration_base64url: String,
    dependency_lock: String,
}

fn exact_family_configuration(
    configurations: &BTreeMap<String, Vec<u8>>,
) -> Result<&[u8], QualificationHarnessError> {
    let preflight = configurations
        .get("auths.opentofu.plan-preflight/1")
        .ok_or(QualificationHarnessError::Onboarding)?;
    let effect = configurations
        .get("auths.opentofu.saved-plan-apply/1")
        .ok_or(QualificationHarnessError::Onboarding)?;
    if configurations.len() != 2 || preflight != effect {
        return Err(QualificationHarnessError::Onboarding);
    }
    Ok(preflight)
}

fn qualification_bundle(
    workspace: &str,
    contents: &str,
    dependency_lock: &str,
) -> Result<crate::OpenTofuSourceBundleV1, QualificationHarnessError> {
    let bundle = crate::OpenTofuSourceBundleV1 {
        root_module_files: BTreeMap::from([("main.tf".into(), contents.into())]),
        variable_values: BTreeMap::new(),
        dependency_lock_file: dependency_lock.into(),
        module_manifest: Vec::new(),
        requested_workspace: workspace.into(),
    };
    bundle
        .validate()
        .map_err(|_| QualificationHarnessError::Onboarding)?;
    Ok(bundle)
}

impl QualificationProtectedSetup for OpentofuQualificationAdapter {
    fn metadata(&self) -> QualificationAdapterMetadata {
        metadata()
    }

    #[allow(clippy::too_many_lines)]
    fn setup(
        &self,
        input: QualificationProtectedSetupInput<'_>,
        setup_credential: &[u8],
    ) -> Result<QualificationSetupHandoffV1, QualificationHarnessError> {
        const TOOL_SHA256: &str =
            "638dd3fb9ecfa6fd9f54a0024b195b12b407c51ccee6f83b18a75a8be79f8214";
        const LOCK_SHA256: &str =
            "26d49718e8ef09f1693391fd84bf8ffa06afbb78f43b187faa72b68a022fcc19";
        if input.run_context.protected_environment != "qualification-opentofu"
            || input.provider_version != "1.9.0"
            || input.provider_artifact_sha256 != TOOL_SHA256
            || input.scenario_ids.is_empty()
            || !input.scenario_ids.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(QualificationHarnessError::Onboarding);
        }
        let setup: OpentofuQualificationSetupCredentialV1 =
            serde_json::from_slice(setup_credential)
                .map_err(|_| QualificationHarnessError::Onboarding)?;
        if setup.schema != "auths.opentofu.qualification-setup-credential/1"
            || serde_json_canonicalizer::to_vec(&setup)
                .map_err(|_| QualificationHarnessError::Onboarding)?
                != setup_credential
            || setup.backend_credential_base64url.contains('=')
            || setup.backend_credential_base64url.len() > 87_384
            || setup.dependency_lock.is_empty()
            || setup.dependency_lock.len() > 65_536
            || hex::encode(Sha256::digest(setup.dependency_lock.as_bytes())) != LOCK_SHA256
        {
            return Err(QualificationHarnessError::Onboarding);
        }
        let backend_credential = Base64UrlUnpadded::decode_vec(&setup.backend_credential_base64url)
            .map_err(|_| QualificationHarnessError::Onboarding)?;
        crate::connection::validate_onboarding(input.connection_descriptor, backend_credential)
            .map_err(|_| QualificationHarnessError::Onboarding)?;
        let backend_credential = Zeroizing::new(
            Base64UrlUnpadded::decode_vec(&setup.backend_credential_base64url)
                .map_err(|_| QualificationHarnessError::Onboarding)?,
        );
        let configuration_bytes = exact_family_configuration(input.profile_configurations)?;
        let configuration =
            crate::OpenTofuLocalAgentConfigurationV1::from_canonical_bytes(configuration_bytes)
                .map_err(|_| QualificationHarnessError::Onboarding)?;
        let descriptor = crate::connection::OpenTofuConnectionDescriptor::from_canonical_bytes(
            input.connection_descriptor,
        )
        .map_err(|_| QualificationHarnessError::Onboarding)?;
        let setup_root = tempfile::tempdir().map_err(|_| QualificationHarnessError::Onboarding)?;
        let provider_namespace = format!(
            "aq-{}-{}-{}",
            input.run_context.run_id,
            input.run_context.run_attempt,
            input.run_context.provider_run_id
        );
        let mut resources = Vec::with_capacity(input.scenario_ids.len());
        let mut vectors = Vec::with_capacity(input.scenario_ids.len());
        for scenario_id in input.scenario_ids {
            let workspace = format!("{provider_namespace}-{scenario_id}");
            let contents = format!(
                "terraform {{ required_providers {{ null = {{ source = \"hashicorp/null\" version = \"3.2.4\" }} }} }}\nresource \"null_resource\" \"qualification\" {{ triggers = {{ marker = \"{workspace}\" }} }}\n"
            );
            let bundle = qualification_bundle(&workspace, &contents, &setup.dependency_lock)?;
            let observed = crate::local_provider::ensure_qualification_workspace(
                setup_root.path(),
                &backend_credential,
                &descriptor,
                &configuration,
                &bundle,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| QualificationHarnessError::Onboarding)?
                    .as_secs(),
            )
            .map_err(|_| QualificationHarnessError::Onboarding)?;
            if observed.workspace != workspace || observed.state_serial != 0 {
                return Err(QualificationHarnessError::Onboarding);
            }
            let mut vector = serde_json::json!({
                "dependencyLock": setup.dependency_lock.clone(),
                "modules": [],
                "sourceFiles": [{"contents":contents,"path":"main.tf"}],
                "variables": [],
                "workspace": workspace,
            });
            if scenario_id == "boundary-plus-one" {
                vector["sourceFiles"] = serde_json::Value::Array(
                    (0..33)
                        .map(|index| {
                            serde_json::json!({
                                "contents":"resource \"null_resource\" \"x\" {}",
                                "path":format!("f{index}.tf"),
                            })
                        })
                        .collect(),
                );
            } else if scenario_id == "exact-boundary" {
                let mut files = Vec::with_capacity(32);
                files.push(serde_json::json!({"contents":contents,"path":"main.tf"}));
                files.extend((1..32).map(|index| {
                    serde_json::json!({
                        "contents":"# qualification boundary filler\n",
                        "path":format!("f{index:02}.tf"),
                    })
                }));
                vector["sourceFiles"] = serde_json::Value::Array(files);
            }
            let bytes = serde_json_canonicalizer::to_vec(&vector)
                .map_err(|_| QualificationHarnessError::Onboarding)?;
            let scenario_program = qualification_scenario_program(scenario_id)?;
            let input_base64url = Base64UrlUnpadded::encode_string(&bytes);
            let cases = scenario_program
                .cases()
                .iter()
                .map(|case| auths_profile_kit::QualificationSetupCaseV1 {
                    case_id: case.case_id().into(),
                    input_base64url: input_base64url.clone(),
                })
                .collect();
            vectors.push(auths_profile_kit::QualificationSetupVectorV1 {
                id: scenario_id.clone(),
                scenario_program,
                cases,
                failpoint: scenario_id
                    .strip_prefix("crash-")
                    .and_then(auths_profile_kit::QualificationFailpoint::from_token),
            });
            resources.push(format!(
                "workspace-sha256:{}",
                hex::encode(Sha256::digest(workspace.as_bytes()))
            ));
        }
        resources.sort();
        let run_reference = QualificationRunReference {
            schema: "auths.profile-qualification-run-reference/1".into(),
            domain: "opentofu".into(),
            target: input.run_context.target,
            candidate_revision: input.run_context.candidate_revision.clone(),
            repository_id: input.run_context.repository_id.clone(),
            run_id: input.run_context.run_id.clone(),
            run_attempt: input.run_context.run_attempt,
            provider_run_id: input.run_context.provider_run_id.clone(),
            provider_namespace,
            connection_alias_sha256: hex::encode(Sha256::digest(input.connection_alias.as_bytes())),
            resource_references: resources,
            connection_generations: vec!["1".into()],
        };
        let handoff = QualificationSetupHandoffV1 {
            schema: "auths.profile-qualification-setup-handoff/1".into(),
            run_context: input.run_context.clone(),
            domain: "opentofu".into(),
            connection_alias: input.connection_alias.into(),
            run_reference,
            vectors,
        };
        handoff.validate()?;
        Ok(handoff)
    }
}

#[derive(Default)]
pub struct OpentofuQualificationEnvironment {
    prepared_plan: Option<String>,
}

impl QualificationCollectionAdapter for OpentofuQualificationAdapter {
    type Environment = OpentofuQualificationEnvironment;

    fn metadata(&self) -> QualificationAdapterMetadata {
        metadata()
    }

    fn open(
        &self,
        context: &QualificationRunContext,
        handoff: &QualificationSetupHandoffV1,
    ) -> Result<Self::Environment, QualificationHarnessError> {
        if handoff.run_context != *context || handoff.domain != "opentofu" {
            return Err(QualificationHarnessError::InvalidSetupHandoff);
        }
        Ok(OpentofuQualificationEnvironment::default())
    }

    fn invoke_phase(
        &self,
        environment: &mut Self::Environment,
        client: &QualificationPhaseClient,
        connection_alias: &str,
        vector: &QualificationVector,
        phase_index: u8,
        role: QualificationOperationRole,
        profile: &str,
    ) -> Result<QualificationCollectedOperation, QualificationHarnessError> {
        match (phase_index, role, profile) {
            (1, QualificationOperationRole::Preflight, "auths.opentofu.plan-preflight/1") => {
                if environment.prepared_plan.is_some() {
                    return Err(QualificationHarnessError::Invocation);
                }
                let outcome = client.invoke_installed(
                    connection_alias,
                    &vector
                        .cases
                        .first()
                        .ok_or(QualificationHarnessError::Invocation)?
                        .input,
                )?;
                if outcome.kind == "completed" {
                    environment.prepared_plan = Some(
                        outcome
                            .value
                            .as_ref()
                            .and_then(|value| value.get("prepared_plan"))
                            .and_then(serde_json::Value::as_str)
                            .filter(|value| (49..=96).contains(&value.len()))
                            .ok_or(QualificationHarnessError::Invocation)?
                            .into(),
                    );
                }
            }
            (2, QualificationOperationRole::Effect, "auths.opentofu.saved-plan-apply/1") => {
                if qualification_pre_admission_attempt_count(&vector.id).is_some() {
                    let outcome = client.invoke_installed(
                        connection_alias,
                        &vector
                            .cases
                            .first()
                            .ok_or(QualificationHarnessError::Invocation)?
                            .input,
                    )?;
                    if outcome.kind != "unavailable" {
                        return Err(QualificationHarnessError::Invocation);
                    }
                    return Ok(QualificationCollectedOperation {
                        role,
                        profile: profile.into(),
                    });
                }
                let prepared_plan = environment
                    .prepared_plan
                    .take()
                    .ok_or(QualificationHarnessError::Invocation)?;
                let input = serde_json::to_vec(&serde_json::json!({
                    "preparedPlan": prepared_plan,
                }))
                .map_err(|_| QualificationHarnessError::Invocation)?;
                client.invoke_installed(connection_alias, &input)?;
            }
            _ => return Err(QualificationHarnessError::Invocation),
        }
        Ok(QualificationCollectedOperation {
            role,
            profile: profile.into(),
        })
    }
}

impl QualificationProtectedObserver for OpentofuQualificationAdapter {
    type Environment = OpentofuProtectedObserverEnvironment;

    fn metadata(&self) -> QualificationAdapterMetadata {
        metadata()
    }

    fn open(
        &self,
        context: &QualificationRunContext,
        reference: Option<&QualificationRunReference>,
    ) -> Result<Self::Environment, QualificationHarnessError> {
        let reference = reference.ok_or(QualificationHarnessError::ProviderTruth)?;
        if reference.domain != "opentofu"
            || reference.target != context.target
            || reference.candidate_revision != context.candidate_revision
            || reference.repository_id != context.repository_id
            || reference.run_id != context.run_id
            || reference.run_attempt != context.run_attempt
            || reference.provider_run_id != context.provider_run_id
            || reference
                .resource_references
                .iter()
                .any(|value| !value.starts_with("workspace-sha256:"))
        {
            return Err(QualificationHarnessError::ProviderTruth);
        }
        let credential = protected_credential(
            "QUALIFICATION_OBSERVER_CREDENTIAL",
            QualificationHarnessError::ProviderTruth,
        )?;
        let material =
            parse_observer_credential(&credential, &QualificationHarnessError::ProviderTruth)?;
        Ok(OpentofuProtectedObserverEnvironment {
            backend_credential: material.backend_credential,
            descriptor: material.descriptor,
            configuration: material.configuration,
            dependency_lock: material.dependency_lock,
            observer_root: tempfile::tempdir()
                .map_err(|_| QualificationHarnessError::ProviderTruth)?,
            reference: reference.clone(),
        })
    }

    fn provider_truth(
        &self,
        environment: &OpentofuProtectedObserverEnvironment,
        scenario_id: &str,
        phase: &QualificationCollectedOperation,
        instance: &QualificationCommonOperationInstanceEvidence,
        in_row_domain_facts: &[u8],
    ) -> Result<QualificationProviderTruth, QualificationHarnessError> {
        if !metadata().family.contains(&phase.profile.as_str())
            || instance.effect == QualificationEffect::Possible
        {
            return Err(QualificationHarnessError::ProviderTruth);
        }
        validate_provider_truth_facts(in_row_domain_facts, instance.effect)?;
        let expected: OpentofuProviderTruthFacts = serde_json::from_slice(in_row_domain_facts)
            .map_err(|_| QualificationHarnessError::ProviderTruth)?;
        let workspace = format!("{}-{scenario_id}", environment.reference.provider_namespace);
        let contents = qualification_source(&workspace);
        let bundle = qualification_bundle(&workspace, &contents, &environment.dependency_lock)?;
        let observed = crate::local_provider::observe_qualification_workspace(
            environment.observer_root.path(),
            &environment.backend_credential,
            &environment.descriptor,
            &environment.configuration,
            &bundle,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| QualificationHarnessError::ProviderTruth)?
                .as_secs(),
        )
        .map_err(|_| QualificationHarnessError::ProviderTruth)?;
        let workspace_sha256 = hex::encode(Sha256::digest(workspace.as_bytes()));
        let lineage_sha256 = hex::encode(Sha256::digest(observed.state_lineage.as_bytes()));
        let serial_matches = if phase.profile == "auths.opentofu.plan-preflight/1" {
            !expected.applied
                && expected.before_serial == expected.after_serial
                && (observed.state_serial == expected.after_serial
                    || observed.state_serial == expected.after_serial.saturating_add(1))
        } else {
            observed.state_serial == expected.after_serial
        };
        if expected.workspace_sha256 != workspace_sha256
            || expected.state_lineage_sha256 != lineage_sha256
            || expected.applied != (instance.effect == QualificationEffect::Applied)
            || !serial_matches
        {
            return Err(QualificationHarnessError::ProviderTruth);
        }
        Ok(QualificationProviderTruth {
            operation_id: instance.operation_id.clone(),
            provider_run_id: environment.reference.provider_run_id.clone(),
            effect: instance.effect,
            provider_calls: instance.counters.provider_calls,
            commitment: Sha256::digest(in_row_domain_facts).into(),
            domain_facts: in_row_domain_facts.to_vec(),
            provider_version: "1.9.0".into(),
            provider_artifact_sha256:
                "638dd3fb9ecfa6fd9f54a0024b195b12b407c51ccee6f83b18a75a8be79f8214".into(),
        })
    }

    fn validate_receipt_payload(
        &self,
        _environment: &OpentofuProtectedObserverEnvironment,
        phase: &QualificationCollectedOperation,
        instance: &QualificationCommonOperationInstanceEvidence,
        truth: &QualificationProviderTruth,
        claims: &[QualificationCommonReceiptClaims],
    ) -> Result<(), QualificationHarnessError> {
        if !metadata().family.contains(&phase.profile.as_str())
            || truth.operation_id != instance.operation_id
            || truth.effect != instance.effect
            || claims.iter().any(|claim| {
                claim.operation_id != instance.operation_id || claim.profile != phase.profile
            })
        {
            return Err(QualificationHarnessError::Receipt);
        }
        Ok(())
    }

    fn validate_domain_scenario(
        &self,
        _environment: &OpentofuProtectedObserverEnvironment,
        program: &QualificationScenarioProgramV1,
        _operations: &[auths_profile_kit::QualificationRedactedOperation],
        _truths: &[QualificationProviderTruth],
    ) -> Result<(), QualificationHarnessError> {
        if !metadata().scenarios.contains(&program.id()) {
            Ok(())
        } else {
            Err(QualificationHarnessError::PrerequisiteUnavailable(
                "OpenTofu scenario predicate is not implemented",
            ))
        }
    }

    fn cleanup(
        &self,
        context: &QualificationRunContext,
        _reference: Option<&QualificationRunReference>,
    ) -> Result<QualificationCleanupEvidence, QualificationHarnessError> {
        if context.protected_environment != "qualification-opentofu" {
            return Err(QualificationHarnessError::Cleanup);
        }
        let credential = protected_credential(
            "QUALIFICATION_CLEANUP_CREDENTIAL",
            QualificationHarnessError::Cleanup,
        )?;
        let material = parse_observer_credential(&credential, &QualificationHarnessError::Cleanup)?;
        let namespace = format!(
            "aq-{}-{}-{}",
            context.run_id, context.run_attempt, context.provider_run_id
        );
        let workspace = format!("{namespace}-cleanup-probe");
        let contents = qualification_source(&workspace);
        let bundle = qualification_bundle(&workspace, &contents, &material.dependency_lock)
            .map_err(|_| QualificationHarnessError::Cleanup)?;
        let root = tempfile::tempdir().map_err(|_| QualificationHarnessError::Cleanup)?;
        crate::local_provider::cleanup_qualification_namespace(
            root.path(),
            &material.backend_credential,
            &material.descriptor,
            &material.configuration,
            &bundle,
            &namespace,
        )
        .map_err(|_| QualificationHarnessError::Cleanup)?;
        Ok(QualificationCleanupEvidence {
            provider_resources_destroyed: true,
            connection_disabled: true,
            credentials_revoked: true,
            residual_resource_count: 0,
        })
    }
}

pub struct OpentofuProtectedObserverEnvironment {
    backend_credential: Zeroizing<Vec<u8>>,
    descriptor: crate::connection::OpenTofuConnectionDescriptor,
    configuration: crate::OpenTofuLocalAgentConfigurationV1,
    dependency_lock: String,
    observer_root: tempfile::TempDir,
    reference: QualificationRunReference,
}

struct OpentofuProtectedMaterial {
    backend_credential: Zeroizing<Vec<u8>>,
    descriptor: crate::connection::OpenTofuConnectionDescriptor,
    configuration: crate::OpenTofuLocalAgentConfigurationV1,
    dependency_lock: String,
}

fn parse_observer_credential(
    bytes: &[u8],
    error: &QualificationHarnessError,
) -> Result<OpentofuProtectedMaterial, QualificationHarnessError> {
    let value: OpentofuQualificationObserverCredentialV1 =
        serde_json::from_slice(bytes).map_err(|_| error.clone())?;
    if value.schema != "auths.opentofu.qualification-observer-credential/1"
        || serde_json_canonicalizer::to_vec(&value).map_err(|_| error.clone())? != bytes
        || value.backend_credential_base64url.contains('=')
        || value.connection_descriptor_base64url.contains('=')
        || value.configuration_base64url.contains('=')
        || value.dependency_lock.is_empty()
        || value.dependency_lock.len() > 65_536
        || hex::encode(Sha256::digest(value.dependency_lock.as_bytes()))
            != "26d49718e8ef09f1693391fd84bf8ffa06afbb78f43b187faa72b68a022fcc19"
    {
        return Err(error.clone());
    }
    let backend_credential = Zeroizing::new(
        Base64UrlUnpadded::decode_vec(&value.backend_credential_base64url)
            .map_err(|_| error.clone())?,
    );
    let descriptor_bytes = Base64UrlUnpadded::decode_vec(&value.connection_descriptor_base64url)
        .map_err(|_| error.clone())?;
    let configuration_bytes =
        Base64UrlUnpadded::decode_vec(&value.configuration_base64url).map_err(|_| error.clone())?;
    let descriptor =
        crate::connection::OpenTofuConnectionDescriptor::from_canonical_bytes(&descriptor_bytes)
            .map_err(|_| error.clone())?;
    let configuration =
        crate::OpenTofuLocalAgentConfigurationV1::from_canonical_bytes(&configuration_bytes)
            .map_err(|_| error.clone())?;
    Ok(OpentofuProtectedMaterial {
        backend_credential,
        descriptor,
        configuration,
        dependency_lock: value.dependency_lock,
    })
}

fn protected_credential(
    name: &str,
    error: QualificationHarnessError,
) -> Result<Zeroizing<Vec<u8>>, QualificationHarnessError> {
    let encoded = std::env::var(name).map_err(|_| error.clone())?;
    if encoded.is_empty() || encoded.len() > 174_764 || encoded.contains('=') {
        return Err(error.clone());
    }
    let bytes = Base64UrlUnpadded::decode_vec(&encoded).map_err(|_| error.clone())?;
    if bytes.is_empty() || bytes.len() > 131_072 {
        return Err(error);
    }
    Ok(Zeroizing::new(bytes))
}

fn qualification_source(workspace: &str) -> String {
    format!(
        "terraform {{ required_providers {{ null = {{ source = \"hashicorp/null\" version = \"3.2.4\" }} }} }}\nresource \"null_resource\" \"qualification\" {{ triggers = {{ marker = \"{workspace}\" }} }}\n"
    )
}

fn metadata() -> QualificationAdapterMetadata {
    QualificationAdapterMetadata {
        domain: "opentofu",
        family: &[
            "auths.opentofu.plan-preflight/1",
            "auths.opentofu.saved-plan-apply/1",
        ],
        targets: &[QualificationTarget::LinuxX86_64],
        protected_environment: "qualification-opentofu",
        scenarios: SCENARIOS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn provider_truth_requires_committed_state_and_effect_algebra() {
        let facts = json!({
            "afterSerial":9,
            "applied":false,
            "appliedMarkerSha256":null,
            "artifactSha256":"11".repeat(32),
            "beforeSerial":9,
            "planSha256":"22".repeat(32),
            "stateLineageSha256":"33".repeat(32),
            "workspaceSha256":"44".repeat(32)
        });
        let bytes = serde_json_canonicalizer::to_vec(&facts).unwrap();
        validate_provider_truth_facts(&bytes, QualificationEffect::NotApplied).unwrap();

        let mut raw = facts.clone();
        raw.as_object_mut()
            .unwrap()
            .insert("stateLineage".into(), json!("raw-lineage"));
        assert!(
            validate_provider_truth_facts(
                &serde_json_canonicalizer::to_vec(&raw).unwrap(),
                QualificationEffect::NotApplied,
            )
            .is_err()
        );
    }
}
