use crate::prelude::*;
use crate::root;
use auths_config::{AgentConfig, AgentPlatform, ReceiptSigningRole};
use auths_profile_kit::{
    ProfileApi, ProfilePackage, ProfileQualification, ProfileRoster, QualificationAttestation,
    QualificationCollectedScenario, QualificationCollectionAdapter,
    QualificationCommonPhaseEvidence, QualificationCrashActionContextV1,
    QualificationDecisionSnapshotV1, QualificationDurableDecisionAckV1,
    QualificationEvidenceLedger, QualificationEvidenceLedgerPlanV1,
    QualificationEvidenceLedgerRecord, QualificationEvidenceLedgerTrustRegistry,
    QualificationEvidenceSource, QualificationEvidenceSourceTrustRegistry, QualificationIndex,
    QualificationInstalledClient, QualificationJournalDecisionContext, QualificationObservation,
    QualificationObservationRecord, QualificationObserverTrustRegistry, QualificationPhaseClient,
    QualificationProtectedObserver, QualificationProtectedSetupInput, QualificationRecord,
    QualificationReleaseBuild, QualificationRunReference, QualificationScenarioManifest,
    QualificationSetupHandoffV1, QualificationTarget, QualificationTrustIdentity,
    QualificationTrustRegistry, QualificationVerifiedRecordBinding,
    qualification_state_directory_commitment, validate_qualification_key_separation,
    validate_qualification_trust_separation,
};
use auths_receipts::{
    ReceiptTrustAnchor, ReceiptTrustAnchorRole, ReceiptTrustAnchors, decode_receipt_trust_anchors,
    encode_receipt_trust_anchors,
};
use base64ct::Encoding as _;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CLOSURE_DOMAIN: &[u8] = b"auths.profile-qualification-closure/1\0";
const ROSTER_PATH: &str = "product/runtime/auths-node/profile-packages.json";
const LAUNCH_PROJECTION_PATH: &str =
    "product/runtime/auths-node/src/generated/profile_launch_projection.json";
const TRUST_PATH: &str = "release/qualification/v1/trust-keys.json";
const OBSERVER_TRUST_PATH: &str = "release/qualification/v1/observer-trust-keys.json";
const EVIDENCE_SOURCE_TRUST_PATH: &str = "release/qualification/v1/evidence-source-trust-keys.json";
const EVIDENCE_LEDGER_TRUST_PATH: &str = "release/qualification/v1/evidence-ledger-trust-keys.json";
const INDEX_PATH: &str = "release/qualification/v1/index.json";
const CLOSURE_MANIFEST_PATH: &str = "release/qualification/v1/closure-manifest.json";
const IMPORT_TRANSACTION_PATH: &str = "release/qualification/v1/import-transaction.json";
const PROTECTED_CLOSURE_MANIFEST: &[u8] =
    include_bytes!("../../release/qualification/v1/closure-manifest.json");
const QUALIFICATION_FAILPOINT_IDS: [&str; 12] = [
    "after-command",
    "after-decision",
    "after-entry-marker",
    "after-execution-receipt",
    "after-lease",
    "after-observation",
    "after-provider-result",
    "after-request-write",
    "after-reread",
    "after-reservation",
    "after-terminal",
    "before-decision",
];
const QUALIFICATION_CRASH_SCENARIO_IDS: [&str; 12] = [
    "crash-after-command",
    "crash-after-decision",
    "crash-after-entry-marker",
    "crash-after-execution-receipt",
    "crash-after-lease",
    "crash-after-observation",
    "crash-after-provider-result",
    "crash-after-request-write",
    "crash-after-reread",
    "crash-after-reservation",
    "crash-after-terminal",
    "crash-before-decision",
];
const COMMON_QUALIFICATION_SCENARIO_IDS: [&str; 24] = [
    "boundary-plus-one",
    "changed-input-conflict",
    "configuration-mismatch",
    "connection-substitution",
    "crash-after-command",
    "crash-after-decision",
    "crash-after-entry-marker",
    "crash-after-execution-receipt",
    "crash-after-lease",
    "crash-after-observation",
    "crash-after-provider-result",
    "crash-after-request-write",
    "crash-after-reread",
    "crash-after-reservation",
    "crash-after-terminal",
    "crash-before-decision",
    "exact-boundary",
    "happy-path",
    "malformed-input",
    "principal-substitution",
    "provider-denial",
    "quota-final-capacity",
    "replay",
    "stale-evidence",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImportTransaction {
    schema: String,
    candidate_revision: String,
    promotion_base_revision: String,
    domain: String,
    target: QualificationTarget,
    qualification_id: String,
    phase: ImportPhase,
    outputs: Vec<ImportOutput>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ImportPhase {
    Promote,
    Rollback,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImportOutput {
    role: ImportOutputRole,
    path: String,
    old_sha256: Option<String>,
    old_bytes_hex: Option<String>,
    new_sha256: String,
    new_bytes_hex: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ImportOutputRole {
    Attestation,
    Index,
    LaunchProjection,
    Roster,
}

type CandidateCollection = auths_profile_kit::QualificationCandidateCollectionV1;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProtectedObservedProviderRun {
    schema: String,
    run_reference: QualificationRunReference,
    scenarios: Vec<ProtectedObservedScenario>,
    provider_truth: Vec<ProtectedObservedTruth>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProtectedObservedScenario {
    scenario_id: String,
    scenario_program_sha256: String,
    domain_predicate_sha256: String,
    operations: Vec<auths_profile_kit::QualificationRedactedOperation>,
}

fn scenario_predicate_sha256(
    program: &auths_profile_kit::QualificationScenarioProgramV1,
    failpoint: Option<auths_profile_kit::QualificationFailpoint>,
    operations: &[auths_profile_kit::QualificationRedactedOperation],
    truths: &[auths_profile_kit::QualificationProviderTruth],
) -> Result<String, String> {
    let truth_projection = truths
        .iter()
        .map(|truth| {
            Ok(serde_json::json!({
                "commitmentSha256": hex::encode(truth.commitment),
                "domainFactsSha256": hex::encode(Sha256::digest(&truth.domain_facts)),
                "effect": truth.effect,
                "operationId": truth.operation_id,
                "providerArtifactSha256": truth.provider_artifact_sha256,
                "providerCalls": truth.provider_calls,
                "providerRunId": truth.provider_run_id,
                "providerVersion": truth.provider_version,
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let projection = serde_json::json!({
        "failpoint": failpoint,
        "operations": operations,
        "programSha256": program.sha256().map_err(string_error)?,
        "truths": truth_projection,
    });
    Ok(hex::encode(Sha256::digest(
        serde_json_canonicalizer::to_vec(&projection).map_err(string_error)?,
    )))
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProtectedObservedTruth {
    operation_id: String,
    provider_run_id: String,
    provider_version: String,
    provider_artifact_sha256: String,
    effect: auths_profile_kit::QualificationEffect,
    provider_calls: u32,
    commitment_sha256: String,
    domain_facts: Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProtectedCleanupProviderRun {
    schema: String,
    repository_id: String,
    candidate_revision: String,
    target: QualificationTarget,
    protected_environment: String,
    run_id: String,
    run_attempt: u32,
    provider_run_id: String,
    evidence: auths_profile_kit::QualificationCleanupEvidence,
    completed_at_unix_seconds: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct QualificationProviderMatrix {
    schema: String,
    domain: String,
    runs: Vec<QualificationProviderMatrixRun>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationProviderMatrixRun {
    contract: Value,
    id: String,
    provider: String,
    provider_artifact_sha256: String,
    provider_version: String,
    scenario_ids: Vec<String>,
    target: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct QualificationRequirements {
    schema: String,
    domain: String,
    requirements: Vec<QualificationRequirement>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationRequirement {
    requirement_id: String,
    profile_references: Vec<String>,
    authoritative_spec_path: String,
    authoritative_spec_section: String,
    production_source_owners: Vec<String>,
    unit_tests: Vec<String>,
    mutation_tests: Vec<String>,
    live_scenario_ids: Vec<String>,
    crash_point_ids: Vec<String>,
    receipt_claim_ids: Vec<String>,
    provider_truth_report_fields: Vec<String>,
    credential_role: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationFailpointCoverage {
    schema: String,
    domain: String,
    provider_truth_fields: Vec<String>,
    boundaries: Vec<QualificationFailpointBoundary>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationFailpointBoundary {
    crash_scenario_id: String,
    failpoint: String,
    after_transition: Option<String>,
    before_transition: Option<String>,
    applicable_effects: Vec<String>,
    counter_assertions: Vec<String>,
    recovery_call: String,
    provider_truth_required: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct QualificationOperationPlans {
    schema: String,
    domain: String,
    plans: Vec<QualificationOperationPlan>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationOperationPlan {
    operations: Vec<QualificationPlannedOperation>,
    scenario_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct QualificationPlannedOperation {
    lifecycle_owner: bool,
    profile: String,
    provider_mutation_owner: bool,
    role: auths_profile_kit::QualificationOperationRole,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QualificationToolchainPins {
    schema: String,
    rust: String,
    node: String,
    python: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerifiedQualificationReleaseBuildBinding {
    schema: String,
    verified_at_unix_seconds: u64,
    repository_id: String,
    workflow_path: String,
    workflow_revision: String,
    run_id: String,
    run_attempt: u32,
    run_label: String,
    retention_days: u16,
    projection_artifact_id: String,
    projection_artifact_name: String,
    projection_uploaded_archive_sha256: String,
    projection_uploaded_archive_bytes: u64,
    projection_created_at_unix_seconds: u64,
    projection_expires_at_unix_seconds: u64,
    release_build_sha256: String,
    qualification_surface_sha256: String,
    qualification_surface: VerifiedQualificationReleaseSurface,
    hosted_metadata_sha256: String,
    provenance_verification_sha256: String,
    provenance_bundle_sha256: String,
    trusted_root_sha256: String,
    provenance_verifier_sha256: String,
    provenance_verifier_version: String,
    release_build_verifier_sha256: String,
    attester_tools: VerifiedAttesterToolsBinding,
    artifacts: Vec<VerifiedQualificationReleaseArtifact>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerifiedQualificationReleaseSurface {
    schema: String,
    candidate_revision: String,
    policy_sha256: String,
    production_feature_set: Vec<String>,
    qualification_feature_set: Vec<String>,
    production_members: Vec<VerifiedQualificationReleaseSurfaceMember>,
    qualification_members: Vec<VerifiedQualificationReleaseSurfaceMember>,
    reviewed_difference: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerifiedQualificationReleaseSurfaceMember {
    path: String,
    sha256: String,
    bytes: u64,
    mode: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationReleaseSurfacePolicyBinding {
    schema: String,
    production_feature_set: Vec<String>,
    qualification_feature_set: Vec<String>,
    production_member_paths: Vec<String>,
    qualification_member_paths: Vec<String>,
    reviewed_difference: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerifiedAttesterToolsBinding {
    schema: String,
    verified_at_unix_seconds: u64,
    repository_id: String,
    workflow_path: String,
    workflow_revision: String,
    run_id: String,
    run_attempt: u32,
    retention_days: u16,
    artifact_id: String,
    artifact_name: String,
    uploaded_archive_sha256: String,
    uploaded_archive_bytes: u64,
    created_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    manifest_sha256: String,
    attester_revision: String,
    gh_version: String,
    runner_image_os: String,
    runner_image_version: String,
    runner_label: String,
    members: Vec<VerifiedAttesterToolMember>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VerifiedAttesterToolMember {
    path: String,
    sha256: String,
    mode: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerifiedQualificationReleaseArtifact {
    role: String,
    name: String,
    artifact_id: String,
    uploaded_archive_sha256: String,
    uploaded_archive_bytes: u64,
    created_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    member_path: String,
    member_sha256: String,
    bytes: u64,
}

const MAX_CANDIDATE_COLLECTION_BYTES: u64 = 67_108_864;
const RELEASE_QUALIFICATION_PROFILES: [(&str, &str); 5] = [
    ("auths.opentofu.plan-preflight/1", "opentofu"),
    ("auths.opentofu.saved-plan-apply/1", "opentofu"),
    ("auths.postgresql.bounded-update/1", "postgresql"),
    ("auths.postgresql.update-preflight/1", "postgresql"),
    ("auths.stripe.refund/1", "stripe"),
];
const VERIFIED_RELEASE_ARTIFACT_ROLES: [&str; 9] = [
    "production-agent",
    "python-native",
    "python-profile-opentofu",
    "python-profile-postgresql",
    "python-profile-stripe",
    "python-wheel",
    "qualification-agent",
    "typescript-native",
    "typescript-package",
];

pub(crate) fn profile_qualification_command(arguments: &[String]) -> Result<(), String> {
    let Some(command) = arguments.first().map(String::as_str) else {
        return Err(usage());
    };
    match command {
        "closure" => {
            let domain = exact_option(&arguments[1..], "--domain")?;
            let closure = semantic_closure(&root(), &domain)?;
            println!(
                "{}",
                serde_json_canonicalizer::to_string(&closure).map_err(string_error)?
            );
            Ok(())
        }
        "status" => status(&arguments[1..]),
        "verify" => {
            let path = exact_option(&arguments[1..], "--attestation")?;
            verify_path(&root(), Path::new(&path), true).map(|_| ())
        }
        "import" => {
            let path = exact_option(&arguments[1..], "--attestation")?;
            import(&root(), Path::new(&path))
        }
        "check" => check_arguments(&arguments[1..]),
        "release-check" if arguments.len() == 1 => qualification_release_check(&root()),
        "validate-workflow-inputs" => validate_workflow_inputs(&root()),
        "preflight-key-separation" => preflight_key_separation_arguments(&arguments[1..]),
        "setup-row" => setup_arguments(&arguments[1..]),
        "verify-uploaded" => verify_uploaded_arguments(&arguments[1..]),
        "installed-verify" => installed_verify_arguments(&arguments[1..]),
        "build-ledger-plan" => build_ledger_plan_arguments(&arguments[1..]),
        "build-cleanup-contexts" => build_cleanup_contexts_arguments(&arguments[1..]),
        "build-proposal" => build_proposal_arguments(&arguments[1..]),
        "assemble-evidence" => assemble_evidence_arguments(&arguments[1..]),
        "build-observation-record" => build_observation_record_arguments(&arguments[1..]),
        "package-observation" => package_observation_arguments(&arguments[1..]),
        "collect" => collect_arguments(&arguments[1..]),
        "observe" => aggregate_observation_arguments(&arguments[1..]),
        "observe-row" => observe_arguments(&arguments[1..]),
        "cleanup" => cleanup_arguments(&arguments[1..]),
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: cargo xtask profile qualification <closure --domain <domain>|status [--domain <domain>]|build-ledger-plan --domain <domain> --target <target> --environment <token> --provider-run <id> --output <path>|build-cleanup-contexts --domain <domain> --target <target> --environment <token> --output <directory>|setup-row --domain <domain> --target <target> --environment <token> --provider-run <id> --agent-config <path> --output <path>|build-proposal --domain <domain> --target <target> --collections <directory> --common-evidence <directory> --release-build <path> --output <path>|installed-verify --proposal <path> --packages <directory> --output <path>|assemble-evidence --proposal <path> --aggregate <directory> --installed <path> --supplemental <directory> --output <directory>|build-observation-record --proposal <path> --evidence <directory> --release-build <path> --output <path>|package-observation --proposal <path> --observation <signed-observation> --cleanup <cleanup-report> --output <directory>|collect --domain <domain> --target <target> --environment <token> --provider-run <id> --setup-handoff <path> --output <directory>|observe --proposal <path> --collections <directory> --common-evidence <directory> --receipt-trust <path> --output <directory>|observe-row --domain <domain> --target <target> --environment <token> --provider-run <id> --candidate-evidence <path> --common-evidence <path> --output <directory>|cleanup --domain <domain> --target <target> --run-context <path> --output <path>|preflight-key-separation --ledger-plan <path> --receipt-trust <path>|verify-uploaded --artifact <directory> --output <verified-record>|verify --attestation <path>|import --attestation <path>|check [--domain <domain>|--all]|release-check|validate-workflow-inputs>".into()
}

fn setup_arguments(arguments: &[String]) -> Result<(), String> {
    use std::io::Read as _;
    const FLAGS: [&str; 6] = [
        "--domain",
        "--target",
        "--environment",
        "--provider-run",
        "--agent-config",
        "--output",
    ];
    if arguments.len() != FLAGS.len() * 2
        || arguments
            .chunks_exact(2)
            .zip(FLAGS)
            .any(|(pair, flag)| pair[0] != flag || pair[1].is_empty())
    {
        return Err(usage());
    }
    let repository = root();
    let domain = &arguments[1];
    let target = QualificationTarget::parse(&arguments[3]).map_err(string_error)?;
    let environment = &arguments[5];
    let provider_run_id = &arguments[7];
    let domain_context = load_domain(&repository, domain)?;
    if env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || !domain_context
            .package
            .qualification()
            .targets()
            .contains(&target)
        || domain_context
            .package
            .qualification()
            .protected_environment()
            != environment
        || validate_secret_zone(
            &["SETUP_CREDENTIAL"],
            &[
                "MUTATION_CREDENTIAL",
                "RUNTIME_READ_CREDENTIAL",
                "OBSERVER_CREDENTIAL",
                "CLEANUP_CREDENTIAL",
                "DECISION_RECEIPT_SEED",
                "EXECUTION_RECEIPT_SEED",
                "RECOVERY_SEED",
                "OBSERVER_SEED",
                "ATTESTATION_SEED",
            ],
        )
        .is_err()
    {
        return Err("protected setup inputs do not match the isolated setup zone".into());
    }
    let provider_run = require_provider_run(&repository, &domain_context, target, provider_run_id)?;
    let output_relative = PathBuf::from("target")
        .join("qualification-setup")
        .join(domain)
        .join(target.as_str())
        .join(provider_run_id)
        .join("setup-handoff.json");
    require_exact_output_path(&repository, Path::new(&arguments[11]), &output_relative)?;
    let output_parent = output_relative
        .parent()
        .ok_or_else(|| "protected setup output has no parent".to_owned())?;
    create_private_output_directory(&repository, output_parent)?;
    let descriptor_encoded = required_env("AUTHS_QUALIFICATION_CONNECTION_DESCRIPTOR_BASE64URL")?;
    if descriptor_encoded.is_empty()
        || descriptor_encoded.len() > 174_764
        || descriptor_encoded.contains('=')
    {
        return Err("protected setup descriptor is malformed".into());
    }
    let connection_descriptor =
        base64ct::Base64UrlUnpadded::decode_vec(&descriptor_encoded).map_err(string_error)?;
    if connection_descriptor.is_empty() || connection_descriptor.len() > 131_072 {
        return Err("protected setup descriptor exceeds its bound".into());
    }
    let config_bytes = read_bounded(Path::new(&arguments[9]), 4_194_304)?;
    let config = AgentConfig::from_toml(
        std::str::from_utf8(&config_bytes).map_err(string_error)?,
        AgentPlatform::Linux,
    )
    .map_err(string_error)?;
    let workload_sha256 = required_sha256_env("AUTHS_QUALIFICATION_WORKLOAD_ID_SHA256")?;
    let connection_alias = unique_default_connection_alias(&config, domain, &workload_sha256)?;
    let operation_plans = load_operation_plans(&repository, &domain_context)?;
    let mut selected_profile_configurations = BTreeMap::new();
    for profile in operation_plans
        .values()
        .flatten()
        .map(|operation| operation.profile.as_str())
        .collect::<BTreeSet<_>>()
    {
        let source = config
            .profile_configurations()
            .get(profile)
            .ok_or_else(|| format!("agent config has no source for reviewed profile {profile}"))?;
        let path = Path::new(source.path());
        if !path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
            || fs::symlink_metadata(path)
                .map_err(string_error)?
                .file_type()
                .is_symlink()
        {
            return Err("protected setup profile configuration path is unsafe".into());
        }
        let bytes = read_bounded(path, u64::from(source.maximum_bytes()))?;
        if hex::encode(Sha256::digest(&bytes)) != source.sha256() {
            return Err(
                "protected setup profile configuration digest differs from agent config".into(),
            );
        }
        selected_profile_configurations.insert(profile.to_owned(), bytes);
    }
    let run_context = auths_profile_kit::QualificationRunContext {
        repository_id: required_env("GITHUB_REPOSITORY_ID")?,
        candidate_revision: required_env("QUALIFICATION_CANDIDATE_REVISION")?,
        target,
        protected_environment: environment.into(),
        run_id: required_env("GITHUB_RUN_ID")?,
        run_attempt: required_env("GITHUB_RUN_ATTEMPT")?
            .parse::<u32>()
            .map_err(string_error)?,
        provider_run_id: provider_run_id.into(),
    };
    run_context.validate().map_err(string_error)?;
    let mut encoded_credential = zeroize::Zeroizing::new(Vec::new());
    std::io::Read::take(std::io::stdin().lock(), 174_765)
        .read_to_end(&mut encoded_credential)
        .map_err(string_error)?;
    while encoded_credential
        .last()
        .is_some_and(u8::is_ascii_whitespace)
    {
        encoded_credential.pop();
    }
    if encoded_credential.is_empty()
        || encoded_credential.len() > 174_764
        || encoded_credential.contains(&b'=')
    {
        return Err("protected setup credential is malformed".into());
    }
    let encoded_credential_text = std::str::from_utf8(&encoded_credential).map_err(string_error)?;
    let setup_credential = zeroize::Zeroizing::new(
        base64ct::Base64UrlUnpadded::decode_vec(encoded_credential_text).map_err(string_error)?,
    );
    if setup_credential.is_empty() || setup_credential.len() > 131_072 {
        return Err("protected setup credential exceeds its bound".into());
    }
    let handoff = crate::profile_qualification_adapters::run_protected_setup(
        QualificationProtectedSetupInput {
            run_context: &run_context,
            connection_alias: &connection_alias,
            connection_descriptor: &connection_descriptor,
            provider_version: &provider_run.provider_version,
            provider_artifact_sha256: &provider_run.provider_artifact_sha256,
            scenario_ids: &provider_run.scenario_ids,
            profile_configurations: &selected_profile_configurations,
        },
        &setup_credential,
    )?;
    handoff.validate().map_err(string_error)?;
    if handoff.run_context != run_context
        || handoff.domain != *domain
        || handoff.connection_alias != connection_alias
        || handoff
            .vectors
            .iter()
            .map(|vector| &vector.id)
            .ne(provider_run.scenario_ids.iter())
    {
        return Err("protected setup returned a handoff outside reviewed policy".into());
    }
    let bytes = serde_json_canonicalizer::to_vec(&handoff).map_err(string_error)?;
    atomic_write_new(Path::new(&arguments[11]), &bytes)
}

fn unique_default_connection_alias(
    config: &AgentConfig,
    domain: &str,
    workload_sha256: &str,
) -> Result<String, String> {
    let workload = config
        .workloads()
        .iter()
        .filter(|workload| hex::encode(Sha256::digest(workload.id().as_bytes())) == workload_sha256)
        .collect::<Vec<_>>();
    if workload.len() != 1 {
        return Err("protected setup workload is not unique in agent configuration".into());
    }
    let connections = workload[0]
        .connections()
        .iter()
        .filter(|connection| connection.provider() == domain && connection.is_default())
        .collect::<Vec<_>>();
    if connections.len() != 1 {
        return Err("protected setup default connection is not unique".into());
    }
    Ok(connections[0].alias().into())
}

fn preflight_key_separation_arguments(arguments: &[String]) -> Result<(), String> {
    if arguments.len() != 4 || arguments[0] != "--ledger-plan" || arguments[2] != "--receipt-trust"
    {
        return Err(usage());
    }
    let repository = root();
    let plan = QualificationEvidenceLedgerPlanV1::from_json(&read_bounded(
        Path::new(&arguments[1]),
        262_144,
    )?)
    .map_err(string_error)?;
    let anchors = read_bounded(Path::new(&arguments[3]), 262_144)?;
    let attestation = load_trust_registry(&repository)?;
    let observer = load_observer_trust_registry(&repository)?;
    validate_complete_qualification_key_separation(
        &repository,
        &attestation,
        &observer,
        &anchors,
        &plan.recovery_key_id,
        &plan.recovery_public_key_base64url,
    )
}

fn exact_option(arguments: &[String], name: &str) -> Result<String, String> {
    if arguments.len() != 2 || arguments[0] != name || arguments[1].is_empty() {
        return Err(usage());
    }
    Ok(arguments[1].clone())
}

fn verify_uploaded_arguments(arguments: &[String]) -> Result<(), String> {
    if arguments.len() != 4
        || arguments[0] != "--artifact"
        || arguments[2] != "--output"
        || arguments[1].is_empty()
        || arguments[3].is_empty()
    {
        return Err(usage());
    }
    verify_uploaded(&root(), Path::new(&arguments[1]), Path::new(&arguments[3]))
}

fn installed_verify_arguments(arguments: &[String]) -> Result<(), String> {
    if arguments.len() != 6
        || arguments[0] != "--proposal"
        || arguments[2] != "--packages"
        || arguments[4] != "--output"
        || arguments[1].is_empty()
        || arguments[3].is_empty()
        || arguments[5].is_empty()
    {
        return Err(usage());
    }
    installed_verify(
        Path::new(&arguments[1]),
        Path::new(&arguments[3]),
        Path::new(&arguments[5]),
    )
}

fn build_ledger_plan_arguments(arguments: &[String]) -> Result<(), String> {
    const FLAGS: [&str; 5] = [
        "--domain",
        "--target",
        "--environment",
        "--provider-run",
        "--output",
    ];
    if arguments.len() != FLAGS.len() * 2
        || arguments
            .chunks_exact(2)
            .zip(FLAGS)
            .any(|(pair, flag)| pair[0] != flag || pair[1].is_empty())
    {
        return Err(usage());
    }
    build_ledger_plan(
        &arguments[1],
        QualificationTarget::parse(&arguments[3]).map_err(string_error)?,
        &arguments[5],
        &arguments[7],
        Path::new(&arguments[9]),
    )
}

fn build_cleanup_contexts_arguments(arguments: &[String]) -> Result<(), String> {
    const FLAGS: [&str; 4] = ["--domain", "--target", "--environment", "--output"];
    if arguments.len() != FLAGS.len() * 2
        || arguments
            .chunks_exact(2)
            .zip(FLAGS)
            .any(|(pair, flag)| pair[0] != flag || pair[1].is_empty())
    {
        return Err(usage());
    }
    build_cleanup_contexts(
        &arguments[1],
        QualificationTarget::parse(&arguments[3]).map_err(string_error)?,
        &arguments[5],
        Path::new(&arguments[7]),
    )
}

fn build_proposal_arguments(arguments: &[String]) -> Result<(), String> {
    if arguments.len() != 12
        || arguments[0] != "--domain"
        || arguments[2] != "--target"
        || arguments[4] != "--collections"
        || arguments[6] != "--common-evidence"
        || arguments[8] != "--release-build"
        || arguments[10] != "--output"
        || arguments.iter().skip(1).step_by(2).any(String::is_empty)
    {
        return Err(usage());
    }
    build_candidate_proposal(
        &arguments[1],
        QualificationTarget::parse(&arguments[3]).map_err(string_error)?,
        Path::new(&arguments[5]),
        Path::new(&arguments[7]),
        Path::new(&arguments[9]),
        Path::new(&arguments[11]),
    )
}

fn assemble_evidence_arguments(arguments: &[String]) -> Result<(), String> {
    if arguments.len() != 10
        || arguments[0] != "--proposal"
        || arguments[2] != "--aggregate"
        || arguments[4] != "--installed"
        || arguments[6] != "--supplemental"
        || arguments[8] != "--output"
        || arguments.iter().skip(1).step_by(2).any(String::is_empty)
    {
        return Err(usage());
    }
    assemble_observation_evidence(
        Path::new(&arguments[1]),
        Path::new(&arguments[3]),
        Path::new(&arguments[5]),
        Path::new(&arguments[7]),
        Path::new(&arguments[9]),
    )
}

fn build_observation_record_arguments(arguments: &[String]) -> Result<(), String> {
    if arguments.len() != 8
        || arguments[0] != "--proposal"
        || arguments[2] != "--evidence"
        || arguments[4] != "--release-build"
        || arguments[6] != "--output"
        || arguments.iter().skip(1).step_by(2).any(String::is_empty)
    {
        return Err(usage());
    }
    build_observation_record(
        Path::new(&arguments[1]),
        Path::new(&arguments[3]),
        Path::new(&arguments[5]),
        Path::new(&arguments[7]),
    )
}

fn package_observation_arguments(arguments: &[String]) -> Result<(), String> {
    if arguments.len() != 8
        || arguments[0] != "--proposal"
        || arguments[2] != "--observation"
        || arguments[4] != "--cleanup"
        || arguments[6] != "--output"
        || arguments.iter().skip(1).step_by(2).any(String::is_empty)
    {
        return Err(usage());
    }
    package_observation(
        Path::new(&arguments[1]),
        Path::new(&arguments[3]),
        Path::new(&arguments[5]),
        Path::new(&arguments[7]),
    )
}

fn aggregate_observation_arguments(arguments: &[String]) -> Result<(), String> {
    if arguments.len() != 10
        || arguments[0] != "--proposal"
        || arguments[2] != "--collections"
        || arguments[4] != "--common-evidence"
        || arguments[6] != "--receipt-trust"
        || arguments[8] != "--output"
        || arguments.iter().skip(1).step_by(2).any(String::is_empty)
    {
        return Err(usage());
    }
    aggregate_observation_reports(
        Path::new(&arguments[1]),
        Path::new(&arguments[3]),
        Path::new(&arguments[5]),
        Path::new(&arguments[7]),
        Path::new(&arguments[9]),
    )
}

const INSTALLED_PYTHON_LINK_FIXTURE: &str = r#"import hashlib, pathlib, sys, tarfile, zipfile
wheel, native, package, wasm = map(pathlib.Path, sys.argv[1:])
def safe(name):
    parts = pathlib.PurePosixPath(name).parts
    return bool(parts) and not name.startswith('/') and '..' not in parts and '\\' not in name
with zipfile.ZipFile(wheel) as archive:
    infos = archive.infolist()
    names = [row.filename for row in infos]
    assert len(names) == len(set(names)) and all(safe(name) for name in names)
    extensions = [row for row in infos if not row.is_dir() and row.filename.endswith(('.so', '.pyd', '.dylib'))]
    assert len(extensions) == 1
    assert hashlib.sha256(archive.read(extensions[0])).digest() == hashlib.sha256(native.read_bytes()).digest()
with tarfile.open(package, 'r:gz') as archive:
    rows = archive.getmembers()
    names = [row.name for row in rows]
    assert len(names) == len(set(names)) and all(safe(name) for name in names)
    assert all(row.isfile() or row.isdir() for row in rows)
    matches = [row for row in rows if row.name == 'package/wasm/auths_proof_wasm_bg.wasm' and row.isfile()]
    assert len(matches) == 1
    extracted = archive.extractfile(matches[0])
    assert extracted is not None
    assert hashlib.sha256(extracted.read()).digest() == hashlib.sha256(wasm.read_bytes()).digest()
"#;

const INSTALLED_PYTHON_IMPORT_FIXTURE: &str = r#"import auths
assert callable(auths.connect)
assert auths.ClientOptions.__module__.startswith('auths')
from auths.verify import verify_receipt, pinned_receipt_trust
assert callable(verify_receipt) and callable(pinned_receipt_trust)
"#;

const INSTALLED_PYTHON_PROFILE_IMPORT_FIXTURE: &str = r#"import importlib, pathlib, sys
source, domain = pathlib.Path(sys.argv[1]), sys.argv[2]
assert source.is_dir()
sys.path.insert(0, str(source))
profile = importlib.import_module(f'auths_profiles.{domain}')
expected = {'stripe':'Stripe', 'postgresql':'PostgreSQL', 'opentofu':'OpenTofu'}[domain]
assert callable(getattr(profile, expected))
assert profile.PROFILE_CLIENT_RUNTIME == 'auths.profile-client-runtime/1'
"#;

const INSTALLED_TYPESCRIPT_IMPORT_FIXTURE: &str = r#"import {connect} from '@auths-dev/sdk';
import {createVerifier, pinnedReceiptTrust} from '@auths-dev/sdk/verify';
if (typeof connect !== 'function' || typeof createVerifier !== 'function' || typeof pinnedReceiptTrust !== 'function') throw new Error('installed SDK exports drifted');
"#;

const INSTALLED_MUTATION_CORPUS: &[u8] = b"auths.profile-qualification-installed-mutations/1\0artifact-byte-flip\0python-native-link\0typescript-native-link\0no-source-import\0no-install-script\0";

#[allow(clippy::too_many_arguments)]
fn build_ledger_plan(
    domain: &str,
    target: QualificationTarget,
    environment: &str,
    provider_run_id: &str,
    output: &Path,
) -> Result<(), String> {
    reject_secret_bearing_environment()?;
    let repository = root();
    let candidate_revision = required_env("QUALIFICATION_CANDIDATE_REVISION")?;
    if !lower_hex(&candidate_revision, 40) || git_revision(&repository)? != candidate_revision {
        return Err("ledger plan candidate checkout differs from protected policy".into());
    }
    let context = load_domain_from_git(&repository, domain, &candidate_revision)?;
    if !context.package.qualification().targets().contains(&target)
        || context.package.qualification().protected_environment() != environment
    {
        return Err("ledger plan target or environment is not manifest-owned".into());
    }
    if !registered_token(provider_run_id) {
        return Err("qualification provider run is not an exact checked matrix row".into());
    }
    let provider_run = load_provider_matrix_at(&repository, &context, target, &candidate_revision)?
        .runs
        .into_iter()
        .find(|run| run.id == provider_run_id)
        .ok_or_else(|| {
            "qualification provider run is not an exact checked matrix row".to_owned()
        })?;
    let operation_plans = load_operation_plans_at(&repository, &context, &candidate_revision)?;
    let connection = context
        .package
        .domain()
        .connection()
        .ok_or_else(|| "qualified profile domain has no provider connection".to_owned())?;
    let workload_id_sha256 = required_sha256_env("AUTHS_QUALIFICATION_WORKLOAD_ID_SHA256")?;
    let mut phases = Vec::new();
    for scenario_id in &provider_run.scenario_ids {
        let scenario_program_sha256 =
            scenario_program_sha256_at(&repository, &context, &candidate_revision, scenario_id)?;
        let operations = operation_plans
            .get(scenario_id)
            .ok_or_else(|| "provider row scenario has no reviewed operation plan".to_owned())?;
        let operation_plan_sha256 = hex::encode(Sha256::digest(
            serde_json_canonicalizer::to_vec(operations).map_err(string_error)?,
        ));
        for (index, operation) in operations.iter().enumerate() {
            let profile = context
                .package
                .profiles()
                .iter()
                .find(|profile| {
                    format!("{}/{}", profile.id(), profile.version()) == operation.profile
                })
                .ok_or_else(|| "reviewed phase profile is absent from its package".to_owned())?;
            phases.push(auths_profile_kit::QualificationEvidencePhasePlanV1 {
                scenario_id: scenario_id.clone(),
                phase_index: u8::try_from(index + 1)
                    .map_err(|_| "reviewed phase index exceeds its hard bound".to_owned())?,
                role: operation.role,
                profile: operation.profile.clone(),
                failpoint: expected_failpoint(scenario_id),
                operation_plan_sha256: operation_plan_sha256.clone(),
                scenario_program_sha256: scenario_program_sha256.clone(),
                credential_requirement: auths_profile_kit::QualificationCredentialRequirementV1 {
                    workload_id_sha256: workload_id_sha256.clone(),
                    provider_kind: connection.provider_kind().to_owned(),
                    contract: connection.contract().to_owned(),
                    descriptor_schema: connection.descriptor_schema().to_owned(),
                    credential_scope: profile
                        .credential_scope()
                        .ok_or_else(|| {
                            "qualified connected profile has no credential scope".to_owned()
                        })?
                        .to_owned(),
                },
            });
        }
    }
    phases.sort_by(|left, right| {
        (left.scenario_id.as_str(), left.phase_index)
            .cmp(&(right.scenario_id.as_str(), right.phase_index))
    });
    let started_at_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(string_error)?
        .as_secs();
    let deadline_at_unix_seconds = started_at_unix_seconds
        .checked_add(21_600)
        .ok_or_else(|| "qualification ledger deadline overflowed".to_owned())?;
    let mut ledger_random = [0_u8; 16];
    let mut session_random = [0_u8; 32];
    getrandom::fill(&mut ledger_random).map_err(string_error)?;
    getrandom::fill(&mut session_random).map_err(string_error)?;
    let ledger_id = format!("ledger-{}", hex::encode(ledger_random));
    let session_nonce_sha256 = hex::encode(Sha256::digest(session_random));
    let release_binding_bytes = read_bounded(
        Path::new(&required_env("AUTHS_QUALIFICATION_RELEASE_BUILD_BINDING")?),
        262_144,
    )?;
    let release_binding: VerifiedQualificationReleaseBuildBinding =
        crate::profile_qualification_reports::parse_canonical(&release_binding_bytes)?;
    let qualification_surface_bytes =
        serde_json_canonicalizer::to_vec(&release_binding.qualification_surface)
            .map_err(string_error)?;
    if release_binding.schema != "auths.qualification-release-build-verification/1"
        || release_binding.workflow_revision != candidate_revision
        || release_binding.qualification_surface.candidate_revision != candidate_revision
        || hex::encode(Sha256::digest(&qualification_surface_bytes))
            != release_binding.qualification_surface_sha256
    {
        return Err("ledger plan release binding differs from the verified candidate".into());
    }
    let agent_executable_sha256 = release_binding
        .qualification_surface
        .qualification_members
        .iter()
        .find(|member| member.path == "target/release/auths-qualification-agent")
        .map(|member| member.sha256.clone())
        .filter(|digest| lower_hex(digest, 64))
        .ok_or_else(|| "verified release binding omits the qualification agent".to_owned())?;
    let plan = auths_profile_kit::QualificationEvidenceLedgerPlanV1 {
        schema: "auths.profile-qualification-evidence-ledger-plan/1".into(),
        repository_id: required_env("GITHUB_REPOSITORY_ID")?,
        workflow_path: format!(".github/workflows/profile-qualification-{domain}.yml"),
        workflow_revision: required_env("AUTHS_QUALIFICATION_WORKFLOW_REVISION")?,
        candidate_revision,
        attester_revision: required_env("AUTHS_QUALIFICATION_ATTESTER_REVISION")?,
        run_id: required_env("GITHUB_RUN_ID")?,
        run_attempt: required_env("GITHUB_RUN_ATTEMPT")?
            .parse::<u32>()
            .map_err(string_error)?,
        domain: domain.into(),
        target,
        protected_environment: environment.into(),
        provider_run_id: provider_run_id.into(),
        ledger_id,
        session_nonce_sha256,
        supervisor_controller_uid: rustix::process::geteuid().as_raw(),
        supervisor_controller_artifact_sha256: required_sha256_env(
            "AUTHS_QUALIFICATION_SUPERVISOR_CONTROLLER_SHA256",
        )?,
        ledger_appender_artifact_sha256: required_sha256_env(
            "AUTHS_QUALIFICATION_LEDGER_APPENDER_SHA256",
        )?,
        agent_uid: required_u32_env("AUTHS_QUALIFICATION_AGENT_UID")?,
        agent_gid: required_u32_env("AUTHS_QUALIFICATION_AGENT_GID")?,
        agent_executable_sha256,
        recovery_key_id: required_env("AUTHS_QUALIFICATION_RECOVERY_KEY_ID")?,
        recovery_public_key_base64url: required_env(
            "AUTHS_QUALIFICATION_RECOVERY_PUBLIC_KEY_BASE64URL",
        )?,
        phases,
        started_at_unix_seconds,
        deadline_at_unix_seconds,
    };
    plan.validate().map_err(string_error)?;
    let relative_directory = PathBuf::from("target")
        .join("qualification-common-evidence")
        .join(domain)
        .join(target.as_str())
        .join("ledger")
        .join(provider_run_id);
    let relative_output = relative_directory.join("ledger-plan.json");
    require_exact_output_path(&repository, output, &relative_output)?;
    let directory = create_private_output_directory_fd(&repository, &relative_directory)?;
    let bytes = serde_json_canonicalizer::to_vec(&plan).map_err(string_error)?;
    auths_profile_kit::QualificationEvidenceLedgerPlanV1::from_json(&bytes)
        .map_err(string_error)?;
    write_new_owner_only_at(&directory, Path::new("ledger-plan.json"), &bytes)
}

fn build_cleanup_contexts(
    domain: &str,
    target: QualificationTarget,
    environment: &str,
    output: &Path,
) -> Result<(), String> {
    reject_secret_bearing_environment()?;
    let repository = root();
    let candidate_revision = required_env("QUALIFICATION_CANDIDATE_REVISION")?;
    if !lower_hex(&candidate_revision, 40) || git_revision(&repository)? != candidate_revision {
        return Err("cleanup-context candidate checkout differs from protected policy".into());
    }
    let context = load_domain_from_git(&repository, domain, &candidate_revision)?;
    if !context.package.qualification().targets().contains(&target)
        || context.package.qualification().protected_environment() != environment
    {
        return Err("cleanup-context target or environment is not manifest-owned".into());
    }
    let matrix = load_provider_matrix_at(&repository, &context, target, &candidate_revision)?;
    let protected_root = PathBuf::from(required_env("QUALIFICATION_PROTECTED_CONTEXT_ROOT")?);
    let relative = PathBuf::from(domain).join(target.as_str());
    require_exact_output_path(&protected_root, output, &relative)?;
    let directory = create_private_output_directory_fd(&protected_root, &relative)?;
    let repository_id = required_env("GITHUB_REPOSITORY_ID")?;
    let run_id = required_env("GITHUB_RUN_ID")?;
    let run_attempt = required_env("GITHUB_RUN_ATTEMPT")?
        .parse::<u32>()
        .map_err(string_error)?;
    for provider_run in matrix.runs {
        let context = auths_profile_kit::QualificationRunContext {
            repository_id: repository_id.clone(),
            candidate_revision: candidate_revision.clone(),
            target,
            protected_environment: environment.into(),
            run_id: run_id.clone(),
            run_attempt,
            provider_run_id: provider_run.id.clone(),
        };
        let bytes = serde_json_canonicalizer::to_vec(&context).map_err(string_error)?;
        let name = PathBuf::from(format!("{}.json", provider_run.id));
        write_new_owner_only_at(&directory, &name, &bytes)?;
    }
    Ok(())
}

fn build_candidate_proposal(
    domain: &str,
    target: QualificationTarget,
    collections: &Path,
    common_evidence: &Path,
    release_build_path: &Path,
    output: &Path,
) -> Result<(), String> {
    reject_secret_bearing_environment()?;
    let repository = root();
    let attester_repository =
        PathBuf::from(required_env("AUTHS_QUALIFICATION_ATTESTER_REPOSITORY")?);
    if git_revision(&attester_repository)? != required_env("AUTHS_QUALIFICATION_ATTESTER_REVISION")?
    {
        return Err("proposal attester checkout differs from protected policy".into());
    }
    let candidate_revision = git_revision(&repository)?;
    let domain_context = load_domain(&repository, domain)?;
    let matrix = load_provider_matrix(&repository, &domain_context, target)?;
    let operation_plans = load_operation_plans(&repository, &domain_context)?;
    let scenario_ids = scenario_roster(&repository, &domain_context)?;
    let release_build_bytes = read_bounded(release_build_path, 262_144)?;
    let release_build =
        QualificationReleaseBuild::from_json(&release_build_bytes).map_err(string_error)?;
    if release_build.repository_id() != required_env("GITHUB_REPOSITORY_ID")? {
        return Err("proposal release build names the wrong repository".into());
    }

    let mut rows = BTreeMap::new();
    let mut common_phases = BTreeMap::new();
    let mut operation_ids = BTreeSet::new();
    let mut connection_generations = BTreeSet::new();
    let mut provider_truth_commitments = BTreeMap::new();
    let mut collection_started_at = u64::MAX;
    let mut collection_completed_at = 0_u64;
    for matrix_run in &matrix.runs {
        let bytes = read_bounded(
            &collections.join(&matrix_run.id).join("collection.json"),
            MAX_CANDIDATE_COLLECTION_BYTES,
        )?;
        let collection: CandidateCollection =
            serde_json::from_slice(&bytes).map_err(string_error)?;
        if collection.validate().is_err()
            || serde_json_canonicalizer::to_vec(&collection).map_err(string_error)? != bytes
            || collection.run_reference.provider_run_id != matrix_run.id
            || collection.run_reference.domain != domain
            || collection.run_reference.target != target
            || collection.run_reference.candidate_revision != candidate_revision
            || collection.run_reference.repository_id != required_env("GITHUB_REPOSITORY_ID")?
            || collection.run_reference.run_id != required_env("GITHUB_RUN_ID")?
            || collection.run_reference.run_attempt
                != required_env("GITHUB_RUN_ATTEMPT")?
                    .parse::<u32>()
                    .map_err(string_error)?
            || collection
                .scenarios
                .iter()
                .map(|scenario| scenario.scenario_id.as_str())
                .ne(matrix_run.scenario_ids.iter().map(String::as_str))
        {
            return Err(format!(
                "candidate collection row is invalid: {}",
                matrix_run.id
            ));
        }
        collection.run_reference.validate().map_err(string_error)?;
        for scenario in &collection.scenarios {
            scenario.validate().map_err(string_error)?;
            let planned = operation_plans
                .get(&scenario.scenario_id)
                .ok_or_else(|| "candidate scenario has no reviewed operation plan".to_owned())?;
            if scenario.provider_run_id != matrix_run.id
                || scenario.failpoint != expected_failpoint(&scenario.scenario_id)
                || scenario.operations.len() != planned.len()
                || scenario
                    .operations
                    .iter()
                    .zip(planned)
                    .any(|(actual, expected)| {
                        actual.role != expected.role || actual.profile != expected.profile
                    })
            {
                return Err("candidate scenario differs from its reviewed plan".into());
            }
        }
        let run_context = auths_profile_kit::QualificationRunContext {
            repository_id: collection.run_reference.repository_id.clone(),
            candidate_revision: candidate_revision.clone(),
            target,
            protected_environment: domain_context
                .package
                .qualification()
                .protected_environment()
                .into(),
            run_id: collection.run_reference.run_id.clone(),
            run_attempt: collection.run_reference.run_attempt,
            provider_run_id: matrix_run.id.clone(),
        };
        let ledger = read_protected_common_ledger(
            &attester_repository,
            &common_evidence.join("ledger").join(&matrix_run.id),
            &run_context,
            domain,
        )?;
        for event in &ledger.record().events {
            if event.kind
                == auths_profile_kit::QualificationEvidenceEventKind::ProviderTruthObserved
                && let (
                    Some(operation_id),
                    auths_profile_kit::QualificationEvidenceEventPayload::ProviderTruth {
                        provider_truth_sha256,
                        ..
                    },
                ) = (&event.operation_id, &event.payload)
                && provider_truth_commitments
                    .insert(operation_id.clone(), provider_truth_sha256.clone())
                    .is_some()
            {
                return Err("protected proposal repeats provider truth for an operation".into());
            }
        }
        for scenario in &collection.scenarios {
            let planned = operation_plans
                .get(&scenario.scenario_id)
                .ok_or_else(|| "candidate scenario has no reviewed operation plan".to_owned())?;
            let operation_plan_sha256 = hex::encode(Sha256::digest(
                serde_json_canonicalizer::to_vec(planned).map_err(string_error)?,
            ));
            for (phase_offset, phase) in scenario.operations.iter().enumerate() {
                let phase_index = u8::try_from(phase_offset + 1).map_err(string_error)?;
                let common = read_protected_common_phase_evidence(
                    common_evidence,
                    ledger.record(),
                    &run_context,
                    domain,
                    &scenario.scenario_id,
                    scenario.failpoint,
                    phase_offset,
                    phase,
                    &operation_plan_sha256,
                )?;
                for instance in &common.instances {
                    if !operation_ids.insert(instance.projection.operation_id.clone()) {
                        return Err("protected proposal repeats an operation ID".into());
                    }
                    connection_generations
                        .insert(instance.projection.connection_generation.clone());
                }
                common_phases.insert(
                    (
                        matrix_run.id.clone(),
                        scenario.scenario_id.clone(),
                        phase_index,
                    ),
                    common,
                );
            }
        }
        collection_started_at = collection_started_at.min(ledger.record().started_at_unix_seconds);
        collection_completed_at =
            collection_completed_at.max(ledger.record().completed_at_unix_seconds);
        if rows.insert(matrix_run.id.clone(), collection).is_some() {
            return Err("candidate proposal repeats a provider row".into());
        }
    }
    if collection_started_at == u64::MAX
        || collection_started_at >= collection_completed_at
        || operation_ids.is_empty()
    {
        return Err("candidate collection has an invalid protected time envelope".into());
    }

    let profiles = domain_context
        .package
        .qualification()
        .family()
        .iter()
        .map(|profile| {
            let (id, version) = profile
                .rsplit_once('/')
                .ok_or_else(|| "qualification family profile is malformed".to_owned())?;
            Ok(json!({"id":id,"version":version.parse::<u16>().map_err(string_error)?}))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let profile_refs = domain_context.package.qualification().family().to_vec();
    let provider_run_ids = matrix
        .runs
        .iter()
        .map(|run| run.id.clone())
        .collect::<Vec<_>>();
    let binding = json!({
        "repositoryId":required_env("GITHUB_REPOSITORY_ID")?,
        "workflowRunId":required_env("GITHUB_RUN_ID")?,
        "workflowRunAttempt":required_env("GITHUB_RUN_ATTEMPT")?.parse::<u32>().map_err(string_error)?,
        "candidateRevision":candidate_revision,
        "domain":domain,
        "target":target,
        "profiles":profile_refs,
        "providerRunIds":provider_run_ids,
        "scenarioIds":scenario_ids,
        "failpoints":all_qualification_failpoints(),
        "operationIds":operation_ids,
        "connectionGenerations":connection_generations,
    });
    let report_binding: crate::profile_qualification_reports::ReportBinding =
        serde_json::from_value(binding.clone()).map_err(string_error)?;
    let scenario_applicability = scenario_ids
        .iter()
        .map(|id| {
            (
                id.clone(),
                matrix
                    .runs
                    .iter()
                    .filter(|run| run.scenario_ids.binary_search(id).is_ok())
                    .map(|run| run.id.clone())
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let expected = crate::profile_qualification_reports::ExpectedReportBinding {
        repository_id: report_binding.repository_id.clone(),
        workflow_run_id: report_binding.workflow_run_id.clone(),
        workflow_run_attempt: report_binding.workflow_run_attempt,
        candidate_revision: report_binding.candidate_revision.clone(),
        domain: report_binding.domain.clone(),
        target: report_binding.target.clone(),
        profiles: report_binding.profiles.clone(),
        provider_run_ids: report_binding.provider_run_ids.clone(),
        scenario_ids: report_binding.scenario_ids.clone(),
        failpoints: report_binding.failpoints.clone(),
        operation_ids: report_binding.operation_ids.clone(),
        connection_generations: report_binding.connection_generations.clone(),
        scenario_applicability: scenario_applicability.clone(),
    };

    let mut scenarios = Vec::with_capacity(scenario_ids.len());
    for scenario_id in &scenario_ids {
        let applicable = scenario_applicability
            .get(scenario_id)
            .ok_or_else(|| "candidate scenario applicability is absent".to_owned())?;
        let mut executions = Vec::with_capacity(applicable.len());
        let mut assertions = 0_u32;
        for run_id in applicable {
            let scenario = rows[run_id]
                .scenarios
                .iter()
                .find(|scenario| scenario.scenario_id == *scenario_id)
                .ok_or_else(|| "candidate provider row omits a scenario".to_owned())?;
            let mut operations = Vec::with_capacity(scenario.operations.len());
            for (phase_offset, operation) in scenario.operations.iter().enumerate() {
                let phase_index = u8::try_from(phase_offset + 1).map_err(string_error)?;
                let common = common_phases
                    .get(&(run_id.clone(), scenario_id.clone(), phase_index))
                    .ok_or_else(|| "protected common phase is absent from proposal".to_owned())?;
                let mut instances = Vec::with_capacity(common.instances.len());
                for instance in &common.instances {
                    let mut value =
                        serde_json::to_value(&instance.projection).map_err(string_error)?;
                    let provider_truth_sha256 = provider_truth_commitments
                        .get(&instance.projection.operation_id)
                        .ok_or_else(|| {
                            "protected ledger omits one operation truth commitment".to_owned()
                        })?;
                    value
                        .as_object_mut()
                        .ok_or_else(|| "candidate operation instance is not an object".to_owned())?
                        .insert(
                            "failpoint".into(),
                            serde_json::to_value(expected_failpoint(scenario_id))
                                .map_err(string_error)?,
                        );
                    value
                        .as_object_mut()
                        .ok_or_else(|| "candidate operation instance is not an object".to_owned())?
                        .insert(
                            "providerTruthSha256".into(),
                            Value::String(provider_truth_sha256.clone()),
                        );
                    instances.push(value);
                }
                let attempts = common.attempts.clone();
                assertions = assertions
                    .checked_add(
                        u32::try_from(instances.len() + attempts.len()).map_err(string_error)?,
                    )
                    .ok_or_else(|| "candidate scenario assertion count overflow".to_owned())?;
                operations.push(json!({
                    "role":operation.role,
                    "profile":operation.profile,
                    "instances":instances,
                    "attempts":attempts,
                }));
            }
            executions.push(json!({"providerRunId":run_id,"operations":operations}));
        }
        let report = json!({
            "schema":"auths.profile-qualification-scenario-report/1",
            "binding":binding,
            "scenarioId":scenario_id,
            "assertions":assertions,
            "executions":executions,
            "status":"passed",
        });
        let report_bytes = serde_json_canonicalizer::to_vec(&report).map_err(string_error)?;
        let parsed: crate::profile_qualification_reports::ScenarioReport =
            crate::profile_qualification_reports::parse_canonical(&report_bytes)?;
        parsed.validate(&expected)?;
        let digest = hex::encode(Sha256::digest(&report_bytes));
        scenarios.push(json!({
            "id":scenario_id,
            "status":"passed",
            "assertions":assertions,
            "reportSha256":digest,
            "providerRunIds":applicable,
        }));
    }
    let provider_runs = matrix
        .runs
        .iter()
        .map(|run| {
            Ok(json!({
                "id":run.id,
                "providerVersion":run.provider_version,
                "providerArtifactSha256":run.provider_artifact_sha256,
                "scenarioSetSha256":scenario_set_sha256_values(&run.id, &scenarios)?,
                "status":"passed",
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;

    let raw_files = collect_relative_regular_files(common_evidence, 4_000)?;
    if raw_files.iter().any(|path| {
        path != "anchor-snapshots/receipt-trust-anchors.json"
            && !path.starts_with("ledger/")
            && !path.starts_with("receipts/")
            && !path.starts_with("receipt-inspection/")
    }) || !raw_files.contains("anchor-snapshots/receipt-trust-anchors.json")
    {
        return Err("proposal common evidence contains an undeclared member".into());
    }
    let anchor_bytes = read_bounded(
        &common_evidence.join("anchor-snapshots/receipt-trust-anchors.json"),
        65_536,
    )?;
    auths_receipts::decode_receipt_trust_anchors(&anchor_bytes).map_err(string_error)?;
    if hex::encode(Sha256::digest(&anchor_bytes))
        != required_sha256_env("AUTHS_QUALIFICATION_RECEIPT_TRUST_ANCHOR_SHA256")?
    {
        return Err("proposal receipt anchors differ from protected policy".into());
    }
    let scanned_file_count =
        u32::try_from(raw_files.len() + scenario_ids.len() + 12).map_err(string_error)?;
    let gitleaks_report = crate::profile_qualification_reports::ScanReport::clean(
        report_binding,
        "gitleaks",
        scanned_file_count,
        0,
    )?;
    gitleaks_report.validate(&expected, "gitleaks")?;
    let gitleaks_bytes =
        serde_json_canonicalizer::to_vec(&gitleaks_report).map_err(string_error)?;
    let toolchains_bytes = read_bounded(
        &repository.join("release/qualification/v1/toolchains.json"),
        4_096,
    )?;
    let toolchains: QualificationToolchainPins =
        serde_json::from_slice(&toolchains_bytes).map_err(string_error)?;
    if serde_json_canonicalizer::to_vec(&toolchains).map_err(string_error)? != toolchains_bytes
        || toolchains.schema != "auths.profile-qualification-toolchains/1"
    {
        return Err("qualification toolchain pins are not canonical".into());
    }
    let candidate_artifacts = release_build
        .artifacts()
        .iter()
        .map(|artifact| {
            json!({
                "role":artifact.role(),
                "memberSha256":artifact.member_sha256(),
                "bytes":artifact.bytes(),
            })
        })
        .collect::<Vec<_>>();
    let runtime_digests = runtime_digests_at(&repository, domain, &candidate_revision)?
        .into_iter()
        .map(|(profile, sha256)| json!({"profile":profile,"sha256":sha256}))
        .collect::<Vec<_>>();
    let proposal = json!({
        "schema":"auths.profile-qualification-proposal/1",
        "domain":domain,
        "profiles":profiles,
        "target":target,
        "candidateRevision":candidate_revision,
        "semanticClosureSha256":semantic_closure(&repository, domain)?.sha256,
        "packageManifestSha256":hex::encode(domain_context.package.package_manifest_digest().map_err(string_error)?),
        "profileRuntimeDigests":runtime_digests,
        "errorRegistrySha256":error_registry_digest_at(&repository, &candidate_revision)?,
        "providerMatrixSha256":provider_matrix_digest_at(&repository, &domain_context, target, &candidate_revision)?,
        "toolchain":{"rust":toolchains.rust,"node":toolchains.node,"python":toolchains.python},
        "candidateArtifacts":candidate_artifacts,
        "environmentClass":"disposable-provider-test",
        "collectionStartedAtUnixSeconds":collection_started_at,
        "collectionCompletedAtUnixSeconds":collection_completed_at,
        "providerRuns":provider_runs,
        "scenarios":scenarios,
        "receiptVerification":{"rust":"passed","python":"passed","typescript":"passed","portableReceiptSchema":"auths.portable-receipt/1"},
        "secretScan":{"tool":"gitleaks-8.28.0","status":"passed","reportSha256":hex::encode(Sha256::digest(gitleaks_bytes))},
    });
    let bytes = serde_json_canonicalizer::to_vec(&proposal).map_err(string_error)?;
    auths_profile_kit::QualificationProposal::from_json(&bytes).map_err(string_error)?;
    atomic_write_new_owner_only(output, &bytes)
}

fn installed_verify(proposal_path: &Path, packages: &Path, output: &Path) -> Result<(), String> {
    let forbidden_roles = [
        "OBSERVER_CREDENTIAL",
        "CLEANUP_CREDENTIAL",
        "OBSERVER_SEED",
        "SETUP_CREDENTIAL",
        "MUTATION_CREDENTIAL",
        "RUNTIME_READ_CREDENTIAL",
        "DECISION_RECEIPT_SEED",
        "EXECUTION_RECEIPT_SEED",
        "RECOVERY_SEED",
        "ATTESTATION_SEED",
    ];
    if forbidden_roles
        .iter()
        .any(|role| env::var_os(format!("QUALIFICATION_{role}")).is_some())
        || env::var_os("AUTHS_QUALIFICATION_ATTESTATION_SEED").is_some()
    {
        return Err("installed verification received a protected role secret".into());
    }
    let (proposal_bytes, _) =
        crate::profile_qualification_evidence::read_untrusted_regular(proposal_path, 262_144)?;
    let proposal = auths_profile_kit::QualificationProposal::from_json(&proposal_bytes)
        .map_err(string_error)?;
    validate_installed_package_directory(packages)?;
    let package_paths = VERIFIED_RELEASE_ARTIFACT_ROLES
        .iter()
        .map(|role| packages.join(role).join(installed_member_name(role)))
        .collect::<Vec<_>>();
    for ((artifact, role), path) in proposal
        .candidate_artifacts()
        .iter()
        .zip(VERIFIED_RELEASE_ARTIFACT_ROLES)
        .zip(&package_paths)
    {
        let (bytes, digest) =
            crate::profile_qualification_evidence::read_untrusted_regular(path, 536_870_912)?;
        if artifact.role() != role
            || artifact.member_sha256() != digest
            || artifact.bytes() != u64::try_from(bytes.len()).map_err(string_error)?
        {
            return Err(format!(
                "installed release member differs from proposal: {role}"
            ));
        }
        let mut mutated = bytes;
        mutated[0] ^= 1;
        if hex::encode(Sha256::digest(&mutated)) == digest {
            return Err(format!("installed mutation corpus did not reject {role}"));
        }
    }

    let temporary = tempfile::tempdir().map_err(string_error)?;
    let python = resolve_installed_tool("QUALIFICATION_PYTHON", "python3")?;
    let node = resolve_installed_tool("QUALIFICATION_NODE", "node")?;
    let npm = resolve_installed_tool("QUALIFICATION_NPM", "npm")?;
    let (rust_pin, node_pin, python_pin) = proposal.toolchain_values();
    require_tool_version(&node, &["--version"], &format!("v{node_pin}"), "Node")?;
    require_tool_version(
        &python,
        &["--version"],
        &format!("Python {python_pin}"),
        "Python",
    )?;
    let package_paths = VERIFIED_RELEASE_ARTIFACT_ROLES
        .iter()
        .copied()
        .zip(package_paths)
        .collect::<BTreeMap<_, _>>();
    let package = |role: &str| {
        package_paths
            .get(role)
            .map(PathBuf::as_path)
            .ok_or_else(|| format!("installed release member is absent: {role}"))
    };
    validate_native_package_links(
        &python,
        package("python-wheel")?,
        package("python-native")?,
        package("typescript-package")?,
        package("typescript-native")?,
        temporary.path(),
    )?;
    run_installed_rust_consumer(package("production-agent")?, temporary.path())?;
    let profile_role = format!("python-profile-{}", proposal.domain());
    run_installed_python_consumer(
        &python,
        package("python-wheel")?,
        package(&profile_role)?,
        proposal.domain(),
        temporary.path(),
    )?;
    run_installed_typescript_consumer(
        &node,
        &npm,
        package("typescript-package")?,
        temporary.path(),
    )?;

    let binding = crate::profile_qualification_reports::InstalledReportBinding {
        candidate_revision: proposal.candidate_revision().into(),
        domain: proposal.domain().into(),
        target: proposal.target().as_str().into(),
        profiles: proposal
            .profiles()
            .iter()
            .map(auths_profile_kit::QualificationProfile::semantic_subject)
            .collect(),
        provider_run_ids: proposal
            .provider_runs()
            .iter()
            .map(|run| run.id().to_owned())
            .collect(),
        scenario_ids: proposal
            .scenarios()
            .iter()
            .map(|scenario| scenario.id().to_owned())
            .collect(),
    };
    let fixture_bytes = [
        INSTALLED_PYTHON_LINK_FIXTURE.as_bytes(),
        INSTALLED_PYTHON_IMPORT_FIXTURE.as_bytes(),
        INSTALLED_PYTHON_PROFILE_IMPORT_FIXTURE.as_bytes(),
        INSTALLED_TYPESCRIPT_IMPORT_FIXTURE.as_bytes(),
    ]
    .concat();
    let report = crate::profile_qualification_reports::InstalledPackagesReport::create(
        binding,
        hex::encode(Sha256::digest(fixture_bytes)),
        hex::encode(Sha256::digest(INSTALLED_MUTATION_CORPUS)),
        crate::profile_qualification_reports::Toolchain {
            rust: rust_pin.into(),
            node: node_pin.into(),
            python: python_pin.into(),
        },
        [
            (
                "auths-production-agent".into(),
                file_sha256(package("production-agent")?, 536_870_912)?,
            ),
            (
                format!("auths+auths-profile-{}", proposal.domain()),
                combined_file_sha256(&[package("python-wheel")?, package(&profile_role)?])?,
            ),
            (
                "@auths-dev/sdk".into(),
                file_sha256(package("typescript-package")?, 536_870_912)?,
            ),
        ],
    );
    let bytes = serde_json_canonicalizer::to_vec(&report).map_err(string_error)?;
    atomic_write_new_owner_only(output, &bytes)
}

fn assemble_observation_evidence(
    proposal_path: &Path,
    aggregate: &Path,
    installed: &Path,
    supplemental: &Path,
    output: &Path,
) -> Result<(), String> {
    reject_secret_bearing_environment()?;
    let (proposal_bytes, _) =
        crate::profile_qualification_evidence::read_untrusted_regular(proposal_path, 262_144)?;
    let proposal = auths_profile_kit::QualificationProposal::from_json(&proposal_bytes)
        .map_err(string_error)?;
    let protected_root = PathBuf::from(required_env("QUALIFICATION_PROTECTED_OUTPUT_ROOT")?);
    require_exact_output_path(&protected_root, output, Path::new("assembled-evidence"))?;
    let output = create_private_output_directory(&protected_root, Path::new("assembled-evidence"))?;
    if fs::read_dir(&output)
        .map_err(string_error)?
        .next()
        .is_some()
    {
        return Err("assembled evidence output is not empty".into());
    }

    let expected_scenarios = proposal
        .scenarios()
        .iter()
        .map(|scenario| format!("reports/scenarios/{}.json", scenario.id()))
        .collect::<BTreeSet<_>>();
    let fixed_aggregate = BTreeSet::from([
        "reports/cleanup.json".to_owned(),
        "reports/counters.json".to_owned(),
        "reports/provider-truth.json".to_owned(),
        "reports/receipt-trust-anchors.json".to_owned(),
    ]);
    let aggregate_files = collect_relative_regular_files(aggregate, 1_024)?;
    let aggregate_names = aggregate_files.iter().cloned().collect::<BTreeSet<_>>();
    let expected_aggregate = fixed_aggregate
        .union(&expected_scenarios)
        .cloned()
        .collect::<BTreeSet<_>>();
    if aggregate_names != expected_aggregate {
        return Err("aggregate evidence does not have the exact report roster".into());
    }
    for relative in aggregate_files {
        copy_private_evidence_member(aggregate, &relative, &output)?;
    }

    let installed_bytes = read_bounded(installed, 1_048_576)?;
    let _: crate::profile_qualification_reports::InstalledPackagesReport =
        crate::profile_qualification_reports::parse_canonical(&installed_bytes)?;
    let installed_destination = output.join("reports/installed-packages.json");
    fs::create_dir_all(
        installed_destination
            .parent()
            .ok_or_else(|| "installed report destination has no parent".to_owned())?,
    )
    .map_err(string_error)?;
    atomic_write_new_owner_only(&installed_destination, &installed_bytes)?;

    let fixed_supplemental = BTreeSet::from([
        "anchor-snapshots/receipt-trust-anchors.json".to_owned(),
        "reports/provenance.json".to_owned(),
        "reports/receipts-python.json".to_owned(),
        "reports/receipts-rust.json".to_owned(),
        "reports/receipts-typescript.json".to_owned(),
    ]);
    let supplemental_files = collect_relative_regular_files(supplemental, 4_000)?;
    if supplemental_files.iter().any(|relative| {
        !fixed_supplemental.contains(relative)
            && !relative.starts_with("ledger/")
            && !relative.starts_with("receipts/")
            && !relative.starts_with("receipt-inspection/")
            && common_phase_archive_path(relative).is_none()
    }) || fixed_supplemental
        .iter()
        .any(|required| !supplemental_files.contains(required))
    {
        return Err("supplemental evidence has a missing or undeclared member".into());
    }
    for relative in supplemental_files {
        if relative == "anchor-snapshots/receipt-trust-anchors.json" {
            let preliminary = read_bounded(&supplemental.join(&relative), 65_536)?;
            let promoted = read_bounded(
                &aggregate.join("reports/receipt-trust-anchors.json"),
                65_536,
            )?;
            if preliminary != promoted {
                return Err(
                    "protected receipt trust-anchor report differs from preliminary snapshot"
                        .into(),
                );
            }
        } else if let Some(destination) = common_phase_archive_path(&relative) {
            copy_private_evidence_member_as(supplemental, &relative, &output, &destination)?;
        } else {
            copy_private_evidence_member(supplemental, &relative, &output)?;
        }
    }
    write_protected_scan_reports(&proposal_bytes, &proposal, &output)?;
    crate::profile_qualification_evidence::validate_pre_observation_source(&output)
}

fn write_protected_scan_reports(
    proposal_bytes: &[u8],
    proposal: &auths_profile_kit::QualificationProposal,
    evidence: &Path,
) -> Result<(), String> {
    let existing = collect_relative_regular_files(evidence, 4_091)?;
    let scanned_file_count = u32::try_from(existing.len() + 3).map_err(string_error)?;
    let counters_bytes = read_observation_report(evidence, "counters.json", 1_048_576)?;
    let counters: crate::profile_qualification_reports::CountersReport =
        crate::profile_qualification_reports::parse_canonical(&counters_bytes)?;
    let expected = expected_binding_from_value(
        &serde_json::to_value(&counters.binding).map_err(string_error)?,
        proposal,
    )?;
    for kind in ["gitleaks", "redaction", "typed-forbidden-field"] {
        let report = crate::profile_qualification_reports::ScanReport::clean(
            counters.binding.clone(),
            kind,
            scanned_file_count,
            0,
        )?;
        report.validate(&expected, kind)?;
        let bytes = serde_json_canonicalizer::to_vec(&report).map_err(string_error)?;
        let file = match kind {
            "gitleaks" => "gitleaks.json",
            "redaction" => "redaction.json",
            "typed-forbidden-field" => "typed-forbidden-fields.json",
            _ => unreachable!("closed scan report kind"),
        };
        atomic_write_new_owner_only(&evidence.join("reports").join(file), &bytes)?;
    }
    let (domain_fields, redaction_prefixes) =
        qualification_evidence_scan_policy(proposal.domain())?;
    scan_evidence_directory(evidence, domain_fields, redaction_prefixes)?;
    rerun_gitleaks(evidence)?;
    let proposed: Value = serde_json::from_slice(proposal_bytes).map_err(string_error)?;
    let proposed_gitleaks = proposed
        .pointer("/secretScan/reportSha256")
        .and_then(Value::as_str)
        .ok_or_else(|| "proposal secret-scan digest is absent".to_owned())?;
    if file_sha256(&evidence.join("reports/gitleaks.json"), 262_144)? != proposed_gitleaks {
        return Err("protected gitleaks report differs from the candidate proposal".into());
    }
    Ok(())
}

fn scan_evidence_directory(
    evidence: &Path,
    domain_fields: &[&str],
    redaction_prefixes: &[&str],
) -> Result<(), String> {
    const FORBIDDEN_FIELDS: [&str; 8] = [
        "authorization",
        "credential",
        "password",
        "privateKey",
        "recoveryHandle",
        "resourceReferences",
        "secret",
        "seed",
    ];
    const FORBIDDEN_CONTENT: [&[u8]; 3] = [b"-----BEGIN PRIVATE KEY-----", b"github_pat_", b"ghp_"];
    for relative in collect_relative_regular_files(evidence, 4_091)? {
        let bytes = read_bounded(&evidence.join(&relative), 16_777_216)?;
        if FORBIDDEN_CONTENT
            .iter()
            .any(|needle| bytes.windows(needle.len()).any(|window| window == *needle))
            || contains_unredacted_provider_identifier(&bytes, redaction_prefixes)
        {
            return Err(format!(
                "qualification evidence contains unredacted sensitive content: {relative}"
            ));
        }
        if relative.ends_with(".json") {
            let value: Value = serde_json::from_slice(&bytes).map_err(string_error)?;
            if json_has_forbidden_field(&value, &FORBIDDEN_FIELDS)
                || json_has_forbidden_field(&value, domain_fields)
            {
                return Err(format!(
                    "qualification evidence contains a forbidden typed field: {relative}"
                ));
            }
        }
    }
    Ok(())
}

fn copy_private_evidence_member(
    source: &Path,
    relative: &str,
    destination_root: &Path,
) -> Result<(), String> {
    let (bytes, _) = crate::profile_qualification_evidence::read_untrusted_regular(
        &source.join(relative),
        16_777_216,
    )?;
    let destination = destination_root.join(relative);
    fs::create_dir_all(
        destination
            .parent()
            .ok_or_else(|| "evidence member destination has no parent".to_owned())?,
    )
    .map_err(string_error)?;
    atomic_write_new_owner_only(&destination, &bytes)
}

fn copy_private_evidence_member_as(
    source: &Path,
    relative: &str,
    destination_root: &Path,
    destination_relative: &str,
) -> Result<(), String> {
    let (bytes, _) = crate::profile_qualification_evidence::read_untrusted_regular(
        &source.join(relative),
        16_777_216,
    )?;
    let destination = destination_root.join(destination_relative);
    fs::create_dir_all(
        destination
            .parent()
            .ok_or_else(|| "evidence member destination has no parent".to_owned())?,
    )
    .map_err(string_error)?;
    atomic_write_new_owner_only(&destination, &bytes)
}

fn common_phase_archive_path(relative: &str) -> Option<String> {
    let components = relative.split('/').collect::<Vec<_>>();
    let ["scenarios", scenario, provider_run, phase] = components.as_slice() else {
        return None;
    };
    let phase = phase.strip_suffix(".json")?;
    if !registered_token(scenario)
        || !registered_token(provider_run)
        || phase.parse::<u8>().ok().is_none_or(|value| value == 0)
        || phase.starts_with('0')
    {
        return None;
    }
    Some(format!(
        "common-phases/{provider_run}/{scenario}/{phase}.json"
    ))
}

fn build_observation_record(
    proposal_path: &Path,
    evidence: &Path,
    release_build_path: &Path,
    output: &Path,
) -> Result<(), String> {
    reject_secret_bearing_environment()?;
    let repository = root();
    let (proposal_bytes, _) =
        crate::profile_qualification_evidence::read_untrusted_regular(proposal_path, 262_144)?;
    let proposal = auths_profile_kit::QualificationProposal::from_json(&proposal_bytes)
        .map_err(string_error)?;
    if git_revision(&repository)? != proposal.candidate_revision() {
        return Err("observation candidate checkout differs from the proposal revision".into());
    }
    let attester_repository =
        PathBuf::from(required_env("AUTHS_QUALIFICATION_ATTESTER_REPOSITORY")?);
    if git_revision(&attester_repository)? != required_env("AUTHS_QUALIFICATION_ATTESTER_REVISION")?
    {
        return Err("observation attester checkout differs from protected policy".into());
    }

    let release_build_bytes = read_bounded(release_build_path, 262_144)?;
    let release_build =
        QualificationReleaseBuild::from_json(&release_build_bytes).map_err(string_error)?;
    if release_build.repository_id() != required_env("GITHUB_REPOSITORY_ID")?
        || proposal.candidate_artifacts().len() != release_build.artifacts().len()
        || proposal
            .candidate_artifacts()
            .iter()
            .zip(release_build.artifacts())
            .any(|(candidate, protected)| {
                candidate.role() != protected.role()
                    || candidate.member_sha256() != protected.member_sha256()
                    || candidate.bytes() != protected.bytes()
            })
    {
        return Err("proposal artifact claims differ from the verified release build".into());
    }

    use crate::profile_qualification_reports::{
        CleanupReport, CountersReport, ExpectedReportBinding, InstalledPackagesReport,
        ProvenanceReport, ProviderTruthReport, ReceiptsReport, ScanReport, ScenarioReport,
        parse_canonical,
    };
    let counters_bytes = read_observation_report(evidence, "counters.json", 1_048_576)?;
    let counters: CountersReport = parse_canonical(&counters_bytes)?;
    let profile_refs = proposal
        .profiles()
        .iter()
        .map(auths_profile_kit::QualificationProfile::semantic_subject)
        .collect::<Vec<_>>();
    let provider_run_ids = proposal
        .provider_runs()
        .iter()
        .map(|run| run.id().to_owned())
        .collect::<Vec<_>>();
    let scenario_ids = proposal
        .scenarios()
        .iter()
        .map(|scenario| scenario.id().to_owned())
        .collect::<Vec<_>>();
    let scenario_applicability = proposal
        .scenarios()
        .iter()
        .map(|scenario| {
            (
                scenario.id().to_owned(),
                scenario.provider_run_ids().to_vec(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let expected = ExpectedReportBinding {
        repository_id: required_env("GITHUB_REPOSITORY_ID")?,
        workflow_run_id: required_env("GITHUB_RUN_ID")?,
        workflow_run_attempt: required_env("GITHUB_RUN_ATTEMPT")?
            .parse::<u32>()
            .map_err(string_error)?,
        candidate_revision: proposal.candidate_revision().to_owned(),
        domain: proposal.domain().to_owned(),
        target: proposal.target().as_str().to_owned(),
        profiles: profile_refs,
        provider_run_ids: provider_run_ids.clone(),
        scenario_ids: scenario_ids.clone(),
        failpoints: all_qualification_failpoints(),
        operation_ids: counters.binding.operation_ids.clone(),
        connection_generations: counters.binding.connection_generations.clone(),
        scenario_applicability,
    };
    counters.validate(&expected)?;

    let truth_bytes = read_observation_report(evidence, "provider-truth.json", 16_777_216)?;
    let truth: ProviderTruthReport = parse_canonical(&truth_bytes)?;
    truth.validate(&expected, proposal.domain())?;
    let mut independently_observed_runs = BTreeMap::new();
    for operation in &truth.operations {
        let identity = (
            operation.provider_version.as_str(),
            operation.provider_artifact_sha256.as_str(),
        );
        if independently_observed_runs
            .insert(operation.provider_run_id.as_str(), identity)
            .is_some_and(|previous| previous != identity)
        {
            return Err("protected provider identity differs within one provider run".into());
        }
    }
    let cleanup_bytes = read_observation_report(evidence, "cleanup.json", 262_144)?;
    let cleanup: CleanupReport = parse_canonical(&cleanup_bytes)?;
    cleanup.validate(&expected)?;
    let installed: InstalledPackagesReport = parse_canonical(&read_observation_report(
        evidence,
        "installed-packages.json",
        1_048_576,
    )?)?;
    installed.validate(&expected)?;
    for (name, kind) in [
        ("gitleaks.json", "gitleaks"),
        ("redaction.json", "redaction"),
        ("typed-forbidden-fields.json", "typed-forbidden-field"),
    ] {
        let report: ScanReport =
            parse_canonical(&read_observation_report(evidence, name, 262_144)?)?;
        report.validate(&expected, kind)?;
    }
    let provenance: ProvenanceReport = parse_canonical(&read_observation_report(
        evidence,
        "provenance.json",
        1_048_576,
    )?)?;
    provenance.validate(&expected)?;

    let mut receipt_operations = None;
    for language in ["python", "rust", "typescript"] {
        let report: ReceiptsReport = parse_canonical(&read_observation_report(
            evidence,
            &format!("receipts-{language}.json"),
            1_048_576,
        )?)?;
        report.validate(&expected, language)?;
        if receipt_operations
            .as_ref()
            .is_some_and(|operations| operations != &report.operations)
        {
            return Err("installed receipt projections disagree across languages".into());
        }
        receipt_operations = Some(report.operations);
    }

    let mut scenario_digests = BTreeMap::new();
    for scenario in proposal.scenarios() {
        let relative = format!("scenarios/{}.json", scenario.id());
        let bytes = read_observation_report(evidence, &relative, 1_048_576)?;
        let report: ScenarioReport = parse_canonical(&bytes)?;
        report.validate(&expected)?;
        let digest = hex::encode(Sha256::digest(&bytes));
        if report.scenario_id != scenario.id()
            || report.assertions != scenario.assertions()
            || report.provider_run_ids() != scenario.provider_run_ids()
            || digest != scenario.report_sha256()
        {
            return Err(format!(
                "protected scenario report differs from proposal: {}",
                scenario.id()
            ));
        }
        scenario_digests.insert(scenario.id().to_owned(), digest);
    }

    let candidate = load_domain(&repository, proposal.domain())?;
    let matrix = load_provider_matrix(&repository, &candidate, proposal.target())?;
    validate_observed_provider_runs(&matrix, proposal.provider_runs())?;
    if independently_observed_runs.len() != matrix.runs.len() {
        return Err("protected provider identity does not cover the provider matrix".into());
    }
    let mut protected_provider_runs = Vec::with_capacity(matrix.runs.len());
    for run in proposal.provider_runs() {
        let observed = independently_observed_runs
            .get(run.id())
            .ok_or_else(|| format!("protected provider identity is absent: {}", run.id()))?;
        if observed.0 != run.provider_version() || observed.1 != run.provider_artifact_sha256() {
            return Err(format!(
                "candidate and independently observed provider identity differ: {}",
                run.id()
            ));
        }
        let committed = scenario_set_sha256(run.id(), proposal.scenarios(), &scenario_digests)?;
        if committed != run.scenario_set_sha256() {
            return Err(format!(
                "provider scenario-set commitment differs from protected reports: {}",
                run.id()
            ));
        }
        protected_provider_runs.push(json!({
            "id":run.id(),
            "providerVersion":observed.0,
            "providerArtifactSha256":observed.1,
            "scenarioSetSha256":committed,
            "status":"passed",
        }));
    }

    let anchor_bytes = read_observation_report(evidence, "receipt-trust-anchors.json", 65_536)?;
    let anchor_sha256 = hex::encode(Sha256::digest(&anchor_bytes));
    if anchor_sha256 != required_env("AUTHS_QUALIFICATION_RECEIPT_TRUST_ANCHOR_SHA256")? {
        return Err("receipt trust-anchor snapshot differs from protected policy".into());
    }
    let recovery_key_id = required_env("AUTHS_QUALIFICATION_RECOVERY_KEY_ID")?;
    let recovery_public_key_base64url =
        required_env("AUTHS_QUALIFICATION_RECOVERY_PUBLIC_KEY_BASE64URL")?;
    let attestation_registry = load_trust_registry(&attester_repository)?;
    let observer_registry = load_observer_trust_registry(&attester_repository)?;
    validate_complete_qualification_key_separation(
        &attester_repository,
        &attestation_registry,
        &observer_registry,
        &anchor_bytes,
        &recovery_key_id,
        &recovery_public_key_base64url,
    )?;

    let source_trust_bytes = read_bounded(
        &attester_repository.join(EVIDENCE_SOURCE_TRUST_PATH),
        262_144,
    )?;
    let ledger_trust_bytes = read_bounded(
        &attester_repository.join(EVIDENCE_LEDGER_TRUST_PATH),
        262_144,
    )?;
    let source_trust_sha256 = hex::encode(Sha256::digest(&source_trust_bytes));
    let ledger_trust_sha256 = hex::encode(Sha256::digest(&ledger_trust_bytes));
    let protected_environment = required_env("QUALIFICATION_PROTECTED_ENVIRONMENT")?;
    let mut ledgers = Vec::with_capacity(provider_run_ids.len());
    let mut started_at = u64::MAX;
    let mut ledger_completed_at = 0_u64;
    for provider_run_id in &provider_run_ids {
        let ledger_root = evidence.join("ledger").join(provider_run_id);
        let staged_source = read_bounded(&ledger_root.join("evidence-source-trust.json"), 262_144)?;
        let staged_ledger = read_bounded(&ledger_root.join("evidence-ledger-trust.json"), 262_144)?;
        if staged_source != source_trust_bytes || staged_ledger != ledger_trust_bytes {
            return Err(format!(
                "retained ledger trust snapshot differs for {provider_run_id}"
            ));
        }
        let run_context = auths_profile_kit::QualificationRunContext {
            repository_id: expected.repository_id.clone(),
            candidate_revision: expected.candidate_revision.clone(),
            target: proposal.target(),
            protected_environment: protected_environment.clone(),
            run_id: expected.workflow_run_id.clone(),
            run_attempt: expected.workflow_run_attempt,
            provider_run_id: provider_run_id.clone(),
        };
        let ledger = read_protected_common_ledger(
            &attester_repository,
            &ledger_root,
            &run_context,
            proposal.domain(),
        )?;
        let agent_trust = ledger.record().agent_trust().ok_or_else(|| {
            "protected ledger omits the exercised agent trust identity".to_owned()
        })?;
        if agent_trust.recovery_key_id() != recovery_key_id
            || agent_trust.recovery_public_key_base64url() != recovery_public_key_base64url
            || agent_trust.receipt_trust_anchor_sha256() != anchor_sha256
        {
            return Err(format!(
                "protected ledger agent trust differs for {provider_run_id}"
            ));
        }
        let ledger_bytes = read_bounded(&ledger_root.join("ledger.json"), 16_777_216)?;
        started_at = started_at.min(ledger.record().started_at_unix_seconds);
        ledger_completed_at = ledger_completed_at.max(ledger.record().completed_at_unix_seconds);
        ledgers.push(json!({
            "providerRunId":provider_run_id,
            "ledgerSha256":hex::encode(Sha256::digest(&ledger_bytes)),
            "sealerKeyId":ledger.key_id(),
            "sourceTrustSha256":source_trust_sha256,
            "ledgerTrustSha256":ledger_trust_sha256,
        }));
    }
    let completed_at = cleanup.completed_at_unix_seconds();
    if started_at == u64::MAX
        || completed_at < ledger_completed_at
        || completed_at > now_unix_seconds()?.saturating_add(300)
    {
        return Err("observation time range does not enclose every protected ledger".into());
    }

    let counter_map = counters
        .operations
        .iter()
        .map(|operation| {
            (
                operation.operation_id.as_str(),
                operation.counters.provider_calls,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut call_counts = Vec::with_capacity(truth.operations.len());
    for operation in &truth.operations {
        if counter_map.get(operation.operation_id.as_str()).copied()
            != Some(operation.provider_calls)
        {
            return Err("protected provider truth and lifecycle counters disagree".into());
        }
        call_counts.push(json!({
            "operationId":operation.operation_id,
            "count":operation.provider_calls,
        }));
    }

    let report_digests = observation_report_digests(evidence, &scenario_ids)?;
    let attester_tools = verified_attester_tools_from_files(
        Path::new(&required_env(
            "AUTHS_QUALIFICATION_ATTESTER_TOOLS_VERIFICATION",
        )?),
        Path::new(&required_env(
            "AUTHS_QUALIFICATION_ATTESTER_TOOLS_MANIFEST",
        )?),
    )?;
    validate_attester_tools_binding(
        &attester_tools,
        now_unix_seconds()?,
        &expected.repository_id,
    )?;
    let attester_tools_sha256 = attester_tools_identity_sha256(&attester_tools)?;
    let record_value = json!({
        "repositoryId":expected.repository_id,
        "workflowPath":format!(".github/workflows/profile-qualification-{}.yml", proposal.domain()),
        "workflowRevision":required_env("AUTHS_QUALIFICATION_WORKFLOW_REVISION")?,
        "runId":expected.workflow_run_id,
        "runAttempt":expected.workflow_run_attempt,
        "candidateRevision":proposal.candidate_revision(),
        "domain":proposal.domain(),
        "target":proposal.target(),
        "profiles":proposal.profiles(),
        "providerRuns":protected_provider_runs,
        "releaseBuildSha256":release_build.sha256().map_err(string_error)?,
        "attesterToolsSha256":attester_tools_sha256,
        "ledgers":ledgers,
        "operationIds":expected.operation_ids,
        "connectionGenerations":expected.connection_generations,
        "externalProviderCallCounts":call_counts,
        "providerTruthSha256":hex::encode(Sha256::digest(&truth_bytes)),
        "counterReportSha256":hex::encode(Sha256::digest(&counters_bytes)),
        "cleanupReportSha256":hex::encode(Sha256::digest(&cleanup_bytes)),
        "receiptTrustAnchorSha256":anchor_sha256,
        "recoveryKeyId":recovery_key_id,
        "recoveryPublicKeyBase64url":recovery_public_key_base64url,
        "observedReportDigests":report_digests,
        "startedAtUnixSeconds":started_at,
        "completedAtUnixSeconds":completed_at,
    });
    let record_bytes = serde_json_canonicalizer::to_vec(&record_value).map_err(string_error)?;
    let record = QualificationObservationRecord::from_json(&record_bytes).map_err(string_error)?;
    let snapshot =
        crate::profile_qualification_evidence::snapshot_pre_observation_source(evidence)?;
    require_exact_ledger_roots(
        &snapshot,
        proposal.provider_runs().iter().map(|run| run.id()),
    )?;
    let retained = verify_retained_evidence_ledgers(
        &attester_repository,
        &snapshot,
        &record,
        &attester_tools,
        None,
    )?;
    verify_retained_receipts(
        &snapshot,
        &anchor_bytes,
        &expected,
        &receipt_operations.ok_or_else(|| "receipt report projection is absent".to_owned())?,
        &retained,
    )?;
    atomic_write_new_owner_only(output, &record_bytes)
}

fn read_observation_report(
    evidence: &Path,
    relative: &str,
    maximum: u64,
) -> Result<Vec<u8>, String> {
    if !safe_relative_path(relative) {
        return Err("observation report path is unsafe".into());
    }
    crate::profile_qualification_evidence::read_untrusted_regular(
        &evidence.join("reports").join(relative),
        maximum,
    )
    .map(|(bytes, _)| bytes)
}

fn observation_report_digests(
    evidence: &Path,
    scenario_ids: &[String],
) -> Result<Vec<Value>, String> {
    let mut expected = BTreeSet::from([
        "cleanup.json".to_owned(),
        "counters.json".to_owned(),
        "gitleaks.json".to_owned(),
        "installed-packages.json".to_owned(),
        "provider-truth.json".to_owned(),
        "provenance.json".to_owned(),
        "receipt-trust-anchors.json".to_owned(),
        "receipts-python.json".to_owned(),
        "receipts-rust.json".to_owned(),
        "receipts-typescript.json".to_owned(),
        "redaction.json".to_owned(),
        "typed-forbidden-fields.json".to_owned(),
    ]);
    expected.extend(
        scenario_ids
            .iter()
            .map(|scenario| format!("scenarios/{scenario}.json")),
    );
    let actual = collect_relative_regular_files(&evidence.join("reports"), 512)?;
    if actual != expected {
        return Err("observation report roster is missing, extra, or already signed".into());
    }
    actual
        .into_iter()
        .map(|relative| {
            let bytes = read_observation_report(evidence, &relative, 16_777_216)?;
            let id = relative
                .strip_suffix(".json")
                .ok_or_else(|| "observation report has a non-JSON name".to_owned())?
                .replace('/', ":");
            Ok(json!({"id":id,"sha256":hex::encode(Sha256::digest(bytes))}))
        })
        .collect()
}

fn collect_relative_regular_files(root: &Path, maximum: usize) -> Result<BTreeSet<String>, String> {
    fn visit(
        root: &Path,
        directory: &Path,
        maximum: usize,
        files: &mut BTreeSet<String>,
    ) -> Result<(), String> {
        for entry in fs::read_dir(directory).map_err(string_error)? {
            let entry = entry.map_err(string_error)?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(string_error)?;
            if metadata.file_type().is_symlink() {
                return Err("observation report tree contains a symlink".into());
            }
            if metadata.is_dir() {
                visit(root, &path, maximum, files)?;
            } else if metadata.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(string_error)?
                    .to_str()
                    .ok_or_else(|| "observation report path is not UTF-8".to_owned())?
                    .replace(std::path::MAIN_SEPARATOR, "/");
                if !safe_relative_path(&relative) || !files.insert(relative) {
                    return Err("observation report path is unsafe or duplicated".into());
                }
                if files.len() > maximum {
                    return Err("observation report tree exceeds its file bound".into());
                }
            } else {
                return Err("observation report tree contains a special file".into());
            }
        }
        Ok(())
    }
    let metadata = fs::symlink_metadata(root).map_err(string_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("observation report root is not a regular directory".into());
    }
    let mut files = BTreeSet::new();
    visit(root, root, maximum, &mut files)?;
    Ok(files)
}

fn scenario_set_sha256(
    provider_run_id: &str,
    scenarios: &[auths_profile_kit::QualificationScenario],
    digests: &BTreeMap<String, String>,
) -> Result<String, String> {
    let projection = scenarios
        .iter()
        .filter(|scenario| {
            scenario
                .provider_run_ids()
                .binary_search_by(|run| run.as_str().cmp(provider_run_id))
                .is_ok()
        })
        .map(|scenario| {
            Ok(json!({
                "id":scenario.id(),
                "reportSha256":digests.get(scenario.id()).ok_or_else(|| "scenario digest is absent".to_owned())?,
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    if projection.is_empty() {
        return Err("provider run has no protected scenario reports".into());
    }
    Ok(hex::encode(Sha256::digest(
        serde_json_canonicalizer::to_vec(&projection).map_err(string_error)?,
    )))
}

fn scenario_set_sha256_values(
    provider_run_id: &str,
    scenarios: &[Value],
) -> Result<String, String> {
    let projection = scenarios
        .iter()
        .filter(|scenario| {
            scenario
                .get("providerRunIds")
                .and_then(Value::as_array)
                .is_some_and(|runs| runs.iter().any(|run| run.as_str() == Some(provider_run_id)))
        })
        .map(|scenario| {
            Ok(json!({
                "id":scenario.get("id").and_then(Value::as_str).ok_or_else(|| "scenario ID is absent".to_owned())?,
                "reportSha256":scenario.get("reportSha256").and_then(Value::as_str).ok_or_else(|| "scenario digest is absent".to_owned())?,
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    if projection.is_empty() {
        return Err("provider run has no candidate scenario reports".into());
    }
    Ok(hex::encode(Sha256::digest(
        serde_json_canonicalizer::to_vec(&projection).map_err(string_error)?,
    )))
}

fn package_observation(
    proposal_path: &Path,
    observation_path: &Path,
    cleanup_path: &Path,
    output: &Path,
) -> Result<(), String> {
    reject_secret_bearing_environment()?;
    if cleanup_path.file_name().and_then(|name| name.to_str()) != Some("cleanup.json")
        || cleanup_path
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            != Some("reports")
    {
        return Err("package cleanup input must be the exact reports/cleanup.json path".into());
    }
    let evidence_source = cleanup_path
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "package cleanup input has no evidence root".to_owned())?;
    let (proposal_bytes, _) =
        crate::profile_qualification_evidence::read_untrusted_regular(proposal_path, 262_144)?;
    let proposal = auths_profile_kit::QualificationProposal::from_json(&proposal_bytes)
        .map_err(string_error)?;
    let (observation_bytes, _) =
        crate::profile_qualification_evidence::read_untrusted_regular(observation_path, 262_144)?;
    let attester_repository =
        PathBuf::from(required_env("AUTHS_QUALIFICATION_ATTESTER_REPOSITORY")?);
    if git_revision(&attester_repository)? != required_env("AUTHS_QUALIFICATION_ATTESTER_REVISION")?
    {
        return Err("package attester checkout differs from protected policy".into());
    }
    let observer_registry = load_observer_trust_registry(&attester_repository)?;
    let verified = QualificationObservation::verify_json(
        &observation_bytes,
        &observer_registry,
        now_unix_seconds()?,
    )
    .map_err(string_error)?;
    let observation = verified.record();
    if observation.domain() != proposal.domain()
        || observation.target() != proposal.target()
        || observation.candidate_revision() != proposal.candidate_revision()
        || observation.profiles() != proposal.profiles()
        || observation.provider_runs() != proposal.provider_runs()
        || verified.key_id() != required_env("AUTHS_QUALIFICATION_OBSERVER_KEY_ID")?
    {
        return Err(
            "signed observation differs from the immutable proposal or observer key".into(),
        );
    }
    let cleanup_bytes = read_bounded(cleanup_path, 262_144)?;
    if hex::encode(Sha256::digest(&cleanup_bytes)) != observation.cleanup_report_sha256() {
        return Err("signed observation does not bind the supplied cleanup report".into());
    }

    let staging = tempfile::Builder::new()
        .prefix("auths-observation-package-")
        .tempdir()
        .map_err(string_error)?;
    for relative in collect_relative_regular_files(evidence_source, 4_095)? {
        if relative == "reports/protected-observation.json" {
            return Err("evidence source already contains a protected observation".into());
        }
        let (bytes, _) = crate::profile_qualification_evidence::read_untrusted_regular(
            &evidence_source.join(&relative),
            16_777_216,
        )?;
        let destination = staging.path().join(&relative);
        fs::create_dir_all(
            destination
                .parent()
                .ok_or_else(|| "evidence staging member has no parent".to_owned())?,
        )
        .map_err(string_error)?;
        atomic_write_new_owner_only(&destination, &bytes)?;
    }
    let protected_observation = staging.path().join("reports/protected-observation.json");
    atomic_write_new_owner_only(&protected_observation, &observation_bytes)?;

    fs::create_dir(output).map_err(string_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(output, fs::Permissions::from_mode(0o700)).map_err(string_error)?;
    }
    atomic_write_new_owner_only(&output.join("proposal.json"), &proposal_bytes)?;
    let archive_path = output.join("evidence.tar.zst");
    crate::profile_qualification_evidence::pack_final_evidence(staging.path(), &archive_path)?;
    let packed = crate::profile_qualification_evidence::verify_and_extract(&archive_path)?;
    validate_observation_report_commitments(&packed, observation)?;
    require_exact_ledger_roots(&packed, proposal.provider_runs().iter().map(|run| run.id()))?;
    let repository = root();
    let domain = load_domain(&repository, proposal.domain())?;
    let matrix = load_provider_matrix(&repository, &domain, proposal.target())?;
    let expected = expected_report_binding_at(
        &repository,
        &domain,
        observation,
        &matrix,
        proposal.candidate_revision(),
    )?;
    let anchors = packed.read_member("reports/receipt-trust-anchors.json", 65_536)?;
    let anchor_sha256 = hex::encode(Sha256::digest(&anchors));
    let recovery_key_id = required_env("AUTHS_QUALIFICATION_RECOVERY_KEY_ID")?;
    let recovery_public_key_base64url =
        required_env("AUTHS_QUALIFICATION_RECOVERY_PUBLIC_KEY_BASE64URL")?;
    if anchor_sha256 != required_sha256_env("AUTHS_QUALIFICATION_RECEIPT_TRUST_ANCHOR_SHA256")?
        || observation.recovery_key_id() != recovery_key_id
        || observation.recovery_public_key_base64url() != recovery_public_key_base64url
    {
        return Err("packaged receipt or recovery trust differs from protected policy".into());
    }
    let attestation_registry = load_trust_registry(&attester_repository)?;
    validate_complete_qualification_key_separation(
        &attester_repository,
        &attestation_registry,
        &observer_registry,
        &anchors,
        &recovery_key_id,
        &recovery_public_key_base64url,
    )?;
    let attester_tools = verified_attester_tools_from_files(
        Path::new(&required_env(
            "AUTHS_QUALIFICATION_ATTESTER_TOOLS_VERIFICATION",
        )?),
        Path::new(&required_env(
            "AUTHS_QUALIFICATION_ATTESTER_TOOLS_MANIFEST",
        )?),
    )?;
    validate_attester_tools_binding(
        &attester_tools,
        now_unix_seconds()?,
        observation.repository_id(),
    )?;
    if attester_tools_identity_sha256(&attester_tools)? != observation.attester_tools_sha256() {
        return Err("packaged attester-tool identity differs from the signed observation".into());
    }
    let retained = verify_retained_evidence_ledgers(
        &attester_repository,
        &packed,
        observation,
        &attester_tools,
        None,
    )?;
    receipt_verification_projection(&packed, &anchors, &anchor_sha256, &expected, &retained)?;
    Ok(())
}

fn aggregate_observation_reports(
    proposal_path: &Path,
    collections: &Path,
    common_evidence: &Path,
    receipt_trust_path: &Path,
    output: &Path,
) -> Result<(), String> {
    reject_secret_bearing_environment()?;
    let (proposal_bytes, _) =
        crate::profile_qualification_evidence::read_untrusted_regular(proposal_path, 262_144)?;
    let proposal = auths_profile_kit::QualificationProposal::from_json(&proposal_bytes)
        .map_err(string_error)?;
    let repository = root();
    if git_revision(&repository)? != proposal.candidate_revision() {
        return Err("aggregate observer candidate checkout differs from proposal".into());
    }
    let domain = load_domain(&repository, proposal.domain())?;
    let matrix = load_provider_matrix(&repository, &domain, proposal.target())?;
    validate_observed_provider_runs(&matrix, proposal.provider_runs())?;
    let (receipt_trust_bytes, _) =
        crate::profile_qualification_evidence::read_untrusted_regular(receipt_trust_path, 65_536)?;
    auths_receipts::decode_receipt_trust_anchors(&receipt_trust_bytes).map_err(string_error)?;
    if hex::encode(Sha256::digest(&receipt_trust_bytes))
        != required_sha256_env("AUTHS_QUALIFICATION_RECEIPT_TRUST_ANCHOR_SHA256")?
    {
        return Err("receipt trust-anchor snapshot differs from protected policy".into());
    }

    struct RunReports {
        collection: CandidateCollection,
        observed: ProtectedObservedProviderRun,
        cleanup: ProtectedCleanupProviderRun,
    }
    let mut runs = Vec::with_capacity(matrix.runs.len());
    for matrix_run in &matrix.runs {
        let collection_bytes = read_bounded(
            &collections.join(&matrix_run.id).join("collection.json"),
            MAX_CANDIDATE_COLLECTION_BYTES,
        )?;
        let collection: CandidateCollection =
            serde_json::from_slice(&collection_bytes).map_err(string_error)?;
        let observed_bytes = read_bounded(
            &common_evidence.join(&matrix_run.id).join("observed.json"),
            16_777_216,
        )?;
        let observed: ProtectedObservedProviderRun =
            serde_json::from_slice(&observed_bytes).map_err(string_error)?;
        let cleanup_bytes = read_bounded(
            &common_evidence.join(&matrix_run.id).join("cleanup.json"),
            262_144,
        )?;
        let cleanup: ProtectedCleanupProviderRun =
            serde_json::from_slice(&cleanup_bytes).map_err(string_error)?;
        if collection.validate().is_err()
            || serde_json_canonicalizer::to_vec(&collection).map_err(string_error)?
                != collection_bytes
            || serde_json_canonicalizer::to_vec(&observed).map_err(string_error)? != observed_bytes
            || serde_json_canonicalizer::to_vec(&cleanup).map_err(string_error)? != cleanup_bytes
            || collection.schema != "auths.profile-qualification-candidate-collection/1"
            || observed.schema != "auths.profile-qualification-observed-provider-run/1"
            || cleanup.schema != "auths.profile-qualification-cleanup-provider-run/1"
        {
            return Err(format!(
                "provider row reports are noncanonical or malformed: {}",
                matrix_run.id
            ));
        }
        collection.run_reference.validate().map_err(string_error)?;
        if collection.run_reference != observed.run_reference
            || collection.run_reference.provider_run_id != matrix_run.id
            || collection.run_reference.domain != proposal.domain()
            || collection.run_reference.target != proposal.target()
            || collection.run_reference.candidate_revision != proposal.candidate_revision()
            || cleanup.repository_id != collection.run_reference.repository_id
            || cleanup.candidate_revision != collection.run_reference.candidate_revision
            || cleanup.target != collection.run_reference.target
            || cleanup.run_id != collection.run_reference.run_id
            || cleanup.run_attempt != collection.run_reference.run_attempt
            || cleanup.provider_run_id != collection.run_reference.provider_run_id
            || cleanup.protected_environment != required_env("QUALIFICATION_PROTECTED_ENVIRONMENT")?
        {
            return Err(format!(
                "provider row reports disagree on protected identity: {}",
                matrix_run.id
            ));
        }
        cleanup.evidence.validate().map_err(string_error)?;
        if collection.scenarios.len() != matrix_run.scenario_ids.len()
            || collection
                .scenarios
                .iter()
                .map(|scenario| scenario.scenario_id.as_str())
                .ne(matrix_run.scenario_ids.iter().map(String::as_str))
            || observed.scenarios.len() != collection.scenarios.len()
            || observed
                .scenarios
                .iter()
                .map(|scenario| scenario.scenario_id.as_str())
                .ne(collection
                    .scenarios
                    .iter()
                    .map(|scenario| scenario.scenario_id.as_str()))
        {
            return Err(format!(
                "provider row does not exactly cover its scenario roster: {}",
                matrix_run.id
            ));
        }
        for (collected, protected) in collection.scenarios.iter().zip(&observed.scenarios) {
            let program = scenario_program_at(
                &repository,
                &domain,
                proposal.candidate_revision(),
                &collected.scenario_id,
            )?;
            let operation_ids = protected
                .operations
                .iter()
                .flat_map(|operation| &operation.instances)
                .map(|instance| instance.operation_id.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            let truths = observed
                .provider_truth
                .iter()
                .filter(|truth| operation_ids.contains(truth.operation_id.as_str()))
                .map(|truth| {
                    let commitment = hex::decode(&truth.commitment_sha256)
                        .map_err(string_error)?
                        .try_into()
                        .map_err(|_| {
                            "protected provider truth commitment has the wrong length".to_owned()
                        })?;
                    let domain_facts = serde_json_canonicalizer::to_vec(&truth.domain_facts)
                        .map_err(string_error)?;
                    if hex::encode(Sha256::digest(&domain_facts)) != truth.commitment_sha256 {
                        return Err(
                            "protected provider truth facts differ from their commitment".into(),
                        );
                    }
                    Ok(auths_profile_kit::QualificationProviderTruth {
                        operation_id: truth.operation_id.clone(),
                        provider_run_id: truth.provider_run_id.clone(),
                        effect: truth.effect,
                        provider_calls: truth.provider_calls,
                        commitment,
                        domain_facts,
                        provider_version: truth.provider_version.clone(),
                        provider_artifact_sha256: truth.provider_artifact_sha256.clone(),
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            if protected.scenario_program_sha256 != program.sha256().map_err(string_error)?
                || protected.domain_predicate_sha256
                    != scenario_predicate_sha256(
                        &program,
                        collected.failpoint,
                        &protected.operations,
                        &truths,
                    )?
            {
                return Err(
                    "protected scenario predicate commitment differs at aggregation".into(),
                );
            }
            auths_profile_kit::validate_scenario_program_projection(
                &program,
                collected.failpoint,
                &protected.operations,
                &truths,
            )
            .map_err(string_error)?;
            crate::profile_qualification_adapters::validate_domain_scenario(
                proposal.domain(),
                &program,
                &protected.operations,
                &truths,
            )?;
        }
        runs.push(RunReports {
            collection,
            observed,
            cleanup,
        });
    }

    let mut operation_ids = BTreeSet::new();
    let mut connection_generations = BTreeSet::new();
    let mut counter_rows = BTreeMap::new();
    let mut expected_truth = BTreeMap::new();
    let mut truth_rows = BTreeMap::new();
    for run in &runs {
        for scenario in &run.observed.scenarios {
            for operation in &scenario.operations {
                operation.validate().map_err(string_error)?;
                for instance in &operation.instances {
                    if !operation_ids.insert(instance.operation_id.clone())
                        || counter_rows
                            .insert(instance.operation_id.clone(), instance.counters.clone())
                            .is_some()
                    {
                        return Err("aggregate observation repeats an operation ID".into());
                    }
                    connection_generations.insert(instance.connection_generation.clone());
                    expected_truth.insert(
                        instance.operation_id.clone(),
                        (
                            instance.effect,
                            instance.counters.provider_calls,
                            instance.provider_truth_sha256.clone(),
                        ),
                    );
                }
            }
        }
        for truth in &run.observed.provider_truth {
            let matrix_run = matrix
                .runs
                .iter()
                .find(|candidate| candidate.id == run.collection.run_reference.provider_run_id)
                .ok_or_else(|| "protected provider truth names an absent matrix row".to_owned())?;
            if expected_truth.get(&truth.operation_id)
                != Some(&(
                    truth.effect,
                    truth.provider_calls,
                    truth.commitment_sha256.clone(),
                ))
                || truth.provider_run_id != matrix_run.id
                || truth.provider_version != matrix_run.provider_version
                || truth.provider_artifact_sha256 != matrix_run.provider_artifact_sha256
            {
                return Err(
                    "provider truth differs from its protected operation projection".into(),
                );
            }
            if truth_rows
                .insert(
                    truth.operation_id.clone(),
                    json!({
                        "operationId":truth.operation_id,
                        "providerRunId":truth.provider_run_id,
                        "providerVersion":truth.provider_version,
                        "providerArtifactSha256":truth.provider_artifact_sha256,
                        "effect":truth.effect,
                        "providerCalls":truth.provider_calls,
                        "commitmentSha256":truth.commitment_sha256,
                        "domainFacts":truth.domain_facts,
                    }),
                )
                .is_some()
            {
                return Err("aggregate provider truth repeats an operation ID".into());
            }
        }
    }
    if operation_ids.is_empty() || truth_rows.keys().ne(operation_ids.iter()) {
        return Err("aggregate provider truth does not cover every operation".into());
    }

    let profiles = proposal
        .profiles()
        .iter()
        .map(auths_profile_kit::QualificationProfile::semantic_subject)
        .collect::<Vec<_>>();
    let provider_run_ids = matrix
        .runs
        .iter()
        .map(|run| run.id.clone())
        .collect::<Vec<_>>();
    let scenario_ids = proposal
        .scenarios()
        .iter()
        .map(|scenario| scenario.id().to_owned())
        .collect::<Vec<_>>();
    let binding = json!({
        "repositoryId":required_env("GITHUB_REPOSITORY_ID")?,
        "workflowRunId":required_env("GITHUB_RUN_ID")?,
        "workflowRunAttempt":required_env("GITHUB_RUN_ATTEMPT")?.parse::<u32>().map_err(string_error)?,
        "candidateRevision":proposal.candidate_revision(),
        "domain":proposal.domain(),
        "target":proposal.target(),
        "profiles":profiles,
        "providerRunIds":provider_run_ids,
        "scenarioIds":scenario_ids,
        "failpoints":all_qualification_failpoints(),
        "operationIds":operation_ids,
        "connectionGenerations":connection_generations,
    });

    let mut scenario_reports = BTreeMap::new();
    for proposed in proposal.scenarios() {
        let applicable = matrix
            .runs
            .iter()
            .filter(|run| {
                run.scenario_ids
                    .binary_search_by(|id| id.as_str().cmp(proposed.id()))
                    .is_ok()
            })
            .map(|run| run.id.clone())
            .collect::<Vec<_>>();
        if applicable != proposed.provider_run_ids() {
            return Err(format!(
                "proposal scenario applicability differs from provider matrix: {}",
                proposed.id()
            ));
        }
        let mut executions = Vec::with_capacity(applicable.len());
        let mut assertions = 0_u32;
        for run_id in &applicable {
            let run = runs
                .iter()
                .find(|run| run.collection.run_reference.provider_run_id == *run_id)
                .ok_or_else(|| "applicable provider run is absent".to_owned())?;
            let collected = run
                .collection
                .scenarios
                .iter()
                .find(|scenario| scenario.scenario_id == proposed.id())
                .ok_or_else(|| "candidate scenario is absent from applicable run".to_owned())?;
            let observed = run
                .observed
                .scenarios
                .iter()
                .find(|scenario| scenario.scenario_id == proposed.id())
                .ok_or_else(|| "protected scenario is absent from applicable run".to_owned())?;
            if collected.failpoint != expected_failpoint(proposed.id())
                || collected.operations.len() != observed.operations.len()
            {
                return Err("candidate/protected scenario operation count differs".into());
            }
            let mut operations = Vec::with_capacity(observed.operations.len());
            for (candidate, protected) in collected.operations.iter().zip(&observed.operations) {
                if candidate.role != protected.role || candidate.profile != protected.profile {
                    return Err("candidate phase identity differs from protected evidence".into());
                }
                let mut value = serde_json::to_value(protected).map_err(string_error)?;
                let object = value
                    .as_object_mut()
                    .ok_or_else(|| "protected operation is not an object".to_owned())?;
                let instances = object
                    .get_mut("instances")
                    .and_then(Value::as_array_mut)
                    .ok_or_else(|| "protected operation instances are absent".to_owned())?;
                for instance in instances.iter_mut() {
                    instance
                        .as_object_mut()
                        .ok_or_else(|| "protected operation instance is not an object".to_owned())?
                        .insert(
                            "failpoint".into(),
                            serde_json::to_value(expected_failpoint(proposed.id()))
                                .map_err(string_error)?,
                        );
                }
                assertions = assertions
                    .checked_add(u32::try_from(instances.len()).map_err(string_error)?)
                    .and_then(|value| {
                        value.checked_add(u32::try_from(protected.attempts.len()).ok()?)
                    })
                    .ok_or_else(|| "scenario assertion count overflow".to_owned())?;
                operations.push(value);
            }
            executions.push(json!({"providerRunId":run_id,"operations":operations}));
        }
        let report = json!({
            "schema":"auths.profile-qualification-scenario-report/1",
            "binding":binding,
            "scenarioId":proposed.id(),
            "assertions":assertions,
            "executions":executions,
            "status":"passed",
        });
        let bytes = serde_json_canonicalizer::to_vec(&report).map_err(string_error)?;
        let parsed: crate::profile_qualification_reports::ScenarioReport =
            crate::profile_qualification_reports::parse_canonical(&bytes)?;
        let expected = expected_binding_from_value(&binding, &proposal)?;
        parsed.validate(&expected)?;
        if assertions != proposed.assertions()
            || hex::encode(Sha256::digest(&bytes)) != proposed.report_sha256()
        {
            return Err(format!(
                "candidate proposal did not predict protected scenario report: {}",
                proposed.id()
            ));
        }
        scenario_reports.insert(proposed.id().to_owned(), bytes);
    }

    let counters = json!({
        "schema":"auths.profile-qualification-counters-report/1",
        "binding":binding,
        "operations":counter_rows.into_iter().map(|(operation_id,counters)| json!({"operationId":operation_id,"counters":counters})).collect::<Vec<_>>(),
    });
    let truth = json!({
        "schema":"auths.profile-qualification-provider-truth-report/1",
        "binding":binding,
        "operations":truth_rows.into_values().collect::<Vec<_>>(),
    });
    let completed_at = runs
        .iter()
        .map(|run| run.cleanup.completed_at_unix_seconds)
        .max()
        .ok_or_else(|| "cleanup report roster is empty".to_owned())?;
    let cleanup = json!({
        "schema":"auths.profile-qualification-cleanup-report/1",
        "binding":binding,
        "status":"passed",
        "providerResourcesDestroyed":true,
        "connectionDisabled":true,
        "credentialsRevoked":true,
        "residualResourceCount":0,
        "completedAtUnixSeconds":completed_at,
    });
    let expected = expected_binding_from_value(&binding, &proposal)?;
    let counters_bytes = serde_json_canonicalizer::to_vec(&counters).map_err(string_error)?;
    let parsed_counters: crate::profile_qualification_reports::CountersReport =
        crate::profile_qualification_reports::parse_canonical(&counters_bytes)?;
    parsed_counters.validate(&expected)?;
    let truth_bytes = serde_json_canonicalizer::to_vec(&truth).map_err(string_error)?;
    let parsed_truth: crate::profile_qualification_reports::ProviderTruthReport =
        crate::profile_qualification_reports::parse_canonical(&truth_bytes)?;
    parsed_truth.validate(&expected, proposal.domain())?;
    let cleanup_bytes = serde_json_canonicalizer::to_vec(&cleanup).map_err(string_error)?;
    let parsed_cleanup: crate::profile_qualification_reports::CleanupReport =
        crate::profile_qualification_reports::parse_canonical(&cleanup_bytes)?;
    parsed_cleanup.validate(&expected)?;

    fs::create_dir(output).map_err(string_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(output, fs::Permissions::from_mode(0o700)).map_err(string_error)?;
    }
    let reports = output.join("reports");
    let scenarios = reports.join("scenarios");
    fs::create_dir_all(&scenarios).map_err(string_error)?;
    atomic_write_new_owner_only(&reports.join("counters.json"), &counters_bytes)?;
    atomic_write_new_owner_only(&reports.join("provider-truth.json"), &truth_bytes)?;
    atomic_write_new_owner_only(&reports.join("cleanup.json"), &cleanup_bytes)?;
    atomic_write_new_owner_only(
        &reports.join("receipt-trust-anchors.json"),
        &receipt_trust_bytes,
    )?;
    for (scenario, bytes) in scenario_reports {
        atomic_write_new_owner_only(&scenarios.join(format!("{scenario}.json")), &bytes)?;
    }
    Ok(())
}

fn expected_binding_from_value(
    binding: &Value,
    proposal: &auths_profile_kit::QualificationProposal,
) -> Result<crate::profile_qualification_reports::ExpectedReportBinding, String> {
    let binding: crate::profile_qualification_reports::ReportBinding =
        serde_json::from_value(binding.clone()).map_err(string_error)?;
    let scenario_applicability = proposal
        .scenarios()
        .iter()
        .map(|scenario| {
            (
                scenario.id().to_owned(),
                scenario.provider_run_ids().to_vec(),
            )
        })
        .collect();
    Ok(
        crate::profile_qualification_reports::ExpectedReportBinding {
            repository_id: binding.repository_id,
            workflow_run_id: binding.workflow_run_id,
            workflow_run_attempt: binding.workflow_run_attempt,
            candidate_revision: binding.candidate_revision,
            domain: binding.domain,
            target: binding.target,
            profiles: binding.profiles,
            provider_run_ids: binding.provider_run_ids,
            scenario_ids: binding.scenario_ids,
            failpoints: binding.failpoints,
            operation_ids: binding.operation_ids,
            connection_generations: binding.connection_generations,
            scenario_applicability,
        },
    )
}

fn installed_member_name(role: &str) -> &'static str {
    match role {
        "production-agent" => "auths-production-agent.tar.zst",
        "python-native" => "auths-python-native.so",
        "python-profile-opentofu" => "auths-python-profile-opentofu.tar.zst",
        "python-profile-postgresql" => "auths-python-profile-postgresql.tar.zst",
        "python-profile-stripe" => "auths-python-profile-stripe.tar.zst",
        "python-wheel" => "auths-python-wheel.whl",
        "qualification-agent" => "auths-qualification-agent.tar.zst",
        "typescript-native" => "auths-typescript-native.wasm",
        "typescript-package" => "auths-typescript-package.tgz",
        _ => unreachable!("closed installed artifact role"),
    }
}

fn validate_installed_package_directory(packages: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(packages).map_err(string_error)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("installed package input is not a regular directory".into());
    }
    let mut roles = fs::read_dir(packages)
        .map_err(string_error)?
        .map(|entry| entry.map_err(string_error))
        .collect::<Result<Vec<_>, _>>()?;
    roles.sort_by_key(|entry| entry.file_name());
    if roles
        .iter()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .ne(VERIFIED_RELEASE_ARTIFACT_ROLES
            .iter()
            .map(|role| role.to_string()))
    {
        return Err("installed package directory has an extra, missing, or reordered role".into());
    }
    for (entry, role) in roles.iter().zip(VERIFIED_RELEASE_ARTIFACT_ROLES) {
        let metadata = fs::symlink_metadata(entry.path()).map_err(string_error)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(format!("installed role is not a regular directory: {role}"));
        }
        let names = fs::read_dir(entry.path())
            .map_err(string_error)?
            .map(|value| value.map(|value| value.file_name()).map_err(string_error))
            .collect::<Result<Vec<_>, _>>()?;
        if names.len() != 1 || names[0] != installed_member_name(role) {
            return Err(format!("installed role has an unexpected member: {role}"));
        }
    }
    Ok(())
}

fn resolve_installed_tool(variable: &str, fallback: &str) -> Result<PathBuf, String> {
    let candidate = env::var_os(variable)
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("PATH").and_then(|path| {
                env::split_paths(&path)
                    .map(|directory| directory.join(fallback))
                    .find(|path| path.is_file())
            })
        })
        .ok_or_else(|| format!("installed verifier cannot locate {fallback}"))?;
    let resolved = fs::canonicalize(candidate).map_err(string_error)?;
    if !resolved.is_file() {
        return Err(format!(
            "installed verifier tool is not a regular file: {fallback}"
        ));
    }
    Ok(resolved)
}

fn require_tool_version(
    program: &Path,
    arguments: &[&str],
    expected: &str,
    label: &str,
) -> Result<(), String> {
    let output = Command::new(program)
        .args(arguments)
        .env_clear()
        .output()
        .map_err(string_error)?;
    let combined = if output.stdout.is_empty() {
        &output.stderr
    } else {
        &output.stdout
    };
    if !output.status.success() || String::from_utf8_lossy(combined).trim() != expected {
        return Err(format!(
            "installed {label} runtime differs from the proposal toolchain"
        ));
    }
    Ok(())
}

fn validate_native_package_links(
    python: &Path,
    wheel: &Path,
    native: &Path,
    package: &Path,
    wasm: &Path,
    temporary: &Path,
) -> Result<(), String> {
    let status = Command::new(python)
        .arg("-I")
        .arg("-c")
        .arg(INSTALLED_PYTHON_LINK_FIXTURE)
        .arg(wheel)
        .arg(native)
        .arg(package)
        .arg(wasm)
        .current_dir(temporary)
        .env_clear()
        .status()
        .map_err(string_error)?;
    if !status.success() {
        return Err("installed package/native structural linkage failed".into());
    }
    Ok(())
}

fn run_installed_rust_consumer(archive_path: &Path, temporary: &Path) -> Result<(), String> {
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt as _;
    let file = fs::File::open(archive_path).map_err(string_error)?;
    let decoder = zstd::Decoder::new(file).map_err(string_error)?;
    let mut archive = tar::Archive::new(decoder);
    let output = temporary.join("auths-installed");
    let expected = [
        "auths-production-agent/target/release/auths",
        "auths-production-agent/target/release/stripe-refund-evidence-reader",
    ];
    let mut seen = Vec::new();
    for entry in archive.entries().map_err(string_error)? {
        let entry = entry.map_err(string_error)?;
        let path = entry
            .path()
            .map_err(string_error)?
            .to_string_lossy()
            .into_owned();
        if !entry.header().entry_type().is_file() || !expected.contains(&path.as_str()) {
            return Err("production agent archive has an unsafe or extra member".into());
        }
        seen.push(path.clone());
        if path.ends_with("/auths") {
            let mut bytes = Vec::new();
            entry
                .take(536_870_913)
                .read_to_end(&mut bytes)
                .map_err(string_error)?;
            if bytes.is_empty() || bytes.len() > 536_870_912 {
                return Err("installed Rust binary exceeds its bound".into());
            }
            atomic_write_new_owner_only(&output, &bytes)?;
            fs::set_permissions(&output, fs::Permissions::from_mode(0o700))
                .map_err(string_error)?;
        }
    }
    seen.sort();
    if seen != expected {
        return Err("production agent archive roster drifted".into());
    }
    let status = Command::new(output)
        .arg("--help")
        .current_dir(temporary)
        .env_clear()
        .status()
        .map_err(string_error)?;
    if !status.success() {
        return Err("installed Rust production agent did not start".into());
    }
    Ok(())
}

fn run_installed_python_consumer(
    python: &Path,
    wheel: &Path,
    profile_archive: &Path,
    domain: &str,
    temporary: &Path,
) -> Result<(), String> {
    let (installed_python, profile_source) =
        install_python_client(python, wheel, profile_archive, domain, temporary)?;
    let status = Command::new(&installed_python)
        .arg("-I")
        .arg("-c")
        .arg(INSTALLED_PYTHON_PROFILE_IMPORT_FIXTURE)
        .arg(profile_source)
        .arg(domain)
        .current_dir(temporary)
        .env_clear()
        .env("PYTHONNOUSERSITE", "1")
        .status()
        .map_err(string_error)?;
    if !status.success() {
        return Err("installed generated Python profile consumer failed".into());
    }
    Ok(())
}

fn install_python_client(
    python: &Path,
    wheel: &Path,
    profile_archive: &Path,
    domain: &str,
    temporary: &Path,
) -> Result<(PathBuf, PathBuf), String> {
    let environment = temporary.join("python-consumer");
    let status = Command::new(python)
        .args(["-I", "-m", "venv"])
        .arg(&environment)
        .current_dir(temporary)
        .env_clear()
        .status()
        .map_err(string_error)?;
    if !status.success() {
        return Err("could not create isolated installed Python consumer".into());
    }
    let installed_python = environment.join("bin/python");
    let status = Command::new(&installed_python)
        .args([
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--disable-pip-version-check",
        ])
        .arg(wheel)
        .current_dir(temporary)
        .env_clear()
        .env("PIP_NO_INDEX", "1")
        .env("PYTHONNOUSERSITE", "1")
        .status()
        .map_err(string_error)?;
    if !status.success() {
        return Err("could not install exact Python wheel offline".into());
    }
    let status = Command::new(&installed_python)
        .arg("-I")
        .arg("-c")
        .arg(INSTALLED_PYTHON_IMPORT_FIXTURE)
        .current_dir(temporary)
        .env_clear()
        .env("PYTHONNOUSERSITE", "1")
        .status()
        .map_err(string_error)?;
    if !status.success() {
        return Err("installed Python public consumer failed".into());
    }
    let profile_source = extract_generated_python_profile(profile_archive, domain, temporary)?;
    Ok((installed_python, profile_source))
}

fn extract_generated_python_profile(
    archive_path: &Path,
    domain: &str,
    temporary: &Path,
) -> Result<PathBuf, String> {
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt as _;

    if !matches!(domain, "opentofu" | "postgresql" | "stripe") {
        return Err("installed generated Python profile domain is invalid".into());
    }
    let source_prefix = format!("auths-profile-{domain}/bindings/generated/{domain}/python/");
    let expected = [
        "README.md".to_owned(),
        "pyproject.toml".to_owned(),
        format!("src/auths_profiles/{domain}/__init__.py"),
        format!("src/auths_profiles/{domain}/generated.py"),
        format!("src/auths_profiles/{domain}/py.typed"),
    ];
    let file = fs::File::open(archive_path).map_err(string_error)?;
    let decoder = zstd::Decoder::new(file).map_err(string_error)?;
    let mut archive = tar::Archive::new(decoder);
    let mut files = BTreeMap::<String, Vec<u8>>::new();
    for entry in archive.entries().map_err(string_error)? {
        let entry = entry.map_err(string_error)?;
        let path = entry
            .path()
            .map_err(string_error)?
            .to_str()
            .ok_or_else(|| "generated Python profile archive path is not UTF-8".to_owned())?
            .to_owned();
        let relative = path
            .strip_prefix(&source_prefix)
            .ok_or_else(|| "generated Python profile archive prefix drifted".to_owned())?;
        if !entry.header().entry_type().is_file()
            || entry.header().mode().map_err(string_error)? != 0o644
            || !expected.iter().any(|candidate| candidate == relative)
            || files.contains_key(relative)
        {
            return Err("generated Python profile archive roster is unsafe".into());
        }
        let mut bytes = Vec::new();
        entry
            .take(16_777_217)
            .read_to_end(&mut bytes)
            .map_err(string_error)?;
        if bytes.is_empty() || bytes.len() > 16_777_216 {
            return Err("generated Python profile member exceeds its bound".into());
        }
        files.insert(relative.to_owned(), bytes);
    }
    if files.keys().ne(expected.iter()) {
        return Err("generated Python profile archive roster drifted".into());
    }
    let output = temporary.join(format!("python-profile-{domain}"));
    for (relative, bytes) in files {
        let destination = output.join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(string_error)?;
        }
        atomic_write_new_owner_only(&destination, &bytes)?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o644))
            .map_err(string_error)?;
    }
    Ok(output.join("src"))
}

fn combined_file_sha256(paths: &[&Path]) -> Result<String, String> {
    let mut digest = Sha256::new();
    digest.update(b"AUTHS-QUALIFICATION-INSTALLED-ARTIFACT-SET\0\x01");
    for path in paths {
        let bytes = read_bounded(path, 536_870_912)?;
        digest.update(
            u64::try_from(bytes.len())
                .map_err(string_error)?
                .to_be_bytes(),
        );
        digest.update(bytes);
    }
    Ok(hex::encode(digest.finalize()))
}

fn run_installed_typescript_consumer(
    node: &Path,
    npm: &Path,
    package: &Path,
    temporary: &Path,
) -> Result<(), String> {
    let consumer = temporary.join("typescript-consumer");
    fs::create_dir(&consumer).map_err(string_error)?;
    atomic_write_new_owner_only(
        &consumer.join("package.json"),
        br#"{"private":true,"type":"module"}"#,
    )?;
    let command_path = env::join_paths([
        node.parent()
            .ok_or("installed Node executable has no parent")?,
        npm.parent()
            .ok_or("installed npm executable has no parent")?,
        Path::new("/usr/bin"),
        Path::new("/bin"),
    ])
    .map_err(string_error)?;
    let status = Command::new(npm)
        .args([
            "install",
            "--offline",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--package-lock=false",
        ])
        .arg(package)
        .current_dir(&consumer)
        .env_clear()
        .env("HOME", temporary)
        .env("PATH", command_path)
        .env("npm_config_offline", "true")
        .status()
        .map_err(string_error)?;
    if !status.success() {
        return Err("could not install exact TypeScript package offline".into());
    }
    let status = Command::new(node)
        .args([
            "--input-type=module",
            "-e",
            INSTALLED_TYPESCRIPT_IMPORT_FIXTURE,
        ])
        .current_dir(&consumer)
        .env_clear()
        .status()
        .map_err(string_error)?;
    if !status.success() {
        return Err("installed TypeScript public consumer failed".into());
    }
    Ok(())
}

fn check_arguments(arguments: &[String]) -> Result<(), String> {
    match arguments {
        [all] if all == "--all" => qualification_check(&root(), None),
        [flag, domain] if flag == "--domain" => qualification_check(&root(), Some(domain)),
        _ => Err(usage()),
    }
}

fn status(arguments: &[String]) -> Result<(), String> {
    let selected = match arguments {
        [] => None,
        [flag, domain] if flag == "--domain" => Some(domain.as_str()),
        _ => return Err(usage()),
    };
    let repository = root();
    let roster = load_roster(&repository)?;
    let index = load_index(&repository)?;
    let mut values = Vec::new();
    for package in roster.packages() {
        if selected.is_some_and(|domain| domain != package.domain()) {
            continue;
        }
        for profile in package.profiles() {
            let targets = profile
                .targets()
                .iter()
                .map(|target| {
                    json!({
                        "target": target.as_str(),
                        "qualificationId": index.qualification_id(profile.profile_ref(), *target),
                    })
                })
                .collect::<Vec<_>>();
            values.push(json!({
                "domain": package.domain(),
                "profile": profile.profile_ref(),
                "state": profile.qualification(),
                "targets": targets,
            }));
        }
    }
    if selected.is_some() && values.is_empty() {
        return Err("selected qualification domain is not in the static roster".into());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema":"auths.profile-qualification-status/1",
            "profiles":values
        }))
        .map_err(string_error)?
    );
    Ok(())
}

fn collect_arguments(arguments: &[String]) -> Result<(), String> {
    if arguments.len() != 12
        || arguments[0] != "--domain"
        || arguments[2] != "--target"
        || arguments[4] != "--environment"
        || arguments[6] != "--provider-run"
        || arguments[8] != "--setup-handoff"
        || arguments[10] != "--output"
    {
        return Err(usage());
    }
    let domain = &arguments[1];
    let target = QualificationTarget::parse(&arguments[3]).map_err(string_error)?;
    let environment = &arguments[5];
    let provider_run_id = &arguments[7];
    let repository = root();
    let context = load_domain(&repository, domain)?;
    if !context.package.qualification().targets().contains(&target)
        || context.package.qualification().protected_environment() != environment
    {
        return Err(
            "qualification run target or protected environment is not manifest-owned".into(),
        );
    }
    let provider_run = require_provider_run(&repository, &context, target, provider_run_id)?;
    let output_relative = PathBuf::from("target")
        .join("qualification-candidate")
        .join(domain)
        .join(target.as_str())
        .join(provider_run_id);
    require_exact_output_path(&repository, Path::new(&arguments[11]), &output_relative)?;
    let output = create_private_output_directory(&repository, &output_relative)?;
    let operation_plans = load_operation_plans(&repository, &context)?;
    if env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || reject_secret_bearing_environment().is_err()
    {
        return Err(
            "candidate collection must be a no-secret coordinator in the protected workflow".into(),
        );
    }
    crate::profile_qualification_adapters::run_collection_adapter(RunAdapterContext {
        repository: &repository,
        domain,
        target,
        environment,
        provider_run_id,
        scenario_ids: &provider_run.scenario_ids,
        operation_plans: &operation_plans,
        package: &context.package,
        setup_handoff: Path::new(&arguments[9]),
        output: &output,
    })
}

fn observe_arguments(arguments: &[String]) -> Result<(), String> {
    if arguments.len() != 14
        || arguments[0] != "--domain"
        || arguments[2] != "--target"
        || arguments[4] != "--environment"
        || arguments[6] != "--provider-run"
        || arguments[8] != "--candidate-evidence"
        || arguments[10] != "--common-evidence"
        || arguments[12] != "--output"
    {
        return Err(usage());
    }
    let domain = &arguments[1];
    let target = QualificationTarget::parse(&arguments[3]).map_err(string_error)?;
    let environment = &arguments[5];
    let provider_run_id = &arguments[7];
    let evidence = Path::new(&arguments[9]);
    let common_evidence = Path::new(&arguments[11]);
    let repository = root();
    let attester_repository =
        PathBuf::from(required_env("AUTHS_QUALIFICATION_ATTESTER_REPOSITORY")?);
    if git_revision(&attester_repository)? != required_env("AUTHS_QUALIFICATION_ATTESTER_REVISION")?
    {
        return Err("protected observer trust repository revision drifted".into());
    }
    let context = load_domain(&repository, domain)?;
    let provider_run = require_provider_run(&repository, &context, target, provider_run_id)?;
    let operation_plans = load_operation_plans(&repository, &context)?;
    let protected_output_root = PathBuf::from(required_env("QUALIFICATION_PROTECTED_OUTPUT_ROOT")?);
    let output_relative = PathBuf::from(domain)
        .join(target.as_str())
        .join(provider_run_id);
    require_exact_output_path(
        &protected_output_root,
        Path::new(&arguments[13]),
        &output_relative,
    )?;
    let output = create_private_output_directory(&protected_output_root, &output_relative)?;
    if !context.package.qualification().targets().contains(&target)
        || context.package.qualification().protected_environment() != environment
        || env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || validate_secret_zone(
            &["OBSERVER_CREDENTIAL"],
            &[
                "CLEANUP_CREDENTIAL",
                "OBSERVER_SEED",
                "SETUP_CREDENTIAL",
                "MUTATION_CREDENTIAL",
                "RUNTIME_READ_CREDENTIAL",
                "DECISION_RECEIPT_SEED",
                "EXECUTION_RECEIPT_SEED",
                "RECOVERY_SEED",
                "ATTESTATION_SEED",
            ],
        )
        .is_err()
        || env::var("AUTHS_QUALIFICATION_RECEIPT_TRUST_ANCHOR_SHA256")
            .ok()
            .is_none_or(|value| !lower_hex(&value, 64))
    {
        return Err("protected observer inputs do not match the manifest-owned trust zone".into());
    }
    crate::profile_qualification_adapters::run_protected_observer(ObserveAdapterContext {
        repository: &repository,
        attester_repository: &attester_repository,
        domain,
        target,
        environment,
        provider_run_id,
        scenario_ids: &provider_run.scenario_ids,
        operation_plans: &operation_plans,
        evidence,
        common_evidence,
        package: &context.package,
        output: &output,
    })
}

fn cleanup_arguments(arguments: &[String]) -> Result<(), String> {
    if arguments.len() != 8
        || arguments[0] != "--domain"
        || arguments[2] != "--target"
        || arguments[4] != "--run-context"
        || arguments[6] != "--output"
    {
        return Err(usage());
    }
    let domain = &arguments[1];
    let target = QualificationTarget::parse(&arguments[3]).map_err(string_error)?;
    let run_context_path = Path::new(&arguments[5]);
    let repository = root();
    let domain_context = load_domain(&repository, domain)?;
    let (bytes, _) =
        crate::profile_qualification_evidence::read_untrusted_regular(run_context_path, 65_536)?;
    let run_context: auths_profile_kit::QualificationRunContext =
        serde_json::from_slice(&bytes).map_err(string_error)?;
    if serde_json_canonicalizer::to_vec(&run_context).map_err(string_error)? != bytes
        || run_context.repository_id != required_env("GITHUB_REPOSITORY_ID")?
        || run_context.candidate_revision != required_env("QUALIFICATION_CANDIDATE_REVISION")?
        || run_context.run_id != required_env("GITHUB_RUN_ID")?
        || run_context.run_attempt
            != required_env("GITHUB_RUN_ATTEMPT")?
                .parse::<u32>()
                .map_err(string_error)?
        || run_context.target != target
        || run_context.protected_environment
            != domain_context
                .package
                .qualification()
                .protected_environment()
        || !domain_context
            .package
            .qualification()
            .targets()
            .contains(&target)
    {
        return Err("cleanup run context differs from the protected workflow".into());
    }
    require_provider_run(
        &repository,
        &domain_context,
        target,
        &run_context.provider_run_id,
    )?;
    let protected_output_root = PathBuf::from(required_env("QUALIFICATION_PROTECTED_OUTPUT_ROOT")?);
    let output_relative = PathBuf::from(domain)
        .join(target.as_str())
        .join(&run_context.provider_run_id);
    require_exact_output_path(
        &protected_output_root,
        Path::new(&arguments[7]),
        &output_relative,
    )?;
    let output = create_private_output_directory(&protected_output_root, &output_relative)?;
    if env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || validate_secret_zone(
            &["CLEANUP_CREDENTIAL"],
            &[
                "OBSERVER_CREDENTIAL",
                "OBSERVER_SEED",
                "SETUP_CREDENTIAL",
                "MUTATION_CREDENTIAL",
                "RUNTIME_READ_CREDENTIAL",
                "DECISION_RECEIPT_SEED",
                "EXECUTION_RECEIPT_SEED",
                "RECOVERY_SEED",
                "ATTESTATION_SEED",
            ],
        )
        .is_err()
    {
        return Err("cleanup inputs do not match the isolated protected trust zone".into());
    }
    crate::profile_qualification_adapters::run_protected_cleanup(CleanupAdapterContext {
        repository: &repository,
        domain,
        run_context: &run_context,
        output: &output,
        package: &domain_context.package,
    })
}

fn required_role_envs(roles: &[&str]) -> Result<(), String> {
    for role in roles {
        required_env(&format!("QUALIFICATION_{role}"))?;
    }
    Ok(())
}

fn require_exact_output_path(root: &Path, requested: &Path, relative: &Path) -> Result<(), String> {
    let expected = root.join(relative);
    let requested = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        root.join(requested)
    };
    if requested != expected
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err("qualification output is outside its fixed protected root".into());
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_output_directory(root: &Path, relative: &Path) -> Result<PathBuf, String> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::MetadataExt as _;

    let root_fd = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(string_error)?;
    let mut directory: fs::File = root_fd.into();
    let root_metadata = directory.metadata().map_err(string_error)?;
    if !root_metadata.is_dir()
        || root_metadata.uid() != rustix::process::geteuid().as_raw()
        || root_metadata.mode() & 0o022 != 0
    {
        return Err("qualification output root is not an owner-controlled directory".into());
    }
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err("qualification output contains an unsafe component".into());
        };
        match rustix::fs::mkdirat(
            &directory,
            Path::new(component),
            Mode::from_bits_truncate(0o700),
        ) {
            Ok(()) => directory.sync_all().map_err(string_error)?,
            Err(error) if error == rustix::io::Errno::EXIST => {}
            Err(error) => return Err(error.to_string()),
        }
        let fd = rustix::fs::openat(
            &directory,
            Path::new(component),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(string_error)?;
        let next: fs::File = fd.into();
        let metadata = next.metadata().map_err(string_error)?;
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o022 != 0
        {
            return Err("qualification output ancestor is not owner-controlled".into());
        }
        directory = next;
    }
    Ok(root.join(relative))
}

#[cfg(not(unix))]
fn create_private_output_directory(_root: &Path, _relative: &Path) -> Result<PathBuf, String> {
    Err("protected qualification output requires Unix no-follow directory handles".into())
}

#[cfg(unix)]
fn create_private_output_directory_fd(root: &Path, relative: &Path) -> Result<fs::File, String> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::MetadataExt as _;

    let components = relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(component) => Ok(component.to_owned()),
            _ => Err("qualification output contains an unsafe component".to_owned()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if components.is_empty() {
        return Err("qualification output directory is empty".into());
    }
    let root_fd = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(string_error)?;
    let mut directory: fs::File = root_fd.into();
    let root_metadata = directory.metadata().map_err(string_error)?;
    if !root_metadata.is_dir()
        || root_metadata.uid() != rustix::process::geteuid().as_raw()
        || root_metadata.mode() & 0o022 != 0
    {
        return Err("qualification output root is not an owner-controlled directory".into());
    }
    for (index, component) in components.iter().enumerate() {
        match rustix::fs::mkdirat(
            &directory,
            Path::new(component),
            Mode::from_bits_truncate(0o700),
        ) {
            Ok(()) => directory.sync_all().map_err(string_error)?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(error.to_string()),
        }
        let fd = rustix::fs::openat(
            &directory,
            Path::new(component),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(string_error)?;
        let next: fs::File = fd.into();
        let metadata = next.metadata().map_err(string_error)?;
        let final_component = index + 1 == components.len();
        if !metadata.is_dir()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || if final_component {
                metadata.mode() & 0o777 != 0o700
            } else {
                metadata.mode() & 0o022 != 0
            }
        {
            return Err("qualification output ancestor is not owner-controlled".into());
        }
        directory = next;
    }
    Ok(directory)
}

#[cfg(not(unix))]
fn create_private_output_directory_fd(_root: &Path, _relative: &Path) -> Result<fs::File, String> {
    Err("protected qualification output requires Unix no-follow directory handles".into())
}

#[cfg(unix)]
fn write_new_owner_only_at(directory: &fs::File, name: &Path, bytes: &[u8]) -> Result<(), String> {
    use rustix::fs::{Mode, OFlags};
    use std::io::Write as _;

    if name.components().count() != 1
        || !matches!(
            name.components().next(),
            Some(std::path::Component::Normal(_))
        )
    {
        return Err("qualification output member name is invalid".into());
    }
    let file = rustix::fs::openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(string_error)?;
    let mut file: fs::File = file.into();
    file.write_all(bytes).map_err(string_error)?;
    file.sync_all().map_err(string_error)?;
    directory.sync_all().map_err(string_error)
}

#[cfg(not(unix))]
fn write_new_owner_only_at(
    _directory: &fs::File,
    _name: &Path,
    _bytes: &[u8],
) -> Result<(), String> {
    Err("protected qualification output requires Unix no-follow directory handles".into())
}

fn validate_secret_zone(required: &[&str], forbidden: &[&str]) -> Result<(), String> {
    required_role_envs(required)?;
    let values = required
        .iter()
        .map(|role| required_env(&format!("QUALIFICATION_{role}")))
        .collect::<Result<Vec<_>, _>>()?;
    for (index, value) in values.iter().enumerate() {
        if values[..index].iter().any(|candidate| candidate == value) {
            return Err("qualification role secrets must be pairwise distinct".into());
        }
    }
    if forbidden
        .iter()
        .any(|role| env::var_os(format!("QUALIFICATION_{role}")).is_some())
        || env::var_os("AUTHS_QUALIFICATION_ATTESTATION_SEED").is_some()
    {
        return Err("qualification job received a secret from another trust zone".into());
    }
    Ok(())
}

pub(crate) struct RunAdapterContext<'a> {
    pub(crate) repository: &'a Path,
    pub(crate) domain: &'a str,
    pub(crate) target: QualificationTarget,
    pub(crate) environment: &'a str,
    pub(crate) provider_run_id: &'a str,
    pub(crate) scenario_ids: &'a [String],
    pub(crate) operation_plans: &'a BTreeMap<String, Vec<QualificationPlannedOperation>>,
    pub(crate) package: &'a ProfilePackage,
    pub(crate) setup_handoff: &'a Path,
    pub(crate) output: &'a Path,
}

pub(crate) struct ObserveAdapterContext<'a> {
    pub(crate) repository: &'a Path,
    pub(crate) attester_repository: &'a Path,
    pub(crate) domain: &'a str,
    pub(crate) target: QualificationTarget,
    pub(crate) environment: &'a str,
    pub(crate) provider_run_id: &'a str,
    pub(crate) scenario_ids: &'a [String],
    pub(crate) operation_plans: &'a BTreeMap<String, Vec<QualificationPlannedOperation>>,
    pub(crate) evidence: &'a Path,
    pub(crate) common_evidence: &'a Path,
    pub(crate) package: &'a ProfilePackage,
    pub(crate) output: &'a Path,
}

pub(crate) struct CleanupAdapterContext<'a> {
    pub(crate) repository: &'a Path,
    pub(crate) domain: &'a str,
    pub(crate) run_context: &'a auths_profile_kit::QualificationRunContext,
    pub(crate) output: &'a Path,
    pub(crate) package: &'a ProfilePackage,
}

trait ProtectedPhaseGuard {
    fn client(&self) -> &QualificationPhaseClient;

    fn complete(&mut self) -> Result<(), String>;
}

trait ProtectedPhaseRuntime {
    type Guard: ProtectedPhaseGuard;

    fn enter(
        &mut self,
        vector: &auths_profile_kit::QualificationVector,
        _phase_index: u8,
        planned: &QualificationPlannedOperation,
    ) -> Result<Self::Guard, String>;
}

struct ProcessProtectedPhaseRuntime {
    controller: PathBuf,
    agent: PathBuf,
    agent_config: PathBuf,
    agent_launcher: PathBuf,
    ledger_plan_path: PathBuf,
    launcher_ledger_plan_path: PathBuf,
    source_trust: PathBuf,
    receipt_trust: PathBuf,
    connection_store_template: PathBuf,
    runtime_root: PathBuf,
    cgroup_root: PathBuf,
    principal: String,
    plan: QualificationEvidenceLedgerPlanV1,
    agent_config_sha256: String,
    agent_launcher_sha256: String,
    installed_python: PathBuf,
    installed_profile_source: PathBuf,
    installed_working_directory: PathBuf,
    installed_python_module: String,
    installed_client_class: String,
    installed_methods: BTreeMap<String, InstalledProfileMethod>,
}

#[derive(Clone, Debug)]
struct InstalledProfileMethod {
    group: String,
    method: String,
    input_type: String,
}

struct ProcessProtectedPhaseGuard {
    client: QualificationPhaseClient,
    child: std::process::Child,
    input: Option<std::process::ChildStdin>,
    output: Option<std::process::ChildStdout>,
    deadline: Instant,
    cgroup_parent: fs::File,
    cgroup_name: std::ffi::OsString,
    cgroup_directory: Option<fs::File>,
    cgroup_owner_uid: u32,
    controller_exited_normally: bool,
    completed: bool,
}

impl ProcessProtectedPhaseRuntime {
    fn from_context(context: &RunAdapterContext<'_>) -> Result<Self, String> {
        let controller = required_absolute_path_env("AUTHS_QUALIFICATION_PHASE_CONTROLLER")?;
        let agent = required_absolute_path_env("AUTHS_QUALIFICATION_AGENT")?;
        let agent_config = required_absolute_path_env("AUTHS_QUALIFICATION_AGENT_CONFIG")?;
        let agent_launcher = required_absolute_path_env("AUTHS_QUALIFICATION_AGENT_LAUNCHER")?;
        let ledger_plan_path = required_absolute_path_env("AUTHS_QUALIFICATION_LEDGER_PLAN")?;
        let launcher_ledger_plan_path =
            required_absolute_path_env("AUTHS_QUALIFICATION_LAUNCHER_LEDGER_PLAN")?;
        let source_trust = required_absolute_path_env("AUTHS_QUALIFICATION_SOURCE_TRUST")?;
        let receipt_trust = required_absolute_path_env("AUTHS_QUALIFICATION_RECEIPT_TRUST")?;
        let connection_store_template =
            required_absolute_path_env("AUTHS_QUALIFICATION_CONNECTION_STORE_TEMPLATE")?;
        let runtime_root = required_absolute_path_env("AUTHS_QUALIFICATION_PHASE_RUNTIME_ROOT")?;
        let cgroup_root = required_absolute_path_env("AUTHS_QUALIFICATION_CGROUP_ROOT")?;
        let principal = required_env("AUTHS_QUALIFICATION_PRINCIPAL")?;
        if !registered_token(&principal) {
            return Err("protected qualification principal is malformed".into());
        }

        let plan_bytes = read_bounded(&ledger_plan_path, 262_144)?;
        let plan =
            QualificationEvidenceLedgerPlanV1::from_json(&plan_bytes).map_err(string_error)?;
        if plan.domain != context.domain
            || plan.target != context.target
            || plan.protected_environment != context.environment
            || plan.provider_run_id != context.provider_run_id
            || plan.phases.len()
                != context
                    .operation_plans
                    .values()
                    .map(Vec::len)
                    .sum::<usize>()
        {
            return Err("protected phase plan differs from collection context".into());
        }
        let now = now_unix_seconds()?;
        if now < plan.started_at_unix_seconds || now >= plan.deadline_at_unix_seconds {
            return Err("protected phase plan is outside its immutable run interval".into());
        }
        let domain_context =
            load_domain_from_git(context.repository, context.domain, &plan.candidate_revision)?;
        for scenario in context.scenario_ids {
            let operations = context
                .operation_plans
                .get(scenario)
                .ok_or_else(|| "reviewed scenario operation plan is absent".to_owned())?;
            for (index, operation) in operations.iter().enumerate() {
                let phase_index = u8::try_from(index + 1).map_err(string_error)?;
                let phase = plan
                    .phases
                    .iter()
                    .find(|phase| {
                        phase.scenario_id == *scenario && phase.phase_index == phase_index
                    })
                    .ok_or_else(|| "protected phase is absent from the ledger plan".to_owned())?;
                let operation_plan_sha256 = hex::encode(Sha256::digest(
                    serde_json_canonicalizer::to_vec(operations).map_err(string_error)?,
                ));
                let scenario_program_sha256 = scenario_program_sha256_at(
                    context.repository,
                    &domain_context,
                    &plan.candidate_revision,
                    scenario,
                )?;
                if phase.role != operation.role
                    || phase.profile != operation.profile
                    || phase.operation_plan_sha256 != operation_plan_sha256
                    || phase.scenario_program_sha256 != scenario_program_sha256
                {
                    return Err("protected phase differs from its reviewed operation plan".into());
                }
            }
        }
        if plan.phases.iter().any(|phase| {
            context
                .operation_plans
                .get(&phase.scenario_id)
                .is_none_or(|operations| {
                    usize::from(phase.phase_index)
                        .checked_sub(1)
                        .is_none_or(|index| index >= operations.len())
                })
        }) {
            return Err("ledger plan contains an unreviewed collection phase".into());
        }

        let controller_sha256 = bounded_file_sha256(&controller, 536_870_912)?;
        let agent_sha256 = bounded_file_sha256(&agent, 536_870_912)?;
        if controller_sha256 != plan.supervisor_controller_artifact_sha256
            || agent_sha256 != plan.agent_executable_sha256
        {
            return Err(
                "protected controller or candidate agent differs from the ledger plan".into(),
            );
        }
        let agent_config_bytes = read_bounded(&agent_config, 4_194_304)?;
        let agent_config_text = std::str::from_utf8(&agent_config_bytes).map_err(string_error)?;
        let parsed_agent_config = AgentConfig::from_toml(agent_config_text, AgentPlatform::Linux)
            .map_err(string_error)?;
        let agent_config_sha256 = hex::encode(Sha256::digest(&agent_config_bytes));
        let agent_launcher_sha256 = bounded_file_sha256(&agent_launcher, 536_870_912)?;
        let source_trust_bytes = read_bounded(&source_trust, 262_144)?;
        let source_registry =
            QualificationEvidenceSourceTrustRegistry::from_json(&source_trust_bytes)
                .map_err(string_error)?;
        let receipt_trust_bytes = read_bounded(&receipt_trust, 262_144)?;
        decode_receipt_trust_anchors(&receipt_trust_bytes).map_err(string_error)?;
        if receipt_anchors_from_agent_config(&parsed_agent_config)? != receipt_trust_bytes {
            return Err(
                "protected receipt anchors differ from the public agent configuration".into(),
            );
        }
        validate_protected_phase_topology(
            &runtime_root,
            &cgroup_root,
            context.scenario_ids,
            context.operation_plans,
            &plan,
            &source_registry,
            &plan_bytes,
            &source_trust_bytes,
            &receipt_trust_bytes,
            now,
        )?;

        let release_binding_path =
            required_absolute_path_env("AUTHS_QUALIFICATION_RELEASE_BUILD_BINDING")?;
        let release_artifacts =
            required_absolute_path_env("AUTHS_QUALIFICATION_RELEASE_ARTIFACTS")?;
        let python = required_absolute_path_env("AUTHS_QUALIFICATION_PYTHON")?;
        let binding_bytes = read_bounded(&release_binding_path, 262_144)?;
        let binding: VerifiedQualificationReleaseBuildBinding =
            crate::profile_qualification_reports::parse_canonical(&binding_bytes)?;
        if binding.workflow_revision != git_revision(context.repository)?
            || binding.repository_id != required_env("GITHUB_REPOSITORY_ID")?
        {
            return Err("installed-client release binding differs from collection context".into());
        }
        let wheel = verified_release_member(&binding, &release_artifacts, "python-wheel")?;
        let profile_role = format!("python-profile-{}", context.domain);
        let profile_archive = verified_release_member(&binding, &release_artifacts, &profile_role)?;
        let installed_working_directory = runtime_root.join("installed-client");
        fs::create_dir(&installed_working_directory).map_err(string_error)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(
                &installed_working_directory,
                fs::Permissions::from_mode(0o700),
            )
            .map_err(string_error)?;
        }
        let (installed_python, installed_profile_source) = install_python_client(
            &python,
            &wheel,
            &profile_archive,
            context.domain,
            &installed_working_directory,
        )?;
        let mut installed_methods = BTreeMap::new();
        for profile in context.package.profiles() {
            let semantic = format!("{}/{}", profile.id(), profile.version());
            let prior = installed_methods.insert(
                semantic,
                InstalledProfileMethod {
                    group: profile.client().group().into(),
                    method: profile.client().method().into(),
                    input_type: profile.client().input_type().into(),
                },
            );
            if prior.is_some() {
                return Err("installed-client profile method roster is duplicated".into());
            }
        }

        Ok(Self {
            controller,
            agent,
            agent_config,
            agent_launcher,
            ledger_plan_path,
            launcher_ledger_plan_path,
            source_trust,
            receipt_trust,
            connection_store_template,
            runtime_root,
            cgroup_root,
            principal,
            plan,
            agent_config_sha256,
            agent_launcher_sha256,
            installed_python,
            installed_profile_source,
            installed_working_directory,
            installed_python_module: context.package.domain().python_module().into(),
            installed_client_class: context.package.domain().client_class().into(),
            installed_methods,
        })
    }

    fn phase_root(&self, scenario: &str, phase_index: u8) -> PathBuf {
        self.runtime_root
            .join(scenario)
            .join(format!("phase-{phase_index}"))
    }

    fn cgroup_path(&self, scenario: &str, phase_index: u8) -> PathBuf {
        self.cgroup_root.join(format!("{scenario}-{phase_index}"))
    }
}

fn receipt_anchors_from_agent_config(config: &AgentConfig) -> Result<Vec<u8>, String> {
    let mut anchors = Vec::with_capacity(config.receipt_signing().prior().len() + 2);
    for value in config.receipt_signing().prior() {
        let mut public_key = [0_u8; 32];
        base64ct::Base64UrlUnpadded::decode(value.public_key_base64url(), &mut public_key)
            .map_err(string_error)?;
        anchors.push(
            ReceiptTrustAnchor::new(
                match value.role() {
                    ReceiptSigningRole::Decision => ReceiptTrustAnchorRole::Decision,
                    ReceiptSigningRole::Execution => ReceiptTrustAnchorRole::Execution,
                },
                value.key_id(),
                value.verification_method(),
                public_key,
                value.not_before_unix_seconds(),
                value.not_after_unix_seconds(),
            )
            .map_err(string_error)?,
        );
    }
    for (role, value) in [
        (
            ReceiptTrustAnchorRole::Decision,
            config.receipt_signing().decision(),
        ),
        (
            ReceiptTrustAnchorRole::Execution,
            config.receipt_signing().execution(),
        ),
    ] {
        let mut public_key = [0_u8; 32];
        base64ct::Base64UrlUnpadded::decode(value.public_key_base64url(), &mut public_key)
            .map_err(string_error)?;
        anchors.push(
            ReceiptTrustAnchor::new(
                role,
                value.key_id(),
                value.verification_method(),
                public_key,
                value.not_before_unix_seconds(),
                value.not_after_unix_seconds(),
            )
            .map_err(string_error)?,
        );
    }
    anchors.sort_by(|left, right| {
        (left.role(), left.key_id().as_bytes()).cmp(&(right.role(), right.key_id().as_bytes()))
    });
    let anchors = ReceiptTrustAnchors::new(anchors).map_err(string_error)?;
    encode_receipt_trust_anchors(&anchors).map_err(string_error)
}

impl ProtectedPhaseRuntime for ProcessProtectedPhaseRuntime {
    type Guard = ProcessProtectedPhaseGuard;

    fn enter(
        &mut self,
        vector: &auths_profile_kit::QualificationVector,
        phase_index: u8,
        planned: &QualificationPlannedOperation,
    ) -> Result<Self::Guard, String> {
        let phase = self
            .plan
            .phases
            .iter()
            .find(|phase| phase.scenario_id == vector.id && phase.phase_index == phase_index)
            .ok_or_else(|| "protected controller phase is absent".to_owned())?;
        if vector.failpoint != phase.failpoint
            || vector.scenario_program.sha256().map_err(string_error)?
                != phase.scenario_program_sha256
            || phase.role != planned.role
            || phase.profile != planned.profile
        {
            return Err("protected controller phase differs from the adapter invocation".into());
        }

        let phase_root = self.phase_root(&vector.id, phase_index);
        let state_directory = self.runtime_root.join(&vector.id).join("state");
        let state_metadata = fs::symlink_metadata(&state_directory).map_err(string_error)?;
        #[cfg(unix)]
        let (state_uid, state_mode, state_device, state_inode) = {
            use std::os::unix::fs::MetadataExt as _;
            (
                state_metadata.uid(),
                state_metadata.mode() & 0o777,
                state_metadata.dev(),
                state_metadata.ino(),
            )
        };
        #[cfg(not(unix))]
        return Err("protected phase orchestration requires Linux process isolation".into());
        #[cfg(unix)]
        if !state_metadata.is_dir() || state_uid != self.plan.agent_uid || state_mode != 0o700 {
            return Err("protected agent state directory ownership or mode is invalid".into());
        }
        let state_path = absolute_path_string(&state_directory)?;
        let state_sha256 = qualification_state_directory_commitment(
            &state_path,
            state_device,
            state_inode,
            state_uid,
            state_mode,
        )
        .map_err(string_error)?;
        let journal_path = absolute_path_string(&state_directory.join("operations.cbor"))?;
        let journal_sha256 = hex::encode(Sha256::digest(journal_path.as_bytes()));
        let deadline = Instant::now()
            + Duration::from_secs(
                self.plan
                    .deadline_at_unix_seconds
                    .checked_sub(now_unix_seconds()?)
                    .filter(|seconds| *seconds != 0)
                    .ok_or_else(|| "protected phase deadline has elapsed".to_owned())?,
            );

        let admin_socket = phase_root.join("agent/admin.sock");
        let agent_socket = phase_root.join("agent/agent.sock");
        let client_proxy_socket = phase_root.join("client-proxy/client.sock");
        let client_result_socket = phase_root.join("client-proxy/result.sock");
        let client_proxy_control_socket = phase_root.join("client-proxy/control.sock");
        let credential_broker_socket = phase_root.join("credential-broker/agent.sock");
        let credential_broker_checkpoint_socket =
            phase_root.join("credential-broker/checkpoint.sock");
        let credential_broker_control_socket = phase_root.join("credential-broker/control.sock");
        let supervisor_source_socket = self.runtime_root.join("supervisor/source.sock");
        let journal_reader_socket = phase_root.join("journal-reader/boundary.sock");
        let profile_state_reader_socket = phase_root.join("profile-state-reader/controller.sock");
        let provider_proxy_socket = phase_root.join("provider-proxy/agent.sock");
        let provider_proxy_checkpoint_socket = phase_root.join("provider-proxy/checkpoint.sock");
        let provider_proxy_control_socket = phase_root.join("provider-proxy/control.sock");
        let provider_observer_socket = phase_root.join("provider-observer/controller.sock");
        let receipt_verifier_socket = phase_root.join("receipt-verifier/controller.sock");
        let sequencer_socket = self.runtime_root.join("sequencer.sock");
        let cgroup = self.cgroup_path(&vector.id, phase_index);
        let (cgroup_parent, cgroup_name) =
            open_new_phase_cgroup_parent(&cgroup, self.plan.supervisor_controller_uid)?;
        let agent_uid = self.plan.agent_uid.to_string();
        let agent_gid = self.plan.agent_gid.to_string();
        let phase_index_string = phase_index.to_string();
        let mut command = Command::new(&self.controller);
        command
            .args([
                "run-phase",
                "--admin-socket",
                absolute_path_string(&admin_socket)?.as_str(),
                "--agent",
                absolute_path_string(&self.agent)?.as_str(),
                "--agent-config",
                absolute_path_string(&self.agent_config)?.as_str(),
                "--agent-gid",
                &agent_gid,
                "--agent-launcher",
                absolute_path_string(&self.agent_launcher)?.as_str(),
                "--agent-socket",
                absolute_path_string(&agent_socket)?.as_str(),
                "--agent-state-directory",
                &state_path,
                "--agent-uid",
                &agent_uid,
                "--cgroup",
                absolute_path_string(&cgroup)?.as_str(),
                "--client-proxy-control-socket",
                absolute_path_string(&client_proxy_control_socket)?.as_str(),
                "--credential-broker-socket",
                absolute_path_string(&credential_broker_socket)?.as_str(),
                "--credential-broker-checkpoint-socket",
                absolute_path_string(&credential_broker_checkpoint_socket)?.as_str(),
                "--credential-broker-control-socket",
                absolute_path_string(&credential_broker_control_socket)?.as_str(),
                "--qualification-connection-store-template",
                absolute_path_string(&self.connection_store_template)?.as_str(),
                "--decision-supervisor-socket",
                absolute_path_string(&supervisor_source_socket)?.as_str(),
                "--journal-reader-socket",
                absolute_path_string(&journal_reader_socket)?.as_str(),
                "--launcher-ledger-plan",
                absolute_path_string(&self.launcher_ledger_plan_path)?.as_str(),
                "--ledger-plan",
                absolute_path_string(&self.ledger_plan_path)?.as_str(),
                "--phase-index",
                &phase_index_string,
                "--principal",
                &self.principal,
                "--profile-state-reader-socket",
                absolute_path_string(&profile_state_reader_socket)?.as_str(),
                "--provider-observer-socket",
                absolute_path_string(&provider_observer_socket)?.as_str(),
                "--provider-proxy-socket",
                absolute_path_string(&provider_proxy_socket)?.as_str(),
                "--provider-proxy-checkpoint-socket",
                absolute_path_string(&provider_proxy_checkpoint_socket)?.as_str(),
                "--provider-proxy-control-socket",
                absolute_path_string(&provider_proxy_control_socket)?.as_str(),
                "--receipt-trust",
                absolute_path_string(&self.receipt_trust)?.as_str(),
                "--receipt-verifier-socket",
                absolute_path_string(&receipt_verifier_socket)?.as_str(),
                "--scenario",
                &vector.id,
                "--sequencer-socket",
                absolute_path_string(&sequencer_socket)?.as_str(),
                "--signer-socket",
                absolute_path_string(&supervisor_source_socket)?.as_str(),
                "--source-trust",
                absolute_path_string(&self.source_trust)?.as_str(),
            ])
            .env_clear()
            .env(
                "AUTHS_QUALIFICATION_AGENT_CONFIG_SHA256",
                &self.agent_config_sha256,
            )
            .env("AUTHS_QUALIFICATION_AGENT_GID", &agent_gid)
            .env(
                "AUTHS_QUALIFICATION_AGENT_JOURNAL_PATH_SHA256",
                journal_sha256,
            )
            .env(
                "AUTHS_QUALIFICATION_AGENT_LAUNCHER_SHA256",
                &self.agent_launcher_sha256,
            )
            .env(
                "AUTHS_QUALIFICATION_AGENT_STATE_DIRECTORY_SHA256",
                state_sha256,
            )
            .env("AUTHS_QUALIFICATION_AGENT_UID", &agent_uid)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
        let mut child = command.spawn().map_err(string_error)?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| "protected phase controller has no completion pipe".to_owned())?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| "protected phase controller has no readiness pipe".to_owned())?;
        let mut guard = ProcessProtectedPhaseGuard {
            client: QualificationPhaseClient::new(
                absolute_path_string(&client_proxy_socket)?,
                absolute_path_string(&client_result_socket)?,
            )
            .map_err(string_error)?
            .with_reviewed_phase(vector.scenario_program.clone(), phase_index, planned.role)
            .map_err(string_error)?
            .with_installed_client(
                QualificationInstalledClient::new(
                    absolute_path_string(&self.installed_python)?,
                    absolute_path_string(&self.installed_profile_source)?,
                    absolute_path_string(&self.installed_working_directory)?,
                    self.installed_python_module.clone(),
                    self.installed_client_class.clone(),
                    self.installed_methods
                        .get(&planned.profile)
                        .ok_or_else(|| "installed-client profile method is absent".to_owned())?
                        .group
                        .clone(),
                    self.installed_methods
                        .get(&planned.profile)
                        .ok_or_else(|| "installed-client profile method is absent".to_owned())?
                        .method
                        .clone(),
                    self.installed_methods
                        .get(&planned.profile)
                        .ok_or_else(|| "installed-client profile method is absent".to_owned())?
                        .input_type
                        .clone(),
                    self.plan.deadline_at_unix_seconds,
                )
                .map_err(string_error)?,
            )
            .map_err(string_error)?,
            child,
            input: Some(input),
            output: Some(output),
            deadline,
            cgroup_parent,
            cgroup_name,
            cgroup_directory: None,
            cgroup_owner_uid: self.plan.supervisor_controller_uid,
            controller_exited_normally: false,
            completed: false,
        };
        guard.wait_ready(&vector.id, phase_index)?;
        guard.require_cgroup_directory()?;
        Ok(guard)
    }
}

impl ProcessProtectedPhaseGuard {
    #[cfg(unix)]
    fn try_capture_cgroup_directory(&mut self) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt as _;

        if self.cgroup_directory.is_some() {
            return Ok(());
        }
        let descriptor = match rustix::fs::openat(
            &self.cgroup_parent,
            Path::new(&self.cgroup_name),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::NOENT => return Ok(()),
            Err(error) => return Err(string_error(error)),
        };
        let directory = fs::File::from(descriptor);
        let metadata = directory.metadata().map_err(string_error)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != self.cgroup_owner_uid
            || metadata.mode() & 0o022 != 0
        {
            return Err("protected qualification phase cgroup is not controller-owned".into());
        }
        self.cgroup_directory = Some(directory);
        Ok(())
    }

    #[cfg(not(unix))]
    fn try_capture_cgroup_directory(&mut self) -> Result<(), String> {
        Err("protected phase orchestration requires Unix process isolation".into())
    }

    fn require_cgroup_directory(&mut self) -> Result<(), String> {
        self.try_capture_cgroup_directory()?;
        if self.cgroup_directory.is_none() {
            return Err("protected phase controller did not create its delegated cgroup".into());
        }
        Ok(())
    }

    #[cfg(unix)]
    fn force_kill_phase_cgroup(&mut self) -> bool {
        use std::io::Write as _;

        let Some(directory) = self.cgroup_directory.as_ref() else {
            return false;
        };
        let Ok(kill_descriptor) = rustix::fs::openat(
            directory,
            "cgroup.kill",
            rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        ) else {
            return false;
        };
        let mut kill = fs::File::from(kill_descriptor);
        if kill.write_all(b"1").is_err() {
            return false;
        }
        drop(kill);
        self.wait_for_empty_cgroup()
    }

    #[cfg(unix)]
    fn wait_for_empty_cgroup(&self) -> bool {
        use std::io::Read as _;

        let Some(directory) = self.cgroup_directory.as_ref() else {
            return false;
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let Ok(events_descriptor) = rustix::fs::openat(
                directory,
                "cgroup.events",
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            ) else {
                break;
            };
            let mut events = String::new();
            if fs::File::from(events_descriptor)
                .read_to_string(&mut events)
                .is_err()
            {
                break;
            }
            if events
                .lines()
                .any(|line| line.split_ascii_whitespace().eq(["populated", "0"]))
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[cfg(not(unix))]
    fn wait_for_empty_cgroup(&self) -> bool {
        false
    }

    #[cfg(not(unix))]
    fn force_kill_phase_cgroup(&mut self) -> bool {
        false
    }

    #[cfg(unix)]
    fn force_kill_controller_group(&self) -> bool {
        let Ok(raw_pid) = i32::try_from(self.child.id()) else {
            return false;
        };
        let Some(process_group) = rustix::process::Pid::from_raw(raw_pid) else {
            return false;
        };
        rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL).is_ok()
    }

    #[cfg(not(unix))]
    fn force_kill_controller_group(&self) -> bool {
        false
    }

    #[cfg(unix)]
    fn observe_controller_exit_without_reaping(&self) -> Result<Option<bool>, String> {
        let raw_pid = i32::try_from(self.child.id()).map_err(string_error)?;
        let pid = rustix::process::Pid::from_raw(raw_pid)
            .ok_or_else(|| "protected phase controller PID is invalid".to_owned())?;
        rustix::process::waitid(
            rustix::process::WaitId::Pid(pid),
            rustix::process::WaitIdOptions::EXITED
                | rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT,
        )
        .map(|status| status.map(|status| status.exited()))
        .map_err(string_error)
    }

    #[cfg(not(unix))]
    fn observe_controller_exit_without_reaping(&mut self) -> Result<Option<bool>, String> {
        self.child
            .try_wait()
            .map(|status| status.map(|_| true))
            .map_err(string_error)
    }

    #[cfg(unix)]
    fn remove_empty_phase_cgroup(&mut self) {
        use std::os::unix::fs::MetadataExt as _;

        let Some(directory) = self.cgroup_directory.take() else {
            return;
        };
        let Ok(captured) = directory.metadata() else {
            return;
        };
        drop(directory);
        let Ok(named) = rustix::fs::statat(
            &self.cgroup_parent,
            Path::new(&self.cgroup_name),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) else {
            return;
        };
        if named.st_dev as u64 != captured.dev() || named.st_ino as u64 != captured.ino() {
            return;
        }
        let _ = rustix::fs::unlinkat(
            &self.cgroup_parent,
            Path::new(&self.cgroup_name),
            rustix::fs::AtFlags::REMOVEDIR,
        );
    }

    #[cfg(not(unix))]
    fn remove_empty_phase_cgroup(&mut self) {}

    fn wait_ready(&mut self, scenario: &str, phase_index: u8) -> Result<(), String> {
        use std::io::Read as _;
        #[cfg(unix)]
        {
            let output = self
                .output
                .as_mut()
                .ok_or_else(|| "protected phase readiness pipe is absent".to_owned())?;
            rustix::fs::fcntl_setfl(&mut *output, rustix::fs::OFlags::NONBLOCK)
                .map_err(string_error)?;
        }
        let expected = format!("AUTHS-QUALIFICATION-PHASE-READY/1 {scenario} {phase_index}\n");
        let mut bytes = Vec::with_capacity(expected.len());
        let mut byte = [0_u8; 1];
        while bytes.last() != Some(&b'\n') {
            self.try_capture_cgroup_directory()?;
            if Instant::now() >= self.deadline {
                return Err(
                    "protected phase controller readiness exceeded the ledger deadline".into(),
                );
            }
            if let Some(normal_exit) = self.observe_controller_exit_without_reaping()? {
                if !normal_exit {
                    return Err("protected phase controller was terminated before readiness".into());
                }
                self.controller_exited_normally = true;
                let status = self.child.wait().map_err(string_error)?;
                return Err(format!(
                    "protected phase controller exited before readiness: {status}"
                ));
            }
            let read = self
                .output
                .as_mut()
                .ok_or_else(|| "protected phase readiness pipe is absent".to_owned())?
                .read(&mut byte);
            match read {
                Ok(0) => return Err("protected phase controller closed before readiness".into()),
                Ok(_) => {
                    bytes.push(byte[0]);
                    if bytes.len() > 256 {
                        return Err("protected phase readiness line exceeds its bound".into());
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(string_error(error)),
            }
        }
        if bytes != expected.as_bytes() {
            return Err("protected phase controller returned a mismatched readiness line".into());
        }
        self.require_cgroup_directory()?;
        Ok(())
    }

    fn close_and_wait(&mut self, complete: bool) -> Result<(), String> {
        use std::io::{Read as _, Write as _};
        if let Some(mut input) = self.input.take() {
            if complete {
                input.write_all(&[1]).map_err(string_error)?;
                input.flush().map_err(string_error)?;
            }
            drop(input);
        }
        loop {
            if let Some(normal_exit) = self.observe_controller_exit_without_reaping()? {
                if !normal_exit {
                    return Err(
                        "protected phase controller was terminated before completion".into(),
                    );
                }
                self.controller_exited_normally = true;
                let status = self.child.wait().map_err(string_error)?;
                let mut trailing = Vec::new();
                if let Some(mut output) = self.output.take() {
                    output.read_to_end(&mut trailing).map_err(string_error)?;
                }
                if !status.success() || !trailing.is_empty() {
                    return Err(format!(
                        "protected phase controller failed or returned trailing output: {status}"
                    ));
                }
                self.completed = complete;
                return Ok(());
            }
            if Instant::now() >= self.deadline {
                return Err("protected phase controller exceeded the ledger deadline".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl ProtectedPhaseGuard for ProcessProtectedPhaseGuard {
    fn client(&self) -> &QualificationPhaseClient {
        &self.client
    }

    fn complete(&mut self) -> Result<(), String> {
        self.close_and_wait(true)
    }
}

impl Drop for ProcessProtectedPhaseGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if self.controller_exited_normally {
            if self.wait_for_empty_cgroup() || self.force_kill_phase_cgroup() {
                self.remove_empty_phase_cgroup();
            }
            return;
        }
        drop(self.input.take());
        let cleanup_deadline = Instant::now() + Duration::from_secs(5);
        let mut controller_exit = None;
        while Instant::now() < cleanup_deadline {
            match self.observe_controller_exit_without_reaping() {
                Ok(Some(normal_exit)) => {
                    controller_exit = Some(normal_exit);
                    break;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => break,
            }
        }
        if controller_exit == Some(true) {
            let _ = self.child.wait();
            if self.wait_for_empty_cgroup() {
                self.remove_empty_phase_cgroup();
            }
            return;
        }
        let mut cgroup_empty = self.force_kill_phase_cgroup();
        let killed_group = self.force_kill_controller_group();
        if controller_exit.is_none() {
            if !killed_group {
                let _ = self.child.kill();
            }
        }
        let _ = self.child.wait();
        if !cgroup_empty {
            cgroup_empty = self.wait_for_empty_cgroup();
        }
        if cgroup_empty {
            self.remove_empty_phase_cgroup();
        }
    }
}

#[cfg(unix)]
fn open_directory_componentwise_no_symlinks(path: &Path) -> Result<fs::File, String> {
    let mut directory = fs::File::from(
        rustix::fs::open(
            if path.is_absolute() {
                Path::new("/")
            } else {
                Path::new(".")
            },
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(string_error)?,
    );
    for component in path.components() {
        let name = match component {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::Normal(name) => name,
            _ => return Err("protected qualification directory has an unsafe component".into()),
        };
        directory = fs::File::from(
            rustix::fs::openat(
                &directory,
                Path::new(name),
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            )
            .map_err(string_error)?,
        );
    }
    Ok(directory)
}

#[cfg(unix)]
fn protected_directory_identity(
    path: &Path,
    expected_uid: u32,
    expected_gid: Option<u32>,
    expected_mode: u32,
) -> Result<(u64, u64), String> {
    use std::os::unix::fs::MetadataExt as _;

    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(
            "protected qualification directory is not one normalized no-symlink path".into(),
        );
    }
    let directory = open_directory_componentwise_no_symlinks(path)?;
    let metadata = directory.metadata().map_err(string_error)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
        || expected_gid.is_some_and(|gid| metadata.gid() != gid)
        || metadata.mode() & 0o777 != expected_mode
    {
        return Err("protected qualification directory ownership or mode is invalid".into());
    }
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn protected_directory_identity(
    _path: &Path,
    _expected_uid: u32,
    _expected_gid: Option<u32>,
    _expected_mode: u32,
) -> Result<(u64, u64), String> {
    Err("protected phase orchestration requires Unix process isolation".into())
}

#[cfg(unix)]
fn protected_regular_file_identity(
    path: &Path,
    expected_uid: u32,
    expected_mode: u32,
    maximum: u64,
) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt as _;

    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err("protected qualification policy file path is unsafe".into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "protected qualification policy file has no parent".to_owned())?;
    let name = path
        .file_name()
        .ok_or_else(|| "protected qualification policy file has no name".to_owned())?;
    let directory = open_directory_componentwise_no_symlinks(parent)?;
    let descriptor = rustix::fs::openat(
        &directory,
        Path::new(name),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(string_error)?;
    let mut file: fs::File = descriptor.into();
    let before = file.metadata().map_err(string_error)?;
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != expected_uid
        || before.mode() & 0o777 != expected_mode
        || before.len() == 0
        || before.len() > maximum
    {
        return Err("protected qualification policy file identity is invalid".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(string_error)?;
    let after = file.metadata().map_err(string_error)?;
    if u64::try_from(bytes.len()).map_err(string_error)? != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.nlink() != after.nlink()
        || before.uid() != after.uid()
        || before.mode() != after.mode()
    {
        return Err("protected qualification policy file changed while reading".into());
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn protected_regular_file_identity(
    _path: &Path,
    _expected_uid: u32,
    _expected_mode: u32,
    _maximum: u64,
) -> Result<Vec<u8>, String> {
    Err("protected phase orchestration requires Unix process isolation".into())
}

fn current_source_uid(
    trust: &QualificationEvidenceSourceTrustRegistry,
    source: QualificationEvidenceSource,
    plan: &QualificationEvidenceLedgerPlanV1,
    now: u64,
) -> Result<u32, String> {
    trust
        .current_source_process_binding(
            source,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map(|(_, _, _, uid)| uid)
        .map_err(string_error)
}

fn current_reader_uid(
    trust: &QualificationEvidenceSourceTrustRegistry,
    source: QualificationEvidenceSource,
    plan: &QualificationEvidenceLedgerPlanV1,
    now: u64,
) -> Result<u32, String> {
    let (_, _, signer_artifact, _) = trust
        .current_source_process_binding(
            source,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map_err(string_error)?;
    trust
        .fixed_source_process_binding(
            source,
            signer_artifact,
            &plan.domain,
            plan.started_at_unix_seconds,
            plan.deadline_at_unix_seconds,
            now,
        )
        .map(|(_, _, _, _, _, reader_uid)| reader_uid)
        .map_err(string_error)
}

#[allow(clippy::too_many_arguments)]
fn validate_protected_phase_topology(
    runtime_root: &Path,
    cgroup_root: &Path,
    scenario_ids: &[String],
    operation_plans: &BTreeMap<String, Vec<QualificationPlannedOperation>>,
    plan: &QualificationEvidenceLedgerPlanV1,
    trust: &QualificationEvidenceSourceTrustRegistry,
    plan_bytes: &[u8],
    source_trust_bytes: &[u8],
    receipt_trust_bytes: &[u8],
    now: u64,
) -> Result<(), String> {
    protected_directory_identity(
        runtime_root,
        plan.supervisor_controller_uid,
        Some(plan.agent_gid),
        0o710,
    )?;
    for (name, expected) in [
        ("ledger-plan.json", plan_bytes),
        ("source-trust.json", source_trust_bytes),
        ("receipt-trust.json", receipt_trust_bytes),
    ] {
        if protected_regular_file_identity(
            &runtime_root.join(name),
            plan.supervisor_controller_uid,
            0o600,
            262_144,
        )? != expected
        {
            return Err("protected qualification row policy snapshot differs from input".into());
        }
    }
    if !cgroup_root.starts_with("/sys/fs/cgroup") || cgroup_root == Path::new("/sys/fs/cgroup") {
        return Err(
            "protected qualification cgroup root is not delegated beneath cgroup v2".into(),
        );
    }
    let supervisor_uid =
        current_source_uid(trust, QualificationEvidenceSource::Supervisor, plan, now)?;
    let journal_reader_uid =
        current_source_uid(trust, QualificationEvidenceSource::JournalReader, plan, now)?;
    let client_proxy_source_uid =
        current_source_uid(trust, QualificationEvidenceSource::ClientProxy, plan, now)?;
    let credential_broker_source_uid = current_source_uid(
        trust,
        QualificationEvidenceSource::CredentialBroker,
        plan,
        now,
    )?;
    let profile_state_source_uid = current_source_uid(
        trust,
        QualificationEvidenceSource::ProfileStateReader,
        plan,
        now,
    )?;
    let receipt_verifier_source_uid = current_source_uid(
        trust,
        QualificationEvidenceSource::ReceiptVerifier,
        plan,
        now,
    )?;
    let provider_proxy_source_uid =
        current_source_uid(trust, QualificationEvidenceSource::ProviderProxy, plan, now)?;
    let provider_observer_source_uid = current_source_uid(
        trust,
        QualificationEvidenceSource::ProviderObserver,
        plan,
        now,
    )?;
    let profile_state_reader_uid = current_reader_uid(
        trust,
        QualificationEvidenceSource::ProfileStateReader,
        plan,
        now,
    )?;
    let client_proxy_reader_uid =
        current_reader_uid(trust, QualificationEvidenceSource::ClientProxy, plan, now)?;
    let credential_broker_reader_uid = current_reader_uid(
        trust,
        QualificationEvidenceSource::CredentialBroker,
        plan,
        now,
    )?;
    let receipt_verifier_uid = current_reader_uid(
        trust,
        QualificationEvidenceSource::ReceiptVerifier,
        plan,
        now,
    )?;
    let provider_proxy_reader_uid =
        current_reader_uid(trust, QualificationEvidenceSource::ProviderProxy, plan, now)?;
    let provider_observer_reader_uid = current_reader_uid(
        trust,
        QualificationEvidenceSource::ProviderObserver,
        plan,
        now,
    )?;

    for (name, uid) in [
        ("supervisor", supervisor_uid),
        ("client-proxy-signer", client_proxy_source_uid),
        ("client-proxy-reader", client_proxy_reader_uid),
        ("journal-reader", journal_reader_uid),
        ("credential-broker-signer", credential_broker_source_uid),
        ("credential-broker-reader", credential_broker_reader_uid),
        ("credential-broker-store", credential_broker_reader_uid),
        ("profile-state-signer", profile_state_source_uid),
        ("profile-state-reader", profile_state_reader_uid),
        ("receipt-verifier-signer", receipt_verifier_source_uid),
        ("receipt-verifier-reader", receipt_verifier_uid),
        ("provider-proxy-signer", provider_proxy_source_uid),
        ("provider-proxy-reader", provider_proxy_reader_uid),
        ("provider-observer-signer", provider_observer_source_uid),
        ("provider-observer-reader", provider_observer_reader_uid),
    ] {
        protected_directory_identity(
            &runtime_root.join(name),
            uid,
            Some(plan.agent_gid),
            if name == "credential-broker-store" {
                0o700
            } else {
                0o710
            },
        )?;
        if protected_regular_file_identity(
            &runtime_root.join(name).join("ledger-plan.json"),
            uid,
            0o600,
            262_144,
        )? != plan_bytes
        {
            return Err("protected qualification role plan snapshot differs from input".into());
        }
        if protected_regular_file_identity(
            &runtime_root.join(name).join("source-trust.json"),
            uid,
            0o600,
            262_144,
        )? != source_trust_bytes
        {
            return Err("protected qualification role trust snapshot differs from input".into());
        }
        if matches!(name, "journal-reader" | "receipt-verifier-reader") {
            if protected_regular_file_identity(
                &runtime_root.join(name).join("receipt-trust.json"),
                uid,
                0o600,
                262_144,
            )? != receipt_trust_bytes
            {
                return Err(
                    "protected qualification role receipt snapshot differs from input".into(),
                );
            }
        }
    }

    for scenario in scenario_ids {
        let scenario_root = runtime_root.join(scenario);
        protected_directory_identity(&scenario_root, plan.supervisor_controller_uid, None, 0o711)?;
        let state_directory = scenario_root.join("state");
        protected_directory_identity(
            &state_directory,
            plan.agent_uid,
            Some(plan.agent_gid),
            0o700,
        )?;
        for name in [
            "qualification-decision.key",
            "qualification-execution.key",
            "qualification-recovery.key",
        ] {
            protected_secret_file_identity(
                &state_directory.join(name),
                plan.agent_uid,
                plan.agent_gid,
            )?;
        }
        let operations = operation_plans
            .get(scenario)
            .ok_or_else(|| "reviewed scenario operation plan is absent".to_owned())?;
        for phase_index in 1..=operations.len() {
            let phase_index = u8::try_from(phase_index).map_err(string_error)?;
            let phase_root = scenario_root.join(format!("phase-{phase_index}"));
            protected_directory_identity(&phase_root, plan.supervisor_controller_uid, None, 0o711)?;
            for (name, uid) in [
                ("agent", plan.agent_uid),
                ("journal-reader", journal_reader_uid),
                ("client-proxy", client_proxy_reader_uid),
                ("credential-broker", credential_broker_reader_uid),
                ("profile-state-reader", profile_state_reader_uid),
                ("receipt-verifier", receipt_verifier_uid),
                ("provider-proxy", provider_proxy_reader_uid),
                ("provider-observer", provider_observer_reader_uid),
            ] {
                protected_directory_identity(
                    &phase_root.join(name),
                    uid,
                    Some(plan.agent_gid),
                    0o710,
                )?;
            }
            let cgroup = cgroup_root.join(format!("{scenario}-{phase_index}"));
            let _ = open_new_phase_cgroup_parent(&cgroup, plan.supervisor_controller_uid)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn protected_secret_file_identity(path: &Path, uid: u32, gid: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let parent = path
        .parent()
        .ok_or_else(|| "protected signing handle has no parent".to_owned())?;
    let name = path
        .file_name()
        .ok_or_else(|| "protected signing handle has no name".to_owned())?;
    let parent = open_directory_componentwise_no_symlinks(parent)?;
    let descriptor = rustix::fs::openat(
        &parent,
        Path::new(name),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(string_error)?;
    let file = fs::File::from(descriptor);
    let metadata = file.metadata().map_err(string_error)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != 32
    {
        return Err("protected signing handle identity is invalid".into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn protected_secret_file_identity(_path: &Path, _uid: u32, _gid: u32) -> Result<(), String> {
    Err("protected signing handles require Unix process isolation".into())
}

#[cfg(unix)]
fn open_new_phase_cgroup_parent(
    path: &Path,
    expected_uid: u32,
) -> Result<(fs::File, std::ffi::OsString), String> {
    use std::os::unix::fs::MetadataExt as _;

    if !path.is_absolute()
        || !path.starts_with("/sys/fs/cgroup")
        || path == Path::new("/sys/fs/cgroup")
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err("protected qualification phase cgroup is not a new normalized target".into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "protected qualification phase cgroup has no parent".to_owned())?;
    let directory = open_directory_componentwise_no_symlinks(parent)?;
    let metadata = directory.metadata().map_err(string_error)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o022 != 0
    {
        return Err(
            "protected qualification cgroup parent is not controller-owned and non-writable".into(),
        );
    }
    let name = path
        .file_name()
        .ok_or_else(|| "protected qualification phase cgroup has no name".to_owned())?
        .to_owned();
    match rustix::fs::openat(
        &directory,
        Path::new(&name),
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    ) {
        Err(error) if error == rustix::io::Errno::NOENT => Ok((directory, name)),
        Err(error) => Err(string_error(error)),
        Ok(_) => Err("protected qualification phase cgroup already exists".into()),
    }
}

#[cfg(not(unix))]
fn open_new_phase_cgroup_parent(
    _path: &Path,
    _expected_uid: u32,
) -> Result<(fs::File, std::ffi::OsString), String> {
    Err("protected phase orchestration requires Unix process isolation".into())
}

fn required_absolute_path_env(name: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(required_env(name)?);
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(format!("{name} is not a normalized absolute path"));
    }
    Ok(path)
}

fn absolute_path_string(path: &Path) -> Result<String, String> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err("protected phase path is not normalized and absolute".into());
    }
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| "protected phase path is not UTF-8".to_owned())
}

fn bounded_file_sha256(path: &Path, maximum: u64) -> Result<String, String> {
    Ok(hex::encode(Sha256::digest(read_bounded(path, maximum)?)))
}

fn verified_release_member(
    binding: &VerifiedQualificationReleaseBuildBinding,
    root: &Path,
    role: &str,
) -> Result<PathBuf, String> {
    let artifact = binding
        .artifacts
        .iter()
        .find(|artifact| artifact.role == role)
        .ok_or_else(|| format!("verified release artifact is absent: {role}"))?;
    if artifact.member_path != installed_member_name(role) {
        return Err(format!("verified release artifact member drifted: {role}"));
    }
    let path = root.join(role).join(&artifact.member_path);
    let metadata = fs::symlink_metadata(&path).map_err(string_error)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != artifact.bytes
        || bounded_file_sha256(&path, 536_870_912)? != artifact.member_sha256
    {
        return Err(format!("verified release artifact bytes drifted: {role}"));
    }
    Ok(path)
}

pub(crate) fn run_domain_adapter<A: QualificationCollectionAdapter>(
    adapter: A,
    context: RunAdapterContext<'_>,
) -> Result<(), String> {
    validate_adapter_metadata(
        &adapter.metadata(),
        context.repository,
        context.domain,
        context.target,
        context.environment,
        context.package,
    )?;
    // Validate the complete protected controller/source topology before any
    // installed SDK call is allowed to reach the candidate agent.
    let mut phase_runtime = ProcessProtectedPhaseRuntime::from_context(&context)?;
    let run_context = auths_profile_kit::QualificationRunContext {
        repository_id: required_env("GITHUB_REPOSITORY_ID")?,
        candidate_revision: git_revision(context.repository)?,
        target: context.target,
        protected_environment: context.environment.into(),
        run_id: required_env("GITHUB_RUN_ID")?,
        run_attempt: required_env("GITHUB_RUN_ATTEMPT")?
            .parse::<u32>()
            .map_err(string_error)?,
        provider_run_id: context.provider_run_id.into(),
    };
    let handoff_bytes = read_bounded(context.setup_handoff, MAX_CANDIDATE_COLLECTION_BYTES)?;
    let handoff: QualificationSetupHandoffV1 =
        serde_json::from_slice(&handoff_bytes).map_err(string_error)?;
    if serde_json_canonicalizer::to_vec(&handoff).map_err(string_error)? != handoff_bytes
        || handoff.validate().is_err()
        || handoff.run_context != run_context
        || handoff.domain != context.domain
        || handoff.run_reference.provider_run_id != context.provider_run_id
        || handoff
            .vectors
            .iter()
            .map(|vector| &vector.id)
            .ne(context.scenario_ids.iter())
    {
        return Err("protected setup handoff differs from trusted workflow context".into());
    }
    let vectors = handoff.decoded_vectors().map_err(string_error)?;
    let connection_alias = handoff.connection_alias.clone();
    let run_reference = handoff.run_reference.clone();
    let mut environment = adapter.open(&run_context, &handoff).map_err(string_error)?;
    fs::create_dir_all(context.output).map_err(string_error)?;
    let reference_bytes = serde_json_canonicalizer::to_vec(&run_reference).map_err(string_error)?;
    atomic_write_new(&context.output.join("run-reference.json"), &reference_bytes)?;
    let scenarios = run_domain_vectors(
        &adapter,
        &mut environment,
        &connection_alias,
        context.provider_run_id,
        vectors,
        context.operation_plans,
        &mut phase_runtime,
    )?;
    let collection = CandidateCollection {
        schema: "auths.profile-qualification-candidate-collection/1".into(),
        run_reference,
        scenarios,
    };
    let collection = serde_json_canonicalizer::to_vec(&collection).map_err(string_error)?;
    atomic_write_new(&context.output.join("collection.json"), &collection)
}

fn run_domain_vectors<A, R>(
    adapter: &A,
    environment: &mut A::Environment,
    connection_alias: &str,
    provider_run_id: &str,
    vectors: Vec<auths_profile_kit::QualificationVector>,
    operation_plans: &BTreeMap<String, Vec<QualificationPlannedOperation>>,
    phase_runtime: &mut R,
) -> Result<Vec<QualificationCollectedScenario>, String>
where
    A: QualificationCollectionAdapter,
    R: ProtectedPhaseRuntime,
{
    let mut collected = Vec::with_capacity(vectors.len());
    for vector in vectors {
        vector.validate().map_err(string_error)?;
        let planned = operation_plans
            .get(&vector.id)
            .ok_or_else(|| "qualification scenario has no reviewed operation plan".to_owned())?;
        let mut operations = Vec::with_capacity(planned.len());
        for (index, expected_operation) in planned.iter().enumerate() {
            let phase_index = u8::try_from(index + 1).map_err(string_error)?;
            let mut phase = phase_runtime.enter(&vector, phase_index, expected_operation)?;
            let operation = adapter
                .invoke_phase(
                    environment,
                    phase.client(),
                    connection_alias,
                    &vector,
                    phase_index,
                    expected_operation.role,
                    &expected_operation.profile,
                )
                .map_err(string_error)?;
            operation.validate().map_err(string_error)?;
            if operation.role != expected_operation.role
                || operation.profile != expected_operation.profile
            {
                return Err(
                    "installed-client phase differs from the reviewed operation plan".into(),
                );
            }
            phase.complete()?;
            operations.push(operation);
        }
        collected.push(QualificationCollectedScenario {
            scenario_id: vector.id,
            provider_run_id: provider_run_id.into(),
            failpoint: vector.failpoint,
            operations,
        });
    }
    Ok(collected)
}

pub(crate) fn observe_domain_adapter<A: QualificationProtectedObserver>(
    adapter: A,
    context: ObserveAdapterContext<'_>,
) -> Result<(), String> {
    let domain_context = load_domain(context.repository, context.domain)?;
    let matrix = load_provider_matrix(context.repository, &domain_context, context.target)?;
    let matrix_run = matrix
        .runs
        .iter()
        .find(|run| run.id == context.provider_run_id)
        .ok_or_else(|| "protected observer provider row is absent".to_owned())?;
    let metadata_validation = validate_adapter_metadata(
        &adapter.metadata(),
        context.repository,
        context.domain,
        context.target,
        context.environment,
        context.package,
    );
    let run_context = auths_profile_kit::QualificationRunContext {
        repository_id: required_env("GITHUB_REPOSITORY_ID")?,
        candidate_revision: required_env("QUALIFICATION_CANDIDATE_REVISION")?,
        target: context.target,
        protected_environment: context.environment.into(),
        run_id: required_env("GITHUB_RUN_ID")?,
        run_attempt: required_env("GITHUB_RUN_ATTEMPT")?
            .parse::<u32>()
            .map_err(string_error)?,
        provider_run_id: context.provider_run_id.into(),
    };
    let common_ledger = read_protected_common_ledger(
        context.attester_repository,
        &context
            .common_evidence
            .join("ledger")
            .join(context.provider_run_id),
        &run_context,
        context.domain,
    )?;
    validate_ledger_phase_roster(
        common_ledger.record(),
        context.scenario_ids,
        context.operation_plans,
    )?;
    let reviewed_domain = load_domain_from_git(
        context.repository,
        context.domain,
        &run_context.candidate_revision,
    )?;
    let parsed = metadata_validation.and_then(|()| {
        let collection_path = context.evidence.join("collection.json");
        let (bytes, _) = crate::profile_qualification_evidence::read_untrusted_regular(
            &collection_path,
            MAX_CANDIDATE_COLLECTION_BYTES,
        )?;
        let collection: CandidateCollection = serde_json::from_slice(&bytes).map_err(string_error)?;
        if collection.validate().is_err()
            || collection.schema != "auths.profile-qualification-candidate-collection/1"
            || serde_json_canonicalizer::to_vec(&collection).map_err(string_error)? != bytes
        {
            return Err("candidate qualification collection is not canonical".into());
        }
        collection.run_reference.validate().map_err(string_error)?;
        if collection.run_reference.domain != context.domain
            || collection.run_reference.target != run_context.target
            || collection.run_reference.candidate_revision != run_context.candidate_revision
            || collection.run_reference.repository_id != run_context.repository_id
            || collection.run_reference.run_id != run_context.run_id
            || collection.run_reference.run_attempt != run_context.run_attempt
            || collection.run_reference.provider_run_id != run_context.provider_run_id
        {
            return Err("candidate run reference differs from trusted workflow context".into());
        }
        let expected = context.scenario_ids;
        if collection.scenarios.len() != expected.len()
            || collection
                .scenarios
                .iter()
                .map(|scenario| scenario.scenario_id.as_str())
                .ne(expected.iter().map(String::as_str))
        {
            return Err("candidate collection does not exactly cover the reviewed scenario roster".into());
        }
        for scenario in &collection.scenarios {
            scenario.validate().map_err(string_error)?;
            if scenario.provider_run_id != run_context.provider_run_id {
                return Err("candidate scenario names the wrong provider-matrix run".into());
            }
            let planned = context
                .operation_plans
                .get(&scenario.scenario_id)
                .ok_or_else(|| "candidate scenario has no reviewed operation plan".to_owned())?;
            if scenario.operations.len() != planned.len()
                || scenario.operations.iter().zip(planned).any(|(actual, expected)| {
                    actual.role != expected.role || actual.profile != expected.profile
                })
            {
                return Err("candidate operations differ from the reviewed operation plan".into());
            }
            if scenario.failpoint != expected_failpoint(&scenario.scenario_id) {
                return Err("candidate scenario uses a failpoint not selected by the reviewed common roster".into());
            }
        }
        Ok(collection)
    });
    let observation = parsed
        .as_ref()
        .map_err(Clone::clone)
        .and_then(|collection| {
            let environment = adapter
                .open(&run_context, Some(&collection.run_reference))
                .map_err(string_error)?;
            let mut reports = Vec::with_capacity(collection.scenarios.len());
            let mut provider_truth = Vec::new();
            for invocation in &collection.scenarios {
                let program = scenario_program_at(
                    context.repository,
                    &reviewed_domain,
                    &run_context.candidate_revision,
                    &invocation.scenario_id,
                )?;
                let planned = context
                    .operation_plans
                    .get(&invocation.scenario_id)
                    .ok_or_else(|| {
                        "candidate scenario has no reviewed operation plan".to_owned()
                    })?;
                let operation_plan_sha256 = hex::encode(Sha256::digest(
                    serde_json_canonicalizer::to_vec(planned).map_err(string_error)?,
                ));
                let mut operation_reports = Vec::with_capacity(invocation.operations.len());
                let mut scenario_truths = Vec::new();
                for (phase_index, phase) in invocation.operations.iter().enumerate() {
                    let common = read_protected_common_phase_evidence(
                        context.common_evidence,
                        common_ledger.record(),
                        &run_context,
                        context.domain,
                        &invocation.scenario_id,
                        invocation.failpoint,
                        phase_index,
                        phase,
                        &operation_plan_sha256,
                    )?;
                    let mut protected_instances = Vec::with_capacity(common.instances.len());
                    for common_instance in &common.instances {
                        let instance = &common_instance.projection;
                        let protected_counters = common_instance.projection.counters.clone();
                        let in_row_domain_facts = read_bounded(
                            &context
                                .common_evidence
                                .join("provider-observer-facts")
                                .join(format!("{}.json", instance.operation_id)),
                            4 * 1_024 * 1_024,
                        )?;
                        let truth = adapter
                            .provider_truth(
                                &environment,
                                &invocation.scenario_id,
                                phase,
                                instance,
                                &in_row_domain_facts,
                            )
                            .map_err(string_error)?;
                        let provider_truth_sha256 = hex::encode(truth.commitment);
                        if truth.operation_id != instance.operation_id
                            || truth.provider_run_id != invocation.provider_run_id
                            || truth.provider_run_id != matrix_run.id
                            || truth.provider_version != matrix_run.provider_version
                            || truth.provider_artifact_sha256 != matrix_run.provider_artifact_sha256
                            || common_instance.projection.effect != truth.effect
                            || truth.provider_calls != protected_counters.provider_calls
                            || !provider_truth_matches_ledger(
                                common_ledger.record(),
                                &invocation.scenario_id,
                                u8::try_from(phase_index + 1).map_err(|_| {
                                    "qualification phase index exceeds its hard bound".to_owned()
                                })?,
                                &truth.operation_id,
                                truth.effect,
                                &provider_truth_sha256,
                            )
                        {
                            return Err(
                                "protected counters and independent provider truth disagree".into(),
                            );
                        }
                        crate::profile_qualification_adapters::validate_provider_truth_facts(
                            context.domain,
                            &truth.domain_facts,
                            truth.effect,
                        )?;
                        let domain_facts: Value =
                            serde_json::from_slice(&truth.domain_facts).map_err(string_error)?;
                        if serde_json_canonicalizer::to_vec(&domain_facts).map_err(string_error)?
                            != truth.domain_facts
                        {
                            return Err("protected provider truth facts are not canonical".into());
                        }
                        adapter
                            .validate_receipt_payload(
                                &environment,
                                phase,
                                instance,
                                &truth,
                                &common_instance.receipt_claims,
                            )
                            .map_err(string_error)?;
                        scenario_truths.push(truth.clone());
                        provider_truth.push(ProtectedObservedTruth {
                            operation_id: truth.operation_id.clone(),
                            provider_run_id: truth.provider_run_id.clone(),
                            provider_version: truth.provider_version.clone(),
                            provider_artifact_sha256: truth.provider_artifact_sha256.clone(),
                            effect: truth.effect,
                            provider_calls: truth.provider_calls,
                            commitment_sha256: provider_truth_sha256.clone(),
                            domain_facts,
                        });
                        protected_instances.push(
                            auths_profile_kit::QualificationRedactedOperationInstance {
                                operation_id: common_instance.projection.operation_id.clone(),
                                connection_generation: common_instance
                                    .projection
                                    .connection_generation
                                    .clone(),
                                principal_sha256: common_instance
                                    .projection
                                    .principal_sha256
                                    .clone(),
                                connection_alias_sha256: common_instance
                                    .projection
                                    .connection_alias_sha256
                                    .clone(),
                                connection_id_sha256: common_instance
                                    .projection
                                    .connection_id_sha256
                                    .clone(),
                                connection_descriptor_sha256: common_instance
                                    .projection
                                    .connection_descriptor_sha256
                                    .clone(),
                                connection_account_sha256: common_instance
                                    .projection
                                    .connection_account_sha256
                                    .clone(),
                                credential_scope_sha256: common_instance
                                    .projection
                                    .credential_scope_sha256
                                    .clone(),
                                canonical_input_sha256: common_instance
                                    .projection
                                    .canonical_input_sha256
                                    .clone(),
                                idempotency_sha256: common_instance
                                    .projection
                                    .idempotency_sha256
                                    .clone(),
                                canonical_action_sha256: common_instance
                                    .projection
                                    .canonical_action_sha256
                                    .clone(),
                                receipt_action_sha256: common_instance
                                    .projection
                                    .receipt_action_sha256
                                    .clone(),
                                receipt_context_sha256: common_instance
                                    .projection
                                    .receipt_context_sha256
                                    .clone(),
                                authority_sha256: common_instance
                                    .projection
                                    .authority_sha256
                                    .clone(),
                                configuration_sha256: common_instance
                                    .projection
                                    .configuration_sha256
                                    .clone(),
                                runtime_contract_sha256: common_instance
                                    .projection
                                    .runtime_contract_sha256
                                    .clone(),
                                preparation_sha256: common_instance
                                    .projection
                                    .preparation_sha256
                                    .clone(),
                                decision_class: common_instance.projection.decision_class,
                                reconciled: common_instance.projection.reconciled,
                                // Common lifecycle truth owns the signed
                                // effect projection. Provider truth is an
                                // independent mismatch oracle above; it may
                                // never author the common effect claim.
                                effect: common_instance.projection.effect,
                                counters: protected_counters,
                                provider_truth_sha256,
                                sealed_command_sha256: common_instance
                                    .projection
                                    .sealed_command_sha256
                                    .clone(),
                                provider_result_sha256: common_instance
                                    .projection
                                    .provider_result_sha256
                                    .clone(),
                                execution_result_sha256: common_instance
                                    .projection
                                    .execution_result_sha256
                                    .clone(),
                            },
                        );
                    }
                    let report = auths_profile_kit::QualificationRedactedOperation {
                        role: phase.role,
                        profile: phase.profile.clone(),
                        instances: protected_instances,
                        attempts: common.attempts,
                    };
                    report.validate().map_err(string_error)?;
                    operation_reports.push(report);
                }
                scenario_truths.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
                if scenario_truths
                    .windows(2)
                    .any(|pair| pair[0].operation_id == pair[1].operation_id)
                {
                    return Err("scenario provider truth repeats an operation".into());
                }
                auths_profile_kit::validate_scenario_program_projection(
                    &program,
                    invocation.failpoint,
                    &operation_reports,
                    &scenario_truths,
                )
                .map_err(string_error)?;
                adapter
                    .validate_domain_scenario(&program, &operation_reports, &scenario_truths)
                    .map_err(string_error)?;
                reports.push(ProtectedObservedScenario {
                    scenario_id: invocation.scenario_id.clone(),
                    scenario_program_sha256: program.sha256().map_err(string_error)?,
                    domain_predicate_sha256: scenario_predicate_sha256(
                        &program,
                        invocation.failpoint,
                        &operation_reports,
                        &scenario_truths,
                    )?,
                    operations: operation_reports,
                });
            }
            provider_truth.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
            if provider_truth
                .windows(2)
                .any(|pair| pair[0].operation_id == pair[1].operation_id)
            {
                return Err("protected provider truth repeats an operation".into());
            }
            Ok((reports, provider_truth))
        });
    match observation {
        Err(error) => Err(error),
        Ok((reports, provider_truth)) => {
            let collection = parsed
                .as_ref()
                .map_err(|error| format!("protected observation lost its collection: {error}"))?;
            if reports.len() != collection.scenarios.len() {
                return Err("protected report roster differs from the candidate scenarios".into());
            }
            let observed = ProtectedObservedProviderRun {
                schema: "auths.profile-qualification-observed-provider-run/1".into(),
                run_reference: collection.run_reference.clone(),
                scenarios: reports,
                provider_truth,
            };
            atomic_write_new(
                &context.output.join("observed.json"),
                &serde_json_canonicalizer::to_vec(&observed).map_err(string_error)?,
            )
        }
    }
}

pub(crate) fn cleanup_domain_adapter<A: QualificationProtectedObserver>(
    adapter: A,
    context: CleanupAdapterContext<'_>,
) -> Result<(), String> {
    validate_adapter_metadata(
        &adapter.metadata(),
        context.repository,
        context.domain,
        context.run_context.target,
        &context.run_context.protected_environment,
        context.package,
    )?;
    let cleanup = adapter
        .cleanup(context.run_context, None)
        .and_then(|evidence| {
            evidence.validate()?;
            Ok(evidence)
        })
        .map_err(string_error)?;
    write_protected_cleanup(context.output, context.run_context, cleanup)
}

fn write_protected_cleanup(
    output: &Path,
    run: &auths_profile_kit::QualificationRunContext,
    cleanup: auths_profile_kit::QualificationCleanupEvidence,
) -> Result<(), String> {
    fs::create_dir_all(output).map_err(string_error)?;
    let report = ProtectedCleanupProviderRun {
        schema: "auths.profile-qualification-cleanup-provider-run/1".into(),
        repository_id: run.repository_id.clone(),
        candidate_revision: run.candidate_revision.clone(),
        target: run.target,
        protected_environment: run.protected_environment.clone(),
        run_id: run.run_id.clone(),
        run_attempt: run.run_attempt,
        provider_run_id: run.provider_run_id.clone(),
        evidence: cleanup,
        completed_at_unix_seconds: now_unix_seconds()?,
    };
    atomic_write_new(
        &output.join("cleanup.json"),
        &serde_json_canonicalizer::to_vec(&report).map_err(string_error)?,
    )
}

fn provider_truth_matches_ledger(
    ledger: &QualificationEvidenceLedgerRecord,
    scenario_id: &str,
    phase_index: u8,
    operation_id: &str,
    effect: auths_profile_kit::QualificationEffect,
    provider_truth_sha256: &str,
) -> bool {
    use auths_profile_kit::{
        QualificationEvidenceEventKind as Kind, QualificationEvidenceEventPayload as Payload,
        QualificationEvidenceSource as Source,
    };
    let Some(commitment) = ledger.phase(scenario_id, phase_index) else {
        return false;
    };
    ledger.phase_events(commitment).is_some_and(|events| {
        events
            .iter()
            .filter(|event| {
                event.source == Source::ProviderObserver
                    && event.kind == Kind::ProviderTruthObserved
                    && event.operation_id.as_deref() == Some(operation_id)
                    && matches!(
                        &event.payload,
                        Payload::ProviderTruth {
                            effect: observed_effect,
                            provider_truth_sha256: observed_sha256,
                        } if *observed_effect == effect && observed_sha256 == provider_truth_sha256
                    )
            })
            .count()
            == 1
    })
}

fn read_protected_common_phase_evidence(
    directory: &Path,
    ledger: &QualificationEvidenceLedgerRecord,
    context: &auths_profile_kit::QualificationRunContext,
    domain: &str,
    scenario_id: &str,
    expected_failpoint: Option<auths_profile_kit::QualificationFailpoint>,
    phase_index: usize,
    phase: &auths_profile_kit::QualificationCollectedOperation,
    operation_plan_sha256: &str,
) -> Result<QualificationCommonPhaseEvidence, String> {
    let path = directory
        .join("scenarios")
        .join(scenario_id)
        .join(&context.provider_run_id)
        .join(format!("{}.json", phase_index + 1));
    let (bytes, _) =
        crate::profile_qualification_evidence::read_untrusted_regular(&path, 1_048_576)?;
    let value: QualificationCommonPhaseEvidence =
        serde_json::from_slice(&bytes).map_err(string_error)?;
    let numbered_phase = u8::try_from(phase_index + 1)
        .map_err(|_| "qualification phase index exceeds its hard bound".to_owned())?;
    let commitment = ledger
        .phase(scenario_id, numbered_phase)
        .ok_or_else(|| "signed supervisor ledger omits the reviewed phase".to_owned())?;
    if serde_json_canonicalizer::to_vec(&value).map_err(string_error)? != bytes
        || hex::encode(Sha256::digest(&bytes)) != commitment.common_phase_evidence_sha256
        || value.schema != "auths.profile-qualification-common-phase-evidence/1"
        || value.repository_id != context.repository_id
        || value.workflow_run_id != context.run_id
        || value.workflow_run_attempt != context.run_attempt
        || value.candidate_revision != context.candidate_revision
        || value.domain != domain
        || value.target != context.target
        || value.protected_environment != context.protected_environment
        || value.provider_run_id != context.provider_run_id
        || value.scenario_id != scenario_id
        || value.phase_index != numbered_phase
        || value.role != phase.role
        || value.profile != phase.profile
        || value.failpoint != expected_failpoint
        || value.failpoint != commitment.failpoint
        || value.operation_plan_sha256 != operation_plan_sha256
        || value.operation_plan_sha256 != commitment.operation_plan_sha256
        || value.scenario_program_sha256 != commitment.scenario_program_sha256
        || value.ledger_id != ledger.ledger_id()
        || value.session_nonce_sha256 != ledger.session_nonce_sha256()
        || value.supervisor_generation == 0
        || value.first_event_sequence != commitment.first_event_sequence
        || value.last_event_sequence != commitment.last_event_sequence
        || commitment.scenario_id != scenario_id
        || commitment.phase_index != numbered_phase
        || commitment.role != phase.role
        || commitment.profile != phase.profile
        || ledger.phase_events(commitment).is_none_or(|events| {
            events.is_empty()
                || events
                    .iter()
                    .any(|event| event.supervisor_generation != value.supervisor_generation)
        })
        || !auths_profile_kit::qualification_common_phase_matches_ledger(ledger, commitment, &value)
            .map_err(string_error)?
        || value.instances.iter().any(|protected| {
            protected.projection.validate().is_err()
                || protected.receipt_claims.len() > 16
                || protected
                    .receipt_claims
                    .iter()
                    .enumerate()
                    .any(|(index, claim)| {
                        claim.sequence != u8::try_from(index + 1).unwrap_or(u8::MAX)
                            || claim.validate().is_err()
                            || claim.operation_id != protected.projection.operation_id
                            || claim.profile != value.profile
                            || claim.connection_generation
                                != protected.projection.connection_generation
                    })
        })
        || value.attempts.is_empty()
        || value.attempts.len() > 8
        || value.attempts.iter().enumerate().any(|(index, attempt)| {
            attempt.sequence != u8::try_from(index + 1).unwrap_or(u8::MAX)
                || attempt.validate().is_err()
        })
    {
        return Err(
            "protected common operation evidence is malformed or context-mismatched".into(),
        );
    }
    Ok(value)
}

fn read_protected_common_ledger(
    repository: &Path,
    path: &Path,
    context: &auths_profile_kit::QualificationRunContext,
    domain: &str,
) -> Result<QualificationEvidenceLedger, String> {
    let (bytes, _) = crate::profile_qualification_evidence::read_untrusted_regular(
        &path.join("ledger.json"),
        16_777_216,
    )?;
    let source_trust_bytes = read_bounded(&repository.join(EVIDENCE_SOURCE_TRUST_PATH), 262_144)?;
    if hex::encode(Sha256::digest(&source_trust_bytes))
        != required_sha256_env("AUTHS_QUALIFICATION_EVIDENCE_SOURCE_TRUST_SHA256")?
    {
        return Err("protected evidence-source trust registry differs from policy".into());
    }
    let source_trust = QualificationEvidenceSourceTrustRegistry::from_json(&source_trust_bytes)
        .map_err(string_error)?;
    let ledger_trust_bytes = read_bounded(&repository.join(EVIDENCE_LEDGER_TRUST_PATH), 262_144)?;
    if hex::encode(Sha256::digest(&ledger_trust_bytes))
        != required_sha256_env("AUTHS_QUALIFICATION_EVIDENCE_LEDGER_TRUST_SHA256")?
    {
        return Err("protected evidence-ledger trust registry differs from policy".into());
    }
    let ledger_trust = QualificationEvidenceLedgerTrustRegistry::from_json(&ledger_trust_bytes)
        .map_err(string_error)?;
    let ledger = QualificationEvidenceLedger::verify_json(
        &bytes,
        &source_trust,
        &ledger_trust,
        now_unix_seconds()?,
    )
    .map_err(string_error)?;
    let record = ledger.record();
    if record.repository_id() != context.repository_id
        || record.candidate_revision() != context.candidate_revision
        || record.run_id() != context.run_id
        || record.run_attempt() != context.run_attempt
        || record.domain() != domain
        || record.target() != context.target
        || record.protected_environment() != context.protected_environment
        || record.provider_run_id() != context.provider_run_id
        || record.workflow_path() != format!(".github/workflows/profile-qualification-{domain}.yml")
        || record.workflow_revision() != required_env("AUTHS_QUALIFICATION_WORKFLOW_REVISION")?
        || record.attester_revision() != required_env("AUTHS_QUALIFICATION_ATTESTER_REVISION")?
    {
        return Err("signed supervisor ledger differs from trusted workflow context".into());
    }
    Ok(ledger)
}

fn validate_ledger_phase_roster(
    ledger: &QualificationEvidenceLedgerRecord,
    scenario_ids: &[String],
    operation_plans: &BTreeMap<String, Vec<QualificationPlannedOperation>>,
) -> Result<(), String> {
    let mut expected = Vec::new();
    for scenario_id in scenario_ids {
        let plan = operation_plans
            .get(scenario_id)
            .ok_or_else(|| "reviewed scenario has no operation plan".to_owned())?;
        let plan_sha256 = hex::encode(Sha256::digest(
            serde_json_canonicalizer::to_vec(plan).map_err(string_error)?,
        ));
        for (index, operation) in plan.iter().enumerate() {
            expected.push((
                scenario_id.as_str(),
                u8::try_from(index + 1)
                    .map_err(|_| "reviewed operation plan exceeds its phase bound".to_owned())?,
                operation.role,
                operation.profile.as_str(),
                expected_failpoint(scenario_id),
                plan_sha256.clone(),
            ));
        }
    }
    if ledger.phases().len() != expected.len()
        || ledger
            .phases()
            .iter()
            .zip(expected)
            .any(|(actual, expected)| {
                actual.scenario_id != expected.0
                    || actual.phase_index != expected.1
                    || actual.role != expected.2
                    || actual.profile != expected.3
                    || actual.failpoint != expected.4
                    || actual.operation_plan_sha256 != expected.5
            })
    {
        return Err(
            "signed supervisor ledger does not exactly cover the reviewed phase roster".into(),
        );
    }
    use auths_profile_kit::{
        QualificationEvidenceEventKind as Kind, QualificationEvidenceEventPayload as Payload,
        QualificationOperationRole as Role,
    };
    for scenario_id in scenario_ids {
        let plan = operation_plans
            .get(scenario_id)
            .ok_or_else(|| "reviewed scenario has no operation plan".to_owned())?;
        if !plan
            .iter()
            .any(|operation| operation.role == Role::Preflight)
            || !plan.iter().any(|operation| operation.role == Role::Effect)
        {
            continue;
        }
        let reservation_roster = |role, kind| {
            ledger
                .events
                .iter()
                .filter(|event| {
                    event.scenario_id == *scenario_id && event.role == role && event.kind == kind
                })
                .filter_map(|event| match &event.payload {
                    Payload::Reservation { reservation_sha256 } => {
                        Some((reservation_sha256.as_str(), event.sequence))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        let consumed = reservation_roster(Role::Preflight, Kind::ReservationConsumed);
        let durable = reservation_roster(Role::Effect, Kind::ReservationDurable);
        if durable.iter().any(|(digest, sequence)| {
            consumed
                .iter()
                .filter(|(candidate, earlier)| candidate == digest && earlier < sequence)
                .count()
                != 1
        }) {
            return Err(format!(
                "effect reservation does not consume the reviewed preflight capability: {scenario_id}"
            ));
        }
    }
    Ok(())
}

fn expected_failpoint(scenario_id: &str) -> Option<auths_profile_kit::QualificationFailpoint> {
    use auths_profile_kit::QualificationFailpoint;
    match scenario_id {
        "crash-before-decision" => Some(QualificationFailpoint::BeforeDecision),
        "crash-after-decision" => Some(QualificationFailpoint::AfterDecision),
        "crash-after-reservation" => Some(QualificationFailpoint::AfterReservation),
        "crash-after-command" => Some(QualificationFailpoint::AfterCommand),
        "crash-after-reread" => Some(QualificationFailpoint::AfterReread),
        "crash-after-lease" => Some(QualificationFailpoint::AfterLease),
        "crash-after-entry-marker" => Some(QualificationFailpoint::AfterEntryMarker),
        "crash-after-request-write" => Some(QualificationFailpoint::AfterRequestWrite),
        "crash-after-provider-result" => Some(QualificationFailpoint::AfterProviderResult),
        "crash-after-observation" => Some(QualificationFailpoint::AfterObservation),
        "crash-after-execution-receipt" => Some(QualificationFailpoint::AfterExecutionReceipt),
        "crash-after-terminal" => Some(QualificationFailpoint::AfterTerminal),
        _ => None,
    }
}

fn validate_adapter_metadata(
    metadata: &auths_profile_kit::QualificationAdapterMetadata,
    repository: &Path,
    domain: &str,
    target: QualificationTarget,
    environment: &str,
    package: &ProfilePackage,
) -> Result<(), String> {
    metadata.validate().map_err(string_error)?;
    let domain_scenarios = QualificationScenarioManifest::from_json(&read_bounded(
        &repository.join(format!(
            "product/integrations/auths-{}/{}",
            domain,
            package.qualification().domain_scenarios()
        )),
        32_768,
    )?)
    .map_err(string_error)?;
    let family = package
        .qualification()
        .family()
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    if metadata.domain != domain
        || metadata.family != family
        || metadata.targets != package.qualification().targets()
        || metadata.targets != [target]
        || metadata.protected_environment != environment
        || metadata.scenarios
            != domain_scenarios
                .programs()
                .iter()
                .map(auths_profile_kit::QualificationScenarioProgramV1::id)
                .collect::<Vec<_>>()
    {
        return Err("qualification adapter metadata differs from its reviewed manifest".into());
    }
    Ok(())
}

fn verify_uploaded(
    repository: &Path,
    evidence_directory: &Path,
    verified_record_output: &Path,
) -> Result<(), String> {
    if env::var("GITHUB_ACTIONS").as_deref() != Ok("true") {
        return Err("qualification upload verification is restricted to GitHub Actions".into());
    }
    reject_secret_bearing_environment()?;
    let domain = required_env("QUALIFICATION_DOMAIN")?;
    let target =
        QualificationTarget::parse(&required_env("QUALIFICATION_TARGET")?).map_err(string_error)?;
    let candidate_repository = PathBuf::from(required_env("QUALIFICATION_CANDIDATE_REPOSITORY")?);
    let candidate_revision = required_env("QUALIFICATION_CANDIDATE_REVISION")?;
    let artifact_id = required_env("QUALIFICATION_ARTIFACT_ID")?;
    let artifact_digest = required_env("QUALIFICATION_ARTIFACT_DIGEST")?;
    let verified_binding_output =
        PathBuf::from(required_env("QUALIFICATION_VERIFIED_BINDING_OUTPUT")?);
    if verified_record_output == verified_binding_output {
        return Err("verified record and binding outputs must be distinct".into());
    }

    validate_attestation_upload_directory(evidence_directory)?;
    if !lower_hex(&candidate_revision, 40)
        || git_revision(&candidate_repository)? != candidate_revision
    {
        return Err(
            "protected candidate checkout does not match the immutable candidate revision".into(),
        );
    }
    let proposal_path = evidence_directory.join("proposal.json");
    let archive_path = evidence_directory.join("evidence.tar.zst");
    let (proposal_bytes, _) =
        crate::profile_qualification_evidence::read_untrusted_regular(&proposal_path, 262_144)?;
    let proposal = auths_profile_kit::QualificationProposal::from_json(&proposal_bytes)
        .map_err(string_error)?;
    let evidence = crate::profile_qualification_evidence::verify_and_extract(&archive_path)?;
    rerun_independent_evidence_scans(&evidence)?;
    let record = reconstruct_protected_record(
        repository,
        &candidate_repository,
        &candidate_revision,
        &domain,
        target,
        &proposal,
        &proposal_bytes,
        &evidence,
        &artifact_id,
        &artifact_digest,
    )?;
    if record.domain() != domain || record.target() != target {
        return Err("uploaded record domain or target does not match the protected job".into());
    }
    if record.artifact().evidence_tar_bytes() != evidence.compressed_bytes()
        || record.artifact().evidence_tar_sha256() != evidence.compressed_sha256()
        || record.artifact().artifact_id() != artifact_id
        || record.artifact().uploaded_archive_sha256() != artifact_digest
    {
        return Err("uploaded artifact does not match the signed evidence record".into());
    }
    let record_bytes = record.canonical_json().map_err(string_error)?;
    let binding = QualificationVerifiedRecordBinding::from_record(&record).map_err(string_error)?;
    let binding_bytes = binding.canonical_json().map_err(string_error)?;
    for output in [verified_record_output, &verified_binding_output] {
        let parent = output
            .parent()
            .ok_or_else(|| "verified handoff destination has no parent".to_owned())?;
        fs::create_dir_all(parent).map_err(string_error)?;
    }
    atomic_write_new_owner_only(verified_record_output, &record_bytes)?;
    atomic_write_new_owner_only(&verified_binding_output, &binding_bytes)?;
    println!(
        "verified uploaded evidence as {}",
        record.qualification_id()
    );
    Ok(())
}

fn validate_attestation_upload_directory(directory: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(directory).map_err(string_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("downloaded qualification evidence is not a regular directory".into());
    }
    let mut names = fs::read_dir(directory)
        .map_err(string_error)?
        .map(|entry| {
            let entry = entry.map_err(string_error)?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(string_error)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(
                    "downloaded qualification evidence contains a non-regular entry".into(),
                );
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| "downloaded qualification evidence name is not UTF-8".to_owned())
        })
        .collect::<Result<Vec<_>, String>>()?;
    names.sort();
    if names != ["evidence.tar.zst", "proposal.json"] {
        return Err("downloaded qualification evidence must contain exactly proposal.json and evidence.tar.zst".into());
    }
    Ok(())
}

fn reject_secret_bearing_environment() -> Result<(), String> {
    if env::vars_os().any(|(name, _)| {
        let name = name.to_string_lossy().to_ascii_uppercase();
        secret_bearing_environment_name(&name)
    }) {
        return Err("no-secret qualification verifier inherited a forbidden secret slot".into());
    }
    Ok(())
}

fn secret_bearing_environment_name(name: &str) -> bool {
    [
        "CREDENTIAL",
        "PASSWORD",
        "PRIVATE_KEY",
        "SECRET",
        "SEED",
        "TOKEN",
    ]
    .iter()
    .any(|part| name.contains(part))
}

fn rerun_independent_evidence_scans(
    evidence: &crate::profile_qualification_evidence::VerifiedEvidence,
) -> Result<(), String> {
    let domain = required_env("QUALIFICATION_DOMAIN")?;
    let (domain_fields, redaction_prefixes) = qualification_evidence_scan_policy(&domain)?;
    // The protected report truthfully covers the complete pre-sign tree. The
    // final attester additionally scans the inserted signed observation and
    // deterministic manifest, but those two later bytes are not retroactively
    // claimed by the observer report.
    let scanned_files = u32::try_from(
        evidence
            .member_names()
            .len()
            .checked_sub(1)
            .ok_or_else(|| "qualification scan roster is empty".to_owned())?,
    )
    .map_err(string_error)?;
    rerun_typed_forbidden_field_scan(evidence, domain_fields)?;
    let redacted_values = rerun_redaction_scan(evidence, redaction_prefixes)?;
    rerun_gitleaks(evidence.extracted_directory())?;

    use crate::profile_qualification_reports::{ScanReport, parse_canonical};
    for (path, kind) in [
        ("reports/gitleaks.json", "gitleaks"),
        (
            "reports/typed-forbidden-fields.json",
            "typed-forbidden-field",
        ),
        ("reports/redaction.json", "redaction"),
    ] {
        let report: ScanReport = parse_canonical(&evidence.read_member(path, 262_144)?)?;
        if report.binding.repository_id != required_env("GITHUB_REPOSITORY_ID")?
            || report.binding.workflow_run_id != required_env("GITHUB_RUN_ID")?
            || report.binding.workflow_run_attempt
                != required_env("GITHUB_RUN_ATTEMPT")?
                    .parse::<u32>()
                    .map_err(string_error)?
            || report.binding.candidate_revision
                != required_env("QUALIFICATION_CANDIDATE_REVISION")?
            || report.binding.domain != domain
            || report.binding.target != required_env("QUALIFICATION_TARGET")?
        {
            return Err("independently rerun scan report has the wrong protected binding".into());
        }
        report.validate(
            &crate::profile_qualification_reports::ExpectedReportBinding {
                repository_id: report.binding.repository_id.clone(),
                workflow_run_id: report.binding.workflow_run_id.clone(),
                workflow_run_attempt: report.binding.workflow_run_attempt,
                candidate_revision: report.binding.candidate_revision.clone(),
                domain: report.binding.domain.clone(),
                target: report.binding.target.clone(),
                profiles: report.binding.profiles.clone(),
                provider_run_ids: report.binding.provider_run_ids.clone(),
                scenario_ids: report.binding.scenario_ids.clone(),
                failpoints: report.binding.failpoints.clone(),
                operation_ids: report.binding.operation_ids.clone(),
                connection_generations: report.binding.connection_generations.clone(),
                scenario_applicability: BTreeMap::new(),
            },
            kind,
        )?;
        report.require_recomputed_clean_scan(scanned_files, redacted_values)?;
    }
    Ok(())
}

fn qualification_evidence_scan_policy(
    domain: &str,
) -> Result<(&'static [&'static str], &'static [&'static str]), String> {
    let fields =
        crate::profile_qualification_adapters::qualification_forbidden_evidence_fields(domain)?;
    let prefixes = crate::profile_qualification_adapters::qualification_redaction_prefixes(domain)?;
    for (values, kind) in [(fields, "field"), (prefixes, "prefix")] {
        if values.len() > 64
            || values.windows(2).any(|pair| pair[0] >= pair[1])
            || values.iter().any(|value| {
                value.is_empty()
                    || value.len() > 128
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_graphic() && byte != b'\\')
            })
        {
            return Err(format!(
                "qualification domain {kind} scan policy is not canonical"
            ));
        }
    }
    Ok((fields, prefixes))
}

fn rerun_typed_forbidden_field_scan(
    evidence: &crate::profile_qualification_evidence::VerifiedEvidence,
    domain_fields: &[&str],
) -> Result<(), String> {
    const FORBIDDEN_FIELDS: [&str; 8] = [
        "authorization",
        "credential",
        "password",
        "privateKey",
        "recoveryHandle",
        "resourceReferences",
        "secret",
        "seed",
    ];
    const FORBIDDEN_CONTENT: [&[u8]; 3] = [b"-----BEGIN PRIVATE KEY-----", b"github_pat_", b"ghp_"];
    for path in evidence.scan_member_names() {
        let bytes = evidence.read_member(path, 16_777_216)?;
        if FORBIDDEN_CONTENT
            .iter()
            .any(|needle| bytes.windows(needle.len()).any(|window| window == *needle))
        {
            return Err(format!(
                "qualification evidence contains forbidden secret content: {path}"
            ));
        }
        if path.ends_with(".json") {
            let value: Value = serde_json::from_slice(&bytes).map_err(string_error)?;
            if json_has_forbidden_field(&value, &FORBIDDEN_FIELDS)
                || json_has_forbidden_field(&value, domain_fields)
            {
                return Err(format!(
                    "qualification evidence contains a forbidden typed field: {path}"
                ));
            }
        }
    }
    Ok(())
}

fn rerun_redaction_scan(
    evidence: &crate::profile_qualification_evidence::VerifiedEvidence,
    raw_provider_prefixes: &[&str],
) -> Result<u32, String> {
    for path in evidence.scan_member_names() {
        let bytes = evidence.read_member(path, 16_777_216)?;
        if contains_unredacted_provider_identifier(&bytes, raw_provider_prefixes) {
            return Err(format!(
                "qualification evidence contains an unredacted provider identifier: {path}"
            ));
        }
    }
    Ok(0)
}

fn contains_unredacted_provider_identifier(bytes: &[u8], prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| {
        let needle = prefix.as_bytes();
        bytes.windows(needle.len()).any(|window| window == needle)
    })
}

fn json_has_forbidden_field(value: &Value, forbidden: &[&str]) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            forbidden
                .iter()
                .any(|forbidden| normalized_field_name(key) == normalized_field_name(forbidden))
                || json_has_forbidden_field(value, forbidden)
        }),
        Value::Array(values) => values
            .iter()
            .any(|value| json_has_forbidden_field(value, forbidden)),
        _ => false,
    }
}

fn normalized_field_name(value: &str) -> String {
    value
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .map(|byte| char::from(byte.to_ascii_lowercase()))
        .collect()
}

fn rerun_gitleaks(directory: &Path) -> Result<(), String> {
    let executable = PathBuf::from(required_env("AUTHS_QUALIFICATION_GITLEAKS")?);
    if !executable.is_absolute() {
        return Err("protected gitleaks path must be absolute".into());
    }
    let metadata = fs::symlink_metadata(&executable).map_err(string_error)?;
    #[cfg(unix)]
    let has_one_link = {
        use std::os::unix::fs::MetadataExt as _;
        metadata.nlink() == 1
    };
    #[cfg(not(unix))]
    let has_one_link = false;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || !has_one_link
        || file_sha256(&executable, 134_217_728)?
            != required_sha256_env("AUTHS_QUALIFICATION_GITLEAKS_SHA256")?
    {
        return Err("protected gitleaks executable does not match its immutable binding".into());
    }
    let version = Command::new(&executable)
        .arg("version")
        .output()
        .map_err(|_| "pinned gitleaks 8.28.0 is unavailable".to_owned())?;
    if !version.status.success()
        || String::from_utf8(version.stdout)
            .map_err(string_error)?
            .trim()
            != "8.28.0"
    {
        return Err("qualification verifier requires exact gitleaks 8.28.0".into());
    }
    let report_directory = tempfile::tempdir().map_err(string_error)?;
    let report = report_directory.path().join("gitleaks.json");
    let status = Command::new(&executable)
        .args(["detect", "--no-git", "--no-banner", "--redact"])
        .arg("--source")
        .arg(directory)
        .args(["--report-format", "json", "--report-path"])
        .arg(&report)
        .status()
        .map_err(string_error)?;
    if !status.success() {
        return Err("independent gitleaks scan found sensitive evidence".into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn reconstruct_protected_record(
    attester_repository: &Path,
    candidate_repository: &Path,
    candidate_revision: &str,
    domain: &str,
    target: QualificationTarget,
    proposal: &auths_profile_kit::QualificationProposal,
    proposal_bytes: &[u8],
    evidence: &crate::profile_qualification_evidence::VerifiedEvidence,
    artifact_id: &str,
    artifact_digest: &str,
) -> Result<QualificationRecord, String> {
    if proposal.domain() != domain
        || proposal.target() != target
        || proposal.candidate_revision() != candidate_revision
    {
        return Err("candidate proposal does not match the protected run identity".into());
    }
    if !lower_hex(artifact_digest, 64) || !artifact_id.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("GitHub artifact identity is malformed".into());
    }
    let attestation_registry = load_trust_registry(attester_repository)?;
    let observer_registry = load_observer_trust_registry(attester_repository)?;
    validate_qualification_trust_separation(&attestation_registry, &observer_registry)
        .map_err(string_error)?;
    let observation_bytes = evidence.read_member("reports/protected-observation.json", 262_144)?;
    let verified_observation = QualificationObservation::verify_json(
        &observation_bytes,
        &observer_registry,
        now_unix_seconds()?,
    )
    .map_err(string_error)?;
    let observation = verified_observation.record();
    let workflow_path = format!(".github/workflows/profile-qualification-{domain}.yml");
    let repository_id = required_env("GITHUB_REPOSITORY_ID")?;
    let workflow_revision = required_env("QUALIFICATION_WORKFLOW_REVISION")?;
    let run_id = required_env("GITHUB_RUN_ID")?;
    let run_attempt = required_env("GITHUB_RUN_ATTEMPT")?
        .parse::<u32>()
        .map_err(string_error)?;
    if observation.domain() != domain
        || observation.target() != target
        || observation.candidate_revision() != candidate_revision
        || observation.repository_id() != repository_id
        || observation.workflow_path() != workflow_path
        || observation.workflow_revision() != workflow_revision
        || observation.run_id() != run_id
        || observation.run_attempt() != run_attempt
        || verified_observation.key_id() != required_env("AUTHS_QUALIFICATION_OBSERVER_KEY_ID")?
    {
        return Err("protected observation does not match the protected run identity".into());
    }
    let candidate = load_domain_from_git(candidate_repository, domain, candidate_revision)?;
    let provider_matrix =
        load_provider_matrix_at(candidate_repository, &candidate, target, candidate_revision)?;
    let operation_plans =
        load_operation_plans_at(candidate_repository, &candidate, candidate_revision)?;
    let failpoint_coverage =
        load_failpoint_coverage_at(candidate_repository, &candidate, candidate_revision)?;
    validate_observed_provider_runs(&provider_matrix, observation.provider_runs())?;
    let expected_binding = expected_report_binding_at(
        candidate_repository,
        &candidate,
        observation,
        &provider_matrix,
        candidate_revision,
    )?;
    let anchor_bytes = evidence.read_member("reports/receipt-trust-anchors.json", 65_536)?;
    let anchor_sha256 = hex::encode(Sha256::digest(&anchor_bytes));
    let recovery_key_id = required_env("AUTHS_QUALIFICATION_RECOVERY_KEY_ID")?;
    let recovery_public_key_base64url =
        required_env("AUTHS_QUALIFICATION_RECOVERY_PUBLIC_KEY_BASE64URL")?;
    if anchor_sha256 != required_env("AUTHS_QUALIFICATION_RECEIPT_TRUST_ANCHOR_SHA256")?
        || observation.receipt_trust_anchor_sha256() != anchor_sha256
        || observation.recovery_key_id() != recovery_key_id
        || observation.recovery_public_key_base64url() != recovery_public_key_base64url
    {
        return Err(
            "receipt or recovery trust differs from protected policy or observation".into(),
        );
    }
    validate_complete_qualification_key_separation(
        attester_repository,
        &attestation_registry,
        &observer_registry,
        &anchor_bytes,
        &recovery_key_id,
        &recovery_public_key_base64url,
    )?;
    validate_observation_report_commitments(evidence, observation)?;
    validate_typed_report_set(
        evidence,
        observation,
        &expected_binding,
        &operation_plans,
        &failpoint_coverage,
    )?;
    let scenarios = scenario_projection_from_reports(evidence, proposal_bytes)?;
    let release_build_path =
        PathBuf::from(required_env("AUTHS_QUALIFICATION_VERIFIED_RELEASE_BUILD")?);
    let release_build_bytes = read_bounded(&release_build_path, 262_144)?;
    let release_build =
        QualificationReleaseBuild::from_json(&release_build_bytes).map_err(string_error)?;
    if release_build.repository_id() != repository_id
        || release_build.sha256().map_err(string_error)? != observation.release_build_sha256()
    {
        return Err(
            "verified release build does not match the protected observation or repository".into(),
        );
    }
    let binding_path = PathBuf::from(required_env(
        "AUTHS_QUALIFICATION_VERIFIED_RELEASE_BUILD_BINDING",
    )?);
    let binding_bytes = read_bounded(&binding_path, 262_144)?;
    let binding: VerifiedQualificationReleaseBuildBinding =
        crate::profile_qualification_reports::parse_canonical(&binding_bytes)?;
    let qualification_agent_sha256 = validate_verified_release_build_binding(
        &binding,
        &release_build_bytes,
        candidate_revision,
        &repository_id,
        attester_repository,
    )?;
    let final_attester_tools_sha256 = attester_tools_identity_sha256(&binding.attester_tools)?;
    if observation.attester_tools_sha256() != final_attester_tools_sha256 {
        return Err("protected observation used a different hosted attester-tool identity".into());
    }
    let retained_receipt_verifications = verify_retained_evidence_ledgers(
        attester_repository,
        evidence,
        observation,
        &binding.attester_tools,
        Some(&qualification_agent_sha256),
    )?;

    let mut value: Value = serde_json::from_slice(proposal_bytes).map_err(string_error)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "qualification proposal is not an object".to_owned())?;
    object.insert("schema".into(), json!("auths.profile-qualification/1"));
    object.insert("qualificationId".into(), json!(""));
    object.insert(
        "proposalSha256".into(),
        json!(hex::encode(Sha256::digest(proposal_bytes))),
    );
    let profiles = candidate
        .package
        .qualification()
        .family()
        .iter()
        .map(|profile| {
            let (id, version) = profile
                .rsplit_once('/')
                .ok_or_else(|| "profile family subject is malformed".to_owned())?;
            Ok(json!({
                "id":id,
                "version":version.parse::<u16>().map_err(string_error)?,
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    object.insert("profiles".into(), Value::Array(profiles));
    let closure = semantic_closure_at(candidate_repository, domain, candidate_revision)?;
    object.insert("semanticClosureSha256".into(), json!(closure.sha256));
    object.insert(
        "packageManifestSha256".into(),
        json!(hex::encode(
            candidate
                .package
                .package_manifest_digest()
                .map_err(string_error)?
        )),
    );
    object.insert(
        "profileRuntimeDigests".into(),
        Value::Array(
            runtime_digests_at(candidate_repository, domain, candidate_revision)?
                .into_iter()
                .map(|(profile, sha256)| json!({"profile":profile,"sha256":sha256}))
                .collect(),
        ),
    );
    object.insert(
        "errorRegistrySha256".into(),
        json!(error_registry_digest_at(
            candidate_repository,
            candidate_revision
        )?),
    );
    object.insert(
        "providerMatrixSha256".into(),
        json!(provider_matrix_digest_at(
            candidate_repository,
            &candidate,
            target,
            candidate_revision
        )?),
    );
    object.insert(
        "toolchain".into(),
        installed_toolchain_at(
            candidate_repository,
            candidate_revision,
            evidence,
            &expected_binding,
        )?,
    );
    object.insert("environmentClass".into(), json!("disposable-provider-test"));
    object.insert("scenarios".into(), Value::Array(scenarios));
    object.remove("candidateArtifacts");
    object.insert(
        "releaseBuild".into(),
        serde_json::to_value(&release_build).map_err(string_error)?,
    );
    object.remove("collectionStartedAtUnixSeconds");
    object.remove("collectionCompletedAtUnixSeconds");
    let observation_value = serde_json::to_value(observation).map_err(string_error)?;
    let observation_object = observation_value
        .as_object()
        .ok_or_else(|| "verified observation record is not an object".to_owned())?;
    for (destination, source) in [
        ("startedAtUnixSeconds", "startedAtUnixSeconds"),
        ("completedAtUnixSeconds", "completedAtUnixSeconds"),
        ("providerRuns", "providerRuns"),
    ] {
        object.insert(
            destination.into(),
            observation_object
                .get(source)
                .cloned()
                .ok_or_else(|| format!("verified observation omits {source}"))?,
        );
    }
    object.insert(
        "workflow".into(),
        json!({
            "provider":"github-actions",
            "repositoryId":repository_id,
            "workflowPath":workflow_path,
            "workflowRevision":workflow_revision,
            "attesterRevision":git_revision(attester_repository)?,
            "runId":run_id,
            "runAttempt":run_attempt,
            "protectedEnvironment":required_env("QUALIFICATION_PROTECTED_ENVIRONMENT")?,
        }),
    );
    let retention_days = required_env("AUTHS_QUALIFICATION_RETENTION_DAYS")?
        .parse::<u16>()
        .map_err(string_error)?;
    object.insert(
        "artifact".into(),
        json!({
            "evidenceTarSha256":evidence.compressed_sha256(),
            "evidenceTarBytes":evidence.compressed_bytes(),
            "retentionDays":retention_days,
            "createdAtUnixSeconds":required_env("QUALIFICATION_ARTIFACT_CREATED_AT")?.parse::<u64>().map_err(string_error)?,
            "expiresAtUnixSeconds":required_env("QUALIFICATION_ARTIFACT_EXPIRES_AT")?.parse::<u64>().map_err(string_error)?,
            "redactionReportSha256":member_sha256(evidence, "reports/redaction.json")?,
            "storageProvider":"github-actions",
            "artifactId":artifact_id,
            "uploadedArchiveSha256":artifact_digest,
        }),
    );
    object.insert(
        "protectedObservation".into(),
        json!({
            "schema":"auths.profile-qualification-observation/1",
            "keyId":verified_observation.key_id(),
            "sha256":hex::encode(Sha256::digest(&observation_bytes)),
        }),
    );
    let receipt_projection = receipt_verification_projection(
        evidence,
        &anchor_bytes,
        &anchor_sha256,
        &expected_binding,
        &retained_receipt_verifications,
    )?;
    object.insert("receiptVerification".into(), receipt_projection);
    object.insert(
        "secretScan".into(),
        json!({
            "tool":"gitleaks-8.28.0",
            "status":"passed",
            "reportSha256":member_sha256(evidence, "reports/gitleaks.json")?,
        }),
    );
    let canonical = serde_json_canonicalizer::to_vec(&value).map_err(string_error)?;
    let record = QualificationRecord::finalize_json(&canonical).map_err(string_error)?;
    proposal
        .require_matches_record(&record)
        .map_err(string_error)?;
    verify_record_against_revision(candidate_repository, &record, candidate_revision)?;
    Ok(record)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RetainedReceiptVerification {
    operation_id: String,
    receipt_bytes_sha256: String,
    decoded_claims_sha256: String,
    profile_inspection_sha256: String,
}

fn validate_verified_release_build_binding(
    binding: &VerifiedQualificationReleaseBuildBinding,
    release_build_bytes: &[u8],
    candidate_revision: &str,
    repository_id: &str,
    attester_repository: &Path,
) -> Result<String, String> {
    let release_build: Value = serde_json::from_slice(release_build_bytes).map_err(string_error)?;
    let now = now_unix_seconds()?;
    let expected_retention_days = required_env("AUTHS_QUALIFICATION_RETENTION_DAYS")?
        .parse::<u16>()
        .map_err(string_error)?;
    if binding.schema != "auths.qualification-release-build-verification/1"
        || binding.verified_at_unix_seconds > now
        || now.saturating_sub(binding.verified_at_unix_seconds) > 3_600
        || binding.repository_id != repository_id
        || binding.repository_id != release_build["repositoryId"]
        || binding.workflow_path != ".github/workflows/release-builder.yml"
        || binding.workflow_path != release_build["workflowPath"]
        || binding.workflow_revision != candidate_revision
        || binding.workflow_revision != release_build["workflowRevision"]
        || binding.run_id != release_build["runId"]
        || binding.run_id != required_env("OFFICIAL_RELEASE_BUILD_RUN_ID")?
        || Value::from(binding.run_attempt) != release_build["runAttempt"]
        || binding.run_label != "official"
        || release_build["runLabel"] != "official"
        || binding.retention_days != expected_retention_days
        || !(90..=365).contains(&binding.retention_days)
        || binding.projection_artifact_name
            != format!("auths-qualification-{candidate_revision}-official-release-build")
        || binding.release_build_sha256 != hex::encode(Sha256::digest(release_build_bytes))
        || binding.qualification_surface_sha256 != release_build["qualificationSurfaceSha256"]
        || !canonical_decimal(&binding.projection_artifact_id, 32)
        || binding.projection_artifact_id != required_env("OFFICIAL_RELEASE_BUILD_ARTIFACT_ID")?
        || !lower_hex(&binding.projection_uploaded_archive_sha256, 64)
        || binding.projection_uploaded_archive_sha256
            != required_sha256_env("OFFICIAL_RELEASE_BUILD_ARTIFACT_DIGEST")?
        || !(1..=16_777_216).contains(&binding.projection_uploaded_archive_bytes)
        || binding.projection_created_at_unix_seconds > binding.verified_at_unix_seconds
        || now >= binding.projection_expires_at_unix_seconds
        || binding.projection_expires_at_unix_seconds
            < binding
                .projection_created_at_unix_seconds
                .saturating_add(u64::from(binding.retention_days) * 86_400)
        || !lower_hex(&binding.hosted_metadata_sha256, 64)
        || !lower_hex(&binding.provenance_verification_sha256, 64)
        || !lower_hex(&binding.provenance_bundle_sha256, 64)
        || !lower_hex(&binding.trusted_root_sha256, 64)
        || binding.trusted_root_sha256
            != required_env("AUTHS_QUALIFICATION_GH_TRUSTED_ROOT_SHA256")?
        || !lower_hex(&binding.provenance_verifier_sha256, 64)
        || binding.provenance_verifier_sha256 != required_env("AUTHS_QUALIFICATION_GH_CLI_SHA256")?
        || !canonical_semver_triplet(&binding.provenance_verifier_version)
        || binding.attester_tools.gh_version != binding.provenance_verifier_version
        || !lower_hex(&binding.release_build_verifier_sha256, 64)
        || binding.release_build_verifier_sha256
            != required_env("AUTHS_QUALIFICATION_RELEASE_VERIFIER_SHA256")?
        || validate_attester_tools_binding(&binding.attester_tools, now, repository_id).is_err()
        || binding.artifacts.len() != VERIFIED_RELEASE_ARTIFACT_ROLES.len()
    {
        return Err("verified release-build binding does not match the protected candidate".into());
    }
    let surface_bytes =
        serde_json_canonicalizer::to_vec(&binding.qualification_surface).map_err(string_error)?;
    let policy_bytes = read_bounded(
        &attester_repository.join("product/qualification/v1/release-surface-policy.json"),
        262_144,
    )?;
    let policy: QualificationReleaseSurfacePolicyBinding =
        crate::profile_qualification_reports::parse_canonical(&policy_bytes)?;
    let surface = &binding.qualification_surface;
    if hex::encode(Sha256::digest(&surface_bytes)) != binding.qualification_surface_sha256
        || surface.schema != "auths.qualification-release-surface/1"
        || surface.candidate_revision != candidate_revision
        || surface.policy_sha256 != hex::encode(Sha256::digest(&policy_bytes))
        || policy.schema != "auths.qualification-release-surface-policy/1"
        || surface.production_feature_set != policy.production_feature_set
        || surface.qualification_feature_set != policy.qualification_feature_set
        || surface.reviewed_difference != policy.reviewed_difference
        || surface.production_feature_set.iter().any(|feature| {
            feature == "auths-stores:qualification-evidence"
                || feature == "auths-node:qualification-failpoints"
        })
    {
        return Err("verified qualification surface differs from protected release policy".into());
    }
    validate_verified_release_surface_members(
        &surface.production_members,
        &policy.production_member_paths,
    )?;
    validate_verified_release_surface_members(
        &surface.qualification_members,
        &policy.qualification_member_paths,
    )?;
    let qualification_agent_sha256 = surface
        .qualification_members
        .iter()
        .find(|member| member.path == "target/release/auths-qualification-agent")
        .map(|member| member.sha256.clone())
        .ok_or_else(|| "verified qualification surface omits the exact crash agent".to_owned())?;
    let projected = release_build["artifacts"]
        .as_array()
        .ok_or("release build has no artifact roster")?;
    if projected.len() != binding.artifacts.len() {
        return Err("verified release-build artifact roster size drifted".into());
    }
    for ((actual, expected), role) in binding
        .artifacts
        .iter()
        .zip(projected)
        .zip(VERIFIED_RELEASE_ARTIFACT_ROLES)
    {
        if actual.role != role
            || actual.role != expected["role"]
            || actual.name != format!("auths-qualification-{candidate_revision}-official-{role}")
            || actual.artifact_id != expected["artifactId"]
            || actual.uploaded_archive_sha256 != expected["uploadedArchiveSha256"]
            || !(1..=536_870_912).contains(&actual.uploaded_archive_bytes)
            || actual.created_at_unix_seconds > binding.verified_at_unix_seconds
            || now >= actual.expires_at_unix_seconds
            || actual.expires_at_unix_seconds
                < actual
                    .created_at_unix_seconds
                    .saturating_add(u64::from(binding.retention_days) * 86_400)
            || actual.member_path != expected["memberPath"]
            || actual.member_sha256 != expected["memberSha256"]
            || Value::from(actual.bytes) != expected["bytes"]
        {
            return Err(format!(
                "verified release-build artifact binding drifted for {role}"
            ));
        }
    }
    Ok(qualification_agent_sha256)
}

fn validate_verified_release_surface_members(
    members: &[VerifiedQualificationReleaseSurfaceMember],
    expected_paths: &[String],
) -> Result<(), String> {
    if members.len() != expected_paths.len() {
        return Err("verified qualification surface member roster size drifted".into());
    }
    for (member, expected_path) in members.iter().zip(expected_paths) {
        if member.path != *expected_path
            || !lower_hex(&member.sha256, 64)
            || !(1..=536_870_912).contains(&member.bytes)
            || member.mode != "0755"
        {
            return Err(format!(
                "verified qualification surface member drifted: {expected_path}"
            ));
        }
    }
    Ok(())
}

fn validate_attester_tools_binding(
    tools: &VerifiedAttesterToolsBinding,
    now: u64,
    repository_id: &str,
) -> Result<(), String> {
    let expected = [
        ("auths-qualification-supervisor", "0755"),
        ("gh", "0755"),
        ("gitleaks", "0755"),
        ("qualification-agent-launcher", "0755"),
        ("qualification-attestation-signer", "0755"),
        ("qualification-crash-controller", "0755"),
        ("qualification-observation-signer", "0755"),
        ("qualification-release-build-verifier", "0755"),
        ("qualification-source-client-proxy", "0755"),
        ("qualification-source-credential-broker", "0755"),
        ("qualification-source-journal-reader", "0755"),
        ("qualification-source-profile-state-reader", "0755"),
        ("qualification-source-provider-observer", "0755"),
        ("qualification-source-provider-proxy", "0755"),
        ("qualification-source-receipt-verifier", "0755"),
        ("qualification-source-supervisor", "0755"),
        ("trusted-root.jsonl", "0600"),
        ("xtask", "0755"),
    ];
    if tools.schema != "auths.qualification-attester-tools-verification/1"
        || tools.verified_at_unix_seconds > now
        || now.saturating_sub(tools.verified_at_unix_seconds) > 3_600
        || tools.repository_id != repository_id
        || tools.workflow_path != ".github/workflows/qualification-attester-tools.yml"
        || tools.workflow_revision != required_env("AUTHS_QUALIFICATION_ATTESTER_REVISION")?
        || tools.attester_revision != tools.workflow_revision
        || tools.run_id != required_env("AUTHS_QUALIFICATION_ATTESTER_TOOLS_RUN_ID")?
        || !canonical_decimal(&tools.run_id, 32)
        || tools.run_attempt
            != required_env("AUTHS_QUALIFICATION_ATTESTER_TOOLS_RUN_ATTEMPT")?
                .parse::<u32>()
                .map_err(string_error)?
        || tools.retention_days != 90
        || tools.artifact_id != required_env("AUTHS_QUALIFICATION_ATTESTER_TOOLS_ARTIFACT_ID")?
        || !canonical_decimal(&tools.artifact_id, 32)
        || tools.artifact_name
            != format!(
                "auths-qualification-attester-tools-{}-attempt-{}",
                tools.attester_revision, tools.run_attempt
            )
        || tools.uploaded_archive_sha256
            != required_sha256_env("AUTHS_QUALIFICATION_ATTESTER_TOOLS_ARTIFACT_DIGEST")?
        || !(1..=536_870_912).contains(&tools.uploaded_archive_bytes)
        || tools.created_at_unix_seconds > tools.verified_at_unix_seconds
        || now >= tools.expires_at_unix_seconds
        || tools.expires_at_unix_seconds < tools.created_at_unix_seconds.saturating_add(90 * 86_400)
        || tools.manifest_sha256
            != required_sha256_env("AUTHS_QUALIFICATION_ATTESTER_TOOLS_MANIFEST_SHA256")?
        || !canonical_semver_triplet(&tools.gh_version)
        || tools.runner_label != "ubuntu-24.04"
        || tools.runner_image_os.is_empty()
        || tools.runner_image_os.len() > 128
        || !tools.runner_image_os.is_ascii()
        || tools.runner_image_version.is_empty()
        || tools.runner_image_version.len() > 128
        || !tools.runner_image_version.is_ascii()
        || tools.members.len() != expected.len()
    {
        return Err("verified attester-tool binding differs from the protected tool run".into());
    }
    for (member, (path, mode)) in tools.members.iter().zip(expected) {
        if member.path != path || member.mode != mode || !lower_hex(&member.sha256, 64) {
            return Err(format!("verified attester-tool member drifted for {path}"));
        }
    }
    let protected_gitleaks_sha256 = required_sha256_env("AUTHS_QUALIFICATION_GITLEAKS_SHA256")?;
    if tools
        .members
        .iter()
        .find(|member| member.path == "gitleaks")
        .map(|member| member.sha256.as_str())
        != Some(protected_gitleaks_sha256.as_str())
    {
        return Err("verified gitleaks member differs from the protected scanner".into());
    }
    let manifest = json!({
        "schema":"auths.qualification-attester-tools/1",
        "attesterRevision":tools.attester_revision,
        "ghVersion":tools.gh_version,
        "members":tools.members,
        "retentionDays":tools.retention_days,
        "runnerImageOs":tools.runner_image_os,
        "runnerImageVersion":tools.runner_image_version,
        "runnerLabel":tools.runner_label,
    });
    let manifest_bytes = serde_json_canonicalizer::to_vec(&manifest).map_err(string_error)?;
    if hex::encode(Sha256::digest(manifest_bytes)) != tools.manifest_sha256 {
        return Err("verified attester-tool manifest commitment drifted".into());
    }
    Ok(())
}

fn verified_attester_tools_from_files(
    verification_path: &Path,
    manifest_path: &Path,
) -> Result<VerifiedAttesterToolsBinding, String> {
    let verification_bytes = read_bounded(verification_path, 262_144)?;
    let manifest_bytes = read_bounded(manifest_path, 262_144)?;
    let mut verification: Value =
        crate::profile_qualification_reports::parse_canonical(&verification_bytes)?;
    let manifest: Value = crate::profile_qualification_reports::parse_canonical(&manifest_bytes)?;
    let object = verification
        .as_object_mut()
        .ok_or_else(|| "attester-tools hosted verification is not an object".to_owned())?;
    let manifest = manifest
        .as_object()
        .ok_or_else(|| "attester-tools manifest is not an object".to_owned())?;
    for field in [
        "attesterRevision",
        "ghVersion",
        "runnerImageOs",
        "runnerImageVersion",
        "runnerLabel",
        "members",
    ] {
        object.insert(
            field.to_owned(),
            manifest
                .get(field)
                .cloned()
                .ok_or_else(|| format!("attester-tools manifest omits {field}"))?,
        );
    }
    serde_json::from_value(verification).map_err(string_error)
}

fn attester_tools_identity_sha256(tools: &VerifiedAttesterToolsBinding) -> Result<String, String> {
    let identity = json!({
        "schema":"auths.qualification-attester-tools-identity/1",
        "repositoryId":tools.repository_id,
        "workflowPath":tools.workflow_path,
        "workflowRevision":tools.workflow_revision,
        "runId":tools.run_id,
        "runAttempt":tools.run_attempt,
        "retentionDays":tools.retention_days,
        "artifactId":tools.artifact_id,
        "artifactName":tools.artifact_name,
        "uploadedArchiveSha256":tools.uploaded_archive_sha256,
        "uploadedArchiveBytes":tools.uploaded_archive_bytes,
        "createdAtUnixSeconds":tools.created_at_unix_seconds,
        "expiresAtUnixSeconds":tools.expires_at_unix_seconds,
        "manifestSha256":tools.manifest_sha256,
        "attesterRevision":tools.attester_revision,
        "ghVersion":tools.gh_version,
        "runnerImageOs":tools.runner_image_os,
        "runnerImageVersion":tools.runner_image_version,
        "runnerLabel":tools.runner_label,
        "members":tools.members,
    });
    Ok(hex::encode(Sha256::digest(
        serde_json_canonicalizer::to_vec(&identity).map_err(string_error)?,
    )))
}

fn verify_retained_evidence_ledgers(
    repository: &Path,
    evidence: &crate::profile_qualification_evidence::VerifiedEvidence,
    observation: &QualificationObservationRecord,
    attester_tools: &VerifiedAttesterToolsBinding,
    expected_qualification_agent_sha256: Option<&str>,
) -> Result<BTreeMap<String, RetainedReceiptVerification>, String> {
    let tool_digest = |path: &str| {
        attester_tools
            .members
            .iter()
            .find(|member| member.path == path)
            .map(|member| member.sha256.as_str())
            .ok_or_else(|| format!("protected attester tool is absent: {path}"))
    };
    let controller_sha256 = tool_digest("qualification-crash-controller")?;
    let supervisor_sha256 = tool_digest("qualification-source-supervisor")?;
    let ledger_appender_sha256 = tool_digest("auths-qualification-supervisor")?;
    let journal_reader_sha256 = tool_digest("qualification-source-journal-reader")?;
    let launcher_sha256 = tool_digest("qualification-agent-launcher")?;
    let supervisor_source_uid = required_u32_env("AUTHS_QUALIFICATION_SUPERVISOR_SOURCE_UID")?;
    let journal_reader_uid = required_u32_env("AUTHS_QUALIFICATION_JOURNAL_READER_UID")?;
    let agent_uid = required_u32_env("AUTHS_QUALIFICATION_AGENT_UID")?;
    let agent_gid = required_u32_env("AUTHS_QUALIFICATION_AGENT_GID")?;
    let recovery_key_id = required_env("AUTHS_QUALIFICATION_RECOVERY_KEY_ID")?;
    let recovery_public_key_base64url =
        required_env("AUTHS_QUALIFICATION_RECOVERY_PUBLIC_KEY_BASE64URL")?;
    require_exact_ledger_roots(
        evidence,
        observation.provider_runs().iter().map(|run| run.id()),
    )?;
    let actual_common_phase_paths = evidence
        .member_names()
        .filter(|path| path.starts_with("common-phases/"))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let mut expected_common_phase_paths = BTreeSet::new();
    let protected_source_trust =
        read_bounded(&repository.join(EVIDENCE_SOURCE_TRUST_PATH), 262_144)?;
    let protected_ledger_trust =
        read_bounded(&repository.join(EVIDENCE_LEDGER_TRUST_PATH), 262_144)?;
    if hex::encode(Sha256::digest(&protected_source_trust))
        != required_sha256_env("AUTHS_QUALIFICATION_EVIDENCE_SOURCE_TRUST_SHA256")?
        || hex::encode(Sha256::digest(&protected_ledger_trust))
            != required_sha256_env("AUTHS_QUALIFICATION_EVIDENCE_LEDGER_TRUST_SHA256")?
    {
        return Err("protected evidence trust registry differs from policy".into());
    }
    let protected_attester_revision = git_revision(repository)?;
    let protected_environment = required_env("QUALIFICATION_PROTECTED_ENVIRONMENT")?;
    let now = now_unix_seconds()?;
    let mut receipt_verifications = BTreeMap::new();
    for reference in observation.ledgers() {
        let root = format!("ledger/{}/", reference.provider_run_id());
        let source_path = format!("{root}evidence-source-trust.json");
        let ledger_trust_path = format!("{root}evidence-ledger-trust.json");
        let ledger_path = format!("{root}ledger.json");
        let source_bytes = evidence.read_member(&source_path, 262_144)?;
        let ledger_trust_bytes = evidence.read_member(&ledger_trust_path, 262_144)?;
        let ledger_bytes = evidence.read_member(&ledger_path, 16_777_216)?;
        if source_bytes != protected_source_trust
            || ledger_trust_bytes != protected_ledger_trust
            || hex::encode(Sha256::digest(&source_bytes)) != reference.source_trust_sha256()
            || hex::encode(Sha256::digest(&ledger_trust_bytes)) != reference.ledger_trust_sha256()
            || hex::encode(Sha256::digest(&ledger_bytes)) != reference.ledger_sha256()
        {
            return Err("retained qualification ledger trust or byte commitment differs".into());
        }
        let source_trust = QualificationEvidenceSourceTrustRegistry::from_json(&source_bytes)
            .map_err(string_error)?;
        let ledger_trust = QualificationEvidenceLedgerTrustRegistry::from_json(&ledger_trust_bytes)
            .map_err(string_error)?;
        let ledger = QualificationEvidenceLedger::verify_json(
            &ledger_bytes,
            &source_trust,
            &ledger_trust,
            now,
        )
        .map_err(string_error)?;
        if ledger.record().supervisor_controller_artifact_sha256 != controller_sha256
            || ledger.record().ledger_appender_artifact_sha256 != ledger_appender_sha256
            || source_trust.uses_process_uid(ledger.record().supervisor_controller_uid)
            || ledger.record().supervisor_controller_uid == agent_uid
            || ledger.record().agent_uid != agent_uid
            || ledger.record().agent_gid != agent_gid
            || ledger.record().recovery_key_id != recovery_key_id
            || ledger.record().recovery_public_key_base64url != recovery_public_key_base64url
            || source_trust.uses_process_uid(ledger.record().agent_uid)
            || expected_qualification_agent_sha256
                != Some(ledger.record().agent_executable_sha256.as_str())
        {
            return Err(
                "retained controller or exercised-agent identity differs from protected policy"
                    .into(),
            );
        }
        let source_plan = ledger.record().source_plan();
        for event in &ledger.record().events {
            let protected_member = match event.source {
                auths_profile_kit::QualificationEvidenceSource::Supervisor => {
                    "qualification-source-supervisor"
                }
                auths_profile_kit::QualificationEvidenceSource::ClientProxy => {
                    "qualification-source-client-proxy"
                }
                auths_profile_kit::QualificationEvidenceSource::JournalReader => {
                    "qualification-source-journal-reader"
                }
                auths_profile_kit::QualificationEvidenceSource::CredentialBroker => {
                    "qualification-source-credential-broker"
                }
                auths_profile_kit::QualificationEvidenceSource::ProfileStateReader => {
                    "qualification-source-profile-state-reader"
                }
                auths_profile_kit::QualificationEvidenceSource::ProviderProxy => {
                    "qualification-source-provider-proxy"
                }
                auths_profile_kit::QualificationEvidenceSource::ReceiptVerifier => {
                    "qualification-source-receipt-verifier"
                }
                auths_profile_kit::QualificationEvidenceSource::ProviderObserver => {
                    "qualification-source-provider-observer"
                }
            };
            let protected_digest = tool_digest(protected_member)?;
            if event.source_artifact_sha256 != protected_digest
                || (matches!(
                    event.source,
                    QualificationEvidenceSource::ClientProxy
                        | QualificationEvidenceSource::CredentialBroker
                        | QualificationEvidenceSource::ProfileStateReader
                        | QualificationEvidenceSource::ProviderProxy
                        | QualificationEvidenceSource::ReceiptVerifier
                        | QualificationEvidenceSource::ProviderObserver
                ) && event.reader_artifact_sha256.as_deref() != Some(protected_digest))
            {
                return Err(format!(
                    "retained source event was not signed and read by protected member: {protected_member}"
                ));
            }
            use auths_profile_kit::QualificationEvidenceEventKind as Kind;
            use auths_profile_kit::QualificationEvidenceEventPayload as Payload;
            if matches!(event.kind, Kind::ScenarioStarted | Kind::ScenarioCompleted) {
                let phase = source_plan
                    .phases
                    .iter()
                    .find(|phase| {
                        phase.scenario_id == event.scenario_id
                            && phase.phase_index == event.phase_index
                            && phase.role == event.role
                            && phase.profile == event.profile
                            && phase.failpoint == event.failpoint
                    })
                    .ok_or_else(|| {
                        "Supervisor phase event is absent from the immutable ledger plan".to_owned()
                    })?;
                let expected = auths_profile_kit::qualification_supervisor_phase_context_sha256(
                    &phase,
                    controller_sha256,
                )
                .map_err(string_error)?;
                if event.source != QualificationEvidenceSource::Supervisor
                    || event.source_uid != Some(supervisor_source_uid)
                    || event.durable_ack_sha256
                        != auths_profile_kit::qualification_event_marker_sha256(
                            event.sequence,
                            event.source,
                        )
                    || !matches!(
                        &event.payload,
                        Payload::Control { context_sha256 } if context_sha256 == &expected
                    )
                {
                    return Err(
                        "Supervisor phase event differs from its protected plan and controller"
                            .into(),
                    );
                }
            }
        }
        let agent_trust = ledger
            .record()
            .agent_trust()
            .ok_or_else(|| "retained ledger omits the exercised agent trust identity".to_owned())?;
        if ledger.key_id() != reference.sealer_key_id()
            || ledger.record().provider_run_id() != reference.provider_run_id()
            || ledger.record().domain() != observation.domain()
            || ledger.record().target() != observation.target()
            || ledger.record().candidate_revision != observation.candidate_revision()
            || ledger.record().repository_id != observation.repository_id()
            || ledger.record().run_id != observation.run_id()
            || ledger.record().run_attempt() != observation.run_attempt()
            || ledger.record().workflow_path() != observation.workflow_path()
            || ledger.record().workflow_revision() != observation.workflow_revision()
            || ledger.record().attester_revision() != protected_attester_revision
            || ledger.record().protected_environment() != protected_environment
            || ledger.record().started_at_unix_seconds() < observation.started_at_unix_seconds()
            || ledger.record().completed_at_unix_seconds() > observation.completed_at_unix_seconds()
            || agent_trust.recovery_key_id() != observation.recovery_key_id()
            || agent_trust.recovery_public_key_base64url()
                != observation.recovery_public_key_base64url()
            || agent_trust.receipt_trust_anchor_sha256()
                != observation.receipt_trust_anchor_sha256()
        {
            return Err("retained qualification ledger context differs from observation".into());
        }
        for phase in ledger.record().phases() {
            let path = format!(
                "common-phases/{}/{}/{}.json",
                reference.provider_run_id(),
                phase.scenario_id,
                phase.phase_index
            );
            if !expected_common_phase_paths.insert(path.clone()) {
                return Err("retained common phase is duplicated".into());
            }
            let bytes = evidence.read_member(&path, 1_048_576)?;
            let common: QualificationCommonPhaseEvidence =
                serde_json::from_slice(&bytes).map_err(string_error)?;
            if serde_json_canonicalizer::to_vec(&common).map_err(string_error)? != bytes
                || hex::encode(Sha256::digest(&bytes)) != phase.common_phase_evidence_sha256
                || !auths_profile_kit::qualification_common_phase_matches_ledger(
                    ledger.record(),
                    phase,
                    &common,
                )
                .map_err(string_error)?
            {
                return Err(
                    "retained common phase differs from its authenticated source events".into(),
                );
            }
        }
        let expected_records = ledger
            .record()
            .events
            .iter()
            .map(|event| {
                let source = evidence_source_path(event.source);
                let path = format!("{root}source-records/{}/{}.json", source, event.sequence);
                let bytes = serde_json_canonicalizer::to_vec(event).map_err(string_error)?;
                Ok((path, bytes))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        let actual_records = evidence
            .member_names()
            .filter(|path| path.starts_with(&format!("{root}source-records/")))
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        if actual_records != expected_records.keys().cloned().collect::<BTreeSet<_>>() {
            return Err("retained source-record set differs from the signed ledger".into());
        }
        for (path, expected) in expected_records {
            if evidence.read_member(&path, 65_536)? != expected {
                return Err("retained source record differs from its signed ledger event".into());
            }
        }
        let mut expected_contexts = BTreeSet::new();
        let mut expected_snapshots = BTreeSet::new();
        let mut expected_acks = BTreeSet::new();
        let mut decision_contexts = BTreeMap::new();
        for event in &ledger.record().events {
            let auths_profile_kit::QualificationEvidenceEventPayload::Decision {
                supervisor_context_sha256,
                ..
            } = &event.payload
            else {
                continue;
            };
            let operation = event
                .operation_id
                .as_deref()
                .ok_or_else(|| "durable decision event omits its operation ID".to_owned())?;
            let context_path = format!("{root}supervisor-contexts/{operation}.json");
            let snapshot_path = format!("{root}decision-snapshots/{operation}.json");
            let ack_path = format!("{root}durable-acks/{operation}.json");
            if !expected_contexts.insert(context_path.clone())
                || !expected_snapshots.insert(snapshot_path.clone())
            {
                return Err("durable decision evidence is duplicated".into());
            }
            let context_bytes = evidence.read_member(&context_path, 65_536)?;
            if hex::encode(Sha256::digest(&context_bytes)) != *supervisor_context_sha256 {
                return Err("retained supervisor context differs from the decision event".into());
            }
            let context = QualificationJournalDecisionContext::verify_json(
                &context_bytes,
                &source_trust,
                ledger.record().started_at_unix_seconds(),
                ledger.record().completed_at_unix_seconds(),
                now,
            )
            .map_err(string_error)?;
            let context = context.record();
            let snapshot_bytes = evidence.read_member(&snapshot_path, 65_536)?;
            let snapshot = QualificationDecisionSnapshotV1::from_json(&snapshot_bytes)
                .map_err(string_error)?;
            if !expected_acks.insert(ack_path.clone()) {
                return Err("durable decision acknowledgement is duplicated".into());
            }
            let ack_bytes = evidence.read_member(&ack_path, 4_096)?;
            let ack =
                QualificationDurableDecisionAckV1::from_json(&ack_bytes).map_err(string_error)?;
            let phase = ledger
                .record()
                .phase_commitments
                .iter()
                .find(|phase| {
                    phase.scenario_id == event.scenario_id
                        && phase.phase_index == event.phase_index
                        && phase.role == event.role
                })
                .ok_or_else(|| {
                    "retained durable decision has no exact signed phase commitment".to_owned()
                })?;
            if hex::encode(Sha256::digest(&snapshot_bytes)) != context.decision_snapshot_sha256
                || hex::encode(Sha256::digest(&ack_bytes)) != context.durable_ack_sha256
                || snapshot.operation_id != operation
                || ack.operation_id != operation
                || snapshot.profile != event.profile
                || Some(snapshot.connection_generation.as_str())
                    != event.connection_generation.as_deref()
                || snapshot.decision_payload(supervisor_context_sha256.clone()) != event.payload
                || context.repository_id != ledger.record().repository_id()
                || context.workflow_path != ledger.record().workflow_path()
                || context.workflow_revision != ledger.record().workflow_revision()
                || context.candidate_revision != ledger.record().candidate_revision()
                || context.attester_revision != ledger.record().attester_revision()
                || context.run_id != ledger.record().run_id()
                || context.run_attempt != ledger.record().run_attempt()
                || context.domain != ledger.record().domain()
                || context.target != ledger.record().target()
                || context.protected_environment != ledger.record().protected_environment()
                || context.provider_run_id != ledger.record().provider_run_id()
                || context.ledger_id != ledger.record().ledger_id()
                || context.session_nonce_sha256 != ledger.record().session_nonce_sha256()
                || context.supervisor_controller_uid != ledger.record().supervisor_controller_uid
                || context.scenario_id != event.scenario_id
                || context.phase_index != event.phase_index
                || context.role != event.role
                || context.profile != event.profile
                || context.profile != phase.profile
                || context.operation_plan_sha256 != phase.operation_plan_sha256
                || context.failpoint != event.failpoint
                || context.supervisor_source_artifact_sha256 != supervisor_sha256
                || context.supervisor_controller_artifact_sha256 != controller_sha256
                || context.agent_launcher_artifact_sha256 != launcher_sha256
                || context.supervisor_source_uid != supervisor_source_uid
                || context.journal_reader_uid != journal_reader_uid
                || context.agent_uid != agent_uid
                || context.agent_gid != agent_gid
                || context.journal_owner_uid != agent_uid
                || context.journal_reader_source_identity != event.source_identity
                || context.journal_reader_source_artifact_sha256 != event.source_artifact_sha256
                || context.journal_reader_source_artifact_sha256 != journal_reader_sha256
                || context.journal_reader_key_id != event.source_key_id
                || context.source_context_sha256 != event.source_context_sha256
                || context.supervisor_generation != event.supervisor_generation
                || Some(context.agent_generation) != event.agent_generation
                || Some(context.agent_process_id) != event.agent_process_id
                || Some(context.agent_boot_sha256.as_str()) != event.agent_boot_sha256.as_deref()
                || expected_qualification_agent_sha256
                    .is_some_and(|expected| context.agent_executable_sha256 != expected)
                || context.operation_id != operation
                || context.journal_revision != snapshot.journal_revision
                || ack.journal_revision != context.journal_revision
                || ack.journal_record_sha256 != context.journal_record_sha256
                || ack.agent_generation != context.agent_generation
                || ack.control_operation_id.as_deref() != context.control_operation_id.as_deref()
                || ack.controller_nonce_sha256.as_deref()
                    != context.controller_nonce_sha256.as_deref()
                || event.journal_revision != Some(snapshot.journal_revision)
            {
                return Err(
                    "retained supervisor context or decision snapshot differs from the ledger"
                        .into(),
                );
            }
            decision_contexts.insert(operation.to_owned(), context.clone());
        }
        let mut expected_crash_action_contexts = BTreeSet::new();
        let mut crash_initial_processes = BTreeMap::new();
        for event in &ledger.record().events {
            use auths_profile_kit::QualificationEvidenceEventKind as Kind;
            use auths_profile_kit::QualificationEvidenceEventPayload as Payload;
            let (action, action_context_sha256) = match (&event.kind, &event.payload) {
                (
                    Kind::FailpointAcknowledged,
                    Payload::FailpointAcknowledgement {
                        action_context_sha256,
                        ..
                    },
                ) => ("failpoint-acknowledged.json", action_context_sha256),
                (
                    Kind::ProcessKilled,
                    Payload::ProcessKill {
                        action_context_sha256,
                        ..
                    },
                ) => ("process-killed.json", action_context_sha256),
                (
                    Kind::ProcessRestarted,
                    Payload::ProcessRestart {
                        action_context_sha256,
                        ..
                    },
                ) => ("process-restarted.json", action_context_sha256),
                (Kind::FailpointAcknowledged | Kind::ProcessKilled | Kind::ProcessRestarted, _) => {
                    return Err("crash action event has the wrong typed payload".into());
                }
                _ => continue,
            };
            let failpoint = event
                .failpoint
                .ok_or_else(|| "crash action event omits its failpoint".to_owned())?;
            let before_decision =
                failpoint == auths_profile_kit::QualificationFailpoint::BeforeDecision;
            let action_key = if before_decision {
                if event.operation_id.is_some() || event.connection_generation.is_some() {
                    return Err(
                        "before-decision crash action exposes an operation projection".into(),
                    );
                }
                event.control_operation_id.as_deref().ok_or_else(|| {
                    "before-decision crash action omits its control operation ID".to_owned()
                })?
            } else {
                event
                    .operation_id
                    .as_deref()
                    .ok_or_else(|| "post-decision crash action omits its operation ID".to_owned())?
            };
            let decision_context = if before_decision {
                None
            } else {
                Some(decision_contexts.get(action_key).ok_or_else(|| {
                    "post-decision crash action has no retained durable-decision context".to_owned()
                })?)
            };
            let action_path = format!("{root}crash-action-contexts/{action_key}/{action}");
            if !expected_crash_action_contexts.insert(action_path.clone()) {
                return Err("crash action context is duplicated".into());
            }
            let action_bytes = evidence.read_member(&action_path, 65_536)?;
            if hex::encode(Sha256::digest(&action_bytes)) != *action_context_sha256 {
                return Err("retained crash action context differs from its event".into());
            }
            let action_context = QualificationCrashActionContextV1::verify_json(
                &action_bytes,
                &source_trust,
                ledger.record().started_at_unix_seconds(),
                ledger.record().completed_at_unix_seconds(),
                now,
            )
            .map_err(string_error)?;
            let action_record = action_context.record();
            let action_process = action_record.event_process();
            let decision_process_matches =
                |process: &auths_profile_kit::QualificationCrashProcessIdentityV1| {
                    decision_context.is_some_and(|decision_context| {
                        process.agent_generation == decision_context.agent_generation
                            && process.agent_process_id == decision_context.agent_process_id
                            && process.agent_boot_sha256 == decision_context.agent_boot_sha256
                            && process.agent_start_time_ticks
                                == decision_context.agent_start_time_ticks
                            && process.agent_launcher_artifact_sha256
                                == decision_context.agent_launcher_artifact_sha256
                            && process.agent_executable_sha256
                                == decision_context.agent_executable_sha256
                            && process.agent_configuration_sha256
                                == decision_context.agent_configuration_sha256
                            && process.agent_state_directory_sha256
                                == decision_context.agent_state_directory_sha256
                            && process.agent_cgroup_sha256 == decision_context.agent_cgroup_sha256
                    })
                };
            let killed_process = match &action_record.facts {
                auths_profile_kit::QualificationCrashActionFactsV1::FailpointAcknowledged {
                    process,
                    ..
                }
                | auths_profile_kit::QualificationCrashActionFactsV1::ProcessKilled {
                    process,
                    ..
                } => process,
                auths_profile_kit::QualificationCrashActionFactsV1::ProcessRestarted {
                    killed_process,
                    ..
                } => killed_process,
            };
            let killed_process_matches = if before_decision {
                match event.kind {
                    Kind::FailpointAcknowledged => crash_initial_processes
                        .insert(action_key.to_owned(), killed_process.clone())
                        .is_none(),
                    Kind::ProcessKilled | Kind::ProcessRestarted => crash_initial_processes
                        .get(action_key)
                        .is_some_and(|expected| expected == killed_process),
                    _ => false,
                }
            } else {
                decision_process_matches(killed_process)
            };
            if action_record.event_kind() != event.kind
                || action_record.event_payload(action_context_sha256.clone()) != event.payload
                || action_record.sequence != event.sequence
                || action_record.previous_event_sha256 != event.previous_event_sha256
                || action_record.profile != event.profile
                || action_record.operation_id.as_deref() != (!before_decision).then_some(action_key)
                || action_record.connection_generation.as_deref()
                    != event.connection_generation.as_deref()
                || action_record.supervisor_controller_uid
                    != ledger.record().supervisor_controller_uid
                || action_record.supervisor_source_artifact_sha256 != supervisor_sha256
                || action_record.supervisor_source_artifact_sha256 != event.source_artifact_sha256
                || action_record.supervisor_controller_artifact_sha256 != controller_sha256
                || action_record.supervisor_controller_artifact_sha256
                    != ledger.record().supervisor_controller_artifact_sha256
                || !action_record
                    .crash_context
                    .binds_ledger_plan(&source_plan)
                    .map_err(string_error)?
                || decision_context
                    .is_some_and(|context| !action_record.crash_context.binds_context(context))
                || action_context.key_id() != event.source_key_id
                || action_record.crash_context.supervisor_source_identity != event.source_identity
                || action_record.crash_context.source_context_sha256 != event.source_context_sha256
                || action_record.crash_context.supervisor_generation != event.supervisor_generation
                || event.source != QualificationEvidenceSource::Supervisor
                || action_record.crash_context.phase.failpoint != Some(failpoint)
                || event.control_operation_id.as_deref()
                    != Some(action_record.crash_context.control_operation_id.as_str())
                || (before_decision && action_record.durable_ack_sha256.is_some())
                || Some(action_process.agent_generation) != event.agent_generation
                || Some(action_process.agent_process_id) != event.agent_process_id
                || Some(action_process.agent_boot_sha256.as_str())
                    != event.agent_boot_sha256.as_deref()
                || !killed_process_matches
            {
                return Err("retained crash action context differs from the ledger".into());
            }
        }
        let actual_contexts = evidence
            .member_names()
            .filter(|path| path.starts_with(&format!("{root}supervisor-contexts/")))
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let actual_snapshots = evidence
            .member_names()
            .filter(|path| path.starts_with(&format!("{root}decision-snapshots/")))
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let actual_acks = evidence
            .member_names()
            .filter(|path| path.starts_with(&format!("{root}durable-acks/")))
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let actual_crash_action_contexts = evidence
            .member_names()
            .filter(|path| path.starts_with(&format!("{root}crash-action-contexts/")))
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        if actual_contexts != expected_contexts
            || actual_snapshots != expected_snapshots
            || actual_acks != expected_acks
            || actual_crash_action_contexts != expected_crash_action_contexts
        {
            return Err(
                "retained supervisor-context, decision-snapshot, durable-ack, or crash-action roster differs from the ledger"
                    .into(),
            );
        }
        for event in &ledger.record().events {
            if event.kind
                != auths_profile_kit::QualificationEvidenceEventKind::NativeReceiptVerified
            {
                continue;
            }
            let operation_id = event.operation_id.clone().ok_or_else(|| {
                "native receipt verification event omits its operation ID".to_owned()
            })?;
            let receipt_id = event.receipt_id.clone().ok_or_else(|| {
                "native receipt verification event omits its receipt ID".to_owned()
            })?;
            let auths_profile_kit::QualificationEvidenceEventPayload::ReceiptVerification {
                receipt_bytes_sha256,
                decoded_claims_sha256,
                profile_inspection_sha256,
            } = &event.payload
            else {
                return Err("native receipt verification event has the wrong payload".into());
            };
            if receipt_verifications
                .insert(
                    receipt_id,
                    RetainedReceiptVerification {
                        operation_id,
                        receipt_bytes_sha256: receipt_bytes_sha256.clone(),
                        decoded_claims_sha256: decoded_claims_sha256.clone(),
                        profile_inspection_sha256: profile_inspection_sha256.clone(),
                    },
                )
                .is_some()
            {
                return Err(
                    "native receipt verification event is duplicated across ledgers".into(),
                );
            }
        }
    }
    if actual_common_phase_paths != expected_common_phase_paths {
        return Err("retained common-phase roster differs from the signed ledgers".into());
    }
    Ok(receipt_verifications)
}

fn require_exact_ledger_roots<'a>(
    evidence: &crate::profile_qualification_evidence::VerifiedEvidence,
    expected: impl Iterator<Item = &'a str>,
) -> Result<(), String> {
    let actual = evidence
        .member_names()
        .filter_map(|path| {
            path.strip_prefix("ledger/")
                .and_then(|tail| tail.split_once('/'))
                .map(|(provider_run_id, _)| provider_run_id.to_owned())
        })
        .collect::<BTreeSet<_>>();
    let expected = expected.map(str::to_owned).collect::<BTreeSet<_>>();
    if actual != expected {
        return Err("retained ledger roots do not exactly match the provider-run roster".into());
    }
    Ok(())
}

const fn evidence_source_path(source: QualificationEvidenceSource) -> &'static str {
    match source {
        QualificationEvidenceSource::Supervisor => "supervisor",
        QualificationEvidenceSource::ClientProxy => "client-proxy",
        QualificationEvidenceSource::JournalReader => "journal-reader",
        QualificationEvidenceSource::CredentialBroker => "credential-broker",
        QualificationEvidenceSource::ProfileStateReader => "profile-state-reader",
        QualificationEvidenceSource::ProviderProxy => "provider-proxy",
        QualificationEvidenceSource::ReceiptVerifier => "receipt-verifier",
        QualificationEvidenceSource::ProviderObserver => "provider-observer",
    }
}

fn member_sha256(
    evidence: &crate::profile_qualification_evidence::VerifiedEvidence,
    path: &str,
) -> Result<String, String> {
    Ok(hex::encode(Sha256::digest(
        evidence.read_member(path, 16_777_216)?,
    )))
}

fn validate_observed_provider_runs(
    matrix: &QualificationProviderMatrix,
    observed: &[auths_profile_kit::QualificationProviderRun],
) -> Result<(), String> {
    if matrix.runs.len() != observed.len() {
        return Err("protected provider runs do not exactly cover the provider matrix".into());
    }
    for (expected, actual) in matrix.runs.iter().zip(observed) {
        if actual.id() != expected.id
            || actual.provider_version() != expected.provider_version
            || actual.provider_artifact_sha256() != expected.provider_artifact_sha256
        {
            return Err(format!(
                "protected provider run does not satisfy matrix row {}",
                expected.id
            ));
        }
    }
    Ok(())
}

fn expected_report_binding_at(
    repository: &Path,
    context: &DomainContext,
    observation: &QualificationObservationRecord,
    matrix: &QualificationProviderMatrix,
    revision: &str,
) -> Result<crate::profile_qualification_reports::ExpectedReportBinding, String> {
    let scenario_ids = scenario_roster_at(repository, context, revision)?;
    expected_report_binding_with_scenarios(context, observation, matrix, scenario_ids)
}

fn expected_report_binding_with_scenarios(
    context: &DomainContext,
    observation: &QualificationObservationRecord,
    matrix: &QualificationProviderMatrix,
    scenario_ids: Vec<String>,
) -> Result<crate::profile_qualification_reports::ExpectedReportBinding, String> {
    let profiles = observation
        .profiles()
        .iter()
        .map(auths_profile_kit::QualificationProfile::semantic_subject)
        .collect::<Vec<_>>();
    let expected_profiles = context.package.qualification().family();
    if profiles
        .iter()
        .map(String::as_str)
        .ne(expected_profiles.iter().map(String::as_str))
    {
        return Err("protected observation profile family differs from the manifest".into());
    }
    let mut scenario_applicability = scenario_ids
        .iter()
        .map(|scenario| (scenario.clone(), Vec::new()))
        .collect::<BTreeMap<_, _>>();
    for run in &matrix.runs {
        for scenario in &run.scenario_ids {
            scenario_applicability
                .get_mut(scenario)
                .ok_or_else(|| "provider matrix names an unknown scenario".to_owned())?
                .push(run.id.clone());
        }
    }
    Ok(
        crate::profile_qualification_reports::ExpectedReportBinding {
            repository_id: observation.repository_id().to_owned(),
            workflow_run_id: observation.run_id().to_owned(),
            workflow_run_attempt: observation.run_attempt(),
            candidate_revision: observation.candidate_revision().to_owned(),
            domain: observation.domain().to_owned(),
            target: observation.target().as_str().to_owned(),
            profiles,
            provider_run_ids: matrix.runs.iter().map(|run| run.id.clone()).collect(),
            scenario_ids,
            failpoints: all_qualification_failpoints(),
            operation_ids: observation.operation_ids().to_vec(),
            connection_generations: observation.connection_generations().to_vec(),
            scenario_applicability,
        },
    )
}

fn all_qualification_failpoints() -> Vec<auths_profile_kit::QualificationFailpoint> {
    use auths_profile_kit::QualificationFailpoint;
    vec![
        QualificationFailpoint::AfterCommand,
        QualificationFailpoint::AfterDecision,
        QualificationFailpoint::AfterExecutionReceipt,
        QualificationFailpoint::AfterEntryMarker,
        QualificationFailpoint::AfterLease,
        QualificationFailpoint::AfterObservation,
        QualificationFailpoint::AfterProviderResult,
        QualificationFailpoint::AfterRequestWrite,
        QualificationFailpoint::AfterReread,
        QualificationFailpoint::AfterReservation,
        QualificationFailpoint::AfterTerminal,
        QualificationFailpoint::BeforeDecision,
    ]
}

fn validate_typed_report_set(
    evidence: &crate::profile_qualification_evidence::VerifiedEvidence,
    observation: &QualificationObservationRecord,
    expected: &crate::profile_qualification_reports::ExpectedReportBinding,
    operation_plans: &BTreeMap<String, Vec<QualificationPlannedOperation>>,
    failpoint_coverage: &QualificationFailpointCoverage,
) -> Result<(), String> {
    use crate::profile_qualification_reports::{
        CleanupReport, CountersReport, InstalledPackagesReport, ProvenanceReport,
        ProviderTruthReport, ScanReport, ScenarioReport, parse_canonical,
    };
    let cleanup: CleanupReport =
        parse_canonical(&evidence.read_member("reports/cleanup.json", 262_144)?)?;
    cleanup.validate(expected)?;
    let counters: CountersReport =
        parse_canonical(&evidence.read_member("reports/counters.json", 1_048_576)?)?;
    counters.validate(expected)?;
    let truth: ProviderTruthReport =
        parse_canonical(&evidence.read_member("reports/provider-truth.json", 16_777_216)?)?;
    truth.validate(expected, &expected.domain)?;
    let protected_provider_runs = observation
        .provider_runs()
        .iter()
        .map(|run| {
            (
                run.id(),
                (run.provider_version(), run.provider_artifact_sha256()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let truth_provider_runs = truth
        .operations
        .iter()
        .map(|operation| operation.provider_run_id.as_str())
        .collect::<BTreeSet<_>>();
    if truth_provider_runs.len() != protected_provider_runs.len()
        || truth_provider_runs
            .iter()
            .any(|run| !protected_provider_runs.contains_key(run))
        || truth.operations.iter().any(|operation| {
            protected_provider_runs
                .get(operation.provider_run_id.as_str())
                .is_none_or(|(version, artifact)| {
                    *version != operation.provider_version
                        || *artifact != operation.provider_artifact_sha256
                })
        })
    {
        return Err(
            "protected provider-truth identities differ from the signed provider-run roster".into(),
        );
    }
    let installed: InstalledPackagesReport =
        parse_canonical(&evidence.read_member("reports/installed-packages.json", 1_048_576)?)?;
    installed.validate(expected)?;
    let gitleaks: ScanReport =
        parse_canonical(&evidence.read_member("reports/gitleaks.json", 262_144)?)?;
    gitleaks.validate(expected, "gitleaks")?;
    let redaction: ScanReport =
        parse_canonical(&evidence.read_member("reports/redaction.json", 262_144)?)?;
    redaction.validate(expected, "redaction")?;
    let typed_forbidden: ScanReport =
        parse_canonical(&evidence.read_member("reports/typed-forbidden-fields.json", 262_144)?)?;
    typed_forbidden.validate(expected, "typed-forbidden-field")?;
    let provenance: ProvenanceReport =
        parse_canonical(&evidence.read_member("reports/provenance.json", 1_048_576)?)?;
    provenance.validate(expected)?;

    let call_counts = observation
        .external_provider_call_counts()
        .iter()
        .map(|count| (count.operation_id(), count.count()))
        .collect::<BTreeMap<_, _>>();
    let counter_map = counters
        .operations
        .iter()
        .map(|operation| (operation.operation_id.as_str(), &operation.counters))
        .collect::<BTreeMap<_, _>>();
    let truth_map = truth
        .operations
        .iter()
        .map(|operation| (operation.operation_id.as_str(), operation))
        .collect::<BTreeMap<_, _>>();
    if call_counts.len() != expected.operation_ids.len()
        || counter_map.len() != expected.operation_ids.len()
        || truth_map.len() != expected.operation_ids.len()
        || expected.operation_ids.iter().any(|operation| {
            let Some(counters) = counter_map.get(operation.as_str()) else {
                return true;
            };
            let Some(truth) = truth_map.get(operation.as_str()) else {
                return true;
            };
            call_counts.get(operation.as_str()).copied() != Some(truth.provider_calls)
                || counters.provider_calls != truth.provider_calls
        })
    {
        return Err("protected provider truth, journal counters, and call counts disagree".into());
    }

    let mut scenario_operations = BTreeSet::new();
    for scenario_id in &expected.scenario_ids {
        let path = format!("reports/scenarios/{scenario_id}.json");
        let report: ScenarioReport = parse_canonical(&evidence.read_member(&path, 1_048_576)?)?;
        report.validate(expected)?;
        let applicable = expected
            .scenario_applicability
            .get(scenario_id)
            .ok_or_else(|| "scenario has no checked provider-run applicability".to_owned())?;
        if report.scenario_id != *scenario_id
            || report
                .executions
                .iter()
                .map(|execution| execution.provider_run_id.as_str())
                .ne(applicable.iter().map(String::as_str))
        {
            return Err(format!(
                "scenario report is not bound to exact provider-run applicability: {scenario_id}"
            ));
        }
        let planned_operations = operation_plans
            .get(scenario_id)
            .ok_or_else(|| "scenario report has no immutable operation plan".to_owned())?;
        let crash_boundary = failpoint_coverage
            .boundaries
            .iter()
            .find(|boundary| boundary.crash_scenario_id == *scenario_id);
        for execution in &report.executions {
            if execution.operations.len() != planned_operations.len() {
                return Err(format!(
                    "scenario execution omits a reviewed family operation: {scenario_id}/{}",
                    execution.provider_run_id
                ));
            }
            for (operation, planned) in execution.operations.iter().zip(planned_operations) {
                if operation.role != planned.role || operation.profile != planned.profile {
                    return Err(format!(
                        "scenario operation differs from its immutable family plan: {scenario_id}/{}",
                        execution.provider_run_id
                    ));
                }
                let expected_operation_failpoint = planned
                    .lifecycle_owner
                    .then(|| expected_failpoint(scenario_id))
                    .flatten();
                for instance in &operation.instances {
                    let counters = counter_map
                        .get(instance.operation_id.as_str())
                        .ok_or_else(|| "scenario report names an unknown operation".to_owned())?;
                    let truth = truth_map
                        .get(instance.operation_id.as_str())
                        .ok_or_else(|| "scenario report names missing provider truth".to_owned())?;
                    if instance.failpoint != expected_operation_failpoint
                        || (!planned.provider_mutation_owner
                            && (instance.effect
                                != auths_profile_kit::QualificationEffect::NotApplied
                                || truth.provider_calls != 0))
                        || &instance.counters != *counters
                        || instance.effect != truth.effect
                        || instance.provider_truth_sha256 != truth.commitment_sha256
                        || !scenario_operations.insert(instance.operation_id.clone())
                    {
                        return Err(format!(
                            "scenario operation instance is not bound to exact counters, truth, failpoint, and provider run: {scenario_id}/{}",
                            execution.provider_run_id
                        ));
                    }
                    if counters.reservation_writes == 1 {
                        let completed = operation.attempts.iter().any(|attempt| {
                            attempt.operation_id.as_deref() == Some(instance.operation_id.as_str())
                                && attempt.outcome
                                    == auths_profile_kit::QualificationOutcomeKind::Completed
                        });
                        let disposition_matches = match instance.effect {
                            auths_profile_kit::QualificationEffect::Applied => {
                                counters.reservation_consumptions == 1
                            }
                            auths_profile_kit::QualificationEffect::Possible => {
                                counters.reservation_retentions == 1
                            }
                            auths_profile_kit::QualificationEffect::NotApplied
                                if !planned.provider_mutation_owner && completed =>
                            {
                                counters.reservation_consumptions == 1
                            }
                            auths_profile_kit::QualificationEffect::NotApplied => {
                                counters.reservation_releases == 1
                            }
                        };
                        if !disposition_matches {
                            return Err(format!(
                                "scenario reservation disposition differs from the reviewed operation role: {scenario_id}/{}",
                                execution.provider_run_id
                            ));
                        }
                    }
                    if planned.lifecycle_owner
                        && crash_boundary.is_some_and(|boundary| {
                            validate_failpoint_report_projection(boundary, operation, instance)
                                .is_err()
                        })
                    {
                        return Err(format!(
                            "scenario operation violates the reviewed crash-boundary contract: {scenario_id}/{}",
                            execution.provider_run_id
                        ));
                    }
                }
                if planned.lifecycle_owner {
                    if let Some(boundary) = crash_boundary {
                        if boundary.failpoint != "before-decision"
                            && operation
                                .attempts
                                .iter()
                                .any(|attempt| attempt.operation_id.is_none())
                        {
                            return Err(format!(
                                "post-decision crash attempt omits its durable operation ID: {scenario_id}/{}",
                                execution.provider_run_id
                            ));
                        }
                        let effects = operation
                            .instances
                            .iter()
                            .map(|instance| match instance.effect {
                                auths_profile_kit::QualificationEffect::Applied => "applied",
                                auths_profile_kit::QualificationEffect::NotApplied => "not-applied",
                                auths_profile_kit::QualificationEffect::Possible => "possible",
                            })
                            .collect::<BTreeSet<_>>();
                        if operation.instances.len() != boundary.applicable_effects.len()
                            || effects
                                != boundary
                                    .applicable_effects
                                    .iter()
                                    .map(String::as_str)
                                    .collect()
                        {
                            return Err(format!(
                                "scenario operation does not cover the exact crash-boundary effect set: {scenario_id}/{}",
                                execution.provider_run_id
                            ));
                        }
                    }
                }
            }
        }
    }
    if scenario_operations != expected.operation_ids.iter().cloned().collect() {
        return Err("scenario reports and operation IDs are not a bijection".into());
    }
    Ok(())
}

fn validate_failpoint_report_projection(
    boundary: &QualificationFailpointBoundary,
    operation: &crate::profile_qualification_reports::ScenarioOperation,
    instance: &crate::profile_qualification_reports::ScenarioOperationInstance,
) -> Result<(), String> {
    use auths_profile_kit::{
        QualificationAttemptKind as Attempt, QualificationCompletion as Completion,
        QualificationEffect as Effect, QualificationOutcomeKind as Outcome,
    };
    let effect = match instance.effect {
        Effect::Applied => "applied",
        Effect::NotApplied => "not-applied",
        Effect::Possible => "possible",
    };
    if boundary
        .applicable_effects
        .binary_search_by(|candidate| candidate.as_str().cmp(effect))
        .is_err()
    {
        return Err("terminal effect is not applicable to this crash boundary".into());
    }
    let instance_attempts = operation
        .attempts
        .iter()
        .filter(|attempt| attempt.operation_id.as_deref() == Some(instance.operation_id.as_str()))
        .collect::<Vec<_>>();
    let counters = &instance.counters;
    for assertion in &boundary.counter_assertions {
        let valid = match assertion.as_str() {
            "connection-reread-once" => counters.connection_rereads == 1,
            "credential-lease-closed" => {
                counters.credential_lease_closes == counters.credential_leases
            }
            "credential-lease-once" => {
                counters.credential_lease_attempts == 1 && counters.credential_leases == 1
            }
            "decision-receipt-durable" => counters.receipt_writes >= 1,
            "execution-receipt-durable" => counters.receipt_writes == 2,
            "no-provider-call" => {
                counters.provider_calls == 0 && counters.provider_request_writes == 0
            }
            "no-second-provider-call" => {
                counters.provider_calls == 1 && counters.provider_request_writes == 1
            }
            "observation-durable" => counters.observations >= 1,
            "provider-entry-once" => counters.provider_entry_markers == 1,
            "provider-request-write-once" => counters.provider_request_writes == 1,
            "provider-result-durable" => counters.durable_provider_results == 1,
            "receipt-not-reminted" => counters.receipt_writes == 2,
            "reservation-released-after-recovery" => {
                counters.reservation_writes == 1 && counters.reservation_releases == 1
            }
            "reservation-written" => counters.reservation_writes == 1,
            "sealed-command-durable" => instance.sealed_command_sha256.is_some(),
            "stable-operation-id" => !instance_attempts.is_empty(),
            "terminal-durable" => instance_attempts.last().is_some_and(|attempt| {
                matches!(
                    attempt.outcome,
                    Outcome::Completed | Outcome::Denied | Outcome::NotApplied | Outcome::Partial
                )
            }),
            _ => false,
        };
        if !valid {
            return Err(format!("counter assertion is false: {assertion}"));
        }
    }
    let recovery_call_present = match boundary.recovery_call.as_str() {
        // One logical installed-SDK invocation may span the original execute,
        // transport loss, status, and recovery exchanges. ClientProxy signs
        // that exact internal projection vector, so the candidate-facing
        // attempt remains Execute while its durable terminal completion proves
        // which recovery path converged.
        "recover" => instance_attempts
            .iter()
            .any(|attempt| attempt.completion == Some(Completion::Reconciled)),
        "status" => instance_attempts.iter().any(|attempt| {
            matches!(attempt.kind, Attempt::Execute | Attempt::Status)
                && attempt.completion == Some(Completion::Replayed)
        }),
        "retry-original" => operation.attempts.iter().any(|attempt| {
            attempt.kind == Attempt::Execute
                && attempt.operation_id.as_deref() == Some(instance.operation_id.as_str())
        }),
        _ => false,
    };
    if !recovery_call_present {
        return Err("reviewed crash recovery call is absent from the attempt transcript".into());
    }
    Ok(())
}

fn validate_observation_report_commitments(
    evidence: &crate::profile_qualification_evidence::VerifiedEvidence,
    observation: &QualificationObservationRecord,
) -> Result<(), String> {
    for (path, expected) in [
        (
            "reports/provider-truth.json",
            observation.provider_truth_sha256(),
        ),
        ("reports/counters.json", observation.counter_report_sha256()),
        ("reports/cleanup.json", observation.cleanup_report_sha256()),
    ] {
        if member_sha256(evidence, path)? != expected {
            return Err(format!("protected observation digest differs from {path}"));
        }
    }
    let actual = evidence
        .member_names()
        .filter(|path| {
            path.starts_with("reports/") && *path != "reports/protected-observation.json"
        })
        .map(|path| {
            let id = path
                .strip_prefix("reports/")
                .and_then(|value| value.strip_suffix(".json"))
                .ok_or_else(|| "protected report path is malformed".to_owned())?
                .replace('/', ":");
            Ok((id, member_sha256(evidence, path)?))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    let expected = observation
        .observed_report_digests()
        .iter()
        .map(|digest| (digest.id().to_owned(), digest.sha256().to_owned()))
        .collect::<BTreeMap<_, _>>();
    if actual != expected {
        return Err("signed protected report digest roster is incomplete or mismatched".into());
    }
    Ok(())
}

fn scenario_projection_from_reports(
    evidence: &crate::profile_qualification_evidence::VerifiedEvidence,
    proposal_bytes: &[u8],
) -> Result<Vec<Value>, String> {
    let proposal: Value = serde_json::from_slice(proposal_bytes).map_err(string_error)?;
    let scenarios = proposal
        .get("scenarios")
        .and_then(Value::as_array)
        .ok_or_else(|| "qualification proposal scenarios are malformed".to_owned())?;
    let expected_paths = scenarios
        .iter()
        .map(|scenario| {
            scenario
                .get("id")
                .and_then(Value::as_str)
                .map(|id| format!("reports/scenarios/{id}.json"))
                .ok_or_else(|| "qualification proposal scenario ID is malformed".to_owned())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let actual_paths = evidence
        .member_names()
        .filter(|path| path.starts_with("reports/scenarios/"))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if actual_paths != expected_paths {
        return Err("scenario reports do not exactly cover the proposed scenario roster".into());
    }
    let mut projections = Vec::with_capacity(scenarios.len());
    for scenario in scenarios {
        let id = scenario["id"]
            .as_str()
            .ok_or_else(|| "qualification scenario ID is malformed".to_owned())?;
        let path = format!("reports/scenarios/{id}.json");
        let bytes = evidence.read_member(&path, 1_048_576)?;
        let report: crate::profile_qualification_reports::ScenarioReport =
            crate::profile_qualification_reports::parse_canonical(&bytes)?;
        let provider_run_ids = report.provider_run_ids();
        if report.scenario_id != id
            || json!(report.assertions) != scenario["assertions"]
            || json!(provider_run_ids) != scenario["providerRunIds"]
            || hex::encode(Sha256::digest(&bytes))
                != scenario["reportSha256"].as_str().unwrap_or("")
        {
            return Err(format!("scenario report does not match proposal: {id}"));
        }
        projections.push(json!({
            "id":id,
            "status":"passed",
            "assertions":report.assertions,
            "reportSha256":hex::encode(Sha256::digest(&bytes)),
            "providerRunIds":provider_run_ids,
        }));
    }
    projections.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    Ok(projections)
}

fn installed_toolchain_at(
    candidate_repository: &Path,
    candidate_revision: &str,
    evidence: &crate::profile_qualification_evidence::VerifiedEvidence,
    expected: &crate::profile_qualification_reports::ExpectedReportBinding,
) -> Result<Value, String> {
    let bytes = evidence.read_member("reports/installed-packages.json", 262_144)?;
    let report: crate::profile_qualification_reports::InstalledPackagesReport =
        crate::profile_qualification_reports::parse_canonical(&bytes)?;
    report.validate(expected)?;
    let pins_bytes = git_blob(
        candidate_repository,
        candidate_revision,
        "release/qualification/v1/toolchains.json",
        4_096,
    )?;
    installed_toolchain_from_pins(&pins_bytes, &report)
}

fn installed_toolchain_from_pins(
    pins_bytes: &[u8],
    report: &crate::profile_qualification_reports::InstalledPackagesReport,
) -> Result<Value, String> {
    let pins: QualificationToolchainPins =
        serde_json::from_slice(pins_bytes).map_err(string_error)?;
    if serde_json_canonicalizer::to_vec(&pins).map_err(string_error)? != pins_bytes
        || pins.schema != "auths.profile-qualification-toolchains/1"
        || report.toolchain.rust != pins.rust
        || report.toolchain.node != pins.node
        || report.toolchain.python != pins.python
    {
        return Err("installed-package toolchain differs from immutable qualification pins".into());
    }
    Ok(json!({"rust":pins.rust,"node":pins.node,"python":pins.python}))
}

fn receipt_verification_projection(
    evidence: &crate::profile_qualification_evidence::VerifiedEvidence,
    anchor_bytes: &[u8],
    anchor_sha256: &str,
    expected: &crate::profile_qualification_reports::ExpectedReportBinding,
    ledger_verifications: &BTreeMap<String, RetainedReceiptVerification>,
) -> Result<Value, String> {
    let mut expected_operations = None;
    let mut decision_methods = None;
    let mut execution_methods = None;
    for language in ["rust", "python", "typescript"] {
        let path = format!("reports/receipts-{language}.json");
        let bytes = evidence.read_member(&path, 262_144)?;
        let report: crate::profile_qualification_reports::ReceiptsReport =
            crate::profile_qualification_reports::parse_canonical(&bytes)?;
        report.validate(expected, language)?;
        let decision = report
            .operations
            .iter()
            .filter_map(|operation| operation.decision_verification_method.clone())
            .collect::<BTreeSet<_>>();
        let execution = report
            .operations
            .iter()
            .filter_map(|operation| operation.execution_verification_method.clone())
            .collect::<BTreeSet<_>>();
        if decision.len() > 1 || execution.len() > 1 {
            return Err("receipt report verification methods are inconsistent".into());
        }
        if expected_operations
            .as_ref()
            .is_some_and(|operations| operations != &report.operations)
            || decision_methods
                .as_ref()
                .is_some_and(|methods| methods != &decision)
            || execution_methods
                .as_ref()
                .is_some_and(|methods| methods != &execution)
        {
            return Err("Rust, Python, and TypeScript receipt reports disagree".into());
        }
        expected_operations = Some(report.operations);
        decision_methods = Some(decision);
        execution_methods = Some(execution);
    }
    let operations = expected_operations
        .ok_or_else(|| "receipt report operation projection is absent".to_owned())?;
    verify_retained_receipts(
        evidence,
        anchor_bytes,
        expected,
        &operations,
        ledger_verifications,
    )?;
    let decision_method = decision_methods
        .and_then(|methods| methods.into_iter().next())
        .ok_or_else(|| "decision verification method is absent".to_owned())?;
    let execution_method = execution_methods
        .and_then(|methods| methods.into_iter().next())
        .ok_or_else(|| "execution verification method is absent".to_owned())?;
    Ok(json!({
        "rust":"passed",
        "python":"passed",
        "typescript":"passed",
        "portableReceiptSchema":"auths.portable-receipt/1",
        "receiptTrustAnchorSha256":anchor_sha256,
        "decisionVerificationMethod":decision_method,
        "executionVerificationMethod":execution_method,
    }))
}

fn verify_retained_receipts(
    evidence: &crate::profile_qualification_evidence::VerifiedEvidence,
    anchor_bytes: &[u8],
    expected: &crate::profile_qualification_reports::ExpectedReportBinding,
    operations: &[crate::profile_qualification_reports::ReceiptOperation],
    ledger_verifications: &BTreeMap<String, RetainedReceiptVerification>,
) -> Result<(), String> {
    use auths_profile_kit::QualificationReceiptState;
    use auths_receipts::{
        PortableReceipt, decode_portable_receipt, decode_receipt_trust_anchors,
        verify_portable_receipt_with_anchors,
    };

    let anchors = decode_receipt_trust_anchors(anchor_bytes).map_err(string_error)?;
    let scenario_instances = receipt_scenario_instances(evidence, expected)?;
    let mut files = BTreeMap::<String, Vec<(u32, String)>>::new();
    for path in evidence
        .member_names()
        .filter(|path| path.starts_with("receipts/"))
    {
        let value = path
            .strip_prefix("receipts/")
            .and_then(|value| value.strip_suffix(".cbor"))
            .ok_or_else(|| "qualification receipt member path is malformed".to_owned())?;
        let (operation_id, sequence) = value
            .split_once('/')
            .ok_or_else(|| "qualification receipt member path is malformed".to_owned())?;
        files.entry(operation_id.to_owned()).or_default().push((
            sequence.parse::<u32>().map_err(string_error)?,
            path.to_owned(),
        ));
    }
    for values in files.values_mut() {
        values.sort_by_key(|(sequence, _)| *sequence);
        if values
            .iter()
            .enumerate()
            .any(|(index, (sequence, _))| usize::try_from(*sequence) != Ok(index))
        {
            return Err("qualification receipt sequence is not gap-free from zero".into());
        }
    }
    let mut inspection_files = evidence
        .member_names()
        .filter_map(|path| {
            path.strip_prefix("receipt-inspection/")
                .and_then(|value| value.strip_suffix(".json"))
                .map(|operation_id| (operation_id.to_owned(), path.to_owned()))
        })
        .collect::<BTreeMap<_, _>>();

    let mut seen_receipt_ids = BTreeSet::new();
    for operation in operations {
        let instance = scenario_instances
            .get(&operation.operation_id)
            .ok_or_else(|| "receipt report operation has no scenario instance".to_owned())?;
        let profile = model_profile_ref(&instance.profile)?;
        let operation_files = files.remove(&operation.operation_id).unwrap_or_default();
        let required_files = match operation.state {
            QualificationReceiptState::None => 0,
            QualificationReceiptState::DecisionOnly => 1,
            QualificationReceiptState::LinkedExecution => 2,
        };
        if operation_files.len() != required_files {
            return Err("retained receipt count differs from the reported receipt state".into());
        }
        if operation.state == QualificationReceiptState::None {
            if inspection_files.remove(&operation.operation_id).is_some() {
                return Err("receipt-free operation has an inspection fact record".into());
            }
            continue;
        }
        let inspection_path = inspection_files
            .remove(&operation.operation_id)
            .ok_or_else(|| "retained receipt inspection facts are absent".to_owned())?;
        let inspection_bytes = evidence.read_member(&inspection_path, 16_777_216)?;
        let inspection: auths_profile_runtime::ProfileReceiptInspectionCommitmentsV1 =
            crate::profile_qualification_reports::parse_canonical(&inspection_bytes)?;
        inspection
            .validate()
            .map_err(|error| format!("receipt inspection commitments are invalid: {error:?}"))?;
        verify_profile_inspection_commitments(instance, &operation.operation_id, &inspection)?;

        let decision_bytes = evidence.read_member(&operation_files[0].1, 1_048_576)?;
        let decision =
            verify_portable_receipt_with_anchors(&decision_bytes, &anchors, Some(&profile), None)
                .map_err(string_error)?;
        if decision.execution_outcome().is_some()
            || operation.decision_receipt_id.as_deref() != Some(decision.portable_id())
            || operation.decision_verification_method.as_deref()
                != Some(decision.decision_verification_method())
            || inspection.decision_profile_claims_sha256
                != hex::encode(Sha256::digest(decision.decision_profile_claims()))
        {
            return Err("retained decision receipt differs from the receipt report".into());
        }
        verify_native_receipt_claims(instance, &decision, false)?;
        verify_ledger_receipt_commitment(
            &operation.operation_id,
            &decision_bytes,
            &decision,
            &inspection_bytes,
            ledger_verifications,
        )?;
        if !seen_receipt_ids.insert(decision.portable_id().to_owned()) {
            return Err("portable receipt identity is duplicated".into());
        }
        if operation.state == QualificationReceiptState::DecisionOnly {
            if inspection.execution_profile_claims_sha256.is_some() {
                return Err("decision-only receipt has execution inspection commitments".into());
            }
        }

        if operation.state == QualificationReceiptState::LinkedExecution {
            let execution_bytes = evidence.read_member(&operation_files[1].1, 1_048_576)?;
            let execution = verify_portable_receipt_with_anchors(
                &execution_bytes,
                &anchors,
                Some(&profile),
                Some(&operation.operation_id),
            )
            .map_err(string_error)?;
            let decision_container =
                decode_portable_receipt(&decision_bytes).map_err(string_error)?;
            let execution_container =
                decode_portable_receipt(&execution_bytes).map_err(string_error)?;
            if !matches!(decision_container, PortableReceipt::Decision { .. })
                || decision_container.attested_decision() != execution_container.attested_decision()
                || execution.execution_outcome().is_none()
                || operation.execution_receipt_id.as_deref() != Some(execution.portable_id())
                || operation.execution_verification_method.as_deref()
                    != execution.execution_verification_method()
                || inspection.execution_profile_claims_sha256.as_deref()
                    != execution
                        .execution_profile_claims()
                        .map(|claims| hex::encode(Sha256::digest(claims)))
                        .as_deref()
            {
                return Err("retained execution receipt differs from its linked report".into());
            }
            verify_native_receipt_claims(instance, &execution, true)?;
            verify_ledger_receipt_commitment(
                &operation.operation_id,
                &execution_bytes,
                &execution,
                &inspection_bytes,
                ledger_verifications,
            )?;
            if !seen_receipt_ids.insert(execution.portable_id().to_owned()) {
                return Err("portable receipt identity is duplicated".into());
            }
            if decision.decision_profile_claims() != execution.decision_profile_claims() {
                return Err("linked receipt changed the signed decision profile claims".into());
            }
        }
    }
    if !files.is_empty()
        || !inspection_files.is_empty()
        || seen_receipt_ids
            != ledger_verifications
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
    {
        return Err(
            "retained receipt files and authenticated ledger events are not bijective".into(),
        );
    }
    Ok(())
}

fn verify_profile_inspection_commitments(
    expected: &ReceiptScenarioInstance,
    operation_id: &str,
    inspection: &auths_profile_runtime::ProfileReceiptInspectionCommitmentsV1,
) -> Result<(), String> {
    use auths_profile_kit::{QualificationEffect, QualificationReceiptDecisionClass as Decision};
    use auths_stores::JournalDecisionClassV1;
    let expected_decision = match expected.decision_class {
        Decision::Authorized => JournalDecisionClassV1::Authorized,
        Decision::Denied => JournalDecisionClassV1::Denied,
        Decision::Indeterminate => JournalDecisionClassV1::Indeterminate,
    };
    let expected_effect = match expected.effect {
        QualificationEffect::Applied => auths_lifecycle::OperationEffectV1::Applied,
        QualificationEffect::NotApplied => auths_lifecycle::OperationEffectV1::NotApplied,
        QualificationEffect::Possible => auths_lifecycle::OperationEffectV1::Possible,
    };
    if inspection.profile != expected.profile
        || inspection.operation_id != operation_id
        || inspection.connection_generation != expected.connection_generation
        || inspection.principal_sha256 != expected.principal_sha256
        || Some(inspection.connection_descriptor_sha256.as_str())
            != expected.connection_descriptor_sha256.as_deref()
        || Some(inspection.connection_account_sha256.as_str())
            != expected.connection_account_sha256.as_deref()
        || inspection.canonical_input_sha256 != expected.canonical_input_sha256
        || inspection.idempotency_sha256 != expected.idempotency_sha256
        || inspection.canonical_action_sha256 != expected.canonical_action_sha256
        || inspection.authority_sha256 != expected.authority_sha256
        || inspection.configuration_sha256 != expected.configuration_sha256
        || inspection.runtime_contract_sha256 != expected.runtime_contract_sha256
        || inspection.preparation_sha256 != expected.preparation_sha256
        || inspection.decision_class != expected_decision
        || inspection.receipt_action_sha256 != expected.receipt_action_sha256
        || inspection.receipt_context_sha256 != expected.receipt_context_sha256
        || inspection.provider_entered != expected.provider_entered
        || inspection.completion != expected.completion
        || inspection.projection.state() != expected.projection_state
        || inspection.projection.effect() != expected_effect
        || !inspection.projection.is_terminal()
        || inspection.sealed_command_sha256 != expected.sealed_command_sha256
        || inspection.provider_result_sha256 != expected.provider_result_sha256
    {
        return Err(
            "receipt inspection commitments differ from authenticated scenario truth".into(),
        );
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct ReceiptScenarioInstance {
    profile: String,
    connection_generation: String,
    principal_sha256: String,
    connection_descriptor_sha256: Option<String>,
    connection_account_sha256: Option<String>,
    canonical_input_sha256: String,
    idempotency_sha256: Option<String>,
    canonical_action_sha256: String,
    receipt_action_sha256: String,
    receipt_context_sha256: String,
    authority_sha256: String,
    configuration_sha256: String,
    runtime_contract_sha256: String,
    preparation_sha256: String,
    decision_class: auths_profile_kit::QualificationReceiptDecisionClass,
    reconciled: bool,
    provider_entered: bool,
    projection_state: auths_lifecycle::OperationStateV1,
    completion: Option<auths_stores::JournalCompletionV1>,
    effect: auths_profile_kit::QualificationEffect,
    sealed_command_sha256: Option<String>,
    provider_result_sha256: Option<String>,
    execution_result_sha256: Option<String>,
}

fn receipt_scenario_instances(
    evidence: &crate::profile_qualification_evidence::VerifiedEvidence,
    expected: &crate::profile_qualification_reports::ExpectedReportBinding,
) -> Result<BTreeMap<String, ReceiptScenarioInstance>, String> {
    let mut instances = BTreeMap::new();
    for scenario_id in &expected.scenario_ids {
        let path = format!("reports/scenarios/{scenario_id}.json");
        let report: crate::profile_qualification_reports::ScenarioReport =
            crate::profile_qualification_reports::parse_canonical(
                &evidence.read_member(&path, 16_777_216)?,
            )?;
        for execution in report.executions {
            for operation in execution.operations {
                for instance in operation.instances {
                    let projection_state = operation
                        .attempts
                        .iter()
                        .rev()
                        .find(|attempt| {
                            attempt.operation_id.as_deref() == Some(instance.operation_id.as_str())
                                && matches!(
                                    attempt.outcome,
                                    auths_profile_kit::QualificationOutcomeKind::Denied
                                        | auths_profile_kit::QualificationOutcomeKind::Unavailable
                                        | auths_profile_kit::QualificationOutcomeKind::Completed
                                        | auths_profile_kit::QualificationOutcomeKind::Partial
                                        | auths_profile_kit::QualificationOutcomeKind::NotApplied
                                )
                        })
                        .map(|attempt| match attempt.outcome {
                            auths_profile_kit::QualificationOutcomeKind::Denied => {
                                auths_lifecycle::OperationStateV1::Denied
                            }
                            auths_profile_kit::QualificationOutcomeKind::Unavailable => {
                                auths_lifecycle::OperationStateV1::Unavailable
                            }
                            auths_profile_kit::QualificationOutcomeKind::Completed => {
                                auths_lifecycle::OperationStateV1::Completed
                            }
                            auths_profile_kit::QualificationOutcomeKind::Partial => {
                                auths_lifecycle::OperationStateV1::Partial
                            }
                            auths_profile_kit::QualificationOutcomeKind::NotApplied => {
                                auths_lifecycle::OperationStateV1::NotApplied
                            }
                            _ => unreachable!(),
                        })
                        .ok_or_else(|| {
                            "receipt-bearing operation has no authenticated terminal attempt"
                                .to_owned()
                        })?;
                    let completion = if instance.reconciled {
                        Some(auths_stores::JournalCompletionV1::Reconciled)
                    } else if matches!(
                        projection_state,
                        auths_lifecycle::OperationStateV1::Completed
                            | auths_lifecycle::OperationStateV1::Partial
                            | auths_lifecycle::OperationStateV1::NotApplied
                    ) {
                        Some(auths_stores::JournalCompletionV1::Fresh)
                    } else {
                        None
                    };
                    let value = ReceiptScenarioInstance {
                        profile: operation.profile.clone(),
                        connection_generation: instance.connection_generation,
                        principal_sha256: instance.principal_sha256,
                        connection_descriptor_sha256: instance.connection_descriptor_sha256,
                        connection_account_sha256: instance.connection_account_sha256,
                        canonical_input_sha256: instance.canonical_input_sha256,
                        idempotency_sha256: instance.idempotency_sha256,
                        canonical_action_sha256: instance.canonical_action_sha256,
                        receipt_action_sha256: instance.receipt_action_sha256,
                        receipt_context_sha256: instance.receipt_context_sha256,
                        authority_sha256: instance.authority_sha256,
                        configuration_sha256: instance.configuration_sha256,
                        runtime_contract_sha256: instance.runtime_contract_sha256,
                        preparation_sha256: instance.preparation_sha256,
                        decision_class: instance.decision_class,
                        reconciled: instance.reconciled,
                        provider_entered: instance.counters.provider_entry_markers == 1,
                        projection_state,
                        completion,
                        effect: instance.effect,
                        sealed_command_sha256: instance.sealed_command_sha256,
                        provider_result_sha256: instance.provider_result_sha256,
                        execution_result_sha256: instance.execution_result_sha256,
                    };
                    if instances.insert(instance.operation_id, value).is_some() {
                        return Err(
                            "operation appears in more than one scenario receipt projection".into(),
                        );
                    }
                }
            }
        }
    }
    if instances.keys().ne(expected.operation_ids.iter()) {
        return Err("scenario receipt projections do not cover the exact operation roster".into());
    }
    Ok(instances)
}

fn model_profile_ref(value: &str) -> Result<auths_model::ProfileRef, String> {
    let (id, version) = value
        .rsplit_once('/')
        .ok_or_else(|| "receipt profile is malformed".to_owned())?;
    auths_model::ProfileRef::new(
        auths_model::ProfileId::parse(id).map_err(string_error)?,
        version.parse::<u16>().map_err(string_error)?,
    )
    .map_err(string_error)
}

fn verify_native_receipt_claims(
    expected: &ReceiptScenarioInstance,
    actual: &auths_receipts::VerifiedPortableReceipt,
    execution: bool,
) -> Result<(), String> {
    use auths_profile_kit::{QualificationEffect, QualificationReceiptDecisionClass as Decision};
    use auths_receipts::{DecisionClass, ExecutionOutcome};
    let decision = match expected.decision_class {
        Decision::Authorized => DecisionClass::Authorized,
        Decision::Denied => DecisionClass::Denied,
        Decision::Indeterminate => DecisionClass::Indeterminate,
    };
    if hex::encode(actual.decision_action()) != expected.receipt_action_sha256
        || hex::encode(actual.decision_context()) != expected.receipt_context_sha256
        || actual.decision() != decision
    {
        return Err("native decision receipt claims differ from scenario evidence".into());
    }
    if !execution {
        return Ok(());
    }
    let outcome = if expected.reconciled {
        ExecutionOutcome::Indeterminate
    } else {
        match expected.effect {
            QualificationEffect::Applied => ExecutionOutcome::Succeeded,
            QualificationEffect::NotApplied => ExecutionOutcome::Failed,
            QualificationEffect::Possible => ExecutionOutcome::Indeterminate,
        }
    };
    if actual.execution_outcome() != Some(outcome)
        || actual.execution_command().map(hex::encode) != expected.sealed_command_sha256
        || actual.execution_result().map(hex::encode) != expected.execution_result_sha256
    {
        return Err("native execution receipt claims differ from scenario evidence".into());
    }
    Ok(())
}

fn verify_ledger_receipt_commitment(
    operation_id: &str,
    bytes: &[u8],
    receipt: &auths_receipts::VerifiedPortableReceipt,
    profile_inspection_bytes: &[u8],
    ledger_verifications: &BTreeMap<String, RetainedReceiptVerification>,
) -> Result<(), String> {
    let ledger = ledger_verifications
        .get(receipt.portable_id())
        .ok_or_else(|| "portable receipt has no authenticated verification event".to_owned())?;
    let claims =
        auths_receipts::verified_portable_receipt_claims_digest(receipt, Some(operation_id))
            .map_err(string_error)?;
    if ledger.operation_id != operation_id
        || ledger.receipt_bytes_sha256 != hex::encode(Sha256::digest(bytes))
        || ledger.decoded_claims_sha256 != hex::encode(claims)
        || ledger.profile_inspection_sha256 != hex::encode(Sha256::digest(profile_inspection_bytes))
    {
        return Err("portable receipt differs from its authenticated verification event".into());
    }
    Ok(())
}

fn required_env(name: &str) -> Result<String, String> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} is missing"))
}

fn required_sha256_env(name: &str) -> Result<String, String> {
    let value = required_env(name)?;
    let value = value.strip_prefix("sha256:").unwrap_or(&value);
    if !lower_hex(value, 64) {
        return Err(format!("{name} is not an exact SHA-256 digest"));
    }
    Ok(value.to_owned())
}

fn required_u32_env(name: &str) -> Result<u32, String> {
    let value = required_env(name)?;
    let parsed = value
        .parse::<u32>()
        .map_err(|_| format!("{name} is not a canonical u32"))?;
    if parsed == 0 || parsed == u32::MAX || parsed.to_string() != value {
        return Err(format!("{name} is not a canonical nonzero u32"));
    }
    Ok(parsed)
}

fn validate_workflow_inputs(repository: &Path) -> Result<(), String> {
    let candidate =
        env::var("CANDIDATE_REVISION").map_err(|_| "CANDIDATE_REVISION is missing".to_owned())?;
    let domain = env::var("QUALIFICATION_DOMAIN")
        .map_err(|_| "QUALIFICATION_DOMAIN is missing".to_owned())?;
    let target = env::var("QUALIFICATION_TARGET")
        .map_err(|_| "QUALIFICATION_TARGET is missing".to_owned())?;
    if !lower_hex(&candidate, 40) {
        return Err("candidate revision must be exactly 40 lowercase hexadecimal bytes".into());
    }
    let target = QualificationTarget::parse(&target).map_err(string_error)?;
    let context = load_domain(repository, &domain)?;
    if !context.package.qualification().targets().contains(&target) {
        return Err("workflow target is not declared by the domain manifest".into());
    }
    if git_revision(repository)? != candidate {
        return Err("checked-out revision does not equal the immutable candidate revision".into());
    }
    Ok(())
}

fn qualification_check(repository: &Path, selected: Option<&str>) -> Result<(), String> {
    if repository.join(IMPORT_TRANSACTION_PATH).exists() {
        return Err("qualification import transaction is incomplete".into());
    }
    qualification_check_inner(repository, selected, true, None)
}

pub(crate) fn qualification_check_all() -> Result<(), String> {
    qualification_check(&root(), None)
}

fn qualification_release_check(repository: &Path) -> Result<(), String> {
    if repository.join(IMPORT_TRANSACTION_PATH).exists() {
        return Err("qualification import transaction is incomplete".into());
    }
    qualification_check_inner(repository, None, false, None)?;
    let roster = load_roster(repository)?;
    validate_release_qualification_roster(&roster)?;
    let index = load_index(repository)?;
    validate_release_qualification_index(&index)?;
    println!("qualification release check passed for the exact five production profiles");
    Ok(())
}

fn validate_release_qualification_roster(roster: &ProfileRoster) -> Result<(), String> {
    let actual = roster
        .packages()
        .iter()
        .flat_map(|package| {
            package
                .profiles()
                .iter()
                .map(move |profile| (profile.profile_ref(), package.domain(), profile))
        })
        .collect::<Vec<_>>();
    if actual.len() != RELEASE_QUALIFICATION_PROFILES.len() {
        return Err("release qualification roster is not the exact five-profile launch set".into());
    }

    let mut family_qualification_ids = BTreeMap::new();
    for ((expected_profile, expected_domain), (profile, domain, entry)) in
        RELEASE_QUALIFICATION_PROFILES.iter().zip(actual)
    {
        if profile != *expected_profile
            || domain != *expected_domain
            || entry.qualification() != ProfileQualification::Qualified
            || entry.targets() != [QualificationTarget::LinuxX86_64]
            || entry.qualification_ids().len() != 1
        {
            return Err(format!(
                "release qualification is incomplete or unexpected for {expected_profile}"
            ));
        }
        let qualification_id = entry.qualification_ids()[0].as_str();
        match family_qualification_ids.insert(domain, qualification_id) {
            Some(existing) if existing != qualification_id => {
                return Err(format!(
                    "release qualification family {domain} has inconsistent qualification IDs"
                ));
            }
            _ => {}
        }
    }
    if family_qualification_ids.len() != 3
        || family_qualification_ids
            .values()
            .collect::<BTreeSet<_>>()
            .len()
            != 3
    {
        return Err("release qualification requires three distinct family attestations".into());
    }
    Ok(())
}

fn validate_release_qualification_index(index: &QualificationIndex) -> Result<(), String> {
    if index.entries().len() != RELEASE_QUALIFICATION_PROFILES.len() {
        return Err("release qualification index is not the exact five-profile launch set".into());
    }
    for ((expected_profile, _), entry) in RELEASE_QUALIFICATION_PROFILES.iter().zip(index.entries())
    {
        if entry.profile() != *expected_profile
            || entry.target() != QualificationTarget::LinuxX86_64
        {
            return Err(format!(
                "release qualification index contains an unexpected binding for {}",
                entry.profile()
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_qualification_state_for_generation(
    repository: &Path,
    domain: &str,
) -> Result<(), String> {
    let roster = load_roster(repository)?;
    validate_qualification_declarations(repository, &roster, Some(domain))?;
    if !roster
        .packages()
        .iter()
        .flat_map(|package| package.profiles())
        .any(|profile| profile.qualification() == ProfileQualification::Qualified)
    {
        return Ok(());
    }
    qualification_check_inner(repository, Some(domain), false, None)
}

pub(crate) fn current_semantic_closure_sha256(
    repository: &Path,
    domain: &str,
) -> Result<String, String> {
    semantic_closure(repository, domain).map(|closure| closure.sha256)
}

pub(crate) fn expected_profile_launch_projection(
    repository: &Path,
    roster: &ProfileRoster,
) -> Result<String, String> {
    let mut profiles = Vec::new();
    for package in roster.packages() {
        let closure = if package
            .profiles()
            .iter()
            .any(|profile| profile.qualification() == ProfileQualification::Qualified)
        {
            Some(current_semantic_closure_sha256(
                repository,
                package.domain(),
            )?)
        } else {
            None
        };
        for profile in package.profiles() {
            profiles.push(json!({
                "profile": profile.profile_ref(),
                "qualificationIds": profile.qualification_ids(),
                "semanticClosureSha256": if profile.qualification() == ProfileQualification::Qualified {
                    closure.as_deref()
                } else {
                    None
                },
                "state": match profile.qualification() {
                    ProfileQualification::Qualified => "qualified",
                    ProfileQualification::Unqualified => "unqualified",
                },
                "testkitAvailable": profile.testkit_available(),
                "targets": profile.targets().iter().map(|target| target.as_str()).collect::<Vec<_>>(),
            }));
        }
    }
    profiles.sort_by(|left, right| left["profile"].as_str().cmp(&right["profile"].as_str()));
    let value = json!({
        "profiles": profiles,
        "schema": "auths.profile-launch-projection/1",
    });
    let mut canonical = serde_json_canonicalizer::to_vec(&value).map_err(string_error)?;
    canonical.push(b'\n');
    String::from_utf8(canonical).map_err(string_error)
}

fn validate_profile_launch_projection(
    repository: &Path,
    roster: &ProfileRoster,
) -> Result<(), String> {
    let expected = expected_profile_launch_projection(repository, roster)?;
    let actual = read_bounded(&repository.join(LAUNCH_PROJECTION_PATH), 65_536)?;
    if actual == expected.as_bytes() {
        Ok(())
    } else {
        Err(
            "generated profile launch projection differs from the protected roster projection"
                .into(),
        )
    }
}

fn qualification_check_inner(
    repository: &Path,
    selected: Option<&str>,
    report: bool,
    exempt_attestation: Option<(&str, QualificationTarget)>,
) -> Result<(), String> {
    let roster = load_roster(repository)?;
    validate_qualification_declarations(repository, &roster, selected)?;
    validate_profile_launch_projection(repository, &roster)?;
    let index = load_index(repository)?;
    let registry = load_trust_registry(repository)?;
    validate_repository_qualification_key_separation(repository, &registry)?;
    let now = now_unix_seconds()?;
    let mut expected_index = BTreeMap::new();
    let mut verified_attestations = BTreeMap::new();

    for package in roster.packages() {
        if selected.is_some_and(|domain| domain != package.domain()) {
            continue;
        }
        let domain = load_domain(repository, package.domain())?;
        let manifest_family = domain.package.qualification().family();
        if package
            .profiles()
            .iter()
            .map(|profile| profile.profile_ref())
            .collect::<Vec<_>>()
            != manifest_family
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        {
            return Err(format!(
                "roster and manifest profile families differ for {}",
                package.domain()
            ));
        }
        for profile in package.profiles() {
            match profile.qualification() {
                ProfileQualification::Qualified => {
                    for (target, qualification_id) in
                        profile.targets().iter().zip(profile.qualification_ids())
                    {
                        expected_index.insert(
                            (profile.profile_ref().to_owned(), *target),
                            qualification_id.to_owned(),
                        );
                        if exempt_attestation.is_some_and(|(domain, exempt_target)| {
                            domain == package.domain() && exempt_target == *target
                        }) {
                            continue;
                        }
                        let key = (package.domain().to_owned(), *target);
                        if !verified_attestations.contains_key(&key) {
                            let path = attestation_path(repository, package.domain(), *target);
                            let bytes = read_bounded(&path, 266_240)?;
                            let verified =
                                QualificationAttestation::verify_json(&bytes, &registry, now)
                                    .map_err(string_error)?;
                            verify_record_against_repository(repository, verified.record(), false)?;
                            verified_attestations.insert(key.clone(), verified.into_record());
                        }
                        let record = &verified_attestations[&key];
                        if record.qualification_id() != qualification_id
                            || !record.profiles().iter().any(|candidate| {
                                candidate.semantic_subject() == profile.profile_ref()
                            })
                        {
                            return Err(format!(
                                "roster qualification does not match attestation for {}",
                                profile.profile_ref()
                            ));
                        }
                    }
                }
                ProfileQualification::Unqualified => {}
            }
        }
    }

    let actual = index
        .entries()
        .iter()
        .filter(|entry| {
            selected.is_none_or(|domain| entry.profile().starts_with(&format!("auths.{domain}.")))
        })
        .map(|entry| {
            (
                (entry.profile().to_owned(), entry.target()),
                entry.qualification_id().to_owned(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if actual != expected_index {
        return Err("qualification index does not exactly match the roster".into());
    }
    if selected.is_some()
        && !roster
            .packages()
            .iter()
            .any(|package| Some(package.domain()) == selected)
    {
        return Err("selected qualification domain is not in the static roster".into());
    }
    if report {
        println!(
            "qualification check passed for {}",
            selected.unwrap_or("all domains")
        );
    }
    Ok(())
}

fn validate_qualification_declarations(
    repository: &Path,
    roster: &ProfileRoster,
    selected: Option<&str>,
) -> Result<(), String> {
    let mut found = false;
    for package in roster.packages() {
        if selected.is_some_and(|domain| domain != package.domain()) {
            continue;
        }
        found = true;
        qualification_evidence_scan_policy(package.domain())?;
        let context = load_domain(repository, package.domain())?;
        let failpoint_coverage = load_failpoint_coverage(repository, &context)?;
        load_requirements(repository, &context, &failpoint_coverage)?;
        for target in context.package.qualification().targets() {
            load_provider_matrix(repository, &context, *target)?;
        }
        load_operation_plans(repository, &context)?;
    }
    if selected.is_some() && !found {
        return Err("selected qualification domain is not in the static roster".into());
    }
    Ok(())
}

fn verify_path(
    repository: &Path,
    path: &Path,
    require_candidate_revision: bool,
) -> Result<QualificationRecord, String> {
    let bytes = read_bounded(path, 266_240)?;
    let registry = load_trust_registry(repository)?;
    let verified = QualificationAttestation::verify_json(&bytes, &registry, now_unix_seconds()?)
        .map_err(string_error)?;
    verify_record_against_repository(repository, verified.record(), require_candidate_revision)?;
    println!(
        "verified {} for {}/{}",
        verified.record().qualification_id(),
        verified.record().domain(),
        verified.record().target().as_str()
    );
    Ok(verified.into_record())
}

fn import(repository: &Path, source: &Path) -> Result<(), String> {
    let _lock = ImportLock::acquire(repository)?;
    cleanup_orphan_import_intent_stage(repository)?;
    if repository.join(IMPORT_TRANSACTION_PATH).exists() {
        return resume_import_transaction(repository);
    }
    if !git_clean(repository)? {
        return Err("qualification import requires a clean candidate worktree".into());
    }
    let record = verify_path(repository, source, false)?;
    qualification_check_inner(
        repository,
        None,
        false,
        Some((record.domain(), record.target())),
    )?;
    let promotion_base_revision = git_revision(repository)?;
    validate_promotion_base(repository, &record, &promotion_base_revision)?;
    let source_bytes = read_bounded(source, 266_240)?;
    let destination = attestation_path(repository, record.domain(), record.target());
    let mut replacing = false;
    if destination.exists() {
        let existing = read_bounded(&destination, 266_240)?;
        if existing == source_bytes {
            return Err("qualification attestation is already imported".into());
        }
        let parsed = QualificationAttestation::from_json(&existing).map_err(string_error)?;
        let completed = parsed.record().completed_at_unix_seconds();
        validate_historical_record_ancestry(repository, parsed.record(), &promotion_base_revision)?;
        let registry = load_trust_registry_at(repository, parsed.record().candidate_revision())?;
        let existing = QualificationAttestation::verify_json(&existing, &registry, completed)
            .map_err(string_error)?;
        validate_prior_qualification_binding(
            repository,
            &promotion_base_revision,
            existing.record(),
        )?;
        validate_monotonic_replacement(existing.record(), &record)?;
        replacing = true;
    }

    let mut index: Value =
        serde_json::from_slice(&read_bounded(&repository.join(INDEX_PATH), 262_144)?)
            .map_err(string_error)?;
    qualify_index(&mut index, &record, replacing)?;
    let index_bytes = serde_json_canonicalizer::to_vec(&index).map_err(string_error)?;
    QualificationIndex::from_json(&index_bytes).map_err(string_error)?;

    let roster_path = repository.join(ROSTER_PATH);
    let mut roster_value: Value =
        serde_json::from_slice(&read_bounded(&roster_path, 131_072)?).map_err(string_error)?;
    qualify_roster(&mut roster_value, &record, replacing)?;
    let roster_bytes = serde_json::to_vec_pretty(&roster_value).map_err(string_error)?;
    let qualified_roster = ProfileRoster::from_json(&roster_bytes).map_err(string_error)?;
    let launch_projection =
        expected_profile_launch_projection(repository, &qualified_roster)?.into_bytes();

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(string_error)?;
    }
    let destination_relative = destination
        .strip_prefix(repository)
        .map_err(string_error)?
        .to_str()
        .ok_or_else(|| "qualification attestation path is not UTF-8".to_owned())?;
    let transaction = ImportTransaction {
        schema: "auths.profile-qualification-import-transaction/1".into(),
        candidate_revision: record.candidate_revision().into(),
        promotion_base_revision,
        domain: record.domain().into(),
        target: record.target(),
        qualification_id: record.qualification_id().into(),
        phase: ImportPhase::Promote,
        outputs: vec![
            import_output(
                repository,
                ImportOutputRole::Attestation,
                destination_relative,
                &source_bytes,
                266_240,
            )?,
            import_output(
                repository,
                ImportOutputRole::Index,
                INDEX_PATH,
                &index_bytes,
                262_144,
            )?,
            import_output(
                repository,
                ImportOutputRole::LaunchProjection,
                LAUNCH_PROJECTION_PATH,
                &launch_projection,
                65_536,
            )?,
            import_output(
                repository,
                ImportOutputRole::Roster,
                ROSTER_PATH,
                &roster_bytes,
                131_072,
            )?,
        ],
    };
    publish_import_intent(repository, &transaction)?;
    resume_import_transaction(repository)
}

fn validate_promotion_base(
    repository: &Path,
    record: &QualificationRecord,
    promotion_base_revision: &str,
) -> Result<(), String> {
    if !lower_hex(record.candidate_revision(), 40) || !lower_hex(promotion_base_revision, 40) {
        return Err("qualification promotion revisions are malformed".into());
    }
    if semantic_closure_at(repository, record.domain(), record.candidate_revision())?.sha256
        != record.semantic_closure_sha256()
        || semantic_closure_at(repository, record.domain(), promotion_base_revision)?.sha256
            != record.semantic_closure_sha256()
    {
        return Err("qualification promotion base changes the signed semantic closure".into());
    }
    if promotion_base_revision == record.candidate_revision() {
        return Ok(());
    }
    let ancestry = Command::new("git")
        .args([
            "merge-base",
            "--is-ancestor",
            record.candidate_revision(),
            promotion_base_revision,
        ])
        .current_dir(repository)
        .status()
        .map_err(string_error)?;
    if !ancestry.success() {
        return Err(
            "qualification promotion base does not descend from the signed candidate".into(),
        );
    }
    let range = format!("{}..{promotion_base_revision}", record.candidate_revision());
    let output = Command::new("git")
        .args(["diff", "--name-only", "--no-renames", &range])
        .current_dir(repository)
        .output()
        .map_err(string_error)?;
    if !output.status.success() {
        return Err("cannot inspect qualification promotion-base changes".into());
    }
    let paths = String::from_utf8(output.stdout).map_err(string_error)?;
    if paths.lines().any(|path| {
        !safe_relative_path(path)
            || !(path == INDEX_PATH
                || path == ROSTER_PATH
                || path == LAUNCH_PROJECTION_PATH
                || path.starts_with("release/qualification/v1/attestations/"))
    }) {
        return Err(
            "qualification promotion base contains non-allowlisted candidate changes".into(),
        );
    }
    Ok(())
}

fn validate_monotonic_replacement(
    old: &QualificationRecord,
    new: &QualificationRecord,
) -> Result<(), String> {
    let scenarios_are_equal_or_stronger = old.scenarios().iter().all(|old| {
        new.scenarios()
            .binary_search_by(|candidate| candidate.id().cmp(old.id()))
            .ok()
            .is_some_and(|index| new.scenarios()[index].assertions() >= old.assertions())
    });
    if old.domain() != new.domain()
        || old.target() != new.target()
        || old.profiles() != new.profiles()
        || old.completed_at_unix_seconds() >= new.completed_at_unix_seconds()
        || !scenarios_are_equal_or_stronger
        || new.artifact().retention_days() < old.artifact().retention_days()
        || new.artifact().expires_at_unix_seconds() <= old.artifact().expires_at_unix_seconds()
    {
        return Err("qualification replacement is not a strict equal-or-stronger successor".into());
    }
    Ok(())
}

fn validate_historical_record_ancestry(
    repository: &Path,
    old: &QualificationRecord,
    promotion_base_revision: &str,
) -> Result<(), String> {
    if !lower_hex(old.candidate_revision(), 40) {
        return Err("historical qualification candidate revision is malformed".into());
    }
    let status = Command::new("git")
        .args([
            "merge-base",
            "--is-ancestor",
            old.candidate_revision(),
            promotion_base_revision,
        ])
        .current_dir(repository)
        .status()
        .map_err(string_error)?;
    if !status.success() {
        return Err("historical qualification does not descend into the promotion base".into());
    }
    Ok(())
}

fn validate_prior_qualification_binding(
    repository: &Path,
    promotion_base_revision: &str,
    old: &QualificationRecord,
) -> Result<(), String> {
    let roster = ProfileRoster::from_json(&git_blob(
        repository,
        promotion_base_revision,
        ROSTER_PATH,
        131_072,
    )?)
    .map_err(string_error)?;
    let package = roster
        .packages()
        .iter()
        .find(|package| package.domain() == old.domain())
        .ok_or_else(|| {
            "historical qualification domain is absent from the base roster".to_owned()
        })?;
    let old_family = old
        .profiles()
        .iter()
        .map(|profile| profile.semantic_subject())
        .collect::<Vec<_>>();
    if package
        .profiles()
        .iter()
        .map(|profile| profile.profile_ref())
        .ne(old_family.iter().map(String::as_str))
        || package.profiles().iter().any(|profile| {
            profile.qualification() != ProfileQualification::Qualified
                || profile.qualification_id(old.target()) != Some(old.qualification_id())
        })
    {
        return Err("historical qualification does not bind the base roster family".into());
    }
    let index = QualificationIndex::from_json(&git_blob(
        repository,
        promotion_base_revision,
        INDEX_PATH,
        262_144,
    )?)
    .map_err(string_error)?;
    if old_family.iter().any(|profile| {
        index.qualification_id(profile, old.target()) != Some(old.qualification_id())
    }) {
        return Err("historical qualification does not bind the base index".into());
    }
    Ok(())
}

fn verify_record_against_repository(
    repository: &Path,
    record: &QualificationRecord,
    require_candidate_revision: bool,
) -> Result<(), String> {
    let roster = load_roster(repository)?;
    validate_profile_launch_projection(repository, &roster)?;
    let context = load_domain(repository, record.domain())?;
    if context
        .package
        .qualification()
        .family()
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != record
            .profiles()
            .iter()
            .map(|profile| profile.semantic_subject())
            .collect::<Vec<_>>()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
        || !context
            .package
            .qualification()
            .targets()
            .contains(&record.target())
        || record.workflow_path()
            != format!(
                ".github/workflows/profile-qualification-{}.yml",
                record.domain()
            )
        || record.protected_environment() != context.package.qualification().protected_environment()
    {
        return Err("attestation family, target, or workflow does not match the manifest".into());
    }
    let package_digest = hex::encode(
        context
            .package
            .package_manifest_digest()
            .map_err(string_error)?,
    );
    if record.package_manifest_sha256() != package_digest {
        return Err("attestation package-manifest digest does not match".into());
    }
    let closure = semantic_closure(repository, record.domain())?;
    if record.semantic_closure_sha256() != closure.sha256 {
        return Err("attestation semantic-closure digest does not match".into());
    }
    let runtime_digests = runtime_digests(repository, record.domain())?;
    for profile in record.profiles() {
        let subject = profile.semantic_subject();
        if record.profile_runtime_sha256(&subject)
            != runtime_digests.get(&subject).map(String::as_str)
        {
            return Err(format!(
                "attestation runtime digest does not match {subject}"
            ));
        }
    }
    if record.error_registry_sha256() != error_registry_digest(repository)? {
        return Err("attestation error-registry digest does not match".into());
    }
    if record.provider_matrix_sha256()
        != provider_matrix_digest(repository, &context, record.target())?
    {
        return Err("attestation provider-matrix digest does not match".into());
    }
    let expected_scenarios = scenario_roster(repository, &context)?;
    if record
        .scenarios()
        .iter()
        .map(|scenario| scenario.id())
        .collect::<Vec<_>>()
        != expected_scenarios
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    {
        return Err("attestation scenario roster is incomplete or unexpected".into());
    }
    if require_candidate_revision && record.candidate_revision() != git_revision(repository)? {
        return Err("attestation candidate revision does not match HEAD".into());
    }
    Ok(())
}

fn verify_record_against_revision(
    repository: &Path,
    record: &QualificationRecord,
    revision: &str,
) -> Result<(), String> {
    let context = load_domain_from_git(repository, record.domain(), revision)?;
    if context
        .package
        .qualification()
        .family()
        .iter()
        .map(String::as_str)
        .ne(record
            .profiles()
            .iter()
            .map(|profile| profile.semantic_subject()))
        || !context
            .package
            .qualification()
            .targets()
            .contains(&record.target())
        || record.workflow_path()
            != format!(
                ".github/workflows/profile-qualification-{}.yml",
                record.domain()
            )
        || record.protected_environment() != context.package.qualification().protected_environment()
    {
        return Err(
            "attestation family, target, or workflow differs at the frozen revision".into(),
        );
    }
    if record.package_manifest_sha256()
        != hex::encode(
            context
                .package
                .package_manifest_digest()
                .map_err(string_error)?,
        )
        || record.semantic_closure_sha256()
            != semantic_closure_at(repository, record.domain(), revision)?.sha256
    {
        return Err("attestation package or closure differs at the frozen revision".into());
    }
    let runtime_digests = runtime_digests_at(repository, record.domain(), revision)?;
    if record.profiles().iter().any(|profile| {
        let subject = profile.semantic_subject();
        record.profile_runtime_sha256(&subject) != runtime_digests.get(&subject).map(String::as_str)
    }) {
        return Err("attestation runtime digest differs at the frozen revision".into());
    }
    if record.error_registry_sha256() != error_registry_digest_at(repository, revision)?
        || record.provider_matrix_sha256()
            != provider_matrix_digest_at(repository, &context, record.target(), revision)?
        || record
            .scenarios()
            .iter()
            .map(|scenario| scenario.id())
            .ne(scenario_roster_at(repository, &context, revision)?
                .iter()
                .map(String::as_str))
    {
        return Err("attestation registry, provider matrix, or scenarios differ".into());
    }
    Ok(())
}

#[derive(Debug)]
struct DomainContext {
    package: ProfilePackage,
}

fn load_domain(repository: &Path, domain: &str) -> Result<DomainContext, String> {
    let roster = load_roster(repository)?;
    let entry = roster
        .packages()
        .iter()
        .find(|entry| entry.domain() == domain)
        .ok_or_else(|| format!("domain {domain} is not in the static profile roster"))?;
    let manifest_path = repository.join(entry.manifest_path());
    let manifest_bytes = read_bounded(&manifest_path, 262_144)?;
    let manifest_value: Value = serde_json::from_slice(&manifest_bytes).map_err(string_error)?;
    let api_path = manifest_path
        .parent()
        .ok_or_else(|| "profile manifest has no parent".to_owned())?
        .join(
            manifest_value
                .get("api")
                .and_then(Value::as_str)
                .ok_or_else(|| "profile manifest API path is missing".to_owned())?,
        );
    let api = ProfileApi::from_json(&read_bounded(&api_path, 262_144)?).map_err(string_error)?;
    let package = ProfilePackage::from_json(&manifest_bytes, &api).map_err(string_error)?;
    Ok(DomainContext { package })
}

fn load_domain_from_git(
    repository: &Path,
    domain: &str,
    revision: &str,
) -> Result<DomainContext, String> {
    let roster = ProfileRoster::from_json(&git_blob(repository, revision, ROSTER_PATH, 131_072)?)
        .map_err(string_error)?;
    let entry = roster
        .packages()
        .iter()
        .find(|entry| entry.domain() == domain)
        .ok_or_else(|| format!("domain {domain} is not in the immutable profile roster"))?;
    let manifest_path = entry.manifest_path();
    let manifest_bytes = git_blob(repository, revision, manifest_path, 262_144)?;
    let manifest_value: Value = serde_json::from_slice(&manifest_bytes).map_err(string_error)?;
    let api_relative = manifest_value
        .get("api")
        .and_then(Value::as_str)
        .filter(|path| safe_relative_path(path))
        .ok_or_else(|| "profile manifest API path is missing or unsafe".to_owned())?;
    let manifest_parent = Path::new(manifest_path)
        .parent()
        .ok_or_else(|| "profile manifest has no parent".to_owned())?;
    let api_path = manifest_parent
        .join(api_relative)
        .to_str()
        .ok_or_else(|| "profile API path is not UTF-8".to_owned())?
        .replace('\\', "/");
    if !safe_relative_path(&api_path) {
        return Err("profile API path escapes the immutable repository tree".into());
    }
    let api = ProfileApi::from_json(&git_blob(repository, revision, &api_path, 262_144)?)
        .map_err(string_error)?;
    let package = ProfilePackage::from_json(&manifest_bytes, &api).map_err(string_error)?;
    Ok(DomainContext { package })
}

fn git_blob(
    repository: &Path,
    revision: &str,
    path: &str,
    maximum: u64,
) -> Result<Vec<u8>, String> {
    if !lower_hex(revision, 40) || !safe_relative_path(path) {
        return Err("immutable Git blob reference is invalid".into());
    }
    let reference = format!("{revision}:{path}");
    let output = Command::new("git")
        .args(["rev-parse", "--verify", &reference])
        .current_dir(repository)
        .output()
        .map_err(string_error)?;
    let object = String::from_utf8(output.stdout)
        .map_err(string_error)?
        .trim()
        .to_owned();
    if !output.status.success() || !lower_hex(&object, 40) {
        return Err(format!("immutable qualification input is missing: {path}"));
    }
    git_object_blob(repository, &object, maximum)
}

fn git_blob_optional(
    repository: &Path,
    revision: &str,
    path: &str,
    maximum: u64,
) -> Result<Option<Vec<u8>>, String> {
    if !lower_hex(revision, 40) || !safe_relative_path(path) {
        return Err("qualification Git blob identity is malformed".into());
    }
    let commit = format!("{revision}^{{commit}}");
    let revision_status = Command::new("git")
        .args(["rev-parse", "--verify", &commit])
        .current_dir(repository)
        .output()
        .map_err(string_error)?;
    if !revision_status.status.success()
        || String::from_utf8(revision_status.stdout)
            .map_err(string_error)?
            .trim()
            != revision
    {
        return Err("qualification Git revision is not an exact commit".into());
    }
    let output = Command::new("git")
        .args(["ls-tree", "-z", "--full-tree", revision, "--", path])
        .current_dir(repository)
        .output()
        .map_err(string_error)?;
    if !output.status.success() {
        return Err("cannot inspect immutable qualification Git tree".into());
    }
    if output.stdout.is_empty() {
        return Ok(None);
    }
    let mut entries = output.stdout.split(|byte| *byte == 0);
    let entry = entries
        .next()
        .ok_or_else(|| "qualification Git tree entry is missing".to_owned())?;
    if entries.next() != Some(&[][..]) || entries.next().is_some() {
        return Err("qualification Git tree lookup is ambiguous".into());
    }
    let tab = entry
        .iter()
        .position(|byte| *byte == b'\t')
        .ok_or_else(|| "qualification Git tree entry is malformed".to_owned())?;
    let metadata = std::str::from_utf8(&entry[..tab]).map_err(string_error)?;
    let returned_path = std::str::from_utf8(&entry[tab + 1..]).map_err(string_error)?;
    let fields = metadata.split(' ').collect::<Vec<_>>();
    if fields.len() != 3
        || fields[0] != "100644"
        || fields[1] != "blob"
        || !lower_hex(fields[2], 40)
        || returned_path != path
    {
        return Err("qualification Git tree entry is not the exact regular blob".into());
    }
    git_object_blob(repository, fields[2], maximum).map(Some)
}

fn git_object_blob(repository: &Path, object: &str, maximum: u64) -> Result<Vec<u8>, String> {
    if !lower_hex(object, 40) {
        return Err("qualification Git object ID is malformed".into());
    }
    let size = Command::new("git")
        .args(["cat-file", "-s", object])
        .current_dir(repository)
        .output()
        .map_err(string_error)?;
    let size_value = String::from_utf8(size.stdout)
        .map_err(string_error)?
        .trim()
        .parse::<u64>()
        .map_err(string_error)?;
    if !size.status.success() || size_value > maximum {
        return Err("qualification Git blob exceeds its hard byte limit".into());
    }
    let output = Command::new("git")
        .args(["cat-file", "blob", object])
        .current_dir(repository)
        .output()
        .map_err(string_error)?;
    if !output.status.success()
        || u64::try_from(output.stdout.len()).map_err(string_error)? != size_value
    {
        return Err("qualification Git blob changed or could not be read".into());
    }
    Ok(output.stdout)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClosureManifest {
    schema: String,
    maximum_file_bytes: u64,
    common_inputs: Vec<String>,
    domain_inputs: Vec<String>,
    excluded_paths: Vec<String>,
    excluded_names: Vec<String>,
    excluded_suffixes: Vec<String>,
    normalized_inputs: Vec<NormalizedInput>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NormalizedInput {
    path: String,
    normalization: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClosureReport {
    schema: &'static str,
    domain: String,
    sha256: String,
    files: Vec<ClosureFile>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClosureFile {
    path: String,
    bytes: u64,
    sha256: String,
    normalized: bool,
}

fn semantic_closure(repository: &Path, domain: &str) -> Result<ClosureReport, String> {
    let revision = git_revision(repository)?;
    semantic_closure_at(repository, domain, &revision)
}

fn semantic_closure_at(
    repository: &Path,
    domain: &str,
    revision: &str,
) -> Result<ClosureReport, String> {
    let context = load_domain_from_git(repository, domain, revision)?;
    let manifest_bytes = git_blob(repository, revision, CLOSURE_MANIFEST_PATH, 65_536)?;
    if manifest_bytes != PROTECTED_CLOSURE_MANIFEST {
        return Err(
            "candidate qualification closure policy differs from the protected attester policy"
                .into(),
        );
    }
    let manifest: ClosureManifest =
        serde_json::from_slice(&manifest_bytes).map_err(string_error)?;
    if !canonical_source_json(&manifest, &manifest_bytes)?
        || manifest.schema != "auths.profile-qualification-closure-manifest/1"
        || manifest.maximum_file_bytes != 16_777_216
        || manifest.common_inputs.is_empty()
        || manifest.common_inputs.len() > 128
        || !manifest
            .common_inputs
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || manifest
            .common_inputs
            .iter()
            .any(|path| !safe_relative_path(path))
        || manifest.domain_inputs.is_empty()
        || manifest.domain_inputs.len() > 16
        || !manifest
            .domain_inputs
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || manifest.domain_inputs.iter().any(|path| {
            path.matches("{domain}").count() != 1
                || !safe_relative_path(&path.replace("{domain}", domain))
        })
        || manifest.excluded_paths.is_empty()
        || manifest.excluded_paths.len() > 16
        || !manifest
            .excluded_paths
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || manifest.excluded_paths
            != [
                "release/qualification/v1/attestations",
                "release/qualification/v1/index.json",
            ]
        || manifest.normalized_inputs.len() != 2
        || manifest
            .normalized_inputs
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
    {
        return Err("qualification closure manifest is invalid".into());
    }
    if !manifest
        .excluded_paths
        .iter()
        .all(|path| safe_relative_path(path))
    {
        return Err("qualification closure exclusions are invalid".into());
    }
    if !strict_sorted_safe_names(&manifest.excluded_names)
        || !strict_sorted_safe_suffixes(&manifest.excluded_suffixes)
    {
        return Err("qualification closure transient exclusions are invalid".into());
    }
    let normalizations = manifest
        .normalized_inputs
        .iter()
        .map(|input| (input.path.as_str(), input.normalization.as_str()))
        .collect::<BTreeMap<_, _>>();
    if normalizations.len() != 2
        || normalizations.get(ROSTER_PATH)
            != Some(&"auths.profile-roster-without-qualification-state/1")
        || normalizations.get(LAUNCH_PROJECTION_PATH)
            != Some(&"auths.profile-launch-projection-without-qualification-state/1")
    {
        return Err("qualification closure launch normalization roster is invalid".into());
    }
    let mut inputs = manifest.common_inputs;
    inputs.extend(
        manifest
            .domain_inputs
            .into_iter()
            .map(|path| path.replace("{domain}", domain)),
    );
    inputs.sort();
    if inputs.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("qualification closure input is duplicated".into());
    }

    if inputs.iter().any(|input| !safe_relative_path(input)) {
        return Err("qualification closure contains an unsafe input path".into());
    }
    if inputs.iter().any(|input| {
        manifest.excluded_paths.iter().any(|excluded| {
            input == excluded
                || input.starts_with(&format!("{excluded}/"))
                || excluded.starts_with(&format!("{input}/"))
        })
    }) {
        return Err("qualification closure input overlaps a protected exclusion".into());
    }
    let files = collect_git_files(
        repository,
        revision,
        &inputs,
        &manifest.excluded_paths,
        &manifest.excluded_names,
        &manifest.excluded_suffixes,
        manifest.maximum_file_bytes,
    )?;
    let mut hasher = Sha256::new();
    hasher.update(CLOSURE_DOMAIN);
    let mut report_files = Vec::with_capacity(files.len());
    for (path, raw) in files {
        let (bytes, normalized) = if let Some(normalization) = normalizations.get(path.as_str()) {
            (normalize_input(&path, &raw, normalization)?, true)
        } else {
            (raw, false)
        };
        let path_bytes = path.as_bytes();
        hasher.update(
            u64::try_from(path_bytes.len())
                .map_err(string_error)?
                .to_be_bytes(),
        );
        hasher.update(path_bytes);
        hasher.update(
            u64::try_from(bytes.len())
                .map_err(string_error)?
                .to_be_bytes(),
        );
        hasher.update(&bytes);
        report_files.push(ClosureFile {
            path,
            bytes: u64::try_from(bytes.len()).map_err(string_error)?,
            sha256: hex::encode(Sha256::digest(&bytes)),
            normalized,
        });
    }
    if report_files.is_empty()
        || context.package.qualification().adapter() != domain
        || !report_files.iter().any(|file| {
            file.path
                == format!(
                    "product/integrations/auths-{domain}/{}",
                    context.package.qualification().domain_scenarios()
                )
        })
    {
        return Err("qualification closure is empty or omits its domain declaration".into());
    }
    Ok(ClosureReport {
        schema: "auths.profile-qualification-closure/1",
        domain: domain.to_owned(),
        sha256: hex::encode(hasher.finalize()),
        files: report_files,
    })
}

fn collect_git_files(
    repository: &Path,
    revision: &str,
    inputs: &[String],
    excluded_paths: &[String],
    excluded_names: &[String],
    excluded_suffixes: &[String],
    maximum_file_bytes: u64,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut command = Command::new("git");
    command
        .args(["ls-tree", "-r", "-z", "--full-tree", revision, "--"])
        .args(inputs)
        .current_dir(repository);
    let output = command.output().map_err(string_error)?;
    if !output.status.success() {
        return Err("cannot enumerate immutable qualification closure tree".into());
    }
    let mut entries = BTreeMap::<String, (String, String)>::new();
    for raw in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let entry = std::str::from_utf8(raw)
            .map_err(|_| "qualification Git tree entry is not UTF-8".to_owned())?;
        let (metadata, path) = entry
            .split_once('\t')
            .ok_or_else(|| "qualification Git tree entry is malformed".to_owned())?;
        let mut metadata = metadata.split(' ');
        let mode = metadata.next().unwrap_or_default();
        let kind = metadata.next().unwrap_or_default();
        let object = metadata.next().unwrap_or_default();
        if metadata.next().is_some()
            || !matches!(mode, "100644" | "100755")
            || kind != "blob"
            || !lower_hex(object, 40)
            || !safe_relative_path(path)
        {
            return Err(format!(
                "qualification closure rejects Git tree entry: {path}"
            ));
        }
        let excluded = excluded_paths
            .iter()
            .any(|candidate| path == candidate || path.starts_with(&format!("{candidate}/")));
        if excluded {
            continue;
        }
        let name = path.rsplit('/').next().unwrap_or(path);
        if excluded_names
            .binary_search_by(|candidate| candidate.as_str().cmp(name))
            .is_ok()
            || excluded_suffixes
                .iter()
                .any(|suffix| name.ends_with(suffix))
        {
            return Err(format!(
                "tracked transient artifact cannot be hidden from qualification closure: {path}"
            ));
        }
        if entries
            .insert(path.to_owned(), (object.to_owned(), mode.to_owned()))
            .is_some()
        {
            return Err(format!("qualification closure path is duplicated: {path}"));
        }
    }
    for input in inputs {
        if !entries
            .keys()
            .any(|path| path == input || path.starts_with(&format!("{input}/")))
        {
            return Err(format!(
                "qualification closure input is absent from {revision}: {input}"
            ));
        }
    }
    entries
        .into_iter()
        .map(|(path, (object, _mode))| {
            git_object_blob(repository, &object, maximum_file_bytes).map(|bytes| (path, bytes))
        })
        .collect()
}

fn strict_sorted_safe_names(values: &[String]) -> bool {
    !values.is_empty()
        && values.windows(2).all(|pair| pair[0] < pair[1])
        && values.iter().all(|value| {
            !value.is_empty()
                && value.len() <= 64
                && !value.contains('/')
                && !value.contains('\\')
                && value != "."
                && value != ".."
        })
}

fn strict_sorted_safe_suffixes(values: &[String]) -> bool {
    !values.is_empty()
        && values.windows(2).all(|pair| pair[0] < pair[1])
        && values.iter().all(|value| {
            value.starts_with('.')
                && value.len() <= 32
                && value[1..]
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn normalize_input(path: &str, bytes: &[u8], normalization: &str) -> Result<Vec<u8>, String> {
    match (path, normalization) {
        (ROSTER_PATH, "auths.profile-roster-without-qualification-state/1") => {
            normalize_roster_launch_state(bytes)
        }
        (
            LAUNCH_PROJECTION_PATH,
            "auths.profile-launch-projection-without-qualification-state/1",
        ) => normalize_launch_projection(bytes),
        _ => Err(format!(
            "unsupported qualification normalization: {normalization}"
        )),
    }
}

fn normalize_roster_launch_state(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut roster: Value = serde_json::from_slice(bytes).map_err(string_error)?;
    for package in roster
        .get_mut("packages")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "profile roster packages are malformed".to_owned())?
    {
        for profile in package
            .get_mut("profiles")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "profile roster profiles are malformed".to_owned())?
        {
            let profile = profile
                .as_object_mut()
                .ok_or_else(|| "profile roster profile is malformed".to_owned())?;
            let state = profile
                .get("state")
                .and_then(Value::as_str)
                .ok_or_else(|| "profile roster launch state is malformed".to_owned())?;
            let targets = profile
                .get("targets")
                .and_then(Value::as_array)
                .ok_or_else(|| "profile roster targets are malformed".to_owned())?;
            let qualification_ids = profile
                .get("qualificationIds")
                .and_then(Value::as_array)
                .ok_or_else(|| "profile roster qualification IDs are malformed".to_owned())?;
            if !profile
                .get("testkitAvailable")
                .is_some_and(Value::is_boolean)
            {
                return Err("profile roster testkit availability is malformed".into());
            }
            match state {
                "qualified" if !targets.is_empty() && targets.len() == qualification_ids.len() => {
                    profile.insert("state".into(), json!("unqualified"));
                    profile.insert("targets".into(), json!([]));
                    profile.insert("qualificationIds".into(), json!([]));
                }
                "unqualified" if targets.is_empty() && qualification_ids.is_empty() => {}
                _ => return Err("profile roster launch-state tuple is invalid".into()),
            }
        }
    }
    serde_json_canonicalizer::to_vec(&roster).map_err(string_error)
}

fn normalize_launch_projection(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut projection: Value = serde_json::from_slice(bytes).map_err(string_error)?;
    let canonical = serde_json_canonicalizer::to_vec(&projection).map_err(string_error)?;
    if bytes != [canonical.as_slice(), b"\n"].concat()
        || !projection.as_object().is_some_and(|value| {
            value.len() == 2 && value.contains_key("profiles") && value.contains_key("schema")
        })
        || projection.get("schema").and_then(Value::as_str)
            != Some("auths.profile-launch-projection/1")
    {
        return Err("profile launch projection schema is invalid".into());
    }
    let profiles = projection
        .get("profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| "profile launch projection profiles are malformed".to_owned())?;
    if profiles.is_empty()
        || profiles.len() > 64
        || !profiles.windows(2).all(|pair| {
            pair[0].get("profile").and_then(Value::as_str)
                < pair[1].get("profile").and_then(Value::as_str)
        })
        || profiles
            .iter()
            .any(|profile| !valid_launch_profile_value(profile))
    {
        return Err("profile launch projection profiles are invalid".into());
    }
    for profile in projection
        .get_mut("profiles")
        .and_then(Value::as_array_mut)
        .expect("validated profiles")
    {
        let profile = profile
            .as_object_mut()
            .ok_or_else(|| "profile launch projection profile is malformed".to_owned())?;
        let state = profile
            .get("state")
            .and_then(Value::as_str)
            .ok_or_else(|| "profile launch projection state is malformed".to_owned())?;
        let targets = profile
            .get("targets")
            .and_then(Value::as_array)
            .ok_or_else(|| "profile launch projection targets are malformed".to_owned())?;
        let qualification_ids = profile
            .get("qualificationIds")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                "profile launch projection qualification IDs are malformed".to_owned()
            })?;
        let closure = profile.get("semanticClosureSha256");
        match state {
            "qualified"
                if !targets.is_empty()
                    && targets.len() == qualification_ids.len()
                    && closure.is_some_and(Value::is_string) =>
            {
                profile.insert("state".into(), json!("unqualified"));
                profile.insert("targets".into(), json!([]));
                profile.insert("qualificationIds".into(), json!([]));
                profile.insert("semanticClosureSha256".into(), Value::Null);
            }
            "unqualified"
                if targets.is_empty()
                    && qualification_ids.is_empty()
                    && closure.is_some_and(Value::is_null) => {}
            _ => return Err("profile launch projection state tuple is invalid".into()),
        }
    }
    serde_json_canonicalizer::to_vec(&projection).map_err(string_error)
}

fn valid_launch_profile_value(value: &Value) -> bool {
    let Some(profile) = value.as_object() else {
        return false;
    };
    if profile.keys().map(String::as_str).collect::<Vec<_>>()
        != [
            "profile",
            "qualificationIds",
            "semanticClosureSha256",
            "state",
            "targets",
            "testkitAvailable",
        ]
    {
        return false;
    }
    let Some(subject) = profile.get("profile").and_then(Value::as_str) else {
        return false;
    };
    let Some((id, version)) = subject.rsplit_once('/') else {
        return false;
    };
    let subject_valid = subject.len() <= 134
        && !id.is_empty()
        && id.len() <= 128
        && id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || (index != 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
        && !version.starts_with('0')
        && !version.is_empty()
        && version.len() <= 5
        && version.bytes().all(|byte| byte.is_ascii_digit());
    let Some(targets) = profile.get("targets").and_then(Value::as_array) else {
        return false;
    };
    let targets_valid = targets.len() <= 4
        && targets
            .windows(2)
            .all(|pair| pair[0].as_str() < pair[1].as_str())
        && targets.iter().all(|target| {
            matches!(
                target.as_str(),
                Some("linux-aarch64" | "linux-x86_64" | "macos-aarch64" | "macos-x86_64")
            )
        });
    let Some(ids) = profile.get("qualificationIds").and_then(Value::as_array) else {
        return false;
    };
    let ids_valid = ids.len() <= 4
        && ids.iter().all(|value| {
            value.as_str().is_some_and(|value| {
                value.len() == 47
                    && value.starts_with("qlf_")
                    && value[4..]
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            })
        })
        && ids
            .iter()
            .filter_map(Value::as_str)
            .collect::<BTreeSet<_>>()
            .len()
            == ids.len();
    let closure = profile.get("semanticClosureSha256");
    let state_valid = match profile.get("state").and_then(Value::as_str) {
        Some("qualified") => {
            !targets.is_empty()
                && targets.len() == ids.len()
                && closure.and_then(Value::as_str).is_some_and(valid_digest)
        }
        Some("unqualified") => {
            targets.is_empty() && ids.is_empty() && closure.is_some_and(Value::is_null)
        }
        _ => false,
    };
    subject_valid
        && targets_valid
        && ids_valid
        && profile
            .get("testkitAvailable")
            .is_some_and(Value::is_boolean)
        && state_valid
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn scenario_roster(repository: &Path, context: &DomainContext) -> Result<Vec<String>, String> {
    let common = read_bounded(
        &repository.join("product/conformance/v2/profile-qualification-common.json"),
        32_768,
    )?;
    let domain = read_bounded(
        &repository
            .join(format!(
                "product/integrations/auths-{}",
                context.package.domain().id()
            ))
            .join(context.package.qualification().domain_scenarios()),
        32_768,
    )?;
    scenario_roster_bytes(&common, &domain, context)
}

fn scenario_roster_at(
    repository: &Path,
    context: &DomainContext,
    revision: &str,
) -> Result<Vec<String>, String> {
    let domain_path = format!(
        "product/integrations/auths-{}/{}",
        context.package.domain().id(),
        context.package.qualification().domain_scenarios()
    );
    scenario_roster_bytes(
        &git_blob(
            repository,
            revision,
            "product/conformance/v2/profile-qualification-common.json",
            32_768,
        )?,
        &git_blob(repository, revision, &domain_path, 32_768)?,
        context,
    )
}

fn scenario_program_sha256_at(
    repository: &Path,
    context: &DomainContext,
    revision: &str,
    scenario_id: &str,
) -> Result<String, String> {
    scenario_program_at(repository, context, revision, scenario_id)?
        .sha256()
        .map_err(string_error)
}

fn scenario_program_at(
    repository: &Path,
    context: &DomainContext,
    revision: &str,
    scenario_id: &str,
) -> Result<auths_profile_kit::QualificationScenarioProgramV1, String> {
    let domain_path = format!(
        "product/integrations/auths-{}/{}",
        context.package.domain().id(),
        context.package.qualification().domain_scenarios()
    );
    let common = QualificationScenarioManifest::from_json(&git_blob(
        repository,
        revision,
        "product/conformance/v2/profile-qualification-common.json",
        262_144,
    )?)
    .map_err(string_error)?;
    let domain = QualificationScenarioManifest::from_json(&git_blob(
        repository,
        revision,
        &domain_path,
        262_144,
    )?)
    .map_err(string_error)?;
    Ok(domain
        .program(scenario_id)
        .or_else(|| common.program(scenario_id))
        .ok_or_else(|| "qualification scenario has no executable program".to_owned())?
        .clone())
}

fn scenario_roster_bytes(
    common: &[u8],
    domain: &[u8],
    context: &DomainContext,
) -> Result<Vec<String>, String> {
    let common = QualificationScenarioManifest::from_json(common).map_err(string_error)?;
    let domain = QualificationScenarioManifest::from_json(domain).map_err(string_error)?;
    if common.domain() != "common" || domain.domain() != context.package.domain().id() {
        return Err("qualification scenario manifest domain is invalid".into());
    }
    if !common
        .programs()
        .iter()
        .map(auths_profile_kit::QualificationScenarioProgramV1::id)
        .eq(COMMON_QUALIFICATION_SCENARIO_IDS.iter().copied())
    {
        return Err(
            "common qualification scenario manifest differs from the protected roster".into(),
        );
    }
    let expected_domain = crate::profile_qualification_adapters::qualification_domain_scenario_ids(
        context.package.domain().id(),
    )?;
    if !domain
        .programs()
        .iter()
        .map(auths_profile_kit::QualificationScenarioProgramV1::id)
        .eq(expected_domain.iter().copied())
    {
        return Err(
            "domain qualification scenario manifest differs from the generated roster".into(),
        );
    }
    if !QUALIFICATION_CRASH_SCENARIO_IDS.iter().all(|scenario| {
        COMMON_QUALIFICATION_SCENARIO_IDS
            .binary_search(scenario)
            .is_ok()
    }) {
        return Err(
            "protected crash-scenario roster is absent from the common scenario roster".into(),
        );
    }
    let mut values = common
        .programs()
        .iter()
        .map(|program| program.id().to_owned())
        .collect::<Vec<_>>();
    values.extend(
        domain
            .programs()
            .iter()
            .map(|program| program.id().to_owned()),
    );
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("qualification scenario IDs overlap".into());
    }
    Ok(values)
}

struct ExpectedFailpointBoundary {
    crash_scenario_id: &'static str,
    failpoint: &'static str,
    after_transition: Option<&'static str>,
    before_transition: Option<&'static str>,
    applicable_effects: &'static [&'static str],
    counter_assertions: &'static [&'static str],
    recovery_call: &'static str,
}

fn expected_failpoint_boundaries() -> [ExpectedFailpointBoundary; 12] {
    [
        ExpectedFailpointBoundary {
            crash_scenario_id: "crash-after-command",
            failpoint: "after-command",
            after_transition: Some("command-durable"),
            before_transition: Some("connection-reread"),
            applicable_effects: &["not-applied"],
            counter_assertions: &[
                "no-provider-call",
                "reservation-released-after-recovery",
                "reservation-written",
                "sealed-command-durable",
                "stable-operation-id",
            ],
            recovery_call: "recover",
        },
        ExpectedFailpointBoundary {
            crash_scenario_id: "crash-after-decision",
            failpoint: "after-decision",
            after_transition: Some("decision-durable"),
            before_transition: Some("reservation-durable"),
            applicable_effects: &["not-applied"],
            counter_assertions: &[
                "decision-receipt-durable",
                "no-provider-call",
                "stable-operation-id",
            ],
            recovery_call: "recover",
        },
        ExpectedFailpointBoundary {
            crash_scenario_id: "crash-after-entry-marker",
            failpoint: "after-entry-marker",
            after_transition: Some("provider-entry-durable"),
            before_transition: Some("provider-request-written"),
            applicable_effects: &["not-applied"],
            counter_assertions: &[
                "no-provider-call",
                "provider-entry-once",
                "reservation-released-after-recovery",
                "reservation-written",
                "stable-operation-id",
            ],
            recovery_call: "recover",
        },
        ExpectedFailpointBoundary {
            crash_scenario_id: "crash-after-execution-receipt",
            failpoint: "after-execution-receipt",
            after_transition: Some("execution-receipt-durable"),
            before_transition: Some("terminal-durable"),
            applicable_effects: &["applied", "not-applied"],
            counter_assertions: &[
                "execution-receipt-durable",
                "no-second-provider-call",
                "receipt-not-reminted",
                "stable-operation-id",
            ],
            recovery_call: "recover",
        },
        ExpectedFailpointBoundary {
            crash_scenario_id: "crash-after-lease",
            failpoint: "after-lease",
            after_transition: Some("credential-lease-succeeded"),
            before_transition: Some("provider-entry-durable"),
            applicable_effects: &["not-applied"],
            counter_assertions: &[
                "credential-lease-closed",
                "credential-lease-once",
                "no-provider-call",
                "reservation-released-after-recovery",
                "reservation-written",
                "stable-operation-id",
            ],
            recovery_call: "recover",
        },
        ExpectedFailpointBoundary {
            crash_scenario_id: "crash-after-observation",
            failpoint: "after-observation",
            after_transition: Some("observation-durable"),
            before_transition: Some("execution-receipt-durable"),
            applicable_effects: &["applied", "not-applied"],
            counter_assertions: &[
                "no-second-provider-call",
                "observation-durable",
                "stable-operation-id",
            ],
            recovery_call: "recover",
        },
        ExpectedFailpointBoundary {
            crash_scenario_id: "crash-after-provider-result",
            failpoint: "after-provider-result",
            after_transition: Some("provider-result-durable"),
            before_transition: Some("observation-durable"),
            applicable_effects: &["applied", "not-applied"],
            counter_assertions: &[
                "no-second-provider-call",
                "provider-result-durable",
                "stable-operation-id",
            ],
            recovery_call: "recover",
        },
        ExpectedFailpointBoundary {
            crash_scenario_id: "crash-after-request-write",
            failpoint: "after-request-write",
            after_transition: Some("provider-request-written"),
            before_transition: Some("provider-response-observed"),
            applicable_effects: &["applied", "not-applied"],
            counter_assertions: &[
                "no-second-provider-call",
                "provider-request-write-once",
                "stable-operation-id",
            ],
            recovery_call: "recover",
        },
        ExpectedFailpointBoundary {
            crash_scenario_id: "crash-after-reread",
            failpoint: "after-reread",
            after_transition: Some("connection-reread"),
            before_transition: Some("credential-lease-attempted"),
            applicable_effects: &["not-applied"],
            counter_assertions: &[
                "connection-reread-once",
                "no-provider-call",
                "reservation-released-after-recovery",
                "reservation-written",
                "stable-operation-id",
            ],
            recovery_call: "recover",
        },
        ExpectedFailpointBoundary {
            crash_scenario_id: "crash-after-reservation",
            failpoint: "after-reservation",
            after_transition: Some("reservation-durable"),
            before_transition: Some("command-durable"),
            applicable_effects: &["not-applied"],
            counter_assertions: &[
                "no-provider-call",
                "reservation-released-after-recovery",
                "reservation-written",
                "stable-operation-id",
            ],
            recovery_call: "recover",
        },
        ExpectedFailpointBoundary {
            crash_scenario_id: "crash-after-terminal",
            failpoint: "after-terminal",
            after_transition: Some("terminal-durable"),
            before_transition: Some("response-projected"),
            applicable_effects: &["applied", "not-applied"],
            counter_assertions: &[
                "no-second-provider-call",
                "stable-operation-id",
                "terminal-durable",
            ],
            recovery_call: "status",
        },
        ExpectedFailpointBoundary {
            crash_scenario_id: "crash-before-decision",
            failpoint: "before-decision",
            after_transition: Some("request-received"),
            before_transition: Some("decision-durable"),
            applicable_effects: &["not-applied"],
            counter_assertions: &["no-provider-call"],
            recovery_call: "retry-original",
        },
    ]
}

pub(crate) fn qualification_failpoint_coverage_value(
    domain: &str,
    provider_truth_fields: &[&str],
) -> Value {
    let boundaries = expected_failpoint_boundaries()
        .into_iter()
        .map(|boundary| {
            json!({
                "afterTransition":boundary.after_transition,
                "applicableEffects":boundary.applicable_effects,
                "beforeTransition":boundary.before_transition,
                "counterAssertions":boundary.counter_assertions,
                "crashScenarioId":boundary.crash_scenario_id,
                "failpoint":boundary.failpoint,
                "providerTruthRequired":true,
                "recoveryCall":boundary.recovery_call,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "boundaries":boundaries,
        "domain":domain,
        "providerTruthFields":provider_truth_fields,
        "schema":"auths.profile-qualification-failpoint-coverage/1",
    })
}

fn load_failpoint_coverage(
    repository: &Path,
    context: &DomainContext,
) -> Result<QualificationFailpointCoverage, String> {
    let domain = context.package.domain().id();
    let path = repository
        .join(format!("product/integrations/auths-{domain}"))
        .join(context.package.qualification().failpoint_coverage());
    let bytes = read_bounded(&path, 262_144)?;
    load_failpoint_coverage_bytes(context, &bytes)
}

fn load_failpoint_coverage_at(
    repository: &Path,
    context: &DomainContext,
    revision: &str,
) -> Result<QualificationFailpointCoverage, String> {
    let domain = context.package.domain().id();
    let path = format!(
        "product/integrations/auths-{domain}/{}",
        context.package.qualification().failpoint_coverage()
    );
    let bytes = git_blob(repository, revision, &path, 262_144)?;
    load_failpoint_coverage_bytes(context, &bytes)
}

fn load_failpoint_coverage_bytes(
    context: &DomainContext,
    bytes: &[u8],
) -> Result<QualificationFailpointCoverage, String> {
    let domain = context.package.domain().id();
    let coverage: QualificationFailpointCoverage =
        serde_json::from_slice(bytes).map_err(string_error)?;
    if !canonical_source_json(&coverage, &bytes)?
        || coverage.schema != "auths.profile-qualification-failpoint-coverage/1"
        || coverage.domain != domain
        || coverage.boundaries.len() != QUALIFICATION_CRASH_SCENARIO_IDS.len()
        || !coverage
            .boundaries
            .windows(2)
            .all(|pair| pair[0].crash_scenario_id < pair[1].crash_scenario_id)
    {
        return Err("qualification failpoint coverage envelope is invalid".into());
    }
    let expected_truth =
        crate::profile_qualification_adapters::qualification_provider_truth_fields(domain)?;
    if coverage
        .provider_truth_fields
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        != expected_truth
    {
        return Err(
            "qualification failpoint provider-truth fields differ from the executable roster"
                .into(),
        );
    }
    for (actual, expected) in coverage
        .boundaries
        .iter()
        .zip(expected_failpoint_boundaries())
    {
        if actual.crash_scenario_id != expected.crash_scenario_id
            || actual.failpoint != expected.failpoint
            || actual.after_transition.as_deref() != expected.after_transition
            || actual.before_transition.as_deref() != expected.before_transition
            || actual
                .applicable_effects
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                != expected.applicable_effects
            || actual
                .counter_assertions
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                != expected.counter_assertions
            || actual.recovery_call != expected.recovery_call
            || !actual.provider_truth_required
        {
            return Err(format!(
                "qualification failpoint boundary {} differs from the closed lifecycle contract",
                actual.crash_scenario_id
            ));
        }
    }
    let failpoints = coverage
        .boundaries
        .iter()
        .map(|row| row.failpoint.as_str())
        .collect::<BTreeSet<_>>();
    if failpoints
        != QUALIFICATION_FAILPOINT_IDS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
    {
        return Err("qualification failpoint enum coverage is not exact".into());
    }
    Ok(coverage)
}

fn load_requirements(
    repository: &Path,
    context: &DomainContext,
    failpoint_coverage: &QualificationFailpointCoverage,
) -> Result<QualificationRequirements, String> {
    let domain = context.package.domain().id();
    let expected_requirement_ids =
        crate::profile_qualification_adapters::qualification_requirement_ids(domain)?
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<BTreeSet<_>>();
    let expected_receipt_claim_ids =
        crate::profile_qualification_adapters::qualification_receipt_claim_ids(domain)?
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<BTreeSet<_>>();
    let expected_provider_truth_fields =
        crate::profile_qualification_adapters::qualification_provider_truth_fields(domain)?
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<BTreeSet<_>>();
    let integration_root = format!("product/integrations/auths-{domain}");
    let path = repository
        .join(&integration_root)
        .join(context.package.qualification().requirements());
    let bytes = read_bounded(&path, 262_144)?;
    let inventory: QualificationRequirements =
        serde_json::from_slice(&bytes).map_err(string_error)?;
    if !canonical_source_json(&inventory, &bytes)? {
        return Err("qualification requirements are not canonical JCS plus one final LF".into());
    }
    if hex::encode(Sha256::digest(&bytes))
        != crate::profile_qualification_adapters::qualification_requirements_sha256(domain)?
    {
        return Err(
            "qualification requirements differ from the generated exact inventory digest".into(),
        );
    }
    if inventory.schema != "auths.profile-qualification-requirements/1"
        || inventory.domain != domain
    {
        return Err("qualification requirements have the wrong schema or domain".into());
    }
    if inventory.requirements.is_empty() || inventory.requirements.len() > 256 {
        return Err("qualification requirement count is outside the closed bounds".into());
    }
    if !inventory
        .requirements
        .windows(2)
        .all(|pair| pair[0].requirement_id < pair[1].requirement_id)
    {
        return Err("qualification requirement IDs are not byte-sorted and unique".into());
    }

    let family = context.package.qualification().family();
    let domain_scenarios = QualificationScenarioManifest::from_json(&read_bounded(
        &repository
            .join(&integration_root)
            .join(context.package.qualification().domain_scenarios()),
        32_768,
    )?)
    .map_err(string_error)?;
    if domain_scenarios.domain() != domain {
        return Err("qualification requirement scenario domain is invalid".into());
    }
    let provider_truth_path = repository
        .join(&integration_root)
        .join(context.package.qualification().provider_truth_schema());
    let provider_truth: Value =
        serde_json::from_slice(&read_bounded(&provider_truth_path, 262_144)?)
            .map_err(string_error)?;
    let provider_truth_fields = provider_truth
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| "qualification provider-truth schema has no property roster".to_owned())?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if provider_truth_fields.is_empty()
        || provider_truth_fields.len() > 128
        || provider_truth_fields
            .iter()
            .any(|field| !registered_token(field))
    {
        return Err("qualification provider-truth schema property roster is invalid".into());
    }
    if provider_truth_fields != expected_provider_truth_fields {
        return Err(
            "qualification provider-truth schema differs from the executable static roster".into(),
        );
    }

    let mut covered_requirement_ids = BTreeSet::new();
    let mut covered_profiles = BTreeSet::new();
    let mut covered_scenarios = BTreeSet::new();
    let mut covered_failpoints = BTreeSet::new();
    let mut covered_receipt_claims = BTreeSet::new();
    let mut covered_truth_fields = BTreeSet::new();
    for requirement in &inventory.requirements {
        if !registered_token(&requirement.requirement_id)
            || requirement.profile_references.is_empty()
            || requirement.profile_references.len() > 8
            || !sorted_unique_strings(&requirement.profile_references)
            || requirement
                .profile_references
                .iter()
                .any(|profile| !family.contains(profile))
            || !authoritative_section_exists(
                repository,
                &requirement.authoritative_spec_path,
                &requirement.authoritative_spec_section,
            )
            || requirement.authoritative_spec_section.is_empty()
            || requirement.authoritative_spec_section.len() > 128
            || !requirement
                .authoritative_spec_section
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' ')
            || !valid_requirement_paths(repository, &requirement.production_source_owners, 128)
            || !valid_requirement_paths(repository, &requirement.unit_tests, 128)
            || !valid_requirement_paths(repository, &requirement.mutation_tests, 128)
            || requirement.live_scenario_ids.is_empty()
            || requirement.live_scenario_ids.len() > 128
            || !sorted_unique_tokens(&requirement.live_scenario_ids)
            || requirement.live_scenario_ids.iter().any(|scenario| {
                domain_scenarios
                    .programs()
                    .binary_search_by(|program| program.id().cmp(scenario))
                    .is_err()
            })
            || requirement.crash_point_ids.len() > QUALIFICATION_FAILPOINT_IDS.len()
            || !sorted_unique_tokens(&requirement.crash_point_ids)
            || requirement.crash_point_ids.iter().any(|failpoint| {
                failpoint_coverage
                    .boundaries
                    .binary_search_by(|row| row.crash_scenario_id.as_str().cmp(failpoint))
                    .is_err()
            })
            || requirement.receipt_claim_ids.is_empty()
            || requirement.receipt_claim_ids.len() > 128
            || !sorted_unique_tokens(&requirement.receipt_claim_ids)
            || requirement.provider_truth_report_fields.is_empty()
            || requirement.provider_truth_report_fields.len() > 128
            || !sorted_unique_tokens(&requirement.provider_truth_report_fields)
            || requirement
                .provider_truth_report_fields
                .iter()
                .any(|field| !provider_truth_fields.contains(field))
            || !matches!(
                requirement.credential_role.as_str(),
                "cleanup" | "mutation" | "none" | "observer" | "runtime-read" | "setup"
            )
        {
            return Err(format!(
                "qualification requirement {} is invalid",
                requirement.requirement_id
            ));
        }
        covered_requirement_ids.insert(requirement.requirement_id.clone());
        covered_profiles.extend(requirement.profile_references.iter().cloned());
        covered_scenarios.extend(requirement.live_scenario_ids.iter().cloned());
        covered_failpoints.extend(requirement.crash_point_ids.iter().cloned());
        covered_receipt_claims.extend(requirement.receipt_claim_ids.iter().cloned());
        covered_truth_fields.extend(requirement.provider_truth_report_fields.iter().cloned());
    }

    if covered_requirement_ids != expected_requirement_ids
        || covered_profiles != family.iter().cloned().collect()
        || covered_scenarios
            != domain_scenarios
                .programs()
                .iter()
                .map(|program| program.id().to_owned())
                .collect()
        || covered_failpoints
            != failpoint_coverage
                .boundaries
                .iter()
                .map(|row| row.crash_scenario_id.clone())
                .collect()
        || covered_receipt_claims != expected_receipt_claim_ids
        || covered_truth_fields != provider_truth_fields
    {
        return Err(
            "qualification requirements do not exactly cover the declared family and evidence"
                .into(),
        );
    }
    Ok(inventory)
}

fn sorted_unique_strings(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn sorted_unique_tokens(values: &[String]) -> bool {
    sorted_unique_strings(values) && values.iter().all(|value| registered_token(value))
}

fn valid_requirement_paths(repository: &Path, values: &[String], maximum: usize) -> bool {
    !values.is_empty()
        && values.len() <= maximum
        && sorted_unique_strings(values)
        && values
            .iter()
            .all(|value| checked_repository_path(repository, value))
}

fn checked_repository_path(repository: &Path, value: &str) -> bool {
    if !safe_relative_path(value) {
        return false;
    }
    fs::symlink_metadata(repository.join(value))
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
}

fn authoritative_section_exists(repository: &Path, path: &str, section: &str) -> bool {
    if !checked_repository_path(repository, path) {
        return false;
    }
    let Some(section_number) = section.split_ascii_whitespace().next() else {
        return false;
    };
    if section_number.is_empty()
        || !section_number
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return false;
    }
    fs::read_to_string(repository.join(path)).is_ok_and(|contents| {
        contents
            .lines()
            .any(|line| line.starts_with(&format!("### {section_number} ")))
    })
}

fn canonical_source_json<T: Serialize>(value: &T, bytes: &[u8]) -> Result<bool, String> {
    let mut canonical = serde_json_canonicalizer::to_vec(value).map_err(string_error)?;
    canonical.push(b'\n');
    Ok(canonical == bytes)
}

fn runtime_digests(repository: &Path, domain: &str) -> Result<BTreeMap<String, String>, String> {
    runtime_digests_bytes(&read_bounded(
        &repository.join(format!(
            "bindings/generated/{domain}/fixtures/manifest-digests.json"
        )),
        262_144,
    )?)
}

fn runtime_digests_at(
    repository: &Path,
    domain: &str,
    revision: &str,
) -> Result<BTreeMap<String, String>, String> {
    runtime_digests_bytes(&git_blob(
        repository,
        revision,
        &format!("bindings/generated/{domain}/fixtures/manifest-digests.json"),
        262_144,
    )?)
}

fn runtime_digests_bytes(bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let fixture: Value = serde_json::from_slice(bytes).map_err(string_error)?;
    let profiles = fixture
        .get("profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| "generated runtime digest fixture is malformed".to_owned())?;
    profiles
        .iter()
        .map(|profile| {
            let id = profile
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| "generated runtime profile ID is missing".to_owned())?;
            let version = profile
                .get("version")
                .and_then(Value::as_u64)
                .ok_or_else(|| "generated runtime profile version is missing".to_owned())?;
            let digest = profile
                .get("runtimeContractSha256")
                .and_then(Value::as_str)
                .filter(|value| lower_hex(value, 64))
                .ok_or_else(|| "generated runtime digest is invalid".to_owned())?;
            Ok((format!("{id}/{version}"), digest.to_owned()))
        })
        .collect()
}

fn error_registry_digest(repository: &Path) -> Result<String, String> {
    let source =
        fs::read(repository.join("bindings/typescript/src/generated/error-registry-digest.ts"))
            .map_err(string_error)?;
    error_registry_digest_bytes(&source)
}

fn error_registry_digest_at(repository: &Path, revision: &str) -> Result<String, String> {
    error_registry_digest_bytes(&git_blob(
        repository,
        revision,
        "bindings/typescript/src/generated/error-registry-digest.ts",
        65_536,
    )?)
}

fn error_registry_digest_bytes(bytes: &[u8]) -> Result<String, String> {
    let source = std::str::from_utf8(bytes).map_err(string_error)?;
    let marker = "ERROR_REGISTRY_SHA256 = \"";
    let digest = source
        .split_once(marker)
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(value, _)| value)
        .filter(|value| lower_hex(value, 64))
        .ok_or_else(|| "generated error-registry digest is invalid".to_owned())?;
    Ok(digest.to_owned())
}

fn provider_matrix_digest(
    repository: &Path,
    context: &DomainContext,
    target: QualificationTarget,
) -> Result<String, String> {
    let matrix = load_provider_matrix(repository, context, target)?;
    Ok(hex::encode(Sha256::digest(
        serde_json_canonicalizer::to_vec(&matrix).map_err(string_error)?,
    )))
}

fn provider_matrix_digest_at(
    repository: &Path,
    context: &DomainContext,
    target: QualificationTarget,
    revision: &str,
) -> Result<String, String> {
    let matrix = load_provider_matrix_at(repository, context, target, revision)?;
    Ok(hex::encode(Sha256::digest(
        serde_json_canonicalizer::to_vec(&matrix).map_err(string_error)?,
    )))
}

fn load_provider_matrix(
    repository: &Path,
    context: &DomainContext,
    target: QualificationTarget,
) -> Result<QualificationProviderMatrix, String> {
    let path = repository
        .join(format!(
            "product/integrations/auths-{}",
            context.package.domain().id()
        ))
        .join(context.package.qualification().provider_matrix());
    let bytes = read_bounded(&path, 65_536)?;
    let scenario_ids = scenario_roster(repository, context)?;
    load_provider_matrix_bytes(context, target, &bytes, &scenario_ids)
}

fn load_provider_matrix_at(
    repository: &Path,
    context: &DomainContext,
    target: QualificationTarget,
    revision: &str,
) -> Result<QualificationProviderMatrix, String> {
    let path = format!(
        "product/integrations/auths-{}/{}",
        context.package.domain().id(),
        context.package.qualification().provider_matrix()
    );
    let bytes = git_blob(repository, revision, &path, 65_536)?;
    let scenario_ids = scenario_roster_at(repository, context, revision)?;
    load_provider_matrix_bytes(context, target, &bytes, &scenario_ids)
}

fn load_provider_matrix_bytes(
    context: &DomainContext,
    target: QualificationTarget,
    bytes: &[u8],
    scenario_ids: &[String],
) -> Result<QualificationProviderMatrix, String> {
    let matrix: QualificationProviderMatrix =
        serde_json::from_slice(bytes).map_err(string_error)?;
    let provider_kind = context
        .package
        .domain()
        .connection()
        .ok_or_else(|| "qualified profile domain has no provider connection".to_owned())?
        .provider_kind();
    let expected_rows = crate::profile_qualification_adapters::qualification_provider_matrix_rows(
        context.package.domain().id(),
    )?;
    if !canonical_source_json(&matrix, bytes)?
        || matrix.schema != "auths.profile-qualification-provider-matrix/1"
        || matrix.domain != context.package.domain().id()
        || matrix.runs.len() != expected_rows.len()
        || !matrix.runs.windows(2).all(|pair| pair[0].id < pair[1].id)
        || matrix.runs.iter().any(|run| {
            !registered_token(&run.id)
                || run.provider != provider_kind
                || run.scenario_ids.is_empty()
                || run.scenario_ids.len() > 256
                || !run.scenario_ids.windows(2).all(|pair| pair[0] < pair[1])
                || run.scenario_ids.iter().any(|id| !registered_token(id))
                || run
                    .scenario_ids
                    .iter()
                    .any(|id| scenario_ids.binary_search(id).is_err())
                || !registered_token(&run.provider_version)
                || !lower_hex(&run.provider_artifact_sha256, 64)
                || run.target != target.as_str()
        })
    {
        return Err("qualification provider matrix is non-canonical or invalid".into());
    }
    for (run, expected) in matrix.runs.iter().zip(expected_rows) {
        if (
            run.id.as_str(),
            run.provider.as_str(),
            run.provider_version.as_str(),
            run.provider_artifact_sha256.as_str(),
            run.target.as_str(),
        ) != *expected
        {
            return Err(
                "qualification provider matrix differs from its exact static row roster".into(),
            );
        }
        if run.scenario_ids != scenario_ids {
            return Err(
                "qualification provider matrix row does not cover the exact scenario roster".into(),
            );
        }
    }
    let covered = matrix
        .runs
        .iter()
        .flat_map(|run| run.scenario_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    if covered != scenario_ids.iter().cloned().collect() {
        return Err(
            "qualification provider matrix does not cover the exact scenario roster".into(),
        );
    }
    for run in &matrix.runs {
        let contract = serde_json_canonicalizer::to_vec(&run.contract).map_err(string_error)?;
        crate::profile_qualification_adapters::validate_provider_matrix_contract(
            &matrix.domain,
            &contract,
            &run.provider_version,
            &run.provider_artifact_sha256,
        )?;
    }
    Ok(matrix)
}

fn require_provider_run(
    repository: &Path,
    context: &DomainContext,
    target: QualificationTarget,
    provider_run_id: &str,
) -> Result<QualificationProviderMatrixRun, String> {
    if !registered_token(provider_run_id) {
        return Err("qualification provider run is not an exact checked matrix row".into());
    }
    load_provider_matrix(repository, context, target)?
        .runs
        .into_iter()
        .find(|run| run.id == provider_run_id)
        .ok_or_else(|| "qualification provider run is not an exact checked matrix row".into())
}

fn load_operation_plans(
    repository: &Path,
    context: &DomainContext,
) -> Result<BTreeMap<String, Vec<QualificationPlannedOperation>>, String> {
    let path = repository
        .join(format!(
            "product/integrations/auths-{}",
            context.package.domain().id()
        ))
        .join(context.package.qualification().operation_plans());
    let bytes = read_bounded(&path, 262_144)?;
    let roster = scenario_roster(repository, context)?;
    load_operation_plan_bytes(context, &bytes, &roster)
}

fn load_operation_plans_at(
    repository: &Path,
    context: &DomainContext,
    revision: &str,
) -> Result<BTreeMap<String, Vec<QualificationPlannedOperation>>, String> {
    let path = format!(
        "product/integrations/auths-{}/{}",
        context.package.domain().id(),
        context.package.qualification().operation_plans()
    );
    let bytes = git_blob(repository, revision, &path, 262_144)?;
    let roster = scenario_roster_at(repository, context, revision)?;
    load_operation_plan_bytes(context, &bytes, &roster)
}

fn load_operation_plan_bytes(
    context: &DomainContext,
    bytes: &[u8],
    roster: &[String],
) -> Result<BTreeMap<String, Vec<QualificationPlannedOperation>>, String> {
    let plans: QualificationOperationPlans = serde_json::from_slice(bytes).map_err(string_error)?;
    if !canonical_source_json(&plans, bytes)?
        || plans.schema != "auths.profile-qualification-operation-plans/1"
        || plans.domain != context.package.domain().id()
        || plans.plans.is_empty()
        || plans.plans.len() > 256
    {
        return Err("qualification operation plans are non-canonical or invalid".into());
    }
    let family = context.package.qualification().family();
    let expected_operations = crate::profile_qualification_adapters::qualification_operation_plan(
        context.package.domain().id(),
    )?;
    let mut expanded = BTreeMap::new();
    for plan in plans.plans {
        if plan.scenario_ids.is_empty()
            || plan.scenario_ids.len() > 256
            || !plan.scenario_ids.windows(2).all(|pair| pair[0] < pair[1])
            || plan.operations.len() != expected_operations.len()
            || !plan.operations.windows(2).all(|pair| {
                (pair[0].role, pair[0].profile.as_str()) < (pair[1].role, pair[1].profile.as_str())
            })
            || plan.operations.iter().any(|operation| {
                !family.contains(&operation.profile)
                    || (!operation.lifecycle_owner && operation.provider_mutation_owner)
            })
            || !plan
                .operations
                .iter()
                .any(|operation| operation.lifecycle_owner)
        {
            return Err("qualification scenario operation plan is invalid".into());
        }
        if plan
            .operations
            .iter()
            .zip(expected_operations)
            .any(|(actual, expected)| {
                (
                    actual.role,
                    actual.profile.as_str(),
                    actual.lifecycle_owner,
                    actual.provider_mutation_owner,
                ) != *expected
            })
        {
            return Err(
                "qualification scenario operation plan differs from its exact static roster".into(),
            );
        }
        for scenario in plan.scenario_ids {
            if roster.binary_search(&scenario).is_err()
                || expanded.insert(scenario, plan.operations.clone()).is_some()
            {
                return Err(
                    "qualification scenario operation plans overlap or name an unknown scenario"
                        .into(),
                );
            }
        }
    }
    if expanded.keys().ne(roster.iter()) {
        return Err(
            "qualification operation plans do not exactly cover the scenario roster".into(),
        );
    }
    Ok(expanded)
}

fn qualify_roster(
    roster: &mut Value,
    record: &QualificationRecord,
    replacing: bool,
) -> Result<(), String> {
    let package = roster
        .get_mut("packages")
        .and_then(Value::as_array_mut)
        .and_then(|packages| {
            packages.iter_mut().find(|package| {
                package.get("domain").and_then(Value::as_str) == Some(record.domain())
            })
        })
        .ok_or_else(|| "attestation domain is missing from roster".to_owned())?;
    let profiles = package
        .get_mut("profiles")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "roster profile family is malformed".to_owned())?;
    for qualified in record.profiles() {
        let subject = qualified.semantic_subject();
        let profile = profiles
            .iter_mut()
            .find(|profile| profile.get("profile").and_then(Value::as_str) == Some(&subject))
            .and_then(Value::as_object_mut)
            .ok_or_else(|| format!("attestation profile is missing from roster: {subject}"))?;
        let state = profile
            .get("state")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("roster profile state is malformed: {subject}"))?;
        let admitted = matches!(
            (replacing, state),
            (true, "qualified") | (false, "unqualified")
        );
        if !admitted {
            return Err(format!(
                "roster launch transition is not admitted for {subject}: {state}"
            ));
        }
        let mut pairs = profile
            .get("targets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .zip(
                profile
                    .get("qualificationIds")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten(),
            )
            .map(|(target, id)| (target.clone(), id.clone()))
            .collect::<Vec<_>>();
        if let Some((_, qualification_id)) = pairs
            .iter_mut()
            .find(|(target, _)| target.as_str() == Some(record.target().as_str()))
        {
            if !replacing {
                return Err(format!("roster target is already qualified: {subject}"));
            }
            *qualification_id = json!(record.qualification_id());
        } else {
            pairs.push((json!(record.target()), json!(record.qualification_id())));
        }
        pairs.sort_by(|left, right| {
            left.0
                .as_str()
                .unwrap_or_default()
                .cmp(right.0.as_str().unwrap_or_default())
        });
        profile.insert("state".into(), json!("qualified"));
        profile.insert(
            "targets".into(),
            Value::Array(pairs.iter().map(|pair| pair.0.clone()).collect()),
        );
        profile.insert(
            "qualificationIds".into(),
            Value::Array(pairs.into_iter().map(|pair| pair.1).collect()),
        );
    }
    Ok(())
}

fn index_identity(value: &Value) -> (String, String) {
    (
        value
            .get("profile")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        value
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    )
}

fn qualify_index(
    index: &mut Value,
    record: &QualificationRecord,
    replacing: bool,
) -> Result<(), String> {
    let entries = index
        .get_mut("entries")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "qualification index entries are malformed".to_owned())?;
    for profile in record.profiles() {
        let subject = profile.semantic_subject();
        if let Some(entry) = entries.iter_mut().find(|entry| {
            entry.get("profile").and_then(Value::as_str) == Some(&subject)
                && entry.get("target").and_then(Value::as_str) == Some(record.target().as_str())
        }) {
            if !replacing {
                return Err("qualification index target already exists".into());
            }
            entry["qualificationId"] = json!(record.qualification_id());
        } else {
            entries.push(json!({
                "profile":subject,
                "target":record.target(),
                "qualificationId":record.qualification_id(),
            }));
        }
    }
    entries.sort_by(|left, right| index_identity(left).cmp(&index_identity(right)));
    Ok(())
}

fn load_roster(repository: &Path) -> Result<ProfileRoster, String> {
    ProfileRoster::from_json(&read_bounded(&repository.join(ROSTER_PATH), 131_072)?)
        .map_err(string_error)
}

fn load_index(repository: &Path) -> Result<QualificationIndex, String> {
    QualificationIndex::from_json(&read_bounded(&repository.join(INDEX_PATH), 262_144)?)
        .map_err(string_error)
}

fn load_trust_registry(repository: &Path) -> Result<QualificationTrustRegistry, String> {
    QualificationTrustRegistry::from_json(&read_bounded(&repository.join(TRUST_PATH), 65_536)?)
        .map_err(string_error)
}

fn load_trust_registry_at(
    repository: &Path,
    revision: &str,
) -> Result<QualificationTrustRegistry, String> {
    QualificationTrustRegistry::from_json(&git_blob(repository, revision, TRUST_PATH, 65_536)?)
        .map_err(string_error)
}

fn load_observer_trust_registry(
    repository: &Path,
) -> Result<QualificationObserverTrustRegistry, String> {
    QualificationObserverTrustRegistry::from_json(&read_bounded(
        &repository.join(OBSERVER_TRUST_PATH),
        65_536,
    )?)
    .map_err(string_error)
}

fn load_evidence_source_trust_registry(
    repository: &Path,
) -> Result<QualificationEvidenceSourceTrustRegistry, String> {
    QualificationEvidenceSourceTrustRegistry::from_json(&read_bounded(
        &repository.join(EVIDENCE_SOURCE_TRUST_PATH),
        262_144,
    )?)
    .map_err(string_error)
}

fn load_evidence_ledger_trust_registry(
    repository: &Path,
) -> Result<QualificationEvidenceLedgerTrustRegistry, String> {
    QualificationEvidenceLedgerTrustRegistry::from_json(&read_bounded(
        &repository.join(EVIDENCE_LEDGER_TRUST_PATH),
        262_144,
    )?)
    .map_err(string_error)
}

fn validate_repository_qualification_key_separation(
    repository: &Path,
    attestation: &QualificationTrustRegistry,
) -> Result<(), String> {
    let observer = load_observer_trust_registry(repository)?;
    let sources = load_evidence_source_trust_registry(repository)?;
    let ledgers = load_evidence_ledger_trust_registry(repository)?;
    validate_qualification_key_separation(
        attestation
            .identities()
            .chain(observer.identities())
            .chain(sources.identities())
            .chain(ledgers.identities()),
    )
    .map_err(string_error)
}

fn validate_complete_qualification_key_separation(
    repository: &Path,
    attestation: &QualificationTrustRegistry,
    observer: &QualificationObserverTrustRegistry,
    receipt_anchor_bytes: &[u8],
    recovery_key_id: &str,
    recovery_public_key_base64url: &str,
) -> Result<(), String> {
    let sources = load_evidence_source_trust_registry(repository)?;
    let ledgers = load_evidence_ledger_trust_registry(repository)?;
    let anchors =
        auths_receipts::decode_receipt_trust_anchors(receipt_anchor_bytes).map_err(string_error)?;
    let recovery =
        QualificationTrustIdentity::parse(recovery_key_id, recovery_public_key_base64url)
            .map_err(string_error)?;
    validate_qualification_key_separation(
        attestation
            .identities()
            .chain(observer.identities())
            .chain(sources.identities())
            .chain(ledgers.identities())
            .chain(anchors.anchors().iter().map(|anchor| {
                QualificationTrustIdentity::new(anchor.key_id(), anchor.public_key_base64url())
            }))
            .chain(std::iter::once(recovery)),
    )
    .map_err(string_error)
}

fn attestation_path(repository: &Path, domain: &str, target: QualificationTarget) -> PathBuf {
    repository
        .join("release/qualification/v1/attestations")
        .join(domain)
        .join(format!("{}.json", target.as_str()))
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt as _;

    #[cfg(unix)]
    let mut file: fs::File = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(string_error)?
    .into();
    #[cfg(not(unix))]
    let mut file = fs::File::open(path).map_err(string_error)?;
    let before = file.metadata().map_err(string_error)?;
    #[cfg(unix)]
    let unsafe_metadata = before.nlink() != 1
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.mode() & 0o022 != 0;
    #[cfg(not(unix))]
    let unsafe_metadata = false;
    if !before.is_file() || before.len() == 0 || before.len() > maximum || unsafe_metadata {
        return Err(format!(
            "input is not a bounded regular file: {}",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(string_error)?;
    let after = file.metadata().map_err(string_error)?;
    #[cfg(unix)]
    let identity_changed = before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.nlink() != after.nlink()
        || before.uid() != after.uid()
        || before.mode() != after.mode();
    #[cfg(not(unix))]
    let identity_changed = false;
    if u64::try_from(bytes.len()).map_err(string_error)? != before.len()
        || before.len() != after.len()
        || identity_changed
    {
        return Err(format!("input changed while reading: {}", path.display()));
    }
    Ok(bytes)
}

struct ImportLock {
    file: fs::File,
}

impl ImportLock {
    fn acquire(repository: &Path) -> Result<Self, String> {
        use std::fs::OpenOptions;
        let path = repository.join(".git/auths-profile-qualification-import.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .map_err(string_error)?;
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "another qualification import owns the repository lock".to_owned())?;
        Ok(Self { file })
    }
}

impl Drop for ImportLock {
    fn drop(&mut self) {
        let _ = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);
    }
}

fn resume_import_transaction(repository: &Path) -> Result<(), String> {
    let transaction_path = repository.join(IMPORT_TRANSACTION_PATH);
    let bytes = read_bounded(&transaction_path, 4_194_304)?;
    let mut transaction: ImportTransaction =
        serde_json::from_slice(&bytes).map_err(string_error)?;
    if serde_json_canonicalizer::to_vec(&transaction).map_err(string_error)? != bytes
        || transaction.schema != "auths.profile-qualification-import-transaction/1"
        || !lower_hex(&transaction.candidate_revision, 40)
        || !lower_hex(&transaction.promotion_base_revision, 40)
        || transaction.promotion_base_revision != git_revision(repository)?
        || !domain_token(&transaction.domain)
        || !transaction.qualification_id.starts_with("qlf_")
        || transaction.qualification_id.len() != 47
        || !transaction.qualification_id[4..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        || !valid_import_outputs(repository, &transaction)?
    {
        return Err("qualification import transaction is malformed".into());
    }

    validate_import_base_snapshots(repository, &transaction)?;

    if transaction.phase == ImportPhase::Rollback {
        rollback_import_outputs(repository, &transaction.outputs)?;
        fs::remove_file(&transaction_path).map_err(string_error)?;
        sync_parent(&transaction_path)?;
        return Err("interrupted qualification import was rolled back".into());
    }

    if let Err(error) = verify_import_transaction(repository, &transaction) {
        return fail_import_transaction(repository, &transaction_path, &mut transaction, error);
    }
    let promoted = (|| {
        for output in &transaction.outputs {
            ensure_import_stage(repository, output)?;
        }
        for output in &transaction.outputs {
            let destination = repository.join(&output.path);
            promote_import_file(
                &staged_import_path(&destination),
                &destination,
                &output.new_sha256,
                import_output_maximum(output.role),
            )?;
        }
        qualification_check_inner(repository, None, false, None)
    })();
    if let Err(error) = promoted {
        return fail_import_transaction(repository, &transaction_path, &mut transaction, error);
    }
    fs::remove_file(&transaction_path).map_err(string_error)?;
    sync_parent(&transaction_path)?;
    println!(
        "imported {}; review and commit the attestation, index, roster, launch projection, and release evidence together",
        transaction.qualification_id
    );
    Ok(())
}

fn fail_import_transaction(
    repository: &Path,
    transaction_path: &Path,
    transaction: &mut ImportTransaction,
    error: String,
) -> Result<(), String> {
    transaction.phase = ImportPhase::Rollback;
    replace_import_intent(transaction_path, transaction)?;
    rollback_import_outputs(repository, &transaction.outputs)?;
    fs::remove_file(transaction_path).map_err(string_error)?;
    sync_parent(transaction_path)?;
    Err(format!(
        "qualification import failed and was rolled back: {error}"
    ))
}

fn replace_import_intent(path: &Path, transaction: &ImportTransaction) -> Result<(), String> {
    let replacement = PathBuf::from(format!("{}.qualification.next", path.display()));
    if replacement.exists() {
        fs::remove_file(&replacement).map_err(string_error)?;
    }
    let bytes = serde_json_canonicalizer::to_vec(transaction).map_err(string_error)?;
    atomic_write_new(&replacement, &bytes)?;
    fs::rename(&replacement, path).map_err(string_error)?;
    sync_parent(path)
}

fn import_intent_stage_path(repository: &Path) -> PathBuf {
    PathBuf::from(format!(
        "{}.qualification.staged",
        repository.join(IMPORT_TRANSACTION_PATH).display()
    ))
}

fn cleanup_orphan_import_intent_stage(repository: &Path) -> Result<(), String> {
    let staged = import_intent_stage_path(repository);
    if staged.exists() {
        fs::remove_file(&staged).map_err(string_error)?;
        sync_parent(&staged)?;
    }
    Ok(())
}

fn publish_import_intent(repository: &Path, transaction: &ImportTransaction) -> Result<(), String> {
    let destination = repository.join(IMPORT_TRANSACTION_PATH);
    if destination.exists() {
        return Err("qualification import intent already exists".into());
    }
    cleanup_orphan_import_intent_stage(repository)?;
    let staged = import_intent_stage_path(repository);
    let bytes = serde_json_canonicalizer::to_vec(transaction).map_err(string_error)?;
    atomic_write_new(&staged, &bytes)?;
    fs::rename(&staged, &destination).map_err(string_error)?;
    sync_parent(&destination)
}

fn import_output(
    repository: &Path,
    role: ImportOutputRole,
    path: &str,
    new_bytes: &[u8],
    maximum: u64,
) -> Result<ImportOutput, String> {
    if !safe_relative_path(path) || u64::try_from(new_bytes.len()).map_err(string_error)? > maximum
    {
        return Err("qualification import output is unsafe or oversized".into());
    }
    let destination = repository.join(path);
    let old_bytes = if destination.exists() {
        Some(read_bounded(&destination, maximum)?)
    } else {
        None
    };
    Ok(ImportOutput {
        role,
        path: path.into(),
        old_sha256: old_bytes
            .as_ref()
            .map(|bytes| hex::encode(Sha256::digest(bytes))),
        old_bytes_hex: old_bytes.as_ref().map(hex::encode),
        new_sha256: hex::encode(Sha256::digest(new_bytes)),
        new_bytes_hex: hex::encode(new_bytes),
    })
}

fn valid_import_outputs(
    repository: &Path,
    transaction: &ImportTransaction,
) -> Result<bool, String> {
    let attestation = attestation_path(repository, &transaction.domain, transaction.target);
    let attestation = attestation.strip_prefix(repository).map_err(string_error)?;
    let expected = [
        (ImportOutputRole::Attestation, attestation),
        (ImportOutputRole::Index, Path::new(INDEX_PATH)),
        (
            ImportOutputRole::LaunchProjection,
            Path::new(LAUNCH_PROJECTION_PATH),
        ),
        (ImportOutputRole::Roster, Path::new(ROSTER_PATH)),
    ];
    if transaction.outputs.len() != expected.len() {
        return Ok(false);
    }
    for (output, (role, path)) in transaction.outputs.iter().zip(expected) {
        let maximum = import_output_maximum(role);
        let new = hex::decode(&output.new_bytes_hex).map_err(string_error)?;
        let old = output
            .old_bytes_hex
            .as_deref()
            .map(hex::decode)
            .transpose()
            .map_err(string_error)?;
        let old_digest = old.as_ref().map(|bytes| hex::encode(Sha256::digest(bytes)));
        if output.role != role
            || Path::new(&output.path) != path
            || !safe_relative_path(&output.path)
            || !lower_hex(&output.new_sha256, 64)
            || hex::encode(Sha256::digest(&new)) != output.new_sha256
            || u64::try_from(new.len()).map_err(string_error)? > maximum
            || output.old_sha256.is_some() != old.is_some()
            || old.as_ref().is_some_and(|bytes| {
                u64::try_from(bytes.len()).map_or(true, |length| length > maximum)
                    || output.old_sha256.as_deref() != old_digest.as_deref()
            })
        {
            return Ok(false);
        }
        let destination = repository.join(&output.path);
        if destination.exists() {
            let digest = file_sha256(&destination, maximum)?;
            if digest != output.new_sha256 && output.old_sha256.as_deref() != Some(digest.as_str())
            {
                return Err(format!(
                    "qualification import destination changed unexpectedly: {}",
                    destination.display()
                ));
            }
        } else if output.old_sha256.is_some() {
            return Err(format!(
                "qualification import destination disappeared: {}",
                destination.display()
            ));
        }
    }
    Ok(true)
}

fn verify_import_transaction(
    repository: &Path,
    transaction: &ImportTransaction,
) -> Result<(), String> {
    validate_import_base_snapshots(repository, transaction)?;
    let attestation = transaction
        .outputs
        .iter()
        .find(|output| output.role == ImportOutputRole::Attestation)
        .ok_or_else(|| "qualification import attestation output is missing".to_owned())?;
    let attestation_bytes = hex::decode(&attestation.new_bytes_hex).map_err(string_error)?;
    let registry = load_trust_registry_at(repository, &transaction.promotion_base_revision)?;
    let verified =
        QualificationAttestation::verify_json(&attestation_bytes, &registry, now_unix_seconds()?)
            .map_err(string_error)?;
    let record = verified.record();
    if record.candidate_revision() != transaction.candidate_revision
        || record.domain() != transaction.domain
        || record.target() != transaction.target
        || record.qualification_id() != transaction.qualification_id
    {
        return Err("qualification import record no longer matches its immutable intent".into());
    }
    validate_promotion_base(repository, record, &transaction.promotion_base_revision)?;
    verify_record_against_revision(repository, record, &transaction.candidate_revision)?;
    verify_record_against_revision(repository, record, &transaction.promotion_base_revision)?;

    let replacing = if let Some(old) = attestation.old_bytes_hex.as_deref() {
        let old = hex::decode(old).map_err(string_error)?;
        let parsed = QualificationAttestation::from_json(&old).map_err(string_error)?;
        let completed = parsed.record().completed_at_unix_seconds();
        validate_historical_record_ancestry(
            repository,
            parsed.record(),
            &transaction.promotion_base_revision,
        )?;
        let old_registry =
            load_trust_registry_at(repository, parsed.record().candidate_revision())?;
        let old = QualificationAttestation::verify_json(&old, &old_registry, completed)
            .map_err(string_error)?;
        validate_prior_qualification_binding(
            repository,
            &transaction.promotion_base_revision,
            old.record(),
        )?;
        validate_monotonic_replacement(old.record(), record)?;
        true
    } else {
        false
    };

    let roster_output = transaction
        .outputs
        .iter()
        .find(|output| output.role == ImportOutputRole::Roster)
        .ok_or_else(|| "qualification import roster output is missing".to_owned())?;
    let roster_bytes = hex::decode(&roster_output.new_bytes_hex).map_err(string_error)?;
    let roster = ProfileRoster::from_json(&roster_bytes).map_err(string_error)?;
    let mut expected_roster: Value = serde_json::from_slice(
        &hex::decode(
            roster_output
                .old_bytes_hex
                .as_deref()
                .ok_or_else(|| "qualification base roster is missing".to_owned())?,
        )
        .map_err(string_error)?,
    )
    .map_err(string_error)?;
    qualify_roster(&mut expected_roster, record, replacing)?;
    if serde_json::to_vec_pretty(&expected_roster).map_err(string_error)? != roster_bytes {
        return Err("qualification staged roster is not the exact record projection".into());
    }
    let expected_projection = expected_profile_launch_projection(repository, &roster)?;
    let projection = transaction
        .outputs
        .iter()
        .find(|output| output.role == ImportOutputRole::LaunchProjection)
        .ok_or_else(|| "qualification import launch projection is missing".to_owned())?;
    if projection.new_bytes_hex != hex::encode(expected_projection.as_bytes()) {
        return Err(
            "qualification import launch projection does not match the staged roster".into(),
        );
    }
    let index = transaction
        .outputs
        .iter()
        .find(|output| output.role == ImportOutputRole::Index)
        .ok_or_else(|| "qualification import index output is missing".to_owned())?;
    let index_bytes = hex::decode(&index.new_bytes_hex).map_err(string_error)?;
    QualificationIndex::from_json(&index_bytes).map_err(string_error)?;
    let mut expected_index: Value = serde_json::from_slice(
        &hex::decode(
            index
                .old_bytes_hex
                .as_deref()
                .ok_or_else(|| "qualification base index is missing".to_owned())?,
        )
        .map_err(string_error)?,
    )
    .map_err(string_error)?;
    qualify_index(&mut expected_index, record, replacing)?;
    if serde_json_canonicalizer::to_vec(&expected_index).map_err(string_error)? != index_bytes {
        return Err("qualification staged index is not the exact record projection".into());
    }
    Ok(())
}

fn validate_import_base_snapshots(
    repository: &Path,
    transaction: &ImportTransaction,
) -> Result<(), String> {
    for output in &transaction.outputs {
        let expected = git_blob_optional(
            repository,
            &transaction.promotion_base_revision,
            &output.path,
            import_output_maximum(output.role),
        )?;
        let retained = output
            .old_bytes_hex
            .as_deref()
            .map(hex::decode)
            .transpose()
            .map_err(string_error)?;
        if retained != expected {
            return Err(format!(
                "qualification import base snapshot differs from {}",
                output.path
            ));
        }
    }
    Ok(())
}

fn ensure_import_stage(repository: &Path, output: &ImportOutput) -> Result<(), String> {
    let destination = repository.join(&output.path);
    let staged = staged_import_path(&destination);
    if staged.exists() {
        return if file_sha256(&staged, import_output_maximum(output.role))? == output.new_sha256 {
            Ok(())
        } else {
            Err(format!(
                "qualification import stage is corrupt: {}",
                staged.display()
            ))
        };
    }
    let bytes = hex::decode(&output.new_bytes_hex).map_err(string_error)?;
    stage_import_file(&staged, &bytes)
}

fn rollback_import_outputs(repository: &Path, outputs: &[ImportOutput]) -> Result<(), String> {
    for output in outputs.iter().rev() {
        let destination = repository.join(&output.path);
        match output.old_bytes_hex.as_deref() {
            Some(bytes) => {
                let bytes = hex::decode(bytes).map_err(string_error)?;
                let already_old = destination.exists()
                    && file_sha256(&destination, import_output_maximum(output.role))?
                        == output.old_sha256.as_deref().unwrap_or_default();
                if !already_old {
                    let rollback = rollback_import_path(&destination);
                    if rollback.exists() {
                        fs::remove_file(&rollback).map_err(string_error)?;
                    }
                    stage_import_file(&rollback, &bytes)?;
                    fs::rename(&rollback, &destination).map_err(string_error)?;
                    sync_parent(&destination)?;
                }
            }
            None if destination.exists() => {
                if file_sha256(&destination, import_output_maximum(output.role))?
                    != output.new_sha256
                {
                    return Err(format!(
                        "qualification import cannot remove an unexpected destination: {}",
                        destination.display()
                    ));
                }
                fs::remove_file(&destination).map_err(string_error)?;
                sync_parent(&destination)?;
            }
            None => {}
        }
        let staged = staged_import_path(&destination);
        if staged.exists() {
            fs::remove_file(&staged).map_err(string_error)?;
            sync_parent(&staged)?;
        }
        let rollback = rollback_import_path(&destination);
        if rollback.exists() {
            fs::remove_file(&rollback).map_err(string_error)?;
            sync_parent(&rollback)?;
        }
    }
    Ok(())
}

const fn import_output_maximum(role: ImportOutputRole) -> u64 {
    match role {
        ImportOutputRole::Attestation => 266_240,
        ImportOutputRole::Index => 262_144,
        ImportOutputRole::LaunchProjection => 65_536,
        ImportOutputRole::Roster => 131_072,
    }
}

fn stage_import_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(string_error)?;
    }
    atomic_write_new(path, bytes)
}

fn promote_import_file(
    staged: &Path,
    destination: &Path,
    expected_sha256: &str,
    maximum: u64,
) -> Result<(), String> {
    if destination.exists() && file_sha256(destination, maximum)? == expected_sha256 {
        if staged.exists() {
            fs::remove_file(staged).map_err(string_error)?;
            sync_parent(staged)?;
        }
        return Ok(());
    }
    if !staged.exists() || file_sha256(staged, maximum)? != expected_sha256 {
        return Err(format!(
            "qualification import stage is missing or corrupt: {}",
            staged.display()
        ));
    }
    if destination.exists() {
        let metadata = fs::symlink_metadata(destination).map_err(string_error)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("qualification import refuses a non-regular destination".into());
        }
    }
    fs::rename(staged, destination).map_err(string_error)?;
    sync_parent(destination)
}

fn file_sha256(path: &Path, maximum: u64) -> Result<String, String> {
    read_bounded(path, maximum).map(|bytes| hex::encode(Sha256::digest(bytes)))
}

fn staged_import_path(destination: &Path) -> PathBuf {
    PathBuf::from(format!("{}.qualification.staged", destination.display()))
}

fn rollback_import_path(destination: &Path) -> PathBuf {
    PathBuf::from(format!("{}.qualification.rollback", destination.display()))
}

fn sync_parent(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "durable output has no parent directory".to_owned())?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(string_error)
}

fn atomic_write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::fs::OpenOptions;
    use std::io::Write as _;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(string_error)?;
    file.write_all(bytes).map_err(string_error)?;
    file.sync_all().map_err(string_error)?;
    drop(file);
    sync_parent(path)
}

fn atomic_write_new_owner_only(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(string_error)?;
    file.write_all(bytes).map_err(string_error)?;
    file.sync_all().map_err(string_error)?;
    drop(file);
    sync_parent(path)
}

fn git_revision(repository: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repository)
        .output()
        .map_err(string_error)?;
    if !output.status.success() {
        return Err("cannot resolve candidate Git revision".into());
    }
    let value = String::from_utf8(output.stdout)
        .map_err(string_error)?
        .trim()
        .to_owned();
    if !lower_hex(&value, 40) {
        return Err("candidate Git revision is not 40 lowercase hexadecimal bytes".into());
    }
    Ok(value)
}

fn git_clean(repository: &Path) -> Result<bool, String> {
    let output = Command::new("git")
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .current_dir(repository)
        .output()
        .map_err(string_error)?;
    Ok(output.status.success() && output.stdout.is_empty())
}

fn now_unix_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(string_error)
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn canonical_decimal(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

fn canonical_semver_triplet(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 3 && parts.iter().all(|part| canonical_decimal(part, 10))
}

fn domain_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn registered_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && !value.contains('\\')
        && !value.contains('\0')
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn string_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, rc::Rc};

    struct PhaseTestAdapter {
        wrong_phase: Option<u8>,
        fail_phase: Option<u8>,
        skip_preflight_retention: bool,
    }

    #[derive(Default)]
    struct PhaseTestEnvironment {
        prepared: bool,
        calls: Vec<u8>,
    }

    impl QualificationCollectionAdapter for PhaseTestAdapter {
        type Environment = PhaseTestEnvironment;

        fn metadata(&self) -> auths_profile_kit::QualificationAdapterMetadata {
            auths_profile_kit::QualificationAdapterMetadata {
                domain: "example",
                family: &["auths.example.effect/1", "auths.example.preflight/1"],
                targets: &[QualificationTarget::LinuxX86_64],
                protected_environment: "qualification-test",
                scenarios: &["happy-path"],
            }
        }

        fn open(
            &self,
            _context: &auths_profile_kit::QualificationRunContext,
            _handoff: &auths_profile_kit::QualificationSetupHandoffV1,
        ) -> Result<Self::Environment, auths_profile_kit::QualificationHarnessError> {
            Ok(PhaseTestEnvironment::default())
        }

        fn invoke_phase(
            &self,
            environment: &mut Self::Environment,
            _client: &QualificationPhaseClient,
            _connection_alias: &str,
            _vector: &auths_profile_kit::QualificationVector,
            phase_index: u8,
            role: auths_profile_kit::QualificationOperationRole,
            profile: &str,
        ) -> Result<
            auths_profile_kit::QualificationCollectedOperation,
            auths_profile_kit::QualificationHarnessError,
        > {
            environment.calls.push(phase_index);
            if self.fail_phase == Some(phase_index) {
                return Err(
                    auths_profile_kit::QualificationHarnessError::PrerequisiteUnavailable(
                        "synthetic phase failure",
                    ),
                );
            }
            if phase_index == 1 {
                if !self.skip_preflight_retention {
                    environment.prepared = true;
                }
            } else if !environment.prepared {
                return Err(
                    auths_profile_kit::QualificationHarnessError::PrerequisiteUnavailable(
                        "effect has no retained preflight",
                    ),
                );
            }
            let actual_profile = if self.wrong_phase == Some(phase_index) {
                "auths.example.wrong/1"
            } else {
                profile
            };
            Ok(denied_phase(role, actual_profile, phase_index))
        }
    }

    struct PhaseTestRuntime {
        log: Rc<RefCell<Vec<String>>>,
    }

    struct PhaseTestGuard {
        client: QualificationPhaseClient,
        log: Rc<RefCell<Vec<String>>>,
        phase_index: u8,
        completed: bool,
    }

    impl ProtectedPhaseRuntime for PhaseTestRuntime {
        type Guard = PhaseTestGuard;

        fn enter(
            &mut self,
            _vector: &auths_profile_kit::QualificationVector,
            phase_index: u8,
            _planned: &QualificationPlannedOperation,
        ) -> Result<Self::Guard, String> {
            self.log.borrow_mut().push(format!("enter-{phase_index}"));
            Ok(PhaseTestGuard {
                client: QualificationPhaseClient::new(
                    "/run/auths/client.sock".into(),
                    "/run/auths/result.sock".into(),
                )
                .unwrap(),
                log: Rc::clone(&self.log),
                phase_index,
                completed: false,
            })
        }
    }

    impl ProtectedPhaseGuard for PhaseTestGuard {
        fn client(&self) -> &QualificationPhaseClient {
            &self.client
        }

        fn complete(&mut self) -> Result<(), String> {
            self.log
                .borrow_mut()
                .push(format!("complete-{}", self.phase_index));
            self.completed = true;
            Ok(())
        }
    }

    impl Drop for PhaseTestGuard {
        fn drop(&mut self) {
            if !self.completed {
                self.log
                    .borrow_mut()
                    .push(format!("abort-{}", self.phase_index));
            }
        }
    }

    fn denied_phase(
        role: auths_profile_kit::QualificationOperationRole,
        profile: &str,
        _phase_index: u8,
    ) -> auths_profile_kit::QualificationCollectedOperation {
        auths_profile_kit::QualificationCollectedOperation {
            role,
            profile: profile.into(),
        }
    }

    fn two_phase_plan() -> BTreeMap<String, Vec<QualificationPlannedOperation>> {
        BTreeMap::from([(
            "happy-path".into(),
            vec![
                QualificationPlannedOperation {
                    lifecycle_owner: true,
                    profile: "auths.example.preflight/1".into(),
                    provider_mutation_owner: false,
                    role: auths_profile_kit::QualificationOperationRole::Preflight,
                },
                QualificationPlannedOperation {
                    lifecycle_owner: true,
                    profile: "auths.example.effect/1".into(),
                    provider_mutation_owner: true,
                    role: auths_profile_kit::QualificationOperationRole::Effect,
                },
            ],
        )])
    }

    fn happy_path_vectors() -> Vec<auths_profile_kit::QualificationVector> {
        vec![auths_profile_kit::QualificationVector {
            id: "happy-path".into(),
            input: Vec::new(),
            failpoint: None,
        }]
    }

    #[test]
    fn common_harness_closes_each_protected_phase_before_starting_the_next() {
        let adapter = PhaseTestAdapter {
            wrong_phase: None,
            fail_phase: None,
            skip_preflight_retention: false,
        };
        let mut environment = PhaseTestEnvironment::default();
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut runtime = PhaseTestRuntime {
            log: Rc::clone(&log),
        };
        let scenarios = run_domain_vectors(
            &adapter,
            &mut environment,
            "connection",
            "provider-run",
            happy_path_vectors(),
            &two_phase_plan(),
            &mut runtime,
        )
        .unwrap();
        assert_eq!(environment.calls, [1, 2]);
        assert_eq!(scenarios[0].operations.len(), 2);
        assert_eq!(
            log.borrow().as_slice(),
            ["enter-1", "complete-1", "enter-2", "complete-2"]
        );
    }

    #[test]
    fn phase_failure_or_identity_drift_never_starts_the_next_phase() {
        for adapter in [
            PhaseTestAdapter {
                wrong_phase: None,
                fail_phase: Some(1),
                skip_preflight_retention: false,
            },
            PhaseTestAdapter {
                wrong_phase: Some(1),
                fail_phase: None,
                skip_preflight_retention: false,
            },
        ] {
            let mut environment = PhaseTestEnvironment::default();
            let log = Rc::new(RefCell::new(Vec::new()));
            let mut runtime = PhaseTestRuntime {
                log: Rc::clone(&log),
            };
            assert!(
                run_domain_vectors(
                    &adapter,
                    &mut environment,
                    "connection",
                    "provider-run",
                    happy_path_vectors(),
                    &two_phase_plan(),
                    &mut runtime,
                )
                .is_err()
            );
            assert_eq!(environment.calls, [1]);
            assert_eq!(log.borrow().as_slice(), ["enter-1", "abort-1"]);
        }
    }

    #[test]
    fn effect_phase_requires_the_adapter_to_retain_its_preflight_capability() {
        let adapter = PhaseTestAdapter {
            wrong_phase: None,
            fail_phase: None,
            skip_preflight_retention: true,
        };
        let mut environment = PhaseTestEnvironment::default();
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut runtime = PhaseTestRuntime {
            log: Rc::clone(&log),
        };
        assert!(
            run_domain_vectors(
                &adapter,
                &mut environment,
                "connection",
                "provider-run",
                happy_path_vectors(),
                &two_phase_plan(),
                &mut runtime,
            )
            .is_err()
        );
        assert_eq!(environment.calls, [1, 2]);
        assert_eq!(
            log.borrow().as_slice(),
            ["enter-1", "complete-1", "enter-2", "abort-2"]
        );
    }

    #[test]
    fn protected_workflow_starts_and_verifies_sources_before_collection() {
        let workflow = include_str!("../../.github/workflows/profile-qualification.yml");
        let services = include_str!("../../.github/scripts/qualification-row-services.sh");
        let appender = workflow
            .find("Start the sole protected append session")
            .unwrap();
        let readers = workflow
            .find("Start and authenticate every no-seed ordinary row reader")
            .unwrap();
        let collection = workflow.find("Collect every exact provider row").unwrap();
        assert!(appender < readers && readers < collection);
        assert!(!services.contains("verify-source-seed"));
        for role in [
            "SUPERVISOR",
            "CLIENT_PROXY",
            "JOURNAL_READER",
            "CREDENTIAL_BROKER",
            "PROFILE_STATE_READER",
            "RECEIPT_VERIFIER",
        ] {
            let slot = format!("QUALIFICATION_SOURCE_{role}_SEED");
            assert_eq!(workflow.matches(&slot).count(), 1, "{slot}");
        }
        assert!(!workflow[..collection].contains("profile qualification collect"));
    }

    #[cfg(unix)]
    #[test]
    fn ledger_plan_output_retains_the_exact_private_directory_handle() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let repository = tempfile::tempdir().unwrap();
        fs::set_permissions(repository.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let relative = Path::new("target/common/stripe-test");
        let directory = create_private_output_directory_fd(repository.path(), relative).unwrap();
        assert_eq!(
            directory.metadata().unwrap().permissions().mode() & 0o777,
            0o700
        );
        write_new_owner_only_at(&directory, Path::new("ledger-plan.json"), b"plan").unwrap();
        assert_eq!(
            fs::read(repository.path().join(relative).join("ledger-plan.json")).unwrap(),
            b"plan"
        );
        assert!(
            write_new_owner_only_at(&directory, Path::new("ledger-plan.json"), b"drift").is_err()
        );

        let loose = repository.path().join("loose");
        fs::create_dir(&loose).unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(create_private_output_directory_fd(repository.path(), Path::new("loose")).is_err());

        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), repository.path().join("linked")).unwrap();
        assert!(
            create_private_output_directory_fd(repository.path(), Path::new("linked/escape"))
                .is_err()
        );
    }

    #[test]
    fn no_secret_verifier_rejects_secret_slot_names() {
        for name in [
            "AUTHS_QUALIFICATION_ATTESTATION_SEED",
            "POSTGRESQL_QUALIFICATION_OBSERVER_CREDENTIAL",
            "QUALIFICATION_PRIVATE_KEY",
            "GITHUB_TOKEN",
        ] {
            assert!(secret_bearing_environment_name(name), "{name}");
        }
        for name in [
            "GITHUB_RUN_ID",
            "QUALIFICATION_ARTIFACT_ID",
            "QUALIFICATION_CANDIDATE_REVISION",
        ] {
            assert!(!secret_bearing_environment_name(name), "{name}");
        }
    }

    #[test]
    fn typed_scanner_detects_raw_provider_and_secret_fields() {
        assert!(json_has_forbidden_field(
            &json!({"domainFacts":{"paymentIntentId":"pi_raw"}}),
            &[
                "accountId",
                "appliedMarker",
                "authorization",
                "credential",
                "database",
                "ledgerOperationId",
                "password",
                "paymentIntentId",
                "privateKey",
                "recoveryHandle",
                "refundId",
                "resourceReferences",
                "secret",
                "seed",
                "stateLineage",
                "transactionId",
            ]
        ));
        assert!(json_has_forbidden_field(
            &json!({"recovery_handle":"sealed-capability"}),
            &["recoveryHandle"]
        ));
        assert!(json_has_forbidden_field(
            &json!({"private_key":"seed"}),
            &["privateKey"]
        ));
        assert!(!json_has_forbidden_field(
            &json!({"domainFacts":{"paymentIntentSha256":"a".repeat(64)}}),
            &["paymentIntentId"]
        ));
        assert!(contains_unredacted_provider_identifier(
            br#"{"safeField":"pi_raw-provider-identifier"}"#,
            &["pi_"]
        ));
        assert!(contains_unredacted_provider_identifier(
            b"\x71pi_raw-provider-identifier",
            &["pi_"]
        ));
        assert!(!contains_unredacted_provider_identifier(
            br#"{"paymentIntentSha256":"aaaaaaaa"}"#,
            &["pi_"]
        ));
    }

    fn canonical_line(value: &Value) -> Vec<u8> {
        let mut bytes = serde_json_canonicalizer::to_vec(value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn launch_profile_value(profile: &str, state: &str, testkit_available: bool) -> Value {
        let qualified = state == "qualified";
        json!({
            "profile": profile,
            "qualificationIds": if qualified { vec![format!("qlf_{}", "A".repeat(43))] } else { Vec::<String>::new() },
            "semanticClosureSha256": if qualified { Some("a".repeat(64)) } else { None },
            "state": state,
            "targets": if qualified { vec!["linux-x86_64"] } else { Vec::<&str>::new() },
            "testkitAvailable": testkit_available,
        })
    }

    fn launch_projection(profiles: Vec<Value>) -> Value {
        json!({"profiles": profiles, "schema": "auths.profile-launch-projection/1"})
    }

    #[test]
    fn launch_projection_normalization_is_strict_and_preserves_testkit() {
        let qualified = launch_projection(vec![launch_profile_value(
            "auths.example.effect/1",
            "qualified",
            true,
        )]);
        let unqualified = launch_projection(vec![launch_profile_value(
            "auths.example.effect/1",
            "unqualified",
            true,
        )]);
        assert_eq!(
            normalize_launch_projection(&canonical_line(&qualified)).unwrap(),
            serde_json_canonicalizer::to_vec(&unqualified).unwrap()
        );

        let mut noncanonical = canonical_line(&unqualified);
        noncanonical.insert(0, b' ');
        assert!(normalize_launch_projection(&noncanonical).is_err());

        let mut unknown = unqualified.clone();
        unknown["profiles"][0]["unknown"] = json!(true);
        assert!(normalize_launch_projection(&canonical_line(&unknown)).is_err());

        let missing = launch_projection(vec![json!({
            "profile": "auths.example.effect/1",
            "qualificationIds": [],
            "state": "unqualified",
            "targets": [],
            "testkitAvailable": false,
        })]);
        assert!(normalize_launch_projection(&canonical_line(&missing)).is_err());

        let reordered = launch_projection(vec![
            launch_profile_value("auths.example.second/1", "unqualified", false),
            launch_profile_value("auths.example.first/1", "unqualified", false),
        ]);
        assert!(normalize_launch_projection(&canonical_line(&reordered)).is_err());

        let mut duplicate_id = qualified.clone();
        duplicate_id["profiles"][0]["targets"] = json!(["linux-aarch64", "linux-x86_64"]);
        let id = format!("qlf_{}", "A".repeat(43));
        duplicate_id["profiles"][0]["qualificationIds"] = json!([id.clone(), id]);
        assert!(normalize_launch_projection(&canonical_line(&duplicate_id)).is_err());

        let maximum = (0..64)
            .map(|index| {
                launch_profile_value(
                    &format!("auths.example.effect{index:02}/1"),
                    "unqualified",
                    false,
                )
            })
            .collect::<Vec<_>>();
        assert!(
            normalize_launch_projection(&canonical_line(&launch_projection(maximum.clone())))
                .is_ok()
        );
        let mut too_many = maximum;
        too_many.push(launch_profile_value(
            "auths.example.effect64/1",
            "unqualified",
            false,
        ));
        assert!(
            normalize_launch_projection(&canonical_line(&launch_projection(too_many))).is_err()
        );
    }

    #[test]
    fn launch_projection_must_exactly_match_the_roster() {
        let repository = root();
        let roster_bytes = fs::read(repository.join(ROSTER_PATH)).unwrap();
        let roster = ProfileRoster::from_json(&roster_bytes).unwrap();
        let expected = expected_profile_launch_projection(&repository, &roster).unwrap();
        let actual = fs::read(repository.join(LAUNCH_PROJECTION_PATH)).unwrap();
        assert_eq!(actual, expected.as_bytes());

        let mut changed: Value = serde_json::from_slice(&roster_bytes).unwrap();
        let stripe = changed["packages"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|package| package["domain"] == "stripe")
            .unwrap();
        stripe["profiles"][0]["testkitAvailable"] = json!(false);
        let changed = serde_json_canonicalizer::to_vec(&changed).unwrap();
        let changed = ProfileRoster::from_json(&changed).unwrap();
        assert_ne!(
            actual,
            expected_profile_launch_projection(&repository, &changed)
                .unwrap()
                .as_bytes()
        );
    }

    #[test]
    fn import_outputs_rollback_every_partial_promotion_prefix() {
        for promoted_count in 0..=4 {
            let directory = tempfile::tempdir().unwrap();
            let repository = directory.path();
            let specifications = [
                (ImportOutputRole::Attestation, "attestation.json", None),
                (
                    ImportOutputRole::Index,
                    "index.json",
                    Some(b"old-index".as_slice()),
                ),
                (
                    ImportOutputRole::LaunchProjection,
                    "launch.json",
                    Some(b"old-launch".as_slice()),
                ),
                (
                    ImportOutputRole::Roster,
                    "roster.json",
                    Some(b"old-roster".as_slice()),
                ),
            ];
            for (_, path, old) in specifications {
                if let Some(old) = old {
                    fs::write(repository.join(path), old).unwrap();
                }
            }
            let outputs = specifications
                .iter()
                .enumerate()
                .map(|(index, (role, path, _))| {
                    import_output(
                        repository,
                        *role,
                        path,
                        format!("new-{index}").as_bytes(),
                        import_output_maximum(*role),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            for output in &outputs {
                ensure_import_stage(repository, output).unwrap();
            }
            for output in outputs.iter().take(promoted_count) {
                let destination = repository.join(&output.path);
                promote_import_file(
                    &staged_import_path(&destination),
                    &destination,
                    &output.new_sha256,
                    import_output_maximum(output.role),
                )
                .unwrap();
            }
            rollback_import_outputs(repository, &outputs).unwrap();
            for (role, path, old) in specifications {
                let destination = repository.join(path);
                match old {
                    Some(old) => assert_eq!(fs::read(&destination).unwrap(), old),
                    None => assert!(!destination.exists()),
                }
                assert!(!staged_import_path(&destination).exists());
                assert!(!rollback_import_path(&destination).exists());
                let _ = role;
            }
        }
    }

    fn git(directory: &Path, arguments: &[&str]) {
        let status = Command::new("git")
            .args(arguments)
            .current_dir(directory)
            .status()
            .unwrap();
        assert!(status.success(), "git {arguments:?} failed");
    }

    #[test]
    fn immutable_closure_ignores_untracked_caches_and_rejects_tracked_caches() {
        let directory = tempfile::tempdir().unwrap();
        git(directory.path(), &["init", "--quiet"]);
        fs::create_dir_all(directory.path().join("src/__pycache__")).unwrap();
        fs::write(directory.path().join("src/main.py"), b"print('reviewed')\n").unwrap();
        fs::write(
            directory.path().join("src/__pycache__/main.pyc"),
            b"transient",
        )
        .unwrap();
        git(directory.path(), &["add", "src/main.py"]);
        git(
            directory.path(),
            &[
                "-c",
                "user.name=Qualification Test",
                "-c",
                "user.email=qualification@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                "reviewed source",
            ],
        );
        let revision = git_revision(directory.path()).unwrap();
        let files = collect_git_files(
            directory.path(),
            &revision,
            &["src".into()],
            &[],
            &["__pycache__".into()],
            &[".pyc".into()],
            1_024,
        )
        .unwrap();
        assert_eq!(
            files.keys().map(String::as_str).collect::<Vec<_>>(),
            ["src/main.py"]
        );

        git(directory.path(), &["add", "src/__pycache__/main.pyc"]);
        git(
            directory.path(),
            &[
                "-c",
                "user.name=Qualification Test",
                "-c",
                "user.email=qualification@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                "bad tracked cache",
            ],
        );
        let revision = git_revision(directory.path()).unwrap();
        assert!(
            collect_git_files(
                directory.path(),
                &revision,
                &["src".into()],
                &[],
                &["__pycache__".into()],
                &[".pyc".into()],
                1_024,
            )
            .unwrap_err()
            .contains("cannot be hidden")
        );
    }

    #[test]
    fn immutable_git_lookup_distinguishes_absent_paths_from_invalid_revisions() {
        let repository = root();
        let revision = git_revision(&repository).unwrap();
        assert!(
            git_blob_optional(&repository, &revision, "Cargo.toml", 131_072)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            git_blob_optional(
                &repository,
                &revision,
                "release/qualification/v1/attestations/absent/linux-x86_64.json",
                266_240,
            )
            .unwrap(),
            None
        );
        assert!(git_blob_optional(&repository, &"0".repeat(40), "Cargo.toml", 131_072).is_err());
    }

    #[test]
    fn import_intent_is_published_only_after_a_complete_staged_write() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir_all(directory.path().join("release/qualification/v1")).unwrap();
        let transaction = ImportTransaction {
            schema: "auths.profile-qualification-import-transaction/1".into(),
            candidate_revision: "a".repeat(40),
            promotion_base_revision: "a".repeat(40),
            domain: "stripe".into(),
            target: QualificationTarget::LinuxX86_64,
            qualification_id: format!("qlf_{}", "A".repeat(43)),
            phase: ImportPhase::Promote,
            outputs: Vec::new(),
        };
        publish_import_intent(directory.path(), &transaction).unwrap();
        let destination = directory.path().join(IMPORT_TRANSACTION_PATH);
        assert_eq!(
            fs::read(&destination).unwrap(),
            serde_json_canonicalizer::to_vec(&transaction).unwrap()
        );
        assert!(!import_intent_stage_path(directory.path()).exists());
    }

    #[test]
    fn invalid_base_snapshot_never_enters_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let repository = directory.path();
        git(repository, &["init", "--quiet"]);
        for path in [INDEX_PATH, LAUNCH_PROJECTION_PATH, ROSTER_PATH] {
            let destination = repository.join(path);
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::write(destination, format!("old-{path}")).unwrap();
        }
        git(repository, &["add", "release", "product"]);
        git(
            repository,
            &[
                "-c",
                "user.name=Qualification Test",
                "-c",
                "user.email=qualification@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                "qualification base",
            ],
        );
        let revision = git_revision(repository).unwrap();
        let attestation_path =
            attestation_path(repository, "stripe", QualificationTarget::LinuxX86_64);
        fs::create_dir_all(attestation_path.parent().unwrap()).unwrap();
        let attestation_relative = attestation_path
            .strip_prefix(repository)
            .unwrap()
            .to_str()
            .unwrap();
        let malicious_old = b"attacker-selected-old";
        let attestation_new = b"new-attestation";
        let mut outputs = vec![ImportOutput {
            role: ImportOutputRole::Attestation,
            path: attestation_relative.into(),
            old_sha256: Some(hex::encode(Sha256::digest(malicious_old))),
            old_bytes_hex: Some(hex::encode(malicious_old)),
            new_sha256: hex::encode(Sha256::digest(attestation_new)),
            new_bytes_hex: hex::encode(attestation_new),
        }];
        for (role, path, maximum) in [
            (ImportOutputRole::Index, INDEX_PATH, 262_144),
            (
                ImportOutputRole::LaunchProjection,
                LAUNCH_PROJECTION_PATH,
                65_536,
            ),
            (ImportOutputRole::Roster, ROSTER_PATH, 131_072),
        ] {
            outputs.push(
                import_output(
                    repository,
                    role,
                    path,
                    format!("new-{path}").as_bytes(),
                    maximum,
                )
                .unwrap(),
            );
        }
        for output in &outputs {
            let destination = repository.join(&output.path);
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::write(&destination, hex::decode(&output.new_bytes_hex).unwrap()).unwrap();
        }
        let transaction = ImportTransaction {
            schema: "auths.profile-qualification-import-transaction/1".into(),
            candidate_revision: revision.clone(),
            promotion_base_revision: revision,
            domain: "stripe".into(),
            target: QualificationTarget::LinuxX86_64,
            qualification_id: format!("qlf_{}", "A".repeat(43)),
            phase: ImportPhase::Promote,
            outputs,
        };
        let intent = repository.join(IMPORT_TRANSACTION_PATH);
        fs::write(
            &intent,
            serde_json_canonicalizer::to_vec(&transaction).unwrap(),
        )
        .unwrap();
        assert!(resume_import_transaction(repository).is_err());
        assert!(intent.exists());
        for output in &transaction.outputs {
            assert_eq!(
                fs::read(repository.join(&output.path)).unwrap(),
                hex::decode(&output.new_bytes_hex).unwrap()
            );
        }
    }
}
