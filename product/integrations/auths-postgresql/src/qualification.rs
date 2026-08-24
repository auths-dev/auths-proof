//! Static protected qualification adapter for the PostgreSQL profile family.

use auths_connections::{ProviderCredentialLease, QualificationProviderCallKind};
use auths_profile_kit::QualificationProfileStateFactV1;
use auths_profile_kit::{
    QualificationAdapterMetadata, QualificationCollectedOperation, QualificationCollectionAdapter,
    QualificationCommonOperationInstanceEvidence, QualificationCommonReceiptClaims,
    QualificationEffect, QualificationHarnessError, QualificationOperationRole,
    QualificationPhaseClient, QualificationProtectedObserver, QualificationProtectedSetup,
    QualificationProtectedSetupInput, QualificationProviderCleanupObservation,
    QualificationProviderTruth, QualificationRunContext, QualificationRunReference,
    QualificationScenarioHookStage, QualificationScenarioProgramV1, QualificationSetupHandoffV1,
    QualificationTarget, QualificationVector, qualification_pre_admission_attempt_count,
    qualification_scenario_program as resolve_qualification_scenario_program,
};
use auths_profile_runtime::{ProfileReceiptInspection, ProfileRuntimeError};
use auths_stores::JournalRecordV1;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;
type DerivedEffectCaseInputs = Option<(Vec<u8>, Vec<u8>)>;

/// Re-encodes the exact effect inputs derived from one authenticated
/// preflight result. The protected ClientProxy retains only commitments over
/// these bytes across phases.
pub fn qualification_effect_case_inputs(
    profile: &str,
    value: &[u8],
) -> Result<DerivedEffectCaseInputs, QualificationHarnessError> {
    if profile != "auths.postgresql.update-preflight/1" {
        return Err(QualificationHarnessError::Invocation);
    }
    let prepared = crate::generated::profile_api::PreparedUpdate::from_canonical_cbor(value)
        .map_err(|_| QualificationHarnessError::Invocation)?;
    let primary = crate::generated::profile_api::PreparedUpdateInput {
        prepared_update: prepared.prepared_update.clone(),
    }
    .to_canonical_cbor()
    .map_err(|_| QualificationHarnessError::Invocation)?;
    let mut changed_token = prepared.prepared_update;
    changed_token.push('x');
    let changed = crate::generated::profile_api::PreparedUpdateInput {
        prepared_update: changed_token,
    }
    .to_canonical_cbor()
    .map_err(|_| QualificationHarnessError::Invocation)?;
    Ok(Some((primary, changed)))
}

/// Returns the exact effect input for a reviewed case that intentionally has
/// no prepared capability. Both the installed-client adapter and protected
/// ClientProxy use this one domain-owned encoding.
pub fn qualification_effect_fallback_case_json(
    profile: &str,
    scenario_id: &str,
    stimulus: &str,
) -> Result<Option<Vec<u8>>, QualificationHarnessError> {
    if profile != "auths.postgresql.bounded-update/1" {
        return Err(QualificationHarnessError::Invocation);
    }
    if qualification_pre_admission_attempt_count(scenario_id).is_none()
        && stimulus != "no-prepared-update"
    {
        return Ok(None);
    }
    serde_json_canonicalizer::to_vec(&serde_json::json!({
        "preparedUpdate": "qualification-missing-prepared-update-00000000000000000001",
    }))
    .map(Some)
    .map_err(|_| QualificationHarnessError::Invocation)
}

/// Independently observes one provider-entered PostgreSQL operation with the
/// protected runtime-read credential.
pub async fn observe_provider_truth(
    scenario_id: &str,
    record: &JournalRecordV1,
    credential: &[u8],
    _observer_root: &std::path::Path,
    now_unix_seconds: u64,
) -> Result<(QualificationEffect, Vec<u8>), ProfileRuntimeError> {
    crate::local_agent::observe_provider_truth_for_qualification(
        scenario_id,
        record,
        credential,
        now_unix_seconds,
    )
    .await
}

/// Runs the production profile receipt inspector through the qualification-only static port.
pub fn inspect_receipt_claims(
    profile: &str,
    inspection: ProfileReceiptInspection<'_>,
) -> Result<(), ProfileRuntimeError> {
    match profile {
        "auths.postgresql.bounded-update/1" => {
            crate::local_agent::updates_execute_inspect_receipt_claims(inspection)
        }
        "auths.postgresql.update-preflight/1" => {
            crate::local_agent::update_preflights_create_inspect_receipt_claims(inspection)
        }
        _ => Err(ProfileRuntimeError::Invalid),
    }
}

/// Reads one canonical protected prepared-update snapshot without opening or
/// mutating the production store.
pub fn inspect_profile_state(
    profile: &str,
    journal: &[JournalRecordV1],
    store_bytes: &[u8],
) -> Result<Vec<QualificationProfileStateFactV1>, ProfileRuntimeError> {
    crate::local_agent::inspect_profile_state_for_qualification(profile, journal, store_bytes)
}

/// Runs exactly the provider-facing PostgreSQL transport without constructing
/// candidate-owned profile state. Durable reservation classification remains
/// in the qualification agent.
pub async fn call_provider_transport(
    profile: &str,
    command: &[u8],
    credential: &[u8],
    configuration: Option<&[u8]>,
    now_unix_seconds: u64,
) -> Result<Vec<u8>, ProfileRuntimeError> {
    match profile {
        "auths.postgresql.update-preflight/1" => {
            crate::local_agent::update_preflights_create_transport_from_bytes(
                command,
                credential,
                configuration.ok_or(ProfileRuntimeError::Invalid)?,
                now_unix_seconds,
            )
            .await
        }
        "auths.postgresql.bounded-update/1" if configuration.is_some() => {
            crate::local_agent::updates_execute_transport_from_bytes(
                command,
                credential,
                now_unix_seconds,
            )
            .await
        }
        _ => Err(ProfileRuntimeError::Invalid),
    }
}

/// Queries provider truth for one unknown-result PostgreSQL operation. `None`
/// is authoritative not-applied truth for the bounded update.
pub async fn reconcile_provider_transport(
    profile: &str,
    command: &[u8],
    credential: &[u8],
    configuration: Option<&[u8]>,
    now_unix_seconds: u64,
) -> Result<Option<Vec<u8>>, ProfileRuntimeError> {
    match profile {
        "auths.postgresql.update-preflight/1" => call_provider_transport(
            profile,
            command,
            credential,
            configuration,
            now_unix_seconds,
        )
        .await
        .map(Some),
        "auths.postgresql.bounded-update/1" if configuration.is_some() => {
            crate::local_agent::updates_execute_reconcile_transport_from_bytes(command, credential)
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
    scenario_id: &str,
    case_id: &str,
    kind: QualificationProviderCallKind,
    command: &[u8],
    _profile_state: &[u8],
    credential: &ProviderCredentialLease,
    configuration: Option<&[u8]>,
    _transport_root: &std::path::Path,
    _operation_id: &str,
    now_unix_seconds: u64,
    deadline: std::time::Instant,
) -> Result<Option<Vec<u8>>, ProfileRuntimeError> {
    let exposed = credential
        .expose(deadline)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let program =
        qualification_scenario_program(scenario_id).map_err(|_| ProfileRuntimeError::Invalid)?;
    let before_effect_drift = kind == QualificationProviderCallKind::Execute
        && profile == "auths.postgresql.bounded-update/1"
        && program
            .hook_for_case(
                case_id,
                QualificationOperationRole::Effect,
                QualificationScenarioHookStage::BeforeProvider,
                "advance-row-before-effect",
            )
            .map_err(|_| ProfileRuntimeError::Invalid)?;
    let after_ledger_drift = kind == QualificationProviderCallKind::Execute
        && profile == "auths.postgresql.bounded-update/1"
        && program
            .hook_for_case(
                case_id,
                QualificationOperationRole::Effect,
                QualificationScenarioHookStage::AfterProviderBeforeResponse,
                "advance-row-after-ledger",
            )
            .map_err(|_| ProfileRuntimeError::Invalid)?;
    let kill_precommit = kind == QualificationProviderCallKind::Execute
        && profile == "auths.postgresql.bounded-update/1"
        && program
            .hook_for_case(
                case_id,
                QualificationOperationRole::Effect,
                QualificationScenarioHookStage::BeforeProvider,
                "kill-precommit",
            )
            .map_err(|_| ProfileRuntimeError::Invalid)?;
    let kill_postcommit = kind == QualificationProviderCallKind::Execute
        && profile == "auths.postgresql.bounded-update/1"
        && program
            .hook_for_case(
                case_id,
                QualificationOperationRole::Effect,
                QualificationScenarioHookStage::AfterProviderBeforeResponse,
                "kill-postcommit",
            )
            .map_err(|_| ProfileRuntimeError::Invalid)?;
    if before_effect_drift {
        crate::local_agent::apply_qualification_row_drift_from_command(
            command,
            exposed,
            "before-effect",
        )
        .await?;
    }
    let result = match kind {
        QualificationProviderCallKind::Execute if kill_precommit || kill_postcommit => {
            crate::local_agent::updates_execute_with_qualification_transaction_kill(
                command,
                exposed,
                now_unix_seconds,
                kill_postcommit,
            )
            .await
            .map(Some)
        }
        QualificationProviderCallKind::Execute => {
            call_provider_transport(profile, command, exposed, configuration, now_unix_seconds)
                .await
                .map(Some)
        }
        QualificationProviderCallKind::Reconcile => {
            reconcile_provider_transport(profile, command, exposed, configuration, now_unix_seconds)
                .await
        }
    };
    if after_ledger_drift && result.is_ok() {
        crate::local_agent::apply_qualification_row_drift_from_command(
            command,
            exposed,
            "after-ledger",
        )
        .await?;
    }
    result
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PostgresqlProviderTruthFacts {
    server_identity_sha256: String,
    database_sha256: String,
    transaction_sha256: Option<String>,
    transaction_isolation: Option<String>,
    ledger_operation_sha256: String,
    rows: Vec<PostgresqlProviderTruthRow>,
    applied: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PostgresqlProviderTruthRow {
    primary_key_sha256: String,
    before_version: u64,
    after_version: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PostgresqlProviderMatrixContract {
    schema: String,
    extensions: Vec<String>,
    grants: PostgresqlQualificationGrants,
    image_reference: String,
    major: u16,
    roles: PostgresqlQualificationRoles,
    tls: PostgresqlQualificationTls,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PostgresqlQualificationGrants {
    audit: Vec<String>,
    executor: Vec<String>,
    owner: Vec<String>,
    preflight: Vec<String>,
    setup: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PostgresqlQualificationRoles {
    audit: String,
    executor: String,
    owner: String,
    preflight: String,
    setup: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PostgresqlQualificationTls {
    certificate_trust: String,
    minimum_version: String,
    server_name_verification: bool,
}

/// Exact v1 prerequisite rows owned by the generated qualification contract.
#[must_use]
pub fn qualification_requirement_ids() -> &'static [&'static str] {
    &[
        "postgresql-connection-binding",
        "postgresql-execution-revalidation",
        "postgresql-immutable-execution-ledger",
        "postgresql-preflight-evaluator",
        "postgresql-prepare-revalidation",
        "postgresql-prepared-storage",
        "postgresql-provider-opening",
        "postgresql-reservation-conflicts-and-results",
    ]
}

/// SHA-256 of the exact canonical v1 requirement inventory bytes.
#[must_use]
pub const fn qualification_requirements_sha256() -> &'static str {
    "1471be0d271bc6c9516ecbb31f55ded4313e5da3d6c83445ba645ea365646c98"
}

/// Exact public receipt-claim roster required by the v1 PostgreSQL family.
#[must_use]
pub fn qualification_receipt_claim_ids() -> &'static [&'static str] {
    &[
        "postgresql.command",
        "postgresql.connection",
        "postgresql.decision",
        "postgresql.destination",
        "postgresql.evidence",
        "postgresql.execution-ledger",
        "postgresql.execution-recheck",
        "postgresql.preparation",
        "postgresql.prepared-store",
        "postgresql.provider-result",
        "postgresql.receipt-payload",
        "postgresql.reconciliation",
        "postgresql.reservation",
    ]
}

/// Exact executable provider-truth field roster.
#[must_use]
pub fn qualification_provider_truth_fields() -> &'static [&'static str] {
    &[
        "applied",
        "databaseSha256",
        "ledgerOperationSha256",
        "rows",
        "serverIdentitySha256",
        "transactionIsolation",
        "transactionSha256",
    ]
}

/// Raw provider-owned JSON field names forbidden from retained evidence.
#[must_use]
pub fn qualification_forbidden_evidence_fields() -> &'static [&'static str] {
    &["database", "ledgerOperationId", "transactionId"]
}

/// Non-secret byte prefixes whose presence proves an unredacted PostgreSQL endpoint.
#[must_use]
pub fn qualification_redaction_prefixes() -> &'static [&'static str] {
    &["postgres://", "postgresql://"]
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
    &[
        (
            "postgresql-16",
            "postgresql",
            "16.14",
            "714b08dd70c05160db032e4321033ac4e5b6328935b2d03ed419c3a898aa8219",
            "linux-x86_64",
        ),
        (
            "postgresql-17",
            "postgresql",
            "17.10",
            "6e5a6518f9d2ff9e9f4cba2a5a87d8f41b0f067f6f92ac847c344351a6c8d923",
            "linux-x86_64",
        ),
        (
            "postgresql-18",
            "postgresql",
            "18.4",
            "7e6103cf85f88f7a0eddb3ec0b1ba8940eba098ed118ade25a729ca9daee5568",
            "linux-x86_64",
        ),
    ]
}

/// Exact atomic family phase roster shared by every v1 PostgreSQL scenario.
#[must_use]
pub fn qualification_operation_plan()
-> &'static [(QualificationOperationRole, &'static str, bool, bool)] {
    &[
        (
            QualificationOperationRole::Preflight,
            "auths.postgresql.update-preflight/1",
            true,
            false,
        ),
        (
            QualificationOperationRole::Effect,
            "auths.postgresql.bounded-update/1",
            true,
            true,
        ),
    ]
}

/// Validates an exact PostgreSQL patch/image/TLS/role selection.
pub fn validate_provider_matrix_contract(
    bytes: &[u8],
    provider_version: &str,
    provider_artifact_sha256: &str,
) -> Result<(), QualificationHarnessError> {
    if bytes.is_empty() || bytes.len() > 65_536 {
        return Err(QualificationHarnessError::Limit);
    }
    let contract: PostgresqlProviderMatrixContract =
        serde_json::from_slice(bytes).map_err(|_| QualificationHarnessError::ProviderTruth)?;
    let expected_digest = match provider_version {
        "16.14" if contract.major == 16 => {
            "714b08dd70c05160db032e4321033ac4e5b6328935b2d03ed419c3a898aa8219"
        }
        "17.10" if contract.major == 17 => {
            "6e5a6518f9d2ff9e9f4cba2a5a87d8f41b0f067f6f92ac847c344351a6c8d923"
        }
        "18.4" if contract.major == 18 => {
            "7e6103cf85f88f7a0eddb3ec0b1ba8940eba098ed118ade25a729ca9daee5568"
        }
        _ => return Err(QualificationHarnessError::ProviderTruth),
    };
    let expected_image = format!("postgres:{provider_version}-bookworm@sha256:{expected_digest}");
    if serde_json_canonicalizer::to_vec(&contract)
        .map_err(|_| QualificationHarnessError::ProviderTruth)?
        != bytes
        || provider_artifact_sha256 != expected_digest
        || contract.schema != "auths.postgresql.qualification-provider-contract/1"
        || contract.image_reference != expected_image
        || contract.extensions.as_slice() != ["plpgsql"]
        || contract.grants.audit.as_slice()
            != [
                "CONNECT",
                "SELECT:auths_execution_ledger",
                "SELECT:tenant_rows",
            ]
        || contract.grants.executor.as_slice()
            != [
                "CONNECT",
                "EXECUTE:auths_finalize_execution",
                "EXECUTE:auths_prepare_execution",
                "EXECUTE:auths_read_execution",
                "UPDATE:tenant_rows",
            ]
        || contract.grants.owner.as_slice() != ["NOLOGIN", "OWNERSHIP:qualification_schema"]
        || contract.grants.preflight.as_slice()
            != ["CONNECT", "SELECT:catalogs", "SELECT:tenant_rows"]
        || contract.grants.setup.as_slice() != ["CONNECT", "CREATE", "TEMPORARY"]
        || contract.roles.audit != "auths_qualification_audit"
        || contract.roles.executor != "auths_qualification_executor"
        || contract.roles.owner != "auths_qualification_owner"
        || contract.roles.preflight != "auths_qualification_preflight"
        || contract.roles.setup != "auths_qualification_setup"
        || contract.tls.certificate_trust != "ephemeral-run-ca"
        || contract.tls.minimum_version != "TLSv1.3"
        || !contract.tls.server_name_verification
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
    if bytes.is_empty() || bytes.len() > 1_048_576 {
        return Err(QualificationHarnessError::Limit);
    }
    let facts: PostgresqlProviderTruthFacts =
        serde_json::from_slice(bytes).map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if serde_json_canonicalizer::to_vec(&facts)
        .map_err(|_| QualificationHarnessError::ProviderTruth)?
        != bytes
        || !digest(&facts.server_identity_sha256)
        || !digest(&facts.database_sha256)
        || facts
            .transaction_sha256
            .as_deref()
            .is_some_and(|value| !digest(value))
        || facts
            .transaction_isolation
            .as_deref()
            .is_some_and(|value| value != "serializable")
        || !digest(&facts.ledger_operation_sha256)
        || facts.rows.len() > 10_000
        || facts
            .rows
            .iter()
            .any(|row| !digest(&row.primary_key_sha256) || row.after_version < row.before_version)
        || facts.applied != (effect == QualificationEffect::Applied)
        || facts.transaction_sha256.is_some() != facts.applied
        || facts.transaction_isolation.is_some() != facts.applied
        || (facts.applied
            && (facts.rows.is_empty()
                || facts
                    .rows
                    .iter()
                    .any(|row| row.after_version <= row.before_version)))
        || (!facts.applied
            && facts
                .rows
                .iter()
                .any(|row| row.after_version != row.before_version))
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
    "postgresql-later-drift",
    "postgresql-preflight",
    "postgresql-response-loss",
    "postgresql-rls-policy",
    "postgresql-role-equality",
    "postgresql-row-boundary",
    "postgresql-row-drift",
    "postgresql-serializable-update",
    "postgresql-transaction-kill",
    "postgresql-value-redaction",
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
        "postgresql",
        id,
    )
    .map_err(|_| QualificationHarnessError::InvalidMetadata)
}

/// Qualification-only PostgreSQL adapter over the installed generated client.
pub struct PostgresqlQualificationAdapter;

impl QualificationProtectedSetup for PostgresqlQualificationAdapter {
    fn metadata(&self) -> QualificationAdapterMetadata {
        metadata()
    }

    fn setup(
        &self,
        input: QualificationProtectedSetupInput<'_>,
        setup_credential: &[u8],
    ) -> Result<QualificationSetupHandoffV1, QualificationHarnessError> {
        let expected_artifact = match input.provider_version {
            "16.14" => "714b08dd70c05160db032e4321033ac4e5b6328935b2d03ed419c3a898aa8219",
            "17.10" => "6e5a6518f9d2ff9e9f4cba2a5a87d8f41b0f067f6f92ac847c344351a6c8d923",
            "18.4" => "7e6103cf85f88f7a0eddb3ec0b1ba8940eba098ed118ade25a729ca9daee5568",
            _ => return Err(QualificationHarnessError::Onboarding),
        };
        if input.run_context.protected_environment != "qualification-postgresql"
            || input.provider_artifact_sha256 != expected_artifact
            || input.scenario_ids.is_empty()
            || !input.scenario_ids.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(QualificationHarnessError::Onboarding);
        }
        let descriptor = crate::connection::PostgresConnectionDescriptor::from_canonical_bytes(
            input.connection_descriptor,
        )
        .map_err(|_| QualificationHarnessError::Onboarding)?;
        let setup_secret =
            crate::connection::PostgresConnectionSecretV1::from_canonical_bytes(setup_credential)
                .map_err(|_| QualificationHarnessError::Onboarding)?;
        setup_secret
            .validate_qualification_destination(&descriptor, "auths_qualification_setup")
            .map_err(|_| QualificationHarnessError::Onboarding)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| QualificationHarnessError::Onboarding)?;
        runtime
            .block_on(crate::local_provider::setup_qualification_row(
                setup_credential,
                &descriptor,
                input.provider_version,
                input.scenario_ids,
            ))
            .map_err(|_| QualificationHarnessError::Onboarding)?;
        let provider_namespace = format!(
            "aq-{}-{}-{}",
            input.run_context.run_id,
            input.run_context.run_attempt,
            input.run_context.provider_run_id
        );
        let mut resources = Vec::with_capacity(input.scenario_ids.len());
        let mut vectors = Vec::with_capacity(input.scenario_ids.len());
        for scenario_id in input.scenario_ids {
            let tenant = format!("tenant-{scenario_id}");
            let assignment = match scenario_id.as_str() {
                "boundary-plus-one" => "x".repeat(4_097),
                "exact-boundary" => "x".repeat(4_096),
                _ => format!("after-{scenario_id}"),
            };
            let scenario_program = qualification_scenario_program(scenario_id)?;
            let cases = scenario_program
                .cases()
                .iter()
                .map(|case| {
                    let assignment = postgresql_case_assignment(case.stimulus(), &assignment)?;
                    let vector = serde_json_canonicalizer::to_vec(&serde_json::json!({
                        "assignments": [{"column":"value","value":assignment}],
                        "relation":"qualification_schema.tenant_rows",
                        "tenantKey":tenant,
                    }))
                    .map_err(|_| QualificationHarnessError::Onboarding)?;
                    Ok(auths_profile_kit::QualificationSetupCaseV1 {
                        case_id: case.case_id().into(),
                        input_base64url: Base64UrlUnpadded::encode_string(&vector),
                    })
                })
                .collect::<Result<Vec<_>, QualificationHarnessError>>()?;
            vectors.push(auths_profile_kit::QualificationSetupVectorV1 {
                id: scenario_id.clone(),
                scenario_program,
                cases,
                failpoint: scenario_id
                    .strip_prefix("crash-")
                    .and_then(auths_profile_kit::QualificationFailpoint::from_token),
            });
            resources.push(format!(
                "tenant-sha256:{}",
                hex::encode(Sha256::digest(tenant.as_bytes()))
            ));
        }
        resources.sort();
        let run_reference = QualificationRunReference {
            schema: "auths.profile-qualification-run-reference/1".into(),
            domain: "postgresql".into(),
            target: input.run_context.target,
            candidate_revision: input.run_context.candidate_revision.clone(),
            repository_id: input.run_context.repository_id.clone(),
            run_id: input.run_context.run_id.clone(),
            run_attempt: input.run_context.run_attempt,
            provider_run_id: input.run_context.provider_run_id.clone(),
            provider_namespace,
            provider_destination_sha256: hex::encode(descriptor.account_commitment()),
            connection_alias_sha256: hex::encode(Sha256::digest(input.connection_alias.as_bytes())),
            resource_references: resources,
            connection_generations: vec!["1".into()],
        };
        let handoff = QualificationSetupHandoffV1 {
            schema: "auths.profile-qualification-setup-handoff/1".into(),
            run_context: input.run_context.clone(),
            domain: "postgresql".into(),
            connection_alias: input.connection_alias.into(),
            run_reference,
            vectors,
        };
        handoff.validate()?;
        Ok(handoff)
    }
}

fn postgresql_case_assignment(
    stimulus: &str,
    assignment: &str,
) -> Result<String, QualificationHarnessError> {
    match stimulus {
        "maximum-assignment" => Ok("x".repeat(4_096)),
        "maximum-plus-one-assignment" => Ok("x".repeat(4_097)),
        "changed-input" => Ok(format!("{assignment}x")),
        "canonical"
        | "duplicate-field"
        | "encoded-canonical"
        | "missing-field"
        | "no-prepared-update"
        | "noncanonical-integer"
        | "preflight-evidence"
        | "preflight-handoff"
        | "prepared-maximum"
        | "redaction-effect"
        | "redaction-preflight"
        | "replay"
        | "serializable-effect"
        | "serializable-preflight"
        | "stale-evidence"
        | "transaction-postcommit"
        | "transaction-precommit"
        | "unknown-field" => Ok(assignment.to_owned()),
        _ => Err(QualificationHarnessError::Onboarding),
    }
}

#[derive(Default)]
pub struct PostgresqlQualificationEnvironment {
    prepared_updates: std::collections::BTreeMap<String, String>,
}

impl QualificationCollectionAdapter for PostgresqlQualificationAdapter {
    type Environment = PostgresqlQualificationEnvironment;

    fn metadata(&self) -> QualificationAdapterMetadata {
        metadata()
    }

    fn open(
        &self,
        context: &QualificationRunContext,
        handoff: &QualificationSetupHandoffV1,
    ) -> Result<Self::Environment, QualificationHarnessError> {
        if handoff.run_context != *context || handoff.domain != "postgresql" {
            return Err(QualificationHarnessError::InvalidSetupHandoff);
        }
        Ok(PostgresqlQualificationEnvironment::default())
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
            (1, QualificationOperationRole::Preflight, "auths.postgresql.update-preflight/1") => {
                if !environment.prepared_updates.is_empty() {
                    return Err(QualificationHarnessError::Invocation);
                }
                let outcome = client.invoke_installed(connection_alias, &vector.cases)?;
                for case_outcome in outcome.cases {
                    if case_outcome.kind != "completed" {
                        continue;
                    }
                    let intent = vector
                        .scenario_program
                        .cases()
                        .iter()
                        .find(|case| case.case_id() == case_outcome.case_id)
                        .ok_or(QualificationHarnessError::Invocation)?
                        .intent_id()
                        .to_owned();
                    let prepared = case_outcome
                        .value
                        .as_ref()
                        .and_then(|value| value.get("prepared_update"))
                        .and_then(serde_json::Value::as_str)
                        .filter(|value| (48..=96).contains(&value.len()))
                        .ok_or(QualificationHarnessError::Invocation)?
                        .to_owned();
                    if environment
                        .prepared_updates
                        .insert(intent, prepared)
                        .is_some()
                    {
                        return Err(QualificationHarnessError::Invocation);
                    }
                }
            }
            (2, QualificationOperationRole::Effect, "auths.postgresql.bounded-update/1") => {
                if qualification_pre_admission_attempt_count(&vector.id).is_some() {
                    let mut cases = vector.cases.clone();
                    for (case, program_case) in cases.iter_mut().zip(
                        vector
                            .scenario_program
                            .cases()
                            .iter()
                            .filter(|case| case.role() == QualificationOperationRole::Effect),
                    ) {
                        case.input = qualification_effect_fallback_case_json(
                            profile,
                            &vector.id,
                            program_case.stimulus(),
                        )?
                        .ok_or(QualificationHarnessError::Invocation)?;
                    }
                    let outcome = client.invoke_installed(connection_alias, &cases)?;
                    if outcome.cases.iter().any(|case| case.kind != "unavailable") {
                        return Err(QualificationHarnessError::Invocation);
                    }
                    return Ok(QualificationCollectedOperation {
                        role,
                        profile: profile.into(),
                    });
                }
                let mut cases = vector.cases.clone();
                for program_case in vector
                    .scenario_program
                    .cases()
                    .iter()
                    .filter(|case| case.role() == QualificationOperationRole::Effect)
                {
                    let fallback = qualification_effect_fallback_case_json(
                        profile,
                        &vector.id,
                        program_case.stimulus(),
                    )?;
                    let mut prepared_update = environment
                        .prepared_updates
                        .get(program_case.intent_id())
                        .cloned()
                        .or_else(|| {
                            fallback.and_then(|bytes| {
                                serde_json::from_slice::<serde_json::Value>(&bytes)
                                    .ok()
                                    .and_then(|input| {
                                        input["preparedUpdate"].as_str().map(str::to_owned)
                                    })
                            })
                        })
                        .ok_or(QualificationHarnessError::Invocation)?;
                    if program_case.stimulus() == "changed-input" {
                        prepared_update.push('x');
                    }
                    let case = cases
                        .iter_mut()
                        .find(|case| case.case_id == program_case.case_id())
                        .ok_or(QualificationHarnessError::Invocation)?;
                    case.input = serde_json_canonicalizer::to_vec(&serde_json::json!({
                        "preparedUpdate": prepared_update,
                    }))
                    .map_err(|_| QualificationHarnessError::Invocation)?;
                }
                client.invoke_installed(connection_alias, &cases)?;
                environment.prepared_updates.clear();
            }
            _ => return Err(QualificationHarnessError::Invocation),
        }
        Ok(QualificationCollectedOperation {
            role,
            profile: profile.into(),
        })
    }
}

impl QualificationProtectedObserver for PostgresqlQualificationAdapter {
    type Environment = PostgresqlProtectedObserverEnvironment;
    type CleanupEnvironment = ();

    fn metadata(&self) -> QualificationAdapterMetadata {
        metadata()
    }

    fn open(
        &self,
        context: &QualificationRunContext,
        reference: Option<&QualificationRunReference>,
    ) -> Result<Self::Environment, QualificationHarnessError> {
        let reference = reference.ok_or(QualificationHarnessError::ProviderTruth)?;
        if reference.domain != "postgresql"
            || reference.target != context.target
            || reference.candidate_revision != context.candidate_revision
            || reference.repository_id != context.repository_id
            || reference.run_id != context.run_id
            || reference.run_attempt != context.run_attempt
            || reference.provider_run_id != context.provider_run_id
            || reference.resource_references.is_empty()
            || reference
                .resource_references
                .iter()
                .any(|value| !value.starts_with("tenant-sha256:"))
        {
            return Err(QualificationHarnessError::ProviderTruth);
        }
        let (provider_version, provider_artifact_sha256) =
            provider_identity(&reference.provider_run_id)?;
        Ok(PostgresqlProtectedObserverEnvironment {
            credential: protected_credential("QUALIFICATION_OBSERVER_CREDENTIAL")?,
            reference: reference.clone(),
            provider_version,
            provider_artifact_sha256,
        })
    }

    fn provider_truth(
        &self,
        environment: &PostgresqlProtectedObserverEnvironment,
        scenario_id: &str,
        phase: &QualificationCollectedOperation,
        instance: &QualificationCommonOperationInstanceEvidence,
        in_row_domain_facts: &[u8],
    ) -> Result<QualificationProviderTruth, QualificationHarnessError> {
        if !metadata().family.contains(&phase.profile.as_str()) {
            return Err(QualificationHarnessError::ProviderTruth);
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| QualificationHarnessError::ProviderTruth)?;
        let observed = runtime
            .block_on(crate::local_provider::observe_qualification_scenario(
                &environment.credential,
                scenario_id,
                &instance.operation_id,
                &phase.profile,
                environment.provider_version,
            ))
            .map_err(|_| QualificationHarnessError::ProviderTruth)?;
        let effect = if observed.applied {
            QualificationEffect::Applied
        } else {
            QualificationEffect::NotApplied
        };
        let rows = if phase.profile == "auths.postgresql.update-preflight/1" {
            Vec::new()
        } else {
            vec![PostgresqlProviderTruthRow {
                primary_key_sha256: observed.primary_key_sha256,
                before_version: observed.before_version,
                after_version: observed.after_version,
            }]
        };
        let facts = PostgresqlProviderTruthFacts {
            server_identity_sha256: observed.server_identity_sha256,
            database_sha256: observed.database_sha256,
            transaction_sha256: observed.transaction_sha256,
            transaction_isolation: observed.transaction_isolation,
            ledger_operation_sha256: hex::encode(Sha256::digest(instance.operation_id.as_bytes())),
            rows,
            applied: observed.applied,
        };
        let facts = serde_json_canonicalizer::to_vec(&facts)
            .map_err(|_| QualificationHarnessError::ProviderTruth)?;
        if facts != in_row_domain_facts {
            return Err(QualificationHarnessError::ProviderTruth);
        }
        validate_provider_truth_facts(&facts, effect)?;
        Ok(QualificationProviderTruth {
            operation_id: instance.operation_id.clone(),
            provider_run_id: environment.reference.provider_run_id.clone(),
            effect,
            provider_calls: instance.counters.provider_calls,
            commitment: Sha256::digest(&facts).into(),
            domain_facts: facts,
            provider_version: environment.provider_version.into(),
            provider_artifact_sha256: environment.provider_artifact_sha256.into(),
        })
    }

    fn validate_receipt_payload(
        &self,
        _environment: &PostgresqlProtectedObserverEnvironment,
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
        program: &QualificationScenarioProgramV1,
        operations: &[auths_profile_kit::QualificationRedactedOperation],
        truths: &[QualificationProviderTruth],
    ) -> Result<(), QualificationHarnessError> {
        if !metadata().scenarios.contains(&program.id()) {
            return Ok(());
        }
        match program.id() {
            "postgresql-preflight" | "postgresql-row-boundary" => {
                validate_successful_postgresql_pair(operations, truths)
            }
            "postgresql-serializable-update" => {
                validate_serializable_postgresql_pair(operations, truths)
            }
            "postgresql-value-redaction" => {
                validate_successful_postgresql_pair(operations, truths)?;
                if truths.iter().any(|truth| {
                    qualification_redaction_prefixes().iter().any(|prefix| {
                        truth
                            .domain_facts
                            .windows(prefix.len())
                            .any(|window| window == prefix.as_bytes())
                    })
                }) {
                    return Err(QualificationHarnessError::Redaction);
                }
                Ok(())
            }
            "postgresql-response-loss" => {
                validate_successful_postgresql_pair(operations, truths)?;
                validate_reconciled_postgresql_effect(operations)
            }
            "postgresql-later-drift" => validate_successful_postgresql_pair(operations, truths),
            "postgresql-row-drift" => validate_postgresql_row_drift(operations, truths),
            "postgresql-transaction-kill" => {
                validate_postgresql_transaction_kill(operations, truths)
            }
            _ => Err(QualificationHarnessError::PrerequisiteUnavailable(
                "PostgreSQL scenario predicate is not implemented",
            )),
        }
    }

    fn open_cleanup(
        &self,
        _context: &QualificationRunContext,
    ) -> Result<Self::CleanupEnvironment, QualificationHarnessError> {
        Err(QualificationHarnessError::PrerequisiteUnavailable(
            "PostgreSQL cleanup requires a run-scoped database and role namespace derived from the protected run context",
        ))
    }

    fn cleanup(
        &self,
        _environment: &Self::CleanupEnvironment,
        context: &QualificationRunContext,
    ) -> Result<QualificationProviderCleanupObservation, QualificationHarnessError> {
        if context.protected_environment != "qualification-postgresql" {
            return Err(QualificationHarnessError::Cleanup);
        }
        Err(QualificationHarnessError::PrerequisiteUnavailable(
            "PostgreSQL cleanup requires a run-scoped database and role namespace bound to the protected setup reference",
        ))
    }
}

pub struct PostgresqlProtectedObserverEnvironment {
    credential: Zeroizing<Vec<u8>>,
    reference: QualificationRunReference,
    provider_version: &'static str,
    provider_artifact_sha256: &'static str,
}

fn validate_successful_postgresql_pair(
    operations: &[auths_profile_kit::QualificationRedactedOperation],
    truths: &[QualificationProviderTruth],
) -> Result<(), QualificationHarnessError> {
    let [preflight, effect] = operations else {
        return Err(QualificationHarnessError::ProviderTruth);
    };
    if preflight.role != QualificationOperationRole::Preflight
        || effect.role != QualificationOperationRole::Effect
        || preflight.instances.len() != 1
        || effect.instances.len() != 1
        || truths.len() != 2
    {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    let preflight_instance = &preflight.instances[0];
    let effect_instance = &effect.instances[0];
    let preflight_truth = truths
        .iter()
        .find(|truth| truth.operation_id == preflight_instance.operation_id)
        .ok_or(QualificationHarnessError::ProviderTruth)?;
    let effect_truth = truths
        .iter()
        .find(|truth| truth.operation_id == effect_instance.operation_id)
        .ok_or(QualificationHarnessError::ProviderTruth)?;
    let preflight_facts: PostgresqlProviderTruthFacts =
        serde_json::from_slice(&preflight_truth.domain_facts)
            .map_err(|_| QualificationHarnessError::ProviderTruth)?;
    let effect_facts: PostgresqlProviderTruthFacts =
        serde_json::from_slice(&effect_truth.domain_facts)
            .map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if serde_json_canonicalizer::to_vec(&preflight_facts)
        .map_err(|_| QualificationHarnessError::ProviderTruth)?
        != preflight_truth.domain_facts
        || serde_json_canonicalizer::to_vec(&effect_facts)
            .map_err(|_| QualificationHarnessError::ProviderTruth)?
            != effect_truth.domain_facts
        || preflight_truth.effect != QualificationEffect::NotApplied
        || preflight_facts.applied
        || preflight_facts.transaction_sha256.is_some()
        || preflight_facts.transaction_isolation.is_some()
        || !preflight_facts.rows.is_empty()
        || effect_truth.effect != QualificationEffect::Applied
        || !effect_facts.applied
        || effect_facts
            .transaction_sha256
            .as_deref()
            .is_none_or(|value| !digest(value))
        || effect_facts.transaction_isolation.as_deref() != Some("serializable")
        || effect_facts.rows.is_empty()
        || effect_facts
            .rows
            .iter()
            .any(|row| row.after_version != row.before_version.saturating_add(1))
        || preflight_facts.server_identity_sha256 != effect_facts.server_identity_sha256
        || preflight_facts.database_sha256 != effect_facts.database_sha256
        || preflight_facts.ledger_operation_sha256
            != hex::encode(Sha256::digest(preflight_instance.operation_id.as_bytes()))
        || effect_facts.ledger_operation_sha256
            != hex::encode(Sha256::digest(effect_instance.operation_id.as_bytes()))
    {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    Ok(())
}

fn validate_serializable_postgresql_pair(
    operations: &[auths_profile_kit::QualificationRedactedOperation],
    truths: &[QualificationProviderTruth],
) -> Result<(), QualificationHarnessError> {
    validate_successful_postgresql_pair(operations, truths)?;
    let effect = operations
        .iter()
        .find(|operation| operation.role == QualificationOperationRole::Effect)
        .and_then(|operation| operation.instances.first())
        .ok_or(QualificationHarnessError::ProviderTruth)?;
    let truth = truths
        .iter()
        .find(|truth| truth.operation_id == effect.operation_id)
        .ok_or(QualificationHarnessError::ProviderTruth)?;
    let facts: PostgresqlProviderTruthFacts = serde_json::from_slice(&truth.domain_facts)
        .map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if facts.transaction_isolation.as_deref() != Some("serializable") {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    Ok(())
}

fn validate_reconciled_postgresql_effect(
    operations: &[auths_profile_kit::QualificationRedactedOperation],
) -> Result<(), QualificationHarnessError> {
    let effect = operations
        .iter()
        .find(|operation| operation.role == QualificationOperationRole::Effect)
        .ok_or(QualificationHarnessError::ProviderTruth)?;
    let [instance] = effect.instances.as_slice() else {
        return Err(QualificationHarnessError::ProviderTruth);
    };
    if !instance.reconciled
        || instance.effect != QualificationEffect::Applied
        || instance.counters.provider_calls != 1
    {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    Ok(())
}

fn validate_postgresql_row_drift(
    operations: &[auths_profile_kit::QualificationRedactedOperation],
    truths: &[QualificationProviderTruth],
) -> Result<(), QualificationHarnessError> {
    let [preflight, effect] = operations else {
        return Err(QualificationHarnessError::ProviderTruth);
    };
    let [preflight_instance] = preflight.instances.as_slice() else {
        return Err(QualificationHarnessError::ProviderTruth);
    };
    let [effect_instance] = effect.instances.as_slice() else {
        return Err(QualificationHarnessError::ProviderTruth);
    };
    let preflight_truth = truths
        .iter()
        .find(|truth| truth.operation_id == preflight_instance.operation_id)
        .ok_or(QualificationHarnessError::ProviderTruth)?;
    let effect_truth = truths
        .iter()
        .find(|truth| truth.operation_id == effect_instance.operation_id)
        .ok_or(QualificationHarnessError::ProviderTruth)?;
    let preflight_facts: PostgresqlProviderTruthFacts =
        serde_json::from_slice(&preflight_truth.domain_facts)
            .map_err(|_| QualificationHarnessError::ProviderTruth)?;
    let effect_facts: PostgresqlProviderTruthFacts =
        serde_json::from_slice(&effect_truth.domain_facts)
            .map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if preflight.role != QualificationOperationRole::Preflight
        || effect.role != QualificationOperationRole::Effect
        || preflight_truth.effect != QualificationEffect::NotApplied
        || effect_truth.effect != QualificationEffect::NotApplied
        || effect_instance.effect != QualificationEffect::NotApplied
        || !effect_instance.reconciled
        || effect_instance.counters.provider_calls != 1
        || preflight_facts.applied
        || effect_facts.applied
        || preflight_facts.transaction_sha256.is_some()
        || effect_facts.transaction_sha256.is_some()
        || !preflight_facts.rows.is_empty()
        || effect_facts.rows.is_empty()
        || effect_facts
            .rows
            .iter()
            .any(|row| row.before_version != row.after_version)
    {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    Ok(())
}

fn validate_postgresql_transaction_kill(
    operations: &[auths_profile_kit::QualificationRedactedOperation],
    truths: &[QualificationProviderTruth],
) -> Result<(), QualificationHarnessError> {
    let preflight = operations
        .iter()
        .find(|operation| operation.role == QualificationOperationRole::Preflight)
        .ok_or(QualificationHarnessError::ProviderTruth)?;
    let effect = operations
        .iter()
        .find(|operation| operation.role == QualificationOperationRole::Effect)
        .ok_or(QualificationHarnessError::ProviderTruth)?;
    if operations.len() != 2
        || preflight.instances.len() != 2
        || effect.instances.len() != 2
        || truths.len() != 4
    {
        return Err(QualificationHarnessError::ProviderTruth);
    }

    let precommit_preflight = postgresql_case_instance(preflight, "preflight-precommit")?;
    let postcommit_preflight = postgresql_case_instance(preflight, "preflight-postcommit")?;
    let precommit_effect = postgresql_case_instance(effect, "effect-precommit")?;
    let postcommit_effect = postgresql_case_instance(effect, "effect-postcommit")?;
    let precommit_preflight_facts =
        postgresql_truth_facts(truths, &precommit_preflight.operation_id)?;
    let postcommit_preflight_facts =
        postgresql_truth_facts(truths, &postcommit_preflight.operation_id)?;
    let precommit_effect_facts = postgresql_truth_facts(truths, &precommit_effect.operation_id)?;
    let postcommit_effect_facts = postgresql_truth_facts(truths, &postcommit_effect.operation_id)?;

    let preflights = [
        (precommit_preflight, &precommit_preflight_facts),
        (postcommit_preflight, &postcommit_preflight_facts),
    ];
    if preflights.iter().any(|(instance, facts)| {
        instance.effect != QualificationEffect::NotApplied
            || instance.counters.provider_calls != 0
            || facts.applied
            || facts.transaction_sha256.is_some()
            || !facts.rows.is_empty()
    }) || precommit_effect.effect != QualificationEffect::NotApplied
        || !precommit_effect.reconciled
        || precommit_effect.counters.provider_calls != 1
        || precommit_effect_facts.applied
        || precommit_effect_facts.transaction_sha256.is_some()
        || precommit_effect_facts.rows.is_empty()
        || precommit_effect_facts
            .rows
            .iter()
            .any(|row| row.before_version != row.after_version)
        || postcommit_effect.effect != QualificationEffect::Applied
        || !postcommit_effect.reconciled
        || postcommit_effect.counters.provider_calls != 1
        || !postcommit_effect_facts.applied
        || postcommit_effect_facts
            .transaction_sha256
            .as_deref()
            .is_none_or(|value| !digest(value))
        || postcommit_effect_facts.rows.is_empty()
        || postcommit_effect_facts
            .rows
            .iter()
            .any(|row| row.after_version != row.before_version.saturating_add(1))
    {
        return Err(QualificationHarnessError::ProviderTruth);
    }

    let all_facts = [
        &precommit_preflight_facts,
        &postcommit_preflight_facts,
        &precommit_effect_facts,
        &postcommit_effect_facts,
    ];
    if all_facts
        .iter()
        .any(|facts| facts.server_identity_sha256 != all_facts[0].server_identity_sha256)
        || all_facts
            .iter()
            .any(|facts| facts.database_sha256 != all_facts[0].database_sha256)
    {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    Ok(())
}

fn postgresql_case_instance<'a>(
    operation: &'a auths_profile_kit::QualificationRedactedOperation,
    case_id: &str,
) -> Result<&'a auths_profile_kit::QualificationRedactedOperationInstance, QualificationHarnessError>
{
    let operation_id = operation
        .attempts
        .iter()
        .find(|attempt| attempt.case_id == case_id)
        .and_then(|attempt| attempt.operation_id.as_deref())
        .ok_or(QualificationHarnessError::ProviderTruth)?;
    operation
        .instances
        .iter()
        .find(|instance| instance.operation_id == operation_id)
        .ok_or(QualificationHarnessError::ProviderTruth)
}

fn postgresql_truth_facts(
    truths: &[QualificationProviderTruth],
    operation_id: &str,
) -> Result<PostgresqlProviderTruthFacts, QualificationHarnessError> {
    let truth = truths
        .iter()
        .find(|truth| truth.operation_id == operation_id)
        .ok_or(QualificationHarnessError::ProviderTruth)?;
    let facts: PostgresqlProviderTruthFacts = serde_json::from_slice(&truth.domain_facts)
        .map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if serde_json_canonicalizer::to_vec(&facts)
        .map_err(|_| QualificationHarnessError::ProviderTruth)?
        != truth.domain_facts
        || facts.applied != (truth.effect == QualificationEffect::Applied)
        || facts.ledger_operation_sha256 != hex::encode(Sha256::digest(operation_id.as_bytes()))
    {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    Ok(facts)
}

fn provider_identity(
    provider_run_id: &str,
) -> Result<(&'static str, &'static str), QualificationHarnessError> {
    qualification_provider_matrix_rows()
        .iter()
        .find(|row| row.0 == provider_run_id)
        .map(|row| (row.2, row.3))
        .ok_or(QualificationHarnessError::ProviderTruth)
}

fn protected_credential(name: &str) -> Result<Zeroizing<Vec<u8>>, QualificationHarnessError> {
    let encoded = std::env::var(name).map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if encoded.is_empty() || encoded.len() > 174_764 || encoded.contains('=') {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    let bytes = Base64UrlUnpadded::decode_vec(&encoded)
        .map_err(|_| QualificationHarnessError::ProviderTruth)?;
    if bytes.is_empty() || bytes.len() > 131_072 {
        return Err(QualificationHarnessError::ProviderTruth);
    }
    Ok(Zeroizing::new(bytes))
}

fn metadata() -> QualificationAdapterMetadata {
    QualificationAdapterMetadata {
        domain: "postgresql",
        family: &[
            "auths.postgresql.bounded-update/1",
            "auths.postgresql.update-preflight/1",
        ],
        targets: &[QualificationTarget::LinuxX86_64],
        protected_environment: "qualification-postgresql",
        scenarios: SCENARIOS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn authenticated_preflight_result_derives_only_the_paired_effect_inputs() {
        let token = "prepared-update-000000000000000000000000000000001";
        let value = crate::generated::profile_api::PreparedUpdate {
            prepared_update: token.into(),
            action_digest: "1".repeat(64),
            matched_rows: 1,
            expires_at: 10,
        }
        .to_canonical_cbor()
        .unwrap();
        let (primary, changed) =
            qualification_effect_case_inputs("auths.postgresql.update-preflight/1", &value)
                .unwrap()
                .unwrap();
        assert_eq!(
            crate::generated::profile_api::PreparedUpdateInput::from_canonical_cbor(&primary)
                .unwrap()
                .prepared_update,
            token
        );
        assert_eq!(
            crate::generated::profile_api::PreparedUpdateInput::from_canonical_cbor(&changed)
                .unwrap()
                .prepared_update,
            format!("{token}x")
        );
        assert!(
            qualification_effect_case_inputs("auths.postgresql.bounded-update/1", &value).is_err()
        );
    }

    #[test]
    fn missing_preflight_uses_one_domain_owned_effect_input() {
        let boundary = qualification_effect_fallback_case_json(
            "auths.postgresql.bounded-update/1",
            "boundary-plus-one",
            "canonical",
        )
        .unwrap()
        .unwrap();
        let missing = qualification_effect_fallback_case_json(
            "auths.postgresql.bounded-update/1",
            "postgresql-row-boundary",
            "no-prepared-update",
        )
        .unwrap()
        .unwrap();
        assert_eq!(boundary, missing);
        let canonical =
            auths_profile_kit::qualification_case_profile_input_cbor("canonical", &boundary)
                .unwrap();
        for stimulus in [
            "duplicate-field",
            "missing-field",
            "noncanonical-integer",
            "unknown-field",
        ] {
            assert_ne!(
                auths_profile_kit::qualification_case_profile_input_cbor(stimulus, &boundary)
                    .unwrap(),
                canonical
            );
        }
        assert!(
            qualification_effect_fallback_case_json(
                "auths.postgresql.bounded-update/1",
                "happy-path",
                "canonical",
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn provider_truth_requires_committed_ids_and_effect_algebra() {
        let facts = json!({
            "applied":false,
            "databaseSha256":"11".repeat(32),
            "ledgerOperationSha256":"22".repeat(32),
            "rows":[{"afterVersion":7,"beforeVersion":7,"primaryKeySha256":"33".repeat(32)}],
            "serverIdentitySha256":"44".repeat(32),
            "transactionIsolation":null,
            "transactionSha256":null
        });
        let bytes = serde_json_canonicalizer::to_vec(&facts).unwrap();
        validate_provider_truth_facts(&bytes, QualificationEffect::NotApplied).unwrap();

        let mut changed = facts.clone();
        changed["rows"][0]["afterVersion"] = json!(8);
        assert!(
            validate_provider_truth_facts(
                &serde_json_canonicalizer::to_vec(&changed).unwrap(),
                QualificationEffect::NotApplied,
            )
            .is_err()
        );

        let committed = json!({
            "applied":true,
            "databaseSha256":"11".repeat(32),
            "ledgerOperationSha256":"22".repeat(32),
            "rows":[{"afterVersion":8,"beforeVersion":7,"primaryKeySha256":"33".repeat(32)}],
            "serverIdentitySha256":"44".repeat(32),
            "transactionIsolation":"serializable",
            "transactionSha256":"55".repeat(32)
        });
        validate_provider_truth_facts(
            &serde_json_canonicalizer::to_vec(&committed).unwrap(),
            QualificationEffect::Applied,
        )
        .unwrap();
        let mut weaker = committed;
        weaker["transactionIsolation"] = json!("repeatable read");
        assert!(
            validate_provider_truth_facts(
                &serde_json_canonicalizer::to_vec(&weaker).unwrap(),
                QualificationEffect::Applied,
            )
            .is_err()
        );
    }

    #[test]
    fn execution_ledger_migration_persists_the_sampled_serializable_level() {
        let migration = include_str!("../migrations/auths_execution_ledger.sql");
        for marker in [
            "transaction_isolation text NOT NULL",
            "CHECK (transaction_isolation = 'serializable')",
            "observed_transaction_isolation text := current_setting('transaction_isolation')",
            "observed_transaction_isolation <> 'serializable'",
            "ledger.transaction_isolation = observed_transaction_isolation",
            "ledger.transaction_isolation,",
        ] {
            assert!(
                migration.contains(marker),
                "missing migration marker {marker}"
            );
        }
        assert!(!migration.contains("SET transaction_isolation = 'serializable'"));
    }

    #[test]
    fn row_boundary_program_uses_distinct_bounded_inputs() {
        let program = qualification_scenario_program("postgresql-row-boundary").unwrap();
        let stimuli = program
            .cases()
            .iter()
            .map(|case| (case.case_id(), case.intent_id(), case.stimulus()))
            .collect::<Vec<_>>();
        assert_eq!(
            stimuli,
            vec![
                ("preflight-maximum", "maximum", "maximum-assignment"),
                ("effect-maximum", "maximum", "prepared-maximum"),
                (
                    "preflight-plus-one",
                    "maximum-plus-one",
                    "maximum-plus-one-assignment",
                ),
                ("effect-plus-one", "maximum-plus-one", "no-prepared-update",),
            ]
        );
    }

    #[test]
    fn every_reviewed_postgresql_stimulus_has_one_fail_closed_setup_mapping() {
        for scenario in SCENARIOS {
            for case in qualification_scenario_program(scenario).unwrap().cases() {
                postgresql_case_assignment(case.stimulus(), "after").unwrap();
            }
        }
        assert!(postgresql_case_assignment("misspelled-stimulus", "after").is_err());
    }
}
