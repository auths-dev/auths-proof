//! Static protected qualification adapter for the PostgreSQL profile family.

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
    qualification_pre_admission_attempt_count, qualification_scenario_program,
};
use auths_profile_runtime::{ProfileReceiptInspection, ProfileRuntimeError};
use auths_stores::JournalRecordV1;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

/// Independently observes one provider-entered PostgreSQL operation with the
/// protected runtime-read credential.
pub async fn observe_provider_truth(
    record: &JournalRecordV1,
    credential: &[u8],
    _observer_root: &std::path::Path,
    now_unix_seconds: u64,
) -> Result<(QualificationEffect, Vec<u8>), ProfileRuntimeError> {
    crate::local_agent::observe_provider_truth_for_qualification(
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
    match kind {
        QualificationProviderCallKind::Execute => {
            call_provider_transport(profile, command, exposed, configuration, now_unix_seconds)
                .await
                .map(Some)
        }
        QualificationProviderCallKind::Reconcile => {
            reconcile_provider_transport(profile, command, exposed, configuration, now_unix_seconds)
                .await
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PostgresqlProviderTruthFacts {
    server_identity_sha256: String,
    database_sha256: String,
    transaction_sha256: Option<String>,
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
    "304c66bfe27b3f73d9ba611c773124978ae3d2d125dbfb99bdbac22091f80696"
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
        || !digest(&facts.ledger_operation_sha256)
        || facts.rows.len() > 10_000
        || facts
            .rows
            .iter()
            .any(|row| !digest(&row.primary_key_sha256) || row.after_version < row.before_version)
        || facts.applied != (effect == QualificationEffect::Applied)
        || facts.transaction_sha256.is_some() != facts.applied
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

fn scenario_program(id: &str) -> Result<QualificationScenarioProgramV1, QualificationHarnessError> {
    qualification_scenario_program(
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
            let vector = serde_json_canonicalizer::to_vec(&serde_json::json!({
                "assignments": [{"column":"value","value":assignment}],
                "relation":"qualification_schema.tenant_rows",
                "tenantKey":tenant,
            }))
            .map_err(|_| QualificationHarnessError::Onboarding)?;
            vectors.push(auths_profile_kit::QualificationSetupVectorV1 {
                id: scenario_id.clone(),
                scenario_program: scenario_program(scenario_id)?,
                input_base64url: Base64UrlUnpadded::encode_string(&vector),
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

#[derive(Default)]
pub struct PostgresqlQualificationEnvironment {
    prepared_update: Option<String>,
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
                if environment.prepared_update.is_some() {
                    return Err(QualificationHarnessError::Invocation);
                }
                let outcome = client.invoke_installed(connection_alias, &vector.input)?;
                if outcome.kind == "completed" {
                    environment.prepared_update = Some(
                        outcome
                            .value
                            .as_ref()
                            .and_then(|value| value.get("prepared_update"))
                            .and_then(serde_json::Value::as_str)
                            .filter(|value| (48..=96).contains(&value.len()))
                            .ok_or(QualificationHarnessError::Invocation)?
                            .into(),
                    );
                }
            }
            (2, QualificationOperationRole::Effect, "auths.postgresql.bounded-update/1") => {
                if qualification_pre_admission_attempt_count(&vector.id).is_some() {
                    let outcome = client.invoke_installed(connection_alias, &vector.input)?;
                    if outcome.kind != "unavailable" {
                        return Err(QualificationHarnessError::Invocation);
                    }
                    return Ok(QualificationCollectedOperation {
                        role,
                        profile: profile.into(),
                    });
                }
                let prepared_update = environment
                    .prepared_update
                    .take()
                    .ok_or(QualificationHarnessError::Invocation)?;
                let input = serde_json::to_vec(&serde_json::json!({
                    "preparedUpdate": prepared_update,
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

impl QualificationProtectedObserver for PostgresqlQualificationAdapter {
    type Environment = PostgresqlProtectedObserverEnvironment;

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

    fn validate_scenario_program(
        &self,
        _environment: &PostgresqlProtectedObserverEnvironment,
        program: &QualificationScenarioProgramV1,
        operations: &[auths_profile_kit::QualificationRedactedOperation],
        truths: &[QualificationProviderTruth],
    ) -> Result<(), QualificationHarnessError> {
        auths_profile_kit::validate_scenario_program_projection(program, operations, truths)
    }

    fn cleanup(
        &self,
        context: &QualificationRunContext,
        _reference: Option<&QualificationRunReference>,
    ) -> Result<QualificationCleanupEvidence, QualificationHarnessError> {
        if context.protected_environment != "qualification-postgresql" {
            return Err(QualificationHarnessError::Cleanup);
        }
        let credential = protected_credential("QUALIFICATION_CLEANUP_CREDENTIAL")
            .map_err(|_| QualificationHarnessError::Cleanup)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| QualificationHarnessError::Cleanup)?;
        runtime
            .block_on(crate::local_provider::cleanup_qualification_row(
                &credential,
            ))
            .map_err(|_| QualificationHarnessError::Cleanup)?;
        Ok(QualificationCleanupEvidence {
            provider_resources_destroyed: true,
            connection_disabled: true,
            credentials_revoked: true,
            residual_resource_count: 0,
        })
    }
}

pub struct PostgresqlProtectedObserverEnvironment {
    credential: Zeroizing<Vec<u8>>,
    reference: QualificationRunReference,
    provider_version: &'static str,
    provider_artifact_sha256: &'static str,
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
    fn provider_truth_requires_committed_ids_and_effect_algebra() {
        let facts = json!({
            "applied":false,
            "databaseSha256":"11".repeat(32),
            "ledgerOperationSha256":"22".repeat(32),
            "rows":[{"afterVersion":7,"beforeVersion":7,"primaryKeySha256":"33".repeat(32)}],
            "serverIdentitySha256":"44".repeat(32),
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
    }
}
