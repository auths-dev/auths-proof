//! Concrete protected PostgreSQL discovery, transaction, and reconciliation.

#![forbid(unsafe_code)]

use std::str::FromStr as _;

use auths_profile_runtime::ProfileRuntimeError;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, pem::PemObject as _};
use serde::{Deserialize, Serialize};
#[cfg(feature = "qualification")]
use sha2::Digest as _;
#[cfg(feature = "qualification")]
use tokio_postgres::config::Host;
use tokio_postgres::{
    Client, Config, GenericClient, IsolationLevel, Row, Transaction, config::SslMode, types::ToSql,
};
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::connection::{PostgresConnectionDescriptor, PostgresConnectionSecretV1};
use crate::{
    AssignmentV1, ColumnEvidenceV1, CompiledBoundedUpdate, DecisionClass, DigestHex,
    EvaluationContext, NamedCommitmentV1, NamedValueV1, ObservedRowV1, PgIdentifier,
    PostgresBoundedUpdateIntentV1, PostgresBoundedUpdateV1, PostgresEvidenceV1,
    PostgresVerifierConfigurationV1, RelationPolicyV1, RowPreconditionV1, TransactionResult,
    TypedValueV1, ValidationError, canonical::canonical_digest, compile_statement,
    generated::profile_api::UpdatePreflightInput,
};

/// Pure preflight action authorized before any credential or database access.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostgresPreflightActionV1 {
    pub schema: String,
    pub relation: String,
    pub tenant_key: String,
    pub assignments: Vec<(String, String)>,
    pub connection_id: String,
    pub connection_generation: u64,
    pub account_commitment: String,
    pub descriptor_commitment: String,
    pub credential_commitment: String,
    pub configuration_commitment: String,
    pub expires_at: u64,
}

impl PostgresPreflightActionV1 {
    pub fn from_input(
        input: &UpdatePreflightInput,
        connection: &auths_connections::ConnectionBinding,
        configuration: &crate::PostgresLocalAgentConfigurationV1,
        configuration_commitment: [u8; 32],
        expires_at: u64,
    ) -> Result<Self, ValidationError> {
        let mut assignments = input
            .assignments
            .iter()
            .map(|value| (value.column.clone(), value.value.clone()))
            .collect::<Vec<_>>();
        assignments.sort_by(|left, right| left.0.cmp(&right.0));
        if assignments.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(ValidationError::MalformedMutation);
        }
        let value = Self {
            schema: "auths.postgresql.update-preflight-action/1".into(),
            relation: input.relation.clone(),
            tenant_key: input.tenant_key.clone(),
            assignments,
            connection_id: connection.connection_id().as_str().into(),
            connection_generation: connection.generation().get(),
            account_commitment: hex::encode(connection.account_commitment()),
            descriptor_commitment: hex::encode(connection.descriptor_commitment()),
            credential_commitment: hex::encode(connection.credential_reference_commitment()),
            configuration_commitment: hex::encode(configuration_commitment),
            expires_at,
        };
        value.validate(configuration.verifier())?;
        Ok(value)
    }

    pub fn validate(
        &self,
        configuration: &PostgresVerifierConfigurationV1,
    ) -> Result<(), ValidationError> {
        let (schema, table) = split_relation(&self.relation)?;
        let database = configuration
            .first_database()
            .ok_or(ValidationError::InvalidConfiguration)?;
        let policy = configuration
            .relation(database, &schema, &table)
            .ok_or(ValidationError::InvalidConfiguration)?;
        if self.schema != "auths.postgresql.update-preflight-action/1"
            || self.tenant_key.is_empty()
            || self.tenant_key.len() > 256
            || self.assignments.is_empty()
            || self.assignments.len() > 32
            || self
                .assignments
                .windows(2)
                .any(|pair| pair[0].0 >= pair[1].0)
            || self.connection_id.is_empty()
            || self.connection_generation == 0
            || !lower_hex(&self.account_commitment)
            || !lower_hex(&self.descriptor_commitment)
            || !lower_hex(&self.credential_commitment)
            || !lower_hex(&self.configuration_commitment)
            || self.expires_at == 0
        {
            return Err(ValidationError::MalformedMutation);
        }
        for (column, value) in &self.assignments {
            let column = PgIdentifier::parse(column)?;
            let constraint = policy
                .assignment_constraints
                .iter()
                .find(|(allowed, _)| allowed == &column)
                .map(|(_, constraint)| constraint)
                .ok_or(ValidationError::InvalidConfiguration)?;
            TypedValueV1::text(value)?.validate(constraint)?;
        }
        Ok(())
    }
}

/// Complete protected discovery output persisted behind a prepared token.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedUpdatePayloadV1 {
    pub action: PostgresBoundedUpdateV1,
    pub evidence: PostgresEvidenceV1,
    pub configuration: PostgresVerifierConfigurationV1,
    pub descriptor: PostgresConnectionDescriptor,
}

impl PreparedUpdatePayloadV1 {
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.configuration.validate()?;
        self.descriptor
            .canonical_bytes()
            .map_err(|_| ValidationError::InvalidConfiguration)?;
        self.evidence.validate()?;
        self.action.validate()?;
        if PostgresBoundedUpdateV1::build(
            self.action.intent.clone(),
            &self.evidence,
            &self.configuration,
        )? != self.action
        {
            return Err(ValidationError::InvalidEvidence);
        }
        if self.descriptor.database() != self.action.intent.database_name.as_str()
            || self.descriptor.executor_role() != self.action.executor_role.as_str()
            || self.descriptor.server_identity() != self.action.database_server_identity
        {
            return Err(ValidationError::InvalidEvidence);
        }
        Ok(())
    }
}

/// Connects with the protected credential and discovers the exact bounded action.
pub async fn discover(
    credential: &[u8],
    descriptor: &PostgresConnectionDescriptor,
    configuration: &PostgresVerifierConfigurationV1,
    action: &PostgresPreflightActionV1,
    nonce: &str,
    now: u64,
) -> Result<PreparedUpdatePayloadV1, ProfileRuntimeError> {
    action
        .validate(configuration)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let mut client = connect(credential, descriptor).await?;
    let database = PgIdentifier::parse(descriptor.database()).map_err(invalid)?;
    if !configuration.allows_database(&database) {
        return Err(ProfileRuntimeError::Invalid);
    }
    let (schema, table) = split_relation(&action.relation).map_err(invalid)?;
    let policy = configuration
        .relation(&database, &schema, &table)
        .ok_or(ProfileRuntimeError::Invalid)?;
    let transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await
        .map_err(possible)?;
    let evidence = discover_evidence(
        &transaction,
        descriptor,
        configuration,
        policy,
        &action.tenant_key,
        &action.assignments,
        now,
    )
    .await?;
    transaction.commit().await.map_err(possible)?;
    let tenant_value = TypedValueV1::text(&action.tenant_key).map_err(invalid)?;
    let assignments = action
        .assignments
        .iter()
        .map(|(column, value)| {
            Ok(AssignmentV1 {
                column: PgIdentifier::parse(column)?,
                value: TypedValueV1::text(value)?,
            })
        })
        .collect::<Result<Vec<_>, ValidationError>>()
        .map_err(invalid)?;
    let rows = evidence
        .rows
        .iter()
        .map(|row| {
            Ok(RowPreconditionV1 {
                primary_key: row.primary_key.clone(),
                before_value_commitments: row
                    .before_values
                    .iter()
                    .map(|value| {
                        Ok(NamedCommitmentV1 {
                            column: value.column.clone(),
                            digest: canonical_digest(&value.value)?,
                        })
                    })
                    .collect::<Result<Vec<_>, ValidationError>>()?,
                row_version: row.row_version,
            })
        })
        .collect::<Result<Vec<_>, ValidationError>>()
        .map_err(invalid)?;
    let intent = PostgresBoundedUpdateIntentV1::new(
        PostgresBoundedUpdateIntentV1 {
            profile: String::new(),
            database_audience: evidence.database_audience.clone(),
            database_name: database,
            schema_name: schema,
            table_name: table,
            tenant_column: policy.tenant_column.clone(),
            tenant_value,
            primary_key_columns: policy.primary_key_columns.clone(),
            rows,
            assignments,
            expected_row_count: u32::try_from(evidence.rows.len())
                .map_err(|_| ProfileRuntimeError::Invalid)?,
            schema_fingerprint: evidence.schema_fingerprint.clone(),
            policy_fingerprint: evidence.policy_fingerprint.clone(),
            trigger_fingerprint: evidence.trigger_fingerprint.clone(),
            required_configuration_digest: configuration.digest().map_err(invalid)?,
            expires_at: action.expires_at,
            nonce: nonce.into(),
        },
        configuration,
    )
    .map_err(invalid)?;
    let payload = PreparedUpdatePayloadV1 {
        action: PostgresBoundedUpdateV1::build(intent, &evidence, configuration)
            .map_err(invalid)?,
        evidence,
        configuration: configuration.clone(),
        descriptor: descriptor.clone(),
    };
    payload.validate().map_err(invalid)?;
    Ok(payload)
}

pub async fn execute(
    credential: &[u8],
    payload: &PreparedUpdatePayloadV1,
    operation_id: &str,
    now: u64,
) -> Result<TransactionResult, ProfileRuntimeError> {
    payload.validate().map_err(invalid)?;
    let compiled =
        compile_statement(&payload.action.intent, &payload.configuration).map_err(invalid)?;
    let mut client = connect(credential, &payload.descriptor).await?;
    let transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .read_only(false)
        .start()
        .await
        .map_err(possible)?;
    configure_session(&transaction, payload, operation_id).await?;
    recheck_all(&transaction, payload).await?;
    if !payload_is_authorized(payload, now)? {
        return Err(ProfileRuntimeError::Invalid);
    }
    let action_digest = payload.action.digest().map_err(invalid)?;
    reserve_ledger(&transaction, payload, operation_id, &action_digest, now).await?;
    let values = compiled
        .parameters
        .iter()
        .map(|binding| binding.value.protocol_text())
        .collect::<Vec<_>>();
    let lock_count = compiled
        .parameters
        .iter()
        .take_while(|binding| binding.role != "assignment")
        .count();
    let locked = transaction
        .query(&compiled.lock_sql, &parameter_refs(&values[..lock_count]))
        .await
        .map_err(possible)?;
    validate_before_rows(payload, &locked)?;
    let updated = transaction
        .query(&compiled.update_sql, &parameter_refs(&values))
        .await
        .map_err(possible)?;
    validate_after_rows(payload, &updated)?;
    let committed_at = now.saturating_add(1);
    let ledger_commitment = canonical_digest(&(
        action_digest.clone(),
        operation_id,
        payload.action.after_state_digest.clone(),
        payload.action.intent.expected_row_count,
        committed_at,
    ))
    .map_err(invalid)?;
    finalize_ledger(
        &transaction,
        payload,
        operation_id,
        &action_digest,
        payload.action.intent.expected_row_count,
        &ledger_commitment,
        committed_at,
    )
    .await?;
    let server_version: String = transaction
        .query_one("SELECT current_setting('server_version')", &[])
        .await
        .map_err(possible)?
        .get(0);
    transaction.commit().await.map_err(possible)?;
    let readback_commitment = readback(&client, payload, &compiled).await?;
    Ok(TransactionResult {
        affected_rows: payload.action.intent.expected_row_count,
        after_state_digest: payload.action.after_state_digest.clone(),
        ledger_commitment,
        readback_commitment,
        server_version,
        transaction_started_at: now,
        committed_at,
        reconciled: false,
    })
}

fn payload_is_authorized(
    payload: &PreparedUpdatePayloadV1,
    now: u64,
) -> Result<bool, ProfileRuntimeError> {
    let audience = payload
        .configuration
        .first_database_audience()
        .ok_or(ProfileRuntimeError::Invalid)?;
    Ok(matches!(
        crate::evaluate(&EvaluationContext {
            action: &payload.action,
            evidence: &payload.evidence,
            required_configuration: &payload.configuration,
            executed_configuration: &payload.configuration,
            request_audience: audience,
            now,
        })
        .class,
        DecisionClass::Authorized
    ))
}

pub async fn reconcile(
    credential: &[u8],
    payload: &PreparedUpdatePayloadV1,
    operation_id: &str,
) -> Result<Option<TransactionResult>, ProfileRuntimeError> {
    payload.validate().map_err(invalid)?;
    let client = connect(credential, &payload.descriptor).await?;
    let action_digest = payload.action.digest().map_err(invalid)?;
    let row = client
        .query_opt(
            "SELECT action_digest, claim_id, profile, relation_oid::bigint,\
             tenant_commitment, row_set_digest, before_state_digest,\
             after_state_digest, affected_rows, result_commitment,\
             transaction_started_at, committed_at\
             FROM auths_internal.auths_read_execution($1)",
            &[&operation_id],
        )
        .await
        .map_err(possible)?;
    let Some(row) = row else { return Ok(None) };
    let affected_rows =
        u32::try_from(row.get::<_, i32>(8)).map_err(|_| ProfileRuntimeError::Invalid)?;
    let transaction_started_at =
        u64::try_from(row.get::<_, i64>(10)).map_err(|_| ProfileRuntimeError::Invalid)?;
    let committed_at =
        u64::try_from(row.get::<_, i64>(11)).map_err(|_| ProfileRuntimeError::Invalid)?;
    let ledger_commitment = DigestHex::parse(row.get::<_, String>(9)).map_err(invalid)?;
    let expected_ledger_commitment = canonical_digest(&(
        action_digest.clone(),
        operation_id,
        payload.action.after_state_digest.clone(),
        affected_rows,
        committed_at,
    ))
    .map_err(invalid)?;
    if row.get::<_, String>(0) != action_digest.as_str()
        || row.get::<_, String>(1) != operation_id
        || row.get::<_, String>(2) != payload.action.intent.profile
        || u32::try_from(row.get::<_, i64>(3)).map_err(|_| ProfileRuntimeError::Invalid)?
            != payload.action.relation_oid
        || row.get::<_, String>(4) != payload.action.tenant_commitment.as_str()
        || row.get::<_, String>(5) != payload.action.row_set_digest.as_str()
        || row.get::<_, String>(6) != payload.action.before_state_digest.as_str()
        || row.get::<_, String>(7) != payload.action.after_state_digest.as_str()
        || affected_rows != payload.action.intent.expected_row_count
        || ledger_commitment != expected_ledger_commitment
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    let compiled =
        compile_statement(&payload.action.intent, &payload.configuration).map_err(invalid)?;
    let readback_commitment = readback(&client, payload, &compiled).await?;
    let server_version: String = client
        .query_one("SELECT current_setting('server_version')", &[])
        .await
        .map_err(possible)?
        .get(0);
    Ok(Some(TransactionResult {
        affected_rows,
        after_state_digest: payload.action.after_state_digest.clone(),
        ledger_commitment,
        readback_commitment,
        server_version,
        transaction_started_at,
        committed_at,
        reconciled: true,
    }))
}

async fn connect(
    bytes: &[u8],
    descriptor: &PostgresConnectionDescriptor,
) -> Result<Client, ProfileRuntimeError> {
    let secret = PostgresConnectionSecretV1::from_canonical_bytes(bytes)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    secret
        .validate_for_descriptor(descriptor)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    connect_secret(&secret).await
}

#[cfg(feature = "qualification")]
pub(crate) async fn connect_qualification_role(
    bytes: &[u8],
    descriptor: &PostgresConnectionDescriptor,
    role: &str,
) -> Result<Client, ProfileRuntimeError> {
    let secret = PostgresConnectionSecretV1::from_canonical_bytes(bytes)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    secret
        .validate_qualification_destination(descriptor, role)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    connect_secret(&secret).await
}

async fn connect_secret(
    secret: &PostgresConnectionSecretV1,
) -> Result<Client, ProfileRuntimeError> {
    let config =
        Config::from_str(secret.connection_string()).map_err(|_| ProfileRuntimeError::Invalid)?;
    if config.get_ssl_mode() != SslMode::Require {
        return Err(ProfileRuntimeError::Invalid);
    }
    let mut roots = RootCertStore::empty();
    let mut count = 0_usize;
    for certificate in CertificateDer::pem_slice_iter(secret.ca_pem().as_bytes()) {
        roots
            .add(certificate.map_err(|_| ProfileRuntimeError::Invalid)?)
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        count = count.saturating_add(1);
    }
    if count == 0 {
        return Err(ProfileRuntimeError::Invalid);
    }
    let tls = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let (client, connection) = config
        .connect(MakeRustlsConnect::new(tls))
        .await
        .map_err(possible)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

/// Creates the exact disposable qualification schema and seed rows through
/// the separately credentialed setup role. This helper is compiled only into
/// protected qualification tools; production provider calls never reach it.
#[cfg(feature = "qualification")]
pub(crate) async fn setup_qualification_row(
    credential: &[u8],
    descriptor: &PostgresConnectionDescriptor,
    expected_provider_version: &str,
    scenario_ids: &[String],
) -> Result<(), ProfileRuntimeError> {
    let client =
        connect_qualification_role(credential, descriptor, "auths_qualification_setup").await?;
    let version: String = client
        .query_one("SELECT current_setting('server_version')", &[])
        .await
        .map_err(possible)?
        .get(0);
    let expected_major = expected_provider_version
        .split('.')
        .next()
        .filter(|value| !value.is_empty())
        .ok_or(ProfileRuntimeError::Invalid)?;
    if version.split('.').next() != Some(expected_major) {
        return Err(ProfileRuntimeError::Invalid);
    }
    let migration = include_str!("../migrations/auths_execution_ledger.sql")
        .replace("auths_executor", "auths_qualification_executor")
        .replace("auths_audit", "auths_qualification_audit");
    client.batch_execute(&migration).await.map_err(possible)?;
    client
        .batch_execute(
            "BEGIN;
             CREATE SCHEMA IF NOT EXISTS qualification_schema AUTHORIZATION auths_qualification_owner;
             CREATE TABLE IF NOT EXISTS qualification_schema.tenant_rows (
                 id text PRIMARY KEY,
                 tenant_id text NOT NULL,
                 value text NOT NULL,
                 row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0)
             );
             ALTER TABLE qualification_schema.tenant_rows OWNER TO auths_qualification_owner;
             ALTER TABLE qualification_schema.tenant_rows ENABLE ROW LEVEL SECURITY;
             ALTER TABLE qualification_schema.tenant_rows FORCE ROW LEVEL SECURITY;
             CREATE OR REPLACE FUNCTION qualification_schema.auths_bump_row_version()
             RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
             SET search_path = pg_catalog, qualification_schema AS $auths$
             BEGIN NEW.row_version = OLD.row_version + 1; RETURN NEW; END
             $auths$;
             DROP TRIGGER IF EXISTS auths_row_version ON qualification_schema.tenant_rows;
             CREATE TRIGGER auths_row_version BEFORE UPDATE ON qualification_schema.tenant_rows
             FOR EACH ROW EXECUTE FUNCTION qualification_schema.auths_bump_row_version();
             DROP POLICY IF EXISTS auths_tenant_policy ON qualification_schema.tenant_rows;
             CREATE POLICY auths_tenant_policy ON qualification_schema.tenant_rows
             USING (tenant_id = current_setting('app.tenant_id', true))
             WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
             REVOKE ALL ON SCHEMA qualification_schema FROM PUBLIC;
             REVOKE ALL ON qualification_schema.tenant_rows FROM PUBLIC;
             GRANT USAGE ON SCHEMA qualification_schema TO auths_qualification_preflight;
             GRANT USAGE ON SCHEMA qualification_schema TO auths_qualification_executor;
             GRANT USAGE ON SCHEMA qualification_schema TO auths_qualification_audit;
             GRANT SELECT ON qualification_schema.tenant_rows TO auths_qualification_preflight;
             GRANT SELECT, UPDATE ON qualification_schema.tenant_rows TO auths_qualification_executor;
             GRANT SELECT ON qualification_schema.tenant_rows TO auths_qualification_audit;
             COMMIT;",
        )
        .await
        .map_err(possible)?;
    for scenario_id in scenario_ids {
        let tenant = format!("tenant-{scenario_id}");
        let row_id = format!("row-{scenario_id}");
        client
            .execute(
                "INSERT INTO qualification_schema.tenant_rows(id,tenant_id,value,row_version)
                 VALUES($1,$2,'before',1)
                 ON CONFLICT(id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id,value='before',row_version=1",
                &[&row_id, &tenant],
            )
            .await
            .map_err(possible)?;
    }
    Ok(())
}

/// Exact provider-owned facts read through the separately credentialed audit
/// role. This deliberately contains only public commitments; the connection
/// string and row value never cross the protected observer boundary.
#[cfg(feature = "qualification")]
pub(crate) struct QualificationPostgresqlObservation {
    pub(crate) server_identity_sha256: String,
    pub(crate) database_sha256: String,
    pub(crate) transaction_sha256: Option<String>,
    pub(crate) primary_key_sha256: String,
    pub(crate) before_version: u64,
    pub(crate) after_version: u64,
    pub(crate) applied: bool,
}

/// Independently reads the execution ledger and exact scenario row through
/// the protected audit identity. No candidate journal or provider result is
/// accepted as input.
#[cfg(feature = "qualification")]
pub(crate) async fn observe_qualification_scenario(
    credential: &[u8],
    scenario_id: &str,
    operation_id: &str,
    profile: &str,
    expected_provider_version: &str,
) -> Result<QualificationPostgresqlObservation, ProfileRuntimeError> {
    if scenario_id.is_empty()
        || scenario_id.len() > 128
        || !scenario_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || operation_id.is_empty()
        || operation_id.len() > 128
    {
        return Err(ProfileRuntimeError::Invalid);
    }
    let secret = PostgresConnectionSecretV1::from_canonical_bytes(credential)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let config =
        Config::from_str(secret.connection_string()).map_err(|_| ProfileRuntimeError::Invalid)?;
    let host = match config.get_hosts() {
        [Host::Tcp(host)] => host.as_str(),
        _ => return Err(ProfileRuntimeError::Invalid),
    };
    let port = match config.get_ports() {
        [] => 5432,
        [port] => *port,
        _ => return Err(ProfileRuntimeError::Invalid),
    };
    let database = config.get_dbname().ok_or(ProfileRuntimeError::Invalid)?;
    if config.get_user() != Some("auths_qualification_audit") {
        return Err(ProfileRuntimeError::Invalid);
    }
    let server_identity = format!("postgresql://{host}:{port}");
    let client = connect_secret(&secret).await?;
    let version: String = client
        .query_one("SELECT current_setting('server_version')", &[])
        .await
        .map_err(possible)?
        .get(0);
    if version.split_whitespace().next() != Some(expected_provider_version) {
        return Err(ProfileRuntimeError::Invalid);
    }
    let tenant = format!("tenant-{scenario_id}");
    let row_id = format!("row-{scenario_id}");
    client
        .query_one(
            "SELECT set_config('app.tenant_id', $1::text, false)",
            &[&tenant],
        )
        .await
        .map_err(possible)?;
    let row = client
        .query_one(
            "SELECT id, row_version FROM qualification_schema.tenant_rows \
             WHERE id=$1 AND tenant_id=$2",
            &[&row_id, &tenant],
        )
        .await
        .map_err(possible)?;
    let observed_row_id: String = row.get(0);
    let after_version =
        u64::try_from(row.get::<_, i64>(1)).map_err(|_| ProfileRuntimeError::Invalid)?;
    if observed_row_id != row_id || after_version == 0 {
        return Err(ProfileRuntimeError::Invalid);
    }
    let ledger = client
        .query_opt(
            "SELECT profile, result_commitment, EXTRACT(EPOCH FROM committed_at)::bigint \
             FROM auths_internal.auths_execution_ledger \
             WHERE claim_id=$1 AND committed_at IS NOT NULL",
            &[&operation_id],
        )
        .await
        .map_err(possible)?;
    let (applied, transaction_sha256) = match ledger {
        Some(row) if profile == "auths.postgresql.bounded-update/1" => {
            let ledger_profile: String = row.get(0);
            let result_commitment: String = row.get(1);
            let committed_at =
                u64::try_from(row.get::<_, i64>(2)).map_err(|_| ProfileRuntimeError::Invalid)?;
            if ledger_profile != profile || DigestHex::parse(result_commitment.clone()).is_err() {
                return Err(ProfileRuntimeError::Invalid);
            }
            let bytes = crate::canonical::canonical_json(&(
                operation_id,
                result_commitment.as_str(),
                committed_at,
            ))
            .map_err(invalid)?;
            (true, Some(hex::encode(sha2::Sha256::digest(bytes))))
        }
        None => (false, None),
        Some(_) => return Err(ProfileRuntimeError::Invalid),
    };
    let before_version = after_version
        .checked_sub(u64::from(applied))
        .ok_or(ProfileRuntimeError::Invalid)?;
    let primary_key = vec![NamedValueV1 {
        column: PgIdentifier::parse("id").map_err(invalid)?,
        value: TypedValueV1::text(observed_row_id).map_err(invalid)?,
    }];
    Ok(QualificationPostgresqlObservation {
        server_identity_sha256: hex::encode(sha2::Sha256::digest(server_identity.as_bytes())),
        database_sha256: hex::encode(sha2::Sha256::digest(database.as_bytes())),
        transaction_sha256,
        primary_key_sha256: hex::encode(sha2::Sha256::digest(
            crate::canonical::canonical_json(&primary_key).map_err(invalid)?,
        )),
        before_version,
        after_version,
        applied,
    })
}

/// Removes the run-owned schemas and disables every qualification credential,
/// then re-reads both facts before returning. The cleanup credential must be a
/// separately reviewed administrative connection; it is never accepted by the
/// candidate runtime.
#[cfg(feature = "qualification")]
pub(crate) async fn cleanup_qualification_row(
    credential: &[u8],
) -> Result<(), ProfileRuntimeError> {
    let secret = PostgresConnectionSecretV1::from_canonical_bytes(credential)
        .map_err(|_| ProfileRuntimeError::Invalid)?;
    let client = connect_secret(&secret).await?;
    client
        .batch_execute(
            "DROP SCHEMA IF EXISTS qualification_schema CASCADE;
             DROP SCHEMA IF EXISTS auths_internal CASCADE;
             ALTER ROLE auths_qualification_executor NOLOGIN;
             ALTER ROLE auths_qualification_preflight NOLOGIN;
             ALTER ROLE auths_qualification_audit NOLOGIN;
             ALTER ROLE auths_qualification_setup NOLOGIN;",
        )
        .await
        .map_err(possible)?;
    let row = client
        .query_one(
            "SELECT to_regnamespace('qualification_schema') IS NULL,
                    to_regnamespace('auths_internal') IS NULL,
                    count(*) FILTER (WHERE rolcanlogin)
             FROM pg_catalog.pg_roles
             WHERE rolname IN (
                 'auths_qualification_executor',
                 'auths_qualification_preflight',
                 'auths_qualification_audit',
                 'auths_qualification_setup'
             )",
            &[],
        )
        .await
        .map_err(possible)?;
    if !row.get::<_, bool>(0) || !row.get::<_, bool>(1) || row.get::<_, i64>(2) != 0 {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn discover_evidence(
    client: &impl GenericClient,
    descriptor: &PostgresConnectionDescriptor,
    configuration: &PostgresVerifierConfigurationV1,
    policy: &RelationPolicyV1,
    tenant: &str,
    assignments: &[(String, String)],
    now: u64,
) -> Result<PostgresEvidenceV1, ProfileRuntimeError> {
    client
        .query_one(
            "SELECT set_config('search_path', 'pg_catalog', false),\
             set_config('application_name', 'auths-postgresql-update-preflight/1', true),\
             set_config('app.tenant_id', $1::text, true)",
            &[&tenant],
        )
        .await
        .map_err(possible)?;
    let relation = client.query_one(
        "SELECT c.oid::int8, n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity,\
         pg_get_userbyid(c.relowner) = current_user, r.rolbypassrls, r.rolsuper,\
         r.rolcreaterole, r.rolcreatedb, r.rolreplication,\
         has_database_privilege(current_user, current_database(), 'CREATE'),\
         has_schema_privilege(current_user, n.oid, 'CREATE'),\
         has_table_privilege(current_user, c.oid, 'TRUNCATE'),\
         EXISTS (SELECT 1 FROM pg_catalog.pg_rewrite w WHERE w.ev_class=c.oid AND w.rulename <> '_RETURN'),\
         c.relkind::text, current_database(), current_user, current_setting('server_version')\
         FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace\
         JOIN pg_catalog.pg_roles r ON r.rolname=current_user\
         WHERE n.nspname=$1 AND c.relname=$2",
        &[&policy.schema.as_str(), &policy.table.as_str()],
    ).await.map_err(possible)?;
    let relation_oid =
        u32::try_from(relation.get::<_, i64>(0)).map_err(|_| ProfileRuntimeError::Invalid)?;
    let catalog = catalog_material(client, relation_oid).await?;
    let columns = catalog_columns(client, relation_oid).await?;
    let primary_key_columns = catalog_primary_key(client, relation_oid).await?;
    if primary_key_columns != policy.primary_key_columns {
        return Err(ProfileRuntimeError::Invalid);
    }
    let rows = discover_rows(
        client,
        policy,
        tenant,
        assignments,
        configuration.maximum_rows(),
    )
    .await?;
    let tenant_value = TypedValueV1::text(tenant).map_err(invalid)?;
    let role: String = relation.get(17);
    let privilege_fingerprint = canonical_digest(&(
        role.as_str(),
        relation.get::<_, bool>(5),
        relation.get::<_, bool>(6),
        relation.get::<_, bool>(7),
        relation.get::<_, bool>(8),
        relation.get::<_, bool>(9),
        relation.get::<_, bool>(10),
        relation.get::<_, bool>(11),
        relation.get::<_, bool>(12),
        relation.get::<_, bool>(13),
    ))
    .map_err(invalid)?;
    let audience = configuration
        .first_database_audience()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let evidence = PostgresEvidenceV1 {
        database_server_identity: descriptor.server_identity().into(),
        database_audience: audience.into(),
        database_name: PgIdentifier::parse(relation.get::<_, String>(16)).map_err(invalid)?,
        schema_name: PgIdentifier::parse(relation.get::<_, String>(1)).map_err(invalid)?,
        table_name: PgIdentifier::parse(relation.get::<_, String>(2)).map_err(invalid)?,
        relation_oid,
        schema_fingerprint: catalog.schema_fingerprint,
        policy_fingerprint: catalog.policy_fingerprint,
        trigger_fingerprint: catalog.trigger_fingerprint,
        privilege_fingerprint,
        row_security_enabled: relation.get(3),
        row_security_forced: relation.get(4),
        executor_role: PgIdentifier::parse(role).map_err(invalid)?,
        executor_owns_relation: relation.get(5),
        executor_bypass_rls: relation.get(6),
        executor_superuser: relation.get(7),
        executor_create_role: relation.get(8),
        executor_create_database: relation.get(9),
        executor_replication: relation.get(10),
        executor_database_create: relation.get(11),
        executor_schema_create: relation.get(12),
        executor_table_truncate: relation.get(13),
        has_rewrite_rules: relation.get(14),
        is_foreign_table: relation.get::<_, String>(15) == "f",
        has_partition_routing: relation.get::<_, String>(15) == "p",
        columns,
        tenant_column: policy.tenant_column.clone(),
        tenant_value_commitment: canonical_digest(&tenant_value).map_err(invalid)?,
        primary_key_columns,
        row_version_column: policy.row_version_column.clone(),
        rows,
        server_version: relation.get(18),
        evidence_source: "tls-protected-catalog-discovery-v1".into(),
        observed_at: now,
    };
    evidence.validate().map_err(invalid)?;
    Ok(evidence)
}

async fn discover_rows(
    client: &impl GenericClient,
    policy: &RelationPolicyV1,
    tenant: &str,
    assignments: &[(String, String)],
    maximum_rows: u32,
) -> Result<Vec<ObservedRowV1>, ProfileRuntimeError> {
    let assignment_columns = assignments
        .iter()
        .map(|(name, _)| PgIdentifier::parse(name))
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid)?;
    let mut columns = policy.primary_key_columns.clone();
    for column in &assignment_columns {
        if !columns.contains(column) {
            columns.push(column.clone());
        }
    }
    columns.sort();
    let select = columns
        .iter()
        .map(|column| format!("{}::text AS {}", column.quoted(), column.quoted()))
        .chain(std::iter::once(format!(
            "{}::text AS {}",
            policy.row_version_column.quoted(),
            policy.row_version_column.quoted()
        )))
        .collect::<Vec<_>>()
        .join(", ");
    let order = policy
        .primary_key_columns
        .iter()
        .map(PgIdentifier::quoted)
        .collect::<Vec<_>>()
        .join(", ");
    let limit = maximum_rows.saturating_add(1);
    let sql = format!(
        "SELECT {select} FROM {}.{} WHERE {}::text = $1::text ORDER BY {order} LIMIT {limit}",
        policy.schema.quoted(),
        policy.table.quoted(),
        policy.tenant_column.quoted()
    );
    let rows = client.query(&sql, &[&tenant]).await.map_err(possible)?;
    if rows.is_empty() || rows.len() > maximum_rows as usize {
        return Err(ProfileRuntimeError::Invalid);
    }
    rows.into_iter()
        .map(|row| {
            let primary_key = policy
                .primary_key_columns
                .iter()
                .map(|column| {
                    Ok(NamedValueV1 {
                        column: column.clone(),
                        value: TypedValueV1::text(
                            row.try_get::<_, String>(column.as_str())
                                .map_err(possible)?,
                        )
                        .map_err(invalid)?,
                    })
                })
                .collect::<Result<Vec<_>, ProfileRuntimeError>>()?;
            let before_values = assignment_columns
                .iter()
                .map(|column| {
                    let constraint = policy
                        .assignment_constraints
                        .iter()
                        .find(|(name, _)| name == column)
                        .map(|(_, value)| value)
                        .ok_or(ProfileRuntimeError::Invalid)?;
                    let value = TypedValueV1::text(
                        row.try_get::<_, String>(column.as_str())
                            .map_err(possible)?,
                    )
                    .map_err(invalid)?;
                    value.validate(constraint).map_err(invalid)?;
                    Ok(NamedValueV1 {
                        column: column.clone(),
                        value,
                    })
                })
                .collect::<Result<Vec<_>, ProfileRuntimeError>>()?;
            let version = row
                .try_get::<_, String>(policy.row_version_column.as_str())
                .map_err(possible)?
                .parse::<i64>()
                .map_err(|_| ProfileRuntimeError::Invalid)?;
            Ok(ObservedRowV1 {
                primary_key,
                before_values,
                row_version: version,
            })
        })
        .collect()
}

#[derive(Serialize)]
#[allow(clippy::struct_field_names)]
struct CatalogMaterial {
    schema_fingerprint: DigestHex,
    policy_fingerprint: DigestHex,
    trigger_fingerprint: DigestHex,
}

async fn catalog_material(
    client: &impl GenericClient,
    relation_oid: u32,
) -> Result<CatalogMaterial, ProfileRuntimeError> {
    let oid = i64::from(relation_oid);
    let columns = client.query("SELECT attnum::int, attname, format_type(atttypid, atttypmod), attnotnull, attgenerated::text, atthasdef FROM pg_catalog.pg_attribute WHERE attrelid=$1::bigint::oid AND attnum>0 AND NOT attisdropped ORDER BY attnum", &[&oid]).await.map_err(possible)?.into_iter().map(|row| (row.get::<_,i32>(0),row.get::<_,String>(1),row.get::<_,String>(2),row.get::<_,bool>(3),row.get::<_,String>(4),row.get::<_,bool>(5))).collect::<Vec<_>>();
    let policies = client.query("SELECT polname, polcmd::text, polpermissive, COALESCE(pg_get_expr(polqual,polrelid),''), COALESCE(pg_get_expr(polwithcheck,polrelid),''), polroles::text FROM pg_catalog.pg_policy WHERE polrelid=$1::bigint::oid ORDER BY polname", &[&oid]).await.map_err(possible)?.into_iter().map(|row| (row.get::<_,String>(0),row.get::<_,String>(1),row.get::<_,bool>(2),row.get::<_,String>(3),row.get::<_,String>(4),row.get::<_,String>(5))).collect::<Vec<_>>();
    let triggers = client.query("SELECT tgname, tgenabled::text, pg_get_triggerdef(oid,true) FROM pg_catalog.pg_trigger WHERE tgrelid=$1::bigint::oid AND NOT tgisinternal ORDER BY tgname", &[&oid]).await.map_err(possible)?.into_iter().map(|row| (row.get::<_,String>(0),row.get::<_,String>(1),row.get::<_,String>(2))).collect::<Vec<_>>();
    Ok(CatalogMaterial {
        schema_fingerprint: canonical_digest(&columns).map_err(invalid)?,
        policy_fingerprint: canonical_digest(&policies).map_err(invalid)?,
        trigger_fingerprint: canonical_digest(&triggers).map_err(invalid)?,
    })
}

async fn catalog_columns(
    client: &impl GenericClient,
    relation_oid: u32,
) -> Result<Vec<ColumnEvidenceV1>, ProfileRuntimeError> {
    let oid = i64::from(relation_oid);
    client.query("SELECT attname, format_type(atttypid,atttypmod), NOT attnotnull, attgenerated <> '', atthasdef FROM pg_catalog.pg_attribute WHERE attrelid=$1::bigint::oid AND attnum>0 AND NOT attisdropped ORDER BY attname", &[&oid]).await.map_err(possible)?.into_iter().map(|row| Ok(ColumnEvidenceV1 { name: PgIdentifier::parse(row.get::<_,String>(0)).map_err(invalid)?, database_type: row.get(1), nullable: row.get(2), generated: row.get(3), has_default: row.get(4) })).collect()
}

async fn catalog_primary_key(
    client: &impl GenericClient,
    relation_oid: u32,
) -> Result<Vec<PgIdentifier>, ProfileRuntimeError> {
    let oid = i64::from(relation_oid);
    let rows = client
        .query(
            "SELECT attribute.attname\
             FROM pg_catalog.pg_index AS index_record\
             JOIN pg_catalog.pg_attribute AS attribute\
               ON attribute.attrelid = index_record.indrelid\
              AND attribute.attnum = ANY(index_record.indkey)\
             WHERE index_record.indrelid = $1::bigint::oid\
               AND index_record.indisprimary\
             ORDER BY array_position(index_record.indkey, attribute.attnum)",
            &[&oid],
        )
        .await
        .map_err(possible)?;
    if rows.is_empty() || rows.len() > 16 {
        return Err(ProfileRuntimeError::Invalid);
    }
    rows.into_iter()
        .map(|row| PgIdentifier::parse(row.get::<_, String>(0)).map_err(invalid))
        .collect()
}

async fn configure_session(
    transaction: &Transaction<'_>,
    payload: &PreparedUpdatePayloadV1,
    operation_id: &str,
) -> Result<(), ProfileRuntimeError> {
    let role = payload.action.executor_role.quoted();
    transaction
        .batch_execute(&format!("SET LOCAL ROLE {role}"))
        .await
        .map_err(possible)?;
    let tenant = payload
        .action
        .intent
        .tenant_value
        .protocol_text()
        .ok_or(ProfileRuntimeError::Invalid)?;
    transaction.query_one("SELECT set_config('search_path','pg_catalog',true), set_config('application_name','auths-postgresql-bounded-update/1',true), set_config('statement_timeout',$1::text,true), set_config('lock_timeout',$2::text,true), set_config('app.tenant_id',$3::text,true), set_config('auths.operation_id',$4::text,true)", &[&format!("{}ms", payload.configuration.statement_timeout_ms()), &format!("{}ms", payload.configuration.lock_timeout_ms()), &tenant, &operation_id]).await.map_err(possible)?;
    Ok(())
}

async fn recheck_all(
    transaction: &Transaction<'_>,
    payload: &PreparedUpdatePayloadV1,
) -> Result<(), ProfileRuntimeError> {
    let policy = payload
        .configuration
        .relation(
            &payload.action.intent.database_name,
            &payload.action.intent.schema_name,
            &payload.action.intent.table_name,
        )
        .ok_or(ProfileRuntimeError::Invalid)?;
    let tenant = payload
        .action
        .intent
        .tenant_value
        .protocol_text()
        .ok_or(ProfileRuntimeError::Invalid)?;
    let assignments = payload
        .action
        .intent
        .assignments
        .iter()
        .map(|value| {
            Ok((
                value.column.as_str().to_owned(),
                value
                    .value
                    .protocol_text()
                    .ok_or(ProfileRuntimeError::Invalid)?,
            ))
        })
        .collect::<Result<Vec<_>, ProfileRuntimeError>>()?;
    let mut current = discover_evidence(
        transaction,
        &payload.descriptor,
        &payload.configuration,
        policy,
        &tenant,
        &assignments,
        payload.evidence.observed_at,
    )
    .await?;
    current.observed_at = payload.evidence.observed_at;
    if current != payload.evidence {
        return Err(ProfileRuntimeError::Invalid);
    }
    Ok(())
}

async fn reserve_ledger(
    transaction: &Transaction<'_>,
    payload: &PreparedUpdatePayloadV1,
    operation_id: &str,
    digest: &DigestHex,
    now: u64,
) -> Result<(), ProfileRuntimeError> {
    let oid = i64::from(payload.action.relation_oid);
    let started = i64::try_from(now).map_err(|_| ProfileRuntimeError::Invalid)?;
    let prepared: bool = transaction
        .query_one(
            "SELECT auths_internal.auths_prepare_execution($1,$2,$3,$4::bigint::oid,$5,$6,$7,$8,$9)",
            &[&digest.as_str(), &operation_id, &payload.action.intent.profile, &oid, &payload.action.tenant_commitment.as_str(), &payload.action.row_set_digest.as_str(), &payload.action.before_state_digest.as_str(), &payload.action.after_state_digest.as_str(), &started],
        )
        .await
        .map_err(possible)?
        .get(0);
    if prepared {
        Ok(())
    } else {
        Err(ProfileRuntimeError::Invalid)
    }
}

async fn finalize_ledger(
    transaction: &Transaction<'_>,
    payload: &PreparedUpdatePayloadV1,
    operation_id: &str,
    digest: &DigestHex,
    affected: u32,
    commitment: &DigestHex,
    committed: u64,
) -> Result<(), ProfileRuntimeError> {
    let oid = i64::from(payload.action.relation_oid);
    let affected = i32::try_from(affected).map_err(|_| ProfileRuntimeError::Invalid)?;
    let committed = i64::try_from(committed).map_err(|_| ProfileRuntimeError::Invalid)?;
    let finalized: bool = transaction
        .query_one(
            "SELECT auths_internal.auths_finalize_execution($1,$2,$3,$4::bigint::oid,$5,$6,$7,$8,$9,$10,$11)",
            &[&digest.as_str(), &operation_id, &payload.action.intent.profile, &oid, &payload.action.tenant_commitment.as_str(), &payload.action.row_set_digest.as_str(), &payload.action.before_state_digest.as_str(), &payload.action.after_state_digest.as_str(), &affected, &commitment.as_str(), &committed],
        )
        .await
        .map_err(possible)?
        .get(0);
    if finalized {
        Ok(())
    } else {
        Err(ProfileRuntimeError::Invalid)
    }
}

fn validate_before_rows(
    payload: &PreparedUpdatePayloadV1,
    rows: &[Row],
) -> Result<(), ProfileRuntimeError> {
    validate_rows(payload, rows, false)
}
fn validate_after_rows(
    payload: &PreparedUpdatePayloadV1,
    rows: &[Row],
) -> Result<(), ProfileRuntimeError> {
    validate_rows(payload, rows, true)
}
fn validate_rows(
    payload: &PreparedUpdatePayloadV1,
    rows: &[Row],
    after: bool,
) -> Result<(), ProfileRuntimeError> {
    if rows.len() != payload.evidence.rows.len() {
        return Err(ProfileRuntimeError::Invalid);
    }
    for expected in &payload.evidence.rows {
        let row = rows
            .iter()
            .find(|row| {
                expected.primary_key.iter().all(|key| {
                    row.try_get::<_, Option<String>>(key.column.as_str()).ok()
                        == Some(key.value.protocol_text())
                })
            })
            .ok_or(ProfileRuntimeError::Invalid)?;
        for key in &expected.primary_key {
            if row
                .try_get::<_, Option<String>>(key.column.as_str())
                .map_err(possible)?
                != key.value.protocol_text()
            {
                return Err(ProfileRuntimeError::Invalid);
            }
        }
        let expected_values = if after {
            payload
                .action
                .intent
                .assignments
                .iter()
                .map(|value| NamedValueV1 {
                    column: value.column.clone(),
                    value: value.value.clone(),
                })
                .collect::<Vec<_>>()
        } else {
            expected.before_values.clone()
        };
        for value in expected_values {
            if row
                .try_get::<_, Option<String>>(value.column.as_str())
                .map_err(possible)?
                != value.value.protocol_text()
            {
                return Err(ProfileRuntimeError::Invalid);
            }
        }
        let version = row
            .try_get::<_, String>(payload.evidence.row_version_column.as_str())
            .map_err(possible)?
            .parse::<i64>()
            .map_err(|_| ProfileRuntimeError::Invalid)?;
        if version != expected.row_version.saturating_add(i64::from(after)) {
            return Err(ProfileRuntimeError::Invalid);
        }
    }
    Ok(())
}

async fn readback(
    client: &Client,
    payload: &PreparedUpdatePayloadV1,
    compiled: &CompiledBoundedUpdate,
) -> Result<DigestHex, ProfileRuntimeError> {
    let tenant = payload
        .action
        .intent
        .tenant_value
        .protocol_text()
        .ok_or(ProfileRuntimeError::Invalid)?;
    client
        .query_one(
            "SELECT set_config('app.tenant_id',$1::text,false)",
            &[&tenant],
        )
        .await
        .map_err(possible)?;
    let values = compiled
        .readback_parameters
        .iter()
        .map(|binding| binding.value.protocol_text())
        .collect::<Vec<_>>();
    let rows = client
        .query(&compiled.readback_sql, &parameter_refs(&values))
        .await
        .map_err(possible)?;
    validate_after_rows(payload, &rows)?;
    Ok(payload.action.after_state_digest.clone())
}

fn parameter_refs(values: &[Option<String>]) -> Vec<&(dyn ToSql + Sync)> {
    values
        .iter()
        .map(|value| value as &(dyn ToSql + Sync))
        .collect()
}
fn split_relation(value: &str) -> Result<(PgIdentifier, PgIdentifier), ValidationError> {
    let mut parts = value.split('.');
    let schema = PgIdentifier::parse(parts.next().ok_or(ValidationError::MalformedMutation)?)?;
    let table = PgIdentifier::parse(parts.next().ok_or(ValidationError::MalformedMutation)?)?;
    if parts.next().is_some() {
        return Err(ValidationError::MalformedMutation);
    }
    Ok((schema, table))
}
fn lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
fn invalid(_: impl core::fmt::Debug) -> ProfileRuntimeError {
    ProfileRuntimeError::Invalid
}
fn possible(_: impl core::fmt::Debug) -> ProfileRuntimeError {
    ProfileRuntimeError::Possible(Vec::new())
}
