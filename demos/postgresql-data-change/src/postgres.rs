//! Protected fixture and TLS PostgreSQL transaction adapters.

use std::{
    collections::BTreeMap,
    str::FromStr as _,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use auths_postgresql::{
    CredentialProvider, DigestHex, NamedValueV1, ObservedRowV1, PortError, PostgresCredential,
    PostgresEvidenceV1, Reconciliation, TransactionGateway, TransactionResult, TypedValueV1,
    VerifiedBoundedUpdateCommand, canonical::canonical_digest,
};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, pem::PemObject as _};
use serde::{Deserialize, Serialize};
use tokio_postgres::{
    Client, Config, IsolationLevel, Row, Transaction, config::SslMode, error::SqlState,
    types::ToSql,
};
use tokio_postgres_rustls::MakeRustlsConnect;

const MAX_SERIALIZATION_RETRIES: usize = 3;

/// Startup-controlled fault points used by the live recovery suite.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PostgresFault {
    #[default]
    None,
    BeforeTransaction,
    AfterUpdateRollback,
    BeforeCommitUnknown,
    AfterCommitUnknown,
    AfterCommitUnreconciled,
    ReconcileUnavailable,
    StatementTimeout,
}

impl PostgresFault {
    const fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::BeforeTransaction => 1,
            Self::AfterUpdateRollback => 2,
            Self::BeforeCommitUnknown => 3,
            Self::AfterCommitUnknown => 4,
            Self::AfterCommitUnreconciled => 5,
            Self::ReconcileUnavailable => 6,
            Self::StatementTimeout => 7,
        }
    }

    const fn from_code(code: u8) -> Self {
        match code {
            1 => Self::BeforeTransaction,
            2 => Self::AfterUpdateRollback,
            3 => Self::BeforeCommitUnknown,
            4 => Self::AfterCommitUnknown,
            5 => Self::AfterCommitUnreconciled,
            6 => Self::ReconcileUnavailable,
            7 => Self::StatementTimeout,
            _ => Self::None,
        }
    }
}

struct SecretBytes(Vec<u8>);

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DatabaseSecret {
    connection_string: String,
    ca_pem: Option<String>,
}

#[derive(Clone)]
enum BackendMode {
    Fixture {
        state: Arc<Mutex<FixtureState>>,
    },
    Live {
        server_identity: String,
        audience: String,
        tenant: String,
    },
}

#[derive(Default)]
struct FixtureState {
    evidence: Option<PostgresEvidenceV1>,
    ledger: BTreeMap<DigestHex, TransactionResult>,
}

/// Protected database backend. The proposing agent never receives its secret.
#[derive(Clone)]
pub struct PostgresBackend {
    mode: BackendMode,
    credential: Arc<SecretBytes>,
    credential_calls: Arc<AtomicUsize>,
    transaction_calls: Arc<AtomicUsize>,
    fault: Arc<AtomicU8>,
}

impl PostgresBackend {
    #[must_use]
    pub fn fixture(evidence: PostgresEvidenceV1) -> Self {
        Self {
            mode: BackendMode::Fixture {
                state: Arc::new(Mutex::new(FixtureState {
                    evidence: Some(evidence),
                    ledger: BTreeMap::new(),
                })),
            },
            credential: Arc::new(SecretBytes(
                b"postgresql://fixture:protected@fixture/auths_demo?sslmode=require".to_vec(),
            )),
            credential_calls: Arc::new(AtomicUsize::new(0)),
            transaction_calls: Arc::new(AtomicUsize::new(0)),
            fault: Arc::new(AtomicU8::new(PostgresFault::None.code())),
        }
    }

    pub fn live(
        connection_string: String,
        ca_pem: Option<String>,
        server_identity: String,
        audience: String,
        tenant: String,
    ) -> Result<Self, PortError> {
        validate_connection_string(connection_string.as_bytes())?;
        if ca_pem
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 1024 * 1024)
        {
            return Err(PortError::InvalidConfiguration);
        }
        let secret = serde_json::to_vec(&DatabaseSecret {
            connection_string,
            ca_pem,
        })
        .map_err(|_| PortError::InvalidConfiguration)?;
        if server_identity.is_empty()
            || audience.is_empty()
            || tenant.is_empty()
            || tenant.len() > 256
        {
            return Err(PortError::InvalidConfiguration);
        }
        Ok(Self {
            mode: BackendMode::Live {
                server_identity,
                audience,
                tenant,
            },
            credential: Arc::new(SecretBytes(secret)),
            credential_calls: Arc::new(AtomicUsize::new(0)),
            transaction_calls: Arc::new(AtomicUsize::new(0)),
            fault: Arc::new(AtomicU8::new(PostgresFault::None.code())),
        })
    }

    #[must_use]
    pub fn label(&self) -> &'static str {
        match self.mode {
            BackendMode::Fixture { .. } => "deterministic-postgresql-fixture",
            BackendMode::Live { .. } => "tls-postgresql",
        }
    }

    #[must_use]
    pub fn credential_calls(&self) -> usize {
        self.credential_calls.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn transaction_calls(&self) -> usize {
        self.transaction_calls.load(Ordering::SeqCst)
    }

    pub fn set_fault(&self, fault: PostgresFault) {
        self.fault.store(fault.code(), Ordering::SeqCst);
    }

    pub async fn readiness(&self) -> Result<(), PortError> {
        match &self.mode {
            BackendMode::Fixture { .. } => Ok(()),
            BackendMode::Live { .. } => {
                let credential = PostgresCredential::new(self.credential.0.clone())?;
                let client = connect(&credential).await?;
                client
                    .query_one("SELECT 1::bigint", &[])
                    .await
                    .map(|_| ())
                    .map_err(|_| PortError::DatabaseExecution)
            }
        }
    }

    /// Protected read path for the fixed synthetic demo relation.
    pub async fn discover(&self, now: u64) -> Result<PostgresEvidenceV1, PortError> {
        match &self.mode {
            BackendMode::Fixture { state } => state
                .lock()
                .map_err(|_| PortError::Persistence)?
                .evidence
                .clone()
                .ok_or(PortError::DatabaseExecution),
            BackendMode::Live {
                server_identity,
                audience,
                tenant,
            } => {
                let credential = PostgresCredential::new(self.credential.0.clone())?;
                let client = connect(&credential).await?;
                discover_live(&client, server_identity, audience, tenant, now).await
            }
        }
    }

    /// Reads the three synthetic demo rows for adjacent before/after display.
    /// This protected read never returns a credential or a reusable predicate.
    pub async fn demo_rows(&self) -> Result<Vec<ObservedRowV1>, PortError> {
        match &self.mode {
            BackendMode::Fixture { state } => state
                .lock()
                .map_err(|_| PortError::Persistence)?
                .evidence
                .as_ref()
                .map(|evidence| evidence.rows.clone())
                .ok_or(PortError::DatabaseExecution),
            BackendMode::Live { tenant, .. } => {
                let credential = PostgresCredential::new(self.credential.0.clone())?;
                let client = connect(&credential).await?;
                read_demo_rows(&client, tenant, false).await
            }
        }
    }
}

impl CredentialProvider for PostgresBackend {
    fn mutation_credential(
        &self,
        _: &auths_postgresql::PostgresBoundedUpdateV1,
    ) -> Result<PostgresCredential, PortError> {
        self.credential_calls.fetch_add(1, Ordering::SeqCst);
        PostgresCredential::new(self.credential.0.clone())
    }
}

#[async_trait]
impl TransactionGateway for PostgresBackend {
    async fn execute(
        &self,
        command: &VerifiedBoundedUpdateCommand,
        credential: &PostgresCredential,
        now: u64,
    ) -> Result<TransactionResult, PortError> {
        self.transaction_calls.fetch_add(1, Ordering::SeqCst);
        let fault = PostgresFault::from_code(
            self.fault
                .swap(PostgresFault::None.code(), Ordering::SeqCst),
        );
        if fault == PostgresFault::BeforeTransaction {
            return Err(PortError::DatabaseExecution);
        }
        match &self.mode {
            BackendMode::Fixture { state } => execute_fixture(state, command, now),
            BackendMode::Live { .. } => {
                for attempt in 0..MAX_SERIALIZATION_RETRIES {
                    match execute_live(command, credential, now, fault, &self.fault).await {
                        Err(PortError::TransactionConflict)
                            if attempt + 1 < MAX_SERIALIZATION_RETRIES =>
                        {
                            match reconcile_live(command, credential).await? {
                                Reconciliation::Committed(result) => return Ok(result),
                                Reconciliation::NotCommitted => {}
                                Reconciliation::Unavailable => {
                                    return Err(PortError::OutcomeUnknown);
                                }
                            }
                        }
                        result => return result,
                    }
                }
                Err(PortError::TransactionConflict)
            }
        }
    }

    async fn reconcile(
        &self,
        command: &VerifiedBoundedUpdateCommand,
        credential: &PostgresCredential,
    ) -> Result<Reconciliation, PortError> {
        if PostgresFault::from_code(
            self.fault
                .swap(PostgresFault::None.code(), Ordering::SeqCst),
        ) == PostgresFault::ReconcileUnavailable
        {
            return Ok(Reconciliation::Unavailable);
        }
        match &self.mode {
            BackendMode::Fixture { state } => {
                let action_digest = command
                    .action()
                    .digest()
                    .map_err(|_| PortError::DatabaseExecution)?;
                Ok(state
                    .lock()
                    .map_err(|_| PortError::Persistence)?
                    .ledger
                    .get(&action_digest)
                    .cloned()
                    .map_or(Reconciliation::NotCommitted, Reconciliation::Committed))
            }
            BackendMode::Live { .. } => reconcile_live(command, credential).await,
        }
    }
}

fn execute_fixture(
    state: &Mutex<FixtureState>,
    command: &VerifiedBoundedUpdateCommand,
    now: u64,
) -> Result<TransactionResult, PortError> {
    let action = command.action();
    let action_digest = action.digest().map_err(|_| PortError::DatabaseExecution)?;
    let mut state = state.lock().map_err(|_| PortError::Persistence)?;
    if state.ledger.contains_key(&action_digest) {
        return Err(PortError::DatabaseExecution);
    }
    let current = state
        .evidence
        .as_mut()
        .ok_or(PortError::DatabaseExecution)?;
    if current
        .row_set_digest()
        .map_err(|_| PortError::DatabaseExecution)?
        != action.row_set_digest
        || current
            .before_state_digest()
            .map_err(|_| PortError::DatabaseExecution)?
            != action.before_state_digest
    {
        return Err(PortError::BeforeStateMismatch);
    }
    for row in &mut current.rows {
        for assignment in &action.intent.assignments {
            let Some(value) = row
                .before_values
                .iter_mut()
                .find(|value| value.column == assignment.column)
            else {
                return Err(PortError::AfterStateMismatch);
            };
            value.value = assignment.value.clone();
        }
        row.row_version = row.row_version.saturating_add(1);
    }
    let ledger_commitment =
        canonical_digest(&(action_digest.clone(), command.claim_id(), now, "committed"))
            .map_err(|_| PortError::DatabaseExecution)?;
    let result = TransactionResult {
        affected_rows: action.intent.expected_row_count,
        after_state_digest: action.after_state_digest.clone(),
        ledger_commitment,
        readback_commitment: action.after_state_digest.clone(),
        server_version: current.server_version.clone(),
        transaction_started_at: now,
        committed_at: now.saturating_add(1),
        reconciled: false,
    };
    state.ledger.insert(action_digest, result.clone());
    Ok(result)
}

async fn connect(credential: &PostgresCredential) -> Result<Client, PortError> {
    let secret: DatabaseSecret =
        serde_json::from_slice(credential.expose()).map_err(|_| PortError::InvalidConfiguration)?;
    let config =
        Config::from_str(&secret.connection_string).map_err(|_| PortError::InvalidConfiguration)?;
    if config.get_ssl_mode() != SslMode::Require {
        return Err(PortError::InvalidConfiguration);
    }
    let mut roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    if let Some(pem) = secret.ca_pem {
        let mut added = 0_usize;
        for certificate in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            roots
                .add(certificate.map_err(|_| PortError::InvalidConfiguration)?)
                .map_err(|_| PortError::InvalidConfiguration)?;
            added = added.saturating_add(1);
        }
        if added == 0 {
            return Err(PortError::InvalidConfiguration);
        }
    }
    let tls_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let (client, connection) = config
        .connect(MakeRustlsConnect::new(tls_config))
        .await
        .map_err(|_| PortError::CredentialUnavailable)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

fn validate_connection_string(bytes: &[u8]) -> Result<(), PortError> {
    let value = std::str::from_utf8(bytes).map_err(|_| PortError::InvalidConfiguration)?;
    let config = Config::from_str(value).map_err(|_| PortError::InvalidConfiguration)?;
    if config.get_ssl_mode() != SslMode::Require || value.len() > 64 * 1024 {
        return Err(PortError::InvalidConfiguration);
    }
    Ok(())
}

async fn execute_live(
    command: &VerifiedBoundedUpdateCommand,
    credential: &PostgresCredential,
    now: u64,
    fault: PostgresFault,
    fault_state: &AtomicU8,
) -> Result<TransactionResult, PortError> {
    let action = command.action();
    let action_digest = action.digest().map_err(|_| PortError::DatabaseExecution)?;
    let mut client = connect(credential).await?;
    let transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .read_only(false)
        .start()
        .await
        .map_err(map_transaction_error)?;
    set_session(&transaction, command).await?;
    if fault == PostgresFault::StatementTimeout {
        transaction
            .query_one("SELECT pg_sleep(10)", &[])
            .await
            .map_err(map_transaction_error)?;
        return Err(PortError::DatabaseExecution);
    }
    recheck_catalog(&transaction, command).await?;
    reserve_ledger(&transaction, command, &action_digest, now).await?;

    let values = command
        .compiled()
        .parameters
        .iter()
        .map(|binding| binding.value.protocol_text())
        .collect::<Vec<_>>();
    let lock_parameter_count = command
        .compiled()
        .parameters
        .iter()
        .take_while(|binding| binding.role != "assignment")
        .count();
    let lock_refs = parameter_refs(&values[..lock_parameter_count]);
    let locked = transaction
        .query(&command.compiled().lock_sql, &lock_refs)
        .await
        .map_err(map_transaction_error)?;
    validate_locked_rows(command, &locked)?;

    let update_refs = parameter_refs(&values);
    let updated = transaction
        .query(&command.compiled().update_sql, &update_refs)
        .await
        .map_err(map_transaction_error)?;
    validate_updated_rows(command, &updated)?;
    if fault == PostgresFault::AfterUpdateRollback {
        return Err(PortError::DatabaseExecution);
    }
    let committed_at = now.saturating_add(1);
    let ledger_commitment = canonical_digest(&(
        action_digest.clone(),
        command.claim_id(),
        action.after_state_digest.clone(),
        action.intent.expected_row_count,
        committed_at,
    ))
    .map_err(|_| PortError::DatabaseExecution)?;
    finalize_ledger(
        &transaction,
        &action_digest,
        action.intent.expected_row_count,
        &ledger_commitment,
        committed_at,
    )
    .await?;
    let server_version: String = transaction
        .query_one("SELECT current_setting('server_version')", &[])
        .await
        .map_err(map_transaction_error)?
        .get(0);
    if fault == PostgresFault::BeforeCommitUnknown {
        drop(transaction);
        return Err(PortError::OutcomeUnknown);
    }
    match transaction.commit().await {
        Ok(())
            if matches!(
                fault,
                PostgresFault::AfterCommitUnknown | PostgresFault::AfterCommitUnreconciled
            ) =>
        {
            if fault == PostgresFault::AfterCommitUnreconciled {
                fault_state.store(PostgresFault::ReconcileUnavailable.code(), Ordering::SeqCst);
            }
            Err(PortError::OutcomeUnknown)
        }
        Ok(()) => {
            let readback_commitment = readback_live(command, credential).await?;
            Ok(TransactionResult {
                affected_rows: action.intent.expected_row_count,
                after_state_digest: action.after_state_digest.clone(),
                ledger_commitment,
                readback_commitment,
                server_version,
                transaction_started_at: now,
                committed_at,
                reconciled: false,
            })
        }
        Err(error) if is_serialization(&error) => Err(PortError::TransactionConflict),
        Err(_) => Err(PortError::OutcomeUnknown),
    }
}

fn parameter_refs(values: &[Option<String>]) -> Vec<&(dyn ToSql + Sync)> {
    values
        .iter()
        .map(|value| value as &(dyn ToSql + Sync))
        .collect()
}

async fn set_session(
    transaction: &Transaction<'_>,
    command: &VerifiedBoundedUpdateCommand,
) -> Result<(), PortError> {
    let statement_timeout = command
        .action()
        .intent
        .required_configuration_digest
        .as_str();
    if command.action().executor_role.as_str() != "auths_executor" {
        return Err(PortError::InvalidConfiguration);
    }
    transaction
        .batch_execute("SET LOCAL ROLE auths_executor")
        .await
        .map_err(map_transaction_error)?;
    let tenant = command
        .action()
        .intent
        .tenant_value
        .protocol_text()
        .ok_or(PortError::InvalidConfiguration)?;
    transaction
        .query_one(
            "SELECT set_config('search_path', 'pg_catalog', true),
                    set_config('application_name', 'auths-postgresql-bounded-update/1', true),
                    set_config('statement_timeout', $1::text, true),
                    set_config('lock_timeout', $2::text, true),
                    set_config('app.tenant_id', $3::text, true)",
            &[
                &format!("{}ms", command.compiled().statement_timeout_ms),
                &format!("{}ms", command.compiled().lock_timeout_ms),
                &tenant,
            ],
        )
        .await
        .map_err(map_transaction_error)?;
    // Read the configuration commitment into the control flow so session
    // setup remains bound to the authorized action without logging it.
    if statement_timeout.len() != 64 {
        return Err(PortError::InvalidConfiguration);
    }
    Ok(())
}

async fn reserve_ledger(
    transaction: &Transaction<'_>,
    command: &VerifiedBoundedUpdateCommand,
    action_digest: &DigestHex,
    now: u64,
) -> Result<(), PortError> {
    let action = command.action();
    let relation_oid = i64::from(action.relation_oid);
    let started = i64::try_from(now).map_err(|_| PortError::InvalidConfiguration)?;
    transaction
        .execute(
            "INSERT INTO auths_internal.auths_execution_ledger
             (action_digest, claim_id, profile, relation_oid, tenant_commitment,
              row_set_digest, before_state_digest, after_state_digest,
              transaction_started_at)
             VALUES ($1, $2, $3, $4::bigint::oid, $5, $6, $7, $8, to_timestamp($9::bigint))",
            &[
                &action_digest.as_str(),
                &command.claim_id(),
                &action.intent.profile,
                &relation_oid,
                &action.tenant_commitment.as_str(),
                &action.row_set_digest.as_str(),
                &action.before_state_digest.as_str(),
                &action.after_state_digest.as_str(),
                &started,
            ],
        )
        .await
        .map_err(map_transaction_error)?;
    Ok(())
}

async fn finalize_ledger(
    transaction: &Transaction<'_>,
    action_digest: &DigestHex,
    affected_rows: u32,
    commitment: &DigestHex,
    committed_at: u64,
) -> Result<(), PortError> {
    let affected = i32::try_from(affected_rows).map_err(|_| PortError::CardinalityMismatch)?;
    let committed = i64::try_from(committed_at).map_err(|_| PortError::InvalidConfiguration)?;
    let count = transaction
        .execute(
            "UPDATE auths_internal.auths_execution_ledger
             SET affected_rows = $2, result_commitment = $3,
                 committed_at = to_timestamp($4::bigint), receipt_digest = $3
             WHERE action_digest = $1 AND committed_at IS NULL",
            &[
                &action_digest.as_str(),
                &affected,
                &commitment.as_str(),
                &committed,
            ],
        )
        .await
        .map_err(map_transaction_error)?;
    if count == 1 {
        Ok(())
    } else {
        Err(PortError::DatabaseExecution)
    }
}

async fn recheck_catalog(
    transaction: &Transaction<'_>,
    command: &VerifiedBoundedUpdateCommand,
) -> Result<(), PortError> {
    let action = command.action();
    let relation_oid = i64::from(action.relation_oid);
    let row = transaction
        .query_one(
            "SELECT current_database(), current_user,
                    c.relrowsecurity, c.relforcerowsecurity,
                    pg_get_userbyid(c.relowner) = current_user,
                    COALESCE(r.rolbypassrls, false),
                    COALESCE(r.rolsuper, false),
                    COALESCE(r.rolcreaterole, false),
                    COALESCE(r.rolcreatedb, false),
                    COALESCE(r.rolreplication, false),
                    has_database_privilege(current_user, current_database(), 'CREATE'),
                    has_schema_privilege(current_user, 'app', 'CREATE'),
                    has_table_privilege(current_user, 'app.demo_accounts', 'TRUNCATE'),
                    EXISTS (
                        SELECT 1
                        FROM pg_catalog.pg_rewrite rewrite
                        WHERE rewrite.ev_class = c.oid AND rewrite.rulename <> '_RETURN'
                    ),
                    c.relkind::text
             FROM pg_catalog.pg_class c
             JOIN pg_catalog.pg_roles r ON r.rolname = current_user
             WHERE c.oid = $1::bigint::oid",
            &[&relation_oid],
        )
        .await
        .map_err(map_transaction_error)?;
    let database: String = row.get(0);
    let role: String = row.get(1);
    let row_security: bool = row.get(2);
    let force_row_security: bool = row.get(3);
    let owns: bool = row.get(4);
    let bypass: bool = row.get(5);
    let superuser: bool = row.get(6);
    let create_role: bool = row.get(7);
    let create_database: bool = row.get(8);
    let replication: bool = row.get(9);
    let database_create: bool = row.get(10);
    let schema_create: bool = row.get(11);
    let table_truncate: bool = row.get(12);
    let has_rewrite_rules: bool = row.get(13);
    let relkind: String = row.get(14);
    if database != action.intent.database_name.as_str()
        || role != action.executor_role.as_str()
        || !row_security
        || !force_row_security
        || owns
        || bypass
        || superuser
        || create_role
        || create_database
        || replication
        || database_create
        || schema_create
        || table_truncate
        || has_rewrite_rules
        || relkind != "r"
    {
        return Err(PortError::BeforeStateMismatch);
    }
    let catalog = catalog_material(transaction, action.relation_oid).await?;
    if catalog.schema_fingerprint != action.intent.schema_fingerprint
        || catalog.policy_fingerprint != action.intent.policy_fingerprint
        || catalog.trigger_fingerprint != action.intent.trigger_fingerprint
    {
        return Err(PortError::BeforeStateMismatch);
    }
    Ok(())
}

fn validate_locked_rows(
    command: &VerifiedBoundedUpdateCommand,
    rows: &[Row],
) -> Result<(), PortError> {
    if rows.len()
        != usize::try_from(command.action().intent.expected_row_count)
            .map_err(|_| PortError::CardinalityMismatch)?
    {
        return Err(PortError::CardinalityMismatch);
    }
    for expected in &command.evidence().rows {
        let row = find_row(rows, &expected.primary_key)?;
        for value in &expected.primary_key {
            compare_row_value(row, value)?;
        }
        for value in &expected.before_values {
            compare_row_value(row, value)?;
        }
        let version: String = row
            .try_get(command.evidence().row_version_column.as_str())
            .map_err(|_| PortError::BeforeStateMismatch)?;
        if version != expected.row_version.to_string() {
            return Err(PortError::BeforeStateMismatch);
        }
    }
    Ok(())
}

fn validate_updated_rows(
    command: &VerifiedBoundedUpdateCommand,
    rows: &[Row],
) -> Result<(), PortError> {
    if rows.len()
        != usize::try_from(command.action().intent.expected_row_count)
            .map_err(|_| PortError::CardinalityMismatch)?
    {
        return Err(PortError::CardinalityMismatch);
    }
    for expected in &command.evidence().rows {
        let row = find_row(rows, &expected.primary_key)?;
        for value in &expected.primary_key {
            compare_row_value(row, value)?;
        }
        for assignment in &command.action().intent.assignments {
            let actual: Option<String> = row
                .try_get(assignment.column.as_str())
                .map_err(|_| PortError::AfterStateMismatch)?;
            if actual != assignment.value.protocol_text() {
                return Err(PortError::AfterStateMismatch);
            }
        }
        let version: String = row
            .try_get(command.evidence().row_version_column.as_str())
            .map_err(|_| PortError::AfterStateMismatch)?;
        if version != expected.row_version.saturating_add(1).to_string() {
            return Err(PortError::AfterStateMismatch);
        }
    }
    Ok(())
}

fn find_row<'a>(rows: &'a [Row], keys: &[NamedValueV1]) -> Result<&'a Row, PortError> {
    rows.iter()
        .find(|row| {
            keys.iter().all(|key| {
                row.try_get::<_, Option<String>>(key.column.as_str()).ok()
                    == Some(key.value.protocol_text())
            })
        })
        .ok_or(PortError::BeforeStateMismatch)
}

fn compare_row_value(row: &Row, expected: &NamedValueV1) -> Result<(), PortError> {
    let actual: Option<String> = row
        .try_get(expected.column.as_str())
        .map_err(|_| PortError::BeforeStateMismatch)?;
    if actual == expected.value.protocol_text() {
        Ok(())
    } else {
        Err(PortError::BeforeStateMismatch)
    }
}

async fn reconcile_live(
    command: &VerifiedBoundedUpdateCommand,
    credential: &PostgresCredential,
) -> Result<Reconciliation, PortError> {
    let Ok(client) = connect(credential).await else {
        return Ok(Reconciliation::Unavailable);
    };
    let action_digest = command
        .action()
        .digest()
        .map_err(|_| PortError::DatabaseExecution)?;
    let row = client
        .query_opt(
            "SELECT affected_rows, after_state_digest, result_commitment,
                    EXTRACT(EPOCH FROM transaction_started_at)::bigint,
                    EXTRACT(EPOCH FROM committed_at)::bigint,
                    current_setting('server_version')
             FROM auths_internal.auths_execution_ledger
             WHERE action_digest = $1 AND committed_at IS NOT NULL",
            &[&action_digest.as_str()],
        )
        .await
        .map_err(|_| PortError::DatabaseExecution)?;
    let Some(row) = row else {
        return Ok(Reconciliation::NotCommitted);
    };
    let affected: i32 = row.get(0);
    let after: String = row.get(1);
    let commitment: String = row.get(2);
    let started: i64 = row.get(3);
    let committed: i64 = row.get(4);
    let Ok(readback_commitment) = readback_with_client(&client, command).await else {
        return Ok(Reconciliation::Unavailable);
    };
    Ok(Reconciliation::Committed(TransactionResult {
        affected_rows: u32::try_from(affected).map_err(|_| PortError::DatabaseExecution)?,
        after_state_digest: DigestHex::parse(after).map_err(|_| PortError::DatabaseExecution)?,
        ledger_commitment: DigestHex::parse(commitment)
            .map_err(|_| PortError::DatabaseExecution)?,
        readback_commitment,
        server_version: row.get(5),
        transaction_started_at: u64::try_from(started).map_err(|_| PortError::DatabaseExecution)?,
        committed_at: u64::try_from(committed).map_err(|_| PortError::DatabaseExecution)?,
        reconciled: true,
    }))
}

async fn readback_live(
    command: &VerifiedBoundedUpdateCommand,
    credential: &PostgresCredential,
) -> Result<DigestHex, PortError> {
    let client = connect(credential).await?;
    readback_with_client(&client, command).await
}

async fn readback_with_client(
    client: &Client,
    command: &VerifiedBoundedUpdateCommand,
) -> Result<DigestHex, PortError> {
    let tenant = command
        .action()
        .intent
        .tenant_value
        .protocol_text()
        .ok_or(PortError::InvalidConfiguration)?;
    client
        .query_one(
            "SELECT set_config('app.tenant_id', $1::text, false)",
            &[&tenant],
        )
        .await
        .map_err(|_| PortError::DatabaseExecution)?;
    let values = command
        .compiled()
        .readback_parameters
        .iter()
        .map(|binding| binding.value.protocol_text())
        .collect::<Vec<_>>();
    let refs = parameter_refs(&values);
    let rows = client
        .query(&command.compiled().readback_sql, &refs)
        .await
        .map_err(|_| PortError::DatabaseExecution)?;
    validate_updated_rows(command, &rows)?;
    Ok(command.action().after_state_digest.clone())
}

#[derive(Serialize)]
struct CatalogMaterial {
    schema_fingerprint: DigestHex,
    policy_fingerprint: DigestHex,
    trigger_fingerprint: DigestHex,
}

async fn catalog_material(
    client: &impl tokio_postgres::GenericClient,
    relation_oid: u32,
) -> Result<CatalogMaterial, PortError> {
    let oid = i64::from(relation_oid);
    let columns = client
        .query(
            "SELECT attnum::int, attname, format_type(atttypid, atttypmod),
                    attnotnull, attgenerated::text, atthasdef
             FROM pg_catalog.pg_attribute
             WHERE attrelid = $1::bigint::oid AND attnum > 0 AND NOT attisdropped
             ORDER BY attnum",
            &[&oid],
        )
        .await
        .map_err(|_| PortError::DatabaseExecution)?
        .into_iter()
        .map(|row| {
            (
                row.get::<_, i32>(0),
                row.get::<_, String>(1),
                row.get::<_, String>(2),
                row.get::<_, bool>(3),
                row.get::<_, String>(4),
                row.get::<_, bool>(5),
            )
        })
        .collect::<Vec<_>>();
    let policies = client
        .query(
            "SELECT polname, polcmd::text, polpermissive,
                    COALESCE(pg_get_expr(polqual, polrelid), ''),
                    COALESCE(pg_get_expr(polwithcheck, polrelid), ''),
                    polroles::text
             FROM pg_catalog.pg_policy
             WHERE polrelid = $1::bigint::oid
             ORDER BY polname",
            &[&oid],
        )
        .await
        .map_err(|_| PortError::DatabaseExecution)?
        .into_iter()
        .map(|row| {
            (
                row.get::<_, String>(0),
                row.get::<_, String>(1),
                row.get::<_, bool>(2),
                row.get::<_, String>(3),
                row.get::<_, String>(4),
                row.get::<_, String>(5),
            )
        })
        .collect::<Vec<_>>();
    let triggers = client
        .query(
            "SELECT tgname, tgenabled::text, pg_get_triggerdef(oid, true)
             FROM pg_catalog.pg_trigger
             WHERE tgrelid = $1::bigint::oid AND NOT tgisinternal
             ORDER BY tgname",
            &[&oid],
        )
        .await
        .map_err(|_| PortError::DatabaseExecution)?
        .into_iter()
        .map(|row| {
            (
                row.get::<_, String>(0),
                row.get::<_, String>(1),
                row.get::<_, String>(2),
            )
        })
        .collect::<Vec<_>>();
    Ok(CatalogMaterial {
        schema_fingerprint: canonical_digest(&columns).map_err(|_| PortError::DatabaseExecution)?,
        policy_fingerprint: canonical_digest(&policies)
            .map_err(|_| PortError::DatabaseExecution)?,
        trigger_fingerprint: canonical_digest(&triggers)
            .map_err(|_| PortError::DatabaseExecution)?,
    })
}

async fn discover_live(
    client: &Client,
    server_identity: &str,
    audience: &str,
    tenant: &str,
    now: u64,
) -> Result<PostgresEvidenceV1, PortError> {
    let relation = client
        .query_one(
            "SELECT c.oid::int8, n.nspname, c.relname, c.relrowsecurity,
                    c.relforcerowsecurity, pg_get_userbyid(c.relowner) = current_user,
                    r.rolbypassrls, r.rolsuper, r.rolcreaterole, r.rolcreatedb,
                    r.rolreplication,
                    has_database_privilege(current_user, current_database(), 'CREATE'),
                    has_schema_privilege(current_user, 'app', 'CREATE'),
                    has_table_privilege(current_user, 'app.demo_accounts', 'TRUNCATE'),
                    EXISTS (
                        SELECT 1
                        FROM pg_catalog.pg_rewrite rewrite
                        WHERE rewrite.ev_class = c.oid AND rewrite.rulename <> '_RETURN'
                    ),
                    c.relkind::text, current_database(), current_user,
                    current_setting('server_version')
             FROM pg_catalog.pg_class c
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             JOIN pg_catalog.pg_roles r ON r.rolname = current_user
             WHERE n.nspname = 'app' AND c.relname = 'demo_accounts'",
            &[],
        )
        .await
        .map_err(|_| PortError::DatabaseExecution)?;
    let relation_oid_i64: i64 = relation.get(0);
    let relation_oid = u32::try_from(relation_oid_i64).map_err(|_| PortError::DatabaseExecution)?;
    let catalog = catalog_material(client, relation_oid).await?;
    let columns = client
        .query(
            "SELECT attname, format_type(atttypid, atttypmod), NOT attnotnull,
                    attgenerated <> '', atthasdef
             FROM pg_catalog.pg_attribute
             WHERE attrelid = $1::bigint::oid AND attnum > 0 AND NOT attisdropped
             ORDER BY attname",
            &[&relation_oid_i64],
        )
        .await
        .map_err(|_| PortError::DatabaseExecution)?
        .into_iter()
        .map(|row| {
            Ok(auths_postgresql::ColumnEvidenceV1 {
                name: auths_postgresql::PgIdentifier::parse(row.get::<_, String>(0))
                    .map_err(|_| PortError::DatabaseExecution)?,
                database_type: row.get(1),
                nullable: row.get(2),
                generated: row.get(3),
                has_default: row.get(4),
            })
        })
        .collect::<Result<Vec<_>, PortError>>()?;
    let rows = read_demo_rows(client, tenant, true).await?;
    let tenant_value = TypedValueV1::text(tenant).map_err(|_| PortError::InvalidConfiguration)?;
    let role = relation.get::<_, String>(17);
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
    .map_err(|_| PortError::DatabaseExecution)?;
    let evidence = PostgresEvidenceV1 {
        database_server_identity: server_identity.into(),
        database_audience: audience.into(),
        database_name: auths_postgresql::PgIdentifier::parse(relation.get::<_, String>(16))
            .map_err(|_| PortError::DatabaseExecution)?,
        schema_name: auths_postgresql::PgIdentifier::parse(relation.get::<_, String>(1))
            .map_err(|_| PortError::DatabaseExecution)?,
        table_name: auths_postgresql::PgIdentifier::parse(relation.get::<_, String>(2))
            .map_err(|_| PortError::DatabaseExecution)?,
        relation_oid,
        schema_fingerprint: catalog.schema_fingerprint,
        policy_fingerprint: catalog.policy_fingerprint,
        trigger_fingerprint: catalog.trigger_fingerprint,
        privilege_fingerprint,
        row_security_enabled: relation.get(3),
        row_security_forced: relation.get(4),
        executor_role: auths_postgresql::PgIdentifier::parse(role)
            .map_err(|_| PortError::DatabaseExecution)?,
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
        tenant_column: auths_postgresql::PgIdentifier::parse("tenant_id").unwrap(),
        tenant_value_commitment: canonical_digest(&tenant_value)
            .map_err(|_| PortError::DatabaseExecution)?,
        primary_key_columns: vec![auths_postgresql::PgIdentifier::parse("account_id").unwrap()],
        row_version_column: auths_postgresql::PgIdentifier::parse("row_version").unwrap(),
        rows,
        server_version: relation.get(18),
        evidence_source: "tls-protected-catalog-discovery-v1".into(),
        observed_at: now,
    };
    evidence
        .validate()
        .map_err(|_| PortError::DatabaseExecution)?;
    Ok(evidence)
}

async fn read_demo_rows(
    client: &Client,
    tenant: &str,
    pending_only: bool,
) -> Result<Vec<ObservedRowV1>, PortError> {
    client
        .query_one(
            "SELECT set_config('app.tenant_id', $1::text, false)",
            &[&tenant],
        )
        .await
        .map_err(|_| PortError::DatabaseExecution)?;
    let statement = if pending_only {
        "SELECT account_id::text, review_status::text, row_version
         FROM app.demo_accounts
         WHERE tenant_id = $1 AND review_status = 'pending'
         ORDER BY account_id
         LIMIT 4"
    } else {
        "SELECT account_id::text, review_status::text, row_version
         FROM app.demo_accounts
         WHERE tenant_id = $1
         ORDER BY account_id
         LIMIT 3"
    };
    client
        .query(statement, &[&tenant])
        .await
        .map_err(|_| PortError::DatabaseExecution)?
        .into_iter()
        .map(|row| {
            Ok(ObservedRowV1 {
                primary_key: vec![NamedValueV1 {
                    column: auths_postgresql::PgIdentifier::parse("account_id").unwrap(),
                    value: TypedValueV1::uuid(&row.get::<_, String>(0))
                        .map_err(|_| PortError::DatabaseExecution)?,
                }],
                before_values: vec![NamedValueV1 {
                    column: auths_postgresql::PgIdentifier::parse("review_status").unwrap(),
                    value: TypedValueV1::enum_text(
                        auths_postgresql::PgIdentifier::parse("review_status").unwrap(),
                        row.get::<_, String>(1),
                    )
                    .map_err(|_| PortError::DatabaseExecution)?,
                }],
                row_version: row.get(2),
            })
        })
        .collect()
}

fn is_serialization(error: &tokio_postgres::Error) -> bool {
    error
        .as_db_error()
        .is_some_and(|database| database.code() == &SqlState::T_R_SERIALIZATION_FAILURE)
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "map_err adapters receive PostgreSQL errors by value"
)]
fn map_transaction_error(error: tokio_postgres::Error) -> PortError {
    if is_serialization(&error) {
        PortError::TransactionConflict
    } else {
        PortError::DatabaseExecution
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use auths_postgresql::{
        BoundedUpdateService, ClaimStore as _, ExecuteBoundedUpdateRequest, FixedClock,
        MemoryClaimStore, MemoryReceiptSink, SdkProofVerifier, ServiceDependencies,
        WorkflowOutcome,
    };

    use super::*;
    use crate::fixture::demo_fixture;

    #[tokio::test]
    async fn exact_transition_commits_once_and_replay_never_reissues() {
        let now = auths_postgresql::test_support::NOW;
        let demo = demo_fixture(now, [9; 32]);
        let backend = Arc::new(PostgresBackend::fixture(demo.product.evidence.clone()));
        let claims = Arc::new(MemoryClaimStore::default());
        let service = BoundedUpdateService::new(ServiceDependencies {
            proof_verifier: SdkProofVerifier::new(demo.auths.verifier),
            credential_provider: Arc::clone(&backend),
            transaction_gateway: Arc::clone(&backend),
            claim_store: Arc::clone(&claims),
            receipt_sink: MemoryReceiptSink::default(),
            clock: FixedClock(now),
            executed_configuration: demo.product.configuration.clone(),
        });
        let request = || ExecuteBoundedUpdateRequest {
            action: demo.product.action.clone(),
            evidence: demo.product.evidence.clone(),
            required_configuration: demo.product.configuration.clone(),
            proof: demo.auths.proof.clone(),
            auths_request: demo.auths.request.clone(),
        };
        assert!(matches!(
            service.execute(request()).await.unwrap(),
            WorkflowOutcome::Executed { .. }
        ));
        assert_eq!(backend.credential_calls(), 1);
        assert_eq!(backend.transaction_calls(), 1);
        assert!(matches!(
            service.execute(request()).await.unwrap(),
            WorkflowOutcome::Replay { .. }
        ));
        assert_eq!(backend.credential_calls(), 1);
        assert_eq!(backend.transaction_calls(), 1);
        let digest = demo.product.action.digest().unwrap();
        assert!(claims.get(&digest).unwrap().is_some());
    }

    #[tokio::test]
    async fn configuration_mismatch_precedes_claim_credential_and_transaction() {
        let now = auths_postgresql::test_support::NOW;
        let demo = demo_fixture(now, [10; 32]);
        let variant = demo
            .variants
            .iter()
            .find(|variant| variant.id == "configuration-changed")
            .unwrap()
            .clone();
        let backend = Arc::new(PostgresBackend::fixture(variant.evidence.clone()));
        let claims = Arc::new(MemoryClaimStore::default());
        let service = BoundedUpdateService::new(ServiceDependencies {
            proof_verifier: SdkProofVerifier::new(demo.auths.verifier),
            credential_provider: Arc::clone(&backend),
            transaction_gateway: Arc::clone(&backend),
            claim_store: Arc::clone(&claims),
            receipt_sink: MemoryReceiptSink::default(),
            clock: FixedClock(now),
            executed_configuration: variant.executed_configuration.clone(),
        });
        let outcome = service
            .execute(ExecuteBoundedUpdateRequest {
                action: variant.action.clone(),
                evidence: variant.evidence,
                required_configuration: variant.required_configuration,
                proof: demo.auths.proof,
                auths_request: demo.auths.request,
            })
            .await
            .unwrap();
        let WorkflowOutcome::Rejected { receipt } = outcome else {
            panic!("configuration mismatch must reject")
        };
        assert_eq!(receipt.decision.code, "verifier-configuration-mismatch");
        assert_eq!(backend.credential_calls(), 0);
        assert_eq!(backend.transaction_calls(), 0);
        assert!(
            claims
                .get(&variant.action.digest().unwrap())
                .unwrap()
                .is_none()
        );
    }
}
