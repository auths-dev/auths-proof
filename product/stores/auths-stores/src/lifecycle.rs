use auths_bounded_policy::{CommitmentDigest, ProfileId, UnitId, VerifierTime};
use auths_lifecycle::{
    CapacityEntryV1, CapacitySnapshotV1, LifecycleRecordV1, LifecycleState, LifecycleStore,
    RecoveryReferenceDigest, ReservationMode, StoreError, StoreTransactionV1, StoredTransitionV1,
    TransitionDisposition, WorkflowId, apply_transition, decode_record, encode_record,
};
use auths_runtime::production::{
    LifecycleReader, RecoverableWorkStore, RecoveryBatchSize, RecoveryConfigurationError,
    RecoveryCursor, RecoveryLease, RecoveryLeaseRequest, RecoveryPage, RecoveryReferenceStore,
    RecoveryTarget,
};
use postgres::{
    Client, Config, IsolationLevel, Transaction,
    config::{Host, SslMode},
};
use r2d2::{CustomizeConnection, Pool};
use r2d2_postgres::PostgresConnectionManager;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, ServerName, pem::PemObject as _};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::{self, File},
    io::Write as _,
    path::{Path, PathBuf},
    str::FromStr as _,
    sync::Mutex,
    time::Duration,
};
use tempfile::NamedTempFile;
use tokio_postgres_rustls::MakeRustlsConnect;

const DATABASE_MAGIC: &[u8; 8] = b"AUTHSLF1";
const MAX_DATABASE_BYTES: usize = 256 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = auths_lifecycle::MAX_LIFECYCLE_RECORD_BYTES;
const POSTGRES_SCHEMA: &str = include_str!("../migrations/postgres_lifecycle_v3.sql");

/// One closed capacity rule configured by a domain registration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleCapacityRuleV1 {
    /// Exact additive capacity.
    Additive {
        /// Domain scope commitment.
        scope_digest: CommitmentDigest,
        /// Optional fixed/rolling window commitment.
        window_digest: Option<CommitmentDigest>,
        /// Exact capacity unit.
        unit: UnitId,
        /// Positive capacity ceiling.
        ceiling: u64,
    },
    /// One live owner for an exact scope.
    Exclusive {
        /// Domain scope commitment.
        scope_digest: CommitmentDigest,
        /// Optional fixed/rolling window commitment.
        window_digest: Option<CommitmentDigest>,
        /// Whether committed claims continue excluding new work.
        retain_after_commit: bool,
    },
}

/// Invalid lifecycle-store configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleStoreConfigurationError {
    /// Maximum record count is zero or unreasonable.
    InvalidRecordLimit,
    /// Additive ceiling is zero.
    ZeroCeiling,
    /// Two capacity rules describe the same key.
    DuplicateRule,
    /// Persistent state could not be opened canonically.
    InvalidPersistentState,
    /// Filesystem operation failed.
    Io,
    /// Transactional database could not be opened or initialized.
    DatabaseUnavailable,
    /// Existing transactional schema does not implement the V1 contract.
    DatabaseSchemaMismatch,
    /// Connection material is missing or malformed.
    InvalidConnectionString,
    /// TLS roots, mode, or server identity are invalid.
    InvalidTlsConfiguration,
    /// Pool sizes or deadlines are invalid.
    InvalidPoolConfiguration,
    /// A required reference-deployment environment slot is absent.
    MissingEnvironment,
}

#[derive(Clone)]
struct LifecycleDatabase {
    records: BTreeMap<WorkflowId, LifecycleRecordV1>,
}

impl LifecycleDatabase {
    fn empty() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }
}

/// Linearizable in-memory reference lifecycle store.
pub struct InMemoryLifecycleStore {
    rules: Vec<LifecycleCapacityRuleV1>,
    maximum_records: usize,
    database: Mutex<LifecycleDatabase>,
}

impl InMemoryLifecycleStore {
    /// Constructs one bounded store with a closed capacity registry.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleStoreConfigurationError`] for invalid limits,
    /// zero ceilings, or duplicate capacity keys.
    pub fn new(
        rules: Vec<LifecycleCapacityRuleV1>,
        maximum_records: usize,
    ) -> Result<Self, LifecycleStoreConfigurationError> {
        validate_configuration(&rules, maximum_records)?;
        Ok(Self {
            rules,
            maximum_records,
            database: Mutex::new(LifecycleDatabase::empty()),
        })
    }

    /// Returns one immutable record snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Unavailable`] if the process lock is poisoned.
    pub fn load(&self, workflow: &WorkflowId) -> Result<Option<LifecycleRecordV1>, StoreError> {
        self.database
            .lock()
            .map(|database| database.records.get(workflow).cloned())
            .map_err(|_| StoreError::Unavailable)
    }
}

impl LifecycleStore for InMemoryLifecycleStore {
    fn transact(&self, transaction: &StoreTransactionV1) -> Result<StoredTransitionV1, StoreError> {
        let mut database = self.database.lock().map_err(|_| StoreError::Unavailable)?;
        transact_database(
            &mut database,
            &self.rules,
            self.maximum_records,
            transaction,
            |_| Ok(()),
        )
    }
}

impl LifecycleReader for InMemoryLifecycleStore {
    fn load_lifecycle(
        &self,
        workflow: &WorkflowId,
    ) -> Result<Option<LifecycleRecordV1>, StoreError> {
        self.load(workflow)
    }
}

/// Single-process crash-persistent lifecycle store.
///
/// Each mutation writes and syncs a complete canonical database to a temporary
/// file, atomically replaces the target, then syncs the parent directory
/// before acknowledging durability. This adapter deliberately does not claim
/// multi-process safety; the transactional adapter covers that boundary.
pub struct PersistentLifecycleStore {
    path: PathBuf,
    rules: Vec<LifecycleCapacityRuleV1>,
    maximum_records: usize,
    database: Mutex<LifecycleDatabase>,
    fault: Mutex<Option<PersistenceFaultPoint>>,
}

impl PersistentLifecycleStore {
    /// Opens or creates a bounded canonical lifecycle database.
    ///
    /// # Errors
    ///
    /// Returns a typed configuration, I/O, corruption, or non-canonical-state
    /// failure. Existing invalid bytes are never replaced automatically.
    pub fn open(
        path: impl Into<PathBuf>,
        rules: Vec<LifecycleCapacityRuleV1>,
        maximum_records: usize,
    ) -> Result<Self, LifecycleStoreConfigurationError> {
        validate_configuration(&rules, maximum_records)?;
        let path = path.into();
        let database = if path.exists() {
            let bytes = fs::read(&path).map_err(|_| LifecycleStoreConfigurationError::Io)?;
            decode_database(&bytes, maximum_records)
                .map_err(|_| LifecycleStoreConfigurationError::InvalidPersistentState)?
        } else {
            LifecycleDatabase::empty()
        };
        Ok(Self {
            path,
            rules,
            maximum_records,
            database: Mutex::new(database),
            fault: Mutex::new(None),
        })
    }

    /// Returns one immutable record snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Unavailable`] if the process lock is poisoned.
    pub fn load(&self, workflow: &WorkflowId) -> Result<Option<LifecycleRecordV1>, StoreError> {
        self.database
            .lock()
            .map(|database| database.records.get(workflow).cloned())
            .map_err(|_| StoreError::Unavailable)
    }

    #[cfg(test)]
    fn inject_once(&self, point: PersistenceFaultPoint) {
        *self.fault.lock().unwrap() = Some(point);
    }
}

impl LifecycleStore for PersistentLifecycleStore {
    fn transact(&self, transaction: &StoreTransactionV1) -> Result<StoredTransitionV1, StoreError> {
        let mut database = self.database.lock().map_err(|_| StoreError::Unavailable)?;
        let path = self.path.clone();
        let fault = self
            .fault
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .take();
        transact_database(
            &mut database,
            &self.rules,
            self.maximum_records,
            transaction,
            |next| persist_database(&path, next, fault),
        )
    }
}

impl LifecycleReader for PersistentLifecycleStore {
    fn load_lifecycle(
        &self,
        workflow: &WorkflowId,
    ) -> Result<Option<LifecycleRecordV1>, StoreError> {
        self.load(workflow)
    }
}

/// Transactional multi-process `PostgreSQL` lifecycle store.
///
/// The adapter serializes mutations through a singleton contract-row lock
/// inside a database transaction. With every writer taking that lock before
/// reading lifecycle state, `READ COMMITTED` supplies a fresh post-lock
/// snapshot and is equivalent to serial execution for this closed schema. It
/// reloads and validates every canonical lifecycle record under that lock
/// before deriving capacity. The deliberately simple implementation is a
/// correctness reference: database indexes and framing never participate in
/// semantic digests, and no acknowledgement is returned before commit.
pub struct PostgresLifecycleStore {
    rules: Vec<LifecycleCapacityRuleV1>,
    maximum_records: usize,
    pool: Pool<PostgresConnectionManager<MakeRustlsConnect>>,
}

/// Connection material that is erased when its owner is dropped.
pub struct SecretConnectionString(Box<[u8]>);

impl SecretConnectionString {
    /// Parses bounded UTF-8 connection material without making it printable.
    ///
    /// # Errors
    ///
    /// Returns an invalid-connection error for empty, oversized, or
    /// NUL-containing input.
    pub fn new(value: String) -> Result<Self, LifecycleStoreConfigurationError> {
        if value.is_empty() || value.len() > 64 * 1024 || value.as_bytes().contains(&0) {
            return Err(LifecycleStoreConfigurationError::InvalidConnectionString);
        }
        Ok(Self(value.into_bytes().into_boxed_slice()))
    }

    fn expose(&self) -> Result<&str, LifecycleStoreConfigurationError> {
        std::str::from_utf8(&self.0)
            .map_err(|_| LifecycleStoreConfigurationError::InvalidConnectionString)
    }
}

impl Drop for SecretConnectionString {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Validated TLS server identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresServerName(String);

impl PostgresServerName {
    /// Parses one DNS server identity.
    ///
    /// # Errors
    ///
    /// Returns an invalid TLS configuration error for non-DNS or oversized
    /// input.
    pub fn parse(value: String) -> Result<Self, LifecycleStoreConfigurationError> {
        if value.len() > 253 || ServerName::try_from(value.clone()).is_err() {
            return Err(LifecycleStoreConfigurationError::InvalidTlsConfiguration);
        }
        Ok(Self(value))
    }

    /// Returns the non-secret expected DNS identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// TLS roots and expected database server identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresTlsConfig {
    root_certificate: PathBuf,
    expected_server_name: PostgresServerName,
}

impl PostgresTlsConfig {
    /// Constructs a TLS-only server-verification policy.
    #[must_use]
    pub const fn new(root_certificate: PathBuf, expected_server_name: PostgresServerName) -> Self {
        Self {
            root_certificate,
            expected_server_name,
        }
    }

    /// Returns the configured certificate bundle path.
    #[must_use]
    pub fn root_certificate(&self) -> &Path {
        &self.root_certificate
    }

    /// Returns the exact expected TLS server identity.
    #[must_use]
    pub const fn expected_server_name(&self) -> &PostgresServerName {
        &self.expected_server_name
    }
}

/// Bounded `PostgreSQL` pool and session deadlines.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgresPoolConfig {
    minimum_connections: u16,
    maximum_connections: u16,
    checkout_timeout: Duration,
    statement_timeout: Duration,
    lock_timeout: Duration,
    idle_timeout: Duration,
}

impl PostgresPoolConfig {
    /// Constructs bounded pool settings.
    ///
    /// # Errors
    ///
    /// Returns an invalid-pool error for zero, inverted, or unreasonable
    /// limits.
    pub fn new(
        minimum_connections: u16,
        maximum_connections: u16,
        checkout_timeout: Duration,
        statement_timeout: Duration,
        lock_timeout: Duration,
        idle_timeout: Duration,
    ) -> Result<Self, LifecycleStoreConfigurationError> {
        let value = Self {
            minimum_connections,
            maximum_connections,
            checkout_timeout,
            statement_timeout,
            lock_timeout,
            idle_timeout,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), LifecycleStoreConfigurationError> {
        if self.minimum_connections == 0
            || self.maximum_connections == 0
            || self.minimum_connections > self.maximum_connections
            || self.maximum_connections > 256
            || [
                self.checkout_timeout,
                self.statement_timeout,
                self.lock_timeout,
                self.idle_timeout,
            ]
            .iter()
            .any(|duration| duration.is_zero() || *duration > Duration::from_hours(24))
        {
            return Err(LifecycleStoreConfigurationError::InvalidPoolConfiguration);
        }
        Ok(())
    }

    /// Returns the minimum maintained connection count.
    #[must_use]
    pub const fn minimum_connections(&self) -> u16 {
        self.minimum_connections
    }

    /// Returns the maximum connection count.
    #[must_use]
    pub const fn maximum_connections(&self) -> u16 {
        self.maximum_connections
    }
}

impl Default for PostgresPoolConfig {
    fn default() -> Self {
        Self {
            minimum_connections: 1,
            maximum_connections: 16,
            checkout_timeout: Duration::from_secs(2),
            statement_timeout: Duration::from_secs(10),
            lock_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_mins(5),
        }
    }
}

/// Complete TLS-only `PostgreSQL` lifecycle-store configuration.
pub struct PostgresStoreConfig {
    connection: SecretConnectionString,
    tls: PostgresTlsConfig,
    pool: PostgresPoolConfig,
    maximum_records: usize,
    rules: Vec<LifecycleCapacityRuleV1>,
}

impl PostgresStoreConfig {
    /// Constructs a validated store configuration.
    ///
    /// # Errors
    ///
    /// Returns a closed configuration failure for invalid capacity or pool
    /// limits.
    pub fn new(
        connection: SecretConnectionString,
        tls: PostgresTlsConfig,
        pool: PostgresPoolConfig,
        maximum_records: usize,
        rules: Vec<LifecycleCapacityRuleV1>,
    ) -> Result<Self, LifecycleStoreConfigurationError> {
        validate_configuration(&rules, maximum_records)?;
        pool.validate()?;
        Ok(Self {
            connection,
            tls,
            pool,
            maximum_records,
            rules,
        })
    }

    /// Reads the three secret-slot values used by the reference deployment.
    ///
    /// # Errors
    ///
    /// Returns a closed error when a required value is absent or invalid.
    pub fn from_env(
        rules: Vec<LifecycleCapacityRuleV1>,
        maximum_records: usize,
    ) -> Result<Self, LifecycleStoreConfigurationError> {
        let connection = env::var("AUTHS_POSTGRES_URL")
            .map_err(|_| LifecycleStoreConfigurationError::MissingEnvironment)?;
        let root_certificate = env::var("AUTHS_POSTGRES_CA_PEM")
            .map_err(|_| LifecycleStoreConfigurationError::MissingEnvironment)?;
        let server_name = env::var("AUTHS_POSTGRES_SERVER_NAME")
            .map_err(|_| LifecycleStoreConfigurationError::MissingEnvironment)?;
        Self::new(
            SecretConnectionString::new(connection)?,
            PostgresTlsConfig::new(
                PathBuf::from(root_certificate),
                PostgresServerName::parse(server_name)?,
            ),
            PostgresPoolConfig::default(),
            maximum_records,
            rules,
        )
    }

    /// Returns a safe non-secret configuration summary.
    #[must_use]
    pub fn summary(&self) -> PostgresStoreSummary {
        PostgresStoreSummary {
            minimum_connections: self.pool.minimum_connections,
            maximum_connections: self.pool.maximum_connections,
            maximum_records: self.maximum_records,
        }
    }
}

/// Safe `PostgreSQL` lifecycle-store configuration projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgresStoreSummary {
    minimum_connections: u16,
    maximum_connections: u16,
    maximum_records: usize,
}

impl PostgresStoreSummary {
    /// Returns the stable adapter family.
    #[must_use]
    pub const fn family(self) -> &'static str {
        "postgresql-v1"
    }

    /// Returns whether transport security is mandatory.
    #[must_use]
    pub const fn tls_required(self) -> bool {
        true
    }

    /// Returns the physical schema identity.
    #[must_use]
    pub const fn schema_id(self) -> &'static str {
        "auths.lifecycle.postgresql/3"
    }

    /// Returns the transactional store contract identity.
    #[must_use]
    pub const fn contract_id(self) -> &'static str {
        "auths.lifecycle.transactional-store/3"
    }

    /// Returns the minimum maintained connection count.
    #[must_use]
    pub const fn minimum_connections(self) -> u16 {
        self.minimum_connections
    }

    /// Returns the maximum connection count.
    #[must_use]
    pub const fn maximum_connections(self) -> u16 {
        self.maximum_connections
    }

    /// Returns the maximum canonical record count.
    #[must_use]
    pub const fn maximum_records(self) -> usize {
        self.maximum_records
    }
}

/// Privacy-safe readiness projection for the lifecycle store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgresStoreHealth {
    schema_version: u16,
    pool_connections: u32,
    pool_idle_connections: u32,
}

impl PostgresStoreHealth {
    /// Returns the verified schema version.
    #[must_use]
    pub const fn schema_version(self) -> u16 {
        self.schema_version
    }

    /// Returns total connections currently managed by the pool.
    #[must_use]
    pub const fn pool_connections(self) -> u32 {
        self.pool_connections
    }

    /// Returns currently idle pool connections.
    #[must_use]
    pub const fn pool_idle_connections(self) -> u32 {
        self.pool_idle_connections
    }
}

#[derive(Debug)]
struct SessionCustomizer {
    statement: u128,
    lock: u128,
    idle: u128,
}

impl CustomizeConnection<Client, postgres::Error> for SessionCustomizer {
    fn on_acquire(&self, client: &mut Client) -> Result<(), postgres::Error> {
        client.batch_execute(&format!(
            "SET statement_timeout = '{}ms';
             SET lock_timeout = '{}ms';
             SET idle_in_transaction_session_timeout = '{}ms';",
            self.statement, self.lock, self.idle
        ))
    }
}

impl PostgresLifecycleStore {
    /// Opens a pooled TLS-only store and installs the fixed V3 schema only in
    /// an otherwise empty database.
    ///
    /// # Errors
    ///
    /// Returns a typed configuration error when limits or rules are invalid,
    /// the database is unavailable, or an existing metadata row conflicts
    /// with the V3 store contract.
    pub fn connect(
        configuration: PostgresStoreConfig,
    ) -> Result<Self, LifecycleStoreConfigurationError> {
        let PostgresStoreConfig {
            connection,
            tls,
            pool,
            maximum_records,
            rules,
        } = configuration;
        let mut database = Config::from_str(connection.expose()?)
            .map_err(|_| LifecycleStoreConfigurationError::InvalidConnectionString)?;
        if database.get_ssl_mode() != SslMode::Require {
            return Err(LifecycleStoreConfigurationError::InvalidTlsConfiguration);
        }
        validate_server_identity(&database, &tls.expected_server_name)?;
        database.application_name("auths-lifecycle-v3");
        let tls_connector = make_tls_connector(&tls)?;
        let manager = PostgresConnectionManager::new(database, tls_connector);
        let connections = Pool::builder()
            .min_idle(Some(u32::from(pool.minimum_connections)))
            .max_size(u32::from(pool.maximum_connections))
            .connection_timeout(pool.checkout_timeout)
            .idle_timeout(Some(pool.idle_timeout))
            .test_on_check_out(true)
            .error_handler(Box::new(r2d2::NopErrorHandler))
            .connection_customizer(Box::new(SessionCustomizer {
                statement: pool.statement_timeout.as_millis(),
                lock: pool.lock_timeout.as_millis(),
                idle: pool.idle_timeout.as_millis(),
            }))
            .build(manager)
            .map_err(|_| LifecycleStoreConfigurationError::DatabaseUnavailable)?;
        {
            let mut client = connections
                .get_timeout(pool.checkout_timeout)
                .map_err(|_| LifecycleStoreConfigurationError::DatabaseUnavailable)?;
            initialize_or_verify_schema(&mut client, maximum_records)?;
        }
        Ok(Self {
            rules,
            maximum_records,
            pool: connections,
        })
    }

    /// Loads and validates one canonical record using the current connection.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the database is unavailable or the row,
    /// its indexes, or its digest are inconsistent.
    pub fn load(&self, workflow: &WorkflowId) -> Result<Option<LifecycleRecordV1>, StoreError> {
        let mut client = self.pool.get().map_err(|_| StoreError::PoolExhausted)?;
        let row = client
            .query_opt(
                "SELECT workflow_id, revision, lifecycle_state, record_bytes, record_sha256
                 FROM auths_lifecycle_records
                 WHERE workflow_id = $1",
                &[&workflow.as_str()],
            )
            .map_err(|error| map_postgres_error(&error))?;
        row.map(|row| decode_postgres_row(&row)).transpose()
    }

    /// Checks pool availability, immutable metadata, and a bounded integrity
    /// sample without claiming provider or authorization health.
    ///
    /// # Errors
    ///
    /// Returns a closed store error for pool, database, schema, or canonical
    /// integrity failure.
    pub fn probe(&self) -> Result<PostgresStoreHealth, StoreError> {
        let mut client = self.pool.get().map_err(|_| StoreError::PoolExhausted)?;
        verify_store_contract(&mut client).map_err(configuration_store_error)?;
        let rows = client
            .query(
                "SELECT workflow_id, revision, lifecycle_state, record_bytes, record_sha256
                 FROM auths_lifecycle_records
                 ORDER BY workflow_id
                 LIMIT 32",
                &[],
            )
            .map_err(|error| map_postgres_error(&error))?;
        for row in rows {
            decode_postgres_row(&row)?;
        }
        let state = self.pool.state();
        Ok(PostgresStoreHealth {
            schema_version: 3,
            pool_connections: state.connections,
            pool_idle_connections: state.idle_connections,
        })
    }
}

impl LifecycleStore for PostgresLifecycleStore {
    fn transact(&self, transaction: &StoreTransactionV1) -> Result<StoredTransitionV1, StoreError> {
        let mut client = self.pool.get().map_err(|_| StoreError::PoolExhausted)?;
        let mut sql = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .map_err(|error| map_postgres_error(&error))?;
        let metadata = sql
            .query_one(
                "SELECT schema_version, contract_id
             FROM auths_lifecycle_store_meta
             WHERE singleton = TRUE
             FOR UPDATE",
                &[],
            )
            .map_err(|error| map_postgres_error(&error))?;
        let schema_version: i32 = metadata
            .try_get(0)
            .map_err(|_| StoreError::SchemaMismatch)?;
        let contract_id: String = metadata
            .try_get(1)
            .map_err(|_| StoreError::SchemaMismatch)?;
        if schema_version != 3 || contract_id != "auths.lifecycle.transactional-store/3" {
            return Err(StoreError::SchemaMismatch);
        }
        let mut database = load_postgres_database(&mut sql, self.maximum_records)?;
        let stored = transact_database(
            &mut database,
            &self.rules,
            self.maximum_records,
            transaction,
            |next| persist_postgres_record(&mut sql, next, transaction),
        )?;
        sql.commit().map_err(|error| map_postgres_error(&error))?;
        Ok(stored)
    }
}

impl LifecycleReader for PostgresLifecycleStore {
    fn load_lifecycle(
        &self,
        workflow: &WorkflowId,
    ) -> Result<Option<LifecycleRecordV1>, StoreError> {
        self.load(workflow)
    }
}

impl RecoveryReferenceStore for PostgresLifecycleStore {
    fn bind_recovery_reference(
        &self,
        digest: RecoveryReferenceDigest,
        target: &RecoveryTarget,
    ) -> Result<(), StoreError> {
        let mut client = self.pool.get().map_err(|_| StoreError::PoolExhausted)?;
        client
            .execute(
                "INSERT INTO auths_recovery_references
                 (recovery_reference_digest, workflow_id, profile_id)
                 VALUES ($1, $2, $3)
                 ON CONFLICT DO NOTHING",
                &[
                    &&digest.bytes()[..],
                    &target.workflow().as_str(),
                    &target.profile().as_str(),
                ],
            )
            .map_err(|error| map_postgres_error(&error))?;
        let rows = client
            .query(
                "SELECT recovery_reference_digest, workflow_id, profile_id
                 FROM auths_recovery_references
                 WHERE recovery_reference_digest = $1 OR workflow_id = $2",
                &[&&digest.bytes()[..], &target.workflow().as_str()],
            )
            .map_err(|error| map_postgres_error(&error))?;
        if rows.len() != 1 {
            return Err(StoreError::Conflict);
        }
        let stored_digest: Vec<u8> = rows[0].try_get(0).map_err(|_| StoreError::Corrupt)?;
        let workflow: String = rows[0].try_get(1).map_err(|_| StoreError::Corrupt)?;
        let profile: String = rows[0].try_get(2).map_err(|_| StoreError::Corrupt)?;
        if stored_digest.as_slice() != digest.bytes()
            || workflow != target.workflow().as_str()
            || profile != target.profile().as_str()
        {
            return Err(StoreError::Conflict);
        }
        Ok(())
    }

    fn resolve_recovery_reference(
        &self,
        digest: RecoveryReferenceDigest,
    ) -> Result<Option<RecoveryTarget>, StoreError> {
        let mut client = self.pool.get().map_err(|_| StoreError::PoolExhausted)?;
        let row = client
            .query_opt(
                "SELECT workflow_id, profile_id
                 FROM auths_recovery_references
                 WHERE recovery_reference_digest = $1",
                &[&&digest.bytes()[..]],
            )
            .map_err(|error| map_postgres_error(&error))?;
        row.map(|row| {
            let workflow: String = row.try_get(0).map_err(|_| StoreError::Corrupt)?;
            let profile: String = row.try_get(1).map_err(|_| StoreError::Corrupt)?;
            Ok(RecoveryTarget::new(
                WorkflowId::parse(&workflow).map_err(|_| StoreError::Corrupt)?,
                ProfileId::parse(&profile).map_err(|_| StoreError::Corrupt)?,
            ))
        })
        .transpose()
    }
}

impl RecoverableWorkStore for PostgresLifecycleStore {
    fn list_recoverable(
        &self,
        profile: &ProfileId,
        cursor: &RecoveryCursor,
        limit: RecoveryBatchSize,
    ) -> Result<RecoveryPage, StoreError> {
        let mut client = self.pool.get().map_err(|_| StoreError::PoolExhausted)?;
        let after = cursor.workflow().map_or("", WorkflowId::as_str);
        let row_limit = i64::from(limit.get()) + 1;
        let rows = client
            .query(
                "SELECT r.workflow_id, r.profile_id,
                        l.revision, l.lifecycle_state, l.record_bytes, l.record_sha256
                 FROM auths_recovery_references r
                 JOIN auths_lifecycle_records l ON l.workflow_id = r.workflow_id
                 WHERE r.profile_id = $1
                   AND r.workflow_id > $2
                   AND l.lifecycle_state IN (1, 2, 3, 6)
                 ORDER BY r.workflow_id
                 LIMIT $3",
                &[&profile.as_str(), &after, &row_limit],
            )
            .map_err(|error| map_postgres_error(&error))?;
        let mut targets = Vec::with_capacity(rows.len());
        for row in rows {
            let workflow: String = row.try_get(0).map_err(|_| StoreError::Corrupt)?;
            let stored_profile: String = row.try_get(1).map_err(|_| StoreError::Corrupt)?;
            let record = decode_postgres_recovery_row(&row)?;
            if record.workflow_id().as_str() != workflow
                || record.decision_input().commitments.profile_id().as_str() != stored_profile
                || stored_profile != profile.as_str()
            {
                return Err(StoreError::Corrupt);
            }
            targets.push(RecoveryTarget::new(
                record.workflow_id().clone(),
                profile.clone(),
            ));
        }
        let has_more = targets.len() > usize::from(limit.get());
        targets.truncate(usize::from(limit.get()));
        let next = has_more
            .then(|| {
                targets
                    .last()
                    .map(|target| RecoveryCursor::after(target.workflow().clone()))
            })
            .flatten();
        RecoveryPage::new(targets, next).map_err(recovery_configuration_store_error)
    }

    fn claim_reconciliation(
        &self,
        request: RecoveryLeaseRequest,
    ) -> Result<RecoveryLease, StoreError> {
        let mut client = self.pool.get().map_err(|_| StoreError::PoolExhausted)?;
        let mut sql = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .map_err(|error| map_postgres_error(&error))?;
        let row = sql
            .query_opt(
                "SELECT l.workflow_id, l.revision, l.lifecycle_state,
                        l.record_bytes, l.record_sha256, r.profile_id
                 FROM auths_lifecycle_records l
                 JOIN auths_recovery_references r ON r.workflow_id = l.workflow_id
                 WHERE l.workflow_id = $1
                 FOR UPDATE OF l",
                &[&request.target().workflow().as_str()],
            )
            .map_err(|error| map_postgres_error(&error))?
            .ok_or(StoreError::Conflict)?;
        let record = decode_postgres_lease_row(&row)?;
        let stored_profile: String = row.try_get(5).map_err(|_| StoreError::Corrupt)?;
        if record.revision() != request.expected_revision()
            || !matches!(
                record.state(),
                LifecycleState::Reserved
                    | LifecycleState::ExecutionIntentRecorded
                    | LifecycleState::Executing
                    | LifecycleState::OutcomeUnknown
            )
            || stored_profile != request.target().profile().as_str()
            || record.decision_input().commitments.profile_id().as_str() != stored_profile
        {
            return Err(StoreError::Conflict);
        }
        let expires_at = request
            .now()
            .unix_seconds()
            .checked_add(request.lease_seconds())
            .ok_or(StoreError::LimitExceeded)?;
        let expires_at_sql = i64::try_from(expires_at).map_err(|_| StoreError::LimitExceeded)?;
        let now_sql =
            i64::try_from(request.now().unix_seconds()).map_err(|_| StoreError::LimitExceeded)?;
        let revision =
            i64::try_from(request.expected_revision()).map_err(|_| StoreError::LimitExceeded)?;
        let lease_digest = request.lease_digest();
        let affected = sql
            .execute(
                "INSERT INTO auths_recovery_leases
                 (workflow_id, profile_id, expected_revision, expires_at, lease_digest)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (workflow_id) DO UPDATE SET
                   profile_id = EXCLUDED.profile_id,
                   expected_revision = EXCLUDED.expected_revision,
                   expires_at = EXCLUDED.expires_at,
                   lease_digest = EXCLUDED.lease_digest
                 WHERE auths_recovery_leases.expires_at <= $6",
                &[
                    &request.target().workflow().as_str(),
                    &request.target().profile().as_str(),
                    &revision,
                    &expires_at_sql,
                    &&lease_digest.bytes()[..],
                    &now_sql,
                ],
            )
            .map_err(|error| map_postgres_error(&error))?;
        if affected != 1 {
            return Err(StoreError::Conflict);
        }
        sql.commit().map_err(|error| map_postgres_error(&error))?;
        Ok(RecoveryLease::acknowledged(
            request.target().clone(),
            request.expected_revision(),
            VerifierTime::from_unix_seconds(expires_at),
            lease_digest,
        ))
    }
}

fn make_tls_connector(
    configuration: &PostgresTlsConfig,
) -> Result<MakeRustlsConnect, LifecycleStoreConfigurationError> {
    let certificates = CertificateDer::pem_file_iter(&configuration.root_certificate)
        .map_err(|_| LifecycleStoreConfigurationError::InvalidTlsConfiguration)?;
    let mut roots = RootCertStore::empty();
    let mut count = 0_usize;
    for certificate in certificates {
        roots
            .add(
                certificate
                    .map_err(|_| LifecycleStoreConfigurationError::InvalidTlsConfiguration)?,
            )
            .map_err(|_| LifecycleStoreConfigurationError::InvalidTlsConfiguration)?;
        count = count.saturating_add(1);
    }
    if count == 0 {
        return Err(LifecycleStoreConfigurationError::InvalidTlsConfiguration);
    }
    Ok(MakeRustlsConnect::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

fn validate_server_identity(
    configuration: &Config,
    expected: &PostgresServerName,
) -> Result<(), LifecycleStoreConfigurationError> {
    if configuration.get_hosts().len() != 1
        || !matches!(
            &configuration.get_hosts()[0],
            Host::Tcp(host) if host == expected.as_str()
        )
    {
        return Err(LifecycleStoreConfigurationError::InvalidTlsConfiguration);
    }
    Ok(())
}

fn initialize_or_verify_schema(
    client: &mut Client,
    maximum_records: usize,
) -> Result<(), LifecycleStoreConfigurationError> {
    let version: String = client
        .query_one("SHOW server_version_num", &[])
        .and_then(|row| row.try_get(0))
        .map_err(|_| LifecycleStoreConfigurationError::DatabaseUnavailable)?;
    let version = version
        .parse::<u32>()
        .map_err(|_| LifecycleStoreConfigurationError::DatabaseUnavailable)?;
    let in_recovery: bool = client
        .query_one("SELECT pg_is_in_recovery()", &[])
        .and_then(|row| row.try_get(0))
        .map_err(|_| LifecycleStoreConfigurationError::DatabaseUnavailable)?;
    if version < 14_00_00 || in_recovery {
        return Err(LifecycleStoreConfigurationError::DatabaseUnavailable);
    }

    let tables = client
        .query_one(
            "SELECT to_regclass('auths_lifecycle_store_meta') IS NOT NULL,
                    to_regclass('auths_lifecycle_records') IS NOT NULL,
                    to_regclass('auths_recovery_references') IS NOT NULL,
                    to_regclass('auths_recovery_leases') IS NOT NULL",
            &[],
        )
        .map_err(|_| LifecycleStoreConfigurationError::DatabaseUnavailable)?;
    let metadata_exists: bool = tables
        .try_get(0)
        .map_err(|_| LifecycleStoreConfigurationError::DatabaseSchemaMismatch)?;
    let records_exist: bool = tables
        .try_get(1)
        .map_err(|_| LifecycleStoreConfigurationError::DatabaseSchemaMismatch)?;
    let references_exist: bool = tables
        .try_get(2)
        .map_err(|_| LifecycleStoreConfigurationError::DatabaseSchemaMismatch)?;
    let leases_exist: bool = tables
        .try_get(3)
        .map_err(|_| LifecycleStoreConfigurationError::DatabaseSchemaMismatch)?;
    match (
        metadata_exists,
        records_exist,
        references_exist,
        leases_exist,
    ) {
        (false, false, false, false) => {
            let existing: i64 = client
                .query_one(
                    "SELECT count(*)
                     FROM pg_catalog.pg_tables
                     WHERE schemaname = current_schema()",
                    &[],
                )
                .and_then(|row| row.try_get(0))
                .map_err(|_| LifecycleStoreConfigurationError::DatabaseUnavailable)?;
            if existing != 0 {
                return Err(LifecycleStoreConfigurationError::DatabaseSchemaMismatch);
            }
            client
                .batch_execute(POSTGRES_SCHEMA)
                .map_err(|_| LifecycleStoreConfigurationError::DatabaseUnavailable)?;
        }
        (true, true, true, true) => {}
        _ => return Err(LifecycleStoreConfigurationError::DatabaseSchemaMismatch),
    }
    verify_store_contract(client)?;
    let count: i64 = client
        .query_one("SELECT count(*) FROM auths_lifecycle_records", &[])
        .and_then(|row| row.try_get(0))
        .map_err(|_| LifecycleStoreConfigurationError::DatabaseUnavailable)?;
    if count < 0 || usize::try_from(count).map_or(true, |count| count > maximum_records) {
        return Err(LifecycleStoreConfigurationError::DatabaseSchemaMismatch);
    }
    let rows = client
        .query(
            "SELECT workflow_id, revision, lifecycle_state, record_bytes, record_sha256
             FROM auths_lifecycle_records
             ORDER BY workflow_id
             LIMIT 32",
            &[],
        )
        .map_err(|_| LifecycleStoreConfigurationError::DatabaseUnavailable)?;
    if rows.iter().any(|row| decode_postgres_row(row).is_err()) {
        return Err(LifecycleStoreConfigurationError::DatabaseSchemaMismatch);
    }
    Ok(())
}

fn verify_store_contract(client: &mut Client) -> Result<(), LifecycleStoreConfigurationError> {
    let rows = client
        .query(
            "SELECT schema_version, contract_id
             FROM auths_lifecycle_store_meta
             WHERE singleton = TRUE",
            &[],
        )
        .map_err(|_| LifecycleStoreConfigurationError::DatabaseUnavailable)?;
    if rows.len() != 1 {
        return Err(LifecycleStoreConfigurationError::DatabaseSchemaMismatch);
    }
    let schema_version: i32 = rows[0]
        .try_get(0)
        .map_err(|_| LifecycleStoreConfigurationError::DatabaseSchemaMismatch)?;
    let contract_id: String = rows[0]
        .try_get(1)
        .map_err(|_| LifecycleStoreConfigurationError::DatabaseSchemaMismatch)?;
    if schema_version != 3 || contract_id != "auths.lifecycle.transactional-store/3" {
        return Err(LifecycleStoreConfigurationError::DatabaseSchemaMismatch);
    }
    Ok(())
}

const fn configuration_store_error(error: LifecycleStoreConfigurationError) -> StoreError {
    match error {
        LifecycleStoreConfigurationError::DatabaseSchemaMismatch => StoreError::SchemaMismatch,
        LifecycleStoreConfigurationError::InvalidRecordLimit
        | LifecycleStoreConfigurationError::ZeroCeiling
        | LifecycleStoreConfigurationError::DuplicateRule
        | LifecycleStoreConfigurationError::InvalidPersistentState => StoreError::Corrupt,
        LifecycleStoreConfigurationError::Io
        | LifecycleStoreConfigurationError::DatabaseUnavailable
        | LifecycleStoreConfigurationError::InvalidConnectionString
        | LifecycleStoreConfigurationError::InvalidTlsConfiguration
        | LifecycleStoreConfigurationError::InvalidPoolConfiguration
        | LifecycleStoreConfigurationError::MissingEnvironment => StoreError::Unavailable,
    }
}

fn load_postgres_database(
    sql: &mut Transaction<'_>,
    maximum_records: usize,
) -> Result<LifecycleDatabase, StoreError> {
    let count: i64 = sql
        .query_one("SELECT count(*) FROM auths_lifecycle_records", &[])
        .and_then(|row| row.try_get(0))
        .map_err(|error| map_postgres_error(&error))?;
    if count < 0 || usize::try_from(count).map_or(true, |count| count > maximum_records) {
        return Err(StoreError::LimitExceeded);
    }
    let rows = sql
        .query(
            "SELECT workflow_id, revision, lifecycle_state, record_bytes, record_sha256
             FROM auths_lifecycle_records
             ORDER BY workflow_id",
            &[],
        )
        .map_err(|error| map_postgres_error(&error))?;
    if rows.len() > maximum_records {
        return Err(StoreError::LimitExceeded);
    }
    let mut records = BTreeMap::new();
    for row in rows {
        let record = decode_postgres_row(&row)?;
        if records
            .insert(record.workflow_id().clone(), record)
            .is_some()
        {
            return Err(StoreError::Corrupt);
        }
    }
    Ok(LifecycleDatabase { records })
}

fn decode_postgres_row(row: &postgres::Row) -> Result<LifecycleRecordV1, StoreError> {
    let workflow_text: String = row.try_get(0).map_err(|_| StoreError::Corrupt)?;
    let revision: i64 = row.try_get(1).map_err(|_| StoreError::Corrupt)?;
    let state: i16 = row.try_get(2).map_err(|_| StoreError::Corrupt)?;
    let record_bytes: Vec<u8> = row.try_get(3).map_err(|_| StoreError::Corrupt)?;
    let stored_digest: Vec<u8> = row.try_get(4).map_err(|_| StoreError::Corrupt)?;
    if record_bytes.is_empty()
        || record_bytes.len() > MAX_RECORD_BYTES
        || stored_digest.len() != 32
        || Sha256::digest(&record_bytes).as_slice() != stored_digest
    {
        return Err(StoreError::Corrupt);
    }
    let workflow = WorkflowId::parse(&workflow_text).map_err(|_| StoreError::Corrupt)?;
    let record = decode_record(&record_bytes).map_err(|_| StoreError::Corrupt)?;
    let indexed_revision = u64::try_from(revision).map_err(|_| StoreError::Corrupt)?;
    if record.workflow_id() != &workflow
        || record.revision() != indexed_revision
        || lifecycle_state_code(record.state()) != state
    {
        return Err(StoreError::Corrupt);
    }
    Ok(record)
}

fn decode_postgres_recovery_row(row: &postgres::Row) -> Result<LifecycleRecordV1, StoreError> {
    let workflow: String = row.try_get(0).map_err(|_| StoreError::Corrupt)?;
    let record: Vec<u8> = row.try_get(4).map_err(|_| StoreError::Corrupt)?;
    let digest: Vec<u8> = row.try_get(5).map_err(|_| StoreError::Corrupt)?;
    decode_postgres_values(
        &workflow,
        row.try_get(2).map_err(|_| StoreError::Corrupt)?,
        row.try_get(3).map_err(|_| StoreError::Corrupt)?,
        &record,
        &digest,
    )
}

fn decode_postgres_lease_row(row: &postgres::Row) -> Result<LifecycleRecordV1, StoreError> {
    let workflow: String = row.try_get(0).map_err(|_| StoreError::Corrupt)?;
    let record: Vec<u8> = row.try_get(3).map_err(|_| StoreError::Corrupt)?;
    let digest: Vec<u8> = row.try_get(4).map_err(|_| StoreError::Corrupt)?;
    decode_postgres_values(
        &workflow,
        row.try_get(1).map_err(|_| StoreError::Corrupt)?,
        row.try_get(2).map_err(|_| StoreError::Corrupt)?,
        &record,
        &digest,
    )
}

fn decode_postgres_values(
    workflow_text: &str,
    revision: i64,
    state: i16,
    record_bytes: &[u8],
    stored_digest: &[u8],
) -> Result<LifecycleRecordV1, StoreError> {
    if record_bytes.is_empty()
        || record_bytes.len() > MAX_RECORD_BYTES
        || stored_digest.len() != 32
        || Sha256::digest(record_bytes).as_slice() != stored_digest
    {
        return Err(StoreError::Corrupt);
    }
    let workflow = WorkflowId::parse(workflow_text).map_err(|_| StoreError::Corrupt)?;
    let record = decode_record(record_bytes).map_err(|_| StoreError::Corrupt)?;
    let indexed_revision = u64::try_from(revision).map_err(|_| StoreError::Corrupt)?;
    if record.workflow_id() != &workflow
        || record.revision() != indexed_revision
        || lifecycle_state_code(record.state()) != state
    {
        return Err(StoreError::Corrupt);
    }
    Ok(record)
}

const fn recovery_configuration_store_error(error: RecoveryConfigurationError) -> StoreError {
    match error {
        RecoveryConfigurationError::InvalidCapacity
        | RecoveryConfigurationError::InvalidBatchSize
        | RecoveryConfigurationError::InvalidLease => StoreError::LimitExceeded,
        RecoveryConfigurationError::RandomnessUnavailable => StoreError::Unavailable,
    }
}

fn persist_postgres_record(
    sql: &mut Transaction<'_>,
    database: &LifecycleDatabase,
    requested: &StoreTransactionV1,
) -> Result<(), StoreError> {
    let record = database
        .records
        .get(&requested.workflow_id)
        .ok_or(StoreError::Corrupt)?;
    let record_bytes = encode_record(record).map_err(|_| StoreError::Corrupt)?;
    if record_bytes.is_empty() || record_bytes.len() > MAX_RECORD_BYTES {
        return Err(StoreError::LimitExceeded);
    }
    let record_digest: [u8; 32] = Sha256::digest(&record_bytes).into();
    let revision = i64::try_from(record.revision()).map_err(|_| StoreError::LimitExceeded)?;
    let affected = match requested.expected_revision {
        None => sql.execute(
            "INSERT INTO auths_lifecycle_records
                 (workflow_id, revision, lifecycle_state, record_bytes, record_sha256)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (workflow_id) DO NOTHING",
            &[
                &record.workflow_id().as_str(),
                &revision,
                &lifecycle_state_code(record.state()),
                &record_bytes,
                &&record_digest[..],
            ],
        ),
        Some(expected) => {
            let expected = i64::try_from(expected).map_err(|_| StoreError::Conflict)?;
            sql.execute(
                "UPDATE auths_lifecycle_records
                 SET revision = $2,
                     lifecycle_state = $3,
                     record_bytes = $4,
                     record_sha256 = $5
                 WHERE workflow_id = $1 AND revision = $6",
                &[
                    &record.workflow_id().as_str(),
                    &revision,
                    &lifecycle_state_code(record.state()),
                    &record_bytes,
                    &&record_digest[..],
                    &expected,
                ],
            )
        }
    }
    .map_err(|error| map_postgres_error(&error))?;
    if affected != 1 {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

const fn lifecycle_state_code(state: LifecycleState) -> i16 {
    match state {
        LifecycleState::DecisionRecorded => 0,
        LifecycleState::Reserved => 1,
        LifecycleState::ExecutionIntentRecorded => 2,
        LifecycleState::Executing => 3,
        LifecycleState::Committed => 4,
        LifecycleState::Released => 5,
        LifecycleState::OutcomeUnknown => 6,
        LifecycleState::ReconciledCommitted => 7,
        LifecycleState::ReconciledReleased => 8,
    }
}

fn map_postgres_error(error: &postgres::Error) -> StoreError {
    let Some(database_error) = error.as_db_error() else {
        return StoreError::Unavailable;
    };
    match database_error.code().code() {
        "40001" | "40P01" | "23505" => StoreError::Conflict,
        "57014" | "55P03" => StoreError::Timeout,
        "23514" => StoreError::Corrupt,
        _ => StoreError::Unavailable,
    }
}

fn transact_database(
    database: &mut LifecycleDatabase,
    rules: &[LifecycleCapacityRuleV1],
    maximum_records: usize,
    transaction: &StoreTransactionV1,
    persist: impl FnOnce(&LifecycleDatabase) -> Result<(), StoreError>,
) -> Result<StoredTransitionV1, StoreError> {
    let current = database.records.get(&transaction.workflow_id);
    if current.map(LifecycleRecordV1::revision) != transaction.expected_revision {
        return Err(StoreError::Conflict);
    }
    if current.is_none() && database.records.len() >= maximum_records {
        return Err(StoreError::LimitExceeded);
    }
    let mut exact = transaction.clone();
    exact.context.capacity = capacity_snapshot(database, rules, &transaction.workflow_id)?;
    let result = apply_transition(current, &exact.command, &exact.context)
        .map_err(|error| StoreError::Rejected(error.failure))?;
    if result.disposition == TransitionDisposition::Applied {
        let mut next = database.clone();
        next.records
            .insert(transaction.workflow_id.clone(), result.record.clone());
        persist(&next)?;
        *database = next;
    }
    Ok(StoredTransitionV1::acknowledged(
        result.record,
        result.disposition,
    ))
}

fn capacity_snapshot(
    database: &LifecycleDatabase,
    rules: &[LifecycleCapacityRuleV1],
    current_workflow: &WorkflowId,
) -> Result<CapacitySnapshotV1, StoreError> {
    let mut entries = Vec::with_capacity(rules.len());
    for rule in rules {
        match rule {
            LifecycleCapacityRuleV1::Additive {
                scope_digest,
                window_digest,
                unit,
                ceiling,
            } => {
                let mut committed = 0_u64;
                let mut active = 0_u64;
                for (workflow, record) in &database.records {
                    if workflow == current_workflow {
                        continue;
                    }
                    for reservation in record.reservations() {
                        if reservation.request().scope_digest() == *scope_digest
                            && reservation.request().window_digest() == *window_digest
                            && let ReservationMode::Additive {
                                unit: request_unit,
                                amount,
                            } = reservation.request().mode()
                            && request_unit == unit
                        {
                            if reservation.is_committed() {
                                committed =
                                    committed.checked_add(*amount).ok_or(StoreError::Corrupt)?;
                            } else if !reservation.is_released()
                                && is_capacity_holding(record.state())
                            {
                                active = active.checked_add(*amount).ok_or(StoreError::Corrupt)?;
                            }
                        }
                    }
                }
                entries.push(CapacityEntryV1::Additive {
                    scope_digest: *scope_digest,
                    window_digest: *window_digest,
                    unit: unit.clone(),
                    ceiling: *ceiling,
                    committed,
                    active,
                });
            }
            LifecycleCapacityRuleV1::Exclusive {
                scope_digest,
                window_digest,
                retain_after_commit,
            } => {
                let mut owner = None;
                for (workflow, record) in &database.records {
                    if workflow == current_workflow {
                        continue;
                    }
                    for reservation in record.reservations() {
                        if reservation.request().scope_digest() == *scope_digest
                            && reservation.request().window_digest() == *window_digest
                            && matches!(reservation.request().mode(), ReservationMode::Exclusive)
                            && !reservation.is_released()
                            && (is_capacity_holding(record.state())
                                || (*retain_after_commit && reservation.is_committed()))
                        {
                            if owner.is_some() {
                                return Err(StoreError::Corrupt);
                            }
                            owner = Some(reservation.request().reservation_id().clone());
                        }
                    }
                }
                entries.push(CapacityEntryV1::Exclusive {
                    scope_digest: *scope_digest,
                    window_digest: *window_digest,
                    live_owner: owner,
                });
            }
        }
    }
    CapacitySnapshotV1::new(entries).map_err(|_| StoreError::Corrupt)
}

const fn is_capacity_holding(state: LifecycleState) -> bool {
    matches!(
        state,
        LifecycleState::Reserved
            | LifecycleState::ExecutionIntentRecorded
            | LifecycleState::Executing
            | LifecycleState::OutcomeUnknown
    )
}

fn validate_configuration(
    rules: &[LifecycleCapacityRuleV1],
    maximum_records: usize,
) -> Result<(), LifecycleStoreConfigurationError> {
    if maximum_records == 0 || maximum_records > 1_000_000 {
        return Err(LifecycleStoreConfigurationError::InvalidRecordLimit);
    }
    let mut keys = BTreeSet::new();
    for rule in rules {
        let key = match rule {
            LifecycleCapacityRuleV1::Additive {
                scope_digest,
                window_digest,
                unit,
                ceiling,
            } => {
                if *ceiling == 0 {
                    return Err(LifecycleStoreConfigurationError::ZeroCeiling);
                }
                (0, *scope_digest, *window_digest, Some(unit.as_str()))
            }
            LifecycleCapacityRuleV1::Exclusive {
                scope_digest,
                window_digest,
                ..
            } => (1, *scope_digest, *window_digest, None),
        };
        if !keys.insert(key) {
            return Err(LifecycleStoreConfigurationError::DuplicateRule);
        }
    }
    Ok(())
}

fn encode_database(database: &LifecycleDatabase) -> Result<Vec<u8>, StoreError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DATABASE_MAGIC);
    let count = u32::try_from(database.records.len()).map_err(|_| StoreError::LimitExceeded)?;
    bytes.extend_from_slice(&count.to_be_bytes());
    for (workflow, record) in &database.records {
        let workflow_bytes = workflow.as_str().as_bytes();
        let workflow_len = u16::try_from(workflow_bytes.len()).map_err(|_| StoreError::Corrupt)?;
        let record_bytes = encode_record(record).map_err(|_| StoreError::Corrupt)?;
        let record_len =
            u32::try_from(record_bytes.len()).map_err(|_| StoreError::LimitExceeded)?;
        bytes.extend_from_slice(&workflow_len.to_be_bytes());
        bytes.extend_from_slice(workflow_bytes);
        bytes.extend_from_slice(&record_len.to_be_bytes());
        bytes.extend_from_slice(&record_bytes);
    }
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    bytes.extend_from_slice(&digest);
    if bytes.len() > MAX_DATABASE_BYTES {
        return Err(StoreError::LimitExceeded);
    }
    Ok(bytes)
}

fn decode_database(bytes: &[u8], maximum_records: usize) -> Result<LifecycleDatabase, StoreError> {
    if bytes.len() < DATABASE_MAGIC.len() + 4 + 32 || bytes.len() > MAX_DATABASE_BYTES {
        return Err(StoreError::Corrupt);
    }
    let (payload, committed_digest) = bytes.split_at(bytes.len() - 32);
    if Sha256::digest(payload).as_slice() != committed_digest {
        return Err(StoreError::Corrupt);
    }
    let mut cursor = Cursor::new(payload);
    if cursor.take(8)? != DATABASE_MAGIC {
        return Err(StoreError::Corrupt);
    }
    let count = usize::try_from(cursor.u32()?).map_err(|_| StoreError::Corrupt)?;
    if count > maximum_records {
        return Err(StoreError::LimitExceeded);
    }
    let mut records = BTreeMap::new();
    for _ in 0..count {
        let workflow_len = usize::from(cursor.u16()?);
        let workflow_text =
            core::str::from_utf8(cursor.take(workflow_len)?).map_err(|_| StoreError::Corrupt)?;
        let workflow = WorkflowId::parse(workflow_text).map_err(|_| StoreError::Corrupt)?;
        let record_len = usize::try_from(cursor.u32()?).map_err(|_| StoreError::Corrupt)?;
        let record = decode_record(cursor.take(record_len)?).map_err(|_| StoreError::Corrupt)?;
        if record.workflow_id() != &workflow || records.insert(workflow, record).is_some() {
            return Err(StoreError::Corrupt);
        }
    }
    if !cursor.remaining().is_empty() {
        return Err(StoreError::Corrupt);
    }
    Ok(LifecycleDatabase { records })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistenceFaultPoint {
    BeforeTemporaryWrite,
    AfterTemporarySync,
    AfterAtomicReplace,
    AfterDirectorySync,
}

fn persist_database(
    path: &Path,
    database: &LifecycleDatabase,
    fault: Option<PersistenceFaultPoint>,
) -> Result<(), StoreError> {
    let bytes = encode_database(database)?;
    let parent = path.parent().ok_or(StoreError::Unavailable)?;
    fs::create_dir_all(parent).map_err(|_| StoreError::Unavailable)?;
    if fault == Some(PersistenceFaultPoint::BeforeTemporaryWrite) {
        return Err(StoreError::Unavailable);
    }
    let mut temporary = NamedTempFile::new_in(parent).map_err(|_| StoreError::Unavailable)?;
    temporary
        .write_all(&bytes)
        .and_then(|()| temporary.flush())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| StoreError::Unavailable)?;
    if fault == Some(PersistenceFaultPoint::AfterTemporarySync) {
        return Err(StoreError::Unavailable);
    }
    temporary
        .persist(path)
        .map_err(|_| StoreError::Unavailable)?;
    if fault == Some(PersistenceFaultPoint::AfterAtomicReplace) {
        return Err(StoreError::Unavailable);
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| StoreError::Unavailable)?;
    if fault == Some(PersistenceFaultPoint::AfterDirectorySync) {
        return Err(StoreError::Unavailable);
    }
    Ok(())
}

struct Cursor<'a> {
    remaining: &'a [u8],
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], StoreError> {
        if count > self.remaining.len() {
            return Err(StoreError::Corrupt);
        }
        let (head, tail) = self.remaining.split_at(count);
        self.remaining = tail;
        Ok(head)
    }

    fn u16(&mut self) -> Result<u16, StoreError> {
        let bytes: [u8; 2] = self.take(2)?.try_into().map_err(|_| StoreError::Corrupt)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, StoreError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| StoreError::Corrupt)?;
        Ok(u32::from_be_bytes(bytes))
    }

    const fn remaining(&self) -> &'a [u8] {
        self.remaining
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_lifecycle::{
        LifecycleFailure, TransitionCommandV1, execute_store_transaction,
        test_support::{CAPACITY_SCOPE, decision_transaction, transaction},
    };
    use std::sync::{Arc, Barrier};

    fn rules() -> Vec<LifecycleCapacityRuleV1> {
        vec![LifecycleCapacityRuleV1::Additive {
            scope_digest: CAPACITY_SCOPE,
            window_digest: None,
            unit: UnitId::parse("requests").unwrap(),
            ceiling: 10,
        }]
    }

    #[test]
    fn concurrent_final_capacity_has_one_winner() {
        let store = Arc::new(InMemoryLifecycleStore::new(rules(), 16).unwrap());
        for workflow in ["workflow-1", "workflow-2"] {
            execute_store_transaction(&*store, &decision_transaction(workflow, Some(6))).unwrap();
        }
        let barrier = Arc::new(Barrier::new(3));
        let handles = ["workflow-1", "workflow-2"].map(|workflow| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                execute_store_transaction(
                    &*store,
                    &transaction(workflow, Some(1), TransitionCommandV1::Reserve, 11),
                )
            })
        });
        barrier.wait();
        let results = handles.map(|handle| handle.join().unwrap());
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(
                    result,
                    Err(StoreError::Rejected(LifecycleFailure::CapacityExceeded))
                ))
                .count(),
            1
        );
    }

    #[test]
    fn persistent_capacity_and_replay_survive_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lifecycle.store");
        {
            let store = PersistentLifecycleStore::open(&path, rules(), 16).unwrap();
            execute_store_transaction(&store, &decision_transaction("workflow-1", Some(6)))
                .unwrap();
            execute_store_transaction(
                &store,
                &transaction("workflow-1", Some(1), TransitionCommandV1::Reserve, 11),
            )
            .unwrap();
        }
        let store = PersistentLifecycleStore::open(&path, rules(), 16).unwrap();
        let restored = store
            .load(&WorkflowId::parse("workflow-1").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(restored.state(), LifecycleState::Reserved);
        execute_store_transaction(&store, &decision_transaction("workflow-2", Some(5))).unwrap();
        assert!(matches!(
            execute_store_transaction(
                &store,
                &transaction("workflow-2", Some(1), TransitionCommandV1::Reserve, 11,),
            ),
            Err(StoreError::Rejected(LifecycleFailure::CapacityExceeded))
        ));
    }

    #[test]
    fn corruption_is_rejected_without_repairing_or_replacing_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lifecycle.store");
        let store = PersistentLifecycleStore::open(&path, rules(), 16).unwrap();
        execute_store_transaction(&store, &decision_transaction("workflow-1", Some(6))).unwrap();
        drop(store);
        let mut bytes = fs::read(&path).unwrap();
        bytes[16] ^= 1;
        fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            PersistentLifecycleStore::open(&path, rules(), 16),
            Err(LifecycleStoreConfigurationError::InvalidPersistentState)
        ));
        assert_eq!(fs::read(path).unwrap(), bytes);
    }

    #[test]
    fn crash_matrix_reopens_old_or_new_canonical_state_never_partial_state() {
        for (point, expected_state) in [
            (
                PersistenceFaultPoint::BeforeTemporaryWrite,
                LifecycleState::DecisionRecorded,
            ),
            (
                PersistenceFaultPoint::AfterTemporarySync,
                LifecycleState::DecisionRecorded,
            ),
            (
                PersistenceFaultPoint::AfterAtomicReplace,
                LifecycleState::Reserved,
            ),
            (
                PersistenceFaultPoint::AfterDirectorySync,
                LifecycleState::Reserved,
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("lifecycle.store");
            let store = PersistentLifecycleStore::open(&path, rules(), 16).unwrap();
            execute_store_transaction(&store, &decision_transaction("workflow-1", Some(6)))
                .unwrap();
            store.inject_once(point);
            assert!(matches!(
                execute_store_transaction(
                    &store,
                    &transaction("workflow-1", Some(1), TransitionCommandV1::Reserve, 11,),
                ),
                Err(StoreError::Unavailable)
            ));
            drop(store);
            let reopened = PersistentLifecycleStore::open(&path, rules(), 16).unwrap();
            assert_eq!(
                reopened
                    .load(&WorkflowId::parse("workflow-1").unwrap())
                    .unwrap()
                    .unwrap()
                    .state(),
                expected_state
            );
        }
    }

    #[test]
    fn production_pool_and_server_identity_are_bounded() {
        assert_eq!(
            PostgresPoolConfig::new(
                2,
                1,
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
            ),
            Err(LifecycleStoreConfigurationError::InvalidPoolConfiguration)
        );
        assert_eq!(
            PostgresServerName::parse("not a host name".to_owned()),
            Err(LifecycleStoreConfigurationError::InvalidTlsConfiguration)
        );
    }

    #[test]
    fn configuration_summary_contains_no_connection_material() {
        let connection = "host=database.example user=auths password=private sslmode=require";
        let configuration = PostgresStoreConfig::new(
            SecretConnectionString::new(connection.to_owned()).unwrap(),
            PostgresTlsConfig::new(
                PathBuf::from("/run/secrets/postgres-ca.pem"),
                PostgresServerName::parse("database.example".to_owned()).unwrap(),
            ),
            PostgresPoolConfig::default(),
            32,
            rules(),
        )
        .unwrap();
        let summary = format!("{:?}", configuration.summary());
        assert!(!summary.contains("database.example"));
        assert!(!summary.contains("private"));
        assert_eq!(configuration.summary().maximum_connections(), 16);
    }
}
