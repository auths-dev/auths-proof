use auths_bounded_policy::{CommitmentDigest, UnitId};
use auths_lifecycle::{
    CapacityEntryV1, CapacitySnapshotV1, LifecycleRecordV1, LifecycleState, LifecycleStore,
    ReservationMode, StoreError, StoreTransactionV1, StoredTransitionV1, TransitionDisposition,
    WorkflowId, apply_transition, decode_record, encode_record,
};
use postgres::{Client, IsolationLevel, NoTls, Transaction};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Write as _,
    path::{Path, PathBuf},
    sync::Mutex,
};
use tempfile::NamedTempFile;

const DATABASE_MAGIC: &[u8; 8] = b"AUTHSLF1";
const MAX_DATABASE_BYTES: usize = 256 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;
const POSTGRES_SCHEMA: &str = include_str!("../migrations/postgres_lifecycle_v1.sql");

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
    client: Mutex<Client>,
}

impl PostgresLifecycleStore {
    /// Opens a PostgreSQL-backed store and installs the fixed V1 schema.
    ///
    /// The connection string is deployment configuration and is not part of
    /// the canonical lifecycle contract. Callers should provision a dedicated
    /// database or schema whose privileges prevent unrelated writers.
    ///
    /// # Errors
    ///
    /// Returns a typed configuration error when limits or rules are invalid,
    /// the database is unavailable, or an existing metadata row conflicts
    /// with the V1 store contract.
    pub fn connect(
        connection_string: &str,
        rules: Vec<LifecycleCapacityRuleV1>,
        maximum_records: usize,
    ) -> Result<Self, LifecycleStoreConfigurationError> {
        validate_configuration(&rules, maximum_records)?;
        let mut client = Client::connect(connection_string, NoTls)
            .map_err(|_| LifecycleStoreConfigurationError::DatabaseUnavailable)?;
        client
            .batch_execute(POSTGRES_SCHEMA)
            .map_err(|_| LifecycleStoreConfigurationError::DatabaseUnavailable)?;
        let metadata = client
            .query_opt(
                "SELECT schema_version, contract_id
                 FROM auths_lifecycle_store_meta
                 WHERE singleton = TRUE",
                &[],
            )
            .map_err(|_| LifecycleStoreConfigurationError::DatabaseUnavailable)?
            .ok_or(LifecycleStoreConfigurationError::DatabaseSchemaMismatch)?;
        let schema_version: i32 = metadata
            .try_get(0)
            .map_err(|_| LifecycleStoreConfigurationError::DatabaseSchemaMismatch)?;
        let contract_id: String = metadata
            .try_get(1)
            .map_err(|_| LifecycleStoreConfigurationError::DatabaseSchemaMismatch)?;
        if schema_version != 1 || contract_id != "auths.lifecycle.transactional-store/1" {
            return Err(LifecycleStoreConfigurationError::DatabaseSchemaMismatch);
        }
        Ok(Self {
            rules,
            maximum_records,
            client: Mutex::new(client),
        })
    }

    /// Loads and validates one canonical record using the current connection.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the database is unavailable or the row,
    /// its indexes, or its digest are inconsistent.
    pub fn load(&self, workflow: &WorkflowId) -> Result<Option<LifecycleRecordV1>, StoreError> {
        let mut client = self.client.lock().map_err(|_| StoreError::Unavailable)?;
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
}

impl LifecycleStore for PostgresLifecycleStore {
    fn transact(&self, transaction: &StoreTransactionV1) -> Result<StoredTransitionV1, StoreError> {
        let mut client = self.client.lock().map_err(|_| StoreError::Unavailable)?;
        let mut sql = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .map_err(|error| map_postgres_error(&error))?;
        sql.query_one(
            "SELECT schema_version
             FROM auths_lifecycle_store_meta
             WHERE singleton = TRUE
             FOR UPDATE",
            &[],
        )
        .map_err(|error| map_postgres_error(&error))?;
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

fn load_postgres_database(
    sql: &mut Transaction<'_>,
    maximum_records: usize,
) -> Result<LifecycleDatabase, StoreError> {
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
    let code = database_error.code();
    if code == &postgres::error::SqlState::T_R_SERIALIZATION_FAILURE
        || code == &postgres::error::SqlState::T_R_DEADLOCK_DETECTED
        || code == &postgres::error::SqlState::UNIQUE_VIOLATION
    {
        StoreError::Conflict
    } else if code == &postgres::error::SqlState::CHECK_VIOLATION {
        StoreError::Corrupt
    } else {
        StoreError::Unavailable
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
}
