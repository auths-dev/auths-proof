//! Crash-persistent provider-connection registry without credential bytes.

// Store operations share one closed persistence error contract; their method
// documentation describes the authoritative state transition instead of
// repeating the same error catalogue on every entry point.
#![allow(clippy::missing_errors_doc)]

use auths_connections::{
    ConnectionAlias, ConnectionBinding, ConnectionProfile, ConnectionRecord, ConnectionRegistry,
    ConnectionRegistryError, ProviderKind, RegistryLimits,
};
use minicbor::{Decoder, Encoder};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write as _,
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::Mutex,
};
use tempfile::NamedTempFile;
use thiserror::Error;

const DATABASE_VERSION: u8 = 1;
const MAX_DEFAULTS: usize = 100_000;
const MAX_DATABASE_BYTES: usize = 300 * 1024 * 1024;

type RecordKey = (ProviderKind, ConnectionAlias);
type DefaultKey = (String, ProviderKind);

#[derive(Clone, Default)]
struct ConnectionDatabase {
    records: BTreeMap<RecordKey, ConnectionRecord>,
    defaults: BTreeMap<DefaultKey, ConnectionAlias>,
    encoded_record_bytes: usize,
}

/// Single-process crash-persistent `auths.provider-connection/1` store.
///
/// Every mutation serializes a complete bounded canonical snapshot to an
/// owner-selected directory, syncs it, atomically replaces the live file, and
/// syncs the parent directory before acknowledging success. Raw provider
/// credentials are never accepted by this store.
pub struct PersistentConnectionStore {
    path: PathBuf,
    limits: RegistryLimits,
    database: Mutex<ConnectionDatabase>,
}

impl PersistentConnectionStore {
    /// Opens or creates a bounded persistent connection registry.
    ///
    /// # Errors
    ///
    /// Existing malformed, noncanonical, duplicate, or over-capacity state is
    /// rejected and is never silently replaced.
    pub fn open(
        path: impl Into<PathBuf>,
        limits: RegistryLimits,
    ) -> Result<Self, ConnectionStoreConfigurationError> {
        let path = path.into();
        if path.as_os_str().is_empty() || path.parent().is_none() {
            return Err(ConnectionStoreConfigurationError::InvalidPath);
        }
        let database = if path.exists() {
            let metadata =
                fs::symlink_metadata(&path).map_err(|_| ConnectionStoreConfigurationError::Io)?;
            if !metadata.file_type().is_file()
                || usize::try_from(metadata.len())
                    .map_or(true, |length| length > MAX_DATABASE_BYTES)
            {
                return Err(ConnectionStoreConfigurationError::InvalidState);
            }
            let bytes = fs::read(&path).map_err(|_| ConnectionStoreConfigurationError::Io)?;
            decode_database(&bytes, limits)?
        } else {
            ConnectionDatabase::default()
        };
        Ok(Self {
            path,
            limits,
            database: Mutex::new(database),
        })
    }

    /// Inserts one unique provider/alias record durably.
    ///
    /// # Errors
    ///
    /// Returns the same closed conflict/capacity classes as the in-memory
    /// registry, plus durable I/O failure.
    pub fn insert(&self, record: ConnectionRecord) -> Result<(), PersistentConnectionStoreError> {
        self.insert_with_defaults(record, &[])
    }

    /// Inserts one record and all workload/provider defaults in the same
    /// crash-durable snapshot publication.
    ///
    /// # Errors
    ///
    /// The complete mutation is refused when any default is unauthorized,
    /// duplicate capacity is exhausted, or durable publication fails. No
    /// partial record/default state becomes visible.
    pub fn insert_with_defaults(
        &self,
        record: ConnectionRecord,
        default_workloads: &[String],
    ) -> Result<(), PersistentConnectionStoreError> {
        let key = (record.provider_kind().clone(), record.alias().clone());
        let record_bytes = record
            .to_canonical_cbor()
            .map_err(|_| PersistentConnectionStoreError::InvalidRecord)?
            .len();
        self.mutate(|database| {
            if database.records.contains_key(&key) {
                return Err(PersistentConnectionStoreError::Conflict);
            }
            if database.records.len() >= self.limits.maximum_records.get()
                || database
                    .encoded_record_bytes
                    .checked_add(record_bytes)
                    .is_none_or(|value| value > self.limits.maximum_encoded_bytes.get())
            {
                return Err(PersistentConnectionStoreError::Capacity);
            }
            database.encoded_record_bytes += record_bytes;
            let provider = record.provider_kind().clone();
            let alias = record.alias().clone();
            database.records.insert(key, record);
            for workload in default_workloads {
                if database.defaults.len() >= MAX_DEFAULTS
                    && !database
                        .defaults
                        .contains_key(&(workload.clone(), provider.clone()))
                {
                    return Err(PersistentConnectionStoreError::Capacity);
                }
                let registry = registry_from(database, self.limits)?;
                registry
                    .set_default(workload, &provider, &alias)
                    .map_err(map_registry)?;
                database
                    .defaults
                    .insert((workload.clone(), provider.clone()), alias.clone());
            }
            Ok(())
        })
    }

    /// Replaces one record only at the expected generation and immutable ID.
    pub fn replace(
        &self,
        expected_generation: NonZeroU64,
        replacement: ConnectionRecord,
    ) -> Result<(), PersistentConnectionStoreError> {
        let key = (
            replacement.provider_kind().clone(),
            replacement.alias().clone(),
        );
        let replacement_bytes = replacement
            .to_canonical_cbor()
            .map_err(|_| PersistentConnectionStoreError::InvalidRecord)?
            .len();
        self.mutate(|database| {
            let current = database
                .records
                .get(&key)
                .ok_or(PersistentConnectionStoreError::Unavailable)?;
            if current.generation() != expected_generation
                || current.connection_id() != replacement.connection_id()
                || current.created_at_unix_seconds() != replacement.created_at_unix_seconds()
                || replacement.generation().get()
                    != expected_generation
                        .get()
                        .checked_add(1)
                        .ok_or(PersistentConnectionStoreError::Conflict)?
            {
                return Err(PersistentConnectionStoreError::Conflict);
            }
            let current_bytes = current
                .to_canonical_cbor()
                .map_err(|_| PersistentConnectionStoreError::InvalidRecord)?
                .len();
            let next_bytes = database
                .encoded_record_bytes
                .checked_sub(current_bytes)
                .and_then(|value| value.checked_add(replacement_bytes))
                .ok_or(PersistentConnectionStoreError::Capacity)?;
            if next_bytes > self.limits.maximum_encoded_bytes.get() {
                return Err(PersistentConnectionStoreError::Capacity);
            }
            database.records.insert(key, replacement);
            database.encoded_record_bytes = next_bytes;
            Ok(())
        })
    }

    /// Atomically disables, enables, or revokes one expected generation.
    pub fn transition_state(
        &self,
        provider: &ProviderKind,
        alias: &ConnectionAlias,
        expected_generation: NonZeroU64,
        state: auths_connections::ConnectionState,
        credential_reference_commitment: [u8; 32],
        updated_at_unix_seconds: u64,
    ) -> Result<ConnectionRecord, PersistentConnectionStoreError> {
        let current = self
            .load(provider, alias)?
            .ok_or(PersistentConnectionStoreError::Unavailable)?;
        if current.generation() != expected_generation {
            return Err(PersistentConnectionStoreError::Conflict);
        }
        let replacement = current
            .transition_state(
                state,
                credential_reference_commitment,
                updated_at_unix_seconds,
            )
            .map_err(|_| PersistentConnectionStoreError::Conflict)?;
        self.replace(expected_generation, replacement.clone())?;
        Ok(replacement)
    }

    /// Assigns one durable workload/provider default after authorization.
    pub fn set_default(
        &self,
        workload_id: &str,
        provider: &ProviderKind,
        alias: &ConnectionAlias,
    ) -> Result<(), PersistentConnectionStoreError> {
        self.mutate(|database| {
            let registry = registry_from(database, self.limits)?;
            registry
                .set_default(workload_id, provider, alias)
                .map_err(map_registry)?;
            let key = (workload_id.to_owned(), provider.clone());
            if !database.defaults.contains_key(&key) && database.defaults.len() >= MAX_DEFAULTS {
                return Err(PersistentConnectionStoreError::Capacity);
            }
            database.defaults.insert(key, alias.clone());
            Ok(())
        })
    }

    /// Resolves an explicit alias or durable workload default to a sealed binding.
    pub fn resolve(
        &self,
        provider: &ProviderKind,
        selected_alias: Option<&ConnectionAlias>,
        workload_id: &str,
        profile: &ConnectionProfile,
    ) -> Result<ConnectionBinding, PersistentConnectionStoreError> {
        let database = self
            .database
            .lock()
            .map_err(|_| PersistentConnectionStoreError::Unavailable)?;
        let alias = match selected_alias {
            Some(value) => value,
            None => database
                .defaults
                .get(&(workload_id.to_owned(), provider.clone()))
                .ok_or(PersistentConnectionStoreError::Unavailable)?,
        };
        registry_from(&database, self.limits)?
            .resolve(provider, Some(alias), workload_id, profile)
            .map_err(map_registry)
    }

    /// Rereads and compares every security-critical connection fact before lease.
    pub fn reread_before_lease(
        &self,
        binding: &ConnectionBinding,
        workload_id: &str,
        profile: &ConnectionProfile,
    ) -> Result<ConnectionRecord, PersistentConnectionStoreError> {
        let database = self
            .database
            .lock()
            .map_err(|_| PersistentConnectionStoreError::Unavailable)?;
        registry_from(&database, self.limits)?
            .reread_before_lease(binding, workload_id, profile)
            .map_err(map_registry)
    }

    /// Returns one sanitized record snapshot by provider and alias.
    pub fn load(
        &self,
        provider: &ProviderKind,
        alias: &ConnectionAlias,
    ) -> Result<Option<ConnectionRecord>, PersistentConnectionStoreError> {
        self.database
            .lock()
            .map(|database| {
                database
                    .records
                    .get(&(provider.clone(), alias.clone()))
                    .cloned()
            })
            .map_err(|_| PersistentConnectionStoreError::Unavailable)
    }

    /// Returns all records in canonical `(provider, alias)` order.
    pub fn list(&self) -> Result<Vec<ConnectionRecord>, PersistentConnectionStoreError> {
        self.database
            .lock()
            .map(|database| database.records.values().cloned().collect())
            .map_err(|_| PersistentConnectionStoreError::Unavailable)
    }

    fn mutate<T>(
        &self,
        mutation: impl FnOnce(&mut ConnectionDatabase) -> Result<T, PersistentConnectionStoreError>,
    ) -> Result<T, PersistentConnectionStoreError> {
        let mut database = self
            .database
            .lock()
            .map_err(|_| PersistentConnectionStoreError::Unavailable)?;
        let mut next = database.clone();
        let value = mutation(&mut next)?;
        persist_database(&self.path, &next)?;
        *database = next;
        Ok(value)
    }
}

/// Startup failure for existing persistent connection state.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConnectionStoreConfigurationError {
    /// Store path is empty or has no parent directory.
    #[error("invalid connection-store path")]
    InvalidPath,
    /// Existing state is malformed, noncanonical, duplicate, or over capacity.
    #[error("invalid persistent connection state")]
    InvalidState,
    /// Existing state could not be read.
    #[error("persistent connection store is unavailable")]
    Io,
}

/// Closed runtime failure for persistent connection mutations and lookup.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PersistentConnectionStoreError {
    /// Record failed canonical validation.
    #[error("invalid connection record")]
    InvalidRecord,
    /// Missing, disabled, revoked, unauthorized, or inaccessible state.
    #[error("connection unavailable")]
    Unavailable,
    /// Alias, generation, or immutable identity conflict.
    #[error("connection state conflict")]
    Conflict,
    /// Sealed identity or commitment changed.
    #[error("connection substitution detected")]
    Substitution,
    /// Fixed record, byte, or default capacity is exhausted.
    #[error("connection store capacity exhausted")]
    Capacity,
    /// Crash-durable publication failed.
    #[error("connection store persistence failed")]
    Io,
}

fn registry_from(
    database: &ConnectionDatabase,
    limits: RegistryLimits,
) -> Result<ConnectionRegistry, PersistentConnectionStoreError> {
    let registry = ConnectionRegistry::new(limits);
    for record in database.records.values() {
        registry.insert(record.clone()).map_err(map_registry)?;
    }
    Ok(registry)
}

fn map_registry(error: ConnectionRegistryError) -> PersistentConnectionStoreError {
    match error {
        ConnectionRegistryError::InvalidRecord | ConnectionRegistryError::InvalidWorkload => {
            PersistentConnectionStoreError::InvalidRecord
        }
        ConnectionRegistryError::Unavailable => PersistentConnectionStoreError::Unavailable,
        ConnectionRegistryError::Conflict => PersistentConnectionStoreError::Conflict,
        ConnectionRegistryError::Substitution => PersistentConnectionStoreError::Substitution,
        ConnectionRegistryError::Capacity => PersistentConnectionStoreError::Capacity,
    }
}

fn encode_database(
    database: &ConnectionDatabase,
) -> Result<Vec<u8>, PersistentConnectionStoreError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(3)
        .map_err(|_| PersistentConnectionStoreError::Io)?;
    encoder
        .u8(1)
        .and_then(|item| item.u8(DATABASE_VERSION))
        .map_err(|_| PersistentConnectionStoreError::Io)?;
    encoder
        .u8(2)
        .and_then(|item| item.array(database.records.len() as u64))
        .map_err(|_| PersistentConnectionStoreError::Io)?;
    for record in database.records.values() {
        let bytes = record
            .to_canonical_cbor()
            .map_err(|_| PersistentConnectionStoreError::InvalidRecord)?;
        encoder
            .bytes(&bytes)
            .map_err(|_| PersistentConnectionStoreError::Io)?;
    }
    encoder
        .u8(3)
        .and_then(|item| item.array(database.defaults.len() as u64))
        .map_err(|_| PersistentConnectionStoreError::Io)?;
    for ((workload, provider), alias) in &database.defaults {
        encoder
            .array(3)
            .and_then(|item| item.str(workload))
            .and_then(|item| item.str(provider.as_str()))
            .and_then(|item| item.str(alias.as_str()))
            .map_err(|_| PersistentConnectionStoreError::Io)?;
    }
    let bytes = encoder.into_writer();
    if bytes.len() > MAX_DATABASE_BYTES {
        return Err(PersistentConnectionStoreError::Capacity);
    }
    Ok(bytes)
}

fn decode_database(
    bytes: &[u8],
    limits: RegistryLimits,
) -> Result<ConnectionDatabase, ConnectionStoreConfigurationError> {
    if bytes.is_empty() || bytes.len() > MAX_DATABASE_BYTES {
        return Err(ConnectionStoreConfigurationError::InvalidState);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder
        .map()
        .map_err(|_| ConnectionStoreConfigurationError::InvalidState)?
        != Some(3)
    {
        return Err(ConnectionStoreConfigurationError::InvalidState);
    }
    expect_key(&mut decoder, 1)?;
    if decoder
        .u8()
        .map_err(|_| ConnectionStoreConfigurationError::InvalidState)?
        != DATABASE_VERSION
    {
        return Err(ConnectionStoreConfigurationError::InvalidState);
    }
    expect_key(&mut decoder, 2)?;
    let records_len = bounded_array(&mut decoder, limits.maximum_records.get())?;
    let mut database = ConnectionDatabase::default();
    for _ in 0..records_len {
        let record_bytes = decoder
            .bytes()
            .map_err(|_| ConnectionStoreConfigurationError::InvalidState)?;
        let record = ConnectionRecord::from_canonical_cbor(record_bytes)
            .map_err(|_| ConnectionStoreConfigurationError::InvalidState)?;
        database.encoded_record_bytes = database
            .encoded_record_bytes
            .checked_add(record_bytes.len())
            .ok_or(ConnectionStoreConfigurationError::InvalidState)?;
        if database.encoded_record_bytes > limits.maximum_encoded_bytes.get()
            || database
                .records
                .insert(
                    (record.provider_kind().clone(), record.alias().clone()),
                    record,
                )
                .is_some()
        {
            return Err(ConnectionStoreConfigurationError::InvalidState);
        }
    }
    expect_key(&mut decoder, 3)?;
    let defaults_len = bounded_array(&mut decoder, MAX_DEFAULTS)?;
    for _ in 0..defaults_len {
        if decoder
            .array()
            .map_err(|_| ConnectionStoreConfigurationError::InvalidState)?
            != Some(3)
        {
            return Err(ConnectionStoreConfigurationError::InvalidState);
        }
        let workload = decoder
            .str()
            .map_err(|_| ConnectionStoreConfigurationError::InvalidState)?
            .to_owned();
        let provider = ProviderKind::parse(
            decoder
                .str()
                .map_err(|_| ConnectionStoreConfigurationError::InvalidState)?,
        )
        .map_err(|_| ConnectionStoreConfigurationError::InvalidState)?;
        let alias = ConnectionAlias::parse(
            decoder
                .str()
                .map_err(|_| ConnectionStoreConfigurationError::InvalidState)?,
        )
        .map_err(|_| ConnectionStoreConfigurationError::InvalidState)?;
        let record = database
            .records
            .get(&(provider.clone(), alias.clone()))
            .ok_or(ConnectionStoreConfigurationError::InvalidState)?;
        if workload.is_empty()
            || workload.len() > 128
            || !workload.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
            || record.allowed_workloads().binary_search(&workload).is_err()
            || database
                .defaults
                .insert((workload, provider), alias)
                .is_some()
        {
            return Err(ConnectionStoreConfigurationError::InvalidState);
        }
    }
    if decoder.position() != bytes.len() {
        return Err(ConnectionStoreConfigurationError::InvalidState);
    }
    let canonical =
        encode_database(&database).map_err(|_| ConnectionStoreConfigurationError::InvalidState)?;
    if canonical != bytes {
        return Err(ConnectionStoreConfigurationError::InvalidState);
    }
    Ok(database)
}

fn persist_database(
    path: &Path,
    database: &ConnectionDatabase,
) -> Result<(), PersistentConnectionStoreError> {
    let parent = path.parent().ok_or(PersistentConnectionStoreError::Io)?;
    fs::create_dir_all(parent).map_err(|_| PersistentConnectionStoreError::Io)?;
    let bytes = encode_database(database)?;
    let mut temporary =
        NamedTempFile::new_in(parent).map_err(|_| PersistentConnectionStoreError::Io)?;
    temporary
        .write_all(&bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| PersistentConnectionStoreError::Io)?;
    temporary
        .persist(path)
        .map_err(|_| PersistentConnectionStoreError::Io)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| PersistentConnectionStoreError::Io)?;
    Ok(())
}

fn expect_key(
    decoder: &mut Decoder<'_>,
    expected: u8,
) -> Result<(), ConnectionStoreConfigurationError> {
    if decoder
        .u8()
        .map_err(|_| ConnectionStoreConfigurationError::InvalidState)?
        != expected
    {
        return Err(ConnectionStoreConfigurationError::InvalidState);
    }
    Ok(())
}

fn bounded_array(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<usize, ConnectionStoreConfigurationError> {
    let count = decoder
        .array()
        .map_err(|_| ConnectionStoreConfigurationError::InvalidState)?
        .ok_or(ConnectionStoreConfigurationError::InvalidState)?;
    let count =
        usize::try_from(count).map_err(|_| ConnectionStoreConfigurationError::InvalidState)?;
    if count > maximum {
        return Err(ConnectionStoreConfigurationError::InvalidState);
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_connections::{ConnectionId, ConnectionState, SemanticId};
    use std::num::{NonZeroU64, NonZeroUsize};

    fn record() -> ConnectionRecord {
        ConnectionRecord::new(
            ProviderKind::parse("stripe").unwrap(),
            ConnectionAlias::parse("merchant-primary").unwrap(),
            ConnectionId::generate().unwrap(),
            SemanticId::parse("auths.stripe.connection/1").unwrap(),
            SemanticId::parse("auths.stripe.connection-descriptor/1").unwrap(),
            vec![0xa1, 0x01, 0x01],
            [7; 32],
            [8; 32],
            NonZeroU64::new(1).unwrap(),
            ConnectionState::Active,
            vec!["payments-worker".to_owned()],
            vec![
                ConnectionProfile::new(SemanticId::parse("auths.stripe.refund").unwrap(), 1)
                    .unwrap(),
            ],
            10,
            10,
            None,
        )
        .unwrap()
    }

    #[test]
    fn records_and_defaults_survive_clean_process_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("connections.cbor");
        let limits = RegistryLimits {
            maximum_records: NonZeroUsize::new(10).unwrap(),
            maximum_encoded_bytes: NonZeroUsize::new(1_048_576).unwrap(),
        };
        let original = record();
        {
            let store = PersistentConnectionStore::open(&path, limits).unwrap();
            store.insert(original.clone()).unwrap();
            store
                .set_default(
                    "payments-worker",
                    original.provider_kind(),
                    original.alias(),
                )
                .unwrap();
        }
        let reopened = PersistentConnectionStore::open(&path, limits).unwrap();
        let profile =
            ConnectionProfile::new(SemanticId::parse("auths.stripe.refund").unwrap(), 1).unwrap();
        let binding = reopened
            .resolve(original.provider_kind(), None, "payments-worker", &profile)
            .unwrap();
        assert_eq!(binding.connection_id(), original.connection_id());
        assert_eq!(reopened.list().unwrap(), vec![original]);
    }

    #[test]
    fn corrupt_or_trailing_state_is_never_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("connections.cbor");
        fs::write(&path, [0xa0, 0x00]).unwrap();
        let Err(error) = PersistentConnectionStore::open(&path, RegistryLimits::default()) else {
            panic!("corrupt connection state must not open");
        };
        assert_eq!(error, ConnectionStoreConfigurationError::InvalidState);
        assert_eq!(fs::read(path).unwrap(), [0xa0, 0x00]);
    }
}
