//! Crash-persistent prepared-update capability store.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use base64ct::{Base64UrlUnpadded, Encoding as _};
use rustix::fs::{FlockOperation, flock};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tempfile::NamedTempFile;

const SCHEMA: &str = "auths.postgresql.prepared-update-store/1";
const MAX_DATABASE_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 100_000;
const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// Closed durable prepared-update state.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PreparedUpdateStateV1 {
    Reserved,
    Ready,
    Claimed { operation_id: String },
    Consumed { operation_id: String },
    Expired,
}

/// Exact metadata bound to one opaque prepared-update capability.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedUpdateRecordV1 {
    token_hash: String,
    state: PreparedUpdateStateV1,
    preflight_operation_id: String,
    principal: String,
    connection_id: String,
    connection_generation: u64,
    account_commitment: String,
    descriptor_commitment: String,
    credential_commitment: String,
    configuration_commitment: String,
    action_digest: String,
    expires_at: u64,
    payload: Option<Vec<u8>>,
}

impl PreparedUpdateRecordV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn reserved(
        token: &str,
        preflight_operation_id: &str,
        principal: &str,
        connection_id: &str,
        connection_generation: u64,
        account_commitment: &[u8; 32],
        descriptor_commitment: &[u8; 32],
        credential_commitment: &[u8; 32],
        configuration_commitment: &[u8; 32],
        action_digest: &[u8; 32],
        expires_at: u64,
    ) -> Result<Self, PreparedUpdateStoreError> {
        if !valid_token(token)
            || !token_text(preflight_operation_id, 128)
            || principal.is_empty()
            || principal.len() > 512
            || !token_text(connection_id, 128)
            || connection_generation == 0
            || expires_at == 0
        {
            return Err(PreparedUpdateStoreError::InvalidRecord);
        }
        Ok(Self {
            token_hash: token_hash(token),
            state: PreparedUpdateStateV1::Reserved,
            preflight_operation_id: preflight_operation_id.into(),
            principal: principal.into(),
            connection_id: connection_id.into(),
            connection_generation,
            account_commitment: hex::encode(account_commitment),
            descriptor_commitment: hex::encode(descriptor_commitment),
            credential_commitment: hex::encode(credential_commitment),
            configuration_commitment: hex::encode(configuration_commitment),
            action_digest: hex::encode(action_digest),
            expires_at,
            payload: None,
        })
    }

    #[must_use]
    pub fn state(&self) -> &PreparedUpdateStateV1 {
        &self.state
    }
    #[cfg(feature = "qualification")]
    #[must_use]
    pub(crate) fn token_hash(&self) -> &str {
        &self.token_hash
    }
    #[cfg(feature = "qualification")]
    #[must_use]
    pub(crate) fn preflight_operation_id(&self) -> &str {
        &self.preflight_operation_id
    }
    #[must_use]
    pub fn payload(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }
    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }
    #[must_use]
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }
    #[must_use]
    pub const fn connection_generation(&self) -> u64 {
        self.connection_generation
    }
    #[must_use]
    pub fn account_commitment(&self) -> &str {
        &self.account_commitment
    }
    #[must_use]
    pub fn descriptor_commitment(&self) -> &str {
        &self.descriptor_commitment
    }
    #[must_use]
    pub fn credential_commitment(&self) -> &str {
        &self.credential_commitment
    }
    #[must_use]
    pub fn configuration_commitment(&self) -> &str {
        &self.configuration_commitment
    }
    #[must_use]
    pub fn action_digest(&self) -> &str {
        &self.action_digest
    }
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    fn validate(&self, key: &str) -> Result<(), PreparedUpdateStoreError> {
        if self.token_hash != key
            || !lower_hex(key)
            || !token_text(&self.preflight_operation_id, 128)
            || self.principal.is_empty()
            || self.principal.len() > 512
            || !token_text(&self.connection_id, 128)
            || self.connection_generation == 0
            || !lower_hex(&self.account_commitment)
            || !lower_hex(&self.descriptor_commitment)
            || !lower_hex(&self.credential_commitment)
            || !lower_hex(&self.configuration_commitment)
            || !lower_hex(&self.action_digest)
            || self.expires_at == 0
            || self
                .payload
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > MAX_PAYLOAD_BYTES)
            || matches!(
                self.state,
                PreparedUpdateStateV1::Ready
                    | PreparedUpdateStateV1::Claimed { .. }
                    | PreparedUpdateStateV1::Consumed { .. }
            ) != self.payload.is_some()
        {
            return Err(PreparedUpdateStoreError::InvalidRecord);
        }
        Ok(())
    }
}

/// File-backed store with process-safe CAS transitions.
pub struct PreparedUpdateStore {
    directory: PathBuf,
    database: PathBuf,
    lock: File,
}

impl PreparedUpdateStore {
    pub fn open(profile_state_root: &Path) -> Result<Self, PreparedUpdateStoreError> {
        let directory = profile_state_root.join("postgresql-prepared-updates-v1");
        if !directory.exists() {
            fs::create_dir(&directory).map_err(|_| PreparedUpdateStoreError::Storage)?;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .map_err(|_| PreparedUpdateStoreError::Storage)?;
        }
        let metadata =
            fs::symlink_metadata(&directory).map_err(|_| PreparedUpdateStoreError::Storage)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(PreparedUpdateStoreError::Storage);
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(directory.join("store.lock"))
            .map_err(|_| PreparedUpdateStoreError::Storage)?;
        Ok(Self {
            database: directory.join("records.json"),
            directory,
            lock,
        })
    }

    /// Generates a caller capability with 256 bits of OS entropy.
    pub fn generate_token() -> Result<String, PreparedUpdateStoreError> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| PreparedUpdateStoreError::Storage)?;
        Ok(format!("pupd_{}", Base64UrlUnpadded::encode_string(&bytes)))
    }

    pub fn reserve(&self, record: PreparedUpdateRecordV1) -> Result<(), PreparedUpdateStoreError> {
        self.mutate(|database| {
            if database.records.len() >= MAX_RECORDS
                || database.records.contains_key(&record.token_hash)
            {
                return Err(PreparedUpdateStoreError::Conflict);
            }
            record.validate(&record.token_hash)?;
            database.records.insert(record.token_hash.clone(), record);
            Ok(())
        })
    }

    pub fn mark_ready(
        &self,
        token: &str,
        operation_id: &str,
        action_digest: &[u8; 32],
        payload: Vec<u8>,
    ) -> Result<PreparedUpdateRecordV1, PreparedUpdateStoreError> {
        if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
            return Err(PreparedUpdateStoreError::InvalidRecord);
        }
        self.mutate(|database| {
            let record = database
                .records
                .get_mut(&token_hash(token))
                .ok_or(PreparedUpdateStoreError::NotFound)?;
            if record.preflight_operation_id != operation_id {
                return Err(PreparedUpdateStoreError::Conflict);
            }
            match record.state {
                PreparedUpdateStateV1::Reserved => {
                    record.state = PreparedUpdateStateV1::Ready;
                    record.action_digest = hex::encode(action_digest);
                    record.payload = Some(payload);
                }
                PreparedUpdateStateV1::Ready
                    if record.payload.as_deref() == Some(&payload)
                        && record.action_digest == hex::encode(action_digest) => {}
                _ => return Err(PreparedUpdateStoreError::Conflict),
            }
            Ok(record.clone())
        })
    }

    /// Permanently invalidates a reserved token after protected discovery
    /// produced a conclusive policy denial.
    pub fn deny_reserved(
        &self,
        token: &str,
        operation_id: &str,
    ) -> Result<PreparedUpdateRecordV1, PreparedUpdateStoreError> {
        self.mutate(|database| {
            let record = database
                .records
                .get_mut(&token_hash(token))
                .ok_or(PreparedUpdateStoreError::NotFound)?;
            if record.preflight_operation_id != operation_id {
                return Err(PreparedUpdateStoreError::Conflict);
            }
            match record.state {
                PreparedUpdateStateV1::Reserved => {
                    record.state = PreparedUpdateStateV1::Expired;
                    record.payload = None;
                }
                PreparedUpdateStateV1::Expired => {}
                _ => return Err(PreparedUpdateStoreError::Conflict),
            }
            Ok(record.clone())
        })
    }

    /// Invalidates the unique reservation owned by a preflight operation.
    ///
    /// This lookup is the crash-safe release path for the boundary after the
    /// domain reservation is durable but before the common journal can store
    /// the sealed command containing the opaque token.  No match is an
    /// idempotent success because the crash may have happened before reserve.
    pub fn deny_reserved_by_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<PreparedUpdateRecordV1>, PreparedUpdateStoreError> {
        if !token_text(operation_id, 128) {
            return Err(PreparedUpdateStoreError::InvalidRecord);
        }
        self.mutate(|database| {
            let keys = database
                .records
                .iter()
                .filter(|(_, record)| record.preflight_operation_id == operation_id)
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>();
            let [key] = keys.as_slice() else {
                return if keys.is_empty() {
                    Ok(None)
                } else {
                    Err(PreparedUpdateStoreError::InvalidRecord)
                };
            };
            let record = database
                .records
                .get_mut(key)
                .ok_or(PreparedUpdateStoreError::InvalidRecord)?;
            match record.state {
                PreparedUpdateStateV1::Reserved => {
                    record.state = PreparedUpdateStateV1::Expired;
                    record.payload = None;
                }
                PreparedUpdateStateV1::Expired => {}
                _ => return Err(PreparedUpdateStoreError::Conflict),
            }
            Ok(Some(record.clone()))
        })
    }

    pub fn load_ready(
        &self,
        token: &str,
        now: u64,
    ) -> Result<PreparedUpdateRecordV1, PreparedUpdateStoreError> {
        self.mutate(|database| {
            let record = database
                .records
                .get_mut(&token_hash(token))
                .ok_or(PreparedUpdateStoreError::NotFound)?;
            if now > record.expires_at && matches!(record.state, PreparedUpdateStateV1::Ready) {
                record.state = PreparedUpdateStateV1::Expired;
                record.payload = None;
                return Err(PreparedUpdateStoreError::Expired);
            }
            if !matches!(record.state, PreparedUpdateStateV1::Ready) {
                return Err(PreparedUpdateStoreError::Conflict);
            }
            Ok(record.clone())
        })
    }

    pub fn claim(
        &self,
        token: &str,
        operation_id: &str,
        now: u64,
    ) -> Result<PreparedUpdateRecordV1, PreparedUpdateStoreError> {
        self.mutate(|database| {
            let record = database
                .records
                .get_mut(&token_hash(token))
                .ok_or(PreparedUpdateStoreError::NotFound)?;
            if now > record.expires_at {
                record.state = PreparedUpdateStateV1::Expired;
                record.payload = None;
                return Err(PreparedUpdateStoreError::Expired);
            }
            match &record.state {
                PreparedUpdateStateV1::Ready => {
                    record.state = PreparedUpdateStateV1::Claimed {
                        operation_id: operation_id.into(),
                    };
                }
                PreparedUpdateStateV1::Claimed {
                    operation_id: existing,
                } if existing == operation_id => {}
                _ => return Err(PreparedUpdateStoreError::Conflict),
            }
            Ok(record.clone())
        })
    }

    pub fn consume(
        &self,
        token: &str,
        operation_id: &str,
    ) -> Result<PreparedUpdateRecordV1, PreparedUpdateStoreError> {
        self.mutate(|database| {
            let record = database
                .records
                .get_mut(&token_hash(token))
                .ok_or(PreparedUpdateStoreError::NotFound)?;
            match &record.state {
                PreparedUpdateStateV1::Claimed {
                    operation_id: existing,
                } if existing == operation_id => {
                    record.state = PreparedUpdateStateV1::Consumed {
                        operation_id: operation_id.into(),
                    };
                }
                PreparedUpdateStateV1::Consumed {
                    operation_id: existing,
                } if existing == operation_id => {}
                _ => return Err(PreparedUpdateStoreError::Conflict),
            }
            Ok(record.clone())
        })
    }

    /// Releases a claim only while the common journal still durably proves
    /// the provider-entry marker was never written.
    pub fn release_claim(
        &self,
        token: &str,
        operation_id: &str,
    ) -> Result<PreparedUpdateRecordV1, PreparedUpdateStoreError> {
        self.mutate(|database| {
            let record = database
                .records
                .get_mut(&token_hash(token))
                .ok_or(PreparedUpdateStoreError::NotFound)?;
            match &record.state {
                PreparedUpdateStateV1::Claimed {
                    operation_id: existing,
                } if existing == operation_id => {
                    record.state = PreparedUpdateStateV1::Ready;
                }
                PreparedUpdateStateV1::Ready => {}
                _ => return Err(PreparedUpdateStoreError::Conflict),
            }
            Ok(record.clone())
        })
    }

    /// Releases the unique claim owned by an effect operation without
    /// requiring the opaque token to have reached the common journal.
    pub fn release_claim_by_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<PreparedUpdateRecordV1>, PreparedUpdateStoreError> {
        if !token_text(operation_id, 128) {
            return Err(PreparedUpdateStoreError::InvalidRecord);
        }
        self.mutate(|database| {
            let keys = database
                .records
                .iter()
                .filter(|(_, record)| {
                    matches!(
                        &record.state,
                        PreparedUpdateStateV1::Claimed {
                            operation_id: existing
                        } if existing == operation_id
                    )
                })
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>();
            let [key] = keys.as_slice() else {
                return if keys.is_empty() {
                    Ok(None)
                } else {
                    Err(PreparedUpdateStoreError::InvalidRecord)
                };
            };
            let record = database
                .records
                .get_mut(key)
                .ok_or(PreparedUpdateStoreError::InvalidRecord)?;
            record.state = PreparedUpdateStateV1::Ready;
            Ok(Some(record.clone()))
        })
    }

    fn mutate<T>(
        &self,
        action: impl FnOnce(&mut PreparedUpdateDatabaseV1) -> Result<T, PreparedUpdateStoreError>,
    ) -> Result<T, PreparedUpdateStoreError> {
        flock(&self.lock, FlockOperation::LockExclusive)
            .map_err(|_| PreparedUpdateStoreError::Storage)?;
        let result = (|| {
            let mut database = self.read()?;
            let value = action(&mut database)?;
            self.write(&database)?;
            Ok(value)
        })();
        let _ = flock(&self.lock, FlockOperation::Unlock);
        result
    }

    fn read(&self) -> Result<PreparedUpdateDatabaseV1, PreparedUpdateStoreError> {
        if !self.database.exists() {
            return Ok(PreparedUpdateDatabaseV1 {
                schema: SCHEMA.into(),
                records: BTreeMap::new(),
            });
        }
        let mut file = File::open(&self.database).map_err(|_| PreparedUpdateStoreError::Storage)?;
        let length = file
            .metadata()
            .map_err(|_| PreparedUpdateStoreError::Storage)?
            .len();
        if length == 0 || length > MAX_DATABASE_BYTES as u64 {
            return Err(PreparedUpdateStoreError::Storage);
        }
        let capacity = usize::try_from(length).map_err(|_| PreparedUpdateStoreError::Storage)?;
        let mut bytes = Vec::with_capacity(capacity);
        std::io::Read::by_ref(&mut file)
            .take((MAX_DATABASE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| PreparedUpdateStoreError::Storage)?;
        decode_database(&bytes)
    }

    fn write(&self, database: &PreparedUpdateDatabaseV1) -> Result<(), PreparedUpdateStoreError> {
        database.validate()?;
        let bytes = serde_json_canonicalizer::to_vec(database)
            .map_err(|_| PreparedUpdateStoreError::Storage)?;
        if bytes.len() > MAX_DATABASE_BYTES {
            return Err(PreparedUpdateStoreError::Capacity);
        }
        let mut temp = NamedTempFile::new_in(&self.directory)
            .map_err(|_| PreparedUpdateStoreError::Storage)?;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| PreparedUpdateStoreError::Storage)?;
        temp.write_all(&bytes)
            .and_then(|()| temp.as_file().sync_all())
            .map_err(|_| PreparedUpdateStoreError::Storage)?;
        temp.persist(&self.database)
            .map_err(|_| PreparedUpdateStoreError::Storage)?;
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| PreparedUpdateStoreError::Storage)
    }
}

fn decode_database(bytes: &[u8]) -> Result<PreparedUpdateDatabaseV1, PreparedUpdateStoreError> {
    if bytes.is_empty() || bytes.len() > MAX_DATABASE_BYTES {
        return Err(PreparedUpdateStoreError::Storage);
    }
    let database: PreparedUpdateDatabaseV1 =
        serde_json::from_slice(bytes).map_err(|_| PreparedUpdateStoreError::Storage)?;
    database.validate()?;
    if serde_json_canonicalizer::to_vec(&database).map_err(|_| PreparedUpdateStoreError::Storage)?
        != bytes
    {
        return Err(PreparedUpdateStoreError::Storage);
    }
    Ok(database)
}

#[cfg(feature = "qualification")]
pub(crate) fn decode_qualification_records(
    bytes: &[u8],
) -> Result<Vec<PreparedUpdateRecordV1>, PreparedUpdateStoreError> {
    Ok(decode_database(bytes)?.records.into_values().collect())
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreparedUpdateDatabaseV1 {
    schema: String,
    records: BTreeMap<String, PreparedUpdateRecordV1>,
}

impl PreparedUpdateDatabaseV1 {
    fn validate(&self) -> Result<(), PreparedUpdateStoreError> {
        if self.schema != SCHEMA || self.records.len() > MAX_RECORDS {
            return Err(PreparedUpdateStoreError::InvalidRecord);
        }
        self.records
            .iter()
            .try_for_each(|(key, record)| record.validate(key))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PreparedUpdateStoreError {
    #[error("prepared update storage is unavailable")]
    Storage,
    #[error("prepared update record is invalid")]
    InvalidRecord,
    #[error("prepared update store is at capacity")]
    Capacity,
    #[error("prepared update does not exist")]
    NotFound,
    #[error("prepared update is expired")]
    Expired,
    #[error("prepared update state conflicts")]
    Conflict,
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn valid_token(value: &str) -> bool {
    value.len() == 48
        && value.starts_with("pupd_")
        && value[5..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn token_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(token: &str) -> PreparedUpdateRecordV1 {
        PreparedUpdateRecordV1::reserved(
            token,
            "OP_01JTEST",
            "did:example:workload",
            "conn_test",
            1,
            &[1; 32],
            &[2; 32],
            &[3; 32],
            &[4; 32],
            &[5; 32],
            200,
        )
        .unwrap()
    }

    #[test]
    fn restart_preserves_exact_cas_and_never_stores_raw_token_as_key() {
        let directory = tempfile::tempdir().unwrap();
        let token = PreparedUpdateStore::generate_token().unwrap();
        let store = PreparedUpdateStore::open(directory.path()).unwrap();
        store.reserve(record(&token)).unwrap();
        let ready = store
            .mark_ready(&token, "OP_01JTEST", &[9; 32], b"payload".to_vec())
            .unwrap();
        assert!(matches!(ready.state(), PreparedUpdateStateV1::Ready));
        drop(store);

        let store = PreparedUpdateStore::open(directory.path()).unwrap();
        assert_eq!(
            store.load_ready(&token, 100).unwrap().payload(),
            Some(&b"payload"[..])
        );
        store.claim(&token, "OP_EFFECT", 100).unwrap();
        store.claim(&token, "OP_EFFECT", 100).unwrap();
        assert_eq!(
            store.claim(&token, "OP_OTHER", 100),
            Err(PreparedUpdateStoreError::Conflict)
        );
        store.consume(&token, "OP_EFFECT").unwrap();

        let bytes = fs::read(store.database).unwrap();
        assert!(
            !bytes
                .windows(token.len())
                .any(|value| value == token.as_bytes())
        );
        #[cfg(feature = "qualification")]
        {
            let decoded = decode_qualification_records(&bytes).unwrap();
            assert_eq!(decoded.len(), 1);
            assert_eq!(decoded[0].token_hash(), token_hash(&token));
            let mut noncanonical = bytes.clone();
            noncanonical.push(b'\n');
            assert!(decode_qualification_records(&noncanonical).is_err());
        }
    }

    #[test]
    fn expired_ready_record_fails_closed_and_discards_payload() {
        let directory = tempfile::tempdir().unwrap();
        let token = PreparedUpdateStore::generate_token().unwrap();
        let store = PreparedUpdateStore::open(directory.path()).unwrap();
        store.reserve(record(&token)).unwrap();
        store
            .mark_ready(&token, "OP_01JTEST", &[9; 32], b"payload".to_vec())
            .unwrap();
        assert_eq!(
            store.load_ready(&token, 201),
            Err(PreparedUpdateStoreError::Expired)
        );
    }

    #[test]
    fn operation_identity_releases_pre_command_reservation_and_claim() {
        let directory = tempfile::tempdir().unwrap();
        let store = PreparedUpdateStore::open(directory.path()).unwrap();
        let reserved_token = PreparedUpdateStore::generate_token().unwrap();
        store.reserve(record(&reserved_token)).unwrap();
        assert!(matches!(
            store
                .deny_reserved_by_operation("OP_01JTEST")
                .unwrap()
                .unwrap()
                .state(),
            PreparedUpdateStateV1::Expired
        ));
        assert!(matches!(
            store
                .deny_reserved_by_operation("OP_01JTEST")
                .unwrap()
                .unwrap()
                .state(),
            PreparedUpdateStateV1::Expired
        ));

        let claimed_token = PreparedUpdateStore::generate_token().unwrap();
        store.reserve(record(&claimed_token)).unwrap();
        store
            .mark_ready(&claimed_token, "OP_01JTEST", &[9; 32], b"payload".to_vec())
            .unwrap();
        store.claim(&claimed_token, "OP_EFFECT", 100).unwrap();
        assert!(matches!(
            store
                .release_claim_by_operation("OP_EFFECT")
                .unwrap()
                .unwrap()
                .state(),
            PreparedUpdateStateV1::Ready
        ));
        assert!(
            store
                .release_claim_by_operation("OP_EFFECT")
                .unwrap()
                .is_none()
        );
    }
}
