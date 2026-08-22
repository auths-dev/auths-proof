//! Crash-persistent prepared-plan capability and artifact metadata store.

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

const SCHEMA: &str = "auths.opentofu.prepared-plan-store/1";
const MAX_DATABASE_BYTES: usize = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 100_000;
const MAX_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;

/// Closed durable prepared-plan state.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PreparedPlanStateV1 {
    Reserved,
    Ready,
    Claimed { operation_id: String },
    Consumed { operation_id: String },
    Expired,
}

/// Exact metadata bound to one opaque prepared-plan capability.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedPlanRecordV1 {
    token_hash: String,
    state: PreparedPlanStateV1,
    preflight_operation_id: String,
    principal: String,
    connection_id: String,
    connection_generation: u64,
    account_commitment: String,
    descriptor_commitment: String,
    credential_commitment: String,
    configuration_commitment: String,
    tool_commitment: String,
    action_digest: String,
    expires_at: u64,
    payload: Option<Vec<u8>>,
}

impl PreparedPlanRecordV1 {
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
        tool_commitment: &[u8; 32],
        action_digest: &[u8; 32],
        expires_at: u64,
    ) -> Result<Self, PreparedPlanStoreError> {
        if !valid_token(token)
            || !token_text(preflight_operation_id, 128)
            || principal.is_empty()
            || principal.len() > 512
            || !token_text(connection_id, 128)
            || connection_generation == 0
            || expires_at == 0
        {
            return Err(PreparedPlanStoreError::InvalidRecord);
        }
        Ok(Self {
            token_hash: token_hash(token),
            state: PreparedPlanStateV1::Reserved,
            preflight_operation_id: preflight_operation_id.into(),
            principal: principal.into(),
            connection_id: connection_id.into(),
            connection_generation,
            account_commitment: hex::encode(account_commitment),
            descriptor_commitment: hex::encode(descriptor_commitment),
            credential_commitment: hex::encode(credential_commitment),
            configuration_commitment: hex::encode(configuration_commitment),
            tool_commitment: hex::encode(tool_commitment),
            action_digest: hex::encode(action_digest),
            expires_at,
            payload: None,
        })
    }

    #[must_use]
    pub const fn state(&self) -> &PreparedPlanStateV1 {
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
    pub fn tool_commitment(&self) -> &str {
        &self.tool_commitment
    }
    #[must_use]
    pub fn action_digest(&self) -> &str {
        &self.action_digest
    }
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    fn validate(&self, key: &str) -> Result<(), PreparedPlanStoreError> {
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
            || !lower_hex(&self.tool_commitment)
            || !lower_hex(&self.action_digest)
            || self.expires_at == 0
            || self
                .payload
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > MAX_PAYLOAD_BYTES)
            || matches!(
                self.state,
                PreparedPlanStateV1::Ready
                    | PreparedPlanStateV1::Claimed { .. }
                    | PreparedPlanStateV1::Consumed { .. }
            ) != self.payload.is_some()
        {
            return Err(PreparedPlanStoreError::InvalidRecord);
        }
        Ok(())
    }
}

/// File-backed store with process-safe compare-and-swap transitions.
pub struct PreparedPlanStore {
    directory: PathBuf,
    database: PathBuf,
    lock: File,
}

impl PreparedPlanStore {
    pub fn open(profile_state_root: &Path) -> Result<Self, PreparedPlanStoreError> {
        let directory = profile_state_root.join("opentofu-prepared-plans-v1");
        if !directory.exists() {
            fs::create_dir(&directory).map_err(|_| PreparedPlanStoreError::Storage)?;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .map_err(|_| PreparedPlanStoreError::Storage)?;
        }
        let metadata =
            fs::symlink_metadata(&directory).map_err(|_| PreparedPlanStoreError::Storage)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(PreparedPlanStoreError::Storage);
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(directory.join("store.lock"))
            .map_err(|_| PreparedPlanStoreError::Storage)?;
        Ok(Self {
            database: directory.join("records.json"),
            directory,
            lock,
        })
    }

    pub fn generate_token() -> Result<String, PreparedPlanStoreError> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| PreparedPlanStoreError::Storage)?;
        Ok(format!(
            "pplan_{}",
            Base64UrlUnpadded::encode_string(&bytes)
        ))
    }

    pub fn reserve(&self, record: PreparedPlanRecordV1) -> Result<(), PreparedPlanStoreError> {
        self.mutate(|database| {
            if database.records.len() >= MAX_RECORDS
                || database.records.contains_key(&record.token_hash)
            {
                return Err(PreparedPlanStoreError::Conflict);
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
    ) -> Result<PreparedPlanRecordV1, PreparedPlanStoreError> {
        if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
            return Err(PreparedPlanStoreError::InvalidRecord);
        }
        self.mutate(|database| {
            let record = database
                .records
                .get_mut(&token_hash(token))
                .ok_or(PreparedPlanStoreError::NotFound)?;
            if record.preflight_operation_id != operation_id {
                return Err(PreparedPlanStoreError::Conflict);
            }
            match record.state {
                PreparedPlanStateV1::Reserved => {
                    record.state = PreparedPlanStateV1::Ready;
                    record.action_digest = hex::encode(action_digest);
                    record.payload = Some(payload);
                }
                PreparedPlanStateV1::Ready
                    if record.payload.as_deref() == Some(&payload)
                        && record.action_digest == hex::encode(action_digest) => {}
                _ => return Err(PreparedPlanStoreError::Conflict),
            }
            Ok(record.clone())
        })
    }

    pub fn deny_reserved(
        &self,
        token: &str,
        operation_id: &str,
    ) -> Result<PreparedPlanRecordV1, PreparedPlanStoreError> {
        self.mutate(|database| {
            let record = database
                .records
                .get_mut(&token_hash(token))
                .ok_or(PreparedPlanStoreError::NotFound)?;
            if record.preflight_operation_id != operation_id {
                return Err(PreparedPlanStoreError::Conflict);
            }
            match record.state {
                PreparedPlanStateV1::Reserved => {
                    record.state = PreparedPlanStateV1::Expired;
                    record.payload = None;
                }
                PreparedPlanStateV1::Expired => {}
                _ => return Err(PreparedPlanStoreError::Conflict),
            }
            Ok(record.clone())
        })
    }

    /// Invalidates the unique reservation owned by a plan operation when a
    /// crash occurred before the common journal stored the sealed command.
    pub fn deny_reserved_by_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<PreparedPlanRecordV1>, PreparedPlanStoreError> {
        if !token_text(operation_id, 128) {
            return Err(PreparedPlanStoreError::InvalidRecord);
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
                    Err(PreparedPlanStoreError::InvalidRecord)
                };
            };
            let record = database
                .records
                .get_mut(key)
                .ok_or(PreparedPlanStoreError::InvalidRecord)?;
            match record.state {
                PreparedPlanStateV1::Reserved => {
                    record.state = PreparedPlanStateV1::Expired;
                    record.payload = None;
                }
                PreparedPlanStateV1::Expired => {}
                _ => return Err(PreparedPlanStoreError::Conflict),
            }
            Ok(Some(record.clone()))
        })
    }

    pub fn load_ready(
        &self,
        token: &str,
        now: u64,
    ) -> Result<PreparedPlanRecordV1, PreparedPlanStoreError> {
        self.mutate(|database| {
            let record = database
                .records
                .get_mut(&token_hash(token))
                .ok_or(PreparedPlanStoreError::NotFound)?;
            if now > record.expires_at && matches!(record.state, PreparedPlanStateV1::Ready) {
                record.state = PreparedPlanStateV1::Expired;
                record.payload = None;
                return Err(PreparedPlanStoreError::Expired);
            }
            if !matches!(record.state, PreparedPlanStateV1::Ready) {
                return Err(PreparedPlanStoreError::Conflict);
            }
            Ok(record.clone())
        })
    }

    pub fn claim(
        &self,
        token: &str,
        operation_id: &str,
        now: u64,
    ) -> Result<PreparedPlanRecordV1, PreparedPlanStoreError> {
        self.mutate(|database| {
            let record = database
                .records
                .get_mut(&token_hash(token))
                .ok_or(PreparedPlanStoreError::NotFound)?;
            if now > record.expires_at {
                record.state = PreparedPlanStateV1::Expired;
                record.payload = None;
                return Err(PreparedPlanStoreError::Expired);
            }
            match &record.state {
                PreparedPlanStateV1::Ready => {
                    record.state = PreparedPlanStateV1::Claimed {
                        operation_id: operation_id.into(),
                    };
                }
                PreparedPlanStateV1::Claimed {
                    operation_id: existing,
                } if existing == operation_id => {}
                _ => return Err(PreparedPlanStoreError::Conflict),
            }
            Ok(record.clone())
        })
    }

    pub fn release_claim(
        &self,
        token: &str,
        operation_id: &str,
    ) -> Result<PreparedPlanRecordV1, PreparedPlanStoreError> {
        self.mutate(|database| {
            let record = database
                .records
                .get_mut(&token_hash(token))
                .ok_or(PreparedPlanStoreError::NotFound)?;
            match &record.state {
                PreparedPlanStateV1::Claimed {
                    operation_id: existing,
                } if existing == operation_id => record.state = PreparedPlanStateV1::Ready,
                PreparedPlanStateV1::Ready => {}
                _ => return Err(PreparedPlanStoreError::Conflict),
            }
            Ok(record.clone())
        })
    }

    /// Releases the unique apply claim owned by an operation when the opaque
    /// token never reached the common journal.
    pub fn release_claim_by_operation(
        &self,
        operation_id: &str,
    ) -> Result<Option<PreparedPlanRecordV1>, PreparedPlanStoreError> {
        if !token_text(operation_id, 128) {
            return Err(PreparedPlanStoreError::InvalidRecord);
        }
        self.mutate(|database| {
            let keys = database
                .records
                .iter()
                .filter(|(_, record)| {
                    matches!(
                        &record.state,
                        PreparedPlanStateV1::Claimed {
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
                    Err(PreparedPlanStoreError::InvalidRecord)
                };
            };
            let record = database
                .records
                .get_mut(key)
                .ok_or(PreparedPlanStoreError::InvalidRecord)?;
            record.state = PreparedPlanStateV1::Ready;
            Ok(Some(record.clone()))
        })
    }

    pub fn consume(
        &self,
        token: &str,
        operation_id: &str,
    ) -> Result<PreparedPlanRecordV1, PreparedPlanStoreError> {
        self.mutate(|database| {
            let record = database
                .records
                .get_mut(&token_hash(token))
                .ok_or(PreparedPlanStoreError::NotFound)?;
            match &record.state {
                PreparedPlanStateV1::Claimed {
                    operation_id: existing,
                } if existing == operation_id => {
                    record.state = PreparedPlanStateV1::Consumed {
                        operation_id: operation_id.into(),
                    };
                }
                PreparedPlanStateV1::Consumed {
                    operation_id: existing,
                } if existing == operation_id => {}
                _ => return Err(PreparedPlanStoreError::Conflict),
            }
            Ok(record.clone())
        })
    }

    fn mutate<T>(
        &self,
        action: impl FnOnce(&mut PreparedPlanDatabaseV1) -> Result<T, PreparedPlanStoreError>,
    ) -> Result<T, PreparedPlanStoreError> {
        flock(&self.lock, FlockOperation::LockExclusive)
            .map_err(|_| PreparedPlanStoreError::Storage)?;
        let result = (|| {
            let mut database = self.read()?;
            let value = action(&mut database)?;
            self.write(&database)?;
            Ok(value)
        })();
        let _ = flock(&self.lock, FlockOperation::Unlock);
        result
    }

    fn read(&self) -> Result<PreparedPlanDatabaseV1, PreparedPlanStoreError> {
        if !self.database.exists() {
            return Ok(PreparedPlanDatabaseV1 {
                schema: SCHEMA.into(),
                records: BTreeMap::new(),
            });
        }
        let mut file = File::open(&self.database).map_err(|_| PreparedPlanStoreError::Storage)?;
        let length = file
            .metadata()
            .map_err(|_| PreparedPlanStoreError::Storage)?
            .len();
        if length == 0 || length > MAX_DATABASE_BYTES as u64 {
            return Err(PreparedPlanStoreError::Storage);
        }
        let capacity = usize::try_from(length).map_err(|_| PreparedPlanStoreError::Storage)?;
        let mut bytes = Vec::with_capacity(capacity);
        std::io::Read::by_ref(&mut file)
            .take((MAX_DATABASE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| PreparedPlanStoreError::Storage)?;
        decode_database(&bytes)
    }

    fn write(&self, database: &PreparedPlanDatabaseV1) -> Result<(), PreparedPlanStoreError> {
        database.validate()?;
        let bytes = serde_json_canonicalizer::to_vec(database)
            .map_err(|_| PreparedPlanStoreError::Storage)?;
        if bytes.len() > MAX_DATABASE_BYTES {
            return Err(PreparedPlanStoreError::Capacity);
        }
        let mut temp =
            NamedTempFile::new_in(&self.directory).map_err(|_| PreparedPlanStoreError::Storage)?;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| PreparedPlanStoreError::Storage)?;
        temp.write_all(&bytes)
            .and_then(|()| temp.as_file().sync_all())
            .map_err(|_| PreparedPlanStoreError::Storage)?;
        temp.persist(&self.database)
            .map_err(|_| PreparedPlanStoreError::Storage)?;
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| PreparedPlanStoreError::Storage)
    }
}

fn decode_database(bytes: &[u8]) -> Result<PreparedPlanDatabaseV1, PreparedPlanStoreError> {
    if bytes.is_empty() || bytes.len() > MAX_DATABASE_BYTES {
        return Err(PreparedPlanStoreError::Storage);
    }
    let database: PreparedPlanDatabaseV1 =
        serde_json::from_slice(bytes).map_err(|_| PreparedPlanStoreError::Storage)?;
    database.validate()?;
    if serde_json_canonicalizer::to_vec(&database).map_err(|_| PreparedPlanStoreError::Storage)?
        != bytes
    {
        return Err(PreparedPlanStoreError::Storage);
    }
    Ok(database)
}

#[cfg(feature = "qualification")]
pub(crate) fn decode_qualification_records(
    bytes: &[u8],
) -> Result<Vec<PreparedPlanRecordV1>, PreparedPlanStoreError> {
    Ok(decode_database(bytes)?.records.into_values().collect())
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreparedPlanDatabaseV1 {
    schema: String,
    records: BTreeMap<String, PreparedPlanRecordV1>,
}

impl PreparedPlanDatabaseV1 {
    fn validate(&self) -> Result<(), PreparedPlanStoreError> {
        if self.schema != SCHEMA || self.records.len() > MAX_RECORDS {
            return Err(PreparedPlanStoreError::InvalidRecord);
        }
        self.records
            .iter()
            .try_for_each(|(key, record)| record.validate(key))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PreparedPlanStoreError {
    #[error("prepared plan storage is unavailable")]
    Storage,
    #[error("prepared plan record is invalid")]
    InvalidRecord,
    #[error("prepared plan store is at capacity")]
    Capacity,
    #[error("prepared plan does not exist")]
    NotFound,
    #[error("prepared plan is expired")]
    Expired,
    #[error("prepared plan state conflicts")]
    Conflict,
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn valid_token(value: &str) -> bool {
    value.len() == 49
        && value.starts_with("pplan_")
        && value[6..]
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
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(token: &str) -> PreparedPlanRecordV1 {
        PreparedPlanRecordV1::reserved(
            token,
            "operation-1",
            "did:key:owner",
            "connection-1",
            1,
            &[1; 32],
            &[2; 32],
            &[3; 32],
            &[4; 32],
            &[5; 32],
            &[6; 32],
            500,
        )
        .unwrap()
    }

    #[test]
    fn restart_preserves_ready_claim_and_consumption() {
        let root = tempfile::tempdir().unwrap();
        let store = PreparedPlanStore::open(root.path()).unwrap();
        let token = PreparedPlanStore::generate_token().unwrap();
        store.reserve(record(&token)).unwrap();
        store
            .mark_ready(&token, "operation-1", &[7; 32], b"payload".to_vec())
            .unwrap();
        drop(store);
        let reopened = PreparedPlanStore::open(root.path()).unwrap();
        reopened.claim(&token, "apply-1", 100).unwrap();
        reopened.consume(&token, "apply-1").unwrap();
        assert!(matches!(
            reopened
                .mutate(|database| Ok(database.records[&token_hash(&token)].clone()))
                .unwrap()
                .state(),
            PreparedPlanStateV1::Consumed { .. }
        ));
        #[cfg(feature = "qualification")]
        {
            let bytes = fs::read(&reopened.database).unwrap();
            let decoded = decode_qualification_records(&bytes).unwrap();
            assert_eq!(decoded.len(), 1);
            assert_eq!(decoded[0].token_hash(), token_hash(&token));
            let mut noncanonical = bytes;
            noncanonical.push(b'\n');
            assert!(decode_qualification_records(&noncanonical).is_err());
        }
    }

    #[test]
    fn operation_identity_releases_pre_command_reservation_and_claim() {
        let root = tempfile::tempdir().unwrap();
        let store = PreparedPlanStore::open(root.path()).unwrap();
        let reserved_token = PreparedPlanStore::generate_token().unwrap();
        store.reserve(record(&reserved_token)).unwrap();
        assert!(matches!(
            store
                .deny_reserved_by_operation("operation-1")
                .unwrap()
                .unwrap()
                .state(),
            PreparedPlanStateV1::Expired
        ));

        let claimed_token = PreparedPlanStore::generate_token().unwrap();
        store.reserve(record(&claimed_token)).unwrap();
        store
            .mark_ready(&claimed_token, "operation-1", &[7; 32], b"payload".to_vec())
            .unwrap();
        store.claim(&claimed_token, "apply-1", 100).unwrap();
        assert!(matches!(
            store
                .release_claim_by_operation("apply-1")
                .unwrap()
                .unwrap()
                .state(),
            PreparedPlanStateV1::Ready
        ));
        assert!(
            store
                .release_claim_by_operation("apply-1")
                .unwrap()
                .is_none()
        );
    }
}
