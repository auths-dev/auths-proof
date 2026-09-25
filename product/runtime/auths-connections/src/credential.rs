use crate::{ConnectionBinding, ConnectionId};
use async_trait::async_trait;
use minicbor::{Decoder, Encoder, encode::Write as CborWrite};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    fmt,
    fs::{self, File},
    io::Write as _,
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::{Mutex, RwLock},
    time::Instant,
};
use subtle::ConstantTimeEq as _;
use tempfile::NamedTempFile;
use thiserror::Error;
use zeroize::Zeroizing;

const CREDENTIAL_DATABASE_VERSION: u8 = 1;
const DEFAULT_MAXIMUM_PERSISTENT_ENTRIES: usize = 10_000;
const DEFAULT_MAXIMUM_PERSISTENT_BYTES: usize = 268_435_456;
const MAXIMUM_SECRET_BYTES: usize = 65_536;

/// Privileged secret bytes accepted only by connection administration.
///
/// The bytes are zeroized when the value is dropped.
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Wraps a bounded non-empty secret.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialStoreError::InvalidSecret`] outside 1-65,536 bytes.
    /// Rejected bytes are zeroized before the error is returned.
    pub fn new(bytes: Vec<u8>) -> Result<Self, CredentialStoreError> {
        let bytes = Zeroizing::new(bytes);
        if !valid_secret_length(bytes.len()) {
            return Err(CredentialStoreError::InvalidSecret);
        }
        Ok(Self(bytes))
    }

    fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

fn valid_secret_length(length: usize) -> bool {
    (1..=MAXIMUM_SECRET_BYTES).contains(&length)
}

/// Commitment to an internal, caller-unresolvable credential reference.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CredentialReferenceCommitment([u8; 32]);

impl CredentialReferenceCommitment {
    /// Returns the fixed-width commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CredentialReferenceCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialReferenceCommitment([REDACTED])")
    }
}

/// Deadline-bound lease visible only to a provider adapter.
///
/// The leased copy is zeroized when the lease is dropped.
pub struct StoredSecretLease {
    bytes: Zeroizing<Vec<u8>>,
    deadline: Instant,
}

impl StoredSecretLease {
    /// Borrows the secret before its deadline.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialStoreError::Expired`] after the lease deadline.
    pub fn expose(&self, now: Instant) -> Result<&[u8], CredentialStoreError> {
        if now > self.deadline {
            return Err(CredentialStoreError::Expired);
        }
        Ok(self.bytes.as_slice())
    }
}

impl fmt::Debug for StoredSecretLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StoredSecretLease([REDACTED])")
    }
}

/// Generic secret-store mechanism. It knows identity and generation only.
#[async_trait]
pub trait ConnectionCredentialStore: Send + Sync {
    /// Installs the first credential generation.
    async fn install(
        &self,
        connection_id: &ConnectionId,
        generation: NonZeroU64,
        secret: SecretBytes,
    ) -> Result<CredentialReferenceCommitment, CredentialStoreError>;

    /// Leases the exact secret generation named by a sealed binding.
    async fn lease_secret(
        &self,
        binding: &ConnectionBinding,
        deadline: Instant,
    ) -> Result<StoredSecretLease, CredentialStoreError>;

    /// Atomically installs a successor without discarding the old generation.
    async fn replace(
        &self,
        connection_id: &ConnectionId,
        old_generation: NonZeroU64,
        new_generation: NonZeroU64,
        secret: SecretBytes,
    ) -> Result<CredentialReferenceCommitment, CredentialStoreError>;

    /// Revokes one exact generation.
    async fn revoke(
        &self,
        connection_id: &ConnectionId,
        generation: NonZeroU64,
    ) -> Result<(), CredentialStoreError>;
}

/// Bounded in-memory conformance implementation.
pub struct InMemoryCredentialStore {
    entries: RwLock<BTreeMap<(String, u64), StoredSecret>>,
    maximum_entries: usize,
    maximum_bytes: usize,
}

/// One retained generation. Every clone, including the copy-on-write map in
/// [`PersistentCredentialStore`], zeroizes its bytes when dropped.
#[derive(Clone)]
struct StoredSecret {
    bytes: Zeroizing<Vec<u8>>,
    commitment: CredentialReferenceCommitment,
}

impl StoredSecret {
    /// Whether this entry already holds exactly `secret` under `commitment`.
    ///
    /// Both comparisons are constant-time and combined without
    /// short-circuiting, so an idempotent retry reveals only the verdict.
    fn holds(&self, commitment: &CredentialReferenceCommitment, secret: &[u8]) -> bool {
        bool::from(
            self.commitment.as_bytes().ct_eq(commitment.as_bytes())
                & self.bytes.as_slice().ct_eq(secret),
        )
    }
}

impl InMemoryCredentialStore {
    /// Creates a bounded in-memory store.
    ///
    /// # Errors
    ///
    /// Rejects zero entry or byte capacity.
    pub fn new(maximum_entries: usize, maximum_bytes: usize) -> Result<Self, CredentialStoreError> {
        if maximum_entries == 0 || maximum_bytes == 0 {
            return Err(CredentialStoreError::InvalidCapacity);
        }
        Ok(Self {
            entries: RwLock::new(BTreeMap::new()),
            maximum_entries,
            maximum_bytes,
        })
    }

    fn total_bytes(entries: &BTreeMap<(String, u64), StoredSecret>) -> usize {
        entries.values().map(|entry| entry.bytes.len()).sum()
    }
}

#[async_trait]
impl ConnectionCredentialStore for InMemoryCredentialStore {
    async fn install(
        &self,
        connection_id: &ConnectionId,
        generation: NonZeroU64,
        secret: SecretBytes,
    ) -> Result<CredentialReferenceCommitment, CredentialStoreError> {
        let key = (connection_id.as_str().to_owned(), generation.get());
        let commitment = credential_commitment(connection_id, generation, secret.expose());
        let mut entries = self
            .entries
            .write()
            .map_err(|_| CredentialStoreError::Unavailable)?;
        if entries.contains_key(&key) {
            return Err(CredentialStoreError::Conflict);
        }
        if entries.len() >= self.maximum_entries
            || Self::total_bytes(&entries)
                .checked_add(secret.expose().len())
                .is_none_or(|value| value > self.maximum_bytes)
        {
            return Err(CredentialStoreError::Capacity);
        }
        entries.insert(
            key,
            StoredSecret {
                bytes: Zeroizing::new(secret.expose().to_vec()),
                commitment,
            },
        );
        Ok(commitment)
    }

    async fn lease_secret(
        &self,
        binding: &ConnectionBinding,
        deadline: Instant,
    ) -> Result<StoredSecretLease, CredentialStoreError> {
        let key = (
            binding.connection_id().as_str().to_owned(),
            binding.generation().get(),
        );
        let entries = self
            .entries
            .read()
            .map_err(|_| CredentialStoreError::Unavailable)?;
        let stored = entries.get(&key).ok_or(CredentialStoreError::Unavailable)?;
        if stored.commitment.as_bytes() != binding.credential_reference_commitment() {
            return Err(CredentialStoreError::Substitution);
        }
        Ok(StoredSecretLease {
            bytes: stored.bytes.clone(),
            deadline,
        })
    }

    async fn replace(
        &self,
        connection_id: &ConnectionId,
        old_generation: NonZeroU64,
        new_generation: NonZeroU64,
        secret: SecretBytes,
    ) -> Result<CredentialReferenceCommitment, CredentialStoreError> {
        if new_generation.get()
            != old_generation
                .get()
                .checked_add(1)
                .ok_or(CredentialStoreError::Conflict)?
        {
            return Err(CredentialStoreError::Conflict);
        }
        let old_key = (connection_id.as_str().to_owned(), old_generation.get());
        let new_key = (connection_id.as_str().to_owned(), new_generation.get());
        let commitment = credential_commitment(connection_id, new_generation, secret.expose());
        let mut entries = self
            .entries
            .write()
            .map_err(|_| CredentialStoreError::Unavailable)?;
        if !entries.contains_key(&old_key) || entries.contains_key(&new_key) {
            return Err(CredentialStoreError::Conflict);
        }
        if entries.len() >= self.maximum_entries
            || Self::total_bytes(&entries)
                .checked_add(secret.expose().len())
                .is_none_or(|value| value > self.maximum_bytes)
        {
            return Err(CredentialStoreError::Capacity);
        }
        entries.insert(
            new_key,
            StoredSecret {
                bytes: Zeroizing::new(secret.expose().to_vec()),
                commitment,
            },
        );
        Ok(commitment)
    }

    async fn revoke(
        &self,
        connection_id: &ConnectionId,
        generation: NonZeroU64,
    ) -> Result<(), CredentialStoreError> {
        let key = (connection_id.as_str().to_owned(), generation.get());
        let mut entries = self
            .entries
            .write()
            .map_err(|_| CredentialStoreError::Unavailable)?;
        entries
            .remove(&key)
            .ok_or(CredentialStoreError::Unavailable)?;
        Ok(())
    }
}

/// Crash-persistent, owner-only implementation of
/// `auths.connection-credential-store/1`.
///
/// The database is intentionally opaque to connection/profile code. It stores
/// only internal connection IDs, generations, commitment-bound secret bytes,
/// and no provider/account/profile metadata. Deployments that require an HSM,
/// OS keychain, or external secret manager can implement the same mechanism
/// contract without changing callers.
pub struct PersistentCredentialStore {
    path: PathBuf,
    entries: Mutex<BTreeMap<(String, u64), StoredSecret>>,
    maximum_entries: usize,
    maximum_bytes: usize,
}

impl PersistentCredentialStore {
    /// Opens or creates one owner-controlled credential database.
    ///
    /// # Errors
    ///
    /// Existing symlinks, non-regular files, permissive POSIX modes,
    /// malformed/noncanonical bytes, duplicate entries, or exceeded limits are
    /// rejected without replacing state.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, CredentialStoreError> {
        Self::open_with_limits(
            path,
            DEFAULT_MAXIMUM_PERSISTENT_ENTRIES,
            DEFAULT_MAXIMUM_PERSISTENT_BYTES,
        )
    }

    /// Opens a persistent store with explicit conformance-test bounds.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialStoreError`] for invalid capacities, insecure file
    /// metadata, malformed persisted bytes, or unavailable storage.
    pub fn open_with_limits(
        path: impl Into<PathBuf>,
        maximum_entries: usize,
        maximum_bytes: usize,
    ) -> Result<Self, CredentialStoreError> {
        let path = path.into();
        if maximum_entries == 0
            || maximum_bytes == 0
            || path.as_os_str().is_empty()
            || path.parent().is_none()
        {
            return Err(CredentialStoreError::InvalidCapacity);
        }
        let parent = path.parent().ok_or(CredentialStoreError::InvalidCapacity)?;
        validate_parent(parent)?;
        let entries = if path.exists() {
            validate_secret_file(&path, maximum_bytes)?;
            let bytes =
                Zeroizing::new(fs::read(&path).map_err(|_| CredentialStoreError::Unavailable)?);
            decode_persistent_entries(&bytes, maximum_entries, maximum_bytes)?
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            path,
            entries: Mutex::new(entries),
            maximum_entries,
            maximum_bytes,
        })
    }

    fn mutate<T>(
        &self,
        mutation: impl FnOnce(
            &mut BTreeMap<(String, u64), StoredSecret>,
        ) -> Result<T, CredentialStoreError>,
    ) -> Result<T, CredentialStoreError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| CredentialStoreError::Unavailable)?;
        let mut next = entries.clone();
        let result = mutation(&mut next)?;
        persist_entries(&self.path, &next, self.maximum_bytes)?;
        *entries = next;
        Ok(result)
    }

    fn total_bytes(entries: &BTreeMap<(String, u64), StoredSecret>) -> usize {
        entries.values().map(|entry| entry.bytes.len()).sum()
    }

    /// Returns the commitment for one retained credential generation without
    /// exposing or leasing its bytes.
    ///
    /// Recovery uses this only after authenticating a principal-bound
    /// operation and matching its sealed connection identity. Missing entries
    /// remain unavailable, including generations removed by emergency
    /// provider revocation.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialStoreError::Unavailable`] when the store cannot be
    /// read or the exact retained generation is absent.
    pub fn retained_commitment(
        &self,
        connection_id: &ConnectionId,
        generation: NonZeroU64,
    ) -> Result<CredentialReferenceCommitment, CredentialStoreError> {
        self.entries
            .lock()
            .map_err(|_| CredentialStoreError::Unavailable)?
            .get(&(connection_id.as_str().to_owned(), generation.get()))
            .map(|entry| entry.commitment)
            .ok_or(CredentialStoreError::Unavailable)
    }

    /// Carries the same protected credential into a generation created by a
    /// metadata/state authorization change, without exposing its bytes to the
    /// administration router.
    ///
    /// The prior generation is retained for unresolved operations. This is the
    /// persistent mechanism's internal implementation of an atomic
    /// `replace` using the existing secret value.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialStoreError`] when the transition is not the next
    /// generation, the prior secret is absent, capacity is exhausted, or the
    /// durable update fails.
    pub fn advance_generation(
        &self,
        connection_id: &ConnectionId,
        old_generation: NonZeroU64,
        new_generation: NonZeroU64,
    ) -> Result<CredentialReferenceCommitment, CredentialStoreError> {
        if new_generation.get()
            != old_generation
                .get()
                .checked_add(1)
                .ok_or(CredentialStoreError::Conflict)?
        {
            return Err(CredentialStoreError::Conflict);
        }
        let old_key = (connection_id.as_str().to_owned(), old_generation.get());
        let new_key = (connection_id.as_str().to_owned(), new_generation.get());
        self.mutate(|entries| {
            let old = entries
                .get(&old_key)
                .ok_or(CredentialStoreError::Unavailable)?;
            let secret = old.bytes.clone();
            let commitment = credential_commitment(connection_id, new_generation, &secret);
            if let Some(existing) = entries.get(&new_key) {
                return if existing.holds(&commitment, &secret) {
                    Ok(commitment)
                } else {
                    Err(CredentialStoreError::Conflict)
                };
            }
            if entries.len() >= self.maximum_entries {
                return Err(CredentialStoreError::Capacity);
            }
            let next = StoredSecret {
                bytes: secret,
                commitment,
            };
            if Self::total_bytes(entries)
                .checked_add(next.bytes.len())
                .is_none_or(|value| value > self.maximum_bytes)
            {
                return Err(CredentialStoreError::Capacity);
            }
            entries.insert(new_key, next);
            Ok(commitment)
        })
    }
}

#[async_trait]
impl ConnectionCredentialStore for PersistentCredentialStore {
    async fn install(
        &self,
        connection_id: &ConnectionId,
        generation: NonZeroU64,
        secret: SecretBytes,
    ) -> Result<CredentialReferenceCommitment, CredentialStoreError> {
        let key = (connection_id.as_str().to_owned(), generation.get());
        let commitment = credential_commitment(connection_id, generation, secret.expose());
        self.mutate(|entries| {
            if entries.contains_key(&key) {
                return Err(CredentialStoreError::Conflict);
            }
            if entries.len() >= self.maximum_entries
                || Self::total_bytes(entries)
                    .checked_add(secret.expose().len())
                    .is_none_or(|value| value > self.maximum_bytes)
            {
                return Err(CredentialStoreError::Capacity);
            }
            entries.insert(
                key,
                StoredSecret {
                    bytes: Zeroizing::new(secret.expose().to_vec()),
                    commitment,
                },
            );
            Ok(commitment)
        })
    }

    async fn lease_secret(
        &self,
        binding: &ConnectionBinding,
        deadline: Instant,
    ) -> Result<StoredSecretLease, CredentialStoreError> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| CredentialStoreError::Unavailable)?;
        let stored = entries
            .get(&(
                binding.connection_id().as_str().to_owned(),
                binding.generation().get(),
            ))
            .ok_or(CredentialStoreError::Unavailable)?;
        if stored.commitment.as_bytes() != binding.credential_reference_commitment() {
            return Err(CredentialStoreError::Substitution);
        }
        Ok(StoredSecretLease {
            bytes: stored.bytes.clone(),
            deadline,
        })
    }

    async fn replace(
        &self,
        connection_id: &ConnectionId,
        old_generation: NonZeroU64,
        new_generation: NonZeroU64,
        secret: SecretBytes,
    ) -> Result<CredentialReferenceCommitment, CredentialStoreError> {
        if new_generation.get()
            != old_generation
                .get()
                .checked_add(1)
                .ok_or(CredentialStoreError::Conflict)?
        {
            return Err(CredentialStoreError::Conflict);
        }
        let old_key = (connection_id.as_str().to_owned(), old_generation.get());
        let new_key = (connection_id.as_str().to_owned(), new_generation.get());
        let commitment = credential_commitment(connection_id, new_generation, secret.expose());
        self.mutate(|entries| {
            if !entries.contains_key(&old_key) {
                return Err(CredentialStoreError::Conflict);
            }
            if let Some(existing) = entries.get(&new_key) {
                return if existing.holds(&commitment, secret.expose()) {
                    Ok(commitment)
                } else {
                    Err(CredentialStoreError::Conflict)
                };
            }
            if entries.len() >= self.maximum_entries
                || Self::total_bytes(entries)
                    .checked_add(secret.expose().len())
                    .is_none_or(|value| value > self.maximum_bytes)
            {
                return Err(CredentialStoreError::Capacity);
            }
            entries.insert(
                new_key,
                StoredSecret {
                    bytes: Zeroizing::new(secret.expose().to_vec()),
                    commitment,
                },
            );
            Ok(commitment)
        })
    }

    async fn revoke(
        &self,
        connection_id: &ConnectionId,
        generation: NonZeroU64,
    ) -> Result<(), CredentialStoreError> {
        let key = (connection_id.as_str().to_owned(), generation.get());
        self.mutate(|entries| {
            // Dropping the removed entry zeroizes its secret.
            entries
                .remove(&key)
                .ok_or(CredentialStoreError::Unavailable)?;
            Ok(())
        })
    }
}

fn validate_parent(path: &Path) -> Result<(), CredentialStoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| CredentialStoreError::Unavailable)?;
    if !metadata.file_type().is_dir() {
        return Err(CredentialStoreError::Unavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CredentialStoreError::UnsafeStorage);
        }
    }
    Ok(())
}

fn validate_secret_file(path: &Path, maximum_bytes: usize) -> Result<(), CredentialStoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| CredentialStoreError::Unavailable)?;
    if !metadata.file_type().is_file()
        || usize::try_from(metadata.len()).map_or(true, |length| length > maximum_bytes)
    {
        return Err(CredentialStoreError::UnsafeStorage);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CredentialStoreError::UnsafeStorage);
        }
    }
    Ok(())
}

fn persist_entries(
    path: &Path,
    entries: &BTreeMap<(String, u64), StoredSecret>,
    maximum_bytes: usize,
) -> Result<(), CredentialStoreError> {
    let bytes = encode_persistent_entries(entries)?;
    if bytes.len() > maximum_bytes {
        return Err(CredentialStoreError::Capacity);
    }
    let parent = path.parent().ok_or(CredentialStoreError::UnsafeStorage)?;
    validate_parent(parent)?;
    let mut temporary =
        NamedTempFile::new_in(parent).map_err(|_| CredentialStoreError::Unavailable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| CredentialStoreError::Unavailable)?;
    }
    temporary
        .write_all(&bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| CredentialStoreError::Unavailable)?;
    temporary
        .persist(path)
        .map_err(|_| CredentialStoreError::Unavailable)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| CredentialStoreError::Unavailable)
}

/// Encodes the database into a buffer sized exactly by a counting pass, so
/// the buffer never reallocates and strands an unwiped partial copy of the
/// secrets it already holds.
fn encode_persistent_entries(
    entries: &BTreeMap<(String, u64), StoredSecret>,
) -> Result<Zeroizing<Vec<u8>>, CredentialStoreError> {
    let mut length = EncodedLength(0);
    write_persistent_entries(&mut length, entries)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length.0)
        .map_err(|_| CredentialStoreError::Unavailable)?;
    write_persistent_entries(&mut *bytes, entries)?;
    Ok(bytes)
}

fn write_persistent_entries<W: CborWrite>(
    writer: W,
    entries: &BTreeMap<(String, u64), StoredSecret>,
) -> Result<(), CredentialStoreError> {
    let mut encoder = Encoder::new(writer);
    encoder
        .map(2)
        .and_then(|value| value.u8(1))
        .and_then(|value| value.u8(CREDENTIAL_DATABASE_VERSION))
        .and_then(|value| value.u8(2))
        .and_then(|value| value.array(entries.len() as u64))
        .map_err(|_| CredentialStoreError::Unavailable)?;
    for ((connection_id, generation), stored) in entries {
        encoder
            .array(4)
            .and_then(|value| value.str(connection_id))
            .and_then(|value| value.u64(*generation))
            .and_then(|value| value.bytes(stored.commitment.as_bytes()))
            .and_then(|value| value.bytes(stored.bytes.as_slice()))
            .map_err(|_| CredentialStoreError::Unavailable)?;
    }
    Ok(())
}

/// CBOR sink that counts bytes without retaining them.
struct EncodedLength(usize);

impl CborWrite for EncodedLength {
    type Error = Infallible;

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(())
    }
}

fn decode_persistent_entries(
    bytes: &[u8],
    maximum_entries: usize,
    maximum_bytes: usize,
) -> Result<BTreeMap<(String, u64), StoredSecret>, CredentialStoreError> {
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(CredentialStoreError::UnsafeStorage);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder
        .map()
        .map_err(|_| CredentialStoreError::UnsafeStorage)?
        != Some(2)
        || decoder
            .u8()
            .map_err(|_| CredentialStoreError::UnsafeStorage)?
            != 1
        || decoder
            .u8()
            .map_err(|_| CredentialStoreError::UnsafeStorage)?
            != CREDENTIAL_DATABASE_VERSION
        || decoder
            .u8()
            .map_err(|_| CredentialStoreError::UnsafeStorage)?
            != 2
    {
        return Err(CredentialStoreError::UnsafeStorage);
    }
    let count = decoder
        .array()
        .map_err(|_| CredentialStoreError::UnsafeStorage)?
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(CredentialStoreError::UnsafeStorage)?;
    if count > maximum_entries {
        return Err(CredentialStoreError::Capacity);
    }
    let mut entries = BTreeMap::new();
    let mut total = 0_usize;
    for _ in 0..count {
        if decoder
            .array()
            .map_err(|_| CredentialStoreError::UnsafeStorage)?
            != Some(4)
        {
            return Err(CredentialStoreError::UnsafeStorage);
        }
        let id_text = decoder
            .str()
            .map_err(|_| CredentialStoreError::UnsafeStorage)?;
        let id = ConnectionId::parse(id_text).map_err(|_| CredentialStoreError::UnsafeStorage)?;
        let generation = NonZeroU64::new(
            decoder
                .u64()
                .map_err(|_| CredentialStoreError::UnsafeStorage)?,
        )
        .ok_or(CredentialStoreError::UnsafeStorage)?;
        let commitment: [u8; 32] = decoder
            .bytes()
            .map_err(|_| CredentialStoreError::UnsafeStorage)?
            .try_into()
            .map_err(|_| CredentialStoreError::UnsafeStorage)?;
        let secret = Zeroizing::new(
            decoder
                .bytes()
                .map_err(|_| CredentialStoreError::UnsafeStorage)?
                .to_vec(),
        );
        total = total
            .checked_add(secret.len())
            .ok_or(CredentialStoreError::Capacity)?;
        if total > maximum_bytes || !valid_secret_length(secret.len()) {
            return Err(CredentialStoreError::UnsafeStorage);
        }
        let expected = credential_commitment(&id, generation, &secret);
        if expected.as_bytes() != &commitment
            || entries
                .insert(
                    (id.as_str().to_owned(), generation.get()),
                    StoredSecret {
                        bytes: secret,
                        commitment: expected,
                    },
                )
                .is_some()
        {
            return Err(CredentialStoreError::UnsafeStorage);
        }
    }
    if decoder.position() != bytes.len()
        || !bool::from(encode_persistent_entries(&entries)?.as_slice().ct_eq(bytes))
    {
        return Err(CredentialStoreError::UnsafeStorage);
    }
    Ok(entries)
}

/// Closed credential-store error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum CredentialStoreError {
    /// Secret bytes are empty or exceed 65,536 bytes.
    #[error("invalid credential secret")]
    InvalidSecret,
    /// Configured store capacity is zero.
    #[error("invalid credential-store capacity")]
    InvalidCapacity,
    /// Existing state conflicts with the requested atomic transition.
    #[error("credential generation conflict")]
    Conflict,
    /// Fixed store capacity has been reached.
    #[error("credential-store capacity exhausted")]
    Capacity,
    /// Secret generation is absent, revoked, or inaccessible.
    #[error("credential unavailable")]
    Unavailable,
    /// Credential-reference commitment did not match the sealed binding.
    #[error("credential reference substitution detected")]
    Substitution,
    /// Secret lease deadline elapsed.
    #[error("credential lease expired")]
    Expired,
    /// Persistent storage is a symlink, has unsafe permissions, or is malformed.
    #[error("credential storage is unsafe")]
    UnsafeStorage,
}

fn credential_commitment(
    connection_id: &ConnectionId,
    generation: NonZeroU64,
    secret: &[u8],
) -> CredentialReferenceCommitment {
    let mut digest = Sha256::new();
    digest.update(b"auths.connection-credential-store/1\0");
    digest.update(connection_id.as_str().as_bytes());
    digest.update(generation.get().to_be_bytes());
    digest.update(secret);
    CredentialReferenceCommitment(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::tests::record;

    #[test]
    fn debug_never_exposes_secret_bytes() {
        let secret = SecretBytes::new(b"super-secret".to_vec()).unwrap();
        assert_eq!(format!("{secret:?}"), "SecretBytes([REDACTED])");
    }

    #[test]
    fn credential_commitment_changes_with_generation() {
        let id = ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert_ne!(
            credential_commitment(&id, NonZeroU64::new(1).unwrap(), b"secret"),
            credential_commitment(&id, NonZeroU64::new(2).unwrap(), b"secret")
        );
    }

    #[test]
    fn binding_commitment_substitution_fails_closed() {
        let connection = record();
        let binding = ConnectionBinding {
            provider_kind: connection.provider_kind().clone(),
            alias: connection.alias().clone(),
            connection_id: connection.connection_id().clone(),
            contract: connection.contract().clone(),
            descriptor_schema: connection.descriptor_schema().clone(),
            descriptor: connection.descriptor().to_vec(),
            generation: connection.generation(),
            descriptor_commitment: *connection.descriptor_commitment(),
            account_commitment: *connection.account_commitment(),
            credential_reference_commitment: [9; 32],
        };
        let store = InMemoryCredentialStore::new(4, 1_024).unwrap();
        let install = store.install(
            binding.connection_id(),
            binding.generation(),
            SecretBytes::new(b"secret".to_vec()).unwrap(),
        );
        let lease = async {
            install.await.unwrap();
            store.lease_secret(&binding, Instant::now()).await
        };
        assert_eq!(
            futures_lite_for_tests(lease).unwrap_err(),
            CredentialStoreError::Substitution
        );
    }

    #[test]
    fn persistent_store_reopens_exact_generation_without_exposing_secret() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = directory.path().join("credentials.cbor");
        let connection = record();
        let store = PersistentCredentialStore::open_with_limits(&path, 4, 65_536).unwrap();
        let commitment = futures_lite_for_tests(store.install(
            connection.connection_id(),
            connection.generation(),
            SecretBytes::new(b"super-secret-value".to_vec()).unwrap(),
        ))
        .unwrap();
        drop(store);

        let reopened = PersistentCredentialStore::open_with_limits(&path, 4, 65_536).unwrap();
        let binding = ConnectionBinding {
            provider_kind: connection.provider_kind().clone(),
            alias: connection.alias().clone(),
            connection_id: connection.connection_id().clone(),
            contract: connection.contract().clone(),
            descriptor_schema: connection.descriptor_schema().clone(),
            descriptor: connection.descriptor().to_vec(),
            generation: connection.generation(),
            descriptor_commitment: *connection.descriptor_commitment(),
            account_commitment: *connection.account_commitment(),
            credential_reference_commitment: *commitment.as_bytes(),
        };
        let lease = futures_lite_for_tests(
            reopened.lease_secret(&binding, Instant::now() + std::time::Duration::from_secs(1)),
        )
        .unwrap();
        assert_eq!(lease.expose(Instant::now()).unwrap(), b"super-secret-value");
        assert!(!format!("{lease:?}").contains("super-secret"));
    }

    #[test]
    fn persistent_store_refuses_corrupt_or_permissive_state() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = directory.path().join("credentials.cbor");
        fs::write(&path, b"not canonical cbor").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            PersistentCredentialStore::open_with_limits(&path, 4, 65_536)
                .err()
                .unwrap(),
            CredentialStoreError::UnsafeStorage
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(
                PersistentCredentialStore::open_with_limits(&path, 4, 65_536)
                    .err()
                    .unwrap(),
                CredentialStoreError::UnsafeStorage
            );
        }
    }

    #[test]
    fn stored_secret_holds_only_the_exact_commitment_and_bytes() {
        let id = ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let generation = NonZeroU64::new(1).unwrap();
        let commitment = credential_commitment(&id, generation, b"secret");
        let stored = StoredSecret {
            bytes: Zeroizing::new(b"secret".to_vec()),
            commitment,
        };
        assert!(stored.holds(&commitment, b"secret"));
        assert!(!stored.holds(&commitment, b"secreT"));
        assert!(!stored.holds(&commitment, b"secret-longer"));
        let other = credential_commitment(&id, NonZeroU64::new(2).unwrap(), b"secret");
        assert!(!stored.holds(&other, b"secret"));
    }

    #[test]
    fn persistent_replace_is_idempotent_only_for_the_same_secret() {
        let directory = private_directory();
        let store =
            PersistentCredentialStore::open_with_limits(directory.path().join("c.cbor"), 4, 4_096)
                .unwrap();
        let id = ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let first = NonZeroU64::new(1).unwrap();
        let second = NonZeroU64::new(2).unwrap();
        futures_lite_for_tests(store.install(&id, first, secret(b"secret-one"))).unwrap();
        let rotated =
            futures_lite_for_tests(store.replace(&id, first, second, secret(b"secret-two")))
                .unwrap();

        let repeated =
            futures_lite_for_tests(store.replace(&id, first, second, secret(b"secret-two")));
        assert_eq!(repeated.unwrap(), rotated);
        for conflicting in [b"secret-twO".as_slice(), b"secret-two-longer", b"s"] {
            let refused =
                futures_lite_for_tests(store.replace(&id, first, second, secret(conflicting)));
            assert_eq!(refused.unwrap_err(), CredentialStoreError::Conflict);
        }
        assert_eq!(store.retained_commitment(&id, second).unwrap(), rotated);
    }

    #[test]
    fn advance_generation_is_idempotent_only_for_the_carried_secret() {
        let directory = private_directory();
        let store =
            PersistentCredentialStore::open_with_limits(directory.path().join("c.cbor"), 4, 4_096)
                .unwrap();
        let id = ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let [first, second, third] = [1, 2, 3].map(|value| NonZeroU64::new(value).unwrap());
        futures_lite_for_tests(store.install(&id, first, secret(b"secret-one"))).unwrap();
        let carried = store.advance_generation(&id, first, second).unwrap();
        assert_eq!(
            store.advance_generation(&id, first, second).unwrap(),
            carried
        );

        futures_lite_for_tests(store.replace(&id, second, third, secret(b"secret-three"))).unwrap();
        assert_eq!(
            store.advance_generation(&id, second, third).unwrap_err(),
            CredentialStoreError::Conflict
        );
    }

    #[test]
    fn encoded_database_buffer_is_sized_before_secrets_are_written() {
        let id = ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let mut entries = BTreeMap::new();
        // Secret lengths cross each CBOR byte-string header width. The large
        // secret is encoded first so an unsized buffer would have to grow
        // after it holds secret bytes.
        for (generation, length) in [(1, 65_536), (2, 256), (3, 24), (4, 1)] {
            let generation = NonZeroU64::new(generation).unwrap();
            let bytes = Zeroizing::new(vec![0x5a; length]);
            let commitment = credential_commitment(&id, generation, &bytes);
            entries.insert(
                (id.as_str().to_owned(), generation.get()),
                StoredSecret { bytes, commitment },
            );
        }
        let encoded = encode_persistent_entries(&entries).unwrap();
        assert_eq!(encoded.capacity(), encoded.len());
        assert_eq!(
            decode_persistent_entries(&encoded, 4, 1 << 20)
                .unwrap()
                .len(),
            4
        );
    }

    fn secret(bytes: &[u8]) -> SecretBytes {
        SecretBytes::new(bytes.to_vec()).unwrap()
    }

    fn private_directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        directory
    }

    fn futures_lite_for_tests<F: std::future::Future>(future: F) -> F::Output {
        use std::{
            future::Future,
            pin::pin,
            task::{Context, Poll, Waker},
        };
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        match Future::poll(future.as_mut(), &mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("in-memory credential future unexpectedly pending"),
        }
    }
}
