//! Concrete bounded stores for outer Auths application state.

#![forbid(unsafe_code)]

mod lifecycle;

pub use lifecycle::{
    InMemoryLifecycleStore, LifecycleCapacityRuleV1, LifecycleStoreConfigurationError,
    PersistentLifecycleStore, PostgresLifecycleStore, PostgresPoolConfig, PostgresServerName,
    PostgresStoreConfig, PostgresStoreHealth, PostgresStoreSummary, PostgresTlsConfig,
    SecretConnectionString,
};

use auths_model::{ActionId, BudgetCeiling, ReceiptId};
use auths_proof_exchange_model::ChallengeNonce;
use auths_receipts::{verify_attested_decision_bytes, verify_attested_execution_bytes};
use auths_runtime::{
    BudgetClaim, BudgetLedger, ChallengeClaim, ChallengeLedger, ReceiptSink, ReceiptStoreError,
};
use minicbor::{Decoder, Encoder};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{ErrorKind, Write as _},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

/// Exact-algebra in-memory budget claims.
///
/// Every action identifier can claim at most once. A configured algebra
/// ceiling bounds the value reserved by that action.
pub struct InMemoryBudgetLedger {
    ceilings: BTreeMap<String, u64>,
    state: Mutex<BudgetState>,
}

#[derive(Clone, Default)]
struct BudgetState {
    consumed: BTreeMap<String, u64>,
    claimed: BTreeSet<ActionId>,
}

/// Decides an action that declares no requested budget.
///
/// A ledger with no configured ceilings meters nothing and admits it. A ledger
/// that was configured with ceilings cannot account for an unbudgeted action
/// and fails closed.
const fn unmetered_claim(no_ceilings_configured: bool) -> BudgetClaim {
    if no_ceilings_configured {
        BudgetClaim::Claimed
    } else {
        BudgetClaim::Exhausted
    }
}

impl InMemoryBudgetLedger {
    /// Constructs a duplicate-free set of exact algebra ceilings.
    ///
    /// # Errors
    ///
    /// Returns a configuration error for an empty identifier, zero ceiling,
    /// or duplicate algebra.
    pub fn new(
        ceilings: impl IntoIterator<Item = (String, u64)>,
    ) -> Result<Self, StoreConfigurationError> {
        let mut values = BTreeMap::new();
        for (algebra, ceiling) in ceilings {
            if algebra.is_empty() || ceiling == 0 || values.insert(algebra, ceiling).is_some() {
                return Err(StoreConfigurationError);
            }
        }
        Ok(Self {
            ceilings: values,
            state: Mutex::new(BudgetState::default()),
        })
    }

    /// Returns whether an action identifier has already reserved budget.
    #[must_use]
    pub fn is_claimed(&self, action: ActionId) -> bool {
        self.state
            .lock()
            .is_ok_and(|state| state.claimed.contains(&action))
    }
}

impl BudgetLedger for InMemoryBudgetLedger {
    fn claim(&self, action: ActionId, requested: Option<&BudgetCeiling>) -> BudgetClaim {
        let Some(requested) = requested else {
            // An action that declares no budget cannot be metered. A ledger
            // that was configured with stateful ceilings therefore refuses it
            // rather than passing it through un-metered: otherwise the
            // configured ceiling is inert for exactly the actions that decline
            // to state what they will spend.
            return unmetered_claim(self.ceilings.is_empty());
        };
        let algebra = requested.algebra().as_str();
        let Some(ceiling) = self.ceilings.get(algebra) else {
            return BudgetClaim::Exhausted;
        };
        let Ok(mut state) = self.state.lock() else {
            return BudgetClaim::Unavailable;
        };
        if state.claimed.contains(&action) {
            return BudgetClaim::Exhausted;
        }
        let consumed = state.consumed.get(algebra).copied().unwrap_or_default();
        let Some(next) = consumed.checked_add(requested.value()) else {
            return BudgetClaim::Exhausted;
        };
        if next > *ceiling {
            return BudgetClaim::Exhausted;
        }
        state.consumed.insert(algebra.to_string(), next);
        state.claimed.insert(action);
        BudgetClaim::Claimed
    }
}

#[derive(Clone, Copy)]
struct ReplayEntry {
    expires_at: u64,
    consumed: bool,
}

#[derive(Clone, Default)]
struct ReplayState {
    entries: BTreeMap<[u8; 32], ReplayEntry>,
}

/// Process-safe, crash-persistent challenge ledger for a single service
/// instance.
///
/// Each mutation is committed through an atomic file replacement before it
/// becomes visible in memory. Deployments with multiple writer processes
/// should implement [`ChallengeLedger`] over a transactional shared store.
pub struct PersistentChallengeLedger {
    path: PathBuf,
    capacity: usize,
    state: Mutex<ReplayState>,
}

impl PersistentChallengeLedger {
    /// Opens or creates a bounded persistent challenge ledger.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for invalid capacity, I/O errors, corrupt
    /// state, or non-canonical persisted bytes.
    pub fn open(path: impl Into<PathBuf>, capacity: usize) -> Result<Self, PersistentStoreError> {
        if capacity == 0 || capacity > 1_000_000 {
            return Err(PersistentStoreError::InvalidConfiguration);
        }
        let path = path.into();
        let state = if path.exists() {
            let bytes = fs::read(&path).map_err(|_| PersistentStoreError::Io)?;
            decode_replay_state(&bytes, capacity)?
        } else {
            ReplayState::default()
        };
        Ok(Self {
            path,
            capacity,
            state: Mutex::new(state),
        })
    }
}

impl ChallengeLedger for PersistentChallengeLedger {
    fn issue(&self, challenge: ChallengeNonce, expires_at: u64) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        if expires_at == 0
            || state.entries.len() >= self.capacity
            || state.entries.contains_key(challenge.as_bytes())
        {
            return false;
        }
        let mut next = state.clone();
        next.entries.insert(
            *challenge.as_bytes(),
            ReplayEntry {
                expires_at,
                consumed: false,
            },
        );
        if persist_replay_state(&self.path, &next).is_err() {
            return false;
        }
        *state = next;
        true
    }

    fn claim(&self, challenge: ChallengeNonce, now: u64) -> ChallengeClaim {
        let Ok(mut state) = self.state.lock() else {
            return ChallengeClaim::Unavailable;
        };
        let Some(current) = state.entries.get(challenge.as_bytes()).copied() else {
            return ChallengeClaim::Unknown;
        };
        if current.consumed {
            return ChallengeClaim::Consumed;
        }
        let result = if now > current.expires_at {
            ChallengeClaim::Expired
        } else {
            ChallengeClaim::Claimed
        };
        let mut next = state.clone();
        if let Some(entry) = next.entries.get_mut(challenge.as_bytes()) {
            entry.consumed = true;
        }
        if persist_replay_state(&self.path, &next).is_err() {
            return ChallengeClaim::Unavailable;
        }
        *state = next;
        result
    }
}

/// Crash-persistent aggregate budget ledger for a single service instance.
///
/// Claims are action-idempotent and consume the configured total for their
/// exact algebra. File replacement occurs before the in-memory state commits.
pub struct PersistentBudgetLedger {
    path: PathBuf,
    ceilings: BTreeMap<String, u64>,
    state: Mutex<BudgetState>,
}

impl PersistentBudgetLedger {
    /// Opens a persistent aggregate ledger with exact algebra ceilings.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for invalid ceilings, corrupt state, usage
    /// above a configured ceiling, or I/O failure.
    pub fn open(
        path: impl Into<PathBuf>,
        ceilings: impl IntoIterator<Item = (String, u64)>,
    ) -> Result<Self, PersistentStoreError> {
        let ceilings = collect_ceilings(ceilings)?;
        let path = path.into();
        let state = if path.exists() {
            let bytes = fs::read(&path).map_err(|_| PersistentStoreError::Io)?;
            decode_budget_state(&bytes, &ceilings)?
        } else {
            BudgetState::default()
        };
        Ok(Self {
            path,
            ceilings,
            state: Mutex::new(state),
        })
    }
}

impl BudgetLedger for PersistentBudgetLedger {
    fn claim(&self, action: ActionId, requested: Option<&BudgetCeiling>) -> BudgetClaim {
        let Some(requested) = requested else {
            // See `InMemoryBudgetLedger::claim`: a configured stateful ledger
            // fails closed on an action that declares no budget.
            return unmetered_claim(self.ceilings.is_empty());
        };
        let algebra = requested.algebra().as_str();
        let Some(ceiling) = self.ceilings.get(algebra) else {
            return BudgetClaim::Exhausted;
        };
        let Ok(mut state) = self.state.lock() else {
            return BudgetClaim::Unavailable;
        };
        if state.claimed.contains(&action) {
            return BudgetClaim::Exhausted;
        }
        let consumed = state.consumed.get(algebra).copied().unwrap_or_default();
        let Some(next_consumed) = consumed.checked_add(requested.value()) else {
            return BudgetClaim::Exhausted;
        };
        if next_consumed > *ceiling {
            return BudgetClaim::Exhausted;
        }
        let mut next = state.clone();
        next.consumed.insert(algebra.to_string(), next_consumed);
        next.claimed.insert(action);
        if persist_budget_state(&self.path, &next).is_err() {
            return BudgetClaim::Unavailable;
        }
        *state = next;
        BudgetClaim::Claimed
    }
}

fn collect_ceilings(
    ceilings: impl IntoIterator<Item = (String, u64)>,
) -> Result<BTreeMap<String, u64>, PersistentStoreError> {
    let mut values = BTreeMap::new();
    for (algebra, ceiling) in ceilings {
        if algebra.is_empty()
            || algebra.len() > 128
            || !algebra
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || ceiling == 0
            || values.insert(algebra, ceiling).is_some()
        {
            return Err(PersistentStoreError::InvalidConfiguration);
        }
    }
    if values.is_empty() {
        return Err(PersistentStoreError::InvalidConfiguration);
    }
    Ok(values)
}

fn persist_replay_state(path: &Path, state: &ReplayState) -> Result<(), PersistentStoreError> {
    persist_replace(path, &encode_replay_state(state)?)
}

fn encode_replay_state(state: &ReplayState) -> Result<Vec<u8>, PersistentStoreError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(2)
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.u16(1))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.array(state.entries.len() as u64))
        .map_err(|_| PersistentStoreError::Corrupt)?;
    for (nonce, entry) in &state.entries {
        encoder
            .array(3)
            .and_then(|encoder| encoder.bytes(nonce))
            .and_then(|encoder| encoder.u64(entry.expires_at))
            .and_then(|encoder| encoder.bool(entry.consumed))
            .map_err(|_| PersistentStoreError::Corrupt)?;
    }
    Ok(encoder.into_writer())
}

fn decode_replay_state(bytes: &[u8], capacity: usize) -> Result<ReplayState, PersistentStoreError> {
    let mut decoder = Decoder::new(bytes);
    exact_map(&mut decoder, 2)?;
    exact_key(&mut decoder, 0)?;
    if decoder.u16().map_err(|_| PersistentStoreError::Corrupt)? != 1 {
        return Err(PersistentStoreError::Corrupt);
    }
    exact_key(&mut decoder, 1)?;
    let count = exact_array(&mut decoder)?;
    if count > capacity {
        return Err(PersistentStoreError::Corrupt);
    }
    let mut entries = BTreeMap::new();
    for _ in 0..count {
        if exact_array(&mut decoder)? != 3 {
            return Err(PersistentStoreError::Corrupt);
        }
        let nonce: [u8; 32] = decoder
            .bytes()
            .map_err(|_| PersistentStoreError::Corrupt)?
            .try_into()
            .map_err(|_| PersistentStoreError::Corrupt)?;
        let expires_at = decoder.u64().map_err(|_| PersistentStoreError::Corrupt)?;
        let consumed = decoder.bool().map_err(|_| PersistentStoreError::Corrupt)?;
        if expires_at == 0
            || entries
                .insert(
                    nonce,
                    ReplayEntry {
                        expires_at,
                        consumed,
                    },
                )
                .is_some()
        {
            return Err(PersistentStoreError::Corrupt);
        }
    }
    if decoder.position() != bytes.len() {
        return Err(PersistentStoreError::Corrupt);
    }
    let state = ReplayState { entries };
    let canonical = encode_replay_state(&state)?;
    if canonical != bytes {
        return Err(PersistentStoreError::Corrupt);
    }
    Ok(state)
}

fn persist_budget_state(path: &Path, state: &BudgetState) -> Result<(), PersistentStoreError> {
    persist_replace(path, &encode_budget_state(state)?)
}

fn encode_budget_state(state: &BudgetState) -> Result<Vec<u8>, PersistentStoreError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(3)
        .and_then(|encoder| encoder.u8(0))
        .and_then(|encoder| encoder.u16(1))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.array(state.consumed.len() as u64))
        .map_err(|_| PersistentStoreError::Corrupt)?;
    for (algebra, consumed) in &state.consumed {
        encoder
            .array(2)
            .and_then(|encoder| encoder.str(algebra))
            .and_then(|encoder| encoder.u64(*consumed))
            .map_err(|_| PersistentStoreError::Corrupt)?;
    }
    encoder
        .u8(2)
        .and_then(|encoder| encoder.array(state.claimed.len() as u64))
        .map_err(|_| PersistentStoreError::Corrupt)?;
    for action in &state.claimed {
        encoder
            .bytes(action.as_bytes())
            .map_err(|_| PersistentStoreError::Corrupt)?;
    }
    Ok(encoder.into_writer())
}

fn decode_budget_state(
    bytes: &[u8],
    ceilings: &BTreeMap<String, u64>,
) -> Result<BudgetState, PersistentStoreError> {
    let mut decoder = Decoder::new(bytes);
    exact_map(&mut decoder, 3)?;
    exact_key(&mut decoder, 0)?;
    if decoder.u16().map_err(|_| PersistentStoreError::Corrupt)? != 1 {
        return Err(PersistentStoreError::Corrupt);
    }
    exact_key(&mut decoder, 1)?;
    let consumed_count = exact_array(&mut decoder)?;
    if consumed_count > ceilings.len() {
        return Err(PersistentStoreError::Corrupt);
    }
    let mut consumed = BTreeMap::new();
    for _ in 0..consumed_count {
        if exact_array(&mut decoder)? != 2 {
            return Err(PersistentStoreError::Corrupt);
        }
        let algebra = decoder
            .str()
            .map_err(|_| PersistentStoreError::Corrupt)?
            .to_string();
        let value = decoder.u64().map_err(|_| PersistentStoreError::Corrupt)?;
        if ceilings
            .get(&algebra)
            .is_none_or(|ceiling| value > *ceiling)
            || consumed.insert(algebra, value).is_some()
        {
            return Err(PersistentStoreError::Corrupt);
        }
    }
    exact_key(&mut decoder, 2)?;
    let claimed_count = exact_array(&mut decoder)?;
    if claimed_count > 1_000_000 {
        return Err(PersistentStoreError::Corrupt);
    }
    let mut claimed = BTreeSet::new();
    for _ in 0..claimed_count {
        let action: [u8; 32] = decoder
            .bytes()
            .map_err(|_| PersistentStoreError::Corrupt)?
            .try_into()
            .map_err(|_| PersistentStoreError::Corrupt)?;
        if !claimed.insert(ActionId::new(action)) {
            return Err(PersistentStoreError::Corrupt);
        }
    }
    if decoder.position() != bytes.len() {
        return Err(PersistentStoreError::Corrupt);
    }
    let state = BudgetState { consumed, claimed };
    if encode_budget_state(&state)? != bytes {
        return Err(PersistentStoreError::Corrupt);
    }
    Ok(state)
}

fn exact_map(decoder: &mut Decoder<'_>, expected: usize) -> Result<(), PersistentStoreError> {
    if decoder
        .map()
        .map_err(|_| PersistentStoreError::Corrupt)?
        .and_then(|value| usize::try_from(value).ok())
        != Some(expected)
    {
        return Err(PersistentStoreError::Corrupt);
    }
    Ok(())
}

fn exact_array(decoder: &mut Decoder<'_>) -> Result<usize, PersistentStoreError> {
    decoder
        .array()
        .map_err(|_| PersistentStoreError::Corrupt)?
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(PersistentStoreError::Corrupt)
}

fn exact_key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), PersistentStoreError> {
    if decoder.u8().map_err(|_| PersistentStoreError::Corrupt)? != expected {
        return Err(PersistentStoreError::Corrupt);
    }
    Ok(())
}

fn persist_replace(path: &Path, bytes: &[u8]) -> Result<(), PersistentStoreError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|_| PersistentStoreError::Io)?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|_| PersistentStoreError::Io)?;
    temporary
        .write_all(bytes)
        .map_err(|_| PersistentStoreError::Io)?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| PersistentStoreError::Io)?;
    temporary
        .persist(path)
        .map_err(|_| PersistentStoreError::Io)?;
    Ok(())
}

/// Persistent replay or budget store failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistentStoreError {
    /// Store configuration is invalid.
    InvalidConfiguration,
    /// Persisted bytes are malformed or non-canonical.
    Corrupt,
    /// Filesystem state is unavailable.
    Io,
}

impl core::fmt::Display for PersistentStoreError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid persistent Auths store configuration",
            Self::Corrupt => "corrupt persistent Auths store state",
            Self::Io => "persistent Auths store I/O failed",
        })
    }
}

impl std::error::Error for PersistentStoreError {}

/// Canonical idempotent in-memory receipt store.
#[derive(Default)]
pub struct InMemoryReceiptStore {
    decisions: Mutex<BTreeMap<ReceiptId, Vec<u8>>>,
    executions: Mutex<BTreeMap<ReceiptId, Vec<u8>>>,
}

impl InMemoryReceiptStore {
    /// Returns one canonical decision receipt.
    #[must_use]
    pub fn decision(&self, id: ReceiptId) -> Option<Vec<u8>> {
        self.decisions.lock().ok()?.get(&id).cloned()
    }

    /// Returns one canonical execution receipt.
    #[must_use]
    pub fn execution(&self, id: ReceiptId) -> Option<Vec<u8>> {
        self.executions.lock().ok()?.get(&id).cloned()
    }

    #[must_use]
    pub fn counts(&self) -> (usize, usize) {
        (
            self.decisions.lock().map_or(0, |values| values.len()),
            self.executions.lock().map_or(0, |values| values.len()),
        )
    }
}

impl ReceiptSink for InMemoryReceiptStore {
    fn store_decision(&self, id: ReceiptId, bytes: Vec<u8>) -> Result<(), ReceiptStoreError> {
        verify_attested_decision_bytes(&bytes, id).map_err(|_| ReceiptStoreError)?;
        idempotent_insert(&self.decisions, id, bytes)
    }

    fn store_execution(&self, id: ReceiptId, bytes: Vec<u8>) -> Result<(), ReceiptStoreError> {
        verify_attested_execution_bytes(&bytes, id).map_err(|_| ReceiptStoreError)?;
        idempotent_insert(&self.executions, id, bytes)
    }
}

fn idempotent_insert(
    store: &Mutex<BTreeMap<ReceiptId, Vec<u8>>>,
    id: ReceiptId,
    bytes: Vec<u8>,
) -> Result<(), ReceiptStoreError> {
    let mut values = store.lock().map_err(|_| ReceiptStoreError)?;
    match values.get(&id) {
        Some(existing) if existing == &bytes => Ok(()),
        Some(_) => Err(ReceiptStoreError),
        None => {
            values.insert(id, bytes);
            Ok(())
        }
    }
}

/// Atomic immutable filesystem receipt store.
pub struct FileReceiptStore {
    root: PathBuf,
}

impl FileReceiptStore {
    /// Selects one explicit receipt root.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn store(&self, class: &str, id: ReceiptId, bytes: &[u8]) -> Result<(), ReceiptStoreError> {
        let directory = self.root.join(class);
        fs::create_dir_all(&directory).map_err(|_| ReceiptStoreError)?;
        let target = directory.join(format!("{}.cbor", hex::encode(id.as_bytes())));
        if target.exists() {
            return if fs::read(target).is_ok_and(|existing| existing == bytes) {
                Ok(())
            } else {
                Err(ReceiptStoreError)
            };
        }
        persist_noclobber(&directory, &target, bytes)
    }

    /// Returns the deterministic filesystem path for a receipt.
    #[must_use]
    pub fn path(&self, class: &str, id: ReceiptId) -> PathBuf {
        self.root
            .join(class)
            .join(format!("{}.cbor", hex::encode(id.as_bytes())))
    }
}

impl ReceiptSink for FileReceiptStore {
    fn store_decision(&self, id: ReceiptId, bytes: Vec<u8>) -> Result<(), ReceiptStoreError> {
        verify_attested_decision_bytes(&bytes, id).map_err(|_| ReceiptStoreError)?;
        self.store("decisions", id, &bytes)
    }

    fn store_execution(&self, id: ReceiptId, bytes: Vec<u8>) -> Result<(), ReceiptStoreError> {
        verify_attested_execution_bytes(&bytes, id).map_err(|_| ReceiptStoreError)?;
        self.store("executions", id, &bytes)
    }
}

/// Receipt sink that uses an immutable local spool only when its primary sink
/// is unavailable.
///
/// This implements the explicit `local-spool` policy. Using the primary sink
/// directly implements `fail-closed`.
pub struct LocalSpoolReceiptSink {
    primary: Arc<dyn ReceiptSink>,
    spool: FileReceiptStore,
}

impl LocalSpoolReceiptSink {
    /// Selects an explicit primary sink and local spool directory.
    #[must_use]
    pub fn new(primary: Arc<dyn ReceiptSink>, spool_root: impl Into<PathBuf>) -> Self {
        Self {
            primary,
            spool: FileReceiptStore::new(spool_root),
        }
    }

    /// Returns the deterministic path used for a spooled receipt.
    #[must_use]
    pub fn spool_path(&self, class: &str, id: ReceiptId) -> PathBuf {
        self.spool.path(class, id)
    }
}

impl ReceiptSink for LocalSpoolReceiptSink {
    fn store_decision(&self, id: ReceiptId, bytes: Vec<u8>) -> Result<(), ReceiptStoreError> {
        if self.primary.store_decision(id, bytes.clone()).is_ok() {
            Ok(())
        } else {
            self.spool.store_decision(id, bytes)
        }
    }

    fn store_execution(&self, id: ReceiptId, bytes: Vec<u8>) -> Result<(), ReceiptStoreError> {
        if self.primary.store_execution(id, bytes.clone()).is_ok() {
            Ok(())
        } else {
            self.spool.store_execution(id, bytes)
        }
    }
}

fn persist_noclobber(
    directory: &Path,
    target: &Path,
    bytes: &[u8],
) -> Result<(), ReceiptStoreError> {
    let mut temporary =
        tempfile::NamedTempFile::new_in(directory).map_err(|_| ReceiptStoreError)?;
    temporary.write_all(bytes).map_err(|_| ReceiptStoreError)?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| ReceiptStoreError)?;
    temporary.persist_noclobber(target).map_or_else(
        |error| {
            if error.error.kind() == ErrorKind::AlreadyExists
                && fs::read(target).is_ok_and(|existing| existing == bytes)
            {
                Ok(())
            } else {
                Err(ReceiptStoreError)
            }
        },
        |_| Ok(()),
    )
}

/// Invalid concrete-store configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreConfigurationError;

impl core::fmt::Display for StoreConfigurationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("invalid Auths store configuration")
    }
}

impl std::error::Error for StoreConfigurationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_model::{
        BudgetAlgebraId, ContextDigest, Digest, PrincipalId, ProfileId, ProfileRef, SignatureBytes,
        SignatureSuiteId, StatusSnapshotId, Timestamp, VerificationMethod,
    };
    use auths_receipts::{
        AttestedDecisionReceipt, DecisionClass, DecisionReceipt, ReceiptSigner,
        decision_receipt_id, encode_attested_decision,
    };

    struct FailingReceiptSink;

    impl ReceiptSink for FailingReceiptSink {
        fn store_decision(&self, _id: ReceiptId, _bytes: Vec<u8>) -> Result<(), ReceiptStoreError> {
            Err(ReceiptStoreError)
        }

        fn store_execution(
            &self,
            _id: ReceiptId,
            _bytes: Vec<u8>,
        ) -> Result<(), ReceiptStoreError> {
            Err(ReceiptStoreError)
        }
    }

    #[test]
    fn budget_claim_is_exact_and_atomic() {
        let ledger = InMemoryBudgetLedger::new([("numeric-ceiling-v1".into(), 10)]).unwrap();
        let action = ActionId::new([7; 32]);
        let requested =
            BudgetCeiling::new(BudgetAlgebraId::parse("numeric-ceiling-v1").unwrap(), 5);
        assert_eq!(ledger.claim(action, Some(&requested)), BudgetClaim::Claimed);
        assert_eq!(
            ledger.claim(action, Some(&requested)),
            BudgetClaim::Exhausted
        );
        assert!(ledger.is_claimed(action));
    }

    /// Regression: a configured stateful ledger used to return `Claimed` for
    /// any action that declared no requested budget, so the configured ceiling
    /// was inert for exactly the actions that decline to state their spend.
    #[test]
    fn configured_ledger_refuses_an_action_without_a_requested_budget() {
        let ledger = InMemoryBudgetLedger::new([("numeric-ceiling-v1".into(), 10)]).unwrap();
        assert_eq!(
            ledger.claim(ActionId::new([9; 32]), None),
            BudgetClaim::Exhausted
        );
        assert!(!ledger.is_claimed(ActionId::new([9; 32])));
    }

    #[test]
    fn unconfigured_ledger_meters_nothing_and_admits_unbudgeted_actions() {
        let ledger = InMemoryBudgetLedger::new([]).unwrap();
        assert_eq!(
            ledger.claim(ActionId::new([9; 32]), None),
            BudgetClaim::Claimed
        );
    }

    #[test]
    fn budget_consumption_is_aggregate() {
        let ledger = InMemoryBudgetLedger::new([("numeric-ceiling-v1".into(), 10)]).unwrap();
        let six = BudgetCeiling::new(BudgetAlgebraId::parse("numeric-ceiling-v1").unwrap(), 6);
        let five = BudgetCeiling::new(BudgetAlgebraId::parse("numeric-ceiling-v1").unwrap(), 5);
        let four = BudgetCeiling::new(BudgetAlgebraId::parse("numeric-ceiling-v1").unwrap(), 4);
        assert_eq!(
            ledger.claim(ActionId::new([1; 32]), Some(&six)),
            BudgetClaim::Claimed
        );
        assert_eq!(
            ledger.claim(ActionId::new([2; 32]), Some(&five)),
            BudgetClaim::Exhausted
        );
        assert_eq!(
            ledger.claim(ActionId::new([3; 32]), Some(&four)),
            BudgetClaim::Claimed
        );
    }

    #[test]
    fn persistent_ledgers_survive_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let replay_path = directory.path().join("replay.cbor");
        let challenge = ChallengeNonce::new([8; 32]);
        {
            let ledger = PersistentChallengeLedger::open(&replay_path, 8).unwrap();
            assert!(ledger.issue(challenge, 100));
            assert_eq!(ledger.claim(challenge, 50), ChallengeClaim::Claimed);
        }
        let ledger = PersistentChallengeLedger::open(&replay_path, 8).unwrap();
        assert_eq!(ledger.claim(challenge, 50), ChallengeClaim::Consumed);

        let budget_path = directory.path().join("budget.cbor");
        let requested =
            BudgetCeiling::new(BudgetAlgebraId::parse("numeric-ceiling-v1").unwrap(), 7);
        {
            let ledger =
                PersistentBudgetLedger::open(&budget_path, [("numeric-ceiling-v1".into(), 10)])
                    .unwrap();
            assert_eq!(
                ledger.claim(ActionId::new([1; 32]), Some(&requested)),
                BudgetClaim::Claimed
            );
        }
        let ledger =
            PersistentBudgetLedger::open(&budget_path, [("numeric-ceiling-v1".into(), 10)])
                .unwrap();
        assert_eq!(
            ledger.claim(ActionId::new([2; 32]), Some(&requested)),
            BudgetClaim::Exhausted
        );
    }

    #[test]
    fn local_spool_policy_persists_attested_receipt_on_primary_failure() {
        let receipt = DecisionReceipt::new(
            Digest::new([1; 32]),
            Digest::new([2; 32]),
            ContextDigest::new([3; 32]),
            StatusSnapshotId::new([4; 32]),
            StatusSnapshotId::new([5; 32]),
            ProfileRef::new(ProfileId::parse("auths.mcp").unwrap(), 1).unwrap(),
            DecisionClass::Authorized,
            vec!["authorized".into()],
            Timestamp::new(10),
        )
        .unwrap();
        let id = decision_receipt_id(&receipt).unwrap();
        let attested = AttestedDecisionReceipt::new(
            receipt,
            ReceiptSigner::new(
                PrincipalId::parse("did:key:verifier").unwrap(),
                VerificationMethod::parse("did:key:verifier#receipt").unwrap(),
                SignatureSuiteId::parse("ed25519-v1").unwrap(),
            ),
            SignatureBytes::new(vec![9; 64]).unwrap(),
        );
        let bytes = encode_attested_decision(&attested).unwrap();
        let root = tempfile::tempdir().unwrap();
        let sink = LocalSpoolReceiptSink::new(Arc::new(FailingReceiptSink), root.path());
        sink.store_decision(id, bytes.clone()).unwrap();
        assert_eq!(fs::read(sink.spool_path("decisions", id)).unwrap(), bytes);
    }
}
