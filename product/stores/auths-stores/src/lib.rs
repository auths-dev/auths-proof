//! Concrete bounded stores for outer Auths application state.

#![forbid(unsafe_code)]

/// Build-time sentinel used by the production agent to reject accidental
/// linkage of its qualification-only journal evidence surface.
#[doc(hidden)]
pub const __QUALIFICATION_EVIDENCE_ENABLED: bool = cfg!(feature = "qualification-evidence");

mod connection;
mod gateway_attempt;
mod lifecycle;
mod operation;

pub use connection::{
    ConnectionStoreConfigurationError, PersistentConnectionStore, PersistentConnectionStoreError,
};

pub use gateway_attempt::{GatewayAttemptInsert, MAX_GATEWAY_ATTEMPT_BYTES};
pub use lifecycle::{
    InMemoryLifecycleStore, LifecycleCapacityRuleV1, LifecycleStoreConfigurationError,
    PersistentLifecycleStore, PostgresLifecycleStore, PostgresPoolConfig, PostgresServerName,
    PostgresStoreConfig, PostgresStoreHealth, PostgresStoreSummary, PostgresTlsConfig,
    SecretConnectionString,
};
#[cfg(all(unix, feature = "qualification-evidence"))]
pub use operation::read_persisted_qualification_boundaries_from_snapshot;
pub use operation::{
    JournalCompletionV1, JournalDecisionClassV1, JournalExecutionOutcomeV1,
    JournalExecutionReceiptBasisV1, JournalReceiptV1, JournalRecordV1, JournalStatusV1,
    OperationJournalConfigurationError, OperationJournalError, OperationJournalLimitsV1,
    OperationMutationV1, PersistentOperationJournal, PreparationIdentityLookup,
    PrepareJournalResult, TombstoneV1, generate_operation_id,
};
#[cfg(feature = "qualification-evidence")]
pub use operation::{QualificationJournalBoundaryKindV1, QualificationJournalBoundaryV1};
#[cfg(all(unix, any(feature = "qualification-evidence", test)))]
pub use operation::{
    open_persisted_operation_snapshot_at_for_qualification,
    open_persisted_operation_snapshot_for_qualification,
    read_persisted_operation_record_for_qualification,
    read_persisted_operation_record_from_qualification_snapshot,
    read_persisted_operation_records_from_qualification_snapshot,
};

use auths_model::{ActionId, BudgetCeiling, ReceiptId};
use auths_receipts::{verify_attested_decision_bytes, verify_attested_execution_bytes};
use auths_runtime::{BudgetClaim, BudgetLedger, ReceiptSink, ReceiptStoreError};
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

#[derive(Default)]
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
        AttestedDecisionReceipt, DecisionClass, DecisionReceipt, ProfileReceiptClaim,
        ProfileReceiptClaimPhase, ReceiptSigner, decision_receipt_id, encode_attested_decision,
        encode_profile_receipt_claims,
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
    fn local_spool_policy_persists_attested_receipt_on_primary_failure() {
        let profile = ProfileRef::new(ProfileId::parse("auths.mcp").unwrap(), 1).unwrap();
        let profile_claims = encode_profile_receipt_claims(
            &profile,
            ProfileReceiptClaimPhase::Decision,
            &[ProfileReceiptClaim::new("auths.mcp.action", [6; 32]).unwrap()],
        )
        .unwrap();
        let receipt = DecisionReceipt::new(
            Digest::new([1; 32]),
            Digest::new([2; 32]),
            ContextDigest::new([3; 32]),
            StatusSnapshotId::new([4; 32]),
            StatusSnapshotId::new([5; 32]),
            profile,
            DecisionClass::Authorized,
            vec!["authorized".into()],
            Timestamp::new(10),
            profile_claims,
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
