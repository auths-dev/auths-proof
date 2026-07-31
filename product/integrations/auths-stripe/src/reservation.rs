//! Stripe-local aggregate refund reservations.
//!
//! The state machine is intentionally concrete: its key and capacity unit are
//! Stripe refund minor units under one configured policy and account.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use auths_lifecycle::{
    LifecycleRecordV1, LifecycleStore, StoreError, StoreTransactionV1, StoredTransitionV1,
    TransitionCommandV1, TransitionDisposition, WorkflowId, apply_transition, decode_record,
    encode_record,
};

use crate::{
    bounded::{
        AggregateBudgetSnapshot, AggregateBudgetUsage, RefundReservationIntent,
        StripeBoundedRefundPolicyV1,
    },
    canonical::{canonical_json, sha256},
    types::{Currency, DigestHex, RefundId, StripeAccountId},
};

const RESERVATION_SCHEMA: &str = "auths.stripe.bounded-reservation/1";
const STATE_SCHEMA: &str = "auths.stripe.bounded-reservation-state/2";
const MAX_STATE_BYTES: usize = 32 * 1024 * 1024;
const MAX_RECORDS: usize = 16_384;

/// Durable aggregate-capacity state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefundReservationState {
    /// Capacity is held before provider acceptance is known.
    Reserved,
    /// Stripe created the exact refund.
    Committed,
    /// Definite non-effect returned capacity.
    Released,
    /// Stripe may have received the request; capacity remains held.
    OutcomeUnknown,
    /// Reconciliation proved creation.
    ReconciledCommitted,
    /// Reconciliation proved non-creation.
    ReconciledReleased,
}

/// Exact durable reservation record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RefundReservationRecord {
    schema: String,
    reservation_id: DigestHex,
    workflow_id: String,
    action_digest: DigestHex,
    decision_receipt_digest: DigestHex,
    policy_digest: DigestHex,
    evaluator_semantic_id: String,
    evaluator_semantic_version: u16,
    evidence_digest: DigestHex,
    required_configuration_digest: DigestHex,
    executed_configuration_digest: DigestHex,
    stripe_account_id: StripeAccountId,
    currency: Currency,
    amount_minor: u64,
    intents: Vec<RefundReservationIntent>,
    state: RefundReservationState,
    idempotency_key_digest: DigestHex,
    refund_id: Option<RefundId>,
    result_digest: Option<DigestHex>,
    created_at: u64,
    updated_at: u64,
}

impl RefundReservationRecord {
    /// Deterministic reservation identity.
    #[must_use]
    pub const fn reservation_id(&self) -> &DigestHex {
        &self.reservation_id
    }

    /// Workflow.
    #[must_use]
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    /// Exact action commitment.
    #[must_use]
    pub const fn action_digest(&self) -> &DigestHex {
        &self.action_digest
    }

    /// Durable decision receipt commitment.
    #[must_use]
    pub const fn decision_receipt_digest(&self) -> &DigestHex {
        &self.decision_receipt_digest
    }

    /// Configured policy commitment.
    #[must_use]
    pub const fn policy_digest(&self) -> &DigestHex {
        &self.policy_digest
    }

    /// Exact amount.
    #[must_use]
    pub const fn amount_minor(&self) -> u64 {
        self.amount_minor
    }

    /// Currency.
    #[must_use]
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }

    /// Current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> RefundReservationState {
        self.state
    }

    /// Aggregate capacity intents.
    #[must_use]
    pub fn intents(&self) -> &[RefundReservationIntent] {
        &self.intents
    }

    /// Provider Refund when known.
    #[must_use]
    pub const fn refund_id(&self) -> Option<&RefundId> {
        self.refund_id.as_ref()
    }
}

/// All exact inputs to one atomic reservation.
pub struct ReserveRefundRequest {
    /// Workflow identity.
    pub workflow_id: String,
    /// Exact action digest.
    pub action_digest: DigestHex,
    /// Durable decision receipt commitment.
    pub decision_receipt_digest: DigestHex,
    /// Configured policy digest.
    pub policy_digest: DigestHex,
    /// Evaluator semantic ID.
    pub evaluator_semantic_id: String,
    /// Evaluator semantic version.
    pub evaluator_semantic_version: u16,
    /// Fresh evidence commitment.
    pub evidence_digest: DigestHex,
    /// Required bounded configuration commitment.
    pub required_configuration_digest: DigestHex,
    /// Executed bounded configuration commitment.
    pub executed_configuration_digest: DigestHex,
    /// Stripe account.
    pub stripe_account_id: StripeAccountId,
    /// Exact currency.
    pub currency: Currency,
    /// Exact amount.
    pub amount_minor: u64,
    /// Pure evaluator intents.
    pub intents: Vec<RefundReservationIntent>,
    /// Stripe idempotency key commitment.
    pub idempotency_key_digest: DigestHex,
    /// Explicit reservation time.
    pub now: u64,
}

#[derive(Serialize)]
struct ReservationIdentity<'a> {
    domain: &'static str,
    policy_digest: &'a DigestHex,
    action_digest: &'a DigestHex,
    workflow_id: &'a str,
    intents: Vec<ReservationIdentityIntent<'a>>,
}

#[derive(Serialize)]
struct ReservationIdentityIntent<'a> {
    budget_id: &'a str,
    currency: &'a Currency,
    window: &'a crate::bounded::RefundWindowIdentity,
    limit_minor: u64,
    amount_minor: u64,
}

impl ReserveRefundRequest {
    /// Computes the deterministic reservation identity.
    ///
    /// # Errors
    ///
    /// Returns a closed canonicalization failure.
    pub fn reservation_id(&self) -> Result<DigestHex, ReservationError> {
        let identity = ReservationIdentity {
            domain: RESERVATION_SCHEMA,
            policy_digest: &self.policy_digest,
            action_digest: &self.action_digest,
            workflow_id: &self.workflow_id,
            intents: self
                .intents
                .iter()
                .map(|intent| ReservationIdentityIntent {
                    budget_id: &intent.budget_id,
                    currency: &intent.currency,
                    window: &intent.window,
                    limit_minor: intent.limit_minor,
                    amount_minor: intent.amount_minor,
                })
                .collect(),
        };
        canonical_json(&identity)
            .map(|bytes| sha256(&bytes))
            .map_err(|_| ReservationError::Corrupt)
    }

    fn into_record(self, reservation_id: DigestHex) -> RefundReservationRecord {
        RefundReservationRecord {
            schema: RESERVATION_SCHEMA.into(),
            reservation_id,
            workflow_id: self.workflow_id,
            action_digest: self.action_digest,
            decision_receipt_digest: self.decision_receipt_digest,
            policy_digest: self.policy_digest,
            evaluator_semantic_id: self.evaluator_semantic_id,
            evaluator_semantic_version: self.evaluator_semantic_version,
            evidence_digest: self.evidence_digest,
            required_configuration_digest: self.required_configuration_digest,
            executed_configuration_digest: self.executed_configuration_digest,
            stripe_account_id: self.stripe_account_id,
            currency: self.currency,
            amount_minor: self.amount_minor,
            intents: self.intents,
            state: RefundReservationState::Reserved,
            idempotency_key_digest: self.idempotency_key_digest,
            refund_id: None,
            result_digest: None,
            created_at: self.now,
            updated_at: self.now,
        }
    }
}

/// Opaque authority to transition one exact reservation.
#[derive(Debug)]
pub struct RefundReservationLease {
    workflow_id: String,
    reservation_id: DigestHex,
    action_digest: DigestHex,
}

impl RefundReservationLease {
    /// Workflow.
    #[must_use]
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    /// Reservation identity.
    #[must_use]
    pub const fn reservation_id(&self) -> &DigestHex {
        &self.reservation_id
    }

    pub(crate) fn from_record(record: &RefundReservationRecord) -> Self {
        Self {
            workflow_id: record.workflow_id.clone(),
            reservation_id: record.reservation_id.clone(),
            action_digest: record.action_digest.clone(),
        }
    }
}

/// Atomic reservation outcome.
#[derive(Debug)]
pub enum ReserveRefundResult {
    /// This caller owns the new reservation.
    Reserved {
        /// Transition lease.
        lease: RefundReservationLease,
        /// Durable record.
        record: RefundReservationRecord,
    },
    /// Same exact operation already exists.
    Replay(RefundReservationRecord),
    /// Workflow is bound to different inputs.
    Conflict(RefundReservationRecord),
    /// Aggregate capacity changed after pure evaluation.
    CapacityExceeded {
        /// Stable budget identifier.
        budget_id: String,
        /// Capacity observed atomically.
        available_minor: u64,
    },
    /// State was unavailable.
    Unavailable,
}

/// Stripe-local durable reservation contract.
pub trait RefundReservationStore: Send + Sync {
    /// Reads an immutable aggregate state view.
    ///
    /// # Errors
    ///
    /// Returns a closed state failure.
    fn snapshot(
        &self,
        policy: &StripeBoundedRefundPolicyV1,
        account: &StripeAccountId,
        now: u64,
    ) -> Result<AggregateBudgetSnapshot, ReservationError>;

    /// Atomically reserves every intent or none.
    fn reserve(&self, request: ReserveRefundRequest) -> ReserveRefundResult;

    /// Commits provider-created usage.
    ///
    /// # Errors
    ///
    /// Rejects missing, conflicting, or illegal transitions.
    fn commit(
        &self,
        lease: &RefundReservationLease,
        refund_id: &RefundId,
        result_digest: &DigestHex,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError>;

    /// Releases capacity after definite non-execution.
    ///
    /// # Errors
    ///
    /// Rejects missing, conflicting, or illegal transitions.
    fn release(
        &self,
        lease: &RefundReservationLease,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError>;

    /// Holds capacity after ambiguous request delivery.
    ///
    /// # Errors
    ///
    /// Rejects missing, conflicting, or illegal transitions.
    fn mark_outcome_unknown(
        &self,
        lease: &RefundReservationLease,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError>;

    /// Reconciles an unknown outcome to committed or released.
    ///
    /// # Errors
    ///
    /// Only a reserved or outcome-unknown record may reconcile. A reserved
    /// record is ambiguous after process failure because the crash may have
    /// happened during provider I/O.
    fn reconcile(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: ReconciledRefundOutcome,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError>;

    /// Reads one workflow.
    ///
    /// # Errors
    ///
    /// Returns a closed state failure.
    fn get(&self, workflow_id: &str) -> Result<Option<RefundReservationRecord>, ReservationError>;
}

/// Domain mutation committed atomically with one shared lifecycle transition.
pub enum RefundLifecycleMutation<'a> {
    /// No Stripe-local record changes at this edge.
    None,
    /// Acquire the exact Stripe aggregate reservation.
    Reserve {
        /// Immutable policy used to validate the transactional capacity view.
        policy: &'a StripeBoundedRefundPolicyV1,
        /// Complete Stripe reservation input.
        request: Box<ReserveRefundRequest>,
    },
    /// Commit an exact Stripe Refund result.
    Commit {
        /// Existing exact reservation authority.
        lease: &'a RefundReservationLease,
        /// Stripe Refund returned by the provider.
        refund_id: &'a RefundId,
        /// Exact normalized provider result commitment.
        result_digest: &'a DigestHex,
        /// Explicit transition time.
        now: u64,
    },
    /// Release held Stripe capacity after definite non-effect.
    Release {
        /// Existing exact reservation authority.
        lease: &'a RefundReservationLease,
        /// Explicit transition time.
        now: u64,
    },
    /// Retain Stripe capacity after ambiguous provider delivery.
    OutcomeUnknown {
        /// Existing exact reservation authority.
        lease: &'a RefundReservationLease,
        /// Explicit transition time.
        now: u64,
    },
    /// Resolve an ambiguous Stripe outcome from fresh provider evidence.
    Reconcile {
        /// Exact workflow identity.
        workflow_id: &'a str,
        /// Exact action commitment.
        action_digest: &'a DigestHex,
        /// Domain-classified reconciliation result.
        outcome: ReconciledRefundOutcome,
        /// Explicit transition time.
        now: u64,
    },
}

/// Stripe store extension that persists the shared lifecycle and domain
/// reservation view under one lock and one canonical file replacement.
pub trait RefundLifecycleStore: RefundReservationStore {
    /// Atomically applies the shared transition and matching Stripe mutation.
    ///
    /// # Errors
    ///
    /// Returns a closed shared store failure without persisting either half
    /// when revision, capacity, transition, encoding, or domain state fails.
    fn transact_refund_lifecycle(
        &self,
        transaction: &StoreTransactionV1,
        mutation: RefundLifecycleMutation<'_>,
    ) -> Result<StoredTransitionV1, StoreError>;

    /// Reads one validated shared lifecycle record.
    ///
    /// # Errors
    ///
    /// Returns a closed shared store failure for unavailable or corrupt state.
    fn load_refund_lifecycle(
        &self,
        workflow: &WorkflowId,
    ) -> Result<Option<LifecycleRecordV1>, StoreError>;
}

/// One-use adapter that binds a shared transaction to its matching Stripe
/// mutation. It exists so callers must pass the combined transaction through
/// [`auths_lifecycle::execute_store_transaction`] and receive its sealed,
/// store-validated result.
pub struct RefundLifecycleTransaction<'a, S: ?Sized> {
    store: &'a S,
    mutation: Mutex<Option<RefundLifecycleMutation<'a>>>,
}

impl<'a, S: RefundLifecycleStore + ?Sized> RefundLifecycleTransaction<'a, S> {
    /// Binds one shared command to exactly one domain mutation.
    #[must_use]
    pub const fn new(store: &'a S, mutation: RefundLifecycleMutation<'a>) -> Self {
        Self {
            store,
            mutation: Mutex::new(Some(mutation)),
        }
    }
}

impl<S: RefundLifecycleStore + ?Sized> LifecycleStore for RefundLifecycleTransaction<'_, S> {
    fn transact(&self, transaction: &StoreTransactionV1) -> Result<StoredTransitionV1, StoreError> {
        let mutation = self
            .mutation
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .take()
            .ok_or(StoreError::Conflict)?;
        self.store.transact_refund_lifecycle(transaction, mutation)
    }
}

impl<T: RefundReservationStore + ?Sized> RefundReservationStore for Arc<T> {
    fn snapshot(
        &self,
        policy: &StripeBoundedRefundPolicyV1,
        account: &StripeAccountId,
        now: u64,
    ) -> Result<AggregateBudgetSnapshot, ReservationError> {
        (**self).snapshot(policy, account, now)
    }

    fn reserve(&self, request: ReserveRefundRequest) -> ReserveRefundResult {
        (**self).reserve(request)
    }

    fn commit(
        &self,
        lease: &RefundReservationLease,
        refund_id: &RefundId,
        result_digest: &DigestHex,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError> {
        (**self).commit(lease, refund_id, result_digest, now)
    }

    fn release(
        &self,
        lease: &RefundReservationLease,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError> {
        (**self).release(lease, now)
    }

    fn mark_outcome_unknown(
        &self,
        lease: &RefundReservationLease,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError> {
        (**self).mark_outcome_unknown(lease, now)
    }

    fn reconcile(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: ReconciledRefundOutcome,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError> {
        (**self).reconcile(workflow_id, action_digest, outcome, now)
    }

    fn get(&self, workflow_id: &str) -> Result<Option<RefundReservationRecord>, ReservationError> {
        (**self).get(workflow_id)
    }
}

impl<T: RefundLifecycleStore + ?Sized> RefundLifecycleStore for Arc<T> {
    fn transact_refund_lifecycle(
        &self,
        transaction: &StoreTransactionV1,
        mutation: RefundLifecycleMutation<'_>,
    ) -> Result<StoredTransitionV1, StoreError> {
        (**self).transact_refund_lifecycle(transaction, mutation)
    }

    fn load_refund_lifecycle(
        &self,
        workflow: &WorkflowId,
    ) -> Result<Option<LifecycleRecordV1>, StoreError> {
        (**self).load_refund_lifecycle(workflow)
    }
}

/// Provider-backed reconciliation result.
pub enum ReconciledRefundOutcome {
    /// Stripe created the exact refund.
    Committed {
        /// Stripe Refund.
        refund_id: RefundId,
        /// Normalized provider result commitment.
        result_digest: DigestHex,
    },
    /// Fresh Stripe evidence proves no effect.
    Released,
}

/// Process-safe reservation store for tests and embedded deployments.
pub struct InMemoryRefundReservationStore {
    database: Mutex<ReservationDatabase>,
}

impl Default for InMemoryRefundReservationStore {
    fn default() -> Self {
        Self {
            database: Mutex::new(ReservationDatabase::empty()),
        }
    }
}

impl InMemoryRefundReservationStore {
    /// Returns the number of live capacity-holding reservations.
    ///
    /// This operational projection does not expose lease material.
    #[must_use]
    pub fn active_reservation_count(&self) -> usize {
        self.database.lock().map_or(0, |database| {
            database
                .records
                .values()
                .filter(|record| {
                    matches!(
                        record.state,
                        RefundReservationState::Reserved
                            | RefundReservationState::Committed
                            | RefundReservationState::OutcomeUnknown
                            | RefundReservationState::ReconciledCommitted
                    )
                })
                .count()
        })
    }
}

impl RefundReservationStore for InMemoryRefundReservationStore {
    fn snapshot(
        &self,
        policy: &StripeBoundedRefundPolicyV1,
        account: &StripeAccountId,
        now: u64,
    ) -> Result<AggregateBudgetSnapshot, ReservationError> {
        let database = self
            .database
            .lock()
            .map_err(|_| ReservationError::Unavailable)?;
        snapshot_in(&database.records, policy, account, now)
    }

    fn reserve(&self, request: ReserveRefundRequest) -> ReserveRefundResult {
        let Ok(mut database) = self.database.lock() else {
            return ReserveRefundResult::Unavailable;
        };
        reserve_in(&mut database.records, request)
    }

    fn commit(
        &self,
        lease: &RefundReservationLease,
        refund_id: &RefundId,
        result_digest: &DigestHex,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError> {
        let mut database = self
            .database
            .lock()
            .map_err(|_| ReservationError::Unavailable)?;
        commit_in(&mut database.records, lease, refund_id, result_digest, now)
    }

    fn release(
        &self,
        lease: &RefundReservationLease,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError> {
        let mut database = self
            .database
            .lock()
            .map_err(|_| ReservationError::Unavailable)?;
        transition_in(
            &mut database.records,
            lease,
            RefundReservationState::Released,
            now,
        )
    }

    fn mark_outcome_unknown(
        &self,
        lease: &RefundReservationLease,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError> {
        let mut database = self
            .database
            .lock()
            .map_err(|_| ReservationError::Unavailable)?;
        transition_in(
            &mut database.records,
            lease,
            RefundReservationState::OutcomeUnknown,
            now,
        )
    }

    fn reconcile(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: ReconciledRefundOutcome,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError> {
        let mut database = self
            .database
            .lock()
            .map_err(|_| ReservationError::Unavailable)?;
        reconcile_in(
            &mut database.records,
            workflow_id,
            action_digest,
            outcome,
            now,
        )
    }

    fn get(&self, workflow_id: &str) -> Result<Option<RefundReservationRecord>, ReservationError> {
        self.database
            .lock()
            .map(|database| database.records.get(workflow_id).cloned())
            .map_err(|_| ReservationError::Unavailable)
    }
}

impl RefundLifecycleStore for InMemoryRefundReservationStore {
    fn transact_refund_lifecycle(
        &self,
        transaction: &StoreTransactionV1,
        mutation: RefundLifecycleMutation<'_>,
    ) -> Result<StoredTransitionV1, StoreError> {
        let mut database = self.database.lock().map_err(|_| StoreError::Unavailable)?;
        let mut next = database.clone();
        let stored = transact_lifecycle_in(&mut next, transaction, mutation)?;
        *database = next;
        Ok(stored)
    }

    fn load_refund_lifecycle(
        &self,
        workflow: &WorkflowId,
    ) -> Result<Option<LifecycleRecordV1>, StoreError> {
        let database = self.database.lock().map_err(|_| StoreError::Unavailable)?;
        decode_lifecycle_record(&database.lifecycle_records, workflow)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReservationStateFile {
    schema: String,
    records: BTreeMap<String, RefundReservationRecord>,
    lifecycle_records: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone)]
struct ReservationDatabase {
    records: BTreeMap<String, RefundReservationRecord>,
    lifecycle_records: BTreeMap<String, Vec<u8>>,
}

impl ReservationDatabase {
    fn empty() -> Self {
        Self {
            records: BTreeMap::new(),
            lifecycle_records: BTreeMap::new(),
        }
    }
}

/// Crash-persistent, cross-process locked Stripe refund budget store.
pub struct PersistentRefundReservationStore {
    path: PathBuf,
    lock_path: PathBuf,
    process_lock: Mutex<()>,
}

impl PersistentRefundReservationStore {
    /// Opens and validates one canonical state file.
    ///
    /// # Errors
    ///
    /// Rejects malformed, non-canonical, oversized, or invalid state.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, ReservationError> {
        let path = path.into();
        let parent = path.parent().ok_or(ReservationError::Unavailable)?;
        fs::create_dir_all(parent).map_err(|_| ReservationError::Unavailable)?;
        let lock_path = path.with_extension("lock");
        let store = Self {
            path,
            lock_path,
            process_lock: Mutex::new(()),
        };
        store.with_locked_database(|_| Ok(()))?;
        Ok(store)
    }

    fn with_locked_database<T, E>(
        &self,
        operation: impl FnOnce(&mut ReservationDatabase) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<ReservationError>,
    {
        let _process_guard = self
            .process_lock
            .lock()
            .map_err(|_| E::from(ReservationError::Unavailable))?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.lock_path)
            .map_err(|_| E::from(ReservationError::Unavailable))?;
        lock.lock()
            .map_err(|_| E::from(ReservationError::Unavailable))?;
        let mut database = load_database(&self.path).map_err(E::from)?;
        let output = operation(&mut database)?;
        persist_database(&self.path, &database).map_err(E::from)?;
        lock.unlock()
            .map_err(|_| E::from(ReservationError::Unavailable))?;
        Ok(output)
    }
}

impl RefundReservationStore for PersistentRefundReservationStore {
    fn snapshot(
        &self,
        policy: &StripeBoundedRefundPolicyV1,
        account: &StripeAccountId,
        now: u64,
    ) -> Result<AggregateBudgetSnapshot, ReservationError> {
        self.with_locked_database(|database| snapshot_in(&database.records, policy, account, now))
    }

    fn reserve(&self, request: ReserveRefundRequest) -> ReserveRefundResult {
        self.with_locked_database(|database| {
            Ok::<_, ReservationError>(reserve_in(&mut database.records, request))
        })
        .unwrap_or(ReserveRefundResult::Unavailable)
    }

    fn commit(
        &self,
        lease: &RefundReservationLease,
        refund_id: &RefundId,
        result_digest: &DigestHex,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError> {
        self.with_locked_database(|database| {
            commit_in(&mut database.records, lease, refund_id, result_digest, now)
        })
    }

    fn release(
        &self,
        lease: &RefundReservationLease,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError> {
        self.with_locked_database(|database| {
            transition_in(
                &mut database.records,
                lease,
                RefundReservationState::Released,
                now,
            )
        })
    }

    fn mark_outcome_unknown(
        &self,
        lease: &RefundReservationLease,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError> {
        self.with_locked_database(|database| {
            transition_in(
                &mut database.records,
                lease,
                RefundReservationState::OutcomeUnknown,
                now,
            )
        })
    }

    fn reconcile(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: ReconciledRefundOutcome,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError> {
        self.with_locked_database(|database| {
            reconcile_in(
                &mut database.records,
                workflow_id,
                action_digest,
                outcome,
                now,
            )
        })
    }

    fn get(&self, workflow_id: &str) -> Result<Option<RefundReservationRecord>, ReservationError> {
        self.with_locked_database(|database| Ok(database.records.get(workflow_id).cloned()))
    }
}

impl RefundLifecycleStore for PersistentRefundReservationStore {
    fn transact_refund_lifecycle(
        &self,
        transaction: &StoreTransactionV1,
        mutation: RefundLifecycleMutation<'_>,
    ) -> Result<StoredTransitionV1, StoreError> {
        self.with_locked_database(|database| transact_lifecycle_in(database, transaction, mutation))
    }

    fn load_refund_lifecycle(
        &self,
        workflow: &WorkflowId,
    ) -> Result<Option<LifecycleRecordV1>, StoreError> {
        self.with_locked_database(|database| {
            decode_lifecycle_record(&database.lifecycle_records, workflow)
        })
    }
}

fn transact_lifecycle_in(
    database: &mut ReservationDatabase,
    transaction: &StoreTransactionV1,
    mutation: RefundLifecycleMutation<'_>,
) -> Result<StoredTransitionV1, StoreError> {
    let current = decode_lifecycle_record(&database.lifecycle_records, &transaction.workflow_id)?;
    if current.as_ref().map(LifecycleRecordV1::revision) != transaction.expected_revision {
        return Err(StoreError::Conflict);
    }
    if current.is_none() && database.lifecycle_records.len() >= MAX_RECORDS {
        return Err(StoreError::LimitExceeded);
    }
    apply_domain_mutation(database, transaction, mutation)?;
    let result = apply_transition(current.as_ref(), &transaction.command, &transaction.context)
        .map_err(|error| StoreError::Rejected(error.failure))?;
    if result.disposition == TransitionDisposition::Applied {
        let encoded = encode_record(&result.record).map_err(|_| StoreError::Corrupt)?;
        database
            .lifecycle_records
            .insert(transaction.workflow_id.as_str().into(), encoded);
    }
    Ok(StoredTransitionV1::acknowledged(
        result.record,
        result.disposition,
    ))
}

fn apply_domain_mutation(
    database: &mut ReservationDatabase,
    transaction: &StoreTransactionV1,
    mutation: RefundLifecycleMutation<'_>,
) -> Result<(), StoreError> {
    match mutation {
        RefundLifecycleMutation::None => {
            if matches!(
                transaction.command,
                TransitionCommandV1::Reserve
                    | TransitionCommandV1::Commit { .. }
                    | TransitionCommandV1::Release { .. }
                    | TransitionCommandV1::MarkOutcomeUnknown { .. }
                    | TransitionCommandV1::Reconcile { .. }
            ) {
                return Err(StoreError::Corrupt);
            }
        }
        RefundLifecycleMutation::Reserve { policy, request } => {
            reserve_lifecycle_in(database, transaction, policy, *request)?;
        }
        RefundLifecycleMutation::Commit {
            lease,
            refund_id,
            result_digest,
            now,
        } => {
            let TransitionCommandV1::Commit {
                result_digest: expected,
                ..
            } = &transaction.command
            else {
                return Err(StoreError::Corrupt);
            };
            if expected.bytes() != shared_digest(result_digest)?.as_bytes() {
                return Err(StoreError::Corrupt);
            }
            commit_in(&mut database.records, lease, refund_id, result_digest, now)
                .map_err(map_reservation_error)?;
        }
        RefundLifecycleMutation::Release { lease, now } => {
            if !matches!(transaction.command, TransitionCommandV1::Release { .. }) {
                return Err(StoreError::Corrupt);
            }
            transition_in(
                &mut database.records,
                lease,
                RefundReservationState::Released,
                now,
            )
            .map_err(map_reservation_error)?;
        }
        RefundLifecycleMutation::OutcomeUnknown { lease, now } => {
            if !matches!(
                transaction.command,
                TransitionCommandV1::MarkOutcomeUnknown { .. }
            ) {
                return Err(StoreError::Corrupt);
            }
            transition_in(
                &mut database.records,
                lease,
                RefundReservationState::OutcomeUnknown,
                now,
            )
            .map_err(map_reservation_error)?;
        }
        RefundLifecycleMutation::Reconcile {
            workflow_id,
            action_digest,
            outcome,
            now,
        } => {
            let TransitionCommandV1::Reconcile { observation, .. } = &transaction.command else {
                return Err(StoreError::Corrupt);
            };
            let conclusion_matches = matches!(
                (&outcome, observation.conclusion),
                (
                    ReconciledRefundOutcome::Committed { .. },
                    auths_lifecycle::EffectConclusion::Effect
                ) | (
                    ReconciledRefundOutcome::Released,
                    auths_lifecycle::EffectConclusion::NonEffect
                )
            );
            if workflow_id != transaction.workflow_id.as_str() || !conclusion_matches {
                return Err(StoreError::Corrupt);
            }
            reconcile_in(
                &mut database.records,
                workflow_id,
                action_digest,
                outcome,
                now,
            )
            .map_err(map_reservation_error)?;
        }
    }
    Ok(())
}

fn reserve_lifecycle_in(
    database: &mut ReservationDatabase,
    transaction: &StoreTransactionV1,
    policy: &StripeBoundedRefundPolicyV1,
    request: ReserveRefundRequest,
) -> Result<(), StoreError> {
    if !matches!(transaction.command, TransitionCommandV1::Reserve)
        || request.workflow_id != transaction.workflow_id.as_str()
    {
        return Err(StoreError::Corrupt);
    }
    let snapshot = snapshot_in(
        &database.records,
        policy,
        &request.stripe_account_id,
        request.now,
    )
    .map_err(map_reservation_error)?;
    let expected_capacity = crate::lifecycle::project_capacity_snapshot(
        request.stripe_account_id.as_str(),
        &request.intents,
        &snapshot,
    )
    .map_err(|_| StoreError::Corrupt)?;
    if transaction.context.capacity != expected_capacity {
        return Err(StoreError::Corrupt);
    }
    match reserve_in(&mut database.records, request) {
        ReserveRefundResult::Reserved { .. } => Ok(()),
        ReserveRefundResult::Replay(_) | ReserveRefundResult::Conflict(_) => {
            Err(StoreError::Conflict)
        }
        ReserveRefundResult::CapacityExceeded { .. } => Err(StoreError::Rejected(
            auths_lifecycle::LifecycleFailure::CapacityExceeded,
        )),
        ReserveRefundResult::Unavailable => Err(StoreError::Unavailable),
    }
}

fn shared_digest(value: &DigestHex) -> Result<auths_bounded_policy::CommitmentDigest, StoreError> {
    let decoded = hex::decode(value.as_str()).map_err(|_| StoreError::Corrupt)?;
    let bytes: [u8; 32] = decoded.try_into().map_err(|_| StoreError::Corrupt)?;
    Ok(auths_bounded_policy::CommitmentDigest::new(bytes))
}

fn decode_lifecycle_record(
    records: &BTreeMap<String, Vec<u8>>,
    workflow: &WorkflowId,
) -> Result<Option<LifecycleRecordV1>, StoreError> {
    records
        .get(workflow.as_str())
        .map(|bytes| decode_record(bytes).map_err(|_| StoreError::Corrupt))
        .transpose()
}

fn map_reservation_error(error: ReservationError) -> StoreError {
    match error {
        ReservationError::Unavailable => StoreError::Unavailable,
        ReservationError::Corrupt => StoreError::Corrupt,
        ReservationError::Missing
        | ReservationError::Conflict
        | ReservationError::InvalidTransition => StoreError::Conflict,
    }
}

fn load_database(path: &Path) -> Result<ReservationDatabase, ReservationError> {
    if !path.exists() {
        return Ok(ReservationDatabase::empty());
    }
    let bytes = fs::read(path).map_err(|_| ReservationError::Unavailable)?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(ReservationError::Corrupt);
    }
    let state: ReservationStateFile =
        serde_json::from_slice(&bytes).map_err(|_| ReservationError::Corrupt)?;
    validate_database_state(&state, &bytes)?;
    Ok(ReservationDatabase {
        records: state.records,
        lifecycle_records: state.lifecycle_records,
    })
}

fn validate_database_state(
    state: &ReservationStateFile,
    canonical_bytes: &[u8],
) -> Result<(), ReservationError> {
    if state.schema != STATE_SCHEMA
        || state.records.len() > MAX_RECORDS
        || state.lifecycle_records.len() > MAX_RECORDS
        || canonical_json(state).map_err(|_| ReservationError::Corrupt)? != canonical_bytes
        || state
            .records
            .iter()
            .any(|(workflow, record)| workflow != &record.workflow_id || !valid_record(record))
        || state.lifecycle_records.iter().any(|(workflow, bytes)| {
            auths_lifecycle::WorkflowId::parse(workflow).is_err()
                || auths_lifecycle::decode_record(bytes).is_err()
        })
    {
        Err(ReservationError::Corrupt)
    } else {
        Ok(())
    }
}

fn persist_database(path: &Path, database: &ReservationDatabase) -> Result<(), ReservationError> {
    if database.records.len() > MAX_RECORDS || database.lifecycle_records.len() > MAX_RECORDS {
        return Err(ReservationError::Unavailable);
    }
    let state = ReservationStateFile {
        schema: STATE_SCHEMA.into(),
        records: database.records.clone(),
        lifecycle_records: database.lifecycle_records.clone(),
    };
    let bytes = canonical_json(&state).map_err(|_| ReservationError::Corrupt)?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(ReservationError::Unavailable);
    }
    let parent = path.parent().ok_or(ReservationError::Unavailable)?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(|_| ReservationError::Unavailable)?;
    temporary
        .write_all(&bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| ReservationError::Unavailable)?;
    temporary
        .persist(path)
        .map_err(|_| ReservationError::Unavailable)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ReservationError::Unavailable)
}

fn valid_record(record: &RefundReservationRecord) -> bool {
    let identity = ReservationIdentity {
        domain: RESERVATION_SCHEMA,
        policy_digest: &record.policy_digest,
        action_digest: &record.action_digest,
        workflow_id: &record.workflow_id,
        intents: record
            .intents
            .iter()
            .map(|intent| ReservationIdentityIntent {
                budget_id: &intent.budget_id,
                currency: &intent.currency,
                window: &intent.window,
                limit_minor: intent.limit_minor,
                amount_minor: intent.amount_minor,
            })
            .collect(),
    };
    let identity_valid =
        canonical_json(&identity).is_ok_and(|bytes| sha256(&bytes) == record.reservation_id);
    let result_shape_valid = match record.state {
        RefundReservationState::Committed | RefundReservationState::ReconciledCommitted => {
            record.refund_id.is_some() && record.result_digest.is_some()
        }
        RefundReservationState::Reserved
        | RefundReservationState::Released
        | RefundReservationState::OutcomeUnknown
        | RefundReservationState::ReconciledReleased => {
            record.refund_id.is_none() && record.result_digest.is_none()
        }
    };
    record.schema == RESERVATION_SCHEMA
        && identity_valid
        && valid_workflow_id(&record.workflow_id)
        && record.amount_minor > 0
        && record.updated_at >= record.created_at
        && record.evaluator_semantic_id == crate::bounded::BOUNDED_EVALUATOR_ID
        && record.evaluator_semantic_version == crate::bounded::BOUNDED_EVALUATOR_VERSION
        && !record.intents.is_empty()
        && record.intents.len() <= 8
        && record.intents.iter().all(|intent| {
            intent.amount_minor == record.amount_minor
                && intent.currency == record.currency
                && intent.amount_minor <= intent.limit_minor
                && intent.window.starts_at < intent.window.ends_at
                && matches!(intent.window.kind.as_str(), "fixed" | "rolling")
        })
        && record
            .intents
            .windows(2)
            .all(|pair| pair[0].budget_id < pair[1].budget_id)
        && result_shape_valid
}

fn snapshot_in(
    records: &BTreeMap<String, RefundReservationRecord>,
    policy: &StripeBoundedRefundPolicyV1,
    account: &StripeAccountId,
    now: u64,
) -> Result<AggregateBudgetSnapshot, ReservationError> {
    let policy_digest = policy.digest().map_err(|_| ReservationError::Corrupt)?;
    let mut usages = Vec::new();
    for budget in policy.aggregate_budgets() {
        let window = budget
            .window()
            .identity(now)
            .map_err(|_| ReservationError::InvalidTransition)?;
        let mut usage = AggregateBudgetUsage {
            budget_id: budget.budget_id().into(),
            window: window.clone(),
            committed_minor: 0,
            reserved_minor: 0,
            outcome_unknown_minor: 0,
        };
        for record in records.values().filter(|record| {
            record.policy_digest == policy_digest
                && &record.stripe_account_id == account
                && record.currency == *budget.currency()
                && record_holds_capacity_in(record, budget.budget_id(), &window)
        }) {
            let target =
                match record.state {
                    RefundReservationState::Reserved => &mut usage.reserved_minor,
                    RefundReservationState::Committed
                    | RefundReservationState::ReconciledCommitted => &mut usage.committed_minor,
                    RefundReservationState::OutcomeUnknown => &mut usage.outcome_unknown_minor,
                    RefundReservationState::Released
                    | RefundReservationState::ReconciledReleased => continue,
                };
            *target = target
                .checked_add(record.amount_minor)
                .ok_or(ReservationError::Corrupt)?;
        }
        usages.push(usage);
    }
    Ok(AggregateBudgetSnapshot { usages })
}

fn reserve_in(
    records: &mut BTreeMap<String, RefundReservationRecord>,
    request: ReserveRefundRequest,
) -> ReserveRefundResult {
    if !valid_workflow_id(&request.workflow_id)
        || request.amount_minor == 0
        || request.intents.is_empty()
        || request
            .intents
            .iter()
            .any(|intent| intent.amount_minor != request.amount_minor)
    {
        return ReserveRefundResult::Unavailable;
    }
    if let Some(existing) = records.get(&request.workflow_id) {
        return if is_exact_replay(existing, &request) {
            ReserveRefundResult::Replay(existing.clone())
        } else {
            ReserveRefundResult::Conflict(existing.clone())
        };
    }
    let Ok(reservation_id) = request.reservation_id() else {
        return ReserveRefundResult::Unavailable;
    };
    for intent in &request.intents {
        let mut used = 0_u64;
        for existing in records.values().filter(|record| {
            record.policy_digest == request.policy_digest
                && record.stripe_account_id == request.stripe_account_id
                && record.currency == request.currency
                && !matches!(
                    record.state,
                    RefundReservationState::Released | RefundReservationState::ReconciledReleased
                )
                && record_holds_capacity_in(record, &intent.budget_id, &intent.window)
        }) {
            let Some(next) = used.checked_add(existing.amount_minor) else {
                return ReserveRefundResult::Unavailable;
            };
            used = next;
        }
        let Some(available) = intent.limit_minor.checked_sub(used) else {
            return ReserveRefundResult::Unavailable;
        };
        if request.amount_minor > available {
            return ReserveRefundResult::CapacityExceeded {
                budget_id: intent.budget_id.clone(),
                available_minor: available,
            };
        }
    }
    if records.len() >= MAX_RECORDS {
        return ReserveRefundResult::Unavailable;
    }
    let workflow_id = request.workflow_id.clone();
    let action_digest = request.action_digest.clone();
    let record = request.into_record(reservation_id.clone());
    records.insert(workflow_id.clone(), record.clone());
    ReserveRefundResult::Reserved {
        lease: RefundReservationLease {
            workflow_id,
            reservation_id,
            action_digest,
        },
        record,
    }
}

fn is_exact_replay(existing: &RefundReservationRecord, request: &ReserveRefundRequest) -> bool {
    existing.action_digest == request.action_digest
        && existing.policy_digest == request.policy_digest
        && existing.evaluator_semantic_id == request.evaluator_semantic_id
        && existing.evaluator_semantic_version == request.evaluator_semantic_version
        && existing.required_configuration_digest == request.required_configuration_digest
        && existing.executed_configuration_digest == request.executed_configuration_digest
        && existing.stripe_account_id == request.stripe_account_id
        && existing.currency == request.currency
        && existing.amount_minor == request.amount_minor
        && existing.idempotency_key_digest == request.idempotency_key_digest
        && existing.intents.len() == request.intents.len()
        && existing
            .intents
            .iter()
            .zip(&request.intents)
            .all(|(left, right)| {
                left.budget_id == right.budget_id
                    && left.currency == right.currency
                    && left.limit_minor == right.limit_minor
                    && left.amount_minor == right.amount_minor
                    && left.window.kind == right.window.kind
            })
}

fn record_holds_capacity_in(
    record: &RefundReservationRecord,
    budget_id: &str,
    window: &crate::bounded::RefundWindowIdentity,
) -> bool {
    let same_budget_kind = record.intents.iter().any(|intent| {
        intent.budget_id == budget_id
            && if window.kind == "rolling" {
                intent.window.kind == "rolling"
            } else {
                intent.window == *window
            }
    });
    if !same_budget_kind {
        return false;
    }
    if window.kind == "rolling"
        && matches!(
            record.state,
            RefundReservationState::Committed | RefundReservationState::ReconciledCommitted
        )
    {
        return (window.starts_at..window.ends_at).contains(&record.created_at);
    }
    // Unfinished effects remain charged even after a rolling interval
    // advances. Only an explicit release/reconciliation returns capacity.
    matches!(
        record.state,
        RefundReservationState::Reserved
            | RefundReservationState::OutcomeUnknown
            | RefundReservationState::Committed
            | RefundReservationState::ReconciledCommitted
    )
}

fn commit_in(
    records: &mut BTreeMap<String, RefundReservationRecord>,
    lease: &RefundReservationLease,
    refund_id: &RefundId,
    result_digest: &DigestHex,
    now: u64,
) -> Result<RefundReservationRecord, ReservationError> {
    let record = record_for_lease(records, lease)?;
    if !matches!(
        record.state,
        RefundReservationState::Reserved | RefundReservationState::OutcomeUnknown
    ) {
        return Err(ReservationError::InvalidTransition);
    }
    record.state = RefundReservationState::Committed;
    record.refund_id = Some(refund_id.clone());
    record.result_digest = Some(result_digest.clone());
    record.updated_at = now;
    Ok(record.clone())
}

fn transition_in(
    records: &mut BTreeMap<String, RefundReservationRecord>,
    lease: &RefundReservationLease,
    next: RefundReservationState,
    now: u64,
) -> Result<RefundReservationRecord, ReservationError> {
    let record = record_for_lease(records, lease)?;
    let valid = matches!(
        (record.state, next),
        (
            RefundReservationState::Reserved,
            RefundReservationState::Released | RefundReservationState::OutcomeUnknown
        )
    );
    if !valid {
        return Err(ReservationError::InvalidTransition);
    }
    record.state = next;
    record.updated_at = now;
    Ok(record.clone())
}

fn reconcile_in(
    records: &mut BTreeMap<String, RefundReservationRecord>,
    workflow_id: &str,
    action_digest: &DigestHex,
    outcome: ReconciledRefundOutcome,
    now: u64,
) -> Result<RefundReservationRecord, ReservationError> {
    let record = records
        .get_mut(workflow_id)
        .ok_or(ReservationError::Missing)?;
    if record.action_digest != *action_digest
        || !matches!(
            record.state,
            RefundReservationState::Reserved | RefundReservationState::OutcomeUnknown
        )
    {
        return Err(ReservationError::InvalidTransition);
    }
    match outcome {
        ReconciledRefundOutcome::Committed {
            refund_id,
            result_digest,
        } => {
            record.state = RefundReservationState::ReconciledCommitted;
            record.refund_id = Some(refund_id);
            record.result_digest = Some(result_digest);
        }
        ReconciledRefundOutcome::Released => {
            record.state = RefundReservationState::ReconciledReleased;
        }
    }
    record.updated_at = now;
    Ok(record.clone())
}

fn record_for_lease<'a>(
    records: &'a mut BTreeMap<String, RefundReservationRecord>,
    lease: &RefundReservationLease,
) -> Result<&'a mut RefundReservationRecord, ReservationError> {
    let record = records
        .get_mut(&lease.workflow_id)
        .ok_or(ReservationError::Missing)?;
    if record.reservation_id != lease.reservation_id || record.action_digest != lease.action_digest
    {
        return Err(ReservationError::Conflict);
    }
    Ok(record)
}

fn valid_workflow_id(value: &str) -> bool {
    (8..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Closed Stripe refund reservation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReservationError {
    /// Durable state is unavailable.
    #[error("Stripe refund reservation state is unavailable")]
    Unavailable,
    /// State bytes or invariants are corrupt.
    #[error("Stripe refund reservation state is corrupt")]
    Corrupt,
    /// Reservation is missing.
    #[error("Stripe refund reservation is missing")]
    Missing,
    /// Lease or exact inputs conflict.
    #[error("Stripe refund reservation conflicts")]
    Conflict,
    /// Lifecycle transition is illegal.
    #[error("invalid Stripe refund reservation transition")]
    InvalidTransition,
}

impl From<ReservationError> for StoreError {
    fn from(error: ReservationError) -> Self {
        map_reservation_error(error)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        bounded::{BoundedEvaluationContext, RefundDenominator, evaluate_bounded_refund},
        canonical::canonical_digest,
        lifecycle::{
            StripeLifecycleDecisionBindings, StripeLifecycleProjectionInput,
            project_refund_lifecycle,
        },
        test_support::{
            NOW, bounded_action, bounded_configuration, bounded_policy, configuration, evidence,
        },
    };
    use auths_lifecycle::{
        LifecycleState, StoreTransactionV1, TransitionCommandV1, execute_store_transaction,
    };

    fn request(
        store: &dyn RefundReservationStore,
        workflow: &str,
        amount: u64,
    ) -> ReserveRefundRequest {
        let evidence = evidence(2_000, 0);
        let exact = configuration(2_000);
        let policy = bounded_policy(
            &evidence,
            2_000,
            10_000,
            RefundDenominator::OriginalChargeAmount,
            1_000,
        );
        request_for_policy(store, workflow, amount, &evidence, &exact, &policy)
    }

    fn request_for_policy(
        store: &dyn RefundReservationStore,
        workflow: &str,
        amount: u64,
        evidence: &crate::types::RefundEvidenceV1,
        exact: &crate::types::StripeVerifierConfiguration,
        policy: &StripeBoundedRefundPolicyV1,
    ) -> ReserveRefundRequest {
        let bounded = bounded_configuration(policy);
        let action = bounded_action(exact, policy, evidence, amount, workflow);
        let snapshot = store
            .snapshot(policy, evidence.stripe_account_id(), NOW)
            .unwrap();
        let decision = evaluate_bounded_refund(&BoundedEvaluationContext {
            policy,
            action: &action,
            evidence,
            aggregate_snapshot: &snapshot,
            required_exact_configuration: exact,
            executed_exact_configuration: exact,
            required_bounded_configuration: &bounded,
            executed_bounded_configuration: &bounded,
            request_audience: exact.executor_audience(),
            now: NOW,
        });
        ReserveRefundRequest {
            workflow_id: workflow.into(),
            action_digest: action.digest().unwrap(),
            decision_receipt_digest: sha256(b"bounded-decision-receipt"),
            policy_digest: policy.digest().unwrap(),
            evaluator_semantic_id: policy.evaluator_semantic_id().into(),
            evaluator_semantic_version: policy.evaluator_semantic_version(),
            evidence_digest: evidence.digest().unwrap(),
            required_configuration_digest: bounded.digest().unwrap(),
            executed_configuration_digest: bounded.digest().unwrap(),
            stripe_account_id: evidence.stripe_account_id().clone(),
            currency: evidence.currency().clone(),
            amount_minor: amount,
            intents: decision.eligibility.unwrap().reservations,
            idempotency_key_digest: sha256(action.idempotency_key().as_bytes()),
            now: NOW,
        }
    }

    #[test]
    fn shared_reservation_and_stripe_capacity_commit_atomically() {
        let store = InMemoryRefundReservationStore::default();
        let exact = configuration(2_000);
        let evidence = evidence(2_000, 0);
        let policy = bounded_policy(
            &evidence,
            2_000,
            10_000,
            RefundDenominator::OriginalChargeAmount,
            1_000,
        );
        let workflow = "bounded-lifecycle-atomic-01";
        let action = bounded_action(&exact, &policy, &evidence, 1_000, workflow);
        let bounded = bounded_configuration(&policy);
        let snapshot = store
            .snapshot(&policy, evidence.stripe_account_id(), NOW)
            .unwrap();
        let decision = evaluate_bounded_refund(&BoundedEvaluationContext {
            policy: &policy,
            action: &action,
            evidence: &evidence,
            aggregate_snapshot: &snapshot,
            required_exact_configuration: &exact,
            executed_exact_configuration: &exact,
            required_bounded_configuration: &bounded,
            executed_bounded_configuration: &bounded,
            request_audience: exact.executor_audience(),
            now: NOW,
        });
        let projection = project_refund_lifecycle(&StripeLifecycleProjectionInput {
            action: &action,
            policy: &policy,
            evidence: &evidence,
            aggregate_snapshot: &snapshot,
            decision: &decision,
            required_configuration: &bounded,
            executed_configuration: &bounded,
            verifier_time: NOW,
        })
        .unwrap();
        let context = projection.transition_context(NOW);
        let workflow_id = projection.workflow_id.clone();
        let decision_digest = sha256(b"stripe-domain-decision");
        let decision_input = projection
            .into_decision_input(&StripeLifecycleDecisionBindings {
                core_authorization_digest: &sha256(b"stripe-core-authorization"),
                decision_receipt_digest: &decision_digest,
                domain_decision_receipt_digest: &decision_digest,
                implementation_build_digest: &sha256(b"stripe-test-build"),
                expires_at: action.expires_at(),
            })
            .unwrap();
        let recorded = execute_store_transaction(
            &RefundLifecycleTransaction::new(&store, RefundLifecycleMutation::None),
            &StoreTransactionV1 {
                workflow_id: workflow_id.clone(),
                expected_revision: None,
                command: TransitionCommandV1::RecordDecision(Box::new(decision_input)),
                context: context.clone(),
            },
        )
        .unwrap();
        assert_eq!(recorded.record().state(), LifecycleState::DecisionRecorded);

        let reserved = execute_store_transaction(
            &RefundLifecycleTransaction::new(
                &store,
                RefundLifecycleMutation::Reserve {
                    policy: &policy,
                    request: Box::new(request_for_policy(
                        &store, workflow, 1_000, &evidence, &exact, &policy,
                    )),
                },
            ),
            &StoreTransactionV1 {
                workflow_id: workflow_id.clone(),
                expected_revision: Some(recorded.record().revision()),
                command: TransitionCommandV1::Reserve,
                context,
            },
        )
        .unwrap();

        assert_eq!(reserved.record().state(), LifecycleState::Reserved);
        let domain = store.get(workflow).unwrap().unwrap();
        assert_eq!(domain.state(), RefundReservationState::Reserved);
        assert_eq!(domain.action_digest(), &action.digest().unwrap());
        assert_eq!(
            store.load_refund_lifecycle(&workflow_id).unwrap().unwrap(),
            *reserved.record()
        );
    }

    #[test]
    fn concurrent_last_capacity_reserves_once() {
        let store = Arc::new(InMemoryRefundReservationStore::default());
        let requests = (0..8)
            .map(|index| {
                let workflow = format!("bounded-concurrent-{index:02}");
                request(store.as_ref(), &workflow, 1_000)
            })
            .collect::<Vec<_>>();
        let handles = requests
            .into_iter()
            .map(|request| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || store.reserve(request))
            })
            .collect::<Vec<_>>();
        let reserved = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|result| matches!(result, ReserveRefundResult::Reserved { .. }))
            .count();
        assert_eq!(reserved, 1);
    }

    #[test]
    fn exact_replay_across_a_rolling_window_tick_is_not_a_conflict() {
        let evidence = evidence(2_000, 0);
        let exact = configuration(2_000);
        let mut input = crate::test_support::bounded_policy_input(&evidence);
        input.aggregate_budgets = vec![
            crate::bounded::AggregateRefundBudget::new(
                "support-rolling",
                evidence.currency().clone(),
                2_500,
                crate::bounded::RefundBudgetWindow::Rolling {
                    duration_seconds: 3_600,
                },
            )
            .unwrap(),
        ];
        let policy = StripeBoundedRefundPolicyV1::new(input).unwrap();
        let store = InMemoryRefundReservationStore::default();
        let first = request_for_policy(
            &store,
            "bounded-rolling-replay-01",
            1_000,
            &evidence,
            &exact,
            &policy,
        );
        assert!(matches!(
            store.reserve(first),
            ReserveRefundResult::Reserved { .. }
        ));

        let mut replay = request_for_policy(
            &store,
            "bounded-rolling-replay-01",
            1_000,
            &evidence,
            &exact,
            &policy,
        );
        replay.now = replay.now.checked_add(1).unwrap();
        let rolling = replay
            .intents
            .iter_mut()
            .find(|intent| intent.window.kind == "rolling")
            .unwrap();
        rolling.window.starts_at = rolling.window.starts_at.checked_add(1).unwrap();
        rolling.window.ends_at = rolling.window.ends_at.checked_add(1).unwrap();

        assert!(matches!(
            store.reserve(replay),
            ReserveRefundResult::Replay(_)
        ));
    }

    #[test]
    fn unknown_capacity_is_held_until_reconciled() {
        let store = InMemoryRefundReservationStore::default();
        let ReserveRefundResult::Reserved { lease, record } =
            store.reserve(request(&store, "bounded-unknown-01", 1_000))
        else {
            panic!("reservation expected")
        };
        store.mark_outcome_unknown(&lease, NOW + 1).unwrap();
        let evidence = evidence(2_000, 0);
        let policy = bounded_policy(
            &evidence,
            2_000,
            10_000,
            RefundDenominator::OriginalChargeAmount,
            1_000,
        );
        let snapshot = store
            .snapshot(&policy, evidence.stripe_account_id(), NOW)
            .unwrap();
        assert_eq!(snapshot.usages[0].outcome_unknown_minor, 1_000);

        let result_digest = canonical_digest(&record).unwrap();
        let reconciled = store
            .reconcile(
                "bounded-unknown-01",
                record.action_digest(),
                ReconciledRefundOutcome::Committed {
                    refund_id: RefundId::parse("re_authsdemo00000999").unwrap(),
                    result_digest,
                },
                NOW + 2,
            )
            .unwrap();
        assert_eq!(
            reconciled.state(),
            RefundReservationState::ReconciledCommitted
        );
    }

    #[test]
    fn persistent_state_survives_restart_and_is_canonical() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("bounded-reservations.json");
        {
            let store = PersistentRefundReservationStore::open(&path).unwrap();
            assert!(matches!(
                store.reserve(request(&store, "bounded-restart-01", 500)),
                ReserveRefundResult::Reserved { .. }
            ));
        }
        let reopened = PersistentRefundReservationStore::open(&path).unwrap();
        let reserved = reopened.get("bounded-restart-01").unwrap().unwrap();
        assert_eq!(reserved.state(), RefundReservationState::Reserved);
        let reconciled = reopened
            .reconcile(
                "bounded-restart-01",
                reserved.action_digest(),
                ReconciledRefundOutcome::Released,
                NOW + 1,
            )
            .unwrap();
        assert_eq!(
            reconciled.state(),
            RefundReservationState::ReconciledReleased
        );
    }

    #[test]
    fn obsolete_prelaunch_state_is_rejected_instead_of_migrated() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("bounded-reservations.json");
        fs::write(
            &path,
            br#"{"records":{},"schema":"auths.stripe.bounded-reservation-state/1"}"#,
        )
        .unwrap();
        assert!(matches!(
            PersistentRefundReservationStore::open(&path),
            Err(ReservationError::Corrupt)
        ));
    }

    #[test]
    fn definite_non_execution_releases_capacity() {
        let store = InMemoryRefundReservationStore::default();
        let ReserveRefundResult::Reserved { lease, .. } =
            store.reserve(request(&store, "bounded-release-01", 1_000))
        else {
            panic!("reservation expected")
        };
        let released = store.release(&lease, NOW + 1).unwrap();
        assert_eq!(released.state(), RefundReservationState::Released);

        let evidence = evidence(2_000, 0);
        let policy = bounded_policy(
            &evidence,
            2_000,
            10_000,
            RefundDenominator::OriginalChargeAmount,
            1_000,
        );
        let snapshot = store
            .snapshot(&policy, evidence.stripe_account_id(), NOW)
            .unwrap();
        assert_eq!(snapshot.usages[0].reserved_minor, 0);
        assert_eq!(snapshot.usages[0].committed_minor, 0);
        assert_eq!(snapshot.usages[0].outcome_unknown_minor, 0);
    }

    #[test]
    fn rolling_window_slides_and_unresolved_capacity_does_not_age_out() {
        let evidence = evidence(2_000, 0);
        let exact = configuration(2_000);
        let mut input = crate::test_support::bounded_policy_input(&evidence);
        input.aggregate_budgets = vec![
            crate::bounded::AggregateRefundBudget::new(
                "support-rolling",
                evidence.currency().clone(),
                1_000,
                crate::bounded::RefundBudgetWindow::Rolling {
                    duration_seconds: 3_600,
                },
            )
            .unwrap(),
        ];
        let policy = StripeBoundedRefundPolicyV1::new(input).unwrap();

        let committed_store = InMemoryRefundReservationStore::default();
        let ReserveRefundResult::Reserved { lease, record } =
            committed_store.reserve(request_for_policy(
                &committed_store,
                "bounded-rolling-committed-01",
                1_000,
                &evidence,
                &exact,
                &policy,
            ))
        else {
            panic!("reservation expected")
        };
        committed_store
            .commit(
                &lease,
                &RefundId::parse("re_authsdemo00000888").unwrap(),
                &canonical_digest(&record).unwrap(),
                NOW + 1,
            )
            .unwrap();
        let after_window = committed_store
            .snapshot(&policy, evidence.stripe_account_id(), NOW + 3_600)
            .unwrap();
        assert_eq!(after_window.usages[0].committed_minor, 0);

        let unknown_store = InMemoryRefundReservationStore::default();
        let ReserveRefundResult::Reserved { lease, .. } =
            unknown_store.reserve(request_for_policy(
                &unknown_store,
                "bounded-rolling-unknown-01",
                1_000,
                &evidence,
                &exact,
                &policy,
            ))
        else {
            panic!("reservation expected")
        };
        unknown_store.mark_outcome_unknown(&lease, NOW + 1).unwrap();
        let unresolved = unknown_store
            .snapshot(&policy, evidence.stripe_account_id(), NOW + 3_600)
            .unwrap();
        assert_eq!(unresolved.usages[0].outcome_unknown_minor, 1_000);
    }
}
