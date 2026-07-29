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

use crate::{
    bounded::{
        AggregateBudgetSnapshot, AggregateBudgetUsage, RefundReservationIntent,
        StripeBoundedRefundPolicyV1,
    },
    canonical::{canonical_json, sha256},
    types::{Currency, DigestHex, RefundId, StripeAccountId},
};

const RESERVATION_SCHEMA: &str = "auths.stripe.bounded-reservation/1";
const STATE_SCHEMA: &str = "auths.stripe.bounded-reservation-state/1";
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
#[derive(Default)]
pub struct InMemoryRefundReservationStore {
    records: Mutex<BTreeMap<String, RefundReservationRecord>>,
}

impl InMemoryRefundReservationStore {
    /// Returns the number of live capacity-holding reservations.
    ///
    /// This operational projection does not expose lease material.
    #[must_use]
    pub fn active_reservation_count(&self) -> usize {
        self.records.lock().map_or(0, |records| {
            records
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
        let records = self
            .records
            .lock()
            .map_err(|_| ReservationError::Unavailable)?;
        snapshot_in(&records, policy, account, now)
    }

    fn reserve(&self, request: ReserveRefundRequest) -> ReserveRefundResult {
        let Ok(mut records) = self.records.lock() else {
            return ReserveRefundResult::Unavailable;
        };
        reserve_in(&mut records, request)
    }

    fn commit(
        &self,
        lease: &RefundReservationLease,
        refund_id: &RefundId,
        result_digest: &DigestHex,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| ReservationError::Unavailable)?;
        commit_in(&mut records, lease, refund_id, result_digest, now)
    }

    fn release(
        &self,
        lease: &RefundReservationLease,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| ReservationError::Unavailable)?;
        transition_in(&mut records, lease, RefundReservationState::Released, now)
    }

    fn mark_outcome_unknown(
        &self,
        lease: &RefundReservationLease,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| ReservationError::Unavailable)?;
        transition_in(
            &mut records,
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
        let mut records = self
            .records
            .lock()
            .map_err(|_| ReservationError::Unavailable)?;
        reconcile_in(&mut records, workflow_id, action_digest, outcome, now)
    }

    fn get(&self, workflow_id: &str) -> Result<Option<RefundReservationRecord>, ReservationError> {
        self.records
            .lock()
            .map(|records| records.get(workflow_id).cloned())
            .map_err(|_| ReservationError::Unavailable)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReservationStateFile {
    schema: String,
    records: BTreeMap<String, RefundReservationRecord>,
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
        store.with_locked_records(|_| Ok(()))?;
        Ok(store)
    }

    fn with_locked_records<T>(
        &self,
        operation: impl FnOnce(
            &mut BTreeMap<String, RefundReservationRecord>,
        ) -> Result<T, ReservationError>,
    ) -> Result<T, ReservationError> {
        let _process_guard = self
            .process_lock
            .lock()
            .map_err(|_| ReservationError::Unavailable)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.lock_path)
            .map_err(|_| ReservationError::Unavailable)?;
        lock.lock().map_err(|_| ReservationError::Unavailable)?;
        let mut records = load_records(&self.path)?;
        let output = operation(&mut records)?;
        persist_records(&self.path, &records)?;
        lock.unlock().map_err(|_| ReservationError::Unavailable)?;
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
        self.with_locked_records(|records| snapshot_in(records, policy, account, now))
    }

    fn reserve(&self, request: ReserveRefundRequest) -> ReserveRefundResult {
        self.with_locked_records(|records| Ok(reserve_in(records, request)))
            .unwrap_or(ReserveRefundResult::Unavailable)
    }

    fn commit(
        &self,
        lease: &RefundReservationLease,
        refund_id: &RefundId,
        result_digest: &DigestHex,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError> {
        self.with_locked_records(|records| commit_in(records, lease, refund_id, result_digest, now))
    }

    fn release(
        &self,
        lease: &RefundReservationLease,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError> {
        self.with_locked_records(|records| {
            transition_in(records, lease, RefundReservationState::Released, now)
        })
    }

    fn mark_outcome_unknown(
        &self,
        lease: &RefundReservationLease,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError> {
        self.with_locked_records(|records| {
            transition_in(records, lease, RefundReservationState::OutcomeUnknown, now)
        })
    }

    fn reconcile(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: ReconciledRefundOutcome,
        now: u64,
    ) -> Result<RefundReservationRecord, ReservationError> {
        self.with_locked_records(|records| {
            reconcile_in(records, workflow_id, action_digest, outcome, now)
        })
    }

    fn get(&self, workflow_id: &str) -> Result<Option<RefundReservationRecord>, ReservationError> {
        self.with_locked_records(|records| Ok(records.get(workflow_id).cloned()))
    }
}

fn load_records(
    path: &Path,
) -> Result<BTreeMap<String, RefundReservationRecord>, ReservationError> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let bytes = fs::read(path).map_err(|_| ReservationError::Unavailable)?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(ReservationError::Corrupt);
    }
    let state: ReservationStateFile =
        serde_json::from_slice(&bytes).map_err(|_| ReservationError::Corrupt)?;
    if state.schema != STATE_SCHEMA
        || state.records.len() > MAX_RECORDS
        || canonical_json(&state).map_err(|_| ReservationError::Corrupt)? != bytes
        || state
            .records
            .iter()
            .any(|(workflow, record)| workflow != &record.workflow_id || !valid_record(record))
    {
        return Err(ReservationError::Corrupt);
    }
    Ok(state.records)
}

fn persist_records(
    path: &Path,
    records: &BTreeMap<String, RefundReservationRecord>,
) -> Result<(), ReservationError> {
    if records.len() > MAX_RECORDS {
        return Err(ReservationError::Unavailable);
    }
    let state = ReservationStateFile {
        schema: STATE_SCHEMA.into(),
        records: records.clone(),
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
    let Ok(reservation_id) = request.reservation_id() else {
        return ReserveRefundResult::Unavailable;
    };
    if let Some(existing) = records.get(&request.workflow_id) {
        return if existing.reservation_id == reservation_id
            && existing.action_digest == request.action_digest
            && existing.policy_digest == request.policy_digest
        {
            ReserveRefundResult::Replay(existing.clone())
        } else {
            ReserveRefundResult::Conflict(existing.clone())
        };
    }
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        bounded::{BoundedEvaluationContext, RefundDenominator, evaluate_bounded_refund},
        canonical::canonical_digest,
        test_support::{
            NOW, bounded_action, bounded_configuration, bounded_policy, configuration, evidence,
        },
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
