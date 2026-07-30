//! Durable atomic reservations for before/after Subscription transitions.

use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use super::{SubscriptionModifyItem, SubscriptionModifyProviderProjection};
use crate::{
    canonical::{canonical_digest, canonical_json},
    subscription::{ImmediateLiabilityReservation, RecurringLiabilityReservation},
    types::{CustomerId, DigestHex, StripeAccountId, SubscriptionId},
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubscriptionModificationState {
    Reserved,
    Claimed,
    Attempting,
    PendingPayment,
    Applied,
    OutcomeUnknown,
    Released,
    Expired,
}

impl SubscriptionModificationState {
    pub const fn holds_incremental_liability(self) -> bool {
        !matches!(self, Self::Released | Self::Expired)
    }
    pub const fn holds_immediate_debit(self) -> bool {
        matches!(
            self,
            Self::Reserved
                | Self::Claimed
                | Self::Attempting
                | Self::PendingPayment
                | Self::OutcomeUnknown
        )
    }
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Applied | Self::Released | Self::Expired)
    }
}

/// Public transition state. It contains commitments, never credentials.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionModificationRecord {
    schema: String,
    workflow_id: String,
    stripe_account_id: StripeAccountId,
    customer_id: CustomerId,
    subscription_id: SubscriptionId,
    action_digest: DigestHex,
    policy_digest: DigestHex,
    decision_receipt_digest: DigestHex,
    transition_id: DigestHex,
    before_subscription_digest: DigestHex,
    after_items: Vec<SubscriptionModifyItem>,
    before_recurring_minor: u64,
    after_recurring_minor: u64,
    before_term_liability_minor: u64,
    after_term_liability_minor: u64,
    incremental_term_liability_minor: u64,
    superseded_term_liability_minor: u64,
    proration_debit_minor: u64,
    proration_credit_minor: u64,
    recurring_reservations: Vec<RecurringLiabilityReservation>,
    immediate_reservations: Vec<ImmediateLiabilityReservation>,
    state: SubscriptionModificationState,
    provider: Option<SubscriptionModifyProviderProjection>,
    idempotency_key_commitment: DigestHex,
    created_at: u64,
    updated_at: u64,
}

impl SubscriptionModificationRecord {
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }
    pub const fn stripe_account_id(&self) -> &StripeAccountId {
        &self.stripe_account_id
    }
    pub const fn customer_id(&self) -> &CustomerId {
        &self.customer_id
    }
    pub const fn subscription_id(&self) -> &SubscriptionId {
        &self.subscription_id
    }
    pub const fn action_digest(&self) -> &DigestHex {
        &self.action_digest
    }
    pub const fn policy_digest(&self) -> &DigestHex {
        &self.policy_digest
    }
    pub const fn decision_receipt_digest(&self) -> &DigestHex {
        &self.decision_receipt_digest
    }
    pub const fn transition_id(&self) -> &DigestHex {
        &self.transition_id
    }
    pub const fn before_subscription_digest(&self) -> &DigestHex {
        &self.before_subscription_digest
    }
    pub fn after_items(&self) -> &[SubscriptionModifyItem] {
        &self.after_items
    }
    pub const fn before_recurring_minor(&self) -> u64 {
        self.before_recurring_minor
    }
    pub const fn after_recurring_minor(&self) -> u64 {
        self.after_recurring_minor
    }
    pub const fn before_term_liability_minor(&self) -> u64 {
        self.before_term_liability_minor
    }
    pub const fn after_term_liability_minor(&self) -> u64 {
        self.after_term_liability_minor
    }
    pub const fn incremental_term_liability_minor(&self) -> u64 {
        self.incremental_term_liability_minor
    }
    pub const fn superseded_term_liability_minor(&self) -> u64 {
        self.superseded_term_liability_minor
    }
    pub const fn proration_debit_minor(&self) -> u64 {
        self.proration_debit_minor
    }
    pub const fn proration_credit_minor(&self) -> u64 {
        self.proration_credit_minor
    }
    pub fn recurring_reservations(&self) -> &[RecurringLiabilityReservation] {
        &self.recurring_reservations
    }
    pub fn immediate_reservations(&self) -> &[ImmediateLiabilityReservation] {
        &self.immediate_reservations
    }
    pub const fn state(&self) -> SubscriptionModificationState {
        self.state
    }
    pub const fn provider(&self) -> Option<&SubscriptionModifyProviderProjection> {
        self.provider.as_ref()
    }
    pub const fn idempotency_key_commitment(&self) -> &DigestHex {
        &self.idempotency_key_commitment
    }
}

#[derive(Clone)]
pub struct ReserveSubscriptionModificationRequest {
    pub workflow_id: String,
    pub stripe_account_id: StripeAccountId,
    pub customer_id: CustomerId,
    pub subscription_id: SubscriptionId,
    pub action_digest: DigestHex,
    pub policy_digest: DigestHex,
    pub decision_receipt_digest: DigestHex,
    pub before_subscription_digest: DigestHex,
    pub after_items: Vec<SubscriptionModifyItem>,
    pub before_recurring_minor: u64,
    pub after_recurring_minor: u64,
    pub before_term_liability_minor: u64,
    pub after_term_liability_minor: u64,
    pub incremental_term_liability_minor: u64,
    pub superseded_term_liability_minor: u64,
    pub proration_debit_minor: u64,
    pub proration_credit_minor: u64,
    pub recurring_reservations: Vec<RecurringLiabilityReservation>,
    pub immediate_reservations: Vec<ImmediateLiabilityReservation>,
    pub now: u64,
}

#[derive(Serialize)]
struct TransitionIdentity<'a> {
    workflow_id: &'a str,
    subscription_id: &'a SubscriptionId,
    action_digest: &'a DigestHex,
    before_subscription_digest: &'a DigestHex,
}

pub enum ReserveSubscriptionModificationResult {
    Reserved(SubscriptionModificationRecord),
    Replay(SubscriptionModificationRecord),
    Conflict(SubscriptionModificationRecord),
    CapacityExceeded,
}

/// Shared persistence mechanics with a modify-owned transition method.
pub trait SubscriptionModificationStore: Send + Sync {
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<SubscriptionModificationRecord>, SubscriptionModificationStateError>;
    fn reserve_modify(
        &self,
        request: ReserveSubscriptionModificationRequest,
    ) -> Result<ReserveSubscriptionModificationResult, SubscriptionModificationStateError>;
    fn transition_modify(
        &self,
        workflow_id: &str,
        expected: SubscriptionModificationState,
        next: SubscriptionModificationState,
        provider: Option<SubscriptionModifyProviderProjection>,
        now: u64,
    ) -> Result<SubscriptionModificationRecord, SubscriptionModificationStateError>;
}

impl<T: SubscriptionModificationStore + ?Sized> SubscriptionModificationStore for Arc<T> {
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<SubscriptionModificationRecord>, SubscriptionModificationStateError> {
        (**self).get(workflow_id)
    }
    fn reserve_modify(
        &self,
        request: ReserveSubscriptionModificationRequest,
    ) -> Result<ReserveSubscriptionModificationResult, SubscriptionModificationStateError> {
        (**self).reserve_modify(request)
    }
    fn transition_modify(
        &self,
        workflow_id: &str,
        expected: SubscriptionModificationState,
        next: SubscriptionModificationState,
        provider: Option<SubscriptionModifyProviderProjection>,
        now: u64,
    ) -> Result<SubscriptionModificationRecord, SubscriptionModificationStateError> {
        (**self).transition_modify(workflow_id, expected, next, provider, now)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SubscriptionModificationStateError {
    #[error("subscription modification state unavailable")]
    Unavailable,
    #[error("subscription modification transition conflict")]
    Conflict,
    #[error("subscription modification state malformed")]
    Malformed,
}

#[derive(Default)]
pub struct InMemorySubscriptionModificationStore {
    records: Mutex<BTreeMap<String, SubscriptionModificationRecord>>,
}

impl SubscriptionModificationStore for InMemorySubscriptionModificationStore {
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<SubscriptionModificationRecord>, SubscriptionModificationStateError> {
        Ok(self
            .records
            .lock()
            .map_err(|_| SubscriptionModificationStateError::Unavailable)?
            .get(workflow_id)
            .cloned())
    }

    fn reserve_modify(
        &self,
        request: ReserveSubscriptionModificationRequest,
    ) -> Result<ReserveSubscriptionModificationResult, SubscriptionModificationStateError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| SubscriptionModificationStateError::Unavailable)?;
        reserve_in(&mut records, request)
    }

    fn transition_modify(
        &self,
        workflow_id: &str,
        expected: SubscriptionModificationState,
        next: SubscriptionModificationState,
        provider: Option<SubscriptionModifyProviderProjection>,
        now: u64,
    ) -> Result<SubscriptionModificationRecord, SubscriptionModificationStateError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| SubscriptionModificationStateError::Unavailable)?;
        transition_in(&mut records, workflow_id, expected, next, provider, now)
    }
}

pub struct PersistentSubscriptionModificationStore {
    path: PathBuf,
    records: Mutex<BTreeMap<String, SubscriptionModificationRecord>>,
}

impl PersistentSubscriptionModificationStore {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, SubscriptionModificationStateError> {
        let path = path.into();
        Ok(Self {
            records: Mutex::new(read_records(&path)?),
            path,
        })
    }
}

impl SubscriptionModificationStore for PersistentSubscriptionModificationStore {
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<SubscriptionModificationRecord>, SubscriptionModificationStateError> {
        Ok(self
            .records
            .lock()
            .map_err(|_| SubscriptionModificationStateError::Unavailable)?
            .get(workflow_id)
            .cloned())
    }

    fn reserve_modify(
        &self,
        request: ReserveSubscriptionModificationRequest,
    ) -> Result<ReserveSubscriptionModificationResult, SubscriptionModificationStateError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| SubscriptionModificationStateError::Unavailable)?;
        let result = reserve_in(&mut records, request)?;
        persist_records(&self.path, &records)?;
        Ok(result)
    }

    fn transition_modify(
        &self,
        workflow_id: &str,
        expected: SubscriptionModificationState,
        next: SubscriptionModificationState,
        provider: Option<SubscriptionModifyProviderProjection>,
        now: u64,
    ) -> Result<SubscriptionModificationRecord, SubscriptionModificationStateError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| SubscriptionModificationStateError::Unavailable)?;
        let result = transition_in(&mut records, workflow_id, expected, next, provider, now)?;
        persist_records(&self.path, &records)?;
        Ok(result)
    }
}

fn reserve_in(
    records: &mut BTreeMap<String, SubscriptionModificationRecord>,
    request: ReserveSubscriptionModificationRequest,
) -> Result<ReserveSubscriptionModificationResult, SubscriptionModificationStateError> {
    if let Some(existing) = records.get(&request.workflow_id) {
        return Ok(if existing.action_digest == request.action_digest {
            ReserveSubscriptionModificationResult::Replay(existing.clone())
        } else {
            ReserveSubscriptionModificationResult::Conflict(existing.clone())
        });
    }
    let recurring_capacity = request.recurring_reservations.iter().all(|candidate| {
        let used = records
            .values()
            .filter(|record| record.state.holds_incremental_liability())
            .flat_map(|record| &record.recurring_reservations)
            .filter(|held| held.budget_id == candidate.budget_id)
            .try_fold(0_u64, |total, held| total.checked_add(held.amount_minor));
        used.and_then(|value| value.checked_add(candidate.amount_minor))
            .is_some_and(|total| total <= candidate.limit_minor)
    });
    let immediate_capacity = request.immediate_reservations.iter().all(|candidate| {
        let used = records
            .values()
            .filter(|record| record.state.holds_immediate_debit())
            .flat_map(|record| &record.immediate_reservations)
            .filter(|held| held.budget_id == candidate.budget_id)
            .try_fold(0_u64, |total, held| total.checked_add(held.amount_minor));
        used.and_then(|value| value.checked_add(candidate.amount_minor))
            .is_some_and(|total| total <= candidate.limit_minor)
    });
    if !recurring_capacity || !immediate_capacity {
        return Ok(ReserveSubscriptionModificationResult::CapacityExceeded);
    }
    let transition_id = canonical_digest(&TransitionIdentity {
        workflow_id: &request.workflow_id,
        subscription_id: &request.subscription_id,
        action_digest: &request.action_digest,
        before_subscription_digest: &request.before_subscription_digest,
    })
    .map_err(|_| SubscriptionModificationStateError::Malformed)?;
    let idempotency_key_commitment =
        crate::canonical::sha256(format!("auths-sub-modify-{transition_id}").as_bytes());
    let record = SubscriptionModificationRecord {
        schema: "auths.stripe.subscription-modification-state/1".into(),
        workflow_id: request.workflow_id.clone(),
        stripe_account_id: request.stripe_account_id,
        customer_id: request.customer_id,
        subscription_id: request.subscription_id,
        action_digest: request.action_digest,
        policy_digest: request.policy_digest,
        decision_receipt_digest: request.decision_receipt_digest,
        transition_id,
        before_subscription_digest: request.before_subscription_digest,
        after_items: request.after_items,
        before_recurring_minor: request.before_recurring_minor,
        after_recurring_minor: request.after_recurring_minor,
        before_term_liability_minor: request.before_term_liability_minor,
        after_term_liability_minor: request.after_term_liability_minor,
        incremental_term_liability_minor: request.incremental_term_liability_minor,
        superseded_term_liability_minor: request.superseded_term_liability_minor,
        proration_debit_minor: request.proration_debit_minor,
        proration_credit_minor: request.proration_credit_minor,
        recurring_reservations: request.recurring_reservations,
        immediate_reservations: request.immediate_reservations,
        state: SubscriptionModificationState::Reserved,
        provider: None,
        idempotency_key_commitment,
        created_at: request.now,
        updated_at: request.now,
    };
    records.insert(request.workflow_id, record.clone());
    Ok(ReserveSubscriptionModificationResult::Reserved(record))
}

fn transition_in(
    records: &mut BTreeMap<String, SubscriptionModificationRecord>,
    workflow_id: &str,
    expected: SubscriptionModificationState,
    next: SubscriptionModificationState,
    provider: Option<SubscriptionModifyProviderProjection>,
    now: u64,
) -> Result<SubscriptionModificationRecord, SubscriptionModificationStateError> {
    let record = records
        .get_mut(workflow_id)
        .ok_or(SubscriptionModificationStateError::Conflict)?;
    if record.state != expected {
        return Err(SubscriptionModificationStateError::Conflict);
    }
    record.state = next;
    if provider.is_some() {
        record.provider = provider;
    }
    record.updated_at = now;
    Ok(record.clone())
}

fn read_records(
    path: &Path,
) -> Result<BTreeMap<String, SubscriptionModificationRecord>, SubscriptionModificationStateError> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let bytes = fs::read(path).map_err(|_| SubscriptionModificationStateError::Unavailable)?;
    serde_json::from_slice(&bytes).map_err(|_| SubscriptionModificationStateError::Malformed)
}

fn persist_records(
    path: &Path,
    records: &BTreeMap<String, SubscriptionModificationRecord>,
) -> Result<(), SubscriptionModificationStateError> {
    let parent = path
        .parent()
        .ok_or(SubscriptionModificationStateError::Unavailable)?;
    fs::create_dir_all(parent).map_err(|_| SubscriptionModificationStateError::Unavailable)?;
    let mut file = NamedTempFile::new_in(parent)
        .map_err(|_| SubscriptionModificationStateError::Unavailable)?;
    file.write_all(
        &canonical_json(records).map_err(|_| SubscriptionModificationStateError::Malformed)?,
    )
    .map_err(|_| SubscriptionModificationStateError::Unavailable)?;
    file.as_file()
        .sync_all()
        .map_err(|_| SubscriptionModificationStateError::Unavailable)?;
    file.persist(path)
        .map_err(|_| SubscriptionModificationStateError::Unavailable)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    use super::*;
    use crate::{
        subscription::{
            ImmediateLiabilityReservation, RecurringLiabilityReservation, SubscriptionInterval,
        },
        types::{Currency, CustomerId, StripeAccountId, SubscriptionId},
    };

    fn request(workflow_id: &str) -> ReserveSubscriptionModificationRequest {
        let currency = Currency::parse("usd").unwrap();
        ReserveSubscriptionModificationRequest {
            workflow_id: workflow_id.into(),
            stripe_account_id: StripeAccountId::parse("acct_modifystorefixture01").unwrap(),
            customer_id: CustomerId::parse("cus_modifystorefixture001").unwrap(),
            subscription_id: SubscriptionId::parse("sub_modifystorefixture001").unwrap(),
            action_digest: crate::canonical::sha256(workflow_id.as_bytes()),
            policy_digest: crate::canonical::sha256(b"modify-policy"),
            decision_receipt_digest: crate::canonical::sha256(b"modify-decision"),
            before_subscription_digest: crate::canonical::sha256(b"modify-before"),
            after_items: vec![
                SubscriptionModifyItem::new(
                    crate::types::SubscriptionItemId::parse("si_modifystorefixture001").unwrap(),
                    crate::types::PriceId::parse("price_modifystorefixture01").unwrap(),
                    crate::types::ProductId::parse("prod_modifystorefixture001").unwrap(),
                    2,
                )
                .unwrap(),
            ],
            before_recurring_minor: 500,
            after_recurring_minor: 1_000,
            before_term_liability_minor: 1_000,
            after_term_liability_minor: 2_000,
            incremental_term_liability_minor: 1_000,
            superseded_term_liability_minor: 0,
            proration_debit_minor: 500,
            proration_credit_minor: 250,
            recurring_reservations: vec![RecurringLiabilityReservation {
                budget_id: "modify-delta".into(),
                currency: currency.clone(),
                interval: SubscriptionInterval::Week,
                amount_minor: 1_000,
                limit_minor: 1_000,
            }],
            immediate_reservations: vec![ImmediateLiabilityReservation {
                budget_id: "modify-debit".into(),
                currency,
                amount_minor: 500,
                limit_minor: 500,
                starts_at: 1,
                ends_at: 100,
            }],
            now: 10,
        }
    }

    #[test]
    fn pending_and_unknown_states_hold_both_transition_sides() {
        for state in [
            SubscriptionModificationState::PendingPayment,
            SubscriptionModificationState::OutcomeUnknown,
        ] {
            assert!(state.holds_incremental_liability());
            assert!(state.holds_immediate_debit());
        }
    }

    #[test]
    fn concurrent_last_delta_has_one_winner() {
        let store = Arc::new(InMemorySubscriptionModificationStore::default());
        let barrier = Arc::new(Barrier::new(2));
        let handles = ["modify-a", "modify-b"].map(|workflow| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                store.reserve_modify(request(workflow)).unwrap()
            })
        });
        let outcomes = handles.map(|handle| handle.join().unwrap());
        assert_eq!(
            outcomes
                .iter()
                .filter(|value| matches!(value, ReserveSubscriptionModificationResult::Reserved(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|value| matches!(
                    value,
                    ReserveSubscriptionModificationResult::CapacityExceeded
                ))
                .count(),
            1
        );
    }

    #[test]
    fn persistent_replay_survives_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("modify-state.json");
        {
            let store = PersistentSubscriptionModificationStore::new(&path).unwrap();
            assert!(matches!(
                store.reserve_modify(request("modify-restart")).unwrap(),
                ReserveSubscriptionModificationResult::Reserved(_)
            ));
        }
        let store = PersistentSubscriptionModificationStore::new(&path).unwrap();
        assert!(matches!(
            store.reserve_modify(request("modify-restart")).unwrap(),
            ReserveSubscriptionModificationResult::Replay(_)
        ));
    }
}
