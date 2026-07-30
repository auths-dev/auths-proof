//! Durable atomic subscription liability reservations.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use super::{SUBSCRIPTION_LIABILITY_SCHEMA, SubscriptionInterval, SubscriptionProviderProjection};
use crate::{
    canonical::{canonical_json, sha256},
    types::{Currency, CustomerId, DigestHex, InvoiceId, StripeAccountId},
};

/// Closed create lifecycle state. Later profiles use their own transitions.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubscriptionLiabilityState {
    Reserved,
    Claimed,
    Attempting,
    Active,
    Trialing,
    Incomplete,
    IncompleteExpired,
    OutcomeUnknown,
    Released,
    Ended,
}

impl SubscriptionLiabilityState {
    pub const fn holds_recurring(self) -> bool {
        !matches!(self, Self::Released | Self::IncompleteExpired | Self::Ended)
    }
    pub const fn holds_immediate(self) -> bool {
        matches!(
            self,
            Self::Reserved
                | Self::Claimed
                | Self::Attempting
                | Self::Incomplete
                | Self::OutcomeUnknown
        )
    }
    pub const fn holds_slot(self) -> bool {
        self.holds_recurring()
    }
}

/// One exact finite recurring reservation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecurringLiabilityReservation {
    pub budget_id: String,
    pub currency: Currency,
    pub interval: SubscriptionInterval,
    pub amount_minor: u64,
    pub limit_minor: u64,
}

/// One immediate first-invoice reservation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImmediateLiabilityReservation {
    pub budget_id: String,
    pub currency: Currency,
    pub amount_minor: u64,
    pub limit_minor: u64,
    pub starts_at: u64,
    pub ends_at: u64,
}

/// Public durable state, containing no Stripe credential.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionLiabilityRecord {
    schema: String,
    workflow_id: String,
    stripe_account_id: StripeAccountId,
    customer_id: CustomerId,
    action_digest: DigestHex,
    policy_digest: DigestHex,
    mandate_receipt_digest: DigestHex,
    decision_receipt_digest: DigestHex,
    liability_id: DigestHex,
    recurring_minor: u64,
    remaining_term_liability_minor: u64,
    immediate_minor: u64,
    remaining_cycles: u32,
    observed_paid_invoice_ids: Vec<InvoiceId>,
    recurring_reservations: Vec<RecurringLiabilityReservation>,
    immediate_reservations: Vec<ImmediateLiabilityReservation>,
    state: SubscriptionLiabilityState,
    provider: Option<SubscriptionProviderProjection>,
    idempotency_key_commitment: DigestHex,
    created_at: u64,
    updated_at: u64,
}

impl SubscriptionLiabilityRecord {
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }
    pub const fn stripe_account_id(&self) -> &StripeAccountId {
        &self.stripe_account_id
    }
    pub const fn customer_id(&self) -> &CustomerId {
        &self.customer_id
    }
    pub const fn action_digest(&self) -> &DigestHex {
        &self.action_digest
    }
    pub const fn policy_digest(&self) -> &DigestHex {
        &self.policy_digest
    }
    pub const fn mandate_receipt_digest(&self) -> &DigestHex {
        &self.mandate_receipt_digest
    }
    pub const fn decision_receipt_digest(&self) -> &DigestHex {
        &self.decision_receipt_digest
    }
    pub const fn liability_id(&self) -> &DigestHex {
        &self.liability_id
    }
    pub const fn recurring_minor(&self) -> u64 {
        self.recurring_minor
    }
    pub const fn remaining_term_liability_minor(&self) -> u64 {
        self.remaining_term_liability_minor
    }
    pub const fn immediate_minor(&self) -> u64 {
        self.immediate_minor
    }
    pub const fn remaining_cycles(&self) -> u32 {
        self.remaining_cycles
    }
    pub fn observed_paid_invoice_ids(&self) -> &[InvoiceId] {
        &self.observed_paid_invoice_ids
    }
    pub fn recurring_reservations(&self) -> &[RecurringLiabilityReservation] {
        &self.recurring_reservations
    }
    pub fn immediate_reservations(&self) -> &[ImmediateLiabilityReservation] {
        &self.immediate_reservations
    }
    pub const fn state(&self) -> SubscriptionLiabilityState {
        self.state
    }
    pub const fn provider(&self) -> Option<&SubscriptionProviderProjection> {
        self.provider.as_ref()
    }
    pub const fn idempotency_key_commitment(&self) -> &DigestHex {
        &self.idempotency_key_commitment
    }
}

/// Atomic all-or-nothing reservation input.
pub struct ReserveSubscriptionLiabilityRequest {
    pub workflow_id: String,
    pub stripe_account_id: StripeAccountId,
    pub customer_id: CustomerId,
    pub action_digest: DigestHex,
    pub policy_digest: DigestHex,
    pub mandate_receipt_digest: DigestHex,
    pub decision_receipt_digest: DigestHex,
    pub recurring_minor: u64,
    pub term_liability_minor: u64,
    pub immediate_minor: u64,
    pub cycle_count: u32,
    pub recurring_reservations: Vec<RecurringLiabilityReservation>,
    pub immediate_reservations: Vec<ImmediateLiabilityReservation>,
    pub maximum_active_subscriptions: u32,
    pub provider_active_subscriptions: u32,
    pub now: u64,
}

/// Result of one atomic reservation attempt.
pub enum ReserveSubscriptionLiabilityResult {
    Reserved(SubscriptionLiabilityRecord),
    Replay(SubscriptionLiabilityRecord),
    Conflict(SubscriptionLiabilityRecord),
    CapacityExceeded,
}

/// Shared reservation mechanics. No operation tag selects transitions.
pub trait SubscriptionLiabilityStore: Send + Sync {
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<SubscriptionLiabilityRecord>, SubscriptionStateError>;
    fn reserve(
        &self,
        request: ReserveSubscriptionLiabilityRequest,
    ) -> Result<ReserveSubscriptionLiabilityResult, SubscriptionStateError>;
    fn transition_create(
        &self,
        workflow_id: &str,
        expected: SubscriptionLiabilityState,
        next: SubscriptionLiabilityState,
        provider: Option<SubscriptionProviderProjection>,
        now: u64,
    ) -> Result<SubscriptionLiabilityRecord, SubscriptionStateError>;
    fn observe_paid_invoice(
        &self,
        workflow_id: &str,
        provider: SubscriptionProviderProjection,
        now: u64,
    ) -> Result<SubscriptionLiabilityRecord, SubscriptionStateError>;
}

impl<T: SubscriptionLiabilityStore + ?Sized> SubscriptionLiabilityStore for Arc<T> {
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<SubscriptionLiabilityRecord>, SubscriptionStateError> {
        (**self).get(workflow_id)
    }
    fn reserve(
        &self,
        request: ReserveSubscriptionLiabilityRequest,
    ) -> Result<ReserveSubscriptionLiabilityResult, SubscriptionStateError> {
        (**self).reserve(request)
    }
    fn transition_create(
        &self,
        workflow_id: &str,
        expected: SubscriptionLiabilityState,
        next: SubscriptionLiabilityState,
        provider: Option<SubscriptionProviderProjection>,
        now: u64,
    ) -> Result<SubscriptionLiabilityRecord, SubscriptionStateError> {
        (**self).transition_create(workflow_id, expected, next, provider, now)
    }
    fn observe_paid_invoice(
        &self,
        workflow_id: &str,
        provider: SubscriptionProviderProjection,
        now: u64,
    ) -> Result<SubscriptionLiabilityRecord, SubscriptionStateError> {
        (**self).observe_paid_invoice(workflow_id, provider, now)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SubscriptionStateError {
    #[error("subscription liability state unavailable")]
    Unavailable,
    #[error("subscription liability transition conflict")]
    Conflict,
    #[error("subscription liability state malformed")]
    Malformed,
}

#[derive(Default)]
pub struct InMemorySubscriptionLiabilityStore {
    records: Mutex<BTreeMap<String, SubscriptionLiabilityRecord>>,
}

impl SubscriptionLiabilityStore for InMemorySubscriptionLiabilityStore {
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<SubscriptionLiabilityRecord>, SubscriptionStateError> {
        Ok(self
            .records
            .lock()
            .map_err(|_| SubscriptionStateError::Unavailable)?
            .get(workflow_id)
            .cloned())
    }

    fn reserve(
        &self,
        request: ReserveSubscriptionLiabilityRequest,
    ) -> Result<ReserveSubscriptionLiabilityResult, SubscriptionStateError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| SubscriptionStateError::Unavailable)?;
        reserve_in(&mut records, request)
    }

    fn transition_create(
        &self,
        workflow_id: &str,
        expected: SubscriptionLiabilityState,
        next: SubscriptionLiabilityState,
        provider: Option<SubscriptionProviderProjection>,
        now: u64,
    ) -> Result<SubscriptionLiabilityRecord, SubscriptionStateError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| SubscriptionStateError::Unavailable)?;
        transition_in(&mut records, workflow_id, expected, next, provider, now)
    }

    fn observe_paid_invoice(
        &self,
        workflow_id: &str,
        provider: SubscriptionProviderProjection,
        now: u64,
    ) -> Result<SubscriptionLiabilityRecord, SubscriptionStateError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| SubscriptionStateError::Unavailable)?;
        observe_paid_invoice_in(&mut records, workflow_id, provider, now)
    }
}

pub struct PersistentSubscriptionLiabilityStore {
    path: PathBuf,
    records: Mutex<BTreeMap<String, SubscriptionLiabilityRecord>>,
}

impl PersistentSubscriptionLiabilityStore {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, SubscriptionStateError> {
        let path = path.into();
        let records = read_records(&path)?;
        Ok(Self {
            path,
            records: Mutex::new(records),
        })
    }
}

impl SubscriptionLiabilityStore for PersistentSubscriptionLiabilityStore {
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<SubscriptionLiabilityRecord>, SubscriptionStateError> {
        Ok(self
            .records
            .lock()
            .map_err(|_| SubscriptionStateError::Unavailable)?
            .get(workflow_id)
            .cloned())
    }

    fn reserve(
        &self,
        request: ReserveSubscriptionLiabilityRequest,
    ) -> Result<ReserveSubscriptionLiabilityResult, SubscriptionStateError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| SubscriptionStateError::Unavailable)?;
        let result = reserve_in(&mut records, request)?;
        persist_records(&self.path, &records)?;
        Ok(result)
    }

    fn transition_create(
        &self,
        workflow_id: &str,
        expected: SubscriptionLiabilityState,
        next: SubscriptionLiabilityState,
        provider: Option<SubscriptionProviderProjection>,
        now: u64,
    ) -> Result<SubscriptionLiabilityRecord, SubscriptionStateError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| SubscriptionStateError::Unavailable)?;
        let result = transition_in(&mut records, workflow_id, expected, next, provider, now)?;
        persist_records(&self.path, &records)?;
        Ok(result)
    }

    fn observe_paid_invoice(
        &self,
        workflow_id: &str,
        provider: SubscriptionProviderProjection,
        now: u64,
    ) -> Result<SubscriptionLiabilityRecord, SubscriptionStateError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| SubscriptionStateError::Unavailable)?;
        let result = observe_paid_invoice_in(&mut records, workflow_id, provider, now)?;
        persist_records(&self.path, &records)?;
        Ok(result)
    }
}

fn reserve_in(
    records: &mut BTreeMap<String, SubscriptionLiabilityRecord>,
    request: ReserveSubscriptionLiabilityRequest,
) -> Result<ReserveSubscriptionLiabilityResult, SubscriptionStateError> {
    if let Some(record) = records.get(&request.workflow_id) {
        return Ok(if record.action_digest == request.action_digest {
            ReserveSubscriptionLiabilityResult::Replay(record.clone())
        } else {
            ReserveSubscriptionLiabilityResult::Conflict(record.clone())
        });
    }

    let local_active = records
        .values()
        .filter(|record| {
            record.stripe_account_id == request.stripe_account_id
                && record.customer_id == request.customer_id
                && record.state.holds_slot()
        })
        .count();
    let total_active = u32::try_from(local_active)
        .ok()
        .and_then(|value| value.checked_add(request.provider_active_subscriptions))
        .ok_or(SubscriptionStateError::Malformed)?;
    if total_active >= request.maximum_active_subscriptions {
        return Ok(ReserveSubscriptionLiabilityResult::CapacityExceeded);
    }

    for reservation in &request.recurring_reservations {
        let used = records
            .values()
            .filter(|record| record.state.holds_recurring())
            .flat_map(|record| &record.recurring_reservations)
            .filter(|prior| prior.budget_id == reservation.budget_id)
            .try_fold(0_u64, |sum, prior| sum.checked_add(prior.amount_minor))
            .ok_or(SubscriptionStateError::Malformed)?;
        if used
            .checked_add(reservation.amount_minor)
            .is_none_or(|next| next > reservation.limit_minor)
        {
            return Ok(ReserveSubscriptionLiabilityResult::CapacityExceeded);
        }
    }
    for reservation in &request.immediate_reservations {
        let used = records
            .values()
            .filter(|record| record.state.holds_immediate())
            .flat_map(|record| &record.immediate_reservations)
            .filter(|prior| {
                prior.budget_id == reservation.budget_id
                    && prior.starts_at == reservation.starts_at
                    && prior.ends_at == reservation.ends_at
            })
            .try_fold(0_u64, |sum, prior| sum.checked_add(prior.amount_minor))
            .ok_or(SubscriptionStateError::Malformed)?;
        if used
            .checked_add(reservation.amount_minor)
            .is_none_or(|next| next > reservation.limit_minor)
        {
            return Ok(ReserveSubscriptionLiabilityResult::CapacityExceeded);
        }
    }

    let liability_id = sha256(
        format!(
            "subscription-liability:{}:{}:{}",
            request.workflow_id, request.action_digest, request.policy_digest
        )
        .as_bytes(),
    );
    let idempotency_key_commitment = sha256(format!("auths-sub-create-{liability_id}").as_bytes());
    let record = SubscriptionLiabilityRecord {
        schema: SUBSCRIPTION_LIABILITY_SCHEMA.into(),
        workflow_id: request.workflow_id.clone(),
        stripe_account_id: request.stripe_account_id,
        customer_id: request.customer_id,
        action_digest: request.action_digest,
        policy_digest: request.policy_digest,
        mandate_receipt_digest: request.mandate_receipt_digest,
        decision_receipt_digest: request.decision_receipt_digest,
        liability_id,
        recurring_minor: request.recurring_minor,
        remaining_term_liability_minor: request.term_liability_minor,
        immediate_minor: request.immediate_minor,
        remaining_cycles: request.cycle_count,
        observed_paid_invoice_ids: Vec::new(),
        recurring_reservations: request.recurring_reservations,
        immediate_reservations: request.immediate_reservations,
        state: SubscriptionLiabilityState::Reserved,
        provider: None,
        idempotency_key_commitment,
        created_at: request.now,
        updated_at: request.now,
    };
    records.insert(request.workflow_id, record.clone());
    Ok(ReserveSubscriptionLiabilityResult::Reserved(record))
}

fn transition_in(
    records: &mut BTreeMap<String, SubscriptionLiabilityRecord>,
    workflow_id: &str,
    expected: SubscriptionLiabilityState,
    next: SubscriptionLiabilityState,
    provider: Option<SubscriptionProviderProjection>,
    now: u64,
) -> Result<SubscriptionLiabilityRecord, SubscriptionStateError> {
    let record = records
        .get_mut(workflow_id)
        .ok_or(SubscriptionStateError::Conflict)?;
    if record.state != expected {
        return Err(SubscriptionStateError::Conflict);
    }
    apply_paid_invoice(record, provider.as_ref())?;
    record.state = next;
    record.provider = provider;
    record.updated_at = now;
    Ok(record.clone())
}

fn observe_paid_invoice_in(
    records: &mut BTreeMap<String, SubscriptionLiabilityRecord>,
    workflow_id: &str,
    provider: SubscriptionProviderProjection,
    now: u64,
) -> Result<SubscriptionLiabilityRecord, SubscriptionStateError> {
    let record = records
        .get_mut(workflow_id)
        .ok_or(SubscriptionStateError::Conflict)?;
    if !matches!(
        record.state,
        SubscriptionLiabilityState::Active | SubscriptionLiabilityState::Trialing
    ) || record
        .provider
        .as_ref()
        .is_none_or(|prior| prior.subscription_id != provider.subscription_id)
        || !matches!(provider.status.as_str(), "active" | "trialing")
    {
        return Err(SubscriptionStateError::Conflict);
    }
    apply_paid_invoice(record, Some(&provider))?;
    record.provider = Some(provider);
    record.updated_at = now;
    Ok(record.clone())
}

fn apply_paid_invoice(
    record: &mut SubscriptionLiabilityRecord,
    provider: Option<&SubscriptionProviderProjection>,
) -> Result<(), SubscriptionStateError> {
    let Some(provider) = provider else {
        return Ok(());
    };
    let Some(invoice_id) = provider.latest_invoice_id.as_ref() else {
        return Ok(());
    };
    if provider.invoice_status.as_deref() != Some("paid")
        || provider.amount_paid_minor == 0
        || record
            .observed_paid_invoice_ids
            .binary_search(invoice_id)
            .is_ok()
    {
        return Ok(());
    }
    record.remaining_cycles = record
        .remaining_cycles
        .checked_sub(1)
        .ok_or(SubscriptionStateError::Malformed)?;
    record.remaining_term_liability_minor = record
        .remaining_term_liability_minor
        .checked_sub(record.recurring_minor)
        .ok_or(SubscriptionStateError::Malformed)?;
    record.observed_paid_invoice_ids.push(invoice_id.clone());
    record.observed_paid_invoice_ids.sort();
    Ok(())
}

fn read_records(
    path: &Path,
) -> Result<BTreeMap<String, SubscriptionLiabilityRecord>, SubscriptionStateError> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| SubscriptionStateError::Malformed),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(_) => Err(SubscriptionStateError::Unavailable),
    }
}

fn persist_records(
    path: &Path,
    records: &BTreeMap<String, SubscriptionLiabilityRecord>,
) -> Result<(), SubscriptionStateError> {
    let parent = path.parent().ok_or(SubscriptionStateError::Unavailable)?;
    fs::create_dir_all(parent).map_err(|_| SubscriptionStateError::Unavailable)?;
    let bytes = canonical_json(records).map_err(|_| SubscriptionStateError::Malformed)?;
    let mut temporary =
        NamedTempFile::new_in(parent).map_err(|_| SubscriptionStateError::Unavailable)?;
    temporary
        .write_all(&bytes)
        .map_err(|_| SubscriptionStateError::Unavailable)?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| SubscriptionStateError::Unavailable)?;
    temporary
        .persist(path)
        .map_err(|_| SubscriptionStateError::Unavailable)?;
    let directory = OpenOptions::new()
        .read(true)
        .open(parent)
        .map_err(|_| SubscriptionStateError::Unavailable)?;
    directory
        .sync_all()
        .map_err(|_| SubscriptionStateError::Unavailable)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::types::{Currency, CustomerId, DigestHex, StripeAccountId};

    fn digest(value: u8) -> DigestHex {
        DigestHex::parse(format!("{value:02x}").repeat(32)).unwrap()
    }

    fn request(workflow: &str, amount: u64) -> ReserveSubscriptionLiabilityRequest {
        ReserveSubscriptionLiabilityRequest {
            workflow_id: workflow.into(),
            stripe_account_id: StripeAccountId::parse("acct_subscriptionfixture01").unwrap(),
            customer_id: CustomerId::parse("cus_subscriptionfixture0001").unwrap(),
            action_digest: digest(1),
            policy_digest: digest(2),
            mandate_receipt_digest: digest(3),
            decision_receipt_digest: digest(4),
            recurring_minor: 500,
            term_liability_minor: amount,
            immediate_minor: 500,
            cycle_count: 3,
            recurring_reservations: vec![RecurringLiabilityReservation {
                budget_id: "term".into(),
                currency: Currency::parse("usd").unwrap(),
                interval: SubscriptionInterval::Month,
                amount_minor: amount,
                limit_minor: 1_500,
            }],
            immediate_reservations: vec![],
            maximum_active_subscriptions: 2,
            provider_active_subscriptions: 0,
            now: 2_000_000_000,
        }
    }

    #[test]
    fn all_exposures_reserve_atomically() {
        let store = InMemorySubscriptionLiabilityStore::default();
        assert!(matches!(
            store.reserve(request("one", 1_000)).unwrap(),
            ReserveSubscriptionLiabilityResult::Reserved(_)
        ));
        assert!(matches!(
            store.reserve(request("two", 1_000)).unwrap(),
            ReserveSubscriptionLiabilityResult::CapacityExceeded
        ));
        assert!(store.get("two").unwrap().is_none());
    }

    #[test]
    fn concurrent_last_active_slot_has_one_winner() {
        let store = Arc::new(InMemorySubscriptionLiabilityStore::default());
        let handles: Vec<_> = ["one", "two"]
            .into_iter()
            .map(|workflow| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    let mut value = request(workflow, 500);
                    value.maximum_active_subscriptions = 1;
                    store.reserve(value).unwrap()
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(
            results
                .iter()
                .filter(|value| matches!(value, ReserveSubscriptionLiabilityResult::Reserved(_)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|value| matches!(
                    value,
                    ReserveSubscriptionLiabilityResult::CapacityExceeded
                ))
                .count(),
            1
        );
    }

    #[test]
    fn persistent_store_replays_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("liabilities.json");
        {
            let store = PersistentSubscriptionLiabilityStore::new(&path).unwrap();
            assert!(matches!(
                store.reserve(request("restart", 500)).unwrap(),
                ReserveSubscriptionLiabilityResult::Reserved(_)
            ));
        }
        let reopened = PersistentSubscriptionLiabilityStore::new(&path).unwrap();
        assert!(matches!(
            reopened.reserve(request("restart", 500)).unwrap(),
            ReserveSubscriptionLiabilityResult::Replay(_)
        ));
    }
}
