//! Durable cancellation release intents and replay state.

#![allow(
    clippy::too_many_arguments,
    reason = "state transitions preserve explicit release accounting at the store boundary"
)]

use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use super::SubscriptionCancelProviderProjection;
use crate::{
    canonical::{canonical_digest, canonical_json},
    subscription::SubscriptionCancelMode,
    types::{CustomerId, DigestHex, StripeAccountId, SubscriptionId},
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubscriptionCancellationState {
    Reserved,
    Claimed,
    Attempting,
    Scheduled,
    OutcomeUnknown,
    TerminalObserved,
    Released,
}

impl SubscriptionCancellationState {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Released)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCancellationRecord {
    schema: String,
    workflow_id: String,
    stripe_account_id: StripeAccountId,
    customer_id: CustomerId,
    subscription_id: SubscriptionId,
    action_digest: DigestHex,
    policy_digest: DigestHex,
    decision_receipt_digest: DigestHex,
    cancellation_id: DigestHex,
    liability_id: DigestHex,
    mode: SubscriptionCancelMode,
    remaining_term_liability_minor: u64,
    current_period_liability_minor: u64,
    future_liability_release_minor: u64,
    liability_released_minor: u64,
    liability_retained_minor: u64,
    release_not_before: u64,
    state: SubscriptionCancellationState,
    provider: Option<SubscriptionCancelProviderProjection>,
    idempotency_key_commitment: DigestHex,
    created_at: u64,
    updated_at: u64,
}

impl SubscriptionCancellationRecord {
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }
    pub const fn subscription_id(&self) -> &SubscriptionId {
        &self.subscription_id
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
    pub const fn decision_receipt_digest(&self) -> &DigestHex {
        &self.decision_receipt_digest
    }
    pub const fn policy_digest(&self) -> &DigestHex {
        &self.policy_digest
    }
    pub const fn cancellation_id(&self) -> &DigestHex {
        &self.cancellation_id
    }
    pub const fn liability_id(&self) -> &DigestHex {
        &self.liability_id
    }
    pub const fn mode(&self) -> SubscriptionCancelMode {
        self.mode
    }
    pub const fn liability_released_minor(&self) -> u64 {
        self.liability_released_minor
    }
    pub const fn remaining_term_liability_minor(&self) -> u64 {
        self.remaining_term_liability_minor
    }
    pub const fn current_period_liability_minor(&self) -> u64 {
        self.current_period_liability_minor
    }
    pub const fn future_liability_release_minor(&self) -> u64 {
        self.future_liability_release_minor
    }
    pub const fn liability_retained_minor(&self) -> u64 {
        self.liability_retained_minor
    }
    pub const fn state(&self) -> SubscriptionCancellationState {
        self.state
    }
    pub const fn provider(&self) -> Option<&SubscriptionCancelProviderProjection> {
        self.provider.as_ref()
    }
    pub fn idempotency_key(&self) -> String {
        format!("auths-sub-cancel-{}", self.cancellation_id)
    }
}

pub struct ReserveSubscriptionCancellationRequest {
    pub workflow_id: String,
    pub stripe_account_id: StripeAccountId,
    pub customer_id: CustomerId,
    pub subscription_id: SubscriptionId,
    pub action_digest: DigestHex,
    pub policy_digest: DigestHex,
    pub decision_receipt_digest: DigestHex,
    pub liability_id: DigestHex,
    pub mode: SubscriptionCancelMode,
    pub remaining_term_liability_minor: u64,
    pub current_period_liability_minor: u64,
    pub future_liability_release_minor: u64,
    pub liability_retained_minor: u64,
    pub release_not_before: u64,
    pub now: u64,
}

pub enum ReserveSubscriptionCancellationResult {
    Reserved(SubscriptionCancellationRecord),
    Replay(SubscriptionCancellationRecord),
    Conflict(SubscriptionCancellationRecord),
}

pub trait SubscriptionCancellationStore: Send + Sync {
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<SubscriptionCancellationRecord>, SubscriptionCancellationStateError>;
    fn reserve_cancel(
        &self,
        request: ReserveSubscriptionCancellationRequest,
    ) -> Result<ReserveSubscriptionCancellationResult, SubscriptionCancellationStateError>;
    fn transition_cancel(
        &self,
        workflow_id: &str,
        expected: SubscriptionCancellationState,
        next: SubscriptionCancellationState,
        provider: Option<SubscriptionCancelProviderProjection>,
        released_minor: u64,
        retained_minor: u64,
        now: u64,
    ) -> Result<SubscriptionCancellationRecord, SubscriptionCancellationStateError>;
}

impl<T: SubscriptionCancellationStore + ?Sized> SubscriptionCancellationStore for Arc<T> {
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<SubscriptionCancellationRecord>, SubscriptionCancellationStateError> {
        (**self).get(workflow_id)
    }
    fn reserve_cancel(
        &self,
        request: ReserveSubscriptionCancellationRequest,
    ) -> Result<ReserveSubscriptionCancellationResult, SubscriptionCancellationStateError> {
        (**self).reserve_cancel(request)
    }
    fn transition_cancel(
        &self,
        workflow_id: &str,
        expected: SubscriptionCancellationState,
        next: SubscriptionCancellationState,
        provider: Option<SubscriptionCancelProviderProjection>,
        released_minor: u64,
        retained_minor: u64,
        now: u64,
    ) -> Result<SubscriptionCancellationRecord, SubscriptionCancellationStateError> {
        (**self).transition_cancel(
            workflow_id,
            expected,
            next,
            provider,
            released_minor,
            retained_minor,
            now,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SubscriptionCancellationStateError {
    #[error("subscription cancellation state unavailable")]
    Unavailable,
    #[error("subscription cancellation transition conflict")]
    Conflict,
    #[error("subscription cancellation state malformed")]
    Malformed,
}

#[derive(Default)]
pub struct InMemorySubscriptionCancellationStore {
    records: Mutex<BTreeMap<String, SubscriptionCancellationRecord>>,
}

impl SubscriptionCancellationStore for InMemorySubscriptionCancellationStore {
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<SubscriptionCancellationRecord>, SubscriptionCancellationStateError> {
        Ok(self
            .records
            .lock()
            .map_err(|_| SubscriptionCancellationStateError::Unavailable)?
            .get(workflow_id)
            .cloned())
    }
    fn reserve_cancel(
        &self,
        request: ReserveSubscriptionCancellationRequest,
    ) -> Result<ReserveSubscriptionCancellationResult, SubscriptionCancellationStateError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| SubscriptionCancellationStateError::Unavailable)?;
        reserve_in(&mut records, request)
    }
    fn transition_cancel(
        &self,
        workflow_id: &str,
        expected: SubscriptionCancellationState,
        next: SubscriptionCancellationState,
        provider: Option<SubscriptionCancelProviderProjection>,
        released_minor: u64,
        retained_minor: u64,
        now: u64,
    ) -> Result<SubscriptionCancellationRecord, SubscriptionCancellationStateError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| SubscriptionCancellationStateError::Unavailable)?;
        transition_in(
            &mut records,
            workflow_id,
            expected,
            next,
            provider,
            released_minor,
            retained_minor,
            now,
        )
    }
}

pub struct PersistentSubscriptionCancellationStore {
    path: PathBuf,
    records: Mutex<BTreeMap<String, SubscriptionCancellationRecord>>,
}

impl PersistentSubscriptionCancellationStore {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, SubscriptionCancellationStateError> {
        let path = path.into();
        Ok(Self {
            records: Mutex::new(read_records(&path)?),
            path,
        })
    }
}

impl SubscriptionCancellationStore for PersistentSubscriptionCancellationStore {
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<SubscriptionCancellationRecord>, SubscriptionCancellationStateError> {
        Ok(self
            .records
            .lock()
            .map_err(|_| SubscriptionCancellationStateError::Unavailable)?
            .get(workflow_id)
            .cloned())
    }
    fn reserve_cancel(
        &self,
        request: ReserveSubscriptionCancellationRequest,
    ) -> Result<ReserveSubscriptionCancellationResult, SubscriptionCancellationStateError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| SubscriptionCancellationStateError::Unavailable)?;
        let result = reserve_in(&mut records, request)?;
        persist_records(&self.path, &records)?;
        Ok(result)
    }
    fn transition_cancel(
        &self,
        workflow_id: &str,
        expected: SubscriptionCancellationState,
        next: SubscriptionCancellationState,
        provider: Option<SubscriptionCancelProviderProjection>,
        released_minor: u64,
        retained_minor: u64,
        now: u64,
    ) -> Result<SubscriptionCancellationRecord, SubscriptionCancellationStateError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| SubscriptionCancellationStateError::Unavailable)?;
        let result = transition_in(
            &mut records,
            workflow_id,
            expected,
            next,
            provider,
            released_minor,
            retained_minor,
            now,
        )?;
        persist_records(&self.path, &records)?;
        Ok(result)
    }
}

fn reserve_in(
    records: &mut BTreeMap<String, SubscriptionCancellationRecord>,
    request: ReserveSubscriptionCancellationRequest,
) -> Result<ReserveSubscriptionCancellationResult, SubscriptionCancellationStateError> {
    if let Some(record) = records.get(&request.workflow_id) {
        return Ok(if record.action_digest == request.action_digest {
            ReserveSubscriptionCancellationResult::Replay(record.clone())
        } else {
            ReserveSubscriptionCancellationResult::Conflict(record.clone())
        });
    }
    if let Some(conflict) = records.values().find(|record| {
        record.subscription_id == request.subscription_id && !record.state.is_terminal()
    }) {
        return Ok(ReserveSubscriptionCancellationResult::Conflict(
            conflict.clone(),
        ));
    }
    let cancellation_id = canonical_digest(&(
        &request.workflow_id,
        &request.subscription_id,
        &request.action_digest,
        &request.liability_id,
    ))
    .map_err(|_| SubscriptionCancellationStateError::Malformed)?;
    let idempotency_key_commitment =
        crate::canonical::sha256(format!("auths-sub-cancel-{cancellation_id}").as_bytes());
    let record = SubscriptionCancellationRecord {
        schema: "auths.stripe.subscription-cancellation/1".into(),
        workflow_id: request.workflow_id.clone(),
        stripe_account_id: request.stripe_account_id,
        customer_id: request.customer_id,
        subscription_id: request.subscription_id,
        action_digest: request.action_digest,
        policy_digest: request.policy_digest,
        decision_receipt_digest: request.decision_receipt_digest,
        cancellation_id,
        liability_id: request.liability_id,
        mode: request.mode,
        remaining_term_liability_minor: request.remaining_term_liability_minor,
        current_period_liability_minor: request.current_period_liability_minor,
        future_liability_release_minor: request.future_liability_release_minor,
        liability_released_minor: 0,
        liability_retained_minor: request.liability_retained_minor,
        release_not_before: request.release_not_before,
        state: SubscriptionCancellationState::Reserved,
        provider: None,
        idempotency_key_commitment,
        created_at: request.now,
        updated_at: request.now,
    };
    records.insert(request.workflow_id, record.clone());
    Ok(ReserveSubscriptionCancellationResult::Reserved(record))
}

#[allow(
    clippy::too_many_arguments,
    reason = "transition inputs preserve liability accounting explicitly"
)]
fn transition_in(
    records: &mut BTreeMap<String, SubscriptionCancellationRecord>,
    workflow_id: &str,
    expected: SubscriptionCancellationState,
    next: SubscriptionCancellationState,
    provider: Option<SubscriptionCancelProviderProjection>,
    released_minor: u64,
    retained_minor: u64,
    now: u64,
) -> Result<SubscriptionCancellationRecord, SubscriptionCancellationStateError> {
    let record = records
        .get_mut(workflow_id)
        .ok_or(SubscriptionCancellationStateError::Conflict)?;
    if record.state != expected
        || released_minor
            .checked_add(retained_minor)
            .is_none_or(|total| total > record.remaining_term_liability_minor)
        || released_minor < record.liability_released_minor
    {
        return Err(SubscriptionCancellationStateError::Conflict);
    }
    record.state = next;
    record.provider = provider;
    record.liability_released_minor = released_minor;
    record.liability_retained_minor = retained_minor;
    record.updated_at = now;
    Ok(record.clone())
}

fn read_records(
    path: &Path,
) -> Result<BTreeMap<String, SubscriptionCancellationRecord>, SubscriptionCancellationStateError> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|_| SubscriptionCancellationStateError::Malformed),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(_) => Err(SubscriptionCancellationStateError::Unavailable),
    }
}

fn persist_records(
    path: &Path,
    records: &BTreeMap<String, SubscriptionCancellationRecord>,
) -> Result<(), SubscriptionCancellationStateError> {
    let parent = path
        .parent()
        .ok_or(SubscriptionCancellationStateError::Unavailable)?;
    fs::create_dir_all(parent).map_err(|_| SubscriptionCancellationStateError::Unavailable)?;
    let bytes =
        canonical_json(records).map_err(|_| SubscriptionCancellationStateError::Malformed)?;
    let mut temporary = NamedTempFile::new_in(parent)
        .map_err(|_| SubscriptionCancellationStateError::Unavailable)?;
    temporary
        .write_all(&bytes)
        .map_err(|_| SubscriptionCancellationStateError::Unavailable)?;
    temporary
        .persist(path)
        .map_err(|_| SubscriptionCancellationStateError::Unavailable)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(workflow: &str, subscription: &str) -> ReserveSubscriptionCancellationRequest {
        ReserveSubscriptionCancellationRequest {
            workflow_id: workflow.into(),
            stripe_account_id: StripeAccountId::parse("acct_subscriptionfixture01").unwrap(),
            customer_id: CustomerId::parse("cus_subscriptionfixture0001").unwrap(),
            subscription_id: SubscriptionId::parse(subscription).unwrap(),
            action_digest: crate::canonical::sha256(workflow.as_bytes()),
            policy_digest: crate::canonical::sha256(b"cancel-policy"),
            decision_receipt_digest: crate::canonical::sha256(b"cancel-decision"),
            liability_id: crate::canonical::sha256(b"recurring-liability"),
            mode: SubscriptionCancelMode::AtPeriodEnd,
            remaining_term_liability_minor: 3_600,
            current_period_liability_minor: 1_200,
            future_liability_release_minor: 2_400,
            liability_retained_minor: 3_600,
            release_not_before: 2_100_605_100,
            now: 2_100_302_700,
        }
    }

    fn reserved(
        store: &dyn SubscriptionCancellationStore,
        workflow: &str,
        subscription: &str,
    ) -> SubscriptionCancellationRecord {
        match store
            .reserve_cancel(request(workflow, subscription))
            .unwrap()
        {
            ReserveSubscriptionCancellationResult::Reserved(value) => value,
            _ => panic!("expected reservation"),
        }
    }

    #[test]
    fn same_workflow_is_replay_but_mutated_action_conflicts() {
        let store = InMemorySubscriptionCancellationStore::default();
        let first = request("workflow-replay", "sub_subscriptionfixture0001");
        assert!(matches!(
            store.reserve_cancel(first).unwrap(),
            ReserveSubscriptionCancellationResult::Reserved(_)
        ));
        assert!(matches!(
            store
                .reserve_cancel(request("workflow-replay", "sub_subscriptionfixture0001"))
                .unwrap(),
            ReserveSubscriptionCancellationResult::Replay(_)
        ));
        let mut changed = request("workflow-replay", "sub_subscriptionfixture0001");
        changed.action_digest = crate::canonical::sha256(b"mutated-action");
        assert!(matches!(
            store.reserve_cancel(changed).unwrap(),
            ReserveSubscriptionCancellationResult::Conflict(_)
        ));
    }

    #[test]
    fn concurrent_cancellation_of_same_subscription_conflicts() {
        let store = InMemorySubscriptionCancellationStore::default();
        let _ = reserved(&store, "workflow-first", "sub_subscriptionfixture0001");
        assert!(matches!(
            store
                .reserve_cancel(request("workflow-second", "sub_subscriptionfixture0001"))
                .unwrap(),
            ReserveSubscriptionCancellationResult::Conflict(_)
        ));
    }

    #[test]
    fn scheduled_release_preserves_current_period_liability() {
        let store = InMemorySubscriptionCancellationStore::default();
        let record = reserved(&store, "workflow-period", "sub_subscriptionfixture0001");
        let claimed = store
            .transition_cancel(
                record.workflow_id(),
                SubscriptionCancellationState::Reserved,
                SubscriptionCancellationState::Claimed,
                None,
                0,
                3_600,
                2_100_302_701,
            )
            .unwrap();
        let attempting = store
            .transition_cancel(
                claimed.workflow_id(),
                SubscriptionCancellationState::Claimed,
                SubscriptionCancellationState::Attempting,
                None,
                0,
                3_600,
                2_100_302_702,
            )
            .unwrap();
        let scheduled = store
            .transition_cancel(
                attempting.workflow_id(),
                SubscriptionCancellationState::Attempting,
                SubscriptionCancellationState::Scheduled,
                None,
                2_400,
                1_200,
                2_100_302_703,
            )
            .unwrap();
        assert_eq!(scheduled.liability_released_minor(), 2_400);
        assert_eq!(scheduled.liability_retained_minor(), 1_200);
    }

    #[test]
    fn release_accounting_cannot_exceed_original_liability() {
        let store = InMemorySubscriptionCancellationStore::default();
        let record = reserved(&store, "workflow-overflow", "sub_subscriptionfixture0001");
        assert_eq!(
            store.transition_cancel(
                record.workflow_id(),
                SubscriptionCancellationState::Reserved,
                SubscriptionCancellationState::Claimed,
                None,
                3_601,
                0,
                2_100_302_701,
            ),
            Err(SubscriptionCancellationStateError::Conflict)
        );
    }

    #[test]
    fn persistent_unknown_outcome_survives_restart() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("cancel-state.json");
        {
            let store = PersistentSubscriptionCancellationStore::new(&path).unwrap();
            let reserved = reserved(&store, "workflow-restart", "sub_subscriptionfixture0001");
            let claimed = store
                .transition_cancel(
                    reserved.workflow_id(),
                    SubscriptionCancellationState::Reserved,
                    SubscriptionCancellationState::Claimed,
                    None,
                    0,
                    3_600,
                    2_100_302_701,
                )
                .unwrap();
            let attempting = store
                .transition_cancel(
                    claimed.workflow_id(),
                    SubscriptionCancellationState::Claimed,
                    SubscriptionCancellationState::Attempting,
                    None,
                    0,
                    3_600,
                    2_100_302_702,
                )
                .unwrap();
            store
                .transition_cancel(
                    attempting.workflow_id(),
                    SubscriptionCancellationState::Attempting,
                    SubscriptionCancellationState::OutcomeUnknown,
                    None,
                    0,
                    3_600,
                    2_100_302_703,
                )
                .unwrap();
        }
        let restarted = PersistentSubscriptionCancellationStore::new(path).unwrap();
        let record = restarted.get("workflow-restart").unwrap().unwrap();
        assert_eq!(
            record.state(),
            SubscriptionCancellationState::OutcomeUnknown
        );
        assert_eq!(record.liability_released_minor(), 0);
        assert_eq!(record.liability_retained_minor(), 3_600);
    }
}
