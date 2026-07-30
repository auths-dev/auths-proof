//! Durable capability-slot reservation, claim, replay, and reconciliation state.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use super::{PAYMENT_MANDATE_CAPABILITY_SCHEMA, PaymentMandateProviderProjection};
use crate::{
    canonical::{canonical_json, sha256},
    types::{CustomerId, DigestHex, PaymentMethodId, StripeAccountId},
};

/// Closed mandate capability lifecycle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentMandateCapabilityState {
    Reserved,
    Claimed,
    Attempting,
    Committed,
    Released,
    OutcomeUnknown,
    CustomerActionRequired,
}

impl PaymentMandateCapabilityState {
    #[must_use]
    pub const fn consumes_slot(self) -> bool {
        !matches!(self, Self::Released)
    }
}

/// Complete public durable record; never contains credentials or client secrets.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentMandateCapabilityRecord {
    schema: String,
    workflow_id: String,
    stripe_account_id: StripeAccountId,
    customer_id: CustomerId,
    payment_method_id: PaymentMethodId,
    reference: String,
    action_digest: DigestHex,
    policy_digest: DigestHex,
    consent_digest: DigestHex,
    capability_id: DigestHex,
    decision_receipt_digest: DigestHex,
    state: PaymentMandateCapabilityState,
    provider: Option<PaymentMandateProviderProjection>,
    idempotency_key_commitment: DigestHex,
    created_at: u64,
    updated_at: u64,
}

impl PaymentMandateCapabilityRecord {
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }
    pub const fn stripe_account_id(&self) -> &StripeAccountId {
        &self.stripe_account_id
    }
    pub const fn customer_id(&self) -> &CustomerId {
        &self.customer_id
    }
    pub const fn payment_method_id(&self) -> &PaymentMethodId {
        &self.payment_method_id
    }
    pub fn reference(&self) -> &str {
        &self.reference
    }
    pub const fn action_digest(&self) -> &DigestHex {
        &self.action_digest
    }
    pub const fn policy_digest(&self) -> &DigestHex {
        &self.policy_digest
    }
    pub const fn consent_digest(&self) -> &DigestHex {
        &self.consent_digest
    }
    pub const fn capability_id(&self) -> &DigestHex {
        &self.capability_id
    }
    pub const fn decision_receipt_digest(&self) -> &DigestHex {
        &self.decision_receipt_digest
    }
    pub const fn state(&self) -> PaymentMandateCapabilityState {
        self.state
    }
    pub const fn provider(&self) -> Option<&PaymentMandateProviderProjection> {
        self.provider.as_ref()
    }
    pub const fn idempotency_key_commitment(&self) -> &DigestHex {
        &self.idempotency_key_commitment
    }
}

/// Exact atomic reservation request.
pub struct ReservePaymentMandateRequest {
    pub workflow_id: String,
    pub stripe_account_id: StripeAccountId,
    pub customer_id: CustomerId,
    pub payment_method_id: PaymentMethodId,
    pub reference: String,
    pub action_digest: DigestHex,
    pub policy_digest: DigestHex,
    pub consent_digest: DigestHex,
    pub decision_receipt_digest: DigestHex,
    pub maximum_active: u32,
    pub provider_active: u32,
    pub now: u64,
}

/// Atomic reservation result.
pub enum ReservePaymentMandateResult {
    Reserved(PaymentMandateCapabilityRecord),
    Replay(PaymentMandateCapabilityRecord),
    Conflict(PaymentMandateCapabilityRecord),
    CapacityExceeded,
    ConsentAlreadyConsumed(PaymentMandateCapabilityRecord),
    DuplicateScope(PaymentMandateCapabilityRecord),
}

/// Mandate-specific durable state boundary.
pub trait PaymentMandateStore: Send + Sync {
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<PaymentMandateCapabilityRecord>, MandateStateError>;
    fn active_count(
        &self,
        account: &StripeAccountId,
        customer: &CustomerId,
    ) -> Result<u32, MandateStateError>;
    fn reserve(
        &self,
        request: ReservePaymentMandateRequest,
    ) -> Result<ReservePaymentMandateResult, MandateStateError>;
    fn transition(
        &self,
        workflow_id: &str,
        expected: PaymentMandateCapabilityState,
        next: PaymentMandateCapabilityState,
        provider: Option<PaymentMandateProviderProjection>,
        now: u64,
    ) -> Result<PaymentMandateCapabilityRecord, MandateStateError>;
}

impl<T: PaymentMandateStore + ?Sized> PaymentMandateStore for Arc<T> {
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<PaymentMandateCapabilityRecord>, MandateStateError> {
        (**self).get(workflow_id)
    }

    fn active_count(
        &self,
        account: &StripeAccountId,
        customer: &CustomerId,
    ) -> Result<u32, MandateStateError> {
        (**self).active_count(account, customer)
    }

    fn reserve(
        &self,
        request: ReservePaymentMandateRequest,
    ) -> Result<ReservePaymentMandateResult, MandateStateError> {
        (**self).reserve(request)
    }

    fn transition(
        &self,
        workflow_id: &str,
        expected: PaymentMandateCapabilityState,
        next: PaymentMandateCapabilityState,
        provider: Option<PaymentMandateProviderProjection>,
        now: u64,
    ) -> Result<PaymentMandateCapabilityRecord, MandateStateError> {
        (**self).transition(workflow_id, expected, next, provider, now)
    }
}

/// Closed state failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MandateStateError {
    #[error("payment-mandate state unavailable")]
    Unavailable,
    #[error("payment-mandate transition conflict")]
    Conflict,
    #[error("payment-mandate state malformed")]
    Malformed,
}

/// Process-local atomic capability store.
#[derive(Default)]
pub struct InMemoryPaymentMandateStore {
    records: Mutex<BTreeMap<String, PaymentMandateCapabilityRecord>>,
}

impl PaymentMandateStore for InMemoryPaymentMandateStore {
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<PaymentMandateCapabilityRecord>, MandateStateError> {
        Ok(self
            .records
            .lock()
            .map_err(|_| MandateStateError::Unavailable)?
            .get(workflow_id)
            .cloned())
    }

    fn active_count(
        &self,
        account: &StripeAccountId,
        customer: &CustomerId,
    ) -> Result<u32, MandateStateError> {
        let records = self
            .records
            .lock()
            .map_err(|_| MandateStateError::Unavailable)?;
        count_active(&records, account, customer)
    }

    fn reserve(
        &self,
        request: ReservePaymentMandateRequest,
    ) -> Result<ReservePaymentMandateResult, MandateStateError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| MandateStateError::Unavailable)?;
        reserve_in(&mut records, request)
    }

    fn transition(
        &self,
        workflow_id: &str,
        expected: PaymentMandateCapabilityState,
        next: PaymentMandateCapabilityState,
        provider: Option<PaymentMandateProviderProjection>,
        now: u64,
    ) -> Result<PaymentMandateCapabilityRecord, MandateStateError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| MandateStateError::Unavailable)?;
        transition_in(&mut records, workflow_id, expected, next, provider, now)
    }
}

/// Restart-safe JSON state store with atomic replacement.
pub struct PersistentPaymentMandateStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl PersistentPaymentMandateStore {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, MandateStateError> {
        let store = Self {
            path: path.into(),
            lock: Mutex::new(()),
        };
        let guard = store
            .lock
            .lock()
            .map_err(|_| MandateStateError::Unavailable)?;
        if store.path.exists() {
            store.load()?;
        } else {
            store.save(&BTreeMap::new())?;
        }
        drop(guard);
        Ok(store)
    }

    fn load(&self) -> Result<BTreeMap<String, PaymentMandateCapabilityRecord>, MandateStateError> {
        let bytes = fs::read(&self.path).map_err(|_| MandateStateError::Unavailable)?;
        serde_json::from_slice(&bytes).map_err(|_| MandateStateError::Malformed)
    }

    fn save(
        &self,
        records: &BTreeMap<String, PaymentMandateCapabilityRecord>,
    ) -> Result<(), MandateStateError> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|_| MandateStateError::Unavailable)?;
        let bytes = canonical_json(records).map_err(|_| MandateStateError::Malformed)?;
        let mut file = NamedTempFile::new_in(parent).map_err(|_| MandateStateError::Unavailable)?;
        file.write_all(&bytes)
            .map_err(|_| MandateStateError::Unavailable)?;
        file.as_file()
            .sync_all()
            .map_err(|_| MandateStateError::Unavailable)?;
        file.persist(&self.path)
            .map_err(|_| MandateStateError::Unavailable)?;
        let directory = OpenOptions::new()
            .read(true)
            .open(parent)
            .map_err(|_| MandateStateError::Unavailable)?;
        directory
            .sync_all()
            .map_err(|_| MandateStateError::Unavailable)
    }
}

impl PaymentMandateStore for PersistentPaymentMandateStore {
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<PaymentMandateCapabilityRecord>, MandateStateError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| MandateStateError::Unavailable)?;
        Ok(self.load()?.get(workflow_id).cloned())
    }

    fn active_count(
        &self,
        account: &StripeAccountId,
        customer: &CustomerId,
    ) -> Result<u32, MandateStateError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| MandateStateError::Unavailable)?;
        count_active(&self.load()?, account, customer)
    }

    fn reserve(
        &self,
        request: ReservePaymentMandateRequest,
    ) -> Result<ReservePaymentMandateResult, MandateStateError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| MandateStateError::Unavailable)?;
        let mut records = self.load()?;
        let result = reserve_in(&mut records, request)?;
        if matches!(result, ReservePaymentMandateResult::Reserved(_)) {
            self.save(&records)?;
        }
        Ok(result)
    }

    fn transition(
        &self,
        workflow_id: &str,
        expected: PaymentMandateCapabilityState,
        next: PaymentMandateCapabilityState,
        provider: Option<PaymentMandateProviderProjection>,
        now: u64,
    ) -> Result<PaymentMandateCapabilityRecord, MandateStateError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| MandateStateError::Unavailable)?;
        let mut records = self.load()?;
        let record = transition_in(&mut records, workflow_id, expected, next, provider, now)?;
        self.save(&records)?;
        Ok(record)
    }
}

fn count_active(
    records: &BTreeMap<String, PaymentMandateCapabilityRecord>,
    account: &StripeAccountId,
    customer: &CustomerId,
) -> Result<u32, MandateStateError> {
    u32::try_from(
        records
            .values()
            .filter(|record| {
                &record.stripe_account_id == account
                    && &record.customer_id == customer
                    && record.state.consumes_slot()
            })
            .count(),
    )
    .map_err(|_| MandateStateError::Unavailable)
}

fn reserve_in(
    records: &mut BTreeMap<String, PaymentMandateCapabilityRecord>,
    request: ReservePaymentMandateRequest,
) -> Result<ReservePaymentMandateResult, MandateStateError> {
    if let Some(existing) = records.get(&request.workflow_id) {
        if existing.action_digest == request.action_digest
            && existing.policy_digest == request.policy_digest
            && existing.consent_digest == request.consent_digest
        {
            return Ok(ReservePaymentMandateResult::Replay(existing.clone()));
        }
        return Ok(ReservePaymentMandateResult::Conflict(existing.clone()));
    }
    if let Some(existing) = records.values().find(|record| {
        record.consent_digest == request.consent_digest && record.state.consumes_slot()
    }) {
        return Ok(ReservePaymentMandateResult::ConsentAlreadyConsumed(
            existing.clone(),
        ));
    }
    if let Some(existing) = records.values().find(|record| {
        record.stripe_account_id == request.stripe_account_id
            && record.customer_id == request.customer_id
            && record.payment_method_id == request.payment_method_id
            && record.reference == request.reference
            && record.state.consumes_slot()
    }) {
        return Ok(ReservePaymentMandateResult::DuplicateScope(
            existing.clone(),
        ));
    }
    let local = count_active(records, &request.stripe_account_id, &request.customer_id)?;
    if local.saturating_add(request.provider_active) >= request.maximum_active {
        return Ok(ReservePaymentMandateResult::CapacityExceeded);
    }
    let capability_id = sha256(
        format!(
            "{}:{}:{}:{}",
            PAYMENT_MANDATE_CAPABILITY_SCHEMA,
            request.workflow_id,
            request.action_digest,
            request.policy_digest
        )
        .as_bytes(),
    );
    let idempotency_key_commitment =
        sha256(format!("auths-mandate-{}", capability_id.as_str()).as_bytes());
    let record = PaymentMandateCapabilityRecord {
        schema: PAYMENT_MANDATE_CAPABILITY_SCHEMA.into(),
        workflow_id: request.workflow_id.clone(),
        stripe_account_id: request.stripe_account_id,
        customer_id: request.customer_id,
        payment_method_id: request.payment_method_id,
        reference: request.reference,
        action_digest: request.action_digest,
        policy_digest: request.policy_digest,
        consent_digest: request.consent_digest,
        capability_id,
        decision_receipt_digest: request.decision_receipt_digest,
        state: PaymentMandateCapabilityState::Reserved,
        provider: None,
        idempotency_key_commitment,
        created_at: request.now,
        updated_at: request.now,
    };
    records.insert(request.workflow_id, record.clone());
    Ok(ReservePaymentMandateResult::Reserved(record))
}

fn transition_in(
    records: &mut BTreeMap<String, PaymentMandateCapabilityRecord>,
    workflow_id: &str,
    expected: PaymentMandateCapabilityState,
    next: PaymentMandateCapabilityState,
    provider: Option<PaymentMandateProviderProjection>,
    now: u64,
) -> Result<PaymentMandateCapabilityRecord, MandateStateError> {
    let record = records
        .get_mut(workflow_id)
        .ok_or(MandateStateError::Conflict)?;
    if record.state != expected || !valid_transition(expected, next) {
        return Err(MandateStateError::Conflict);
    }
    record.state = next;
    record.provider = provider;
    record.updated_at = now;
    Ok(record.clone())
}

#[allow(
    clippy::unnested_or_patterns,
    reason = "the explicit transition matrix is easier to audit in edge form"
)]
const fn valid_transition(
    from: PaymentMandateCapabilityState,
    to: PaymentMandateCapabilityState,
) -> bool {
    matches!(
        (from, to),
        (
            PaymentMandateCapabilityState::Reserved,
            PaymentMandateCapabilityState::Claimed
        ) | (
            PaymentMandateCapabilityState::Claimed,
            PaymentMandateCapabilityState::Attempting
        ) | (
            PaymentMandateCapabilityState::Claimed,
            PaymentMandateCapabilityState::Released
        ) | (
            PaymentMandateCapabilityState::Attempting,
            PaymentMandateCapabilityState::Committed
        ) | (
            PaymentMandateCapabilityState::Attempting,
            PaymentMandateCapabilityState::Released
        ) | (
            PaymentMandateCapabilityState::Attempting,
            PaymentMandateCapabilityState::OutcomeUnknown
        ) | (
            PaymentMandateCapabilityState::Attempting,
            PaymentMandateCapabilityState::CustomerActionRequired
        ) | (
            PaymentMandateCapabilityState::OutcomeUnknown,
            PaymentMandateCapabilityState::Committed
        ) | (
            PaymentMandateCapabilityState::OutcomeUnknown,
            PaymentMandateCapabilityState::Released
        ) | (
            PaymentMandateCapabilityState::CustomerActionRequired,
            PaymentMandateCapabilityState::Committed
        ) | (
            PaymentMandateCapabilityState::CustomerActionRequired,
            PaymentMandateCapabilityState::Released
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CustomerId, PaymentMethodId, StripeAccountId};

    fn request(workflow: &str, consent: &str) -> ReservePaymentMandateRequest {
        ReservePaymentMandateRequest {
            workflow_id: workflow.into(),
            stripe_account_id: StripeAccountId::parse("acct_12345678").unwrap(),
            customer_id: CustomerId::parse("cus_12345678").unwrap(),
            payment_method_id: PaymentMethodId::parse("pm_12345678").unwrap(),
            reference: "membership".into(),
            action_digest: sha256(workflow.as_bytes()),
            policy_digest: sha256(b"policy"),
            consent_digest: sha256(consent.as_bytes()),
            decision_receipt_digest: sha256(b"decision"),
            maximum_active: 2,
            provider_active: 0,
            now: 10,
        }
    }

    #[test]
    fn capacity_and_consent_are_atomic() {
        let store = InMemoryPaymentMandateStore::default();
        assert!(matches!(
            store.reserve(request("workflow-a", "consent-a")).unwrap(),
            ReservePaymentMandateResult::Reserved(_)
        ));
        assert!(matches!(
            store.reserve(request("workflow-b", "consent-a")).unwrap(),
            ReservePaymentMandateResult::ConsentAlreadyConsumed(_)
        ));
        let mut other = request("workflow-b", "consent-b");
        other.reference = "other".into();
        assert!(matches!(
            store.reserve(other).unwrap(),
            ReservePaymentMandateResult::Reserved(_)
        ));
        let mut third = request("workflow-c", "consent-c");
        third.reference = "third".into();
        assert!(matches!(
            store.reserve(third).unwrap(),
            ReservePaymentMandateResult::CapacityExceeded
        ));
    }

    #[test]
    fn persistent_store_replays_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mandates.json");
        {
            let store = PersistentPaymentMandateStore::new(&path).unwrap();
            assert!(matches!(
                store.reserve(request("workflow-a", "consent-a")).unwrap(),
                ReservePaymentMandateResult::Reserved(_)
            ));
        }
        let restarted = PersistentPaymentMandateStore::new(&path).unwrap();
        assert!(matches!(
            restarted
                .reserve(request("workflow-a", "consent-a"))
                .unwrap(),
            ReservePaymentMandateResult::Replay(_)
        ));
    }
}
