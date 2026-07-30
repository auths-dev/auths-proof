//! Store acknowledgement and stage-sealed side-effect boundaries.

use alloc::vec::Vec;

use crate::{
    ExecutionId, ExecutionIntentDigest, LifecycleEventKind, LifecycleId, LifecycleRecordV1,
    LifecycleState, ProviderContractId, ProviderRequestDigest, StoreTransactionV1,
    TransitionDisposition, WorkflowId,
};

/// Failures at the trusted lifecycle-store boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    /// Store could not establish availability or durability.
    Unavailable,
    /// Compare-and-swap revision failed.
    Conflict,
    /// Pure lifecycle semantics rejected the command without mutation.
    Rejected(crate::LifecycleFailure),
    /// Persisted bytes or indexes were invalid.
    Corrupt,
    /// A hard storage or record limit was exceeded.
    LimitExceeded,
    /// Store returned an acknowledgement inconsistent with the transaction.
    InvalidAcknowledgement,
}

/// Store-produced transition acknowledgement.
///
/// Constructing this value is an explicit trusted adapter claim that the
/// record and receipt append satisfy the adapter's documented durability
/// contract. [`execute_store_transaction`] independently validates its
/// identity, revision, and trace before granting a sealed side-effect token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredTransitionV1 {
    record: LifecycleRecordV1,
    disposition: TransitionDisposition,
}

impl StoredTransitionV1 {
    /// Records one store adapter's durable acknowledgement.
    ///
    /// This constructor does not prove filesystem or database behavior. Store
    /// conformance evidence is required for each adapter.
    #[must_use]
    pub const fn acknowledged(
        record: LifecycleRecordV1,
        disposition: TransitionDisposition,
    ) -> Self {
        Self {
            record,
            disposition,
        }
    }
}

/// Atomic lifecycle-store port.
///
/// Implementations own locking, capacity snapshot acquisition, compare-and-
/// swap, receipt persistence, and commit acknowledgement. The supplied
/// transaction is semantic input; adapters MUST NOT trust a caller-supplied
/// capacity snapshot without deriving or validating it transactionally.
pub trait LifecycleStore {
    /// Atomically evaluates and durably commits, or returns an exact replay.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when state is unavailable, conflicting,
    /// malformed, over limit, or cannot be durably acknowledged.
    fn transact(&self, transaction: &StoreTransactionV1) -> Result<StoredTransitionV1, StoreError>;
}

/// Validated durable transition returned by the shared boundary.
///
/// Its fields are private so an untrusted command cannot directly manufacture
/// execution authorization from semantic inputs.
pub struct DurableTransitionV1 {
    record: LifecycleRecordV1,
    disposition: TransitionDisposition,
}

impl DurableTransitionV1 {
    /// Returns the durably acknowledged record.
    #[must_use]
    pub const fn record(&self) -> &LifecycleRecordV1 {
        &self.record
    }

    /// Returns whether the store changed state or returned an exact replay.
    #[must_use]
    pub const fn disposition(&self) -> TransitionDisposition {
        self.disposition
    }
}

/// Executes one transaction and rejects a dishonest or corrupted acknowledgement.
///
/// # Errors
///
/// Returns the adapter error or [`StoreError::InvalidAcknowledgement`] when
/// the returned workflow/revision/trace cannot correspond to the request.
pub fn execute_store_transaction(
    store: &impl LifecycleStore,
    transaction: &StoreTransactionV1,
) -> Result<DurableTransitionV1, StoreError> {
    let stored = store.transact(transaction)?;
    validate_acknowledgement(transaction, &stored)?;
    Ok(DurableTransitionV1 {
        record: stored.record,
        disposition: stored.disposition,
    })
}

fn validate_acknowledgement(
    transaction: &StoreTransactionV1,
    stored: &StoredTransitionV1,
) -> Result<(), StoreError> {
    if transaction.workflow_id != *stored.record.workflow_id() {
        return Err(StoreError::InvalidAcknowledgement);
    }
    if let crate::TransitionCommandV1::RecordDecision(input) = &transaction.command
        && input.workflow_id != transaction.workflow_id
    {
        return Err(StoreError::InvalidAcknowledgement);
    }
    match stored.disposition {
        TransitionDisposition::Applied => {
            let expected = transaction
                .expected_revision
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(StoreError::InvalidAcknowledgement)?;
            if stored.record.revision() != expected {
                return Err(StoreError::InvalidAcknowledgement);
            }
        }
        TransitionDisposition::ExactReplay => {
            if !matches!(
                transaction.command,
                crate::TransitionCommandV1::RecordDecision(_)
            ) {
                return Err(StoreError::InvalidAcknowledgement);
            }
        }
    }
    let Some(last) = stored.record.events().last() else {
        return Err(StoreError::InvalidAcknowledgement);
    };
    if last.revision != stored.record.revision()
        || stored
            .record
            .receipts()
            .last()
            .map(|receipt| receipt.revision)
            != Some(stored.record.revision())
    {
        return Err(StoreError::InvalidAcknowledgement);
    }
    Ok(())
}

/// Sealed proof that durable lifecycle state permits credential acquisition.
pub struct ExecutionAuthorizationV1 {
    workflow_id: WorkflowId,
    lifecycle_id: LifecycleId,
    execution_id: ExecutionId,
    revision: u64,
    execution_intent_digest: ExecutionIntentDigest,
    provider_contract_id: ProviderContractId,
    provider_request_digest: ProviderRequestDigest,
}

impl ExecutionAuthorizationV1 {
    /// Derives authorization only from a newly durable credential-authorization event.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::StageNotAuthorized`] for replayed, terminal,
    /// malformed, or incorrectly ordered records.
    pub fn from_durable(durable: &DurableTransitionV1) -> Result<Self, CredentialError> {
        let record = durable.record();
        let intent = record
            .execution_intent()
            .ok_or(CredentialError::StageNotAuthorized)?;
        let last = record
            .events()
            .last()
            .ok_or(CredentialError::StageNotAuthorized)?;
        if durable.disposition() != TransitionDisposition::Applied
            || record.state() != LifecycleState::ExecutionIntentRecorded
            || !record.credential_authorized()
            || last.kind != LifecycleEventKind::CredentialAuthorized
            || last.revision != record.revision()
        {
            return Err(CredentialError::StageNotAuthorized);
        }
        Ok(Self {
            workflow_id: record.workflow_id().clone(),
            lifecycle_id: record.lifecycle_id().clone(),
            execution_id: record.execution_id().clone(),
            revision: record.revision(),
            execution_intent_digest: intent.intent_digest(),
            provider_contract_id: intent.provider_contract_id().clone(),
            provider_request_digest: intent.provider_request_digest(),
        })
    }

    /// Returns workflow identity.
    #[must_use]
    pub const fn workflow_id(&self) -> &WorkflowId {
        &self.workflow_id
    }

    /// Returns lifecycle identity.
    #[must_use]
    pub const fn lifecycle_id(&self) -> &LifecycleId {
        &self.lifecycle_id
    }

    /// Returns execution identity.
    #[must_use]
    pub const fn execution_id(&self) -> &ExecutionId {
        &self.execution_id
    }

    /// Returns store-acknowledged revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns exact execution-intent commitment.
    #[must_use]
    pub const fn execution_intent_digest(&self) -> ExecutionIntentDigest {
        self.execution_intent_digest
    }

    /// Returns domain-owned provider contract.
    #[must_use]
    pub const fn provider_contract_id(&self) -> &ProviderContractId {
        &self.provider_contract_id
    }

    /// Returns exact provider request commitment.
    #[must_use]
    pub const fn provider_request_digest(&self) -> ProviderRequestDigest {
        self.provider_request_digest
    }
}

/// Sealed proof that attempt and provider-call entry are both durable.
pub struct ProviderCallAuthorizationV1 {
    workflow_id: WorkflowId,
    execution_id: ExecutionId,
    revision: u64,
    provider_request_digest: ProviderRequestDigest,
}

impl ProviderCallAuthorizationV1 {
    /// Derives provider-call authorization from a newly durable call-entry event.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError::StageNotAuthorized`] for any other stage.
    pub fn from_durable(durable: &DurableTransitionV1) -> Result<Self, CredentialError> {
        let record = durable.record();
        let last_event = record
            .events()
            .last()
            .ok_or(CredentialError::StageNotAuthorized)?;
        let attempt = record
            .attempts()
            .last()
            .ok_or(CredentialError::StageNotAuthorized)?;
        if durable.disposition() != TransitionDisposition::Applied
            || record.state() != LifecycleState::Executing
            || !attempt.call_entered
            || last_event.kind != LifecycleEventKind::ProviderCallEntered
            || last_event.revision != record.revision()
        {
            return Err(CredentialError::StageNotAuthorized);
        }
        Ok(Self {
            workflow_id: record.workflow_id().clone(),
            execution_id: record.execution_id().clone(),
            revision: record.revision(),
            provider_request_digest: attempt.provider_request_digest,
        })
    }

    /// Returns exact provider request commitment.
    #[must_use]
    pub const fn provider_request_digest(&self) -> ProviderRequestDigest {
        self.provider_request_digest
    }

    /// Returns workflow identity.
    #[must_use]
    pub const fn workflow_id(&self) -> &WorkflowId {
        &self.workflow_id
    }

    /// Returns execution identity.
    #[must_use]
    pub const fn execution_id(&self) -> &ExecutionId {
        &self.execution_id
    }

    /// Returns store-acknowledged revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

/// Credential acquisition failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialError {
    /// Durable lifecycle stage does not authorize acquisition.
    StageNotAuthorized,
    /// Broker could not issue exact-operation credentials.
    Unavailable,
}

/// Opaque credential material deliberately lacking `Debug`, cloning, and serialization.
pub struct CredentialMaterial {
    bytes: Vec<u8>,
}

impl CredentialMaterial {
    /// Creates credential material inside a trusted broker.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Exposes credentials only to one scoped operation closure.
    pub fn expose<R>(&self, operation: impl FnOnce(&[u8]) -> R) -> R {
        operation(&self.bytes)
    }
}

impl Drop for CredentialMaterial {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// Domain credential broker boundary.
pub trait CredentialBroker {
    /// Acquires exact-operation credentials from sealed durable authorization.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialError`] when credentials are unavailable.
    fn acquire(
        &self,
        authorization: &ExecutionAuthorizationV1,
    ) -> Result<CredentialMaterial, CredentialError>;
}
