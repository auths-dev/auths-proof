//! Narrow protected boundaries for proof, credentials, database effects, and receipts.

use std::sync::Arc;

use async_trait::async_trait;
use auths_model::CanonicalAction;
use auths_sdk::{Authorized, RequestContext};
use serde::{Deserialize, Serialize};

use crate::{
    action::PostgresBoundedUpdateV1, executor::VerifiedBoundedUpdateCommand,
    profile::PostgresUpdateCommand, receipts::PostgresReceipt, schema::DigestHex,
};

/// Secret connection material; it is never serializable or printable.
pub struct PostgresCredential(Vec<u8>);

impl PostgresCredential {
    pub fn new(bytes: Vec<u8>) -> Result<Self, PortError> {
        if !(16..=64 * 1024).contains(&bytes.len()) {
            return Err(PortError::InvalidConfiguration);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for PostgresCredential {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Auths kernel result.
pub enum ProofDecision {
    Authorized(Box<Authorized<PostgresUpdateCommand>>),
    Denied { code: String },
    Indeterminate { code: String },
}

pub trait ProofVerifier: Send + Sync {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<ProofDecision, PortError>;
}

/// Credential broker invoked only after successful verification and claim.
pub trait CredentialProvider: Send + Sync {
    fn mutation_credential(
        &self,
        action: &PostgresBoundedUpdateV1,
    ) -> Result<PostgresCredential, PortError>;
}

/// Committed effect and privacy-safe transaction evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionResult {
    pub affected_rows: u32,
    pub after_state_digest: DigestHex,
    pub ledger_commitment: DigestHex,
    pub readback_commitment: DigestHex,
    pub server_version: String,
    pub transaction_started_at: u64,
    pub committed_at: u64,
    pub reconciled: bool,
}

/// Fresh ledger reconciliation result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reconciliation {
    Committed(TransactionResult),
    NotCommitted,
    Unavailable,
}

/// Database transaction boundary. Implementations must use SERIALIZABLE and
/// protocol parameters, and atomically commit the ledger with the update.
#[async_trait]
pub trait TransactionGateway: Send + Sync {
    async fn execute(
        &self,
        command: &VerifiedBoundedUpdateCommand,
        credential: &PostgresCredential,
        now: u64,
    ) -> Result<TransactionResult, PortError>;

    async fn reconcile(
        &self,
        action_digest: &DigestHex,
        credential: &PostgresCredential,
    ) -> Result<Reconciliation, PortError>;
}

pub trait ReceiptSink: Send + Sync {
    fn append(&self, receipt: &PostgresReceipt) -> Result<(), PortError>;
}

pub trait Clock: Send + Sync {
    fn now(&self) -> Result<u64, PortError>;
}

/// Closed protected-boundary failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PortError {
    #[error("proof verification failed")]
    Verification,
    #[error("credential unavailable")]
    CredentialUnavailable,
    #[error("invalid protected configuration")]
    InvalidConfiguration,
    #[error("persistence failed")]
    Persistence,
    #[error("serialization conflict")]
    TransactionConflict,
    #[error("row precondition changed")]
    BeforeStateMismatch,
    #[error("transaction cardinality mismatch")]
    CardinalityMismatch,
    #[error("transaction after-state mismatch")]
    AfterStateMismatch,
    #[error("database execution failed")]
    DatabaseExecution,
    #[error("commit outcome unknown")]
    OutcomeUnknown,
}

impl<T: ProofVerifier + ?Sized> ProofVerifier for Arc<T> {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<ProofDecision, PortError> {
        (**self).verify(proof, action, request)
    }
}

impl<T: CredentialProvider + ?Sized> CredentialProvider for Arc<T> {
    fn mutation_credential(
        &self,
        action: &PostgresBoundedUpdateV1,
    ) -> Result<PostgresCredential, PortError> {
        (**self).mutation_credential(action)
    }
}

#[async_trait]
impl<T: TransactionGateway + ?Sized> TransactionGateway for Arc<T> {
    async fn execute(
        &self,
        command: &VerifiedBoundedUpdateCommand,
        credential: &PostgresCredential,
        now: u64,
    ) -> Result<TransactionResult, PortError> {
        (**self).execute(command, credential, now).await
    }

    async fn reconcile(
        &self,
        action_digest: &DigestHex,
        credential: &PostgresCredential,
    ) -> Result<Reconciliation, PortError> {
        (**self).reconcile(action_digest, credential).await
    }
}

impl<T: ReceiptSink + ?Sized> ReceiptSink for Arc<T> {
    fn append(&self, receipt: &PostgresReceipt) -> Result<(), PortError> {
        (**self).append(receipt)
    }
}

impl<T: Clock + ?Sized> Clock for Arc<T> {
    fn now(&self) -> Result<u64, PortError> {
        (**self).now()
    }
}
