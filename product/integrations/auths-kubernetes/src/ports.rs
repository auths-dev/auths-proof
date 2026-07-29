//! Narrow effect ports for protected Kubernetes rollout execution.

#![allow(
    clippy::missing_errors_doc,
    reason = "each effect port returns the closed PortError documented directly below the interfaces"
)]

use std::sync::Arc;

use auths_model::CanonicalAction;
use auths_sdk::{Authorized, RequestContext};

use crate::{
    executor::VerifiedRolloutCommand,
    profile::KubernetesRolloutCommand,
    receipts::KubernetesReceipt,
    types::{KubernetesRolloutResult, KubernetesWorkloadRolloutV1},
};

/// Mutation credential that cannot be serialized or logged.
pub struct KubernetesCredential(Vec<u8>);

impl KubernetesCredential {
    /// Wraps a bounded non-empty token.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, PortError> {
        let value = value.into();
        if !(16..=16 * 1024).contains(&value.len()) || value.iter().any(u8::is_ascii_whitespace) {
            return Err(PortError::InvalidConfiguration);
        }
        Ok(Self(value))
    }

    /// Exposes bytes only to the protected Kubernetes adapter.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for KubernetesCredential {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Auths kernel outcome.
pub enum ProofDecision {
    Authorized(Box<Authorized<KubernetesRolloutCommand>>),
    Denied { code: String },
    Indeterminate { code: String },
}

/// Auths proof-verification boundary.
pub trait ProofVerifier: Send + Sync {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<ProofDecision, PortError>;
}

/// Protected mutation-credential broker.
pub trait CredentialProvider: Send + Sync {
    fn mutation_credential(
        &self,
        action: &KubernetesWorkloadRolloutV1,
    ) -> Result<KubernetesCredential, PortError>;
}

/// Only Kubernetes write and rollout-observation boundary.
pub trait KubernetesGateway: Send + Sync {
    fn apply_and_observe(
        &self,
        command: &VerifiedRolloutCommand,
        credential: &KubernetesCredential,
        now: u64,
    ) -> Result<KubernetesRolloutResult, PortError>;

    /// Reconciles an ambiguous request without resubmitting it.
    fn reconcile(
        &self,
        command: &VerifiedRolloutCommand,
        credential: &KubernetesCredential,
        now: u64,
    ) -> Result<KubernetesRolloutResult, PortError>;
}

/// Append-only receipt boundary.
pub trait ReceiptSink: Send + Sync {
    fn append(&self, receipt: &KubernetesReceipt) -> Result<(), PortError>;
}

/// Trusted time boundary.
pub trait Clock: Send + Sync {
    fn now(&self) -> Result<u64, PortError>;
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
        action: &KubernetesWorkloadRolloutV1,
    ) -> Result<KubernetesCredential, PortError> {
        (**self).mutation_credential(action)
    }
}
impl<T: KubernetesGateway + ?Sized> KubernetesGateway for Arc<T> {
    fn apply_and_observe(
        &self,
        command: &VerifiedRolloutCommand,
        credential: &KubernetesCredential,
        now: u64,
    ) -> Result<KubernetesRolloutResult, PortError> {
        (**self).apply_and_observe(command, credential, now)
    }

    fn reconcile(
        &self,
        command: &VerifiedRolloutCommand,
        credential: &KubernetesCredential,
        now: u64,
    ) -> Result<KubernetesRolloutResult, PortError> {
        (**self).reconcile(command, credential, now)
    }
}
impl<T: ReceiptSink + ?Sized> ReceiptSink for Arc<T> {
    fn append(&self, receipt: &KubernetesReceipt) -> Result<(), PortError> {
        (**self).append(receipt)
    }
}
impl<T: Clock + ?Sized> Clock for Arc<T> {
    fn now(&self) -> Result<u64, PortError> {
        (**self).now()
    }
}

/// Closed effect failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PortError {
    #[error("invalid Kubernetes adapter configuration")]
    InvalidConfiguration,
    #[error("Kubernetes adapter limit exceeded")]
    LimitExceeded,
    #[error("malformed Kubernetes adapter data")]
    Malformed,
    #[error("Kubernetes evidence is unavailable")]
    EvidenceUnavailable,
    #[error("Auths verifier integration failed")]
    Verification,
    #[error("durable Kubernetes workflow state is unavailable")]
    Persistence,
    #[error("Kubernetes rejected the exact request")]
    Execution,
    #[error("Kubernetes request outcome is unknown")]
    OutcomeUnknown,
    #[error("persisted Kubernetes state differs from the authorized projection")]
    PersistedStateMismatch,
    #[error("Kubernetes rollout did not converge")]
    RolloutFailed,
}
