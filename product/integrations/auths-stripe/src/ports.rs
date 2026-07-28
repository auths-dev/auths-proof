//! Narrow effect ports for exact Stripe refund execution.

use auths_model::CanonicalAction;
use auths_sdk::{Authorized, RequestContext};
use std::sync::Arc;

use crate::{
    executor::VerifiedRefundCommand,
    profile::StripeRefundCommand,
    receipts::StripeReceipt,
    types::{RefundResult, StripeAccountId},
};

/// Secret mutation credential. It cannot be logged or serialized.
pub struct StripeCredential(Vec<u8>);

impl StripeCredential {
    /// Wraps a non-empty Stripe test-mode secret.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or non-test-mode credentials.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, PortError> {
        let value = value.into();
        if !(16..=512).contains(&value.len())
            || !value.starts_with(b"sk_test_")
            || value.iter().any(u8::is_ascii_whitespace)
        {
            return Err(PortError::InvalidConfiguration);
        }
        Ok(Self(value))
    }

    /// Exposes the credential only to the protected provider adapter.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for StripeCredential {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Auths proof-verification outcome.
pub enum ProofDecision {
    /// Exact authority was established.
    Authorized(Box<Authorized<StripeRefundCommand>>),
    /// Complete inputs establish denial.
    Denied {
        /// Stable Auths code.
        code: String,
    },
    /// A trustworthy input or implementation is unavailable.
    Indeterminate {
        /// Stable Auths code.
        code: String,
    },
}

/// Auths kernel boundary.
pub trait ProofVerifier: Send + Sync {
    /// Verifies proof against an already canonicalized action.
    ///
    /// # Errors
    ///
    /// Returns a closed integration failure, distinct from proof denial.
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<ProofDecision, PortError>;
}

/// Protected mutation-credential broker.
pub trait CredentialProvider: Send + Sync {
    /// Returns a restricted Stripe test key only after the caller owns a claim.
    ///
    /// # Errors
    ///
    /// Returns a closed configuration or availability failure.
    fn mutation_credential(&self, account: &StripeAccountId)
    -> Result<StripeCredential, PortError>;
}

/// Only Stripe refund write boundary.
pub trait StripeGateway: Send + Sync {
    /// Creates the exact verified refund using the exact idempotency key.
    ///
    /// # Errors
    ///
    /// `OutcomeUnknown` means request delivery may have reached Stripe and must
    /// be reconciled without generating a new idempotency key.
    fn create_refund(
        &self,
        command: &VerifiedRefundCommand,
        credential: &StripeCredential,
        now: u64,
    ) -> Result<RefundResult, PortError>;
}

/// Append-only receipt boundary.
pub trait ReceiptSink: Send + Sync {
    /// Durably appends one canonical receipt.
    ///
    /// # Errors
    ///
    /// Returns a closed persistence failure.
    fn append(&self, receipt: &StripeReceipt) -> Result<(), PortError>;
}

/// Trusted time boundary.
pub trait Clock: Send + Sync {
    /// Returns Unix time in seconds.
    ///
    /// # Errors
    ///
    /// Returns a closed time failure.
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
        account: &StripeAccountId,
    ) -> Result<StripeCredential, PortError> {
        (**self).mutation_credential(account)
    }
}

impl<T: StripeGateway + ?Sized> StripeGateway for Arc<T> {
    fn create_refund(
        &self,
        command: &VerifiedRefundCommand,
        credential: &StripeCredential,
        now: u64,
    ) -> Result<RefundResult, PortError> {
        (**self).create_refund(command, credential, now)
    }
}

impl<T: ReceiptSink + ?Sized> ReceiptSink for Arc<T> {
    fn append(&self, receipt: &StripeReceipt) -> Result<(), PortError> {
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
    /// Adapter configuration is unsafe.
    #[error("invalid Stripe adapter configuration")]
    InvalidConfiguration,
    /// External bytes exceed a hard limit.
    #[error("Stripe adapter limit exceeded")]
    LimitExceeded,
    /// External output is malformed.
    #[error("malformed Stripe adapter data")]
    Malformed,
    /// Fresh provider evidence is unavailable.
    #[error("Stripe evidence is unavailable")]
    EvidenceUnavailable,
    /// Auths integration failed.
    #[error("Auths verifier integration failed")]
    Verification,
    /// Durable state is unavailable.
    #[error("durable Stripe workflow state is unavailable")]
    Persistence,
    /// Provider rejected the exact request.
    #[error("Stripe rejected the refund request")]
    Execution,
    /// Request outcome is ambiguous and requires reconciliation.
    #[error("Stripe request outcome is unknown")]
    OutcomeUnknown,
}
