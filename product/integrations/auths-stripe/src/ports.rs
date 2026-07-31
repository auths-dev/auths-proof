//! Narrow shared mechanism ports for exact Stripe execution.

use auths_lifecycle::ExecutionAuthorizationV1;
use auths_model::CanonicalAction;
use auths_sdk::{Authorized, RequestContext};
use std::{marker::PhantomData, sync::Arc};

use crate::{
    executor::RefundExecutionCommand,
    profile::StripeRefundCommand,
    types::{RefundResult, StripeAccountId},
};

/// Type marker for the exact-refund credential scope.
pub enum RefundCredentialScope {}

/// Type marker for the exact automatic-collection credential scope.
pub enum PaymentCollectCredentialScope {}

/// Type marker for the exact manual-authorization credential scope.
pub enum PaymentAuthorizeCredentialScope {}

/// Type marker for the exact final-capture credential scope.
pub enum PaymentCaptureCredentialScope {}

/// Type marker for the exact `PaymentIntent` cancellation credential scope.
pub enum PaymentCancelCredentialScope {}

/// Type marker for exact `SetupIntent` creation, confirmation, and retrieval.
pub enum PaymentMandateCredentialScope {}

/// Type marker for exact fixed-term Subscription creation.
pub enum SubscriptionCreateCredentialScope {}

/// Type marker for one exact bounded Subscription modification.
pub enum SubscriptionModifyCredentialScope {}

/// Type marker for one exact Subscription cancellation.
pub enum SubscriptionCancelCredentialScope {}

/// Type marker for read-only Issuing authorization reconciliation.
pub enum PurchaseAuthorizationCredentialScope {}

/// Type marker for exact Connect Transfer creation and reconciliation.
pub enum ConnectTransferCredentialScope {}

/// Type marker for exact manual Payout creation and reconciliation.
pub enum PayoutCredentialScope {}

/// Secret Stripe credential bound to one compile-time effect scope.
///
/// A credential with one scope cannot be passed to a provider gateway for
/// another scope. It cannot be logged or serialized.
pub struct StripeCredential<S = RefundCredentialScope> {
    value: Vec<u8>,
    scope: PhantomData<fn() -> S>,
}

/// Exact-refund credential.
pub type StripeRefundCredential = StripeCredential<RefundCredentialScope>;

/// Exact automatic-collection credential.
///
/// An authorization-scoped credential cannot cross this boundary:
///
/// ```compile_fail
/// use auths_stripe::{
///     PaymentAuthorizeCredential, PaymentCollectGateway, VerifiedPaymentCollectCommand,
/// };
///
/// fn wrong_scope(
///     gateway: &dyn PaymentCollectGateway,
///     command: &VerifiedPaymentCollectCommand,
///     credential: &PaymentAuthorizeCredential,
/// ) {
///     let _ = gateway.collect(command, credential, 0);
/// }
/// ```
pub type PaymentCollectCredential = StripeCredential<PaymentCollectCredentialScope>;

/// Exact manual-authorization credential.
pub type PaymentAuthorizeCredential = StripeCredential<PaymentAuthorizeCredentialScope>;

/// Exact final-capture credential.
///
/// An authorization-scoped credential cannot cross the capture boundary:
///
/// ```compile_fail
/// use auths_stripe::{
///     PaymentAuthorizeCredential, PaymentCaptureGateway, VerifiedPaymentCaptureCommand,
/// };
///
/// fn wrong_scope(
///     gateway: &dyn PaymentCaptureGateway,
///     command: &VerifiedPaymentCaptureCommand,
///     credential: &PaymentAuthorizeCredential,
/// ) {
///     let _ = gateway.capture(command, credential, 0);
/// }
/// ```
pub type PaymentCaptureCredential = StripeCredential<PaymentCaptureCredentialScope>;

/// Exact `PaymentIntent` cancellation credential.
///
/// A capture-scoped credential cannot cross the cancellation boundary:
///
/// ```compile_fail
/// use auths_stripe::{
///     PaymentCancelGateway, PaymentCaptureCredential, VerifiedPaymentCancelCommand,
/// };
///
/// fn wrong_scope(
///     gateway: &dyn PaymentCancelGateway,
///     command: &VerifiedPaymentCancelCommand,
///     credential: &PaymentCaptureCredential,
/// ) {
///     let _ = gateway.cancel(command, credential, 0);
/// }
/// ```
pub type PaymentCancelCredential = StripeCredential<PaymentCancelCredentialScope>;

/// Exact payment-mandate credential.
///
/// A collection-scoped credential cannot cross the mandate boundary:
///
/// ```compile_fail
/// use auths_stripe::{
///     PaymentCollectCredential, PaymentMandateGateway, VerifiedPaymentMandateCommand,
/// };
///
/// fn wrong_scope(
///     gateway: &dyn PaymentMandateGateway,
///     command: &VerifiedPaymentMandateCommand,
///     credential: &PaymentCollectCredential,
/// ) {
///     let _ = gateway.create_and_confirm(command, credential, 0);
/// }
/// ```
pub type PaymentMandateCredential = StripeCredential<PaymentMandateCredentialScope>;

/// Exact subscription-create credential.
///
/// A mandate credential cannot cross the subscription-create boundary:
///
/// ```compile_fail
/// use auths_stripe::{
///     PaymentMandateCredential, SubscriptionCreateGateway,
///     VerifiedSubscriptionCreateCommand,
/// };
///
/// fn wrong_scope(
///     gateway: &dyn SubscriptionCreateGateway,
///     command: &VerifiedSubscriptionCreateCommand,
///     credential: &PaymentMandateCredential,
/// ) {
///     let _ = gateway.create(command, credential, 0);
/// }
/// ```
pub type SubscriptionCreateCredential = StripeCredential<SubscriptionCreateCredentialScope>;

/// Exact subscription-modify credential.
///
/// A create credential cannot cross the modify boundary:
///
/// ```compile_fail
/// use auths_stripe::{
///     SubscriptionCreateCredential, SubscriptionModifyGateway,
///     VerifiedSubscriptionModifyCommand,
/// };
///
/// fn wrong_scope(
///     gateway: &dyn SubscriptionModifyGateway,
///     command: &VerifiedSubscriptionModifyCommand,
///     credential: &SubscriptionCreateCredential,
/// ) {
///     let _ = gateway.modify(command, credential, 0);
/// }
/// ```
pub type SubscriptionModifyCredential = StripeCredential<SubscriptionModifyCredentialScope>;

/// Credential restricted to Subscription cancellation.
///
/// ```compile_fail
/// use auths_stripe::{SubscriptionCancelCredential, SubscriptionModifyCredential};
///
/// fn wrong_scope(credential: SubscriptionModifyCredential) -> SubscriptionCancelCredential {
///     credential
/// }
/// ```
pub type SubscriptionCancelCredential = StripeCredential<SubscriptionCancelCredentialScope>;

/// Credential restricted to the Issuing purchase-authorization profile.
///
/// A merchant authorization credential cannot cross the Issuing boundary:
///
/// ```compile_fail
/// use auths_stripe::{
///     IssuingAuthorizationId, PaymentAuthorizeCredential, PurchaseAuthorizationGateway,
/// };
///
/// fn wrong_scope(
///     gateway: &dyn PurchaseAuthorizationGateway,
///     authorization: &IssuingAuthorizationId,
///     credential: &PaymentAuthorizeCredential,
/// ) {
///     let _ = gateway.retrieve(authorization, credential, 0);
/// }
/// ```
pub type PurchaseAuthorizationCredential = StripeCredential<PurchaseAuthorizationCredentialScope>;

/// Credential restricted to the Connect-transfer profile.
///
/// A refund credential cannot cross the transfer boundary:
///
/// ```compile_fail
/// use auths_stripe::{
///     ConnectTransferCredential, StripeRefundCredential, StripeCredential,
/// };
///
/// fn wrong_scope(credential: StripeRefundCredential) -> ConnectTransferCredential {
///     credential
/// }
/// ```
pub type ConnectTransferCredential = StripeCredential<ConnectTransferCredentialScope>;

/// Credential restricted to the manual-payout profile.
///
/// A Connect Transfer credential cannot cross the payout boundary:
///
/// ```compile_fail
/// use auths_stripe::{ConnectTransferCredential, PayoutCredential};
///
/// fn wrong_scope(credential: ConnectTransferCredential) -> PayoutCredential {
///     credential
/// }
/// ```
pub type PayoutCredential = StripeCredential<PayoutCredentialScope>;

impl<S> StripeCredential<S> {
    /// Wraps a non-empty Stripe test-mode secret.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or non-test-mode credentials.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, PortError> {
        let value = value.into();
        if !(16..=512).contains(&value.len())
            || !(value.starts_with(b"sk_test_") || value.starts_with(b"rk_test_"))
            || value.iter().any(u8::is_ascii_whitespace)
        {
            return Err(PortError::InvalidConfiguration);
        }
        Ok(Self {
            value,
            scope: PhantomData,
        })
    }

    /// Exposes the credential only to the protected provider adapter.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.value
    }
}

impl<S> Drop for StripeCredential<S> {
    fn drop(&mut self) {
        self.value.fill(0);
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

/// Protected credential broker fixed to one compile-time effect scope.
pub trait CredentialProvider<S = RefundCredentialScope>: Send + Sync {
    /// Returns a scope-bound Stripe test key only after the caller owns a claim.
    ///
    /// # Errors
    ///
    /// Returns a closed configuration or availability failure.
    fn credential(&self, account: &StripeAccountId) -> Result<StripeCredential<S>, PortError>;
}

/// Refund credential broker that requires a newly durable shared lifecycle
/// authorization token.
pub trait LifecycleRefundCredentialProvider: Send + Sync {
    /// Returns the exact refund credential only for the durably authorized
    /// workflow and account.
    ///
    /// # Errors
    ///
    /// Returns a closed configuration or availability failure.
    fn credential_after_authorization(
        &self,
        authorization: &ExecutionAuthorizationV1,
        account: &StripeAccountId,
    ) -> Result<StripeRefundCredential, PortError>;
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
        command: &dyn RefundExecutionCommand,
        credential: &StripeRefundCredential,
        now: u64,
    ) -> Result<RefundResult, PortError>;
}

/// Append-only receipt boundary typed to one closed receipt family.
pub trait ReceiptSink<R>: Send + Sync {
    /// Durably appends one canonical receipt.
    ///
    /// # Errors
    ///
    /// Returns a closed persistence failure.
    fn append(&self, receipt: &R) -> Result<(), PortError>;
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

impl<T, S> CredentialProvider<S> for Arc<T>
where
    T: CredentialProvider<S> + ?Sized,
{
    fn credential(&self, account: &StripeAccountId) -> Result<StripeCredential<S>, PortError> {
        (**self).credential(account)
    }
}

impl<T: LifecycleRefundCredentialProvider + ?Sized> LifecycleRefundCredentialProvider for Arc<T> {
    fn credential_after_authorization(
        &self,
        authorization: &ExecutionAuthorizationV1,
        account: &StripeAccountId,
    ) -> Result<StripeRefundCredential, PortError> {
        (**self).credential_after_authorization(authorization, account)
    }
}

impl<T: StripeGateway + ?Sized> StripeGateway for Arc<T> {
    fn create_refund(
        &self,
        command: &dyn RefundExecutionCommand,
        credential: &StripeRefundCredential,
        now: u64,
    ) -> Result<RefundResult, PortError> {
        (**self).create_refund(command, credential, now)
    }
}

impl<T, R> ReceiptSink<R> for Arc<T>
where
    T: ReceiptSink<R> + ?Sized,
{
    fn append(&self, receipt: &R) -> Result<(), PortError> {
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

#[cfg(test)]
mod tests {
    use std::any::TypeId;

    use super::{
        ConnectTransferCredential, PaymentAuthorizeCredential, PaymentCancelCredential,
        PaymentCaptureCredential, PaymentCollectCredential, PaymentMandateCredential,
        PayoutCredential, PurchaseAuthorizationCredential, StripeRefundCredential,
        SubscriptionCancelCredential, SubscriptionCreateCredential, SubscriptionModifyCredential,
    };

    #[test]
    fn credential_types_are_distinct_per_effect_scope() {
        assert_ne!(
            TypeId::of::<PaymentCollectCredential>(),
            TypeId::of::<PaymentAuthorizeCredential>()
        );
        assert_ne!(
            TypeId::of::<PaymentCollectCredential>(),
            TypeId::of::<StripeRefundCredential>()
        );
        assert_ne!(
            TypeId::of::<PaymentAuthorizeCredential>(),
            TypeId::of::<StripeRefundCredential>()
        );
        assert_ne!(
            TypeId::of::<PaymentAuthorizeCredential>(),
            TypeId::of::<PaymentCaptureCredential>()
        );
        assert_ne!(
            TypeId::of::<PaymentCollectCredential>(),
            TypeId::of::<PaymentCaptureCredential>()
        );
        assert_ne!(
            TypeId::of::<PaymentCaptureCredential>(),
            TypeId::of::<StripeRefundCredential>()
        );
        assert_ne!(
            TypeId::of::<PaymentCancelCredential>(),
            TypeId::of::<PaymentCaptureCredential>()
        );
        assert_ne!(
            TypeId::of::<PaymentCancelCredential>(),
            TypeId::of::<PaymentAuthorizeCredential>()
        );
        assert_ne!(
            TypeId::of::<PaymentMandateCredential>(),
            TypeId::of::<PaymentCollectCredential>()
        );
        assert_ne!(
            TypeId::of::<PaymentMandateCredential>(),
            TypeId::of::<PaymentAuthorizeCredential>()
        );
        assert_ne!(
            TypeId::of::<PaymentMandateCredential>(),
            TypeId::of::<StripeRefundCredential>()
        );
        assert_ne!(
            TypeId::of::<SubscriptionCreateCredential>(),
            TypeId::of::<SubscriptionModifyCredential>()
        );
        assert_ne!(
            TypeId::of::<PaymentMandateCredential>(),
            TypeId::of::<SubscriptionModifyCredential>()
        );
        assert_ne!(
            TypeId::of::<SubscriptionCancelCredential>(),
            TypeId::of::<SubscriptionModifyCredential>()
        );
        assert_ne!(
            TypeId::of::<SubscriptionCancelCredential>(),
            TypeId::of::<SubscriptionCreateCredential>()
        );
        assert_ne!(
            TypeId::of::<PurchaseAuthorizationCredential>(),
            TypeId::of::<PaymentAuthorizeCredential>()
        );
        assert_ne!(
            TypeId::of::<PurchaseAuthorizationCredential>(),
            TypeId::of::<SubscriptionModifyCredential>()
        );
        assert_ne!(
            TypeId::of::<ConnectTransferCredential>(),
            TypeId::of::<StripeRefundCredential>()
        );
        assert_ne!(
            TypeId::of::<ConnectTransferCredential>(),
            TypeId::of::<PurchaseAuthorizationCredential>()
        );
        assert_ne!(
            TypeId::of::<PayoutCredential>(),
            TypeId::of::<ConnectTransferCredential>()
        );
        assert!(PaymentCaptureCredential::new(b"rk_test_repository_test_value".to_vec()).is_ok());
    }
}
