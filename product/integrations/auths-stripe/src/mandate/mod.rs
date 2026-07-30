//! Exact, bounded Stripe future-payment capability establishment.
//!
//! This vertical deliberately owns its action, policy, consent evidence,
//! evaluator, capability state, gateway, service, and receipt family. A
//! mandate is not a payment and does not share merchant money reservations.

#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::struct_excessive_bools,
    clippy::too_many_lines,
    reason = "the profile exposes explicit, reviewable trust-boundary fields and closed results"
)]

mod action;
mod evaluator;
mod execution;
mod profile;
mod receipts;
mod service;
mod state;
mod trust;

pub use action::{
    MandateAmountType, MandateInterval, MandateUsage, StripeExactPaymentMandateInput,
    StripeExactPaymentMandateV1,
};
pub use evaluator::{
    PaymentMandateDecision, PaymentMandateDecisionClass, PaymentMandateDecisionCode,
    PaymentMandateDecisionStage, PaymentMandateEligibility, PaymentMandateEvaluationContext,
    evaluate_payment_mandate,
};
pub use execution::{
    PaymentMandateEffect, PaymentMandateGateway, PaymentMandateProofDecision,
    PaymentMandateProofVerifier, PaymentMandateProviderProjection,
    PaymentMandateReconciliationOutcome, PaymentMandateTransition, SdkPaymentMandateProofVerifier,
    VerifiedPaymentMandateCommand, transition_payment_mandate,
};
pub use profile::{StripePaymentMandateCommand, StripePaymentMandateProfile};
pub use receipts::{
    PaymentMandateDecisionReceipt, PaymentMandateObservationReceipt, PaymentMandateReceipt,
    PaymentMandateTransitionReceipt,
};
pub use service::{
    ExecutePaymentMandateRequest, PaymentMandateService, PaymentMandateServiceDependencies,
    PaymentMandateServiceError, PaymentMandateWorkflowOutcome,
};
pub use state::{
    InMemoryPaymentMandateStore, MandateStateError, PaymentMandateCapabilityRecord,
    PaymentMandateCapabilityState, PaymentMandateStore, PersistentPaymentMandateStore,
    ReservePaymentMandateRequest, ReservePaymentMandateResult,
};
pub use trust::{
    MandateConnectAccount, PaymentConsentEvidenceInput, PaymentConsentEvidenceV1,
    PaymentMandateEvidenceInput, PaymentMandateEvidenceV1, StripeBoundedPaymentMandatePolicyInput,
    StripeBoundedPaymentMandatePolicyV1, StripePaymentMandateConfigurationV1,
};

/// Exact V1 profile.
pub const PAYMENT_MANDATE_PROFILE: &str = "auths.stripe.exact-payment-mandate/1";
/// Immutable policy type.
pub const PAYMENT_MANDATE_POLICY_TYPE: &str = "auths.stripe.bounded-payment-mandate-policy/1";
/// Pure evaluator identity.
pub const PAYMENT_MANDATE_EVALUATOR_ID: &str = "auths.stripe.bounded-payment-mandate-evaluator/1";
/// Canonicalization identity.
pub const PAYMENT_MANDATE_CANONICALIZATION: &str = "rfc8785-sha256-v1";
/// Capability state schema.
pub const PAYMENT_MANDATE_CAPABILITY_SCHEMA: &str = "auths.stripe.payment-mandate-capability/1";
/// Receipt schema family.
pub const PAYMENT_MANDATE_RECEIPT_SCHEMA: &str = "auths.stripe.payment-mandate-receipt/1";

fn valid_local(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
}

fn valid_api_version(value: &str) -> bool {
    (10..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        && value.as_bytes().first().is_some_and(u8::is_ascii_digit)
}

fn sorted_unique_nonempty<T: Ord>(values: &[T]) -> bool {
    !values.is_empty() && values.len() <= 64 && values.windows(2).all(|pair| pair[0] < pair[1])
}

/// Closed validation error for mandate-owned values.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PaymentMandateValidationError {
    /// Invalid exact action.
    #[error("invalid exact payment-mandate action")]
    Action,
    /// Invalid immutable policy.
    #[error("invalid bounded payment-mandate policy")]
    Policy,
    /// Invalid evaluator configuration.
    #[error("invalid payment-mandate evaluator configuration")]
    Configuration,
    /// Invalid trusted consent.
    #[error("invalid payment consent evidence")]
    Consent,
    /// Invalid protected Stripe evidence.
    #[error("invalid payment-mandate Stripe evidence")]
    Evidence,
}
