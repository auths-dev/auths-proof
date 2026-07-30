//! Closed Stripe-local bounded merchant-payment family.
//!
//! Shared code in this module is limited to the policy vocabulary, protected
//! evidence, aggregate accounting values, commitments, and durable storage
//! mechanics. Collection and authorization retain separate exact actions,
//! profiles, evaluators, lifecycle transitions, verified commands, gateways,
//! services, and receipts.

pub mod authorize;
mod budget;
pub mod cancel;
pub mod capture;
pub mod collect;
mod commitments;
mod evidence;
mod policy;
pub mod state;

pub use authorize::{
    ExecutePaymentAuthorizeRequest, MerchantAuthorizationDecisionReceipt,
    MerchantAuthorizationObservationReceipt, MerchantAuthorizationReceipt,
    MerchantAuthorizationTransitionReceipt, PaymentAuthorizeDecision,
    PaymentAuthorizeDecisionClass, PaymentAuthorizeDecisionCode, PaymentAuthorizeDecisionStage,
    PaymentAuthorizeEffect, PaymentAuthorizeEligibility, PaymentAuthorizeEvaluationContext,
    PaymentAuthorizeGateway, PaymentAuthorizeProofDecision, PaymentAuthorizeProofVerifier,
    PaymentAuthorizeProviderRequest, PaymentAuthorizeReconciliationOutcome,
    PaymentAuthorizeService, PaymentAuthorizeServiceDependencies, PaymentAuthorizeTransition,
    PaymentAuthorizeWorkflowOutcome, SdkPaymentAuthorizeProofVerifier,
    StripeExactPaymentAuthorizeInput, StripeExactPaymentAuthorizeV1, StripePaymentAuthorizeCommand,
    StripePaymentAuthorizeProfile, VerifiedPaymentAuthorizeCommand, evaluate_payment_authorize,
    transition_payment_authorize,
};
pub use budget::{
    MerchantAggregateBudget, MerchantAggregateSnapshot, MerchantAggregateUsage,
    MerchantBudgetWindow, MerchantReservationIntent, MerchantWindowIdentity,
};
pub use cancel::{
    ExecutePaymentCancelRequest, MerchantCancelDecisionReceipt, MerchantCancelObservationReceipt,
    MerchantCancelReceipt, MerchantCancelServiceError, MerchantCancelTransitionReceipt,
    PaymentCancelDecision, PaymentCancelDecisionClass, PaymentCancelDecisionCode,
    PaymentCancelDecisionStage, PaymentCancelEffect, PaymentCancelEligibility,
    PaymentCancelEvaluationContext, PaymentCancelEvidenceInput, PaymentCancelEvidenceV1,
    PaymentCancelGateway, PaymentCancelProofDecision, PaymentCancelProofVerifier,
    PaymentCancelProviderProjection, PaymentCancelProviderRequest,
    PaymentCancelReconciliationOutcome, PaymentCancelService, PaymentCancelServiceDependencies,
    PaymentCancelTransition, PaymentCancelWorkflowOutcome, PaymentCancellationReason,
    SdkPaymentCancelProofVerifier, StripeExactPaymentCancelInput, StripeExactPaymentCancelV1,
    StripePaymentCancelCommand, StripePaymentCancelProfile, VerifiedPaymentCancelCommand,
    evaluate_payment_cancel, transition_payment_cancel,
};
pub use capture::{
    ExecutePaymentCaptureRequest, MerchantCaptureDecisionReceipt,
    MerchantCaptureObservationReceipt, MerchantCaptureReceipt, MerchantCaptureServiceError,
    MerchantCaptureTransitionReceipt, PaymentCaptureDecision, PaymentCaptureDecisionClass,
    PaymentCaptureDecisionCode, PaymentCaptureDecisionStage, PaymentCaptureEffect,
    PaymentCaptureEligibility, PaymentCaptureEvaluationContext, PaymentCaptureEvidenceInput,
    PaymentCaptureEvidenceV1, PaymentCaptureGateway, PaymentCaptureProofDecision,
    PaymentCaptureProofVerifier, PaymentCaptureProviderProjection, PaymentCaptureProviderRequest,
    PaymentCaptureReconciliationOutcome, PaymentCaptureService, PaymentCaptureServiceDependencies,
    PaymentCaptureTransition, PaymentCaptureWorkflowOutcome, SdkPaymentCaptureProofVerifier,
    StripeExactPaymentCaptureInput, StripeExactPaymentCaptureV1, StripePaymentCaptureCommand,
    StripePaymentCaptureProfile, VerifiedPaymentCaptureCommand, evaluate_payment_capture,
    transition_payment_capture,
};
pub use collect::{
    ExecutePaymentCollectRequest, MerchantCollectionDecisionReceipt,
    MerchantCollectionObservationReceipt, MerchantCollectionReceipt,
    MerchantCollectionTransitionReceipt, MerchantServiceError, PaymentCollectDecision,
    PaymentCollectDecisionClass, PaymentCollectDecisionCode, PaymentCollectDecisionStage,
    PaymentCollectEffect, PaymentCollectEligibility, PaymentCollectEvaluationContext,
    PaymentCollectGateway, PaymentCollectProofDecision, PaymentCollectProofVerifier,
    PaymentCollectProviderRequest, PaymentCollectReconciliationOutcome, PaymentCollectService,
    PaymentCollectServiceDependencies, PaymentCollectTransition, PaymentCollectWorkflowOutcome,
    SdkPaymentCollectProofVerifier, StripeExactPaymentCollectInput, StripeExactPaymentCollectV1,
    StripePaymentCollectCommand, StripePaymentCollectProfile, VerifiedPaymentCollectCommand,
    evaluate_payment_collect, transition_payment_collect,
};
pub use commitments::{
    fixed_merchant_metadata_commitment, merchant_statement_descriptor_commitment,
};
pub use evidence::{
    MerchantPaymentEvidenceInput, MerchantPaymentEvidenceV1, PriorMerchantPayment,
    PriorMerchantPaymentState,
};
pub use policy::{
    MERCHANT_CANONICALIZATION, MERCHANT_EVALUATOR_ID, MERCHANT_EVALUATOR_VERSION,
    MERCHANT_POLICY_PROVENANCE, MERCHANT_POLICY_TYPE, MERCHANT_POLICY_VERSION,
    MerchantConnectAccount, MerchantEvaluatorCommitment, MerchantOperation,
    PAYMENT_AUTHORIZE_PROFILE, PAYMENT_CANCEL_PROFILE, PAYMENT_CAPTURE_PROFILE,
    PAYMENT_COLLECT_PROFILE, PAYMENT_STATEMENT_DESCRIPTOR, StripeBoundedMerchantPaymentPolicyInput,
    StripeBoundedMerchantPaymentPolicyV1, StripeMerchantEvaluatorConfigurationV1,
};
pub use state::{
    InMemoryMerchantPaymentStore, MerchantPaymentStore, MerchantProviderProjection,
    MerchantReservationLease, MerchantReservationRecord, MerchantReservationState,
    MerchantStateError, PersistentMerchantPaymentStore, ReserveMerchantPaymentRequest,
    ReserveMerchantPaymentResult, ReservePaymentCancelRequest, ReservePaymentCaptureRequest,
};

fn valid_nonempty_sorted<T: Ord>(values: &[T]) -> bool {
    !values.is_empty() && values.len() <= 64 && values.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_local_id(value: &str) -> bool {
    (1..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
}

fn valid_workflow_id(value: &str) -> bool {
    (8..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_payment_method_type(value: &str) -> bool {
    value == "card"
}

fn valid_api_version(value: &str) -> bool {
    (10..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        && value.as_bytes().first().is_some_and(u8::is_ascii_digit)
}

/// Closed merchant-payment value validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MerchantValidationError {
    /// Policy violates exact V1 invariants.
    #[error("invalid Stripe bounded merchant-payment policy")]
    InvalidPolicy,
    /// Runtime configuration violates exact V1 invariants.
    #[error("invalid Stripe merchant-payment evaluator configuration")]
    InvalidConfiguration,
    /// Protected evidence is malformed or contradictory.
    #[error("invalid Stripe merchant-payment evidence")]
    InvalidEvidence,
    /// Exact action violates V1 invariants.
    #[error("invalid exact Stripe merchant-payment action")]
    InvalidAction,
    /// Canonical identity could not be produced.
    #[error("could not canonicalize Stripe merchant-payment value")]
    Canonicalization,
}
