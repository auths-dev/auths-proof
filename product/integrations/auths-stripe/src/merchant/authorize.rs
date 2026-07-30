//! Exact manual-capture authorization vertical.

mod action;
mod evaluator;
mod execution;
mod profile;
mod receipts;
mod service;

pub use action::{StripeExactPaymentAuthorizeInput, StripeExactPaymentAuthorizeV1};
pub use evaluator::{
    PaymentAuthorizeDecision, PaymentAuthorizeDecisionClass, PaymentAuthorizeDecisionCode,
    PaymentAuthorizeDecisionStage, PaymentAuthorizeEligibility, PaymentAuthorizeEvaluationContext,
    evaluate_payment_authorize,
};
pub use execution::{
    PaymentAuthorizeEffect, PaymentAuthorizeGateway, PaymentAuthorizeProofDecision,
    PaymentAuthorizeProofVerifier, PaymentAuthorizeProviderRequest,
    PaymentAuthorizeReconciliationOutcome, PaymentAuthorizeTransition,
    SdkPaymentAuthorizeProofVerifier, VerifiedPaymentAuthorizeCommand,
    transition_payment_authorize,
};
pub use profile::{StripePaymentAuthorizeCommand, StripePaymentAuthorizeProfile};
pub use receipts::{
    MerchantAuthorizationDecisionReceipt, MerchantAuthorizationObservationReceipt,
    MerchantAuthorizationTransitionReceipt, merchant_policy_provenance,
};
pub use service::{
    ExecutePaymentAuthorizeRequest, PaymentAuthorizeService, PaymentAuthorizeServiceDependencies,
    PaymentAuthorizeWorkflowOutcome,
};
