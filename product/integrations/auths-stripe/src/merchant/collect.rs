//! Exact automatic-capture collection vertical.

mod action;
mod evaluator;
mod execution;
mod profile;
mod receipts;
mod service;

pub use action::{StripeExactPaymentCollectInput, StripeExactPaymentCollectV1};
pub use evaluator::{
    PaymentCollectDecision, PaymentCollectDecisionClass, PaymentCollectDecisionCode,
    PaymentCollectDecisionStage, PaymentCollectEligibility, PaymentCollectEvaluationContext,
    evaluate_payment_collect,
};
pub use execution::{
    PaymentCollectEffect, PaymentCollectGateway, PaymentCollectProofDecision,
    PaymentCollectProofVerifier, SdkPaymentCollectProofVerifier, VerifiedPaymentCollectCommand,
    connected_account_header,
};
pub use profile::{StripePaymentCollectCommand, StripePaymentCollectProfile};
pub use receipts::{
    MerchantCollectionDecisionReceipt, MerchantCollectionObservationReceipt,
    MerchantCollectionTransitionReceipt, merchant_policy_provenance,
};
pub use service::{
    ExecutePaymentCollectRequest, MerchantServiceError, PaymentCollectService,
    PaymentCollectServiceDependencies, PaymentCollectWorkflowOutcome,
};
