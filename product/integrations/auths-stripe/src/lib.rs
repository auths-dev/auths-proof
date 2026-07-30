//! Exact Auths authorization for separate Stripe-local financial profiles.
//!
//! Stripe vocabulary, evidence, containment, idempotency, execution, and
//! receipts remain in this vertical product package. The proposing agent never
//! receives a Stripe credential. Refunds, automatic collection, and manual
//! authorization retain distinct actions, evaluators, verified commands,
//! provider gateways, services, receipts, and lifecycle effects.

#![forbid(unsafe_code)]

pub mod adapters;
pub mod bounded;
pub mod bounded_service;
pub mod canonical;
pub mod claim;
pub mod decision;
pub mod executor;
pub mod merchant;
pub mod ports;
pub mod profile;
pub mod receipts;
pub mod reservation;
pub mod service;
pub mod types;

#[cfg(test)]
mod test_support;

pub use adapters::{SdkProofVerifier, SystemClock};
pub use bounded::{
    AggregateBudgetSnapshot, AggregateBudgetUsage, AggregateRefundBudget, BOUNDED_CANONICALIZATION,
    BOUNDED_EVALUATOR_ID, BOUNDED_EVALUATOR_VERSION, BOUNDED_POLICY_TYPE, BOUNDED_POLICY_VERSION,
    BoundedDecisionClass, BoundedDecisionCode, BoundedDecisionStage, BoundedEvaluationContext,
    BoundedRefundDecision, BoundedRefundEligibility, BoundedValidationError,
    CONFIGURED_POLICY_PROVENANCE, ConnectScope, RefundBudgetWindow, RefundDenominator,
    RefundReservationIntent, RefundRounding, RefundWindowIdentity, RelativeRefundLimit,
    StripeBoundedEvaluatorConfigurationV1, StripeBoundedRefundPolicyInput,
    StripeBoundedRefundPolicyV1, evaluate_bounded_refund,
};
pub use bounded_service::{
    BoundedRefundService, BoundedServiceDependencies, BoundedWorkflowOutcome,
    ExecuteBoundedRefundRequest,
};
pub use claim::{
    ClaimLease, ClaimRecord, ClaimResult, ClaimStage, ClaimStore, InMemoryClaimStore,
    PersistentClaimStore,
};
pub use decision::{Decision, DecisionClass, DecisionCode, EvaluationContext, evaluate};
pub use executor::VerifiedRefundCommand;
pub use merchant::*;
pub use ports::{
    Clock, CredentialProvider, PaymentAuthorizeCredential, PaymentAuthorizeCredentialScope,
    PaymentCaptureCredential, PaymentCaptureCredentialScope, PaymentCollectCredential,
    PaymentCollectCredentialScope, PortError, ProofDecision, ProofVerifier, ReceiptSink,
    RefundCredentialScope, StripeCredential, StripeGateway, StripeRefundCredential,
};
pub use profile::{StripeRefundCommand, StripeRefundProfile};
pub use receipts::{
    BoundedDecisionReceipt, BoundedDecisionReceiptInput, DecisionReceipt, ExecutionReceipt,
    ObservationReceipt, ReservationReceipt, StripeReceipt,
};
pub use reservation::{
    InMemoryRefundReservationStore, PersistentRefundReservationStore, ReconciledRefundOutcome,
    RefundReservationLease, RefundReservationRecord, RefundReservationState,
    RefundReservationStore, ReservationError, ReserveRefundRequest, ReserveRefundResult,
};
pub use service::{
    ExecuteRefundRequest, RefundService, ServiceDependencies, ServiceError, WorkflowOutcome,
};
pub use types::{
    ChargeId, Currency, CustomerId, DigestHex, ExactRefundActionInput, ExactRefundActionV1, Money,
    PaymentIntentId, PaymentMethodId, RefundEvidenceInput, RefundEvidenceV1, RefundId,
    RefundResult, StripeAccountId, StripeVerifierConfiguration, StripeVerifierConfigurationInput,
};
