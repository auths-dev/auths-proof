//! Exact Auths authorization for separate Stripe-local financial profiles.
//!
//! Stripe vocabulary, evidence, containment, idempotency, execution, and
//! receipts remain in this vertical product package. The proposing agent never
//! receives a Stripe credential. Refunds, automatic collection, and manual
//! authorization retain distinct actions, evaluators, verified commands,
//! provider gateways, services, receipts, and lifecycle effects.

#![forbid(unsafe_code)]

/// Build-time sentinel used by the production agent to reject accidental
/// linkage of Stripe's synthetic testkit surface.
#[doc(hidden)]
pub const __TESTKIT_AGENT_ENABLED: bool = cfg!(feature = "testkit-agent");

pub mod adapters;
pub mod bounded;
pub mod bounded_service;
pub mod canonical;
pub mod claim;
pub mod connect;
pub mod connection;
pub mod decision;
pub mod executor;
pub mod generated;
pub mod issuing;
pub mod lifecycle;
pub mod local_agent;
pub mod local_configuration;
pub mod mandate;
pub mod merchant;
pub mod ports;
pub mod profile;
pub mod protected_evidence;
#[cfg(feature = "qualification")]
pub mod qualification;
pub mod receipts;
pub mod reservation;
pub mod service;
pub mod subscription;
pub mod treasury;
pub mod types;

#[cfg(any(test, feature = "fixture-support"))]
#[doc(hidden)]
pub mod test_support;

pub use adapters::{SdkProofVerifier, SystemClock};
pub use auths_lifecycle::ExecutionAuthorizationV1;
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
    ExecuteBoundedRefundRequest, reconcile_bounded_refund,
};
pub use claim::{
    ClaimLease, ClaimRecord, ClaimResult, ClaimStage, ClaimStore, InMemoryClaimStore,
    PersistentClaimStore,
};
pub use connect::*;
pub use decision::{Decision, DecisionClass, DecisionCode, EvaluationContext, evaluate};
pub use executor::{LifecycleVerifiedRefundCommand, RefundExecutionCommand, VerifiedRefundCommand};
pub use issuing::*;
pub use lifecycle::{
    StripeLifecycleDecisionBindings, StripeLifecycleProjectionError,
    StripeLifecycleProjectionInput, StripeLifecycleProjectionV1, project_refund_lifecycle,
};
pub use local_configuration::{StripeRefundEvidenceStoreV1, StripeRefundLocalAgentConfigurationV1};
pub use mandate::*;
pub use merchant::*;
pub use ports::{
    Clock, ConnectTransferCredential, ConnectTransferCredentialScope, CredentialProvider,
    LifecycleRefundCredentialProvider, PaymentAuthorizeCredential, PaymentAuthorizeCredentialScope,
    PaymentCancelCredential, PaymentCancelCredentialScope, PaymentCaptureCredential,
    PaymentCaptureCredentialScope, PaymentCollectCredential, PaymentCollectCredentialScope,
    PaymentMandateCredential, PaymentMandateCredentialScope, PayoutCredential,
    PayoutCredentialScope, PortError, ProofDecision, ProofVerifier,
    PurchaseAuthorizationCredential, PurchaseAuthorizationCredentialScope, ReceiptSink,
    RefundCredentialScope, StripeCredential, StripeGateway, StripeRefundCredential,
    SubscriptionCancelCredential, SubscriptionCancelCredentialScope, SubscriptionCreateCredential,
    SubscriptionCreateCredentialScope, SubscriptionModifyCredential,
    SubscriptionModifyCredentialScope,
};
pub use profile::{StripeRefundCommand, StripeRefundProfile};
pub use protected_evidence::{
    ProtectedRefundEvidenceSnapshotV1, StripeEvidenceStoreError, StripeRefundEvidencePhase,
    StripeRefundEvidenceRequestV1, request_refund_evidence_snapshot,
};
pub use receipts::{
    BoundedDecisionReceipt, BoundedDecisionReceiptInput, DecisionReceipt, ExecutionReceipt,
    ObservationReceipt, ReservationReceipt, StripeReceipt,
};
pub use reservation::{
    InMemoryRefundReservationStore, PersistentRefundReservationStore, ReconciledRefundOutcome,
    RefundLifecycleMutation, RefundLifecycleStore, RefundLifecycleTransaction,
    RefundReservationLease, RefundReservationRecord, RefundReservationState,
    RefundReservationStore, ReservationError, ReserveRefundRequest, ReserveRefundResult,
    read_persistent_refund_snapshot,
};
pub use service::{
    ExecuteRefundRequest, RefundService, ServiceDependencies, ServiceError, WorkflowOutcome,
};
pub use subscription::*;
pub use treasury::*;
pub use types::{
    BalanceTransactionId, ChargeId, Currency, CustomerId, DigestHex, EventId,
    ExactRefundActionInput, ExactRefundActionV1, ExternalAccountId, InvoiceId,
    IssuingAuthorizationId, IssuingCardId, IssuingCardholderId, MandateId, Money, PaymentIntentId,
    PaymentMethodId, PayoutId, PriceId, ProductId, RefundEvidenceInput, RefundEvidenceV1, RefundId,
    RefundResult, SetupAttemptId, SetupIntentId, StripeAccountId, StripeVerifierConfiguration,
    StripeVerifierConfigurationInput, SubscriptionId, SubscriptionItemId, TestClockId, TransferId,
};
