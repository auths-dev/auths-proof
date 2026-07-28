//! Exact, replay-safe Auths authorization for one Stripe refund.
//!
//! Stripe vocabulary, evidence, containment, idempotency, execution, and
//! receipts remain in this vertical product package. The proposing agent never
//! receives a Stripe credential.

#![forbid(unsafe_code)]

pub mod adapters;
pub mod canonical;
pub mod claim;
pub mod decision;
pub mod executor;
pub mod ports;
pub mod profile;
pub mod receipts;
pub mod service;
pub mod types;

#[cfg(test)]
mod test_support;

pub use adapters::{SdkProofVerifier, SystemClock};
pub use claim::{
    ClaimLease, ClaimRecord, ClaimResult, ClaimStage, ClaimStore, InMemoryClaimStore,
    PersistentClaimStore,
};
pub use decision::{Decision, DecisionClass, DecisionCode, EvaluationContext, evaluate};
pub use executor::VerifiedRefundCommand;
pub use ports::{
    Clock, CredentialProvider, PortError, ProofDecision, ProofVerifier, ReceiptSink,
    StripeCredential, StripeGateway,
};
pub use profile::{StripeRefundCommand, StripeRefundProfile};
pub use receipts::{DecisionReceipt, ExecutionReceipt, ObservationReceipt, StripeReceipt};
pub use service::{
    ExecuteRefundRequest, RefundService, ServiceDependencies, ServiceError, WorkflowOutcome,
};
pub use types::{
    ChargeId, Currency, DigestHex, ExactRefundActionInput, ExactRefundActionV1, Money,
    PaymentIntentId, RefundEvidenceInput, RefundEvidenceV1, RefundId, RefundResult,
    StripeAccountId, StripeVerifierConfiguration, StripeVerifierConfigurationInput,
};
