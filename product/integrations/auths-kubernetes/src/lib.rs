//! Exact, replay-safe Auths authorization for one Kubernetes Deployment rollout.
//!
//! Kubernetes vocabulary, evidence, containment, lifecycle projection,
//! execution ports, reconciliation, and receipts remain in this product
//! package. The proposing agent never receives a kubeconfig, `ServiceAccount`
//! token, or reusable cluster credential.

#![forbid(unsafe_code)]

pub mod adapters;
pub mod canonical;
pub mod claim;
pub mod decision;
pub mod executor;
pub mod lifecycle;
pub mod ports;
pub mod profile;
pub mod receipts;
pub mod service;
pub mod test_support;
pub mod types;

pub use adapters::{FixedClock, MemoryReceiptSink, SdkProofVerifier, SystemClock};
pub use claim::{ClaimRecord, ClaimStage};
pub use decision::{Decision, DecisionClass, DecisionCode, EvaluationContext, evaluate};
pub use executor::VerifiedRolloutCommand;
pub use lifecycle::{
    KubernetesLifecycleDecisionBindings, KubernetesLifecycleProjectionError,
    KubernetesLifecycleProjectionInput, KubernetesLifecycleProjectionV1, reservation_scope_digest,
};
pub use ports::{
    Clock, CredentialProvider, KubernetesCredential, KubernetesGateway, PortError, ProofDecision,
    ProofVerifier, ReceiptSink,
};
pub use profile::{KubernetesRolloutCommand, KubernetesRolloutProfile};
pub use receipts::{DecisionReceipt, ExecutionReceipt, KubernetesReceipt};
pub use service::{
    ExecuteRolloutRequest, KubernetesLifecycleStore, RolloutService, ServiceDependencies,
    ServiceError, WorkflowOutcome,
};
pub use types::*;
