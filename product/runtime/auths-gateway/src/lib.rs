//! Closed, digest-bound request construction from native-verified MCP commands.
//!
//! Compilation is not installation or authorization. A separate operator
//! binding and native proof verification are required before any request may
//! reach a credential-bearing transport.

#![forbid(unsafe_code)]

mod binding;
mod engine;
mod recipe;
mod store;
mod transport;

pub use binding::{GatewayConnectionDescriptor, GatewayConnectionError};
pub use engine::{
    GatewayEngine, GatewayEngineConfigurationError, GatewayEvidenceSummary, GatewaySubmitResult,
};
pub use recipe::{
    ClosedObservationRequest, ClosedProviderRequest, CompiledRecipe, CredentialRequirement,
    GatewayRecipeError, LogicalOperationId, OperatorNamespace, RecipeEchoReview, RecipeReview,
    WriteMethod, echo_token,
};
pub use store::{
    ClaimedGatewayAttempt, FileGatewayAttemptStore, GatewayAttemptError, GatewayAttemptSnapshot,
    GatewayAttemptStage, GatewayEvidenceChannel, GatewayObservationFact, GatewayProviderEvidence,
    ObservableGatewayAttempt,
};
