//! Closed, digest-bound request construction from native-verified MCP commands.
//!
//! Compilation is not installation or authorization. A separate operator
//! binding and native proof verification are required before any request may
//! reach a credential-bearing transport.

#![forbid(unsafe_code)]

mod action_facts;
mod binding;
mod engine;
mod observer;
mod recipe;
mod store;
mod transport;

#[cfg(test)]
mod observed_tests;

pub use action_facts::{MCP_ARGUMENTS_V1, McpArgumentsPolicy};
pub use binding::{GatewayConnectionDescriptor, GatewayConnectionError};
pub use engine::{
    GatewayEngine, GatewayEngineConfigurationError, GatewayEvidenceSummary, GatewayObserveRequest,
    GatewayObserveResult, GatewaySubmitResult, gateway_verifier_configuration,
};
pub use observer::{
    GatewayObserver, GatewayObserverError, GatewaySignedObservation, OBSERVATION_MEDIA_TYPE,
    OPERATION_SUBJECT_SCHEME, OUTCOME_SCHEMA, ObserverAnchorTemplate, READ_BACK_SCHEMA,
    operation_subject,
};
pub use recipe::{
    ClosedObservationRequest, ClosedProviderRequest, CompiledRecipe, CredentialRequirement,
    GatewayRecipeError, LogicalOperationId, OperatorNamespace, RecipeEchoReview,
    RecipePreconditionReview, RecipeReview, WriteMethod, echo_token,
};
pub use store::{
    ClaimedGatewayAttempt, FileGatewayAttemptStore, GatewayAttemptError, GatewayAttemptSnapshot,
    GatewayAttemptStage, GatewayEvidenceChannel, GatewayObservationFact, GatewayProviderEvidence,
    ObservableGatewayAttempt,
};
