//! Closed, digest-bound request construction from native-verified MCP commands.
//!
//! Compilation is not installation or authorization. A separate operator
//! binding and native proof verification are required before any request may
//! reach a credential-bearing transport.

#![forbid(unsafe_code)]

mod action_facts;
mod binding;
mod bounds;
mod engine;
mod observer;
mod recipe;
mod separation;
mod store;
mod transport;

#[cfg(test)]
mod observed_tests;
#[cfg(test)]
mod store_testkit;

pub use action_facts::{MCP_ARGUMENTS_V1, McpArgumentsPolicy};
pub use binding::{GatewayConnectionDescriptor, GatewayConnectionError};
pub use bounds::{
    ARGUMENT_CEILING_CANONICALIZATION_V1, ARGUMENT_CEILING_EVALUATOR_V1,
    ARGUMENT_CEILING_POLICY_TYPE_V1, ARGUMENT_CEILING_POLICY_VERSION, ArgumentCeilingPolicy,
    BoundedCountStore, BoundedPolicyError, MAX_WINDOW_COUNT, MAX_WINDOW_SECONDS,
    gateway_evaluator_registrations,
};
pub use engine::{
    GatewayEngine, GatewayEngineConfigurationError, GatewayEvidenceSummary, GatewayObserveRequest,
    GatewayObserveResult, GatewaySubmitResult, gateway_verifier_configuration,
};
pub use observer::{
    GatewayObserver, GatewayObserverError, GatewaySignedObservation, OBSERVATION_MEDIA_TYPE,
    OPERATION_SUBJECT_SCHEME, OUTCOME_SCHEMA, ObserverAnchorTemplate, ObserverCustody,
    READ_BACK_SCHEMA, operation_subject,
};
pub use recipe::{
    ClosedObservationRequest, ClosedProviderRequest, CompiledRecipe, CredentialRequirement,
    GatewayRecipeError, LogicalOperationId, OperatorNamespace, RecipeEchoReview,
    RecipePreconditionReview, RecipeReview, WriteMethod, echo_token,
};
pub use separation::{PrincipalSeparationError, check_principal_separation};
pub use store::{
    ClaimedGatewayAttempt, FileGatewayAttemptStore, GatewayAttemptError, GatewayAttemptKey,
    GatewayAttemptSnapshot, GatewayAttemptStage, GatewayAttemptStore, GatewayAttempts,
    GatewayEvidenceChannel, GatewayObservationFact, GatewayProviderEvidence,
    ObservableGatewayAttempt, PostgresGatewayAttemptStore,
};
