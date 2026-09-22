//! Closed, digest-bound request construction from native-verified MCP commands.
//!
//! Compilation is not installation or authorization. A separate operator
//! binding and native proof verification are required before any request may
//! reach a credential-bearing transport.

#![forbid(unsafe_code)]

mod recipe;

pub use recipe::{
    ClosedObservationRequest, ClosedProviderRequest, CompiledRecipe, CredentialRequirement,
    GatewayRecipeError, LogicalOperationId, OperatorNamespace, RecipeReview, WriteMethod,
};
