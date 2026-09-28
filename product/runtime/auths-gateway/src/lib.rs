//! Closed, digest-bound request construction from native-verified MCP commands.
//!
//! Compilation is not installation or authorization. A separate operator
//! binding and native proof verification are required before any request may
//! reach a credential-bearing transport.

#![forbid(unsafe_code)]

#[cfg(unix)]
pub mod app;
mod audit;
mod binding;
mod bounds;
mod engine;
#[cfg(unix)]
pub mod listener;
mod observer;
mod onboarding;
mod pre_entry;
pub mod recipe;
mod separation;
mod store;
mod submit;
mod transport;

#[cfg(test)]
mod bounds_aggregate_tests;
#[cfg(any(test, feature = "testkit-harness"))]
pub mod harness;
#[cfg(test)]
mod observed_tests;
#[cfg(test)]
mod pending_vectors;
#[cfg(test)]
mod quorum_tests;
#[cfg(test)]
mod scenario_tests;
#[cfg(test)]
mod store_testkit;

pub use audit::{
    AUDIT_BUNDLE_SCHEMA, AUDIT_REPORT_SCHEMA, AuditPins, AuditReport, AuditStatus, AuditedEntry,
    MAX_AUDIT_BUNDLE_BYTES, MAX_AUDIT_ENTRIES, audit_bundle,
};
pub use binding::{GatewayConnectionDescriptor, GatewayConnectionError};
pub use bounds::{
    ARGUMENT_CEILING_CANONICALIZATION, ARGUMENT_CEILING_EVALUATOR, ARGUMENT_CEILING_POLICY_TYPE,
    ARGUMENT_CEILING_POLICY_VERSION, ArgumentCeilingPolicy, BoundedPolicyError, ListedValues,
    MAX_BOUNDED_LINKS, MAX_LISTED_VALUE_BYTES, MAX_LISTED_VALUES, MAX_SUM_LIMIT, MAX_WINDOW_COUNT,
    MAX_WINDOW_SECONDS, gateway_evaluator_registrations,
};
pub use engine::{
    GatewayEngine, GatewayEngineConfigurationError, GatewayEvidenceSummary, GatewayObserveRequest,
    GatewayObserveResult, GatewaySubmitResult, SLOT_SWEEP_INTERVAL_SECONDS, SLOT_SWEEP_LIMIT,
    gateway_verifier_configuration,
};
pub use observer::{
    GatewayObserver, GatewayObserverError, GatewaySignedObservation, OBSERVATION_MEDIA_TYPE,
    OPERATION_SUBJECT_SCHEME, OUTCOME_SCHEMA, ObserverAnchorTemplate, ObserverCustody,
    READ_BACK_SCHEMA, operation_subject,
};
pub use onboarding::{OnboardingAccount, OnboardingFailure, check_candidate_credential};
pub use recipe::{
    ClosedActionRead, ClosedCredentialRead, ClosedCredentialReads, ClosedObservationRequest,
    ClosedProviderRequest, CompiledRecipe, CredentialReadMethod, CredentialRequirement,
    GatewayRecipeError, IdempotencyKind, LogicalOperationId, LostClaimReentry, OperatorNamespace,
    ProviderHeaderClass, ProviderResponseRule, RECIPE_REVIEW_SCHEMA, RECIPE_SOURCE_SCHEMA,
    RECOVERY_CAPABILITY_SCHEMA, RecipeEchoReview, RecipePreconditionReview, RecipeReview,
    RecoveryCapability, RecoveryClass, RecoveryDeclarations, RequestHeader, StateObservation,
    UnknownResolution, WriteMethod, echo_token, idempotency_key, recovery_capability,
};
pub use separation::{PrincipalSeparationError, check_principal_separation};
pub use store::{
    ClaimedGatewayAttempt, FileGatewayAttemptStore, GatewayAttemptError, GatewayAttemptKey,
    GatewayAttemptSnapshot, GatewayAttemptStage, GatewayAttemptStore, GatewayAttempts,
    GatewayCounterEntry, GatewayCounterKind, GatewayEvidenceChannel, GatewayInsert,
    GatewayObservationFact, GatewayPreEntry, GatewayProviderEvidence, GatewayRecordEntry,
    GatewayRecordKind, GatewayRelativeBasis, ObservableGatewayAttempt, PostgresGatewayAttemptStore,
    pre_entry_digest,
};
