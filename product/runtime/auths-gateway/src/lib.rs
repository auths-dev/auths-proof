//! Closed, digest-bound request construction from native-verified MCP commands.
//!
//! Compilation is not installation or authorization. A separate operator
//! binding and native proof verification are required before any request may
//! reach a credential-bearing transport.

#![forbid(unsafe_code)]

pub mod admin;
#[cfg(unix)]
pub mod app;
mod audit;
mod binding;
mod bounds;
mod connection;
mod echo_verify;
mod engine;
#[cfg(feature = "fuzzing")]
pub mod fuzzing;
#[cfg(unix)]
pub mod listener;
mod observer;
mod onboarding;
mod operator;
mod pre_entry;
mod readiness;
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
mod property_tests;
#[cfg(test)]
mod quorum_tests;
#[cfg(test)]
mod scenario_tests;
#[cfg(test)]
mod store_testkit;

pub use audit::{
    AUDIT_BUNDLE_SCHEMA, AUDIT_REPORT_SCHEMA, AuditPins, AuditReport, AuditStatus,
    AuditedApprovalResponse, AuditedEntry, AuditedPreEntry, MAX_AUDIT_BUNDLE_BYTES,
    MAX_AUDIT_ENTRIES, MAX_AUDIT_PRE_ENTRY_OBSERVATIONS, ProviderResult, UnverifiedEntries,
    audit_bundle,
};
pub use binding::{GatewayConnectionDescriptor, GatewayConnectionError};
pub use bounds::{
    ARGUMENT_CEILING_CANONICALIZATION, ARGUMENT_CEILING_EVALUATOR, ARGUMENT_CEILING_POLICY_TYPE,
    ARGUMENT_CEILING_POLICY_VERSION, ArgumentCeilingPolicy, BoundedPolicyError, ListedValues,
    MAX_BOUNDED_LINKS, MAX_LISTED_VALUE_BYTES, MAX_LISTED_VALUES, MAX_SUM_LIMIT, MAX_WINDOW_COUNT,
    MAX_WINDOW_SECONDS, gateway_evaluator_registrations,
};
pub use connection::{
    LoadedConnection, SharedConnection, SharedConnectionError, authorizes_entry, connection_key,
    install_connection, join_connection,
};
pub use echo_verify::{
    ECHO_VERIFICATION_NOTE, ECHO_VERIFICATION_SCHEMA, EchoResult, EchoVerification,
    EchoVerifyError, MAX_ECHO_POINTER_BYTES, MAX_ECHO_RECORD_BYTES, canonical_action_commitment,
    echo_verify, echo_verify_bundle,
};
pub use engine::{
    GatewayAdminOutcome, GatewayAdminStatus, GatewayEngine, GatewayEngineConfigurationError,
    GatewayEvidenceSummary, GatewayObserveRequest, GatewayObserveResult, GatewaySubmitResult,
    SLOT_SWEEP_INTERVAL_SECONDS, SLOT_SWEEP_LIMIT, gateway_verifier_configuration,
};
pub use observer::{
    GatewayObserver, GatewayObserverError, GatewaySignedObservation, OBSERVATION_MEDIA_TYPE,
    OPERATION_SUBJECT_SCHEME, OUTCOME_SCHEMA, ObserverAnchorTemplate, ObserverCustody,
    READ_BACK_SCHEMA, operation_subject,
};
#[cfg(feature = "loopback-provider")]
pub use onboarding::check_candidate_credential_loopback;
pub use onboarding::{OnboardingAccount, OnboardingFailure, check_candidate_credential};
pub use operator::{
    MAX_ISSUED_AHEAD_SECONDS, MAX_OPERATOR_ATTESTATION_BYTES, MAX_OPERATOR_EVIDENCE,
    OPERATOR_ATTESTATION_SCHEMA, OperatorAttestation, OperatorAttestationError, OperatorEvidence,
    OperatorInstallation, OperatorStatement, verify_operator_attestation,
};
pub use readiness::{
    ClockTrustState, CredentialRetirementDelay, ObserverCustodyState, PreconditionState,
    ProductionReadiness, ReadinessPrecondition, RequiredPreconditions, credential_store_policy,
};
pub use recipe::{
    ClosedActionRead, ClosedCredentialRead, ClosedCredentialReads, ClosedObservationRequest,
    ClosedProviderRequest, CompiledRecipe, CredentialReadMethod, CredentialRequirement,
    GatewayRecipeError, IdempotencyKind, LogicalOperationId, LostClaimReentry, OperatorNamespace,
    ProviderHeaderClass, ProviderResponseRule, RECIPE_REVIEW_SCHEMA, RECIPE_SOURCE_SCHEMA,
    RECOVERY_CAPABILITY_SCHEMA, RecipeEchoReview, RecipePreconditionReview, RecipeReview,
    RecoveryCapability, RecoveryClass, RecoveryDeclarations, RequestHeader, StateObservation,
    UnknownResolution, WriteMethod, echo_token, idempotency_key, recovery_capability,
};
pub use separation::{
    PrincipalSeparationError, check_anchor_aliasing, check_principal_separation, key_identity,
    principals_overlap,
};
pub use store::{
    ClaimedGatewayAttempt, FileGatewayAttemptStore, GatewayAttemptError, GatewayAttemptKey,
    GatewayAttemptSnapshot, GatewayAttemptStage, GatewayAttemptStore, GatewayAttempts,
    GatewayCounterEntry, GatewayCounterKind, GatewayEvidenceChannel, GatewayInsert,
    GatewayObservationFact, GatewayPreEntry, GatewayProviderEvidence, GatewayRecordEntry,
    GatewayRecordKind, GatewayRelativeBasis, ObservableGatewayAttempt, PostgresGatewayAttemptStore,
    PrivateDirectoryError, check_private_directory, check_private_directory_owned_by,
    pre_entry_digest,
};
pub use transport::MAX_TRANSPORT_DURATION;
