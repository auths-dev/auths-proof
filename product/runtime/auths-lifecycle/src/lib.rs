//! Product-layer reservation and execution lifecycle semantics.
//!
//! The crate owns deterministic lifecycle mechanics only. Domain packages
//! retain action and evidence meaning, provider requests, credentials,
//! idempotency contracts, reconciliation interpretation, and domain receipts.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod codec;
mod digest;
mod identifier;
pub mod kernel;
mod model;
mod registry;
mod sealed;
#[cfg(feature = "test-support")]
pub mod test_support;
mod transition;

pub use codec::{CodecError, decode_record, encode_record};
pub use digest::{
    DecisionReceiptDigest, DomainReceiptDigest, ExecutionIntentDigest, LifecycleReceiptDigest,
    ObservationDigest, ProviderConditionDigest, ProviderRequestDigest, ProviderResultDigest,
    ReservationSetDigest, TypedDigest,
};
pub use identifier::{
    DomainId, ExecutionId, ExecutorAudienceId, IdentifierError, LifecycleId, ProviderContractId,
    ReconciliationId, ReservationAlgebraId, ReservationId, ReservationUnitId, WorkflowId,
};
pub use model::{
    AttemptOrdinal, AttemptOrdinalError, CancellationDisposition, CapacityEntryV1,
    CapacitySnapshotError, CapacitySnapshotV1, DecisionInputV1, EffectConclusion,
    ExecutionIntentV1, LifecycleEventKind, LifecycleEventV1, LifecycleReceiptEnvelopeV1,
    LifecycleRecordV1, LifecycleState, LifecycleWork, ProviderAttemptV1, ProviderRetryClass,
    ReconciliationObservationV1, ReservationEntryV1, ReservationMode, ReservationRequestV1,
    ReservationSetError, ReservationSetV1, RevocationSnapshotV1, StoreTransactionV1,
    TransitionCommandV1, TransitionContextV1,
};
pub use registry::{LifecycleRegistrationV1, LifecycleRegistryError, validate_lifecycle_registry};
pub use sealed::{
    CredentialBroker, CredentialError, CredentialMaterial, DurableTransitionV1,
    ExecutionAuthorizationV1, LifecycleStore, ProviderCallAuthorizationV1, StoreError,
    StoredTransitionV1, execute_store_transaction,
};
pub use transition::{
    LifecycleFailure, TransitionDisposition, TransitionError, TransitionResultV1, apply_transition,
};

/// Immutable lifecycle contract identity.
pub const CONTRACT_ID: &str = "auths.product.reservation-execution-contract/1";
/// Immutable reservation key identity.
pub const RESERVATION_KEY_ID: &str = "auths.product.reservation-key/1";
/// Immutable lifecycle-record identity.
pub const LIFECYCLE_RECORD_ID: &str = "auths.product.lifecycle-record/1";
/// Immutable execution-intent identity.
pub const EXECUTION_INTENT_ID: &str = "auths.product.execution-intent/1";
/// Immutable sealed execution-authorization identity.
pub const EXECUTION_AUTHORIZATION_ID: &str = "auths.product.execution-authorization/1";
/// Immutable provider-attempt identity.
pub const PROVIDER_ATTEMPT_ID: &str = "auths.product.provider-attempt/1";
/// Immutable reconciliation-observation identity.
pub const RECONCILIATION_OBSERVATION_ID: &str = "auths.product.reconciliation-observation/1";
/// Immutable lifecycle-receipt envelope identity.
pub const LIFECYCLE_RECEIPT_ID: &str = "auths.product.lifecycle-receipt-envelope/1";
/// Immutable store-contract identity.
pub const STORE_CONTRACT_ID: &str = "auths.product.lifecycle-store-contract/1";
/// Immutable transition-semantics identity.
pub const TRANSITION_ID: &str = "auths.product.lifecycle-transition/1";

/// Maximum UTF-8 bytes in a workflow identity.
pub const MAX_WORKFLOW_ID_BYTES: usize = 256;
/// Maximum bytes in domain/profile/provider/lifecycle semantic identities.
pub const MAX_SEMANTIC_ID_BYTES: usize = 128;
/// Maximum bytes in lifecycle, reservation, execution, and reconciliation identities.
pub const MAX_OPERATION_ID_BYTES: usize = 64;
/// Maximum reservation intents in one atomic set.
pub const MAX_RESERVATION_INTENTS: usize = 32;
/// Maximum provider attempts in one lifecycle.
pub const MAX_PROVIDER_ATTEMPTS: usize = 16;
/// Maximum reconciliation observations in one lifecycle.
pub const MAX_RECONCILIATION_OBSERVATIONS: usize = 32;
/// Maximum lifecycle events retained in one record.
pub const MAX_LIFECYCLE_EVENTS: usize = 128;
/// Maximum canonical lifecycle-record bytes.
pub const MAX_LIFECYCLE_RECORD_BYTES: usize = 256 * 1024;
/// Maximum nested composite reservation depth.
pub const MAX_COMPOSITE_DEPTH: usize = 16;
