//! Pure product-layer semantics for closed bounded authorization.
//!
//! This crate owns commitments and eligibility mechanics only. Domain
//! packages retain policy payloads, evaluators, reservation payloads,
//! obligations, diagnostics, commands, credentials, stores, and receipts.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod arithmetic;
mod commitment;
mod eligibility;
mod identifier;
pub mod kernel;
mod receipt;
mod registry;

pub use arithmetic::{
    ArithmeticError, BasisPoints, RoundingDirection, UnitQuantity, checked_basis_points,
};
pub use commitment::{
    CommitmentError, ConfigurationCommitmentV1, ConfigurationMatch, EvaluationCommitmentsV1,
    PolicyCommitmentV1, configuration_match,
};
pub use eligibility::{
    BoundedOutputs, EligibilityV1, ObligationClass, ObligationCommitmentV1, OutputError,
    ReservationIntentCommitmentV1, ReservationKind, ValidationWork,
};
pub use identifier::{
    CanonicalizationId, ConfigurationSemanticId, EvaluatorSemanticId, EvidenceSourceId,
    IdentifierError, ImplementationId, IntentId, ObligationId, PolicyTypeId, ProfileId, SchemaId,
    StableCode, StableStage, UnitId,
};
pub use receipt::BoundedDecisionEnvelopeV1;
pub use registry::{EvaluatorRegistrationV1, RegistryError, validate_registry};

/// The immutable V1 contract identity.
pub const CONTRACT_ID: &str = "auths.product.bounded-policy-contract/1";
/// The immutable V1 policy commitment identity.
pub const POLICY_COMMITMENT_ID: &str = "auths.product.policy-commitment/1";
/// The immutable V1 evaluation commitment identity.
pub const EVALUATION_COMMITMENTS_ID: &str = "auths.product.evaluation-commitments/1";
/// The immutable V1 configuration gate identity.
pub const CONFIGURATION_MATCH_ID: &str = "auths.product.configuration-match/1";
/// The immutable V1 eligibility identity.
pub const ELIGIBILITY_ID: &str = "auths.product.eligibility/1";
/// The immutable V1 checked arithmetic identity.
pub const CHECKED_ARITHMETIC_ID: &str = "auths.product.checked-arithmetic/1";
/// The immutable V1 bounded decision envelope identity.
pub const DECISION_ENVELOPE_ID: &str = "auths.product.bounded-decision-envelope/1";
/// The immutable V1 compatibility identity.
pub const COMPATIBILITY_ID: &str = "auths.product.bounded-policy-compatibility/1";

/// Maximum canonical bytes accepted for any policy/evidence/action/state
/// payload by conformance tooling.
pub const MAX_CONFORMANCE_PAYLOAD_BYTES: usize = 1024 * 1024;
/// Maximum reservation intents returned by one pure evaluation.
pub const MAX_RESERVATION_INTENTS: usize = 32;
/// Maximum obligations returned by one pure evaluation.
pub const MAX_OBLIGATIONS: usize = 32;
/// Maximum combined canonical bytes committed by intents and obligations.
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;
/// Maximum nested canonical product-policy depth.
pub const MAX_PRODUCT_POLICY_DEPTH: usize = 16;

/// A fixed 32-byte cryptographic commitment.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CommitmentDigest([u8; 32]);

impl CommitmentDigest {
    /// Constructs an exact-width commitment.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Explicit verifier time in whole Unix seconds.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct VerifierTime(u64);

impl VerifierTime {
    /// Constructs an explicit verifier time.
    #[must_use]
    pub const fn from_unix_seconds(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Returns whole Unix seconds.
    #[must_use]
    pub const fn unix_seconds(self) -> u64 {
        self.0
    }
}
