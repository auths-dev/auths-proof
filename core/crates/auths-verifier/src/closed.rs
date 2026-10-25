//! Closed principal/suite entry points for the AP-SPEC-061 configuration.
//!
//! These functions run the authoritative staged verifier, specialized to
//! concrete principal and suite enums and built-in pure handlers. Construction
//! and static dispatch are implementation boundaries to qualify, not evidence
//! that the full verifier proof has already been completed.

use auths_codec::CodecError;
use auths_did_key::DidKeyMethod;
use auths_model::{
    AdapterConfigurationId, ModelError, PrincipalMethodId, RegistryManifestId,
    SignatureSuiteId, VerifierConfigurationId,
};
use auths_ports::{
    ControlEvidence, PrincipalControlError, PrincipalControlInput, PrincipalMethod,
    SignatureError, SignatureInput, SignatureSuite,
    diagnostics::{ControlEvaluation, DiagnosticMode},
};
use auths_raw_key::RawKeyMethod;
use auths_registries::{RegistryAccess, RegistryError, StaticCoreRegistries};
use auths_signature::{Ed25519Suite, P256Sha256Suite};
use alloc::vec::Vec;

/// The self-certifying principal methods in this closed configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalKind { RawKeyV1, DidKeyV1 }

/// The signature suites in this closed configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuiteKind { Ed25519V1, P256Sha256V1 }

enum ClosedPrincipal { RawKey(RawKeyMethod), DidKey(DidKeyMethod) }
enum ClosedSuite { Ed25519(Ed25519Suite), P256(P256Sha256Suite) }

impl PrincipalMethod for ClosedPrincipal {
    fn id(&self) -> &PrincipalMethodId {
        match self {
            Self::RawKey(implementation) => implementation.id(),
            Self::DidKey(implementation) => implementation.id(),
        }
    }
    fn configuration_id(&self) -> AdapterConfigurationId {
        match self {
            Self::RawKey(implementation) => implementation.configuration_id(),
            Self::DidKey(implementation) => implementation.configuration_id(),
        }
    }
    fn maximum_work_units(&self) -> u64 {
        match self {
            Self::RawKey(implementation) => implementation.maximum_work_units(),
            Self::DidKey(implementation) => implementation.maximum_work_units(),
        }
    }
    fn verify_control(&self, input: PrincipalControlInput<'_>) -> Result<ControlEvidence, PrincipalControlError> {
        match self {
            Self::RawKey(implementation) => implementation.verify_control(input),
            Self::DidKey(implementation) => implementation.verify_control(input),
        }
    }
    fn evaluate_control(&self, input: PrincipalControlInput<'_>, diagnostics: DiagnosticMode) -> ControlEvaluation {
        match self {
            Self::RawKey(implementation) => implementation.evaluate_control(input, diagnostics),
            Self::DidKey(implementation) => implementation.evaluate_control(input, diagnostics),
        }
    }
}

impl SignatureSuite for ClosedSuite {
    fn id(&self) -> &SignatureSuiteId {
        match self {
            Self::Ed25519(implementation) => implementation.id(),
            Self::P256(implementation) => implementation.id(),
        }
    }
    fn configuration_id(&self) -> AdapterConfigurationId {
        match self {
            Self::Ed25519(implementation) => implementation.configuration_id(),
            Self::P256(implementation) => implementation.configuration_id(),
        }
    }
    fn validate_key(&self, verification_key: &[u8]) -> Result<(), SignatureError> {
        match self {
            Self::Ed25519(implementation) => implementation.validate_key(verification_key),
            Self::P256(implementation) => implementation.validate_key(verification_key),
        }
    }
    fn verify(&self, input: SignatureInput<'_>) -> Result<(), SignatureError> {
        match self {
            Self::Ed25519(implementation) => implementation.verify(input),
            Self::P256(implementation) => implementation.verify(input),
        }
    }
    fn work_units(&self) -> u64 {
        match self {
            Self::Ed25519(implementation) => implementation.work_units(),
            Self::P256(implementation) => implementation.work_units(),
        }
    }
}

fn principal(kind: Option<PrincipalKind>) -> Result<Option<ClosedPrincipal>, ModelError> {
    match kind {
        None => Ok(None),
        Some(PrincipalKind::RawKeyV1) => Ok(Some(ClosedPrincipal::RawKey(RawKeyMethod::new()?))),
        Some(PrincipalKind::DidKeyV1) => Ok(Some(ClosedPrincipal::DidKey(DidKeyMethod::new()?))),
    }
}
fn suite(kind: Option<SuiteKind>) -> Result<Option<ClosedSuite>, ModelError> {
    match kind {
        None => Ok(None),
        Some(SuiteKind::Ed25519V1) => Ok(Some(ClosedSuite::Ed25519(Ed25519Suite::new()?))),
        Some(SuiteKind::P256Sha256V1) => Ok(Some(ClosedSuite::P256(P256Sha256Suite::new()?))),
    }
}

/// Immutable closed executable configuration. There is no external-handler
/// variant or mutation API. Missing slots remain unavailable implementations.
pub struct ClosedRegistries {
    registries: StaticCoreRegistries<ClosedPrincipal, ClosedSuite>,
}

impl ClosedRegistries {
    /// Constructs the exact requested subset of the closed handler roster.
    /// Ordering and empty slots do not affect the configuration commitment.
    ///
    /// # Errors
    /// Returns a typed error for duplicate identifiers or invalid compiled
    /// registry identifiers.
    pub fn new(principals: [Option<PrincipalKind>; 2], suites: [Option<SuiteKind>; 2])
    -> Result<Self, RegistryError> {
        let methods = [
            principal(principals[0]).map_err(|_| RegistryError::InvalidBuiltin)?,
            principal(principals[1]).map_err(|_| RegistryError::InvalidBuiltin)?,
        ];
        let signatures = [
            suite(suites[0]).map_err(|_| RegistryError::InvalidBuiltin)?,
            suite(suites[1]).map_err(|_| RegistryError::InvalidBuiltin)?,
        ];
        Ok(Self { registries: StaticCoreRegistries::new(methods, signatures)? })
    }

    /// Constructs both self-certifying methods and both mandatory suites.
    ///
    /// # Errors
    /// Returns a typed error if a compiled registry identifier is invalid.
    pub fn standard() -> Result<Self, RegistryError> {
        Self::new(
            [Some(PrincipalKind::RawKeyV1), Some(PrincipalKind::DidKeyV1)],
            [Some(SuiteKind::Ed25519V1), Some(SuiteKind::P256Sha256V1)],
        )
    }

    /// Exact complete executable-configuration commitment.
    #[must_use]
    pub fn configuration_id(&self) -> VerifierConfigurationId { self.registries.configuration_id() }

    /// The target V1 registry manifest implemented by this configuration.
    #[must_use]
    pub fn manifest_id(&self) -> RegistryManifestId { self.registries.manifest_id() }
}

/// Runs the complete portable verifier with concrete closed handlers.
///
/// The trusted context must commit to this exact configuration. A requested
/// method, suite or pure handler outside it retains the ordinary unavailable
/// result; no fallback replaces a missing implementation.
///
/// # Errors
/// Returns a codec error only if encoding the constructed result fails.
pub fn verify_v1(
    proof_cbor: &[u8], canonical_action_cbor: &[u8], trusted_context_cbor: &[u8],
    registries: &ClosedRegistries,
) -> Result<Vec<u8>, CodecError> {
    crate::verify_v1(proof_cbor, canonical_action_cbor, trusted_context_cbor, &registries.registries)
}

/// Runs the same byte-oriented path and retains its sealed action capability.
///
/// # Errors
/// Returns a codec error only if encoding the constructed result fails.
pub fn verify_v1_sealed(
    proof_cbor: &[u8], canonical_action_cbor: &[u8], trusted_context_cbor: &[u8],
    registries: &ClosedRegistries,
) -> Result<crate::SealedVerificationResult, CodecError> {
    crate::verify_v1_sealed(proof_cbor, canonical_action_cbor, trusted_context_cbor, &registries.registries)
}

#[cfg(test)]
#[path = "closed_tests.rs"]
mod tests;
