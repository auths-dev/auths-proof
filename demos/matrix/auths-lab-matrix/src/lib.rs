//! Bounded factorial experiment model for Auths Lab.
//!
//! This crate contains no production runtime logic. It enumerates the target
//! principal/suite/transport/profile surface, records reproducible build and
//! environment metadata, checks transport invariance, and captures operator
//! study outcomes without collecting proof or principal contents.

#![forbid(unsafe_code)]

use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

const MAX_OBSERVATIONS: usize = 100_000;
const MAX_LABEL_BYTES: usize = 256;

/// Target principal-control family.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PrincipalFamily {
    RawKey,
    DidKey,
    DidKeri,
    DidWeb,
    SpiffeX509,
    WebAuthn,
    HsmAttested,
}

impl PrincipalFamily {
    pub const ALL: [Self; 7] = [
        Self::RawKey,
        Self::DidKey,
        Self::DidKeri,
        Self::DidWeb,
        Self::SpiffeX509,
        Self::WebAuthn,
        Self::HsmAttested,
    ];
}

/// Mandatory target signature suite.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SignatureFamily {
    Ed25519,
    P256Sha256,
}

impl SignatureFamily {
    pub const ALL: [Self; 2] = [Self::Ed25519, Self::P256Sha256];
}

/// Target exchange transport.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TransportFamily {
    Memory,
    Iroh,
    Https,
    Tcp,
    Unix,
    File,
}

impl TransportFamily {
    pub const ALL: [Self; 6] = [
        Self::Memory,
        Self::Iroh,
        Self::Https,
        Self::Tcp,
        Self::Unix,
        Self::File,
    ];
}

/// Target application profile.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProfileFamily {
    Mcp,
    Http,
    Git,
    Deployment,
    SupplyChain,
    Edge,
}

impl ProfileFamily {
    pub const ALL: [Self; 6] = [
        Self::Mcp,
        Self::Http,
        Self::Git,
        Self::Deployment,
        Self::SupplyChain,
        Self::Edge,
    ];
}

/// One nominal point in the target 7 × 2 × 6 × 6 surface.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MatrixPoint {
    pub principal: PrincipalFamily,
    pub suite: SignatureFamily,
    pub transport: TransportFamily,
    pub profile: ProfileFamily,
}

impl MatrixPoint {
    /// Reports whether the baseline evidence family can expose the selected
    /// suite in the current target registry.
    #[must_use]
    pub fn is_compatible(self) -> bool {
        match self.principal {
            PrincipalFamily::RawKey
            | PrincipalFamily::DidKey
            | PrincipalFamily::DidKeri
            | PrincipalFamily::DidWeb => true,
            PrincipalFamily::SpiffeX509
            | PrincipalFamily::WebAuthn
            | PrincipalFamily::HsmAttested => self.suite == SignatureFamily::P256Sha256,
        }
    }
}

/// Enumerates all 504 nominal matrix points in stable axis order.
#[must_use]
pub fn nominal_matrix() -> Vec<MatrixPoint> {
    let mut points = Vec::with_capacity(504);
    for principal in PrincipalFamily::ALL {
        for suite in SignatureFamily::ALL {
            for transport in TransportFamily::ALL {
                for profile in ProfileFamily::ALL {
                    points.push(MatrixPoint {
                        principal,
                        suite,
                        transport,
                        profile,
                    });
                }
            }
        }
    }
    points
}

/// Enumerates current semantically compatible baseline points.
#[must_use]
pub fn compatible_matrix() -> Vec<MatrixPoint> {
    nominal_matrix()
        .into_iter()
        .filter(|point| point.is_compatible())
        .collect()
}

/// Stable semantic result recorded independently of timing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticResult {
    pub verdict: VerdictClass,
    pub diagnostic_digest: [u8; 32],
    pub action_digest: [u8; 32],
}

/// Three-valued authority outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerdictClass {
    Authorized,
    Denied,
    Indeterminate,
}

/// One reproducible experiment observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExperimentObservation {
    pub point: MatrixPoint,
    pub semantic: SemanticResult,
    pub proof_bytes: usize,
    pub evidence_bytes: usize,
    pub verification_micros: u64,
    pub total_micros: u64,
    pub cold_cache: bool,
    pub direct_path: Option<bool>,
}

/// Verifies that transport substitution did not change semantic output.
///
/// Measurements may differ. Semantic comparison groups observations by every
/// axis except transport.
///
/// # Errors
///
/// Returns a typed failure for an excessive input, duplicate transport point,
/// or semantic divergence.
pub fn assert_transport_invariance(observations: &[ExperimentObservation]) -> Result<(), LabError> {
    if observations.len() > MAX_OBSERVATIONS {
        return Err(LabError::LimitExceeded);
    }
    let mut groups = BTreeMap::<
        (PrincipalFamily, SignatureFamily, ProfileFamily, bool),
        (SemanticResult, BTreeSet<TransportFamily>),
    >::new();
    for observation in observations {
        let key = (
            observation.point.principal,
            observation.point.suite,
            observation.point.profile,
            observation.cold_cache,
        );
        let entry = groups
            .entry(key)
            .or_insert((observation.semantic, BTreeSet::new()));
        if entry.0 != observation.semantic {
            return Err(LabError::SemanticDivergence);
        }
        if !entry.1.insert(observation.point.transport) {
            return Err(LabError::DuplicateObservation);
        }
    }
    Ok(())
}

/// Privacy-preserving operator-study result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorStudy {
    task: String,
    completed: bool,
    elapsed_seconds: u64,
    error_count: u32,
    recovery_count: u32,
    over_granting_warnings: u32,
    notes_digest: [u8; 32],
}

impl OperatorStudy {
    /// Constructs one bounded, content-minimized study result.
    ///
    /// Free-form notes are reduced to a digest and are never retained.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed labels.
    pub fn new(
        task: impl Into<String>,
        completed: bool,
        elapsed_seconds: u64,
        error_count: u32,
        recovery_count: u32,
        over_granting_warnings: u32,
        notes: &[u8],
    ) -> Result<Self, LabError> {
        let task = task.into();
        if task.is_empty()
            || task.len() > MAX_LABEL_BYTES
            || task.bytes().any(|byte| {
                !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_'))
            })
        {
            return Err(LabError::InvalidLabel);
        }
        Ok(Self {
            task,
            completed,
            elapsed_seconds,
            error_count,
            recovery_count,
            over_granting_warnings,
            notes_digest: Sha256::digest(notes).into(),
        })
    }

    #[must_use]
    pub fn task(&self) -> &str {
        &self.task
    }

    #[must_use]
    pub const fn completed(&self) -> bool {
        self.completed
    }

    #[must_use]
    pub const fn elapsed_seconds(&self) -> u64 {
        self.elapsed_seconds
    }

    #[must_use]
    pub const fn error_count(&self) -> u32 {
        self.error_count
    }

    #[must_use]
    pub const fn recovery_count(&self) -> u32 {
        self.recovery_count
    }

    #[must_use]
    pub const fn over_granting_warnings(&self) -> u32 {
        self.over_granting_warnings
    }

    #[must_use]
    pub const fn notes_digest(&self) -> &[u8; 32] {
        &self.notes_digest
    }
}

/// Auths Lab data/model failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabError {
    InvalidLabel,
    LimitExceeded,
    DuplicateObservation,
    SemanticDivergence,
}

impl fmt::Display for LabError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLabel => "invalid Auths Lab label",
            Self::LimitExceeded => "Auths Lab observation limit exceeded",
            Self::DuplicateObservation => "duplicate Auths Lab matrix observation",
            Self::SemanticDivergence => "transport changed Auths semantic output",
        })
    }
}

impl std::error::Error for LabError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(transport: TransportFamily, digest: u8) -> ExperimentObservation {
        ExperimentObservation {
            point: MatrixPoint {
                principal: PrincipalFamily::RawKey,
                suite: SignatureFamily::Ed25519,
                transport,
                profile: ProfileFamily::Mcp,
            },
            semantic: SemanticResult {
                verdict: VerdictClass::Authorized,
                diagnostic_digest: [digest; 32],
                action_digest: [2; 32],
            },
            proof_bytes: 100,
            evidence_bytes: 20,
            verification_micros: 10,
            total_micros: 20,
            cold_cache: false,
            direct_path: None,
        }
    }

    #[test]
    fn matrix_has_504_nominal_and_396_compatible_points() {
        assert_eq!(nominal_matrix().len(), 504);
        assert_eq!(compatible_matrix().len(), 396);
    }

    #[test]
    fn transport_semantic_divergence_is_detected() {
        let memory = observation(TransportFamily::Memory, 1);
        let iroh = observation(TransportFamily::Iroh, 1);
        assert!(assert_transport_invariance(&[memory.clone(), iroh]).is_ok());
        assert_eq!(
            assert_transport_invariance(&[memory, observation(TransportFamily::Https, 9)]),
            Err(LabError::SemanticDivergence)
        );
    }

    #[test]
    fn operator_notes_are_minimized_to_a_digest() {
        let study =
            OperatorStudy::new("air_gapped_deploy", true, 90, 1, 1, 2, b"private notes").unwrap();
        assert_eq!(study.task(), "air_gapped_deploy");
        assert_ne!(study.notes_digest(), &[0; 32]);
    }
}
