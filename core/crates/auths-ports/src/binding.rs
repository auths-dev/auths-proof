//! Typed bindings from external algorithm identifiers to signature suites.

extern crate alloc;

use alloc::{string::String, vec, vec::Vec};
use auths_model::{AdapterConfigurationId, BoundError, BoundedBytes, BoundedSet, SignatureSuiteId};
use core::fmt;

use crate::{SignatureSuite, configuration_id};

/// Maximum registered bindings in one verifier configuration.
pub const MAX_ALGORITHM_BINDINGS: usize = 32;
const MAX_JWS_ALGORITHM_BYTES: usize = 64;
const MAX_ALGORITHM_IDENTIFIER_BYTES: usize = 256;

/// Validated asymmetric JWS algorithm name.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct JwsAlgorithmName(String);

impl JwsAlgorithmName {
    /// Parses a bounded asymmetric JWS algorithm name.
    pub fn parse(value: &str) -> Result<Self, BindingError> {
        if value.is_empty()
            || value.len() > MAX_JWS_ALGORITHM_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'_' | b'-')
            })
            || value.eq_ignore_ascii_case("none")
            || value
                .get(..2)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("HS"))
        {
            return Err(BindingError::InvalidJwsAlgorithm);
        }
        Ok(Self(value.into()))
    }

    /// Returns the exact registered name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact canonical DER encoding of an X.509 `AlgorithmIdentifier`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AlgorithmIdentifierDer(BoundedBytes<MAX_ALGORITHM_IDENTIFIER_BYTES>);

impl AlgorithmIdentifierDer {
    /// Parses one complete DER sequence.
    pub fn new(bytes: Vec<u8>) -> Result<Self, BindingError> {
        validate_complete_der_sequence(&bytes)?;
        Ok(Self(BoundedBytes::new(bytes).map_err(BindingError::Bound)?))
    }

    /// Returns the exact DER bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Suite-specific representation in which a certificate key is delivered.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum KeyForm {
    /// Contents of the SPKI BIT STRING, excluding the unused-bit count.
    BitStringContents,
    /// Complete DER `SubjectPublicKeyInfo`.
    SubjectPublicKeyInfoDer,
    /// Canonical compressed SEC1 point derived from an uncompressed point.
    Sec1Compressed,
}

/// One external-algorithm-to-suite binding.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AlgorithmBinding {
    /// JWS algorithm names deliver separately pinned opaque key bytes.
    Jws {
        /// Exact protected-header algorithm name.
        algorithm: JwsAlgorithmName,
        /// Suite accepting the pinned verification key.
        suite: SignatureSuiteId,
    },
    /// X.509 SPKI algorithms select a suite and a key projection.
    Spki {
        /// Exact DER `AlgorithmIdentifier`.
        algorithm: AlgorithmIdentifierDer,
        /// Suite accepting the projected key.
        suite: SignatureSuiteId,
        /// Requested projection from the verified SPKI.
        key_form: KeyForm,
    },
}

impl AlgorithmBinding {
    /// Returns the selected suite.
    #[must_use]
    pub const fn suite(&self) -> &SignatureSuiteId {
        match self {
            Self::Jws { suite, .. } | Self::Spki { suite, .. } => suite,
        }
    }
}

/// Result of one JWS binding lookup.
#[derive(Clone, Copy, Debug)]
pub struct JwsSelection<'a> {
    suite: &'a SignatureSuiteId,
}

impl<'a> JwsSelection<'a> {
    /// Returns the selected signature suite.
    #[must_use]
    pub const fn suite(self) -> &'a SignatureSuiteId {
        self.suite
    }
}

/// Result of one SPKI binding lookup.
#[derive(Clone, Copy, Debug)]
pub struct SpkiSelection<'a> {
    suite: &'a SignatureSuiteId,
    key_form: KeyForm,
}

impl<'a> SpkiSelection<'a> {
    /// Returns the selected signature suite.
    #[must_use]
    pub const fn suite(self) -> &'a SignatureSuiteId {
        self.suite
    }

    /// Returns the configured key projection.
    #[must_use]
    pub const fn key_form(self) -> KeyForm {
        self.key_form
    }
}

/// Canonical bounded collection of algorithm bindings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlgorithmBindingSet {
    bindings: BoundedSet<AlgorithmBinding, MAX_ALGORITHM_BINDINGS>,
    configuration_id: AdapterConfigurationId,
}

impl AlgorithmBindingSet {
    /// Constructs bindings against an exact registered suite set.
    pub fn new(
        bindings: Vec<AlgorithmBinding>,
        suites: &[&dyn SignatureSuite],
    ) -> Result<Self, BindingError> {
        let bindings = BoundedSet::new(bindings).map_err(BindingError::Bound)?;
        let values = bindings.as_slice();
        for (index, binding) in values.iter().enumerate() {
            if suites.iter().all(|suite| suite.id() != binding.suite()) {
                return Err(BindingError::UnregisteredSuite);
            }
            for other in &values[index + 1..] {
                match (binding, other) {
                    (
                        AlgorithmBinding::Jws {
                            algorithm: left, ..
                        },
                        AlgorithmBinding::Jws {
                            algorithm: right, ..
                        },
                    ) if left == right => return Err(BindingError::DuplicateSelector),
                    (
                        AlgorithmBinding::Spki {
                            algorithm: left, ..
                        },
                        AlgorithmBinding::Spki {
                            algorithm: right, ..
                        },
                    ) if left == right => return Err(BindingError::DuplicateSelector),
                    _ => {}
                }
            }
        }

        let mut components = Vec::new();
        for binding in values {
            match binding {
                AlgorithmBinding::Jws { algorithm, suite } => {
                    components.push(vec![0]);
                    components.push(algorithm.as_str().as_bytes().to_vec());
                    components.push(suite.as_str().as_bytes().to_vec());
                }
                AlgorithmBinding::Spki {
                    algorithm,
                    suite,
                    key_form,
                } => {
                    components.push(vec![1]);
                    components.push(algorithm.as_bytes().to_vec());
                    components.push(suite.as_str().as_bytes().to_vec());
                    components.push(vec![match key_form {
                        KeyForm::BitStringContents => 0,
                        KeyForm::SubjectPublicKeyInfoDer => 1,
                        KeyForm::Sec1Compressed => 2,
                    }]);
                }
            }
            let suite = suites
                .iter()
                .find(|candidate| candidate.id() == binding.suite())
                .ok_or(BindingError::UnregisteredSuite)?;
            components.push(suite.configuration_id().as_bytes().to_vec());
        }
        let configuration_id = configuration_id(
            b"auths-algorithm-binding-v1",
            components.iter().map(Vec::as_slice),
        );
        Ok(Self {
            bindings,
            configuration_id,
        })
    }

    /// Selects by exact JWS algorithm name.
    #[must_use]
    pub fn select_jws(&self, algorithm: &JwsAlgorithmName) -> Option<JwsSelection<'_>> {
        self.bindings
            .as_slice()
            .iter()
            .find_map(|binding| match binding {
                AlgorithmBinding::Jws {
                    algorithm: candidate,
                    suite,
                } if candidate == algorithm => Some(JwsSelection { suite }),
                _ => None,
            })
    }

    /// Selects by exact SPKI algorithm DER, returning the configured key form.
    #[must_use]
    pub fn select_spki(&self, algorithm: &AlgorithmIdentifierDer) -> Option<SpkiSelection<'_>> {
        self.bindings
            .as_slice()
            .iter()
            .find_map(|binding| match binding {
                AlgorithmBinding::Spki {
                    algorithm: candidate,
                    suite,
                    key_form,
                } if candidate == algorithm => Some(SpkiSelection {
                    suite,
                    key_form: *key_form,
                }),
                _ => None,
            })
    }

    /// Returns the immutable binding commitment.
    #[must_use]
    pub const fn configuration_id(&self) -> AdapterConfigurationId {
        self.configuration_id
    }

    /// Returns the canonical rows.
    #[must_use]
    pub fn as_slice(&self) -> &[AlgorithmBinding] {
        self.bindings.as_slice()
    }
}

/// Algorithm-binding construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingError {
    /// Generic cardinality or exact duplicate failure.
    Bound(BoundError),
    /// Invalid JWS algorithm name.
    InvalidJwsAlgorithm,
    /// Invalid or non-canonical DER algorithm identifier.
    InvalidAlgorithmIdentifier,
    /// Two rows use the same lookup selector.
    DuplicateSelector,
    /// A row names a suite absent from the registered suite slice.
    UnregisteredSuite,
}

impl fmt::Display for BindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bound(error) => write!(formatter, "invalid binding bound: {error}"),
            Self::InvalidJwsAlgorithm => formatter.write_str("invalid JWS algorithm name"),
            Self::InvalidAlgorithmIdentifier => {
                formatter.write_str("invalid DER algorithm identifier")
            }
            Self::DuplicateSelector => formatter.write_str("duplicate algorithm selector"),
            Self::UnregisteredSuite => formatter.write_str("unregistered signature suite"),
        }
    }
}

fn validate_complete_der_sequence(bytes: &[u8]) -> Result<(), BindingError> {
    let Some((&0x30, remainder)) = bytes.split_first() else {
        return Err(BindingError::InvalidAlgorithmIdentifier);
    };
    let (header_length, content_length) = der_length(remainder)?;
    if 1usize
        .checked_add(header_length)
        .and_then(|value| value.checked_add(content_length))
        != Some(bytes.len())
        || content_length == 0
    {
        return Err(BindingError::InvalidAlgorithmIdentifier);
    }
    Ok(())
}

fn der_length(bytes: &[u8]) -> Result<(usize, usize), BindingError> {
    let first = *bytes
        .first()
        .ok_or(BindingError::InvalidAlgorithmIdentifier)?;
    if first & 0x80 == 0 {
        return Ok((1, usize::from(first)));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > core::mem::size_of::<usize>() || bytes.len() <= count {
        return Err(BindingError::InvalidAlgorithmIdentifier);
    }
    if bytes[1] == 0 {
        return Err(BindingError::InvalidAlgorithmIdentifier);
    }
    let mut length = 0usize;
    for byte in &bytes[1..=count] {
        length = length
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .ok_or(BindingError::InvalidAlgorithmIdentifier)?;
    }
    if length < 128 {
        return Err(BindingError::InvalidAlgorithmIdentifier);
    }
    Ok((1 + count, length))
}

#[cfg(feature = "std")]
impl std::error::Error for BindingError {}
