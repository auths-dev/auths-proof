//! Certificate-path verification port and verified leaf projection.

extern crate alloc;

use alloc::{string::String, vec::Vec};
use auths_model::{AdapterConfigurationId, BoundError, BoundedBytes, BoundedSet, Timestamp};
use core::fmt;

use crate::binding::{AlgorithmIdentifierDer, KeyForm};

/// Maximum DER certificate size accepted by the shared path port.
pub const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;
/// Maximum trust anchors in one path request.
pub const MAX_TRUST_ANCHORS: usize = 16;
/// Maximum certificates in a supplied path, including the leaf.
pub const MAX_PATH_LENGTH: usize = 8;
const MAX_EKU_OID_BYTES: usize = 32;
const MAX_PATH_VERIFIER_ID_BYTES: usize = 128;

const CLIENT_AUTH_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
const CODE_SIGNING_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];

/// One bounded DER certificate.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CertificateDer(BoundedBytes<MAX_CERTIFICATE_BYTES>);

impl CertificateDer {
    /// Constructs one bounded DER certificate.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::Malformed`] unless `bytes` is exactly one complete
    /// DER sequence, or [`PathError::LimitExceeded`] when it is oversized.
    pub fn new(bytes: Vec<u8>) -> Result<Self, PathError> {
        if !is_complete_der_sequence(&bytes) {
            return Err(PathError::Malformed);
        }
        Ok(Self(BoundedBytes::new(bytes).map_err(
            |error| match error {
                BoundError::AboveMaximum => PathError::LimitExceeded,
                BoundError::Empty | BoundError::Duplicate => PathError::Malformed,
            },
        )?))
    }

    /// Returns the exact DER bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Canonical non-empty trust-anchor set.
pub type TrustAnchorSet = BoundedSet<CertificateDer, MAX_TRUST_ANCHORS>;

/// Exact DER content octets of an extended-key-usage object identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExtendedKeyUsage(BoundedBytes<MAX_EKU_OID_BYTES>);

impl ExtendedKeyUsage {
    /// Constructs an EKU from DER OID content octets.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::Malformed`] for invalid OID content and
    /// [`PathError::LimitExceeded`] when the encoding is oversized.
    pub fn from_der_content(bytes: Vec<u8>) -> Result<Self, PathError> {
        if bytes.is_empty() || bytes[0] > 119 {
            return Err(PathError::Malformed);
        }
        Ok(Self(BoundedBytes::new(bytes).map_err(
            |error| match error {
                BoundError::AboveMaximum => PathError::LimitExceeded,
                BoundError::Empty | BoundError::Duplicate => PathError::Malformed,
            },
        )?))
    }

    /// Client-authentication EKU (`1.3.6.1.5.5.7.3.2`).
    ///
    /// # Panics
    ///
    /// Panics only if the internal registered OID exceeds the compile-time
    /// EKU bound, which would be an implementation defect.
    #[must_use]
    pub fn client_auth() -> Self {
        Self(BoundedBytes::new(CLIENT_AUTH_OID.to_vec()).expect("registered EKU is bounded"))
    }

    /// Code-signing EKU (`1.3.6.1.5.5.7.3.3`).
    ///
    /// # Panics
    ///
    /// Panics only if the internal registered OID exceeds the compile-time
    /// EKU bound, which would be an implementation defect.
    #[must_use]
    pub fn code_signing() -> Self {
        Self(BoundedBytes::new(CODE_SIGNING_OID.to_vec()).expect("registered EKU is bounded"))
    }

    /// Returns DER OID content octets.
    #[must_use]
    pub fn as_der_content(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Parsed path-verifier implementation identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PathVerifierId(String);

impl PathVerifierId {
    /// Parses one bounded identifier.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::Malformed`] when the identifier is empty,
    /// oversized, or contains control or whitespace bytes.
    pub fn parse(value: &str) -> Result<Self, PathError> {
        if value.is_empty()
            || value.len() > MAX_PATH_VERIFIER_ID_BYTES
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(PathError::Malformed);
        }
        Ok(Self(value.into()))
    }

    /// Returns the exact identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Immutable inputs to certificate path verification.
pub struct PathInput<'a> {
    /// End-entity certificate.
    pub leaf: &'a CertificateDer,
    /// Supplied intermediates in leaf-to-root order, excluding anchors.
    pub intermediates: &'a [CertificateDer],
    /// Verifier-pinned trust anchors.
    pub anchors: &'a TrustAnchorSet,
    /// Exact historical instant at which the path must be valid.
    pub at: Timestamp,
    /// Required extended-key usage.
    pub required_eku: &'a ExtendedKeyUsage,
}

/// Leaf facts returned only after successful path verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedLeaf {
    der: CertificateDer,
    not_before: Timestamp,
    not_after: Timestamp,
    verified_at: Timestamp,
    spki_algorithm: AlgorithmIdentifierDer,
    spki: BoundedBytes<MAX_CERTIFICATE_BYTES>,
}

impl VerifiedLeaf {
    /// Constructs a verified result from the exact input accepted by a path
    /// verifier.
    ///
    /// This constructor is public so independent crates can implement the
    /// port. It copies the leaf and verification instant from `input`.
    ///
    /// # Errors
    ///
    /// Returns a [`PathError`] when the path exceeds its bound, the requested
    /// instant is outside the leaf validity window, or the SPKI is malformed
    /// or oversized.
    pub fn from_path_input(
        input: &PathInput<'_>,
        not_before: Timestamp,
        not_after: Timestamp,
        spki_algorithm: AlgorithmIdentifierDer,
        spki: Vec<u8>,
    ) -> Result<Self, PathError> {
        if input.intermediates.len() >= MAX_PATH_LENGTH {
            return Err(PathError::LimitExceeded);
        }
        if not_before > input.at {
            return Err(PathError::NotYetValid);
        }
        if input.at >= not_after || not_before >= not_after {
            return Err(PathError::Expired);
        }
        if !is_complete_der_sequence(&spki) {
            return Err(PathError::Malformed);
        }
        Ok(Self {
            der: input.leaf.clone(),
            not_before,
            not_after,
            verified_at: input.at,
            spki_algorithm,
            spki: BoundedBytes::new(spki).map_err(|error| match error {
                BoundError::AboveMaximum => PathError::LimitExceeded,
                BoundError::Empty | BoundError::Duplicate => PathError::Malformed,
            })?,
        })
    }

    /// Returns the exact verified leaf certificate.
    #[must_use]
    pub const fn der(&self) -> &CertificateDer {
        &self.der
    }

    /// Returns the parsed not-before instant.
    #[must_use]
    pub const fn not_before(&self) -> Timestamp {
        self.not_before
    }

    /// Returns the parsed exclusive not-after instant.
    #[must_use]
    pub const fn not_after(&self) -> Timestamp {
        self.not_after
    }

    /// Returns the exact requested verification instant.
    #[must_use]
    pub const fn verified_at(&self) -> Timestamp {
        self.verified_at
    }

    /// Returns the exact SPKI algorithm identifier.
    #[must_use]
    pub const fn spki_algorithm(&self) -> &AlgorithmIdentifierDer {
        &self.spki_algorithm
    }

    /// Returns the complete DER SPKI.
    #[must_use]
    pub fn spki(&self) -> &[u8] {
        self.spki.as_slice()
    }

    /// Derives the configured suite-specific verification-key form.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::Malformed`] for an invalid SPKI encoding or
    /// [`PathError::UnsupportedKeyForm`] when the requested projection does
    /// not apply to the verified key.
    pub fn key_bytes(&self, form: KeyForm) -> Result<Vec<u8>, PathError> {
        match form {
            KeyForm::SubjectPublicKeyInfoDer => Ok(self.spki.as_slice().to_vec()),
            KeyForm::BitStringContents => spki_bit_string(self.spki.as_slice()).map(<[u8]>::to_vec),
            KeyForm::Sec1Compressed => {
                let point = spki_bit_string(self.spki.as_slice())?;
                if point.len() != 65 || point[0] != 0x04 {
                    return Err(PathError::UnsupportedKeyForm);
                }
                let mut compressed = Vec::with_capacity(33);
                compressed.push(if point[64] & 1 == 0 { 0x02 } else { 0x03 });
                compressed.extend_from_slice(&point[1..33]);
                Ok(compressed)
            }
        }
    }
}

/// Pure certificate-path verification implementation.
pub trait CertificatePathVerifier {
    /// Returns the implementation identifier.
    fn id(&self) -> &PathVerifierId;
    /// Returns the immutable implementation commitment.
    fn configuration_id(&self) -> AdapterConfigurationId;
    /// Returns a conservative work bound for one supplied chain length.
    fn maximum_work_units(&self, chain_length: usize) -> u64;
    /// Verifies a path and returns exact leaf facts.
    ///
    /// # Errors
    ///
    /// Returns a [`PathError`] describing the deterministic reason the path
    /// could not be verified under the supplied anchors, instant, and EKU.
    fn verify(&self, input: PathInput<'_>) -> Result<VerifiedLeaf, PathError>;
}

/// Closed path-verification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathError {
    /// Malformed certificate, identifier, or path input.
    Malformed,
    /// No supplied anchor validates the chain.
    UntrustedAnchor,
    /// A certificate signature is invalid.
    InvalidSignature,
    /// The leaf is not yet valid at the requested instant.
    NotYetValid,
    /// The leaf is expired at the requested instant.
    Expired,
    /// The required extended-key usage is absent.
    MissingEku,
    /// The leaf is not an end-entity certificate.
    NotEndEntity,
    /// A name constraint rejects the leaf.
    NameConstraint,
    /// The path uses an unsupported cryptographic algorithm.
    UnsupportedAlgorithm,
    /// The requested suite key projection is inapplicable.
    UnsupportedKeyForm,
    /// A deterministic resource bound was exceeded.
    LimitExceeded,
}

impl fmt::Display for PathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "malformed certificate path",
            Self::UntrustedAnchor => "untrusted certificate anchor",
            Self::InvalidSignature => "invalid certificate signature",
            Self::NotYetValid => "certificate is not yet valid",
            Self::Expired => "certificate is expired",
            Self::MissingEku => "required extended key usage is absent",
            Self::NotEndEntity => "certificate is not an end entity",
            Self::NameConstraint => "certificate name constraint failed",
            Self::UnsupportedAlgorithm => "unsupported certificate algorithm",
            Self::UnsupportedKeyForm => "unsupported certificate key form",
            Self::LimitExceeded => "certificate path resource limit exceeded",
        })
    }
}

fn spki_bit_string(spki: &[u8]) -> Result<&[u8], PathError> {
    let (outer_header, outer_length) = der_tlv(spki, 0x30)?;
    let body = &spki[outer_header..outer_header + outer_length];
    let (algorithm_header, algorithm_length) = der_tlv(body, 0x30)?;
    let bit_string = &body[algorithm_header + algorithm_length..];
    let (bit_header, bit_length) = der_tlv(bit_string, 0x03)?;
    if bit_header + bit_length != bit_string.len() || bit_length < 2 || bit_string[bit_header] != 0
    {
        return Err(PathError::Malformed);
    }
    Ok(&bit_string[bit_header + 1..])
}

fn is_complete_der_sequence(bytes: &[u8]) -> bool {
    der_tlv(bytes, 0x30)
        .is_ok_and(|(header, length)| header.checked_add(length) == Some(bytes.len()))
}

fn der_tlv(bytes: &[u8], expected_tag: u8) -> Result<(usize, usize), PathError> {
    if bytes.first().copied() != Some(expected_tag) {
        return Err(PathError::Malformed);
    }
    let length_byte = *bytes.get(1).ok_or(PathError::Malformed)?;
    if length_byte & 0x80 == 0 {
        let length = usize::from(length_byte);
        if bytes.len() < 2 + length {
            return Err(PathError::Malformed);
        }
        return Ok((2, length));
    }
    let count = usize::from(length_byte & 0x7f);
    if count == 0 || count > core::mem::size_of::<usize>() || bytes.len() < 2 + count {
        return Err(PathError::Malformed);
    }
    if bytes[2] == 0 {
        return Err(PathError::Malformed);
    }
    let mut length = 0usize;
    for byte in &bytes[2..2 + count] {
        length = length
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .ok_or(PathError::LimitExceeded)?;
    }
    if length < 128 || bytes.len() < 2 + count + length {
        return Err(PathError::Malformed);
    }
    Ok((2 + count, length))
}

#[cfg(feature = "std")]
impl std::error::Error for PathError {}
