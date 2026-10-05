//! Canonical decoding shared by every artifact.

use crate::{QualificationFormatError, Sha256Digest};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};

mod sealed {
    pub trait Sealed {}
}
pub(crate) use sealed::Sealed;

/// One artifact body: its schema, its byte limit, and its structural rules.
///
/// The trait is sealed. Only this crate defines artifacts.
pub trait Artifact: DeserializeOwned + Serialize + Sealed {
    /// The schema the body must name, and the domain of its digests.
    const SCHEMA: &'static str;
    /// The largest canonical encoding accepted.
    const MAX_BYTES: usize;

    /// The schema the body names.
    fn schema(&self) -> &str;

    /// Checks every structural rule that the body's types do not already
    /// enforce.
    ///
    /// # Errors
    ///
    /// Returns the first rule the body breaks.
    fn validate(&self) -> Result<(), QualificationFormatError>;
}

/// A decoded artifact whose every structural rule holds, with the exact
/// canonical bytes it was decoded from.
///
/// The only constructor is [`Canonical::from_canonical_json`], so holding
/// this value is proof that the body was size-checked, parsed strictly,
/// found canonical, and validated. It is not proof of any signature, trust,
/// or freshness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Canonical<T> {
    body: T,
    bytes: Vec<u8>,
}

impl<T: Artifact> Canonical<T> {
    /// Decodes one artifact from its canonical JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`QualificationFormatError::Oversized`] before parsing for an
    /// empty or oversized input, [`QualificationFormatError::Malformed`] for
    /// input that is not strictly of the artifact's shape,
    /// [`QualificationFormatError::NonCanonical`] for input that differs
    /// from its own canonical form, and otherwise the first structural rule
    /// the body breaks.
    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, QualificationFormatError> {
        if bytes.is_empty() || bytes.len() > T::MAX_BYTES {
            return Err(QualificationFormatError::Oversized);
        }
        let body: T =
            serde_json::from_slice(bytes).map_err(|_| QualificationFormatError::Malformed)?;
        if canonical_bytes(&body)? != bytes {
            return Err(QualificationFormatError::NonCanonical);
        }
        if body.schema() != T::SCHEMA {
            return Err(QualificationFormatError::UnknownSchema);
        }
        body.validate()?;
        Ok(Self {
            body,
            bytes: bytes.to_vec(),
        })
    }

    /// The validated body.
    #[must_use]
    pub const fn body(&self) -> &T {
        &self.body
    }

    /// The exact canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// SHA-256 of the schema, a NUL byte, and the canonical bytes.
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        domain_digest(T::SCHEMA, &self.bytes)
    }
}

/// The RFC 8785 bytes of `value`.
pub(crate) fn canonical_bytes<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, QualificationFormatError> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| QualificationFormatError::Malformed)
}

/// The schema, a NUL byte, and the canonical bytes: the preimage of every
/// signature and domain-separated digest in this crate. Schemas start with
/// lowercase `auths.` and every core signing preimage starts with `AUTHS`,
/// so the two can never be equal.
pub(crate) fn preimage(schema: &str, canonical: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(schema.len() + 1 + canonical.len());
    bytes.extend_from_slice(schema.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(canonical);
    bytes
}

pub(crate) fn domain_digest(schema: &str, canonical: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(preimage(schema, canonical)).into())
}

/// Requires `items` to be strictly ascending, which also forbids repeats.
pub(crate) fn strictly_ascending<T: Ord>(items: &[T]) -> Result<(), QualificationFormatError> {
    if items.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        Err(QualificationFormatError::ListOrder)
    }
}

/// The largest unix time a signed field may carry: the end of year 9999.
pub(crate) const MAX_TIMESTAMP: u64 = 253_402_300_799;

/// Requires a non-empty window no longer than `maximum_seconds`, issued no
/// later than its end.
pub(crate) fn valid_window(
    issued_at: u64,
    not_before: u64,
    not_after: u64,
    maximum_seconds: u64,
) -> Result<(), QualificationFormatError> {
    let valid = issued_at <= MAX_TIMESTAMP
        && not_after <= MAX_TIMESTAMP
        && not_before < not_after
        && issued_at < not_after
        && not_after - not_before <= maximum_seconds;
    if valid {
        Ok(())
    } else {
        Err(QualificationFormatError::InvalidTimeWindow)
    }
}
