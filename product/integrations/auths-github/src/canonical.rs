//! Canonical JSON and SHA-256 commitments used by the GitHub vertical.

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::types::DigestHex;

/// Canonicalization failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("canonical JSON encoding failed")]
pub struct CanonicalError;

/// Returns RFC 8785-style canonical JSON bytes.
///
/// # Errors
///
/// Returns an encoding failure for unsupported values.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| CanonicalError)
}

/// Returns the SHA-256 commitment to canonical JSON.
///
/// # Errors
///
/// Returns an encoding failure for unsupported values.
pub fn canonical_digest<T: Serialize>(value: &T) -> Result<DigestHex, CanonicalError> {
    Ok(sha256(&canonical_json(value)?))
}

/// Returns a lowercase SHA-256 commitment.
#[must_use]
pub fn sha256(bytes: &[u8]) -> DigestHex {
    DigestHex::from_digest_bytes(Sha256::digest(bytes).into())
}
