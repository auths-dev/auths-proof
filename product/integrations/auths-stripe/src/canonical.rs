//! Deterministic Stripe-profile canonicalization.

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::types::DigestHex;

/// Serializes a closed profile value as RFC 8785 canonical JSON.
///
/// # Errors
///
/// Returns a typed error when the value cannot be represented.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| CanonicalError)
}

/// Computes a lowercase SHA-256 commitment.
#[must_use]
pub fn sha256(bytes: &[u8]) -> DigestHex {
    DigestHex::from_digest_bytes(Sha256::digest(bytes).into())
}

/// Computes a canonical JSON commitment.
///
/// # Errors
///
/// Returns a typed error when canonicalization fails.
pub fn canonical_digest<T: Serialize>(value: &T) -> Result<DigestHex, CanonicalError> {
    Ok(sha256(&canonical_json(value)?))
}

/// Canonical JSON serialization failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("could not produce canonical Stripe profile JSON")]
pub struct CanonicalError;
