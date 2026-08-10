//! Protocol-neutral canonical signature verification semantics.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

use core::fmt;
use ed25519_dalek::{Signature, VerifyingKey};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256Key, signature::Verifier as _};

/// Auths-defined Ed25519 suite identifier.
pub const ED25519_V1: &str = "ed25519-v1";
/// Auths-defined P-256/SHA-256 suite identifier.
pub const P256_SHA256_V1: &str = "p256-sha256-v1";

/// Failure classes shared by every Ed25519 protocol adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ed25519Error {
    /// The verification key is not one canonical Ed25519 public key.
    InvalidKey,
    /// The signature is not one canonical fixed-width Ed25519 signature.
    InvalidSignatureEncoding,
    /// The signature does not authenticate the exact supplied message.
    VerificationFailed,
}

impl fmt::Display for Ed25519Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidKey => "invalid Ed25519 verification key",
            Self::InvalidSignatureEncoding => "invalid Ed25519 signature encoding",
            Self::VerificationFailed => "Ed25519 verification failed",
        })
    }
}

impl core::error::Error for Ed25519Error {}

/// Failure classes shared by every P-256/SHA-256 protocol adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum P256Error {
    /// The verification key is not one compressed SEC1 P-256 public key.
    InvalidKey,
    /// The signature is not one canonical fixed-width P-256 signature.
    InvalidSignatureEncoding,
    /// The signature is high-S or does not authenticate the exact supplied message.
    VerificationFailed,
}

impl fmt::Display for P256Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidKey => "invalid P-256 verification key",
            Self::InvalidSignatureEncoding => "invalid P-256 signature encoding",
            Self::VerificationFailed => "P-256/SHA-256 verification failed",
        })
    }
}

impl core::error::Error for P256Error {}

/// Verifies an Ed25519 signature with the repository's one strict implementation.
///
/// This primitive assigns no protocol meaning to `message`; each caller remains responsible for
/// constructing its own domain-separated signing preimage.
///
/// # Errors
///
/// Distinguishes malformed keys, malformed signature encodings, and cryptographic failure.
pub fn verify_ed25519(
    verification_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Ed25519Error> {
    let key_bytes: &[u8; 32] = verification_key
        .try_into()
        .map_err(|_| Ed25519Error::InvalidKey)?;
    let key = VerifyingKey::from_bytes(key_bytes).map_err(|_| Ed25519Error::InvalidKey)?;
    let signature =
        Signature::from_slice(signature).map_err(|_| Ed25519Error::InvalidSignatureEncoding)?;
    key.verify_strict(message, &signature)
        .map_err(|_| Ed25519Error::VerificationFailed)
}

/// Validates a compressed SEC1 P-256 public key using the canonical implementation.
///
/// # Errors
///
/// Rejects malformed or unsupported P-256 verification material.
pub fn validate_p256_key(verification_key: &[u8]) -> Result<(), P256Error> {
    P256Key::from_sec1_bytes(verification_key)
        .map(|_| ())
        .map_err(|_| P256Error::InvalidKey)
}

/// Verifies one fixed-width low-S P-256/SHA-256 signature.
///
/// This primitive assigns no protocol meaning to `message`; each caller remains responsible for
/// constructing its own domain-separated signing preimage.
///
/// # Errors
///
/// Distinguishes malformed keys, malformed signature encodings, and cryptographic failure. High-S
/// signatures are rejected rather than normalized.
pub fn verify_p256_sha256(
    verification_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), P256Error> {
    let key = P256Key::from_sec1_bytes(verification_key).map_err(|_| P256Error::InvalidKey)?;
    let signature =
        P256Signature::from_slice(signature).map_err(|_| P256Error::InvalidSignatureEncoding)?;
    if signature.normalize_s().is_some() {
        return Err(P256Error::VerificationFailed);
    }
    key.verify(message, &signature)
        .map_err(|_| P256Error::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    #[test]
    fn strict_verifier_binds_every_byte_and_classifies_shapes() {
        let signing = SigningKey::from_bytes(&[17; 32]);
        let signature = signing.sign(b"canonical message").to_bytes();
        let key = signing.verifying_key().to_bytes();

        assert_eq!(
            verify_ed25519(&key, b"canonical message", &signature),
            Ok(())
        );
        assert_eq!(
            verify_ed25519(&key, b"changed message", &signature),
            Err(Ed25519Error::VerificationFailed)
        );
        assert_eq!(
            verify_ed25519(&key[..31], b"canonical message", &signature),
            Err(Ed25519Error::InvalidKey)
        );
        assert_eq!(
            verify_ed25519(&key, b"canonical message", &signature[..63]),
            Err(Ed25519Error::InvalidSignatureEncoding)
        );
    }
}
