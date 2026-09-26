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
const P256_KEY_LEN: usize = 33;

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
    /// The verification key is not one 33-byte compressed SEC1 P-256 point with tag `0x02` or
    /// `0x03`.
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

/// Validates one canonical Ed25519 public key.
///
/// # Errors
///
/// Rejects malformed Ed25519 verification material.
pub fn validate_ed25519_key(verification_key: &[u8]) -> Result<(), Ed25519Error> {
    let key_bytes: &[u8; 32] = verification_key
        .try_into()
        .map_err(|_| Ed25519Error::InvalidKey)?;
    VerifyingKey::from_bytes(key_bytes)
        .map(|_| ())
        .map_err(|_| Ed25519Error::InvalidKey)
}

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
    validate_ed25519_key(verification_key)?;
    let key_bytes: &[u8; 32] = verification_key
        .try_into()
        .map_err(|_| Ed25519Error::InvalidKey)?;
    let key = VerifyingKey::from_bytes(key_bytes).map_err(|_| Ed25519Error::InvalidKey)?;
    let signature =
        Signature::from_slice(signature).map_err(|_| Ed25519Error::InvalidSignatureEncoding)?;
    key.verify_strict(message, &signature)
        .map_err(|_| Ed25519Error::VerificationFailed)
}

/// Validates one P-256 verification key.
///
/// The only accepted encoding is the 33-byte compressed SEC1 point: tag `0x02` or `0x03`
/// followed by the 32-byte big-endian x-coordinate of a point on the curve. Every other
/// length is rejected, as are the SEC1 identity (`0x00`), uncompressed (`0x04`), compact
/// (`0x05`), and hybrid (`0x06`/`0x07`) forms, so one key has exactly one accepted encoding.
///
/// # Errors
///
/// Returns [`P256Error::InvalidKey`] for any other encoding, and for an x-coordinate that is not
/// below the field modulus or has no point on the curve.
pub fn validate_p256_key(verification_key: &[u8]) -> Result<(), P256Error> {
    decode_p256_key(verification_key).map(|_| ())
}

/// Decodes the one key encoding [`validate_p256_key`] accepts.
///
/// The tag and length are checked before point decoding because the SEC1 decoder also accepts
/// the uncompressed and compact forms of the same point.
fn decode_p256_key(verification_key: &[u8]) -> Result<P256Key, P256Error> {
    match verification_key {
        [0x02 | 0x03, ..] if verification_key.len() == P256_KEY_LEN => {
            P256Key::from_sec1_bytes(verification_key).map_err(|_| P256Error::InvalidKey)
        }
        _ => Err(P256Error::InvalidKey),
    }
}

/// Verifies one fixed-width low-S P-256/SHA-256 signature.
///
/// The key must use the one encoding [`validate_p256_key`] accepts. This primitive assigns no
/// protocol meaning to `message`; each caller remains responsible for constructing its own
/// domain-separated signing preimage.
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
    let key = decode_p256_key(verification_key)?;
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
    extern crate alloc;

    use super::*;
    use alloc::{vec, vec::Vec};
    use ed25519_dalek::{Signer as _, SigningKey};
    use p256::ecdsa::SigningKey as P256SigningKey;

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

    const P256_MESSAGE: &[u8] = b"canonical message";

    /// A fixed P-256 key whose public point is the one its compact form `0x05 || x` decodes to.
    ///
    /// A compact point decodes to the candidate with the smaller of y and p - y. Negating the
    /// scalar reflects the point to (x, p - y), so exactly one of d and n - d qualifies.
    fn compact_decodable_p256_key() -> P256SigningKey {
        let mut scalar = [0; 32];
        scalar[31] = 7;
        let key = P256SigningKey::from_bytes((&scalar).into()).unwrap();
        let mut compact = vec![0x05];
        compact.extend_from_slice(&key.verifying_key().to_encoded_point(true).as_bytes()[1..]);
        if P256Key::from_sec1_bytes(&compact).unwrap() == *key.verifying_key() {
            key
        } else {
            P256SigningKey::from(-*key.as_nonzero_scalar())
        }
    }

    fn with_tag(tag: u8, rest: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag];
        encoded.extend_from_slice(rest);
        encoded
    }

    #[test]
    fn p256_accepts_only_the_compressed_encoding_of_a_point() {
        let key = compact_decodable_p256_key();
        let signature: P256Signature = key.sign(P256_MESSAGE);
        let signature = signature.normalize_s().unwrap_or(signature);
        let signature_bytes = signature.to_bytes();
        let compressed = key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let uncompressed = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let x = &uncompressed[1..33];
        let x_and_y = &uncompressed[1..];
        let compact = with_tag(0x05, x);

        assert_eq!(validate_p256_key(&compressed), Ok(()));
        assert_eq!(
            verify_p256_sha256(&compressed, P256_MESSAGE, &signature_bytes),
            Ok(())
        );

        // The SEC1 decoder accepts these forms and the signature is valid for the point they
        // decode to, so only the encoding rule can reject them below.
        for permissive in [&uncompressed, &compact] {
            let decoded = P256Key::from_sec1_bytes(permissive).unwrap();
            assert_eq!(decoded, *key.verifying_key());
            assert!(decoded.verify(P256_MESSAGE, &signature).is_ok());
        }

        let mut rejected = vec![
            uncompressed.clone(),
            compact,
            with_tag(0x06, x_and_y),
            with_tag(0x07, x_and_y),
            vec![0x00],
            Vec::new(),
            compressed[..32].to_vec(),
            [compressed.as_slice(), &[0]].concat(),
            x_and_y.to_vec(),
            [uncompressed.as_slice(), &[0]].concat(),
            // A compressed tag over an x-coordinate that is not a canonical field element.
            with_tag(0x02, &[0xff; 32]),
        ];
        rejected.extend(
            (0..=u8::MAX)
                .filter(|tag| !matches!(tag, 0x02 | 0x03))
                .map(|tag| with_tag(tag, x)),
        );
        for encoded in &rejected {
            assert_eq!(
                validate_p256_key(encoded),
                Err(P256Error::InvalidKey),
                "{encoded:02x?}"
            );
            assert_eq!(
                verify_p256_sha256(encoded, P256_MESSAGE, &signature_bytes),
                Err(P256Error::InvalidKey),
                "{encoded:02x?}"
            );
        }
    }
}
