//! Closed, canonical Multikey parsing shared by target V1 principal methods.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};
use core::fmt;
use ed25519_dalek::VerifyingKey as Ed25519Key;
use p256::ecdsa::VerifyingKey as P256Key;

const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];
const P256_MULTICODEC: [u8; 2] = [0x80, 0x24];
const MAX_MULTIBASE_LEN: usize = 128;

/// Mandatory target V1 Ed25519 signature-suite identifier.
pub const ED25519_SUITE: &str = "ed25519-v1";
/// Mandatory target V1 P-256/SHA-256 signature-suite identifier.
pub const P256_SUITE: &str = "p256-sha256-v1";

/// Closed public-key forms accepted by target V1 Multikey consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultikeyType {
    /// Ed25519 public key with multicodec `0xed`.
    Ed25519,
    /// Compressed SEC1 P-256 public key with multicodec `0x1200`.
    P256,
}

impl MultikeyType {
    /// Returns the exact signature suite required by this key form.
    #[must_use]
    pub const fn suite(self) -> &'static str {
        match self {
            Self::Ed25519 => ED25519_SUITE,
            Self::P256 => P256_SUITE,
        }
    }

    const fn multicodec(self) -> [u8; 2] {
        match self {
            Self::Ed25519 => ED25519_MULTICODEC,
            Self::P256 => P256_MULTICODEC,
        }
    }

    const fn key_len(self) -> usize {
        match self {
            Self::Ed25519 => 32,
            Self::P256 => 33,
        }
    }
}

/// Canonical base58btc Multikey value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Multikey {
    encoded: String,
    key_type: MultikeyType,
    public_key: Vec<u8>,
}

impl Multikey {
    /// Parses the target V1 base58btc and multicodec subset.
    ///
    /// # Errors
    ///
    /// Returns a typed error for unsupported, malformed, non-canonical, or
    /// cryptographically invalid public-key material.
    pub fn parse(encoded: &str) -> Result<Self, MultikeyError> {
        if encoded.len() < 2 || encoded.len() > MAX_MULTIBASE_LEN || !encoded.is_ascii() {
            return Err(MultikeyError::InvalidEncoding);
        }
        let payload = encoded
            .strip_prefix('z')
            .ok_or(MultikeyError::UnsupportedMultibase)?;
        let decoded = bs58::decode(payload)
            .into_vec()
            .map_err(|_| MultikeyError::InvalidEncoding)?;
        let key_type = match decoded.get(..2) {
            Some(prefix) if prefix == ED25519_MULTICODEC => MultikeyType::Ed25519,
            Some(prefix) if prefix == P256_MULTICODEC => MultikeyType::P256,
            Some(_) => return Err(MultikeyError::UnsupportedMulticodec),
            None => return Err(MultikeyError::InvalidEncoding),
        };
        let public_key = decoded[2..].to_vec();
        let canonical = Self::from_public_key(key_type, public_key)?;
        if canonical.encoded != encoded {
            return Err(MultikeyError::NonCanonical);
        }
        Ok(canonical)
    }

    /// Constructs the unique target V1 Multikey encoding for a public key.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the key length or encoded point is invalid.
    pub fn from_public_key(
        key_type: MultikeyType,
        public_key: Vec<u8>,
    ) -> Result<Self, MultikeyError> {
        if public_key.len() != key_type.key_len() {
            return Err(MultikeyError::InvalidKeyLength);
        }
        validate_public_key(key_type, &public_key)?;
        let mut bytes = Vec::with_capacity(2 + public_key.len());
        bytes.extend_from_slice(&key_type.multicodec());
        bytes.extend_from_slice(&public_key);
        Ok(Self {
            encoded: format!("z{}", bs58::encode(bytes).into_string()),
            key_type,
            public_key,
        })
    }

    /// Returns the canonical base58btc value including the `z` prefix.
    #[must_use]
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    /// Returns the closed key form.
    #[must_use]
    pub const fn key_type(&self) -> MultikeyType {
        self.key_type
    }

    /// Returns suite-specific public verification-key bytes.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

fn validate_public_key(key_type: MultikeyType, public_key: &[u8]) -> Result<(), MultikeyError> {
    match key_type {
        MultikeyType::Ed25519 => {
            let bytes: [u8; 32] = public_key
                .try_into()
                .map_err(|_| MultikeyError::InvalidKeyLength)?;
            Ed25519Key::from_bytes(&bytes).map_err(|_| MultikeyError::InvalidPublicKey)?;
        }
        MultikeyType::P256 => {
            P256Key::from_sec1_bytes(public_key).map_err(|_| MultikeyError::InvalidPublicKey)?;
        }
    }
    Ok(())
}

/// Closed Multikey parsing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultikeyError {
    /// The multibase text is malformed or outside the bounded grammar.
    InvalidEncoding,
    /// The value does not use base58btc.
    UnsupportedMultibase,
    /// The decoded multicodec is not in the V1 registry.
    UnsupportedMulticodec,
    /// The public key has the wrong length for its multicodec.
    InvalidKeyLength,
    /// The public key is not a valid point/key for its suite.
    InvalidPublicKey,
    /// The text is not the unique base58btc representation of its bytes.
    NonCanonical,
}

impl fmt::Display for MultikeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "invalid Multikey encoding",
            Self::UnsupportedMultibase => "unsupported Multikey multibase",
            Self::UnsupportedMulticodec => "unsupported Multikey multicodec",
            Self::InvalidKeyLength => "invalid Multikey public-key length",
            Self::InvalidPublicKey => "invalid Multikey public key",
            Self::NonCanonical => "non-canonical Multikey encoding",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MultikeyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_vectors_parse_canonically() {
        let ed25519 = Multikey::parse("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
        assert_eq!(ed25519.key_type(), MultikeyType::Ed25519);
        assert_eq!(ed25519.public_key().len(), 32);
        let p256 = Multikey::parse("zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv").unwrap();
        assert_eq!(p256.key_type(), MultikeyType::P256);
        assert_eq!(p256.public_key().len(), 33);
    }

    #[test]
    fn unsupported_and_noncanonical_values_fail_closed() {
        assert_eq!(
            Multikey::parse("uZm9v"),
            Err(MultikeyError::UnsupportedMultibase)
        );
        assert_eq!(
            Multikey::parse("z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p"),
            Err(MultikeyError::UnsupportedMulticodec)
        );
        assert!(Multikey::parse("z0OIl").is_err());
    }
}
