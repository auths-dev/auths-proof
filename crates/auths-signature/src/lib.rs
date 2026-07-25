//! Mandatory target V1 signature-suite implementations.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

use auths_model::{ModelError, SignatureSuiteId};
use auths_ports::{SignatureError, SignatureInput, SignatureSuite};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519Key};
use p256::ecdsa::{signature::Verifier as _, Signature as P256Signature, VerifyingKey as P256Key};

/// Exact V1 Ed25519 suite identifier.
pub const ED25519_V1: &str = "ed25519-v1";
/// Exact V1 P-256/SHA-256 suite identifier.
pub const P256_SHA256_V1: &str = "p256-sha256-v1";

/// RFC 8032 Ed25519 verification over the complete signing preimage.
pub struct Ed25519Suite {
    id: SignatureSuiteId,
}

impl Ed25519Suite {
    /// Constructs the mandatory Ed25519 suite.
    ///
    /// # Errors
    ///
    /// Returns a model error only if the compiled registry identifier is
    /// invalid.
    pub fn new() -> Result<Self, ModelError> {
        Ok(Self {
            id: SignatureSuiteId::parse(ED25519_V1)?,
        })
    }
}

impl SignatureSuite for Ed25519Suite {
    fn id(&self) -> &SignatureSuiteId {
        &self.id
    }

    fn verify(&self, input: SignatureInput<'_>) -> Result<(), SignatureError> {
        let key_bytes: &[u8; 32] = input
            .verification_key
            .try_into()
            .map_err(|_| SignatureError::InvalidKey)?;
        let key = Ed25519Key::from_bytes(key_bytes).map_err(|_| SignatureError::InvalidKey)?;
        let signature = Ed25519Signature::from_slice(input.signature)
            .map_err(|_| SignatureError::InvalidSignatureEncoding)?;
        key.verify_strict(input.signing_preimage, &signature)
            .map_err(|_| SignatureError::InvalidSignature)
    }

    fn work_units(&self) -> u64 {
        100
    }
}

/// ECDSA P-256/SHA-256 verification with fixed-width low-S signatures.
pub struct P256Sha256Suite {
    id: SignatureSuiteId,
}

impl P256Sha256Suite {
    /// Constructs the mandatory P-256/SHA-256 suite.
    ///
    /// # Errors
    ///
    /// Returns a model error only if the compiled registry identifier is
    /// invalid.
    pub fn new() -> Result<Self, ModelError> {
        Ok(Self {
            id: SignatureSuiteId::parse(P256_SHA256_V1)?,
        })
    }
}

impl SignatureSuite for P256Sha256Suite {
    fn id(&self) -> &SignatureSuiteId {
        &self.id
    }

    fn verify(&self, input: SignatureInput<'_>) -> Result<(), SignatureError> {
        let key = P256Key::from_sec1_bytes(input.verification_key)
            .map_err(|_| SignatureError::InvalidKey)?;
        let signature = P256Signature::from_slice(input.signature)
            .map_err(|_| SignatureError::InvalidSignatureEncoding)?;
        if signature.normalize_s().is_some() {
            return Err(SignatureError::InvalidSignature);
        }
        key.verify(input.signing_preimage, &signature)
            .map_err(|_| SignatureError::InvalidSignature)
    }

    fn work_units(&self) -> u64 {
        250
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_ports::SignatureSuite;
    use ed25519_dalek::{Signer as _, SigningKey};

    #[test]
    fn ed25519_binds_every_message_byte() {
        let signing = SigningKey::from_bytes(&[9; 32]);
        let signature = signing.sign(b"target-v1");
        let suite = Ed25519Suite::new().unwrap();
        assert!(suite
            .verify(SignatureInput {
                verification_key: signing.verifying_key().as_bytes(),
                signing_preimage: b"target-v1",
                signature: &signature.to_bytes(),
            })
            .is_ok());
        assert_eq!(
            suite.verify(SignatureInput {
                verification_key: signing.verifying_key().as_bytes(),
                signing_preimage: b"target-v2",
                signature: &signature.to_bytes(),
            }),
            Err(SignatureError::InvalidSignature)
        );
    }
}
