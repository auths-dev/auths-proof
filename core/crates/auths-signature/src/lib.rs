//! Mandatory target V1 signature-suite implementations.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

use auths_model::{AdapterConfigurationId, ModelError, SignatureSuiteId};
use auths_ports::{SignatureError, SignatureInput, SignatureSuite};
pub use auths_signature_core::{ED25519_V1, P256_SHA256_V1};
use auths_signature_core::{Ed25519Error, P256Error, verify_ed25519, verify_p256_sha256};

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

    fn configuration_id(&self) -> AdapterConfigurationId {
        auths_ports::configuration_id(ED25519_V1.as_bytes(), core::iter::empty())
    }

    fn verify(&self, input: SignatureInput<'_>) -> Result<(), SignatureError> {
        verify_ed25519(
            input.verification_key,
            input.signing_preimage,
            input.signature,
        )
        .map_err(|error| match error {
            Ed25519Error::InvalidKey => SignatureError::InvalidKey,
            Ed25519Error::InvalidSignatureEncoding => SignatureError::InvalidSignatureEncoding,
            Ed25519Error::VerificationFailed => SignatureError::InvalidSignature,
        })
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

    fn configuration_id(&self) -> AdapterConfigurationId {
        auths_ports::configuration_id(P256_SHA256_V1.as_bytes(), core::iter::empty())
    }

    fn verify(&self, input: SignatureInput<'_>) -> Result<(), SignatureError> {
        verify_p256_sha256(
            input.verification_key,
            input.signing_preimage,
            input.signature,
        )
        .map_err(|error| match error {
            P256Error::InvalidKey => SignatureError::InvalidKey,
            P256Error::InvalidSignatureEncoding => SignatureError::InvalidSignatureEncoding,
            P256Error::VerificationFailed => SignatureError::InvalidSignature,
        })
    }

    fn work_units(&self) -> u64 {
        250
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_identity::SignatureVerifier;
    use auths_ports::SignatureSuite;
    use auths_signature_ed25519::Ed25519Verifier;
    use ed25519_dalek::{Signer as _, SigningKey};

    #[test]
    fn ed25519_binds_every_message_byte() {
        let signing = SigningKey::from_bytes(&[9; 32]);
        let signature = signing.sign(b"target-v1");
        let suite = Ed25519Suite::new().unwrap();
        assert!(
            suite
                .verify(SignatureInput {
                    verification_key: signing.verifying_key().as_bytes(),
                    signing_preimage: b"target-v1",
                    signature: &signature.to_bytes(),
                })
                .is_ok()
        );
        assert_eq!(
            suite.verify(SignatureInput {
                verification_key: signing.verifying_key().as_bytes(),
                signing_preimage: b"target-v2",
                signature: &signature.to_bytes(),
            }),
            Err(SignatureError::InvalidSignature)
        );
    }

    #[test]
    fn identity_and_proof_ports_accept_the_same_corpus() {
        type Vector<'a> = (&'a [u8], &'a [u8], &'a [u8], bool);

        let signing = SigningKey::from_bytes(&[11; 32]);
        let key = signing.verifying_key().to_bytes();
        let signature = signing.sign(b"same semantics").to_bytes();
        let malformed = [0; 63];
        let invalid = [0; 64];
        let short_key = [0; 31];
        let vectors: &[Vector<'_>] = &[
            (&key, b"same semantics", &signature, true),
            (&key, b"changed semantics", &signature, false),
            (&short_key, b"same semantics", &signature, false),
            (&key, b"same semantics", &malformed, false),
            (&key, b"same semantics", &invalid, false),
        ];
        let proof = Ed25519Suite::new().unwrap();

        for &(verification_key, preimage, candidate, expected) in vectors {
            let identity_result = Ed25519Verifier
                .verify(verification_key, preimage, candidate)
                .is_ok();
            let proof_result = proof
                .verify(SignatureInput {
                    verification_key,
                    signing_preimage: preimage,
                    signature: candidate,
                })
                .is_ok();
            assert_eq!(identity_result, expected);
            assert_eq!(proof_result, expected);
        }
    }
}
