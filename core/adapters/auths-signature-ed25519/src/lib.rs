//! Standalone Ed25519 verifier for algorithm-neutral identity messages.

#![no_std]
#![forbid(unsafe_code)]

use auths_identity::{IdentityError, SignatureVerifier};
use auths_signature_core::{Ed25519Error, verify_ed25519};

pub use auths_signature_core::ED25519_V1;

pub struct Ed25519Verifier;

impl SignatureVerifier for Ed25519Verifier {
    fn suite_id(&self) -> &'static str {
        ED25519_V1
    }

    fn verify(
        &self,
        public_key: &[u8],
        preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), IdentityError> {
        verify_ed25519(public_key, preimage, signature).map_err(|error| match error {
            Ed25519Error::InvalidKey => IdentityError::InvalidPublicKey,
            Ed25519Error::InvalidSignatureEncoding => IdentityError::InvalidSignature,
            Ed25519Error::VerificationFailed => IdentityError::VerificationFailed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_identity::SignatureVerifier;
    use ed25519_dalek::{Signer as _, SigningKey};

    #[test]
    fn verifies_exact_message() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let signature = key.sign(b"exact");
        Ed25519Verifier
            .verify(
                key.verifying_key().as_bytes(),
                b"exact",
                &signature.to_bytes(),
            )
            .unwrap();
        assert_eq!(
            Ed25519Verifier.verify(
                key.verifying_key().as_bytes(),
                b"changed",
                &signature.to_bytes()
            ),
            Err(IdentityError::VerificationFailed)
        );
    }
}
