//! Strict, self-contained `did:key` principal-control verification.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{format, vec, vec::Vec};
use auths_proof_adapter_api::{
    ControlProofInput, PrincipalControlError, PrincipalControlVerifier, VerifiedPrincipal,
};
use auths_proof_codec::evidence_id;
use auths_proof_model::{
    AdapterId, AlgorithmId, AssuranceClaim, AssuranceClaims, EvidenceBytes, EvidenceMediaType,
    ModelError, PrincipalEvidenceEntry, PrincipalRef, SignatureDescriptor, VerificationMethodRef,
};
use auths_proof_multikey::{Multikey, MultikeyError};
use core::fmt;

pub const ADAPTER_ID: &str = "did-key-v1";
pub const EVIDENCE_MEDIA_TYPE: &str = "application/vnd.auths.did-key.v1";
pub const PRINCIPAL_PREFIX: &str = "did:key:";
pub const EVIDENCE_DOMAIN: &[u8] = b"auths-proof/did-key/evidence/v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidKeyEvidence {
    multikey: Multikey,
}

impl DidKeyEvidence {
    pub const fn new(multikey: Multikey) -> Self {
        Self { multikey }
    }

    pub const fn multikey(&self) -> &Multikey {
        &self.multikey
    }

    pub fn encode(&self) -> Result<Vec<u8>, DidKeyError> {
        let encoded = self.multikey.encoded().as_bytes();
        let len = u16::try_from(encoded.len()).map_err(|_| DidKeyError::InvalidEvidence)?;
        let mut output = Vec::with_capacity(EVIDENCE_DOMAIN.len() + 2 + encoded.len());
        output.extend_from_slice(EVIDENCE_DOMAIN);
        output.extend_from_slice(&len.to_be_bytes());
        output.extend_from_slice(encoded);
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DidKeyError> {
        if !bytes.starts_with(EVIDENCE_DOMAIN) {
            return Err(DidKeyError::InvalidEvidence);
        }
        let offset = EVIDENCE_DOMAIN.len();
        let length = bytes
            .get(offset..offset + 2)
            .ok_or(DidKeyError::InvalidEvidence)?;
        let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
        let encoded = bytes
            .get(offset + 2..)
            .ok_or(DidKeyError::InvalidEvidence)?;
        if encoded.len() != length {
            return Err(DidKeyError::InvalidEvidence);
        }
        let encoded = core::str::from_utf8(encoded).map_err(|_| DidKeyError::InvalidEvidence)?;
        Ok(Self::new(Multikey::parse(encoded)?))
    }

    pub fn principal(&self) -> Result<PrincipalRef, ModelError> {
        PrincipalRef::parse(&format!("{PRINCIPAL_PREFIX}{}", self.multikey.encoded()))
    }

    pub fn verification_method(&self) -> Result<VerificationMethodRef, ModelError> {
        let principal = self.principal()?;
        VerificationMethodRef::parse(&format!(
            "{}#{}",
            principal.as_str(),
            self.multikey.encoded()
        ))
    }

    pub fn signature_descriptor(&self) -> Result<SignatureDescriptor, ModelError> {
        Ok(SignatureDescriptor::new(
            AdapterId::parse(ADAPTER_ID)?,
            self.verification_method()?,
            AlgorithmId::parse(self.multikey.key_type().algorithm())?,
        ))
    }

    pub fn evidence_entry(&self) -> Result<PrincipalEvidenceEntry, DidKeyError> {
        let adapter = AdapterId::parse(ADAPTER_ID)?;
        let media_type = EvidenceMediaType::parse(EVIDENCE_MEDIA_TYPE)?;
        let bytes = self.encode()?;
        let id = evidence_id(&adapter, &media_type, &bytes);
        Ok(PrincipalEvidenceEntry::new(
            id,
            adapter,
            media_type,
            EvidenceBytes::new(bytes)?,
        ))
    }
}

pub struct DidKeyAdapter {
    adapter_id: AdapterId,
    media_type: EvidenceMediaType,
}

impl DidKeyAdapter {
    pub fn new() -> Result<Self, ModelError> {
        Ok(Self {
            adapter_id: AdapterId::parse(ADAPTER_ID)?,
            media_type: EvidenceMediaType::parse(EVIDENCE_MEDIA_TYPE)?,
        })
    }
}

impl PrincipalControlVerifier for DidKeyAdapter {
    fn adapter_id(&self) -> &AdapterId {
        &self.adapter_id
    }

    fn supports(&self, principal: &PrincipalRef) -> bool {
        principal.as_str().starts_with(PRINCIPAL_PREFIX)
    }

    fn verify_control(
        &self,
        input: ControlProofInput<'_>,
    ) -> Result<VerifiedPrincipal, PrincipalControlError> {
        if !self.supports(input.principal) {
            return Err(PrincipalControlError::UnsupportedPrincipal);
        }
        if input.evidence.method() != &self.adapter_id
            || input.evidence.media_type() != &self.media_type
        {
            return Err(PrincipalControlError::AdapterMismatch);
        }
        let evidence = DidKeyEvidence::decode(input.evidence.bytes().as_slice())
            .map_err(|_| PrincipalControlError::InvalidEvidence)?;
        if evidence
            .principal()
            .map_err(|_| PrincipalControlError::InvalidEvidence)?
            != *input.principal
        {
            return Err(PrincipalControlError::InvalidEvidence);
        }
        if evidence
            .verification_method()
            .map_err(|_| PrincipalControlError::InvalidEvidence)?
            != *input.verification_method
        {
            return Err(PrincipalControlError::VerificationMethodMismatch);
        }
        if input.algorithm.as_str() != evidence.multikey.key_type().algorithm() {
            return Err(PrincipalControlError::AlgorithmMismatch);
        }
        evidence
            .multikey
            .verify(
                input.algorithm.as_str(),
                input.signing_bytes,
                input.signature,
            )
            .map_err(|error| match error {
                MultikeyError::AlgorithmMismatch => PrincipalControlError::AlgorithmMismatch,
                _ => PrincipalControlError::InvalidSignature,
            })?;

        Ok(VerifiedPrincipal::verified(
            input.principal.clone(),
            input.verification_method.clone(),
            self.adapter_id.clone(),
            input.evidence.id(),
            AssuranceClaims::new(vec![
                AssuranceClaim::SelfCertifyingIdentifier,
                AssuranceClaim::OfflineVerifiable,
            ]),
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DidKeyError {
    Model(ModelError),
    Multikey(MultikeyError),
    InvalidEvidence,
    InvalidSecretKey,
}

impl From<ModelError> for DidKeyError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl From<MultikeyError> for DidKeyError {
    fn from(error: MultikeyError) -> Self {
        Self::Multikey(error)
    }
}

impl fmt::Display for DidKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model(error) => write!(formatter, "invalid Auths model value: {error}"),
            Self::Multikey(error) => write!(formatter, "invalid Multikey: {error}"),
            Self::InvalidEvidence => formatter.write_str("invalid did:key evidence"),
            Self::InvalidSecretKey => formatter.write_str("invalid test signing key"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DidKeyError {}

#[cfg(any(test, feature = "test-signing"))]
pub mod test_signing {
    use super::*;
    use auths_proof_multikey::MultikeyType;
    use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
    use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};

    pub struct TestDidKeyIdentity {
        evidence: DidKeyEvidence,
        secret: TestSecret,
    }

    enum TestSecret {
        Ed25519([u8; 32]),
        P256([u8; 32]),
    }

    impl TestDidKeyIdentity {
        pub fn ed25519(seed: [u8; 32]) -> Result<Self, DidKeyError> {
            let signing_key = Ed25519SigningKey::from_bytes(&seed);
            Ok(Self {
                evidence: DidKeyEvidence::new(Multikey::from_public_key(
                    MultikeyType::Ed25519,
                    signing_key.verifying_key().to_bytes().to_vec(),
                )?),
                secret: TestSecret::Ed25519(seed),
            })
        }

        pub fn p256(seed: [u8; 32]) -> Result<Self, DidKeyError> {
            let signing_key =
                P256SigningKey::from_slice(&seed).map_err(|_| DidKeyError::InvalidSecretKey)?;
            Ok(Self {
                evidence: DidKeyEvidence::new(Multikey::from_public_key(
                    MultikeyType::P256,
                    signing_key
                        .verifying_key()
                        .to_encoded_point(true)
                        .as_bytes()
                        .to_vec(),
                )?),
                secret: TestSecret::P256(seed),
            })
        }

        pub fn principal(&self) -> Result<PrincipalRef, ModelError> {
            self.evidence.principal()
        }

        pub fn signature_descriptor(&self) -> Result<SignatureDescriptor, ModelError> {
            self.evidence.signature_descriptor()
        }

        pub fn evidence_entry(&self) -> Result<PrincipalEvidenceEntry, DidKeyError> {
            self.evidence.evidence_entry()
        }

        pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DidKeyError> {
            match self.secret {
                TestSecret::Ed25519(seed) => Ok(Ed25519SigningKey::from_bytes(&seed)
                    .sign(message)
                    .to_bytes()
                    .to_vec()),
                TestSecret::P256(seed) => {
                    let key = P256SigningKey::from_slice(&seed)
                        .map_err(|_| DidKeyError::InvalidSecretKey)?;
                    let mut signature: P256Signature = key.sign(message);
                    if let Some(normalized) = signature.normalize_s() {
                        signature = normalized;
                    }
                    Ok(signature.to_bytes().to_vec())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_proof_adapter_api::ControlProofInput;
    use auths_proof_model::{ProofPurpose, Timestamp};

    #[test]
    fn official_ed25519_principal_derives_expected_method() {
        let multikey =
            Multikey::parse("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").expect("vector");
        let evidence = DidKeyEvidence::new(multikey);
        let principal = evidence.principal().expect("principal");
        assert_eq!(
            principal.as_str(),
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
        assert_eq!(
            evidence.verification_method().expect("method").as_str(),
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
    }

    #[test]
    fn ed25519_control_proof_verifies() {
        let identity = test_signing::TestDidKeyIdentity::ed25519([81; 32]).expect("identity");
        let principal = identity.principal().expect("principal");
        let descriptor = identity.signature_descriptor().expect("descriptor");
        let evidence = identity.evidence_entry().expect("evidence");
        let signature = identity.sign(b"signed").expect("signature");
        let verified = DidKeyAdapter::new()
            .expect("adapter")
            .verify_control(ControlProofInput {
                principal: &principal,
                purpose: ProofPurpose::CapabilityInvocation,
                verification_method: descriptor.verification_method(),
                algorithm: descriptor.algorithm(),
                signing_bytes: b"signed",
                signature: &signature,
                evidence: &evidence,
                asserted_signing_time: Timestamp::new(1),
                verification_time: Timestamp::new(2),
            })
            .expect("valid control");
        assert_eq!(verified.principal(), &principal);
    }
}
