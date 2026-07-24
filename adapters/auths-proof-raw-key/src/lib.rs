//! Self-certifying raw Ed25519 and P-256 principal adapter.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{format, vec::Vec};
use auths_proof_adapter_api::{
    ControlProofInput, PrincipalControlError, PrincipalControlVerifier, VerifiedPrincipal,
};
use auths_proof_codec::evidence_id;
use auths_proof_model::{
    AdapterId, AlgorithmId, AssuranceClaim, AssuranceClaims, EvidenceBytes, EvidenceMediaType,
    ModelError, PrincipalEvidenceEntry, PrincipalRef, VerificationMethodRef,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use core::fmt;
use ed25519_dalek::{Signature as Ed25519Signature, Verifier as _, VerifyingKey as Ed25519Key};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256Key};
use sha2::{Digest, Sha256};

pub const ADAPTER_ID: &str = "raw-key-v1";
pub const EVIDENCE_MEDIA_TYPE: &str = "application/vnd.auths.raw-key.v1";
pub const ED25519_ALGORITHM: &str = "ed25519";
pub const P256_ALGORITHM: &str = "p256-sha256";
pub const PRINCIPAL_PREFIX: &str = "key:sha256:";
pub const DESCRIPTOR_DOMAIN: &[u8] = b"auths-proof/raw-key/v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawKeyType {
    Ed25519,
    P256,
}

impl RawKeyType {
    const fn tag(self) -> u8 {
        match self {
            Self::Ed25519 => 1,
            Self::P256 => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, RawKeyError> {
        match tag {
            1 => Ok(Self::Ed25519),
            2 => Ok(Self::P256),
            _ => Err(RawKeyError::UnsupportedKeyType),
        }
    }

    pub const fn algorithm(self) -> &'static str {
        match self {
            Self::Ed25519 => ED25519_ALGORITHM,
            Self::P256 => P256_ALGORITHM,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyDescriptor {
    key_type: RawKeyType,
    public_key: Vec<u8>,
}

impl KeyDescriptor {
    pub fn new(key_type: RawKeyType, public_key: Vec<u8>) -> Result<Self, RawKeyError> {
        let valid_len = match key_type {
            RawKeyType::Ed25519 => public_key.len() == 32,
            RawKeyType::P256 => public_key.len() == 33,
        };
        if !valid_len {
            return Err(RawKeyError::InvalidKeyLength);
        }
        Ok(Self {
            key_type,
            public_key,
        })
    }

    pub const fn key_type(&self) -> RawKeyType {
        self.key_type
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(DESCRIPTOR_DOMAIN.len() + 1 + 2 + self.public_key.len());
        bytes.extend_from_slice(DESCRIPTOR_DOMAIN);
        bytes.push(self.key_type.tag());
        bytes.extend_from_slice(&(self.public_key.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.public_key);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RawKeyError> {
        if !bytes.starts_with(DESCRIPTOR_DOMAIN) {
            return Err(RawKeyError::InvalidDescriptor);
        }
        let header = DESCRIPTOR_DOMAIN.len();
        let key_type =
            RawKeyType::from_tag(*bytes.get(header).ok_or(RawKeyError::InvalidDescriptor)?)?;
        let length_bytes = bytes
            .get(header + 1..header + 3)
            .ok_or(RawKeyError::InvalidDescriptor)?;
        let len = u16::from_be_bytes([length_bytes[0], length_bytes[1]]) as usize;
        let key = bytes
            .get(header + 3..)
            .ok_or(RawKeyError::InvalidDescriptor)?;
        if key.len() != len {
            return Err(RawKeyError::InvalidDescriptor);
        }
        Self::new(key_type, key.to_vec())
    }

    pub fn principal(&self) -> Result<PrincipalRef, ModelError> {
        let digest: [u8; 32] = Sha256::digest(self.encode()).into();
        let encoded = Base64UrlUnpadded::encode_string(&digest);
        PrincipalRef::parse(&format!("{PRINCIPAL_PREFIX}{encoded}"))
    }

    pub fn verification_method(&self) -> Result<VerificationMethodRef, ModelError> {
        VerificationMethodRef::parse(self.principal()?.as_str())
    }

    pub fn signature_descriptor(
        &self,
    ) -> Result<auths_proof_model::SignatureDescriptor, ModelError> {
        Ok(auths_proof_model::SignatureDescriptor::new(
            AdapterId::parse(ADAPTER_ID)?,
            self.verification_method()?,
            AlgorithmId::parse(self.key_type.algorithm())?,
        ))
    }

    pub fn evidence_entry(&self) -> Result<PrincipalEvidenceEntry, RawKeyError> {
        let method = AdapterId::parse(ADAPTER_ID)?;
        let media_type = EvidenceMediaType::parse(EVIDENCE_MEDIA_TYPE)?;
        let encoded = self.encode();
        let id = evidence_id(&method, &media_type, &encoded);
        Ok(PrincipalEvidenceEntry::new(
            id,
            method,
            media_type,
            EvidenceBytes::new(encoded)?,
        ))
    }
}

pub struct RawKeyAdapter {
    adapter_id: AdapterId,
    media_type: EvidenceMediaType,
}

impl RawKeyAdapter {
    pub fn new() -> Result<Self, ModelError> {
        Ok(Self {
            adapter_id: AdapterId::parse(ADAPTER_ID)?,
            media_type: EvidenceMediaType::parse(EVIDENCE_MEDIA_TYPE)?,
        })
    }
}

impl PrincipalControlVerifier for RawKeyAdapter {
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
        if input.verification_method.as_str() != input.principal.as_str() {
            return Err(PrincipalControlError::VerificationMethodMismatch);
        }

        let descriptor = KeyDescriptor::decode(input.evidence.bytes().as_slice())
            .map_err(|_| PrincipalControlError::InvalidEvidence)?;
        let evidence_principal = descriptor
            .principal()
            .map_err(|_| PrincipalControlError::InvalidEvidence)?;
        if evidence_principal != *input.principal {
            return Err(PrincipalControlError::InvalidEvidence);
        }
        if input.algorithm.as_str() != descriptor.key_type.algorithm() {
            return Err(PrincipalControlError::AlgorithmMismatch);
        }

        match descriptor.key_type {
            RawKeyType::Ed25519 => verify_ed25519(
                descriptor.public_key(),
                input.signing_bytes,
                input.signature,
            )?,
            RawKeyType::P256 => verify_p256(
                descriptor.public_key(),
                input.signing_bytes,
                input.signature,
            )?,
        }

        Ok(VerifiedPrincipal::verified(
            input.principal.clone(),
            input.verification_method.clone(),
            self.adapter_id.clone(),
            input.evidence.id(),
            AssuranceClaims::new(alloc::vec![
                AssuranceClaim::SelfCertifyingIdentifier,
                AssuranceClaim::OfflineVerifiable,
            ]),
        ))
    }
}

fn verify_ed25519(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), PrincipalControlError> {
    let key_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| PrincipalControlError::InvalidEvidence)?;
    let key =
        Ed25519Key::from_bytes(&key_bytes).map_err(|_| PrincipalControlError::InvalidEvidence)?;
    let signature = Ed25519Signature::from_slice(signature)
        .map_err(|_| PrincipalControlError::InvalidSignature)?;
    key.verify_strict(message, &signature)
        .map_err(|_| PrincipalControlError::InvalidSignature)
}

fn verify_p256(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), PrincipalControlError> {
    let key =
        P256Key::from_sec1_bytes(public_key).map_err(|_| PrincipalControlError::InvalidEvidence)?;
    let signature = P256Signature::from_slice(signature)
        .map_err(|_| PrincipalControlError::InvalidSignature)?;
    if signature.normalize_s().is_some() {
        return Err(PrincipalControlError::InvalidSignature);
    }
    key.verify(message, &signature)
        .map_err(|_| PrincipalControlError::InvalidSignature)
}

#[cfg(any(test, feature = "test-signing"))]
pub mod test_signing {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
    use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};

    pub fn ed25519_descriptor(seed: [u8; 32]) -> Result<KeyDescriptor, RawKeyError> {
        let signing_key = Ed25519SigningKey::from_bytes(&seed);
        KeyDescriptor::new(
            RawKeyType::Ed25519,
            signing_key.verifying_key().to_bytes().to_vec(),
        )
    }

    pub fn sign_ed25519(seed: [u8; 32], message: &[u8]) -> Vec<u8> {
        Ed25519SigningKey::from_bytes(&seed)
            .sign(message)
            .to_bytes()
            .to_vec()
    }

    pub fn p256_descriptor(seed: [u8; 32]) -> Result<KeyDescriptor, RawKeyError> {
        let signing_key =
            P256SigningKey::from_slice(&seed).map_err(|_| RawKeyError::InvalidSecretKey)?;
        KeyDescriptor::new(
            RawKeyType::P256,
            signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
        )
    }

    pub fn sign_p256(seed: [u8; 32], message: &[u8]) -> Result<Vec<u8>, RawKeyError> {
        let signing_key =
            P256SigningKey::from_slice(&seed).map_err(|_| RawKeyError::InvalidSecretKey)?;
        let mut signature: P256Signature = signing_key.sign(message);
        if let Some(normalized) = signature.normalize_s() {
            signature = normalized;
        }
        Ok(signature.to_bytes().to_vec())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawKeyError {
    Model(ModelError),
    InvalidDescriptor,
    UnsupportedKeyType,
    InvalidKeyLength,
    InvalidSecretKey,
}

impl From<ModelError> for RawKeyError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl fmt::Display for RawKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model(error) => write!(formatter, "invalid model value: {error}"),
            Self::InvalidDescriptor => formatter.write_str("invalid raw-key descriptor"),
            Self::UnsupportedKeyType => formatter.write_str("unsupported raw-key type"),
            Self::InvalidKeyLength => formatter.write_str("invalid raw-key length"),
            Self::InvalidSecretKey => formatter.write_str("invalid test signing key"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RawKeyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_proof_adapter_api::ControlProofInput;
    use auths_proof_model::{ProofPurpose, Timestamp};

    #[test]
    fn ed25519_control_proof_verifies() {
        let seed = [11; 32];
        let descriptor = test_signing::ed25519_descriptor(seed).expect("descriptor");
        let principal = descriptor.principal().expect("principal");
        let evidence = descriptor.evidence_entry().expect("evidence");
        let signature = test_signing::sign_ed25519(seed, b"signed");
        let signature_descriptor = descriptor
            .signature_descriptor()
            .expect("signature descriptor");
        let adapter = RawKeyAdapter::new().expect("adapter");

        let verified = adapter
            .verify_control(ControlProofInput {
                principal: &principal,
                purpose: ProofPurpose::CapabilityInvocation,
                verification_method: signature_descriptor.verification_method(),
                algorithm: signature_descriptor.algorithm(),
                signing_bytes: b"signed",
                signature: &signature,
                evidence: &evidence,
                asserted_signing_time: Timestamp::new(1),
                verification_time: Timestamp::new(2),
            })
            .expect("valid proof");
        assert_eq!(verified.principal(), &principal);
    }

    #[test]
    fn p256_high_s_is_not_created_by_test_signer() {
        let seed = [12; 32];
        let descriptor = test_signing::p256_descriptor(seed).expect("descriptor");
        let signature = test_signing::sign_p256(seed, b"signed").expect("signature");
        let parsed = P256Signature::from_slice(&signature).expect("parse");
        assert!(parsed.normalize_s().is_none());
        assert_eq!(descriptor.key_type(), RawKeyType::P256);
    }
}
