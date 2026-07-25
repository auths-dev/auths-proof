//! Self-certifying raw-key principal method for target V1.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{format, vec, vec::Vec};
use auths_model::{
    AdapterId, AssuranceClaim, AssuranceClaimId, EvidenceId, EvidenceSourceId, EvidenceTypeId,
    MediaType, ModelError, PrincipalId, PrincipalMethodId,
};
use auths_ports::{ControlEvidence, PrincipalControlError, PrincipalControlInput, PrincipalMethod};
use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest as _, Sha256};

/// Exact principal-method and evidence-type identifier.
pub const RAW_KEY_V1: &str = "raw-key-v1";
/// Deterministic raw-key evidence media type.
pub const RAW_KEY_MEDIA_TYPE: &str = "application/vnd.auths.raw-key.v1";
/// Self-certifying raw-key principal prefix.
pub const PRINCIPAL_PREFIX: &str = "key:sha256:";
const DESCRIPTOR_DOMAIN: &[u8] = b"AUTHS-RAW-KEY\x00\x01";
const ED25519_V1: &str = "ed25519-v1";
const P256_SHA256_V1: &str = "p256-sha256-v1";

/// Supported raw public-key form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawKeyType {
    /// 32-byte Ed25519 compressed point.
    Ed25519,
    /// 33-byte compressed SEC1 P-256 point.
    P256,
}

impl RawKeyType {
    const fn tag(self) -> u8 {
        match self {
            Self::Ed25519 => 1,
            Self::P256 => 2,
        }
    }

    fn suite(self) -> &'static str {
        match self {
            Self::Ed25519 => ED25519_V1,
            Self::P256 => P256_SHA256_V1,
        }
    }
}

/// Canonical self-certifying raw public-key descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawKeyDescriptor {
    key_type: RawKeyType,
    public_key: Vec<u8>,
}

impl RawKeyDescriptor {
    /// Constructs a descriptor with exact key length.
    ///
    /// # Errors
    ///
    /// Returns [`RawKeyError::InvalidKey`] for an incompatible key length.
    pub fn new(key_type: RawKeyType, public_key: Vec<u8>) -> Result<Self, RawKeyError> {
        let expected = match key_type {
            RawKeyType::Ed25519 => 32,
            RawKeyType::P256 => 33,
        };
        if public_key.len() != expected {
            return Err(RawKeyError::InvalidKey);
        }
        Ok(Self {
            key_type,
            public_key,
        })
    }

    /// Encodes the unique raw-key evidence bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(DESCRIPTOR_DOMAIN.len() + 3 + self.public_key.len());
        output.extend_from_slice(DESCRIPTOR_DOMAIN);
        output.push(self.key_type.tag());
        let key_length = match self.key_type {
            RawKeyType::Ed25519 => 32_u16,
            RawKeyType::P256 => 33_u16,
        };
        output.extend_from_slice(&key_length.to_be_bytes());
        output.extend_from_slice(&self.public_key);
        output
    }

    /// Decodes exact raw-key evidence bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed error for a wrong domain, tag, length, or key.
    pub fn decode(input: &[u8]) -> Result<Self, RawKeyError> {
        if !input.starts_with(DESCRIPTOR_DOMAIN) || input.len() < DESCRIPTOR_DOMAIN.len() + 3 {
            return Err(RawKeyError::InvalidEncoding);
        }
        let offset = DESCRIPTOR_DOMAIN.len();
        let key_type = match input[offset] {
            1 => RawKeyType::Ed25519,
            2 => RawKeyType::P256,
            _ => return Err(RawKeyError::InvalidEncoding),
        };
        let length = usize::from(u16::from_be_bytes([input[offset + 1], input[offset + 2]]));
        let public_key = input
            .get(offset + 3..)
            .ok_or(RawKeyError::InvalidEncoding)?;
        if public_key.len() != length {
            return Err(RawKeyError::InvalidEncoding);
        }
        Self::new(key_type, public_key.to_vec())
    }

    /// Derives the canonical self-certifying principal.
    ///
    /// # Errors
    ///
    /// Returns a model error if the derived principal cannot be represented.
    pub fn principal(&self) -> Result<PrincipalId, ModelError> {
        let digest: [u8; 32] = Sha256::digest(self.encode()).into();
        PrincipalId::parse(&format!(
            "{PRINCIPAL_PREFIX}{}",
            Base64UrlUnpadded::encode_string(&digest)
        ))
    }

    /// Returns the exact suite required by this key form.
    #[must_use]
    pub fn suite(&self) -> &'static str {
        self.key_type.suite()
    }

    /// Returns the suite-specific verification-key bytes.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

/// Target V1 raw-key principal-control adapter.
pub struct RawKeyMethod {
    id: PrincipalMethodId,
    evidence_type: EvidenceTypeId,
    media_type: MediaType,
    adapter: AdapterId,
    source: EvidenceSourceId,
}

impl RawKeyMethod {
    /// Constructs the exact raw-key implementation.
    ///
    /// # Errors
    ///
    /// Returns a model error only if a compiled identifier is invalid.
    pub fn new() -> Result<Self, ModelError> {
        Ok(Self {
            id: PrincipalMethodId::parse(RAW_KEY_V1)?,
            evidence_type: EvidenceTypeId::parse(RAW_KEY_V1)?,
            media_type: MediaType::parse(RAW_KEY_MEDIA_TYPE)?,
            adapter: AdapterId::parse(RAW_KEY_V1)?,
            source: EvidenceSourceId::parse(RAW_KEY_V1)?,
        })
    }
}

impl PrincipalMethod for RawKeyMethod {
    fn id(&self) -> &PrincipalMethodId {
        &self.id
    }

    fn maximum_work_units(&self) -> u64 {
        10
    }

    fn verify_control(
        &self,
        input: PrincipalControlInput<'_>,
    ) -> Result<ControlEvidence, PrincipalControlError> {
        let mut selected = None;
        for evidence in input.evidence {
            if evidence.evidence_type() == &self.evidence_type {
                if selected.is_some() || evidence.media_type() != &self.media_type {
                    return Err(PrincipalControlError::InvalidEvidence);
                }
                selected = Some(*evidence);
            }
        }
        let evidence = selected.ok_or(PrincipalControlError::MissingEvidence)?;
        let descriptor = RawKeyDescriptor::decode(evidence.bytes())
            .map_err(|_| PrincipalControlError::InvalidEvidence)?;
        if descriptor.suite() != input.signature_suite.as_str() {
            return Err(PrincipalControlError::SignatureSuiteMismatch);
        }
        let principal = descriptor
            .principal()
            .map_err(|_| PrincipalControlError::InvalidEvidence)?;
        if &principal != input.principal {
            return Err(PrincipalControlError::PrincipalMethodMismatch);
        }
        if input.verification_method.as_str() != principal.as_str() {
            return Err(PrincipalControlError::VerificationMethodMismatch);
        }
        let claims = vec![
            AssuranceClaim::new(
                AssuranceClaimId::parse("self-certifying-identifier")
                    .map_err(|_| PrincipalControlError::InvalidEvidence)?,
                Vec::new(),
                None,
                self.source.clone(),
            )
            .map_err(|_| PrincipalControlError::InvalidEvidence)?,
            AssuranceClaim::new(
                AssuranceClaimId::parse("offline-verifiable")
                    .map_err(|_| PrincipalControlError::InvalidEvidence)?,
                Vec::new(),
                None,
                self.source.clone(),
            )
            .map_err(|_| PrincipalControlError::InvalidEvidence)?,
        ];
        ControlEvidence::new(
            descriptor.public_key().to_vec(),
            claims,
            vec![EvidenceId::new(*evidence.id().as_bytes())],
            self.adapter.clone(),
            1,
            10,
        )
    }
}

/// Raw-key parsing or construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawKeyError {
    /// Key bytes do not have the registered length.
    InvalidKey,
    /// Evidence bytes do not use the exact descriptor encoding.
    InvalidEncoding,
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_model::{Digest, EvidenceObject, SignatureSuiteId, Timestamp, VerificationMethod};

    #[test]
    fn descriptor_is_self_certifying_and_suite_bound() {
        let descriptor = RawKeyDescriptor::new(RawKeyType::Ed25519, vec![3; 32]).unwrap();
        let principal = descriptor.principal().unwrap();
        let evidence = EvidenceObject::new(
            EvidenceId::from_digest(Digest::ZERO),
            EvidenceTypeId::parse(RAW_KEY_V1).unwrap(),
            MediaType::parse(RAW_KEY_MEDIA_TYPE).unwrap(),
            descriptor.encode(),
        )
        .unwrap();
        let refs = [&evidence];
        let method = RawKeyMethod::new().unwrap();
        assert!(method
            .verify_control(PrincipalControlInput {
                principal: &principal,
                verification_method: &VerificationMethod::parse(principal.as_str()).unwrap(),
                signature_suite: &SignatureSuiteId::parse(ED25519_V1).unwrap(),
                purpose: auths_ports::ControlPurpose::CapabilityInvocation,
                signing_preimage: b"test",
                asserted_signing_time: Timestamp::new(0),
                evidence: &refs,
                evaluation_time: Timestamp::new(0),
            })
            .is_ok());
    }
}
