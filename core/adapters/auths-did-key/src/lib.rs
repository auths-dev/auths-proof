//! Strict, effect-free `did:key` principal control for target V1.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{format, vec, vec::Vec};
use auths_model::{
    AdapterConfigurationId, AdapterId, AssuranceClaim, AssuranceClaimId, EvidenceId,
    EvidenceSourceId, EvidenceTypeId, MediaType, ModelError, PrincipalId, PrincipalMethodId,
    VerificationMethod,
};
use auths_multikey::{Multikey, MultikeyError};
use auths_ports::{ControlEvidence, PrincipalControlError, PrincipalControlInput, PrincipalMethod};
use core::fmt;

/// Exact target V1 principal-method and evidence-type identifier.
pub const DID_KEY_V1: &str = "did-key-v1";
/// Deterministic target V1 `did:key` evidence media type.
pub const DID_KEY_MEDIA_TYPE: &str = "application/vnd.auths.did-key.v1";
/// Canonical `did:key` principal prefix.
pub const PRINCIPAL_PREFIX: &str = "did:key:";
const EVIDENCE_DOMAIN: &[u8] = b"AUTHS-DID-KEY\x00\x01";

/// Canonical evidence containing exactly one Multikey.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidKeyEvidence {
    multikey: Multikey,
}

impl DidKeyEvidence {
    /// Constructs evidence for a validated canonical Multikey.
    #[must_use]
    pub const fn new(multikey: Multikey) -> Self {
        Self { multikey }
    }

    /// Returns the validated Multikey.
    #[must_use]
    pub const fn multikey(&self) -> &Multikey {
        &self.multikey
    }

    /// Encodes the unique bounded target V1 evidence bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DidKeyError::InvalidEvidence`] if the bounded Multikey
    /// invariant cannot be represented by the evidence framing.
    pub fn encode(&self) -> Result<Vec<u8>, DidKeyError> {
        let encoded = self.multikey.encoded().as_bytes();
        let length = u16::try_from(encoded.len()).map_err(|_| DidKeyError::InvalidEvidence)?;
        let mut output = Vec::with_capacity(EVIDENCE_DOMAIN.len() + 2 + encoded.len());
        output.extend_from_slice(EVIDENCE_DOMAIN);
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(encoded);
        Ok(output)
    }

    /// Decodes exact target V1 evidence bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed error for a wrong domain, malformed length, UTF-8,
    /// Multibase, multicodec, key, or non-canonical representation.
    pub fn decode(bytes: &[u8]) -> Result<Self, DidKeyError> {
        if !bytes.starts_with(EVIDENCE_DOMAIN) {
            return Err(DidKeyError::InvalidEvidence);
        }
        let offset = EVIDENCE_DOMAIN.len();
        let length_bytes = bytes
            .get(offset..offset + 2)
            .ok_or(DidKeyError::InvalidEvidence)?;
        let length = usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
        let encoded = bytes
            .get(offset + 2..)
            .ok_or(DidKeyError::InvalidEvidence)?;
        if encoded.len() != length {
            return Err(DidKeyError::InvalidEvidence);
        }
        let encoded = core::str::from_utf8(encoded).map_err(|_| DidKeyError::InvalidEvidence)?;
        Ok(Self::new(Multikey::parse(encoded)?))
    }

    /// Derives the self-certifying principal identifier.
    ///
    /// # Errors
    ///
    /// Returns a model error if the canonical identifier is not representable.
    pub fn principal(&self) -> Result<PrincipalId, ModelError> {
        PrincipalId::parse(&format!("{PRINCIPAL_PREFIX}{}", self.multikey.encoded()))
    }

    /// Derives the only verification method permitted for this DID.
    ///
    /// # Errors
    ///
    /// Returns a model error if the canonical method is not representable.
    pub fn verification_method(&self) -> Result<VerificationMethod, ModelError> {
        let principal = self.principal()?;
        VerificationMethod::parse(&format!(
            "{}#{}",
            principal.as_str(),
            self.multikey.encoded()
        ))
    }
}

/// Target V1 `did:key` method implementation.
pub struct DidKeyMethod {
    id: PrincipalMethodId,
    evidence_type: EvidenceTypeId,
    media_type: MediaType,
    adapter: AdapterId,
    source: EvidenceSourceId,
}

impl DidKeyMethod {
    /// Constructs the exact compiled `did:key` implementation.
    ///
    /// # Errors
    ///
    /// Returns a model error only if a compiled registry identifier is invalid.
    pub fn new() -> Result<Self, ModelError> {
        Ok(Self {
            id: PrincipalMethodId::parse(DID_KEY_V1)?,
            evidence_type: EvidenceTypeId::parse(DID_KEY_V1)?,
            media_type: MediaType::parse(DID_KEY_MEDIA_TYPE)?,
            adapter: AdapterId::parse(DID_KEY_V1)?,
            source: EvidenceSourceId::parse(DID_KEY_V1)?,
        })
    }
}

impl PrincipalMethod for DidKeyMethod {
    fn id(&self) -> &PrincipalMethodId {
        &self.id
    }

    fn configuration_id(&self) -> AdapterConfigurationId {
        auths_ports::configuration_id(DID_KEY_V1.as_bytes(), core::iter::empty())
    }

    fn maximum_work_units(&self) -> u64 {
        15
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
        let descriptor = DidKeyEvidence::decode(evidence.bytes())
            .map_err(|_| PrincipalControlError::InvalidEvidence)?;
        if descriptor.multikey().key_type().suite() != input.signature_suite.as_str() {
            return Err(PrincipalControlError::SignatureSuiteMismatch);
        }
        let principal = descriptor
            .principal()
            .map_err(|_| PrincipalControlError::InvalidEvidence)?;
        if &principal != input.principal {
            return Err(PrincipalControlError::PrincipalMethodMismatch);
        }
        let verification_method = descriptor
            .verification_method()
            .map_err(|_| PrincipalControlError::InvalidEvidence)?;
        if &verification_method != input.verification_method {
            return Err(PrincipalControlError::VerificationMethodMismatch);
        }
        let claims = vec![
            claim("self-certifying-identifier", &self.source)?,
            claim("offline-verifiable", &self.source)?,
        ];
        ControlEvidence::new(
            descriptor.multikey().public_key().to_vec(),
            claims,
            vec![EvidenceId::new(*evidence.id().as_bytes())],
            self.adapter.clone(),
            1,
            15,
        )
    }
}

fn claim(
    identifier: &str,
    source: &EvidenceSourceId,
) -> Result<AssuranceClaim, PrincipalControlError> {
    AssuranceClaim::new(
        AssuranceClaimId::parse(identifier).map_err(|_| PrincipalControlError::InvalidEvidence)?,
        Vec::new(),
        None,
        source.clone(),
    )
    .map_err(|_| PrincipalControlError::InvalidEvidence)
}

/// `did:key` evidence construction or parsing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DidKeyError {
    /// A model identifier could not be represented.
    Model(ModelError),
    /// The closed Multikey grammar rejected the value.
    Multikey(MultikeyError),
    /// The target evidence framing is malformed.
    InvalidEvidence,
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
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DidKeyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_codec::evidence_id;
    use auths_model::{Digest, EvidenceObject, SignatureSuiteId, Timestamp};
    use auths_multikey::MultikeyType;
    use ed25519_dalek::SigningKey;

    #[test]
    fn official_principal_and_method_are_exact() {
        let multikey = Multikey::parse("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
        let evidence = DidKeyEvidence::new(multikey);
        assert_eq!(
            evidence.principal().unwrap().as_str(),
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
        assert_eq!(
            evidence.verification_method().unwrap().as_str(),
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
    }

    #[test]
    fn exact_bound_evidence_establishes_control() {
        let key = SigningKey::from_bytes(&[81; 32]);
        let descriptor = DidKeyEvidence::new(
            Multikey::from_public_key(
                MultikeyType::Ed25519,
                key.verifying_key().to_bytes().to_vec(),
            )
            .unwrap(),
        );
        let unaddressed = EvidenceObject::new(
            EvidenceId::from_digest(Digest::ZERO),
            EvidenceTypeId::parse(DID_KEY_V1).unwrap(),
            MediaType::parse(DID_KEY_MEDIA_TYPE).unwrap(),
            descriptor.encode().unwrap(),
        )
        .unwrap();
        let evidence = EvidenceObject::new(
            evidence_id(&unaddressed).unwrap(),
            unaddressed.evidence_type().clone(),
            unaddressed.media_type().clone(),
            unaddressed.bytes().to_vec(),
        )
        .unwrap();
        let refs = [&evidence];
        let result = DidKeyMethod::new()
            .unwrap()
            .verify_control(PrincipalControlInput {
                principal: &descriptor.principal().unwrap(),
                verification_method: &descriptor.verification_method().unwrap(),
                signature_suite: &SignatureSuiteId::parse("ed25519-v1").unwrap(),
                purpose: auths_ports::ControlPurpose::CapabilityInvocation,
                signing_preimage: b"test",
                asserted_signing_time: Timestamp::new(1),
                evidence: &refs,
                evaluation_time: Timestamp::new(1),
            });
        assert_eq!(
            result.unwrap().verification_key(),
            key.verifying_key().as_bytes()
        );
    }
}
