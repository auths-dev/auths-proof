//! Self-certifying raw-key principal method for target V1.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{vec, vec::Vec};
use auths_model::{
    AdapterConfigurationId, AdapterId, AssuranceClaim, AssuranceClaimId, EvidenceId,
    EvidenceSourceId, EvidenceTypeId, MediaType, ModelError, PrincipalId, PrincipalMethodId,
};
use auths_ports::{ControlEvidence, PrincipalControlError, PrincipalControlInput, PrincipalMethod};
pub use auths_raw_key_core::{
    RAW_KEY_V2, RAW_KEY_V2_MEDIA_TYPE, RawKeyDescriptorV2, V2_PRINCIPAL_PREFIX,
};
use auths_raw_key_core::{RawKeyTypeV1, decode_v1, encode_v1, identifier_v1};

/// Exact principal-method and evidence-type identifier.
pub use auths_raw_key_core::RAW_KEY_V1;
/// Deterministic raw-key evidence media type.
pub use auths_raw_key_core::RAW_KEY_V1_MEDIA_TYPE as RAW_KEY_MEDIA_TYPE;
/// Self-certifying raw-key principal prefix.
pub use auths_raw_key_core::V1_PRINCIPAL_PREFIX as PRINCIPAL_PREFIX;
use auths_raw_key_core::{ED25519_V1, P256_SHA256_V1};

/// Supported raw public-key form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawKeyType {
    /// 32-byte Ed25519 compressed point.
    Ed25519,
    /// 33-byte compressed SEC1 P-256 point.
    P256,
}

impl RawKeyType {
    const fn core(self) -> RawKeyTypeV1 {
        match self {
            Self::Ed25519 => RawKeyTypeV1::Ed25519,
            Self::P256 => RawKeyTypeV1::P256,
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
        encode_v1(key_type.core(), &public_key).map_err(|_| RawKeyError::InvalidKey)?;
        Ok(Self {
            key_type,
            public_key,
        })
    }

    /// Encodes the unique raw-key evidence bytes.
    ///
    /// # Panics
    ///
    /// This cannot panic for a descriptor constructed or decoded by this type.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode_v1(self.key_type.core(), &self.public_key)
            .expect("validated target-V1 raw-key descriptor")
    }

    /// Decodes exact raw-key evidence bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed error for a wrong domain, tag, length, or key.
    pub fn decode(input: &[u8]) -> Result<Self, RawKeyError> {
        let (key_type, public_key) = decode_v1(input).map_err(|_| RawKeyError::InvalidEncoding)?;
        Self::new(
            match key_type {
                RawKeyTypeV1::Ed25519 => RawKeyType::Ed25519,
                RawKeyTypeV1::P256 => RawKeyType::P256,
            },
            public_key,
        )
    }

    /// Derives the canonical self-certifying principal.
    ///
    /// # Errors
    ///
    /// Returns a model error if the derived principal cannot be represented.
    pub fn principal(&self) -> Result<PrincipalId, ModelError> {
        PrincipalId::parse(
            &identifier_v1(self.key_type.core(), &self.public_key)
                .map_err(|_| ModelError::InvalidPrincipal)?,
        )
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

    fn configuration_id(&self) -> AdapterConfigurationId {
        auths_ports::configuration_id(RAW_KEY_V1.as_bytes(), core::iter::empty())
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

/// Generalized V2 raw-key principal-control adapter.
pub struct RawKeyV2Method {
    id: PrincipalMethodId,
    evidence_type: EvidenceTypeId,
    media_type: MediaType,
    adapter: AdapterId,
    source: EvidenceSourceId,
}

impl RawKeyV2Method {
    /// Constructs the generalized raw-key implementation.
    ///
    /// # Errors
    ///
    /// Returns a model error only if a compiled identifier is invalid.
    pub fn new() -> Result<Self, ModelError> {
        Ok(Self {
            id: PrincipalMethodId::parse(RAW_KEY_V2)?,
            evidence_type: EvidenceTypeId::parse(RAW_KEY_V2)?,
            media_type: MediaType::parse(RAW_KEY_V2_MEDIA_TYPE)?,
            adapter: AdapterId::parse(RAW_KEY_V2)?,
            source: EvidenceSourceId::parse(RAW_KEY_V2)?,
        })
    }
}

impl PrincipalMethod for RawKeyV2Method {
    fn id(&self) -> &PrincipalMethodId {
        &self.id
    }

    fn configuration_id(&self) -> AdapterConfigurationId {
        auths_ports::configuration_id(RAW_KEY_V2.as_bytes(), core::iter::empty())
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
        let descriptor = RawKeyDescriptorV2::decode(evidence.bytes())
            .map_err(|_| PrincipalControlError::InvalidEvidence)?;
        if descriptor.suite_id() != input.signature_suite.as_str() {
            return Err(PrincipalControlError::SignatureSuiteMismatch);
        }
        let principal = PrincipalId::parse(&descriptor.identifier())
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
            2,
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
    use auths_identity_authority::{PrincipalFromIdentity, RawKeyV2AuthorityBridge};
    use auths_identity_raw_key::RawKeyIdentityMethod;
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
        assert!(
            method
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
                .is_ok()
        );
    }

    #[test]
    fn generalized_descriptor_matches_the_authority_principal() {
        let descriptor = RawKeyDescriptorV2::new("example-pq-v1", vec![7; 4096]).unwrap();
        let principal = PrincipalId::parse(&descriptor.identifier()).unwrap();
        let evidence = EvidenceObject::new(
            EvidenceId::from_digest(Digest::ZERO),
            EvidenceTypeId::parse(RAW_KEY_V2).unwrap(),
            MediaType::parse(RAW_KEY_V2_MEDIA_TYPE).unwrap(),
            descriptor.encode(),
        )
        .unwrap();
        let refs = [&evidence];
        let method = RawKeyV2Method::new().unwrap();
        assert!(
            method
                .verify_control(PrincipalControlInput {
                    principal: &principal,
                    verification_method: &VerificationMethod::parse(principal.as_str()).unwrap(),
                    signature_suite: &SignatureSuiteId::parse("example-pq-v1").unwrap(),
                    purpose: auths_ports::ControlPurpose::CapabilityInvocation,
                    signing_preimage: b"test",
                    asserted_signing_time: Timestamp::new(0),
                    evidence: &refs,
                    evaluation_time: Timestamp::new(0),
                })
                .is_ok()
        );
    }

    #[test]
    fn validated_identity_promotes_without_application_owned_derivation() {
        let identity = RawKeyIdentityMethod::identity("example-pq-v1", vec![7; 4096]).unwrap();
        let authority = RawKeyV2AuthorityBridge.promote(&identity).unwrap();
        assert_eq!(authority.principal().as_str(), identity.identity_id());
        assert_eq!(authority.verification_material(), identity.public_key());
        assert_eq!(
            authority.signature_descriptor().principal_method().as_str(),
            identity.method_id()
        );
        assert_eq!(
            authority.signature_descriptor().suite().as_str(),
            identity.suite_id()
        );

        let evidence = authority.evidence().iter().collect::<Vec<_>>();
        assert!(
            RawKeyV2Method::new()
                .unwrap()
                .verify_control(PrincipalControlInput {
                    principal: authority.principal(),
                    verification_method: authority.signature_descriptor().verification_method(),
                    signature_suite: authority.signature_descriptor().suite(),
                    purpose: auths_ports::ControlPurpose::CapabilityInvocation,
                    signing_preimage: b"application-owned preimage",
                    asserted_signing_time: Timestamp::new(0),
                    evidence: &evidence,
                    evaluation_time: Timestamp::new(0),
                })
                .is_ok()
        );
    }
}
