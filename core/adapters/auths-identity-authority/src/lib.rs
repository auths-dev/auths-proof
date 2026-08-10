//! Explicit, non-authorizing promotion of validated identities into authority inputs.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{vec, vec::Vec};
use auths_identity::ValidatedIdentity;
use auths_model::{
    Digest, EvidenceId, EvidenceObject, EvidenceTypeId, MediaType, ModelError, PrincipalId,
    PrincipalMethodId, SignatureDescriptor, SignatureSuiteId, VerificationMethod,
};
use auths_raw_key_core::{RAW_KEY_V2, RAW_KEY_V2_MEDIA_TYPE, RawKeyDescriptorV2};
use core::fmt;
use sha2::{Digest as _, Sha256};

/// Authority-shaped identity facts produced only from a validation witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityIdentity {
    principal: PrincipalId,
    signature: SignatureDescriptor,
    verification_material: Vec<u8>,
    evidence: Vec<EvidenceObject>,
}

impl AuthorityIdentity {
    /// Returns the canonical authority principal.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Returns the preserved method, verification relationship, and suite.
    #[must_use]
    pub const fn signature_descriptor(&self) -> &SignatureDescriptor {
        &self.signature
    }

    /// Returns opaque public verification material without interpreting its shape.
    #[must_use]
    pub fn verification_material(&self) -> &[u8] {
        &self.verification_material
    }

    /// Returns authority evidence explicitly created by the selected bridge.
    #[must_use]
    pub fn evidence(&self) -> &[EvidenceObject] {
        &self.evidence
    }
}

/// Explicit authority-side promotion selected by the application.
pub trait PrincipalFromIdentity {
    /// Promotes a method-validated identity without creating any authority or decision.
    ///
    /// # Errors
    ///
    /// Rejects identities outside the bridge's method or identities whose preserved facts cannot
    /// be represented by the authority model.
    fn promote(
        &self,
        identity: &ValidatedIdentity,
    ) -> Result<AuthorityIdentity, IdentityPromotionError>;
}

/// Raw-key V2 proof that a neutral validation witness can feed the authority stack.
pub struct RawKeyV2AuthorityBridge;

impl PrincipalFromIdentity for RawKeyV2AuthorityBridge {
    fn promote(
        &self,
        identity: &ValidatedIdentity,
    ) -> Result<AuthorityIdentity, IdentityPromotionError> {
        if identity.method_id() != RAW_KEY_V2 {
            return Err(IdentityPromotionError::UnsupportedMethod);
        }
        let descriptor =
            RawKeyDescriptorV2::new(identity.suite_id(), identity.public_key().to_vec())
                .map_err(|_| IdentityPromotionError::InvalidIdentity)?;
        if descriptor.identifier() != identity.identity_id() {
            return Err(IdentityPromotionError::InvalidIdentity);
        }

        let principal = PrincipalId::parse(identity.identity_id())?;
        let encoded = descriptor.encode();
        let digest: [u8; 32] = Sha256::digest(&encoded).into();
        let evidence = EvidenceObject::new(
            EvidenceId::from_digest(Digest::new(digest)),
            EvidenceTypeId::parse(RAW_KEY_V2)?,
            MediaType::parse(RAW_KEY_V2_MEDIA_TYPE)?,
            encoded,
        )?;
        let signature = SignatureDescriptor::new(
            PrincipalMethodId::parse(identity.method_id())?,
            VerificationMethod::parse(identity.identity_id())?,
            SignatureSuiteId::parse(identity.suite_id())?,
        );
        Ok(AuthorityIdentity {
            principal,
            signature,
            verification_material: identity.public_key().to_vec(),
            evidence: vec![evidence],
        })
    }
}

/// A validated identity could not be represented by the selected authority bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityPromotionError {
    /// The bridge does not implement the identity's method.
    UnsupportedMethod,
    /// The witness's fields do not satisfy the bridge's canonical relationship.
    InvalidIdentity,
    /// The authority model rejected a preserved field.
    InvalidAuthorityField,
}

impl From<ModelError> for IdentityPromotionError {
    fn from(_: ModelError) -> Self {
        Self::InvalidAuthorityField
    }
}

impl fmt::Display for IdentityPromotionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedMethod => "identity method is not supported by this authority bridge",
            Self::InvalidIdentity => "validated identity does not satisfy the bridge contract",
            Self::InvalidAuthorityField => "validated identity cannot be represented by authority",
        })
    }
}

impl core::error::Error for IdentityPromotionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_identity::{IdentityError, IdentityMethod, PublicIdentity};
    use auths_identity_raw_key::RawKeyIdentityMethod;

    struct PermissiveRawKeyMethod;

    impl IdentityMethod for PermissiveRawKeyMethod {
        fn method_id(&self) -> &str {
            RAW_KEY_V2
        }

        fn validate(&self, _: &PublicIdentity) -> Result<(), IdentityError> {
            Ok(())
        }
    }

    #[test]
    fn bridge_rechecks_even_a_caller_selected_validation_method() {
        let identity = PublicIdentity::new(
            RAW_KEY_V2,
            "key:sha256-v2:not-the-key",
            "external-suite-v1",
            vec![7; 128],
        )
        .unwrap()
        .validate(&PermissiveRawKeyMethod)
        .unwrap();
        assert_eq!(
            RawKeyV2AuthorityBridge.promote(&identity),
            Err(IdentityPromotionError::InvalidIdentity)
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
    }
}
