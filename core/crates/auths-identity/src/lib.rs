//! Transport-, identity-method-, and signature-suite-independent identities.
//!
//! This crate owns bounded canonical identity packets and extension interfaces.
//! Concrete identity methods and cryptographic suites live in separate adapters.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::fmt;

/// First supported Auths identity product-protocol compatibility family.
pub const IDENTITY_PROTOCOL_V1: &str = "auths-identity/v1";
/// Stable semantic model carried by the first product-protocol family.
pub const IDENTITY_MODEL_VERSION: u16 = 1;
/// Canonical compact wire revision selected by `auths-identity/v1`.
///
/// Wire revision 1 was experimental and unpublished. Product protocol V1 deliberately freezes
/// the corrected revision 2 bytes rather than renumbering them during release hardening.
pub const IDENTITY_WIRE_VERSION: u8 = 2;
/// Signing-preimage revision selected by `auths-identity/v1`.
pub const IDENTITY_SIGNING_DOMAIN_VERSION: u8 = 2;
/// Registered application-protocol label used by the reference identity/Iroh composition.
///
/// Generic identity interoperability does not require Iroh or this label; callers using another
/// transport select an application protocol appropriate to that transport.
pub const IDENTITY_APPLICATION_PROTOCOL_V1: &str = "/auths/identity/1";
/// Exact canonical packet prefix for identity wire revision 2.
pub const IDENTITY_WIRE_MAGIC_V2: &[u8] = b"AUTHS-IDENTITY\0\x02";
/// Exact domain prefix for identity-message signing revision 2.
pub const IDENTITY_SIGNING_DOMAIN_V2: &[u8] = b"AUTHS-IDENTITY-MESSAGE\0\x02";
/// Canonical prefix for the credential-shape-agnostic descriptor packet.
pub const IDENTITY_DESCRIPTOR_WIRE_MAGIC_V1: &[u8] = b"AUTHS-IDENTITY-DESCRIPTOR\0\x01";
/// Domain prefix for exact application messages signed through one descriptor relationship.
pub const IDENTITY_DESCRIPTOR_SIGNING_DOMAIN_V1: &[u8] = b"AUTHS-IDENTITY-DESCRIPTOR-MESSAGE\0\x01";

pub const MAX_METHOD_ID_BYTES: usize = 128;
pub const MAX_SUITE_ID_BYTES: usize = 128;
pub const MAX_IDENTITY_ID_BYTES: usize = 512;
pub const MAX_PUBLIC_KEY_BYTES: usize = 128 * 1024;
pub const MAX_METHOD_MATERIAL_BYTES: usize = 128 * 1024;
pub const MAX_VERIFICATION_MATERIAL_BYTES: usize = MAX_PUBLIC_KEY_BYTES;
pub const MAX_RELATIONSHIPS: usize = 16;
pub const MAX_MATERIALS_PER_RELATIONSHIP: usize = 16;
pub const MAX_RELATIONSHIP_ID_BYTES: usize = 128;
pub const MAX_PURPOSE_ID_BYTES: usize = 128;
pub const MAX_SIGNATURE_BYTES: usize = 128 * 1024;
pub const MAX_IDENTITY_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_IDENTITY_PACKET_BYTES: usize = WIRE_MAGIC.len()
    + 1
    + 2
    + MAX_METHOD_ID_BYTES
    + 2
    + MAX_IDENTITY_ID_BYTES
    + 2
    + MAX_SUITE_ID_BYTES
    + 4
    + MAX_PUBLIC_KEY_BYTES
    + 4
    + MAX_IDENTITY_MESSAGE_BYTES
    + 4
    + MAX_SIGNATURE_BYTES;
pub const MAX_IDENTITY_DESCRIPTOR_PACKET_BYTES: usize = IDENTITY_DESCRIPTOR_WIRE_MAGIC_V1.len()
    + 2
    + MAX_METHOD_ID_BYTES
    + 2
    + MAX_IDENTITY_ID_BYTES
    + 4
    + MAX_METHOD_MATERIAL_BYTES
    + 2
    + MAX_RELATIONSHIPS
        * (2 + MAX_RELATIONSHIP_ID_BYTES
            + 2
            + MAX_PURPOSE_ID_BYTES
            + 2
            + MAX_SUITE_ID_BYTES
            + 2
            + MAX_MATERIALS_PER_RELATIONSHIP * (2 + MAX_RELATIONSHIP_ID_BYTES + 4))
    + MAX_VERIFICATION_MATERIAL_BYTES;

const WIRE_MAGIC: &[u8] = IDENTITY_WIRE_MAGIC_V2;
const SIGNING_DOMAIN: &[u8] = IDENTITY_SIGNING_DOMAIN_V2;
const PUBLIC_IDENTITY_TAG: u8 = 1;
const SIGNED_MESSAGE_TAG: u8 = 2;

/// Method-owned identity data that does not assume an embedded key or credential shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityDescriptor {
    method_id: String,
    identity_id: String,
    method_material: Vec<u8>,
    relationships: Vec<VerificationRelationship>,
}

impl IdentityDescriptor {
    /// Constructs a bounded general identity descriptor.
    ///
    /// Method material may be empty, allowing methods whose stable identifier is sufficient or
    /// whose verification state is obtained through an explicit resolver.
    ///
    /// # Errors
    ///
    /// Rejects malformed identifiers, duplicate relationships, excessive counts, and excessive
    /// aggregate verification material.
    pub fn new(
        method_id: &str,
        identity_id: &str,
        method_material: Vec<u8>,
        relationships: Vec<VerificationRelationship>,
    ) -> Result<Self, IdentityError> {
        validate_identifier(method_id, MAX_METHOD_ID_BYTES)?;
        validate_identifier(identity_id, MAX_IDENTITY_ID_BYTES)?;
        if method_material.len() > MAX_METHOD_MATERIAL_BYTES
            || relationships.len() > MAX_RELATIONSHIPS
        {
            return Err(IdentityError::Limit);
        }
        let mut total_material = 0_usize;
        for (index, relationship) in relationships.iter().enumerate() {
            if relationships[..index]
                .iter()
                .any(|prior| prior.relationship_id == relationship.relationship_id)
            {
                return Err(IdentityError::InvalidIdentity);
            }
            for material in &relationship.verification_material {
                total_material = total_material
                    .checked_add(material.bytes.len())
                    .ok_or(IdentityError::Limit)?;
            }
        }
        if total_material > MAX_VERIFICATION_MATERIAL_BYTES {
            return Err(IdentityError::Limit);
        }
        Ok(Self {
            method_id: method_id.into(),
            identity_id: identity_id.into(),
            method_material,
            relationships,
        })
    }

    /// Returns the identity method selected by the descriptor.
    #[must_use]
    pub fn method_id(&self) -> &str {
        &self.method_id
    }

    /// Returns the stable identity identifier, independent of current keys.
    #[must_use]
    pub fn identity_id(&self) -> &str {
        &self.identity_id
    }

    /// Returns bounded opaque bytes interpreted only by the identity method.
    #[must_use]
    pub fn method_material(&self) -> &[u8] {
        &self.method_material
    }

    /// Returns the descriptor's explicit verification relationships.
    #[must_use]
    pub fn relationships(&self) -> &[VerificationRelationship] {
        &self.relationships
    }

    /// Returns a relationship by its stable local identifier.
    #[must_use]
    pub fn relationship(&self, relationship_id: &str) -> Option<&VerificationRelationship> {
        self.relationships
            .iter()
            .find(|relationship| relationship.relationship_id == relationship_id)
    }

    /// Encodes the complete method-owned descriptor into canonical transport-independent bytes.
    ///
    /// # Errors
    ///
    /// Rejects a descriptor whose aggregate canonical representation exceeds the protocol bound.
    pub fn encode(&self) -> Result<Vec<u8>, IdentityError> {
        let mut output = Vec::new();
        output.extend_from_slice(IDENTITY_DESCRIPTOR_WIRE_MAGIC_V1);
        encode_text(&mut output, &self.method_id)?;
        encode_text(&mut output, &self.identity_id)?;
        encode_bytes(&mut output, &self.method_material)?;
        encode_count(&mut output, self.relationships.len())?;
        for relationship in &self.relationships {
            encode_text(&mut output, relationship.relationship_id())?;
            encode_text(&mut output, relationship.purpose())?;
            encode_text(&mut output, relationship.suite_id())?;
            encode_count(&mut output, relationship.verification_material().len())?;
            for material in relationship.verification_material() {
                encode_text(&mut output, material.material_id())?;
                encode_bytes(&mut output, material.bytes())?;
            }
        }
        if output.len() > MAX_IDENTITY_DESCRIPTOR_PACKET_BYTES {
            return Err(IdentityError::Limit);
        }
        Ok(output)
    }

    /// Decodes one complete canonical credential-shape-agnostic descriptor.
    ///
    /// # Errors
    ///
    /// Rejects malformed, non-canonical, duplicate, trailing, or excessive input.
    pub fn decode(input: &[u8]) -> Result<Self, IdentityError> {
        if input.len() > MAX_IDENTITY_DESCRIPTOR_PACKET_BYTES
            || !input.starts_with(IDENTITY_DESCRIPTOR_WIRE_MAGIC_V1)
        {
            return Err(IdentityError::Codec);
        }
        let mut cursor = IDENTITY_DESCRIPTOR_WIRE_MAGIC_V1.len();
        let method_id = decode_text(input, &mut cursor, MAX_METHOD_ID_BYTES)?;
        let identity_id = decode_text(input, &mut cursor, MAX_IDENTITY_ID_BYTES)?;
        let method_material =
            decode_optional_bytes(input, &mut cursor, MAX_METHOD_MATERIAL_BYTES)?.to_vec();
        let relationship_count = decode_count(input, &mut cursor, MAX_RELATIONSHIPS)?;
        let mut relationships = Vec::with_capacity(relationship_count);
        for _ in 0..relationship_count {
            let relationship_id = decode_text(input, &mut cursor, MAX_RELATIONSHIP_ID_BYTES)?;
            let purpose = decode_text(input, &mut cursor, MAX_PURPOSE_ID_BYTES)?;
            let suite_id = decode_text(input, &mut cursor, MAX_SUITE_ID_BYTES)?;
            let material_count = decode_count(input, &mut cursor, MAX_MATERIALS_PER_RELATIONSHIP)?;
            let mut materials = Vec::with_capacity(material_count);
            for _ in 0..material_count {
                let material_id = decode_text(input, &mut cursor, MAX_RELATIONSHIP_ID_BYTES)?;
                let bytes =
                    decode_bytes(input, &mut cursor, MAX_VERIFICATION_MATERIAL_BYTES)?.to_vec();
                materials.push(VerificationMaterial::new(material_id, bytes)?);
            }
            relationships.push(VerificationRelationship::new(
                relationship_id,
                purpose,
                suite_id,
                materials,
            )?);
        }
        if cursor != input.len() {
            return Err(IdentityError::Codec);
        }
        let descriptor = Self::new(method_id, identity_id, method_material, relationships)?;
        if descriptor.encode()?.as_slice() != input {
            return Err(IdentityError::Codec);
        }
        Ok(descriptor)
    }

    /// Returns exact domain-separated bytes for one relationship and application message.
    ///
    /// # Errors
    ///
    /// Rejects an unknown relationship or invalid message bound.
    pub fn signing_preimage(
        &self,
        relationship_id: &str,
        message: &[u8],
    ) -> Result<Vec<u8>, IdentityError> {
        validate_message(message)?;
        if self.relationship(relationship_id).is_none() {
            return Err(IdentityError::InvalidVerificationMaterial);
        }
        let descriptor = self.encode()?;
        let mut output = Vec::with_capacity(
            IDENTITY_DESCRIPTOR_SIGNING_DOMAIN_V1.len()
                + 4
                + descriptor.len()
                + 2
                + relationship_id.len()
                + 4
                + message.len(),
        );
        output.extend_from_slice(IDENTITY_DESCRIPTOR_SIGNING_DOMAIN_V1);
        encode_bytes(&mut output, &descriptor)?;
        encode_text(&mut output, relationship_id)?;
        encode_bytes(&mut output, message)?;
        Ok(output)
    }

    /// Promotes the descriptor into method-validated general identity state.
    ///
    /// # Errors
    ///
    /// Rejects a mismatched method or method-specific validation failure.
    pub fn validate<M: IdentityDescriptorMethod + ?Sized>(
        &self,
        method: &M,
    ) -> Result<ValidatedIdentityDescriptor, IdentityError> {
        if method.method_id() != self.method_id {
            return Err(IdentityError::UnsupportedIdentityMethod);
        }
        method.validate(self)?;
        Ok(ValidatedIdentityDescriptor {
            descriptor: self.clone(),
        })
    }
}

/// One explicit purpose- and suite-labelled verification relationship.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationRelationship {
    relationship_id: String,
    purpose: String,
    suite_id: String,
    verification_material: Vec<VerificationMaterial>,
}

impl VerificationRelationship {
    /// Constructs a relationship containing one or more separately labelled material objects.
    ///
    /// # Errors
    ///
    /// Rejects malformed identifiers, empty or excessive material sets, and duplicate material
    /// identifiers.
    pub fn new(
        relationship_id: &str,
        purpose: &str,
        suite_id: &str,
        verification_material: Vec<VerificationMaterial>,
    ) -> Result<Self, IdentityError> {
        validate_identifier(relationship_id, MAX_RELATIONSHIP_ID_BYTES)?;
        validate_identifier(purpose, MAX_PURPOSE_ID_BYTES)?;
        validate_identifier(suite_id, MAX_SUITE_ID_BYTES)?;
        if verification_material.is_empty()
            || verification_material.len() > MAX_MATERIALS_PER_RELATIONSHIP
        {
            return Err(IdentityError::InvalidVerificationMaterial);
        }
        for (index, material) in verification_material.iter().enumerate() {
            if verification_material[..index]
                .iter()
                .any(|prior| prior.material_id == material.material_id)
            {
                return Err(IdentityError::InvalidVerificationMaterial);
            }
        }
        Ok(Self {
            relationship_id: relationship_id.into(),
            purpose: purpose.into(),
            suite_id: suite_id.into(),
            verification_material,
        })
    }

    #[must_use]
    pub fn relationship_id(&self) -> &str {
        &self.relationship_id
    }

    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    #[must_use]
    pub fn suite_id(&self) -> &str {
        &self.suite_id
    }

    #[must_use]
    pub fn verification_material(&self) -> &[VerificationMaterial] {
        &self.verification_material
    }
}

/// One separately labelled opaque input to a signature suite.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationMaterial {
    material_id: String,
    bytes: Vec<u8>,
}

impl VerificationMaterial {
    /// Constructs one bounded non-empty verification-material object.
    ///
    /// # Errors
    ///
    /// Rejects malformed identifiers and empty or oversized material.
    pub fn new(material_id: &str, bytes: Vec<u8>) -> Result<Self, IdentityError> {
        validate_identifier(material_id, MAX_RELATIONSHIP_ID_BYTES)?;
        if bytes.is_empty() || bytes.len() > MAX_VERIFICATION_MATERIAL_BYTES {
            return Err(IdentityError::InvalidVerificationMaterial);
        }
        Ok(Self {
            material_id: material_id.into(),
            bytes,
        })
    }

    #[must_use]
    pub fn material_id(&self) -> &str {
        &self.material_id
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Replaceable validator for a general, method-owned identity descriptor.
pub trait IdentityDescriptorMethod {
    fn method_id(&self) -> &str;
    /// Validates stable identity, method material, and relationship semantics.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for an invalid or unsupported descriptor.
    fn validate(&self, descriptor: &IdentityDescriptor) -> Result<(), IdentityError>;
}

/// A general descriptor whose method-specific relationships have been validated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedIdentityDescriptor {
    descriptor: IdentityDescriptor,
}

impl ValidatedIdentityDescriptor {
    /// Returns the validated general descriptor.
    #[must_use]
    pub const fn as_descriptor(&self) -> &IdentityDescriptor {
        &self.descriptor
    }

    /// Consumes the witness and returns the structural descriptor.
    #[must_use]
    pub fn into_descriptor(self) -> IdentityDescriptor {
        self.descriptor
    }
}

/// Algorithm-neutral public identity and verification key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicIdentity {
    method_id: String,
    identity_id: String,
    suite_id: String,
    public_key: Vec<u8>,
}

impl PublicIdentity {
    /// Constructs a structurally valid identity without choosing its method or
    /// cryptographic implementation.
    ///
    /// # Errors
    ///
    /// Rejects empty, control-bearing, oversized, or empty-key fields.
    pub fn new(
        method_id: &str,
        identity_id: &str,
        suite_id: &str,
        public_key: Vec<u8>,
    ) -> Result<Self, IdentityError> {
        validate_identifier(method_id, MAX_METHOD_ID_BYTES)?;
        validate_identifier(identity_id, MAX_IDENTITY_ID_BYTES)?;
        validate_identifier(suite_id, MAX_SUITE_ID_BYTES)?;
        if public_key.is_empty() || public_key.len() > MAX_PUBLIC_KEY_BYTES {
            return Err(IdentityError::InvalidPublicKey);
        }
        Ok(Self {
            method_id: method_id.into(),
            identity_id: identity_id.into(),
            suite_id: suite_id.into(),
            public_key,
        })
    }

    #[must_use]
    pub fn method_id(&self) -> &str {
        &self.method_id
    }

    #[must_use]
    pub fn identity_id(&self) -> &str {
        &self.identity_id
    }

    #[must_use]
    pub fn suite_id(&self) -> &str {
        &self.suite_id
    }

    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Expands the compact V2 single-key profile into the general descriptor model.
    ///
    /// # Errors
    ///
    /// Returns a typed error only if the already-bounded compact fields cannot satisfy the
    /// general model's stricter relationship construction.
    pub fn to_descriptor(&self) -> Result<IdentityDescriptor, IdentityError> {
        IdentityDescriptor::new(
            &self.method_id,
            &self.identity_id,
            Vec::new(),
            alloc::vec![VerificationRelationship::new(
                "default-signing",
                "authentication",
                &self.suite_id,
                alloc::vec![VerificationMaterial::new(
                    "default-key",
                    self.public_key.clone(),
                )?],
            )?],
        )
    }

    /// Promotes this structural descriptor into a method-validated identity.
    ///
    /// # Errors
    ///
    /// Rejects a mismatched method or method-specific validation failure.
    pub fn validate<M: IdentityMethod + ?Sized>(
        &self,
        method: &M,
    ) -> Result<ValidatedIdentity, IdentityError> {
        if method.method_id() != self.method_id {
            return Err(IdentityError::UnsupportedIdentityMethod);
        }
        method.validate(self)?;
        Ok(ValidatedIdentity {
            identity: self.clone(),
        })
    }

    fn encode_descriptor(&self) -> Result<Vec<u8>, IdentityError> {
        let mut output = Vec::new();
        encode_text(&mut output, &self.method_id)?;
        encode_text(&mut output, &self.identity_id)?;
        encode_text(&mut output, &self.suite_id)?;
        encode_bytes(&mut output, &self.public_key)?;
        Ok(output)
    }
}

/// A public identity whose method-specific identifier and material relationship
/// has been validated.
///
/// This wrapper cannot be constructed directly. Canonical decoding produces a
/// structural [`PublicIdentity`]; callers must explicitly promote it through
/// [`PublicIdentity::validate`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedIdentity {
    identity: PublicIdentity,
}

impl ValidatedIdentity {
    /// Returns the structural identity whose relationship was validated.
    #[must_use]
    pub const fn as_public_identity(&self) -> &PublicIdentity {
        &self.identity
    }

    /// Returns the validated identity method identifier.
    #[must_use]
    pub fn method_id(&self) -> &str {
        self.identity.method_id()
    }

    /// Returns the validated stable identity identifier.
    #[must_use]
    pub fn identity_id(&self) -> &str {
        self.identity.identity_id()
    }

    /// Returns the validated signature-suite identifier.
    #[must_use]
    pub fn suite_id(&self) -> &str {
        self.identity.suite_id()
    }

    /// Returns the validated public verification material.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        self.identity.public_key()
    }

    /// Consumes the validation witness and returns its structural identity.
    #[must_use]
    pub fn into_public_identity(self) -> PublicIdentity {
        self.identity
    }
}

/// Replaceable identity-method implementation such as raw key, DID, or X.509.
pub trait IdentityMethod {
    fn method_id(&self) -> &str;
    /// Validates the method-specific identity relationship.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for an invalid or unsupported identity.
    fn validate(&self, identity: &PublicIdentity) -> Result<(), IdentityError>;
}

/// Replaceable signature-suite implementation.
pub trait SignatureVerifier {
    fn suite_id(&self) -> &str;
    /// Verifies one exact signing preimage using suite-specific bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed key, signature, suite, or verification failure.
    fn verify(
        &self,
        public_key: &[u8],
        signing_preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), IdentityError>;
}

/// One exact message signed by a public identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedIdentityMessage {
    identity: PublicIdentity,
    message: Vec<u8>,
    signature: Vec<u8>,
}

impl SignedIdentityMessage {
    /// Constructs an unverified bounded signed-message carrier.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized message or signature.
    pub fn new(
        identity: PublicIdentity,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<Self, IdentityError> {
        validate_message(&message)?;
        if signature.is_empty() || signature.len() > MAX_SIGNATURE_BYTES {
            return Err(IdentityError::InvalidSignature);
        }
        Ok(Self {
            identity,
            message,
            signature,
        })
    }

    /// Constructs the exact domain-separated bytes for external custody.
    ///
    /// # Errors
    ///
    /// Rejects invalid identity fields or an invalid message bound.
    pub fn signing_preimage(
        identity: &PublicIdentity,
        message: &[u8],
    ) -> Result<Vec<u8>, IdentityError> {
        validate_message(message)?;
        let descriptor = identity.encode_descriptor()?;
        let mut output =
            Vec::with_capacity(SIGNING_DOMAIN.len() + 4 + descriptor.len() + 4 + message.len());
        output.extend_from_slice(SIGNING_DOMAIN);
        encode_bytes(&mut output, &descriptor)?;
        encode_bytes(&mut output, message)?;
        Ok(output)
    }

    /// Validates both the identity method and signature using caller-selected
    /// implementations. Success authenticates bytes; it does not authorize.
    ///
    /// # Errors
    ///
    /// Rejects method or suite mismatches and failed validation or verification.
    pub fn verify<M, S>(
        &self,
        method: &M,
        suite: &S,
    ) -> Result<AuthenticatedIdentityMessage, IdentityError>
    where
        M: IdentityMethod + ?Sized,
        S: SignatureVerifier + ?Sized,
    {
        let identity = self.identity.validate(method)?;
        if suite.suite_id() != self.identity.suite_id {
            return Err(IdentityError::UnsupportedSignatureSuite);
        }
        let preimage = Self::signing_preimage(&self.identity, &self.message)?;
        suite.verify(&self.identity.public_key, &preimage, &self.signature)?;
        Ok(AuthenticatedIdentityMessage {
            signed: self.clone(),
            identity,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> &PublicIdentity {
        &self.identity
    }

    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// An exact message authenticated to a method-validated public identity.
///
/// Construction is private so neither decoding nor application code can mint
/// authentication without running both method and signature verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedIdentityMessage {
    signed: SignedIdentityMessage,
    identity: ValidatedIdentity,
}

impl AuthenticatedIdentityMessage {
    /// Returns the validated identity that authenticated the message.
    #[must_use]
    pub const fn identity(&self) -> &ValidatedIdentity {
        &self.identity
    }

    /// Returns the exact authenticated application bytes.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        self.signed.message()
    }

    /// Returns the verified signature bytes.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        self.signed.signature()
    }

    /// Consumes the witness and returns the structurally signed carrier.
    #[must_use]
    pub fn into_signed_message(self) -> SignedIdentityMessage {
        self.signed
    }
}

/// Closed packet shapes with open identity-method and signature-suite fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityPacket {
    PublicIdentity(PublicIdentity),
    SignedMessage(SignedIdentityMessage),
}

impl IdentityPacket {
    #[must_use]
    pub const fn identity(&self) -> &PublicIdentity {
        match self {
            Self::PublicIdentity(identity) => identity,
            Self::SignedMessage(message) => message.identity(),
        }
    }

    /// Encodes canonical transport-independent bytes.
    ///
    /// # Errors
    ///
    /// Rejects fields or packets outside the declared resource bounds.
    pub fn encode(&self) -> Result<Vec<u8>, IdentityError> {
        let descriptor = self.identity().encode_descriptor()?;
        let mut output = Vec::new();
        output.extend_from_slice(WIRE_MAGIC);
        output.push(match self {
            Self::PublicIdentity(_) => PUBLIC_IDENTITY_TAG,
            Self::SignedMessage(_) => SIGNED_MESSAGE_TAG,
        });
        encode_bytes(&mut output, &descriptor)?;
        if let Self::SignedMessage(message) = self {
            encode_bytes(&mut output, message.message())?;
            encode_bytes(&mut output, message.signature())?;
        }
        if output.len() > MAX_IDENTITY_PACKET_BYTES {
            return Err(IdentityError::Limit);
        }
        Ok(output)
    }

    /// Decodes one complete canonical packet.
    ///
    /// # Errors
    ///
    /// Rejects malformed, non-canonical, unknown, trailing, or oversized input.
    pub fn decode(input: &[u8]) -> Result<Self, IdentityError> {
        if input.len() > MAX_IDENTITY_PACKET_BYTES || !input.starts_with(WIRE_MAGIC) {
            return Err(IdentityError::Codec);
        }
        let mut cursor = WIRE_MAGIC.len();
        let tag = take(input, &mut cursor, 1)?[0];
        let descriptor = decode_bytes(input, &mut cursor, descriptor_maximum())?;
        let identity = decode_descriptor(descriptor)?;
        let packet = match tag {
            PUBLIC_IDENTITY_TAG => Self::PublicIdentity(identity),
            SIGNED_MESSAGE_TAG => {
                let message =
                    decode_bytes(input, &mut cursor, MAX_IDENTITY_MESSAGE_BYTES)?.to_vec();
                let signature = decode_bytes(input, &mut cursor, MAX_SIGNATURE_BYTES)?.to_vec();
                Self::SignedMessage(SignedIdentityMessage::new(identity, message, signature)?)
            }
            _ => return Err(IdentityError::Protocol),
        };
        if cursor != input.len() || packet.encode()?.as_slice() != input {
            return Err(IdentityError::Codec);
        }
        Ok(packet)
    }
}

fn decode_descriptor(input: &[u8]) -> Result<PublicIdentity, IdentityError> {
    let mut cursor = 0;
    let method = decode_text(input, &mut cursor, MAX_METHOD_ID_BYTES)?;
    let identity = decode_text(input, &mut cursor, MAX_IDENTITY_ID_BYTES)?;
    let suite = decode_text(input, &mut cursor, MAX_SUITE_ID_BYTES)?;
    let key = decode_bytes(input, &mut cursor, MAX_PUBLIC_KEY_BYTES)?.to_vec();
    if cursor != input.len() {
        return Err(IdentityError::Codec);
    }
    PublicIdentity::new(method, identity, suite, key)
}

const fn descriptor_maximum() -> usize {
    2 + MAX_METHOD_ID_BYTES
        + 2
        + MAX_IDENTITY_ID_BYTES
        + 2
        + MAX_SUITE_ID_BYTES
        + 4
        + MAX_PUBLIC_KEY_BYTES
}

fn validate_identifier(value: &str, maximum: usize) -> Result<(), IdentityError> {
    if value.is_empty()
        || value.len() > maximum
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(IdentityError::InvalidIdentity);
    }
    Ok(())
}

fn validate_message(message: &[u8]) -> Result<(), IdentityError> {
    if message.is_empty() || message.len() > MAX_IDENTITY_MESSAGE_BYTES {
        return Err(IdentityError::InvalidMessage);
    }
    Ok(())
}

fn encode_text(output: &mut Vec<u8>, value: &str) -> Result<(), IdentityError> {
    let length = u16::try_from(value.len()).map_err(|_| IdentityError::Limit)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn encode_count(output: &mut Vec<u8>, value: usize) -> Result<(), IdentityError> {
    let value = u16::try_from(value).map_err(|_| IdentityError::Limit)?;
    output.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn encode_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), IdentityError> {
    let length = u32::try_from(value.len()).map_err(|_| IdentityError::Limit)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn decode_text<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    maximum: usize,
) -> Result<&'a str, IdentityError> {
    let length = usize::from(u16::from_be_bytes(
        take(input, cursor, 2)?
            .try_into()
            .map_err(|_| IdentityError::Codec)?,
    ));
    if length == 0 || length > maximum {
        return Err(IdentityError::Limit);
    }
    core::str::from_utf8(take(input, cursor, length)?).map_err(|_| IdentityError::Codec)
}

fn decode_count(input: &[u8], cursor: &mut usize, maximum: usize) -> Result<usize, IdentityError> {
    let count = usize::from(u16::from_be_bytes(
        take(input, cursor, 2)?
            .try_into()
            .map_err(|_| IdentityError::Codec)?,
    ));
    if count > maximum {
        return Err(IdentityError::Limit);
    }
    Ok(count)
}

fn decode_bytes<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    maximum: usize,
) -> Result<&'a [u8], IdentityError> {
    let length = usize::try_from(u32::from_be_bytes(
        take(input, cursor, 4)?
            .try_into()
            .map_err(|_| IdentityError::Codec)?,
    ))
    .map_err(|_| IdentityError::Limit)?;
    if length == 0 || length > maximum {
        return Err(IdentityError::Limit);
    }
    take(input, cursor, length)
}

fn decode_optional_bytes<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    maximum: usize,
) -> Result<&'a [u8], IdentityError> {
    let length = usize::try_from(u32::from_be_bytes(
        take(input, cursor, 4)?
            .try_into()
            .map_err(|_| IdentityError::Codec)?,
    ))
    .map_err(|_| IdentityError::Limit)?;
    if length > maximum {
        return Err(IdentityError::Limit);
    }
    take(input, cursor, length)
}

fn take<'a>(input: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], IdentityError> {
    let end = cursor.checked_add(length).ok_or(IdentityError::Limit)?;
    let value = input.get(*cursor..end).ok_or(IdentityError::Codec)?;
    *cursor = end;
    Ok(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    InvalidIdentity,
    InvalidPublicKey,
    InvalidVerificationMaterial,
    InvalidMessage,
    InvalidSignature,
    UnsupportedIdentityMethod,
    UnsupportedSignatureSuite,
    VerificationFailed,
    Codec,
    Limit,
    Protocol,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentity => "invalid public identity",
            Self::InvalidPublicKey => "invalid public verification key",
            Self::InvalidVerificationMaterial => "invalid identity verification material",
            Self::InvalidMessage => "invalid identity message length",
            Self::InvalidSignature => "invalid identity signature encoding",
            Self::UnsupportedIdentityMethod => "unsupported identity method",
            Self::UnsupportedSignatureSuite => "unsupported signature suite",
            Self::VerificationFailed => "identity signature verification failed",
            Self::Codec => "invalid canonical identity message",
            Self::Limit => "identity message resource limit exceeded",
            Self::Protocol => "unsupported identity protocol",
        })
    }
}

impl core::error::Error for IdentityError {}

#[cfg(test)]
mod tests {
    use super::*;

    struct AnyMethod;
    impl IdentityMethod for AnyMethod {
        fn method_id(&self) -> &'static str {
            "example-method-v1"
        }
        fn validate(&self, identity: &PublicIdentity) -> Result<(), IdentityError> {
            (identity.identity_id() == "example:alice")
                .then_some(())
                .ok_or(IdentityError::InvalidIdentity)
        }
    }

    struct VariableLengthSuite;
    impl SignatureVerifier for VariableLengthSuite {
        fn suite_id(&self) -> &'static str {
            "example-pq-v1"
        }
        fn verify(
            &self,
            key: &[u8],
            preimage: &[u8],
            signature: &[u8],
        ) -> Result<(), IdentityError> {
            (key.len() == 4096 && signature == preimage.get(..96).unwrap_or(preimage))
                .then_some(())
                .ok_or(IdentityError::VerificationFailed)
        }
    }

    struct GeneralMethod;

    impl IdentityDescriptorMethod for GeneralMethod {
        fn method_id(&self) -> &'static str {
            "example-method-v2"
        }

        fn validate(&self, descriptor: &IdentityDescriptor) -> Result<(), IdentityError> {
            descriptor
                .identity_id()
                .starts_with("example:")
                .then_some(())
                .ok_or(IdentityError::InvalidIdentity)
        }
    }

    #[test]
    fn variable_length_third_party_methods_and_suites_require_no_core_changes() {
        let identity = PublicIdentity::new(
            "example-method-v1",
            "example:alice",
            "example-pq-v1",
            alloc::vec![7; 4096],
        )
        .unwrap();
        let message = b"algorithm neutral";
        let preimage = SignedIdentityMessage::signing_preimage(&identity, message).unwrap();
        let signed =
            SignedIdentityMessage::new(identity, message.to_vec(), preimage[..96].to_vec())
                .unwrap();
        let authenticated = signed.verify(&AnyMethod, &VariableLengthSuite).unwrap();
        assert_eq!(authenticated.identity().identity_id(), "example:alice");
        assert_eq!(authenticated.message(), message);
        let packet = IdentityPacket::SignedMessage(signed);
        assert_eq!(
            IdentityPacket::decode(&packet.encode().unwrap()).unwrap(),
            packet
        );
    }

    #[test]
    fn unknown_method_or_suite_fails_closed() {
        let identity = PublicIdentity::new(
            "other-method-v1",
            "example:alice",
            "example-pq-v1",
            alloc::vec![7; 32],
        )
        .unwrap();
        assert_eq!(
            identity.validate(&AnyMethod),
            Err(IdentityError::UnsupportedIdentityMethod)
        );
    }

    #[test]
    fn canonical_decoding_does_not_mint_method_validation() {
        let forged = PublicIdentity::new(
            "example-method-v1",
            "example:mallory",
            "example-pq-v1",
            alloc::vec![7; 4096],
        )
        .unwrap();
        let encoded = IdentityPacket::PublicIdentity(forged).encode().unwrap();
        let decoded = IdentityPacket::decode(&encoded).unwrap();
        assert_eq!(
            decoded.identity().validate(&AnyMethod),
            Err(IdentityError::InvalidIdentity)
        );
    }

    #[test]
    fn compact_single_key_profile_expands_concisely() {
        let compact = PublicIdentity::new(
            "example-method-v1",
            "example:alice",
            "ed25519-v1",
            alloc::vec![7; 32],
        )
        .unwrap();
        let descriptor = compact.to_descriptor().unwrap();
        let relationship = descriptor.relationship("default-signing").unwrap();
        assert_eq!(descriptor.identity_id(), "example:alice");
        assert_eq!(relationship.purpose(), "authentication");
        assert_eq!(relationship.verification_material().len(), 1);
        assert_eq!(relationship.verification_material()[0].bytes(), &[7; 32]);
    }

    #[test]
    fn key_rotation_preserves_the_stable_identity() {
        let relationship = |key_byte| {
            VerificationRelationship::new(
                "current-signing-key",
                "authentication",
                "ed25519-v1",
                alloc::vec![
                    VerificationMaterial::new("rotating-key", alloc::vec![key_byte; 32],).unwrap()
                ],
            )
            .unwrap()
        };
        let before = IdentityDescriptor::new(
            "example-method-v2",
            "example:stable-alice",
            Vec::new(),
            alloc::vec![relationship(1)],
        )
        .unwrap();
        let after = IdentityDescriptor::new(
            "example-method-v2",
            "example:stable-alice",
            Vec::new(),
            alloc::vec![relationship(2)],
        )
        .unwrap();
        assert_eq!(before.identity_id(), after.identity_id());
        assert_ne!(before.relationships(), after.relationships());
    }

    #[test]
    fn hybrid_and_resolver_shapes_need_no_private_concatenation() {
        let hybrid = VerificationRelationship::new(
            "hybrid-signing",
            "authentication",
            "example-hybrid-v1",
            alloc::vec![
                VerificationMaterial::new("classical", alloc::vec![3; 32]).unwrap(),
                VerificationMaterial::new("post-quantum", alloc::vec![4; 2048]).unwrap(),
            ],
        )
        .unwrap();
        let hybrid_identity = IdentityDescriptor::new(
            "example-method-v2",
            "example:hybrid",
            Vec::new(),
            alloc::vec![hybrid],
        )
        .unwrap();
        assert_eq!(
            hybrid_identity.relationships()[0].verification_material()[1].material_id(),
            "post-quantum"
        );

        let resolver_identity = IdentityDescriptor::new(
            "example-method-v2",
            "example:resolver-backed",
            b"https://resolver.example/identities/alice".to_vec(),
            Vec::new(),
        )
        .unwrap();
        let validated = resolver_identity.validate(&GeneralMethod).unwrap();
        assert!(validated.as_descriptor().relationships().is_empty());
        assert_eq!(
            validated.as_descriptor().method_material(),
            b"https://resolver.example/identities/alice"
        );
    }

    #[test]
    fn general_descriptors_round_trip_and_bind_relationship_messages() {
        let descriptor = IdentityDescriptor::new(
            "example-method-v2",
            "example:hybrid",
            b"resolver:example".to_vec(),
            alloc::vec![
                VerificationRelationship::new(
                    "hybrid-signing",
                    "authentication",
                    "example-hybrid-v1",
                    alloc::vec![
                        VerificationMaterial::new("classical", alloc::vec![3; 32]).unwrap(),
                        VerificationMaterial::new("post-quantum", alloc::vec![4; 2048]).unwrap(),
                    ],
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let encoded = descriptor.encode().unwrap();
        assert_eq!(IdentityDescriptor::decode(&encoded).unwrap(), descriptor);

        let preimage = descriptor
            .signing_preimage("hybrid-signing", b"exact message")
            .unwrap();
        let changed = descriptor
            .signing_preimage("hybrid-signing", b"changed message")
            .unwrap();
        assert_ne!(preimage, changed);
        assert_eq!(
            descriptor.signing_preimage("unknown", b"exact message"),
            Err(IdentityError::InvalidVerificationMaterial)
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            IdentityDescriptor::decode(&trailing),
            Err(IdentityError::Codec)
        );
    }
}
