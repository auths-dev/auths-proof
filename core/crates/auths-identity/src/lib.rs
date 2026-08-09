//! Transport-independent Ed25519 public identities and signed messages.
//!
//! This crate produces and verifies identity facts. It does not perform
//! networking and does not evaluate grants, capabilities, approvals, policy,
//! lifecycle state, or authorization.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use auths_model::PrincipalId;
use auths_ports::{SignatureInput, SignatureSuite as _};
use auths_raw_key::{RawKeyDescriptor, RawKeyType};
use auths_signature::Ed25519Suite;

/// Maximum application message accepted by the identity protocol.
pub const MAX_IDENTITY_MESSAGE_BYTES: usize = 64 * 1024;
/// Maximum encoded identity packet size.
pub const MAX_IDENTITY_PACKET_BYTES: usize =
    WIRE_MAGIC.len() + 1 + 2 + MAX_DESCRIPTOR_BYTES + 4 + MAX_IDENTITY_MESSAGE_BYTES + 64;

const WIRE_MAGIC: &[u8] = b"AUTHS-IDENTITY\0\x01";
const SIGNING_DOMAIN: &[u8] = b"AUTHS-IDENTITY-MESSAGE\0\x01";
const PUBLIC_IDENTITY_TAG: u8 = 1;
const SIGNED_MESSAGE_TAG: u8 = 2;
const ED25519_SIGNATURE_BYTES: usize = 64;
const MAX_DESCRIPTOR_BYTES: usize = 256;

/// Canonical self-certifying Ed25519 public identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicIdentity {
    descriptor: RawKeyDescriptor,
    principal: PrincipalId,
    public_key: [u8; 32],
}

impl PublicIdentity {
    /// Constructs an identity from an Ed25519 verification key.
    ///
    /// # Errors
    ///
    /// Returns a typed error if the canonical raw-key principal cannot be
    /// represented.
    pub fn from_ed25519(public_key: [u8; 32]) -> Result<Self, IdentityError> {
        let descriptor = RawKeyDescriptor::new(RawKeyType::Ed25519, public_key.to_vec())
            .map_err(|_| IdentityError::InvalidIdentity)?;
        Self::from_descriptor(descriptor)
    }

    fn from_descriptor(descriptor: RawKeyDescriptor) -> Result<Self, IdentityError> {
        if descriptor.suite() != auths_signature::ED25519_V1 || descriptor.public_key().len() != 32
        {
            return Err(IdentityError::InvalidIdentity);
        }
        let principal = descriptor
            .principal()
            .map_err(|_| IdentityError::InvalidIdentity)?;
        let public_key = descriptor
            .public_key()
            .try_into()
            .map_err(|_| IdentityError::InvalidIdentity)?;
        Ok(Self {
            descriptor,
            principal,
            public_key,
        })
    }

    /// Returns the self-certifying Auths principal identifier.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Returns the exact 32-byte Ed25519 verification key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    fn descriptor_bytes(&self) -> Vec<u8> {
        self.descriptor.encode()
    }
}

/// One exact message signed by an Ed25519 public identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedIdentityMessage {
    identity: PublicIdentity,
    message: Vec<u8>,
    signature: [u8; ED25519_SIGNATURE_BYTES],
}

impl SignedIdentityMessage {
    /// Constructs a bounded signed-message carrier.
    ///
    /// This constructor does not claim that the supplied signature is valid;
    /// call [`Self::verify`] at the trust boundary.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidMessage`] for an empty or oversized
    /// application message.
    pub fn new(
        identity: PublicIdentity,
        message: Vec<u8>,
        signature: [u8; ED25519_SIGNATURE_BYTES],
    ) -> Result<Self, IdentityError> {
        validate_message(&message)?;
        Ok(Self {
            identity,
            message,
            signature,
        })
    }

    /// Constructs the exact domain-separated bytes that custody must sign.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidMessage`] for an empty or oversized
    /// message.
    pub fn signing_preimage(
        identity: &PublicIdentity,
        message: &[u8],
    ) -> Result<Vec<u8>, IdentityError> {
        validate_message(message)?;
        let descriptor = identity.descriptor_bytes();
        let descriptor_length =
            u16::try_from(descriptor.len()).map_err(|_| IdentityError::InvalidIdentity)?;
        let message_length =
            u32::try_from(message.len()).map_err(|_| IdentityError::InvalidMessage)?;
        let mut output =
            Vec::with_capacity(SIGNING_DOMAIN.len() + 2 + descriptor.len() + 4 + message.len());
        output.extend_from_slice(SIGNING_DOMAIN);
        output.extend_from_slice(&descriptor_length.to_be_bytes());
        output.extend_from_slice(&descriptor);
        output.extend_from_slice(&message_length.to_be_bytes());
        output.extend_from_slice(message);
        Ok(output)
    }

    /// Verifies the exact message with the canonical Ed25519 suite.
    ///
    /// Success authenticates these bytes to this public identity. It does not
    /// authorize an action or provide freshness or replay protection.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::InvalidSignature`] when verification fails.
    pub fn verify(&self) -> Result<(), IdentityError> {
        let preimage = Self::signing_preimage(&self.identity, &self.message)?;
        let suite = Ed25519Suite::new().map_err(|_| IdentityError::InvalidSignature)?;
        suite
            .verify(SignatureInput {
                verification_key: self.identity.public_key(),
                signing_preimage: &preimage,
                signature: &self.signature,
            })
            .map_err(|_| IdentityError::InvalidSignature)
    }

    /// Returns the identity that signed the message.
    #[must_use]
    pub const fn identity(&self) -> &PublicIdentity {
        &self.identity
    }

    /// Returns the exact application message bytes.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Returns the Ed25519 signature bytes.
    #[must_use]
    pub const fn signature(&self) -> &[u8; ED25519_SIGNATURE_BYTES] {
        &self.signature
    }
}

/// Closed, transport-independent identity message family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityPacket {
    /// Carry a canonical public identity without an application signature.
    PublicIdentity(PublicIdentity),
    /// Carry one application message signed by its public identity.
    SignedMessage(SignedIdentityMessage),
}

impl IdentityPacket {
    /// Returns the public identity carried by either packet form.
    #[must_use]
    pub const fn identity(&self) -> &PublicIdentity {
        match self {
            Self::PublicIdentity(identity) => identity,
            Self::SignedMessage(message) => message.identity(),
        }
    }

    /// Encodes the packet into canonical, transport-independent bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed error when a field violates the protocol bounds.
    pub fn encode(&self) -> Result<Vec<u8>, IdentityError> {
        let descriptor = self.identity().descriptor_bytes();
        let descriptor_length =
            u16::try_from(descriptor.len()).map_err(|_| IdentityError::InvalidIdentity)?;
        let mut output = Vec::with_capacity(MAX_DESCRIPTOR_BYTES + 128);
        output.extend_from_slice(WIRE_MAGIC);
        output.push(match self {
            Self::PublicIdentity(_) => PUBLIC_IDENTITY_TAG,
            Self::SignedMessage(_) => SIGNED_MESSAGE_TAG,
        });
        output.extend_from_slice(&descriptor_length.to_be_bytes());
        output.extend_from_slice(&descriptor);
        if let Self::SignedMessage(message) = self {
            validate_message(message.message())?;
            let message_length = u32::try_from(message.message().len())
                .map_err(|_| IdentityError::InvalidMessage)?;
            output.extend_from_slice(&message_length.to_be_bytes());
            output.extend_from_slice(message.message());
            output.extend_from_slice(message.signature());
        }
        Ok(output)
    }

    /// Decodes one complete canonical identity packet.
    ///
    /// # Errors
    ///
    /// Rejects malformed, non-canonical, unknown-version, oversized, or
    /// trailing input.
    pub fn decode(input: &[u8]) -> Result<Self, IdentityError> {
        if !input.starts_with(WIRE_MAGIC) {
            return Err(IdentityError::Codec);
        }
        let mut cursor = WIRE_MAGIC.len();
        let tag = take(input, &mut cursor, 1)?[0];
        let descriptor_length = usize::from(u16::from_be_bytes(
            take(input, &mut cursor, 2)?
                .try_into()
                .map_err(|_| IdentityError::Codec)?,
        ));
        if descriptor_length == 0 || descriptor_length > MAX_DESCRIPTOR_BYTES {
            return Err(IdentityError::Limit);
        }
        let descriptor_bytes = take(input, &mut cursor, descriptor_length)?;
        let descriptor = RawKeyDescriptor::decode(descriptor_bytes)
            .map_err(|_| IdentityError::InvalidIdentity)?;
        if descriptor.encode() != descriptor_bytes {
            return Err(IdentityError::Codec);
        }
        let identity = PublicIdentity::from_descriptor(descriptor)?;
        match tag {
            PUBLIC_IDENTITY_TAG => {
                if cursor != input.len() {
                    return Err(IdentityError::Codec);
                }
                Ok(Self::PublicIdentity(identity))
            }
            SIGNED_MESSAGE_TAG => {
                let message_length = usize::try_from(u32::from_be_bytes(
                    take(input, &mut cursor, 4)?
                        .try_into()
                        .map_err(|_| IdentityError::Codec)?,
                ))
                .map_err(|_| IdentityError::Limit)?;
                if message_length == 0 || message_length > MAX_IDENTITY_MESSAGE_BYTES {
                    return Err(IdentityError::Limit);
                }
                let message = take(input, &mut cursor, message_length)?.to_vec();
                let signature = take(input, &mut cursor, ED25519_SIGNATURE_BYTES)?
                    .try_into()
                    .map_err(|_| IdentityError::Codec)?;
                if cursor != input.len() {
                    return Err(IdentityError::Codec);
                }
                Ok(Self::SignedMessage(SignedIdentityMessage::new(
                    identity, message, signature,
                )?))
            }
            _ => Err(IdentityError::Protocol),
        }
    }
}

fn validate_message(message: &[u8]) -> Result<(), IdentityError> {
    if message.is_empty() || message.len() > MAX_IDENTITY_MESSAGE_BYTES {
        return Err(IdentityError::InvalidMessage);
    }
    Ok(())
}

fn take<'a>(input: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], IdentityError> {
    let end = cursor.checked_add(length).ok_or(IdentityError::Limit)?;
    let value = input.get(*cursor..end).ok_or(IdentityError::Codec)?;
    *cursor = end;
    Ok(value)
}

/// Typed identity model, signature, and canonical-wire failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    /// Public identity is malformed or is not Ed25519.
    InvalidIdentity,
    /// Application message is empty or exceeds its hard bound.
    InvalidMessage,
    /// Ed25519 verification failed.
    InvalidSignature,
    /// Wire message is malformed or non-canonical.
    Codec,
    /// Declared or actual input exceeds a hard bound.
    Limit,
    /// Protocol version or packet tag is unsupported.
    Protocol,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentity => "invalid Ed25519 public identity",
            Self::InvalidMessage => "invalid identity message length",
            Self::InvalidSignature => "identity message signature is invalid",
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
    use ed25519_dalek::{Signer as _, SigningKey};

    fn signed(message: &[u8]) -> SignedIdentityMessage {
        let key = SigningKey::from_bytes(&[7; 32]);
        let identity = PublicIdentity::from_ed25519(key.verifying_key().to_bytes()).unwrap();
        let preimage = SignedIdentityMessage::signing_preimage(&identity, message).unwrap();
        SignedIdentityMessage::new(identity, message.to_vec(), key.sign(&preimage).to_bytes())
            .unwrap()
    }

    #[test]
    fn public_identity_round_trip_is_canonical_without_a_transport() {
        let packet = IdentityPacket::PublicIdentity(PublicIdentity::from_ed25519([3; 32]).unwrap());
        assert_eq!(
            IdentityPacket::decode(&packet.encode().unwrap()).unwrap(),
            packet
        );
    }

    #[test]
    fn signed_message_verifies_and_binds_every_byte_without_a_transport() {
        let signed = signed(b"hello anywhere");
        signed.verify().unwrap();
        let packet = IdentityPacket::SignedMessage(signed.clone());
        assert_eq!(
            IdentityPacket::decode(&packet.encode().unwrap()).unwrap(),
            packet
        );
        let tampered = SignedIdentityMessage::new(
            signed.identity().clone(),
            b"hello anywherE".to_vec(),
            *signed.signature(),
        )
        .unwrap();
        assert_eq!(tampered.verify(), Err(IdentityError::InvalidSignature));
    }

    #[test]
    fn decoder_rejects_trailing_and_oversized_input() {
        let mut encoded = IdentityPacket::SignedMessage(signed(b"hello"))
            .encode()
            .unwrap();
        encoded.push(0);
        assert_eq!(IdentityPacket::decode(&encoded), Err(IdentityError::Codec));
        assert_eq!(
            SignedIdentityMessage::signing_preimage(
                &PublicIdentity::from_ed25519([1; 32]).unwrap(),
                &alloc::vec![0; MAX_IDENTITY_MESSAGE_BYTES + 1],
            ),
            Err(IdentityError::InvalidMessage)
        );
    }
}
