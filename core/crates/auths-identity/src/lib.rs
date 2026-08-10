//! Transport-, identity-method-, and signature-suite-independent identities.
//!
//! This crate owns bounded canonical identity packets and extension interfaces.
//! Concrete identity methods and cryptographic suites live in separate adapters.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::fmt;

pub const MAX_METHOD_ID_BYTES: usize = 128;
pub const MAX_SUITE_ID_BYTES: usize = 128;
pub const MAX_IDENTITY_ID_BYTES: usize = 512;
pub const MAX_PUBLIC_KEY_BYTES: usize = 128 * 1024;
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

const WIRE_MAGIC: &[u8] = b"AUTHS-IDENTITY\0\x02";
const SIGNING_DOMAIN: &[u8] = b"AUTHS-IDENTITY-MESSAGE\0\x02";
const PUBLIC_IDENTITY_TAG: u8 = 1;
const SIGNED_MESSAGE_TAG: u8 = 2;

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

    /// Validates this descriptor with one caller-selected identity method.
    ///
    /// # Errors
    ///
    /// Rejects a mismatched method or method-specific validation failure.
    pub fn validate<M: IdentityMethod + ?Sized>(&self, method: &M) -> Result<(), IdentityError> {
        if method.method_id() != self.method_id {
            return Err(IdentityError::UnsupportedIdentityMethod);
        }
        method.validate(self)
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
    pub fn verify<M, S>(&self, method: &M, suite: &S) -> Result<(), IdentityError>
    where
        M: IdentityMethod + ?Sized,
        S: SignatureVerifier + ?Sized,
    {
        self.identity.validate(method)?;
        if suite.suite_id() != self.identity.suite_id {
            return Err(IdentityError::UnsupportedSignatureSuite);
        }
        let preimage = Self::signing_preimage(&self.identity, &self.message)?;
        suite.verify(&self.identity.public_key, &preimage, &self.signature)
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
        signed.verify(&AnyMethod, &VariableLengthSuite).unwrap();
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
}
