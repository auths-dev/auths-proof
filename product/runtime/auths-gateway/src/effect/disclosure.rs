//! Exact recipient evidence. ACKs describe history and never confer delivery
//! authority. The sole journal reducer decides whether that history can be added.

use super::{EffectBinding, EffectBindingError, Protocol, canonical, commitment};
use auths_raw_key::{RawKeyDescriptor, RawKeyType};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

/// Only accepted recipient acknowledgement contract.
pub const DISCLOSURE_ACK_SCHEMA: &str = "auths.gateway-disclosure-ack/1";
/// Maximum canonical acknowledgement or signing request, before decoding.
pub const MAX_DISCLOSURE_ACK_BYTES: usize = 4_096;

/// Private exact delivery statement for a recipient's Ed25519 signer.
/// Construction is data-only: it neither authenticates receipt of bytes nor
/// establishes native authority, approval, admission or a delivery grant.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosureAcknowledgementRequest {
    schema: String,
    effect: [u8; 32],
    source_effect: [u8; 32],
    protected_content: [u8; 32],
    recipient: String,
    recipient_key: [u8; 32],
    channel: [u8; 32],
    delivery_instance: [u8; 32],
    projection: [u8; 32],
    maximum_bytes: u64,
    acknowledged_bytes: u64,
}

impl fmt::Debug for DisclosureAcknowledgementRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DisclosureAcknowledgementRequest { private: [redacted] }")
    }
}

impl DisclosureAcknowledgementRequest {
    /// Constructs the exact signing statement from a private disclosure binding.
    /// `content_bytes` is the length of the protected content the runtime will
    /// deliver, not a recipient-supplied limit. Empty content remains distinct
    /// from missing content. The recipient must be the bound raw-key principal.
    ///
    /// # Errors
    /// Refuses other protocols, an unrelated/weak key or length above the bound.
    pub fn for_delivery(
        binding: &EffectBinding,
        content_bytes: u64,
        recipient_key: [u8; 32],
    ) -> Result<Self, EffectBindingError> {
        let Protocol::Disclosure {
            source_effect,
            protected_content,
            recipient,
            channel,
            delivery_instance,
            projection,
            maximum_bytes,
        } = &binding.wire.protocol
        else {
            return Err(EffectBindingError::Invalid);
        };
        let request = Self {
            schema: DISCLOSURE_ACK_SCHEMA.to_owned(),
            effect: *binding.id().as_bytes(),
            source_effect: *source_effect,
            protected_content: *protected_content,
            recipient: recipient.clone(),
            recipient_key,
            channel: *channel,
            delivery_instance: *delivery_instance,
            projection: *projection,
            maximum_bytes: *maximum_bytes,
            acknowledged_bytes: content_bytes,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), EffectBindingError> {
        if self.schema != DISCLOSURE_ACK_SCHEMA {
            return Err(EffectBindingError::Unsupported);
        }
        let key = VerifyingKey::from_bytes(&self.recipient_key)
            .map_err(|_| EffectBindingError::Invalid)?;
        if key.is_weak()
            || self.maximum_bytes > 65_536
            || self.acknowledged_bytes > self.maximum_bytes
            || self.recipient.len() > 512
        {
            return Err(EffectBindingError::Invalid);
        }
        let principal = RawKeyDescriptor::new(RawKeyType::Ed25519, self.recipient_key.to_vec())
            .map_err(|_| EffectBindingError::Invalid)?
            .principal()
            .map_err(|_| EffectBindingError::Invalid)?;
        if principal.as_str() != self.recipient {
            return Err(EffectBindingError::Invalid);
        }
        Ok(())
    }

    /// Encodes private signing data with the native canonical codec.
    ///
    /// # Errors
    /// Refuses invalid or oversized statements.
    pub fn to_private_bytes(&self) -> Result<Zeroizing<Vec<u8>>, EffectBindingError> {
        self.validate()?;
        bounded_canonical(self)
    }

    /// Decodes data only. Exact encoding and the total bound are mandatory.
    ///
    /// # Errors
    /// Refuses malformed, duplicate, unknown, obsolete, oversized or alternate
    /// encodings. Successful decoding is not evidence of an actual delivery.
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, EffectBindingError> {
        check_length(bytes)?;
        let request: Self =
            serde_json::from_slice(bytes).map_err(|_| EffectBindingError::Invalid)?;
        if request.to_private_bytes()?.as_slice() != bytes {
            return Err(EffectBindingError::Invalid);
        }
        Ok(request)
    }

    /// Returns the native domain-separated Ed25519 message. The authenticated
    /// recipient signs only after checking the received content and delivery
    /// metadata on its bound channel. A signature is the recipient's assertion,
    /// not proof of human attention or of the transport's implementation.
    ///
    /// # Errors
    /// Refuses malformed/unsupported statements.
    pub fn signing_message(&self) -> Result<[u8; 32], EffectBindingError> {
        commitment(DISCLOSURE_ACK_SCHEMA, &self.to_private_bytes()?)
    }

    /// Attaches an unverified signature. This creates portable evidence data,
    /// never a delivery capability or authenticated journal fact.
    #[must_use]
    pub fn with_signature(self, signature: [u8; 64]) -> DisclosureAcknowledgement {
        DisclosureAcknowledgement {
            request: self,
            signature_b64: Base64UrlUnpadded::encode_string(&signature),
        }
    }
}

/// Bounded portable recipient evidence, subject to native verification against
/// the retained delivery. It contains private correlations and is not a public
/// receipt. There is deliberately no expiry or current-authority field: an
/// exact late ACK may refine history after revocation or approval expiry.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosureAcknowledgement {
    request: DisclosureAcknowledgementRequest,
    signature_b64: String,
}

impl fmt::Debug for DisclosureAcknowledgement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DisclosureAcknowledgement { private: [redacted] }")
    }
}

impl DisclosureAcknowledgement {
    /// Encodes private evidence for the protected channel/journal.
    ///
    /// # Errors
    /// Refuses invalid statements, noncanonical signatures or oversized data.
    pub fn to_private_bytes(&self) -> Result<Zeroizing<Vec<u8>>, EffectBindingError> {
        self.request.validate()?;
        self.signature()?;
        bounded_canonical(self)
    }

    /// Decodes canonical evidence without authenticating it.
    ///
    /// # Errors
    /// Refuses duplicate/unknown fields, obsolete schemas, malformed signatures,
    /// alternate encodings and input larger than `MAX_DISCLOSURE_ACK_BYTES`.
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, EffectBindingError> {
        check_length(bytes)?;
        let ack: Self = serde_json::from_slice(bytes).map_err(|_| EffectBindingError::Invalid)?;
        if ack.to_private_bytes()?.as_slice() != bytes {
            return Err(EffectBindingError::Invalid);
        }
        Ok(ack)
    }

    fn signature(&self) -> Result<Signature, EffectBindingError> {
        let mut bytes = [0_u8; 64];
        let decoded = Base64UrlUnpadded::decode(&self.signature_b64, &mut bytes)
            .map_err(|_| EffectBindingError::Invalid)?;
        if decoded.len() != 64 || Base64UrlUnpadded::encode_string(decoded) != self.signature_b64 {
            return Err(EffectBindingError::Invalid);
        }
        Ok(Signature::from_bytes(&bytes))
    }

    /// Authenticates exact evidence against the retained disclosure binding
    /// and protected content length. The expected values must come from the
    /// authoritative journal/content owner, never the incoming ACK. This is a
    /// historical assertion only: callers must also require a retained grant
    /// and apply the shared reducer before recording it. No fresh permission,
    /// credential lease, byte release or refund follows from verification.
    ///
    /// # Errors
    /// Refuses any substituted dimension, length, signer or invalid signature.
    pub fn verify(
        &self,
        binding: &EffectBinding,
        content_bytes: u64,
    ) -> Result<AuthenticatedDisclosureAcknowledgement, EffectBindingError> {
        let expected = DisclosureAcknowledgementRequest::for_delivery(
            binding,
            content_bytes,
            self.request.recipient_key,
        )?;
        if self.request != expected {
            return Err(EffectBindingError::Invalid);
        }
        VerifyingKey::from_bytes(&expected.recipient_key)
            .map_err(|_| EffectBindingError::Invalid)?
            .verify_strict(&expected.signing_message()?, &self.signature()?)
            .map_err(|_| EffectBindingError::Invalid)?;
        Ok(AuthenticatedDisclosureAcknowledgement {
            canonical: self.to_private_bytes()?,
        })
    }
}

/// Sealed authenticated historical assertion. It cannot be deserialized or
/// cloned into execution authority and is never a transport permit.
pub struct AuthenticatedDisclosureAcknowledgement {
    canonical: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for AuthenticatedDisclosureAcknowledgement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticatedDisclosureAcknowledgement { private: [redacted] }")
    }
}

impl AuthenticatedDisclosureAcknowledgement {
    /// Exact private evidence bytes for the journal's immutable ACK field.
    /// Persistence still requires its matching original grant and reducer.
    #[must_use]
    pub fn as_private_bytes(&self) -> &[u8] {
        &self.canonical
    }
}

fn check_length(bytes: &[u8]) -> Result<(), EffectBindingError> {
    if bytes.is_empty() || bytes.len() > MAX_DISCLOSURE_ACK_BYTES {
        return Err(EffectBindingError::Invalid);
    }
    Ok(())
}

fn bounded_canonical<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>, EffectBindingError> {
    let bytes = canonical(value)?;
    check_length(&bytes)?;
    Ok(bytes)
}
