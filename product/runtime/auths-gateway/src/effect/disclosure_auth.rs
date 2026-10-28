//! Bounded private local-channel identity and historical authentication data.
//! This module has no socket access and cannot construct a live channel/permit.
use super::{DisclosureAcknowledgementRequest, EffectBinding, canonical, commitment};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signature, VerifyingKey};
#[cfg(any(unix, test))]
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;
const CHANNEL_SCHEMA: &str = "auths.gateway-unix-disclosure-channel/1";
pub(crate) const AUTH_SCHEMA: &str = "auths.gateway-disclosure-auth/1";
pub(crate) const MAX_AUTH_BYTES: usize = 4_096;

/// Proposed local channel identity. This is data, never proof that a live peer
/// has authenticated. Its native commitment must match the approved effect.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnixDisclosurePolicy {
    schema: String,
    gateway_uid: u32,
    recipient_uid: u32,
    channel_id: [u8; 32],
}

impl fmt::Debug for UnixDisclosurePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnixDisclosurePolicy { private: [redacted] }")
    }
}

impl UnixDisclosurePolicy {
    /// Pins OS identities and a channel identifier chosen on the private
    /// authoring channel. Same-UID use does not establish agent isolation.
    #[must_use]
    pub fn new(gateway_uid: u32, recipient_uid: u32, channel_id: [u8; 32]) -> Self {
        Self {
            schema: CHANNEL_SCHEMA.to_owned(),
            gateway_uid,
            recipient_uid,
            channel_id,
        }
    }
    /// Native channel value for the disclosure target and exact approval.
    ///
    /// # Errors
    /// Refuses unsupported/invalid policy encodings.
    pub fn commitment(&self) -> Result<[u8; 32], &'static str> {
        if self.schema != CHANNEL_SCHEMA {
            return Err("gateway.disclosure.channel");
        }
        commitment(
            CHANNEL_SCHEMA,
            &canonical(self).map_err(|_| "gateway.disclosure.channel")?,
        )
        .map_err(|_| "gateway.disclosure.channel")
    }
    pub(crate) fn matches(&self, binding: &EffectBinding) -> Result<(), &'static str> {
        if !binding.disclosure_channel_matches(&self.commitment()?) {
            return Err("gateway.disclosure.channel");
        }
        Ok(())
    }
    #[cfg(unix)]
    pub(crate) fn gateway_uid(&self) -> u32 {
        self.gateway_uid
    }
    #[cfg(unix)]
    pub(crate) fn recipient_uid(&self) -> u32 {
        self.recipient_uid
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Challenge {
    pub(crate) schema: String,
    pub(crate) delivery: DisclosureAcknowledgementRequest,
    pub(crate) nonce: [u8; 32],
}

impl Challenge {
    pub(crate) fn message(&self) -> Result<[u8; 32], &'static str> {
        if self.schema != AUTH_SCHEMA {
            return Err("gateway.disclosure.authentication");
        }
        self.delivery
            .to_private_bytes()
            .map_err(|_| "gateway.disclosure.authentication")?;
        commitment(AUTH_SCHEMA, &bounded(self)?).map_err(|_| "gateway.disclosure.authentication")
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Response {
    schema: String,
    signature: String,
}

impl Response {
    #[cfg(any(unix, test))]
    pub(crate) fn sign(challenge: &Challenge, key: &SigningKey) -> Result<Self, &'static str> {
        Ok(Self {
            schema: AUTH_SCHEMA.to_owned(),
            signature: Base64UrlUnpadded::encode_string(
                &key.sign(&challenge.message()?).to_bytes(),
            ),
        })
    }
    pub(crate) fn verify(&self, challenge: &Challenge, key: [u8; 32]) -> Result<(), &'static str> {
        if self.schema != AUTH_SCHEMA {
            return Err("gateway.disclosure.authentication");
        }
        let mut signature = [0; 64];
        let bytes = Base64UrlUnpadded::decode(&self.signature, &mut signature)
            .map_err(|_| "gateway.disclosure.authentication")?;
        if bytes.len() != 64 || Base64UrlUnpadded::encode_string(bytes) != self.signature {
            return Err("gateway.disclosure.authentication");
        }
        let key =
            VerifyingKey::from_bytes(&key).map_err(|_| "gateway.disclosure.authentication")?;
        if key.is_weak() {
            return Err("gateway.disclosure.authentication");
        }
        key.verify_strict(&challenge.message()?, &Signature::from_bytes(&signature))
            .map_err(|_| "gateway.disclosure.authentication")
    }
}

/// Private authenticated historical transcript. Decoding it never reconstructs
/// an owned live stream or a one-use delivery permit.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecipientAuthentication {
    pub(crate) policy: UnixDisclosurePolicy,
    pub(crate) challenge: Challenge,
    pub(crate) response: Response,
}
impl RecipientAuthentication {
    /// Historical fixture assumption only; no socket or permit is constructed.
    #[cfg(test)]
    pub(crate) fn synthetic(
        binding: &EffectBinding,
        bytes: u64,
        key: &SigningKey,
        policy: UnixDisclosurePolicy,
    ) -> Self {
        let challenge = Challenge {
            schema: AUTH_SCHEMA.to_owned(),
            delivery: DisclosureAcknowledgementRequest::for_delivery(
                binding,
                bytes,
                key.verifying_key().to_bytes(),
            )
            .expect("fixture delivery"),
            nonce: [17; 32],
        };
        let response = Response::sign(&challenge, key).expect("fixture response");
        Self {
            policy,
            challenge,
            response,
        }
    }

    pub(crate) fn validate(
        &self,
        binding: &EffectBinding,
        bytes: u64,
        key: [u8; 32],
    ) -> Result<(), &'static str> {
        self.policy.matches(binding)?;
        let expected = DisclosureAcknowledgementRequest::for_delivery(binding, bytes, key)
            .map_err(|_| "gateway.disclosure.authentication")?;
        if self.challenge.delivery != expected {
            return Err("gateway.disclosure.authentication");
        }
        bounded(self)?;
        self.response.verify(&self.challenge, key)
    }
}

pub(crate) fn bounded<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let bytes = canonical(value).map_err(|_| "gateway.disclosure.authentication")?;
    if bytes.is_empty() || bytes.len() > MAX_AUTH_BYTES {
        return Err("gateway.disclosure.frame");
    }
    Ok(bytes)
}
#[cfg(unix)]
pub(crate) fn decode<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_AUTH_BYTES {
        return Err("gateway.disclosure.frame");
    }
    let value: T = serde_json::from_slice(bytes).map_err(|_| "gateway.disclosure.frame")?;
    if bounded(&value)?.as_slice() != bytes {
        return Err("gateway.disclosure.frame");
    }
    Ok(value)
}
