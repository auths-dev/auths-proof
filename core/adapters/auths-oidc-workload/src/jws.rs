extern crate alloc;

use alloc::{string::String, vec::Vec};
use auths_ports::JwsAlgorithmName;
use base64ct::{Base64UrlUnpadded, Encoding as _};

use crate::{
    JwsError,
    json::{JsonValue, flat_object},
};

pub const MAX_TOKEN_BYTES: usize = 16_384;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct KeyId(String);
impl KeyId {
    /// Parses one bounded JWS key identifier.
    ///
    /// # Errors
    ///
    /// Returns [`JwsError`] when the identifier is empty, exceeds its bound,
    /// or contains non-graphic bytes.
    pub fn parse(value: &str) -> Result<Self, JwsError> {
        if value.is_empty() || value.len() > 256 || !value.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(JwsError::InvalidKid);
        }
        Ok(Self(value.into()))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedHeader {
    pub alg: JwsAlgorithmName,
    pub kid: KeyId,
    pub x5t: Option<String>,
    pub x5t_s256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactJws {
    pub header: ProtectedHeader,
    pub signing_input: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}
impl CompactJws {
    /// Parses one bounded compact JWS with a closed protected header.
    ///
    /// # Errors
    ///
    /// Returns [`JwsError`] when the compact encoding, protected header, or a
    /// configured bound is invalid.
    pub fn parse(input: &[u8]) -> Result<Self, JwsError> {
        if input.is_empty() || input.len() > MAX_TOKEN_BYTES {
            return Err(JwsError::Limit);
        }
        if input
            .iter()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
        {
            return Err(JwsError::Alphabet);
        }
        let mut parts = input.split(|byte| *byte == b'.');
        let encoded_header = parts.next().ok_or(JwsError::Segments)?;
        let encoded_payload = parts.next().ok_or(JwsError::Segments)?;
        let encoded_signature = parts.next().ok_or(JwsError::Segments)?;
        if parts.next().is_some()
            || encoded_header.is_empty()
            || encoded_payload.is_empty()
            || encoded_signature.is_empty()
        {
            return Err(JwsError::Segments);
        }
        let header_bytes = Base64UrlUnpadded::decode_vec(
            core::str::from_utf8(encoded_header).map_err(|_| JwsError::Encoding)?,
        )
        .map_err(|_| JwsError::Encoding)?;
        let payload = Base64UrlUnpadded::decode_vec(
            core::str::from_utf8(encoded_payload).map_err(|_| JwsError::Encoding)?,
        )
        .map_err(|_| JwsError::Encoding)?;
        let signature = Base64UrlUnpadded::decode_vec(
            core::str::from_utf8(encoded_signature).map_err(|_| JwsError::Encoding)?,
        )
        .map_err(|_| JwsError::Encoding)?;
        let members = flat_object(&header_bytes).map_err(|_| JwsError::Header)?;
        let mut alg = None;
        let mut kid = None;
        let mut typ = None;
        let mut x5t = None;
        let mut x5t_s256 = None;
        for (name, value) in members {
            let JsonValue::String(value) = value else {
                return Err(JwsError::Header);
            };
            match name.as_str() {
                "alg" => {
                    alg = Some(
                        JwsAlgorithmName::parse(&value).map_err(|_| JwsError::InvalidAlgorithm)?,
                    );
                }
                "kid" => kid = Some(KeyId::parse(&value)?),
                "typ" => typ = Some(value),
                "x5t" => {
                    validate_thumbprint(&value)?;
                    x5t = Some(value);
                }
                "x5t#S256" => {
                    validate_thumbprint(&value)?;
                    x5t_s256 = Some(value);
                }
                "crit" | "jku" | "jwk" | "x5u" | "x5c" | "cty" => {
                    return Err(JwsError::ForbiddenHeader);
                }
                _ => return Err(JwsError::UnknownHeader),
            }
        }
        if typ.as_deref().is_some_and(|value| value != "JWT") {
            return Err(JwsError::Type);
        }
        let signing_input_end = encoded_header
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_add(encoded_payload.len()))
            .ok_or(JwsError::Limit)?;
        Ok(Self {
            header: ProtectedHeader {
                alg: alg.ok_or(JwsError::MissingAlgorithm)?,
                kid: kid.ok_or(JwsError::MissingKid)?,
                x5t,
                x5t_s256,
            },
            signing_input: input[..signing_input_end].to_vec(),
            payload,
            signature,
        })
    }
}

fn validate_thumbprint(value: &str) -> Result<(), JwsError> {
    if value.is_empty() || value.len() > 64 || Base64UrlUnpadded::decode_vec(value).is_err() {
        return Err(JwsError::Thumbprint);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_closed_protected_header() {
        let header =
            Base64UrlUnpadded::encode_string(br#"{"alg":"EdDSA","kid":"one","typ":"JWT"}"#);
        let payload = Base64UrlUnpadded::encode_string(br#"{"sub":"x"}"#);
        let token = alloc::format!("{header}.{payload}.AA");
        assert!(CompactJws::parse(token.as_bytes()).is_ok());
        let bad = Base64UrlUnpadded::encode_string(br#"{"alg":"none","kid":"one"}"#);
        assert_eq!(
            CompactJws::parse(alloc::format!("{bad}.{payload}.AA").as_bytes()),
            Err(JwsError::InvalidAlgorithm)
        );
    }
}
