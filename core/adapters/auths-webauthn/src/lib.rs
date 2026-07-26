//! Pure `WebAuthn` assertion verification inputs for Auths target V1.
//!
//! Browser ceremonies and credential registration are effectful outer-layer
//! operations. This method validates their immutable outputs, binds the
//! ceremony challenge to the exact Auths signing preimage, and returns the
//! `WebAuthn` signature message to the registered P-256 suite.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use auths_model::{
    AdapterConfigurationId, AdapterId, AssuranceClaim, AssuranceClaimId, ClaimParameterId,
    EvidenceId, EvidenceSourceId, EvidenceTypeId, MediaType, ModelError, PrincipalId,
    PrincipalMethodId, Timestamp, VerificationMethod,
};
use auths_ports::{ControlEvidence, PrincipalControlError, PrincipalControlInput, PrincipalMethod};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use core::{fmt, str};
use p256::ecdsa::VerifyingKey;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

/// Exact target V1 method/evidence identifier.
pub const WEBAUTHN_V1: &str = "webauthn-v1";
/// Exact assertion-evidence media type.
pub const WEBAUTHN_MEDIA_TYPE: &str = "application/vnd.auths.webauthn-assertion.v1";
/// Principal scheme for credential-scoped `WebAuthn` principals.
pub const PRINCIPAL_PREFIX: &str = "webauthn:";
/// P-256/SHA-256 is the mandatory target `WebAuthn` suite.
pub const P256_SUITE: &str = "p256-sha256-v1";
const EVIDENCE_DOMAIN: &[u8] = b"AUTHS-WEBAUTHN\x00\x01";
const MAX_CREDENTIAL_ID: usize = 1024;
const MAX_AUTHENTICATOR_DATA: usize = 1024;
const MAX_CLIENT_DATA: usize = 4096;
const MAX_CREDENTIALS: usize = 256;
const MAX_ORIGINS: usize = 16;
const AUTHENTICATOR_DATA_MINIMUM: usize = 37;
const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;

/// Signature-counter policy compiled from credential registration state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CounterPolicy {
    /// The authenticator does not provide a meaningful counter.
    Disabled,
    /// The assertion counter must be strictly greater than this value.
    GreaterThan(u32),
}

/// Verifier-local immutable `WebAuthn` credential registration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebAuthnCredential {
    credential_id: Vec<u8>,
    principal: PrincipalId,
    verification_method: VerificationMethod,
    public_key: [u8; 33],
    rp_id: String,
    origins: Vec<String>,
    require_user_verification: bool,
    counter_policy: CounterPolicy,
    attestation_level: Option<String>,
    observed_at: Timestamp,
    valid_until: Timestamp,
}

impl WebAuthnCredential {
    /// Constructs a closed credential registration record.
    ///
    /// # Errors
    ///
    /// Rejects invalid credential IDs, P-256 keys, RP IDs, origins,
    /// attestation labels, time windows, and collection bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        credential_id: Vec<u8>,
        public_key: [u8; 33],
        rp_id: String,
        mut origins: Vec<String>,
        require_user_verification: bool,
        counter_policy: CounterPolicy,
        attestation_level: Option<String>,
        observed_at: Timestamp,
        valid_until: Timestamp,
    ) -> Result<Self, WebAuthnError> {
        if credential_id.is_empty()
            || credential_id.len() > MAX_CREDENTIAL_ID
            || !valid_rp_id(&rp_id)
            || origins.is_empty()
            || origins.len() > MAX_ORIGINS
            || origins.iter().any(|origin| !valid_origin(origin))
            || observed_at > valid_until
            || attestation_level
                .as_ref()
                .is_some_and(|level| level.is_empty() || level.len() > 64)
        {
            return Err(WebAuthnError::InvalidCredential);
        }
        VerifyingKey::from_sec1_bytes(&public_key).map_err(|_| WebAuthnError::InvalidCredential)?;
        origins.sort();
        if origins.windows(2).any(|window| window[0] == window[1]) {
            return Err(WebAuthnError::InvalidCredential);
        }
        let encoded = Base64UrlUnpadded::encode_string(&credential_id);
        let principal = PrincipalId::parse(&format!("{PRINCIPAL_PREFIX}{encoded}"))?;
        let verification_method =
            VerificationMethod::parse(&format!("{}#credential", principal.as_str()))?;
        Ok(Self {
            credential_id,
            principal,
            verification_method,
            public_key,
            rp_id,
            origins,
            require_user_verification,
            counter_policy,
            attestation_level,
            observed_at,
            valid_until,
        })
    }

    /// Returns the credential-derived principal.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Returns the only verification method for the credential.
    #[must_use]
    pub const fn verification_method(&self) -> &VerificationMethod {
        &self.verification_method
    }

    /// Returns the registered credential identifier.
    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// Returns the compressed SEC1 P-256 verification key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 33] {
        &self.public_key
    }

    /// Returns the exact relying-party identifier.
    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// Returns the accepted canonical origins.
    #[must_use]
    pub fn origins(&self) -> &[String] {
        &self.origins
    }

    /// Returns whether user verification is mandatory.
    #[must_use]
    pub const fn require_user_verification(&self) -> bool {
        self.require_user_verification
    }

    /// Returns the registered signature-counter policy.
    #[must_use]
    pub const fn counter_policy(&self) -> CounterPolicy {
        self.counter_policy
    }

    /// Returns the optional attestation level.
    #[must_use]
    pub fn attestation_level(&self) -> Option<&str> {
        self.attestation_level.as_deref()
    }

    /// Returns when the registration was observed.
    #[must_use]
    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    /// Returns the end of the registration validity interval.
    #[must_use]
    pub const fn valid_until(&self) -> Timestamp {
        self.valid_until
    }
}

/// Untrusted assertion inputs carried as principal evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebAuthnEvidence {
    credential_id: Vec<u8>,
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
}

impl WebAuthnEvidence {
    /// Constructs bounded assertion evidence.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized fields and short authenticator data.
    pub fn new(
        credential_id: Vec<u8>,
        authenticator_data: Vec<u8>,
        client_data_json: Vec<u8>,
    ) -> Result<Self, WebAuthnError> {
        if credential_id.is_empty()
            || credential_id.len() > MAX_CREDENTIAL_ID
            || authenticator_data.len() < AUTHENTICATOR_DATA_MINIMUM
            || authenticator_data.len() > MAX_AUTHENTICATOR_DATA
            || client_data_json.is_empty()
            || client_data_json.len() > MAX_CLIENT_DATA
        {
            return Err(WebAuthnError::LimitExceeded);
        }
        Ok(Self {
            credential_id,
            authenticator_data,
            client_data_json,
        })
    }

    /// Encodes the unique target assertion envelope.
    ///
    /// # Errors
    ///
    /// Returns a typed limit error if a bounded length cannot be represented.
    pub fn encode(&self) -> Result<Vec<u8>, WebAuthnError> {
        let credential_length =
            u16::try_from(self.credential_id.len()).map_err(|_| WebAuthnError::LimitExceeded)?;
        let authenticator_length = u16::try_from(self.authenticator_data.len())
            .map_err(|_| WebAuthnError::LimitExceeded)?;
        let client_length =
            u32::try_from(self.client_data_json.len()).map_err(|_| WebAuthnError::LimitExceeded)?;
        let mut output = Vec::with_capacity(
            EVIDENCE_DOMAIN.len()
                + 8
                + self.credential_id.len()
                + self.authenticator_data.len()
                + self.client_data_json.len(),
        );
        output.extend_from_slice(EVIDENCE_DOMAIN);
        output.extend_from_slice(&credential_length.to_be_bytes());
        output.extend_from_slice(&self.credential_id);
        output.extend_from_slice(&authenticator_length.to_be_bytes());
        output.extend_from_slice(&self.authenticator_data);
        output.extend_from_slice(&client_length.to_be_bytes());
        output.extend_from_slice(&self.client_data_json);
        Ok(output)
    }

    /// Decodes exact bounded assertion evidence.
    ///
    /// # Errors
    ///
    /// Rejects wrong domains, malformed lengths, trailing bytes, and bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, WebAuthnError> {
        let mut reader = Reader::new(bytes);
        if reader.take(EVIDENCE_DOMAIN.len())? != EVIDENCE_DOMAIN {
            return Err(WebAuthnError::InvalidEvidence);
        }
        let credential_length = usize::from(reader.u16()?);
        let credential_id = reader.take(credential_length)?.to_vec();
        let authenticator_length = usize::from(reader.u16()?);
        let authenticator_data = reader.take(authenticator_length)?.to_vec();
        let client_length =
            usize::try_from(reader.u32()?).map_err(|_| WebAuthnError::LimitExceeded)?;
        let client_data_json = reader.take(client_length)?.to_vec();
        if !reader.finished() {
            return Err(WebAuthnError::InvalidEvidence);
        }
        Self::new(credential_id, authenticator_data, client_data_json)
    }

    /// Returns the exact message signed by the authenticator.
    #[must_use]
    pub fn signature_message(&self) -> Vec<u8> {
        let mut message = Vec::with_capacity(self.authenticator_data.len() + 32);
        message.extend_from_slice(&self.authenticator_data);
        message.extend_from_slice(&Sha256::digest(&self.client_data_json));
        message
    }
}

/// Pure `WebAuthn` principal-control method.
pub struct WebAuthnMethod {
    id: PrincipalMethodId,
    evidence_type: EvidenceTypeId,
    media_type: MediaType,
    adapter: AdapterId,
    source: EvidenceSourceId,
    credentials: Vec<WebAuthnCredential>,
}

impl WebAuthnMethod {
    /// Constructs a method from verifier-local credential registrations.
    ///
    /// # Errors
    ///
    /// Rejects oversized or duplicate credential registrations.
    pub fn new(mut credentials: Vec<WebAuthnCredential>) -> Result<Self, WebAuthnError> {
        if credentials.len() > MAX_CREDENTIALS {
            return Err(WebAuthnError::LimitExceeded);
        }
        credentials.sort_by(|left, right| left.principal.cmp(&right.principal));
        if credentials
            .windows(2)
            .any(|window| window[0].principal == window[1].principal)
        {
            return Err(WebAuthnError::InvalidCredential);
        }
        Ok(Self {
            id: PrincipalMethodId::parse(WEBAUTHN_V1)?,
            evidence_type: EvidenceTypeId::parse(WEBAUTHN_V1)?,
            media_type: MediaType::parse(WEBAUTHN_MEDIA_TYPE)?,
            adapter: AdapterId::parse(WEBAUTHN_V1)?,
            source: EvidenceSourceId::parse(WEBAUTHN_V1)?,
            credentials,
        })
    }
}

impl PrincipalMethod for WebAuthnMethod {
    fn id(&self) -> &PrincipalMethodId {
        &self.id
    }

    fn configuration_id(&self) -> AdapterConfigurationId {
        let mut components = Vec::new();
        for credential in &self.credentials {
            components.push(credential.credential_id.clone());
            components.push(credential.principal.as_str().as_bytes().to_vec());
            components.push(credential.verification_method.as_str().as_bytes().to_vec());
            components.push(credential.public_key.to_vec());
            components.push(credential.rp_id.as_bytes().to_vec());
            components.push(
                u64::try_from(credential.origins.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes()
                    .to_vec(),
            );
            for origin in &credential.origins {
                components.push(origin.as_bytes().to_vec());
            }
            components.push(vec![u8::from(credential.require_user_verification)]);
            components.push(match credential.counter_policy {
                CounterPolicy::Disabled => vec![0],
                CounterPolicy::GreaterThan(counter) => {
                    let mut value = vec![1];
                    value.extend_from_slice(&counter.to_be_bytes());
                    value
                }
            });
            components.push(
                credential
                    .attestation_level
                    .as_deref()
                    .unwrap_or_default()
                    .as_bytes()
                    .to_vec(),
            );
            components.push(credential.observed_at.get().to_be_bytes().to_vec());
            components.push(credential.valid_until.get().to_be_bytes().to_vec());
        }
        auths_ports::configuration_id(WEBAUTHN_V1.as_bytes(), components.iter().map(Vec::as_slice))
    }

    fn maximum_work_units(&self) -> u64 {
        75
    }

    fn verify_control(
        &self,
        input: PrincipalControlInput<'_>,
    ) -> Result<ControlEvidence, PrincipalControlError> {
        if !input.principal.as_str().starts_with(PRINCIPAL_PREFIX) {
            return Err(PrincipalControlError::PrincipalMethodMismatch);
        }
        if input.signature_suite.as_str() != P256_SUITE {
            return Err(PrincipalControlError::SignatureSuiteMismatch);
        }
        let credential = self
            .credentials
            .iter()
            .find(|credential| credential.principal == *input.principal)
            .ok_or(PrincipalControlError::ExternalFactUnavailable)?;
        if &credential.verification_method != input.verification_method {
            return Err(PrincipalControlError::VerificationMethodMismatch);
        }
        if input.evaluation_time < credential.observed_at
            || input.evaluation_time > credential.valid_until
        {
            return Err(PrincipalControlError::ExternalFactUnavailable);
        }
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
        let assertion = WebAuthnEvidence::decode(evidence.bytes()).map_err(map_evidence_error)?;
        if assertion.credential_id != credential.credential_id {
            return Err(PrincipalControlError::PrincipalMethodMismatch);
        }
        let flags = assertion.authenticator_data[32];
        if flags & FLAG_USER_PRESENT == 0
            || (credential.require_user_verification && flags & FLAG_USER_VERIFIED == 0)
        {
            return Err(PrincipalControlError::InvalidEvidence);
        }
        let rp_id_hash: [u8; 32] = Sha256::digest(credential.rp_id.as_bytes()).into();
        if assertion.authenticator_data[..32] != rp_id_hash {
            return Err(PrincipalControlError::InvalidEvidence);
        }
        let sign_count = u32::from_be_bytes(
            assertion.authenticator_data[33..37]
                .try_into()
                .map_err(|_| PrincipalControlError::InvalidEvidence)?,
        );
        if matches!(
            credential.counter_policy,
            CounterPolicy::GreaterThan(previous) if sign_count == 0 || sign_count <= previous
        ) {
            return Err(PrincipalControlError::InvalidEvidence);
        }
        let client = parse_client_data(&assertion.client_data_json)
            .map_err(|_| PrincipalControlError::InvalidEvidence)?;
        let expected_challenge = Sha256::digest(input.signing_preimage);
        let challenge = Base64UrlUnpadded::decode_vec(&client.challenge)
            .map_err(|_| PrincipalControlError::InvalidEvidence)?;
        if challenge.as_slice() != expected_challenge.as_slice()
            || !credential
                .origins
                .iter()
                .any(|origin| origin == &client.origin)
        {
            return Err(PrincipalControlError::InvalidEvidence);
        }
        let claims = assertion_claims(
            flags,
            credential,
            &client.origin,
            input.evaluation_time,
            &self.source,
        )?;
        let signature_message = assertion.signature_message();
        ControlEvidence::new(
            credential.public_key.to_vec(),
            claims,
            vec![EvidenceId::new(*evidence.id().as_bytes())],
            self.adapter.clone(),
            1,
            75,
        )?
        .with_signature_message(signature_message)
    }
}

fn assertion_claims(
    flags: u8,
    credential: &WebAuthnCredential,
    origin: &str,
    evaluation_time: Timestamp,
    source: &EvidenceSourceId,
) -> Result<Vec<AssuranceClaim>, PrincipalControlError> {
    let mut claims = vec![
        claim(
            "origin-bound",
            vec![("origin", origin)],
            Some(credential.observed_at),
            source,
        )?,
        claim(
            "controller-state-current-at",
            Vec::new(),
            Some(credential.observed_at),
            source,
        )?,
        claim(
            "revocation-checked-at",
            Vec::new(),
            Some(credential.observed_at),
            source,
        )?,
    ];
    if flags & FLAG_USER_VERIFIED != 0 {
        claims.push(claim(
            "user-verified",
            Vec::new(),
            Some(evaluation_time),
            source,
        )?);
    }
    if let Some(level) = &credential.attestation_level {
        claims.push(claim(
            "hardware-attested",
            vec![("level", level)],
            Some(credential.observed_at),
            source,
        )?);
    }
    Ok(claims)
}

struct ClientData {
    challenge: String,
    origin: String,
}

fn parse_client_data(bytes: &[u8]) -> Result<ClientData, WebAuthnError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| WebAuthnError::InvalidClientData)?;
    let object = value.as_object().ok_or(WebAuthnError::InvalidClientData)?;
    if object.len() < 3
        || object.len() > 4
        || object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "type" | "challenge" | "origin" | "crossOrigin"
            )
        })
        || text(object, "type")? != "webauthn.get"
        || object
            .get("crossOrigin")
            .is_some_and(|value| value.as_bool() != Some(false))
    {
        return Err(WebAuthnError::InvalidClientData);
    }
    Ok(ClientData {
        challenge: text(object, "challenge")?.to_string(),
        origin: text(object, "origin")?.to_string(),
    })
}

fn text<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, WebAuthnError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(WebAuthnError::InvalidClientData)
}

fn claim(
    identifier: &str,
    parameters: Vec<(&str, &str)>,
    observed_at: Option<Timestamp>,
    source: &EvidenceSourceId,
) -> Result<AssuranceClaim, PrincipalControlError> {
    let parameters = parameters
        .into_iter()
        .map(|(key, value)| {
            Ok((
                ClaimParameterId::parse(key).map_err(|_| PrincipalControlError::InvalidEvidence)?,
                ClaimParameterId::parse(value)
                    .map_err(|_| PrincipalControlError::InvalidEvidence)?,
            ))
        })
        .collect::<Result<Vec<_>, PrincipalControlError>>()?;
    AssuranceClaim::new(
        AssuranceClaimId::parse(identifier).map_err(|_| PrincipalControlError::InvalidEvidence)?,
        parameters,
        observed_at,
        source.clone(),
    )
    .map_err(|_| PrincipalControlError::InvalidEvidence)
}

fn valid_rp_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.contains('.')
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn valid_origin(value: &str) -> bool {
    value.strip_prefix("https://").is_some_and(|authority| {
        !authority.is_empty()
            && authority.len() <= 253 + 6
            && !authority.contains(['/', '?', '#', '@'])
            && authority.is_ascii()
            && authority == authority.to_ascii_lowercase()
    })
}

fn map_evidence_error(error: WebAuthnError) -> PrincipalControlError {
    match error {
        WebAuthnError::LimitExceeded => PrincipalControlError::ResourceLimitExceeded,
        _ => PrincipalControlError::InvalidEvidence,
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], WebAuthnError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(WebAuthnError::InvalidEvidence)?;
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or(WebAuthnError::InvalidEvidence)?;
        self.cursor = end;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16, WebAuthnError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, WebAuthnError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    const fn finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

/// `WebAuthn` registration or assertion failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebAuthnError {
    /// A target model identifier is invalid.
    Model(ModelError),
    /// The credential registration is invalid.
    InvalidCredential,
    /// The assertion evidence envelope is invalid.
    InvalidEvidence,
    /// The client data is outside the closed target profile.
    InvalidClientData,
    /// A target bound was exceeded.
    LimitExceeded,
}

impl From<ModelError> for WebAuthnError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl fmt::Display for WebAuthnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model(error) => write!(formatter, "invalid Auths model value: {error}"),
            Self::InvalidCredential => formatter.write_str("invalid WebAuthn credential record"),
            Self::InvalidEvidence => formatter.write_str("invalid WebAuthn assertion evidence"),
            Self::InvalidClientData => formatter.write_str("invalid WebAuthn client data"),
            Self::LimitExceeded => formatter.write_str("WebAuthn resource limit exceeded"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WebAuthnError {}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_model::{Digest, EvidenceObject, SignatureSuiteId};
    use auths_ports::{ControlPurpose, PrincipalControlInput};
    use p256::ecdsa::SigningKey;

    #[test]
    fn ceremony_message_binds_exact_auths_preimage() {
        let signing_key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let point = signing_key.verifying_key().to_encoded_point(true);
        let public_key: [u8; 33] = point.as_bytes().try_into().unwrap();
        let credential = WebAuthnCredential::new(
            b"credential-1".to_vec(),
            public_key,
            "auths.example".to_string(),
            vec!["https://auths.example".to_string()],
            true,
            CounterPolicy::GreaterThan(4),
            Some("non-exportable".to_string()),
            Timestamp::new(10),
            Timestamp::new(30),
        )
        .unwrap();
        let preimage = b"exact Auths signing preimage";
        let challenge = Base64UrlUnpadded::encode_string(&Sha256::digest(preimage));
        let client_data = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://auths.example","crossOrigin":false}}"#
        )
        .into_bytes();
        let mut authenticator_data = Vec::new();
        authenticator_data.extend_from_slice(&Sha256::digest(b"auths.example"));
        authenticator_data.push(FLAG_USER_PRESENT | FLAG_USER_VERIFIED);
        authenticator_data.extend_from_slice(&5u32.to_be_bytes());
        let assertion =
            WebAuthnEvidence::new(b"credential-1".to_vec(), authenticator_data, client_data)
                .unwrap();
        let evidence = EvidenceObject::new(
            EvidenceId::from_digest(Digest::ZERO),
            EvidenceTypeId::parse(WEBAUTHN_V1).unwrap(),
            MediaType::parse(WEBAUTHN_MEDIA_TYPE).unwrap(),
            assertion.encode().unwrap(),
        )
        .unwrap();
        let refs = [&evidence];
        let method = WebAuthnMethod::new(vec![credential.clone()]).unwrap();
        let control = method
            .verify_control(PrincipalControlInput {
                principal: credential.principal(),
                verification_method: credential.verification_method(),
                signature_suite: &SignatureSuiteId::parse(P256_SUITE).unwrap(),
                purpose: ControlPurpose::CapabilityInvocation,
                signing_preimage: preimage,
                asserted_signing_time: Timestamp::new(20),
                evidence: &refs,
                evaluation_time: Timestamp::new(20),
            })
            .unwrap();
        assert!(control.signature_message().is_some());
        assert!(
            control
                .claims()
                .iter()
                .any(|claim| claim.kind().as_str() == "user-verified")
        );
        assert!(
            control
                .claims()
                .iter()
                .any(|claim| claim.kind().as_str() == "origin-bound")
        );

        let error = method
            .verify_control(PrincipalControlInput {
                principal: credential.principal(),
                verification_method: credential.verification_method(),
                signature_suite: &SignatureSuiteId::parse(P256_SUITE).unwrap(),
                purpose: ControlPurpose::CapabilityInvocation,
                signing_preimage: b"a different Auths signing preimage",
                asserted_signing_time: Timestamp::new(20),
                evidence: &refs,
                evaluation_time: Timestamp::new(20),
            })
            .unwrap_err();
        assert_eq!(error, PrincipalControlError::InvalidEvidence);
    }
}
