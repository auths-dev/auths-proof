//! Offline OIDC workload principal control.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod claims;
mod github;
pub mod identity;
mod json;
pub mod jws;
pub mod token;
pub mod window;

use alloc::{format, string::String, vec, vec::Vec};
use auths_model::{
    AdapterConfigurationId, AdapterId, BoundError, BoundedBytes, BoundedSet, EvidenceId,
    EvidenceSourceId, EvidenceTypeId, MediaType, PrincipalMethodId, VerificationMethod,
};
use auths_ports::{
    AlgorithmBinding, ControlEvidence, PrincipalControlError, PrincipalControlInput,
    PrincipalMethod, SignatureError, SignatureInput, SignatureSuite,
};
use auths_raw_key_core::{MAX_RAW_KEY_BYTES, RAW_KEY_V2_MEDIA_TYPE, RawKeyDescriptorV2};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use core::{cmp::Ordering, fmt, str};
use identity::{IssuerProfile, IssuerUrl, PolicyRejection, Subject};
use jws::{CompactJws, KeyId};
use sha2::{Digest as _, Sha256};
use token::{ClaimSet, MAX_CLAIM_BYTES};
use window::{TokenLifetime, WindowViolation};

pub const OIDC_WORKLOAD_V1: &str = "oidc-workload-v1";
pub const TOKEN_MEDIA_TYPE: &str = "application/vnd.auths.oidc-workload-token.v1";
pub const MAX_ISSUERS: usize = 16;
pub const MAX_KEYS: usize = 32;
pub const MAX_KEY_MATERIAL_BYTES: usize = 131_072;
const PARSING_WORK_UNITS: u64 = 200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JwsError {
    Limit,
    Alphabet,
    Segments,
    Encoding,
    Header,
    MissingAlgorithm,
    MissingKid,
    InvalidAlgorithm,
    InvalidKid,
    ForbiddenHeader,
    UnknownHeader,
    Type,
    Thumbprint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimError {
    Syntax,
    DuplicateMember,
    UnsupportedType,
    UnknownMember,
    MissingMember,
    WrongType,
    InvalidValue,
    InconsistentIdentity,
    Window,
    Limit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationError {
    BindingNotJws,
    UnregisteredSuite,
    InvalidKey,
    Keys(BoundError),
    Issuers(BoundError),
    Policies(BoundError),
    Lifetime,
    Model,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcError {
    PrincipalSyntax,
    UnknownIssuer,
    MissingToken,
    DuplicateToken,
    MissingKeyDescriptor,
    DuplicateKeyDescriptor,
    Jws(JwsError),
    KeyDescriptor,
    UnknownKey,
    AlgorithmMismatch,
    TokenSignature,
    SuiteContract,
    Claims(ClaimError),
    IssuerMismatch,
    SubjectMismatch,
    VerificationMethodMismatch,
    OutsideWindow(WindowViolation),
    AudienceMismatch,
    WorkloadSuiteMismatch,
    PolicyRejected(PolicyRejection),
    LimitExceeded,
}

impl fmt::Display for OidcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "oidc.{self:?}")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedIssuerKey {
    kid: KeyId,
    binding: AlgorithmBinding,
    material: BoundedBytes<MAX_KEY_MATERIAL_BYTES>,
}
impl PinnedIssuerKey {
    /// Constructs one pinned issuer verification key.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] when the binding is not JWS, its suite
    /// is unregistered, or the key material is invalid or oversized.
    pub fn new(
        kid: KeyId,
        binding: AlgorithmBinding,
        material: Vec<u8>,
        suites: &[&dyn SignatureSuite],
    ) -> Result<Self, ConfigurationError> {
        if !matches!(binding, AlgorithmBinding::Jws { .. }) {
            return Err(ConfigurationError::BindingNotJws);
        }
        let suite = suites
            .iter()
            .find(|suite| suite.id() == binding.suite())
            .ok_or(ConfigurationError::UnregisteredSuite)?;
        let material = BoundedBytes::new(material).map_err(|_| ConfigurationError::InvalidKey)?;
        suite
            .validate_key(material.as_slice())
            .map_err(|_| ConfigurationError::InvalidKey)?;
        Ok(Self {
            kid,
            binding,
            material,
        })
    }
    #[must_use]
    pub const fn kid(&self) -> &KeyId {
        &self.kid
    }
    #[must_use]
    pub const fn binding(&self) -> &AlgorithmBinding {
        &self.binding
    }
    #[must_use]
    pub fn material(&self) -> &[u8] {
        self.material.as_slice()
    }
}
impl Ord for PinnedIssuerKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.kid.cmp(&other.kid)
    }
}
impl PartialOrd for PinnedIssuerKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub type IssuerKeySet = BoundedSet<PinnedIssuerKey, MAX_KEYS>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Issuer {
    url: IssuerUrl,
    keys: IssuerKeySet,
    profile: IssuerProfile,
    lifetime: TokenLifetime,
}
impl Issuer {
    /// Constructs one bounded issuer configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] when keys are duplicated or exceed the
    /// configured issuer-key bound.
    pub fn new(
        url: IssuerUrl,
        keys: Vec<PinnedIssuerKey>,
        profile: IssuerProfile,
        lifetime: TokenLifetime,
    ) -> Result<Self, ConfigurationError> {
        Ok(Self {
            url,
            keys: BoundedSet::new(keys).map_err(ConfigurationError::Keys)?,
            profile,
            lifetime,
        })
    }
    #[must_use]
    pub const fn url(&self) -> &IssuerUrl {
        &self.url
    }
    #[must_use]
    pub const fn profile(&self) -> &IssuerProfile {
        &self.profile
    }
}
impl Ord for Issuer {
    fn cmp(&self, other: &Self) -> Ordering {
        self.url.cmp(&other.url)
    }
}
impl PartialOrd for Issuer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
pub type IssuerSet = BoundedSet<Issuer, MAX_ISSUERS>;

pub struct OidcWorkloadMethod<'a> {
    id: PrincipalMethodId,
    evidence_type: EvidenceTypeId,
    token_media: MediaType,
    descriptor_media: MediaType,
    adapter: AdapterId,
    source: EvidenceSourceId,
    issuers: IssuerSet,
    suites: &'a [&'a dyn SignatureSuite],
}
impl<'a> OidcWorkloadMethod<'a> {
    /// Constructs an OIDC workload principal method.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError`] when issuers are invalid, a suite is
    /// unregistered, or a configured bound is exceeded.
    pub fn new(
        issuers: Vec<Issuer>,
        suites: &'a [&'a dyn SignatureSuite],
    ) -> Result<Self, ConfigurationError> {
        let issuers = BoundedSet::new(issuers).map_err(ConfigurationError::Issuers)?;
        for issuer in issuers.as_slice() {
            for key in issuer.keys.as_slice() {
                let suite = suites
                    .iter()
                    .find(|suite| suite.id() == key.binding.suite())
                    .ok_or(ConfigurationError::UnregisteredSuite)?;
                suite
                    .validate_key(key.material())
                    .map_err(|_| ConfigurationError::InvalidKey)?;
            }
        }
        Ok(Self {
            id: PrincipalMethodId::parse(OIDC_WORKLOAD_V1)
                .map_err(|_| ConfigurationError::Model)?,
            evidence_type: EvidenceTypeId::parse(OIDC_WORKLOAD_V1)
                .map_err(|_| ConfigurationError::Model)?,
            token_media: MediaType::parse(TOKEN_MEDIA_TYPE)
                .map_err(|_| ConfigurationError::Model)?,
            descriptor_media: MediaType::parse(RAW_KEY_V2_MEDIA_TYPE)
                .map_err(|_| ConfigurationError::Model)?,
            adapter: AdapterId::parse(OIDC_WORKLOAD_V1).map_err(|_| ConfigurationError::Model)?,
            source: EvidenceSourceId::parse("adapter:oidc-workload-v1")
                .map_err(|_| ConfigurationError::Model)?,
            issuers,
            suites,
        })
    }

    /// Verifies one OIDC workload token and bound key descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`OidcError`] for malformed or inconsistent evidence, failed
    /// token verification, invalid time/audience binding, or policy rejection.
    pub fn verify_detailed(
        &self,
        input: &PrincipalControlInput<'_>,
    ) -> Result<ControlEvidence, OidcError> {
        let (principal_issuer, principal_subject) = parse_principal(input.principal.as_str())?;
        let issuer = self
            .issuers
            .as_slice()
            .iter()
            .find(|candidate| candidate.url == principal_issuer)
            .ok_or(OidcError::UnknownIssuer)?;
        let (token_evidence, descriptor_evidence) = self.select_evidence(input.evidence)?;
        let jws = CompactJws::parse(token_evidence.bytes()).map_err(OidcError::Jws)?;
        let descriptor = RawKeyDescriptorV2::decode(descriptor_evidence.bytes())
            .map_err(|_| OidcError::KeyDescriptor)?;
        let key = issuer
            .keys
            .as_slice()
            .iter()
            .find(|key| key.kid == jws.header.kid)
            .ok_or(OidcError::UnknownKey)?;
        let AlgorithmBinding::Jws { algorithm, suite } = &key.binding else {
            return Err(OidcError::SuiteContract);
        };
        if algorithm != &jws.header.alg {
            return Err(OidcError::AlgorithmMismatch);
        }
        let verifier = self
            .suites
            .iter()
            .find(|candidate| candidate.id() == suite)
            .ok_or(OidcError::SuiteContract)?;
        verifier
            .verify(SignatureInput {
                verification_key: key.material(),
                signing_preimage: &jws.signing_input,
                signature: &jws.signature,
            })
            .map_err(|error| match error {
                SignatureError::InvalidKey => OidcError::SuiteContract,
                SignatureError::InvalidSignature | SignatureError::InvalidSignatureEncoding => {
                    OidcError::TokenSignature
                }
            })?;
        let claims = ClaimSet::parse(&jws.payload, &issuer.profile, issuer.lifetime)?;
        if claims.common().iss != issuer.url {
            return Err(OidcError::IssuerMismatch);
        }
        if claims.common().sub != principal_subject {
            return Err(OidcError::SubjectMismatch);
        }
        let method = verification_method(input.principal.as_str(), token_evidence.bytes())
            .map_err(|_| OidcError::LimitExceeded)?;
        if &method != input.verification_method {
            return Err(OidcError::VerificationMethodMismatch);
        }
        claims.common().window.admits_live(input.evaluation_time)?;
        if claims.common().aud.as_str() != audience_commitment(&descriptor) {
            return Err(OidcError::AudienceMismatch);
        }
        if descriptor.suite_id() != input.signature_suite {
            return Err(OidcError::WorkloadSuiteMismatch);
        }
        let issued_at = claims.common().window.issued().get();
        let expires_at = claims.common().window.expires().get();
        let identity = claims.into_identity()?;
        let admitted = issuer
            .profile
            .admit(&identity)
            .map_err(OidcError::PolicyRejected)?;
        let mut assurance = claims::assurance_claims(&admitted, &self.source)
            .map_err(|_| OidcError::LimitExceeded)?;
        assurance.push(
            claims::token_window_claim(issued_at, expires_at, &self.source)
                .map_err(|_| OidcError::LimitExceeded)?,
        );
        ControlEvidence::new(
            descriptor.public_key().to_vec(),
            assurance,
            vec![
                EvidenceId::new(*token_evidence.id().as_bytes()),
                EvidenceId::new(*descriptor_evidence.id().as_bytes()),
            ],
            self.adapter.clone(),
            1,
            self.maximum_work_units(),
        )
        .map_err(|_| OidcError::LimitExceeded)
    }

    fn select_evidence<'b>(
        &self,
        evidence: &'b [&'b auths_model::EvidenceObject],
    ) -> Result<
        (
            &'b auths_model::EvidenceObject,
            &'b auths_model::EvidenceObject,
        ),
        OidcError,
    > {
        let mut token = None;
        let mut descriptor = None;
        for item in evidence
            .iter()
            .copied()
            .filter(|item| item.evidence_type() == &self.evidence_type)
        {
            if item.media_type() == &self.token_media {
                if token.replace(item).is_some() {
                    return Err(OidcError::DuplicateToken);
                }
            } else if item.media_type() == &self.descriptor_media
                && descriptor.replace(item).is_some()
            {
                return Err(OidcError::DuplicateKeyDescriptor);
            }
        }
        Ok((
            token.ok_or(OidcError::MissingToken)?,
            descriptor.ok_or(OidcError::MissingKeyDescriptor)?,
        ))
    }
}

impl PrincipalMethod for OidcWorkloadMethod<'_> {
    fn id(&self) -> &PrincipalMethodId {
        &self.id
    }
    fn configuration_id(&self) -> AdapterConfigurationId {
        let mut components = Vec::new();
        for issuer in self.issuers.as_slice() {
            components.push(issuer.url.as_str().as_bytes().to_vec());
            components.push(issuer.lifetime.get().to_be_bytes().to_vec());
            components.extend(issuer.profile.configuration_components());
            for key in issuer.keys.as_slice() {
                components.push(key.kid.as_str().as_bytes().to_vec());
                components.push(key.material().to_vec());
                match &key.binding {
                    AlgorithmBinding::Jws { algorithm, suite } => {
                        components.push(algorithm.as_str().as_bytes().to_vec());
                        components.push(suite.as_str().as_bytes().to_vec());
                    }
                    AlgorithmBinding::Spki { .. } => {}
                }
                if let Some(suite) = self
                    .suites
                    .iter()
                    .find(|suite| suite.id() == key.binding.suite())
                {
                    components.push(suite.configuration_id().as_bytes().to_vec());
                }
            }
        }
        auths_ports::configuration_id(
            b"auths-oidc-workload-v1",
            components.iter().map(Vec::as_slice),
        )
    }
    fn maximum_work_units(&self) -> u64 {
        PARSING_WORK_UNITS.saturating_add(
            self.suites
                .iter()
                .map(|suite| suite.work_units())
                .max()
                .unwrap_or(0),
        )
    }
    fn verify_control(
        &self,
        input: PrincipalControlInput<'_>,
    ) -> Result<ControlEvidence, PrincipalControlError> {
        self.verify_detailed(&input).map_err(map_error)
    }
}

#[must_use]
pub fn audience_commitment(descriptor: &RawKeyDescriptorV2) -> String {
    let digest: [u8; 32] = Sha256::digest(descriptor.encode()).into();
    format!(
        "auths-oidc-workload-v1:{}",
        Base64UrlUnpadded::encode_string(&digest)
    )
}

/// Derives the token-bound verification method for one principal.
///
/// # Errors
///
/// Returns [`auths_model::ModelError`] when the resulting method identifier
/// violates model bounds or syntax.
pub fn verification_method(
    principal: &str,
    token: &[u8],
) -> Result<VerificationMethod, auths_model::ModelError> {
    let digest: [u8; 32] = Sha256::digest(token).into();
    let encoded = Base64UrlUnpadded::encode_string(&digest);
    VerificationMethod::parse(&format!("{principal}#oidc-{}", &encoded[..16]))
}

/// Constructs the canonical OIDC workload principal identifier.
///
/// # Errors
///
/// Returns [`auths_model::ModelError`] when the encoded principal exceeds a
/// model bound or violates principal syntax.
pub fn principal(
    issuer: &IssuerUrl,
    subject: &Subject,
) -> Result<auths_model::PrincipalId, auths_model::ModelError> {
    auths_model::PrincipalId::parse(&format!(
        "oidc-workload:{}#{}",
        pct_encode(issuer.as_str().as_bytes()),
        pct_encode(subject.as_str().as_bytes())
    ))
}

fn parse_principal(value: &str) -> Result<(IssuerUrl, Subject), OidcError> {
    let rest = value
        .strip_prefix("oidc-workload:")
        .ok_or(OidcError::PrincipalSyntax)?;
    let (issuer_encoded, subject_encoded) =
        rest.split_once('#').ok_or(OidcError::PrincipalSyntax)?;
    if subject_encoded.contains('#') {
        return Err(OidcError::PrincipalSyntax);
    }
    let issuer = pct_decode(issuer_encoded)?;
    let subject = pct_decode(subject_encoded)?;
    if pct_encode(issuer.as_bytes()) != issuer_encoded
        || pct_encode(subject.as_bytes()) != subject_encoded
    {
        return Err(OidcError::PrincipalSyntax);
    }
    Ok((
        IssuerUrl::parse(&issuer).map_err(|_| OidcError::PrincipalSyntax)?,
        Subject::parse(&subject).map_err(|_| OidcError::PrincipalSyntax)?,
    ))
}

fn pct_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::new();
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(*byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    output
}
fn pct_decode(value: &str) -> Result<String, OidcError> {
    let bytes = value.as_bytes();
    let mut output = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] == b'%' {
            let pair = bytes
                .get(cursor + 1..cursor + 3)
                .ok_or(OidcError::PrincipalSyntax)?;
            output.push((hex(pair[0])? << 4) | hex(pair[1])?);
            cursor += 3;
        } else {
            output.push(bytes[cursor]);
            cursor += 1;
        }
    }
    String::from_utf8(output).map_err(|_| OidcError::PrincipalSyntax)
}
fn hex(byte: u8) -> Result<u8, OidcError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(OidcError::PrincipalSyntax),
    }
}

fn map_error(error: OidcError) -> PrincipalControlError {
    match error {
        OidcError::PrincipalSyntax | OidcError::IssuerMismatch | OidcError::SubjectMismatch => {
            PrincipalControlError::PrincipalMethodMismatch
        }
        OidcError::VerificationMethodMismatch => PrincipalControlError::VerificationMethodMismatch,
        OidcError::MissingToken | OidcError::MissingKeyDescriptor => {
            PrincipalControlError::MissingEvidence
        }
        OidcError::WorkloadSuiteMismatch => PrincipalControlError::SignatureSuiteMismatch,
        OidcError::SuiteContract => PrincipalControlError::ExternalFactUnavailable,
        OidcError::LimitExceeded => PrincipalControlError::ResourceLimitExceeded,
        _ => PrincipalControlError::InvalidEvidence,
    }
}

const _: usize = MAX_RAW_KEY_BYTES;
const _: usize = MAX_CLAIM_BYTES;

#[cfg(test)]
mod tests {
    use super::*;
    use auths_ports::JwsAlgorithmName;
    use auths_signature::Ed25519Suite;
    use ed25519_dalek::SigningKey;

    #[test]
    fn principal_encoding_is_exact_and_canonical() {
        let issuer = IssuerUrl::parse("https://token.actions.githubusercontent.com").unwrap();
        let subject = Subject::parse("repo:auths-dev/auths-proof:ref:refs/heads/main").unwrap();
        let value = principal(&issuer, &subject).unwrap();
        assert_eq!(parse_principal(value.as_str()).unwrap(), (issuer, subject));
        assert_eq!(
            parse_principal(&value.as_str().replace("%3A", "%3a")),
            Err(OidcError::PrincipalSyntax)
        );
    }

    #[test]
    fn pinned_keys_validate_binding_and_material_at_construction() {
        let suite = Ed25519Suite::new().unwrap();
        let suites: &[&dyn SignatureSuite] = &[&suite];
        let binding = AlgorithmBinding::Jws {
            algorithm: JwsAlgorithmName::parse("EdDSA").unwrap(),
            suite: suite.id().clone(),
        };
        let key = SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes()
            .to_vec();
        assert!(PinnedIssuerKey::new(KeyId::parse("key-1").unwrap(), binding, key, suites).is_ok());
    }
}
