//! Pure verification of explicitly trusted, bundled `did:web` documents.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{
    collections::BTreeSet,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use auths_proof_adapter_api::{
    ControlProofInput, PrincipalControlError, PrincipalControlVerifier, VerifiedPrincipal,
};
use auths_proof_codec::evidence_id;
use auths_proof_model::{
    AdapterId, AssuranceClaim, AssuranceClaims, EvidenceBytes, EvidenceMediaType, ModelError,
    PrincipalEvidenceEntry, PrincipalRef, ProofPurpose, Timestamp, VerificationMethodRef,
};
use auths_proof_multikey::{Multikey, MultikeyError};
use core::{fmt, str};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const ADAPTER_ID: &str = "did-web-v1";
pub const EVIDENCE_MEDIA_TYPE: &str = "application/vnd.auths.did-web-document.v1";
pub const PRINCIPAL_PREFIX: &str = "did:web:";
pub const EVIDENCE_DOMAIN: &[u8] = b"auths-proof/did-web/evidence/v1\0";
pub const TRUST_RECORD_DOMAIN: &[u8] = b"auths-proof/did-web/trust-record/v1\0";

const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
const MAX_DOCUMENT_BYTES: usize = 128 * 1024;
const MAX_METHODS: usize = 32;
const MAX_RELATIONSHIPS: usize = 64;
const ROOT_FIELDS: &[&str] = &[
    "@context",
    "id",
    "verificationMethod",
    "authentication",
    "assertionMethod",
    "capabilityInvocation",
    "capabilityDelegation",
    "service",
    "alsoKnownAs",
    "controller",
];
const METHOD_FIELDS: &[&str] = &["id", "type", "controller", "publicKeyMultibase"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidWebId {
    principal: PrincipalRef,
    host: String,
    port: Option<u16>,
    path: Vec<String>,
}

impl DidWebId {
    pub fn parse(value: &str) -> Result<Self, DidWebError> {
        let method_specific = value
            .strip_prefix(PRINCIPAL_PREFIX)
            .ok_or(DidWebError::InvalidDid)?;
        if method_specific.is_empty() || !method_specific.is_ascii() {
            return Err(DidWebError::InvalidDid);
        }
        let mut parts = method_specific.split(':');
        let authority = parts.next().ok_or(DidWebError::InvalidDid)?;
        let path = parts
            .map(|part| {
                if part.is_empty()
                    || !part.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
                    })
                    || part == "."
                    || part == ".."
                {
                    Err(DidWebError::InvalidDid)
                } else {
                    Ok(part.to_string())
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (host, port) = parse_authority(authority)?;
        Ok(Self {
            principal: PrincipalRef::parse(value)?,
            host,
            port,
            path,
        })
    }

    pub const fn principal(&self) -> &PrincipalRef {
        &self.principal
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    pub fn resolution_url(&self) -> String {
        let authority = match self.port {
            Some(port) => format!("{}:{port}", self.host),
            None => self.host.clone(),
        };
        if self.path.is_empty() {
            format!("https://{authority}/.well-known/did.json")
        } else {
            format!("https://{authority}/{}/did.json", self.path.join("/"))
        }
    }
}

fn parse_authority(value: &str) -> Result<(String, Option<u16>), DidWebError> {
    if value.is_empty() || value.contains('%') && !value.contains("%3A") {
        return Err(DidWebError::InvalidDid);
    }
    let mut pieces = value.split("%3A");
    let host = pieces.next().ok_or(DidWebError::InvalidDid)?;
    let port = match pieces.next() {
        Some(value) => Some(
            value
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or(DidWebError::InvalidDid)?,
        ),
        None => None,
    };
    if pieces.next().is_some()
        || host.len() > 253
        || host.starts_with('.')
        || host.ends_with('.')
        || !host.contains('.')
        || host.bytes().any(|byte| {
            !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.'))
        })
        || host.split('.').any(|label| {
            label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
        })
        || host
            .split('.')
            .all(|label| label.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(DidWebError::InvalidDid);
    }
    Ok((host.to_string(), port))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidWebEvidence {
    document: Vec<u8>,
}

impl DidWebEvidence {
    pub fn from_document(document: &[u8]) -> Result<Self, DidWebError> {
        if document.is_empty() || document.len() > MAX_DOCUMENT_BYTES {
            return Err(DidWebError::LimitExceeded);
        }
        let value: Value =
            serde_json::from_slice(document).map_err(|_| DidWebError::InvalidDocument)?;
        let canonical = serde_json::to_vec(&value).map_err(|_| DidWebError::InvalidDocument)?;
        if canonical != document {
            return Err(DidWebError::NonCanonicalDocument);
        }
        Ok(Self {
            document: canonical,
        })
    }

    pub fn canonicalize(document: &[u8]) -> Result<Self, DidWebError> {
        if document.is_empty() || document.len() > MAX_DOCUMENT_BYTES {
            return Err(DidWebError::LimitExceeded);
        }
        let value: Value =
            serde_json::from_slice(document).map_err(|_| DidWebError::InvalidDocument)?;
        let canonical = serde_json::to_vec(&value).map_err(|_| DidWebError::InvalidDocument)?;
        Self::from_document(&canonical)
    }

    pub fn document(&self) -> &[u8] {
        &self.document
    }

    pub fn document_digest(&self) -> [u8; 32] {
        Sha256::digest(&self.document).into()
    }

    pub fn encode(&self) -> Result<Vec<u8>, DidWebError> {
        let len = u32::try_from(self.document.len()).map_err(|_| DidWebError::LimitExceeded)?;
        let mut output = Vec::with_capacity(EVIDENCE_DOMAIN.len() + 4 + self.document.len());
        output.extend_from_slice(EVIDENCE_DOMAIN);
        output.extend_from_slice(&len.to_be_bytes());
        output.extend_from_slice(&self.document);
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DidWebError> {
        if !bytes.starts_with(EVIDENCE_DOMAIN) {
            return Err(DidWebError::InvalidEvidence);
        }
        let offset = EVIDENCE_DOMAIN.len();
        let length = bytes
            .get(offset..offset + 4)
            .ok_or(DidWebError::InvalidEvidence)?;
        let length = u32::from_be_bytes([length[0], length[1], length[2], length[3]]) as usize;
        let document = bytes
            .get(offset + 4..)
            .ok_or(DidWebError::InvalidEvidence)?;
        if document.len() != length {
            return Err(DidWebError::InvalidEvidence);
        }
        Self::from_document(document)
    }

    pub fn evidence_entry(&self) -> Result<PrincipalEvidenceEntry, DidWebError> {
        let adapter = AdapterId::parse(ADAPTER_ID)?;
        let media_type = EvidenceMediaType::parse(EVIDENCE_MEDIA_TYPE)?;
        let bytes = self.encode()?;
        let id = evidence_id(&adapter, &media_type, &bytes);
        Ok(PrincipalEvidenceEntry::new(
            id,
            adapter,
            media_type,
            EvidenceBytes::new(bytes)?,
        ))
    }

    pub fn validate_for(&self, principal: &PrincipalRef) -> Result<(), DidWebError> {
        parse_document(self, principal).map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoricalStatementPin {
    signing_bytes_digest: [u8; 32],
    existed_at: Timestamp,
}

impl HistoricalStatementPin {
    pub fn new(signing_bytes: &[u8], existed_at: Timestamp) -> Self {
        Self {
            signing_bytes_digest: Sha256::digest(signing_bytes).into(),
            existed_at,
        }
    }

    pub const fn signing_bytes_digest(self) -> [u8; 32] {
        self.signing_bytes_digest
    }

    pub const fn existed_at(self) -> Timestamp {
        self.existed_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DidWebTrustRecord {
    Current {
        principal: PrincipalRef,
        document_digest: [u8; 32],
        observed_at: Timestamp,
        valid_until: Timestamp,
    },
    Historical {
        principal: PrincipalRef,
        document_digest: [u8; 32],
        valid_from: Timestamp,
        valid_until: Timestamp,
        statement: Option<HistoricalStatementPin>,
    },
}

impl DidWebTrustRecord {
    pub fn current(
        principal: PrincipalRef,
        document_digest: [u8; 32],
        observed_at: Timestamp,
        valid_until: Timestamp,
    ) -> Result<Self, DidWebError> {
        if observed_at > valid_until {
            return Err(DidWebError::InvalidTrustRecord);
        }
        Ok(Self::Current {
            principal,
            document_digest,
            observed_at,
            valid_until,
        })
    }

    pub fn historical(
        principal: PrincipalRef,
        document_digest: [u8; 32],
        valid_from: Timestamp,
        valid_until: Timestamp,
        statement: Option<HistoricalStatementPin>,
    ) -> Result<Self, DidWebError> {
        if valid_from > valid_until
            || statement
                .is_some_and(|pin| pin.existed_at < valid_from || pin.existed_at > valid_until)
        {
            return Err(DidWebError::InvalidTrustRecord);
        }
        Ok(Self::Historical {
            principal,
            document_digest,
            valid_from,
            valid_until,
            statement,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, DidWebError> {
        let mut output = Vec::new();
        output.extend_from_slice(TRUST_RECORD_DOMAIN);
        match self {
            Self::Current {
                principal,
                document_digest,
                observed_at,
                valid_until,
            } => {
                output.push(1);
                write_principal(&mut output, principal)?;
                output.extend_from_slice(document_digest);
                output.extend_from_slice(&observed_at.as_secs().to_be_bytes());
                output.extend_from_slice(&valid_until.as_secs().to_be_bytes());
            }
            Self::Historical {
                principal,
                document_digest,
                valid_from,
                valid_until,
                statement,
            } => {
                output.push(2);
                write_principal(&mut output, principal)?;
                output.extend_from_slice(document_digest);
                output.extend_from_slice(&valid_from.as_secs().to_be_bytes());
                output.extend_from_slice(&valid_until.as_secs().to_be_bytes());
                match statement {
                    Some(pin) => {
                        output.push(1);
                        output.extend_from_slice(&pin.signing_bytes_digest);
                        output.extend_from_slice(&pin.existed_at.as_secs().to_be_bytes());
                    }
                    None => output.push(0),
                }
            }
        }
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DidWebError> {
        let mut reader = Reader::new(bytes);
        if reader.take(TRUST_RECORD_DOMAIN.len())? != TRUST_RECORD_DOMAIN {
            return Err(DidWebError::InvalidTrustRecord);
        }
        let tag = reader.byte()?;
        let principal_len = usize::from(reader.u16()?);
        let principal = PrincipalRef::parse(
            str::from_utf8(reader.take(principal_len)?)
                .map_err(|_| DidWebError::InvalidTrustRecord)?,
        )?;
        let document_digest: [u8; 32] = reader
            .take(32)?
            .try_into()
            .map_err(|_| DidWebError::InvalidTrustRecord)?;
        let first = Timestamp::new(reader.u64()?);
        let second = Timestamp::new(reader.u64()?);
        let record = match tag {
            1 if reader.finished() => Self::current(principal, document_digest, first, second)?,
            2 => {
                let statement = match reader.byte()? {
                    0 => None,
                    1 => {
                        let signing_bytes_digest = reader
                            .take(32)?
                            .try_into()
                            .map_err(|_| DidWebError::InvalidTrustRecord)?;
                        Some(HistoricalStatementPin {
                            signing_bytes_digest,
                            existed_at: Timestamp::new(reader.u64()?),
                        })
                    }
                    _ => return Err(DidWebError::InvalidTrustRecord),
                };
                if !reader.finished() {
                    return Err(DidWebError::InvalidTrustRecord);
                }
                Self::historical(principal, document_digest, first, second, statement)?
            }
            _ => return Err(DidWebError::InvalidTrustRecord),
        };
        Ok(record)
    }
}

fn write_principal(output: &mut Vec<u8>, principal: &PrincipalRef) -> Result<(), DidWebError> {
    let bytes = principal.as_str().as_bytes();
    let len = u16::try_from(bytes.len()).map_err(|_| DidWebError::InvalidTrustRecord)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], DidWebError> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(DidWebError::InvalidTrustRecord)?;
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or(DidWebError::InvalidTrustRecord)?;
        self.cursor = end;
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, DidWebError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, DidWebError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u64(&mut self) -> Result<u64, DidWebError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(
            bytes
                .try_into()
                .map_err(|_| DidWebError::InvalidTrustRecord)?,
        ))
    }

    const fn finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

pub struct DidWebAdapter {
    adapter_id: AdapterId,
    media_type: EvidenceMediaType,
    trust: Vec<DidWebTrustRecord>,
}

impl DidWebAdapter {
    pub fn new(trust: Vec<DidWebTrustRecord>) -> Result<Self, DidWebError> {
        if trust.len() > 256 {
            return Err(DidWebError::LimitExceeded);
        }
        Ok(Self {
            adapter_id: AdapterId::parse(ADAPTER_ID)?,
            media_type: EvidenceMediaType::parse(EVIDENCE_MEDIA_TYPE)?,
            trust,
        })
    }
}

impl PrincipalControlVerifier for DidWebAdapter {
    fn adapter_id(&self) -> &AdapterId {
        &self.adapter_id
    }

    fn supports(&self, principal: &PrincipalRef) -> bool {
        DidWebId::parse(principal.as_str()).is_ok()
    }

    fn verify_control(
        &self,
        input: ControlProofInput<'_>,
    ) -> Result<VerifiedPrincipal, PrincipalControlError> {
        if !self.supports(input.principal) {
            return Err(PrincipalControlError::UnsupportedPrincipal);
        }
        if input.evidence.method() != &self.adapter_id
            || input.evidence.media_type() != &self.media_type
        {
            return Err(PrincipalControlError::AdapterMismatch);
        }
        let evidence = DidWebEvidence::decode(input.evidence.bytes().as_slice())
            .map_err(map_evidence_error)?;
        let document = parse_document(&evidence, input.principal).map_err(map_evidence_error)?;
        let method = document
            .method(input.verification_method, input.purpose)
            .map_err(|_| PrincipalControlError::VerificationMethodMismatch)?;
        if input.algorithm.as_str() != method.key.key_type().algorithm() {
            return Err(PrincipalControlError::AlgorithmMismatch);
        }
        let mut claims = trust_claims(&self.trust, &input, evidence.document_digest())
            .map_err(map_evidence_error)?;
        method
            .key
            .verify(
                input.algorithm.as_str(),
                input.signing_bytes,
                input.signature,
            )
            .map_err(|error| match error {
                MultikeyError::AlgorithmMismatch => PrincipalControlError::AlgorithmMismatch,
                _ => PrincipalControlError::InvalidSignature,
            })?;
        claims.push(AssuranceClaim::OfflineVerifiable);
        claims.push(AssuranceClaim::RotationAware);

        Ok(VerifiedPrincipal::verified(
            input.principal.clone(),
            input.verification_method.clone(),
            self.adapter_id.clone(),
            input.evidence.id(),
            AssuranceClaims::new(claims),
        ))
    }
}

fn trust_claims(
    records: &[DidWebTrustRecord],
    input: &ControlProofInput<'_>,
    document_digest: [u8; 32],
) -> Result<Vec<AssuranceClaim>, DidWebError> {
    for record in records {
        if let DidWebTrustRecord::Current {
            principal,
            document_digest: expected,
            observed_at,
            valid_until,
        } = record
        {
            if principal == input.principal
                && expected == &document_digest
                && *observed_at <= input.verification_time
                && input.verification_time <= *valid_until
            {
                return Ok(vec![
                    AssuranceClaim::ControllerStateCurrentAt(*observed_at),
                    AssuranceClaim::RevocationCheckedAt(*observed_at),
                ]);
            }
        }
    }

    let mut document_only_history = None;
    for record in records {
        if let DidWebTrustRecord::Historical {
            principal,
            document_digest: expected,
            valid_from,
            valid_until,
            statement,
        } = record
        {
            if principal == input.principal
                && expected == &document_digest
                && *valid_from <= input.asserted_signing_time
                && input.asserted_signing_time <= *valid_until
            {
                let mut claims = vec![AssuranceClaim::ControllerStateHistoricalAt(
                    input.asserted_signing_time,
                )];
                if let Some(pin) = statement {
                    let actual: [u8; 32] = Sha256::digest(input.signing_bytes).into();
                    if pin.signing_bytes_digest == actual
                        && pin.existed_at >= input.asserted_signing_time
                        && pin.existed_at <= *valid_until
                    {
                        claims.push(AssuranceClaim::StatementExistenceProvenAt(pin.existed_at));
                        return Ok(claims);
                    }
                }
                document_only_history = Some(claims);
            }
        }
    }
    document_only_history.ok_or(DidWebError::UntrustedDocument)
}

struct ParsedDocument {
    methods: Vec<ParsedMethod>,
    capability_delegation: BTreeSet<String>,
    capability_invocation: BTreeSet<String>,
}

struct ParsedMethod {
    id: VerificationMethodRef,
    key: Multikey,
}

impl ParsedDocument {
    fn method(
        &self,
        requested: &VerificationMethodRef,
        purpose: ProofPurpose,
    ) -> Result<&ParsedMethod, DidWebError> {
        let relationship = match purpose {
            ProofPurpose::CapabilityDelegation => &self.capability_delegation,
            ProofPurpose::CapabilityInvocation => &self.capability_invocation,
        };
        if !relationship.contains(requested.as_str()) {
            return Err(DidWebError::WrongVerificationRelationship);
        }
        self.methods
            .iter()
            .find(|method| method.id == *requested)
            .ok_or(DidWebError::UnknownVerificationMethod)
    }
}

fn parse_document(
    evidence: &DidWebEvidence,
    principal: &PrincipalRef,
) -> Result<ParsedDocument, DidWebError> {
    let value: Value =
        serde_json::from_slice(evidence.document()).map_err(|_| DidWebError::InvalidDocument)?;
    let object = value.as_object().ok_or(DidWebError::InvalidDocument)?;
    if object
        .keys()
        .any(|key| !ROOT_FIELDS.contains(&key.as_str()))
    {
        return Err(DidWebError::UnsupportedDocumentFeature);
    }
    validate_context(object.get("@context"))?;
    if text(object, "id")? != principal.as_str() {
        return Err(DidWebError::DocumentIdMismatch);
    }
    let method_values = array(object, "verificationMethod")?;
    if method_values.is_empty() || method_values.len() > MAX_METHODS {
        return Err(DidWebError::LimitExceeded);
    }
    let mut ids = BTreeSet::new();
    let mut methods = Vec::with_capacity(method_values.len());
    for value in method_values {
        let method = value.as_object().ok_or(DidWebError::InvalidDocument)?;
        if method.len() != METHOD_FIELDS.len()
            || method
                .keys()
                .any(|key| !METHOD_FIELDS.contains(&key.as_str()))
            || text(method, "type")? != "Multikey"
            || text(method, "controller")? != principal.as_str()
        {
            return Err(DidWebError::UnsupportedDocumentFeature);
        }
        let id = VerificationMethodRef::parse(text(method, "id")?)?;
        if !id.as_str().starts_with(&format!("{}#", principal.as_str())) || !ids.insert(id.clone())
        {
            return Err(DidWebError::InvalidDocument);
        }
        methods.push(ParsedMethod {
            id,
            key: Multikey::parse(text(method, "publicKeyMultibase")?)?,
        });
    }
    Ok(ParsedDocument {
        methods,
        capability_delegation: relationship(object, "capabilityDelegation")?,
        capability_invocation: relationship(object, "capabilityInvocation")?,
    })
}

fn validate_context(value: Option<&Value>) -> Result<(), DidWebError> {
    match value {
        Some(Value::String(context)) if context == DID_CONTEXT => Ok(()),
        Some(Value::Array(contexts))
            if contexts.len() == 1 && contexts[0].as_str() == Some(DID_CONTEXT) =>
        {
            Ok(())
        }
        _ => Err(DidWebError::UnsupportedDocumentFeature),
    }
}

fn text<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, DidWebError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(DidWebError::InvalidDocument)
}

fn array<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Vec<Value>, DidWebError> {
    object
        .get(key)
        .and_then(Value::as_array)
        .ok_or(DidWebError::InvalidDocument)
}

fn relationship(object: &Map<String, Value>, key: &str) -> Result<BTreeSet<String>, DidWebError> {
    let values = array(object, key)?;
    if values.is_empty() || values.len() > MAX_RELATIONSHIPS {
        return Err(DidWebError::LimitExceeded);
    }
    let relationship = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToString::to_string)
                .ok_or(DidWebError::UnsupportedDocumentFeature)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if relationship.len() != values.len() {
        return Err(DidWebError::InvalidDocument);
    }
    Ok(relationship)
}

fn map_evidence_error(error: DidWebError) -> PrincipalControlError {
    match error {
        DidWebError::LimitExceeded => PrincipalControlError::ResourceLimitExceeded,
        _ => PrincipalControlError::InvalidEvidence,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DidWebError {
    Model(ModelError),
    Multikey(MultikeyError),
    InvalidDid,
    InvalidEvidence,
    InvalidDocument,
    NonCanonicalDocument,
    UnsupportedDocumentFeature,
    DocumentIdMismatch,
    UnknownVerificationMethod,
    WrongVerificationRelationship,
    InvalidTrustRecord,
    UntrustedDocument,
    LimitExceeded,
    InvalidSecretKey,
}

impl From<ModelError> for DidWebError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl From<MultikeyError> for DidWebError {
    fn from(error: MultikeyError) -> Self {
        Self::Multikey(error)
    }
}

impl fmt::Display for DidWebError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Model(_) => "invalid Auths model value",
            Self::Multikey(_) => "invalid Multikey",
            Self::InvalidDid => "invalid or unsupported did:web identifier",
            Self::InvalidEvidence => "invalid did:web evidence envelope",
            Self::InvalidDocument => "invalid DID document",
            Self::NonCanonicalDocument => "non-canonical bundled DID document",
            Self::UnsupportedDocumentFeature => "unsupported DID document feature",
            Self::DocumentIdMismatch => "DID document id does not match principal",
            Self::UnknownVerificationMethod => "unknown DID verification method",
            Self::WrongVerificationRelationship => "wrong DID verification relationship",
            Self::InvalidTrustRecord => "invalid did:web trust record",
            Self::UntrustedDocument => "DID document is not explicitly trusted",
            Self::LimitExceeded => "did:web evidence exceeds a resource limit",
            Self::InvalidSecretKey => "invalid test signing key",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DidWebError {}

#[cfg(any(test, feature = "test-signing"))]
pub mod test_signing {
    use super::*;
    use auths_proof_model::{AlgorithmId, SignatureDescriptor};
    use auths_proof_multikey::MultikeyType;
    use ed25519_dalek::{Signer as _, SigningKey};

    pub struct TestDidWebIdentity {
        principal: PrincipalRef,
        method: VerificationMethodRef,
        evidence: DidWebEvidence,
        seed: [u8; 32],
    }

    impl TestDidWebIdentity {
        pub fn ed25519(did: &str, seed: [u8; 32]) -> Result<Self, DidWebError> {
            let principal = DidWebId::parse(did)?.principal().clone();
            let signing_key = SigningKey::from_bytes(&seed);
            let multikey = Multikey::from_public_key(
                MultikeyType::Ed25519,
                signing_key.verifying_key().to_bytes().to_vec(),
            )?;
            let method = VerificationMethodRef::parse(&format!("{}#key-1", principal.as_str()))?;
            let document = build_document(&principal, &method, multikey.encoded())?;
            Ok(Self {
                principal,
                method,
                evidence: DidWebEvidence::from_document(&document)?,
                seed,
            })
        }

        pub const fn principal(&self) -> &PrincipalRef {
            &self.principal
        }

        pub const fn evidence(&self) -> &DidWebEvidence {
            &self.evidence
        }

        pub fn evidence_entry(&self) -> Result<PrincipalEvidenceEntry, DidWebError> {
            self.evidence.evidence_entry()
        }

        pub fn signature_descriptor(&self) -> Result<SignatureDescriptor, ModelError> {
            Ok(SignatureDescriptor::new(
                AdapterId::parse(ADAPTER_ID)?,
                self.method.clone(),
                AlgorithmId::parse(auths_proof_multikey::ED25519_ALGORITHM)?,
            ))
        }

        pub fn sign(&self, message: &[u8]) -> Vec<u8> {
            SigningKey::from_bytes(&self.seed)
                .sign(message)
                .to_bytes()
                .to_vec()
        }

        pub fn current_trust(
            &self,
            observed_at: Timestamp,
            valid_until: Timestamp,
        ) -> Result<DidWebTrustRecord, DidWebError> {
            DidWebTrustRecord::current(
                self.principal.clone(),
                self.evidence.document_digest(),
                observed_at,
                valid_until,
            )
        }

        pub fn historical_trust(
            &self,
            valid_from: Timestamp,
            valid_until: Timestamp,
            statement: Option<HistoricalStatementPin>,
        ) -> Result<DidWebTrustRecord, DidWebError> {
            DidWebTrustRecord::historical(
                self.principal.clone(),
                self.evidence.document_digest(),
                valid_from,
                valid_until,
                statement,
            )
        }
    }

    fn build_document(
        principal: &PrincipalRef,
        method: &VerificationMethodRef,
        multikey: &str,
    ) -> Result<Vec<u8>, DidWebError> {
        let mut verification_method = Map::new();
        verification_method.insert("id".into(), Value::String(method.as_str().into()));
        verification_method.insert("type".into(), Value::String("Multikey".into()));
        verification_method.insert(
            "controller".into(),
            Value::String(principal.as_str().into()),
        );
        verification_method.insert("publicKeyMultibase".into(), Value::String(multikey.into()));
        let relationship = Value::Array(vec![Value::String(method.as_str().into())]);
        let mut document = Map::new();
        document.insert("@context".into(), Value::String(DID_CONTEXT.into()));
        document.insert("id".into(), Value::String(principal.as_str().into()));
        document.insert(
            "verificationMethod".into(),
            Value::Array(vec![Value::Object(verification_method)]),
        );
        document.insert("authentication".into(), relationship.clone());
        document.insert("assertionMethod".into(), relationship.clone());
        document.insert("capabilityInvocation".into(), relationship.clone());
        document.insert("capabilityDelegation".into(), relationship);
        serde_json::to_vec(&Value::Object(document)).map_err(|_| DidWebError::InvalidDocument)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_proof_adapter_api::ControlProofInput;

    #[test]
    fn maps_did_to_spec_https_url() {
        assert_eq!(
            DidWebId::parse("did:web:example.com")
                .expect("did")
                .resolution_url(),
            "https://example.com/.well-known/did.json"
        );
        assert_eq!(
            DidWebId::parse("did:web:example.com%3A8443:users:alice")
                .expect("did")
                .resolution_url(),
            "https://example.com:8443/users/alice/did.json"
        );
    }

    #[test]
    fn current_document_verifies_without_network() {
        let identity = test_signing::TestDidWebIdentity::ed25519("did:web:example.com", [91; 32])
            .expect("identity");
        let descriptor = identity.signature_descriptor().expect("descriptor");
        let evidence = identity.evidence_entry().expect("evidence");
        let signature = identity.sign(b"signed");
        let adapter = DidWebAdapter::new(vec![identity
            .current_trust(Timestamp::new(10), Timestamp::new(20))
            .expect("trust")])
        .expect("adapter");
        let verified = adapter
            .verify_control(ControlProofInput {
                principal: identity.principal(),
                purpose: ProofPurpose::CapabilityInvocation,
                verification_method: descriptor.verification_method(),
                algorithm: descriptor.algorithm(),
                signing_bytes: b"signed",
                signature: &signature,
                evidence: &evidence,
                asserted_signing_time: Timestamp::new(12),
                verification_time: Timestamp::new(15),
            })
            .expect("verified");
        assert!(verified
            .claims()
            .contains(&AssuranceClaim::ControllerStateCurrentAt(Timestamp::new(
                10
            ))));
    }

    #[test]
    fn historical_document_separates_key_state_from_statement_existence() {
        let identity = test_signing::TestDidWebIdentity::ed25519("did:web:example.com", [92; 32])
            .expect("identity");
        let descriptor = identity.signature_descriptor().expect("descriptor");
        let evidence = identity.evidence_entry().expect("evidence");
        let signature = identity.sign(b"signed");
        let without_statement = DidWebAdapter::new(vec![identity
            .historical_trust(Timestamp::new(10), Timestamp::new(20), None)
            .expect("trust")])
        .expect("adapter")
        .verify_control(ControlProofInput {
            principal: identity.principal(),
            purpose: ProofPurpose::CapabilityInvocation,
            verification_method: descriptor.verification_method(),
            algorithm: descriptor.algorithm(),
            signing_bytes: b"signed",
            signature: &signature,
            evidence: &evidence,
            asserted_signing_time: Timestamp::new(12),
            verification_time: Timestamp::new(30),
        })
        .expect("historical state");
        assert!(without_statement
            .claims()
            .contains(&AssuranceClaim::ControllerStateHistoricalAt(
                Timestamp::new(12)
            )));
        assert!(!without_statement
            .claims()
            .as_slice()
            .iter()
            .any(|claim| { matches!(claim, AssuranceClaim::StatementExistenceProvenAt(_)) }));
    }
}
