//! Pure verification of explicitly trusted, bundled `did:web` documents.
//!
//! HTTPS acquisition is deliberately outside this crate. The proof supplies a
//! canonical document, while the verifier supplies immutable digest pins.

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
use auths_model::{
    AdapterConfigurationId, AdapterId, AssuranceClaim, AssuranceClaimId, EvidenceId,
    EvidenceSourceId, EvidenceTypeId, MediaType, ModelError, PrincipalId, PrincipalMethodId,
    Timestamp, VerificationMethod,
};
use auths_multikey::{Multikey, MultikeyError};
use auths_ports::{
    ControlEvidence, ControlPurpose, PrincipalControlError, PrincipalControlInput, PrincipalMethod,
};
use core::{fmt, str};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

/// Exact target V1 principal-method and evidence-type identifier.
pub const DID_WEB_V1: &str = "did-web-bundled-v1";
/// Canonical media type shared with the native acquisition resolver.
pub const DID_WEB_MEDIA_TYPE: &str = "application/vnd.auths.did-web-bundle.v1";
/// Canonical principal prefix.
pub const PRINCIPAL_PREFIX: &str = "did:web:";
const EVIDENCE_DOMAIN: &[u8] = b"AUTHS-DID-WEB\x00\x01";
const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
const MAX_DOCUMENT_BYTES: usize = 32 * 1024;
const MAX_METHODS: usize = 32;
const MAX_RELATIONSHIPS: usize = 64;
const MAX_TRUST_RECORDS: usize = 256;
const ROOT_FIELDS: &[&str] = &[
    "@context",
    "id",
    "verificationMethod",
    "assertionMethod",
    "capabilityInvocation",
    "capabilityDelegation",
];
const METHOD_FIELDS: &[&str] = &["id", "type", "controller", "publicKeyMultibase"];

/// Parsed target V1 `did:web` identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidWebId {
    principal: PrincipalId,
    host: String,
    port: Option<u16>,
    path: Vec<String>,
}

impl DidWebId {
    /// Parses the closed lowercase DNS-based target grammar.
    ///
    /// # Errors
    ///
    /// Rejects IP hosts, Unicode, arbitrary percent encoding, dot segments,
    /// empty components, invalid ports, and non-`did:web` identifiers.
    pub fn parse(value: &str) -> Result<Self, DidWebError> {
        let specific = value
            .strip_prefix(PRINCIPAL_PREFIX)
            .ok_or(DidWebError::InvalidDid)?;
        if specific.is_empty() || !specific.is_ascii() {
            return Err(DidWebError::InvalidDid);
        }
        let mut parts = specific.split(':');
        let authority = parts.next().ok_or(DidWebError::InvalidDid)?;
        let path = parts
            .map(|part| {
                if part.is_empty()
                    || part == "."
                    || part == ".."
                    || !part.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
                    })
                {
                    Err(DidWebError::InvalidDid)
                } else {
                    Ok(part.to_string())
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (host, port) = parse_authority(authority)?;
        Ok(Self {
            principal: PrincipalId::parse(value)?,
            host,
            port,
            path,
        })
    }

    /// Returns the validated principal.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Returns the lower-case DNS host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the explicitly encoded HTTPS port.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    /// Returns the deterministic HTTPS resolution URL.
    #[must_use]
    pub fn resolution_url(&self) -> String {
        let authority = self
            .port
            .map_or_else(|| self.host.clone(), |port| format!("{}:{port}", self.host));
        if self.path.is_empty() {
            format!("https://{authority}/.well-known/did.json")
        } else {
            format!("https://{authority}/{}/did.json", self.path.join("/"))
        }
    }
}

fn parse_authority(value: &str) -> Result<(String, Option<u16>), DidWebError> {
    let mut pieces = value.split("%3A");
    let host = pieces.next().ok_or(DidWebError::InvalidDid)?;
    let port = pieces
        .next()
        .map(|value| {
            value
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or(DidWebError::InvalidDid)
        })
        .transpose()?;
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

/// Canonical bundled document evidence produced by the native resolver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidWebEvidence {
    principal: PrincipalId,
    document: Vec<u8>,
}

impl DidWebEvidence {
    /// Validates an already-canonical target document.
    ///
    /// # Errors
    ///
    /// Rejects malformed, non-canonical, out-of-profile, oversized, or
    /// principal-confused documents.
    pub fn from_canonical(principal: PrincipalId, document: Vec<u8>) -> Result<Self, DidWebError> {
        let evidence = Self {
            principal,
            document,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Converts an in-profile JSON document to its deterministic target form.
    ///
    /// # Errors
    ///
    /// Rejects any document outside the closed target profile.
    pub fn canonicalize(principal: PrincipalId, document: &[u8]) -> Result<Self, DidWebError> {
        if document.is_empty() || document.len() > MAX_DOCUMENT_BYTES {
            return Err(DidWebError::LimitExceeded);
        }
        DidWebId::parse(principal.as_str())?;
        let value: Value =
            serde_json::from_slice(document).map_err(|_| DidWebError::InvalidDocument)?;
        parse_document(&value, &principal)?;
        let canonical = canonical_json(&value)?;
        Self::from_canonical(principal, canonical)
    }

    /// Decodes the exact resolver/adapter evidence contract.
    ///
    /// # Errors
    ///
    /// Rejects wrong domains, truncated or trailing fields, malformed
    /// identifiers, size violations, and invalid document bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, DidWebError> {
        let mut reader = Reader::new(bytes);
        if reader.take(EVIDENCE_DOMAIN.len())? != EVIDENCE_DOMAIN {
            return Err(DidWebError::InvalidEvidence);
        }
        let principal_length = usize::from(reader.u16()?);
        let principal = PrincipalId::parse(
            str::from_utf8(reader.take(principal_length)?)
                .map_err(|_| DidWebError::InvalidEvidence)?,
        )?;
        let document_length =
            usize::try_from(reader.u32()?).map_err(|_| DidWebError::LimitExceeded)?;
        if document_length > MAX_DOCUMENT_BYTES {
            return Err(DidWebError::LimitExceeded);
        }
        let document = reader.take(document_length)?.to_vec();
        if !reader.finished() {
            return Err(DidWebError::InvalidEvidence);
        }
        Self::from_canonical(principal, document)
    }

    /// Encodes the exact resolver/adapter evidence contract.
    ///
    /// # Errors
    ///
    /// Returns a typed error if a bounded length cannot be represented.
    pub fn encode(&self) -> Result<Vec<u8>, DidWebError> {
        let principal = self.principal.as_str().as_bytes();
        let principal_length =
            u16::try_from(principal.len()).map_err(|_| DidWebError::LimitExceeded)?;
        let document_length =
            u32::try_from(self.document.len()).map_err(|_| DidWebError::LimitExceeded)?;
        let mut output =
            Vec::with_capacity(EVIDENCE_DOMAIN.len() + 6 + principal.len() + self.document.len());
        output.extend_from_slice(EVIDENCE_DOMAIN);
        output.extend_from_slice(&principal_length.to_be_bytes());
        output.extend_from_slice(principal);
        output.extend_from_slice(&document_length.to_be_bytes());
        output.extend_from_slice(&self.document);
        Ok(output)
    }

    /// Returns the principal bound into the evidence envelope.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Returns canonical document bytes.
    #[must_use]
    pub fn document(&self) -> &[u8] {
        &self.document
    }

    /// Returns the SHA-256 digest pinned by local trust.
    #[must_use]
    pub fn document_digest(&self) -> [u8; 32] {
        Sha256::digest(&self.document).into()
    }

    fn validate(&self) -> Result<(), DidWebError> {
        if self.document.is_empty() || self.document.len() > MAX_DOCUMENT_BYTES {
            return Err(DidWebError::LimitExceeded);
        }
        DidWebId::parse(self.principal.as_str())?;
        let value: Value =
            serde_json::from_slice(&self.document).map_err(|_| DidWebError::InvalidDocument)?;
        parse_document(&value, &self.principal)?;
        if canonical_json(&value)? != self.document {
            return Err(DidWebError::NonCanonicalDocument);
        }
        Ok(())
    }
}

/// Exact signed-statement pin used to rule out key-removal backdating.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoricalStatementPin {
    signing_preimage_digest: [u8; 32],
    existed_at: Timestamp,
}

impl HistoricalStatementPin {
    /// Pins one exact Auths signing preimage.
    #[must_use]
    pub fn new(signing_preimage: &[u8], existed_at: Timestamp) -> Self {
        Self {
            signing_preimage_digest: Sha256::digest(signing_preimage).into(),
            existed_at,
        }
    }

    /// Returns the pinned signing-preimage digest.
    #[must_use]
    pub const fn signing_preimage_digest(&self) -> [u8; 32] {
        self.signing_preimage_digest
    }

    /// Returns when the exact signed statement was known to exist.
    #[must_use]
    pub const fn existed_at(&self) -> Timestamp {
        self.existed_at
    }
}

/// Verifier-local immutable trust for one bundled document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DidWebTrustRecord {
    /// A document observed through an accepted live acquisition path.
    Current {
        /// Exact principal.
        principal: PrincipalId,
        /// SHA-256 of canonical document bytes.
        document_digest: [u8; 32],
        /// Trusted observation time.
        observed_at: Timestamp,
        /// End of the local freshness window.
        valid_until: Timestamp,
    },
    /// A document pinned for a historical controller-state interval.
    Historical {
        /// Exact principal.
        principal: PrincipalId,
        /// SHA-256 of canonical document bytes.
        document_digest: [u8; 32],
        /// Start of the historical state interval.
        valid_from: Timestamp,
        /// End of the historical state interval.
        valid_until: Timestamp,
        /// Optional proof that the exact signed statement existed in-window.
        statement: Option<HistoricalStatementPin>,
    },
}

impl DidWebTrustRecord {
    /// Constructs validated current-document trust.
    ///
    /// # Errors
    ///
    /// Rejects invalid `did:web` principals or inverted time windows.
    pub fn current(
        principal: PrincipalId,
        document_digest: [u8; 32],
        observed_at: Timestamp,
        valid_until: Timestamp,
    ) -> Result<Self, DidWebError> {
        DidWebId::parse(principal.as_str())?;
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

    /// Constructs validated historical-document trust.
    ///
    /// # Errors
    ///
    /// Rejects invalid principals, inverted windows, or statement observations
    /// outside the controller-state interval.
    pub fn historical(
        principal: PrincipalId,
        document_digest: [u8; 32],
        valid_from: Timestamp,
        valid_until: Timestamp,
        statement: Option<HistoricalStatementPin>,
    ) -> Result<Self, DidWebError> {
        DidWebId::parse(principal.as_str())?;
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
}

/// Target V1 bundled `did:web` principal method.
pub struct DidWebMethod {
    id: PrincipalMethodId,
    evidence_type: EvidenceTypeId,
    media_type: MediaType,
    adapter: AdapterId,
    source: EvidenceSourceId,
    trust: Vec<DidWebTrustRecord>,
}

impl DidWebMethod {
    /// Constructs a method from verifier-local immutable trust records.
    ///
    /// # Errors
    ///
    /// Rejects an oversized trust set or invalid compiled identifiers.
    pub fn new(mut trust: Vec<DidWebTrustRecord>) -> Result<Self, DidWebError> {
        if trust.len() > MAX_TRUST_RECORDS {
            return Err(DidWebError::LimitExceeded);
        }
        trust.sort_by_key(did_web_trust_record_id);
        if trust.windows(2).any(|window| window[0] == window[1])
            || trust.iter().enumerate().any(|(index, left)| {
                trust
                    .iter()
                    .skip(index.saturating_add(1))
                    .any(|right| did_web_records_ambiguous(left, right))
            })
        {
            return Err(DidWebError::InvalidTrustRecord);
        }
        Ok(Self {
            id: PrincipalMethodId::parse(DID_WEB_V1)?,
            evidence_type: EvidenceTypeId::parse(DID_WEB_V1)?,
            media_type: MediaType::parse(DID_WEB_MEDIA_TYPE)?,
            adapter: AdapterId::parse(DID_WEB_V1)?,
            source: EvidenceSourceId::parse(DID_WEB_V1)?,
            trust,
        })
    }
}

impl PrincipalMethod for DidWebMethod {
    fn id(&self) -> &PrincipalMethodId {
        &self.id
    }

    fn configuration_id(&self) -> AdapterConfigurationId {
        let components: Vec<_> = self
            .trust
            .iter()
            .map(|record| did_web_trust_record_id(record).as_bytes().to_vec())
            .collect();
        auths_ports::configuration_id(DID_WEB_V1.as_bytes(), components.iter().map(Vec::as_slice))
    }

    fn maximum_work_units(&self) -> u64 {
        45
    }

    fn verify_control(
        &self,
        input: PrincipalControlInput<'_>,
    ) -> Result<ControlEvidence, PrincipalControlError> {
        DidWebId::parse(input.principal.as_str())
            .map_err(|_| PrincipalControlError::PrincipalMethodMismatch)?;
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
        let bundled = DidWebEvidence::decode(evidence.bytes()).map_err(map_evidence_error)?;
        if bundled.principal() != input.principal {
            return Err(PrincipalControlError::PrincipalMethodMismatch);
        }
        let value: Value = serde_json::from_slice(bundled.document())
            .map_err(|_| PrincipalControlError::InvalidEvidence)?;
        let document = parse_document(&value, input.principal)
            .map_err(|_| PrincipalControlError::InvalidEvidence)?;
        let method = document
            .method(input.verification_method, input.purpose)
            .map_err(|_| PrincipalControlError::VerificationMethodMismatch)?;
        if method.key.key_type().suite() != input.signature_suite.as_str() {
            return Err(PrincipalControlError::SignatureSuiteMismatch);
        }
        let mut claims =
            trust_claims(&self.trust, &input, bundled.document_digest(), &self.source)?;
        claims.push(claim("offline-verifiable", None, &self.source)?);
        claims.push(claim("rotation-aware", None, &self.source)?);
        ControlEvidence::new(
            method.key.public_key().to_vec(),
            claims,
            vec![EvidenceId::new(*evidence.id().as_bytes())],
            self.adapter.clone(),
            1,
            45,
        )
    }
}

fn did_web_trust_record_id(record: &DidWebTrustRecord) -> AdapterConfigurationId {
    let mut components = Vec::new();
    match record {
        DidWebTrustRecord::Current {
            principal,
            document_digest,
            observed_at,
            valid_until,
        } => {
            components.push(vec![0]);
            components.push(principal.as_str().as_bytes().to_vec());
            components.push(document_digest.to_vec());
            components.push(observed_at.get().to_be_bytes().to_vec());
            components.push(valid_until.get().to_be_bytes().to_vec());
        }
        DidWebTrustRecord::Historical {
            principal,
            document_digest,
            valid_from,
            valid_until,
            statement,
        } => {
            components.push(vec![1]);
            components.push(principal.as_str().as_bytes().to_vec());
            components.push(document_digest.to_vec());
            components.push(valid_from.get().to_be_bytes().to_vec());
            components.push(valid_until.get().to_be_bytes().to_vec());
            match statement {
                Some(statement) => {
                    components.push(vec![1]);
                    components.push(statement.signing_preimage_digest.to_vec());
                    components.push(statement.existed_at.get().to_be_bytes().to_vec());
                }
                None => components.push(vec![0]),
            }
        }
    }
    auths_ports::configuration_id(
        b"auths-did-web-trust-record-v1",
        components.iter().map(Vec::as_slice),
    )
}

fn did_web_records_ambiguous(left: &DidWebTrustRecord, right: &DidWebTrustRecord) -> bool {
    match (left, right) {
        (
            DidWebTrustRecord::Current {
                principal: left_principal,
                observed_at: left_start,
                valid_until: left_end,
                ..
            },
            DidWebTrustRecord::Current {
                principal: right_principal,
                observed_at: right_start,
                valid_until: right_end,
                ..
            },
        )
        | (
            DidWebTrustRecord::Historical {
                principal: left_principal,
                valid_from: left_start,
                valid_until: left_end,
                ..
            },
            DidWebTrustRecord::Historical {
                principal: right_principal,
                valid_from: right_start,
                valid_until: right_end,
                ..
            },
        ) => {
            left_principal == right_principal
                && *left_start <= *right_end
                && *right_start <= *left_end
        }
        _ => false,
    }
}

fn trust_claims(
    records: &[DidWebTrustRecord],
    input: &PrincipalControlInput<'_>,
    document_digest: [u8; 32],
    source: &EvidenceSourceId,
) -> Result<Vec<AssuranceClaim>, PrincipalControlError> {
    let mut matching_document = false;
    for record in records {
        if let DidWebTrustRecord::Current {
            principal,
            document_digest: expected,
            observed_at,
            valid_until,
        } = record
        {
            if principal == input.principal && expected == &document_digest {
                matching_document = true;
            }
            if principal == input.principal
                && expected == &document_digest
                && *observed_at <= input.evaluation_time
                && input.evaluation_time <= *valid_until
            {
                return Ok(vec![
                    claim("controller-state-current-at", Some(*observed_at), source)?,
                    claim("revocation-checked-at", Some(*observed_at), source)?,
                ]);
            }
        }
    }
    let mut document_only = None;
    for record in records {
        if let DidWebTrustRecord::Historical {
            principal,
            document_digest: expected,
            valid_from,
            valid_until,
            statement,
        } = record
        {
            if principal == input.principal && expected == &document_digest {
                matching_document = true;
            }
            if principal == input.principal
                && expected == &document_digest
                && *valid_from <= input.asserted_signing_time
                && input.asserted_signing_time <= *valid_until
            {
                let mut claims = vec![claim(
                    "historical-at",
                    Some(input.asserted_signing_time),
                    source,
                )?];
                if let Some(pin) = statement
                    && pin.signing_preimage_digest
                        == <[u8; 32]>::from(Sha256::digest(input.signing_preimage))
                    && pin.existed_at >= input.asserted_signing_time
                    && pin.existed_at <= *valid_until
                {
                    claims.push(claim(
                        "statement-existence-proven-at",
                        Some(pin.existed_at),
                        source,
                    )?);
                    return Ok(claims);
                }
                document_only = Some(claims);
            }
        }
    }
    if let Some(claims) = document_only {
        Ok(claims)
    } else if matching_document {
        Err(PrincipalControlError::HistoricalStateUnavailable)
    } else {
        Err(PrincipalControlError::ExternalFactUnavailable)
    }
}

fn claim(
    identifier: &str,
    observed_at: Option<Timestamp>,
    source: &EvidenceSourceId,
) -> Result<AssuranceClaim, PrincipalControlError> {
    AssuranceClaim::new(
        AssuranceClaimId::parse(identifier).map_err(|_| PrincipalControlError::InvalidEvidence)?,
        Vec::new(),
        observed_at,
        source.clone(),
    )
    .map_err(|_| PrincipalControlError::InvalidEvidence)
}

struct ParsedDocument {
    methods: Vec<ParsedMethod>,
    assertion: BTreeSet<String>,
    capability_delegation: BTreeSet<String>,
    capability_invocation: BTreeSet<String>,
}

struct ParsedMethod {
    id: VerificationMethod,
    key: Multikey,
}

impl ParsedDocument {
    fn method(
        &self,
        requested: &VerificationMethod,
        purpose: ControlPurpose,
    ) -> Result<&ParsedMethod, DidWebError> {
        let relationship = match purpose {
            ControlPurpose::CapabilityDelegation => &self.capability_delegation,
            ControlPurpose::CapabilityInvocation => &self.capability_invocation,
            ControlPurpose::Assertion => &self.assertion,
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

fn parse_document(value: &Value, principal: &PrincipalId) -> Result<ParsedDocument, DidWebError> {
    let object = value.as_object().ok_or(DidWebError::InvalidDocument)?;
    if object.len() != ROOT_FIELDS.len()
        || object
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
        let id = VerificationMethod::parse(text(method, "id")?)?;
        if !id.as_str().starts_with(&format!("{}#", principal.as_str())) || !ids.insert(id.clone())
        {
            return Err(DidWebError::InvalidDocument);
        }
        methods.push(ParsedMethod {
            id,
            key: Multikey::parse(text(method, "publicKeyMultibase")?)?,
        });
    }
    let assertion = relationship(object, "assertionMethod")?;
    let capability_delegation = relationship(object, "capabilityDelegation")?;
    let capability_invocation = relationship(object, "capabilityInvocation")?;
    if assertion
        .iter()
        .chain(capability_delegation.iter())
        .chain(capability_invocation.iter())
        .any(|reference| !ids.iter().any(|method| method.as_str() == reference))
    {
        return Err(DidWebError::UnknownVerificationMethod);
    }
    Ok(ParsedDocument {
        methods,
        assertion,
        capability_delegation,
        capability_invocation,
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

fn canonical_json(value: &Value) -> Result<Vec<u8>, DidWebError> {
    let mut output = String::new();
    write_canonical_json(value, &mut output)?;
    if output.len() > MAX_DOCUMENT_BYTES {
        return Err(DidWebError::LimitExceeded);
    }
    Ok(output.into_bytes())
}

fn write_canonical_json(value: &Value, output: &mut String) -> Result<(), DidWebError> {
    match value {
        Value::String(text) => {
            output
                .push_str(&serde_json::to_string(text).map_err(|_| DidWebError::InvalidDocument)?);
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(']');
        }
        Value::Object(object) => {
            let mut keys: Vec<_> = object.keys().collect();
            keys.sort_unstable();
            output.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key).map_err(|_| DidWebError::InvalidDocument)?,
                );
                output.push(':');
                write_canonical_json(&object[key], output)?;
            }
            output.push('}');
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {
            return Err(DidWebError::UnsupportedDocumentFeature);
        }
    }
    Ok(())
}

fn map_evidence_error(error: DidWebError) -> PrincipalControlError {
    match error {
        DidWebError::LimitExceeded => PrincipalControlError::ResourceLimitExceeded,
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

    fn take(&mut self, length: usize) -> Result<&'a [u8], DidWebError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(DidWebError::InvalidEvidence)?;
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or(DidWebError::InvalidEvidence)?;
        self.cursor = end;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16, DidWebError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, DidWebError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    const fn finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

/// Bundled `did:web` parsing, trust, or profile error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DidWebError {
    /// A target model identifier is invalid.
    Model(ModelError),
    /// Multikey material is invalid or unsupported.
    Multikey(MultikeyError),
    /// The principal is outside the closed `did:web` grammar.
    InvalidDid,
    /// The evidence envelope is malformed.
    InvalidEvidence,
    /// The DID document is malformed.
    InvalidDocument,
    /// The document is not in the unique target JSON form.
    NonCanonicalDocument,
    /// The document uses a feature outside the closed target profile.
    UnsupportedDocumentFeature,
    /// The document identifies a different principal.
    DocumentIdMismatch,
    /// The requested verification method is absent.
    UnknownVerificationMethod,
    /// The method lacks the required relationship.
    WrongVerificationRelationship,
    /// A verifier-local trust record is invalid.
    InvalidTrustRecord,
    /// A target resource bound was exceeded.
    LimitExceeded,
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
        match self {
            Self::Model(error) => write!(formatter, "invalid Auths model value: {error}"),
            Self::Multikey(error) => write!(formatter, "invalid Multikey: {error}"),
            Self::InvalidDid => formatter.write_str("invalid or unsupported did:web identifier"),
            Self::InvalidEvidence => formatter.write_str("invalid did:web evidence envelope"),
            Self::InvalidDocument => formatter.write_str("invalid did:web document"),
            Self::NonCanonicalDocument => formatter.write_str("non-canonical did:web document"),
            Self::UnsupportedDocumentFeature => {
                formatter.write_str("unsupported did:web document feature")
            }
            Self::DocumentIdMismatch => formatter.write_str("did:web document id mismatch"),
            Self::UnknownVerificationMethod => {
                formatter.write_str("unknown did:web verification method")
            }
            Self::WrongVerificationRelationship => {
                formatter.write_str("wrong did:web verification relationship")
            }
            Self::InvalidTrustRecord => formatter.write_str("invalid did:web trust record"),
            Self::LimitExceeded => formatter.write_str("did:web resource limit exceeded"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DidWebError {}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_codec::evidence_id;
    use auths_model::{Digest, EvidenceObject, SignatureSuiteId};
    use auths_multikey::MultikeyType;
    use ed25519_dalek::SigningKey;

    fn identity() -> (DidWebEvidence, VerificationMethod) {
        let principal = PrincipalId::parse("did:web:example.com").unwrap();
        let key = SigningKey::from_bytes(&[91; 32]);
        let multikey = Multikey::from_public_key(
            MultikeyType::Ed25519,
            key.verifying_key().to_bytes().to_vec(),
        )
        .unwrap();
        let method = VerificationMethod::parse("did:web:example.com#key-1").unwrap();
        let document = format!(
            r#"{{"verificationMethod":[{{"publicKeyMultibase":"{}","controller":"{}","type":"Multikey","id":"{}"}}],"id":"{}","capabilityInvocation":["{}"],"capabilityDelegation":["{}"],"assertionMethod":["{}"],"@context":"{}"}}"#,
            multikey.encoded(),
            principal.as_str(),
            method.as_str(),
            principal.as_str(),
            method.as_str(),
            method.as_str(),
            method.as_str(),
            DID_CONTEXT
        );
        (
            DidWebEvidence::canonicalize(principal, document.as_bytes()).unwrap(),
            method,
        )
    }

    fn addressed(evidence: &DidWebEvidence) -> EvidenceObject {
        let unaddressed = EvidenceObject::new(
            EvidenceId::from_digest(Digest::ZERO),
            EvidenceTypeId::parse(DID_WEB_V1).unwrap(),
            MediaType::parse(DID_WEB_MEDIA_TYPE).unwrap(),
            evidence.encode().unwrap(),
        )
        .unwrap();
        EvidenceObject::new(
            evidence_id(&unaddressed).unwrap(),
            unaddressed.evidence_type().clone(),
            unaddressed.media_type().clone(),
            unaddressed.bytes().to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn maps_closed_dids_to_https() {
        assert_eq!(
            DidWebId::parse("did:web:example.com")
                .unwrap()
                .resolution_url(),
            "https://example.com/.well-known/did.json"
        );
        assert_eq!(
            DidWebId::parse("did:web:example.com%3A8443:users:alice")
                .unwrap()
                .resolution_url(),
            "https://example.com:8443/users/alice/did.json"
        );
        assert!(DidWebId::parse("did:web:127.0.0.1").is_err());
    }

    #[test]
    fn current_trust_establishes_suite_key_and_freshness_claims() {
        let (bundled, method) = identity();
        let evidence = addressed(&bundled);
        let refs = [&evidence];
        let verifier = DidWebMethod::new(vec![
            DidWebTrustRecord::current(
                bundled.principal().clone(),
                bundled.document_digest(),
                Timestamp::new(10),
                Timestamp::new(20),
            )
            .unwrap(),
        ])
        .unwrap();
        let control = verifier
            .verify_control(PrincipalControlInput {
                principal: bundled.principal(),
                verification_method: &method,
                signature_suite: &SignatureSuiteId::parse("ed25519-v1").unwrap(),
                purpose: ControlPurpose::CapabilityInvocation,
                signing_preimage: b"signed",
                asserted_signing_time: Timestamp::new(12),
                evidence: &refs,
                evaluation_time: Timestamp::new(15),
            })
            .unwrap();
        assert_eq!(control.verification_key().len(), 32);
        assert!(
            control
                .claims()
                .iter()
                .any(|claim| claim.kind().as_str() == "controller-state-current-at")
        );
    }

    #[test]
    fn historical_statement_pin_is_distinct_from_controller_state() {
        let (bundled, method) = identity();
        let evidence = addressed(&bundled);
        let refs = [&evidence];
        let verifier = DidWebMethod::new(vec![
            DidWebTrustRecord::historical(
                bundled.principal().clone(),
                bundled.document_digest(),
                Timestamp::new(10),
                Timestamp::new(20),
                Some(HistoricalStatementPin::new(b"signed", Timestamp::new(13))),
            )
            .unwrap(),
        ])
        .unwrap();
        let control = verifier
            .verify_control(PrincipalControlInput {
                principal: bundled.principal(),
                verification_method: &method,
                signature_suite: &SignatureSuiteId::parse("ed25519-v1").unwrap(),
                purpose: ControlPurpose::CapabilityDelegation,
                signing_preimage: b"signed",
                asserted_signing_time: Timestamp::new(12),
                evidence: &refs,
                evaluation_time: Timestamp::new(30),
            })
            .unwrap();
        assert!(
            control
                .claims()
                .iter()
                .any(|claim| claim.kind().as_str() == "historical-at")
        );
        assert!(
            control
                .claims()
                .iter()
                .any(|claim| claim.kind().as_str() == "statement-existence-proven-at")
        );
    }

    #[test]
    fn configuration_commitment_is_order_independent_and_value_sensitive() {
        let (bundled, _) = identity();
        let current = DidWebTrustRecord::current(
            bundled.principal().clone(),
            bundled.document_digest(),
            Timestamp::new(10),
            Timestamp::new(20),
        )
        .unwrap();
        let historical = DidWebTrustRecord::historical(
            bundled.principal().clone(),
            bundled.document_digest(),
            Timestamp::new(1),
            Timestamp::new(9),
            None,
        )
        .unwrap();
        let forward = DidWebMethod::new(vec![current.clone(), historical.clone()]).unwrap();
        let reverse = DidWebMethod::new(vec![historical, current.clone()]).unwrap();
        assert_eq!(forward.configuration_id(), reverse.configuration_id());

        let changed = DidWebMethod::new(vec![
            current.clone(),
            DidWebTrustRecord::historical(
                bundled.principal().clone(),
                bundled.document_digest(),
                Timestamp::new(1),
                Timestamp::new(8),
                None,
            )
            .unwrap(),
        ])
        .unwrap();
        assert_ne!(forward.configuration_id(), changed.configuration_id());
        assert!(DidWebMethod::new(vec![current.clone(), current]).is_err());
    }
}
