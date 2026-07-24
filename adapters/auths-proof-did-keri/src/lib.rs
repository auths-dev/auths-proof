//! Pure, bounded, offline `did:keri` principal-control verification.
//!
//! This adapter deliberately implements a narrow KERI V1 profile: self-addressing
//! `icp`, `rot`, and `ixn` events; detached CESR controller signatures; simple
//! thresholds; Ed25519 and P-256 keys; and zero-witness KELs. Unsupported KERI
//! features fail closed.

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
    PrincipalEvidenceEntry, PrincipalRef, VerificationMethodRef,
};
#[cfg(any(test, feature = "test-signing"))]
use auths_proof_model::{AlgorithmId, SignatureDescriptor};
use base64ct::{Base64UrlUnpadded, Encoding};
use core::{fmt, str};
use ed25519_dalek::{Signature as Ed25519Signature, Verifier as _, VerifyingKey as Ed25519Key};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256Key};
use serde_json::{Map, Value};

pub const ADAPTER_ID: &str = "did-keri-v1";
pub const EVIDENCE_MEDIA_TYPE: &str = "application/vnd.auths.did-keri-kel.v1";
pub const PRINCIPAL_PREFIX: &str = "did:keri:";
pub const ED25519_ALGORITHM: &str = "ed25519";
pub const P256_ALGORITHM: &str = "p256-sha256";
pub const EVIDENCE_DOMAIN: &[u8] = b"auths-proof/did-keri/evidence/v1\0";

const SAID_PLACEHOLDER: &str = "############################################";
const MAX_EVENTS: usize = 64;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_ATTACHMENT_BYTES: usize = 16 * 1024;
const MAX_KEYS: usize = 16;
const MAX_ANCHORS: usize = 64;

const ICP_FIELDS: &[&str] = &[
    "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a",
];
const ROT_FIELDS: &[&str] = &[
    "v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "a",
];
const IXN_FIELDS: &[&str] = &["v", "t", "d", "i", "s", "p", "a"];
const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeriLimits {
    pub max_events: usize,
    pub max_event_bytes: usize,
    pub max_attachment_bytes: usize,
    pub max_keys: usize,
}

impl KeriLimits {
    pub const fn standard() -> Self {
        Self {
            max_events: MAX_EVENTS,
            max_event_bytes: MAX_EVENT_BYTES,
            max_attachment_bytes: MAX_ATTACHMENT_BYTES,
            max_keys: MAX_KEYS,
        }
    }

    fn validate(self) -> Result<Self, KeriError> {
        if self.max_events == 0
            || self.max_events > MAX_EVENTS
            || self.max_event_bytes == 0
            || self.max_event_bytes > MAX_EVENT_BYTES
            || self.max_attachment_bytes == 0
            || self.max_attachment_bytes > MAX_ATTACHMENT_BYTES
            || self.max_keys == 0
            || self.max_keys > MAX_KEYS
        {
            Err(KeriError::LimitExceeded)
        } else {
            Ok(self)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KelEvent {
    event_json: Vec<u8>,
    attachment: Vec<u8>,
}

impl KelEvent {
    pub fn new(event_json: Vec<u8>, attachment: Vec<u8>) -> Result<Self, KeriError> {
        if event_json.is_empty()
            || event_json.len() > MAX_EVENT_BYTES
            || attachment.is_empty()
            || attachment.len() > MAX_ATTACHMENT_BYTES
        {
            return Err(KeriError::LimitExceeded);
        }
        Ok(Self {
            event_json,
            attachment,
        })
    }

    pub fn event_json(&self) -> &[u8] {
        &self.event_json
    }

    pub fn attachment(&self) -> &[u8] {
        &self.attachment
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeriEvidence {
    events: Vec<KelEvent>,
}

impl KeriEvidence {
    pub fn new(events: Vec<KelEvent>) -> Result<Self, KeriError> {
        if events.is_empty() || events.len() > MAX_EVENTS {
            return Err(KeriError::LimitExceeded);
        }
        Ok(Self { events })
    }

    pub fn events(&self) -> &[KelEvent] {
        &self.events
    }

    pub fn encode(&self) -> Result<Vec<u8>, KeriError> {
        let count = u16::try_from(self.events.len()).map_err(|_| KeriError::LimitExceeded)?;
        let mut output = Vec::new();
        output.extend_from_slice(EVIDENCE_DOMAIN);
        output.extend_from_slice(&count.to_be_bytes());
        for event in &self.events {
            write_sized(&mut output, &event.event_json)?;
            write_sized(&mut output, &event.attachment)?;
        }
        Ok(output)
    }

    pub fn decode(bytes: &[u8], limits: KeriLimits) -> Result<Self, KeriError> {
        let limits = limits.validate()?;
        let mut reader = EvidenceReader::new(bytes);
        if reader.take(EVIDENCE_DOMAIN.len())? != EVIDENCE_DOMAIN {
            return Err(KeriError::InvalidEvidence);
        }
        let count = usize::from(reader.u16()?);
        if count == 0 || count > limits.max_events {
            return Err(KeriError::LimitExceeded);
        }
        let mut events = Vec::with_capacity(count);
        for _ in 0..count {
            let event_json = reader.sized(limits.max_event_bytes)?.to_vec();
            let attachment = reader.sized(limits.max_attachment_bytes)?.to_vec();
            events.push(KelEvent {
                event_json,
                attachment,
            });
        }
        if !reader.is_finished() {
            return Err(KeriError::InvalidEvidence);
        }
        Ok(Self { events })
    }

    pub fn evidence_entry(&self) -> Result<PrincipalEvidenceEntry, KeriError> {
        let method = AdapterId::parse(ADAPTER_ID)?;
        let media_type = EvidenceMediaType::parse(EVIDENCE_MEDIA_TYPE)?;
        let encoded = self.encode()?;
        let id = evidence_id(&method, &media_type, &encoded);
        Ok(PrincipalEvidenceEntry::new(
            id,
            method,
            media_type,
            EvidenceBytes::new(encoded)?,
        ))
    }
}

fn write_sized(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), KeriError> {
    let size = u32::try_from(bytes.len()).map_err(|_| KeriError::LimitExceeded)?;
    output.extend_from_slice(&size.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

struct EvidenceReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> EvidenceReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], KeriError> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(KeriError::LimitExceeded)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(KeriError::InvalidEvidence)?;
        self.cursor = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, KeriError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, KeriError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn sized(&mut self, max: usize) -> Result<&'a [u8], KeriError> {
        let len = usize::try_from(self.u32()?).map_err(|_| KeriError::LimitExceeded)?;
        if len == 0 || len > max {
            return Err(KeriError::LimitExceeded);
        }
        self.take(len)
    }

    const fn is_finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

pub struct DidKeriAdapter {
    adapter_id: AdapterId,
    media_type: EvidenceMediaType,
    limits: KeriLimits,
}

impl DidKeriAdapter {
    pub fn new() -> Result<Self, ModelError> {
        Self::with_limits(KeriLimits::standard()).map_err(|error| match error {
            KeriError::Model(model) => model,
            _ => ModelError::InvalidSyntax,
        })
    }

    pub fn with_limits(limits: KeriLimits) -> Result<Self, KeriError> {
        Ok(Self {
            adapter_id: AdapterId::parse(ADAPTER_ID)?,
            media_type: EvidenceMediaType::parse(EVIDENCE_MEDIA_TYPE)?,
            limits: limits.validate()?,
        })
    }
}

impl PrincipalControlVerifier for DidKeriAdapter {
    fn adapter_id(&self) -> &AdapterId {
        &self.adapter_id
    }

    fn supports(&self, principal: &PrincipalRef) -> bool {
        principal.as_str().starts_with(PRINCIPAL_PREFIX)
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

        let evidence = KeriEvidence::decode(input.evidence.bytes().as_slice(), self.limits)
            .map_err(map_evidence_error)?;
        let state = replay_kel(&evidence, self.limits).map_err(map_evidence_error)?;
        let expected_principal =
            PrincipalRef::parse(&format!("{PRINCIPAL_PREFIX}{}", state.prefix))
                .map_err(|_| PrincipalControlError::InvalidEvidence)?;
        if expected_principal != *input.principal {
            return Err(PrincipalControlError::InvalidEvidence);
        }

        let (method_sequence, key_index) =
            parse_verification_method(input.principal, input.verification_method)
                .map_err(|_| PrincipalControlError::VerificationMethodMismatch)?;
        if method_sequence != state.establishment_sequence {
            return Err(PrincipalControlError::VerificationMethodMismatch);
        }
        let key = state
            .current_keys
            .get(key_index)
            .ok_or(PrincipalControlError::VerificationMethodMismatch)?;
        if input.algorithm.as_str() != key.algorithm() {
            return Err(PrincipalControlError::AlgorithmMismatch);
        }
        key.verify(input.signing_bytes, input.signature)
            .map_err(|_| PrincipalControlError::InvalidSignature)?;

        let mut claims = vec![
            AssuranceClaim::SelfCertifyingIdentifier,
            AssuranceClaim::OfflineVerifiable,
        ];
        if !state.abandoned && !state.next_commitments.is_empty() {
            claims.push(AssuranceClaim::RotationAware);
        }
        Ok(VerifiedPrincipal::verified(
            input.principal.clone(),
            input.verification_method.clone(),
            self.adapter_id.clone(),
            input.evidence.id(),
            AssuranceClaims::new(claims),
        ))
    }
}

fn map_evidence_error(error: KeriError) -> PrincipalControlError {
    match error {
        KeriError::LimitExceeded => PrincipalControlError::ResourceLimitExceeded,
        _ => PrincipalControlError::InvalidEvidence,
    }
}

pub fn verification_method(
    principal: &PrincipalRef,
    establishment_sequence: u128,
    key_index: usize,
) -> Result<VerificationMethodRef, ModelError> {
    VerificationMethodRef::parse(&format!(
        "{}#key-{:x}-{key_index}",
        principal.as_str(),
        establishment_sequence
    ))
}

fn parse_verification_method(
    principal: &PrincipalRef,
    method: &VerificationMethodRef,
) -> Result<(u128, usize), KeriError> {
    let suffix = method
        .as_str()
        .strip_prefix(principal.as_str())
        .and_then(|value| value.strip_prefix("#key-"))
        .ok_or(KeriError::InvalidVerificationMethod)?;
    let (sequence, index) = suffix
        .split_once('-')
        .ok_or(KeriError::InvalidVerificationMethod)?;
    if sequence.is_empty()
        || index.is_empty()
        || (sequence.len() > 1 && sequence.starts_with('0'))
        || (index.len() > 1 && index.starts_with('0'))
    {
        return Err(KeriError::InvalidVerificationMethod);
    }
    let sequence =
        u128::from_str_radix(sequence, 16).map_err(|_| KeriError::InvalidVerificationMethod)?;
    let index = index
        .parse::<usize>()
        .map_err(|_| KeriError::InvalidVerificationMethod)?;
    Ok((sequence, index))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventKind {
    Inception,
    Rotation,
    Interaction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedEvent {
    raw: Vec<u8>,
    kind: EventKind,
    said: String,
    prefix: String,
    sequence: u128,
    previous: Option<String>,
    threshold: u16,
    keys: Vec<KeriKey>,
    next_threshold: u16,
    next_commitments: Vec<String>,
    establishment_only: bool,
    signatures: Vec<IndexedSignature>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IndexedSignature {
    index: usize,
    prior_index: Option<usize>,
    curve: KeyCurve,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyCurve {
    Ed25519,
    P256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum KeriKey {
    Ed25519([u8; 32]),
    P256([u8; 33]),
}

impl KeriKey {
    fn parse(encoded: &str) -> Result<Self, KeriError> {
        if let Some(payload) = encoded
            .strip_prefix('D')
            .or_else(|| encoded.strip_prefix('B'))
        {
            if encoded.len() != 44 {
                return Err(KeriError::InvalidKey);
            }
            let decoded = decode_one_char_matter(payload).map_err(|_| KeriError::InvalidKey)?;
            let key: [u8; 32] = decoded.try_into().map_err(|_| KeriError::InvalidKey)?;
            return Ok(Self::Ed25519(key));
        }
        if let Some(payload) = encoded
            .strip_prefix("1AAJ")
            .or_else(|| encoded.strip_prefix("1AAI"))
        {
            if encoded.len() != 48 {
                return Err(KeriError::InvalidKey);
            }
            let decoded =
                Base64UrlUnpadded::decode_vec(payload).map_err(|_| KeriError::InvalidKey)?;
            let key: [u8; 33] = decoded.try_into().map_err(|_| KeriError::InvalidKey)?;
            P256Key::from_sec1_bytes(&key).map_err(|_| KeriError::InvalidKey)?;
            return Ok(Self::P256(key));
        }
        Err(KeriError::UnsupportedKey)
    }

    const fn curve(&self) -> KeyCurve {
        match self {
            Self::Ed25519(_) => KeyCurve::Ed25519,
            Self::P256(_) => KeyCurve::P256,
        }
    }

    const fn algorithm(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => ED25519_ALGORITHM,
            Self::P256(_) => P256_ALGORITHM,
        }
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), KeriError> {
        match self {
            Self::Ed25519(bytes) => {
                let key = Ed25519Key::from_bytes(bytes).map_err(|_| KeriError::InvalidKey)?;
                let signature = Ed25519Signature::from_slice(signature)
                    .map_err(|_| KeriError::InvalidSignature)?;
                key.verify_strict(message, &signature)
                    .map_err(|_| KeriError::InvalidSignature)
            }
            Self::P256(bytes) => {
                let key = P256Key::from_sec1_bytes(bytes).map_err(|_| KeriError::InvalidKey)?;
                let signature = P256Signature::from_slice(signature)
                    .map_err(|_| KeriError::InvalidSignature)?;
                if signature.normalize_s().is_some() {
                    return Err(KeriError::InvalidSignature);
                }
                key.verify(message, &signature)
                    .map_err(|_| KeriError::InvalidSignature)
            }
        }
    }
}

#[derive(Clone, Debug)]
struct KeyState {
    prefix: String,
    current_keys: Vec<KeriKey>,
    threshold: u16,
    next_commitments: Vec<String>,
    next_threshold: u16,
    sequence: u128,
    establishment_sequence: u128,
    last_said: String,
    abandoned: bool,
    establishment_only: bool,
}

fn replay_kel(evidence: &KeriEvidence, limits: KeriLimits) -> Result<KeyState, KeriError> {
    let mut parsed = Vec::with_capacity(evidence.events.len());
    for event in &evidence.events {
        parsed.push(parse_event(event, limits)?);
    }
    let first = parsed.first().ok_or(KeriError::EmptyKel)?;
    if first.kind != EventKind::Inception || first.sequence != 0 || first.prefix != first.said {
        return Err(KeriError::InvalidInception);
    }
    validate_threshold(first.threshold, first.keys.len())?;
    validate_threshold(first.next_threshold, first.next_commitments.len())?;
    verify_event_signatures(first, &first.keys, first.threshold)?;

    let mut state = KeyState {
        prefix: first.prefix.clone(),
        current_keys: first.keys.clone(),
        threshold: first.threshold,
        next_commitments: first.next_commitments.clone(),
        next_threshold: first.next_threshold,
        sequence: 0,
        establishment_sequence: 0,
        last_said: first.said.clone(),
        abandoned: false,
        establishment_only: first.establishment_only,
    };

    if state.next_commitments.is_empty() && parsed.len() > 1 {
        return Err(KeriError::NonTransferable);
    }

    for event in parsed.iter().skip(1) {
        if state.abandoned
            || event.sequence != state.sequence + 1
            || event.prefix != state.prefix
            || event.previous.as_deref() != Some(state.last_said.as_str())
        {
            return Err(KeriError::BrokenKel);
        }
        match event.kind {
            EventKind::Inception => return Err(KeriError::MultipleInceptions),
            EventKind::Rotation => {
                if state.next_commitments.is_empty() {
                    return Err(KeriError::NonTransferable);
                }
                validate_threshold(event.threshold, event.keys.len())?;
                validate_threshold(event.next_threshold, event.next_commitments.len())?;
                let verified = verify_event_signatures(event, &event.keys, event.threshold)?;
                verify_rotation_commitments(event, &state, &verified)?;
                state.current_keys = event.keys.clone();
                state.threshold = event.threshold;
                state.next_commitments = event.next_commitments.clone();
                state.next_threshold = event.next_threshold;
                state.establishment_sequence = event.sequence;
                state.abandoned = state.next_commitments.is_empty();
            }
            EventKind::Interaction => {
                if state.establishment_only {
                    return Err(KeriError::EstablishmentOnly);
                }
                verify_event_signatures(event, &state.current_keys, state.threshold)?;
            }
        }
        state.sequence = event.sequence;
        state.last_said = event.said.clone();
    }
    Ok(state)
}

fn parse_event(event: &KelEvent, limits: KeriLimits) -> Result<ParsedEvent, KeriError> {
    if event.event_json.len() > limits.max_event_bytes
        || event.attachment.len() > limits.max_attachment_bytes
    {
        return Err(KeriError::LimitExceeded);
    }
    let value: Value =
        serde_json::from_slice(&event.event_json).map_err(|_| KeriError::InvalidJson)?;
    if serde_json::to_vec(&value).map_err(|_| KeriError::InvalidJson)? != event.event_json {
        return Err(KeriError::NonCanonicalJson);
    }
    let object = value.as_object().ok_or(KeriError::InvalidJson)?;
    let event_type = text_field(object, "t")?;
    let (kind, fields) = match event_type {
        "icp" => (EventKind::Inception, ICP_FIELDS),
        "rot" => (EventKind::Rotation, ROT_FIELDS),
        "ixn" => (EventKind::Interaction, IXN_FIELDS),
        _ => return Err(KeriError::UnsupportedEvent),
    };
    if !object.keys().map(String::as_str).eq(fields.iter().copied()) {
        return Err(KeriError::InvalidFieldSet);
    }
    let expected_version = format!("KERI10JSON{:06x}_", event.event_json.len());
    if text_field(object, "v")? != expected_version {
        return Err(KeriError::InvalidVersion);
    }
    let said = parse_said(text_field(object, "d")?)?;
    let prefix = parse_said(text_field(object, "i")?)?;
    let sequence = parse_hex(text_field(object, "s")?)?;
    let previous = if kind == EventKind::Inception {
        None
    } else {
        Some(parse_said(text_field(object, "p")?)?)
    };
    verify_said(&value, kind, &said)?;

    let (threshold, keys, next_threshold, next_commitments, establishment_only) =
        if kind == EventKind::Interaction {
            if array_field(object, "a")?.len() > MAX_ANCHORS {
                return Err(KeriError::LimitExceeded);
            }
            (0, Vec::new(), 0, Vec::new(), false)
        } else {
            if parse_threshold(text_field(object, "bt")?)? != 0 {
                return Err(KeriError::UnsupportedWitnesses);
            }
            let backer_field = if kind == EventKind::Inception {
                "b"
            } else {
                "br"
            };
            if !array_field(object, backer_field)?.is_empty()
                || (kind == EventKind::Rotation && !array_field(object, "ba")?.is_empty())
            {
                return Err(KeriError::UnsupportedWitnesses);
            }
            if array_field(object, "a")?.len() > MAX_ANCHORS {
                return Err(KeriError::LimitExceeded);
            }
            let key_values = array_field(object, "k")?;
            if key_values.is_empty() || key_values.len() > limits.max_keys {
                return Err(KeriError::LimitExceeded);
            }
            let keys = key_values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .ok_or(KeriError::InvalidKey)
                        .and_then(KeriKey::parse)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let commitments = array_field(object, "n")?;
            if commitments.len() > limits.max_keys {
                return Err(KeriError::LimitExceeded);
            }
            let next_commitments = commitments
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .ok_or(KeriError::InvalidSaid)
                        .and_then(parse_said)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let establishment_only = if kind == EventKind::Inception {
                let traits = array_field(object, "c")?;
                if traits.len() > 16 || traits.iter().any(|value| value.as_str().is_none()) {
                    return Err(KeriError::InvalidFieldSet);
                }
                traits.iter().any(|value| value.as_str() == Some("EO"))
            } else {
                false
            };
            (
                parse_threshold(text_field(object, "kt")?)?,
                keys,
                parse_threshold(text_field(object, "nt")?)?,
                next_commitments,
                establishment_only,
            )
        };

    Ok(ParsedEvent {
        raw: event.event_json.clone(),
        kind,
        said,
        prefix,
        sequence,
        previous,
        threshold,
        keys,
        next_threshold,
        next_commitments,
        establishment_only,
        signatures: parse_attachment(&event.attachment, limits.max_keys)?,
    })
}

fn text_field<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, KeriError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(KeriError::InvalidFieldSet)
}

fn array_field<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Vec<Value>, KeriError> {
    object
        .get(key)
        .and_then(Value::as_array)
        .ok_or(KeriError::InvalidFieldSet)
}

fn parse_said(value: &str) -> Result<String, KeriError> {
    if value.len() != 44
        || !value.starts_with('E')
        || !value.bytes().all(|byte| {
            byte == b'-'
                || byte == b'_'
                || byte.is_ascii_uppercase()
                || byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
        })
    {
        return Err(KeriError::InvalidSaid);
    }
    let decoded = decode_one_char_matter(&value[1..]).map_err(|_| KeriError::InvalidSaid)?;
    if decoded.len() != 32 {
        return Err(KeriError::InvalidSaid);
    }
    Ok(value.to_string())
}

fn parse_hex(value: &str) -> Result<u128, KeriError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(KeriError::InvalidSequence);
    }
    u128::from_str_radix(value, 16).map_err(|_| KeriError::InvalidSequence)
}

fn parse_threshold(value: &str) -> Result<u16, KeriError> {
    let parsed = parse_hex(value)?;
    u16::try_from(parsed).map_err(|_| KeriError::UnsupportedThreshold)
}

fn validate_threshold(threshold: u16, item_count: usize) -> Result<(), KeriError> {
    if (item_count == 0 && threshold != 0)
        || (item_count > 0 && (threshold == 0 || usize::from(threshold) > item_count))
    {
        Err(KeriError::UnsatisfiedThreshold)
    } else {
        Ok(())
    }
}

fn verify_said(value: &Value, kind: EventKind, actual: &str) -> Result<(), KeriError> {
    let mut said_value = value.clone();
    let object = said_value.as_object_mut().ok_or(KeriError::InvalidJson)?;
    object.insert("d".to_string(), Value::String(SAID_PLACEHOLDER.to_string()));
    if kind == EventKind::Inception {
        object.insert("i".to_string(), Value::String(SAID_PLACEHOLDER.to_string()));
    }
    let serialized = serde_json::to_vec(&said_value).map_err(|_| KeriError::InvalidJson)?;
    let computed = encode_digest(blake3::hash(&serialized).as_bytes());
    if computed == actual {
        Ok(())
    } else {
        Err(KeriError::InvalidSaid)
    }
}

fn encode_digest(bytes: &[u8; 32]) -> String {
    encode_one_char_matter('E', bytes)
}

fn encode_one_char_matter(code: char, raw: &[u8]) -> String {
    let mut framed = Vec::with_capacity(raw.len() + 1);
    framed.push(0);
    framed.extend_from_slice(raw);
    let encoded = Base64UrlUnpadded::encode_string(&framed);
    format!("{code}{}", &encoded[1..])
}

fn decode_one_char_matter(payload: &str) -> Result<Vec<u8>, KeriError> {
    let framed = format!("A{payload}");
    let decoded = Base64UrlUnpadded::decode_vec(&framed).map_err(|_| KeriError::InvalidEvidence)?;
    if decoded.first() != Some(&0) {
        return Err(KeriError::InvalidEvidence);
    }
    Ok(decoded[1..].to_vec())
}

fn decode_indexed_signature(payload: &str) -> Result<Vec<u8>, KeriError> {
    let framed = format!("AA{payload}");
    let decoded =
        Base64UrlUnpadded::decode_vec(&framed).map_err(|_| KeriError::InvalidAttachment)?;
    if decoded.len() != 66 || decoded[..2] != [0, 0] {
        return Err(KeriError::InvalidAttachment);
    }
    Ok(decoded[2..].to_vec())
}

fn parse_attachment(
    bytes: &[u8],
    max_signatures: usize,
) -> Result<Vec<IndexedSignature>, KeriError> {
    let text = str::from_utf8(bytes).map_err(|_| KeriError::InvalidAttachment)?;
    if !text.is_ascii() {
        return Err(KeriError::InvalidAttachment);
    }
    let body = text
        .strip_prefix("-A")
        .ok_or(KeriError::InvalidAttachment)?;
    if body.len() < 2 {
        return Err(KeriError::InvalidAttachment);
    }
    let count = decode_b64_number(&body[..2])?;
    if count == 0 || count > max_signatures {
        return Err(KeriError::LimitExceeded);
    }
    let mut cursor = &body[2..];
    let mut signatures = Vec::with_capacity(count);
    let mut indices = BTreeSet::new();
    for _ in 0..count {
        let (code, width, index_width, prior_width, curve) = if cursor.starts_with("2A") {
            ("2A", 92, 2, 2, KeyCurve::Ed25519)
        } else if cursor.starts_with("2E") {
            ("2E", 92, 2, 2, KeyCurve::P256)
        } else if cursor.starts_with('A') {
            ("A", 88, 1, 0, KeyCurve::Ed25519)
        } else if cursor.starts_with('E') {
            ("E", 88, 1, 0, KeyCurve::P256)
        } else {
            return Err(KeriError::UnsupportedSignatureCode);
        };
        if cursor.len() < width {
            return Err(KeriError::InvalidAttachment);
        }
        let (encoded, remainder) = cursor.split_at(width);
        cursor = remainder;
        let mut offset = code.len();
        let index = decode_b64_number(&encoded[offset..offset + index_width])?;
        offset += index_width;
        let prior_index = if prior_width == 0 {
            None
        } else {
            let prior = decode_b64_number(&encoded[offset..offset + prior_width])?;
            offset += prior_width;
            Some(prior)
        };
        let signature = decode_indexed_signature(&encoded[offset..])?;
        if signature.len() != 64 || !indices.insert(index) {
            return Err(KeriError::InvalidAttachment);
        }
        signatures.push(IndexedSignature {
            index,
            prior_index,
            curve,
            bytes: signature,
        });
    }
    if !cursor.is_empty() {
        return Err(KeriError::InvalidAttachment);
    }
    Ok(signatures)
}

fn decode_b64_number(value: &str) -> Result<usize, KeriError> {
    if value.is_empty() {
        return Err(KeriError::InvalidAttachment);
    }
    let mut result = 0usize;
    for byte in value.bytes() {
        let digit = B64_ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or(KeriError::InvalidAttachment)?;
        result = result
            .checked_mul(64)
            .and_then(|number| number.checked_add(digit))
            .ok_or(KeriError::LimitExceeded)?;
    }
    Ok(result)
}

fn verify_event_signatures(
    event: &ParsedEvent,
    keys: &[KeriKey],
    threshold: u16,
) -> Result<Vec<IndexedSignature>, KeriError> {
    let mut verified = Vec::new();
    for signature in &event.signatures {
        let key = keys
            .get(signature.index)
            .ok_or(KeriError::InvalidSignature)?;
        if key.curve() != signature.curve {
            return Err(KeriError::AlgorithmMismatch);
        }
        key.verify(&event.raw, &signature.bytes)?;
        verified.push(signature.clone());
    }
    if verified.len() < usize::from(threshold) {
        return Err(KeriError::UnsatisfiedThreshold);
    }
    Ok(verified)
}

fn verify_rotation_commitments(
    event: &ParsedEvent,
    state: &KeyState,
    verified: &[IndexedSignature],
) -> Result<(), KeriError> {
    let mut revealed = BTreeSet::new();
    for signature in verified {
        let key = event
            .keys
            .get(signature.index)
            .ok_or(KeriError::CommitmentMismatch)?;
        let prior_index = signature.prior_index.unwrap_or(signature.index);
        let commitment = state
            .next_commitments
            .get(prior_index)
            .ok_or(KeriError::CommitmentMismatch)?;
        if commitment_for_key(key)? != *commitment {
            return Err(KeriError::CommitmentMismatch);
        }
        revealed.insert(prior_index);
    }
    if revealed.len() < usize::from(state.next_threshold) {
        return Err(KeriError::CommitmentMismatch);
    }
    Ok(())
}

fn commitment_for_key(key: &KeriKey) -> Result<String, KeriError> {
    let encoded = match key {
        KeriKey::Ed25519(bytes) => encode_one_char_matter('D', bytes),
        KeriKey::P256(bytes) => {
            format!("1AAJ{}", Base64UrlUnpadded::encode_string(bytes))
        }
    };
    Ok(encode_digest(blake3::hash(encoded.as_bytes()).as_bytes()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeriError {
    Model(ModelError),
    LimitExceeded,
    InvalidEvidence,
    InvalidJson,
    NonCanonicalJson,
    InvalidFieldSet,
    InvalidVersion,
    InvalidSaid,
    InvalidSequence,
    InvalidKey,
    UnsupportedKey,
    InvalidAttachment,
    UnsupportedSignatureCode,
    UnsupportedEvent,
    UnsupportedThreshold,
    UnsupportedWitnesses,
    InvalidInception,
    EmptyKel,
    BrokenKel,
    MultipleInceptions,
    NonTransferable,
    EstablishmentOnly,
    UnsatisfiedThreshold,
    InvalidSignature,
    AlgorithmMismatch,
    CommitmentMismatch,
    InvalidVerificationMethod,
}

impl From<ModelError> for KeriError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl fmt::Display for KeriError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Model(_) => "invalid Auths model value",
            Self::LimitExceeded => "KERI evidence exceeds a configured limit",
            Self::InvalidEvidence => "invalid KERI evidence envelope",
            Self::InvalidJson => "invalid KERI JSON",
            Self::NonCanonicalJson => "non-canonical KERI JSON",
            Self::InvalidFieldSet => "invalid or non-canonical KERI event fields",
            Self::InvalidVersion => "invalid KERI version or byte count",
            Self::InvalidSaid => "invalid KERI SAID",
            Self::InvalidSequence => "invalid KERI sequence",
            Self::InvalidKey => "invalid KERI key",
            Self::UnsupportedKey => "unsupported KERI key",
            Self::InvalidAttachment => "invalid CESR signature attachment",
            Self::UnsupportedSignatureCode => "unsupported CESR signature code",
            Self::UnsupportedEvent => "unsupported KERI event type",
            Self::UnsupportedThreshold => "unsupported KERI threshold",
            Self::UnsupportedWitnesses => "witnessed KELs are not supported by this profile",
            Self::InvalidInception => "invalid KERI inception",
            Self::EmptyKel => "empty KERI event log",
            Self::BrokenKel => "broken KERI event log",
            Self::MultipleInceptions => "multiple KERI inception events",
            Self::NonTransferable => "non-transferable KERI identifier changed state",
            Self::EstablishmentOnly => "establishment-only KERI identifier used an interaction",
            Self::UnsatisfiedThreshold => "KERI signing threshold was not satisfied",
            Self::InvalidSignature => "invalid KERI signature",
            Self::AlgorithmMismatch => "KERI key and signature algorithm differ",
            Self::CommitmentMismatch => "KERI pre-rotation commitment mismatch",
            Self::InvalidVerificationMethod => "invalid KERI verification method",
        };
        formatter.write_str(message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for KeriError {}

#[cfg(any(test, feature = "test-signing"))]
pub mod test_signing {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    pub struct TestKeriIdentity {
        principal: PrincipalRef,
        evidence: KeriEvidence,
        current_seed: [u8; 32],
        establishment_sequence: u128,
    }

    impl TestKeriIdentity {
        pub fn rotated_ed25519(
            inception_seed: [u8; 32],
            current_seed: [u8; 32],
            next_seed: [u8; 32],
        ) -> Result<Self, KeriError> {
            let inception_key = SigningKey::from_bytes(&inception_seed);
            let current_key = SigningKey::from_bytes(&current_seed);
            let next_key = SigningKey::from_bytes(&next_seed);
            let inception_qb64 = ed25519_qb64(&inception_key.verifying_key().to_bytes());
            let current_qb64 = ed25519_qb64(&current_key.verifying_key().to_bytes());
            let next_qb64 = ed25519_qb64(&next_key.verifying_key().to_bytes());

            let mut inception = Map::new();
            insert_text(&mut inception, "v", "KERI10JSON000000_");
            insert_text(&mut inception, "t", "icp");
            insert_text(&mut inception, "d", SAID_PLACEHOLDER);
            insert_text(&mut inception, "i", SAID_PLACEHOLDER);
            insert_text(&mut inception, "s", "0");
            insert_text(&mut inception, "kt", "1");
            insert_strings(&mut inception, "k", &[inception_qb64]);
            insert_text(&mut inception, "nt", "1");
            insert_strings(&mut inception, "n", &[commitment_for_qb64(&current_qb64)]);
            insert_text(&mut inception, "bt", "0");
            insert_array(&mut inception, "b");
            insert_array(&mut inception, "c");
            insert_array(&mut inception, "a");
            let (inception_raw, prefix) = finalize_event(inception, true)?;
            let inception_signature = inception_key.sign(&inception_raw).to_bytes();

            let mut rotation = Map::new();
            insert_text(&mut rotation, "v", "KERI10JSON000000_");
            insert_text(&mut rotation, "t", "rot");
            insert_text(&mut rotation, "d", SAID_PLACEHOLDER);
            insert_text(&mut rotation, "i", &prefix);
            insert_text(&mut rotation, "s", "1");
            insert_text(&mut rotation, "p", &prefix);
            insert_text(&mut rotation, "kt", "1");
            insert_strings(&mut rotation, "k", &[current_qb64]);
            insert_text(&mut rotation, "nt", "1");
            insert_strings(&mut rotation, "n", &[commitment_for_qb64(&next_qb64)]);
            insert_text(&mut rotation, "bt", "0");
            insert_array(&mut rotation, "br");
            insert_array(&mut rotation, "ba");
            insert_array(&mut rotation, "a");
            let (rotation_raw, _) = finalize_event(rotation, false)?;
            let rotation_signature = current_key.sign(&rotation_raw).to_bytes();

            let evidence = KeriEvidence::new(vec![
                KelEvent::new(
                    inception_raw,
                    single_ed25519_attachment(&inception_signature),
                )?,
                KelEvent::new(rotation_raw, single_ed25519_attachment(&rotation_signature))?,
            ])?;
            Ok(Self {
                principal: PrincipalRef::parse(&format!("{PRINCIPAL_PREFIX}{prefix}"))?,
                evidence,
                current_seed,
                establishment_sequence: 1,
            })
        }

        pub fn principal(&self) -> &PrincipalRef {
            &self.principal
        }

        pub fn evidence(&self) -> &KeriEvidence {
            &self.evidence
        }

        pub fn evidence_entry(&self) -> Result<PrincipalEvidenceEntry, KeriError> {
            self.evidence.evidence_entry()
        }

        pub fn verification_method(&self) -> Result<VerificationMethodRef, ModelError> {
            super::verification_method(&self.principal, self.establishment_sequence, 0)
        }

        pub fn signature_descriptor(&self) -> Result<SignatureDescriptor, ModelError> {
            Ok(SignatureDescriptor::new(
                AdapterId::parse(ADAPTER_ID)?,
                self.verification_method()?,
                AlgorithmId::parse(ED25519_ALGORITHM)?,
            ))
        }

        pub fn sign(&self, bytes: &[u8]) -> Vec<u8> {
            SigningKey::from_bytes(&self.current_seed)
                .sign(bytes)
                .to_bytes()
                .to_vec()
        }
    }

    fn ed25519_qb64(bytes: &[u8; 32]) -> String {
        encode_one_char_matter('D', bytes)
    }

    fn commitment_for_qb64(key: &str) -> String {
        encode_digest(blake3::hash(key.as_bytes()).as_bytes())
    }

    fn insert_text(map: &mut Map<String, Value>, key: &str, value: &str) {
        map.insert(key.to_string(), Value::String(value.to_string()));
    }

    fn insert_strings(map: &mut Map<String, Value>, key: &str, values: &[String]) {
        map.insert(
            key.to_string(),
            Value::Array(values.iter().cloned().map(Value::String).collect()),
        );
    }

    fn insert_array(map: &mut Map<String, Value>, key: &str) {
        map.insert(key.to_string(), Value::Array(Vec::new()));
    }

    fn finalize_event(
        mut map: Map<String, Value>,
        self_addressing: bool,
    ) -> Result<(Vec<u8>, String), KeriError> {
        let pass_one =
            serde_json::to_vec(&Value::Object(map.clone())).map_err(|_| KeriError::InvalidJson)?;
        map.insert(
            "v".to_string(),
            Value::String(format!("KERI10JSON{:06x}_", pass_one.len())),
        );
        let said_input =
            serde_json::to_vec(&Value::Object(map.clone())).map_err(|_| KeriError::InvalidJson)?;
        let said = encode_digest(blake3::hash(&said_input).as_bytes());
        map.insert("d".to_string(), Value::String(said.clone()));
        if self_addressing {
            map.insert("i".to_string(), Value::String(said.clone()));
        }
        let raw = serde_json::to_vec(&Value::Object(map)).map_err(|_| KeriError::InvalidJson)?;
        Ok((raw, said))
    }

    fn single_ed25519_attachment(signature: &[u8; 64]) -> Vec<u8> {
        let mut framed = Vec::with_capacity(signature.len() + 2);
        framed.extend_from_slice(&[0, 0]);
        framed.extend_from_slice(signature);
        format!("-AAB{}", Base64UrlUnpadded::encode_string(&framed)).into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_proof_adapter_api::ControlProofInput;
    use auths_proof_model::{ProofPurpose, Timestamp};

    #[test]
    fn deterministic_rotated_identity_verifies_control() {
        let identity =
            test_signing::TestKeriIdentity::rotated_ed25519([41; 32], [42; 32], [43; 32])
                .expect("identity");
        let evidence = identity.evidence_entry().expect("evidence");
        let method = identity.verification_method().expect("method");
        let algorithm = AlgorithmId::parse(ED25519_ALGORITHM).expect("algorithm");
        let signature = identity.sign(b"auths signing bytes");
        let adapter = DidKeriAdapter::new().expect("adapter");

        let verified = adapter
            .verify_control(ControlProofInput {
                principal: identity.principal(),
                purpose: ProofPurpose::CapabilityInvocation,
                verification_method: &method,
                algorithm: &algorithm,
                signing_bytes: b"auths signing bytes",
                signature: &signature,
                evidence: &evidence,
                asserted_signing_time: Timestamp::new(10),
                verification_time: Timestamp::new(11),
            })
            .expect("verified");

        assert_eq!(verified.principal(), identity.principal());
        assert!(verified.claims().contains(&AssuranceClaim::RotationAware));
    }

    #[test]
    fn forged_kel_signature_is_rejected() {
        let identity =
            test_signing::TestKeriIdentity::rotated_ed25519([51; 32], [52; 32], [53; 32])
                .expect("identity");
        let mut evidence = identity.evidence().clone();
        let final_byte = evidence.events[0].attachment.len() - 1;
        evidence.events[0].attachment[final_byte] =
            if evidence.events[0].attachment[final_byte] == b'A' {
                b'B'
            } else {
                b'A'
            };
        assert!(replay_kel(&evidence, KeriLimits::standard()).is_err());
    }

    #[test]
    fn accepts_independent_keripy_multisig_rotation() {
        let evidence = KeriEvidence::new(vec![
            KelEvent::new(
                include_bytes!("../tests/fixtures/keripy/rot_remove.icp.json").to_vec(),
                include_bytes!("../tests/fixtures/keripy/rot_remove.icp.att").to_vec(),
            )
            .expect("keripy inception"),
            KelEvent::new(
                include_bytes!("../tests/fixtures/keripy/rot_remove.rot.json").to_vec(),
                include_bytes!("../tests/fixtures/keripy/rot_remove.rot.att").to_vec(),
            )
            .expect("keripy rotation"),
        ])
        .expect("keripy KEL");

        parse_event(&evidence.events[0], KeriLimits::standard())
            .expect("keripy inception must parse");
        parse_event(&evidence.events[1], KeriLimits::standard())
            .expect("keripy rotation must parse");
        let state = replay_kel(&evidence, KeriLimits::standard())
            .expect("keripy-valid multisig rotation must be accepted");
        assert_eq!(state.sequence, 1);
        assert_eq!(state.establishment_sequence, 1);
        assert_eq!(state.current_keys.len(), 2);
        assert_eq!(state.threshold, 2);
    }

    #[test]
    fn rejects_independent_keripy_tampers() {
        let inception_json =
            include_bytes!("../tests/fixtures/keripy/rot_remove.icp.json").to_vec();
        let inception_attachment =
            include_bytes!("../tests/fixtures/keripy/rot_remove.icp.att").to_vec();
        let rotation_json = include_bytes!("../tests/fixtures/keripy/rot_remove.rot.json").to_vec();
        let rotation_attachment =
            include_bytes!("../tests/fixtures/keripy/rot_remove.rot.att").to_vec();

        let mut forged_attachment = inception_attachment.clone();
        forged_attachment[6] = if forged_attachment[6] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let forged = KeriEvidence::new(vec![
            KelEvent::new(inception_json.clone(), forged_attachment).expect("forged event"),
            KelEvent::new(rotation_json.clone(), rotation_attachment.clone())
                .expect("keripy rotation"),
        ])
        .expect("forged KEL envelope");
        assert!(replay_kel(&forged, KeriLimits::standard()).is_err());

        let mut one_signature = b"-AAB".to_vec();
        one_signature.extend_from_slice(&inception_attachment[4..92]);
        let below_threshold = KeriEvidence::new(vec![
            KelEvent::new(inception_json.clone(), one_signature).expect("threshold event"),
            KelEvent::new(rotation_json.clone(), rotation_attachment.clone())
                .expect("keripy rotation"),
        ])
        .expect("threshold KEL envelope");
        assert!(replay_kel(&below_threshold, KeriLimits::standard()).is_err());

        let wrong_said = b"EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let needle = b"\"p\":\"";
        let position = rotation_json
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("rotation prior field")
            + needle.len();
        let mut broken_prior = rotation_json;
        broken_prior[position..position + wrong_said.len()].copy_from_slice(wrong_said);
        let broken = KeriEvidence::new(vec![
            KelEvent::new(inception_json, inception_attachment).expect("keripy inception"),
            KelEvent::new(broken_prior, rotation_attachment).expect("broken rotation"),
        ])
        .expect("broken KEL envelope");
        assert!(replay_kel(&broken, KeriLimits::standard()).is_err());
    }
}
