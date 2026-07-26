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
use auths_model::{
    AdapterConfigurationId, AdapterId, AssuranceClaim, AssuranceClaimId, EvidenceId,
    EvidenceSourceId, EvidenceTypeId, MediaType, ModelError, PrincipalId, PrincipalMethodId,
    Timestamp, VerificationMethod,
};
use auths_ports::{ControlEvidence, PrincipalControlError, PrincipalControlInput, PrincipalMethod};
use base64ct::{Base64UrlUnpadded, Encoding};
use core::{fmt, str};
use ed25519_dalek::{Signature as Ed25519Signature, Verifier as _, VerifyingKey as Ed25519Key};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256Key};
use serde_json::{Map, Value};

pub const ADAPTER_ID: &str = "did-keri-v1";
pub const EVIDENCE_MEDIA_TYPE: &str = "application/vnd.auths.did-keri-kel.v1";
pub const PRINCIPAL_PREFIX: &str = "did:keri:";
pub const ED25519_SUITE: &str = "ed25519-v1";
pub const P256_SUITE: &str = "p256-sha256-v1";
pub const EVIDENCE_DOMAIN: &[u8] = b"AUTHS-DID-KERI\x00\x01";

const SAID_PLACEHOLDER: &str = "############################################";
const MAX_EVENTS: usize = 64;
const MAX_EVENT_BYTES: usize = 64 * 1024;
const MAX_ATTACHMENT_BYTES: usize = 16 * 1024;
const MAX_KEYS: usize = 16;
const MAX_ANCHORS: usize = 64;
const MAX_CHECKPOINTS: usize = 256;

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
    /// Returns the closed target V1 limits for KERI evidence.
    #[must_use]
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
    /// Constructs one bounded event and its detached CESR attachment.
    ///
    /// # Errors
    ///
    /// Returns [`KeriError::LimitExceeded`] when either component is empty or
    /// exceeds the target V1 bound.
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

    /// Returns the exact canonical KERI event JSON.
    #[must_use]
    pub fn event_json(&self) -> &[u8] {
        &self.event_json
    }

    /// Returns the exact detached CESR attachment.
    #[must_use]
    pub fn attachment(&self) -> &[u8] {
        &self.attachment
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeriEvidence {
    events: Vec<KelEvent>,
}

impl KeriEvidence {
    /// Constructs a non-empty bounded key-event log.
    ///
    /// # Errors
    ///
    /// Returns [`KeriError::LimitExceeded`] when the event count is invalid.
    pub fn new(events: Vec<KelEvent>) -> Result<Self, KeriError> {
        if events.is_empty() || events.len() > MAX_EVENTS {
            return Err(KeriError::LimitExceeded);
        }
        Ok(Self { events })
    }

    /// Returns the ordered key-event log.
    #[must_use]
    pub fn events(&self) -> &[KelEvent] {
        &self.events
    }

    /// Encodes the bounded target V1 KERI evidence envelope.
    ///
    /// # Errors
    ///
    /// Returns [`KeriError::LimitExceeded`] if an event length cannot be
    /// represented by the target envelope.
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

    /// Decodes one exact bounded target V1 KERI evidence envelope.
    ///
    /// # Errors
    ///
    /// Returns a typed KERI parsing or resource-limit error for invalid input.
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

pub struct DidKeriMethod {
    id: PrincipalMethodId,
    evidence_type: EvidenceTypeId,
    media_type: MediaType,
    adapter: AdapterId,
    source: EvidenceSourceId,
    limits: KeriLimits,
    checkpoints: Vec<KeriCheckpoint>,
}

impl DidKeriMethod {
    /// Constructs the target V1 method with standard limits and no checkpoints.
    ///
    /// # Errors
    ///
    /// Returns a typed model or limit error if fixed registry values are
    /// invalid.
    pub fn new() -> Result<Self, KeriError> {
        Self::with_context(KeriLimits::standard(), Vec::new())
    }

    /// Constructs the target V1 method with deployment-specific limits.
    ///
    /// # Errors
    ///
    /// Returns [`KeriError::LimitExceeded`] for limits outside protocol hard
    /// maxima, or a model error for invalid fixed registry values.
    pub fn with_limits(limits: KeriLimits) -> Result<Self, KeriError> {
        Self::with_context(limits, Vec::new())
    }

    /// Constructs the method with immutable KERI checkpoints.
    ///
    /// # Errors
    ///
    /// Returns a typed model or limit error for invalid limits, registry
    /// values, or an excessive checkpoint collection.
    pub fn with_context(
        limits: KeriLimits,
        mut checkpoints: Vec<KeriCheckpoint>,
    ) -> Result<Self, KeriError> {
        if checkpoints.len() > MAX_CHECKPOINTS {
            return Err(KeriError::LimitExceeded);
        }
        checkpoints.sort_by(|left, right| {
            (
                &left.principal,
                left.sequence,
                &left.event_said,
                left.observed_at,
                left.valid_until,
                left.witness_threshold,
            )
                .cmp(&(
                    &right.principal,
                    right.sequence,
                    &right.event_said,
                    right.observed_at,
                    right.valid_until,
                    right.witness_threshold,
                ))
        });
        if checkpoints.windows(2).any(|window| {
            window[0].principal == window[1].principal && window[0].sequence == window[1].sequence
        }) {
            return Err(KeriError::InvalidCheckpoint);
        }
        Ok(Self {
            id: PrincipalMethodId::parse(ADAPTER_ID)?,
            evidence_type: EvidenceTypeId::parse(ADAPTER_ID)?,
            media_type: MediaType::parse(EVIDENCE_MEDIA_TYPE)?,
            adapter: AdapterId::parse(ADAPTER_ID)?,
            source: EvidenceSourceId::parse(ADAPTER_ID)?,
            limits: limits.validate()?,
            checkpoints,
        })
    }
}

impl PrincipalMethod for DidKeriMethod {
    fn id(&self) -> &PrincipalMethodId {
        &self.id
    }

    fn configuration_id(&self) -> AdapterConfigurationId {
        let mut components = vec![
            u64::try_from(self.limits.max_events)
                .unwrap_or(u64::MAX)
                .to_be_bytes()
                .to_vec(),
            u64::try_from(self.limits.max_event_bytes)
                .unwrap_or(u64::MAX)
                .to_be_bytes()
                .to_vec(),
            u64::try_from(self.limits.max_attachment_bytes)
                .unwrap_or(u64::MAX)
                .to_be_bytes()
                .to_vec(),
            u64::try_from(self.limits.max_keys)
                .unwrap_or(u64::MAX)
                .to_be_bytes()
                .to_vec(),
        ];
        for checkpoint in &self.checkpoints {
            components.push(checkpoint.principal.as_str().as_bytes().to_vec());
            components.push(checkpoint.sequence.to_be_bytes().to_vec());
            components.push(checkpoint.event_said.as_bytes().to_vec());
            components.push(checkpoint.observed_at.get().to_be_bytes().to_vec());
            components.push(checkpoint.valid_until.get().to_be_bytes().to_vec());
            components.push(match checkpoint.witness_threshold {
                Some((required, verified)) => {
                    let mut value = vec![1];
                    value.extend_from_slice(&required.to_be_bytes());
                    value.extend_from_slice(&verified.to_be_bytes());
                    value
                }
                None => vec![0],
            });
        }
        auths_ports::configuration_id(ADAPTER_ID.as_bytes(), components.iter().map(Vec::as_slice))
    }

    fn maximum_work_units(&self) -> u64 {
        60 + 40 * 64
    }

    fn verify_control(
        &self,
        input: PrincipalControlInput<'_>,
    ) -> Result<ControlEvidence, PrincipalControlError> {
        if !input.principal.as_str().starts_with(PRINCIPAL_PREFIX) {
            return Err(PrincipalControlError::PrincipalMethodMismatch);
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
        let kel =
            KeriEvidence::decode(evidence.bytes(), self.limits).map_err(map_evidence_error)?;
        let state = replay_kel(&kel, self.limits).map_err(map_evidence_error)?;
        let expected_principal = PrincipalId::parse(&format!("{PRINCIPAL_PREFIX}{}", state.prefix))
            .map_err(|_| PrincipalControlError::InvalidEvidence)?;
        if expected_principal != *input.principal {
            return Err(PrincipalControlError::PrincipalMethodMismatch);
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
        if input.signature_suite.as_str() != key.suite() {
            return Err(PrincipalControlError::SignatureSuiteMismatch);
        }

        let mut claims = vec![
            claim("self-certifying-identifier", None, &self.source)?,
            claim("offline-verifiable", None, &self.source)?,
        ];
        if !state.abandoned && !state.next_commitments.is_empty() {
            claims.push(claim("rotation-aware", None, &self.source)?);
        }
        if let Some(checkpoint) = self.checkpoints.iter().find(|checkpoint| {
            checkpoint.principal == *input.principal
                && checkpoint.sequence == state.sequence
                && checkpoint.event_said == state.last_said
                && checkpoint.observed_at <= input.evaluation_time
                && input.evaluation_time <= checkpoint.valid_until
        }) {
            claims.push(claim(
                "controller-state-current-at",
                Some(checkpoint.observed_at),
                &self.source,
            )?);
            claims.push(claim(
                "revocation-checked-at",
                Some(checkpoint.observed_at),
                &self.source,
            )?);
            if checkpoint.witness_threshold.is_some() {
                claims.push(claim(
                    "witness-threshold-met",
                    Some(checkpoint.observed_at),
                    &self.source,
                )?);
            }
        }
        let work_units = 60u64
            .checked_add(
                u64::try_from(kel.events().len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(40),
            )
            .ok_or(PrincipalControlError::ResourceLimitExceeded)?;
        ControlEvidence::new(
            key.public_key(),
            claims,
            vec![EvidenceId::new(*evidence.id().as_bytes())],
            self.adapter.clone(),
            1,
            work_units,
        )
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

/// Verifier-local authenticated observation of the latest accepted KERI event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeriCheckpoint {
    principal: PrincipalId,
    sequence: u128,
    event_said: String,
    observed_at: Timestamp,
    valid_until: Timestamp,
    witness_threshold: Option<(u16, u16)>,
}

impl KeriCheckpoint {
    /// Constructs a bounded immutable checkpoint.
    ///
    /// `witness_threshold` is `(required, verified)` and is accepted only when
    /// both are non-zero and `verified >= required`.
    ///
    /// # Errors
    ///
    /// Returns [`KeriError::InvalidCheckpoint`] when the principal, SAID,
    /// validity, or witness observation is invalid.
    pub fn new(
        principal: PrincipalId,
        sequence: u128,
        event_said: String,
        observed_at: Timestamp,
        valid_until: Timestamp,
        witness_threshold: Option<(u16, u16)>,
    ) -> Result<Self, KeriError> {
        if principal
            .as_str()
            .strip_prefix(PRINCIPAL_PREFIX)
            .is_none_or(|prefix| parse_said(prefix).is_err())
            || parse_said(&event_said).is_err()
            || observed_at > valid_until
            || witness_threshold
                .is_some_and(|(required, verified)| required == 0 || verified < required)
        {
            return Err(KeriError::InvalidCheckpoint);
        }
        Ok(Self {
            principal,
            sequence,
            event_said,
            observed_at,
            valid_until,
            witness_threshold,
        })
    }
}

fn map_evidence_error(error: KeriError) -> PrincipalControlError {
    match error {
        KeriError::LimitExceeded => PrincipalControlError::ResourceLimitExceeded,
        _ => PrincipalControlError::InvalidEvidence,
    }
}

/// Derives the exact target V1 verification-method identifier for a KERI key.
///
/// # Errors
///
/// Returns [`ModelError`] when the formatted identifier exceeds model bounds.
pub fn verification_method(
    principal: &PrincipalId,
    establishment_sequence: u128,
    key_index: usize,
) -> Result<VerificationMethod, ModelError> {
    VerificationMethod::parse(&format!(
        "{}#key-{:x}-{key_index}",
        principal.as_str(),
        establishment_sequence
    ))
}

fn parse_verification_method(
    principal: &PrincipalId,
    method: &VerificationMethod,
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

struct EstablishmentFields {
    threshold: u16,
    keys: Vec<KeriKey>,
    next_threshold: u16,
    next_commitments: Vec<String>,
    establishment_only: bool,
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

    const fn suite(&self) -> &'static str {
        match self {
            Self::Ed25519(_) => ED25519_SUITE,
            Self::P256(_) => P256_SUITE,
        }
    }

    fn public_key(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(bytes) => bytes.to_vec(),
            Self::P256(bytes) => bytes.to_vec(),
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
                state.current_keys.clone_from(&event.keys);
                state.threshold = event.threshold;
                state.next_commitments.clone_from(&event.next_commitments);
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
        state.last_said.clone_from(&event.said);
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

    let fields = parse_establishment_fields(kind, object, limits)?;

    Ok(ParsedEvent {
        raw: event.event_json.clone(),
        kind,
        said,
        prefix,
        sequence,
        previous,
        threshold: fields.threshold,
        keys: fields.keys,
        next_threshold: fields.next_threshold,
        next_commitments: fields.next_commitments,
        establishment_only: fields.establishment_only,
        signatures: parse_attachment(&event.attachment, limits.max_keys)?,
    })
}

fn parse_establishment_fields(
    kind: EventKind,
    object: &Map<String, Value>,
    limits: KeriLimits,
) -> Result<EstablishmentFields, KeriError> {
    if array_field(object, "a")?.len() > MAX_ANCHORS {
        return Err(KeriError::LimitExceeded);
    }
    if kind == EventKind::Interaction {
        return Ok(EstablishmentFields {
            threshold: 0,
            keys: Vec::new(),
            next_threshold: 0,
            next_commitments: Vec::new(),
            establishment_only: false,
        });
    }
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
    Ok(EstablishmentFields {
        threshold: parse_threshold(text_field(object, "kt")?)?,
        keys,
        next_threshold: parse_threshold(text_field(object, "nt")?)?,
        next_commitments,
        establishment_only,
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
        if commitment_for_key(key) != *commitment {
            return Err(KeriError::CommitmentMismatch);
        }
        revealed.insert(prior_index);
    }
    if revealed.len() < usize::from(state.next_threshold) {
        return Err(KeriError::CommitmentMismatch);
    }
    Ok(())
}

fn commitment_for_key(key: &KeriKey) -> String {
    let encoded = match key {
        KeriKey::Ed25519(bytes) => encode_one_char_matter('D', bytes),
        KeriKey::P256(bytes) => {
            format!("1AAJ{}", Base64UrlUnpadded::encode_string(bytes))
        }
    };
    encode_digest(blake3::hash(encoded.as_bytes()).as_bytes())
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
    InvalidCheckpoint,
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
            Self::InvalidCheckpoint => "invalid KERI checkpoint",
        };
        formatter.write_str(message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for KeriError {}

#[cfg(any(test, feature = "test-signing"))]
pub mod test_signing {
    use super::{
        encode_digest, encode_one_char_matter, KelEvent, KeriError, KeriEvidence, ADAPTER_ID,
        ED25519_SUITE, PRINCIPAL_PREFIX, SAID_PLACEHOLDER,
    };
    use alloc::{
        format,
        string::{String, ToString},
        vec,
        vec::Vec,
    };
    use auths_model::{
        ModelError, PrincipalId, PrincipalMethodId, SignatureDescriptor, SignatureSuiteId,
        VerificationMethod,
    };
    use base64ct::{Base64UrlUnpadded, Encoding as _};
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde_json::{Map, Value};

    #[derive(Clone)]
    pub struct TestKeriIdentity {
        principal: PrincipalId,
        evidence: KeriEvidence,
        current_seed: [u8; 32],
        establishment_sequence: u128,
    }

    impl TestKeriIdentity {
        /// Builds a deterministic two-event transferable Ed25519 identity.
        ///
        /// # Errors
        ///
        /// Returns a typed KERI or model error if generated target values
        /// violate their bounds.
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
                principal: PrincipalId::parse(&format!("{PRINCIPAL_PREFIX}{prefix}"))?,
                evidence,
                current_seed,
                establishment_sequence: 1,
            })
        }

        /// Returns the generated KERI principal.
        #[must_use]
        pub fn principal(&self) -> &PrincipalId {
            &self.principal
        }

        /// Returns the signed two-event KEL evidence.
        #[must_use]
        pub fn evidence(&self) -> &KeriEvidence {
            &self.evidence
        }

        /// Returns the current key's exact verification method.
        ///
        /// # Errors
        ///
        /// Returns [`ModelError`] if the method identifier violates bounds.
        pub fn verification_method(&self) -> Result<VerificationMethod, ModelError> {
            super::verification_method(&self.principal, self.establishment_sequence, 0)
        }

        /// Returns the current target V1 signature descriptor.
        ///
        /// # Errors
        ///
        /// Returns [`ModelError`] if a fixed registry identifier is invalid.
        pub fn signature_descriptor(&self) -> Result<SignatureDescriptor, ModelError> {
            Ok(SignatureDescriptor::new(
                PrincipalMethodId::parse(ADAPTER_ID)?,
                self.verification_method()?,
                SignatureSuiteId::parse(ED25519_SUITE)?,
            ))
        }

        /// Signs exact bytes with the current establishment key.
        #[must_use]
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
    use auths_codec::evidence_id;
    use auths_model::{Digest, EvidenceObject, SignatureSuiteId, Timestamp};
    use auths_ports::{ControlPurpose, PrincipalControlInput};

    fn keripy_fixture(bytes: &[u8]) -> Vec<u8> {
        bytes.strip_suffix(b"\n").unwrap_or(bytes).to_vec()
    }

    #[test]
    fn deterministic_rotated_identity_verifies_control() {
        let identity =
            test_signing::TestKeriIdentity::rotated_ed25519([41; 32], [42; 32], [43; 32])
                .expect("identity");
        let encoded = identity.evidence().encode().expect("evidence");
        let unaddressed = EvidenceObject::new(
            EvidenceId::from_digest(Digest::ZERO),
            EvidenceTypeId::parse(ADAPTER_ID).expect("evidence type"),
            MediaType::parse(EVIDENCE_MEDIA_TYPE).expect("media type"),
            encoded,
        )
        .expect("evidence");
        let evidence = EvidenceObject::new(
            evidence_id(&unaddressed).expect("evidence ID"),
            unaddressed.evidence_type().clone(),
            unaddressed.media_type().clone(),
            unaddressed.bytes().to_vec(),
        )
        .expect("addressed evidence");
        let refs = [&evidence];
        let method = identity.verification_method().expect("method");
        let suite = SignatureSuiteId::parse(ED25519_SUITE).expect("suite");
        let state = replay_kel(identity.evidence(), KeriLimits::standard()).expect("state");
        let checkpoint = KeriCheckpoint::new(
            identity.principal().clone(),
            state.sequence,
            state.last_said,
            Timestamp::new(10),
            Timestamp::new(20),
            Some((2, 3)),
        )
        .expect("checkpoint");
        let adapter =
            DidKeriMethod::with_context(KeriLimits::standard(), vec![checkpoint]).expect("adapter");

        let verified = adapter
            .verify_control(PrincipalControlInput {
                principal: identity.principal(),
                verification_method: &method,
                signature_suite: &suite,
                purpose: ControlPurpose::CapabilityInvocation,
                signing_preimage: b"auths signing bytes",
                asserted_signing_time: Timestamp::new(10),
                evidence: &refs,
                evaluation_time: Timestamp::new(11),
            })
            .expect("verified");

        assert_eq!(verified.verification_key().len(), 32);
        assert!(verified
            .claims()
            .iter()
            .any(|claim| claim.kind().as_str() == "rotation-aware"));
        assert!(verified
            .claims()
            .iter()
            .any(|claim| claim.kind().as_str() == "controller-state-current-at"));
        assert!(verified
            .claims()
            .iter()
            .any(|claim| claim.kind().as_str() == "witness-threshold-met"));
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
                keripy_fixture(include_bytes!(
                    "../tests/fixtures/keripy/rot_remove.icp.json"
                )),
                keripy_fixture(include_bytes!(
                    "../tests/fixtures/keripy/rot_remove.icp.att"
                )),
            )
            .expect("keripy inception"),
            KelEvent::new(
                keripy_fixture(include_bytes!(
                    "../tests/fixtures/keripy/rot_remove.rot.json"
                )),
                keripy_fixture(include_bytes!(
                    "../tests/fixtures/keripy/rot_remove.rot.att"
                )),
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
        let inception_json = keripy_fixture(include_bytes!(
            "../tests/fixtures/keripy/rot_remove.icp.json"
        ));
        let inception_attachment = keripy_fixture(include_bytes!(
            "../tests/fixtures/keripy/rot_remove.icp.att"
        ));
        let rotation_json = keripy_fixture(include_bytes!(
            "../tests/fixtures/keripy/rot_remove.rot.json"
        ));
        let rotation_attachment = keripy_fixture(include_bytes!(
            "../tests/fixtures/keripy/rot_remove.rot.att"
        ));

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
