//! Deterministic CBOR for the Auths proof-exchange V1 messages.

#![forbid(unsafe_code)]

use auths_proof_exchange_model::{
    ActionChallenge, ActionResponse, ActionSubmission, ChallengeNonce, EXCHANGE_VERSION_V1,
    ExchangeAudience, ExchangeCapabilities, ExchangeMetrics, ExchangeOutcome, ExchangeProfileId,
    MAX_MESSAGE_BYTES, MAX_NEGOTIATED_PROFILES, MAX_NEGOTIATED_VERSIONS, MAX_REASON_BYTES,
    MAX_REASON_COUNT, MAX_RESULT_BYTES, ModelError, ProfileBinding, RefusalKind, VerdictDecision,
    VerdictSummary,
};
use minicbor::{Decoder, Encoder, data::Type};
use std::fmt;

const CHALLENGE_FIELDS: u64 = 9;
const REQUEST_FIELDS: u64 = 7;
const RESPONSE_FIELDS: u64 = 9;
const CAPABILITIES_FIELDS: u64 = 5;

/// Encodes a canonical capability advertisement.
///
/// # Panics
///
/// Panics only if `minicbor` reports a write failure for its in-memory
/// `Vec<u8>` writer, which is treated as an implementation invariant.
#[must_use]
pub fn encode_capabilities(message: &ExchangeCapabilities) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(CAPABILITIES_FIELDS)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.u16(EXCHANGE_VERSION_V1))
        .and_then(|encoder| encoder.u8(2))
        .and_then(|encoder| encoder.array(message.exchange_versions().len() as u64))
        .expect("Vec writer is infallible");
    for version in message.exchange_versions() {
        encoder.u16(*version).expect("Vec writer is infallible");
    }
    encoder
        .u8(3)
        .and_then(|encoder| encoder.array(message.profiles().len() as u64))
        .expect("Vec writer is infallible");
    for profile in message.profiles() {
        encoder
            .map(3)
            .and_then(|encoder| encoder.u8(1))
            .and_then(|encoder| encoder.u16(profile.auths_protocol()))
            .and_then(|encoder| encoder.u8(2))
            .and_then(|encoder| encoder.str(profile.profile_id().as_str()))
            .and_then(|encoder| encoder.u8(3))
            .and_then(|encoder| encoder.u16(profile.profile_version()))
            .expect("Vec writer is infallible");
    }
    encoder
        .u8(4)
        .and_then(|encoder| encoder.u32(message.max_body_bytes()))
        .and_then(|encoder| encoder.u8(5))
        .and_then(|encoder| encoder.u32(message.max_proof_bytes()))
        .expect("Vec writer is infallible");
    encoder.into_writer()
}

/// Decodes a canonical, bounded capability advertisement.
///
/// # Errors
///
/// Returns a typed codec error for malformed, excessive, duplicate, or
/// non-canonical capabilities.
pub fn decode_capabilities(input: &[u8]) -> Result<ExchangeCapabilities, CodecError> {
    let mut decoder = Decoder::new(input);
    exact_map(&mut decoder, CAPABILITIES_FIELDS)?;
    exact_key(&mut decoder, 1)?;
    exact_version(&mut decoder)?;
    exact_key(&mut decoder, 2)?;
    let version_count = exact_array(&mut decoder)?;
    if version_count == 0 || version_count > MAX_NEGOTIATED_VERSIONS {
        return Err(CodecError::ResourceLimit);
    }
    let mut versions = Vec::with_capacity(version_count);
    for _ in 0..version_count {
        versions.push(decoder.u16()?);
    }
    exact_key(&mut decoder, 3)?;
    let profile_count = exact_array(&mut decoder)?;
    if profile_count == 0 || profile_count > MAX_NEGOTIATED_PROFILES {
        return Err(CodecError::ResourceLimit);
    }
    let mut profiles = Vec::with_capacity(profile_count);
    for _ in 0..profile_count {
        exact_map(&mut decoder, 3)?;
        exact_key(&mut decoder, 1)?;
        let auths_protocol = decoder.u16()?;
        exact_key(&mut decoder, 2)?;
        let profile_id = ExchangeProfileId::parse(decoder.str()?)?;
        exact_key(&mut decoder, 3)?;
        let profile_version = decoder.u16()?;
        profiles.push(ProfileBinding::new(
            auths_protocol,
            profile_id,
            profile_version,
        )?);
    }
    exact_key(&mut decoder, 4)?;
    let max_body_bytes = decoder.u32()?;
    exact_key(&mut decoder, 5)?;
    let max_proof_bytes = decoder.u32()?;
    finish(&decoder, input)?;
    let capabilities =
        ExchangeCapabilities::new(versions, profiles, max_body_bytes, max_proof_bytes)?;
    ensure_canonical(input, &encode_capabilities(&capabilities))?;
    Ok(capabilities)
}

/// Encodes a challenge in deterministic V1 CBOR.
///
/// # Panics
///
/// Panics only if `minicbor` reports a write failure for its in-memory
/// `Vec<u8>` writer, which is treated as an implementation invariant.
#[must_use]
pub fn encode_challenge(message: &ActionChallenge) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(CHALLENGE_FIELDS)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.u16(EXCHANGE_VERSION_V1))
        .and_then(|encoder| encoder.u8(2))
        .and_then(|encoder| encoder.bytes(message.challenge().as_bytes()))
        .and_then(|encoder| encoder.u8(3))
        .and_then(|encoder| encoder.str(message.audience().as_str()))
        .and_then(|encoder| encoder.u8(4))
        .and_then(|encoder| encoder.u64(message.expires_at()))
        .and_then(|encoder| encoder.u8(5))
        .and_then(|encoder| encoder.u32(message.max_body_bytes()))
        .and_then(|encoder| encoder.u8(6))
        .and_then(|encoder| encoder.u32(message.max_proof_bytes()))
        .and_then(|encoder| encoder.u8(7))
        .and_then(|encoder| encoder.u16(message.auths_protocol()))
        .and_then(|encoder| encoder.u8(8))
        .and_then(|encoder| encoder.str(message.profile_id().as_str()))
        .and_then(|encoder| encoder.u8(9))
        .and_then(|encoder| encoder.u16(message.profile_version()))
        .expect("Vec writer is infallible");
    encoder.into_writer()
}

/// Decodes a canonical, closed-map V1 challenge.
///
/// # Errors
///
/// Returns [`CodecError`] for malformed, non-canonical, unsupported, or
/// out-of-bounds input.
pub fn decode_challenge(input: &[u8]) -> Result<ActionChallenge, CodecError> {
    let mut decoder = Decoder::new(input);
    exact_map(&mut decoder, CHALLENGE_FIELDS)?;
    exact_key(&mut decoder, 1)?;
    exact_version(&mut decoder)?;
    exact_key(&mut decoder, 2)?;
    let challenge = array_32(decoder.bytes()?)?;
    exact_key(&mut decoder, 3)?;
    let audience = ExchangeAudience::parse(decoder.str()?)?;
    exact_key(&mut decoder, 4)?;
    let expires_at = decoder.u64()?;
    exact_key(&mut decoder, 5)?;
    let max_body_bytes = decoder.u32()?;
    exact_key(&mut decoder, 6)?;
    let max_proof_bytes = decoder.u32()?;
    exact_key(&mut decoder, 7)?;
    let auths_protocol = decoder.u16()?;
    exact_key(&mut decoder, 8)?;
    let profile_id = ExchangeProfileId::parse(decoder.str()?)?;
    exact_key(&mut decoder, 9)?;
    let profile_version = decoder.u16()?;
    finish(&decoder, input)?;
    let profile = ProfileBinding::new(auths_protocol, profile_id, profile_version)?;
    let message = ActionChallenge::new(
        ChallengeNonce::new(challenge),
        audience,
        expires_at,
        max_body_bytes,
        max_proof_bytes,
        profile,
    )?;
    ensure_canonical(input, &encode_challenge(&message))?;
    Ok(message)
}

/// Encodes an action submission in deterministic V1 CBOR.
///
/// # Panics
///
/// Panics only if `minicbor` reports a write failure for its in-memory
/// `Vec<u8>` writer, which is treated as an implementation invariant.
#[must_use]
pub fn encode_request(message: &ActionSubmission) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(REQUEST_FIELDS)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.u16(EXCHANGE_VERSION_V1))
        .and_then(|encoder| encoder.u8(2))
        .and_then(|encoder| encoder.bytes(message.challenge().as_bytes()))
        .and_then(|encoder| encoder.u8(3))
        .and_then(|encoder| encoder.u16(message.auths_protocol()))
        .and_then(|encoder| encoder.u8(4))
        .and_then(|encoder| encoder.str(message.profile_id().as_str()))
        .and_then(|encoder| encoder.u8(5))
        .and_then(|encoder| encoder.u16(message.profile_version()))
        .and_then(|encoder| encoder.u8(6))
        .and_then(|encoder| encoder.bytes(message.body()))
        .and_then(|encoder| encoder.u8(7))
        .and_then(|encoder| encoder.bytes(message.proof()))
        .expect("Vec writer is infallible");
    encoder.into_writer()
}

/// Decodes a canonical request under challenge-specific bounds.
///
/// # Errors
///
/// Returns [`CodecError`] for malformed, non-canonical, unsupported, or
/// out-of-bounds input.
pub fn decode_request(
    input: &[u8],
    challenge: &ActionChallenge,
) -> Result<ActionSubmission, CodecError> {
    let mut decoder = Decoder::new(input);
    exact_map(&mut decoder, REQUEST_FIELDS)?;
    exact_key(&mut decoder, 1)?;
    exact_version(&mut decoder)?;
    exact_key(&mut decoder, 2)?;
    let submitted_challenge = ChallengeNonce::new(array_32(decoder.bytes()?)?);
    exact_key(&mut decoder, 3)?;
    let auths_protocol = decoder.u16()?;
    exact_key(&mut decoder, 4)?;
    let profile_id = ExchangeProfileId::parse(decoder.str()?)?;
    exact_key(&mut decoder, 5)?;
    let profile_version = decoder.u16()?;
    exact_key(&mut decoder, 6)?;
    let body = decoder.bytes()?;
    if body.is_empty() || body.len() > challenge.max_body_bytes() as usize {
        return Err(CodecError::ResourceLimit);
    }
    exact_key(&mut decoder, 7)?;
    let proof = decoder.bytes()?;
    if proof.is_empty() || proof.len() > challenge.max_proof_bytes() as usize {
        return Err(CodecError::ResourceLimit);
    }
    finish(&decoder, input)?;
    let message = ActionSubmission::new(body.to_vec(), proof.to_vec(), challenge)?;
    if submitted_challenge != challenge.challenge()
        || auths_protocol != challenge.auths_protocol()
        || profile_id != *challenge.profile_id()
        || profile_version != challenge.profile_version()
        || !message.matches_challenge(challenge)
    {
        return Err(CodecError::Model(ModelError::SubmissionMismatch));
    }
    ensure_canonical(input, &encode_request(&message))?;
    Ok(message)
}

/// Encodes an action response in deterministic V1 CBOR.
///
/// # Panics
///
/// Panics only if `minicbor` reports a write failure for its in-memory
/// `Vec<u8>` writer, which is treated as an implementation invariant.
#[must_use]
pub fn encode_response(message: &ActionResponse) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(RESPONSE_FIELDS)
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.u16(EXCHANGE_VERSION_V1))
        .and_then(|encoder| encoder.u8(2))
        .expect("Vec writer is infallible");
    match message.request_id() {
        Some(request_id) => {
            encoder.bytes(request_id).expect("Vec writer is infallible");
        }
        None => {
            encoder.null().expect("Vec writer is infallible");
        }
    }

    let (outcome_code, result, refusal, verdict, message_text) = match message.outcome() {
        ExchangeOutcome::Completed { result } => (0, result.as_slice(), None, None, ""),
        ExchangeOutcome::Refused {
            kind,
            verdict,
            message,
        } => (1, &[][..], Some(*kind), verdict.as_ref(), message.as_str()),
        // Decision 11.8 (contract §10A / §5A.3): additive outcome code. A
        // possibly-applied effect carries no refusal kind, because it is not a
        // refusal, and no result, because none was observed.
        ExchangeOutcome::Indeterminate { verdict, message } => {
            (2, &[][..], None, verdict.as_ref(), message.as_str())
        }
    };

    encoder
        .u8(3)
        .and_then(|encoder| encoder.u8(outcome_code))
        .and_then(|encoder| encoder.u8(4))
        .and_then(|encoder| encoder.bytes(result))
        .and_then(|encoder| encoder.u8(5))
        .expect("Vec writer is infallible");
    match refusal {
        Some(kind) => {
            encoder
                .u8(refusal_to_wire(kind))
                .expect("Vec writer is infallible");
        }
        None => {
            encoder.null().expect("Vec writer is infallible");
        }
    }
    encoder.u8(6).expect("Vec writer is infallible");
    match verdict {
        Some(summary) => {
            encoder
                .u8(decision_to_wire(summary.decision()))
                .expect("Vec writer is infallible");
        }
        None => {
            encoder.null().expect("Vec writer is infallible");
        }
    }
    let reasons = verdict.map_or(&[][..], VerdictSummary::reasons);
    encoder
        .u8(7)
        .and_then(|encoder| encoder.array(reasons.len() as u64))
        .expect("Vec writer is infallible");
    for reason in reasons {
        encoder.str(reason).expect("Vec writer is infallible");
    }
    encoder
        .u8(8)
        .and_then(|encoder| encoder.str(message_text))
        .and_then(|encoder| encoder.u8(9))
        .and_then(|encoder| encoder.map(2))
        .and_then(|encoder| encoder.u8(1))
        .and_then(|encoder| encoder.u64(message.metrics().verification_micros()))
        .and_then(|encoder| encoder.u8(2))
        .and_then(|encoder| encoder.u64(message.metrics().execution_micros()))
        .expect("Vec writer is infallible");
    encoder.into_writer()
}

/// Decodes a canonical, closed-map V1 action response.
///
/// # Errors
///
/// Returns [`CodecError`] for malformed, non-canonical, unsupported, or
/// out-of-bounds input.
pub fn decode_response(input: &[u8]) -> Result<ActionResponse, CodecError> {
    let mut decoder = Decoder::new(input);
    exact_map(&mut decoder, RESPONSE_FIELDS)?;
    exact_key(&mut decoder, 1)?;
    exact_version(&mut decoder)?;
    exact_key(&mut decoder, 2)?;
    let request_id = decode_optional_array_32(&mut decoder)?;
    exact_key(&mut decoder, 3)?;
    let outcome_code = decoder.u8()?;
    exact_key(&mut decoder, 4)?;
    let result = decoder.bytes()?;
    if result.len() > MAX_RESULT_BYTES {
        return Err(CodecError::ResourceLimit);
    }
    exact_key(&mut decoder, 5)?;
    let refusal = decode_optional_u8(&mut decoder)?
        .map(refusal_from_wire)
        .transpose()?;
    exact_key(&mut decoder, 6)?;
    let decision = decode_optional_u8(&mut decoder)?
        .map(decision_from_wire)
        .transpose()?;
    exact_key(&mut decoder, 7)?;
    let reason_count = exact_array(&mut decoder)?;
    if reason_count > MAX_REASON_COUNT {
        return Err(CodecError::ResourceLimit);
    }
    let mut reasons = Vec::with_capacity(reason_count);
    for _ in 0..reason_count {
        let reason = decoder.str()?;
        if reason.is_empty() || reason.len() > MAX_REASON_BYTES {
            return Err(CodecError::ResourceLimit);
        }
        reasons.push(reason.to_owned());
    }
    exact_key(&mut decoder, 8)?;
    let message = decoder.str()?;
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(CodecError::ResourceLimit);
    }
    exact_key(&mut decoder, 9)?;
    exact_map(&mut decoder, 2)?;
    exact_key(&mut decoder, 1)?;
    let verification_micros = decoder.u64()?;
    exact_key(&mut decoder, 2)?;
    let execution_micros = decoder.u64()?;
    finish(&decoder, input)?;

    let outcome = match outcome_code {
        0 if refusal.is_none()
            && decision.is_none()
            && reasons.is_empty()
            && message.is_empty() =>
        {
            ExchangeOutcome::completed(result.to_vec())?
        }
        1 if result.is_empty() => {
            let kind = refusal.ok_or(CodecError::Malformed)?;
            let verdict = match decision {
                Some(decision) => Some(VerdictSummary::new(decision, reasons)?),
                None if reasons.is_empty() => None,
                None => return Err(CodecError::Malformed),
            };
            ExchangeOutcome::refused(kind, verdict, message)?
        }
        2 if result.is_empty() && refusal.is_none() => {
            let verdict = match decision {
                Some(decision) => Some(VerdictSummary::new(decision, reasons)?),
                None if reasons.is_empty() => None,
                None => return Err(CodecError::Malformed),
            };
            ExchangeOutcome::indeterminate(verdict, message)?
        }
        _ => return Err(CodecError::Malformed),
    };
    let response = ActionResponse::new(
        request_id,
        outcome,
        ExchangeMetrics::new(verification_micros, execution_micros),
    );
    ensure_canonical(input, &encode_response(&response))?;
    Ok(response)
}

fn exact_map(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), CodecError> {
    if decoder.map()? == Some(expected) {
        Ok(())
    } else {
        Err(CodecError::Malformed)
    }
}

fn exact_array(decoder: &mut Decoder<'_>) -> Result<usize, CodecError> {
    let length = decoder.array()?.ok_or(CodecError::Malformed)?;
    usize::try_from(length).map_err(|_| CodecError::ResourceLimit)
}

fn exact_key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), CodecError> {
    if decoder.u8()? == expected {
        Ok(())
    } else {
        Err(CodecError::NonCanonical)
    }
}

fn exact_version(decoder: &mut Decoder<'_>) -> Result<(), CodecError> {
    if decoder.u16()? == EXCHANGE_VERSION_V1 {
        Ok(())
    } else {
        Err(CodecError::UnsupportedVersion)
    }
}

fn finish(decoder: &Decoder<'_>, input: &[u8]) -> Result<(), CodecError> {
    if decoder.position() == input.len() {
        Ok(())
    } else {
        Err(CodecError::NonCanonical)
    }
}

fn ensure_canonical(input: &[u8], encoded: &[u8]) -> Result<(), CodecError> {
    if input == encoded {
        Ok(())
    } else {
        Err(CodecError::NonCanonical)
    }
}

fn array_32(bytes: &[u8]) -> Result<[u8; 32], CodecError> {
    bytes.try_into().map_err(|_| CodecError::Malformed)
}

fn decode_optional_array_32(decoder: &mut Decoder<'_>) -> Result<Option<[u8; 32]>, CodecError> {
    if decoder.datatype()? == Type::Null {
        decoder.null()?;
        Ok(None)
    } else {
        Ok(Some(array_32(decoder.bytes()?)?))
    }
}

fn decode_optional_u8(decoder: &mut Decoder<'_>) -> Result<Option<u8>, CodecError> {
    if decoder.datatype()? == Type::Null {
        decoder.null()?;
        Ok(None)
    } else {
        Ok(Some(decoder.u8()?))
    }
}

const fn refusal_to_wire(kind: RefusalKind) -> u8 {
    match kind {
        RefusalKind::ApplicationPolicy => 0,
        RefusalKind::TransportPolicy => 1,
        RefusalKind::AuthsVerdict => 2,
        RefusalKind::MalformedInput => 3,
        RefusalKind::OversizedInput => 4,
        RefusalKind::UnknownChallenge => 5,
        RefusalKind::ExpiredChallenge => 6,
        RefusalKind::ConsumedChallenge => 7,
    }
}

fn refusal_from_wire(value: u8) -> Result<RefusalKind, CodecError> {
    match value {
        0 => Ok(RefusalKind::ApplicationPolicy),
        1 => Ok(RefusalKind::TransportPolicy),
        2 => Ok(RefusalKind::AuthsVerdict),
        3 => Ok(RefusalKind::MalformedInput),
        4 => Ok(RefusalKind::OversizedInput),
        5 => Ok(RefusalKind::UnknownChallenge),
        6 => Ok(RefusalKind::ExpiredChallenge),
        7 => Ok(RefusalKind::ConsumedChallenge),
        _ => Err(CodecError::Malformed),
    }
}

const fn decision_to_wire(decision: VerdictDecision) -> u8 {
    match decision {
        VerdictDecision::Authorized => 0,
        VerdictDecision::Denied => 1,
        VerdictDecision::Indeterminate => 2,
    }
}

fn decision_from_wire(value: u8) -> Result<VerdictDecision, CodecError> {
    match value {
        0 => Ok(VerdictDecision::Authorized),
        1 => Ok(VerdictDecision::Denied),
        2 => Ok(VerdictDecision::Indeterminate),
        _ => Err(CodecError::Malformed),
    }
}

#[derive(Debug)]
pub enum CodecError {
    Malformed,
    NonCanonical,
    UnsupportedVersion,
    ResourceLimit,
    Cbor(minicbor::decode::Error),
    Model(ModelError),
}

impl From<minicbor::decode::Error> for CodecError {
    fn from(error: minicbor::decode::Error) -> Self {
        Self::Cbor(error)
    }
}

impl From<ModelError> for CodecError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => formatter.write_str("malformed exchange message"),
            Self::NonCanonical => formatter.write_str("non-canonical exchange message"),
            Self::UnsupportedVersion => formatter.write_str("unsupported exchange version"),
            Self::ResourceLimit => formatter.write_str("exchange resource limit exceeded"),
            Self::Cbor(error) => write!(formatter, "invalid CBOR: {error}"),
            Self::Model(error) => write!(formatter, "invalid exchange model: {error}"),
        }
    }
}

impl std::error::Error for CodecError {}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn challenge() -> ActionChallenge {
        ActionChallenge::new(
            ChallengeNonce::new([0xa5; 32]),
            ExchangeAudience::parse("mcp://reports").unwrap(),
            100,
            1024,
            4096,
            ProfileBinding::new(
                auths_proof_exchange_model::AUTHS_PROTOCOL_V1,
                ExchangeProfileId::parse("auths.mcp").unwrap(),
                1,
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn messages_round_trip_canonically() {
        let challenge = challenge();
        let encoded = encode_challenge(&challenge);
        assert_eq!(decode_challenge(&encoded).unwrap(), challenge);

        let request =
            ActionSubmission::new(b"body".to_vec(), b"proof".to_vec(), &challenge).unwrap();
        let encoded = encode_request(&request);
        assert_eq!(decode_request(&encoded, &challenge).unwrap(), request);

        let verdict =
            VerdictSummary::new(VerdictDecision::Denied, vec!["InvalidSignature".into()]).unwrap();
        let response = ActionResponse::new(
            Some([9; 32]),
            ExchangeOutcome::refused(
                RefusalKind::AuthsVerdict,
                Some(verdict),
                "authorization refused",
            )
            .unwrap(),
            ExchangeMetrics::new(12, 0),
        );
        let encoded = encode_response(&response);
        assert_eq!(decode_response(&encoded).unwrap(), response);
    }

    /// Decision 11.8 (contract §10A / §5A.3). An unknown-effect response must
    /// survive the wire as itself. If it decoded as a refusal the caller would
    /// retry a possibly-applied effect, which is the exact failure the third
    /// member exists to prevent.
    #[test]
    fn an_indeterminate_response_round_trips_and_never_decodes_as_a_refusal() {
        let verdict =
            VerdictSummary::new(VerdictDecision::Authorized, vec!["authorized".into()]).unwrap();
        let response = ActionResponse::new(
            None,
            ExchangeOutcome::indeterminate(
                Some(verdict),
                "effect possible, reconcile before retry: provider call timed out",
            )
            .unwrap(),
            ExchangeMetrics::new(12, 0),
        );
        let encoded = encode_response(&response);
        let decoded = decode_response(&encoded).unwrap();
        assert_eq!(decoded, response);
        assert!(matches!(
            decoded.outcome(),
            ExchangeOutcome::Indeterminate { .. }
        ));

        // Same shape without a verdict, so the optional field is exercised.
        let bare = ActionResponse::new(
            None,
            ExchangeOutcome::indeterminate(None, "unknown effect").unwrap(),
            ExchangeMetrics::new(0, 0),
        );
        assert_eq!(decode_response(&encode_response(&bare)).unwrap(), bare);
    }

    /// An indeterminate response carries no refusal kind and no result. A
    /// hand-built encoding that smuggles either in must fail closed rather than
    /// decode into a member whose fields the encoder never wrote.
    #[test]
    fn an_indeterminate_response_rejects_a_refusal_kind_or_a_result() {
        let refused = ActionResponse::new(
            None,
            ExchangeOutcome::refused(RefusalKind::ApplicationPolicy, None, "refused").unwrap(),
            ExchangeMetrics::new(0, 0),
        );
        let mut smuggled = encode_response(&refused);
        // Flip only the outcome code 1 -> 2, leaving the refusal kind in place.
        let baseline = encode_response(&ActionResponse::new(
            None,
            ExchangeOutcome::indeterminate(None, "refused").unwrap(),
            ExchangeMetrics::new(0, 0),
        ));
        let index = smuggled
            .iter()
            .zip(&baseline)
            .position(|(left, right)| left != right)
            .expect("outcome code differs");
        assert_eq!(smuggled[index], 1);
        smuggled[index] = 2;
        assert!(decode_response(&smuggled).is_err());
    }

    #[test]
    fn capabilities_round_trip_without_downgrade_aliases() {
        let capabilities = ExchangeCapabilities::new(
            vec![EXCHANGE_VERSION_V1],
            vec![
                ProfileBinding::new(
                    auths_proof_exchange_model::AUTHS_PROTOCOL_V1,
                    ExchangeProfileId::parse("auths.mcp").unwrap(),
                    1,
                )
                .unwrap(),
            ],
            1024,
            4096,
        )
        .unwrap();
        let encoded = encode_capabilities(&capabilities);
        assert_eq!(decode_capabilities(&encoded).unwrap(), capabilities);
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded = encode_challenge(&challenge());
        encoded.push(0);
        assert!(matches!(
            decode_challenge(&encoded),
            Err(CodecError::NonCanonical)
        ));
    }

    proptest! {
        #[test]
        fn arbitrary_messages_never_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..8192)
        ) {
            let _ = decode_capabilities(&bytes);
            let _ = decode_challenge(&bytes);
            let _ = decode_response(&bytes);
            let _ = decode_request(&bytes, &challenge());
        }
    }
}
