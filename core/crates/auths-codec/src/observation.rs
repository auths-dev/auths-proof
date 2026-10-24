//! Deterministic encoding of signed observations, observation requirements,
//! observer anchors, and reported observation satisfactions.

use crate::cbor::{Decoder, Encoder, Type};
use crate::{
    CanonicalSignedObservation, CodecError,
    decode::{
        V1Decoder, array, bounded_bytes, digest_bytes, ensure_complete, evidence, key, map,
        signature, text,
    },
    encode::{
        V1Encoder, array as encode_array, bytes, encode_error, encode_signature,
        encode_signature_descriptor, key as encode_key, map as encode_map,
        text as encode_text,
    },
};
use alloc::vec::Vec;
use auths_model::{
    AttachmentDigest, ConditionTest, FactBytes, FactName, FactText, FactValue, LimitKind,
    MAX_MEMBER_VALUES, MAX_OBSERVATION_BYTES, MAX_OBSERVATION_CONDITIONS, MAX_OBSERVATION_EVIDENCE,
    MAX_OBSERVATION_FACTS, MAX_OBSERVATION_REQUIREMENTS_PER_GRANT, MAX_OBSERVER_ANCHORS,
    MemberValues, ObservationCondition, ObservationFact, ObservationFacts, ObservationRequirement,
    ObservationRequirementId, ObservationRequirements, ObservationSatisfaction,
    ObservationSchemaId, ObservationStatement, ObservationSubject, ObserverAnchor,
    ObserverAnchorId, PrincipalId, ResourceId, SignatureDescriptor,
    SignedObservation, Timestamp, UintRange, ValidityWindow, VerifierLimits,
};

/// Upper bound on reported observation satisfactions in one result.
pub(crate) const MAX_OBSERVATION_SATISFACTIONS: usize = 1_024;

fn encode_fact_value(encoder: &mut V1Encoder, value: &FactValue) -> Result<(), CodecError> {
    match value {
        FactValue::Uint(value) => {
            encoder.u64(*value).map_err(encode_error)?;
            Ok(())
        }
        FactValue::Bytes(value) => bytes(encoder, value.as_slice()),
        FactValue::Text(value) => encode_text(encoder, value.as_str()),
    }
}

fn fact_value(decoder: &mut V1Decoder<'_>) -> Result<FactValue, CodecError> {
    match decoder.datatype().map_err(|_| CodecError::Malformed)? {
        Type::U8 | Type::U16 | Type::U32 | Type::U64 => Ok(FactValue::Uint(
            decoder.u64().map_err(|_| CodecError::Malformed)?,
        )),
        Type::Bytes => Ok(FactValue::Bytes(FactBytes::new(bounded_bytes(
            decoder,
            auths_model::MAX_FACT_VALUE_BYTES,
            false,
        )?)?)),
        Type::String => {
            let value = text(decoder)?;
            if value.len() > auths_model::MAX_FACT_VALUE_TEXT_BYTES {
                return Err(CodecError::LimitExceeded);
            }
            Ok(FactValue::Text(FactText::new(value)?))
        }
        _ => Err(CodecError::Malformed),
    }
}

fn fact_name(decoder: &mut V1Decoder<'_>) -> Result<FactName, CodecError> {
    FactName::parse(text(decoder)?).map_err(CodecError::from)
}

fn timestamp(decoder: &mut V1Decoder<'_>) -> Result<Timestamp, CodecError> {
    Ok(Timestamp::new(
        decoder.u64().map_err(|_| CodecError::Malformed)?,
    ))
}

pub(crate) fn encode_observation_statement_to(
    encoder: &mut V1Encoder,
    statement: &ObservationStatement,
) -> Result<(), CodecError> {
    encode_map(encoder, 6)?;
    encode_key(encoder, 0)?;
    encoder
        .u16(statement.version().get())
        .map_err(encode_error)?;
    encode_key(encoder, 1)?;
    encode_text(encoder, statement.observer().as_str())?;
    encode_key(encoder, 2)?;
    encode_text(encoder, statement.schema().as_str())?;
    encode_key(encoder, 3)?;
    encode_text(encoder, statement.subject().as_str())?;
    encode_key(encoder, 4)?;
    encoder
        .u64(statement.observed_at().get())
        .map_err(encode_error)?;
    encode_key(encoder, 5)?;
    encode_observation_facts(encoder, statement.facts().as_slice())?;
    Ok(())
}

fn observation_statement(decoder: &mut V1Decoder<'_>) -> Result<ObservationStatement, CodecError> {
    map(decoder, 6)?;
    key(decoder, 0)?;
    auths_model::ProtocolVersion::new(decoder.u16().map_err(|_| CodecError::Malformed)?)?;
    key(decoder, 1)?;
    let observer = PrincipalId::parse(text(decoder)?)?;
    key(decoder, 2)?;
    let schema = ObservationSchemaId::parse(text(decoder)?)?;
    key(decoder, 3)?;
    let subject = ResourceId::parse(text(decoder)?)?;
    key(decoder, 4)?;
    let observed_at = timestamp(decoder)?;
    key(decoder, 5)?;
    let count = array(decoder, MAX_OBSERVATION_FACTS)?;
    let facts = crate::collections::read_items!(count, observation_fact(decoder))?;
    Ok(ObservationStatement::new(
        observer,
        schema,
        subject,
        observed_at,
        ObservationFacts::new(facts)?,
    ))
}

fn encode_signed_observation_to(
    encoder: &mut V1Encoder,
    observation: &SignedObservation,
) -> Result<(), CodecError> {
    encode_map(encoder, 3)?;
    encode_key(encoder, 0)?;
    encode_observation_statement_to(encoder, observation.statement())?;
    encode_key(encoder, 1)?;
    encode_signature(encoder, observation.signature())?;
    encode_key(encoder, 2)?;
    crate::encode::encode_evidence_objects(encoder, observation.evidence())?;
    Ok(())
}

/// Encodes one signed observation as detached attachment bytes.
/// Requires explicit canonical construction, including evidence content IDs.
///
/// # Errors
///
/// Returns [`CodecError`] if the observation cannot be represented.
pub fn encode_signed_observation(observation: &CanonicalSignedObservation) -> Result<Vec<u8>, CodecError> {
    encode_signed_observation_value(observation.as_value())
}

pub(crate) fn encode_signed_observation_value(observation: &SignedObservation) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_signed_observation_to(&mut encoder, observation)?;
    Ok(encoder.into_writer())
}

/// Encodes the canonical unsigned observation statement.
///
/// # Errors
///
/// Returns [`CodecError`] if the statement cannot be represented.
pub fn encode_observation_statement(
    statement: &ObservationStatement,
) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_observation_statement_to(&mut encoder, statement)?;
    Ok(encoder.into_writer())
}

/// Encodes the canonical observation signing object.
///
/// # Errors
///
/// Returns [`CodecError`] if the statement cannot be represented.
pub fn encode_observation_signing_input(
    statement: &ObservationStatement,
    descriptor: &SignatureDescriptor,
) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_map(&mut encoder, 2)?;
    encode_key(&mut encoder, 0)?;
    encode_observation_statement_to(&mut encoder, statement)?;
    encode_key(&mut encoder, 1)?;
    encode_signature_descriptor(&mut encoder, descriptor)?;
    Ok(encoder.into_writer())
}

/// Decodes one signed observation attachment of at most 4 KiB.
/// Returns an immutable carrier with content-consistent evidence. Freshness,
/// signature validity and observer trust remain separate obligations.
///
/// # Errors
///
/// Returns [`CodecError::LimitExceeded`] above the byte or collection
/// bounds, and a typed error for malformed, non-canonical, or invalid bytes.
pub fn decode_signed_observation(
    input: &[u8],
    limits: &VerifierLimits,
) -> Result<CanonicalSignedObservation, CodecError> {
    limits.validate()?;
    if input.len() > MAX_OBSERVATION_BYTES {
        return Err(CodecError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    map(&mut decoder, 3)?;
    key(&mut decoder, 0)?;
    let statement = observation_statement(&mut decoder)?;
    key(&mut decoder, 1)?;
    let signature = signature(&mut decoder, limits)?;
    key(&mut decoder, 2)?;
    let count = array(&mut decoder, MAX_OBSERVATION_EVIDENCE)?;
    let objects = crate::collections::read_items!(count, evidence(&mut decoder, limits))?;
    let observation = SignedObservation::new(statement, signature, objects)?;
    ensure_complete(&decoder, input)?;
    let observation = crate::canonical_value::checked_signed_observation(observation)?;
    crate::canonical::accept(input, encode_signed_observation(&observation)?, observation)
}

fn encode_member_values(encoder: &mut V1Encoder, values: &[FactValue]) -> Result<(), CodecError> {
    encode_array(encoder, values.len())?;
    crate::collections::write_items!(values, value => encode_fact_value(encoder, value))?;
    Ok(())
}

fn encode_condition(
    encoder: &mut V1Encoder,
    condition: &ObservationCondition,
) -> Result<(), CodecError> {
    let (tag, entries) = match condition.test() {
        ConditionTest::EqLiteral(_) => (0, 3),
        ConditionTest::EqAction(_) => (1, 3),
        ConditionTest::UintRange(_) => (2, 4),
        ConditionTest::Member(_) => (3, 3),
    };
    encode_map(encoder, entries)?;
    encode_key(encoder, 0)?;
    encode_key(encoder, tag)?;
    encode_key(encoder, 1)?;
    encode_text(encoder, condition.name().as_str())?;
    encode_key(encoder, 2)?;
    match condition.test() {
        ConditionTest::EqLiteral(value) => encode_fact_value(encoder, value)?,
        ConditionTest::EqAction(name) => encode_text(encoder, name.as_str())?,
        ConditionTest::UintRange(range) => {
            encoder.u64(range.lo()).map_err(encode_error)?;
            encode_key(encoder, 3)?;
            encoder.u64(range.hi()).map_err(encode_error)?;
        }
        ConditionTest::Member(values) => {
            encode_member_values(encoder, values.as_slice())?;
        }
    }
    Ok(())
}

fn condition(decoder: &mut V1Decoder<'_>) -> Result<ObservationCondition, CodecError> {
    let entries = decoder.map().map_err(|_| CodecError::Malformed)?;
    key(decoder, 0)?;
    let tag = decoder.u8().map_err(|_| CodecError::Malformed)?;
    if entries != Some(if tag == 2 { 4 } else { 3 }) {
        return Err(CodecError::Malformed);
    }
    key(decoder, 1)?;
    let name = fact_name(decoder)?;
    key(decoder, 2)?;
    let test = match tag {
        0 => ConditionTest::EqLiteral(fact_value(decoder)?),
        1 => ConditionTest::EqAction(fact_name(decoder)?),
        2 => {
            let lo = decoder.u64().map_err(|_| CodecError::Malformed)?;
            key(decoder, 3)?;
            let hi = decoder.u64().map_err(|_| CodecError::Malformed)?;
            ConditionTest::UintRange(UintRange::new(lo, hi)?)
        }
        3 => {
            let count = array(decoder, MAX_MEMBER_VALUES)?;
            let values = crate::collections::read_items!(count, fact_value(decoder))?;
            ConditionTest::Member(MemberValues::new(values)?)
        }
        _ => return Err(CodecError::Malformed),
    };
    Ok(ObservationCondition::new(name, test))
}

fn encode_observation_subject(
    encoder: &mut V1Encoder,
    subject: &ObservationSubject,
) -> Result<(), CodecError> {
    encode_map(encoder, 2)?;
    encode_key(encoder, 0)?;
    match subject {
        ObservationSubject::Resource(resource) => {
            encode_key(encoder, 0)?;
            encode_key(encoder, 1)?;
            encode_text(encoder, resource.as_str())?;
        }
        ObservationSubject::ActionFact(name) => {
            encode_key(encoder, 1)?;
            encode_key(encoder, 1)?;
            encode_text(encoder, name.as_str())?;
        }
    }
    Ok(())
}

fn encode_conditions(
    encoder: &mut V1Encoder,
    conditions: &[ObservationCondition],
) -> Result<(), CodecError> {
    encode_array(encoder, conditions.len())?;
    crate::collections::write_items!(conditions, condition => encode_condition(encoder, condition))?;
    Ok(())
}

fn encode_requirement_to(
    encoder: &mut V1Encoder,
    requirement: &ObservationRequirement,
) -> Result<(), CodecError> {
    encode_map(encoder, 5)?;
    encode_key(encoder, 0)?;
    encode_text(encoder, requirement.observer_anchor().as_str())?;
    encode_key(encoder, 1)?;
    encode_text(encoder, requirement.schema().as_str())?;
    encode_key(encoder, 2)?;
    encode_observation_subject(encoder, requirement.subject())?;
    encode_key(encoder, 3)?;
    encoder
        .u32(requirement.max_age_seconds())
        .map_err(encode_error)?;
    encode_key(encoder, 4)?;
    encode_conditions(encoder, requirement.conditions())?;
    Ok(())
}

fn requirement(decoder: &mut V1Decoder<'_>) -> Result<ObservationRequirement, CodecError> {
    map(decoder, 5)?;
    key(decoder, 0)?;
    let observer_anchor = ObserverAnchorId::parse(text(decoder)?)?;
    key(decoder, 1)?;
    let schema = ObservationSchemaId::parse(text(decoder)?)?;
    key(decoder, 2)?;
    map(decoder, 2)?;
    key(decoder, 0)?;
    let subject_kind = decoder.u8().map_err(|_| CodecError::Malformed)?;
    key(decoder, 1)?;
    let subject = match subject_kind {
        0 => ObservationSubject::Resource(ResourceId::parse(text(decoder)?)?),
        1 => ObservationSubject::ActionFact(fact_name(decoder)?),
        _ => return Err(CodecError::Malformed),
    };
    key(decoder, 3)?;
    let max_age_seconds = decoder.u32().map_err(|_| CodecError::Malformed)?;
    key(decoder, 4)?;
    let count = array(decoder, MAX_OBSERVATION_CONDITIONS)?;
    let conditions = crate::collections::read_items!(count, condition(decoder))?;
    ObservationRequirement::new(
        observer_anchor,
        schema,
        subject,
        max_age_seconds,
        conditions,
    )
    .map_err(CodecError::from)
}

/// Encodes one requirement as its canonical content bytes.
///
/// # Errors
///
/// Returns [`CodecError`] if the requirement cannot be represented.
pub fn encode_observation_requirement(
    requirement: &ObservationRequirement,
) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_requirement_to(&mut encoder, requirement)?;
    Ok(encoder.into_writer())
}

/// Encodes the exact bytes of an `observation-requirement-v1` extension.
///
/// # Errors
///
/// Returns [`CodecError`] if the requirements cannot be represented.
pub fn encode_observation_requirements(
    requirements: &ObservationRequirements,
) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_array(&mut encoder, requirements.as_slice().len())?;
    crate::collections::write_items!(requirements.as_slice(), requirement => encode_requirement_to(&mut encoder, requirement))?;
    Ok(encoder.into_writer())
}

/// Decodes the exact bytes of an `observation-requirement-v1` extension.
///
/// # Errors
///
/// Returns [`CodecError::LimitExceeded`] above eight requirements, sixteen
/// conditions, or sixteen membership values, and a typed error for
/// malformed, non-canonical, or invalid bytes.
pub fn decode_observation_requirements(
    input: &[u8],
) -> Result<ObservationRequirements, CodecError> {
    if input.len() > auths_model::HARD_MAX_EXTENSION_BYTES {
        return Err(CodecError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    let count = array(&mut decoder, MAX_OBSERVATION_REQUIREMENTS_PER_GRANT)?;
    let requirements = crate::collections::read_items!(count, requirement(&mut decoder))?;
    let requirements = ObservationRequirements::new(requirements).map_err(|error| match error {
        auths_model::ModelError::CollectionLimitExceeded => CodecError::LimitExceeded,
        other => CodecError::Model(other),
    })?;
    ensure_complete(&decoder, input)?;
    crate::canonical::accept(input, encode_observation_requirements(&requirements)?, requirements)
}

pub(crate) fn encode_observer_anchors(
    encoder: &mut V1Encoder,
    anchors: &[ObserverAnchor],
) -> Result<(), CodecError> {
    encode_array(encoder, anchors.len())?;
    crate::collections::write_items!(anchors, anchor => encode_observer_anchor(encoder, anchor))?;
    Ok(())
}

pub(crate) fn observer_anchors(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<Vec<ObserverAnchor>, CodecError> {
    let count = array(decoder, MAX_OBSERVER_ANCHORS)?;
    let anchors = crate::collections::read_items!(count, observer_anchor(decoder, limits))?;
    Ok(anchors)
}

pub(crate) fn encode_observation_satisfactions(
    encoder: &mut V1Encoder,
    satisfactions: &[ObservationSatisfaction],
) -> Result<(), CodecError> {
    encode_array(encoder, satisfactions.len())?;
    crate::collections::write_items!(satisfactions, satisfaction => encode_observation_satisfaction(encoder, satisfaction))?;
    Ok(())
}

pub(crate) fn observation_satisfactions(
    decoder: &mut V1Decoder<'_>,
) -> Result<Vec<ObservationSatisfaction>, CodecError> {
    let count = array(decoder, MAX_OBSERVATION_SATISFACTIONS)?;
    let satisfactions = crate::collections::read_items!(count, observation_satisfaction(decoder))?;
    Ok(satisfactions)
}

fn encode_observation_facts(encoder: &mut V1Encoder, values: &[ObservationFact]) -> Result<(), CodecError> {
    encode_array(encoder, values.len())?;
    crate::collections::write_items!(values, fact => encode_observation_fact(encoder, fact))?;
    Ok(())
}

fn encode_observation_fact(encoder: &mut V1Encoder, fact: &ObservationFact) -> Result<(), CodecError> {
    encode_map(encoder, 2)?;
    encode_key(encoder, 0)?;
    encode_text(encoder, fact.name().as_str())?;
    encode_key(encoder, 1)?;
    encode_fact_value(encoder, fact.value())?;
    Ok(())
}

fn encode_observer_anchor(encoder: &mut V1Encoder, anchor: &ObserverAnchor) -> Result<(), CodecError> {
    encode_map(encoder, 7)?;
    encode_key(encoder, 0)?;
    encode_text(encoder, anchor.id().as_str())?;
    encode_key(encoder, 1)?;
    encode_text(encoder, anchor.principal().as_str())?;
    encode_key(encoder, 2)?;
    crate::text_list::encode_principal_methods(encoder, anchor.accepted_methods())?;
    encode_key(encoder, 3)?;
    crate::text_list::encode_observation_schemas(encoder, anchor.schemas())?;
    encode_key(encoder, 4)?;
    crate::text_list::encode_resource_ids(encoder, anchor.subject_namespaces())?;
    encode_key(encoder, 5)?;
    encoder
        .u64(anchor.validity().not_before().get())
        .map_err(encode_error)?;
    encode_key(encoder, 6)?;
    encoder
        .u64(anchor.validity().expires_at().get())
        .map_err(encode_error)?;
    Ok(())
}

fn encode_observation_satisfaction(encoder: &mut V1Encoder, satisfaction: &ObservationSatisfaction) -> Result<(), CodecError> {
    encode_map(encoder, 2)?;
    encode_key(encoder, 0)?;
    bytes(encoder, satisfaction.requirement().as_bytes())?;
    encode_key(encoder, 1)?;
    bytes(encoder, satisfaction.observation().as_bytes())?;
    Ok(())
}

fn observation_fact(decoder: &mut V1Decoder<'_>) -> Result<ObservationFact, CodecError> {
    map(decoder, 2)?;
    key(decoder, 0)?;
    let name = fact_name(decoder)?;
    key(decoder, 1)?;
    Ok(ObservationFact::new(name, fact_value(decoder)?))
}

fn observer_anchor(decoder: &mut V1Decoder<'_>, limits: &VerifierLimits) -> Result<ObserverAnchor, CodecError> {
    map(decoder, 7)?;
    key(decoder, 0)?;
    let id = ObserverAnchorId::parse(text(decoder)?)?;
    key(decoder, 1)?;
    let principal = PrincipalId::parse(text(decoder)?)?;
    key(decoder, 2)?;
    let methods = crate::text_list::principal_methods(decoder, limits.get(LimitKind::RegistryEntries))?;
    key(decoder, 3)?;
    let schemas = crate::text_list::observation_schemas(decoder, limits.get(LimitKind::RegistryEntries))?;
    key(decoder, 4)?;
    let namespaces = crate::text_list::resource_ids(decoder, limits.get(LimitKind::Permissions))?;
    key(decoder, 5)?;
    let not_before = timestamp(decoder)?;
    key(decoder, 6)?;
    let expires_at = timestamp(decoder)?;
    Ok(ObserverAnchor::new(
        id,
        principal,
        methods,
        schemas,
        namespaces,
        ValidityWindow::new(not_before, expires_at)?,
    )?)
}

fn observation_satisfaction(decoder: &mut V1Decoder<'_>) -> Result<ObservationSatisfaction, CodecError> {
    map(decoder, 2)?;
    key(decoder, 0)?;
    let requirement = ObservationRequirementId::new(digest_bytes(decoder)?);
    key(decoder, 1)?;
    let observation = AttachmentDigest::new(digest_bytes(decoder)?);
    Ok(ObservationSatisfaction::new(requirement, observation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic_and_accepted_bytes_are_canonical(
            input in proptest::collection::vec(any::<u8>(), 0..512)
        ) {
            if let Ok(requirements) = decode_observation_requirements(&input) {
                prop_assert_eq!(encode_observation_requirements(&requirements).unwrap(), input.clone());
            }
            if let Ok(observation) = decode_signed_observation(&input, &VerifierLimits::default()) {
                prop_assert_eq!(encode_signed_observation(&observation).unwrap(), input);
            }
        }
    }

    fn name(value: &str) -> FactName {
        FactName::parse(value).unwrap()
    }

    fn requirement_with(conditions: Vec<ObservationCondition>) -> ObservationRequirement {
        ObservationRequirement::new(
            ObserverAnchorId::parse("gateway-observer").unwrap(),
            ObservationSchemaId::parse("auths.gateway-readback/1").unwrap(),
            ObservationSubject::ActionFact(name("record_uri")),
            60,
            conditions,
        )
        .unwrap()
    }

    #[test]
    fn requirements_round_trip_every_condition_atom() {
        let requirements = ObservationRequirements::new(vec![requirement_with(vec![
            ObservationCondition::new(
                name("field.Status"),
                ConditionTest::EqAction(name("expected")),
            ),
            ObservationCondition::new(
                name("count"),
                ConditionTest::UintRange(UintRange::new(1, 9).unwrap()),
            ),
            ObservationCondition::new(
                name("stage"),
                ConditionTest::Member(
                    MemberValues::new(vec![
                        FactValue::Text(FactText::new("observed-by-provider").unwrap()),
                        FactValue::Uint(7),
                    ])
                    .unwrap(),
                ),
            ),
            ObservationCondition::new(
                name("etag"),
                ConditionTest::EqLiteral(FactValue::Bytes(FactBytes::new(vec![1, 2]).unwrap())),
            ),
        ])])
        .unwrap();
        let bytes = encode_observation_requirements(&requirements).unwrap();
        assert_eq!(
            decode_observation_requirements(&bytes).unwrap(),
            requirements
        );
    }

    #[test]
    fn requirement_limits_fail_at_the_exact_boundary() {
        let one = requirement_with(vec![ObservationCondition::new(
            name("stage"),
            ConditionTest::EqLiteral(FactValue::Uint(1)),
        )]);
        let many: Vec<_> = (0..=MAX_OBSERVATION_REQUIREMENTS_PER_GRANT)
            .map(|index| {
                requirement_with(vec![ObservationCondition::new(
                    name("stage"),
                    ConditionTest::EqLiteral(FactValue::Uint(index as u64)),
                )])
            })
            .collect();
        let at_limit =
            ObservationRequirements::new(many[..MAX_OBSERVATION_REQUIREMENTS_PER_GRANT].to_vec())
                .unwrap();
        let bytes = encode_observation_requirements(&at_limit).unwrap();
        assert!(decode_observation_requirements(&bytes).is_ok());
        let mut over = bytes.clone();
        over[0] += 1;
        over.extend(encode_observation_requirement(&one).unwrap());
        assert_eq!(
            decode_observation_requirements(&over),
            Err(CodecError::LimitExceeded)
        );
    }

    #[test]
    fn inverted_range_and_non_canonical_integers_are_rejected() {
        let requirements =
            ObservationRequirements::new(vec![requirement_with(vec![ObservationCondition::new(
                name("count"),
                ConditionTest::UintRange(UintRange::new(1, 1).unwrap()),
            )])])
            .unwrap();
        let bytes = encode_observation_requirements(&requirements).unwrap();
        let position = bytes.len() - 1;
        let mut inverted = bytes.clone();
        inverted[position - 2] = 2;
        assert!(decode_observation_requirements(&inverted).is_err());
        assert!(UintRange::new(2, 1).is_err());
    }
}
