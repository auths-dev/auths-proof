//! Frozen pre-refactor text-list algorithm, used only for source-cutover parity.

use super::*;
use crate::cbor::Decoder;
use core::fmt::Debug;

fn reference<T>(
    decoder: &mut V1Decoder<'_>,
    maximum: usize,
    parse: impl Fn(&str) -> Result<T, auths_model::ModelError>,
) -> Result<Vec<T>, CodecError> {
    let length = array(decoder, maximum)?;
    let mut values = Vec::with_capacity(length);
    for _ in 0..length {
        values.push(parse(text(decoder)?)?);
    }
    Ok(values)
}

fn same<T: Debug + Eq>(
    input: &[u8],
    maximum: usize,
    read: impl Fn(&mut V1Decoder<'_>, usize) -> Result<Vec<T>, CodecError>,
    parse: impl Fn(&str) -> Result<T, auths_model::ModelError>,
) {
    let mut actual = Decoder::new(input);
    let mut expected = Decoder::new(input);
    assert_eq!(
        read(&mut actual, maximum),
        reference(&mut expected, maximum, parse),
        "input={input:?}, maximum={maximum}"
    );
    assert_eq!(
        actual.position(),
        expected.position(),
        "failure/success cursor: input={input:?}, maximum={maximum}"
    );
}

fn corpus() -> Vec<Vec<u8>> {
    let mut valid = Vec::from([0x81, 0x71]);
    valid.extend_from_slice(b"did:example:actor");
    // The text above is 17 bytes. Keep explicit headers independent of the
    // production encoder: this corpus is also a malformed-input/cursor oracle.
    let mut followed_by_error = valid.clone();
    followed_by_error[0] = 0x83;
    followed_by_error.extend_from_slice(&[0x61, b' ', 0x61, b'z']);
    let mut two = valid.clone();
    two[0] = 0x82;
    two.extend_from_slice(&valid[1..]);
    let mut inputs = alloc::vec![
        Vec::new(),
        alloc::vec![0x80],
        alloc::vec![0x80, 0xff],
        alloc::vec![0x81],
        alloc::vec![0x81, 0x00],
        alloc::vec![0x81, 0x60],
        alloc::vec![0x81, 0x61, b'a'],
        alloc::vec![0x81, 0x61, b' '],
        alloc::vec![0x81, 0x62, 0xc0, 0x80],
        alloc::vec![0x81, 0x63, 0xed, 0xa0, 0x80],
        alloc::vec![0x81, 0x78, 0x01, b'a'],
        alloc::vec![0x98, 0x01, 0x61, b'a'],
        alloc::vec![0x9f, 0x61, b'a', 0xff],
        alloc::vec![0x9b, 255, 255, 255, 255, 255, 255, 255, 255],
        followed_by_error,
        two,
    ];
    for end in 0..=valid.len() {
        inputs.push(valid[..end].to_vec());
    }
    for position in 0..valid.len() {
        for byte in [0, 1, 23, 24, 31, 32, 127, 128, 192, 224, 237, 244, 246, 255] {
            let mut changed = valid.clone();
            changed[position] = byte;
            inputs.push(changed);
        }
    }
    inputs.push(valid);
    inputs
}

macro_rules! parity_tests {
    ($($name:ident => $kind:ident),+ $(,)?) => {$ (
        #[test]
        fn $name() {
            for input in corpus() {
                for maximum in [0, 1, 2, 16] {
                    same(&input, maximum, super::$name, auths_model::$kind::parse);
                }
            }
        }
    )+};
}

parity_tests! {
    principal_ids => PrincipalId,
    principal_methods => PrincipalMethodId,
    resource_ids => ResourceId,
    signature_suites => SignatureSuiteId,
    evidence_types => EvidenceTypeId,
    status_methods => StatusMethodId,
    assurance_claims => AssuranceClaimId,
    assurance_implications => AssuranceImplicationId,
    resource_matchers => ResourceMatcherId,
    budget_algebras => BudgetAlgebraId,
    extension_ids => ExtensionId,
    profile_policies => ProfilePolicyId,
    observation_schemas => ObservationSchemaId,
    audiences => Audience,
}

fn reference_write<T>(
    encoder: &mut V1Encoder,
    values: &[T],
    as_str: impl Fn(&T) -> &str,
) -> Result<(), CodecError> {
    encode_array(encoder, values.len())?;
    for value in values {
        encode_text(encoder, as_str(value))?;
    }
    Ok(())
}

macro_rules! writer_parity_tests {
    ($($name:ident => $kind:ident),+ $(,)?) => {$ (
        #[test]
        fn $name() {
            for count in [0, 1, 2, 23, 24, 255, 256] {
                let value = auths_model::$kind::parse("did:example:actor").unwrap();
                let values = alloc::vec![value; count];
                for initial in [Vec::new(), alloc::vec![0xa2, 0, 1], alloc::vec![0; 128]] {
                    let mut actual = crate::cbor::Encoder::new(initial.clone());
                    let mut expected = crate::cbor::Encoder::new(initial);
                    assert_eq!(
                        super::$name(&mut actual, &values),
                        reference_write(&mut expected, &values, |value| value.as_str()),
                    );
                    assert_eq!(actual.into_writer(), expected.into_writer());
                }
            }
        }
    )+};
}

writer_parity_tests! {
    encode_principal_ids => PrincipalId,
    encode_principal_methods => PrincipalMethodId,
    encode_resource_ids => ResourceId,
    encode_signature_suites => SignatureSuiteId,
    encode_evidence_types => EvidenceTypeId,
    encode_status_methods => StatusMethodId,
    encode_assurance_claims => AssuranceClaimId,
    encode_assurance_implications => AssuranceImplicationId,
    encode_resource_matchers => ResourceMatcherId,
    encode_budget_algebras => BudgetAlgebraId,
    encode_extension_ids => ExtensionId,
    encode_profile_policies => ProfilePolicyId,
    encode_observation_schemas => ObservationSchemaId,
    encode_audiences => Audience,
    encode_trust_anchor_ids => TrustAnchorId,
}
