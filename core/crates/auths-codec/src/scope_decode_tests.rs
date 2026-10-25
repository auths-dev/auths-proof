//! Frozen pre-refactor decoder control flow. The model crate separately
//! compares constructor behavior with its frozen sorting/validation oracle.
use super::*;
use crate::cbor::Encoder;
use alloc::format;

fn reference(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<StatusScope, CodecError> {
    let entries = decoder
        .map()
        .map_err(decode_error)?
        .ok_or(CodecError::Malformed)?;
    if !(1..=2).contains(&entries) {
        return Err(CodecError::Malformed);
    }
    key(decoder, 0)?;
    let tag = decoder.u8().map_err(decode_error)?;
    match (tag, entries) {
        (0, 1) => Ok(StatusScope::OwnAnchor),
        (1, 2) => {
            key(decoder, 1)?;
            let length = array(decoder, limits.get(LimitKind::TrustAnchors))?;
            let mut anchors = Vec::with_capacity(length);
            for _ in 0..length {
                anchors.push(parse_text!(decoder, TrustAnchorId)?);
            }
            Ok(StatusScope::Anchors(StatusScopeAnchors::new(anchors)?))
        }
        (2, 1) => Ok(StatusScope::AnyAnchor),
        _ => Err(CodecError::Malformed),
    }
}

fn check(bytes: &[u8], maximum: usize) {
    let limits = VerifierLimits::default_deployment()
        .with_limit(LimitKind::TrustAnchors, maximum)
        .unwrap();
    let mut actual_decoder = V1Decoder::new(bytes);
    let mut reference_decoder = V1Decoder::new(bytes);
    let expected = reference(&mut reference_decoder, &limits);
    let actual = status_scope(&mut actual_decoder, &limits);
    assert_eq!(actual, expected, "bytes {bytes:?}, maximum {maximum}");
    assert_eq!(actual_decoder.position(), reference_decoder.position());
}

fn encode_scope(ids: &[&str]) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(2).unwrap();
    encoder.u8(0).unwrap();
    encoder.u8(1).unwrap();
    encoder.u8(1).unwrap();
    encoder.array(u64::try_from(ids.len()).unwrap()).unwrap();
    for id in ids {
        encoder.str(id).unwrap();
    }
    encoder.into_writer()
}

fn next_word(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn scope_decoder_preserves_result_and_cursor_for_truncation_and_invalid_ids() {
    let choices = [
        "anchor:a",
        "anchor:b",
        "anchor:c",
        "anchor:é",
        "anchor:δ",
        "",
        "two words",
        "line\nbreak",
        "anchor:\u{200b}",
    ];
    let mut state = 42_u64;
    for _ in 0..500 {
        let length = usize::try_from(next_word(&mut state) % 9).unwrap();
        let ids: Vec<_> = (0..length)
            .map(|_| {
                let index =
                    usize::try_from(next_word(&mut state) % u64::try_from(choices.len()).unwrap())
                        .unwrap();
                choices[index]
            })
            .collect();
        let encoded = encode_scope(&ids);
        for maximum in [1, 2, 8, auths_model::HARD_MAX_TRUST_ANCHORS] {
            for end in 0..=encoded.len() {
                check(&encoded[..end], maximum);
            }
        }
    }
}

#[test]
fn scope_decoder_preserves_all_header_tags_and_adversarial_bytes() {
    for tag in 0..=u8::MAX {
        let bytes = [0xa1, 0x00, tag];
        for maximum in [1, 2, 8, auths_model::HARD_MAX_TRUST_ANCHORS] {
            check(&bytes, maximum);
        }
    }
    let mut state = 17_u64;
    for _ in 0..8_000 {
        let length = usize::try_from(next_word(&mut state) % 64).unwrap();
        let bytes: Vec<_> = (0..length)
            .map(|_| u8::try_from(next_word(&mut state) % 256).unwrap())
            .collect();
        for maximum in [1, 2, 8, auths_model::HARD_MAX_TRUST_ANCHORS] {
            check(&bytes, maximum);
        }
    }
}

#[test]
fn scope_decoder_preserves_own_any_sorted_and_limit_boundaries() {
    let limits = VerifierLimits::default_deployment();
    for (bytes, expected) in [
        (&[0xa1, 0x00, 0x00][..], StatusScope::OwnAnchor),
        (&[0xa1, 0x00, 0x02][..], StatusScope::AnyAnchor),
    ] {
        let mut decoder = V1Decoder::new(bytes);
        assert_eq!(status_scope(&mut decoder, &limits), Ok(expected));
        check(bytes, auths_model::HARD_MAX_TRUST_ANCHORS);
    }
    let bytes = encode_scope(&["anchor:c", "anchor:a"]);
    let mut decoder = V1Decoder::new(&bytes);
    let StatusScope::Anchors(anchors) = status_scope(&mut decoder, &limits).unwrap() else {
        panic!("listed scope");
    };
    assert_eq!(
        anchors
            .ids()
            .iter()
            .map(TrustAnchorId::as_str)
            .collect::<Vec<_>>(),
        ["anchor:a", "anchor:c"]
    );
    for length in [
        0,
        1,
        auths_model::HARD_MAX_TRUST_ANCHORS - 1,
        auths_model::HARD_MAX_TRUST_ANCHORS,
        auths_model::HARD_MAX_TRUST_ANCHORS + 1,
    ] {
        let ids: Vec<_> = (0..length)
            .map(|index| format!("anchor:{index:04}"))
            .collect();
        let borrowed: Vec<_> = ids.iter().map(String::as_str).collect();
        let encoded = encode_scope(&borrowed);
        for maximum in [1, 2, 8, auths_model::HARD_MAX_TRUST_ANCHORS] {
            check(&encoded, maximum);
        }
    }
}

fn reference_trust(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<Vec<StatusTrustRule>, CodecError> {
    let length = array(decoder, limits.get(LimitKind::RegistryEntries))?;
    let mut rules = Vec::with_capacity(length);
    for _ in 0..length {
        map(decoder, 4)?;
        key(decoder, 0)?;
        let method = parse_text!(decoder, StatusMethodId)?;
        key(decoder, 1)?;
        let issuer = parse_text!(decoder, PrincipalId)?;
        key(decoder, 2)?;
        let sequence_floor = decoder.u64().map_err(decode_error)?;
        key(decoder, 3)?;
        let scope = reference(decoder, limits)?;
        rules.push(StatusTrustRule::new(method, issuer, sequence_floor, scope));
    }
    Ok(rules)
}

fn check_trust(bytes: &[u8], maximum: usize) {
    let limits = VerifierLimits::default_deployment()
        .with_limit(LimitKind::RegistryEntries, maximum)
        .unwrap();
    let mut actual = V1Decoder::new(bytes);
    let mut expected = V1Decoder::new(bytes);
    assert_eq!(
        status_trust(&mut actual, &limits),
        reference_trust(&mut expected, &limits)
    );
    assert_eq!(actual.position(), expected.position());
}

fn encode_trust(entries: &[(&str, &str, u64, &[&str])]) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .array(u64::try_from(entries.len()).unwrap())
        .unwrap();
    for (method, issuer, floor, ids) in entries {
        encoder.map(4).unwrap();
        encoder.u8(0).unwrap();
        encoder.str(method).unwrap();
        encoder.u8(1).unwrap();
        encoder.str(issuer).unwrap();
        encoder.u8(2).unwrap();
        encoder.u64(*floor).unwrap();
        encoder.u8(3).unwrap();
        encoder.map(2).unwrap();
        encoder.u8(0).unwrap();
        encoder.u8(1).unwrap();
        encoder.u8(1).unwrap();
        encoder.array(u64::try_from(ids.len()).unwrap()).unwrap();
        for id in *ids {
            encoder.str(id).unwrap();
        }
    }
    encoder.into_writer()
}

#[test]
fn status_trust_preserves_values_first_error_and_cursor() {
    let methods = ["exact", "", "two words", "méthod"];
    let issuers = [
        "raw:issuer",
        "did:key:z",
        "a+1-.:x",
        "A:issuer",
        "no-scheme",
        "a:",
        "a:é",
    ];
    let mut state = 731_u64;
    for _ in 0..400 {
        let length = usize::try_from(next_word(&mut state) % 5).unwrap();
        let mut entries = Vec::new();
        for _ in 0..length {
            let method = methods[usize::try_from(
                next_word(&mut state) % u64::try_from(methods.len()).unwrap(),
            )
            .unwrap()];
            let issuer = issuers[usize::try_from(
                next_word(&mut state) % u64::try_from(issuers.len()).unwrap(),
            )
            .unwrap()];
            let ids: &[&str] = match next_word(&mut state) % 4 {
                0 => &["a", "c"],
                1 => &["c", "a"],
                2 => &["a", "a"],
                _ => &[],
            };
            entries.push((method, issuer, next_word(&mut state), ids));
        }
        let bytes = encode_trust(&entries);
        for prefix in 0..=bytes.len() {
            for maximum in [0, 1, 2, 8] {
                check_trust(&bytes[..prefix], maximum);
            }
        }
    }
    for _ in 0..8000 {
        let length = usize::try_from(next_word(&mut state) % 65).unwrap();
        let bytes: Vec<u8> = (0..length)
            .map(|_| next_word(&mut state).to_le_bytes()[0])
            .collect();
        check_trust(&bytes, 8);
    }
}
