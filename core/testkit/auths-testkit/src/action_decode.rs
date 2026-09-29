//! Canonical-action decode vectors.
//!
//! Each vector reuses `raw-key-chain`'s proof and context, which authorize
//! the well-formed action, and supplies raw canonical-action bytes with one
//! encoding fault that one canonical-action decode check rejects first. The
//! manifest marks these bytes `"encoding": "raw"`; the fixture's action model
//! still describes the well-formed action they were derived from.

use super::{CorpusFixture, DenialReason, Expected, encode_canonical_action, raw_key_chain};

/// Replaces the one occurrence of `from` in `source`.
fn replace_once(source: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let positions: Vec<_> = source
        .windows(from.len())
        .enumerate()
        .filter(|(_, window)| *window == from)
        .map(|(position, _)| position)
        .collect();
    assert_eq!(positions.len(), 1, "mutation site must be unique");
    let mut output = source[..positions[0]].to_vec();
    output.extend_from_slice(to);
    output.extend_from_slice(&source[positions[0] + from.len()..]);
    output
}

fn raw_action_vector(name: &'static str, bytes: Vec<u8>, expected: Expected) -> CorpusFixture {
    let mut fixture = raw_key_chain();
    fixture.name = name;
    fixture.class = "denied";
    fixture.raw_action_bytes = Some(bytes);
    fixture.expected = expected;
    fixture
}

/// One raw-byte vector per canonical-action decode check site. Every
/// construction mutates the encoding of `raw-key-chain`'s action, whose
/// detached attachments are empty.
#[allow(clippy::too_many_lines)]
pub(crate) fn action_decode_vectors() -> Vec<CorpusFixture> {
    let action = encode_canonical_action(raw_key_chain().canonical_action())
        .expect("canonical raw-key-chain action");
    let malformed = Expected::Denied(DenialReason::MalformedProof);
    let non_canonical = Expected::Denied(DenialReason::NonCanonicalProof);
    let attachments = |first: u8, second: u8| {
        let mut output = vec![0x05, 0x82];
        for fill in [first, second] {
            output.extend_from_slice(&[0xa2, 0x00, 0x58, 0x20]);
            output.extend_from_slice(&[fill; 32]);
            output.extend_from_slice(&[0x01, 0x41, 0x01]);
        }
        output
    };
    let position = |pattern: &[u8]| {
        action
            .windows(pattern.len())
            .position(|window| window == pattern)
            .expect("mutation site")
    };
    let body_at = position(&[0x02, 0x58, 0x18]);
    let permission_at = position(&[0x03, 0xa2]);
    let mut empty_body = action[..body_at].to_vec();
    empty_body.extend_from_slice(&[0x02, 0x40]);
    empty_body.extend_from_slice(&action[permission_at..]);
    let mut trailing = action.clone();
    trailing.push(0x00);
    let mut map_size = vec![0xa5];
    map_size.extend_from_slice(&action[1..]);
    let mut non_shortest_key = vec![0xa6, 0x18, 0x00];
    non_shortest_key.extend_from_slice(&action[2..]);
    // The first key-value pair is key 0 and the profile map, which ends with
    // its identifier's bytes and the version.
    let profile_end = position(b"auths.mcp\x01\x01") + b"auths.mcp\x01\x01".len();
    let mut duplicated_first_pair = vec![0xa7];
    duplicated_first_pair.extend_from_slice(&action[1..]);
    duplicated_first_pair.extend_from_slice(&action[1..profile_end]);
    vec![
        // `decode.action-map`
        raw_action_vector("action-decode-map-size", map_size, malformed),
        raw_action_vector(
            "action-decode-duplicated-first-pair",
            duplicated_first_pair,
            malformed,
        ),
        // `decode.action-key`
        raw_action_vector(
            "action-decode-key-out-of-order",
            replace_once(&action, &[0x05, 0x80], &[0x06, 0x80]),
            non_canonical,
        ),
        // `decode.action-field`
        raw_action_vector(
            "action-decode-truncated",
            action[..action.len() - 1].to_vec(),
            malformed,
        ),
        raw_action_vector(
            "action-decode-zero-profile-version",
            replace_once(&action, b"auths.mcp\x01\x01", b"auths.mcp\x01\x00"),
            malformed,
        ),
        raw_action_vector(
            "action-decode-whitespace-in-media-type",
            replace_once(&action, b"auths.mcp-call", b"auths mcp-call"),
            malformed,
        ),
        raw_action_vector(
            "action-decode-body-as-text",
            replace_once(&action, &[0x02, 0x58, 0x18], &[0x02, 0x78, 0x18]),
            malformed,
        ),
        raw_action_vector(
            "action-decode-indefinite-attachments",
            replace_once(&action, &[0x05, 0x80], &[0x05, 0x9f, 0xff]),
            malformed,
        ),
        // `decode.action-body-bytes`
        raw_action_vector(
            "action-decode-empty-body",
            empty_body,
            Expected::Denied(DenialReason::ResourceLimitExceeded),
        ),
        // `decode.action-attachment-duplicate`
        raw_action_vector(
            "action-decode-duplicate-attachments",
            replace_once(&action, &[0x05, 0x80], &attachments(0xaa, 0xaa)),
            malformed,
        ),
        // `decode.action-trailing`
        raw_action_vector("action-decode-trailing-byte", trailing, malformed),
        // `decode.action-canonical`
        raw_action_vector(
            "action-decode-non-shortest-key",
            non_shortest_key,
            non_canonical,
        ),
        raw_action_vector(
            "action-decode-attachments-out-of-order",
            replace_once(&action, &[0x05, 0x80], &attachments(0xff, 0x00)),
            non_canonical,
        ),
    ]
}
