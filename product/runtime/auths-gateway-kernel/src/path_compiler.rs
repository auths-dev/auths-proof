//! Lowering of the existing recipe path vocabulary into positional plans.
//!
//! These borrowed cases are a byte view of the source AST, not another wire
//! format. Only fixed literals and exact named fields can lower. Response
//! locators and author-placed echo nodes use the explicit unsupported case.

use alloc::vec::Vec;

use crate::arguments::MAX_PROFILE_FIELDS;
use crate::construct::{ConstructError, SegmentPlan, append_bytes, copy_bytes, field_index, field_name_equal, is_path_literal, segment_value_valid};
use crate::identity::valid_token;

/// Maximum number of segments in any declared recipe path.
pub const MAX_PATH_SEGMENTS: usize = 16;
/// Maximum bytes in an approved fixed path segment.
pub const MAX_FIXED_SEGMENT_BYTES: usize = 128;
/// Eight HTTPS framing bytes plus the maximum 253-byte canonical DNS host.
pub const MAX_ORIGIN_BYTES: usize = 261;

/// Exact agreement between approved origin bytes and a parsed canonical host.
/// Hostname/IP/DNS policy remains the native validator's responsibility.
#[must_use]
pub fn origin_matches_host(origin: &[u8], host: &[u8]) -> bool {
    if host.is_empty() || host.len() > 253 || origin.len() != 8 + host.len() {
        return false;
    }
    let expected = append_bytes(copy_bytes(b"https://"), host);
    field_name_equal(origin, &expected)
}

/// Owned byte view of an existing decoded source path segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NamedSegment {
    /// Exact approved literal bytes.
    Fixed(Vec<u8>),
    /// Exact profile field name, resolved without normalization.
    Field(Vec<u8>),
    /// A source node that cannot occur in a compiled action/fixed-read path.
    Unsupported,
}

/// The complete fixed path grammar: 1–128 unreserved ASCII bytes, excluding
/// dot and dot-dot. No slash, query, fragment or percent escape is admitted.
#[must_use]
pub fn fixed_segment_valid(text: &[u8]) -> bool {
    if text.len() > MAX_FIXED_SEGMENT_BYTES || !segment_value_valid(text) {
        return false;
    }
    let mut position = 0;
    while position < text.len() {
        if !is_path_literal(text[position]) {
            return false;
        }
        position += 1;
    }
    true
}

/// Resolves a valid field name to its exact position in the bounded layout.
///
/// # Errors
/// Returns [`ConstructError::ArgumentMismatch`] for an oversized layout,
/// malformed reference or undeclared field. The compiler obtains a unique
/// lexical layout through `field_projection::field_names`.
pub fn lower_field(names: &[Vec<u8>], name: &[u8]) -> Result<usize, ConstructError> {
    if names.len() > MAX_PROFILE_FIELDS || !valid_token(name, 64) {
        return Err(ConstructError::ArgumentMismatch);
    }
    match field_index(names, name) {
        Some(position) => Ok(position),
        None => Err(ConstructError::ArgumentMismatch),
    }
}

/// Lowers exactly one existing source segment, preserving literal bytes.
///
/// # Errors
/// Returns [`ConstructError::UnsafeSegment`] for an invalid fixed literal,
/// and [`ConstructError::ArgumentMismatch`] for an invalid field or unsupported
/// source node. It grants no schema validity or execution authority.
pub fn lower_segment(names: &[Vec<u8>], segment: &NamedSegment) -> Result<SegmentPlan, ConstructError> {
    match segment {
        NamedSegment::Fixed(text) => {
            if fixed_segment_valid(text) {
                Ok(SegmentPlan::Fixed(copy_bytes(text)))
            } else {
                Err(ConstructError::UnsafeSegment)
            }
        }
        NamedSegment::Field(name) => match lower_field(names, name) {
            Ok(position) => Ok(SegmentPlan::Field(position)),
            Err(error) => Err(error),
        },
        NamedSegment::Unsupported => Err(ConstructError::ArgumentMismatch),
    }
}

/// Lowers a nonempty bounded path using only its declared literals/names.
///
/// # Errors
/// Returns [`ConstructError::ArgumentMismatch`] for a count outside 1–16 or
/// more than 32 profile fields, and forwards the exact first segment error.
pub fn lower_path(names: &[Vec<u8>], path: &[NamedSegment]) -> Result<Vec<SegmentPlan>, ConstructError> {
    if path.is_empty() || path.len() > MAX_PATH_SEGMENTS || names.len() > MAX_PROFILE_FIELDS {
        return Err(ConstructError::ArgumentMismatch);
    }
    let mut output = Vec::new();
    let mut position = 0;
    while position < path.len() {
        let lowered = lower_segment(names, &path[position]);
        match &lowered {
            Ok(segment) => output.push(segment.clone()),
            Err(error) => return Err(*error),
        }
        position += 1;
    }
    Ok(output)
}

/// Lowers a credential-read path, which can contain only fixed literals.
/// No named action value can become a credential-read path component.
///
/// # Errors
/// Returns [`ConstructError::ArgumentMismatch`] for an invalid count or any
/// dynamic/unsupported node, and [`ConstructError::UnsafeSegment`] for an
/// invalid literal. It forwards no action value into the resulting path.
pub fn lower_fixed_path(path: &[NamedSegment]) -> Result<Vec<Vec<u8>>, ConstructError> {
    if path.is_empty() || path.len() > MAX_PATH_SEGMENTS {
        return Err(ConstructError::ArgumentMismatch);
    }
    let mut output = Vec::new();
    let mut position = 0;
    while position < path.len() {
        match &path[position] {
            NamedSegment::Fixed(text) => {
                if !fixed_segment_valid(text) {
                    return Err(ConstructError::UnsafeSegment);
                }
                output.push(copy_bytes(text));
            }
            NamedSegment::Field(_) | NamedSegment::Unsupported => {
                return Err(ConstructError::ArgumentMismatch);
            }
        }
        position += 1;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn origin_must_equal_the_parsed_host_with_one_exact_https_prefix() {
        let host = b"api.example.com";
        assert!(origin_matches_host(b"https://api.example.com", host));
        for origin in [
            b"HTTPS://api.example.com".as_slice(), b" https://api.example.com",
            b"https:////api.example.com", b"https://api.example.com/",
            b"https://user@api.example.com", b"https://api.example.com:443",
            b"https://API.example.com", b"http://api.example.com",
        ] {
            assert!(!origin_matches_host(origin, host));
        }
        let mut maximum = b"https://".to_vec();
        maximum.extend_from_slice(&[b'a'; 253]);
        assert_eq!(maximum.len(), MAX_ORIGIN_BYTES);
        assert!(origin_matches_host(&maximum, &[b'a'; 253]));
        assert!(!origin_matches_host(b"https://", b""));
        assert!(!origin_matches_host(&maximum, &[b'a'; 254]));
    }

    #[test]
    fn literal_grammar_matches_frozen_native_rule_for_every_byte() {
        for byte in 0_u8..=255 {
            let expected = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'~');
            assert_eq!(fixed_segment_valid(&[byte]), expected);
            let pair = [b'a', byte];
            let expected = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~');
            assert_eq!(fixed_segment_valid(&pair), expected);
        }
        for value in [b"".as_slice(), b".", b"..", b"a/b", b"a?b", b"a#b", b"a%2Fb", "é".as_bytes()] {
            assert!(!fixed_segment_valid(value));
        }
        assert!(fixed_segment_valid(&[b'a'; MAX_FIXED_SEGMENT_BYTES]));
        assert!(!fixed_segment_valid(&[b'a'; MAX_FIXED_SEGMENT_BYTES + 1]));
    }

    #[test]
    fn exact_name_positions_and_literal_bytes_are_preserved() {
        let names = vec![b"a".to_vec(), b"a.b".to_vec(), b"b".to_vec()];
        assert_eq!(lower_path(&names, &[
            NamedSegment::Fixed(b"v1".to_vec()), NamedSegment::Field(b"b".to_vec()), NamedSegment::Field(b"a.b".to_vec()),
        ]), Ok(vec![SegmentPlan::Fixed(b"v1".to_vec()), SegmentPlan::Field(2), SegmentPlan::Field(1)]));
        for name in [b"B".as_slice(), b"a.b.c", b"a\0", b"unknown"] {
            assert_eq!(lower_field(&names, name), Err(ConstructError::ArgumentMismatch));
        }
        assert_eq!(lower_path(&names, &[NamedSegment::Unsupported]), Err(ConstructError::ArgumentMismatch));
        assert_eq!(lower_path(&names, &[NamedSegment::Fixed(b"..".to_vec())]), Err(ConstructError::UnsafeSegment));
    }

    #[test]
    fn complete_path_limits_and_first_refusal_are_exact() {
        let names = vec![b"a".to_vec()];
        let maximum = vec![NamedSegment::Fixed(b"v1".to_vec()); MAX_PATH_SEGMENTS];
        assert_eq!(lower_path(&names, &maximum).unwrap().len(), MAX_PATH_SEGMENTS);
        assert_eq!(lower_fixed_path(&maximum).unwrap().len(), MAX_PATH_SEGMENTS);
        let too_many = vec![NamedSegment::Fixed(b"v1".to_vec()); MAX_PATH_SEGMENTS + 1];
        assert_eq!(lower_path(&names, &too_many), Err(ConstructError::ArgumentMismatch));
        assert_eq!(lower_fixed_path(&too_many), Err(ConstructError::ArgumentMismatch));
        assert_eq!(lower_path(&names, &[]), Err(ConstructError::ArgumentMismatch));
        assert_eq!(lower_path(&names, &[NamedSegment::Fixed(b"..".to_vec()), NamedSegment::Unsupported]), Err(ConstructError::UnsafeSegment));
        assert_eq!(lower_path(&names, &[NamedSegment::Unsupported, NamedSegment::Fixed(b"..".to_vec())]), Err(ConstructError::ArgumentMismatch));
        assert_eq!(lower_fixed_path(&[NamedSegment::Field(b"a".to_vec())]), Err(ConstructError::ArgumentMismatch));
    }

    #[test]
    fn actual_name_generation_object_projection_and_url_writer_preserve_source_path() {
        use crate::field_projection::{FieldSpec, NamedInput, field_names, project_object};
        use crate::scalars::{ScalarInput, ScalarSchema};
        let fields = [FieldSpec { name: b"record".to_vec(), schema: ScalarSchema::String { minimum: 1, maximum: 64 } }];
        let names = field_names(&fields).unwrap();
        let compiled = lower_path(&names, &[NamedSegment::Fixed(b"v1".to_vec()), NamedSegment::Field(b"record".to_vec())]).unwrap();
        let supplied = [NamedInput { name: b"record", value: ScalarInput::Text("x/é".as_bytes()) }];
        let arguments = project_object(&fields, &supplied).unwrap();
        assert_eq!(
            crate::construct::build_url(b"https://api.example.com", &compiled, &arguments),
            Ok(b"https://api.example.com/v1/x%2F%C3%A9".to_vec())
        );
        let supplied = [NamedInput { name: b"record", value: ScalarInput::Text(b"..") }];
        let arguments = project_object(&fields, &supplied).unwrap();
        assert_eq!(
            crate::construct::build_url(b"https://api.example.com", &compiled, &arguments),
            Err(ConstructError::UnsafeSegment)
        );
    }
}
