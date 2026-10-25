//! Former iterator parser is a test-only independent oracle for the indexed
//! closed-ASCII source cutover. It is never used by production or extraction.

use super::*;
use alloc::vec;

fn former_accepts(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b':' | b'_' | b'-')
        })
}

fn compare(value: &str, maximum: usize) {
    let actual = PolicyIdentifier::parse(value, maximum);
    if former_accepts(value, maximum) {
        assert_eq!(actual.unwrap().as_str(), value);
    } else {
        assert_eq!(actual, Err(ModelError::InvalidBoundedPolicy));
    }
}

#[test]
fn every_byte_has_the_same_closed_ascii_classification() {
    for byte in u8::MIN..=u8::MAX {
        assert_eq!(policy_identifier_byte_allowed(byte),
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b':' | b'_' | b'-'));
    }
}

#[test]
fn parser_retains_exact_values_and_refusal_at_every_bound() {
    for length in [0, 1, 2, 63, 64, 65, 127, 128, 129, 130] {
        let value = "a".repeat(length);
        for maximum in [0, 1, 2, 64, 128, 129, usize::MAX] {
            compare(&value, maximum);
        }
    }
    for value in ["a", "0", "Z", ".", "/", ":", "_", "-", "AZaz09./:_-",
        "a b", "a\tb", "a\nb", "a\0b", "a@b", "a~b", "é", "λ", "中", "a\u{200b}b",
        "a\u{202e}b", "\u{10ffff}"]
    {
        for maximum in [0, 1, 2, 64, 128, usize::MAX] {
            compare(value, maximum);
        }
    }
    for byte in 0_u8..=127 {
        let character = char::from(byte);
        for value in [alloc::format!("{character}aa"), alloc::format!("a{character}a"), alloc::format!("aa{character}")] {
            compare(&value, 3);
            compare(&value, 2);
        }
    }
}

fn identifier(value: &str) -> PolicyIdentifier {
    PolicyIdentifier::parse(value, value.len()).unwrap()
}

#[test]
fn commitment_rechecks_each_field_and_nonzero_version() {
    let make = |policy_type, version, canonicalization, evaluator| PolicyCommitment::new(
        identifier(policy_type), version, identifier(canonicalization), Digest::new([0; 32]), identifier(evaluator));
    assert!(make("t", 1, "c", "e").is_ok());
    assert!(make(&"t".repeat(128), u16::MAX, &"c".repeat(64), &"e".repeat(128)).is_ok());
    for actual in [make("t", 0, "c", "e"), make(&"t".repeat(129), 1, "c", "e"),
        make("t", 1, &"c".repeat(65), "e"), make("t", 1, "c", &"e".repeat(129))]
    {
        assert_eq!(actual, Err(ModelError::InvalidBoundedPolicy));
    }
}

#[test]
fn body_constructor_retains_bytes_and_typed_empty_oversize_refusal() {
    let commitment = PolicyCommitment::new(identifier("t"), 1, identifier("c"),
        Digest::new([0; 32]), identifier("e")).unwrap();
    assert_eq!(BoundedPolicyCommitment::new(commitment.clone(), vec![], None),
        Err(ModelError::InvalidBoundedPolicy));
    assert_eq!(BoundedPolicyCommitment::new(commitment.clone(), vec![0; 4097], None),
        Err(ModelError::CollectionLimitExceeded));
    for policy in [vec![0], vec![255; 4096]] {
        let body = BoundedPolicyCommitment::new(commitment.clone(), policy.clone(), Some(Digest::new([255; 32]))).unwrap();
        assert_eq!(body.policy(), policy);
        assert_eq!(body.commitment(), &commitment);
        assert_eq!(body.parent(), Some(&Digest::new([255; 32])));
    }
    // Model construction checks representation, not a cryptographic opening.
    // The codec's checked canonical carrier supplies the separate opening gate.
}
