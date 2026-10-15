//! Fixed Unicode control and whitespace rules for protocol identifiers.
//!
//! Matching UTF-8 prefixes avoids an iterator callback and keeps the bounded
//! validation loop directly available to the qualified Rust-to-Lean translator.
//! Callers pass valid Rust strings; the byte scan itself is total on any slice.
//! The exclusion set agrees with the pinned Rust toolchain's `char::is_control`
//! and `char::is_whitespace`, as checked against every Unicode scalar in tests.

fn forbidden_three_byte_prefix(first: u8, second: u8, third: u8) -> bool {
    if first == 0xe1 {
        second == 0x9a && third == 0x80
    } else if first == 0xe2 {
        if second == 0x80 {
            matches!(third, 0x80..=0x8a) || third == 0xa8 || third == 0xa9 || third == 0xaf
        } else {
            second == 0x81 && third == 0x9f
        }
    } else {
        first == 0xe3 && second == 0x80 && third == 0x80
    }
}

fn forbidden_identifier_at(input: &[u8], position: usize) -> bool {
    let first = match input.get(position) {
        Some(byte) => *byte,
        None => return false,
    };
    if first <= 0x20 || first == 0x7f {
        return true;
    }
    if input.len() - position < 2 {
        return false;
    }
    let second = input[position + 1];
    if first == 0xc2 {
        return matches!(second, 0x80..=0xa0);
    }
    if input.len() - position < 3 {
        return false;
    }
    forbidden_three_byte_prefix(first, second, input[position + 2])
}

fn contains_forbidden_identifier(input: &[u8]) -> bool {
    let mut position = 0;
    while position < input.len() {
        if forbidden_identifier_at(input, position) {
            return true;
        }
        position += 1;
    }
    false
}

pub(crate) fn bounded_identifier_valid(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !contains_forbidden_identifier(value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{bounded_identifier_valid, contains_forbidden_identifier};
    use alloc::vec::Vec;
    use proptest::prelude::*;

    #[test]
    fn every_unicode_scalar_matches_the_character_oracle() {
        let mut allowed = Vec::new();
        for scalar in 0..=0x0010_ffff {
            let Some(character) = char::from_u32(scalar) else {
                continue;
            };
            let mut encoded = [0; 4];
            let text = character.encode_utf8(&mut encoded);
            let expected = character.is_control() || character.is_whitespace();
            assert_eq!(
                contains_forbidden_identifier(text.as_bytes()),
                expected,
                "standalone U+{scalar:04X}"
            );
            let mut framed = [b'a'; 6];
            let end = 1 + text.len();
            framed[1..end].copy_from_slice(text.as_bytes());
            framed[end] = b'z';
            assert_eq!(
                contains_forbidden_identifier(&framed[..=end]),
                expected,
                "framed U+{scalar:04X}"
            );
            if !expected {
                allowed.extend_from_slice(text.as_bytes());
            }
        }
        assert!(
            !contains_forbidden_identifier(&allowed),
            "adjacent allowed scalars cannot create a forbidden prefix"
        );
    }

    proptest! {
        #[test]
        fn bounded_validation_matches_the_previous_character_rule(
            text in "(?s).{0,1024}", maximum in 0usize..4096,
        ) {
            let expected = !text.is_empty() && text.len() <= maximum
                && !text.chars().any(|c| c.is_control() || c.is_whitespace());
            prop_assert_eq!(bounded_identifier_valid(&text, maximum), expected);
        }
    }
}
