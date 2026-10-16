//! Independent character-based oracle for the principal byte-loop cutover.
use super::*;
use alloc::{format, string::String};

fn reference(value: &str) -> Result<String, ModelError> {
    if value.is_empty()
        || value.len() > 512
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ModelError::InvalidPrincipal);
    }
    let parsed = String::from(value);
    let (scheme, remainder) = parsed.split_once(':').ok_or(ModelError::InvalidPrincipal)?;
    let mut characters = scheme.chars();
    if remainder.is_empty()
        || !characters
            .next()
            .is_some_and(|character| character.is_ascii_lowercase())
        || !characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '+' | '-' | '.')
        })
    {
        return Err(ModelError::InvalidPrincipal);
    }
    Ok(parsed)
}

fn check(value: &str) {
    let actual = PrincipalId::parse(value).map(|id| String::from(id.as_str()));
    assert_eq!(actual, reference(value), "principal {value:?}");
}

#[test]
fn principal_parser_matches_each_unicode_scalar_in_scheme_and_remainder() {
    for scalar in 0..=0x0010_ffff {
        let Some(character) = char::from_u32(scalar) else {
            continue;
        };
        check(&format!("{character}:x"));
        check(&format!("a{character}:x"));
        check(&format!("a:{character}"));
    }
}

#[test]
fn principal_parser_matches_adversarial_schemes_and_byte_boundaries() {
    for first in 0_u8..=127 {
        for second in 0_u8..=127 {
            check(&format!("{}{}:x", char::from(first), char::from(second)));
        }
    }
    for size in [0, 1, 2, 3, 510, 511, 512, 513, 1024] {
        check(&"a".repeat(size));
        check(&format!("a:{}", "x".repeat(size)));
        check(&format!("{}:x", "a".repeat(size)));
        check(&format!("a:{}", "é".repeat(size)));
    }
    for value in [
        "a:x",
        "raw:key",
        "did:key:z",
        "a+1-.:x",
        "a:",
        "a",
        ":x",
        "A:x",
        "1:x",
        "+a:x",
        "a:x:y",
        "a:é",
        "a:🙂",
    ] {
        check(value);
    }
}
