//! Independent character-language oracles exercise actual owned-String APIs.
use super::*;

fn lower_language(value: &str) -> bool {
    let mut characters = value.chars();
    value.len() <= 64
        && matches!(characters.next(), Some('a'..='z'))
        && characters.all(|character| matches!(character, 'a'..='z' | '0'..='9' | '-'))
}

fn semantic_language(value: &str) -> bool {
    let mut characters = value.chars();
    value.len() <= 128
        && characters
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric())
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '/' | '-')
        })
}

fn check(value: &str) -> [bool; 3] {
    let lower = lower_language(value);
    let semantic = semantic_language(value);
    let provider = ProviderKind::parse(value.to_owned()).map(|parsed| parsed.as_str().to_owned());
    let alias = ConnectionAlias::parse(value.to_owned()).map(|parsed| parsed.as_str().to_owned());
    let identifier = SemanticId::parse(value.to_owned()).map(|parsed| parsed.as_str().to_owned());
    assert_eq!(
        provider,
        if lower {
            Ok(value.to_owned())
        } else {
            Err(ConnectionRecordError::InvalidProviderKind)
        }
    );
    assert_eq!(
        alias,
        if lower {
            Ok(value.to_owned())
        } else {
            Err(ConnectionRecordError::InvalidAlias)
        }
    );
    assert_eq!(
        identifier,
        if semantic {
            Ok(value.to_owned())
        } else {
            Err(ConnectionRecordError::InvalidSemanticId)
        }
    );
    [provider.is_ok(), alias.is_ok(), identifier.is_ok()]
}

#[test]
fn actual_string_constructors_preserve_payloads_and_closed_errors() {
    let mut accepted = [0; 3];
    let mut texts = 0;
    for first in 0..=u8::MAX {
        for second in 0..=u8::MAX {
            let pair = [first, second];
            for length in 0..=2 {
                if let Ok(value) = std::str::from_utf8(&pair[..length]) {
                    let result = check(value);
                    for index in 0..3 {
                        accepted[index] += usize::from(result[index]);
                    }
                    texts += 1;
                }
            }
        }
    }
    // Independent language cardinalities: 26 heads/37 tails versus 62/67.
    assert_eq!(texts, 65_536 + 128 * 256 + 128 * 128 + 30 * 64);
    assert_eq!(
        accepted,
        [26 * 256 + 26 * 37, 26 * 256 + 26 * 37, 62 * 256 + 62 * 67]
    );
    for value in [
        "stripe",
        "a-b",
        "A:1",
        "auths.profile/1",
        "é",
        "e\u{301}",
        "猫",
        "🙂",
        "\0",
        "",
        "--",
        "a/b",
        "A123",
    ] {
        check(value);
    }
    for length in [63, 64, 65, 127, 128, 129] {
        check(&"a".repeat(length));
    }
}
