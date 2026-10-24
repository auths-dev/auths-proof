//! Schema-checked scalar projection for gateway recipes.
//!
//! JSON extraction supplies an exact string, signed integer, or boolean. These
//! functions enforce the complete scalar bounds and produce the construction
//! representation. Decimal rendering uses only bounded integer arithmetic;
//! neither locale nor JSON/string formatting chooses the emitted digits.

use alloc::vec::Vec;

use crate::construct::{ArgumentValue, copy_bytes, field_index, is_alphanumeric};
use crate::arguments::unique_fields;

/// Maximum UTF-8 byte length of a profile string field.
pub const MAX_TEXT_BYTES: usize = 4096;
/// Largest exact signed integer admitted by the JSON profile contract.
pub const MAX_JSON_INTEGER: i64 = 9_007_199_254_740_991;
/// Maximum count of distinct enum variants.
pub const MAX_ENUM_VARIANTS: usize = 32;
/// Maximum bytes in one ASCII enum variant.
pub const MAX_ENUM_BYTES: usize = 64;

/// The complete supported scalar schema carried by a compiled profile lock.
/// Construction alone does not establish that its bounds or variants are valid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScalarSchema {
    /// UTF-8 string byte limits, with NUL excluded by projection.
    String { minimum: usize, maximum: usize },
    /// Exact bounded ASCII members, checked for duplicates before use.
    Enum { variants: Vec<Vec<u8>> },
    /// Inclusive bounds inside the safe signed JSON integer range.
    Integer { minimum: i64, maximum: i64 },
    /// Exactly a JSON boolean.
    Boolean,
}

/// A borrowed scalar extracted from a JSON value without schema coercion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalarInput<'a> {
    /// Exact bytes of a decoded JSON string.
    Text(&'a [u8]),
    /// An exactly represented signed JSON integer.
    Integer(i64),
    /// The decoded JSON boolean, without truthiness conversion.
    Boolean(bool),
    /// Null, collections, floats, or numbers outside the signed carrier.
    Unsupported,
}

/// Whether projected values of this schema have the direct form-field kind.
/// Booleans remain available inside JSON, including JSON nested in a form.
/// This checks the supported kind only; complete schema/value bounds are
/// independently enforced by projection.
#[must_use]
pub const fn form_schema_allowed(schema: &ScalarSchema) -> bool {
    match schema {
        ScalarSchema::String { .. } | ScalarSchema::Enum { .. } | ScalarSchema::Integer { .. } => true,
        ScalarSchema::Boolean => false,
    }
}

/// Whether a string schema has ordered bounds within the complete byte limit.
#[must_use]
pub const fn string_schema_valid(minimum: usize, maximum: usize) -> bool {
    minimum <= maximum && maximum <= MAX_TEXT_BYTES
}

/// Whether the schema admits these exact string bytes, including its NUL rule.
/// JSON extraction owns UTF-8 validity; this function never normalizes bytes.
#[must_use]
pub fn string_value_valid(minimum: usize, maximum: usize, text: &[u8]) -> bool {
    if !string_schema_valid(minimum, maximum) || text.len() < minimum || text.len() > maximum {
        return false;
    }
    let mut position = 0;
    while position < text.len() {
        if text[position] == 0 {
            return false;
        }
        position += 1;
    }
    true
}

/// The exact ASCII enum language used by profile-lock validation.
#[must_use]
pub fn enum_byte_valid(byte: u8) -> bool {
    is_alphanumeric(byte) || byte == b'_' || byte == b'.' || byte == b':' || byte == b'-'
}

/// Whether the complete variant has the bounded nonempty ASCII enum language.
#[must_use]
pub fn enum_variant_valid(text: &[u8]) -> bool {
    if text.is_empty() || text.len() > MAX_ENUM_BYTES {
        return false;
    }
    let mut position = 0;
    while position < text.len() {
        let byte = text[position];
        if !enum_byte_valid(byte) {
            return false;
        }
        position += 1;
    }
    true
}

/// Whether the enum is bounded, nonempty, lexical and free of duplicate bytes.
#[must_use]
pub fn enum_schema_valid(variants: &[Vec<u8>]) -> bool {
    if variants.is_empty() || variants.len() > MAX_ENUM_VARIANTS {
        return false;
    }
    if !unique_fields(variants) {
        return false;
    }
    let mut position = 0;
    while position < variants.len() {
        if !enum_variant_valid(&variants[position]) {
            return false;
        }
        position += 1;
    }
    true
}

/// Whether an exact text value belongs to the complete validated enum schema.
#[must_use]
pub fn enum_value_valid(variants: &[Vec<u8>], text: &[u8]) -> bool {
    if !enum_schema_valid(variants) {
        return false;
    }
    field_index(variants, text).is_some()
}

/// Whether a signed integer schema lies within the exact JSON integer domain.
#[must_use]
pub const fn integer_schema_valid(minimum: i64, maximum: i64) -> bool {
    minimum <= maximum && minimum >= -MAX_JSON_INTEGER && maximum <= MAX_JSON_INTEGER
}

/// Whether this exact signed value satisfies all schema and global bounds.
#[must_use]
pub const fn integer_value_valid(minimum: i64, maximum: i64, value: i64) -> bool {
    integer_schema_valid(minimum, maximum) && minimum <= value && value <= maximum
}

/// Absolute magnitude of any i64, including its minimum without overflow.
#[must_use]
#[allow(clippy::cast_sign_loss, reason = "INVARIANT: both cast operands are nonnegative; the negative branch offsets before negation so i64::MIN is represented exactly")]
pub const fn magnitude(value: i64) -> u64 {
    if value < 0 {
        ((-(value + 1)) as u64) + 1
    } else {
        value as u64
    }
}

/// Largest power of ten not exceeding a positive value; one for zero.
/// Every multiplication is at most `value`, so the full u64 domain is safe.
#[must_use]
pub fn decimal_divisor(value: u64) -> u64 {
    let mut divisor = 1;
    while value / divisor >= 10 {
        divisor *= 10;
    }
    divisor
}

/// Appends the unique ordinary unsigned decimal representation of `value`.
/// The output has at most twenty additional bytes, including the zero case.
#[must_use]
pub fn append_unsigned_decimal(mut output: Vec<u8>, value: u64) -> Vec<u8> {
    let mut divisor = decimal_divisor(value);
    let mut remaining = value;
    while divisor > 0 {
        #[allow(clippy::cast_possible_truncation, reason = "INVARIANT: the largest-divisor construction and successive remainders keep the quotient below ten")]
        let digit = (remaining / divisor) as u8;
        output.push(b'0' + digit);
        remaining %= divisor;
        divisor /= 10;
    }
    output
}

/// Canonical signed decimal bytes for every i64; no plus or negative zero.
#[must_use]
pub fn integer_bytes(value: i64) -> Vec<u8> {
    let mut output = Vec::new();
    if value < 0 {
        output.push(b'-');
    }
    append_unsigned_decimal(output, magnitude(value))
}

/// Validates a string and preserves every accepted byte in the typed value.
#[must_use]
pub fn string_value(minimum: usize, maximum: usize, text: &[u8]) -> Option<ArgumentValue> {
    if string_value_valid(minimum, maximum, text) {
        Some(ArgumentValue::Text(copy_bytes(text)))
    } else {
        None
    }
}

/// Validates an enum and preserves the exact supplied member bytes.
#[must_use]
pub fn enum_value(variants: &[Vec<u8>], text: &[u8]) -> Option<ArgumentValue> {
    if enum_value_valid(variants, text) {
        Some(ArgumentValue::Text(copy_bytes(text)))
    } else {
        None
    }
}

/// Validates an integer and renders that same signed value as exact decimal.
#[must_use]
pub fn integer_value(minimum: i64, maximum: i64, value: i64) -> Option<ArgumentValue> {
    if integer_value_valid(minimum, maximum, value) {
        Some(ArgumentValue::Integer(integer_bytes(value)))
    } else {
        None
    }
}

/// Preserves the exact JSON boolean in the closed construction vocabulary.
#[must_use]
pub const fn boolean_value(value: bool) -> ArgumentValue {
    ArgumentValue::Boolean(value)
}

/// Validates the complete scalar using exactly the schema/input-kind pair.
/// Mismatched kinds and unsupported JSON values are always refused.
#[must_use]
pub fn scalar_valid(schema: &ScalarSchema, input: ScalarInput<'_>) -> bool {
    match (schema, input) {
        (ScalarSchema::String { minimum, maximum }, ScalarInput::Text(text)) => {
            string_value_valid(*minimum, *maximum, text)
        }
        (ScalarSchema::Enum { variants }, ScalarInput::Text(text)) => enum_value_valid(variants, text),
        (ScalarSchema::Integer { minimum, maximum }, ScalarInput::Integer(value)) => {
            integer_value_valid(*minimum, *maximum, value)
        }
        (ScalarSchema::Boolean, ScalarInput::Boolean(_)) => true,
        _ => false,
    }
}

/// Validates and projects one complete typed scalar, with no coercion or
/// caller-provided validity flag. Every accepted payload is at most 4096 bytes.
#[must_use]
pub fn project_scalar(schema: &ScalarSchema, input: ScalarInput<'_>) -> Option<ArgumentValue> {
    match (schema, input) {
        (ScalarSchema::String { minimum, maximum }, ScalarInput::Text(text)) => {
            string_value(*minimum, *maximum, text)
        }
        (ScalarSchema::Enum { variants }, ScalarInput::Text(text)) => enum_value(variants, text),
        (ScalarSchema::Integer { minimum, maximum }, ScalarInput::Integer(value)) => {
            integer_value(*minimum, *maximum, value)
        }
        (ScalarSchema::Boolean, ScalarInput::Boolean(value)) => Some(boolean_value(value)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::vec;

    #[test]
    fn decimal_arithmetic_matches_independent_standard_formatting() {
        for value in -65_536_i64..=65_536 {
            assert_eq!(integer_bytes(value), std::format!("{value}").into_bytes());
        }
        let mut power = 1_i64;
        for _ in 0..=18 {
            for value in [power - 1, power, power + 1, -(power - 1), -power, -(power + 1)] {
                assert_eq!(integer_bytes(value), std::format!("{value}").into_bytes());
            }
            if power <= i64::MAX / 10 {
                power *= 10;
            }
        }
        for value in [i64::MIN, i64::MIN + 1, i64::MAX - 1, i64::MAX, -MAX_JSON_INTEGER, MAX_JSON_INTEGER] {
            assert_eq!(integer_bytes(value), std::format!("{value}").into_bytes());
            assert!(integer_bytes(value).len() <= 20);
        }
        for value in [0, 1, 9, 10, 99, 100, u64::MAX - 1, u64::MAX] {
            assert_eq!(append_unsigned_decimal(Vec::new(), value), std::format!("{value}").into_bytes());
        }
    }

    #[test]
    fn string_boundaries_and_all_single_bytes_have_exact_refusals() {
        assert_eq!(string_value(0, 0, b""), Some(ArgumentValue::Text(vec![])));
        for byte in 0_u8..=255 {
            let expected = if byte == 0 { None } else { Some(ArgumentValue::Text(vec![byte])) };
            assert_eq!(string_value(1, 1, &[byte]), expected);
        }
        assert!(string_value(0, MAX_TEXT_BYTES, &vec![b'x'; MAX_TEXT_BYTES]).is_some());
        assert!(string_value(0, MAX_TEXT_BYTES, &vec![b'x'; MAX_TEXT_BYTES + 1]).is_none());
        assert!(string_value(2, 1, b"x").is_none());
        assert!(string_value(0, usize::MAX, b"x").is_none());
    }

    #[test]
    fn enum_lexical_membership_and_duplicates_are_checked_together() {
        let variants = vec![b"first".to_vec(), b"second".to_vec()];
        assert_eq!(enum_value(&variants, b"second"), Some(ArgumentValue::Text(b"second".to_vec())));
        for text in [b"Second".as_slice(), b"second\0", b"second.", b""] {
            assert!(enum_value(&variants, text).is_none());
        }
        assert!(!enum_schema_valid(&[]));
        assert!(!enum_schema_valid(&[b"same".to_vec(), b"same".to_vec()]));
        assert!(!enum_schema_valid(&[vec![b'x'; MAX_ENUM_BYTES + 1]]));
        let mut maximum: Vec<_> = (0..MAX_ENUM_VARIANTS)
            .map(|index| std::format!("variant_{index}").into_bytes()).collect();
        assert!(enum_schema_valid(&maximum));
        maximum.push(b"one_more".to_vec());
        assert!(!enum_schema_valid(&maximum));
        for byte in 0_u8..=255 {
            let expected = byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-');
            assert_eq!(enum_variant_valid(&[byte]), expected);
        }
    }

    #[test]
    fn integer_global_and_schema_bounds_refuse_before_rendering() {
        for value in [-MAX_JSON_INTEGER, -1, 0, 1, MAX_JSON_INTEGER] {
            assert_eq!(integer_value(-MAX_JSON_INTEGER, MAX_JSON_INTEGER, value),
                Some(ArgumentValue::Integer(std::format!("{value}").into_bytes())));
            assert!(integer_bytes(value).len() <= 17);
        }
        for value in [i64::MIN, -MAX_JSON_INTEGER - 1, MAX_JSON_INTEGER + 1, i64::MAX] {
            assert!(integer_value(-MAX_JSON_INTEGER, MAX_JSON_INTEGER, value).is_none());
        }
        assert!(integer_value(2, 1, 1).is_none());
        assert!(integer_value(i64::MIN, i64::MAX, 0).is_none());
    }

    #[test]
    fn closed_dispatch_matches_independent_kind_matrix_without_coercion() {
        let schemas = [
            ScalarSchema::String { minimum: 1, maximum: 64 },
            ScalarSchema::Enum { variants: vec![b"first".to_vec()] },
            ScalarSchema::Integer { minimum: -1, maximum: 1 },
            ScalarSchema::Boolean,
        ];
        let inputs = [
            ScalarInput::Text(b"first"), ScalarInput::Integer(-1),
            ScalarInput::Boolean(false), ScalarInput::Unsupported,
        ];
        let expected = [
            [true, false, false, false], [true, false, false, false],
            [false, true, false, false], [false, false, true, false],
        ];
        for (row, schema) in schemas.iter().enumerate() {
            for (column, input) in inputs.iter().enumerate() {
                assert_eq!(scalar_valid(schema, *input), expected[row][column]);
                assert_eq!(project_scalar(schema, *input).is_some(), expected[row][column]);
            }
        }
        assert_eq!(project_scalar(&schemas[2], inputs[1]), Some(ArgumentValue::Integer(b"-1".to_vec())));
        assert_eq!(project_scalar(&schemas[3], inputs[2]), Some(ArgumentValue::Boolean(false)));
        for invalid in [
            ScalarSchema::String { minimum: 2, maximum: 1 },
            ScalarSchema::Enum { variants: vec![b"first".to_vec(), b"first".to_vec()] },
            ScalarSchema::Integer { minimum: 2, maximum: 1 },
        ] {
            for input in &inputs {
                assert!(!scalar_valid(&invalid, *input));
                assert!(project_scalar(&invalid, *input).is_none());
            }
        }
    }
}
