//! Exact named-to-positional argument binding for compiled recipe fields.
//!
//! JSON decoding and schema validation remain in the gateway. This leaf takes
//! those typed values, finds them by their complete field name, and produces
//! the positional vector consumed by request construction. A supplied object's
//! iteration order never selects which value a compiled field receives.

use alloc::vec::Vec;

use crate::construct::{ArgumentValue, ConstructError, copy_bytes, field_index, field_name_equal};

/// The maximum number of fields in a generated gateway profile lock.
pub const MAX_PROFILE_FIELDS: usize = 32;

/// A schema-validated scalar together with its complete verified field name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedArgument {
    /// Exact UTF-8 field-name bytes; no normalization or case folding occurs.
    pub name: Vec<u8>,
    /// The complete scalar representation used by request construction.
    pub value: ArgumentValue,
}

/// Copies one complete construction value without changing its kind or bytes.
#[must_use]
pub fn copy_argument(value: &ArgumentValue) -> ArgumentValue {
    match value {
        ArgumentValue::Text(bytes) => ArgumentValue::Text(copy_bytes(bytes)),
        ArgumentValue::Integer(bytes) => ArgumentValue::Integer(copy_bytes(bytes)),
        ArgumentValue::Boolean(value) => ArgumentValue::Boolean(*value),
    }
}

/// Finds the first value with the exact requested name.
///
/// This lookup grants no schema validity or authority. [`bind_arguments`]
/// checks the complete field/value layout before its result can be consumed.
#[must_use]
pub fn named_argument<'a>(
    supplied: &'a [NamedArgument],
    name: &[u8],
) -> Option<&'a ArgumentValue> {
    let mut position = 0;
    while position < supplied.len() {
        if field_name_equal(&supplied[position].name, name) {
            return Some(&supplied[position].value);
        }
        position += 1;
    }
    None
}

/// Checks that every compiled field name is unique.
#[must_use]
pub fn unique_fields(fields: &[Vec<u8>]) -> bool {
    let mut position = 0;
    while position < fields.len() {
        match field_index(fields, &fields[position]) {
            Some(first) => {
                if first != position {
                    return false;
                }
            }
            None => return false,
        }
        position += 1;
    }
    true
}

/// Binds every supplied value to the compiled field with the same exact name.
///
/// The output follows `fields`, the same field-name snapshot used by compiler
/// lowering. Equal cardinalities, unique compiled names and a value for every
/// name exclude missing, extra and repeated supplied names. The source object
/// may list its members in any order. Complete scalar payloads are preserved.
///
/// # Errors
/// Returns [`ConstructError::ArgumentMismatch`] for an oversized layout,
/// unequal lengths, repeated compiled names, or an absent supplied name. The
/// caller must separately establish schema validity and verified provenance.
pub fn bind_arguments(
    fields: &[Vec<u8>],
    supplied: &[NamedArgument],
) -> Result<Vec<ArgumentValue>, ConstructError> {
    if fields.len() > MAX_PROFILE_FIELDS || supplied.len() != fields.len() {
        return Err(ConstructError::ArgumentMismatch);
    }
    if !unique_fields(fields) {
        return Err(ConstructError::ArgumentMismatch);
    }
    let mut output = Vec::new();
    let mut position = 0;
    while position < fields.len() {
        match named_argument(supplied, &fields[position]) {
            Some(value) => output.push(copy_argument(value)),
            None => return Err(ConstructError::ArgumentMismatch),
        }
        position += 1;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::vec;

    fn named(name: &[u8], value: ArgumentValue) -> NamedArgument {
        NamedArgument { name: name.to_vec(), value }
    }

    #[test]
    fn complete_values_follow_names_for_every_supplied_permutation() {
        let fields = vec![b"a".to_vec(), b"a.b".to_vec(), b"amount".to_vec(), b"enabled".to_vec()];
        let supplied = [
            named(b"a", ArgumentValue::Text(b"\0\xc3\xa9".to_vec())),
            named(b"a.b", ArgumentValue::Text(b"different".to_vec())),
            named(b"amount", ArgumentValue::Integer(b"-9007199254740991".to_vec())),
            named(b"enabled", ArgumentValue::Boolean(false)),
        ];
        let expected: Vec<_> = supplied.iter().map(|argument| argument.value.clone()).collect();
        for a in 0..4 {
            for b in 0..4 {
                for c in 0..4 {
                    for d in 0..4 {
                        let order = [a, b, c, d];
                        if order.iter().enumerate().any(|(i, n)| order[..i].contains(n)) {
                            continue;
                        }
                        let values: Vec<_> = order.iter().map(|i| supplied[*i].clone()).collect();
                        assert_eq!(bind_arguments(&fields, &values), Ok(expected.clone()));
                    }
                }
            }
        }
    }

    #[test]
    fn missing_extra_duplicate_and_similar_names_refuse() {
        let fields = vec![b"amount".to_vec(), b"scope".to_vec()];
        let amount = named(b"amount", ArgumentValue::Integer(b"100".to_vec()));
        let scope = named(b"scope", ArgumentValue::Text(b"acct_synthetic".to_vec()));
        for values in [
            vec![],
            vec![amount.clone()],
            vec![amount.clone(), amount.clone()],
            vec![amount.clone(), named(b"Scope", scope.value.clone())],
            vec![amount.clone(), named(b"scope\0", scope.value.clone())],
            vec![amount.clone(), scope.clone(), scope.clone()],
        ] {
            assert_eq!(bind_arguments(&fields, &values), Err(ConstructError::ArgumentMismatch));
        }
        assert_eq!(
            bind_arguments(&[b"amount".to_vec(), b"amount".to_vec()], &[amount.clone(), amount]),
            Err(ConstructError::ArgumentMismatch)
        );
    }

    #[test]
    fn field_bound_is_inclusive_and_empty_layout_is_total() {
        assert_eq!(bind_arguments(&[], &[]), Ok(vec![]));
        let mut fields = Vec::new();
        let mut supplied = Vec::new();
        for index in 0..=MAX_PROFILE_FIELDS {
            let name = std::format!("field_{index}").into_bytes();
            fields.push(name.clone());
            supplied.push(named(&name, ArgumentValue::Boolean(index % 2 == 0)));
            if index < MAX_PROFILE_FIELDS {
                assert_eq!(bind_arguments(&fields, &supplied).map(|values| values.len()), Ok(index + 1));
            } else {
                assert_eq!(bind_arguments(&fields, &supplied), Err(ConstructError::ArgumentMismatch));
            }
        }
    }
}
