//! Complete named-object projection from compiled field schemas to arguments.
//!
//! The compiler derives positional names from the same field specifications
//! consumed here. JSON supplies only borrowed names and closed scalar inputs;
//! schema lookup, validation, complete value projection and final name binding
//! are all shipping kernel decisions.

use alloc::vec::Vec;

use crate::arguments::{MAX_PROFILE_FIELDS, NamedArgument, bind_arguments, unique_fields};
use crate::construct::{ArgumentValue, ConstructError, copy_bytes, field_name_equal};
use crate::identity::valid_token;
use crate::scalars::{ScalarInput, ScalarSchema, project_scalar};

/// One complete compiled field; name and schema cannot occupy separate slots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldSpec {
    /// Exact bounded ASCII name, checked by [`field_names`].
    pub name: Vec<u8>,
    /// The complete scalar schema, checked when projecting its input.
    pub schema: ScalarSchema,
}

/// One JSON object member after kind extraction, without a selected schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamedInput<'a> {
    /// Complete borrowed name, never normalized or case folded.
    pub name: &'a [u8],
    /// Exact scalar kind and contents from that same member.
    pub value: ScalarInput<'a>,
}

/// The complete projected object and the logical operation from that same
/// object. This is request data, not an authorization or execution capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestArguments {
    /// Values in the immutable compiled field order.
    pub values: Vec<ArgumentValue>,
    /// The exact validated operation token from the projected input object.
    pub operation_id: Vec<u8>,
}

/// Stable distinctions used by the native request shell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestBindingError {
    /// Count, operator namespace or approved recipe digest does not match.
    ActionMismatch,
    /// Complete object schema/name/value projection refused.
    Projection(ConstructError),
    /// The same object's operation is not a canonical 1–128-byte token.
    OperationId,
}

/// Finds the first exactly named text member. A first member with another
/// scalar kind refuses; it cannot be skipped in favor of a later duplicate.
/// Full duplicate exclusion is earned separately by [`project_object`].
#[must_use]
pub fn text_member<'a>(supplied: &[NamedInput<'a>], name: &[u8]) -> Option<&'a [u8]> {
    let mut position = 0;
    while position < supplied.len() {
        let input = &supplied[position];
        if field_name_equal(input.name, name) {
            return match input.value {
                ScalarInput::Text(value) => Some(value),
                ScalarInput::Integer(_) | ScalarInput::Boolean(_) | ScalarInput::Unsupported => None,
            };
        }
        position += 1;
    }
    None
}

/// Copies the bounded, lexical field-name column without changing its order.
///
/// # Errors
/// Returns [`ConstructError::ArgumentMismatch`] for more than 32 fields,
/// or a malformed/oversized name. Uniqueness is checked by [`field_names`].
pub fn copy_field_names(fields: &[FieldSpec]) -> Result<Vec<Vec<u8>>, ConstructError> {
    if fields.len() > MAX_PROFILE_FIELDS {
        return Err(ConstructError::ArgumentMismatch);
    }
    let mut names = Vec::new();
    let mut position = 0;
    while position < fields.len() {
        let name = &fields[position].name;
        if !valid_token(name, 64) {
            return Err(ConstructError::ArgumentMismatch);
        }
        names.push(copy_bytes(name));
        position += 1;
    }
    Ok(names)
}

/// Validates and copies the unique positional names of a bounded field layout.
/// Compilation and runtime binding call this same function on the same fields.
///
/// # Errors
/// Returns [`ConstructError::ArgumentMismatch`] for more than 32 fields,
/// malformed/oversized names, or duplicates. Empty layouts are total; native
/// profile-lock validation separately requires its mandatory binding fields.
pub fn field_names(fields: &[FieldSpec]) -> Result<Vec<Vec<u8>>, ConstructError> {
    let copied = copy_field_names(fields);
    // Borrow the initialized result throughout matching. A successful name
    // column is already bounded to 32 names of at most 64 bytes each.
    match &copied {
        Ok(names) => {
            if unique_fields(names) {
                Ok(names.clone())
            } else {
                Err(ConstructError::ArgumentMismatch)
            }
        }
        Err(error) => Err(*error),
    }
}

/// Finds the schema paired with the first exact field name.
/// Layout uniqueness is established separately by [`field_names`].
#[must_use]
pub fn schema_for<'a>(fields: &'a [FieldSpec], name: &[u8]) -> Option<&'a ScalarSchema> {
    let mut position = 0;
    while position < fields.len() {
        if field_name_equal(&fields[position].name, name) {
            return Some(&fields[position].schema);
        }
        position += 1;
    }
    None
}

/// Projects complete named members through their exact paired schemas.
/// Successful rows preserve supplied order and earn all name/payload bounds.
/// This helper can project a subset; [`project_object`] additionally requires
/// and binds the complete field set before returning positional arguments.
///
/// # Errors
/// Returns [`ConstructError::ArgumentMismatch`] for an oversized layout/input,
/// malformed or unknown name, unsupported/wrong scalar kind, invalid schema,
/// or a scalar outside its schema bounds.
pub fn project_rows(
    fields: &[FieldSpec],
    supplied: &[NamedInput<'_>],
) -> Result<Vec<NamedArgument>, ConstructError> {
    if fields.len() > MAX_PROFILE_FIELDS || supplied.len() > MAX_PROFILE_FIELDS {
        return Err(ConstructError::ArgumentMismatch);
    }
    let mut output = Vec::new();
    let mut position = 0;
    while position < supplied.len() {
        let input = &supplied[position];
        if !valid_token(input.name, 64) {
            return Err(ConstructError::ArgumentMismatch);
        }
        let schema = match schema_for(fields, input.name) {
            Some(schema) => schema,
            None => return Err(ConstructError::ArgumentMismatch),
        };
        let value = match project_scalar(schema, input.value) {
            Some(value) => value,
            None => return Err(ConstructError::ArgumentMismatch),
        };
        output.push(NamedArgument { name: copy_bytes(input.name), value });
        position += 1;
    }
    Ok(output)
}

/// Produces the complete positional vector from one compiled layout and one
/// named scalar object. No validity, alignment or schema-selection flag is an
/// input. Missing, extra, duplicate and malformed fields cannot be returned as
/// an executable construction value.
///
/// # Errors
/// Returns [`ConstructError::ArgumentMismatch`] for any invalid layout, count,
/// name, scalar, or incomplete binding, before returning any argument vector.
#[allow(clippy::question_mark, reason = "explicit closed Result branches retain the existing translated kernel interface without adding Try/FromResidual models")]
pub fn project_object(
    fields: &[FieldSpec],
    supplied: &[NamedInput<'_>],
) -> Result<Vec<ArgumentValue>, ConstructError> {
    if fields.len() > MAX_PROFILE_FIELDS || supplied.len() != fields.len() {
        return Err(ConstructError::ArgumentMismatch);
    }
    let names = match field_names(fields) {
        Ok(names) => names,
        Err(error) => return Err(error),
    };
    let projected = match project_rows(fields, supplied) {
        Ok(projected) => projected,
        Err(error) => return Err(error),
    };
    bind_arguments(&names, &projected)
}

/// Binds a complete request object to its installed namespace and recipe,
/// projects every field, and obtains the operation from that same object.
/// Checks consume no separately supplied operation, field index or admission
/// flag. The namespace is checked here as well as by its native constructor,
/// so successful projection earns the preimage framing domain.
///
/// The digest is compared as exact bytes; the native compiled-recipe caller
/// is responsible for deriving those expected bytes from its approved digest.
///
/// # Errors
/// Refuses count/layout bounds and namespace/digest disagreement first, then
/// complete object projection, then the operation token. No partially bound
/// object is returned on any refusal.
#[allow(clippy::question_mark, reason = "explicit Result branches keep the translated refusal interface closed")]
pub fn project_request(
    fields: &[FieldSpec],
    supplied: &[NamedInput<'_>],
    namespace: &[u8],
    recipe_digest: &[u8],
) -> Result<RequestArguments, RequestBindingError> {
    if fields.len() > MAX_PROFILE_FIELDS || supplied.len() != fields.len() {
        return Err(RequestBindingError::ActionMismatch);
    }
    if !valid_token(namespace, 64) {
        return Err(RequestBindingError::ActionMismatch);
    }
    let actual_namespace = match text_member(supplied, b"operator_namespace") {
        Some(value) => value,
        None => return Err(RequestBindingError::ActionMismatch),
    };
    if !field_name_equal(actual_namespace, namespace) {
        return Err(RequestBindingError::ActionMismatch);
    }
    let actual_digest = match text_member(supplied, b"recipe_digest") {
        Some(value) => value,
        None => return Err(RequestBindingError::ActionMismatch),
    };
    if !field_name_equal(actual_digest, recipe_digest) {
        return Err(RequestBindingError::ActionMismatch);
    }
    let values = match project_object(fields, supplied) {
        Ok(values) => values,
        Err(error) => return Err(RequestBindingError::Projection(error)),
    };
    let operation = match text_member(supplied, b"operation_id") {
        Some(value) => value,
        None => return Err(RequestBindingError::OperationId),
    };
    if !valid_token(operation, 128) {
        return Err(RequestBindingError::OperationId);
    }
    Ok(RequestArguments { values, operation_id: copy_bytes(operation) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn fields() -> Vec<FieldSpec> {
        vec![
            FieldSpec { name: b"amount".to_vec(), schema: ScalarSchema::Integer { minimum: -1, maximum: 100 } },
            FieldSpec { name: b"label".to_vec(), schema: ScalarSchema::String { minimum: 1, maximum: 64 } },
            FieldSpec { name: b"enabled".to_vec(), schema: ScalarSchema::Boolean },
        ]
    }

    #[test]
    fn object_projection_binds_names_schemas_and_complete_values() {
        let fields = fields();
        let supplied = [
            NamedInput { name: b"amount", value: ScalarInput::Integer(-1) },
            NamedInput { name: b"label", value: ScalarInput::Text("é\"\\".as_bytes()) },
            NamedInput { name: b"enabled", value: ScalarInput::Boolean(false) },
        ];
        let expected = vec![
            ArgumentValue::Integer(b"-1".to_vec()), ArgumentValue::Text("é\"\\".as_bytes().to_vec()),
            ArgumentValue::Boolean(false),
        ];
        for order in [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
            let reordered = order.map(|index| supplied[index]);
            assert_eq!(project_object(&fields, &reordered), Ok(expected.clone()));
        }
        assert_eq!(field_names(&fields), Ok(vec![b"amount".to_vec(), b"label".to_vec(), b"enabled".to_vec()]));
    }

    #[test]
    fn same_count_cannot_hide_missing_duplicate_unknown_or_wrong_schema_values() {
        let fields = fields();
        let valid = [
            NamedInput { name: b"amount", value: ScalarInput::Integer(1) },
            NamedInput { name: b"label", value: ScalarInput::Text(b"label") },
            NamedInput { name: b"enabled", value: ScalarInput::Boolean(true) },
        ];
        for hostile in [
            NamedInput { name: b"label", value: ScalarInput::Integer(1) },
            NamedInput { name: b"Label", value: ScalarInput::Text(b"label") },
            NamedInput { name: b"label\0", value: ScalarInput::Text(b"label") },
            NamedInput { name: b"amount", value: ScalarInput::Integer(1) },
            NamedInput { name: b"label", value: ScalarInput::Unsupported },
        ] {
            assert_eq!(project_object(&fields, &[valid[0], hostile, valid[2]]), Err(ConstructError::ArgumentMismatch));
        }
        assert_eq!(project_object(&fields, &valid[..2]), Err(ConstructError::ArgumentMismatch));
        let mut duplicate = fields.clone();
        duplicate[1].name = duplicate[0].name.clone();
        assert_eq!(project_object(&duplicate, &valid), Err(ConstructError::ArgumentMismatch));
        let mut invalid = fields;
        invalid[0].schema = ScalarSchema::Integer { minimum: 2, maximum: 1 };
        assert_eq!(project_object(&invalid, &valid), Err(ConstructError::ArgumentMismatch));
    }

    #[test]
    fn name_layout_boundaries_refuse_before_projection() {
        assert_eq!(project_object(&[], &[]), Ok(vec![]));
        let invalid = [b"".as_slice(), b"_first", b"a\0b", b"a/b", "é".as_bytes()];
        for name in invalid {
            let field = FieldSpec { name: name.to_vec(), schema: ScalarSchema::Boolean };
            assert_eq!(field_names(&[field]), Err(ConstructError::ArgumentMismatch));
        }
        let mut maximum = Vec::new();
        for index in 0_u8..32 {
            maximum.push(FieldSpec {
                name: vec![b'a', b'0' + index / 10, b'0' + index % 10],
                schema: ScalarSchema::Boolean,
            });
        }
        assert!(field_names(&maximum).is_ok());
        maximum.push(FieldSpec { name: b"one_more".to_vec(), schema: ScalarSchema::Boolean });
        assert_eq!(field_names(&maximum), Err(ConstructError::ArgumentMismatch));
    }

    fn request_fields() -> Vec<FieldSpec> {
        vec![
            FieldSpec { name: b"operation_id".to_vec(), schema: ScalarSchema::String { minimum: 0, maximum: 4096 } },
            FieldSpec { name: b"recipe_digest".to_vec(), schema: ScalarSchema::String { minimum: 1, maximum: 64 } },
            FieldSpec { name: b"operator_namespace".to_vec(), schema: ScalarSchema::String { minimum: 1, maximum: 64 } },
            FieldSpec { name: b"operation_id_extra".to_vec(), schema: ScalarSchema::String { minimum: 1, maximum: 64 } },
        ]
    }

    #[test]
    fn request_binding_uses_the_same_object_for_values_and_operation() {
        let fields = request_fields();
        let supplied = [
            NamedInput { name: b"operator_namespace", value: ScalarInput::Text(b"operator-a") },
            NamedInput { name: b"operation_id_extra", value: ScalarInput::Text(b"wrong-operation") },
            NamedInput { name: b"recipe_digest", value: ScalarInput::Text(b"approved-digest") },
            NamedInput { name: b"operation_id", value: ScalarInput::Text(b"actual-operation") },
        ];
        for first in 0..4 {
            for second in 0..4 {
                for third in 0..4 {
                    for fourth in 0..4 {
                        let order = [first, second, third, fourth];
                        if order.iter().enumerate().any(|(i, value)| order[..i].contains(value)) {
                            continue;
                        }
                        let reordered = order.map(|index| supplied[index]);
                        let actual = project_request(&fields, &reordered, b"operator-a", b"approved-digest").unwrap();
                        assert_eq!(actual.operation_id, b"actual-operation");
                        assert_eq!(actual.values, vec![
                            ArgumentValue::Text(b"actual-operation".to_vec()),
                            ArgumentValue::Text(b"approved-digest".to_vec()),
                            ArgumentValue::Text(b"operator-a".to_vec()),
                            ArgumentValue::Text(b"wrong-operation".to_vec()),
                        ]);
                    }
                }
            }
        }
        assert_eq!(project_request(&fields, &supplied, b"operator-b", b"approved-digest"), Err(RequestBindingError::ActionMismatch));
        assert_eq!(project_request(&fields, &supplied, b"operator-a", b"other-digest"), Err(RequestBindingError::ActionMismatch));
        let mut duplicate = supplied;
        duplicate[1] = supplied[3];
        assert_eq!(project_request(&fields, &duplicate, b"operator-a", b"approved-digest"), Err(RequestBindingError::Projection(ConstructError::ArgumentMismatch)));
        assert_eq!(text_member(&[
            NamedInput { name: b"operation_id", value: ScalarInput::Boolean(true) }, supplied[3],
        ], b"operation_id"), None);
    }

    #[test]
    fn request_binding_earns_token_bounds_and_keeps_refusal_precedence() {
        let fields = request_fields();
        let namespace = [b'n'; 64];
        let operation = [b'o'; 128];
        let mut supplied = [
            NamedInput { name: b"operator_namespace", value: ScalarInput::Text(&namespace) },
            NamedInput { name: b"recipe_digest", value: ScalarInput::Text(b"digest") },
            NamedInput { name: b"operation_id_extra", value: ScalarInput::Text(b"extra") },
            NamedInput { name: b"operation_id", value: ScalarInput::Text(&operation) },
        ];
        let admitted = project_request(&fields, &supplied, &namespace, b"digest").unwrap();
        assert_eq!(admitted.operation_id, operation);
        let too_long = [b'o'; 129];
        for invalid in [b"".as_slice(), b"_starts-wrong", b"a/b", &too_long] {
            supplied[3].value = ScalarInput::Text(invalid);
            assert_eq!(project_request(&fields, &supplied, &namespace, b"digest"), Err(RequestBindingError::OperationId));
        }
        supplied[3].value = ScalarInput::Text(b"_starts-wrong");
        supplied[2].value = ScalarInput::Boolean(true);
        assert_eq!(project_request(&fields, &supplied, &namespace, b"digest"), Err(RequestBindingError::Projection(ConstructError::ArgumentMismatch)));
        assert_eq!(project_request(&fields, &supplied, &namespace, b"different"), Err(RequestBindingError::ActionMismatch));
        assert_eq!(project_request(&fields, &supplied[..3], &namespace, b"digest"), Err(RequestBindingError::ActionMismatch));
        assert_eq!(project_request(&fields, &supplied, b"_invalid", b"digest"), Err(RequestBindingError::ActionMismatch));
    }
}
