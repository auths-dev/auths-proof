//! Complete validation of decoded profile command schemas.
//!
//! The native JSON boundary supplies exact member names, string bytes and
//! integer kinds. This module owns all Auths key sets, schema bounds, enum
//! checks, field-name uniqueness and reserved binding decisions. It grants no
//! installation or action authority and does not canonicalize or hash JSON.

use alloc::vec::Vec;

use crate::arguments::MAX_PROFILE_FIELDS;
use crate::construct::{copy_bytes, field_name_equal};
use crate::field_projection::{FieldSpec, field_names, schema_for};
use crate::identity::valid_token;
use crate::scalars::{self, ScalarSchema};

/// A kind-preserving projection of an untrusted JSON schema value. Unsupported
/// JSON scalars (including floats) remain a refusal kind, without coercion.
/// Objects retain every original name/value pair, including any duplicates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SchemaValue {
    /// Exact UTF-8 bytes of a decoded JSON string.
    Text(Vec<u8>),
    /// A JSON integer represented exactly by the signed carrier.
    Signed(i64),
    /// A nonnegative JSON integer; it is range checked before signed use.
    Unsigned(u64),
    /// Every original array value in order.
    Array(Vec<SchemaValue>),
    /// Every original member, without selecting a known key in the adapter.
    Object(Vec<SchemaMember>),
    /// Null, booleans and non-integer JSON numbers cannot be schema atoms.
    Unsupported,
}

/// One decoded object member; the adapter cannot supply a prevalidated schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaMember {
    /// Complete original member name.
    pub name: Vec<u8>,
    /// The value belonging to that same member.
    pub value: SchemaValue,
}

fn member<'a>(members: &'a [SchemaMember], wanted: &[u8]) -> Option<&'a SchemaValue> {
    let mut position = 0;
    while position < members.len() {
        let current = &members[position];
        if field_name_equal(&current.name, wanted) {
            return Some(&current.value);
        }
        position += 1;
    }
    None
}

fn text_is(value: Option<&SchemaValue>, expected: &[u8]) -> bool {
    match value {
        Some(SchemaValue::Text(text)) => field_name_equal(text, expected),
        _ => false,
    }
}

fn one_key(members: &[SchemaMember], first: &[u8]) -> bool {
    members.len() == 1 && member(members, first).is_some()
}

fn two_keys(members: &[SchemaMember], first: &[u8], second: &[u8]) -> bool {
    members.len() == 2 && member(members, first).is_some() && member(members, second).is_some()
}

fn three_keys(members: &[SchemaMember], first: &[u8], second: &[u8], third: &[u8]) -> bool {
    members.len() == 3 && member(members, first).is_some()
        && member(members, second).is_some() && member(members, third).is_some()
}

#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    reason = "INVARIANT: both integer arms are range checked to 0..=4096 before the usize cast, including on the 32-bit extraction target"
)]
fn string_bound(value: Option<&SchemaValue>) -> Option<usize> {
    match value {
        Some(SchemaValue::Signed(value)) => {
            if *value < 0 || *value > 4096 { None } else { Some(*value as usize) }
        }
        Some(SchemaValue::Unsigned(value)) => {
            if *value > 4096 { None } else { Some(*value as usize) }
        }
        _ => None,
    }
}

#[allow(
    clippy::cast_possible_wrap,
    reason = "INVARIANT: the unsigned carrier is compared with i64::MAX before conversion"
)]
fn signed_bound(value: Option<&SchemaValue>) -> Option<i64> {
    match value {
        Some(SchemaValue::Signed(value)) => Some(*value),
        Some(SchemaValue::Unsigned(value)) => {
            if *value > 9_223_372_036_854_775_807 { None } else { Some(*value as i64) }
        }
        _ => None,
    }
}

fn enum_schema(values: &[SchemaValue]) -> Option<ScalarSchema> {
    if values.is_empty() || values.len() > scalars::MAX_ENUM_VARIANTS { return None; }
    let mut variants = Vec::new();
    let mut position = 0;
    loop {
        if position >= values.len() {
            if !scalars::enum_schema_valid(&variants) { return None; }
            return Some(ScalarSchema::Enum { variants });
        }
        let text = match &values[position] {
            SchemaValue::Text(text) => text,
            _ => return None,
        };
        if !scalars::enum_variant_valid(text) { return None; }
        variants.push(copy_bytes(text));
        position += 1;
    }
}

/// Parses one complete scalar schema, including exact keys and every bound.
/// All unsupported kinds, duplicate/extra/missing keys, wrong numeric types
/// and invalid or duplicate enum variants return `None`.
#[must_use]
#[allow(clippy::question_mark, reason = "explicit closed Option branches preserve the translated source interface")]
pub fn parse_scalar(value: &SchemaValue) -> Option<ScalarSchema> {
    let object = match value { SchemaValue::Object(members) => members, _ => return None };
    if text_is(member(object, b"type"), b"enum") {
        if !two_keys(object, b"type", b"variants") { return None; }
        return match member(object, b"variants") {
            Some(SchemaValue::Array(values)) => enum_schema(values),
            _ => None,
        };
    }
    if text_is(member(object, b"kind"), b"boolean") {
        if !one_key(object, b"kind") { return None; }
        return Some(ScalarSchema::Boolean);
    }
    if !three_keys(object, b"kind", b"minimum", b"maximum") { return None; }
    if text_is(member(object, b"kind"), b"string") {
        let minimum = match string_bound(member(object, b"minimum")) { Some(value) => value, None => return None };
        let maximum = match string_bound(member(object, b"maximum")) { Some(value) => value, None => return None };
        if !scalars::string_schema_valid(minimum, maximum) { return None; }
        return Some(ScalarSchema::String { minimum, maximum });
    }
    if text_is(member(object, b"kind"), b"integer") {
        let minimum = match signed_bound(member(object, b"minimum")) { Some(value) => value, None => return None };
        let maximum = match signed_bound(member(object, b"maximum")) { Some(value) => value, None => return None };
        if !scalars::integer_schema_valid(minimum, maximum) { return None; }
        return Some(ScalarSchema::Integer { minimum, maximum });
    }
    None
}

fn parse_field(current: &SchemaMember) -> Option<FieldSpec> {
    if !valid_token(&current.name, 64) { return None; }
    let parsed = parse_scalar(&current.value);
    let schema = match &parsed { Some(schema) => schema.clone(), None => return None };
    let name = copy_bytes(&current.name);
    Some(FieldSpec { name, schema })
}

fn parse_fields(members: &[SchemaMember]) -> Option<Vec<FieldSpec>> {
    if members.is_empty() || members.len() > MAX_PROFILE_FIELDS { return None; }
    let mut fields = Vec::new();
    let mut position = 0;
    loop {
        if position >= members.len() {
            return match field_names(&fields) {
                Ok(_) => Some(fields),
                Err(_) => None,
            };
        }
        let parsed = parse_field(&members[position]);
        let field = match &parsed { Some(field) => field.clone(), None => return None };
        fields.push(field);
        position += 1;
    }
}

/// Parses the entire closed root object and all original named fields.
/// Success retains the exact name/schema pairing and original field order;
/// names are bounded ASCII tokens and unique. No JSON key is preselected by
/// the native adapter. All structural/type/limit failures return `None`.
#[must_use]
pub fn parse_root(value: &SchemaValue) -> Option<Vec<FieldSpec>> {
    let root = match value { SchemaValue::Object(members) => members, _ => return None };
    if !two_keys(root, b"kind", b"fields") || !text_is(member(root, b"kind"), b"object") { return None; }
    match member(root, b"fields") {
        Some(SchemaValue::Object(members)) => parse_fields(members),
        _ => None,
    }
}

/// Checks the complete reserved binding schemas from the parsed field set.
/// The namespace is compared in full. This does not authenticate the lock,
/// approve its mapping or authorize an action; callers must retain those
/// provenance checks and the constructor-valid schemas from [`parse_root`].
#[must_use]
pub fn binding_fields_match(fields: &[FieldSpec], namespace: &[u8]) -> bool {
    match schema_for(fields, b"operator_namespace") {
        Some(ScalarSchema::Enum { variants }) => {
            if variants.len() != 1 || !field_name_equal(&variants[0], namespace) { return false; }
        }
        _ => return false,
    }
    match schema_for(fields, b"operation_id") {
        Some(ScalarSchema::String { minimum, maximum }) => {
            if *minimum < 1 || *maximum > 128 { return false; }
        }
        _ => return false,
    }
    match schema_for(fields, b"recipe_digest") {
        Some(ScalarSchema::String { minimum, maximum }) => *minimum == 64 && *maximum == 64,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec};

    fn text(bytes: &[u8]) -> SchemaValue { SchemaValue::Text(bytes.to_vec()) }
    fn property(name: &[u8], value: SchemaValue) -> SchemaMember {
        SchemaMember { name: name.to_vec(), value }
    }
    fn object(properties: Vec<SchemaMember>) -> SchemaValue { SchemaValue::Object(properties) }
    fn bounded(kind: &[u8], minimum: SchemaValue, maximum: SchemaValue) -> SchemaValue {
        object(vec![property(b"kind", text(kind)), property(b"minimum", minimum), property(b"maximum", maximum)])
    }
    fn boolean() -> SchemaValue { object(vec![property(b"kind", text(b"boolean"))]) }
    fn enumeration(values: Vec<SchemaValue>) -> SchemaValue {
        object(vec![property(b"type", text(b"enum")), property(b"variants", SchemaValue::Array(values))])
    }
    fn root(fields: Vec<SchemaMember>) -> SchemaValue {
        object(vec![property(b"kind", text(b"object")), property(b"fields", object(fields))])
    }

    #[test]
    fn complete_scalar_schemas_preserve_exact_kinds_and_inclusive_limits() {
        assert_eq!(parse_scalar(&boolean()), Some(ScalarSchema::Boolean));
        for (minimum, maximum) in [(0, 0), (1, 1), (2, 64), (0, 4096), (4096, 4096)] {
            for source in [
                bounded(b"string", SchemaValue::Signed(minimum), SchemaValue::Signed(maximum)),
                bounded(b"string", SchemaValue::Unsigned(minimum as u64), SchemaValue::Unsigned(maximum as u64)),
            ] {
                assert_eq!(parse_scalar(&source), Some(ScalarSchema::String { minimum: minimum as usize, maximum: maximum as usize }));
            }
        }
        for (minimum, maximum) in [(-9_007_199_254_740_991, 9_007_199_254_740_991), (-1, 1), (0, 0)] {
            assert_eq!(parse_scalar(&bounded(b"integer", SchemaValue::Signed(minimum), SchemaValue::Signed(maximum))),
                Some(ScalarSchema::Integer { minimum, maximum }));
        }
        assert_eq!(parse_scalar(&bounded(b"integer", SchemaValue::Unsigned(0), SchemaValue::Unsigned(9_007_199_254_740_991))),
            Some(ScalarSchema::Integer { minimum: 0, maximum: 9_007_199_254_740_991 }));
        assert_eq!(parse_scalar(&enumeration(vec![text(b"first"), text(b"second:_-.9")])),
            Some(ScalarSchema::Enum { variants: vec![b"first".to_vec(), b"second:_-.9".to_vec()] }));
    }

    #[test]
    fn unsupported_or_out_of_range_bounds_never_coerce() {
        for bound in [SchemaValue::Unsupported, text(b"1"), SchemaValue::Array(vec![]), object(vec![])] {
            for kind in [b"string".as_slice(), b"integer"] {
                assert!(parse_scalar(&bounded(kind, bound.clone(), SchemaValue::Signed(1))).is_none());
                assert!(parse_scalar(&bounded(kind, SchemaValue::Signed(0), bound.clone())).is_none());
            }
        }
        for (minimum, maximum) in [(-1, 1), (2, 1), (0, 4097), (4097, 4097), (i64::MIN, i64::MAX)] {
            assert!(parse_scalar(&bounded(b"string", SchemaValue::Signed(minimum), SchemaValue::Signed(maximum))).is_none());
        }
        for (minimum, maximum) in [(2, 1), (-9_007_199_254_740_992, 1), (0, 9_007_199_254_740_992), (i64::MIN, i64::MAX)] {
            assert!(parse_scalar(&bounded(b"integer", SchemaValue::Signed(minimum), SchemaValue::Signed(maximum))).is_none());
        }
        for unsigned in [9_223_372_036_854_775_808, u64::MAX] {
            assert!(parse_scalar(&bounded(b"integer", SchemaValue::Signed(0), SchemaValue::Unsigned(unsigned))).is_none());
        }
    }

    #[test]
    fn scalar_key_sets_are_closed_order_independent_and_duplicate_free() {
        let schemas = [boolean(), bounded(b"string", SchemaValue::Signed(0), SchemaValue::Signed(4)),
            bounded(b"integer", SchemaValue::Signed(-1), SchemaValue::Signed(1)), enumeration(vec![text(b"a")])];
        for schema in schemas {
            let expected = parse_scalar(&schema).expect("valid test schema");
            let SchemaValue::Object(original) = schema else { panic!("object fixture"); };
            let mut reversed = original.clone();
            reversed.reverse();
            assert_eq!(parse_scalar(&object(reversed)), Some(expected));
            for position in 0..original.len() {
                let mut missing = original.clone();
                missing.remove(position);
                assert!(parse_scalar(&object(missing)).is_none());
                let mut duplicate = original.clone();
                duplicate.push(original[position].clone());
                assert!(parse_scalar(&object(duplicate)).is_none());
                let mut replacement = original.clone();
                replacement[position].name = b"unrecognized".to_vec();
                assert!(parse_scalar(&object(replacement)).is_none());
            }
            let mut extra = original;
            extra.push(property(b"extra", SchemaValue::Unsupported));
            assert!(parse_scalar(&object(extra)).is_none());
        }
        // Correct cardinality alone cannot admit repeated keys.
        assert!(parse_scalar(&object(vec![property(b"kind", text(b"string")),
            property(b"minimum", SchemaValue::Signed(0)), property(b"minimum", SchemaValue::Signed(1))])).is_none());
        assert!(parse_scalar(&object(vec![property(b"type", text(b"enum")), property(b"type", text(b"enum"))])).is_none());
    }

    #[test]
    fn enum_count_text_grammar_and_duplicate_limits_are_complete() {
        for values in [vec![], vec![text(b"a"), text(b"a")], vec![text(b"")], vec![text("é".as_bytes())],
            vec![text(b"a\0b")], vec![text(&[b'x'; 65])], vec![SchemaValue::Signed(1)], vec![SchemaValue::Unsupported]] {
            assert!(parse_scalar(&enumeration(values)).is_none());
        }
        let values: Vec<_> = (0..32).map(|index| text(format!("v{index}").as_bytes())).collect();
        assert!(parse_scalar(&enumeration(values.clone())).is_some());
        let mut oversized = values;
        oversized.push(text(b"v32"));
        assert!(parse_scalar(&enumeration(oversized)).is_none());
        assert!(parse_scalar(&enumeration(vec![text(&[b'x'; 64])])).is_some());
    }

    #[test]
    fn root_retains_every_original_pair_and_enforces_all_layout_limits() {
        let fields = vec![property(b"z", boolean()), property(b"a", bounded(b"integer", SchemaValue::Signed(-1), SchemaValue::Signed(1)))];
        assert_eq!(parse_root(&root(fields)), Some(vec![
            FieldSpec { name: b"z".to_vec(), schema: ScalarSchema::Boolean },
            FieldSpec { name: b"a".to_vec(), schema: ScalarSchema::Integer { minimum: -1, maximum: 1 } },
        ]));
        assert!(parse_root(&root(vec![])).is_none());
        assert!(parse_root(&root(vec![property(b"a", boolean()), property(b"a", boolean())])).is_none());
        for name in [b"".as_slice(), b"_bad", b"a:b", "é".as_bytes(), &[b'x'; 65]] {
            assert!(parse_root(&root(vec![property(name, boolean())])).is_none());
        }
        let fields: Vec<_> = (0..32).map(|index| property(format!("field{index}").as_bytes(), boolean())).collect();
        assert_eq!(parse_root(&root(fields.clone())).expect("inclusive count").len(), 32);
        let mut oversized = fields;
        oversized.push(property(b"field32", boolean()));
        assert!(parse_root(&root(oversized)).is_none());
        for value in [SchemaValue::Unsupported, boolean(), object(vec![property(b"kind", text(b"object")),
            property(b"kind", text(b"object"))]), object(vec![property(b"kind", text(b"object")),
            property(b"fields", SchemaValue::Array(vec![]))])] {
            assert!(parse_root(&value).is_none());
        }
    }

    fn binding_fields() -> Vec<FieldSpec> {
        parse_root(&root(vec![
            property(b"operator_namespace", enumeration(vec![text(b"operator-1")])),
            property(b"operation_id", bounded(b"string", SchemaValue::Signed(1), SchemaValue::Signed(128))),
            property(b"recipe_digest", bounded(b"string", SchemaValue::Signed(64), SchemaValue::Signed(64))),
        ])).expect("valid reserved schemas")
    }

    #[test]
    fn reserved_bindings_use_complete_names_types_and_inclusive_bounds() {
        let fields = binding_fields();
        assert!(binding_fields_match(&fields, b"operator-1"));
        for namespace in [b"operator".as_slice(), b"operator-1-suffix", b"Operator-1", b""] {
            assert!(!binding_fields_match(&fields, namespace));
        }
        for position in 0..3 {
            let mut missing = fields.clone();
            missing.remove(position);
            assert!(!binding_fields_match(&missing, b"operator-1"));
            let mut wrong_type = fields.clone();
            wrong_type[position].schema = ScalarSchema::Boolean;
            assert!(!binding_fields_match(&wrong_type, b"operator-1"));
            let mut suffix = fields.clone();
            suffix[position].name.extend_from_slice(b"_extra");
            assert!(!binding_fields_match(&suffix, b"operator-1"));
        }
        for (minimum, maximum) in [(0, 128), (1, 129)] {
            let mut altered = fields.clone();
            altered[1].schema = ScalarSchema::String { minimum, maximum };
            assert!(!binding_fields_match(&altered, b"operator-1"));
        }
        for (minimum, maximum) in [(63, 64), (64, 65)] {
            let mut altered = fields.clone();
            altered[2].schema = ScalarSchema::String { minimum, maximum };
            assert!(!binding_fields_match(&altered, b"operator-1"));
        }
        let mut multiple = fields;
        multiple[0].schema = ScalarSchema::Enum { variants: vec![b"operator-1".to_vec(), b"operator-2".to_vec()] };
        assert!(!binding_fields_match(&multiple, b"operator-1"));
    }
}
