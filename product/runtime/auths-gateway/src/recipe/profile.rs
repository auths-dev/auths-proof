//! JSON-kind/byte adapters for the kernel's complete profile-schema parser.
//! No Auths field, key set, enum, bound or binding rule is selected here.

use super::{FieldSchema, GatewayRecipeError};
use auths_gateway_kernel::field_projection::FieldSpec;
use auths_gateway_kernel::profile_schema::{self, SchemaMember, SchemaValue};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Every original object/array child is retained. The two JSON integer
/// carriers preserve exact integer conversions; non-integer numbers remain
/// unsupported, including floating spellings such as `1.0` and `-0.0`.
fn schema_value(value: &Value) -> SchemaValue {
    match value {
        Value::String(text) => SchemaValue::Text(text.as_bytes().to_vec()),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                SchemaValue::Signed(value)
            } else if let Some(value) = number.as_u64() {
                SchemaValue::Unsigned(value)
            } else {
                SchemaValue::Unsupported
            }
        }
        Value::Array(values) => SchemaValue::Array(schema_array(values)),
        Value::Object(members) => SchemaValue::Object(schema_members(members)),
        Value::Null | Value::Bool(_) => SchemaValue::Unsupported,
    }
}

fn schema_array(values: &[Value]) -> Vec<SchemaValue> {
    let mut output = Vec::new();
    let mut position = 0;
    while position < values.len() {
        output.push(schema_value(&values[position]));
        position += 1;
    }
    output
}

fn schema_members(members: &Map<String, Value>) -> Vec<SchemaMember> {
    let mut output = Vec::new();
    for (name, value) in members {
        output.push(SchemaMember { name: name.as_bytes().to_vec(), value: schema_value(value) });
    }
    output
}

pub(super) fn parse_root(value: &Value) -> Result<Vec<FieldSpec>, GatewayRecipeError> {
    match profile_schema::parse_root(&schema_value(value)) {
        Some(fields) => Ok(fields),
        None => Err(GatewayRecipeError::InvalidProfileLock),
    }
}

/// Native rule lookup is derived from the exact kernel-produced pairs. The
/// kernel has already checked unique ASCII names; UTF-8 conversion is still
/// fallible here so a violated adapter invariant remains a typed refusal.
pub(super) fn rule_fields(fields: &[FieldSpec]) -> Result<BTreeMap<String, FieldSchema>, GatewayRecipeError> {
    let mut output = BTreeMap::new();
    for field in fields {
        let name = match String::from_utf8(field.name.clone()) {
            Ok(name) => name,
            Err(_) => return Err(GatewayRecipeError::InvalidProfileLock),
        };
        if output.insert(name, field.schema.clone()).is_some() {
            return Err(GatewayRecipeError::InvalidProfileLock);
        }
    }
    Ok(output)
}

#[cfg(test)]
pub(super) fn parse_scalar(value: &Value) -> Result<FieldSchema, GatewayRecipeError> {
    profile_schema::parse_scalar(&schema_value(value)).ok_or(GatewayRecipeError::InvalidProfileLock)
}
