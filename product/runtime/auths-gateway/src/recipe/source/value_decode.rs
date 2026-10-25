//! Iterative decoding of the recursive value-expression AST. Serde handles
//! one outer tag/container; recursive children are ordinary JSON data and are
//! assembled by an explicit worklist. This avoids a recursive Deserialize /
//! Visitor trait cycle while retaining the compiler's strict preflight,
//! internally tagged map/sequence grammar and buffered tag identifiers.

use super::ValueExpr;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Clone, Copy)]
enum Kind {
    String,
    Integer,
    Boolean,
    Field,
    Object,
    Array,
    Echo,
}

impl Kind {
    fn named(name: &str) -> Option<Self> {
        match name {
            "string" => Some(Self::String),
            "integer" => Some(Self::Integer),
            "boolean" => Some(Self::Boolean),
            "field" => Some(Self::Field),
            "object" => Some(Self::Object),
            "array" => Some(Self::Array),
            "echo" => Some(Self::Echo),
            _ => None,
        }
    }

    fn indexed(index: u64) -> Option<Self> {
        match index {
            0 => Some(Self::String),
            1 => Some(Self::Integer),
            2 => Some(Self::Boolean),
            3 => Some(Self::Field),
            4 => Some(Self::Object),
            5 => Some(Self::Array),
            6 => Some(Self::Echo),
            _ => None,
        }
    }

    fn accepts_field(self, name: &str) -> bool {
        match self {
            Self::String | Self::Integer | Self::Boolean => name == "value",
            Self::Field => name == "name",
            Self::Object => name == "fields",
            Self::Array => name == "items",
            Self::Echo => false,
        }
    }
}

// Assembly failures are owned, closed values. Display is the sole serde
// diagnostic boundary; internal control flow carries no static string borrow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DecodeError {
    UnexpectedUnitContent,
    InvalidFields,
    MissingField,
    UnknownField,
    InvalidSequenceLength,
    MissingKind,
    InvalidContainer,
    InvalidKind,
    InvalidSignedInteger,
    InvalidFieldType,
    IncompleteObject,
    IncompleteArray,
    IncompleteAssembly,
    MissingExpression,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedUnitContent => formatter.write_str("unexpected value-expression unit content"),
            Self::InvalidFields => formatter.write_str("missing, duplicate or unknown value-expression field"),
            Self::MissingField => formatter.write_str("missing value-expression field"),
            Self::UnknownField => formatter.write_str("unknown value-expression field"),
            Self::InvalidSequenceLength => formatter.write_str("invalid value-expression sequence length"),
            Self::MissingKind => formatter.write_str("missing value-expression kind"),
            Self::InvalidContainer => formatter.write_str("invalid value-expression container"),
            Self::InvalidKind => formatter.write_str("invalid value-expression kind"),
            Self::InvalidSignedInteger => formatter.write_str("invalid signed value-expression integer"),
            Self::InvalidFieldType => formatter.write_str("invalid value-expression field type"),
            Self::IncompleteObject => formatter.write_str("incomplete value-expression object"),
            Self::IncompleteArray => formatter.write_str("incomplete value-expression array"),
            Self::IncompleteAssembly => formatter.write_str("incomplete value-expression assembly"),
            Self::MissingExpression => formatter.write_str("missing value expression"),
        }
    }
}

struct KindVisitor;

impl<'de> Visitor<'de> for KindVisitor {
    type Value = Kind;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a value-expression variant identifier")
    }

    fn visit_str<E: de::Error>(self, name: &str) -> Result<Kind, E> {
        Kind::named(name).ok_or_else(|| E::custom("unknown value-expression kind"))
    }

    fn visit_u64<E: de::Error>(self, index: u64) -> Result<Kind, E> {
        Kind::indexed(index).ok_or_else(|| E::custom("unknown value-expression kind index"))
    }
}

impl<'de> Deserialize<'de> for Kind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Native JSON identifiers require strings. Serde's buffered Content
        // identifiers additionally dispatch u64 indices, as the old derive did.
        deserializer.deserialize_identifier(KindVisitor)
    }
}

enum Payload {
    Map(Vec<(String, Value)>),
    Sequence(Vec<Value>),
}

struct ExprVisitor;

fn map_step<'de, A: MapAccess<'de>>(map: &mut A, kind: &mut Option<Kind>, fields: &mut Vec<(String, Value)>) -> Result<bool, A::Error> {
    let Some(name) = map.next_key::<String>()? else { return Ok(false); };
    if name == "kind" {
        if kind.is_some() {
            return Err(de::Error::duplicate_field("kind"));
        }
        *kind = Some(map.next_value::<Kind>()?);
    } else {
        fields.push((name, map.next_value::<Value>()?));
    }
    Ok(true)
}

fn sequence_step<'de, A: SeqAccess<'de>>(sequence: &mut A, fields: &mut Vec<Value>) -> Result<bool, A::Error> {
    match sequence.next_element::<Value>()? {
        Some(value) => { fields.push(value); Ok(true) }
        None => Ok(false),
    }
}

impl<'de> Visitor<'de> for ExprVisitor {
    type Value = ValueExpr;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an internally tagged value expression")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ValueExpr, A::Error> {
        let mut kind = None;
        let mut fields = Vec::new();
        let mut progress = Ok(true);
        while matches!(progress, Ok(true)) {
            progress = map_step(&mut map, &mut kind, &mut fields);
        }
        progress?;
        let kind = kind.ok_or_else(|| <A::Error as de::Error>::missing_field("kind"))?;
        match decode(kind, Payload::Map(fields)) {
            Ok(value) => Ok(value),
            Err(error) => Err(de::Error::custom(error)),
        }
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<ValueExpr, A::Error> {
        let kind = sequence.next_element::<Kind>()?.ok_or_else(|| <A::Error as de::Error>::missing_field("kind"))?;
        let mut fields = Vec::new();
        let mut progress = Ok(true);
        while matches!(progress, Ok(true)) {
            progress = sequence_step(&mut sequence, &mut fields);
        }
        progress?;
        match decode(kind, Payload::Sequence(fields)) {
            Ok(value) => Ok(value),
            Err(error) => Err(de::Error::custom(error)),
        }
    }
}

impl<'de> Deserialize<'de> for ValueExpr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ExprVisitor)
    }
}

fn payload(kind: Kind, fields: Payload) -> Result<Option<Value>, DecodeError> {
    if matches!(kind, Kind::Echo) {
        // Internally tagged unit variants ignore map content; a positional
        // unit variant still requires an empty remaining sequence.
        return match fields {
            Payload::Map(_) => Ok(None),
            Payload::Sequence(values) if values.is_empty() => Ok(None),
            Payload::Sequence(_) => Err(DecodeError::UnexpectedUnitContent),
        };
    }
    match fields {
        Payload::Map(mut values) => {
            if values.len() != 1 {
                return Err(DecodeError::InvalidFields);
            }
            let Some((name, value)) = values.pop() else {
                return Err(DecodeError::MissingField);
            };
            if !kind.accepts_field(&name) {
                return Err(DecodeError::UnknownField);
            }
            Ok(Some(value))
        }
        Payload::Sequence(mut values) => {
            if values.len() != 1 {
                return Err(DecodeError::InvalidSequenceLength);
            }
            values.pop().map(Some).ok_or(DecodeError::MissingField)
        }
    }
}

fn buffered_tag(tag: Value, fields: Payload) -> Result<(Kind, Payload), DecodeError> {
    let kind = match tag {
        Value::String(name) => Kind::named(&name),
        Value::Number(number) => match number.as_u64() {
            Some(index) => Kind::indexed(index),
            None => None,
        },
        _ => None,
    }.ok_or(DecodeError::InvalidKind)?;
    Ok((kind, fields))
}

fn buffered_map(mut values: serde_json::Map<String, Value>) -> Result<(Kind, Payload), DecodeError> {
    let tag = values.remove("kind").ok_or(DecodeError::MissingKind)?;
    let mut fields = Vec::new();
    for member in values { fields.push(member); }
    buffered_tag(tag, Payload::Map(fields))
}

fn buffered_sequence(values: Vec<Value>) -> Result<(Kind, Payload), DecodeError> {
    let mut values = values.into_iter();
    let tag = values.next().ok_or(DecodeError::MissingKind)?;
    let mut fields = Vec::new();
    for value in values { fields.push(value); }
    buffered_tag(tag, Payload::Sequence(fields))
}

fn buffered(value: Value) -> Result<(Kind, Payload), DecodeError> {
    match value {
        Value::Object(values) => buffered_map(values),
        Value::Array(values) => buffered_sequence(values),
        _ => Err(DecodeError::InvalidContainer),
    }
}

enum Work {
    Node(Kind, Payload),
    Child(Value),
    Object(Vec<String>),
    Array(usize),
}

// Consume both original sequences from the same end, retaining each exact
// name/child association. BTreeMap supplies the final key order. A mismatch
// refuses before an object is published; no truncating iterator is involved.
fn object_pair_step(names: &mut Vec<String>, children: &mut Vec<ValueExpr>,
    fields: &mut BTreeMap<String, ValueExpr>) -> Result<bool, DecodeError> {
    match (names.pop(), children.pop()) {
        (None, None) => Ok(false),
        (Some(name), Some(child)) => { fields.insert(name, child); Ok(true) },
        _ => Err(DecodeError::IncompleteObject),
    }
}

fn decode_step(work: Work, pending: &mut Vec<Work>, completed: &mut Vec<ValueExpr>) -> Result<(), DecodeError> {
        match work {
            Work::Child(value) => {
                let (kind, fields) = buffered(value)?;
                pending.push(Work::Node(kind, fields));
            }
            Work::Node(kind, fields) => match (kind, payload(kind, fields)?) {
                (Kind::String, Some(Value::String(value))) => completed.push(ValueExpr::String { value }),
                (Kind::Integer, Some(Value::Number(value))) => {
                    let value = value.as_i64().ok_or(DecodeError::InvalidSignedInteger)?;
                    completed.push(ValueExpr::Integer { value });
                }
                (Kind::Boolean, Some(Value::Bool(value))) => completed.push(ValueExpr::Boolean { value }),
                (Kind::Field, Some(Value::String(name))) => completed.push(ValueExpr::Field { name }),
                (Kind::Echo, None) => completed.push(ValueExpr::Echo),
                (Kind::Object, Some(Value::Object(fields))) => {
                    let mut names = Vec::new();
                    let mut children = Vec::new();
                    for (name, child) in fields {
                        names.push(name);
                        children.push(child);
                    }
                    pending.push(Work::Object(names));
                    let mut next = children.pop();
                    while let Some(child) = next {
                        pending.push(Work::Child(child));
                        next = children.pop();
                    }
                }
                (Kind::Array, Some(Value::Array(mut items))) => {
                    pending.push(Work::Array(items.len()));
                    let mut next = items.pop();
                    while let Some(child) = next {
                        pending.push(Work::Child(child));
                        next = items.pop();
                    }
                }
                _ => return Err(DecodeError::InvalidFieldType),
            },
            Work::Object(mut names) => {
                let start = completed.len().checked_sub(names.len()).ok_or(DecodeError::IncompleteObject)?;
                let mut children = completed.split_off(start);
                let mut fields = BTreeMap::new();
                // checked_sub/split_off earn equal complete lengths; the
                // closed step also refuses any mismatch before publication.
                let mut progress = Ok(true);
                while matches!(progress, Ok(true)) {
                    progress = object_pair_step(&mut names, &mut children, &mut fields);
                }
                progress?;
                completed.push(ValueExpr::Object { fields });
            }
            Work::Array(count) => {
                let start = completed.len().checked_sub(count).ok_or(DecodeError::IncompleteArray)?;
                let items = completed.split_off(start);
                completed.push(ValueExpr::Array { items });
            }
        }
    Ok(())
}

fn decode(kind: Kind, fields: Payload) -> Result<ValueExpr, DecodeError> {
    let mut pending = Vec::new();
    pending.push(Work::Node(kind, fields));
    let mut completed = Vec::new();
    let mut next = pending.pop();
    let mut result = Ok(());
    while let Some(work) = next {
        result = decode_step(work, &mut pending, &mut completed);
        next = if result.is_ok() { pending.pop() } else { None };
    }
    result?;
    if completed.len() != 1 {
        return Err(DecodeError::IncompleteAssembly);
    }
    completed.pop().ok_or(DecodeError::MissingExpression)
}

#[cfg(test)]
mod tests;
