//! Bounded emission of the existing decoded recipe body AST into named
//! templates. This internal byte view has no serialization, parser, callback,
//! provider tag or new recipe capability. Native JSON/String decoding and
//! approved-source digest provenance remain explicit outer contracts.

use alloc::vec::Vec;
use crate::body_compiler::{self, NamedFormPiece, NamedJsonPiece, ResourceUse};
use crate::construct::{append_form_encoded, append_json_string, copy_bytes, field_name_equal};
use crate::identity::valid_token;
use crate::request_compiler::NamedBody;
use crate::scalars::{self, MAX_JSON_INTEGER};
use crate::template_members::{self, EchoTarget, MemberChoice, MemberDomain, MemberError, NamedKey};

/// The source language's shared recursive JSON-node budget.
pub const MAX_NODES: usize = 64;
/// Maximum zero-based JSON source depth.
pub const MAX_DEPTH: usize = 6;
/// Maximum bytes in a source string literal before escaping.
pub const MAX_LITERAL_BYTES: usize = 1024;

/// Complete existing JSON source vocabulary, retaining original field names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    /// UTF-8 bytes supplied by native String decoding; arbitrary byte views
    /// have exact escaping semantics but do not independently earn UTF-8.
    String(Vec<u8>),
    /// Exact signed source integer; safe-JSON bounds are checked on emission.
    Integer(i64),
    /// Exact source boolean.
    Boolean(bool),
    /// Original profile field name, before any positional lowering.
    Field(Vec<u8>),
    /// Source members in their original canonical byte-key order.
    Object(Vec<JsonMember>),
    /// Source elements in their original order.
    Array(Vec<Value>),
    /// Author-supplied echo nodes always refuse.
    AuthorEcho,
}

/// A source key and its exact child stay in one record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonMember {
    /// Original decoded source key bytes.
    pub name: Vec<u8>,
    /// Exact child associated with those bytes.
    pub value: Value,
}

/// Complete existing form source vocabulary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FormValue {
    /// A literal form value, escaped once during compilation.
    String(Vec<u8>),
    /// A named profile field, escaped once by the outbound writer.
    Field(Vec<u8>),
    /// A nested JSON value, rendered then form-escaped once by the writer.
    Json(Value),
    /// Author-supplied echo nodes always refuse.
    AuthorEcho,
}

/// A source form key and its exact value stay in one record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FormMember {
    /// Original decoded source form key bytes.
    pub name: Vec<u8>,
    /// Exact value associated with those bytes.
    pub value: FormValue,
}

/// The existing JSON/form source choice without a new wire representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Body {
    /// One complete recursive JSON source.
    Json(Value),
    /// One complete canonically ordered source form.
    Form(Vec<FormMember>),
}

/// Compiler-owned placement copied from the separately approved source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Echo {
    /// Decoded, slash-separated original JSON pointer tokens.
    Json(Vec<Vec<u8>>),
    /// Original form key, including the existing single-bracket form.
    Form(Vec<u8>),
}

/// A fully emitted named template consumed by the existing positional compiler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NamedTemplate {
    /// Canonical JSON syntax/literals, original field names and owned echo.
    Json(Vec<NamedJsonPiece>),
    /// Canonical form syntax/literals, named values and nested named JSON.
    Form(Vec<NamedFormPiece>),
}

impl NamedTemplate {
    /// Borrows the actual completed template for the whole write compiler.
    #[must_use]
    pub fn source(&self) -> NamedBody<'_> {
        match self {
            Self::Json(pieces) => NamedBody::Json(pieces),
            Self::Form(pieces) => NamedBody::Form(pieces),
        }
    }
}

/// Typed source/emission failures; no partial template escapes an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemplateError {
    /// Invalid count, depth, literal, integer, key or field reference grammar.
    Shape,
    /// Invalid placement, missing parent, collision or author-created echo.
    EchoConflict,
    /// Aggregate emitted piece/literal/dynamic budget exhausted.
    Resources,
}

// Copy results keep their enum initialized through cleanup. Owned vectors
// are moved out through an explicit empty replacement, without cloning the
// growing emission buffer or introducing Try/FromResidual models.
macro_rules! take {
    ($value:expr) => {{
        let result = $value;
        match &result { Ok(value) => *value, Err(error) => return Err(*error) }
    }};
}

macro_rules! take_vec {
    ($value:expr) => {{
        let mut result = $value;
        match &mut result {
            Ok(value) => {
                #[allow(clippy::mem_replace_with_default, reason = "explicit Vec replacement keeps the translated result initialized")]
                let output = core::mem::replace(value, Vec::new());
                output
            }
            Err(error) => return Err(*error),
        }
    }};
}

macro_rules! take_member {
    ($value:expr) => {{
        let result = $value;
        match &result { Ok(value) => *value, Err(error) => return Err(member_error(*error)) }
    }};
}

macro_rules! take_member_vec {
    ($value:expr) => {{
        let mut result = $value;
        match &mut result {
            Ok(value) => {
                #[allow(clippy::mem_replace_with_default, reason = "explicit Vec replacement keeps the translated result initialized")]
                let output = core::mem::replace(value, Vec::new());
                output
            }
            Err(error) => return Err(member_error(*error)),
        }
    }};
}

fn member_error(error: MemberError) -> TemplateError {
    match error {
        MemberError::Members => TemplateError::Shape,
        MemberError::EchoConflict => TemplateError::EchoConflict,
    }
}

/// Charges one JSON node before inspecting or traversing its children.
///
/// # Errors
/// Refuses exhausted/invalid counters and excessive depth before addition.
pub fn charge_node(nodes: usize, depth: usize) -> Result<usize, TemplateError> {
    if nodes >= MAX_NODES || depth > MAX_DEPTH {
        return Err(TemplateError::Shape);
    }
    Ok(nodes + 1)
}

/// Body references cannot render the installed namespace or recipe digest.
/// Logical operation IDs retain their existing allowed rendering behavior.
#[must_use]
pub fn rendered_field_allowed(name: &[u8]) -> bool {
    valid_token(name, 64)
        && !field_name_equal(name, b"operator_namespace")
        && !field_name_equal(name, b"recipe_digest")
}

struct JsonBuild {
    nodes: usize,
    resources: ResourceUse,
    pieces: Vec<NamedJsonPiece>,
}

struct FormBuild {
    nodes: usize,
    resources: ResourceUse,
    pieces: Vec<NamedFormPiece>,
}

fn json_start(nodes: usize) -> JsonBuild {
    JsonBuild { nodes, resources: ResourceUse { literal_bytes: 0, dynamic_pieces: 0 }, pieces: Vec::new() }
}

fn form_start() -> FormBuild {
    FormBuild { nodes: 0, resources: ResourceUse { literal_bytes: 0, dynamic_pieces: 0 }, pieces: Vec::new() }
}

fn json_finish(output: &mut JsonBuild) -> Vec<NamedJsonPiece> {
    #[allow(clippy::mem_replace_with_default, reason = "explicit Vec replacement preserves initialized translated builder state")]
    let pieces = core::mem::replace(&mut output.pieces, Vec::new());
    pieces
}

fn form_finish(output: &mut FormBuild) -> Vec<NamedFormPiece> {
    #[allow(clippy::mem_replace_with_default, reason = "explicit Vec replacement preserves initialized translated builder state")]
    let pieces = core::mem::replace(&mut output.pieces, Vec::new());
    pieces
}

fn json_push(output: &mut JsonBuild, piece: NamedJsonPiece) -> Result<(), TemplateError> {
    if output.pieces.len() >= body_compiler::MAX_TEMPLATE_PIECES {
        return Err(TemplateError::Resources);
    }
    let (literals, dynamics) = match &piece {
        NamedJsonPiece::Raw(bytes) => (bytes.len(), 0),
        NamedJsonPiece::Field(_) | NamedJsonPiece::Echo => (0, 1),
    };
    output.resources = match body_compiler::add_resources(output.resources, literals, dynamics) {
        Some(next) => next,
        None => return Err(TemplateError::Resources),
    };
    output.pieces.push(piece);
    Ok(())
}

fn form_push(output: &mut FormBuild, piece: NamedFormPiece) -> Result<(), TemplateError> {
    if output.pieces.len() >= body_compiler::MAX_TEMPLATE_PIECES {
        return Err(TemplateError::Resources);
    }
    output.resources = match body_compiler::form_piece_resources(output.resources, &piece) {
        Some(next) => next,
        None => return Err(TemplateError::Resources),
    };
    output.pieces.push(piece);
    Ok(())
}

fn json_keys(fields: &[JsonMember]) -> Result<Vec<NamedKey>, TemplateError> {
    if fields.is_empty() || fields.len() > 32 {
        return Err(TemplateError::Shape);
    }
    for field in fields {
        if !valid_token(&field.name, 64) {
            return Err(TemplateError::Shape);
        }
    }
    Ok(json_key_column(fields))
}

// The checked caller bounds both count and each name before any key copy.
fn json_key_column(fields: &[JsonMember]) -> Vec<NamedKey> {
    let mut keys = Vec::new();
    for field in fields {
        keys.push(NamedKey { name: copy_bytes(&field.name) });
    }
    keys
}

fn form_keys(fields: &[FormMember]) -> Result<Vec<NamedKey>, TemplateError> {
    if fields.is_empty() || fields.len() > 16 {
        return Err(TemplateError::Shape);
    }
    for field in fields {
        if !valid_token(&field.name, 64) {
            return Err(TemplateError::Shape);
        }
    }
    Ok(form_key_column(fields))
}

fn form_key_column(fields: &[FormMember]) -> Vec<NamedKey> {
    let mut keys = Vec::new();
    for field in fields {
        keys.push(NamedKey { name: copy_bytes(&field.name) });
    }
    keys
}

fn json_prefix(name: &[u8], comma: bool) -> Vec<u8> {
    let output = if comma { copy_bytes(b",") } else { Vec::new() };
    let mut output = append_json_string(output, name);
    output.push(b':');
    output
}

fn form_prefix(name: &[u8], separator: bool) -> Vec<u8> {
    let output = if separator { copy_bytes(b"&") } else { Vec::new() };
    let mut output = append_form_encoded(output, name);
    output.push(b'=');
    output
}

fn json_value(value: &Value, echo: Option<&[Vec<u8>]>, depth: usize, output: &mut JsonBuild) -> Result<(), TemplateError> {
    output.nodes = take!(charge_node(output.nodes, depth));
    if echo.is_some() && !matches!(value, Value::Object(_)) {
        return Err(TemplateError::EchoConflict);
    }
    match value {
        Value::String(value) => {
            if value.len() > MAX_LITERAL_BYTES { return Err(TemplateError::Shape); }
            json_push(output, NamedJsonPiece::Raw(append_json_string(Vec::new(), value)))
        }
        Value::Integer(value) => {
            if !scalars::integer_value_valid(-MAX_JSON_INTEGER, MAX_JSON_INTEGER, *value) {
                return Err(TemplateError::Shape);
            }
            json_push(output, NamedJsonPiece::Raw(scalars::integer_bytes(*value)))
        }
        Value::Boolean(value) => json_push(output, NamedJsonPiece::Raw(copy_bytes(if *value { b"true" } else { b"false" }))),
        Value::Field(name) => {
            if !rendered_field_allowed(name) { return Err(TemplateError::Shape); }
            json_push(output, NamedJsonPiece::Field(copy_bytes(name)))
        }
        Value::AuthorEcho => Err(TemplateError::EchoConflict),
        Value::Array(items) => json_array(items, depth, output),
        Value::Object(fields) => json_object(fields, echo, depth, output),
    }
}

// Each recursive child charges its node against this same emission buffer.
fn json_array(items: &[Value], depth: usize, output: &mut JsonBuild) -> Result<(), TemplateError> {
    if items.is_empty() || items.len() > 16 { return Err(TemplateError::Shape); }
    take!(json_push(output, NamedJsonPiece::Raw(copy_bytes(b"["))));
    let mut position = 0;
    while position < items.len() {
        take!(json_array_item(&items[position], depth, position, output));
        position += 1;
    }
    json_push(output, NamedJsonPiece::Raw(copy_bytes(b"]")))
}

fn json_array_item(value: &Value, depth: usize, position: usize, output: &mut JsonBuild) -> Result<(), TemplateError> {
    if position > 0 { take!(json_push(output, NamedJsonPiece::Raw(copy_bytes(b",")))); }
    json_value(value, None, depth + 1, output)
}

fn json_object(fields: &[JsonMember], echo: Option<&[Vec<u8>]>, depth: usize, output: &mut JsonBuild) -> Result<(), TemplateError> {
    let keys = take_vec!(json_keys(fields));
    let target = take!(json_target(&keys, echo));
    let insertion = take!(json_insertion(target, echo));
    let order = take_member_vec!(template_members::canonical_members(&keys, insertion, MemberDomain::Json));
    take!(json_push(output, NamedJsonPiece::Raw(copy_bytes(b"{"))));
    take!(json_members(fields, &order, target, echo, insertion, depth, output));
    json_push(output, NamedJsonPiece::Raw(copy_bytes(b"}")))
}

fn json_members(fields: &[JsonMember], order: &[MemberChoice], target: Option<EchoTarget>, echo: Option<&[Vec<u8>]>, insertion: Option<&[u8]>, depth: usize, output: &mut JsonBuild) -> Result<(), TemplateError> {
    let mut position = 0;
    while position < order.len() {
        take!(json_member(fields, order[position], target, echo, insertion, depth, position, output));
        position += 1;
    }
    Ok(())
}

fn json_target(keys: &[NamedKey], echo: Option<&[Vec<u8>]>) -> Result<Option<EchoTarget>, TemplateError> {
    match echo {
        Some(tokens) => Ok(Some(take_member!(template_members::json_echo_target(keys, tokens)))),
        None => Ok(None),
    }
}

fn json_insertion(target: Option<EchoTarget>, echo: Option<&[Vec<u8>]>) -> Result<Option<&[u8]>, TemplateError> {
    match (target, echo) {
        (Some(EchoTarget::Insert), Some(tokens)) => {
            if tokens.is_empty() { return Err(TemplateError::EchoConflict); }
            Ok(Some(tokens[0].as_slice()))
        }
        (Some(EchoTarget::Insert), None) => Err(TemplateError::EchoConflict),
        _ => Ok(None),
    }
}

fn json_child_echo(target: Option<EchoTarget>, echo: Option<&[Vec<u8>]>, index: usize) -> Result<Option<&[Vec<u8>]>, TemplateError> {
    match (target, echo) {
        (Some(EchoTarget::Descend(selected)), Some(tokens)) if selected == index => match tokens.get(1..) {
            Some(rest) => Ok(Some(rest)),
            None => Err(TemplateError::EchoConflict),
        },
        _ => Ok(None),
    }
}

fn json_member(fields: &[JsonMember], choice: MemberChoice, target: Option<EchoTarget>, echo: Option<&[Vec<u8>]>, insertion: Option<&[u8]>, depth: usize, position: usize, output: &mut JsonBuild) -> Result<(), TemplateError> {
    match choice {
        MemberChoice::Source(index) => {
            let member = match fields.get(index) { Some(member) => member, None => return Err(TemplateError::Shape) };
            take!(json_push(output, NamedJsonPiece::Raw(json_prefix(&member.name, position > 0))));
            let nested = take!(json_child_echo(target, echo, index));
            json_value(&member.value, nested, depth + 1, output)
        }
        MemberChoice::Echo => {
            let name = match insertion { Some(name) => name, None => return Err(TemplateError::EchoConflict) };
            take!(json_push(output, NamedJsonPiece::Raw(json_prefix(name, position > 0))));
            json_push(output, NamedJsonPiece::Echo)
        }
    }
}

fn form_json_allowed(value: &Value) -> bool {
    match value { Value::Array(items) => items.len() == 1, _ => true }
}

fn form_value(value: &FormValue, output: &mut FormBuild) -> Result<(), TemplateError> {
    match value {
        FormValue::String(value) => {
            if value.len() > MAX_LITERAL_BYTES { return Err(TemplateError::Shape); }
            form_push(output, NamedFormPiece::Raw(append_form_encoded(Vec::new(), value)))
        }
        FormValue::Field(name) => {
            if !rendered_field_allowed(name) { return Err(TemplateError::Shape); }
            form_push(output, NamedFormPiece::Field(copy_bytes(name)))
        }
        FormValue::Json(value) => {
            if !form_json_allowed(value) { return Err(TemplateError::Shape); }
            let mut nested = json_start(output.nodes);
            take!(json_value(value, None, 0, &mut nested));
            output.nodes = nested.nodes;
            form_push(output, NamedFormPiece::Json(json_finish(&mut nested)))
        }
        FormValue::AuthorEcho => Err(TemplateError::EchoConflict),
    }
}

fn form_member(fields: &[FormMember], choice: MemberChoice, insertion: Option<&[u8]>, position: usize, output: &mut FormBuild) -> Result<(), TemplateError> {
    match choice {
        MemberChoice::Source(index) => {
            let member = match fields.get(index) { Some(member) => member, None => return Err(TemplateError::Shape) };
            take!(form_push(output, NamedFormPiece::Raw(form_prefix(&member.name, position > 0))));
            form_value(&member.value, output)
        }
        MemberChoice::Echo => {
            let name = match insertion { Some(name) => name, None => return Err(TemplateError::EchoConflict) };
            take!(form_push(output, NamedFormPiece::Raw(form_prefix(name, position > 0))));
            form_push(output, NamedFormPiece::Echo)
        }
    }
}

fn form_members(fields: &[FormMember], order: &[MemberChoice], insertion: Option<&[u8]>, output: &mut FormBuild) -> Result<(), TemplateError> {
    let mut position = 0;
    while position < order.len() {
        take!(form_member(fields, order[position], insertion, position, output));
        position += 1;
    }
    Ok(())
}

/// Emits the complete decoded source body without resolving profile names.
/// Each recursive JSON node shares one 64-node budget, including nested form
/// values. Every piece charges the existing aggregate resource envelope.
/// The mutable emission buffer stays local and no partial template escapes.
///
/// # Errors
/// Refuses invalid AST shape/literals/names/integers, excessive nodes/depth,
/// conflicting echo placement, or aggregate emission resources. Native JSON,
/// profile/approval validation and execution authority remain outer obligations.
pub fn compile_body(body: &Body, echo: Option<&Echo>) -> Result<NamedTemplate, TemplateError> {
    match body {
        Body::Json(value) => {
            let tokens = match echo {
                Some(Echo::Json(tokens)) => Some(tokens.as_slice()),
                Some(Echo::Form(_)) => return Err(TemplateError::EchoConflict),
                None => None,
            };
            let mut output = json_start(0);
            take!(json_value(value, tokens, 0, &mut output));
            Ok(NamedTemplate::Json(json_finish(&mut output)))
        }
        Body::Form(fields) => {
            // Preserve count-before-echo-kind error precedence, then check
            // names before allocating the owned key column.
            if fields.is_empty() || fields.len() > 16 { return Err(TemplateError::Shape); }
            let insertion = match echo {
                Some(Echo::Form(name)) => Some(name.as_slice()),
                Some(Echo::Json(_)) => return Err(TemplateError::EchoConflict),
                None => None,
            };
            let keys = take_vec!(form_keys(fields));
            let order = take_member_vec!(template_members::canonical_members(&keys, insertion, MemberDomain::Form));
            let mut output = form_start();
            take!(form_members(fields, &order, insertion, &mut output));
            Ok(NamedTemplate::Form(form_finish(&mut output)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use crate::body_compiler::{lower_form, lower_json};
    use crate::construct::{BodyPlan, build_body};
    use crate::field_projection::{FieldSpec, NamedInput, field_names, project_object};
    use crate::scalars::{ScalarInput, ScalarSchema};

    fn json_member(name: &[u8], value: Value) -> JsonMember {
        JsonMember { name: name.to_vec(), value }
    }

    #[test]
    fn complete_ast_request_keeps_reserved_bindings_operation_and_original_field_names() {
        use crate::construct::{ConstructError, Header, RequestMethod, construct_write};
        use crate::derived_tokens::{echo_token_bytes, idempotency_token_bytes};
        use crate::field_projection::{RequestBindingError, project_request};
        use crate::path_compiler::NamedSegment;
        use crate::request_compiler::{WriteSource, compile_write};

        let body = Body::Json(Value::Object(vec![
            json_member(b"invoice", Value::Field(b"invoice".to_vec())),
            json_member(b"operation", Value::Field(b"operation_id".to_vec())),
        ]));
        let placement = Echo::Json(vec![b"auths".to_vec()]);
        let template = compile_body(&body, Some(&placement)).unwrap();
        // Field order, body-key order and supplied-object order deliberately
        // differ, and a similarly named operation carries a different value.
        let fields = [
            FieldSpec { name: b"operation_id_extra".to_vec(), schema: ScalarSchema::String { minimum: 1, maximum: 64 } },
            FieldSpec { name: b"operation_id".to_vec(), schema: ScalarSchema::String { minimum: 1, maximum: 128 } },
            FieldSpec { name: b"invoice".to_vec(), schema: ScalarSchema::String { minimum: 1, maximum: 64 } },
            FieldSpec { name: b"operator_namespace".to_vec(), schema: ScalarSchema::String { minimum: 1, maximum: 64 } },
            FieldSpec { name: b"recipe_digest".to_vec(), schema: ScalarSchema::String { minimum: 64, maximum: 64 } },
        ];
        let path = [NamedSegment::Fixed(b"v1".to_vec()), NamedSegment::Fixed(b"invoices".to_vec()), NamedSegment::Field(b"invoice".to_vec())];
        let source = WriteSource {
            method: RequestMethod::Post,
            origin: b"https://api.example.com",
            parsed_host: b"api.example.com",
            path: &path,
            versions: None,
            scope: None,
            idempotency_header: true,
            body: template.source(),
        };
        let compiled = compile_write(&fields, source).unwrap();
        let recipe = [b'0'; 64];
        let supplied = [
            NamedInput { name: b"invoice", value: ScalarInput::Text(b"in_demo") },
            NamedInput { name: b"recipe_digest", value: ScalarInput::Text(&recipe) },
            NamedInput { name: b"operation_id_extra", value: ScalarInput::Text(b"wrong-operation") },
            NamedInput { name: b"operator_namespace", value: ScalarInput::Text(b"operator-demo") },
            NamedInput { name: b"operation_id", value: ScalarInput::Text(b"op-17") },
        ];
        let accepted = project_request(&fields, &supplied, b"operator-demo", &recipe).unwrap();
        assert_eq!(accepted.operation_id, b"op-17");
        let echo = echo_token_bytes(&[0; 32]);
        let key = idempotency_token_bytes(&[255; 32]);
        let request = construct_write(&compiled.plan, &accepted.values, &echo, &key).unwrap();
        let mut expected_body = b"{\"auths\":\"auths-e1-".to_vec();
        expected_body.extend_from_slice(&[b'0'; 64]);
        expected_body.extend_from_slice(b"\",\"invoice\":\"in_demo\",\"operation\":\"op-17\"}");
        let mut expected_key = b"auths-i1-".to_vec();
        expected_key.extend_from_slice(&[b'f'; 64]);
        assert_eq!(request.method, RequestMethod::Post);
        assert_eq!(request.url, b"https://api.example.com/v1/invoices/in_demo");
        assert_eq!(request.body, expected_body);
        assert_eq!(request.headers, vec![Header { name: b"Idempotency-Key".to_vec(), value: expected_key }]);

        assert_eq!(project_request(&fields, &supplied, b"other-operator", &recipe), Err(RequestBindingError::ActionMismatch));
        assert_eq!(project_request(&fields, &supplied, b"operator-demo", &[b'1'; 64]), Err(RequestBindingError::ActionMismatch));
        let mut duplicate = supplied;
        duplicate[2] = supplied[4];
        assert_eq!(project_request(&fields, &duplicate, b"operator-demo", &recipe),
            Err(RequestBindingError::Projection(ConstructError::ArgumentMismatch)));
        let mut invalid_operation = supplied;
        invalid_operation[4].value = ScalarInput::Text(b"/invalid");
        assert_eq!(project_request(&fields, &invalid_operation, b"operator-demo", &recipe), Err(RequestBindingError::OperationId));
    }

    #[test]
    fn complete_ast_emission_and_projection_keep_named_values_literals_and_echo() {
        let source = Body::Json(Value::Object(vec![
            json_member(b"a", Value::String("x/é\n\0".as_bytes().to_vec())),
            json_member(b"b", Value::Array(vec![Value::Field(b"second".to_vec()), Value::Integer(-17)])),
            json_member(b"c", Value::Field(b"first".to_vec())),
        ]));
        let echo = Echo::Json(vec![b"echo".to_vec()]);
        let template = compile_body(&source, Some(&echo)).unwrap();
        let NamedTemplate::Json(pieces) = template else { panic!("JSON template"); };
        let fields = [
            FieldSpec { name: b"first".to_vec(), schema: ScalarSchema::String { minimum: 0, maximum: 64 } },
            FieldSpec { name: b"second".to_vec(), schema: ScalarSchema::Boolean },
        ];
        let names = field_names(&fields).unwrap();
        let values = project_object(&fields, &[
            NamedInput { name: b"second", value: ScalarInput::Boolean(true) },
            NamedInput { name: b"first", value: ScalarInput::Text("field\"\\/é".as_bytes()) },
        ]).unwrap();
        let plan = BodyPlan::Json(lower_json(&names, &pieces).unwrap());
        assert_eq!(build_body(&plan, &values, b"echo+token"), Ok(
            r#"{"a":"x/é\n\u0000","b":[true,-17],"c":"field\"\\/é","echo":"echo+token"}"#.as_bytes().to_vec()
        ));
        let source = Body::Form(vec![
            FormMember { name: b"a".to_vec(), value: FormValue::Json(Value::Array(vec![Value::Field(b"second".to_vec())])) },
            FormMember { name: b"z".to_vec(), value: FormValue::String("a&b=é +%".as_bytes().to_vec()) },
        ]);
        let echo = Echo::Form(b"metadata[auths_echo]".to_vec());
        let NamedTemplate::Form(pieces) = compile_body(&source, Some(&echo)).unwrap() else { panic!("form template"); };
        let plan = BodyPlan::Form(lower_form(&names, &pieces).unwrap());
        assert_eq!(build_body(&plan, &values, b"echo+token"), Ok(
            b"a=%5Btrue%5D&metadata%5Bauths_echo%5D=echo%2Btoken&z=a%26b%3D%C3%A9+%2B%25".to_vec()
        ));
    }

    fn object_with_leaves(count: u8) -> Value {
        Value::Object((0..count).map(|index| json_member(
            &[b'a', b'0' + index / 10, b'0' + index % 10], Value::Integer(1),
        )).collect())
    }

    #[test]
    fn form_json_values_share_one_actual_node_budget() {
        let fields = |count| Body::Form(vec![
            FormMember { name: b"a".to_vec(), value: FormValue::Json(object_with_leaves(count)) },
            FormMember { name: b"b".to_vec(), value: FormValue::Json(object_with_leaves(count)) },
        ]);
        assert!(compile_body(&fields(31), None).is_ok(), "two 32-node objects fit exactly");
        assert_eq!(compile_body(&fields(32), None), Err(TemplateError::Shape), "two 33-node objects cannot reset the budget");
        let mut json = Value::Boolean(true);
        for _ in 0..6 { json = Value::Array(vec![json]); }
        assert!(compile_body(&Body::Json(json.clone()), None).is_ok());
        assert_eq!(compile_body(&Body::Json(Value::Array(vec![json])), None), Err(TemplateError::Shape));
        assert_eq!(charge_node(63, 6), Ok(64));
        for nodes in [64, 65, usize::MAX] { assert_eq!(charge_node(nodes, 0), Err(TemplateError::Shape)); }
        assert_eq!(charge_node(0, usize::MAX), Err(TemplateError::Shape));
    }

    #[test]
    fn raw_ast_shape_reserved_names_and_echo_cannot_bypass_source_guards() {
        for value in [-MAX_JSON_INTEGER, 0, MAX_JSON_INTEGER] {
            assert!(compile_body(&Body::Json(Value::Integer(value)), None).is_ok());
        }
        for value in [i64::MIN, -MAX_JSON_INTEGER - 1, MAX_JSON_INTEGER + 1, i64::MAX] {
            assert_eq!(compile_body(&Body::Json(Value::Integer(value)), None), Err(TemplateError::Shape));
        }
        assert!(compile_body(&Body::Json(Value::String(vec![b'x'; 1024])), None).is_ok());
        assert_eq!(compile_body(&Body::Json(Value::String(vec![b'x'; 1025])), None), Err(TemplateError::Shape));
        for name in [b"operator_namespace".as_slice(), b"recipe_digest", b"_invalid", b"a\0"] {
            assert_eq!(compile_body(&Body::Json(Value::Field(name.to_vec())), None), Err(TemplateError::Shape));
        }
        assert!(compile_body(&Body::Json(Value::Field(b"operation_id".to_vec())), None).is_ok());
        for value in [Value::Object(vec![]), Value::Array(vec![]), Value::Object(vec![
            json_member(b"b", Value::Boolean(true)), json_member(b"a", Value::Boolean(false)),
        ])] {
            assert_eq!(compile_body(&Body::Json(value), None), Err(TemplateError::Shape));
        }
        assert_eq!(compile_body(&Body::Json(Value::AuthorEcho), None), Err(TemplateError::EchoConflict));
        let scalar_parent = Body::Json(Value::Object(vec![json_member(b"a", Value::String(b"scalar".to_vec()))]));
        assert_eq!(compile_body(&scalar_parent, Some(&Echo::Json(vec![b"a".to_vec(), b"echo".to_vec()]))), Err(TemplateError::EchoConflict));
        assert_eq!(compile_body(&scalar_parent, Some(&Echo::Json(vec![b"a".to_vec()]))), Err(TemplateError::EchoConflict));
        assert_eq!(compile_body(&scalar_parent, Some(&Echo::Form(b"echo".to_vec()))), Err(TemplateError::EchoConflict));
    }

    #[test]
    fn every_actual_piece_push_checks_aggregate_resources_before_mutation() {
        let mut invalid = JsonBuild { nodes: 0, resources: ResourceUse { literal_bytes: usize::MAX, dynamic_pieces: 0 }, pieces: Vec::new() };
        assert_eq!(json_push(&mut invalid, NamedJsonPiece::Raw(Vec::new())), Err(TemplateError::Resources));
        assert!(invalid.pieces.is_empty());
        assert_eq!(invalid.resources.literal_bytes, usize::MAX);
        let mut full = JsonBuild { nodes: 0, resources: ResourceUse { literal_bytes: 0, dynamic_pieces: 0 },
            pieces: vec![NamedJsonPiece::Echo; body_compiler::MAX_TEMPLATE_PIECES] };
        assert_eq!(json_push(&mut full, NamedJsonPiece::Echo), Err(TemplateError::Resources));
        assert_eq!(full.pieces.len(), body_compiler::MAX_TEMPLATE_PIECES);
        let mut form = form_start();
        let nested = NamedFormPiece::Json(vec![NamedJsonPiece::Raw(vec![b'x'; body_compiler::MAX_TEMPLATE_LITERAL_BYTES])]);
        form_push(&mut form, nested).unwrap();
        assert_eq!(form_push(&mut form, NamedFormPiece::Raw(vec![b'x'])), Err(TemplateError::Resources));
        assert_eq!(form.pieces.len(), 1);
        assert_eq!(form.resources.literal_bytes, body_compiler::MAX_TEMPLATE_LITERAL_BYTES);
    }
}
