//! Closed request construction: a compiled recipe's plans and verified
//! argument values in, request bytes out.
//!
//! The compiler lowers a validated recipe into the plans below, and the
//! gateway shell converts native-verified MCP arguments into
//! [`ArgumentValue`]s in profile-field order. Everything here is then a pure,
//! total function of those two inputs plus the echo token and idempotency key
//! the shell derives. Credential reads take no argument at all, so no action
//! value can reach them.
//!
//! This module is a translated leaf. It uses index loops over slices, one loop
//! per helper, closed enums, byte comparisons, and no iterator adapters,
//! closures, trait objects, or standard-library string handling, so the
//! pinned Charon/Aeneas route translates it without external models.

#![allow(
    clippy::manual_range_contains,
    reason = "byte comparisons translate without a model of `RangeInclusive::contains`"
)]

use alloc::vec::Vec;

/// The largest request body.
pub const MAX_BODY_BYTES: usize = 16_384;
/// The largest verified value one path segment may carry.
pub const MAX_SEGMENT_VALUE_BYTES: usize = 4_096;
/// The largest encoded path, excluding the origin.
pub const MAX_PATH_BYTES: usize = 8_192;

/// One verified argument value, in profile-field order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArgumentValue {
    /// The UTF-8 bytes of a string or enum field.
    Text(Vec<u8>),
    /// The decimal ASCII spelling of an integer field.
    Integer(Vec<u8>),
    /// A boolean field.
    Boolean(bool),
}

/// The closed request methods.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestMethod {
    /// HTTP GET.
    Get,
    /// HTTP HEAD.
    Head,
    /// HTTP POST.
    Post,
    /// HTTP PUT.
    Put,
    /// HTTP PATCH.
    Patch,
    /// HTTP DELETE.
    Delete,
}

/// One path segment of an action request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SegmentPlan {
    /// A fixed segment the compiler validated.
    Fixed(Vec<u8>),
    /// The percent-encoded value of the verified argument at this index.
    Field(usize),
}

/// One request header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Header {
    /// The header name.
    pub name: Vec<u8>,
    /// The header value.
    pub value: Vec<u8>,
}

/// The value grammar of an account-scope header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeGrammar {
    /// `acct_` followed by 8 to 59 bytes of `[A-Za-z0-9_]`.
    StripeAccount,
}

/// The declared account-scope header and the argument that supplies it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountScopePlan {
    /// The registered header name.
    pub name: Vec<u8>,
    /// The index of the verified string argument.
    pub field: usize,
    /// The registered value grammar.
    pub grammar: ScopeGrammar,
}

/// The provider headers of every action request: the fixed version headers
/// and the optional account-scope header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderPlan {
    /// Registered version headers with their fixed values.
    pub versions: Vec<Header>,
    /// The declared account-scope header, if any.
    pub account_scope: Option<AccountScopePlan>,
}

/// One piece of a canonical JSON body: pre-rendered canonical bytes, the JSON
/// value of a verified argument, or the echo token as a JSON string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JsonPiece {
    /// Canonical JSON bytes the compiler rendered.
    Raw(Vec<u8>),
    /// The verified argument at this index, rendered as JSON.
    Field(usize),
    /// The echo token, rendered as a JSON string.
    Echo,
}

/// One piece of a form body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FormPiece {
    /// Form-encoded bytes the compiler rendered, including separators.
    Raw(Vec<u8>),
    /// The verified text or integer argument at this index, form-encoded.
    Field(usize),
    /// A canonical JSON value, form-encoded.
    Json(Vec<JsonPiece>),
    /// The echo token, form-encoded.
    Echo,
}

/// The body plan of a write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BodyPlan {
    /// `application/json`.
    Json(Vec<JsonPiece>),
    /// `application/x-www-form-urlencoded`.
    Form(Vec<FormPiece>),
}

/// The write of a compiled recipe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WritePlan {
    /// The approved write method.
    pub method: RequestMethod,
    /// The pinned origin, without a trailing slash.
    pub origin: Vec<u8>,
    /// The declared path segments.
    pub path: Vec<SegmentPlan>,
    /// The declared provider headers.
    pub headers: HeaderPlan,
    /// The derived idempotency header name, when declared.
    pub idempotency_header: Option<Vec<u8>>,
    /// The declared body.
    pub body: BodyPlan,
}

/// An action read: a GET that carries verified values in its path and the
/// declared provider headers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionReadPlan {
    /// The pinned origin, without a trailing slash.
    pub origin: Vec<u8>,
    /// The declared path segments.
    pub path: Vec<SegmentPlan>,
    /// The declared provider headers.
    pub headers: HeaderPlan,
}

/// A credential read: a fixed request that carries only the version headers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialReadPlan {
    /// `GET` or `HEAD`.
    pub method: RequestMethod,
    /// The pinned origin, without a trailing slash.
    pub origin: Vec<u8>,
    /// The fixed path segments.
    pub path: Vec<Vec<u8>>,
    /// The registered version headers with their fixed values.
    pub versions: Vec<Header>,
}

/// A constructed request. The credential header is added only by the
/// transport, at lease time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltRequest {
    /// The request method.
    pub method: RequestMethod,
    /// The origin followed by the encoded path.
    pub url: Vec<u8>,
    /// Every non-credential header.
    pub headers: Vec<Header>,
    /// The body, empty for a read.
    pub body: Vec<u8>,
}

/// Why a request could not be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConstructError {
    /// A referenced argument is absent or has the wrong kind.
    ArgumentMismatch,
    /// A path value is empty, `.`, `..`, or over its bound.
    UnsafeSegment,
    /// The encoded path is over its bound.
    PathTooLong,
    /// An account-scope value is outside its registered grammar.
    HeaderValue,
    /// The body is empty or over its bound.
    BodySize,
}

/// Appends `bytes` to `out`.
#[must_use]
pub fn append_bytes(mut out: Vec<u8>, bytes: &[u8]) -> Vec<u8> {
    let mut index = 0;
    while index < bytes.len() {
        out.push(bytes[index]);
        index += 1;
    }
    out
}

/// A fresh copy of `bytes`.
#[must_use]
pub fn copy_bytes(bytes: &[u8]) -> Vec<u8> {
    append_bytes(Vec::new(), bytes)
}

/// ASCII letters and digits.
#[must_use]
pub const fn is_alphanumeric(byte: u8) -> bool {
    (byte >= b'0' && byte <= b'9')
        || (byte >= b'A' && byte <= b'Z')
        || (byte >= b'a' && byte <= b'z')
}

/// Bytes a path segment carries unencoded.
#[must_use]
pub const fn is_path_literal(byte: u8) -> bool {
    is_alphanumeric(byte) || byte == b'-' || byte == b'_' || byte == b'.' || byte == b'~'
}

/// Bytes a form value carries unencoded.
#[must_use]
pub const fn is_form_literal(byte: u8) -> bool {
    is_alphanumeric(byte) || byte == b'*' || byte == b'-' || byte == b'.' || byte == b'_'
}

/// The uppercase hexadecimal digit of a nibble.
#[must_use]
pub const fn hex_upper(nibble: u8) -> u8 {
    if nibble < 10 {
        b'0' + nibble
    } else {
        b'A' + (nibble - 10)
    }
}

/// The lowercase hexadecimal digit of a nibble.
#[must_use]
pub const fn hex_lower(nibble: u8) -> u8 {
    if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + (nibble - 10)
    }
}

/// Appends `%` and the two uppercase hexadecimal digits of `byte`.
#[must_use]
pub fn append_percent(mut out: Vec<u8>, byte: u8) -> Vec<u8> {
    out.push(b'%');
    out.push(hex_upper(byte / 16));
    out.push(hex_upper(byte % 16));
    out
}

/// Appends one byte of a path segment, percent-encoding every byte outside
/// the unreserved set, so a value can never add `/`, `?`, or `#`.
#[must_use]
pub fn append_path_byte(mut out: Vec<u8>, byte: u8) -> Vec<u8> {
    if is_path_literal(byte) {
        out.push(byte);
        out
    } else {
        append_percent(out, byte)
    }
}

/// Appends a percent-encoded path segment value.
#[must_use]
pub fn append_path_encoded(mut out: Vec<u8>, text: &[u8]) -> Vec<u8> {
    let mut index = 0;
    while index < text.len() {
        out = append_path_byte(out, text[index]);
        index += 1;
    }
    out
}

/// A verified path value is non-empty, is not `.` or `..`, and is within its
/// bound.
#[must_use]
pub fn segment_value_valid(text: &[u8]) -> bool {
    if text.is_empty() || text.len() > MAX_SEGMENT_VALUE_BYTES {
        return false;
    }
    if text.len() == 1 && text[0] == b'.' {
        return false;
    }
    !(text.len() == 2 && text[0] == b'.' && text[1] == b'.')
}

/// The first reason one segment cannot be built, if any.
#[must_use]
pub fn segment_error(segment: &SegmentPlan, arguments: &[ArgumentValue]) -> Option<ConstructError> {
    match segment {
        SegmentPlan::Fixed(_) => None,
        SegmentPlan::Field(field) => {
            if *field >= arguments.len() {
                return Some(ConstructError::ArgumentMismatch);
            }
            match &arguments[*field] {
                ArgumentValue::Text(text) => {
                    if segment_value_valid(text) {
                        None
                    } else {
                        Some(ConstructError::UnsafeSegment)
                    }
                }
                ArgumentValue::Integer(_) | ArgumentValue::Boolean(_) => {
                    Some(ConstructError::ArgumentMismatch)
                }
            }
        }
    }
}

/// The first reason a path cannot be built, if any.
#[must_use]
pub fn path_error(path: &[SegmentPlan], arguments: &[ArgumentValue]) -> Option<ConstructError> {
    let mut index = 0;
    while index < path.len() {
        let error = segment_error(&path[index], arguments);
        if error.is_some() {
            return error;
        }
        index += 1;
    }
    None
}

/// Appends `/` and one segment. A field whose argument is not text appends
/// only the separator; [`path_error`] refuses that case first.
#[must_use]
pub fn append_segment(
    mut out: Vec<u8>,
    segment: &SegmentPlan,
    arguments: &[ArgumentValue],
) -> Vec<u8> {
    out.push(b'/');
    match segment {
        SegmentPlan::Fixed(value) => append_bytes(out, value),
        SegmentPlan::Field(field) => {
            if *field < arguments.len() {
                match &arguments[*field] {
                    ArgumentValue::Text(text) => append_path_encoded(out, text),
                    ArgumentValue::Integer(_) | ArgumentValue::Boolean(_) => out,
                }
            } else {
                out
            }
        }
    }
}

/// Appends every segment in declaration order.
#[must_use]
pub fn append_segments(
    mut out: Vec<u8>,
    path: &[SegmentPlan],
    arguments: &[ArgumentValue],
) -> Vec<u8> {
    let mut index = 0;
    while index < path.len() {
        out = append_segment(out, &path[index], arguments);
        index += 1;
    }
    out
}

/// The origin followed by the encoded path.
///
/// # Errors
/// Refuses a missing or non-text path argument, an unsafe value, or an
/// encoded path over [`MAX_PATH_BYTES`].
pub fn build_url(
    origin: &[u8],
    path: &[SegmentPlan],
    arguments: &[ArgumentValue],
) -> Result<Vec<u8>, ConstructError> {
    if let Some(error) = path_error(path, arguments) {
        return Err(error);
    }
    let encoded = append_segments(Vec::new(), path, arguments);
    if encoded.len() > MAX_PATH_BYTES {
        Err(ConstructError::PathTooLong)
    } else {
        Ok(append_bytes(copy_bytes(origin), &encoded))
    }
}

/// The origin followed by fixed segments.
#[must_use]
pub fn fixed_url(origin: &[u8], path: &[Vec<u8>]) -> Vec<u8> {
    let mut out = copy_bytes(origin);
    let mut index = 0;
    while index < path.len() {
        out.push(b'/');
        out = append_bytes(out, &path[index]);
        index += 1;
    }
    out
}

/// A copy of one header.
#[must_use]
pub fn copy_header(header: &Header) -> Header {
    Header {
        name: copy_bytes(&header.name),
        value: copy_bytes(&header.value),
    }
}

/// Appends a copy of every version header.
#[must_use]
pub fn append_version_headers(mut out: Vec<Header>, versions: &[Header]) -> Vec<Header> {
    let mut index = 0;
    while index < versions.len() {
        out.push(copy_header(&versions[index]));
        index += 1;
    }
    out
}

/// One byte of a Stripe account identifier after its prefix.
#[must_use]
pub const fn is_account_byte(byte: u8) -> bool {
    is_alphanumeric(byte) || byte == b'_'
}

/// Every byte of `value` from `start` is an account byte.
#[must_use]
pub fn account_bytes_valid(value: &[u8], start: usize) -> bool {
    let mut index = start;
    while index < value.len() {
        if !is_account_byte(value[index]) {
            return false;
        }
        index += 1;
    }
    true
}

/// Whether `value` matches the header's registered grammar. A value that
/// matches contains no byte that could end or add a header line.
#[must_use]
pub fn scope_value_valid(grammar: ScopeGrammar, value: &[u8]) -> bool {
    match grammar {
        ScopeGrammar::StripeAccount => {
            value.len() >= 13
                && value.len() <= 64
                && value[0] == b'a'
                && value[1] == b'c'
                && value[2] == b'c'
                && value[3] == b't'
                && value[4] == b'_'
                && account_bytes_valid(value, 5)
        }
    }
}

/// The account-scope header with the verified value.
///
/// # Errors
/// Refuses a missing or non-text argument, or a value outside the grammar.
pub fn account_scope_header(
    plan: &AccountScopePlan,
    arguments: &[ArgumentValue],
) -> Result<Header, ConstructError> {
    if plan.field >= arguments.len() {
        return Err(ConstructError::ArgumentMismatch);
    }
    match &arguments[plan.field] {
        ArgumentValue::Text(value) => {
            if scope_value_valid(plan.grammar, value) {
                Ok(Header {
                    name: copy_bytes(&plan.name),
                    value: copy_bytes(value),
                })
            } else {
                Err(ConstructError::HeaderValue)
            }
        }
        ArgumentValue::Integer(_) | ArgumentValue::Boolean(_) => {
            Err(ConstructError::ArgumentMismatch)
        }
    }
}

/// The headers of every action request: the version headers, then the
/// account-scope header when declared.
///
/// # Errors
/// Refuses an account-scope value [`account_scope_header`] refuses.
pub fn action_headers(
    plan: &HeaderPlan,
    arguments: &[ArgumentValue],
) -> Result<Vec<Header>, ConstructError> {
    let mut out = append_version_headers(Vec::new(), &plan.versions);
    match &plan.account_scope {
        None => Ok(out),
        Some(scope) => match account_scope_header(scope, arguments) {
            Ok(header) => {
                out.push(header);
                Ok(out)
            }
            Err(error) => Err(error),
        },
    }
}

/// Appends one byte of a JSON string under RFC 8785: `"` and `\` are
/// escaped, the five named controls use their short escapes, other controls
/// use `\u00xx`, and every other byte is copied.
#[must_use]
pub fn append_json_byte(mut out: Vec<u8>, byte: u8) -> Vec<u8> {
    if byte == b'"' || byte == b'\\' {
        out.push(b'\\');
        out.push(byte);
    } else if byte == 0x08 {
        out.push(b'\\');
        out.push(b'b');
    } else if byte == 0x09 {
        out.push(b'\\');
        out.push(b't');
    } else if byte == 0x0a {
        out.push(b'\\');
        out.push(b'n');
    } else if byte == 0x0c {
        out.push(b'\\');
        out.push(b'f');
    } else if byte == 0x0d {
        out.push(b'\\');
        out.push(b'r');
    } else if byte < 0x20 {
        out.push(b'\\');
        out.push(b'u');
        out.push(b'0');
        out.push(b'0');
        out.push(hex_lower(byte / 16));
        out.push(hex_lower(byte % 16));
    } else {
        out.push(byte);
    }
    out
}

/// Appends the escaped bytes of a JSON string, without quotes.
#[must_use]
pub fn append_json_escaped(mut out: Vec<u8>, text: &[u8]) -> Vec<u8> {
    let mut index = 0;
    while index < text.len() {
        out = append_json_byte(out, text[index]);
        index += 1;
    }
    out
}

/// Appends a quoted JSON string.
#[must_use]
pub fn append_json_string(mut out: Vec<u8>, text: &[u8]) -> Vec<u8> {
    out.push(b'"');
    let mut escaped = append_json_escaped(out, text);
    escaped.push(b'"');
    escaped
}

/// Appends the JSON value of one argument.
#[must_use]
pub fn append_json_argument(mut out: Vec<u8>, value: &ArgumentValue) -> Vec<u8> {
    match value {
        ArgumentValue::Text(text) => append_json_string(out, text),
        ArgumentValue::Integer(digits) => append_bytes(out, digits),
        ArgumentValue::Boolean(true) => {
            out.push(b't');
            out.push(b'r');
            out.push(b'u');
            out.push(b'e');
            out
        }
        ArgumentValue::Boolean(false) => {
            out.push(b'f');
            out.push(b'a');
            out.push(b'l');
            out.push(b's');
            out.push(b'e');
            out
        }
    }
}

/// Whether the argument a JSON piece references exists.
#[must_use]
pub fn json_piece_valid(piece: &JsonPiece, arguments: &[ArgumentValue]) -> bool {
    match piece {
        JsonPiece::Raw(_) | JsonPiece::Echo => true,
        JsonPiece::Field(field) => *field < arguments.len(),
    }
}

/// Whether every argument a JSON piece list references exists.
#[must_use]
pub fn json_pieces_valid(pieces: &[JsonPiece], arguments: &[ArgumentValue]) -> bool {
    let mut index = 0;
    while index < pieces.len() {
        if !json_piece_valid(&pieces[index], arguments) {
            return false;
        }
        index += 1;
    }
    true
}

/// Appends one JSON piece.
#[must_use]
pub fn append_json_piece(
    out: Vec<u8>,
    piece: &JsonPiece,
    arguments: &[ArgumentValue],
    echo: &[u8],
) -> Vec<u8> {
    match piece {
        JsonPiece::Raw(bytes) => append_bytes(out, bytes),
        JsonPiece::Field(field) => {
            if *field < arguments.len() {
                append_json_argument(out, &arguments[*field])
            } else {
                out
            }
        }
        JsonPiece::Echo => append_json_string(out, echo),
    }
}

/// Appends every JSON piece in order.
#[must_use]
pub fn append_json_pieces(
    mut out: Vec<u8>,
    pieces: &[JsonPiece],
    arguments: &[ArgumentValue],
    echo: &[u8],
) -> Vec<u8> {
    let mut index = 0;
    while index < pieces.len() {
        out = append_json_piece(out, &pieces[index], arguments, echo);
        index += 1;
    }
    out
}

/// Appends one form-encoded byte: a space becomes `+`, form literals are
/// copied, and every other byte is percent-encoded.
#[must_use]
pub fn append_form_byte(mut out: Vec<u8>, byte: u8) -> Vec<u8> {
    if byte == b' ' {
        out.push(b'+');
        out
    } else if is_form_literal(byte) {
        out.push(byte);
        out
    } else {
        append_percent(out, byte)
    }
}

/// Appends form-encoded bytes.
#[must_use]
pub fn append_form_encoded(mut out: Vec<u8>, text: &[u8]) -> Vec<u8> {
    let mut index = 0;
    while index < text.len() {
        out = append_form_byte(out, text[index]);
        index += 1;
    }
    out
}

/// Whether one form piece can be built: a field must name a text or integer
/// argument, and a JSON value must reference only existing arguments.
#[must_use]
pub fn form_piece_valid(piece: &FormPiece, arguments: &[ArgumentValue]) -> bool {
    match piece {
        FormPiece::Raw(_) | FormPiece::Echo => true,
        FormPiece::Field(field) => {
            *field < arguments.len()
                && match &arguments[*field] {
                    ArgumentValue::Text(_) | ArgumentValue::Integer(_) => true,
                    ArgumentValue::Boolean(_) => false,
                }
        }
        FormPiece::Json(pieces) => json_pieces_valid(pieces, arguments),
    }
}

/// Whether every form piece can be built.
#[must_use]
pub fn form_pieces_valid(pieces: &[FormPiece], arguments: &[ArgumentValue]) -> bool {
    let mut index = 0;
    while index < pieces.len() {
        if !form_piece_valid(&pieces[index], arguments) {
            return false;
        }
        index += 1;
    }
    true
}

/// Appends one form piece.
#[must_use]
pub fn append_form_piece(
    out: Vec<u8>,
    piece: &FormPiece,
    arguments: &[ArgumentValue],
    echo: &[u8],
) -> Vec<u8> {
    match piece {
        FormPiece::Raw(bytes) => append_bytes(out, bytes),
        FormPiece::Field(field) => {
            if *field < arguments.len() {
                match &arguments[*field] {
                    ArgumentValue::Text(text) | ArgumentValue::Integer(text) => {
                        append_form_encoded(out, text)
                    }
                    ArgumentValue::Boolean(_) => out,
                }
            } else {
                out
            }
        }
        FormPiece::Json(pieces) => {
            let json = append_json_pieces(Vec::new(), pieces, arguments, echo);
            append_form_encoded(out, &json)
        }
        FormPiece::Echo => append_form_encoded(out, echo),
    }
}

/// Appends every form piece in order.
#[must_use]
pub fn append_form_pieces(
    mut out: Vec<u8>,
    pieces: &[FormPiece],
    arguments: &[ArgumentValue],
    echo: &[u8],
) -> Vec<u8> {
    let mut index = 0;
    while index < pieces.len() {
        out = append_form_piece(out, &pieces[index], arguments, echo);
        index += 1;
    }
    out
}

/// The body bytes.
///
/// # Errors
/// Refuses a missing or mismatched argument, and an empty body or one over
/// [`MAX_BODY_BYTES`].
#[allow(
    clippy::len_zero,
    reason = "the translated standard-library model covers `len`, not `Vec::is_empty`"
)]
pub fn build_body(
    plan: &BodyPlan,
    arguments: &[ArgumentValue],
    echo: &[u8],
) -> Result<Vec<u8>, ConstructError> {
    let body = match plan {
        BodyPlan::Json(pieces) => {
            if !json_pieces_valid(pieces, arguments) {
                return Err(ConstructError::ArgumentMismatch);
            }
            append_json_pieces(Vec::new(), pieces, arguments, echo)
        }
        BodyPlan::Form(pieces) => {
            if !form_pieces_valid(pieces, arguments) {
                return Err(ConstructError::ArgumentMismatch);
            }
            append_form_pieces(Vec::new(), pieces, arguments, echo)
        }
    };
    if body.len() == 0 || body.len() > MAX_BODY_BYTES {
        Err(ConstructError::BodySize)
    } else {
        Ok(body)
    }
}

/// The write: the approved method, the origin and encoded path, the version
/// headers, the account-scope header when declared, the derived idempotency
/// header when declared, and the bounded body with the echo when declared.
///
/// # Errors
/// Refuses what [`build_url`], [`build_body`], and [`action_headers`] refuse.
pub fn construct_write(
    plan: &WritePlan,
    arguments: &[ArgumentValue],
    echo: &[u8],
    idempotency_key: &[u8],
) -> Result<BuiltRequest, ConstructError> {
    let url = build_url(&plan.origin, &plan.path, arguments)?;
    let body = build_body(&plan.body, arguments, echo)?;
    let mut headers = action_headers(&plan.headers, arguments)?;
    if let Some(name) = &plan.idempotency_header {
        headers.push(Header {
            name: copy_bytes(name),
            value: copy_bytes(idempotency_key),
        });
    }
    Ok(BuiltRequest {
        method: plan.method,
        url,
        headers,
        body,
    })
}

/// An action read: a GET to the origin and encoded path with the version
/// headers and the account-scope header when declared.
///
/// # Errors
/// Refuses what [`build_url`] and [`action_headers`] refuse.
pub fn construct_action_read(
    plan: &ActionReadPlan,
    arguments: &[ArgumentValue],
) -> Result<BuiltRequest, ConstructError> {
    let url = build_url(&plan.origin, &plan.path, arguments)?;
    let headers = action_headers(&plan.headers, arguments)?;
    Ok(BuiltRequest {
        method: RequestMethod::Get,
        url,
        headers,
        body: Vec::new(),
    })
}

/// A credential read: the declared method to the origin and fixed path, with
/// only the version headers. It takes no argument, so no action value can
/// reach it.
#[must_use]
pub fn construct_credential_read(plan: &CredentialReadPlan) -> BuiltRequest {
    BuiltRequest {
        method: plan.method,
        url: fixed_url(&plan.origin, &plan.path),
        headers: append_version_headers(Vec::new(), &plan.versions),
        body: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn text(value: &str) -> ArgumentValue {
        ArgumentValue::Text(value.as_bytes().to_vec())
    }

    fn headers(plan: Vec<(&str, &str)>) -> Vec<Header> {
        plan.into_iter()
            .map(|(name, value)| Header {
                name: name.as_bytes().to_vec(),
                value: value.as_bytes().to_vec(),
            })
            .collect()
    }

    fn scoped() -> HeaderPlan {
        HeaderPlan {
            versions: headers(vec![("Stripe-Version", "2025-03-31.basil")]),
            account_scope: Some(AccountScopePlan {
                name: b"Stripe-Account".to_vec(),
                field: 1,
                grammar: ScopeGrammar::StripeAccount,
            }),
        }
    }

    #[test]
    fn json_strings_follow_rfc_8785_escaping() {
        let rendered =
            append_json_string(Vec::new(), "a\"b\\c\u{8}\u{c}\n\r\t\u{1}\u{7f}é".as_bytes());
        assert_eq!(
            rendered,
            "\"a\\\"b\\\\c\\b\\f\\n\\r\\t\\u0001\u{7f}é\"".as_bytes()
        );
    }

    #[test]
    fn path_and_form_encoding_never_pass_a_separator() {
        assert_eq!(
            append_path_encoded(Vec::new(), b"a/b?c#d e%~._-"),
            b"a%2Fb%3Fc%23d%20e%25~._-"
        );
        assert_eq!(
            append_form_encoded(Vec::new(), b"a b&c=d*-._~"),
            b"a+b%26c%3Dd*-._%7E"
        );
        for value in [&b""[..], b".", b".."] {
            assert!(!segment_value_valid(value));
        }
    }

    #[test]
    fn account_scope_grammar_admits_only_account_identifiers() {
        let valid = ScopeGrammar::StripeAccount;
        assert!(scope_value_valid(valid, b"acct_TESTACCOUNT01"));
        assert!(scope_value_valid(valid, b"acct_12345678"));
        for hostile in [
            &b"acct_1234567"[..],
            b"acct_TEST\r\nX: 1",
            b"acct_TEST-ACCOUNT",
            b"cust_TESTACCOUNT01",
            b"acct_",
            b"",
        ] {
            assert!(!scope_value_valid(valid, hostile));
        }
        assert!(!scope_value_valid(valid, &[b'a'; 65]));
    }

    #[test]
    fn write_carries_versions_scope_and_key_and_reads_carry_no_key() {
        let plan = WritePlan {
            method: RequestMethod::Post,
            origin: b"https://api.stripe.com".to_vec(),
            path: vec![SegmentPlan::Fixed(b"v1".to_vec()), SegmentPlan::Field(0)],
            headers: scoped(),
            idempotency_header: Some(b"Idempotency-Key".to_vec()),
            body: BodyPlan::Form(vec![
                FormPiece::Raw(b"amount=".to_vec()),
                FormPiece::Field(2),
                FormPiece::Raw(b"&metadata%5Bauths_echo%5D=".to_vec()),
                FormPiece::Echo,
            ]),
        };
        let arguments = vec![
            text("re/1"),
            text("acct_TESTACCOUNT01"),
            ArgumentValue::Integer(b"500".to_vec()),
        ];
        let built =
            construct_write(&plan, &arguments, b"auths-e1-00", b"auths-i1-00").expect("write");
        assert_eq!(built.url, b"https://api.stripe.com/v1/re%2F1");
        assert_eq!(
            built.body,
            b"amount=500&metadata%5Bauths_echo%5D=auths-e1-00"
        );
        assert_eq!(
            built.headers,
            headers(vec![
                ("Stripe-Version", "2025-03-31.basil"),
                ("Stripe-Account", "acct_TESTACCOUNT01"),
                ("Idempotency-Key", "auths-i1-00"),
            ])
        );
        let read = construct_action_read(
            &ActionReadPlan {
                origin: plan.origin.clone(),
                path: plan.path.clone(),
                headers: scoped(),
            },
            &arguments,
        )
        .expect("read");
        assert_eq!(read.method, RequestMethod::Get);
        assert!(read.body.is_empty());
        assert_eq!(
            read.headers,
            headers(vec![
                ("Stripe-Version", "2025-03-31.basil"),
                ("Stripe-Account", "acct_TESTACCOUNT01"),
            ])
        );
        let mut hostile = arguments.clone();
        hostile[1] = text("acct_TEST\r\nX: 1");
        assert_eq!(
            construct_write(&plan, &hostile, b"", b"").err(),
            Some(ConstructError::HeaderValue)
        );
    }

    #[test]
    fn credential_reads_carry_only_fixed_segments_and_version_headers() {
        let plan = CredentialReadPlan {
            method: RequestMethod::Head,
            origin: b"https://api.stripe.com".to_vec(),
            path: vec![b"v1".to_vec(), b"customers".to_vec()],
            versions: headers(vec![("Stripe-Version", "2025-03-31.basil")]),
        };
        let built = construct_credential_read(&plan);
        assert_eq!(built.method, RequestMethod::Head);
        assert_eq!(built.url, b"https://api.stripe.com/v1/customers");
        assert_eq!(built.headers, plan.versions);
        assert!(built.body.is_empty());
    }

    #[test]
    fn body_bound_and_argument_kinds_are_enforced() {
        let json = BodyPlan::Json(vec![JsonPiece::Field(0)]);
        let long = text(&"x".repeat(MAX_BODY_BYTES));
        assert_eq!(
            build_body(&json, &[long], b"").err(),
            Some(ConstructError::BodySize)
        );
        assert_eq!(
            build_body(&json, &[], b"").err(),
            Some(ConstructError::ArgumentMismatch)
        );
        let form = BodyPlan::Form(vec![FormPiece::Field(0)]);
        assert_eq!(
            build_body(&form, &[ArgumentValue::Boolean(true)], b"").err(),
            Some(ConstructError::ArgumentMismatch)
        );
        assert_eq!(
            build_body(
                &BodyPlan::Json(vec![JsonPiece::Field(0)]),
                &[ArgumentValue::Boolean(false)],
                b""
            ),
            Ok(b"false".to_vec())
        );
        assert_eq!(
            build_url(
                b"https://a.example",
                &[SegmentPlan::Field(0)],
                &[ArgumentValue::Integer(b"1".to_vec())]
            )
            .err(),
            Some(ConstructError::ArgumentMismatch)
        );
    }
}
