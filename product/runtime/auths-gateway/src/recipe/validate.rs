//! The compile rules of recipe source `/2`.
//!
//! Each rule refuses with its stable code. The rules are independent: a
//! source that breaks exactly one rule fails with that rule's code whatever
//! order the checks run in.

use super::source::{
    AccountReadSource, AccountScopeSource, BodySource, BoundsSource, DeniedReadSource,
    EchoPlacement, EchoSource, FormExpr, GuardSource, IdempotencyLocation, IdempotencySource,
    BindSource, ObservationSource, PathSegment, PreEntrySource, PreconditionSource, ProbeSource, RecipeSource,
    RelativeCeilingSource, ValueExpr,
};
use super::{
    FieldSchema, FieldSchemaRuntime, GatewayRecipeError, OperatorNamespace, ProfileLockFile, MAX_FORM_FIELDS, MAX_PATH_SEGMENTS, MAX_POINTER_BYTES,
    MAX_VERIFIED_FIELDS, valid_field_name,
};
use serde_json::Value;
use auths_gateway_kernel::template_ast::MAX_LITERAL_BYTES;
use auths_gateway_kernel::recipe_binding::{self, ProfileBinding};
use auths_gateway_kernel::field_projection::FieldSpec;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_READ_RESPONSE_BYTES: u64 = 65_536;
const MAX_RETENTION_SECONDS: u64 = 2_592_000;
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
const MAX_PROBE_TEXT_BYTES: usize = 256;
const MAX_GUARD_PREFIXES: usize = 4;
const MAX_GUARD_PREFIX_BYTES: usize = 32;
const MAX_DENIED_READS: usize = 4;
const MAX_REFUSED_STATUSES: usize = 3;
const MAX_RESPONSE_FIELDS: usize = 2;
const MAX_RESPONSE_FIELD_BYTES: u64 = 255;
const MAX_PRE_ENTRY_POINTERS: usize = 4;
const MAX_BINDS: usize = 2;
const MAX_BASIS_POINTS: u64 = 10_000;
const MAX_PROVIDER_HEADERS: usize = auths_gateway_kernel::header_compiler::MAX_PROVIDER_HEADERS;

/// Which profile fields each part of a recipe consumes.
#[derive(Default)]
pub(super) struct Consumption {
    /// Every consumed field, for the rule that each profile field is used.
    pub(super) all: BTreeSet<String>,
    /// Fields the write body renders.
    pub(super) body: BTreeSet<String>,
    /// Fields a relative-ceiling bind names.
    pub(super) binds: BTreeSet<String>,
}

pub(super) struct Rules<'a> {
    pub(super) fields: &'a BTreeMap<String, FieldSchema>,
    pub(super) consumed: Consumption,
}

/// Where a path appears, which fixes the code a response-field segment gets.
#[derive(Clone, Copy)]
enum PathRole {
    Write,
    Observation,
    PreEntry,
    RelativeCeiling,
}

impl PathRole {
    const fn response_fields(self) -> usize {
        match self {
            Self::Observation => MAX_RESPONSE_FIELDS,
            Self::Write | Self::PreEntry | Self::RelativeCeiling => 0,
        }
    }

    const fn response_error(self) -> GatewayRecipeError {
        match self {
            Self::Write | Self::Observation => GatewayRecipeError::ResponseLocatorConflict,
            Self::PreEntry => GatewayRecipeError::InvalidPreEntry,
            Self::RelativeCeiling => GatewayRecipeError::InvalidRelativeCeiling,
        }
    }
}

fn is_binding_field(name: &str) -> bool {
    let bytes = name.as_bytes();
    auths_gateway_kernel::construct::field_name_equal(bytes, b"operator_namespace")
        || auths_gateway_kernel::construct::field_name_equal(bytes, b"operation_id")
        || auths_gateway_kernel::construct::field_name_equal(bytes, b"recipe_digest")
}

fn is_namespace_or_recipe_field(name: &str) -> bool {
    let bytes = name.as_bytes();
    auths_gateway_kernel::construct::field_name_equal(bytes, b"operator_namespace")
        || auths_gateway_kernel::construct::field_name_equal(bytes, b"recipe_digest")
}

fn form_json_shape(value: &ValueExpr) -> bool {
    match value {
        ValueExpr::Array { items } => items.len() == 1,
        _ => true,
    }
}

fn account_scope_uses_field(scope: Option<&AccountScopeSource>, name: &str) -> bool {
    match scope {
        Some(scope) => auths_gateway_kernel::construct::field_name_equal(scope.field.as_bytes(), name.as_bytes()),
        None => false,
    }
}

fn partition_bound(consumed: &Consumption, scope: Option<&AccountScopeSource>, name: &str) -> bool {
    if consumed.body.contains(name) {
        true
    } else if account_scope_uses_field(scope, name) {
        true
    } else {
        consumed.binds.contains(name)
    }
}

fn all_fields_consumed(fields: &BTreeMap<String, FieldSchema>, consumed: &BTreeSet<String>) -> bool {
    for (field, _) in fields {
        if !is_binding_field(field) && !consumed.contains(field) {
            return false;
        }
    }
    true
}

/// An observation pointer: absolute, at most 128 bytes and eight tokens, and
/// without the `~2` escape.
pub(super) fn valid_response_pointer(pointer: &str) -> bool {
    let bytes = pointer.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_POINTER_BYTES || bytes[0] != b'/' {
        return false;
    }
    let mut position = 0;
    let mut tokens = 0;
    let mut valid = true;
    while position < bytes.len() && valid {
        if bytes[position] == b'/' { tokens += 1; }
        if bytes[position] == b'~' && position + 1 < bytes.len() && bytes[position + 1] == b'2' {
            valid = false;
        }
        position += 1;
    }
    valid && tokens <= 8
}

fn pointers_overlap(first: &str, second: &str) -> bool {
    let left = first.as_bytes();
    let right = second.as_bytes();
    auths_gateway_kernel::construct::field_name_equal(left, right)
        || pointer_descends(left, right) || pointer_descends(right, left)
}

fn pointer_descends(child: &[u8], parent: &[u8]) -> bool {
    child.starts_with(parent) && child.get(parent.len()) == Some(&b'/')
}

fn valid_fixed_segment(value: &str) -> bool {
    auths_gateway_kernel::path_compiler::fixed_segment_valid(value.as_bytes())
}

fn read_bound_valid(bytes: u64) -> bool {
    (1..=MAX_READ_RESPONSE_BYTES).contains(&bytes)
}

/// The fixed values of a path made only of fixed segments.
pub(super) fn fixed_values(path: &[PathSegment]) -> Option<Vec<String>> {
    let mut values = Vec::new();
    let mut position = 0;
    let mut valid = true;
    while position < path.len() && valid {
        match &path[position] {
            PathSegment::Fixed { value } => values.push(value.clone()),
            _ => valid = false,
        }
        position += 1;
    }
    if valid { Some(values) } else { None }
}

/// A credential-read path: 1–16 valid fixed segments.
fn fixed_path(path: &[PathSegment]) -> Result<Vec<String>, GatewayRecipeError> {
    // Earn both count and segment bounds before copying the owned column.
    if path.is_empty() || path.len() > MAX_PATH_SEGMENTS {
        return Err(GatewayRecipeError::InvalidCredentialGuard);
    }
    if !fixed_segments_valid(path) {
        return Err(GatewayRecipeError::InvalidCredentialGuard);
    }
    fixed_values(path).ok_or(GatewayRecipeError::InvalidCredentialGuard)
}

fn fixed_segments_valid(path: &[PathSegment]) -> bool {
    let mut position = 0;
    let mut valid = true;
    while position < path.len() && valid {
        valid = match &path[position] {
            PathSegment::Fixed { value } => valid_fixed_segment(value),
            _ => false,
        };
        position += 1;
    }
    valid
}

// These callers check their small count limit before this scan. An invalid
// cursor fails closed instead of creating an unchecked indexed read.
fn string_seen_before(values: &[String], position: usize) -> bool {
    let Some(value) = values.get(position) else { return true; };
    let mut previous = 0;
    let mut seen = false;
    while previous < position && !seen {
        seen = values[previous] == *value;
        previous += 1;
    }
    seen
}

fn pre_entry_pointers_valid(pointers: &[String], maximum_response_bytes: u64) -> bool {
    if pointers.is_empty() || pointers.len() > MAX_PRE_ENTRY_POINTERS
        || !read_bound_valid(maximum_response_bytes) {
        return false;
    }
    let mut position = 0;
    let mut valid = true;
    while position < pointers.len() && valid {
        valid = valid_response_pointer(&pointers[position]) && !string_seen_before(pointers, position);
        position += 1;
    }
    valid
}

fn bind_pointer_seen_before(binds: &[super::source::BindSource], position: usize) -> bool {
    let Some(value) = binds.get(position) else { return true; };
    let mut previous = 0;
    let mut seen = false;
    while previous < position && !seen {
        seen = binds[previous].pointer == value.pointer;
        previous += 1;
    }
    seen
}

fn bind_pointers_valid(binds: &[super::source::BindSource]) -> bool {
    if binds.len() > MAX_BINDS { return false; }
    let mut position = 0;
    let mut valid = true;
    while position < binds.len() && valid {
        valid = !bind_pointer_seen_before(binds, position);
        position += 1;
    }
    valid
}

fn bindable_field(fields: &BTreeMap<String, FieldSchema>, name: &str) -> bool {
    match fields.get(name) {
        Some(FieldSchema::String { .. } | FieldSchema::Enum { .. } | FieldSchema::Integer { .. }) => true,
        _ => false,
    }
}

fn relative_bind_valid(fields: &BTreeMap<String, FieldSchema>, bind: &BindSource, argument: &str) -> bool {
    valid_response_pointer(&bind.pointer) && bindable_field(fields, &bind.field)
        && !auths_gateway_kernel::construct::field_name_equal(bind.field.as_bytes(), argument.as_bytes())
        && !is_binding_field(&bind.field)
}

fn relative_binds_valid(fields: &BTreeMap<String, FieldSchema>, binds: &[BindSource], argument: &str) -> bool {
    if !bind_pointers_valid(binds) { return false; }
    let mut position = 0;
    let mut valid = true;
    while position < binds.len() && valid {
        valid = relative_bind_valid(fields, &binds[position], argument);
        position += 1;
    }
    valid
}

impl Rules<'_> {
    fn path_field(&self, name: &str) -> bool {
        match self.fields.get(name) {
            Some(schema) => schema.is_path_scalar(),
            None => false,
        }
    }

    fn form_field(&self, name: &str) -> bool {
        match self.fields.get(name) {
            Some(schema) => schema.is_form_scalar(),
            None => false,
        }
    }

    fn fact_field(&self, name: &str) -> bool {
        match self.fields.get(name) {
            Some(schema) => schema.has_fact_form(),
            None => false,
        }
    }

    fn text_fact_field(&self, name: &str) -> bool {
        match self.fields.get(name) {
            Some(schema @ FieldSchema::String { .. }) => schema.has_fact_form(),
            _ => false,
        }
    }

    fn integer_field(&self, name: &str) -> bool {
        match self.fields.get(name) {
            Some(FieldSchema::Integer { .. }) => true,
            _ => false,
        }
    }

    fn consume(&mut self, name: &str) {
        self.consumed.all.insert(name.to_owned());
    }

    fn path(&mut self, path: &[PathSegment], role: PathRole) -> Result<(), GatewayRecipeError> {
        if path.is_empty() || path.len() > MAX_PATH_SEGMENTS {
            return Err(GatewayRecipeError::UnsafePath);
        }
        let mut response_fields = 0;
        for segment in path {
            match segment {
                PathSegment::Fixed { value } => {
                    if !valid_fixed_segment(value) {
                        return Err(GatewayRecipeError::UnsafePath);
                    }
                }
                PathSegment::Field { name } => {
                    if !self.path_field(name)
                        || is_namespace_or_recipe_field(name)
                    {
                        return Err(GatewayRecipeError::UnsafePath);
                    }
                    self.consume(name);
                }
                PathSegment::ResponseField { pointer, max_bytes } => {
                    response_fields += 1;
                    if response_fields > role.response_fields()
                        || !valid_response_pointer(pointer)
                        || !(1..=MAX_RESPONSE_FIELD_BYTES).contains(max_bytes)
                    {
                        return Err(role.response_error());
                    }
                }
                PathSegment::Echo => return Err(GatewayRecipeError::EchoConflict),
            }
        }
        Ok(())
    }

    fn field_ref(&mut self, name: &str) -> Result<(), GatewayRecipeError> {
        if !self.fields.contains_key(name)
            || !auths_gateway_kernel::template_ast::rendered_field_allowed(name.as_bytes())
        {
            return Err(GatewayRecipeError::UnsafeTemplate);
        }
        self.consume(name);
        self.consumed.body.insert(name.to_owned());
        Ok(())
    }

    fn body(&mut self, body: &BodySource) -> Result<(), GatewayRecipeError> {
        let mut nodes = 0;
        match body {
            BodySource::Json { value } => self.value_expr(value, 0, &mut nodes),
            BodySource::Form { fields: form } => {
                if form.is_empty() || form.len() > MAX_FORM_FIELDS {
                    return Err(GatewayRecipeError::UnsafeTemplate);
                }
                for (name, value) in form {
                    if matches!(value, FormExpr::Echo) {
                        return Err(GatewayRecipeError::EchoConflict);
                    }
                    if !valid_field_name(name) {
                        return Err(GatewayRecipeError::UnsafeTemplate);
                    }
                    match value {
                        FormExpr::String { value } if value.len() <= MAX_LITERAL_BYTES => {}
                        FormExpr::Field { name } => {
                            if !self.form_field(name) {
                                return Err(GatewayRecipeError::UnsafeTemplate);
                            }
                            self.field_ref(name)?;
                        }
                        FormExpr::Json { value } => {
                            if !form_json_shape(value) {
                                return Err(GatewayRecipeError::UnsafeTemplate);
                            }
                            self.value_expr(value, 0, &mut nodes)?;
                        }
                        FormExpr::String { .. } | FormExpr::Echo => {
                            return Err(GatewayRecipeError::UnsafeTemplate);
                        }
                    }
                }
                Ok(())
            }
        }
    }

    fn value_expr(
        &mut self,
        value: &ValueExpr,
        depth: usize,
        nodes: &mut usize,
    ) -> Result<(), GatewayRecipeError> {
        *nodes = auths_gateway_kernel::template_ast::charge_node(*nodes, depth)
            .map_err(|_| GatewayRecipeError::UnsafeTemplate)?;
        match value {
            ValueExpr::String { value } if value.len() <= MAX_LITERAL_BYTES => Ok(()),
            ValueExpr::Integer { value } if value.unsigned_abs() <= MAX_SAFE_INTEGER => Ok(()),
            ValueExpr::Boolean { .. } => Ok(()),
            ValueExpr::Field { name } => self.field_ref(name),
            ValueExpr::Object { fields: object } if !object.is_empty() && object.len() <= 32 => {
                for (key, child) in object {
                    if !valid_field_name(key) {
                        return Err(GatewayRecipeError::UnsafeTemplate);
                    }
                    self.value_expr(child, depth + 1, nodes)?;
                }
                Ok(())
            }
            ValueExpr::Array { items } if !items.is_empty() && items.len() <= 16 => {
                for child in items {
                    self.value_expr(child, depth + 1, nodes)?;
                }
                Ok(())
            }
            ValueExpr::Echo => Err(GatewayRecipeError::EchoConflict),
            _ => Err(GatewayRecipeError::UnsafeTemplate),
        }
    }

    fn observation(&mut self, source: &ObservationSource) -> Result<(), GatewayRecipeError> {
        self.path(&source.path, PathRole::Observation)?;
        if source.maximum_response_bytes == 0
            || source.maximum_response_bytes > 65_536
            || !valid_response_pointer(&source.json_pointer)
        {
            return Err(GatewayRecipeError::UnsafeTemplate);
        }
        if !self.fields.contains_key(&source.expected_field)
            || is_namespace_or_recipe_field(&source.expected_field)
        {
            return Err(GatewayRecipeError::UnsafeTemplate);
        }
        self.consume(&source.expected_field);
        Ok(())
    }

    /// Admits precondition arguments: each must be a non-binding profile
    /// field that no request template uses, appear once, and map to a fact
    /// value. The read-back subject must be a bounded string, needs an
    /// observation, and cannot name a record located by the write response.
    fn preconditions(
        &mut self,
        source: &PreconditionSource,
        observation: Option<&ObservationSource>,
    ) -> Result<(), GatewayRecipeError> {
        if source.read_back_subject.is_none() && source.verified.is_empty() {
            return Err(GatewayRecipeError::InvalidSource);
        }
        if source.verified.len() > MAX_VERIFIED_FIELDS {
            return Err(GatewayRecipeError::PreconditionConflict);
        }
        if let Some(subject) = &source.read_back_subject {
            let observation =
                observation.ok_or(GatewayRecipeError::PreconditionWithoutObservation)?;
            if super::lower::contains_response_field(&observation.path) {
                return Err(GatewayRecipeError::PreconditionConflict);
            }
            let admissible = self.text_fact_field(subject);
            self.claim_unused(subject, admissible)?;
        }
        self.claim_verified(&source.verified)
    }

    fn claim_verified(&mut self, names: &[String]) -> Result<(), GatewayRecipeError> {
        let mut position = 0;
        let mut failure = None;
        while position < names.len() && failure.is_none() {
            let name = &names[position];
            let admissible = self.fact_field(name);
            match self.claim_unused(name, admissible) {
                Ok(()) => {}
                Err(error) => failure = Some(error),
            }
            position += 1;
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn claim_unused(&mut self, name: &str, admissible: bool) -> Result<(), GatewayRecipeError> {
        if !admissible || is_binding_field(name) || !self.consumed.all.insert(name.to_owned()) {
            return Err(GatewayRecipeError::PreconditionConflict);
        }
        Ok(())
    }

    fn pre_entry(&mut self, source: &PreEntrySource) -> Result<(), GatewayRecipeError> {
        self.path(&source.path, PathRole::PreEntry)?;
        if !pre_entry_pointers_valid(&source.pointers, source.maximum_response_bytes) {
            return Err(GatewayRecipeError::InvalidPreEntry);
        }
        Ok(())
    }

    fn integer_body_field(&self, name: &str) -> bool {
        self.integer_field(name) && self.consumed.body.contains(name)
    }

    fn relative_ceiling(
        &mut self,
        source: &RelativeCeilingSource,
    ) -> Result<(), GatewayRecipeError> {
        let invalid = GatewayRecipeError::InvalidRelativeCeiling;
        if !self.integer_body_field(&source.argument)
            || !(1..=MAX_BASIS_POINTS).contains(&source.basis_points)
            || !read_bound_valid(source.maximum_response_bytes)
            || !valid_response_pointer(&source.json_pointer)
        {
            return Err(invalid);
        }
        if let Some(subtract) = &source.subtract_pointer
            && (!valid_response_pointer(subtract) || *subtract == source.json_pointer)
        {
            return Err(invalid);
        }
        if let Some(binds) = &source.bind {
            if !relative_binds_valid(self.fields, binds, &source.argument) {
                return Err(invalid);
            }
        }
        self.path(&source.path, PathRole::RelativeCeiling)?;
        if let Some(binds) = &source.bind {
            self.consume_binds(binds);
        }
        Ok(())
    }

    fn consume_binds(&mut self, binds: &[BindSource]) {
        let mut position = 0;
        while position < binds.len() {
            let bind = &binds[position];
            self.consume(&bind.field);
            self.consumed.binds.insert(bind.field.clone());
            position += 1;
        }
    }

    fn idempotency(
        source: &IdempotencySource,
        body: &BodySource,
    ) -> Result<(), GatewayRecipeError> {
        let invalid = GatewayRecipeError::InvalidIdempotency;
        if !(1..=MAX_RETENTION_SECONDS).contains(&source.retention_seconds()) {
            return Err(invalid);
        }
        match source {
            IdempotencySource::DerivedHeader { .. } => Ok(()),
            IdempotencySource::OperationIdField { location, .. } => {
                if operation_id_location(location, body) {
                    Ok(())
                } else {
                    Err(invalid)
                }
            }
        }
    }

    fn string_field(&self, name: &str) -> bool {
        match self.fields.get(name) {
            Some(FieldSchema::String { .. } | FieldSchema::Enum { .. }) => true,
            _ => false,
        }
    }

    /// The account-scope header names a registered account-scope header and
    /// takes its value from a string field nothing else renders.
    pub(super) fn account_scope(
        &mut self,
        source: &AccountScopeSource,
    ) -> Result<(), GatewayRecipeError> {
        let registered = auths_gateway_kernel::header_compiler::account_scope_header_name(source.header.as_bytes());
        if !registered
            || !self.string_field(&source.field)
            || is_binding_field(&source.field)
            || self.consumed.all.contains(&source.field)
        {
            return Err(GatewayRecipeError::InvalidAccountScope);
        }
        self.consume(&source.field);
        Ok(())
    }

    /// The sum bound's argument is an integer the body renders, and its
    /// partition is a string field that reaches the provider or is bound to
    /// the provider record.
    pub(super) fn bounds(
        &self,
        source: &BoundsSource,
        account_scope: Option<&AccountScopeSource>,
    ) -> Result<(), GatewayRecipeError> {
        let invalid = GatewayRecipeError::InvalidBounds;
        let sum = source.sum.as_ref().ok_or(invalid)?;
        if !self.integer_body_field(&sum.argument) {
            return Err(invalid);
        }
        let Some(partition) = &sum.partition else {
            return Ok(());
        };
        if *partition == sum.argument
            || !self.string_field(partition)
            || is_binding_field(partition)
        {
            return Err(invalid);
        }
        if partition_bound(&self.consumed, account_scope, partition) {
            Ok(())
        } else {
            Err(GatewayRecipeError::UnboundPartition)
        }
    }
}

/// Whether `location` resolves, in the body template, to a field reference
/// to `operation_id`.
fn operation_id_location(location: &IdempotencyLocation, body: &BodySource) -> bool {
    match body {
        BodySource::Json { value } => {
            if location.form_field.is_some() || location.pointer.is_some() { return false; }
            match &location.json_pointer {
                Some(pointer) => template_is_operation_id(value, pointer),
                None => false,
            }
        }
        BodySource::Form { fields } => {
            if location.json_pointer.is_some() { return false; }
            let Some(field) = &location.form_field else { return false; };
            match fields.get(field) {
                Some(FormExpr::Field { name }) => location.pointer.is_none()
                    && auths_gateway_kernel::construct::field_name_equal(name.as_bytes(), b"operation_id"),
                Some(FormExpr::Json { value }) => match &location.pointer {
                    Some(pointer) => template_is_operation_id(value, pointer),
                    None => false,
                },
                _ => false,
            }
        }
    }
}

fn is_operation_id(value: &ValueExpr) -> bool {
    match value {
        ValueExpr::Field { name } => auths_gateway_kernel::construct::field_name_equal(name.as_bytes(), b"operation_id"),
        _ => false,
    }
}

fn template_is_operation_id(value: &ValueExpr, pointer: &str) -> bool {
    match template_at(value, pointer) {
        Some(selected) => is_operation_id(selected),
        None => false,
    }
}

/// The template node at an unescaped JSON pointer of object keys and array
/// indices.
fn template_at<'a>(value: &'a ValueExpr, pointer: &str) -> Option<&'a ValueExpr> {
    if !valid_response_pointer(pointer) || pointer.as_bytes().contains(&b'~') {
        return None;
    }
    template_at_token(value, pointer, 1)
}

fn template_at_token<'a>(value: &'a ValueExpr, pointer: &str, start: usize) -> Option<&'a ValueExpr> {
    let bytes = pointer.as_bytes();
    let mut end = start;
    while end < bytes.len() && bytes[end] != b'/' { end += 1; }
    // ASCII separators are UTF-8 boundaries. get still refuses an invalid
    // direct helper cursor instead of assuming that representation fact.
    let token = pointer.get(start..end)?;
    let selected = match value {
        ValueExpr::Object { fields } => fields.get(token)?,
        ValueExpr::Array { items } => items.get(template_array_index(token.as_bytes())?)?,
        _ => return None,
    };
    if end == bytes.len() {
        Some(selected)
    } else {
        template_at_token(selected, pointer, end + 1)
    }
}

fn template_array_index(token: &[u8]) -> Option<usize> {
    if token.is_empty() || (token.len() > 1 && token[0] == b'0') { return None; }
    let mut position = 0;
    let mut value = 0_usize;
    let mut valid = true;
    while position < token.len() && valid {
        let byte = token[position];
        if byte < b'0' || byte > b'9' {
            valid = false;
        } else {
            match value.checked_mul(10) {
                None => valid = false,
                Some(product) => match product.checked_add(usize::from(byte - b'0')) {
                    None => valid = false,
                    Some(next) => value = next,
                },
            }
        }
        position += 1;
    }
    if valid { Some(value) } else { None }
}

/// A form echo name: `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`, optionally followed
/// by one bracketed segment of the same grammar.
/// The echo lands on a new key inside a fixed JSON object of the body
/// template, or in one new form field; never on a profile argument, a
/// literal, an array element, a path segment, or the compared observation
/// value.
pub(super) fn validate_echo(
    echo: &EchoSource,
    body: &BodySource,
    observation: &ObservationSource,
) -> Result<(), GatewayRecipeError> {
    if !valid_response_pointer(&echo.observe) {
        return Err(GatewayRecipeError::UnsafeTemplate);
    }
    if pointers_overlap(&echo.observe, &observation.json_pointer) {
        return Err(GatewayRecipeError::EchoConflict);
    }
    match (&echo.write, body) {
        (EchoPlacement::JsonPointer { pointer }, BodySource::Json { value }) => {
            validate_json_echo(pointer, value)
        }
        (EchoPlacement::FormField { name }, BodySource::Form { fields }) => {
            if fields.is_empty() || fields.len() > MAX_FORM_FIELDS
                || !form_member_names_valid(fields)
            {
                return Err(GatewayRecipeError::EchoConflict);
            }
            let keys = form_member_keys(fields);
            auths_gateway_kernel::template_members::canonical_members(
                &keys, Some(name.as_bytes()), auths_gateway_kernel::template_members::MemberDomain::Form,
            ).map(|_| ()).map_err(|_| GatewayRecipeError::EchoConflict)
        }
        _ => Err(GatewayRecipeError::EchoConflict),
    }
}

fn validate_json_echo(pointer: &str, value: &ValueExpr) -> Result<(), GatewayRecipeError> {
    use auths_gateway_kernel::template_members;
    let tokens = template_members::echo_pointer_tokens(pointer.as_bytes())
        .map_err(|_| GatewayRecipeError::EchoConflict)?;
    validate_json_echo_tokens(value, &tokens)
}

fn form_member_names_valid(fields: &BTreeMap<String, FormExpr>) -> bool {
    for (name, _) in fields {
        if !valid_field_name(name) { return false; }
    }
    true
}

fn json_member_names_valid(fields: &BTreeMap<String, ValueExpr>) -> bool {
    for (name, _) in fields {
        if !valid_field_name(name) { return false; }
    }
    true
}

fn form_member_keys(fields: &BTreeMap<String, FormExpr>) -> Vec<auths_gateway_kernel::template_members::NamedKey> {
    let mut keys = Vec::new();
    for (name, _) in fields {
        keys.push(auths_gateway_kernel::template_members::NamedKey { name: name.as_bytes().to_vec() });
    }
    keys
}

fn json_member_keys(fields: &BTreeMap<String, ValueExpr>) -> Vec<auths_gateway_kernel::template_members::NamedKey> {
    let mut keys = Vec::new();
    for (name, _) in fields {
        keys.push(auths_gateway_kernel::template_members::NamedKey { name: name.as_bytes().to_vec() });
    }
    keys
}

// Each descent consumes one original token. The public decoder admits at
// most six tokens, and the selected child remains in the original object.
fn validate_json_echo_tokens(value: &ValueExpr, tokens: &[Vec<u8>]) -> Result<(), GatewayRecipeError> {
    use auths_gateway_kernel::template_members::{self, EchoTarget};
    let ValueExpr::Object { fields } = value else {
        return Err(GatewayRecipeError::EchoConflict);
    };
    if fields.is_empty() || fields.len() > 32 || !json_member_names_valid(fields) {
        return Err(GatewayRecipeError::EchoConflict);
    }
    let keys = json_member_keys(fields);
    match template_members::json_echo_target(&keys, tokens).map_err(|_| GatewayRecipeError::EchoConflict)? {
        EchoTarget::Insert => Ok(()),
        EchoTarget::Descend(_) => {
            // The target checker earned an exact existing first-token key.
            // Look up that key in the original object, without retaining an
            // allocated column of references into its children.
            let token = tokens.first().ok_or(GatewayRecipeError::EchoConflict)?;
            let key = std::str::from_utf8(token).map_err(|_| GatewayRecipeError::EchoConflict)?;
            let child = fields.get(key).ok_or(GatewayRecipeError::EchoConflict)?;
            let remaining = tokens.get(1..).ok_or(GatewayRecipeError::EchoConflict)?;
            validate_json_echo_tokens(child, remaining)
        }
    }
}

/// The version headers: one or two registered `version`-class names, each
/// with a value its grammar allows.
pub(super) fn validate_provider_headers(
    headers: &BTreeMap<String, String>,
) -> Result<(), GatewayRecipeError> {
    if headers.is_empty() || headers.len() > MAX_PROVIDER_HEADERS {
        return Err(GatewayRecipeError::InvalidProviderHeader);
    }
    // Validate every borrowed name/value before allocating the owned view.
    if !provider_versions_valid(headers) {
        return Err(GatewayRecipeError::InvalidProviderHeader);
    }
    let named = provider_version_entries(headers);
    if !auths_gateway_kernel::header_compiler::version_headers_valid(&named) {
        return Err(GatewayRecipeError::InvalidProviderHeader);
    }
    Ok(())
}

fn provider_versions_valid(headers: &BTreeMap<String, String>) -> bool {
    for (name, value) in headers {
        if !auths_gateway_kernel::header_compiler::version_header_valid(name.as_bytes(), value.as_bytes()) {
            return false;
        }
    }
    true
}

fn provider_version_entries(headers: &BTreeMap<String, String>) -> Vec<auths_gateway_kernel::header_compiler::NamedHeader> {
    let mut named = Vec::new();
    for (name, value) in headers {
        named.push(auths_gateway_kernel::header_compiler::NamedHeader {
            name: name.as_bytes().to_vec(), value: value.as_bytes().to_vec(),
        });
    }
    named
}

fn guard_prefix_valid(prefix: &str) -> bool {
    let bytes = prefix.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_GUARD_PREFIX_BYTES { return false; }
    let mut position = 0;
    let mut valid = true;
    while position < bytes.len() && valid {
        valid = bytes[position] >= 0x21 && bytes[position] <= 0x7e;
        position += 1;
    }
    valid
}

fn validate_prefixes(prefixes: &[String]) -> Result<(), GatewayRecipeError> {
    if prefixes.is_empty() || prefixes.len() > MAX_GUARD_PREFIXES {
        return Err(GatewayRecipeError::InvalidCredentialGuard);
    }
    let mut position = 0;
    let mut valid = true;
    while position < prefixes.len() && valid {
        valid = guard_prefix_valid(&prefixes[position]) && !string_seen_before(prefixes, position);
        position += 1;
    }
    if !valid { return Err(GatewayRecipeError::InvalidCredentialGuard); }
    Ok(())
}

fn probe_literal_valid(value: &Value) -> bool {
    match value {
        Value::Bool(_) => true,
        Value::String(text) => text.len() <= MAX_PROBE_TEXT_BYTES,
        Value::Number(number) => number
            .as_i64()
            .map(i64::unsigned_abs)
            .or_else(|| number.as_u64())
            .is_some_and(|magnitude| magnitude <= MAX_SAFE_INTEGER),
        Value::Null | Value::Array(_) | Value::Object(_) => false,
    }
}

fn validate_probe(probe: &ProbeSource) -> Result<Vec<String>, GatewayRecipeError> {
    let path = fixed_path(&probe.path)?;
    if !valid_response_pointer(&probe.json_pointer)
        || !probe_literal_valid(&probe.equals)
        || !read_bound_valid(probe.maximum_response_bytes)
    {
        return Err(GatewayRecipeError::InvalidCredentialGuard);
    }
    Ok(path)
}

fn validate_account_read(account: &AccountReadSource) -> Result<Vec<String>, GatewayRecipeError> {
    let path = fixed_path(&account.path)?;
    if !valid_response_pointer(&account.json_pointer)
        || !read_bound_valid(account.maximum_response_bytes)
    {
        return Err(GatewayRecipeError::InvalidCredentialGuard);
    }
    Ok(path)
}

fn refused_statuses_valid(statuses: &[u64]) -> bool {
    if statuses.is_empty() || statuses.len() > MAX_REFUSED_STATUSES {
        return false;
    }
    let mut position = 0;
    let mut valid = true;
    while position < statuses.len() && valid {
        valid = refused_status_valid_at(statuses, position);
        position += 1;
    }
    valid
}

fn refused_status_valid_at(statuses: &[u64], position: usize) -> bool {
    let Some(status) = statuses.get(position) else { return false; };
    if !(400..=499).contains(status) || matches!(*status, 408 | 429) { return false; }
    let mut previous = 0;
    let mut unique = true;
    while previous < position && unique {
        unique = statuses[previous] != *status;
        previous += 1;
    }
    unique
}

fn validate_denied_reads(
    reads: &[DeniedReadSource],
    reserved: &[Vec<String>],
) -> Result<(), GatewayRecipeError> {
    let invalid = GatewayRecipeError::InvalidCredentialGuard;
    if reads.is_empty() || reads.len() > MAX_DENIED_READS {
        return Err(invalid);
    }
    let mut seen: Vec<Vec<String>> = Vec::new();
    let mut position = 0;
    let mut failure = None;
    while position < reads.len() && failure.is_none() {
        match validate_denied_read(&reads[position], reserved, &mut seen) {
            Ok(()) => {}
            Err(error) => failure = Some(error),
        }
        position += 1;
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn denied_path_allowed(read: &DeniedReadSource, path: &[String], seen: &[Vec<String>], reserved: &[Vec<String>]) -> bool {
    (auths_gateway_kernel::construct::field_name_equal(read.method.as_bytes(), b"GET")
        || auths_gateway_kernel::construct::field_name_equal(read.method.as_bytes(), b"HEAD"))
        && refused_statuses_valid(&read.refused_status)
        && !path_seen(seen, path) && !path_seen(reserved, path)
}

fn path_seen(paths: &[Vec<String>], candidate: &[String]) -> bool {
    let mut position = 0;
    let mut seen = false;
    while position < paths.len() && !seen {
        seen = fixed_paths_equal(&paths[position], candidate);
        position += 1;
    }
    seen
}

fn fixed_paths_equal(left: &[String], right: &[String]) -> bool {
    if left.len() != right.len() { return false; }
    let mut position = 0;
    let mut equal = true;
    while position < left.len() && equal {
        equal = auths_gateway_kernel::construct::field_name_equal(left[position].as_bytes(), right[position].as_bytes());
        position += 1;
    }
    equal
}

fn validate_denied_read(read: &DeniedReadSource, reserved: &[Vec<String>], seen: &mut Vec<Vec<String>>) -> Result<(), GatewayRecipeError> {
    let checked = fixed_path(&read.path);
    match &checked {
        Err(error) => Err(*error),
        Ok(path) => {
            if !denied_path_allowed(read, path, seen, reserved) {
                return Err(GatewayRecipeError::InvalidCredentialGuard);
            }
            // At most four previously admitted, sixteen-segment paths.
            seen.push(path.clone());
            Ok(())
        }
    }
}

fn reserve_fixed_path(reserved: &mut Vec<Vec<String>>, path: &[PathSegment]) {
    if let Some(values) = fixed_values(path) {
        reserved.push(values);
    }
}

fn validate_guard_denied(
    reads: &[DeniedReadSource],
    mut reserved: Vec<Vec<String>>,
    source: &RecipeSource,
) -> Result<(), GatewayRecipeError> {
    reserve_fixed_path(&mut reserved, &source.write.path);
    if let Some(observation) = &source.observation {
        reserve_fixed_path(&mut reserved, &observation.path);
    }
    if let Some(pre_entry) = &source.pre_entry {
        reserve_fixed_path(&mut reserved, &pre_entry.path);
    }
    if let Some(ceiling) = &source.relative_ceiling {
        reserve_fixed_path(&mut reserved, &ceiling.path);
    }
    validate_denied_reads(reads, &reserved)
}

/// The credential guard. Denied-read paths must differ from each other, from
/// the probe and account paths, and from every declared all-fixed path.
pub(super) fn validate_guard(
    guard: &GuardSource,
    source: &RecipeSource,
) -> Result<(), GatewayRecipeError> {
    validate_prefixes(&guard.prefixes)?;
    let mut reserved: Vec<Vec<String>> = Vec::new();
    if let Some(probe) = &guard.probe {
        reserved.push(validate_probe(probe)?);
    }
    if let Some(account) = &guard.account {
        reserved.push(validate_account_read(account)?);
    }
    match &guard.denied_reads {
        Some(reads) => validate_guard_denied(reads, reserved, source),
        None => Ok(()),
    }
}

/// Every rule that reads the whole source, run in dependency order: the
/// request templates first, then the declarations that name the fields those
/// templates consume.
pub(super) fn validate_source<'a>(
    source: &'a RecipeSource,
    lock: &ProfileLockFile,
    canonical: &'a super::CanonicalRecipeInputs,
) -> Result<ValidatedSource<'a>, GatewayRecipeError> {
    if !recipe_binding::source_schema_supported(source.schema.as_bytes()) {
        return Err(GatewayRecipeError::InvalidSource);
    }
    super::validate_lock(lock, &canonical.schema)?;
    if !recipe_binding::source_matches_profile(
        ProfileBinding { service: source.service.as_bytes(), tool: source.tool.as_bytes(), schema_digest: source.profile_schema_digest.as_bytes() },
        ProfileBinding { service: lock.service.as_bytes(), tool: lock.tool.as_bytes(), schema_digest: lock.schema_digest.as_bytes() },
    ) {
        return Err(GatewayRecipeError::ProfileMismatch);
    }
    let field_specs = super::parse_root_fields(&lock.command_schema)?;
    let namespace = OperatorNamespace::parse(&source.operator_namespace)?;
    super::validate_binding_fields(&field_specs, &namespace)?;
    let fields = super::profile::rule_fields(&field_specs)?;
    super::credential_requirement(&source.credential).validate()?;
    let parsed_host = super::validate_origin(&source.origin)?;
    validate_source_rules(source, &fields)?;
    Ok(ValidatedSource { source, field_specs, namespace, parsed_host, canonical_source: &canonical.source })
}

// Keep the transient mutable consumption ledger inside admission. Only the
// original source and owned, checked columns cross the constructor boundary.
fn validate_source_rules(
    source: &RecipeSource,
    fields: &BTreeMap<String, FieldSchema>,
) -> Result<(), GatewayRecipeError> {
    let mut rules = Rules {
        fields,
        consumed: Consumption::default(),
    };
    validate_write_rules(&mut rules, source)?;
    validate_response_rules(&mut rules, source)?;
    validate_fact_rules(&mut rules, source)?;
    validate_header_guard_rules(source)?;
    validate_bound_rules(&mut rules, source)?;
    if !all_fields_consumed(fields, &rules.consumed.all) {
        return Err(GatewayRecipeError::UnsafeTemplate);
    }
    Ok(())
}

// Each group closes its optional branches before the next group borrows the
// ledger. This bounds translation growth without changing admission order.
fn validate_write_rules(rules: &mut Rules<'_>, source: &RecipeSource) -> Result<(), GatewayRecipeError> {
    rules.path(&source.write.path, PathRole::Write)?;
    rules.body(&source.write.body)?;
    if let Some(idempotency) = &source.write.idempotency {
        Rules::idempotency(idempotency, &source.write.body)?;
    }
    Ok(())
}

fn validate_response_rules(rules: &mut Rules<'_>, source: &RecipeSource) -> Result<(), GatewayRecipeError> {
    if let Some(observation) = &source.observation {
        rules.observation(observation)?;
    }
    if let Some(echo) = &source.echo {
        let observation = source
            .observation
            .as_ref()
            .ok_or(GatewayRecipeError::EchoWithoutObservation)?;
        validate_echo(echo, &source.write.body, observation)?;
    }
    if let Some(pre_entry) = &source.pre_entry {
        rules.pre_entry(pre_entry)?;
    }
    Ok(())
}

fn validate_fact_rules(rules: &mut Rules<'_>, source: &RecipeSource) -> Result<(), GatewayRecipeError> {
    if let Some(ceiling) = &source.relative_ceiling {
        rules.relative_ceiling(ceiling)?;
    }
    if let Some(preconditions) = &source.preconditions {
        rules.preconditions(preconditions, source.observation.as_ref())?;
    }
    Ok(())
}

fn validate_header_guard_rules(source: &RecipeSource) -> Result<(), GatewayRecipeError> {
    if let Some(headers) = &source.provider_headers {
        validate_provider_headers(headers)?;
    }
    if let Some(guard) = source.credential.guard() {
        validate_guard(guard, source)?;
    }
    Ok(())
}

fn validate_bound_rules(rules: &mut Rules<'_>, source: &RecipeSource) -> Result<(), GatewayRecipeError> {
    if let Some(scope) = &source.account_scope {
        rules.account_scope(scope)?;
    }
    if let Some(bounds) = &source.bounds {
        rules.bounds(bounds, source.account_scope.as_ref())?;
    }
    Ok(())
}

/// Immutable original source, exact verified-lock field pairs, namespace and
/// parsed host after the complete native admission sequence succeeded. The
/// private constructor prevents lowering/hash callers from replacing a field
/// map, namespace or host independently. Parsing/canonicalization/SHA contracts
/// and the constructor's formal source proof remain separate obligations.
/// This grants no installation or action authority.
pub(super) struct ValidatedSource<'a> {
    source: &'a RecipeSource,
    field_specs: Vec<FieldSpec>,
    namespace: OperatorNamespace,
    parsed_host: String,
    canonical_source: &'a Result<Vec<u8>, ()>,
}

impl ValidatedSource<'_> {
    pub(super) const fn source(&self) -> &RecipeSource {
        self.source
    }

    pub(super) fn field_specs(&self) -> &[FieldSpec] {
        &self.field_specs
    }

    pub(super) fn parsed_host(&self) -> &str {
        &self.parsed_host
    }

    /// Hashes only the canonical original source held by this admission.
    pub(super) fn digest(&self) -> Result<[u8; 32], GatewayRecipeError> {
        let canonical = match self.canonical_source {
            Ok(bytes) => bytes.as_slice(),
            Err(()) => return Err(GatewayRecipeError::InvalidSource),
        };
        let input = recipe_binding::recipe_digest_input(canonical);
        let mut hasher = Sha256::new();
        hasher.update(input.domain);
        hasher.update(input.canonical_source);
        Ok(hasher.finalize().into())
    }

    pub(super) fn into_namespace(self) -> OperatorNamespace {
        self.namespace
    }
}

#[cfg(test)]
mod bounded_source_tests {
    use super::*;

    fn object(leaves: usize) -> ValueExpr {
        ValueExpr::Object {
            fields: (0..leaves).map(|index| (format!("a{index:02}"), ValueExpr::Boolean { value: true })).collect(),
        }
    }

    #[test]
    fn native_node_charge_keeps_inclusive_limits_and_refuses_before_increment() {
        let fields = BTreeMap::new();
        let mut rules = Rules { fields: &fields, consumed: Consumption::default() };
        let leaf = ValueExpr::Boolean { value: true };
        let mut nodes = 63;
        assert_eq!(rules.value_expr(&leaf, 6, &mut nodes), Ok(()));
        assert_eq!(nodes, 64);
        assert_eq!(rules.value_expr(&leaf, 6, &mut nodes), Err(GatewayRecipeError::UnsafeTemplate));
        assert_eq!(nodes, 64);
        let mut nodes = 0;
        assert_eq!(rules.value_expr(&leaf, 7, &mut nodes), Err(GatewayRecipeError::UnsafeTemplate));
        assert_eq!(nodes, 0);
        let mut nodes = usize::MAX;
        assert_eq!(rules.value_expr(&leaf, 0, &mut nodes), Err(GatewayRecipeError::UnsafeTemplate));
        assert_eq!(nodes, usize::MAX);
        let mut nodes = 0;
        assert_eq!(rules.value_expr(&leaf, usize::MAX, &mut nodes), Err(GatewayRecipeError::UnsafeTemplate));
        assert_eq!(nodes, 0);
    }

    #[test]
    fn native_admission_shares_the_node_meter_across_distinct_form_json_values() {
        let fields = BTreeMap::new();
        let mut rules = Rules { fields: &fields, consumed: Consumption::default() };
        let body = BodySource::Form { fields: BTreeMap::from([
            ("a".into(), FormExpr::Json { value: object(31) }),
            ("b".into(), FormExpr::Json { value: object(31) }),
        ]) };
        assert_eq!(rules.body(&body), Ok(()));
        let too_many = BodySource::Form { fields: BTreeMap::from([
            ("a".into(), FormExpr::Json { value: object(32) }),
            ("b".into(), FormExpr::Json { value: object(32) }),
        ]) };
        assert_eq!(rules.body(&too_many), Err(GatewayRecipeError::UnsafeTemplate));
    }

    #[test]
    fn native_resource_refusal_precedes_authored_echo_dispatch() {
        let fields = BTreeMap::new();
        let mut rules = Rules { fields: &fields, consumed: Consumption::default() };
        let mut exhausted = 64;
        assert_eq!(rules.value_expr(&ValueExpr::Echo, 0, &mut exhausted), Err(GatewayRecipeError::UnsafeTemplate));
        let mut available = 0;
        assert_eq!(rules.value_expr(&ValueExpr::Echo, 0, &mut available), Err(GatewayRecipeError::EchoConflict));
    }

    #[test]
    fn bounded_status_scan_retains_the_original_status_language() {
        fn reference(statuses: &[u64]) -> bool {
            let unique: BTreeSet<u64> = statuses.iter().copied().collect();
            !statuses.is_empty()
                && statuses.len() <= MAX_REFUSED_STATUSES
                && unique.len() == statuses.len()
                && statuses.iter().all(|status| (400..=499).contains(status) && !matches!(status, 408 | 429))
        }
        fn compare(prefix: &mut Vec<u64>, remaining: usize) {
            assert_eq!(refused_statuses_valid(prefix), reference(prefix), "{prefix:?}");
            if remaining == 0 {
                return;
            }
            for status in [0, 399, 400, 401, 408, 429, 499, 500, u64::MAX] {
                prefix.push(status);
                compare(prefix, remaining - 1);
                let _ = prefix.pop();
            }
        }
        compare(&mut Vec::new(), MAX_REFUSED_STATUSES + 1);
    }

    #[test]
    fn bounded_prefix_scan_retains_the_original_prefix_language() {
        fn reference(prefixes: &[String]) -> bool {
            let unique: BTreeSet<&str> = prefixes.iter().map(String::as_str).collect();
            !prefixes.is_empty()
                && prefixes.len() <= MAX_GUARD_PREFIXES
                && unique.len() == prefixes.len()
                && prefixes.iter().all(|prefix| {
                    !prefix.is_empty()
                        && prefix.len() <= MAX_GUARD_PREFIX_BYTES
                        && prefix.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
                })
        }
        let corpus = [
            String::new(), "a".into(), "A".into(), "a-b_".into(), " ".into(),
            "a b".into(), "\n".into(), "\u{7f}".into(), "é".into(),
            "x".repeat(MAX_GUARD_PREFIX_BYTES), "x".repeat(MAX_GUARD_PREFIX_BYTES + 1),
        ];
        for first in &corpus {
            for second in &corpus {
                for values in [vec![first.clone()], vec![first.clone(), second.clone()],
                    vec![first.clone(), second.clone(), first.clone()]] {
                    assert_eq!(validate_prefixes(&values).is_ok(), reference(&values), "{values:?}");
                }
            }
        }
        let exact = vec!["a".into(), "b".into(), "c".into(), "d".into()];
        assert!(validate_prefixes(&exact).is_ok());
        let mut oversized = exact;
        oversized.push("e".into());
        assert_eq!(validate_prefixes(&oversized), Err(GatewayRecipeError::InvalidCredentialGuard));
        assert_eq!(validate_prefixes(&[]), Err(GatewayRecipeError::InvalidCredentialGuard));
    }

    #[test]
    fn credential_fixed_path_keeps_exact_count_and_kind_refusals() {
        let exact = vec![PathSegment::Fixed { value: "v1".into() }; MAX_PATH_SEGMENTS];
        assert_eq!(fixed_path(&exact), Ok(vec!["v1".to_owned(); MAX_PATH_SEGMENTS]));
        let mut oversized = exact;
        oversized.push(PathSegment::Fixed { value: "extra".into() });
        assert_eq!(fixed_path(&oversized), Err(GatewayRecipeError::InvalidCredentialGuard));
        assert_eq!(fixed_path(&[]), Err(GatewayRecipeError::InvalidCredentialGuard));
        assert_eq!(fixed_path(&[PathSegment::Field { name: "payment_id".into() }]),
            Err(GatewayRecipeError::InvalidCredentialGuard));
    }

    #[test]
    fn bounded_pre_entry_scan_retains_duplicates_and_four_pointer_limit() {
        let fields = BTreeMap::new();
        let mut rules = Rules { fields: &fields, consumed: Consumption::default() };
        let mut source = PreEntrySource {
            path: vec![PathSegment::Fixed { value: "v1".into() }],
            pointers: vec!["/a".into(), "/b".into(), "/c".into(), "/d".into()],
            maximum_response_bytes: 1,
        };
        assert_eq!(rules.pre_entry(&source), Ok(()));
        source.pointers[3] = "/a".into();
        assert_eq!(rules.pre_entry(&source), Err(GatewayRecipeError::InvalidPreEntry));
        source.pointers[3] = "/d".into();
        source.pointers.push("/e".into());
        assert_eq!(rules.pre_entry(&source), Err(GatewayRecipeError::InvalidPreEntry));
        source.pointers.clear();
        assert_eq!(rules.pre_entry(&source), Err(GatewayRecipeError::InvalidPreEntry));
    }

    #[test]
    fn byte_pointer_scans_retain_original_utf8_and_token_boundaries() {
        fn reference(pointer: &str) -> bool {
            pointer.starts_with('/') && pointer.len() <= MAX_POINTER_BYTES
                && pointer.split('/').skip(1).count() <= 8 && !pointer.contains("~2")
        }
        let mut pointers: Vec<String> = ["", "/", "//", "a", "/a", "/a/b", "/a~0", "/a~1", "/a~2", "/é/字段", "/0", "/01"]
            .into_iter().map(str::to_owned).collect();
        pointers.extend(["/a".repeat(8), "/a".repeat(9), format!("/{}", "x".repeat(127)), format!("/{}", "x".repeat(128))]);
        for pointer in &pointers {
            assert_eq!(valid_response_pointer(pointer), reference(pointer), "{pointer}");
        }
        for first in ["", "/", "/a", "/a/b", "/ab", "/é", "/é/a"] {
            for second in ["", "/", "/a", "/a/b", "/ab", "/é", "/é/a"] {
                let expected = first == second
                    || first.strip_prefix(second).is_some_and(|rest| rest.starts_with('/'))
                    || second.strip_prefix(first).is_some_and(|rest| rest.starts_with('/'));
                assert_eq!(pointers_overlap(first, second), expected, "{first:?} / {second:?}");
            }
        }
    }

    #[test]
    fn canonical_array_index_keeps_digit_and_word_overflow_refusals() {
        fn reference(token: &str) -> Option<usize> {
            if token.is_empty() || (token.len() > 1 && token.starts_with('0'))
                || !token.bytes().all(|byte| byte.is_ascii_digit()) {
                None
            } else { token.parse().ok() }
        }
        let mut tokens: Vec<String> = ["", "0", "1", "9", "10", "01", "00", "+1", "-1", "1.0", "1e2", "١"]
            .into_iter().map(str::to_owned).collect();
        tokens.push(usize::MAX.to_string());
        tokens.push((usize::MAX as u128 + 1).to_string());
        tokens.push("9".repeat(MAX_POINTER_BYTES));
        for token in tokens {
            assert_eq!(template_array_index(token.as_bytes()), reference(&token), "{token}");
        }
    }

    #[test]
    fn recursive_template_lookup_selects_the_original_named_child() {
        let value = ValueExpr::Object { fields: BTreeMap::from([
            ("nested".into(), ValueExpr::Object { fields: BTreeMap::from([
                ("operation_id".into(), ValueExpr::Field { name: "operation_id".into() }),
            ]) }),
            ("items".into(), ValueExpr::Array { items: vec![ValueExpr::Field { name: "operation_id".into() }] }),
            ("é".into(), ValueExpr::Boolean { value: true }),
        ]) };
        let ValueExpr::Object { fields } = &value else { panic!("test fixture is an object"); };
        let ValueExpr::Object { fields: nested } = &fields["nested"] else { panic!("nested fixture is an object"); };
        assert!(std::ptr::eq(template_at(&value, "/nested/operation_id").expect("original child"), &nested["operation_id"]));
        let ValueExpr::Array { items } = &fields["items"] else { panic!("items fixture is an array"); };
        assert!(std::ptr::eq(template_at(&value, "/items/0").expect("original array item"), &items[0]));
        assert!(std::ptr::eq(template_at(&value, "/é").expect("complete UTF-8 key"), &fields["é"]));
        for pointer in ["/items/01", "/items/1", "/items/+0", "/nested/operation", "/nested/operation_id/extra", "/~0"] {
            assert!(template_at(&value, pointer).is_none(), "{pointer}");
        }
    }

    #[test]
    fn idempotency_location_branches_keep_the_original_exclusive_location_rules() {
        fn reference(location: &IdempotencyLocation, body: &BodySource) -> bool {
            match (body, location) {
                (BodySource::Json { value }, IdempotencyLocation {
                    json_pointer: Some(pointer), form_field: None, pointer: None,
                }) => template_at(value, pointer).is_some_and(is_operation_id),
                (BodySource::Form { fields }, IdempotencyLocation {
                    json_pointer: None, form_field: Some(name), pointer,
                }) => match (fields.get(name), pointer) {
                    (Some(FormExpr::Field { name }), None) => name == "operation_id",
                    (Some(FormExpr::Json { value }), Some(pointer)) => {
                        template_at(value, pointer).is_some_and(is_operation_id)
                    }
                    _ => false,
                },
                _ => false,
            }
        }
        let value = ValueExpr::Object { fields: BTreeMap::from([
            ("id".into(), ValueExpr::Field { name: "operation_id".into() }),
            ("alias".into(), ValueExpr::Field { name: "operation_id_suffix".into() }),
            ("literal".into(), ValueExpr::String { value: "operation_id".into() }),
        ]) };
        let bodies = [
            BodySource::Json { value: value.clone() },
            BodySource::Form { fields: BTreeMap::from([
                ("id".into(), FormExpr::Field { name: "operation_id".into() }),
                ("alias".into(), FormExpr::Field { name: "operation_id_suffix".into() }),
                ("nested".into(), FormExpr::Json { value }),
            ]) },
        ];
        let pointers = [None, Some(""), Some("/id"), Some("/alias"), Some("/literal"), Some("/id/extra")];
        let fields = [None, Some("id"), Some("alias"), Some("nested"), Some("missing")];
        for body in &bodies {
            for json_pointer in pointers {
                for form_field in fields {
                    for pointer in pointers {
                        let location = IdempotencyLocation {
                            json_pointer: json_pointer.map(str::to_owned),
                            form_field: form_field.map(str::to_owned),
                            pointer: pointer.map(str::to_owned),
                        };
                        assert_eq!(operation_id_location(&location, body), reference(&location, body), "{location:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn echo_descent_retains_original_member_selection_and_refusal_order() {
        fn reference(pointer: &str, value: &ValueExpr) -> Result<(), GatewayRecipeError> {
            use auths_gateway_kernel::template_members::{self, EchoTarget, NamedKey};
            let tokens = template_members::echo_pointer_tokens(pointer.as_bytes())
                .map_err(|_| GatewayRecipeError::EchoConflict)?;
            let mut current = value;
            for position in 0..tokens.len() {
                let ValueExpr::Object { fields } = current else {
                    return Err(GatewayRecipeError::EchoConflict);
                };
                if fields.is_empty() || fields.len() > 32 || !fields.keys().all(|key| valid_field_name(key)) {
                    return Err(GatewayRecipeError::EchoConflict);
                }
                let members: Vec<_> = fields.iter().collect();
                let keys: Vec<_> = members.iter().map(|(key, _)| NamedKey { name: key.as_bytes().to_vec() }).collect();
                match template_members::json_echo_target(&keys, &tokens[position..])
                    .map_err(|_| GatewayRecipeError::EchoConflict)? {
                    EchoTarget::Insert => return Ok(()),
                    EchoTarget::Descend(index) => {
                        current = members.get(index).ok_or(GatewayRecipeError::EchoConflict)?.1;
                    }
                }
            }
            Err(GatewayRecipeError::EchoConflict)
        }
        let nested = ValueExpr::Object { fields: BTreeMap::from([
            ("first".into(), ValueExpr::Boolean { value: true }),
            ("last".into(), ValueExpr::Boolean { value: false }),
        ]) };
        let values = [
            ValueExpr::Object { fields: BTreeMap::from([
                ("alpha".into(), nested),
                ("middle".into(), ValueExpr::Boolean { value: true }),
                ("omega".into(), ValueExpr::Object { fields: BTreeMap::new() }),
            ]) },
            object(32), object(33),
            ValueExpr::Object { fields: BTreeMap::from([
                ("bad key".into(), ValueExpr::Boolean { value: true }),
            ]) },
            ValueExpr::Array { items: vec![object(1)] },
        ];
        for value in &values {
            for pointer in ["", "/fresh", "/alpha", "/alpha/fresh", "/alpha/first", "/middle/fresh", "/omega/fresh", "/missing/fresh", "/alpha/~1", "/a/b/c/d/e/f/g", "/a~2"] {
                assert_eq!(validate_json_echo(pointer, value), reference(pointer, value), "{pointer}: {value:?}");
            }
        }
    }

    #[test]
    fn precondition_scan_keeps_the_consumed_prefix_when_a_later_field_refuses() {
        fn reference(rules: &mut Rules<'_>, names: &[String]) -> Result<(), GatewayRecipeError> {
            for name in names {
                let admissible = rules.fact_field(name);
                rules.claim_unused(name, admissible)?;
            }
            Ok(())
        }
        let fields = BTreeMap::from([
            ("a".into(), FieldSchema::String { minimum: 1, maximum: 64 }),
            ("b".into(), FieldSchema::Boolean),
            ("operation_id".into(), FieldSchema::String { minimum: 1, maximum: 64 }),
        ]);
        for names in [
            vec![], vec!["a", "b"], vec!["a", "a", "b"],
            vec!["a", "missing", "b"], vec!["operation_id", "b"],
        ] {
            let names: Vec<String> = names.into_iter().map(str::to_owned).collect();
            for initial in [vec![], vec!["a"], vec!["b"]] {
                let mut actual = Rules { fields: &fields, consumed: Consumption::default() };
                let mut expected = Rules { fields: &fields, consumed: Consumption::default() };
                for name in initial {
                    actual.consume(name);
                    expected.consume(name);
                }
                assert_eq!(actual.claim_verified(&names), reference(&mut expected, &names));
                assert_eq!(actual.consumed.all, expected.consumed.all);
                assert_eq!(actual.consumed.body, expected.consumed.body);
                assert_eq!(actual.consumed.binds, expected.consumed.binds);
            }
        }
    }

    #[test]
    fn relative_binds_distinguish_duplicate_pointers_from_reused_fields() {
        let fields = BTreeMap::from([
            ("amount".into(), FieldSchema::Integer { minimum: 0, maximum: 100 }),
            ("record".into(), FieldSchema::String { minimum: 1, maximum: 64 }),
            ("flag".into(), FieldSchema::Boolean),
        ]);
        let bind = |pointer: &str, field: &str| BindSource { pointer: pointer.into(), field: field.into() };
        assert!(relative_binds_valid(&fields, &[], "amount"));
        assert!(relative_binds_valid(&fields, &[bind("/first", "record"), bind("/second", "record")], "amount"));
        for binds in [
            vec![bind("/first", "record"), bind("/first", "record")],
            vec![bind("/first", "amount")], vec![bind("/first", "flag")],
            vec![bind("/first", "missing")], vec![bind("first", "record")],
            vec![bind("/a", "record"), bind("/b", "record"), bind("/c", "record")],
        ] {
            assert!(!relative_binds_valid(&fields, &binds, "amount"), "{binds:?}");
        }
    }

    #[test]
    fn denied_reads_retain_the_original_full_path_and_status_comparisons() {
        fn reference(reads: &[DeniedReadSource], reserved: &[Vec<String>]) -> Result<(), GatewayRecipeError> {
            let invalid = GatewayRecipeError::InvalidCredentialGuard;
            if reads.is_empty() || reads.len() > MAX_DENIED_READS { return Err(invalid); }
            let mut seen: Vec<Vec<String>> = Vec::new();
            for read in reads {
                let path = fixed_path(&read.path)?;
                if !matches!(read.method.as_str(), "GET" | "HEAD")
                    || !refused_statuses_valid(&read.refused_status)
                    || seen.contains(&path) || reserved.contains(&path) {
                    return Err(invalid);
                }
                seen.push(path);
            }
            Ok(())
        }
        let read = |method: &str, path: &[&str], refused_status: Vec<u64>| DeniedReadSource {
            method: method.into(),
            path: path.iter().map(|value| PathSegment::Fixed { value: (*value).into() }).collect(),
            refused_status,
        };
        let candidates = [
            read("GET", &["v1", "first"], vec![401]),
            read("HEAD", &["v1", "second"], vec![403, 404]),
            read("GET", &["v1", "first-suffix"], vec![401]),
            read("get", &["v1", "first"], vec![401]),
            read("POST", &["v1", "first"], vec![401]),
            read("GET", &["v1", "first"], vec![408]),
            read("GET", &["v1", "first"], vec![401, 401]),
            read("GET", &[], vec![401]),
        ];
        for reserved in [vec![], vec![vec!["v1".into(), "first".into()]], vec![vec!["v1".into(), "fir".into()]]] {
            assert_eq!(validate_denied_reads(&[], &reserved), reference(&[], &reserved));
            for first in &candidates {
                for second in &candidates {
                    let reads = [first.clone(), second.clone()];
                    assert_eq!(validate_denied_reads(&reads, &reserved), reference(&reads, &reserved));
                }
            }
            let too_many = vec![candidates[0].clone(); MAX_DENIED_READS + 1];
            assert_eq!(validate_denied_reads(&too_many, &reserved), reference(&too_many, &reserved));
        }
    }
}
