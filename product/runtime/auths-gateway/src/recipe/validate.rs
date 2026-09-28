//! The compile rules of recipe source `/2`.
//!
//! Each rule refuses with its stable code. The rules are independent: a
//! source that breaks exactly one rule fails with that rule's code whatever
//! order the checks run in.

use super::source::{
    AccountReadSource, AccountScopeSource, BodySource, BoundsSource, DeniedReadSource,
    EchoPlacement, EchoSource, FormExpr, GuardSource, IdempotencyLocation, IdempotencySource,
    ObservationSource, PathSegment, PreEntrySource, PreconditionSource, ProbeSource, RecipeSource,
    RelativeCeilingSource, ValueExpr,
};
use super::{
    FieldSchema, GatewayRecipeError, MAX_FORM_FIELDS, MAX_PATH_SEGMENTS, MAX_POINTER_BYTES,
    MAX_TEMPLATE_DEPTH, MAX_TEMPLATE_NODES, MAX_VERIFIED_FIELDS, ProviderHeaderClass,
    provider_header, valid_field_name,
};
use serde_json::Value;
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
const MAX_PROVIDER_HEADERS: usize = 2;

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

const fn is_binding_field(name: &str) -> bool {
    matches!(
        name.as_bytes(),
        b"operator_namespace" | b"operation_id" | b"recipe_digest"
    )
}

/// An observation pointer: absolute, at most 128 bytes and eight tokens, and
/// without the `~2` escape.
pub(super) fn valid_response_pointer(pointer: &str) -> bool {
    pointer.starts_with('/')
        && pointer.len() <= MAX_POINTER_BYTES
        && pointer.split('/').skip(1).count() <= 8
        && !pointer.contains("~2")
}

fn pointers_overlap(first: &str, second: &str) -> bool {
    first == second
        || first
            .strip_prefix(second)
            .is_some_and(|rest| rest.starts_with('/'))
        || second
            .strip_prefix(first)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn valid_fixed_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

fn read_bound_valid(bytes: u64) -> bool {
    (1..=MAX_READ_RESPONSE_BYTES).contains(&bytes)
}

/// The fixed values of a path made only of fixed segments.
pub(super) fn fixed_values(path: &[PathSegment]) -> Option<Vec<&str>> {
    path.iter()
        .map(|segment| match segment {
            PathSegment::Fixed { value } => Some(value.as_str()),
            _ => None,
        })
        .collect()
}

/// A credential-read path: 1–16 valid fixed segments.
fn fixed_path(path: &[PathSegment]) -> Result<Vec<&str>, GatewayRecipeError> {
    let values = fixed_values(path).ok_or(GatewayRecipeError::InvalidCredentialGuard)?;
    if values.is_empty()
        || values.len() > MAX_PATH_SEGMENTS
        || !values.iter().all(|value| valid_fixed_segment(value))
    {
        return Err(GatewayRecipeError::InvalidCredentialGuard);
    }
    Ok(values)
}

impl Rules<'_> {
    fn field(&self, name: &str) -> Option<&FieldSchema> {
        self.fields.get(name)
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
                    if !self.field(name).is_some_and(FieldSchema::is_path_scalar)
                        || matches!(name.as_str(), "operator_namespace" | "recipe_digest")
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
        if !self.fields.contains_key(name) || matches!(name, "operator_namespace" | "recipe_digest")
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
                        FormExpr::String { value } if value.len() <= 1024 => {}
                        FormExpr::Field { name } => self.field_ref(name)?,
                        FormExpr::Json { value } => {
                            if matches!(value, ValueExpr::Array { items } if items.len() != 1) {
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
        *nodes += 1;
        if *nodes > MAX_TEMPLATE_NODES || depth > MAX_TEMPLATE_DEPTH {
            return Err(GatewayRecipeError::UnsafeTemplate);
        }
        match value {
            ValueExpr::String { value } if value.len() <= 1024 => Ok(()),
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
            || matches!(
                source.expected_field.as_str(),
                "operator_namespace" | "recipe_digest"
            )
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
            if observation
                .path
                .iter()
                .any(|segment| matches!(segment, PathSegment::ResponseField { .. }))
            {
                return Err(GatewayRecipeError::PreconditionConflict);
            }
            let admissible = matches!(
                self.field(subject),
                Some(schema @ FieldSchema::String { .. }) if schema.has_fact_form()
            );
            self.claim_unused(subject, admissible)?;
        }
        for name in &source.verified {
            let admissible = self.field(name).is_some_and(FieldSchema::has_fact_form);
            self.claim_unused(name, admissible)?;
        }
        Ok(())
    }

    fn claim_unused(&mut self, name: &str, admissible: bool) -> Result<(), GatewayRecipeError> {
        if !admissible || is_binding_field(name) || !self.consumed.all.insert(name.to_owned()) {
            return Err(GatewayRecipeError::PreconditionConflict);
        }
        Ok(())
    }

    fn pre_entry(&mut self, source: &PreEntrySource) -> Result<(), GatewayRecipeError> {
        self.path(&source.path, PathRole::PreEntry)?;
        let unique: BTreeSet<&str> = source.pointers.iter().map(String::as_str).collect();
        if source.pointers.is_empty()
            || source.pointers.len() > MAX_PRE_ENTRY_POINTERS
            || unique.len() != source.pointers.len()
            || !source
                .pointers
                .iter()
                .all(|pointer| valid_response_pointer(pointer))
            || !read_bound_valid(source.maximum_response_bytes)
        {
            return Err(GatewayRecipeError::InvalidPreEntry);
        }
        Ok(())
    }

    fn integer_body_field(&self, name: &str) -> bool {
        matches!(self.field(name), Some(FieldSchema::Integer { .. }))
            && self.consumed.body.contains(name)
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
        let binds = source.bind.as_deref().unwrap_or_default();
        let pointers: BTreeSet<&str> = binds.iter().map(|bind| bind.pointer.as_str()).collect();
        if binds.len() > MAX_BINDS || pointers.len() != binds.len() {
            return Err(invalid);
        }
        for bind in binds {
            let bindable = matches!(
                self.field(&bind.field),
                Some(
                    FieldSchema::String { .. }
                        | FieldSchema::Enum { .. }
                        | FieldSchema::Integer { .. }
                )
            );
            if !valid_response_pointer(&bind.pointer)
                || !bindable
                || bind.field == source.argument
                || is_binding_field(&bind.field)
            {
                return Err(invalid);
            }
        }
        self.path(&source.path, PathRole::RelativeCeiling)?;
        for bind in binds {
            self.consume(&bind.field);
            self.consumed.binds.insert(bind.field.clone());
        }
        Ok(())
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
        matches!(
            self.field(name),
            Some(FieldSchema::String { .. } | FieldSchema::Enum { .. })
        )
    }

    /// The account-scope header names a registered account-scope header and
    /// takes its value from a string field nothing else renders.
    pub(super) fn account_scope(
        &mut self,
        source: &AccountScopeSource,
    ) -> Result<(), GatewayRecipeError> {
        let registered = provider_header(&source.header)
            .is_some_and(|entry| entry.class == ProviderHeaderClass::AccountScope);
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
        let bound = self.consumed.body.contains(partition)
            || account_scope.is_some_and(|scope| scope.field == *partition)
            || self.consumed.binds.contains(partition);
        if bound {
            Ok(())
        } else {
            Err(GatewayRecipeError::UnboundPartition)
        }
    }
}

/// Whether `location` resolves, in the body template, to a field reference
/// to `operation_id`.
fn operation_id_location(location: &IdempotencyLocation, body: &BodySource) -> bool {
    match (body, location) {
        (
            BodySource::Json { value },
            IdempotencyLocation {
                json_pointer: Some(pointer),
                form_field: None,
                pointer: None,
            },
        ) => template_at(value, pointer).is_some_and(is_operation_id),
        (
            BodySource::Form { fields },
            IdempotencyLocation {
                json_pointer: None,
                form_field: Some(name),
                pointer,
            },
        ) => match (fields.get(name), pointer) {
            (Some(FormExpr::Field { name }), None) => name == "operation_id",
            (Some(FormExpr::Json { value }), Some(pointer)) => {
                template_at(value, pointer).is_some_and(is_operation_id)
            }
            _ => false,
        },
        _ => false,
    }
}

fn is_operation_id(value: &ValueExpr) -> bool {
    matches!(value, ValueExpr::Field { name } if name == "operation_id")
}

/// The template node at an unescaped JSON pointer of object keys and array
/// indices.
fn template_at<'a>(value: &'a ValueExpr, pointer: &str) -> Option<&'a ValueExpr> {
    if !valid_response_pointer(pointer) || pointer.contains('~') {
        return None;
    }
    let mut current = value;
    for token in pointer.split('/').skip(1) {
        current = match current {
            ValueExpr::Object { fields } => fields.get(token)?,
            ValueExpr::Array { items } => {
                if token.is_empty()
                    || (token.len() > 1 && token.starts_with('0'))
                    || !token.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return None;
                }
                items.get(token.parse::<usize>().ok()?)?
            }
            _ => return None,
        };
    }
    Some(current)
}

/// A form echo name: `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`, optionally followed
/// by one bracketed segment of the same grammar.
fn valid_form_echo_name(name: &str) -> bool {
    fn part(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 64
            && value.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'_' | b'.' | b'-'))
            })
    }
    match name.find('[') {
        None => part(name),
        Some(open) => {
            let (base, rest) = name.split_at(open);
            rest.strip_prefix('[')
                .and_then(|inner| inner.strip_suffix(']'))
                .is_some_and(|inner| part(base) && part(inner))
        }
    }
}

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
            if !valid_form_echo_name(name)
                || fields.contains_key(name)
                || fields.len() + 1 > MAX_FORM_FIELDS
            {
                Err(GatewayRecipeError::EchoConflict)
            } else {
                Ok(())
            }
        }
        _ => Err(GatewayRecipeError::EchoConflict),
    }
}

fn validate_json_echo(pointer: &str, value: &ValueExpr) -> Result<(), GatewayRecipeError> {
    let tokens: Vec<&str> = pointer
        .strip_prefix('/')
        .ok_or(GatewayRecipeError::EchoConflict)?
        .split('/')
        .collect();
    if pointer.len() > MAX_POINTER_BYTES
        || tokens.len() > MAX_TEMPLATE_DEPTH
        || !tokens.iter().all(|token| valid_field_name(token))
    {
        return Err(GatewayRecipeError::EchoConflict);
    }
    let (last, parents) = tokens
        .split_last()
        .ok_or(GatewayRecipeError::EchoConflict)?;
    let mut current = value;
    for token in parents {
        let ValueExpr::Object { fields } = current else {
            return Err(GatewayRecipeError::EchoConflict);
        };
        current = fields.get(*token).ok_or(GatewayRecipeError::EchoConflict)?;
    }
    match current {
        ValueExpr::Object { fields } if !fields.contains_key(*last) && fields.len() < 32 => Ok(()),
        _ => Err(GatewayRecipeError::EchoConflict),
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
    for (name, value) in headers {
        let entry = provider_header(name).ok_or(GatewayRecipeError::InvalidProviderHeader)?;
        if entry.class != ProviderHeaderClass::Version || !entry.grammar.admits(value) {
            return Err(GatewayRecipeError::InvalidProviderHeader);
        }
    }
    Ok(())
}

fn validate_prefixes(prefixes: &[String]) -> Result<(), GatewayRecipeError> {
    let unique: BTreeSet<&str> = prefixes.iter().map(String::as_str).collect();
    if prefixes.is_empty()
        || prefixes.len() > MAX_GUARD_PREFIXES
        || unique.len() != prefixes.len()
        || !prefixes.iter().all(|prefix| {
            !prefix.is_empty()
                && prefix.len() <= MAX_GUARD_PREFIX_BYTES
                && prefix.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        })
    {
        return Err(GatewayRecipeError::InvalidCredentialGuard);
    }
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

fn validate_probe(probe: &ProbeSource) -> Result<Vec<&str>, GatewayRecipeError> {
    let path = fixed_path(&probe.path)?;
    if !valid_response_pointer(&probe.json_pointer)
        || !probe_literal_valid(&probe.equals)
        || !read_bound_valid(probe.maximum_response_bytes)
    {
        return Err(GatewayRecipeError::InvalidCredentialGuard);
    }
    Ok(path)
}

fn validate_account_read(account: &AccountReadSource) -> Result<Vec<&str>, GatewayRecipeError> {
    let path = fixed_path(&account.path)?;
    if !valid_response_pointer(&account.json_pointer)
        || !read_bound_valid(account.maximum_response_bytes)
    {
        return Err(GatewayRecipeError::InvalidCredentialGuard);
    }
    Ok(path)
}

fn refused_statuses_valid(statuses: &[u64]) -> bool {
    let unique: BTreeSet<u64> = statuses.iter().copied().collect();
    !statuses.is_empty()
        && statuses.len() <= MAX_REFUSED_STATUSES
        && unique.len() == statuses.len()
        && statuses
            .iter()
            .all(|status| (400..=499).contains(status) && !matches!(status, 408 | 429))
}

fn validate_denied_reads<'a>(
    reads: &'a [DeniedReadSource],
    reserved: &[Vec<&str>],
) -> Result<(), GatewayRecipeError> {
    let invalid = GatewayRecipeError::InvalidCredentialGuard;
    if reads.is_empty() || reads.len() > MAX_DENIED_READS {
        return Err(invalid);
    }
    let mut seen: Vec<Vec<&'a str>> = Vec::new();
    for read in reads {
        let path = fixed_path(&read.path)?;
        if !matches!(read.method.as_str(), "GET" | "HEAD")
            || !refused_statuses_valid(&read.refused_status)
            || seen.contains(&path)
            || reserved.contains(&path)
        {
            return Err(invalid);
        }
        seen.push(path);
    }
    Ok(())
}

/// The credential guard. Denied-read paths must differ from each other, from
/// the probe and account paths, and from every declared all-fixed path.
pub(super) fn validate_guard(
    guard: &GuardSource,
    source: &RecipeSource,
) -> Result<(), GatewayRecipeError> {
    validate_prefixes(&guard.prefixes)?;
    let mut reserved: Vec<Vec<&str>> = Vec::new();
    if let Some(probe) = &guard.probe {
        reserved.push(validate_probe(probe)?);
    }
    if let Some(account) = &guard.account {
        reserved.push(validate_account_read(account)?);
    }
    let Some(reads) = &guard.denied_reads else {
        return Ok(());
    };
    let declared = [
        Some(source.write.path.as_slice()),
        source
            .observation
            .as_ref()
            .map(|value| value.path.as_slice()),
        source.pre_entry.as_ref().map(|value| value.path.as_slice()),
        source
            .relative_ceiling
            .as_ref()
            .map(|value| value.path.as_slice()),
    ];
    for path in declared.into_iter().flatten() {
        if let Some(values) = fixed_values(path) {
            reserved.push(values);
        }
    }
    validate_denied_reads(reads, &reserved)
}

/// Every rule that reads the whole source, run in dependency order: the
/// request templates first, then the declarations that name the fields those
/// templates consume.
pub(super) fn validate_source(
    source: &RecipeSource,
    fields: &BTreeMap<String, FieldSchema>,
) -> Result<(), GatewayRecipeError> {
    let mut rules = Rules {
        fields,
        consumed: Consumption::default(),
    };
    rules.path(&source.write.path, PathRole::Write)?;
    rules.body(&source.write.body)?;
    if let Some(idempotency) = &source.write.idempotency {
        Rules::idempotency(idempotency, &source.write.body)?;
    }
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
    if let Some(ceiling) = &source.relative_ceiling {
        rules.relative_ceiling(ceiling)?;
    }
    if let Some(preconditions) = &source.preconditions {
        rules.preconditions(preconditions, source.observation.as_ref())?;
    }
    if let Some(headers) = &source.provider_headers {
        validate_provider_headers(headers)?;
    }
    if let Some(guard) = source.credential.guard() {
        validate_guard(guard, source)?;
    }
    if let Some(scope) = &source.account_scope {
        rules.account_scope(scope)?;
    }
    if let Some(bounds) = &source.bounds {
        rules.bounds(bounds, source.account_scope.as_ref())?;
    }
    for field in fields.keys() {
        if !is_binding_field(field) && !rules.consumed.all.contains(field) {
            return Err(GatewayRecipeError::UnsafeTemplate);
        }
    }
    Ok(())
}
