//! Argument mapping: request-body and parameter schemas to root scalars.

use crate::diagnostic::{DeriveCode, Diagnostic};
use crate::document::{Dialect, resolve};
use crate::json::{Json, SAFE_INTEGER, escape_token};
use crate::mapper::Mapper;
use crate::model::{ArgSchema, Argument, Media, Omitted, Template, Unenforced};
use crate::request::{Literal, ROOT_PATH, ScalarType};

/// Maximum nesting of body objects, counting the root object as one.
pub(crate) const MAX_OBJECT_DEPTH: usize = 4;
const MAX_STRING_BYTES: usize = 4096;
const MAX_ENUM_VARIANTS: usize = 32;

/// Keywords that never change which values are valid.
const ANNOTATIONS: [&str; 11] = [
    "title",
    "description",
    "example",
    "examples",
    "default",
    "deprecated",
    "readOnly",
    "writeOnly",
    "externalDocs",
    "xml",
    "$comment",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    String,
    Integer,
    Boolean,
    Null,
    Number,
    Object,
    Array,
}

impl Kind {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "string" => Self::String,
            "integer" => Self::Integer,
            "boolean" => Self::Boolean,
            "null" => Self::Null,
            "number" => Self::Number,
            "object" => Self::Object,
            "array" => Self::Array,
            _ => return None,
        })
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Integer => "integer",
            Self::Boolean => "boolean",
            Self::Null => "null",
            Self::Number => "number",
            Self::Object => "object",
            Self::Array => "array",
        }
    }

    const fn scalar(self) -> Option<ScalarType> {
        match self {
            Self::String => Some(ScalarType::String),
            Self::Integer => Some(ScalarType::Integer),
            Self::Boolean => Some(ScalarType::Boolean),
            _ => None,
        }
    }
}

/// One alternative of a possibly-union schema, with the node carrying its
/// constraints.
#[derive(Clone, Debug)]
pub(crate) struct Alternative<'a> {
    pub(crate) kind: Kind,
    pub(crate) node: &'a Json,
    pub(crate) pointer: String,
}

fn unsupported(pointer: impl Into<String>, message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(DeriveCode::UnsupportedConstruct, pointer, message)
}

/// Rejects every keyword outside `allowed`, annotations, and extensions.
pub(crate) fn check_keys(node: &Json, pointer: &str, allowed: &[&str]) -> Result<(), Diagnostic> {
    for (key, _) in node.as_object().into_iter().flatten() {
        if !allowed.contains(&key.as_str())
            && !ANNOTATIONS.contains(&key.as_str())
            && !key.starts_with("x-")
        {
            return Err(unsupported(
                format!("{pointer}/{}", escape_token(key)),
                format!("schema keyword {key:?} has no restricted-schema form"),
            ));
        }
    }
    Ok(())
}

/// A name usable both as a generated argument and a gateway field.
pub(crate) fn valid_argument_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.as_bytes()[0].is_ascii_alphabetic()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && !matches!(name, "prototype" | "constructor")
}

/// A name the gateway compiler accepts as a fixed body key.
fn valid_body_key(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'_' | b'-' | b'.'))
        })
}

/// A value the gateway compiler accepts as a fixed path segment.
pub(crate) fn valid_fixed_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

fn valid_variant(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

impl<'a> Mapper<'a> {
    /// Lists a schema's alternatives: a scalar `oneOf`/`anyOf`, a 3.1 type
    /// array, or a single type, each widened by `nullable: true`.
    pub(crate) fn alternatives(
        &self,
        node: &'a Json,
        pointer: &str,
    ) -> Result<Vec<Alternative<'a>>, Diagnostic> {
        for keyword in [
            "allOf",
            "not",
            "discriminator",
            "if",
            "then",
            "else",
            "const",
        ] {
            if node.get(keyword).is_some() {
                return Err(unsupported(
                    format!("{pointer}/{keyword}"),
                    format!("{keyword} has no restricted-schema form"),
                ));
            }
        }
        let nullable = node.get("nullable").and_then(Json::as_bool) == Some(true);
        let union = match (node.get("oneOf"), node.get("anyOf")) {
            (Some(_), Some(_)) => {
                return Err(unsupported(
                    pointer,
                    "oneOf and anyOf together have no form",
                ));
            }
            (Some(list), None) => Some(("oneOf", list)),
            (None, Some(list)) => Some(("anyOf", list)),
            (None, None) => None,
        };
        let mut found = Vec::new();
        if let Some((keyword, list)) = union {
            check_keys(node, pointer, &[keyword, "nullable"])?;
            let items = list
                .as_array()
                .filter(|items| !items.is_empty())
                .ok_or_else(|| {
                    unsupported(
                        format!("{pointer}/{keyword}"),
                        format!("{keyword} is not a non-empty array"),
                    )
                })?;
            for (index, item) in items.iter().enumerate() {
                let (item, at) =
                    resolve(self.document, item, format!("{pointer}/{keyword}/{index}"))?;
                if ["oneOf", "anyOf", "allOf", "not"]
                    .iter()
                    .any(|key| item.get(key).is_some())
                {
                    return Err(unsupported(
                        at,
                        "a nested union has no restricted-schema form",
                    ));
                }
                for kind in self.types(item, &at)? {
                    found.push(Alternative {
                        kind,
                        node: item,
                        pointer: at.clone(),
                    });
                }
            }
        } else {
            for kind in self.types(node, pointer)? {
                found.push(Alternative {
                    kind,
                    node,
                    pointer: pointer.to_owned(),
                });
            }
        }
        if nullable
            && !found
                .iter()
                .any(|alternative| alternative.kind == Kind::Null)
        {
            found.push(Alternative {
                kind: Kind::Null,
                node,
                pointer: pointer.to_owned(),
            });
        }
        Ok(found)
    }

    fn types(&self, node: &Json, pointer: &str) -> Result<Vec<Kind>, Diagnostic> {
        let invalid = || unsupported(format!("{pointer}/type"), "type is not a known JSON type");
        match node.get("type") {
            Some(Json::String(name)) => Ok(vec![Kind::parse(name).ok_or_else(invalid)?]),
            Some(Json::Array(names)) if self.dialect == Dialect::V31 && !names.is_empty() => {
                let mut kinds = Vec::new();
                for name in names {
                    let kind = name.as_str().and_then(Kind::parse).ok_or_else(invalid)?;
                    if kinds.contains(&kind) {
                        return Err(invalid());
                    }
                    kinds.push(kind);
                }
                Ok(kinds)
            }
            Some(_) => Err(invalid()),
            None if node.get("properties").is_some() => Ok(vec![Kind::Object]),
            None => Err(unsupported(pointer, "the schema declares no type")),
        }
    }

    /// Chooses the single alternative, consuming `--pick` where it applies.
    pub(crate) fn select(
        &mut self,
        alternatives: Vec<Alternative<'a>>,
        path: &str,
        pointer: &str,
    ) -> Result<Alternative<'a>, Diagnostic> {
        if alternatives.len() == 1 {
            return alternatives
                .into_iter()
                .next()
                .ok_or_else(|| unsupported(pointer, "the schema has no alternative"));
        }
        if let Some(other) = alternatives.iter().find(|alternative| {
            matches!(alternative.kind, Kind::Object | Kind::Array | Kind::Number)
        }) {
            return Err(unsupported(
                pointer,
                format!(
                    "a union containing an alternative of type {} has no restricted-schema form",
                    other.kind.as_str()
                ),
            ));
        }
        let values: Vec<&Alternative<'a>> = alternatives
            .iter()
            .filter(|alternative| alternative.kind != Kind::Null)
            .collect();
        if let Some(wanted) = self.overrides.pick.take(path) {
            let mut matching = values
                .iter()
                .filter(|alternative| alternative.kind.scalar() == Some(wanted));
            return match (matching.next(), matching.next()) {
                (Some(alternative), None) => Ok((*alternative).clone()),
                _ => Err(Diagnostic::new(
                    DeriveCode::InvalidOverride,
                    pointer,
                    format!(
                        "--pick {path}={} does not name exactly one alternative",
                        wanted.as_str()
                    ),
                )),
            };
        }
        let picks = values.iter().filter_map(|alternative| {
            alternative
                .kind
                .scalar()
                .map(|kind| format!("--pick {path}={}", kind.as_str()))
        });
        if values.len() == 1 {
            return Err(Diagnostic::new(
                DeriveCode::CompilerLimit,
                pointer,
                format!(
                    "{path} is a nullable {}; the gateway recipe compiler has no nullable field, so a derived request always sends a value",
                    values[0].kind.as_str()
                ),
            )
            .resolved_by(picks));
        }
        Err(Diagnostic::new(
            DeriveCode::ScalarUnion,
            pointer,
            format!("{path} is a union of scalar types; one alternative must be selected"),
        )
        .resolved_by(picks))
    }

    /// Maps one selected scalar alternative to a root argument schema.
    pub(crate) fn scalar(
        &mut self,
        alternative: &Alternative<'a>,
        path: &str,
    ) -> Result<ArgSchema, Diagnostic> {
        let Alternative {
            kind,
            node,
            pointer,
        } = alternative;
        match kind {
            Kind::String => self.string(node, pointer, path),
            Kind::Integer => self.integer(node, pointer, path),
            Kind::Boolean => {
                check_keys(node, pointer, &["type", "nullable"])?;
                Ok(ArgSchema::Boolean)
            }
            Kind::Number => Err(unsupported(
                pointer.clone(),
                format!("{path} is a number; floats are not in the command API"),
            )),
            Kind::Null => Err(unsupported(
                pointer.clone(),
                format!("{path} can only be null"),
            )),
            Kind::Object | Kind::Array => Err(Diagnostic::new(
                DeriveCode::CompilerLimit,
                pointer.clone(),
                format!(
                    "{path} is an {}; the gateway recipe compiler accepts only root-level scalar fields",
                    kind.as_str()
                ),
            )),
        }
    }

    fn string(&mut self, node: &Json, pointer: &str, path: &str) -> Result<ArgSchema, Diagnostic> {
        check_keys(
            node,
            pointer,
            &[
                "type",
                "nullable",
                "maxLength",
                "minLength",
                "enum",
                "format",
                "pattern",
            ],
        )?;
        if let Some(values) = node.get("enum") {
            return enumeration(values, &format!("{pointer}/enum"), path);
        }
        self.string_format(node, pointer, path)?;
        let (minimum, maximum_length) = lengths(node, pointer)?;
        let minimum = minimum.unwrap_or(0);
        let maximum = match (self.overrides.max_bytes.take(path), maximum_length) {
            // Every character is at least one UTF-8 byte, so a byte bound at
            // or below the character bound never admits a longer value.
            (Some(bytes), Some(characters)) if bytes <= characters => bytes,
            (Some(bytes), Some(characters)) => {
                return Err(Diagnostic::new(
                    DeriveCode::InvalidOverride,
                    format!("{pointer}/maxLength"),
                    format!(
                        "--max-bytes {path}={bytes} would admit more than maxLength {characters} characters; a byte override may only narrow"
                    ),
                ));
            }
            (Some(bytes), None) => bytes,
            (None, Some(characters)) => characters.min(MAX_STRING_BYTES),
            (None, None) => {
                return Err(Diagnostic::new(
                    DeriveCode::UnboundedString,
                    pointer,
                    format!("{path} is a string without maxLength"),
                )
                .resolved_by([format!("--max-bytes {path}=<N>")]));
            }
        };
        if minimum > maximum {
            return Err(unsupported(
                format!("{pointer}/minLength"),
                format!("{path} minLength {minimum} exceeds its byte maximum {maximum}"),
            ));
        }
        if minimum > 1 {
            self.unenforce(
                pointer,
                path,
                "minLength",
                "minLength counts characters and min_bytes counts UTF-8 bytes; a multibyte value with fewer characters is admitted and left to the provider",
            );
        }
        Ok(ArgSchema::String {
            min: minimum,
            max: maximum,
        })
    }

    fn integer(&mut self, node: &Json, pointer: &str, path: &str) -> Result<ArgSchema, Diagnostic> {
        check_keys(
            node,
            pointer,
            &[
                "type",
                "nullable",
                "minimum",
                "maximum",
                "exclusiveMinimum",
                "exclusiveMaximum",
                "format",
            ],
        )?;
        let (lower, upper) = integer_bounds(node, pointer)?;
        if let Some((low, high)) = self.overrides.range.take(path) {
            if lower.is_some_and(|bound| low < bound) || upper.is_some_and(|bound| high > bound) {
                return Err(Diagnostic::new(
                    DeriveCode::InvalidOverride,
                    pointer,
                    format!("--range {path}={low}:{high} widens the document's bounds"),
                ));
            }
            return Ok(ArgSchema::Integer {
                min: low,
                max: high,
            });
        }
        match (lower, upper) {
            (Some(min), Some(max)) if min <= max => Ok(ArgSchema::Integer { min, max }),
            (Some(_), Some(_)) => Err(unsupported(pointer, format!("{path} has an empty range"))),
            _ => Err(Diagnostic::new(
                DeriveCode::UnboundedInteger,
                pointer,
                format!("{path} is an integer without an inclusive safe minimum and maximum"),
            )
            .resolved_by([format!("--range {path}=<min>:<max>")])),
        }
    }

    pub(crate) fn unenforce(
        &mut self,
        pointer: &str,
        path: &str,
        keyword: &'static str,
        note: &'static str,
    ) {
        self.unenforced.push(Unenforced {
            pointer: format!("{pointer}/{keyword}"),
            path: path.to_owned(),
            keyword,
            note,
        });
    }

    /// Checks a `--literal` value against the schema it replaces, applying
    /// the same keyword rules as a derived argument plus exact membership in
    /// any `enum`. A malformed schema is an error, never a pass.
    pub(crate) fn literal_fits(
        &mut self,
        node: &'a Json,
        pointer: &str,
        path: &str,
        literal: &Literal,
    ) -> Result<(), Diagnostic> {
        let mut fits = false;
        for alternative in self.alternatives(node, pointer)? {
            fits |= self.literal_matches(&alternative, path, literal)?;
        }
        if fits {
            Ok(())
        } else {
            Err(Diagnostic::new(
                DeriveCode::InvalidOverride,
                pointer,
                format!("--literal for {path} does not satisfy the document schema"),
            ))
        }
    }

    fn literal_matches(
        &mut self,
        alternative: &Alternative<'a>,
        path: &str,
        literal: &Literal,
    ) -> Result<bool, Diagnostic> {
        let Alternative {
            kind,
            node,
            pointer,
        } = alternative;
        match (literal, kind) {
            (Literal::String(text), Kind::String) => {
                check_keys(
                    node,
                    pointer,
                    &[
                        "type",
                        "nullable",
                        "maxLength",
                        "minLength",
                        "enum",
                        "format",
                        "pattern",
                    ],
                )?;
                self.string_format(node, pointer, path)?;
                let characters = text.chars().count();
                let within = lengths(node, pointer)?;
                Ok(enum_allows(node, pointer, &Json::String(text.clone()))?
                    && within.0.is_none_or(|minimum| characters >= minimum)
                    && within.1.is_none_or(|maximum| characters <= maximum))
            }
            (Literal::Integer(number), Kind::Integer) => {
                check_keys(
                    node,
                    pointer,
                    &[
                        "type",
                        "nullable",
                        "minimum",
                        "maximum",
                        "exclusiveMinimum",
                        "exclusiveMaximum",
                        "format",
                        "enum",
                    ],
                )?;
                let (lower, upper) = integer_bounds(node, pointer)?;
                Ok(enum_allows(node, pointer, &Json::Number((*number).into()))?
                    && lower.is_none_or(|bound| *number >= bound)
                    && upper.is_none_or(|bound| *number <= bound))
            }
            (Literal::Boolean(flag), Kind::Boolean) => {
                check_keys(node, pointer, &["type", "nullable", "enum"])?;
                enum_allows(node, pointer, &Json::Bool(*flag))
            }
            _ => Ok(false),
        }
    }

    /// Rejects encoded binary formats and records any other format or
    /// pattern as a constraint the contract does not enforce.
    fn string_format(&mut self, node: &Json, pointer: &str, path: &str) -> Result<(), Diagnostic> {
        if let Some(format) = node.get("format") {
            let format = format.as_str().ok_or_else(|| {
                unsupported(format!("{pointer}/format"), "format is not a string")
            })?;
            if matches!(format, "byte" | "binary") {
                return Err(unsupported(
                    format!("{pointer}/format"),
                    format!("{path} has format {format}; encoded binary bodies are not derived"),
                ));
            }
            self.unenforce(
                pointer,
                path,
                "format",
                "string formats are not validated by the contract",
            );
        }
        if node.get("pattern").is_some() {
            self.unenforce(
                pointer,
                path,
                "pattern",
                "patterns are not validated by the contract; the provider may reject a value",
            );
        }
        Ok(())
    }

    /// Applies the closed-object rule; `None` stops mapping this object,
    /// `Some(false)` records a rejection but keeps mapping its properties.
    fn closed(&mut self, node: &Json, pointer: &str, path: Option<&str>) -> Option<bool> {
        let closed_path = path.unwrap_or(ROOT_PATH);
        match node.get("additionalProperties") {
            Some(Json::Bool(false)) => Some(true),
            None if self.overrides.closed.take(closed_path).is_some() => Some(true),
            None => {
                self.push(
                    Diagnostic::new(
                        DeriveCode::OpenObject,
                        pointer,
                        format!(
                            "object {} does not declare additionalProperties: false",
                            path.unwrap_or("request body")
                        ),
                    )
                    .resolved_by([format!("--closed {closed_path}")]),
                );
                Some(false)
            }
            Some(_) => {
                self.push(unsupported(
                    format!("{pointer}/additionalProperties"),
                    "a free-form map has no restricted-schema form",
                ));
                None
            }
        }
    }

    /// Maps an object's properties into flattened arguments and a template.
    pub(crate) fn object(
        &mut self,
        node: &'a Json,
        pointer: &str,
        path: Option<&str>,
        prefix: &str,
        depth: usize,
        media: Media,
    ) -> Option<Vec<(String, Template)>> {
        if depth > MAX_OBJECT_DEPTH {
            self.push(Diagnostic::new(
                DeriveCode::FieldLimit,
                pointer,
                "objects nest deeper than four levels",
            ));
            return None;
        }
        let checked = check_keys(
            node,
            pointer,
            &[
                "type",
                "properties",
                "required",
                "additionalProperties",
                "nullable",
            ],
        );
        let (required, properties) = checked
            .and_then(|()| members(node, pointer))
            .map_err(|error| self.push(error))
            .ok()?;
        let mut failed = !self.closed(node, pointer, path)?;
        let mut fields = Vec::new();
        for (name, child) in properties {
            let property = Property {
                name,
                path: path.map_or_else(|| name.clone(), |parent| format!("{parent}.{name}")),
                argument: format!("{prefix}{name}"),
                pointer: format!("{pointer}/properties/{}", escape_token(name)),
                required: required.contains(&name.as_str()),
                depth,
                media,
            };
            match self.property(child, &property) {
                Outcome::Mapped(template) => fields.push((name.clone(), template)),
                Outcome::Omitted => {}
                Outcome::Failed => failed = true,
            }
        }
        if failed {
            return None;
        }
        if fields.is_empty() {
            self.push(Diagnostic::new(
                DeriveCode::CompilerLimit,
                pointer,
                "every property is omitted; the gateway recipe compiler needs a non-empty object",
            ));
            return None;
        }
        Some(fields)
    }

    /// Maps one property.
    fn property(&mut self, raw: &'a Json, property: &Property<'_>) -> Outcome {
        let (node, pointer) = match resolve(self.document, raw, property.pointer.clone()) {
            Ok(found) => found,
            Err(error) => {
                self.push(error);
                return Outcome::Failed;
            }
        };
        let path = property.path.as_str();
        if node.get("readOnly").and_then(Json::as_bool) == Some(true) {
            self.omitted.push(Omitted {
                pointer: property.pointer.clone(),
                path: path.to_owned(),
                reason: "readOnly",
            });
            return Outcome::Omitted;
        }
        if self.overrides.omit.take(path).is_some() {
            if property.required {
                self.push(Diagnostic::new(
                    DeriveCode::InvalidOverride,
                    property.pointer.clone(),
                    format!("--omit {path} removes a required property"),
                ));
                return Outcome::Failed;
            }
            self.omitted.push(Omitted {
                pointer: property.pointer.clone(),
                path: path.to_owned(),
                reason: "--omit",
            });
            return Outcome::Omitted;
        }
        let optional_fix = (!property.required).then(|| format!("--omit {path}"));
        if !valid_body_key(property.name) {
            self.push(
                Diagnostic::new(
                    DeriveCode::InvalidName,
                    property.pointer.clone(),
                    format!(
                        "property name {:?} is not a gateway body key",
                        property.name
                    ),
                )
                .resolved_by(optional_fix),
            );
            return Outcome::Failed;
        }
        if let Some(literal) = self.overrides.literal.take(path) {
            return match self.literal_fits(node, &pointer, path, &literal) {
                Ok(()) => Outcome::Mapped(Template::Literal(literal)),
                Err(error) => {
                    self.push(error);
                    Outcome::Failed
                }
            };
        }
        if !property.required && self.overrides.require.take(path).is_none() {
            self.push(
                Diagnostic::new(
                    DeriveCode::OptionalProperty,
                    property.pointer.clone(),
                    format!(
                        "{path} is optional; a fixed-shape request has no encoding for absence"
                    ),
                )
                .resolved_by([format!("--omit {path}"), format!("--require {path}")]),
            );
            return Outcome::Failed;
        }
        self.value(node, &pointer, property)
            .map_or(Outcome::Failed, Outcome::Mapped)
    }

    fn value(
        &mut self,
        node: &'a Json,
        pointer: &str,
        property: &Property<'_>,
    ) -> Option<Template> {
        let path = property.path.as_str();
        let alternative = match self
            .alternatives(node, pointer)
            .and_then(|found| self.select(found, path, pointer))
        {
            Ok(alternative) => alternative,
            Err(error) => {
                self.push(error);
                return None;
            }
        };
        if alternative.kind == Kind::Object {
            if property.media == Media::Form {
                self.push(unsupported(
                    pointer,
                    format!("{path} is an object; form bodies carry scalar fields only"),
                ));
                return None;
            }
            let prefix = format!("{}_", property.argument);
            return self
                .object(
                    alternative.node,
                    &alternative.pointer,
                    Some(path),
                    &prefix,
                    property.depth + 1,
                    property.media,
                )
                .map(Template::Object);
        }
        if alternative.kind == Kind::Array {
            let _ = self.overrides.max_items.take(path);
            self.push(
                Diagnostic::new(
                    DeriveCode::CompilerLimit,
                    pointer,
                    format!("{path} is an array; the gateway recipe compiler accepts only root-level scalar fields, so no item bound can admit it"),
                )
                .resolved_by((!property.required).then(|| format!("--omit {path}"))),
            );
            return None;
        }
        let schema = match self.scalar(&alternative, path) {
            Ok(schema) => schema,
            Err(error) => {
                self.push(error);
                return None;
            }
        };
        if !valid_argument_name(&property.argument) {
            self.push(Diagnostic::new(
                DeriveCode::InvalidName,
                property.pointer.clone(),
                format!(
                    "argument name {:?} is not a generated field name",
                    property.argument
                ),
            ));
            return None;
        }
        let string_like = schema.is_string_like();
        self.arguments.push(Argument {
            name: property.argument.clone(),
            schema,
            pointer: property.pointer.clone(),
        });
        Some(Template::Field {
            name: property.argument.clone(),
            string_like,
        })
    }
}

/// Context for one property.
pub(crate) struct Property<'p> {
    pub(crate) name: &'p str,
    pub(crate) path: String,
    pub(crate) argument: String,
    pub(crate) pointer: String,
    pub(crate) required: bool,
    pub(crate) depth: usize,
    pub(crate) media: Media,
}

/// The result of mapping one property.
enum Outcome {
    Mapped(Template),
    Omitted,
    Failed,
}

type Members<'j> = (Vec<&'j str>, &'j [(String, Json)]);

/// Reads `required` and `properties`, rejecting a required name that is not declared.
fn members<'j>(node: &'j Json, pointer: &str) -> Result<Members<'j>, Diagnostic> {
    let required = required_names(node, pointer)?;
    let properties = match node.get("properties") {
        None => &[][..],
        Some(Json::Object(entries)) => entries.as_slice(),
        Some(_) => {
            return Err(unsupported(
                format!("{pointer}/properties"),
                "properties is not an object",
            ));
        }
    };
    if let Some(missing) = required
        .iter()
        .find(|name| !properties.iter().any(|(key, _)| key == *name))
    {
        return Err(unsupported(
            format!("{pointer}/required"),
            format!("required property {missing:?} is not declared"),
        ));
    }
    Ok((required, properties))
}

fn required_names<'j>(node: &'j Json, pointer: &str) -> Result<Vec<&'j str>, Diagnostic> {
    match node.get("required") {
        None => Ok(Vec::new()),
        Some(Json::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str().ok_or_else(|| {
                    unsupported(format!("{pointer}/required"), "required lists a non-string")
                })
            })
            .collect(),
        Some(_) => Err(unsupported(
            format!("{pointer}/required"),
            "required is not an array",
        )),
    }
}

fn enumeration(values: &Json, pointer: &str, path: &str) -> Result<ArgSchema, Diagnostic> {
    let invalid = |message: String| Diagnostic::new(DeriveCode::EnumVariant, pointer, message);
    let items = values
        .as_array()
        .ok_or_else(|| invalid(format!("{path} enum is not an array")))?;
    if items.is_empty() || items.len() > MAX_ENUM_VARIANTS {
        return Err(invalid(format!(
            "{path} enum has {} variants; 1 to 32 are allowed",
            items.len()
        )));
    }
    let mut variants: Vec<String> = Vec::new();
    for item in items {
        let text = item
            .as_str()
            .filter(|text| valid_variant(text))
            .ok_or_else(|| {
                let shown = item
                    .as_str()
                    .map_or_else(|| "a non-string".to_owned(), |text| format!("{text:?}"));
                invalid(format!(
                    "{path} enum variant {shown} is not a 1-64 byte [A-Za-z0-9_.-] string"
                ))
            })?;
        if variants.iter().any(|seen| seen == text) {
            return Err(invalid(format!("{path} enum repeats {text:?}")));
        }
        variants.push(text.to_owned());
    }
    Ok(ArgSchema::Enum(variants))
}

/// Reads `minLength` and `maxLength`; a present bound must be a
/// non-negative integer.
fn lengths(node: &Json, pointer: &str) -> Result<(Option<usize>, Option<usize>), Diagnostic> {
    let read = |key: &str| -> Result<Option<usize>, Diagnostic> {
        node.get(key)
            .map(|value| {
                value
                    .as_integer()
                    .and_then(|number| usize::try_from(number).ok())
                    .ok_or_else(|| {
                        unsupported(
                            format!("{pointer}/{key}"),
                            format!("{key} is not a non-negative integer"),
                        )
                    })
            })
            .transpose()
    };
    Ok((read("minLength")?, read("maxLength")?))
}

/// Reports whether `value` is a member of the node's `enum`, if it has one.
fn enum_allows(node: &Json, pointer: &str, value: &Json) -> Result<bool, Diagnostic> {
    match node.get("enum") {
        None => Ok(true),
        Some(Json::Array(items)) => Ok(items.iter().any(|item| match (item, value) {
            (Json::Number(_), Json::Number(_)) => {
                item.as_integer().is_some() && item.as_integer() == value.as_integer()
            }
            _ => item == value,
        })),
        Some(_) => Err(unsupported(
            format!("{pointer}/enum"),
            "enum is not an array",
        )),
    }
}

/// One numeric bound, rejected outside the safe-integer range.
fn bound(node: &Json, pointer: &str, key: &str) -> Result<Option<f64>, Diagnostic> {
    let Some(value) = node.get(key) else {
        return Ok(None);
    };
    let Json::Number(number) = value else {
        return Err(unsupported(
            format!("{pointer}/{key}"),
            format!("{key} is not a number"),
        ));
    };
    // INVARIANT: every finite JSON number has an f64 value; values beyond
    // the safe range are rejected below, so rounding error cannot move an
    // accepted bound.
    #[allow(clippy::cast_precision_loss)]
    let limit = SAFE_INTEGER as f64;
    match number.as_f64() {
        Some(parsed) if parsed.abs() <= limit => Ok(Some(parsed)),
        _ => Err(unsupported(
            format!("{pointer}/{key}"),
            format!("{key} lies outside the safe-integer range"),
        )),
    }
}

/// Converts an integral, safe-range f64 to i64.
fn integral(value: f64) -> i64 {
    // INVARIANT: callers pass floor/ceil of a value within the safe-integer
    // range, which i64 represents exactly.
    #[allow(clippy::cast_possible_truncation)]
    let converted = value as i64;
    converted
}

/// Reads inclusive integer bounds. Fractional bounds round inward, an
/// exclusive bound excludes its own value, and when inclusive and exclusive
/// bounds are both present the tighter one wins.
fn integer_bounds(node: &Json, pointer: &str) -> Result<(Option<i64>, Option<i64>), Diagnostic> {
    let minimum = bound(node, pointer, "minimum")?;
    let maximum = bound(node, pointer, "maximum")?;
    let at_least = |value: f64| integral(value.ceil());
    let above = |value: f64| integral(value.floor()) + 1;
    let at_most = |value: f64| integral(value.floor());
    let below = |value: f64| integral(value.ceil()) - 1;
    // The 3.0 spelling is a boolean beside the bound; the 3.1 spelling is a
    // number of its own, read below.
    let flag = |key: &str| node.get(key).and_then(Json::as_bool);
    let lower = match flag("exclusiveMinimum") {
        Some(true) => minimum.map(above),
        Some(false) => minimum.map(at_least),
        None => {
            let exclusive = bound(node, pointer, "exclusiveMinimum")?.map(above);
            match (minimum.map(at_least), exclusive) {
                (Some(inclusive), Some(exclusive)) => Some(inclusive.max(exclusive)),
                (inclusive, exclusive) => inclusive.or(exclusive),
            }
        }
    };
    let upper = match flag("exclusiveMaximum") {
        Some(true) => maximum.map(below),
        Some(false) => maximum.map(at_most),
        None => {
            let exclusive = bound(node, pointer, "exclusiveMaximum")?.map(below);
            match (maximum.map(at_most), exclusive) {
                (Some(inclusive), Some(exclusive)) => Some(inclusive.min(exclusive)),
                (inclusive, exclusive) => inclusive.or(exclusive),
            }
        }
    };
    let safe =
        |value: Option<i64>| value.filter(|number| (-SAFE_INTEGER..=SAFE_INTEGER).contains(number));
    match (lower, upper) {
        (Some(low), _) if safe(Some(low)).is_none() => Err(unsupported(
            pointer,
            "the lower bound lies outside the safe-integer range",
        )),
        (_, Some(high)) if safe(Some(high)).is_none() => Err(unsupported(
            pointer,
            "the upper bound lies outside the safe-integer range",
        )),
        bounds => Ok(bounds),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    fn bounds(schema: &str) -> Result<(Option<i64>, Option<i64>), Diagnostic> {
        integer_bounds(&parse(schema.as_bytes()).unwrap(), "#")
    }

    #[test]
    fn integer_bounds_round_inward_and_keep_the_tighter_bound() {
        assert_eq!(
            bounds(r#"{"minimum":0.5,"maximum":10.5}"#).unwrap(),
            (Some(1), Some(10))
        );
        assert_eq!(
            bounds(r#"{"minimum":-0.5,"maximum":-0.5}"#).unwrap(),
            (Some(0), Some(-1))
        );
        assert_eq!(
            bounds(r#"{"minimum":10,"exclusiveMinimum":0.5,"maximum":20,"exclusiveMaximum":30}"#)
                .unwrap(),
            (Some(10), Some(20))
        );
        assert_eq!(
            bounds(r#"{"minimum":0,"exclusiveMinimum":5,"maximum":9,"exclusiveMaximum":4.5}"#)
                .unwrap(),
            (Some(6), Some(4))
        );
        assert_eq!(
            bounds(r#"{"minimum":1,"exclusiveMinimum":true,"maximum":4,"exclusiveMaximum":true}"#)
                .unwrap(),
            (Some(2), Some(3))
        );
        assert_eq!(
            bounds(r#"{"exclusiveMinimum":2.5}"#).unwrap(),
            (Some(3), None)
        );
        assert!(bounds(r#"{"minimum":1e16}"#).is_err());
        assert!(bounds(r#"{"maximum":9007199254740992}"#).is_err());
        assert!(bounds(r#"{"minimum":"1"}"#).is_err());
        assert_eq!(
            bounds(r#"{"minimum":-9007199254740991,"maximum":9007199254740991}"#).unwrap(),
            (Some(-9_007_199_254_740_991), Some(9_007_199_254_740_991))
        );
    }
}
