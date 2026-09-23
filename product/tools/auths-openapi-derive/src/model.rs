//! Typed result of a successful mapping, before rendering.

use crate::request::Literal;

/// Fields the gateway compiler requires in every recipe-bound profile.
pub(crate) const BINDING_FIELDS: [&str; 3] =
    ["operator_namespace", "operation_id", "recipe_digest"];

/// Longest logical operation ID the gateway accepts.
pub(crate) const OPERATION_ID_MAX_BYTES: usize = 128;

/// One root-level argument schema the gateway compiler accepts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ArgSchema {
    String { min: usize, max: usize },
    Enum(Vec<String>),
    Integer { min: i64, max: i64 },
    Boolean,
}

impl ArgSchema {
    /// Worst-case canonical JSON bytes of one value, matching the packaged
    /// profile generator's bound.
    pub(crate) fn worst_case_bytes(&self) -> usize {
        match self {
            Self::String { max, .. } => 2 + 6 * max,
            Self::Enum(variants) => 2 + variants.iter().map(String::len).max().unwrap_or(0),
            Self::Integer { min, max } => min.to_string().len().max(max.to_string().len()),
            Self::Boolean => 5,
        }
    }

    pub(crate) const fn is_string_like(&self) -> bool {
        matches!(self, Self::String { .. } | Self::Enum(_))
    }
}

/// One derived argument and the document location it came from.
#[derive(Clone, Debug)]
pub(crate) struct Argument {
    pub(crate) name: String,
    pub(crate) schema: ArgSchema,
    pub(crate) pointer: String,
}

/// A body template node.
#[derive(Clone, Debug)]
pub(crate) enum Template {
    Field { name: String, string_like: bool },
    Literal(Literal),
    Object(Vec<(String, Template)>),
}

impl Template {
    /// Counts compiler template nodes.
    pub(crate) fn nodes(&self) -> usize {
        match self {
            Self::Field { .. } | Self::Literal(_) => 1,
            Self::Object(fields) => {
                1 + fields.iter().map(|(_, child)| child.nodes()).sum::<usize>()
            }
        }
    }
}

/// One recipe path segment.
#[derive(Clone, Debug)]
pub(crate) enum Segment {
    Fixed(String),
    Field(String),
}

/// Request body media type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Media {
    Json,
    Form,
}

impl Media {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Form => "application/x-www-form-urlencoded",
        }
    }
}

/// Credential requirement recorded in the recipe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CredentialKind {
    Bearer,
    HeaderApiKey(String),
}

/// Security selection and its provenance.
#[derive(Clone, Debug)]
pub(crate) struct Credential {
    pub(crate) kind: CredentialKind,
    pub(crate) scheme_name: Option<String>,
    pub(crate) scheme_type: String,
    pub(crate) from_override: bool,
    pub(crate) application_owned_acquisition: bool,
}

/// The pinned origin and fixed leading path from one listed server.
#[derive(Clone, Debug)]
pub(crate) struct Server {
    pub(crate) listed: String,
    pub(crate) origin: String,
    pub(crate) base_path: Vec<String>,
}

/// A document property or parameter left out of the contract.
#[derive(Clone, Debug)]
pub(crate) struct Omitted {
    pub(crate) pointer: String,
    pub(crate) path: String,
    pub(crate) reason: &'static str,
}

/// A document constraint the contract does not enforce exactly.
#[derive(Clone, Debug)]
pub(crate) struct Unenforced {
    pub(crate) pointer: String,
    pub(crate) path: String,
    pub(crate) keyword: &'static str,
    pub(crate) note: &'static str,
}

/// Everything rendering needs.
#[derive(Clone, Debug)]
pub(crate) struct Mapping {
    pub(crate) tool: String,
    pub(crate) server: Server,
    pub(crate) credential: Credential,
    pub(crate) arguments: Vec<Argument>,
    pub(crate) path: Vec<Segment>,
    pub(crate) media: Media,
    pub(crate) body: Vec<(String, Template)>,
    pub(crate) omitted: Vec<Omitted>,
    pub(crate) unenforced: Vec<Unenforced>,
}
