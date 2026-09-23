//! Closed derivation diagnostic codes.

use std::fmt;

/// One stable derivation rejection code in the `contract` stage.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DeriveCode {
    /// A command-line flag or identity value is malformed, repeated, or missing.
    InvalidRequest,
    /// The document is not bounded, duplicate-free JSON.
    DocumentInvalid,
    /// The document is not JSON; YAML is not read by this format.
    DocumentFormat,
    /// The document is not `OpenAPI` 3.0.x or 3.1.x.
    UnsupportedVersion,
    /// No operation carries the requested `operationId`.
    OperationNotFound,
    /// More than one operation carries the requested `operationId`.
    DuplicateOperation,
    /// The operation method is not a single write.
    UnsupportedMethod,
    /// The `operationId` is not a valid tool name.
    ToolName,
    /// A reference leaves the document.
    RemoteRef,
    /// A reference chain returns to itself.
    RefCycle,
    /// The operation needs more than the reference-resolution budget.
    RefLimit,
    /// The resolved operation exceeds the slice byte budget.
    SliceLimit,
    /// Zero or several servers apply and none was selected.
    AmbiguousServer,
    /// The selected server is not a fixed public HTTPS origin.
    UnsafeServer,
    /// Several security requirements apply and none was selected.
    AmbiguousSecurity,
    /// The document declares no security requirement.
    MissingSecurity,
    /// The credential scheme is outside one static header credential.
    CredentialSchemeOutOfScope,
    /// A query parameter has no form in the recipe language.
    QueryParameter,
    /// A header or cookie parameter has no form in the recipe language.
    UnsupportedParameter,
    /// The request body is absent, optional, or of an unsupported media type.
    UnsupportedBody,
    /// A string has no maximum length.
    UnboundedString,
    /// An integer lacks an inclusive safe range.
    UnboundedInteger,
    /// A schema construct has no restricted-schema form.
    UnsupportedConstruct,
    /// A union of scalar types needs one selected alternative.
    ScalarUnion,
    /// An optional property has no encoding for absence.
    OptionalProperty,
    /// An object does not declare whether extra properties are allowed.
    OpenObject,
    /// The construct maps to the schema but not to the gateway recipe compiler.
    CompilerLimit,
    /// An enum has too many or non-conforming variants.
    EnumVariant,
    /// A name cannot be an argument or body key.
    InvalidName,
    /// Two derived arguments would have the same name.
    NameCollision,
    /// The derived command exceeds field, depth, or size limits.
    FieldLimit,
    /// An override is malformed or contradicts the document.
    InvalidOverride,
    /// An override did not apply to any construct.
    UnusedOverride,
}

impl DeriveCode {
    /// Returns the stable diagnostic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "contract.derive.invalid-request",
            Self::DocumentInvalid => "contract.derive.document-invalid",
            Self::DocumentFormat => "contract.derive.document-format",
            Self::UnsupportedVersion => "contract.derive.unsupported-version",
            Self::OperationNotFound => "contract.derive.operation-not-found",
            Self::DuplicateOperation => "contract.derive.duplicate-operation",
            Self::UnsupportedMethod => "contract.derive.unsupported-method",
            Self::ToolName => "contract.derive.tool-name",
            Self::RemoteRef => "contract.derive.remote-ref",
            Self::RefCycle => "contract.derive.ref-cycle",
            Self::RefLimit => "contract.derive.ref-limit",
            Self::SliceLimit => "contract.derive.slice-limit",
            Self::AmbiguousServer => "contract.derive.ambiguous-server",
            Self::UnsafeServer => "contract.derive.unsafe-server",
            Self::AmbiguousSecurity => "contract.derive.ambiguous-security",
            Self::MissingSecurity => "contract.derive.missing-security",
            Self::CredentialSchemeOutOfScope => "contract.derive.credential-scheme-out-of-scope",
            Self::QueryParameter => "contract.derive.query-parameter",
            Self::UnsupportedParameter => "contract.derive.unsupported-parameter",
            Self::UnsupportedBody => "contract.derive.unsupported-body",
            Self::UnboundedString => "contract.derive.unbounded-string",
            Self::UnboundedInteger => "contract.derive.unbounded-integer",
            Self::UnsupportedConstruct => "contract.derive.unsupported-construct",
            Self::ScalarUnion => "contract.derive.scalar-union",
            Self::OptionalProperty => "contract.derive.optional-property",
            Self::OpenObject => "contract.derive.open-object",
            Self::CompilerLimit => "contract.derive.compiler-limit",
            Self::EnumVariant => "contract.derive.enum-variant",
            Self::InvalidName => "contract.derive.invalid-name",
            Self::NameCollision => "contract.derive.name-collision",
            Self::FieldLimit => "contract.derive.field-limit",
            Self::InvalidOverride => "contract.derive.invalid-override",
            Self::UnusedOverride => "contract.derive.unused-override",
        }
    }
}

impl fmt::Display for DeriveCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One rejection: stable code, JSON pointer into the document (empty for a
/// command-line problem), one human sentence, and the exact flags that would
/// resolve it, if any exist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    code: DeriveCode,
    pointer: String,
    message: String,
    overrides: Vec<String>,
}

impl Diagnostic {
    pub(crate) fn new(
        code: DeriveCode,
        pointer: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            pointer: pointer.into(),
            message: message.into(),
            overrides: Vec::new(),
        }
    }

    pub(crate) fn resolved_by(mut self, overrides: impl IntoIterator<Item = String>) -> Self {
        self.overrides.extend(overrides);
        self
    }

    /// Returns the stable code.
    #[must_use]
    pub const fn code(&self) -> DeriveCode {
        self.code
    }

    /// Returns the JSON pointer, or an empty string for a flag problem.
    #[must_use]
    pub fn pointer(&self) -> &str {
        &self.pointer
    }

    /// Returns the human sentence.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the flags that would resolve the rejection; empty when none exists.
    #[must_use]
    pub fn overrides(&self) -> &[String] {
        &self.overrides
    }

    /// Renders the diagnostic as the two lines both CLIs print.
    #[must_use]
    pub fn lines(&self) -> [String; 2] {
        let head = if self.pointer.is_empty() {
            format!("  {}", self.code)
        } else {
            format!("  {}  {}", self.code, self.pointer)
        };
        let resolution = match self.overrides.as_slice() {
            [] if self.pointer.is_empty() => String::new(),
            [] => "; no override exists".to_owned(),
            [only] => format!("; pass {only}"),
            several => format!("; pass {}", several.join(" or ")),
        };
        [head, format!("    {}{resolution}", self.message)]
    }
}
