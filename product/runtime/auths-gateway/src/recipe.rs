use auths_profile_mcp::McpCommand;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use url::{Host, Url, form_urlencoded};

const MAX_SOURCE_BYTES: usize = 65_536;
const MAX_LOCK_BYTES: usize = 65_536;
const MAX_BODY_BYTES: usize = 16_384;
const MAX_TEMPLATE_NODES: usize = 64;
const MAX_TEMPLATE_DEPTH: usize = 6;
const MAX_PATH_SEGMENTS: usize = 16;
const DIGEST_DOMAIN: &[u8] = b"auths.gateway-compiled-recipe/1\0";

/// Operator-controlled account namespace. A different proof challenge never
/// creates a new replay namespace.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OperatorNamespace(String);

impl OperatorNamespace {
    /// Parses a canonical 1–64-byte ASCII replay namespace.
    ///
    /// # Errors
    /// Rejects empty, oversized, or noncanonical tokens.
    pub fn parse(value: &str) -> Result<Self, GatewayRecipeError> {
        if !valid_token(value, 64) {
            return Err(GatewayRecipeError::InvalidNamespace);
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the canonical token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Application-selected stable logical write ID within an operator namespace.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LogicalOperationId(String);

impl LogicalOperationId {
    /// Parses a canonical 1–128-byte ASCII operation ID.
    ///
    /// # Errors
    /// Rejects empty, oversized, or noncanonical tokens.
    pub fn parse(value: &str) -> Result<Self, GatewayRecipeError> {
        if !valid_token(value, 128) {
            return Err(GatewayRecipeError::InvalidOperationId);
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the canonical token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.is_ascii()
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
}

/// One supported credential injection requirement. The operator connection,
/// not the recipe, names the actual injection header.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum CredentialRequirement {
    /// `Authorization: Bearer <secret>`.
    Bearer,
    /// A static secret in one named API-key header.
    HeaderApiKey { header: String },
}

impl CredentialRequirement {
    fn validate(&self) -> Result<(), GatewayRecipeError> {
        if let Self::HeaderApiKey { header } = self {
            let lower = header.to_ascii_lowercase();
            if header.len() > 64
                || !header.bytes().enumerate().all(|(index, byte)| {
                    byte.is_ascii_alphanumeric() || (index > 0 && byte == b'-')
                })
                || matches!(
                    lower.as_str(),
                    "authorization"
                        | "host"
                        | "cookie"
                        | "set-cookie"
                        | "content-type"
                        | "content-length"
                        | "accept"
                        | "connection"
                        | "transfer-encoding"
                )
            {
                return Err(GatewayRecipeError::InvalidCredential);
            }
        }
        Ok(())
    }
}

/// Closed write methods. GET is reserved for a separately declared observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum WriteMethod {
    /// HTTP POST.
    Post,
    /// HTTP PUT.
    Put,
    /// HTTP PATCH.
    Patch,
    /// HTTP DELETE.
    Delete,
}

impl WriteMethod {
    /// Returns the fixed HTTP spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

/// Closed compiler failure with a stable non-secret diagnostic code.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum GatewayRecipeError {
    /// Source shape, type, or size is invalid.
    #[error("invalid recipe source")]
    InvalidSource,
    /// Profile lock is malformed, stale, or unsupported.
    #[error("invalid profile lock")]
    InvalidProfileLock,
    /// Recipe and profile identity or digest differ.
    #[error("recipe profile mismatch")]
    ProfileMismatch,
    /// Origin is not a pinned public HTTPS DNS origin.
    #[error("unsafe recipe origin")]
    UnsafeOrigin,
    /// Path contains an unsafe or unbounded segment.
    #[error("unsafe recipe path")]
    UnsafePath,
    /// Body or observation mapping is unsupported or unbounded.
    #[error("unsafe recipe template")]
    UnsafeTemplate,
    /// Credential requirement is unsupported.
    #[error("invalid credential requirement")]
    InvalidCredential,
    /// Operator namespace is invalid.
    #[error("invalid operator namespace")]
    InvalidNamespace,
    /// Logical operation ID is invalid.
    #[error("invalid logical operation ID")]
    InvalidOperationId,
    /// Verified action does not match the approved profile or recipe.
    #[error("verified action does not match approved recipe")]
    ActionMismatch,
}

impl GatewayRecipeError {
    /// Returns a stable non-secret diagnostic code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidSource => "gateway.recipe.invalid-source",
            Self::InvalidProfileLock => "gateway.recipe.invalid-profile-lock",
            Self::ProfileMismatch => "gateway.recipe.profile-mismatch",
            Self::UnsafeOrigin => "gateway.recipe.unsafe-origin",
            Self::UnsafePath => "gateway.recipe.unsafe-path",
            Self::UnsafeTemplate => "gateway.recipe.unsafe-template",
            Self::InvalidCredential => "gateway.recipe.invalid-credential",
            Self::InvalidNamespace => "gateway.recipe.invalid-namespace",
            Self::InvalidOperationId => "gateway.recipe.invalid-operation-id",
            Self::ActionMismatch => "gateway.recipe.action-mismatch",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipeSource {
    schema: String,
    profile_schema_digest: String,
    service: String,
    tool: String,
    operator_namespace: String,
    credential: CredentialRequirement,
    origin: String,
    write: WriteSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    observation: Option<ObservationSource>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteSource {
    method: WriteMethod,
    path: Vec<PathSegment>,
    body: BodySource,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum PathSegment {
    Fixed { value: String },
    Field { name: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum BodySource {
    Json { value: ValueExpr },
    Form { fields: BTreeMap<String, FormExpr> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum FormExpr {
    String { value: String },
    Field { name: String },
    Json { value: ValueExpr },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ValueExpr {
    String { value: String },
    Integer { value: i64 },
    Boolean { value: bool },
    Field { name: String },
    Object { fields: BTreeMap<String, ValueExpr> },
    Array { items: Vec<ValueExpr> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationSource {
    path: Vec<PathSegment>,
    json_pointer: String,
    expected_field: String,
    maximum_response_bytes: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileLockFile {
    schema: String,
    profile: String,
    version: u16,
    service: String,
    tool: String,
    schema_digest: String,
    command_schema: Value,
    generator_format: u8,
}

#[derive(Clone, Debug)]
enum FieldSchema {
    String { minimum: usize, maximum: usize },
    Enum { variants: Vec<String> },
    Integer { minimum: i64, maximum: i64 },
    Boolean,
}

impl FieldSchema {
    fn validate_value(&self, value: &Value) -> bool {
        match self {
            Self::String { minimum, maximum } => value.as_str().is_some_and(|text| {
                (*minimum..=*maximum).contains(&text.len())
                    && text.as_bytes().iter().all(|byte| *byte != 0)
            }),
            Self::Enum { variants } => value
                .as_str()
                .is_some_and(|text| variants.iter().any(|variant| variant == text)),
            Self::Integer { minimum, maximum } => value
                .as_i64()
                .is_some_and(|number| (*minimum..=*maximum).contains(&number)),
            Self::Boolean => value.is_boolean(),
        }
    }

    fn is_path_scalar(&self) -> bool {
        matches!(self, Self::String { .. } | Self::Enum { .. })
    }
}

/// Operator review facts that are safe to show without a credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipeReview {
    service: String,
    tool: String,
    origin: String,
    method: WriteMethod,
    path: Vec<String>,
    credential: CredentialRequirement,
    maximum_body_bytes: usize,
    has_observation: bool,
}

impl RecipeReview {
    /// Returns the exact MCP service.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }
    /// Returns the versioned MCP tool.
    #[must_use]
    pub fn tool(&self) -> &str {
        &self.tool
    }
    /// Returns the pinned public HTTPS origin.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
    /// Returns the fixed write method.
    #[must_use]
    pub const fn method(&self) -> WriteMethod {
        self.method
    }
    /// Returns fixed and typed path segments for operator review.
    #[must_use]
    pub fn path(&self) -> &[String] {
        &self.path
    }
    /// Returns the credential-header requirement, never the secret.
    #[must_use]
    pub const fn credential(&self) -> &CredentialRequirement {
        &self.credential
    }
    /// Returns the maximum body bytes enforced by the compiler.
    #[must_use]
    pub const fn maximum_body_bytes(&self) -> usize {
        self.maximum_body_bytes
    }
    /// Reports whether a separate read-only observation is declared.
    #[must_use]
    pub const fn has_observation(&self) -> bool {
        self.has_observation
    }
}

/// Validated, bounded, digest-stable recipe tied to one generated profile lock.
/// Compilation grants no authority to execute or lease a credential.
#[derive(Clone, Debug)]
pub struct CompiledRecipe {
    source: RecipeSource,
    fields: BTreeMap<String, FieldSchema>,
    namespace: OperatorNamespace,
    digest: [u8; 32],
}

impl CompiledRecipe {
    /// Compiles source against the exact generated profile lock.
    ///
    /// # Errors
    /// Rejects malformed, unbounded, stale, or unsafe mappings. This operation
    /// does not install the recipe or authorize an action.
    pub fn compile(source_bytes: &[u8], lock_bytes: &[u8]) -> Result<Self, GatewayRecipeError> {
        if source_bytes.is_empty()
            || source_bytes.len() > MAX_SOURCE_BYTES
            || lock_bytes.is_empty()
            || lock_bytes.len() > MAX_LOCK_BYTES
        {
            return Err(GatewayRecipeError::InvalidSource);
        }
        let source: RecipeSource =
            serde_json::from_slice(source_bytes).map_err(|_| GatewayRecipeError::InvalidSource)?;
        let lock: ProfileLockFile = serde_json::from_slice(lock_bytes)
            .map_err(|_| GatewayRecipeError::InvalidProfileLock)?;
        if source.schema != "auths.gateway-recipe-source/1" {
            return Err(GatewayRecipeError::InvalidSource);
        }
        if lock.schema != "auths.self-hosted-profile-lock/1"
            || lock.generator_format != 2
            || lock.version == 0
            || lock.profile.is_empty()
            || lock.service.is_empty()
            || lock.tool.is_empty()
            || !lower_hex_digest(&lock.schema_digest)
        {
            return Err(GatewayRecipeError::InvalidProfileLock);
        }
        let schema_bytes = serde_json_canonicalizer::to_vec(&lock.command_schema)
            .map_err(|_| GatewayRecipeError::InvalidProfileLock)?;
        if hex::encode(Sha256::digest(schema_bytes)) != lock.schema_digest {
            return Err(GatewayRecipeError::InvalidProfileLock);
        }
        if source.service != lock.service
            || source.tool != lock.tool
            || source.profile_schema_digest != lock.schema_digest
        {
            return Err(GatewayRecipeError::ProfileMismatch);
        }
        let fields = parse_root_fields(&lock.command_schema)?;
        let namespace = OperatorNamespace::parse(&source.operator_namespace)?;
        validate_binding_fields(&fields, &namespace)?;
        source.credential.validate()?;
        validate_origin(&source.origin)?;
        let mut used = BTreeSet::new();
        validate_path(&source.write.path, &fields, &mut used)?;
        validate_body(&source.write.body, &fields, &mut used)?;
        if let Some(observation) = &source.observation {
            validate_path(&observation.path, &fields, &mut used)?;
            validate_observation(observation, &fields, &mut used)?;
        }
        for field in fields.keys() {
            if !matches!(
                field.as_str(),
                "operator_namespace" | "operation_id" | "recipe_digest"
            ) && !used.contains(field)
            {
                return Err(GatewayRecipeError::UnsafeTemplate);
            }
        }
        let canonical = serde_json_canonicalizer::to_vec(&source)
            .map_err(|_| GatewayRecipeError::InvalidSource)?;
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(canonical);
        let digest = hasher.finalize().into();
        Ok(Self {
            source,
            fields,
            namespace,
            digest,
        })
    }

    /// Returns the domain-separated compiled-recipe digest.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns the canonical lowercase digest spelling committed in actions.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        hex::encode(self.digest)
    }

    /// Returns the operator-controlled replay namespace.
    #[must_use]
    pub const fn namespace(&self) -> &OperatorNamespace {
        &self.namespace
    }

    /// Returns a bounded, secret-free operator review projection.
    #[must_use]
    pub fn review(&self) -> RecipeReview {
        RecipeReview {
            service: self.source.service.clone(),
            tool: self.source.tool.clone(),
            origin: self.source.origin.clone(),
            method: self.source.write.method,
            path: self
                .source
                .write
                .path
                .iter()
                .map(|part| match part {
                    PathSegment::Fixed { value } => value.clone(),
                    PathSegment::Field { name } => format!("<{name}>"),
                })
                .collect(),
            credential: self.source.credential.clone(),
            maximum_body_bytes: MAX_BODY_BYTES,
            has_observation: self.source.observation.is_some(),
        }
    }

    /// Builds a closed request only from a native-verified MCP command.
    ///
    /// # Errors
    /// Rejects a mismatched service/tool, schema value, recipe digest,
    /// namespace, logical ID, or unsafe substitution before any credential
    /// access or network entry.
    pub fn closed_request(
        &self,
        command: &McpCommand,
    ) -> Result<ClosedProviderRequest, GatewayRecipeError> {
        if command.call().service() != self.source.service || command.name() != self.source.tool {
            return Err(GatewayRecipeError::ActionMismatch);
        }
        self.closed_request_from_arguments(command.arguments())
    }

    fn closed_request_from_arguments(
        &self,
        arguments: &Map<String, Value>,
    ) -> Result<ClosedProviderRequest, GatewayRecipeError> {
        if arguments.len() != self.fields.len()
            || !self.fields.iter().all(|(name, schema)| {
                arguments
                    .get(name)
                    .is_some_and(|value| schema.validate_value(value))
            })
            || arguments.get("operator_namespace").and_then(Value::as_str)
                != Some(self.namespace.as_str())
            || arguments.get("recipe_digest").and_then(Value::as_str)
                != Some(self.digest_hex().as_str())
        {
            return Err(GatewayRecipeError::ActionMismatch);
        }
        let operation_id = arguments
            .get("operation_id")
            .and_then(Value::as_str)
            .ok_or(GatewayRecipeError::InvalidOperationId)
            .and_then(LogicalOperationId::parse)?;
        let path = build_path(&self.source.write.path, arguments)?;
        let (content_type, body) = build_body(&self.source.write.body, arguments)?;
        if body.is_empty() || body.len() > MAX_BODY_BYTES {
            return Err(GatewayRecipeError::UnsafeTemplate);
        }
        let observation = self
            .source
            .observation
            .as_ref()
            .map(|source| {
                Ok(ClosedObservationRequest {
                    url: format!(
                        "{}{}",
                        self.source.origin,
                        build_path(&source.path, arguments)?
                    ),
                    json_pointer: source.json_pointer.clone(),
                    expected: arguments
                        .get(&source.expected_field)
                        .cloned()
                        .ok_or(GatewayRecipeError::ActionMismatch)?,
                    maximum_response_bytes: source.maximum_response_bytes,
                })
            })
            .transpose()?;
        Ok(ClosedProviderRequest {
            namespace: self.namespace.clone(),
            operation_id,
            method: self.source.write.method,
            url: format!("{}{path}", self.source.origin),
            content_type,
            body,
            credential_requirement: self.source.credential.clone(),
            observation,
        })
    }
}

/// Credential-free closed HTTP request derived from a verified action.
/// Its fields cannot be supplied by the application at submission time.
#[derive(Clone, Debug)]
pub struct ClosedProviderRequest {
    namespace: OperatorNamespace,
    operation_id: LogicalOperationId,
    method: WriteMethod,
    url: String,
    content_type: &'static str,
    body: Vec<u8>,
    credential_requirement: CredentialRequirement,
    observation: Option<ClosedObservationRequest>,
}

impl ClosedProviderRequest {
    /// Returns the operator namespace.
    #[must_use]
    pub const fn namespace(&self) -> &OperatorNamespace {
        &self.namespace
    }
    /// Returns the durable logical operation ID.
    #[must_use]
    pub const fn operation_id(&self) -> &LogicalOperationId {
        &self.operation_id
    }
    /// Returns the approved write method.
    #[must_use]
    pub const fn method(&self) -> WriteMethod {
        self.method
    }
    /// Returns the closed approved URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }
    /// Returns the compiler-owned body media type.
    #[must_use]
    pub const fn content_type(&self) -> &'static str {
        self.content_type
    }
    /// Returns the bounded request body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    /// Returns the static credential-header requirement, not a credential.
    #[must_use]
    pub const fn credential_requirement(&self) -> &CredentialRequirement {
        &self.credential_requirement
    }
    /// Returns the optional closed read-back request.
    #[must_use]
    pub const fn observation(&self) -> Option<&ClosedObservationRequest> {
        self.observation.as_ref()
    }
}

/// One approved read-only comparison; matching never proves causation.
#[derive(Clone, Debug)]
pub struct ClosedObservationRequest {
    url: String,
    json_pointer: String,
    expected: Value,
    maximum_response_bytes: usize,
}

impl ClosedObservationRequest {
    /// Returns the closed GET URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }
    /// Returns the fixed JSON pointer.
    #[must_use]
    pub fn json_pointer(&self) -> &str {
        &self.json_pointer
    }
    /// Returns the verified value to compare against.
    #[must_use]
    pub const fn expected(&self) -> &Value {
        &self.expected
    }
    /// Returns the enforced response-byte limit.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> usize {
        self.maximum_response_bytes
    }
}

fn lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn exact_keys(object: &Map<String, Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

fn parse_root_fields(value: &Value) -> Result<BTreeMap<String, FieldSchema>, GatewayRecipeError> {
    let root = value
        .as_object()
        .ok_or(GatewayRecipeError::InvalidProfileLock)?;
    if !exact_keys(root, &["kind", "fields"])
        || root.get("kind").and_then(Value::as_str) != Some("object")
    {
        return Err(GatewayRecipeError::InvalidProfileLock);
    }
    let fields = root
        .get("fields")
        .and_then(Value::as_object)
        .ok_or(GatewayRecipeError::InvalidProfileLock)?;
    if fields.is_empty() || fields.len() > 32 {
        return Err(GatewayRecipeError::InvalidProfileLock);
    }
    fields
        .iter()
        .map(|(name, value)| {
            if !valid_field_name(name) {
                return Err(GatewayRecipeError::InvalidProfileLock);
            }
            Ok((name.clone(), parse_field_schema(value)?))
        })
        .collect()
}

fn parse_field_schema(value: &Value) -> Result<FieldSchema, GatewayRecipeError> {
    let object = value
        .as_object()
        .ok_or(GatewayRecipeError::InvalidProfileLock)?;
    if object.get("type").and_then(Value::as_str) == Some("enum") {
        if !exact_keys(object, &["type", "variants"]) {
            return Err(GatewayRecipeError::InvalidProfileLock);
        }
        let values = object
            .get("variants")
            .and_then(Value::as_array)
            .ok_or(GatewayRecipeError::InvalidProfileLock)?;
        if values.is_empty() || values.len() > 32 {
            return Err(GatewayRecipeError::InvalidProfileLock);
        }
        let variants: Vec<String> = values
            .iter()
            .map(|value| {
                let text = value
                    .as_str()
                    .ok_or(GatewayRecipeError::InvalidProfileLock)?;
                if !valid_enum_variant(text) {
                    return Err(GatewayRecipeError::InvalidProfileLock);
                }
                Ok(text.to_owned())
            })
            .collect::<Result<_, _>>()?;
        if variants.iter().collect::<BTreeSet<_>>().len() != variants.len() {
            return Err(GatewayRecipeError::InvalidProfileLock);
        }
        return Ok(FieldSchema::Enum { variants });
    }
    match object.get("kind").and_then(Value::as_str) {
        Some("string") if exact_keys(object, &["kind", "minimum", "maximum"]) => {
            let minimum = object
                .get("minimum")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or(GatewayRecipeError::InvalidProfileLock)?;
            let maximum = object
                .get("maximum")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or(GatewayRecipeError::InvalidProfileLock)?;
            if minimum > maximum || maximum > 4096 {
                return Err(GatewayRecipeError::InvalidProfileLock);
            }
            Ok(FieldSchema::String { minimum, maximum })
        }
        Some("integer") if exact_keys(object, &["kind", "minimum", "maximum"]) => {
            let minimum = object
                .get("minimum")
                .and_then(Value::as_i64)
                .ok_or(GatewayRecipeError::InvalidProfileLock)?;
            let maximum = object
                .get("maximum")
                .and_then(Value::as_i64)
                .ok_or(GatewayRecipeError::InvalidProfileLock)?;
            if minimum > maximum || minimum < -(2_i64.pow(53) - 1) || maximum > 2_i64.pow(53) - 1 {
                return Err(GatewayRecipeError::InvalidProfileLock);
            }
            Ok(FieldSchema::Integer { minimum, maximum })
        }
        Some("boolean") if exact_keys(object, &["kind"]) => Ok(FieldSchema::Boolean),
        _ => Err(GatewayRecipeError::InvalidProfileLock),
    }
}

fn validate_binding_fields(
    fields: &BTreeMap<String, FieldSchema>,
    namespace: &OperatorNamespace,
) -> Result<(), GatewayRecipeError> {
    if !matches!(
        fields.get("operator_namespace"),
        Some(FieldSchema::Enum { variants }) if variants.len() == 1 && variants[0] == namespace.as_str()
    ) || !matches!(
        fields.get("operation_id"),
        Some(FieldSchema::String { minimum, maximum }) if *minimum >= 1 && *maximum <= 128
    ) || !matches!(
        fields.get("recipe_digest"),
        Some(FieldSchema::String {
            minimum: 64,
            maximum: 64
        })
    ) {
        return Err(GatewayRecipeError::ProfileMismatch);
    }
    Ok(())
}

fn validate_origin(origin: &str) -> Result<(), GatewayRecipeError> {
    let parsed = Url::parse(origin).map_err(|_| GatewayRecipeError::UnsafeOrigin)?;
    let host = parsed.host();
    if parsed.scheme() != "https"
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(host, Some(Host::Domain(_)))
        || !origin.ends_with(parsed.host_str().unwrap_or_default())
    {
        return Err(GatewayRecipeError::UnsafeOrigin);
    }
    let Some(Host::Domain(domain)) = host else {
        return Err(GatewayRecipeError::UnsafeOrigin);
    };
    if domain.len() > 253
        || domain == "localhost"
        || domain.ends_with(".localhost")
        || domain.ends_with(".local")
        || domain.ends_with(".internal")
        || !domain.contains('.')
    {
        return Err(GatewayRecipeError::UnsafeOrigin);
    }
    Ok(())
}

fn valid_field_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'_' | b'-' | b'.'))
        })
}

fn valid_enum_variant(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
}

fn validate_path(
    path: &[PathSegment],
    fields: &BTreeMap<String, FieldSchema>,
    used: &mut BTreeSet<String>,
) -> Result<(), GatewayRecipeError> {
    if path.is_empty() || path.len() > MAX_PATH_SEGMENTS {
        return Err(GatewayRecipeError::UnsafePath);
    }
    for segment in path {
        match segment {
            PathSegment::Fixed { value } => {
                if value.is_empty()
                    || value.len() > 128
                    || matches!(value.as_str(), "." | "..")
                    || !value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
                    })
                {
                    return Err(GatewayRecipeError::UnsafePath);
                }
            }
            PathSegment::Field { name } => {
                if !fields.get(name).is_some_and(FieldSchema::is_path_scalar)
                    || matches!(name.as_str(), "operator_namespace" | "recipe_digest")
                {
                    return Err(GatewayRecipeError::UnsafePath);
                }
                used.insert(name.clone());
            }
        }
    }
    Ok(())
}

fn validate_body(
    body: &BodySource,
    fields: &BTreeMap<String, FieldSchema>,
    used: &mut BTreeSet<String>,
) -> Result<(), GatewayRecipeError> {
    let mut nodes = 0;
    match body {
        BodySource::Json { value } => validate_value_expr(value, fields, used, 0, &mut nodes),
        BodySource::Form { fields: form } => {
            if form.is_empty() || form.len() > 16 {
                return Err(GatewayRecipeError::UnsafeTemplate);
            }
            for (name, value) in form {
                if !valid_field_name(name) {
                    return Err(GatewayRecipeError::UnsafeTemplate);
                }
                match value {
                    FormExpr::String { value } if value.len() <= 1024 => {}
                    FormExpr::Field { name } => {
                        validate_field_ref(name, fields, used)?;
                    }
                    FormExpr::Json { value } => {
                        if matches!(value, ValueExpr::Array { items } if items.len() != 1) {
                            return Err(GatewayRecipeError::UnsafeTemplate);
                        }
                        validate_value_expr(value, fields, used, 0, &mut nodes)?;
                    }
                    _ => return Err(GatewayRecipeError::UnsafeTemplate),
                }
            }
            Ok(())
        }
    }
}

fn validate_field_ref(
    name: &str,
    fields: &BTreeMap<String, FieldSchema>,
    used: &mut BTreeSet<String>,
) -> Result<(), GatewayRecipeError> {
    if !fields.contains_key(name) || matches!(name, "operator_namespace" | "recipe_digest") {
        return Err(GatewayRecipeError::UnsafeTemplate);
    }
    used.insert(name.to_owned());
    Ok(())
}

fn validate_value_expr(
    value: &ValueExpr,
    fields: &BTreeMap<String, FieldSchema>,
    used: &mut BTreeSet<String>,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), GatewayRecipeError> {
    *nodes += 1;
    if *nodes > MAX_TEMPLATE_NODES || depth > MAX_TEMPLATE_DEPTH {
        return Err(GatewayRecipeError::UnsafeTemplate);
    }
    match value {
        ValueExpr::String { value } if value.len() <= 1024 => Ok(()),
        ValueExpr::Integer { value } if value.unsigned_abs() <= (2_u64.pow(53) - 1) => Ok(()),
        ValueExpr::Boolean { .. } => Ok(()),
        ValueExpr::Field { name } => validate_field_ref(name, fields, used),
        ValueExpr::Object { fields: object } if !object.is_empty() && object.len() <= 32 => {
            for (key, child) in object {
                if !valid_field_name(key) {
                    return Err(GatewayRecipeError::UnsafeTemplate);
                }
                validate_value_expr(child, fields, used, depth + 1, nodes)?;
            }
            Ok(())
        }
        ValueExpr::Array { items } if !items.is_empty() && items.len() <= 16 => {
            for child in items {
                validate_value_expr(child, fields, used, depth + 1, nodes)?;
            }
            Ok(())
        }
        _ => Err(GatewayRecipeError::UnsafeTemplate),
    }
}

fn validate_observation(
    source: &ObservationSource,
    fields: &BTreeMap<String, FieldSchema>,
    used: &mut BTreeSet<String>,
) -> Result<(), GatewayRecipeError> {
    if source.maximum_response_bytes == 0
        || source.maximum_response_bytes > 65_536
        || !source.json_pointer.starts_with('/')
        || source.json_pointer.len() > 128
        || source.json_pointer.split('/').skip(1).count() > 8
        || source.json_pointer.contains("~2")
    {
        return Err(GatewayRecipeError::UnsafeTemplate);
    }
    validate_field_ref(&source.expected_field, fields, used)
}

fn build_path(
    segments: &[PathSegment],
    arguments: &Map<String, Value>,
) -> Result<String, GatewayRecipeError> {
    let mut path = String::new();
    for segment in segments {
        path.push('/');
        match segment {
            PathSegment::Fixed { value } => path.push_str(value),
            PathSegment::Field { name } => {
                let value = arguments
                    .get(name)
                    .and_then(Value::as_str)
                    .ok_or(GatewayRecipeError::ActionMismatch)?;
                if value.is_empty() || matches!(value, "." | "..") || value.len() > 4096 {
                    return Err(GatewayRecipeError::UnsafePath);
                }
                for byte in value.bytes() {
                    if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                        path.push(char::from(byte));
                    } else {
                        path.push('%');
                        path.push_str(&format!("{byte:02X}"));
                    }
                }
            }
        }
    }
    if path.len() > 8192 {
        return Err(GatewayRecipeError::UnsafePath);
    }
    Ok(path)
}

fn build_body(
    body: &BodySource,
    arguments: &Map<String, Value>,
) -> Result<(&'static str, Vec<u8>), GatewayRecipeError> {
    match body {
        BodySource::Json { value } => {
            let value = eval_value_expr(value, arguments)?;
            let bytes = serde_json_canonicalizer::to_vec(&value)
                .map_err(|_| GatewayRecipeError::UnsafeTemplate)?;
            Ok(("application/json", bytes))
        }
        BodySource::Form { fields } => {
            let mut pairs = form_urlencoded::Serializer::new(String::new());
            for (name, value) in fields {
                let text = match value {
                    FormExpr::String { value } => value.clone(),
                    FormExpr::Field { name } => arguments
                        .get(name)
                        .and_then(Value::as_str)
                        .ok_or(GatewayRecipeError::ActionMismatch)?
                        .to_owned(),
                    FormExpr::Json { value } => {
                        let evaluated = eval_value_expr(value, arguments)?;
                        let bytes = serde_json_canonicalizer::to_vec(&evaluated)
                            .map_err(|_| GatewayRecipeError::UnsafeTemplate)?;
                        String::from_utf8(bytes).map_err(|_| GatewayRecipeError::UnsafeTemplate)?
                    }
                };
                pairs.append_pair(name, &text);
            }
            Ok((
                "application/x-www-form-urlencoded",
                pairs.finish().into_bytes(),
            ))
        }
    }
}

fn eval_value_expr(
    value: &ValueExpr,
    arguments: &Map<String, Value>,
) -> Result<Value, GatewayRecipeError> {
    match value {
        ValueExpr::String { value } => Ok(Value::String(value.clone())),
        ValueExpr::Integer { value } => Ok(Value::from(*value)),
        ValueExpr::Boolean { value } => Ok(Value::Bool(*value)),
        ValueExpr::Field { name } => arguments
            .get(name)
            .cloned()
            .ok_or(GatewayRecipeError::ActionMismatch),
        ValueExpr::Object { fields } => fields
            .iter()
            .map(|(name, value)| Ok((name.clone(), eval_value_expr(value, arguments)?)))
            .collect::<Result<Map<String, Value>, _>>()
            .map(Value::Object),
        ValueExpr::Array { items } => items
            .iter()
            .map(|value| eval_value_expr(value, arguments))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileGatewayAttemptStore, GatewayAttemptError, GatewayAttemptStage};
    use serde_json::json;
    use std::sync::Arc;

    fn fixture(name: &str) -> (&'static [u8], &'static [u8]) {
        match name {
            "airtable" => (
                include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json"),
                include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json"),
            ),
            "todoist" => (
                include_bytes!("../../../../bindings/fixtures/gateway/todoist/recipe.json"),
                include_bytes!("../../../../bindings/fixtures/gateway/todoist/profile.lock.json"),
            ),
            "github" => (
                include_bytes!("../../../../bindings/fixtures/gateway/github/recipe.json"),
                include_bytes!("../../../../bindings/fixtures/gateway/github/profile.lock.json"),
            ),
            _ => panic!("unknown test-only fixture"),
        }
    }

    fn compiled(name: &str) -> CompiledRecipe {
        let (recipe, lock) = fixture(name);
        CompiledRecipe::compile(recipe, lock).expect("canonical fixture compiles")
    }

    fn arguments(recipe: &CompiledRecipe, values: Value) -> Map<String, Value> {
        let mut object = values.as_object().expect("object fixture").clone();
        object.insert(
            "operator_namespace".into(),
            Value::String(recipe.namespace().as_str().to_owned()),
        );
        object.insert("recipe_digest".into(), Value::String(recipe.digest_hex()));
        object
    }

    #[test]
    fn three_independent_recipes_compile_without_provider_code() {
        for name in ["airtable", "todoist", "github"] {
            let recipe = compiled(name);
            assert!(recipe.review().origin().starts_with("https://"));
            assert_eq!(recipe.digest_hex().len(), 64);
            assert_eq!(recipe.review().maximum_body_bytes(), MAX_BODY_BYTES);
        }
    }

    #[test]
    fn hostile_recipe_corpus_fails_with_exact_codes() {
        let corpus: Value = serde_json::from_slice(include_bytes!(
            "../../../../bindings/fixtures/gateway/hostile-recipes.json"
        ))
        .expect("valid corpus");
        assert_eq!(
            corpus.get("schema").and_then(Value::as_str),
            Some("auths.gateway-hostile-recipes/1")
        );
        for case in corpus["cases"].as_array().expect("cases") {
            let base = case["base"].as_str().expect("base");
            let pointer = case["pointer"].as_str().expect("pointer");
            let expected = case["code"].as_str().expect("code");
            let (source, lock) = fixture(base);
            let mut mutated: Value = serde_json::from_slice(source).expect("recipe JSON");
            let value = case["value"].clone();
            if pointer.ends_with("/items/1") {
                mutated
                    .pointer_mut("/write/body/fields/commands/value/items")
                    .and_then(Value::as_array_mut)
                    .expect("array")
                    .push(value);
            } else if pointer == "/write/headers" {
                mutated
                    .as_object_mut()
                    .and_then(|object| object.get_mut("write"))
                    .and_then(Value::as_object_mut)
                    .expect("write")
                    .insert("headers".into(), value);
            } else {
                *mutated.pointer_mut(pointer).expect("existing pointer") = value;
            }
            let bytes = serde_json::to_vec(&mutated).expect("fixture JSON");
            let result = CompiledRecipe::compile(&bytes, lock).expect_err("hostile recipe");
            assert_eq!(result.code(), expected, "{}", case["id"]);
        }
    }

    #[test]
    fn airtable_closed_request_uses_only_bound_values() {
        let recipe = compiled("airtable");
        let arguments = arguments(
            &recipe,
            json!({
                "operation_id": "run-123",
                "record_id": "recTEST0000000001",
                "replacement": "Approved"
            }),
        );
        let request = recipe
            .closed_request_from_arguments(&arguments)
            .expect("closed request");
        assert_eq!(request.method(), WriteMethod::Patch);
        assert_eq!(
            request.url(),
            "https://api.airtable.com/v0/appTEST0000000001/tblTEST0000000001/recTEST0000000001"
        );
        assert_eq!(request.body(), br#"{"fields":{"DemoStatus":"Approved"}}"#);
        let observation = request.observation().expect("read-back declared");
        assert_eq!(observation.json_pointer(), "/fields/DemoStatus");
        assert_eq!(observation.expected(), "Approved");
    }

    #[test]
    fn todoist_sync_body_is_compiler_serialized_one_command() {
        let recipe = compiled("todoist");
        let arguments = arguments(
            &recipe,
            json!({
                "operation_id": "f38bff5f-430e-4fe1-814b-6e43690a641f",
                "content": "Auths gateway test",
                "description": "Auths demo run f38bff5f-430e-4fe1-814b-6e43690a641f",
                "temp_id": "f5034de3-4de1-42e0-bb54-70a340226f0e"
            }),
        );
        let request = recipe
            .closed_request_from_arguments(&arguments)
            .expect("closed request");
        assert_eq!(request.method(), WriteMethod::Post);
        assert_eq!(request.url(), "https://api.todoist.com/api/v1/sync");
        let form: BTreeMap<String, String> = form_urlencoded::parse(request.body())
            .into_owned()
            .collect();
        assert_eq!(form.len(), 1);
        let commands: Value = serde_json::from_str(&form["commands"]).expect("JSON form field");
        assert_eq!(commands.as_array().expect("array").len(), 1);
        assert_eq!(commands[0]["type"], "item_add");
    }

    #[test]
    fn github_recipe_change_invalidates_old_authorized_arguments() {
        let original = compiled("github");
        let arguments = arguments(
            &original,
            json!({"operation_id": "issue-1", "title": "Example", "body": "Example body"}),
        );
        let (source, lock) = fixture("github");
        let mut mutated: Value = serde_json::from_slice(source).expect("source");
        mutated["write"]["path"][2]["value"] = Value::String("other-repo".into());
        let changed = CompiledRecipe::compile(&serde_json::to_vec(&mutated).expect("source"), lock)
            .expect("deliberate changed recipe");
        assert_ne!(original.digest(), changed.digest());
        assert_eq!(
            changed.closed_request_from_arguments(&arguments).err(),
            Some(GatewayRecipeError::ActionMismatch)
        );
    }

    #[test]
    fn logical_id_and_namespace_are_canonical_and_bounded() {
        assert!(LogicalOperationId::parse("run-1.2").is_ok());
        assert!(OperatorNamespace::parse("operator_A").is_ok());
        for hostile in ["", "-leading", "with/slash", "with space", "x\n"] {
            assert!(LogicalOperationId::parse(hostile).is_err());
            assert!(OperatorNamespace::parse(hostile).is_err());
        }
        assert!(LogicalOperationId::parse(&"x".repeat(129)).is_err());
        assert!(OperatorNamespace::parse(&"x".repeat(65)).is_err());
    }

    #[test]
    fn durable_claim_is_one_use_across_races_and_restart() {
        let fixture: Value = serde_json::from_slice(include_bytes!(
            "../../../../bindings/fixtures/gateway/attempt-scenarios.json"
        ))
        .expect("valid state corpus");
        assert_eq!(fixture["schema"], "auths.gateway-attempt-scenarios/1");
        assert_eq!(fixture["cases"].as_array().expect("cases").len(), 9);
        let recipe = compiled("github");
        let args = arguments(
            &recipe,
            json!({"operation_id": "issue-42", "title": "Exact", "body": "One issue"}),
        );
        let request = Arc::new(
            recipe
                .closed_request_from_arguments(&args)
                .expect("request"),
        );
        let temp = tempfile::tempdir().expect("temp directory");
        let root = std::fs::canonicalize(temp.path())
            .expect("canonical temp")
            .join("attempts");
        let store = Arc::new(FileGatewayAttemptStore::open(&root).expect("private store"));
        let outcomes: Vec<_> = (0..16)
            .map(|_| {
                let store = Arc::clone(&store);
                let request = Arc::clone(&request);
                let digest = *recipe.digest();
                std::thread::spawn(move || store.claim(&request, [7; 32], digest))
            })
            .map(|thread| thread.join().expect("thread"))
            .collect();
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, Err(GatewayAttemptError::Replay)))
                .count(),
            15
        );
        drop(outcomes);
        drop(store);
        let restarted = FileGatewayAttemptStore::open(&root).expect("restart");
        let snapshot = restarted
            .read(request.namespace(), request.operation_id())
            .expect("read")
            .expect("retained claim");
        assert_eq!(snapshot.stage(), GatewayAttemptStage::Unknown);
        assert!(matches!(
            restarted.claim(&request, [8; 32], *recipe.digest()),
            Err(GatewayAttemptError::Replay)
        ));
    }

    #[test]
    fn response_and_observation_are_distinct_durable_stages() {
        let recipe = compiled("airtable");
        let args = arguments(
            &recipe,
            json!({"operation_id": "record-1", "record_id": "recTEST0000000001", "replacement": "Approved"}),
        );
        let request = recipe
            .closed_request_from_arguments(&args)
            .expect("request");
        let temp = tempfile::tempdir().expect("temp directory");
        let root = std::fs::canonicalize(temp.path())
            .expect("canonical temp")
            .join("attempts");
        let store = FileGatewayAttemptStore::open(&root).expect("store");
        let claim = store
            .claim(&request, [9; 32], *recipe.digest())
            .expect("claim");
        let response = claim.record_response(200, [3; 32]).expect("response");
        assert_eq!(
            response.snapshot().expect("snapshot").stage(),
            GatewayAttemptStage::ResponseRecorded
        );
        let observed = response.record_observation(true).expect("observation");
        assert_eq!(observed.stage(), GatewayAttemptStage::Observed);
        assert_eq!(observed.observation_match(), Some(true));
        assert_eq!(
            store
                .read(request.namespace(), request.operation_id())
                .expect("read"),
            Some(observed)
        );
        assert!(matches!(
            store.claim(&request, [9; 32], *recipe.digest()),
            Err(GatewayAttemptError::Replay)
        ));
    }
}
