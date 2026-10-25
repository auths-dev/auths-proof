//! Recipe source `auths.gateway-recipe-source/2`: compilation, operator
//! review, recovery capability, and closed request construction.
//!
//! The compiler parses the source once into a typed AST, refuses anything
//! outside the compile rules with a stable code, and lowers the result into
//! closed request plans. Request construction itself is the pure leaf in
//! [`construct`], and the recovery capability the pure leaf in [`recovery`],
//! both from `auths-gateway-kernel`; this module only validates verified
//! arguments against the profile lock, derives the echo token and idempotency
//! key, and converts the constructed bytes into the gateway's request types.

use auths_model::MAX_FACT_VALUE_TEXT_BYTES;
use auths_gateway_kernel::field_projection::{self, NamedInput, RequestArguments, RequestBindingError};
use auths_gateway_kernel::scalars;
use auths_gateway_kernel::recipe_binding::{self, LockMetadata, ProfileBinding};
use auths_profile_mcp::McpCommand;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use url::{Host, Url};

pub use auths_gateway_kernel::{construct, recovery};

mod lower;
mod profile;
mod review;
mod runtime;
#[macro_use]
mod serde_decode;
mod source;
pub(crate) mod strict_json;
mod validate;

#[cfg(test)]
mod tests;

pub use recovery::{
    IdempotencyKind, LostClaimReentry, RecoveryCapability, RecoveryClass, RecoveryDeclarations,
    StateObservation, UnknownResolution, recovery_capability,
};
pub(crate) use review::recovery_document;
pub use review::{
    RECIPE_REVIEW_SCHEMA, RECOVERY_CAPABILITY_SCHEMA, RecipeEchoReview, RecipePreconditionReview,
    RecipeReview,
};

use construct::{ArgumentValue, ConstructError};
pub(crate) use runtime::{
    CeilingCheck, CeilingReading, ENTRY_DEADLINE_SECONDS, GuardChecks, MAX_ACCOUNT_BYTES,
    ObservationTemplate,
};
use source::{CredentialSource, IdempotencySource, PathSegment, RecipeSource};

/// The only recipe source schema the compiler accepts.
pub const RECIPE_SOURCE_SCHEMA: &str = recipe_binding::SOURCE_SCHEMA;
const MAX_BODY_BYTES: usize = construct::MAX_BODY_BYTES;
const MAX_PATH_SEGMENTS: usize = auths_gateway_kernel::path_compiler::MAX_PATH_SEGMENTS;
const MAX_FORM_FIELDS: usize = 16;
const IDEMPOTENCY_HEADER: &str = auths_gateway_kernel::request_compiler::IDEMPOTENCY_HEADER;
const DENIED_READ_RESPONSE_BYTES: u64 = 16_384;
const MAX_POINTER_BYTES: usize = 128;
const MAX_VERIFIED_FIELDS: usize = 8;

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
    auths_gateway_kernel::identity::valid_token(value.as_bytes(), maximum)
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
    /// The credential header may be neither a transport or content header,
    /// nor the derived idempotency header, nor any registered provider header.
    fn validate(&self) -> Result<(), GatewayRecipeError> {
        if let Self::HeaderApiKey { header } = self {
            if header.is_empty() || header.len() > 64 {
                return Err(GatewayRecipeError::InvalidCredential);
            }
            if !credential_header_token(header)
                || auths_gateway_kernel::header_compiler::reserved_credential_header_name(header.as_bytes())
                || registered_provider_header(header)
            {
                return Err(GatewayRecipeError::InvalidCredential);
            }
        }
        Ok(())
    }
}

fn credential_header_token(header: &str) -> bool {
    let bytes = header.as_bytes();
    let mut position = 0;
    let mut valid = true;
    while position < bytes.len() && valid {
        valid = auths_gateway_kernel::construct::is_alphanumeric(bytes[position])
            || (position > 0 && bytes[position] == b'-');
        position += 1;
    }
    valid
}

fn registered_provider_header(header: &str) -> bool {
    auths_gateway_kernel::header_compiler::registered_header_name(header.as_bytes())
}

/// Closed write methods. GET is reserved for a separately declared observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
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

pub use auths_gateway_kernel::header_compiler::{ProviderHeaderClass, ProviderResponseRule};
use auths_gateway_kernel::header_compiler::{ProviderHeaderEntry, PROVIDER_HEADERS};

/// The shared catalog entry spelled exactly `name`.
pub(crate) fn provider_header(name: &str) -> Option<&'static ProviderHeaderEntry> {
    match auths_gateway_kernel::header_compiler::header_index(name.as_bytes()) {
        Some(0) => Some(&PROVIDER_HEADERS[0]),
        Some(1) => Some(&PROVIDER_HEADERS[1]),
        Some(2) => Some(&PROVIDER_HEADERS[2]),
        Some(_) | None => None,
    }
}

/// Closed compiler failure with a stable non-secret diagnostic code.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum GatewayRecipeError {
    /// Source shape, type, size, or schema is invalid.
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
    /// The credential guard's prefixes, probe, account read, or denied reads
    /// are outside their rules.
    #[error("invalid credential guard")]
    InvalidCredentialGuard,
    /// A provider header is unregistered, not a version header, or has a
    /// value its grammar refuses.
    #[error("invalid provider header")]
    InvalidProviderHeader,
    /// The account-scope header or its field is outside its rules.
    #[error("invalid account scope")]
    InvalidAccountScope,
    /// The bounds declaration is outside its rules.
    #[error("invalid bounds")]
    InvalidBounds,
    /// A sum partition reaches neither the provider nor a relative-ceiling
    /// bind.
    #[error("unbound partition")]
    UnboundPartition,
    /// The relative ceiling is outside its rules.
    #[error("invalid relative ceiling")]
    InvalidRelativeCeiling,
    /// The idempotency declaration is outside its rules.
    #[error("invalid idempotency declaration")]
    InvalidIdempotency,
    /// A response-field segment is misplaced or outside its rules.
    #[error("response locator conflict")]
    ResponseLocatorConflict,
    /// The pre-entry re-read is outside its rules.
    #[error("invalid pre-entry re-read")]
    InvalidPreEntry,
    /// Operator namespace is invalid.
    #[error("invalid operator namespace")]
    InvalidNamespace,
    /// Logical operation ID is invalid.
    #[error("invalid logical operation ID")]
    InvalidOperationId,
    /// Verified action does not match the approved profile or recipe.
    #[error("verified action does not match approved recipe")]
    ActionMismatch,
    /// The verified account-scope value is outside its header's registered
    /// grammar, so it could end or add a header line.
    #[error("account-scope value outside its registered grammar")]
    InvalidAccountScopeValue,
    /// An echo field was declared without a read-only observation.
    #[error("recipe echo requires an observation")]
    EchoWithoutObservation,
    /// The echo placement is not a new fixed JSON body key or a new form
    /// field, or an echo source appears anywhere other than the
    /// compiler-owned placement.
    #[error("recipe echo conflicts with the request template")]
    EchoConflict,
    /// A read-back subject argument was declared without a read-only observation.
    #[error("recipe precondition subject requires an observation")]
    PreconditionWithoutObservation,
    /// A precondition argument is a binding field, is used by the request,
    /// is repeated, or has no observation-fact form, or the read-back subject
    /// names a record located by the write response.
    #[error("recipe precondition conflicts with the request template")]
    PreconditionConflict,
    /// The verified read-back subject argument does not name the record this
    /// request observes.
    #[error("verified read-back subject does not name the observed record")]
    PreconditionSubjectMismatch,
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
            Self::InvalidCredentialGuard => "gateway.recipe.invalid-credential-guard",
            Self::InvalidProviderHeader => "gateway.recipe.invalid-provider-header",
            Self::InvalidAccountScope => "gateway.recipe.invalid-account-scope",
            Self::InvalidBounds => "gateway.recipe.invalid-bounds",
            Self::UnboundPartition => "gateway.recipe.unbound-partition",
            Self::InvalidRelativeCeiling => "gateway.recipe.invalid-relative-ceiling",
            Self::InvalidIdempotency => "gateway.recipe.invalid-idempotency",
            Self::ResponseLocatorConflict => "gateway.recipe.response-locator-conflict",
            Self::InvalidPreEntry => "gateway.recipe.invalid-pre-entry",
            Self::InvalidNamespace => "gateway.recipe.invalid-namespace",
            Self::InvalidOperationId => "gateway.recipe.invalid-operation-id",
            Self::ActionMismatch => "gateway.recipe.action-mismatch",
            Self::InvalidAccountScopeValue => "gateway.account-scope.invalid-value",
            Self::EchoWithoutObservation => "gateway.recipe.echo-without-observation",
            Self::EchoConflict => "gateway.recipe.echo-conflict",
            Self::PreconditionWithoutObservation => {
                "gateway.recipe.precondition-without-observation"
            }
            Self::PreconditionConflict => "gateway.recipe.precondition-conflict",
            Self::PreconditionSubjectMismatch => "gateway.recipe.precondition-subject-mismatch",
        }
    }

    const fn from_construct(error: ConstructError) -> Self {
        match error {
            ConstructError::ArgumentMismatch => Self::ActionMismatch,
            ConstructError::HeaderValue => Self::InvalidAccountScopeValue,
            ConstructError::UnsafeSegment | ConstructError::PathTooLong => Self::UnsafePath,
            ConstructError::BodySize => Self::UnsafeTemplate,
        }
    }
}

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

recipe_record_decode!(ProfileLockFile {
    schema: String => required,
    profile: String => required,
    version: u16 => required,
    service: String => required,
    tool: String => required,
    schema_digest: String => required,
    command_schema: Value => required,
    generator_format: u8 => required,
});
recipe_external_unit_decode!(WriteMethod {
    0 => "POST" => Post,
    1 => "PUT" => Put,
    2 => "PATCH" => Patch,
    3 => "DELETE" => Delete,
});

use scalars::ScalarSchema as FieldSchema;

/// The JSON boundary extracts a carrier by its actual JSON kind. It never
/// chooses a representation from the requested schema or coerces a string,
/// float, boolean or collection into another scalar kind.
fn scalar_input(value: &Value) -> scalars::ScalarInput<'_> {
    match value {
        Value::String(text) => scalars::ScalarInput::Text(text.as_bytes()),
        Value::Number(number) => match number.as_i64() {
            Some(value) => scalars::ScalarInput::Integer(value),
            None => scalars::ScalarInput::Unsupported,
        },
        Value::Bool(value) => scalars::ScalarInput::Boolean(*value),
        Value::Null | Value::Array(_) | Value::Object(_) => scalars::ScalarInput::Unsupported,
    }
}

trait FieldSchemaRuntime {
    fn validate_value(&self, value: &Value) -> bool;
    fn is_path_scalar(&self) -> bool;
    fn is_form_scalar(&self) -> bool;
    fn has_fact_form(&self) -> bool;
    fn argument_value(&self, value: &Value) -> Option<ArgumentValue>;
}

impl FieldSchemaRuntime for FieldSchema {
    fn validate_value(&self, value: &Value) -> bool {
        scalars::scalar_valid(self, scalar_input(value))
    }

    fn is_path_scalar(&self) -> bool {
        matches!(self, Self::String { .. } | Self::Enum { .. })
    }

    fn is_form_scalar(&self) -> bool {
        scalars::form_schema_allowed(self)
    }

    /// Reports whether every valid value maps to an observation fact value.
    fn has_fact_form(&self) -> bool {
        match self {
            Self::String { maximum, .. } => *maximum <= MAX_FACT_VALUE_TEXT_BYTES,
            Self::Enum { .. } => true,
            Self::Integer { minimum, .. } => *minimum >= 0,
            Self::Boolean => false,
        }
    }

    /// Validates the complete scalar and returns its exact construction value.
    fn argument_value(&self, value: &Value) -> Option<ArgumentValue> {
        scalars::project_scalar(self, scalar_input(value))
    }
}

/// Validated, bounded, digest-stable recipe tied to one generated profile lock.
/// Compilation grants no authority to execute or lease a credential.
#[derive(Clone, Debug)]
pub struct CompiledRecipe {
    source: RecipeSource,
    namespace: OperatorNamespace,
    digest: [u8; 32],
    plans: lower::Plans,
}

/// The shipping decoded-source constructor. The public bounded parser computes
/// both canonical outcomes from these exact original values before calling it.
/// Validation, digest, plans and namespace are derived in their original order;
/// a private checked record alone is not a source-admission proof.
fn compile_decoded(
    source: RecipeSource,
    lock: &ProfileLockFile,
    canonical: &CanonicalRecipeInputs,
) -> Result<CompiledRecipe, GatewayRecipeError> {
    let checked = validate::validate_source(&source, lock, canonical)?;
    let digest = checked.digest()?;
    let plans = lower::plans(&checked)?;
    let namespace = checked.into_namespace();
    Ok(CompiledRecipe {
        source,
        namespace,
        digest,
        plans,
    })
}

// The selected formal entry is the actual byte-to-compiled-source caller.
// Keeping this as one free function gives extraction a stable source root;
// it must include the called Auths serde derives rather than treating a typed
// decoder or serializer supplied by Auths as an ordinary-library contract.
fn compile_source_bytes(source_bytes: &[u8], lock_bytes: &[u8]) -> Result<CompiledRecipe, GatewayRecipeError> {
    if !recipe_binding::source_lengths_bounded(source_bytes.len(), lock_bytes.len()) {
        return Err(GatewayRecipeError::InvalidSource);
    }
    let source: RecipeSource =
        strict_json::from_slice(source_bytes).map_err(|_| GatewayRecipeError::InvalidSource)?;
    let lock: ProfileLockFile = strict_json::from_slice(lock_bytes)
        .map_err(|_| GatewayRecipeError::InvalidProfileLock)?;
    let canonical = CanonicalRecipeInputs::from_decoded(&source, &lock);
    compile_decoded(source, &lock, &canonical)
}

impl CompiledRecipe {
    /// Compiles source against the exact generated profile lock. Only
    /// `auths.gateway-recipe-source/2` is accepted.
    ///
    /// # Errors
    /// Rejects malformed, unbounded, stale, or unsafe mappings with the code
    /// of the rule they break. This operation does not install the recipe or
    /// authorize an action.
    pub fn compile(source_bytes: &[u8], lock_bytes: &[u8]) -> Result<Self, GatewayRecipeError> {
        compile_source_bytes(source_bytes, lock_bytes)
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

    /// What this recipe can prove after an ambiguous write.
    #[must_use]
    pub fn recovery(&self) -> RecoveryCapability {
        recovery_capability(self.recovery_declarations())
    }

    fn recovery_declarations(&self) -> RecoveryDeclarations {
        let observation = match &self.source.observation {
            None => StateObservation::None,
            Some(observation)
                if observation
                    .path
                    .iter()
                    .any(|segment| matches!(segment, PathSegment::ResponseField { .. })) =>
            {
                StateObservation::ResponseLocator
            }
            Some(_) => StateObservation::VerifiedLocator,
        };
        let idempotency = match &self.source.write.idempotency {
            None => LostClaimReentry::None,
            Some(IdempotencySource::DerivedHeader { retention_seconds }) => {
                LostClaimReentry::Declared {
                    kind: IdempotencyKind::DerivedHeader,
                    retention_seconds: *retention_seconds,
                }
            }
            Some(IdempotencySource::OperationIdField {
                retention_seconds, ..
            }) => LostClaimReentry::Declared {
                kind: IdempotencyKind::OperationIdField,
                retention_seconds: *retention_seconds,
            },
        };
        RecoveryDeclarations {
            observation,
            echo: self.source.echo.is_some(),
            idempotency,
            pre_entry: self.source.pre_entry.is_some(),
        }
    }

    /// The credential reads the recipe declares: the probe, the account read,
    /// and the denied reads, in declaration order. Each is built from the
    /// recipe alone and carries only the version headers.
    ///
    /// # Errors
    /// Returns `gateway.recipe.unsafe-path` only if a constructed URL is not
    /// ASCII, which the compile rules exclude.
    pub fn credential_reads(&self) -> Result<ClosedCredentialReads, GatewayRecipeError> {
        let guard = self.source.credential.guard();
        let probe_bound = guard
            .and_then(|guard| guard.probe.as_ref())
            .map_or(0, |probe| probe.maximum_response_bytes);
        let account_bound = guard
            .and_then(|guard| guard.account.as_ref())
            .map_or(0, |account| account.maximum_response_bytes);
        let probe = self
            .plans
            .probe
            .as_ref()
            .map(|plan| ClosedCredentialRead::from_plan(plan, probe_bound))
            .transpose()?;
        let account = self
            .plans
            .account
            .as_ref()
            .map(|plan| ClosedCredentialRead::from_plan(plan, account_bound))
            .transpose()?;
        let denied = self
            .plans
            .denied
            .iter()
            .map(|plan| ClosedCredentialRead::from_plan(plan, DENIED_READ_RESPONSE_BYTES))
            .collect::<Result<_, _>>()?;
        Ok(ClosedCredentialReads {
            probe,
            account,
            denied,
        })
    }

    /// Builds a closed request only from a native-verified MCP command and
    /// the commitment of that same verified action. When the recipe declares
    /// an echo field, the token is derived here from the commitment; when it
    /// declares the derived idempotency header, the key is derived here from
    /// the verified namespace and logical operation ID. No submit-time input
    /// can supply or change either.
    ///
    /// # Errors
    /// Rejects a mismatched service/tool, schema value, recipe digest,
    /// namespace, logical ID, account-scope value, or unsafe substitution
    /// before any credential access or network entry.
    pub fn closed_request(
        &self,
        command: &McpCommand,
        action_commitment: [u8; 32],
    ) -> Result<ClosedProviderRequest, GatewayRecipeError> {
        if command.call().service() != self.source.service || command.name() != self.source.tool {
            return Err(GatewayRecipeError::ActionMismatch);
        }
        self.closed_request_from_arguments(command.arguments(), action_commitment)
    }

    /// Binds the verified object's namespace/digest, projects its complete
    /// field set, and obtains its operation in the same kernel invocation.
    fn request_arguments(
        &self,
        arguments: &Map<String, Value>,
    ) -> Result<RequestArguments, GatewayRecipeError> {
        if arguments.len() != self.plans.field_schemas.len() {
            return Err(GatewayRecipeError::ActionMismatch);
        }
        let supplied: Vec<_> = arguments
            .iter()
            .map(|(name, value)| NamedInput {
                name: name.as_bytes(),
                value: scalar_input(value),
            })
            .collect();
        field_projection::project_request(
            &self.plans.field_schemas, &supplied, self.namespace.as_str().as_bytes(),
            self.digest_hex().as_bytes(),
        ).map_err(|error| match error {
            RequestBindingError::ActionMismatch => GatewayRecipeError::ActionMismatch,
            RequestBindingError::Projection(error) => GatewayRecipeError::from_construct(error),
            RequestBindingError::OperationId => GatewayRecipeError::InvalidOperationId,
        })
    }

    /// The request shell around the construction leaf: arguments are
    /// validated and converted, the echo token and key are derived, and the
    /// leaf builds the write and every action read.
    pub(crate) fn closed_request_from_arguments(
        &self,
        arguments: &Map<String, Value>,
        action_commitment: [u8; 32],
    ) -> Result<ClosedProviderRequest, GatewayRecipeError> {
        let admitted = self.request_arguments(arguments)?;
        let operation_id = LogicalOperationId::parse(&ascii(admitted.operation_id)?)?;
        let values = admitted.values;
        let echo = self
            .source
            .echo
            .as_ref()
            .map(|_| echo_token(&self.namespace, &operation_id, &action_commitment));
        let key = matches!(
            self.source.write.idempotency,
            Some(IdempotencySource::DerivedHeader { .. })
        )
        .then(|| idempotency_key(&self.namespace, &operation_id));
        let built = construct::construct_write(
            &self.plans.write,
            &values,
            echo.as_deref().unwrap_or_default().as_bytes(),
            key.as_deref().unwrap_or_default().as_bytes(),
        )
        .map_err(GatewayRecipeError::from_construct)?;
        let content_type = match self.plans.write.body {
            construct::BodyPlan::Json(_) => "application/json",
            construct::BodyPlan::Form(_) => "application/x-www-form-urlencoded",
        };
        let observation = self.observation_request(arguments, &values)?;
        let headers = request_headers(built.headers)?;
        let observation_template = match &self.source.observation {
            Some(source) => self.observation_template(
                &values,
                &headers,
                arguments
                    .get(&source.expected_field)
                    .ok_or(GatewayRecipeError::ActionMismatch)?,
            )?,
            None => None,
        };
        let pre_entry = action_read(self.plans.pre_entry.as_ref(), &values, || {
            self.source
                .pre_entry
                .as_ref()
                .map_or(0, |source| source.maximum_response_bytes)
        })?;
        let relative_ceiling = action_read(self.plans.relative_ceiling.as_ref(), &values, || {
            self.source
                .relative_ceiling
                .as_ref()
                .map_or(0, |source| source.maximum_response_bytes)
        })?;
        self.check_read_back_subject(arguments, observation.as_ref())?;
        Ok(ClosedProviderRequest {
            namespace: self.namespace.clone(),
            recipe_digest: self.digest,
            operation_id,
            action_commitment,
            echo,
            idempotency_key: key,
            method: self.source.write.method,
            url: ascii(built.url)?,
            content_type,
            body: built.body,
            headers,
            credential_requirement: credential_requirement(&self.source.credential),
            observation,
            observation_template,
            pre_entry,
            relative_ceiling,
        })
    }

    fn observation_request(
        &self,
        arguments: &Map<String, Value>,
        values: &[ArgumentValue],
    ) -> Result<Option<ClosedObservationRequest>, GatewayRecipeError> {
        let (Some(plan), Some(source)) = (&self.plans.observation, &self.source.observation) else {
            return Ok(None);
        };
        let read = ClosedActionRead::construct(plan, values, source.maximum_response_bytes)?;
        Ok(Some(ClosedObservationRequest {
            url: read.url,
            headers: read.headers,
            json_pointer: source.json_pointer.clone(),
            expected: arguments
                .get(&source.expected_field)
                .cloned()
                .ok_or(GatewayRecipeError::ActionMismatch)?,
            maximum_response_bytes: source.maximum_response_bytes,
            echo_pointer: self.source.echo.as_ref().map(|echo| echo.observe.clone()),
        }))
    }

    /// Refuses a verified action whose declared read-back subject argument
    /// does not name exactly the record this request observes. Without this,
    /// a requirement whose subject is that argument could be met by an
    /// observation of one record while the write targets another.
    fn check_read_back_subject(
        &self,
        arguments: &Map<String, Value>,
        observation: Option<&ClosedObservationRequest>,
    ) -> Result<(), GatewayRecipeError> {
        let Some(field) = self
            .source
            .preconditions
            .as_ref()
            .and_then(|source| source.read_back_subject.as_deref())
        else {
            return Ok(());
        };
        let subject = observation
            .ok_or(GatewayRecipeError::PreconditionWithoutObservation)?
            .subject();
        if arguments.get(field).and_then(Value::as_str) == Some(subject.as_str()) {
            Ok(())
        } else {
            Err(GatewayRecipeError::PreconditionSubjectMismatch)
        }
    }

    /// Builds the recipe's read-only observation for a gateway read-back
    /// observation requested before any action exists. `arguments` must name
    /// exactly the observation path's fields, each valid under the profile
    /// lock; the URL is built from the approved origin and path alone. The
    /// result carries no expected value and is never compared or recorded.
    ///
    /// # Errors
    /// Rejects a recipe without a verified-locator observation, a recipe that
    /// declares an account-scope header (no verified value exists here), a
    /// missing or extra argument, or a value outside its schema.
    pub fn read_back_target(
        &self,
        arguments: &Map<String, Value>,
    ) -> Result<ClosedObservationRequest, GatewayRecipeError> {
        let (Some(plan), Some(source)) = (&self.plans.observation, &self.source.observation) else {
            return Err(GatewayRecipeError::ActionMismatch);
        };
        if self.source.account_scope.is_some() {
            return Err(GatewayRecipeError::ActionMismatch);
        }
        let names: std::collections::BTreeSet<&str> = source
            .path
            .iter()
            .filter_map(|segment| match segment {
                PathSegment::Field { name } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        if arguments.len() != names.len()
            || !arguments.iter().all(|(name, value)| {
                names.contains(name.as_str())
                    && field_projection::schema_for(&self.plans.field_schemas, name.as_bytes())
                        .is_some_and(|schema| schema.validate_value(value))
            })
        {
            return Err(GatewayRecipeError::ActionMismatch);
        }
        // Only the path's fields are known. Every other slot holds a value no
        // path segment accepts, so a plan that read one would refuse.
        let values: Vec<ArgumentValue> = self
            .plans.field_schemas
            .iter()
            .map(|field| {
                arguments
                    .iter()
                    .find(|(name, _)| name.as_bytes() == field.name.as_slice())
                    .and_then(|(_, value)| field.schema.argument_value(value))
                    .unwrap_or(ArgumentValue::Boolean(false))
            })
            .collect();
        let read = ClosedActionRead::construct(plan, &values, source.maximum_response_bytes)?;
        Ok(ClosedObservationRequest {
            url: read.url,
            headers: read.headers,
            json_pointer: source.json_pointer.clone(),
            expected: Value::Null,
            maximum_response_bytes: source.maximum_response_bytes,
            echo_pointer: self.source.echo.as_ref().map(|echo| echo.observe.clone()),
        })
    }
}

fn action_read(
    plan: Option<&construct::ActionReadPlan>,
    values: &[ArgumentValue],
    bound: impl FnOnce() -> u64,
) -> Result<Option<ClosedActionRead>, GatewayRecipeError> {
    plan.map(|plan| ClosedActionRead::construct(plan, values, bounded_usize(bound())))
        .transpose()
}

fn bounded_usize(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn ascii(bytes: Vec<u8>) -> Result<String, GatewayRecipeError> {
    if !bytes.is_ascii() {
        return Err(GatewayRecipeError::UnsafePath);
    }
    String::from_utf8(bytes).map_err(|_| GatewayRecipeError::UnsafePath)
}

fn request_headers(
    headers: Vec<construct::Header>,
) -> Result<Vec<RequestHeader>, GatewayRecipeError> {
    headers
        .into_iter()
        .map(|header| {
            if !header.name.is_ascii() || !header.value.is_ascii() {
                return Err(GatewayRecipeError::ActionMismatch);
            }
            Ok(RequestHeader {
                name: String::from_utf8(header.name)
                    .map_err(|_| GatewayRecipeError::ActionMismatch)?,
                value: String::from_utf8(header.value)
                    .map_err(|_| GatewayRecipeError::ActionMismatch)?,
            })
        })
        .collect()
}

fn credential_requirement(source: &CredentialSource) -> CredentialRequirement {
    match source {
        CredentialSource::Bearer { .. } => CredentialRequirement::Bearer,
        CredentialSource::HeaderApiKey { header, .. } => CredentialRequirement::HeaderApiKey {
            header: header.clone(),
        },
    }
}

/// One non-credential request header: a registered version header, the
/// declared account-scope header, or the derived `Idempotency-Key`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestHeader {
    name: String,
    value: String,
}

impl RequestHeader {
    /// Returns the header name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Returns the header value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// Credential-free closed HTTP request derived from a verified action.
/// Its fields cannot be supplied by the application at submission time.
#[derive(Clone, Debug)]
pub struct ClosedProviderRequest {
    namespace: OperatorNamespace,
    recipe_digest: [u8; 32],
    operation_id: LogicalOperationId,
    action_commitment: [u8; 32],
    echo: Option<String>,
    idempotency_key: Option<String>,
    method: WriteMethod,
    url: String,
    content_type: &'static str,
    body: Vec<u8>,
    headers: Vec<RequestHeader>,
    credential_requirement: CredentialRequirement,
    observation: Option<ClosedObservationRequest>,
    observation_template: Option<ObservationTemplate>,
    pre_entry: Option<ClosedActionRead>,
    relative_ceiling: Option<ClosedActionRead>,
}

impl ClosedProviderRequest {
    /// Returns the operator namespace.
    #[must_use]
    pub const fn namespace(&self) -> &OperatorNamespace {
        &self.namespace
    }
    /// Returns the exact compiled mapping digest retained when this request
    /// was constructed. Durable claims and transport derive their recipe
    /// binding from this same request; a caller cannot supply another digest.
    #[must_use]
    pub const fn recipe_digest(&self) -> &[u8; 32] {
        &self.recipe_digest
    }
    /// Returns the durable logical operation ID.
    #[must_use]
    pub const fn operation_id(&self) -> &LogicalOperationId {
        &self.operation_id
    }
    /// Returns the commitment of the verified action this request was built from.
    #[must_use]
    pub const fn action_commitment(&self) -> &[u8; 32] {
        &self.action_commitment
    }
    /// Returns the echo token written into the body, when the recipe declares one.
    #[must_use]
    pub fn echo_token(&self) -> Option<&str> {
        self.echo.as_deref()
    }
    /// Returns the `Idempotency-Key` value the write sends, only when the
    /// recipe declares the derived header. No read ever sends it.
    #[must_use]
    pub fn idempotency_key(&self) -> Option<&str> {
        self.idempotency_key.as_deref()
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
    /// Returns every non-credential header the write sends: the version
    /// headers, the account-scope header, and the derived `Idempotency-Key`,
    /// each only when declared.
    #[must_use]
    pub fn headers(&self) -> &[RequestHeader] {
        &self.headers
    }
    /// Returns the static credential-header requirement, not a credential.
    #[must_use]
    pub const fn credential_requirement(&self) -> &CredentialRequirement {
        &self.credential_requirement
    }
    /// Returns the optional closed read-back request. A response-locator
    /// observation has none until its locator is read from the recorded
    /// write response.
    #[must_use]
    pub const fn observation(&self) -> Option<&ClosedObservationRequest> {
        self.observation.as_ref()
    }
    /// Returns the observation fixed at the claim: resolved from verified
    /// fields, with any response-field pointers still to be read from the
    /// recorded response.
    pub(crate) const fn observation_template(&self) -> Option<&ObservationTemplate> {
        self.observation_template.as_ref()
    }
    /// Returns the declared pre-entry re-read.
    #[must_use]
    pub const fn pre_entry_read(&self) -> Option<&ClosedActionRead> {
        self.pre_entry.as_ref()
    }
    /// Returns the declared relative-ceiling read.
    #[must_use]
    pub const fn relative_ceiling_read(&self) -> Option<&ClosedActionRead> {
        self.relative_ceiling.as_ref()
    }
}

/// An action read other than the observation: a GET built from fixed
/// segments and verified fields, with the version headers and the declared
/// account-scope header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosedActionRead {
    url: String,
    headers: Vec<RequestHeader>,
    maximum_response_bytes: usize,
}

impl ClosedActionRead {
    fn construct(
        plan: &construct::ActionReadPlan,
        values: &[ArgumentValue],
        maximum_response_bytes: usize,
    ) -> Result<Self, GatewayRecipeError> {
        let built = construct::construct_action_read(plan, values)
            .map_err(GatewayRecipeError::from_construct)?;
        Ok(Self {
            url: ascii(built.url)?,
            headers: request_headers(built.headers)?,
            maximum_response_bytes,
        })
    }

    /// Returns the closed GET URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }
    /// Returns the provider headers the read sends.
    #[must_use]
    pub fn headers(&self) -> &[RequestHeader] {
        &self.headers
    }
    /// Returns the enforced response-byte limit.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> usize {
        self.maximum_response_bytes
    }
    /// Returns the subject of the field at `pointer` in this read's
    /// response: the URL with the pointer as its fragment.
    #[must_use]
    pub fn subject(&self, pointer: &str) -> String {
        format!("{}#{pointer}", self.url)
    }
}

/// The method of a credential read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialReadMethod {
    /// HTTP GET.
    Get,
    /// HTTP HEAD.
    Head,
}

impl CredentialReadMethod {
    /// Returns the fixed HTTP spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
        }
    }
}

/// A credential read: a fixed request built from the recipe alone. It carries
/// the version headers and never an action value or account-scope header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosedCredentialRead {
    method: CredentialReadMethod,
    url: String,
    headers: Vec<RequestHeader>,
    maximum_response_bytes: usize,
}

impl ClosedCredentialRead {
    fn from_plan(
        plan: &construct::CredentialReadPlan,
        maximum_response_bytes: u64,
    ) -> Result<Self, GatewayRecipeError> {
        let built = construct::construct_credential_read(plan);
        let method = match built.method {
            construct::RequestMethod::Head => CredentialReadMethod::Head,
            _ => CredentialReadMethod::Get,
        };
        Ok(Self {
            method,
            url: ascii(built.url)?,
            headers: request_headers(built.headers)?,
            maximum_response_bytes: bounded_usize(maximum_response_bytes),
        })
    }

    /// Returns the declared method.
    #[must_use]
    pub const fn method(&self) -> CredentialReadMethod {
        self.method
    }
    /// Returns the fixed URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }
    /// Returns the version headers the read sends.
    #[must_use]
    pub fn headers(&self) -> &[RequestHeader] {
        &self.headers
    }
    /// Returns the response-byte bound.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> usize {
        self.maximum_response_bytes
    }
}

/// Every credential read a recipe declares.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosedCredentialReads {
    probe: Option<ClosedCredentialRead>,
    account: Option<ClosedCredentialRead>,
    denied: Vec<ClosedCredentialRead>,
}

impl ClosedCredentialReads {
    /// Returns the onboarding probe, if declared.
    #[must_use]
    pub const fn probe(&self) -> Option<&ClosedCredentialRead> {
        self.probe.as_ref()
    }
    /// Returns the account read, if declared.
    #[must_use]
    pub const fn account(&self) -> Option<&ClosedCredentialRead> {
        self.account.as_ref()
    }
    /// Returns the denied reads in declaration order.
    #[must_use]
    pub fn denied(&self) -> &[ClosedCredentialRead] {
        &self.denied
    }
}

/// One approved read-only comparison; matching never proves causation.
#[derive(Clone, Debug)]
pub struct ClosedObservationRequest {
    url: String,
    headers: Vec<RequestHeader>,
    json_pointer: String,
    expected: Value,
    maximum_response_bytes: usize,
    echo_pointer: Option<String>,
}

/// Classified read-back. Only an exact echo-token match links the provider
/// record to the authorized action; nothing here proves absence of an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadBack {
    /// No echo token was found (or none is declared); plain value equality.
    Value { matched: bool },
    /// The echo field holds exactly this attempt's token and the value matched.
    EchoMatched,
    /// The echo field holds something other than this attempt's token.
    EchoMismatch,
}

impl ClosedObservationRequest {
    /// Returns the closed GET URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }
    /// Returns the provider headers the read-back sends.
    #[must_use]
    pub fn headers(&self) -> &[RequestHeader] {
        &self.headers
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
    /// Returns the fixed echo pointer in the observation response, if declared.
    #[must_use]
    pub fn echo_pointer(&self) -> Option<&str> {
        self.echo_pointer.as_deref()
    }

    /// Returns the canonical subject URI of a gateway read-back observation:
    /// the closed observation URL with the observed JSON pointer as its
    /// fragment, so observations of different fields of one record differ.
    #[must_use]
    pub fn subject(&self) -> String {
        format!("{}#{}", self.url, self.json_pointer)
    }

    /// Extracts the observed value and, when an echo field is declared and
    /// present, its value from bounded response bytes. A response that is too
    /// large, not JSON, contains duplicate object members, or lacks the
    /// observed value yields `None`.
    pub(crate) fn observed_values(&self, response: &[u8]) -> Option<(Value, Option<Value>)> {
        if response.len() > self.maximum_response_bytes {
            return None;
        }
        let decoded: Value = strict_json::from_slice(response).ok()?;
        let value = decoded.pointer(&self.json_pointer)?.clone();
        let echo = self
            .echo_pointer
            .as_deref()
            .and_then(|pointer| decoded.pointer(pointer))
            .filter(|echo| !echo.is_null())
            .cloned();
        Some((value, echo))
    }

    /// Classifies bounded response bytes against the verified expected value
    /// and, when declared, the attempt's echo token. A missing value, or bytes
    /// that are not unique-member JSON, is an unavailable observation.
    pub(crate) fn read_back(&self, token: Option<&str>, response: &[u8]) -> Option<ReadBack> {
        if response.len() > self.maximum_response_bytes {
            return None;
        }
        let decoded: Value = strict_json::from_slice(response).ok()?;
        let matched = decoded.pointer(&self.json_pointer)? == &self.expected;
        let (Some(pointer), Some(token)) = (self.echo_pointer.as_deref(), token) else {
            return Some(ReadBack::Value { matched });
        };
        Some(match decoded.pointer(pointer) {
            None | Some(Value::Null) => ReadBack::Value { matched },
            Some(Value::String(found)) if found == token => {
                if matched {
                    ReadBack::EchoMatched
                } else {
                    ReadBack::Value { matched: false }
                }
            }
            Some(_) => ReadBack::EchoMismatch,
        })
    }
}

/// Derives the 73-byte echo token for one namespace, logical operation, and
/// verified action commitment. Anyone who knows those three values can
/// compute it, so it is a link, not a signature.
#[must_use]
pub fn echo_token(
    namespace: &OperatorNamespace,
    operation_id: &LogicalOperationId,
    action_commitment: &[u8; 32],
) -> String {
    let preimage = auths_gateway_kernel::derived_tokens::echo_preimage(
        namespace.as_str().as_bytes(), operation_id.as_str().as_bytes(), action_commitment,
    );
    let digest: [u8; 32] = Sha256::digest(preimage).into();
    // The closed renderer emits only ASCII. Standard byte-to-char collection
    // therefore preserves every byte without a fallible UTF-8 fallback.
    auths_gateway_kernel::derived_tokens::echo_token_bytes(&digest)
        .into_iter().map(char::from).collect()
}

/// Derives the 73-byte `Idempotency-Key` value for one logical operation in
/// one operator namespace. Nothing else enters it, so a fresh proof
/// challenge, a changed action, or a new credential generation for the same
/// logical operation yields the same key. Anyone who knows the namespace and
/// operation ID can compute it, so it is neither a secret nor a signature.
///
/// The gateway's durable claim of the same pair already stops a second
/// provider entry while its attempt store is intact. The key matters only
/// when that claim is lost and the operation is submitted again: a provider
/// that honors the header can then de-duplicate the repeat, within the
/// provider's own retention window.
#[must_use]
pub fn idempotency_key(namespace: &OperatorNamespace, operation_id: &LogicalOperationId) -> String {
    let preimage = auths_gateway_kernel::derived_tokens::idempotency_preimage(
        namespace.as_str().as_bytes(), operation_id.as_str().as_bytes(),
    );
    let digest: [u8; 32] = Sha256::digest(preimage).into();
    auths_gateway_kernel::derived_tokens::idempotency_token_bytes(&digest)
        .into_iter().map(char::from).collect()
}

// Foreign JSON canonicalization is evaluated once from these same immutable
// decoded values. Retain failures as data so admission consumes them at the
// original rule boundary, rather than changing which error wins.
struct CanonicalRecipeInputs {
    schema: Result<Vec<u8>, ()>,
    source: Result<Vec<u8>, ()>,
}

impl CanonicalRecipeInputs {
    fn from_decoded(source: &RecipeSource, lock: &ProfileLockFile) -> Self {
        Self {
            schema: serde_json_canonicalizer::to_vec(&lock.command_schema).map_err(|_| ()),
            source: serde_json_canonicalizer::to_vec(source).map_err(|_| ()),
        }
    }
}

fn validate_lock(lock: &ProfileLockFile, canonical: &Result<Vec<u8>, ()>) -> Result<(), GatewayRecipeError> {
    if !recipe_binding::lock_metadata_valid(LockMetadata {
        schema: lock.schema.as_bytes(), generator_format: lock.generator_format,
        version: lock.version, profile: lock.profile.as_bytes(),
        binding: ProfileBinding { service: lock.service.as_bytes(), tool: lock.tool.as_bytes(), schema_digest: lock.schema_digest.as_bytes() },
    }) {
        return Err(GatewayRecipeError::InvalidProfileLock);
    }
    let schema_bytes = match canonical {
        Ok(bytes) => bytes.as_slice(),
        Err(()) => return Err(GatewayRecipeError::InvalidProfileLock),
    };
    let digest: [u8; 32] = Sha256::digest(schema_bytes).into();
    if !recipe_binding::schema_digest_matches(lock.schema_digest.as_bytes(), &digest) {
        return Err(GatewayRecipeError::InvalidProfileLock);
    }
    Ok(())
}

fn parse_root_fields(value: &Value) -> Result<Vec<field_projection::FieldSpec>, GatewayRecipeError> {
    profile::parse_root(value)
}

#[cfg(test)]
fn parse_field_schema(value: &Value) -> Result<FieldSchema, GatewayRecipeError> {
    profile::parse_scalar(value)
}

fn validate_binding_fields(
    fields: &[field_projection::FieldSpec],
    namespace: &OperatorNamespace,
) -> Result<(), GatewayRecipeError> {
    if !auths_gateway_kernel::profile_schema::binding_fields_match(fields, namespace.as_str().as_bytes()) {
        return Err(GatewayRecipeError::ProfileMismatch);
    }
    Ok(())
}

fn validate_origin(origin: &str) -> Result<String, GatewayRecipeError> {
    if origin.len() > auths_gateway_kernel::path_compiler::MAX_ORIGIN_BYTES {
        return Err(GatewayRecipeError::UnsafeOrigin);
    }
    let parsed = Url::parse(origin).map_err(|_| GatewayRecipeError::UnsafeOrigin)?;
    if !auths_gateway_kernel::construct::field_name_equal(parsed.scheme().as_bytes(), b"https")
        || !parsed.username().as_bytes().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || !auths_gateway_kernel::construct::field_name_equal(parsed.path().as_bytes(), b"/")
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(GatewayRecipeError::UnsafeOrigin);
    }
    let domain = match parsed.host() {
        Some(Host::Domain(domain)) => domain.to_owned(),
        _ => return Err(GatewayRecipeError::UnsafeOrigin),
    };
    if !auths_gateway_kernel::path_compiler::origin_matches_host(origin.as_bytes(), domain.as_bytes())
        || !origin_domain_allowed(&domain)
    {
        return Err(GatewayRecipeError::UnsafeOrigin);
    }
    Ok(domain)
}

fn origin_domain_allowed(domain: &str) -> bool {
    if domain.len() > 253 { return false; }
    let bytes = domain.as_bytes();
    let mut end = bytes.len();
    // A final DNS root dot leaves the existing hostname policy class intact.
    if end > 0 && bytes[end - 1] == b'.' { end -= 1; }
    let policy = &bytes[..end];
    !auths_gateway_kernel::construct::field_name_equal(policy, b"localhost")
        && !policy.ends_with(b".localhost")
        && !auths_gateway_kernel::construct::field_name_equal(policy, b"local")
        && !policy.ends_with(b".local")
        && !policy.ends_with(b".internal")
        && policy.contains(&b'.')
}

fn valid_field_name(name: &str) -> bool {
    auths_gateway_kernel::identity::valid_token(name.as_bytes(), 64)
}
