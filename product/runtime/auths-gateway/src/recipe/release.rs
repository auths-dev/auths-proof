//! A closed read-release recipe. Compilation and projection alone confer no
//! authority to call a provider or deliver content to an agent.

use super::construct::{self, ActionReadPlan, ArgumentValue, HeaderPlan, SegmentPlan};
use super::source::PathSegment;
use super::{
    CredentialRequirement, FieldSchema, GatewayRecipeError, LogicalOperationId, OperatorNamespace,
    ProfileLockFile, parse_root_fields, validate_binding_fields, validate_lock, validate_origin,
};
use auths_profile_mcp::McpCommand;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use url::form_urlencoded;

/// The only release source schema accepted by this compiler.
pub const RELEASE_RECIPE_SOURCE_SCHEMA: &str = "auths.gateway-release-recipe-source/1";
/// Operator review projection for a compiled release recipe.
pub const RELEASE_RECIPE_REVIEW_SCHEMA: &str = "auths.gateway-release-recipe-review/1";
const MAX_SOURCE_BYTES: usize = 16_384;
const MAX_LOCK_BYTES: usize = 65_536;
const MAX_PROVIDER_BYTES: u64 = 1_048_576;
const MAX_RELEASE_BYTES: u64 = 262_144;
const DIGEST_DOMAIN: &[u8] = b"auths.gateway-release-recipe/1\0";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseSource {
    schema: String,
    profile_schema_digest: String,
    service: String,
    tool: String,
    operator_namespace: String,
    credential: CredentialRequirement,
    origin: String,
    path: Vec<PathSegment>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    query: BTreeMap<String, String>,
    resource_field: String,
    recipient_field: String,
    response: ResponseSource,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResponseSource {
    status: u16,
    media_type: String,
    maximum_provider_bytes: u64,
    maximum_release_bytes: u64,
    projection: Projection,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Projection {
    WholeText,
    JsonString { pointer: String },
}

/// A compiled release recipe tied to one exact profile lock.
///
/// It can construct a GET and project a bounded response, but cannot perform
/// native verification, lease credentials, reserve budgets or send content.
#[derive(Clone, Debug)]
pub struct CompiledReleaseRecipe {
    source: ReleaseSource,
    fields: BTreeMap<String, FieldSchema>,
    namespace: OperatorNamespace,
    digest: [u8; 32],
    plan: ActionReadPlan,
    fixed_query: String,
}

/// One credential-free GET derived from a native-verified command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosedReleaseRequest {
    namespace: OperatorNamespace,
    operation_id: LogicalOperationId,
    task_id: String,
    task_commitment: [u8; 32],
    resource_handle: String,
    recipient: String,
    recipe_digest: [u8; 32],
    action_commitment: [u8; 32],
    url: String,
}

impl ClosedReleaseRequest {
    /// The operator-approved HTTPS URL, including only fixed query values.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The verified task ID, for a later task-admission check.
    #[must_use]
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    /// Commitment to the exact human-signed task card.
    #[must_use]
    pub const fn task_commitment(&self) -> &[u8; 32] {
        &self.task_commitment
    }

    /// The exact signed resource handle committed to a release receipt.
    #[must_use]
    pub fn resource_handle(&self) -> &str {
        &self.resource_handle
    }

    /// The verified agent principal, for a later recipient-channel check.
    #[must_use]
    pub fn recipient(&self) -> &str {
        &self.recipient
    }

    /// Exact reviewed release recipe bound in the native-verified action.
    #[must_use]
    pub const fn recipe_digest(&self) -> &[u8; 32] {
        &self.recipe_digest
    }

    /// The stable, replay-claimed logical operation ID.
    #[must_use]
    pub const fn operation_id(&self) -> &LogicalOperationId {
        &self.operation_id
    }

    /// The operator replay namespace.
    #[must_use]
    pub const fn namespace(&self) -> &OperatorNamespace {
        &self.namespace
    }

    /// Commitment of the native-verified canonical action.
    #[must_use]
    pub const fn action_commitment(&self) -> &[u8; 32] {
        &self.action_commitment
    }
}

/// A provider response cannot be released under this recipe.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ReleaseProjectionError {
    /// Status is not the one the operator approved.
    #[error("provider status is unavailable for release")]
    Status,
    /// Media type is not the one the operator approved.
    #[error("provider media type is unavailable for release")]
    MediaType,
    /// Body is oversized, malformed or not valid UTF-8.
    #[error("provider body is unavailable for release")]
    Body,
    /// The declared projection is absent or has a different JSON type.
    #[error("declared content projection is unavailable")]
    Projection,
}

impl CompiledReleaseRecipe {
    /// Compile closed source against one exact generated profile lock.
    ///
    /// # Errors
    /// Refuses unknown fields, stale locks, unsafe origins/paths, dynamic
    /// queries, unbounded responses and unsupported projections.
    pub fn compile(source_bytes: &[u8], lock_bytes: &[u8]) -> Result<Self, GatewayRecipeError> {
        if source_bytes.is_empty()
            || source_bytes.len() > MAX_SOURCE_BYTES
            || lock_bytes.is_empty()
            || lock_bytes.len() > MAX_LOCK_BYTES
        {
            return Err(GatewayRecipeError::InvalidSource);
        }
        let source: ReleaseSource =
            serde_json::from_slice(source_bytes).map_err(|_| GatewayRecipeError::InvalidSource)?;
        let lock: ProfileLockFile = serde_json::from_slice(lock_bytes)
            .map_err(|_| GatewayRecipeError::InvalidProfileLock)?;
        if source.schema != RELEASE_RECIPE_SOURCE_SCHEMA {
            return Err(GatewayRecipeError::InvalidSource);
        }
        validate_lock(&lock)?;
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
        let plan = validate_and_lower(&source, &fields)?;
        let fixed_query = fixed_query(&source.query)?;
        let canonical = serde_json_canonicalizer::to_vec(&source)
            .map_err(|_| GatewayRecipeError::InvalidSource)?;
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(canonical);
        Ok(Self {
            source,
            fields,
            namespace,
            digest: hasher.finalize().into(),
            plan,
            fixed_query,
        })
    }

    /// Canonical lowercase digest committed by a release action.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        hex::encode(self.digest)
    }

    /// The exact operator namespace sealed into a read connection.
    #[must_use]
    pub const fn namespace(&self) -> &OperatorNamespace {
        &self.namespace
    }

    /// Digest bytes sealed into a read connection.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The credential header shape; never the credential value.
    #[must_use]
    pub const fn credential_requirement(&self) -> &CredentialRequirement {
        &self.source.credential
    }

    /// Approved HTTPS origin for the bounded GET transport.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.source.origin
    }

    /// Provider response ceiling checked before projecting any content.
    #[must_use]
    pub fn maximum_provider_bytes(&self) -> usize {
        usize::try_from(self.source.response.maximum_provider_bytes).unwrap_or(1_048_576)
    }

    /// Show the complete, credential-free request and response policy an
    /// operator would pin. Compilation alone does not install this policy.
    #[must_use]
    pub fn review_document(&self) -> Value {
        json!({
            "schema": RELEASE_RECIPE_REVIEW_SCHEMA,
            "digest": self.digest_hex(),
            "profile_schema_digest": self.source.profile_schema_digest,
            "operator_namespace": self.namespace.as_str(),
            "service": self.source.service,
            "tool": self.source.tool,
            "credential": self.source.credential,
            "origin": self.source.origin,
            "method": "GET",
            "path": self.source.path,
            "query": self.source.query,
            "resource_field": self.source.resource_field,
            "recipient_field": self.source.recipient_field,
            "response": self.source.response,
            "disclosure": "Compilation constructs and projects a closed GET. Native verification, task admission, credential leasing, provider transport, durable budgets, recipient delivery and audit-key custody require separate runtime gates."
        })
    }

    /// Build a credential-free request from a native-verified command.
    /// Task admission and credential leasing must happen in a separate engine.
    ///
    /// # Errors
    /// Refuses changed service, tool, arguments, namespace, recipe digest,
    /// task ID, recipient or path value before any provider access.
    pub fn closed_request(
        &self,
        command: &McpCommand,
        action_commitment: [u8; 32],
    ) -> Result<ClosedReleaseRequest, GatewayRecipeError> {
        if command.call().service() != self.source.service || command.name() != self.source.tool {
            return Err(GatewayRecipeError::ActionMismatch);
        }
        self.closed_request_from_arguments(command.arguments(), action_commitment)
    }

    fn closed_request_from_arguments(
        &self,
        arguments: &Map<String, Value>,
        action_commitment: [u8; 32],
    ) -> Result<ClosedReleaseRequest, GatewayRecipeError> {
        if arguments.len() != self.fields.len()
            || arguments.get("operator_namespace").and_then(Value::as_str)
                != Some(self.namespace.as_str())
            || arguments.get("recipe_digest").and_then(Value::as_str)
                != Some(self.digest_hex().as_str())
        {
            return Err(GatewayRecipeError::ActionMismatch);
        }
        let values: Vec<ArgumentValue> = self
            .fields
            .iter()
            .map(|(name, schema)| {
                arguments
                    .get(name)
                    .filter(|value| schema.validate_value(value))
                    .and_then(|value| schema.argument_value(value))
                    .ok_or(GatewayRecipeError::ActionMismatch)
            })
            .collect::<Result<_, _>>()?;
        let operation_id = arguments
            .get("operation_id")
            .and_then(Value::as_str)
            .ok_or(GatewayRecipeError::InvalidOperationId)
            .and_then(LogicalOperationId::parse)?;
        let task_id = arguments
            .get("task_id")
            .and_then(Value::as_str)
            .filter(|value| super::valid_token(value, 128))
            .ok_or(GatewayRecipeError::ActionMismatch)?;
        let task_commitment = arguments
            .get("task_commitment")
            .and_then(Value::as_str)
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
            .and_then(|value| hex::decode(value).ok())
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(GatewayRecipeError::ActionMismatch)?;
        let recipient = arguments
            .get(&self.source.recipient_field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(GatewayRecipeError::ActionMismatch)?;
        let resource_handle = arguments
            .get(&self.source.resource_field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(GatewayRecipeError::ActionMismatch)?;
        let built = construct::construct_action_read(&self.plan, &values)
            .map_err(GatewayRecipeError::from_construct)?;
        let mut url = String::from_utf8(built.url).map_err(|_| GatewayRecipeError::UnsafePath)?;
        url.push_str(&self.fixed_query);
        if url.len() > construct::MAX_PATH_BYTES + self.source.origin.len() + 512 {
            return Err(GatewayRecipeError::UnsafePath);
        }
        Ok(ClosedReleaseRequest {
            namespace: self.namespace.clone(),
            operation_id,
            task_id: task_id.to_owned(),
            task_commitment,
            resource_handle: resource_handle.to_owned(),
            recipient: recipient.to_owned(),
            recipe_digest: self.digest,
            action_commitment,
            url,
        })
    }

    #[cfg(all(test, feature = "loopback-provider"))]
    pub(crate) fn test_closed_request(
        &self,
        arguments: &Map<String, Value>,
    ) -> Result<ClosedReleaseRequest, GatewayRecipeError> {
        self.closed_request_from_arguments(arguments, [7; 32])
    }

    /// Project exactly the operator-approved bytes from a complete response.
    /// No delivery or receipt is produced by this pure operation.
    ///
    /// # Errors
    /// Rejects wrong status/type, oversized or malformed bodies, missing
    /// pointers and projections over the released-byte ceiling.
    pub fn project(
        &self,
        status: u16,
        content_type: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, ReleaseProjectionError> {
        let response = &self.source.response;
        if status != response.status {
            return Err(ReleaseProjectionError::Status);
        }
        if !content_type_matches(content_type, &response.media_type) {
            return Err(ReleaseProjectionError::MediaType);
        }
        if !u64::try_from(body.len()).is_ok_and(|bytes| bytes <= response.maximum_provider_bytes) {
            return Err(ReleaseProjectionError::Body);
        }
        let selected = match &response.projection {
            Projection::WholeText => {
                std::str::from_utf8(body).map_err(|_| ReleaseProjectionError::Body)?;
                body.to_vec()
            }
            Projection::JsonString { pointer } => {
                let document: Value =
                    serde_json::from_slice(body).map_err(|_| ReleaseProjectionError::Body)?;
                document
                    .pointer(pointer)
                    .and_then(Value::as_str)
                    .ok_or(ReleaseProjectionError::Projection)?
                    .as_bytes()
                    .to_vec()
            }
        };
        if !u64::try_from(selected.len()).is_ok_and(|bytes| bytes <= response.maximum_release_bytes)
        {
            return Err(ReleaseProjectionError::Projection);
        }
        Ok(selected)
    }
}

fn validate_and_lower(
    source: &ReleaseSource,
    fields: &BTreeMap<String, FieldSchema>,
) -> Result<ActionReadPlan, GatewayRecipeError> {
    if source.recipient_field != "agent_principal"
        || !matches!(fields.get("agent_principal"), Some(FieldSchema::String { minimum, maximum }) if *minimum >= 1 && *maximum <= 256)
        || !matches!(fields.get("task_id"), Some(FieldSchema::String { minimum, maximum }) if *minimum >= 1 && *maximum <= 128)
        || !matches!(fields.get("task_commitment"), Some(FieldSchema::String { minimum, maximum }) if *minimum == 64 && *maximum == 64)
        || !matches!(fields.get(&source.resource_field), Some(FieldSchema::String { minimum, maximum }) if *minimum >= 1 && *maximum <= 256)
        || matches!(
            source.resource_field.as_str(),
            "task_id"
                | "task_commitment"
                | "operation_id"
                | "recipe_digest"
                | "operator_namespace"
                | "agent_principal"
        )
        || source.path.is_empty()
        || source.path.len() > 16
    {
        return Err(GatewayRecipeError::ProfileMismatch);
    }
    let mut consumed = BTreeSet::from([
        "operator_namespace".to_owned(),
        "operation_id".to_owned(),
        "recipe_digest".to_owned(),
        "task_id".to_owned(),
        "task_commitment".to_owned(),
        source.recipient_field.clone(),
    ]);
    let mut segments = Vec::with_capacity(source.path.len());
    for segment in &source.path {
        match segment {
            PathSegment::Fixed { value } if super::validate::valid_fixed_segment(value) => {
                segments.push(SegmentPlan::Fixed(value.as_bytes().to_vec()));
            }
            PathSegment::Field { name }
                if fields.get(name).is_some_and(|field| match field {
                    FieldSchema::String { maximum, .. } => *maximum <= 256,
                    FieldSchema::Enum { .. } => true,
                    _ => false,
                }) =>
            {
                consumed.insert(name.clone());
                let index = fields
                    .keys()
                    .position(|field| field == name)
                    .ok_or(GatewayRecipeError::UnsafePath)?;
                segments.push(SegmentPlan::Field(index));
            }
            _ => return Err(GatewayRecipeError::UnsafePath),
        }
    }
    if consumed.len() != fields.len() || !fields.keys().all(|name| consumed.contains(name)) {
        return Err(GatewayRecipeError::ProfileMismatch);
    }
    if !source.path.iter().any(
        |segment| matches!(segment, PathSegment::Field { name } if name == &source.resource_field),
    ) {
        return Err(GatewayRecipeError::ProfileMismatch);
    }
    let response = &source.response;
    if response.status != 200
        || response.maximum_provider_bytes == 0
        || response.maximum_provider_bytes > MAX_PROVIDER_BYTES
        || response.maximum_release_bytes == 0
        || response.maximum_release_bytes > MAX_RELEASE_BYTES
        || response.maximum_release_bytes > response.maximum_provider_bytes
        || !matches!(
            (&response.media_type[..], &response.projection),
            ("text/plain", Projection::WholeText)
                | ("application/json", Projection::JsonString { .. })
        )
    {
        return Err(GatewayRecipeError::UnsafeTemplate);
    }
    if let Projection::JsonString { pointer } = &response.projection
        && !super::validate::valid_response_pointer(pointer)
    {
        return Err(GatewayRecipeError::UnsafeTemplate);
    }
    Ok(ActionReadPlan {
        origin: source.origin.as_bytes().to_vec(),
        path: segments,
        headers: HeaderPlan {
            versions: Vec::new(),
            account_scope: None,
        },
    })
}

fn fixed_query(query: &BTreeMap<String, String>) -> Result<String, GatewayRecipeError> {
    if query.len() > 4 {
        return Err(GatewayRecipeError::UnsafeTemplate);
    }
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (name, value) in query {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .enumerate()
                .all(|(index, byte)| byte.is_ascii_alphanumeric() || (index > 0 && byte == b'_'))
            || value.is_empty()
            || value.len() > 128
            || !value.is_ascii()
            || value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
        {
            return Err(GatewayRecipeError::UnsafeTemplate);
        }
        serializer.append_pair(name, value);
    }
    let encoded = serializer.finish();
    if encoded.is_empty() {
        Ok(String::new())
    } else {
        Ok(format!("?{encoded}"))
    }
}

fn content_type_matches(observed: &str, expected: &str) -> bool {
    let mut parts = observed.split(';');
    let media = parts.next().map(str::trim);
    let charset = parts.next().map(str::trim);
    media == Some(expected)
        && charset.is_none_or(|value| value.eq_ignore_ascii_case("charset=utf-8"))
        && parts.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release_state::{
        ReleaseResourceScope, ReleaseStateError, ReleaseTaskPolicy, ReleaseTaskState,
    };
    use serde_json::json;

    fn fixture(google: bool) -> (&'static [u8], &'static [u8]) {
        if google {
            (
                include_bytes!(
                    "../../../../../demos/google-employee-delegation/read_reference/recipe.json"
                ),
                include_bytes!(
                    "../../../../../demos/google-employee-delegation/read_reference/profile.lock.json"
                ),
            )
        } else {
            (
                include_bytes!("../../../../../demos/airtable-gateway/read_reference/recipe.json"),
                include_bytes!(
                    "../../../../../demos/airtable-gateway/read_reference/profile.lock.json"
                ),
            )
        }
    }

    fn arguments(recipe: &CompiledReleaseRecipe, namespace: &str) -> Map<String, Value> {
        let resource_id = if namespace == "airtable-read-demo" {
            "recTEST0000000001"
        } else {
            "resource-1"
        };
        json!({
            "operator_namespace": namespace,
            "operation_id": "read-1",
            "recipe_digest": recipe.digest_hex(),
            "task_id": "task-1",
            "task_commitment": "01".repeat(32),
            "agent_principal": "agent-principal",
            "resource_id": resource_id
        })
        .as_object()
        .expect("argument object")
        .clone()
    }

    #[test]
    fn google_and_airtable_compile_to_the_same_closed_release_mechanism() {
        let (google_source, google_lock) = fixture(true);
        let google = CompiledReleaseRecipe::compile(google_source, google_lock)
            .expect("Google release compiles");
        let request = google
            .closed_request_from_arguments(&arguments(&google, "google-read-demo"), [7; 32])
            .expect("verified arguments construct a request");
        assert_eq!(
            request.url(),
            "https://www.googleapis.com/drive/v3/files/resource-1/export?mimeType=text%2Fplain"
        );
        assert_eq!(request.recipient(), "agent-principal");
        assert_eq!(request.task_id(), "task-1");
        assert_eq!(request.resource_handle(), "resource-1");
        let review = google.review_document();
        assert_eq!(review["schema"], RELEASE_RECIPE_REVIEW_SCHEMA);
        assert_eq!(review["response"]["projection"]["kind"], "whole-text");
        assert_eq!(review["recipient_field"], "agent_principal");
        assert_eq!(
            google.project(200, "text/plain; charset=UTF-8", b"Project A update"),
            Ok(b"Project A update".to_vec())
        );

        let (airtable_source, airtable_lock) = fixture(false);
        let airtable = CompiledReleaseRecipe::compile(airtable_source, airtable_lock)
            .expect("Airtable release compiles");
        let request = airtable
            .closed_request_from_arguments(&arguments(&airtable, "airtable-read-demo"), [9; 32])
            .expect("verified arguments construct a request");
        assert_eq!(
            request.url(),
            "https://api.airtable.com/v0/appQD3Qf0YFBCW9bV/tblBx2jwe0IsPYRKT/recTEST0000000001"
        );
        assert_eq!(
            airtable.project(
                200,
                "application/json",
                br#"{"fields":{"DemoStatus":"Approved"}}"#
            ),
            Ok(b"Approved".to_vec())
        );
    }

    #[test]
    fn closed_request_admits_only_matching_task_actor_and_connection() {
        let (source, lock) = fixture(true);
        let recipe = CompiledReleaseRecipe::compile(source, lock).expect("release compiles");
        let request = recipe
            .closed_request_from_arguments(&arguments(&recipe, "google-read-demo"), [7; 32])
            .expect("closed request");
        let mut state = ReleaseTaskState::from_test_policy(ReleaseTaskPolicy {
            task_id: "task-1".to_owned(),
            task_commitment: [1; 32],
            company_id: "atlas".to_owned(),
            human_principal: "jules".to_owned(),
            agent_principal: "agent-principal".to_owned(),
            not_before: 100,
            expires_at: 200,
            max_provider_calls: 1,
            max_releases: 1,
            max_release_bytes: 512,
            max_writes: 0,
            write_scopes: vec![],
            connection_id: "jules-google".to_owned(),
            connection_generation: 3,
            connection_subject: "jules-subject".to_owned(),
            resources: vec![ReleaseResourceScope {
                handle: "resource-1".to_owned(),
                recipe_digest: recipe.digest_hex(),
                connection_id: "jules-google".to_owned(),
                connection_generation: 3,
                connection_subject: "jules-subject".to_owned(),
            }],
        })
        .expect("task policy");
        assert_eq!(
            state.reserve_closed_request(
                &request,
                &["other-agent".to_owned()],
                "jules-google",
                3,
                "jules-subject",
                101
            ),
            Err(ReleaseStateError::Binding)
        );
        assert_eq!(
            state.reserve_closed_request(
                &request,
                &["agent-principal".to_owned()],
                "jules-google",
                4,
                "jules-subject",
                101
            ),
            Err(ReleaseStateError::Binding)
        );
        assert_eq!(state.counts(), (0, 0, 0));
        state
            .reserve_closed_request(
                &request,
                &["agent-principal".to_owned()],
                "jules-google",
                3,
                "jules-subject",
                101,
            )
            .expect("exact binding");
        assert_eq!(state.counts(), (1, 0, 0));
    }

    #[test]
    fn changed_action_and_unavailable_projection_never_produce_release_bytes() {
        let (source, lock) = fixture(false);
        let recipe = CompiledReleaseRecipe::compile(source, lock).expect("release compiles");
        let mut changed = arguments(&recipe, "airtable-read-demo");
        changed.insert("recipe_digest".into(), json!("0".repeat(64)));
        assert_eq!(
            recipe
                .closed_request_from_arguments(&changed, [0; 32])
                .err(),
            Some(GatewayRecipeError::ActionMismatch)
        );
        assert_eq!(
            recipe.project(
                403,
                "application/json",
                br#"{"fields":{"DemoStatus":"Approved"}}"#
            ),
            Err(ReleaseProjectionError::Status)
        );
        assert_eq!(
            recipe.project(
                200,
                "application/json",
                br#"{"fields":{"Other":"Approved"}}"#
            ),
            Err(ReleaseProjectionError::Projection)
        );
        assert_eq!(
            recipe.project(200, "text/plain", b"Approved"),
            Err(ReleaseProjectionError::MediaType)
        );
        assert_eq!(
            recipe.project(200, "application/json", &vec![b'x'; 16_385]),
            Err(ReleaseProjectionError::Body)
        );
    }

    #[test]
    fn hostile_source_changes_fail_before_request_construction() {
        let (source, lock) = fixture(true);
        let mut value: Value = serde_json::from_slice(source).expect("source JSON");
        value["origin"] = json!("http://localhost");
        assert_eq!(
            CompiledReleaseRecipe::compile(&serde_json::to_vec(&value).expect("JSON"), lock).err(),
            Some(GatewayRecipeError::UnsafeOrigin)
        );
        value["origin"] = json!("https://www.googleapis.com");
        value["path"][3] = json!({"kind":"response-field","pointer":"/id","max_bytes":128});
        assert_eq!(
            CompiledReleaseRecipe::compile(&serde_json::to_vec(&value).expect("JSON"), lock).err(),
            Some(GatewayRecipeError::UnsafePath)
        );
        value["path"][3] = json!({"kind":"field","name":"resource_id"});
        value["response"]["maximum_release_bytes"] = json!(1_048_577);
        assert_eq!(
            CompiledReleaseRecipe::compile(&serde_json::to_vec(&value).expect("JSON"), lock).err(),
            Some(GatewayRecipeError::UnsafeTemplate)
        );
    }
}
