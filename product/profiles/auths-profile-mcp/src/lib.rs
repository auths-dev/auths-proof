//! Exact `auths.mcp/1` profile and verified command decoder.

#![forbid(unsafe_code)]

mod session;

pub use session::*;

use auths_model::{
    Audience, CanonicalAction, CapabilityId, MediaType, Permission, ProfileId, ProfileRef,
    ResourceId,
};
use auths_profile_api::{ActionProfile, ProfileContractError, ReviewDisplay};
use auths_verifier::VerifiedAction;
use rmcp::model::CallToolRequestParams;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::{fmt, string::String};

/// Exact profile identifier.
pub const PROFILE_ID: &str = "auths.mcp";
/// Exact profile semantic version.
pub const PROFILE_VERSION: u16 = 1;
/// Exact capability derived for MCP tool calls.
pub const CAPABILITY: &str = "tools/call";
/// Exact canonical JSON media type.
pub const MEDIA_TYPE: &str = "application/vnd.auths.mcp-call.v1+json";
/// Maximum service identifier bytes.
pub const MAX_SERVICE_ID_BYTES: usize = 64;
/// Maximum tool-name bytes.
pub const MAX_TOOL_NAME_BYTES: usize = 128;
/// Maximum canonical call bytes.
pub const MAX_CANONICAL_CALL_BYTES: usize = 256 * 1024;

/// Closed canonical MCP `tools/call` action.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpToolCall {
    profile: String,
    profile_version: u16,
    service: String,
    name: String,
    arguments: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    channel_binding: Option<McpChannelBinding>,
}

impl McpToolCall {
    /// Constructs one validated call.
    ///
    /// # Errors
    ///
    /// Returns a typed profile error for invalid service/tool identifiers.
    pub fn new(
        service: impl Into<String>,
        name: impl Into<String>,
        arguments: Map<String, Value>,
    ) -> Result<Self, ProfileError> {
        let call = Self {
            profile: PROFILE_ID.into(),
            profile_version: PROFILE_VERSION,
            service: service.into(),
            name: name.into(),
            arguments,
            channel_binding: None,
        };
        call.validate()?;
        Ok(call)
    }

    /// Maps an immediate official `rmcp` tool call.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::UnsupportedMcpExtension`] for task or metadata
    /// extensions and a typed validation error for other invalid fields.
    pub fn from_rmcp(
        service: impl Into<String>,
        request: CallToolRequestParams,
    ) -> Result<Self, ProfileError> {
        if request.meta.is_some() || request.task.is_some() {
            return Err(ProfileError::UnsupportedMcpExtension);
        }
        Self::new(
            service,
            request.name.into_owned(),
            request.arguments.unwrap_or_default(),
        )
    }

    /// Parses the unique canonical JSON representation.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed, oversized, invalid, or
    /// non-canonical input.
    pub fn from_canonical_bytes(input: &[u8]) -> Result<Self, ProfileError> {
        if input.is_empty() || input.len() > MAX_CANONICAL_CALL_BYTES {
            return Err(ProfileError::InvalidLength);
        }
        let call: Self = serde_json::from_slice(input).map_err(|_| ProfileError::MalformedJson)?;
        call.validate()?;
        if call.canonical_bytes()? != input {
            return Err(ProfileError::NonCanonical);
        }
        Ok(call)
    }

    /// Serializes unique RFC 8785 canonical JSON.
    ///
    /// # Errors
    ///
    /// Returns a typed error for serialization or byte-limit failure.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProfileError> {
        let bytes =
            serde_json_canonicalizer::to_vec(self).map_err(|_| ProfileError::Canonicalization)?;
        if bytes.is_empty() || bytes.len() > MAX_CANONICAL_CALL_BYTES {
            return Err(ProfileError::InvalidLength);
        }
        Ok(bytes)
    }

    /// Derives the exact Auths permission.
    ///
    /// # Errors
    ///
    /// Returns a typed error only if validated identifiers cannot be
    /// represented by the proof model.
    pub fn permission(&self) -> Result<Permission, ProfileError> {
        Ok(Permission::new(
            CapabilityId::parse(CAPABILITY).map_err(|_| ProfileError::InvalidPermission)?,
            ResourceId::parse(&format!("mcp://{}/tools/{}", self.service, self.name))
                .map_err(|_| ProfileError::InvalidPermission)?,
        ))
    }

    /// Derives the exact verifier audience.
    ///
    /// # Errors
    ///
    /// Returns a typed error only if the validated service cannot be
    /// represented by the proof model.
    pub fn audience(&self) -> Result<Audience, ProfileError> {
        Audience::parse(&format!("mcp://{}", self.service))
            .map_err(|_| ProfileError::InvalidPermission)
    }

    /// Returns the exact profile reference.
    ///
    /// # Errors
    ///
    /// Returns a typed error only if compiled profile constants are invalid.
    pub fn profile_ref(&self) -> Result<ProfileRef, ProfileError> {
        ProfileRef::new(
            ProfileId::parse(PROFILE_ID).map_err(|_| ProfileError::UnsupportedProfile)?,
            PROFILE_VERSION,
        )
        .map_err(|_| ProfileError::UnsupportedProfile)
    }

    /// Returns the tool name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the MCP service.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Returns exact JSON arguments.
    #[must_use]
    pub const fn arguments(&self) -> &Map<String, Value> {
        &self.arguments
    }

    /// Binds the call to an exact Iroh sender or recipient endpoint.
    ///
    /// # Errors
    ///
    /// Returns a typed profile error for a malformed endpoint identifier.
    pub fn with_channel_binding(
        mut self,
        binding: McpChannelBinding,
    ) -> Result<Self, ProfileError> {
        binding.validate()?;
        self.channel_binding = Some(binding);
        Ok(self)
    }

    /// Returns the signed endpoint commitment, when present.
    #[must_use]
    pub const fn channel_binding(&self) -> Option<&McpChannelBinding> {
        self.channel_binding.as_ref()
    }

    fn validate(&self) -> Result<(), ProfileError> {
        if self.profile != PROFILE_ID || self.profile_version != PROFILE_VERSION {
            return Err(ProfileError::UnsupportedProfile);
        }
        if self.service.is_empty()
            || self.service.len() > MAX_SERVICE_ID_BYTES
            || !self.service.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'-' | b'_')
            })
        {
            return Err(ProfileError::InvalidService);
        }
        if self.name.is_empty()
            || self.name.len() > MAX_TOOL_NAME_BYTES
            || !self
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(ProfileError::InvalidToolName);
        }
        if let Some(binding) = &self.channel_binding {
            binding.validate()?;
        }
        Ok(())
    }
}

/// MCP profile implementation.
#[derive(Clone, Copy, Debug, Default)]
pub struct McpProfile;

impl ActionProfile for McpProfile {
    type Command = McpCommand;

    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
        if untrusted.is_empty() || untrusted.len() > MAX_CANONICAL_CALL_BYTES {
            return Err(ProfileContractError::LimitExceeded);
        }
        let call: McpToolCall =
            serde_json::from_slice(untrusted).map_err(|_| ProfileContractError::Malformed)?;
        call.validate().map_err(ProfileContractError::from)?;
        let bytes = call.canonical_bytes().map_err(ProfileContractError::from)?;
        CanonicalAction::new(
            call.profile_ref().map_err(ProfileContractError::from)?,
            MediaType::parse(MEDIA_TYPE).map_err(|_| ProfileContractError::UnsupportedProfile)?,
            bytes,
            call.permission().map_err(ProfileContractError::from)?,
            None,
        )
        .map_err(|_| ProfileContractError::LimitExceeded)
    }

    fn review_display(
        &self,
        action: &CanonicalAction,
    ) -> Result<ReviewDisplay, ProfileContractError> {
        let call = validate_canonical_action(action)?;
        let digest = Sha256::digest(action.body());
        Ok(ReviewDisplay::new(
            "Auths V1 · MCP approval",
            vec![
                ("Service".into(), call.service().into()),
                ("Tool".into(), call.name().into()),
                (
                    "Arguments".into(),
                    Value::Object(call.arguments().clone()).to_string(),
                ),
                (
                    "Resource".into(),
                    action.permission().resource().to_string(),
                ),
                (
                    "Channel binding".into(),
                    call.channel_binding().map_or_else(
                        || "none".into(),
                        |binding| {
                            format!("{}:{}", binding.kind().as_str(), binding.endpoint_id_hex())
                        },
                    ),
                ),
            ],
            hex::encode(digest),
        ))
    }

    fn decode_verified(
        &self,
        action: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError> {
        let call = validate_canonical_action(action.canonical_action())?;
        Ok(McpCommand { call })
    }
}

/// Independently assembles the closed MCP schema around canonical argument
/// JSON and derives the same Auths action.
///
/// This reference path does not serialize `McpToolCall` as a Rust struct. It
/// exists for differential conformance of field order, omission, and profile
/// meaning.
///
/// # Errors
///
/// Returns a closed profile failure for malformed or unsupported input.
pub fn reference_canonicalize(untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError> {
    if untrusted.is_empty() || untrusted.len() > MAX_CANONICAL_CALL_BYTES {
        return Err(ProfileContractError::LimitExceeded);
    }
    let call: McpToolCall =
        serde_json::from_slice(untrusted).map_err(|_| ProfileContractError::Malformed)?;
    call.validate().map_err(ProfileContractError::from)?;
    let arguments = serde_json_canonicalizer::to_vec(&Value::Object(call.arguments.clone()))
        .map_err(|_| ProfileContractError::Malformed)?;
    let mut bytes = Vec::with_capacity(arguments.len() + 256);
    bytes.extend_from_slice(br#"{"arguments":"#);
    bytes.extend_from_slice(&arguments);
    if let Some(binding) = &call.channel_binding {
        bytes.extend_from_slice(br#","channel_binding":{"endpoint_id_hex":"#);
        bytes.extend_from_slice(
            &serde_json::to_vec(&binding.endpoint_id_hex)
                .map_err(|_| ProfileContractError::Malformed)?,
        );
        bytes.extend_from_slice(br#","kind":"#);
        bytes.extend_from_slice(
            &serde_json::to_vec(binding.kind.as_str())
                .map_err(|_| ProfileContractError::Malformed)?,
        );
        bytes.push(b'}');
    }
    bytes.extend_from_slice(br#","name":"#);
    bytes.extend_from_slice(
        &serde_json::to_vec(&call.name).map_err(|_| ProfileContractError::Malformed)?,
    );
    bytes.extend_from_slice(br#","profile":"auths.mcp","profile_version":1,"service":"#);
    bytes.extend_from_slice(
        &serde_json::to_vec(&call.service).map_err(|_| ProfileContractError::Malformed)?,
    );
    bytes.push(b'}');
    if bytes.len() > MAX_CANONICAL_CALL_BYTES {
        return Err(ProfileContractError::LimitExceeded);
    }
    CanonicalAction::new(
        call.profile_ref().map_err(ProfileContractError::from)?,
        MediaType::parse(MEDIA_TYPE).map_err(|_| ProfileContractError::UnsupportedProfile)?,
        bytes,
        call.permission().map_err(ProfileContractError::from)?,
        None,
    )
    .map_err(|_| ProfileContractError::LimitExceeded)
}

fn validate_canonical_action(
    action: &CanonicalAction,
) -> Result<McpToolCall, ProfileContractError> {
    let expected_profile = ProfileRef::new(
        ProfileId::parse(PROFILE_ID).map_err(|_| ProfileContractError::UnsupportedProfile)?,
        PROFILE_VERSION,
    )
    .map_err(|_| ProfileContractError::UnsupportedProfile)?;
    if action.profile() != &expected_profile || action.media_type().as_str() != MEDIA_TYPE {
        return Err(ProfileContractError::UnsupportedProfile);
    }
    let call =
        McpToolCall::from_canonical_bytes(action.body()).map_err(ProfileContractError::from)?;
    if call.permission().map_err(ProfileContractError::from)? != *action.permission()
        || action.requested_budget().is_some()
    {
        return Err(ProfileContractError::MeaningMismatch);
    }
    Ok(call)
}

/// Endpoint role committed by an MCP approval.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum McpChannelBindingKind {
    /// The authenticated transport sender must match the endpoint.
    Sender,
    /// The local transport recipient must match the endpoint.
    Recipient,
}

impl McpChannelBindingKind {
    /// Returns the exact canonical profile token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sender => "sender",
            Self::Recipient => "recipient",
        }
    }
}

/// Exact Iroh endpoint commitment included in canonical MCP bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpChannelBinding {
    kind: McpChannelBindingKind,
    endpoint_id_hex: String,
}

impl McpChannelBinding {
    /// Constructs a canonical lower-case endpoint commitment.
    #[must_use]
    pub fn new(kind: McpChannelBindingKind, endpoint_id: [u8; 32]) -> Self {
        Self {
            kind,
            endpoint_id_hex: hex::encode(endpoint_id),
        }
    }

    /// Returns the committed endpoint role.
    #[must_use]
    pub const fn kind(&self) -> McpChannelBindingKind {
        self.kind
    }

    /// Returns the lower-case 32-byte endpoint identifier.
    #[must_use]
    pub fn endpoint_id_hex(&self) -> &str {
        &self.endpoint_id_hex
    }

    /// Decodes the committed endpoint identifier.
    ///
    /// # Errors
    ///
    /// Returns a typed profile error if stored bytes violate the closed
    /// canonical form.
    pub fn endpoint_id(&self) -> Result<[u8; 32], ProfileError> {
        self.validate()?;
        let decoded =
            hex::decode(&self.endpoint_id_hex).map_err(|_| ProfileError::InvalidChannelBinding)?;
        decoded
            .try_into()
            .map_err(|_| ProfileError::InvalidChannelBinding)
    }

    fn validate(&self) -> Result<(), ProfileError> {
        if self.endpoint_id_hex.len() != 64
            || self
                .endpoint_id_hex
                .bytes()
                .any(|byte| !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        {
            return Err(ProfileError::InvalidChannelBinding);
        }
        Ok(())
    }
}

/// Executor-safe MCP command decoded only from a sealed verified action.
#[derive(Clone, Debug, PartialEq)]
pub struct McpCommand {
    call: McpToolCall,
}

impl McpCommand {
    /// Returns the verified call.
    #[must_use]
    pub const fn call(&self) -> &McpToolCall {
        &self.call
    }

    /// Returns the verified tool name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.call.name()
    }

    /// Returns verified arguments.
    #[must_use]
    pub const fn arguments(&self) -> &Map<String, Value> {
        self.call.arguments()
    }
}

/// MCP-specific construction and canonicalization failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileError {
    /// Canonical bytes are empty or oversized.
    InvalidLength,
    /// Input is not JSON with the closed schema.
    MalformedJson,
    /// Input is not the unique RFC 8785 representation.
    NonCanonical,
    /// Canonical JSON serialization failed.
    Canonicalization,
    /// Profile identifier or version is unsupported.
    UnsupportedProfile,
    /// MCP metadata/task extensions are outside V1.
    UnsupportedMcpExtension,
    /// Service identifier is invalid.
    InvalidService,
    /// Tool name is invalid.
    InvalidToolName,
    /// Permission mapping failed.
    InvalidPermission,
    /// Signed transport endpoint commitment is malformed.
    InvalidChannelBinding,
}

impl From<ProfileError> for ProfileContractError {
    fn from(error: ProfileError) -> Self {
        match error {
            ProfileError::InvalidLength => Self::LimitExceeded,
            ProfileError::MalformedJson | ProfileError::Canonicalization => Self::Malformed,
            ProfileError::NonCanonical => Self::NonCanonical,
            ProfileError::UnsupportedProfile | ProfileError::UnsupportedMcpExtension => {
                Self::UnsupportedProfile
            }
            ProfileError::InvalidService
            | ProfileError::InvalidToolName
            | ProfileError::InvalidPermission
            | ProfileError::InvalidChannelBinding => Self::MeaningMismatch,
        }
    }
}

impl fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLength => "invalid canonical MCP call length",
            Self::MalformedJson => "malformed MCP call JSON",
            Self::NonCanonical => "MCP call is not RFC 8785 canonical JSON",
            Self::Canonicalization => "failed to canonicalize MCP call",
            Self::UnsupportedProfile => "unsupported MCP action profile",
            Self::UnsupportedMcpExtension => "MCP metadata and tasks are not supported in V1",
            Self::InvalidService => "invalid MCP service identifier",
            Self::InvalidToolName => "invalid MCP tool name",
            Self::InvalidPermission => "invalid MCP Auths permission mapping",
            Self::InvalidChannelBinding => "invalid MCP channel-binding commitment",
        })
    }
}

impl std::error::Error for ProfileError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rmcp_call_maps_to_exact_permission_and_canonical_body() {
        let request = CallToolRequestParams::new("read_report").with_arguments(Map::from_iter([(
            "name".into(),
            Value::String("q3".into()),
        )]));
        let call = McpToolCall::from_rmcp("reports", request).unwrap();
        assert_eq!(
            call.permission().unwrap().resource().as_str(),
            "mcp://reports/tools/read_report"
        );
        let encoded = call.canonical_bytes().unwrap();
        assert_eq!(McpToolCall::from_canonical_bytes(&encoded).unwrap(), call);
    }

    #[test]
    fn noncanonical_json_is_rejected() {
        let input = br#"{ "profile":"auths.mcp","profile_version":1,"service":"reports","name":"read_report","arguments":{} }"#;
        assert_eq!(
            McpToolCall::from_canonical_bytes(input),
            Err(ProfileError::NonCanonical)
        );
    }

    #[test]
    fn channel_endpoint_is_part_of_canonical_review_bytes() {
        let plain = McpToolCall::new("reports", "read_report", Map::new()).unwrap();
        let bound = plain
            .clone()
            .with_channel_binding(McpChannelBinding::new(
                McpChannelBindingKind::Recipient,
                [7; 32],
            ))
            .unwrap();
        assert_ne!(
            plain.canonical_bytes().unwrap(),
            bound.canonical_bytes().unwrap()
        );
        assert_eq!(
            bound.channel_binding().unwrap().endpoint_id().unwrap(),
            [7; 32]
        );
        let untrusted = serde_json::to_vec(&bound).unwrap();
        assert_eq!(
            McpProfile.canonicalize(&untrusted).unwrap(),
            reference_canonicalize(&untrusted).unwrap()
        );
    }
}
