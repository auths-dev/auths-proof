//! Canonical local-agent handshake and profile-operation request framing.

// Every public codec below returns the same closed framing error. Repeating an
// identical `# Errors` paragraph on each map encoder/decoder would obscure the
// wire layout this module is meant to make reviewable.
#![allow(clippy::missing_errors_doc)]

use base64ct::{Base64UrlUnpadded, Encoding as _};
use minicbor::{Decoder, Encoder, data::Type};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeSet, fmt};
use thiserror::Error;

/// Exact media type for the local authenticated IPC protocol.
pub const LOCAL_AGENT_CONTENT_TYPE: &str = "application/auths+cbor;version=1";
/// Absolute local-agent request frame ceiling.
pub const MAX_LOCAL_REQUEST_BYTES: usize = 33_554_432;
/// Absolute local-agent response frame ceiling.
pub const MAX_LOCAL_RESPONSE_BYTES: usize = 16_777_216;

const QUALIFICATION_CLIENT_CANCELLATION_DOMAIN: &[u8] =
    b"AUTHS-QUALIFICATION-CLIENT-CANCELLATION\0\x01";
const QUALIFICATION_CLIENT_RESULT_HEADER_BYTES: usize = 22;

const LOCAL_AGENT_VERSION: u8 = 1;

/// CSPRNG client request identifier retained for one complete method call.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ClientRequestId([u8; 16]);

impl ClientRequestId {
    /// Generates a request ID using the operating-system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`LocalAgentProtocolError::Randomness`] if the random source fails.
    pub fn generate() -> Result<Self, LocalAgentProtocolError> {
        let mut bytes = [0_u8; 16];
        fill_request_id(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Constructs an ID from exact wire bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the exact request ID bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Returns the canonical unpadded base64url qualification token.
    #[must_use]
    pub fn to_base64url(self) -> String {
        Base64UrlUnpadded::encode_string(&self.0)
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn fill_request_id(bytes: &mut [u8; 16]) -> Result<(), LocalAgentProtocolError> {
    getrandom::fill(bytes).map_err(|_| LocalAgentProtocolError::Randomness)
}

#[cfg(target_arch = "wasm32")]
fn fill_request_id(_bytes: &mut [u8; 16]) -> Result<(), LocalAgentProtocolError> {
    // Local-agent sessions are a host IPC facility. Browser bindings create
    // request IDs with Web Crypto before encoding and never call this path.
    Err(LocalAgentProtocolError::Randomness)
}

impl fmt::Debug for ClientRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ClientRequestId")
            .field(&Base64UrlUnpadded::encode_string(&self.0))
            .finish()
    }
}

/// Server-generated durable operation identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OperationId(String);

impl OperationId {
    /// Parses `op_` plus unpadded base64url for exactly 16 nonzero bytes.
    ///
    /// # Errors
    ///
    /// Returns [`LocalAgentProtocolError::InvalidIdentifier`] for malformed input.
    pub fn parse(value: impl Into<String>) -> Result<Self, LocalAgentProtocolError> {
        let value = value.into();
        let encoded = value
            .strip_prefix("op_")
            .ok_or(LocalAgentProtocolError::InvalidIdentifier)?;
        let mut buffer = [0_u8; 16];
        let decoded = Base64UrlUnpadded::decode(encoded, &mut buffer)
            .map_err(|_| LocalAgentProtocolError::InvalidIdentifier)?;
        if decoded.len() != 16
            || decoded == [0; 16]
            || Base64UrlUnpadded::encode_string(decoded) != encoded
        {
            return Err(LocalAgentProtocolError::InvalidIdentifier);
        }
        Ok(Self(value))
    }

    /// Returns the canonical operation identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Session capability mode negotiated from the common registry digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionMode {
    /// Compatible session may prepare and execute new operations.
    Full,
    /// Drifted session may only inspect and recover existing operations.
    RecoveryOnly,
}

impl SessionMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::RecoveryOnly => "recovery-only",
        }
    }

    fn parse(value: &str) -> Result<Self, LocalAgentProtocolError> {
        match value {
            "full" => Ok(Self::Full),
            "recovery-only" => Ok(Self::RecoveryOnly),
            _ => Err(LocalAgentProtocolError::InvalidShape),
        }
    }
}

/// Local-agent session handshake request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRequest {
    request_id: ClientRequestId,
    sdk_family: String,
    sdk_version: String,
    common_registry_digest: [u8; 32],
    requested_mode: SessionMode,
}

impl SessionRequest {
    /// Constructs a fully validated handshake request.
    ///
    /// # Errors
    ///
    /// Rejects unknown SDK families and invalid diagnostic version strings.
    pub fn new(
        request_id: ClientRequestId,
        sdk_family: impl Into<String>,
        sdk_version: impl Into<String>,
        common_registry_digest: [u8; 32],
        requested_mode: SessionMode,
    ) -> Result<Self, LocalAgentProtocolError> {
        let sdk_family = sdk_family.into();
        let sdk_version = sdk_version.into();
        if !matches!(sdk_family.as_str(), "python" | "typescript")
            || !sdk_version_text(&sdk_version)
        {
            return Err(LocalAgentProtocolError::InvalidShape);
        }
        Ok(Self {
            request_id,
            sdk_family,
            sdk_version,
            common_registry_digest,
            requested_mode,
        })
    }

    /// Returns the request ID.
    #[must_use]
    pub const fn request_id(&self) -> ClientRequestId {
        self.request_id
    }
    /// Returns `python` or `typescript`.
    #[must_use]
    pub fn sdk_family(&self) -> &str {
        &self.sdk_family
    }
    /// Returns the diagnostic SDK version.
    #[must_use]
    pub fn sdk_version(&self) -> &str {
        &self.sdk_version
    }
    /// Returns the installed common error registry digest.
    #[must_use]
    pub const fn common_registry_digest(&self) -> &[u8; 32] {
        &self.common_registry_digest
    }
    /// Returns the requested session mode.
    #[must_use]
    pub const fn requested_mode(&self) -> SessionMode {
        self.requested_mode
    }
}

/// Profile identity used for duplicate detection and capability lookup.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SessionProfileKey {
    id: String,
    version: u16,
}

impl SessionProfileKey {
    /// Constructs a canonical `auths.<domain>.<effect>` profile key.
    ///
    /// # Errors
    ///
    /// Rejects malformed identifiers and version zero.
    pub fn new(id: impl Into<String>, version: u16) -> Result<Self, LocalAgentProtocolError> {
        let id = id.into();
        validate_profile_id(&id)?;
        if version == 0 {
            return Err(LocalAgentProtocolError::InvalidIdentifier);
        }
        Ok(Self { id, version })
    }

    /// Returns the profile ID without the version suffix.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Returns the immutable profile version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }
}

/// Connected domain contract included in a profile advertisement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileConnectionAdvertisement {
    provider_kind: String,
    contract: String,
    descriptor_schema: String,
}

impl ProfileConnectionAdvertisement {
    /// Constructs a validated connection projection.
    ///
    /// # Errors
    ///
    /// Rejects malformed provider or semantic identifiers.
    pub fn new(
        provider_kind: impl Into<String>,
        contract: impl Into<String>,
        descriptor_schema: impl Into<String>,
    ) -> Result<Self, LocalAgentProtocolError> {
        let value = Self {
            provider_kind: provider_kind.into(),
            contract: contract.into(),
            descriptor_schema: descriptor_schema.into(),
        };
        if !lower_token(&value.provider_kind)
            || !semantic_id(&value.contract)
            || !semantic_id(&value.descriptor_schema)
        {
            return Err(LocalAgentProtocolError::InvalidIdentifier);
        }
        Ok(value)
    }

    /// Returns the provider kind.
    #[must_use]
    pub fn provider_kind(&self) -> &str {
        &self.provider_kind
    }
    /// Returns the immutable connection contract.
    #[must_use]
    pub fn contract(&self) -> &str {
        &self.contract
    }
    /// Returns the immutable descriptor schema.
    #[must_use]
    pub fn descriptor_schema(&self) -> &str {
        &self.descriptor_schema
    }
}

/// One negotiated generated-profile capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileAdvertisement {
    profile: SessionProfileKey,
    runtime_contract_digest: [u8; 32],
    operation_protocol: String,
    error_projection_digest: [u8; 32],
    connection: Option<ProfileConnectionAdvertisement>,
    qualification: Option<ProfileQualificationAdvertisement>,
}

/// Trusted build-time qualification facts for one production profile target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileQualificationAdvertisement {
    qualification_id: String,
    target: String,
    semantic_closure_sha256: [u8; 32],
}

impl ProfileQualificationAdvertisement {
    /// Constructs exact, safe qualification metadata.
    ///
    /// # Errors
    ///
    /// Rejects malformed qualification IDs and targets outside the closed
    /// production target roster.
    pub fn new(
        qualification_id: impl Into<String>,
        target: impl Into<String>,
        semantic_closure_sha256: [u8; 32],
    ) -> Result<Self, LocalAgentProtocolError> {
        let qualification_id = qualification_id.into();
        let target = target.into();
        if !qualification_id_token(&qualification_id)
            || !matches!(
                target.as_str(),
                "linux-x86_64" | "linux-aarch64" | "macos-x86_64" | "macos-aarch64"
            )
        {
            return Err(LocalAgentProtocolError::InvalidIdentifier);
        }
        Ok(Self {
            qualification_id,
            target,
            semantic_closure_sha256,
        })
    }

    /// Returns the signed qualification identifier.
    #[must_use]
    pub fn qualification_id(&self) -> &str {
        &self.qualification_id
    }

    /// Returns the exact compilation target qualified by the record.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Returns the semantic-closure digest bound by the signed record.
    #[must_use]
    pub const fn semantic_closure_sha256(&self) -> &[u8; 32] {
        &self.semantic_closure_sha256
    }
}

impl ProfileAdvertisement {
    /// Constructs an exact profile advertisement.
    ///
    /// # Errors
    ///
    /// Rejects any operation protocol other than `auths.profile-operation/1`.
    pub fn new(
        profile: SessionProfileKey,
        runtime_contract_digest: [u8; 32],
        operation_protocol: impl Into<String>,
        error_projection_digest: [u8; 32],
        connection: Option<ProfileConnectionAdvertisement>,
        qualification: Option<ProfileQualificationAdvertisement>,
    ) -> Result<Self, LocalAgentProtocolError> {
        let operation_protocol = operation_protocol.into();
        if operation_protocol != "auths.profile-operation/1" {
            return Err(LocalAgentProtocolError::UnsupportedVersion);
        }
        Ok(Self {
            profile,
            runtime_contract_digest,
            operation_protocol,
            error_projection_digest,
            connection,
            qualification,
        })
    }

    /// Returns the profile key.
    #[must_use]
    pub const fn profile(&self) -> &SessionProfileKey {
        &self.profile
    }
    /// Returns the runtime-contract digest.
    #[must_use]
    pub const fn runtime_contract_digest(&self) -> &[u8; 32] {
        &self.runtime_contract_digest
    }
    /// Returns the profile operation protocol.
    #[must_use]
    pub fn operation_protocol(&self) -> &str {
        &self.operation_protocol
    }
    /// Returns the profile error-projection digest.
    #[must_use]
    pub const fn error_projection_digest(&self) -> &[u8; 32] {
        &self.error_projection_digest
    }
    /// Returns the connected-domain projection, if any.
    #[must_use]
    pub const fn connection(&self) -> Option<&ProfileConnectionAdvertisement> {
        self.connection.as_ref()
    }

    /// Returns trusted qualification metadata for production profiles.
    #[must_use]
    pub const fn qualification(&self) -> Option<&ProfileQualificationAdvertisement> {
        self.qualification.as_ref()
    }
}

/// Successful local-agent session negotiation response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionResponse {
    request_id: ClientRequestId,
    session_id: String,
    principal: String,
    common_registry_digest: [u8; 32],
    profiles: Vec<ProfileAdvertisement>,
    maximum_concurrent_requests: u8,
    mode: SessionMode,
}

impl SessionResponse {
    /// Constructs and checks one negotiated response.
    #[allow(clippy::too_many_arguments)]
    ///
    /// # Errors
    ///
    /// Rejects invalid IDs, principals, profile order/duplicates, and limits.
    pub fn new(
        request_id: ClientRequestId,
        session_id: impl Into<String>,
        principal: impl Into<String>,
        common_registry_digest: [u8; 32],
        profiles: Vec<ProfileAdvertisement>,
        maximum_concurrent_requests: u8,
        mode: SessionMode,
    ) -> Result<Self, LocalAgentProtocolError> {
        let session_id = session_id.into();
        let principal = principal.into();
        if !session_id_token(&session_id)
            || !bounded_ascii_graphic(&principal, 512)
            || profiles.len() > 256
            || maximum_concurrent_requests == 0
            || maximum_concurrent_requests > 32
        {
            return Err(LocalAgentProtocolError::InvalidShape);
        }
        let mut seen = BTreeSet::new();
        let mut previous: Option<&SessionProfileKey> = None;
        for profile in &profiles {
            if previous.is_some_and(|value| value >= profile.profile())
                || !seen.insert(profile.profile())
            {
                return Err(LocalAgentProtocolError::DuplicateProfile);
            }
            previous = Some(profile.profile());
        }
        Ok(Self {
            request_id,
            session_id,
            principal,
            common_registry_digest,
            profiles,
            maximum_concurrent_requests,
            mode,
        })
    }

    /// Returns the echoed request ID.
    #[must_use]
    pub const fn request_id(&self) -> ClientRequestId {
        self.request_id
    }
    /// Returns the diagnostic session routing ID.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    /// Returns the observed Auths principal.
    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }
    /// Returns the server common registry digest.
    #[must_use]
    pub const fn common_registry_digest(&self) -> &[u8; 32] {
        &self.common_registry_digest
    }
    /// Returns sorted profile capabilities.
    #[must_use]
    pub fn profiles(&self) -> &[ProfileAdvertisement] {
        &self.profiles
    }
    /// Returns the per-session in-flight limit.
    #[must_use]
    pub const fn maximum_concurrent_requests(&self) -> u8 {
        self.maximum_concurrent_requests
    }
    /// Returns the negotiated session mode.
    #[must_use]
    pub const fn mode(&self) -> SessionMode {
        self.mode
    }
}

/// Bounded operation preparation request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareOperationRequest {
    request_id: ClientRequestId,
    idempotency_key: Option<String>,
    runtime_contract_digest: [u8; 32],
    profile_input: Vec<u8>,
    connection_alias: Option<String>,
    preparation_evidence_handle: Option<Vec<u8>>,
}

impl PrepareOperationRequest {
    /// Constructs a profile preparation request with caller/profile bounds.
    ///
    /// # Errors
    ///
    /// Rejects invalid idempotency, alias, input, or declared request bounds.
    pub fn new(
        request_id: ClientRequestId,
        idempotency_key: Option<String>,
        runtime_contract_digest: [u8; 32],
        profile_input: Vec<u8>,
        connection_alias: Option<String>,
        profile_request_limit: usize,
    ) -> Result<Self, LocalAgentProtocolError> {
        if profile_request_limit == 0
            || profile_request_limit > 25_165_824
            || profile_input.is_empty()
            || profile_input.len() > profile_request_limit
            || idempotency_key
                .as_deref()
                .is_some_and(|value| !registered_token(value))
            || connection_alias
                .as_deref()
                .is_some_and(|value| !lower_token(value))
        {
            return Err(LocalAgentProtocolError::LimitExceeded);
        }
        Ok(Self {
            request_id,
            idempotency_key,
            runtime_contract_digest,
            profile_input,
            connection_alias,
            preparation_evidence_handle: None,
        })
    }

    /// Returns the request ID.
    #[must_use]
    pub const fn request_id(&self) -> ClientRequestId {
        self.request_id
    }
    /// Returns the optional caller idempotency key.
    #[must_use]
    pub fn idempotency_key(&self) -> Option<&str> {
        self.idempotency_key.as_deref()
    }
    /// Returns the negotiated profile runtime digest.
    #[must_use]
    pub const fn runtime_contract_digest(&self) -> &[u8; 32] {
        &self.runtime_contract_digest
    }
    /// Returns canonical restricted profile input bytes.
    #[must_use]
    pub fn profile_input(&self) -> &[u8] {
        &self.profile_input
    }
    /// Returns the explicit alias, or `None` to request the workload default.
    #[must_use]
    pub fn connection_alias(&self) -> Option<&str> {
        self.connection_alias.as_deref()
    }

    /// Attaches the bounded opaque preparation-evidence lease handle returned
    /// by the profile's generated support route.
    pub fn with_preparation_evidence_handle(
        mut self,
        handle: Option<Vec<u8>>,
    ) -> Result<Self, LocalAgentProtocolError> {
        if handle.as_deref().is_some_and(|value| value.len() != 32) {
            return Err(LocalAgentProtocolError::InvalidShape);
        }
        self.preparation_evidence_handle = handle;
        Ok(self)
    }

    /// Returns the opaque connection-owned evidence lease handle.
    #[must_use]
    pub fn preparation_evidence_handle(&self) -> Option<&[u8]> {
        self.preparation_evidence_handle.as_deref()
    }
}

/// Request accepted only by a manifest-declared preparation-evidence route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparationEvidenceRequest(PrepareOperationRequest);

impl PreparationEvidenceRequest {
    /// Returns the exact preparation tuple whose evidence lease is requested.
    #[must_use]
    pub const fn preparation(&self) -> &PrepareOperationRequest {
        &self.0
    }
}

/// Durable opaque preparation-evidence lease returned by the local agent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparationEvidenceLease {
    request_id: ClientRequestId,
    handle: [u8; 32],
    commitment: [u8; 32],
    expires_at_unix_seconds: u64,
}

impl PreparationEvidenceLease {
    /// Constructs one validated lease response.
    pub fn new(
        request_id: ClientRequestId,
        handle: [u8; 32],
        commitment: [u8; 32],
        expires_at_unix_seconds: u64,
    ) -> Result<Self, LocalAgentProtocolError> {
        if expires_at_unix_seconds == 0 {
            return Err(LocalAgentProtocolError::InvalidShape);
        }
        Ok(Self {
            request_id,
            handle,
            commitment,
            expires_at_unix_seconds,
        })
    }

    #[must_use]
    pub const fn request_id(&self) -> ClientRequestId {
        self.request_id
    }
    #[must_use]
    pub const fn handle(&self) -> &[u8; 32] {
        &self.handle
    }
    #[must_use]
    pub const fn commitment(&self) -> &[u8; 32] {
        &self.commitment
    }
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
}

/// At-most-once execute request for a prepared operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecuteOperationRequest {
    request_id: ClientRequestId,
    operation_id: OperationId,
    preparation_commitment: [u8; 32],
}

impl ExecuteOperationRequest {
    /// Constructs a fixed execute request.
    #[must_use]
    pub const fn new(
        request_id: ClientRequestId,
        operation_id: OperationId,
        preparation_commitment: [u8; 32],
    ) -> Self {
        Self {
            request_id,
            operation_id,
            preparation_commitment,
        }
    }
    /// Returns the request ID.
    #[must_use]
    pub const fn request_id(&self) -> ClientRequestId {
        self.request_id
    }
    /// Returns the durable operation ID.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }
    /// Returns the preparation commitment.
    #[must_use]
    pub const fn preparation_commitment(&self) -> &[u8; 32] {
        &self.preparation_commitment
    }
}

/// Recovery request containing only a sealed handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverOperationRequest {
    request_id: ClientRequestId,
    recovery_handle: Vec<u8>,
}

/// Terminal result provenance projected by generated profile clients.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalOperationCompletion {
    /// First projection from ordinary execution.
    Fresh,
    /// Exact replay of a retained terminal operation.
    Replayed,
    /// Concrete reconciliation established the result.
    Reconciled,
}

impl LocalOperationCompletion {
    fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Replayed => "replayed",
            Self::Reconciled => "reconciled",
        }
    }

    fn parse(value: &str) -> Result<Self, LocalAgentProtocolError> {
        match value {
            "fresh" => Ok(Self::Fresh),
            "replayed" => Ok(Self::Replayed),
            "reconciled" => Ok(Self::Reconciled),
            _ => Err(LocalAgentProtocolError::InvalidShape),
        }
    }
}

/// Closed canonical Auths operation outcome returned with HTTP 200.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalOperationOutcome {
    /// Prepared command is durable and provider entry has not occurred.
    Ready {
        /// Original request ID.
        request_id: ClientRequestId,
        /// Durable operation ID.
        operation_id: OperationId,
        /// Commitment over every preparation fact.
        preparation_commitment: [u8; 32],
        /// Portable decision receipt.
        decision_receipt: Vec<u8>,
        /// Sealed recovery handle.
        recovery_handle: Vec<u8>,
        /// Resolved public connection alias.
        connection_alias: Option<String>,
    },
    /// Accepted nonterminal operation.
    InProgress {
        /// Original request ID.
        request_id: ClientRequestId,
        /// Durable operation ID.
        operation_id: OperationId,
        /// `preparing` or `executing`.
        state: String,
        /// `not-applied` or `possible`.
        effect: String,
        /// Ordered retained receipt IDs.
        receipt_ids: Vec<String>,
        /// Sealed recovery handle.
        recovery_handle: Vec<u8>,
        /// Resolved public connection alias.
        connection_alias: Option<String>,
    },
    /// Concrete policy denial before provider entry.
    Denied {
        /// Original request ID.
        request_id: ClientRequestId,
        /// Durable operation ID.
        operation_id: OperationId,
        /// Canonical `auths.error/1` envelope.
        issue: Vec<u8>,
        /// Portable decision receipt.
        decision_receipt: Vec<u8>,
        /// Resolved public connection alias.
        connection_alias: Option<String>,
    },
    /// Pre-entry dependency unavailability.
    Unavailable {
        /// Original request ID.
        request_id: ClientRequestId,
        /// Present only after durable allocation.
        operation_id: Option<OperationId>,
        /// Canonical `auths.error/1` envelope.
        issue: Vec<u8>,
        /// Zero or one portable decision receipt.
        receipts: Vec<Vec<u8>>,
        /// Requested/resolved public connection alias.
        connection_alias: Option<String>,
    },
    /// Same idempotency identity was already bound to different commitments.
    Conflict {
        /// New request ID whose commitments conflicted.
        request_id: ClientRequestId,
        /// Original durable operation ID.
        operation_id: OperationId,
        /// Canonical `auths.error/1` envelope.
        issue: Vec<u8>,
        /// Original operation recovery handle.
        recovery_handle: Vec<u8>,
        /// Original ordered portable receipts.
        receipts: Vec<Vec<u8>>,
        /// Original resolved connection alias.
        connection_alias: Option<String>,
    },
    /// Complete effect is proven.
    Completed {
        /// Original request ID.
        request_id: ClientRequestId,
        /// Durable operation ID.
        operation_id: OperationId,
        /// Canonical generated profile success bytes.
        value: Vec<u8>,
        /// Ordered linked portable receipts.
        receipts: Vec<Vec<u8>>,
        /// Fresh, replayed, or reconciled.
        completion: LocalOperationCompletion,
        /// Resolved connection alias.
        connection_alias: Option<String>,
    },
    /// Profile-defined subset is proven applied.
    Partial {
        /// Original request ID.
        request_id: ClientRequestId,
        /// Durable operation ID.
        operation_id: OperationId,
        /// Canonical generated profile partial bytes.
        value: Vec<u8>,
        /// Canonical `auths.error/1` envelope.
        issue: Vec<u8>,
        /// Ordered linked portable receipts.
        receipts: Vec<Vec<u8>>,
        /// Fresh, replayed, or reconciled.
        completion: LocalOperationCompletion,
        /// Resolved connection alias.
        connection_alias: Option<String>,
    },
    /// Concrete evidence proves provider non-effect.
    NotApplied {
        /// Original request ID.
        request_id: ClientRequestId,
        /// Durable operation ID.
        operation_id: OperationId,
        /// Canonical `auths.error/1` envelope.
        issue: Vec<u8>,
        /// Ordered linked portable receipts.
        receipts: Vec<Vec<u8>>,
        /// Fresh, replayed, or reconciled.
        completion: LocalOperationCompletion,
        /// Resolved connection alias.
        connection_alias: Option<String>,
    },
    /// Provider effect remains possible and only recovery may advance it.
    RecoveryRequired {
        /// Original request ID.
        request_id: ClientRequestId,
        /// Durable operation ID.
        operation_id: OperationId,
        /// Canonical `auths.error/1` envelope.
        issue: Vec<u8>,
        /// Sealed recovery handle.
        recovery_handle: Vec<u8>,
        /// Ordered linked portable receipts.
        receipts: Vec<Vec<u8>>,
        /// Optional generated profile progress bytes.
        progress: Option<Vec<u8>>,
        /// Resolved connection alias.
        connection_alias: Option<String>,
    },
    /// Receipt verification failed after provider truth became durable.
    ///
    /// This outcome never exposes the quarantined receipt or any success
    /// value. `effect` and `terminal` preserve the already-proven provider
    /// truth independently of receipt validity.
    ReceiptIntegrityFailed {
        /// Original request ID.
        request_id: ClientRequestId,
        /// Durable operation ID.
        operation_id: OperationId,
        /// Canonical `core.terminal-receipt-integrity-failed` envelope.
        issue: Vec<u8>,
        /// Exact durable lifecycle state when integrity failed.
        state: String,
        /// `not-applied`, `possible`, or `applied`.
        effect: String,
        /// Whether the durable lifecycle state is terminal.
        terminal: bool,
        /// Resolved connection alias.
        connection_alias: Option<String>,
    },
}

/// Exact bounded HTTP/1.1 request emitted by the generated local SDK clients.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalAgentHttpRequest {
    method: String,
    path: String,
    session: Option<String>,
    body: Vec<u8>,
}

impl LocalAgentHttpRequest {
    /// Returns the exact uppercase HTTP method.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns the normalized local-agent route.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the optional session routing token.
    #[must_use]
    pub fn session(&self) -> Option<&str> {
        self.session.as_deref()
    }

    /// Returns the exact canonical CBOR request body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Exact bounded HTTP/1.1 response returned by the local agent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalAgentHttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl LocalAgentHttpResponse {
    /// Returns the HTTP status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns the exact canonical CBOR response body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl LocalOperationOutcome {
    /// Reports whether this canonical response is a final SDK-visible outcome
    /// rather than a state that the generated client must advance or recover.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        !matches!(
            self,
            Self::Ready { .. } | Self::InProgress { .. } | Self::RecoveryRequired { .. }
        )
    }

    /// Returns the request echoed by this outcome.
    #[must_use]
    pub const fn request_id(&self) -> ClientRequestId {
        match self {
            Self::Ready { request_id, .. }
            | Self::InProgress { request_id, .. }
            | Self::Denied { request_id, .. }
            | Self::Unavailable { request_id, .. }
            | Self::Conflict { request_id, .. }
            | Self::Completed { request_id, .. }
            | Self::Partial { request_id, .. }
            | Self::NotApplied { request_id, .. }
            | Self::RecoveryRequired { request_id, .. }
            | Self::ReceiptIntegrityFailed { request_id, .. } => *request_id,
        }
    }

    /// Returns the durable operation ID when one has been allocated.
    #[must_use]
    pub const fn operation_id(&self) -> Option<&OperationId> {
        match self {
            Self::Unavailable { operation_id, .. } => operation_id.as_ref(),
            Self::Ready { operation_id, .. }
            | Self::InProgress { operation_id, .. }
            | Self::Denied { operation_id, .. }
            | Self::Conflict { operation_id, .. }
            | Self::Completed { operation_id, .. }
            | Self::Partial { operation_id, .. }
            | Self::NotApplied { operation_id, .. }
            | Self::RecoveryRequired { operation_id, .. }
            | Self::ReceiptIntegrityFailed { operation_id, .. } => Some(operation_id),
        }
    }

    /// Returns the terminal projection provenance when the response carries
    /// one. Nonterminal and policy outcomes deliberately have no completion.
    #[must_use]
    pub const fn completion(&self) -> Option<LocalOperationCompletion> {
        match self {
            Self::Completed { completion, .. }
            | Self::Partial { completion, .. }
            | Self::NotApplied { completion, .. } => Some(*completion),
            Self::Ready { .. }
            | Self::InProgress { .. }
            | Self::Denied { .. }
            | Self::Unavailable { .. }
            | Self::Conflict { .. }
            | Self::RecoveryRequired { .. }
            | Self::ReceiptIntegrityFailed { .. } => None,
        }
    }

    /// Returns the exact public value or issue projected by a completed SDK
    /// call. Ready and in-progress responses are transport intermediates and
    /// have no final result. This accessor is not evidence by itself; the
    /// qualification reader additionally requires a same-process consumer
    /// acknowledgement after successful delivery.
    #[must_use]
    pub fn projected_result(&self) -> Option<&[u8]> {
        match self {
            Self::Completed { value, .. } | Self::Partial { value, .. } => Some(value),
            Self::Denied { issue, .. }
            | Self::Unavailable { issue, .. }
            | Self::Conflict { issue, .. }
            | Self::NotApplied { issue, .. }
            | Self::RecoveryRequired { issue, .. }
            | Self::ReceiptIntegrityFailed { issue, .. } => Some(issue),
            Self::Ready { .. } | Self::InProgress { .. } => None,
        }
    }
}

/// Commits the exact canonical public request body observed on local IPC.
#[must_use]
pub fn local_request_commitment(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Commits the authenticated principal returned by the session handshake.
#[must_use]
pub fn local_principal_commitment(principal: &str) -> [u8; 32] {
    Sha256::digest(principal.as_bytes()).into()
}

/// Commits the exact profile preparation input carried by a prepare request.
#[must_use]
pub fn local_preparation_input_commitment(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Commits an idempotency key under the runtime's fixed domain separator.
#[must_use]
pub fn local_idempotency_commitment(value: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"AUTHS-IDEMPOTENCY-KEY\x00\x01");
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
    digest.finalize().into()
}

/// Decodes the exact bounded HTTP/1.1 request grammar emitted by the generated
/// TypeScript and Python local SDK clients.
pub fn decode_local_agent_http_request(
    bytes: &[u8],
) -> Result<LocalAgentHttpRequest, LocalAgentProtocolError> {
    let (head, body) = split_local_http(bytes, MAX_LOCAL_REQUEST_BYTES)?;
    let mut lines = head.split("\r\n");
    let request = lines.next().ok_or(LocalAgentProtocolError::InvalidShape)?;
    let mut parts = request.split(' ');
    let method = parts.next().ok_or(LocalAgentProtocolError::InvalidShape)?;
    let path = parts.next().ok_or(LocalAgentProtocolError::InvalidShape)?;
    if parts.next() != Some("HTTP/1.1")
        || parts.next().is_some()
        || !matches!(method, "GET" | "POST" | "DELETE")
        || path.is_empty()
        || path.len() > 2_048
        || !path.starts_with('/')
        || path
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'?' | b'%'))
    {
        return Err(LocalAgentProtocolError::InvalidShape);
    }
    let headers = lines.collect::<Vec<_>>();
    if !matches!(headers.len(), 4 | 5)
        || headers[0] != "Host: localhost"
        || headers[1] != format!("Content-Type: {LOCAL_AGENT_CONTENT_TYPE}")
        || headers[3] != "Connection: close"
    {
        return Err(LocalAgentProtocolError::InvalidShape);
    }
    let length = headers[2]
        .strip_prefix("Content-Length: ")
        .and_then(parse_canonical_decimal)
        .ok_or(LocalAgentProtocolError::InvalidShape)?;
    if length != body.len() {
        return Err(LocalAgentProtocolError::InvalidShape);
    }
    let session = if headers.len() == 5 {
        let value = headers[4]
            .strip_prefix("Auths-Session: ")
            .filter(|value| session_id_token(value))
            .ok_or(LocalAgentProtocolError::InvalidShape)?;
        Some(value.to_owned())
    } else {
        None
    };
    if path == "/v1/session" && session.is_some() {
        return Err(LocalAgentProtocolError::InvalidShape);
    }
    Ok(LocalAgentHttpRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        session,
        body: body.to_vec(),
    })
}

/// Decodes one bounded HTTP/1.1 local-agent response without changing its
/// exact body bytes. Successful responses must carry the canonical Auths media
/// type used by both generated clients.
pub fn decode_local_agent_http_response(
    bytes: &[u8],
) -> Result<LocalAgentHttpResponse, LocalAgentProtocolError> {
    let (head, body) = split_local_http(bytes, MAX_LOCAL_RESPONSE_BYTES)?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or(LocalAgentProtocolError::InvalidShape)?;
    let mut parts = status_line.splitn(3, ' ');
    if parts.next() != Some("HTTP/1.1") {
        return Err(LocalAgentProtocolError::InvalidShape);
    }
    let status = parts
        .next()
        .filter(|value| value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or(LocalAgentProtocolError::InvalidShape)?
        .parse::<u16>()
        .map_err(|_| LocalAgentProtocolError::InvalidShape)?;
    if !(100..=599).contains(&status) || parts.next().is_none() {
        return Err(LocalAgentProtocolError::InvalidShape);
    }
    let mut content_length = None;
    let mut content_type = None;
    let mut names = BTreeSet::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or(LocalAgentProtocolError::InvalidShape)?;
        let name = name.to_ascii_lowercase();
        let value = value.trim();
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
            || value.len() > 1_024
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' ')
            || !names.insert(name.clone())
            || names.len() > 32
        {
            return Err(LocalAgentProtocolError::InvalidShape);
        }
        match name.as_str() {
            "content-length" => content_length = parse_canonical_decimal(value),
            "content-type" => content_type = Some(value),
            _ => {}
        }
    }
    if content_length != Some(body.len())
        || status == 200 && content_type != Some(LOCAL_AGENT_CONTENT_TYPE)
    {
        return Err(LocalAgentProtocolError::InvalidShape);
    }
    Ok(LocalAgentHttpResponse {
        status,
        body: body.to_vec(),
    })
}

/// Returns the complete HTTP message length once the bounded generated
/// local-agent header has arrived. The caller still passes the resulting
/// bytes through the strict request or response decoder before use.
pub fn local_agent_http_message_length(
    bytes: &[u8],
    maximum: usize,
) -> Result<Option<usize>, LocalAgentProtocolError> {
    if maximum == 0 || maximum > MAX_LOCAL_REQUEST_BYTES || bytes.len() > maximum {
        return Err(LocalAgentProtocolError::LimitExceeded);
    }
    let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
        if bytes.len() > 16_384 {
            return Err(LocalAgentProtocolError::LimitExceeded);
        }
        return Ok(None);
    };
    if header_end > 16_384 {
        return Err(LocalAgentProtocolError::LimitExceeded);
    }
    let head = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| LocalAgentProtocolError::InvalidShape)?;
    let mut content_length = None;
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            return Err(LocalAgentProtocolError::InvalidShape);
        };
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(LocalAgentProtocolError::InvalidShape);
            }
            content_length = value
                .trim()
                .parse::<usize>()
                .ok()
                .filter(|length| length.to_string() == value.trim());
        }
    }
    let content_length = content_length.ok_or(LocalAgentProtocolError::InvalidShape)?;
    let total = header_end
        .checked_add(4)
        .and_then(|head| head.checked_add(content_length))
        .filter(|total| *total <= maximum)
        .ok_or(LocalAgentProtocolError::LimitExceeded)?;
    if bytes.len() > total {
        return Err(LocalAgentProtocolError::InvalidShape);
    }
    Ok(Some(total))
}

fn split_local_http(
    bytes: &[u8],
    maximum_body: usize,
) -> Result<(&str, &[u8]), LocalAgentProtocolError> {
    if bytes.is_empty()
        || bytes.len() > maximum_body.saturating_add(16_388)
        || bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .is_none_or(|offset| offset == 0 || offset > 16_384)
    {
        return Err(LocalAgentProtocolError::LimitExceeded);
    }
    let marker = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(LocalAgentProtocolError::InvalidShape)?;
    let head =
        std::str::from_utf8(&bytes[..marker]).map_err(|_| LocalAgentProtocolError::InvalidShape)?;
    if !head.is_ascii() {
        return Err(LocalAgentProtocolError::InvalidShape);
    }
    let body = &bytes[marker + 4..];
    if body.len() > maximum_body {
        return Err(LocalAgentProtocolError::LimitExceeded);
    }
    Ok((head, body))
}

fn parse_canonical_decimal(value: &str) -> Option<usize> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
    {
        return None;
    }
    value.parse().ok()
}

/// One nonterminal operation in the common pending list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalPendingOperation {
    /// Durable operation ID.
    pub operation_id: OperationId,
    /// Exact profile ID.
    pub profile_id: String,
    /// Immutable profile version.
    pub profile_version: u16,
    /// `preparing`, `ready`, `executing`, or `recovery-required`.
    pub state: String,
    /// `not-applied` or `possible`.
    pub effect: String,
    /// Last durable update time.
    pub updated_at_unix_seconds: u64,
    /// Ordered retained receipt IDs.
    pub receipt_ids: Vec<String>,
    /// Sealed recovery handle.
    pub recovery_handle: Vec<u8>,
    /// Resolved connection alias.
    pub connection_alias: Option<String>,
}

/// One ordered portable receipt-list entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalReceiptEntry {
    /// Portable receipt ID.
    pub receipt_id: String,
    /// Exact portable receipt bytes.
    pub bytes: Vec<u8>,
}

impl RecoverOperationRequest {
    /// Constructs a bounded recovery request.
    ///
    /// # Errors
    ///
    /// Rejects empty or greater-than-16KiB capabilities before copying.
    pub fn new(
        request_id: ClientRequestId,
        recovery_handle: Vec<u8>,
    ) -> Result<Self, LocalAgentProtocolError> {
        if !(1..=16_384).contains(&recovery_handle.len()) {
            return Err(LocalAgentProtocolError::LimitExceeded);
        }
        Ok(Self {
            request_id,
            recovery_handle,
        })
    }
    /// Returns the request ID.
    #[must_use]
    pub const fn request_id(&self) -> ClientRequestId {
        self.request_id
    }
    /// Returns the sealed recovery-handle bytes.
    #[must_use]
    pub fn recovery_handle(&self) -> &[u8] {
        &self.recovery_handle
    }
}

/// Static route family derived from one manifest profile identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileRoute {
    collection: String,
}

impl ProfileRoute {
    /// Constructs the exact static collection route.
    ///
    /// # Errors
    ///
    /// Rejects malformed profile identities or version zero.
    pub fn new(profile_id: &str, version: u16) -> Result<Self, LocalAgentProtocolError> {
        validate_profile_id(profile_id)?;
        if version == 0 {
            return Err(LocalAgentProtocolError::InvalidIdentifier);
        }
        let mut parts = profile_id.split('.');
        let _auths = parts.next();
        let domain = parts
            .next()
            .ok_or(LocalAgentProtocolError::InvalidIdentifier)?;
        let effect = parts
            .next()
            .ok_or(LocalAgentProtocolError::InvalidIdentifier)?;
        if parts.next().is_some() {
            return Err(LocalAgentProtocolError::InvalidIdentifier);
        }
        Ok(Self {
            collection: format!("/v1/profiles/{domain}/{effect}/{version}/operations"),
        })
    }

    /// Returns the prepare collection path.
    #[must_use]
    pub fn collection(&self) -> &str {
        &self.collection
    }
    /// Returns the generated companion route used to acquire a protected
    /// preparation-evidence lease. The route is mounted only for profiles
    /// whose checked manifest declares that support contract.
    ///
    /// # Panics
    ///
    /// Panics only if this value's internally generated collection route no
    /// longer ends in `/operations`, which would violate its constructor
    /// invariant.
    #[must_use]
    pub fn preparation_evidence(&self) -> String {
        format!(
            "{}/preparation-evidence",
            self.collection
                .strip_suffix("/operations")
                .expect("profile collection routes always end in /operations")
        )
    }
    /// Returns the fixed execute path for one server-issued operation ID.
    #[must_use]
    pub fn execute(&self, operation: &OperationId) -> String {
        format!("{}/{}/execute", self.collection, operation.as_str())
    }
    /// Returns the fixed recover path for one server-issued operation ID.
    #[must_use]
    pub fn recover(&self, operation: &OperationId) -> String {
        format!("{}/{}/recover", self.collection, operation.as_str())
    }
    /// Returns the fixed status path for one server-issued operation ID.
    #[must_use]
    pub fn status(&self, operation: &OperationId) -> String {
        format!("{}/{}", self.collection, operation.as_str())
    }
    /// Returns the fixed receipts path for one server-issued operation ID.
    #[must_use]
    pub fn receipts(&self, operation: &OperationId) -> String {
        format!("{}/{}/receipts", self.collection, operation.as_str())
    }
}

/// Encodes one canonical session request map.
pub fn encode_session_request(value: &SessionRequest) -> Result<Vec<u8>, LocalAgentProtocolError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(6).map_err(encode_error)?;
    pair_u8(&mut encoder, 1, LOCAL_AGENT_VERSION)?;
    pair_bytes(&mut encoder, 2, value.request_id.as_bytes())?;
    pair_text(&mut encoder, 3, &value.sdk_family)?;
    pair_text(&mut encoder, 4, &value.sdk_version)?;
    pair_bytes(&mut encoder, 5, &value.common_registry_digest)?;
    pair_text(&mut encoder, 6, value.requested_mode.as_str())?;
    Ok(encoder.into_writer())
}

/// Decodes and byte-canonicalizes one session request.
pub fn decode_session_request(bytes: &[u8]) -> Result<SessionRequest, LocalAgentProtocolError> {
    request_limit(bytes)?;
    let mut decoder = Decoder::new(bytes);
    exact_map(&mut decoder, 6)?;
    version_field(&mut decoder)?;
    expect_key(&mut decoder, 2)?;
    let request_id = ClientRequestId(decode_exact_bytes::<16>(&mut decoder)?);
    expect_key(&mut decoder, 3)?;
    let family = decoder.str().map_err(decode_error)?.to_owned();
    expect_key(&mut decoder, 4)?;
    let sdk_version = decoder.str().map_err(decode_error)?.to_owned();
    expect_key(&mut decoder, 5)?;
    let digest = decode_exact_bytes::<32>(&mut decoder)?;
    expect_key(&mut decoder, 6)?;
    let mode = SessionMode::parse(decoder.str().map_err(decode_error)?)?;
    finish(&decoder, bytes)?;
    let value = SessionRequest::new(request_id, family, sdk_version, digest, mode)?;
    require_canonical(bytes, &encode_session_request(&value)?)?;
    Ok(value)
}

/// Encodes one canonical session response map.
pub fn encode_session_response(
    value: &SessionResponse,
) -> Result<Vec<u8>, LocalAgentProtocolError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(8).map_err(encode_error)?;
    pair_u8(&mut encoder, 1, LOCAL_AGENT_VERSION)?;
    pair_bytes(&mut encoder, 2, value.request_id.as_bytes())?;
    pair_text(&mut encoder, 3, &value.session_id)?;
    pair_text(&mut encoder, 4, &value.principal)?;
    pair_bytes(&mut encoder, 5, &value.common_registry_digest)?;
    encoder
        .u8(6)
        .and_then(|item| item.array(value.profiles.len() as u64))
        .map_err(encode_error)?;
    for profile in &value.profiles {
        encode_profile(&mut encoder, profile)?;
    }
    pair_u8(&mut encoder, 7, value.maximum_concurrent_requests)?;
    pair_text(&mut encoder, 8, value.mode.as_str())?;
    let bytes = encoder.into_writer();
    if bytes.len() > MAX_LOCAL_RESPONSE_BYTES {
        return Err(LocalAgentProtocolError::LimitExceeded);
    }
    Ok(bytes)
}

/// Decodes and byte-canonicalizes one session response.
pub fn decode_session_response(bytes: &[u8]) -> Result<SessionResponse, LocalAgentProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_LOCAL_RESPONSE_BYTES {
        return Err(LocalAgentProtocolError::LimitExceeded);
    }
    let mut decoder = Decoder::new(bytes);
    exact_map(&mut decoder, 8)?;
    version_field(&mut decoder)?;
    expect_key(&mut decoder, 2)?;
    let request_id = ClientRequestId(decode_exact_bytes::<16>(&mut decoder)?);
    expect_key(&mut decoder, 3)?;
    let session_id = decoder.str().map_err(decode_error)?.to_owned();
    expect_key(&mut decoder, 4)?;
    let principal = decoder.str().map_err(decode_error)?.to_owned();
    expect_key(&mut decoder, 5)?;
    let digest = decode_exact_bytes::<32>(&mut decoder)?;
    expect_key(&mut decoder, 6)?;
    let profile_count = definite_array(&mut decoder, 256)?;
    let mut profiles = Vec::with_capacity(profile_count);
    for _ in 0..profile_count {
        profiles.push(decode_profile(&mut decoder)?);
    }
    expect_key(&mut decoder, 7)?;
    let maximum = decoder.u8().map_err(decode_error)?;
    expect_key(&mut decoder, 8)?;
    let mode = SessionMode::parse(decoder.str().map_err(decode_error)?)?;
    finish(&decoder, bytes)?;
    let value = SessionResponse::new(
        request_id, session_id, principal, digest, profiles, maximum, mode,
    )?;
    require_canonical(bytes, &encode_session_response(&value)?)?;
    Ok(value)
}

/// Encodes a canonical prepare request.
pub fn encode_prepare_operation_request(
    value: &PrepareOperationRequest,
) -> Result<Vec<u8>, LocalAgentProtocolError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(7).map_err(encode_error)?;
    pair_u8(&mut encoder, 1, LOCAL_AGENT_VERSION)?;
    pair_bytes(&mut encoder, 2, value.request_id.as_bytes())?;
    pair_optional_text(&mut encoder, 3, value.idempotency_key.as_deref())?;
    pair_bytes(&mut encoder, 4, &value.runtime_contract_digest)?;
    pair_bytes(&mut encoder, 5, &value.profile_input)?;
    pair_optional_text(&mut encoder, 6, value.connection_alias.as_deref())?;
    pair_optional_bytes(
        &mut encoder,
        7,
        value.preparation_evidence_handle.as_deref(),
    )?;
    let bytes = encoder.into_writer();
    request_limit(&bytes)?;
    Ok(bytes)
}

/// Decodes a prepare request under the selected profile limit.
pub fn decode_prepare_operation_request(
    bytes: &[u8],
    profile_limit: usize,
) -> Result<PrepareOperationRequest, LocalAgentProtocolError> {
    request_limit(bytes)?;
    let mut decoder = Decoder::new(bytes);
    exact_map(&mut decoder, 7)?;
    version_field(&mut decoder)?;
    expect_key(&mut decoder, 2)?;
    let request_id = ClientRequestId(decode_exact_bytes::<16>(&mut decoder)?);
    expect_key(&mut decoder, 3)?;
    let idempotency = decode_optional_text(&mut decoder)?;
    expect_key(&mut decoder, 4)?;
    let digest = decode_exact_bytes::<32>(&mut decoder)?;
    expect_key(&mut decoder, 5)?;
    let input = decoder.bytes().map_err(decode_error)?.to_vec();
    expect_key(&mut decoder, 6)?;
    let alias = decode_optional_text(&mut decoder)?;
    expect_key(&mut decoder, 7)?;
    let evidence_handle = decode_optional_exact_bytes::<32>(&mut decoder)?;
    finish(&decoder, bytes)?;
    let value =
        PrepareOperationRequest::new(request_id, idempotency, digest, input, alias, profile_limit)?
            .with_preparation_evidence_handle(evidence_handle.map(Vec::from))?;
    require_canonical(bytes, &encode_prepare_operation_request(&value)?)?;
    Ok(value)
}

/// Decodes the exact six-field tuple accepted by a declared evidence route.
pub fn decode_preparation_evidence_request(
    bytes: &[u8],
    profile_limit: usize,
) -> Result<PreparationEvidenceRequest, LocalAgentProtocolError> {
    request_limit(bytes)?;
    let mut decoder = Decoder::new(bytes);
    exact_map(&mut decoder, 6)?;
    version_field(&mut decoder)?;
    expect_key(&mut decoder, 2)?;
    let request_id = ClientRequestId(decode_exact_bytes::<16>(&mut decoder)?);
    expect_key(&mut decoder, 3)?;
    let idempotency = decode_optional_text(&mut decoder)?;
    expect_key(&mut decoder, 4)?;
    let digest = decode_exact_bytes::<32>(&mut decoder)?;
    expect_key(&mut decoder, 5)?;
    let input = decoder.bytes().map_err(decode_error)?.to_vec();
    expect_key(&mut decoder, 6)?;
    let alias = decode_optional_text(&mut decoder)?;
    finish(&decoder, bytes)?;
    let value =
        PrepareOperationRequest::new(request_id, idempotency, digest, input, alias, profile_limit)?;
    let expected = encode_preparation_evidence_request(&PreparationEvidenceRequest(value.clone()))?;
    require_canonical(bytes, &expected)?;
    Ok(PreparationEvidenceRequest(value))
}

/// Encodes the exact tuple used to acquire a preparation-evidence lease.
pub fn encode_preparation_evidence_request(
    value: &PreparationEvidenceRequest,
) -> Result<Vec<u8>, LocalAgentProtocolError> {
    let value = value.preparation();
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(6).map_err(encode_error)?;
    pair_u8(&mut encoder, 1, LOCAL_AGENT_VERSION)?;
    pair_bytes(&mut encoder, 2, value.request_id.as_bytes())?;
    pair_optional_text(&mut encoder, 3, value.idempotency_key.as_deref())?;
    pair_bytes(&mut encoder, 4, &value.runtime_contract_digest)?;
    pair_bytes(&mut encoder, 5, &value.profile_input)?;
    pair_optional_text(&mut encoder, 6, value.connection_alias.as_deref())?;
    let bytes = encoder.into_writer();
    request_limit(&bytes)?;
    Ok(bytes)
}

/// Encodes one opaque preparation-evidence lease response.
pub fn encode_preparation_evidence_lease(
    value: &PreparationEvidenceLease,
) -> Result<Vec<u8>, LocalAgentProtocolError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(6).map_err(encode_error)?;
    pair_u8(&mut encoder, 1, LOCAL_AGENT_VERSION)?;
    pair_bytes(&mut encoder, 2, value.request_id().as_bytes())?;
    pair_text(&mut encoder, 3, "lease")?;
    pair_bytes(&mut encoder, 4, value.handle())?;
    pair_bytes(&mut encoder, 5, value.commitment())?;
    encoder
        .u8(6)
        .and_then(|item| item.u64(value.expires_at_unix_seconds()))
        .map_err(encode_error)?;
    let bytes = encoder.into_writer();
    if bytes.len() > MAX_LOCAL_RESPONSE_BYTES {
        return Err(LocalAgentProtocolError::LimitExceeded);
    }
    Ok(bytes)
}

/// Encodes a sealed ordinary profile outcome returned by the companion when
/// the durable journal already owns this request or idempotency identity.
pub fn encode_preparation_evidence_outcome(
    request_id: ClientRequestId,
    outcome: &[u8],
) -> Result<Vec<u8>, LocalAgentProtocolError> {
    if outcome.is_empty() || outcome.len() > MAX_LOCAL_RESPONSE_BYTES {
        return Err(LocalAgentProtocolError::LimitExceeded);
    }
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(4).map_err(encode_error)?;
    pair_u8(&mut encoder, 1, LOCAL_AGENT_VERSION)?;
    pair_bytes(&mut encoder, 2, request_id.as_bytes())?;
    pair_text(&mut encoder, 3, "outcome")?;
    pair_bytes(&mut encoder, 4, outcome)?;
    let bytes = encoder.into_writer();
    if bytes.len() > MAX_LOCAL_RESPONSE_BYTES {
        return Err(LocalAgentProtocolError::LimitExceeded);
    }
    Ok(bytes)
}

/// Decodes a canonical preparation-evidence response and returns its nested
/// ordinary operation outcome, or `None` for an exact lease response.
pub fn decode_preparation_evidence_outcome(
    bytes: &[u8],
) -> Result<Option<LocalOperationOutcome>, LocalAgentProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_LOCAL_RESPONSE_BYTES {
        return Err(LocalAgentProtocolError::LimitExceeded);
    }
    let mut decoder = Decoder::new(bytes);
    let fields = decoder
        .map()
        .map_err(decode_error)?
        .ok_or(LocalAgentProtocolError::InvalidShape)?;
    if !matches!(fields, 4 | 6) {
        return Err(LocalAgentProtocolError::InvalidShape);
    }
    version_field(&mut decoder)?;
    expect_key(&mut decoder, 2)?;
    let request_id = ClientRequestId(decode_exact_bytes::<16>(&mut decoder)?);
    expect_key(&mut decoder, 3)?;
    match decoder.str().map_err(decode_error)? {
        "lease" if fields == 6 => {
            expect_key(&mut decoder, 4)?;
            let handle = decode_exact_bytes::<32>(&mut decoder)?;
            expect_key(&mut decoder, 5)?;
            let commitment = decode_exact_bytes::<32>(&mut decoder)?;
            expect_key(&mut decoder, 6)?;
            let expires_at = decoder.u64().map_err(decode_error)?;
            finish(&decoder, bytes)?;
            let lease = PreparationEvidenceLease::new(request_id, handle, commitment, expires_at)?;
            require_canonical(bytes, &encode_preparation_evidence_lease(&lease)?)?;
            Ok(None)
        }
        "outcome" if fields == 4 => {
            expect_key(&mut decoder, 4)?;
            let nested = decoder.bytes().map_err(decode_error)?;
            finish(&decoder, bytes)?;
            let outcome = decode_local_operation_outcome(nested)?;
            if outcome.request_id() != request_id {
                return Err(LocalAgentProtocolError::InvalidShape);
            }
            require_canonical(
                bytes,
                &encode_preparation_evidence_outcome(request_id, nested)?,
            )?;
            Ok(Some(outcome))
        }
        _ => Err(LocalAgentProtocolError::InvalidShape),
    }
}

/// Encodes a canonical execute request.
pub fn encode_execute_operation_request(
    value: &ExecuteOperationRequest,
) -> Result<Vec<u8>, LocalAgentProtocolError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(4).map_err(encode_error)?;
    pair_u8(&mut encoder, 1, LOCAL_AGENT_VERSION)?;
    pair_bytes(&mut encoder, 2, value.request_id.as_bytes())?;
    pair_text(&mut encoder, 3, value.operation_id.as_str())?;
    pair_bytes(&mut encoder, 4, &value.preparation_commitment)?;
    Ok(encoder.into_writer())
}

/// Decodes a canonical execute request.
pub fn decode_execute_operation_request(
    bytes: &[u8],
) -> Result<ExecuteOperationRequest, LocalAgentProtocolError> {
    request_limit(bytes)?;
    let mut decoder = Decoder::new(bytes);
    exact_map(&mut decoder, 4)?;
    version_field(&mut decoder)?;
    expect_key(&mut decoder, 2)?;
    let request_id = ClientRequestId(decode_exact_bytes::<16>(&mut decoder)?);
    expect_key(&mut decoder, 3)?;
    let operation = OperationId::parse(decoder.str().map_err(decode_error)?)?;
    expect_key(&mut decoder, 4)?;
    let commitment = decode_exact_bytes::<32>(&mut decoder)?;
    finish(&decoder, bytes)?;
    let value = ExecuteOperationRequest::new(request_id, operation, commitment);
    require_canonical(bytes, &encode_execute_operation_request(&value)?)?;
    Ok(value)
}

/// Encodes a canonical recovery request.
pub fn encode_recover_operation_request(
    value: &RecoverOperationRequest,
) -> Result<Vec<u8>, LocalAgentProtocolError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(3).map_err(encode_error)?;
    pair_u8(&mut encoder, 1, LOCAL_AGENT_VERSION)?;
    pair_bytes(&mut encoder, 2, value.request_id.as_bytes())?;
    pair_bytes(&mut encoder, 3, &value.recovery_handle)?;
    Ok(encoder.into_writer())
}

/// Decodes a canonical recovery request.
pub fn decode_recover_operation_request(
    bytes: &[u8],
) -> Result<RecoverOperationRequest, LocalAgentProtocolError> {
    request_limit(bytes)?;
    let mut decoder = Decoder::new(bytes);
    exact_map(&mut decoder, 3)?;
    version_field(&mut decoder)?;
    expect_key(&mut decoder, 2)?;
    let request_id = ClientRequestId(decode_exact_bytes::<16>(&mut decoder)?);
    expect_key(&mut decoder, 3)?;
    let handle = decoder.bytes().map_err(decode_error)?.to_vec();
    finish(&decoder, bytes)?;
    let value = RecoverOperationRequest::new(request_id, handle)?;
    require_canonical(bytes, &encode_recover_operation_request(&value)?)?;
    Ok(value)
}

/// Encodes one closed canonical operation outcome.
#[allow(clippy::too_many_lines)]
pub fn encode_local_operation_outcome(
    value: &LocalOperationOutcome,
) -> Result<Vec<u8>, LocalAgentProtocolError> {
    validate_outcome(value)?;
    let mut encoder = Encoder::new(Vec::new());
    match value {
        LocalOperationOutcome::Ready {
            request_id,
            operation_id,
            preparation_commitment,
            decision_receipt,
            recovery_handle,
            connection_alias,
        } => {
            encoder.map(8).map_err(encode_error)?;
            outcome_prefix(&mut encoder, "ready", request_id, operation_id)?;
            pair_bytes(&mut encoder, 5, preparation_commitment)?;
            pair_bytes(&mut encoder, 6, decision_receipt)?;
            pair_bytes(&mut encoder, 7, recovery_handle)?;
            pair_optional_text(&mut encoder, 8, connection_alias.as_deref())?;
        }
        LocalOperationOutcome::InProgress {
            request_id,
            operation_id,
            state,
            effect,
            receipt_ids,
            recovery_handle,
            connection_alias,
        } => {
            encoder.map(9).map_err(encode_error)?;
            outcome_prefix(&mut encoder, "in-progress", request_id, operation_id)?;
            pair_text(&mut encoder, 5, state)?;
            pair_text(&mut encoder, 6, effect)?;
            encode_text_array_pair(&mut encoder, 7, receipt_ids)?;
            pair_bytes(&mut encoder, 8, recovery_handle)?;
            pair_optional_text(&mut encoder, 9, connection_alias.as_deref())?;
        }
        LocalOperationOutcome::Denied {
            request_id,
            operation_id,
            issue,
            decision_receipt,
            connection_alias,
        } => {
            encoder.map(7).map_err(encode_error)?;
            outcome_prefix(&mut encoder, "denied", request_id, operation_id)?;
            pair_bytes(&mut encoder, 5, issue)?;
            pair_bytes(&mut encoder, 6, decision_receipt)?;
            pair_optional_text(&mut encoder, 7, connection_alias.as_deref())?;
        }
        LocalOperationOutcome::Unavailable {
            request_id,
            operation_id,
            issue,
            receipts,
            connection_alias,
        } => {
            encoder.map(7).map_err(encode_error)?;
            encoder
                .u8(1)
                .and_then(|item| item.u8(LOCAL_AGENT_VERSION))
                .map_err(encode_error)?;
            pair_text(&mut encoder, 2, "unavailable")?;
            pair_bytes(&mut encoder, 3, request_id.as_bytes())?;
            encoder.u8(4).map_err(encode_error)?;
            match operation_id {
                Some(operation) => {
                    encoder.str(operation.as_str()).map_err(encode_error)?;
                }
                None => {
                    encoder.null().map_err(encode_error)?;
                }
            }
            pair_bytes(&mut encoder, 5, issue)?;
            encode_bytes_array_pair(&mut encoder, 6, receipts)?;
            pair_optional_text(&mut encoder, 7, connection_alias.as_deref())?;
        }
        LocalOperationOutcome::Conflict {
            request_id,
            operation_id,
            issue,
            recovery_handle,
            receipts,
            connection_alias,
        } => {
            encoder.map(8).map_err(encode_error)?;
            outcome_prefix(&mut encoder, "conflict", request_id, operation_id)?;
            pair_bytes(&mut encoder, 5, issue)?;
            pair_bytes(&mut encoder, 6, recovery_handle)?;
            encode_bytes_array_pair(&mut encoder, 7, receipts)?;
            pair_optional_text(&mut encoder, 8, connection_alias.as_deref())?;
        }
        LocalOperationOutcome::Completed {
            request_id,
            operation_id,
            value,
            receipts,
            completion,
            connection_alias,
        } => {
            encoder.map(8).map_err(encode_error)?;
            outcome_prefix(&mut encoder, "completed", request_id, operation_id)?;
            pair_bytes(&mut encoder, 5, value)?;
            encode_bytes_array_pair(&mut encoder, 6, receipts)?;
            pair_text(&mut encoder, 7, completion.as_str())?;
            pair_optional_text(&mut encoder, 8, connection_alias.as_deref())?;
        }
        LocalOperationOutcome::Partial {
            request_id,
            operation_id,
            value,
            issue,
            receipts,
            completion,
            connection_alias,
        } => {
            encoder.map(9).map_err(encode_error)?;
            outcome_prefix(&mut encoder, "partial", request_id, operation_id)?;
            pair_bytes(&mut encoder, 5, value)?;
            pair_bytes(&mut encoder, 6, issue)?;
            encode_bytes_array_pair(&mut encoder, 7, receipts)?;
            pair_text(&mut encoder, 8, completion.as_str())?;
            pair_optional_text(&mut encoder, 9, connection_alias.as_deref())?;
        }
        LocalOperationOutcome::NotApplied {
            request_id,
            operation_id,
            issue,
            receipts,
            completion,
            connection_alias,
        } => {
            encoder.map(8).map_err(encode_error)?;
            outcome_prefix(&mut encoder, "not-applied", request_id, operation_id)?;
            pair_bytes(&mut encoder, 5, issue)?;
            encode_bytes_array_pair(&mut encoder, 6, receipts)?;
            pair_text(&mut encoder, 7, completion.as_str())?;
            pair_optional_text(&mut encoder, 8, connection_alias.as_deref())?;
        }
        LocalOperationOutcome::RecoveryRequired {
            request_id,
            operation_id,
            issue,
            recovery_handle,
            receipts,
            progress,
            connection_alias,
        } => {
            encoder.map(9).map_err(encode_error)?;
            outcome_prefix(&mut encoder, "recovery-required", request_id, operation_id)?;
            pair_bytes(&mut encoder, 5, issue)?;
            pair_bytes(&mut encoder, 6, recovery_handle)?;
            encode_bytes_array_pair(&mut encoder, 7, receipts)?;
            encoder.u8(8).map_err(encode_error)?;
            match progress {
                Some(bytes) => {
                    encoder.bytes(bytes).map_err(encode_error)?;
                }
                None => {
                    encoder.null().map_err(encode_error)?;
                }
            }
            pair_optional_text(&mut encoder, 9, connection_alias.as_deref())?;
        }
        LocalOperationOutcome::ReceiptIntegrityFailed {
            request_id,
            operation_id,
            issue,
            state,
            effect,
            terminal,
            connection_alias,
        } => {
            encoder.map(9).map_err(encode_error)?;
            outcome_prefix(
                &mut encoder,
                "receipt-integrity-failed",
                request_id,
                operation_id,
            )?;
            pair_bytes(&mut encoder, 5, issue)?;
            pair_text(&mut encoder, 6, state)?;
            pair_text(&mut encoder, 7, effect)?;
            encoder
                .u8(8)
                .and_then(|item| item.bool(*terminal))
                .map_err(encode_error)?;
            pair_optional_text(&mut encoder, 9, connection_alias.as_deref())?;
        }
    }
    bounded_response(encoder.into_writer())
}

/// Decodes and byte-canonicalizes one closed operation outcome.
#[allow(clippy::too_many_lines)]
pub fn decode_local_operation_outcome(
    bytes: &[u8],
) -> Result<LocalOperationOutcome, LocalAgentProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_LOCAL_RESPONSE_BYTES {
        return Err(LocalAgentProtocolError::LimitExceeded);
    }
    let mut decoder = Decoder::new(bytes);
    let field_count = decoder
        .map()
        .map_err(decode_error)?
        .ok_or(LocalAgentProtocolError::InvalidShape)?;
    version_field(&mut decoder)?;
    expect_key(&mut decoder, 2)?;
    let kind = decoder.str().map_err(decode_error)?.to_owned();
    expect_key(&mut decoder, 3)?;
    let request_id = ClientRequestId(decode_exact_bytes::<16>(&mut decoder)?);

    let value = match kind.as_str() {
        "ready" => {
            require_field_count(field_count, 8)?;
            let operation_id = decode_required_operation_id(&mut decoder)?;
            expect_key(&mut decoder, 5)?;
            let preparation_commitment = decode_exact_bytes::<32>(&mut decoder)?;
            expect_key(&mut decoder, 6)?;
            let decision_receipt = decoder.bytes().map_err(decode_error)?.to_vec();
            expect_key(&mut decoder, 7)?;
            let recovery_handle = decoder.bytes().map_err(decode_error)?.to_vec();
            expect_key(&mut decoder, 8)?;
            let connection_alias = decode_optional_text(&mut decoder)?;
            LocalOperationOutcome::Ready {
                request_id,
                operation_id,
                preparation_commitment,
                decision_receipt,
                recovery_handle,
                connection_alias,
            }
        }
        "in-progress" => {
            require_field_count(field_count, 9)?;
            let operation_id = decode_required_operation_id(&mut decoder)?;
            expect_key(&mut decoder, 5)?;
            let state = decoder.str().map_err(decode_error)?.to_owned();
            expect_key(&mut decoder, 6)?;
            let effect = decoder.str().map_err(decode_error)?.to_owned();
            expect_key(&mut decoder, 7)?;
            let receipt_ids = decode_text_array(&mut decoder, 16)?;
            expect_key(&mut decoder, 8)?;
            let recovery_handle = decoder.bytes().map_err(decode_error)?.to_vec();
            expect_key(&mut decoder, 9)?;
            let connection_alias = decode_optional_text(&mut decoder)?;
            LocalOperationOutcome::InProgress {
                request_id,
                operation_id,
                state,
                effect,
                receipt_ids,
                recovery_handle,
                connection_alias,
            }
        }
        "denied" => {
            require_field_count(field_count, 7)?;
            let operation_id = decode_required_operation_id(&mut decoder)?;
            expect_key(&mut decoder, 5)?;
            let issue = decoder.bytes().map_err(decode_error)?.to_vec();
            expect_key(&mut decoder, 6)?;
            let decision_receipt = decoder.bytes().map_err(decode_error)?.to_vec();
            expect_key(&mut decoder, 7)?;
            let connection_alias = decode_optional_text(&mut decoder)?;
            LocalOperationOutcome::Denied {
                request_id,
                operation_id,
                issue,
                decision_receipt,
                connection_alias,
            }
        }
        "unavailable" => {
            require_field_count(field_count, 7)?;
            expect_key(&mut decoder, 4)?;
            let operation_id = decode_optional_operation_id(&mut decoder)?;
            expect_key(&mut decoder, 5)?;
            let issue = decoder.bytes().map_err(decode_error)?.to_vec();
            expect_key(&mut decoder, 6)?;
            let receipts = decode_bytes_array(&mut decoder, 1)?;
            expect_key(&mut decoder, 7)?;
            let connection_alias = decode_optional_text(&mut decoder)?;
            LocalOperationOutcome::Unavailable {
                request_id,
                operation_id,
                issue,
                receipts,
                connection_alias,
            }
        }
        "conflict" => {
            require_field_count(field_count, 8)?;
            let operation_id = decode_required_operation_id(&mut decoder)?;
            expect_key(&mut decoder, 5)?;
            let issue = decoder.bytes().map_err(decode_error)?.to_vec();
            expect_key(&mut decoder, 6)?;
            let recovery_handle = decoder.bytes().map_err(decode_error)?.to_vec();
            expect_key(&mut decoder, 7)?;
            let receipts = decode_bytes_array(&mut decoder, 16)?;
            expect_key(&mut decoder, 8)?;
            let connection_alias = decode_optional_text(&mut decoder)?;
            LocalOperationOutcome::Conflict {
                request_id,
                operation_id,
                issue,
                recovery_handle,
                receipts,
                connection_alias,
            }
        }
        "completed" => {
            require_field_count(field_count, 8)?;
            let operation_id = decode_required_operation_id(&mut decoder)?;
            expect_key(&mut decoder, 5)?;
            let value = decoder.bytes().map_err(decode_error)?.to_vec();
            expect_key(&mut decoder, 6)?;
            let receipts = decode_bytes_array(&mut decoder, 16)?;
            expect_key(&mut decoder, 7)?;
            let completion = LocalOperationCompletion::parse(decoder.str().map_err(decode_error)?)?;
            expect_key(&mut decoder, 8)?;
            let connection_alias = decode_optional_text(&mut decoder)?;
            LocalOperationOutcome::Completed {
                request_id,
                operation_id,
                value,
                receipts,
                completion,
                connection_alias,
            }
        }
        "partial" => {
            require_field_count(field_count, 9)?;
            let operation_id = decode_required_operation_id(&mut decoder)?;
            expect_key(&mut decoder, 5)?;
            let value = decoder.bytes().map_err(decode_error)?.to_vec();
            expect_key(&mut decoder, 6)?;
            let issue = decoder.bytes().map_err(decode_error)?.to_vec();
            expect_key(&mut decoder, 7)?;
            let receipts = decode_bytes_array(&mut decoder, 16)?;
            expect_key(&mut decoder, 8)?;
            let completion = LocalOperationCompletion::parse(decoder.str().map_err(decode_error)?)?;
            expect_key(&mut decoder, 9)?;
            let connection_alias = decode_optional_text(&mut decoder)?;
            LocalOperationOutcome::Partial {
                request_id,
                operation_id,
                value,
                issue,
                receipts,
                completion,
                connection_alias,
            }
        }
        "not-applied" => {
            require_field_count(field_count, 8)?;
            let operation_id = decode_required_operation_id(&mut decoder)?;
            expect_key(&mut decoder, 5)?;
            let issue = decoder.bytes().map_err(decode_error)?.to_vec();
            expect_key(&mut decoder, 6)?;
            let receipts = decode_bytes_array(&mut decoder, 16)?;
            expect_key(&mut decoder, 7)?;
            let completion = LocalOperationCompletion::parse(decoder.str().map_err(decode_error)?)?;
            expect_key(&mut decoder, 8)?;
            let connection_alias = decode_optional_text(&mut decoder)?;
            LocalOperationOutcome::NotApplied {
                request_id,
                operation_id,
                issue,
                receipts,
                completion,
                connection_alias,
            }
        }
        "recovery-required" => {
            require_field_count(field_count, 9)?;
            let operation_id = decode_required_operation_id(&mut decoder)?;
            expect_key(&mut decoder, 5)?;
            let issue = decoder.bytes().map_err(decode_error)?.to_vec();
            expect_key(&mut decoder, 6)?;
            let recovery_handle = decoder.bytes().map_err(decode_error)?.to_vec();
            expect_key(&mut decoder, 7)?;
            let receipts = decode_bytes_array(&mut decoder, 16)?;
            expect_key(&mut decoder, 8)?;
            let progress = decode_optional_bytes(&mut decoder)?;
            expect_key(&mut decoder, 9)?;
            let connection_alias = decode_optional_text(&mut decoder)?;
            LocalOperationOutcome::RecoveryRequired {
                request_id,
                operation_id,
                issue,
                recovery_handle,
                receipts,
                progress,
                connection_alias,
            }
        }
        "receipt-integrity-failed" => {
            require_field_count(field_count, 9)?;
            let operation_id = decode_required_operation_id(&mut decoder)?;
            expect_key(&mut decoder, 5)?;
            let issue = decoder.bytes().map_err(decode_error)?.to_vec();
            expect_key(&mut decoder, 6)?;
            let state = decoder.str().map_err(decode_error)?.to_owned();
            expect_key(&mut decoder, 7)?;
            let effect = decoder.str().map_err(decode_error)?.to_owned();
            expect_key(&mut decoder, 8)?;
            let terminal = decoder.bool().map_err(decode_error)?;
            expect_key(&mut decoder, 9)?;
            let connection_alias = decode_optional_text(&mut decoder)?;
            LocalOperationOutcome::ReceiptIntegrityFailed {
                request_id,
                operation_id,
                issue,
                state,
                effect,
                terminal,
                connection_alias,
            }
        }
        _ => return Err(LocalAgentProtocolError::InvalidShape),
    };
    finish(&decoder, bytes)?;
    validate_outcome(&value)?;
    require_canonical(bytes, &encode_local_operation_outcome(&value)?)?;
    Ok(value)
}

/// Encodes the complete bounded common pending response.
pub fn encode_pending_operations(
    values: &[LocalPendingOperation],
) -> Result<Vec<u8>, LocalAgentProtocolError> {
    if values.len() > 256
        || values.windows(2).any(|pair| {
            (
                &pair[0].updated_at_unix_seconds,
                pair[0].operation_id.as_str(),
            ) >= (
                &pair[1].updated_at_unix_seconds,
                pair[1].operation_id.as_str(),
            )
        })
    {
        return Err(LocalAgentProtocolError::InvalidShape);
    }
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(2).map_err(encode_error)?;
    pair_u8(&mut encoder, 1, LOCAL_AGENT_VERSION)?;
    encoder
        .u8(2)
        .and_then(|item| item.array(values.len() as u64))
        .map_err(encode_error)?;
    for value in values {
        if !validate_pending(value) {
            return Err(LocalAgentProtocolError::InvalidShape);
        }
        encoder.map(10).map_err(encode_error)?;
        pair_text(&mut encoder, 1, value.operation_id.as_str())?;
        pair_text(&mut encoder, 2, &value.profile_id)?;
        encoder
            .u8(3)
            .and_then(|item| item.u16(value.profile_version))
            .map_err(encode_error)?;
        pair_text(&mut encoder, 4, &value.state)?;
        pair_text(&mut encoder, 5, &value.effect)?;
        encoder
            .u8(6)
            .and_then(|item| item.bool(false))
            .map_err(encode_error)?;
        encoder
            .u8(7)
            .and_then(|item| item.u64(value.updated_at_unix_seconds))
            .map_err(encode_error)?;
        encode_text_array_pair(&mut encoder, 8, &value.receipt_ids)?;
        pair_bytes(&mut encoder, 9, &value.recovery_handle)?;
        pair_optional_text(&mut encoder, 10, value.connection_alias.as_deref())?;
    }
    bounded_response(encoder.into_writer())
}

/// Encodes one operation's ordered portable receipt list.
pub fn encode_receipt_entries(
    operation_id: &OperationId,
    values: &[LocalReceiptEntry],
) -> Result<Vec<u8>, LocalAgentProtocolError> {
    if values.is_empty()
        || values.len() > 16
        || values.iter().any(|value| {
            !bounded_ascii_graphic(&value.receipt_id, 128)
                || value.bytes.is_empty()
                || value.bytes.len() > 8 * 1024 * 1024
        })
    {
        return Err(LocalAgentProtocolError::InvalidShape);
    }
    let mut seen = BTreeSet::new();
    if values
        .iter()
        .any(|value| !seen.insert(value.receipt_id.as_str()))
    {
        return Err(LocalAgentProtocolError::InvalidShape);
    }
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(3).map_err(encode_error)?;
    pair_u8(&mut encoder, 1, LOCAL_AGENT_VERSION)?;
    pair_text(&mut encoder, 2, operation_id.as_str())?;
    encoder
        .u8(3)
        .and_then(|item| item.array(values.len() as u64))
        .map_err(encode_error)?;
    for value in values {
        encoder.map(2).map_err(encode_error)?;
        pair_text(&mut encoder, 1, &value.receipt_id)?;
        pair_bytes(&mut encoder, 2, &value.bytes)?;
    }
    bounded_response(encoder.into_writer())
}

#[allow(clippy::too_many_lines)]
fn validate_outcome(value: &LocalOperationOutcome) -> Result<(), LocalAgentProtocolError> {
    let (issue, receipts, recovery, profile_bytes, alias) = match value {
        LocalOperationOutcome::Ready {
            decision_receipt,
            recovery_handle,
            connection_alias,
            ..
        } => (
            None,
            core::slice::from_ref(decision_receipt),
            Some(recovery_handle),
            None,
            connection_alias,
        ),
        LocalOperationOutcome::InProgress {
            state,
            effect,
            receipt_ids,
            recovery_handle,
            connection_alias,
            ..
        } => {
            if !matches!(state.as_str(), "preparing" | "executing")
                || !matches!(effect.as_str(), "not-applied" | "possible")
                || receipt_ids.len() > 16
                || receipt_ids
                    .iter()
                    .any(|item| !bounded_ascii_graphic(item, 128))
            {
                return Err(LocalAgentProtocolError::InvalidShape);
            }
            return validate_common_outcome(
                None,
                &[] as &[Vec<u8>],
                Some(recovery_handle),
                None,
                connection_alias.as_deref(),
            );
        }
        LocalOperationOutcome::Denied {
            issue,
            decision_receipt,
            connection_alias,
            ..
        } => (
            Some(issue),
            core::slice::from_ref(decision_receipt),
            None,
            None,
            connection_alias,
        ),
        LocalOperationOutcome::Unavailable {
            issue,
            receipts,
            connection_alias,
            ..
        } => {
            if receipts.len() > 1 {
                return Err(LocalAgentProtocolError::InvalidShape);
            }
            (
                Some(issue),
                receipts.as_slice(),
                None,
                None,
                connection_alias,
            )
        }
        LocalOperationOutcome::Conflict {
            issue,
            recovery_handle,
            receipts,
            connection_alias,
            ..
        } => (
            Some(issue),
            receipts.as_slice(),
            Some(recovery_handle),
            None,
            connection_alias,
        ),
        LocalOperationOutcome::Completed {
            value,
            receipts,
            connection_alias,
            ..
        } => (
            None,
            receipts.as_slice(),
            None,
            Some(value),
            connection_alias,
        ),
        LocalOperationOutcome::Partial {
            value,
            issue,
            receipts,
            connection_alias,
            ..
        } => (
            Some(issue),
            receipts.as_slice(),
            None,
            Some(value),
            connection_alias,
        ),
        LocalOperationOutcome::NotApplied {
            issue,
            receipts,
            connection_alias,
            ..
        } => (
            Some(issue),
            receipts.as_slice(),
            None,
            None,
            connection_alias,
        ),
        LocalOperationOutcome::RecoveryRequired {
            issue,
            recovery_handle,
            receipts,
            progress,
            connection_alias,
            ..
        } => (
            Some(issue),
            receipts.as_slice(),
            Some(recovery_handle),
            progress.as_ref(),
            connection_alias,
        ),
        LocalOperationOutcome::ReceiptIntegrityFailed {
            issue,
            state,
            effect,
            terminal,
            connection_alias,
            ..
        } => {
            let valid_truth = match state.as_str() {
                "preparing" | "ready" => effect == "not-applied" && !*terminal,
                "executing" => matches!(effect.as_str(), "not-applied" | "possible") && !*terminal,
                "denied" | "unavailable" | "not-applied" => effect == "not-applied" && *terminal,
                "recovery-required" => effect == "possible" && !*terminal,
                "completed" | "partial" => effect == "applied" && *terminal,
                _ => false,
            };
            if !valid_truth {
                return Err(LocalAgentProtocolError::InvalidShape);
            }
            (Some(issue), &[] as &[Vec<u8>], None, None, connection_alias)
        }
    };
    validate_common_outcome(issue, receipts, recovery, profile_bytes, alias.as_deref())
}

fn validate_common_outcome(
    issue: Option<&Vec<u8>>,
    receipts: &[Vec<u8>],
    recovery: Option<&Vec<u8>>,
    profile_bytes: Option<&Vec<u8>>,
    alias: Option<&str>,
) -> Result<(), LocalAgentProtocolError> {
    let receipt_total = receipts
        .iter()
        .try_fold(0_usize, |total, value| total.checked_add(value.len()))
        .ok_or(LocalAgentProtocolError::LimitExceeded)?;
    if issue.is_some_and(|bytes| bytes.is_empty() || bytes.len() > 64 * 1024)
        || receipts.len() > 16
        || receipts.iter().any(Vec::is_empty)
        || receipt_total > 8 * 1024 * 1024
        || recovery.is_some_and(|bytes| bytes.is_empty() || bytes.len() > 16 * 1024)
        || profile_bytes.is_some_and(|bytes| bytes.is_empty() || bytes.len() > 16 * 1024 * 1024)
        || alias.is_some_and(|value| !lower_token(value))
    {
        return Err(LocalAgentProtocolError::LimitExceeded);
    }
    Ok(())
}

fn validate_pending(value: &LocalPendingOperation) -> bool {
    validate_profile_id(&value.profile_id).is_ok()
        && value.profile_version > 0
        && matches!(
            value.state.as_str(),
            "preparing" | "ready" | "executing" | "recovery-required"
        )
        && matches!(value.effect.as_str(), "not-applied" | "possible")
        && value.updated_at_unix_seconds > 0
        && value.receipt_ids.len() <= 16
        && value
            .receipt_ids
            .iter()
            .all(|item| bounded_ascii_graphic(item, 128))
        && (1..=16 * 1024).contains(&value.recovery_handle.len())
        && value.connection_alias.as_deref().is_none_or(lower_token)
}

fn outcome_prefix(
    encoder: &mut Encoder<Vec<u8>>,
    kind: &str,
    request_id: &ClientRequestId,
    operation_id: &OperationId,
) -> Result<(), LocalAgentProtocolError> {
    pair_u8(encoder, 1, LOCAL_AGENT_VERSION)?;
    pair_text(encoder, 2, kind)?;
    pair_bytes(encoder, 3, request_id.as_bytes())?;
    pair_text(encoder, 4, operation_id.as_str())?;
    Ok(())
}

fn encode_text_array_pair(
    encoder: &mut Encoder<Vec<u8>>,
    key: u8,
    values: &[String],
) -> Result<(), LocalAgentProtocolError> {
    encoder
        .u8(key)
        .and_then(|item| item.array(values.len() as u64))
        .map_err(encode_error)?;
    for value in values {
        encoder.str(value).map_err(encode_error)?;
    }
    Ok(())
}

fn encode_bytes_array_pair(
    encoder: &mut Encoder<Vec<u8>>,
    key: u8,
    values: &[Vec<u8>],
) -> Result<(), LocalAgentProtocolError> {
    encoder
        .u8(key)
        .and_then(|item| item.array(values.len() as u64))
        .map_err(encode_error)?;
    for value in values {
        encoder.bytes(value).map_err(encode_error)?;
    }
    Ok(())
}

fn bounded_response(bytes: Vec<u8>) -> Result<Vec<u8>, LocalAgentProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_LOCAL_RESPONSE_BYTES {
        return Err(LocalAgentProtocolError::LimitExceeded);
    }
    Ok(bytes)
}

/// Derives the fixed result for a cancelled protected qualification request.
///
/// This is part of the local-client transport contract so language bindings
/// never independently define the domain separator or digest construction.
#[must_use]
pub fn qualification_client_cancellation_result(request_id: &[u8; 16]) -> [u8; 32] {
    let mut preimage =
        Vec::with_capacity(QUALIFICATION_CLIENT_CANCELLATION_DOMAIN.len() + request_id.len());
    preimage.extend_from_slice(QUALIFICATION_CLIENT_CANCELLATION_DOMAIN);
    preimage.extend_from_slice(request_id);
    Sha256::digest(preimage).into()
}

/// Encodes one bounded protected qualification result frame.
///
/// Modes `0` and `1` carry a new result or cancellation. Modes `2` and `3`
/// are their exact retry forms after an ambiguous transport outcome.
///
/// # Errors
///
/// Returns an error for an unknown mode or an empty/oversized result.
pub fn encode_qualification_client_result_frame(
    mode: u8,
    request_id: &[u8; 16],
    result: &[u8],
) -> Result<Vec<u8>, LocalAgentProtocolError> {
    if mode > 3 {
        return Err(LocalAgentProtocolError::InvalidShape);
    }
    if result.is_empty() || result.len() > MAX_LOCAL_RESPONSE_BYTES {
        return Err(LocalAgentProtocolError::LimitExceeded);
    }
    let result_len =
        u32::try_from(result.len()).map_err(|_| LocalAgentProtocolError::LimitExceeded)?;
    let mut frame = Vec::with_capacity(QUALIFICATION_CLIENT_RESULT_HEADER_BYTES + result.len());
    frame.push(1);
    frame.push(mode);
    frame.extend_from_slice(request_id);
    frame.extend_from_slice(&result_len.to_be_bytes());
    frame.extend_from_slice(result);
    Ok(frame)
}

/// Closed local-agent framing and validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LocalAgentProtocolError {
    /// Operating-system CSPRNG failed.
    #[error("local-agent randomness unavailable")]
    Randomness,
    /// Canonical CBOR encoder failed.
    #[error("local-agent encoding failed")]
    Encoding,
    /// CBOR is malformed or has the wrong field shape.
    #[error("local-agent message is malformed")]
    InvalidShape,
    /// Message is not byte-canonical.
    #[error("local-agent message is noncanonical")]
    Noncanonical,
    /// Protocol or immutable operation contract is unknown.
    #[error("local-agent protocol version is unsupported")]
    UnsupportedVersion,
    /// Identifier or token is malformed.
    #[error("local-agent identifier is invalid")]
    InvalidIdentifier,
    /// Frame or contained data exceeds its hard bound.
    #[error("local-agent message exceeds its bound")]
    LimitExceeded,
    /// Profile advertisements are duplicate or not sorted.
    #[error("local-agent profile advertisement is duplicate or unsorted")]
    DuplicateProfile,
    /// Message has trailing bytes.
    #[error("local-agent message has trailing bytes")]
    TrailingBytes,
}

fn encode_profile(
    encoder: &mut Encoder<Vec<u8>>,
    profile: &ProfileAdvertisement,
) -> Result<(), LocalAgentProtocolError> {
    encoder.map(7).map_err(encode_error)?;
    pair_text(encoder, 1, profile.profile.id())?;
    encoder
        .u8(2)
        .and_then(|item| item.u16(profile.profile.version()))
        .map_err(encode_error)?;
    pair_bytes(encoder, 3, &profile.runtime_contract_digest)?;
    pair_text(encoder, 4, &profile.operation_protocol)?;
    pair_bytes(encoder, 5, &profile.error_projection_digest)?;
    encoder.u8(6).map_err(encode_error)?;
    match &profile.connection {
        None => {
            encoder.null().map_err(encode_error)?;
        }
        Some(connection) => {
            encoder.map(3).map_err(encode_error)?;
            pair_text(encoder, 1, &connection.provider_kind)?;
            pair_text(encoder, 2, &connection.contract)?;
            pair_text(encoder, 3, &connection.descriptor_schema)?;
        }
    }
    encoder.u8(7).map_err(encode_error)?;
    match &profile.qualification {
        None => {
            encoder.null().map_err(encode_error)?;
        }
        Some(qualification) => {
            encoder.map(3).map_err(encode_error)?;
            pair_text(encoder, 1, qualification.qualification_id())?;
            pair_text(encoder, 2, qualification.target())?;
            pair_bytes(encoder, 3, qualification.semantic_closure_sha256())?;
        }
    }
    Ok(())
}

fn decode_profile(
    decoder: &mut Decoder<'_>,
) -> Result<ProfileAdvertisement, LocalAgentProtocolError> {
    exact_map(decoder, 7)?;
    expect_key(decoder, 1)?;
    let id = decoder.str().map_err(decode_error)?.to_owned();
    expect_key(decoder, 2)?;
    let version = decoder.u16().map_err(decode_error)?;
    expect_key(decoder, 3)?;
    let runtime = decode_exact_bytes::<32>(decoder)?;
    expect_key(decoder, 4)?;
    let protocol = decoder.str().map_err(decode_error)?.to_owned();
    expect_key(decoder, 5)?;
    let errors = decode_exact_bytes::<32>(decoder)?;
    expect_key(decoder, 6)?;
    let connection = if decoder.datatype().map_err(decode_error)? == Type::Null {
        decoder.null().map_err(decode_error)?;
        None
    } else {
        exact_map(decoder, 3)?;
        expect_key(decoder, 1)?;
        let provider = decoder.str().map_err(decode_error)?.to_owned();
        expect_key(decoder, 2)?;
        let contract = decoder.str().map_err(decode_error)?.to_owned();
        expect_key(decoder, 3)?;
        let schema = decoder.str().map_err(decode_error)?.to_owned();
        Some(ProfileConnectionAdvertisement::new(
            provider, contract, schema,
        )?)
    };
    expect_key(decoder, 7)?;
    let qualification = if decoder.datatype().map_err(decode_error)? == Type::Null {
        decoder.null().map_err(decode_error)?;
        None
    } else {
        exact_map(decoder, 3)?;
        expect_key(decoder, 1)?;
        let qualification_id = decoder.str().map_err(decode_error)?.to_owned();
        expect_key(decoder, 2)?;
        let target = decoder.str().map_err(decode_error)?.to_owned();
        expect_key(decoder, 3)?;
        let closure = decode_exact_bytes::<32>(decoder)?;
        Some(ProfileQualificationAdvertisement::new(
            qualification_id,
            target,
            closure,
        )?)
    };
    ProfileAdvertisement::new(
        SessionProfileKey::new(id, version)?,
        runtime,
        protocol,
        errors,
        connection,
        qualification,
    )
}

fn pair_u8(
    encoder: &mut Encoder<Vec<u8>>,
    key: u8,
    value: u8,
) -> Result<(), LocalAgentProtocolError> {
    encoder
        .u8(key)
        .and_then(|item| item.u8(value))
        .map_err(encode_error)?;
    Ok(())
}
fn pair_bytes(
    encoder: &mut Encoder<Vec<u8>>,
    key: u8,
    value: &[u8],
) -> Result<(), LocalAgentProtocolError> {
    encoder
        .u8(key)
        .and_then(|item| item.bytes(value))
        .map_err(encode_error)?;
    Ok(())
}
fn pair_text(
    encoder: &mut Encoder<Vec<u8>>,
    key: u8,
    value: &str,
) -> Result<(), LocalAgentProtocolError> {
    encoder
        .u8(key)
        .and_then(|item| item.str(value))
        .map_err(encode_error)?;
    Ok(())
}
fn pair_optional_text(
    encoder: &mut Encoder<Vec<u8>>,
    key: u8,
    value: Option<&str>,
) -> Result<(), LocalAgentProtocolError> {
    encoder.u8(key).map_err(encode_error)?;
    match value {
        Some(value) => {
            encoder.str(value).map_err(encode_error)?;
        }
        None => {
            encoder.null().map_err(encode_error)?;
        }
    }
    Ok(())
}
fn pair_optional_bytes(
    encoder: &mut Encoder<Vec<u8>>,
    key: u8,
    value: Option<&[u8]>,
) -> Result<(), LocalAgentProtocolError> {
    encoder.u8(key).map_err(encode_error)?;
    match value {
        Some(value) => {
            encoder.bytes(value).map_err(encode_error)?;
        }
        None => {
            encoder.null().map_err(encode_error)?;
        }
    }
    Ok(())
}
fn decode_optional_text(
    decoder: &mut Decoder<'_>,
) -> Result<Option<String>, LocalAgentProtocolError> {
    if decoder.datatype().map_err(decode_error)? == Type::Null {
        decoder.null().map_err(decode_error)?;
        Ok(None)
    } else {
        Ok(Some(decoder.str().map_err(decode_error)?.to_owned()))
    }
}
fn decode_optional_bytes(
    decoder: &mut Decoder<'_>,
) -> Result<Option<Vec<u8>>, LocalAgentProtocolError> {
    if decoder.datatype().map_err(decode_error)? == Type::Null {
        decoder.null().map_err(decode_error)?;
        Ok(None)
    } else {
        Ok(Some(decoder.bytes().map_err(decode_error)?.to_vec()))
    }
}
fn decode_required_operation_id(
    decoder: &mut Decoder<'_>,
) -> Result<OperationId, LocalAgentProtocolError> {
    expect_key(decoder, 4)?;
    OperationId::parse(decoder.str().map_err(decode_error)?)
}
fn decode_optional_operation_id(
    decoder: &mut Decoder<'_>,
) -> Result<Option<OperationId>, LocalAgentProtocolError> {
    if decoder.datatype().map_err(decode_error)? == Type::Null {
        decoder.null().map_err(decode_error)?;
        Ok(None)
    } else {
        OperationId::parse(decoder.str().map_err(decode_error)?).map(Some)
    }
}
fn decode_text_array(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<Vec<String>, LocalAgentProtocolError> {
    let count = definite_array(decoder, maximum)?;
    (0..count)
        .map(|_| decoder.str().map(str::to_owned).map_err(decode_error))
        .collect()
}
fn decode_bytes_array(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<Vec<Vec<u8>>, LocalAgentProtocolError> {
    let count = definite_array(decoder, maximum)?;
    (0..count)
        .map(|_| decoder.bytes().map(<[u8]>::to_vec).map_err(decode_error))
        .collect()
}
fn require_field_count(actual: u64, expected: u64) -> Result<(), LocalAgentProtocolError> {
    if actual == expected {
        Ok(())
    } else {
        Err(LocalAgentProtocolError::InvalidShape)
    }
}
fn decode_optional_exact_bytes<const SIZE: usize>(
    decoder: &mut Decoder<'_>,
) -> Result<Option<[u8; SIZE]>, LocalAgentProtocolError> {
    if decoder.datatype().map_err(decode_error)? == Type::Null {
        decoder.null().map_err(decode_error)?;
        Ok(None)
    } else {
        decode_exact_bytes(decoder).map(Some)
    }
}
fn exact_map(decoder: &mut Decoder<'_>, count: u64) -> Result<(), LocalAgentProtocolError> {
    if decoder.map().map_err(decode_error)? != Some(count) {
        return Err(LocalAgentProtocolError::InvalidShape);
    }
    Ok(())
}
fn definite_array(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<usize, LocalAgentProtocolError> {
    let count = decoder
        .array()
        .map_err(decode_error)?
        .ok_or(LocalAgentProtocolError::InvalidShape)?;
    let count = usize::try_from(count).map_err(|_| LocalAgentProtocolError::LimitExceeded)?;
    if count > maximum {
        return Err(LocalAgentProtocolError::LimitExceeded);
    }
    Ok(count)
}
fn version_field(decoder: &mut Decoder<'_>) -> Result<(), LocalAgentProtocolError> {
    expect_key(decoder, 1)?;
    if decoder.u8().map_err(decode_error)? != LOCAL_AGENT_VERSION {
        return Err(LocalAgentProtocolError::UnsupportedVersion);
    }
    Ok(())
}
fn expect_key(decoder: &mut Decoder<'_>, key: u8) -> Result<(), LocalAgentProtocolError> {
    if decoder.u8().map_err(decode_error)? != key {
        return Err(LocalAgentProtocolError::InvalidShape);
    }
    Ok(())
}
fn decode_exact_bytes<const SIZE: usize>(
    decoder: &mut Decoder<'_>,
) -> Result<[u8; SIZE], LocalAgentProtocolError> {
    decoder
        .bytes()
        .map_err(decode_error)?
        .try_into()
        .map_err(|_| LocalAgentProtocolError::InvalidShape)
}
fn request_limit(bytes: &[u8]) -> Result<(), LocalAgentProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_LOCAL_REQUEST_BYTES {
        Err(LocalAgentProtocolError::LimitExceeded)
    } else {
        Ok(())
    }
}
fn finish(decoder: &Decoder<'_>, bytes: &[u8]) -> Result<(), LocalAgentProtocolError> {
    if decoder.position() == bytes.len() {
        Ok(())
    } else {
        Err(LocalAgentProtocolError::TrailingBytes)
    }
}
fn require_canonical(input: &[u8], encoded: &[u8]) -> Result<(), LocalAgentProtocolError> {
    if input == encoded {
        Ok(())
    } else {
        Err(LocalAgentProtocolError::Noncanonical)
    }
}
fn encode_error<E>(_error: minicbor::encode::Error<E>) -> LocalAgentProtocolError {
    LocalAgentProtocolError::Encoding
}
fn decode_error(_error: minicbor::decode::Error) -> LocalAgentProtocolError {
    LocalAgentProtocolError::InvalidShape
}

fn sdk_version_text(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.is_ascii()
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'+' | b'-'))
        })
}
fn lower_token(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}
fn registered_token(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.is_ascii()
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
}
fn qualification_id_token(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix("qlf_") else {
        return false;
    };
    let mut bytes = [0_u8; 32];
    Base64UrlUnpadded::decode(encoded, &mut bytes).is_ok_and(|decoded| {
        decoded.len() == 32 && Base64UrlUnpadded::encode_string(decoded) == encoded
    })
}
fn semantic_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.is_ascii()
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}
fn bounded_ascii_graphic(value: &str, maximum: usize) -> bool {
    (1..=maximum).contains(&value.len()) && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}
fn session_id_token(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix("ses_") else {
        return false;
    };
    let mut bytes = [0_u8; 16];
    Base64UrlUnpadded::decode(encoded, &mut bytes).is_ok_and(|decoded| {
        decoded.len() == 16
            && decoded != [0; 16]
            && Base64UrlUnpadded::encode_string(decoded) == encoded
    })
}
fn validate_profile_id(value: &str) -> Result<(), LocalAgentProtocolError> {
    let mut parts = value.split('.');
    if parts.next() != Some("auths")
        || !parts.next().is_some_and(lower_token)
        || !parts.next().is_some_and(lower_token)
        || parts.next().is_some()
        || value.len() > 128
    {
        return Err(LocalAgentProtocolError::InvalidIdentifier);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_id() -> ClientRequestId {
        ClientRequestId::from_bytes([1; 16])
    }

    #[test]
    fn qualification_client_result_semantics_are_owned_by_the_core() {
        let request_id = [0_u8; 16];
        assert_eq!(
            qualification_client_cancellation_result(&request_id),
            [
                18, 10, 25, 4, 44, 29, 246, 147, 28, 220, 97, 53, 81, 32, 150, 245, 61, 244, 4, 34,
                252, 21, 126, 87, 170, 145, 36, 31, 222, 78, 249, 66,
            ]
        );

        let result = [7_u8; 32];
        let frame = encode_qualification_client_result_frame(3, &request_id, &result).unwrap();
        assert_eq!(
            frame.len(),
            QUALIFICATION_CLIENT_RESULT_HEADER_BYTES + result.len()
        );
        assert_eq!(&frame[..2], &[1, 3]);
        assert_eq!(&frame[2..18], &request_id);
        assert_eq!(&frame[18..22], &(result.len() as u32).to_be_bytes());
        assert_eq!(&frame[22..], &result);
        assert_eq!(
            encode_qualification_client_result_frame(4, &request_id, &result),
            Err(LocalAgentProtocolError::InvalidShape)
        );
        assert_eq!(
            encode_qualification_client_result_frame(0, &request_id, &[]),
            Err(LocalAgentProtocolError::LimitExceeded)
        );
    }

    #[test]
    fn session_handshake_round_trips_canonically() {
        let request = SessionRequest::new(
            request_id(),
            "typescript",
            "1.0.0-rc.1",
            [2; 32],
            SessionMode::Full,
        )
        .unwrap();
        let bytes = encode_session_request(&request).unwrap();
        assert_eq!(decode_session_request(&bytes).unwrap(), request);

        let response = SessionResponse::new(
            request_id(),
            "ses_AQEBAQEBAQEBAQEBAQEBAQ",
            "did:example:worker",
            [2; 32],
            vec![
                ProfileAdvertisement::new(
                    SessionProfileKey::new("auths.stripe.refund", 1).unwrap(),
                    [3; 32],
                    "auths.profile-operation/1",
                    [4; 32],
                    Some(
                        ProfileConnectionAdvertisement::new(
                            "stripe",
                            "auths.stripe.connection/1",
                            "auths.stripe.connection-descriptor/1",
                        )
                        .unwrap(),
                    ),
                    Some(
                        ProfileQualificationAdvertisement::new(
                            "qlf_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
                            "linux-x86_64",
                            [5; 32],
                        )
                        .unwrap(),
                    ),
                )
                .unwrap(),
            ],
            32,
            SessionMode::Full,
        )
        .unwrap();
        let bytes = encode_session_response(&response).unwrap();
        assert_eq!(decode_session_response(&bytes).unwrap(), response);
    }

    #[test]
    fn operation_requests_round_trip_without_resubmitting_input() {
        let prepare = PrepareOperationRequest::new(
            request_id(),
            Some("refund.1".into()),
            [5; 32],
            vec![6; 100],
            Some("merchant-primary".into()),
            1_024,
        )
        .unwrap()
        .with_preparation_evidence_handle(Some(vec![9; 32]))
        .unwrap();
        let bytes = encode_prepare_operation_request(&prepare).unwrap();
        assert_eq!(bytes.first(), Some(&0xa7));
        assert_eq!(
            decode_prepare_operation_request(&bytes, 1_024).unwrap(),
            prepare
        );
        let without_lease = PrepareOperationRequest::new(
            request_id(),
            Some("refund.1".into()),
            [5; 32],
            vec![6; 100],
            Some("merchant-primary".into()),
            1_024,
        )
        .unwrap();
        let bytes = encode_prepare_operation_request(&without_lease).unwrap();
        assert_eq!(
            decode_prepare_operation_request(&bytes, 1_024).unwrap(),
            without_lease
        );
        assert!(
            without_lease
                .clone()
                .with_preparation_evidence_handle(Some(vec![0; 33]))
                .is_err()
        );

        let evidence_request = PreparationEvidenceRequest(without_lease.clone());
        let evidence_bytes = encode_preparation_evidence_request(&evidence_request).unwrap();
        assert_eq!(evidence_bytes.first(), Some(&0xa6));
        assert_eq!(
            decode_preparation_evidence_request(&evidence_bytes, 1_024).unwrap(),
            evidence_request
        );
        let mut wrong_map = encode_prepare_operation_request(&without_lease).unwrap();
        wrong_map[0] = 0xa6;
        assert!(decode_prepare_operation_request(&wrong_map, 1_024).is_err());
        let operation = OperationId::parse("op_AQEBAQEBAQEBAQEBAQEBAQ").unwrap();
        let execute = ExecuteOperationRequest::new(request_id(), operation, [7; 32]);
        let bytes = encode_execute_operation_request(&execute).unwrap();
        assert_eq!(decode_execute_operation_request(&bytes).unwrap(), execute);
        let recover = RecoverOperationRequest::new(request_id(), vec![8; 64]).unwrap();
        let bytes = encode_recover_operation_request(&recover).unwrap();
        assert_eq!(decode_recover_operation_request(&bytes).unwrap(), recover);
    }

    #[test]
    fn operation_outcomes_round_trip_canonically() {
        let operation_id = OperationId::parse("op_AQEBAQEBAQEBAQEBAQEBAQ").unwrap();
        let receipt = vec![1, 2, 3];
        let issue = vec![4, 5, 6];
        let recovery_handle = vec![7, 8, 9];
        let outcomes = vec![
            LocalOperationOutcome::Ready {
                request_id: request_id(),
                operation_id: operation_id.clone(),
                preparation_commitment: [2; 32],
                decision_receipt: receipt.clone(),
                recovery_handle: recovery_handle.clone(),
                connection_alias: Some("primary".into()),
            },
            LocalOperationOutcome::InProgress {
                request_id: request_id(),
                operation_id: operation_id.clone(),
                state: "executing".into(),
                effect: "possible".into(),
                receipt_ids: vec!["receipt-1".into()],
                recovery_handle: recovery_handle.clone(),
                connection_alias: None,
            },
            LocalOperationOutcome::Denied {
                request_id: request_id(),
                operation_id: operation_id.clone(),
                issue: issue.clone(),
                decision_receipt: receipt.clone(),
                connection_alias: None,
            },
            LocalOperationOutcome::Unavailable {
                request_id: request_id(),
                operation_id: None,
                issue: issue.clone(),
                receipts: vec![],
                connection_alias: Some("primary".into()),
            },
            LocalOperationOutcome::Conflict {
                request_id: request_id(),
                operation_id: operation_id.clone(),
                issue: issue.clone(),
                recovery_handle: recovery_handle.clone(),
                receipts: vec![receipt.clone()],
                connection_alias: None,
            },
            LocalOperationOutcome::Completed {
                request_id: request_id(),
                operation_id: operation_id.clone(),
                value: vec![10],
                receipts: vec![receipt.clone()],
                completion: LocalOperationCompletion::Fresh,
                connection_alias: None,
            },
            LocalOperationOutcome::Partial {
                request_id: request_id(),
                operation_id: operation_id.clone(),
                value: vec![10],
                issue: issue.clone(),
                receipts: vec![receipt.clone()],
                completion: LocalOperationCompletion::Replayed,
                connection_alias: None,
            },
            LocalOperationOutcome::NotApplied {
                request_id: request_id(),
                operation_id: operation_id.clone(),
                issue: issue.clone(),
                receipts: vec![receipt.clone()],
                completion: LocalOperationCompletion::Reconciled,
                connection_alias: None,
            },
            LocalOperationOutcome::RecoveryRequired {
                request_id: request_id(),
                operation_id: operation_id.clone(),
                issue: issue.clone(),
                recovery_handle: recovery_handle.clone(),
                receipts: vec![receipt],
                progress: Some(vec![11]),
                connection_alias: None,
            },
            LocalOperationOutcome::ReceiptIntegrityFailed {
                request_id: request_id(),
                operation_id,
                issue,
                state: "completed".into(),
                effect: "applied".into(),
                terminal: true,
                connection_alias: None,
            },
        ];
        for outcome in outcomes {
            let bytes = encode_local_operation_outcome(&outcome).unwrap();
            let decoded = decode_local_operation_outcome(&bytes).unwrap();
            assert_eq!(
                decoded.request_id().to_base64url(),
                request_id().to_base64url()
            );
            assert_eq!(decoded, outcome);
            let wrapped = encode_preparation_evidence_outcome(request_id(), &bytes).unwrap();
            assert_eq!(
                decode_preparation_evidence_outcome(&wrapped).unwrap(),
                Some(outcome)
            );
        }
        let lease = PreparationEvidenceLease::new(request_id(), [2; 32], [3; 32], 4).unwrap();
        let lease = encode_preparation_evidence_lease(&lease).unwrap();
        assert_eq!(decode_preparation_evidence_outcome(&lease).unwrap(), None);
        let mut noncanonical = lease;
        noncanonical.push(0);
        assert!(decode_preparation_evidence_outcome(&noncanonical).is_err());
    }

    #[test]
    fn qualification_commitments_share_the_runtime_idempotency_domain() {
        let request: [u8; 32] = Sha256::digest(b"request").into();
        let input: [u8; 32] = Sha256::digest(b"input").into();
        let principal: [u8; 32] = Sha256::digest(b"did:example:worker").into();
        let raw_idempotency: [u8; 32] = Sha256::digest(b"refund.1").into();
        assert_eq!(local_request_commitment(b"request"), request);
        assert_eq!(local_preparation_input_commitment(b"input"), input);
        assert_eq!(local_principal_commitment("did:example:worker"), principal);
        assert_ne!(local_idempotency_commitment("refund.1"), raw_idempotency);
    }

    #[test]
    fn generated_local_http_envelopes_decode_under_one_strict_grammar() {
        let body = encode_session_request(
            &SessionRequest::new(
                request_id(),
                "typescript",
                "1.0.0",
                [3; 32],
                SessionMode::Full,
            )
            .unwrap(),
        )
        .unwrap();
        let wire = [
            format!(
                "POST /v1/session HTTP/1.1\r\nHost: localhost\r\nContent-Type: {LOCAL_AGENT_CONTENT_TYPE}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes(),
            body.clone(),
        ]
        .concat();
        let request = decode_local_agent_http_request(&wire).unwrap();
        assert_eq!(
            local_agent_http_message_length(&wire[..wire.len() - 1], MAX_LOCAL_REQUEST_BYTES)
                .unwrap(),
            Some(wire.len())
        );
        assert_eq!(
            local_agent_http_message_length(
                &wire[..wire
                    .windows(4)
                    .position(|value| value == b"\r\n\r\n")
                    .unwrap()],
                MAX_LOCAL_REQUEST_BYTES,
            )
            .unwrap(),
            None
        );
        assert_eq!(
            local_agent_http_message_length(&wire, wire.len() - 1),
            Err(LocalAgentProtocolError::LimitExceeded)
        );
        assert_eq!(request.method(), "POST");
        assert_eq!(request.path(), "/v1/session");
        assert_eq!(request.session(), None);
        assert_eq!(request.body(), body);

        let response_wire = [
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: {LOCAL_AGENT_CONTENT_TYPE}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes(),
            body.clone(),
        ]
        .concat();
        let response = decode_local_agent_http_response(&response_wire).unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), body);

        let mut trailing = wire;
        trailing.push(0);
        assert!(decode_local_agent_http_request(&trailing).is_err());
        let leading_zero = format!(
            "POST /v1/session HTTP/1.1\r\nHost: localhost\r\nContent-Type: {LOCAL_AGENT_CONTENT_TYPE}\r\nContent-Length: 01\r\nConnection: close\r\n\r\n0"
        );
        assert!(decode_local_agent_http_request(leading_zero.as_bytes()).is_err());
        let duplicate_length =
            b"POST /v1/session HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            local_agent_http_message_length(duplicate_length, MAX_LOCAL_REQUEST_BYTES),
            Err(LocalAgentProtocolError::InvalidShape)
        );
    }

    #[test]
    fn operation_outcome_decoder_rejects_noncanonical_and_trailing_bytes() {
        let outcome = LocalOperationOutcome::Ready {
            request_id: request_id(),
            operation_id: OperationId::parse("op_AQEBAQEBAQEBAQEBAQEBAQ").unwrap(),
            preparation_commitment: [2; 32],
            decision_receipt: vec![1],
            recovery_handle: vec![2],
            connection_alias: None,
        };
        let bytes = encode_local_operation_outcome(&outcome).unwrap();
        let mut noncanonical = vec![0xb8, 8];
        noncanonical.extend_from_slice(&bytes[1..]);
        assert_eq!(
            decode_local_operation_outcome(&noncanonical),
            Err(LocalAgentProtocolError::Noncanonical)
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            decode_local_operation_outcome(&trailing),
            Err(LocalAgentProtocolError::TrailingBytes)
        );
    }

    #[test]
    fn static_route_family_has_no_generic_invoke() {
        let route = ProfileRoute::new("auths.stripe.refund", 1).unwrap();
        let operation = OperationId::parse("op_AQEBAQEBAQEBAQEBAQEBAQ").unwrap();
        assert_eq!(
            route.collection(),
            "/v1/profiles/stripe/refund/1/operations"
        );
        assert_eq!(
            route.preparation_evidence(),
            "/v1/profiles/stripe/refund/1/preparation-evidence"
        );
        assert_eq!(
            route.execute(&operation),
            "/v1/profiles/stripe/refund/1/operations/op_AQEBAQEBAQEBAQEBAQEBAQ/execute"
        );
    }
}
