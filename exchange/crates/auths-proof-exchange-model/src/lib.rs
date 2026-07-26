//! Validated semantic types for exchanging proof-bearing actions.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::fmt;

pub const EXCHANGE_VERSION_V1: u16 = 1;
pub const AUTHS_PROTOCOL_V1: u16 = 1;
pub const MAX_AUDIENCE_BYTES: usize = 512;
pub const MAX_PROFILE_ID_BYTES: usize = 128;
pub const MAX_NEGOTIATED_VERSIONS: usize = 16;
pub const MAX_NEGOTIATED_PROFILES: usize = 64;
pub const MAX_BODY_BYTES: u32 = 1024 * 1024;
pub const MAX_PROOF_BYTES: u32 = 16 * 1024 * 1024;
pub const MAX_RESULT_BYTES: usize = 1024 * 1024;
pub const MAX_REASON_COUNT: usize = 32;
pub const MAX_REASON_BYTES: usize = 128;
pub const MAX_MESSAGE_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ChallengeNonce([u8; 32]);

impl ChallengeNonce {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ExchangeAudience(String);

impl ExchangeAudience {
    /// Parses a non-empty, bounded audience without whitespace or controls.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidAudience`] when the audience is invalid.
    pub fn parse(value: &str) -> Result<Self, ModelError> {
        if value.is_empty()
            || value.len() > MAX_AUDIENCE_BYTES
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(ModelError::InvalidAudience);
        }
        Ok(Self(String::from(value)))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ExchangeProfileId(String);

impl ExchangeProfileId {
    /// Parses an exact bounded application-profile identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidProfileBinding`] for an empty,
    /// oversized, whitespace-bearing, or control-bearing identifier.
    pub fn parse(value: &str) -> Result<Self, ModelError> {
        if value.is_empty()
            || value.len() > MAX_PROFILE_ID_BYTES
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(ModelError::InvalidProfileBinding);
        }
        Ok(Self(String::from(value)))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact Auths protocol and application-profile binding.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ProfileBinding {
    auths_protocol: u16,
    profile_id: ExchangeProfileId,
    profile_version: u16,
}

impl ProfileBinding {
    /// Constructs one exact profile binding.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidProfileBinding`] for an unsupported
    /// Auths protocol or zero profile version.
    pub fn new(
        auths_protocol: u16,
        profile_id: ExchangeProfileId,
        profile_version: u16,
    ) -> Result<Self, ModelError> {
        if auths_protocol != AUTHS_PROTOCOL_V1 || profile_version == 0 {
            return Err(ModelError::InvalidProfileBinding);
        }
        Ok(Self {
            auths_protocol,
            profile_id,
            profile_version,
        })
    }

    #[must_use]
    pub const fn auths_protocol(&self) -> u16 {
        self.auths_protocol
    }

    #[must_use]
    pub const fn profile_id(&self) -> &ExchangeProfileId {
        &self.profile_id
    }

    #[must_use]
    pub const fn profile_version(&self) -> u16 {
        self.profile_version
    }
}

/// Bounded, canonical capabilities exchanged before a challenge is issued.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExchangeCapabilities {
    exchange_versions: Vec<u16>,
    profiles: Vec<ProfileBinding>,
    max_body_bytes: u32,
    max_proof_bytes: u32,
}

impl ExchangeCapabilities {
    /// Constructs a sorted, duplicate-free capability advertisement.
    ///
    /// # Errors
    ///
    /// Returns a typed error for empty, duplicate, zero, or excessive
    /// capability sets and invalid message limits.
    pub fn new(
        mut exchange_versions: Vec<u16>,
        mut profiles: Vec<ProfileBinding>,
        max_body_bytes: u32,
        max_proof_bytes: u32,
    ) -> Result<Self, ModelError> {
        if exchange_versions.is_empty()
            || exchange_versions.len() > MAX_NEGOTIATED_VERSIONS
            || profiles.is_empty()
            || profiles.len() > MAX_NEGOTIATED_PROFILES
            || exchange_versions.contains(&0)
            || max_body_bytes == 0
            || max_body_bytes > MAX_BODY_BYTES
            || max_proof_bytes == 0
            || max_proof_bytes > MAX_PROOF_BYTES
        {
            return Err(ModelError::InvalidCapabilities);
        }
        exchange_versions.sort_unstable();
        profiles.sort();
        if exchange_versions.windows(2).any(|pair| pair[0] == pair[1])
            || profiles.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(ModelError::DuplicateCapability);
        }
        Ok(Self {
            exchange_versions,
            profiles,
            max_body_bytes,
            max_proof_bytes,
        })
    }

    #[must_use]
    pub fn exchange_versions(&self) -> &[u16] {
        &self.exchange_versions
    }

    #[must_use]
    pub fn profiles(&self) -> &[ProfileBinding] {
        &self.profiles
    }

    #[must_use]
    pub const fn max_body_bytes(&self) -> u32 {
        self.max_body_bytes
    }

    #[must_use]
    pub const fn max_proof_bytes(&self) -> u32 {
        self.max_proof_bytes
    }
}

/// Exact result of fail-closed capability negotiation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedExchange {
    exchange_version: u16,
    profile: ProfileBinding,
    max_body_bytes: u32,
    max_proof_bytes: u32,
}

impl NegotiatedExchange {
    #[must_use]
    pub const fn exchange_version(&self) -> u16 {
        self.exchange_version
    }

    #[must_use]
    pub const fn profile(&self) -> &ProfileBinding {
        &self.profile
    }

    #[must_use]
    pub const fn max_body_bytes(&self) -> u32 {
        self.max_body_bytes
    }

    #[must_use]
    pub const fn max_proof_bytes(&self) -> u32 {
        self.max_proof_bytes
    }
}

/// Negotiates only an explicitly required exact profile binding.
///
/// # Errors
///
/// Returns [`ModelError::NoCompatibleProtocol`] instead of selecting another
/// protocol or profile version.
pub fn negotiate_exact(
    client: &ExchangeCapabilities,
    server: &ExchangeCapabilities,
    required: &ProfileBinding,
) -> Result<NegotiatedExchange, ModelError> {
    if !client.exchange_versions.contains(&EXCHANGE_VERSION_V1)
        || !server.exchange_versions.contains(&EXCHANGE_VERSION_V1)
        || !client.profiles.contains(required)
        || !server.profiles.contains(required)
    {
        return Err(ModelError::NoCompatibleProtocol);
    }
    Ok(NegotiatedExchange {
        exchange_version: EXCHANGE_VERSION_V1,
        profile: required.clone(),
        max_body_bytes: client.max_body_bytes.min(server.max_body_bytes),
        max_proof_bytes: client.max_proof_bytes.min(server.max_proof_bytes),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionChallenge {
    challenge: ChallengeNonce,
    audience: ExchangeAudience,
    expires_at: u64,
    max_body_bytes: u32,
    max_proof_bytes: u32,
    profile: ProfileBinding,
}

impl ActionChallenge {
    /// Constructs a challenge from an exact negotiated binding and limits.
    ///
    /// # Errors
    ///
    /// Returns a typed model error when negotiated values are unsupported or
    /// invalid.
    pub fn from_negotiated(
        challenge: ChallengeNonce,
        audience: ExchangeAudience,
        expires_at: u64,
        negotiated: &NegotiatedExchange,
    ) -> Result<Self, ModelError> {
        if negotiated.exchange_version != EXCHANGE_VERSION_V1 {
            return Err(ModelError::NoCompatibleProtocol);
        }
        Self::new(
            challenge,
            audience,
            expires_at,
            negotiated.max_body_bytes,
            negotiated.max_proof_bytes,
            negotiated.profile.clone(),
        )
    }

    /// Constructs a challenge with bounded, non-zero request limits.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidLimit`] when a limit is zero or exceeds
    /// the protocol maximum.
    pub fn new(
        challenge: ChallengeNonce,
        audience: ExchangeAudience,
        expires_at: u64,
        max_body_bytes: u32,
        max_proof_bytes: u32,
        profile: ProfileBinding,
    ) -> Result<Self, ModelError> {
        if max_body_bytes == 0
            || max_body_bytes > MAX_BODY_BYTES
            || max_proof_bytes == 0
            || max_proof_bytes > MAX_PROOF_BYTES
        {
            return Err(ModelError::InvalidLimit);
        }
        Ok(Self {
            challenge,
            audience,
            expires_at,
            max_body_bytes,
            max_proof_bytes,
            profile,
        })
    }

    #[must_use]
    pub const fn version(&self) -> u16 {
        EXCHANGE_VERSION_V1
    }
    #[must_use]
    pub const fn challenge(&self) -> ChallengeNonce {
        self.challenge
    }
    #[must_use]
    pub const fn audience(&self) -> &ExchangeAudience {
        &self.audience
    }
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    #[must_use]
    pub const fn max_body_bytes(&self) -> u32 {
        self.max_body_bytes
    }
    #[must_use]
    pub const fn max_proof_bytes(&self) -> u32 {
        self.max_proof_bytes
    }
    #[must_use]
    pub const fn auths_protocol(&self) -> u16 {
        self.profile.auths_protocol
    }
    #[must_use]
    pub const fn profile_id(&self) -> &ExchangeProfileId {
        &self.profile.profile_id
    }
    #[must_use]
    pub const fn profile_version(&self) -> u16 {
        self.profile.profile_version
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionSubmission {
    challenge: ChallengeNonce,
    auths_protocol: u16,
    profile_id: ExchangeProfileId,
    profile_version: u16,
    body: Vec<u8>,
    proof: Vec<u8>,
}

impl ActionSubmission {
    /// Constructs a request within the challenge-specific bounds.
    ///
    /// # Errors
    ///
    /// Returns a length error when either byte sequence is empty or exceeds
    /// the limit advertised by `challenge`.
    pub fn new(
        body: Vec<u8>,
        proof: Vec<u8>,
        challenge: &ActionChallenge,
    ) -> Result<Self, ModelError> {
        if body.is_empty() || body.len() > challenge.max_body_bytes as usize {
            return Err(ModelError::InvalidBodyLength);
        }
        if proof.is_empty() || proof.len() > challenge.max_proof_bytes as usize {
            return Err(ModelError::InvalidProofLength);
        }
        Ok(Self {
            challenge: challenge.challenge,
            auths_protocol: challenge.profile.auths_protocol,
            profile_id: challenge.profile.profile_id.clone(),
            profile_version: challenge.profile.profile_version,
            body,
            proof,
        })
    }

    #[must_use]
    pub const fn challenge(&self) -> ChallengeNonce {
        self.challenge
    }
    #[must_use]
    pub const fn auths_protocol(&self) -> u16 {
        self.auths_protocol
    }
    #[must_use]
    pub const fn profile_id(&self) -> &ExchangeProfileId {
        &self.profile_id
    }
    #[must_use]
    pub const fn profile_version(&self) -> u16 {
        self.profile_version
    }
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    #[must_use]
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    /// Reports whether every repeated submission binding matches a challenge.
    #[must_use]
    pub fn matches_challenge(&self, challenge: &ActionChallenge) -> bool {
        self.challenge == challenge.challenge()
            && self.auths_protocol == challenge.auths_protocol()
            && self.profile_id == *challenge.profile_id()
            && self.profile_version == challenge.profile_version()
            && self.body.len() <= challenge.max_body_bytes() as usize
            && self.proof.len() <= challenge.max_proof_bytes() as usize
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerObservation {
    IrohEndpoint([u8; 32]),
    HttpsServerCertificate([u8; 32]),
    MutualTlsCertificate([u8; 32]),
    TcpEndpoint(String),
    UnixPeerCredentials {
        uid: u32,
        gid: u32,
        pid: Option<u32>,
    },
    FileEnvelope {
        digest: [u8; 32],
        sequence: u64,
    },
    AuthenticatedOpaque {
        kind: String,
        identifier: Vec<u8>,
    },
    ServerAuthenticated,
    Unauthenticated,
}

impl PeerObservation {
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        !matches!(
            self,
            Self::Unauthenticated | Self::TcpEndpoint(_) | Self::FileEnvelope { .. }
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelBindingPolicy {
    None,
    RequireAuthenticatedPeer,
    RequireSignedSenderBinding,
    RequireSignedRecipientBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerdictDecision {
    Authorized,
    Denied,
    Indeterminate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerdictSummary {
    decision: VerdictDecision,
    reasons: Vec<String>,
}

impl VerdictSummary {
    /// Constructs a bounded, display-safe verdict projection.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidVerdict`] for an empty, oversized, or
    /// control-character-bearing reason set.
    pub fn new(decision: VerdictDecision, reasons: Vec<String>) -> Result<Self, ModelError> {
        if reasons.is_empty()
            || reasons.len() > MAX_REASON_COUNT
            || reasons.iter().any(|reason| {
                reason.is_empty()
                    || reason.len() > MAX_REASON_BYTES
                    || reason.bytes().any(|byte| byte.is_ascii_control())
            })
        {
            return Err(ModelError::InvalidVerdict);
        }
        Ok(Self { decision, reasons })
    }

    #[must_use]
    pub const fn decision(&self) -> VerdictDecision {
        self.decision
    }
    #[must_use]
    pub fn reasons(&self) -> &[String] {
        &self.reasons
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusalKind {
    ApplicationPolicy,
    TransportPolicy,
    AuthsVerdict,
    MalformedInput,
    OversizedInput,
    UnknownChallenge,
    ExpiredChallenge,
    ConsumedChallenge,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExchangeOutcome {
    Completed {
        result: Vec<u8>,
    },
    Refused {
        kind: RefusalKind,
        verdict: Option<VerdictSummary>,
        message: String,
    },
}

impl ExchangeOutcome {
    /// Constructs a completed result within the protocol maximum.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidResultLength`] when `result` is too large.
    pub fn completed(result: Vec<u8>) -> Result<Self, ModelError> {
        if result.len() > MAX_RESULT_BYTES {
            return Err(ModelError::InvalidResultLength);
        }
        Ok(Self::Completed { result })
    }

    /// Constructs an application refusal with a bounded, display-safe message.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::InvalidMessage`] when the message is empty,
    /// oversized, or contains control characters.
    pub fn refused(
        kind: RefusalKind,
        verdict: Option<VerdictSummary>,
        message: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let message = message.into();
        if message.is_empty()
            || message.len() > MAX_MESSAGE_BYTES
            || message.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(ModelError::InvalidMessage);
        }
        Ok(Self::Refused {
            kind,
            verdict,
            message,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExchangeMetrics {
    verification_micros: u64,
    execution_micros: u64,
}

impl ExchangeMetrics {
    #[must_use]
    pub const fn new(verification_micros: u64, execution_micros: u64) -> Self {
        Self {
            verification_micros,
            execution_micros,
        }
    }
    #[must_use]
    pub const fn verification_micros(self) -> u64 {
        self.verification_micros
    }
    #[must_use]
    pub const fn execution_micros(self) -> u64 {
        self.execution_micros
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionResponse {
    request_id: Option<[u8; 32]>,
    outcome: ExchangeOutcome,
    metrics: ExchangeMetrics,
}

impl ActionResponse {
    #[must_use]
    pub const fn new(
        request_id: Option<[u8; 32]>,
        outcome: ExchangeOutcome,
        metrics: ExchangeMetrics,
    ) -> Self {
        Self {
            request_id,
            outcome,
            metrics,
        }
    }
    #[must_use]
    pub const fn request_id(&self) -> Option<&[u8; 32]> {
        self.request_id.as_ref()
    }
    #[must_use]
    pub const fn outcome(&self) -> &ExchangeOutcome {
        &self.outcome
    }
    #[must_use]
    pub const fn metrics(&self) -> ExchangeMetrics {
        self.metrics
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelError {
    InvalidAudience,
    InvalidLimit,
    InvalidBodyLength,
    InvalidProofLength,
    InvalidVerdict,
    InvalidResultLength,
    InvalidMessage,
    InvalidProfileBinding,
    SubmissionMismatch,
    InvalidCapabilities,
    DuplicateCapability,
    NoCompatibleProtocol,
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidAudience => "invalid exchange audience",
            Self::InvalidLimit => "invalid exchange size limit",
            Self::InvalidBodyLength => "invalid action body length",
            Self::InvalidProofLength => "invalid proof length",
            Self::InvalidVerdict => "invalid verdict summary",
            Self::InvalidResultLength => "invalid application result length",
            Self::InvalidMessage => "invalid refusal message",
            Self::InvalidProfileBinding => "invalid Auths/profile binding",
            Self::SubmissionMismatch => "submission does not match challenge",
            Self::InvalidCapabilities => "invalid exchange capabilities",
            Self::DuplicateCapability => "duplicate exchange capability",
            Self::NoCompatibleProtocol => "no exact compatible exchange binding",
        };
        formatter.write_str(message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ModelError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_limits_are_challenge_specific() {
        let challenge = ActionChallenge::new(
            ChallengeNonce::new([1; 32]),
            ExchangeAudience::parse("mcp://reports").unwrap(),
            10,
            4,
            8,
            ProfileBinding::new(
                AUTHS_PROTOCOL_V1,
                ExchangeProfileId::parse("auths.mcp").unwrap(),
                1,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(ActionSubmission::new(vec![1; 4], vec![2; 8], &challenge).is_ok());
        assert_eq!(
            ActionSubmission::new(vec![1; 5], vec![2; 8], &challenge),
            Err(ModelError::InvalidBodyLength)
        );
    }

    #[test]
    fn transport_authentication_is_not_authority() {
        assert!(PeerObservation::IrohEndpoint([7; 32]).is_authenticated());
        assert!(
            !PeerObservation::FileEnvelope {
                digest: [7; 32],
                sequence: 1,
            }
            .is_authenticated()
        );
        assert_ne!(VerdictDecision::Authorized, VerdictDecision::Indeterminate);
    }

    #[test]
    fn negotiation_never_downgrades_the_required_profile() {
        let exact = ProfileBinding::new(
            AUTHS_PROTOCOL_V1,
            ExchangeProfileId::parse("auths.mcp").unwrap(),
            1,
        )
        .unwrap();
        let older = ProfileBinding::new(
            AUTHS_PROTOCOL_V1,
            ExchangeProfileId::parse("auths.mcp").unwrap(),
            2,
        )
        .unwrap();
        let client = ExchangeCapabilities::new(vec![1], vec![exact.clone()], 1024, 4096).unwrap();
        let server = ExchangeCapabilities::new(vec![1], vec![older], 512, 2048).unwrap();
        assert_eq!(
            negotiate_exact(&client, &server, &exact),
            Err(ModelError::NoCompatibleProtocol)
        );
    }
}
