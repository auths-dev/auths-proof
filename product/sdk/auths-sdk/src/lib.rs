//! Idiomatic embedded Auths verification and verified-command decoding.

#![forbid(unsafe_code)]

use auths_kernel_runtime::AuthsKernel;
use auths_model::{
    AssurancePolicy, Audience, Challenge, ChannelBindingId, CompositionRequirement, EvidenceTypeId,
    ExtensionId, GrantStatusSnapshot, PrincipalStatusSnapshot, ProfileRef, SignatureSuiteId,
    Timestamp, TrustAnchor, TrustedContext, VerifierConfigurationId, VerifierLimits,
};
use auths_profile_api::{ActionProfile, ProfileContractError};
use auths_registries::TrustedContextTemplate;
use auths_verifier::VerificationOutcome;
use std::sync::Arc;
use thiserror::Error;

/// Safe grant planning and external signing-request construction.
pub use auths_author as authority;
/// Identity-agnostic external key-custody integration.
pub use auths_custody as custody;
/// Stable error, recovery, and redaction contract used by every SDK.
pub use auths_errors as errors;
/// Canonical protocol model used by explicit advanced configuration.
pub use auths_model as model;
/// Re-exported MCP profile for the shortest supported reference integration.
pub use auths_profile_mcp::{McpCommand, McpProfile, McpToolCall};
/// Sealed verifier output constructible only by the protocol kernel.
pub use auths_verifier::VerifiedAction;

/// Explicit values that vary for one verification request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestContext {
    audience: Audience,
    challenge: Challenge,
    evaluation_time: Timestamp,
}

impl RequestContext {
    /// Constructs exact per-request verification values.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::InvalidAudience`] for a non-canonical audience.
    pub fn new(
        audience: &str,
        challenge: [u8; 32],
        evaluation_time: u64,
    ) -> Result<Self, SdkError> {
        Ok(Self {
            audience: Audience::parse(audience).map_err(|_| SdkError::InvalidAudience)?,
            challenge: Challenge::new(challenge),
            evaluation_time: Timestamp::new(evaluation_time),
        })
    }

    /// Returns the exact verifier audience.
    #[must_use]
    pub const fn audience(&self) -> &Audience {
        &self.audience
    }

    /// Returns the exact replay challenge.
    #[must_use]
    pub const fn challenge(&self) -> Challenge {
        self.challenge
    }

    /// Returns the explicit evaluation time.
    #[must_use]
    pub const fn evaluation_time(&self) -> Timestamp {
        self.evaluation_time
    }
}

/// Builder for an explicit immutable trusted-context template.
///
/// The assembly is [`auths_registries::TrustedContextTemplate`], which the WASM
/// package also compiles through, so both SDKs give equal context bytes for
/// equal inputs.
pub struct TrustedContextBuilder {
    template: TrustedContextTemplate,
}

impl TrustedContextBuilder {
    /// Starts from explicit trusted roots and an explicit assurance policy.
    ///
    /// Mandatory V1 signature suites and self-describing evidence identifiers
    /// are accepted by default. Every value remains encoded into the returned
    /// [`TrustedContext`].
    ///
    /// # Errors
    ///
    /// Returns a typed error when roots are empty or compiled V1 identifiers
    /// are invalid.
    pub fn new(
        configuration: VerifierConfigurationId,
        composition: CompositionRequirement,
        trust_anchors: Vec<TrustAnchor>,
        assurance_policy: AssurancePolicy,
    ) -> Result<Self, SdkError> {
        if trust_anchors.is_empty() {
            return Err(SdkError::MissingTrustAnchor);
        }
        let template = TrustedContextTemplate::new(
            configuration,
            composition,
            trust_anchors,
            assurance_policy,
            [
                SignatureSuiteId::parse(auths_signature::ED25519_V1)?,
                SignatureSuiteId::parse(auths_signature::P256_SHA256_V1)?,
            ],
        )?;
        Ok(Self { template })
    }

    /// Replaces the explicit principal lifecycle snapshot.
    #[must_use]
    pub fn with_principal_status(self, snapshot: PrincipalStatusSnapshot) -> Self {
        Self {
            template: self.template.with_principal_status(snapshot),
        }
    }

    /// Replaces the explicit grant lifecycle snapshot.
    #[must_use]
    pub fn with_grant_status(self, snapshot: GrantStatusSnapshot) -> Self {
        Self {
            template: self.template.with_grant_status(snapshot),
        }
    }

    /// Selects the exact signed channel-binding policy.
    #[must_use]
    pub fn with_channel_policy(self, policy: ChannelBindingId) -> Self {
        Self {
            template: self.template.with_channel_policy(policy),
        }
    }

    /// Selects bounded verifier limits.
    #[must_use]
    pub fn with_limits(self, limits: VerifierLimits) -> Self {
        Self {
            template: self.template.with_limits(limits),
        }
    }

    /// Accepts one additional exact evidence identifier.
    #[must_use]
    pub fn accept_evidence_type(self, identifier: EvidenceTypeId) -> Self {
        Self {
            template: self.template.accept_evidence_type(identifier),
        }
    }

    /// Accepts one critical extension with an installed implementation.
    #[must_use]
    pub fn accept_critical_extension(self, identifier: ExtensionId) -> Self {
        Self {
            template: self.template.accept_critical_extension(identifier),
        }
    }

    /// Declares one profile whose canonical actions cannot express a requested
    /// budget, so an action of that profile provably spends zero.
    ///
    /// The value must come from the profile's own
    /// `ActionProfile::BUDGET_EXPRESSION`; this builder cannot see profile
    /// implementations. A profile that is never declared keeps the denying
    /// reading of an absent request under a bounded ceiling. A declaration for
    /// a profile no trust anchor accepts is dropped rather than rejected, since
    /// the builder derives its accepted-profile set from the anchors.
    #[must_use]
    pub fn declare_budget_free_profile(self, profile: ProfileRef) -> Self {
        Self {
            template: self.template.declare_budget_free_profile(profile),
        }
    }

    /// Compiles one immutable trusted-context template.
    ///
    /// # Errors
    ///
    /// Returns a typed model failure if roots, profiles, status policy,
    /// registries, or limits disagree.
    pub fn build(self) -> Result<TrustedContext, SdkError> {
        Ok(self.template.compile()?)
    }
}

/// Supported embedded service verifier.
pub struct Verifier {
    kernel: Arc<AuthsKernel>,
}

impl Verifier {
    /// Constructs an SDK verifier around explicit immutable kernel inputs.
    #[must_use]
    pub const fn new(kernel: Arc<AuthsKernel>) -> Self {
        Self { kernel }
    }

    /// Constructs the prebuilt self-contained V1 verifier.
    ///
    /// The distribution includes raw-key, `did:key`, and `did:keri` control
    /// plus both mandatory signature suites. Trust-configured adapters can be
    /// supplied through [`Self::new`] without changing application code.
    ///
    /// # Errors
    ///
    /// Returns a typed error only if a compiled identifier or immutable
    /// kernel configuration is invalid.
    pub fn self_contained(context: TrustedContext) -> Result<Self, SdkError> {
        let methods: Vec<Box<dyn auths_ports::PrincipalMethod + Send + Sync>> = vec![
            Box::new(auths_raw_key::RawKeyMethod::new()?),
            Box::new(auths_did_key::DidKeyMethod::new()?),
            Box::new(auths_did_keri::DidKeriMethod::new()?),
        ];
        let suites: Vec<Box<dyn auths_ports::SignatureSuite + Send + Sync>> = vec![
            Box::new(auths_signature::Ed25519Suite::new()?),
            Box::new(auths_signature::P256Sha256Suite::new()?),
        ];
        Ok(Self::new(Arc::new(AuthsKernel::new(
            context, methods, suites,
        )?)))
    }

    /// Verifies authority and decodes a command only from sealed verified data.
    ///
    /// No application API receives the original unverified action bytes after
    /// authorization. Protocol outcomes are returned as [`VerifyResult`];
    /// integration/profile mismatches are typed errors.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Profile`] only if the supplied profile cannot
    /// decode an action that the kernel authorized.
    pub fn verify<P: ActionProfile>(
        &self,
        proof: &[u8],
        canonical_action: &auths_model::CanonicalAction,
        request: &RequestContext,
        profile: &P,
    ) -> Result<VerifyResult<P::Command>, SdkError> {
        match self.kernel.verify(
            proof,
            canonical_action,
            request.audience.clone(),
            request.challenge,
            request.evaluation_time,
        ) {
            VerificationOutcome::Authorized(action) => {
                let command = profile.decode_verified(&action)?;
                Ok(VerifyResult::Authorized(Box::new(Authorized {
                    verified: *action,
                    command,
                })))
            }
            VerificationOutcome::Denied(reason) => {
                Ok(VerifyResult::Denied(Explanation::denied(reason)))
            }
            VerificationOutcome::Indeterminate(requirement) => Ok(VerifyResult::Indeterminate(
                Explanation::indeterminate(requirement),
            )),
        }
    }
}

/// Three-way native verification result with a sealed authorized command.
pub enum VerifyResult<C> {
    /// Exact authority was established and the profile decoded a command.
    Authorized(Box<Authorized<C>>),
    /// Available facts established a stable denial.
    Denied(Explanation),
    /// Required trustworthy facts or capabilities were unavailable.
    Indeterminate(Explanation),
}

/// Command obtained only from a sealed [`VerifiedAction`].
pub struct Authorized<C> {
    verified: VerifiedAction,
    command: C,
}

impl<C> Authorized<C> {
    /// Returns the sealed verifier output.
    #[must_use]
    pub const fn verified(&self) -> &VerifiedAction {
        &self.verified
    }

    /// Returns the executor-safe profile command.
    #[must_use]
    pub const fn command(&self) -> &C {
        &self.command
    }

    /// Consumes the authorization into its verified source and command.
    #[must_use]
    pub fn into_parts(self) -> (VerifiedAction, C) {
        (self.verified, self.command)
    }
}

/// Stable non-sensitive protocol explanation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Explanation {
    code: &'static str,
    message: &'static str,
    retryable: bool,
}

impl Explanation {
    const fn denied(reason: auths_model::DenialReason) -> Self {
        Self {
            code: reason.code(),
            message: "the supplied proof does not authorize this exact action",
            retryable: false,
        }
    }

    const fn indeterminate(requirement: auths_model::Requirement) -> Self {
        Self {
            code: requirement.code(),
            message: "a required trustworthy fact or implementation is unavailable",
            retryable: true,
        }
    }

    /// Returns the stable language-neutral V1 code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.code
    }

    /// Returns a non-sensitive operator summary.
    #[must_use]
    pub const fn message(self) -> &'static str {
        self.message
    }

    /// Reports whether fresh facts or explicit support may change the result.
    #[must_use]
    pub const fn retryable(self) -> bool {
        self.retryable
    }
}

/// SDK configuration or profile-contract failure.
#[derive(Debug, Error)]
pub enum SdkError {
    /// No authority roots were configured.
    #[error("at least one explicit trust anchor is required")]
    MissingTrustAnchor,
    /// A request audience was invalid.
    #[error("invalid request audience")]
    InvalidAudience,
    /// A target V1 model invariant was violated.
    #[error("invalid Auths V1 context: {0}")]
    Model(#[from] auths_model::ModelError),
    /// A self-contained principal adapter could not initialize.
    #[error("could not initialize did:keri: {0}")]
    Keri(#[from] auths_did_keri::KeriError),
    /// Immutable runtime kernel configuration is invalid.
    #[error("invalid embedded verifier configuration: {0}")]
    Runtime(#[from] auths_kernel_runtime::KernelConfigurationError),
    /// Authorized bytes could not be decoded by the selected profile.
    #[error("verified action does not satisfy the selected profile: {0}")]
    Profile(#[from] ProfileContractError),
}
