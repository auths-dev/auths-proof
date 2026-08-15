//! Idiomatic embedded Auths verification and verified-command decoding.

#![forbid(unsafe_code)]

use auths_kernel_runtime::AuthsKernel;
use auths_model::{
    AcceptedRegistries, AssuranceClaimId, AssurancePolicy, Audience, BudgetAlgebraId, Challenge,
    ChannelBindingId, CompositionRequirement, EvidenceTypeId, ExtensionId, GrantStatusSnapshot,
    PrincipalMethodId, PrincipalStatusSnapshot, ProfilePolicyId, ProfileRef, ResourceMatcherId,
    SignatureSuiteId, StatusMethodId, StatusPolicy, StatusSnapshotId, Timestamp, TrustAnchor,
    TrustedContext, VerifierConfigurationId, VerifierLimits,
};
use auths_profile_api::{ActionProfile, ProfileContractError};
use auths_verifier::VerificationOutcome;
use std::{collections::BTreeSet, sync::Arc};
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
pub struct TrustedContextBuilder {
    configuration: VerifierConfigurationId,
    composition: CompositionRequirement,
    trust_anchors: Vec<TrustAnchor>,
    assurance_policy: AssurancePolicy,
    principal_status: PrincipalStatusSnapshot,
    grant_status: GrantStatusSnapshot,
    channel_policy: ChannelBindingId,
    limits: VerifierLimits,
    signature_suites: BTreeSet<SignatureSuiteId>,
    evidence_types: BTreeSet<EvidenceTypeId>,
    critical_extensions: BTreeSet<ExtensionId>,
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
        let signature_suites = [
            SignatureSuiteId::parse(auths_signature::ED25519_V1)?,
            SignatureSuiteId::parse(auths_signature::P256_SHA256_V1)?,
        ]
        .into_iter()
        .collect();
        let evidence_types = trust_anchors
            .iter()
            .flat_map(TrustAnchor::accepted_methods)
            .map(|method| EvidenceTypeId::parse(method.as_str()))
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(Self {
            configuration,
            composition,
            trust_anchors,
            assurance_policy,
            principal_status: empty_principal_status()?,
            grant_status: empty_grant_status()?,
            channel_policy: ChannelBindingId::parse("none-v1")?,
            limits: VerifierLimits::default(),
            signature_suites,
            evidence_types,
            critical_extensions: BTreeSet::new(),
        })
    }

    /// Replaces the explicit principal lifecycle snapshot.
    #[must_use]
    pub fn with_principal_status(mut self, snapshot: PrincipalStatusSnapshot) -> Self {
        self.principal_status = snapshot;
        self
    }

    /// Replaces the explicit grant lifecycle snapshot.
    #[must_use]
    pub fn with_grant_status(mut self, snapshot: GrantStatusSnapshot) -> Self {
        self.grant_status = snapshot;
        self
    }

    /// Selects the exact signed channel-binding policy.
    #[must_use]
    pub fn with_channel_policy(mut self, policy: ChannelBindingId) -> Self {
        self.channel_policy = policy;
        self
    }

    /// Selects bounded verifier limits.
    #[must_use]
    pub fn with_limits(mut self, limits: VerifierLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Accepts one additional exact evidence identifier.
    #[must_use]
    pub fn accept_evidence_type(mut self, identifier: EvidenceTypeId) -> Self {
        self.evidence_types.insert(identifier);
        self
    }

    /// Accepts one critical extension with an installed implementation.
    #[must_use]
    pub fn accept_critical_extension(mut self, identifier: ExtensionId) -> Self {
        self.critical_extensions.insert(identifier);
        self
    }

    /// Compiles one immutable trusted-context template.
    ///
    /// # Errors
    ///
    /// Returns a typed model failure if roots, profiles, status policy,
    /// registries, or limits disagree.
    pub fn build(self) -> Result<TrustedContext, SdkError> {
        let principal_methods: BTreeSet<PrincipalMethodId> = self
            .trust_anchors
            .iter()
            .flat_map(TrustAnchor::accepted_methods)
            .cloned()
            .collect();
        let profiles: BTreeSet<ProfileRef> = self
            .trust_anchors
            .iter()
            .flat_map(TrustAnchor::profiles)
            .cloned()
            .collect();
        let principal_status_methods: BTreeSet<StatusMethodId> = self
            .trust_anchors
            .iter()
            .filter_map(|anchor| match anchor.status_policy() {
                StatusPolicy::ExpiryOnly => None,
                StatusPolicy::SnapshotRequired { method, .. } => Some(method.clone()),
            })
            .collect();
        let assurance_claims: BTreeSet<AssuranceClaimId> = self
            .assurance_policy
            .requirements()
            .iter()
            .map(|requirement| requirement.claim_kind().clone())
            .collect();
        let accepted = AcceptedRegistries::new(
            auths_registries::TARGET_V1_REGISTRY_MANIFEST,
            principal_methods.into_iter().collect(),
            self.signature_suites.into_iter().collect(),
            self.evidence_types.into_iter().collect(),
            principal_status_methods.into_iter().collect(),
            Vec::new(),
            assurance_claims.into_iter().collect(),
            Vec::new(),
            vec![ResourceMatcherId::parse(
                auths_registries::URI_NAMESPACE_V1,
            )?],
            vec![BudgetAlgebraId::parse(
                auths_registries::NUMERIC_CEILING_V1,
            )?],
            self.critical_extensions.into_iter().collect(),
            profiles.into_iter().collect(),
            vec![ProfilePolicyId::parse(auths_registries::EXACT_PROFILE_V1)?],
        )?;
        Ok(TrustedContext::new(
            self.configuration,
            self.composition,
            self.trust_anchors,
            accepted,
            Audience::parse("auths://request-template")?,
            Challenge::new([0; 32]),
            Timestamp::new(0),
            self.assurance_policy,
            self.principal_status,
            self.grant_status,
            ResourceMatcherId::parse(auths_registries::URI_NAMESPACE_V1)?,
            ProfilePolicyId::parse(auths_registries::EXACT_PROFILE_V1)?,
            self.channel_policy,
            self.limits,
        )?)
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

fn empty_principal_status() -> Result<PrincipalStatusSnapshot, SdkError> {
    Ok(PrincipalStatusSnapshot::new(
        StatusSnapshotId::new([0; 32]),
        Timestamp::new(0),
        Timestamp::new(u64::MAX),
        Vec::new(),
        Vec::new(),
    )?)
}

fn empty_grant_status() -> Result<GrantStatusSnapshot, SdkError> {
    Ok(GrantStatusSnapshot::new(
        StatusSnapshotId::new([1; 32]),
        Timestamp::new(0),
        Timestamp::new(u64::MAX),
        Vec::new(),
        Vec::new(),
    )?)
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
