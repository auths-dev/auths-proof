//! Effect-free ports implemented by signature suites and principal methods.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use auths_model::{
    AdapterConfigurationId, AdapterId, AssuranceClaim, AssuranceClaimId, AssuranceImplicationId,
    BudgetAlgebraId, BudgetCeiling, CanonicalAction, CriticalExtension, EvidenceId, EvidenceObject,
    ExtensionId, GrantId, GrantStatusSnapshot, PrincipalId, PrincipalMethodId,
    PrincipalStatusSnapshot, ProfilePolicyId, ResourceId, ResourceMatcherId, SignatureSuiteId,
    StatusMethodId, StatusPolicy, Timestamp, VerificationMethod,
};
use core::fmt;
use sha2::{Digest as _, Sha256};

/// Computes an unambiguous domain-separated commitment to ordered immutable
/// configuration components.
#[must_use]
pub fn configuration_id<'a>(
    domain: &[u8],
    components: impl IntoIterator<Item = &'a [u8]>,
) -> AdapterConfigurationId {
    let mut hasher = Sha256::new();
    hasher.update(b"auths-proof-adapter-configuration-v1");
    hasher.update(
        u64::try_from(domain.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(domain);
    for component in components {
        hasher.update(
            u64::try_from(component.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(component);
    }
    AdapterConfigurationId::new(hasher.finalize().into())
}

/// Bounded facts a principal method established from immutable evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlEvidence {
    verification_key: Vec<u8>,
    claims: Vec<AssuranceClaim>,
    consumed_evidence: Vec<EvidenceId>,
    adapter: AdapterId,
    adapter_version: u16,
    work_units: u64,
    signature_message: Option<Vec<u8>>,
}

impl ControlEvidence {
    /// Constructs a principal-method result.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalControlError::InvalidEvidence`] if no key or no
    /// evidence provenance is supplied.
    pub fn new(
        verification_key: Vec<u8>,
        claims: Vec<AssuranceClaim>,
        mut consumed_evidence: Vec<EvidenceId>,
        adapter: AdapterId,
        adapter_version: u16,
        work_units: u64,
    ) -> Result<Self, PrincipalControlError> {
        consumed_evidence.sort();
        if verification_key.is_empty() || consumed_evidence.is_empty() {
            return Err(PrincipalControlError::InvalidEvidence);
        }
        if consumed_evidence
            .windows(2)
            .any(|window| window[0] == window[1])
        {
            return Err(PrincipalControlError::InvalidEvidence);
        }
        Ok(Self {
            verification_key,
            claims,
            consumed_evidence,
            adapter,
            adapter_version,
            work_units,
            signature_message: None,
        })
    }

    /// Replaces the default Auths signing preimage with a method-derived
    /// signature message.
    ///
    /// This is required by ceremony-based methods such as `WebAuthn`, where the
    /// authenticator signs a structured message whose challenge commits to the
    /// exact Auths preimage.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalControlError::InvalidEvidence`] for an empty
    /// replacement message.
    pub fn with_signature_message(
        mut self,
        signature_message: Vec<u8>,
    ) -> Result<Self, PrincipalControlError> {
        if signature_message.is_empty() {
            return Err(PrincipalControlError::InvalidEvidence);
        }
        self.signature_message = Some(signature_message);
        Ok(self)
    }

    /// Returns suite-specific public verification-key bytes.
    #[must_use]
    pub fn verification_key(&self) -> &[u8] {
        &self.verification_key
    }

    /// Returns parameterized claims established by the method.
    #[must_use]
    pub fn claims(&self) -> &[AssuranceClaim] {
        &self.claims
    }

    /// Returns exact evidence identifiers consumed by the method.
    #[must_use]
    pub fn consumed_evidence(&self) -> &[EvidenceId] {
        &self.consumed_evidence
    }

    /// Returns the adapter implementation identifier.
    #[must_use]
    pub const fn adapter(&self) -> &AdapterId {
        &self.adapter
    }

    /// Returns the adapter semantic version.
    #[must_use]
    pub const fn adapter_version(&self) -> u16 {
        self.adapter_version
    }

    /// Returns deterministic work charged by principal processing.
    #[must_use]
    pub const fn work_units(&self) -> u64 {
        self.work_units
    }

    /// Returns a principal-method-derived cryptographic message, when the
    /// method does not sign the Auths preimage directly.
    #[must_use]
    pub fn signature_message(&self) -> Option<&[u8]> {
        self.signature_message.as_deref()
    }
}

/// Immutable input to one principal-control method.
pub struct PrincipalControlInput<'a> {
    /// Principal whose control must be established.
    pub principal: &'a PrincipalId,
    /// Exact verification-method identifier signed into the statement.
    pub verification_method: &'a VerificationMethod,
    /// Exact signature suite selected by the signed descriptor.
    pub signature_suite: &'a SignatureSuiteId,
    /// Semantic relationship under which the verification method is used.
    pub purpose: ControlPurpose,
    /// Exact domain-separated bytes signed by the principal.
    pub signing_preimage: &'a [u8],
    /// Statement time against which historical controller state is evaluated.
    pub asserted_signing_time: Timestamp,
    /// Evidence objects explicitly bound to the signed statement.
    pub evidence: &'a [&'a EvidenceObject],
    /// Verifier-supplied evaluation time.
    pub evaluation_time: Timestamp,
}

/// Closed target V1 verification-method relationships.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlPurpose {
    /// Issuing an attenuating authority grant.
    CapabilityDelegation,
    /// Invoking an authorized application action.
    CapabilityInvocation,
    /// Attesting principal or grant status.
    Assertion,
}

/// Pure, deterministic principal-control adapter.
pub trait PrincipalMethod {
    /// Returns the exact registry identifier implemented by this adapter.
    fn id(&self) -> &PrincipalMethodId;

    /// Returns a canonical commitment to every decision-affecting immutable
    /// configuration value held by this adapter instance.
    fn configuration_id(&self) -> AdapterConfigurationId;

    /// Declares a conservative upper bound charged before adapter execution.
    fn maximum_work_units(&self) -> u64;

    /// Establishes a suite-specific key and assurance facts.
    ///
    /// # Errors
    ///
    /// Returns a typed error when supplied evidence is invalid or does not
    /// establish control for the exact principal and verification method.
    fn verify_control(
        &self,
        input: PrincipalControlInput<'_>,
    ) -> Result<ControlEvidence, PrincipalControlError>;
}

/// Immutable input to one signature-suite verifier.
pub struct SignatureInput<'a> {
    /// Suite-specific public verification-key bytes.
    pub verification_key: &'a [u8],
    /// Exact domain-separated signing preimage.
    pub signing_preimage: &'a [u8],
    /// Exact signature bytes from the proof.
    pub signature: &'a [u8],
}

/// Pure cryptographic signature-suite implementation.
pub trait SignatureSuite {
    /// Returns the exact suite registry identifier.
    fn id(&self) -> &SignatureSuiteId;

    /// Returns a canonical commitment to the suite implementation
    /// configuration.
    fn configuration_id(&self) -> AdapterConfigurationId;

    /// Verifies the exact signing preimage.
    ///
    /// # Errors
    ///
    /// Returns a typed error for incompatible key/signature forms or an
    /// invalid signature.
    fn verify(&self, input: SignatureInput<'_>) -> Result<(), SignatureError>;

    /// Returns deterministic work charged for one verification.
    fn work_units(&self) -> u64;
}

/// Failure from an exact pure registry implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryOperationError {
    /// Validated inputs still exceed the implementation's declared bounds.
    ResourceLimitExceeded,
    /// Inputs are incompatible with the exact implementation identifier.
    InvalidInput,
}

/// Pure deterministic resource namespace algebra.
pub trait ResourceMatcher {
    /// Returns the exact implementation identifier.
    fn id(&self) -> &ResourceMatcherId;
    /// Returns the exact immutable implementation-configuration commitment.
    fn configuration_id(&self) -> AdapterConfigurationId;
    /// Returns a conservative pre-execution work reservation.
    fn maximum_work_units(&self, namespace: &ResourceId, resource: &ResourceId) -> u64;
    /// Evaluates one namespace constraint.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for invalid or over-limit inputs.
    fn matches(
        &self,
        namespace: &ResourceId,
        resource: &ResourceId,
    ) -> Result<bool, RegistryOperationError>;
}

/// Typed effect-free profile policy verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileDecision {
    /// The already validated protocol facts are accepted.
    Accept,
    /// Local application policy rejects the action.
    Deny,
}

/// Pure application-profile policy over already validated protocol facts.
pub trait ProfilePolicy {
    /// Returns the exact profile-policy identifier.
    fn id(&self) -> &ProfilePolicyId;
    /// Returns the exact immutable implementation-configuration commitment.
    fn configuration_id(&self) -> AdapterConfigurationId;
    /// Returns a conservative pre-execution work reservation.
    fn maximum_work_units(&self, action: &CanonicalAction) -> u64;
    /// Evaluates policy without acquiring evidence, choosing trust, or doing I/O.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for invalid or over-limit input.
    fn evaluate(&self, action: &CanonicalAction)
        -> Result<ProfileDecision, RegistryOperationError>;
}

/// Pure stateful-budget attenuation algebra.
pub trait BudgetAlgebra {
    /// Returns the exact budget-algebra identifier.
    fn id(&self) -> &BudgetAlgebraId;
    /// Returns the exact immutable implementation-configuration commitment.
    fn configuration_id(&self) -> AdapterConfigurationId;
    /// Returns a conservative pre-execution work reservation.
    fn maximum_work_units(&self) -> u64;
    /// Checks child attenuation under this exact algebra.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for incompatible inputs.
    fn attenuates(
        &self,
        child: &BudgetCeiling,
        parent: &BudgetCeiling,
    ) -> Result<bool, RegistryOperationError>;
    /// Checks whether a ceiling covers an action request.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for incompatible inputs.
    fn covers(
        &self,
        ceiling: &BudgetCeiling,
        requested: &BudgetCeiling,
    ) -> Result<bool, RegistryOperationError>;
}

/// Pure handler for one exact critical-extension version.
pub trait CriticalExtensionHandler {
    /// Returns the exact extension identifier.
    fn id(&self) -> &ExtensionId;
    /// Returns the exact immutable implementation-configuration commitment.
    fn configuration_id(&self) -> AdapterConfigurationId;
    /// Returns a conservative pre-execution work reservation.
    fn maximum_work_units(&self, extension: &CriticalExtension) -> u64;
    /// Validates extension bytes without expanding enclosing authority.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for invalid or over-limit bytes.
    fn evaluate(&self, extension: &CriticalExtension) -> Result<(), RegistryOperationError>;
}

/// Status-method decision after trusted issuer, method, sequence, and freshness evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusDecision {
    /// The subject is active at the trusted snapshot.
    Active,
    /// The subject is revoked or superseded.
    Revoked,
    /// No trusted matching statement exists.
    Missing,
    /// A matching statement is outside its freshness boundary.
    Stale,
    /// A statement is below the context-pinned sequence floor.
    Rollback,
    /// A correctly signed statement came from an untrusted issuer.
    UntrustedIssuer,
    /// Bytes were presented under the wrong exact method identifier.
    WrongMethod,
}

/// Pure exact status-method implementation shared by principal and grant status.
pub trait StatusMethod {
    /// Returns the exact status-method identifier.
    fn id(&self) -> &StatusMethodId;
    /// Returns the exact immutable implementation-configuration commitment.
    fn configuration_id(&self) -> AdapterConfigurationId;
    /// Returns a conservative pre-execution work reservation.
    fn maximum_work_units(&self, statement_count: usize) -> u64;
    /// Evaluates principal status.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when bounded status evaluation cannot complete.
    fn principal(
        &self,
        policy: &StatusPolicy,
        snapshot: &PrincipalStatusSnapshot,
        principal: &PrincipalId,
        evaluation_time: Timestamp,
    ) -> Result<StatusDecision, RegistryOperationError>;
    /// Evaluates grant status under the same selection rules.
    ///
    /// # Errors
    ///
    /// Returns a typed failure when bounded status evaluation cannot complete.
    fn grant(
        &self,
        policy: &StatusPolicy,
        snapshot: &GrantStatusSnapshot,
        grant: GrantId,
        evaluation_time: Timestamp,
    ) -> Result<StatusDecision, RegistryOperationError>;
}

/// Pure exact assurance-claim validation rule.
pub trait AssuranceClaimRule {
    /// Returns the exact claim-kind identifier.
    fn id(&self) -> &AssuranceClaimId;
    /// Returns the exact immutable implementation-configuration commitment.
    fn configuration_id(&self) -> AdapterConfigurationId;
    /// Returns a conservative pre-execution work reservation.
    fn maximum_work_units(&self, claim: &AssuranceClaim) -> u64;
    /// Validates typed claim parameters and source.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for invalid emitted claims.
    fn validate(&self, claim: &AssuranceClaim) -> Result<(), RegistryOperationError>;
}

/// Closed, explicit implication edge between two exact assurance claims.
pub trait AssuranceImplication {
    /// Returns the exact implication-rule identifier.
    fn id(&self) -> &AssuranceImplicationId;
    /// Returns the exact immutable implementation-configuration commitment.
    fn configuration_id(&self) -> AdapterConfigurationId;
    /// Returns the stronger source claim.
    fn source(&self) -> &AssuranceClaimId;
    /// Returns the weaker target claim.
    fn target(&self) -> &AssuranceClaimId;
    /// Returns a conservative pre-execution work reservation.
    fn maximum_work_units(&self) -> u64;
    /// Evaluates whether one validated source claim implies the target.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for incompatible parameters.
    fn implies(&self, claim: &AssuranceClaim) -> Result<bool, RegistryOperationError>;
}

/// Principal-control failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalControlError {
    /// The principal syntax is incompatible with the selected method.
    PrincipalMethodMismatch,
    /// The verification method is not valid for the principal.
    VerificationMethodMismatch,
    /// Supplied evidence is malformed, contradictory, or unauthentic.
    InvalidEvidence,
    /// Evidence key form is incompatible with the signed suite identifier.
    SignatureSuiteMismatch,
    /// Required evidence is absent.
    MissingEvidence,
    /// Bounded adapter work cannot be completed.
    ResourceLimitExceeded,
    /// A trustworthy external fact required by the method is unavailable.
    ExternalFactUnavailable,
    /// Required historical state was not supplied.
    HistoricalStateUnavailable,
    /// Authenticated lifecycle evidence proves the principal is revoked.
    PrincipalRevoked,
}

impl fmt::Display for PrincipalControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PrincipalMethodMismatch => "principal method mismatch",
            Self::VerificationMethodMismatch => "verification method mismatch",
            Self::InvalidEvidence => "invalid principal evidence",
            Self::SignatureSuiteMismatch => "signature suite mismatch",
            Self::MissingEvidence => "missing principal evidence",
            Self::ResourceLimitExceeded => "principal-method work limit exceeded",
            Self::ExternalFactUnavailable => "external fact unavailable",
            Self::HistoricalStateUnavailable => "historical state unavailable",
            Self::PrincipalRevoked => "principal revoked",
        })
    }
}

/// Signature-suite failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureError {
    /// Verification key is malformed or incompatible with the suite.
    InvalidKey,
    /// Signature encoding is malformed or incompatible with the suite.
    InvalidSignatureEncoding,
    /// Cryptographic verification failed.
    InvalidSignature,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidKey => "invalid verification key",
            Self::InvalidSignatureEncoding => "invalid signature encoding",
            Self::InvalidSignature => "invalid signature",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrincipalControlError {}

#[cfg(feature = "std")]
impl std::error::Error for SignatureError {}
