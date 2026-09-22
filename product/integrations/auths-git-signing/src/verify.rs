//! Verifying a Git signature under whatever principal methods the verifier
//! enables.
//!
//! The caller supplies the executable registries. Enabling a method is a
//! configuration choice bound into the trusted context's configuration
//! commitment, and there is no per-method code on this path. The request is
//! re-derived from the object and the trusted context:
//!
//! - the expected action from the object's payload and the trusted
//!   repository;
//! - the challenge and plan from the payload digest;
//! - the evaluation time from the caller.
//!
//! The signed action must equal the expected action byte for byte. The kernel
//! then verifies the proof against the **expected** action, never against
//! bytes taken from the signature.

use crate::action::{GitSignatureAction, RepositoryId};
use crate::envelope::GitSignatureEnvelope;
use crate::object::{ObjectKind, SignedObject, UnsignedPayload};
use crate::program::{VerifiedSigner, VerifyStatus};
use auths_codec::{
    decode_bundle, decode_canonical_action, decode_verifier_context, encode_canonical_action,
    plan_id,
};
use auths_model::{
    Audience, AuthorizationPlan, Challenge, CompositionRequirement, PrincipalId, ProofRef,
    Timestamp, TrustedContext,
};
use auths_registries::ImmutableRegistries;
use auths_verifier::{VerificationOutcome, verify};
use thiserror::Error;

/// The pinned trust a verifier applies to one repository's signatures.
///
/// The context's expected audience names the repository as
/// `git://<repository>`. Its request fields (challenge, evaluation time,
/// composition) are replaced for every object.
#[derive(Clone, Debug)]
pub struct GitTrust {
    context: TrustedContext,
    repository: RepositoryId,
    audience: Audience,
}

/// Why trust material was rejected.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TrustError {
    /// The trusted context bytes are not a canonical verifier context.
    #[error("malformed git trust context")]
    Malformed,
    /// The context audience is not `git://<repository>`.
    #[error("git trust context does not name a repository")]
    NotARepository,
}

impl TrustError {
    /// Returns the stable result code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "git.trust-malformed",
            Self::NotARepository => "git.trust-repository-invalid",
        }
    }
}

impl GitTrust {
    /// Wraps a trusted context whose audience names the repository.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::NotARepository`] when the audience is not
    /// `git://<repository>` with a valid repository identifier.
    pub fn new(context: TrustedContext) -> Result<Self, TrustError> {
        let audience = context.expected_audience().clone();
        let repository = audience
            .as_str()
            .strip_prefix("git://")
            .and_then(|value| RepositoryId::parse(value).ok())
            .ok_or(TrustError::NotARepository)?;
        Ok(Self {
            context,
            repository,
            audience,
        })
    }

    /// Decodes canonical trusted-context bytes.
    ///
    /// # Errors
    ///
    /// Returns [`TrustError::Malformed`] for bytes that are not a canonical
    /// verifier context, and the [`GitTrust::new`] errors.
    pub fn decode(bytes: &[u8]) -> Result<Self, TrustError> {
        Self::new(decode_verifier_context(bytes).map_err(|_| TrustError::Malformed)?)
    }

    #[cfg(test)]
    pub(crate) const fn context_for_tests(&self) -> &TrustedContext {
        &self.context
    }

    /// Returns the repository this trust applies to.
    #[must_use]
    pub const fn repository(&self) -> &RepositoryId {
        &self.repository
    }
}

/// A verified signature and who it chains to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedGitSignature {
    kind: ObjectKind,
    signer: PrincipalId,
    chain: Vec<PrincipalId>,
    tag_name: Option<String>,
}

impl VerifiedGitSignature {
    /// Returns the object kind.
    #[must_use]
    pub const fn kind(&self) -> ObjectKind {
        self.kind
    }

    /// Returns the signing principal.
    #[must_use]
    pub const fn signer(&self) -> &PrincipalId {
        &self.signer
    }

    /// Returns the grant issuers from the pinned root to the signer's issuer.
    #[must_use]
    pub fn chain(&self) -> &[PrincipalId] {
        &self.chain
    }

    /// Returns the signed tag name for a tag.
    #[must_use]
    pub fn tag_name(&self) -> Option<&str> {
        self.tag_name.as_deref()
    }
}

/// The result of verifying one object. Codes are stable: `git.*` codes come
/// from this package, and every other code is the kernel's.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitVerification {
    /// Every check passed.
    Verified(VerifiedGitSignature),
    /// Available facts establish that the signature does not authorize the
    /// object.
    Denied(&'static str),
    /// A required fact or capability was unavailable.
    Indeterminate(&'static str),
}

impl GitVerification {
    /// Returns the status reported to Git. Only a verified result is good.
    #[must_use]
    pub fn status(&self) -> VerifyStatus {
        match self {
            Self::Verified(signature) => {
                VerifyStatus::Good(VerifiedSigner::new(signature.signer.as_str()))
            }
            Self::Denied(code) => VerifyStatus::Bad(code),
            Self::Indeterminate(code) => VerifyStatus::Error(code),
        }
    }
}

/// Verifies a raw signed commit or tag, as `git cat-file` prints it.
#[must_use]
pub fn verify_object(
    raw: &[u8],
    trust: &GitTrust,
    registries: &ImmutableRegistries<'_>,
    evaluation_time: Timestamp,
) -> GitVerification {
    match SignedObject::parse(raw) {
        Ok(object) => verify_signature(
            object.payload(),
            object.signature(),
            trust,
            registries,
            evaluation_time,
        ),
        Err(error) => GitVerification::Denied(error.code()),
    }
}

/// Verifies a stored signature over an unsigned payload, as Git supplies them
/// to the signing program's verify mode.
#[must_use]
pub fn verify_signature(
    payload: &UnsignedPayload,
    signature: &[u8],
    trust: &GitTrust,
    registries: &ImmutableRegistries<'_>,
    evaluation_time: Timestamp,
) -> GitVerification {
    match verify_inner(payload, signature, trust, registries, evaluation_time) {
        Ok(verified) => verified,
        Err(code) => GitVerification::Denied(code),
    }
}

fn verify_inner(
    payload: &UnsignedPayload,
    signature: &[u8],
    trust: &GitTrust,
    registries: &ImmutableRegistries<'_>,
    evaluation_time: Timestamp,
) -> Result<GitVerification, &'static str> {
    let envelope = GitSignatureEnvelope::from_armored(signature)
        .map_err(crate::envelope::EnvelopeError::code)?;
    let expected = GitSignatureAction::for_payload(&trust.repository, payload)
        .map_err(crate::action::ActionError::code)?;
    let limits = trust.context.limits();
    let signed =
        decode_canonical_action(envelope.action(), limits).map_err(|_| "git.action-malformed")?;
    expected
        .check_signed_body(signed.body())
        .map_err(crate::action::ActionError::code)?;
    let expected_canonical = expected
        .canonical_action()
        .map_err(crate::action::ActionError::code)?;
    let expected_bytes =
        encode_canonical_action(&expected_canonical).map_err(|_| "git.action-malformed")?;
    if expected_bytes.as_slice() != envelope.action() {
        return Err("git.action-malformed");
    }

    let digest = payload.digest();
    let plan = plan_id(&AuthorizationPlan::proof(ProofRef::new(digest)))
        .map_err(|_| "git.action-malformed")?;
    let context = trust
        .context
        .for_request(
            trust.audience.clone(),
            Challenge::new(digest),
            evaluation_time,
        )
        .and_then(|context| context.with_composition(CompositionRequirement::exact(plan)))
        .map_err(|_| "git.trust-malformed")?;

    Ok(
        match verify(envelope.proof(), &expected_canonical, &context, registries) {
            VerificationOutcome::Authorized(_) => {
                GitVerification::Verified(report(&envelope, payload, limits)?)
            }
            VerificationOutcome::Denied(reason) => GitVerification::Denied(reason.code()),
            VerificationOutcome::Indeterminate(requirement) => {
                GitVerification::Indeterminate(requirement.code())
            }
        },
    )
}

/// Reads the signer and issuer chain from a proof the kernel just authorized.
fn report(
    envelope: &GitSignatureEnvelope,
    payload: &UnsignedPayload,
    limits: &auths_model::VerifierLimits,
) -> Result<VerifiedGitSignature, &'static str> {
    let bundle = decode_bundle(envelope.proof(), limits).map_err(|_| "git.action-malformed")?;
    let signer = bundle
        .actions()
        .first()
        .map(|action| action.envelope().actor().clone())
        .ok_or("git.action-malformed")?;
    Ok(VerifiedGitSignature {
        kind: payload.kind(),
        signer,
        chain: bundle
            .grants()
            .iter()
            .map(|grant| grant.statement().issuer().clone())
            .collect(),
        tag_name: payload.tag_name().map(|name| name.as_str().to_owned()),
    })
}
