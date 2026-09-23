//! Grant revocation for long-lived Git signatures.
//!
//! The kernel's status snapshot requires every status statement to be bound
//! inside the proof being verified. A commit is signed once and verified
//! later, so a revocation issued after signing can never be bound into that
//! proof. Revocation is therefore its own Auths proof: an authorized
//! principal, normally the pinned root, signs a `revoke-grant` action over one
//! grant identifier. The kernel verifies that record against the same pinned
//! trust as the signatures. The verifier holds the verified revocations as
//! explicit local state and denies any signature whose chain includes a
//! revoked grant.
//!
//! A revocation takes effect for a verifier exactly when the record is in the
//! trust material that verifier reads. Nothing here can make it take effect
//! anywhere else.
//!
//! A record is verified at the time it was issued, read from its own signed
//! action window. The kernel requires that window to lie inside the
//! revoker's authority, and a revocation stays meaningful after that
//! authority's window ends. Reading the time from the record cannot widen
//! anything: a revocation only removes authority, and the revoker's
//! signature is still required.

use crate::action::{ActionError, MEDIA_TYPE, PROFILE_ID, PROFILE_VERSION, RepositoryId};
use crate::envelope::GitSignatureEnvelope;
use crate::sign::{CHANNEL_BINDING, GitProofSigner, SignError};
use auths_author::prepare_action;
use auths_codec::{
    action_id, body_digest, decode_bundle, decode_canonical_action, encode_bundle,
    encode_canonical_action, plan_id,
};
use auths_model::{
    ActionEnvelope, Audience, AuthorizationPlan, BundleHeader, CanonicalAction, CapabilityId,
    Challenge, ChannelBindingId, CompositionRequirement, ControlBinding, CriticalExtensions,
    EvidenceObject, GrantId, MediaType, Permission, ProfileId, ProfileRef, ProofBundle, ProofRef,
    ResourceId, StatementRef, Timestamp, TrustedContext, ValidityWindow,
};
use auths_registries::ImmutableRegistries;
use auths_verifier::{VerificationOutcome, verify};
use serde::{Deserialize, Serialize};

/// Capability for revoking a grant.
pub const REVOKE_GRANT: &str = "git/revoke-grant";
/// Length of a revocation record's action window, in seconds.
pub const REVOCATION_WINDOW_SECONDS: u64 = 300;

/// Authorization to revoke one grant in one repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeGrantAction {
    repository: RepositoryId,
    grant: GrantId,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Body {
    grant_id: String,
    kind: String,
    repository: String,
}

impl RevokeGrantAction {
    /// Builds the action revoking `grant` in `repository`.
    #[must_use]
    pub const fn new(repository: RepositoryId, grant: GrantId) -> Self {
        Self { repository, grant }
    }

    /// Returns the revoked grant.
    #[must_use]
    pub const fn grant(&self) -> GrantId {
        self.grant
    }

    fn body(&self) -> Result<Vec<u8>, ActionError> {
        serde_json_canonicalizer::to_vec(&Body {
            grant_id: hex::encode(self.grant.as_bytes()),
            kind: "revoke-grant".to_owned(),
            repository: self.repository.as_str().to_owned(),
        })
        .map_err(|_| ActionError::Malformed)
    }

    /// Returns `git/revoke-grant` on `git://<repository>/grants`.
    ///
    /// # Errors
    ///
    /// Returns [`ActionError::Model`] if an identifier exceeds a model bound.
    pub fn permission(&self) -> Result<Permission, ActionError> {
        Ok(Permission::new(
            CapabilityId::parse(REVOKE_GRANT)?,
            ResourceId::parse(&format!("git://{}/grants", self.repository.as_str()))?,
        ))
    }

    /// Returns the kernel's canonical action.
    ///
    /// # Errors
    ///
    /// Returns an [`ActionError`] if encoding or a model bound fails.
    pub fn canonical_action(&self) -> Result<CanonicalAction, ActionError> {
        Ok(CanonicalAction::new(
            ProfileRef::new(ProfileId::parse(PROFILE_ID)?, PROFILE_VERSION)?,
            MediaType::parse(MEDIA_TYPE)?,
            self.body()?,
            self.permission()?,
            None,
        )?)
    }

    fn plan(&self) -> AuthorizationPlan {
        AuthorizationPlan::proof(ProofRef::new(*self.grant.as_bytes()))
    }
}

/// Signs a revocation of `grant` in `repository` as `revoker`, who must be
/// authorized for `git/revoke-grant` by the verifier's trust (normally the
/// pinned root acting directly).
///
/// # Errors
///
/// Returns a [`SignError`] when the action, signer, or proof assembly fails.
pub fn sign_revocation(
    repository: &RepositoryId,
    grant: GrantId,
    revoker: &dyn GitProofSigner,
    issued_at: u64,
) -> Result<GitSignatureEnvelope, SignError> {
    let action = RevokeGrantAction::new(repository.clone(), grant);
    let canonical = action.canonical_action()?;
    let plan = action.plan();
    let validity = ValidityWindow::new(
        Timestamp::new(issued_at),
        Timestamp::new(issued_at.saturating_add(REVOCATION_WINDOW_SECONDS)),
    )
    .map_err(|_| SignError::Assembly)?;
    let envelope = ActionEnvelope::new(
        canonical.profile().clone(),
        canonical.media_type().clone(),
        body_digest(canonical.body()),
        canonical.permission().clone(),
        None,
        Audience::parse(&repository.audience()).map_err(|_| SignError::Assembly)?,
        Challenge::new(*grant.as_bytes()),
        validity,
        revoker.principal(),
        None,
        plan_id(&plan).map_err(|_| SignError::Assembly)?,
        ChannelBindingId::parse(CHANNEL_BINDING).map_err(|_| SignError::Assembly)?,
        ProofRef::new(*grant.as_bytes()),
        Vec::new(),
        CriticalExtensions::empty(),
    );
    let request =
        prepare_action(envelope, revoker.descriptor()).map_err(|_| SignError::Assembly)?;
    let statement = revoker.sign_action(request)?;
    let evidence = revoker.control_evidence();
    let binding = ControlBinding::new(
        StatementRef::Action(action_id(statement.envelope()).map_err(|_| SignError::Assembly)?),
        evidence.iter().map(EvidenceObject::id).collect(),
    )
    .map_err(|_| SignError::Assembly)?;
    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        Vec::new(),
        vec![statement],
        plan,
        evidence,
        vec![binding],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .map_err(|_| SignError::Assembly)?;
    Ok(GitSignatureEnvelope::new(
        encode_bundle(&bundle).map_err(|_| SignError::Assembly)?,
        encode_canonical_action(&canonical).map_err(|_| SignError::Assembly)?,
    )?)
}

/// Verifies one armored revocation record and returns the revoked grant.
///
/// The record's action must decode to a canonical `revoke-grant` action for
/// `repository`, and the kernel must authorize it under `context` at the
/// record's own issue time.
///
/// # Errors
///
/// Returns `git.revocation-invalid` for a record that is malformed or names
/// a different action, and the kernel's code when the kernel does not
/// authorize it.
pub fn verify_revocation(
    record: &[u8],
    repository: &RepositoryId,
    context: &TrustedContext,
    registries: &ImmutableRegistries<'_>,
) -> Result<GrantId, &'static str> {
    const INVALID: &str = "git.revocation-invalid";
    let envelope = GitSignatureEnvelope::from_armored(record).map_err(|_| INVALID)?;
    let issued_at = decode_bundle(envelope.proof(), context.limits())
        .ok()
        .and_then(|bundle| {
            bundle
                .actions()
                .first()
                .map(|action| action.envelope().validity().not_before())
        })
        .ok_or(INVALID)?;
    let signed =
        decode_canonical_action(envelope.action(), context.limits()).map_err(|_| INVALID)?;
    let body: Body = serde_json::from_slice(signed.body()).map_err(|_| INVALID)?;
    let bytes: [u8; 32] = hex::decode(&body.grant_id)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(INVALID)?;
    let action = RevokeGrantAction::new(repository.clone(), GrantId::new(bytes));
    let expected = action.canonical_action().map_err(|_| INVALID)?;
    if encode_canonical_action(&expected).map_err(|_| INVALID)? != envelope.action() {
        return Err(INVALID);
    }
    let plan = plan_id(&action.plan()).map_err(|_| INVALID)?;
    let request = context
        .for_request(
            context.expected_audience().clone(),
            Challenge::new(bytes),
            issued_at,
        )
        .and_then(|request| request.with_composition(CompositionRequirement::exact(plan)))
        .map_err(|_| INVALID)?;
    match verify(envelope.proof(), &expected, &request, registries) {
        VerificationOutcome::Authorized(_) => Ok(action.grant()),
        VerificationOutcome::Denied(reason) => Err(reason.code()),
        VerificationOutcome::Indeterminate(requirement) => Err(requirement.code()),
    }
}
