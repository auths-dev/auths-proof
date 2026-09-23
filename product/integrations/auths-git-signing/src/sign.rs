//! Authoring a Git signature under any principal method.
//!
//! Nothing here knows which principal method signs. A method plugs in through
//! [`GitProofSigner`]; the delegation chain is supplied as signed grants with
//! each issuer's control evidence.
//!
//! The proof is bound to the object, not to a request:
//!
//! - the action challenge and the proof reference are both the payload
//!   digest, so a verifier re-derives the whole request from the object;
//! - the audience is `git://<repository>`;
//! - the action is valid for the terminal grant's validity window, so a gate
//!   can verify it at any time the grant is valid.

use crate::action::{ActionError, GitSignatureAction, RepositoryId};
use crate::envelope::{EnvelopeError, GitSignatureEnvelope};
use crate::object::UnsignedPayload;
use auths_author::{ExternalSigningRequest, prepare_action};
use auths_codec::{
    action_id, body_digest, encode_bundle, encode_canonical_action, grant_id, plan_id,
};
use auths_model::{
    ActionEnvelope, Audience, AuthorizationPlan, BundleHeader, Challenge, ChannelBindingId,
    ControlBinding, CriticalExtensions, EvidenceObject, GrantStatement, PrincipalId, ProofBundle,
    ProofRef, SignatureBytes, SignatureDescriptor, SignedAction, SignedGrant, StatementRef,
    Timestamp, ValidityWindow,
};
use thiserror::Error;

/// Maximum number of grants between the pinned root and the signer.
pub const MAX_DELEGATION_DEPTH: usize = 4;
/// Channel binding of every Git signature: none, because nothing is sent.
pub const CHANNEL_BINDING: &str = "none-v1";

/// A principal that can sign Auths statements, under any principal method.
///
/// Signing takes the exact prepared request, never bare bytes, so a
/// custody-held key signs through the same transaction-bound request and
/// response check as every other custody signature.
pub trait GitProofSigner {
    /// The signing principal.
    fn principal(&self) -> PrincipalId;
    /// The principal method, verification method, and signature suite.
    fn descriptor(&self) -> SignatureDescriptor;
    /// Evidence that lets a verifier establish control of the principal.
    /// Some methods need more than one object, such as a token and a key
    /// descriptor, or a certificate chain and a transparency-log entry. It
    /// is requested after signing, so a method may produce evidence that
    /// depends on the signature.
    fn control_evidence(&self) -> Vec<EvidenceObject>;
    /// Where the private key is held: `software`, `workload`, or a custody
    /// kind such as `kms` or `pkcs11`.
    fn custody(&self) -> &'static str;
    /// Signs one prepared grant.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::Signer`] when the method cannot produce a
    /// signature.
    fn sign_grant(
        &self,
        request: ExternalSigningRequest<GrantStatement>,
    ) -> Result<SignedGrant, SignError>;
    /// Signs one prepared action.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::Signer`] when the method cannot produce a
    /// signature.
    fn sign_action(
        &self,
        request: ExternalSigningRequest<ActionEnvelope>,
    ) -> Result<SignedAction, SignError>;
}

/// Completes a grant with a signature made in this process.
pub(crate) fn local_grant(
    request: ExternalSigningRequest<GrantStatement>,
    sign: impl FnOnce(&[u8]) -> Result<SignatureBytes, SignError>,
) -> Result<SignedGrant, SignError> {
    let signature = sign(request.signing_preimage())?;
    Ok(request.complete(signature))
}

/// Completes an action with a signature made in this process.
pub(crate) fn local_action(
    request: ExternalSigningRequest<ActionEnvelope>,
    sign: impl FnOnce(&[u8]) -> Result<SignatureBytes, SignError>,
) -> Result<SignedAction, SignError> {
    let signature = sign(request.signing_preimage())?;
    Ok(request.complete(signature))
}

/// One grant in a delegation chain, with its issuer's control evidence.
#[derive(Clone, Debug)]
pub struct DelegationLink {
    grant: SignedGrant,
    issuer_evidence: EvidenceObject,
}

impl DelegationLink {
    /// Pairs a signed grant with the evidence for its issuer.
    #[must_use]
    pub const fn new(grant: SignedGrant, issuer_evidence: EvidenceObject) -> Self {
        Self {
            grant,
            issuer_evidence,
        }
    }

    /// Returns the signed grant.
    #[must_use]
    pub const fn grant(&self) -> &SignedGrant {
        &self.grant
    }

    /// Returns the issuer's control evidence.
    #[must_use]
    pub const fn issuer_evidence(&self) -> &EvidenceObject {
        &self.issuer_evidence
    }
}

/// A grant chain from a pinned root to the signer, root first.
#[derive(Clone, Debug)]
pub struct Delegation {
    links: Vec<DelegationLink>,
}

impl Delegation {
    /// Builds a chain.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::Delegation`] for an empty chain, a chain longer
    /// than [`MAX_DELEGATION_DEPTH`], or a link whose issuer is not the
    /// previous link's subject.
    pub fn new(links: Vec<DelegationLink>) -> Result<Self, SignError> {
        if links.is_empty() || links.len() > MAX_DELEGATION_DEPTH {
            return Err(SignError::Delegation);
        }
        let connected = links
            .windows(2)
            .all(|pair| pair[0].grant.statement().subject() == pair[1].grant.statement().issuer());
        if !connected {
            return Err(SignError::Delegation);
        }
        Ok(Self { links })
    }

    /// Returns the links, root first.
    #[must_use]
    pub fn links(&self) -> &[DelegationLink] {
        &self.links
    }

    /// Returns the grant issued to the signer.
    ///
    /// # Errors
    ///
    /// Returns [`SignError::Delegation`] only for an empty chain, which
    /// [`Delegation::new`] never builds.
    pub fn terminal(&self) -> Result<&SignedGrant, SignError> {
        self.links
            .last()
            .map(|link| &link.grant)
            .ok_or(SignError::Delegation)
    }
}

/// Why a signature could not be produced.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SignError {
    /// The payload has no valid action in this repository.
    #[error("git signature action: {0}")]
    Action(#[from] ActionError),
    /// The delegation chain is empty, too long, or disconnected.
    #[error("invalid delegation chain")]
    Delegation,
    /// The terminal grant was issued to a different principal.
    #[error("the terminal grant was not issued to this signer")]
    GrantSubjectMismatch,
    /// A proof object could not be assembled or encoded.
    #[error("could not assemble the proof")]
    Assembly,
    /// The principal method could not sign.
    #[error("the principal method could not sign")]
    Signer,
    /// The custody boundary refused to sign, or its response did not bind
    /// to the exact request.
    #[error("custody refused to sign: {0}")]
    Custody(auths_custody::CustodyError),
    /// The proof or action exceeds the envelope limits.
    #[error("git signature envelope: {0}")]
    Envelope(#[from] EnvelopeError),
    /// The installed grant does not cover this object now.
    #[error("the installed grant does not cover this signature (capability or validity)")]
    NotCovered,
}

/// Checks locally that the installed grant covers signing `payload` in
/// `repository` at `now`, so the signer can refuse early with a clear
/// message. The verifier remains the authority.
///
/// # Errors
///
/// Returns [`SignError::NotCovered`] when the terminal grant lacks the
/// permission or is not valid at `now`, and [`SignError::Action`] for an
/// invalid action.
pub fn check_coverage(
    delegation: &Delegation,
    payload: &UnsignedPayload,
    repository: &RepositoryId,
    now: u64,
) -> Result<(), SignError> {
    let permission = GitSignatureAction::for_payload(repository, payload)?.permission()?;
    let terminal = delegation.terminal()?.statement();
    if terminal.permissions().contains(&permission)
        && terminal
            .validity()
            .contains(auths_model::Timestamp::new(now))
    {
        Ok(())
    } else {
        Err(SignError::NotCovered)
    }
}

/// Signs `payload` for `repository` as `signer`, under `delegation`, at
/// `signed_at` (Unix seconds).
///
/// The action is valid from `signed_at` until the terminal grant expires.
/// Methods that check signing time against their own evidence, such as a
/// transparency-log integration time, see the true signing time.
///
/// # Errors
///
/// Returns [`SignError::NotCovered`] when `signed_at` is outside the terminal
/// grant, and another [`SignError`] when the action, delegation, signer, or
/// proof assembly fails. The signer is called exactly once, and only after
/// every other input has been validated.
pub fn sign_payload(
    payload: &UnsignedPayload,
    repository: &RepositoryId,
    signer: &dyn GitProofSigner,
    delegation: &Delegation,
    signed_at: u64,
) -> Result<GitSignatureEnvelope, SignError> {
    let action = GitSignatureAction::for_payload(repository, payload)?;
    let canonical = action.canonical_action()?;
    let terminal = delegation.terminal()?;
    let actor = signer.principal();
    if terminal.statement().subject() != &actor {
        return Err(SignError::GrantSubjectMismatch);
    }
    let grant_window = terminal.statement().validity();
    if !grant_window.contains(Timestamp::new(signed_at)) {
        return Err(SignError::NotCovered);
    }
    let validity = ValidityWindow::new(Timestamp::new(signed_at), grant_window.expires_at())
        .map_err(|_| SignError::NotCovered)?;
    let digest = payload.digest();
    let proof_ref = ProofRef::new(digest);
    let plan = AuthorizationPlan::proof(proof_ref);

    let envelope = ActionEnvelope::new(
        canonical.profile().clone(),
        canonical.media_type().clone(),
        body_digest(canonical.body()),
        canonical.permission().clone(),
        None,
        Audience::parse(&repository.audience()).map_err(|_| SignError::Assembly)?,
        Challenge::new(digest),
        validity,
        actor,
        Some(grant_id(terminal.statement()).map_err(|_| SignError::Assembly)?),
        plan_id(&plan).map_err(|_| SignError::Assembly)?,
        ChannelBindingId::parse(CHANNEL_BINDING).map_err(|_| SignError::Assembly)?,
        proof_ref,
        Vec::new(),
        CriticalExtensions::empty(),
    );
    let request = prepare_action(envelope, signer.descriptor()).map_err(|_| SignError::Assembly)?;
    let action_statement = signer.sign_action(request)?;

    let mut evidence: Vec<EvidenceObject> = Vec::new();
    let mut bindings = Vec::with_capacity(delegation.links.len() + 1);
    for link in &delegation.links {
        push_unique(&mut evidence, &link.issuer_evidence);
        bindings.push(
            ControlBinding::new(
                StatementRef::Grant(
                    grant_id(link.grant.statement()).map_err(|_| SignError::Assembly)?,
                ),
                vec![link.issuer_evidence.id()],
            )
            .map_err(|_| SignError::Assembly)?,
        );
    }
    let signer_evidence = signer.control_evidence();
    for item in &signer_evidence {
        push_unique(&mut evidence, item);
    }
    bindings.push(
        ControlBinding::new(
            StatementRef::Action(
                action_id(action_statement.envelope()).map_err(|_| SignError::Assembly)?,
            ),
            signer_evidence.iter().map(EvidenceObject::id).collect(),
        )
        .map_err(|_| SignError::Assembly)?,
    );

    let bundle = ProofBundle::new(
        BundleHeader::v1(),
        delegation
            .links
            .iter()
            .map(|link| link.grant.clone())
            .collect(),
        vec![action_statement],
        plan,
        evidence,
        bindings,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Some(canonical.body().to_vec()),
    )
    .map_err(|_| SignError::Assembly)?;
    let proof = encode_bundle(&bundle).map_err(|_| SignError::Assembly)?;
    let action_bytes = encode_canonical_action(&canonical).map_err(|_| SignError::Assembly)?;
    Ok(GitSignatureEnvelope::new(proof, action_bytes)?)
}

fn push_unique(evidence: &mut Vec<EvidenceObject>, item: &EvidenceObject) {
    if !evidence.iter().any(|existing| existing.id() == item.id()) {
        evidence.push(item.clone());
    }
}
