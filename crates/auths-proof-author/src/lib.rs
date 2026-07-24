//! Safe construction of Auths grant/action signing requests and proof bundles.
//!
//! This crate never creates, stores, or receives private key material.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{vec, vec::Vec};
use auths_proof_codec::{action_id, action_signing_bytes, grant_id, grant_signing_bytes};
use auths_proof_model::{
    ActionStatement, Audience, BodyDigest, Challenge, DelegationDepth, GrantId, GrantPayload,
    ModelError, Permission, PermissionSet, PrincipalEvidenceBinding, PrincipalEvidenceEntry,
    PrincipalRef, ProofBundle, RevocationRequirement, SignatureBytes, SignatureDescriptor,
    SignatureEnvelope, SignedAction, SignedGrant, StatementId, Timestamp, ValidityWindow,
};
use core::fmt;

#[derive(Clone, Debug)]
pub struct GrantBuilder {
    issuer: PrincipalRef,
    subject: PrincipalRef,
    descriptor: SignatureDescriptor,
    permissions: Vec<Permission>,
    issued_at: Option<Timestamp>,
    validity: Option<ValidityWindow>,
    delegation_depth: DelegationDepth,
    revocation: RevocationRequirement,
    parent: Option<GrantId>,
}

impl GrantBuilder {
    pub fn new(
        issuer: PrincipalRef,
        subject: PrincipalRef,
        descriptor: SignatureDescriptor,
    ) -> Self {
        Self {
            issuer,
            subject,
            descriptor,
            permissions: Vec::new(),
            issued_at: None,
            validity: None,
            delegation_depth: DelegationDepth::new(0),
            revocation: RevocationRequirement::ExpiryOnly,
            parent: None,
        }
    }

    pub fn permission(mut self, permission: Permission) -> Self {
        self.permissions.push(permission);
        self
    }

    pub fn issued_at(mut self, issued_at: Timestamp) -> Self {
        self.issued_at = Some(issued_at);
        self
    }

    pub fn valid_between(mut self, from: Timestamp, until: Timestamp) -> Result<Self, AuthorError> {
        self.validity = Some(ValidityWindow::new(from, until)?);
        Ok(self)
    }

    pub fn delegation_depth(mut self, depth: DelegationDepth) -> Self {
        self.delegation_depth = depth;
        self
    }

    pub fn expiry_only(mut self) -> Self {
        self.revocation = RevocationRequirement::ExpiryOnly;
        self
    }

    pub fn status_proof_required(
        mut self,
        method: auths_proof_model::AuthorityStateMethod,
    ) -> Self {
        self.revocation = RevocationRequirement::StatusProofRequired { method };
        self
    }

    pub fn parent(mut self, parent: GrantId) -> Self {
        self.parent = Some(parent);
        self
    }

    pub fn build(self) -> Result<GrantDraft, AuthorError> {
        let issued_at = self.issued_at.ok_or(AuthorError::MissingIssueTime)?;
        let validity = self.validity.ok_or(AuthorError::MissingValidity)?;
        let payload = GrantPayload::new(
            self.issuer,
            self.subject,
            PermissionSet::new(self.permissions)?,
            issued_at,
            validity,
            self.delegation_depth,
            self.revocation,
            self.parent,
        )?;
        Ok(GrantDraft {
            payload,
            descriptor: self.descriptor,
        })
    }
}

#[derive(Clone, Debug)]
pub struct GrantDraft {
    payload: GrantPayload,
    descriptor: SignatureDescriptor,
}

impl GrantDraft {
    pub const fn payload(&self) -> &GrantPayload {
        &self.payload
    }

    pub const fn descriptor(&self) -> &SignatureDescriptor {
        &self.descriptor
    }

    pub fn signing_request(&self) -> GrantSigningRequest {
        GrantSigningRequest {
            payload: self.payload.clone(),
            descriptor: self.descriptor.clone(),
            bytes: grant_signing_bytes(&self.payload, &self.descriptor),
        }
    }

    pub fn attach(self, signature: Vec<u8>) -> Result<SignedGrant, AuthorError> {
        Ok(SignedGrant::new(
            self.payload,
            SignatureEnvelope::new(self.descriptor, SignatureBytes::new(signature)?),
        ))
    }
}

#[derive(Clone, Debug)]
pub struct GrantSigningRequest {
    payload: GrantPayload,
    descriptor: SignatureDescriptor,
    bytes: Vec<u8>,
}

impl GrantSigningRequest {
    pub const fn payload(&self) -> &GrantPayload {
        &self.payload
    }
    pub const fn descriptor(&self) -> &SignatureDescriptor {
        &self.descriptor
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug)]
pub struct ActionBuilder {
    actor: PrincipalRef,
    descriptor: SignatureDescriptor,
    permission: Permission,
    body_digest: BodyDigest,
    audience: Audience,
    issued_at: Timestamp,
    expires_at: Timestamp,
    challenge: Challenge,
}

impl ActionBuilder {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        actor: PrincipalRef,
        descriptor: SignatureDescriptor,
        permission: Permission,
        body_digest: BodyDigest,
        audience: Audience,
        issued_at: Timestamp,
        expires_at: Timestamp,
        challenge: Challenge,
    ) -> Self {
        Self {
            actor,
            descriptor,
            permission,
            body_digest,
            audience,
            issued_at,
            expires_at,
            challenge,
        }
    }

    pub fn build(self) -> Result<ActionDraft, AuthorError> {
        Ok(ActionDraft {
            payload: ActionStatement::new(
                self.actor,
                self.permission,
                self.body_digest,
                self.audience,
                self.issued_at,
                self.expires_at,
                self.challenge,
            )?,
            descriptor: self.descriptor,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ActionDraft {
    payload: ActionStatement,
    descriptor: SignatureDescriptor,
}

impl ActionDraft {
    pub const fn payload(&self) -> &ActionStatement {
        &self.payload
    }

    pub const fn descriptor(&self) -> &SignatureDescriptor {
        &self.descriptor
    }

    pub fn signing_request(&self) -> ActionSigningRequest {
        ActionSigningRequest {
            payload: self.payload.clone(),
            descriptor: self.descriptor.clone(),
            bytes: action_signing_bytes(&self.payload, &self.descriptor),
        }
    }

    pub fn attach(self, signature: Vec<u8>) -> Result<SignedAction, AuthorError> {
        Ok(SignedAction::new(
            self.payload,
            SignatureEnvelope::new(self.descriptor, SignatureBytes::new(signature)?),
        ))
    }
}

#[derive(Clone, Debug)]
pub struct ActionSigningRequest {
    payload: ActionStatement,
    descriptor: SignatureDescriptor,
    bytes: Vec<u8>,
}

impl ActionSigningRequest {
    pub const fn payload(&self) -> &ActionStatement {
        &self.payload
    }
    pub const fn descriptor(&self) -> &SignatureDescriptor {
        &self.descriptor
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub struct ProofBundleBuilder {
    action: SignedAction,
    grants: Vec<SignedGrant>,
    evidence: Vec<PrincipalEvidenceEntry>,
    bindings: Vec<PrincipalEvidenceBinding>,
}

impl ProofBundleBuilder {
    pub fn new(
        action: SignedAction,
        action_evidence: PrincipalEvidenceEntry,
    ) -> Result<Self, AuthorError> {
        let statement = StatementId::Action(action_id(&action));
        let evidence_id = action_evidence.id();
        Ok(Self {
            action,
            grants: Vec::new(),
            evidence: vec![action_evidence],
            bindings: vec![PrincipalEvidenceBinding::new(statement, evidence_id)],
        })
    }

    pub fn push_grant(
        mut self,
        grant: SignedGrant,
        evidence: PrincipalEvidenceEntry,
    ) -> Result<Self, AuthorError> {
        let statement = StatementId::Grant(grant_id(&grant));
        let evidence_id = evidence.id();
        self.grants.push(grant);
        self.evidence.push(evidence);
        self.bindings
            .push(PrincipalEvidenceBinding::new(statement, evidence_id));
        Ok(self)
    }

    pub fn build(mut self) -> Result<ProofBundle, AuthorError> {
        self.evidence.sort();
        self.evidence.dedup();
        if self
            .evidence
            .windows(2)
            .any(|pair| pair[0].id() == pair[1].id())
        {
            return Err(AuthorError::DuplicateEvidence);
        }
        self.bindings.sort();
        if self
            .bindings
            .windows(2)
            .any(|pair| pair[0].statement() == pair[1].statement())
        {
            return Err(AuthorError::DuplicateEvidenceBinding);
        }
        ProofBundle::new(
            self.action,
            self.grants,
            self.evidence,
            self.bindings,
            Vec::new(),
        )
        .map_err(AuthorError::from)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorError {
    Model(ModelError),
    MissingIssueTime,
    MissingValidity,
    DuplicateEvidence,
    DuplicateEvidenceBinding,
}

impl From<ModelError> for AuthorError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl fmt::Display for AuthorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model(error) => write!(formatter, "invalid protocol value: {error}"),
            Self::MissingIssueTime => formatter.write_str("grant issue time is required"),
            Self::MissingValidity => formatter.write_str("grant validity is required"),
            Self::DuplicateEvidence => formatter.write_str("duplicate evidence identifier"),
            Self::DuplicateEvidenceBinding => {
                formatter.write_str("duplicate statement-to-evidence binding")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AuthorError {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use auths_proof_codec::body_digest;
    use auths_proof_model::{
        AdapterId, AlgorithmId, CapabilityId, ResourceId, VerificationMethodRef,
    };

    fn descriptor(principal: &PrincipalRef) -> SignatureDescriptor {
        SignatureDescriptor::new(
            AdapterId::parse("raw-key-v1").expect("adapter"),
            VerificationMethodRef::parse(principal.as_str()).expect("method"),
            AlgorithmId::parse("ed25519").expect("algorithm"),
        )
    }

    #[test]
    fn signing_request_is_bound_to_descriptor() {
        let principal = PrincipalRef::parse("key:sha256:test").expect("principal");
        let permission = Permission::new(
            CapabilityId::parse("mcp.tools.call").expect("capability"),
            ResourceId::parse("mcp://files/read").expect("resource"),
        );
        let first = ActionBuilder::new(
            principal.clone(),
            descriptor(&principal),
            permission.clone(),
            body_digest(b"action"),
            Audience::parse("mcp://files").expect("audience"),
            Timestamp::new(10),
            Timestamp::new(20),
            Challenge::new([1; 32]),
        )
        .build()
        .expect("draft");

        let alternate = SignatureDescriptor::new(
            AdapterId::parse("raw-key-v1").expect("adapter"),
            VerificationMethodRef::parse(principal.as_str()).expect("method"),
            AlgorithmId::parse("p256-sha256").expect("algorithm"),
        );
        let second = ActionBuilder::new(
            principal,
            alternate,
            permission,
            body_digest(b"action"),
            Audience::parse("mcp://files").expect("audience"),
            Timestamp::new(10),
            Timestamp::new(20),
            Challenge::new([1; 32]),
        )
        .build()
        .expect("draft");

        assert_ne!(
            first.signing_request().bytes(),
            second.signing_request().bytes()
        );
        assert!(first.attach(vec![0; 64]).is_ok());
    }
}
