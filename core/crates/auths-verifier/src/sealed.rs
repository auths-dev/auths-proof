//! The verifier-owned capability carrier and its lossless authority projection.
//!
//! These types have no public constructors. The complete verifier earns the
//! authority; this module moves its exact fields into the downstream capability.

use alloc::{boxed::Box, vec::Vec};
use auths_model::{
    ActionId, ApprovalSatisfaction, AssuranceSatisfaction, CanonicalAction, ContextDigest,
    Digest, ObservationSatisfaction, ParticipantAssurance, PlanId, PortableVerificationResult,
    ProofRef, Timestamp,
};

/// Authority established by an authorizing plan, covering every branch that
/// authorized, whether or not the plan needed that branch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAuthority {
    pub(super) canonical_action: CanonicalAction,
    pub(super) proof_digest: Digest,
    pub(super) context_digest: ContextDigest,
    pub(super) plan_id: PlanId,
    pub(super) action_ids: Vec<ActionId>,
    pub(super) authorized_branches: Vec<ProofRef>,
    pub(super) assurance: Vec<ParticipantAssurance>,
    pub(super) assurance_satisfactions: Vec<AssuranceSatisfaction>,
    pub(super) observation_satisfactions: Vec<ObservationSatisfaction>,
    pub(super) approval_satisfactions: Vec<ApprovalSatisfaction>,
    pub(super) authority_not_after: Timestamp,
    pub(super) work_units: u64,
}

/// Sealed data consumed by downstream profile decoders.
///
/// Fields have no public constructor. Applications can obtain this value only
/// from a complete verification: [`crate::verify`], [`crate::verify_explained`], or
/// [`crate::verify_v1_sealed`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAction {
    pub(super) canonical_action: CanonicalAction,
    pub(super) proof_digest: Digest,
    pub(super) context_digest: ContextDigest,
    pub(super) plan_id: PlanId,
    pub(super) action_ids: Vec<ActionId>,
    pub(super) authorized_branches: Vec<ProofRef>,
    pub(super) assurance: Vec<ParticipantAssurance>,
    pub(super) assurance_satisfactions: Vec<AssuranceSatisfaction>,
    pub(super) observation_satisfactions: Vec<ObservationSatisfaction>,
    pub(super) approval_satisfactions: Vec<ApprovalSatisfaction>,
    pub(super) authority_not_after: Timestamp,
    pub(super) work_units: u64,
}

/// Portable decision data paired with the sealed action from the same run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedVerificationResult {
    pub(super) portable: PortableVerificationResult,
    pub(super) cbor: Vec<u8>,
    pub(super) action: Option<Box<VerifiedAction>>,
}

impl SealedVerificationResult {
    /// Returns the language-neutral decision data.
    #[must_use]
    pub const fn portable(&self) -> &PortableVerificationResult {
        &self.portable
    }

    /// Returns the canonical portable decision bytes.
    #[must_use]
    pub fn cbor(&self) -> &[u8] {
        &self.cbor
    }

    /// Returns the sealed action only when the decision is authorized.
    #[must_use]
    pub fn action(&self) -> Option<&VerifiedAction> {
        self.action.as_deref()
    }

    /// Consumes the result into decision data, canonical bytes, and capability.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        PortableVerificationResult,
        Vec<u8>,
        Option<Box<VerifiedAction>>,
    ) {
        (self.portable, self.cbor, self.action)
    }
}

impl VerifiedAction {
    /// Inclusive last time allowed by the temporal evidence selected in this
    /// verification: successful anchors, grants/actions, counted approvals,
    /// selected observations/status, and selected assurance freshness.
    /// It does not assert that the host clock is correct or that no newer
    /// revocation exists. Downstream entry must also reject clock rollback
    /// and impose its own shorter operational deadlines.
    #[must_use]
    pub const fn authority_not_after(&self) -> Timestamp {
        self.authority_not_after
    }

    /// Returns exact profile-canonical bytes and derived meaning.
    #[must_use]
    pub const fn canonical_action(&self) -> &CanonicalAction {
        &self.canonical_action
    }

    /// Returns the canonical proof digest.
    #[must_use]
    pub const fn proof_digest(&self) -> Digest {
        self.proof_digest
    }

    /// Returns the public trusted-context digest.
    #[must_use]
    pub const fn context_digest(&self) -> ContextDigest {
        self.context_digest
    }

    /// Returns the authorization-plan identifier.
    #[must_use]
    pub const fn plan_id(&self) -> PlanId {
        self.plan_id
    }

    /// Returns action identifiers for every authorized branch in canonical
    /// order.
    #[must_use]
    pub fn action_ids(&self) -> &[ActionId] {
        &self.action_ids
    }

    /// Returns the proof reference of every authorized branch, whether or not
    /// the plan needed it, in ascending order.
    #[must_use]
    pub fn authorized_branches(&self) -> &[ProofRef] {
        &self.authorized_branches
    }

    /// Returns role-indexed assurance reports for every authorized branch.
    #[must_use]
    pub fn assurance(&self) -> &[ParticipantAssurance] {
        &self.assurance
    }

    /// Returns canonical evidence selected for each assurance requirement.
    #[must_use]
    pub fn assurance_satisfactions(&self) -> &[AssuranceSatisfaction] {
        &self.assurance_satisfactions
    }

    /// Returns, for each observation requirement in every authorized branch,
    /// the signed observation attachment that satisfied it.
    #[must_use]
    pub fn observation_satisfactions(&self) -> &[ObservationSatisfaction] {
        &self.observation_satisfactions
    }

    /// Returns, for each approval requirement of the trusted context and of
    /// every authorized branch's chain, the approvals that counted: one per
    /// counted approver.
    #[must_use]
    pub fn approval_satisfactions(&self) -> &[ApprovalSatisfaction] {
        &self.approval_satisfactions
    }

    /// Returns deterministic proof-kernel work charged.
    #[must_use]
    pub const fn work_units(&self) -> u64 {
        self.work_units
    }
}


/// Seals a verified authority result as a downstream-consumable action.
#[must_use]
pub(crate) fn bind_verified_action(authority: VerifiedAuthority) -> VerifiedAction {
    VerifiedAction {
        canonical_action: authority.canonical_action,
        proof_digest: authority.proof_digest,
        context_digest: authority.context_digest,
        plan_id: authority.plan_id,
        action_ids: authority.action_ids,
        authorized_branches: authority.authorized_branches,
        assurance: authority.assurance,
        assurance_satisfactions: authority.assurance_satisfactions,
        observation_satisfactions: authority.observation_satisfactions,
        approval_satisfactions: authority.approval_satisfactions,
        authority_not_after: authority.authority_not_after,
        work_units: authority.work_units,
    }
}

