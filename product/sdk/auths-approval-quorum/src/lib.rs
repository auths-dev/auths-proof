//! Authoring of one exact action approved by any `K` of `N` named approvers.
//!
//! A [`QuorumProposal`] fixes the canonical action, the actor that submits
//! it, and an [`ApprovalRequirement`]: `required` of the listed approvers.
//! The actor signs one action envelope under a single-proof plan, with its
//! own grant chain. Each approver signs one [`ApprovalStatement`] bound to
//! the action's meaning, the relying party's audience and challenge, and the
//! requirement's identifier. Any `required` distinct approvers suffice; who
//! they are is decided by who answers, not fixed before the first signature.
//! The actor is never one of the approvers: self-approval never counts.
//!
//! The envelope and every statement carry the same validity window, from the
//! evaluation time for `validity_seconds` ([`DEFAULT_QUORUM_VALIDITY_SECONDS`]
//! when `None`, at most [`MAX_QUORUM_VALIDITY_SECONDS`]), cut to the actor's
//! terminal-grant expiry. Human approvers need hours, not the seconds a
//! single signer gets, so the quorum path has its own bounds; the window
//! arithmetic is core's `ActionValidityPolicy`. Approvals must be collected
//! and verified inside the window.
//!
//! This crate assembles bytes only. Whether the approvals authorize is decided
//! by the verifier against a trusted context that carries the requirement
//! ([`QuorumProposal::requirement`]) and one approver anchor per listed
//! approver. A proof never sets its own threshold.

#![forbid(unsafe_code)]

use auths_author::{ActionValidityPolicy, PlanBuilder, WorkflowAssemblyError};
use auths_codec::{
    CodecError, action_id, approval_digest, approval_requirement_id, body_digest,
    domain_commitment, grant_id,
};
use auths_model::{
    ActionEnvelope, ApprovalRequirement, ApprovalRequirementId, ApprovalStatement, Audience,
    AuthorizationPlan, BundleHeader, CanonicalAction, Challenge, ChannelBindingId, ControlBinding,
    CriticalExtensions, EvidenceId, EvidenceObject, GrantId, MAX_APPROVAL_EVIDENCE,
    MAX_APPROVERS_PER_REQUIREMENT, ModelError, PrincipalId, ProofBundle, ProofRef, SignedAction,
    SignedApproval, SignedGrant, StatementRef, VerifierLimits,
};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Validity, in seconds, of every approval when none is requested.
pub const DEFAULT_QUORUM_VALIDITY_SECONDS: u64 = 86_400;

/// Longest validity, in seconds, an approval quorum may carry.
pub const MAX_QUORUM_VALIDITY_SECONDS: u64 = 604_800;

/// Largest approver set one proposal accepts.
pub const MAX_APPROVERS: usize = MAX_APPROVERS_PER_REQUIREMENT;

/// Largest grant chain the actor may carry.
pub const MAX_ACTOR_GRANTS: usize = 16;

/// Largest evidence collection bound to one grant or action statement.
pub const MAX_STATEMENT_EVIDENCE: usize = 32;

/// Largest evidence collection one approval carries.
pub const MAX_APPROVER_EVIDENCE: usize = MAX_APPROVAL_EVIDENCE;

const ACTOR_REFERENCE_DOMAIN: &str = "auths.approval-quorum.actor/1";

/// Typed authoring failure. No variant carries secret material.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum QuorumError {
    /// The threshold is zero, exceeds the approver count, or the approver
    /// count is outside `1..=MAX_APPROVERS`.
    #[error("approval quorum threshold or approver count is invalid")]
    InvalidQuorum,
    /// The requested validity is outside `1..=MAX_QUORUM_VALIDITY_SECONDS`.
    #[error("approval quorum validity is outside bounds")]
    ActionValidity,
    /// The same principal appears twice in one approver set.
    #[error("approval quorum names the same approver twice")]
    DuplicateApprover,
    /// The actor is listed as an approver; its approval would never count.
    #[error("approval quorum names the actor as an approver")]
    SelfApproval,
    /// The signed action is not this proposal's envelope.
    #[error("signed action is not this proposal's envelope")]
    ActionMismatch,
    /// A signed approval does not equal this proposal's statement for its
    /// approver, or names an approver the proposal does not list.
    #[error("approval does not match this proposal")]
    UnknownApproval,
    /// Two approvals were supplied for the same approver.
    #[error("approval was supplied twice for the same approver")]
    DuplicateApproval,
    /// Fewer distinct listed approvers approved than the threshold.
    #[error("approval quorum has {approved} of {required} required approvals")]
    Incomplete {
        /// Distinct listed approvers that approved.
        approved: usize,
        /// The threshold.
        required: u16,
    },
    /// A grant chain, evidence set, or the resulting bundle exceeds bounds.
    #[error("approval quorum material exceeds collection bounds")]
    CollectionLimit,
    /// Core model validation rejected a constructed value.
    #[error("approval quorum model value is invalid: {0:?}")]
    Model(ModelError),
    /// Deterministic encoding or identifier derivation failed.
    #[error("approval quorum encoding failed: {0:?}")]
    Codec(CodecError),
}

impl From<ModelError> for QuorumError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl From<CodecError> for QuorumError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

impl From<WorkflowAssemblyError> for QuorumError {
    fn from(error: WorkflowAssemblyError) -> Self {
        match error {
            WorkflowAssemblyError::Model(error) => Self::Model(error),
            WorkflowAssemblyError::Codec(error) => Self::Codec(error),
            WorkflowAssemblyError::CollectionLimit => Self::CollectionLimit,
            WorkflowAssemblyError::ActionValidity
            | WorkflowAssemblyError::InvalidGrantIndex
            | WorkflowAssemblyError::ActionPlanMismatch => Self::ActionValidity,
        }
    }
}

/// The principal that submits the action, with the terminal grant its
/// authority descends from. `None` means the actor is itself a trust anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuorumActor {
    actor: PrincipalId,
    terminal_grant: Option<GrantId>,
    grant_expires_at: Option<u64>,
}

impl QuorumActor {
    /// Names the actor.
    ///
    /// # Errors
    ///
    /// Returns a codec error when the terminal grant identifier cannot be
    /// derived.
    pub fn new(
        actor: PrincipalId,
        terminal_grant: Option<&SignedGrant>,
    ) -> Result<Self, QuorumError> {
        Ok(Self {
            actor,
            terminal_grant: terminal_grant
                .map(|grant| grant_id(grant.statement()))
                .transpose()?,
            grant_expires_at: terminal_grant
                .map(|grant| grant.statement().validity().expires_at().get()),
        })
    }

    /// Returns the submitting principal.
    #[must_use]
    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }
}

/// The exact envelope, requirement, and approval statements for one
/// canonical action.
#[derive(Clone, Debug)]
pub struct QuorumProposal {
    canonical: CanonicalAction,
    requirement: ApprovalRequirement,
    requirement_id: ApprovalRequirementId,
    plan: AuthorizationPlan,
    envelope: ActionEnvelope,
    statements: Vec<ApprovalStatement>,
}

impl QuorumProposal {
    /// Builds the actor's unsigned envelope and one unsigned approval
    /// statement per approver for a `required`-of-N requirement. The proof
    /// reference is derived from the challenge and the actor, so one proposal
    /// is reproducible from its inputs. The validity window follows the
    /// module rule above.
    ///
    /// # Errors
    ///
    /// Returns [`QuorumError::InvalidQuorum`] for an impossible threshold or
    /// approver count, [`QuorumError::DuplicateApprover`] for a repeated
    /// principal, [`QuorumError::SelfApproval`] when the actor is listed,
    /// [`QuorumError::ActionValidity`] for a validity outside bounds, and
    /// model or codec errors from envelope construction.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        canonical: CanonicalAction,
        audience: &Audience,
        challenge: [u8; 32],
        evaluation_time: u64,
        validity_seconds: Option<u64>,
        required: u16,
        approvers: &[PrincipalId],
        actor: &QuorumActor,
    ) -> Result<Self, QuorumError> {
        if approvers.is_empty()
            || approvers.len() > MAX_APPROVERS
            || required == 0
            || usize::from(required) > approvers.len()
        {
            return Err(QuorumError::InvalidQuorum);
        }
        let distinct: BTreeSet<&PrincipalId> = approvers.iter().collect();
        if distinct.len() != approvers.len() {
            return Err(QuorumError::DuplicateApprover);
        }
        if distinct.contains(&actor.actor) {
            return Err(QuorumError::SelfApproval);
        }
        let requirement = ApprovalRequirement::new(approvers.to_vec(), required)?;
        let requirement_id = approval_requirement_id(&requirement)?;
        let validity = quorum_validity()?
            .window(evaluation_time, validity_seconds, actor.grant_expires_at)
            .map_err(QuorumError::from)?;
        let reference = actor_reference(&challenge, &actor.actor)?;
        let limits = VerifierLimits::default_deployment();
        let plan = PlanBuilder::new(&limits).proof(reference);
        let plan_identifier = auths_codec::plan_id(&plan)?;
        let digest = body_digest(canonical.body());
        let envelope = ActionEnvelope::new(
            canonical.profile().clone(),
            canonical.media_type().clone(),
            digest,
            canonical.permission().clone(),
            canonical.requested_budget().cloned(),
            audience.clone(),
            Challenge::new(challenge),
            validity,
            actor.actor.clone(),
            actor.terminal_grant,
            plan_identifier,
            ChannelBindingId::parse("none-v1")?,
            reference,
            Vec::new(),
            CriticalExtensions::empty(),
        );
        let statements = requirement
            .approvers()
            .iter()
            .map(|approver| {
                ApprovalStatement::new(
                    approver.clone(),
                    requirement_id,
                    canonical.media_type().clone(),
                    digest,
                    canonical.permission().clone(),
                    canonical.requested_budget().cloned(),
                    None,
                    audience.clone(),
                    Challenge::new(challenge),
                    validity,
                )
            })
            .collect();
        Ok(Self {
            canonical,
            requirement,
            requirement_id,
            plan,
            envelope,
            statements,
        })
    }

    /// Returns the canonical action the actor submits and approvers approve.
    #[must_use]
    pub const fn canonical(&self) -> &CanonicalAction {
        &self.canonical
    }

    /// Returns the approval requirement the verifier's trusted context must
    /// carry.
    #[must_use]
    pub const fn requirement(&self) -> &ApprovalRequirement {
        &self.requirement
    }

    /// Returns the requirement's identifier, which every statement binds.
    #[must_use]
    pub const fn requirement_id(&self) -> ApprovalRequirementId {
        self.requirement_id
    }

    /// Returns the threshold.
    #[must_use]
    pub const fn required(&self) -> u16 {
        self.requirement.threshold()
    }

    /// Returns the listed approvers in ascending order.
    #[must_use]
    pub fn approvers(&self) -> &[PrincipalId] {
        self.requirement.approvers()
    }

    /// Returns the actor.
    #[must_use]
    pub const fn actor(&self) -> &PrincipalId {
        self.envelope.actor()
    }

    /// Returns the actor's single-proof plan.
    #[must_use]
    pub const fn plan(&self) -> &AuthorizationPlan {
        &self.plan
    }

    /// Returns the unsigned envelope the actor signs.
    #[must_use]
    pub const fn envelope(&self) -> &ActionEnvelope {
        &self.envelope
    }

    /// Returns one unsigned statement per listed approver, in ascending
    /// approver order.
    #[must_use]
    pub fn statements(&self) -> &[ApprovalStatement] {
        &self.statements
    }

    /// Returns the statement `approver` signs, or `None` when the proposal
    /// does not list it.
    #[must_use]
    pub fn statement(&self, approver: &PrincipalId) -> Option<&ApprovalStatement> {
        self.slot(approver).map(|index| &self.statements[index])
    }

    /// Assembles the proof from the actor's signed action and the approvals
    /// of at least `required` distinct listed approvers.
    ///
    /// Signatures are not checked here; the verifier checks them. An approval
    /// is accepted only when its statement equals this proposal's statement
    /// for its approver. Every accepted approval is carried, ordered by
    /// approval digest, so a later signature failure of one approver does
    /// not by itself lose the quorum.
    ///
    /// # Errors
    ///
    /// Returns [`QuorumError::ActionMismatch`], [`QuorumError::UnknownApproval`],
    /// [`QuorumError::DuplicateApproval`], [`QuorumError::Incomplete`],
    /// [`QuorumError::CollectionLimit`], or a model or codec error from
    /// bundle construction.
    pub fn assemble(
        &self,
        action: &QuorumAction,
        approvals: &[SignedApproval],
    ) -> Result<ProofBundle, QuorumError> {
        if action.action.envelope() != &self.envelope {
            return Err(QuorumError::ActionMismatch);
        }
        let mut filled = vec![false; self.statements.len()];
        for approval in approvals {
            let slot = self
                .slot(approval.statement().approver())
                .filter(|slot| &self.statements[*slot] == approval.statement())
                .ok_or(QuorumError::UnknownApproval)?;
            if std::mem::replace(&mut filled[slot], true) {
                return Err(QuorumError::DuplicateApproval);
            }
            if bad_approval_evidence(approval.evidence()) {
                return Err(QuorumError::CollectionLimit);
            }
        }
        let approved = filled.iter().filter(|value| **value).count();
        if approved < usize::from(self.required()) {
            return Err(QuorumError::Incomplete {
                approved,
                required: self.required(),
            });
        }
        let mut ordered = approvals
            .iter()
            .map(|approval| Ok((approval_digest(approval)?, approval.clone())))
            .collect::<Result<Vec<_>, CodecError>>()?;
        ordered.sort_by_key(|(digest, _)| *digest);

        let mut grants: Vec<SignedGrant> = Vec::new();
        let mut grant_ids: BTreeSet<GrantId> = BTreeSet::new();
        let mut evidence: BTreeMap<EvidenceId, EvidenceObject> = BTreeMap::new();
        let mut bound: BTreeMap<StatementRef, BTreeSet<EvidenceId>> = BTreeMap::new();
        for (grant, grant_evidence) in &action.grants {
            let id = grant_id(grant.statement())?;
            if grant_ids.insert(id) {
                grants.push(grant.clone());
            }
            bind(
                &mut evidence,
                &mut bound,
                StatementRef::Grant(id),
                grant_evidence,
            )?;
        }
        bind(
            &mut evidence,
            &mut bound,
            StatementRef::Action(action_id(action.action.envelope())?),
            &action.action_evidence,
        )?;
        grants.sort_by_cached_key(|grant| grant_id(grant.statement()).ok());
        let bindings = bound
            .into_iter()
            .map(|(statement, ids)| ControlBinding::new(statement, ids.into_iter().collect()))
            .collect::<Result<Vec<_>, _>>()?;
        ProofBundle::new(
            BundleHeader::v1(),
            grants,
            vec![action.action.clone()],
            self.plan.clone(),
            evidence.into_values().collect(),
            bindings,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(self.canonical.body().to_vec()),
        )
        .and_then(|bundle| {
            bundle.with_approvals(ordered.into_iter().map(|(_, approval)| approval).collect())
        })
        .map_err(|error| match error {
            ModelError::CollectionLimitExceeded => QuorumError::CollectionLimit,
            other => QuorumError::Model(other),
        })
    }

    fn slot(&self, approver: &PrincipalId) -> Option<usize> {
        self.requirement.approvers().binary_search(approver).ok()
    }
}

/// The actor's signed envelope with its public control material.
#[derive(Clone, Debug)]
pub struct QuorumAction {
    action: SignedAction,
    grants: Vec<(SignedGrant, Vec<EvidenceObject>)>,
    action_evidence: Vec<EvidenceObject>,
}

impl QuorumAction {
    /// Pairs the actor's signed envelope with its grant chain (root first)
    /// and the public evidence controlling each grant and the action.
    ///
    /// # Errors
    ///
    /// Returns [`QuorumError::CollectionLimit`] for an oversized chain or an
    /// empty or oversized evidence collection.
    pub fn new(
        action: SignedAction,
        grants: Vec<(SignedGrant, Vec<EvidenceObject>)>,
        action_evidence: Vec<EvidenceObject>,
    ) -> Result<Self, QuorumError> {
        if grants.len() > MAX_ACTOR_GRANTS
            || grants
                .iter()
                .any(|(_, evidence)| bad_evidence_count(evidence))
            || bad_evidence_count(&action_evidence)
        {
            return Err(QuorumError::CollectionLimit);
        }
        Ok(Self {
            action,
            grants,
            action_evidence,
        })
    }

    /// Returns the signed envelope.
    #[must_use]
    pub const fn action(&self) -> &SignedAction {
        &self.action
    }
}

fn quorum_validity() -> Result<ActionValidityPolicy, QuorumError> {
    ActionValidityPolicy::new(DEFAULT_QUORUM_VALIDITY_SECONDS, MAX_QUORUM_VALIDITY_SECONDS)
        .map_err(QuorumError::from)
}

fn actor_reference(challenge: &[u8; 32], actor: &PrincipalId) -> Result<ProofRef, QuorumError> {
    let mut canonical = Vec::with_capacity(32 + actor.as_str().len());
    canonical.extend_from_slice(challenge);
    canonical.extend_from_slice(actor.as_str().as_bytes());
    Ok(ProofRef::new(
        *domain_commitment(ACTOR_REFERENCE_DOMAIN, &canonical)?.as_bytes(),
    ))
}

fn bad_evidence_count(evidence: &[EvidenceObject]) -> bool {
    evidence.is_empty() || evidence.len() > MAX_STATEMENT_EVIDENCE
}

pub(crate) fn bad_approval_evidence(evidence: &[EvidenceObject]) -> bool {
    evidence.is_empty() || evidence.len() > MAX_APPROVER_EVIDENCE
}

fn bind(
    evidence: &mut BTreeMap<EvidenceId, EvidenceObject>,
    bound: &mut BTreeMap<StatementRef, BTreeSet<EvidenceId>>,
    statement: StatementRef,
    objects: &[EvidenceObject],
) -> Result<(), QuorumError> {
    let ids = bound.entry(statement).or_default();
    for object in objects {
        if let Some(existing) = evidence.get(&object.id()) {
            if existing != object {
                return Err(QuorumError::Model(ModelError::InvalidEvidenceBinding));
            }
        } else {
            evidence.insert(object.id(), object.clone());
        }
        ids.insert(object.id());
    }
    if ids.len() > MAX_STATEMENT_EVIDENCE {
        return Err(QuorumError::CollectionLimit);
    }
    Ok(())
}

pub mod remote;

pub use remote::{
    ApprovalCode, ApprovalRequest, ApprovalResponse, ApprovalWindow, ApproverStatus, Collection,
    PendingApproval, PendingDecline, RegisteredProfile, ResponseBody, ReviewProfile,
    ReviewedRequest, SignedDecline, collect, decode_request, decode_response, open_request,
    requests,
};

#[cfg(test)]
mod tests;
