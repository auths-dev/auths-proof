//! Authoring of one exact action approved by a threshold of distinct approvers.
//!
//! A [`QuorumProposal`] fixes the canonical action, the approver set, and a
//! core `k_of_n` [`AuthorizationPlan`] over one proof leaf per approver. Every
//! approver signs its own envelope; each envelope commits to the whole plan,
//! so the approver set is fixed before the first signature and every listed
//! approver must sign before the bundle can be assembled. Replacing an
//! approver is a new proposal.
//!
//! Every envelope carries the same validity window, from the evaluation time
//! for `validity_seconds` ([`DEFAULT_QUORUM_VALIDITY_SECONDS`] when `None`, at
//! most [`MAX_QUORUM_VALIDITY_SECONDS`]), cut to the earliest terminal-grant
//! expiry among the approvers. Human approvers need hours, not the seconds a
//! single signer gets, so the quorum path has its own bounds; the window
//! arithmetic is core's `ActionValidityPolicy`. All approvals must be
//! collected and verified inside the window.
//!
//! This crate assembles bytes only. Whether the approvals authorize is decided
//! by the verifier against a trusted context whose composition requirement
//! names the threshold (see [`quorum_requirement`]) and whose trust anchors
//! name the members. A proof-carried plan alone never sets the threshold.

#![forbid(unsafe_code)]

use auths_author::{ActionValidityPolicy, PlanBuilder, PlanningError, WorkflowAssemblyError};
use auths_codec::{CodecError, action_id, body_digest, domain_commitment, grant_id, plan_id};
use auths_model::{
    ActionEnvelope, Audience, AuthorizationPlan, BundleHeader, CanonicalAction, Challenge,
    ChannelBindingId, CompositionRequirement, ControlBinding, CriticalExtensions, EvidenceId,
    EvidenceObject, GrantId, ModelError, PrincipalId, ProofBundle, ProofRef, SignedAction,
    SignedGrant, StatementRef, VerifierLimits,
};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Validity, in seconds, of every approval when none is requested.
pub const DEFAULT_QUORUM_VALIDITY_SECONDS: u64 = 86_400;

/// Longest validity, in seconds, an approval quorum may carry.
pub const MAX_QUORUM_VALIDITY_SECONDS: u64 = 604_800;

/// Largest approver set one proposal accepts.
pub const MAX_APPROVERS: usize = 16;

/// Largest grant chain one approval may carry.
pub const MAX_APPROVAL_GRANTS: usize = 16;

/// Largest evidence collection bound to one statement.
pub const MAX_STATEMENT_EVIDENCE: usize = 32;

const MEMBER_REFERENCE_DOMAIN: &str = "auths.approval-quorum.member/1";

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
    /// A signed approval does not equal any envelope of this proposal.
    #[error("approval does not match any envelope of this proposal")]
    UnknownApproval,
    /// Two approvals were supplied for the same approver.
    #[error("approval was supplied twice for the same approver")]
    DuplicateApproval,
    /// At least one listed approver has not signed.
    #[error("approval quorum has {signed} of {approvers} approver signatures")]
    Incomplete {
        /// Signatures supplied.
        signed: usize,
        /// Approvers listed in the proposal.
        approvers: usize,
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

impl From<PlanningError> for QuorumError {
    fn from(error: PlanningError) -> Self {
        match error {
            PlanningError::Codec(error) => Self::Codec(error),
            PlanningError::InvalidPlan | PlanningError::Expanded(_) => Self::InvalidQuorum,
        }
    }
}

/// One member asked to approve, with the terminal grant its authority
/// descends from. `None` means the member is itself a trust anchor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuorumApprover {
    actor: PrincipalId,
    terminal_grant: Option<GrantId>,
    grant_expires_at: Option<u64>,
}

impl QuorumApprover {
    /// Names one approver.
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

    /// Returns the approving principal.
    #[must_use]
    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }
}

/// Exact envelopes and threshold plan for one canonical action.
#[derive(Clone, Debug)]
pub struct QuorumProposal {
    canonical: CanonicalAction,
    required: u16,
    plan: AuthorizationPlan,
    envelopes: Vec<ActionEnvelope>,
}

impl QuorumProposal {
    /// Builds one unsigned envelope per approver under a `required`-of-N
    /// plan. Proof references are derived from the challenge and the
    /// approver, so one proposal is reproducible from its inputs. The
    /// validity window follows the module rule above.
    ///
    /// # Errors
    ///
    /// Returns [`QuorumError::InvalidQuorum`] for an impossible threshold or
    /// approver count, [`QuorumError::ActionValidity`] for a validity outside
    /// bounds, [`QuorumError::DuplicateApprover`] for a repeated
    /// principal, and model or codec errors from plan and envelope
    /// construction.
    pub fn new(
        canonical: CanonicalAction,
        audience: &Audience,
        challenge: [u8; 32],
        evaluation_time: u64,
        validity_seconds: Option<u64>,
        required: u16,
        approvers: &[QuorumApprover],
    ) -> Result<Self, QuorumError> {
        if approvers.is_empty()
            || approvers.len() > MAX_APPROVERS
            || required == 0
            || usize::from(required) > approvers.len()
        {
            return Err(QuorumError::InvalidQuorum);
        }
        let distinct: BTreeSet<&str> = approvers
            .iter()
            .map(|approver| approver.actor.as_str())
            .collect();
        if distinct.len() != approvers.len() {
            return Err(QuorumError::DuplicateApprover);
        }
        let validity = quorum_validity()?
            .window(
                evaluation_time,
                validity_seconds,
                approvers
                    .iter()
                    .filter_map(|approver| approver.grant_expires_at),
            )
            .map_err(QuorumError::from)?;
        let references = approvers
            .iter()
            .map(|approver| member_reference(&challenge, &approver.actor))
            .collect::<Result<Vec<_>, _>>()?;
        let limits = VerifierLimits::default_deployment();
        let builder = PlanBuilder::new(&limits);
        let plan = builder.threshold(
            required,
            references
                .iter()
                .copied()
                .map(|reference| builder.proof(reference))
                .collect(),
        )?;
        let plan_identifier = plan_id(&plan)?;
        let channel = ChannelBindingId::parse("none-v1")?;
        let envelopes = approvers
            .iter()
            .zip(references)
            .map(|(approver, reference)| {
                ActionEnvelope::new(
                    canonical.profile().clone(),
                    canonical.media_type().clone(),
                    body_digest(canonical.body()),
                    canonical.permission().clone(),
                    canonical.requested_budget().cloned(),
                    audience.clone(),
                    Challenge::new(challenge),
                    validity,
                    approver.actor.clone(),
                    approver.terminal_grant,
                    plan_identifier,
                    channel.clone(),
                    reference,
                    Vec::new(),
                    CriticalExtensions::empty(),
                )
            })
            .collect();
        Ok(Self {
            canonical,
            required,
            plan,
            envelopes,
        })
    }

    /// Returns the canonical action every approver signs.
    #[must_use]
    pub const fn canonical(&self) -> &CanonicalAction {
        &self.canonical
    }

    /// Returns the plan threshold.
    #[must_use]
    pub const fn required(&self) -> u16 {
        self.required
    }

    /// Returns the core threshold plan.
    #[must_use]
    pub const fn plan(&self) -> &AuthorizationPlan {
        &self.plan
    }

    /// Returns one unsigned envelope per approver, in approver order.
    #[must_use]
    pub fn envelopes(&self) -> &[ActionEnvelope] {
        &self.envelopes
    }

    /// Assembles the proof from exactly one approval per listed approver.
    ///
    /// Signatures are not checked here; the verifier checks them. An approval
    /// is accepted only when its envelope equals one of this proposal's
    /// envelopes byte for byte.
    ///
    /// # Errors
    ///
    /// Returns [`QuorumError::UnknownApproval`], [`QuorumError::DuplicateApproval`],
    /// [`QuorumError::Incomplete`], [`QuorumError::CollectionLimit`], or a
    /// model or codec error from bundle construction.
    pub fn assemble(&self, approvals: &[QuorumApproval]) -> Result<ProofBundle, QuorumError> {
        let mut filled = vec![false; self.envelopes.len()];
        let mut grants: Vec<SignedGrant> = Vec::new();
        let mut grant_ids: BTreeSet<GrantId> = BTreeSet::new();
        let mut evidence: BTreeMap<EvidenceId, EvidenceObject> = BTreeMap::new();
        let mut bound: BTreeMap<StatementRef, BTreeSet<EvidenceId>> = BTreeMap::new();
        let mut actions = Vec::with_capacity(approvals.len());
        for approval in approvals {
            let slot = self
                .envelopes
                .iter()
                .position(|envelope| envelope == approval.action.envelope())
                .ok_or(QuorumError::UnknownApproval)?;
            if std::mem::replace(&mut filled[slot], true) {
                return Err(QuorumError::DuplicateApproval);
            }
            for (grant, grant_evidence) in &approval.grants {
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
            let statement = StatementRef::Action(action_id(approval.action.envelope())?);
            bind(
                &mut evidence,
                &mut bound,
                statement,
                &approval.action_evidence,
            )?;
            actions.push(approval.action.clone());
        }
        let signed = filled.iter().filter(|value| **value).count();
        if signed != self.envelopes.len() {
            return Err(QuorumError::Incomplete {
                signed,
                approvers: self.envelopes.len(),
            });
        }
        grants.sort_by_cached_key(|grant| grant_id(grant.statement()).ok());
        let bindings = bound
            .into_iter()
            .map(|(statement, ids)| ControlBinding::new(statement, ids.into_iter().collect()))
            .collect::<Result<Vec<_>, _>>()?;
        ProofBundle::new(
            BundleHeader::v1(),
            grants,
            actions,
            self.plan.clone(),
            evidence.into_values().collect(),
            bindings,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(self.canonical.body().to_vec()),
        )
        .map_err(|error| match error {
            ModelError::CollectionLimitExceeded => QuorumError::CollectionLimit,
            other => QuorumError::Model(other),
        })
    }
}

/// One approver's signed envelope with its public control material.
#[derive(Clone, Debug)]
pub struct QuorumApproval {
    action: SignedAction,
    grants: Vec<(SignedGrant, Vec<EvidenceObject>)>,
    action_evidence: Vec<EvidenceObject>,
}

impl QuorumApproval {
    /// Pairs a signed envelope with the approver's grant chain (root first)
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
        if grants.len() > MAX_APPROVAL_GRANTS
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
}

/// The verifier-trusted composition an operator installs for a
/// `required`-of-N quorum: `required` authorized branches from `required`
/// distinct actors. Two approvals by one principal count once.
///
/// # Errors
///
/// Returns a model error when the minimums are zero or out of protocol range.
pub fn quorum_requirement(
    required: u16,
    minimum_distinct_roots: u16,
) -> Result<CompositionRequirement, QuorumError> {
    Ok(CompositionRequirement::new(
        None,
        required,
        required,
        minimum_distinct_roots,
    )?)
}

fn quorum_validity() -> Result<ActionValidityPolicy, QuorumError> {
    ActionValidityPolicy::new(DEFAULT_QUORUM_VALIDITY_SECONDS, MAX_QUORUM_VALIDITY_SECONDS)
        .map_err(QuorumError::from)
}

pub(crate) fn member_reference(
    challenge: &[u8; 32],
    actor: &PrincipalId,
) -> Result<ProofRef, QuorumError> {
    let mut canonical = Vec::with_capacity(32 + actor.as_str().len());
    canonical.extend_from_slice(challenge);
    canonical.extend_from_slice(actor.as_str().as_bytes());
    Ok(ProofRef::new(
        *domain_commitment(MEMBER_REFERENCE_DOMAIN, &canonical)?.as_bytes(),
    ))
}

fn bad_evidence_count(evidence: &[EvidenceObject]) -> bool {
    evidence.is_empty() || evidence.len() > MAX_STATEMENT_EVIDENCE
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
