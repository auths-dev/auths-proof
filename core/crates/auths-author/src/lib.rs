//! Pure, keyless target V1 authoring requests and authority diffs.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use auths_authority::{AuthorScopeDecision, evaluate_author_scope_view};
use auths_codec::{
    CodecError, action_id, action_signing_preimage, body_digest, domain_commitment,
    encode_canonical_action, evidence_id, grant_id, grant_signing_preimage, grant_status_id,
    grant_status_signing_preimage, plan_id, principal_status_id, principal_status_signing_preimage,
    transaction_binding,
};
use auths_model::{
    ActionConstraint, ActionEnvelope, ActionId, AssurancePolicyId, Audience, AudienceSet,
    AuthorizationPlan, BudgetCeiling, BundleHeader, CanonicalAction, Challenge, ChannelBindingId,
    CompositionRequirement, ControlBinding, CriticalExtensions, Digest, EvidenceId, EvidenceObject,
    EvidenceTypeId, GrantId, GrantStatement, GrantStatusId, GrantStatusStatement, LimitKind,
    MediaType, ModelError, PermissionSet, PrincipalId, PrincipalStatusId, PrincipalStatusStatement,
    ProfileRef, ProofBundle, ProofRef, ResourceId, ScopeAuthorityView, SignatureBytes,
    SignatureDescriptor, SignatureEnvelope, SignedAction, SignedGrant, SignedGrantStatus,
    SignedPrincipalStatus, StatementRef, StatusPolicy, Timestamp, ValidityWindow, VerifierContext,
    VerifierLimits, grant_authority_view, scope_authority_view,
};
use core::fmt;

pub use auths_authority::AuthorityDimension;

/// Profile-owned action meaning paired with its verifier envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedAction {
    canonical: CanonicalAction,
    envelope: ActionEnvelope,
}

impl PreparedAction {
    /// Returns the canonical profile action.
    #[must_use]
    pub const fn canonical(&self) -> &CanonicalAction {
        &self.canonical
    }

    /// Returns the exact unsigned action envelope.
    #[must_use]
    pub const fn envelope(&self) -> &ActionEnvelope {
        &self.envelope
    }

    /// Consumes the preparation into its canonical action and envelope.
    #[must_use]
    pub fn into_parts(self) -> (CanonicalAction, ActionEnvelope) {
        (self.canonical, self.envelope)
    }
}

/// Constructs the shared target V1 envelope for a profile-owned action.
///
/// # Errors
///
/// Returns a typed error if any deterministic identifier cannot be derived.
pub fn prepare_profile_action(
    canonical: CanonicalAction,
    audience: Audience,
    actor: PrincipalId,
    terminal_grant: &SignedGrant,
    challenge: [u8; 32],
    evaluation_time: u64,
) -> Result<PreparedAction, WorkflowAssemblyError> {
    let proof_ref = ProofRef::new(challenge);
    let plan = AuthorizationPlan::proof(proof_ref);
    let envelope = ActionEnvelope::new(
        canonical.profile().clone(),
        canonical.media_type().clone(),
        body_digest(canonical.body()),
        canonical.permission().clone(),
        canonical.requested_budget().cloned(),
        audience,
        Challenge::new(challenge),
        ValidityWindow::new(
            Timestamp::new(evaluation_time),
            Timestamp::new(evaluation_time),
        )?,
        actor,
        Some(grant_id(terminal_grant.statement())?),
        plan_id(&plan)?,
        ChannelBindingId::parse("none-v1")?,
        proof_ref,
        Vec::new(),
        CriticalExtensions::empty(),
    );
    Ok(PreparedAction {
        canonical,
        envelope,
    })
}

#[derive(Clone, Debug)]
struct GrantProofMaterial {
    grant: SignedGrant,
    evidence: Vec<EvidenceObject>,
}

/// Native-owned result of exact proof and request-context assembly.
#[derive(Clone, Debug)]
pub struct WorkflowAuthorizationArtifacts {
    proof: ProofBundle,
    context: VerifierContext,
}

impl WorkflowAuthorizationArtifacts {
    /// Returns the assembled proof bundle.
    #[must_use]
    pub const fn proof(&self) -> &ProofBundle {
        &self.proof
    }

    /// Returns the request-bound verifier context.
    #[must_use]
    pub const fn context(&self) -> &VerifierContext {
        &self.context
    }
}

/// Bounded collector for signed grants and their public control evidence.
#[derive(Clone, Debug)]
pub struct WorkflowProofBuilder {
    grants: Vec<GrantProofMaterial>,
    action_evidence: Vec<EvidenceObject>,
    limits: VerifierLimits,
}

impl WorkflowProofBuilder {
    /// Creates a collector using the deployment verifier limits.
    #[must_use]
    pub fn new() -> Self {
        Self {
            grants: Vec::new(),
            action_evidence: Vec::new(),
            limits: VerifierLimits::default_deployment(),
        }
    }

    /// Appends one signed grant and returns its evidence-binding index.
    ///
    /// # Errors
    ///
    /// Returns a collection-limit error before retaining excessive material.
    pub fn push_grant(&mut self, grant: SignedGrant) -> Result<usize, WorkflowAssemblyError> {
        if self.grants.len() >= self.limits.get(LimitKind::Grants) {
            return Err(WorkflowAssemblyError::CollectionLimit);
        }
        let index = self.grants.len();
        self.grants.push(GrantProofMaterial {
            grant,
            evidence: Vec::new(),
        });
        Ok(index)
    }

    /// Binds one addressed evidence object to a grant.
    ///
    /// # Errors
    ///
    /// Returns an invalid-index or collection-limit error.
    pub fn bind_grant_evidence(
        &mut self,
        index: usize,
        evidence: EvidenceObject,
    ) -> Result<(), WorkflowAssemblyError> {
        let material = self
            .grants
            .get_mut(index)
            .ok_or(WorkflowAssemblyError::InvalidGrantIndex)?;
        if material.evidence.len() >= self.limits.get(LimitKind::EvidenceObjects) {
            return Err(WorkflowAssemblyError::CollectionLimit);
        }
        material.evidence.push(evidence);
        Ok(())
    }

    /// Binds one addressed evidence object to the signed action.
    ///
    /// # Errors
    ///
    /// Returns a collection-limit error before retaining excessive material.
    pub fn bind_action_evidence(
        &mut self,
        evidence: EvidenceObject,
    ) -> Result<(), WorkflowAssemblyError> {
        if self.action_evidence.len() >= self.limits.get(LimitKind::EvidenceObjects) {
            return Err(WorkflowAssemblyError::CollectionLimit);
        }
        self.action_evidence.push(evidence);
        Ok(())
    }

    /// Assembles the proof and exact request-bound verifier context.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for inconsistent bindings or invalid model data.
    pub fn finish(
        &self,
        action: &SignedAction,
        canonical: &CanonicalAction,
        context: &VerifierContext,
    ) -> Result<WorkflowAuthorizationArtifacts, WorkflowAssemblyError> {
        let plan = AuthorizationPlan::proof(action.envelope().proof_ref());
        let exact_plan = plan_id(&plan)?;
        if exact_plan != action.envelope().authorization_plan() {
            return Err(WorkflowAssemblyError::ActionPlanMismatch);
        }
        let mut evidence = Vec::new();
        let mut bindings = Vec::new();
        for material in &self.grants {
            let ids = unique_evidence(&mut evidence, &material.evidence);
            if !ids.is_empty() {
                bindings.push(ControlBinding::new(
                    StatementRef::Grant(grant_id(material.grant.statement())?),
                    ids,
                )?);
            }
        }
        let action_ids = unique_evidence(&mut evidence, &self.action_evidence);
        if !action_ids.is_empty() {
            bindings.push(ControlBinding::new(
                StatementRef::Action(action_id(action.envelope())?),
                action_ids,
            )?);
        }
        if evidence.len() > self.limits.get(LimitKind::EvidenceObjects) {
            return Err(WorkflowAssemblyError::CollectionLimit);
        }
        let proof = ProofBundle::new(
            BundleHeader::v1(),
            self.grants.iter().map(|item| item.grant.clone()).collect(),
            vec![action.clone()],
            plan,
            evidence,
            bindings,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(canonical.body().to_vec()),
        )?;
        let context = context
            .for_request(
                action.envelope().audience().clone(),
                action.envelope().challenge(),
                action.envelope().validity().not_before(),
            )?
            .with_composition(CompositionRequirement::exact(exact_plan))?;
        Ok(WorkflowAuthorizationArtifacts { proof, context })
    }
}

impl Default for WorkflowProofBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Constructs a content-addressed evidence object from typed public bytes.
///
/// # Errors
///
/// Returns a typed failure for invalid identifiers, media, or evidence bytes.
pub fn address_evidence(
    evidence_type: EvidenceTypeId,
    media_type: MediaType,
    bytes: Vec<u8>,
) -> Result<EvidenceObject, WorkflowAssemblyError> {
    let unaddressed = EvidenceObject::new(
        EvidenceId::new([0; 32]),
        evidence_type.clone(),
        media_type.clone(),
        bytes.clone(),
    )?;
    Ok(EvidenceObject::new(
        evidence_id(&unaddressed)?,
        evidence_type,
        media_type,
        bytes,
    )?)
}

fn unique_evidence(all: &mut Vec<EvidenceObject>, additions: &[EvidenceObject]) -> Vec<EvidenceId> {
    let mut ids = Vec::with_capacity(additions.len());
    for object in additions {
        if !all.iter().any(|candidate| candidate.id() == object.id()) {
            all.push(object.clone());
        }
        if !ids.contains(&object.id()) {
            ids.push(object.id());
        }
    }
    ids
}

/// Failure to prepare an action or assemble its authorization proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowAssemblyError {
    /// A target V1 model invariant was violated.
    Model(ModelError),
    /// Deterministic encoding or identifier derivation failed.
    Codec(CodecError),
    /// A bounded material collection exceeded deployment limits.
    CollectionLimit,
    /// Evidence targeted a grant index that does not exist.
    InvalidGrantIndex,
    /// The signed action did not bind the derived authorization plan.
    ActionPlanMismatch,
}

impl From<ModelError> for WorkflowAssemblyError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl From<CodecError> for WorkflowAssemblyError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

impl fmt::Display for WorkflowAssemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model(_) => formatter.write_str("invalid authorization workflow value"),
            Self::Codec(_) => formatter.write_str("could not derive authorization binding"),
            Self::CollectionLimit => formatter.write_str("authorization material exceeds limits"),
            Self::InvalidGrantIndex => formatter.write_str("grant evidence index is invalid"),
            Self::ActionPlanMismatch => {
                formatter.write_str("signed action does not bind its authorization plan")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WorkflowAssemblyError {}

/// Requested child authority before issuer/linkage fields are derived.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantRequest {
    subject: PrincipalId,
    profile: ProfileRef,
    permissions: PermissionSet,
    validity: ValidityWindow,
    audiences: AudienceSet,
    action_constraint: ActionConstraint,
    budget_ceiling: Option<BudgetCeiling>,
    remaining_depth: u16,
    status_policy: StatusPolicy,
    assurance_floor: AssurancePolicyId,
    extensions: CriticalExtensions,
}

impl GrantRequest {
    /// Constructs an explicit child-authority request.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        subject: PrincipalId,
        profile: ProfileRef,
        permissions: PermissionSet,
        validity: ValidityWindow,
        audiences: AudienceSet,
        action_constraint: ActionConstraint,
        budget_ceiling: Option<BudgetCeiling>,
        remaining_depth: u16,
        status_policy: StatusPolicy,
        assurance_floor: AssurancePolicyId,
        extensions: CriticalExtensions,
    ) -> Self {
        Self {
            subject,
            profile,
            permissions,
            validity,
            audiences,
            action_constraint,
            budget_ceiling,
            remaining_depth,
            status_policy,
            assurance_floor,
            extensions,
        }
    }

    /// Projects requested child scope from a complete proposed statement.
    ///
    /// The proposal's issuer and parent fields are deliberately discarded.
    /// [`plan_child_grant`] derives both from the actual parent, preventing a
    /// binding from accidentally treating caller-supplied linkage as trusted.
    #[must_use]
    pub fn from_proposed_statement(statement: &GrantStatement) -> Self {
        Self {
            subject: statement.subject().clone(),
            profile: statement.profile().clone(),
            permissions: statement.permissions().clone(),
            validity: statement.validity(),
            audiences: statement.audiences().clone(),
            action_constraint: statement.action_constraint().clone(),
            budget_ceiling: statement.budget_ceiling().cloned(),
            remaining_depth: statement.remaining_depth(),
            status_policy: statement.status_policy().clone(),
            assurance_floor: statement.assurance_floor().clone(),
            extensions: statement.extensions().clone(),
        }
    }
}

/// Non-fatal authoring warning shown before custody is invoked.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OverGrantingWarning {
    /// Child retains discretion over every canonical action body.
    AnyBody,
    /// Child receives more than one exact permission.
    MultiplePermissions,
    /// Child can target more than one audience.
    MultipleAudiences,
    /// Child may delegate again.
    DelegationAllowed,
    /// Neither parent nor child has a stateful budget ceiling.
    NoBudgetCeiling,
    /// Child validity exceeds one day.
    LongValidity,
}

/// Machine-readable semantic difference between parent and planned child.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityDiff {
    removed_permissions: usize,
    removed_audiences: usize,
    validity_shortened: bool,
    action_narrowed: bool,
    budget_narrowed: bool,
    status_narrowed: bool,
    parent_depth: u16,
    child_depth: u16,
}

impl AuthorityDiff {
    /// Returns how many parent permissions are absent from the child.
    #[must_use]
    pub const fn removed_permissions(&self) -> usize {
        self.removed_permissions
    }

    /// Returns how many parent audiences are absent from the child.
    #[must_use]
    pub const fn removed_audiences(&self) -> usize {
        self.removed_audiences
    }

    /// Reports whether the child window is strictly smaller.
    #[must_use]
    pub const fn validity_shortened(&self) -> bool {
        self.validity_shortened
    }

    /// Reports whether action-body discretion was reduced.
    #[must_use]
    pub const fn action_narrowed(&self) -> bool {
        self.action_narrowed
    }

    /// Reports whether the budget ceiling was reduced.
    #[must_use]
    pub const fn budget_narrowed(&self) -> bool {
        self.budget_narrowed
    }

    /// Reports whether the child requires a stricter status policy.
    #[must_use]
    pub const fn status_narrowed(&self) -> bool {
        self.status_narrowed
    }

    /// Returns `(parent, child)` delegation depth.
    #[must_use]
    pub const fn delegation_depth(&self) -> (u16, u16) {
        (self.parent_depth, self.child_depth)
    }
}

/// A safe unsigned child grant and its pre-signing review material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantPlan {
    statement: GrantStatement,
    diff: AuthorityDiff,
    warnings: Vec<OverGrantingWarning>,
}

impl GrantPlan {
    /// Returns the unsigned child statement.
    #[must_use]
    pub const fn statement(&self) -> &GrantStatement {
        &self.statement
    }

    /// Returns the semantic parent-to-child authority diff.
    #[must_use]
    pub const fn diff(&self) -> &AuthorityDiff {
        &self.diff
    }

    /// Returns canonical over-granting warnings.
    #[must_use]
    pub fn warnings(&self) -> &[OverGrantingWarning] {
        &self.warnings
    }

    /// Consumes the reviewed plan into an unsigned statement.
    #[must_use]
    pub fn into_statement(self) -> GrantStatement {
        self.statement
    }
}

/// Plans a child grant and refuses widening before any signer is invoked.
///
/// The issuer and parent identifier are derived from `parent`; callers cannot
/// substitute either field.
///
/// # Errors
///
/// Returns a typed error identifying the first widened authority dimension or
/// a deterministic identifier failure.
pub fn plan_child_grant(
    parent: &GrantStatement,
    request: GrantRequest,
) -> Result<GrantPlan, PlanningError> {
    let parent_scope = scope_authority_view(grant_authority_view(parent));
    let child_scope = ScopeAuthorityView {
        profile: &request.profile,
        permissions: &request.permissions,
        validity: request.validity,
        audiences: &request.audiences,
        action_constraint: &request.action_constraint,
        budget_ceiling: request.budget_ceiling.as_ref(),
        remaining_depth: request.remaining_depth,
        status_policy: &request.status_policy,
        assurance_floor: &request.assurance_floor,
        extensions: &request.extensions,
    };
    if let AuthorScopeDecision::Denied(dimension) =
        evaluate_author_scope_view(parent_scope, child_scope)
    {
        return Err(PlanningError::Expanded(dimension));
    }

    let diff = AuthorityDiff {
        removed_permissions: parent
            .permissions()
            .as_slice()
            .len()
            .saturating_sub(request.permissions.as_slice().len()),
        removed_audiences: parent
            .audiences()
            .as_slice()
            .len()
            .saturating_sub(request.audiences.as_slice().len()),
        validity_shortened: request.validity != parent.validity(),
        action_narrowed: request.action_constraint != *parent.action_constraint(),
        budget_narrowed: request.budget_ceiling.as_ref() != parent.budget_ceiling(),
        status_narrowed: request.status_policy != *parent.status_policy(),
        parent_depth: parent.remaining_depth(),
        child_depth: request.remaining_depth,
    };
    let mut warnings = Vec::new();
    if request.action_constraint == ActionConstraint::AnyBody {
        warnings.push(OverGrantingWarning::AnyBody);
    }
    if request.permissions.as_slice().len() > 1 {
        warnings.push(OverGrantingWarning::MultiplePermissions);
    }
    if request.audiences.as_slice().len() > 1 {
        warnings.push(OverGrantingWarning::MultipleAudiences);
    }
    if request.remaining_depth > 0 {
        warnings.push(OverGrantingWarning::DelegationAllowed);
    }
    if request.budget_ceiling.is_none() {
        warnings.push(OverGrantingWarning::NoBudgetCeiling);
    }
    if request
        .validity
        .expires_at()
        .get()
        .saturating_sub(request.validity.not_before().get())
        > 86_400
    {
        warnings.push(OverGrantingWarning::LongValidity);
    }
    warnings.sort_unstable();
    let statement = GrantStatement::new(
        parent.subject().clone(),
        request.subject,
        request.profile,
        request.permissions,
        request.validity,
        request.audiences,
        request.action_constraint,
        request.budget_ceiling,
        request.remaining_depth,
        Some(grant_id(parent)?),
        request.status_policy,
        request.assurance_floor,
        request.extensions,
    );
    Ok(GrantPlan {
        statement,
        diff,
        warnings,
    })
}

/// Bounded safe builder for authorization composition plans.
pub struct PlanBuilder<'a> {
    limits: &'a VerifierLimits,
}

impl<'a> PlanBuilder<'a> {
    /// Selects the exact deployment plan limits.
    #[must_use]
    pub const fn new(limits: &'a VerifierLimits) -> Self {
        Self { limits }
    }

    /// Builds one proof leaf.
    #[must_use]
    pub const fn proof(&self, reference: ProofRef) -> AuthorizationPlan {
        AuthorizationPlan::proof(reference)
    }

    /// Builds and validates an all-of plan.
    ///
    /// # Errors
    ///
    /// Returns a typed shape or deployment-limit failure.
    pub fn all_of(
        &self,
        members: Vec<AuthorizationPlan>,
    ) -> Result<AuthorizationPlan, PlanningError> {
        self.validate(AuthorizationPlan::all_of(members)?)
    }

    /// Builds and validates an any-of plan.
    ///
    /// # Errors
    ///
    /// Returns a typed shape or deployment-limit failure.
    pub fn any_of(
        &self,
        members: Vec<AuthorizationPlan>,
    ) -> Result<AuthorizationPlan, PlanningError> {
        self.validate(AuthorizationPlan::any_of(members)?)
    }

    /// Builds and validates a threshold plan.
    ///
    /// # Errors
    ///
    /// Returns a typed shape or deployment-limit failure.
    pub fn k_of_n(
        &self,
        k: u16,
        members: Vec<AuthorizationPlan>,
    ) -> Result<AuthorizationPlan, PlanningError> {
        self.validate(AuthorizationPlan::k_of_n(k, members)?)
    }

    fn validate(&self, plan: AuthorizationPlan) -> Result<AuthorizationPlan, PlanningError> {
        plan.validate(self.limits)?;
        Ok(plan)
    }
}

/// Content identifier returned with one external signing request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningObjectId {
    /// Grant statement identifier.
    Grant(GrantId),
    /// Action envelope identifier.
    Action(ActionId),
    /// Principal-status statement identifier.
    PrincipalStatus(PrincipalStatusId),
    /// Grant-status statement identifier.
    GrantStatus(GrantStatusId),
}

impl SigningObjectId {
    /// Returns the exact identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        match self {
            Self::Grant(identifier) => identifier.as_bytes(),
            Self::Action(identifier) => identifier.as_bytes(),
            Self::PrincipalStatus(identifier) => identifier.as_bytes(),
            Self::GrantStatus(identifier) => identifier.as_bytes(),
        }
    }

    /// Returns the closed object-kind label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Grant(_) => "grant",
            Self::Action(_) => "action",
            Self::PrincipalStatus(_) => "principal-status",
            Self::GrantStatus(_) => "grant-status",
        }
    }
}

/// Approval-policy configuration committed before any signer is invoked.
///
/// The SDK compares this commitment against the requirement published by the
/// trusted authority, so its canonical form decides whether signing proceeds.
/// It is stated here, in deterministic length-framed bytes, rather than in a
/// language binding's own serializer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalPolicyCommitment;

impl ApprovalPolicyCommitment {
    /// Commits to one exact executable approval configuration.
    ///
    /// Requirements are committed in the caller's order after rejecting
    /// duplicates, so a reordered or padded requirement set never collides
    /// with the configuration an authority actually required.
    ///
    /// # Errors
    ///
    /// Returns an error when any field exceeds protocol limits or the
    /// requirement list repeats a value.
    pub fn commit(
        mode: &str,
        max_uses: u32,
        expires_in_seconds: u32,
        requirements: &[&str],
    ) -> Result<Digest, CodecError> {
        let mut canonical = Vec::new();
        push_framed(&mut canonical, mode.as_bytes())?;
        canonical.extend_from_slice(&max_uses.to_be_bytes());
        canonical.extend_from_slice(&expires_in_seconds.to_be_bytes());
        let count = u32::try_from(requirements.len()).map_err(|_| CodecError::LimitExceeded)?;
        canonical.extend_from_slice(&count.to_be_bytes());
        for (index, requirement) in requirements.iter().enumerate() {
            if requirements[..index].contains(requirement) {
                return Err(CodecError::NonCanonical);
            }
            push_framed(&mut canonical, requirement.as_bytes())?;
        }
        domain_commitment("auths.approval-policy.v1", &canonical)
    }
}

/// Binds one plan approval to the exact plan, policy, and expiry it covered.
///
/// A single approval may release many signatures, so what it covered must be
/// committed rather than reassembled by each binding.
///
/// # Errors
///
/// Returns an error when the commitment inputs exceed protocol limits.
pub fn commit_plan_approval(
    plan_commitment: &[u8; 32],
    configuration_digest: &[u8; 32],
    max_uses: u32,
    expires_at: u64,
) -> Result<Digest, CodecError> {
    let mut canonical = Vec::with_capacity(32 + 32 + 4 + 8);
    canonical.extend_from_slice(plan_commitment);
    canonical.extend_from_slice(configuration_digest);
    canonical.extend_from_slice(&max_uses.to_be_bytes());
    canonical.extend_from_slice(&expires_at.to_be_bytes());
    domain_commitment("auths.plan-approval.v1", &canonical)
}

/// Canonical bytes for one member of a profile-owned action plan.
///
/// The action owns profile, media type, body, permission, and budget meaning.
/// Plan authority additionally commits to the resource namespace and audience.
/// Keeping this framing here prevents language bindings from defining a second
/// cross-language plan format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfilePlanMember;

impl ProfilePlanMember {
    /// Encodes one exact plan member from validated protocol values.
    ///
    /// # Errors
    ///
    /// Returns an error when the canonical action or a framed field exceeds
    /// protocol limits.
    pub fn encode(
        action: &CanonicalAction,
        resource_namespace: &ResourceId,
        audience: &Audience,
    ) -> Result<Vec<u8>, CodecError> {
        let action = encode_canonical_action(action)?;
        let mut canonical = Vec::new();
        push_framed(&mut canonical, &action)?;
        push_framed(&mut canonical, resource_namespace.as_str().as_bytes())?;
        push_framed(&mut canonical, audience.as_str().as_bytes())?;
        Ok(canonical)
    }
}

/// Commitment over one profile plan and each of its ordered members.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfilePlanCommitment {
    plan: Digest,
    members: Vec<Digest>,
}

impl ProfilePlanCommitment {
    /// Commits to an ordered plan membership for one profile.
    ///
    /// The plan digest covers every member in order, so approving a plan
    /// cannot approve a different set or a different ordering.
    ///
    /// # Errors
    ///
    /// Returns an error when the profile reference or membership exceeds
    /// protocol limits.
    pub fn commit(
        profile_id: &str,
        profile_version: u16,
        members: &[&[u8]],
    ) -> Result<Self, CodecError> {
        let mut canonical = Vec::new();
        push_framed(&mut canonical, profile_id.as_bytes())?;
        canonical.extend_from_slice(&profile_version.to_be_bytes());
        let count = u32::try_from(members.len()).map_err(|_| CodecError::LimitExceeded)?;
        canonical.extend_from_slice(&count.to_be_bytes());
        let mut member_digests = Vec::with_capacity(members.len());
        for (index, member) in members.iter().enumerate() {
            push_framed(&mut canonical, member)?;
            let position = u32::try_from(index).map_err(|_| CodecError::LimitExceeded)?;
            let mut member_input = Vec::new();
            push_framed(&mut member_input, profile_id.as_bytes())?;
            member_input.extend_from_slice(&profile_version.to_be_bytes());
            member_input.extend_from_slice(&position.to_be_bytes());
            push_framed(&mut member_input, member)?;
            member_digests.push(domain_commitment(
                "auths.profile-plan-member.v1",
                &member_input,
            )?);
        }
        Ok(Self {
            plan: domain_commitment("auths.profile-plan.v1", &canonical)?,
            members: member_digests,
        })
    }

    /// Returns the commitment over the whole ordered plan.
    #[must_use]
    pub const fn plan(&self) -> Digest {
        self.plan
    }

    /// Returns the ordered per-member commitments.
    #[must_use]
    pub fn members(&self) -> &[Digest] {
        &self.members
    }
}

fn push_framed(output: &mut Vec<u8>, value: &[u8]) -> Result<(), CodecError> {
    let length = u64::try_from(value.len()).map_err(|_| CodecError::LimitExceeded)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

/// Longest label, two 32-byte hex identifiers, and two separators.
const REQUEST_ID_CAPACITY: usize = 16 + 1 + 64 + 1 + 64;

fn push_hex(output: &mut String, bytes: &[u8; 32]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
}

/// Exact bytes and descriptor to submit to an external signer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalSigningRequest<T> {
    unsigned: T,
    descriptor: SignatureDescriptor,
    object_id: SigningObjectId,
    signing_preimage: Vec<u8>,
}

impl<T> ExternalSigningRequest<T> {
    /// Returns the exact signed descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &SignatureDescriptor {
        &self.descriptor
    }

    /// Returns the content identifier of the unsigned object.
    #[must_use]
    pub const fn object_id(&self) -> SigningObjectId {
        self.object_id
    }

    /// Returns exact domain-separated bytes for the signer.
    #[must_use]
    pub fn signing_preimage(&self) -> &[u8] {
        &self.signing_preimage
    }

    /// Returns the exact identifier for this signing transaction.
    ///
    /// Custody ports and approval providers echo this value back, so its
    /// format is owned here rather than assembled by each language binding.
    /// It is `<object kind>:<hex object id>:<hex transaction binding>`.
    #[must_use]
    pub fn request_id(&self) -> String {
        let mut value = String::with_capacity(REQUEST_ID_CAPACITY);
        value.push_str(self.object_id.label());
        value.push(':');
        push_hex(&mut value, self.object_id.as_bytes());
        value.push(':');
        push_hex(&mut value, self.transaction_digest().as_bytes());
        value
    }

    /// Returns the transaction binding every custody port must echo back.
    ///
    /// Approval prompts, external signers, and language bindings all commit to
    /// this value. It is derived here from the exact signing preimage so that
    /// no consumer restates the rule in its own language.
    #[must_use]
    pub fn transaction_digest(&self) -> Digest {
        transaction_binding(&self.signing_preimage)
    }
}

impl ExternalSigningRequest<GrantStatement> {
    /// Completes a grant without exposing or accepting private key material.
    #[must_use]
    pub fn complete(self, signature: SignatureBytes) -> SignedGrant {
        SignedGrant::new(
            self.unsigned,
            SignatureEnvelope::new(self.descriptor, signature),
        )
    }
}

impl ExternalSigningRequest<ActionEnvelope> {
    /// Completes an action without exposing or accepting private key material.
    #[must_use]
    pub fn complete(self, signature: SignatureBytes) -> SignedAction {
        SignedAction::new(
            self.unsigned,
            SignatureEnvelope::new(self.descriptor, signature),
        )
    }
}

impl ExternalSigningRequest<PrincipalStatusStatement> {
    /// Completes a principal-status statement.
    #[must_use]
    pub fn complete(self, signature: SignatureBytes) -> SignedPrincipalStatus {
        SignedPrincipalStatus::new(
            self.unsigned,
            SignatureEnvelope::new(self.descriptor, signature),
        )
    }
}

impl ExternalSigningRequest<GrantStatusStatement> {
    /// Completes a grant-status statement.
    #[must_use]
    pub fn complete(self, signature: SignatureBytes) -> SignedGrantStatus {
        SignedGrantStatus::new(
            self.unsigned,
            SignatureEnvelope::new(self.descriptor, signature),
        )
    }
}

/// Prepares one grant for an external signer.
///
/// # Errors
///
/// Returns a codec error if deterministic encoding or identifier derivation
/// fails.
pub fn prepare_grant(
    statement: GrantStatement,
    descriptor: SignatureDescriptor,
) -> Result<ExternalSigningRequest<GrantStatement>, AuthorError> {
    let object_id = SigningObjectId::Grant(grant_id(&statement)?);
    let signing_preimage = grant_signing_preimage(&statement, &descriptor)?;
    Ok(ExternalSigningRequest {
        unsigned: statement,
        descriptor,
        object_id,
        signing_preimage,
    })
}

/// Prepares one action for an external signer.
///
/// # Errors
///
/// Returns a codec error if deterministic encoding or identifier derivation
/// fails.
pub fn prepare_action(
    envelope: ActionEnvelope,
    descriptor: SignatureDescriptor,
) -> Result<ExternalSigningRequest<ActionEnvelope>, AuthorError> {
    let object_id = SigningObjectId::Action(action_id(&envelope)?);
    let signing_preimage = action_signing_preimage(&envelope, &descriptor)?;
    Ok(ExternalSigningRequest {
        unsigned: envelope,
        descriptor,
        object_id,
        signing_preimage,
    })
}

/// Prepares one principal-status statement for an external signer.
///
/// # Errors
///
/// Returns a codec error if deterministic encoding or identifier derivation
/// fails.
pub fn prepare_principal_status(
    statement: PrincipalStatusStatement,
    descriptor: SignatureDescriptor,
) -> Result<ExternalSigningRequest<PrincipalStatusStatement>, AuthorError> {
    let object_id = SigningObjectId::PrincipalStatus(principal_status_id(&statement)?);
    let signing_preimage = principal_status_signing_preimage(&statement, &descriptor)?;
    Ok(ExternalSigningRequest {
        unsigned: statement,
        descriptor,
        object_id,
        signing_preimage,
    })
}

/// Prepares one grant-status statement for an external signer.
///
/// # Errors
///
/// Returns a codec error if deterministic encoding or identifier derivation
/// fails.
pub fn prepare_grant_status(
    statement: GrantStatusStatement,
    descriptor: SignatureDescriptor,
) -> Result<ExternalSigningRequest<GrantStatusStatement>, AuthorError> {
    let object_id = SigningObjectId::GrantStatus(grant_status_id(&statement)?);
    let signing_preimage = grant_status_signing_preimage(&statement, &descriptor)?;
    Ok(ExternalSigningRequest {
        unsigned: statement,
        descriptor,
        object_id,
        signing_preimage,
    })
}

/// Safe planning failure returned before signing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanningError {
    /// The request widened one named authority dimension.
    Expanded(AuthorityDimension),
    /// The composition plan is malformed or exceeds deployment limits.
    InvalidPlan,
    /// Deterministic parent identifier derivation failed.
    Codec(CodecError),
}

impl From<ModelError> for PlanningError {
    fn from(_error: ModelError) -> Self {
        Self::InvalidPlan
    }
}

impl From<CodecError> for PlanningError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

impl fmt::Display for PlanningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expanded(dimension) => {
                write!(formatter, "grant request widens {dimension:?}")
            }
            Self::InvalidPlan => formatter.write_str("invalid or excessive authorization plan"),
            Self::Codec(_) => formatter.write_str("could not derive parent grant identifier"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PlanningError {}

/// Keyless authoring failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorError {
    /// Deterministic encoding or identifier derivation failed.
    Codec(CodecError),
}

impl From<CodecError> for AuthorError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

impl fmt::Display for AuthorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("could not prepare exact target V1 signing bytes")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AuthorError {}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_model::{
        Audience, CapabilityId, CriticalExtension, CriticalExtensions, ExtensionId, LimitKind,
        MediaType, Permission, PrincipalMethodId, ProfileId, ResourceId, SignatureSuiteId,
        StatusPolicy, Timestamp, VerificationMethod,
    };

    fn permissions(resource: &str) -> PermissionSet {
        PermissionSet::new(vec![Permission::new(
            CapabilityId::parse("deploy/release").unwrap(),
            ResourceId::parse(resource).unwrap(),
        )])
        .unwrap()
    }

    fn parent() -> GrantStatement {
        GrantStatement::new(
            PrincipalId::parse("did:key:root").unwrap(),
            PrincipalId::parse("did:key:manager").unwrap(),
            ProfileRef::new(ProfileId::parse("auths.deploy").unwrap(), 1).unwrap(),
            permissions("deploy://production"),
            ValidityWindow::new(Timestamp::new(10), Timestamp::new(200_000)).unwrap(),
            AudienceSet::new(vec![Audience::parse("deploy://production").unwrap()]).unwrap(),
            ActionConstraint::AnyBody,
            None,
            2,
            None,
            StatusPolicy::ExpiryOnly,
            AssurancePolicyId::parse("production-v1").unwrap(),
            CriticalExtensions::empty(),
        )
    }

    fn signed_parent() -> SignedGrant {
        SignedGrant::new(
            parent(),
            SignatureEnvelope::new(
                SignatureDescriptor::new(
                    PrincipalMethodId::parse("raw-key-v1").unwrap(),
                    VerificationMethod::parse("did:key:root").unwrap(),
                    SignatureSuiteId::parse("ed25519-v1").unwrap(),
                ),
                SignatureBytes::new(vec![1; 64]).unwrap(),
            ),
        )
    }

    fn request(permission: PermissionSet) -> GrantRequest {
        GrantRequest::new(
            PrincipalId::parse("did:key:agent").unwrap(),
            ProfileRef::new(ProfileId::parse("auths.deploy").unwrap(), 1).unwrap(),
            permission,
            ValidityWindow::new(Timestamp::new(20), Timestamp::new(100)).unwrap(),
            AudienceSet::new(vec![Audience::parse("deploy://production").unwrap()]).unwrap(),
            ActionConstraint::AnyBody,
            None,
            1,
            StatusPolicy::ExpiryOnly,
            AssurancePolicyId::parse("production-v1").unwrap(),
            CriticalExtensions::empty(),
        )
    }

    fn extensions(bytes: &[u8]) -> CriticalExtensions {
        CriticalExtensions::new(vec![
            CriticalExtension::new(
                ExtensionId::parse("exact-marker-v1").unwrap(),
                bytes.to_vec(),
            )
            .unwrap(),
        ])
        .unwrap()
    }

    fn parent_with_extensions() -> GrantStatement {
        GrantStatement::new(
            PrincipalId::parse("did:key:root").unwrap(),
            PrincipalId::parse("did:key:manager").unwrap(),
            ProfileRef::new(ProfileId::parse("auths.deploy").unwrap(), 1).unwrap(),
            permissions("deploy://production"),
            ValidityWindow::new(Timestamp::new(10), Timestamp::new(200_000)).unwrap(),
            AudienceSet::new(vec![Audience::parse("deploy://production").unwrap()]).unwrap(),
            ActionConstraint::AnyBody,
            None,
            2,
            None,
            StatusPolicy::ExpiryOnly,
            AssurancePolicyId::parse("production-v1").unwrap(),
            extensions(&[1]),
        )
    }

    #[test]
    fn planner_derives_linkage_and_reports_over_granting() {
        let parent = parent();
        let plan = plan_child_grant(&parent, request(permissions("deploy://production"))).unwrap();
        assert_eq!(plan.statement().issuer(), parent.subject());
        assert_eq!(plan.statement().parent(), Some(grant_id(&parent).unwrap()));
        assert_eq!(plan.diff().delegation_depth(), (2, 1));
        assert_eq!(
            plan.warnings(),
            &[
                OverGrantingWarning::AnyBody,
                OverGrantingWarning::DelegationAllowed,
                OverGrantingWarning::NoBudgetCeiling,
            ]
        );
    }

    #[test]
    fn planner_refuses_widening_before_signing() {
        assert_eq!(
            plan_child_grant(
                &parent(),
                request(permissions("deploy://production-and-staging"))
            ),
            Err(PlanningError::Expanded(AuthorityDimension::Permissions))
        );
    }

    #[test]
    fn planner_rejects_critical_extension_drift_before_signing() {
        let parent = parent_with_extensions();
        for child_extensions in [CriticalExtensions::empty(), extensions(&[2])] {
            let mut child = request(permissions("deploy://production"));
            child.extensions = child_extensions;
            assert_eq!(
                plan_child_grant(&parent, child),
                Err(PlanningError::Expanded(AuthorityDimension::Extensions))
            );
        }

        let mut child = request(permissions("deploy://production"));
        child.extensions = extensions(&[1]);
        plan_child_grant(&parent, child).expect("exact extension set is accepted");
    }

    #[test]
    fn plan_builder_applies_deployment_limits() {
        let limits = VerifierLimits::default_deployment()
            .with_limit(LimitKind::PlanLeaves, 1)
            .unwrap();
        let builder = PlanBuilder::new(&limits);
        let left = builder.proof(ProofRef::new([1; 32]));
        let right = builder.proof(ProofRef::new([2; 32]));
        assert_eq!(
            builder.all_of(vec![left, right]),
            Err(PlanningError::InvalidPlan)
        );
    }

    #[test]
    fn profile_action_preparation_derives_exact_shared_bindings() {
        let grant = signed_parent();
        let canonical = CanonicalAction::new(
            grant.statement().profile().clone(),
            MediaType::parse("application/json").unwrap(),
            br#"{"value":1}"#.to_vec(),
            grant.statement().permissions().as_slice()[0].clone(),
            None,
        )
        .unwrap();
        let prepared = prepare_profile_action(
            canonical.clone(),
            Audience::parse("deploy://production").unwrap(),
            grant.statement().subject().clone(),
            &grant,
            [7; 32],
            42,
        )
        .unwrap();
        assert_eq!(prepared.canonical(), &canonical);
        assert_eq!(
            prepared.envelope().terminal_grant(),
            Some(grant_id(grant.statement()).unwrap())
        );
        assert_eq!(prepared.envelope().challenge(), Challenge::new([7; 32]));
        assert_eq!(
            prepared.envelope().validity().not_before(),
            Timestamp::new(42)
        );
    }

    #[test]
    fn proof_builder_bounds_grants_before_retaining_overflow() {
        let mut builder = WorkflowProofBuilder::new();
        let limit = VerifierLimits::default_deployment().get(LimitKind::Grants);
        for _ in 0..limit {
            builder.push_grant(signed_parent()).unwrap();
        }
        assert_eq!(
            builder.push_grant(signed_parent()),
            Err(WorkflowAssemblyError::CollectionLimit)
        );
    }

    #[test]
    fn public_evidence_is_content_addressed_deterministically() {
        let first = address_evidence(
            EvidenceTypeId::parse("raw-key-v1").unwrap(),
            MediaType::parse("application/vnd.auths.raw-key.v1").unwrap(),
            vec![1, 2, 3],
        )
        .unwrap();
        let second = address_evidence(
            EvidenceTypeId::parse("raw-key-v1").unwrap(),
            MediaType::parse("application/vnd.auths.raw-key.v1").unwrap(),
            vec![1, 2, 3],
        )
        .unwrap();
        assert_eq!(first.id(), second.id());
        assert_ne!(first.id(), EvidenceId::new([0; 32]));
    }
    #[test]
    fn approval_policy_commitment_separates_every_field() {
        let baseline =
            ApprovalPolicyCommitment::commit("every-action", 1, 300, &["visible-human-review"])
                .unwrap();
        for candidate in [
            ApprovalPolicyCommitment::commit("plan-once", 1, 300, &["visible-human-review"]),
            ApprovalPolicyCommitment::commit("every-action", 2, 300, &["visible-human-review"]),
            ApprovalPolicyCommitment::commit("every-action", 1, 301, &["visible-human-review"]),
            ApprovalPolicyCommitment::commit("every-action", 1, 300, &[]),
            ApprovalPolicyCommitment::commit("every-action", 1, 300, &["visible-human-reviewX"]),
        ] {
            assert_ne!(baseline, candidate.unwrap());
        }
    }

    #[test]
    fn approval_policy_commitment_is_unambiguous_across_field_boundaries() {
        // Length framing must stop a longer mode from imitating a shorter mode
        // followed by a requirement.
        assert_ne!(
            ApprovalPolicyCommitment::commit("every", 1, 300, &["action"]).unwrap(),
            ApprovalPolicyCommitment::commit("everyaction", 1, 300, &[""]).unwrap()
        );
        assert_eq!(
            ApprovalPolicyCommitment::commit("every-action", 1, 300, &["a", "a"]),
            Err(CodecError::NonCanonical)
        );
    }

    #[test]
    fn profile_plan_commitment_binds_membership_and_order() {
        let first: &[u8] = b"first";
        let second: &[u8] = b"second";
        let ordered = ProfilePlanCommitment::commit("auths.mcp", 1, &[first, second]).unwrap();
        let reordered = ProfilePlanCommitment::commit("auths.mcp", 1, &[second, first]).unwrap();
        let shortened = ProfilePlanCommitment::commit("auths.mcp", 1, &[first]).unwrap();
        let other_profile =
            ProfilePlanCommitment::commit("other.plan", 1, &[first, second]).unwrap();

        assert_ne!(ordered.plan(), reordered.plan());
        assert_ne!(ordered.plan(), shortened.plan());
        assert_ne!(ordered.plan(), other_profile.plan());
        assert_eq!(ordered.members().len(), 2);
        // Identical bytes at different positions commit differently.
        let repeated = ProfilePlanCommitment::commit("auths.mcp", 1, &[first, first]).unwrap();
        assert_ne!(repeated.members()[0], repeated.members()[1]);
    }

    #[test]
    fn profile_plan_member_binds_action_namespace_and_audience() {
        let profile =
            ProfileRef::new(auths_model::ProfileId::parse("auths.test").unwrap(), 1).unwrap();
        let baseline = CanonicalAction::new(
            profile,
            auths_model::MediaType::parse("application/json").unwrap(),
            br#"{"value":1}"#.to_vec(),
            auths_model::Permission::new(
                auths_model::CapabilityId::parse("records/update").unwrap(),
                ResourceId::parse("records://one").unwrap(),
            ),
            None,
        )
        .unwrap();
        let namespace = ResourceId::parse("records://").unwrap();
        let audience = auths_model::Audience::parse("records://service").unwrap();
        let encoded = ProfilePlanMember::encode(&baseline, &namespace, &audience).unwrap();

        let other_namespace = ResourceId::parse("other://").unwrap();
        let other_audience = auths_model::Audience::parse("records://other").unwrap();
        assert_ne!(
            encoded,
            ProfilePlanMember::encode(&baseline, &other_namespace, &audience).unwrap()
        );
        assert_ne!(
            encoded,
            ProfilePlanMember::encode(&baseline, &namespace, &other_audience).unwrap()
        );
    }
}
