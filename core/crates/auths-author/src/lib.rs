//! Pure, keyless target V1 authoring requests and authority diffs.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use auths_codec::{
    action_id, action_signing_preimage, grant_id, grant_signing_preimage, grant_status_id,
    grant_status_signing_preimage, principal_status_id, principal_status_signing_preimage,
    CodecError,
};
use auths_model::{
    ActionConstraint, ActionEnvelope, ActionId, AssurancePolicyId, AudienceSet, AuthorizationPlan,
    BudgetCeiling, CriticalExtensions, GrantId, GrantStatement, GrantStatusId,
    GrantStatusStatement, ModelError, PermissionSet, PrincipalId, PrincipalStatusId,
    PrincipalStatusStatement, ProfileRef, ProofRef, SignatureBytes, SignatureDescriptor,
    SignatureEnvelope, SignedAction, SignedGrant, SignedGrantStatus, SignedPrincipalStatus,
    StatusPolicy, ValidityWindow, VerifierLimits,
};
use core::fmt;

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
}

/// Authority dimension that an unsafe grant request attempted to widen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityDimension {
    /// Application profile differs from the parent.
    Profile,
    /// Requested permissions are not a subset.
    Permissions,
    /// Requested validity extends outside the parent window.
    Validity,
    /// Requested audiences are not a subset.
    Audiences,
    /// Action-body authority is wider.
    ActionConstraint,
    /// Stateful budget ceiling is wider.
    Budget,
    /// Delegation depth did not strictly decrease.
    DelegationDepth,
    /// Status/freshness policy is weaker.
    Status,
    /// Assurance policy is different.
    Assurance,
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityDiff {
    removed_permissions: usize,
    removed_audiences: usize,
    validity_shortened: bool,
    action_narrowed: bool,
    budget_narrowed: bool,
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
    if request.profile != *parent.profile() {
        return Err(PlanningError::Expanded(AuthorityDimension::Profile));
    }
    if !request.permissions.is_subset_of(parent.permissions()) {
        return Err(PlanningError::Expanded(AuthorityDimension::Permissions));
    }
    if !parent.validity().contains_window(request.validity) {
        return Err(PlanningError::Expanded(AuthorityDimension::Validity));
    }
    if !request.audiences.is_subset_of(parent.audiences()) {
        return Err(PlanningError::Expanded(AuthorityDimension::Audiences));
    }
    if !request
        .action_constraint
        .attenuates(parent.action_constraint())
    {
        return Err(PlanningError::Expanded(
            AuthorityDimension::ActionConstraint,
        ));
    }
    if !budget_attenuates(request.budget_ceiling.as_ref(), parent.budget_ceiling()) {
        return Err(PlanningError::Expanded(AuthorityDimension::Budget));
    }
    if parent.remaining_depth() == 0 || request.remaining_depth >= parent.remaining_depth() {
        return Err(PlanningError::Expanded(AuthorityDimension::DelegationDepth));
    }
    if !status_attenuates(&request.status_policy, parent.status_policy()) {
        return Err(PlanningError::Expanded(AuthorityDimension::Status));
    }
    if request.assurance_floor != *parent.assurance_floor() {
        return Err(PlanningError::Expanded(AuthorityDimension::Assurance));
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

fn budget_attenuates(child: Option<&BudgetCeiling>, parent: Option<&BudgetCeiling>) -> bool {
    match (child, parent) {
        (_, None) => true,
        (Some(child), Some(parent)) => child.attenuates(parent),
        (None, Some(_)) => false,
    }
}

fn status_attenuates(child: &StatusPolicy, parent: &StatusPolicy) -> bool {
    match (child, parent) {
        (_, StatusPolicy::ExpiryOnly) => true,
        (
            StatusPolicy::SnapshotRequired {
                method: child_method,
                max_age: child_age,
            },
            StatusPolicy::SnapshotRequired {
                method: parent_method,
                max_age: parent_age,
            },
        ) => child_method == parent_method && child_age <= parent_age,
        (StatusPolicy::ExpiryOnly, StatusPolicy::SnapshotRequired { .. }) => false,
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
        Audience, CapabilityId, CriticalExtensions, LimitKind, Permission, ProfileId, ResourceId,
        StatusPolicy, Timestamp,
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
}
