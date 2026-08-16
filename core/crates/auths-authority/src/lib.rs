//! Closed target V1 authority attenuation.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use auths_algebra_kernel::{
    AttenuationChecks, RootLinkage, attenuation_checks_accept, root_preserved,
};
use auths_model::{
    AcceptedRegistries, ActionAuthorityView, ActionConstraint, ActionEnvelope, AssurancePolicyId,
    AudienceSet, BudgetCeiling, CriticalExtensions, DenialReason, GrantAuthorityView, GrantId,
    GrantStatement, PermissionSet, PrincipalId, ProfileBudgetExpression, ProfileRef,
    ScopeAuthorityView, StatusPolicy, TrustAnchor, ValidityWindow, action_authority_view,
    action_constraint_allows, action_constraint_attenuates, assurance_policy_id_equal,
    audience_set_contains, audience_set_is_subset, budget_ceiling_covers_action,
    critical_extensions_equal, grant_authority_view, optional_budget_attenuates,
    optional_grant_id_equal, permission_set_contains, permission_set_is_subset, principal_id_equal,
    profile_ref_equal, profile_slice_contains, status_policy_attenuates, validity_window_contains,
};

/// Authority accumulated while walking one root-to-terminal grant chain.
///
/// Raw state views are intentionally not part of the public API:
///
/// ```compile_fail
/// use auths_authority::AuthorityStateView;
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveAuthority {
    root: PrincipalId,
    subject: PrincipalId,
    allowed_profiles: Vec<ProfileRef>,
    profile: Option<ProfileRef>,
    permissions: PermissionSet,
    validity: ValidityWindow,
    audiences: AudienceSet,
    action_constraint: ActionConstraint,
    budget_ceiling: Option<BudgetCeiling>,
    remaining_depth: u16,
    last_grant: Option<GrantId>,
    assurance_policy: AssurancePolicyId,
    status_policy: StatusPolicy,
    extensions: Option<CriticalExtensions>,
}

/// Borrowed descriptor of the unique state changes for an accepted grant.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct AcceptedTransition<'a> {
    subject: &'a PrincipalId,
    profile: &'a ProfileRef,
    permissions: &'a PermissionSet,
    validity: ValidityWindow,
    audiences: &'a AudienceSet,
    action_constraint: &'a ActionConstraint,
    budget_ceiling: Option<&'a BudgetCeiling>,
    remaining_depth: u16,
    grant_id: GrantId,
    status_policy: &'a StatusPolicy,
    extensions: &'a CriticalExtensions,
}

/// Stable delegation decision made by the production authority kernel.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub enum DelegationOutcome<'a> {
    Accepted(AcceptedTransition<'a>),
    Denied(DenialReason),
}

/// Projection and outcome produced together by the production kernel.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct DelegationEvaluation<'a> {
    pub checks: AttenuationChecks,
    pub outcome: DelegationOutcome<'a>,
}

/// Stable terminal action-coverage decision.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageDecision {
    Authorized,
    Denied(DenialReason),
}

/// Ordered authority dimension used by pre-signing authoring diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityDimension {
    Profile,
    Permissions,
    Validity,
    Audiences,
    ActionConstraint,
    Budget,
    DelegationDepth,
    Status,
    Assurance,
    Extensions,
}

/// Stable pre-signing scope decision made by the production authority kernel.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorScopeDecision {
    Accepted,
    Denied(AuthorityDimension),
}

/// Lossless borrowed projection of accumulated authority state.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct AuthorityStateView<'a> {
    /// Trust root this authority is anchored at. Every accepted delegation
    /// copies it forward unchanged, so it is the identity a chain must still
    /// descend from after any number of edges.
    root: &'a PrincipalId,
    subject: &'a PrincipalId,
    allowed_profiles: &'a [ProfileRef],
    profile: Option<&'a ProfileRef>,
    permissions: &'a PermissionSet,
    validity: ValidityWindow,
    audiences: &'a AudienceSet,
    action_constraint: &'a ActionConstraint,
    budget_ceiling: Option<&'a BudgetCeiling>,
    remaining_depth: u16,
    last_grant: Option<GrantId>,
    assurance_policy: &'a AssurancePolicyId,
    status_policy: &'a StatusPolicy,
    extensions: Option<&'a CriticalExtensions>,
}

/// Borrowed principal whose equality is the canonical protocol comparison.
///
/// The derived `PartialEq` on [`PrincipalId`] is deliberately not used: every
/// authority decision in this crate compares principals through
/// [`principal_id_equal`], and the trust-root dimension must not become a
/// second, unmodelled comparison path.
#[derive(Clone, Copy, Debug)]
struct CanonicalPrincipal<'a>(&'a PrincipalId);

impl PartialEq for CanonicalPrincipal<'_> {
    fn eq(&self, other: &Self) -> bool {
        principal_id_equal(self.0, other.0)
    }
}

/// Whether a grant's critical extensions attenuate its parent's.
///
/// A parent declaring no extension scope constrains nothing, so any grant
/// attenuates it. Otherwise the sets must match exactly: the eleventh
/// dimension is equality, not containment.
///
/// Named for the same reason as [`depth_decreases`]: aeneas cannot translate a
/// branching expression sitting in struct-field position, and this `match` was
/// the second one in `evaluate_grant_view`.
fn extensions_attenuate(
    parent_extensions: Option<&CriticalExtensions>,
    grant_extensions: &CriticalExtensions,
) -> bool {
    match parent_extensions {
        Some(parent) => critical_extensions_equal(grant_extensions, parent),
        None => true,
    }
}

/// Whether a delegation strictly decreases the remaining delegation depth.
///
/// A parent with no depth left can delegate nothing, and a child must have
/// strictly less depth than its parent.
///
/// This is a named function rather than the inline conjunction it replaces
/// because aeneas raises `Internal error, please file an issue` translating a
/// short-circuiting `&&` here, in struct-field position or hoisted to a local
/// alike. Every sibling dimension in `AttenuationChecks` is already a function
/// call, so this also makes the one odd field out consistent with the rest.
fn depth_decreases(parent_remaining: u16, grant_remaining: u16) -> bool {
    if parent_remaining == 0 {
        return false;
    }
    grant_remaining < parent_remaining
}

/// Projects the chain-linkage facts the trust-root dimension consumes.
fn root_linkage<'a>(
    parent: &AuthorityStateView<'a>,
    issuer: &'a PrincipalId,
) -> RootLinkage<CanonicalPrincipal<'a>> {
    RootLinkage {
        parent_root: CanonicalPrincipal(parent.root),
        parent_subject: CanonicalPrincipal(parent.subject),
        parent_delegated: parent.last_grant.is_some(),
        grant_issuer: CanonicalPrincipal(issuer),
    }
}

fn selected_profile_attenuates(
    selected: Option<&ProfileRef>,
    allowed_profiles: &[ProfileRef],
    child: &ProfileRef,
) -> bool {
    match selected {
        Some(parent) => profile_ref_equal(parent, child),
        None => profile_slice_contains(allowed_profiles, child),
    }
}

/// Evaluates the exact ordered scope and first-failure contract used before a
/// child grant can be signed.
#[doc(hidden)]
#[must_use]
pub fn evaluate_author_scope_view(
    parent: ScopeAuthorityView<'_>,
    child: ScopeAuthorityView<'_>,
) -> AuthorScopeDecision {
    if !profile_ref_equal(child.profile, parent.profile) {
        return AuthorScopeDecision::Denied(AuthorityDimension::Profile);
    }
    if !permission_set_is_subset(child.permissions, parent.permissions) {
        return AuthorScopeDecision::Denied(AuthorityDimension::Permissions);
    }
    if !validity_window_contains(parent.validity, child.validity) {
        return AuthorScopeDecision::Denied(AuthorityDimension::Validity);
    }
    if !audience_set_is_subset(child.audiences, parent.audiences) {
        return AuthorScopeDecision::Denied(AuthorityDimension::Audiences);
    }
    if !action_constraint_attenuates(child.action_constraint, parent.action_constraint) {
        return AuthorScopeDecision::Denied(AuthorityDimension::ActionConstraint);
    }
    if !optional_budget_attenuates(child.budget_ceiling, parent.budget_ceiling) {
        return AuthorScopeDecision::Denied(AuthorityDimension::Budget);
    }
    if parent.remaining_depth == 0 || child.remaining_depth >= parent.remaining_depth {
        return AuthorScopeDecision::Denied(AuthorityDimension::DelegationDepth);
    }
    if !status_policy_attenuates(child.status_policy, parent.status_policy) {
        return AuthorScopeDecision::Denied(AuthorityDimension::Status);
    }
    if !assurance_policy_id_equal(child.assurance_floor, parent.assurance_floor) {
        return AuthorScopeDecision::Denied(AuthorityDimension::Assurance);
    }
    if !critical_extensions_equal(child.extensions, parent.extensions) {
        return AuthorScopeDecision::Denied(AuthorityDimension::Extensions);
    }
    AuthorScopeDecision::Accepted
}

/// Evaluates linkage, all attenuation dimensions, diagnostic selection, and
/// the unique accepted state change used by [`EffectiveAuthority::delegate`].
#[doc(hidden)]
#[must_use]
pub fn evaluate_grant<'grant>(
    parent: &EffectiveAuthority,
    grant_id: GrantId,
    grant: &'grant GrantStatement,
) -> DelegationEvaluation<'grant> {
    evaluate_grant_view(
        authority_state_view(parent),
        grant_id,
        grant_authority_view(grant),
    )
}

/// Pure authority-kernel evaluation over lossless validated-model views.
#[doc(hidden)]
#[must_use]
pub(crate) fn evaluate_grant_view<'grant>(
    parent: AuthorityStateView<'_>,
    grant_id: GrantId,
    grant: GrantAuthorityView<'grant>,
) -> DelegationEvaluation<'grant> {
    // Bound to a local rather than borrowed inline. `root_preserved` takes a
    // reference, and a reference to a temporary in argument position is what
    // aeneas failed to translate here (Aeneas.Errors.CFailure on this span).
    // Same value, same order of evaluation, one name.
    let linkage = root_linkage(&parent, grant.issuer);
    let checks = AttenuationChecks {
        root_preserved: root_preserved(&linkage),
        depth_decreases: depth_decreases(parent.remaining_depth, grant.remaining_depth),
        profile_attenuates: selected_profile_attenuates(
            parent.profile,
            parent.allowed_profiles,
            grant.profile,
        ),
        permissions_attenuate: permission_set_is_subset(grant.permissions, parent.permissions),
        validity_attenuates: validity_window_contains(parent.validity, grant.validity),
        audiences_attenuate: audience_set_is_subset(grant.audiences, parent.audiences),
        action_constraint_attenuates: action_constraint_attenuates(
            grant.action_constraint,
            parent.action_constraint,
        ),
        budget_attenuates: optional_budget_attenuates(grant.budget_ceiling, parent.budget_ceiling),
        status_attenuates: status_policy_attenuates(grant.status_policy, parent.status_policy),
        assurance_attenuates: assurance_policy_id_equal(
            grant.assurance_floor,
            parent.assurance_policy,
        ),
        extensions_attenuate: extensions_attenuate(parent.extensions, grant.extensions),
    };
    // `root_preserved` subsumes the issuer/subject linkage and additionally
    // rejects a parent state that never descended from the root it claims, so
    // the linkage gate consumes it rather than recomputing a weaker condition.
    if !checks.root_preserved || !optional_grant_id_equal(grant.parent, parent.last_grant) {
        return DelegationEvaluation {
            checks,
            outcome: DelegationOutcome::Denied(DenialReason::BrokenGrantChain),
        };
    }
    if !attenuation_checks_accept(&checks) {
        return DelegationEvaluation {
            checks,
            outcome: DelegationOutcome::Denied(DenialReason::DelegationExpanded),
        };
    }
    DelegationEvaluation {
        checks,
        outcome: DelegationOutcome::Accepted(AcceptedTransition {
            subject: grant.subject,
            profile: grant.profile,
            permissions: grant.permissions,
            validity: grant.validity,
            audiences: grant.audiences,
            action_constraint: grant.action_constraint,
            budget_ceiling: grant.budget_ceiling,
            remaining_depth: grant.remaining_depth,
            grant_id,
            status_policy: grant.status_policy,
            extensions: grant.extensions,
        }),
    }
}

/// Evaluates terminal linkage, exact profile, membership, containment, and
/// first-failure diagnostics used by [`EffectiveAuthority::authorizes`].
#[doc(hidden)]
#[must_use]
fn evaluate_action_coverage(
    authority: &EffectiveAuthority,
    action: &ActionEnvelope,
    expression: ProfileBudgetExpression,
) -> CoverageDecision {
    evaluate_action_coverage_view(
        authority_state_view(authority),
        action_authority_view(action),
        expression,
    )
}

/// Pure terminal-coverage evaluation over lossless validated-model views.
#[doc(hidden)]
#[must_use]
pub(crate) fn evaluate_action_coverage_view(
    authority: AuthorityStateView<'_>,
    action: ActionAuthorityView<'_>,
    expression: ProfileBudgetExpression,
) -> CoverageDecision {
    // Terminal coverage is the same chain claim as a delegation edge with the
    // actor in the issuer position: an authority that never descended from the
    // root it claims authorizes nothing.
    let linkage = root_linkage(&authority, action.actor);
    if !root_preserved(&linkage)
        || !optional_grant_id_equal(action.terminal_grant, authority.last_grant)
    {
        return CoverageDecision::Denied(DenialReason::BrokenGrantChain);
    }
    if !selected_profile_attenuates(
        authority.profile,
        authority.allowed_profiles,
        action.profile,
    ) {
        return CoverageDecision::Denied(DenialReason::BrokenGrantChain);
    }
    if !permission_set_contains(authority.permissions, action.permission) {
        return CoverageDecision::Denied(DenialReason::PermissionNotGranted);
    }
    if !validity_window_contains(authority.validity, action.validity) {
        return CoverageDecision::Denied(DenialReason::ActionOutsideValidity);
    }
    if !audience_set_contains(authority.audiences, action.audience) {
        return CoverageDecision::Denied(DenialReason::AudienceMismatch);
    }
    if !action_constraint_allows(authority.action_constraint, action.canonical_body_digest) {
        return CoverageDecision::Denied(DenialReason::ActionConstraintMismatch);
    }
    if !budget_ceiling_covers_action(
        authority.budget_ceiling,
        action.requested_budget,
        expression,
    ) {
        return CoverageDecision::Denied(DenialReason::BudgetCeilingExceeded);
    }
    CoverageDecision::Authorized
}

/// Projects exactly the accumulated fields consumed by authority decisions.
#[doc(hidden)]
#[must_use]
pub(crate) fn authority_state_view(authority: &EffectiveAuthority) -> AuthorityStateView<'_> {
    AuthorityStateView {
        root: &authority.root,
        subject: &authority.subject,
        allowed_profiles: &authority.allowed_profiles,
        profile: authority.profile.as_ref(),
        permissions: &authority.permissions,
        validity: authority.validity,
        audiences: &authority.audiences,
        action_constraint: &authority.action_constraint,
        budget_ceiling: authority.budget_ceiling.as_ref(),
        remaining_depth: authority.remaining_depth,
        last_grant: authority.last_grant,
        assurance_policy: &authority.assurance_policy,
        status_policy: &authority.status_policy,
        extensions: authority.extensions.as_ref(),
    }
}

impl EffectiveAuthority {
    /// Starts authority at one local trust anchor.
    #[must_use]
    pub fn from_anchor(anchor: &TrustAnchor) -> Self {
        Self {
            root: anchor.principal().clone(),
            subject: anchor.principal().clone(),
            allowed_profiles: anchor.profiles().to_vec(),
            profile: None,
            permissions: anchor.permissions().clone(),
            validity: anchor.validity(),
            audiences: anchor.audiences().clone(),
            action_constraint: ActionConstraint::AnyBody,
            budget_ceiling: anchor.budget_ceiling().cloned(),
            remaining_depth: anchor.max_delegation_depth(),
            last_grant: None,
            assurance_policy: anchor.assurance_policy().clone(),
            status_policy: anchor.status_policy().clone(),
            extensions: None,
        }
    }

    /// Applies one grant edge.
    ///
    /// # Errors
    ///
    /// Returns a stable denial reason when linkage is broken or any authority
    /// dimension widens.
    pub fn delegate(
        &mut self,
        grant_id: GrantId,
        grant: &GrantStatement,
    ) -> Result<(), DenialReason> {
        let transition = match evaluate_grant(self, grant_id, grant).outcome {
            DelegationOutcome::Accepted(transition) => transition,
            DelegationOutcome::Denied(reason) => return Err(reason),
        };
        self.subject = transition.subject.clone();
        self.profile = Some(transition.profile.clone());
        self.permissions = transition.permissions.clone();
        self.validity = transition.validity;
        self.audiences = transition.audiences.clone();
        self.action_constraint = transition.action_constraint.clone();
        self.budget_ceiling = transition.budget_ceiling.cloned();
        self.remaining_depth = transition.remaining_depth;
        self.last_grant = Some(transition.grant_id);
        self.status_policy = transition.status_policy.clone();
        self.extensions = Some(transition.extensions.clone());
        Ok(())
    }

    /// Checks an action against the terminal authority.
    ///
    /// # Errors
    ///
    /// Returns the first stable authority failure in protocol order.
    /// Budget expressibility is resolved inside this boundary from the exact
    /// action profile and the caller's accepted registry set. Callers cannot
    /// supply a naked expression that reclassifies an absent request.
    pub fn authorizes(
        &self,
        action: &ActionEnvelope,
        registries: &AcceptedRegistries,
    ) -> Result<(), DenialReason> {
        let expression = registries.profile_budget_expression(action.profile());
        match evaluate_action_coverage(self, action, expression) {
            CoverageDecision::Authorized => Ok(()),
            CoverageDecision::Denied(reason) => Err(reason),
        }
    }

    /// Returns the selected local root.
    #[must_use]
    pub const fn root(&self) -> &PrincipalId {
        &self.root
    }

    /// Returns the terminal subject.
    #[must_use]
    pub const fn subject(&self) -> &PrincipalId {
        &self.subject
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use auths_model::{
        ActionAuthorityView, Audience, CapabilityId, Challenge, ChannelBindingId,
        CriticalExtension, CriticalExtensions, ExtensionId, MediaType, PlanId, PrincipalMethodId,
        ProfileId, ProfilePolicyId, ProofRef, RegistryManifestId, ResourceId, ResourceMatcherId,
        SignatureSuiteId, Timestamp, TrustAnchorId,
    };

    fn profile(name: &str) -> ProfileRef {
        ProfileRef::new(ProfileId::parse(name).expect("profile id"), 1).expect("profile")
    }

    fn permissions() -> PermissionSet {
        PermissionSet::new(vec![auths_model::Permission::new(
            CapabilityId::parse("deploy").expect("capability"),
            ResourceId::parse("cluster://production").expect("resource"),
        )])
        .expect("permissions")
    }

    fn audiences() -> AudienceSet {
        AudienceSet::new(vec![
            Audience::parse("cluster://production").expect("audience"),
        ])
        .expect("audiences")
    }

    fn anchor() -> TrustAnchor {
        anchor_with_budget(None)
    }

    fn anchor_with_budget(budget_ceiling: Option<BudgetCeiling>) -> TrustAnchor {
        TrustAnchor::new(
            TrustAnchorId::parse("root").expect("anchor id"),
            PrincipalId::parse("did:key:root").expect("root"),
            vec![PrincipalMethodId::parse("did-key-v1").expect("method")],
            vec![profile("profile-a"), profile("profile-b")],
            permissions(),
            vec![ResourceId::parse("cluster://").expect("namespace")],
            audiences(),
            ValidityWindow::new(Timestamp::new(0), Timestamp::new(u64::MAX)).expect("validity"),
            budget_ceiling,
            2,
            AssurancePolicyId::parse("assurance-v1").expect("assurance"),
            StatusPolicy::ExpiryOnly,
        )
        .expect("anchor")
    }

    fn grant(
        issuer: &str,
        subject: &str,
        selected_profile: &str,
        remaining_depth: u16,
        parent: Option<GrantId>,
    ) -> GrantStatement {
        grant_with_extensions(
            issuer,
            subject,
            selected_profile,
            remaining_depth,
            parent,
            CriticalExtensions::empty(),
        )
    }

    fn grant_with_extensions(
        issuer: &str,
        subject: &str,
        selected_profile: &str,
        remaining_depth: u16,
        parent: Option<GrantId>,
        extensions: CriticalExtensions,
    ) -> GrantStatement {
        GrantStatement::new(
            PrincipalId::parse(issuer).expect("issuer"),
            PrincipalId::parse(subject).expect("subject"),
            profile(selected_profile),
            permissions(),
            ValidityWindow::new(Timestamp::new(0), Timestamp::new(u64::MAX)).expect("validity"),
            audiences(),
            ActionConstraint::AnyBody,
            None,
            remaining_depth,
            parent,
            StatusPolicy::ExpiryOnly,
            AssurancePolicyId::parse("assurance-v1").expect("assurance"),
            extensions,
        )
    }

    fn extensions(bytes: &[u8]) -> CriticalExtensions {
        CriticalExtensions::new(vec![
            CriticalExtension::new(
                ExtensionId::parse("exact-marker-v1").expect("extension id"),
                bytes.to_vec(),
            )
            .expect("extension"),
        ])
        .expect("extensions")
    }

    #[test]
    fn delegation_denies_a_grant_issued_under_a_different_root() {
        let mut authority = EffectiveAuthority::from_anchor(&anchor());
        assert_eq!(
            authority.delegate(
                GrantId::new([9; 32]),
                &grant("did:key:other-root", "did:key:agent", "profile-a", 1, None),
            ),
            Err(DenialReason::BrokenGrantChain)
        );
    }

    #[test]
    fn kernel_denies_a_delegation_whose_parent_state_is_not_rooted() {
        // A chain state that claims a root it never received authority from.
        // `evaluate_grant_view` is the pure kernel entry point: nothing above
        // it re-derives the root, so this state must be rejected here.
        let anchor = anchor();
        let root = PrincipalId::parse("did:key:root").expect("root");
        let forged = PrincipalId::parse("did:key:attacker").expect("attacker");
        let permissions = permissions();
        let audiences = audiences();
        let profiles = [profile("profile-a"), profile("profile-b")];
        let constraint = ActionConstraint::AnyBody;
        let assurance = AssurancePolicyId::parse("assurance-v1").expect("assurance");
        let status = StatusPolicy::ExpiryOnly;
        let unrooted = AuthorityStateView {
            root: &root,
            subject: &forged,
            allowed_profiles: &profiles,
            profile: None,
            permissions: &permissions,
            validity: anchor.validity(),
            audiences: &audiences,
            action_constraint: &constraint,
            budget_ceiling: None,
            remaining_depth: 2,
            last_grant: None,
            assurance_policy: &assurance,
            status_policy: &status,
            extensions: None,
        };
        let statement = grant("did:key:attacker", "did:key:victim", "profile-a", 1, None);
        let evaluation = evaluate_grant_view(
            unrooted,
            GrantId::new([7; 32]),
            grant_authority_view(&statement),
        );
        let preserved = evaluation.checks.root_preserved;
        assert!(
            matches!(
                evaluation.outcome,
                DelegationOutcome::Denied(DenialReason::BrokenGrantChain)
            ),
            "unrooted parent state must not mint authority (root_preserved={preserved})"
        );
        assert!(
            !preserved,
            "root preservation must be computed, not asserted"
        );
    }

    #[test]
    fn terminal_coverage_denies_an_authority_that_is_not_rooted() {
        let anchor = anchor();
        let root = PrincipalId::parse("did:key:root").expect("root");
        let forged = PrincipalId::parse("did:key:attacker").expect("attacker");
        let permissions = permissions();
        let audiences = audiences();
        let profiles = [profile("profile-a"), profile("profile-b")];
        let constraint = ActionConstraint::AnyBody;
        let assurance = AssurancePolicyId::parse("assurance-v1").expect("assurance");
        let status = StatusPolicy::ExpiryOnly;
        let selected = profile("profile-a");
        let permission = auths_model::Permission::new(
            CapabilityId::parse("deploy").expect("capability"),
            ResourceId::parse("cluster://production").expect("resource"),
        );
        let audience = Audience::parse("cluster://production").expect("audience");
        let action = ActionAuthorityView {
            profile: &selected,
            canonical_body_digest: auths_model::Digest::new([0; 32]),
            permission: &permission,
            requested_budget: None,
            audience: &audience,
            validity: anchor.validity(),
            actor: &forged,
            terminal_grant: None,
        };
        let unrooted = AuthorityStateView {
            root: &root,
            subject: &forged,
            allowed_profiles: &profiles,
            profile: None,
            permissions: &permissions,
            validity: anchor.validity(),
            audiences: &audiences,
            action_constraint: &constraint,
            budget_ceiling: None,
            remaining_depth: 2,
            last_grant: None,
            assurance_policy: &assurance,
            status_policy: &status,
            extensions: None,
        };
        assert_eq!(
            evaluate_action_coverage_view(unrooted, action, ProfileBudgetExpression::Expressible),
            CoverageDecision::Denied(DenialReason::BrokenGrantChain)
        );
    }

    /// A present grant id is only a representation marker. This counterexample
    /// records why raw views must stay crate-private and why formal historical
    /// claims require `AnchoredChain`: if arbitrary construction were public,
    /// matching a forged marker would pass the raw evaluator.
    #[test]
    fn forged_present_marker_demonstrates_why_raw_views_are_sealed() {
        let anchor = anchor();
        let root = PrincipalId::parse("did:key:root").expect("root");
        let forged = PrincipalId::parse("did:key:attacker").expect("attacker");
        let permissions = permissions();
        let audiences = audiences();
        let profiles = [profile("profile-a"), profile("profile-b")];
        let constraint = ActionConstraint::AnyBody;
        let assurance = AssurancePolicyId::parse("assurance-v1").expect("assurance");
        let status = StatusPolicy::ExpiryOnly;
        let marker = GrantId::new([4; 32]);
        let raw = AuthorityStateView {
            root: &root,
            subject: &forged,
            allowed_profiles: &profiles,
            profile: None,
            permissions: &permissions,
            validity: anchor.validity(),
            audiences: &audiences,
            action_constraint: &constraint,
            budget_ceiling: None,
            remaining_depth: 2,
            last_grant: Some(marker),
            assurance_policy: &assurance,
            status_policy: &status,
            extensions: None,
        };
        let statement = grant(
            "did:key:attacker",
            "did:key:victim",
            "profile-a",
            1,
            Some(marker),
        );
        assert!(matches!(
            evaluate_grant_view(raw, GrantId::new([5; 32]), grant_authority_view(&statement))
                .outcome,
            DelegationOutcome::Accepted(_)
        ));
    }

    fn numeric_budget(value: u64) -> BudgetCeiling {
        BudgetCeiling::new(
            auths_model::BudgetAlgebraId::parse("numeric-ceiling-v1").expect("algebra"),
            value,
        )
    }

    fn accepted_registries(selected: &ProfileRef, budget_free: bool) -> AcceptedRegistries {
        accepted_registries_for(
            vec![selected.clone()],
            if budget_free {
                vec![selected.clone()]
            } else {
                Vec::new()
            },
        )
    }

    fn accepted_registries_for(
        profiles: Vec<ProfileRef>,
        budget_free_profiles: Vec<ProfileRef>,
    ) -> AcceptedRegistries {
        let registries = AcceptedRegistries::new(
            RegistryManifestId::new([0x11; 32]),
            vec![PrincipalMethodId::parse("raw-key-v1").expect("principal method")],
            vec![SignatureSuiteId::parse("ed25519-v1").expect("signature suite")],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![ResourceMatcherId::parse("uri-namespace-v1").expect("resource matcher")],
            Vec::new(),
            Vec::new(),
            profiles,
            vec![ProfilePolicyId::parse("exact-v1").expect("profile policy")],
        )
        .expect("accepted registries");
        if budget_free_profiles.is_empty() {
            registries
        } else {
            registries
                .with_budget_free_profiles(budget_free_profiles)
                .expect("budget-free declaration")
        }
    }

    fn action_envelope(
        anchor: &TrustAnchor,
        selected: ProfileRef,
        requested_budget: Option<BudgetCeiling>,
    ) -> ActionEnvelope {
        ActionEnvelope::new(
            selected,
            MediaType::parse("application/vnd.auths.test.v1+cbor").expect("media type"),
            auths_model::Digest::new([0; 32]),
            auths_model::Permission::new(
                CapabilityId::parse("deploy").expect("capability"),
                ResourceId::parse("cluster://production").expect("resource"),
            ),
            requested_budget,
            Audience::parse("cluster://production").expect("audience"),
            Challenge::new([1; 32]),
            anchor.validity(),
            PrincipalId::parse("did:key:root").expect("actor"),
            None,
            PlanId::new([2; 32]),
            ChannelBindingId::parse("none-v1").expect("channel binding"),
            ProofRef::new([3; 32]),
            Vec::new(),
            CriticalExtensions::empty(),
        )
    }

    /// A bounded ceiling must not cover an action that declares no budget.
    ///
    /// This reaches terminal coverage directly, so nothing above the kernel can
    /// supply the denial: the full verifier's `validate_budget_constraints`
    /// guard runs earlier in `auths-verifier` and is bypassed here on purpose.
    /// An action with no requested budget under a bounded ceiling has no bound
    /// on what it may spend, so the kernel itself must deny it.
    #[test]
    fn terminal_coverage_denies_an_absent_request_under_a_bounded_ceiling() {
        let anchor = anchor_with_budget(Some(numeric_budget(10)));
        let authority = EffectiveAuthority::from_anchor(&anchor);
        let actor = PrincipalId::parse("did:key:root").expect("root");
        let selected = profile("profile-a");
        let permission = auths_model::Permission::new(
            CapabilityId::parse("deploy").expect("capability"),
            ResourceId::parse("cluster://production").expect("resource"),
        );
        let audience = Audience::parse("cluster://production").expect("audience");
        let action = ActionAuthorityView {
            profile: &selected,
            canonical_body_digest: auths_model::Digest::new([0; 32]),
            permission: &permission,
            requested_budget: None,
            audience: &audience,
            validity: anchor.validity(),
            actor: &actor,
            terminal_grant: None,
        };
        assert_eq!(
            evaluate_action_coverage_view(
                authority_state_view(&authority),
                action,
                ProfileBudgetExpression::Expressible
            ),
            CoverageDecision::Denied(DenialReason::BudgetCeilingExceeded),
            "a bounded ceiling must not authorize an unbounded (absent) request"
        );
    }

    /// The same fact through the public `EffectiveAuthority::authorizes` entry
    /// point, which is what every embedder that is not the full verifier calls.
    #[test]
    fn authorizes_denies_an_absent_request_under_a_bounded_ceiling() {
        let anchor = anchor_with_budget(Some(numeric_budget(10)));
        let authority = EffectiveAuthority::from_anchor(&anchor);
        let selected = profile("profile-a");
        let registries = accepted_registries(&selected, false);
        let action = action_envelope(&anchor, selected.clone(), None);
        // A bounded request inside the ceiling is still authorized: the denial
        // above is specific to the absent request, not a blanket budget denial.
        assert_eq!(
            authority.authorizes(
                &action_envelope(&anchor, selected.clone(), Some(numeric_budget(5))),
                &registries,
            ),
            Ok(())
        );
        assert_eq!(
            authority.authorizes(&action, &registries),
            Err(DenialReason::BudgetCeilingExceeded)
        );

        let budget_free = accepted_registries(&selected, true);
        assert_eq!(
            authority.authorizes(&action, &budget_free),
            Ok(()),
            "only a registry declaration bound to the exact action profile may reclassify absence"
        );
    }

    #[test]
    fn authorizes_resolves_budget_expression_for_the_exact_action_profile() {
        let anchor = anchor_with_budget(Some(numeric_budget(10)));
        let authority = EffectiveAuthority::from_anchor(&anchor);
        let budget_free = profile("profile-a");
        let budget_capable = profile("profile-b");
        let registries = accepted_registries_for(
            vec![budget_free.clone(), budget_capable.clone()],
            vec![budget_free.clone()],
        );

        assert_eq!(
            authority.authorizes(&action_envelope(&anchor, budget_free, None), &registries),
            Ok(()),
            "the exact profile declared budget-free may omit a request"
        );
        assert_eq!(
            authority.authorizes(&action_envelope(&anchor, budget_capable, None), &registries),
            Err(DenialReason::BudgetCeilingExceeded),
            "a different accepted profile must not inherit budget-free status"
        );
    }

    /// The mirror of the two tests above: the *only* thing that changes is what
    /// the caller says about the action's profile, and the verdict flips.
    ///
    /// An action whose profile cannot express a budget provably spends zero, so
    /// every ceiling covers it. Without this the whole class of budget-free
    /// profiles — `auths.mcp/1` among them — is unconstructible under any
    /// bounded grant chain.
    #[test]
    fn terminal_coverage_authorizes_an_absent_request_for_a_budget_free_profile() {
        let anchor = anchor_with_budget(Some(numeric_budget(10)));
        let authority = EffectiveAuthority::from_anchor(&anchor);
        let actor = PrincipalId::parse("did:key:root").expect("root");
        let selected = profile("profile-a");
        let permission = auths_model::Permission::new(
            CapabilityId::parse("deploy").expect("capability"),
            ResourceId::parse("cluster://production").expect("resource"),
        );
        let audience = Audience::parse("cluster://production").expect("audience");
        let action = ActionAuthorityView {
            profile: &selected,
            canonical_body_digest: auths_model::Digest::new([0; 32]),
            permission: &permission,
            requested_budget: None,
            audience: &audience,
            validity: anchor.validity(),
            actor: &actor,
            terminal_grant: None,
        };
        for ceiling in [0, 10, u64::MAX] {
            let anchor = anchor_with_budget(Some(numeric_budget(ceiling)));
            let authority = EffectiveAuthority::from_anchor(&anchor);
            assert_eq!(
                evaluate_action_coverage_view(
                    authority_state_view(&authority),
                    action,
                    ProfileBudgetExpression::Inexpressible
                ),
                CoverageDecision::Authorized,
                "zero spend is within ceiling {ceiling}"
            );
        }
        // The capability only reclassifies an *absent* request. A declared
        // request is still compared against the ceiling by the algebra.
        let over = numeric_budget(11);
        assert_eq!(
            evaluate_action_coverage_view(
                authority_state_view(&authority),
                ActionAuthorityView {
                    requested_budget: Some(&over),
                    ..action
                },
                ProfileBudgetExpression::Inexpressible
            ),
            CoverageDecision::Denied(DenialReason::BudgetCeilingExceeded)
        );
    }

    #[test]
    fn every_edge_of_a_rooted_chain_reports_root_preservation() {
        // Guards the other direction: a check that denied everything would
        // also make the exploit tests above pass.
        let anchor = anchor();
        let mut authority = EffectiveAuthority::from_anchor(&anchor);
        let first_id = GrantId::new([1; 32]);
        let first = grant("did:key:root", "did:key:agent", "profile-b", 1, None);
        assert!(
            evaluate_grant(&authority, first_id, &first)
                .checks
                .root_preserved
        );
        authority.delegate(first_id, &first).expect("first edge");
        let second = grant(
            "did:key:agent",
            "did:key:child",
            "profile-b",
            0,
            Some(first_id),
        );
        assert!(
            evaluate_grant(&authority, GrantId::new([2; 32]), &second)
                .checks
                .root_preserved
        );
        assert_eq!(authority.root().as_str(), "did:key:root");
    }

    #[test]
    fn a_broken_root_is_reported_on_the_dimension_not_only_in_the_reason() {
        let authority = EffectiveAuthority::from_anchor(&anchor());
        let statement = grant("did:key:other-root", "did:key:agent", "profile-a", 1, None);
        let evaluation = evaluate_grant(&authority, GrantId::new([9; 32]), &statement);
        assert!(!evaluation.checks.root_preserved);
        assert!(!attenuation_checks_accept(&evaluation.checks));
    }

    #[test]
    fn first_grant_selects_one_allowed_profile_and_depth_strictly_decreases() {
        let mut authority = EffectiveAuthority::from_anchor(&anchor());
        let first_id = GrantId::new([1; 32]);
        assert_eq!(
            authority.delegate(
                first_id,
                &grant("did:key:root", "did:key:agent", "profile-b", 2, None)
            ),
            Err(DenialReason::DelegationExpanded)
        );
        authority
            .delegate(
                first_id,
                &grant("did:key:root", "did:key:agent", "profile-b", 1, None),
            )
            .expect("allowed profile and strict depth");
        assert_eq!(authority.subject().as_str(), "did:key:agent");

        assert_eq!(
            authority.delegate(
                GrantId::new([2; 32]),
                &grant(
                    "did:key:agent",
                    "did:key:child",
                    "profile-a",
                    0,
                    Some(first_id)
                )
            ),
            Err(DenialReason::DelegationExpanded)
        );
        authority
            .delegate(
                GrantId::new([3; 32]),
                &grant(
                    "did:key:agent",
                    "did:key:child",
                    "profile-b",
                    0,
                    Some(first_id),
                ),
            )
            .expect("selected profile remains exact");
    }

    #[test]
    fn zero_depth_parent_cannot_delegate() {
        let first_id = GrantId::new([1; 32]);
        let mut authority = EffectiveAuthority::from_anchor(&anchor());
        authority
            .delegate(
                first_id,
                &grant("did:key:root", "did:key:agent", "profile-a", 0, None),
            )
            .expect("first edge may consume all depth");
        assert_eq!(
            authority.delegate(
                GrantId::new([2; 32]),
                &grant(
                    "did:key:agent",
                    "did:key:child",
                    "profile-a",
                    0,
                    Some(first_id)
                )
            ),
            Err(DenialReason::DelegationExpanded)
        );
    }

    #[test]
    fn child_grant_must_preserve_the_selected_extension_set_exactly() {
        let first_id = GrantId::new([1; 32]);
        let mut authority = EffectiveAuthority::from_anchor(&anchor());
        authority
            .delegate(
                first_id,
                &grant_with_extensions(
                    "did:key:root",
                    "did:key:agent",
                    "profile-a",
                    1,
                    None,
                    extensions(&[1]),
                ),
            )
            .expect("first grant selects the extension set");

        for child_extensions in [CriticalExtensions::empty(), extensions(&[2])] {
            assert_eq!(
                authority.delegate(
                    GrantId::new([2; 32]),
                    &grant_with_extensions(
                        "did:key:agent",
                        "did:key:child",
                        "profile-a",
                        0,
                        Some(first_id),
                        child_extensions,
                    ),
                ),
                Err(DenialReason::DelegationExpanded)
            );
        }

        authority
            .delegate(
                GrantId::new([3; 32]),
                &grant_with_extensions(
                    "did:key:agent",
                    "did:key:child",
                    "profile-a",
                    0,
                    Some(first_id),
                    extensions(&[1]),
                ),
            )
            .expect("an exactly preserved extension set attenuates");
    }
}
