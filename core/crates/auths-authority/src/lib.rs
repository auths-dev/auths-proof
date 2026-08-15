//! Closed target V1 authority attenuation.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use auths_algebra_kernel::{
    AttenuationChecks, RootLinkage, attenuation_checks_accept, root_preserved,
};
use auths_model::{
    ActionAuthorityView, ActionConstraint, ActionEnvelope, AssurancePolicyId, AudienceSet,
    BudgetCeiling, CriticalExtensions, DenialReason, GrantAuthorityView, GrantId, GrantStatement,
    PermissionSet, PrincipalId, ProfileRef, ScopeAuthorityView, StatusPolicy, TrustAnchor,
    ValidityWindow, action_authority_view, action_constraint_allows, action_constraint_attenuates,
    assurance_policy_id_equal, audience_set_contains, audience_set_is_subset,
    critical_extensions_equal, grant_authority_view, optional_budget_attenuates,
    optional_budget_covers, optional_grant_id_equal, permission_set_contains,
    permission_set_is_subset, principal_id_equal, profile_ref_equal, profile_slice_contains,
    status_policy_attenuates, validity_window_contains,
};

/// Authority accumulated while walking one root-to-terminal grant chain.
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
pub struct AuthorityStateView<'a> {
    /// Trust root this authority is anchored at. Every accepted delegation
    /// copies it forward unchanged, so it is the identity a chain must still
    /// descend from after any number of edges.
    pub root: &'a PrincipalId,
    pub subject: &'a PrincipalId,
    pub allowed_profiles: &'a [ProfileRef],
    pub profile: Option<&'a ProfileRef>,
    pub permissions: &'a PermissionSet,
    pub validity: ValidityWindow,
    pub audiences: &'a AudienceSet,
    pub action_constraint: &'a ActionConstraint,
    pub budget_ceiling: Option<&'a BudgetCeiling>,
    pub remaining_depth: u16,
    pub last_grant: Option<GrantId>,
    pub assurance_policy: &'a AssurancePolicyId,
    pub status_policy: &'a StatusPolicy,
    pub extensions: Option<&'a CriticalExtensions>,
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
pub fn evaluate_grant_view<'grant>(
    parent: AuthorityStateView<'_>,
    grant_id: GrantId,
    grant: GrantAuthorityView<'grant>,
) -> DelegationEvaluation<'grant> {
    let checks = AttenuationChecks {
        root_preserved: root_preserved(&root_linkage(&parent, grant.issuer)),
        depth_decreases: parent.remaining_depth > 0
            && grant.remaining_depth < parent.remaining_depth,
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
        extensions_attenuate: match parent.extensions {
            Some(parent) => critical_extensions_equal(grant.extensions, parent),
            None => true,
        },
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
pub fn evaluate_action_coverage(
    authority: &EffectiveAuthority,
    action: &ActionEnvelope,
) -> CoverageDecision {
    evaluate_action_coverage_view(
        authority_state_view(authority),
        action_authority_view(action),
    )
}

/// Pure terminal-coverage evaluation over lossless validated-model views.
#[doc(hidden)]
#[must_use]
pub fn evaluate_action_coverage_view(
    authority: AuthorityStateView<'_>,
    action: ActionAuthorityView<'_>,
) -> CoverageDecision {
    // Terminal coverage is the same chain claim as a delegation edge with the
    // actor in the issuer position: an authority that never descended from the
    // root it claims authorizes nothing.
    if !root_preserved(&root_linkage(&authority, action.actor))
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
    if !optional_budget_covers(authority.budget_ceiling, action.requested_budget) {
        return CoverageDecision::Denied(DenialReason::BudgetCeilingExceeded);
    }
    CoverageDecision::Authorized
}

/// Projects exactly the accumulated fields consumed by authority decisions.
#[doc(hidden)]
#[must_use]
pub fn authority_state_view(authority: &EffectiveAuthority) -> AuthorityStateView<'_> {
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
    pub fn authorizes(&self, action: &ActionEnvelope) -> Result<(), DenialReason> {
        match evaluate_action_coverage(self, action) {
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
        ActionAuthorityView, Audience, CapabilityId, CriticalExtension, CriticalExtensions,
        ExtensionId, PrincipalMethodId, ProfileId, ResourceId, Timestamp, TrustAnchorId,
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
        TrustAnchor::new(
            TrustAnchorId::parse("root").expect("anchor id"),
            PrincipalId::parse("did:key:root").expect("root"),
            vec![PrincipalMethodId::parse("did-key-v1").expect("method")],
            vec![profile("profile-a"), profile("profile-b")],
            permissions(),
            vec![ResourceId::parse("cluster://").expect("namespace")],
            audiences(),
            ValidityWindow::new(Timestamp::new(0), Timestamp::new(u64::MAX)).expect("validity"),
            None,
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
            evaluate_action_coverage_view(unrooted, action),
            CoverageDecision::Denied(DenialReason::BrokenGrantChain)
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
