//! Closed target V1 authority attenuation.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use auths_model::{
    ActionConstraint, ActionEnvelope, AssurancePolicyId, AudienceSet, BudgetCeiling, DenialReason,
    GrantId, GrantStatement, PermissionSet, PrincipalId, ProfileRef, StatusPolicy, TrustAnchor,
    ValidityWindow,
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
        if grant.issuer() != &self.subject || grant.parent() != self.last_grant {
            return Err(DenialReason::BrokenGrantChain);
        }
        if self.remaining_depth == 0 || grant.remaining_depth() >= self.remaining_depth {
            return Err(DenialReason::DelegationExpanded);
        }
        if self.profile.as_ref().map_or_else(
            || !self.allowed_profiles.contains(grant.profile()),
            |profile| profile != grant.profile(),
        ) || !grant.permissions().is_subset_of(&self.permissions)
            || !self.validity.contains_window(grant.validity())
            || !grant.audiences().is_subset_of(&self.audiences)
            || !grant
                .action_constraint()
                .attenuates(&self.action_constraint)
            || !budget_attenuates(grant.budget_ceiling(), self.budget_ceiling.as_ref())
            || !status_attenuates(grant.status_policy(), &self.status_policy)
            || grant.assurance_floor() != &self.assurance_policy
        {
            return Err(DenialReason::DelegationExpanded);
        }
        self.subject = grant.subject().clone();
        self.profile = Some(grant.profile().clone());
        self.permissions = grant.permissions().clone();
        self.validity = grant.validity();
        self.audiences = grant.audiences().clone();
        self.action_constraint = grant.action_constraint().clone();
        self.budget_ceiling = grant.budget_ceiling().cloned();
        self.remaining_depth = grant.remaining_depth();
        self.last_grant = Some(grant_id);
        self.status_policy = grant.status_policy().clone();
        Ok(())
    }

    /// Checks an action against the terminal authority.
    ///
    /// # Errors
    ///
    /// Returns the first stable authority failure in protocol order.
    pub fn authorizes(&self, action: &ActionEnvelope) -> Result<(), DenialReason> {
        if action.actor() != &self.subject || action.terminal_grant() != self.last_grant {
            return Err(DenialReason::BrokenGrantChain);
        }
        if self.profile.as_ref().map_or_else(
            || !self.allowed_profiles.contains(action.profile()),
            |profile| profile != action.profile(),
        ) {
            return Err(DenialReason::BrokenGrantChain);
        }
        if !self.permissions.contains(action.permission()) {
            return Err(DenialReason::PermissionNotGranted);
        }
        if !self.validity.contains_window(action.validity()) {
            return Err(DenialReason::ActionOutsideValidity);
        }
        if !self.audiences.contains(action.audience()) {
            return Err(DenialReason::AudienceMismatch);
        }
        if !self
            .action_constraint
            .allows(action.canonical_body_digest())
        {
            return Err(DenialReason::ActionConstraintMismatch);
        }
        if !budget_covers(self.budget_ceiling.as_ref(), action.requested_budget()) {
            return Err(DenialReason::BudgetCeilingExceeded);
        }
        Ok(())
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

fn budget_attenuates(child: Option<&BudgetCeiling>, parent: Option<&BudgetCeiling>) -> bool {
    match (child, parent) {
        (_, None) => true,
        (Some(child), Some(parent)) => child.attenuates(parent),
        (None, Some(_)) => false,
    }
}

fn budget_covers(ceiling: Option<&BudgetCeiling>, requested: Option<&BudgetCeiling>) -> bool {
    match (ceiling, requested) {
        (_, None) | (None, Some(_)) => true,
        (Some(ceiling), Some(requested)) => ceiling.covers(requested),
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
