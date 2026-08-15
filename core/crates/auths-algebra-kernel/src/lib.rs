//! Mechanically linked target V1 attenuation and composition algebra.

#![no_std]
#![forbid(unsafe_code)]
#![allow(unexpected_cfgs)]

mod generated;

pub use generated::{
    AttenuationChecks, AttenuationProjection, CONTRACT_SCHEMA, EXHAUSTIVE_THRESHOLD_BOUND, Truth,
    attenuation_accepts, attenuation_checks_accept, threshold_counts,
};

/// The chain-linkage facts one delegation edge presents to the trust-root
/// dimension of [`AttenuationChecks`].
///
/// The identity type is abstract on purpose: the production kernel supplies
/// borrowed `PrincipalId` values, bounded proofs supply small scalars, and both
/// obtain the same decision from [`root_preserved`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootLinkage<Identity> {
    /// Trust root the parent authority is anchored at.
    pub parent_root: Identity,
    /// Principal the parent authority currently speaks for.
    pub parent_subject: Identity,
    /// Whether the parent has already applied at least one grant, so its
    /// subject was reached from `parent_root` by an accepted edge rather than
    /// by being the root itself.
    pub parent_delegated: bool,
    /// Principal that issued the edge under evaluation.
    pub grant_issuer: Identity,
}

/// Accepts exactly when the edge continues the chain rooted at `parent_root`.
///
/// Two independent facts are required, and neither is implied by the other:
///
/// 1. the parent state genuinely descends from the root it claims — it is
///    either the root itself (no grant applied yet) or it reached its subject
///    through an accepted edge that already carried the root forward; and
/// 2. the edge is issued by the parent's own subject, so the authority being
///    extended is the one the root conferred.
///
/// An accepted transition copies `parent_root` unchanged, so these two facts
/// are exactly what makes the child descend from the same root as the parent.
/// Because delegation acceptance is the conjunction over every dimension, a
/// false result here can never be rescued by any other dimension.
#[must_use]
pub fn root_preserved<Identity: PartialEq>(linkage: &RootLinkage<Identity>) -> bool {
    (linkage.parent_delegated || linkage.parent_root == linkage.parent_subject)
        && linkage.grant_issuer == linkage.parent_subject
}

#[cfg(kani)]
mod kani_harnesses {
    use super::{
        AttenuationChecks, RootLinkage, Truth, attenuation_accepts, attenuation_checks_accept,
        root_preserved, threshold_counts,
    };

    /// Bounded identity carrier. Principals are compared only for equality, so
    /// a scalar with more than two inhabitants is a faithful model: every
    /// equal/distinct arrangement of the four identities in a `RootLinkage` is
    /// reachable, and `kani::any()` explores all of them.
    type Identity = u8;

    fn any_linkage() -> RootLinkage<Identity> {
        RootLinkage {
            parent_root: kani::any(),
            parent_subject: kani::any(),
            parent_delegated: kani::any(),
            grant_issuer: kani::any(),
        }
    }

    #[kani::proof]
    fn root_preservation_requires_an_anchored_edge() {
        let linkage = any_linkage();
        let preserved = root_preserved(&linkage);

        // An edge issued by anyone other than the parent's subject extends an
        // authority the root never conferred.
        if linkage.grant_issuer != linkage.parent_subject {
            assert!(!preserved);
        }
        // A parent that has applied no grant and whose subject is not the root
        // it claims descends from no root at all.
        if !linkage.parent_delegated && linkage.parent_root != linkage.parent_subject {
            assert!(!preserved);
        }
        // Preservation is not vacuous in the other direction either: whenever
        // both facts hold the dimension must accept, so the check cannot be
        // satisfied by refusing everything.
        if linkage.grant_issuer == linkage.parent_subject
            && (linkage.parent_delegated || linkage.parent_root == linkage.parent_subject)
        {
            assert!(preserved);
        }
    }

    #[kani::proof]
    fn a_broken_root_cannot_be_rescued_by_any_other_dimension() {
        let linkage = any_linkage();
        let checks = AttenuationChecks {
            root_preserved: root_preserved(&linkage),
            depth_decreases: kani::any(),
            profile_attenuates: kani::any(),
            permissions_attenuate: kani::any(),
            validity_attenuates: kani::any(),
            audiences_attenuate: kani::any(),
            action_constraint_attenuates: kani::any(),
            budget_attenuates: kani::any(),
            status_attenuates: kani::any(),
            assurance_attenuates: kani::any(),
            extensions_attenuate: kani::any(),
        };
        let unrooted_parent =
            !linkage.parent_delegated && linkage.parent_root != linkage.parent_subject;
        if unrooted_parent || linkage.grant_issuer != linkage.parent_subject {
            assert!(!attenuation_accepts(&checks));
            assert!(!attenuation_checks_accept(&checks));
        }
    }

    #[kani::proof]
    fn an_accepted_edge_leaves_the_child_under_the_parent_root() {
        let linkage = any_linkage();
        kani::assume(root_preserved(&linkage));
        // `acceptedNextState` copies the parent root, so the child root is
        // `parent_root` by construction; the reachable content of the claim is
        // that the edge starts at a principal the root actually authorised.
        let child_root = linkage.parent_root;
        assert!(child_root == linkage.parent_root);
        assert!(linkage.grant_issuer == linkage.parent_subject);
        assert!(linkage.parent_delegated || linkage.grant_issuer == linkage.parent_root);
    }

    #[kani::proof]
    fn threshold_partition_matches_contract() {
        let authorized: u16 = kani::any();
        let indeterminate: u16 = kani::any();
        let required: u16 = kani::any();
        kani::assume(authorized <= super::EXHAUSTIVE_THRESHOLD_BOUND);
        kani::assume(indeterminate <= super::EXHAUSTIVE_THRESHOLD_BOUND - authorized);
        kani::assume(required > 0 && required <= super::EXHAUSTIVE_THRESHOLD_BOUND);

        let result = threshold_counts(
            required,
            usize::from(authorized),
            usize::from(indeterminate),
        );
        assert!(
            (result == Truth::Authorized && authorized >= required)
                || (result == Truth::Indeterminate
                    && authorized < required
                    && authorized + indeterminate >= required)
                || (result == Truth::Denied && authorized + indeterminate < required)
        );
    }

    #[kani::proof]
    fn attenuation_accepts_exactly_the_conjunction() {
        let checks = AttenuationChecks {
            root_preserved: kani::any(),
            depth_decreases: kani::any(),
            profile_attenuates: kani::any(),
            permissions_attenuate: kani::any(),
            validity_attenuates: kani::any(),
            audiences_attenuate: kani::any(),
            action_constraint_attenuates: kani::any(),
            budget_attenuates: kani::any(),
            status_attenuates: kani::any(),
            assurance_attenuates: kani::any(),
            extensions_attenuate: kani::any(),
        };
        let expected = checks.root_preserved
            && checks.depth_decreases
            && checks.profile_attenuates
            && checks.permissions_attenuate
            && checks.validity_attenuates
            && checks.audiences_attenuate
            && checks.action_constraint_attenuates
            && checks.budget_attenuates
            && checks.status_attenuates
            && checks.assurance_attenuates
            && checks.extensions_attenuate;
        let generic = attenuation_accepts(&checks);
        let concrete = attenuation_checks_accept(&checks);
        assert!(generic == expected);
        assert!(concrete == expected);
        assert!(generic == concrete);
    }
}
