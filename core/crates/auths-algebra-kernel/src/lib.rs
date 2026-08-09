//! Mechanically linked target V1 attenuation and composition algebra.

#![no_std]
#![forbid(unsafe_code)]
#![allow(unexpected_cfgs)]

mod generated;

pub use generated::{
    AttenuationChecks, AttenuationProjection, CONTRACT_SCHEMA, EXHAUSTIVE_THRESHOLD_BOUND, Truth,
    attenuation_accepts, attenuation_checks_accept, threshold_counts,
};

#[cfg(kani)]
mod kani_harnesses {
    use super::{
        AttenuationChecks, Truth, attenuation_accepts, attenuation_checks_accept, threshold_counts,
    };

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
