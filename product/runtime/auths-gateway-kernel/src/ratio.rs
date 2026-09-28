//! The relative ceiling: one integer basis read from the provider after the
//! lease, and one exact comparison of the verified argument against a
//! declared ratio of it.
//!
//! This module is a translated leaf. It uses no loops, no floating point,
//! and no standard-library call; the comparison widens both products to
//! `u128`, where neither can overflow.

/// The number of basis points in one whole.
pub const BASIS_POINTS_PER_WHOLE: u128 = 10_000;

/// The basis of a relative ceiling: `value`, or `value` minus `subtrahend`
/// when a second pointer is declared. A negative difference is unavailable,
/// never zero.
#[must_use]
pub const fn relative_basis(value: u64, subtrahend: Option<u64>) -> Option<u64> {
    match subtrahend {
        None => Some(value),
        Some(second) => {
            if second <= value {
                Some(value - second)
            } else {
                None
            }
        }
    }
}

/// Whether `argument` is within `basis_points` ten-thousandths of `basis`:
/// `argument × 10 000 ≤ basis × basis_points`. This equals
/// `argument ≤ floor(basis × basis_points / 10 000)`, so the ceiling rounds
/// toward zero, the boundary is inclusive, and a zero basis admits only a
/// zero argument. Both products are below 2^78.
#[must_use]
pub const fn relative_ceiling_admits(argument: u64, basis: u64, basis_points: u16) -> bool {
    let scaled_argument = (argument as u128) * BASIS_POINTS_PER_WHOLE;
    let scaled_basis = (basis as u128) * (basis_points as u128);
    scaled_argument <= scaled_basis
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basis_is_the_difference_or_unavailable() {
        assert_eq!(relative_basis(1_001, None), Some(1_001));
        assert_eq!(relative_basis(1_001, Some(1)), Some(1_000));
        assert_eq!(relative_basis(1_001, Some(1_001)), Some(0));
        assert_eq!(relative_basis(1_001, Some(1_002)), None);
        assert_eq!(relative_basis(u64::MAX, Some(0)), Some(u64::MAX));
    }

    #[test]
    fn ceiling_agrees_with_floor_division_around_every_exact_multiple() {
        for basis in [0_u64, 1, 2, 999, 1_000, 1_001, 10_000, 123_457] {
            for basis_points in [1_u16, 2, 5_000, 9_999, 10_000] {
                let ceiling = u64::try_from(
                    u128::from(basis) * u128::from(basis_points) / BASIS_POINTS_PER_WHOLE,
                )
                .unwrap_or(u64::MAX);
                for argument in [ceiling.saturating_sub(1), ceiling, ceiling + 1] {
                    assert_eq!(
                        relative_ceiling_admits(argument, basis, basis_points),
                        argument <= ceiling,
                        "argument {argument} basis {basis} points {basis_points}"
                    );
                }
            }
        }
        assert!(relative_ceiling_admits(500, 1_001, 5_000));
        assert!(!relative_ceiling_admits(501, 1_001, 5_000));
        assert!(relative_ceiling_admits(0, 0, 1));
        assert!(!relative_ceiling_admits(1, 0, 10_000));
        assert!(relative_ceiling_admits(u64::MAX, u64::MAX, 10_000));
        assert!(!relative_ceiling_admits(u64::MAX, u64::MAX, 9_999));
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Symbolic over every `u64` argument and basis and every `u16` basis
    /// point: the leaf never overflows. Its products stay below 2^78.
    #[kani::proof]
    fn relative_ceiling_admits_never_overflows() {
        let argument: u64 = kani::any();
        let basis: u64 = kani::any();
        let basis_points: u16 = kani::any();
        let _ = relative_ceiling_admits(argument, basis, basis_points);
    }

    /// Symbolic over every argument and basis below 2^8 and every basis
    /// point in 1–10 000: the leaf admits exactly the arguments at most
    /// `floor(basis × basis_points / 10 000)`. The full-width statement is
    /// the Lean theorem `relative_ceiling_exact` over the translated leaf: a
    /// SAT solver cannot compare the leaf's multiplier with a second one at
    /// 64 bits, or even at 16, within the gate's time budget.
    #[kani::proof]
    fn relative_ceiling_admits_matches_floor_division() {
        let argument: u8 = kani::any();
        let basis: u8 = kani::any();
        let basis_points: u16 = kani::any();
        kani::assume((1..=10_000).contains(&basis_points));
        let floor = u32::from(basis) * u32::from(basis_points) / 10_000;
        assert_eq!(
            relative_ceiling_admits(u64::from(argument), u64::from(basis), basis_points),
            u32::from(argument) <= floor
        );
    }

    /// Symbolic over every value and subtrahend: the basis is exactly
    /// checked subtraction, and the value itself without a subtrahend.
    #[kani::proof]
    fn relative_basis_is_checked_subtraction() {
        let value: u64 = kani::any();
        let second: u64 = kani::any();
        assert_eq!(relative_basis(value, None), Some(value));
        assert_eq!(
            relative_basis(value, Some(second)),
            value.checked_sub(second)
        );
    }
}
