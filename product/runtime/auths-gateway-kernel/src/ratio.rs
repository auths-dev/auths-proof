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
