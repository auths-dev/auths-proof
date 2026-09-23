//! Aeneas-shaped pure production primitives.
//!
//! These functions contain no allocation, strings, callbacks, I/O, or hidden
//! state. Public carriers validate and project their rich values into this
//! boundary; the same functions execute in production and are translated.

/// Stable projection result for the configuration gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationMatchCode {
    /// Required and executed configuration meaning matches.
    Match,
    /// Semantic identity differs.
    SemanticMismatch,
    /// Canonicalization identity differs.
    CanonicalizationMismatch,
    /// Canonical configuration bytes differ.
    DigestMismatch,
    /// A required implementation pin differs.
    ImplementationMismatch,
}

/// Applies the immutable configuration diagnostic order.
#[must_use]
#[allow(
    clippy::fn_params_excessive_bools,
    reason = "this generated boundary deliberately projects four independent proof gates"
)]
pub fn configuration_match_code(
    semantic_equal: bool,
    canonicalization_equal: bool,
    digest_equal: bool,
    implementation_equal_or_unpinned: bool,
) -> ConfigurationMatchCode {
    if !semantic_equal {
        ConfigurationMatchCode::SemanticMismatch
    } else if !canonicalization_equal {
        ConfigurationMatchCode::CanonicalizationMismatch
    } else if !digest_equal {
        ConfigurationMatchCode::DigestMismatch
    } else if !implementation_equal_or_unpinned {
        ConfigurationMatchCode::ImplementationMismatch
    } else {
        ConfigurationMatchCode::Match
    }
}

/// Adds two unsigned amounts and returns `None` on overflow.
#[must_use]
pub const fn checked_add_u64(left: u64, right: u64) -> Option<u64> {
    left.checked_add(right)
}

/// Subtracts two unsigned amounts and returns `None` on underflow.
#[must_use]
pub const fn checked_sub_u64(left: u64, right: u64) -> Option<u64> {
    left.checked_sub(right)
}

/// Multiplies two unsigned amounts and returns `None` on overflow.
#[must_use]
pub const fn checked_mul_u64(left: u64, right: u64) -> Option<u64> {
    left.checked_mul(right)
}

/// Divides two unsigned amounts and returns `None` for a zero divisor.
#[must_use]
pub const fn checked_div_u64(left: u64, right: u64) -> Option<u64> {
    left.checked_div(right)
}

/// Stable projection of one argument-ceiling and window-count evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CeilingCountCode {
    /// The value is within the ceiling and the window has room.
    Eligible,
    /// The verified argument value exceeds the ceiling.
    AboveCeiling,
    /// The window already counts the maximum number of authorized actions.
    WindowExhausted,
}

/// Evaluates one verified argument `value` against `ceiling`, and the
/// `count` of actions already authorized in the current window against
/// `max_count`. The ceiling is checked first.
#[must_use]
pub const fn ceiling_count_code(
    value: u64,
    ceiling: u64,
    count: u64,
    max_count: u64,
) -> CeilingCountCode {
    if value > ceiling {
        CeilingCountCode::AboveCeiling
    } else if count >= max_count {
        CeilingCountCode::WindowExhausted
    } else {
        CeilingCountCode::Eligible
    }
}

/// The numeric tightening decider: the child keeps the parent's window, and
/// its ceiling and maximum count are no larger than the parent's.
#[must_use]
pub const fn ceiling_count_tightens(
    child_ceiling: u64,
    child_max_count: u64,
    child_window: u64,
    parent_ceiling: u64,
    parent_max_count: u64,
    parent_window: u64,
) -> bool {
    if child_window != parent_window {
        return false;
    }
    if child_ceiling > parent_ceiling {
        return false;
    }
    child_max_count <= parent_max_count
}

/// The index of the window of `window_seconds` that contains `now`; `None`
/// for a zero-length window.
#[must_use]
pub const fn window_index(now: u64, window_seconds: u64) -> Option<u64> {
    now.checked_div(window_seconds)
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn configuration_match_is_eligible_only_when_every_gate_matches() {
        let semantic_equal = kani::any();
        let canonicalization_equal = kani::any();
        let digest_equal = kani::any();
        let implementation_equal_or_unpinned = kani::any();
        let result = configuration_match_code(
            semantic_equal,
            canonicalization_equal,
            digest_equal,
            implementation_equal_or_unpinned,
        );
        assert_eq!(
            result == ConfigurationMatchCode::Match,
            semantic_equal
                && canonicalization_equal
                && digest_equal
                && implementation_equal_or_unpinned
        );
    }

    #[kani::proof]
    fn checked_add_matches_widened_arithmetic() {
        let left: u64 = kani::any();
        let right: u64 = kani::any();
        let widened = u128::from(left) + u128::from(right);
        match checked_add_u64(left, right) {
            Some(result) => {
                assert_eq!(u128::from(result), widened);
                assert!(widened <= u128::from(u64::MAX));
            }
            None => assert!(widened > u128::from(u64::MAX)),
        }
    }

    #[kani::proof]
    fn checked_sub_never_underflows() {
        let left: u64 = kani::any();
        let right: u64 = kani::any();
        match checked_sub_u64(left, right) {
            Some(result) => {
                assert!(right <= left);
                assert_eq!(result, left - right);
            }
            None => assert!(left < right),
        }
    }

    #[kani::proof]
    fn checked_div_rejects_zero_for_every_dividend() {
        let left: u64 = kani::any();
        assert_eq!(checked_div_u64(left, 0), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceiling_count_checks_the_ceiling_before_the_window() {
        assert_eq!(ceiling_count_code(10, 10, 0, 1), CeilingCountCode::Eligible);
        assert_eq!(
            ceiling_count_code(11, 10, 0, 1),
            CeilingCountCode::AboveCeiling
        );
        assert_eq!(
            ceiling_count_code(10, 10, 1, 1),
            CeilingCountCode::WindowExhausted
        );
        assert_eq!(
            ceiling_count_code(11, 10, 1, 1),
            CeilingCountCode::AboveCeiling
        );
        assert_eq!(window_index(7_200, 3_600), Some(2));
        assert_eq!(window_index(7_200, 0), None);
    }

    #[test]
    fn tightening_decider_is_sound_on_a_grid() {
        for child_ceiling in 0..4 {
            for parent_ceiling in 0..4 {
                for child_max in 0..4 {
                    for parent_max in 0..4 {
                        for (child_window, parent_window) in [(60, 60), (60, 120)] {
                            if !ceiling_count_tightens(
                                child_ceiling,
                                child_max,
                                child_window,
                                parent_ceiling,
                                parent_max,
                                parent_window,
                            ) {
                                continue;
                            }
                            for value in 0..5 {
                                for count in 0..5 {
                                    if ceiling_count_code(value, child_ceiling, count, child_max)
                                        == CeilingCountCode::Eligible
                                    {
                                        assert_eq!(
                                            ceiling_count_code(
                                                value,
                                                parent_ceiling,
                                                count,
                                                parent_max
                                            ),
                                            CeilingCountCode::Eligible
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn configuration_projection_is_exhaustive() {
        for semantic in [false, true] {
            for canonicalization in [false, true] {
                for digest in [false, true] {
                    for implementation in [false, true] {
                        let result = configuration_match_code(
                            semantic,
                            canonicalization,
                            digest,
                            implementation,
                        );
                        assert_eq!(
                            result == ConfigurationMatchCode::Match,
                            semantic && canonicalization && digest && implementation
                        );
                    }
                }
            }
        }
    }
}
