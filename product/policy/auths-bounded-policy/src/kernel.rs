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
