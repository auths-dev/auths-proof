//! Aeneas-shaped pure production primitives.
//!
//! These functions allocate nothing and contain no strings, callbacks, I/O,
//! or hidden state; the tightening decider reads owned byte vectors its
//! caller projects. Public carriers validate and project their rich values
//! into this boundary; the same functions execute in production and are
//! translated.

use alloc::vec::Vec;

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

/// The index of the fixed, epoch-aligned window of `window_seconds` that
/// contains `now`; `None` for a zero-length window.
#[must_use]
pub const fn window_index(now: u64, window_seconds: u64) -> Option<u64> {
    now.checked_div(window_seconds)
}

/// Whether every distinct count counter of a chain has room: `counts[i]` is
/// the number of slots counter `i` already holds in the current window and
/// `capacities[i]` the smallest maximum count of the links that share it.
/// Slices of different lengths never admit.
#[must_use]
pub fn chain_counts_admit(counts: &[u64], capacities: &[u64]) -> bool {
    if counts.len() != capacities.len() {
        return false;
    }
    let mut index = 0;
    while index < counts.len() {
        if counts[index] >= capacities[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Whether every distinct sum counter of a chain has room for `argument`:
/// `sums[i]` is counter `i`'s running sum in the current window and
/// `capacities[i]` the smallest sum limit of the links that share it. Each
/// addition is checked, and an overflow refuses. Slices of different lengths
/// never admit.
#[must_use]
pub fn chain_sums_admit(sums: &[u64], argument: u64, capacities: &[u64]) -> bool {
    if sums.len() != capacities.len() {
        return false;
    }
    let mut index = 0;
    while index < sums.len() {
        match sums[index].checked_add(argument) {
            None => return false,
            Some(total) => {
                if total > capacities[index] {
                    return false;
                }
            }
        }
        index += 1;
    }
    true
}

/// A policy's list of admitted values for one named verified argument.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValueList {
    /// The UTF-8 bytes of the argument name.
    pub argument: Vec<u8>,
    /// The admitted values' bytes.
    pub values: Vec<Vec<u8>>,
}

/// A policy's sum limit and optional partition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SumBound {
    /// The largest window sum of the bounded argument.
    pub limit: u64,
    /// The argument whose value selects the sum counter, and the values a
    /// grant lists for it.
    pub partition: Option<ValueList>,
}

/// The members of one argument-ceiling policy the tightening decider reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyMembers {
    /// The UTF-8 bytes of the bounded argument's name.
    pub argument: Vec<u8>,
    /// The largest admitted argument value.
    pub ceiling: u64,
    /// The fixed window length, in seconds.
    pub window: u64,
    /// The largest number of actions per counter per window.
    pub max_count: u64,
    /// The optional sum limit and partition.
    pub sum: Option<SumBound>,
    /// The optional scope.
    pub scope: Option<ValueList>,
}

/// Byte equality of two slices.
#[must_use]
pub fn bytes_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Whether `values` holds `value`.
#[must_use]
pub fn values_contain(values: &[Vec<u8>], value: &[u8]) -> bool {
    let mut index = 0;
    while index < values.len() {
        if bytes_equal(&values[index], value) {
            return true;
        }
        index += 1;
    }
    false
}

/// Whether every value of `child` is in `parent`.
#[must_use]
pub fn values_subset(child: &[Vec<u8>], parent: &[Vec<u8>]) -> bool {
    let mut index = 0;
    while index < child.len() {
        if !values_contain(parent, &child[index]) {
            return false;
        }
        index += 1;
    }
    true
}

/// The same argument, and a subset of the parent's values.
#[must_use]
pub fn values_narrow(child: &ValueList, parent: &ValueList) -> bool {
    bytes_equal(&child.argument, &parent.argument) && values_subset(&child.values, &parent.values)
}

/// Whether a child partition narrows its parent's: none under none, or the
/// same argument with a subset of the values.
#[must_use]
#[allow(
    clippy::redundant_pattern_matching,
    reason = "a match translates without a model of `Option::is_none`"
)]
pub fn partition_narrows(child: &Option<ValueList>, parent: &Option<ValueList>) -> bool {
    match parent {
        None => match child {
            None => true,
            Some(_) => false,
        },
        Some(parent) => match child {
            None => false,
            Some(child) => values_narrow(child, parent),
        },
    }
}

/// A parent without a sum accepts any child; otherwise the child keeps a sum
/// no larger, with the parent's partition argument and a subset of its
/// values, or no partition when the parent has none.
#[must_use]
pub fn sum_tightens(child: &Option<SumBound>, parent: &Option<SumBound>) -> bool {
    match parent {
        None => true,
        Some(parent) => match child {
            None => false,
            Some(child) => {
                child.limit <= parent.limit
                    && partition_narrows(&child.partition, &parent.partition)
            }
        },
    }
}

/// A parent without a scope accepts any child; otherwise the child keeps a
/// scope on the same argument with a subset of its values.
#[must_use]
pub fn scope_tightens(child: &Option<ValueList>, parent: &Option<ValueList>) -> bool {
    match parent {
        None => true,
        Some(parent) => match child {
            None => false,
            Some(child) => values_narrow(child, parent),
        },
    }
}

/// The registered tightening decider of policy `/2`: the same argument,
/// [`ceiling_count_tightens`], and the sum, partition, and scope rules. A
/// child that adds a sum or scope under a parent without one only narrows.
#[must_use]
pub fn argument_policy_tightens(child: &PolicyMembers, parent: &PolicyMembers) -> bool {
    if !bytes_equal(&child.argument, &parent.argument) {
        return false;
    }
    if !ceiling_count_tightens(
        child.ceiling,
        child.max_count,
        child.window,
        parent.ceiling,
        parent.max_count,
        parent.window,
    ) {
        return false;
    }
    if !sum_tightens(&child.sum, &parent.sum) {
        return false;
    }
    scope_tightens(&child.scope, &parent.scope)
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

    /// Up to four counters of symbolic counts and capacities, including
    /// slices of different lengths: the chain admits exactly when the
    /// lengths agree and every counter holds fewer slots than its capacity.
    #[kani::proof]
    #[kani::unwind(6)]
    fn chain_counts_admit_matches_every_counter_having_room() {
        let counts: [u64; 4] = kani::any();
        let capacities: [u64; 4] = kani::any();
        let used: usize = kani::any();
        let declared: usize = kani::any();
        kani::assume(used <= 4 && declared <= 4);
        let expected = used == declared && (0..used).all(|index| counts[index] < capacities[index]);
        assert_eq!(
            chain_counts_admit(&counts[..used], &capacities[..declared]),
            expected
        );
    }

    /// Up to four sum counters of symbolic sums, argument, and capacities:
    /// the chain admits exactly when the lengths agree and every running sum
    /// plus the argument, computed without overflow, is within its capacity.
    #[kani::proof]
    #[kani::unwind(6)]
    fn chain_sums_admit_matches_every_sum_having_room() {
        let sums: [u64; 4] = kani::any();
        let capacities: [u64; 4] = kani::any();
        let argument: u64 = kani::any();
        let used: usize = kani::any();
        let declared: usize = kani::any();
        kani::assume(used <= 4 && declared <= 4);
        let expected = used == declared
            && (0..used).all(|index| {
                u128::from(sums[index]) + u128::from(argument) <= u128::from(capacities[index])
            });
        assert_eq!(
            chain_sums_admit(&sums[..used], argument, &capacities[..declared]),
            expected
        );
    }

    /// One byte of two values: enough to tell equal names apart.
    fn any_name() -> Vec<u8> {
        alloc::vec![u8::from(kani::any::<bool>())]
    }

    /// Up to three values, each one byte of three values: enough for a
    /// child list to hold a value its parent lacks.
    fn any_values() -> Vec<Vec<u8>> {
        let value = || alloc::vec![kani::any::<u8>() % 3];
        match kani::any::<u8>() % 4 {
            0 => Vec::new(),
            1 => alloc::vec![value()],
            2 => alloc::vec![value(), value()],
            _ => alloc::vec![value(), value(), value()],
        }
    }

    fn any_list() -> Option<ValueList> {
        if kani::any() {
            Some(ValueList {
                argument: any_name(),
                values: any_values(),
            })
        } else {
            None
        }
    }

    fn any_members() -> PolicyMembers {
        PolicyMembers {
            argument: any_name(),
            ceiling: kani::any(),
            window: kani::any(),
            max_count: kani::any(),
            sum: if kani::any() {
                Some(SumBound {
                    limit: kani::any(),
                    partition: any_list(),
                })
            } else {
                None
            },
            scope: any_list(),
        }
    }

    /// A child list narrows its parent's: the same argument and a subset of
    /// the values, as sets.
    fn narrows(child: &ValueList, parent: &ValueList) -> bool {
        child.argument == parent.argument
            && child
                .values
                .iter()
                .all(|value| parent.values.contains(value))
    }

    /// Exhaustive over value lists of up to three values: the decider holds
    /// exactly when the argument, window, ceiling, and count tighten, a
    /// parent's sum is kept no larger with a narrowing partition (or none
    /// under none), and a parent's scope is kept narrowing.
    #[kani::proof]
    #[kani::unwind(4)]
    fn argument_policy_tightens_matches_the_tightening_rules() {
        let child = any_members();
        let parent = any_members();
        let sum = match (&child.sum, &parent.sum) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some(child), Some(parent)) => {
                child.limit <= parent.limit
                    && match (&child.partition, &parent.partition) {
                        (None, None) => true,
                        (Some(child), Some(parent)) => narrows(child, parent),
                        _ => false,
                    }
            }
        };
        let scope = match (&child.scope, &parent.scope) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some(child), Some(parent)) => narrows(child, parent),
        };
        let expected = child.argument == parent.argument
            && child.window == parent.window
            && child.ceiling <= parent.ceiling
            && child.max_count <= parent.max_count
            && sum
            && scope;
        assert_eq!(argument_policy_tightens(&child, &parent), expected);
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
    fn chain_counts_admit_only_when_every_counter_has_room() {
        assert!(chain_counts_admit(&[], &[]));
        assert!(chain_counts_admit(&[0, 2], &[1, 3]));
        assert!(!chain_counts_admit(&[0, 3], &[1, 3]));
        assert!(!chain_counts_admit(&[0], &[1, 3]));
        assert!(!chain_counts_admit(&[0, 0], &[1]));
    }

    #[test]
    fn chain_sums_admit_is_inclusive_and_refuses_overflow() {
        assert!(chain_sums_admit(&[400], 600, &[1_000]));
        assert!(!chain_sums_admit(&[400], 601, &[1_000]));
        assert!(!chain_sums_admit(&[u64::MAX], 1, &[u64::MAX]));
        assert!(!chain_sums_admit(&[0, 0], 1, &[1]));
        assert!(chain_sums_admit(&[0, 900], 100, &[100, 1_000]));
    }

    fn list(argument: &str, values: &[&str]) -> ValueList {
        ValueList {
            argument: argument.as_bytes().to_vec(),
            values: values
                .iter()
                .map(|value| value.as_bytes().to_vec())
                .collect(),
        }
    }

    fn members(sum: Option<SumBound>, scope: Option<ValueList>) -> PolicyMembers {
        PolicyMembers {
            argument: b"amount".to_vec(),
            ceiling: 1_000,
            window: 86_400,
            max_count: 10,
            sum,
            scope,
        }
    }

    #[test]
    fn argument_policy_tightening_follows_the_sum_partition_and_scope_rules() {
        let usd = Some(list("currency", &["usd"]));
        let eur_usd = Some(list("currency", &["eur", "usd"]));
        let sum = |limit, partition: &Option<ValueList>| {
            Some(SumBound {
                limit,
                partition: partition.clone(),
            })
        };
        let parent = members(sum(1_000, &usd), Some(list("connect_account", &["acct_1"])));
        assert!(argument_policy_tightens(&parent, &parent));
        let narrower = members(sum(500, &usd), Some(list("connect_account", &["acct_1"])));
        assert!(argument_policy_tightens(&narrower, &parent));
        for expanded in [
            members(None, parent.scope.clone()),
            members(sum(2_000, &usd), parent.scope.clone()),
            members(sum(1_000, &eur_usd), parent.scope.clone()),
            members(sum(1_000, &None), parent.scope.clone()),
            members(
                sum(1_000, &Some(list("operation_id", &["usd"]))),
                parent.scope.clone(),
            ),
            members(sum(1_000, &usd), None),
            members(
                sum(1_000, &usd),
                Some(list("connect_account", &["acct_1", "acct_2"])),
            ),
        ] {
            assert!(!argument_policy_tightens(&expanded, &parent));
        }
        let unpartitioned = members(sum(1_000, &None), None);
        assert!(!argument_policy_tightens(
            &members(sum(1_000, &usd), None),
            &unpartitioned
        ));
        assert!(argument_policy_tightens(
            &members(sum(500, &usd), None),
            &members(None, None)
        ));
        let mut other_argument = parent.clone();
        other_argument.argument = b"quantity".to_vec();
        assert!(!argument_policy_tightens(&other_argument, &parent));
        let mut other_window = parent.clone();
        other_window.window = 3_600;
        assert!(!argument_policy_tightens(&other_window, &parent));
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
