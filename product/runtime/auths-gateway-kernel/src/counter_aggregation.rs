//! A keyed capacity update retains the first key position and the smallest
//! capacity of every contribution to that key. Inputs are public counter IDs.

use alloc::vec::Vec;

/// One shared counter and its tightest capacity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CounterCapacity {
    /// Domain-separated counter ID.
    pub key: [u8; 32],
    /// Smallest capacity contributed so far.
    pub capacity: u64,
}

/// Exact public counter-ID equality. These IDs contain no secret material.
#[must_use]
pub fn counter_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut index = 0;
    while index < 32 {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Finds the first exact counter key; an absent key has no position.
#[must_use]
pub fn counter_position(counters: &[CounterCapacity], key: &[u8; 32]) -> Option<usize> {
    let mut index = 0;
    while index < counters.len() {
        if counter_equal(&counters[index].key, key) {
            return Some(index);
        }
        index += 1;
    }
    None
}

/// The first exact count counter's capacity, or zero when absent. An absent
/// link therefore grants no sum slots. Counter IDs are public identifiers.
#[must_use]
pub fn count_capacity(counters: &[CounterCapacity], key: &[u8; 32]) -> u64 {
    match counter_position(counters, key) {
        Some(index) => counters[index].capacity,
        None => 0,
    }
}

/// Builds one sum contribution using the shared count counter's actual
/// minimum as its slot bound. Callers derive both IDs from the same link.
#[must_use]
pub fn linked_sum_contribution(
    counts: &[CounterCapacity],
    count_key: &[u8; 32],
    sum_key: [u8; 32],
    capacity: u64,
) -> SumCapacity {
    SumCapacity {
        key: sum_key,
        capacity,
        slots: count_capacity(counts, count_key),
    }
}

/// Adds one contribution to the same shared counter. This function never
/// increases an existing capacity or appends a second copy of an existing ID.
#[must_use]
pub fn contribute(
    mut counters: Vec<CounterCapacity>,
    key: [u8; 32],
    capacity: u64,
) -> Vec<CounterCapacity> {
    match counter_position(&counters, &key) {
        Some(index) => {
            if capacity < counters[index].capacity {
                counters[index].capacity = capacity;
            }
        }
        None => counters.push(CounterCapacity { key, capacity }),
    }
    counters
}

/// Aggregates every contribution, preserving the first key order and taking
/// the smallest capacity for each shared ID. Gateway chains supply at most
/// sixteen contributions; callers must bound attacker-controlled collections.
#[must_use]
pub fn aggregate(contributions: &[CounterCapacity]) -> Vec<CounterCapacity> {
    let mut counters = Vec::new();
    let mut index = 0;
    while index < contributions.len() {
        let contribution = &contributions[index];
        counters = contribute(counters, contribution.key, contribution.capacity);
        index += 1;
    }
    counters
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linked_sum_slots_use_the_exact_shared_count_capacity() {
        let key = [7; 32];
        let contributions = [
            CounterCapacity {
                key,
                capacity: u64::MAX,
            },
            CounterCapacity {
                key: [8; 32],
                capacity: 19,
            },
            CounterCapacity { key, capacity: 3 },
        ];
        let counts = aggregate(&contributions);
        let sum = linked_sum_contribution(&counts, &key, [9; 32], 700);
        assert_eq!(
            sum,
            SumCapacity {
                key: [9; 32],
                capacity: 700,
                slots: 3
            }
        );
        assert_eq!(count_capacity(&counts, &[10; 32]), 0);
        assert_eq!(count_capacity(&[], &key), 0);
        assert_eq!(count_capacity(&contributions, &key), u64::MAX);
    }

    fn original(
        mut counters: Vec<CounterCapacity>,
        key: [u8; 32],
        capacity: u64,
    ) -> Vec<CounterCapacity> {
        match counters.iter_mut().find(|counter| counter.key == key) {
            Some(counter) => counter.capacity = counter.capacity.min(capacity),
            None => counters.push(CounterCapacity { key, capacity }),
        }
        counters
    }

    #[test]
    fn keyed_updates_preserve_the_previous_complete_result() {
        let mut seed = 0x4155_5448_5350_524fu64;
        for length in 0..=24 {
            let mut state = Vec::new();
            for _ in 0..length {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                state.push(CounterCapacity {
                    key: [((seed >> 32) % 7) as u8; 32],
                    capacity: seed,
                });
            }
            for byte in 0..=9 {
                let key = [byte; 32];
                for capacity in [0, 1, 255, u64::MAX] {
                    assert_eq!(
                        contribute(state.clone(), key, capacity),
                        original(state.clone(), key, capacity)
                    );
                    let expected = state.iter().fold(Vec::new(), |prior, entry| {
                        original(prior, entry.key, entry.capacity)
                    });
                    assert_eq!(aggregate(&state), expected);
                }
            }
        }
    }

    #[test]
    fn every_prefix_keeps_one_shared_smallest_capacity() {
        let mut actual = Vec::new();
        let mut expected = alloc::collections::BTreeMap::<[u8; 32], u64>::new();
        let mut seed = 0x4155_5448_534d_494eu64;
        for _ in 0..6000 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let key = [((seed >> 32) % 17) as u8; 32];
            let limit = seed;
            actual = contribute(actual, key, limit);
            expected
                .entry(key)
                .and_modify(|old| *old = (*old).min(limit))
                .or_insert(limit);
            assert_eq!(actual.len(), expected.len());
            for counter in &actual {
                assert_eq!(Some(&counter.capacity), expected.get(&counter.key));
                assert_eq!(
                    actual
                        .iter()
                        .filter(|other| other.key == counter.key)
                        .count(),
                    1
                );
            }
        }
    }

    #[test]
    fn public_counter_equality_and_first_position_are_exact() {
        let key = [42; 32];
        assert!(counter_equal(&key, &key));
        for index in 0..32 {
            let mut changed = key;
            changed[index] ^= 1;
            assert!(!counter_equal(&key, &changed));
            assert!(!counter_equal(&changed, &key));
        }
        let counters = alloc::vec![
            CounterCapacity { key, capacity: 9 },
            CounterCapacity { key, capacity: 1 },
        ];
        assert_eq!(counter_position(&counters, &key), Some(0));
        assert_eq!(counter_position(&counters, &[0; 32]), None);
    }
}

/// A shared sum counter and the count-slot bound derived by its caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SumCapacity {
    /// Domain-separated sum counter ID.
    pub key: [u8; 32],
    /// Smallest sum limit contributed so far.
    pub capacity: u64,
    /// Count-slot bound supplied by the first contribution to this ID.
    pub slots: u64,
}

/// Finds the first exact sum counter ID.
#[must_use]
pub fn sum_position(counters: &[SumCapacity], key: &[u8; 32]) -> Option<usize> {
    let mut index = 0;
    while index < counters.len() {
        if counter_equal(&counters[index].key, key) {
            return Some(index);
        }
        index += 1;
    }
    None
}

/// Tightens a shared sum capacity while preserving the first count-slot bound.
/// The caller derives that bound from the corresponding shared count counter.
#[must_use]
pub fn contribute_sum(
    mut counters: Vec<SumCapacity>,
    key: [u8; 32],
    capacity: u64,
    slots: u64,
) -> Vec<SumCapacity> {
    match sum_position(&counters, &key) {
        Some(index) => {
            if capacity < counters[index].capacity {
                counters[index].capacity = capacity;
            }
        }
        None => counters.push(SumCapacity {
            key,
            capacity,
            slots,
        }),
    }
    counters
}

/// Aggregates every sum contribution in order, without adding another slot
/// pool for duplicate IDs. Gateway chains supply at most sixteen entries.
#[must_use]
pub fn aggregate_sum(contributions: &[SumCapacity]) -> Vec<SumCapacity> {
    let mut counters = Vec::new();
    let mut index = 0;
    while index < contributions.len() {
        let contribution = &contributions[index];
        counters = contribute_sum(
            counters,
            contribution.key,
            contribution.capacity,
            contribution.slots,
        );
        index += 1;
    }
    counters
}

#[cfg(test)]
mod sum_tests {
    use super::*;

    fn original(
        mut counters: Vec<SumCapacity>,
        key: [u8; 32],
        capacity: u64,
        slots: u64,
    ) -> Vec<SumCapacity> {
        match counters.iter_mut().find(|counter| counter.key == key) {
            Some(counter) => counter.capacity = counter.capacity.min(capacity),
            None => counters.push(SumCapacity {
                key,
                capacity,
                slots,
            }),
        }
        counters
    }

    #[test]
    fn sums_preserve_the_first_slot_bound_and_tighten_only_capacity() {
        let key = [9; 32];
        let state = alloc::vec![SumCapacity {
            key,
            capacity: 20,
            slots: 3
        }];
        for capacity in [0, 1, 20, u64::MAX] {
            for slots in [0, 1, 100, u64::MAX] {
                let actual = contribute_sum(state.clone(), key, capacity, slots);
                assert_eq!(actual, original(state.clone(), key, capacity, slots));
                assert_eq!(actual[0].slots, 3);
            }
        }
    }

    #[test]
    fn full_sum_aggregation_preserves_the_previous_result() {
        let mut seed = 0x4155_5448_5353_554du64;
        for length in 0..=24 {
            for _ in 0..64 {
                let mut incoming = Vec::new();
                for _ in 0..length {
                    seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    incoming.push(SumCapacity {
                        key: [((seed >> 32) % 7) as u8; 32],
                        capacity: seed,
                        slots: seed >> 8,
                    });
                }
                let expected = incoming.iter().fold(Vec::new(), |prior, entry| {
                    original(prior, entry.key, entry.capacity, entry.slots)
                });
                assert_eq!(aggregate_sum(&incoming), expected);
            }
        }
    }
}
