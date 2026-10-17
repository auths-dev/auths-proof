//! Complete claim/count/sum descriptions. Policy guards remain in the caller;
//! this builder checks shape, bounded work, and cumulative arithmetic.
use crate::counter_aggregation::{CounterCapacity, SumCapacity};
use alloc::vec::Vec;

/// The admitted per-kind counter bound used by the gateway.
pub const MAX_COUNTERS_PER_KIND: usize = 16;

/// A complete entry description before canonical record serialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SlotEntry {
    /// The logical-operation claim is always entry zero.
    Claim { key: [u8; 32] },
    /// One count reservation, preserving the counter and frontier order.
    Count { counter: [u8; 32], slot: u64 },
    /// One sum reservation, with the checked new cumulative value.
    Sum {
        counter: [u8; 32],
        slot: u64,
        amount: u64,
        cumulative: u64,
    },
}

/// Describes every slot and the claim, or rejects inconsistent vector shapes,
/// excessive counter counts, and sum overflow before any storage operation.
/// A successful description does not by itself authorize execution.
#[must_use]
#[allow(
    clippy::question_mark,
    reason = "the explicit branch avoids additional Option Try/FromResidual interfaces in this mechanically translated boundary"
)]
pub fn build_batch(
    claim: [u8; 32],
    counts: &[CounterCapacity],
    count_slots: &[u64],
    sums: &[SumCapacity],
    sum_slots: &[u64],
    totals: &[u64],
    amount: u64,
) -> Option<Vec<SlotEntry>> {
    if counts.len() > MAX_COUNTERS_PER_KIND || sums.len() > MAX_COUNTERS_PER_KIND {
        return None;
    }
    if counts.len() != count_slots.len()
        || sums.len() != sum_slots.len()
        || sums.len() != totals.len()
    {
        return None;
    }
    let mut entries = Vec::new();
    entries.push(SlotEntry::Claim { key: claim });
    let mut index = 0;
    while index < counts.len() {
        entries.push(SlotEntry::Count {
            counter: counts[index].key,
            slot: count_slots[index],
        });
        index += 1;
    }
    let mut index = 0;
    while index < sums.len() {
        let Some(cumulative) = totals[index].checked_add(amount) else {
            return None;
        };
        entries.push(SlotEntry::Sum {
            counter: sums[index].key,
            slot: sum_slots[index],
            amount,
            cumulative,
        });
        index += 1;
    }
    Some(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(length: usize) -> Vec<CounterCapacity> {
        (0..length)
            .map(|index| CounterCapacity {
                key: [u8::try_from(index).expect("small index"); 32],
                capacity: u64::MAX,
            })
            .collect()
    }
    fn sums(length: usize) -> Vec<SumCapacity> {
        (0..length)
            .map(|index| SumCapacity {
                key: [128 + u8::try_from(index).expect("small index"); 32],
                capacity: u64::MAX,
                slots: u64::MAX,
            })
            .collect()
    }

    #[test]
    fn every_required_counter_is_present_in_retry_order() {
        for count in 0..=16 {
            for sum in 0..=16 {
                let counts = counts(count);
                let sums = sums(sum);
                let count_slots: Vec<_> = (0..count)
                    .map(|index| u64::try_from(index).expect("small index"))
                    .collect();
                let sum_slots: Vec<_> = (0..sum)
                    .map(|index| u64::try_from(index).expect("small index"))
                    .collect();
                let totals = alloc::vec![10; sum];
                let entries = build_batch(
                    [42; 32],
                    &counts,
                    &count_slots,
                    &sums,
                    &sum_slots,
                    &totals,
                    5,
                )
                .expect("complete batch");
                assert_eq!(entries.len(), 1 + count + sum);
                assert_eq!(entries[0], SlotEntry::Claim { key: [42; 32] });
                for (index, counter) in counts.iter().enumerate() {
                    assert_eq!(
                        entries[1 + index],
                        SlotEntry::Count {
                            counter: counter.key,
                            slot: count_slots[index]
                        }
                    );
                }
                for (index, counter) in sums.iter().enumerate() {
                    assert_eq!(
                        entries[1 + count + index],
                        SlotEntry::Sum {
                            counter: counter.key,
                            slot: sum_slots[index],
                            amount: 5,
                            cumulative: 15
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn no_partial_batch_survives_shape_or_arithmetic_failure() {
        assert_eq!(
            build_batch([0; 32], &counts(1), &[], &[], &[], &[], 0),
            None
        );
        assert_eq!(build_batch([0; 32], &[], &[], &sums(1), &[], &[0], 0), None);
        assert_eq!(build_batch([0; 32], &[], &[], &sums(1), &[0], &[], 0), None);
        assert_eq!(
            build_batch([0; 32], &counts(17), &[0; 17], &[], &[], &[], 0),
            None
        );
        assert_eq!(
            build_batch([0; 32], &[], &[], &sums(17), &[0; 17], &[0; 17], 0),
            None
        );
        assert_eq!(
            build_batch(
                [0; 32],
                &counts(1),
                &[0],
                &sums(2),
                &[0, 1],
                &[0, u64::MAX],
                1
            ),
            None
        );
        assert!(build_batch([0; 32], &[], &[], &sums(1), &[0], &[u64::MAX - 1], 1).is_some());
    }
}
