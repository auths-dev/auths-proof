//! Public batch-conflict interpretation. No branch grants execution authority.

/// The only progress a failed atomic reservation may request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryTarget {
    /// The logical claim already exists; never retry ownership acquisition.
    Replay,
    /// Advance one count frontier by exactly one.
    Count { position: usize, next: u64 },
    /// Read this exact sum slot before advancing its frontier.
    Sum {
        position: usize,
        read_slot: u64,
        next: u64,
    },
    /// The backend index or local frontier cannot represent safe progress.
    Corrupt,
}

/// Interprets the index of the existing member of a claim/count/sum batch.
/// All index arithmetic is guarded and frontier additions are checked, so a
/// malformed backend response or corrupt frontier fails closed.
#[must_use]
pub fn retry_target(
    index: usize,
    counts: &[u64],
    sums: &[u64],
    totals_len: usize,
    sum_counters_len: usize,
) -> RetryTarget {
    if index == 0 {
        return RetryTarget::Replay;
    }
    let position = index - 1;
    if position < counts.len() {
        return match counts[position].checked_add(1) {
            Some(next) => RetryTarget::Count { position, next },
            None => RetryTarget::Corrupt,
        };
    }
    let position = position - counts.len();
    if position >= sums.len() || position >= totals_len || position >= sum_counters_len {
        return RetryTarget::Corrupt;
    }
    let read_slot = sums[position];
    match read_slot.checked_add(1) {
        Some(next) => RetryTarget::Sum {
            position,
            read_slot,
            next,
        },
        None => RetryTarget::Corrupt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conflicts_keep_the_claim_count_sum_batch_order() {
        let counts = [4, 9];
        let sums = [2];
        assert_eq!(retry_target(0, &counts, &sums, 1, 1), RetryTarget::Replay);
        assert_eq!(
            retry_target(1, &counts, &sums, 1, 1),
            RetryTarget::Count {
                position: 0,
                next: 5
            }
        );
        assert_eq!(
            retry_target(2, &counts, &sums, 1, 1),
            RetryTarget::Count {
                position: 1,
                next: 10
            }
        );
        assert_eq!(
            retry_target(3, &counts, &sums, 1, 1),
            RetryTarget::Sum {
                position: 0,
                read_slot: 2,
                next: 3
            }
        );
        assert_eq!(retry_target(4, &counts, &sums, 1, 1), RetryTarget::Corrupt);
    }

    #[test]
    fn malformed_indices_missing_arrays_and_overflow_fail_closed() {
        for counts in [
            alloc::vec![],
            alloc::vec![0],
            alloc::vec![u64::MAX - 1],
            alloc::vec![u64::MAX],
        ] {
            for sums in [
                alloc::vec![],
                alloc::vec![0],
                alloc::vec![u64::MAX - 1],
                alloc::vec![u64::MAX],
            ] {
                for total_size in 0..=2 {
                    for counter_size in 0..=2 {
                        for index in [0, 1, 2, 3, 4, usize::MAX] {
                            match retry_target(index, &counts, &sums, total_size, counter_size) {
                                RetryTarget::Replay => assert_eq!(index, 0),
                                RetryTarget::Count { position, next } => {
                                    assert_eq!(index, position + 1);
                                    assert_eq!(
                                        counts.get(position).and_then(|value| value.checked_add(1)),
                                        Some(next)
                                    );
                                }
                                RetryTarget::Sum {
                                    position,
                                    read_slot,
                                    next,
                                } => {
                                    assert_eq!(index, counts.len() + position + 1);
                                    assert!(position < total_size && position < counter_size);
                                    assert_eq!(sums.get(position), Some(&read_slot));
                                    assert_eq!(read_slot.checked_add(1), Some(next));
                                }
                                RetryTarget::Corrupt => assert_ne!(index, 0),
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(
            retry_target(usize::MAX, &[], &[0], usize::MAX, usize::MAX),
            RetryTarget::Corrupt
        );
        assert_eq!(
            retry_target(1, &[u64::MAX], &[], 0, 0),
            RetryTarget::Corrupt
        );
        assert_eq!(
            retry_target(1, &[], &[u64::MAX], 1, 1),
            RetryTarget::Corrupt
        );
        assert_eq!(
            retry_target(1, &[u64::MAX - 1], &[], 0, 0),
            RetryTarget::Count {
                position: 0,
                next: u64::MAX
            }
        );
    }
}
