//! Pure binary-search state for an append-only occupied slot prefix.
//! The runtime performs each requested read; this module has no store access.

/// A bounded search interval. Only the constructor and observed-read transition
/// can create a state, preserving `lower <= upper <= original bound`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrontierSearch {
    lower: u64,
    upper: u64,
}

impl FrontierSearch {
    /// Starts a search for the first unoccupied slot below `bound`. Zero means
    /// the counter has no available slots. The complete `u64` domain is valid.
    #[must_use]
    pub const fn new(bound: u64) -> Self {
        Self {
            lower: 0,
            upper: bound,
        }
    }

    /// The next slot to read, or `None` when the interval has closed. A probe
    /// is strictly below the original bound, including at `u64::MAX`.
    #[must_use]
    pub const fn probe(self) -> Option<u64> {
        if self.lower < self.upper {
            Some(self.lower + (self.upper - self.lower) / 2)
        } else {
            None
        }
    }

    /// Consumes the occupancy result for this state's probe. Every nonterminal
    /// transition shrinks the interval. Terminal states remain unchanged.
    #[must_use]
    pub const fn observe(self, occupied: bool) -> Self {
        match self.probe() {
            Some(middle) => {
                if occupied {
                    Self {
                        lower: middle + 1,
                        upper: self.upper,
                    }
                } else {
                    Self {
                        lower: self.lower,
                        upper: middle,
                    }
                }
            }
            None => self,
        }
    }

    /// The candidate frontier. The runtime uses it only after `probe` returns
    /// `None`; concurrent insertions can make it stale and require a retry.
    #[must_use]
    pub const fn candidate(self) -> u64 {
        self.lower
    }
}

#[cfg(test)]
mod tests {
    use super::FrontierSearch;
    use alloc::vec::Vec;

    fn original(bound: u64, mut occupied: impl FnMut(u64) -> bool) -> u64 {
        let (mut low, mut high) = (0, bound);
        while low < high {
            let middle = low + (high - low) / 2;
            if occupied(middle) {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        low
    }

    fn run(bound: u64, mut occupied: impl FnMut(u64) -> bool) -> (u64, Vec<u64>) {
        let mut state = FrontierSearch::new(bound);
        let mut reads = Vec::new();
        while let Some(slot) = state.probe() {
            assert!(slot < bound);
            reads.push(slot);
            assert!(reads.len() <= 64);
            state = state.observe(occupied(slot));
        }
        assert_eq!(state.observe(false), state);
        assert_eq!(state.observe(true), state);
        (state.candidate(), reads)
    }

    #[test]
    fn every_small_prefix_and_sparse_observation_matches_the_previous_loop() {
        for bound in 0..=256 {
            for frontier in 0..=bound {
                let (candidate, reads) = run(bound, |slot| slot < frontier);
                let mut expected_reads = Vec::new();
                assert_eq!(
                    candidate,
                    original(bound, |slot| {
                        expected_reads.push(slot);
                        slot < frontier
                    })
                );
                assert_eq!(candidate, frontier);
                assert_eq!(reads, expected_reads);
            }
        }
        for mask in 0..=u16::MAX {
            let (candidate, reads) = run(16, |slot| mask & (1 << slot) != 0);
            let mut expected_reads = Vec::new();
            assert_eq!(
                candidate,
                original(16, |slot| {
                    expected_reads.push(slot);
                    mask & (1 << slot) != 0
                })
            );
            assert_eq!(reads, expected_reads);
        }
    }

    #[test]
    fn full_width_and_monotone_concurrent_prefixes_keep_the_candidate_conservative() {
        for bound in [0, 1, 2, 3, 63, 64, 65, u64::MAX - 1, u64::MAX] {
            for frontier in [0, 1, bound / 2, bound.saturating_sub(1), bound] {
                let frontier = frontier.min(bound);
                assert_eq!(run(bound, |slot| slot < frontier).0, frontier);
            }
            let mut committed = 0_u64;
            let mut seed = 0x2040_0199_u64;
            let (candidate, _) = run(bound, |slot| {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                committed = committed.saturating_add(seed % 17).min(bound);
                slot < committed
            });
            assert!(candidate <= committed);
            if candidate >= committed {
                assert_eq!(candidate, committed);
            }
        }
    }
}
