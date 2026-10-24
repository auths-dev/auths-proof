//! Exact endpoint arithmetic for the final provider-entry gate.

/// Maximum elapsed verification-to-entry time, including fractional seconds.
pub const MAX_ENTRY_ELAPSED_SECONDS: u64 = 60;
/// Nanoseconds preserve the full monotonic clock sample without rounding down.
pub const MAX_ENTRY_ELAPSED_NANOS: u128 = 60_000_000_000;

/// One finite upper endpoint. A half-open permit stays half-open even when
/// another inclusive authorization ends at the same timestamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryBound {
    /// Last timestamp at the boundary.
    pub not_after: u64,
    /// Whether equality with `not_after` is allowed.
    pub inclusive: bool,
}

/// Intersects two upper endpoints without incrementing or overflowing time.
#[must_use]
pub fn intersect_entry_bounds(left: EntryBound, right: EntryBound) -> EntryBound {
    match left.not_after.cmp(&right.not_after) {
        core::cmp::Ordering::Less => left,
        core::cmp::Ordering::Greater => right,
        core::cmp::Ordering::Equal => EntryBound {
            not_after: left.not_after,
            inclusive: left.inclusive && right.inclusive,
        },
    }
}

/// Checks both the authority endpoint and the lower bound established by
/// verification. Clock rollback never grants a new provider entry.
#[must_use]
pub fn entry_time_allows(evaluated_at: u64, now: u64, bound: EntryBound) -> bool {
    now >= evaluated_at && (now < bound.not_after || (now == bound.not_after && bound.inclusive))
}

/// The complete time gate used both by the driver and at HTTP dispatch. Missing
/// clock/qualification samples refuse. The original native authority, prepared
/// installation and currently checked installation all constrain this entry;
/// elapsed time uses nanoseconds so 60 seconds plus one nanosecond refuses.
/// This function does not establish clock correctness or authorize a request.
#[must_use]
pub fn entry_gate_allows(
    evaluated_at: u64,
    now: Option<u64>,
    authority: EntryBound,
    prepared: EntryBound,
    current: Option<EntryBound>,
    elapsed_nanos: u128,
) -> bool {
    let Some(now) = now else { return false; };
    let Some(current) = current else { return false; };
    if elapsed_nanos > MAX_ENTRY_ELAPSED_NANOS {
        return false;
    }
    let bound = intersect_entry_bounds(authority, intersect_entry_bounds(prepared, current));
    entry_time_allows(evaluated_at, now, bound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_full_gate_matches_every_independent_endpoint_and_exact_elapsed_time() {
        // Independent oracle checks each original endpoint, without computing
        // an intersection or calling either source predicate.
        let permits = |bound: EntryBound, now: u64| {
            now < bound.not_after || (now == bound.not_after && bound.inclusive)
        };
        let endpoints = [0, 9, 10, 11, u64::MAX];
        for authority_at in endpoints {
            for prepared_at in endpoints {
                for current_at in endpoints {
                    for inclusive in 0_u8..8 {
                        let authority = EntryBound { not_after: authority_at, inclusive: inclusive & 1 != 0 };
                        let prepared = EntryBound { not_after: prepared_at, inclusive: inclusive & 2 != 0 };
                        let current = EntryBound { not_after: current_at, inclusive: inclusive & 4 != 0 };
                        for now in [None, Some(0), Some(9), Some(10), Some(11), Some(u64::MAX)] {
                            for current in [None, Some(current)] {
                                for elapsed in [0, 59_999_999_999, 60_000_000_000, 60_000_000_001, u128::MAX] {
                                    let expected = match (now, current) {
                                        (Some(now), Some(current)) => now >= 10
                                            && elapsed <= 60_000_000_000
                                            && permits(authority, now)
                                            && permits(prepared, now)
                                            && permits(current, now),
                                        _ => false,
                                    };
                                    assert_eq!(entry_gate_allows(10, now, authority, prepared, current, elapsed), expected);
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(u128::from(MAX_ENTRY_ELAPSED_SECONDS) * 1_000_000_000, MAX_ENTRY_ELAPSED_NANOS);
    }
}
