//! Exact endpoint arithmetic for the final provider-entry gate.

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
    if left.not_after < right.not_after {
        left
    } else if right.not_after < left.not_after {
        right
    } else {
        EntryBound {
            not_after: left.not_after,
            inclusive: left.inclusive && right.inclusive,
        }
    }
}

/// Checks both the authority endpoint and the lower bound established by
/// verification. Clock rollback never grants a new provider entry.
#[must_use]
pub fn entry_time_allows(evaluated_at: u64, now: u64, bound: EntryBound) -> bool {
    now >= evaluated_at && (now < bound.not_after || (now == bound.not_after && bound.inclusive))
}
