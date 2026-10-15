//! Pure collection-fence decisions shared by both gateway stores.

/// Whether a slot may be inserted after the durable collection
/// cutoff. The caller must read the durable cutoff in the same critical
/// section or transaction that inserts the batch.
#[must_use]
pub fn gateway_window_open(expires_at: u64, collected_through: Option<u64>) -> bool {
    match collected_through {
        None => true,
        Some(cutoff) => expires_at > cutoff,
    }
}

/// Advances the durable collection cutoff without allowing an older worker's
/// clock sample to move it backwards. Publication must precede deletion, or
/// be committed atomically with it.
#[must_use]
pub fn advance_gateway_collection(current: Option<u64>, requested: u64) -> u64 {
    match current {
        Some(previous) if previous > requested => previous,
        _ => requested,
    }
}
