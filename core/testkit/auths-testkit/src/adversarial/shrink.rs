/// Reproducible byte-level failure used by the deterministic shrinker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ByteFailure {
    /// Minimal failing input.
    pub bytes: Vec<u8>,
    /// Earliest byte offset that differs from the seed.
    pub first_difference: Option<usize>,
}

/// Deterministically removes suffix bytes while the failure predicate holds.
#[must_use]
pub fn shrink_bytes(mut bytes: Vec<u8>, mut fails: impl FnMut(&[u8]) -> bool) -> ByteFailure {
    while !bytes.is_empty() && fails(&bytes[..bytes.len() - 1]) {
        bytes.pop();
    }
    ByteFailure {
        bytes,
        first_difference: Some(0),
    }
}
