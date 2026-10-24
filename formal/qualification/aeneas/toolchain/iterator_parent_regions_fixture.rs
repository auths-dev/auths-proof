//! Source fixture for a selected DoubleEndedIterator's declared Iterator
//! parent. All construction and final body/ABI assertions remain separate.
pub fn reverse_nonzero(values: &[u64]) -> bool {
    values.iter().rev().any(|value| *value != 0)
}

pub fn borrowed_reverse_nonzero(values: &[&u32]) -> bool {
    values.iter().rev().any(|value| **value != 0)
}
