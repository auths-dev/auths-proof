//! Actual global/initializer source fixture for final closure qualification.

pub static READ_ONLY_BYTES: [u8; 4] = [3, 5, 7, 11];
pub const NAMED_BYTES: &[u8] = &READ_ONLY_BYTES;
pub const COMPUTED: u32 = initializer(6);

pub const fn initializer(value: u32) -> u32 {
    value * 7
}

pub struct Carrier<const N: usize>;

impl<const N: usize> Carrier<N> {
    pub const SIZE: usize = N;
}

pub fn through_globals(index: usize) -> Option<u32> {
    NAMED_BYTES.get(index).map(|value| u32::from(*value) + COMPUTED)
}

pub fn generic_associated_global<const N: usize>() -> usize {
    Carrier::<N>::SIZE
}
