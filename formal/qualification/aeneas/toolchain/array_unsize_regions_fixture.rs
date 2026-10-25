//! Source-origin fixture for array-to-slice lowering. It is intentionally
//! dependency-free and is run only in the final toolchain qualification batch.

pub fn shared<'a, const N: usize>(input: &'a [u8; N]) -> &'a [u8] {
    input
}

pub fn mutable<'a, const N: usize>(input: &'a mut [u8; N]) -> &'a mut [u8] {
    input
}

pub fn static_shared() -> &'static [u8] {
    b"retained-source-region"
}

pub fn zero_length(input: &[u8; 0]) -> &[u8] {
    input
}

pub fn reborrow_shared<'a, 'b>(input: &'a mut [u8; 4], other: &'b [u8; 2]) -> u8 {
    let first: &[u8] = &*input;
    let second: &[u8] = other;
    first[0] ^ second[0]
}

pub fn repeated_mutable(input: &mut [u8; 4]) {
    let first: &mut [u8] = &mut *input;
    first[0] = 1;
    let second: &mut [u8] = &mut *input;
    second[1] = 2;
}
