//@ charon-arg=--index-to-function-calls
// Source fixture for the unapplied pinned Charon index-borrow region patch.
// Covers every shared/mutable array/slice element/range builtin shape.
// Actual AST assertions and exact source/borrow qualification remain required.

pub fn slice_shared(values: &[u32], at: usize) -> &u32 {
    &values[at]
}

pub fn slice_mut(values: &mut [u32], at: usize) -> &mut u32 {
    &mut values[at]
}

pub fn array_shared(values: &[u32; 4], at: usize) -> &u32 {
    &values[at]
}

pub fn array_mut(values: &mut [u32; 4], at: usize) -> &mut u32 {
    &mut values[at]
}

pub fn slice_range_shared(values: &[u32], first: usize, end: usize) -> &[u32] {
    &values[first..end]
}

pub fn slice_range_mut(values: &mut [u32], first: usize, end: usize) -> &mut [u32] {
    &mut values[first..end]
}

pub fn array_range_shared(values: &[u32; 4], first: usize, end: usize) -> &[u32] {
    &values[first..end]
}

pub fn array_range_mut(values: &mut [u32; 4], first: usize, end: usize) -> &mut [u32] {
    &mut values[first..end]
}

pub fn two_borrows(values: &[u32], first: usize, second: usize) -> (&u32, &u32) {
    (&values[first], &values[second])
}

pub fn existing_borrow(values: &[u32], at: usize) -> (&[u32], &u32) {
    let whole = &values[..];
    (whole, &whole[at])
}
