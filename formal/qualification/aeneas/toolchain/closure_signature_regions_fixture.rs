//! Source-signature lifetime provenance for closure trait/Output construction.
//! Run the source/AST qualification assertions in the final validation batch.

pub fn borrowed_argument(values: &[u8], threshold: u8) -> bool {
    values.iter().all(|value: &u8| *value >= threshold)
}

pub fn shared_callable(values: &[u8]) -> bool {
    let nonzero = |value: &u8| *value != 0;
    nonzero(&1) && values.iter().all(nonzero)
}

pub fn borrowed_output<'a>(input: &'a [u8]) -> &'a [u8] {
    let identity = |value: &'a [u8]| -> &'a [u8] { value };
    identity(input)
}

pub fn consuming_capture(input: String, value: &u8) -> usize {
    let once = move |item: &u8| -> usize { input.len() + usize::from(*item) };
    once(value)
}

pub fn separate_borrows<'a>(input: &'a [u8], scratch: &mut Vec<u8>) -> usize {
    let mut copy = |value: &u8| scratch.push(*value);
    for value in input {
        copy(value);
    }
    scratch.len()
}
