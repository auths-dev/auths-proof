//! Actual source signatures for the generated-vtable lifetime boundary.
//! Borrowed receivers must never acquire a static object lifetime. Source
//! function, initializer/shim, drop and native loan assertions remain required.

pub trait Describe {
    fn text(&self) -> &str;
}

pub struct Borrowed<'a>(pub &'a str);

impl Describe for Borrowed<'_> {
    fn text(&self) -> &str {
        self.0
    }
}

pub fn described_len(value: &dyn Describe) -> usize {
    value.text().len()
}

pub fn borrowed_len(input: &str) -> usize {
    let receiver = Borrowed(input);
    described_len(&receiver)
}

pub fn through_function_pointer(
    call: for<'a> fn(&'a dyn Describe) -> usize,
    value: &dyn Describe,
) -> usize {
    call(value)
}

pub fn concrete_function_pointer(input: &str) -> usize {
    let receiver = Borrowed(input);
    through_function_pointer(described_len, &receiver)
}

#[cfg(test)]
mod tests {
    use super::{borrowed_len, concrete_function_pointer};

    #[test]
    fn borrowed_receiver_uses_its_actual_input() {
        let input = String::from("short lived source");
        assert_eq!(borrowed_len(&input), input.len());
        assert_eq!(concrete_function_pointer(&input), input.len());
    }
}
