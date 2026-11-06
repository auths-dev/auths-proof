//! One opaque-resource string boundary for native enrollment, provider
//! selection and retained lineage. This validates neither path syntax nor
//! ownership: those remain the compiler/authority boundary's responsibility.

pub(crate) const MAX_HANDLE_BYTES: usize = 256;

pub(crate) fn valid_handle(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_HANDLE_BYTES && !value.chars().any(char::is_control)
}
