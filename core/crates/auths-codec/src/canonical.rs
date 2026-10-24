//! Final byte-identity gate shared by the public protocol decoders.
//!
//! Callers supply their actual encoder output after complete parsing and
//! constructor checks. No callback or claimed canonicality flag is accepted.
//! The value is moved out only when those bytes equal the complete input.

use crate::CodecError;
use alloc::vec::Vec;

pub(crate) fn accept<T>(input: &[u8], encoded: Vec<u8>, value: T) -> Result<T, CodecError> {
    accept_with_error(input, encoded, value, CodecError::NonCanonical)
}

pub(crate) fn accept_with_error<T>(
    input: &[u8], encoded: Vec<u8>, value: T, mismatch: CodecError,
) -> Result<T, CodecError> {
    if encoded.as_slice() != input { Err(mismatch) } else { Ok(value) }
}
