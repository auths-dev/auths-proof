//! Typed deterministic-codec failures.

use auths_model::ModelError;
use core::fmt;

/// Failure while encoding, decoding, or deriving target V1 identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    /// Input exceeded an explicit deployment or protocol bound.
    LimitExceeded,
    /// Input was not a complete target V1 CBOR object.
    Malformed,
    /// Input decoded but was not the unique deterministic encoding.
    NonCanonical,
    /// A content-addressed object did not match its declared identifier.
    DigestMismatch,
    /// Two semantic objects resolved to the same identifier or reference.
    DuplicateObject,
    /// The decoded value violated a target model invariant.
    Model(ModelError),
}

impl From<ModelError> for CodecError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LimitExceeded => "codec limit exceeded",
            Self::Malformed => "malformed target V1 CBOR",
            Self::NonCanonical => "non-canonical target V1 CBOR",
            Self::DigestMismatch => "content identifier mismatch",
            Self::DuplicateObject => "duplicate content-addressed object",
            Self::Model(_) => "decoded value violates the target V1 model",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CodecError {}
