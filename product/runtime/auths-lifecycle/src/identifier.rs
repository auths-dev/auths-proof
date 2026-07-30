use alloc::string::{String, ToString};
use core::fmt;

use crate::{MAX_OPERATION_ID_BYTES, MAX_SEMANTIC_ID_BYTES, MAX_WORKFLOW_ID_BYTES};

/// Failure to construct a bounded, byte-exact lifecycle identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentifierError {
    /// The identifier was empty.
    Empty,
    /// The identifier exceeded its V1 byte ceiling.
    TooLong,
    /// A semantic identifier contained a byte outside the closed vocabulary.
    InvalidByte,
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "identifier is empty",
            Self::TooLong => "identifier exceeds its V1 byte limit",
            Self::InvalidByte => "identifier contains a disallowed byte",
        })
    }
}

fn validate_semantic(value: &str, maximum: usize) -> Result<(), IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError::Empty);
    }
    if value.len() > maximum {
        return Err(IdentifierError::TooLong);
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b':' | b'_' | b'-')
    }) {
        return Err(IdentifierError::InvalidByte);
    }
    Ok(())
}

fn validate_workflow(value: &str) -> Result<(), IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError::Empty);
    }
    if value.len() > MAX_WORKFLOW_ID_BYTES {
        return Err(IdentifierError::TooLong);
    }
    Ok(())
}

macro_rules! semantic_identifier {
    ($name:ident, $maximum:expr) => {
        #[doc = concat!("Validated byte-exact `", stringify!($name), "`.")]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Parses the closed V1 semantic identifier.
            ///
            /// # Errors
            ///
            /// Returns [`IdentifierError`] when empty, over the hard limit, or
            /// outside the closed ASCII vocabulary.
            pub fn parse(value: &str) -> Result<Self, IdentifierError> {
                validate_semantic(value, $maximum)?;
                Ok(Self(value.to_string()))
            }

            /// Returns the exact identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

/// Bounded workflow identity. Workflow values may use the complete UTF-8
/// vocabulary because their semantic equality is byte exact, not normalized.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkflowId(String);

impl WorkflowId {
    /// Parses one exact workflow identity.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] when empty or above 256 UTF-8 bytes.
    pub fn parse(value: &str) -> Result<Self, IdentifierError> {
        validate_workflow(value)?;
        Ok(Self(value.to_string()))
    }

    /// Returns the exact workflow identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

semantic_identifier!(LifecycleId, MAX_OPERATION_ID_BYTES);
semantic_identifier!(ExecutionId, MAX_OPERATION_ID_BYTES);
semantic_identifier!(ReservationId, MAX_OPERATION_ID_BYTES);
semantic_identifier!(ReconciliationId, MAX_OPERATION_ID_BYTES);
semantic_identifier!(DomainId, MAX_SEMANTIC_ID_BYTES);
semantic_identifier!(ExecutorAudienceId, MAX_SEMANTIC_ID_BYTES);
semantic_identifier!(ProviderContractId, MAX_SEMANTIC_ID_BYTES);
semantic_identifier!(ReservationAlgebraId, MAX_SEMANTIC_ID_BYTES);
semantic_identifier!(ReservationUnitId, MAX_SEMANTIC_ID_BYTES);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_and_workflow_limits_are_distinct_and_exact() {
        assert!(ProviderContractId::parse("auths.stripe.refund-provider/1").is_ok());
        assert_eq!(
            ProviderContractId::parse("provider contract"),
            Err(IdentifierError::InvalidByte)
        );
        assert!(WorkflowId::parse("ticket/🧪/42").is_ok());
        assert_eq!(
            WorkflowId::parse(&"x".repeat(MAX_WORKFLOW_ID_BYTES + 1)),
            Err(IdentifierError::TooLong)
        );
    }
}
