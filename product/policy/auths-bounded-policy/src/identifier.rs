use alloc::string::{String, ToString};
use core::fmt;

const MAX_POLICY_TYPE: usize = 128;
const MAX_EVALUATOR_SEMANTIC: usize = 128;
const MAX_CANONICALIZATION: usize = 64;
const MAX_CONFIGURATION_SEMANTIC: usize = 128;
const MAX_STABLE_CODE: usize = 96;
const MAX_STABLE_STAGE: usize = 64;
const MAX_UNIT: usize = 64;
const MAX_OBLIGATION: usize = 96;
const MAX_INTENT: usize = 96;
const MAX_GENERAL_SCHEMA: usize = 128;
const MAX_IMPLEMENTATION: usize = 128;
const MAX_PROFILE: usize = 128;
const MAX_EVIDENCE_SOURCE: usize = 128;

/// Failure to construct an immutable semantic identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentifierError {
    /// Identifier is empty.
    Empty,
    /// Identifier exceeds its V1 byte limit.
    TooLong,
    /// Identifier contains a byte outside the closed ASCII vocabulary.
    InvalidByte,
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "identifier is empty",
            Self::TooLong => "identifier exceeds its V1 byte limit",
            Self::InvalidByte => "identifier contains a disallowed byte",
        };
        formatter.write_str(message)
    }
}

fn validate(value: &str, maximum: usize) -> Result<(), IdentifierError> {
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

macro_rules! identifier {
    ($name:ident, $maximum:expr) => {
        #[doc = concat!("Validated byte-exact `", stringify!($name), "`.")]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Parses the closed ASCII representation.
            pub fn parse(value: &str) -> Result<Self, IdentifierError> {
                validate(value, $maximum)?;
                Ok(Self(value.to_string()))
            }

            /// Returns the byte-exact identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

identifier!(PolicyTypeId, MAX_POLICY_TYPE);
identifier!(EvaluatorSemanticId, MAX_EVALUATOR_SEMANTIC);
identifier!(CanonicalizationId, MAX_CANONICALIZATION);
identifier!(ConfigurationSemanticId, MAX_CONFIGURATION_SEMANTIC);
identifier!(StableCode, MAX_STABLE_CODE);
identifier!(StableStage, MAX_STABLE_STAGE);
identifier!(UnitId, MAX_UNIT);
identifier!(ObligationId, MAX_OBLIGATION);
identifier!(IntentId, MAX_INTENT);
identifier!(SchemaId, MAX_GENERAL_SCHEMA);
identifier!(ImplementationId, MAX_IMPLEMENTATION);
identifier!(ProfileId, MAX_PROFILE);
identifier!(EvidenceSourceId, MAX_EVIDENCE_SOURCE);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_byte_exact_and_bounded() {
        assert!(PolicyTypeId::parse("auths.stripe.refund-policy/1").is_ok());
        assert_eq!(PolicyTypeId::parse(""), Err(IdentifierError::Empty));
        assert_eq!(
            PolicyTypeId::parse("auths policy"),
            Err(IdentifierError::InvalidByte)
        );
        assert_eq!(
            PolicyTypeId::parse(&"a".repeat(MAX_POLICY_TYPE + 1)),
            Err(IdentifierError::TooLong)
        );
    }

    #[test]
    fn normalization_aliases_are_not_accepted() {
        assert_eq!(
            SchemaId::parse("auths\u{2010}schema"),
            Err(IdentifierError::InvalidByte)
        );
    }
}
