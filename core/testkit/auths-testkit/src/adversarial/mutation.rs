use auths_model::{EvidenceId, MediaType, PrincipalId, SignatureSuiteId};
use core::fmt;

/// Stable, path-safe mutation identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MutationId(String);

impl MutationId {
    /// Parses a lowercase identifier.
    ///
    /// # Errors
    ///
    /// Returns [`MutationError::InvalidId`] for an empty or unsafe identifier.
    pub fn parse(value: impl Into<String>) -> Result<Self, MutationError> {
        let value = value.into();
        if value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(MutationError::InvalidId);
        }
        Ok(Self(value))
    }

    /// Returns the stable identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Pure deterministic mutation.
pub trait Mutation<T> {
    /// Returns the stable mutation identifier.
    fn id(&self) -> &MutationId;
    /// Applies the mutation without modifying the seed.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the requested target does not exist.
    fn apply(&self, seed: &T) -> Result<T, MutationError>;
}

/// Deterministic parser-boundary byte mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ByteMutation {
    id: MutationId,
    offset: usize,
    mask: u8,
}

impl ByteMutation {
    /// Constructs a non-zero single-byte XOR mutation.
    ///
    /// # Errors
    ///
    /// Returns a typed error for an invalid identifier or zero mask.
    pub fn new(id: impl Into<String>, offset: usize, mask: u8) -> Result<Self, MutationError> {
        if mask == 0 {
            return Err(MutationError::ZeroMask);
        }
        Ok(Self {
            id: MutationId::parse(id)?,
            offset,
            mask,
        })
    }
}

impl Mutation<Vec<u8>> for ByteMutation {
    fn id(&self) -> &MutationId {
        &self.id
    }

    fn apply(&self, seed: &Vec<u8>) -> Result<Vec<u8>, MutationError> {
        let mut mutated = seed.clone();
        let byte = mutated
            .get_mut(self.offset)
            .ok_or(MutationError::OffsetOutOfRange)?;
        *byte ^= self.mask;
        Ok(mutated)
    }
}

/// Typed evidence-set mutations used by every principal adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceMutation {
    /// Remove the required evidence object.
    RemoveRequired(EvidenceId),
    /// Bind the same evidence identifier twice.
    Duplicate(EvidenceId),
    /// Replace the asserted principal.
    SubstitutePrincipal(PrincipalId),
    /// Replace the asserted signature suite.
    SubstituteSuite(SignatureSuiteId),
    /// Replace the evidence media type.
    ChangeMediaType(MediaType),
    /// Truncate the evidence payload.
    Truncate { bytes: usize },
    /// Extend the evidence payload.
    Extend { bytes: usize },
    /// Flip one recorded byte.
    Flip { offset: usize, mask: u8 },
}

/// Mutation construction or application failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationError {
    /// The stable identifier was malformed.
    InvalidId,
    /// A byte offset was outside the bounded seed.
    OffsetOutOfRange,
    /// A bit flip used an empty mask.
    ZeroMask,
}

impl fmt::Display for MutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidId => "invalid mutation identifier",
            Self::OffsetOutOfRange => "mutation offset outside seed",
            Self::ZeroMask => "mutation mask must be non-zero",
        })
    }
}

impl std::error::Error for MutationError {}
