//! Application-profile contract from untrusted input to verified command.

#![forbid(unsafe_code)]

use auths_model::CanonicalAction;
use auths_verifier::VerifiedAction;
use std::fmt;

/// Human-reviewable rendering bound to exact canonical bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewDisplay {
    title: String,
    fields: Vec<(String, String)>,
    canonical_digest_hex: String,
}

impl ReviewDisplay {
    /// Constructs a profile-owned deterministic review display.
    #[must_use]
    pub fn new(
        title: impl Into<String>,
        fields: Vec<(String, String)>,
        canonical_digest_hex: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            fields,
            canonical_digest_hex: canonical_digest_hex.into(),
        }
    }

    /// Returns the display title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns ordered profile-owned fields.
    #[must_use]
    pub fn fields(&self) -> &[(String, String)] {
        &self.fields
    }

    /// Returns the digest of bytes represented by this display.
    #[must_use]
    pub fn canonical_digest_hex(&self) -> &str {
        &self.canonical_digest_hex
    }
}

/// Exact application profile implemented on both sides of verification.
pub trait ActionProfile {
    /// Command type safe for a profile executor.
    type Command;

    /// Canonicalizes untrusted application input and derives exact meaning.
    ///
    /// # Errors
    ///
    /// Returns a closed profile error for malformed, ambiguous, or
    /// unsupported input.
    fn canonicalize(&self, untrusted: &[u8]) -> Result<CanonicalAction, ProfileContractError>;

    /// Produces a human display bound to canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed profile error when the canonical action is not this
    /// exact profile/version.
    fn review_display(
        &self,
        action: &CanonicalAction,
    ) -> Result<ReviewDisplay, ProfileContractError>;

    /// Decodes only sealed verified data into an executable domain command.
    ///
    /// # Errors
    ///
    /// Returns a closed profile error when verified bytes or derived meaning
    /// do not satisfy this profile.
    fn decode_verified(
        &self,
        action: &VerifiedAction,
    ) -> Result<Self::Command, ProfileContractError>;
}

/// Common closed profile-boundary failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileContractError {
    /// Input exceeds the profile's byte or structural limit.
    LimitExceeded,
    /// Input is malformed.
    Malformed,
    /// Input has more than one possible meaning.
    Ambiguous,
    /// Input is not the exact registered profile/version.
    UnsupportedProfile,
    /// Input is valid but not the unique canonical representation.
    NonCanonical,
    /// Derived permission/resource/budget does not match verified data.
    MeaningMismatch,
}

impl fmt::Display for ProfileContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LimitExceeded => "profile limit exceeded",
            Self::Malformed => "malformed profile input",
            Self::Ambiguous => "ambiguous profile input",
            Self::UnsupportedProfile => "unsupported profile",
            Self::NonCanonical => "non-canonical profile input",
            Self::MeaningMismatch => "verified action meaning mismatch",
        })
    }
}

impl std::error::Error for ProfileContractError {}
