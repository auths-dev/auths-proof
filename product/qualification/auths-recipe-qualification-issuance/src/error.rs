use auths_recipe_qualification::{ClosureFault, QualificationFormatError};
use thiserror::Error;

/// Why nothing was assembled or signed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum IssuanceError {
    /// An artifact is not of its canonical form.
    #[error("format: {0}")]
    Format(#[from] QualificationFormatError),
    /// The record does not close over its evidence.
    #[error("evidence closure: {0}")]
    Closure(#[from] ClosureFault),
    /// A reported case did not pass, or observed an unauthorized provider
    /// entry.
    #[error("a case did not pass")]
    CaseFailed,
    /// A capability is neither exercised nor declared not applicable, or is
    /// both.
    #[error("a capability is unaccounted for")]
    Capability,
    /// The key is not the one the trust root or certificate names.
    #[error("the key is not the one its certificate names")]
    KeyMismatch,
    /// The certificate does not permit signing this kind of artifact.
    #[error("the certificate does not permit this artifact")]
    NotPermitted,
    /// A requested window is outside the record's or the certificate's.
    #[error("the window is outside what may be signed")]
    Window,
    /// An index entry's attestation does not name its record, or was issued
    /// by another signer.
    #[error("an index entry is inconsistent")]
    IndexEntry,
    /// The operating system supplied no randomness.
    #[error("no randomness is available")]
    Randomness,
}

impl IssuanceError {
    /// The stable token of this refusal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Format(_) => "format",
            Self::Closure(_) => "evidence-closure",
            Self::CaseFailed => "case-failed",
            Self::Capability => "capability",
            Self::KeyMismatch => "key-mismatch",
            Self::NotPermitted => "not-permitted",
            Self::Window => "window",
            Self::IndexEntry => "index-entry",
            Self::Randomness => "randomness",
        }
    }
}
