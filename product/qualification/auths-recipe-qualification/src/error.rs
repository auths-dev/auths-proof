use thiserror::Error;

/// Why a qualification artifact was refused before any signature or trust
/// decision.
///
/// These are format reasons for the release verifier and its tests. They are
/// not gateway stable codes: a gateway reports an artifact it cannot use
/// under its own qualification codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum QualificationFormatError {
    /// The input is empty or exceeds the artifact's byte limit.
    #[error("the artifact is empty or oversized")]
    Oversized,
    /// The input is not JSON of the artifact's shape: a member is missing,
    /// unknown, repeated, or of the wrong type, an enumeration value is
    /// unknown, or an identifier breaks its grammar.
    #[error("the artifact is malformed")]
    Malformed,
    /// The input parses but is not its own RFC 8785 canonical form.
    #[error("the artifact is not canonical")]
    NonCanonical,
    /// The artifact names another schema.
    #[error("the artifact names an unknown schema")]
    UnknownSchema,
    /// A signed time field is out of range, a window is empty or reversed,
    /// or a window exceeds its fixed maximum.
    #[error("the artifact carries an invalid time window")]
    InvalidTimeWindow,
    /// A list is empty where a member is required, or exceeds its bound.
    #[error("a list is outside its bound")]
    ListBound,
    /// A list is unsorted or repeats a member.
    #[error("a list is unsorted or repeats a member")]
    ListOrder,
    /// The evidence does not close: a member or capability is missing,
    /// repeated, or out of order, a result contradicts its counters or
    /// reason, an unauthorized provider entry is recorded, or a live effect
    /// lacks its read-back.
    #[error("the evidence does not close")]
    InvalidEvidence,
}

impl QualificationFormatError {
    /// Returns the reason token the fixtures pin.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Oversized => "oversized",
            Self::Malformed => "malformed",
            Self::NonCanonical => "non-canonical",
            Self::UnknownSchema => "unknown-schema",
            Self::InvalidTimeWindow => "invalid-time-window",
            Self::ListBound => "list-bound",
            Self::ListOrder => "list-order",
            Self::InvalidEvidence => "invalid-evidence",
        }
    }
}
