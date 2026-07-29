//! Closed errors for the OpenTofu integration.

/// Validation failure for untrusted source, plan, action, or configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ValidationError {
    #[error("OpenTofu input exceeded a hard limit")]
    LimitExceeded,
    #[error("OpenTofu input is malformed")]
    Malformed,
    #[error("OpenTofu input is not canonical")]
    NonCanonical,
    #[error("OpenTofu profile or version is unsupported")]
    UnsupportedProfile,
    #[error("OpenTofu verifier configuration is invalid")]
    InvalidConfiguration,
    #[error("OpenTofu evidence is invalid")]
    InvalidEvidence,
    #[error("OpenTofu feature is forbidden by the saved-plan profile")]
    ForbiddenFeature,
    #[error("OpenTofu dependency is not pinned")]
    DependencyNotPinned,
    #[error("OpenTofu plan change falls outside the profile")]
    ChangeOutsideProfile,
    #[error("OpenTofu plan contains a destroy action")]
    DestroyDenied,
    #[error("OpenTofu plan contains a replacement action")]
    ReplacementDenied,
}

/// Canonical JSON or digest failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CanonicalError {
    #[error("canonical JSON serialization failed")]
    Serialize,
}

/// Protected integration boundary failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PortError {
    #[error("OpenTofu adapter configuration is invalid")]
    InvalidConfiguration,
    #[error("OpenTofu adapter input exceeded a hard limit")]
    LimitExceeded,
    #[error("OpenTofu evidence is unavailable")]
    EvidenceUnavailable,
    #[error("Auths verification integration failed")]
    Verification,
    #[error("durable OpenTofu workflow state is unavailable")]
    Persistence,
    #[error("protected saved-plan artifact is unavailable")]
    ArtifactUnavailable,
    #[error("saved-plan artifact digest does not match")]
    ArtifactMismatch,
    #[error("OpenTofu credential acquisition failed")]
    CredentialUnavailable,
    #[error("OpenTofu apply failed")]
    Execution,
    #[error("OpenTofu execution outcome is unknown")]
    OutcomeUnknown,
    #[error("OpenTofu postcondition does not match the authorized plan")]
    PostconditionFailed,
}
