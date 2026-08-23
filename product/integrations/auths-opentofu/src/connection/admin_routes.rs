//! OpenTofu connection onboarding routes on the privileged listener.

/// Begins bounded backend enrollment.
pub const START: &str = "/v1/admin/providers/opentofu/connections/start";
/// Completes backend identity validation and installs its credential.
pub const COMPLETE: &str = "/v1/admin/providers/opentofu/connections/complete";
