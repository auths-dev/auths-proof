//! PostgreSQL connection onboarding routes on the privileged listener.

/// Begins bounded deployment connection enrollment.
pub const START: &str = "/v1/admin/providers/postgresql/connections/start";
/// Completes TLS/account identity validation and installs the credential.
pub const COMPLETE: &str = "/v1/admin/providers/postgresql/connections/complete";
