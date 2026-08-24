//! Exact PostgreSQL deployment connection contract.

pub mod admin_routes;
pub mod credentials;
pub mod descriptor;
pub mod onboarding;

pub use credentials::PostgresConnectionAdapter;
pub use descriptor::PostgresConnectionDescriptor;
pub use onboarding::{PostgresConnectionSecretV1, validate_connection_secret, validate_onboarding};

/// Constructs the statically linked connection adapter used by generated
/// runtime roster glue.
#[must_use]
pub fn adapter() -> PostgresConnectionAdapter {
    PostgresConnectionAdapter::new()
}
