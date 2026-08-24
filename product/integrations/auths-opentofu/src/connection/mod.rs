//! Exact OpenTofu backend connection contract.

pub mod admin_routes;
pub mod credentials;
pub mod descriptor;
pub mod onboarding;

pub use credentials::OpenTofuConnectionAdapter;
pub use descriptor::OpenTofuConnectionDescriptor;
pub use onboarding::{OpenTofuConnectionSecretV1, validate_backend_secret, validate_onboarding};

/// Constructs the statically linked connection adapter used by generated
/// runtime roster glue.
#[must_use]
pub fn adapter() -> OpenTofuConnectionAdapter {
    OpenTofuConnectionAdapter::new()
}
