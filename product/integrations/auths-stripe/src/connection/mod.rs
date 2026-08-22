//! Exact Stripe account connection contract.

pub mod admin_routes;
pub mod credentials;
pub mod descriptor;
pub mod onboarding;

pub use credentials::StripeConnectionAdapter;
pub use descriptor::StripeConnectionDescriptor;
pub use onboarding::{validate_onboarding, validate_static_secret};

/// Constructs the statically linked connection adapter used by generated
/// runtime roster glue.
#[must_use]
pub fn adapter() -> StripeConnectionAdapter {
    StripeConnectionAdapter::new()
}
