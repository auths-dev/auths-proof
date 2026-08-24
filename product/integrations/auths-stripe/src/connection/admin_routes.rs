//! Provider-owned exact onboarding routes.

/// Starts Stripe API-key onboarding through the privileged listener.
pub const START: &str = "/v1/admin/providers/stripe/connections/start";
/// Completes Stripe API-key onboarding and account commitment verification.
pub const COMPLETE: &str = "/v1/admin/providers/stripe/connections/complete";
