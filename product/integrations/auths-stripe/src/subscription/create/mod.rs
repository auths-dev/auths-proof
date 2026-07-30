//! Exact creation of one bounded fixed-term Stripe subscription.

mod action;
mod evaluator;
mod execution;
mod profile;
mod receipts;
mod service;

pub use action::*;
pub use evaluator::*;
pub use execution::*;
pub use profile::*;
pub use receipts::*;
pub use service::*;

/// Exact V1 action profile.
pub const SUBSCRIPTION_CREATE_PROFILE: &str = "auths.stripe.exact-subscription-create/1";
/// Profile-specific receipt schema.
pub const SUBSCRIPTION_CREATE_RECEIPT_SCHEMA: &str = "auths.stripe.subscription-create-receipt/1";
