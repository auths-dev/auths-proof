//! One exact, bounded before/after Subscription modification.

mod action;
mod evaluator;
mod execution;
mod profile;
mod receipts;
mod service;
mod state;

pub use action::*;
pub use evaluator::*;
pub use execution::*;
pub use profile::*;
pub use receipts::*;
pub use service::*;
pub use state::*;

/// Exact V1 action profile.
pub const SUBSCRIPTION_MODIFY_PROFILE: &str = "auths.stripe.exact-subscription-modify/1";
/// Profile-specific receipt schema.
pub const SUBSCRIPTION_MODIFY_RECEIPT_SCHEMA: &str = "auths.stripe.subscription-modify-receipt/1";
