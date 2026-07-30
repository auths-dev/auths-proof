//! Closed Stripe subscription profiles and their finite-liability state.
//!
//! The subscription family shares only immutable policy and durable liability
//! mechanics. Create, modify, and cancel retain separate actions, evaluators,
//! commands, gateways, transitions, credentials, and receipt unions.

#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::struct_excessive_bools,
    clippy::too_many_lines,
    reason = "explicit financial trust-boundary fields are intentionally verbose"
)]

pub mod create;
mod policy;
mod state;

pub use create::*;
pub use policy::*;
pub use state::*;

/// Shared closed subscription policy carrier.
pub const SUBSCRIPTION_POLICY_TYPE: &str = "auths.stripe.bounded-subscription-policy/1";
/// Shared semantic evaluator identity.
pub const SUBSCRIPTION_EVALUATOR_ID: &str = "auths.stripe.bounded-subscription-evaluator/1";
/// Canonicalization identity.
pub const SUBSCRIPTION_CANONICALIZATION: &str = "rfc8785-sha256-v1";
/// Durable reservation schema.
pub const SUBSCRIPTION_LIABILITY_SCHEMA: &str = "auths.stripe.subscription-liability/1";

fn valid_local(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
}

fn valid_api_version(value: &str) -> bool {
    (10..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        && value.as_bytes().first().is_some_and(u8::is_ascii_digit)
}

fn sorted_unique_nonempty<T: Ord>(values: &[T]) -> bool {
    !values.is_empty() && values.len() <= 64 && values.windows(2).all(|pair| pair[0] < pair[1])
}

/// Closed validation failures for the subscription family.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SubscriptionValidationError {
    #[error("invalid exact subscription-create action")]
    Action,
    #[error("invalid bounded subscription policy")]
    Policy,
    #[error("invalid subscription evaluator configuration")]
    Configuration,
    #[error("invalid protected subscription evidence")]
    Evidence,
}
