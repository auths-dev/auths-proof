//! Exact manual-capture authorization vertical.

mod action;
mod profile;

pub use action::{StripeExactPaymentAuthorizeInput, StripeExactPaymentAuthorizeV1};
pub use profile::{StripePaymentAuthorizeCommand, StripePaymentAuthorizeProfile};
