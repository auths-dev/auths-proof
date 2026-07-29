//! Mechanism-only infrastructure shared by the separate Stripe payment demos.
//!
//! This crate deliberately does not define merchant actions, evaluators,
//! gateways, services, outcomes, or lifecycle semantics.

#![forbid(unsafe_code)]

mod fixture;
mod http;

pub use fixture::{AuthorizationFixture, authorization_fixture};
pub use http::{StripeHttp, StripeHttpResponse};
