//! Native and browser surfaces for the exact Stripe refund demonstration.

#![forbid(unsafe_code)]

mod app;
mod fixture;
mod stripe;

pub use app::{AppConfig, StartupError, app, app_with_environment, app_with_stores};
pub use stripe::{DemoStripeEnvironment, LiveStripeEnvironment};
