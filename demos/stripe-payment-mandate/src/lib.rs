//! Native API and browser surface for exact bounded Stripe payment mandates.

#![forbid(unsafe_code)]

mod app;
mod receipts;
mod stripe;

pub use app::{AppConfig, StartupError, app, app_with_environment};
pub use stripe::{DemoPaymentMandateEnvironment, LivePaymentMandateEnvironment};
