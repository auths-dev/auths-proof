//! Native API and browser surface for bounded exact Stripe cancel.

#![forbid(unsafe_code)]

mod app;
mod receipts;
mod stripe;

pub use app::{AppConfig, StartupError, app, app_with_environment};
pub use stripe::{DemoPaymentCancelEnvironment, LivePaymentCancelEnvironment};
