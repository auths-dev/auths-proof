//! Native API and browser surface for one bounded subscription.

#![forbid(unsafe_code)]

mod app;
mod receipts;
mod stripe;

pub use app::{AppConfig, StartupError, app, app_with_environment};
pub use stripe::{DemoSubscriptionCreateEnvironment, LiveSubscriptionCreateEnvironment};
