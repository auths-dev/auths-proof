//! Native service and deterministic fixtures for the GitHub issue demo.

#![forbid(unsafe_code)]

mod app;
mod fixture;
mod scenario;

pub use app::{AppConfig, StartupError, app, serve};
pub use fixture::EphemeralAuthsAuthorizer;
pub use scenario::DemoVariant;

#[cfg(test)]
mod tests;
