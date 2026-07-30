//! Native service and browser demo for `OpenTofu` saved-plan authorization.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    reason = "the demo exposes closed startup and protected-port errors"
)]
#![allow(
    clippy::missing_panics_doc,
    reason = "repository-owned fixture construction is test-only"
)]

pub mod app;
pub mod fixture;
pub mod opentofu;

pub use app::{AppConfig, StartupError, app, serve};
