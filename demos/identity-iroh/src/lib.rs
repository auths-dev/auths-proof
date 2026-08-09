//! Native backend for the capability-free identity-over-Iroh demonstration.

#![forbid(unsafe_code)]

mod app;

pub use app::{AppConfig, StartupError, app, serve};
