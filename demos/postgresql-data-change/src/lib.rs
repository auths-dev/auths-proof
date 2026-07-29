//! Native service and browser demo for bounded PostgreSQL updates.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    reason = "PostgreSQL is a product name, not a Rust identifier"
)]
#![allow(
    clippy::too_many_lines,
    reason = "security-relevant demo flows remain intentionally linear"
)]
#![allow(
    clippy::struct_field_names,
    reason = "catalog fingerprint field names are deliberately explicit"
)]
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
pub mod postgres;

pub use app::{AppConfig, StartupError, app, serve};
