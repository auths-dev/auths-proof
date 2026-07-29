//! Exact, replay-safe authorization for one OpenTofu saved-plan application.
//!
//! OpenTofu source, plan, backend, state, claim, credential, execution, and
//! receipt concepts remain in this product package. Core stays provider-neutral.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    reason = "OpenTofu is a product name, not a Rust identifier"
)]
#![allow(
    clippy::missing_errors_doc,
    reason = "the public API returns closed, self-describing error enums"
)]
#![allow(
    clippy::missing_panics_doc,
    reason = "deterministic fixture constructors are test-only"
)]

pub mod action;
pub mod adapters;
pub mod bundle;
pub mod canonical;
pub mod claim;
pub mod decision;
pub mod errors;
pub mod executor;
pub mod observe;
pub mod plan_projection;
pub mod planner;
pub mod ports;
pub mod profile;
pub mod receipts;
pub mod service;
pub mod test_support;
pub mod types;

pub use action::*;
pub use adapters::*;
pub use bundle::*;
pub use claim::*;
pub use decision::*;
pub use errors::*;
pub use executor::*;
pub use plan_projection::*;
pub use planner::*;
pub use ports::*;
pub use profile::*;
pub use receipts::*;
pub use service::*;
pub use types::*;
