//! Exact authorization for bounded, typed PostgreSQL data changes.
//!
//! Database identifiers, catalog evidence, SQL compilation, transaction
//! protocol, and receipts stay in this product package. Core remains
//! database-neutral.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    reason = "PostgreSQL is a product name, not a Rust identifier"
)]
#![allow(
    clippy::too_many_lines,
    reason = "security-relevant ordered flows remain intentionally linear"
)]
#![allow(
    clippy::struct_excessive_bools,
    reason = "catalog evidence preserves independent PostgreSQL boolean facts"
)]
#![allow(
    clippy::missing_errors_doc,
    reason = "public APIs return closed, self-describing error enums"
)]
#![allow(
    clippy::missing_panics_doc,
    reason = "deterministic fixture helpers are test-only"
)]

pub mod action;
pub mod adapters;
pub mod canonical;
pub mod claim;
pub mod compiler;
pub mod decision;
pub mod evidence;
pub mod executor;
pub mod ports;
pub mod profile;
pub mod receipts;
pub mod schema;
pub mod service;
pub mod test_support;
pub mod value;

pub use action::*;
pub use adapters::*;
pub use claim::*;
pub use compiler::*;
pub use decision::*;
pub use evidence::*;
pub use executor::*;
pub use ports::*;
pub use profile::*;
pub use receipts::*;
pub use schema::*;
pub use service::*;
pub use value::*;
