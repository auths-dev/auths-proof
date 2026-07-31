//! The supported embedded core facade for Auths.
//!
//! This crate gives consumers the stable Auths product coordinate while the
//! bounded proof protocol remains isolated in [`auths-proof`](auths_proof).
//! It deliberately adds no I/O, provider, profile, custody, or runtime
//! behavior.
//!
//! ```no_run
//! use auths::{Engine, Verdict};
//!
//! # fn verify(
//! #     engine: &Engine<'_>,
//! #     proof: &[u8],
//! #     action: &[u8],
//! #     trusted_context: &[u8],
//! # ) {
//! let result = engine
//!     .verify_cbor(proof, action, trusted_context)
//!     .expect("the embedded engine must encode its canonical result");
//! assert!(matches!(
//!     result.verdict(),
//!     Verdict::Authorized | Verdict::Denied | Verdict::Indeterminate
//! ));
//! # }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

pub use auths_proof::*;
