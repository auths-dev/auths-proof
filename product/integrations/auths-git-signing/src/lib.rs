//! Git commit and tag signing with Auths proofs (AP-SPEC-058).
//!
//! Git stores an Auths signature in its native signature slot by calling an
//! external signing program (`gpg.format = x509`, `gpg.x509.program`). This
//! package owns the envelope stored in that slot and the program protocol Git
//! speaks. Profile actions, verification, signing, and delegation are not
//! implemented yet, so nothing here can report a signature as good.
//!
//! The package must never depend on `auths-did-keri`, directly or
//! transitively. `architecture.toml` enforces that with an explicit
//! dependency boundary.

#![forbid(unsafe_code)]

pub mod envelope;
pub mod program;

#[cfg(all(test, unix))]
mod git_protocol_tests;

pub use envelope::{EnvelopeError, GitSignatureEnvelope};
pub use program::{ProgramError, ProgramRequest, SigningKeyRef, VerifyStatus};
