//! Issuance of recipe qualifications: building evidence artifacts from what
//! a protected run's stages reported, assembling the record they determine,
//! and signing it.
//!
//! This crate is release tooling. A gateway does not depend on it: a
//! gateway verifies qualifications and can neither assemble nor sign one,
//! and the pure oracle a family's differential stage runs is an argument to
//! a function here, never part of a gateway build.
//!
//! The library reads no clock and performs no I/O; the `auths-qualification`
//! binary does both at its boundary.

#![forbid(unsafe_code)]

mod error;
mod proposal;
mod sign;
pub mod stages;
#[cfg(feature = "testkit")]
pub mod testkit;

pub use error::IssuanceError;
pub use proposal::{CaseReport, NotApplicable, QualificationProposal, RecordDraft, evidence};
pub use sign::{CertificateRequest, ReleaseSigner, RootSigner, SigningSeed};
