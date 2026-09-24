//! Git commit and tag signing with Auths proofs (AP-SPEC-058).
//!
//! Git stores an Auths signature in its native signature slot by calling an
//! external signing program (`gpg.format = x509`, `gpg.x509.program`). This
//! package owns:
//!
//! - the envelope stored in that slot and the program protocol Git speaks;
//! - bounded parsing of the objects around it;
//! - the typed commit and tag actions;
//! - method-agnostic signing and verification.
//!
//! Principal methods are never named on the signing or verification path.
//! A signer plugs in through [`sign::GitProofSigner`], and a verifier passes
//! the executable registries for the methods it enables. Local agents sign
//! as `did:key` ([`custody`]), and production roots sign through
//! `auths-custody` (KMS or PKCS#11); CI workloads sign as their OIDC workload
//! identity ([`workload`]). The trust directory's `methods.json`
//! ([`methods`]) enables the workload methods.
//!
//! The package must never depend on `auths-did-keri`, directly or
//! transitively. `architecture.toml` enforces that with an explicit
//! dependency boundary.

#![forbid(unsafe_code)]

pub mod action;
pub mod claims;
pub mod custody;
pub mod envelope;
pub mod files;
pub mod methods;
pub mod object;
pub mod program;
pub mod revoke;
pub mod sign;
pub mod sigstore_client;
pub mod tool;
pub mod trust;
pub mod verify;
pub mod workload;

#[cfg(test)]
mod custody_tests;
#[cfg(all(test, unix))]
mod git_protocol_tests;
#[cfg(test)]
mod verify_tests;
#[cfg(all(test, unix))]
mod workflow_tests;
#[cfg(test)]
mod workload_fakes;
#[cfg(test)]
mod workload_tests;

pub use action::{
    ActionError, CommitSignatureAction, GitSignatureAction, RepositoryId, TagSignatureAction,
};
pub use envelope::{EnvelopeError, GitSignatureEnvelope};
pub use object::{ObjectError, ObjectFormat, ObjectKind, SignedObject, TagName, UnsignedPayload};
pub use program::{ProgramError, ProgramRequest, SigningKeyRef, VerifyStatus};
pub use sign::{Delegation, DelegationLink, GitProofSigner, SignError, sign_payload};
pub use verify::{
    GitTrust, GitVerification, TrustError, VerifiedGitSignature, verify_object, verify_signature,
};
