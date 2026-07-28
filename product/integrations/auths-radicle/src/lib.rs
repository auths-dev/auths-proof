//! Exact, replay-safe Auths authorization for one Radicle issue patch.
//!
//! Radicle-specific vocabulary, candidate inspection, evidence acquisition,
//! workflow state, and execution remain in this vertical package. The Auths
//! kernel stays unaware of Radicle and receives only a canonical exact action.

#![forbid(unsafe_code)]

pub mod adapters;
pub mod candidate;
pub mod canonical;
pub mod containment;
pub mod executor;
pub mod ports;
pub mod profile;
pub mod receipts;
pub mod service;
pub mod types;
pub mod workflow;

#[cfg(test)]
mod test_support;

pub use containment::{Decision, DecisionClass, DecisionCode, EvaluationContext, evaluate};
pub use executor::{LocalPublication, VerifiedOpenPatchCommand};
pub use profile::{RadiclePatchCommand, RadiclePatchProfile};
pub use service::{
    AuthorizeRequest, RadicleIssueWorkflowService, ServiceDependencies, ServiceError,
    WorkflowOutcome, derive_exact_action,
};
pub use types::{
    CandidateFacts, CandidateSubmission, CobId, DigestHex, ExecutorAudience, GitOid,
    IssueAddressGrantV1, NodeId, OpenPatchActionV1, PathChange, RadicleDid, RadicleEvidenceV1, Rid,
    VerifierConfiguration, WorkflowId,
};
