//! Narrow effect ports for the Radicle issue workflow.

use auths_model::CanonicalAction;
use auths_sdk::{Authorized, RequestContext};

use crate::{
    candidate::InspectedCandidate,
    executor::{LocalPublication, VerifiedOpenPatchCommand},
    profile::RadiclePatchCommand,
    receipts::{RadiclePropagationReceipt, RadicleReceipt},
    types::{CandidateSubmission, CobId, Rid, VerifierConfiguration, WorkflowId},
};

/// Trusted candidate inspection boundary.
pub trait CandidateInspector: Send + Sync {
    /// Produces facts and an isolated repository from hostile bundle bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed adapter failure for malformed input, limits, or I/O.
    fn inspect(
        &self,
        submission: &CandidateSubmission,
        configuration: &VerifierConfiguration,
    ) -> Result<InspectedCandidate, PortError>;
}

/// Fresh synchronized Radicle evidence boundary.
pub trait EvidenceSource: Send + Sync {
    /// Synchronizes configured peers and materializes one exact repository issue.
    ///
    /// # Errors
    ///
    /// Returns a closed adapter failure when trustworthy evidence is unavailable.
    fn observe(
        &self,
        rid: &Rid,
        issue_id: &CobId,
        configuration: &VerifierConfiguration,
        now: u64,
    ) -> Result<crate::types::RadicleEvidenceV1, PortError>;
}

/// Auths proof-verification outcome.
pub enum ProofDecision {
    /// Exact Auths authority was established.
    Authorized(Box<Authorized<RadiclePatchCommand>>),
    /// Complete Auths inputs establish denial.
    Denied {
        /// Stable Auths reason.
        code: String,
    },
    /// A trustworthy Auths input or implementation is unavailable.
    Indeterminate {
        /// Stable Auths requirement.
        code: String,
    },
}

/// Auths kernel boundary.
pub trait ProofVerifier: Send + Sync {
    /// Verifies the supplied proof against the already canonicalized action.
    ///
    /// # Errors
    ///
    /// Returns a closed integration failure, distinct from proof denial.
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<ProofDecision, PortError>;
}

/// Only irreversible Radicle write boundary.
pub trait RadicleWriter: Send + Sync {
    /// Opens one patch from an executor-safe sealed command.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when signer checks or the local write fail.
    fn open_patch(
        &self,
        command: VerifiedOpenPatchCommand,
        now: u64,
    ) -> Result<(LocalPublication, crate::workflow::ExecutionLease), PortError>;

    /// Announces a patch that was already stored and receipted.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when the configured announce quorum fails.
    fn announce(&self, publication: &LocalPublication) -> Result<(), PortError>;
}

/// Independent propagation observer boundary.
pub trait PropagationObserver: Send + Sync {
    /// Observes a specific initial revision on a distinct Radicle node.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when independent observation cannot be proven.
    fn observe(
        &self,
        publication: &LocalPublication,
        execution_receipt_digest: &crate::types::DigestHex,
        now: u64,
    ) -> Result<RadiclePropagationReceipt, PortError>;
}

/// Append-only receipt boundary.
pub trait ReceiptSink: Send + Sync {
    /// Durably appends canonical receipt bytes.
    ///
    /// # Errors
    ///
    /// Returns a closed persistence failure.
    fn append(&self, receipt: &RadicleReceipt) -> Result<(), PortError>;
}

/// Trusted time boundary.
pub trait Clock: Send + Sync {
    /// Returns Unix time in seconds.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when trusted time is unavailable.
    fn now(&self) -> Result<u64, PortError>;
}

/// Closed effect failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PortError {
    /// Effect configuration is unsafe or inconsistent.
    #[error("invalid adapter configuration")]
    InvalidConfiguration,
    /// Input or output exceeds a hard bound.
    #[error("adapter limit exceeded")]
    LimitExceeded,
    /// External bytes or output are malformed.
    #[error("malformed adapter data")]
    Malformed,
    /// Required synchronized evidence is unavailable.
    #[error("required evidence is unavailable")]
    EvidenceUnavailable,
    /// Auths verification integration failed.
    #[error("Auths verifier integration failed")]
    Verification,
    /// Durable state or receipt persistence failed.
    #[error("durable workflow state is unavailable")]
    Persistence,
    /// Radicle rejected or failed the write.
    #[error("Radicle write failed")]
    Execution,
    /// Independent propagation was not observed.
    #[error("Radicle propagation was not observed")]
    Propagation,
}

/// Stable workflow summary returned for replay requests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplaySummary {
    /// Workflow.
    pub workflow_id: WorkflowId,
    /// Previously stored patch, if execution reached that stage.
    pub patch_id: Option<CobId>,
}
