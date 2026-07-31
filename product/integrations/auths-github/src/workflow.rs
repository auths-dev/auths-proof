//! Domain receipt vocabulary for the GitHub issue workflow.
//!
//! Durable effect ownership, replay, and reconciliation are implemented only
//! by the shared lifecycle contract. This module intentionally retains no
//! GitHub-specific workflow store.

use serde::{Deserialize, Serialize};

/// Domain projection of the prior state expected by a GitHub execution
/// receipt.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowStage {
    /// The candidate was inspected and contained before branch publication.
    CandidateAccepted,
    /// The exact branch was durably committed before draft-PR creation.
    BranchPublished,
}
