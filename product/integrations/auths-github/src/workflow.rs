//! Durable compare-and-swap claims for branch and pull-request effects.

#![allow(
    clippy::missing_errors_doc,
    reason = "store operations share the closed WorkflowStoreError contract"
)]

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};

use crate::{
    canonical::{canonical_json, sha256},
    types::{DigestHex, ExactGitHubAction, GitHubOperation, WorkflowId},
};

/// Workflow state machine stage.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowStage {
    /// Workflow grant accepted.
    Authorized,
    /// Candidate inspected and contained.
    CandidateAccepted,
    /// Branch effect atomically reserved.
    BranchClaimed,
    /// Branch outcome requires reconciliation.
    BranchReconciliationRequired,
    /// Exact branch observed at GitHub.
    BranchPublished,
    /// Draft-PR effect atomically reserved.
    PullRequestClaimed,
    /// PR outcome requires reconciliation.
    PullRequestReconciliationRequired,
    /// Exact draft PR observed at GitHub.
    Completed,
    /// Cancelled before an effect was claimed.
    Cancelled,
    /// Expired.
    Expired,
    /// Denied.
    Denied,
    /// Permanently failed.
    FailedPermanent,
}

/// Durable execution-claim status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimStatus {
    /// Claimed before the external call.
    Pending,
    /// Exact postcondition and receipt committed.
    Completed,
    /// External result cannot yet be proven.
    ReconciliationRequired,
}

/// One atomic effect claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRecord {
    /// Deterministic claim identifier.
    pub claim_id: DigestHex,
    /// Exact action commitment.
    pub action_digest: DigestHex,
    /// Complete canonical action needed for deterministic recovery.
    pub exact_action: ExactGitHubAction,
    /// Decision receipt that authorized the exact action before this claim.
    pub decision_receipt_digest: DigestHex,
    /// Effect category.
    pub operation: GitHubOperation,
    /// Claim status.
    pub status: ClaimStatus,
    /// Execution receipt commitment after success.
    pub execution_receipt_digest: Option<DigestHex>,
    /// Trusted update time.
    pub updated_at: u64,
}

/// Durable workflow state with monotonic revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowState {
    /// Workflow identifier.
    pub workflow_id: WorkflowId,
    /// Monotonic compare-and-swap revision.
    pub revision: u64,
    /// Current stage.
    pub stage: WorkflowStage,
    /// Branch budget/claim.
    pub branch_claim: Option<ClaimRecord>,
    /// Pull-request budget/claim.
    pub pull_request_claim: Option<ClaimRecord>,
}

impl WorkflowState {
    fn new(workflow_id: WorkflowId) -> Self {
        Self {
            workflow_id,
            revision: 0,
            stage: WorkflowStage::Authorized,
            branch_claim: None,
            pull_request_claim: None,
        }
    }

    /// Returns the claim for one effect category.
    #[must_use]
    pub const fn claim(&self, operation: GitHubOperation) -> Option<&ClaimRecord> {
        match operation {
            GitHubOperation::PublishBranch => self.branch_claim.as_ref(),
            GitHubOperation::OpenDraftPullRequest => self.pull_request_claim.as_ref(),
        }
    }
}

/// Sealed proof that one effect was durably reserved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionClaim {
    workflow_id: WorkflowId,
    operation: GitHubOperation,
    claim_id: DigestHex,
    action_digest: DigestHex,
}

impl ExecutionClaim {
    pub(crate) fn from_record(
        workflow_id: WorkflowId,
        record: &ClaimRecord,
    ) -> Result<Self, WorkflowStoreError> {
        if record.exact_action.workflow_id() != &workflow_id
            || record.exact_action.operation() != record.operation
            || record.exact_action.digest().ok().as_ref() != Some(&record.action_digest)
        {
            return Err(WorkflowStoreError::Corrupt);
        }
        Ok(Self {
            workflow_id,
            operation: record.operation,
            claim_id: record.claim_id.clone(),
            action_digest: record.action_digest.clone(),
        })
    }

    /// Workflow identifier.
    #[must_use]
    pub const fn workflow_id(&self) -> &WorkflowId {
        &self.workflow_id
    }

    /// Effect category.
    #[must_use]
    pub const fn operation(&self) -> GitHubOperation {
        self.operation
    }

    /// Claim identifier.
    #[must_use]
    pub const fn claim_id(&self) -> &DigestHex {
        &self.claim_id
    }

    /// Exact action commitment.
    #[must_use]
    pub const fn action_digest(&self) -> &DigestHex {
        &self.action_digest
    }
}

/// Atomic claim result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimResult {
    /// Caller won the effect claim.
    Claimed(ExecutionClaim),
    /// Exact completed action already has a receipt.
    Replay(DigestHex),
    /// Same exact action has an unresolved pending claim.
    ReconciliationRequired(ClaimRecord),
    /// Budget is bound to another exact action.
    BudgetExhausted(ClaimRecord),
    /// Store unavailable.
    Unavailable,
}

/// Durable workflow/claim boundary.
pub trait WorkflowStore: Send + Sync {
    /// Creates or returns one workflow.
    fn initialize(&self, workflow_id: &WorkflowId) -> Result<WorkflowState, WorkflowStoreError>;
    /// Marks deterministic candidate acceptance.
    fn accept_candidate(
        &self,
        workflow_id: &WorkflowId,
    ) -> Result<WorkflowState, WorkflowStoreError>;
    /// Atomically reserves one external effect.
    fn claim(
        &self,
        workflow_id: &WorkflowId,
        exact_action: &ExactGitHubAction,
        decision_receipt_digest: &DigestHex,
        now: u64,
    ) -> ClaimResult;
    /// Commits the exact successful receipt.
    fn complete(
        &self,
        claim: &ExecutionClaim,
        receipt_digest: &DigestHex,
        now: u64,
    ) -> Result<WorkflowState, WorkflowStoreError>;
    /// Marks an ambiguous post-claim result.
    fn require_reconciliation(
        &self,
        claim: &ExecutionClaim,
        now: u64,
    ) -> Result<WorkflowState, WorkflowStoreError>;
    /// Loads current state.
    fn load(&self, workflow_id: &WorkflowId) -> Result<Option<WorkflowState>, WorkflowStoreError>;
}

impl<T: WorkflowStore + ?Sized> WorkflowStore for Arc<T> {
    fn initialize(&self, workflow_id: &WorkflowId) -> Result<WorkflowState, WorkflowStoreError> {
        (**self).initialize(workflow_id)
    }

    fn accept_candidate(
        &self,
        workflow_id: &WorkflowId,
    ) -> Result<WorkflowState, WorkflowStoreError> {
        (**self).accept_candidate(workflow_id)
    }

    fn claim(
        &self,
        workflow_id: &WorkflowId,
        exact_action: &ExactGitHubAction,
        decision_receipt_digest: &DigestHex,
        now: u64,
    ) -> ClaimResult {
        (**self).claim(workflow_id, exact_action, decision_receipt_digest, now)
    }

    fn complete(
        &self,
        claim: &ExecutionClaim,
        receipt_digest: &DigestHex,
        now: u64,
    ) -> Result<WorkflowState, WorkflowStoreError> {
        (**self).complete(claim, receipt_digest, now)
    }

    fn require_reconciliation(
        &self,
        claim: &ExecutionClaim,
        now: u64,
    ) -> Result<WorkflowState, WorkflowStoreError> {
        (**self).require_reconciliation(claim, now)
    }

    fn load(&self, workflow_id: &WorkflowId) -> Result<Option<WorkflowState>, WorkflowStoreError> {
        (**self).load(workflow_id)
    }
}

/// Process-local CAS store for tests and single-process composition.
#[derive(Default)]
pub struct InMemoryWorkflowStore {
    records: Mutex<BTreeMap<WorkflowId, WorkflowState>>,
}

impl WorkflowStore for InMemoryWorkflowStore {
    fn initialize(&self, workflow_id: &WorkflowId) -> Result<WorkflowState, WorkflowStoreError> {
        mutate_records(&self.records, |records| {
            Ok(records
                .entry(workflow_id.clone())
                .or_insert_with(|| WorkflowState::new(workflow_id.clone()))
                .clone())
        })
    }

    fn accept_candidate(
        &self,
        workflow_id: &WorkflowId,
    ) -> Result<WorkflowState, WorkflowStoreError> {
        mutate_records(&self.records, |records| {
            accept_candidate_in(records, workflow_id)
        })
    }

    fn claim(
        &self,
        workflow_id: &WorkflowId,
        exact_action: &ExactGitHubAction,
        decision_receipt_digest: &DigestHex,
        now: u64,
    ) -> ClaimResult {
        mutate_records(&self.records, |records| {
            Ok(claim_in(
                records,
                workflow_id,
                exact_action,
                decision_receipt_digest,
                now,
            ))
        })
        .unwrap_or(ClaimResult::Unavailable)
    }

    fn complete(
        &self,
        claim: &ExecutionClaim,
        receipt_digest: &DigestHex,
        now: u64,
    ) -> Result<WorkflowState, WorkflowStoreError> {
        mutate_records(&self.records, |records| {
            complete_in(records, claim, receipt_digest, now)
        })
    }

    fn require_reconciliation(
        &self,
        claim: &ExecutionClaim,
        now: u64,
    ) -> Result<WorkflowState, WorkflowStoreError> {
        mutate_records(&self.records, |records| reconcile_in(records, claim, now))
    }

    fn load(&self, workflow_id: &WorkflowId) -> Result<Option<WorkflowState>, WorkflowStoreError> {
        self.records
            .lock()
            .map(|records| records.get(workflow_id).cloned())
            .map_err(|_| WorkflowStoreError::Unavailable)
    }
}

/// Crash-persistent JSON store for one active writer process.
pub struct PersistentWorkflowStore {
    path: PathBuf,
    capacity: usize,
    records: Mutex<BTreeMap<WorkflowId, WorkflowState>>,
}

impl PersistentWorkflowStore {
    /// Opens or creates a bounded persistent store.
    ///
    /// # Errors
    ///
    /// Rejects invalid capacity, corrupt state, non-canonical state, or I/O.
    pub fn open(path: impl Into<PathBuf>, capacity: usize) -> Result<Self, WorkflowStoreError> {
        let path = path.into();
        if capacity == 0 || capacity > 100_000 || path.parent().is_none() {
            return Err(WorkflowStoreError::InvalidConfiguration);
        }
        let records = if path.exists() {
            let bytes = fs::read(&path).map_err(|_| WorkflowStoreError::Unavailable)?;
            let records: BTreeMap<WorkflowId, WorkflowState> =
                serde_json::from_slice(&bytes).map_err(|_| WorkflowStoreError::Corrupt)?;
            if records.len() > capacity
                || canonical_json(&records).map_err(|_| WorkflowStoreError::Corrupt)? != bytes
            {
                return Err(WorkflowStoreError::Corrupt);
            }
            records
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            path,
            capacity,
            records: Mutex::new(records),
        })
    }

    fn mutate<T>(
        &self,
        mutation: impl FnOnce(&mut BTreeMap<WorkflowId, WorkflowState>) -> Result<T, WorkflowStoreError>,
    ) -> Result<T, WorkflowStoreError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| WorkflowStoreError::Unavailable)?;
        let mut next = records.clone();
        let result = mutation(&mut next)?;
        if next.len() > self.capacity {
            return Err(WorkflowStoreError::Capacity);
        }
        persist(&self.path, &next)?;
        *records = next;
        Ok(result)
    }
}

impl WorkflowStore for PersistentWorkflowStore {
    fn initialize(&self, workflow_id: &WorkflowId) -> Result<WorkflowState, WorkflowStoreError> {
        self.mutate(|records| {
            Ok(records
                .entry(workflow_id.clone())
                .or_insert_with(|| WorkflowState::new(workflow_id.clone()))
                .clone())
        })
    }

    fn accept_candidate(
        &self,
        workflow_id: &WorkflowId,
    ) -> Result<WorkflowState, WorkflowStoreError> {
        self.mutate(|records| accept_candidate_in(records, workflow_id))
    }

    fn claim(
        &self,
        workflow_id: &WorkflowId,
        exact_action: &ExactGitHubAction,
        decision_receipt_digest: &DigestHex,
        now: u64,
    ) -> ClaimResult {
        self.mutate(|records| {
            Ok(claim_in(
                records,
                workflow_id,
                exact_action,
                decision_receipt_digest,
                now,
            ))
        })
        .unwrap_or(ClaimResult::Unavailable)
    }

    fn complete(
        &self,
        claim: &ExecutionClaim,
        receipt_digest: &DigestHex,
        now: u64,
    ) -> Result<WorkflowState, WorkflowStoreError> {
        self.mutate(|records| complete_in(records, claim, receipt_digest, now))
    }

    fn require_reconciliation(
        &self,
        claim: &ExecutionClaim,
        now: u64,
    ) -> Result<WorkflowState, WorkflowStoreError> {
        self.mutate(|records| reconcile_in(records, claim, now))
    }

    fn load(&self, workflow_id: &WorkflowId) -> Result<Option<WorkflowState>, WorkflowStoreError> {
        self.records
            .lock()
            .map(|records| records.get(workflow_id).cloned())
            .map_err(|_| WorkflowStoreError::Unavailable)
    }
}

fn mutate_records<T>(
    records: &Mutex<BTreeMap<WorkflowId, WorkflowState>>,
    mutation: impl FnOnce(&mut BTreeMap<WorkflowId, WorkflowState>) -> Result<T, WorkflowStoreError>,
) -> Result<T, WorkflowStoreError> {
    let mut records = records
        .lock()
        .map_err(|_| WorkflowStoreError::Unavailable)?;
    mutation(&mut records)
}

fn accept_candidate_in(
    records: &mut BTreeMap<WorkflowId, WorkflowState>,
    workflow_id: &WorkflowId,
) -> Result<WorkflowState, WorkflowStoreError> {
    let state = records
        .get_mut(workflow_id)
        .ok_or(WorkflowStoreError::NotFound)?;
    if state.stage > WorkflowStage::CandidateAccepted {
        return Ok(state.clone());
    }
    if state.stage != WorkflowStage::Authorized {
        return Err(WorkflowStoreError::InvalidTransition);
    }
    state.stage = WorkflowStage::CandidateAccepted;
    state.revision = state
        .revision
        .checked_add(1)
        .ok_or(WorkflowStoreError::Corrupt)?;
    Ok(state.clone())
}

fn claim_in(
    records: &mut BTreeMap<WorkflowId, WorkflowState>,
    workflow_id: &WorkflowId,
    exact_action: &ExactGitHubAction,
    decision_receipt_digest: &DigestHex,
    now: u64,
) -> ClaimResult {
    if exact_action.workflow_id() != workflow_id || exact_action.validate().is_err() {
        return ClaimResult::Unavailable;
    }
    let operation = exact_action.operation();
    let Ok(action_digest) = exact_action.digest() else {
        return ClaimResult::Unavailable;
    };
    let Some(state) = records.get_mut(workflow_id) else {
        return ClaimResult::Unavailable;
    };
    if let Some(existing) = state.claim(operation) {
        return if existing.action_digest == action_digest
            && existing.exact_action == *exact_action
            && existing.decision_receipt_digest == *decision_receipt_digest
        {
            match (existing.status, existing.execution_receipt_digest.as_ref()) {
                (ClaimStatus::Completed, Some(receipt)) => ClaimResult::Replay(receipt.clone()),
                _ => ClaimResult::ReconciliationRequired(existing.clone()),
            }
        } else {
            ClaimResult::BudgetExhausted(existing.clone())
        };
    }
    let expected_stage = match operation {
        GitHubOperation::PublishBranch => WorkflowStage::CandidateAccepted,
        GitHubOperation::OpenDraftPullRequest => WorkflowStage::BranchPublished,
    };
    if state.stage != expected_stage {
        return ClaimResult::Unavailable;
    }
    let claim_id = sha256(
        format!("auths-github-claim-v1\0{workflow_id}\0{operation:?}\0{action_digest}").as_bytes(),
    );
    let record = ClaimRecord {
        claim_id: claim_id.clone(),
        action_digest: action_digest.clone(),
        exact_action: exact_action.clone(),
        decision_receipt_digest: decision_receipt_digest.clone(),
        operation,
        status: ClaimStatus::Pending,
        execution_receipt_digest: None,
        updated_at: now,
    };
    match operation {
        GitHubOperation::PublishBranch => {
            state.branch_claim = Some(record);
            state.stage = WorkflowStage::BranchClaimed;
        }
        GitHubOperation::OpenDraftPullRequest => {
            state.pull_request_claim = Some(record);
            state.stage = WorkflowStage::PullRequestClaimed;
        }
    }
    state.revision = match state.revision.checked_add(1) {
        Some(revision) => revision,
        None => return ClaimResult::Unavailable,
    };
    ClaimResult::Claimed(ExecutionClaim {
        workflow_id: workflow_id.clone(),
        operation,
        claim_id,
        action_digest,
    })
}

fn complete_in(
    records: &mut BTreeMap<WorkflowId, WorkflowState>,
    claim: &ExecutionClaim,
    receipt_digest: &DigestHex,
    now: u64,
) -> Result<WorkflowState, WorkflowStoreError> {
    let state = records
        .get_mut(&claim.workflow_id)
        .ok_or(WorkflowStoreError::NotFound)?;
    let record = match claim.operation {
        GitHubOperation::PublishBranch => state.branch_claim.as_mut(),
        GitHubOperation::OpenDraftPullRequest => state.pull_request_claim.as_mut(),
    }
    .ok_or(WorkflowStoreError::Conflict)?;
    if record.claim_id != claim.claim_id
        || record.action_digest != claim.action_digest
        || (record.status == ClaimStatus::Completed
            && record.execution_receipt_digest.as_ref() != Some(receipt_digest))
    {
        return Err(WorkflowStoreError::Conflict);
    }
    record.status = ClaimStatus::Completed;
    record.execution_receipt_digest = Some(receipt_digest.clone());
    record.updated_at = now;
    state.stage = match claim.operation {
        GitHubOperation::PublishBranch => WorkflowStage::BranchPublished,
        GitHubOperation::OpenDraftPullRequest => WorkflowStage::Completed,
    };
    state.revision = state
        .revision
        .checked_add(1)
        .ok_or(WorkflowStoreError::Corrupt)?;
    Ok(state.clone())
}

fn reconcile_in(
    records: &mut BTreeMap<WorkflowId, WorkflowState>,
    claim: &ExecutionClaim,
    now: u64,
) -> Result<WorkflowState, WorkflowStoreError> {
    let state = records
        .get_mut(&claim.workflow_id)
        .ok_or(WorkflowStoreError::NotFound)?;
    let record = match claim.operation {
        GitHubOperation::PublishBranch => state.branch_claim.as_mut(),
        GitHubOperation::OpenDraftPullRequest => state.pull_request_claim.as_mut(),
    }
    .ok_or(WorkflowStoreError::Conflict)?;
    if record.claim_id != claim.claim_id || record.action_digest != claim.action_digest {
        return Err(WorkflowStoreError::Conflict);
    }
    record.status = ClaimStatus::ReconciliationRequired;
    record.updated_at = now;
    state.stage = match claim.operation {
        GitHubOperation::PublishBranch => WorkflowStage::BranchReconciliationRequired,
        GitHubOperation::OpenDraftPullRequest => WorkflowStage::PullRequestReconciliationRequired,
    };
    state.revision = state
        .revision
        .checked_add(1)
        .ok_or(WorkflowStoreError::Corrupt)?;
    Ok(state.clone())
}

fn persist(
    path: &Path,
    records: &BTreeMap<WorkflowId, WorkflowState>,
) -> Result<(), WorkflowStoreError> {
    let parent = path
        .parent()
        .ok_or(WorkflowStoreError::InvalidConfiguration)?;
    fs::create_dir_all(parent).map_err(|_| WorkflowStoreError::Unavailable)?;
    let bytes = canonical_json(records).map_err(|_| WorkflowStoreError::Corrupt)?;
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes).map_err(|_| WorkflowStoreError::Unavailable)?;
    fs::rename(&temporary, path).map_err(|_| WorkflowStoreError::Unavailable)
}

/// Closed durable-store failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WorkflowStoreError {
    /// Invalid trusted store configuration.
    #[error("invalid workflow store configuration")]
    InvalidConfiguration,
    /// Workflow does not exist.
    #[error("workflow not found")]
    NotFound,
    /// State transition is not legal.
    #[error("invalid workflow transition")]
    InvalidTransition,
    /// Claimed values differ.
    #[error("workflow claim conflict")]
    Conflict,
    /// Persistent state is corrupt.
    #[error("workflow state corrupt")]
    Corrupt,
    /// Store capacity reached.
    #[error("workflow store capacity reached")]
    Capacity,
    /// Store is unavailable.
    #[error("workflow store unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::types::{
        BRANCH_CAPABILITY, ExecutorAudience, GitOid, IssueResource, NodeId, PROFILE_ID,
        PROFILE_VERSION, PublishBranchAction, RefName, RepositoryName, RepositoryOwner,
        RepositoryResource,
    };

    use super::*;

    #[test]
    fn concurrent_duplicate_claims_have_one_winner() {
        let store = Arc::new(InMemoryWorkflowStore::default());
        let workflow = WorkflowId::parse("workflow-1234567890").unwrap();
        store.initialize(&workflow).unwrap();
        store.accept_candidate(&workflow).unwrap();
        let action = branch_action(&workflow);
        let decision = DigestHex::parse("d".repeat(64)).unwrap();
        let threads = (0..16)
            .map(|_| {
                let store = Arc::clone(&store);
                let workflow = workflow.clone();
                let action = action.clone();
                let decision = decision.clone();
                std::thread::spawn(move || store.claim(&workflow, &action, &decision, 100))
            })
            .collect::<Vec<_>>();
        let results = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, ClaimResult::Claimed(_)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, ClaimResult::ReconciliationRequired(_)))
                .count(),
            15
        );
    }

    #[test]
    fn replay_returns_original_receipt() {
        let store = InMemoryWorkflowStore::default();
        let workflow = WorkflowId::parse("workflow-1234567890").unwrap();
        store.initialize(&workflow).unwrap();
        store.accept_candidate(&workflow).unwrap();
        let action = branch_action(&workflow);
        let decision = DigestHex::parse("d".repeat(64)).unwrap();
        let claim = match store.claim(&workflow, &action, &decision, 100) {
            ClaimResult::Claimed(claim) => claim,
            other => panic!("unexpected claim: {other:?}"),
        };
        let receipt = DigestHex::parse("b".repeat(64)).unwrap();
        store.complete(&claim, &receipt, 101).unwrap();
        assert_eq!(
            store.claim(&workflow, &action, &decision, 102),
            ClaimResult::Replay(receipt)
        );
    }

    fn branch_action(workflow_id: &WorkflowId) -> ExactGitHubAction {
        let repository = RepositoryResource::new(
            42,
            NodeId::parse("R_node_123").unwrap(),
            RepositoryOwner::parse("auths-dev").unwrap(),
            RepositoryName::parse("auths-github-demo").unwrap(),
        )
        .unwrap();
        let issue = IssueResource::new(42, NodeId::parse("I_node_123").unwrap(), 7).unwrap();
        ExactGitHubAction::PublishBranch(PublishBranchAction {
            capability: BRANCH_CAPABILITY.into(),
            profile_id: PROFILE_ID.into(),
            profile_version: PROFILE_VERSION,
            workflow_id: workflow_id.clone(),
            workflow_grant_digest: DigestHex::parse("1".repeat(64)).unwrap(),
            repository,
            issue,
            base_ref: RefName::parse("main").unwrap(),
            base_revision: GitOid::parse("2".repeat(40)).unwrap(),
            target_ref: RefName::parse("auths/issue-7-workflow-12").unwrap(),
            expected_target_state: "absent".into(),
            candidate_revision: GitOid::parse("3".repeat(40)).unwrap(),
            candidate_tree: GitOid::parse("4".repeat(40)).unwrap(),
            candidate_bundle_digest: DigestHex::parse("5".repeat(64)).unwrap(),
            change_set_digest: DigestHex::parse("6".repeat(64)).unwrap(),
            evidence_digest: DigestHex::parse("7".repeat(64)).unwrap(),
            verifier_configuration_digest: DigestHex::parse("8".repeat(64)).unwrap(),
            executor_audience: ExecutorAudience::parse("https://executor.auths.dev").unwrap(),
            expires_at: 200,
        })
    }
}
