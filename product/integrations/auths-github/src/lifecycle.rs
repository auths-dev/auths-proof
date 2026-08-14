//! Exact projection from GitHub issue-workflow semantics into shared policy
//! and durable-lifecycle contracts.
//!
//! GitHub keeps ownership of repository and Git object identity, candidate
//! inspection, workflow composition, provider commands, credentials,
//! reconciliation, stable codes, and public receipts. Shared crates receive
//! only canonical commitments and operation-specific exclusive reservations.

use auths_bounded_policy::{
    BoundedOutputs, CanonicalizationId, CommitmentDigest, ConfigurationCommitmentV1,
    ConfigurationSemanticId, EvaluationCommitmentsV1, EvaluatorSemanticId, EvidenceSourceId,
    ImplementationId, IntentId, ObligationClass, ObligationCommitmentV1, ObligationId,
    PolicyCommitmentV1, PolicyTypeId, ProfileId, ReservationIntentCommitmentV1, ReservationKind,
    SchemaId, VerifierTime,
};
use auths_lifecycle::{
    CancellationDisposition, CapacityEntryV1, CapacitySnapshotV1, DecisionInputV1,
    DecisionReceiptDigest, DomainId, DomainReceiptDigest, ExecutionId, ExecutorAudienceId,
    LifecycleId, LifecycleRecordV1, LifecycleStore, ReservationAlgebraId, ReservationSetV1,
    RevocationSnapshotV1, StoreError, TransitionContextV1, WorkflowId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

use crate::{
    canonical::{canonical_digest, canonical_json, sha256},
    containment::{Decision, DecisionClass},
    evidence::GitHubEvidence,
    types::{
        DigestHex, ExactGitHubAction, GitHubOperation, PROFILE_VERSION, VerifierConfiguration,
        WorkflowGrant,
    },
};

pub const BRANCH_PROFILE_ID: &str = "auths.github.issue-address.branch-publish/1";
pub const PULL_REQUEST_PROFILE_ID: &str = "auths.github.issue-address.pull-request-open-draft/1";
pub const POLICY_TYPE_ID: &str = "auths.github.issue-workflow-grant/1";
pub const BRANCH_EVALUATOR_SEMANTIC_ID: &str = "auths.github.branch-publish.evaluate/1";
pub const PULL_REQUEST_EVALUATOR_SEMANTIC_ID: &str =
    "auths.github.pull-request-open-draft.evaluate/1";
pub const IMPLEMENTATION_ID: &str = "auths-github/shared-lifecycle-production/1";
pub const CANONICALIZATION_ID: &str = "rfc8785-sha256-v1";
pub const CONFIGURATION_SEMANTIC_ID: &str = "auths.github.verifier-configuration/1";
pub const EVIDENCE_SCHEMA_ID: &str = "auths.github.repository-evidence/1";
pub const EVIDENCE_SOURCE_ID: &str = "github-read-api/1";
pub const BRANCH_STATE_SCHEMA_ID: &str = "auths.github.branch-ref-snapshot/1";
pub const PULL_REQUEST_STATE_SCHEMA_ID: &str = "auths.github.pull-request-set-snapshot/1";
pub const BRANCH_INTENT_SCHEMA_ID: &str = "auths.github.branch-ref-exclusive-intent/1";
pub const PULL_REQUEST_INTENT_SCHEMA_ID: &str = "auths.github.pull-request-head-exclusive-intent/1";
pub const BRANCH_RESERVATION_ALGEBRA_ID: &str = "auths.github.branch-ref-exclusive/1";
pub const PULL_REQUEST_RESERVATION_ALGEBRA_ID: &str = "auths.github.pull-request-head-exclusive/1";
pub const BRANCH_OBLIGATION_SCHEMA_ID: &str = "auths.github.verified-branch-publish-command/1";
pub const PULL_REQUEST_OBLIGATION_SCHEMA_ID: &str =
    "auths.github.verified-draft-pull-request-command/1";
pub const BRANCH_PROVIDER_CONTRACT_ID: &str = "auths.github.fixed-refspec-branch-publish/1";
pub const PULL_REQUEST_PROVIDER_CONTRACT_ID: &str = "auths.github.rest-draft-pull-request-create/1";
pub const DOMAIN_ID: &str = "github";

/// Complete domain inputs to the pure shared-contract projection.
pub struct GitHubLifecycleProjectionInput<'a> {
    pub grant: &'a WorkflowGrant,
    pub action: &'a ExactGitHubAction,
    pub evidence: &'a GitHubEvidence,
    pub required_configuration: &'a VerifierConfiguration,
    pub executed_configuration: &'a VerifierConfiguration,
    pub decision: &'a Decision,
    pub verifier_time: u64,
}

/// Validated shared projection of one authorized GitHub effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubLifecycleProjectionV1 {
    pub commitments: EvaluationCommitmentsV1,
    pub outputs: BoundedOutputs,
    pub reservations: ReservationSetV1,
    pub workflow_id: WorkflowId,
    pub domain_id: DomainId,
    pub executor_audience: ExecutorAudienceId,
    pub reservation_algebra_id: ReservationAlgebraId,
    pub capacity: CapacitySnapshotV1,
}

/// Durable bindings available only after Auths authorization and GitHub
/// decision-receipt construction.
pub struct GitHubLifecycleDecisionBindings<'a> {
    pub core_authorization_digest: &'a DigestHex,
    pub decision_receipt_digest: &'a DigestHex,
    pub implementation_build_digest: &'a DigestHex,
    pub expires_at: u64,
}

/// Closed failure before shared state can be persisted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GitHubLifecycleProjectionError {
    #[error("GitHub decision is not authorized")]
    NotAuthorized,
    #[error("GitHub lifecycle payload is not canonical")]
    Canonicalization,
    #[error("GitHub lifecycle digest is malformed")]
    InvalidDigest,
    #[error("GitHub lifecycle projection violates the shared contract")]
    InvalidProjection,
}

/// Shared lifecycle store plus the read required for exact replay and
/// recovery.
pub trait GitHubLifecycleStore: LifecycleStore + Send + Sync {
    /// Loads one validated immutable shared lifecycle record.
    ///
    /// # Errors
    ///
    /// Returns a closed store error for unavailable or corrupt state.
    fn load_github_lifecycle(
        &self,
        workflow: &WorkflowId,
    ) -> Result<Option<LifecycleRecordV1>, StoreError>;
}

/// Domain-local registry that selects the store enforcing one canonical
/// GitHub reservation scope.
pub trait GitHubLifecycleRegistry: Send + Sync {
    /// Returns the shared store for one exact operation-specific capacity
    /// scope.
    ///
    /// # Errors
    ///
    /// Returns a closed store error when durable state cannot be opened.
    fn for_action(
        &self,
        action: &ExactGitHubAction,
    ) -> Result<Arc<dyn GitHubLifecycleStore>, StoreError>;

    /// Persists recovery material that is committed by, but cannot authorize
    /// independently of, the shared lifecycle record.
    ///
    /// # Errors
    ///
    /// Returns a closed store error for unavailable, conflicting, or corrupt
    /// recovery state.
    fn persist_recovery(&self, record: &GitHubRecoveryRecordV1) -> Result<(), StoreError>;

    /// Loads exact domain recovery material for one workflow operation.
    ///
    /// # Errors
    ///
    /// Returns a closed store error for unavailable or corrupt recovery state.
    fn load_recovery(
        &self,
        workflow_id: &crate::types::WorkflowId,
        operation: GitHubOperation,
    ) -> Result<Option<GitHubRecoveryRecordV1>, StoreError>;
}

impl<T: GitHubLifecycleRegistry + ?Sized> GitHubLifecycleRegistry for Arc<T> {
    fn for_action(
        &self,
        action: &ExactGitHubAction,
    ) -> Result<Arc<dyn GitHubLifecycleStore>, StoreError> {
        (**self).for_action(action)
    }

    fn persist_recovery(&self, record: &GitHubRecoveryRecordV1) -> Result<(), StoreError> {
        (**self).persist_recovery(record)
    }

    fn load_recovery(
        &self,
        workflow_id: &crate::types::WorkflowId,
        operation: GitHubOperation,
    ) -> Result<Option<GitHubRecoveryRecordV1>, StoreError> {
        (**self).load_recovery(workflow_id, operation)
    }
}

/// Domain-owned exact recovery material. This record carries no execution
/// authority; every resumed operation must match the corresponding shared
/// lifecycle commitments and stage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubRecoveryRecordV1 {
    pub schema: String,
    pub workflow_id: crate::types::WorkflowId,
    pub operation: GitHubOperation,
    pub shared_workflow_id: String,
    pub exact_action: ExactGitHubAction,
    pub planning_evidence: GitHubEvidence,
    pub decision_receipt_digest: DigestHex,
    pub claim_id: DigestHex,
}

impl GitHubRecoveryRecordV1 {
    /// Validates internal commitments before recovery material is trusted.
    ///
    /// # Errors
    ///
    /// Rejects mismatched workflows, operations, actions, or shared
    /// identifiers.
    pub fn validate(&self) -> Result<(), GitHubLifecycleProjectionError> {
        if self.schema != "auths.github.recovery-record/1"
            || self.exact_action.workflow_id() != &self.workflow_id
            || self.exact_action.operation() != self.operation
            || WorkflowId::parse(&self.shared_workflow_id).is_err()
        {
            return Err(GitHubLifecycleProjectionError::InvalidProjection);
        }
        Ok(())
    }
}

impl GitHubLifecycleProjectionInput<'_> {
    /// Projects one authorized domain decision into shared commitments.
    ///
    /// # Errors
    ///
    /// Fails closed for a non-authorized decision, invalid identifiers,
    /// malformed canonical payloads, inconsistent workflow inputs, or exceeded
    /// shared limits.
    pub fn project(&self) -> Result<GitHubLifecycleProjectionV1, GitHubLifecycleProjectionError> {
        if self.decision.class != DecisionClass::Authorized {
            return Err(GitHubLifecycleProjectionError::NotAuthorized);
        }
        if self.action.workflow_id() != self.grant.workflow_id()
            || self.action.repository() != self.grant.repository()
            || self.action.issue() != self.grant.issue()
        {
            return Err(GitHubLifecycleProjectionError::InvalidProjection);
        }
        let commitments = project_commitments(self)?;
        let scope_bytes = canonical_json(&reservation_scope(self.action)).map_err(canonical)?;
        let scope_digest = commitment(&sha256(&scope_bytes))?;
        let action_bytes = self.action.canonical_bytes().map_err(canonical)?;
        let action_digest = commitments.exact_action_digest();
        let policy_digest = commitments.policy_commitment().policy_digest();
        let evidence_digest = commitments.evidence_digest();
        let operation = operation_contract(self.action.operation());
        let reservation = ReservationIntentCommitmentV1::new(
            SchemaId::parse(operation.intent_schema_id).map_err(invalid)?,
            IntentId::parse(operation.intent_id).map_err(invalid)?,
            scope_digest,
            ReservationKind::Exclusive,
            None,
            action_digest,
            policy_digest,
            evidence_digest,
            commitment(&canonical_digest(&reservation_scope(self.action)).map_err(canonical)?)?,
            u32::try_from(scope_bytes.len()).map_err(invalid)?,
        )
        .map_err(invalid)?;
        let obligation = ObligationCommitmentV1::new(
            SchemaId::parse(operation.obligation_schema_id).map_err(invalid)?,
            ObligationId::parse(operation.obligation_id).map_err(invalid)?,
            ObligationClass::CommandConstruction,
            action_digest,
            u32::try_from(action_bytes.len()).map_err(invalid)?,
        )
        .map_err(invalid)?;
        let outputs = BoundedOutputs::new(
            vec![reservation],
            vec![obligation],
            commitment(&canonical_digest(&reservation_scope(self.action)).map_err(canonical)?)?,
            commitment(&sha256(&action_bytes))?,
        )
        .map_err(invalid)?;
        let workflow_id = shared_workflow_id(self.action, policy_digest)?;
        let domain_id = DomainId::parse(DOMAIN_ID).map_err(invalid)?;
        let executor_audience =
            ExecutorAudienceId::parse(self.action.executor_audience().as_str()).map_err(invalid)?;
        let reservation_algebra_id =
            ReservationAlgebraId::parse(operation.reservation_algebra_id).map_err(invalid)?;
        let reservations = ReservationSetV1::derive(
            &workflow_id,
            &domain_id,
            commitments.profile_id(),
            commitments.policy_commitment().evaluator_semantic_id(),
            &executor_audience,
            &reservation_algebra_id,
            &outputs,
        )
        .map_err(invalid)?;
        let capacity = CapacitySnapshotV1::new(vec![CapacityEntryV1::Exclusive {
            scope_digest,
            window_digest: None,
            live_owner: None,
        }])
        .map_err(invalid)?;
        Ok(GitHubLifecycleProjectionV1 {
            commitments,
            outputs,
            reservations,
            workflow_id,
            domain_id,
            executor_audience,
            reservation_algebra_id,
            capacity,
        })
    }
}

impl GitHubLifecycleProjectionV1 {
    /// Consumes the projection into one complete shared decision input.
    ///
    /// # Errors
    ///
    /// Rejects malformed exact digests or derived identifiers.
    pub fn into_decision_input(
        self,
        bindings: &GitHubLifecycleDecisionBindings<'_>,
    ) -> Result<DecisionInputV1, GitHubLifecycleProjectionError> {
        let action_digest = self.commitments.exact_action_digest();
        let policy_digest = self.commitments.policy_commitment().policy_digest();
        let lifecycle_id = derived_identifier(
            b"AUTHS-GITHUB-LIFECYCLE\x00\x01",
            self.workflow_id.as_str(),
            action_digest,
            policy_digest,
        );
        let execution_id = derived_identifier(
            b"AUTHS-GITHUB-EXECUTION\x00\x01",
            self.workflow_id.as_str(),
            action_digest,
            policy_digest,
        );
        Ok(DecisionInputV1 {
            core_authorized: true,
            core_authorization_digest: commitment(bindings.core_authorization_digest)?,
            workflow_id: self.workflow_id,
            lifecycle_id: LifecycleId::parse(&lifecycle_id).map_err(invalid)?,
            execution_id: ExecutionId::parse(&execution_id).map_err(invalid)?,
            recovery_reference_digest: auths_lifecycle::RecoveryReferenceDigest::new(digest_bytes(
                bindings.decision_receipt_digest,
            )?),
            domain_id: self.domain_id,
            executor_audience: self.executor_audience,
            reservation_algebra_id: self.reservation_algebra_id,
            commitments: self.commitments,
            outputs: self.outputs,
            reservations: self.reservations,
            decision_receipt_digest: DecisionReceiptDigest::new(digest_bytes(
                bindings.decision_receipt_digest,
            )?),
            domain_decision_receipt_digest: DomainReceiptDigest::new(digest_bytes(
                bindings.decision_receipt_digest,
            )?),
            implementation_id: ImplementationId::parse(IMPLEMENTATION_ID).map_err(invalid)?,
            implementation_build_digest: commitment(bindings.implementation_build_digest)?,
            expires_at: VerifierTime::from_unix_seconds(bindings.expires_at),
            cancellation: CancellationDisposition::BeforeAttemptAllowed,
        })
    }

    /// Constructs the explicit transition context for this evaluation.
    #[must_use]
    pub fn transition_context(&self, verifier_time: u64) -> TransitionContextV1 {
        TransitionContextV1 {
            verifier_time: VerifierTime::from_unix_seconds(verifier_time),
            executed_configuration: self.commitments.executed_configuration().clone(),
            revocation: RevocationSnapshotV1 {
                revoked: false,
                snapshot_digest: commit_bytes(b"auths.github.revocation-not-configured/1"),
            },
            capacity: self.capacity.clone(),
        }
    }
}

/// Returns the exact branch-ref or pull-request-head capacity scope.
///
/// # Errors
///
/// Fails only if canonical scope construction fails.
pub fn reservation_scope_digest(
    action: &ExactGitHubAction,
) -> Result<CommitmentDigest, GitHubLifecycleProjectionError> {
    commitment(&canonical_digest(&reservation_scope(action)).map_err(canonical)?)
}

fn project_commitments(
    input: &GitHubLifecycleProjectionInput<'_>,
) -> Result<EvaluationCommitmentsV1, GitHubLifecycleProjectionError> {
    let operation = operation_contract(input.action.operation());
    let action_digest = commitment(&input.action.digest().map_err(canonical)?)?;
    let policy_digest = commitment(&input.grant.digest().map_err(canonical)?)?;
    let evidence_digest = commitment(&input.evidence.digest().map_err(canonical)?)?;
    Ok(EvaluationCommitmentsV1::new(
        ProfileId::parse(operation.profile_id).map_err(invalid)?,
        action_digest,
        PolicyCommitmentV1::new(
            PolicyTypeId::parse(POLICY_TYPE_ID).map_err(invalid)?,
            PROFILE_VERSION,
            CanonicalizationId::parse(CANONICALIZATION_ID).map_err(invalid)?,
            policy_digest,
            EvaluatorSemanticId::parse(operation.evaluator_semantic_id).map_err(invalid)?,
        )
        .map_err(invalid)?,
        SchemaId::parse(EVIDENCE_SCHEMA_ID).map_err(invalid)?,
        evidence_digest,
        EvidenceSourceId::parse(EVIDENCE_SOURCE_ID).map_err(invalid)?,
        VerifierTime::from_unix_seconds(input.evidence.acquired_at),
        SchemaId::parse(operation.state_schema_id).map_err(invalid)?,
        evidence_digest,
        VerifierTime::from_unix_seconds(input.verifier_time),
        configuration_commitment(input.required_configuration, false)?,
        configuration_commitment(input.executed_configuration, true)?,
    ))
}

fn configuration_commitment(
    configuration: &VerifierConfiguration,
    executed: bool,
) -> Result<ConfigurationCommitmentV1, GitHubLifecycleProjectionError> {
    Ok(ConfigurationCommitmentV1::new(
        ConfigurationSemanticId::parse(CONFIGURATION_SEMANTIC_ID).map_err(invalid)?,
        CanonicalizationId::parse(CANONICALIZATION_ID).map_err(invalid)?,
        commitment(&configuration.digest().map_err(canonical)?)?,
        executed
            .then(|| ImplementationId::parse(IMPLEMENTATION_ID))
            .transpose()
            .map_err(invalid)?,
    ))
}

#[allow(
    clippy::struct_field_names,
    reason = "each field names the exact identifier class carried into the shared contract"
)]
struct OperationContract {
    profile_id: &'static str,
    evaluator_semantic_id: &'static str,
    state_schema_id: &'static str,
    intent_schema_id: &'static str,
    intent_id: &'static str,
    reservation_algebra_id: &'static str,
    obligation_schema_id: &'static str,
    obligation_id: &'static str,
}

const fn operation_contract(operation: GitHubOperation) -> OperationContract {
    match operation {
        GitHubOperation::PublishBranch => OperationContract {
            profile_id: BRANCH_PROFILE_ID,
            evaluator_semantic_id: BRANCH_EVALUATOR_SEMANTIC_ID,
            state_schema_id: BRANCH_STATE_SCHEMA_ID,
            intent_schema_id: BRANCH_INTENT_SCHEMA_ID,
            intent_id: "branch-ref-exclusive",
            reservation_algebra_id: BRANCH_RESERVATION_ALGEBRA_ID,
            obligation_schema_id: BRANCH_OBLIGATION_SCHEMA_ID,
            obligation_id: "publish-exact-branch",
        },
        GitHubOperation::OpenDraftPullRequest => OperationContract {
            profile_id: PULL_REQUEST_PROFILE_ID,
            evaluator_semantic_id: PULL_REQUEST_EVALUATOR_SEMANTIC_ID,
            state_schema_id: PULL_REQUEST_STATE_SCHEMA_ID,
            intent_schema_id: PULL_REQUEST_INTENT_SCHEMA_ID,
            intent_id: "pull-request-head-exclusive",
            reservation_algebra_id: PULL_REQUEST_RESERVATION_ALGEBRA_ID,
            obligation_schema_id: PULL_REQUEST_OBLIGATION_SCHEMA_ID,
            obligation_id: "open-exact-draft-pull-request",
        },
    }
}

#[derive(Serialize)]
#[serde(tag = "operation", rename_all = "kebab-case")]
enum GitHubReservationScope<'a> {
    PublishBranch {
        executor_audience: &'a str,
        repository_node_id: &'a str,
        target_ref: &'a str,
        expected_target_state: &'a str,
    },
    OpenDraftPullRequest {
        executor_audience: &'a str,
        repository_node_id: &'a str,
        base_ref: &'a str,
        head_ref: &'a str,
        expected_existing_pull_requests: u8,
    },
}

fn reservation_scope(action: &ExactGitHubAction) -> GitHubReservationScope<'_> {
    match action {
        ExactGitHubAction::PublishBranch(action) => GitHubReservationScope::PublishBranch {
            executor_audience: action.executor_audience.as_str(),
            repository_node_id: action.repository.repository_node_id().as_str(),
            target_ref: action.target_ref.as_str(),
            expected_target_state: &action.expected_target_state,
        },
        ExactGitHubAction::OpenDraftPullRequest(action) => {
            GitHubReservationScope::OpenDraftPullRequest {
                executor_audience: action.executor_audience.as_str(),
                repository_node_id: action.repository.repository_node_id().as_str(),
                base_ref: action.base_ref.as_str(),
                head_ref: action.head_ref.as_str(),
                expected_existing_pull_requests: action.expected_existing_pull_requests,
            }
        }
    }
}

fn shared_workflow_id(
    action: &ExactGitHubAction,
    policy_digest: CommitmentDigest,
) -> Result<WorkflowId, GitHubLifecycleProjectionError> {
    let operation = match action.operation() {
        GitHubOperation::PublishBranch => b"branch".as_slice(),
        GitHubOperation::OpenDraftPullRequest => b"pull-request".as_slice(),
    };
    let mut hasher = Sha256::new();
    hasher.update(b"AUTHS-GITHUB-SHARED-WORKFLOW\x00\x01");
    hasher.update(operation);
    hasher.update(action.workflow_id().as_str().as_bytes());
    hasher.update(action.digest().map_err(canonical)?.as_str().as_bytes());
    hasher.update(policy_digest.as_bytes());
    WorkflowId::parse(&hex::encode(hasher.finalize())).map_err(invalid)
}

fn commitment(value: &DigestHex) -> Result<CommitmentDigest, GitHubLifecycleProjectionError> {
    Ok(CommitmentDigest::new(digest_bytes(value)?))
}

fn digest_bytes(value: &DigestHex) -> Result<[u8; 32], GitHubLifecycleProjectionError> {
    hex::decode(value.as_str())
        .map_err(|_| GitHubLifecycleProjectionError::InvalidDigest)?
        .try_into()
        .map_err(|_| GitHubLifecycleProjectionError::InvalidDigest)
}

fn commit_bytes(value: &[u8]) -> CommitmentDigest {
    CommitmentDigest::new(Sha256::digest(value).into())
}

fn derived_identifier(
    domain: &[u8],
    workflow_id: &str,
    action_digest: CommitmentDigest,
    policy_digest: CommitmentDigest,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(workflow_id.as_bytes());
    hasher.update(action_digest.as_bytes());
    hasher.update(policy_digest.as_bytes());
    hex::encode(hasher.finalize())
}

fn canonical(_: impl core::fmt::Debug) -> GitHubLifecycleProjectionError {
    GitHubLifecycleProjectionError::Canonicalization
}

fn invalid(_: impl core::fmt::Debug) -> GitHubLifecycleProjectionError {
    GitHubLifecycleProjectionError::InvalidProjection
}
