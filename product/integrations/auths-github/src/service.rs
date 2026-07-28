//! End-to-end orchestration for one exact GitHub issue workflow.

use crate::{
    candidate::{CandidateError, CandidateSubmission, QuarantinedCandidate},
    canonical::sha256,
    containment::{Decision, DecisionClass, DecisionCode, EvaluationContext, evaluate},
    evidence::GitHubEvidence,
    executor::{VerifiedOpenDraftPullRequest, VerifiedPublishBranch},
    ports::{
        CandidateInspector, Clock, CredentialProvider, ExactActionAuthorizer, GitHubReadError,
        GitHubReadPort, GitHubWriteError, GitHubWritePort, ReceiptSink,
    },
    receipts::{
        ExecutionResult, GitHubDecisionReceipt, GitHubExecutionReceipt, GitHubReceipt,
        ObservedGitHubState, OpenedPullRequest, PublishedBranch, ReconciliationEntry,
    },
    types::{
        ExactGitHubAction, GitHubOperation, OpenDraftPullRequestAction, PublishBranchAction,
        VerifierConfiguration, WorkflowGrant,
    },
    workflow::{ClaimRecord, ClaimResult, ExecutionClaim, WorkflowStage, WorkflowStore},
};

/// Hostile candidate plus the fixed human workflow.
pub struct ExecuteWorkflowRequest {
    /// Human-issued constraints.
    pub workflow_grant: WorkflowGrant,
    /// Configuration demanded by the caller/grant context.
    pub required_configuration: VerifierConfiguration,
    /// Hostile candidate bundle.
    pub candidate: CandidateSubmission,
}

/// Explicit trusted dependencies.
pub struct ServiceDependencies<I, G, A, W, C, R, S, T> {
    /// Trusted Git inspector.
    pub candidate_inspector: I,
    /// Read-only fresh GitHub evidence.
    pub github_read: G,
    /// Executor-owned exact child-proof authorizer.
    pub action_authorizer: A,
    /// Durable effect claims.
    pub workflow_store: W,
    /// GitHub App credential broker.
    pub credential_provider: C,
    /// Only GitHub mutation boundary.
    pub github_write: R,
    /// Signed append-only receipts.
    pub receipt_sink: S,
    /// Trusted clock.
    pub clock: T,
    /// Configuration actually loaded by this executor.
    pub executed_configuration: VerifierConfiguration,
    /// Public receipt-view base URL used in deterministic PR bodies.
    pub receipt_view_base_url: String,
    /// Public executor identity.
    pub executor_identity: String,
}

/// Complete vertical GitHub product service.
pub struct GitHubIssueWorkflowService<I, G, A, W, C, R, S, T> {
    dependencies: ServiceDependencies<I, G, A, W, C, R, S, T>,
}

impl<I, G, A, W, C, R, S, T> GitHubIssueWorkflowService<I, G, A, W, C, R, S, T>
where
    I: CandidateInspector,
    G: GitHubReadPort,
    A: ExactActionAuthorizer,
    W: WorkflowStore,
    C: CredentialProvider,
    R: GitHubWritePort,
    S: ReceiptSink,
    T: Clock,
{
    /// Constructs the workflow from explicit boundaries.
    ///
    /// # Errors
    ///
    /// Rejects invalid public receipt URLs and executor identities.
    pub fn new(
        dependencies: ServiceDependencies<I, G, A, W, C, R, S, T>,
    ) -> Result<Self, ServiceError> {
        if !dependencies.receipt_view_base_url.starts_with("https://")
            || dependencies.receipt_view_base_url.ends_with('/')
            || dependencies.receipt_view_base_url.len() > 512
            || dependencies.executor_identity.is_empty()
            || dependencies.executor_identity.len() > 256
        {
            return Err(ServiceError::InvalidConfiguration);
        }
        dependencies
            .executed_configuration
            .validate()
            .map_err(|_| ServiceError::InvalidConfiguration)?;
        Ok(Self { dependencies })
    }

    /// Inspects, authorizes, claims, publishes, confirms, and opens one draft PR.
    ///
    /// No credential is requested until product containment and the Auths
    /// kernel authorize the same exact action and its effect is durably claimed.
    ///
    /// # Errors
    ///
    /// Returns a typed internal/adapter failure. Product denials are successful
    /// results with durable decision receipts.
    #[allow(
        clippy::too_many_lines,
        reason = "security-relevant effect ordering is intentionally linear and visible"
    )]
    pub fn execute(
        &self,
        request: ExecuteWorkflowRequest,
    ) -> Result<WorkflowOutcome, ServiceError> {
        let now = self
            .dependencies
            .clock
            .now()
            .map_err(|_| ServiceError::Clock)?;
        request
            .workflow_grant
            .validate()
            .map_err(|_| ServiceError::InvalidGrant)?;
        let grant_digest = request
            .workflow_grant
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;

        if request.required_configuration != *request.workflow_grant.required_configuration()
            || request.required_configuration != self.dependencies.executed_configuration
        {
            return self.reject_preflight(
                &request.workflow_grant,
                grant_digest,
                request.required_configuration,
                Decision::denied(
                    DecisionCode::VerifierConfigurationMismatch,
                    "required and executed verifier configurations differ",
                ),
                now,
            );
        }

        let initial_state = self
            .dependencies
            .workflow_store
            .initialize(request.workflow_grant.workflow_id())
            .map_err(|_| ServiceError::WorkflowState)?;
        if initial_state.stage == WorkflowStage::Completed {
            let receipt_digest = initial_state
                .pull_request_claim
                .as_ref()
                .and_then(|claim| claim.execution_receipt_digest.clone())
                .ok_or(ServiceError::WorkflowState)?;
            return Ok(WorkflowOutcome::Replay {
                operation: GitHubOperation::OpenDraftPullRequest,
                receipt_digest,
            });
        }
        if matches!(
            initial_state.stage,
            WorkflowStage::BranchClaimed
                | WorkflowStage::BranchReconciliationRequired
                | WorkflowStage::PullRequestClaimed
                | WorkflowStage::PullRequestReconciliationRequired
        ) {
            let operation = if matches!(
                initial_state.stage,
                WorkflowStage::BranchClaimed | WorkflowStage::BranchReconciliationRequired
            ) {
                GitHubOperation::PublishBranch
            } else {
                GitHubOperation::OpenDraftPullRequest
            };
            return Ok(WorkflowOutcome::ReconciliationRequired { operation });
        }
        let candidate = match self.dependencies.candidate_inspector.inspect(
            &request.candidate,
            request.workflow_grant.candidate_policy(),
            request.workflow_grant.object_format(),
        ) {
            Ok(candidate) => candidate,
            Err(error) => {
                return self.reject_preflight(
                    &request.workflow_grant,
                    grant_digest,
                    request.required_configuration,
                    decision_from_candidate_error(error),
                    now,
                );
            }
        };
        self.dependencies
            .workflow_store
            .accept_candidate(request.workflow_grant.workflow_id())
            .map_err(|_| ServiceError::WorkflowState)?;

        if initial_state.stage == WorkflowStage::BranchPublished {
            let branch_claim = initial_state
                .branch_claim
                .as_ref()
                .filter(|claim| claim.execution_receipt_digest.is_some())
                .ok_or(ServiceError::WorkflowState)?;
            let evidence =
                self.acquire_evidence(&request.workflow_grant, candidate.evidence(), now)?;
            if evidence.target.revision.as_ref() != Some(candidate.evidence().candidate_revision())
            {
                return Ok(WorkflowOutcome::ReconciliationRequired {
                    operation: GitHubOperation::PublishBranch,
                });
            }
            let published_branch = PublishedBranch {
                repository_id: request.workflow_grant.repository().repository_id(),
                branch_ref: request
                    .workflow_grant
                    .target_ref()
                    .map_err(|_| ServiceError::InvalidGrant)?,
                head_revision: candidate.evidence().candidate_revision().clone(),
            };
            return self.continue_after_branch(
                &request.workflow_grant,
                &request.required_configuration,
                &candidate,
                published_branch,
                branch_claim
                    .execution_receipt_digest
                    .clone()
                    .ok_or(ServiceError::WorkflowState)?,
                &branch_claim.action_digest,
            );
        }

        let branch_evidence =
            self.acquire_evidence(&request.workflow_grant, candidate.evidence(), now)?;
        let branch_action = derive_publish_branch_action(
            &request.workflow_grant,
            &request.required_configuration,
            &branch_evidence,
        )?;
        let branch_result = self.authorize_action(
            &request.workflow_grant,
            &request.required_configuration,
            &candidate,
            &branch_evidence,
            ExactGitHubAction::PublishBranch(branch_action),
            now,
        )?;
        let AuthorizedAction {
            action: branch_action,
            proof: branch_proof,
            decision: branch_decision,
            decision_digest: branch_decision_digest,
        } = match branch_result {
            AuthorizationResult::Authorized(authorized) => *authorized,
            AuthorizationResult::Rejected(receipt) => {
                return Ok(WorkflowOutcome::Rejected { receipt });
            }
        };
        let branch_action_digest = branch_action
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let branch_claim = match self.dependencies.workflow_store.claim(
            request.workflow_grant.workflow_id(),
            &branch_action,
            &branch_decision_digest,
            now,
        ) {
            ClaimResult::Claimed(claim) => claim,
            ClaimResult::Replay(receipt_digest) => {
                return Ok(WorkflowOutcome::Replay {
                    operation: GitHubOperation::PublishBranch,
                    receipt_digest,
                });
            }
            ClaimResult::ReconciliationRequired(_) => {
                return Ok(WorkflowOutcome::ReconciliationRequired {
                    operation: GitHubOperation::PublishBranch,
                });
            }
            ClaimResult::BudgetExhausted(_) => {
                return Ok(WorkflowOutcome::Rejected {
                    receipt: Box::new(
                        self.append_budget_denial(
                            &request.workflow_grant,
                            &request.required_configuration,
                            Some(branch_action_digest),
                            Some(
                                branch_evidence
                                    .digest()
                                    .map_err(|_| ServiceError::Canonicalization)?,
                            ),
                            DecisionCode::BranchBudgetExhausted,
                            now,
                        )?,
                    ),
                });
            }
            ClaimResult::Unavailable => return Err(ServiceError::WorkflowState),
        };
        let branch_command =
            VerifiedPublishBranch::new(branch_proof.authorized, branch_claim.clone())
                .map_err(|_| ServiceError::SealedCommand)?;
        let branch_credential = self
            .dependencies
            .credential_provider
            .installation_credential(
                request.workflow_grant.repository(),
                GitHubOperation::PublishBranch,
            )
            .map_err(|_| ServiceError::Credential)?;
        let published_branch = match self.dependencies.github_write.publish_branch(
            &branch_command,
            &candidate,
            &branch_credential,
        ) {
            Ok(branch) => branch,
            Err(error) => {
                return self.execution_failure(
                    &request.workflow_grant,
                    &branch_claim,
                    branch_decision_digest,
                    branch_action_digest,
                    WorkflowStage::CandidateAccepted,
                    error,
                    now,
                );
            }
        };
        if published_branch.repository_id != request.workflow_grant.repository().repository_id()
            || published_branch.branch_ref != *branch_command.target_ref()
            || published_branch.head_revision != *branch_command.candidate_revision()
        {
            self.dependencies
                .workflow_store
                .require_reconciliation(&branch_claim, now)
                .map_err(|_| ServiceError::WorkflowState)?;
            return Ok(WorkflowOutcome::ReconciliationRequired {
                operation: GitHubOperation::PublishBranch,
            });
        }
        let branch_execution = GitHubExecutionReceipt {
            schema: self
                .dependencies
                .executed_configuration
                .receipt_schema()
                .into(),
            decision_receipt_digest: branch_decision_digest,
            action_digest: branch_action_digest,
            claim_id: branch_claim.claim_id().clone(),
            expected_prior_state: WorkflowStage::CandidateAccepted,
            operation: GitHubOperation::PublishBranch,
            observed_state: Some(ObservedGitHubState::Branch(published_branch.clone())),
            repository_id: request.workflow_grant.repository().repository_id(),
            result: ExecutionResult::Succeeded,
            executed_at: now,
            reconciliation_history: Vec::new(),
        };
        let branch_execution_digest = self.append_execution(&branch_execution)?;
        self.dependencies
            .workflow_store
            .complete(&branch_claim, &branch_execution_digest, now)
            .map_err(|_| ServiceError::WorkflowState)?;

        let pr_now = self
            .dependencies
            .clock
            .now()
            .map_err(|_| ServiceError::Clock)?;
        let pull_request_evidence =
            self.acquire_evidence(&request.workflow_grant, candidate.evidence(), pr_now)?;
        let exact_body = deterministic_pull_request_body(
            &request.workflow_grant,
            candidate.evidence().candidate_revision(),
            &branch_execution.action_digest,
            &self.dependencies.receipt_view_base_url,
        );
        let pull_request_action = derive_open_pull_request_action(
            &request.workflow_grant,
            &request.required_configuration,
            &pull_request_evidence,
            &branch_execution_digest,
            &exact_body,
        )?;
        let pull_request_result = self.authorize_action(
            &request.workflow_grant,
            &request.required_configuration,
            &candidate,
            &pull_request_evidence,
            ExactGitHubAction::OpenDraftPullRequest(pull_request_action),
            pr_now,
        )?;
        let AuthorizedAction {
            action: pull_request_action,
            proof: pull_request_proof,
            decision: pull_request_decision,
            decision_digest: pull_request_decision_digest,
        } = match pull_request_result {
            AuthorizationResult::Authorized(authorized) => *authorized,
            AuthorizationResult::Rejected(receipt) => {
                return Ok(WorkflowOutcome::Partial {
                    branch: published_branch,
                    branch_decision: Box::new(branch_decision),
                    branch_execution: Box::new(branch_execution),
                    pull_request_decision: Some(receipt),
                });
            }
        };
        let pull_request_action_digest = pull_request_action
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let pull_request_claim = match self.dependencies.workflow_store.claim(
            request.workflow_grant.workflow_id(),
            &pull_request_action,
            &pull_request_decision_digest,
            pr_now,
        ) {
            ClaimResult::Claimed(claim) => claim,
            ClaimResult::Replay(receipt_digest) => {
                return Ok(WorkflowOutcome::Replay {
                    operation: GitHubOperation::OpenDraftPullRequest,
                    receipt_digest,
                });
            }
            ClaimResult::ReconciliationRequired(_) => {
                return Ok(WorkflowOutcome::ReconciliationRequired {
                    operation: GitHubOperation::OpenDraftPullRequest,
                });
            }
            ClaimResult::BudgetExhausted(_) => {
                let receipt = self.append_budget_denial(
                    &request.workflow_grant,
                    &request.required_configuration,
                    Some(pull_request_action_digest),
                    Some(
                        pull_request_evidence
                            .digest()
                            .map_err(|_| ServiceError::Canonicalization)?,
                    ),
                    DecisionCode::PullRequestBudgetExhausted,
                    pr_now,
                )?;
                return Ok(WorkflowOutcome::Partial {
                    branch: published_branch,
                    branch_decision: Box::new(branch_decision),
                    branch_execution: Box::new(branch_execution),
                    pull_request_decision: Some(Box::new(receipt)),
                });
            }
            ClaimResult::Unavailable => return Err(ServiceError::WorkflowState),
        };
        let pull_request_command = VerifiedOpenDraftPullRequest::new(
            pull_request_proof.authorized,
            pull_request_claim.clone(),
            exact_body,
        )
        .map_err(|_| ServiceError::SealedCommand)?;
        let pull_request_credential = self
            .dependencies
            .credential_provider
            .installation_credential(
                request.workflow_grant.repository(),
                GitHubOperation::OpenDraftPullRequest,
            )
            .map_err(|_| ServiceError::Credential)?;
        let opened_pull_request = match self
            .dependencies
            .github_write
            .open_draft_pull_request(&pull_request_command, &pull_request_credential)
        {
            Ok(pull_request) => pull_request,
            Err(error) => {
                return self.execution_failure(
                    &request.workflow_grant,
                    &pull_request_claim,
                    pull_request_decision_digest,
                    pull_request_action_digest,
                    WorkflowStage::BranchPublished,
                    error,
                    pr_now,
                );
            }
        };
        if !opened_pull_request.draft
            || opened_pull_request.base_ref != *request.workflow_grant.base_ref()
            || opened_pull_request.head_ref
                != request
                    .workflow_grant
                    .target_ref()
                    .map_err(|_| ServiceError::InvalidGrant)?
            || opened_pull_request.head_revision != *candidate.evidence().candidate_revision()
        {
            self.dependencies
                .workflow_store
                .require_reconciliation(&pull_request_claim, pr_now)
                .map_err(|_| ServiceError::WorkflowState)?;
            return Ok(WorkflowOutcome::ReconciliationRequired {
                operation: GitHubOperation::OpenDraftPullRequest,
            });
        }
        let pull_request_execution = GitHubExecutionReceipt {
            schema: self
                .dependencies
                .executed_configuration
                .receipt_schema()
                .into(),
            decision_receipt_digest: pull_request_decision_digest,
            action_digest: pull_request_action_digest,
            claim_id: pull_request_claim.claim_id().clone(),
            expected_prior_state: WorkflowStage::BranchPublished,
            operation: GitHubOperation::OpenDraftPullRequest,
            observed_state: Some(ObservedGitHubState::PullRequest(
                opened_pull_request.clone(),
            )),
            repository_id: request.workflow_grant.repository().repository_id(),
            result: ExecutionResult::Succeeded,
            executed_at: pr_now,
            reconciliation_history: Vec::new(),
        };
        let pull_request_execution_digest = self.append_execution(&pull_request_execution)?;
        self.dependencies
            .workflow_store
            .complete(&pull_request_claim, &pull_request_execution_digest, pr_now)
            .map_err(|_| ServiceError::WorkflowState)?;
        Ok(WorkflowOutcome::Completed {
            branch: published_branch,
            pull_request: opened_pull_request,
            branch_decision: Box::new(branch_decision),
            branch_execution: Box::new(branch_execution),
            pull_request_decision: Box::new(pull_request_decision),
            pull_request_execution: Box::new(pull_request_execution),
        })
    }

    /// Reconciles an already claimed effect from fresh GitHub postconditions.
    ///
    /// This operation never calls the GitHub write port and never requests a
    /// credential. It can therefore prove a mutation accepted before a crash
    /// without issuing a second push or pull-request request.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for corrupt durable state, invalid recovery
    /// inputs, unavailable evidence, clock failure, or receipt persistence.
    #[allow(
        clippy::too_many_lines,
        reason = "reconciliation keeps validation, observation, receipt, and state commitment linear"
    )]
    pub fn reconcile(
        &self,
        request: ExecuteWorkflowRequest,
    ) -> Result<WorkflowOutcome, ServiceError> {
        let now = self
            .dependencies
            .clock
            .now()
            .map_err(|_| ServiceError::Clock)?;
        request
            .workflow_grant
            .validate()
            .map_err(|_| ServiceError::InvalidGrant)?;
        if request.required_configuration != *request.workflow_grant.required_configuration()
            || request.required_configuration != self.dependencies.executed_configuration
        {
            return self.reject_preflight(
                &request.workflow_grant,
                request
                    .workflow_grant
                    .digest()
                    .map_err(|_| ServiceError::Canonicalization)?,
                request.required_configuration,
                Decision::denied(
                    DecisionCode::VerifierConfigurationMismatch,
                    "required and executed verifier configurations differ",
                ),
                now,
            );
        }
        let state = self
            .dependencies
            .workflow_store
            .load(request.workflow_grant.workflow_id())
            .map_err(|_| ServiceError::WorkflowState)?
            .ok_or(ServiceError::WorkflowState)?;
        let operation = match state.stage {
            WorkflowStage::BranchClaimed | WorkflowStage::BranchReconciliationRequired => {
                GitHubOperation::PublishBranch
            }
            WorkflowStage::PullRequestClaimed
            | WorkflowStage::PullRequestReconciliationRequired => {
                GitHubOperation::OpenDraftPullRequest
            }
            WorkflowStage::Completed => {
                let receipt_digest = state
                    .pull_request_claim
                    .as_ref()
                    .and_then(|claim| claim.execution_receipt_digest.clone())
                    .ok_or(ServiceError::WorkflowState)?;
                return Ok(WorkflowOutcome::Replay {
                    operation: GitHubOperation::OpenDraftPullRequest,
                    receipt_digest,
                });
            }
            _ => return Err(ServiceError::WorkflowState),
        };
        let record = state
            .claim(operation)
            .cloned()
            .ok_or(ServiceError::WorkflowState)?;
        let candidate = self
            .dependencies
            .candidate_inspector
            .inspect(
                &request.candidate,
                request.workflow_grant.candidate_policy(),
                request.workflow_grant.object_format(),
            )
            .map_err(ServiceError::Candidate)?;
        if !recovery_action_matches(
            &record,
            &request.workflow_grant,
            &request.required_configuration,
            &candidate,
        )? {
            return Err(ServiceError::WorkflowState);
        }
        let evidence = self.acquire_evidence(&request.workflow_grant, candidate.evidence(), now)?;
        let observed_state = match &record.exact_action {
            ExactGitHubAction::PublishBranch(action) => {
                if evidence.target.revision.as_ref() != Some(&action.candidate_revision) {
                    return Ok(WorkflowOutcome::ReconciliationRequired { operation });
                }
                ObservedGitHubState::Branch(PublishedBranch {
                    repository_id: action.repository.repository_id(),
                    branch_ref: action.target_ref.clone(),
                    head_revision: action.candidate_revision.clone(),
                })
            }
            ExactGitHubAction::OpenDraftPullRequest(action) => {
                let mut exact = evidence
                    .matching_pull_requests
                    .iter()
                    .filter(|pull_request| {
                        pull_request.base_ref == action.base_ref
                            && pull_request.head_ref == action.head_ref
                            && pull_request.head_revision == action.head_revision
                            && pull_request.draft == action.draft
                    });
                let Some(pull_request) = exact.next() else {
                    return Ok(WorkflowOutcome::ReconciliationRequired { operation });
                };
                if exact.next().is_some() {
                    return Ok(WorkflowOutcome::ReconciliationRequired { operation });
                }
                ObservedGitHubState::PullRequest(pull_request.clone().into())
            }
        };
        let claim =
            ExecutionClaim::from_record(request.workflow_grant.workflow_id().clone(), &record)
                .map_err(|_| ServiceError::WorkflowState)?;
        let execution = GitHubExecutionReceipt {
            schema: self
                .dependencies
                .executed_configuration
                .receipt_schema()
                .into(),
            decision_receipt_digest: record.decision_receipt_digest,
            action_digest: record.action_digest,
            claim_id: record.claim_id,
            expected_prior_state: match operation {
                GitHubOperation::PublishBranch => WorkflowStage::CandidateAccepted,
                GitHubOperation::OpenDraftPullRequest => WorkflowStage::BranchPublished,
            },
            operation,
            observed_state: Some(observed_state.clone()),
            repository_id: request.workflow_grant.repository().repository_id(),
            result: ExecutionResult::Succeeded,
            executed_at: now,
            reconciliation_history: vec![ReconciliationEntry {
                result: ExecutionResult::Succeeded,
                observed_at: now,
            }],
        };
        let receipt_digest = self.append_execution(&execution)?;
        self.dependencies
            .workflow_store
            .complete(&claim, &receipt_digest, now)
            .map_err(|_| ServiceError::WorkflowState)?;
        Ok(WorkflowOutcome::Reconciled {
            operation,
            observed_state,
            receipt: Box::new(execution),
        })
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "recovery continuation keeps the separately claimed PR effect ordering explicit"
    )]
    fn continue_after_branch(
        &self,
        grant: &WorkflowGrant,
        required_configuration: &VerifierConfiguration,
        candidate: &QuarantinedCandidate,
        published_branch: PublishedBranch,
        branch_execution_receipt_digest: crate::types::DigestHex,
        branch_action_digest: &crate::types::DigestHex,
    ) -> Result<WorkflowOutcome, ServiceError> {
        let now = self
            .dependencies
            .clock
            .now()
            .map_err(|_| ServiceError::Clock)?;
        let evidence = self.acquire_evidence(grant, candidate.evidence(), now)?;
        let exact_body = deterministic_pull_request_body(
            grant,
            candidate.evidence().candidate_revision(),
            branch_action_digest,
            &self.dependencies.receipt_view_base_url,
        );
        let action = derive_open_pull_request_action(
            grant,
            required_configuration,
            &evidence,
            &branch_execution_receipt_digest,
            &exact_body,
        )?;
        let result = self.authorize_action(
            grant,
            required_configuration,
            candidate,
            &evidence,
            ExactGitHubAction::OpenDraftPullRequest(action),
            now,
        )?;
        let AuthorizedAction {
            action,
            proof,
            decision,
            decision_digest,
        } = match result {
            AuthorizationResult::Authorized(authorized) => *authorized,
            AuthorizationResult::Rejected(receipt) => {
                return Ok(WorkflowOutcome::ResumedPartial {
                    branch: published_branch,
                    branch_execution_receipt_digest,
                    pull_request_decision: receipt,
                });
            }
        };
        let action_digest = action
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let claim = match self.dependencies.workflow_store.claim(
            grant.workflow_id(),
            &action,
            &decision_digest,
            now,
        ) {
            ClaimResult::Claimed(claim) => claim,
            ClaimResult::Replay(receipt_digest) => {
                return Ok(WorkflowOutcome::Replay {
                    operation: GitHubOperation::OpenDraftPullRequest,
                    receipt_digest,
                });
            }
            ClaimResult::ReconciliationRequired(_) => {
                return Ok(WorkflowOutcome::ReconciliationRequired {
                    operation: GitHubOperation::OpenDraftPullRequest,
                });
            }
            ClaimResult::BudgetExhausted(_) => {
                let denial = self.append_budget_denial(
                    grant,
                    required_configuration,
                    Some(action_digest),
                    Some(
                        evidence
                            .digest()
                            .map_err(|_| ServiceError::Canonicalization)?,
                    ),
                    DecisionCode::PullRequestBudgetExhausted,
                    now,
                )?;
                return Ok(WorkflowOutcome::ResumedPartial {
                    branch: published_branch,
                    branch_execution_receipt_digest,
                    pull_request_decision: Box::new(denial),
                });
            }
            ClaimResult::Unavailable => return Err(ServiceError::WorkflowState),
        };
        let command =
            VerifiedOpenDraftPullRequest::new(proof.authorized, claim.clone(), exact_body)
                .map_err(|_| ServiceError::SealedCommand)?;
        let credential = self
            .dependencies
            .credential_provider
            .installation_credential(grant.repository(), GitHubOperation::OpenDraftPullRequest)
            .map_err(|_| ServiceError::Credential)?;
        let opened = match self
            .dependencies
            .github_write
            .open_draft_pull_request(&command, &credential)
        {
            Ok(opened) => opened,
            Err(error) => {
                return self.execution_failure(
                    grant,
                    &claim,
                    decision_digest,
                    action_digest,
                    WorkflowStage::BranchPublished,
                    error,
                    now,
                );
            }
        };
        if !opened.draft
            || opened.base_ref != *grant.base_ref()
            || opened.head_ref != grant.target_ref().map_err(|_| ServiceError::InvalidGrant)?
            || opened.head_revision != *candidate.evidence().candidate_revision()
        {
            self.dependencies
                .workflow_store
                .require_reconciliation(&claim, now)
                .map_err(|_| ServiceError::WorkflowState)?;
            return Ok(WorkflowOutcome::ReconciliationRequired {
                operation: GitHubOperation::OpenDraftPullRequest,
            });
        }
        let execution = GitHubExecutionReceipt {
            schema: self
                .dependencies
                .executed_configuration
                .receipt_schema()
                .into(),
            decision_receipt_digest: decision_digest,
            action_digest,
            claim_id: claim.claim_id().clone(),
            expected_prior_state: WorkflowStage::BranchPublished,
            operation: GitHubOperation::OpenDraftPullRequest,
            observed_state: Some(ObservedGitHubState::PullRequest(opened.clone())),
            repository_id: grant.repository().repository_id(),
            result: ExecutionResult::Succeeded,
            executed_at: now,
            reconciliation_history: Vec::new(),
        };
        let execution_digest = self.append_execution(&execution)?;
        self.dependencies
            .workflow_store
            .complete(&claim, &execution_digest, now)
            .map_err(|_| ServiceError::WorkflowState)?;
        Ok(WorkflowOutcome::ResumedCompleted {
            branch: published_branch,
            pull_request: opened,
            branch_execution_receipt_digest,
            pull_request_decision: Box::new(decision),
            pull_request_execution: Box::new(execution),
        })
    }

    fn acquire_evidence(
        &self,
        grant: &WorkflowGrant,
        candidate: &crate::candidate::CandidateEvidence,
        now: u64,
    ) -> Result<GitHubEvidence, ServiceError> {
        let repository = self
            .dependencies
            .github_read
            .repository(grant.repository())
            .map_err(ServiceError::GitHubRead)?;
        let issue = self
            .dependencies
            .github_read
            .issue(grant.issue())
            .map_err(ServiceError::GitHubRead)?;
        let base = self
            .dependencies
            .github_read
            .ref_state(grant.repository(), grant.base_ref())
            .map_err(ServiceError::GitHubRead)?;
        let target_ref = grant.target_ref().map_err(|_| ServiceError::InvalidGrant)?;
        let target = self
            .dependencies
            .github_read
            .ref_state(grant.repository(), &target_ref)
            .map_err(ServiceError::GitHubRead)?;
        let matching_pull_requests = self
            .dependencies
            .github_read
            .matching_pull_requests(grant.repository(), &target_ref, grant.base_ref())
            .map_err(ServiceError::GitHubRead)?;
        let evidence = GitHubEvidence {
            schema: "auths-github-evidence-v1".into(),
            workflow_id: grant.workflow_id().clone(),
            repository,
            issue,
            base,
            target,
            matching_pull_requests,
            candidate: candidate.clone(),
            repository_policy_digest: self
                .dependencies
                .executed_configuration
                .repository_automation_policy_digest()
                .clone(),
            acquired_at: now,
            source_configuration: "github-rest-v3".into(),
        };
        evidence
            .validate(
                grant.repository(),
                grant.issue(),
                grant.base_ref(),
                &target_ref,
            )
            .map_err(|_| ServiceError::Evidence)?;
        Ok(evidence)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "all committed decision inputs remain explicit"
    )]
    fn authorize_action(
        &self,
        grant: &WorkflowGrant,
        required_configuration: &VerifierConfiguration,
        candidate: &QuarantinedCandidate,
        evidence: &GitHubEvidence,
        action: ExactGitHubAction,
        now: u64,
    ) -> Result<AuthorizationResult, ServiceError> {
        let product_decision = evaluate(&EvaluationContext {
            grant,
            action: &action,
            candidate: candidate.evidence(),
            evidence,
            required_configuration,
            executed_configuration: &self.dependencies.executed_configuration,
            request_audience: grant.executor_audience().as_str(),
            now,
        });
        let action_digest = action
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let evidence_digest = evidence
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let mut decision = self.decision_receipt(
            grant,
            required_configuration,
            Some(action_digest),
            Some(evidence_digest),
            product_decision.clone(),
            now,
        )?;
        if product_decision.class != DecisionClass::Authorized {
            self.append_decision(&decision)?;
            return Ok(AuthorizationResult::Rejected(Box::new(decision)));
        }
        let proof = match self.dependencies.action_authorizer.authorize(&action, now) {
            Ok(proof) => proof,
            Err(error) => {
                decision.auths_code = Some(
                    match error {
                        crate::ports::ProofError::Denied => "workflow-proof-invalid",
                        crate::ports::ProofError::Indeterminate => "evidence-missing",
                        crate::ports::ProofError::Adapter => "proof-adapter-failed",
                    }
                    .into(),
                );
                self.append_decision(&decision)?;
                return Ok(AuthorizationResult::Rejected(Box::new(decision)));
            }
        };
        if proof.authorized.command().action() != &action {
            return Err(ServiceError::SealedCommand);
        }
        decision.proof_digest = Some(proof.proof_digest.clone());
        decision.trusted_context_digest = Some(proof.context_digest.clone());
        decision.auths_code = Some("authorized".into());
        let decision_digest = self.append_decision(&decision)?;
        Ok(AuthorizationResult::Authorized(Box::new(
            AuthorizedAction {
                action,
                proof,
                decision,
                decision_digest,
            },
        )))
    }

    fn reject_preflight(
        &self,
        grant: &WorkflowGrant,
        grant_digest: crate::types::DigestHex,
        required_configuration: VerifierConfiguration,
        product_decision: Decision,
        now: u64,
    ) -> Result<WorkflowOutcome, ServiceError> {
        let receipt = GitHubDecisionReceipt {
            schema: self
                .dependencies
                .executed_configuration
                .receipt_schema()
                .into(),
            workflow_id: grant.workflow_id().clone(),
            workflow_grant_digest: grant_digest,
            action_digest: None,
            proof_digest: None,
            trusted_context_digest: None,
            required_configuration_digest: required_configuration
                .digest()
                .map_err(|_| ServiceError::Canonicalization)?,
            executed_configuration_digest: self
                .dependencies
                .executed_configuration
                .digest()
                .map_err(|_| ServiceError::Canonicalization)?,
            required_configuration,
            executed_configuration: self.dependencies.executed_configuration.clone(),
            evidence_digest: None,
            product_decision,
            auths_code: None,
            executor_identity: self.dependencies.executor_identity.clone(),
            evaluated_at: now,
        };
        self.append_decision(&receipt)?;
        Ok(WorkflowOutcome::Rejected {
            receipt: Box::new(receipt),
        })
    }

    fn decision_receipt(
        &self,
        grant: &WorkflowGrant,
        required_configuration: &VerifierConfiguration,
        action_digest: Option<crate::types::DigestHex>,
        evidence_digest: Option<crate::types::DigestHex>,
        product_decision: Decision,
        now: u64,
    ) -> Result<GitHubDecisionReceipt, ServiceError> {
        Ok(GitHubDecisionReceipt {
            schema: self
                .dependencies
                .executed_configuration
                .receipt_schema()
                .into(),
            workflow_id: grant.workflow_id().clone(),
            workflow_grant_digest: grant.digest().map_err(|_| ServiceError::Canonicalization)?,
            action_digest,
            proof_digest: None,
            trusted_context_digest: None,
            required_configuration: required_configuration.clone(),
            executed_configuration: self.dependencies.executed_configuration.clone(),
            required_configuration_digest: required_configuration
                .digest()
                .map_err(|_| ServiceError::Canonicalization)?,
            executed_configuration_digest: self
                .dependencies
                .executed_configuration
                .digest()
                .map_err(|_| ServiceError::Canonicalization)?,
            evidence_digest,
            product_decision,
            auths_code: None,
            executor_identity: self.dependencies.executor_identity.clone(),
            evaluated_at: now,
        })
    }

    fn append_budget_denial(
        &self,
        grant: &WorkflowGrant,
        required_configuration: &VerifierConfiguration,
        action_digest: Option<crate::types::DigestHex>,
        evidence_digest: Option<crate::types::DigestHex>,
        code: DecisionCode,
        now: u64,
    ) -> Result<GitHubDecisionReceipt, ServiceError> {
        let receipt = self.decision_receipt(
            grant,
            required_configuration,
            action_digest,
            evidence_digest,
            Decision::denied(code, "the exact workflow publication budget is exhausted"),
            now,
        )?;
        self.append_decision(&receipt)?;
        Ok(receipt)
    }

    fn append_decision(
        &self,
        decision: &GitHubDecisionReceipt,
    ) -> Result<crate::types::DigestHex, ServiceError> {
        self.dependencies
            .receipt_sink
            .append(&GitHubReceipt::Decision(Box::new(decision.clone())))
            .map_err(|_| ServiceError::Receipt)
    }

    fn append_execution(
        &self,
        execution: &GitHubExecutionReceipt,
    ) -> Result<crate::types::DigestHex, ServiceError> {
        self.dependencies
            .receipt_sink
            .append(&GitHubReceipt::Execution(Box::new(execution.clone())))
            .map_err(|_| ServiceError::Receipt)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "failure receipt must explicitly bind every claimed value"
    )]
    fn execution_failure(
        &self,
        grant: &WorkflowGrant,
        claim: &crate::workflow::ExecutionClaim,
        decision_digest: crate::types::DigestHex,
        action_digest: crate::types::DigestHex,
        prior_state: WorkflowStage,
        error: GitHubWriteError,
        now: u64,
    ) -> Result<WorkflowOutcome, ServiceError> {
        let result = match error {
            GitHubWriteError::Rejected => ExecutionResult::GitHubRejected,
            GitHubWriteError::Ambiguous
            | GitHubWriteError::PostconditionMismatch
            | GitHubWriteError::Adapter => ExecutionResult::ReconciliationRequired,
        };
        let execution = GitHubExecutionReceipt {
            schema: self
                .dependencies
                .executed_configuration
                .receipt_schema()
                .into(),
            decision_receipt_digest: decision_digest,
            action_digest,
            claim_id: claim.claim_id().clone(),
            expected_prior_state: prior_state,
            operation: claim.operation(),
            observed_state: None,
            repository_id: grant.repository().repository_id(),
            result,
            executed_at: now,
            reconciliation_history: Vec::new(),
        };
        self.append_execution(&execution)?;
        self.dependencies
            .workflow_store
            .require_reconciliation(claim, now)
            .map_err(|_| ServiceError::WorkflowState)?;
        Ok(WorkflowOutcome::ExecutionFailed {
            operation: claim.operation(),
            receipt: Box::new(execution),
        })
    }
}

struct AuthorizedAction {
    action: ExactGitHubAction,
    proof: crate::ports::ProofAuthorization,
    decision: GitHubDecisionReceipt,
    decision_digest: crate::types::DigestHex,
}

enum AuthorizationResult {
    Authorized(Box<AuthorizedAction>),
    Rejected(Box<GitHubDecisionReceipt>),
}

/// Derives the exact branch action from trusted candidate and fresh GitHub facts.
///
/// # Errors
///
/// Returns a canonicalization or invalid-grant failure.
pub fn derive_publish_branch_action(
    grant: &WorkflowGrant,
    required_configuration: &VerifierConfiguration,
    evidence: &GitHubEvidence,
) -> Result<PublishBranchAction, ServiceError> {
    Ok(PublishBranchAction {
        capability: crate::types::BRANCH_CAPABILITY.into(),
        profile_id: crate::types::PROFILE_ID.into(),
        profile_version: crate::types::PROFILE_VERSION,
        workflow_id: grant.workflow_id().clone(),
        workflow_grant_digest: grant.digest().map_err(|_| ServiceError::Canonicalization)?,
        repository: grant.repository().clone(),
        issue: grant.issue().clone(),
        base_ref: grant.base_ref().clone(),
        base_revision: grant.base_revision().clone(),
        target_ref: grant.target_ref().map_err(|_| ServiceError::InvalidGrant)?,
        expected_target_state: "absent".into(),
        candidate_revision: evidence.candidate.candidate_revision().clone(),
        candidate_tree: evidence.candidate.candidate_tree().clone(),
        candidate_bundle_digest: evidence.candidate.bundle_digest().clone(),
        change_set_digest: evidence.candidate.change_set_digest().clone(),
        evidence_digest: evidence
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?,
        verifier_configuration_digest: required_configuration
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?,
        executor_audience: grant.executor_audience().clone(),
        expires_at: grant.expires_at(),
    })
}

/// Derives the exact draft-PR action after the exact branch receipt exists.
///
/// # Errors
///
/// Returns a canonicalization or invalid-grant failure.
pub fn derive_open_pull_request_action(
    grant: &WorkflowGrant,
    required_configuration: &VerifierConfiguration,
    evidence: &GitHubEvidence,
    branch_execution_receipt_digest: &crate::types::DigestHex,
    exact_body: &str,
) -> Result<OpenDraftPullRequestAction, ServiceError> {
    Ok(OpenDraftPullRequestAction {
        capability: crate::types::PULL_REQUEST_CAPABILITY.into(),
        profile_id: crate::types::PROFILE_ID.into(),
        profile_version: crate::types::PROFILE_VERSION,
        workflow_id: grant.workflow_id().clone(),
        workflow_grant_digest: grant.digest().map_err(|_| ServiceError::Canonicalization)?,
        repository: grant.repository().clone(),
        issue: grant.issue().clone(),
        base_ref: grant.base_ref().clone(),
        base_revision: grant.base_revision().clone(),
        head_ref: grant.target_ref().map_err(|_| ServiceError::InvalidGrant)?,
        head_revision: evidence.candidate.candidate_revision().clone(),
        draft: true,
        exact_title: grant.pull_request_title(),
        exact_body_digest: sha256(exact_body.as_bytes()),
        expected_existing_pull_requests: 0,
        branch_execution_receipt_digest: branch_execution_receipt_digest.clone(),
        evidence_digest: evidence
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?,
        verifier_configuration_digest: required_configuration
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?,
        executor_audience: grant.executor_audience().clone(),
        expires_at: grant.expires_at(),
    })
}

/// Exact deterministic PR body; public callers cannot alter it.
#[must_use]
pub fn deterministic_pull_request_body(
    grant: &WorkflowGrant,
    candidate_revision: &crate::types::GitOid,
    branch_action_digest: &crate::types::DigestHex,
    receipt_view_base_url: &str,
) -> String {
    format!(
        "Addresses #{}\n\nAuths workflow: `{}`\nCandidate: `{}`\nBranch action: `{}`\nReceipts: {}/{}",
        grant.issue().issue_number(),
        grant.workflow_id(),
        candidate_revision,
        branch_action_digest,
        receipt_view_base_url,
        grant.workflow_id()
    )
}

fn decision_from_candidate_error(error: CandidateError) -> Decision {
    let code = match error {
        CandidateError::InvalidConfiguration => DecisionCode::VerifierConfigurationMismatch,
        CandidateError::LimitExceeded => DecisionCode::CandidateLimitExceeded,
        CandidateError::UnexpectedRef
        | CandidateError::Malformed
        | CandidateError::Git
        | CandidateError::Io => DecisionCode::CandidateBundleMalformed,
        CandidateError::InvalidHistory => DecisionCode::CandidateNotDescendant,
        CandidateError::MergeCommitDenied => DecisionCode::MergeCommitDenied,
        CandidateError::PathNotAllowed => DecisionCode::PathNotAllowed,
        CandidateError::PathExplicitlyDenied => DecisionCode::PathExplicitlyDenied,
        CandidateError::FileModeDenied => DecisionCode::FileModeDenied,
        CandidateError::NonUtf8Path | CandidateError::UnsupportedChange => {
            DecisionCode::UnsupportedGitObject
        }
    };
    Decision::denied(code, error.to_string())
}

fn recovery_action_matches(
    record: &ClaimRecord,
    grant: &WorkflowGrant,
    required_configuration: &VerifierConfiguration,
    candidate: &QuarantinedCandidate,
) -> Result<bool, ServiceError> {
    if record
        .exact_action
        .digest()
        .map_err(|_| ServiceError::Canonicalization)?
        != record.action_digest
        || record.exact_action.workflow_id() != grant.workflow_id()
        || record.exact_action.repository() != grant.repository()
    {
        return Ok(false);
    }
    let grant_digest = grant.digest().map_err(|_| ServiceError::Canonicalization)?;
    let configuration_digest = required_configuration
        .digest()
        .map_err(|_| ServiceError::Canonicalization)?;
    let target_ref = grant.target_ref().map_err(|_| ServiceError::InvalidGrant)?;
    let candidate = candidate.evidence();
    Ok(match &record.exact_action {
        ExactGitHubAction::PublishBranch(action) => {
            action.workflow_grant_digest == grant_digest
                && action.repository == *grant.repository()
                && action.issue == *grant.issue()
                && action.base_ref == *grant.base_ref()
                && action.base_revision == *grant.base_revision()
                && action.target_ref == target_ref
                && action.expected_target_state == "absent"
                && action.candidate_revision == *candidate.candidate_revision()
                && action.candidate_tree == *candidate.candidate_tree()
                && action.candidate_bundle_digest == *candidate.bundle_digest()
                && action.change_set_digest == *candidate.change_set_digest()
                && action.verifier_configuration_digest == configuration_digest
                && action.executor_audience == *grant.executor_audience()
                && action.expires_at == grant.expires_at()
        }
        ExactGitHubAction::OpenDraftPullRequest(action) => {
            action.workflow_grant_digest == grant_digest
                && action.repository == *grant.repository()
                && action.issue == *grant.issue()
                && action.base_ref == *grant.base_ref()
                && action.base_revision == *grant.base_revision()
                && action.head_ref == target_ref
                && action.head_revision == *candidate.candidate_revision()
                && action.draft
                && action.exact_title == grant.pull_request_title()
                && action.expected_existing_pull_requests == 0
                && action.verifier_configuration_digest == configuration_digest
                && action.executor_audience == *grant.executor_audience()
                && action.expires_at == grant.expires_at()
        }
    })
}

/// End-to-end workflow result.
pub enum WorkflowOutcome {
    /// Product containment or Auths denied before credential acquisition.
    Rejected {
        /// Durable decision receipt.
        receipt: Box<GitHubDecisionReceipt>,
    },
    /// Branch succeeded, PR did not complete.
    Partial {
        /// Exact published branch.
        branch: PublishedBranch,
        /// Branch decision.
        branch_decision: Box<GitHubDecisionReceipt>,
        /// Branch execution.
        branch_execution: Box<GitHubExecutionReceipt>,
        /// PR decision when one was reached.
        pull_request_decision: Option<Box<GitHubDecisionReceipt>>,
    },
    /// Both exact effects completed.
    Completed {
        /// Exact published branch.
        branch: PublishedBranch,
        /// Real draft PR.
        pull_request: OpenedPullRequest,
        /// Branch decision.
        branch_decision: Box<GitHubDecisionReceipt>,
        /// Branch execution.
        branch_execution: Box<GitHubExecutionReceipt>,
        /// PR decision.
        pull_request_decision: Box<GitHubDecisionReceipt>,
        /// PR execution.
        pull_request_execution: Box<GitHubExecutionReceipt>,
    },
    /// A previously receipted branch resumed and completed its draft PR.
    ResumedCompleted {
        /// Exact branch re-observed before continuation.
        branch: PublishedBranch,
        /// Real draft PR.
        pull_request: OpenedPullRequest,
        /// Original branch execution receipt commitment.
        branch_execution_receipt_digest: crate::types::DigestHex,
        /// New PR decision.
        pull_request_decision: Box<GitHubDecisionReceipt>,
        /// New PR execution.
        pull_request_execution: Box<GitHubExecutionReceipt>,
    },
    /// A previously receipted branch remains while PR continuation is denied.
    ResumedPartial {
        /// Exact branch re-observed before continuation.
        branch: PublishedBranch,
        /// Original branch execution receipt commitment.
        branch_execution_receipt_digest: crate::types::DigestHex,
        /// New PR denial.
        pull_request_decision: Box<GitHubDecisionReceipt>,
    },
    /// A claimed external effect was proven after recovery without repeating it.
    Reconciled {
        /// Reconciled effect category.
        operation: GitHubOperation,
        /// Exact observed result.
        observed_state: ObservedGitHubState,
        /// Recovery execution receipt.
        receipt: Box<GitHubExecutionReceipt>,
    },
    /// Exact completed action returned its existing receipt.
    Replay {
        /// Effect category.
        operation: GitHubOperation,
        /// Original execution receipt commitment.
        receipt_digest: crate::types::DigestHex,
    },
    /// Pending claim cannot safely be repeated.
    ReconciliationRequired {
        /// Effect category.
        operation: GitHubOperation,
    },
    /// Authorized GitHub operation failed after claiming.
    ExecutionFailed {
        /// Effect category.
        operation: GitHubOperation,
        /// Durable failure receipt.
        receipt: Box<GitHubExecutionReceipt>,
    },
}

/// Closed orchestration failure.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// Invalid trusted configuration.
    #[error("invalid GitHub workflow service configuration")]
    InvalidConfiguration,
    /// Invalid workflow grant.
    #[error("invalid GitHub workflow grant")]
    InvalidGrant,
    /// Canonical commitment failed.
    #[error("could not canonicalize GitHub workflow data")]
    Canonicalization,
    /// Trusted clock unavailable.
    #[error("trusted clock unavailable")]
    Clock,
    /// Fresh GitHub evidence failed.
    #[error("GitHub read failed: {0}")]
    GitHubRead(GitHubReadError),
    /// Evidence was structurally invalid.
    #[error("GitHub evidence invalid")]
    Evidence,
    /// Candidate could not be reconstructed for recovery.
    #[error("GitHub candidate recovery failed: {0}")]
    Candidate(CandidateError),
    /// Durable workflow state unavailable.
    #[error("GitHub workflow state unavailable")]
    WorkflowState,
    /// Sealed Auths command invariant failed.
    #[error("verified GitHub command mismatch")]
    SealedCommand,
    /// GitHub App credential unavailable after exact claim.
    #[error("GitHub App credential unavailable")]
    Credential,
    /// Signed receipt unavailable.
    #[error("GitHub receipt unavailable")]
    Receipt,
}
