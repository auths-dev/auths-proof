//! End-to-end orchestration for one exact GitHub issue workflow.

use auths_bounded_policy::{CommitmentDigest, EvidenceSourceId, VerifierTime};
use auths_lifecycle::{
    DomainReceiptDigest, DurableTransitionV1, EffectConclusion, ExecutionAuthorizationV1,
    ExecutionIntentV1, LifecycleFailure, LifecycleRecordV1, LifecycleState, ObservationDigest,
    ProviderConditionDigest, ProviderContractId, ProviderRequestDigest, ProviderResultDigest,
    ProviderRetryClass, ReconciliationId, ReconciliationObservationV1, RecoveryReferenceDigest,
    StoreError, StoreTransactionV1, TransitionCommandV1, TransitionContextV1,
    TransitionDisposition, WorkflowId as SharedWorkflowId, execute_store_transaction,
};

use crate::{
    candidate::{CandidateError, CandidateSubmission, QuarantinedCandidate},
    canonical::{canonical_digest, sha256},
    containment::{Decision, DecisionClass, DecisionCode, EvaluationContext, evaluate},
    evidence::GitHubEvidence,
    executor::{VerifiedOpenDraftPullRequest, VerifiedPublishBranch},
    lifecycle::{
        BRANCH_PROVIDER_CONTRACT_ID, EVIDENCE_SOURCE_ID, GitHubLifecycleDecisionBindings,
        GitHubLifecycleProjectionInput, GitHubLifecycleRegistry, GitHubRecoveryRecordV1,
        PULL_REQUEST_PROVIDER_CONTRACT_ID,
    },
    ports::{
        CandidateInspector, Clock, CredentialProvider, ExactActionAuthorizer, GitHubReadError,
        GitHubReadPort, GitHubWriteError, GitHubWritePort, ReceiptSink,
    },
    provider_request::{BranchPublishRequestV1, DraftPullRequestV1},
    receipts::{
        ExecutionResult, GitHubDecisionReceipt, GitHubExecutionReceipt, GitHubReceipt,
        ObservedGitHubState, OpenedPullRequest, PublishedBranch, ReconciliationEntry,
    },
    types::{
        ExactGitHubAction, GitHubOperation, OpenDraftPullRequestAction, PublishBranchAction,
        VerifierConfiguration, WorkflowGrant,
    },
    workflow::WorkflowStage,
};

/// Hostile candidate plus the fixed human workflow.
pub struct ExecuteWorkflowRequest {
    /// Human-issued constraints.
    pub workflow_grant: WorkflowGrant,
    /// Configuration demanded by the caller/grant context.
    pub required_configuration: VerifierConfiguration,
    /// Hostile candidate bundle.
    pub candidate: CandidateSubmission,
    pub recovery_references: GitHubRecoveryReferencesV1,
}

#[derive(Clone, Copy)]
pub struct GitHubRecoveryReferencesV1 {
    pub branch: RecoveryReferenceDigest,
    pub pull_request: RecoveryReferenceDigest,
}

/// Explicit trusted dependencies.
pub struct ServiceDependencies<I, G, A, W, C, R, S, T> {
    /// Trusted Git inspector.
    pub candidate_inspector: I,
    /// Read-only fresh GitHub evidence.
    pub github_read: G,
    /// Executor-owned exact child-proof authorizer.
    pub action_authorizer: A,
    /// Durable operation-specific shared lifecycle stores.
    pub lifecycle_registry: W,
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
    W: GitHubLifecycleRegistry,
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
        let branch_evidence =
            self.acquire_evidence(&request.workflow_grant, candidate.evidence(), now)?;
        let recovered_branch = match self.recover_branch(&request, &candidate, &branch_evidence)? {
            BranchRecoveryResult::Absent => None,
            BranchRecoveryResult::Completed(recovered) => Some((
                recovered.branch,
                recovered.execution_receipt_digest,
                recovered.action_digest,
                None,
            )),
            BranchRecoveryResult::ReconciliationRequired => {
                return Ok(WorkflowOutcome::ReconciliationRequired {
                    operation: GitHubOperation::PublishBranch,
                });
            }
        };
        let (
            published_branch,
            branch_execution_receipt_digest,
            branch_action_digest,
            fresh_branch_receipts,
        ) = if let Some(recovered) = recovered_branch {
            recovered
        } else {
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
            let branch_lifecycle_start = begin_lifecycle(
                &self.dependencies.lifecycle_registry,
                &request.workflow_grant,
                &branch_action,
                &branch_evidence,
                &request.required_configuration,
                &self.dependencies.executed_configuration,
                &branch_decision,
                &branch_proof,
                &branch_decision_digest,
                request.recovery_references.branch,
                None,
                now,
            )?;
            match branch_lifecycle_start {
                LifecycleStartResult::Started(start) => {
                    let mut branch_lifecycle = *start;
                    let branch_credential = self
                        .dependencies
                        .credential_provider
                        .installation_credential(
                            branch_lifecycle
                                .execution_authorization
                                .as_ref()
                                .ok_or(ServiceError::ClaimState)?,
                            request.workflow_grant.repository(),
                            GitHubOperation::PublishBranch,
                        )
                        .map_err(|_| ServiceError::Credential)?;
                    let branch_preparation = VerifiedPublishBranch::new(
                        branch_proof.authorized,
                        branch_lifecycle
                            .execution_authorization
                            .take()
                            .ok_or(ServiceError::ClaimState)?,
                    )
                    .map_err(|_| ServiceError::SealedCommand)?;
                    let fresh_branch_evidence =
                        self.acquire_evidence(&request.workflow_grant, candidate.evidence(), now)?;
                    if fresh_branch_evidence.target.revision.is_some()
                        || fresh_branch_evidence
                            .digest()
                            .map_err(|_| ServiceError::Canonicalization)?
                            != branch_evidence
                                .digest()
                                .map_err(|_| ServiceError::Canonicalization)?
                    {
                        release_lifecycle(
                            &branch_lifecycle.store,
                            &branch_lifecycle.workflow_id,
                            branch_lifecycle.credential_stage.record().revision(),
                            branch_lifecycle.context,
                            &branch_action_digest,
                            now,
                        )?;
                        return Ok(WorkflowOutcome::ReconciliationRequired {
                            operation: GitHubOperation::PublishBranch,
                        });
                    }
                    let branch_attempt = lifecycle_transition(
                        &branch_lifecycle.store,
                        &branch_lifecycle.workflow_id,
                        branch_lifecycle.credential_stage.record().revision(),
                        TransitionCommandV1::StartAttempt,
                        branch_lifecycle.context.clone(),
                    )?;
                    let branch_call_entry = lifecycle_transition(
                        &branch_lifecycle.store,
                        &branch_lifecycle.workflow_id,
                        branch_attempt.record().revision(),
                        TransitionCommandV1::MarkProviderCallEntered,
                        branch_lifecycle.context.clone(),
                    )?;
                    let branch_call_authorization =
                        auths_lifecycle::ProviderCallAuthorizationV1::from_durable(
                            &branch_call_entry,
                        )
                        .map_err(|_| ServiceError::ClaimState)?;
                    let branch_command =
                        branch_preparation.authorize_provider_call(branch_call_authorization);
                    let published_branch = match self.dependencies.github_write.publish_branch(
                        &branch_command,
                        &candidate,
                        &branch_credential,
                    ) {
                        Ok(branch) => branch,
                        Err(error) => {
                            return self.execution_failure(
                                &request.workflow_grant,
                                &branch_lifecycle,
                                &branch_call_entry,
                                GitHubOperation::PublishBranch,
                                branch_decision_digest,
                                &branch_action_digest,
                                WorkflowStage::CandidateAccepted,
                                error,
                                now,
                            );
                        }
                    };
                    if published_branch.repository_id
                        != request.workflow_grant.repository().repository_id()
                        || published_branch.branch_ref != *branch_command.target_ref()
                        || published_branch.head_revision != *branch_command.candidate_revision()
                    {
                        mark_unknown_lifecycle(
                            &branch_lifecycle.store,
                            &branch_lifecycle.workflow_id,
                            branch_call_entry.record().revision(),
                            branch_lifecycle.context,
                            &branch_action_digest,
                            now,
                        )?;
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
                        action_digest: branch_action_digest.clone(),
                        claim_id: branch_lifecycle.claim_id.clone(),
                        expected_prior_state: WorkflowStage::CandidateAccepted,
                        operation: GitHubOperation::PublishBranch,
                        observed_state: Some(ObservedGitHubState::Branch(published_branch.clone())),
                        repository_id: request.workflow_grant.repository().repository_id(),
                        result: ExecutionResult::Succeeded,
                        executed_at: now,
                        reconciliation_history: Vec::new(),
                    };
                    let receipt_digest = self.append_execution(&branch_execution)?;
                    commit_lifecycle(
                        &branch_lifecycle.store,
                        &branch_lifecycle.workflow_id,
                        branch_call_entry.record().revision(),
                        branch_lifecycle.context,
                        &receipt_digest,
                        &branch_action_digest,
                    )?;
                    (
                        published_branch,
                        receipt_digest,
                        branch_action_digest,
                        Some((branch_decision, branch_execution)),
                    )
                }
                LifecycleStartResult::Replay(receipt_digest) => {
                    if branch_evidence.target.revision.as_ref()
                        != Some(candidate.evidence().candidate_revision())
                    {
                        return Ok(WorkflowOutcome::ReconciliationRequired {
                            operation: GitHubOperation::PublishBranch,
                        });
                    }
                    (
                        PublishedBranch {
                            repository_id: request.workflow_grant.repository().repository_id(),
                            branch_ref: request
                                .workflow_grant
                                .target_ref()
                                .map_err(|_| ServiceError::InvalidGrant)?,
                            head_revision: candidate.evidence().candidate_revision().clone(),
                        },
                        receipt_digest,
                        branch_action_digest,
                        None,
                    )
                }
                LifecycleStartResult::ReconciliationRequired => {
                    return Ok(WorkflowOutcome::ReconciliationRequired {
                        operation: GitHubOperation::PublishBranch,
                    });
                }
                LifecycleStartResult::Conflict => {
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
            }
        };

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
            &branch_action_digest,
            &self.dependencies.receipt_view_base_url,
        );
        match self.recover_pull_request(
            &request,
            &candidate,
            &pull_request_evidence,
            &branch_execution_receipt_digest,
            &exact_body,
        )? {
            PullRequestRecoveryResult::Absent => {}
            PullRequestRecoveryResult::Replay(receipt_digest) => {
                return Ok(WorkflowOutcome::Replay {
                    operation: GitHubOperation::OpenDraftPullRequest,
                    receipt_digest,
                });
            }
            PullRequestRecoveryResult::ReconciliationRequired => {
                return Ok(WorkflowOutcome::ReconciliationRequired {
                    operation: GitHubOperation::OpenDraftPullRequest,
                });
            }
        }
        let pull_request_action = derive_open_pull_request_action(
            &request.workflow_grant,
            &request.required_configuration,
            &pull_request_evidence,
            &branch_execution_receipt_digest,
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
                return Ok(match fresh_branch_receipts {
                    Some((branch_decision, branch_execution)) => WorkflowOutcome::Partial {
                        branch: published_branch,
                        branch_decision: Box::new(branch_decision),
                        branch_execution: Box::new(branch_execution),
                        pull_request_decision: Some(receipt),
                    },
                    None => WorkflowOutcome::ResumedPartial {
                        branch: published_branch,
                        branch_execution_receipt_digest,
                        pull_request_decision: receipt,
                    },
                });
            }
        };
        let pull_request_action_digest = pull_request_action
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let mut pull_request_lifecycle = match begin_lifecycle(
            &self.dependencies.lifecycle_registry,
            &request.workflow_grant,
            &pull_request_action,
            &pull_request_evidence,
            &request.required_configuration,
            &self.dependencies.executed_configuration,
            &pull_request_decision,
            &pull_request_proof,
            &pull_request_decision_digest,
            request.recovery_references.pull_request,
            Some(&exact_body),
            pr_now,
        )? {
            LifecycleStartResult::Started(start) => *start,
            LifecycleStartResult::Replay(receipt_digest) => {
                return Ok(WorkflowOutcome::Replay {
                    operation: GitHubOperation::OpenDraftPullRequest,
                    receipt_digest,
                });
            }
            LifecycleStartResult::ReconciliationRequired => {
                return Ok(WorkflowOutcome::ReconciliationRequired {
                    operation: GitHubOperation::OpenDraftPullRequest,
                });
            }
            LifecycleStartResult::Conflict => {
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
                return Ok(match fresh_branch_receipts {
                    Some((branch_decision, branch_execution)) => WorkflowOutcome::Partial {
                        branch: published_branch,
                        branch_decision: Box::new(branch_decision),
                        branch_execution: Box::new(branch_execution),
                        pull_request_decision: Some(Box::new(receipt)),
                    },
                    None => WorkflowOutcome::ResumedPartial {
                        branch: published_branch,
                        branch_execution_receipt_digest,
                        pull_request_decision: Box::new(receipt),
                    },
                });
            }
        };
        let pull_request_credential = self
            .dependencies
            .credential_provider
            .installation_credential(
                pull_request_lifecycle
                    .execution_authorization
                    .as_ref()
                    .ok_or(ServiceError::ClaimState)?,
                request.workflow_grant.repository(),
                GitHubOperation::OpenDraftPullRequest,
            )
            .map_err(|_| ServiceError::Credential)?;
        let pull_request_preparation = VerifiedOpenDraftPullRequest::new(
            pull_request_proof.authorized,
            pull_request_lifecycle
                .execution_authorization
                .take()
                .ok_or(ServiceError::ClaimState)?,
            exact_body,
        )
        .map_err(|_| ServiceError::SealedCommand)?;
        let fresh_pull_request_evidence =
            self.acquire_evidence(&request.workflow_grant, candidate.evidence(), pr_now)?;
        if fresh_pull_request_evidence.target.revision
            != Some(candidate.evidence().candidate_revision().clone())
            || !fresh_pull_request_evidence
                .matching_pull_requests
                .is_empty()
        {
            release_lifecycle(
                &pull_request_lifecycle.store,
                &pull_request_lifecycle.workflow_id,
                pull_request_lifecycle.credential_stage.record().revision(),
                pull_request_lifecycle.context,
                &pull_request_action_digest,
                pr_now,
            )?;
            return Ok(WorkflowOutcome::ReconciliationRequired {
                operation: GitHubOperation::OpenDraftPullRequest,
            });
        }
        let pull_request_attempt = lifecycle_transition(
            &pull_request_lifecycle.store,
            &pull_request_lifecycle.workflow_id,
            pull_request_lifecycle.credential_stage.record().revision(),
            TransitionCommandV1::StartAttempt,
            pull_request_lifecycle.context.clone(),
        )?;
        let pull_request_call_entry = lifecycle_transition(
            &pull_request_lifecycle.store,
            &pull_request_lifecycle.workflow_id,
            pull_request_attempt.record().revision(),
            TransitionCommandV1::MarkProviderCallEntered,
            pull_request_lifecycle.context.clone(),
        )?;
        let pull_request_call_authorization =
            auths_lifecycle::ProviderCallAuthorizationV1::from_durable(&pull_request_call_entry)
                .map_err(|_| ServiceError::ClaimState)?;
        let pull_request_command =
            pull_request_preparation.authorize_provider_call(pull_request_call_authorization);
        let opened_pull_request = match self
            .dependencies
            .github_write
            .open_draft_pull_request(&pull_request_command, &pull_request_credential)
        {
            Ok(pull_request) => pull_request,
            Err(error) => {
                return self.execution_failure(
                    &request.workflow_grant,
                    &pull_request_lifecycle,
                    &pull_request_call_entry,
                    GitHubOperation::OpenDraftPullRequest,
                    pull_request_decision_digest,
                    &pull_request_action_digest,
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
            mark_unknown_lifecycle(
                &pull_request_lifecycle.store,
                &pull_request_lifecycle.workflow_id,
                pull_request_call_entry.record().revision(),
                pull_request_lifecycle.context,
                &pull_request_action_digest,
                pr_now,
            )?;
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
            action_digest: pull_request_action_digest.clone(),
            claim_id: pull_request_lifecycle.claim_id.clone(),
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
        commit_lifecycle(
            &pull_request_lifecycle.store,
            &pull_request_lifecycle.workflow_id,
            pull_request_call_entry.record().revision(),
            pull_request_lifecycle.context,
            &pull_request_execution_digest,
            &pull_request_action_digest,
        )?;
        Ok(match fresh_branch_receipts {
            Some((branch_decision, branch_execution)) => WorkflowOutcome::Completed {
                branch: published_branch,
                pull_request: opened_pull_request,
                branch_decision: Box::new(branch_decision),
                branch_execution: Box::new(branch_execution),
                pull_request_decision: Box::new(pull_request_decision),
                pull_request_execution: Box::new(pull_request_execution),
            },
            None => WorkflowOutcome::ResumedCompleted {
                branch: published_branch,
                pull_request: opened_pull_request,
                branch_execution_receipt_digest,
                pull_request_decision: Box::new(pull_request_decision),
                pull_request_execution: Box::new(pull_request_execution),
            },
        })
    }

    fn recover_branch(
        &self,
        request: &ExecuteWorkflowRequest,
        candidate: &QuarantinedCandidate,
        evidence: &GitHubEvidence,
    ) -> Result<BranchRecoveryResult, ServiceError> {
        let Some(recovery) = self.dependencies.lifecycle_registry.load_recovery(
            request.workflow_grant.workflow_id(),
            GitHubOperation::PublishBranch,
        )?
        else {
            return Ok(BranchRecoveryResult::Absent);
        };
        recovery
            .validate()
            .map_err(|_| ServiceError::WorkflowState)?;
        if !recovery_action_matches(
            &recovery.exact_action,
            &request.workflow_grant,
            &request.required_configuration,
            candidate,
        )? {
            return Err(ServiceError::WorkflowState);
        }
        let ExactGitHubAction::PublishBranch(action) = &recovery.exact_action else {
            return Err(ServiceError::WorkflowState);
        };
        let store = self
            .dependencies
            .lifecycle_registry
            .for_action(&recovery.exact_action)?;
        let workflow_id = SharedWorkflowId::parse(&recovery.shared_workflow_id)
            .map_err(|_| ServiceError::WorkflowState)?;
        let record = store
            .load_github_lifecycle(&workflow_id)?
            .ok_or(ServiceError::WorkflowState)?;
        if !matches!(
            record.state(),
            LifecycleState::Committed | LifecycleState::ReconciledCommitted
        ) {
            return Ok(BranchRecoveryResult::ReconciliationRequired);
        }
        let action_digest = recovery
            .exact_action
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        if record.decision_input().commitments.exact_action_digest() != commitment(&action_digest)?
            || evidence.target.revision.as_ref() != Some(&action.candidate_revision)
        {
            return Ok(BranchRecoveryResult::ReconciliationRequired);
        }
        Ok(BranchRecoveryResult::Completed(RecoveredBranch {
            branch: PublishedBranch {
                repository_id: action.repository.repository_id(),
                branch_ref: action.target_ref.clone(),
                head_revision: action.candidate_revision.clone(),
            },
            execution_receipt_digest: domain_receipt_digest(&record)?,
            action_digest,
        }))
    }

    fn recover_pull_request(
        &self,
        request: &ExecuteWorkflowRequest,
        candidate: &QuarantinedCandidate,
        evidence: &GitHubEvidence,
        branch_execution_receipt_digest: &crate::types::DigestHex,
        exact_body: &str,
    ) -> Result<PullRequestRecoveryResult, ServiceError> {
        let Some(recovery) = self.dependencies.lifecycle_registry.load_recovery(
            request.workflow_grant.workflow_id(),
            GitHubOperation::OpenDraftPullRequest,
        )?
        else {
            return Ok(PullRequestRecoveryResult::Absent);
        };
        recovery
            .validate()
            .map_err(|_| ServiceError::WorkflowState)?;
        if !recovery_action_matches(
            &recovery.exact_action,
            &request.workflow_grant,
            &request.required_configuration,
            candidate,
        )? {
            return Err(ServiceError::WorkflowState);
        }
        let ExactGitHubAction::OpenDraftPullRequest(action) = &recovery.exact_action else {
            return Err(ServiceError::WorkflowState);
        };
        if action.branch_execution_receipt_digest != *branch_execution_receipt_digest
            || action.exact_body_digest != sha256(exact_body.as_bytes())
        {
            return Err(ServiceError::WorkflowState);
        }
        let store = self
            .dependencies
            .lifecycle_registry
            .for_action(&recovery.exact_action)?;
        let workflow_id = SharedWorkflowId::parse(&recovery.shared_workflow_id)
            .map_err(|_| ServiceError::WorkflowState)?;
        let record = store
            .load_github_lifecycle(&workflow_id)?
            .ok_or(ServiceError::WorkflowState)?;
        if !matches!(
            record.state(),
            LifecycleState::Committed | LifecycleState::ReconciledCommitted
        ) {
            return Ok(PullRequestRecoveryResult::ReconciliationRequired);
        }
        let action_digest = recovery
            .exact_action
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        if record.decision_input().commitments.exact_action_digest() != commitment(&action_digest)?
        {
            return Err(ServiceError::WorkflowState);
        }
        let mut exact = evidence
            .matching_pull_requests
            .iter()
            .filter(|pull_request| {
                pull_request.base_ref == action.base_ref
                    && pull_request.head_ref == action.head_ref
                    && pull_request.head_revision == action.head_revision
                    && pull_request.draft == action.draft
            });
        if exact.next().is_none() || exact.next().is_some() {
            return Ok(PullRequestRecoveryResult::ReconciliationRequired);
        }
        Ok(PullRequestRecoveryResult::Replay(domain_receipt_digest(
            &record,
        )?))
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
        let candidate = self
            .dependencies
            .candidate_inspector
            .inspect(
                &request.candidate,
                request.workflow_grant.candidate_policy(),
                request.workflow_grant.object_format(),
            )
            .map_err(ServiceError::Candidate)?;
        let mut selected = None;
        for operation in [
            GitHubOperation::PublishBranch,
            GitHubOperation::OpenDraftPullRequest,
        ] {
            let Some(recovery) = self
                .dependencies
                .lifecycle_registry
                .load_recovery(request.workflow_grant.workflow_id(), operation)?
            else {
                continue;
            };
            recovery
                .validate()
                .map_err(|_| ServiceError::WorkflowState)?;
            let store = self
                .dependencies
                .lifecycle_registry
                .for_action(&recovery.exact_action)?;
            let workflow_id = SharedWorkflowId::parse(&recovery.shared_workflow_id)
                .map_err(|_| ServiceError::WorkflowState)?;
            let record = store
                .load_github_lifecycle(&workflow_id)?
                .ok_or(ServiceError::WorkflowState)?;
            if record.state() == LifecycleState::OutcomeUnknown {
                selected = Some((recovery, store, record));
                break;
            }
            if matches!(
                record.state(),
                LifecycleState::DecisionRecorded
                    | LifecycleState::Reserved
                    | LifecycleState::ExecutionIntentRecorded
                    | LifecycleState::Executing
            ) {
                return Ok(WorkflowOutcome::ReconciliationRequired { operation });
            }
        }
        let Some((recovery, store, record)) = selected else {
            return Err(ServiceError::WorkflowState);
        };
        let operation = recovery.operation;
        if !recovery_action_matches(
            &recovery.exact_action,
            &request.workflow_grant,
            &request.required_configuration,
            &candidate,
        )? {
            return Err(ServiceError::WorkflowState);
        }
        let evidence = self.acquire_evidence(&request.workflow_grant, candidate.evidence(), now)?;
        let observed_state = match &recovery.exact_action {
            ExactGitHubAction::PublishBranch(action) => match evidence.target.revision.as_ref() {
                Some(revision) if revision == &action.candidate_revision => {
                    Some(ObservedGitHubState::Branch(PublishedBranch {
                        repository_id: action.repository.repository_id(),
                        branch_ref: action.target_ref.clone(),
                        head_revision: action.candidate_revision.clone(),
                    }))
                }
                None => None,
                Some(_) => {
                    return Ok(WorkflowOutcome::ReconciliationRequired { operation });
                }
            },
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
                let pull_request = exact.next();
                if exact.next().is_some() {
                    return Ok(WorkflowOutcome::ReconciliationRequired { operation });
                }
                pull_request.map(|pull_request| {
                    ObservedGitHubState::PullRequest(pull_request.clone().into())
                })
            }
        };
        let result = if observed_state.is_some() {
            ExecutionResult::Succeeded
        } else {
            ExecutionResult::NotApplied
        };
        let execution = GitHubExecutionReceipt {
            schema: self
                .dependencies
                .executed_configuration
                .receipt_schema()
                .into(),
            decision_receipt_digest: recovery.decision_receipt_digest,
            action_digest: recovery
                .exact_action
                .digest()
                .map_err(|_| ServiceError::Canonicalization)?,
            claim_id: recovery.claim_id,
            expected_prior_state: match operation {
                GitHubOperation::PublishBranch => WorkflowStage::CandidateAccepted,
                GitHubOperation::OpenDraftPullRequest => WorkflowStage::BranchPublished,
            },
            operation,
            observed_state: observed_state.clone(),
            repository_id: request.workflow_grant.repository().repository_id(),
            result,
            executed_at: now,
            reconciliation_history: vec![ReconciliationEntry {
                result,
                observed_at: now,
            }],
        };
        let receipt_digest = self.append_execution(&execution)?;
        reconcile_lifecycle(
            &store,
            &record,
            context_from_record(&record, now)?,
            &receipt_digest,
            if observed_state.is_some() {
                EffectConclusion::Effect
            } else {
                EffectConclusion::NonEffect
            },
            now,
        )?;
        Ok(match observed_state {
            Some(observed_state) => WorkflowOutcome::Reconciled {
                operation,
                observed_state,
                receipt: Box::new(execution),
            },
            None => WorkflowOutcome::ReconciledNonEffect {
                operation,
                receipt: Box::new(execution),
            },
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
        lifecycle: &LifecycleStart,
        call_entry: &DurableTransitionV1,
        operation: GitHubOperation,
        decision_digest: crate::types::DigestHex,
        action_digest: &crate::types::DigestHex,
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
            action_digest: action_digest.clone(),
            claim_id: lifecycle.claim_id.clone(),
            expected_prior_state: prior_state,
            operation,
            observed_state: None,
            repository_id: grant.repository().repository_id(),
            result,
            executed_at: now,
            reconciliation_history: Vec::new(),
        };
        let failure_receipt_digest = self.append_execution(&execution)?;
        lifecycle_transition(
            &lifecycle.store,
            &lifecycle.workflow_id,
            call_entry.record().revision(),
            TransitionCommandV1::MarkOutcomeUnknown {
                domain_receipt_digest: DomainReceiptDigest::new(digest_bytes(
                    &failure_receipt_digest,
                )?),
            },
            lifecycle.context.clone(),
        )?;
        Ok(WorkflowOutcome::ExecutionFailed {
            operation,
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

struct LifecycleStart {
    store: std::sync::Arc<dyn crate::lifecycle::GitHubLifecycleStore>,
    workflow_id: SharedWorkflowId,
    context: TransitionContextV1,
    credential_stage: DurableTransitionV1,
    execution_authorization: Option<ExecutionAuthorizationV1>,
    claim_id: crate::types::DigestHex,
}

enum LifecycleStartResult {
    Started(Box<LifecycleStart>),
    Replay(crate::types::DigestHex),
    ReconciliationRequired,
    Conflict,
}

struct RecoveredBranch {
    branch: PublishedBranch,
    execution_receipt_digest: crate::types::DigestHex,
    action_digest: crate::types::DigestHex,
}

enum BranchRecoveryResult {
    Absent,
    Completed(RecoveredBranch),
    ReconciliationRequired,
}

enum PullRequestRecoveryResult {
    Absent,
    Replay(crate::types::DigestHex),
    ReconciliationRequired,
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "security-relevant lifecycle projection and staged persistence remain explicit and linear"
)]
fn begin_lifecycle(
    registry: &impl GitHubLifecycleRegistry,
    grant: &WorkflowGrant,
    action: &ExactGitHubAction,
    evidence: &GitHubEvidence,
    required_configuration: &VerifierConfiguration,
    executed_configuration: &VerifierConfiguration,
    decision: &GitHubDecisionReceipt,
    proof: &crate::ports::ProofAuthorization,
    decision_digest: &crate::types::DigestHex,
    recovery_reference_digest: RecoveryReferenceDigest,
    exact_provider_body: Option<&str>,
    now: u64,
) -> Result<LifecycleStartResult, ServiceError> {
    let projection = GitHubLifecycleProjectionInput {
        grant,
        action,
        evidence,
        required_configuration,
        executed_configuration,
        decision: &decision.product_decision,
        verifier_time: now,
    }
    .project()
    .map_err(|_| ServiceError::Projection)?;
    let workflow_id = projection.workflow_id.clone();
    let context = projection.transition_context(now);
    let store = registry.for_action(action)?;
    let action_digest = action
        .digest()
        .map_err(|_| ServiceError::Canonicalization)?;
    let recovery = GitHubRecoveryRecordV1 {
        schema: "auths.github.recovery-record/1".into(),
        workflow_id: action.workflow_id().clone(),
        operation: action.operation(),
        shared_workflow_id: workflow_id.as_str().into(),
        exact_action: action.clone(),
        planning_evidence: evidence.clone(),
        decision_receipt_digest: decision_digest.clone(),
        claim_id: claim_id(action, &action_digest),
    };
    recovery.validate().map_err(|_| ServiceError::Projection)?;
    if let Some(existing) = registry.load_recovery(action.workflow_id(), action.operation())? {
        if existing != recovery {
            return Ok(LifecycleStartResult::Conflict);
        }
    } else {
        registry.persist_recovery(&recovery)?;
    }
    if let Some(existing) = store.load_github_lifecycle(&workflow_id)? {
        if existing.decision_input().commitments.exact_action_digest()
            != commitment(&action_digest)?
        {
            return Ok(LifecycleStartResult::Conflict);
        }
        return classify_existing_lifecycle(&existing);
    }
    let decision_input = projection
        .into_decision_input(&GitHubLifecycleDecisionBindings {
            core_authorization_digest: &core_authorization_digest(proof),
            decision_receipt_digest: decision_digest,
            implementation_build_digest: &implementation_build_digest(),
            recovery_reference_digest,
            expires_at: match action {
                ExactGitHubAction::PublishBranch(action) => action.expires_at,
                ExactGitHubAction::OpenDraftPullRequest(action) => action.expires_at,
            },
        })
        .map_err(|_| ServiceError::Projection)?;
    let recorded = match execute_store_transaction(
        &store,
        &StoreTransactionV1 {
            workflow_id: workflow_id.clone(),
            expected_revision: None,
            command: TransitionCommandV1::RecordDecision(Box::new(decision_input)),
            context: context.clone(),
        },
    ) {
        Ok(recorded) => recorded,
        Err(StoreError::Conflict | StoreError::Rejected(LifecycleFailure::Conflict)) => {
            return store.load_github_lifecycle(&workflow_id)?.as_ref().map_or(
                Ok(LifecycleStartResult::Conflict),
                classify_existing_lifecycle,
            );
        }
        Err(error) => return Err(ServiceError::Lifecycle(error)),
    };
    if recorded.disposition() == TransitionDisposition::ExactReplay {
        return classify_existing_lifecycle(recorded.record());
    }
    let reserved = match lifecycle_transition(
        &store,
        &workflow_id,
        recorded.record().revision(),
        TransitionCommandV1::Reserve,
        context.clone(),
    ) {
        Ok(reserved) => reserved,
        Err(ServiceError::Lifecycle(
            StoreError::Conflict
            | StoreError::Rejected(LifecycleFailure::Conflict | LifecycleFailure::CapacityExceeded),
        )) => return Ok(LifecycleStartResult::Conflict),
        Err(error) => return Err(error),
    };
    let provider_contract = match action.operation() {
        GitHubOperation::PublishBranch => BRANCH_PROVIDER_CONTRACT_ID,
        GitHubOperation::OpenDraftPullRequest => PULL_REQUEST_PROVIDER_CONTRACT_ID,
    };
    let provider_request_digest = match action {
        ExactGitHubAction::PublishBranch(action) => canonical_digest(
            &BranchPublishRequestV1::derive(action).map_err(|_| ServiceError::Projection)?,
        ),
        ExactGitHubAction::OpenDraftPullRequest(action) => canonical_digest(
            &DraftPullRequestV1::derive(
                action,
                exact_provider_body.ok_or(ServiceError::Projection)?,
            )
            .map_err(|_| ServiceError::Projection)?,
        ),
    }
    .map_err(|_| ServiceError::Canonicalization)?;
    let evidence_digest = evidence
        .digest()
        .map_err(|_| ServiceError::Canonicalization)?;
    let execution_intent = ExecutionIntentV1::new(
        commitment(&action_digest)?,
        ProviderRequestDigest::new(digest_bytes(&provider_request_digest)?),
        ProviderConditionDigest::new(digest_bytes(&evidence_digest)?),
        ProviderContractId::parse(provider_contract).map_err(|_| ServiceError::Projection)?,
        ProviderRetryClass::ObserveBeforeRetry,
    );
    let intent_recorded = lifecycle_transition(
        &store,
        &workflow_id,
        reserved.record().revision(),
        TransitionCommandV1::RecordExecutionIntent(execution_intent),
        context.clone(),
    )?;
    let credential_stage = lifecycle_transition(
        &store,
        &workflow_id,
        intent_recorded.record().revision(),
        TransitionCommandV1::AuthorizeCredential,
        context.clone(),
    )?;
    let execution_authorization = ExecutionAuthorizationV1::from_durable(&credential_stage)
        .map_err(|_| ServiceError::ClaimState)?;
    Ok(LifecycleStartResult::Started(Box::new(LifecycleStart {
        store,
        workflow_id,
        context,
        credential_stage,
        execution_authorization: Some(execution_authorization),
        claim_id: recovery.claim_id,
    })))
}

fn classify_existing_lifecycle(
    existing: &LifecycleRecordV1,
) -> Result<LifecycleStartResult, ServiceError> {
    match existing.state() {
        LifecycleState::Committed | LifecycleState::ReconciledCommitted => Ok(
            LifecycleStartResult::Replay(domain_receipt_digest(existing)?),
        ),
        LifecycleState::OutcomeUnknown
        | LifecycleState::DecisionRecorded
        | LifecycleState::Reserved
        | LifecycleState::ExecutionIntentRecorded
        | LifecycleState::Executing => Ok(LifecycleStartResult::ReconciliationRequired),
        LifecycleState::Released | LifecycleState::ReconciledReleased => {
            Ok(LifecycleStartResult::Conflict)
        }
    }
}

fn domain_receipt_digest(
    record: &LifecycleRecordV1,
) -> Result<crate::types::DigestHex, ServiceError> {
    record
        .receipts()
        .iter()
        .rev()
        .find_map(|receipt| receipt.domain_receipt_digest)
        .map(|digest| crate::types::DigestHex::from_digest_bytes(*digest.bytes()))
        .ok_or(ServiceError::ClaimState)
}

fn lifecycle_transition(
    store: &std::sync::Arc<dyn crate::lifecycle::GitHubLifecycleStore>,
    workflow_id: &SharedWorkflowId,
    revision: u64,
    command: TransitionCommandV1,
    context: TransitionContextV1,
) -> Result<DurableTransitionV1, ServiceError> {
    execute_store_transaction(
        store,
        &StoreTransactionV1 {
            workflow_id: workflow_id.clone(),
            expected_revision: Some(revision),
            command,
            context,
        },
    )
    .map_err(ServiceError::Lifecycle)
}

fn release_lifecycle(
    store: &std::sync::Arc<dyn crate::lifecycle::GitHubLifecycleStore>,
    workflow_id: &SharedWorkflowId,
    revision: u64,
    context: TransitionContextV1,
    action_digest: &crate::types::DigestHex,
    now: u64,
) -> Result<DurableTransitionV1, ServiceError> {
    let event = lifecycle_event_digest(b"github-definite-non-effect", action_digest, now);
    lifecycle_transition(
        store,
        workflow_id,
        revision,
        TransitionCommandV1::Release {
            result_digest: ProviderResultDigest::new(digest_bytes(&event)?),
            domain_receipt_digest: DomainReceiptDigest::new(digest_bytes(&event)?),
            conclusion: EffectConclusion::NonEffect,
        },
        context,
    )
}

fn mark_unknown_lifecycle(
    store: &std::sync::Arc<dyn crate::lifecycle::GitHubLifecycleStore>,
    workflow_id: &SharedWorkflowId,
    revision: u64,
    context: TransitionContextV1,
    action_digest: &crate::types::DigestHex,
    now: u64,
) -> Result<DurableTransitionV1, ServiceError> {
    let event = lifecycle_event_digest(b"github-provider-outcome-unknown", action_digest, now);
    lifecycle_transition(
        store,
        workflow_id,
        revision,
        TransitionCommandV1::MarkOutcomeUnknown {
            domain_receipt_digest: DomainReceiptDigest::new(digest_bytes(&event)?),
        },
        context,
    )
}

fn commit_lifecycle(
    store: &std::sync::Arc<dyn crate::lifecycle::GitHubLifecycleStore>,
    workflow_id: &SharedWorkflowId,
    revision: u64,
    context: TransitionContextV1,
    execution_receipt_digest: &crate::types::DigestHex,
    result_digest: &crate::types::DigestHex,
) -> Result<DurableTransitionV1, ServiceError> {
    lifecycle_transition(
        store,
        workflow_id,
        revision,
        TransitionCommandV1::Commit {
            result_digest: ProviderResultDigest::new(digest_bytes(result_digest)?),
            domain_receipt_digest: DomainReceiptDigest::new(digest_bytes(
                execution_receipt_digest,
            )?),
        },
        context,
    )
}

fn reconcile_lifecycle(
    store: &std::sync::Arc<dyn crate::lifecycle::GitHubLifecycleStore>,
    unknown: &LifecycleRecordV1,
    context: TransitionContextV1,
    domain_receipt_digest: &crate::types::DigestHex,
    conclusion: EffectConclusion,
    now: u64,
) -> Result<DurableTransitionV1, ServiceError> {
    let intent = unknown.execution_intent().ok_or(ServiceError::ClaimState)?;
    let reconciliation_digest =
        lifecycle_event_digest(b"github-reconciliation", domain_receipt_digest, now);
    let observation = ReconciliationObservationV1::new(
        ReconciliationId::parse(reconciliation_digest.as_str())
            .map_err(|_| ServiceError::Projection)?,
        EvidenceSourceId::parse(EVIDENCE_SOURCE_ID).map_err(|_| ServiceError::Projection)?,
        VerifierTime::from_unix_seconds(now),
        VerifierTime::from_unix_seconds(now.checked_add(30).ok_or(ServiceError::Canonicalization)?),
        ObservationDigest::new(digest_bytes(domain_receipt_digest)?),
        conclusion,
        intent.provider_request_digest(),
    );
    lifecycle_transition(
        store,
        unknown.workflow_id(),
        unknown.revision(),
        TransitionCommandV1::Reconcile {
            observation,
            domain_receipt_digest: DomainReceiptDigest::new(digest_bytes(domain_receipt_digest)?),
        },
        context,
    )
}

fn context_from_record(
    record: &LifecycleRecordV1,
    now: u64,
) -> Result<TransitionContextV1, ServiceError> {
    let capacity = auths_lifecycle::CapacitySnapshotV1::new(
        record
            .reservations()
            .iter()
            .map(|entry| auths_lifecycle::CapacityEntryV1::Exclusive {
                scope_digest: entry.request().scope_digest(),
                window_digest: entry.request().window_digest(),
                live_owner: Some(entry.request().reservation_id().clone()),
            })
            .collect(),
    )
    .map_err(|_| ServiceError::Projection)?;
    Ok(TransitionContextV1 {
        verifier_time: VerifierTime::from_unix_seconds(now),
        executed_configuration: record
            .decision_input()
            .commitments
            .executed_configuration()
            .clone(),
        revocation: auths_lifecycle::RevocationSnapshotV1 {
            revoked: false,
            snapshot_digest: commitment(
                &crate::canonical::canonical_digest(&(
                    "auths.github.revocation-not-configured/1",
                    record.workflow_id().as_str(),
                ))
                .map_err(|_| ServiceError::Canonicalization)?,
            )?,
        },
        capacity,
    })
}

fn lifecycle_event_digest(
    domain: &[u8],
    digest: &crate::types::DigestHex,
    now: u64,
) -> crate::types::DigestHex {
    let mut bytes = Vec::with_capacity(domain.len() + 72);
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(digest.as_str().as_bytes());
    bytes.extend_from_slice(&now.to_be_bytes());
    sha256(&bytes)
}

fn core_authorization_digest(proof: &crate::ports::ProofAuthorization) -> crate::types::DigestHex {
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(proof.proof_digest.as_str().as_bytes());
    bytes.extend_from_slice(proof.context_digest.as_str().as_bytes());
    sha256(&bytes)
}

fn implementation_build_digest() -> crate::types::DigestHex {
    sha256(
        option_env!("AUTHS_BUILD_COMMIT")
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .as_bytes(),
    )
}

fn claim_id(
    action: &ExactGitHubAction,
    action_digest: &crate::types::DigestHex,
) -> crate::types::DigestHex {
    sha256(
        format!(
            "auths-github-claim-v1\0{}\0{:?}\0{}",
            action.workflow_id(),
            action.operation(),
            action_digest
        )
        .as_bytes(),
    )
}

fn commitment(value: &crate::types::DigestHex) -> Result<CommitmentDigest, ServiceError> {
    Ok(CommitmentDigest::new(digest_bytes(value)?))
}

fn digest_bytes(value: &crate::types::DigestHex) -> Result<[u8; 32], ServiceError> {
    hex::decode(value.as_str())
        .map_err(|_| ServiceError::Canonicalization)?
        .try_into()
        .map_err(|_| ServiceError::Canonicalization)
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
    exact_action: &ExactGitHubAction,
    grant: &WorkflowGrant,
    required_configuration: &VerifierConfiguration,
    candidate: &QuarantinedCandidate,
) -> Result<bool, ServiceError> {
    if exact_action.workflow_id() != grant.workflow_id()
        || exact_action.repository() != grant.repository()
    {
        return Ok(false);
    }
    let grant_digest = grant.digest().map_err(|_| ServiceError::Canonicalization)?;
    let configuration_digest = required_configuration
        .digest()
        .map_err(|_| ServiceError::Canonicalization)?;
    let target_ref = grant.target_ref().map_err(|_| ServiceError::InvalidGrant)?;
    let candidate = candidate.evidence();
    Ok(match exact_action {
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
    /// Fresh provider evidence proved that a claimed effect did not occur and
    /// the exclusive reservation was released.
    ReconciledNonEffect {
        /// Reconciled effect category.
        operation: GitHubOperation,
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
    /// Shared lifecycle projection failed closed.
    #[error("GitHub lifecycle projection failed")]
    Projection,
    /// Shared lifecycle state or stage is invalid.
    #[error("GitHub lifecycle stage is not authorized")]
    ClaimState,
    /// Shared lifecycle persistence failed.
    #[error("GitHub lifecycle store failed")]
    Lifecycle(StoreError),
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

impl From<StoreError> for ServiceError {
    fn from(error: StoreError) -> Self {
        Self::Lifecycle(error)
    }
}
