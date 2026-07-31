//! End-to-end orchestration for exact Radicle issue patch workflows.

use auths_bounded_policy::{CommitmentDigest, EvidenceSourceId, VerifierTime};
use auths_lifecycle::{
    DomainReceiptDigest, DurableTransitionV1, EffectConclusion, ExecutionAuthorizationV1,
    ExecutionIntentV1, LifecycleFailure, LifecycleRecordV1, LifecycleState, ObservationDigest,
    ProviderConditionDigest, ProviderContractId, ProviderRequestDigest, ProviderResultDigest,
    ProviderRetryClass, ReconciliationId, ReconciliationObservationV1, StoreError,
    StoreTransactionV1, TransitionCommandV1, TransitionContextV1, TransitionDisposition,
    WorkflowId as SharedWorkflowId, execute_store_transaction,
};
use auths_profile_api::ActionProfile as _;
use auths_sdk::RequestContext;

use crate::{
    canonical::sha256,
    containment::{DecisionClass, EvaluationContext, evaluate},
    executor::VerifiedOpenPatchCommand,
    lifecycle::{
        EVIDENCE_SOURCE_ID, PROVIDER_CONTRACT_ID, RadicleLifecycleDecisionBindings,
        RadicleLifecycleProjectionInput, RadicleLifecycleRegistry, RadicleLifecycleStore,
        RadicleRecoveryRecordV1,
    },
    ports::{
        CandidateInspector, Clock, EvidenceSource, PortError, ProofDecision, ProofVerifier,
        PropagationObserver, PublicationReconciliation, PublicationReconciliationQuery,
        RadicleWriter, ReceiptSink,
    },
    profile::RadiclePatchProfile,
    receipts::{
        RadicleDecisionReceipt, RadicleExecutionReceipt, RadiclePropagationReceipt, RadicleReceipt,
        decision_receipt, preflight_decision_receipt,
    },
    types::{
        CandidateSubmission, DigestHex, IssueAddressGrantV1, OpenPatchActionInput,
        OpenPatchActionV1, VerifierConfiguration,
    },
    workflow::{WorkflowRecord, WorkflowStage},
};

/// Hostile request plus the human workflow and Auths proof.
pub struct AuthorizeRequest {
    /// Human-issued vertical workflow constraints.
    pub workflow_grant: IssueAddressGrantV1,
    /// Caller-required verifier configuration.
    pub required_configuration: VerifierConfiguration,
    /// Git bundle and patch metadata.
    pub candidate: CandidateSubmission,
    /// Auths proof bundle.
    pub proof: Vec<u8>,
    /// Exact Auths audience, challenge, and evaluation time.
    pub auths_request: RequestContext,
}

/// Explicit service dependencies keep every authority and effect boundary visible.
pub struct ServiceDependencies<I, E, V, W, R, O, S, C> {
    /// Trusted Git inspector.
    pub candidate_inspector: I,
    /// Synchronized Radicle evidence provider.
    pub evidence_source: E,
    /// Auths kernel adapter.
    pub proof_verifier: V,
    /// Durable shared lifecycle plus domain recovery state.
    pub workflow_store: W,
    /// Only Radicle write adapter.
    pub radicle_writer: R,
    /// Independent propagation observer.
    pub propagation_observer: O,
    /// Append-only receipt sink.
    pub receipt_sink: S,
    /// Trusted clock.
    pub clock: C,
    /// Configuration actually loaded by this executor.
    pub executed_configuration: VerifierConfiguration,
}

/// Complete vertical product service.
pub struct RadicleIssueWorkflowService<I, E, V, W, R, O, S, C> {
    dependencies: ServiceDependencies<I, E, V, W, R, O, S, C>,
}

impl<I, E, V, W, R, O, S, C> RadicleIssueWorkflowService<I, E, V, W, R, O, S, C>
where
    I: CandidateInspector,
    E: EvidenceSource,
    V: ProofVerifier,
    W: RadicleLifecycleRegistry,
    R: RadicleWriter,
    O: PropagationObserver,
    S: ReceiptSink,
    C: Clock,
{
    /// Constructs the workflow from explicit trusted dependencies.
    #[must_use]
    pub const fn new(dependencies: ServiceDependencies<I, E, V, W, R, O, S, C>) -> Self {
        Self { dependencies }
    }

    /// Inspects, observes, authorizes, claims, writes, announces, and observes.
    ///
    /// The signer is unreachable until both product containment and the Auths
    /// kernel authorize the same canonical action and the workflow is claimed.
    ///
    /// # Errors
    ///
    /// Returns a typed integration failure. A write failure after claiming is
    /// intentionally not retried: durable state remains `claimed` for explicit
    /// operator reconciliation.
    #[allow(
        clippy::too_many_lines,
        reason = "the security-relevant effect ordering is intentionally visible in one method"
    )]
    pub fn execute(&self, request: AuthorizeRequest) -> Result<WorkflowOutcome, ServiceError> {
        let now = self.dependencies.clock.now()?;
        if let Some(product_decision) = preflight_configuration_decision(
            &request.workflow_grant,
            &request.required_configuration,
            &self.dependencies.executed_configuration,
        ) {
            let decision = preflight_decision_receipt(
                request.workflow_grant.workflow_id().clone(),
                request
                    .workflow_grant
                    .digest()
                    .map_err(|_| ServiceError::Canonicalization)?,
                request.required_configuration,
                self.dependencies.executed_configuration.clone(),
                product_decision,
                now,
            )
            .map_err(|_| ServiceError::Canonicalization)?;
            self.append_decision(&decision)?;
            return Ok(WorkflowOutcome::Rejected {
                receipt: Box::new(decision),
            });
        }
        let candidate = self.dependencies.candidate_inspector.inspect(
            &request.candidate,
            &self.dependencies.executed_configuration,
        )?;
        let evidence = self.dependencies.evidence_source.observe(
            request.workflow_grant.rid(),
            request.workflow_grant.issue_id(),
            &self.dependencies.executed_configuration,
            now,
        )?;
        let action = derive_exact_action(
            &request.workflow_grant,
            &request.required_configuration,
            &request.candidate,
            candidate.facts(),
            &evidence,
        )?;
        let product_decision = evaluate(&EvaluationContext {
            grant: &request.workflow_grant,
            action: &action,
            submission: &request.candidate,
            candidate: candidate.facts(),
            evidence: &evidence,
            required_configuration: &request.required_configuration,
            executed_configuration: &self.dependencies.executed_configuration,
            request_audience: request.auths_request.audience().as_str(),
            now,
        });
        let mut decision = decision_receipt(
            &action,
            &request.required_configuration,
            &self.dependencies.executed_configuration,
            product_decision.clone(),
            now,
        )
        .map_err(|_| ServiceError::Canonicalization)?;
        if product_decision.class != DecisionClass::Authorized {
            self.append_decision(&decision)?;
            return Ok(WorkflowOutcome::Rejected {
                receipt: Box::new(decision),
            });
        }

        let canonical = RadiclePatchProfile
            .canonicalize(
                &action
                    .canonical_bytes()
                    .map_err(|_| ServiceError::Canonicalization)?,
            )
            .map_err(|_| ServiceError::Profile)?;
        let authorized = match self.dependencies.proof_verifier.verify(
            &request.proof,
            &canonical,
            &request.auths_request,
        )? {
            ProofDecision::Authorized(authorized) => {
                if authorized.command().action() != &action {
                    return Err(ServiceError::Profile);
                }
                decision.auths_decision = Some(DecisionClass::Authorized);
                decision.auths_code = Some("authorized".into());
                decision.auths_proof_digest = Some(DigestHex::from_digest_bytes(
                    *authorized.verified().proof_digest().as_bytes(),
                ));
                decision.auths_context_digest = Some(DigestHex::from_digest_bytes(
                    *authorized.verified().context_digest().as_bytes(),
                ));
                *authorized
            }
            ProofDecision::Denied { code } => {
                decision.auths_decision = Some(DecisionClass::Denied);
                decision.auths_code = Some(code);
                self.append_decision(&decision)?;
                return Ok(WorkflowOutcome::Rejected {
                    receipt: Box::new(decision),
                });
            }
            ProofDecision::Indeterminate { code } => {
                decision.auths_decision = Some(DecisionClass::Indeterminate);
                decision.auths_code = Some(code);
                self.append_decision(&decision)?;
                return Ok(WorkflowOutcome::Rejected {
                    receipt: Box::new(decision),
                });
            }
        };
        self.append_decision(&decision)?;
        let decision_digest = decision
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let action_digest = action
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let claim_id = claim_id(&action, &action_digest);
        let core_authorization_digest = core_authorization_digest(&decision)?;
        let lifecycle = start_lifecycle(
            &self.dependencies.workflow_store,
            &request.workflow_grant,
            &action,
            candidate.facts(),
            &evidence,
            &request.required_configuration,
            &self.dependencies.executed_configuration,
            &product_decision,
            &decision_digest,
            &core_authorization_digest,
            &claim_id,
            now,
        )?;
        let LifecycleStartResult::Started(mut lifecycle) = lifecycle else {
            return match lifecycle {
                LifecycleStartResult::Replay(record) => Ok(WorkflowOutcome::Replay { record }),
                LifecycleStartResult::Conflict(record) => Ok(WorkflowOutcome::Conflict { record }),
                LifecycleStartResult::ReconciliationRequired {
                    store,
                    record,
                    recovery,
                } => self.reconcile_unknown(
                    store,
                    *record,
                    *recovery,
                    decision,
                    decision_digest,
                    now,
                ),
                LifecycleStartResult::Started(_) => unreachable!(),
            };
        };
        let fresh_evidence = self.dependencies.evidence_source.observe(
            action.rid(),
            action.issue_id(),
            &self.dependencies.executed_configuration,
            now,
        )?;
        if !critical_evidence_matches(&evidence, &fresh_evidence) {
            release_lifecycle(
                &lifecycle.store,
                &lifecycle.workflow_id,
                lifecycle.credential_stage.record().revision(),
                lifecycle.context,
                &action_digest,
                now,
            )?;
            return Err(ServiceError::FreshEvidence);
        }
        let attempt = lifecycle_transition(
            &lifecycle.store,
            &lifecycle.workflow_id,
            lifecycle.credential_stage.record().revision(),
            TransitionCommandV1::StartAttempt,
            lifecycle.context.clone(),
        )?;
        let call_entry = lifecycle_transition(
            &lifecycle.store,
            &lifecycle.workflow_id,
            attempt.record().revision(),
            TransitionCommandV1::MarkProviderCallEntered,
            lifecycle.context.clone(),
        )?;
        let provider_call_authorization =
            auths_lifecycle::ProviderCallAuthorizationV1::from_durable(&call_entry)
                .map_err(|_| ServiceError::LifecycleAuthorization)?;
        let command = VerifiedOpenPatchCommand::new(
            authorized,
            candidate,
            request.candidate,
            fresh_evidence,
            lifecycle
                .execution_authorization
                .take()
                .ok_or(ServiceError::LifecycleAuthorization)?,
            provider_call_authorization,
            claim_id.clone(),
        );
        let Ok(publication) = self.dependencies.radicle_writer.open_patch(command, now) else {
            let unknown = mark_unknown_lifecycle(
                &lifecycle.store,
                &lifecycle.workflow_id,
                call_entry.record().revision(),
                lifecycle.context,
                &action_digest,
                now,
            )?;
            return Ok(WorkflowOutcome::ReconciliationRequired {
                record: workflow_record(&action, &claim_id, unknown.record(), None, now)?,
            });
        };
        let execution = RadicleExecutionReceipt::new(
            self.dependencies.executed_configuration.receipt_schema(),
            decision_digest.clone(),
            claim_id.clone(),
            publication.clone(),
        );
        self.dependencies
            .workflow_store
            .persist_publication(action.workflow_id(), &publication)?;
        self.dependencies
            .receipt_sink
            .append(&RadicleReceipt::Execution(Box::new(execution.clone())))?;
        let execution_digest = execution
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let publication_digest = crate::canonical::canonical_digest(&publication)
            .map_err(|_| ServiceError::Canonicalization)?;
        commit_lifecycle(
            &lifecycle.store,
            &lifecycle.workflow_id,
            call_entry.record().revision(),
            lifecycle.context,
            &execution_digest,
            &publication_digest,
        )?;
        self.complete_propagation(publication, decision, execution, now)
    }

    fn append_decision(&self, decision: &RadicleDecisionReceipt) -> Result<(), ServiceError> {
        self.dependencies
            .receipt_sink
            .append(&RadicleReceipt::Decision(Box::new(decision.clone())))
            .map_err(ServiceError::from)
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "the helper consumes the domain outcome values into one terminal result"
    )]
    fn complete_propagation(
        &self,
        publication: crate::executor::LocalPublication,
        decision: RadicleDecisionReceipt,
        execution: RadicleExecutionReceipt,
        now: u64,
    ) -> Result<WorkflowOutcome, ServiceError> {
        if self
            .dependencies
            .radicle_writer
            .announce(&publication)
            .is_err()
        {
            return Ok(WorkflowOutcome::Executed {
                stage: WorkflowStage::Stored,
                decision: Box::new(decision),
                execution: Box::new(execution),
                propagation: None,
            });
        }
        let execution_digest = execution
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let Ok(propagation) =
            self.dependencies
                .propagation_observer
                .observe(&publication, &execution_digest, now)
        else {
            return Ok(WorkflowOutcome::Executed {
                stage: WorkflowStage::Announced,
                decision: Box::new(decision),
                execution: Box::new(execution),
                propagation: None,
            });
        };
        self.dependencies
            .receipt_sink
            .append(&RadicleReceipt::Propagation(Box::new(propagation.clone())))?;
        Ok(WorkflowOutcome::Executed {
            stage: WorkflowStage::Replicated,
            decision: Box::new(decision),
            execution: Box::new(execution),
            propagation: Some(Box::new(propagation)),
        })
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "recovery inputs are consumed as one authoritative restart attempt"
    )]
    fn reconcile_unknown(
        &self,
        store: std::sync::Arc<dyn RadicleLifecycleStore>,
        record: LifecycleRecordV1,
        recovery: RadicleRecoveryRecordV1,
        decision: RadicleDecisionReceipt,
        decision_digest: DigestHex,
        now: u64,
    ) -> Result<WorkflowOutcome, ServiceError> {
        let publication = if let Some(publication) = self
            .dependencies
            .workflow_store
            .load_publication(recovery.exact_action.workflow_id())?
        {
            Some(publication)
        } else {
            let query = PublicationReconciliationQuery {
                action: recovery.exact_action.clone(),
                claim_id: recovery.claim_id.clone(),
            };
            match self
                .dependencies
                .evidence_source
                .reconcile_publication(&query, now)
            {
                Ok(PublicationReconciliation::Exact(publication)) => Some(publication),
                Ok(PublicationReconciliation::Ambiguous) | Err(_) => None,
            }
        };
        let Some(publication) = publication else {
            let observation_digest =
                lifecycle_event_digest(b"radicle-publication-ambiguous", &recovery.claim_id, now);
            let reconciled = reconcile_lifecycle(
                &store,
                &record,
                context_from_record(&record, now)?,
                &observation_digest,
                EffectConclusion::Inconclusive,
                now,
            )?;
            return Ok(WorkflowOutcome::ReconciliationRequired {
                record: workflow_record(
                    &recovery.exact_action,
                    &recovery.claim_id,
                    reconciled.record(),
                    None,
                    now,
                )?,
            });
        };
        let execution = RadicleExecutionReceipt::new(
            self.dependencies.executed_configuration.receipt_schema(),
            decision_digest,
            recovery.claim_id.clone(),
            publication.clone(),
        );
        self.dependencies
            .workflow_store
            .persist_publication(recovery.exact_action.workflow_id(), &publication)?;
        self.dependencies
            .receipt_sink
            .append(&RadicleReceipt::Execution(Box::new(execution.clone())))?;
        let execution_digest = execution
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        reconcile_lifecycle(
            &store,
            &record,
            context_from_record(&record, now)?,
            &execution_digest,
            EffectConclusion::Effect,
            now,
        )?;
        self.complete_propagation(publication, decision, execution, now)
    }
}

struct LifecycleStart {
    store: std::sync::Arc<dyn RadicleLifecycleStore>,
    workflow_id: SharedWorkflowId,
    context: TransitionContextV1,
    credential_stage: DurableTransitionV1,
    execution_authorization: Option<ExecutionAuthorizationV1>,
}

enum LifecycleStartResult {
    Started(Box<LifecycleStart>),
    Replay(WorkflowRecord),
    Conflict(WorkflowRecord),
    ReconciliationRequired {
        store: std::sync::Arc<dyn RadicleLifecycleStore>,
        record: Box<LifecycleRecordV1>,
        recovery: Box<RadicleRecoveryRecordV1>,
    },
}

#[allow(clippy::too_many_arguments)]
#[allow(
    clippy::too_many_lines,
    reason = "the durable decision-to-credential sequence stays visible as one audited unit"
)]
fn start_lifecycle(
    registry: &impl RadicleLifecycleRegistry,
    grant: &IssueAddressGrantV1,
    action: &OpenPatchActionV1,
    candidate: &crate::types::CandidateFacts,
    evidence: &crate::types::RadicleEvidenceV1,
    required_configuration: &VerifierConfiguration,
    executed_configuration: &VerifierConfiguration,
    decision: &crate::containment::Decision,
    decision_digest: &DigestHex,
    core_authorization_digest: &DigestHex,
    claim_id: &DigestHex,
    now: u64,
) -> Result<LifecycleStartResult, ServiceError> {
    let projection = RadicleLifecycleProjectionInput {
        grant,
        action,
        candidate,
        evidence,
        required_configuration,
        executed_configuration,
        decision,
        verifier_time: now,
    }
    .project()
    .map_err(|_| ServiceError::Projection)?;
    let workflow_id = projection.workflow_id.clone();
    let context = projection.transition_context(now);
    let recovery = RadicleRecoveryRecordV1 {
        schema: "auths.radicle.recovery-record/1".into(),
        workflow_id: action.workflow_id().clone(),
        shared_workflow_id: workflow_id.as_str().into(),
        exact_action: action.clone(),
        candidate_facts: candidate.clone(),
        planning_evidence: evidence.clone(),
        decision_receipt_digest: decision_digest.clone(),
        claim_id: claim_id.clone(),
    };
    recovery.validate().map_err(|_| ServiceError::Projection)?;
    if let Some(existing) = registry.load_recovery(action.workflow_id())? {
        if existing != recovery {
            let store = registry.for_action(&existing.exact_action)?;
            let shared_id = SharedWorkflowId::parse(&existing.shared_workflow_id)
                .map_err(|_| ServiceError::Projection)?;
            let record = store
                .load_radicle_lifecycle(&shared_id)?
                .ok_or(ServiceError::WorkflowState)?;
            return Ok(LifecycleStartResult::Conflict(workflow_record(
                &existing.exact_action,
                &existing.claim_id,
                &record,
                registry.load_publication(action.workflow_id())?.as_ref(),
                now,
            )?));
        }
    } else {
        registry.persist_recovery(&recovery)?;
    }
    let store = registry.for_action(action)?;
    if let Some(existing) = store.load_radicle_lifecycle(&workflow_id)? {
        if existing.decision_input().commitments.exact_action_digest()
            != commitment(
                &action
                    .digest()
                    .map_err(|_| ServiceError::Canonicalization)?,
            )?
        {
            return Ok(LifecycleStartResult::Conflict(workflow_record(
                action,
                claim_id,
                &existing,
                registry.load_publication(action.workflow_id())?.as_ref(),
                now,
            )?));
        }
        return classify_existing_lifecycle(
            registry, store, existing, recovery, action, claim_id, now,
        );
    }
    let decision_input = projection
        .into_decision_input(&RadicleLifecycleDecisionBindings {
            core_authorization_digest,
            decision_receipt_digest: decision_digest,
            implementation_build_digest: &implementation_build_digest(),
            expires_at: grant.expires_at(),
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
            let existing = store
                .load_radicle_lifecycle(&workflow_id)?
                .ok_or(ServiceError::WorkflowState)?;
            return classify_existing_lifecycle(
                registry, store, existing, recovery, action, claim_id, now,
            );
        }
        Err(error) => return Err(ServiceError::Lifecycle(error)),
    };
    if recorded.disposition() == TransitionDisposition::ExactReplay {
        return classify_existing_lifecycle(
            registry,
            store,
            recorded.record().clone(),
            recovery,
            action,
            claim_id,
            now,
        );
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
        )) => {
            return Ok(LifecycleStartResult::Conflict(workflow_record(
                action,
                claim_id,
                recorded.record(),
                None,
                now,
            )?));
        }
        Err(error) => return Err(error),
    };
    let action_digest = action
        .digest()
        .map_err(|_| ServiceError::Canonicalization)?;
    let evidence_digest = evidence
        .digest()
        .map_err(|_| ServiceError::Canonicalization)?;
    let execution_intent = ExecutionIntentV1::new(
        commitment(&action_digest)?,
        ProviderRequestDigest::new(digest_bytes(&action_digest)?),
        ProviderConditionDigest::new(digest_bytes(&evidence_digest)?),
        ProviderContractId::parse(PROVIDER_CONTRACT_ID).map_err(|_| ServiceError::Projection)?,
        ProviderRetryClass::NonRetryable,
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
        .map_err(|_| ServiceError::LifecycleAuthorization)?;
    Ok(LifecycleStartResult::Started(Box::new(LifecycleStart {
        store,
        workflow_id,
        context,
        credential_stage,
        execution_authorization: Some(execution_authorization),
    })))
}

#[allow(clippy::too_many_arguments)]
fn classify_existing_lifecycle(
    registry: &impl RadicleLifecycleRegistry,
    store: std::sync::Arc<dyn RadicleLifecycleStore>,
    existing: LifecycleRecordV1,
    recovery: RadicleRecoveryRecordV1,
    action: &OpenPatchActionV1,
    claim_id: &DigestHex,
    now: u64,
) -> Result<LifecycleStartResult, ServiceError> {
    let publication = registry.load_publication(action.workflow_id())?;
    match existing.state() {
        LifecycleState::Committed | LifecycleState::ReconciledCommitted => {
            Ok(LifecycleStartResult::Replay(workflow_record(
                action,
                claim_id,
                &existing,
                publication.as_ref(),
                now,
            )?))
        }
        LifecycleState::OutcomeUnknown => Ok(LifecycleStartResult::ReconciliationRequired {
            store,
            record: Box::new(existing),
            recovery: Box::new(recovery),
        }),
        LifecycleState::Executing
            if existing
                .attempts()
                .last()
                .is_some_and(|attempt| attempt.call_entered) =>
        {
            let action_digest = action
                .digest()
                .map_err(|_| ServiceError::Canonicalization)?;
            let unknown = mark_unknown_lifecycle(
                &store,
                existing.workflow_id(),
                existing.revision(),
                context_from_record(&existing, now)?,
                &action_digest,
                now,
            )?;
            Ok(LifecycleStartResult::ReconciliationRequired {
                store,
                record: Box::new(unknown.record().clone()),
                recovery: Box::new(recovery),
            })
        }
        LifecycleState::DecisionRecorded => Ok(LifecycleStartResult::Conflict(workflow_record(
            action, claim_id, &existing, None, now,
        )?)),
        LifecycleState::Reserved
        | LifecycleState::ExecutionIntentRecorded
        | LifecycleState::Executing => {
            let action_digest = action
                .digest()
                .map_err(|_| ServiceError::Canonicalization)?;
            let released = release_lifecycle(
                &store,
                existing.workflow_id(),
                existing.revision(),
                context_from_record(&existing, now)?,
                &action_digest,
                now,
            )?;
            Ok(LifecycleStartResult::Conflict(workflow_record(
                action,
                claim_id,
                released.record(),
                None,
                now,
            )?))
        }
        LifecycleState::Released | LifecycleState::ReconciledReleased => {
            Ok(LifecycleStartResult::Conflict(workflow_record(
                action,
                claim_id,
                &existing,
                publication.as_ref(),
                now,
            )?))
        }
    }
}

fn workflow_record(
    action: &OpenPatchActionV1,
    claim_id: &DigestHex,
    lifecycle: &LifecycleRecordV1,
    publication: Option<&crate::executor::LocalPublication>,
    now: u64,
) -> Result<WorkflowRecord, ServiceError> {
    let stage = if publication.is_some()
        && matches!(
            lifecycle.state(),
            LifecycleState::Committed | LifecycleState::ReconciledCommitted
        ) {
        WorkflowStage::Stored
    } else {
        WorkflowStage::Claimed
    };
    Ok(WorkflowRecord::from_lifecycle(
        action.workflow_id().clone(),
        action
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?,
        claim_id.clone(),
        stage,
        publication,
        now,
    ))
}

fn lifecycle_transition(
    store: &std::sync::Arc<dyn RadicleLifecycleStore>,
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
    store: &std::sync::Arc<dyn RadicleLifecycleStore>,
    workflow_id: &SharedWorkflowId,
    revision: u64,
    context: TransitionContextV1,
    action_digest: &DigestHex,
    now: u64,
) -> Result<DurableTransitionV1, ServiceError> {
    let event = lifecycle_event_digest(b"radicle-definite-pre-effect-failure", action_digest, now);
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
    store: &std::sync::Arc<dyn RadicleLifecycleStore>,
    workflow_id: &SharedWorkflowId,
    revision: u64,
    context: TransitionContextV1,
    action_digest: &DigestHex,
    now: u64,
) -> Result<DurableTransitionV1, ServiceError> {
    let event = lifecycle_event_digest(b"radicle-publication-outcome-unknown", action_digest, now);
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
    store: &std::sync::Arc<dyn RadicleLifecycleStore>,
    workflow_id: &SharedWorkflowId,
    revision: u64,
    context: TransitionContextV1,
    execution_receipt_digest: &DigestHex,
    result_digest: &DigestHex,
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
    store: &std::sync::Arc<dyn RadicleLifecycleStore>,
    unknown: &LifecycleRecordV1,
    context: TransitionContextV1,
    domain_receipt_digest: &DigestHex,
    conclusion: EffectConclusion,
    now: u64,
) -> Result<DurableTransitionV1, ServiceError> {
    let intent = unknown
        .execution_intent()
        .ok_or(ServiceError::WorkflowState)?;
    let reconciliation_digest = lifecycle_event_digest(
        b"radicle-publication-reconciliation",
        domain_receipt_digest,
        now,
    );
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
                    "auths.radicle.revocation-not-configured/1",
                    record.workflow_id().as_str(),
                ))
                .map_err(|_| ServiceError::Canonicalization)?,
            )?,
        },
        capacity,
    })
}

fn critical_evidence_matches(
    planning: &crate::types::RadicleEvidenceV1,
    fresh: &crate::types::RadicleEvidenceV1,
) -> bool {
    planning.rid() == fresh.rid()
        && planning.repository_identity_revision() == fresh.repository_identity_revision()
        && planning.canonical_head_oid() == fresh.canonical_head_oid()
        && planning.issue_id() == fresh.issue_id()
        && planning.issue_open() == fresh.issue_open()
        && planning.issue_history_complete() == fresh.issue_history_complete()
        && planning.executor_signer_did() == fresh.executor_signer_did()
        && planning.executor_node_id() == fresh.executor_node_id()
        && planning.default_branch() == fresh.default_branch()
        && planning.canonical_derivation_digest() == fresh.canonical_derivation_digest()
}

fn core_authorization_digest(decision: &RadicleDecisionReceipt) -> Result<DigestHex, ServiceError> {
    let proof = decision
        .auths_proof_digest
        .as_ref()
        .ok_or(ServiceError::LifecycleAuthorization)?;
    let context = decision
        .auths_context_digest
        .as_ref()
        .ok_or(ServiceError::LifecycleAuthorization)?;
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(proof.as_str().as_bytes());
    bytes.extend_from_slice(context.as_str().as_bytes());
    Ok(sha256(&bytes))
}

fn implementation_build_digest() -> DigestHex {
    sha256(
        option_env!("AUTHS_BUILD_COMMIT")
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .as_bytes(),
    )
}

fn claim_id(action: &OpenPatchActionV1, action_digest: &DigestHex) -> DigestHex {
    let mut bytes = Vec::with_capacity(160);
    bytes.extend_from_slice(b"AUTHS-RADICLE-CLAIM\x00\x01");
    bytes.extend_from_slice(action.workflow_id().as_str().as_bytes());
    bytes.extend_from_slice(action_digest.as_str().as_bytes());
    sha256(&bytes)
}

fn lifecycle_event_digest(domain: &[u8], digest: &DigestHex, now: u64) -> DigestHex {
    let mut bytes = Vec::with_capacity(domain.len() + 72);
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(digest.as_str().as_bytes());
    bytes.extend_from_slice(&now.to_be_bytes());
    sha256(&bytes)
}

fn commitment(value: &DigestHex) -> Result<CommitmentDigest, ServiceError> {
    Ok(CommitmentDigest::new(digest_bytes(value)?))
}

fn digest_bytes(value: &DigestHex) -> Result<[u8; 32], ServiceError> {
    hex::decode(value.as_str())
        .map_err(|_| ServiceError::Canonicalization)?
        .try_into()
        .map_err(|_| ServiceError::Canonicalization)
}

fn preflight_configuration_decision(
    grant: &IssueAddressGrantV1,
    required: &VerifierConfiguration,
    executed: &VerifierConfiguration,
) -> Option<crate::containment::Decision> {
    use crate::containment::{Decision, DecisionCode};

    if grant.validate().is_err() || required.validate().is_err() || executed.validate().is_err() {
        return Some(Decision {
            class: DecisionClass::Denied,
            code: DecisionCode::InvalidConfiguration,
            detail: "workflow or verifier configuration is invalid".into(),
        });
    }
    (required != grant.required_configuration() || required != executed).then(|| Decision {
        class: DecisionClass::Denied,
        code: DecisionCode::VerifierConfigurationMismatch,
        detail: "required and executed verifier configurations differ".into(),
    })
}

/// Derives the only exact Auths action from inspected facts and synchronized evidence.
///
/// # Errors
///
/// Returns a canonicalization failure if a committed input cannot be encoded.
pub fn derive_exact_action(
    grant: &IssueAddressGrantV1,
    required_configuration: &VerifierConfiguration,
    submission: &CandidateSubmission,
    candidate: &crate::types::CandidateFacts,
    evidence: &crate::types::RadicleEvidenceV1,
) -> Result<OpenPatchActionV1, ServiceError> {
    let issue_reference = format!(
        "Radicle-Issue: {}\nAuths-Workflow: {}",
        grant.issue_id(),
        grant.workflow_id()
    );
    Ok(OpenPatchActionV1::new(OpenPatchActionInput {
        workflow_id: grant.workflow_id().clone(),
        workflow_grant_digest: grant.digest().map_err(|_| ServiceError::Canonicalization)?,
        rid: grant.rid().clone(),
        issue_id: grant.issue_id().clone(),
        repository_identity_revision: grant.repository_identity_revision().clone(),
        canonical_base_oid: grant.canonical_base_oid().clone(),
        candidate_oid: candidate.candidate_oid().clone(),
        candidate_bundle_digest: candidate.bundle_digest().clone(),
        candidate_commit_set_digest: candidate.commit_set_digest().clone(),
        candidate_tree_delta_digest: candidate.tree_delta_digest().clone(),
        patch_title_digest: sha256(submission.patch_title.as_bytes()),
        patch_body_digest: sha256(submission.patch_body.as_bytes()),
        issue_reference_digest: sha256(issue_reference.as_bytes()),
        signer_did: grant.expected_signer_did().clone(),
        executor_audience: grant.executor_audience().clone(),
        required_configuration_digest: required_configuration
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?,
        evidence_snapshot_digest: evidence
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?,
    }))
}

/// End-to-end workflow result.
pub enum WorkflowOutcome {
    /// Product containment or Auths denied/was indeterminate; no claim or write occurred.
    Rejected {
        /// Durable decision receipt.
        receipt: Box<RadicleDecisionReceipt>,
    },
    /// The exact action was already claimed.
    Replay {
        /// Existing durable workflow state.
        record: WorkflowRecord,
    },
    /// The workflow identifier is already bound to other action bytes.
    Conflict {
        /// Existing durable workflow state.
        record: WorkflowRecord,
    },
    /// A local publication may have occurred and must be reconciled without
    /// calling the writer again.
    ReconciliationRequired {
        /// Durable public workflow projection.
        record: WorkflowRecord,
    },
    /// The patch was stored; announce/propagation stages may still be pending.
    Executed {
        /// Farthest proven stage.
        stage: WorkflowStage,
        /// Authority decision.
        decision: Box<RadicleDecisionReceipt>,
        /// Local write result.
        execution: Box<RadicleExecutionReceipt>,
        /// Independent propagation evidence when available.
        propagation: Option<Box<RadiclePropagationReceipt>>,
    },
}

/// Closed workflow-service failure.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// An effect adapter failed.
    #[error("workflow adapter failed: {0}")]
    Port(#[from] PortError),
    /// Exact action canonicalization failed.
    #[error("could not canonicalize the exact Radicle action")]
    Canonicalization,
    /// The profile meaning did not match.
    #[error("exact Radicle action did not satisfy its Auths profile")]
    Profile,
    /// Durable at-most-once state could not commit.
    #[error("durable workflow state is unavailable")]
    WorkflowState,
    /// Shared lifecycle projection failed closed.
    #[error("Radicle inputs could not be projected into shared lifecycle")]
    Projection,
    /// Shared lifecycle storage or transition failed.
    #[error("shared lifecycle state failed: {0:?}")]
    Lifecycle(StoreError),
    /// A durable stage did not authorize signer or provider-call access.
    #[error("shared lifecycle did not authorize the protected Radicle boundary")]
    LifecycleAuthorization,
    /// Critical Radicle evidence changed immediately before publication.
    #[error("critical Radicle evidence changed before publication")]
    FreshEvidence,
}

impl From<StoreError> for ServiceError {
    fn from(value: StoreError) -> Self {
        Self::Lifecycle(value)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use auths_model::CanonicalAction;
    use auths_sdk::RequestContext;

    use super::*;
    use crate::{
        candidate::InspectedCandidate,
        executor::LocalPublication,
        ports::{
            CandidateInspector, Clock, EvidenceSource, ProofDecision, ProofVerifier,
            PropagationObserver, RadicleWriter, ReceiptSink,
        },
        receipts::{RadiclePropagationReceipt, RadicleReceipt},
        test_support::{NOW, configuration, grant, submission},
        types::{CandidateSubmission, CobId, Rid},
    };

    struct ForbiddenEffects {
        calls: Arc<AtomicUsize>,
    }

    impl ForbiddenEffects {
        fn called(&self) -> ! {
            self.calls.fetch_add(1, Ordering::SeqCst);
            panic!("a preflight configuration mismatch reached a protected effect")
        }
    }

    impl CandidateInspector for ForbiddenEffects {
        fn inspect(
            &self,
            _: &CandidateSubmission,
            _: &VerifierConfiguration,
        ) -> Result<InspectedCandidate, PortError> {
            self.called()
        }
    }

    impl EvidenceSource for ForbiddenEffects {
        fn observe(
            &self,
            _: &Rid,
            _: &CobId,
            _: &VerifierConfiguration,
            _: u64,
        ) -> Result<crate::types::RadicleEvidenceV1, PortError> {
            self.called()
        }
    }

    impl ProofVerifier for ForbiddenEffects {
        fn verify(
            &self,
            _: &[u8],
            _: &CanonicalAction,
            _: &RequestContext,
        ) -> Result<ProofDecision, PortError> {
            self.called()
        }
    }

    impl RadicleWriter for ForbiddenEffects {
        fn open_patch(
            &self,
            _: VerifiedOpenPatchCommand,
            _: u64,
        ) -> Result<LocalPublication, PortError> {
            self.called()
        }

        fn announce(&self, _: &LocalPublication) -> Result<(), PortError> {
            self.called()
        }
    }

    impl RadicleLifecycleRegistry for ForbiddenEffects {
        fn for_action(
            &self,
            _: &OpenPatchActionV1,
        ) -> Result<std::sync::Arc<dyn RadicleLifecycleStore>, StoreError> {
            self.called()
        }

        fn persist_recovery(&self, _: &RadicleRecoveryRecordV1) -> Result<(), StoreError> {
            self.called()
        }

        fn load_recovery(
            &self,
            _: &crate::types::WorkflowId,
        ) -> Result<Option<RadicleRecoveryRecordV1>, StoreError> {
            self.called()
        }

        fn persist_publication(
            &self,
            _: &crate::types::WorkflowId,
            _: &LocalPublication,
        ) -> Result<(), StoreError> {
            self.called()
        }

        fn load_publication(
            &self,
            _: &crate::types::WorkflowId,
        ) -> Result<Option<LocalPublication>, StoreError> {
            self.called()
        }
    }

    impl PropagationObserver for ForbiddenEffects {
        fn observe(
            &self,
            _: &LocalPublication,
            _: &DigestHex,
            _: u64,
        ) -> Result<RadiclePropagationReceipt, PortError> {
            self.called()
        }
    }

    #[derive(Clone, Copy)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> Result<u64, PortError> {
            Ok(NOW)
        }
    }

    #[derive(Default)]
    struct CapturingReceipts {
        receipts: Mutex<Vec<RadicleReceipt>>,
    }

    impl ReceiptSink for CapturingReceipts {
        fn append(&self, receipt: &RadicleReceipt) -> Result<(), PortError> {
            self.receipts
                .lock()
                .map_err(|_| PortError::Persistence)?
                .push(receipt.clone());
            Ok(())
        }
    }

    #[test]
    fn configuration_mismatch_never_reaches_candidate_evidence_auths_signer_or_writer() {
        let required = configuration(30);
        let executed = configuration(31);
        let grant = grant(required.clone());
        let forbidden_calls = Arc::new(AtomicUsize::new(0));
        let receipt_sink = CapturingReceipts::default();
        let service = RadicleIssueWorkflowService::new(ServiceDependencies {
            candidate_inspector: ForbiddenEffects {
                calls: Arc::clone(&forbidden_calls),
            },
            evidence_source: ForbiddenEffects {
                calls: Arc::clone(&forbidden_calls),
            },
            proof_verifier: ForbiddenEffects {
                calls: Arc::clone(&forbidden_calls),
            },
            workflow_store: ForbiddenEffects {
                calls: Arc::clone(&forbidden_calls),
            },
            radicle_writer: ForbiddenEffects {
                calls: Arc::clone(&forbidden_calls),
            },
            propagation_observer: ForbiddenEffects {
                calls: Arc::clone(&forbidden_calls),
            },
            receipt_sink,
            clock: FixedClock,
            executed_configuration: executed.clone(),
        });
        let request = AuthorizeRequest {
            workflow_grant: grant,
            required_configuration: required,
            candidate: submission(),
            proof: Vec::new(),
            auths_request: RequestContext::new(
                executed.executor_audience().as_str(),
                [0x42; 32],
                NOW,
            )
            .unwrap(),
        };

        let outcome = service.execute(request).unwrap();

        let WorkflowOutcome::Rejected { receipt } = outcome else {
            panic!("configuration drift must be rejected")
        };
        assert_eq!(
            receipt.product_decision.code,
            crate::containment::DecisionCode::VerifierConfigurationMismatch
        );
        assert_eq!(
            receipt.required_configuration_digest,
            configuration(30).digest().unwrap()
        );
        assert_eq!(
            receipt.executed_configuration_digest,
            executed.digest().unwrap()
        );
        assert!(receipt.action_digest.is_none());
        assert_eq!(forbidden_calls.load(Ordering::SeqCst), 0);
    }
}
