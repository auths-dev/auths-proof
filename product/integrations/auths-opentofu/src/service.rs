//! Linear shared-lifecycle orchestration for one exact OpenTofu saved plan.

use std::sync::Arc;

use auths_bounded_policy::{CommitmentDigest, EvidenceSourceId, VerifierTime};
use auths_lifecycle::{
    DomainReceiptDigest, DurableTransitionV1, EffectConclusion, ExecutionAuthorizationV1,
    ExecutionIntentV1, LifecycleFailure, LifecycleRecordV1, LifecycleState, LifecycleStore,
    ObservationDigest, ProviderConditionDigest, ProviderContractId, ProviderRequestDigest,
    ProviderResultDigest, ProviderRetryClass, ReconciliationId, ReconciliationObservationV1,
    StoreError, StoreTransactionV1, TransitionCommandV1, TransitionContextV1,
    TransitionDisposition, WorkflowId, execute_store_transaction,
};
use auths_profile_api::ActionProfile as _;
use auths_sdk::{Authorized, RequestContext};
use subtle::ConstantTimeEq as _;

use crate::{
    action::OpenTofuSavedPlanApplyV1,
    canonical::sha256,
    claim::{ClaimRecord, ClaimStage},
    decision::DecisionClass,
    errors::PortError,
    executor::{
        OpenTofuReconciliationAuthorizationV1, VerifiedOpenTofuReconciliationCommand,
        VerifiedSavedPlanPreparationCommand,
    },
    lifecycle::{
        EVIDENCE_SOURCE_ID, OpenTofuLifecycleDecisionBindings, OpenTofuLifecycleProjectionInput,
        PROVIDER_CONTRACT_ID,
    },
    observe::validate_apply_result,
    plan_projection::SavedPlanProjectionV1,
    ports::{
        Clock, CredentialProvider, OpenTofuCredential, OpenTofuGateway, PlanArtifactStore,
        ProofDecision, ProofVerifier, ReceiptSink,
    },
    profile::{OpenTofuApplyCommand, OpenTofuSavedPlanProfile},
    receipts::{
        ApplyReceipt, DecisionReceipt, ObservationReceipt, OpenTofuReceipt, apply_receipt,
        decision_receipt, observation_receipt,
    },
    types::{
        DigestHex, OpenTofuApplyResult, OpenTofuStateEvidenceV1, OpenTofuVerifierConfigurationV1,
    },
};

/// Hostile request plus protected planning output and an Auths proof.
pub struct ExecuteSavedPlanRequest {
    pub action: OpenTofuSavedPlanApplyV1,
    pub projection: SavedPlanProjectionV1,
    pub evidence: OpenTofuStateEvidenceV1,
    pub required_configuration: OpenTofuVerifierConfigurationV1,
    pub proof: Vec<u8>,
    pub auths_request: RequestContext,
}

/// Lifecycle store plus the read required for exact replay and recovery.
pub trait OpenTofuLifecycleStore: LifecycleStore + Send + Sync {
    /// Loads one validated immutable shared lifecycle record.
    ///
    /// # Errors
    ///
    /// Returns a closed store error for unavailable or corrupt state.
    fn load_opentofu_lifecycle(
        &self,
        workflow: &WorkflowId,
    ) -> Result<Option<LifecycleRecordV1>, StoreError>;
}

impl<T: OpenTofuLifecycleStore + ?Sized> OpenTofuLifecycleStore for Arc<T> {
    fn load_opentofu_lifecycle(
        &self,
        workflow: &WorkflowId,
    ) -> Result<Option<LifecycleRecordV1>, StoreError> {
        (**self).load_opentofu_lifecycle(workflow)
    }
}

/// Explicit dependencies keep security-relevant ordering auditable.
pub struct ServiceDependencies<V, A, C, G, W, R, T> {
    pub proof_verifier: V,
    pub artifact_store: A,
    pub credential_provider: C,
    pub opentofu_gateway: G,
    pub lifecycle_store: W,
    pub receipt_sink: R,
    pub clock: T,
    pub executed_configuration: OpenTofuVerifierConfigurationV1,
}

/// Complete saved-plan service.
pub struct SavedPlanService<V, A, C, G, W, R, T> {
    dependencies: ServiceDependencies<V, A, C, G, W, R, T>,
}

impl<V, A, C, G, W, R, T> SavedPlanService<V, A, C, G, W, R, T>
where
    V: ProofVerifier,
    A: PlanArtifactStore,
    C: CredentialProvider,
    G: OpenTofuGateway,
    W: OpenTofuLifecycleStore,
    R: ReceiptSink,
    T: Clock,
{
    #[must_use]
    pub const fn new(dependencies: ServiceDependencies<V, A, C, G, W, R, T>) -> Self {
        Self { dependencies }
    }

    /// Applies one exact saved plan through durable shared lifecycle stages.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError`] when verification, persistence, artifacts,
    /// credentials, state reads, execution, or reconciliation cannot be
    /// classified safely.
    #[allow(
        clippy::too_many_lines,
        reason = "security-relevant durable, artifact, credential, apply, and receipt ordering stays linear"
    )]
    pub fn execute(
        &self,
        request: ExecuteSavedPlanRequest,
    ) -> Result<WorkflowOutcome, ServiceError> {
        let now = self.dependencies.clock.now()?;
        let mut decision = decision_receipt(
            &request.action,
            &request.projection,
            &request.evidence,
            &request.required_configuration,
            &self.dependencies.executed_configuration,
            request.auths_request.audience().as_str(),
            now,
        )?;
        if decision.decision.class != DecisionClass::Authorized {
            self.append(&OpenTofuReceipt::Decision(Box::new(decision.clone())))?;
            return Ok(WorkflowOutcome::Rejected {
                receipt: Box::new(decision),
            });
        }

        let canonical = OpenTofuSavedPlanProfile
            .canonicalize(&request.action.canonical_bytes()?)
            .map_err(|_| ServiceError::Profile)?;
        let authorized = match self.dependencies.proof_verifier.verify(
            &request.proof,
            &canonical,
            &request.auths_request,
        )? {
            ProofDecision::Authorized(authorized) => {
                if authorized.command().action() != &request.action {
                    return Err(ServiceError::Profile);
                }
                decision.auths_decision = Some("authorized".into());
                decision.auths_code = Some("authorized".into());
                *authorized
            }
            ProofDecision::Denied { code } => {
                decision.auths_decision = Some("denied".into());
                decision.auths_code = Some(code);
                decision.decision = crate::decision::Decision::proof_denied();
                self.append(&OpenTofuReceipt::Decision(Box::new(decision.clone())))?;
                return Ok(WorkflowOutcome::Rejected {
                    receipt: Box::new(decision),
                });
            }
            ProofDecision::Indeterminate { code } => {
                decision.auths_decision = Some("indeterminate".into());
                decision.auths_code = Some(code);
                decision.decision = crate::decision::Decision::proof_indeterminate();
                self.append(&OpenTofuReceipt::Decision(Box::new(decision.clone())))?;
                return Ok(WorkflowOutcome::Rejected {
                    receipt: Box::new(decision),
                });
            }
        };
        self.append(&OpenTofuReceipt::Decision(Box::new(decision.clone())))?;

        let action_digest = request.action.digest()?;
        let workflow_id = WorkflowId::parse(request.action.nonce().as_str())
            .map_err(|_| ServiceError::Projection)?;
        if let Some(existing) = self
            .dependencies
            .lifecycle_store
            .load_opentofu_lifecycle(&workflow_id)
            .map_err(ServiceError::Lifecycle)?
        {
            return self.resume_or_replay(
                decision,
                authorized,
                request.projection,
                request.evidence,
                &existing,
                now,
            );
        }

        let projection = OpenTofuLifecycleProjectionInput {
            action: &request.action,
            evidence: &request.evidence,
            required_configuration: &request.required_configuration,
            executed_configuration: &self.dependencies.executed_configuration,
            decision: &decision.decision,
            verifier_time: now,
        }
        .project()
        .map_err(|_| ServiceError::Projection)?;
        let context = projection.transition_context(now);
        let decision_digest = decision.digest()?;
        let decision_input = projection
            .into_decision_input(&OpenTofuLifecycleDecisionBindings {
                core_authorization_digest: &core_authorization_digest(&authorized),
                decision_receipt_digest: &decision_digest,
                implementation_build_digest: &implementation_build_digest(),
                expires_at: request.action.expires_at(),
            })
            .map_err(|_| ServiceError::Projection)?;
        let recorded = match execute_store_transaction(
            &self.dependencies.lifecycle_store,
            &StoreTransactionV1 {
                workflow_id: workflow_id.clone(),
                expected_revision: None,
                command: TransitionCommandV1::RecordDecision(Box::new(decision_input)),
                context: context.clone(),
            },
        ) {
            Ok(recorded) => recorded,
            Err(StoreError::Conflict | StoreError::Rejected(LifecycleFailure::Conflict)) => {
                return self.concurrent_conflict(&workflow_id, &action_digest);
            }
            Err(error) => return Err(ServiceError::Lifecycle(error)),
        };
        if recorded.disposition() == TransitionDisposition::ExactReplay {
            return self.concurrent_conflict(&workflow_id, &action_digest);
        }
        self.append_claim(recorded.record(), ClaimStage::Claimed)?;
        let reserved = match lifecycle_transition(
            &self.dependencies.lifecycle_store,
            &workflow_id,
            recorded.record().revision(),
            TransitionCommandV1::Reserve,
            context.clone(),
        ) {
            Ok(reserved) => reserved,
            Err(ServiceError::Lifecycle(
                StoreError::Conflict
                | StoreError::Rejected(
                    LifecycleFailure::Conflict | LifecycleFailure::CapacityExceeded,
                ),
            )) => return self.concurrent_conflict(&workflow_id, &action_digest),
            Err(error) => return Err(error),
        };

        let artifact = match self
            .dependencies
            .artifact_store
            .resolve(request.action.plan_handle())
        {
            Ok(artifact)
                if digest_eq(
                    &sha256(artifact.bytes()),
                    request.action.opaque_plan_digest(),
                ) =>
            {
                artifact
            }
            Ok(_) => {
                self.release_after_failure(
                    &workflow_id,
                    reserved.record().revision(),
                    context,
                    &action_digest,
                    now,
                )?;
                return Err(ServiceError::Port(PortError::ArtifactMismatch));
            }
            Err(error) => {
                self.release_after_failure(
                    &workflow_id,
                    reserved.record().revision(),
                    context,
                    &action_digest,
                    now,
                )?;
                return Err(ServiceError::Port(error));
            }
        };
        self.append_claim(reserved.record(), ClaimStage::ArtifactVerified)?;

        let provider_request = canonical_digest(&(
            request.action.opaque_plan_digest(),
            request.action.plan_projection_digest(),
        ))?;
        let evidence_digest = request.evidence.digest()?;
        let execution_intent = ExecutionIntentV1::new(
            commitment(&action_digest)?,
            ProviderRequestDigest::new(digest_bytes(&provider_request)?),
            ProviderConditionDigest::new(digest_bytes(&evidence_digest)?),
            ProviderContractId::parse(PROVIDER_CONTRACT_ID)
                .map_err(|_| ServiceError::Projection)?,
            ProviderRetryClass::ObserveBeforeRetry,
        );
        let intent_recorded = lifecycle_transition(
            &self.dependencies.lifecycle_store,
            &workflow_id,
            reserved.record().revision(),
            TransitionCommandV1::RecordExecutionIntent(execution_intent),
            context.clone(),
        )?;
        let credential_stage = lifecycle_transition(
            &self.dependencies.lifecycle_store,
            &workflow_id,
            intent_recorded.record().revision(),
            TransitionCommandV1::AuthorizeCredential,
            context.clone(),
        )?;
        let execution_authorization = ExecutionAuthorizationV1::from_durable(&credential_stage)
            .map_err(|_| ServiceError::ClaimState)?;
        let credential = match self
            .dependencies
            .credential_provider
            .credential_after_authorization(&execution_authorization, &request.action)
        {
            Ok(credential) => credential,
            Err(error) => {
                self.release_after_failure(
                    &workflow_id,
                    credential_stage.record().revision(),
                    context,
                    &action_digest,
                    now,
                )?;
                return Err(ServiceError::Port(error));
            }
        };
        self.append_claim(credential_stage.record(), ClaimStage::CredentialAcquired)?;
        let preparation = VerifiedSavedPlanPreparationCommand::new(
            authorized,
            request.projection,
            request.evidence,
            execution_authorization,
        );
        let current = match self
            .dependencies
            .opentofu_gateway
            .recheck_state(&preparation, &credential)
        {
            Ok(current) => current,
            Err(error) => {
                self.release_after_failure(
                    &workflow_id,
                    credential_stage.record().revision(),
                    context,
                    &action_digest,
                    now,
                )?;
                return Err(ServiceError::Port(error));
            }
        };
        if let Err(error) = validate_state_recheck(
            preparation.action(),
            preparation.planning_evidence(),
            &current,
        ) {
            self.release_after_failure(
                &workflow_id,
                credential_stage.record().revision(),
                context,
                &action_digest,
                now,
            )?;
            return Err(error);
        }
        self.append_claim(credential_stage.record(), ClaimStage::StateRechecked)?;
        let attempt = lifecycle_transition(
            &self.dependencies.lifecycle_store,
            &workflow_id,
            credential_stage.record().revision(),
            TransitionCommandV1::StartAttempt,
            context.clone(),
        )?;
        let call_entry = lifecycle_transition(
            &self.dependencies.lifecycle_store,
            &workflow_id,
            attempt.record().revision(),
            TransitionCommandV1::MarkProviderCallEntered,
            context.clone(),
        )?;
        let call_authorization =
            auths_lifecycle::ProviderCallAuthorizationV1::from_durable(&call_entry)
                .map_err(|_| ServiceError::ClaimState)?;
        self.append_claim(call_entry.record(), ClaimStage::ApplyStarted)?;
        let command = preparation.authorize_provider_call(call_authorization);
        match self.dependencies.opentofu_gateway.apply_saved_plan(
            &command,
            &artifact,
            &credential,
            now,
        ) {
            Ok(result) if validate_apply_result(command.action(), &result).is_ok() => {
                self.finish_committed(decision, command.action(), result, &call_entry, context)
            }
            Ok(_) | Err(PortError::OutcomeUnknown) => {
                let unknown = mark_unknown_lifecycle(
                    &self.dependencies.lifecycle_store,
                    &workflow_id,
                    call_entry.record().revision(),
                    context.clone(),
                    &action_digest,
                    now,
                )?;
                self.append_claim(unknown.record(), ClaimStage::OutcomeUnknown)?;
                let authorization =
                    OpenTofuReconciliationAuthorizationV1::from_record(unknown.record())
                        .map_err(|_| ServiceError::ClaimState)?;
                let reconciliation =
                    VerifiedOpenTofuReconciliationCommand::new(command, authorization);
                self.reconcile_unknown(
                    decision,
                    &reconciliation,
                    &credential,
                    unknown.record(),
                    context,
                    now,
                )
            }
            Err(error) => {
                self.release_after_failure(
                    &workflow_id,
                    call_entry.record().revision(),
                    context,
                    &action_digest,
                    now,
                )?;
                Err(ServiceError::Port(error))
            }
        }
    }

    fn resume_or_replay(
        &self,
        decision: DecisionReceipt,
        authorized: Authorized<OpenTofuApplyCommand>,
        projection: SavedPlanProjectionV1,
        evidence: OpenTofuStateEvidenceV1,
        existing: &LifecycleRecordV1,
        now: u64,
    ) -> Result<WorkflowOutcome, ServiceError> {
        let action_digest = authorized.command().action().digest()?;
        if existing.decision_input().commitments.exact_action_digest()
            != commitment(&action_digest)?
        {
            return Ok(WorkflowOutcome::Conflict {
                record: ClaimRecord::replay(existing).map_err(|_| ServiceError::ClaimState)?,
            });
        }
        if existing.state() != LifecycleState::OutcomeUnknown {
            return Ok(WorkflowOutcome::Replay {
                record: ClaimRecord::replay(existing).map_err(|_| ServiceError::ClaimState)?,
            });
        }
        let authorization = OpenTofuReconciliationAuthorizationV1::from_record(existing)
            .map_err(|_| ServiceError::ClaimState)?;
        let credential = self
            .dependencies
            .credential_provider
            .reconciliation_credential(&authorization, authorized.command().action())?;
        let command = VerifiedOpenTofuReconciliationCommand::from_authorized(
            authorized,
            projection,
            evidence,
            authorization,
        );
        let context = context_from_record(existing, now)?;
        self.reconcile_unknown(decision, &command, &credential, existing, context, now)
    }

    fn reconcile_unknown(
        &self,
        decision: DecisionReceipt,
        command: &VerifiedOpenTofuReconciliationCommand,
        credential: &OpenTofuCredential,
        unknown: &LifecycleRecordV1,
        context: TransitionContextV1,
        now: u64,
    ) -> Result<WorkflowOutcome, ServiceError> {
        match self
            .dependencies
            .opentofu_gateway
            .reconcile(command, credential, now)
        {
            Ok(result) if validate_apply_result(command.action(), &result).is_ok() => {
                self.finish_reconciled(decision, command.action(), result, unknown, context, now)
            }
            Ok(_) | Err(PortError::OutcomeUnknown) => Ok(WorkflowOutcome::OutcomeUnknown {
                record: ClaimRecord::from_lifecycle(unknown, ClaimStage::OutcomeUnknown)
                    .map_err(|_| ServiceError::ClaimState)?,
            }),
            Err(error) => Err(ServiceError::Port(error)),
        }
    }

    fn finish_committed(
        &self,
        decision: DecisionReceipt,
        action: &OpenTofuSavedPlanApplyV1,
        result: OpenTofuApplyResult,
        call_entry: &DurableTransitionV1,
        context: TransitionContextV1,
    ) -> Result<WorkflowOutcome, ServiceError> {
        let apply = apply_receipt(decision.digest()?, action, result.clone())?;
        let observation = observation_receipt(action, &result)?;
        let apply_digest = canonical_digest(&apply)?;
        let result_digest = canonical_digest(&result)?;
        let committed = lifecycle_transition(
            &self.dependencies.lifecycle_store,
            call_entry.record().workflow_id(),
            call_entry.record().revision(),
            TransitionCommandV1::Commit {
                result_digest: ProviderResultDigest::new(digest_bytes(&result_digest)?),
                domain_receipt_digest: DomainReceiptDigest::new(digest_bytes(&apply_digest)?),
            },
            context,
        )?;
        self.append_claim(committed.record(), ClaimStage::StateCommitted)?;
        self.append_claim(committed.record(), ClaimStage::PostconditionsObserved)?;
        self.append_claim(committed.record(), ClaimStage::Converged)?;
        self.append(&OpenTofuReceipt::Apply(Box::new(apply.clone())))?;
        self.append(&OpenTofuReceipt::Observation(observation.clone()))?;
        Ok(WorkflowOutcome::Executed {
            decision: Box::new(decision),
            apply: Box::new(apply),
            observation,
            result: Box::new(result),
        })
    }

    fn finish_reconciled(
        &self,
        decision: DecisionReceipt,
        action: &OpenTofuSavedPlanApplyV1,
        result: OpenTofuApplyResult,
        unknown: &LifecycleRecordV1,
        context: TransitionContextV1,
        now: u64,
    ) -> Result<WorkflowOutcome, ServiceError> {
        let apply = apply_receipt(decision.digest()?, action, result.clone())?;
        let observation = observation_receipt(action, &result)?;
        let apply_digest = canonical_digest(&apply)?;
        let result_digest = canonical_digest(&result)?;
        let reconciled = reconcile_lifecycle(
            &self.dependencies.lifecycle_store,
            unknown,
            context,
            &result_digest,
            &apply_digest,
            now,
        )?;
        self.append_claim(reconciled.record(), ClaimStage::Converged)?;
        self.append(&OpenTofuReceipt::Apply(Box::new(apply.clone())))?;
        self.append(&OpenTofuReceipt::Observation(observation.clone()))?;
        Ok(WorkflowOutcome::Executed {
            decision: Box::new(decision),
            apply: Box::new(apply),
            observation,
            result: Box::new(result),
        })
    }

    fn concurrent_conflict(
        &self,
        workflow_id: &WorkflowId,
        action_digest: &DigestHex,
    ) -> Result<WorkflowOutcome, ServiceError> {
        let existing = self
            .dependencies
            .lifecycle_store
            .load_opentofu_lifecycle(workflow_id)
            .map_err(ServiceError::Lifecycle)?
            .ok_or(ServiceError::ClaimState)?;
        let record = ClaimRecord::replay(&existing).map_err(|_| ServiceError::ClaimState)?;
        if existing.decision_input().commitments.exact_action_digest() == commitment(action_digest)?
            && matches!(
                existing.state(),
                LifecycleState::Committed | LifecycleState::ReconciledCommitted
            )
        {
            Ok(WorkflowOutcome::Replay { record })
        } else {
            Ok(WorkflowOutcome::Conflict { record })
        }
    }

    fn release_after_failure(
        &self,
        workflow_id: &WorkflowId,
        revision: u64,
        context: TransitionContextV1,
        action_digest: &DigestHex,
        now: u64,
    ) -> Result<(), ServiceError> {
        let released = release_lifecycle(
            &self.dependencies.lifecycle_store,
            workflow_id,
            revision,
            context,
            action_digest,
            now,
        )?;
        self.append_claim(released.record(), ClaimStage::Failed)
    }

    fn append_claim(
        &self,
        record: &LifecycleRecordV1,
        stage: ClaimStage,
    ) -> Result<(), ServiceError> {
        let receipt =
            ClaimRecord::from_lifecycle(record, stage).map_err(|_| ServiceError::ClaimState)?;
        self.append(&OpenTofuReceipt::Claim(receipt))
    }

    fn append(&self, receipt: &OpenTofuReceipt) -> Result<(), ServiceError> {
        self.dependencies.receipt_sink.append(receipt)?;
        Ok(())
    }
}

fn lifecycle_transition(
    store: &impl LifecycleStore,
    workflow_id: &WorkflowId,
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
    store: &impl LifecycleStore,
    workflow_id: &WorkflowId,
    revision: u64,
    context: TransitionContextV1,
    action_digest: &DigestHex,
    now: u64,
) -> Result<DurableTransitionV1, ServiceError> {
    let event = lifecycle_event_digest(b"opentofu-definite-non-effect", action_digest, now);
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
    store: &impl LifecycleStore,
    workflow_id: &WorkflowId,
    revision: u64,
    context: TransitionContextV1,
    action_digest: &DigestHex,
    now: u64,
) -> Result<DurableTransitionV1, ServiceError> {
    let event = lifecycle_event_digest(b"opentofu-apply-outcome-unknown", action_digest, now);
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

fn reconcile_lifecycle(
    store: &impl LifecycleStore,
    unknown: &LifecycleRecordV1,
    context: TransitionContextV1,
    result_digest: &DigestHex,
    domain_receipt_digest: &DigestHex,
    now: u64,
) -> Result<DurableTransitionV1, ServiceError> {
    let intent = unknown.execution_intent().ok_or(ServiceError::ClaimState)?;
    let reconciliation_digest =
        lifecycle_event_digest(b"opentofu-backend-reconciliation", result_digest, now);
    let observation = ReconciliationObservationV1::new(
        ReconciliationId::parse(reconciliation_digest.as_str())
            .map_err(|_| ServiceError::Projection)?,
        EvidenceSourceId::parse(EVIDENCE_SOURCE_ID).map_err(|_| ServiceError::Projection)?,
        VerifierTime::from_unix_seconds(now),
        VerifierTime::from_unix_seconds(now.checked_add(300).ok_or(ServiceError::Canonical)?),
        ObservationDigest::new(digest_bytes(result_digest)?),
        EffectConclusion::Effect,
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
            snapshot_digest: commitment(&canonical_digest(&(
                "auths.opentofu.revocation-not-configured/1",
                record.workflow_id().as_str(),
            ))?)?,
        },
        capacity,
    })
}

fn validate_state_recheck(
    action: &OpenTofuSavedPlanApplyV1,
    planning: &OpenTofuStateEvidenceV1,
    current: &OpenTofuStateEvidenceV1,
) -> Result<(), ServiceError> {
    if current.backend_identity != planning.backend_identity
        || current.workspace != planning.workspace
        || current.state_lineage != planning.state_lineage
        || current.state_serial != planning.state_serial
        || !digest_eq(&current.state_digest, &planning.state_digest)
        || current.backend_identity != action.backend_identity()
        || current.workspace != action.workspace()
        || current.state_lineage != action.state_lineage()
        || current.state_serial != action.state_serial()
    {
        return Err(ServiceError::StateChanged);
    }
    Ok(())
}

fn digest_eq(left: &DigestHex, right: &DigestHex) -> bool {
    bool::from(left.as_str().as_bytes().ct_eq(right.as_str().as_bytes()))
}

fn core_authorization_digest(authorized: &Authorized<OpenTofuApplyCommand>) -> DigestHex {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(authorized.verified().proof_digest().as_bytes());
    bytes.extend_from_slice(authorized.verified().context_digest().as_bytes());
    sha256(&bytes)
}

fn implementation_build_digest() -> DigestHex {
    sha256(
        option_env!("AUTHS_BUILD_COMMIT")
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .as_bytes(),
    )
}

fn lifecycle_event_digest(domain: &[u8], digest: &DigestHex, now: u64) -> DigestHex {
    let mut bytes = Vec::with_capacity(domain.len() + 72);
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(digest.as_str().as_bytes());
    bytes.extend_from_slice(&now.to_be_bytes());
    sha256(&bytes)
}

fn canonical_digest<T: serde::Serialize>(value: &T) -> Result<DigestHex, ServiceError> {
    crate::canonical::canonical_digest(value).map_err(|_| ServiceError::Canonical)
}

fn digest_bytes(value: &DigestHex) -> Result<[u8; 32], ServiceError> {
    hex::decode(value.as_str())
        .map_err(|_| ServiceError::Canonical)?
        .try_into()
        .map_err(|_| ServiceError::Canonical)
}

fn commitment(value: &DigestHex) -> Result<CommitmentDigest, ServiceError> {
    Ok(CommitmentDigest::new(digest_bytes(value)?))
}

/// Complete workflow outcome.
pub enum WorkflowOutcome {
    Rejected {
        receipt: Box<DecisionReceipt>,
    },
    Replay {
        record: ClaimRecord,
    },
    Conflict {
        record: ClaimRecord,
    },
    OutcomeUnknown {
        record: ClaimRecord,
    },
    Executed {
        decision: Box<DecisionReceipt>,
        apply: Box<ApplyReceipt>,
        observation: ObservationReceipt,
        result: Box<OpenTofuApplyResult>,
    },
}

/// Closed service failure.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("OpenTofu profile failed")]
    Profile,
    #[error("OpenTofu lifecycle projection failed")]
    Projection,
    #[error("OpenTofu lifecycle state failed")]
    ClaimState,
    #[error("shared lifecycle store failed: {0:?}")]
    Lifecycle(StoreError),
    #[error("OpenTofu state changed after planning")]
    StateChanged,
    #[error("OpenTofu canonicalization failed")]
    Canonical,
    #[error(transparent)]
    Validation(#[from] crate::errors::ValidationError),
    #[error(transparent)]
    CanonicalSource(#[from] crate::errors::CanonicalError),
    #[error(transparent)]
    Port(#[from] PortError),
}
