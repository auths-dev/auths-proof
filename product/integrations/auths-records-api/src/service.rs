//! Ordered verification, shared lifecycle control, sealed provider execution,
//! replay, and reconciliation for create and read.

use std::sync::Arc;

use auths_bounded_policy::{CommitmentDigest, EvidenceSourceId, VerifierTime};
use auths_lifecycle::{
    DomainReceiptDigest, EffectConclusion, ExecutionAuthorizationV1, ExecutionIntentV1,
    LifecycleFailure, LifecycleRecordV1, LifecycleState, ObservationDigest,
    ProviderCallAuthorizationV1, ProviderConditionDigest, ProviderContractId,
    ProviderRequestDigest, ProviderResultDigest, ProviderRetryClass, ReconciliationId,
    ReconciliationObservationV1, StoreError, StoreTransactionV1, TransitionCommandV1,
    TransitionContextV1, TransitionDisposition, WorkflowId, execute_store_transaction,
};
use auths_profile_api::ActionProfile as _;
use auths_sdk::{Authorized, RequestContext, Verifier, VerifyResult};

use crate::{
    CREATE_PROVIDER_CONTRACT_ID, CreateEvaluation, CreateRecordProfile, CreateTransition,
    DecisionClass, DecisionReceipt, DeliveryReceipt, EffectReceipt, ExecutionClassification,
    ObservationReceipt, READ_PROVIDER_CONTRACT_ID, ReadEvaluation, ReadRecordProfile,
    ReadTransition, ReceiptBundle, RecordProjection, RecordsActionV1,
    RecordsApiVerifierConfigurationV1, RecordsDecision, RecordsError, RecordsLedger,
    RecordsLifecycleAction, RecordsLifecycleDecisionBindings, RecordsLifecycleProjectionInput,
    RecordsLifecycleProjectionV1, RecordsLifecycleRegistry, RecordsLifecycleStore,
    RecordsRequestEnvelopeV1, SealedCreateRecordCommand, SealedReadRecordCommand,
    VerifiedCreateRecordCommand, VerifiedReadRecordCommand,
    canonical::{canonical_digest, sha256},
    evaluate_create, evaluate_read,
};

pub enum CreateProofDecision {
    Authorized(Box<Authorized<VerifiedCreateRecordCommand>>),
    Denied(String),
    Indeterminate(String),
}

pub enum ReadProofDecision {
    Authorized(Box<Authorized<VerifiedReadRecordCommand>>),
    Denied(String),
    Indeterminate(String),
}

pub trait RecordsProofVerifier: Send + Sync {
    fn verify_create(
        &self,
        proof: &[u8],
        canonical: &auths_model::CanonicalAction,
        request: &RequestContext,
    ) -> Result<CreateProofDecision, RecordsError>;

    fn verify_read(
        &self,
        proof: &[u8],
        canonical: &auths_model::CanonicalAction,
        request: &RequestContext,
    ) -> Result<ReadProofDecision, RecordsError>;
}

pub struct SdkRecordsProofVerifier {
    verifier: Arc<Verifier>,
}

impl SdkRecordsProofVerifier {
    #[must_use]
    pub fn new(verifier: Verifier) -> Self {
        Self {
            verifier: Arc::new(verifier),
        }
    }

    #[must_use]
    pub const fn from_shared(verifier: Arc<Verifier>) -> Self {
        Self { verifier }
    }
}

impl RecordsProofVerifier for SdkRecordsProofVerifier {
    fn verify_create(
        &self,
        proof: &[u8],
        canonical: &auths_model::CanonicalAction,
        request: &RequestContext,
    ) -> Result<CreateProofDecision, RecordsError> {
        match self
            .verifier
            .verify(proof, canonical, request, &CreateRecordProfile)
            .map_err(|_| RecordsError::MeaningMismatch)?
        {
            VerifyResult::Authorized(authorized) => Ok(CreateProofDecision::Authorized(authorized)),
            VerifyResult::Denied(explanation) => {
                Ok(CreateProofDecision::Denied(explanation.code().into()))
            }
            VerifyResult::Indeterminate(explanation) => Ok(CreateProofDecision::Indeterminate(
                explanation.code().into(),
            )),
        }
    }

    fn verify_read(
        &self,
        proof: &[u8],
        canonical: &auths_model::CanonicalAction,
        request: &RequestContext,
    ) -> Result<ReadProofDecision, RecordsError> {
        match self
            .verifier
            .verify(proof, canonical, request, &ReadRecordProfile)
            .map_err(|_| RecordsError::MeaningMismatch)?
        {
            VerifyResult::Authorized(authorized) => Ok(ReadProofDecision::Authorized(authorized)),
            VerifyResult::Denied(explanation) => {
                Ok(ReadProofDecision::Denied(explanation.code().into()))
            }
            VerifyResult::Indeterminate(explanation) => {
                Ok(ReadProofDecision::Indeterminate(explanation.code().into()))
            }
        }
    }
}

pub struct RecordsService<V, L, W> {
    verifier: V,
    ledger: L,
    lifecycles: W,
    executed_configuration: RecordsApiVerifierConfigurationV1,
}

impl<V, L, W> RecordsService<V, L, W>
where
    V: RecordsProofVerifier,
    L: RecordsLedger,
    W: RecordsLifecycleRegistry,
{
    #[must_use]
    pub const fn new(
        verifier: V,
        ledger: L,
        lifecycles: W,
        executed_configuration: RecordsApiVerifierConfigurationV1,
    ) -> Self {
        Self {
            verifier,
            ledger,
            lifecycles,
            executed_configuration,
        }
    }

    pub fn execute(
        &self,
        request: &RecordsExecutionRequest,
    ) -> Result<RecordsWorkflowOutcome, RecordsError> {
        request.envelope.validate(
            usize::try_from(request.required_configuration.maximum_proof_bytes)
                .map_err(|_| RecordsError::LimitExceeded)?,
        )?;
        match &request.envelope.canonical_action {
            RecordsActionV1::Create(action) => self.execute_create(request, action),
            RecordsActionV1::Read(action) => self.execute_read(request, action),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the ordered create security pipeline remains visible as one audited unit"
    )]
    fn execute_create(
        &self,
        request: &RecordsExecutionRequest,
        action: &crate::CreateRecordV1,
    ) -> Result<RecordsWorkflowOutcome, RecordsError> {
        let proof = request.envelope.proof()?;
        let action_digest = action.digest()?;
        let mut decision = evaluate_create(&CreateEvaluation {
            action,
            policy: &request.policy,
            required_configuration: &request.required_configuration,
            executed_configuration: &self.executed_configuration,
            now: request.now,
        });
        let mut auths_decision = "not-run".to_string();
        let mut auths_code = "not-run".to_string();
        if decision.is_authorized()
            && request
                .envelope
                .presentation
                .verify(
                    &proof,
                    request.envelope.canonical_action.operation_id(),
                    &action_digest,
                    request.challenge,
                    &action.executor_audience,
                    request.now,
                    request.policy.maximum_presentation_lifetime_seconds,
                    &request.policy.presenter_principal,
                )
                .is_err()
        {
            decision = RecordsDecision::denied("presentation-invalid", "presentation");
        }
        let canonical = CreateRecordProfile
            .canonicalize(&action.canonical_bytes()?)
            .map_err(|_| RecordsError::MeaningMismatch)?;
        let authorized = if decision.is_authorized() {
            match self
                .verifier
                .verify_create(&proof, &canonical, &request.auths_request)?
            {
                CreateProofDecision::Authorized(value) if value.command().action() == action => {
                    auths_decision = "authorized".into();
                    auths_code = "authorized".into();
                    Some(value)
                }
                CreateProofDecision::Authorized(_) => return Err(RecordsError::MeaningMismatch),
                CreateProofDecision::Denied(code) => {
                    auths_decision = "denied".into();
                    auths_code = code;
                    decision = RecordsDecision::denied("proof-invalid", "proof");
                    None
                }
                CreateProofDecision::Indeterminate(code) => {
                    auths_decision = "indeterminate".into();
                    auths_code = code;
                    decision = indeterminate_proof();
                    None
                }
            }
        } else {
            None
        };
        let Some(authorized) = authorized else {
            let receipt = decision_receipt(
                request,
                &action_digest,
                &proof,
                &decision,
                &auths_decision,
                &auths_code,
                None,
                &self.executed_configuration,
            );
            return self.finish(
                request,
                receipt,
                None,
                None,
                ExecutionClassification::NotAuthorized,
                false,
            );
        };
        let projection = RecordsLifecycleProjectionInput {
            action: RecordsLifecycleAction::Create(action),
            policy: &request.policy,
            presentation: &request.envelope.presentation,
            required_configuration: &request.required_configuration,
            executed_configuration: &self.executed_configuration,
            decision: &decision,
            verifier_time: request.now,
        }
        .project()
        .map_err(|_| RecordsError::MeaningMismatch)?;
        let receipt = decision_receipt(
            request,
            &action_digest,
            &proof,
            &decision,
            &auths_decision,
            &auths_code,
            Some(&projection),
            &self.executed_configuration,
        );
        let decision_digest = canonical_digest(&receipt)?;
        let store = self
            .lifecycles
            .for_policy(&request.policy)
            .map_err(store_error)?;
        match start_lifecycle(
            &store,
            projection,
            &core_authorization_digest(&authorized),
            &decision_digest,
            action.expires_at,
            CREATE_PROVIDER_CONTRACT_ID,
            &action_digest,
            request.now,
        )? {
            LifecycleStart::Existing(record, context) => self.recover_existing(
                request,
                receipt,
                &store,
                &record,
                context,
                &action_digest,
                request.envelope.operation_id.as_str(),
            ),
            LifecycleStart::CapacityDenied => self.capacity_non_effect(
                request,
                receipt,
                &action_digest,
                "shared-create-capacity-exhausted",
            ),
            LifecycleStart::Ready(ready) => {
                let LifecycleReady {
                    workflow_id,
                    context,
                    execution_authorization,
                    call_authorization,
                    call_revision,
                } = *ready;
                let command = SealedCreateRecordCommand::new(
                    *authorized,
                    execution_authorization,
                    call_authorization,
                    decision_digest,
                    request.now,
                );
                match self.ledger.create(command) {
                    Ok(CreateTransition::Executed(effect) | CreateTransition::Replay(effect)) => {
                        commit_effect(&store, &workflow_id, &context, call_revision, &effect)?;
                        self.finish(
                            request,
                            receipt,
                            Some(effect),
                            None,
                            ExecutionClassification::Executed,
                            false,
                        )
                    }
                    Ok(CreateTransition::Denied(code)) => self.release_non_effect(
                        request,
                        receipt,
                        &store,
                        context,
                        call_revision,
                        &action_digest,
                        code,
                        true,
                    ),
                    Err(_) => self.reconcile_after_provider_error(
                        request,
                        receipt,
                        &store,
                        context,
                        call_revision,
                        &action_digest,
                    ),
                }
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the ordered read security pipeline remains visible as one audited unit"
    )]
    fn execute_read(
        &self,
        request: &RecordsExecutionRequest,
        action: &crate::ReadRecordV1,
    ) -> Result<RecordsWorkflowOutcome, RecordsError> {
        let proof = request.envelope.proof()?;
        let action_digest = action.digest()?;
        let mut decision = evaluate_read(&ReadEvaluation {
            action,
            policy: &request.policy,
            required_configuration: &request.required_configuration,
            executed_configuration: &self.executed_configuration,
            now: request.now,
        });
        let mut auths_decision = "not-run".to_string();
        let mut auths_code = "not-run".to_string();
        if decision.is_authorized()
            && request
                .envelope
                .presentation
                .verify(
                    &proof,
                    request.envelope.canonical_action.operation_id(),
                    &action_digest,
                    request.challenge,
                    &action.executor_audience,
                    request.now,
                    request.policy.maximum_presentation_lifetime_seconds,
                    &request.policy.presenter_principal,
                )
                .is_err()
        {
            decision = RecordsDecision::denied("presentation-invalid", "presentation");
        }
        let canonical = ReadRecordProfile
            .canonicalize(&action.canonical_bytes()?)
            .map_err(|_| RecordsError::MeaningMismatch)?;
        let authorized = if decision.is_authorized() {
            match self
                .verifier
                .verify_read(&proof, &canonical, &request.auths_request)?
            {
                ReadProofDecision::Authorized(value) if value.command().action() == action => {
                    auths_decision = "authorized".into();
                    auths_code = "authorized".into();
                    Some(value)
                }
                ReadProofDecision::Authorized(_) => return Err(RecordsError::MeaningMismatch),
                ReadProofDecision::Denied(code) => {
                    auths_decision = "denied".into();
                    auths_code = code;
                    decision = RecordsDecision::denied("proof-invalid", "proof");
                    None
                }
                ReadProofDecision::Indeterminate(code) => {
                    auths_decision = "indeterminate".into();
                    auths_code = code;
                    decision = indeterminate_proof();
                    None
                }
            }
        } else {
            None
        };
        let Some(authorized) = authorized else {
            let receipt = decision_receipt(
                request,
                &action_digest,
                &proof,
                &decision,
                &auths_decision,
                &auths_code,
                None,
                &self.executed_configuration,
            );
            return self.finish(
                request,
                receipt,
                None,
                None,
                ExecutionClassification::NotAuthorized,
                false,
            );
        };
        let projection = RecordsLifecycleProjectionInput {
            action: RecordsLifecycleAction::Read(action),
            policy: &request.policy,
            presentation: &request.envelope.presentation,
            required_configuration: &request.required_configuration,
            executed_configuration: &self.executed_configuration,
            decision: &decision,
            verifier_time: request.now,
        }
        .project()
        .map_err(|_| RecordsError::MeaningMismatch)?;
        let receipt = decision_receipt(
            request,
            &action_digest,
            &proof,
            &decision,
            &auths_decision,
            &auths_code,
            Some(&projection),
            &self.executed_configuration,
        );
        let decision_digest = canonical_digest(&receipt)?;
        let store = self
            .lifecycles
            .for_policy(&request.policy)
            .map_err(store_error)?;
        match start_lifecycle(
            &store,
            projection,
            &core_authorization_digest(&authorized),
            &decision_digest,
            action.expires_at,
            READ_PROVIDER_CONTRACT_ID,
            &action_digest,
            request.now,
        )? {
            LifecycleStart::Existing(record, context) => self.recover_existing(
                request,
                receipt,
                &store,
                &record,
                context,
                &action_digest,
                request.envelope.operation_id.as_str(),
            ),
            LifecycleStart::CapacityDenied => self.capacity_non_effect(
                request,
                receipt,
                &action_digest,
                "shared-read-capacity-exhausted",
            ),
            LifecycleStart::Ready(ready) => {
                let LifecycleReady {
                    workflow_id,
                    context,
                    execution_authorization,
                    call_authorization,
                    call_revision,
                } = *ready;
                let command = SealedReadRecordCommand::new(
                    *authorized,
                    request.policy.clone(),
                    execution_authorization,
                    call_authorization,
                    decision_digest,
                    request.now,
                );
                match self.ledger.read(command) {
                    Ok(
                        ReadTransition::Disclosed {
                            receipt: effect,
                            projection,
                        }
                        | ReadTransition::Replay {
                            receipt: effect,
                            projection,
                        },
                    ) => {
                        commit_effect(&store, &workflow_id, &context, call_revision, &effect)?;
                        self.finish(
                            request,
                            receipt,
                            Some(effect),
                            Some(projection),
                            ExecutionClassification::Executed,
                            false,
                        )
                    }
                    Ok(ReadTransition::Denied(code)) => self.release_non_effect(
                        request,
                        receipt,
                        &store,
                        context,
                        call_revision,
                        &action_digest,
                        code,
                        true,
                    ),
                    Err(_) => self.reconcile_after_provider_error(
                        request,
                        receipt,
                        &store,
                        context,
                        call_revision,
                        &action_digest,
                    ),
                }
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "non-effect lifecycle and receipt bindings remain explicit"
    )]
    fn release_non_effect(
        &self,
        request: &RecordsExecutionRequest,
        decision: DecisionReceipt,
        store: &Arc<dyn RecordsLifecycleStore>,
        context: TransitionContextV1,
        revision: u64,
        action_digest: &str,
        code: &str,
        protected_storage_accessed: bool,
    ) -> Result<RecordsWorkflowOutcome, RecordsError> {
        let effect = non_effect_receipt(
            &decision,
            action_digest,
            request.envelope.operation_id.as_str(),
            code,
            protected_storage_accessed,
            request.now,
        )?;
        let digest = canonical_digest(&effect)?;
        lifecycle_transition(
            store,
            &WorkflowId::parse(
                decision
                    .shared_workflow_id
                    .as_deref()
                    .ok_or(RecordsError::MeaningMismatch)?,
            )
            .map_err(|_| RecordsError::MeaningMismatch)?,
            revision,
            TransitionCommandV1::Release {
                result_digest: ProviderResultDigest::new(digest_bytes(&digest)?),
                domain_receipt_digest: DomainReceiptDigest::new(digest_bytes(&digest)?),
                conclusion: EffectConclusion::NonEffect,
            },
            context,
        )?;
        self.finish(
            request,
            decision,
            Some(effect),
            None,
            ExecutionClassification::DefiniteNonEffect,
            false,
        )
    }

    fn capacity_non_effect(
        &self,
        request: &RecordsExecutionRequest,
        decision: DecisionReceipt,
        action_digest: &str,
        code: &str,
    ) -> Result<RecordsWorkflowOutcome, RecordsError> {
        let effect = non_effect_receipt(
            &decision,
            action_digest,
            request.envelope.operation_id.as_str(),
            code,
            false,
            request.now,
        )?;
        self.finish(
            request,
            decision,
            Some(effect),
            None,
            ExecutionClassification::DefiniteNonEffect,
            false,
        )
    }

    fn reconcile_after_provider_error(
        &self,
        request: &RecordsExecutionRequest,
        decision: DecisionReceipt,
        store: &Arc<dyn RecordsLifecycleStore>,
        context: TransitionContextV1,
        revision: u64,
        action_digest: &str,
    ) -> Result<RecordsWorkflowOutcome, RecordsError> {
        let workflow = WorkflowId::parse(
            decision
                .shared_workflow_id
                .as_deref()
                .ok_or(RecordsError::MeaningMismatch)?,
        )
        .map_err(|_| RecordsError::MeaningMismatch)?;
        let unknown_receipt = non_effect_receipt(
            &decision,
            action_digest,
            request.envelope.operation_id.as_str(),
            "provider-outcome-unknown",
            true,
            request.now,
        )?;
        let unknown_digest = canonical_digest(&unknown_receipt)?;
        let unknown = lifecycle_transition(
            store,
            &workflow,
            revision,
            TransitionCommandV1::MarkOutcomeUnknown {
                domain_receipt_digest: DomainReceiptDigest::new(digest_bytes(&unknown_digest)?),
            },
            context.clone(),
        )?;
        match self.ledger.completed(action_digest) {
            Ok(completed) => self.reconcile_known(
                request,
                decision,
                store,
                unknown.record(),
                context,
                action_digest,
                completed,
            ),
            Err(_) => self.finish(
                request,
                decision,
                None,
                None,
                ExecutionClassification::OutcomeUnknown,
                false,
            ),
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "recovery keeps every exact lifecycle and domain binding explicit"
    )]
    #[allow(
        clippy::too_many_lines,
        reason = "the closed recovery state table stays visible as one audited unit"
    )]
    fn recover_existing(
        &self,
        request: &RecordsExecutionRequest,
        decision: DecisionReceipt,
        store: &Arc<dyn RecordsLifecycleStore>,
        record: &LifecycleRecordV1,
        context: TransitionContextV1,
        action_digest: &str,
        operation_id: &str,
    ) -> Result<RecordsWorkflowOutcome, RecordsError> {
        match record.state() {
            LifecycleState::Committed | LifecycleState::ReconciledCommitted => {
                let completed = self
                    .ledger
                    .completed(action_digest)?
                    .ok_or(RecordsError::StateUnavailable)?;
                self.finish(
                    request,
                    decision,
                    Some(completed.effect),
                    completed.projection,
                    ExecutionClassification::ReplayEffect,
                    true,
                )
            }
            LifecycleState::Released | LifecycleState::ReconciledReleased => {
                let effect = non_effect_receipt(
                    &decision,
                    action_digest,
                    operation_id,
                    "previous-non-effect-confirmed",
                    false,
                    request.now,
                )?;
                self.finish(
                    request,
                    decision,
                    Some(effect),
                    None,
                    ExecutionClassification::ReplayNonEffect,
                    true,
                )
            }
            LifecycleState::OutcomeUnknown => match self.ledger.completed(action_digest) {
                Ok(completed) => self.reconcile_known(
                    request,
                    decision,
                    store,
                    record,
                    context,
                    action_digest,
                    completed,
                ),
                Err(_) => self.finish(
                    request,
                    decision,
                    None,
                    None,
                    ExecutionClassification::OutcomeUnknown,
                    true,
                ),
            },
            LifecycleState::DecisionRecorded => {
                let effect = non_effect_receipt(
                    &decision,
                    action_digest,
                    operation_id,
                    "shared-capacity-exhausted",
                    false,
                    request.now,
                )?;
                self.finish(
                    request,
                    decision,
                    Some(effect),
                    None,
                    ExecutionClassification::ReplayNonEffect,
                    true,
                )
            }
            LifecycleState::Executing
                if record
                    .attempts()
                    .last()
                    .is_some_and(|attempt| attempt.call_entered) =>
            {
                let unknown_receipt = non_effect_receipt(
                    &decision,
                    action_digest,
                    operation_id,
                    "provider-outcome-unknown",
                    true,
                    request.now,
                )?;
                let digest = canonical_digest(&unknown_receipt)?;
                let unknown = lifecycle_transition(
                    store,
                    record.workflow_id(),
                    record.revision(),
                    TransitionCommandV1::MarkOutcomeUnknown {
                        domain_receipt_digest: DomainReceiptDigest::new(digest_bytes(&digest)?),
                    },
                    context.clone(),
                )?;
                match self.ledger.completed(action_digest) {
                    Ok(completed) => self.reconcile_known(
                        request,
                        decision,
                        store,
                        unknown.record(),
                        context,
                        action_digest,
                        completed,
                    ),
                    Err(_) => self.finish(
                        request,
                        decision,
                        None,
                        None,
                        ExecutionClassification::OutcomeUnknown,
                        true,
                    ),
                }
            }
            _ => Err(RecordsError::StateUnavailable),
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "reconciliation binds the exact lifecycle record and domain evidence"
    )]
    fn reconcile_known(
        &self,
        request: &RecordsExecutionRequest,
        decision: DecisionReceipt,
        store: &Arc<dyn RecordsLifecycleStore>,
        unknown: &LifecycleRecordV1,
        context: TransitionContextV1,
        action_digest: &str,
        completed: Option<crate::CompletedRecordsAction>,
    ) -> Result<RecordsWorkflowOutcome, RecordsError> {
        let (effect, projection, conclusion, classification) = if let Some(completed) = completed {
            (
                completed.effect,
                completed.projection,
                EffectConclusion::Effect,
                ExecutionClassification::ReplayEffect,
            )
        } else {
            (
                non_effect_receipt(
                    &decision,
                    action_digest,
                    request.envelope.operation_id.as_str(),
                    "canonical-provider-non-effect",
                    false,
                    request.now,
                )?,
                None,
                EffectConclusion::NonEffect,
                ExecutionClassification::ReplayNonEffect,
            )
        };
        let effect_digest = canonical_digest(&effect)?;
        let observation_digest = sha256(
            format!("auths.records.reconciliation/1:{action_digest}:{effect_digest}").as_bytes(),
        );
        lifecycle_transition(
            store,
            unknown.workflow_id(),
            unknown.revision(),
            TransitionCommandV1::Reconcile {
                observation: ReconciliationObservationV1::new(
                    ReconciliationId::parse(&sha256(
                        format!("records-reconcile:{action_digest}").as_bytes(),
                    ))
                    .map_err(|_| RecordsError::MeaningMismatch)?,
                    EvidenceSourceId::parse("auths.records-domain-ledger/2")
                        .map_err(|_| RecordsError::MeaningMismatch)?,
                    VerifierTime::from_unix_seconds(request.now),
                    VerifierTime::from_unix_seconds(request.now.saturating_add(60)),
                    ObservationDigest::new(digest_bytes(&observation_digest)?),
                    conclusion,
                    ProviderRequestDigest::new(digest_bytes(action_digest)?),
                ),
                domain_receipt_digest: DomainReceiptDigest::new(digest_bytes(&effect_digest)?),
            },
            context,
        )?;
        self.finish(
            request,
            decision,
            Some(effect),
            projection,
            classification,
            true,
        )
    }

    fn finish(
        &self,
        request: &RecordsExecutionRequest,
        decision: DecisionReceipt,
        effect: Option<EffectReceipt>,
        projection: Option<RecordProjection>,
        execution: ExecutionClassification,
        replay: bool,
    ) -> Result<RecordsWorkflowOutcome, RecordsError> {
        let observation = if let Some(effect) = &effect {
            Some(ObservationReceipt {
                schema: "auths.records-observation-receipt/2".into(),
                receipt_id: format!("observation-{}", &decision.action_digest[..24]),
                action_digest: decision.action_digest.clone(),
                effect_digest: canonical_digest(effect)?,
                state_commitment: self.ledger.state_commitment()?,
                outcome: match execution {
                    ExecutionClassification::Executed => "effect-observed",
                    ExecutionClassification::DefiniteNonEffect => "non-effect-observed",
                    ExecutionClassification::ReplayEffect => "previous-effect-confirmed",
                    ExecutionClassification::ReplayNonEffect => "previous-non-effect-confirmed",
                    ExecutionClassification::NotAuthorized
                    | ExecutionClassification::OutcomeUnknown => "no-observation",
                }
                .into(),
                observed_at: request.now,
            })
        } else {
            None
        };
        let bundle = ReceiptBundle {
            schema: "auths.records-receipt-bundle/2".into(),
            delivery: request.delivery.clone(),
            decision,
            execution,
            effect,
            observation,
        };
        self.ledger.append_receipt(bundle.clone())?;
        Ok(RecordsWorkflowOutcome {
            receipt: bundle,
            projection,
            replay,
            reusable_api_key_present: false,
        })
    }
}

enum LifecycleStart {
    Existing(Box<LifecycleRecordV1>, TransitionContextV1),
    CapacityDenied,
    Ready(Box<LifecycleReady>),
}

struct LifecycleReady {
    workflow_id: WorkflowId,
    context: TransitionContextV1,
    execution_authorization: ExecutionAuthorizationV1,
    call_authorization: ProviderCallAuthorizationV1,
    call_revision: u64,
}

#[allow(
    clippy::too_many_arguments,
    reason = "the lifecycle start binds every exact authority and provider commitment"
)]
#[allow(
    clippy::too_many_lines,
    reason = "the ordered durable authorization gates remain visible as one audited sequence"
)]
fn start_lifecycle(
    store: &Arc<dyn RecordsLifecycleStore>,
    projection: RecordsLifecycleProjectionV1,
    core_authorization_digest: &str,
    decision_digest: &str,
    expires_at: u64,
    provider_contract_id: &str,
    action_digest: &str,
    now: u64,
) -> Result<LifecycleStart, RecordsError> {
    let workflow_id = projection.workflow_id.clone();
    let context = projection.transition_context(now);
    let input = projection
        .into_decision_input(&RecordsLifecycleDecisionBindings {
            core_authorization_digest,
            decision_receipt_digest: decision_digest,
            implementation_build_digest: &implementation_build_digest(),
            expires_at,
        })
        .map_err(|_| RecordsError::MeaningMismatch)?;
    let record = match execute_store_transaction(
        store,
        &StoreTransactionV1 {
            workflow_id: workflow_id.clone(),
            expected_revision: None,
            command: TransitionCommandV1::RecordDecision(Box::new(input)),
            context: context.clone(),
        },
    ) {
        Ok(recorded) => {
            if recorded.disposition() == TransitionDisposition::ExactReplay
                && recorded.record().state() != LifecycleState::DecisionRecorded
            {
                return Ok(LifecycleStart::Existing(
                    Box::new(recorded.record().clone()),
                    context,
                ));
            }
            recorded.record().clone()
        }
        Err(StoreError::Conflict | StoreError::Rejected(LifecycleFailure::Conflict)) => {
            let record = store
                .load_records_lifecycle(&workflow_id)
                .map_err(store_error)?
                .ok_or(RecordsError::StateUnavailable)?;
            if record.state() != LifecycleState::DecisionRecorded {
                return Ok(LifecycleStart::Existing(Box::new(record), context));
            }
            record
        }
        Err(error) => return Err(store_error(error)),
    };
    let reserved = match execute_store_transaction(
        store,
        &StoreTransactionV1 {
            workflow_id: workflow_id.clone(),
            expected_revision: Some(record.revision()),
            command: TransitionCommandV1::Reserve,
            context: context.clone(),
        },
    ) {
        Ok(value) => value,
        Err(StoreError::Rejected(LifecycleFailure::CapacityExceeded)) => {
            return Ok(LifecycleStart::CapacityDenied);
        }
        Err(StoreError::Conflict | StoreError::Rejected(LifecycleFailure::Conflict)) => {
            let record = store
                .load_records_lifecycle(&workflow_id)
                .map_err(store_error)?
                .ok_or(RecordsError::StateUnavailable)?;
            return Ok(LifecycleStart::Existing(Box::new(record), context));
        }
        Err(error) => return Err(store_error(error)),
    };
    let execution_intent = ExecutionIntentV1::new(
        commitment(action_digest)?,
        ProviderRequestDigest::new(digest_bytes(action_digest)?),
        ProviderConditionDigest::new(digest_bytes(decision_digest)?),
        ProviderContractId::parse(provider_contract_id)
            .map_err(|_| RecordsError::MeaningMismatch)?,
        ProviderRetryClass::ObserveBeforeRetry,
    );
    let intent = lifecycle_transition(
        store,
        &workflow_id,
        reserved.record().revision(),
        TransitionCommandV1::RecordExecutionIntent(execution_intent),
        context.clone(),
    )?;
    let credential = lifecycle_transition(
        store,
        &workflow_id,
        intent.record().revision(),
        TransitionCommandV1::AuthorizeCredential,
        context.clone(),
    )?;
    let execution_authorization = ExecutionAuthorizationV1::from_durable(&credential)
        .map_err(|_| RecordsError::MeaningMismatch)?;
    let attempt = lifecycle_transition(
        store,
        &workflow_id,
        credential.record().revision(),
        TransitionCommandV1::StartAttempt,
        context.clone(),
    )?;
    let call = lifecycle_transition(
        store,
        &workflow_id,
        attempt.record().revision(),
        TransitionCommandV1::MarkProviderCallEntered,
        context.clone(),
    )?;
    let call_authorization = ProviderCallAuthorizationV1::from_durable(&call)
        .map_err(|_| RecordsError::MeaningMismatch)?;
    Ok(LifecycleStart::Ready(Box::new(LifecycleReady {
        workflow_id,
        context,
        execution_authorization,
        call_authorization,
        call_revision: call.record().revision(),
    })))
}

fn lifecycle_transition(
    store: &Arc<dyn RecordsLifecycleStore>,
    workflow_id: &WorkflowId,
    revision: u64,
    command: TransitionCommandV1,
    context: TransitionContextV1,
) -> Result<auths_lifecycle::DurableTransitionV1, RecordsError> {
    execute_store_transaction(
        store,
        &StoreTransactionV1 {
            workflow_id: workflow_id.clone(),
            expected_revision: Some(revision),
            command,
            context,
        },
    )
    .map_err(store_error)
}

fn commit_effect(
    store: &Arc<dyn RecordsLifecycleStore>,
    workflow_id: &WorkflowId,
    context: &TransitionContextV1,
    revision: u64,
    effect: &EffectReceipt,
) -> Result<(), RecordsError> {
    let digest = canonical_digest(effect)?;
    lifecycle_transition(
        store,
        workflow_id,
        revision,
        TransitionCommandV1::Commit {
            result_digest: ProviderResultDigest::new(digest_bytes(&digest)?),
            domain_receipt_digest: DomainReceiptDigest::new(digest_bytes(&digest)?),
        },
        context.clone(),
    )?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the immutable decision receipt exposes independent commitments"
)]
fn decision_receipt(
    request: &RecordsExecutionRequest,
    action_digest: &str,
    proof: &[u8],
    decision: &RecordsDecision,
    auths_decision: &str,
    auths_code: &str,
    projection: Option<&RecordsLifecycleProjectionV1>,
    executed_configuration: &RecordsApiVerifierConfigurationV1,
) -> DecisionReceipt {
    let receipt_key =
        sha256(format!("{}:{}", action_digest, request.delivery.delivery_id).as_bytes());
    DecisionReceipt {
        schema: "auths.records-decision-receipt/2".into(),
        receipt_id: format!("decision-{}", &receipt_key[..32]),
        action_digest: action_digest.into(),
        policy_digest: request.policy.digest().unwrap_or_default(),
        proof_digest: sha256(proof),
        presenter_principal: request.policy.presenter_principal.clone(),
        operation_id: request.envelope.operation_id.clone(),
        executor_audience: request.policy.executor_audience.clone(),
        required_configuration: request.required_configuration.clone(),
        executed_configuration: executed_configuration.clone(),
        decision: decision.clone(),
        auths_decision: auths_decision.into(),
        auths_code: auths_code.into(),
        shared_workflow_id: projection.map(|value| value.workflow_id.as_str().into()),
        reservation_set_digest: projection
            .map(|value| hex::encode(value.reservations.commitment().bytes())),
        reservation_intents_commitment: projection
            .map(|value| hex::encode(value.outputs.reservation_intents_commitment().as_bytes())),
        protected_storage_accessed: false,
        decided_at: request.now,
    }
}

fn non_effect_receipt(
    decision: &DecisionReceipt,
    action_digest: &str,
    operation_id: &str,
    code: &str,
    protected_storage_accessed: bool,
    now: u64,
) -> Result<EffectReceipt, RecordsError> {
    Ok(EffectReceipt::NonEffect {
        receipt_id: format!(
            "effect-{}",
            &sha256(format!("{action_digest}:{code}").as_bytes())[..24]
        ),
        decision_digest: canonical_digest(decision)?,
        action_digest: action_digest.into(),
        operation_id: operation_id.into(),
        code: code.into(),
        protected_storage_accessed,
        observed_at: now,
    })
}

fn indeterminate_proof() -> RecordsDecision {
    RecordsDecision {
        class: DecisionClass::Indeterminate,
        code: "proof-indeterminate".into(),
        stage: "proof".into(),
    }
}

fn core_authorization_digest<C>(authorized: &Authorized<C>) -> String {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(authorized.verified().proof_digest().as_bytes());
    bytes.extend_from_slice(authorized.verified().context_digest().as_bytes());
    sha256(&bytes)
}

fn implementation_build_digest() -> String {
    sha256(
        option_env!("AUTHS_BUILD_COMMIT")
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .as_bytes(),
    )
}

fn commitment(value: &str) -> Result<CommitmentDigest, RecordsError> {
    Ok(CommitmentDigest::new(digest_bytes(value)?))
}

fn digest_bytes(value: &str) -> Result<[u8; 32], RecordsError> {
    hex::decode(value)
        .map_err(|_| RecordsError::MeaningMismatch)?
        .try_into()
        .map_err(|_| RecordsError::MeaningMismatch)
}

fn store_error(_: StoreError) -> RecordsError {
    RecordsError::StateUnavailable
}

pub struct RecordsExecutionRequest {
    pub envelope: RecordsRequestEnvelopeV1,
    pub policy: crate::BoundedRecordApiPolicyV1,
    pub required_configuration: RecordsApiVerifierConfigurationV1,
    pub auths_request: RequestContext,
    pub challenge: [u8; 32],
    pub delivery: DeliveryReceipt,
    pub now: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordsWorkflowOutcome {
    pub receipt: ReceiptBundle,
    #[serde(rename = "response")]
    pub projection: Option<RecordProjection>,
    pub replay: bool,
    pub reusable_api_key_present: bool,
}
