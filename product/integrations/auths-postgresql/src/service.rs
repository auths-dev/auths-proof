//! Linear shared-lifecycle orchestration for one exact PostgreSQL update.

use std::{future::Future, pin::Pin, sync::Arc};

use auths_bounded_policy::{CommitmentDigest, EvidenceSourceId, VerifierTime};
use auths_lifecycle::{
    DomainReceiptDigest, DurableTransitionV1, EffectConclusion, ExecutionAuthorizationV1,
    ExecutionIntentV1, LifecycleFailure, LifecycleRecordV1, LifecycleState, LifecycleStore,
    ObservationDigest, ProviderConditionDigest, ProviderContractId, ProviderRequestDigest,
    ProviderResultDigest, ProviderRetryClass, ReconciliationId, ReconciliationObservationV1,
    RecoveryReferenceDigest, StoreError, StoreTransactionV1, TransitionCommandV1,
    TransitionContextV1, TransitionDisposition, WorkflowId, execute_store_transaction,
};
use auths_profile_api::ActionProfile as _;
use auths_sdk::{Authorized, RequestContext};

use crate::{
    action::PostgresBoundedUpdateV1,
    claim::{ClaimRecord, ClaimStage},
    compiler::{CompiledBoundedUpdate, compile_statement},
    decision::DecisionClass,
    evidence::PostgresEvidenceV1,
    executor::{
        PostgresReconciliationAuthorizationV1, VerifiedBoundedUpdateCommand,
        VerifiedPostgresReconciliationCommand,
    },
    lifecycle::{
        EVIDENCE_SOURCE_ID, PROVIDER_CONTRACT_ID, PostgresLifecycleDecisionBindings,
        PostgresLifecycleProjectionInput,
    },
    ports::{
        Clock, CredentialProvider, PortError, PostgresCredential, ProofDecision, ProofVerifier,
        ReceiptSink, Reconciliation, TransactionGateway, TransactionResult,
    },
    profile::{PostgresBoundedUpdateProfile, PostgresUpdateCommand},
    receipts::{
        DecisionReceipt, ObservationReceipt, PostgresReceipt, TransactionReceipt, decision_receipt,
        observation_receipt, transaction_receipt,
    },
    schema::{DigestHex, PostgresVerifierConfigurationV1, ValidationError},
};

/// Hostile request plus protected evidence and an Auths proof.
pub struct ExecuteBoundedUpdateRequest {
    pub action: PostgresBoundedUpdateV1,
    pub evidence: PostgresEvidenceV1,
    pub required_configuration: PostgresVerifierConfigurationV1,
    pub proof: Vec<u8>,
    pub auths_request: RequestContext,
    pub recovery_reference_digest: RecoveryReferenceDigest,
}

/// Lifecycle store plus the read required for exact replay and recovery.
pub trait PostgresLifecycleStore: LifecycleStore + Send + Sync {
    /// Loads one validated immutable shared lifecycle record.
    ///
    /// # Errors
    ///
    /// Returns a closed store error for unavailable or corrupt state.
    fn load_postgres_lifecycle(
        &self,
        workflow: &WorkflowId,
    ) -> Result<Option<LifecycleRecordV1>, StoreError>;
}

impl<T: PostgresLifecycleStore + ?Sized> PostgresLifecycleStore for Arc<T> {
    fn load_postgres_lifecycle(
        &self,
        workflow: &WorkflowId,
    ) -> Result<Option<LifecycleRecordV1>, StoreError> {
        (**self).load_postgres_lifecycle(workflow)
    }
}

/// Explicit dependencies make durable and effect ordering auditable.
pub struct ServiceDependencies<V, C, G, W, R, T> {
    pub proof_verifier: V,
    pub credential_provider: C,
    pub transaction_gateway: G,
    pub lifecycle_store: W,
    pub receipt_sink: R,
    pub clock: T,
    pub executed_configuration: PostgresVerifierConfigurationV1,
}

/// Complete bounded-update service.
pub struct BoundedUpdateService<V, C, G, W, R, T> {
    dependencies: ServiceDependencies<V, C, G, W, R, T>,
}

impl<V, C, G, W, R, T> BoundedUpdateService<V, C, G, W, R, T>
where
    V: ProofVerifier,
    C: CredentialProvider,
    G: TransactionGateway,
    W: PostgresLifecycleStore,
    R: ReceiptSink,
    T: Clock,
{
    #[must_use]
    pub const fn new(dependencies: ServiceDependencies<V, C, G, W, R, T>) -> Self {
        Self { dependencies }
    }

    /// Executes one exact update through durable shared lifecycle stages.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError`] when verification, persistence, credentials,
    /// canonicalization, transaction execution, or reconciliation cannot be
    /// classified safely.
    pub fn execute(
        &self,
        request: ExecuteBoundedUpdateRequest,
    ) -> Pin<Box<dyn Future<Output = Result<WorkflowOutcome, ServiceError>> + Send + '_>> {
        Box::pin(self.execute_inner(request))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "security-relevant durable, credential, transaction, and receipt ordering stays linear"
    )]
    async fn execute_inner(
        &self,
        request: ExecuteBoundedUpdateRequest,
    ) -> Result<WorkflowOutcome, ServiceError> {
        let now = self.dependencies.clock.now()?;
        let mut decision = decision_receipt(
            &request.action,
            &request.evidence,
            &request.required_configuration,
            &self.dependencies.executed_configuration,
            request.auths_request.audience().as_str(),
            now,
        )?;
        if decision.decision.class != DecisionClass::Authorized {
            self.append(&PostgresReceipt::Decision(Box::new(decision.clone())))?;
            return Ok(WorkflowOutcome::Rejected {
                receipt: Box::new(decision),
            });
        }

        let canonical = PostgresBoundedUpdateProfile
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
                self.append(&PostgresReceipt::Decision(Box::new(decision.clone())))?;
                return Ok(WorkflowOutcome::Rejected {
                    receipt: Box::new(decision),
                });
            }
            ProofDecision::Indeterminate { code } => {
                decision.auths_decision = Some("indeterminate".into());
                decision.auths_code = Some(code);
                decision.decision = crate::decision::Decision::proof_indeterminate();
                self.append(&PostgresReceipt::Decision(Box::new(decision.clone())))?;
                return Ok(WorkflowOutcome::Rejected {
                    receipt: Box::new(decision),
                });
            }
        };
        self.append(&PostgresReceipt::Decision(Box::new(decision.clone())))?;

        let action_digest = request.action.digest()?;
        let workflow_id = WorkflowId::parse(&request.action.intent.nonce)
            .map_err(|_| ServiceError::Projection)?;
        let compiled = compile_statement(
            &request.action.intent,
            &self.dependencies.executed_configuration,
        )?;
        if let Some(existing) = self
            .dependencies
            .lifecycle_store
            .load_postgres_lifecycle(&workflow_id)
            .map_err(ServiceError::Lifecycle)?
        {
            return self
                .resume_or_replay(
                    decision,
                    authorized,
                    request.evidence,
                    compiled,
                    existing,
                    now,
                )
                .await;
        }

        let projection = PostgresLifecycleProjectionInput {
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
            .into_decision_input(&PostgresLifecycleDecisionBindings {
                core_authorization_digest: &core_authorization_digest(&authorized),
                decision_receipt_digest: &decision_digest,
                implementation_build_digest: &implementation_build_digest(),
                recovery_reference_digest: request.recovery_reference_digest,
                expires_at: request.action.intent.expires_at,
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

        let reserved = lifecycle_transition(
            &self.dependencies.lifecycle_store,
            &workflow_id,
            recorded.record().revision(),
            TransitionCommandV1::Reserve,
            context.clone(),
        )?;
        let compiled_digest = canonical_digest(&compiled)?;
        let evidence_digest = request.evidence.digest()?;
        let execution_intent = ExecutionIntentV1::new(
            commitment(&action_digest)?,
            ProviderRequestDigest::new(digest_bytes(&compiled_digest)?),
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
        let credential_authorization = ExecutionAuthorizationV1::from_durable(&credential_stage)
            .map_err(|_| ServiceError::ClaimState)?;
        let credential = match self
            .dependencies
            .credential_provider
            .credential_after_authorization(&credential_authorization, &request.action)
        {
            Ok(credential) => credential,
            Err(error) => {
                let released = release_lifecycle(
                    &self.dependencies.lifecycle_store,
                    &workflow_id,
                    credential_stage.record().revision(),
                    context,
                    &action_digest,
                    now,
                )?;
                self.append_claim(released.record(), ClaimStage::Failed)?;
                return Err(ServiceError::Port(error));
            }
        };
        self.append_claim(credential_stage.record(), ClaimStage::CredentialAcquired)?;
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
        self.append_claim(call_entry.record(), ClaimStage::TransactionStarted)?;
        let command = VerifiedBoundedUpdateCommand::new(
            authorized,
            request.evidence,
            compiled,
            call_authorization,
        );
        match self
            .dependencies
            .transaction_gateway
            .execute(&command, &credential, now)
            .await
        {
            Ok(result) if validate_result(command.action(), &result).is_ok() => {
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
                let reconciliation_authorization =
                    PostgresReconciliationAuthorizationV1::from_record(unknown.record())
                        .map_err(|_| ServiceError::ClaimState)?;
                let reconciliation = command.into_reconciliation(reconciliation_authorization);
                self.reconcile_unknown(
                    decision,
                    reconciliation,
                    credential,
                    unknown.record(),
                    context,
                    now,
                )
                .await
            }
            Err(error) => {
                let released = release_lifecycle(
                    &self.dependencies.lifecycle_store,
                    &workflow_id,
                    call_entry.record().revision(),
                    context,
                    &action_digest,
                    now,
                )?;
                self.append_claim(released.record(), ClaimStage::Failed)?;
                Err(ServiceError::Port(error))
            }
        }
    }

    async fn resume_or_replay(
        &self,
        decision: DecisionReceipt,
        authorized: Authorized<PostgresUpdateCommand>,
        evidence: PostgresEvidenceV1,
        compiled: CompiledBoundedUpdate,
        existing: LifecycleRecordV1,
        now: u64,
    ) -> Result<WorkflowOutcome, ServiceError> {
        let action_digest = authorized.command().action().digest()?;
        if existing.decision_input().commitments.exact_action_digest()
            != commitment(&action_digest)?
        {
            return Ok(WorkflowOutcome::Conflict {
                record: ClaimRecord::replay(&existing).map_err(|_| ServiceError::ClaimState)?,
            });
        }
        if existing.state() != LifecycleState::OutcomeUnknown {
            return Ok(WorkflowOutcome::Replay {
                record: ClaimRecord::replay(&existing).map_err(|_| ServiceError::ClaimState)?,
            });
        }
        let authorization = PostgresReconciliationAuthorizationV1::from_record(&existing)
            .map_err(|_| ServiceError::ClaimState)?;
        let credential = self
            .dependencies
            .credential_provider
            .reconciliation_credential(&authorization, authorized.command().action())?;
        let command = VerifiedPostgresReconciliationCommand::new(
            authorized,
            evidence,
            compiled,
            authorization,
        );
        let context = context_from_record(&existing, now)?;
        self.reconcile_unknown(decision, command, credential, &existing, context, now)
            .await
    }

    async fn reconcile_unknown(
        &self,
        decision: DecisionReceipt,
        command: VerifiedPostgresReconciliationCommand,
        credential: PostgresCredential,
        unknown: &LifecycleRecordV1,
        context: TransitionContextV1,
        now: u64,
    ) -> Result<WorkflowOutcome, ServiceError> {
        match self
            .dependencies
            .transaction_gateway
            .reconcile(&command, &credential)
            .await?
        {
            Reconciliation::Committed(mut result)
                if validate_result(command.action(), &result).is_ok() =>
            {
                result.reconciled = true;
                self.finish_reconciled(decision, command.action(), result, unknown, context, now)
            }
            Reconciliation::Committed(_) | Reconciliation::Unavailable => {
                Ok(WorkflowOutcome::OutcomeUnknown {
                    record: ClaimRecord::from_lifecycle(unknown, ClaimStage::OutcomeUnknown)
                        .map_err(|_| ServiceError::ClaimState)?,
                })
            }
            Reconciliation::NotCommitted => {
                let reconciled = reconcile_lifecycle(
                    &self.dependencies.lifecycle_store,
                    unknown,
                    context,
                    EffectConclusion::NonEffect,
                    &canonical_digest(&("postgresql-ledger-not-committed", now))?,
                    &canonical_digest(&("postgresql-ledger-not-committed", now))?,
                    now,
                )?;
                self.append_claim(reconciled.record(), ClaimStage::Failed)?;
                Err(ServiceError::NotCommitted)
            }
        }
    }

    fn finish_committed(
        &self,
        decision: DecisionReceipt,
        action: &PostgresBoundedUpdateV1,
        result: TransactionResult,
        call_entry: &DurableTransitionV1,
        context: TransitionContextV1,
    ) -> Result<WorkflowOutcome, ServiceError> {
        let transaction = transaction_receipt(
            decision.digest()?,
            action,
            call_entry.record().execution_id().as_str(),
            &result,
        )?;
        let observation = observation_receipt(action, &result);
        let transaction_digest = canonical_digest(&transaction)?;
        let result_digest = canonical_digest(&result)?;
        let committed = lifecycle_transition(
            &self.dependencies.lifecycle_store,
            call_entry.record().workflow_id(),
            call_entry.record().revision(),
            TransitionCommandV1::Commit {
                result_digest: ProviderResultDigest::new(digest_bytes(&result_digest)?),
                domain_receipt_digest: DomainReceiptDigest::new(digest_bytes(&transaction_digest)?),
            },
            context,
        )?;
        self.append_claim(committed.record(), ClaimStage::MutationCommitted)?;
        self.append_claim(committed.record(), ClaimStage::Observed)?;
        self.append(&PostgresReceipt::Transaction(Box::new(transaction.clone())))?;
        self.append(&PostgresReceipt::Observation(observation.clone()))?;
        Ok(WorkflowOutcome::Executed {
            decision: Box::new(decision),
            transaction: Box::new(transaction),
            observation,
            result: Box::new(result),
        })
    }

    fn finish_reconciled(
        &self,
        decision: DecisionReceipt,
        action: &PostgresBoundedUpdateV1,
        result: TransactionResult,
        unknown: &LifecycleRecordV1,
        context: TransitionContextV1,
        now: u64,
    ) -> Result<WorkflowOutcome, ServiceError> {
        let transaction = transaction_receipt(
            decision.digest()?,
            action,
            unknown.execution_id().as_str(),
            &result,
        )?;
        let observation = observation_receipt(action, &result);
        let transaction_digest = canonical_digest(&transaction)?;
        let result_digest = canonical_digest(&result)?;
        let reconciled = reconcile_lifecycle(
            &self.dependencies.lifecycle_store,
            unknown,
            context,
            EffectConclusion::Effect,
            &result_digest,
            &transaction_digest,
            now,
        )?;
        if reconciled
            .record()
            .receipts()
            .last()
            .and_then(|receipt| receipt.domain_receipt_digest)
            != Some(DomainReceiptDigest::new(digest_bytes(&transaction_digest)?))
        {
            return Err(ServiceError::ClaimState);
        }
        self.append_claim(reconciled.record(), ClaimStage::Reconciled)?;
        self.append_claim(reconciled.record(), ClaimStage::Observed)?;
        self.append(&PostgresReceipt::Transaction(Box::new(transaction.clone())))?;
        self.append(&PostgresReceipt::Observation(observation.clone()))?;
        Ok(WorkflowOutcome::Executed {
            decision: Box::new(decision),
            transaction: Box::new(transaction),
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
            .load_postgres_lifecycle(workflow_id)
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

    fn append_claim(
        &self,
        record: &LifecycleRecordV1,
        stage: ClaimStage,
    ) -> Result<(), ServiceError> {
        let receipt =
            ClaimRecord::from_lifecycle(record, stage).map_err(|_| ServiceError::ClaimState)?;
        self.append(&PostgresReceipt::Claim(receipt))
    }

    fn append(&self, receipt: &PostgresReceipt) -> Result<(), ServiceError> {
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
    let event = lifecycle_event_digest(b"postgresql-definite-non-effect", action_digest, now);
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
    let event = lifecycle_event_digest(b"postgresql-commit-outcome-unknown", action_digest, now);
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
    conclusion: EffectConclusion,
    result_digest: &DigestHex,
    domain_receipt_digest: &DigestHex,
    now: u64,
) -> Result<DurableTransitionV1, ServiceError> {
    let intent = unknown.execution_intent().ok_or(ServiceError::ClaimState)?;
    let reconciliation_digest =
        lifecycle_event_digest(b"postgresql-ledger-reconciliation", result_digest, now);
    let observation = ReconciliationObservationV1::new(
        ReconciliationId::parse(reconciliation_digest.as_str())
            .map_err(|_| ServiceError::Projection)?,
        EvidenceSourceId::parse(EVIDENCE_SOURCE_ID).map_err(|_| ServiceError::Projection)?,
        VerifierTime::from_unix_seconds(now),
        VerifierTime::from_unix_seconds(
            now.checked_add(300).ok_or(ServiceError::Canonicalization)?,
        ),
        ObservationDigest::new(digest_bytes(result_digest)?),
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
            snapshot_digest: commitment(&canonical_digest(&(
                "auths.postgresql.revocation-not-configured/1",
                record.workflow_id().as_str(),
            ))?)?,
        },
        capacity,
    })
}

fn validate_result(
    action: &PostgresBoundedUpdateV1,
    result: &TransactionResult,
) -> Result<(), ServiceError> {
    if result.affected_rows != action.intent.expected_row_count {
        return Err(ServiceError::Port(PortError::CardinalityMismatch));
    }
    if result.after_state_digest != action.after_state_digest
        || result.readback_commitment != action.after_state_digest
    {
        return Err(ServiceError::Port(PortError::AfterStateMismatch));
    }
    Ok(())
}

fn core_authorization_digest(authorized: &Authorized<PostgresUpdateCommand>) -> DigestHex {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(authorized.verified().proof_digest().as_bytes());
    bytes.extend_from_slice(authorized.verified().context_digest().as_bytes());
    crate::canonical::sha256(&bytes)
}

fn implementation_build_digest() -> DigestHex {
    crate::canonical::sha256(
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
    crate::canonical::sha256(&bytes)
}

fn canonical_digest<T: serde::Serialize>(value: &T) -> Result<DigestHex, ServiceError> {
    crate::canonical::canonical_digest(value).map_err(|_| ServiceError::Canonicalization)
}

fn digest_bytes(value: &DigestHex) -> Result<[u8; 32], ServiceError> {
    hex::decode(value.as_str())
        .map_err(|_| ServiceError::Canonicalization)?
        .try_into()
        .map_err(|_| ServiceError::Canonicalization)
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
        transaction: Box<TransactionReceipt>,
        observation: ObservationReceipt,
        result: Box<TransactionResult>,
    },
}

/// Closed service failure.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("PostgreSQL canonicalization failed")]
    Canonicalization,
    #[error("PostgreSQL profile failed")]
    Profile,
    #[error("PostgreSQL lifecycle projection failed")]
    Projection,
    #[error("shared lifecycle state failed")]
    ClaimState,
    #[error("shared lifecycle store failed: {0:?}")]
    Lifecycle(StoreError),
    #[error("database outcome is unknown")]
    OutcomeUnknown,
    #[error("ledger proves the transaction did not commit")]
    NotCommitted,
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Port(#[from] PortError),
}
