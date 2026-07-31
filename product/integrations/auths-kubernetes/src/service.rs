//! Linear shared-lifecycle orchestration for one exact Kubernetes rollout.

use std::sync::Arc;

use auths_bounded_policy::{CommitmentDigest, EvidenceSourceId, VerifierTime};
use auths_lifecycle::{
    DomainReceiptDigest, DurableTransitionV1, EffectConclusion, ExecutionAuthorizationV1,
    ExecutionIntentV1, LifecycleRecordV1, LifecycleStore, ObservationDigest,
    ProviderCallAuthorizationV1, ProviderConditionDigest, ProviderContractId,
    ProviderRequestDigest, ProviderResultDigest, ProviderRetryClass, ReconciliationId,
    ReconciliationObservationV1, StoreError, StoreTransactionV1, TransitionCommandV1,
    TransitionContextV1, TransitionDisposition, WorkflowId, execute_store_transaction,
};
use auths_profile_api::ActionProfile as _;
use auths_sdk::{Authorized, RequestContext};

use crate::{
    claim::{ClaimRecord, ClaimStage},
    decision::DecisionClass,
    executor::VerifiedRolloutCommand,
    lifecycle::{
        EVIDENCE_SOURCE_ID, KubernetesLifecycleDecisionBindings,
        KubernetesLifecycleProjectionInput, PROVIDER_CONTRACT_ID,
    },
    ports::{
        Clock, CredentialProvider, KubernetesGateway, PortError, ProofDecision, ProofVerifier,
        ReceiptSink,
    },
    profile::{KubernetesRolloutCommand, KubernetesRolloutProfile},
    receipts::{
        DecisionReceipt, ExecutionReceipt, KubernetesReceipt, decision_receipt, execution_receipt,
    },
    types::{
        DigestHex, KubernetesEvidenceV1, KubernetesRolloutResult, KubernetesVerifierConfiguration,
        KubernetesWorkloadRolloutV1,
    },
};

/// Hostile request plus fresh evidence and an Auths proof.
pub struct ExecuteRolloutRequest {
    pub action: KubernetesWorkloadRolloutV1,
    pub evidence: KubernetesEvidenceV1,
    pub required_configuration: KubernetesVerifierConfiguration,
    pub proof: Vec<u8>,
    pub auths_request: RequestContext,
}

/// Lifecycle store plus the read required for exact replay projection.
pub trait KubernetesLifecycleStore: LifecycleStore + Send + Sync {
    /// Loads one validated immutable shared lifecycle record.
    ///
    /// # Errors
    ///
    /// Returns a closed store error for unavailable or corrupt state.
    fn load_kubernetes_lifecycle(
        &self,
        workflow: &WorkflowId,
    ) -> Result<Option<LifecycleRecordV1>, StoreError>;
}

impl<T: KubernetesLifecycleStore + ?Sized> KubernetesLifecycleStore for Arc<T> {
    fn load_kubernetes_lifecycle(
        &self,
        workflow: &WorkflowId,
    ) -> Result<Option<LifecycleRecordV1>, StoreError> {
        (**self).load_kubernetes_lifecycle(workflow)
    }
}

/// Explicit dependencies keep durable and effect ordering auditable.
pub struct ServiceDependencies<V, C, G, W, R, T> {
    pub proof_verifier: V,
    pub credential_provider: C,
    pub kubernetes_gateway: G,
    pub lifecycle_store: W,
    pub receipt_sink: R,
    pub clock: T,
    pub executed_configuration: KubernetesVerifierConfiguration,
}

/// Complete Kubernetes rollout service.
pub struct RolloutService<V, C, G, W, R, T> {
    dependencies: ServiceDependencies<V, C, G, W, R, T>,
}

impl<V, C, G, W, R, T> RolloutService<V, C, G, W, R, T>
where
    V: ProofVerifier,
    C: CredentialProvider,
    G: KubernetesGateway,
    W: KubernetesLifecycleStore,
    R: ReceiptSink,
    T: Clock,
{
    #[must_use]
    pub const fn new(dependencies: ServiceDependencies<V, C, G, W, R, T>) -> Self {
        Self { dependencies }
    }

    /// Executes one exact rollout through durable shared lifecycle stages.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError`] when trusted verification, persistence,
    /// credentials, canonicalization, provider execution, or reconciliation
    /// cannot be safely classified.
    #[allow(
        clippy::too_many_lines,
        reason = "security-relevant decision, durable stage, credential, provider, and receipt ordering stays linear"
    )]
    pub fn execute(&self, request: ExecuteRolloutRequest) -> Result<WorkflowOutcome, ServiceError> {
        let now = self.dependencies.clock.now()?;
        let mut decision = decision_receipt(
            &request.action,
            &request.evidence,
            &request.required_configuration,
            &self.dependencies.executed_configuration,
            request.auths_request.audience().as_str(),
            now,
        )
        .map_err(|_| ServiceError::Canonicalization)?;
        if decision.decision.class != DecisionClass::Authorized {
            self.append(&KubernetesReceipt::Decision(Box::new(decision.clone())))?;
            return Ok(WorkflowOutcome::Rejected {
                receipt: Box::new(decision),
            });
        }

        let canonical = KubernetesRolloutProfile
            .canonicalize(
                &request
                    .action
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
                if authorized.command().action() != &request.action {
                    return Err(ServiceError::Profile);
                }
                decision.auths_decision = Some("authorized".into());
                decision.auths_code = Some("authorized".into());
                *authorized
            }
            ProofDecision::Denied { code } => {
                decision.auths_decision = Some("denied".into());
                decision.decision = crate::decision::Decision::proof_denied(&code);
                decision.auths_code = Some(code);
                self.append(&KubernetesReceipt::Decision(Box::new(decision.clone())))?;
                return Ok(WorkflowOutcome::Rejected {
                    receipt: Box::new(decision),
                });
            }
            ProofDecision::Indeterminate { code } => {
                decision.auths_decision = Some("indeterminate".into());
                decision.decision = crate::decision::Decision::proof_indeterminate();
                decision.auths_code = Some(code);
                self.append(&KubernetesReceipt::Decision(Box::new(decision.clone())))?;
                return Ok(WorkflowOutcome::Rejected {
                    receipt: Box::new(decision),
                });
            }
        };
        self.append(&KubernetesReceipt::Decision(Box::new(decision.clone())))?;

        let action_digest = request
            .action
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let evidence_digest = request
            .evidence
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let projection = KubernetesLifecycleProjectionInput {
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
        let workflow_id = projection.workflow_id.clone();
        let decision_digest = decision
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let decision_input = projection
            .into_decision_input(&KubernetesLifecycleDecisionBindings {
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
            Err(StoreError::Conflict) => {
                return self.conflict_or_replay(&workflow_id, &action_digest);
            }
            Err(error) => return Err(ServiceError::Lifecycle(error)),
        };
        if recorded.disposition() == TransitionDisposition::ExactReplay {
            return Ok(WorkflowOutcome::Replay {
                record: ClaimRecord::replay(recorded.record())
                    .map_err(|_| ServiceError::ClaimState)?,
            });
        }
        let reserved = lifecycle_transition(
            &self.dependencies.lifecycle_store,
            &workflow_id,
            recorded.record().revision(),
            TransitionCommandV1::Reserve,
            context.clone(),
        )?;
        let execution_intent = ExecutionIntentV1::new(
            commitment(&action_digest)?,
            ProviderRequestDigest::new(digest_bytes(request.action.patch_digest())?),
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
        let call_authorization = ProviderCallAuthorizationV1::from_durable(&call_entry)
            .map_err(|_| ServiceError::ClaimState)?;
        let command = VerifiedRolloutCommand::new(authorized, request.evidence, call_authorization);
        let result =
            match self
                .dependencies
                .kubernetes_gateway
                .apply_and_observe(&command, &credential, now)
            {
                Ok(result) => result,
                Err(PortError::OutcomeUnknown) => {
                    let unknown = mark_unknown_lifecycle(
                        &self.dependencies.lifecycle_store,
                        &workflow_id,
                        call_entry.record().revision(),
                        context.clone(),
                        &action_digest,
                        now,
                    )?;
                    self.append_claim(unknown.record(), ClaimStage::OutcomeUnknown)?;
                    match self
                        .dependencies
                        .kubernetes_gateway
                        .reconcile(&command, &credential, now)
                    {
                        Ok(result) if result_matches_action(command.action(), &result) => {
                            return self.finish_reconciled(
                                decision, &command, result, &unknown, context, now,
                            );
                        }
                        Ok(_) | Err(_) => {
                            return Ok(WorkflowOutcome::OutcomeUnknown {
                                record: ClaimRecord::from_lifecycle(
                                    unknown.record(),
                                    ClaimStage::OutcomeUnknown,
                                )
                                .map_err(|_| ServiceError::ClaimState)?,
                            });
                        }
                    }
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
                    return Err(ServiceError::Port(error));
                }
            };
        if !result_matches_action(command.action(), &result) {
            let unknown = mark_unknown_lifecycle(
                &self.dependencies.lifecycle_store,
                &workflow_id,
                call_entry.record().revision(),
                context,
                &action_digest,
                now,
            )?;
            self.append_claim(unknown.record(), ClaimStage::OutcomeUnknown)?;
            return Ok(WorkflowOutcome::OutcomeUnknown {
                record: ClaimRecord::from_lifecycle(unknown.record(), ClaimStage::OutcomeUnknown)
                    .map_err(|_| ServiceError::ClaimState)?,
            });
        }
        let execution = execution_receipt(decision_digest, command.action(), result.clone())
            .map_err(|_| ServiceError::Canonicalization)?;
        let execution_digest = canonical_digest(&execution)?;
        let result_digest = canonical_digest(&result)?;
        let committed = lifecycle_transition(
            &self.dependencies.lifecycle_store,
            &workflow_id,
            call_entry.record().revision(),
            TransitionCommandV1::Commit {
                result_digest: ProviderResultDigest::new(digest_bytes(&result_digest)?),
                domain_receipt_digest: DomainReceiptDigest::new(digest_bytes(&execution_digest)?),
            },
            context,
        )?;
        self.append_effect_claims(committed.record())?;
        self.append(&KubernetesReceipt::Execution(Box::new(execution.clone())))?;
        Ok(WorkflowOutcome::Executed {
            decision: Box::new(decision),
            execution: Box::new(execution),
            result,
        })
    }

    fn finish_reconciled(
        &self,
        decision: DecisionReceipt,
        command: &VerifiedRolloutCommand,
        result: KubernetesRolloutResult,
        unknown: &DurableTransitionV1,
        context: TransitionContextV1,
        now: u64,
    ) -> Result<WorkflowOutcome, ServiceError> {
        let result_digest = canonical_digest(&result)?;
        let decision_digest = decision
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let execution = execution_receipt(decision_digest, command.action(), result.clone())
            .map_err(|_| ServiceError::Canonicalization)?;
        let execution_digest = canonical_digest(&execution)?;
        let request_digest = command.provider_authorization().provider_request_digest();
        let reconciliation_digest =
            lifecycle_event_digest(b"kubernetes-reconciliation", &result_digest, now);
        let observation = ReconciliationObservationV1::new(
            ReconciliationId::parse(reconciliation_digest.as_str())
                .map_err(|_| ServiceError::Projection)?,
            EvidenceSourceId::parse(EVIDENCE_SOURCE_ID).map_err(|_| ServiceError::Projection)?,
            VerifierTime::from_unix_seconds(now),
            VerifierTime::from_unix_seconds(
                now.checked_add(300).ok_or(ServiceError::Canonicalization)?,
            ),
            ObservationDigest::new(digest_bytes(&result_digest)?),
            EffectConclusion::Effect,
            request_digest,
        );
        let reconciled = lifecycle_transition(
            &self.dependencies.lifecycle_store,
            unknown.record().workflow_id(),
            unknown.record().revision(),
            TransitionCommandV1::Reconcile {
                observation,
                domain_receipt_digest: DomainReceiptDigest::new(digest_bytes(&execution_digest)?),
            },
            context,
        )?;
        self.append_effect_claims(reconciled.record())?;
        self.append(&KubernetesReceipt::Execution(Box::new(execution.clone())))?;
        Ok(WorkflowOutcome::Executed {
            decision: Box::new(decision),
            execution: Box::new(execution),
            result,
        })
    }

    fn conflict_or_replay(
        &self,
        workflow_id: &WorkflowId,
        action_digest: &DigestHex,
    ) -> Result<WorkflowOutcome, ServiceError> {
        let existing = self
            .dependencies
            .lifecycle_store
            .load_kubernetes_lifecycle(workflow_id)
            .map_err(ServiceError::Lifecycle)?
            .ok_or(ServiceError::ClaimState)?;
        let record = ClaimRecord::replay(&existing).map_err(|_| ServiceError::ClaimState)?;
        if existing.decision_input().commitments.exact_action_digest() == commitment(action_digest)?
        {
            Ok(WorkflowOutcome::Replay { record })
        } else {
            Ok(WorkflowOutcome::Conflict { record })
        }
    }

    fn append_effect_claims(&self, record: &LifecycleRecordV1) -> Result<(), ServiceError> {
        for stage in [
            ClaimStage::ApiAccepted,
            ClaimStage::PersistedVerified,
            ClaimStage::RolloutConverged,
        ] {
            self.append_claim(record, stage)?;
        }
        Ok(())
    }

    fn append_claim(
        &self,
        record: &LifecycleRecordV1,
        stage: ClaimStage,
    ) -> Result<(), ServiceError> {
        let receipt =
            ClaimRecord::from_lifecycle(record, stage).map_err(|_| ServiceError::ClaimState)?;
        self.append(&KubernetesReceipt::Claim(receipt))
    }

    fn append(&self, receipt: &KubernetesReceipt) -> Result<(), ServiceError> {
        self.dependencies
            .receipt_sink
            .append(receipt)
            .map_err(ServiceError::Port)
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
    let event = lifecycle_event_digest(b"kubernetes-definite-non-effect", action_digest, now);
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
    let event = lifecycle_event_digest(b"kubernetes-provider-outcome-unknown", action_digest, now);
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

fn core_authorization_digest(authorized: &Authorized<KubernetesRolloutCommand>) -> DigestHex {
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

fn result_matches_action(
    action: &KubernetesWorkloadRolloutV1,
    result: &KubernetesRolloutResult,
) -> bool {
    &result.resource_uid == action.resource_uid()
        && result.image == action.projection().requested_image_digest
        && result.requested_replicas == action.projection().requested_replicas
        && result.api_accepted
        && result.persisted_verified
        && result.rollout_converged
        && result.observed_generation >= result.generation
        && result.updated_replicas == result.requested_replicas
        && result.available_replicas == result.requested_replicas
}

/// Complete service outcome.
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
        execution: Box<ExecutionReceipt>,
        result: KubernetesRolloutResult,
    },
}

/// Closed orchestration failure.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("Kubernetes rollout canonicalization failed")]
    Canonicalization,
    #[error("Kubernetes rollout profile failed")]
    Profile,
    #[error("Kubernetes lifecycle projection failed")]
    Projection,
    #[error("Kubernetes lifecycle state failed")]
    ClaimState,
    #[error("shared lifecycle store failed: {0:?}")]
    Lifecycle(StoreError),
    #[error(transparent)]
    Port(#[from] PortError),
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use auths_lifecycle::{LifecycleStore, StoredTransitionV1};
    use auths_model::CanonicalAction;

    use super::*;
    use crate::{
        FixedClock, MemoryReceiptSink,
        decision::DecisionCode,
        lifecycle::reservation_scope_digest,
        ports::KubernetesCredential,
        test_support::{NOW, fixture},
    };

    struct TestStore {
        inner: auths_stores::InMemoryLifecycleStore,
    }

    impl TestStore {
        fn new() -> Self {
            let fixture = fixture();
            let scope = reservation_scope_digest(
                fixture.action.cluster_audience(),
                fixture.action.namespace_name(),
                fixture.action.resource_name(),
            )
            .unwrap();
            Self {
                inner: auths_stores::InMemoryLifecycleStore::new(
                    vec![auths_stores::LifecycleCapacityRuleV1::Exclusive {
                        scope_digest: scope,
                        window_digest: None,
                        retain_after_commit: false,
                    }],
                    128,
                )
                .unwrap(),
            }
        }
    }

    impl LifecycleStore for TestStore {
        fn transact(
            &self,
            transaction: &StoreTransactionV1,
        ) -> Result<StoredTransitionV1, StoreError> {
            self.inner.transact(transaction)
        }
    }

    impl KubernetesLifecycleStore for TestStore {
        fn load_kubernetes_lifecycle(
            &self,
            workflow: &WorkflowId,
        ) -> Result<Option<LifecycleRecordV1>, StoreError> {
            self.inner.load(workflow)
        }
    }

    struct ForbiddenEffects {
        calls: Arc<AtomicUsize>,
    }

    impl ForbiddenEffects {
        fn called<T>(&self) -> Result<T, PortError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(PortError::Execution)
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

    impl CredentialProvider for ForbiddenEffects {
        fn credential_after_authorization(
            &self,
            _: &ExecutionAuthorizationV1,
            _: &KubernetesWorkloadRolloutV1,
        ) -> Result<KubernetesCredential, PortError> {
            self.called()
        }
    }

    impl KubernetesGateway for ForbiddenEffects {
        fn apply_and_observe(
            &self,
            _: &VerifiedRolloutCommand,
            _: &KubernetesCredential,
            _: u64,
        ) -> Result<KubernetesRolloutResult, PortError> {
            self.called()
        }

        fn reconcile(
            &self,
            _: &VerifiedRolloutCommand,
            _: &KubernetesCredential,
            _: u64,
        ) -> Result<KubernetesRolloutResult, PortError> {
            self.called()
        }
    }

    #[test]
    fn configuration_mismatch_never_verifies_persists_or_reads_credential() {
        let fixture = fixture();
        let executed = fixture.configuration_with_maximum_replicas(4);
        let calls = Arc::new(AtomicUsize::new(0));
        let store = TestStore::new();
        let service = RolloutService::new(ServiceDependencies {
            proof_verifier: ForbiddenEffects {
                calls: Arc::clone(&calls),
            },
            credential_provider: ForbiddenEffects {
                calls: Arc::clone(&calls),
            },
            kubernetes_gateway: ForbiddenEffects {
                calls: Arc::clone(&calls),
            },
            lifecycle_store: store,
            receipt_sink: MemoryReceiptSink::default(),
            clock: FixedClock(NOW),
            executed_configuration: executed.clone(),
        });
        let workflow = WorkflowId::parse(fixture.action.workflow_id()).unwrap();
        let request = ExecuteRolloutRequest {
            action: fixture.action,
            evidence: fixture.evidence,
            required_configuration: fixture.configuration.clone(),
            proof: Vec::new(),
            auths_request: RequestContext::new(
                fixture.configuration.executor_audience(),
                [0x44; 32],
                NOW,
            )
            .unwrap(),
        };

        let outcome = service.execute(request).unwrap();

        let WorkflowOutcome::Rejected { receipt } = outcome else {
            panic!("configuration mismatch must reject")
        };
        assert_eq!(
            receipt.decision.code,
            DecisionCode::VerifierConfigurationMismatch
        );
        assert_eq!(receipt.required_configuration, fixture.configuration);
        assert_eq!(receipt.executed_configuration, executed);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(
            service
                .dependencies
                .lifecycle_store
                .load_kubernetes_lifecycle(&workflow)
                .unwrap()
                .is_none()
        );
    }
}
