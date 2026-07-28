//! Linear verify-claim-credential-apply-observe orchestration.

use auths_profile_api::ActionProfile as _;
use auths_sdk::RequestContext;

use crate::{
    claim::{ClaimRecord, ClaimResult, ClaimStage, ClaimStore},
    decision::DecisionClass,
    executor::VerifiedRolloutCommand,
    ports::{
        Clock, CredentialProvider, KubernetesGateway, PortError, ProofDecision, ProofVerifier,
        ReceiptSink,
    },
    profile::KubernetesRolloutProfile,
    receipts::{
        DecisionReceipt, ExecutionReceipt, KubernetesReceipt, decision_receipt, execution_receipt,
    },
    types::{
        KubernetesEvidenceV1, KubernetesRolloutResult, KubernetesVerifierConfiguration,
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

/// Explicit dependencies keep credential ordering auditable.
pub struct ServiceDependencies<V, C, G, W, R, T> {
    pub proof_verifier: V,
    pub credential_provider: C,
    pub kubernetes_gateway: G,
    pub claim_store: W,
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
    W: ClaimStore,
    R: ReceiptSink,
    T: Clock,
{
    #[must_use]
    pub const fn new(dependencies: ServiceDependencies<V, C, G, W, R, T>) -> Self {
        Self { dependencies }
    }

    /// Executes one exact rollout. No credential is requested before claim.
    #[allow(
        clippy::too_many_lines,
        reason = "security-relevant ordering remains intentionally linear"
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
        let lease = match self.dependencies.claim_store.claim(
            request.action.workflow_id(),
            &action_digest,
            now,
        ) {
            ClaimResult::Claimed(lease) => lease,
            ClaimResult::Replay(record) => return Ok(WorkflowOutcome::Replay { record }),
            ClaimResult::Conflict(record) => return Ok(WorkflowOutcome::Conflict { record }),
            ClaimResult::Unavailable => return Err(ServiceError::ClaimState),
        };

        let credential = self
            .dependencies
            .credential_provider
            .mutation_credential(&request.action)
            .map_err(ServiceError::Port)?;
        self.record(&lease, ClaimStage::CredentialAcquired, now)?;
        let command = VerifiedRolloutCommand::new(authorized, request.evidence, lease);
        let result =
            match self
                .dependencies
                .kubernetes_gateway
                .apply_and_observe(&command, &credential, now)
            {
                Ok(result) => result,
                Err(PortError::OutcomeUnknown) => {
                    self.record(command.lease(), ClaimStage::OutcomeUnknown, now)?;
                    match self
                        .dependencies
                        .kubernetes_gateway
                        .reconcile(&command, &credential, now)
                    {
                        Ok(result) => result,
                        Err(_) => return Err(ServiceError::OutcomeUnknown),
                    }
                }
                Err(error) => {
                    self.record(command.lease(), ClaimStage::Failed, now)?;
                    return Err(ServiceError::Port(error));
                }
            };
        validate_result(command.action(), &result)?;
        self.record(command.lease(), ClaimStage::ApiAccepted, now)?;
        self.record(command.lease(), ClaimStage::PersistedVerified, now)?;
        self.record(command.lease(), ClaimStage::RolloutConverged, now)?;
        let execution = execution_receipt(
            decision
                .digest()
                .map_err(|_| ServiceError::Canonicalization)?,
            command.action(),
            result.clone(),
        )
        .map_err(|_| ServiceError::Canonicalization)?;
        self.append(&KubernetesReceipt::Execution(Box::new(execution.clone())))?;
        Ok(WorkflowOutcome::Executed {
            decision: Box::new(decision),
            execution: Box::new(execution),
            result,
        })
    }

    fn append(&self, receipt: &KubernetesReceipt) -> Result<(), ServiceError> {
        self.dependencies
            .receipt_sink
            .append(receipt)
            .map_err(ServiceError::Port)
    }

    fn record(
        &self,
        lease: &crate::claim::ClaimLease,
        stage: ClaimStage,
        now: u64,
    ) -> Result<(), ServiceError> {
        let record = self
            .dependencies
            .claim_store
            .record_stage(lease, stage, now)
            .map_err(|_| ServiceError::ClaimState)?;
        self.append(&KubernetesReceipt::Claim(record))
    }
}

fn validate_result(
    action: &KubernetesWorkloadRolloutV1,
    result: &KubernetesRolloutResult,
) -> Result<(), ServiceError> {
    if &result.resource_uid != action.resource_uid()
        || result.image != action.projection().requested_image_digest
        || result.requested_replicas != action.projection().requested_replicas
        || !result.api_accepted
        || !result.persisted_verified
        || !result.rollout_converged
        || result.observed_generation < result.generation
        || result.updated_replicas != result.requested_replicas
        || result.available_replicas != result.requested_replicas
    {
        return Err(ServiceError::ProviderMismatch);
    }
    Ok(())
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
    #[error("Kubernetes claim state failed")]
    ClaimState,
    #[error("Kubernetes outcome is unknown and could not be reconciled")]
    OutcomeUnknown,
    #[error("Kubernetes returned state outside the authorized projection")]
    ProviderMismatch,
    #[error(transparent)]
    Port(#[from] PortError),
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use auths_model::CanonicalAction;

    use super::*;
    use crate::{
        FixedClock, MemoryClaimStore, MemoryReceiptSink,
        decision::DecisionCode,
        ports::KubernetesCredential,
        test_support::{NOW, fixture},
    };

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
        fn mutation_credential(
            &self,
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
    fn configuration_mismatch_never_verifies_claims_or_reads_mutation_credential() {
        let fixture = fixture();
        let executed = fixture.configuration_with_maximum_replicas(4);
        let calls = Arc::new(AtomicUsize::new(0));
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
            claim_store: MemoryClaimStore::default(),
            receipt_sink: MemoryReceiptSink::default(),
            clock: FixedClock(NOW),
            executed_configuration: executed.clone(),
        });
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
    }
}
