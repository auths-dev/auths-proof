//! Linear verify-claim-artifact-credential-apply-observe orchestration.

use auths_profile_api::ActionProfile as _;
use auths_sdk::RequestContext;
use subtle::ConstantTimeEq as _;

use crate::{
    action::OpenTofuSavedPlanApplyV1,
    canonical::sha256,
    claim::{ClaimRecord, ClaimResult, ClaimStage, ClaimStore},
    decision::DecisionClass,
    errors::PortError,
    executor::VerifiedSavedPlanCommand,
    observe::validate_apply_result,
    plan_projection::SavedPlanProjectionV1,
    ports::{
        Clock, CredentialProvider, OpenTofuGateway, PlanArtifactStore, ProofDecision,
        ProofVerifier, ReceiptSink,
    },
    profile::OpenTofuSavedPlanProfile,
    receipts::{
        ApplyReceipt, DecisionReceipt, ObservationReceipt, OpenTofuReceipt, apply_receipt,
        decision_receipt, observation_receipt,
    },
    types::{OpenTofuApplyResult, OpenTofuStateEvidenceV1, OpenTofuVerifierConfigurationV1},
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

/// Explicit dependencies keep security-relevant ordering auditable.
pub struct ServiceDependencies<V, A, C, G, W, R, T> {
    pub proof_verifier: V,
    pub artifact_store: A,
    pub credential_provider: C,
    pub opentofu_gateway: G,
    pub claim_store: W,
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
    W: ClaimStore,
    R: ReceiptSink,
    T: Clock,
{
    #[must_use]
    pub const fn new(dependencies: ServiceDependencies<V, A, C, G, W, R, T>) -> Self {
        Self { dependencies }
    }

    /// Applies exactly one verified saved plan. Credentials are requested only
    /// after the action has been verified, claimed, and artifact-checked.
    #[allow(
        clippy::too_many_lines,
        reason = "security-relevant ordering remains intentionally linear"
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
        let lease = match self.dependencies.claim_store.claim(&action_digest, now) {
            ClaimResult::Claimed(lease) => lease,
            ClaimResult::Replay(record) => return Ok(WorkflowOutcome::Replay { record }),
            ClaimResult::Conflict(record) => return Ok(WorkflowOutcome::Conflict { record }),
            ClaimResult::Unavailable => return Err(ServiceError::ClaimState),
        };
        self.record(&lease, ClaimStage::Claimed, now)?;

        let artifact = self
            .dependencies
            .artifact_store
            .resolve(request.action.plan_handle())?;
        if !digest_eq(
            &sha256(artifact.bytes()),
            request.action.opaque_plan_digest(),
        ) {
            self.record(&lease, ClaimStage::Failed, now)?;
            return Err(ServiceError::Port(PortError::ArtifactMismatch));
        }
        self.record(&lease, ClaimStage::ArtifactVerified, now)?;

        let credential = self
            .dependencies
            .credential_provider
            .mutation_credential(&request.action)?;
        self.record(&lease, ClaimStage::CredentialAcquired, now)?;
        let command =
            VerifiedSavedPlanCommand::new(authorized, request.projection, request.evidence, lease);
        let current = self
            .dependencies
            .opentofu_gateway
            .recheck_state(&command, &credential)?;
        validate_state_recheck(command.action(), command.planning_evidence(), &current)?;
        self.record(command.lease(), ClaimStage::StateRechecked, now)?;
        self.record(command.lease(), ClaimStage::ApplyStarted, now)?;

        let result = match self.dependencies.opentofu_gateway.apply_saved_plan(
            &command,
            &artifact,
            &credential,
            now,
        ) {
            Ok(result) => result,
            Err(PortError::OutcomeUnknown) => {
                self.record(command.lease(), ClaimStage::OutcomeUnknown, now)?;
                self.dependencies
                    .opentofu_gateway
                    .reconcile(&command, &credential, now)
                    .map_err(|_| ServiceError::OutcomeUnknown)?
            }
            Err(error) => {
                self.record(command.lease(), ClaimStage::Failed, now)?;
                return Err(ServiceError::Port(error));
            }
        };
        validate_apply_result(command.action(), &result)?;
        self.record(command.lease(), ClaimStage::StateCommitted, now)?;
        self.record(command.lease(), ClaimStage::PostconditionsObserved, now)?;
        self.record(command.lease(), ClaimStage::Converged, now)?;
        let apply = apply_receipt(decision.digest()?, command.action(), result.clone())?;
        let observation = observation_receipt(command.action(), &result)?;
        self.append(&OpenTofuReceipt::Apply(Box::new(apply.clone())))?;
        self.append(&OpenTofuReceipt::Observation(observation.clone()))?;
        Ok(WorkflowOutcome::Executed {
            decision: Box::new(decision),
            apply: Box::new(apply),
            observation,
            result: Box::new(result),
        })
    }

    fn append(&self, receipt: &OpenTofuReceipt) -> Result<(), ServiceError> {
        self.dependencies.receipt_sink.append(receipt)?;
        Ok(())
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
        self.append(&OpenTofuReceipt::Claim(record))
    }
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

fn digest_eq(left: &crate::types::DigestHex, right: &crate::types::DigestHex) -> bool {
    bool::from(left.as_str().as_bytes().ct_eq(right.as_str().as_bytes()))
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
    #[error("OpenTofu claim state failed")]
    ClaimState,
    #[error("OpenTofu state changed after planning")]
    StateChanged,
    #[error("OpenTofu outcome is unknown and could not be reconciled")]
    OutcomeUnknown,
    #[error(transparent)]
    Validation(#[from] crate::errors::ValidationError),
    #[error(transparent)]
    Canonical(#[from] crate::errors::CanonicalError),
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
        FixedClock, MemoryClaimStore, MemoryReceiptSink, OpenTofuCredential, PlanHandle,
        SavedPlanArtifact,
        test_support::{NOW, configuration_with_maximum_resource_changes, fixture},
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

    impl PlanArtifactStore for ForbiddenEffects {
        fn put(&self, _: SavedPlanArtifact) -> Result<PlanHandle, PortError> {
            self.called()
        }

        fn resolve(&self, _: &PlanHandle) -> Result<SavedPlanArtifact, PortError> {
            self.called()
        }
    }

    impl CredentialProvider for ForbiddenEffects {
        fn mutation_credential(
            &self,
            _: &OpenTofuSavedPlanApplyV1,
        ) -> Result<OpenTofuCredential, PortError> {
            self.called()
        }
    }

    impl OpenTofuGateway for ForbiddenEffects {
        fn recheck_state(
            &self,
            _: &VerifiedSavedPlanCommand,
            _: &OpenTofuCredential,
        ) -> Result<OpenTofuStateEvidenceV1, PortError> {
            self.called()
        }

        fn apply_saved_plan(
            &self,
            _: &VerifiedSavedPlanCommand,
            _: &SavedPlanArtifact,
            _: &OpenTofuCredential,
            _: u64,
        ) -> Result<OpenTofuApplyResult, PortError> {
            self.called()
        }

        fn reconcile(
            &self,
            _: &VerifiedSavedPlanCommand,
            _: &OpenTofuCredential,
            _: u64,
        ) -> Result<OpenTofuApplyResult, PortError> {
            self.called()
        }
    }

    #[test]
    fn configuration_mismatch_never_verifies_claims_resolves_plan_or_reads_credentials() {
        let fixture = fixture();
        let executed = configuration_with_maximum_resource_changes(5);
        let calls = Arc::new(AtomicUsize::new(0));
        let service = SavedPlanService::new(ServiceDependencies {
            proof_verifier: ForbiddenEffects {
                calls: Arc::clone(&calls),
            },
            artifact_store: ForbiddenEffects {
                calls: Arc::clone(&calls),
            },
            credential_provider: ForbiddenEffects {
                calls: Arc::clone(&calls),
            },
            opentofu_gateway: ForbiddenEffects {
                calls: Arc::clone(&calls),
            },
            claim_store: MemoryClaimStore::default(),
            receipt_sink: MemoryReceiptSink::default(),
            clock: FixedClock(NOW),
            executed_configuration: executed.clone(),
        });
        let request = ExecuteSavedPlanRequest {
            action: fixture.action,
            projection: fixture.projection,
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
            crate::DecisionCode::VerifierConfigurationMismatch
        );
        assert_eq!(receipt.required_configuration, fixture.configuration);
        assert_eq!(receipt.executed_configuration, executed);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
