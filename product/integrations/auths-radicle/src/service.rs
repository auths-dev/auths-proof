//! End-to-end orchestration for exact Radicle issue patch workflows.

use auths_profile_api::ActionProfile as _;
use auths_sdk::RequestContext;

use crate::{
    canonical::sha256,
    containment::{DecisionClass, EvaluationContext, evaluate},
    executor::VerifiedOpenPatchCommand,
    ports::{
        CandidateInspector, Clock, EvidenceSource, PortError, ProofDecision, ProofVerifier,
        PropagationObserver, RadicleWriter, ReceiptSink,
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
    workflow::{ClaimResult, WorkflowRecord, WorkflowStage, WorkflowStore},
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
    /// Durable at-most-once workflow state.
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
    W: WorkflowStore,
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
        let lease =
            match self
                .dependencies
                .workflow_store
                .claim(action.workflow_id(), &action_digest, now)
            {
                ClaimResult::Claimed(lease) => lease,
                ClaimResult::Replay(record) => return Ok(WorkflowOutcome::Replay { record }),
                ClaimResult::Conflict(record) => {
                    return Ok(WorkflowOutcome::Conflict { record });
                }
                ClaimResult::Unavailable => return Err(ServiceError::WorkflowState),
            };
        let command = VerifiedOpenPatchCommand::new(
            authorized,
            candidate,
            request.candidate,
            evidence,
            lease,
        );
        let (publication, lease) = self.dependencies.radicle_writer.open_patch(command, now)?;
        let execution = RadicleExecutionReceipt::new(
            self.dependencies.executed_configuration.receipt_schema(),
            decision_digest,
            &lease,
            publication.clone(),
        );
        self.dependencies
            .receipt_sink
            .append(&RadicleReceipt::Execution(Box::new(execution.clone())))?;
        self.dependencies
            .workflow_store
            .record_stored(&lease, &publication.patch_id, &publication.revision_id, now)
            .map_err(|_| ServiceError::WorkflowState)?;

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
        self.dependencies
            .workflow_store
            .advance(&lease, WorkflowStage::Announced, now)
            .map_err(|_| ServiceError::WorkflowState)?;
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
        self.dependencies
            .workflow_store
            .advance(&lease, WorkflowStage::Replicated, now)
            .map_err(|_| ServiceError::WorkflowState)?;
        Ok(WorkflowOutcome::Executed {
            stage: WorkflowStage::Replicated,
            decision: Box::new(decision),
            execution: Box::new(execution),
            propagation: Some(Box::new(propagation)),
        })
    }

    fn append_decision(&self, decision: &RadicleDecisionReceipt) -> Result<(), ServiceError> {
        self.dependencies
            .receipt_sink
            .append(&RadicleReceipt::Decision(Box::new(decision.clone())))
            .map_err(ServiceError::from)
    }
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
        workflow::{ExecutionLease, InMemoryWorkflowStore},
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
        ) -> Result<(LocalPublication, ExecutionLease), PortError> {
            self.called()
        }

        fn announce(&self, _: &LocalPublication) -> Result<(), PortError> {
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
            workflow_store: InMemoryWorkflowStore::default(),
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
