//! End-to-end exact-refund orchestration.

use auths_profile_api::ActionProfile as _;
use auths_sdk::RequestContext;

use crate::{
    canonical::{canonical_digest, sha256},
    claim::{ClaimRecord, ClaimResult, ClaimStage, ClaimStore},
    decision::{Decision, DecisionClass, DecisionCode, EvaluationContext, evaluate},
    executor::VerifiedRefundCommand,
    ports::{
        Clock, CredentialProvider, PortError, ProofDecision, ProofVerifier, ReceiptSink,
        StripeGateway,
    },
    profile::StripeRefundProfile,
    receipts::{DecisionReceipt, ExecutionReceipt, StripeReceipt, execution_receipt},
    types::{
        DigestHex, ExactRefundActionV1, RefundEvidenceV1, RefundResult, StripeVerifierConfiguration,
    },
};

/// Hostile request plus fresh evidence and an Auths proof.
pub struct ExecuteRefundRequest {
    /// Exact action proposed for execution.
    pub action: ExactRefundActionV1,
    /// Fresh protected Stripe read evidence.
    pub evidence: RefundEvidenceV1,
    /// Configuration demanded by the relying party and proof.
    pub required_configuration: StripeVerifierConfiguration,
    /// Auths proof bundle.
    pub proof: Vec<u8>,
    /// Exact Auths audience, challenge, and time.
    pub auths_request: RequestContext,
}

/// Explicit effect dependencies keep credential ordering auditable.
pub struct ServiceDependencies<V, C, G, W, R, T> {
    /// Auths kernel adapter.
    pub proof_verifier: V,
    /// Mutation credential broker.
    pub credential_provider: C,
    /// Only Stripe write adapter.
    pub stripe_gateway: G,
    /// Durable at-most-once state.
    pub claim_store: W,
    /// Append-only receipt sink.
    pub receipt_sink: R,
    /// Trusted clock.
    pub clock: T,
    /// Configuration actually loaded.
    pub executed_configuration: StripeVerifierConfiguration,
}

/// Complete vertical exact-refund service.
pub struct RefundService<V, C, G, W, R, T> {
    dependencies: ServiceDependencies<V, C, G, W, R, T>,
}

impl<V, C, G, W, R, T> RefundService<V, C, G, W, R, T>
where
    V: ProofVerifier,
    C: CredentialProvider,
    G: StripeGateway,
    W: ClaimStore,
    R: ReceiptSink,
    T: Clock,
{
    /// Constructs the service from explicit trusted dependencies.
    #[must_use]
    pub const fn new(dependencies: ServiceDependencies<V, C, G, W, R, T>) -> Self {
        Self { dependencies }
    }

    /// Authorizes, claims, obtains a credential, and creates one exact refund.
    ///
    /// No mutation credential is requested before both product and Auths
    /// authorization succeed and the exact action is durably claimed.
    ///
    /// # Errors
    ///
    /// Returns a typed integration failure. An ambiguous provider outcome is
    /// durably marked for reconciliation and is never blindly retried here.
    #[allow(
        clippy::too_many_lines,
        reason = "security-relevant proof, claim, credential, and effect ordering stays linear"
    )]
    pub fn execute(&self, request: ExecuteRefundRequest) -> Result<WorkflowOutcome, ServiceError> {
        let now = self.dependencies.clock.now()?;
        let product_decision = evaluate(&EvaluationContext {
            action: &request.action,
            evidence: &request.evidence,
            required_configuration: &request.required_configuration,
            executed_configuration: &self.dependencies.executed_configuration,
            request_audience: request.auths_request.audience().as_str(),
            now,
        });
        let action_digest = request
            .action
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let evidence_digest = request
            .evidence
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let mut decision = DecisionReceipt {
            schema: self
                .dependencies
                .executed_configuration
                .receipt_schema_version()
                .into(),
            workflow_id: request.action.workflow_id().into(),
            action_digest: Some(action_digest.clone()),
            evidence_digest,
            required_configuration: request.required_configuration.clone(),
            executed_configuration: self.dependencies.executed_configuration.clone(),
            product_decision: product_decision.clone(),
            auths_decision: None,
            auths_code: None,
            decided_at: now,
        };
        if product_decision.class != DecisionClass::Authorized {
            self.append(&StripeReceipt::Decision(Box::new(decision.clone())))?;
            return Ok(WorkflowOutcome::Rejected {
                receipt: Box::new(decision),
            });
        }

        let canonical = StripeRefundProfile
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
                decision.auths_code = Some(code);
                self.append(&StripeReceipt::Decision(Box::new(decision.clone())))?;
                return Ok(WorkflowOutcome::Rejected {
                    receipt: Box::new(decision),
                });
            }
            ProofDecision::Indeterminate { code } => {
                decision.auths_decision = Some("indeterminate".into());
                decision.auths_code = Some(code);
                self.append(&StripeReceipt::Decision(Box::new(decision.clone())))?;
                return Ok(WorkflowOutcome::Rejected {
                    receipt: Box::new(decision),
                });
            }
        };
        self.append(&StripeReceipt::Decision(Box::new(decision.clone())))?;
        let decision_digest = decision
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

        let credential = match self
            .dependencies
            .credential_provider
            .mutation_credential(request.action.stripe_account_id())
        {
            Ok(credential) => credential,
            Err(error) => {
                self.dependencies
                    .claim_store
                    .record_stage(&lease, ClaimStage::Failed, now)
                    .map_err(|_| ServiceError::ClaimState)?;
                return Err(ServiceError::Port(error));
            }
        };
        let command = VerifiedRefundCommand::new(authorized, request.evidence, lease);
        let result =
            match self
                .dependencies
                .stripe_gateway
                .create_refund(&command, &credential, now)
            {
                Ok(result) => result,
                Err(PortError::OutcomeUnknown) => {
                    self.dependencies
                        .claim_store
                        .record_stage(command.lease(), ClaimStage::OutcomeUnknown, now)
                        .map_err(|_| ServiceError::ClaimState)?;
                    return Err(ServiceError::OutcomeUnknown);
                }
                Err(error) => {
                    self.dependencies
                        .claim_store
                        .record_stage(command.lease(), ClaimStage::Failed, now)
                        .map_err(|_| ServiceError::ClaimState)?;
                    return Err(ServiceError::Port(error));
                }
            };
        validate_provider_result(command.action(), &result)?;
        let result_digest =
            canonical_digest(&result).map_err(|_| ServiceError::Canonicalization)?;
        self.dependencies
            .claim_store
            .record_provider_result(command.lease(), &result.refund_id, &result_digest, now)
            .map_err(|_| ServiceError::ClaimState)?;
        let execution = execution_receipt(
            self.dependencies
                .executed_configuration
                .receipt_schema_version(),
            decision_digest,
            command.action(),
            &result,
        )
        .map_err(|_| ServiceError::Canonicalization)?;
        self.append(&StripeReceipt::Execution(Box::new(execution.clone())))?;
        Ok(WorkflowOutcome::Executed {
            decision: Box::new(decision),
            execution: Box::new(execution),
            result,
        })
    }

    fn append(&self, receipt: &StripeReceipt) -> Result<(), ServiceError> {
        self.dependencies
            .receipt_sink
            .append(receipt)
            .map_err(ServiceError::from)
    }
}

fn validate_provider_result(
    action: &ExactRefundActionV1,
    result: &RefundResult,
) -> Result<(), ServiceError> {
    result
        .validate()
        .map_err(|_| ServiceError::ProviderMismatch)?;
    if result.charge_id != *action.charge_id()
        || result.payment_intent_id.as_ref() != action.payment_intent_id()
        || result.amount != *action.amount()
    {
        return Err(ServiceError::ProviderMismatch);
    }
    Ok(())
}

/// Complete workflow outcome.
pub enum WorkflowOutcome {
    /// Product or Auths authorization rejected before claim/credential.
    Rejected {
        /// Durable decision receipt.
        receipt: Box<DecisionReceipt>,
    },
    /// Exact action was already claimed.
    Replay {
        /// Existing claim.
        record: ClaimRecord,
    },
    /// Workflow ID is bound to different action bytes.
    Conflict {
        /// Existing claim.
        record: ClaimRecord,
    },
    /// Stripe created the exact refund.
    Executed {
        /// Authority receipt.
        decision: Box<DecisionReceipt>,
        /// Provider execution receipt.
        execution: Box<ExecutionReceipt>,
        /// Normalized provider result.
        result: RefundResult,
    },
}

/// Closed service failure.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// Effect adapter failed.
    #[error("exact-refund adapter failed: {0}")]
    Port(#[from] PortError),
    /// Exact value could not be canonicalized.
    #[error("could not canonicalize exact-refund state")]
    Canonicalization,
    /// Auths profile meaning differed.
    #[error("exact refund did not satisfy its Auths profile")]
    Profile,
    /// Durable claim state failed.
    #[error("durable refund claim state is unavailable")]
    ClaimState,
    /// Stripe output differed from the exact action.
    #[error("Stripe response did not match the exact refund")]
    ProviderMismatch,
    /// Provider may have accepted the request.
    #[error("Stripe request outcome is unknown and requires reconciliation")]
    OutcomeUnknown,
}

/// Produces a stable preflight configuration decision.
#[must_use]
pub fn configuration_decision(
    required: &StripeVerifierConfiguration,
    executed: &StripeVerifierConfiguration,
) -> Decision {
    if required.validate().is_err() || executed.validate().is_err() {
        return Decision {
            class: DecisionClass::Denied,
            code: DecisionCode::InvalidInput,
            detail: "verifier configuration is invalid".into(),
        };
    }
    if required != executed {
        return Decision {
            class: DecisionClass::Denied,
            code: DecisionCode::VerifierConfigurationMismatch,
            detail: "required and executed verifier configurations differ".into(),
        };
    }
    Decision {
        class: DecisionClass::Authorized,
        code: DecisionCode::Authorized,
        detail: "verifier configurations match".into(),
    }
}

/// Returns the public commitment for a Stripe identifier.
#[must_use]
pub fn identifier_commitment(value: &str) -> DigestHex {
    sha256(value.as_bytes())
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use auths_model::CanonicalAction;

    use super::*;
    use crate::{
        InMemoryClaimStore,
        ports::{StripeCredential, StripeGateway},
        test_support::{NOW, action, configuration, evidence},
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
            _: &crate::types::StripeAccountId,
        ) -> Result<StripeCredential, PortError> {
            self.called()
        }
    }

    impl StripeGateway for ForbiddenEffects {
        fn create_refund(
            &self,
            _: &VerifiedRefundCommand,
            _: &StripeCredential,
            _: u64,
        ) -> Result<RefundResult, PortError> {
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
    struct CapturingReceipts(Mutex<Vec<StripeReceipt>>);

    impl ReceiptSink for CapturingReceipts {
        fn append(&self, receipt: &StripeReceipt) -> Result<(), PortError> {
            self.0
                .lock()
                .map_err(|_| PortError::Persistence)?
                .push(receipt.clone());
            Ok(())
        }
    }

    #[test]
    fn configuration_mismatch_never_reads_mutation_credential() {
        let required = configuration(1_000);
        let executed = configuration(1_001);
        let evidence = evidence(2_000, 0);
        let action = action(&required, &evidence, 1_000);
        let calls = Arc::new(AtomicUsize::new(0));
        let service = RefundService::new(ServiceDependencies {
            proof_verifier: ForbiddenEffects {
                calls: Arc::clone(&calls),
            },
            credential_provider: ForbiddenEffects {
                calls: Arc::clone(&calls),
            },
            stripe_gateway: ForbiddenEffects {
                calls: Arc::clone(&calls),
            },
            claim_store: InMemoryClaimStore::default(),
            receipt_sink: CapturingReceipts::default(),
            clock: FixedClock,
            executed_configuration: executed.clone(),
        });
        let request = ExecuteRefundRequest {
            action,
            evidence,
            required_configuration: required.clone(),
            proof: Vec::new(),
            auths_request: RequestContext::new(required.executor_audience(), [0x44; 32], NOW)
                .unwrap(),
        };

        let outcome = service.execute(request).unwrap();

        let WorkflowOutcome::Rejected { receipt } = outcome else {
            panic!("configuration mismatch must reject")
        };
        assert_eq!(
            receipt.product_decision.code,
            DecisionCode::VerifierConfigurationMismatch
        );
        assert_eq!(receipt.required_configuration, required);
        assert_eq!(receipt.executed_configuration, executed);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
