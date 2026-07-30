//! Protected execution path for one exact refund inside configured bounds.

use auths_profile_api::ActionProfile as _;
use auths_sdk::RequestContext;

use crate::{
    bounded::{
        BoundedDecisionClass, BoundedEvaluationContext, BoundedRefundDecision,
        StripeBoundedEvaluatorConfigurationV1, StripeBoundedRefundPolicyV1,
        evaluate_bounded_refund,
    },
    canonical::{canonical_digest, sha256},
    claim::{ClaimResult, ClaimStage, ClaimStore},
    executor::VerifiedRefundCommand,
    ports::{
        Clock, CredentialProvider, PortError, ProofDecision, ProofVerifier, ReceiptSink,
        RefundCredentialScope, StripeGateway,
    },
    profile::StripeRefundProfile,
    receipts::{
        BoundedDecisionReceipt, BoundedDecisionReceiptInput, ExecutionReceipt, ReservationReceipt,
        StripeReceipt, execution_receipt,
    },
    reservation::{
        RefundReservationRecord, RefundReservationStore, ReserveRefundRequest, ReserveRefundResult,
    },
    service::ServiceError,
    types::{ExactRefundActionV1, RefundEvidenceV1, RefundResult, StripeVerifierConfiguration},
};

/// Hostile exact action plus configured bounded-policy inputs.
pub struct ExecuteBoundedRefundRequest {
    /// Agent-selected exact provider action.
    pub action: ExactRefundActionV1,
    /// Fresh protected Stripe read evidence.
    pub evidence: RefundEvidenceV1,
    /// Immutable executor-configured policy.
    pub policy: StripeBoundedRefundPolicyV1,
    /// Exact-refund configuration required by the action/proof.
    pub required_exact_configuration: StripeVerifierConfiguration,
    /// Bounded evaluator configuration required by the relying party.
    pub required_bounded_configuration: StripeBoundedEvaluatorConfigurationV1,
    /// Auths proof for the exact action.
    pub proof: Vec<u8>,
    /// Exact Auths audience, challenge, and time.
    pub auths_request: RequestContext,
}

/// Explicit dependencies keep policy, persistence, credentials, and effects auditable.
pub struct BoundedServiceDependencies<V, C, G, W, B, R, T> {
    /// Auths kernel adapter.
    pub proof_verifier: V,
    /// Mutation credential broker.
    pub credential_provider: C,
    /// Only Stripe write adapter.
    pub stripe_gateway: G,
    /// Exact-action replay claim.
    pub claim_store: W,
    /// Stripe-local aggregate reservation state.
    pub reservation_store: B,
    /// Append-only receipt sink.
    pub receipt_sink: R,
    /// Trusted clock.
    pub clock: T,
    /// Exact-refund configuration actually loaded.
    pub executed_exact_configuration: StripeVerifierConfiguration,
    /// Bounded evaluator configuration actually loaded.
    pub executed_bounded_configuration: StripeBoundedEvaluatorConfigurationV1,
}

/// Complete bounded Stripe refund service.
pub struct BoundedRefundService<V, C, G, W, B, R, T> {
    dependencies: BoundedServiceDependencies<V, C, G, W, B, R, T>,
}

impl<V, C, G, W, B, R, T> BoundedRefundService<V, C, G, W, B, R, T>
where
    V: ProofVerifier,
    C: CredentialProvider<RefundCredentialScope>,
    G: StripeGateway,
    W: ClaimStore,
    B: RefundReservationStore,
    R: ReceiptSink<StripeReceipt>,
    T: Clock,
{
    /// Constructs the service from explicit trusted dependencies.
    #[must_use]
    pub const fn new(dependencies: BoundedServiceDependencies<V, C, G, W, B, R, T>) -> Self {
        Self { dependencies }
    }

    /// Executes one exact refund only after durable aggregate reservation.
    ///
    /// # Errors
    ///
    /// Returns a typed failure while preserving reservation state according to
    /// whether provider non-execution is known or ambiguous.
    #[allow(
        clippy::too_many_lines,
        reason = "security-relevant decision, receipt, reservation, claim, credential, and provider ordering stays linear"
    )]
    pub fn execute(
        &self,
        request: ExecuteBoundedRefundRequest,
    ) -> Result<BoundedWorkflowOutcome, ServiceError> {
        let now = self.dependencies.clock.now()?;
        let aggregate_before = self
            .dependencies
            .reservation_store
            .snapshot(&request.policy, request.evidence.stripe_account_id(), now)
            .map_err(|_| ServiceError::ClaimState)?;
        let bounded_decision = evaluate_bounded_refund(&BoundedEvaluationContext {
            policy: &request.policy,
            action: &request.action,
            evidence: &request.evidence,
            aggregate_snapshot: &aggregate_before,
            required_exact_configuration: &request.required_exact_configuration,
            executed_exact_configuration: &self.dependencies.executed_exact_configuration,
            required_bounded_configuration: &request.required_bounded_configuration,
            executed_bounded_configuration: &self.dependencies.executed_bounded_configuration,
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
        let policy_digest = request
            .policy
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let mut decision_receipt = BoundedDecisionReceipt::new(BoundedDecisionReceiptInput {
            workflow_id: request.action.workflow_id().into(),
            policy: request.policy.clone(),
            policy_digest: policy_digest.clone(),
            exact_action: request.action.clone(),
            action_digest: action_digest.clone(),
            evidence: request.evidence.clone(),
            evidence_digest: evidence_digest.clone(),
            aggregate_before,
            required_exact_configuration: request.required_exact_configuration.clone(),
            executed_exact_configuration: self.dependencies.executed_exact_configuration.clone(),
            required_bounded_configuration: request.required_bounded_configuration.clone(),
            executed_bounded_configuration: self
                .dependencies
                .executed_bounded_configuration
                .clone(),
            bounded_decision: bounded_decision.clone(),
            decided_at: now,
        });
        if bounded_decision.class != BoundedDecisionClass::Eligible {
            self.append(&StripeReceipt::BoundedDecision(Box::new(
                decision_receipt.clone(),
            )))?;
            return Ok(BoundedWorkflowOutcome::Rejected {
                receipt: Box::new(decision_receipt),
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
                decision_receipt.auths_decision = Some("authorized".into());
                decision_receipt.auths_code = Some("authorized".into());
                *authorized
            }
            ProofDecision::Denied { code } => {
                decision_receipt.auths_decision = Some("denied".into());
                decision_receipt.auths_code = Some(code);
                self.append(&StripeReceipt::BoundedDecision(Box::new(
                    decision_receipt.clone(),
                )))?;
                return Ok(BoundedWorkflowOutcome::Rejected {
                    receipt: Box::new(decision_receipt),
                });
            }
            ProofDecision::Indeterminate { code } => {
                decision_receipt.auths_decision = Some("indeterminate".into());
                decision_receipt.auths_code = Some(code);
                self.append(&StripeReceipt::BoundedDecision(Box::new(
                    decision_receipt.clone(),
                )))?;
                return Ok(BoundedWorkflowOutcome::Rejected {
                    receipt: Box::new(decision_receipt),
                });
            }
        };

        // The decision receipt is durable before aggregate reservation.
        self.append(&StripeReceipt::BoundedDecision(Box::new(
            decision_receipt.clone(),
        )))?;
        let decision_receipt_digest = decision_receipt
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let eligibility = bounded_decision
            .eligibility
            .as_ref()
            .ok_or(ServiceError::Profile)?;
        let required_bounded_digest = request
            .required_bounded_configuration
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let executed_bounded_digest = self
            .dependencies
            .executed_bounded_configuration
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let reservation = self
            .dependencies
            .reservation_store
            .reserve(ReserveRefundRequest {
                workflow_id: request.action.workflow_id().into(),
                action_digest: action_digest.clone(),
                decision_receipt_digest: decision_receipt_digest.clone(),
                policy_digest,
                evaluator_semantic_id: request.policy.evaluator_semantic_id().into(),
                evaluator_semantic_version: request.policy.evaluator_semantic_version(),
                evidence_digest,
                required_configuration_digest: required_bounded_digest,
                executed_configuration_digest: executed_bounded_digest,
                stripe_account_id: request.action.stripe_account_id().clone(),
                currency: request.action.amount().currency().clone(),
                amount_minor: request.action.amount().amount_minor(),
                intents: eligibility.reservations.clone(),
                idempotency_key_digest: sha256(request.action.idempotency_key().as_bytes()),
                now,
            });
        let (reservation_lease, reserved_record) = match reservation {
            ReserveRefundResult::Reserved { lease, record } => (lease, record),
            ReserveRefundResult::Replay(record) => {
                return Ok(BoundedWorkflowOutcome::Replay {
                    reservation: record,
                });
            }
            ReserveRefundResult::Conflict(record) => {
                return Ok(BoundedWorkflowOutcome::Conflict {
                    reservation: record,
                });
            }
            ReserveRefundResult::CapacityExceeded {
                budget_id,
                available_minor,
            } => {
                return Ok(BoundedWorkflowOutcome::CapacityChanged {
                    decision: bounded_decision,
                    budget_id,
                    available_minor,
                });
            }
            ReserveRefundResult::Unavailable => return Err(ServiceError::ClaimState),
        };
        self.append(&StripeReceipt::Reservation(Box::new(ReservationReceipt {
            schema: "auths.stripe.bounded-reservation-receipt/1".into(),
            decision_receipt_digest: decision_receipt_digest.clone(),
            reservation: reserved_record.clone(),
            credential_requested: false,
            stripe_called: false,
            recorded_at: now,
        })))?;

        let claim_lease = match self.dependencies.claim_store.claim(
            request.action.workflow_id(),
            &action_digest,
            now,
        ) {
            ClaimResult::Claimed(lease) => lease,
            ClaimResult::Replay(_) => {
                self.dependencies
                    .reservation_store
                    .release(&reservation_lease, now)
                    .map_err(|_| ServiceError::ClaimState)?;
                return Ok(BoundedWorkflowOutcome::Replay {
                    reservation: reserved_record,
                });
            }
            ClaimResult::Conflict(_) => {
                self.dependencies
                    .reservation_store
                    .release(&reservation_lease, now)
                    .map_err(|_| ServiceError::ClaimState)?;
                return Ok(BoundedWorkflowOutcome::Conflict {
                    reservation: reserved_record,
                });
            }
            ClaimResult::Unavailable => {
                self.dependencies
                    .reservation_store
                    .release(&reservation_lease, now)
                    .map_err(|_| ServiceError::ClaimState)?;
                return Err(ServiceError::ClaimState);
            }
        };

        // Credential acquisition is deliberately after decision persistence,
        // aggregate reservation, and exact-action claim.
        let credential = match self
            .dependencies
            .credential_provider
            .credential(request.action.stripe_account_id())
        {
            Ok(credential) => credential,
            Err(error) => {
                self.dependencies
                    .claim_store
                    .record_stage(&claim_lease, ClaimStage::Failed, now)
                    .map_err(|_| ServiceError::ClaimState)?;
                self.dependencies
                    .reservation_store
                    .release(&reservation_lease, now)
                    .map_err(|_| ServiceError::ClaimState)?;
                return Err(ServiceError::Port(error));
            }
        };
        let command = VerifiedRefundCommand::new(authorized, request.evidence, claim_lease);
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
                    let reservation = self
                        .dependencies
                        .reservation_store
                        .mark_outcome_unknown(&reservation_lease, now)
                        .map_err(|_| ServiceError::ClaimState)?;
                    self.append(&StripeReceipt::Reservation(Box::new(ReservationReceipt {
                        schema: "auths.stripe.bounded-reservation-receipt/1".into(),
                        decision_receipt_digest,
                        reservation: reservation.clone(),
                        credential_requested: true,
                        stripe_called: true,
                        recorded_at: now,
                    })))?;
                    return Ok(BoundedWorkflowOutcome::OutcomeUnknown { reservation });
                }
                Err(error) => {
                    self.dependencies
                        .claim_store
                        .record_stage(command.lease(), ClaimStage::Failed, now)
                        .map_err(|_| ServiceError::ClaimState)?;
                    self.dependencies
                        .reservation_store
                        .release(&reservation_lease, now)
                        .map_err(|_| ServiceError::ClaimState)?;
                    return Err(ServiceError::Port(error));
                }
            };
        if validate_result(command.action(), &result).is_err() {
            self.dependencies
                .claim_store
                .record_stage(command.lease(), ClaimStage::OutcomeUnknown, now)
                .map_err(|_| ServiceError::ClaimState)?;
            let reservation = self
                .dependencies
                .reservation_store
                .mark_outcome_unknown(&reservation_lease, now)
                .map_err(|_| ServiceError::ClaimState)?;
            self.append(&StripeReceipt::Reservation(Box::new(ReservationReceipt {
                schema: "auths.stripe.bounded-reservation-receipt/1".into(),
                decision_receipt_digest,
                reservation: reservation.clone(),
                credential_requested: true,
                stripe_called: true,
                recorded_at: now,
            })))?;
            return Ok(BoundedWorkflowOutcome::OutcomeUnknown { reservation });
        }
        let result_digest =
            canonical_digest(&result).map_err(|_| ServiceError::Canonicalization)?;
        self.dependencies
            .claim_store
            .record_provider_result(command.lease(), &result.refund_id, &result_digest, now)
            .map_err(|_| ServiceError::ClaimState)?;
        let committed = self
            .dependencies
            .reservation_store
            .commit(&reservation_lease, &result.refund_id, &result_digest, now)
            .map_err(|_| ServiceError::ClaimState)?;
        let execution = execution_receipt(
            self.dependencies
                .executed_exact_configuration
                .receipt_schema_version(),
            decision_receipt_digest.clone(),
            command.action(),
            &result,
        )
        .map_err(|_| ServiceError::Canonicalization)?;
        self.append(&StripeReceipt::Execution(Box::new(execution.clone())))?;
        self.append(&StripeReceipt::Reservation(Box::new(ReservationReceipt {
            schema: "auths.stripe.bounded-reservation-receipt/1".into(),
            decision_receipt_digest,
            reservation: committed.clone(),
            credential_requested: true,
            stripe_called: true,
            recorded_at: now,
        })))?;
        Ok(BoundedWorkflowOutcome::Executed {
            decision: Box::new(decision_receipt),
            reservation: committed,
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

fn validate_result(
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

/// Complete bounded workflow result.
pub enum BoundedWorkflowOutcome {
    /// Policy, exact-refund containment, or Auths rejected pre-reservation.
    Rejected {
        /// Durable decision receipt.
        receipt: Box<BoundedDecisionReceipt>,
    },
    /// Same exact reserved action already exists.
    Replay {
        /// Existing reservation and provider state.
        reservation: RefundReservationRecord,
    },
    /// Workflow is bound to different exact inputs.
    Conflict {
        /// Existing reservation.
        reservation: RefundReservationRecord,
    },
    /// Capacity changed between pure evaluation and atomic reservation.
    CapacityChanged {
        /// Pure decision using the earlier snapshot.
        decision: BoundedRefundDecision,
        /// Budget that lost capacity.
        budget_id: String,
        /// Atomic availability.
        available_minor: u64,
    },
    /// Stripe delivery is ambiguous and capacity remains held.
    OutcomeUnknown {
        /// Durable unknown-outcome reservation.
        reservation: RefundReservationRecord,
    },
    /// Stripe created the exact refund and capacity is committed.
    Executed {
        /// Configured-policy and Auths decision.
        decision: Box<BoundedDecisionReceipt>,
        /// Committed aggregate usage.
        reservation: RefundReservationRecord,
        /// Provider receipt.
        execution: Box<ExecutionReceipt>,
        /// Normalized Stripe result.
        result: RefundResult,
    },
}

#[cfg(test)]
mod tests {
    #[test]
    fn credential_acquisition_is_after_reservation() {
        let source = include_str!("bounded_service.rs");
        let reserve = source
            .find(".reservation_store.reserve")
            .expect("bounded service must reserve aggregate capacity");
        let claim = source[reserve..]
            .find(".claim_store.claim")
            .map(|offset| reserve + offset)
            .expect("bounded service must durably claim the exact action");
        let credential = source[claim..]
            .find(".credential(")
            .map(|offset| claim + offset)
            .expect("bounded service must acquire the credential");
        let provider = source[credential..]
            .find(".create_refund")
            .map(|offset| credential + offset)
            .expect("bounded service must call the exact Stripe gateway");
        assert!(reserve < claim && claim < credential && credential < provider);
    }
}
