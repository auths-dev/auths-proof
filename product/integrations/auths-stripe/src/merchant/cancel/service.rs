//! Protected exact-proof-to-Stripe pipeline for one exact payment cancellation.

use auths_profile_api::ActionProfile as _;
use auths_sdk::RequestContext;
use serde::Serialize;

use super::{
    MerchantCancelDecisionReceipt, MerchantCancelObservationReceipt, MerchantCancelReceipt,
    MerchantCancelTransitionReceipt, PaymentCancelDecision, PaymentCancelDecisionClass,
    PaymentCancelDecisionCode, PaymentCancelDecisionStage, PaymentCancelEffect,
    PaymentCancelEvaluationContext, PaymentCancelEvidenceV1, PaymentCancelGateway,
    PaymentCancelProofDecision, PaymentCancelProofVerifier, PaymentCancelProviderProjection,
    PaymentCancelReconciliationOutcome, StripeExactPaymentCancelV1, StripePaymentCancelProfile,
    VerifiedPaymentCancelCommand, evaluate_payment_cancel, merchant_policy_provenance,
};
use crate::{
    canonical::{canonical_digest, sha256},
    merchant::{
        MERCHANT_EVALUATOR_ID, MERCHANT_EVALUATOR_VERSION, MerchantAggregateSnapshot,
        MerchantOperation, MerchantPaymentStore, MerchantReservationLease,
        MerchantReservationRecord, MerchantReservationState, PAYMENT_CANCEL_PROFILE,
        ReserveMerchantPaymentResult, ReservePaymentCancelRequest,
        StripeBoundedMerchantPaymentPolicyV1, StripeMerchantEvaluatorConfigurationV1,
    },
    ports::{
        Clock, CredentialProvider, PaymentCancelCredential, PaymentCancelCredentialScope,
        PortError, ReceiptSink,
    },
    types::DigestHex,
};

/// Hostile exact action plus protected configured inputs.
pub struct ExecutePaymentCancelRequest {
    /// Durable server-selected cancel workflow identity.
    pub workflow_id: String,
    /// Agent-selected exact payment cancellation.
    pub action: StripeExactPaymentCancelV1,
    /// Fresh protected Stripe and durable-authorization evidence.
    pub evidence: PaymentCancelEvidenceV1,
    /// Immutable executor-configured policy.
    pub policy: StripeBoundedMerchantPaymentPolicyV1,
    /// Runtime configuration required by the relying party.
    pub required_configuration: StripeMerchantEvaluatorConfigurationV1,
    /// Exact Auths proof.
    pub proof: Vec<u8>,
    /// Exact audience, challenge, and time.
    pub auths_request: RequestContext,
}

/// Explicit dependencies keep every trust boundary visible.
pub struct PaymentCancelServiceDependencies<V, C, G, S, R, T> {
    /// Auths verifier fixed to the exact payment-cancellation profile.
    pub proof_verifier: V,
    /// Cancel-scoped Stripe credential broker.
    pub credential_provider: C,
    /// Only cancel/retrieve provider surface.
    pub stripe_gateway: G,
    /// Durable merchant reservation, claim, and replay state.
    pub store: S,
    /// Append-only cancel receipt sink.
    pub receipt_sink: R,
    /// Trusted time.
    pub clock: T,
    /// Runtime configuration actually loaded.
    pub executed_configuration: StripeMerchantEvaluatorConfigurationV1,
}

/// Complete bounded one-time payment-cancellation service.
pub struct PaymentCancelService<V, C, G, S, R, T> {
    dependencies: PaymentCancelServiceDependencies<V, C, G, S, R, T>,
}

impl<V, C, G, S, R, T> PaymentCancelService<V, C, G, S, R, T>
where
    V: PaymentCancelProofVerifier,
    C: CredentialProvider<PaymentCancelCredentialScope>,
    G: PaymentCancelGateway,
    S: MerchantPaymentStore,
    R: ReceiptSink<MerchantCancelReceipt>,
    T: Clock,
{
    /// Constructs the protected service.
    #[must_use]
    pub const fn new(dependencies: PaymentCancelServiceDependencies<V, C, G, S, R, T>) -> Self {
        Self { dependencies }
    }

    /// Executes one exact cancellation after proof, decision, reservation, and claim.
    ///
    /// # Errors
    ///
    /// Returns closed integration, persistence, or canonicalization failures.
    /// Ambiguous Stripe delivery remains a durable successful workflow outcome.
    #[allow(
        clippy::too_many_lines,
        reason = "security-relevant ordering stays linear and auditable"
    )]
    pub fn execute(
        &self,
        request: ExecutePaymentCancelRequest,
    ) -> Result<PaymentCancelWorkflowOutcome, MerchantCancelServiceError> {
        let now = self.dependencies.clock.now()?;
        let canonical = StripePaymentCancelProfile
            .canonicalize(
                &request
                    .action
                    .canonical_bytes()
                    .map_err(|_| MerchantCancelServiceError::Canonicalization)?,
            )
            .map_err(|_| MerchantCancelServiceError::Profile)?;
        let proof = self.dependencies.proof_verifier.verify(
            &request.proof,
            &canonical,
            &request.auths_request,
        )?;
        let action_digest = request
            .action
            .digest()
            .map_err(|_| MerchantCancelServiceError::Canonicalization)?;
        let evidence_digest = request
            .evidence
            .digest()
            .map_err(|_| MerchantCancelServiceError::Canonicalization)?;
        let policy_digest = request
            .policy
            .digest()
            .map_err(|_| MerchantCancelServiceError::Canonicalization)?;
        let authorized = match proof {
            PaymentCancelProofDecision::Authorized(authorized) => {
                if authorized.command().action() != &request.action {
                    return Err(MerchantCancelServiceError::Profile);
                }
                authorized
            }
            PaymentCancelProofDecision::Denied { code } => {
                let receipt = self.decision_receipt(
                    &request,
                    policy_digest,
                    action_digest,
                    evidence_digest,
                    MerchantAggregateSnapshot::default(),
                    "denied",
                    code,
                    false,
                    None,
                    now,
                );
                self.append_decision(&receipt)?;
                return Ok(PaymentCancelWorkflowOutcome::Rejected {
                    receipt: Box::new(receipt),
                    persisted: true,
                });
            }
            PaymentCancelProofDecision::Indeterminate { code } => {
                let receipt = self.decision_receipt(
                    &request,
                    policy_digest,
                    action_digest,
                    evidence_digest,
                    MerchantAggregateSnapshot::default(),
                    "indeterminate",
                    code,
                    false,
                    None,
                    now,
                );
                self.append_decision(&receipt)?;
                return Ok(PaymentCancelWorkflowOutcome::Rejected {
                    receipt: Box::new(receipt),
                    persisted: true,
                });
            }
        };

        if request.required_configuration != self.dependencies.executed_configuration {
            let required_configuration_digest = request
                .required_configuration
                .digest()
                .map_err(|_| MerchantCancelServiceError::Canonicalization)?;
            let executed_configuration_digest =
                self.dependencies
                    .executed_configuration
                    .digest()
                    .map_err(|_| MerchantCancelServiceError::Canonicalization)?;
            let bounded = PaymentCancelDecision {
                decision: PaymentCancelDecisionClass::Denied,
                code: PaymentCancelDecisionCode::ConfigurationMismatch
                    .as_str()
                    .into(),
                stage: PaymentCancelDecisionStage::Configuration,
                required_configuration_digest,
                executed_configuration_digest,
                eligibility: None,
            };
            let receipt = self.decision_receipt(
                &request,
                policy_digest,
                action_digest,
                evidence_digest,
                MerchantAggregateSnapshot::default(),
                "authorized",
                "authorized".into(),
                true,
                Some(bounded),
                now,
            );
            return Ok(PaymentCancelWorkflowOutcome::Rejected {
                receipt: Box::new(receipt),
                persisted: false,
            });
        }

        // Resolve exact durable replay before time-sensitive evidence checks.
        if let Some(existing) = self
            .dependencies
            .store
            .get(&request.workflow_id)
            .map_err(|_| MerchantCancelServiceError::State("initial replay read"))?
        {
            if existing.operation() == MerchantOperation::Cancel
                && existing.exact_action_profile() == PAYMENT_CANCEL_PROFILE
                && existing.action_digest() == &action_digest
                && existing.policy_digest() == &policy_digest
            {
                return Ok(PaymentCancelWorkflowOutcome::Replay { record: existing });
            }
            return Ok(PaymentCancelWorkflowOutcome::Conflict { record: existing });
        }

        let aggregate_before = self
            .dependencies
            .store
            .snapshot(&request.policy, request.action.stripe_account_id(), now)
            .map_err(|_| MerchantCancelServiceError::State("aggregate snapshot"))?;
        let bounded = evaluate_payment_cancel(&PaymentCancelEvaluationContext {
            policy: &request.policy,
            action: &request.action,
            evidence: &request.evidence,
            required_configuration: &request.required_configuration,
            executed_configuration: &self.dependencies.executed_configuration,
            now,
        });
        let decision_receipt = self.decision_receipt(
            &request,
            policy_digest.clone(),
            action_digest.clone(),
            evidence_digest.clone(),
            aggregate_before,
            "authorized",
            "authorized".into(),
            true,
            Some(bounded.clone()),
            now,
        );
        self.append_decision(&decision_receipt)?;
        if bounded.decision != PaymentCancelDecisionClass::Eligible {
            return Ok(PaymentCancelWorkflowOutcome::Rejected {
                receipt: Box::new(decision_receipt),
                persisted: true,
            });
        }
        let decision_digest = decision_receipt
            .digest()
            .map_err(|_| MerchantCancelServiceError::Canonicalization)?;
        let required_configuration_digest = request
            .required_configuration
            .digest()
            .map_err(|_| MerchantCancelServiceError::Canonicalization)?;
        let executed_configuration_digest = self
            .dependencies
            .executed_configuration
            .digest()
            .map_err(|_| MerchantCancelServiceError::Canonicalization)?;
        let idempotency_key = payment_cancel_idempotency_key(
            &request.workflow_id,
            &policy_digest,
            &action_digest,
            request.action.stripe_account_id(),
            request.action.connect_account(),
        )?;
        let eligibility = bounded
            .eligibility
            .as_ref()
            .ok_or(MerchantCancelServiceError::Profile)?;
        let reservation = self
            .dependencies
            .store
            .reserve_cancel(ReservePaymentCancelRequest::new(
                request.workflow_id.clone(),
                action_digest.clone(),
                decision_digest.clone(),
                policy_digest.clone(),
                MERCHANT_EVALUATOR_ID.into(),
                MERCHANT_EVALUATOR_VERSION,
                evidence_digest,
                required_configuration_digest.clone(),
                executed_configuration_digest.clone(),
                request.action.stripe_account_id().clone(),
                request.action.connect_account().clone(),
                request.action.customer_id().clone(),
                request.action.order_scope().into(),
                request.action.currency().clone(),
                sha256(idempotency_key.as_bytes()),
                request
                    .evidence
                    .authorization_workflow_id()
                    .map(str::to_owned),
                request.action.authorization_action_digest().cloned(),
                request.action.authorization_reservation_id().cloned(),
                eligibility
                    .release_authorization_hold
                    .then_some(eligibility.authorization_release_minor),
                request.action.payment_intent_id().clone(),
                request.action.cancellation_reason(),
                request.action.current_status().into(),
                request.action.amount_minor(),
                now,
            ));
        let (lease, reserved) = match reservation {
            ReserveMerchantPaymentResult::Reserved { lease, record } => (lease, record),
            ReserveMerchantPaymentResult::Replay(record) => {
                return Ok(PaymentCancelWorkflowOutcome::Replay { record });
            }
            ReserveMerchantPaymentResult::Conflict(record) => {
                return Ok(PaymentCancelWorkflowOutcome::Conflict { record });
            }
            ReserveMerchantPaymentResult::CapacityExceeded {
                budget_id,
                available_minor,
            } => {
                return Ok(PaymentCancelWorkflowOutcome::CapacityChanged {
                    budget_id,
                    available_minor,
                });
            }
            ReserveMerchantPaymentResult::Unavailable => {
                return Err(MerchantCancelServiceError::State("cancel reservation"));
            }
        };
        self.append_transition(
            &decision_digest,
            "cancellation-claim-reserved",
            reserved,
            false,
            false,
            false,
            false,
            now,
        )?;
        let claimed = self
            .dependencies
            .store
            .claim_cancel(&lease, now)
            .map_err(|_| MerchantCancelServiceError::State("cancel claim"))?;
        self.append_transition(
            &decision_digest,
            "cancel-claimed",
            claimed,
            false,
            false,
            false,
            false,
            now,
        )?;
        let command = VerifiedPaymentCancelCommand::new(
            *authorized,
            request.workflow_id,
            request.evidence,
            policy_digest,
            lease.reservation_id().clone(),
            decision_digest.clone(),
            required_configuration_digest,
            executed_configuration_digest,
            idempotency_key,
        );

        let credential = match self
            .dependencies
            .credential_provider
            .credential(command.action().stripe_account_id())
        {
            Ok(credential) => credential,
            Err(error) => {
                self.release_before_delivery(
                    &decision_digest,
                    &lease,
                    "cancellation-claim-released-credential-failed",
                    now,
                )?;
                return Err(MerchantCancelServiceError::Port(error));
            }
        };
        let critical = match self.dependencies.stripe_gateway.reread_critical_evidence(
            &command,
            &credential,
            now,
        ) {
            Ok(evidence) => evidence,
            Err(error) => {
                self.release_before_delivery(
                    &decision_digest,
                    &lease,
                    "cancellation-claim-released-critical-read-failed",
                    now,
                )?;
                return Err(MerchantCancelServiceError::Port(error));
            }
        };
        if !command.evidence().critical_scope_matches(&critical) {
            let record = self.release_before_delivery(
                &decision_digest,
                &lease,
                "cancellation-claim-released-critical-evidence-changed",
                now,
            )?;
            return Ok(PaymentCancelWorkflowOutcome::CriticalEvidenceChanged { record });
        }
        let attempting = self
            .dependencies
            .store
            .mark_cancel_attempting(&lease, now)
            .map_err(|_| MerchantCancelServiceError::State("cancel attempt"))?;
        self.append_transition(
            &decision_digest,
            "cancel-attempting",
            attempting,
            true,
            true,
            true,
            false,
            now,
        )?;
        let effect = self
            .dependencies
            .stripe_gateway
            .cancel(&command, &credential, now)
            .unwrap_or(PaymentCancelEffect::OutcomeUnknown(None));
        match effect {
            PaymentCancelEffect::NotDelivered { code } => {
                let record = self.release_before_delivery(
                    &decision_digest,
                    &lease,
                    "cancel-not-delivered-claim-released",
                    now,
                )?;
                Ok(PaymentCancelWorkflowOutcome::NotDelivered { code, record })
            }
            PaymentCancelEffect::Declined { code } => {
                let record = self.release_before_delivery(
                    &decision_digest,
                    &lease,
                    "cancel-declined-claim-released",
                    now,
                )?;
                Ok(PaymentCancelWorkflowOutcome::ProviderDeclined { code, record })
            }
            PaymentCancelEffect::OutcomeUnknown(provider) => {
                self.unknown(&decision_digest, &lease, provider, now)
            }
            PaymentCancelEffect::Accepted(provider) => self.finish_accepted(
                &command,
                &credential,
                &decision_digest,
                &lease,
                provider,
                now,
            ),
            PaymentCancelEffect::CaptureConflict(provider) => {
                let record = self
                    .dependencies
                    .store
                    .record_cancel_capture_conflict(&lease, provider, now)
                    .map_err(|_| MerchantCancelServiceError::State("capture conflict"))?;
                let receipt = self.append_transition(
                    &decision_digest,
                    "payment-cancel-capture-conflict",
                    record.clone(),
                    true,
                    true,
                    true,
                    true,
                    now,
                )?;
                Ok(PaymentCancelWorkflowOutcome::CaptureConflict {
                    record,
                    receipt: Box::new(receipt),
                })
            }
        }
    }

    /// Reconciles an ambiguous workflow without issuing cancel again.
    ///
    /// # Errors
    ///
    /// Returns a closed state, credential, provider, receipt, or canonicalization failure.
    pub fn reconcile(
        &self,
        workflow_id: &str,
    ) -> Result<PaymentCancelWorkflowOutcome, MerchantCancelServiceError> {
        let now = self.dependencies.clock.now()?;
        let record = self
            .dependencies
            .store
            .get(workflow_id)
            .map_err(|_| MerchantCancelServiceError::State("reconciliation read"))?
            .ok_or(MerchantCancelServiceError::NotFound)?;
        if record.operation() != MerchantOperation::Cancel {
            return Err(MerchantCancelServiceError::State(
                "reconciliation operation mismatch",
            ));
        }
        if matches!(
            record.state(),
            MerchantReservationState::CancelCommitted
                | MerchantReservationState::ReconciledCancelCommitted
                | MerchantReservationState::CancelCaptureConflict
                | MerchantReservationState::Released
                | MerchantReservationState::ReconciledReleased
        ) {
            return Ok(PaymentCancelWorkflowOutcome::Replay { record });
        }
        let credential = self
            .dependencies
            .credential_provider
            .credential(record.stripe_account_id())?;
        let outcome = self
            .dependencies
            .stripe_gateway
            .reconcile(&record, &credential, now)
            .unwrap_or(PaymentCancelReconciliationOutcome::OutcomeUnknown(None));
        let provider = reconciliation_provider(&outcome).cloned();
        let reconciled = self
            .dependencies
            .store
            .reconcile_cancel(workflow_id, record.action_digest(), outcome, now)
            .map_err(|_| MerchantCancelServiceError::State("reconciliation transition"))?;
        if let Some(provider) = provider {
            self.append_observation(
                &reconciled,
                provider,
                matches!(
                    reconciled.state(),
                    MerchantReservationState::ReconciledCancelCommitted
                ),
                true,
                now,
            )?;
        }
        let transition = self.append_transition(
            record.decision_receipt_digest(),
            "cancel-reconciled",
            reconciled.clone(),
            true,
            true,
            true,
            true,
            now,
        )?;
        Ok(PaymentCancelWorkflowOutcome::Reconciled {
            record: reconciled,
            receipt: Box::new(transition),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn decision_receipt(
        &self,
        request: &ExecutePaymentCancelRequest,
        policy_digest: DigestHex,
        action_digest: DigestHex,
        evidence_digest: DigestHex,
        aggregate_before: MerchantAggregateSnapshot,
        auths_decision: &str,
        auths_code: String,
        authorization_established: bool,
        bounded_decision: Option<PaymentCancelDecision>,
        now: u64,
    ) -> MerchantCancelDecisionReceipt {
        MerchantCancelDecisionReceipt {
            schema: "auths.stripe.payment-cancel-decision-receipt/1".into(),
            workflow_id: request.workflow_id.clone(),
            policy_provenance: merchant_policy_provenance(),
            policy: request.policy.clone(),
            policy_digest,
            exact_action: request.action.clone(),
            action_digest,
            evidence: request.evidence.clone(),
            evidence_digest,
            aggregate_before,
            required_configuration: request.required_configuration.clone(),
            executed_configuration: self.dependencies.executed_configuration.clone(),
            configuration_equal: request.required_configuration
                == self.dependencies.executed_configuration,
            auths_decision: auths_decision.into(),
            auths_code,
            authorization_established,
            bounded_decision,
            credential_requested: false,
            stripe_called: false,
            decided_at: now,
        }
    }

    fn finish_accepted(
        &self,
        command: &VerifiedPaymentCancelCommand,
        credential: &PaymentCancelCredential,
        decision_digest: &DigestHex,
        lease: &MerchantReservationLease,
        provider: PaymentCancelProviderProjection,
        now: u64,
    ) -> Result<PaymentCancelWorkflowOutcome, MerchantCancelServiceError> {
        let accepted = self
            .dependencies
            .store
            .record_cancel_provider_accepted(lease, provider.clone(), now)
            .map_err(|_| MerchantCancelServiceError::State("provider response persistence"))?;
        self.append_transition(
            decision_digest,
            "cancel-provider-accepted",
            accepted,
            true,
            true,
            true,
            false,
            now,
        )?;
        let Ok(observed) = self
            .dependencies
            .stripe_gateway
            .observe(command, credential, now)
        else {
            return self.unknown(decision_digest, lease, Some(provider), now);
        };
        if is_capture_conflict_projection(&observed) {
            self.append_observation_from_command(
                command,
                lease,
                observed.clone(),
                false,
                false,
                now,
            )?;
            let record = self
                .dependencies
                .store
                .record_cancel_capture_conflict(lease, observed, now)
                .map_err(|_| MerchantCancelServiceError::State("observed capture conflict"))?;
            let receipt = self.append_transition(
                decision_digest,
                "payment-cancel-capture-conflict",
                record.clone(),
                true,
                true,
                true,
                true,
                now,
            )?;
            return Ok(PaymentCancelWorkflowOutcome::CaptureConflict {
                record,
                receipt: Box::new(receipt),
            });
        }
        let exact = exact_committed_projection(command.action(), &observed);
        self.append_observation_from_command(command, lease, observed.clone(), exact, false, now)?;
        if !exact {
            return self.unknown(decision_digest, lease, Some(observed), now);
        }
        self.dependencies
            .store
            .record_cancel_provider_accepted(lease, observed, now)
            .map_err(|_| MerchantCancelServiceError::State("provider observation persistence"))?;
        let committed = self
            .dependencies
            .store
            .commit_cancel(lease, now)
            .map_err(|_| MerchantCancelServiceError::State("atomic cancel commit"))?;
        let receipt = self.append_transition(
            decision_digest,
            "cancel-committed-hold-released",
            committed.clone(),
            true,
            true,
            true,
            true,
            now,
        )?;
        Ok(PaymentCancelWorkflowOutcome::Canceled {
            record: committed,
            receipt: Box::new(receipt),
        })
    }

    fn release_before_delivery(
        &self,
        decision_digest: &DigestHex,
        lease: &MerchantReservationLease,
        event: &str,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantCancelServiceError> {
        let released = self
            .dependencies
            .store
            .release_cancel(lease, now)
            .map_err(|_| MerchantCancelServiceError::State("cancel release"))?;
        self.append_transition(
            decision_digest,
            event,
            released.clone(),
            false,
            true,
            false,
            false,
            now,
        )?;
        Ok(released)
    }

    fn unknown(
        &self,
        decision_digest: &DigestHex,
        lease: &MerchantReservationLease,
        provider: Option<PaymentCancelProviderProjection>,
        now: u64,
    ) -> Result<PaymentCancelWorkflowOutcome, MerchantCancelServiceError> {
        let record = self
            .dependencies
            .store
            .mark_cancel_outcome_unknown(lease, provider, now)
            .map_err(|_| MerchantCancelServiceError::State("unknown outcome retention"))?;
        let receipt = self.append_transition(
            decision_digest,
            "cancel-outcome-unknown-hold-retained",
            record.clone(),
            true,
            true,
            true,
            false,
            now,
        )?;
        Ok(PaymentCancelWorkflowOutcome::OutcomeUnknown {
            record,
            receipt: Box::new(receipt),
        })
    }

    fn append_decision(
        &self,
        receipt: &MerchantCancelDecisionReceipt,
    ) -> Result<(), MerchantCancelServiceError> {
        self.dependencies
            .receipt_sink
            .append(&MerchantCancelReceipt::Decision(Box::new(receipt.clone())))
            .map_err(MerchantCancelServiceError::Port)
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::fn_params_excessive_bools,
        reason = "receipt transition facts remain independent and visibly ordered"
    )]
    fn append_transition(
        &self,
        decision_digest: &DigestHex,
        event: &str,
        reservation: MerchantReservationRecord,
        execution_attempted: bool,
        credential_requested: bool,
        stripe_called: bool,
        reconciled_observation: bool,
        now: u64,
    ) -> Result<MerchantCancelTransitionReceipt, MerchantCancelServiceError> {
        let authorization_action_digest = reservation.authorization_action_digest().cloned();
        let authorization_reservation_id = reservation.authorization_reservation_id().cloned();
        let authorization_release_minor = reservation.authorization_release_minor();
        let atomic = matches!(
            reservation.state(),
            MerchantReservationState::CancelCommitted
                | MerchantReservationState::ReconciledCancelCommitted
        ) && authorization_release_minor.is_some();
        let linked_authorization = if atomic {
            self.dependencies
                .store
                .get(reservation.authorization_workflow_id().ok_or(
                    MerchantCancelServiceError::State("authorization workflow link"),
                )?)
                .map_err(|_| MerchantCancelServiceError::State("linked authorization read"))?
        } else {
            None
        };
        let receipt = MerchantCancelTransitionReceipt {
            schema: "auths.stripe.payment-cancel-transition-receipt/1".into(),
            decision_receipt_digest: decision_digest.clone(),
            exact_action_profile: reservation.exact_action_profile().into(),
            operation: reservation.operation(),
            action_digest: reservation.action_digest().clone(),
            authorization_action_digest,
            authorization_reservation_id,
            policy_digest: reservation.policy_digest().clone(),
            required_configuration_digest: reservation.required_configuration_digest().clone(),
            executed_configuration_digest: reservation.executed_configuration_digest().clone(),
            semantic_event: event.into(),
            resulting_state: reservation.state(),
            payment_intent_id: reservation
                .cancel_payment_intent_id()
                .cloned()
                .ok_or(MerchantCancelServiceError::State("cancellation target"))?,
            cancellation_reason: reservation
                .cancellation_reason()
                .ok_or(MerchantCancelServiceError::State("cancellation reason"))?,
            pre_cancel_status: reservation
                .cancel_pre_status()
                .ok_or(MerchantCancelServiceError::State("pre-cancel status"))?
                .into(),
            target_amount_minor: reservation
                .cancel_amount_minor()
                .ok_or(MerchantCancelServiceError::State("cancellation amount"))?,
            authorization_release_minor,
            atomic_hold_release: atomic
                && linked_authorization.as_ref().is_some_and(|record| {
                    record.state() == MerchantReservationState::AuthorizationReleasedByCancel
                }),
            capture_conflict: reservation.state()
                == MerchantReservationState::CancelCaptureConflict,
            linked_authorization,
            provider_accepted: reservation.cancel_provider().is_some(),
            cancel_reservation: reservation,
            authorization_established: true,
            execution_attempted,
            credential_requested,
            stripe_called,
            reconciled_observation,
            recorded_at: now,
        };
        self.dependencies
            .receipt_sink
            .append(&MerchantCancelReceipt::Transition(Box::new(
                receipt.clone(),
            )))
            .map_err(MerchantCancelServiceError::Port)?;
        Ok(receipt)
    }

    fn append_observation_from_command(
        &self,
        command: &VerifiedPaymentCancelCommand,
        lease: &MerchantReservationLease,
        provider: PaymentCancelProviderProjection,
        exact: bool,
        reconciled: bool,
        now: u64,
    ) -> Result<(), MerchantCancelServiceError> {
        let receipt = MerchantCancelObservationReceipt {
            schema: "auths.stripe.payment-cancel-observation-receipt/1".into(),
            workflow_id: command.workflow_id().into(),
            exact_action_profile: command.action().profile().into(),
            operation: MerchantOperation::Cancel,
            action_digest: command
                .action()
                .digest()
                .map_err(|_| MerchantCancelServiceError::Canonicalization)?,
            decision_receipt_digest: command.decision_receipt_digest().clone(),
            policy_digest: command.policy_digest().clone(),
            required_configuration_digest: command.required_configuration_digest().clone(),
            executed_configuration_digest: command.executed_configuration_digest().clone(),
            reservation_id: lease.reservation_id().clone(),
            authorization_reservation_id: command.action().authorization_reservation_id().cloned(),
            provider,
            exact_provider_equality: exact,
            hold_release_observed: false,
            capture_conflict: false,
            reconciled,
            residual_assumptions: residual_assumptions(),
            recorded_at: now,
        };
        self.dependencies
            .receipt_sink
            .append(&MerchantCancelReceipt::Observation(Box::new(receipt)))
            .map_err(MerchantCancelServiceError::Port)
    }

    fn append_observation(
        &self,
        record: &MerchantReservationRecord,
        provider: PaymentCancelProviderProjection,
        exact: bool,
        reconciled: bool,
        now: u64,
    ) -> Result<(), MerchantCancelServiceError> {
        let receipt = MerchantCancelObservationReceipt {
            schema: "auths.stripe.payment-cancel-observation-receipt/1".into(),
            workflow_id: record.workflow_id().into(),
            exact_action_profile: record.exact_action_profile().into(),
            operation: record.operation(),
            action_digest: record.action_digest().clone(),
            decision_receipt_digest: record.decision_receipt_digest().clone(),
            policy_digest: record.policy_digest().clone(),
            required_configuration_digest: record.required_configuration_digest().clone(),
            executed_configuration_digest: record.executed_configuration_digest().clone(),
            reservation_id: record.reservation_id().clone(),
            authorization_reservation_id: record.authorization_reservation_id().cloned(),
            provider,
            exact_provider_equality: exact,
            hold_release_observed: record.authorization_release_minor().is_some()
                && matches!(
                    record.state(),
                    MerchantReservationState::CancelCommitted
                        | MerchantReservationState::ReconciledCancelCommitted
                ),
            capture_conflict: record.state() == MerchantReservationState::CancelCaptureConflict,
            reconciled,
            residual_assumptions: residual_assumptions(),
            recorded_at: now,
        };
        self.dependencies
            .receipt_sink
            .append(&MerchantCancelReceipt::Observation(Box::new(receipt)))
            .map_err(MerchantCancelServiceError::Port)
    }
}

/// Complete workflow outcome with durable ambiguity as data.
pub enum PaymentCancelWorkflowOutcome {
    /// Proof or bounded policy denied the action.
    Rejected {
        /// Exact receipt.
        receipt: Box<MerchantCancelDecisionReceipt>,
        /// Configuration mismatch is intentionally not persisted.
        persisted: bool,
    },
    /// Cancellation was terminally observed and any linked hold was released.
    Canceled {
        /// Durable cancellation state.
        record: MerchantReservationRecord,
        /// Final transition receipt.
        receipt: Box<MerchantCancelTransitionReceipt>,
    },
    /// Same exact workflow already exists.
    Replay {
        /// Durable original state.
        record: MerchantReservationRecord,
    },
    /// Workflow identifier is bound to a different exact action.
    Conflict {
        /// Durable original state.
        record: MerchantReservationRecord,
    },
    /// The atomic cancellation claim became unavailable after pure evaluation.
    CapacityChanged {
        /// Stable budget identifier.
        budget_id: String,
        /// Capacity observed atomically.
        available_minor: u64,
    },
    /// Critical pre-cancel facts changed after claim.
    CriticalEvidenceChanged {
        /// Cancellation claim released; authorization hold retained.
        record: MerchantReservationRecord,
    },
    /// Adapter proved the cancel request never left the executor.
    NotDelivered {
        /// Stable non-secret transport category.
        code: String,
        /// Cancellation claim released; authorization hold retained.
        record: MerchantReservationRecord,
    },
    /// Stripe definitively declined cancel.
    ProviderDeclined {
        /// Stable non-secret provider category.
        code: String,
        /// Cancellation claim released; authorization hold retained.
        record: MerchantReservationRecord,
    },
    /// Stripe delivery or outcome is ambiguous.
    OutcomeUnknown {
        /// Cancellation claim and any authorization hold remain charged.
        record: MerchantReservationRecord,
        /// Final transition receipt.
        receipt: Box<MerchantCancelTransitionReceipt>,
    },
    /// A capture won the race; cancellation is terminal and the hold is retained.
    CaptureConflict {
        /// Durable conflicting provider transition.
        record: MerchantReservationRecord,
        /// Conflict transition receipt.
        receipt: Box<MerchantCancelTransitionReceipt>,
    },
    /// Retrieval reconciled prior durable state.
    Reconciled {
        /// Reconciled durable state.
        record: MerchantReservationRecord,
        /// Reconciliation transition receipt.
        receipt: Box<MerchantCancelTransitionReceipt>,
    },
}

#[derive(Serialize)]
struct PaymentCancelIdempotencyIdentity<'a> {
    schema: &'static str,
    workflow_id: &'a str,
    operation: &'static str,
    policy_digest: &'a DigestHex,
    action_digest: &'a DigestHex,
    stripe_account_id: &'a crate::types::StripeAccountId,
    connect_account: &'a crate::merchant::MerchantConnectAccount,
}

fn payment_cancel_idempotency_key(
    workflow_id: &str,
    policy_digest: &DigestHex,
    action_digest: &DigestHex,
    stripe_account_id: &crate::types::StripeAccountId,
    connect_account: &crate::merchant::MerchantConnectAccount,
) -> Result<String, MerchantCancelServiceError> {
    let digest = canonical_digest(&PaymentCancelIdempotencyIdentity {
        schema: "auths.stripe.payment-cancel-idempotency/1",
        workflow_id,
        operation: "cancel",
        policy_digest,
        action_digest,
        stripe_account_id,
        connect_account,
    })
    .map_err(|_| MerchantCancelServiceError::Canonicalization)?;
    Ok(format!("auths-pc-{}", &digest.as_str()[..48]))
}

fn exact_committed_projection(
    action: &StripeExactPaymentCancelV1,
    provider: &PaymentCancelProviderProjection,
) -> bool {
    provider.payment_intent_id == *action.payment_intent_id()
        && provider.status == "canceled"
        && provider.cancellation_reason == Some(action.cancellation_reason())
        && provider.amount_minor == action.amount_minor()
        && provider.currency == *action.currency()
        && provider.amount_capturable_minor == 0
        && provider.amount_received_minor == 0
        && provider.charge_captured != Some(true)
}

fn is_capture_conflict_projection(provider: &PaymentCancelProviderProjection) -> bool {
    provider.status == "succeeded" || provider.charge_captured == Some(true)
}

fn reconciliation_provider(
    outcome: &PaymentCancelReconciliationOutcome,
) -> Option<&PaymentCancelProviderProjection> {
    match outcome {
        PaymentCancelReconciliationOutcome::Canceled(provider)
        | PaymentCancelReconciliationOutcome::CaptureConflict(provider) => Some(provider),
        PaymentCancelReconciliationOutcome::Released(provider)
        | PaymentCancelReconciliationOutcome::OutcomeUnknown(provider) => provider.as_ref(),
    }
}

fn residual_assumptions() -> Vec<String> {
    vec![
        "Stripe test mode is not evidence of live-mode payment behavior".into(),
        "policy provenance is executor-local trusted configuration".into(),
    ]
}

/// Closed payment-cancellation service error.
#[derive(Debug, thiserror::Error)]
pub enum MerchantCancelServiceError {
    /// Exact profile canonicalization or decode failed.
    #[error("exact Stripe cancel profile rejected the action")]
    Profile,
    /// Canonical digest or receipt identity failed.
    #[error("could not canonicalize Stripe cancel workflow data")]
    Canonicalization,
    /// Durable reservation, claim, or replay state failed.
    #[error("Stripe cancel workflow state is unavailable at {0}")]
    State(&'static str),
    /// Workflow was not found.
    #[error("Stripe cancel workflow was not found")]
    NotFound,
    /// Closed port failure.
    #[error(transparent)]
    Port(#[from] PortError),
}
