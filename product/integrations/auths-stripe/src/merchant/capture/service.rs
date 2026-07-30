//! Protected exact-proof-to-Stripe pipeline for one final capture.

use auths_profile_api::ActionProfile as _;
use auths_sdk::RequestContext;
use serde::Serialize;

use super::{
    MerchantCaptureDecisionReceipt, MerchantCaptureObservationReceipt, MerchantCaptureReceipt,
    MerchantCaptureTransitionReceipt, PaymentCaptureDecision, PaymentCaptureDecisionClass,
    PaymentCaptureDecisionCode, PaymentCaptureDecisionStage, PaymentCaptureEffect,
    PaymentCaptureEvaluationContext, PaymentCaptureEvidenceV1, PaymentCaptureGateway,
    PaymentCaptureProofDecision, PaymentCaptureProofVerifier, PaymentCaptureProviderProjection,
    PaymentCaptureReconciliationOutcome, StripeExactPaymentCaptureV1, StripePaymentCaptureProfile,
    VerifiedPaymentCaptureCommand, evaluate_payment_capture, merchant_policy_provenance,
};
use crate::{
    canonical::{canonical_digest, sha256},
    merchant::{
        MERCHANT_EVALUATOR_ID, MERCHANT_EVALUATOR_VERSION, MerchantAggregateSnapshot,
        MerchantOperation, MerchantPaymentStore, MerchantReservationLease,
        MerchantReservationRecord, MerchantReservationState, PAYMENT_CAPTURE_PROFILE,
        ReserveMerchantPaymentResult, ReservePaymentCaptureRequest,
        StripeBoundedMerchantPaymentPolicyV1, StripeMerchantEvaluatorConfigurationV1,
    },
    ports::{
        Clock, CredentialProvider, PaymentCaptureCredential, PaymentCaptureCredentialScope,
        PortError, ReceiptSink,
    },
    types::DigestHex,
};

/// Hostile exact action plus protected configured inputs.
pub struct ExecutePaymentCaptureRequest {
    /// Durable server-selected capture workflow identity.
    pub workflow_id: String,
    /// Agent-selected exact final capture.
    pub action: StripeExactPaymentCaptureV1,
    /// Fresh protected Stripe and durable-authorization evidence.
    pub evidence: PaymentCaptureEvidenceV1,
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
pub struct PaymentCaptureServiceDependencies<V, C, G, S, R, T> {
    /// Auths verifier fixed to the exact final-capture profile.
    pub proof_verifier: V,
    /// Capture-scoped Stripe credential broker.
    pub credential_provider: C,
    /// Only capture/retrieve provider surface.
    pub stripe_gateway: G,
    /// Durable merchant reservation, claim, and replay state.
    pub store: S,
    /// Append-only capture receipt sink.
    pub receipt_sink: R,
    /// Trusted time.
    pub clock: T,
    /// Runtime configuration actually loaded.
    pub executed_configuration: StripeMerchantEvaluatorConfigurationV1,
}

/// Complete bounded one-time final-capture service.
pub struct PaymentCaptureService<V, C, G, S, R, T> {
    dependencies: PaymentCaptureServiceDependencies<V, C, G, S, R, T>,
}

impl<V, C, G, S, R, T> PaymentCaptureService<V, C, G, S, R, T>
where
    V: PaymentCaptureProofVerifier,
    C: CredentialProvider<PaymentCaptureCredentialScope>,
    G: PaymentCaptureGateway,
    S: MerchantPaymentStore,
    R: ReceiptSink<MerchantCaptureReceipt>,
    T: Clock,
{
    /// Constructs the protected service.
    #[must_use]
    pub const fn new(dependencies: PaymentCaptureServiceDependencies<V, C, G, S, R, T>) -> Self {
        Self { dependencies }
    }

    /// Executes one exact final capture after proof, decision, reservation, and claim.
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
        request: ExecutePaymentCaptureRequest,
    ) -> Result<PaymentCaptureWorkflowOutcome, MerchantCaptureServiceError> {
        let now = self.dependencies.clock.now()?;
        let canonical = StripePaymentCaptureProfile
            .canonicalize(
                &request
                    .action
                    .canonical_bytes()
                    .map_err(|_| MerchantCaptureServiceError::Canonicalization)?,
            )
            .map_err(|_| MerchantCaptureServiceError::Profile)?;
        let proof = self.dependencies.proof_verifier.verify(
            &request.proof,
            &canonical,
            &request.auths_request,
        )?;
        let action_digest = request
            .action
            .digest()
            .map_err(|_| MerchantCaptureServiceError::Canonicalization)?;
        let evidence_digest = request
            .evidence
            .digest()
            .map_err(|_| MerchantCaptureServiceError::Canonicalization)?;
        let policy_digest = request
            .policy
            .digest()
            .map_err(|_| MerchantCaptureServiceError::Canonicalization)?;
        let authorized = match proof {
            PaymentCaptureProofDecision::Authorized(authorized) => {
                if authorized.command().action() != &request.action {
                    return Err(MerchantCaptureServiceError::Profile);
                }
                authorized
            }
            PaymentCaptureProofDecision::Denied { code } => {
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
                return Ok(PaymentCaptureWorkflowOutcome::Rejected {
                    receipt: Box::new(receipt),
                    persisted: true,
                });
            }
            PaymentCaptureProofDecision::Indeterminate { code } => {
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
                return Ok(PaymentCaptureWorkflowOutcome::Rejected {
                    receipt: Box::new(receipt),
                    persisted: true,
                });
            }
        };

        if request.required_configuration != self.dependencies.executed_configuration {
            let bounded = PaymentCaptureDecision {
                class: PaymentCaptureDecisionClass::Denied,
                code: PaymentCaptureDecisionCode::BoundedConfigurationMismatch,
                stage: PaymentCaptureDecisionStage::Configuration,
                detail: "required and executed final-capture configurations differ".into(),
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
            return Ok(PaymentCaptureWorkflowOutcome::Rejected {
                receipt: Box::new(receipt),
                persisted: false,
            });
        }

        // Resolve exact durable replay before time-sensitive evidence checks.
        if let Some(existing) = self
            .dependencies
            .store
            .get(&request.workflow_id)
            .map_err(|_| MerchantCaptureServiceError::State("initial replay read"))?
        {
            if existing.operation() == MerchantOperation::Capture
                && existing.exact_action_profile() == PAYMENT_CAPTURE_PROFILE
                && existing.action_digest() == &action_digest
                && existing.policy_digest() == &policy_digest
            {
                return Ok(PaymentCaptureWorkflowOutcome::Replay { record: existing });
            }
            return Ok(PaymentCaptureWorkflowOutcome::Conflict { record: existing });
        }

        let aggregate_before = self
            .dependencies
            .store
            .snapshot(&request.policy, request.action.stripe_account_id(), now)
            .map_err(|_| MerchantCaptureServiceError::State("aggregate snapshot"))?;
        let bounded = evaluate_payment_capture(&PaymentCaptureEvaluationContext {
            workflow_id: &request.workflow_id,
            policy: &request.policy,
            action: &request.action,
            evidence: &request.evidence,
            aggregate_snapshot: &aggregate_before,
            required_configuration: &request.required_configuration,
            executed_configuration: &self.dependencies.executed_configuration,
            request_audience: request.auths_request.audience().as_str(),
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
        if bounded.class != PaymentCaptureDecisionClass::Eligible {
            return Ok(PaymentCaptureWorkflowOutcome::Rejected {
                receipt: Box::new(decision_receipt),
                persisted: true,
            });
        }
        let decision_digest = decision_receipt
            .digest()
            .map_err(|_| MerchantCaptureServiceError::Canonicalization)?;
        let required_configuration_digest = request
            .required_configuration
            .digest()
            .map_err(|_| MerchantCaptureServiceError::Canonicalization)?;
        let executed_configuration_digest = self
            .dependencies
            .executed_configuration
            .digest()
            .map_err(|_| MerchantCaptureServiceError::Canonicalization)?;
        let idempotency_key = payment_capture_idempotency_key(
            &request.workflow_id,
            &policy_digest,
            &action_digest,
            request.action.stripe_account_id(),
            request.action.connect_account(),
        )?;
        let eligibility = bounded
            .eligibility
            .as_ref()
            .ok_or(MerchantCaptureServiceError::Profile)?;
        let reservation =
            self.dependencies
                .store
                .reserve_capture(ReservePaymentCaptureRequest::new(
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
                    request.action.amount_to_capture_minor(),
                    eligibility.settlement_reservations.clone(),
                    sha256(idempotency_key.as_bytes()),
                    request.evidence.authorization_workflow_id().into(),
                    request.action.authorization_action_digest().clone(),
                    request.action.authorization_reservation_id().clone(),
                    eligibility.authorization_release_minor,
                    request.action.payment_intent_id().clone(),
                    request.action.latest_charge_id().clone(),
                    now,
                ));
        let (lease, reserved) = match reservation {
            ReserveMerchantPaymentResult::Reserved { lease, record } => (lease, record),
            ReserveMerchantPaymentResult::Replay(record) => {
                return Ok(PaymentCaptureWorkflowOutcome::Replay { record });
            }
            ReserveMerchantPaymentResult::Conflict(record) => {
                return Ok(PaymentCaptureWorkflowOutcome::Conflict { record });
            }
            ReserveMerchantPaymentResult::CapacityExceeded {
                budget_id,
                available_minor,
            } => {
                return Ok(PaymentCaptureWorkflowOutcome::CapacityChanged {
                    budget_id,
                    available_minor,
                });
            }
            ReserveMerchantPaymentResult::Unavailable => {
                return Err(MerchantCaptureServiceError::State("capture reservation"));
            }
        };
        self.append_transition(
            &decision_digest,
            "settlement-reserved",
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
            .claim_capture(&lease, now)
            .map_err(|_| MerchantCaptureServiceError::State("capture claim"))?;
        self.append_transition(
            &decision_digest,
            "capture-claimed",
            claimed,
            false,
            false,
            false,
            false,
            now,
        )?;
        let command = VerifiedPaymentCaptureCommand::new(
            *authorized,
            request.workflow_id,
            request.evidence,
            policy_digest,
            lease.reservation_id().clone(),
            decision_digest.clone(),
            required_configuration_digest,
            executed_configuration_digest,
            request.policy.minimum_capture_window_seconds(),
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
                    "settlement-released-credential-failed",
                    now,
                )?;
                return Err(MerchantCaptureServiceError::Port(error));
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
                    "settlement-released-critical-read-failed",
                    now,
                )?;
                return Err(MerchantCaptureServiceError::Port(error));
            }
        };
        if !command.evidence().critical_scope_matches(&critical)
            || critical.capture_before().saturating_sub(now)
                < command.minimum_capture_window_seconds()
        {
            let record = self.release_before_delivery(
                &decision_digest,
                &lease,
                "settlement-released-critical-evidence-changed",
                now,
            )?;
            return Ok(PaymentCaptureWorkflowOutcome::CriticalEvidenceChanged { record });
        }
        let attempting = self
            .dependencies
            .store
            .mark_capture_attempting(&lease, now)
            .map_err(|_| MerchantCaptureServiceError::State("capture attempt"))?;
        self.append_transition(
            &decision_digest,
            "capture-attempting",
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
            .capture(&command, &credential, now)
            .unwrap_or(PaymentCaptureEffect::OutcomeUnknown(None));
        match effect {
            PaymentCaptureEffect::NotDelivered { code } => {
                let record = self.release_before_delivery(
                    &decision_digest,
                    &lease,
                    "capture-not-delivered-settlement-released",
                    now,
                )?;
                Ok(PaymentCaptureWorkflowOutcome::NotDelivered { code, record })
            }
            PaymentCaptureEffect::Declined { code } => {
                let record = self.release_before_delivery(
                    &decision_digest,
                    &lease,
                    "capture-declined-settlement-released",
                    now,
                )?;
                Ok(PaymentCaptureWorkflowOutcome::ProviderDeclined { code, record })
            }
            PaymentCaptureEffect::OutcomeUnknown(provider) => {
                self.unknown(&decision_digest, &lease, provider, now)
            }
            PaymentCaptureEffect::Accepted(provider) => self.finish_accepted(
                &command,
                &credential,
                &decision_digest,
                &lease,
                provider,
                now,
            ),
        }
    }

    /// Reconciles an ambiguous workflow without issuing capture again.
    ///
    /// # Errors
    ///
    /// Returns a closed state, credential, provider, receipt, or canonicalization failure.
    pub fn reconcile(
        &self,
        workflow_id: &str,
    ) -> Result<PaymentCaptureWorkflowOutcome, MerchantCaptureServiceError> {
        let now = self.dependencies.clock.now()?;
        let record = self
            .dependencies
            .store
            .get(workflow_id)
            .map_err(|_| MerchantCaptureServiceError::State("reconciliation read"))?
            .ok_or(MerchantCaptureServiceError::NotFound)?;
        if record.operation() != MerchantOperation::Capture {
            return Err(MerchantCaptureServiceError::State(
                "reconciliation operation mismatch",
            ));
        }
        if matches!(
            record.state(),
            MerchantReservationState::CaptureCommitted
                | MerchantReservationState::ReconciledCaptureCommitted
                | MerchantReservationState::Released
                | MerchantReservationState::ReconciledReleased
        ) {
            return Ok(PaymentCaptureWorkflowOutcome::Replay { record });
        }
        let credential = self
            .dependencies
            .credential_provider
            .credential(record.stripe_account_id())?;
        let outcome = self
            .dependencies
            .stripe_gateway
            .reconcile(&record, &credential, now)
            .unwrap_or(PaymentCaptureReconciliationOutcome::OutcomeUnknown(None));
        let provider = reconciliation_provider(&outcome).cloned();
        let reconciled = self
            .dependencies
            .store
            .reconcile_capture(workflow_id, record.action_digest(), outcome, now)
            .map_err(|_| MerchantCaptureServiceError::State("reconciliation transition"))?;
        if let Some(provider) = provider {
            self.append_observation(
                &reconciled,
                provider,
                matches!(
                    reconciled.state(),
                    MerchantReservationState::ReconciledCaptureCommitted
                ),
                true,
                now,
            )?;
        }
        let transition = self.append_transition(
            record.decision_receipt_digest(),
            "capture-reconciled",
            reconciled.clone(),
            false,
            true,
            true,
            true,
            now,
        )?;
        Ok(PaymentCaptureWorkflowOutcome::Reconciled {
            record: reconciled,
            receipt: Box::new(transition),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn decision_receipt(
        &self,
        request: &ExecutePaymentCaptureRequest,
        policy_digest: DigestHex,
        action_digest: DigestHex,
        evidence_digest: DigestHex,
        aggregate_before: MerchantAggregateSnapshot,
        auths_decision: &str,
        auths_code: String,
        authorization_established: bool,
        bounded_decision: Option<PaymentCaptureDecision>,
        now: u64,
    ) -> MerchantCaptureDecisionReceipt {
        MerchantCaptureDecisionReceipt {
            schema: "auths.stripe.payment-capture-decision-receipt/1".into(),
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
        command: &VerifiedPaymentCaptureCommand,
        credential: &PaymentCaptureCredential,
        decision_digest: &DigestHex,
        lease: &MerchantReservationLease,
        provider: PaymentCaptureProviderProjection,
        now: u64,
    ) -> Result<PaymentCaptureWorkflowOutcome, MerchantCaptureServiceError> {
        let accepted = self
            .dependencies
            .store
            .record_capture_provider_accepted(lease, provider.clone(), now)
            .map_err(|_| MerchantCaptureServiceError::State("provider response persistence"))?;
        self.append_transition(
            decision_digest,
            "capture-provider-accepted",
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
        let exact = exact_committed_projection(command.action(), &observed);
        self.append_observation_from_command(command, lease, observed.clone(), exact, false, now)?;
        if !exact {
            return self.unknown(decision_digest, lease, Some(observed), now);
        }
        self.dependencies
            .store
            .record_capture_provider_accepted(lease, observed, now)
            .map_err(|_| MerchantCaptureServiceError::State("provider observation persistence"))?;
        let committed = self
            .dependencies
            .store
            .commit_capture(lease, now)
            .map_err(|_| MerchantCaptureServiceError::State("atomic capture commit"))?;
        let receipt = self.append_transition(
            decision_digest,
            "capture-committed-hold-released",
            committed.clone(),
            true,
            true,
            true,
            true,
            now,
        )?;
        Ok(PaymentCaptureWorkflowOutcome::Captured {
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
    ) -> Result<MerchantReservationRecord, MerchantCaptureServiceError> {
        let released = self
            .dependencies
            .store
            .release_capture(lease, now)
            .map_err(|_| MerchantCaptureServiceError::State("capture release"))?;
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
        provider: Option<PaymentCaptureProviderProjection>,
        now: u64,
    ) -> Result<PaymentCaptureWorkflowOutcome, MerchantCaptureServiceError> {
        let record = self
            .dependencies
            .store
            .mark_capture_outcome_unknown(lease, provider, now)
            .map_err(|_| MerchantCaptureServiceError::State("unknown outcome retention"))?;
        let receipt = self.append_transition(
            decision_digest,
            "capture-outcome-unknown-hold-retained",
            record.clone(),
            true,
            true,
            true,
            false,
            now,
        )?;
        Ok(PaymentCaptureWorkflowOutcome::OutcomeUnknown {
            record,
            receipt: Box::new(receipt),
        })
    }

    fn append_decision(
        &self,
        receipt: &MerchantCaptureDecisionReceipt,
    ) -> Result<(), MerchantCaptureServiceError> {
        self.dependencies
            .receipt_sink
            .append(&MerchantCaptureReceipt::Decision(Box::new(receipt.clone())))
            .map_err(MerchantCaptureServiceError::Port)
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
    ) -> Result<MerchantCaptureTransitionReceipt, MerchantCaptureServiceError> {
        let authorization_action_digest =
            reservation.authorization_action_digest().cloned().ok_or(
                MerchantCaptureServiceError::State("authorization action link"),
            )?;
        let authorization_reservation_id =
            reservation.authorization_reservation_id().cloned().ok_or(
                MerchantCaptureServiceError::State("authorization reservation link"),
            )?;
        let authorization_release_minor =
            reservation
                .authorization_release_minor()
                .ok_or(MerchantCaptureServiceError::State(
                    "authorization release amount",
                ))?;
        let atomic = matches!(
            reservation.state(),
            MerchantReservationState::CaptureCommitted
                | MerchantReservationState::ReconciledCaptureCommitted
        );
        let linked_authorization = if atomic {
            self.dependencies
                .store
                .get(reservation.authorization_workflow_id().ok_or(
                    MerchantCaptureServiceError::State("authorization workflow link"),
                )?)
                .map_err(|_| MerchantCaptureServiceError::State("linked authorization read"))?
        } else {
            None
        };
        let receipt = MerchantCaptureTransitionReceipt {
            schema: "auths.stripe.payment-capture-transition-receipt/1".into(),
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
            settlement_amount_minor: reservation.amount_minor(),
            authorization_release_minor,
            atomic_cross_budget_transition: atomic
                && linked_authorization.as_ref().is_some_and(|record| {
                    record.state() == MerchantReservationState::AuthorizationReleasedByCapture
                }),
            linked_authorization,
            provider_accepted: reservation.capture_provider().is_some(),
            capture_reservation: reservation,
            authorization_established: true,
            execution_attempted,
            credential_requested,
            stripe_called,
            reconciled_observation,
            recorded_at: now,
        };
        self.dependencies
            .receipt_sink
            .append(&MerchantCaptureReceipt::Transition(Box::new(
                receipt.clone(),
            )))
            .map_err(MerchantCaptureServiceError::Port)?;
        Ok(receipt)
    }

    fn append_observation_from_command(
        &self,
        command: &VerifiedPaymentCaptureCommand,
        lease: &MerchantReservationLease,
        provider: PaymentCaptureProviderProjection,
        exact: bool,
        reconciled: bool,
        now: u64,
    ) -> Result<(), MerchantCaptureServiceError> {
        let receipt = MerchantCaptureObservationReceipt {
            schema: "auths.stripe.payment-capture-observation-receipt/1".into(),
            workflow_id: command.workflow_id().into(),
            exact_action_profile: command.action().profile().into(),
            operation: MerchantOperation::Capture,
            action_digest: command
                .action()
                .digest()
                .map_err(|_| MerchantCaptureServiceError::Canonicalization)?,
            decision_receipt_digest: command.decision_receipt_digest().clone(),
            policy_digest: command.policy_digest().clone(),
            required_configuration_digest: command.required_configuration_digest().clone(),
            executed_configuration_digest: command.executed_configuration_digest().clone(),
            reservation_id: lease.reservation_id().clone(),
            authorization_reservation_id: command.action().authorization_reservation_id().clone(),
            provider,
            exact_provider_equality: exact,
            atomic_cross_budget_transition: false,
            reconciled,
            residual_assumptions: residual_assumptions(),
            recorded_at: now,
        };
        self.dependencies
            .receipt_sink
            .append(&MerchantCaptureReceipt::Observation(Box::new(receipt)))
            .map_err(MerchantCaptureServiceError::Port)
    }

    fn append_observation(
        &self,
        record: &MerchantReservationRecord,
        provider: PaymentCaptureProviderProjection,
        exact: bool,
        reconciled: bool,
        now: u64,
    ) -> Result<(), MerchantCaptureServiceError> {
        let receipt = MerchantCaptureObservationReceipt {
            schema: "auths.stripe.payment-capture-observation-receipt/1".into(),
            workflow_id: record.workflow_id().into(),
            exact_action_profile: record.exact_action_profile().into(),
            operation: record.operation(),
            action_digest: record.action_digest().clone(),
            decision_receipt_digest: record.decision_receipt_digest().clone(),
            policy_digest: record.policy_digest().clone(),
            required_configuration_digest: record.required_configuration_digest().clone(),
            executed_configuration_digest: record.executed_configuration_digest().clone(),
            reservation_id: record.reservation_id().clone(),
            authorization_reservation_id: record.authorization_reservation_id().cloned().ok_or(
                MerchantCaptureServiceError::State("observation authorization reservation link"),
            )?,
            provider,
            exact_provider_equality: exact,
            atomic_cross_budget_transition: matches!(
                record.state(),
                MerchantReservationState::CaptureCommitted
                    | MerchantReservationState::ReconciledCaptureCommitted
            ),
            reconciled,
            residual_assumptions: residual_assumptions(),
            recorded_at: now,
        };
        self.dependencies
            .receipt_sink
            .append(&MerchantCaptureReceipt::Observation(Box::new(receipt)))
            .map_err(MerchantCaptureServiceError::Port)
    }
}

/// Complete workflow outcome with durable ambiguity as data.
pub enum PaymentCaptureWorkflowOutcome {
    /// Proof or bounded policy denied the action.
    Rejected {
        /// Exact receipt.
        receipt: Box<MerchantCaptureDecisionReceipt>,
        /// Configuration mismatch is intentionally not persisted.
        persisted: bool,
    },
    /// Final capture committed and linked hold was released atomically.
    Captured {
        /// Durable settlement state.
        record: MerchantReservationRecord,
        /// Final transition receipt.
        receipt: Box<MerchantCaptureTransitionReceipt>,
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
    /// Atomic aggregate settlement capacity changed after pure evaluation.
    CapacityChanged {
        /// Stable budget identifier.
        budget_id: String,
        /// Capacity observed atomically.
        available_minor: u64,
    },
    /// Critical pre-capture facts changed after claim.
    CriticalEvidenceChanged {
        /// Capture settlement released; authorization hold retained.
        record: MerchantReservationRecord,
    },
    /// Adapter proved the capture request never left the executor.
    NotDelivered {
        /// Stable non-secret transport category.
        code: String,
        /// Capture settlement released; authorization hold retained.
        record: MerchantReservationRecord,
    },
    /// Stripe definitively declined capture.
    ProviderDeclined {
        /// Stable non-secret provider category.
        code: String,
        /// Capture settlement released; authorization hold retained.
        record: MerchantReservationRecord,
    },
    /// Stripe delivery or outcome is ambiguous.
    OutcomeUnknown {
        /// Settlement and authorization hold remain charged.
        record: MerchantReservationRecord,
        /// Final transition receipt.
        receipt: Box<MerchantCaptureTransitionReceipt>,
    },
    /// Retrieval reconciled prior durable state.
    Reconciled {
        /// Reconciled durable state.
        record: MerchantReservationRecord,
        /// Reconciliation transition receipt.
        receipt: Box<MerchantCaptureTransitionReceipt>,
    },
}

#[derive(Serialize)]
struct PaymentCaptureIdempotencyIdentity<'a> {
    schema: &'static str,
    workflow_id: &'a str,
    operation: &'static str,
    policy_digest: &'a DigestHex,
    action_digest: &'a DigestHex,
    stripe_account_id: &'a crate::types::StripeAccountId,
    connect_account: &'a crate::merchant::MerchantConnectAccount,
}

fn payment_capture_idempotency_key(
    workflow_id: &str,
    policy_digest: &DigestHex,
    action_digest: &DigestHex,
    stripe_account_id: &crate::types::StripeAccountId,
    connect_account: &crate::merchant::MerchantConnectAccount,
) -> Result<String, MerchantCaptureServiceError> {
    let digest = canonical_digest(&PaymentCaptureIdempotencyIdentity {
        schema: "auths.stripe.payment-capture-idempotency/1",
        workflow_id,
        operation: "capture",
        policy_digest,
        action_digest,
        stripe_account_id,
        connect_account,
    })
    .map_err(|_| MerchantCaptureServiceError::Canonicalization)?;
    Ok(format!("auths-pc-{}", &digest.as_str()[..48]))
}

fn exact_committed_projection(
    action: &StripeExactPaymentCaptureV1,
    provider: &PaymentCaptureProviderProjection,
) -> bool {
    provider.payment_intent_id == *action.payment_intent_id()
        && provider.charge_id == *action.latest_charge_id()
        && provider.status == "succeeded"
        && provider.authorized_amount_minor == action.authorized_amount_minor()
        && provider.captured_amount_minor == action.amount_to_capture_minor()
        && provider.currency == *action.currency()
        && provider.amount_capturable_minor == 0
        && provider.amount_received_minor == action.amount_to_capture_minor()
        && provider.balance_transaction_id.is_some()
}

fn reconciliation_provider(
    outcome: &PaymentCaptureReconciliationOutcome,
) -> Option<&PaymentCaptureProviderProjection> {
    match outcome {
        PaymentCaptureReconciliationOutcome::Committed(provider) => Some(provider),
        PaymentCaptureReconciliationOutcome::Released(provider)
        | PaymentCaptureReconciliationOutcome::OutcomeUnknown(provider) => provider.as_ref(),
    }
}

fn residual_assumptions() -> Vec<String> {
    vec![
        "Stripe test mode is not evidence of live settlement".into(),
        "policy provenance is executor-local trusted configuration".into(),
    ]
}

/// Closed final-capture service error.
#[derive(Debug, thiserror::Error)]
pub enum MerchantCaptureServiceError {
    /// Exact profile canonicalization or decode failed.
    #[error("exact Stripe capture profile rejected the action")]
    Profile,
    /// Canonical digest or receipt identity failed.
    #[error("could not canonicalize Stripe capture workflow data")]
    Canonicalization,
    /// Durable reservation, claim, or replay state failed.
    #[error("Stripe capture workflow state is unavailable at {0}")]
    State(&'static str),
    /// Workflow was not found.
    #[error("Stripe capture workflow was not found")]
    NotFound,
    /// Closed port failure.
    #[error(transparent)]
    Port(#[from] PortError),
}
