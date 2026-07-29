//! Protected exact-proof-to-Stripe pipeline for bounded one-time collection.

use auths_profile_api::ActionProfile as _;
use auths_sdk::RequestContext;
use serde::Serialize;

use super::{
    MerchantCollectionDecisionReceipt, MerchantCollectionObservationReceipt,
    MerchantCollectionTransitionReceipt, PaymentCollectDecision, PaymentCollectDecisionClass,
    PaymentCollectDecisionCode, PaymentCollectDecisionStage, PaymentCollectEffect,
    PaymentCollectEvaluationContext, PaymentCollectGateway, PaymentCollectProofDecision,
    PaymentCollectProofVerifier, PaymentCollectReconciliationOutcome, StripeExactPaymentCollectV1,
    StripePaymentCollectProfile, VerifiedPaymentCollectCommand, evaluate_payment_collect,
    merchant_policy_provenance,
};
use crate::{
    canonical::{canonical_digest, sha256},
    merchant::{
        MERCHANT_EVALUATOR_ID, MERCHANT_EVALUATOR_VERSION, MerchantAggregateSnapshot,
        MerchantOperation, MerchantPaymentEvidenceV1, StripeBoundedMerchantPaymentPolicyV1,
        StripeMerchantEvaluatorConfigurationV1,
        state::{
            MerchantPaymentStore, MerchantProviderProjection, MerchantReservationRecord,
            MerchantReservationState, ReserveMerchantPaymentRequest, ReserveMerchantPaymentResult,
        },
    },
    ports::{Clock, CredentialProvider, PortError, ReceiptSink},
    receipts::StripeReceipt,
    types::DigestHex,
};

/// Hostile exact action plus protected configured inputs.
pub struct ExecutePaymentCollectRequest {
    /// Durable server-selected workflow identity.
    pub workflow_id: String,
    /// Agent-selected exact automatic-capture payment.
    pub action: StripeExactPaymentCollectV1,
    /// Fresh protected Stripe and order evidence.
    pub evidence: MerchantPaymentEvidenceV1,
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
pub struct PaymentCollectServiceDependencies<V, C, G, S, R, T> {
    /// Auths verifier fixed to the exact collection profile.
    pub proof_verifier: V,
    /// Restricted Stripe mutation-credential broker.
    pub credential_provider: C,
    /// Only create/retrieve provider surface.
    pub stripe_gateway: G,
    /// Durable merchant reservation, claim, and replay state.
    pub store: S,
    /// Append-only canonical receipts.
    pub receipt_sink: R,
    /// Trusted time.
    pub clock: T,
    /// Runtime configuration actually loaded.
    pub executed_configuration: StripeMerchantEvaluatorConfigurationV1,
}

/// Complete bounded one-time collection service.
pub struct PaymentCollectService<V, C, G, S, R, T> {
    dependencies: PaymentCollectServiceDependencies<V, C, G, S, R, T>,
}

impl<V, C, G, S, R, T> PaymentCollectService<V, C, G, S, R, T>
where
    V: PaymentCollectProofVerifier,
    C: CredentialProvider,
    G: PaymentCollectGateway,
    S: MerchantPaymentStore,
    R: ReceiptSink,
    T: Clock,
{
    /// Constructs the protected service.
    #[must_use]
    pub const fn new(dependencies: PaymentCollectServiceDependencies<V, C, G, S, R, T>) -> Self {
        Self { dependencies }
    }

    /// Executes one exact collection after proof, decision, reservation, and claim.
    ///
    /// # Errors
    ///
    /// Returns only closed integration, persistence, or canonicalization
    /// failures. Ambiguous Stripe delivery is a successful durable workflow
    /// outcome that requires reconciliation.
    #[allow(
        clippy::too_many_lines,
        reason = "the security-relevant ordering is deliberately linear and auditable"
    )]
    pub fn execute(
        &self,
        request: ExecutePaymentCollectRequest,
    ) -> Result<PaymentCollectWorkflowOutcome, MerchantServiceError> {
        let now = self.dependencies.clock.now()?;
        let canonical = StripePaymentCollectProfile
            .canonicalize(
                &request
                    .action
                    .canonical_bytes()
                    .map_err(|_| MerchantServiceError::Canonicalization)?,
            )
            .map_err(|_| MerchantServiceError::Profile)?;
        let proof = self.dependencies.proof_verifier.verify(
            &request.proof,
            &canonical,
            &request.auths_request,
        )?;
        let action_digest = request
            .action
            .digest()
            .map_err(|_| MerchantServiceError::Canonicalization)?;
        let evidence_digest = request
            .evidence
            .digest()
            .map_err(|_| MerchantServiceError::Canonicalization)?;
        let policy_digest = request
            .policy
            .digest()
            .map_err(|_| MerchantServiceError::Canonicalization)?;

        let authorized = match proof {
            PaymentCollectProofDecision::Authorized(authorized) => {
                if authorized.command().action() != &request.action {
                    return Err(MerchantServiceError::Profile);
                }
                authorized
            }
            PaymentCollectProofDecision::Denied { code } => {
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
                return Ok(PaymentCollectWorkflowOutcome::Rejected {
                    receipt: Box::new(receipt),
                    persisted: true,
                });
            }
            PaymentCollectProofDecision::Indeterminate { code } => {
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
                return Ok(PaymentCollectWorkflowOutcome::Rejected {
                    receipt: Box::new(receipt),
                    persisted: true,
                });
            }
        };

        // Required/executed inequality is known without state access and must
        // precede decision persistence, reservation, credentials, and Stripe.
        if request.required_configuration != self.dependencies.executed_configuration {
            let bounded = PaymentCollectDecision {
                class: PaymentCollectDecisionClass::Denied,
                code: PaymentCollectDecisionCode::BoundedConfigurationMismatch,
                stage: PaymentCollectDecisionStage::Configuration,
                detail: "required and executed merchant-payment configurations differ".into(),
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
            return Ok(PaymentCollectWorkflowOutcome::Rejected {
                receipt: Box::new(receipt),
                persisted: false,
            });
        }

        let aggregate_before = self
            .dependencies
            .store
            .snapshot(&request.policy, request.action.stripe_account_id(), now)
            .map_err(|_| MerchantServiceError::State)?;
        let bounded = evaluate_payment_collect(&PaymentCollectEvaluationContext {
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
        if bounded.class != PaymentCollectDecisionClass::Eligible {
            return Ok(PaymentCollectWorkflowOutcome::Rejected {
                receipt: Box::new(decision_receipt),
                persisted: true,
            });
        }
        let decision_digest = decision_receipt
            .digest()
            .map_err(|_| MerchantServiceError::Canonicalization)?;
        let required_configuration_digest = request
            .required_configuration
            .digest()
            .map_err(|_| MerchantServiceError::Canonicalization)?;
        let executed_configuration_digest = self
            .dependencies
            .executed_configuration
            .digest()
            .map_err(|_| MerchantServiceError::Canonicalization)?;
        let idempotency_key = payment_collect_idempotency_key(
            &request.workflow_id,
            &policy_digest,
            &action_digest,
            request.action.stripe_account_id(),
            request.action.connect_account(),
        )?;
        let eligibility = bounded
            .eligibility
            .as_ref()
            .ok_or(MerchantServiceError::Profile)?;
        let reservation = self
            .dependencies
            .store
            .reserve(ReserveMerchantPaymentRequest {
                workflow_id: request.workflow_id.clone(),
                operation: MerchantOperation::Collect,
                exact_action_profile: crate::merchant::PAYMENT_COLLECT_PROFILE.into(),
                action_digest: action_digest.clone(),
                decision_receipt_digest: decision_digest.clone(),
                policy_digest: policy_digest.clone(),
                evaluator_semantic_id: MERCHANT_EVALUATOR_ID.into(),
                evaluator_semantic_version: MERCHANT_EVALUATOR_VERSION,
                evidence_digest,
                required_configuration_digest: required_configuration_digest.clone(),
                executed_configuration_digest: executed_configuration_digest.clone(),
                stripe_account_id: request.action.stripe_account_id().clone(),
                connect_account: request.action.connect_account().clone(),
                customer_id: request.action.customer_id().clone(),
                order_scope: request.action.order_scope().into(),
                currency: request.action.currency().clone(),
                amount_minor: request.action.amount_minor(),
                intents: eligibility.reservations.clone(),
                idempotency_key_digest: sha256(idempotency_key.as_bytes()),
                now,
            });
        let (lease, reserved) = match reservation {
            ReserveMerchantPaymentResult::Reserved { lease, record } => (lease, record),
            ReserveMerchantPaymentResult::Replay(record) => {
                return Ok(PaymentCollectWorkflowOutcome::Replay { record });
            }
            ReserveMerchantPaymentResult::Conflict(record) => {
                return Ok(PaymentCollectWorkflowOutcome::Conflict { record });
            }
            ReserveMerchantPaymentResult::CapacityExceeded {
                budget_id,
                available_minor,
            } => {
                return Ok(PaymentCollectWorkflowOutcome::CapacityChanged {
                    budget_id,
                    available_minor,
                });
            }
            ReserveMerchantPaymentResult::Unavailable => {
                return Err(MerchantServiceError::State);
            }
        };
        self.append_transition(
            &decision_digest,
            "reserved",
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
            .claim(&lease, now)
            .map_err(|_| MerchantServiceError::State)?;
        self.append_transition(
            &decision_digest,
            "claimed",
            claimed,
            false,
            false,
            false,
            false,
            now,
        )?;

        let command = VerifiedPaymentCollectCommand::new(
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

        // Credential access is strictly after durable decision, reservation,
        // and exact-action claim.
        let credential = match self
            .dependencies
            .credential_provider
            .mutation_credential(command.action().stripe_account_id())
        {
            Ok(credential) => credential,
            Err(error) => {
                let released = self
                    .dependencies
                    .store
                    .release(&lease, now)
                    .map_err(|_| MerchantServiceError::State)?;
                self.append_transition(
                    &decision_digest,
                    "released-before-provider",
                    released,
                    false,
                    true,
                    false,
                    false,
                    now,
                )?;
                return Err(MerchantServiceError::Port(error));
            }
        };
        let critical = match self.dependencies.stripe_gateway.reread_critical_evidence(
            &command,
            &credential,
            now,
        ) {
            Ok(evidence) => evidence,
            Err(error) => {
                let released = self
                    .dependencies
                    .store
                    .release(&lease, now)
                    .map_err(|_| MerchantServiceError::State)?;
                self.append_transition(
                    &decision_digest,
                    "released-critical-read-failed",
                    released,
                    false,
                    true,
                    false,
                    false,
                    now,
                )?;
                return Err(MerchantServiceError::Port(error));
            }
        };
        if !command.evidence().critical_scope_matches(&critical) {
            let released = self
                .dependencies
                .store
                .release(&lease, now)
                .map_err(|_| MerchantServiceError::State)?;
            self.append_transition(
                &decision_digest,
                "released-critical-evidence-changed",
                released.clone(),
                false,
                true,
                false,
                false,
                now,
            )?;
            return Ok(PaymentCollectWorkflowOutcome::CriticalEvidenceChanged { record: released });
        }
        let attempting = self
            .dependencies
            .store
            .mark_attempting(&lease, now)
            .map_err(|_| MerchantServiceError::State)?;
        self.append_transition(
            &decision_digest,
            "attempting",
            attempting,
            true,
            true,
            true,
            false,
            now,
        )?;

        let effect = match self
            .dependencies
            .stripe_gateway
            .collect(&command, &credential, now)
        {
            Ok(effect) => effect,
            Err(_) => PaymentCollectEffect::OutcomeUnknown(None),
        };
        match effect {
            PaymentCollectEffect::NotDelivered { code } => {
                let released = self
                    .dependencies
                    .store
                    .release(&lease, now)
                    .map_err(|_| MerchantServiceError::State)?;
                self.append_transition(
                    &decision_digest,
                    "provider-not-delivered-released",
                    released.clone(),
                    true,
                    true,
                    false,
                    false,
                    now,
                )?;
                Ok(PaymentCollectWorkflowOutcome::NotDelivered {
                    code,
                    record: released,
                })
            }
            PaymentCollectEffect::Declined { code } => {
                let released = self
                    .dependencies
                    .store
                    .release(&lease, now)
                    .map_err(|_| MerchantServiceError::State)?;
                self.append_transition(
                    &decision_digest,
                    "provider-declined-released",
                    released.clone(),
                    true,
                    true,
                    true,
                    false,
                    now,
                )?;
                Ok(PaymentCollectWorkflowOutcome::ProviderDeclined {
                    code,
                    record: released,
                })
            }
            PaymentCollectEffect::OutcomeUnknown(provider) => {
                self.unknown(&decision_digest, &lease, provider, now)
            }
            PaymentCollectEffect::Processing(provider) => {
                self.unknown(&decision_digest, &lease, Some(provider), now)
            }
            PaymentCollectEffect::CustomerActionRequired(provider) => {
                let unknown = self
                    .dependencies
                    .store
                    .mark_outcome_unknown(&lease, Some(provider), now)
                    .map_err(|_| MerchantServiceError::State)?;
                self.append_transition(
                    &decision_digest,
                    "customer-action-required-outcome-unknown",
                    unknown.clone(),
                    true,
                    true,
                    true,
                    false,
                    now,
                )?;
                Ok(PaymentCollectWorkflowOutcome::CustomerActionRequired { record: unknown })
            }
            PaymentCollectEffect::Accepted(provider) => self.finish_accepted(
                &command,
                &credential,
                &decision_digest,
                &lease,
                provider,
                now,
            ),
        }
    }

    /// Reconciles a durable ambiguous workflow without issuing create again.
    ///
    /// # Errors
    ///
    /// Returns a closed state, credential, provider, receipt, or
    /// canonicalization failure.
    pub fn reconcile(
        &self,
        workflow_id: &str,
    ) -> Result<PaymentCollectWorkflowOutcome, MerchantServiceError> {
        let now = self.dependencies.clock.now()?;
        let record = self
            .dependencies
            .store
            .get(workflow_id)
            .map_err(|_| MerchantServiceError::State)?
            .ok_or(MerchantServiceError::NotFound)?;
        if matches!(
            record.state(),
            MerchantReservationState::Committed
                | MerchantReservationState::ReconciledCommitted
                | MerchantReservationState::Released
                | MerchantReservationState::ReconciledReleased
        ) {
            return Ok(PaymentCollectWorkflowOutcome::Replay { record });
        }
        let credential = self
            .dependencies
            .credential_provider
            .mutation_credential(record.stripe_account_id())?;
        let outcome = self
            .dependencies
            .stripe_gateway
            .reconcile(&record, &credential, now)
            .unwrap_or(PaymentCollectReconciliationOutcome::OutcomeUnknown(None));
        let outcome = normalize_collection_reconciliation(&record, outcome);
        let provider = reconciled_provider(&outcome).cloned();
        let reconciled = self
            .dependencies
            .store
            .reconcile_collection(workflow_id, record.action_digest(), outcome, now)
            .map_err(|_| MerchantServiceError::State)?;
        if let Some(provider) = provider {
            self.append_observation(
                &reconciled,
                provider,
                matches!(
                    reconciled.state(),
                    MerchantReservationState::ReconciledCommitted
                ),
                true,
                now,
            )?;
        }
        let transition = self.append_transition(
            record.decision_receipt_digest(),
            "reconciled",
            reconciled.clone(),
            false,
            true,
            true,
            true,
            now,
        )?;
        Ok(PaymentCollectWorkflowOutcome::Reconciled {
            record: reconciled,
            receipt: Box::new(transition),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn decision_receipt(
        &self,
        request: &ExecutePaymentCollectRequest,
        policy_digest: DigestHex,
        action_digest: DigestHex,
        evidence_digest: DigestHex,
        aggregate_before: MerchantAggregateSnapshot,
        auths_decision: &str,
        auths_code: String,
        authorization_established: bool,
        bounded_decision: Option<PaymentCollectDecision>,
        now: u64,
    ) -> MerchantCollectionDecisionReceipt {
        MerchantCollectionDecisionReceipt {
            schema: "auths.stripe.payment-collect-decision-receipt/1".into(),
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
        command: &VerifiedPaymentCollectCommand,
        credential: &crate::ports::StripeCredential,
        decision_digest: &DigestHex,
        lease: &crate::merchant::state::MerchantReservationLease,
        provider: MerchantProviderProjection,
        now: u64,
    ) -> Result<PaymentCollectWorkflowOutcome, MerchantServiceError> {
        let accepted = self
            .dependencies
            .store
            .record_provider_accepted(lease, provider.clone(), now)
            .map_err(|_| MerchantServiceError::State)?;
        self.append_transition(
            decision_digest,
            "provider-accepted",
            accepted,
            true,
            true,
            true,
            false,
            now,
        )?;
        if provider.status != "succeeded" {
            return self.unknown(decision_digest, lease, Some(provider), now);
        }
        let Ok(observed) = self.dependencies.stripe_gateway.observe(
            command,
            credential,
            &provider.payment_intent_id,
            now,
        ) else {
            return self.unknown(decision_digest, lease, Some(provider), now);
        };
        let exact = exact_collection_projection(command.action(), &observed);
        self.append_observation_from_command(command, lease, observed.clone(), exact, false, now)?;
        if !exact {
            return self.unknown(decision_digest, lease, Some(observed), now);
        }
        let committed = self
            .dependencies
            .store
            .commit_collection(lease, now)
            .map_err(|_| MerchantServiceError::State)?;
        let receipt = self.append_transition(
            decision_digest,
            "committed",
            committed.clone(),
            true,
            true,
            true,
            true,
            now,
        )?;
        Ok(PaymentCollectWorkflowOutcome::Collected {
            record: committed,
            receipt: Box::new(receipt),
        })
    }

    fn unknown(
        &self,
        decision_digest: &DigestHex,
        lease: &crate::merchant::state::MerchantReservationLease,
        provider: Option<MerchantProviderProjection>,
        now: u64,
    ) -> Result<PaymentCollectWorkflowOutcome, MerchantServiceError> {
        let record = self
            .dependencies
            .store
            .mark_outcome_unknown(lease, provider, now)
            .map_err(|_| MerchantServiceError::State)?;
        let receipt = self.append_transition(
            decision_digest,
            "outcome-unknown",
            record.clone(),
            true,
            true,
            true,
            false,
            now,
        )?;
        Ok(PaymentCollectWorkflowOutcome::OutcomeUnknown {
            record,
            receipt: Box::new(receipt),
        })
    }

    fn append_decision(
        &self,
        receipt: &MerchantCollectionDecisionReceipt,
    ) -> Result<(), MerchantServiceError> {
        self.dependencies
            .receipt_sink
            .append(&StripeReceipt::MerchantCollectionDecision(Box::new(
                receipt.clone(),
            )))
            .map_err(MerchantServiceError::Port)
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::fn_params_excessive_bools,
        reason = "receipt transition facts remain independent and visibly ordered"
    )]
    fn append_transition(
        &self,
        decision_digest: &DigestHex,
        transition: &str,
        reservation: MerchantReservationRecord,
        execution_attempted: bool,
        credential_requested: bool,
        stripe_called: bool,
        reconciled_observation: bool,
        now: u64,
    ) -> Result<MerchantCollectionTransitionReceipt, MerchantServiceError> {
        let receipt = MerchantCollectionTransitionReceipt {
            schema: "auths.stripe.payment-collect-transition-receipt/1".into(),
            decision_receipt_digest: decision_digest.clone(),
            exact_action_profile: reservation.exact_action_profile().into(),
            operation: reservation.operation(),
            action_digest: reservation.action_digest().clone(),
            policy_digest: reservation.policy_digest().clone(),
            required_configuration_digest: reservation.required_configuration_digest().clone(),
            executed_configuration_digest: reservation.executed_configuration_digest().clone(),
            semantic_event: transition.into(),
            resulting_state: reservation.state(),
            provider_accepted: reservation.provider().is_some(),
            reservation,
            authorization_established: true,
            execution_attempted,
            credential_requested,
            stripe_called,
            reconciled_observation,
            recorded_at: now,
        };
        self.dependencies
            .receipt_sink
            .append(&StripeReceipt::MerchantCollectionTransition(Box::new(
                receipt.clone(),
            )))
            .map_err(MerchantServiceError::Port)?;
        Ok(receipt)
    }

    fn append_observation_from_command(
        &self,
        command: &VerifiedPaymentCollectCommand,
        lease: &crate::merchant::state::MerchantReservationLease,
        provider: MerchantProviderProjection,
        exact: bool,
        reconciled: bool,
        now: u64,
    ) -> Result<(), MerchantServiceError> {
        let receipt = MerchantCollectionObservationReceipt {
            schema: "auths.stripe.payment-collect-observation-receipt/1".into(),
            workflow_id: command.workflow_id().into(),
            exact_action_profile: command.action().profile().into(),
            operation: MerchantOperation::Collect,
            action_digest: command
                .action()
                .digest()
                .map_err(|_| MerchantServiceError::Canonicalization)?,
            decision_receipt_digest: command.decision_receipt_digest().clone(),
            policy_digest: command.policy_digest().clone(),
            required_configuration_digest: command.required_configuration_digest().clone(),
            executed_configuration_digest: command.executed_configuration_digest().clone(),
            reservation_id: lease.reservation_id().clone(),
            provider,
            exact_provider_equality: exact,
            reconciled,
            residual_assumptions: vec![
                "Stripe test mode is not evidence of live settlement".into(),
                "policy provenance is executor-local trusted configuration".into(),
            ],
            recorded_at: now,
        };
        self.dependencies
            .receipt_sink
            .append(&StripeReceipt::MerchantCollectionObservation(Box::new(
                receipt,
            )))
            .map_err(MerchantServiceError::Port)
    }

    fn append_observation(
        &self,
        record: &MerchantReservationRecord,
        provider: MerchantProviderProjection,
        exact: bool,
        reconciled: bool,
        now: u64,
    ) -> Result<(), MerchantServiceError> {
        let receipt = MerchantCollectionObservationReceipt {
            schema: "auths.stripe.payment-collect-observation-receipt/1".into(),
            workflow_id: record.workflow_id().into(),
            exact_action_profile: record.exact_action_profile().into(),
            operation: record.operation(),
            action_digest: record.action_digest().clone(),
            decision_receipt_digest: record.decision_receipt_digest().clone(),
            policy_digest: record.policy_digest().clone(),
            required_configuration_digest: record.required_configuration_digest().clone(),
            executed_configuration_digest: record.executed_configuration_digest().clone(),
            reservation_id: record.reservation_id().clone(),
            provider,
            exact_provider_equality: exact,
            reconciled,
            residual_assumptions: vec![
                "Stripe test mode is not evidence of live settlement".into(),
                "policy provenance is executor-local trusted configuration".into(),
            ],
            recorded_at: now,
        };
        self.dependencies
            .receipt_sink
            .append(&StripeReceipt::MerchantCollectionObservation(Box::new(
                receipt,
            )))
            .map_err(MerchantServiceError::Port)
    }
}

/// Complete workflow outcome with durable ambiguity as data, not failure.
pub enum PaymentCollectWorkflowOutcome {
    /// Proof or bounded policy denied the action.
    Rejected {
        /// Exact receipt.
        receipt: Box<MerchantCollectionDecisionReceipt>,
        /// Configuration mismatch is intentionally not persisted.
        persisted: bool,
    },
    /// Automatic collection was observed exactly once.
    Collected {
        /// Durable committed state.
        record: MerchantReservationRecord,
        /// Final transition receipt.
        receipt: Box<MerchantCollectionTransitionReceipt>,
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
    /// Atomic aggregate capacity changed after pure evaluation.
    CapacityChanged {
        /// Stable budget identifier.
        budget_id: String,
        /// Capacity observed atomically.
        available_minor: u64,
    },
    /// Critical execution evidence changed after claim.
    CriticalEvidenceChanged {
        /// Released durable state.
        record: MerchantReservationRecord,
    },
    /// Adapter proved the create request never left the executor.
    NotDelivered {
        /// Stable non-secret transport category.
        code: String,
        /// Released durable state.
        record: MerchantReservationRecord,
    },
    /// Stripe definitively declined.
    ProviderDeclined {
        /// Stable non-secret provider category.
        code: String,
        /// Released durable state.
        record: MerchantReservationRecord,
    },
    /// Customer action would be required and V1 will not continue.
    CustomerActionRequired {
        /// Conservatively retained durable state.
        record: MerchantReservationRecord,
    },
    /// Stripe delivery or outcome is ambiguous.
    OutcomeUnknown {
        /// Capacity-retaining durable state.
        record: MerchantReservationRecord,
        /// Final transition receipt.
        receipt: Box<MerchantCollectionTransitionReceipt>,
    },
    /// Retrieval reconciled prior durable state.
    Reconciled {
        /// Reconciled durable state.
        record: MerchantReservationRecord,
        /// Reconciliation transition receipt.
        receipt: Box<MerchantCollectionTransitionReceipt>,
    },
}

#[derive(Serialize)]
struct PaymentCollectIdempotencyIdentity<'a> {
    schema: &'static str,
    workflow_id: &'a str,
    operation: &'static str,
    policy_digest: &'a DigestHex,
    action_digest: &'a DigestHex,
    stripe_account_id: &'a crate::types::StripeAccountId,
    connect_account: &'a crate::merchant::MerchantConnectAccount,
}

fn payment_collect_idempotency_key(
    workflow_id: &str,
    policy_digest: &DigestHex,
    action_digest: &DigestHex,
    stripe_account_id: &crate::types::StripeAccountId,
    connect_account: &crate::merchant::MerchantConnectAccount,
) -> Result<String, MerchantServiceError> {
    let digest = canonical_digest(&PaymentCollectIdempotencyIdentity {
        schema: "auths.stripe.payment-collect-idempotency/1",
        workflow_id,
        operation: "collect",
        policy_digest,
        action_digest,
        stripe_account_id,
        connect_account,
    })
    .map_err(|_| MerchantServiceError::Canonicalization)?;
    Ok(format!("auths-pc-{}", &digest.as_str()[..48]))
}

fn exact_collection_projection(
    action: &StripeExactPaymentCollectV1,
    provider: &MerchantProviderProjection,
) -> bool {
    provider.status == "succeeded"
        && provider.amount_minor == action.amount_minor()
        && provider.amount_received_minor == action.amount_minor()
        && provider.amount_capturable_minor == 0
        && provider.currency == *action.currency()
        && provider.charge_id.is_some()
}

fn normalize_collection_reconciliation(
    record: &MerchantReservationRecord,
    outcome: PaymentCollectReconciliationOutcome,
) -> PaymentCollectReconciliationOutcome {
    match outcome {
        PaymentCollectReconciliationOutcome::Committed(provider)
            if provider.status == "succeeded"
                && provider.amount_minor == record.amount_minor()
                && provider.amount_received_minor == record.amount_minor()
                && provider.amount_capturable_minor == 0
                && provider.currency == *record.currency()
                && provider.charge_id.is_some() =>
        {
            PaymentCollectReconciliationOutcome::Committed(provider)
        }
        PaymentCollectReconciliationOutcome::Released(provider) => {
            PaymentCollectReconciliationOutcome::Released(provider)
        }
        PaymentCollectReconciliationOutcome::OutcomeUnknown(provider) => {
            PaymentCollectReconciliationOutcome::OutcomeUnknown(provider)
        }
        PaymentCollectReconciliationOutcome::Committed(provider) => {
            PaymentCollectReconciliationOutcome::OutcomeUnknown(Some(provider))
        }
    }
}

fn reconciled_provider(
    outcome: &PaymentCollectReconciliationOutcome,
) -> Option<&MerchantProviderProjection> {
    match outcome {
        PaymentCollectReconciliationOutcome::Committed(provider) => Some(provider),
        PaymentCollectReconciliationOutcome::Released(provider)
        | PaymentCollectReconciliationOutcome::OutcomeUnknown(provider) => provider.as_ref(),
    }
}

/// Closed merchant collection service error.
#[derive(Debug, thiserror::Error)]
pub enum MerchantServiceError {
    /// Exact profile canonicalization or decode failed.
    #[error("exact Stripe payment profile rejected the action")]
    Profile,
    /// Canonical digest or receipt identity failed.
    #[error("could not canonicalize Stripe payment workflow data")]
    Canonicalization,
    /// Durable reservation, claim, or replay state failed.
    #[error("Stripe payment workflow state is unavailable")]
    State,
    /// Workflow was not found.
    #[error("Stripe payment workflow was not found")]
    NotFound,
    /// Closed port failure.
    #[error(transparent)]
    Port(#[from] PortError),
}
