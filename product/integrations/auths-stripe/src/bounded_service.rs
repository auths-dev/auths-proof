//! Protected execution path for one exact refund inside configured bounds.

use auths_bounded_policy::{CommitmentDigest, EvidenceSourceId, VerifierTime};
use auths_lifecycle::{
    CapacitySnapshotV1, DomainReceiptDigest, DurableTransitionV1, EffectConclusion,
    ExecutionAuthorizationV1, ExecutionIntentV1, LifecycleFailure, LifecycleState,
    ObservationDigest, ProviderCallAuthorizationV1, ProviderConditionDigest, ProviderContractId,
    ProviderRequestDigest, ProviderResultDigest, ProviderRetryClass, ReconciliationId,
    ReconciliationObservationV1, RevocationSnapshotV1, StoreError, StoreTransactionV1,
    TransitionCommandV1, TransitionContextV1, TransitionDisposition, WorkflowId,
    execute_store_transaction,
};
use auths_profile_api::ActionProfile as _;
use auths_sdk::{Authorized, RequestContext};

use crate::{
    bounded::{
        BoundedDecisionClass, BoundedEvaluationContext, BoundedRefundDecision,
        BoundedRefundEligibility, StripeBoundedEvaluatorConfigurationV1,
        StripeBoundedRefundPolicyV1, evaluate_bounded_refund,
    },
    canonical::{canonical_digest, sha256},
    executor::LifecycleVerifiedRefundCommand,
    lifecycle::{
        StripeLifecycleDecisionBindings, StripeLifecycleProjectionInput, project_refund_lifecycle,
    },
    ports::{
        Clock, LifecycleRefundCredentialProvider, PortError, ProofDecision, ProofVerifier,
        ReceiptSink, StripeGateway,
    },
    profile::{StripeRefundCommand, StripeRefundProfile},
    receipts::{
        BoundedDecisionReceipt, BoundedDecisionReceiptInput, ExecutionReceipt, ReservationReceipt,
        StripeReceipt, execution_receipt,
    },
    reservation::{
        ReconciledRefundOutcome, RefundLifecycleMutation, RefundLifecycleStore,
        RefundLifecycleTransaction, RefundReservationLease, RefundReservationRecord,
        RefundReservationStore, ReserveRefundRequest,
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
pub struct BoundedServiceDependencies<V, C, G, B, R, T> {
    /// Auths kernel adapter.
    pub proof_verifier: V,
    /// Mutation credential broker.
    pub credential_provider: C,
    /// Only Stripe write adapter.
    pub stripe_gateway: G,
    /// Atomic shared lifecycle and Stripe-local aggregate reservation state.
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
pub struct BoundedRefundService<V, C, G, B, R, T> {
    dependencies: BoundedServiceDependencies<V, C, G, B, R, T>,
}

impl<V, C, G, B, R, T> BoundedRefundService<V, C, G, B, R, T>
where
    V: ProofVerifier,
    C: LifecycleRefundCredentialProvider,
    G: StripeGateway,
    B: RefundLifecycleStore,
    R: ReceiptSink<StripeReceipt>,
    T: Clock,
{
    /// Constructs the service from explicit trusted dependencies.
    #[must_use]
    pub const fn new(dependencies: BoundedServiceDependencies<V, C, G, B, R, T>) -> Self {
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
            aggregate_before: aggregate_before.clone(),
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

        let requested_workflow =
            WorkflowId::parse(request.action.workflow_id()).map_err(|_| ServiceError::Profile)?;
        if let Some(existing) = self
            .dependencies
            .reservation_store
            .load_refund_lifecycle(&requested_workflow)
            .map_err(store_failure)?
            && matches!(
                existing.state(),
                LifecycleState::Executing
                    | LifecycleState::OutcomeUnknown
                    | LifecycleState::Committed
                    | LifecycleState::Released
                    | LifecycleState::ReconciledCommitted
                    | LifecycleState::ReconciledReleased
            )
        {
            let reservation = self
                .dependencies
                .reservation_store
                .get(request.action.workflow_id())
                .map_err(|_| ServiceError::ClaimState)?
                .ok_or(ServiceError::ClaimState)?;
            return if existing.decision_input().commitments.exact_action_digest()
                == commitment(&action_digest)?
            {
                Ok(BoundedWorkflowOutcome::Replay { reservation })
            } else {
                Ok(BoundedWorkflowOutcome::Conflict { reservation })
            };
        }

        let projection = project_refund_lifecycle(&StripeLifecycleProjectionInput {
            action: &request.action,
            policy: &request.policy,
            evidence: &request.evidence,
            aggregate_snapshot: &aggregate_before,
            decision: &bounded_decision,
            required_configuration: &request.required_bounded_configuration,
            executed_configuration: &self.dependencies.executed_bounded_configuration,
            verifier_time: now,
        })
        .map_err(|_| ServiceError::Profile)?;
        let lifecycle_context = projection.transition_context(now);
        let core_authorization_digest = core_authorization_digest(&authorized);

        // The decision receipt is durable before aggregate reservation.
        self.append(&StripeReceipt::BoundedDecision(Box::new(
            decision_receipt.clone(),
        )))?;
        let decision_receipt_digest = decision_receipt
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        let workflow_id = projection.workflow_id.clone();
        let implementation_build_digest = implementation_build_digest();
        let decision_input = projection
            .into_decision_input(&StripeLifecycleDecisionBindings {
                core_authorization_digest: &core_authorization_digest,
                decision_receipt_digest: &decision_receipt_digest,
                domain_decision_receipt_digest: &decision_receipt_digest,
                implementation_build_digest: &implementation_build_digest,
                expires_at: request.action.expires_at(),
            })
            .map_err(|_| ServiceError::Profile)?;
        let existing_lifecycle = self
            .dependencies
            .reservation_store
            .load_refund_lifecycle(&workflow_id)
            .map_err(store_failure)?;
        let recorded = execute_store_transaction(
            &RefundLifecycleTransaction::new(
                &self.dependencies.reservation_store,
                RefundLifecycleMutation::None,
            ),
            &StoreTransactionV1 {
                workflow_id: workflow_id.clone(),
                expected_revision: existing_lifecycle
                    .as_ref()
                    .map(auths_lifecycle::LifecycleRecordV1::revision),
                command: TransitionCommandV1::RecordDecision(Box::new(decision_input)),
                context: lifecycle_context.clone(),
            },
        )
        .map_err(store_failure)?;
        if recorded.disposition() == TransitionDisposition::ExactReplay
            && recorded.record().state() != LifecycleState::DecisionRecorded
        {
            let reservation = self
                .dependencies
                .reservation_store
                .get(request.action.workflow_id())
                .map_err(|_| ServiceError::ClaimState)?
                .ok_or(ServiceError::ClaimState)?;
            return Ok(BoundedWorkflowOutcome::Replay { reservation });
        }
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
        let reserve_request = ReserveRefundRequest {
            workflow_id: request.action.workflow_id().into(),
            action_digest: action_digest.clone(),
            decision_receipt_digest: decision_receipt_digest.clone(),
            policy_digest,
            evaluator_semantic_id: request.policy.evaluator_semantic_id().into(),
            evaluator_semantic_version: request.policy.evaluator_semantic_version(),
            evidence_digest: evidence_digest.clone(),
            required_configuration_digest: required_bounded_digest,
            executed_configuration_digest: executed_bounded_digest,
            stripe_account_id: request.action.stripe_account_id().clone(),
            currency: request.action.amount().currency().clone(),
            amount_minor: request.action.amount().amount_minor(),
            intents: eligibility.reservations.clone(),
            idempotency_key_digest: sha256(request.action.idempotency_key().as_bytes()),
            now,
        };
        let reserved = execute_store_transaction(
            &RefundLifecycleTransaction::new(
                &self.dependencies.reservation_store,
                RefundLifecycleMutation::Reserve {
                    policy: &request.policy,
                    request: Box::new(reserve_request),
                },
            ),
            &StoreTransactionV1 {
                workflow_id: workflow_id.clone(),
                expected_revision: Some(recorded.record().revision()),
                command: TransitionCommandV1::Reserve,
                context: lifecycle_context.clone(),
            },
        );
        let reserved = match reserved {
            Ok(reserved) => reserved,
            Err(StoreError::Rejected(LifecycleFailure::CapacityExceeded)) => {
                let (budget_id, available_minor) = changed_capacity(
                    &self.dependencies.reservation_store,
                    &request.policy,
                    &request.action,
                    eligibility,
                    now,
                )?;
                return Ok(BoundedWorkflowOutcome::CapacityChanged {
                    decision: bounded_decision,
                    budget_id,
                    available_minor,
                });
            }
            Err(StoreError::Conflict) => {
                let existing = self
                    .dependencies
                    .reservation_store
                    .get(request.action.workflow_id())
                    .map_err(|_| ServiceError::ClaimState)?
                    .ok_or(ServiceError::ClaimState)?;
                return if existing.action_digest() == &action_digest {
                    Ok(BoundedWorkflowOutcome::Replay {
                        reservation: existing,
                    })
                } else {
                    Ok(BoundedWorkflowOutcome::Conflict {
                        reservation: existing,
                    })
                };
            }
            Err(error) => return Err(store_failure(error)),
        };
        let reserved_record = self
            .dependencies
            .reservation_store
            .get(request.action.workflow_id())
            .map_err(|_| ServiceError::ClaimState)?
            .ok_or(ServiceError::ClaimState)?;
        let reservation_lease = RefundReservationLease::from_record(&reserved_record);
        self.append(&StripeReceipt::Reservation(Box::new(ReservationReceipt {
            schema: "auths.stripe.bounded-reservation-receipt/1".into(),
            decision_receipt_digest: decision_receipt_digest.clone(),
            reservation: reserved_record.clone(),
            credential_requested: false,
            stripe_called: false,
            recorded_at: now,
        })))?;

        let execution_intent = ExecutionIntentV1::new(
            commitment(&action_digest)?,
            ProviderRequestDigest::new(digest_bytes(&action_digest)?),
            ProviderConditionDigest::new(digest_bytes(&evidence_digest)?),
            ProviderContractId::parse("auths.stripe.refund-create/1")
                .map_err(|_| ServiceError::Profile)?,
            ProviderRetryClass::ExactIdempotent,
        );
        let intent_recorded = lifecycle_transition(
            &self.dependencies.reservation_store,
            &workflow_id,
            reserved.record().revision(),
            TransitionCommandV1::RecordExecutionIntent(execution_intent),
            lifecycle_context.clone(),
            RefundLifecycleMutation::None,
        )?;
        let credential_stage = lifecycle_transition(
            &self.dependencies.reservation_store,
            &workflow_id,
            intent_recorded.record().revision(),
            TransitionCommandV1::AuthorizeCredential,
            lifecycle_context.clone(),
            RefundLifecycleMutation::None,
        )?;
        let credential_authorization = ExecutionAuthorizationV1::from_durable(&credential_stage)
            .map_err(|_| ServiceError::ClaimState)?;

        // Credential acquisition is type-gated by the newly durable shared
        // lifecycle authorization.
        let credential = match self
            .dependencies
            .credential_provider
            .credential_after_authorization(
                &credential_authorization,
                request.action.stripe_account_id(),
            ) {
            Ok(credential) => credential,
            Err(error) => {
                release_lifecycle(
                    &self.dependencies.reservation_store,
                    &workflow_id,
                    credential_stage.record().revision(),
                    lifecycle_context.clone(),
                    &reservation_lease,
                    &action_digest,
                    now,
                )?;
                return Err(ServiceError::Port(error));
            }
        };
        let attempt = lifecycle_transition(
            &self.dependencies.reservation_store,
            &workflow_id,
            credential_stage.record().revision(),
            TransitionCommandV1::StartAttempt,
            lifecycle_context.clone(),
            RefundLifecycleMutation::None,
        )?;
        let call_entry = lifecycle_transition(
            &self.dependencies.reservation_store,
            &workflow_id,
            attempt.record().revision(),
            TransitionCommandV1::MarkProviderCallEntered,
            lifecycle_context.clone(),
            RefundLifecycleMutation::None,
        )?;
        let call_authorization = ProviderCallAuthorizationV1::from_durable(&call_entry)
            .map_err(|_| ServiceError::ClaimState)?;
        let command =
            LifecycleVerifiedRefundCommand::new(authorized, request.evidence, call_authorization);
        let result =
            match self
                .dependencies
                .stripe_gateway
                .create_refund(&command, &credential, now)
            {
                Ok(result) => result,
                Err(PortError::OutcomeUnknown) => {
                    let reservation = mark_unknown_lifecycle(
                        &self.dependencies.reservation_store,
                        &workflow_id,
                        call_entry.record().revision(),
                        lifecycle_context.clone(),
                        &reservation_lease,
                        &action_digest,
                        now,
                    )?;
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
                    release_lifecycle(
                        &self.dependencies.reservation_store,
                        &workflow_id,
                        call_entry.record().revision(),
                        lifecycle_context.clone(),
                        &reservation_lease,
                        &action_digest,
                        now,
                    )?;
                    return Err(ServiceError::Port(error));
                }
            };
        if validate_result(command.action(), &result).is_err() {
            let reservation = mark_unknown_lifecycle(
                &self.dependencies.reservation_store,
                &workflow_id,
                call_entry.record().revision(),
                lifecycle_context.clone(),
                &reservation_lease,
                &action_digest,
                now,
            )?;
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
        let execution = execution_receipt(
            self.dependencies
                .executed_exact_configuration
                .receipt_schema_version(),
            decision_receipt_digest.clone(),
            command.action(),
            &result,
        )
        .map_err(|_| ServiceError::Canonicalization)?;
        let execution_digest = execution
            .digest()
            .map_err(|_| ServiceError::Canonicalization)?;
        lifecycle_transition(
            &self.dependencies.reservation_store,
            &workflow_id,
            call_entry.record().revision(),
            TransitionCommandV1::Commit {
                result_digest: ProviderResultDigest::new(digest_bytes(&result_digest)?),
                domain_receipt_digest: DomainReceiptDigest::new(digest_bytes(&execution_digest)?),
            },
            lifecycle_context,
            RefundLifecycleMutation::Commit {
                lease: &reservation_lease,
                refund_id: &result.refund_id,
                result_digest: &result_digest,
                now,
            },
        )?;
        let committed = self
            .dependencies
            .reservation_store
            .get(request.action.workflow_id())
            .map_err(|_| ServiceError::ClaimState)?
            .ok_or(ServiceError::ClaimState)?;
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

/// Atomically reconciles one ambiguous Stripe refund in both the shared
/// lifecycle and Stripe aggregate-capacity views.
///
/// # Errors
///
/// Fails closed for a missing/non-ambiguous workflow, malformed identifiers,
/// stale arithmetic, or any non-durable shared/domain transition.
pub fn reconcile_bounded_refund(
    store: &impl RefundLifecycleStore,
    workflow: &str,
    action_digest: &crate::types::DigestHex,
    outcome: ReconciledRefundOutcome,
    now: u64,
) -> Result<RefundReservationRecord, ServiceError> {
    let workflow_id = WorkflowId::parse(workflow).map_err(|_| ServiceError::Profile)?;
    let lifecycle = store
        .load_refund_lifecycle(&workflow_id)
        .map_err(store_failure)?
        .ok_or(ServiceError::ClaimState)?;
    let provider_request_digest = lifecycle
        .execution_intent()
        .map(ExecutionIntentV1::provider_request_digest)
        .ok_or(ServiceError::ClaimState)?;
    let conclusion = match &outcome {
        ReconciledRefundOutcome::Committed { .. } => EffectConclusion::Effect,
        ReconciledRefundOutcome::Released => EffectConclusion::NonEffect,
    };
    let event = lifecycle_event_digest(b"stripe-refund-reconciliation", action_digest, now);
    let reconciliation_id =
        ReconciliationId::parse(event.as_str()).map_err(|_| ServiceError::Canonicalization)?;
    let observation = ReconciliationObservationV1::new(
        reconciliation_id,
        EvidenceSourceId::parse("stripe-api-refund-list/1").map_err(|_| ServiceError::Profile)?,
        VerifierTime::from_unix_seconds(now),
        VerifierTime::from_unix_seconds(
            now.checked_add(300).ok_or(ServiceError::Canonicalization)?,
        ),
        ObservationDigest::new(digest_bytes(&event)?),
        conclusion,
        provider_request_digest,
    );
    let context = TransitionContextV1 {
        verifier_time: VerifierTime::from_unix_seconds(now),
        executed_configuration: lifecycle
            .decision_input()
            .commitments
            .executed_configuration()
            .clone(),
        revocation: RevocationSnapshotV1 {
            revoked: false,
            snapshot_digest: commitment(&sha256(b"auths.stripe.revocation-not-configured/1"))?,
        },
        capacity: CapacitySnapshotV1::new(Vec::new()).map_err(|_| ServiceError::Profile)?,
    };
    lifecycle_transition(
        store,
        &workflow_id,
        lifecycle.revision(),
        TransitionCommandV1::Reconcile {
            observation,
            domain_receipt_digest: DomainReceiptDigest::new(digest_bytes(&event)?),
        },
        context,
        RefundLifecycleMutation::Reconcile {
            workflow_id: workflow,
            action_digest,
            outcome,
            now,
        },
    )?;
    store
        .get(workflow)
        .map_err(|_| ServiceError::ClaimState)?
        .ok_or(ServiceError::ClaimState)
}

fn lifecycle_transition(
    store: &impl RefundLifecycleStore,
    workflow_id: &WorkflowId,
    revision: u64,
    command: TransitionCommandV1,
    context: TransitionContextV1,
    mutation: RefundLifecycleMutation<'_>,
) -> Result<DurableTransitionV1, ServiceError> {
    execute_store_transaction(
        &RefundLifecycleTransaction::new(store, mutation),
        &StoreTransactionV1 {
            workflow_id: workflow_id.clone(),
            expected_revision: Some(revision),
            command,
            context,
        },
    )
    .map_err(store_failure)
}

fn release_lifecycle(
    store: &impl RefundLifecycleStore,
    workflow_id: &WorkflowId,
    revision: u64,
    context: TransitionContextV1,
    lease: &RefundReservationLease,
    action_digest: &crate::types::DigestHex,
    now: u64,
) -> Result<(), ServiceError> {
    let event = lifecycle_event_digest(b"stripe-definite-non-effect", action_digest, now);
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
        RefundLifecycleMutation::Release { lease, now },
    )?;
    Ok(())
}

fn mark_unknown_lifecycle(
    store: &impl RefundLifecycleStore,
    workflow_id: &WorkflowId,
    revision: u64,
    context: TransitionContextV1,
    lease: &RefundReservationLease,
    action_digest: &crate::types::DigestHex,
    now: u64,
) -> Result<RefundReservationRecord, ServiceError> {
    let event = lifecycle_event_digest(b"stripe-provider-outcome-unknown", action_digest, now);
    lifecycle_transition(
        store,
        workflow_id,
        revision,
        TransitionCommandV1::MarkOutcomeUnknown {
            domain_receipt_digest: DomainReceiptDigest::new(digest_bytes(&event)?),
        },
        context,
        RefundLifecycleMutation::OutcomeUnknown { lease, now },
    )?;
    store
        .get(workflow_id.as_str())
        .map_err(|_| ServiceError::ClaimState)?
        .ok_or(ServiceError::ClaimState)
}

fn changed_capacity(
    store: &impl RefundReservationStore,
    policy: &StripeBoundedRefundPolicyV1,
    action: &ExactRefundActionV1,
    eligibility: &BoundedRefundEligibility,
    now: u64,
) -> Result<(String, u64), ServiceError> {
    let snapshot = store
        .snapshot(policy, action.stripe_account_id(), now)
        .map_err(|_| ServiceError::ClaimState)?;
    for intent in &eligibility.reservations {
        let usage = snapshot
            .usages
            .iter()
            .find(|usage| usage.budget_id == intent.budget_id && usage.window == intent.window);
        let used = usage.map_or(Ok(0), |usage| {
            usage
                .committed_minor
                .checked_add(usage.reserved_minor)
                .and_then(|value| value.checked_add(usage.outcome_unknown_minor))
                .ok_or(ServiceError::ClaimState)
        })?;
        let available = intent
            .limit_minor
            .checked_sub(used)
            .ok_or(ServiceError::ClaimState)?;
        if intent.amount_minor > available {
            return Ok((intent.budget_id.clone(), available));
        }
    }
    Err(ServiceError::ClaimState)
}

fn core_authorization_digest(
    authorized: &Authorized<StripeRefundCommand>,
) -> crate::types::DigestHex {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(authorized.verified().proof_digest().as_bytes());
    bytes.extend_from_slice(authorized.verified().context_digest().as_bytes());
    sha256(&bytes)
}

fn implementation_build_digest() -> crate::types::DigestHex {
    sha256(
        option_env!("AUTHS_BUILD_COMMIT")
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .as_bytes(),
    )
}

fn lifecycle_event_digest(
    domain: &[u8],
    action_digest: &crate::types::DigestHex,
    now: u64,
) -> crate::types::DigestHex {
    let mut bytes = Vec::with_capacity(domain.len() + 72);
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(action_digest.as_str().as_bytes());
    bytes.extend_from_slice(&now.to_be_bytes());
    sha256(&bytes)
}

fn digest_bytes(value: &crate::types::DigestHex) -> Result<[u8; 32], ServiceError> {
    hex::decode(value.as_str())
        .map_err(|_| ServiceError::Canonicalization)?
        .try_into()
        .map_err(|_| ServiceError::Canonicalization)
}

fn commitment(value: &crate::types::DigestHex) -> Result<CommitmentDigest, ServiceError> {
    Ok(CommitmentDigest::new(digest_bytes(value)?))
}

fn store_failure(error: StoreError) -> ServiceError {
    ServiceError::Lifecycle(error)
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
