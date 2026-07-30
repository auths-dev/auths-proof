//! Ordered orchestration for one exact subscription creation.

use std::sync::Arc;

use auths_model::CanonicalAction;
use auths_sdk::RequestContext;

use super::{
    SubscriptionCreateDecisionClass, SubscriptionCreateDecisionReceipt, SubscriptionCreateEffect,
    SubscriptionCreateEvaluationContext, SubscriptionCreateGateway,
    SubscriptionCreateObservationReceipt, SubscriptionCreateProofDecision,
    SubscriptionCreateProofVerifier, SubscriptionCreateReceipt,
    SubscriptionCreateReconciliationOutcome, SubscriptionCreateTransition,
    SubscriptionCreateTransitionReceipt, VerifiedSubscriptionCreateCommand,
    evaluate_subscription_create, transition_subscription_create,
};
use crate::{
    ports::{Clock, CredentialProvider, ReceiptSink, SubscriptionCreateCredentialScope},
    subscription::{
        ReserveSubscriptionLiabilityRequest, ReserveSubscriptionLiabilityResult,
        StripeBoundedSubscriptionPolicyV1, StripeSubscriptionConfigurationV1,
        SubscriptionCreateEvidenceV1, SubscriptionLiabilityRecord, SubscriptionLiabilityState,
        SubscriptionLiabilityStore, SubscriptionProviderProjection,
    },
    types::DigestHex,
};

pub struct ExecuteSubscriptionCreateRequest {
    pub workflow_id: String,
    pub proof: Vec<u8>,
    pub canonical_action: CanonicalAction,
    pub request_context: RequestContext,
    pub action: super::StripeExactSubscriptionCreateV1,
    pub policy: StripeBoundedSubscriptionPolicyV1,
    pub evidence: SubscriptionCreateEvidenceV1,
    pub required_configuration: StripeSubscriptionConfigurationV1,
}

pub struct SubscriptionCreateServiceDependencies {
    pub verifier: Arc<dyn SubscriptionCreateProofVerifier>,
    pub store: Arc<dyn SubscriptionLiabilityStore>,
    pub credentials: Arc<dyn CredentialProvider<SubscriptionCreateCredentialScope>>,
    pub gateway: Arc<dyn SubscriptionCreateGateway>,
    pub receipts: Arc<dyn ReceiptSink<SubscriptionCreateReceipt>>,
    pub clock: Arc<dyn Clock>,
}

pub struct SubscriptionCreateService {
    verifier: Arc<dyn SubscriptionCreateProofVerifier>,
    store: Arc<dyn SubscriptionLiabilityStore>,
    credentials: Arc<dyn CredentialProvider<SubscriptionCreateCredentialScope>>,
    gateway: Arc<dyn SubscriptionCreateGateway>,
    receipts: Arc<dyn ReceiptSink<SubscriptionCreateReceipt>>,
    clock: Arc<dyn Clock>,
    executed_configuration: StripeSubscriptionConfigurationV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubscriptionCreateWorkflowOutcome {
    Denied {
        code: String,
        decision_receipt_digest: DigestHex,
    },
    Indeterminate {
        code: String,
        decision_receipt_digest: DigestHex,
    },
    Active(SubscriptionLiabilityRecord),
    Trialing(SubscriptionLiabilityRecord),
    Incomplete(SubscriptionLiabilityRecord),
    IncompleteExpired(SubscriptionLiabilityRecord),
    OutcomeUnknown(SubscriptionLiabilityRecord),
    Released(SubscriptionLiabilityRecord),
    Replay(SubscriptionLiabilityRecord),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SubscriptionCreateServiceError {
    #[error("subscription-create verification boundary failed")]
    Verification,
    #[error("subscription-create canonicalization failed")]
    Canonical,
    #[error("subscription-create receipt persistence failed")]
    Receipt,
    #[error("subscription-create liability persistence failed")]
    State,
    #[error("subscription-create provider boundary failed")]
    Provider,
    #[error("subscription-create credential unavailable")]
    Credential,
    #[error("subscription-create transition conflict")]
    Transition,
}

impl SubscriptionCreateService {
    pub fn new(
        dependencies: SubscriptionCreateServiceDependencies,
        executed_configuration: StripeSubscriptionConfigurationV1,
    ) -> Self {
        Self {
            verifier: dependencies.verifier,
            store: dependencies.store,
            credentials: dependencies.credentials,
            gateway: dependencies.gateway,
            receipts: dependencies.receipts,
            clock: dependencies.clock,
            executed_configuration,
        }
    }

    pub fn execute(
        &self,
        request: ExecuteSubscriptionCreateRequest,
    ) -> Result<SubscriptionCreateWorkflowOutcome, SubscriptionCreateServiceError> {
        if let Some(record) = self
            .store
            .get(&request.workflow_id)
            .map_err(|_| SubscriptionCreateServiceError::State)?
        {
            return Ok(SubscriptionCreateWorkflowOutcome::Replay(record));
        }

        let now = self
            .clock
            .now()
            .map_err(|_| SubscriptionCreateServiceError::State)?;
        let policy_digest = request
            .policy
            .digest()
            .map_err(|_| SubscriptionCreateServiceError::Canonical)?;
        let action_digest = request
            .action
            .digest()
            .map_err(|_| SubscriptionCreateServiceError::Canonical)?;
        let evidence_digest = request
            .evidence
            .digest()
            .map_err(|_| SubscriptionCreateServiceError::Canonical)?;
        let configuration_equal = request.required_configuration == self.executed_configuration;
        let proof = self
            .verifier
            .verify(
                &request.proof,
                &request.canonical_action,
                &request.request_context,
            )
            .map_err(|_| SubscriptionCreateServiceError::Verification)?;

        let (authorized, auths_decision, auths_code) = match proof {
            SubscriptionCreateProofDecision::Authorized(value) => (
                Some(value),
                "authorized".to_owned(),
                "authorized".to_owned(),
            ),
            SubscriptionCreateProofDecision::Denied { code } => (None, "denied".to_owned(), code),
            SubscriptionCreateProofDecision::Indeterminate { code } => {
                (None, "indeterminate".to_owned(), code)
            }
        };

        let bounded_decision = authorized.as_ref().map(|_| {
            evaluate_subscription_create(&SubscriptionCreateEvaluationContext {
                action: &request.action,
                policy: &request.policy,
                evidence: &request.evidence,
                required_configuration: &request.required_configuration,
                executed_configuration: &self.executed_configuration,
                now,
            })
        });
        let decision = SubscriptionCreateDecisionReceipt {
            schema: "auths.stripe.subscription-create-decision-receipt/1".into(),
            workflow_id: request.workflow_id.clone(),
            policy: request.policy.clone(),
            policy_digest: policy_digest.clone(),
            exact_action: request.action.clone(),
            action_digest: action_digest.clone(),
            evidence: request.evidence.clone(),
            evidence_digest,
            required_configuration: request.required_configuration.clone(),
            executed_configuration: self.executed_configuration.clone(),
            configuration_equal,
            auths_decision: auths_decision.clone(),
            auths_code: auths_code.clone(),
            authorization_established: authorized.is_some(),
            bounded_decision: bounded_decision.clone(),
            recurring_reserved: false,
            immediate_reserved: false,
            active_slot_reserved: false,
            credential_requested: false,
            stripe_called: false,
            decided_at: now,
        };
        let decision_digest = decision
            .digest()
            .map_err(|_| SubscriptionCreateServiceError::Canonical)?;
        self.receipts
            .append(&SubscriptionCreateReceipt::Decision(Box::new(decision)))
            .map_err(|_| SubscriptionCreateServiceError::Receipt)?;

        let Some(authorized) = authorized else {
            return Ok(if auths_decision == "denied" {
                SubscriptionCreateWorkflowOutcome::Denied {
                    code: auths_code,
                    decision_receipt_digest: decision_digest,
                }
            } else {
                SubscriptionCreateWorkflowOutcome::Indeterminate {
                    code: auths_code,
                    decision_receipt_digest: decision_digest,
                }
            });
        };
        let Some(bounded) = bounded_decision else {
            unreachable!("authorized proof always produces bounded evaluation")
        };
        if bounded.class != SubscriptionCreateDecisionClass::Eligible {
            let code = format!("{:?}", bounded.code).to_ascii_lowercase();
            return Ok(match bounded.class {
                SubscriptionCreateDecisionClass::Denied => {
                    SubscriptionCreateWorkflowOutcome::Denied {
                        code,
                        decision_receipt_digest: decision_digest,
                    }
                }
                SubscriptionCreateDecisionClass::Indeterminate => {
                    SubscriptionCreateWorkflowOutcome::Indeterminate {
                        code,
                        decision_receipt_digest: decision_digest,
                    }
                }
                SubscriptionCreateDecisionClass::Eligible => unreachable!(),
            });
        }
        let eligibility = bounded
            .eligibility
            .ok_or(SubscriptionCreateServiceError::Transition)?;

        let reserve = self
            .store
            .reserve(ReserveSubscriptionLiabilityRequest {
                workflow_id: request.workflow_id.clone(),
                stripe_account_id: request.action.stripe_account_id().clone(),
                customer_id: request.action.customer_id().clone(),
                action_digest: action_digest.clone(),
                policy_digest: policy_digest.clone(),
                mandate_receipt_digest: request.action.mandate_receipt_digest().clone(),
                decision_receipt_digest: decision_digest.clone(),
                recurring_minor: eligibility.recurring_minor,
                term_liability_minor: eligibility.term_liability_minor,
                immediate_minor: eligibility.first_invoice_minor,
                cycle_count: eligibility.cycle_count,
                recurring_reservations: eligibility.recurring_reservations,
                immediate_reservations: eligibility.immediate_reservations,
                maximum_active_subscriptions: request
                    .policy
                    .maximum_active_subscriptions_per_customer(),
                provider_active_subscriptions: request.evidence.active_subscriptions,
                now,
            })
            .map_err(|_| SubscriptionCreateServiceError::State)?;
        let reserved = match reserve {
            ReserveSubscriptionLiabilityResult::Reserved(record) => record,
            ReserveSubscriptionLiabilityResult::Replay(record) => {
                return Ok(SubscriptionCreateWorkflowOutcome::Replay(record));
            }
            ReserveSubscriptionLiabilityResult::Conflict(_) => {
                return Err(SubscriptionCreateServiceError::Transition);
            }
            ReserveSubscriptionLiabilityResult::CapacityExceeded => {
                return Ok(SubscriptionCreateWorkflowOutcome::Indeterminate {
                    code: "subscription-reservation-unavailable".into(),
                    decision_receipt_digest: decision_digest,
                });
            }
        };
        self.append_transition("liability-reserved", &reserved, false, false, false, now)?;

        let claimed =
            self.apply_transition(&reserved, SubscriptionCreateTransition::Claim, None, now)?;
        self.append_transition("exact-action-claimed", &claimed, false, false, false, now)?;

        // Purpose-bound credential acquisition is intentionally after proof,
        // decision persistence, atomic reservation, and exact claim.
        let credential = self
            .credentials
            .credential(request.action.stripe_account_id())
            .map_err(|_| SubscriptionCreateServiceError::Credential)?;
        let command = VerifiedSubscriptionCreateCommand::new(
            *authorized,
            request.workflow_id,
            request.evidence.clone(),
            claimed.clone(),
        );
        let fresh = self
            .gateway
            .reread_critical_evidence(&command, &credential, now)
            .map_err(|_| SubscriptionCreateServiceError::Provider)?;
        if !critical_evidence_equal(&fresh, &request.evidence) {
            let released = self.apply_transition(
                &claimed,
                SubscriptionCreateTransition::KnownFailureReleased,
                None,
                now,
            )?;
            self.append_transition(
                "critical-preview-changed",
                &released,
                true,
                false,
                false,
                now,
            )?;
            return Ok(SubscriptionCreateWorkflowOutcome::Released(released));
        }

        let attempting = self.apply_transition(
            &claimed,
            SubscriptionCreateTransition::BeginAttempt,
            None,
            now,
        )?;
        self.append_transition(
            "provider-attempt-began",
            &attempting,
            true,
            true,
            false,
            now,
        )?;
        let effect = self
            .gateway
            .create(&command, &credential, now)
            .map_err(|_| SubscriptionCreateServiceError::Provider)?;
        self.finish_effect(attempting, effect, now)
    }

    pub fn reconcile(
        &self,
        workflow_id: &str,
    ) -> Result<SubscriptionCreateWorkflowOutcome, SubscriptionCreateServiceError> {
        let record = self
            .store
            .get(workflow_id)
            .map_err(|_| SubscriptionCreateServiceError::State)?
            .ok_or(SubscriptionCreateServiceError::State)?;
        if !matches!(
            record.state(),
            SubscriptionLiabilityState::OutcomeUnknown | SubscriptionLiabilityState::Incomplete
        ) {
            return Ok(SubscriptionCreateWorkflowOutcome::Replay(record));
        }
        let now = self
            .clock
            .now()
            .map_err(|_| SubscriptionCreateServiceError::State)?;
        let credential = self
            .credentials
            .credential(record.stripe_account_id())
            .map_err(|_| SubscriptionCreateServiceError::Credential)?;
        let outcome = self
            .gateway
            .reconcile(&record, &credential, now)
            .map_err(|_| SubscriptionCreateServiceError::Provider)?;
        let (event, projection, label) = match outcome {
            SubscriptionCreateReconciliationOutcome::Active(value) => (
                SubscriptionCreateTransition::ReconcileActive,
                Some(value),
                "reconcile-active",
            ),
            SubscriptionCreateReconciliationOutcome::Trialing(value) => (
                SubscriptionCreateTransition::ReconcileTrialing,
                Some(value),
                "reconcile-trialing",
            ),
            SubscriptionCreateReconciliationOutcome::Incomplete(value) => (
                SubscriptionCreateTransition::ReconcileIncomplete,
                Some(value),
                "reconcile-incomplete",
            ),
            SubscriptionCreateReconciliationOutcome::IncompleteExpired(value) => (
                SubscriptionCreateTransition::ReconcileIncompleteExpired,
                Some(value),
                "reconcile-incomplete-expired",
            ),
            SubscriptionCreateReconciliationOutcome::KnownNoEffect => (
                SubscriptionCreateTransition::ReconcileNoEffect,
                None,
                "reconcile-no-effect",
            ),
            SubscriptionCreateReconciliationOutcome::StillUnknown(value) => (
                SubscriptionCreateTransition::ReconcileStillUnknown,
                value,
                "reconcile-still-unknown",
            ),
        };
        let updated = self.apply_transition(&record, event, projection.clone(), now)?;
        self.append_transition(label, &updated, true, false, true, now)?;
        if let Some(provider) = projection {
            self.append_observation(&updated, provider, true, now)?;
        }
        Ok(outcome_for(updated))
    }

    fn finish_effect(
        &self,
        record: SubscriptionLiabilityRecord,
        effect: SubscriptionCreateEffect,
        now: u64,
    ) -> Result<SubscriptionCreateWorkflowOutcome, SubscriptionCreateServiceError> {
        let (event, projection, label) = match effect {
            SubscriptionCreateEffect::Active(value) => (
                SubscriptionCreateTransition::ProviderActive,
                Some(value),
                "provider-active",
            ),
            SubscriptionCreateEffect::Trialing(value) => (
                SubscriptionCreateTransition::ProviderTrialing,
                Some(value),
                "provider-trialing",
            ),
            SubscriptionCreateEffect::Incomplete(value) => (
                SubscriptionCreateTransition::ProviderIncomplete,
                Some(value),
                "provider-incomplete",
            ),
            SubscriptionCreateEffect::IncompleteExpired(value) => (
                SubscriptionCreateTransition::ProviderIncompleteExpired,
                Some(value),
                "provider-incomplete-expired",
            ),
            SubscriptionCreateEffect::KnownFailure { code, projection } => {
                let updated = self.apply_transition(
                    &record,
                    SubscriptionCreateTransition::KnownFailureReleased,
                    projection.clone(),
                    now,
                )?;
                self.append_transition(
                    &format!("known-failure-{code}"),
                    &updated,
                    true,
                    true,
                    true,
                    now,
                )?;
                if let Some(provider) = projection {
                    self.append_observation(&updated, provider, false, now)?;
                }
                return Ok(SubscriptionCreateWorkflowOutcome::Released(updated));
            }
            SubscriptionCreateEffect::OutcomeUnknown(projection) => (
                SubscriptionCreateTransition::OutcomeBecameUnknown,
                projection,
                "provider-outcome-unknown",
            ),
        };
        let updated = self.apply_transition(&record, event, projection.clone(), now)?;
        self.append_transition(label, &updated, true, true, true, now)?;
        if let Some(provider) = projection {
            self.append_observation(&updated, provider, false, now)?;
        }
        Ok(outcome_for(updated))
    }

    fn apply_transition(
        &self,
        record: &SubscriptionLiabilityRecord,
        event: SubscriptionCreateTransition,
        provider: Option<SubscriptionProviderProjection>,
        now: u64,
    ) -> Result<SubscriptionLiabilityRecord, SubscriptionCreateServiceError> {
        let next = transition_subscription_create(record.state(), event)
            .ok_or(SubscriptionCreateServiceError::Transition)?;
        self.store
            .transition_create(record.workflow_id(), record.state(), next, provider, now)
            .map_err(|_| SubscriptionCreateServiceError::State)
    }

    fn append_transition(
        &self,
        event: &str,
        liability: &SubscriptionLiabilityRecord,
        credential_requested: bool,
        stripe_called: bool,
        provider_accepted: bool,
        now: u64,
    ) -> Result<(), SubscriptionCreateServiceError> {
        let receipt = SubscriptionCreateTransitionReceipt {
            schema: "auths.stripe.subscription-create-transition-receipt/1".into(),
            decision_receipt_digest: liability.decision_receipt_digest().clone(),
            action_digest: liability.action_digest().clone(),
            policy_digest: liability.policy_digest().clone(),
            semantic_event: event.into(),
            liability: liability.clone(),
            authorization_established: true,
            active_slot_reserved: liability.state().holds_slot(),
            recurring_reserved: liability.state().holds_recurring(),
            immediate_reserved: liability.state().holds_immediate(),
            credential_requested,
            stripe_called,
            provider_accepted,
            recorded_at: now,
        };
        self.receipts
            .append(&SubscriptionCreateReceipt::Transition(Box::new(receipt)))
            .map_err(|_| SubscriptionCreateServiceError::Receipt)
    }

    fn append_observation(
        &self,
        liability: &SubscriptionLiabilityRecord,
        provider: SubscriptionProviderProjection,
        reconciled: bool,
        now: u64,
    ) -> Result<(), SubscriptionCreateServiceError> {
        let exact = provider.customer_id == *liability.customer_id()
            && provider.cancel_at > 0
            && !provider.livemode;
        let receipt = SubscriptionCreateObservationReceipt {
            schema: "auths.stripe.subscription-create-observation-receipt/1".into(),
            workflow_id: liability.workflow_id().into(),
            action_digest: liability.action_digest().clone(),
            policy_digest: liability.policy_digest().clone(),
            decision_receipt_digest: liability.decision_receipt_digest().clone(),
            liability_id: liability.liability_id().clone(),
            first_invoice_collected: provider.amount_paid_minor >= liability.immediate_minor(),
            recurring_liability_committed: matches!(
                liability.state(),
                SubscriptionLiabilityState::Active | SubscriptionLiabilityState::Trialing
            ),
            remaining_term_liability_minor: liability.remaining_term_liability_minor(),
            remaining_cycles: liability.remaining_cycles(),
            exact_provider_equality: exact,
            provider,
            reconciled,
            residual_assumptions: vec![
                "Stripe restricted keys cannot express metadata-value or fixed Price/Customer constraints; exact request construction remains enforced by the typed gateway".into(),
            ],
            recorded_at: now,
        };
        self.receipts
            .append(&SubscriptionCreateReceipt::Observation(Box::new(receipt)))
            .map_err(|_| SubscriptionCreateServiceError::Receipt)
    }
}

fn outcome_for(record: SubscriptionLiabilityRecord) -> SubscriptionCreateWorkflowOutcome {
    match record.state() {
        SubscriptionLiabilityState::Active => SubscriptionCreateWorkflowOutcome::Active(record),
        SubscriptionLiabilityState::Trialing => SubscriptionCreateWorkflowOutcome::Trialing(record),
        SubscriptionLiabilityState::Incomplete => {
            SubscriptionCreateWorkflowOutcome::Incomplete(record)
        }
        SubscriptionLiabilityState::IncompleteExpired => {
            SubscriptionCreateWorkflowOutcome::IncompleteExpired(record)
        }
        SubscriptionLiabilityState::OutcomeUnknown => {
            SubscriptionCreateWorkflowOutcome::OutcomeUnknown(record)
        }
        SubscriptionLiabilityState::Released => SubscriptionCreateWorkflowOutcome::Released(record),
        _ => SubscriptionCreateWorkflowOutcome::Replay(record),
    }
}

fn critical_evidence_equal(
    fresh: &SubscriptionCreateEvidenceV1,
    authorized: &SubscriptionCreateEvidenceV1,
) -> bool {
    fresh.stripe_account_id == authorized.stripe_account_id
        && fresh.connect_account == authorized.connect_account
        && fresh.customer_id == authorized.customer_id
        && fresh.payment_method_id == authorized.payment_method_id
        && fresh.test_clock_id == authorized.test_clock_id
        && fresh.mandate_action == authorized.mandate_action
        && fresh.mandate_capability == authorized.mandate_capability
        && fresh.mandate_receipt == authorized.mandate_receipt
        && fresh.mandate_receipt_digest == authorized.mandate_receipt_digest
        && fresh.catalog == authorized.catalog
        && fresh.preview_lines == authorized.preview_lines
        && fresh.preview_digest == authorized.preview_digest
        && fresh.preview_amount_due_minor == authorized.preview_amount_due_minor
        && fresh.cycle_anchors == authorized.cycle_anchors
        && fresh.active_subscriptions == authorized.active_subscriptions
        && fresh.livemode == authorized.livemode
        && fresh.stripe_api_version == authorized.stripe_api_version
}
