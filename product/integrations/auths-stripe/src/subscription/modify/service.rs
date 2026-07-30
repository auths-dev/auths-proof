//! Ordered orchestration for one exact Subscription modification.

use std::sync::Arc;

use auths_model::CanonicalAction;
use auths_sdk::RequestContext;

use super::{
    ReserveSubscriptionModificationRequest, ReserveSubscriptionModificationResult,
    StripeExactSubscriptionModifyV1, SubscriptionModificationRecord, SubscriptionModificationState,
    SubscriptionModificationStore, SubscriptionModifyDecisionClass,
    SubscriptionModifyDecisionReceipt, SubscriptionModifyEffect,
    SubscriptionModifyEvaluationContext, SubscriptionModifyGateway,
    SubscriptionModifyObservationReceipt, SubscriptionModifyProofDecision,
    SubscriptionModifyProofVerifier, SubscriptionModifyReceipt,
    SubscriptionModifyReconciliationOutcome, SubscriptionModifyTransition,
    SubscriptionModifyTransitionReceipt, VerifiedSubscriptionModifyCommand,
    evaluate_subscription_modify, transition_subscription_modify,
};
use crate::{
    ports::{Clock, CredentialProvider, ReceiptSink, SubscriptionModifyCredentialScope},
    subscription::{StripeBoundedSubscriptionPolicyV1, StripeSubscriptionConfigurationV1},
    types::DigestHex,
};

pub struct ExecuteSubscriptionModifyRequest {
    pub workflow_id: String,
    pub proof: Vec<u8>,
    pub canonical_action: CanonicalAction,
    pub request_context: RequestContext,
    pub action: StripeExactSubscriptionModifyV1,
    pub policy: StripeBoundedSubscriptionPolicyV1,
    pub evidence: super::SubscriptionModifyEvidenceV1,
    pub required_configuration: StripeSubscriptionConfigurationV1,
}

pub struct SubscriptionModifyServiceDependencies {
    pub verifier: Arc<dyn SubscriptionModifyProofVerifier>,
    pub store: Arc<dyn SubscriptionModificationStore>,
    pub credentials: Arc<dyn CredentialProvider<SubscriptionModifyCredentialScope>>,
    pub gateway: Arc<dyn SubscriptionModifyGateway>,
    pub receipts: Arc<dyn ReceiptSink<SubscriptionModifyReceipt>>,
    pub clock: Arc<dyn Clock>,
}

pub struct SubscriptionModifyService {
    verifier: Arc<dyn SubscriptionModifyProofVerifier>,
    store: Arc<dyn SubscriptionModificationStore>,
    credentials: Arc<dyn CredentialProvider<SubscriptionModifyCredentialScope>>,
    gateway: Arc<dyn SubscriptionModifyGateway>,
    receipts: Arc<dyn ReceiptSink<SubscriptionModifyReceipt>>,
    clock: Arc<dyn Clock>,
    executed_configuration: StripeSubscriptionConfigurationV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubscriptionModifyWorkflowOutcome {
    Denied {
        code: String,
        decision_receipt_digest: DigestHex,
    },
    Indeterminate {
        code: String,
        decision_receipt_digest: DigestHex,
    },
    PendingPayment(SubscriptionModificationRecord),
    Applied(SubscriptionModificationRecord),
    OutcomeUnknown(SubscriptionModificationRecord),
    Released(SubscriptionModificationRecord),
    Expired(SubscriptionModificationRecord),
    Replay(SubscriptionModificationRecord),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SubscriptionModifyServiceError {
    #[error("subscription-modify verification boundary failed")]
    Verification,
    #[error("subscription-modify canonicalization failed")]
    Canonical,
    #[error("subscription-modify receipt persistence failed")]
    Receipt,
    #[error("subscription-modify state persistence failed")]
    State,
    #[error("subscription-modify credential unavailable")]
    Credential,
    #[error("subscription-modify transition conflict")]
    Transition,
}

impl SubscriptionModifyService {
    pub fn new(
        dependencies: SubscriptionModifyServiceDependencies,
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
        request: ExecuteSubscriptionModifyRequest,
    ) -> Result<SubscriptionModifyWorkflowOutcome, SubscriptionModifyServiceError> {
        if let Some(record) = self
            .store
            .get(&request.workflow_id)
            .map_err(|_| SubscriptionModifyServiceError::State)?
        {
            return Ok(SubscriptionModifyWorkflowOutcome::Replay(record));
        }
        let now = self
            .clock
            .now()
            .map_err(|_| SubscriptionModifyServiceError::State)?;
        let policy_digest = request
            .policy
            .digest()
            .map_err(|_| SubscriptionModifyServiceError::Canonical)?;
        let action_digest = request
            .action
            .digest()
            .map_err(|_| SubscriptionModifyServiceError::Canonical)?;
        let evidence_digest = request
            .evidence
            .digest()
            .map_err(|_| SubscriptionModifyServiceError::Canonical)?;
        let proof = self
            .verifier
            .verify(
                &request.proof,
                &request.canonical_action,
                &request.request_context,
            )
            .map_err(|_| SubscriptionModifyServiceError::Verification)?;
        let (authorized, auths_decision, auths_code) = match proof {
            SubscriptionModifyProofDecision::Authorized(value) => (
                Some(value),
                "authorized".to_owned(),
                "authorized".to_owned(),
            ),
            SubscriptionModifyProofDecision::Denied { code } => (None, "denied".to_owned(), code),
            SubscriptionModifyProofDecision::Indeterminate { code } => {
                (None, "indeterminate".to_owned(), code)
            }
        };
        let bounded_decision = authorized.as_ref().map(|_| {
            evaluate_subscription_modify(&SubscriptionModifyEvaluationContext {
                action: &request.action,
                policy: &request.policy,
                evidence: &request.evidence,
                required_configuration: &request.required_configuration,
                executed_configuration: &self.executed_configuration,
                now,
            })
        });
        let decision = SubscriptionModifyDecisionReceipt {
            schema: "auths.stripe.subscription-modify-decision-receipt/1".into(),
            workflow_id: request.workflow_id.clone(),
            policy: request.policy.clone(),
            policy_digest: policy_digest.clone(),
            exact_action: request.action.clone(),
            action_digest: action_digest.clone(),
            evidence: request.evidence.clone(),
            evidence_digest,
            required_configuration: request.required_configuration.clone(),
            executed_configuration: self.executed_configuration.clone(),
            configuration_equal: request.required_configuration == self.executed_configuration,
            auths_decision: auths_decision.clone(),
            auths_code: auths_code.clone(),
            authorization_established: authorized.is_some(),
            bounded_decision: bounded_decision.clone(),
            incremental_recurring_reserved: false,
            proration_debit_reserved: false,
            credit_counted_as_capacity: false,
            credential_requested: false,
            stripe_called: false,
            decided_at: now,
        };
        let decision_digest = decision
            .digest()
            .map_err(|_| SubscriptionModifyServiceError::Canonical)?;
        self.receipts
            .append(&SubscriptionModifyReceipt::Decision(Box::new(decision)))
            .map_err(|_| SubscriptionModifyServiceError::Receipt)?;

        let Some(authorized) = authorized else {
            return Ok(if auths_decision == "denied" {
                SubscriptionModifyWorkflowOutcome::Denied {
                    code: auths_code,
                    decision_receipt_digest: decision_digest,
                }
            } else {
                SubscriptionModifyWorkflowOutcome::Indeterminate {
                    code: auths_code,
                    decision_receipt_digest: decision_digest,
                }
            });
        };
        let Some(bounded) = bounded_decision else {
            return Err(SubscriptionModifyServiceError::Transition);
        };
        if bounded.class != SubscriptionModifyDecisionClass::Eligible {
            return Ok(match bounded.class {
                SubscriptionModifyDecisionClass::Denied => {
                    SubscriptionModifyWorkflowOutcome::Denied {
                        code: bounded.stable_code,
                        decision_receipt_digest: decision_digest,
                    }
                }
                SubscriptionModifyDecisionClass::Indeterminate => {
                    SubscriptionModifyWorkflowOutcome::Indeterminate {
                        code: bounded.stable_code,
                        decision_receipt_digest: decision_digest,
                    }
                }
                SubscriptionModifyDecisionClass::Eligible => unreachable!(),
            });
        }
        let eligibility = bounded
            .eligibility
            .ok_or(SubscriptionModifyServiceError::Transition)?;
        let reserve = self
            .store
            .reserve_modify(ReserveSubscriptionModificationRequest {
                workflow_id: request.workflow_id.clone(),
                stripe_account_id: request.action.stripe_account_id().clone(),
                customer_id: request.action.customer_id().clone(),
                subscription_id: request.action.subscription_id().clone(),
                action_digest: action_digest.clone(),
                policy_digest: policy_digest.clone(),
                decision_receipt_digest: decision_digest.clone(),
                before_subscription_digest: request.action.before_subscription_digest().clone(),
                after_items: request.action.after_items().to_vec(),
                before_recurring_minor: eligibility.before_recurring_minor,
                after_recurring_minor: eligibility.after_recurring_minor,
                before_term_liability_minor: eligibility.before_term_liability_minor,
                after_term_liability_minor: eligibility.after_term_liability_minor,
                incremental_term_liability_minor: eligibility.incremental_term_liability_minor,
                superseded_term_liability_minor: eligibility.superseded_term_liability_minor,
                proration_debit_minor: eligibility.proration_debit_minor,
                proration_credit_minor: eligibility.proration_credit_minor,
                recurring_reservations: eligibility.recurring_reservations,
                immediate_reservations: eligibility.immediate_reservations,
                now,
            })
            .map_err(|_| SubscriptionModifyServiceError::State)?;
        let reserved = match reserve {
            ReserveSubscriptionModificationResult::Reserved(value) => value,
            ReserveSubscriptionModificationResult::Replay(value) => {
                return Ok(SubscriptionModifyWorkflowOutcome::Replay(value));
            }
            ReserveSubscriptionModificationResult::Conflict(_) => {
                return Err(SubscriptionModifyServiceError::Transition);
            }
            ReserveSubscriptionModificationResult::CapacityExceeded => {
                return Ok(SubscriptionModifyWorkflowOutcome::Indeterminate {
                    code: "subscription-reservation-unavailable".into(),
                    decision_receipt_digest: decision_digest,
                });
            }
        };
        self.append_transition("liability-delta-reserved", &reserved, false, false, now)?;
        let claimed =
            self.apply_transition(&reserved, SubscriptionModifyTransition::Claim, None, now)?;
        self.append_transition("exact-action-claimed", &claimed, false, false, now)?;

        // Purpose-bound credential access is after proof, decision receipt,
        // atomic delta/debit reservation, and exact claim.
        let credential = self
            .credentials
            .credential(request.action.stripe_account_id())
            .map_err(|_| SubscriptionModifyServiceError::Credential)?;
        let command = VerifiedSubscriptionModifyCommand::new(
            *authorized,
            request.workflow_id,
            request.evidence.clone(),
            claimed.clone(),
        );
        let Ok(fresh) = self
            .gateway
            .reread_critical_evidence(&command, &credential, now)
        else {
            let released = self.apply_transition(
                &claimed,
                SubscriptionModifyTransition::KnownFailureReleased,
                None,
                now,
            )?;
            self.append_transition(
                "critical-reread-unavailable-before-update",
                &released,
                true,
                false,
                now,
            )?;
            return Ok(SubscriptionModifyWorkflowOutcome::Released(released));
        };
        if !critical_evidence_equal(&fresh, &request.evidence) {
            let released = self.apply_transition(
                &claimed,
                SubscriptionModifyTransition::KnownFailureReleased,
                None,
                now,
            )?;
            self.append_transition(
                "critical-state-or-preview-changed",
                &released,
                true,
                false,
                now,
            )?;
            return Ok(SubscriptionModifyWorkflowOutcome::Released(released));
        }
        let attempting = self.apply_transition(
            &claimed,
            SubscriptionModifyTransition::BeginAttempt,
            None,
            now,
        )?;
        self.append_transition("provider-attempt-began", &attempting, true, true, now)?;
        let effect = match self.gateway.modify(&command, &credential, now) {
            Ok(value) => value,
            Err(_) => SubscriptionModifyEffect::OutcomeUnknown(None),
        };
        self.finish_effect(&request.action, attempting, effect, now)
    }

    pub fn reconcile(
        &self,
        workflow_id: &str,
    ) -> Result<SubscriptionModifyWorkflowOutcome, SubscriptionModifyServiceError> {
        let record = self
            .store
            .get(workflow_id)
            .map_err(|_| SubscriptionModifyServiceError::State)?
            .ok_or(SubscriptionModifyServiceError::State)?;
        if !matches!(
            record.state(),
            SubscriptionModificationState::PendingPayment
                | SubscriptionModificationState::OutcomeUnknown
        ) {
            return Ok(SubscriptionModifyWorkflowOutcome::Replay(record));
        }
        let now = self
            .clock
            .now()
            .map_err(|_| SubscriptionModifyServiceError::State)?;
        let credential = self
            .credentials
            .credential(record.stripe_account_id())
            .map_err(|_| SubscriptionModifyServiceError::Credential)?;
        let outcome = match self.gateway.reconcile(&record, &credential, now) {
            Ok(value) => value,
            Err(_) => SubscriptionModifyReconciliationOutcome::StillUnknown(None),
        };
        let (event, projection, label) = match outcome {
            SubscriptionModifyReconciliationOutcome::Applied(value) => (
                SubscriptionModifyTransition::ReconcileApplied,
                Some(value),
                "reconcile-applied",
            ),
            SubscriptionModifyReconciliationOutcome::PendingPayment(value) => (
                SubscriptionModifyTransition::ReconcilePendingPayment,
                Some(value),
                "reconcile-pending-payment",
            ),
            SubscriptionModifyReconciliationOutcome::ExpiredOrVoided(value) => (
                SubscriptionModifyTransition::ReconcileExpired,
                Some(value),
                "reconcile-expired-or-voided",
            ),
            SubscriptionModifyReconciliationOutcome::KnownNoEffect => (
                SubscriptionModifyTransition::ReconcileNoEffect,
                None,
                "reconcile-known-no-effect",
            ),
            SubscriptionModifyReconciliationOutcome::StillUnknown(value) => (
                SubscriptionModifyTransition::ReconcileStillUnknown,
                value,
                "reconcile-still-unknown",
            ),
        };
        let updated = self.apply_transition(&record, event, projection.clone(), now)?;
        self.append_transition(label, &updated, true, false, now)?;
        if let Some(provider) = projection {
            self.append_observation(&updated, provider, true, now)?;
        }
        Ok(outcome_for(updated))
    }

    fn finish_effect(
        &self,
        action: &StripeExactSubscriptionModifyV1,
        record: SubscriptionModificationRecord,
        effect: SubscriptionModifyEffect,
        now: u64,
    ) -> Result<SubscriptionModifyWorkflowOutcome, SubscriptionModifyServiceError> {
        let (event, projection, label) = match effect {
            SubscriptionModifyEffect::Applied(value)
                if value.applied
                    && value.pending_update_digest.is_none()
                    && value.items == action.after_items() =>
            {
                (
                    SubscriptionModifyTransition::ProviderApplied,
                    Some(value),
                    "provider-update-applied",
                )
            }
            SubscriptionModifyEffect::Applied(value) => (
                SubscriptionModifyTransition::OutcomeBecameUnknown,
                Some(value),
                "provider-applied-projection-mismatch",
            ),
            SubscriptionModifyEffect::PendingPayment(value) => (
                SubscriptionModifyTransition::ProviderPendingPayment,
                Some(value),
                "provider-pending-payment",
            ),
            SubscriptionModifyEffect::KnownFailure { code, projection } => {
                let updated = self.apply_transition(
                    &record,
                    SubscriptionModifyTransition::KnownFailureReleased,
                    projection.clone(),
                    now,
                )?;
                self.append_transition(
                    &format!("known-failure-{code}"),
                    &updated,
                    true,
                    true,
                    now,
                )?;
                if let Some(provider) = projection {
                    self.append_observation(&updated, provider, false, now)?;
                }
                return Ok(SubscriptionModifyWorkflowOutcome::Released(updated));
            }
            SubscriptionModifyEffect::OutcomeUnknown(value) => (
                SubscriptionModifyTransition::OutcomeBecameUnknown,
                value,
                "subscription-update-outcome-unknown",
            ),
        };
        let updated = self.apply_transition(&record, event, projection.clone(), now)?;
        self.append_transition(label, &updated, true, true, now)?;
        if let Some(provider) = projection {
            self.append_observation(&updated, provider, false, now)?;
        }
        Ok(outcome_for(updated))
    }

    fn apply_transition(
        &self,
        record: &SubscriptionModificationRecord,
        event: SubscriptionModifyTransition,
        provider: Option<super::SubscriptionModifyProviderProjection>,
        now: u64,
    ) -> Result<SubscriptionModificationRecord, SubscriptionModifyServiceError> {
        let next = transition_subscription_modify(record.state(), event)
            .ok_or(SubscriptionModifyServiceError::Transition)?;
        self.store
            .transition_modify(record.workflow_id(), record.state(), next, provider, now)
            .map_err(|_| SubscriptionModifyServiceError::State)
    }

    fn append_transition(
        &self,
        event: &str,
        record: &SubscriptionModificationRecord,
        credential_requested: bool,
        stripe_called: bool,
        now: u64,
    ) -> Result<(), SubscriptionModifyServiceError> {
        let applied = record.state() == SubscriptionModificationState::Applied;
        let receipt = SubscriptionModifyTransitionReceipt {
            schema: "auths.stripe.subscription-modify-transition-receipt/1".into(),
            decision_receipt_digest: record.decision_receipt_digest().clone(),
            action_digest: record.action_digest().clone(),
            policy_digest: record.policy_digest().clone(),
            semantic_event: event.into(),
            modification: record.clone(),
            old_liability_retained: !applied,
            incremental_recurring_held: record.state().holds_incremental_liability(),
            proration_debit_held: record.state().holds_immediate_debit(),
            superseded_liability_released: applied,
            credential_requested,
            stripe_called,
            provider_accepted: record.provider().is_some(),
            recorded_at: now,
        };
        self.receipts
            .append(&SubscriptionModifyReceipt::Transition(Box::new(receipt)))
            .map_err(|_| SubscriptionModifyServiceError::Receipt)
    }

    fn append_observation(
        &self,
        record: &SubscriptionModificationRecord,
        provider: super::SubscriptionModifyProviderProjection,
        reconciled: bool,
        now: u64,
    ) -> Result<(), SubscriptionModifyServiceError> {
        let applied = record.state() == SubscriptionModificationState::Applied;
        let exact_after = applied
            && provider.applied
            && provider.pending_update_digest.is_none()
            && provider.items == record.after_items();
        let receipt = SubscriptionModifyObservationReceipt {
            schema: "auths.stripe.subscription-modify-observation-receipt/1".into(),
            workflow_id: record.workflow_id().into(),
            action_digest: record.action_digest().clone(),
            policy_digest: record.policy_digest().clone(),
            decision_receipt_digest: record.decision_receipt_digest().clone(),
            transition_id: record.transition_id().clone(),
            exact_after_items_observed: exact_after,
            pending_update_only: record.state() == SubscriptionModificationState::PendingPayment,
            update_applied: applied,
            invoice_payment_succeeded: applied && provider.amount_paid_minor > 0,
            old_liability_retained: !applied,
            new_liability_committed: applied,
            superseded_liability_released: applied,
            proration_credit_is_observation_only: true,
            provider,
            reconciled,
            residual_assumptions: vec![
                "Stripe restricted keys may not express endpoint-perfect subscription-update scope"
                    .into(),
                "typed credential scope and closed gateway constrain application-side use".into(),
            ],
            recorded_at: now,
        };
        self.receipts
            .append(&SubscriptionModifyReceipt::Observation(Box::new(receipt)))
            .map_err(|_| SubscriptionModifyServiceError::Receipt)
    }
}

fn outcome_for(record: SubscriptionModificationRecord) -> SubscriptionModifyWorkflowOutcome {
    match record.state() {
        SubscriptionModificationState::PendingPayment => {
            SubscriptionModifyWorkflowOutcome::PendingPayment(record)
        }
        SubscriptionModificationState::Applied => {
            SubscriptionModifyWorkflowOutcome::Applied(record)
        }
        SubscriptionModificationState::OutcomeUnknown => {
            SubscriptionModifyWorkflowOutcome::OutcomeUnknown(record)
        }
        SubscriptionModificationState::Released => {
            SubscriptionModifyWorkflowOutcome::Released(record)
        }
        SubscriptionModificationState::Expired => {
            SubscriptionModifyWorkflowOutcome::Expired(record)
        }
        _ => SubscriptionModifyWorkflowOutcome::Replay(record),
    }
}

fn critical_evidence_equal(
    fresh: &super::SubscriptionModifyEvidenceV1,
    authorized: &super::SubscriptionModifyEvidenceV1,
) -> bool {
    fresh.stripe_account_id == authorized.stripe_account_id
        && fresh.connect_account == authorized.connect_account
        && fresh.subscription_id == authorized.subscription_id
        && fresh.customer_id == authorized.customer_id
        && fresh.current_items == authorized.current_items
        && fresh.currency == authorized.currency
        && fresh.collection_method == authorized.collection_method
        && fresh.payment_method_id == authorized.payment_method_id
        && fresh.billing_cycle_anchor == authorized.billing_cycle_anchor
        && fresh.current_period_start == authorized.current_period_start
        && fresh.current_period_end == authorized.current_period_end
        && fresh.cancel_at == authorized.cancel_at
        && fresh.mandate_receipt_digest == authorized.mandate_receipt_digest
        && fresh.test_clock_id == authorized.test_clock_id
        && fresh.before_subscription_digest == authorized.before_subscription_digest
        && fresh.pending_update_digest == authorized.pending_update_digest
        && fresh.catalog == authorized.catalog
        && fresh.preview_lines == authorized.preview_lines
        && fresh.preview_digest == authorized.preview_digest
        && fresh.proration_date == authorized.proration_date
        && fresh.proration_debit_minor == authorized.proration_debit_minor
        && fresh.proration_credit_minor == authorized.proration_credit_minor
        && fresh.before_recurring_minor == authorized.before_recurring_minor
        && fresh.after_recurring_minor == authorized.after_recurring_minor
        && fresh.remaining_cycle_count == authorized.remaining_cycle_count
        && fresh.stripe_api_version == authorized.stripe_api_version
        && !fresh.livemode
}
