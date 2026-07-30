//! Ordered orchestration for one exact Subscription cancellation.

use std::sync::Arc;

use auths_model::CanonicalAction;
use auths_sdk::RequestContext;

use super::{
    ReserveSubscriptionCancellationRequest, ReserveSubscriptionCancellationResult,
    StripeExactSubscriptionCancelV1, StripeSubscriptionCancelConfigurationV1,
    SubscriptionCancelDecisionClass, SubscriptionCancelDecisionReceipt, SubscriptionCancelEffect,
    SubscriptionCancelEvaluationContext, SubscriptionCancelGateway,
    SubscriptionCancelObservationReceipt, SubscriptionCancelProofDecision,
    SubscriptionCancelProofVerifier, SubscriptionCancelReceipt,
    SubscriptionCancelReconciliationOutcome, SubscriptionCancelTransition,
    SubscriptionCancelTransitionReceipt, SubscriptionCancellationRecord,
    SubscriptionCancellationState, SubscriptionCancellationStore,
    VerifiedSubscriptionCancelCommand, evaluate_subscription_cancel,
    transition_subscription_cancel,
};
use crate::{
    ports::{Clock, CredentialProvider, ReceiptSink, SubscriptionCancelCredentialScope},
    subscription::{StripeBoundedSubscriptionPolicyV1, SubscriptionCancelMode},
    types::DigestHex,
};

pub struct ExecuteSubscriptionCancelRequest {
    pub workflow_id: String,
    pub proof: Vec<u8>,
    pub canonical_action: CanonicalAction,
    pub request_context: RequestContext,
    pub action: StripeExactSubscriptionCancelV1,
    pub policy: StripeBoundedSubscriptionPolicyV1,
    pub evidence: super::SubscriptionCancelEvidenceV1,
    pub required_configuration: StripeSubscriptionCancelConfigurationV1,
}

pub struct SubscriptionCancelServiceDependencies {
    pub verifier: Arc<dyn SubscriptionCancelProofVerifier>,
    pub store: Arc<dyn SubscriptionCancellationStore>,
    pub credentials: Arc<dyn CredentialProvider<SubscriptionCancelCredentialScope>>,
    pub gateway: Arc<dyn SubscriptionCancelGateway>,
    pub receipts: Arc<dyn ReceiptSink<SubscriptionCancelReceipt>>,
    pub clock: Arc<dyn Clock>,
}

pub struct SubscriptionCancelService {
    verifier: Arc<dyn SubscriptionCancelProofVerifier>,
    store: Arc<dyn SubscriptionCancellationStore>,
    credentials: Arc<dyn CredentialProvider<SubscriptionCancelCredentialScope>>,
    gateway: Arc<dyn SubscriptionCancelGateway>,
    receipts: Arc<dyn ReceiptSink<SubscriptionCancelReceipt>>,
    clock: Arc<dyn Clock>,
    executed_configuration: StripeSubscriptionCancelConfigurationV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubscriptionCancelWorkflowOutcome {
    Denied {
        code: String,
        decision_receipt_digest: DigestHex,
    },
    Indeterminate {
        code: String,
        decision_receipt_digest: DigestHex,
    },
    Scheduled(SubscriptionCancellationRecord),
    Terminal(SubscriptionCancellationRecord),
    OutcomeUnknown(SubscriptionCancellationRecord),
    NoEffect(SubscriptionCancellationRecord),
    Replay(SubscriptionCancellationRecord),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SubscriptionCancelServiceError {
    #[error("subscription-cancel verification boundary failed")]
    Verification,
    #[error("subscription-cancel canonicalization failed")]
    Canonical,
    #[error("subscription-cancel receipt persistence failed")]
    Receipt,
    #[error("subscription-cancel state persistence failed")]
    State,
    #[error("subscription-cancel credential unavailable")]
    Credential,
    #[error("subscription-cancel transition conflict")]
    Transition,
}

impl SubscriptionCancelService {
    pub fn new(
        dependencies: SubscriptionCancelServiceDependencies,
        executed_configuration: StripeSubscriptionCancelConfigurationV1,
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
        request: ExecuteSubscriptionCancelRequest,
    ) -> Result<SubscriptionCancelWorkflowOutcome, SubscriptionCancelServiceError> {
        if let Some(record) = self
            .store
            .get(&request.workflow_id)
            .map_err(|_| SubscriptionCancelServiceError::State)?
        {
            return Ok(SubscriptionCancelWorkflowOutcome::Replay(record));
        }
        let now = self
            .clock
            .now()
            .map_err(|_| SubscriptionCancelServiceError::State)?;
        let policy_digest = request
            .policy
            .digest()
            .map_err(|_| SubscriptionCancelServiceError::Canonical)?;
        let action_digest = request
            .action
            .digest()
            .map_err(|_| SubscriptionCancelServiceError::Canonical)?;
        let evidence_digest = request
            .evidence
            .digest()
            .map_err(|_| SubscriptionCancelServiceError::Canonical)?;
        let proof = self
            .verifier
            .verify(
                &request.proof,
                &request.canonical_action,
                &request.request_context,
            )
            .map_err(|_| SubscriptionCancelServiceError::Verification)?;
        let (authorized, auths_decision, auths_code) = match proof {
            SubscriptionCancelProofDecision::Authorized(value) => (
                Some(value),
                "authorized".to_owned(),
                "authorized".to_owned(),
            ),
            SubscriptionCancelProofDecision::Denied { code } => (None, "denied".to_owned(), code),
            SubscriptionCancelProofDecision::Indeterminate { code } => {
                (None, "indeterminate".to_owned(), code)
            }
        };
        let bounded_decision = authorized.as_ref().map(|_| {
            evaluate_subscription_cancel(&SubscriptionCancelEvaluationContext {
                action: &request.action,
                policy: &request.policy,
                evidence: &request.evidence,
                required_configuration: &request.required_configuration,
                executed_configuration: &self.executed_configuration,
                request_audience: request.request_context.audience().as_str(),
                now,
            })
        });
        let decision = SubscriptionCancelDecisionReceipt {
            schema: "auths.stripe.subscription-cancel-decision-receipt/1".into(),
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
            release_intent_persisted: false,
            credential_requested: false,
            stripe_called: false,
            decided_at: now,
        };
        let decision_digest = decision
            .digest()
            .map_err(|_| SubscriptionCancelServiceError::Canonical)?;
        self.receipts
            .append(&SubscriptionCancelReceipt::Decision(Box::new(decision)))
            .map_err(|_| SubscriptionCancelServiceError::Receipt)?;
        let Some(authorized) = authorized else {
            return Ok(if auths_decision == "denied" {
                SubscriptionCancelWorkflowOutcome::Denied {
                    code: auths_code,
                    decision_receipt_digest: decision_digest,
                }
            } else {
                SubscriptionCancelWorkflowOutcome::Indeterminate {
                    code: auths_code,
                    decision_receipt_digest: decision_digest,
                }
            });
        };
        let Some(bounded) = bounded_decision else {
            return Err(SubscriptionCancelServiceError::Transition);
        };
        if bounded.class != SubscriptionCancelDecisionClass::Eligible {
            return Ok(match bounded.class {
                SubscriptionCancelDecisionClass::Denied => {
                    SubscriptionCancelWorkflowOutcome::Denied {
                        code: bounded.stable_code,
                        decision_receipt_digest: decision_digest,
                    }
                }
                SubscriptionCancelDecisionClass::Indeterminate => {
                    SubscriptionCancelWorkflowOutcome::Indeterminate {
                        code: bounded.stable_code,
                        decision_receipt_digest: decision_digest,
                    }
                }
                SubscriptionCancelDecisionClass::Eligible => unreachable!(),
            });
        }
        let eligibility = bounded
            .eligibility
            .ok_or(SubscriptionCancelServiceError::Transition)?;
        let reserve = self
            .store
            .reserve_cancel(ReserveSubscriptionCancellationRequest {
                workflow_id: request.workflow_id.clone(),
                stripe_account_id: request.action.stripe_account_id().clone(),
                customer_id: request.action.customer_id().clone(),
                subscription_id: request.action.subscription_id().clone(),
                action_digest: action_digest.clone(),
                policy_digest: policy_digest.clone(),
                decision_receipt_digest: decision_digest.clone(),
                liability_id: request.evidence.liability_id.clone(),
                mode: eligibility.mode,
                remaining_term_liability_minor: eligibility.remaining_term_liability_minor,
                current_period_liability_minor: eligibility.current_period_liability_minor,
                future_liability_release_minor: eligibility.future_liability_release_minor,
                // A release intent is not a provider observation. Retain the
                // complete liability until Stripe accepts the exact branch.
                liability_retained_minor: eligibility.remaining_term_liability_minor,
                release_not_before: eligibility.release_not_before,
                now,
            })
            .map_err(|_| SubscriptionCancelServiceError::State)?;
        let reserved = match reserve {
            ReserveSubscriptionCancellationResult::Reserved(value) => value,
            ReserveSubscriptionCancellationResult::Replay(value) => {
                return Ok(SubscriptionCancelWorkflowOutcome::Replay(value));
            }
            ReserveSubscriptionCancellationResult::Conflict(_) => {
                return Err(SubscriptionCancelServiceError::Transition);
            }
        };
        self.append_transition(
            "liability-release-intent-reserved",
            &reserved,
            false,
            false,
            now,
        )?;
        let claimed = self.apply_transition(
            &reserved,
            SubscriptionCancelTransition::Claim,
            None,
            0,
            reserved.liability_retained_minor(),
            now,
        )?;
        self.append_transition("exact-cancellation-claimed", &claimed, false, false, now)?;

        // Credential access is purpose-bound and occurs only after proof,
        // durable decision, release intent, and exact claim.
        let credential = self
            .credentials
            .credential(request.action.stripe_account_id())
            .map_err(|_| SubscriptionCancelServiceError::Credential)?;
        let command = VerifiedSubscriptionCancelCommand::new(
            *authorized,
            request.workflow_id,
            request.evidence.clone(),
            claimed.clone(),
        );
        let Ok(fresh) = self
            .gateway
            .reread_critical_evidence(&command, &credential, now)
        else {
            return self.known_no_effect(&claimed, "critical-reread-unavailable", now);
        };
        if !critical_evidence_equal(&fresh, &request.evidence) {
            return self.known_no_effect(&claimed, "critical-state-changed", now);
        }
        let attempting = self.apply_transition(
            &claimed,
            SubscriptionCancelTransition::BeginAttempt,
            None,
            0,
            claimed.remaining_term_liability_minor(),
            now,
        )?;
        self.append_transition("provider-attempt-began", &attempting, true, true, now)?;
        let effect = match self.gateway.cancel(&command, &credential, now) {
            Ok(value) => value,
            Err(_) => SubscriptionCancelEffect::OutcomeUnknown(None),
        };
        self.finish_effect(&request.action, attempting, effect, now)
    }

    pub fn reconcile(
        &self,
        workflow_id: &str,
    ) -> Result<SubscriptionCancelWorkflowOutcome, SubscriptionCancelServiceError> {
        let record = self
            .store
            .get(workflow_id)
            .map_err(|_| SubscriptionCancelServiceError::State)?
            .ok_or(SubscriptionCancelServiceError::State)?;
        if !matches!(
            record.state(),
            SubscriptionCancellationState::Scheduled
                | SubscriptionCancellationState::OutcomeUnknown
        ) {
            return Ok(SubscriptionCancelWorkflowOutcome::Replay(record));
        }
        let now = self
            .clock
            .now()
            .map_err(|_| SubscriptionCancelServiceError::State)?;
        let credential = self
            .credentials
            .credential(record.stripe_account_id())
            .map_err(|_| SubscriptionCancelServiceError::Credential)?;
        let result = match self.gateway.reconcile(&record, &credential, now) {
            Ok(value) => value,
            Err(_) => SubscriptionCancelReconciliationOutcome::StillUnknown(None),
        };
        let (event, projection, released, retained, label) = match result {
            SubscriptionCancelReconciliationOutcome::Scheduled(value) => (
                SubscriptionCancelTransition::ReconcileScheduled,
                Some(value),
                record.future_liability_release_minor(),
                record.current_period_liability_minor(),
                "reconcile-scheduled",
            ),
            SubscriptionCancelReconciliationOutcome::Terminal(value) => (
                SubscriptionCancelTransition::ReconcileTerminal,
                Some(value),
                record.remaining_term_liability_minor(),
                0,
                "reconcile-terminal",
            ),
            SubscriptionCancelReconciliationOutcome::KnownNoEffect => (
                SubscriptionCancelTransition::ReconcileNoEffect,
                None,
                0,
                record.remaining_term_liability_minor(),
                "reconcile-known-no-effect",
            ),
            SubscriptionCancelReconciliationOutcome::StillUnknown(value) => (
                SubscriptionCancelTransition::ReconcileStillUnknown,
                value,
                record.liability_released_minor(),
                record.liability_retained_minor(),
                "reconcile-still-unknown",
            ),
            SubscriptionCancelReconciliationOutcome::Conflict(value) => (
                SubscriptionCancelTransition::ReconcileStillUnknown,
                Some(value),
                record.liability_released_minor(),
                record.liability_retained_minor(),
                "reconcile-conflict",
            ),
        };
        let updated =
            self.apply_transition(&record, event, projection.clone(), released, retained, now)?;
        self.append_transition(label, &updated, true, false, now)?;
        if let Some(provider) = projection {
            self.append_observation(&updated, provider, true, now)?;
        }
        Ok(outcome_for(updated))
    }

    fn finish_effect(
        &self,
        action: &StripeExactSubscriptionCancelV1,
        record: SubscriptionCancellationRecord,
        effect: SubscriptionCancelEffect,
        now: u64,
    ) -> Result<SubscriptionCancelWorkflowOutcome, SubscriptionCancelServiceError> {
        let (event, projection, released, retained, label) = match effect {
            SubscriptionCancelEffect::Scheduled(value)
                if action.mode() == SubscriptionCancelMode::AtPeriodEnd
                    && provider_matches(action, &value)
                    && value.cancel_at_period_end
                    && !value.terminal() =>
            {
                (
                    SubscriptionCancelTransition::ProviderScheduled,
                    Some(value),
                    record.future_liability_release_minor(),
                    record.current_period_liability_minor(),
                    "provider-cancellation-scheduled",
                )
            }
            SubscriptionCancelEffect::Terminal(value)
                if provider_matches(action, &value) && value.terminal() =>
            {
                (
                    SubscriptionCancelTransition::ProviderTerminal,
                    Some(value),
                    record.remaining_term_liability_minor(),
                    0,
                    "provider-terminal-cancellation-observed",
                )
            }
            SubscriptionCancelEffect::KnownFailure { code } => {
                return self.known_no_effect(&record, &format!("known-failure-{code}"), now);
            }
            SubscriptionCancelEffect::Scheduled(value)
            | SubscriptionCancelEffect::Terminal(value) => (
                SubscriptionCancelTransition::OutcomeUnknown,
                Some(value),
                0,
                record.remaining_term_liability_minor(),
                "provider-projection-mismatch",
            ),
            SubscriptionCancelEffect::OutcomeUnknown(value) => (
                SubscriptionCancelTransition::OutcomeUnknown,
                value,
                0,
                record.remaining_term_liability_minor(),
                "subscription-cancel-outcome-unknown",
            ),
        };
        let updated =
            self.apply_transition(&record, event, projection.clone(), released, retained, now)?;
        self.append_transition(label, &updated, true, true, now)?;
        if let Some(provider) = projection {
            self.append_observation(&updated, provider, false, now)?;
        }
        Ok(outcome_for(updated))
    }

    fn known_no_effect(
        &self,
        record: &SubscriptionCancellationRecord,
        label: &str,
        now: u64,
    ) -> Result<SubscriptionCancelWorkflowOutcome, SubscriptionCancelServiceError> {
        let updated = self.apply_transition(
            record,
            SubscriptionCancelTransition::KnownFailure,
            None,
            0,
            record.remaining_term_liability_minor(),
            now,
        )?;
        self.append_transition(label, &updated, true, false, now)?;
        Ok(SubscriptionCancelWorkflowOutcome::NoEffect(updated))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "transition preserves explicit release accounting"
    )]
    fn apply_transition(
        &self,
        record: &SubscriptionCancellationRecord,
        event: SubscriptionCancelTransition,
        provider: Option<super::SubscriptionCancelProviderProjection>,
        released_minor: u64,
        retained_minor: u64,
        now: u64,
    ) -> Result<SubscriptionCancellationRecord, SubscriptionCancelServiceError> {
        let next = transition_subscription_cancel(record.state(), event)
            .ok_or(SubscriptionCancelServiceError::Transition)?;
        self.store
            .transition_cancel(
                record.workflow_id(),
                record.state(),
                next,
                provider,
                released_minor,
                retained_minor,
                now,
            )
            .map_err(|_| SubscriptionCancelServiceError::State)
    }

    fn append_transition(
        &self,
        event: &str,
        record: &SubscriptionCancellationRecord,
        credential_requested: bool,
        stripe_called: bool,
        now: u64,
    ) -> Result<(), SubscriptionCancelServiceError> {
        let receipt = SubscriptionCancelTransitionReceipt {
            schema: "auths.stripe.subscription-cancel-transition-receipt/1".into(),
            decision_receipt_digest: record.decision_receipt_digest().clone(),
            action_digest: record.action_digest().clone(),
            policy_digest: record.policy_digest().clone(),
            semantic_event: event.into(),
            cancellation: record.clone(),
            liability_before_minor: record.remaining_term_liability_minor(),
            liability_released_minor: record.liability_released_minor(),
            liability_retained_minor: record.liability_retained_minor(),
            credential_requested,
            stripe_called,
            provider_accepted: record.provider().is_some(),
            recorded_at: now,
        };
        self.receipts
            .append(&SubscriptionCancelReceipt::Transition(Box::new(receipt)))
            .map_err(|_| SubscriptionCancelServiceError::Receipt)
    }

    fn append_observation(
        &self,
        record: &SubscriptionCancellationRecord,
        provider: super::SubscriptionCancelProviderProjection,
        reconciled: bool,
        now: u64,
    ) -> Result<(), SubscriptionCancelServiceError> {
        let receipt = SubscriptionCancelObservationReceipt {
            schema: "auths.stripe.subscription-cancel-observation-receipt/1".into(),
            workflow_id: record.workflow_id().into(),
            action_digest: record.action_digest().clone(),
            policy_digest: record.policy_digest().clone(),
            decision_receipt_digest: record.decision_receipt_digest().clone(),
            cancellation_id: record.cancellation_id().clone(),
            cancellation_scheduled: provider.cancel_at_period_end,
            terminal_cancellation_observed: provider.terminal(),
            invoice_now: provider.invoice_now,
            prorate: provider.prorate,
            liability_released_minor: record.liability_released_minor(),
            liability_retained_minor: record.liability_retained_minor(),
            provider,
            reconciled,
            downstream_deprovisioning_proven: false,
            residual_assumptions: vec![
                "paid and payable invoices remain separately accounted".into(),
                "cancellation does not prove downstream service deprovisioning".into(),
                "typed credential scope and closed gateway constrain application-side use".into(),
            ],
            recorded_at: now,
        };
        self.receipts
            .append(&SubscriptionCancelReceipt::Observation(Box::new(receipt)))
            .map_err(|_| SubscriptionCancelServiceError::Receipt)
    }
}

fn outcome_for(record: SubscriptionCancellationRecord) -> SubscriptionCancelWorkflowOutcome {
    match record.state() {
        SubscriptionCancellationState::Scheduled => {
            SubscriptionCancelWorkflowOutcome::Scheduled(record)
        }
        SubscriptionCancellationState::Released if record.liability_released_minor() > 0 => {
            SubscriptionCancelWorkflowOutcome::Terminal(record)
        }
        SubscriptionCancellationState::Released => {
            SubscriptionCancelWorkflowOutcome::NoEffect(record)
        }
        SubscriptionCancellationState::OutcomeUnknown => {
            SubscriptionCancelWorkflowOutcome::OutcomeUnknown(record)
        }
        _ => SubscriptionCancelWorkflowOutcome::Replay(record),
    }
}

fn provider_matches(
    action: &StripeExactSubscriptionCancelV1,
    provider: &super::SubscriptionCancelProviderProjection,
) -> bool {
    provider.subscription_id == *action.subscription_id()
        && provider.customer_id == *action.customer_id()
        && !provider.invoice_now
        && !provider.prorate
}

fn critical_evidence_equal(
    fresh: &super::SubscriptionCancelEvidenceV1,
    authorized: &super::SubscriptionCancelEvidenceV1,
) -> bool {
    fresh.stripe_account_id == authorized.stripe_account_id
        && fresh.connect_account == authorized.connect_account
        && fresh.subscription_id == authorized.subscription_id
        && fresh.customer_id == authorized.customer_id
        && fresh.subscription_digest == authorized.subscription_digest
        && fresh.item_set_digest == authorized.item_set_digest
        && fresh.status == authorized.status
        && fresh.currency == authorized.currency
        && fresh.current_period_end == authorized.current_period_end
        && fresh.cancel_at == authorized.cancel_at
        && fresh.cancel_at_period_end == authorized.cancel_at_period_end
        && fresh.ended_at == authorized.ended_at
        && fresh.pending_update_digest == authorized.pending_update_digest
        && fresh.pending_invoice_items_digest == authorized.pending_invoice_items_digest
        && fresh.pending_invoice_item_count == authorized.pending_invoice_item_count
        && fresh.latest_invoice_digest == authorized.latest_invoice_digest
        && fresh.liability_id == authorized.liability_id
        && fresh.liability_state == authorized.liability_state
        && fresh.remaining_term_liability_minor == authorized.remaining_term_liability_minor
        && fresh.current_period_liability_minor == authorized.current_period_liability_minor
        && fresh.renewal_or_modification_pending == authorized.renewal_or_modification_pending
        && fresh.test_clock_id == authorized.test_clock_id
        && fresh.stripe_api_version == authorized.stripe_api_version
        && !fresh.livemode
}
