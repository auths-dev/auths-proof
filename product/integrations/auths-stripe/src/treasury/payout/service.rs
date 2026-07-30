//! Exact proof-to-Stripe Payout service.

#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::wildcard_imports,
    reason = "the security boundary ordering remains linear and auditable"
)]

use auths_profile_api::ActionProfile as _;
use auths_sdk::RequestContext;

use super::*;
use crate::ports::{Clock, CredentialProvider, PayoutCredentialScope, PortError, ReceiptSink};

pub struct ExecutePayoutRequest {
    pub workflow_id: String,
    pub action: StripeExactPayoutV1,
    pub evidence: PayoutEvidenceV1,
    pub policy: StripeBoundedPayoutPolicyV1,
    pub required_configuration: StripePayoutConfigurationV1,
    pub proof: Vec<u8>,
    pub auths_request: RequestContext,
}

pub struct PayoutServiceDependencies<V, C, G, S, R, T> {
    pub proof_verifier: V,
    pub credential_provider: C,
    pub gateway: G,
    pub store: S,
    pub receipt_sink: R,
    pub clock: T,
    pub executed_configuration: StripePayoutConfigurationV1,
}

pub struct PayoutService<V, C, G, S, R, T> {
    dependencies: PayoutServiceDependencies<V, C, G, S, R, T>,
}

pub enum PayoutWorkflowOutcome {
    Executed(PayoutReservationRecord),
    Denied {
        code: String,
        receipt: Box<PayoutDecisionReceipt>,
    },
    Replay(PayoutReservationRecord),
    OutcomeUnknown(PayoutReservationRecord),
    Released(PayoutReservationRecord),
    ObservationOutsidePolicy(PayoutReservationRecord),
}

impl<V, C, G, S, R, T> PayoutService<V, C, G, S, R, T>
where
    V: PayoutProofVerifier,
    C: CredentialProvider<PayoutCredentialScope>,
    G: PayoutGateway,
    S: PayoutReservationStore,
    R: ReceiptSink<PayoutReceipt>,
    T: Clock,
{
    pub const fn new(dependencies: PayoutServiceDependencies<V, C, G, S, R, T>) -> Self {
        Self { dependencies }
    }

    pub fn execute(
        &self,
        request: ExecutePayoutRequest,
    ) -> Result<PayoutWorkflowOutcome, PayoutServiceError> {
        let now = self.dependencies.clock.now()?;
        let canonical = StripePayoutProfile
            .canonicalize(
                &request
                    .action
                    .canonical_bytes()
                    .map_err(|_| PayoutServiceError::Canonicalization)?,
            )
            .map_err(|_| PayoutServiceError::Profile)?;
        let proof = self.dependencies.proof_verifier.verify(
            &request.proof,
            &canonical,
            &request.auths_request,
        )?;
        let policy_digest = request
            .policy
            .digest()
            .map_err(|_| PayoutServiceError::Canonicalization)?;
        let action_digest = request
            .action
            .digest()
            .map_err(|_| PayoutServiceError::Canonicalization)?;
        let evidence_digest = request
            .evidence
            .digest()
            .map_err(|_| PayoutServiceError::Canonicalization)?;
        let authorized = match proof {
            PayoutProofDecision::Authorized(value) => {
                if value.command().action() != &request.action {
                    return Err(PayoutServiceError::Profile);
                }
                value
            }
            PayoutProofDecision::Denied { code } | PayoutProofDecision::Indeterminate { code } => {
                let receipt = self.decision_receipt(
                    &request,
                    policy_digest,
                    action_digest,
                    evidence_digest,
                    PayoutAggregateSnapshot::default(),
                    code.clone(),
                    None,
                    now,
                );
                self.append(&PayoutReceipt::Decision(Box::new(receipt.clone())))?;
                return Ok(PayoutWorkflowOutcome::Denied {
                    code,
                    receipt: Box::new(receipt),
                });
            }
        };
        if request.required_configuration != self.dependencies.executed_configuration {
            let decision = PayoutDecision {
                class: PayoutDecisionClass::Denied,
                code: PayoutDecisionCode::PayoutConfigurationMismatch,
                stage: PayoutDecisionStage::Configuration,
                detail: "required and executed payout configurations differ".into(),
                eligibility: None,
            };
            let receipt = self.decision_receipt(
                &request,
                policy_digest,
                action_digest,
                evidence_digest,
                PayoutAggregateSnapshot::default(),
                "authorized".into(),
                Some(decision.clone()),
                now,
            );
            return Ok(PayoutWorkflowOutcome::Denied {
                code: decision.code.as_str().into(),
                receipt: Box::new(receipt),
            });
        }
        if let Some(record) = self
            .dependencies
            .store
            .get(&request.workflow_id)
            .map_err(|_| PayoutServiceError::State)?
        {
            return Ok(PayoutWorkflowOutcome::Replay(record));
        }
        let aggregate = self
            .dependencies
            .store
            .snapshot()
            .map_err(|_| PayoutServiceError::State)?;
        let bounded = evaluate_payout(&PayoutEvaluationContext {
            policy: &request.policy,
            action: &request.action,
            evidence: &request.evidence,
            aggregate: &aggregate,
            required_configuration: &request.required_configuration,
            executed_configuration: &self.dependencies.executed_configuration,
            request_audience: request.auths_request.audience().as_str(),
            now,
        });
        let decision_receipt = self.decision_receipt(
            &request,
            policy_digest.clone(),
            action_digest.clone(),
            evidence_digest,
            aggregate,
            "authorized".into(),
            Some(bounded.clone()),
            now,
        );
        self.append(&PayoutReceipt::Decision(Box::new(decision_receipt.clone())))?;
        if bounded.class != PayoutDecisionClass::Eligible {
            return Ok(PayoutWorkflowOutcome::Denied {
                code: bounded.code.as_str().into(),
                receipt: Box::new(decision_receipt),
            });
        }
        let decision_digest = decision_receipt
            .digest()
            .map_err(|_| PayoutServiceError::Canonicalization)?;
        let eligibility = bounded.eligibility.ok_or(PayoutServiceError::State)?;
        let reservation = match self
            .dependencies
            .store
            .reserve(
                &request.workflow_id,
                &action_digest,
                &policy_digest,
                &decision_digest,
                request.action.amount_minor(),
                request.action.currency(),
                &eligibility.reservations,
                now,
            )
            .map_err(|_| PayoutServiceError::State)?
        {
            ReservePayoutResult::Reserved(record) => record,
            ReservePayoutResult::Replay(record) => {
                return Ok(PayoutWorkflowOutcome::Replay(record));
            }
            ReservePayoutResult::Conflict(record) => {
                return Ok(PayoutWorkflowOutcome::ObservationOutsidePolicy(record));
            }
            ReservePayoutResult::CapacityExceeded => {
                return Ok(PayoutWorkflowOutcome::Denied {
                    code: PayoutDecisionCode::PayoutLimitExceeded.as_str().into(),
                    receipt: Box::new(decision_receipt),
                });
            }
        };
        let credential = self
            .dependencies
            .credential_provider
            .credential(request.action.stripe_account_id())?;
        let critical =
            match self
                .dependencies
                .gateway
                .critical_read(&request.action, &credential, now)
            {
                Ok(value) => value,
                Err(PortError::OutcomeUnknown) => {
                    return self.mark_unknown(&request.workflow_id, &decision_digest, None, now);
                }
                Err(_) => return self.release(&request.workflow_id, now),
            };
        let critical_digest = critical
            .digest()
            .map_err(|_| PayoutServiceError::Canonicalization)?;
        let mut critical_aggregate = self
            .dependencies
            .store
            .snapshot()
            .map_err(|_| PayoutServiceError::State)?;
        exclude_current(&mut critical_aggregate, &reservation)?;
        let critical_decision = evaluate_payout(&PayoutEvaluationContext {
            policy: &request.policy,
            action: &request.action,
            evidence: &critical,
            aggregate: &critical_aggregate,
            required_configuration: &request.required_configuration,
            executed_configuration: &self.dependencies.executed_configuration,
            request_audience: request.auths_request.audience().as_str(),
            now,
        });
        if critical_decision.class != PayoutDecisionClass::Eligible {
            return self.release(&request.workflow_id, now);
        }
        let command =
            VerifiedPayoutCommand::new(*authorized, request.workflow_id.clone(), reservation);
        let provider = match self.dependencies.gateway.create(&command, &credential, now) {
            Ok(value) => value,
            Err(PortError::OutcomeUnknown) => {
                return self.mark_unknown(
                    &request.workflow_id,
                    &decision_digest,
                    Some(critical_digest),
                    now,
                );
            }
            Err(_) => return self.release(&request.workflow_id, now),
        };
        let exact = provider_matches(&request.action, &provider);
        let state = if exact {
            state_for_projection(&provider)
        } else {
            PayoutReservationState::ObservationOutsidePolicy
        };
        let record = self
            .dependencies
            .store
            .record_provider(&request.workflow_id, provider.clone(), state, now)
            .map_err(|_| PayoutServiceError::State)?;
        self.append(&PayoutReceipt::Transition(Box::new(
            PayoutTransitionReceipt {
                schema: "auths.stripe.payout-transition-receipt/1".into(),
                workflow_id: request.workflow_id,
                decision_receipt_digest: decision_digest,
                semantic_event: if exact {
                    "provider-accepted"
                } else {
                    "provider-result-outside-policy"
                }
                .into(),
                reservation: record.clone(),
                critical_evidence_digest: Some(critical_digest),
                provider: Some(provider),
                credential_requested: true,
                provider_called: true,
                recorded_at: now,
            },
        )))?;
        Ok(if exact {
            PayoutWorkflowOutcome::Executed(record)
        } else {
            PayoutWorkflowOutcome::ObservationOutsidePolicy(record)
        })
    }

    pub fn reconcile(
        &self,
        workflow_id: &str,
        action: &StripeExactPayoutV1,
    ) -> Result<PayoutWorkflowOutcome, PayoutServiceError> {
        let now = self.dependencies.clock.now()?;
        let record = self
            .dependencies
            .store
            .get(workflow_id)
            .map_err(|_| PayoutServiceError::State)?
            .ok_or(PayoutServiceError::State)?;
        if record.action_digest()
            != &action
                .digest()
                .map_err(|_| PayoutServiceError::Canonicalization)?
        {
            return Err(PayoutServiceError::State);
        }
        let credential = self
            .dependencies
            .credential_provider
            .credential(action.stripe_account_id())?;
        let provider = self.dependencies.gateway.reconcile(
            action,
            record.provider().map(|value| &value.payout_id),
            workflow_id,
            &credential,
            now,
        )?;
        let exact = provider_matches(action, &provider);
        let state = if exact {
            state_for_projection(&provider)
        } else {
            PayoutReservationState::ObservationOutsidePolicy
        };
        let result = self
            .dependencies
            .store
            .record_provider(workflow_id, provider.clone(), state, now)
            .map_err(|_| PayoutServiceError::State)?;
        self.append(&PayoutReceipt::Observation(Box::new(
            PayoutObservationReceipt {
                schema: "auths.stripe.payout-observation-receipt/1".into(),
                workflow_id: workflow_id.into(),
                decision_receipt_digest: result.decision_receipt_digest().clone(),
                provider,
                exact_provider_result: exact,
                capacity_held_after: result.state().holds_capacity(),
                reconciled: true,
                residual_assumptions: vec![
                    "paid is Stripe observation, not human recognition of bank credit".into(),
                    "failed delivery releases capacity only after balance return evidence".into(),
                ],
                recorded_at: now,
            },
        )))?;
        Ok(if exact {
            if result.state() == PayoutReservationState::Released {
                PayoutWorkflowOutcome::Released(result)
            } else {
                PayoutWorkflowOutcome::Executed(result)
            }
        } else {
            PayoutWorkflowOutcome::ObservationOutsidePolicy(result)
        })
    }

    fn mark_unknown(
        &self,
        workflow_id: &str,
        decision_receipt_digest: &crate::types::DigestHex,
        critical_evidence_digest: Option<crate::types::DigestHex>,
        now: u64,
    ) -> Result<PayoutWorkflowOutcome, PayoutServiceError> {
        let record = self
            .dependencies
            .store
            .set_state(workflow_id, PayoutReservationState::OutcomeUnknown, now)
            .map_err(|_| PayoutServiceError::State)?;
        self.append(&PayoutReceipt::Transition(Box::new(
            PayoutTransitionReceipt {
                schema: "auths.stripe.payout-transition-receipt/1".into(),
                workflow_id: workflow_id.into(),
                decision_receipt_digest: decision_receipt_digest.clone(),
                semantic_event: "payout-outcome-unknown".into(),
                reservation: record.clone(),
                critical_evidence_digest,
                provider: None,
                credential_requested: true,
                provider_called: true,
                recorded_at: now,
            },
        )))?;
        Ok(PayoutWorkflowOutcome::OutcomeUnknown(record))
    }

    fn release(
        &self,
        workflow_id: &str,
        now: u64,
    ) -> Result<PayoutWorkflowOutcome, PayoutServiceError> {
        let record = self
            .dependencies
            .store
            .set_state(workflow_id, PayoutReservationState::Released, now)
            .map_err(|_| PayoutServiceError::State)?;
        Ok(PayoutWorkflowOutcome::Released(record))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "every decision commitment remains explicit"
    )]
    fn decision_receipt(
        &self,
        request: &ExecutePayoutRequest,
        policy_digest: crate::types::DigestHex,
        action_digest: crate::types::DigestHex,
        evidence_digest: crate::types::DigestHex,
        aggregate_before: PayoutAggregateSnapshot,
        auths_code: String,
        bounded_decision: Option<PayoutDecision>,
        now: u64,
    ) -> PayoutDecisionReceipt {
        PayoutDecisionReceipt {
            schema: "auths.stripe.payout-decision-receipt/1".into(),
            workflow_id: request.workflow_id.clone(),
            policy_provenance: PAYOUT_POLICY_PROVENANCE.into(),
            policy: request.policy.clone(),
            policy_digest,
            action: request.action.clone(),
            action_digest,
            evidence: request.evidence.clone(),
            evidence_digest,
            aggregate_before,
            required_configuration: request.required_configuration.clone(),
            executed_configuration: self.dependencies.executed_configuration.clone(),
            configuration_equal: request.required_configuration
                == self.dependencies.executed_configuration,
            auths_decision: if bounded_decision.is_some() {
                "authorized"
            } else {
                "not-authorized"
            }
            .into(),
            auths_code,
            bounded_decision,
            credential_requested: false,
            provider_called: false,
            decided_at: now,
        }
    }

    fn append(&self, receipt: &PayoutReceipt) -> Result<(), PayoutServiceError> {
        self.dependencies
            .receipt_sink
            .append(receipt)
            .map_err(|_| PayoutServiceError::Receipt)
    }
}

fn provider_matches(action: &StripeExactPayoutV1, provider: &PayoutProviderProjection) -> bool {
    provider.destination_external_account_id == *action.destination_external_account_id()
        && provider.amount_minor == action.amount_minor()
        && provider.currency == *action.currency()
        && provider.method == action.method()
        && provider.source_type == action.source_type()
}

fn exclude_current(
    aggregate: &mut PayoutAggregateSnapshot,
    reservation: &PayoutReservationRecord,
) -> Result<(), PayoutServiceError> {
    for intent in reservation.reservations() {
        let held = aggregate
            .held_minor_by_reservation
            .get_mut(&intent.reservation_id)
            .ok_or(PayoutServiceError::State)?;
        *held = held
            .checked_sub(intent.amount_minor)
            .ok_or(PayoutServiceError::State)?;
        if *held == 0 {
            aggregate
                .held_minor_by_reservation
                .remove(&intent.reservation_id);
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum PayoutServiceError {
    #[error("Payout profile failure")]
    Profile,
    #[error("Payout canonicalization failed")]
    Canonicalization,
    #[error("Payout state failed")]
    State,
    #[error("Payout receipt failed")]
    Receipt,
    #[error("Payout port failed")]
    Port(#[from] PortError),
}
