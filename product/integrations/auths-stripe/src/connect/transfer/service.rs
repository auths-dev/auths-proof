//! Exact proof-to-Stripe Connect Transfer service.

#![allow(
    clippy::must_use_candidate,
    reason = "service construction is a direct dependency-boundary operation"
)]

use auths_profile_api::ActionProfile as _;
use auths_sdk::RequestContext;

use super::{
    CONNECT_TRANSFER_POLICY_PROVENANCE, ConnectTransferAggregateSnapshot, ConnectTransferDecision,
    ConnectTransferDecisionClass, ConnectTransferDecisionReceipt, ConnectTransferEvidenceV1,
    ConnectTransferGateway, ConnectTransferObservationReceipt, ConnectTransferProofDecision,
    ConnectTransferProofVerifier, ConnectTransferReceipt, ConnectTransferReservationRecord,
    ConnectTransferReservationState, ConnectTransferReservationStore,
    ConnectTransferTransitionReceipt, ReserveConnectTransferResult,
    StripeBoundedConnectTransferPolicyV1, StripeConnectTransferConfigurationV1,
    StripeConnectTransferProfile, StripeExactConnectTransferV1, VerifiedConnectTransferCommand,
    evaluate_connect_transfer,
};
use crate::ports::{
    Clock, ConnectTransferCredentialScope, CredentialProvider, PortError, ReceiptSink,
};

/// Complete protected transfer request.
pub struct ExecuteConnectTransferRequest {
    pub workflow_id: String,
    pub action: StripeExactConnectTransferV1,
    pub evidence: ConnectTransferEvidenceV1,
    pub policy: StripeBoundedConnectTransferPolicyV1,
    pub required_configuration: StripeConnectTransferConfigurationV1,
    pub proof: Vec<u8>,
    pub auths_request: RequestContext,
}

/// Explicit transfer service boundaries.
pub struct ConnectTransferServiceDependencies<V, C, G, S, R, T> {
    pub proof_verifier: V,
    pub credential_provider: C,
    pub gateway: G,
    pub store: S,
    pub receipt_sink: R,
    pub clock: T,
    pub executed_configuration: StripeConnectTransferConfigurationV1,
}

pub struct ConnectTransferService<V, C, G, S, R, T> {
    dependencies: ConnectTransferServiceDependencies<V, C, G, S, R, T>,
}

/// Closed transfer workflow result.
pub enum ConnectTransferWorkflowOutcome {
    Executed(ConnectTransferReservationRecord),
    Denied {
        code: String,
        receipt: Box<ConnectTransferDecisionReceipt>,
    },
    Replay(ConnectTransferReservationRecord),
    OutcomeUnknown(ConnectTransferReservationRecord),
    Released(ConnectTransferReservationRecord),
    ObservationOutsidePolicy(ConnectTransferReservationRecord),
}

impl<V, C, G, S, R, T> ConnectTransferService<V, C, G, S, R, T>
where
    V: ConnectTransferProofVerifier,
    C: CredentialProvider<ConnectTransferCredentialScope>,
    G: ConnectTransferGateway,
    S: ConnectTransferReservationStore,
    R: ReceiptSink<ConnectTransferReceipt>,
    T: Clock,
{
    pub const fn new(dependencies: ConnectTransferServiceDependencies<V, C, G, S, R, T>) -> Self {
        Self { dependencies }
    }

    /// Executes at most one exact Transfer.
    ///
    /// # Errors
    ///
    /// Returns a closed verifier, persistence, credential, or provider failure.
    #[allow(
        clippy::needless_pass_by_value,
        clippy::too_many_lines,
        reason = "the security boundary ordering remains linear and auditable"
    )]
    pub fn execute(
        &self,
        request: ExecuteConnectTransferRequest,
    ) -> Result<ConnectTransferWorkflowOutcome, ConnectTransferServiceError> {
        let now = self.dependencies.clock.now()?;
        let canonical = StripeConnectTransferProfile
            .canonicalize(
                &request
                    .action
                    .canonical_bytes()
                    .map_err(|_| ConnectTransferServiceError::Canonicalization)?,
            )
            .map_err(|_| ConnectTransferServiceError::Profile)?;
        let proof = self.dependencies.proof_verifier.verify(
            &request.proof,
            &canonical,
            &request.auths_request,
        )?;
        let policy_digest = request
            .policy
            .digest()
            .map_err(|_| ConnectTransferServiceError::Canonicalization)?;
        let action_digest = request
            .action
            .digest()
            .map_err(|_| ConnectTransferServiceError::Canonicalization)?;
        let evidence_digest = request
            .evidence
            .digest()
            .map_err(|_| ConnectTransferServiceError::Canonicalization)?;
        let authorized = match proof {
            ConnectTransferProofDecision::Authorized(value) => {
                if value.command().action() != &request.action {
                    return Err(ConnectTransferServiceError::Profile);
                }
                value
            }
            ConnectTransferProofDecision::Denied { code }
            | ConnectTransferProofDecision::Indeterminate { code } => {
                let receipt = self.decision_receipt(
                    &request,
                    policy_digest,
                    action_digest,
                    evidence_digest,
                    ConnectTransferAggregateSnapshot::default(),
                    code.clone(),
                    None,
                    now,
                );
                self.append(&ConnectTransferReceipt::Decision(Box::new(receipt.clone())))?;
                return Ok(ConnectTransferWorkflowOutcome::Denied {
                    code,
                    receipt: Box::new(receipt),
                });
            }
        };
        if request.required_configuration != self.dependencies.executed_configuration {
            let decision = ConnectTransferDecision {
                class: ConnectTransferDecisionClass::Denied,
                code: super::ConnectTransferDecisionCode::ConnectConfigurationMismatch,
                stage: super::ConnectTransferDecisionStage::Configuration,
                detail: "required and executed transfer configurations differ".into(),
                eligibility: None,
            };
            let receipt = self.decision_receipt(
                &request,
                policy_digest,
                action_digest,
                evidence_digest,
                ConnectTransferAggregateSnapshot::default(),
                "authorized".into(),
                Some(decision.clone()),
                now,
            );
            return Ok(ConnectTransferWorkflowOutcome::Denied {
                code: decision.code.as_str().into(),
                receipt: Box::new(receipt),
            });
        }
        if let Some(record) = self
            .dependencies
            .store
            .get(&request.workflow_id)
            .map_err(|_| ConnectTransferServiceError::State)?
        {
            return Ok(ConnectTransferWorkflowOutcome::Replay(record));
        }
        let aggregate = self
            .dependencies
            .store
            .snapshot()
            .map_err(|_| ConnectTransferServiceError::State)?;
        let bounded = evaluate_connect_transfer(&super::ConnectTransferEvaluationContext {
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
            aggregate.clone(),
            "authorized".into(),
            Some(bounded.clone()),
            now,
        );
        self.append(&ConnectTransferReceipt::Decision(Box::new(
            decision_receipt.clone(),
        )))?;
        if bounded.class != ConnectTransferDecisionClass::Eligible {
            return Ok(ConnectTransferWorkflowOutcome::Denied {
                code: bounded.code.as_str().into(),
                receipt: Box::new(decision_receipt),
            });
        }
        let decision_receipt_digest = decision_receipt
            .digest()
            .map_err(|_| ConnectTransferServiceError::Canonicalization)?;
        let eligibility = bounded
            .eligibility
            .ok_or(ConnectTransferServiceError::State)?;
        let reserved = self
            .dependencies
            .store
            .reserve(
                &request.workflow_id,
                &action_digest,
                &policy_digest,
                &decision_receipt_digest,
                request.action.amount_minor(),
                request.action.currency(),
                &eligibility.reservations,
                now,
            )
            .map_err(|_| ConnectTransferServiceError::State)?;
        let reservation = match reserved {
            ReserveConnectTransferResult::Reserved(value) => value,
            ReserveConnectTransferResult::Replay(value) => {
                return Ok(ConnectTransferWorkflowOutcome::Replay(value));
            }
            ReserveConnectTransferResult::Conflict(value) => {
                return Ok(ConnectTransferWorkflowOutcome::ObservationOutsidePolicy(
                    value,
                ));
            }
            ReserveConnectTransferResult::CapacityExceeded => {
                return Ok(ConnectTransferWorkflowOutcome::Denied {
                    code: super::ConnectTransferDecisionCode::ConnectTransferLimitExceeded
                        .as_str()
                        .into(),
                    receipt: Box::new(decision_receipt),
                });
            }
        };
        let credential = self
            .dependencies
            .credential_provider
            .credential(request.action.platform_account_id())?;
        let critical =
            match self
                .dependencies
                .gateway
                .critical_read(&request.action, &credential, now)
            {
                Ok(value) => value,
                Err(PortError::OutcomeUnknown) => {
                    return self.mark_unknown(
                        &request.workflow_id,
                        &decision_receipt_digest,
                        reservation,
                        None,
                        now,
                    );
                }
                Err(_) => {
                    let released = self
                        .dependencies
                        .store
                        .set_state(
                            &request.workflow_id,
                            ConnectTransferReservationState::Released,
                            now,
                        )
                        .map_err(|_| ConnectTransferServiceError::State)?;
                    return Ok(ConnectTransferWorkflowOutcome::Released(released));
                }
            };
        let critical_digest = critical
            .digest()
            .map_err(|_| ConnectTransferServiceError::Canonicalization)?;
        let mut critical_aggregate = self
            .dependencies
            .store
            .snapshot()
            .map_err(|_| ConnectTransferServiceError::State)?;
        exclude_current_reservation(&mut critical_aggregate, &reservation)?;
        let critical_decision =
            evaluate_connect_transfer(&super::ConnectTransferEvaluationContext {
                policy: &request.policy,
                action: &request.action,
                evidence: &critical,
                aggregate: &critical_aggregate,
                required_configuration: &request.required_configuration,
                executed_configuration: &self.dependencies.executed_configuration,
                request_audience: request.auths_request.audience().as_str(),
                now,
            });
        if critical_decision.class != ConnectTransferDecisionClass::Eligible {
            let released = self
                .dependencies
                .store
                .set_state(
                    &request.workflow_id,
                    ConnectTransferReservationState::Released,
                    now,
                )
                .map_err(|_| ConnectTransferServiceError::State)?;
            self.append(&ConnectTransferReceipt::Transition(Box::new(
                ConnectTransferTransitionReceipt {
                    schema: "auths.stripe.connect-transfer-transition-receipt/1".into(),
                    workflow_id: request.workflow_id,
                    decision_receipt_digest,
                    semantic_event: "critical-reread-denied".into(),
                    reservation: released.clone(),
                    critical_evidence_digest: Some(critical_digest),
                    provider: None,
                    credential_requested: true,
                    provider_called: true,
                    recorded_at: now,
                },
            )))?;
            return Ok(ConnectTransferWorkflowOutcome::Released(released));
        }
        let command = VerifiedConnectTransferCommand::new(
            *authorized,
            request.workflow_id.clone(),
            reservation.clone(),
        );
        let provider = match self.dependencies.gateway.create(&command, &credential, now) {
            Ok(value) => value,
            Err(PortError::OutcomeUnknown) => {
                return self.mark_unknown(
                    &request.workflow_id,
                    &decision_receipt_digest,
                    reservation,
                    Some(critical_digest),
                    now,
                );
            }
            Err(_) => {
                let released = self
                    .dependencies
                    .store
                    .set_state(
                        &request.workflow_id,
                        ConnectTransferReservationState::Released,
                        now,
                    )
                    .map_err(|_| ConnectTransferServiceError::State)?;
                return Ok(ConnectTransferWorkflowOutcome::Released(released));
            }
        };
        let exact = provider_matches(&request.action, &provider);
        let state = if exact {
            ConnectTransferReservationState::ProviderAccepted
        } else {
            ConnectTransferReservationState::ObservationOutsidePolicy
        };
        let record = self
            .dependencies
            .store
            .record_provider(&request.workflow_id, provider.clone(), state, now)
            .map_err(|_| ConnectTransferServiceError::State)?;
        self.append(&ConnectTransferReceipt::Transition(Box::new(
            ConnectTransferTransitionReceipt {
                schema: "auths.stripe.connect-transfer-transition-receipt/1".into(),
                workflow_id: request.workflow_id,
                decision_receipt_digest,
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
            ConnectTransferWorkflowOutcome::Executed(record)
        } else {
            ConnectTransferWorkflowOutcome::ObservationOutsidePolicy(record)
        })
    }

    /// Reconciles without creating a second Transfer.
    ///
    /// # Errors
    ///
    /// Returns a closed state, credential, provider, or receipt failure.
    pub fn reconcile(
        &self,
        workflow_id: &str,
        action: &StripeExactConnectTransferV1,
    ) -> Result<ConnectTransferWorkflowOutcome, ConnectTransferServiceError> {
        let now = self.dependencies.clock.now()?;
        let record = self
            .dependencies
            .store
            .get(workflow_id)
            .map_err(|_| ConnectTransferServiceError::State)?
            .ok_or(ConnectTransferServiceError::State)?;
        if record.action_digest()
            != &action
                .digest()
                .map_err(|_| ConnectTransferServiceError::Canonicalization)?
        {
            return Err(ConnectTransferServiceError::State);
        }
        let credential = self
            .dependencies
            .credential_provider
            .credential(action.platform_account_id())?;
        let known_id = record.provider().map(|value| &value.transfer_id);
        let provider =
            self.dependencies
                .gateway
                .reconcile(action, known_id, workflow_id, &credential, now)?;
        let exact = provider_matches(action, &provider);
        let state = if exact {
            ConnectTransferReservationState::ProviderAccepted
        } else {
            ConnectTransferReservationState::ObservationOutsidePolicy
        };
        let result = self
            .dependencies
            .store
            .record_provider(workflow_id, provider.clone(), state, now)
            .map_err(|_| ConnectTransferServiceError::State)?;
        self.append(&ConnectTransferReceipt::Observation(Box::new(
            ConnectTransferObservationReceipt {
                schema: "auths.stripe.connect-transfer-observation-receipt/1".into(),
                workflow_id: workflow_id.into(),
                decision_receipt_digest: result.decision_receipt_digest().clone(),
                provider,
                exact_provider_result: exact,
                capacity_held_after: result.state().holds_capacity(),
                reconciled: true,
                residual_assumptions: vec![
                    "Stripe balance availability and connected-account settlement remain provider facts"
                        .into(),
                    "later source failure requires a separate reversal obligation".into(),
                ],
                recorded_at: now,
            },
        )))?;
        Ok(if exact {
            ConnectTransferWorkflowOutcome::Executed(result)
        } else {
            ConnectTransferWorkflowOutcome::ObservationOutsidePolicy(result)
        })
    }

    fn mark_unknown(
        &self,
        workflow_id: &str,
        decision_receipt_digest: &crate::types::DigestHex,
        _reservation: ConnectTransferReservationRecord,
        critical_evidence_digest: Option<crate::types::DigestHex>,
        now: u64,
    ) -> Result<ConnectTransferWorkflowOutcome, ConnectTransferServiceError> {
        let record = self
            .dependencies
            .store
            .set_state(
                workflow_id,
                ConnectTransferReservationState::OutcomeUnknown,
                now,
            )
            .map_err(|_| ConnectTransferServiceError::State)?;
        self.append(&ConnectTransferReceipt::Transition(Box::new(
            ConnectTransferTransitionReceipt {
                schema: "auths.stripe.connect-transfer-transition-receipt/1".into(),
                workflow_id: workflow_id.into(),
                decision_receipt_digest: decision_receipt_digest.clone(),
                semantic_event: "connect-transfer-outcome-unknown".into(),
                reservation: record.clone(),
                critical_evidence_digest,
                provider: None,
                credential_requested: true,
                provider_called: true,
                recorded_at: now,
            },
        )))?;
        Ok(ConnectTransferWorkflowOutcome::OutcomeUnknown(record))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "every decision commitment remains explicit"
    )]
    fn decision_receipt(
        &self,
        request: &ExecuteConnectTransferRequest,
        policy_digest: crate::types::DigestHex,
        action_digest: crate::types::DigestHex,
        evidence_digest: crate::types::DigestHex,
        aggregate_before: ConnectTransferAggregateSnapshot,
        auths_code: String,
        bounded_decision: Option<ConnectTransferDecision>,
        now: u64,
    ) -> ConnectTransferDecisionReceipt {
        ConnectTransferDecisionReceipt {
            schema: "auths.stripe.connect-transfer-decision-receipt/1".into(),
            workflow_id: request.workflow_id.clone(),
            policy_provenance: CONNECT_TRANSFER_POLICY_PROVENANCE.into(),
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

    fn append(&self, receipt: &ConnectTransferReceipt) -> Result<(), ConnectTransferServiceError> {
        self.dependencies
            .receipt_sink
            .append(receipt)
            .map_err(|_| ConnectTransferServiceError::Receipt)
    }
}

fn provider_matches(
    action: &StripeExactConnectTransferV1,
    provider: &super::ConnectTransferProviderProjection,
) -> bool {
    provider.destination_account_id == *action.destination_account_id()
        && provider.source_charge_id == *action.source_charge_id()
        && provider.amount_minor == action.amount_minor()
        && provider.currency == *action.currency()
        && provider.transfer_group == action.transfer_group()
        && !provider.reversed
}

fn exclude_current_reservation(
    aggregate: &mut ConnectTransferAggregateSnapshot,
    reservation: &ConnectTransferReservationRecord,
) -> Result<(), ConnectTransferServiceError> {
    for intent in reservation.reservations() {
        let held = aggregate
            .held_minor_by_reservation
            .get_mut(&intent.reservation_id)
            .ok_or(ConnectTransferServiceError::State)?;
        *held = held
            .checked_sub(intent.amount_minor)
            .ok_or(ConnectTransferServiceError::State)?;
        if *held == 0 {
            aggregate
                .held_minor_by_reservation
                .remove(&intent.reservation_id);
        }
    }
    Ok(())
}

/// Closed service failures.
#[derive(Debug, thiserror::Error)]
pub enum ConnectTransferServiceError {
    #[error("Connect transfer profile failure")]
    Profile,
    #[error("Connect transfer canonicalization failed")]
    Canonicalization,
    #[error("Connect transfer state failed")]
    State,
    #[error("Connect transfer receipt failed")]
    Receipt,
    #[error("Connect transfer port failed")]
    Port(#[from] PortError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        canonical,
        connect::transfer::{
            ConnectTransferReservationIntent, InMemoryConnectTransferReservationStore,
        },
        types::Currency,
    };

    #[test]
    fn critical_snapshot_excludes_only_the_current_workflow() {
        let store = InMemoryConnectTransferReservationStore::new();
        let currency = Currency::parse("usd").unwrap();
        let intent = ConnectTransferReservationIntent {
            reservation_id: "platform:acct_fixture:usd".into(),
            currency: currency.clone(),
            amount_minor: 500,
            limit_minor: 1_000,
        };
        let digest = canonical::sha256(b"critical-snapshot");
        let first = match store
            .reserve(
                "workflow-first",
                &digest,
                &digest,
                &digest,
                500,
                &currency,
                std::slice::from_ref(&intent),
                1,
            )
            .unwrap()
        {
            ReserveConnectTransferResult::Reserved(record) => record,
            other => panic!("unexpected reservation result: {other:?}"),
        };
        store
            .reserve(
                "workflow-second",
                &canonical::sha256(b"second"),
                &digest,
                &digest,
                500,
                &currency,
                std::slice::from_ref(&intent),
                1,
            )
            .unwrap();
        let mut aggregate = store.snapshot().unwrap();
        exclude_current_reservation(&mut aggregate, &first).unwrap();
        assert_eq!(
            aggregate
                .held_minor_by_reservation
                .get("platform:acct_fixture:usd"),
            Some(&500)
        );
    }
}
