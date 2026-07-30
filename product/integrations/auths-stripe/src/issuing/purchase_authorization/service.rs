//! Exact signed-event to direct Stripe response pipeline.

#![allow(
    clippy::must_use_candidate,
    reason = "service construction is a direct dependency-boundary operation"
)]

use auths_profile_api::ActionProfile as _;
use auths_sdk::RequestContext;

use super::{
    PurchaseAuthorizationDecision, PurchaseAuthorizationDecisionClass,
    PurchaseAuthorizationDecisionCode, PurchaseAuthorizationDecisionReceipt,
    PurchaseAuthorizationDirectResponse, PurchaseAuthorizationEvaluationContext,
    PurchaseAuthorizationGateway, PurchaseAuthorizationObservationReceipt,
    PurchaseAuthorizationProofDecision, PurchaseAuthorizationProofVerifier,
    PurchaseAuthorizationReceipt, PurchaseAuthorizationTransitionReceipt,
    StripeExactPurchaseAuthorizationV1, StripePurchaseAuthorizationProfile,
    VerifiedPurchaseAuthorizationCommand, evaluate_purchase_authorization,
};
use crate::{
    canonical::canonical_digest,
    issuing::{
        AgentProcurementIntentV1, PURCHASE_POLICY_PROVENANCE, PurchaseAggregateSnapshot,
        PurchaseAuthorizationStore, PurchaseError, PurchaseReservationRecord,
        PurchaseWebhookEvidenceV1, ReservePurchaseResult, StripeBoundedPurchasePolicyV1,
        StripePurchaseConfigurationV1,
    },
    ports::{
        Clock, CredentialProvider, PortError, PurchaseAuthorizationCredentialScope, ReceiptSink,
    },
};

/// Complete protected request built by the authenticated webhook adapter.
pub struct ExecutePurchaseAuthorizationRequest {
    pub workflow_id: String,
    pub action: StripeExactPurchaseAuthorizationV1,
    pub webhook_evidence: PurchaseWebhookEvidenceV1,
    pub procurement_intent: Option<AgentProcurementIntentV1>,
    pub policy: StripeBoundedPurchasePolicyV1,
    pub required_configuration: StripePurchaseConfigurationV1,
    pub proof: Vec<u8>,
    pub auths_request: RequestContext,
    pub elapsed_milliseconds: u64,
    pub response_delivery_unknown: bool,
}

/// Explicit service boundaries.
pub struct PurchaseAuthorizationServiceDependencies<V, C, G, S, R, T> {
    pub proof_verifier: V,
    pub credential_provider: C,
    pub gateway: G,
    pub store: S,
    pub receipt_sink: R,
    pub clock: T,
    pub executed_configuration: StripePurchaseConfigurationV1,
}

pub struct PurchaseAuthorizationService<V, C, G, S, R, T> {
    dependencies: PurchaseAuthorizationServiceDependencies<V, C, G, S, R, T>,
}

/// Direct webhook workflow result.
pub enum PurchaseAuthorizationWorkflowOutcome {
    Authorized {
        record: PurchaseReservationRecord,
        response: PurchaseAuthorizationDirectResponse,
        command: Box<VerifiedPurchaseAuthorizationCommand>,
    },
    Declined {
        response: PurchaseAuthorizationDirectResponse,
        receipt: Box<PurchaseAuthorizationDecisionReceipt>,
        persisted: bool,
    },
    Replay {
        record: PurchaseReservationRecord,
        response: PurchaseAuthorizationDirectResponse,
    },
    OutcomeUnknown {
        record: PurchaseReservationRecord,
        response: PurchaseAuthorizationDirectResponse,
    },
    Conflict {
        record: PurchaseReservationRecord,
        response: PurchaseAuthorizationDirectResponse,
    },
}

impl<V, C, G, S, R, T> PurchaseAuthorizationService<V, C, G, S, R, T>
where
    V: PurchaseAuthorizationProofVerifier,
    C: CredentialProvider<PurchaseAuthorizationCredentialScope>,
    G: PurchaseAuthorizationGateway,
    S: PurchaseAuthorizationStore,
    R: ReceiptSink<PurchaseAuthorizationReceipt>,
    T: Clock,
{
    pub const fn new(
        dependencies: PurchaseAuthorizationServiceDependencies<V, C, G, S, R, T>,
    ) -> Self {
        Self { dependencies }
    }

    /// Makes one full-amount direct webhook decision.
    ///
    /// # Errors
    ///
    /// Returns a closed verifier, state, receipt, or canonicalization failure.
    #[allow(
        clippy::needless_pass_by_value,
        clippy::too_many_lines,
        reason = "the latency-critical trust-boundary ordering is explicit"
    )]
    pub fn execute(
        &self,
        request: ExecutePurchaseAuthorizationRequest,
    ) -> Result<PurchaseAuthorizationWorkflowOutcome, PurchaseServiceError> {
        let now = self.dependencies.clock.now()?;
        let canonical = StripePurchaseAuthorizationProfile
            .canonicalize(
                &request
                    .action
                    .canonical_bytes()
                    .map_err(|_| PurchaseServiceError::Canonicalization)?,
            )
            .map_err(|_| PurchaseServiceError::Profile)?;
        let proof = self.dependencies.proof_verifier.verify(
            &request.proof,
            &canonical,
            &request.auths_request,
        )?;
        let policy_digest = request
            .policy
            .digest()
            .map_err(|_| PurchaseServiceError::Canonicalization)?;
        let action_digest = request
            .action
            .digest()
            .map_err(|_| PurchaseServiceError::Canonicalization)?;
        let webhook_evidence_digest = request
            .webhook_evidence
            .digest()
            .map_err(|_| PurchaseServiceError::Canonicalization)?;

        let authorized = match proof {
            PurchaseAuthorizationProofDecision::Authorized(authorized) => {
                if authorized.command().action() != &request.action {
                    return Err(PurchaseServiceError::Profile);
                }
                authorized
            }
            PurchaseAuthorizationProofDecision::Denied { code }
            | PurchaseAuthorizationProofDecision::Indeterminate { code } => {
                let receipt = self.decision_receipt(
                    &request,
                    policy_digest,
                    action_digest,
                    webhook_evidence_digest,
                    PurchaseAggregateSnapshot::default(),
                    code,
                    None,
                    now,
                );
                self.append(&PurchaseAuthorizationReceipt::Decision(Box::new(
                    receipt.clone(),
                )))?;
                return Ok(PurchaseAuthorizationWorkflowOutcome::Declined {
                    response: PurchaseAuthorizationDirectResponse { approved: false },
                    receipt: Box::new(receipt),
                    persisted: true,
                });
            }
        };

        if request.required_configuration != self.dependencies.executed_configuration {
            let bounded = PurchaseAuthorizationDecision {
                class: PurchaseAuthorizationDecisionClass::Denied,
                code: PurchaseAuthorizationDecisionCode::PurchaseConfigurationMismatch,
                stage: super::PurchaseAuthorizationDecisionStage::Configuration,
                detail: "required and executed Issuing configurations differ".into(),
                eligibility: None,
            };
            let receipt = self.decision_receipt(
                &request,
                policy_digest,
                action_digest,
                webhook_evidence_digest,
                PurchaseAggregateSnapshot::default(),
                "authorized".into(),
                Some(bounded),
                now,
            );
            return Ok(PurchaseAuthorizationWorkflowOutcome::Declined {
                response: PurchaseAuthorizationDirectResponse { approved: false },
                receipt: Box::new(receipt),
                persisted: false,
            });
        }

        if let Some(existing) = self
            .dependencies
            .store
            .get(&request.workflow_id)
            .map_err(|_| PurchaseServiceError::State)?
        {
            let approved = existing.state().holds_capacity()
                || matches!(
                    existing.state(),
                    crate::issuing::PurchaseReservationState::Captured
                );
            return Ok(PurchaseAuthorizationWorkflowOutcome::Replay {
                record: existing,
                response: PurchaseAuthorizationDirectResponse { approved },
            });
        }
        let aggregate = self
            .dependencies
            .store
            .snapshot(&request.policy, now)
            .map_err(|_| PurchaseServiceError::State)?;
        let bounded = evaluate_purchase_authorization(&PurchaseAuthorizationEvaluationContext {
            policy: &request.policy,
            action: &request.action,
            webhook: &request.webhook_evidence,
            intent: request.procurement_intent.as_ref(),
            aggregate: &aggregate,
            required_configuration: &request.required_configuration,
            executed_configuration: &self.dependencies.executed_configuration,
            request_audience: request.auths_request.audience().as_str(),
            now,
            elapsed_milliseconds: request.elapsed_milliseconds,
        });
        let decision_receipt = self.decision_receipt(
            &request,
            policy_digest.clone(),
            action_digest.clone(),
            webhook_evidence_digest,
            aggregate,
            "authorized".into(),
            Some(bounded.clone()),
            now,
        );
        self.append(&PurchaseAuthorizationReceipt::Decision(Box::new(
            decision_receipt.clone(),
        )))?;
        if bounded.class != PurchaseAuthorizationDecisionClass::Eligible {
            return Ok(PurchaseAuthorizationWorkflowOutcome::Declined {
                response: PurchaseAuthorizationDirectResponse { approved: false },
                receipt: Box::new(decision_receipt),
                persisted: true,
            });
        }
        let decision_receipt_digest = decision_receipt
            .digest()
            .map_err(|_| PurchaseServiceError::Canonicalization)?;
        let Some(eligibility) = bounded.eligibility else {
            return Err(PurchaseServiceError::State);
        };
        let reserved = self
            .dependencies
            .store
            .reserve(
                &request.workflow_id,
                request.action.event_id(),
                request.action.authorization_id(),
                &action_digest,
                &policy_digest,
                &decision_receipt_digest,
                request.action.amount_minor(),
                request.action.currency(),
                &eligibility.reservations,
                now,
            )
            .map_err(|_| PurchaseServiceError::State)?;
        let record = match reserved {
            ReservePurchaseResult::Reserved(record) => record,
            ReservePurchaseResult::Replay(record) => {
                return Ok(PurchaseAuthorizationWorkflowOutcome::Replay {
                    record,
                    response: PurchaseAuthorizationDirectResponse { approved: true },
                });
            }
            ReservePurchaseResult::Conflict(record) => {
                return Ok(PurchaseAuthorizationWorkflowOutcome::Conflict {
                    record,
                    response: PurchaseAuthorizationDirectResponse { approved: false },
                });
            }
            ReservePurchaseResult::CapacityExceeded => {
                return Ok(PurchaseAuthorizationWorkflowOutcome::Declined {
                    response: PurchaseAuthorizationDirectResponse { approved: false },
                    receipt: Box::new(decision_receipt),
                    persisted: true,
                });
            }
        };
        let command = Box::new(VerifiedPurchaseAuthorizationCommand::new(
            *authorized,
            request.workflow_id.clone(),
            record.clone(),
        ));
        let response = PurchaseAuthorizationDirectResponse { approved: true };
        let response_digest =
            canonical_digest(&response).map_err(|_| PurchaseServiceError::Canonicalization)?;
        let transition = PurchaseAuthorizationTransitionReceipt {
            schema: "auths.stripe.purchase-authorization-transition-receipt/1".into(),
            decision_receipt_digest,
            action_digest,
            policy_digest,
            semantic_event: if request.response_delivery_unknown {
                "direct-response-outcome-unknown"
            } else {
                "direct-response-committed"
            }
            .into(),
            reservation: record.clone(),
            approved_response: true,
            stripe_version_header: request.action.stripe_api_version().into(),
            response_digest,
            capacity_held: true,
            credential_requested: false,
            provider_called: false,
            elapsed_milliseconds: request.elapsed_milliseconds,
            recorded_at: now,
        };
        self.append(&PurchaseAuthorizationReceipt::Transition(Box::new(
            transition,
        )))?;
        if request.response_delivery_unknown {
            let record = self
                .dependencies
                .store
                .mark_unknown(&request.workflow_id, now)
                .map_err(|_| PurchaseServiceError::State)?;
            Ok(PurchaseAuthorizationWorkflowOutcome::OutcomeUnknown { record, response })
        } else {
            Ok(PurchaseAuthorizationWorkflowOutcome::Authorized {
                record,
                response,
                command,
            })
        }
    }

    /// Reconciles only by retrieving the existing Issuing authorization.
    ///
    /// # Errors
    ///
    /// Returns a closed credential, provider, state, or receipt failure.
    pub fn reconcile(
        &self,
        workflow_id: &str,
    ) -> Result<PurchaseReservationRecord, PurchaseServiceError> {
        let now = self.dependencies.clock.now()?;
        let record = self
            .dependencies
            .store
            .get(workflow_id)
            .map_err(|_| PurchaseServiceError::State)?
            .ok_or(PurchaseServiceError::State)?;
        let credential = self
            .dependencies
            .credential_provider
            .credential(self.dependencies.executed_configuration.stripe_account_id())?;
        let provider =
            self.dependencies
                .gateway
                .retrieve(record.authorization_id(), &credential, now)?;
        let result = self
            .dependencies
            .store
            .observe(workflow_id, provider.clone(), now)
            .map_err(|_| PurchaseServiceError::State)?;
        let receipt = PurchaseAuthorizationObservationReceipt {
            schema: "auths.stripe.purchase-authorization-observation-receipt/1".into(),
            workflow_id: workflow_id.into(),
            action_digest: record.action_digest().clone(),
            policy_digest: record.policy_digest().clone(),
            decision_receipt_digest: record.decision_receipt_digest().clone(),
            exact_amount_or_lower: provider.authorized_amount_minor <= record.amount_minor()
                && provider.captured_amount_minor <= record.amount_minor(),
            capacity_held_after: result.state().holds_capacity(),
            provider,
            reconciled: true,
            residual_assumptions: vec![
                "Stripe Issuing availability and network settlement remain provider facts".into(),
                "the Rust credential scope does not make a broad Stripe key provider-restricted"
                    .into(),
            ],
            recorded_at: now,
        };
        self.append(&PurchaseAuthorizationReceipt::Observation(Box::new(
            receipt,
        )))?;
        Ok(result)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "every trust-boundary commitment remains explicit"
    )]
    fn decision_receipt(
        &self,
        request: &ExecutePurchaseAuthorizationRequest,
        policy_digest: crate::types::DigestHex,
        action_digest: crate::types::DigestHex,
        webhook_evidence_digest: crate::types::DigestHex,
        aggregate_before: PurchaseAggregateSnapshot,
        auths_code: String,
        bounded_decision: Option<PurchaseAuthorizationDecision>,
        now: u64,
    ) -> PurchaseAuthorizationDecisionReceipt {
        PurchaseAuthorizationDecisionReceipt {
            schema: "auths.stripe.purchase-authorization-decision-receipt/1".into(),
            workflow_id: request.workflow_id.clone(),
            policy_provenance: PURCHASE_POLICY_PROVENANCE.into(),
            policy: request.policy.clone(),
            policy_digest,
            exact_action: request.action.clone(),
            action_digest,
            webhook_evidence: request.webhook_evidence.clone(),
            webhook_evidence_digest,
            procurement_intent: request.procurement_intent.clone(),
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
            elapsed_milliseconds: request.elapsed_milliseconds,
            decided_at: now,
        }
    }

    fn append(&self, receipt: &PurchaseAuthorizationReceipt) -> Result<(), PurchaseServiceError> {
        self.dependencies
            .receipt_sink
            .append(receipt)
            .map_err(|_| PurchaseServiceError::Receipt)
    }
}

/// Closed service failures.
#[derive(Debug, thiserror::Error)]
pub enum PurchaseServiceError {
    #[error("profile failure")]
    Profile,
    #[error("canonicalization failure")]
    Canonicalization,
    #[error("state failure")]
    State,
    #[error("receipt failure")]
    Receipt,
    #[error("port failure")]
    Port(#[from] PortError),
}

impl From<PurchaseError> for PurchaseServiceError {
    fn from(_: PurchaseError) -> Self {
        Self::State
    }
}
