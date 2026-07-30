//! Ordered exact-proof-to-SetupIntent pipeline.

use auths_profile_api::ActionProfile as _;
use auths_sdk::RequestContext;

use super::{
    PAYMENT_MANDATE_RECEIPT_SCHEMA, PaymentMandateCapabilityRecord, PaymentMandateCapabilityState,
    PaymentMandateDecision, PaymentMandateDecisionClass, PaymentMandateDecisionCode,
    PaymentMandateDecisionReceipt, PaymentMandateDecisionStage, PaymentMandateEffect,
    PaymentMandateEvaluationContext, PaymentMandateGateway, PaymentMandateObservationReceipt,
    PaymentMandateProofDecision, PaymentMandateProofVerifier, PaymentMandateReceipt,
    PaymentMandateReconciliationOutcome, PaymentMandateStore, PaymentMandateTransitionReceipt,
    ReservePaymentMandateRequest, ReservePaymentMandateResult, StripeBoundedPaymentMandatePolicyV1,
    StripeExactPaymentMandateV1, StripePaymentMandateConfigurationV1, StripePaymentMandateProfile,
    VerifiedPaymentMandateCommand, evaluate_payment_mandate,
};
use crate::{
    canonical::CanonicalError,
    ports::{Clock, CredentialProvider, PaymentMandateCredentialScope, PortError, ReceiptSink},
    types::DigestHex,
};

/// Hostile exact action plus protected configured inputs.
pub struct ExecutePaymentMandateRequest {
    pub workflow_id: String,
    pub action: StripeExactPaymentMandateV1,
    pub consent: Option<super::PaymentConsentEvidenceV1>,
    pub evidence: super::PaymentMandateEvidenceV1,
    pub policy: StripeBoundedPaymentMandatePolicyV1,
    pub required_configuration: StripePaymentMandateConfigurationV1,
    pub proof: Vec<u8>,
    pub auths_request: RequestContext,
}

/// Explicit dependencies preserve every trust boundary.
pub struct PaymentMandateServiceDependencies<V, C, G, S, R, T> {
    pub proof_verifier: V,
    pub credential_provider: C,
    pub stripe_gateway: G,
    pub store: S,
    pub receipt_sink: R,
    pub clock: T,
    pub executed_configuration: StripePaymentMandateConfigurationV1,
}

/// Complete payment-mandate service.
pub struct PaymentMandateService<V, C, G, S, R, T> {
    dependencies: PaymentMandateServiceDependencies<V, C, G, S, R, T>,
}

impl<V, C, G, S, R, T> PaymentMandateService<V, C, G, S, R, T>
where
    V: PaymentMandateProofVerifier,
    C: CredentialProvider<PaymentMandateCredentialScope>,
    G: PaymentMandateGateway,
    S: PaymentMandateStore,
    R: ReceiptSink<PaymentMandateReceipt>,
    T: Clock,
{
    #[must_use]
    pub const fn new(dependencies: PaymentMandateServiceDependencies<V, C, G, S, R, T>) -> Self {
        Self { dependencies }
    }

    /// Executes one exact `SetupIntent` capability creation.
    #[allow(
        clippy::too_many_lines,
        reason = "security ordering remains linear and reviewable"
    )]
    pub fn execute(
        &self,
        request: ExecutePaymentMandateRequest,
    ) -> Result<PaymentMandateWorkflowOutcome, PaymentMandateServiceError> {
        let now = self.dependencies.clock.now()?;
        let canonical = StripePaymentMandateProfile
            .canonicalize(&request.action.canonical_bytes()?)
            .map_err(|_| PaymentMandateServiceError::Profile)?;
        let proof = self.dependencies.proof_verifier.verify(
            &request.proof,
            &canonical,
            &request.auths_request,
        )?;
        let action_digest = request.action.digest()?;
        let policy_digest = request.policy.digest()?;
        let evidence_digest = request.evidence.digest()?;
        let consent_digest = request
            .consent
            .as_ref()
            .map(super::PaymentConsentEvidenceV1::digest)
            .transpose()?;

        let authorized = match proof {
            PaymentMandateProofDecision::Authorized(authorized) => {
                if authorized.command().action() != &request.action {
                    return Err(PaymentMandateServiceError::Profile);
                }
                authorized
            }
            PaymentMandateProofDecision::Denied { code }
            | PaymentMandateProofDecision::Indeterminate { code } => {
                let receipt = decision_receipt(
                    &request,
                    policy_digest,
                    action_digest,
                    consent_digest,
                    evidence_digest,
                    0,
                    &self.dependencies.executed_configuration,
                    false,
                    code,
                    None,
                    now,
                );
                self.append(PaymentMandateReceipt::Decision(Box::new(receipt.clone())))?;
                return Ok(PaymentMandateWorkflowOutcome::Rejected {
                    receipt: Box::new(receipt),
                    persisted: true,
                });
            }
        };

        // Literal configuration inequality is a no-side-effect result.
        if request.required_configuration != self.dependencies.executed_configuration {
            let bounded = PaymentMandateDecision {
                decision: PaymentMandateDecisionClass::Denied,
                code: PaymentMandateDecisionCode::ConfigurationMismatch
                    .as_str()
                    .into(),
                stage: PaymentMandateDecisionStage::Configuration,
                eligibility: None,
            };
            return Ok(PaymentMandateWorkflowOutcome::Rejected {
                receipt: Box::new(decision_receipt(
                    &request,
                    policy_digest,
                    action_digest,
                    consent_digest,
                    evidence_digest,
                    0,
                    &self.dependencies.executed_configuration,
                    true,
                    "authorized".into(),
                    Some(bounded),
                    now,
                )),
                persisted: false,
            });
        }

        if let Some(existing) = self.dependencies.store.get(&request.workflow_id)? {
            if existing.action_digest() == &action_digest
                && existing.policy_digest() == &policy_digest
                && consent_digest.as_ref() == Some(existing.consent_digest())
            {
                return Ok(PaymentMandateWorkflowOutcome::Replay(existing));
            }
            return Ok(PaymentMandateWorkflowOutcome::Conflict(existing));
        }

        let durable_active = self.dependencies.store.active_count(
            request.action.stripe_account_id(),
            request.action.customer_id(),
        )?;
        let bounded = evaluate_payment_mandate(&PaymentMandateEvaluationContext {
            policy: &request.policy,
            action: &request.action,
            consent: request.consent.as_ref(),
            evidence: &request.evidence,
            required_configuration: &request.required_configuration,
            executed_configuration: &self.dependencies.executed_configuration,
            durable_active_before: durable_active,
            now,
        });
        let decision = decision_receipt(
            &request,
            policy_digest.clone(),
            action_digest.clone(),
            consent_digest.clone(),
            evidence_digest,
            durable_active,
            &self.dependencies.executed_configuration,
            true,
            "authorized".into(),
            Some(bounded.clone()),
            now,
        );
        self.append(PaymentMandateReceipt::Decision(Box::new(decision.clone())))?;
        if bounded.decision != PaymentMandateDecisionClass::Eligible {
            return Ok(PaymentMandateWorkflowOutcome::Rejected {
                receipt: Box::new(decision),
                persisted: true,
            });
        }
        let consent = request
            .consent
            .clone()
            .ok_or(PaymentMandateServiceError::Invariant)?;
        let consent_digest = consent_digest.ok_or(PaymentMandateServiceError::Invariant)?;
        let decision_digest = decision.digest()?;
        let reserved = match self
            .dependencies
            .store
            .reserve(ReservePaymentMandateRequest {
                workflow_id: request.workflow_id.clone(),
                stripe_account_id: request.action.stripe_account_id().clone(),
                customer_id: request.action.customer_id().clone(),
                payment_method_id: request.action.payment_method_id().clone(),
                reference: request.action.reference().into(),
                action_digest: action_digest.clone(),
                policy_digest: policy_digest.clone(),
                consent_digest,
                decision_receipt_digest: decision_digest.clone(),
                maximum_active: request.policy.maximum_active_mandates_per_customer(),
                provider_active: request.evidence.active_mandate_count(),
                now,
            })? {
            ReservePaymentMandateResult::Reserved(record) => record,
            ReservePaymentMandateResult::Replay(record) => {
                return Ok(PaymentMandateWorkflowOutcome::Replay(record));
            }
            ReservePaymentMandateResult::Conflict(record)
            | ReservePaymentMandateResult::ConsentAlreadyConsumed(record)
            | ReservePaymentMandateResult::DuplicateScope(record) => {
                return Ok(PaymentMandateWorkflowOutcome::Conflict(record));
            }
            ReservePaymentMandateResult::CapacityExceeded => {
                return Ok(PaymentMandateWorkflowOutcome::Rejected {
                    receipt: Box::new(decision),
                    persisted: true,
                });
            }
        };
        self.append_transition(
            &reserved,
            &decision_digest,
            "capability-reserved",
            false,
            false,
            false,
            now,
        )?;
        let claimed = self.dependencies.store.transition(
            &request.workflow_id,
            PaymentMandateCapabilityState::Reserved,
            PaymentMandateCapabilityState::Claimed,
            None,
            now,
        )?;
        self.append_transition(
            &claimed,
            &decision_digest,
            "claim-acquired",
            false,
            false,
            false,
            now,
        )?;

        // The credential broker is reached only after the capability claim.
        let credential = self
            .dependencies
            .credential_provider
            .credential(request.action.stripe_account_id())?;
        let command = VerifiedPaymentMandateCommand::new(
            *authorized,
            request.workflow_id.clone(),
            consent,
            request.evidence.clone(),
            claimed,
        );
        let reread = self.dependencies.stripe_gateway.reread_critical_evidence(
            &command,
            &credential,
            now,
        )?;
        if !critical_evidence_equal(&request.evidence, &reread) {
            let released = self.dependencies.store.transition(
                &request.workflow_id,
                PaymentMandateCapabilityState::Claimed,
                PaymentMandateCapabilityState::Released,
                None,
                now,
            )?;
            self.append_transition(
                &released,
                &decision_digest,
                "critical-evidence-changed",
                false,
                true,
                true,
                now,
            )?;
            return Ok(PaymentMandateWorkflowOutcome::ProviderFailed {
                code: "bounded-evidence-changed".into(),
                record: released,
            });
        }
        let attempting = self.dependencies.store.transition(
            &request.workflow_id,
            PaymentMandateCapabilityState::Claimed,
            PaymentMandateCapabilityState::Attempting,
            None,
            now,
        )?;
        self.append_transition(
            &attempting,
            &decision_digest,
            "setup-intent-attempting",
            true,
            true,
            true,
            now,
        )?;
        let effect =
            self.dependencies
                .stripe_gateway
                .create_and_confirm(&command, &credential, now)?;
        self.finish_effect(effect, &attempting, &decision_digest, now)
    }

    /// Reconciles an uncertain or customer-action state by provider observation.
    pub fn reconcile(
        &self,
        workflow_id: &str,
    ) -> Result<PaymentMandateWorkflowOutcome, PaymentMandateServiceError> {
        let now = self.dependencies.clock.now()?;
        let current = self
            .dependencies
            .store
            .get(workflow_id)?
            .ok_or(PaymentMandateServiceError::State)?;
        if !matches!(
            current.state(),
            PaymentMandateCapabilityState::OutcomeUnknown
                | PaymentMandateCapabilityState::CustomerActionRequired
        ) {
            return Ok(PaymentMandateWorkflowOutcome::Replay(current));
        }
        let credential = self
            .dependencies
            .credential_provider
            .credential(current.stripe_account_id())?;
        let observed = self
            .dependencies
            .stripe_gateway
            .reconcile(&current, &credential, now)?;
        let (next, projection, event, code) = match observed {
            PaymentMandateReconciliationOutcome::Succeeded(value) => (
                PaymentMandateCapabilityState::Committed,
                Some(value),
                "reconcile-succeeded",
                "payment-mandate-authorized",
            ),
            PaymentMandateReconciliationOutcome::KnownFailure(value) => (
                PaymentMandateCapabilityState::Released,
                Some(value),
                "reconcile-known-failure",
                "payment-mandate-provider-failed",
            ),
            PaymentMandateReconciliationOutcome::CustomerActionRequired(value) => {
                return Ok(PaymentMandateWorkflowOutcome::CustomerActionRequired {
                    record: current,
                    projection: value,
                });
            }
            PaymentMandateReconciliationOutcome::StillUnknown(value) => {
                return Ok(PaymentMandateWorkflowOutcome::OutcomeUnknown {
                    record: current,
                    projection: value,
                });
            }
        };
        let projection = projection.ok_or(PaymentMandateServiceError::Invariant)?;
        if !provider_matches_record(&projection, &current) {
            return Err(PaymentMandateServiceError::Invariant);
        }
        let updated = self.dependencies.store.transition(
            workflow_id,
            current.state(),
            next,
            Some(projection.clone()),
            now,
        )?;
        self.append_observation(&updated, projection, true, now)?;
        self.append_transition(
            &updated,
            current.decision_receipt_digest(),
            event,
            true,
            true,
            true,
            now,
        )?;
        Ok(PaymentMandateWorkflowOutcome::Completed {
            code: code.into(),
            record: updated,
        })
    }

    fn finish_effect(
        &self,
        effect: PaymentMandateEffect,
        attempting: &PaymentMandateCapabilityRecord,
        decision_digest: &DigestHex,
        now: u64,
    ) -> Result<PaymentMandateWorkflowOutcome, PaymentMandateServiceError> {
        let workflow_id = attempting.workflow_id();
        match effect {
            PaymentMandateEffect::Succeeded(projection) => {
                if !provider_matches_record(&projection, attempting) {
                    return Err(PaymentMandateServiceError::Invariant);
                }
                let record = self.dependencies.store.transition(
                    workflow_id,
                    PaymentMandateCapabilityState::Attempting,
                    PaymentMandateCapabilityState::Committed,
                    Some(projection.clone()),
                    now,
                )?;
                self.append_observation(&record, projection, false, now)?;
                self.append_transition(
                    &record,
                    decision_digest,
                    "provider-succeeded",
                    true,
                    true,
                    true,
                    now,
                )?;
                Ok(PaymentMandateWorkflowOutcome::Completed {
                    code: "payment-mandate-authorized".into(),
                    record,
                })
            }
            PaymentMandateEffect::KnownFailure { code, projection } => {
                let record = self.dependencies.store.transition(
                    workflow_id,
                    PaymentMandateCapabilityState::Attempting,
                    PaymentMandateCapabilityState::Released,
                    projection.clone(),
                    now,
                )?;
                if let Some(value) = projection {
                    self.append_observation(&record, value, false, now)?;
                }
                self.append_transition(
                    &record,
                    decision_digest,
                    "known-failure-released",
                    true,
                    true,
                    true,
                    now,
                )?;
                Ok(PaymentMandateWorkflowOutcome::ProviderFailed { code, record })
            }
            PaymentMandateEffect::CustomerActionRequired(projection) => {
                let record = self.dependencies.store.transition(
                    workflow_id,
                    PaymentMandateCapabilityState::Attempting,
                    PaymentMandateCapabilityState::CustomerActionRequired,
                    Some(projection.clone()),
                    now,
                )?;
                self.append_observation(&record, projection.clone(), false, now)?;
                self.append_transition(
                    &record,
                    decision_digest,
                    "customer-action-required",
                    true,
                    true,
                    true,
                    now,
                )?;
                Ok(PaymentMandateWorkflowOutcome::CustomerActionRequired { record, projection })
            }
            PaymentMandateEffect::Processing(projection) => {
                self.hold_unknown(attempting, decision_digest, Some(projection), now)
            }
            PaymentMandateEffect::OutcomeUnknown(projection) => {
                self.hold_unknown(attempting, decision_digest, projection, now)
            }
        }
    }

    fn hold_unknown(
        &self,
        attempting: &PaymentMandateCapabilityRecord,
        decision_digest: &DigestHex,
        projection: Option<super::PaymentMandateProviderProjection>,
        now: u64,
    ) -> Result<PaymentMandateWorkflowOutcome, PaymentMandateServiceError> {
        let record = self.dependencies.store.transition(
            attempting.workflow_id(),
            PaymentMandateCapabilityState::Attempting,
            PaymentMandateCapabilityState::OutcomeUnknown,
            projection.clone(),
            now,
        )?;
        if let Some(value) = projection.as_ref() {
            self.append_observation(&record, value.clone(), false, now)?;
        }
        self.append_transition(
            &record,
            decision_digest,
            "outcome-unknown-held",
            true,
            true,
            true,
            now,
        )?;
        Ok(PaymentMandateWorkflowOutcome::OutcomeUnknown { record, projection })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "receipt booleans mirror ordered boundaries"
    )]
    fn append_transition(
        &self,
        record: &PaymentMandateCapabilityRecord,
        decision_receipt_digest: &DigestHex,
        event: &str,
        execution_attempted: bool,
        credential_requested: bool,
        stripe_called: bool,
        now: u64,
    ) -> Result<(), PaymentMandateServiceError> {
        let receipt = PaymentMandateTransitionReceipt {
            schema: PAYMENT_MANDATE_RECEIPT_SCHEMA.into(),
            decision_receipt_digest: decision_receipt_digest.clone(),
            action_digest: record.action_digest().clone(),
            policy_digest: record.policy_digest().clone(),
            semantic_event: event.into(),
            capability: record.clone(),
            authorization_established: true,
            consent_consumed: true,
            capability_reserved: true,
            execution_attempted,
            credential_requested,
            stripe_called,
            provider_accepted: record.state() == PaymentMandateCapabilityState::Committed,
            no_immediate_charge: true,
            recorded_at: now,
        };
        self.append(PaymentMandateReceipt::Transition(Box::new(receipt)))
    }

    fn append_observation(
        &self,
        record: &PaymentMandateCapabilityRecord,
        provider: super::PaymentMandateProviderProjection,
        reconciled: bool,
        now: u64,
    ) -> Result<(), PaymentMandateServiceError> {
        let receipt = PaymentMandateObservationReceipt {
            schema: PAYMENT_MANDATE_RECEIPT_SCHEMA.into(),
            workflow_id: record.workflow_id().into(),
            action_digest: record.action_digest().clone(),
            policy_digest: record.policy_digest().clone(),
            decision_receipt_digest: record.decision_receipt_digest().clone(),
            capability_id: record.capability_id().clone(),
            exact_provider_equality: provider_matches_record(&provider, record),
            provider,
            reconciled,
            client_secret_exposed: false,
            no_immediate_charge: true,
            residual_assumptions: vec![
                "a later payment still requires its own exact Auths authority and bounded policy"
                    .into(),
            ],
            recorded_at: now,
        };
        self.append(PaymentMandateReceipt::Observation(Box::new(receipt)))
    }

    fn append(&self, receipt: PaymentMandateReceipt) -> Result<(), PaymentMandateServiceError> {
        self.dependencies.receipt_sink.append(&receipt)?;
        Ok(())
    }
}

/// Public workflow outcome.
pub enum PaymentMandateWorkflowOutcome {
    Rejected {
        receipt: Box<PaymentMandateDecisionReceipt>,
        persisted: bool,
    },
    Completed {
        code: String,
        record: PaymentMandateCapabilityRecord,
    },
    ProviderFailed {
        code: String,
        record: PaymentMandateCapabilityRecord,
    },
    CustomerActionRequired {
        record: PaymentMandateCapabilityRecord,
        projection: super::PaymentMandateProviderProjection,
    },
    OutcomeUnknown {
        record: PaymentMandateCapabilityRecord,
        projection: Option<super::PaymentMandateProviderProjection>,
    },
    Replay(PaymentMandateCapabilityRecord),
    Conflict(PaymentMandateCapabilityRecord),
}

/// Closed service failure.
#[derive(Debug, thiserror::Error)]
pub enum PaymentMandateServiceError {
    #[error(transparent)]
    Port(#[from] PortError),
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
    #[error(transparent)]
    MandateState(#[from] super::MandateStateError),
    #[error("payment-mandate profile mismatch")]
    Profile,
    #[error("payment-mandate state not found")]
    State,
    #[error("payment-mandate invariant violated")]
    Invariant,
}

#[allow(clippy::too_many_arguments, reason = "receipt binds every trust input")]
fn decision_receipt(
    request: &ExecutePaymentMandateRequest,
    policy_digest: DigestHex,
    action_digest: DigestHex,
    consent_digest: Option<DigestHex>,
    evidence_digest: DigestHex,
    durable_active_before: u32,
    executed_configuration: &StripePaymentMandateConfigurationV1,
    authorized: bool,
    auths_code: String,
    bounded_decision: Option<PaymentMandateDecision>,
    now: u64,
) -> PaymentMandateDecisionReceipt {
    PaymentMandateDecisionReceipt {
        schema: PAYMENT_MANDATE_RECEIPT_SCHEMA.into(),
        workflow_id: request.workflow_id.clone(),
        policy: request.policy.clone(),
        policy_digest,
        exact_action: request.action.clone(),
        action_digest,
        consent: request.consent.clone(),
        consent_digest,
        evidence: request.evidence.clone(),
        evidence_digest,
        durable_active_before,
        required_configuration: request.required_configuration.clone(),
        executed_configuration: executed_configuration.clone(),
        configuration_equal: request.required_configuration == *executed_configuration,
        auths_decision: if authorized { "authorized" } else { "denied" }.into(),
        auths_code,
        authorization_established: authorized,
        bounded_decision,
        consent_consumed: false,
        capability_reserved: false,
        credential_requested: false,
        stripe_called: false,
        no_immediate_charge: true,
        decided_at: now,
    }
}

fn critical_evidence_equal(
    original: &super::PaymentMandateEvidenceV1,
    reread: &super::PaymentMandateEvidenceV1,
) -> bool {
    original.stripe_account_id() == reread.stripe_account_id()
        && original.connect_account() == reread.connect_account()
        && original.customer_id() == reread.customer_id()
        && original.customer_exists() == reread.customer_exists()
        && original.payment_method_id() == reread.payment_method_id()
        && original.payment_method_type() == reread.payment_method_type()
        && original.payment_method_customer_id() == reread.payment_method_customer_id()
        && original.active_mandate_count() == reread.active_mandate_count()
        && original.duplicate_scope_exists() == reread.duplicate_scope_exists()
        && original.ambiguous_setup_exists() == reread.ambiguous_setup_exists()
        && original.stripe_api_version() == reread.stripe_api_version()
        && original.livemode() == reread.livemode()
}

fn provider_matches_record(
    provider: &super::PaymentMandateProviderProjection,
    record: &PaymentMandateCapabilityRecord,
) -> bool {
    &provider.customer_id == record.customer_id()
        && &provider.payment_method_id == record.payment_method_id()
        && !provider.livemode
}
