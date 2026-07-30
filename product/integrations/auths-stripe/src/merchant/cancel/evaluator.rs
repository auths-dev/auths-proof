//! Pure deterministic evaluator for exact `PaymentIntent` cancellation.

use serde::{Deserialize, Serialize};

use super::{PaymentCancelEvidenceV1, StripeExactPaymentCancelV1};
use crate::{
    merchant::{
        MerchantEvaluatorCommitment, MerchantOperation, MerchantValidationError,
        PAYMENT_CANCEL_PROFILE, StripeBoundedMerchantPaymentPolicyV1,
        StripeMerchantEvaluatorConfigurationV1,
    },
    types::DigestHex,
};

/// Complete eligibility output for the cancellation claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentCancelEligibility {
    pub action_digest: DigestHex,
    pub policy_digest: DigestHex,
    pub evidence_digest: DigestHex,
    pub release_authorization_hold: bool,
    pub authorization_release_minor: u64,
}

/// Three-way pure decision class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentCancelDecisionClass {
    Eligible,
    Denied,
    Indeterminate,
}

/// Stable stage at which evaluation stopped.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentCancelDecisionStage {
    Configuration,
    Structure,
    Policy,
    Evidence,
    Scope,
    ProviderState,
    AuthorizationLink,
    Eligible,
}

/// Stable cancellation result code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentCancelDecisionCode {
    PaymentCancelAuthorized,
    PaymentCancelStateIneligible,
    PaymentCancelReasonDenied,
    PaymentCancelTargetMismatch,
    PaymentCancelAlreadyTerminal,
    PaymentCancelCaptureConflict,
    PaymentCancelOutcomeUnknown,
    ConfigurationMismatch,
    InvalidAction,
    InvalidPolicy,
    InvalidEvidence,
    PolicyExpired,
    ActionExpired,
    EvidenceStale,
    TestModeRequired,
    AccountDenied,
    ConnectAccountDenied,
    CustomerDenied,
    OrderDenied,
    ApiVersionDenied,
    AuthorizationLinkMismatch,
    ArithmeticOverflow,
}

impl PaymentCancelDecisionCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PaymentCancelAuthorized => "payment-cancel-authorized",
            Self::PaymentCancelStateIneligible => "payment-cancel-state-ineligible",
            Self::PaymentCancelReasonDenied => "payment-cancel-reason-denied",
            Self::PaymentCancelTargetMismatch => "payment-cancel-target-mismatch",
            Self::PaymentCancelAlreadyTerminal => "payment-cancel-already-terminal",
            Self::PaymentCancelCaptureConflict => "payment-cancel-capture-conflict",
            Self::PaymentCancelOutcomeUnknown => "payment-cancel-outcome-unknown",
            Self::ConfigurationMismatch => "configuration-mismatch",
            Self::InvalidAction => "invalid-action",
            Self::InvalidPolicy => "invalid-policy",
            Self::InvalidEvidence => "invalid-evidence",
            Self::PolicyExpired => "policy-expired",
            Self::ActionExpired => "action-expired",
            Self::EvidenceStale => "evidence-stale",
            Self::TestModeRequired => "test-mode-required",
            Self::AccountDenied => "account-denied",
            Self::ConnectAccountDenied => "connect-account-denied",
            Self::CustomerDenied => "customer-denied",
            Self::OrderDenied => "order-denied",
            Self::ApiVersionDenied => "api-version-denied",
            Self::AuthorizationLinkMismatch => "authorization-link-mismatch",
            Self::ArithmeticOverflow => "arithmetic-overflow",
        }
    }
}

/// Canonical pure cancellation decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentCancelDecision {
    pub decision: PaymentCancelDecisionClass,
    pub stage: PaymentCancelDecisionStage,
    pub code: String,
    pub required_configuration_digest: DigestHex,
    pub executed_configuration_digest: DigestHex,
    pub eligibility: Option<PaymentCancelEligibility>,
}

/// Complete immutable context for pure evaluation.
pub struct PaymentCancelEvaluationContext<'a> {
    pub action: &'a StripeExactPaymentCancelV1,
    pub evidence: &'a PaymentCancelEvidenceV1,
    pub policy: &'a StripeBoundedMerchantPaymentPolicyV1,
    pub required_configuration: &'a StripeMerchantEvaluatorConfigurationV1,
    pub executed_configuration: &'a StripeMerchantEvaluatorConfigurationV1,
    pub now: u64,
}

fn stopped(
    class: PaymentCancelDecisionClass,
    stage: PaymentCancelDecisionStage,
    code: PaymentCancelDecisionCode,
    required: DigestHex,
    executed: DigestHex,
) -> PaymentCancelDecision {
    PaymentCancelDecision {
        decision: class,
        stage,
        code: code.as_str().into(),
        required_configuration_digest: required,
        executed_configuration_digest: executed,
        eligibility: None,
    }
}

/// Evaluates one exact cancellation without persistence or provider I/O.
#[allow(
    clippy::too_many_lines,
    reason = "the closed fail-closed check ordering remains linear and auditable"
)]
#[must_use]
pub fn evaluate_payment_cancel(
    context: &PaymentCancelEvaluationContext<'_>,
) -> PaymentCancelDecision {
    let Ok(required) = context.required_configuration.digest() else {
        return stopped(
            PaymentCancelDecisionClass::Indeterminate,
            PaymentCancelDecisionStage::Configuration,
            PaymentCancelDecisionCode::InvalidPolicy,
            DigestHex::from_digest_bytes([0; 32]),
            DigestHex::from_digest_bytes([0; 32]),
        );
    };
    let Ok(executed) = context.executed_configuration.digest() else {
        return stopped(
            PaymentCancelDecisionClass::Indeterminate,
            PaymentCancelDecisionStage::Configuration,
            PaymentCancelDecisionCode::InvalidPolicy,
            required,
            DigestHex::from_digest_bytes([0; 32]),
        );
    };
    if context.required_configuration != context.executed_configuration || required != executed {
        return stopped(
            PaymentCancelDecisionClass::Denied,
            PaymentCancelDecisionStage::Configuration,
            PaymentCancelDecisionCode::ConfigurationMismatch,
            required,
            executed,
        );
    }
    if !matches!(
        context.action.current_status(),
        "requires_payment_method"
            | "requires_capture"
            | "requires_confirmation"
            | "requires_action"
    ) {
        let code = if matches!(context.action.current_status(), "succeeded" | "canceled") {
            PaymentCancelDecisionCode::PaymentCancelAlreadyTerminal
        } else {
            PaymentCancelDecisionCode::PaymentCancelStateIneligible
        };
        return stopped(
            PaymentCancelDecisionClass::Denied,
            PaymentCancelDecisionStage::ProviderState,
            code,
            required,
            executed,
        );
    }
    if context.action.validate().is_err() {
        return stopped(
            PaymentCancelDecisionClass::Denied,
            PaymentCancelDecisionStage::Structure,
            PaymentCancelDecisionCode::InvalidAction,
            required,
            executed,
        );
    }
    if context.policy.validate().is_err() {
        return stopped(
            PaymentCancelDecisionClass::Indeterminate,
            PaymentCancelDecisionStage::Policy,
            PaymentCancelDecisionCode::InvalidPolicy,
            required,
            executed,
        );
    }
    if context.evidence.validate().is_err() {
        return stopped(
            PaymentCancelDecisionClass::Indeterminate,
            PaymentCancelDecisionStage::Evidence,
            PaymentCancelDecisionCode::InvalidEvidence,
            required,
            executed,
        );
    }
    let Ok(policy_digest) = context.policy.digest() else {
        return stopped(
            PaymentCancelDecisionClass::Indeterminate,
            PaymentCancelDecisionStage::Policy,
            PaymentCancelDecisionCode::InvalidPolicy,
            required,
            executed,
        );
    };
    if context.action.profile() != PAYMENT_CANCEL_PROFILE
        || context.action.required_policy_digest() != &policy_digest
        || context.action.required_evaluator() != &MerchantEvaluatorCommitment::v1()
        || context.action.required_configuration_digest() != &required
        || context.required_configuration.policy_digest() != &policy_digest
        || context.required_configuration.exact_action_profile() != PAYMENT_CANCEL_PROFILE
    {
        return stopped(
            PaymentCancelDecisionClass::Denied,
            PaymentCancelDecisionStage::Configuration,
            PaymentCancelDecisionCode::ConfigurationMismatch,
            required,
            executed,
        );
    }
    if context.now < context.policy.valid_from() || context.now > context.policy.expires_at() {
        return stopped(
            PaymentCancelDecisionClass::Denied,
            PaymentCancelDecisionStage::Policy,
            PaymentCancelDecisionCode::PolicyExpired,
            required,
            executed,
        );
    }
    if context.now > context.action.expires_at()
        || context.action.expires_at().saturating_sub(context.now)
            > context.policy.maximum_action_lifetime_seconds()
    {
        return stopped(
            PaymentCancelDecisionClass::Denied,
            PaymentCancelDecisionStage::Structure,
            PaymentCancelDecisionCode::ActionExpired,
            required,
            executed,
        );
    }
    let Some(evidence_age) = context.now.checked_sub(context.evidence.observed_at()) else {
        return stopped(
            PaymentCancelDecisionClass::Indeterminate,
            PaymentCancelDecisionStage::Evidence,
            PaymentCancelDecisionCode::ArithmeticOverflow,
            required,
            executed,
        );
    };
    if evidence_age > context.policy.maximum_evidence_age_seconds() {
        return stopped(
            PaymentCancelDecisionClass::Indeterminate,
            PaymentCancelDecisionStage::Evidence,
            PaymentCancelDecisionCode::EvidenceStale,
            required,
            executed,
        );
    }
    if context.evidence.livemode() {
        return stopped(
            PaymentCancelDecisionClass::Denied,
            PaymentCancelDecisionStage::Evidence,
            PaymentCancelDecisionCode::TestModeRequired,
            required,
            executed,
        );
    }
    if context.action.stripe_account_id() != context.evidence.stripe_account_id()
        || context.action.connect_account() != context.evidence.connect_account()
        || context.action.payment_intent_id() != context.evidence.payment_intent_id()
        || context.action.current_status() != context.evidence.payment_intent_status()
        || context.action.amount_minor() != context.evidence.amount_minor()
        || context.action.amount_capturable_minor() != context.evidence.amount_capturable_minor()
        || context.action.currency() != context.evidence.currency()
    {
        return stopped(
            PaymentCancelDecisionClass::Denied,
            PaymentCancelDecisionStage::Scope,
            PaymentCancelDecisionCode::PaymentCancelTargetMismatch,
            required,
            executed,
        );
    }
    if context.action.customer_id() != context.evidence.customer_id()
        || context.action.order_scope() != context.evidence.order_scope()
    {
        return stopped(
            PaymentCancelDecisionClass::Denied,
            PaymentCancelDecisionStage::Scope,
            PaymentCancelDecisionCode::PaymentCancelTargetMismatch,
            required,
            executed,
        );
    }
    if context
        .policy
        .allowed_operations()
        .binary_search(&MerchantOperation::Cancel)
        .is_err()
    {
        return stopped(
            PaymentCancelDecisionClass::Denied,
            PaymentCancelDecisionStage::Policy,
            PaymentCancelDecisionCode::PaymentCancelStateIneligible,
            required,
            executed,
        );
    }
    if context
        .policy
        .allowed_cancellation_reasons()
        .binary_search(&context.action.cancellation_reason().as_str().to_owned())
        .is_err()
    {
        return stopped(
            PaymentCancelDecisionClass::Denied,
            PaymentCancelDecisionStage::Policy,
            PaymentCancelDecisionCode::PaymentCancelReasonDenied,
            required,
            executed,
        );
    }
    if context
        .policy
        .allowed_test_account_ids()
        .binary_search(context.action.stripe_account_id())
        .is_err()
    {
        return stopped(
            PaymentCancelDecisionClass::Denied,
            PaymentCancelDecisionStage::Scope,
            PaymentCancelDecisionCode::AccountDenied,
            required,
            executed,
        );
    }
    if context
        .policy
        .allowed_connect_accounts()
        .binary_search(context.action.connect_account())
        .is_err()
    {
        return stopped(
            PaymentCancelDecisionClass::Denied,
            PaymentCancelDecisionStage::Scope,
            PaymentCancelDecisionCode::ConnectAccountDenied,
            required,
            executed,
        );
    }
    if context
        .policy
        .allowed_customer_ids()
        .binary_search(context.action.customer_id())
        .is_err()
    {
        return stopped(
            PaymentCancelDecisionClass::Denied,
            PaymentCancelDecisionStage::Scope,
            PaymentCancelDecisionCode::CustomerDenied,
            required,
            executed,
        );
    }
    if context
        .policy
        .allowed_order_scopes()
        .binary_search(&context.action.order_scope().to_owned())
        .is_err()
    {
        return stopped(
            PaymentCancelDecisionClass::Denied,
            PaymentCancelDecisionStage::Scope,
            PaymentCancelDecisionCode::OrderDenied,
            required,
            executed,
        );
    }
    if context
        .policy
        .allowed_api_versions()
        .binary_search(&context.action.stripe_api_version().to_owned())
        .is_err()
        || context.action.stripe_api_version() != context.evidence.stripe_api_version()
    {
        return stopped(
            PaymentCancelDecisionClass::Denied,
            PaymentCancelDecisionStage::Scope,
            PaymentCancelDecisionCode::ApiVersionDenied,
            required,
            executed,
        );
    }
    if !matches!(
        context.evidence.payment_intent_status(),
        "requires_payment_method"
            | "requires_capture"
            | "requires_confirmation"
            | "requires_action"
    ) {
        let code = if matches!(
            context.evidence.payment_intent_status(),
            "succeeded" | "canceled"
        ) {
            PaymentCancelDecisionCode::PaymentCancelAlreadyTerminal
        } else {
            PaymentCancelDecisionCode::PaymentCancelStateIneligible
        };
        return stopped(
            PaymentCancelDecisionClass::Denied,
            PaymentCancelDecisionStage::ProviderState,
            code,
            required,
            executed,
        );
    }
    let requires_hold_release = context.evidence.payment_intent_status() == "requires_capture";
    if context.action.authorization_action_digest()
        != context.evidence.authorization_action_digest()
        || context.action.authorization_reservation_id()
            != context.evidence.authorization_reservation_id()
        || (requires_hold_release
            && (!matches!(
                context.evidence.authorization_state(),
                Some(
                    crate::merchant::MerchantReservationState::Authorized
                        | crate::merchant::MerchantReservationState::ReconciledAuthorized
                )
            ) || context.evidence.authorization_workflow_id().is_none()))
    {
        return stopped(
            PaymentCancelDecisionClass::Denied,
            PaymentCancelDecisionStage::AuthorizationLink,
            PaymentCancelDecisionCode::AuthorizationLinkMismatch,
            required,
            executed,
        );
    }
    let Ok(action_digest) = context.action.digest() else {
        return stopped(
            PaymentCancelDecisionClass::Indeterminate,
            PaymentCancelDecisionStage::Structure,
            PaymentCancelDecisionCode::InvalidAction,
            required,
            executed,
        );
    };
    let Ok(evidence_digest) = context.evidence.digest() else {
        return stopped(
            PaymentCancelDecisionClass::Indeterminate,
            PaymentCancelDecisionStage::Evidence,
            PaymentCancelDecisionCode::InvalidEvidence,
            required,
            executed,
        );
    };
    PaymentCancelDecision {
        decision: PaymentCancelDecisionClass::Eligible,
        stage: PaymentCancelDecisionStage::Eligible,
        code: PaymentCancelDecisionCode::PaymentCancelAuthorized
            .as_str()
            .into(),
        required_configuration_digest: required,
        executed_configuration_digest: executed,
        eligibility: Some(PaymentCancelEligibility {
            action_digest,
            policy_digest,
            evidence_digest,
            release_authorization_hold: requires_hold_release,
            authorization_release_minor: if requires_hold_release {
                context.evidence.amount_capturable_minor()
            } else {
                0
            },
        }),
    }
}

impl From<MerchantValidationError> for PaymentCancelDecisionCode {
    fn from(value: MerchantValidationError) -> Self {
        match value {
            MerchantValidationError::InvalidAction => Self::InvalidAction,
            MerchantValidationError::InvalidPolicy
            | MerchantValidationError::InvalidConfiguration => Self::InvalidPolicy,
            MerchantValidationError::InvalidEvidence
            | MerchantValidationError::Canonicalization => Self::InvalidEvidence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        canonical::sha256,
        merchant::{
            MerchantConnectAccount, MerchantOperation, MerchantReservationState,
            PaymentCancelEvidenceInput, PaymentCancellationReason, StripeExactPaymentCancelInput,
        },
        test_support::{NOW, merchant_cancel_configuration, merchant_policy},
        types::{Currency, CustomerId, PaymentIntentId, StripeAccountId},
    };

    fn evaluate(
        status: &str,
        reason: PaymentCancellationReason,
    ) -> (
        PaymentCancelDecision,
        StripeExactPaymentCancelV1,
        PaymentCancelEvidenceV1,
        StripeBoundedMerchantPaymentPolicyV1,
        StripeMerchantEvaluatorConfigurationV1,
    ) {
        let policy = merchant_policy(MerchantOperation::Cancel, 0, 0);
        let configuration = merchant_cancel_configuration(&policy);
        let account = StripeAccountId::parse("acct_authsdemo01").unwrap();
        let customer = CustomerId::parse("cus_authsdemo00000001").unwrap();
        let payment_intent = PaymentIntentId::parse("pi_cancel_evaluator_test").unwrap();
        let currency = Currency::parse("usd").unwrap();
        let requires_hold = status == "requires_capture";
        let authorization_action_digest = requires_hold.then(|| sha256(b"authorization-action"));
        let authorization_reservation_id =
            requires_hold.then(|| sha256(b"authorization-reservation"));
        let evidence = PaymentCancelEvidenceV1::new(PaymentCancelEvidenceInput {
            stripe_account_id: account.clone(),
            connect_account: MerchantConnectAccount::Platform,
            payment_intent_id: payment_intent.clone(),
            latest_charge_id: None,
            customer_id: customer.clone(),
            order_scope: "order-demo-001".into(),
            amount_minor: 1_000,
            amount_capturable_minor: if requires_hold { 1_000 } else { 0 },
            currency: currency.clone(),
            payment_intent_status: status.into(),
            cancellation_eligible: true,
            livemode: false,
            stripe_api_version: "2025-04-30.basil".into(),
            authorization_workflow_id: requires_hold.then(|| "cancel-source-0001".into()),
            authorization_action_digest: authorization_action_digest.clone(),
            authorization_reservation_id: authorization_reservation_id.clone(),
            authorization_state: requires_hold.then_some(MerchantReservationState::Authorized),
            authorization_created_at: requires_hold.then_some(NOW - 30),
            observed_at: NOW - 5,
            source: "stripe-api-and-auths-store".into(),
            response_commitment: sha256(b"cancel-evidence"),
        })
        .unwrap();
        let action = StripeExactPaymentCancelV1::new(StripeExactPaymentCancelInput {
            stripe_account_id: account,
            connect_account: MerchantConnectAccount::Platform,
            payment_intent_id: payment_intent,
            customer_id: customer,
            order_scope: "order-demo-001".into(),
            current_status: status.into(),
            amount_minor: 1_000,
            amount_capturable_minor: if requires_hold { 1_000 } else { 0 },
            currency,
            cancellation_reason: reason,
            authorization_action_digest,
            authorization_reservation_id,
            stripe_api_version: "2025-04-30.basil".into(),
            required_policy_digest: policy.digest().unwrap(),
            required_configuration_digest: configuration.digest().unwrap(),
            executor_audience: "https://stripe-cancel.auths.dev".into(),
            expires_at: NOW + 120,
            nonce: sha256(b"cancel-action"),
        })
        .unwrap();
        let decision = evaluate_payment_cancel(&PaymentCancelEvaluationContext {
            action: &action,
            evidence: &evidence,
            policy: &policy,
            required_configuration: &configuration,
            executed_configuration: &configuration,
            now: NOW,
        });
        (decision, action, evidence, policy, configuration)
    }

    #[test]
    fn every_supported_state_and_reason_is_eligible_with_the_exact_hold_shape() {
        for status in [
            "requires_payment_method",
            "requires_capture",
            "requires_confirmation",
            "requires_action",
        ] {
            for reason in [
                PaymentCancellationReason::Duplicate,
                PaymentCancellationReason::Fraudulent,
                PaymentCancellationReason::RequestedByCustomer,
                PaymentCancellationReason::Abandoned,
            ] {
                let (decision, ..) = evaluate(status, reason);
                assert_eq!(
                    decision.decision,
                    PaymentCancelDecisionClass::Eligible,
                    "{status} / {}",
                    reason.as_str()
                );
                let eligibility = decision.eligibility.unwrap();
                assert_eq!(
                    eligibility.release_authorization_hold,
                    status == "requires_capture"
                );
                assert_eq!(
                    eligibility.authorization_release_minor,
                    if status == "requires_capture" {
                        1_000
                    } else {
                        0
                    }
                );
            }
        }
    }

    #[test]
    fn processing_and_terminal_states_have_stable_denial_codes() {
        let (_, action, evidence, policy, configuration) = evaluate(
            "requires_capture",
            PaymentCancellationReason::RequestedByCustomer,
        );
        for (status, expected) in [
            ("processing", "payment-cancel-state-ineligible"),
            ("succeeded", "payment-cancel-already-terminal"),
            ("canceled", "payment-cancel-already-terminal"),
        ] {
            let mut value = serde_json::to_value(&action).unwrap();
            value["current_status"] = status.into();
            let changed: StripeExactPaymentCancelV1 = serde_json::from_value(value).unwrap();
            let decision = evaluate_payment_cancel(&PaymentCancelEvaluationContext {
                action: &changed,
                evidence: &evidence,
                policy: &policy,
                required_configuration: &configuration,
                executed_configuration: &configuration,
                now: NOW,
            });
            assert_eq!(decision.decision, PaymentCancelDecisionClass::Denied);
            assert_eq!(decision.code, expected);
            assert!(decision.eligibility.is_none());
        }
    }

    #[test]
    fn reason_and_target_changes_deny_without_a_release_intent() {
        let (_, action, evidence, policy, configuration) =
            evaluate("requires_capture", PaymentCancellationReason::Fraudulent);
        let mut policy_value = serde_json::to_value(&policy).unwrap();
        policy_value["allowed_cancellation_reasons"] = serde_json::json!(["requested_by_customer"]);
        let restricted_policy: StripeBoundedMerchantPaymentPolicyV1 =
            serde_json::from_value(policy_value).unwrap();
        let restricted_configuration = merchant_cancel_configuration(&restricted_policy);
        let mut action_value = serde_json::to_value(&action).unwrap();
        action_value["required_policy_digest"] =
            serde_json::to_value(restricted_policy.digest().unwrap()).unwrap();
        action_value["required_configuration_digest"] =
            serde_json::to_value(restricted_configuration.digest().unwrap()).unwrap();
        let restricted_action: StripeExactPaymentCancelV1 =
            serde_json::from_value(action_value).unwrap();
        let reason_denied = evaluate_payment_cancel(&PaymentCancelEvaluationContext {
            action: &restricted_action,
            evidence: &evidence,
            policy: &restricted_policy,
            required_configuration: &restricted_configuration,
            executed_configuration: &restricted_configuration,
            now: NOW,
        });
        assert_eq!(reason_denied.code, "payment-cancel-reason-denied");
        assert!(reason_denied.eligibility.is_none());

        let mut evidence_value = serde_json::to_value(&evidence).unwrap();
        evidence_value["payment_intent_id"] = "pi_cancel_evaluator_changed".into();
        let changed_evidence: PaymentCancelEvidenceV1 =
            serde_json::from_value(evidence_value).unwrap();
        let target_denied = evaluate_payment_cancel(&PaymentCancelEvaluationContext {
            action: &action,
            evidence: &changed_evidence,
            policy: &policy,
            required_configuration: &configuration,
            executed_configuration: &configuration,
            now: NOW,
        });
        assert_eq!(target_denied.code, "payment-cancel-target-mismatch");
        assert!(target_denied.eligibility.is_none());
    }
}
