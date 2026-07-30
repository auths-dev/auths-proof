//! Pure bounded evaluator for one exact final capture.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use super::super::{
    MerchantAggregateSnapshot, MerchantOperation, MerchantReservationIntent,
    PAYMENT_CAPTURE_PROFILE, StripeBoundedMerchantPaymentPolicyV1,
    StripeMerchantEvaluatorConfigurationV1, fixed_merchant_metadata_commitment,
    merchant_statement_descriptor_commitment,
};
use super::{action::StripeExactPaymentCaptureV1, evidence::PaymentCaptureEvidenceV1};
use crate::types::DigestHex;

/// Successful settlement and hold-release calculation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentCaptureEligibility {
    /// Per-operation settlement ceiling.
    pub operation_ceiling_minor: u64,
    /// Per-customer settlement ceiling.
    pub customer_ceiling_minor: u64,
    /// Per-order settlement ceiling.
    pub order_ceiling_minor: u64,
    /// Effective inclusive settlement ceiling.
    pub effective_ceiling_minor: u64,
    /// Exact aggregate settlement reservation intents.
    pub settlement_reservations: Vec<MerchantReservationIntent>,
    /// Amount of the linked authorization hold released on commit.
    pub authorization_release_minor: u64,
}

/// Stable final-capture decision class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentCaptureDecisionClass {
    /// Complete inputs establish eligibility.
    Eligible,
    /// Complete inputs establish denial.
    Denied,
    /// Trusted state is unavailable or contradictory.
    Indeterminate,
}

/// Stable final-capture decision stage.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentCaptureDecisionStage {
    /// Required/executed configuration.
    Configuration,
    /// Policy identity or validity.
    Policy,
    /// Exact action validation.
    ExactAction,
    /// Protected provider and authorization evidence.
    Evidence,
    /// Exact linked authorization identity.
    AuthorizationLink,
    /// Account, Connect, Customer, order, currency, or API scope.
    StripeScope,
    /// Per-action, customer, or order ceilings.
    Limits,
    /// Aggregate settlement budget calculation.
    AggregateBudget,
    /// All pure checks succeeded.
    Complete,
}

/// Stable final-capture decision code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentCaptureDecisionCode {
    /// Exact final capture is eligible.
    PaymentCaptureAuthorized,
    /// `PaymentIntent` is not in an exact capturable state.
    PaymentIntentNotCapturable,
    /// Exact capture amount exceeds a limit or provider capacity.
    PaymentCaptureAmountExceeded,
    /// The remaining authorization window is insufficient.
    PaymentCaptureWindowExpired,
    /// The action does not match the durable authorization.
    PaymentAuthorizationLinkMismatch,
    /// An earlier capture already consumed this authorization.
    PaymentCaptureAlreadyExecuted,
    /// Protected provider facts contradict the exact action.
    PaymentCaptureProviderMismatch,
    /// Required and executed configurations differ.
    BoundedConfigurationMismatch,
    /// Policy is malformed or identity mismatched.
    BoundedPolicyInvalid,
    /// Policy is inactive.
    BoundedPolicyExpired,
    /// Exact action is malformed or does not bind runtime inputs.
    BoundedActionMismatch,
    /// Evidence is malformed or does not bind the action.
    BoundedEvidenceMismatch,
    /// Evidence is stale or from the future.
    BoundedEvidenceStale,
    /// Test mode is mandatory.
    BoundedTestModeRequired,
    /// Account or Connect context denied.
    BoundedAccountDenied,
    /// Customer outside configured scope.
    PaymentCustomerDenied,
    /// API version denied.
    BoundedApiVersionDenied,
    /// Currency denied.
    BoundedCurrencyDenied,
    /// Order denied.
    BoundedOrderDenied,
    /// Aggregate settlement budget has insufficient capacity.
    BoundedAggregateBudgetExceeded,
    /// Checked integer arithmetic failed.
    BoundedArithmeticOverflow,
}

impl PaymentCaptureDecisionCode {
    /// Stable literal code used in receipts and APIs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PaymentCaptureAuthorized => "payment-capture-authorized",
            Self::PaymentIntentNotCapturable => "payment-intent-not-capturable",
            Self::PaymentCaptureAmountExceeded => "payment-capture-amount-exceeded",
            Self::PaymentCaptureWindowExpired => "payment-capture-window-expired",
            Self::PaymentAuthorizationLinkMismatch => "payment-authorization-link-mismatch",
            Self::PaymentCaptureAlreadyExecuted => "payment-capture-already-executed",
            Self::PaymentCaptureProviderMismatch => "payment-capture-provider-mismatch",
            Self::BoundedConfigurationMismatch => "bounded-configuration-mismatch",
            Self::BoundedPolicyInvalid => "bounded-policy-invalid",
            Self::BoundedPolicyExpired => "bounded-policy-expired",
            Self::BoundedActionMismatch => "bounded-action-mismatch",
            Self::BoundedEvidenceMismatch => "bounded-evidence-mismatch",
            Self::BoundedEvidenceStale => "bounded-evidence-stale",
            Self::BoundedTestModeRequired => "bounded-test-mode-required",
            Self::BoundedAccountDenied => "bounded-account-denied",
            Self::PaymentCustomerDenied => "payment-customer-denied",
            Self::BoundedApiVersionDenied => "bounded-api-version-denied",
            Self::BoundedCurrencyDenied => "bounded-currency-denied",
            Self::BoundedOrderDenied => "bounded-order-denied",
            Self::BoundedAggregateBudgetExceeded => "bounded-aggregate-budget-exceeded",
            Self::BoundedArithmeticOverflow => "bounded-arithmetic-overflow",
        }
    }
}

/// Pure bounded final-capture decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentCaptureDecision {
    /// Three-way class.
    pub class: PaymentCaptureDecisionClass,
    /// Stable code.
    pub code: PaymentCaptureDecisionCode,
    /// Stable evaluation stage.
    pub stage: PaymentCaptureDecisionStage,
    /// Literal non-secret explanation.
    pub detail: String,
    /// Successful calculations.
    pub eligibility: Option<PaymentCaptureEligibility>,
}

impl PaymentCaptureDecision {
    fn denied(
        code: PaymentCaptureDecisionCode,
        stage: PaymentCaptureDecisionStage,
        detail: &'static str,
    ) -> Self {
        Self {
            class: PaymentCaptureDecisionClass::Denied,
            code,
            stage,
            detail: detail.into(),
            eligibility: None,
        }
    }
}

/// Explicit inputs to the pure final-capture evaluator.
pub struct PaymentCaptureEvaluationContext<'a> {
    /// Durable capture workflow identity.
    pub workflow_id: &'a str,
    /// Immutable configured policy.
    pub policy: &'a StripeBoundedMerchantPaymentPolicyV1,
    /// Agent-selected exact capture.
    pub action: &'a StripeExactPaymentCaptureV1,
    /// Fresh protected Stripe and durable-authorization evidence.
    pub evidence: &'a PaymentCaptureEvidenceV1,
    /// Aggregate settlement state before reservation.
    pub aggregate_snapshot: &'a MerchantAggregateSnapshot,
    /// Required runtime configuration.
    pub required_configuration: &'a StripeMerchantEvaluatorConfigurationV1,
    /// Configuration actually executing.
    pub executed_configuration: &'a StripeMerchantEvaluatorConfigurationV1,
    /// Request audience.
    pub request_audience: &'a str,
    /// Explicit trusted time.
    pub now: u64,
}

/// Evaluates one exact final capture and its atomic hold-release obligation.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "the closed fail-closed check ordering stays linear and auditable"
)]
pub fn evaluate_payment_capture(
    context: &PaymentCaptureEvaluationContext<'_>,
) -> PaymentCaptureDecision {
    if context.required_configuration != context.executed_configuration {
        return denied(
            PaymentCaptureDecisionCode::BoundedConfigurationMismatch,
            PaymentCaptureDecisionStage::Configuration,
            "required and executed final-capture configurations differ",
        );
    }
    if context.policy.validate().is_err()
        || context.required_configuration.validate().is_err()
        || context.action.validate().is_err()
    {
        return denied(
            PaymentCaptureDecisionCode::BoundedPolicyInvalid,
            PaymentCaptureDecisionStage::Policy,
            "policy, configuration, action, or evidence is not valid V1",
        );
    }
    if context.evidence.validate().is_err() {
        return denied(
            PaymentCaptureDecisionCode::BoundedEvidenceMismatch,
            PaymentCaptureDecisionStage::Evidence,
            "protected capture evidence is malformed or contradictory",
        );
    }
    let Ok(policy_digest) = context.policy.digest() else {
        return denied(
            PaymentCaptureDecisionCode::BoundedPolicyInvalid,
            PaymentCaptureDecisionStage::Policy,
            "policy identity could not be computed",
        );
    };
    let Ok(configuration_digest) = context.required_configuration.digest() else {
        return denied(
            PaymentCaptureDecisionCode::BoundedPolicyInvalid,
            PaymentCaptureDecisionStage::Configuration,
            "configuration identity could not be computed",
        );
    };
    if !digest_eq(
        context.required_configuration.policy_digest(),
        &policy_digest,
    ) || context.required_configuration.exact_action_profile() != PAYMENT_CAPTURE_PROFILE
        || !digest_eq(context.action.required_policy_digest(), &policy_digest)
        || !digest_eq(
            context.action.required_configuration_digest(),
            &configuration_digest,
        )
        || context.action.stripe_account_id() != context.required_configuration.stripe_account_id()
        || context.action.connect_account() != context.required_configuration.connect_account()
        || context.action.stripe_api_version()
            != context.required_configuration.stripe_api_version()
        || context.action.executor_audience() != context.required_configuration.executor_audience()
        || context.request_audience != context.required_configuration.executor_audience()
    {
        return denied(
            PaymentCaptureDecisionCode::BoundedActionMismatch,
            PaymentCaptureDecisionStage::ExactAction,
            "the exact action does not bind the configured policy and runtime",
        );
    }
    if context.now < context.policy.valid_from() || context.now > context.policy.expires_at() {
        return denied(
            PaymentCaptureDecisionCode::BoundedPolicyExpired,
            PaymentCaptureDecisionStage::Policy,
            "the immutable configured policy is not active",
        );
    }
    let Some(lifetime) = context.action.expires_at().checked_sub(context.now) else {
        return denied(
            PaymentCaptureDecisionCode::BoundedActionMismatch,
            PaymentCaptureDecisionStage::ExactAction,
            "the exact final-capture action is expired",
        );
    };
    if lifetime == 0
        || lifetime > context.policy.maximum_action_lifetime_seconds()
        || context.action.expires_at() > context.policy.expires_at()
    {
        return denied(
            PaymentCaptureDecisionCode::BoundedActionMismatch,
            PaymentCaptureDecisionStage::ExactAction,
            "the exact action lifetime exceeds configured containment",
        );
    }
    let Ok(expected_metadata) = fixed_merchant_metadata_commitment(
        context.workflow_id,
        PAYMENT_CAPTURE_PROFILE,
        context.action.order_scope(),
        &policy_digest,
    ) else {
        return denied(
            PaymentCaptureDecisionCode::BoundedActionMismatch,
            PaymentCaptureDecisionStage::ExactAction,
            "the protected fixed metadata commitment is invalid",
        );
    };
    if !digest_eq(
        context.action.statement_descriptor_commitment(),
        &merchant_statement_descriptor_commitment(),
    ) || !digest_eq(
        context.action.fixed_metadata_commitment(),
        &expected_metadata,
    ) {
        return denied(
            PaymentCaptureDecisionCode::BoundedActionMismatch,
            PaymentCaptureDecisionStage::ExactAction,
            "provider-visible descriptor or fixed metadata commitment differs",
        );
    }
    let Some(evidence_age) = context.now.checked_sub(context.evidence.observed_at()) else {
        return denied(
            PaymentCaptureDecisionCode::BoundedEvidenceStale,
            PaymentCaptureDecisionStage::Evidence,
            "provider evidence is from the future",
        );
    };
    if evidence_age > context.policy.maximum_evidence_age_seconds() {
        return denied(
            PaymentCaptureDecisionCode::BoundedEvidenceStale,
            PaymentCaptureDecisionStage::Evidence,
            "provider evidence is older than the configured freshness bound",
        );
    }
    if context.evidence.livemode() {
        return denied(
            PaymentCaptureDecisionCode::BoundedTestModeRequired,
            PaymentCaptureDecisionStage::Evidence,
            "final-capture V1 requires Stripe test mode",
        );
    }
    if context
        .now
        .checked_sub(context.evidence.authorization_created_at())
        .is_none_or(|age| age > context.policy.maximum_authorization_age_seconds())
    {
        return denied(
            PaymentCaptureDecisionCode::PaymentCaptureWindowExpired,
            PaymentCaptureDecisionStage::AuthorizationLink,
            "the linked authorization exceeded its configured maximum age",
        );
    }
    if context
        .evidence
        .capture_before()
        .saturating_sub(context.now)
        < context.policy.minimum_capture_window_seconds()
    {
        return denied(
            PaymentCaptureDecisionCode::PaymentCaptureWindowExpired,
            PaymentCaptureDecisionStage::Evidence,
            "the linked authorization has insufficient capture time remaining",
        );
    }
    if context.action.authorization_action_digest()
        != context.evidence.authorization_action_digest()
        || context.action.authorization_reservation_id()
            != context.evidence.authorization_reservation_id()
    {
        return denied(
            PaymentCaptureDecisionCode::PaymentAuthorizationLinkMismatch,
            PaymentCaptureDecisionStage::AuthorizationLink,
            "the action does not link to the protected durable authorization",
        );
    }
    if context.evidence.amount_captured_minor() != 0 {
        return denied(
            PaymentCaptureDecisionCode::PaymentCaptureAlreadyExecuted,
            PaymentCaptureDecisionStage::Evidence,
            "the authorization already has captured funds",
        );
    }
    if context.evidence.payment_intent_status() != "requires_capture"
        || context.evidence.amount_capturable_minor() == 0
    {
        return denied(
            PaymentCaptureDecisionCode::PaymentIntentNotCapturable,
            PaymentCaptureDecisionStage::Evidence,
            "the PaymentIntent is not in a capturable state",
        );
    }
    if context.action.stripe_account_id() != context.evidence.stripe_account_id()
        || context.action.connect_account() != context.evidence.connect_account()
        || context.action.payment_intent_id() != context.evidence.payment_intent_id()
        || context.action.latest_charge_id() != context.evidence.latest_charge_id()
        || context.action.customer_id() != context.evidence.customer_id()
        || context.action.order_scope() != context.evidence.order_scope()
        || context.action.authorized_amount_minor() != context.evidence.authorized_amount_minor()
        || context.action.amount_capturable_before_minor()
            != context.evidence.amount_capturable_minor()
        || context.action.currency() != context.evidence.currency()
        || context.action.stripe_api_version() != context.evidence.stripe_api_version()
    {
        return denied(
            PaymentCaptureDecisionCode::PaymentCaptureProviderMismatch,
            PaymentCaptureDecisionStage::Evidence,
            "the exact capture differs from protected Stripe or authorization facts",
        );
    }
    if context.action.amount_to_capture_minor() > context.evidence.amount_capturable_minor() {
        return denied(
            PaymentCaptureDecisionCode::PaymentCaptureAmountExceeded,
            PaymentCaptureDecisionStage::Evidence,
            "the exact capture exceeds the currently capturable amount",
        );
    }
    if context
        .policy
        .allowed_operations()
        .binary_search(&MerchantOperation::Capture)
        .is_err()
    {
        return denied(
            PaymentCaptureDecisionCode::PaymentCaptureAmountExceeded,
            PaymentCaptureDecisionStage::StripeScope,
            "final capture is not an allowed operation",
        );
    }
    if context
        .policy
        .allowed_test_account_ids()
        .binary_search(context.action.stripe_account_id())
        .is_err()
        || context
            .policy
            .allowed_connect_accounts()
            .binary_search(context.action.connect_account())
            .is_err()
    {
        return denied(
            PaymentCaptureDecisionCode::BoundedAccountDenied,
            PaymentCaptureDecisionStage::StripeScope,
            "the Stripe account or Connect context is outside configured scope",
        );
    }
    if context
        .policy
        .allowed_customer_ids()
        .binary_search(context.action.customer_id())
        .is_err()
    {
        return denied(
            PaymentCaptureDecisionCode::PaymentCustomerDenied,
            PaymentCaptureDecisionStage::StripeScope,
            "the linked Customer is outside configured scope",
        );
    }
    if context
        .policy
        .allowed_order_scopes()
        .binary_search_by(|value| value.as_str().cmp(context.action.order_scope()))
        .is_err()
    {
        return denied(
            PaymentCaptureDecisionCode::BoundedOrderDenied,
            PaymentCaptureDecisionStage::StripeScope,
            "the protected order scope is outside configured scope",
        );
    }
    if context
        .policy
        .allowed_currencies()
        .binary_search(context.action.currency())
        .is_err()
    {
        return denied(
            PaymentCaptureDecisionCode::BoundedCurrencyDenied,
            PaymentCaptureDecisionStage::StripeScope,
            "the exact currency is outside configured scope",
        );
    }
    if context
        .policy
        .allowed_api_versions()
        .binary_search_by(|value| value.as_str().cmp(context.action.stripe_api_version()))
        .is_err()
    {
        return denied(
            PaymentCaptureDecisionCode::BoundedApiVersionDenied,
            PaymentCaptureDecisionStage::StripeScope,
            "the pinned Stripe API version is outside configured scope",
        );
    }
    let Some(operation_ceiling_minor) = context
        .policy
        .operation_limit_minor(MerchantOperation::Capture, context.action.currency())
    else {
        return denied(
            PaymentCaptureDecisionCode::PaymentCaptureAmountExceeded,
            PaymentCaptureDecisionStage::Limits,
            "no capture ceiling applies to the exact currency",
        );
    };
    let Some(customer_ceiling_minor) = context
        .policy
        .customer_limit_minor(context.action.currency())
    else {
        return denied(
            PaymentCaptureDecisionCode::PaymentCaptureAmountExceeded,
            PaymentCaptureDecisionStage::Limits,
            "no customer ceiling applies to the exact currency",
        );
    };
    let Some(order_ceiling_minor) = context.policy.order_limit_minor(context.action.currency())
    else {
        return denied(
            PaymentCaptureDecisionCode::PaymentCaptureAmountExceeded,
            PaymentCaptureDecisionStage::Limits,
            "no order ceiling applies to the exact currency",
        );
    };
    let effective_ceiling_minor = operation_ceiling_minor
        .min(customer_ceiling_minor)
        .min(order_ceiling_minor);
    if context.action.amount_to_capture_minor() > effective_ceiling_minor {
        return denied(
            PaymentCaptureDecisionCode::PaymentCaptureAmountExceeded,
            PaymentCaptureDecisionStage::Limits,
            "the exact capture exceeds an operation, customer, or order ceiling",
        );
    }
    let mut settlement_reservations = Vec::new();
    for budget in context.policy.aggregate_budgets().iter().filter(|budget| {
        budget.operation() == MerchantOperation::Capture
            && budget.currency() == context.action.currency()
    }) {
        let Ok(window) = budget.window().identity(context.now) else {
            return denied(
                PaymentCaptureDecisionCode::BoundedPolicyExpired,
                PaymentCaptureDecisionStage::AggregateBudget,
                "an applicable aggregate settlement window is inactive",
            );
        };
        let usage = context.aggregate_snapshot.usages.iter().find(|usage| {
            usage.budget_id == budget.budget_id()
                && usage.operation == MerchantOperation::Capture
                && usage.currency == *context.action.currency()
                && usage.window == window
        });
        let (committed, reserved, unknown, active) = usage.map_or((0, 0, 0, 0), |usage| {
            (
                usage.committed_minor,
                usage.reserved_minor,
                usage.outcome_unknown_minor,
                usage.active_authorization_minor,
            )
        });
        let Some(used) = committed
            .checked_add(reserved)
            .and_then(|value| value.checked_add(unknown))
            .and_then(|value| value.checked_add(active))
        else {
            return denied(
                PaymentCaptureDecisionCode::BoundedArithmeticOverflow,
                PaymentCaptureDecisionStage::AggregateBudget,
                "aggregate settlement usage addition overflowed",
            );
        };
        let Some(available) = budget.limit_minor().checked_sub(used) else {
            return denied(
                PaymentCaptureDecisionCode::BoundedArithmeticOverflow,
                PaymentCaptureDecisionStage::AggregateBudget,
                "aggregate settlement usage exceeds its configured limit",
            );
        };
        if context.action.amount_to_capture_minor() > available {
            return denied(
                PaymentCaptureDecisionCode::BoundedAggregateBudgetExceeded,
                PaymentCaptureDecisionStage::AggregateBudget,
                "the exact capture exceeds currently available settlement capacity",
            );
        }
        settlement_reservations.push(MerchantReservationIntent {
            budget_id: budget.budget_id().into(),
            operation: MerchantOperation::Capture,
            currency: context.action.currency().clone(),
            window,
            limit_minor: budget.limit_minor(),
            amount_minor: context.action.amount_to_capture_minor(),
            available_before_minor: available,
        });
    }
    if settlement_reservations.is_empty() {
        return denied(
            PaymentCaptureDecisionCode::BoundedAggregateBudgetExceeded,
            PaymentCaptureDecisionStage::AggregateBudget,
            "no aggregate settlement budget applies to final capture",
        );
    }
    PaymentCaptureDecision {
        class: PaymentCaptureDecisionClass::Eligible,
        code: PaymentCaptureDecisionCode::PaymentCaptureAuthorized,
        stage: PaymentCaptureDecisionStage::Complete,
        detail: "the exact final capture and hold release are inside the immutable policy".into(),
        eligibility: Some(PaymentCaptureEligibility {
            operation_ceiling_minor,
            customer_ceiling_minor,
            order_ceiling_minor,
            effective_ceiling_minor,
            settlement_reservations,
            authorization_release_minor: context.action.amount_capturable_before_minor(),
        }),
    }
}

fn denied(
    code: PaymentCaptureDecisionCode,
    stage: PaymentCaptureDecisionStage,
    detail: &'static str,
) -> PaymentCaptureDecision {
    PaymentCaptureDecision::denied(code, stage, detail)
}

fn digest_eq(left: &DigestHex, right: &DigestHex) -> bool {
    bool::from(left.as_str().as_bytes().ct_eq(right.as_str().as_bytes()))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{
        canonical::sha256,
        test_support::{
            NOW, merchant_capture_action, merchant_capture_configuration,
            merchant_capture_evidence, merchant_policy,
        },
    };

    fn decision(amount_minor: u64, operation_limit: u64) -> PaymentCaptureDecision {
        let policy = merchant_policy(MerchantOperation::Capture, operation_limit, 2_000);
        let configuration = merchant_capture_configuration(&policy);
        let action = merchant_capture_action(
            "merchant-capture-evaluator-0001",
            &policy,
            &configuration,
            amount_minor,
        );
        evaluate_payment_capture(&PaymentCaptureEvaluationContext {
            workflow_id: "merchant-capture-evaluator-0001",
            policy: &policy,
            action: &action,
            evidence: &merchant_capture_evidence(),
            aggregate_snapshot: &MerchantAggregateSnapshot::default(),
            required_configuration: &configuration,
            executed_configuration: &configuration,
            request_audience: configuration.executor_audience(),
            now: NOW,
        })
    }

    #[test]
    fn partial_final_capture_reserves_settlement_and_releases_the_full_hold() {
        let decision = decision(500, 1_000);
        assert_eq!(decision.class, PaymentCaptureDecisionClass::Eligible);
        assert_eq!(
            decision.code,
            PaymentCaptureDecisionCode::PaymentCaptureAuthorized
        );
        let eligibility = decision.eligibility.unwrap();
        assert_eq!(eligibility.settlement_reservations[0].amount_minor, 500);
        assert_eq!(eligibility.authorization_release_minor, 1_000);
    }

    #[test]
    fn exact_capture_boundary_and_one_past_are_distinct() {
        assert_eq!(
            decision(1_000, 1_000).class,
            PaymentCaptureDecisionClass::Eligible
        );
        assert_eq!(
            decision(1_000, 999).code,
            PaymentCaptureDecisionCode::PaymentCaptureAmountExceeded
        );
    }

    #[test]
    fn changed_authorization_link_is_denied() {
        let policy = merchant_policy(MerchantOperation::Capture, 1_000, 2_000);
        let configuration = merchant_capture_configuration(&policy);
        let action = merchant_capture_action(
            "merchant-capture-evaluator-0002",
            &policy,
            &configuration,
            500,
        );
        let mut evidence_value = serde_json::to_value(merchant_capture_evidence()).unwrap();
        evidence_value["authorization_action_digest"] =
            serde_json::json!(sha256(b"another-authorization").to_string());
        let evidence: PaymentCaptureEvidenceV1 = serde_json::from_value(evidence_value).unwrap();
        let decision = evaluate_payment_capture(&PaymentCaptureEvaluationContext {
            workflow_id: "merchant-capture-evaluator-0002",
            policy: &policy,
            action: &action,
            evidence: &evidence,
            aggregate_snapshot: &MerchantAggregateSnapshot::default(),
            required_configuration: &configuration,
            executed_configuration: &configuration,
            request_audience: configuration.executor_audience(),
            now: NOW,
        });
        assert_eq!(
            decision.code,
            PaymentCaptureDecisionCode::PaymentAuthorizationLinkMismatch
        );
    }

    #[test]
    fn prior_capture_is_a_stable_denial() {
        let policy = merchant_policy(MerchantOperation::Capture, 1_000, 2_000);
        let configuration = merchant_capture_configuration(&policy);
        let action = merchant_capture_action(
            "merchant-capture-evaluator-0003",
            &policy,
            &configuration,
            500,
        );
        let mut evidence_value = serde_json::to_value(merchant_capture_evidence()).unwrap();
        evidence_value["amount_capturable_minor"] = serde_json::json!(500);
        evidence_value["amount_captured_minor"] = serde_json::json!(500);
        evidence_value["payment_intent_status"] = serde_json::json!("succeeded");
        let evidence: PaymentCaptureEvidenceV1 = serde_json::from_value(evidence_value).unwrap();
        let decision = evaluate_payment_capture(&PaymentCaptureEvaluationContext {
            workflow_id: "merchant-capture-evaluator-0003",
            policy: &policy,
            action: &action,
            evidence: &evidence,
            aggregate_snapshot: &MerchantAggregateSnapshot::default(),
            required_configuration: &configuration,
            executed_configuration: &configuration,
            request_audience: configuration.executor_audience(),
            now: NOW,
        });
        assert_eq!(
            decision.code,
            PaymentCaptureDecisionCode::PaymentCaptureAlreadyExecuted
        );
    }

    #[test]
    fn changed_provider_scope_dimensions_never_open_the_capture() {
        let policy = merchant_policy(MerchantOperation::Capture, 1_000, 2_000);
        let configuration = merchant_capture_configuration(&policy);
        let action = merchant_capture_action(
            "merchant-capture-evaluator-0004",
            &policy,
            &configuration,
            500,
        );
        let base = serde_json::to_value(merchant_capture_evidence()).unwrap();
        let mutations = [
            (
                "payment_intent_id",
                serde_json::json!("pi_changed000000000001"),
            ),
            (
                "latest_charge_id",
                serde_json::json!("ch_changed000000000001"),
            ),
            ("customer_id", serde_json::json!("cus_changed000000000001")),
            ("currency", serde_json::json!("eur")),
        ];
        for (field, value) in mutations {
            let mut changed = base.clone();
            changed[field] = value;
            let evidence: PaymentCaptureEvidenceV1 = serde_json::from_value(changed).unwrap();
            let decision = evaluate_payment_capture(&PaymentCaptureEvaluationContext {
                workflow_id: "merchant-capture-evaluator-0004",
                policy: &policy,
                action: &action,
                evidence: &evidence,
                aggregate_snapshot: &MerchantAggregateSnapshot::default(),
                required_configuration: &configuration,
                executed_configuration: &configuration,
                request_audience: configuration.executor_audience(),
                now: NOW,
            });
            assert_ne!(decision.class, PaymentCaptureDecisionClass::Eligible);
        }
    }

    proptest! {
        #[test]
        fn every_positive_amount_at_or_below_the_capture_ceiling_is_eligible(
            ceiling in 1_u64..=999,
        ) {
            let policy = merchant_policy(MerchantOperation::Capture, ceiling, 2_000);
            let configuration = merchant_capture_configuration(&policy);
            let action = merchant_capture_action(
                "merchant-capture-property-inside",
                &policy,
                &configuration,
                ceiling,
            );
            let decision = evaluate_payment_capture(&PaymentCaptureEvaluationContext {
                workflow_id: "merchant-capture-property-inside",
                policy: &policy,
                action: &action,
                evidence: &merchant_capture_evidence(),
                aggregate_snapshot: &MerchantAggregateSnapshot::default(),
                required_configuration: &configuration,
                executed_configuration: &configuration,
                request_audience: configuration.executor_audience(),
                now: NOW,
            });
            prop_assert_eq!(decision.class, PaymentCaptureDecisionClass::Eligible);
            let eligibility = decision.eligibility.expect("eligible calculation");
            prop_assert_eq!(eligibility.authorization_release_minor, 1_000);
            prop_assert!(eligibility.settlement_reservations.iter().all(
                |reservation| reservation.amount_minor == ceiling
            ));
        }

        #[test]
        fn one_minor_unit_past_a_capture_ceiling_is_denied(
            ceiling in 1_u64..=999,
        ) {
            let policy = merchant_policy(MerchantOperation::Capture, ceiling, 2_000);
            let configuration = merchant_capture_configuration(&policy);
            let action = merchant_capture_action(
                "merchant-capture-property-outside",
                &policy,
                &configuration,
                ceiling + 1,
            );
            let decision = evaluate_payment_capture(&PaymentCaptureEvaluationContext {
                workflow_id: "merchant-capture-property-outside",
                policy: &policy,
                action: &action,
                evidence: &merchant_capture_evidence(),
                aggregate_snapshot: &MerchantAggregateSnapshot::default(),
                required_configuration: &configuration,
                executed_configuration: &configuration,
                request_audience: configuration.executor_audience(),
                now: NOW,
            });
            prop_assert_eq!(
                decision.code,
                PaymentCaptureDecisionCode::PaymentCaptureAmountExceeded
            );
        }
    }
}
