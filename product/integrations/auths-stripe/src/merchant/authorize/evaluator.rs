//! Pure bounded evaluator for one exact manual-capture authorization hold.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use super::super::{
    MerchantAggregateSnapshot, MerchantOperation, MerchantPaymentEvidenceV1,
    MerchantReservationIntent, PAYMENT_AUTHORIZE_PROFILE, PriorMerchantPaymentState,
    StripeBoundedMerchantPaymentPolicyV1, StripeMerchantEvaluatorConfigurationV1,
    fixed_merchant_metadata_commitment, merchant_statement_descriptor_commitment,
};
use super::action::StripeExactPaymentAuthorizeV1;
use crate::types::DigestHex;

/// Successful bounded calculation projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentAuthorizeEligibility {
    /// Per-operation ceiling.
    pub operation_ceiling_minor: u64,
    /// Per-customer ceiling.
    pub customer_ceiling_minor: u64,
    /// Per-order ceiling.
    pub order_ceiling_minor: u64,
    /// Effective inclusive ceiling.
    pub effective_ceiling_minor: u64,
    /// Exact aggregate reservation intents.
    pub reservations: Vec<MerchantReservationIntent>,
}

/// Stable bounded merchant-payment class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentAuthorizeDecisionClass {
    /// Complete inputs establish eligibility.
    Eligible,
    /// Complete inputs establish denial.
    Denied,
    /// Trusted state is unavailable or contradictory.
    Indeterminate,
}

/// Stable bounded merchant-payment stage.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentAuthorizeDecisionStage {
    /// Required/executed configuration.
    Configuration,
    /// Policy identity or validity.
    Policy,
    /// Exact action validation.
    ExactAction,
    /// Protected evidence.
    Evidence,
    /// Account, Connect, Customer, `PaymentMethod`, order, or API scope.
    StripeScope,
    /// Per-action, customer, or order ceilings.
    Limits,
    /// Aggregate budget calculation.
    AggregateBudget,
    /// All pure checks succeeded.
    Complete,
}

/// Stable merchant-payment decision code.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentAuthorizeDecisionCode {
    /// Exact authorization hold is eligible.
    PaymentAuthorizationAuthorized,
    /// Per-action ceiling exceeded.
    PaymentAuthorizationLimitExceeded,
    /// Customer outside configured scope.
    PaymentCustomerDenied,
    /// `PaymentMethod` outside configured scope.
    PaymentMethodDenied,
    /// `PaymentMethod` cannot be separately authorized and captured.
    PaymentMethodCaptureUnsupported,
    /// The action does not leave the configured minimum capture window.
    PaymentAuthorizationWindowTooShort,
    /// Order already has successful or ambiguous authorization state.
    PaymentAuthorizationAlreadyExists,
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
    /// API version denied.
    BoundedApiVersionDenied,
    /// Currency denied.
    BoundedCurrencyDenied,
    /// Order denied.
    BoundedOrderDenied,
    /// Aggregate budget has insufficient capacity.
    BoundedAggregateBudgetExceeded,
    /// Checked integer arithmetic failed.
    BoundedArithmeticOverflow,
}

impl PaymentAuthorizeDecisionCode {
    /// Stable literal code used in receipts and APIs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PaymentAuthorizationAuthorized => "payment-authorization-authorized",
            Self::PaymentAuthorizationLimitExceeded => "payment-authorization-limit-exceeded",
            Self::PaymentCustomerDenied => "payment-customer-denied",
            Self::PaymentMethodDenied => "payment-method-denied",
            Self::PaymentMethodCaptureUnsupported => "payment-method-capture-unsupported",
            Self::PaymentAuthorizationWindowTooShort => "payment-authorization-window-too-short",
            Self::PaymentAuthorizationAlreadyExists => "payment-authorization-already-exists",
            Self::BoundedConfigurationMismatch => "bounded-configuration-mismatch",
            Self::BoundedPolicyInvalid => "bounded-policy-invalid",
            Self::BoundedPolicyExpired => "bounded-policy-expired",
            Self::BoundedActionMismatch => "bounded-action-mismatch",
            Self::BoundedEvidenceMismatch => "bounded-evidence-mismatch",
            Self::BoundedEvidenceStale => "bounded-evidence-stale",
            Self::BoundedTestModeRequired => "bounded-test-mode-required",
            Self::BoundedAccountDenied => "bounded-account-denied",
            Self::BoundedApiVersionDenied => "bounded-api-version-denied",
            Self::BoundedCurrencyDenied => "bounded-currency-denied",
            Self::BoundedOrderDenied => "bounded-order-denied",
            Self::BoundedAggregateBudgetExceeded => "bounded-aggregate-budget-exceeded",
            Self::BoundedArithmeticOverflow => "bounded-arithmetic-overflow",
        }
    }
}

/// Pure bounded merchant-payment decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentAuthorizeDecision {
    /// Three-way class.
    pub class: PaymentAuthorizeDecisionClass,
    /// Stable code.
    pub code: PaymentAuthorizeDecisionCode,
    /// Stable evaluation stage.
    pub stage: PaymentAuthorizeDecisionStage,
    /// Literal non-secret explanation.
    pub detail: String,
    /// Successful calculations.
    pub eligibility: Option<PaymentAuthorizeEligibility>,
}

impl PaymentAuthorizeDecision {
    fn denied(
        code: PaymentAuthorizeDecisionCode,
        stage: PaymentAuthorizeDecisionStage,
        detail: &'static str,
    ) -> Self {
        Self {
            class: PaymentAuthorizeDecisionClass::Denied,
            code,
            stage,
            detail: detail.into(),
            eligibility: None,
        }
    }
}

/// Explicit inputs to the pure authorization evaluator.
pub struct PaymentAuthorizeEvaluationContext<'a> {
    /// Durable workflow identity.
    pub workflow_id: &'a str,
    /// Immutable configured policy.
    pub policy: &'a StripeBoundedMerchantPaymentPolicyV1,
    /// Agent-selected exact payment.
    pub action: &'a StripeExactPaymentAuthorizeV1,
    /// Fresh protected provider/order evidence.
    pub evidence: &'a MerchantPaymentEvidenceV1,
    /// Aggregate state before reservation.
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

/// Evaluates one exact manual-capture authorization hold inside configured bounds.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "the closed fail-closed check ordering stays linear and auditable"
)]
pub fn evaluate_payment_authorize(
    context: &PaymentAuthorizeEvaluationContext<'_>,
) -> PaymentAuthorizeDecision {
    if context.required_configuration != context.executed_configuration {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::BoundedConfigurationMismatch,
            PaymentAuthorizeDecisionStage::Configuration,
            "required and executed merchant-payment configurations differ",
        );
    }
    if context.policy.validate().is_err()
        || context.required_configuration.validate().is_err()
        || context.action.validate().is_err()
    {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::BoundedPolicyInvalid,
            PaymentAuthorizeDecisionStage::Policy,
            "policy, configuration, or exact action is not valid V1",
        );
    }
    let Ok(policy_digest) = context.policy.digest() else {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::BoundedPolicyInvalid,
            PaymentAuthorizeDecisionStage::Policy,
            "policy identity could not be computed",
        );
    };
    let Ok(configuration_digest) = context.required_configuration.digest() else {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::BoundedPolicyInvalid,
            PaymentAuthorizeDecisionStage::Configuration,
            "configuration identity could not be computed",
        );
    };
    if !digest_eq(
        context.required_configuration.policy_digest(),
        &policy_digest,
    ) || context.required_configuration.exact_action_profile() != PAYMENT_AUTHORIZE_PROFILE
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
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::BoundedActionMismatch,
            PaymentAuthorizeDecisionStage::ExactAction,
            "the exact action does not bind the configured policy and runtime",
        );
    }
    if context.now < context.policy.valid_from() || context.now > context.policy.expires_at() {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::BoundedPolicyExpired,
            PaymentAuthorizeDecisionStage::Policy,
            "the immutable configured policy is not active",
        );
    }
    let Some(lifetime) = context.action.expires_at().checked_sub(context.now) else {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::BoundedPolicyExpired,
            PaymentAuthorizeDecisionStage::ExactAction,
            "the exact action is expired",
        );
    };
    if lifetime == 0
        || lifetime > context.policy.maximum_action_lifetime_seconds()
        || lifetime > context.policy.maximum_authorization_age_seconds()
        || context.action.expires_at() > context.policy.expires_at()
    {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::BoundedActionMismatch,
            PaymentAuthorizeDecisionStage::ExactAction,
            "the exact action lifetime exceeds configured containment",
        );
    }
    if lifetime < context.policy.minimum_capture_window_seconds() {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::PaymentAuthorizationWindowTooShort,
            PaymentAuthorizeDecisionStage::ExactAction,
            "the exact action leaves less than the configured minimum capture window",
        );
    }
    let Ok(expected_metadata) = fixed_merchant_metadata_commitment(
        context.workflow_id,
        PAYMENT_AUTHORIZE_PROFILE,
        context.action.order_scope(),
        &policy_digest,
    ) else {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::BoundedActionMismatch,
            PaymentAuthorizeDecisionStage::ExactAction,
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
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::BoundedActionMismatch,
            PaymentAuthorizeDecisionStage::ExactAction,
            "provider-visible descriptor or fixed metadata commitment differs",
        );
    }
    if context.evidence.livemode() {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::BoundedTestModeRequired,
            PaymentAuthorizeDecisionStage::Evidence,
            "merchant-payment V1 requires Stripe test mode",
        );
    }
    let Some(evidence_age) = context.now.checked_sub(context.evidence.observed_at()) else {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::BoundedEvidenceStale,
            PaymentAuthorizeDecisionStage::Evidence,
            "provider evidence is from the future",
        );
    };
    if evidence_age > context.policy.maximum_evidence_age_seconds() {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::BoundedEvidenceStale,
            PaymentAuthorizeDecisionStage::Evidence,
            "provider evidence is older than the configured freshness bound",
        );
    }
    if context.action.stripe_account_id() != context.evidence.stripe_account_id()
        || context.action.connect_account() != context.evidence.connect_account()
        || context.action.customer_id() != context.evidence.customer_id()
        || context.action.payment_method_id() != context.evidence.payment_method_id()
        || context.action.payment_method_type() != context.evidence.payment_method_type()
        || context.action.order_scope() != context.evidence.order_scope()
        || context.action.stripe_api_version() != context.evidence.stripe_api_version()
    {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::BoundedEvidenceMismatch,
            PaymentAuthorizeDecisionStage::Evidence,
            "fresh Customer, PaymentMethod, order, account, or API evidence differs",
        );
    }
    if context
        .policy
        .allowed_operations()
        .binary_search(&MerchantOperation::Authorize)
        .is_err()
    {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::PaymentAuthorizationLimitExceeded,
            PaymentAuthorizeDecisionStage::StripeScope,
            "manual-capture authorization is not an allowed operation",
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
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::BoundedAccountDenied,
            PaymentAuthorizeDecisionStage::StripeScope,
            "Stripe account or Connect context is outside configured scope",
        );
    }
    if context
        .policy
        .allowed_customer_ids()
        .binary_search(context.action.customer_id())
        .is_err()
    {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::PaymentCustomerDenied,
            PaymentAuthorizeDecisionStage::StripeScope,
            "the exact Customer is outside configured scope",
        );
    }
    if context
        .policy
        .allowed_payment_method_ids()
        .binary_search(context.action.payment_method_id())
        .is_err()
        || context
            .policy
            .allowed_payment_method_types()
            .binary_search_by(|value| value.as_str().cmp(context.action.payment_method_type()))
            .is_err()
    {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::PaymentMethodDenied,
            PaymentAuthorizeDecisionStage::StripeScope,
            "the exact PaymentMethod or type is outside configured scope",
        );
    }
    if !context.evidence.supports_manual_capture() {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::PaymentMethodCaptureUnsupported,
            PaymentAuthorizeDecisionStage::Evidence,
            "fresh PaymentMethod evidence does not support separate authorization and capture",
        );
    }
    if context
        .policy
        .allowed_order_scopes()
        .binary_search_by(|value| value.as_str().cmp(context.action.order_scope()))
        .is_err()
    {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::BoundedOrderDenied,
            PaymentAuthorizeDecisionStage::StripeScope,
            "the protected order scope is outside configured scope",
        );
    }
    if context
        .policy
        .allowed_currencies()
        .binary_search(context.action.currency())
        .is_err()
    {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::BoundedCurrencyDenied,
            PaymentAuthorizeDecisionStage::StripeScope,
            "the exact currency is outside configured scope",
        );
    }
    if context
        .policy
        .allowed_api_versions()
        .binary_search_by(|value| value.as_str().cmp(context.action.stripe_api_version()))
        .is_err()
    {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::BoundedApiVersionDenied,
            PaymentAuthorizeDecisionStage::StripeScope,
            "the pinned Stripe API version is outside configured scope",
        );
    }
    if context.evidence.prior_payments().iter().any(|prior| {
        prior.order_scope() == context.action.order_scope()
            && matches!(
                prior.state(),
                PriorMerchantPaymentState::Succeeded
                    | PriorMerchantPaymentState::RequiresCapture
                    | PriorMerchantPaymentState::Processing
                    | PriorMerchantPaymentState::OutcomeUnknown
            )
    }) {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::PaymentAuthorizationAlreadyExists,
            PaymentAuthorizeDecisionStage::Evidence,
            "the order already has successful, active, processing, or ambiguous payment state",
        );
    }
    let Some(operation_ceiling_minor) = context
        .policy
        .operation_limit_minor(MerchantOperation::Authorize, context.action.currency())
    else {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::PaymentAuthorizationLimitExceeded,
            PaymentAuthorizeDecisionStage::Limits,
            "no operation ceiling applies to the exact currency",
        );
    };
    let Some(customer_ceiling_minor) = context
        .policy
        .customer_limit_minor(context.action.currency())
    else {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::PaymentAuthorizationLimitExceeded,
            PaymentAuthorizeDecisionStage::Limits,
            "no customer ceiling applies to the exact currency",
        );
    };
    let Some(order_ceiling_minor) = context.policy.order_limit_minor(context.action.currency())
    else {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::PaymentAuthorizationLimitExceeded,
            PaymentAuthorizeDecisionStage::Limits,
            "no order ceiling applies to the exact currency",
        );
    };
    let effective_ceiling_minor = operation_ceiling_minor
        .min(customer_ceiling_minor)
        .min(order_ceiling_minor);
    if context.action.authorized_amount_minor() > effective_ceiling_minor {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::PaymentAuthorizationLimitExceeded,
            PaymentAuthorizeDecisionStage::Limits,
            "the exact authorization exceeds an operation, customer, or order ceiling",
        );
    }
    let mut reservations = Vec::new();
    for budget in context.policy.aggregate_budgets().iter().filter(|budget| {
        budget.operation() == MerchantOperation::Authorize
            && budget.currency() == context.action.currency()
    }) {
        let Ok(window) = budget.window().identity(context.now) else {
            return PaymentAuthorizeDecision::denied(
                PaymentAuthorizeDecisionCode::BoundedPolicyExpired,
                PaymentAuthorizeDecisionStage::AggregateBudget,
                "an applicable aggregate window is inactive",
            );
        };
        let usage = context.aggregate_snapshot.usages.iter().find(|usage| {
            usage.budget_id == budget.budget_id()
                && usage.operation == MerchantOperation::Authorize
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
            return PaymentAuthorizeDecision::denied(
                PaymentAuthorizeDecisionCode::BoundedArithmeticOverflow,
                PaymentAuthorizeDecisionStage::AggregateBudget,
                "aggregate usage addition overflowed",
            );
        };
        let Some(available) = budget.limit_minor().checked_sub(used) else {
            return PaymentAuthorizeDecision::denied(
                PaymentAuthorizeDecisionCode::BoundedArithmeticOverflow,
                PaymentAuthorizeDecisionStage::AggregateBudget,
                "aggregate usage exceeds its configured limit",
            );
        };
        if context.action.authorized_amount_minor() > available {
            return PaymentAuthorizeDecision::denied(
                PaymentAuthorizeDecisionCode::BoundedAggregateBudgetExceeded,
                PaymentAuthorizeDecisionStage::AggregateBudget,
                "the exact authorization exceeds currently available aggregate capacity",
            );
        }
        reservations.push(MerchantReservationIntent {
            budget_id: budget.budget_id().into(),
            operation: MerchantOperation::Authorize,
            currency: context.action.currency().clone(),
            window,
            limit_minor: budget.limit_minor(),
            amount_minor: context.action.authorized_amount_minor(),
            available_before_minor: available,
        });
    }
    if reservations.is_empty() {
        return PaymentAuthorizeDecision::denied(
            PaymentAuthorizeDecisionCode::BoundedAggregateBudgetExceeded,
            PaymentAuthorizeDecisionStage::AggregateBudget,
            "no aggregate hold budget applies to manual-capture authorization",
        );
    }
    PaymentAuthorizeDecision {
        class: PaymentAuthorizeDecisionClass::Eligible,
        code: PaymentAuthorizeDecisionCode::PaymentAuthorizationAuthorized,
        stage: PaymentAuthorizeDecisionStage::Complete,
        detail:
            "the exact manual-capture authorization hold is inside the immutable configured policy"
                .into(),
        eligibility: Some(PaymentAuthorizeEligibility {
            operation_ceiling_minor,
            customer_ceiling_minor,
            order_ceiling_minor,
            effective_ceiling_minor,
            reservations,
        }),
    }
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
        merchant::MerchantAggregateUsage,
        test_support::{
            NOW, merchant_authorize_action, merchant_authorize_configuration, merchant_evidence,
            merchant_policy,
        },
    };

    fn decision(amount_minor: u64) -> PaymentAuthorizeDecision {
        let policy = merchant_policy(MerchantOperation::Authorize, 1_000, 2_000);
        let configuration = merchant_authorize_configuration(&policy);
        let action = merchant_authorize_action(
            "merchant-workflow-0001",
            &policy,
            &configuration,
            amount_minor,
        );
        evaluate_payment_authorize(&PaymentAuthorizeEvaluationContext {
            workflow_id: "merchant-workflow-0001",
            policy: &policy,
            action: &action,
            evidence: &merchant_evidence(),
            aggregate_snapshot: &MerchantAggregateSnapshot::default(),
            required_configuration: &configuration,
            executed_configuration: &configuration,
            request_audience: configuration.executor_audience(),
            now: NOW,
        })
    }

    #[test]
    fn inclusive_authorization_boundary_and_one_past_are_distinct() {
        assert_eq!(
            decision(1_000).class,
            PaymentAuthorizeDecisionClass::Eligible
        );
        let denied = decision(1_001);
        assert_eq!(denied.class, PaymentAuthorizeDecisionClass::Denied);
        assert_eq!(
            denied.code,
            PaymentAuthorizeDecisionCode::PaymentAuthorizationLimitExceeded
        );
    }

    #[test]
    fn configuration_mismatch_denies_before_any_capacity_intent() {
        let policy = merchant_policy(MerchantOperation::Authorize, 1_000, 2_000);
        let required = merchant_authorize_configuration(&policy);
        let other_policy = merchant_policy(MerchantOperation::Authorize, 1_000, 1_999);
        let executed = merchant_authorize_configuration(&other_policy);
        let action = merchant_authorize_action("merchant-workflow-0002", &policy, &required, 1_000);
        let decision = evaluate_payment_authorize(&PaymentAuthorizeEvaluationContext {
            workflow_id: "merchant-workflow-0002",
            policy: &policy,
            action: &action,
            evidence: &merchant_evidence(),
            aggregate_snapshot: &MerchantAggregateSnapshot::default(),
            required_configuration: &required,
            executed_configuration: &executed,
            request_audience: required.executor_audience(),
            now: NOW,
        });
        assert_eq!(
            decision.code,
            PaymentAuthorizeDecisionCode::BoundedConfigurationMismatch
        );
        assert!(decision.eligibility.is_none());
    }

    #[test]
    fn aggregate_arithmetic_is_checked() {
        let policy = merchant_policy(MerchantOperation::Authorize, 1_000, 2_000);
        let configuration = merchant_authorize_configuration(&policy);
        let action =
            merchant_authorize_action("merchant-workflow-0003", &policy, &configuration, 1_000);
        let budget = &policy.aggregate_budgets()[0];
        let snapshot = MerchantAggregateSnapshot {
            usages: vec![MerchantAggregateUsage {
                budget_id: budget.budget_id().into(),
                operation: MerchantOperation::Authorize,
                currency: action.currency().clone(),
                window: budget.window().identity(NOW).unwrap(),
                committed_minor: u64::MAX,
                reserved_minor: 1,
                outcome_unknown_minor: 0,
                active_authorization_minor: 0,
            }],
        };
        let decision = evaluate_payment_authorize(&PaymentAuthorizeEvaluationContext {
            workflow_id: "merchant-workflow-0003",
            policy: &policy,
            action: &action,
            evidence: &merchant_evidence(),
            aggregate_snapshot: &snapshot,
            required_configuration: &configuration,
            executed_configuration: &configuration,
            request_audience: configuration.executor_audience(),
            now: NOW,
        });
        assert_eq!(
            decision.code,
            PaymentAuthorizeDecisionCode::BoundedArithmeticOverflow
        );
    }

    #[test]
    fn tightening_every_shared_policy_dimension_never_opens_fixed_action() {
        let policy = merchant_policy(MerchantOperation::Authorize, 1_000, 2_000);
        let configuration = merchant_authorize_configuration(&policy);
        let action =
            merchant_authorize_action("merchant-workflow-0004", &policy, &configuration, 1_001);
        let evidence = merchant_evidence();
        let base = serde_json::to_value(&policy).unwrap();
        let mut tightened = Vec::new();
        for (pointer, value) in [
            ("/allowed_operations", serde_json::json!([])),
            (
                "/allowed_test_account_ids/0",
                serde_json::json!("acct_tighter_scope01"),
            ),
            (
                "/allowed_connect_accounts/0",
                serde_json::json!({"kind":"connected","account_id":"acct_tighter_scope02"}),
            ),
            (
                "/allowed_customer_ids/0",
                serde_json::json!("cus_tighter_scope0001"),
            ),
            (
                "/allowed_payment_method_ids/0",
                serde_json::json!("pm_tighter_scope00001"),
            ),
            ("/allowed_payment_method_types", serde_json::json!([])),
            ("/allowed_currencies/0", serde_json::json!("eur")),
            (
                "/allowed_order_scopes/0",
                serde_json::json!("order-tighter"),
            ),
            (
                "/per_operation_absolute_minor_by_currency/authorize/usd",
                serde_json::json!(999),
            ),
            (
                "/per_customer_minor_by_currency/usd",
                serde_json::json!(999),
            ),
            ("/per_order_minor_by_currency/usd", serde_json::json!(999)),
            ("/aggregate_budgets/0/limit_minor", serde_json::json!(999)),
            ("/maximum_evidence_age_seconds", serde_json::json!(4)),
            ("/maximum_action_lifetime_seconds", serde_json::json!(100)),
            (
                "/allowed_api_versions/0",
                serde_json::json!("2025-05-28.basil"),
            ),
            ("/expires_at", serde_json::json!(NOW + 100)),
            (
                "/aggregate_budgets/0/window/ends_at",
                serde_json::json!(NOW + 1),
            ),
        ] {
            let mut value_copy = base.clone();
            *value_copy.pointer_mut(pointer).unwrap() = value;
            tightened.push(value_copy);
        }
        for value in tightened {
            let policy: StripeBoundedMerchantPaymentPolicyV1 =
                serde_json::from_value(value).unwrap();
            let decision = evaluate_payment_authorize(&PaymentAuthorizeEvaluationContext {
                workflow_id: "merchant-workflow-0004",
                policy: &policy,
                action: &action,
                evidence: &evidence,
                aggregate_snapshot: &MerchantAggregateSnapshot::default(),
                required_configuration: &configuration,
                executed_configuration: &configuration,
                request_audience: configuration.executor_audience(),
                now: NOW,
            });
            assert_ne!(decision.class, PaymentAuthorizeDecisionClass::Eligible);
        }
    }

    #[test]
    fn merchant_public_values_contain_no_refund_schema_or_type() {
        let policy = merchant_policy(MerchantOperation::Authorize, 1_000, 2_000);
        let configuration = merchant_authorize_configuration(&policy);
        let action =
            merchant_authorize_action("merchant-workflow-0005", &policy, &configuration, 1_000);
        let values = [
            serde_json::to_string(&policy).unwrap(),
            serde_json::to_string(&configuration).unwrap(),
            serde_json::to_string(&action).unwrap(),
            serde_json::to_string(&merchant_evidence()).unwrap(),
        ];
        for value in values {
            assert!(!value.to_ascii_lowercase().contains("refund"));
        }
        assert_ne!(action.digest().unwrap(), sha256(b"refund"));
    }

    proptest! {
        #[test]
        fn every_positive_amount_at_or_below_the_closed_ceiling_is_eligible(
            ceiling in 1_u64..=99_999_998,
        ) {
            let policy = merchant_policy(MerchantOperation::Authorize, ceiling, 99_999_999);
            let configuration = merchant_authorize_configuration(&policy);
            let action = merchant_authorize_action(
                "merchant-property-inside-0001",
                &policy,
                &configuration,
                ceiling,
            );
            let decision = evaluate_payment_authorize(&PaymentAuthorizeEvaluationContext {
                workflow_id: "merchant-property-inside-0001",
                policy: &policy,
                action: &action,
                evidence: &merchant_evidence(),
                aggregate_snapshot: &MerchantAggregateSnapshot::default(),
                required_configuration: &configuration,
                executed_configuration: &configuration,
                request_audience: configuration.executor_audience(),
                now: NOW,
            });
            prop_assert_eq!(decision.class, PaymentAuthorizeDecisionClass::Eligible);
        }

        #[test]
        fn one_minor_unit_past_any_representable_ceiling_is_denied(
            ceiling in 1_u64..=99_999_998,
        ) {
            let policy = merchant_policy(MerchantOperation::Authorize, ceiling, 99_999_999);
            let configuration = merchant_authorize_configuration(&policy);
            let action = merchant_authorize_action(
                "merchant-property-outside-0001",
                &policy,
                &configuration,
                ceiling + 1,
            );
            let decision = evaluate_payment_authorize(&PaymentAuthorizeEvaluationContext {
                workflow_id: "merchant-property-outside-0001",
                policy: &policy,
                action: &action,
                evidence: &merchant_evidence(),
                aggregate_snapshot: &MerchantAggregateSnapshot::default(),
                required_configuration: &configuration,
                executed_configuration: &configuration,
                request_audience: configuration.executor_audience(),
                now: NOW,
            });
            prop_assert_eq!(
                decision.code,
                PaymentAuthorizeDecisionCode::PaymentAuthorizationLimitExceeded
            );
        }
    }
}
