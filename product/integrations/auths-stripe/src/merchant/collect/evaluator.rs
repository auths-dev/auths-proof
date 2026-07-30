//! Pure bounded evaluator for one exact automatic-capture collection.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use super::super::{
    MerchantAggregateSnapshot, MerchantOperation, MerchantPaymentEvidenceV1,
    MerchantReservationIntent, PAYMENT_COLLECT_PROFILE, PriorMerchantPaymentState,
    StripeBoundedMerchantPaymentPolicyV1, StripeMerchantEvaluatorConfigurationV1,
    fixed_merchant_metadata_commitment, merchant_statement_descriptor_commitment,
};
use super::action::StripeExactPaymentCollectV1;
use crate::types::DigestHex;

/// Successful bounded calculation projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentCollectEligibility {
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
pub enum PaymentCollectDecisionClass {
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
pub enum PaymentCollectDecisionStage {
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
pub enum PaymentCollectDecisionCode {
    /// Exact payment is eligible.
    PaymentCollectAuthorized,
    /// Per-action ceiling exceeded.
    PaymentCollectLimitExceeded,
    /// Customer outside configured scope.
    PaymentCustomerDenied,
    /// `PaymentMethod` outside configured scope.
    PaymentMethodDenied,
    /// Order already has successful or ambiguous payment state.
    PaymentOrderConflict,
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

impl PaymentCollectDecisionCode {
    /// Stable literal code used in receipts and APIs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PaymentCollectAuthorized => "payment-collect-authorized",
            Self::PaymentCollectLimitExceeded => "payment-collect-limit-exceeded",
            Self::PaymentCustomerDenied => "payment-customer-denied",
            Self::PaymentMethodDenied => "payment-method-denied",
            Self::PaymentOrderConflict => "payment-order-conflict",
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
pub struct PaymentCollectDecision {
    /// Three-way class.
    pub class: PaymentCollectDecisionClass,
    /// Stable code.
    pub code: PaymentCollectDecisionCode,
    /// Stable evaluation stage.
    pub stage: PaymentCollectDecisionStage,
    /// Literal non-secret explanation.
    pub detail: String,
    /// Successful calculations.
    pub eligibility: Option<PaymentCollectEligibility>,
}

impl PaymentCollectDecision {
    fn denied(
        code: PaymentCollectDecisionCode,
        stage: PaymentCollectDecisionStage,
        detail: &'static str,
    ) -> Self {
        Self {
            class: PaymentCollectDecisionClass::Denied,
            code,
            stage,
            detail: detail.into(),
            eligibility: None,
        }
    }
}

/// Explicit inputs to the pure collection evaluator.
pub struct PaymentCollectEvaluationContext<'a> {
    /// Durable workflow identity.
    pub workflow_id: &'a str,
    /// Immutable configured policy.
    pub policy: &'a StripeBoundedMerchantPaymentPolicyV1,
    /// Agent-selected exact payment.
    pub action: &'a StripeExactPaymentCollectV1,
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

/// Evaluates one exact automatic-capture collection inside configured bounds.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "the closed fail-closed check ordering stays linear and auditable"
)]
pub fn evaluate_payment_collect(
    context: &PaymentCollectEvaluationContext<'_>,
) -> PaymentCollectDecision {
    if context.required_configuration != context.executed_configuration {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::BoundedConfigurationMismatch,
            PaymentCollectDecisionStage::Configuration,
            "required and executed merchant-payment configurations differ",
        );
    }
    if context.policy.validate().is_err()
        || context.required_configuration.validate().is_err()
        || context.action.validate().is_err()
    {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::BoundedPolicyInvalid,
            PaymentCollectDecisionStage::Policy,
            "policy, configuration, or exact action is not valid V1",
        );
    }
    let Ok(policy_digest) = context.policy.digest() else {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::BoundedPolicyInvalid,
            PaymentCollectDecisionStage::Policy,
            "policy identity could not be computed",
        );
    };
    let Ok(configuration_digest) = context.required_configuration.digest() else {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::BoundedPolicyInvalid,
            PaymentCollectDecisionStage::Configuration,
            "configuration identity could not be computed",
        );
    };
    if !digest_eq(
        context.required_configuration.policy_digest(),
        &policy_digest,
    ) || context.required_configuration.exact_action_profile() != PAYMENT_COLLECT_PROFILE
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
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::BoundedActionMismatch,
            PaymentCollectDecisionStage::ExactAction,
            "the exact action does not bind the configured policy and runtime",
        );
    }
    if context.now < context.policy.valid_from() || context.now > context.policy.expires_at() {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::BoundedPolicyExpired,
            PaymentCollectDecisionStage::Policy,
            "the immutable configured policy is not active",
        );
    }
    let Some(lifetime) = context.action.expires_at().checked_sub(context.now) else {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::BoundedPolicyExpired,
            PaymentCollectDecisionStage::ExactAction,
            "the exact action is expired",
        );
    };
    if lifetime == 0
        || lifetime > context.policy.maximum_action_lifetime_seconds()
        || context.action.expires_at() > context.policy.expires_at()
    {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::BoundedActionMismatch,
            PaymentCollectDecisionStage::ExactAction,
            "the exact action lifetime exceeds configured containment",
        );
    }
    let Ok(expected_metadata) = fixed_merchant_metadata_commitment(
        context.workflow_id,
        PAYMENT_COLLECT_PROFILE,
        context.action.order_scope(),
        &policy_digest,
    ) else {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::BoundedActionMismatch,
            PaymentCollectDecisionStage::ExactAction,
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
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::BoundedActionMismatch,
            PaymentCollectDecisionStage::ExactAction,
            "provider-visible descriptor or fixed metadata commitment differs",
        );
    }
    if context.evidence.livemode() {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::BoundedTestModeRequired,
            PaymentCollectDecisionStage::Evidence,
            "merchant-payment V1 requires Stripe test mode",
        );
    }
    let Some(evidence_age) = context.now.checked_sub(context.evidence.observed_at()) else {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::BoundedEvidenceStale,
            PaymentCollectDecisionStage::Evidence,
            "provider evidence is from the future",
        );
    };
    if evidence_age > context.policy.maximum_evidence_age_seconds() {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::BoundedEvidenceStale,
            PaymentCollectDecisionStage::Evidence,
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
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::BoundedEvidenceMismatch,
            PaymentCollectDecisionStage::Evidence,
            "fresh Customer, PaymentMethod, order, account, or API evidence differs",
        );
    }
    if context
        .policy
        .allowed_operations()
        .binary_search(&MerchantOperation::Collect)
        .is_err()
    {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::PaymentCollectLimitExceeded,
            PaymentCollectDecisionStage::StripeScope,
            "automatic collection is not an allowed operation",
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
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::BoundedAccountDenied,
            PaymentCollectDecisionStage::StripeScope,
            "Stripe account or Connect context is outside configured scope",
        );
    }
    if context
        .policy
        .allowed_customer_ids()
        .binary_search(context.action.customer_id())
        .is_err()
    {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::PaymentCustomerDenied,
            PaymentCollectDecisionStage::StripeScope,
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
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::PaymentMethodDenied,
            PaymentCollectDecisionStage::StripeScope,
            "the exact PaymentMethod or type is outside configured scope",
        );
    }
    if context
        .policy
        .allowed_order_scopes()
        .binary_search_by(|value| value.as_str().cmp(context.action.order_scope()))
        .is_err()
    {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::BoundedOrderDenied,
            PaymentCollectDecisionStage::StripeScope,
            "the protected order scope is outside configured scope",
        );
    }
    if context
        .policy
        .allowed_currencies()
        .binary_search(context.action.currency())
        .is_err()
    {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::BoundedCurrencyDenied,
            PaymentCollectDecisionStage::StripeScope,
            "the exact currency is outside configured scope",
        );
    }
    if context
        .policy
        .allowed_api_versions()
        .binary_search_by(|value| value.as_str().cmp(context.action.stripe_api_version()))
        .is_err()
    {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::BoundedApiVersionDenied,
            PaymentCollectDecisionStage::StripeScope,
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
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::PaymentOrderConflict,
            PaymentCollectDecisionStage::Evidence,
            "the order already has successful, active, processing, or ambiguous payment state",
        );
    }
    let Some(operation_ceiling_minor) = context
        .policy
        .operation_limit_minor(MerchantOperation::Collect, context.action.currency())
    else {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::PaymentCollectLimitExceeded,
            PaymentCollectDecisionStage::Limits,
            "no operation ceiling applies to the exact currency",
        );
    };
    let Some(customer_ceiling_minor) = context
        .policy
        .customer_limit_minor(context.action.currency())
    else {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::PaymentCollectLimitExceeded,
            PaymentCollectDecisionStage::Limits,
            "no customer ceiling applies to the exact currency",
        );
    };
    let Some(order_ceiling_minor) = context.policy.order_limit_minor(context.action.currency())
    else {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::PaymentCollectLimitExceeded,
            PaymentCollectDecisionStage::Limits,
            "no order ceiling applies to the exact currency",
        );
    };
    let effective_ceiling_minor = operation_ceiling_minor
        .min(customer_ceiling_minor)
        .min(order_ceiling_minor);
    if context.action.amount_minor() > effective_ceiling_minor {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::PaymentCollectLimitExceeded,
            PaymentCollectDecisionStage::Limits,
            "the exact collection exceeds an operation, customer, or order ceiling",
        );
    }
    let mut reservations = Vec::new();
    for budget in context.policy.aggregate_budgets().iter().filter(|budget| {
        budget.operation() == MerchantOperation::Collect
            && budget.currency() == context.action.currency()
    }) {
        let Ok(window) = budget.window().identity(context.now) else {
            return PaymentCollectDecision::denied(
                PaymentCollectDecisionCode::BoundedPolicyExpired,
                PaymentCollectDecisionStage::AggregateBudget,
                "an applicable aggregate window is inactive",
            );
        };
        let usage = context.aggregate_snapshot.usages.iter().find(|usage| {
            usage.budget_id == budget.budget_id()
                && usage.operation == MerchantOperation::Collect
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
            return PaymentCollectDecision::denied(
                PaymentCollectDecisionCode::BoundedArithmeticOverflow,
                PaymentCollectDecisionStage::AggregateBudget,
                "aggregate usage addition overflowed",
            );
        };
        let Some(available) = budget.limit_minor().checked_sub(used) else {
            return PaymentCollectDecision::denied(
                PaymentCollectDecisionCode::BoundedArithmeticOverflow,
                PaymentCollectDecisionStage::AggregateBudget,
                "aggregate usage exceeds its configured limit",
            );
        };
        if context.action.amount_minor() > available {
            return PaymentCollectDecision::denied(
                PaymentCollectDecisionCode::BoundedAggregateBudgetExceeded,
                PaymentCollectDecisionStage::AggregateBudget,
                "the exact collection exceeds currently available aggregate capacity",
            );
        }
        reservations.push(MerchantReservationIntent {
            budget_id: budget.budget_id().into(),
            operation: MerchantOperation::Collect,
            currency: context.action.currency().clone(),
            window,
            limit_minor: budget.limit_minor(),
            amount_minor: context.action.amount_minor(),
            available_before_minor: available,
        });
    }
    if reservations.is_empty() {
        return PaymentCollectDecision::denied(
            PaymentCollectDecisionCode::BoundedAggregateBudgetExceeded,
            PaymentCollectDecisionStage::AggregateBudget,
            "no aggregate budget applies to automatic collection",
        );
    }
    PaymentCollectDecision {
        class: PaymentCollectDecisionClass::Eligible,
        code: PaymentCollectDecisionCode::PaymentCollectAuthorized,
        stage: PaymentCollectDecisionStage::Complete,
        detail: "the exact automatic-capture payment is inside the immutable configured policy"
            .into(),
        eligibility: Some(PaymentCollectEligibility {
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
            NOW, merchant_collect_action, merchant_configuration, merchant_evidence,
            merchant_policy,
        },
    };

    fn decision(amount_minor: u64) -> PaymentCollectDecision {
        let policy = merchant_policy(MerchantOperation::Collect, 1_000, 2_000);
        let configuration = merchant_configuration(&policy);
        let action = merchant_collect_action(
            "merchant-workflow-0001",
            &policy,
            &configuration,
            amount_minor,
        );
        evaluate_payment_collect(&PaymentCollectEvaluationContext {
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
    fn inclusive_collection_boundary_and_one_past_are_distinct() {
        assert_eq!(decision(1_000).class, PaymentCollectDecisionClass::Eligible);
        let denied = decision(1_001);
        assert_eq!(denied.class, PaymentCollectDecisionClass::Denied);
        assert_eq!(
            denied.code,
            PaymentCollectDecisionCode::PaymentCollectLimitExceeded
        );
    }

    #[test]
    fn configuration_mismatch_denies_before_any_capacity_intent() {
        let policy = merchant_policy(MerchantOperation::Collect, 1_000, 2_000);
        let required = merchant_configuration(&policy);
        let other_policy = merchant_policy(MerchantOperation::Collect, 1_000, 1_999);
        let executed = merchant_configuration(&other_policy);
        let action = merchant_collect_action("merchant-workflow-0002", &policy, &required, 1_000);
        let decision = evaluate_payment_collect(&PaymentCollectEvaluationContext {
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
            PaymentCollectDecisionCode::BoundedConfigurationMismatch
        );
        assert!(decision.eligibility.is_none());
    }

    #[test]
    fn aggregate_arithmetic_is_checked() {
        let policy = merchant_policy(MerchantOperation::Collect, 1_000, 2_000);
        let configuration = merchant_configuration(&policy);
        let action =
            merchant_collect_action("merchant-workflow-0003", &policy, &configuration, 1_000);
        let budget = &policy.aggregate_budgets()[0];
        let snapshot = MerchantAggregateSnapshot {
            usages: vec![MerchantAggregateUsage {
                budget_id: budget.budget_id().into(),
                operation: MerchantOperation::Collect,
                currency: action.currency().clone(),
                window: budget.window().identity(NOW).unwrap(),
                committed_minor: u64::MAX,
                reserved_minor: 1,
                outcome_unknown_minor: 0,
                active_authorization_minor: 0,
            }],
        };
        let decision = evaluate_payment_collect(&PaymentCollectEvaluationContext {
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
            PaymentCollectDecisionCode::BoundedArithmeticOverflow
        );
    }

    #[test]
    fn tightening_every_shared_policy_dimension_never_opens_fixed_action() {
        let policy = merchant_policy(MerchantOperation::Collect, 1_000, 2_000);
        let configuration = merchant_configuration(&policy);
        let action =
            merchant_collect_action("merchant-workflow-0004", &policy, &configuration, 1_001);
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
                "/per_operation_absolute_minor_by_currency/collect/usd",
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
            let decision = evaluate_payment_collect(&PaymentCollectEvaluationContext {
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
            assert_ne!(decision.class, PaymentCollectDecisionClass::Eligible);
        }
    }

    #[test]
    fn merchant_public_values_contain_no_refund_schema_or_type() {
        let policy = merchant_policy(MerchantOperation::Collect, 1_000, 2_000);
        let configuration = merchant_configuration(&policy);
        let action =
            merchant_collect_action("merchant-workflow-0005", &policy, &configuration, 1_000);
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
            let policy = merchant_policy(MerchantOperation::Collect, ceiling, 99_999_999);
            let configuration = merchant_configuration(&policy);
            let action = merchant_collect_action(
                "merchant-property-inside-0001",
                &policy,
                &configuration,
                ceiling,
            );
            let decision = evaluate_payment_collect(&PaymentCollectEvaluationContext {
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
            prop_assert_eq!(decision.class, PaymentCollectDecisionClass::Eligible);
        }

        #[test]
        fn one_minor_unit_past_any_representable_ceiling_is_denied(
            ceiling in 1_u64..=99_999_998,
        ) {
            let policy = merchant_policy(MerchantOperation::Collect, ceiling, 99_999_999);
            let configuration = merchant_configuration(&policy);
            let action = merchant_collect_action(
                "merchant-property-outside-0001",
                &policy,
                &configuration,
                ceiling + 1,
            );
            let decision = evaluate_payment_collect(&PaymentCollectEvaluationContext {
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
                PaymentCollectDecisionCode::PaymentCollectLimitExceeded
            );
        }
    }
}
