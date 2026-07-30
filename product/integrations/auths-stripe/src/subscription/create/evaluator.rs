//! Pure deterministic bounded subscription-create evaluator.

use serde::{Deserialize, Serialize};

use super::StripeExactSubscriptionCreateV1;
use crate::{
    mandate::MandateAmountType,
    subscription::{
        ImmediateLiabilityReservation, RecurringLiabilityReservation,
        StripeBoundedSubscriptionPolicyV1, StripeSubscriptionConfigurationV1,
        SubscriptionCreateEvidenceV1, SubscriptionInterval, SubscriptionOperation,
    },
};

/// Stable decision class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionCreateDecisionClass {
    Eligible,
    Denied,
    Indeterminate,
}

/// Stable profile-specific codes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubscriptionCreateDecisionCode {
    Authorized,
    ConfigurationMismatch,
    PolicyInvalid,
    ActionInvalid,
    EvidenceInvalid,
    PolicyInactive,
    ActionExpired,
    EvidenceStale,
    PreviewStale,
    AccountDenied,
    CustomerDenied,
    PriceDenied,
    MeteredPriceDenied,
    QuantityExceeded,
    TermRequired,
    TermExceeded,
    RecurringLimitExceeded,
    FirstInvoiceLimitExceeded,
    PreviewMismatch,
    MandateMismatch,
    ActiveCountExceeded,
    ArithmeticOverflow,
    ReservationUnavailable,
}

/// Evaluation stage reached before returning.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionCreateDecisionStage {
    Configuration,
    Validation,
    Freshness,
    Scope,
    Calculation,
    Capacity,
    Complete,
}

/// Exact calculated authority and atomic reservation intents.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCreateEligibility {
    pub interval: SubscriptionInterval,
    pub recurring_minor: u64,
    pub first_invoice_minor: u64,
    pub cycle_count: u32,
    pub term_liability_minor: u64,
    pub recurring_reservations: Vec<RecurringLiabilityReservation>,
    pub immediate_reservations: Vec<ImmediateLiabilityReservation>,
}

/// Closed pure result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCreateDecision {
    pub class: SubscriptionCreateDecisionClass,
    pub code: SubscriptionCreateDecisionCode,
    pub stage: SubscriptionCreateDecisionStage,
    pub detail: String,
    pub eligibility: Option<SubscriptionCreateEligibility>,
}

impl SubscriptionCreateDecision {
    fn denied(
        code: SubscriptionCreateDecisionCode,
        stage: SubscriptionCreateDecisionStage,
        detail: &str,
    ) -> Self {
        Self {
            class: SubscriptionCreateDecisionClass::Denied,
            code,
            stage,
            detail: detail.into(),
            eligibility: None,
        }
    }
    fn indeterminate(
        code: SubscriptionCreateDecisionCode,
        stage: SubscriptionCreateDecisionStage,
        detail: &str,
    ) -> Self {
        Self {
            class: SubscriptionCreateDecisionClass::Indeterminate,
            code,
            stage,
            detail: detail.into(),
            eligibility: None,
        }
    }
}

/// Complete pure input.
pub struct SubscriptionCreateEvaluationContext<'a> {
    pub action: &'a StripeExactSubscriptionCreateV1,
    pub policy: &'a StripeBoundedSubscriptionPolicyV1,
    pub evidence: &'a SubscriptionCreateEvidenceV1,
    pub required_configuration: &'a StripeSubscriptionConfigurationV1,
    pub executed_configuration: &'a StripeSubscriptionConfigurationV1,
    pub now: u64,
}

/// Evaluates only creation semantics; no operation tag dispatches behavior.
pub fn evaluate_subscription_create(
    context: &SubscriptionCreateEvaluationContext<'_>,
) -> SubscriptionCreateDecision {
    let action = context.action;
    let policy = context.policy;
    let evidence = context.evidence;

    let configuration_equal = context.required_configuration == context.executed_configuration
        && action.required_configuration_digest()
            == &match context.required_configuration.digest() {
                Ok(value) => value,
                Err(_) => {
                    return SubscriptionCreateDecision::indeterminate(
                        SubscriptionCreateDecisionCode::ConfigurationMismatch,
                        SubscriptionCreateDecisionStage::Configuration,
                        "required evaluator configuration could not be canonicalized",
                    );
                }
            }
        && action.required_policy_digest()
            == &match policy.digest() {
                Ok(value) => value,
                Err(_) => {
                    return SubscriptionCreateDecision::indeterminate(
                        SubscriptionCreateDecisionCode::PolicyInvalid,
                        SubscriptionCreateDecisionStage::Configuration,
                        "configured policy could not be canonicalized",
                    );
                }
            };
    if !configuration_equal {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::ConfigurationMismatch,
            SubscriptionCreateDecisionStage::Configuration,
            "required and executed subscription configurations differ",
        );
    }
    if policy.validate().is_err() {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::PolicyInvalid,
            SubscriptionCreateDecisionStage::Validation,
            "configured subscription policy is invalid",
        );
    }
    if action.validate().is_err() {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::ActionInvalid,
            SubscriptionCreateDecisionStage::Validation,
            "exact subscription action is invalid",
        );
    }
    if evidence.validate().is_err() {
        return SubscriptionCreateDecision::indeterminate(
            SubscriptionCreateDecisionCode::EvidenceInvalid,
            SubscriptionCreateDecisionStage::Validation,
            "protected Stripe evidence is malformed",
        );
    }

    if context.now < policy.valid_from() || context.now > policy.expires_at() {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::PolicyInactive,
            SubscriptionCreateDecisionStage::Freshness,
            "subscription policy is not active",
        );
    }
    if action.expires_at() < context.now
        || action.expires_at().saturating_sub(context.now)
            > policy.maximum_action_lifetime_seconds()
    {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::ActionExpired,
            SubscriptionCreateDecisionStage::Freshness,
            "exact subscription action is expired or too long lived",
        );
    }
    if evidence.observed_at > context.now
        || context.now.saturating_sub(evidence.observed_at) > policy.maximum_evidence_age_seconds()
    {
        return SubscriptionCreateDecision::indeterminate(
            SubscriptionCreateDecisionCode::EvidenceStale,
            SubscriptionCreateDecisionStage::Freshness,
            "catalog, customer, mandate, or preview evidence is stale",
        );
    }
    if evidence.preview_valid_until
        < context
            .now
            .saturating_add(policy.minimum_preview_validity_seconds())
    {
        return SubscriptionCreateDecision::indeterminate(
            SubscriptionCreateDecisionCode::PreviewStale,
            SubscriptionCreateDecisionStage::Freshness,
            "invoice preview validity is too short",
        );
    }

    let scope_matches = policy
        .allowed_operations()
        .binary_search(&SubscriptionOperation::Create)
        .is_ok()
        && policy
            .allowed_test_account_ids()
            .binary_search(action.stripe_account_id())
            .is_ok()
        && action.stripe_account_id() == &evidence.stripe_account_id
        && action.connect_account() == &evidence.connect_account
        && action.test_clock_id() == &evidence.test_clock_id
        && action.stripe_api_version() == evidence.stripe_api_version
        && policy
            .allowed_api_versions()
            .binary_search(&action.stripe_api_version().to_owned())
            .is_ok();
    if !scope_matches {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::AccountDenied,
            SubscriptionCreateDecisionStage::Scope,
            "Stripe account, Connect, API, or test-clock scope differs",
        );
    }
    if policy
        .allowed_customer_ids()
        .binary_search(action.customer_id())
        .is_err()
        || action.customer_id() != &evidence.customer_id
    {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::CustomerDenied,
            SubscriptionCreateDecisionStage::Scope,
            "customer is outside configured scope",
        );
    }
    let Ok(mandate_action_digest) = evidence.mandate_action.digest() else {
        return SubscriptionCreateDecision::indeterminate(
            SubscriptionCreateDecisionCode::MandateMismatch,
            SubscriptionCreateDecisionStage::Scope,
            "mandate action could not be canonicalized",
        );
    };
    let mandate_matches = action.mandate_receipt_digest() == &evidence.mandate_receipt_digest
        && policy
            .allowed_mandate_receipt_digests()
            .binary_search(action.mandate_receipt_digest())
            .is_ok()
        && crate::canonical::canonical_digest(&evidence.mandate_receipt)
            .ok()
            .as_ref()
            == Some(action.mandate_receipt_digest())
        && evidence.mandate_capability.action_digest() == &mandate_action_digest
        && evidence.mandate_action.currency() == action.currency()
        && evidence.mandate_action.customer_id() == action.customer_id()
        && evidence.mandate_action.payment_method_id() == action.default_payment_method_id()
        && policy
            .allowed_payment_method_ids()
            .binary_search(action.default_payment_method_id())
            .is_ok();
    if !mandate_matches {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::MandateMismatch,
            SubscriptionCreateDecisionStage::Scope,
            "exact committed mandate does not authorize this subscription",
        );
    }

    if action.items().len() != evidence.catalog.len()
        || action
            .items()
            .iter()
            .zip(&evidence.catalog)
            .any(|(item, catalog)| {
                item.price_id() != &catalog.price_id
                    || item.product_id() != &catalog.product_id
                    || !catalog.active
                    || policy
                        .allowed_price_ids()
                        .binary_search(&catalog.price_id)
                        .is_err()
                    || policy
                        .allowed_product_ids()
                        .binary_search(&catalog.product_id)
                        .is_err()
            })
    {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::PriceDenied,
            SubscriptionCreateDecisionStage::Scope,
            "an exact Product/Price identity or active catalog fact differs",
        );
    }
    if evidence
        .catalog
        .iter()
        .any(|item| !item.licensed || item.interval_count != 1)
    {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::MeteredPriceDenied,
            SubscriptionCreateDecisionStage::Scope,
            "only fixed licensed prices with interval_count=1 are allowed",
        );
    }
    if action.items().iter().any(|item| {
        policy
            .maximum_quantity_by_price()
            .get(item.price_id())
            .is_none_or(|maximum| item.quantity() > *maximum)
    }) {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::QuantityExceeded,
            SubscriptionCreateDecisionStage::Scope,
            "a quantity exceeds its exact Price ceiling",
        );
    }

    let Some(interval) = evidence.catalog.first().map(|item| item.interval) else {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::PriceDenied,
            SubscriptionCreateDecisionStage::Calculation,
            "catalog is empty",
        );
    };
    if evidence
        .catalog
        .iter()
        .any(|item| item.interval != interval || item.currency != *action.currency())
        || policy.allowed_intervals().binary_search(&interval).is_err()
    {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::PriceDenied,
            SubscriptionCreateDecisionStage::Calculation,
            "catalog currency or interval is not uniform and allowed",
        );
    }

    let Some(recurring_minor) = action.items().iter().zip(&evidence.catalog).try_fold(
        0_u64,
        |sum, (action_item, catalog)| {
            catalog
                .unit_amount_minor
                .checked_mul(u64::from(action_item.quantity()))
                .and_then(|value| sum.checked_add(value))
        },
    ) else {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::ArithmeticOverflow,
            SubscriptionCreateDecisionStage::Calculation,
            "recurring amount arithmetic overflowed",
        );
    };
    if recurring_minor != action.projected_recurring_minor() {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::PreviewMismatch,
            SubscriptionCreateDecisionStage::Calculation,
            "protected catalog does not reproduce projected recurring amount",
        );
    }

    if action.billing_cycle_anchor() >= action.cancel_at()
        || evidence.cycle_anchors.first().copied() != Some(action.billing_cycle_anchor())
        || evidence
            .cycle_anchors
            .last()
            .is_none_or(|last| *last >= action.cancel_at())
    {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::TermRequired,
            SubscriptionCreateDecisionStage::Calculation,
            "fixed term is absent or not reproduced by exact calendar evidence",
        );
    }
    let Ok(cycle_count) = u32::try_from(evidence.cycle_anchors.len()) else {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::TermExceeded,
            SubscriptionCreateDecisionStage::Calculation,
            "billing cycle count exceeds the integer boundary",
        );
    };
    if cycle_count != action.projected_cycle_count()
        || cycle_count > policy.maximum_billing_cycles()
        || action
            .cancel_at()
            .saturating_sub(action.billing_cycle_anchor())
            > policy.maximum_term_seconds()
    {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::TermExceeded,
            SubscriptionCreateDecisionStage::Calculation,
            "fixed term or exact provider-derived cycle count exceeds policy",
        );
    }
    let Some(term_liability_minor) = recurring_minor.checked_mul(u64::from(cycle_count)) else {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::ArithmeticOverflow,
            SubscriptionCreateDecisionStage::Calculation,
            "finite term liability overflowed",
        );
    };
    if term_liability_minor != action.projected_term_liability_minor() {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::PreviewMismatch,
            SubscriptionCreateDecisionStage::Calculation,
            "projected finite term liability differs",
        );
    }
    let mandate_ceiling_ok = match evidence.mandate_action.mandate_amount_type() {
        MandateAmountType::Fixed => {
            recurring_minor == evidence.mandate_action.mandate_amount_minor()
        }
        MandateAmountType::Maximum => {
            recurring_minor <= evidence.mandate_action.mandate_amount_minor()
        }
    };
    if !mandate_ceiling_ok || evidence.mandate_action.interval() != interval.mandate_interval() {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::MandateMismatch,
            SubscriptionCreateDecisionStage::Calculation,
            "recurring amount or interval exceeds the exact mandate capability",
        );
    }
    let recurring_limit = policy
        .recurring_limits()
        .iter()
        .find(|limit| limit.currency == *action.currency() && limit.interval == interval)
        .map(|limit| limit.limit_minor);
    if recurring_limit.is_none_or(|limit| recurring_minor > limit) {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::RecurringLimitExceeded,
            SubscriptionCreateDecisionStage::Capacity,
            "per-cycle recurring amount exceeds policy",
        );
    }

    if evidence.preview_digest != *action.invoice_preview_digest()
        || evidence
            .preview_lines
            .iter()
            .any(|line| line.proration || line.amount_minor < 0)
    {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::PreviewMismatch,
            SubscriptionCreateDecisionStage::Calculation,
            "invoice preview includes a mismatch, credit, or proration",
        );
    }
    let preview_sum = evidence
        .preview_lines
        .iter()
        .try_fold(0_i64, |sum, line| sum.checked_add(line.amount_minor));
    if preview_sum != Some(evidence.preview_amount_due_minor)
        || evidence.preview_amount_due_minor < 0
    {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::PreviewMismatch,
            SubscriptionCreateDecisionStage::Calculation,
            "invoice preview lines do not reproduce amount_due",
        );
    }
    let first_invoice_minor = u64::try_from(evidence.preview_amount_due_minor).unwrap_or(0);
    if first_invoice_minor != action.projected_first_invoice_minor()
        || policy
            .first_invoice_limits()
            .get(action.currency())
            .is_none_or(|limit| first_invoice_minor > *limit)
    {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::FirstInvoiceLimitExceeded,
            SubscriptionCreateDecisionStage::Capacity,
            "first invoice differs or exceeds policy",
        );
    }
    if evidence.active_subscriptions >= policy.maximum_active_subscriptions_per_customer() {
        return SubscriptionCreateDecision::denied(
            SubscriptionCreateDecisionCode::ActiveCountExceeded,
            SubscriptionCreateDecisionStage::Capacity,
            "active subscription slot is unavailable",
        );
    }

    let recurring_reservations = policy
        .aggregate_recurring_budgets()
        .iter()
        .filter(|budget| {
            budget.customer_id == *action.customer_id()
                && budget.currency == *action.currency()
                && budget.interval == interval
        })
        .map(|budget| RecurringLiabilityReservation {
            budget_id: budget.budget_id.clone(),
            currency: budget.currency.clone(),
            interval: budget.interval,
            amount_minor: term_liability_minor,
            limit_minor: budget.limit_minor,
        })
        .collect();
    let immediate_reservations = policy
        .aggregate_immediate_budgets()
        .iter()
        .filter(|budget| {
            budget.currency == *action.currency()
                && budget.starts_at <= context.now
                && context.now < budget.ends_at
        })
        .map(|budget| ImmediateLiabilityReservation {
            budget_id: budget.budget_id.clone(),
            currency: budget.currency.clone(),
            amount_minor: first_invoice_minor,
            limit_minor: budget.limit_minor,
            starts_at: budget.starts_at,
            ends_at: budget.ends_at,
        })
        .collect();

    SubscriptionCreateDecision {
        class: SubscriptionCreateDecisionClass::Eligible,
        code: SubscriptionCreateDecisionCode::Authorized,
        stage: SubscriptionCreateDecisionStage::Complete,
        detail: "exact fixed-term subscription is inside mandate and configured liability bounds"
            .into(),
        eligibility: Some(SubscriptionCreateEligibility {
            interval,
            recurring_minor,
            first_invoice_minor,
            cycle_count,
            term_liability_minor,
            recurring_reservations,
            immediate_reservations,
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;
    use crate::subscription::{
        StripeBoundedSubscriptionPolicyV1, StripeSubscriptionConfigurationV1,
        SubscriptionCreateEvidenceV1,
    };

    fn fixtures() -> (
        StripeExactSubscriptionCreateV1,
        StripeBoundedSubscriptionPolicyV1,
        SubscriptionCreateEvidenceV1,
        StripeSubscriptionConfigurationV1,
    ) {
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/subscription-create/v1");
        (
            serde_json::from_slice(&fs::read(root.join("action.json")).unwrap()).unwrap(),
            serde_json::from_slice(&fs::read(root.join("policy.json")).unwrap()).unwrap(),
            serde_json::from_slice(&fs::read(root.join("evidence.json")).unwrap()).unwrap(),
            serde_json::from_slice(&fs::read(root.join("configuration.json")).unwrap()).unwrap(),
        )
    }

    #[test]
    fn exact_fixture_is_eligible() {
        let (action, policy, evidence, configuration) = fixtures();
        let decision = evaluate_subscription_create(&SubscriptionCreateEvaluationContext {
            action: &action,
            policy: &policy,
            evidence: &evidence,
            required_configuration: &configuration,
            executed_configuration: &configuration,
            now: 2_100_000_000,
        });
        assert_eq!(decision.class, SubscriptionCreateDecisionClass::Eligible);
        let eligibility = decision.eligibility.unwrap();
        assert_eq!(eligibility.recurring_minor, 500);
        assert_eq!(eligibility.cycle_count, 3);
        assert_eq!(eligibility.term_liability_minor, 1_500);
    }

    #[test]
    fn configuration_mismatch_precedes_scope_and_capacity() {
        let (action, policy, evidence, mut configuration) = fixtures();
        let altered: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&configuration).unwrap()).unwrap();
        let mut altered = altered;
        altered["executor_audience"] = serde_json::json!("https://other.auths.dev");
        configuration = serde_json::from_value(altered).unwrap();
        let required: StripeSubscriptionConfigurationV1 = serde_json::from_slice(
            &fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("fixtures/subscription-create/v1/configuration.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let decision = evaluate_subscription_create(&SubscriptionCreateEvaluationContext {
            action: &action,
            policy: &policy,
            evidence: &evidence,
            required_configuration: &required,
            executed_configuration: &configuration,
            now: 2_100_000_000,
        });
        assert_eq!(
            decision.code,
            SubscriptionCreateDecisionCode::ConfigurationMismatch
        );
        assert_eq!(
            decision.stage,
            SubscriptionCreateDecisionStage::Configuration
        );
    }

    #[test]
    fn provider_calendar_not_seconds_defines_cycle_count() {
        let (action, policy, mut evidence, configuration) = fixtures();
        evidence.cycle_anchors.pop();
        let decision = evaluate_subscription_create(&SubscriptionCreateEvaluationContext {
            action: &action,
            policy: &policy,
            evidence: &evidence,
            required_configuration: &configuration,
            executed_configuration: &configuration,
            now: 2_100_000_000,
        });
        assert_eq!(decision.code, SubscriptionCreateDecisionCode::TermExceeded);
    }
}
