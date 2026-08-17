//! Pure deterministic evaluator for one exact Subscription modification.

use serde::{Deserialize, Serialize};

use super::{StripeExactSubscriptionModifyV1, SubscriptionModifyEvidenceV1};
use crate::subscription::{
    ImmediateLiabilityReservation, RecurringLiabilityReservation,
    StripeBoundedSubscriptionPolicyV1, StripeSubscriptionConfigurationV1, SubscriptionInterval,
    SubscriptionModifyPaymentBehavior, SubscriptionOperation, SubscriptionProrationBehavior,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionModifyDecisionClass {
    Eligible,
    Denied,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubscriptionModifyDecisionCode {
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
    BeforeStateMismatch,
    ProtectedFieldChanged,
    PriceDenied,
    QuantityExceeded,
    ProrationLimitExceeded,
    RecurringLimitExceeded,
    PreviewMismatch,
    PendingUpdateConflict,
    MandateMismatch,
    ArithmeticOverflow,
    ReservationUnavailable,
}

impl SubscriptionModifyDecisionCode {
    pub const fn stable_code(self) -> &'static str {
        match self {
            Self::Authorized => "subscription-modify-authorized",
            Self::BeforeStateMismatch => "subscription-before-state-mismatch",
            Self::ProtectedFieldChanged => "subscription-protected-field-changed",
            Self::PriceDenied => "subscription-price-denied",
            Self::QuantityExceeded => "subscription-quantity-exceeded",
            Self::ProrationLimitExceeded => "subscription-proration-limit-exceeded",
            Self::RecurringLimitExceeded => "subscription-recurring-limit-exceeded",
            Self::PreviewMismatch => "subscription-preview-mismatch",
            Self::PendingUpdateConflict => "subscription-pending-update-conflict",
            Self::ConfigurationMismatch => "subscription-configuration-mismatch",
            Self::PolicyInvalid => "subscription-policy-invalid",
            Self::ActionInvalid => "subscription-action-invalid",
            Self::EvidenceInvalid => "subscription-evidence-invalid",
            Self::PolicyInactive => "subscription-policy-inactive",
            Self::ActionExpired => "subscription-action-expired",
            Self::EvidenceStale => "subscription-evidence-stale",
            Self::PreviewStale => "subscription-preview-stale",
            Self::AccountDenied => "subscription-account-denied",
            Self::CustomerDenied => "subscription-customer-denied",
            Self::MandateMismatch => "subscription-mandate-mismatch",
            Self::ArithmeticOverflow => "subscription-arithmetic-overflow",
            Self::ReservationUnavailable => "subscription-reservation-unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionModifyDecisionStage {
    Configuration,
    Validation,
    Freshness,
    Scope,
    Calculation,
    Capacity,
    Complete,
}

/// Exact independent debit and recurring-delta authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionModifyEligibility {
    pub interval: SubscriptionInterval,
    pub before_recurring_minor: u64,
    pub after_recurring_minor: u64,
    pub before_term_liability_minor: u64,
    pub after_term_liability_minor: u64,
    pub incremental_term_liability_minor: u64,
    pub superseded_term_liability_minor: u64,
    pub proration_debit_minor: u64,
    pub proration_credit_minor: u64,
    pub recurring_reservations: Vec<RecurringLiabilityReservation>,
    pub immediate_reservations: Vec<ImmediateLiabilityReservation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionModifyDecision {
    pub class: SubscriptionModifyDecisionClass,
    pub code: SubscriptionModifyDecisionCode,
    pub stable_code: String,
    pub stage: SubscriptionModifyDecisionStage,
    pub detail: String,
    pub eligibility: Option<SubscriptionModifyEligibility>,
}

impl SubscriptionModifyDecision {
    fn denied(
        code: SubscriptionModifyDecisionCode,
        stage: SubscriptionModifyDecisionStage,
        detail: &str,
    ) -> Self {
        Self {
            class: SubscriptionModifyDecisionClass::Denied,
            code,
            stable_code: code.stable_code().into(),
            stage,
            detail: detail.into(),
            eligibility: None,
        }
    }
    fn indeterminate(
        code: SubscriptionModifyDecisionCode,
        stage: SubscriptionModifyDecisionStage,
        detail: &str,
    ) -> Self {
        Self {
            class: SubscriptionModifyDecisionClass::Indeterminate,
            code,
            stable_code: code.stable_code().into(),
            stage,
            detail: detail.into(),
            eligibility: None,
        }
    }
}

/// Splits a term-liability change into the amount that must be newly reserved
/// and the amount the modification supersedes.
///
/// This is the whole liability arithmetic of a modification, isolated so it is
/// callable from a bounded proof harness with the same bytes production runs.
///
/// The two sides are deliberately disjoint: an upgrade reserves and releases
/// nothing, a downgrade releases and reserves nothing. Netting them (or letting
/// a credit reduce `incremental`) would let a modification widen spend beyond
/// the reserved ceiling.
#[must_use]
pub const fn term_liability_delta(before_term: u64, after_term: u64) -> (u64, u64) {
    (
        after_term.saturating_sub(before_term),
        before_term.saturating_sub(after_term),
    )
}

pub struct SubscriptionModifyEvaluationContext<'a> {
    pub action: &'a StripeExactSubscriptionModifyV1,
    pub policy: &'a StripeBoundedSubscriptionPolicyV1,
    pub evidence: &'a SubscriptionModifyEvidenceV1,
    pub required_configuration: &'a StripeSubscriptionConfigurationV1,
    pub executed_configuration: &'a StripeSubscriptionConfigurationV1,
    pub now: u64,
}

/// Evaluates only modify semantics. Credits never offset debit or delta checks.
pub fn evaluate_subscription_modify(
    context: &SubscriptionModifyEvaluationContext<'_>,
) -> SubscriptionModifyDecision {
    let action = context.action;
    let policy = context.policy;
    let evidence = context.evidence;

    let Ok(required_digest) = context.required_configuration.digest() else {
        return SubscriptionModifyDecision::indeterminate(
            SubscriptionModifyDecisionCode::ConfigurationMismatch,
            SubscriptionModifyDecisionStage::Configuration,
            "required configuration cannot be canonicalized",
        );
    };
    let Ok(policy_digest) = policy.digest() else {
        return SubscriptionModifyDecision::indeterminate(
            SubscriptionModifyDecisionCode::PolicyInvalid,
            SubscriptionModifyDecisionStage::Configuration,
            "policy cannot be canonicalized",
        );
    };
    if context.required_configuration != context.executed_configuration
        || action.required_configuration_digest() != &required_digest
        || action.required_policy_digest() != &policy_digest
    {
        return SubscriptionModifyDecision::denied(
            SubscriptionModifyDecisionCode::ConfigurationMismatch,
            SubscriptionModifyDecisionStage::Configuration,
            "required and executed configuration differ",
        );
    }
    if policy.validate().is_err() {
        return SubscriptionModifyDecision::denied(
            SubscriptionModifyDecisionCode::PolicyInvalid,
            SubscriptionModifyDecisionStage::Validation,
            "bounded subscription policy is invalid",
        );
    }
    if action.validate().is_err() {
        return SubscriptionModifyDecision::denied(
            SubscriptionModifyDecisionCode::ActionInvalid,
            SubscriptionModifyDecisionStage::Validation,
            "exact modify action is invalid",
        );
    }
    if evidence.validate().is_err() {
        return SubscriptionModifyDecision::indeterminate(
            SubscriptionModifyDecisionCode::EvidenceInvalid,
            SubscriptionModifyDecisionStage::Validation,
            "protected Stripe evidence is invalid",
        );
    }
    if context.now < policy.valid_from() || context.now > policy.expires_at() {
        return SubscriptionModifyDecision::denied(
            SubscriptionModifyDecisionCode::PolicyInactive,
            SubscriptionModifyDecisionStage::Freshness,
            "policy is not active",
        );
    }
    if action.expires_at() < context.now
        || action.expires_at().saturating_sub(context.now)
            > policy.maximum_action_lifetime_seconds()
    {
        return SubscriptionModifyDecision::denied(
            SubscriptionModifyDecisionCode::ActionExpired,
            SubscriptionModifyDecisionStage::Freshness,
            "action is expired or too long lived",
        );
    }
    if evidence.observed_at > context.now
        || context.now.saturating_sub(evidence.observed_at) > policy.maximum_evidence_age_seconds()
    {
        return SubscriptionModifyDecision::indeterminate(
            SubscriptionModifyDecisionCode::EvidenceStale,
            SubscriptionModifyDecisionStage::Freshness,
            "Subscription evidence is stale",
        );
    }
    if evidence.preview_valid_until
        < context
            .now
            .saturating_add(policy.minimum_preview_validity_seconds())
    {
        return SubscriptionModifyDecision::indeterminate(
            SubscriptionModifyDecisionCode::PreviewStale,
            SubscriptionModifyDecisionStage::Freshness,
            "invoice preview is stale",
        );
    }
    if evidence.pending_update_digest.is_some() {
        return SubscriptionModifyDecision::denied(
            SubscriptionModifyDecisionCode::PendingUpdateConflict,
            SubscriptionModifyDecisionStage::Scope,
            "Subscription already has a pending update",
        );
    }

    let scope_matches = policy
        .allowed_operations()
        .binary_search(&SubscriptionOperation::Modify)
        .is_ok()
        && policy
            .allowed_test_account_ids()
            .binary_search(action.stripe_account_id())
            .is_ok()
        && action.stripe_account_id() == &evidence.stripe_account_id
        && action.connect_account() == &evidence.connect_account
        && action.subscription_id() == &evidence.subscription_id
        && action.test_clock_id() == &evidence.test_clock_id
        && action.stripe_api_version() == evidence.stripe_api_version
        && policy
            .allowed_api_versions()
            .binary_search(&action.stripe_api_version().to_owned())
            .is_ok();
    if !scope_matches {
        return SubscriptionModifyDecision::denied(
            SubscriptionModifyDecisionCode::AccountDenied,
            SubscriptionModifyDecisionStage::Scope,
            "account, Subscription, API, Connect, or test-clock scope differs",
        );
    }
    if action.customer_id() != &evidence.customer_id
        || policy
            .allowed_customer_ids()
            .binary_search(action.customer_id())
            .is_err()
    {
        return SubscriptionModifyDecision::denied(
            SubscriptionModifyDecisionCode::CustomerDenied,
            SubscriptionModifyDecisionStage::Scope,
            "Customer is outside configured scope",
        );
    }
    if action.before_subscription_digest() != &evidence.before_subscription_digest
        || action.before_items() != evidence.current_items
    {
        return SubscriptionModifyDecision::denied(
            SubscriptionModifyDecisionCode::BeforeStateMismatch,
            SubscriptionModifyDecisionStage::Scope,
            "committed before state does not equal current Subscription state",
        );
    }
    if action.currency() != &evidence.currency
        || action.billing_cycle_anchor() != evidence.billing_cycle_anchor
        || action.cancel_at() != evidence.cancel_at
        || action.mandate_receipt_digest() != &evidence.mandate_receipt_digest
        || action.proration_date() != evidence.proration_date
        || evidence.collection_method
            != crate::subscription::SubscriptionCollectionMethod::ChargeAutomatically
    {
        return SubscriptionModifyDecision::denied(
            SubscriptionModifyDecisionCode::ProtectedFieldChanged,
            SubscriptionModifyDecisionStage::Scope,
            "a protected field differs",
        );
    }
    if policy
        .allowed_mandate_receipt_digests()
        .binary_search(action.mandate_receipt_digest())
        .is_err()
        || policy
            .allowed_payment_method_ids()
            .binary_search(&evidence.payment_method_id)
            .is_err()
    {
        return SubscriptionModifyDecision::denied(
            SubscriptionModifyDecisionCode::MandateMismatch,
            SubscriptionModifyDecisionStage::Scope,
            "mandate or payment method is outside configured scope",
        );
    }
    if action.payment_behavior() != SubscriptionModifyPaymentBehavior::PendingIfIncomplete
        || action.proration_behavior() != SubscriptionProrationBehavior::AlwaysInvoice
        || policy
            .allowed_proration_behaviors()
            .binary_search(&action.proration_behavior())
            .is_err()
    {
        return SubscriptionModifyDecision::denied(
            SubscriptionModifyDecisionCode::ProtectedFieldChanged,
            SubscriptionModifyDecisionStage::Scope,
            "pending-update or proration semantics differ",
        );
    }

    let mut interval = None;
    let mut before_recurring = 0_u64;
    let mut after_recurring = 0_u64;
    for (before, after) in action.before_items().iter().zip(action.after_items()) {
        if before.subscription_item_id() != after.subscription_item_id() {
            return SubscriptionModifyDecision::denied(
                SubscriptionModifyDecisionCode::ProtectedFieldChanged,
                SubscriptionModifyDecisionStage::Scope,
                "Subscription Item identity changed",
            );
        }
        for item in [before, after] {
            if policy
                .allowed_price_ids()
                .binary_search(item.price_id())
                .is_err()
                || policy
                    .allowed_product_ids()
                    .binary_search(item.product_id())
                    .is_err()
            {
                return SubscriptionModifyDecision::denied(
                    SubscriptionModifyDecisionCode::PriceDenied,
                    SubscriptionModifyDecisionStage::Scope,
                    "Price or Product is outside configured scope",
                );
            }
            if policy
                .maximum_quantity_by_price()
                .get(item.price_id())
                .is_none_or(|limit| item.quantity() > *limit)
            {
                return SubscriptionModifyDecision::denied(
                    SubscriptionModifyDecisionCode::QuantityExceeded,
                    SubscriptionModifyDecisionStage::Scope,
                    "quantity exceeds its Price ceiling",
                );
            }
            let Some(catalog) = evidence.catalog.iter().find(|catalog| {
                &catalog.price_id == item.price_id() && &catalog.product_id == item.product_id()
            }) else {
                return SubscriptionModifyDecision::denied(
                    SubscriptionModifyDecisionCode::PriceDenied,
                    SubscriptionModifyDecisionStage::Scope,
                    "exact catalog identity is absent",
                );
            };
            if !catalog.active
                || !catalog.licensed
                || catalog.interval_count != 1
                || &catalog.currency != action.currency()
                || policy
                    .allowed_intervals()
                    .binary_search(&catalog.interval)
                    .is_err()
            {
                return SubscriptionModifyDecision::denied(
                    SubscriptionModifyDecisionCode::PriceDenied,
                    SubscriptionModifyDecisionStage::Scope,
                    "catalog semantics are outside configured bounds",
                );
            }
            if interval
                .replace(catalog.interval)
                .is_some_and(|old| old != catalog.interval)
            {
                return SubscriptionModifyDecision::denied(
                    SubscriptionModifyDecisionCode::PriceDenied,
                    SubscriptionModifyDecisionStage::Scope,
                    "mixed recurring intervals are forbidden",
                );
            }
        }
        let Some(before_catalog) = evidence
            .catalog
            .iter()
            .find(|value| &value.price_id == before.price_id())
        else {
            return SubscriptionModifyDecision::denied(
                SubscriptionModifyDecisionCode::PriceDenied,
                SubscriptionModifyDecisionStage::Scope,
                "before Price disappeared from protected catalog evidence",
            );
        };
        let Some(after_catalog) = evidence
            .catalog
            .iter()
            .find(|value| &value.price_id == after.price_id())
        else {
            return SubscriptionModifyDecision::denied(
                SubscriptionModifyDecisionCode::PriceDenied,
                SubscriptionModifyDecisionStage::Scope,
                "after Price disappeared from protected catalog evidence",
            );
        };
        let Some(before_amount) = before_catalog
            .unit_amount_minor
            .checked_mul(u64::from(before.quantity()))
        else {
            return SubscriptionModifyDecision::denied(
                SubscriptionModifyDecisionCode::ArithmeticOverflow,
                SubscriptionModifyDecisionStage::Calculation,
                "before recurring arithmetic overflowed",
            );
        };
        let Some(after_amount) = after_catalog
            .unit_amount_minor
            .checked_mul(u64::from(after.quantity()))
        else {
            return SubscriptionModifyDecision::denied(
                SubscriptionModifyDecisionCode::ArithmeticOverflow,
                SubscriptionModifyDecisionStage::Calculation,
                "after recurring arithmetic overflowed",
            );
        };
        let Some(next_before) = before_recurring.checked_add(before_amount) else {
            return SubscriptionModifyDecision::denied(
                SubscriptionModifyDecisionCode::ArithmeticOverflow,
                SubscriptionModifyDecisionStage::Calculation,
                "before total overflowed",
            );
        };
        let Some(next_after) = after_recurring.checked_add(after_amount) else {
            return SubscriptionModifyDecision::denied(
                SubscriptionModifyDecisionCode::ArithmeticOverflow,
                SubscriptionModifyDecisionStage::Calculation,
                "after total overflowed",
            );
        };
        before_recurring = next_before;
        after_recurring = next_after;
    }
    let Some(interval) = interval else {
        return SubscriptionModifyDecision::denied(
            SubscriptionModifyDecisionCode::ActionInvalid,
            SubscriptionModifyDecisionStage::Calculation,
            "exact action has no recurring interval",
        );
    };

    let mut preview_debit = 0_u64;
    let mut preview_credit = 0_u64;
    for line in evidence.preview_lines.iter().filter(|line| line.proration) {
        if line.amount_minor >= 0 {
            let Some(next) = preview_debit.checked_add(line.amount_minor.unsigned_abs()) else {
                return SubscriptionModifyDecision::denied(
                    SubscriptionModifyDecisionCode::ArithmeticOverflow,
                    SubscriptionModifyDecisionStage::Calculation,
                    "preview debit overflowed",
                );
            };
            preview_debit = next;
        } else {
            let Some(next) = preview_credit.checked_add(line.amount_minor.unsigned_abs()) else {
                return SubscriptionModifyDecision::denied(
                    SubscriptionModifyDecisionCode::ArithmeticOverflow,
                    SubscriptionModifyDecisionStage::Calculation,
                    "preview credit overflowed",
                );
            };
            preview_credit = next;
        }
    }
    if action.invoice_preview_digest() != &evidence.preview_digest
        || action.proration_debit_minor() != evidence.proration_debit_minor
        || action.proration_credit_minor() != evidence.proration_credit_minor
        || preview_debit != evidence.proration_debit_minor
        || preview_credit != evidence.proration_credit_minor
        || before_recurring != evidence.before_recurring_minor
        || after_recurring != evidence.after_recurring_minor
        || before_recurring != action.before_recurring_minor()
        || after_recurring != action.after_recurring_minor()
        || action.remaining_cycle_count() != evidence.remaining_cycle_count
    {
        return SubscriptionModifyDecision::denied(
            SubscriptionModifyDecisionCode::PreviewMismatch,
            SubscriptionModifyDecisionStage::Calculation,
            "preview, debit, credit, recurring, or remaining-cycle commitment differs",
        );
    }
    if policy
        .proration_debit_limits()
        .get(action.currency())
        .is_none_or(|limit| preview_debit > *limit)
    {
        return SubscriptionModifyDecision::denied(
            SubscriptionModifyDecisionCode::ProrationLimitExceeded,
            SubscriptionModifyDecisionStage::Capacity,
            "independent proration debit exceeds its ceiling",
        );
    }
    if policy.recurring_limits().iter().all(|limit| {
        &limit.currency != action.currency()
            || limit.interval != interval
            || after_recurring > limit.limit_minor
    }) {
        return SubscriptionModifyDecision::denied(
            SubscriptionModifyDecisionCode::RecurringLimitExceeded,
            SubscriptionModifyDecisionStage::Capacity,
            "new recurring amount exceeds its ceiling",
        );
    }

    let Some(before_term) = before_recurring.checked_mul(u64::from(action.remaining_cycle_count()))
    else {
        return SubscriptionModifyDecision::denied(
            SubscriptionModifyDecisionCode::ArithmeticOverflow,
            SubscriptionModifyDecisionStage::Calculation,
            "before term liability overflowed",
        );
    };
    let Some(after_term) = after_recurring.checked_mul(u64::from(action.remaining_cycle_count()))
    else {
        return SubscriptionModifyDecision::denied(
            SubscriptionModifyDecisionCode::ArithmeticOverflow,
            SubscriptionModifyDecisionStage::Calculation,
            "after term liability overflowed",
        );
    };
    let (incremental, superseded) = term_liability_delta(before_term, after_term);
    if incremental != action.incremental_term_liability_minor() {
        return SubscriptionModifyDecision::denied(
            SubscriptionModifyDecisionCode::PreviewMismatch,
            SubscriptionModifyDecisionStage::Calculation,
            "incremental term liability differs",
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
            amount_minor: incremental,
            limit_minor: budget.limit_minor,
        })
        .collect::<Vec<_>>();
    let immediate_reservations = policy
        .aggregate_immediate_budgets()
        .iter()
        .filter(|budget| {
            budget.currency == *action.currency()
                && context.now >= budget.starts_at
                && context.now < budget.ends_at
        })
        .map(|budget| ImmediateLiabilityReservation {
            budget_id: budget.budget_id.clone(),
            currency: budget.currency.clone(),
            amount_minor: preview_debit,
            limit_minor: budget.limit_minor,
            starts_at: budget.starts_at,
            ends_at: budget.ends_at,
        })
        .collect::<Vec<_>>();
    if (incremental > 0 && recurring_reservations.is_empty())
        || (preview_debit > 0 && immediate_reservations.is_empty())
    {
        return SubscriptionModifyDecision::denied(
            SubscriptionModifyDecisionCode::ReservationUnavailable,
            SubscriptionModifyDecisionStage::Capacity,
            "positive liability lacks an aggregate reservation",
        );
    }

    SubscriptionModifyDecision {
        class: SubscriptionModifyDecisionClass::Eligible,
        code: SubscriptionModifyDecisionCode::Authorized,
        stable_code: SubscriptionModifyDecisionCode::Authorized
            .stable_code()
            .into(),
        stage: SubscriptionModifyDecisionStage::Complete,
        detail: "exact before/after transition is bounded independently of credits".into(),
        eligibility: Some(SubscriptionModifyEligibility {
            interval,
            before_recurring_minor: before_recurring,
            after_recurring_minor: after_recurring,
            before_term_liability_minor: before_term,
            after_term_liability_minor: after_term,
            incremental_term_liability_minor: incremental,
            superseded_term_liability_minor: superseded,
            proration_debit_minor: preview_debit,
            proration_credit_minor: preview_credit,
            recurring_reservations,
            immediate_reservations,
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;
    use crate::subscription::{StripeExactSubscriptionModifyV1, SubscriptionModifyEvidenceV1};

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/subscription-modify/v1")
    }

    fn fixture<T: serde::de::DeserializeOwned>(name: &str) -> T {
        serde_json::from_slice(&fs::read(root().join(name)).unwrap()).unwrap()
    }

    #[test]
    fn exact_debit_boundary_is_eligible_without_netting_credit() {
        let action: StripeExactSubscriptionModifyV1 = fixture("action.json");
        let policy: StripeBoundedSubscriptionPolicyV1 = fixture("policy.json");
        let evidence: SubscriptionModifyEvidenceV1 = fixture("evidence.json");
        let configuration: StripeSubscriptionConfigurationV1 = fixture("configuration.json");
        let decision = evaluate_subscription_modify(&SubscriptionModifyEvaluationContext {
            action: &action,
            policy: &policy,
            evidence: &evidence,
            required_configuration: &configuration,
            executed_configuration: &configuration,
            now: evidence.observed_at,
        });
        assert_eq!(decision.class, SubscriptionModifyDecisionClass::Eligible);
        let eligible = decision.eligibility.unwrap();
        assert_eq!(eligible.proration_debit_minor, 500);
        assert_eq!(eligible.proration_credit_minor, 250);
        assert_eq!(eligible.incremental_term_liability_minor, 1_000);
    }

    #[test]
    fn existing_pending_update_denies_before_reservation() {
        let action: StripeExactSubscriptionModifyV1 = fixture("action.json");
        let policy: StripeBoundedSubscriptionPolicyV1 = fixture("policy.json");
        let mut evidence: SubscriptionModifyEvidenceV1 = fixture("evidence.json");
        let configuration: StripeSubscriptionConfigurationV1 = fixture("configuration.json");
        evidence.pending_update_digest = Some(crate::canonical::sha256(b"pending-update"));
        let decision = evaluate_subscription_modify(&SubscriptionModifyEvaluationContext {
            action: &action,
            policy: &policy,
            evidence: &evidence,
            required_configuration: &configuration,
            executed_configuration: &configuration,
            now: evidence.observed_at,
        });
        assert_eq!(
            decision.code,
            SubscriptionModifyDecisionCode::PendingUpdateConflict
        );
        assert!(decision.eligibility.is_none());
    }

    #[test]
    fn quantity_boundary_plus_one_is_denied() {
        let mut action_json: serde_json::Value =
            serde_json::from_slice(&fs::read(root().join("action.json")).unwrap()).unwrap();
        action_json["after_items"][0]["quantity"] = serde_json::json!(3);
        let action: StripeExactSubscriptionModifyV1 = serde_json::from_value(action_json).unwrap();
        let policy: StripeBoundedSubscriptionPolicyV1 = fixture("policy.json");
        let evidence: SubscriptionModifyEvidenceV1 = fixture("evidence.json");
        let configuration: StripeSubscriptionConfigurationV1 = fixture("configuration.json");
        let decision = evaluate_subscription_modify(&SubscriptionModifyEvaluationContext {
            action: &action,
            policy: &policy,
            evidence: &evidence,
            required_configuration: &configuration,
            executed_configuration: &configuration,
            now: evidence.observed_at,
        });
        assert_eq!(
            decision.code,
            SubscriptionModifyDecisionCode::QuantityExceeded
        );
    }

    #[test]
    fn configuration_mismatch_precedes_provider_scope() {
        let action: StripeExactSubscriptionModifyV1 = fixture("action.json");
        let policy: StripeBoundedSubscriptionPolicyV1 = fixture("policy.json");
        let evidence: SubscriptionModifyEvidenceV1 = fixture("evidence.json");
        let configuration: StripeSubscriptionConfigurationV1 = fixture("configuration.json");
        let create_configuration: StripeSubscriptionConfigurationV1 = serde_json::from_slice(
            &fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("fixtures/subscription-create/v1/configuration.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let decision = evaluate_subscription_modify(&SubscriptionModifyEvaluationContext {
            action: &action,
            policy: &policy,
            evidence: &evidence,
            required_configuration: &configuration,
            executed_configuration: &create_configuration,
            now: evidence.observed_at,
        });
        assert_eq!(
            decision.stage,
            SubscriptionModifyDecisionStage::Configuration
        );
        assert!(decision.eligibility.is_none());
    }
}

#[cfg(kani)]
mod proofs {
    use super::term_liability_delta;

    #[kani::proof]
    fn credits_never_reduce_incremental_term_liability() {
        let before = kani::any::<u64>();
        let after = kani::any::<u64>();
        let (incremental, _) = term_liability_delta(before, after);

        // `term_liability_delta` takes no credit input at all, so no credit can
        // enter the reserved amount. The falsifiable content of that claim is
        // that `incremental` is exactly the un-netted upgrade amount: it is
        // positive whenever the term grows, and equals the full growth.
        if after > before {
            assert!(incremental > 0);
            assert_eq!(
                u128::from(incremental),
                u128::from(after) - u128::from(before)
            );
        } else {
            assert_eq!(incremental, 0);
        }
        // The reserved amount never exceeds the new term liability, so it can
        // never demand more capacity than the modification actually creates.
        assert!(incremental <= after);
    }

    #[kani::proof]
    fn downgrade_release_is_disjoint_from_upgrade_reservation() {
        let before = kani::any::<u64>();
        let after = kani::any::<u64>();
        let (reserve, release) = term_liability_delta(before, after);
        assert!(reserve == 0 || release == 0);
        // Conservation: the two sides reconstruct the original terms exactly,
        // so neither side can silently absorb liability.
        assert_eq!(
            u128::from(before) + u128::from(reserve),
            u128::from(after) + u128::from(release)
        );
    }
}
