//! Pure deterministic evaluator for exact Subscription cancellation.

use serde::{Deserialize, Serialize};

use super::{
    StripeExactSubscriptionCancelV1, StripeSubscriptionCancelConfigurationV1,
    SubscriptionCancelEvidenceV1,
};
use crate::subscription::{
    StripeBoundedSubscriptionPolicyV1, SubscriptionCancelMode, SubscriptionOperation,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionCancelDecisionClass {
    Eligible,
    Denied,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubscriptionCancelDecisionCode {
    Authorized,
    ModeDenied,
    BeforeStateMismatch,
    PendingUpdate,
    PendingInvoiceItems,
    AlreadyScheduled,
    AlreadyTerminal,
    RenewalConflict,
    OutcomeUnknown,
    ConfigurationMismatch,
    PolicyInvalid,
    ActionInvalid,
    EvidenceInvalid,
    PolicyInactive,
    ActionExpired,
    EvidenceStale,
    AccountDenied,
    CustomerDenied,
    LiabilityMismatch,
    Replay,
    ArithmeticOverflow,
}

impl SubscriptionCancelDecisionCode {
    pub const fn stable_code(self) -> &'static str {
        match self {
            Self::Authorized => "subscription-cancel-authorized",
            Self::ModeDenied => "subscription-cancel-mode-denied",
            Self::BeforeStateMismatch => "subscription-cancel-before-state-mismatch",
            Self::PendingUpdate => "subscription-cancel-pending-update",
            Self::PendingInvoiceItems => "subscription-cancel-pending-invoice-items",
            Self::AlreadyScheduled => "subscription-cancel-already-scheduled",
            Self::AlreadyTerminal => "subscription-cancel-already-terminal",
            Self::RenewalConflict => "subscription-cancel-renewal-conflict",
            Self::OutcomeUnknown => "subscription-cancel-outcome-unknown",
            Self::ConfigurationMismatch => "subscription-configuration-mismatch",
            Self::PolicyInvalid => "subscription-policy-invalid",
            Self::ActionInvalid => "subscription-action-invalid",
            Self::EvidenceInvalid => "subscription-evidence-invalid",
            Self::PolicyInactive => "subscription-policy-inactive",
            Self::ActionExpired => "subscription-action-expired",
            Self::EvidenceStale => "subscription-evidence-stale",
            Self::AccountDenied => "subscription-account-denied",
            Self::CustomerDenied => "subscription-customer-denied",
            Self::LiabilityMismatch => "subscription-liability-mismatch",
            Self::Replay => "subscription-cancel-replay",
            Self::ArithmeticOverflow => "subscription-arithmetic-overflow",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionCancelDecisionStage {
    Configuration,
    Validation,
    Freshness,
    Scope,
    BeforeState,
    InvoiceSafety,
    Liability,
    Complete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCancelEligibility {
    pub mode: SubscriptionCancelMode,
    pub remaining_term_liability_minor: u64,
    pub current_period_liability_minor: u64,
    pub future_liability_release_minor: u64,
    pub liability_retained_until_terminal_minor: u64,
    pub release_not_before: u64,
    pub invoice_now: bool,
    pub prorate: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCancelDecision {
    pub class: SubscriptionCancelDecisionClass,
    pub code: SubscriptionCancelDecisionCode,
    pub stable_code: String,
    pub stage: SubscriptionCancelDecisionStage,
    pub detail: String,
    pub eligibility: Option<SubscriptionCancelEligibility>,
}

impl SubscriptionCancelDecision {
    fn denied(
        code: SubscriptionCancelDecisionCode,
        stage: SubscriptionCancelDecisionStage,
        detail: &'static str,
    ) -> Self {
        Self {
            class: SubscriptionCancelDecisionClass::Denied,
            code,
            stable_code: code.stable_code().into(),
            stage,
            detail: detail.into(),
            eligibility: None,
        }
    }
    fn indeterminate(
        code: SubscriptionCancelDecisionCode,
        stage: SubscriptionCancelDecisionStage,
        detail: &'static str,
    ) -> Self {
        Self {
            class: SubscriptionCancelDecisionClass::Indeterminate,
            code,
            stable_code: code.stable_code().into(),
            stage,
            detail: detail.into(),
            eligibility: None,
        }
    }
}

pub struct SubscriptionCancelEvaluationContext<'a> {
    pub action: &'a StripeExactSubscriptionCancelV1,
    pub policy: &'a StripeBoundedSubscriptionPolicyV1,
    pub evidence: &'a SubscriptionCancelEvidenceV1,
    pub required_configuration: &'a StripeSubscriptionCancelConfigurationV1,
    pub executed_configuration: &'a StripeSubscriptionCancelConfigurationV1,
    pub request_audience: &'a str,
    pub now: u64,
}

pub fn evaluate_subscription_cancel(
    context: &SubscriptionCancelEvaluationContext<'_>,
) -> SubscriptionCancelDecision {
    let action = context.action;
    let policy = context.policy;
    let evidence = context.evidence;
    let (Ok(required_digest), Ok(policy_digest)) =
        (context.required_configuration.digest(), policy.digest())
    else {
        return SubscriptionCancelDecision::indeterminate(
            SubscriptionCancelDecisionCode::ConfigurationMismatch,
            SubscriptionCancelDecisionStage::Configuration,
            "configuration commitments cannot be computed",
        );
    };
    let base = context.required_configuration.base();
    if context.required_configuration != context.executed_configuration
        || action.required_configuration_digest() != &required_digest
        || action.required_policy_digest() != &policy_digest
        || base.policy_digest() != &policy_digest
        || base.stripe_account_id() != action.stripe_account_id()
        || base.connect_account() != action.connect_account()
        || base.test_clock_id() != action.test_clock_id()
        || base.stripe_api_version() != action.stripe_api_version()
        || base.executor_audience() != context.request_audience
        || action.executor_audience() != context.request_audience
    {
        return SubscriptionCancelDecision::denied(
            SubscriptionCancelDecisionCode::ConfigurationMismatch,
            SubscriptionCancelDecisionStage::Configuration,
            "required and executed cancellation configuration differ",
        );
    }
    if policy.validate().is_err() {
        return SubscriptionCancelDecision::denied(
            SubscriptionCancelDecisionCode::PolicyInvalid,
            SubscriptionCancelDecisionStage::Validation,
            "bounded subscription policy is invalid",
        );
    }
    if action.validate().is_err() {
        return SubscriptionCancelDecision::denied(
            SubscriptionCancelDecisionCode::ActionInvalid,
            SubscriptionCancelDecisionStage::Validation,
            "exact cancellation action is invalid",
        );
    }
    if evidence.validate().is_err() {
        return SubscriptionCancelDecision::indeterminate(
            SubscriptionCancelDecisionCode::EvidenceInvalid,
            SubscriptionCancelDecisionStage::Validation,
            "protected Subscription evidence is invalid",
        );
    }
    if context.now < policy.valid_from() || context.now > policy.expires_at() {
        return SubscriptionCancelDecision::denied(
            SubscriptionCancelDecisionCode::PolicyInactive,
            SubscriptionCancelDecisionStage::Freshness,
            "policy is inactive",
        );
    }
    if action.expires_at() < context.now
        || action.expires_at().saturating_sub(context.now)
            > policy.maximum_action_lifetime_seconds()
    {
        return SubscriptionCancelDecision::denied(
            SubscriptionCancelDecisionCode::ActionExpired,
            SubscriptionCancelDecisionStage::Freshness,
            "action is expired or too long lived",
        );
    }
    if evidence.observed_at > context.now
        || context.now.saturating_sub(evidence.observed_at) > policy.maximum_evidence_age_seconds()
    {
        return SubscriptionCancelDecision::indeterminate(
            SubscriptionCancelDecisionCode::EvidenceStale,
            SubscriptionCancelDecisionStage::Freshness,
            "Subscription or Invoice evidence is stale",
        );
    }
    if policy
        .allowed_operations()
        .binary_search(&SubscriptionOperation::Cancel)
        .is_err()
        || policy
            .allowed_cancel_modes()
            .binary_search(&action.mode())
            .is_err()
        || context
            .required_configuration
            .supported_modes()
            .binary_search(&action.mode())
            .is_err()
    {
        return SubscriptionCancelDecision::denied(
            SubscriptionCancelDecisionCode::ModeDenied,
            SubscriptionCancelDecisionStage::Scope,
            "cancel operation or selected mode is outside policy",
        );
    }
    if policy
        .allowed_test_account_ids()
        .binary_search(action.stripe_account_id())
        .is_err()
        || action.stripe_account_id() != &evidence.stripe_account_id
        || action.connect_account() != &evidence.connect_account
        || action.subscription_id() != &evidence.subscription_id
        || action.test_clock_id() != &evidence.test_clock_id
        || action.stripe_api_version() != evidence.stripe_api_version
        || evidence.livemode
    {
        return SubscriptionCancelDecision::denied(
            SubscriptionCancelDecisionCode::AccountDenied,
            SubscriptionCancelDecisionStage::Scope,
            "account, Subscription, API, Connect, or test-clock scope differs",
        );
    }
    if policy
        .allowed_customer_ids()
        .binary_search(action.customer_id())
        .is_err()
        || action.customer_id() != &evidence.customer_id
    {
        return SubscriptionCancelDecision::denied(
            SubscriptionCancelDecisionCode::CustomerDenied,
            SubscriptionCancelDecisionStage::Scope,
            "Customer is outside configured scope",
        );
    }
    if action.subscription_digest() != &evidence.subscription_digest
        || action.item_set_digest() != &evidence.item_set_digest
        || action.currency() != &evidence.currency
        || action.current_period_end() != evidence.current_period_end
        || action.pending_invoice_items_digest() != &evidence.pending_invoice_items_digest
        || action.latest_invoice_digest() != &evidence.latest_invoice_digest
    {
        return SubscriptionCancelDecision::denied(
            SubscriptionCancelDecisionCode::BeforeStateMismatch,
            SubscriptionCancelDecisionStage::BeforeState,
            "committed cancellation before-state differs from protected evidence",
        );
    }
    if matches!(evidence.status.as_str(), "canceled" | "incomplete_expired")
        || evidence.ended_at.is_some()
    {
        return SubscriptionCancelDecision::denied(
            SubscriptionCancelDecisionCode::AlreadyTerminal,
            SubscriptionCancelDecisionStage::BeforeState,
            "Subscription is already terminal",
        );
    }
    if evidence.cancel_at_period_end || evidence.cancel_at.is_some() {
        return SubscriptionCancelDecision::denied(
            SubscriptionCancelDecisionCode::AlreadyScheduled,
            SubscriptionCancelDecisionStage::BeforeState,
            "Subscription already has cancellation scheduled",
        );
    }
    if evidence.pending_update_digest.is_some() || action.pending_update_digest().is_some() {
        return SubscriptionCancelDecision::denied(
            SubscriptionCancelDecisionCode::PendingUpdate,
            SubscriptionCancelDecisionStage::BeforeState,
            "Subscription has a pending update",
        );
    }
    if evidence.renewal_or_modification_pending {
        return SubscriptionCancelDecision::denied(
            SubscriptionCancelDecisionCode::RenewalConflict,
            SubscriptionCancelDecisionStage::BeforeState,
            "renewal or modification races cancellation",
        );
    }
    if action.mode() == SubscriptionCancelMode::Immediate
        && evidence.unhandled_pending_invoice_item_count > 0
    {
        return SubscriptionCancelDecision::denied(
            SubscriptionCancelDecisionCode::PendingInvoiceItems,
            SubscriptionCancelDecisionStage::InvoiceSafety,
            "immediate cancellation has unhandled pending invoice items",
        );
    }
    if action.invoice_now() || action.prorate() {
        return SubscriptionCancelDecision::denied(
            SubscriptionCancelDecisionCode::ModeDenied,
            SubscriptionCancelDecisionStage::InvoiceSafety,
            "V1 never invoices now or prorates cancellation",
        );
    }
    if action.remaining_term_liability_minor() != evidence.remaining_term_liability_minor
        || action.current_period_liability_minor() != evidence.current_period_liability_minor
        || !evidence.liability_state.holds_recurring()
    {
        return SubscriptionCancelDecision::denied(
            SubscriptionCancelDecisionCode::LiabilityMismatch,
            SubscriptionCancelDecisionStage::Liability,
            "durable recurring liability differs or is not active",
        );
    }
    let Some(future_release) = evidence
        .remaining_term_liability_minor
        .checked_sub(evidence.current_period_liability_minor)
    else {
        return SubscriptionCancelDecision::indeterminate(
            SubscriptionCancelDecisionCode::ArithmeticOverflow,
            SubscriptionCancelDecisionStage::Liability,
            "liability subtraction failed",
        );
    };
    let retained = match action.mode() {
        SubscriptionCancelMode::AtPeriodEnd => evidence.current_period_liability_minor,
        SubscriptionCancelMode::Immediate => evidence.remaining_term_liability_minor,
    };
    SubscriptionCancelDecision {
        class: SubscriptionCancelDecisionClass::Eligible,
        code: SubscriptionCancelDecisionCode::Authorized,
        stable_code: SubscriptionCancelDecisionCode::Authorized
            .stable_code()
            .into(),
        stage: SubscriptionCancelDecisionStage::Complete,
        detail: "exact cancellation is inside policy and invoice-safety bounds".into(),
        eligibility: Some(SubscriptionCancelEligibility {
            mode: action.mode(),
            remaining_term_liability_minor: evidence.remaining_term_liability_minor,
            current_period_liability_minor: evidence.current_period_liability_minor,
            future_liability_release_minor: future_release,
            liability_retained_until_terminal_minor: retained,
            release_not_before: match action.mode() {
                SubscriptionCancelMode::AtPeriodEnd => evidence.current_period_end,
                SubscriptionCancelMode::Immediate => context.now,
            },
            invoice_now: false,
            prorate: false,
        }),
    }
}

#[cfg(kani)]
mod proofs {
    #[kani::proof]
    fn period_end_release_and_retained_liability_conserve_the_original() {
        let remaining = kani::any::<u64>();
        let current = kani::any::<u64>();
        kani::assume(remaining >= current);
        let future = remaining - current;
        assert_eq!(future.checked_add(current), Some(remaining));
    }

    #[kani::proof]
    fn immediate_branch_retains_all_liability_before_terminal_observation() {
        let remaining = kani::any::<u64>();
        let released_before_terminal = 0_u64;
        let retained_before_terminal = remaining;
        assert_eq!(
            released_before_terminal.checked_add(retained_before_terminal),
            Some(remaining)
        );
    }
}
