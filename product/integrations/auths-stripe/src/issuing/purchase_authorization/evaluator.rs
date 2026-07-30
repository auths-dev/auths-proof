//! Pure reference evaluator for latency-bounded Issuing decisions.

#![allow(
    clippy::must_use_candidate,
    reason = "stable decision-code conversion is intentionally lightweight"
)]

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use super::StripeExactPurchaseAuthorizationV1;
use crate::{
    issuing::{
        AgentProcurementIntentV1, PurchaseAggregateSnapshot, PurchaseReservationIntent,
        PurchaseWebhookEvidenceV1, StripeBoundedPurchasePolicyV1, StripePurchaseConfigurationV1,
    },
    types::DigestHex,
};

/// Stable three-way purchase decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PurchaseAuthorizationDecisionClass {
    Eligible,
    Denied,
    Indeterminate,
}

/// Stable evaluation stage.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PurchaseAuthorizationDecisionStage {
    Configuration,
    Policy,
    ExactAction,
    Webhook,
    Intent,
    Merchant,
    Limits,
    AggregateBudget,
    Deadline,
    Complete,
}

/// Stable purchase decision codes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PurchaseAuthorizationDecisionCode {
    PurchaseAuthorized,
    PurchaseDeclined,
    PurchaseIntentMismatch,
    PurchaseMerchantDenied,
    PurchaseCategoryDenied,
    PurchaseCountryDenied,
    PurchaseCurrencyDenied,
    PurchaseAmountExceeded,
    PurchaseAggregateBudgetExceeded,
    PurchaseRecurringDenied,
    PurchaseCashDenied,
    PurchaseDecisionTimeout,
    PurchaseOutcomeUnknown,
    PurchaseObservationOutsidePolicy,
    PurchaseConfigurationMismatch,
    PurchaseEvidenceInvalid,
    PurchaseEvidenceStale,
    PurchaseEventReplay,
}

impl PurchaseAuthorizationDecisionCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PurchaseAuthorized => "purchase-authorized",
            Self::PurchaseDeclined => "purchase-declined",
            Self::PurchaseIntentMismatch => "purchase-intent-mismatch",
            Self::PurchaseMerchantDenied => "purchase-merchant-denied",
            Self::PurchaseCategoryDenied => "purchase-category-denied",
            Self::PurchaseCountryDenied => "purchase-country-denied",
            Self::PurchaseCurrencyDenied => "purchase-currency-denied",
            Self::PurchaseAmountExceeded => "purchase-amount-exceeded",
            Self::PurchaseAggregateBudgetExceeded => "purchase-aggregate-budget-exceeded",
            Self::PurchaseRecurringDenied => "purchase-recurring-denied",
            Self::PurchaseCashDenied => "purchase-cash-denied",
            Self::PurchaseDecisionTimeout => "purchase-decision-timeout",
            Self::PurchaseOutcomeUnknown => "purchase-outcome-unknown",
            Self::PurchaseObservationOutsidePolicy => "purchase-observation-outside-policy",
            Self::PurchaseConfigurationMismatch => "purchase-configuration-mismatch",
            Self::PurchaseEvidenceInvalid => "purchase-evidence-invalid",
            Self::PurchaseEvidenceStale => "purchase-evidence-stale",
            Self::PurchaseEventReplay => "purchase-event-replay",
        }
    }
}

/// Successful exact bounded calculations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PurchaseAuthorizationEligibility {
    pub per_purchase_limit_minor: u64,
    pub per_merchant_limit_minor: u64,
    pub per_category_limit_minor: u64,
    pub reservations: Vec<PurchaseReservationIntent>,
}

/// Pure reference outcome.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PurchaseAuthorizationDecision {
    pub class: PurchaseAuthorizationDecisionClass,
    pub code: PurchaseAuthorizationDecisionCode,
    pub stage: PurchaseAuthorizationDecisionStage,
    pub detail: String,
    pub eligibility: Option<PurchaseAuthorizationEligibility>,
}

impl PurchaseAuthorizationDecision {
    fn denied(
        code: PurchaseAuthorizationDecisionCode,
        stage: PurchaseAuthorizationDecisionStage,
        detail: &'static str,
    ) -> Self {
        Self {
            class: PurchaseAuthorizationDecisionClass::Denied,
            code,
            stage,
            detail: detail.into(),
            eligibility: None,
        }
    }
}

/// Explicit complete inputs for the pure evaluator.
pub struct PurchaseAuthorizationEvaluationContext<'a> {
    pub policy: &'a StripeBoundedPurchasePolicyV1,
    pub action: &'a StripeExactPurchaseAuthorizationV1,
    pub webhook: &'a PurchaseWebhookEvidenceV1,
    pub intent: Option<&'a AgentProcurementIntentV1>,
    pub aggregate: &'a PurchaseAggregateSnapshot,
    pub required_configuration: &'a StripePurchaseConfigurationV1,
    pub executed_configuration: &'a StripePurchaseConfigurationV1,
    pub request_audience: &'a str,
    pub now: u64,
    pub elapsed_milliseconds: u64,
}

fn digest_eq(left: &DigestHex, right: &DigestHex) -> bool {
    left.as_str()
        .as_bytes()
        .ct_eq(right.as_str().as_bytes())
        .into()
}

/// Evaluates one exact purchase with deny precedence and checked capacity.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "security check precedence remains linear and auditable"
)]
pub fn evaluate_purchase_authorization(
    context: &PurchaseAuthorizationEvaluationContext<'_>,
) -> PurchaseAuthorizationDecision {
    if context.required_configuration != context.executed_configuration {
        return PurchaseAuthorizationDecision::denied(
            PurchaseAuthorizationDecisionCode::PurchaseConfigurationMismatch,
            PurchaseAuthorizationDecisionStage::Configuration,
            "required and executed Issuing configurations differ",
        );
    }
    if context.policy.validate().is_err()
        || context.action.validate().is_err()
        || context.required_configuration.validate().is_err()
    {
        return PurchaseAuthorizationDecision::denied(
            PurchaseAuthorizationDecisionCode::PurchaseDeclined,
            PurchaseAuthorizationDecisionStage::Policy,
            "policy, action, or configuration is malformed",
        );
    }
    let (Ok(policy_digest), Ok(configuration_digest)) = (
        context.policy.digest(),
        context.required_configuration.digest(),
    ) else {
        return PurchaseAuthorizationDecision::denied(
            PurchaseAuthorizationDecisionCode::PurchaseDeclined,
            PurchaseAuthorizationDecisionStage::Configuration,
            "configuration commitments cannot be computed",
        );
    };
    if !digest_eq(context.action.required_policy_digest(), &policy_digest)
        || !digest_eq(
            context.action.required_configuration_digest(),
            &configuration_digest,
        )
        || context.required_configuration.policy_digest() != &policy_digest
        || context.required_configuration.stripe_account_id() != context.action.stripe_account_id()
        || context.required_configuration.stripe_api_version()
            != context.action.stripe_api_version()
        || context.required_configuration.executor_audience() != context.request_audience
        || context.action.executor_audience() != context.request_audience
    {
        return PurchaseAuthorizationDecision::denied(
            PurchaseAuthorizationDecisionCode::PurchaseConfigurationMismatch,
            PurchaseAuthorizationDecisionStage::Configuration,
            "a required protected configuration commitment differs",
        );
    }
    if context.elapsed_milliseconds
        >= context
            .required_configuration
            .decision_deadline_milliseconds()
    {
        return PurchaseAuthorizationDecision::denied(
            PurchaseAuthorizationDecisionCode::PurchaseDecisionTimeout,
            PurchaseAuthorizationDecisionStage::Deadline,
            "decision deadline elapsed; configured fallback is decline",
        );
    }
    if context.policy.valid_from() > context.now || context.now > context.policy.expires_at() {
        return PurchaseAuthorizationDecision::denied(
            PurchaseAuthorizationDecisionCode::PurchaseDeclined,
            PurchaseAuthorizationDecisionStage::Policy,
            "configured purchase policy is inactive",
        );
    }
    if context.webhook.validate().is_err()
        || context.webhook.event_id != *context.action.event_id()
        || context.webhook.payload_digest != *context.action.webhook_payload_digest()
        || context.webhook.account_id != *context.action.stripe_account_id()
        || context.webhook.api_version != context.action.stripe_api_version()
    {
        return PurchaseAuthorizationDecision::denied(
            PurchaseAuthorizationDecisionCode::PurchaseEvidenceInvalid,
            PurchaseAuthorizationDecisionStage::Webhook,
            "signed webhook evidence does not bind the exact action",
        );
    }
    if context.webhook.signature_timestamp > context.now
        || context
            .now
            .saturating_sub(context.webhook.signature_timestamp)
            > context.policy.maximum_event_age_seconds()
        || context.webhook.received_at != context.action.received_at()
    {
        return PurchaseAuthorizationDecision::denied(
            PurchaseAuthorizationDecisionCode::PurchaseEvidenceStale,
            PurchaseAuthorizationDecisionStage::Webhook,
            "signed event is stale or from the future",
        );
    }
    if context
        .policy
        .allowed_accounts()
        .binary_search(context.action.stripe_account_id())
        .is_err()
        || context
            .policy
            .allowed_cardholders()
            .binary_search(context.action.cardholder_id())
            .is_err()
        || context
            .policy
            .allowed_cards()
            .binary_search(context.action.card_id())
            .is_err()
        || context
            .policy
            .allowed_methods()
            .binary_search(&context.action.authorization_method())
            .is_err()
    {
        return PurchaseAuthorizationDecision::denied(
            PurchaseAuthorizationDecisionCode::PurchaseDeclined,
            PurchaseAuthorizationDecisionStage::ExactAction,
            "account, cardholder, card, or method is denied",
        );
    }
    let Some(intent) = context.intent else {
        return PurchaseAuthorizationDecision::denied(
            PurchaseAuthorizationDecisionCode::PurchaseIntentMismatch,
            PurchaseAuthorizationDecisionStage::Intent,
            "a matching procurement intent is required",
        );
    };
    let Ok(intent_digest) = intent.digest() else {
        return PurchaseAuthorizationDecision::denied(
            PurchaseAuthorizationDecisionCode::PurchaseIntentMismatch,
            PurchaseAuthorizationDecisionStage::Intent,
            "procurement intent cannot be committed",
        );
    };
    if intent.validate().is_err()
        || context.action.procurement_intent_digest() != Some(&intent_digest)
        || intent.procurement_scope != context.action.procurement_scope()
        || intent.expected_merchant_id != context.action.merchant_id()
        || intent.currency != *context.action.currency()
        || intent.maximum_amount_minor < context.action.amount_minor()
        || intent.recurring
        || intent.valid_from > context.now
        || context.now > intent.expires_at
        || context.now.saturating_sub(intent.valid_from)
            > context.policy.maximum_intent_age_seconds()
        || context
            .policy
            .allowed_scopes()
            .binary_search(&intent.procurement_scope)
            .is_err()
    {
        return PurchaseAuthorizationDecision::denied(
            PurchaseAuthorizationDecisionCode::PurchaseIntentMismatch,
            PurchaseAuthorizationDecisionStage::Intent,
            "procurement intent is absent, expired, or not exact",
        );
    }
    if context
        .policy
        .blocked_categories()
        .binary_search(&context.action.merchant_category().to_owned())
        .is_ok()
        || context
            .policy
            .allowed_categories()
            .binary_search(&context.action.merchant_category().to_owned())
            .is_err()
    {
        return PurchaseAuthorizationDecision::denied(
            PurchaseAuthorizationDecisionCode::PurchaseCategoryDenied,
            PurchaseAuthorizationDecisionStage::Merchant,
            "merchant category is blocked or absent from the allow set",
        );
    }
    if context
        .policy
        .blocked_countries()
        .binary_search(&context.action.merchant_country().to_owned())
        .is_ok()
        || context
            .policy
            .allowed_countries()
            .binary_search(&context.action.merchant_country().to_owned())
            .is_err()
    {
        return PurchaseAuthorizationDecision::denied(
            PurchaseAuthorizationDecisionCode::PurchaseCountryDenied,
            PurchaseAuthorizationDecisionStage::Merchant,
            "merchant country is blocked or absent from the allow set",
        );
    }
    if context
        .policy
        .allowed_merchants()
        .binary_search(&context.action.merchant_id().to_owned())
        .is_err()
        || context
            .policy
            .allowed_merchant_names()
            .binary_search(context.action.merchant_name_commitment())
            .is_err()
    {
        return PurchaseAuthorizationDecision::denied(
            PurchaseAuthorizationDecisionCode::PurchaseMerchantDenied,
            PurchaseAuthorizationDecisionStage::Merchant,
            "merchant identity is outside configured scope",
        );
    }
    if context
        .policy
        .allowed_currencies()
        .binary_search(context.action.currency())
        .is_err()
        || context.action.currency() != context.action.merchant_currency()
        || context.action.amount_minor() != context.action.merchant_amount_minor()
    {
        return PurchaseAuthorizationDecision::denied(
            PurchaseAuthorizationDecisionCode::PurchaseCurrencyDenied,
            PurchaseAuthorizationDecisionStage::Limits,
            "currency or exact no-FX amount differs",
        );
    }
    let limits = [
        context
            .policy
            .purchase_limits()
            .get(context.action.currency()),
        context
            .policy
            .merchant_limits()
            .get(context.action.currency()),
        context
            .policy
            .category_limits()
            .get(context.action.currency()),
    ];
    let [Some(per_purchase), Some(per_merchant), Some(per_category)] = limits else {
        return PurchaseAuthorizationDecision::denied(
            PurchaseAuthorizationDecisionCode::PurchaseCurrencyDenied,
            PurchaseAuthorizationDecisionStage::Limits,
            "currency limits are incomplete",
        );
    };
    if [*per_purchase, *per_merchant, *per_category]
        .into_iter()
        .any(|limit| context.action.amount_minor() > limit)
    {
        return PurchaseAuthorizationDecision::denied(
            PurchaseAuthorizationDecisionCode::PurchaseAmountExceeded,
            PurchaseAuthorizationDecisionStage::Limits,
            "exact full amount exceeds an inclusive policy ceiling",
        );
    }
    let mut reservations = Vec::new();
    for budget in context.policy.aggregate_budgets() {
        if context.now < budget.starts_at || context.now > budget.ends_at {
            continue;
        }
        let applies = match &budget.scope {
            crate::issuing::PurchaseBudgetScope::Global => true,
            crate::issuing::PurchaseBudgetScope::Merchant(value) => {
                value == context.action.merchant_id()
            }
            crate::issuing::PurchaseBudgetScope::Category(value) => {
                value == context.action.merchant_category()
            }
        };
        if applies && budget.currency == *context.action.currency() {
            let held = context
                .aggregate
                .held_minor_by_budget
                .get(&budget.budget_id)
                .copied()
                .unwrap_or_default();
            let Some(after) = held.checked_add(context.action.amount_minor()) else {
                return PurchaseAuthorizationDecision::denied(
                    PurchaseAuthorizationDecisionCode::PurchaseAmountExceeded,
                    PurchaseAuthorizationDecisionStage::AggregateBudget,
                    "checked aggregate arithmetic overflowed",
                );
            };
            if after > budget.limit_minor {
                return PurchaseAuthorizationDecision::denied(
                    PurchaseAuthorizationDecisionCode::PurchaseAggregateBudgetExceeded,
                    PurchaseAuthorizationDecisionStage::AggregateBudget,
                    "aggregate purchase capacity is exhausted",
                );
            }
            reservations.push(PurchaseReservationIntent {
                budget_id: budget.budget_id.clone(),
                currency: budget.currency.clone(),
                amount_minor: context.action.amount_minor(),
                limit_minor: budget.limit_minor,
            });
        }
    }
    if reservations.is_empty() {
        return PurchaseAuthorizationDecision::denied(
            PurchaseAuthorizationDecisionCode::PurchaseAggregateBudgetExceeded,
            PurchaseAuthorizationDecisionStage::AggregateBudget,
            "no active aggregate budget covers the exact purchase",
        );
    }
    PurchaseAuthorizationDecision {
        class: PurchaseAuthorizationDecisionClass::Eligible,
        code: PurchaseAuthorizationDecisionCode::PurchaseAuthorized,
        stage: PurchaseAuthorizationDecisionStage::Complete,
        detail: "exact signed purchase is inside all configured bounds".into(),
        eligibility: Some(PurchaseAuthorizationEligibility {
            per_purchase_limit_minor: *per_purchase,
            per_merchant_limit_minor: *per_merchant,
            per_category_limit_minor: *per_category,
            reservations,
        }),
    }
}

#[cfg(kani)]
mod proofs {
    #[kani::proof]
    fn checked_budget_never_wraps() {
        let held: u64 = kani::any();
        let amount: u64 = kani::any();
        if let Some(after) = held.checked_add(amount) {
            assert!(after >= held);
            assert!(after >= amount);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{
        canonical::sha256,
        issuing::{
            AggregatePurchaseBudget, PurchaseAuthorizationMethod, PurchaseBudgetScope,
            StripeBoundedPurchasePolicyInput,
        },
        types::{
            Currency, EventId, IssuingAuthorizationId, IssuingCardId, IssuingCardholderId,
            StripeAccountId,
        },
    };

    struct Fixture {
        policy: StripeBoundedPurchasePolicyV1,
        configuration: StripePurchaseConfigurationV1,
        intent: AgentProcurementIntentV1,
        action: StripeExactPurchaseAuthorizationV1,
        webhook: PurchaseWebhookEvidenceV1,
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture keeps all protected inputs visible"
    )]
    fn fixture(
        amount_minor: u64,
        limit_minor: u64,
        merchant_id: &str,
        allowed_merchants: Vec<String>,
        blocked_categories: Vec<String>,
        blocked_countries: Vec<String>,
    ) -> Fixture {
        let account = StripeAccountId::parse("acct_purchasefixture").unwrap();
        let currency = Currency::parse("usd").unwrap();
        let policy = StripeBoundedPurchasePolicyV1::new(StripeBoundedPurchasePolicyInput {
            policy_id: "purchase-policy".into(),
            valid_from: 100,
            expires_at: 1_000,
            allowed_test_account_ids: vec![account.clone()],
            allowed_cardholder_ids: vec![
                IssuingCardholderId::parse("ich_purchasefixture").unwrap(),
            ],
            allowed_card_ids: vec![IssuingCardId::parse("ic_purchasefixture").unwrap()],
            allowed_currencies: vec![currency.clone()],
            allowed_merchant_ids: allowed_merchants,
            allowed_merchant_name_commitments: vec![sha256(b"Auths API")],
            allowed_merchant_categories: vec!["computer_software_stores".into()],
            blocked_merchant_categories: blocked_categories,
            allowed_merchant_countries: vec!["US".into()],
            blocked_merchant_countries: blocked_countries,
            allowed_procurement_scopes: vec!["api-access".into()],
            allowed_authorization_methods: vec![PurchaseAuthorizationMethod::Online],
            per_purchase_minor_by_currency: BTreeMap::from([(currency.clone(), limit_minor)]),
            per_merchant_minor_by_currency: BTreeMap::from([(currency.clone(), limit_minor)]),
            per_category_minor_by_currency: BTreeMap::from([(currency.clone(), limit_minor)]),
            aggregate_budgets: vec![AggregatePurchaseBudget {
                budget_id: "global".into(),
                scope: PurchaseBudgetScope::Global,
                currency: currency.clone(),
                limit_minor,
                starts_at: 100,
                ends_at: 1_000,
            }],
            maximum_intent_age_seconds: 300,
            maximum_event_age_seconds: 60,
            decision_deadline_milliseconds: 1_000,
            allowed_api_versions: vec!["2025-04-30.basil".into()],
        })
        .unwrap();
        let configuration = StripePurchaseConfigurationV1::new(
            &policy,
            account.clone(),
            "2025-04-30.basil".into(),
            "https://issuer.example".into(),
        )
        .unwrap();
        let intent = AgentProcurementIntentV1 {
            schema: "auths.stripe.agent-procurement-intent/1".into(),
            intent_id: "intent-fixture".into(),
            agent_identity: "agent-auths".into(),
            procurement_scope: "api-access".into(),
            expected_merchant_id: merchant_id.into(),
            maximum_amount_minor: amount_minor,
            currency: currency.clone(),
            recurring: false,
            fulfillment_reference_commitment: sha256(b"order-42"),
            valid_from: 450,
            expires_at: 600,
            nonce: sha256(b"nonce-42"),
        };
        let payload_digest = sha256(b"signed-stripe-payload");
        let action = StripeExactPurchaseAuthorizationV1::new(
            crate::issuing::StripeExactPurchaseAuthorizationInput {
                stripe_account_id: account.clone(),
                event_id: EventId::parse("evt_purchasefixture").unwrap(),
                issuing_authorization_id: IssuingAuthorizationId::parse("iauth_purchasefixture")
                    .unwrap(),
                cardholder_id: IssuingCardholderId::parse("ich_purchasefixture").unwrap(),
                card_id: IssuingCardId::parse("ic_purchasefixture").unwrap(),
                amount_minor,
                currency: currency.clone(),
                merchant_amount_minor: amount_minor,
                merchant_currency: currency,
                merchant_id: merchant_id.into(),
                merchant_name_commitment: sha256(b"Auths API"),
                merchant_category: "computer_software_stores".into(),
                merchant_country: "US".into(),
                authorization_method: PurchaseAuthorizationMethod::Online,
                procurement_scope: "api-access".into(),
                procurement_intent_digest: Some(intent.digest().unwrap()),
                stripe_api_version: "2025-04-30.basil".into(),
                webhook_payload_digest: payload_digest.clone(),
                required_policy_digest: policy.digest().unwrap(),
                required_configuration_digest: configuration.digest().unwrap(),
                executor_audience: "https://issuer.example".into(),
                received_at: 500,
            },
        )
        .unwrap();
        let webhook = PurchaseWebhookEvidenceV1 {
            schema: "auths.stripe.issuing-webhook-evidence/1".into(),
            event_id: action.event_id().clone(),
            event_type: "issuing_authorization.request".into(),
            payload_digest,
            signature_header_digest: sha256(b"t=500,v1=redacted"),
            signature_timestamp: 500,
            signature_verified: true,
            account_id: account,
            api_version: "2025-04-30.basil".into(),
            livemode: false,
            received_at: 500,
        };
        Fixture {
            policy,
            configuration,
            intent,
            action,
            webhook,
        }
    }

    fn evaluate(value: &Fixture, elapsed_milliseconds: u64) -> PurchaseAuthorizationDecision {
        evaluate_purchase_authorization(&PurchaseAuthorizationEvaluationContext {
            policy: &value.policy,
            action: &value.action,
            webhook: &value.webhook,
            intent: Some(&value.intent),
            aggregate: &PurchaseAggregateSnapshot::default(),
            required_configuration: &value.configuration,
            executed_configuration: &value.configuration,
            request_audience: "https://issuer.example",
            now: 500,
            elapsed_milliseconds,
        })
    }

    #[test]
    fn exact_limit_is_inclusive_and_one_over_is_denied() {
        let exact = fixture(
            1_000,
            1_000,
            "merchant-auths",
            vec!["merchant-auths".into()],
            vec![],
            vec![],
        );
        assert_eq!(
            evaluate(&exact, 10).code,
            PurchaseAuthorizationDecisionCode::PurchaseAuthorized
        );
        let over = fixture(
            1_001,
            1_000,
            "merchant-auths",
            vec!["merchant-auths".into()],
            vec![],
            vec![],
        );
        assert_eq!(
            evaluate(&over, 10).code,
            PurchaseAuthorizationDecisionCode::PurchaseAmountExceeded
        );
    }

    #[test]
    fn deny_sets_take_precedence_over_allow_sets() {
        let category = fixture(
            500,
            1_000,
            "merchant-auths",
            vec!["merchant-auths".into()],
            vec!["computer_software_stores".into()],
            vec![],
        );
        assert_eq!(
            evaluate(&category, 10).code,
            PurchaseAuthorizationDecisionCode::PurchaseCategoryDenied
        );
        let country = fixture(
            500,
            1_000,
            "merchant-auths",
            vec!["merchant-auths".into()],
            vec![],
            vec!["US".into()],
        );
        assert_eq!(
            evaluate(&country, 10).code,
            PurchaseAuthorizationDecisionCode::PurchaseCountryDenied
        );
    }

    #[test]
    fn merchant_and_intent_mismatches_decline() {
        let merchant = fixture(
            500,
            1_000,
            "merchant-other",
            vec!["merchant-auths".into()],
            vec![],
            vec![],
        );
        assert_eq!(
            evaluate(&merchant, 10).code,
            PurchaseAuthorizationDecisionCode::PurchaseMerchantDenied
        );
        let mut expired = fixture(
            500,
            1_000,
            "merchant-auths",
            vec!["merchant-auths".into()],
            vec![],
            vec![],
        );
        expired.intent.expires_at = 499;
        assert_eq!(
            evaluate(&expired, 10).code,
            PurchaseAuthorizationDecisionCode::PurchaseIntentMismatch
        );
    }

    #[test]
    fn malformed_or_stale_webhooks_and_deadline_fail_closed() {
        let mut invalid = fixture(
            500,
            1_000,
            "merchant-auths",
            vec!["merchant-auths".into()],
            vec![],
            vec![],
        );
        invalid.webhook.signature_verified = false;
        assert_eq!(
            evaluate(&invalid, 10).code,
            PurchaseAuthorizationDecisionCode::PurchaseEvidenceInvalid
        );
        let mut stale = fixture(
            500,
            1_000,
            "merchant-auths",
            vec!["merchant-auths".into()],
            vec![],
            vec![],
        );
        stale.webhook.signature_timestamp = 400;
        assert_eq!(
            evaluate(&stale, 10).code,
            PurchaseAuthorizationDecisionCode::PurchaseEvidenceStale
        );
        let timeout = fixture(
            500,
            1_000,
            "merchant-auths",
            vec!["merchant-auths".into()],
            vec![],
            vec![],
        );
        assert_eq!(
            evaluate(&timeout, 1_000).code,
            PurchaseAuthorizationDecisionCode::PurchaseDecisionTimeout
        );
    }

    #[test]
    fn aggregate_capacity_is_checked_with_exact_arithmetic() {
        let value = fixture(
            500,
            1_000,
            "merchant-auths",
            vec!["merchant-auths".into()],
            vec![],
            vec![],
        );
        let aggregate = PurchaseAggregateSnapshot {
            held_minor_by_budget: BTreeMap::from([("global".into(), 501)]),
        };
        let result = evaluate_purchase_authorization(&PurchaseAuthorizationEvaluationContext {
            policy: &value.policy,
            action: &value.action,
            webhook: &value.webhook,
            intent: Some(&value.intent),
            aggregate: &aggregate,
            required_configuration: &value.configuration,
            executed_configuration: &value.configuration,
            request_audience: "https://issuer.example",
            now: 500,
            elapsed_milliseconds: 10,
        });
        assert_eq!(
            result.code,
            PurchaseAuthorizationDecisionCode::PurchaseAggregateBudgetExceeded
        );
    }
}
