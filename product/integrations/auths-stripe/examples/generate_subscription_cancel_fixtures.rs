use std::{collections::BTreeMap, fs, path::PathBuf};

use auths_stripe::{
    AggregateImmediateBudget, AggregateRecurringBudget, Currency, CustomerId, PaymentMethodId,
    PriceId, ProductId, StripeAccountId, StripeBoundedSubscriptionPolicyInput,
    StripeBoundedSubscriptionPolicyV1, StripeExactSubscriptionCancelInput,
    StripeExactSubscriptionCancelV1, StripeSubscriptionCancelConfigurationV1,
    SubscriptionCancelEvidenceV1, SubscriptionCancelMode, SubscriptionConnectAccount,
    SubscriptionId, SubscriptionInterval, SubscriptionLiabilityState, SubscriptionOperation,
    SubscriptionPaymentBehavior, SubscriptionRecurringLimit, TestClockId,
};
use serde::Serialize;

#[allow(
    clippy::too_many_lines,
    reason = "the fixture generator intentionally keeps one auditable construction flow"
)]
fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/subscription-cancel/v1");
    fs::create_dir_all(&root).unwrap();
    let account = StripeAccountId::parse("acct_subscriptionfixture01").unwrap();
    let customer = CustomerId::parse("cus_subscriptionfixture0001").unwrap();
    let payment_method = PaymentMethodId::parse("pm_subscriptionfixture001").unwrap();
    let product = ProductId::parse("prod_subscriptionfixture001").unwrap();
    let price = PriceId::parse("price_subscriptionfixture01").unwrap();
    let currency = Currency::parse("usd").unwrap();
    let clock = TestClockId::parse("clock_subscriptionfixture01").unwrap();
    let subscription = SubscriptionId::parse("sub_subscriptionfixture0001").unwrap();
    let mandate = auths_stripe::canonical::sha256(b"subscription-cancel-mandate");
    let observed_at = 2_100_302_700;
    let policy = StripeBoundedSubscriptionPolicyV1::new(StripeBoundedSubscriptionPolicyInput {
        policy_id: "subscription-cancel-fixture".into(),
        valid_from: observed_at - 60,
        expires_at: observed_at + 3_600,
        allowed_operations: vec![SubscriptionOperation::Cancel],
        allowed_test_account_ids: vec![account.clone()],
        allowed_customer_ids: vec![customer.clone()],
        allowed_product_ids: vec![product],
        allowed_price_ids: vec![price.clone()],
        allowed_payment_method_ids: vec![payment_method],
        allowed_mandate_receipt_digests: vec![mandate],
        allowed_currencies: vec![currency.clone()],
        allowed_intervals: vec![SubscriptionInterval::Week],
        allowed_payment_behaviors: vec![SubscriptionPaymentBehavior::ErrorIfIncomplete],
        maximum_quantity_by_price: BTreeMap::from([(price, 1)]),
        maximum_recurring_minor_by_currency_and_interval: vec![SubscriptionRecurringLimit {
            currency: currency.clone(),
            interval: SubscriptionInterval::Week,
            limit_minor: 1_200,
        }],
        maximum_first_invoice_minor_by_currency: BTreeMap::from([(currency.clone(), 1_200)]),
        maximum_term_seconds: 2_000_000,
        maximum_billing_cycles: 3,
        maximum_active_subscriptions_per_customer: 1,
        aggregate_recurring_budgets: vec![AggregateRecurringBudget {
            budget_id: "subscription-cancel-recurring".into(),
            customer_id: customer.clone(),
            currency: currency.clone(),
            interval: SubscriptionInterval::Week,
            limit_minor: 3_600,
        }],
        aggregate_immediate_budgets: vec![AggregateImmediateBudget {
            budget_id: "subscription-cancel-invoice".into(),
            currency: currency.clone(),
            limit_minor: 1_200,
            starts_at: observed_at - 60,
            ends_at: observed_at + 3_600,
        }],
        minimum_preview_validity_seconds: 60,
        maximum_evidence_age_seconds: 120,
        maximum_action_lifetime_seconds: 600,
        allowed_api_versions: vec!["2025-04-30.basil".into()],
    })
    .unwrap();
    let configuration = StripeSubscriptionCancelConfigurationV1::new(
        &policy,
        account.clone(),
        SubscriptionConnectAccount::Platform,
        clock.clone(),
        "2025-04-30.basil".into(),
        "https://stripe-subscription-cancel.auths.dev".into(),
    )
    .unwrap();
    let subscription_digest = auths_stripe::canonical::sha256(b"subscription-before-cancel");
    let item_set_digest = auths_stripe::canonical::sha256(b"subscription-items");
    let pending_items_digest = auths_stripe::canonical::sha256(b"no-pending-invoice-items");
    let latest_invoice_digest = auths_stripe::canonical::sha256(b"latest-paid-invoice");
    let evidence = SubscriptionCancelEvidenceV1 {
        schema: "auths.stripe.subscription-cancel-evidence/1".into(),
        stripe_account_id: account.clone(),
        connect_account: SubscriptionConnectAccount::Platform,
        subscription_id: subscription.clone(),
        customer_id: customer.clone(),
        subscription_digest: subscription_digest.clone(),
        item_set_digest: item_set_digest.clone(),
        status: "active".into(),
        currency: currency.clone(),
        current_period_end: 2_100_605_100,
        cancel_at: None,
        cancel_at_period_end: false,
        canceled_at: None,
        ended_at: None,
        pending_update_digest: None,
        pending_invoice_items_digest: pending_items_digest.clone(),
        pending_invoice_item_count: 0,
        unhandled_pending_invoice_item_count: 0,
        latest_invoice_id: None,
        latest_invoice_digest: latest_invoice_digest.clone(),
        latest_invoice_status: Some("paid".into()),
        latest_payment_intent_id: None,
        liability_id: auths_stripe::canonical::sha256(b"subscription-liability"),
        liability_state: SubscriptionLiabilityState::Active,
        remaining_term_liability_minor: 3_600,
        current_period_liability_minor: 1_200,
        renewal_or_modification_pending: false,
        test_clock_id: clock.clone(),
        livemode: false,
        stripe_api_version: "2025-04-30.basil".into(),
        observed_at,
        response_digest: auths_stripe::canonical::sha256(b"subscription-cancel-evidence"),
        source: "stripe-fixture".into(),
    };
    evidence.validate().unwrap();
    let action = StripeExactSubscriptionCancelV1::new(StripeExactSubscriptionCancelInput {
        stripe_account_id: account,
        connect_account: SubscriptionConnectAccount::Platform,
        subscription_id: subscription,
        customer_id: customer,
        subscription_digest,
        item_set_digest,
        currency,
        current_period_end: evidence.current_period_end,
        cancel_at: evidence.current_period_end,
        mode: SubscriptionCancelMode::AtPeriodEnd,
        pending_invoice_items_digest: pending_items_digest,
        latest_invoice_digest,
        remaining_term_liability_minor: 3_600,
        current_period_liability_minor: 1_200,
        cancellation_reason_commitment: auths_stripe::canonical::sha256(b"requested-by-owner"),
        test_clock_id: clock,
        stripe_api_version: "2025-04-30.basil".into(),
        required_policy_digest: policy.digest().unwrap(),
        required_configuration_digest: configuration.digest().unwrap(),
        executor_audience: "https://stripe-subscription-cancel.auths.dev".into(),
        expires_at: observed_at + 300,
        nonce: auths_stripe::canonical::sha256(b"subscription-cancel-action"),
    })
    .unwrap();
    write(&root, "action.json", &action);
    write(&root, "policy.json", &policy);
    write(&root, "configuration.json", &configuration);
    write(&root, "evidence.json", &evidence);
    write(
        &root,
        "calculation.json",
        &serde_json::json!({
            "mode": "at_period_end",
            "remaining_term_liability_minor": 3600,
            "current_period_liability_minor": 1200,
            "future_liability_release_minor": 2400,
            "liability_retained_until_terminal_minor": 1200,
            "invoice_now": false,
            "prorate": false
        }),
    );
    write(
        &root,
        "stable-codes.json",
        &vec![
            "subscription-cancel-authorized",
            "subscription-cancel-mode-denied",
            "subscription-cancel-before-state-mismatch",
            "subscription-cancel-pending-update",
            "subscription-cancel-pending-invoice-items",
            "subscription-cancel-already-scheduled",
            "subscription-cancel-already-terminal",
            "subscription-cancel-renewal-conflict",
            "subscription-cancel-outcome-unknown",
        ],
    );
    let mut manifest = BTreeMap::new();
    for name in [
        "action.json",
        "calculation.json",
        "configuration.json",
        "evidence.json",
        "policy.json",
        "stable-codes.json",
    ] {
        manifest.insert(
            name.to_owned(),
            auths_stripe::canonical::sha256(&fs::read(root.join(name)).unwrap()),
        );
    }
    write(&root, "manifest.sha256.json", &manifest);
}

fn write<T: Serialize>(root: &std::path::Path, name: &str, value: &T) {
    fs::write(
        root.join(name),
        auths_stripe::canonical::canonical_json(value).unwrap(),
    )
    .unwrap();
}
