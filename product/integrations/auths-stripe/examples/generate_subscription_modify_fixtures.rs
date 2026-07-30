use std::{collections::BTreeMap, fs, path::PathBuf};

use auths_stripe::{
    AggregateImmediateBudget, AggregateRecurringBudget, Currency, CustomerId, DigestHex,
    PaymentMethodId, PriceId, ProductId, SUBSCRIPTION_MODIFY_PROFILE,
    SUBSCRIPTION_MODIFY_RECEIPT_SCHEMA, StripeAccountId, StripeBoundedSubscriptionPolicyInput,
    StripeBoundedSubscriptionPolicyV1, StripeExactSubscriptionCreateV1,
    StripeExactSubscriptionModifyInput, StripeExactSubscriptionModifyV1,
    StripeSubscriptionConfigurationV1, SubscriptionCatalogItemEvidence, SubscriptionConnectAccount,
    SubscriptionId, SubscriptionInterval, SubscriptionItemId, SubscriptionModifyEvidenceV1,
    SubscriptionModifyItem, SubscriptionOperation, SubscriptionPaymentBehavior,
    SubscriptionPreviewLine, SubscriptionRecurringLimit, TestClockId,
};
use serde::Serialize;

#[allow(
    clippy::too_many_lines,
    reason = "the fixture generator intentionally keeps one auditable construction flow"
)]
fn main() {
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let create_fixture_dir = crate_root.join("fixtures/subscription-create/v1");
    let root = crate_root.join("fixtures/subscription-modify/v1");
    fs::create_dir_all(&root).unwrap();

    let create_action: StripeExactSubscriptionCreateV1 =
        serde_json::from_slice(&fs::read(create_fixture_dir.join("action.json")).unwrap()).unwrap();
    let account = StripeAccountId::parse("acct_subscriptionfixture01").unwrap();
    let customer = CustomerId::parse("cus_subscriptionfixture0001").unwrap();
    let payment_method = PaymentMethodId::parse("pm_subscriptionfixture001").unwrap();
    let product = ProductId::parse("prod_subscriptionfixture001").unwrap();
    let price = PriceId::parse("price_subscriptionfixture01").unwrap();
    let currency = Currency::parse("usd").unwrap();
    let test_clock = TestClockId::parse("clock_subscriptionfixture01").unwrap();
    let mandate_digest = create_action.mandate_receipt_digest().clone();
    let observed_at = 2_100_302_700;

    let policy = StripeBoundedSubscriptionPolicyV1::new(StripeBoundedSubscriptionPolicyInput {
        policy_id: "subscription-modify-fixture".into(),
        valid_from: observed_at - 60,
        expires_at: observed_at + 3_600,
        allowed_operations: vec![SubscriptionOperation::Create],
        allowed_test_account_ids: vec![account.clone()],
        allowed_customer_ids: vec![customer.clone()],
        allowed_product_ids: vec![product.clone()],
        allowed_price_ids: vec![price.clone()],
        allowed_payment_method_ids: vec![payment_method.clone()],
        allowed_mandate_receipt_digests: vec![mandate_digest.clone()],
        allowed_currencies: vec![currency.clone()],
        allowed_intervals: vec![SubscriptionInterval::Week],
        allowed_payment_behaviors: vec![SubscriptionPaymentBehavior::ErrorIfIncomplete],
        maximum_quantity_by_price: BTreeMap::from([(price.clone(), 2)]),
        maximum_recurring_minor_by_currency_and_interval: vec![SubscriptionRecurringLimit {
            currency: currency.clone(),
            interval: SubscriptionInterval::Week,
            limit_minor: 1_000,
        }],
        maximum_first_invoice_minor_by_currency: BTreeMap::from([(currency.clone(), 500)]),
        maximum_term_seconds: 2_000_000,
        maximum_billing_cycles: 3,
        maximum_active_subscriptions_per_customer: 1,
        aggregate_recurring_budgets: vec![AggregateRecurringBudget {
            budget_id: "subscription-modify-delta".into(),
            customer_id: customer.clone(),
            currency: currency.clone(),
            interval: SubscriptionInterval::Week,
            limit_minor: 1_000,
        }],
        aggregate_immediate_budgets: vec![AggregateImmediateBudget {
            budget_id: "subscription-modify-proration".into(),
            currency: currency.clone(),
            limit_minor: 500,
            starts_at: observed_at - 60,
            ends_at: observed_at + 3_600,
        }],
        minimum_preview_validity_seconds: 60,
        maximum_evidence_age_seconds: 120,
        maximum_action_lifetime_seconds: 600,
        allowed_api_versions: vec!["2025-04-30.basil".into()],
    })
    .unwrap()
    .with_modify_limits(BTreeMap::from([(currency.clone(), 500)]))
    .unwrap();

    let configuration = StripeSubscriptionConfigurationV1::new(
        SUBSCRIPTION_MODIFY_PROFILE,
        SUBSCRIPTION_MODIFY_RECEIPT_SCHEMA,
        &policy,
        account.clone(),
        SubscriptionConnectAccount::Platform,
        test_clock.clone(),
        "2025-04-30.basil".into(),
        "https://stripe-subscription-modify.auths.dev".into(),
    )
    .unwrap();

    let subscription_id = SubscriptionId::parse("sub_subscriptionfixture0001").unwrap();
    let item_id = SubscriptionItemId::parse("si_subscriptionfixture0001").unwrap();
    let before_item =
        SubscriptionModifyItem::new(item_id.clone(), price.clone(), product.clone(), 1).unwrap();
    let after_item =
        SubscriptionModifyItem::new(item_id, price.clone(), product.clone(), 2).unwrap();
    let catalog = vec![SubscriptionCatalogItemEvidence {
        price_id: price.clone(),
        product_id: product,
        currency: currency.clone(),
        unit_amount_minor: 500,
        interval: SubscriptionInterval::Week,
        interval_count: 1,
        licensed: true,
        active: true,
    }];
    let preview_lines = vec![
        SubscriptionPreviewLine {
            price_id: price.clone(),
            quantity: 1,
            amount_minor: -250,
            proration: true,
        },
        SubscriptionPreviewLine {
            price_id: price,
            quantity: 2,
            amount_minor: 500,
            proration: true,
        },
    ];
    let preview_digest = auths_stripe::canonical::canonical_digest(&preview_lines).unwrap();
    let mut evidence = SubscriptionModifyEvidenceV1 {
        schema: "auths.stripe.subscription-modify-evidence/1".into(),
        stripe_account_id: account.clone(),
        connect_account: SubscriptionConnectAccount::Platform,
        subscription_id: subscription_id.clone(),
        customer_id: customer.clone(),
        current_items: vec![before_item.clone()],
        currency: currency.clone(),
        collection_method: auths_stripe::SubscriptionCollectionMethod::ChargeAutomatically,
        payment_method_id: payment_method,
        billing_cycle_anchor: 2_100_000_300,
        current_period_start: 2_100_000_300,
        current_period_end: 2_100_605_100,
        cancel_at: 2_101_814_700,
        mandate_receipt_digest: mandate_digest.clone(),
        test_clock_id: test_clock.clone(),
        before_subscription_digest: DigestHex::parse("0".repeat(64)).unwrap(),
        pending_update_digest: None,
        catalog,
        preview_lines,
        preview_digest: preview_digest.clone(),
        proration_date: observed_at,
        proration_debit_minor: 500,
        proration_credit_minor: 250,
        before_recurring_minor: 500,
        after_recurring_minor: 1_000,
        remaining_cycle_count: 2,
        latest_invoice_id: None,
        latest_payment_intent_id: None,
        invoice_status: None,
        payment_status: None,
        preview_valid_until: observed_at + 300,
        livemode: false,
        stripe_api_version: "2025-04-30.basil".into(),
        observed_at,
        response_digest: auths_stripe::canonical::sha256(b"subscription-modify-evidence"),
        source: "stripe-fixture".into(),
    };
    evidence.before_subscription_digest = evidence.before_digest().unwrap();
    evidence.validate().unwrap();
    let action = StripeExactSubscriptionModifyV1::new(StripeExactSubscriptionModifyInput {
        stripe_account_id: account,
        connect_account: SubscriptionConnectAccount::Platform,
        subscription_id,
        customer_id: customer,
        before_subscription_digest: evidence.before_subscription_digest.clone(),
        before_items: vec![before_item],
        after_items: vec![after_item],
        currency,
        billing_cycle_anchor: evidence.billing_cycle_anchor,
        cancel_at: evidence.cancel_at,
        proration_date: evidence.proration_date,
        mandate_receipt_digest: mandate_digest,
        invoice_preview_digest: preview_digest,
        proration_debit_minor: 500,
        proration_credit_minor: 250,
        before_recurring_minor: 500,
        after_recurring_minor: 1_000,
        remaining_cycle_count: 2,
        incremental_term_liability_minor: 1_000,
        test_clock_id: test_clock,
        stripe_api_version: "2025-04-30.basil".into(),
        required_policy_digest: policy.digest().unwrap(),
        required_configuration_digest: configuration.digest().unwrap(),
        executor_audience: "https://stripe-subscription-modify.auths.dev".into(),
        expires_at: observed_at + 300,
        nonce: auths_stripe::canonical::sha256(b"subscription-modify-action"),
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
            "before_recurring_minor": 500,
            "after_recurring_minor": 1_000,
            "remaining_cycle_count": 2,
            "before_term_liability_minor": 1_000,
            "after_term_liability_minor": 2_000,
            "incremental_term_liability_minor": 1_000,
            "superseded_term_liability_minor": 0,
            "proration_debit_minor": 500,
            "proration_credit_minor": 250,
            "credit_counted_as_capacity": false,
            "payment_behavior": "pending_if_incomplete",
            "proration_behavior": "always_invoice"
        }),
    );
    write(
        &root,
        "stable-codes.json",
        &vec![
            "subscription-modify-authorized",
            "subscription-before-state-mismatch",
            "subscription-protected-field-changed",
            "subscription-price-denied",
            "subscription-quantity-exceeded",
            "subscription-proration-limit-exceeded",
            "subscription-recurring-limit-exceeded",
            "subscription-preview-mismatch",
            "subscription-pending-update-conflict",
            "subscription-update-payment-incomplete",
            "subscription-update-outcome-unknown",
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
