use std::{collections::BTreeMap, fs, path::PathBuf};

use auths_stripe::{
    AggregateImmediateBudget, AggregateRecurringBudget, CustomerId, DigestHex,
    InMemoryPaymentMandateStore, MandateAmountType, MandateConnectAccount, MandateInterval,
    MandateUsage, PaymentMandateCapabilityState, PaymentMandateObservationReceipt,
    PaymentMandateProviderProjection, PaymentMandateReceipt, PaymentMandateStore, PaymentMethodId,
    PriceId, ProductId, ReservePaymentMandateRequest, ReservePaymentMandateResult,
    SUBSCRIPTION_CREATE_PROFILE, SUBSCRIPTION_CREATE_RECEIPT_SCHEMA, SetupIntentId,
    StripeAccountId, StripeBoundedSubscriptionPolicyInput, StripeBoundedSubscriptionPolicyV1,
    StripeExactPaymentMandateInput, StripeExactPaymentMandateV1,
    StripeExactSubscriptionCreateInput, StripeExactSubscriptionCreateV1,
    StripeSubscriptionConfigurationV1, SubscriptionCatalogItemEvidence,
    SubscriptionCollectionMethod, SubscriptionConnectAccount, SubscriptionCreateEvidenceV1,
    SubscriptionCreateItem, SubscriptionInterval, SubscriptionOperation,
    SubscriptionPaymentBehavior, SubscriptionPreviewLine, SubscriptionRecurringLimit, TestClockId,
    canonical::{canonical_json, sha256},
};

fn id<T>(value: &str) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}

fn digest(byte: u8) -> DigestHex {
    DigestHex::parse(format!("{byte:02x}").repeat(32)).unwrap()
}

#[allow(
    clippy::too_many_lines,
    reason = "fixture generation keeps the complete canonical corpus adjacent"
)]
fn main() {
    let now = 2_100_000_000;
    let account: StripeAccountId = id("acct_subscriptionfixture01");
    let customer: CustomerId = id("cus_subscriptionfixture0001");
    let payment_method: PaymentMethodId = id("pm_subscriptionfixture00001");
    let price: PriceId = id("price_subscriptionfixture01");
    let product: ProductId = id("prod_subscriptionfixture001");
    let clock: TestClockId = id("clock_subscriptionfixture01");
    let mandate_decision_receipt_digest = digest(7);

    let mandate_action = StripeExactPaymentMandateV1::new(StripeExactPaymentMandateInput {
        stripe_account_id: account.clone(),
        connect_account: MandateConnectAccount::Platform,
        customer_id: customer.clone(),
        payment_method_id: payment_method.clone(),
        payment_method_type: "card".into(),
        usage: MandateUsage::OffSession,
        mandate_amount_type: MandateAmountType::Maximum,
        mandate_amount_minor: 500,
        currency: id("usd"),
        interval: MandateInterval::Weekly,
        reference: "subscription-fixture".into(),
        consent_evidence_digest: digest(5),
        displayed_terms_digest: digest(6),
        on_behalf_of: None,
        return_url_commitment: None,
        stripe_api_version: "2025-04-30.basil".into(),
        required_policy_digest: digest(3),
        required_configuration_digest: digest(4),
        executor_audience: "https://stripe-subscription-create.auths.dev".into(),
        expires_at: now + 300,
        nonce: digest(8),
    })
    .unwrap();
    let mandate_action_digest = mandate_action.digest().unwrap();
    let mandate_store = InMemoryPaymentMandateStore::default();
    let ReservePaymentMandateResult::Reserved(reserved) = mandate_store
        .reserve(ReservePaymentMandateRequest {
            workflow_id: "mandate-for-subscription".into(),
            stripe_account_id: account.clone(),
            customer_id: customer.clone(),
            payment_method_id: payment_method.clone(),
            reference: "subscription-fixture".into(),
            action_digest: mandate_action_digest,
            policy_digest: digest(3),
            consent_digest: digest(5),
            decision_receipt_digest: mandate_decision_receipt_digest.clone(),
            maximum_active: 3,
            provider_active: 0,
            now,
        })
        .unwrap()
    else {
        unreachable!()
    };
    let claimed = mandate_store
        .transition(
            reserved.workflow_id(),
            PaymentMandateCapabilityState::Reserved,
            PaymentMandateCapabilityState::Claimed,
            None,
            now,
        )
        .unwrap();
    let attempting = mandate_store
        .transition(
            claimed.workflow_id(),
            PaymentMandateCapabilityState::Claimed,
            PaymentMandateCapabilityState::Attempting,
            None,
            now,
        )
        .unwrap();
    let mandate_capability = mandate_store
        .transition(
            attempting.workflow_id(),
            PaymentMandateCapabilityState::Attempting,
            PaymentMandateCapabilityState::Committed,
            Some(PaymentMandateProviderProjection {
                setup_intent_id: id::<SetupIntentId>("seti_subscriptionfixture01"),
                latest_setup_attempt_id: None,
                mandate_id: None,
                customer_id: customer.clone(),
                payment_method_id: payment_method.clone(),
                usage: "off_session".into(),
                status: "succeeded".into(),
                livemode: false,
                stripe_request_id: Some("req_subscriptionfixture01".into()),
                response_digest: digest(9),
                observed_at: now,
                source: "stripe-test-fixture".into(),
            }),
            now,
        )
        .unwrap();

    let mandate_receipt =
        PaymentMandateReceipt::Observation(Box::new(PaymentMandateObservationReceipt {
            schema: "auths.stripe.payment-mandate-observation-receipt/1".into(),
            workflow_id: mandate_capability.workflow_id().into(),
            action_digest: mandate_capability.action_digest().clone(),
            policy_digest: mandate_capability.policy_digest().clone(),
            decision_receipt_digest: mandate_decision_receipt_digest,
            capability_id: mandate_capability.capability_id().clone(),
            provider: mandate_capability.provider().unwrap().clone(),
            exact_provider_equality: true,
            reconciled: false,
            client_secret_exposed: false,
            no_immediate_charge: true,
            residual_assumptions: vec![],
            recorded_at: now,
        }));
    let mandate_receipt_digest =
        auths_stripe::canonical::canonical_digest(&mandate_receipt).unwrap();

    let policy = StripeBoundedSubscriptionPolicyV1::new(StripeBoundedSubscriptionPolicyInput {
        policy_id: "subscription-create-fixture-policy".into(),
        valid_from: now - 60,
        expires_at: now + 3_600,
        allowed_operations: vec![SubscriptionOperation::Create],
        allowed_test_account_ids: vec![account.clone()],
        allowed_customer_ids: vec![customer.clone()],
        allowed_product_ids: vec![product.clone()],
        allowed_price_ids: vec![price.clone()],
        allowed_payment_method_ids: vec![payment_method.clone()],
        allowed_mandate_receipt_digests: vec![mandate_receipt_digest.clone()],
        allowed_currencies: vec![id("usd")],
        allowed_intervals: vec![SubscriptionInterval::Week],
        allowed_payment_behaviors: vec![SubscriptionPaymentBehavior::ErrorIfIncomplete],
        maximum_quantity_by_price: BTreeMap::from([(price.clone(), 1)]),
        maximum_recurring_minor_by_currency_and_interval: vec![SubscriptionRecurringLimit {
            currency: id("usd"),
            interval: SubscriptionInterval::Week,
            limit_minor: 500,
        }],
        maximum_first_invoice_minor_by_currency: BTreeMap::from([(id("usd"), 500)]),
        maximum_term_seconds: 2_000_000,
        maximum_billing_cycles: 3,
        maximum_active_subscriptions_per_customer: 1,
        aggregate_recurring_budgets: vec![AggregateRecurringBudget {
            budget_id: "subscription-term".into(),
            customer_id: customer.clone(),
            currency: id("usd"),
            interval: SubscriptionInterval::Week,
            limit_minor: 1_500,
        }],
        aggregate_immediate_budgets: vec![AggregateImmediateBudget {
            budget_id: "subscription-immediate".into(),
            currency: id("usd"),
            limit_minor: 500,
            starts_at: now - 60,
            ends_at: now + 3_600,
        }],
        minimum_preview_validity_seconds: 30,
        maximum_evidence_age_seconds: 120,
        maximum_action_lifetime_seconds: 300,
        allowed_api_versions: vec!["2025-04-30.basil".into()],
    })
    .unwrap();
    let configuration = StripeSubscriptionConfigurationV1::new(
        SUBSCRIPTION_CREATE_PROFILE,
        SUBSCRIPTION_CREATE_RECEIPT_SCHEMA,
        &policy,
        account.clone(),
        SubscriptionConnectAccount::Platform,
        clock.clone(),
        "2025-04-30.basil".into(),
        "https://stripe-subscription-create.auths.dev".into(),
    )
    .unwrap();
    let action = StripeExactSubscriptionCreateV1::new(StripeExactSubscriptionCreateInput {
        stripe_account_id: account.clone(),
        connect_account: SubscriptionConnectAccount::Platform,
        customer_id: customer.clone(),
        items: vec![SubscriptionCreateItem::new(price.clone(), product.clone(), 1).unwrap()],
        currency: id("usd"),
        default_payment_method_id: payment_method.clone(),
        mandate_receipt_digest: mandate_receipt_digest.clone(),
        payment_behavior: SubscriptionPaymentBehavior::ErrorIfIncomplete,
        trial_end: None,
        billing_cycle_anchor: now + 300,
        cancel_at: now + 1_814_700,
        fixed_metadata_commitment: digest(10),
        invoice_preview_digest: digest(11),
        projected_first_invoice_minor: 500,
        projected_recurring_minor: 500,
        projected_cycle_count: 3,
        projected_term_liability_minor: 1_500,
        test_clock_id: clock.clone(),
        stripe_api_version: "2025-04-30.basil".into(),
        required_policy_digest: policy.digest().unwrap(),
        required_configuration_digest: configuration.digest().unwrap(),
        executor_audience: "https://stripe-subscription-create.auths.dev".into(),
        expires_at: now + 120,
        nonce: digest(12),
    })
    .unwrap();
    let evidence = SubscriptionCreateEvidenceV1 {
        schema: "auths.stripe.subscription-create-evidence/1".into(),
        stripe_account_id: account,
        connect_account: SubscriptionConnectAccount::Platform,
        customer_id: customer,
        payment_method_id: payment_method,
        test_clock_id: clock,
        mandate_action,
        mandate_capability,
        mandate_receipt,
        mandate_receipt_digest,
        catalog: vec![SubscriptionCatalogItemEvidence {
            price_id: price.clone(),
            product_id: product,
            currency: id("usd"),
            unit_amount_minor: 500,
            interval: SubscriptionInterval::Week,
            interval_count: 1,
            licensed: true,
            active: true,
        }],
        preview_lines: vec![SubscriptionPreviewLine {
            price_id: price,
            quantity: 1,
            amount_minor: 500,
            proration: false,
        }],
        preview_digest: digest(11),
        preview_amount_due_minor: 500,
        preview_valid_until: now + 300,
        cycle_anchors: vec![now + 300, now + 605_100, now + 1_209_900],
        active_subscriptions: 0,
        livemode: false,
        stripe_api_version: "2025-04-30.basil".into(),
        observed_at: now,
        response_digest: digest(13),
        source: "stripe-test-clock-and-invoice-preview".into(),
    };
    evidence.validate().unwrap();

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/subscription-create/v1");
    fs::create_dir_all(&root).unwrap();
    let calculation = serde_json::json!({
        "collection_method": SubscriptionCollectionMethod::ChargeAutomatically,
        "cycle_count": 3,
        "first_invoice_minor": 500,
        "recurring_minor": 500,
        "term_liability_minor": 1500
    });
    let values = [
        ("action.json", serde_json::to_value(&action).unwrap()),
        ("calculation.json", calculation),
        (
            "configuration.json",
            serde_json::to_value(&configuration).unwrap(),
        ),
        ("evidence.json", serde_json::to_value(&evidence).unwrap()),
        ("policy.json", serde_json::to_value(&policy).unwrap()),
        (
            "stable-codes.json",
            serde_json::json!([
                "subscription-create-authorized",
                "subscription-price-denied",
                "subscription-metered-price-denied",
                "subscription-quantity-exceeded",
                "subscription-term-required",
                "subscription-term-exceeded",
                "subscription-recurring-limit-exceeded",
                "subscription-first-invoice-limit-exceeded",
                "subscription-preview-mismatch",
                "subscription-mandate-mismatch",
                "subscription-payment-incomplete",
                "subscription-outcome-unknown"
            ]),
        ),
    ];
    let mut manifest = BTreeMap::new();
    for (name, value) in values {
        let bytes = canonical_json(&value).unwrap();
        fs::write(root.join(name), &bytes).unwrap();
        manifest.insert(name.to_owned(), sha256(&bytes));
    }
    fs::write(
        root.join("manifest.sha256.json"),
        canonical_json(&manifest).unwrap(),
    )
    .unwrap();
}
