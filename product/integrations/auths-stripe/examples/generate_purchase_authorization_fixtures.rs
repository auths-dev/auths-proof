use std::{collections::BTreeMap, fs, path::PathBuf};

use auths_stripe::{
    AgentProcurementIntentV1, AggregatePurchaseBudget, Currency, EventId, IssuingAuthorizationId,
    IssuingCardId, IssuingCardholderId, PurchaseAuthorizationMethod, PurchaseBudgetScope,
    PurchaseWebhookEvidenceV1, StripeAccountId, StripeBoundedPurchasePolicyInput,
    StripeBoundedPurchasePolicyV1, StripeExactPurchaseAuthorizationInput,
    StripeExactPurchaseAuthorizationV1, StripePurchaseConfigurationV1,
};
use serde::Serialize;

#[allow(
    clippy::too_many_lines,
    reason = "the generator keeps every canonical purchase commitment visible"
)]
fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/purchase-authorization/v1");
    fs::create_dir_all(&root).unwrap();
    let now = 2_100_400_000;
    let account = StripeAccountId::parse("acct_purchasefixture").unwrap();
    let cardholder = IssuingCardholderId::parse("ich_purchasefixture").unwrap();
    let card = IssuingCardId::parse("ic_purchasefixture").unwrap();
    let currency = Currency::parse("usd").unwrap();
    let merchant_name = auths_stripe::canonical::sha256(b"Auths API");
    let policy = StripeBoundedPurchasePolicyV1::new(StripeBoundedPurchasePolicyInput {
        policy_id: "purchase-authorization-fixture".into(),
        valid_from: now - 60,
        expires_at: now + 3_600,
        allowed_test_account_ids: vec![account.clone()],
        allowed_cardholder_ids: vec![cardholder.clone()],
        allowed_card_ids: vec![card.clone()],
        allowed_currencies: vec![currency.clone()],
        allowed_merchant_ids: vec!["merchant-auths".into()],
        allowed_merchant_name_commitments: vec![merchant_name.clone()],
        allowed_merchant_categories: vec!["computer_software_stores".into()],
        blocked_merchant_categories: vec![],
        allowed_merchant_countries: vec!["US".into()],
        blocked_merchant_countries: vec![],
        allowed_procurement_scopes: vec!["api-access".into()],
        allowed_authorization_methods: vec![PurchaseAuthorizationMethod::Online],
        per_purchase_minor_by_currency: BTreeMap::from([(currency.clone(), 1_000)]),
        per_merchant_minor_by_currency: BTreeMap::from([(currency.clone(), 2_000)]),
        per_category_minor_by_currency: BTreeMap::from([(currency.clone(), 3_000)]),
        aggregate_budgets: vec![AggregatePurchaseBudget {
            budget_id: "purchase-global".into(),
            scope: PurchaseBudgetScope::Global,
            currency: currency.clone(),
            limit_minor: 5_000,
            starts_at: now - 60,
            ends_at: now + 3_600,
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
        "https://stripe-purchase-authorization.auths.dev".into(),
    )
    .unwrap();
    let intent = AgentProcurementIntentV1 {
        schema: "auths.stripe.agent-procurement-intent/1".into(),
        intent_id: "purchase-intent-fixture".into(),
        agent_identity: "agent-auths".into(),
        procurement_scope: "api-access".into(),
        expected_merchant_id: "merchant-auths".into(),
        maximum_amount_minor: 500,
        currency: currency.clone(),
        recurring: false,
        fulfillment_reference_commitment: auths_stripe::canonical::sha256(b"order-fixture"),
        valid_from: now - 30,
        expires_at: now + 300,
        nonce: auths_stripe::canonical::sha256(b"purchase-intent-nonce"),
    };
    let payload_digest = auths_stripe::canonical::sha256(b"signed-issuing-payload");
    let action = StripeExactPurchaseAuthorizationV1::new(StripeExactPurchaseAuthorizationInput {
        stripe_account_id: account.clone(),
        event_id: EventId::parse("evt_purchasefixture").unwrap(),
        issuing_authorization_id: IssuingAuthorizationId::parse("iauth_purchasefixture").unwrap(),
        cardholder_id: cardholder,
        card_id: card,
        amount_minor: 500,
        currency: currency.clone(),
        merchant_amount_minor: 500,
        merchant_currency: currency,
        merchant_id: "merchant-auths".into(),
        merchant_name_commitment: merchant_name,
        merchant_category: "computer_software_stores".into(),
        merchant_country: "US".into(),
        authorization_method: PurchaseAuthorizationMethod::Online,
        procurement_scope: "api-access".into(),
        procurement_intent_digest: Some(intent.digest().unwrap()),
        stripe_api_version: "2025-04-30.basil".into(),
        webhook_payload_digest: payload_digest.clone(),
        required_policy_digest: policy.digest().unwrap(),
        required_configuration_digest: configuration.digest().unwrap(),
        executor_audience: "https://stripe-purchase-authorization.auths.dev".into(),
        received_at: now,
    })
    .unwrap();
    let evidence = PurchaseWebhookEvidenceV1 {
        schema: "auths.stripe.issuing-webhook-evidence/1".into(),
        event_id: action.event_id().clone(),
        event_type: "issuing_authorization.request".into(),
        payload_digest,
        signature_header_digest: auths_stripe::canonical::sha256(b"redacted-signature-header"),
        signature_timestamp: now,
        signature_verified: true,
        account_id: account,
        api_version: "2025-04-30.basil".into(),
        livemode: false,
        received_at: now,
    };

    write(&root, "action.json", &action);
    write(&root, "policy.json", &policy);
    write(&root, "configuration.json", &configuration);
    write(&root, "intent.json", &intent);
    write(&root, "evidence.json", &evidence);
    write(
        &root,
        "calculation.json",
        &serde_json::json!({
            "amount_minor": 500,
            "per_purchase_limit_minor": 1000,
            "per_merchant_limit_minor": 2000,
            "per_category_limit_minor": 3000,
            "aggregate_before_minor": 0,
            "aggregate_after_minor": 500,
            "aggregate_limit_minor": 5000,
            "full_amount_approved": true,
            "provider_calls_on_hot_path": 0,
            "credential_requests_on_hot_path": 0
        }),
    );
    write(
        &root,
        "stable-codes.json",
        &vec![
            "purchase-authorized",
            "purchase-declined",
            "purchase-intent-mismatch",
            "purchase-merchant-denied",
            "purchase-category-denied",
            "purchase-country-denied",
            "purchase-currency-denied",
            "purchase-amount-exceeded",
            "purchase-aggregate-budget-exceeded",
            "purchase-recurring-denied",
            "purchase-cash-denied",
            "purchase-decision-timeout",
            "purchase-outcome-unknown",
            "purchase-observation-outside-policy",
        ],
    );
    let mut manifest = BTreeMap::new();
    for name in [
        "action.json",
        "calculation.json",
        "configuration.json",
        "evidence.json",
        "intent.json",
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
