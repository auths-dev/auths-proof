use std::{collections::BTreeMap, fs, path::PathBuf};

use auths_stripe::{
    AggregateConnectTransferBudget, ChargeId, ConnectTransferBudgetScope,
    ConnectTransferEvidenceV1, Currency, PaymentIntentId, StripeAccountId,
    StripeBoundedConnectTransferPolicyInput, StripeBoundedConnectTransferPolicyV1,
    StripeConnectTransferConfigurationV1, StripeExactConnectTransferInput,
    StripeExactConnectTransferV1,
};
use serde::Serialize;

#[allow(
    clippy::too_many_lines,
    reason = "the generator keeps every canonical transfer commitment visible"
)]
fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/connect-transfer/v1");
    fs::create_dir_all(&root).unwrap();
    let now = 2_100_500_000;
    let platform = StripeAccountId::parse("acct_platformfixture").unwrap();
    let destination = StripeAccountId::parse("acct_destinationfixture").unwrap();
    let source = ChargeId::parse("ch_connectfixture").unwrap();
    let payment_intent = PaymentIntentId::parse("pi_connectfixture").unwrap();
    let currency = Currency::parse("usd").unwrap();
    let policy =
        StripeBoundedConnectTransferPolicyV1::new(StripeBoundedConnectTransferPolicyInput {
            policy_id: "connect-transfer-fixture".into(),
            valid_from: now - 60,
            expires_at: now + 3_600,
            allowed_test_platform_account_ids: vec![platform.clone()],
            allowed_destination_connected_account_ids: vec![destination.clone()],
            allowed_source_charge_ids: vec![source.clone()],
            allowed_transfer_groups: vec!["order-fixture".into()],
            allowed_currencies: vec![currency.clone()],
            allowed_business_scopes: vec!["supplier-payment".into()],
            per_transfer_minor_by_currency: BTreeMap::from([(currency.clone(), 500)]),
            per_destination_minor_by_currency: BTreeMap::from([(currency.clone(), 1_000)]),
            per_source_charge_basis_points: 2_500,
            aggregate_budgets: vec![AggregateConnectTransferBudget {
                budget_id: "connect-global".into(),
                scope: ConnectTransferBudgetScope::Global,
                currency: currency.clone(),
                limit_minor: 2_000,
                starts_at: now - 60,
                ends_at: now + 3_600,
            }],
            maximum_source_evidence_age_seconds: 60,
            maximum_action_lifetime_seconds: 300,
            allowed_api_versions: vec!["2025-04-30.basil".into()],
        })
        .unwrap();
    let configuration = StripeConnectTransferConfigurationV1::new(
        &policy,
        platform.clone(),
        "2025-04-30.basil".into(),
        "https://stripe-connect-transfer.auths.dev".into(),
    )
    .unwrap();
    let action = StripeExactConnectTransferV1::new(StripeExactConnectTransferInput {
        platform_account_id: platform.clone(),
        destination_connected_account_id: destination.clone(),
        source_charge_id: source.clone(),
        source_payment_intent_id: payment_intent.clone(),
        transfer_group: "order-fixture".into(),
        business_scope: "supplier-payment".into(),
        amount_minor: 500,
        currency: currency.clone(),
        description_commitment: auths_stripe::canonical::sha256(b"fixture transfer"),
        fixed_metadata_commitment: auths_stripe::canonical::sha256(b"fixture metadata"),
        stripe_api_version: "2025-04-30.basil".into(),
        required_policy_digest: policy.digest().unwrap(),
        required_configuration_digest: configuration.digest().unwrap(),
        executor_audience: "https://stripe-connect-transfer.auths.dev".into(),
        expires_at: now + 120,
        nonce: auths_stripe::canonical::sha256(b"connect-transfer-nonce"),
    })
    .unwrap();
    let evidence = ConnectTransferEvidenceV1 {
        schema: "auths.stripe.connect-transfer-evidence/1".into(),
        platform_account_id: platform,
        destination_account_id: destination,
        destination_transfers_capability_active: true,
        source_charge_id: source,
        source_payment_intent_id: payment_intent,
        source_charge_amount_minor: 4_000,
        source_charge_captured: true,
        source_charge_paid: true,
        source_charge_status: "succeeded".into(),
        source_currency: currency,
        source_committed_transfer_minor: 400,
        source_reversed_transfer_minor: 100,
        platform_available_balance_minor: 5_000,
        transfer_group: "order-fixture".into(),
        livemode: false,
        stripe_api_version: "2025-04-30.basil".into(),
        observed_at: now,
        response_digest: auths_stripe::canonical::sha256(b"source-and-balance-response"),
        source: "stripe-api".into(),
    };

    write(&root, "action.json", &action);
    write(&root, "policy.json", &policy);
    write(&root, "configuration.json", &configuration);
    write(&root, "evidence.json", &evidence);
    write(
        &root,
        "calculation.json",
        &serde_json::json!({
            "amount_minor": 500,
            "source_charge_amount_minor": 4000,
            "source_basis_points": 2500,
            "source_ceiling_minor": 1000,
            "source_committed_minor": 400,
            "source_reversed_minor": 100,
            "source_committed_net_minor": 300,
            "source_available_before_minor": 700,
            "per_transfer_limit_minor": 500,
            "per_destination_limit_minor": 1000,
            "platform_available_before_minor": 5000,
            "source_transaction_required": true
        }),
    );
    write(
        &root,
        "stable-codes.json",
        &vec![
            "connect-transfer-authorized",
            "connect-destination-denied",
            "connect-source-charge-denied",
            "connect-source-not-available",
            "connect-transfer-group-mismatch",
            "connect-transfer-limit-exceeded",
            "connect-source-capacity-exceeded",
            "connect-platform-balance-insufficient",
            "connect-transfer-outcome-unknown",
            "connect-configuration-mismatch",
            "connect-evidence-invalid",
            "connect-evidence-stale",
            "connect-replay",
            "connect-arithmetic-failure",
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
