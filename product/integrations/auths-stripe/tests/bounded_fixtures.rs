use std::{collections::BTreeMap, fs, path::PathBuf};

use auths_stripe::{
    AggregateBudgetSnapshot, AggregateRefundBudget, BoundedEvaluationContext, ChargeId,
    ConnectScope, Currency, ExactRefundActionInput, ExactRefundActionV1, Money, PaymentIntentId,
    RefundBudgetWindow, RefundDenominator, RefundEvidenceInput, RefundEvidenceV1,
    RelativeRefundLimit, StripeAccountId, StripeBoundedEvaluatorConfigurationV1,
    StripeBoundedRefundPolicyInput, StripeBoundedRefundPolicyV1, StripeVerifierConfiguration,
    StripeVerifierConfigurationInput, canonical, evaluate_bounded_refund,
};

const NOW: u64 = 1_800_000_000;

#[allow(
    clippy::too_many_lines,
    reason = "one linear builder keeps every cross-linked canonical fixture visibly identical"
)]
fn fixture_values() -> Vec<(&'static str, Vec<u8>)> {
    let account = StripeAccountId::parse("acct_authsdemo01").unwrap();
    let charge = ChargeId::parse("ch_authsdemo00000001").unwrap();
    let payment_intent = PaymentIntentId::parse("pi_authsdemo00000001").unwrap();
    let currency = Currency::parse("usd").unwrap();
    let evidence = RefundEvidenceV1::new(RefundEvidenceInput {
        stripe_account_id: account.clone(),
        stripe_api_version: "2025-04-30.basil".into(),
        livemode: false,
        charge_id: charge.clone(),
        payment_intent_id: Some(payment_intent.clone()),
        connect_account_id: None,
        currency: currency.clone(),
        charge_amount_minor: 2_000,
        captured_amount_minor: 2_000,
        amount_refunded_minor: 0,
        paid: true,
        captured: true,
        charge_refunded: false,
        disputed: false,
        observed_at: NOW - 5,
        response_commitment: canonical::sha256(b"canonical Stripe fixture response"),
    })
    .unwrap();
    let exact_configuration = StripeVerifierConfiguration::new(StripeVerifierConfigurationInput {
        allowed_test_account_ids: vec![account.clone()],
        allowed_api_versions: vec!["2025-04-30.basil".into()],
        allowed_currencies: vec![currency.clone()],
        maximum_refund_minor_by_currency: BTreeMap::from([(currency.clone(), 2_000)]),
        allowed_reasons: vec!["requested_by_customer".into()],
        maximum_evidence_age_seconds: 60,
        maximum_authorization_lifetime_seconds: 300,
        allow_partial_refunds: true,
        allow_refund_application_fee: false,
        allow_reverse_transfer: false,
        allowed_metadata_keys: vec![
            "auths_action".into(),
            "auths_policy".into(),
            "auths_workflow".into(),
        ],
        executor_audience: "https://stripe-executor.auths.dev".into(),
        receipt_schema_version: "auths.stripe.receipt/1".into(),
    })
    .unwrap();
    let policy = StripeBoundedRefundPolicyV1::new(StripeBoundedRefundPolicyInput {
        policy_id: "canonical-support-refunds".into(),
        valid_from: NOW - 60,
        expires_at: NOW + 3_600,
        allowed_test_account_ids: vec![account.clone()],
        allowed_currencies: vec![currency.clone()],
        allowed_reasons: vec!["requested_by_customer".into()],
        allowed_charge_ids: vec![charge.clone()],
        allowed_payment_intent_ids: vec![payment_intent.clone()],
        allowed_api_versions: vec!["2025-04-30.basil".into()],
        connect_scope: ConnectScope::PlatformOnly,
        maximum_evidence_age_seconds: 60,
        per_refund_absolute_minor_by_currency: BTreeMap::from([(currency.clone(), 1_500)]),
        relative_limit: RelativeRefundLimit::new(5_000, RefundDenominator::OriginalChargeAmount)
            .unwrap(),
        aggregate_budgets: vec![
            AggregateRefundBudget::new(
                "daily-support",
                currency.clone(),
                5_000,
                RefundBudgetWindow::Fixed {
                    starts_at: NOW - 3_600,
                    ends_at: NOW + 3_600,
                },
            )
            .unwrap(),
            AggregateRefundBudget::new(
                "rolling-hour",
                currency.clone(),
                2_500,
                RefundBudgetWindow::Rolling {
                    duration_seconds: 3_600,
                },
            )
            .unwrap(),
        ],
    })
    .unwrap();
    let bounded_configuration = StripeBoundedEvaluatorConfigurationV1::for_policy(
        &policy,
        "auths-stripe-fixture-build",
        exact_configuration.executor_audience(),
    )
    .unwrap();
    let workflow = "canonical-bounded-refund-01";
    let action = ExactRefundActionV1::new(ExactRefundActionInput {
        workflow_id: workflow.into(),
        executor_audience: exact_configuration.executor_audience().into(),
        stripe_account_id: account,
        stripe_api_version: evidence.stripe_api_version().into(),
        livemode: false,
        charge_id: charge,
        payment_intent_id: Some(payment_intent),
        amount: Money::new(currency, 1_000).unwrap(),
        reason: Some("requested_by_customer".into()),
        metadata: BTreeMap::from([
            ("auths_action".into(), "exact-refund".into()),
            ("auths_policy".into(), policy.digest().unwrap().to_string()),
            ("auths_workflow".into(), workflow.into()),
        ]),
        refund_application_fee: false,
        reverse_transfer: false,
        expected_charge_amount_minor: 2_000,
        expected_amount_refunded_minor: 0,
        expected_refundable_amount_minor: 2_000,
        evidence_digest: evidence.digest().unwrap(),
        required_configuration_digest: exact_configuration.digest().unwrap(),
        observed_at: NOW - 5,
        expires_at: NOW + 295,
        nonce: canonical::sha256(b"canonical bounded refund nonce"),
    })
    .unwrap();
    let snapshot = AggregateBudgetSnapshot::default();
    let decision = evaluate_bounded_refund(&BoundedEvaluationContext {
        policy: &policy,
        action: &action,
        evidence: &evidence,
        aggregate_snapshot: &snapshot,
        required_exact_configuration: &exact_configuration,
        executed_exact_configuration: &exact_configuration,
        required_bounded_configuration: &bounded_configuration,
        executed_bounded_configuration: &bounded_configuration,
        request_audience: exact_configuration.executor_audience(),
        now: NOW,
    });
    vec![
        ("policy.json", canonical::canonical_json(&policy).unwrap()),
        (
            "bounded-configuration.json",
            canonical::canonical_json(&bounded_configuration).unwrap(),
        ),
        (
            "exact-configuration.json",
            canonical::canonical_json(&exact_configuration).unwrap(),
        ),
        (
            "evidence.json",
            canonical::canonical_json(&evidence).unwrap(),
        ),
        ("exact-action.json", action.canonical_bytes().unwrap()),
        (
            "aggregate-snapshot.json",
            canonical::canonical_json(&snapshot).unwrap(),
        ),
        (
            "eligibility.json",
            canonical::canonical_json(&decision).unwrap(),
        ),
    ]
}

#[test]
fn canonical_bounded_refund_fixtures_are_exact_and_manifested() {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/v1");
    let update = std::env::var_os("AUTHS_UPDATE_STRIPE_FIXTURES").is_some();
    if update {
        fs::create_dir_all(&directory).unwrap();
    }
    let values = fixture_values();
    let mut manifest = BTreeMap::new();
    for (name, bytes) in values {
        manifest.insert(name, canonical::sha256(&bytes).to_string());
        let path = directory.join(name);
        if update {
            fs::write(&path, &bytes).unwrap();
        }
        assert_eq!(fs::read(path).unwrap(), bytes, "fixture drift: {name}");
    }
    let manifest_bytes = canonical::canonical_json(&manifest).unwrap();
    let manifest_path = directory.join("manifest.sha256.json");
    if update {
        fs::write(&manifest_path, &manifest_bytes).unwrap();
    }
    assert_eq!(fs::read(manifest_path).unwrap(), manifest_bytes);
}

#[test]
fn policy_fixture_rejects_unknown_fields() {
    let mut value: serde_json::Value = serde_json::from_slice(&fixture_values()[0].1).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unrecognized_authority".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<StripeBoundedRefundPolicyV1>(value).is_err());
}
