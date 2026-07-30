use std::{collections::BTreeMap, fs, path::PathBuf};

use auths_stripe::{
    Currency, CustomerId, MandateAmountType, MandateConnectAccount, MandateInterval, MandateUsage,
    PaymentConsentEvidenceInput, PaymentConsentEvidenceV1, PaymentMandateEvidenceInput,
    PaymentMandateEvidenceV1, StripeAccountId, StripeBoundedPaymentMandatePolicyInput,
    StripeBoundedPaymentMandatePolicyV1, StripeExactPaymentMandateInput,
    StripeExactPaymentMandateV1, StripePaymentMandateConfigurationV1,
    canonical::{canonical_json, sha256},
};

#[allow(
    clippy::too_many_lines,
    reason = "the generator keeps the canonical fixture family visibly co-located"
)]
fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/payment-mandate/v1");
    fs::create_dir_all(&root).expect("create fixture directory");
    let account = StripeAccountId::parse("acct_1234567890").unwrap();
    let customer = CustomerId::parse("cus_1234567890").unwrap();
    let method = auths_stripe::PaymentMethodId::parse("pm_1234567890").unwrap();
    let currency = Currency::parse("usd").unwrap();
    let terms = sha256(b"synthetic exact payment mandate terms v1");
    let policy = StripeBoundedPaymentMandatePolicyV1::new(StripeBoundedPaymentMandatePolicyInput {
        valid_from: 2_000_000_000,
        expires_at: 2_000_003_600,
        allowed_test_account_ids: vec![account.clone()],
        allowed_customer_ids: vec![customer.clone()],
        allowed_payment_method_ids: vec![method.clone()],
        allowed_payment_method_types: vec!["card".into()],
        allowed_usage_modes: vec![MandateUsage::OffSession],
        allowed_currencies: vec![currency.clone()],
        allowed_intervals: vec![MandateInterval::Monthly],
        per_future_charge_minor_by_currency: BTreeMap::from([(currency.clone(), 500)]),
        maximum_active_mandates_per_customer: 3,
        maximum_consent_age_seconds: 300,
        maximum_evidence_age_seconds: 120,
        maximum_action_lifetime_seconds: 300,
        required_consent_assurance: 2,
        allowed_api_versions: vec!["2025-04-30.basil".into()],
    })
    .unwrap();
    let configuration = StripePaymentMandateConfigurationV1::new(
        &policy,
        account.clone(),
        MandateConnectAccount::Platform,
        "auths-stripe-mandate-human-session-v1".into(),
        "2025-04-30.basil".into(),
        "https://stripe-mandate-executor.auths.dev".into(),
    )
    .unwrap();
    let consent = PaymentConsentEvidenceV1::new(PaymentConsentEvidenceInput {
        customer_id: customer.clone(),
        payment_method_commitment: sha256(method.as_str().as_bytes()),
        stripe_account_id: account.clone(),
        connect_account: MandateConnectAccount::Platform,
        usage: MandateUsage::OffSession,
        mandate_amount_type: MandateAmountType::Maximum,
        mandate_amount_minor: 500,
        currency: currency.clone(),
        interval: MandateInterval::Monthly,
        reference: "membership-fixture".into(),
        displayed_terms_digest: terms.clone(),
        accepted_at: 2_000_000_000,
        expires_at: 2_000_000_300,
        consent_principal: "trusted-human-fixture".into(),
        consent_assurance: 2,
        synthetic_test_consent: true,
    })
    .unwrap();
    let evidence = PaymentMandateEvidenceV1::new(PaymentMandateEvidenceInput {
        stripe_account_id: account.clone(),
        connect_account: MandateConnectAccount::Platform,
        customer_id: customer.clone(),
        customer_exists: true,
        payment_method_id: method.clone(),
        payment_method_type: "card".into(),
        payment_method_customer_id: customer.clone(),
        existing_setup_intent_ids: Vec::new(),
        active_mandate_count: 0,
        duplicate_scope_exists: false,
        ambiguous_setup_exists: false,
        stripe_api_version: "2025-04-30.basil".into(),
        livemode: false,
        observed_at: 2_000_000_010,
        source: "stripe-test-fixture".into(),
        response_commitment: sha256(b"fixture-customer-payment-method-response"),
    })
    .unwrap();
    let action = StripeExactPaymentMandateV1::new(StripeExactPaymentMandateInput {
        stripe_account_id: account,
        connect_account: MandateConnectAccount::Platform,
        customer_id: customer,
        payment_method_id: method,
        payment_method_type: "card".into(),
        usage: MandateUsage::OffSession,
        mandate_amount_type: MandateAmountType::Maximum,
        mandate_amount_minor: 500,
        currency,
        interval: MandateInterval::Monthly,
        reference: "membership-fixture".into(),
        consent_evidence_digest: consent.digest().unwrap(),
        displayed_terms_digest: terms,
        on_behalf_of: None,
        return_url_commitment: None,
        stripe_api_version: "2025-04-30.basil".into(),
        required_policy_digest: policy.digest().unwrap(),
        required_configuration_digest: configuration.digest().unwrap(),
        executor_audience: "https://stripe-mandate-executor.auths.dev".into(),
        expires_at: 2_000_000_300,
        nonce: sha256(b"payment-mandate-fixture-nonce"),
    })
    .unwrap();
    let values = [
        ("action.json", canonical_json(&action).unwrap()),
        (
            "configuration.json",
            canonical_json(&configuration).unwrap(),
        ),
        ("consent.json", canonical_json(&consent).unwrap()),
        ("evidence.json", canonical_json(&evidence).unwrap()),
        ("policy.json", canonical_json(&policy).unwrap()),
        (
            "stable-codes.json",
            canonical_json(&serde_json::json!({
                "codes": [
                    "payment-mandate-authorized",
                    "payment-mandate-consent-required",
                    "payment-mandate-consent-mismatch",
                    "payment-mandate-scope-exceeded",
                    "payment-mandate-capacity-exceeded",
                    "payment-mandate-customer-action-required",
                    "payment-mandate-provider-failed",
                    "payment-mandate-outcome-unknown",
                    "bounded-configuration-mismatch",
                    "bounded-evidence-stale"
                ]
            }))
            .unwrap(),
        ),
    ];
    let mut manifest = BTreeMap::new();
    for (name, bytes) in values {
        manifest.insert(name.to_owned(), sha256(&bytes));
        fs::write(root.join(name), bytes).expect("write canonical fixture");
    }
    fs::write(
        root.join("manifest.sha256.json"),
        canonical_json(&manifest).unwrap(),
    )
    .expect("write manifest");
}
