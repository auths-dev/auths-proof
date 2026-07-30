use std::{collections::BTreeMap, fs, path::PathBuf};

use auths_stripe::{
    AggregatePayoutBudget, Currency, ExternalAccountId, PayoutApprovalEvidence,
    PayoutApprovalThreshold, PayoutBudgetScope, StripeAccountId, StripeBoundedPayoutPolicyInput,
    StripeBoundedPayoutPolicyV1, StripeExactPayoutInput, StripeExactPayoutV1,
    StripePayoutConfigurationV1,
};
use serde::Serialize;

#[allow(
    clippy::too_many_lines,
    reason = "the generator keeps every canonical payout commitment visible"
)]
fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/payout/v1");
    fs::create_dir_all(&root).unwrap();
    let now = 2_100_600_000;
    let account = StripeAccountId::parse("acct_payoutfixture").unwrap();
    let destination = ExternalAccountId::parse("ba_payoutfixture").unwrap();
    let currency = Currency::parse("usd").unwrap();
    let destination_type = auths_stripe::canonical::sha256(b"bank-account");
    let approvals = vec![
        PayoutApprovalEvidence {
            commitment: auths_stripe::canonical::sha256(b"approval-one"),
            principal_commitment: auths_stripe::canonical::sha256(b"principal-one"),
            approver_scope: "finance-payout".into(),
            assurance: 2,
            expires_at: now + 300,
        },
        PayoutApprovalEvidence {
            commitment: auths_stripe::canonical::sha256(b"approval-two"),
            principal_commitment: auths_stripe::canonical::sha256(b"principal-two"),
            approver_scope: "finance-payout".into(),
            assurance: 2,
            expires_at: now + 300,
        },
    ];
    let policy = StripeBoundedPayoutPolicyV1::new(StripeBoundedPayoutPolicyInput {
        policy_id: "payout-fixture".into(),
        valid_from: now - 60,
        expires_at: now + 3_600,
        allowed_test_account_ids: vec![account.clone()],
        allowed_external_destination_ids: vec![destination.clone()],
        allowed_destination_type_commitments: vec![destination_type.clone()],
        allowed_currencies: vec![currency.clone()],
        allowed_source_types: vec!["bank_account".into()],
        allowed_business_scopes: vec!["supplier-settlement".into()],
        per_payout_minor_by_currency: BTreeMap::from([(currency.clone(), 500)]),
        per_destination_minor_by_currency: BTreeMap::from([(currency.clone(), 1_000)]),
        aggregate_budgets: vec![AggregatePayoutBudget {
            budget_id: "payout-global".into(),
            scope: PayoutBudgetScope::Global,
            currency: currency.clone(),
            limit_minor: 2_000,
            starts_at: now - 60,
            ends_at: now + 3_600,
        }],
        approval_thresholds: vec![PayoutApprovalThreshold {
            currency: currency.clone(),
            amount_minor: 500,
            required_assurance: 2,
            required_approver_scope: "finance-payout".into(),
            required_distinct_principals: 2,
        }],
        minimum_available_balance_after_minor_by_currency: BTreeMap::from([(
            currency.clone(),
            500,
        )]),
        maximum_balance_evidence_age_seconds: 60,
        maximum_destination_evidence_age_seconds: 60,
        maximum_action_lifetime_seconds: 300,
        allowed_api_versions: vec!["2025-04-30.basil".into()],
    })
    .unwrap();
    let configuration = StripePayoutConfigurationV1::new(
        &policy,
        account.clone(),
        "bank_account".into(),
        "2025-04-30.basil".into(),
        "https://stripe-payout.auths.dev".into(),
    )
    .unwrap();
    let action = StripeExactPayoutV1::new(StripeExactPayoutInput {
        stripe_account_id: account.clone(),
        destination_external_account_id: destination.clone(),
        destination_type_commitment: destination_type.clone(),
        business_scope: "supplier-settlement".into(),
        amount_minor: 500,
        currency: currency.clone(),
        source_type: "bank_account".into(),
        description_commitment: auths_stripe::canonical::sha256(b"supplier payout"),
        statement_descriptor_commitment: auths_stripe::canonical::sha256(b"AUTHS SUPPLIER"),
        required_approval_commitments: approvals
            .iter()
            .map(|approval| approval.commitment.clone())
            .collect(),
        stripe_api_version: "2025-04-30.basil".into(),
        required_policy_digest: policy.digest().unwrap(),
        required_configuration_digest: configuration.digest().unwrap(),
        executor_audience: "https://stripe-payout.auths.dev".into(),
        expires_at: now + 120,
        nonce: auths_stripe::canonical::sha256(b"payout-nonce"),
    })
    .unwrap();
    let evidence = auths_stripe::PayoutEvidenceV1 {
        schema: "auths.stripe.payout-evidence/1".into(),
        stripe_account_id: account,
        livemode: false,
        manual_payouts_enabled: true,
        available_balance_minor: 2_000,
        pending_balance_minor: 250,
        currency,
        source_type: "bank_account".into(),
        destination_external_account_id: destination,
        destination_type_commitment: destination_type,
        destination_fingerprint_commitment: auths_stripe::canonical::sha256(
            b"redacted-fingerprint",
        ),
        destination_status: "verified".into(),
        destination_observed_at: now,
        existing_pending_payout_minor: 0,
        approvals,
        stripe_api_version: "2025-04-30.basil".into(),
        balance_observed_at: now,
        response_digest: auths_stripe::canonical::sha256(b"payout-evidence-response"),
        source: "stripe-api-and-approval-store".into(),
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
            "available_balance_before_minor": 2000,
            "minimum_retained_minor": 500,
            "available_after_minor": 1500,
            "per_payout_limit_minor": 500,
            "per_destination_limit_minor": 1000,
            "distinct_approvers": 2,
            "manual_standard_only": true
        }),
    );
    write(
        &root,
        "stable-codes.json",
        &vec![
            "payout-authorized",
            "payout-destination-denied",
            "payout-destination-unavailable",
            "payout-method-denied",
            "payout-limit-exceeded",
            "payout-minimum-balance-violated",
            "payout-approval-required",
            "payout-balance-insufficient",
            "payout-pending",
            "payout-failed",
            "payout-outcome-unknown",
            "payout-configuration-mismatch",
            "payout-evidence-invalid",
            "payout-evidence-stale",
            "payout-replay",
            "payout-arithmetic-failure",
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
