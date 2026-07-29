use std::collections::BTreeMap;

use crate::{
    bounded::{
        AggregateRefundBudget, ConnectScope, RefundBudgetWindow, RefundDenominator,
        RelativeRefundLimit, StripeBoundedEvaluatorConfigurationV1, StripeBoundedRefundPolicyInput,
        StripeBoundedRefundPolicyV1,
    },
    canonical::sha256,
    types::{
        ChargeId, Currency, ExactRefundActionInput, ExactRefundActionV1, Money, PaymentIntentId,
        RefundEvidenceInput, RefundEvidenceV1, StripeAccountId, StripeVerifierConfiguration,
        StripeVerifierConfigurationInput,
    },
};

pub const NOW: u64 = 1_800_000_000;

pub fn configuration(maximum_usd: u64) -> StripeVerifierConfiguration {
    StripeVerifierConfiguration::new(StripeVerifierConfigurationInput {
        allowed_test_account_ids: vec![StripeAccountId::parse("acct_authsdemo01").unwrap()],
        allowed_api_versions: vec!["2025-04-30.basil".into()],
        allowed_currencies: vec![Currency::parse("usd").unwrap()],
        maximum_refund_minor_by_currency: BTreeMap::from([(
            Currency::parse("usd").unwrap(),
            maximum_usd,
        )]),
        allowed_reasons: vec!["requested_by_customer".into()],
        maximum_evidence_age_seconds: 60,
        maximum_authorization_lifetime_seconds: 300,
        allow_partial_refunds: true,
        allow_refund_application_fee: false,
        allow_reverse_transfer: false,
        allowed_metadata_keys: vec![
            "auths_action".into(),
            "auths_connect_account".into(),
            "auths_policy".into(),
            "auths_workflow".into(),
        ],
        executor_audience: "https://stripe-executor.auths.dev".into(),
        receipt_schema_version: "auths.stripe.receipt/1".into(),
    })
    .unwrap()
}

pub fn evidence(charge_amount: u64, amount_refunded: u64) -> RefundEvidenceV1 {
    RefundEvidenceV1::new(RefundEvidenceInput {
        stripe_account_id: StripeAccountId::parse("acct_authsdemo01").unwrap(),
        stripe_api_version: "2025-04-30.basil".into(),
        livemode: false,
        charge_id: ChargeId::parse("ch_authsdemo00000001").unwrap(),
        payment_intent_id: Some(PaymentIntentId::parse("pi_authsdemo00000001").unwrap()),
        connect_account_id: None,
        currency: Currency::parse("usd").unwrap(),
        charge_amount_minor: charge_amount,
        captured_amount_minor: charge_amount,
        amount_refunded_minor: amount_refunded,
        paid: true,
        captured: true,
        charge_refunded: amount_refunded == charge_amount,
        disputed: false,
        observed_at: NOW - 5,
        response_commitment: sha256(b"bounded normalized Stripe response"),
    })
    .unwrap()
}

pub fn action(
    configuration: &StripeVerifierConfiguration,
    evidence: &RefundEvidenceV1,
    amount: u64,
) -> ExactRefundActionV1 {
    ExactRefundActionV1::new(ExactRefundActionInput {
        workflow_id: "stripe-demo-workflow-01".into(),
        executor_audience: configuration.executor_audience().into(),
        stripe_account_id: evidence.stripe_account_id().clone(),
        stripe_api_version: evidence.stripe_api_version().into(),
        livemode: evidence.livemode(),
        charge_id: evidence.charge_id().clone(),
        payment_intent_id: evidence.payment_intent_id().cloned(),
        amount: Money::new(evidence.currency().clone(), amount).unwrap(),
        reason: Some("requested_by_customer".into()),
        metadata: BTreeMap::from([
            ("auths_action".into(), "exact-refund".into()),
            ("auths_workflow".into(), "stripe-demo-workflow-01".into()),
        ]),
        refund_application_fee: false,
        reverse_transfer: false,
        expected_charge_amount_minor: evidence.charge_amount_minor(),
        expected_amount_refunded_minor: evidence.amount_refunded_minor(),
        expected_refundable_amount_minor: evidence.refundable_amount_minor(),
        evidence_digest: evidence.digest().unwrap(),
        required_configuration_digest: configuration.digest().unwrap(),
        observed_at: evidence.observed_at(),
        expires_at: evidence.observed_at() + 300,
        nonce: sha256(b"stripe-demo-nonce"),
    })
    .unwrap()
}

pub fn bounded_policy(
    evidence: &RefundEvidenceV1,
    absolute_limit: u64,
    basis_points: u16,
    denominator: RefundDenominator,
    aggregate_limit: u64,
) -> StripeBoundedRefundPolicyV1 {
    let mut input = bounded_policy_input(evidence);
    input.per_refund_absolute_minor_by_currency =
        BTreeMap::from([(evidence.currency().clone(), absolute_limit)]);
    input.relative_limit = RelativeRefundLimit::new(basis_points, denominator).unwrap();
    input.aggregate_budgets = vec![
        AggregateRefundBudget::new(
            "support-daily",
            evidence.currency().clone(),
            aggregate_limit,
            RefundBudgetWindow::Fixed {
                starts_at: NOW - 3_600,
                ends_at: NOW + 3_600,
            },
        )
        .unwrap(),
    ];
    StripeBoundedRefundPolicyV1::new(input).unwrap()
}

pub fn bounded_policy_input(evidence: &RefundEvidenceV1) -> StripeBoundedRefundPolicyInput {
    StripeBoundedRefundPolicyInput {
        policy_id: "support-refunds-v1".into(),
        valid_from: NOW - 60,
        expires_at: NOW + 3_600,
        allowed_test_account_ids: vec![evidence.stripe_account_id().clone()],
        allowed_currencies: vec![evidence.currency().clone()],
        allowed_reasons: vec!["requested_by_customer".into()],
        allowed_charge_ids: vec![evidence.charge_id().clone()],
        allowed_payment_intent_ids: vec![evidence.payment_intent_id().unwrap().clone()],
        allowed_api_versions: vec![evidence.stripe_api_version().into()],
        connect_scope: ConnectScope::PlatformOnly,
        maximum_evidence_age_seconds: 60,
        per_refund_absolute_minor_by_currency: BTreeMap::from([(
            evidence.currency().clone(),
            2_000,
        )]),
        relative_limit: RelativeRefundLimit::new(10_000, RefundDenominator::OriginalChargeAmount)
            .unwrap(),
        aggregate_budgets: vec![
            AggregateRefundBudget::new(
                "support-daily",
                evidence.currency().clone(),
                5_000,
                RefundBudgetWindow::Fixed {
                    starts_at: NOW - 3_600,
                    ends_at: NOW + 3_600,
                },
            )
            .unwrap(),
        ],
    }
}

pub fn bounded_configuration(
    policy: &StripeBoundedRefundPolicyV1,
) -> StripeBoundedEvaluatorConfigurationV1 {
    StripeBoundedEvaluatorConfigurationV1::for_policy(
        policy,
        "auths-stripe-test-build",
        "https://stripe-executor.auths.dev",
    )
    .unwrap()
}

pub fn bounded_action(
    configuration: &StripeVerifierConfiguration,
    policy: &StripeBoundedRefundPolicyV1,
    evidence: &RefundEvidenceV1,
    amount: u64,
    workflow_id: &str,
) -> ExactRefundActionV1 {
    ExactRefundActionV1::new(ExactRefundActionInput {
        workflow_id: workflow_id.into(),
        executor_audience: configuration.executor_audience().into(),
        stripe_account_id: evidence.stripe_account_id().clone(),
        stripe_api_version: evidence.stripe_api_version().into(),
        livemode: evidence.livemode(),
        charge_id: evidence.charge_id().clone(),
        payment_intent_id: evidence.payment_intent_id().cloned(),
        amount: Money::new(evidence.currency().clone(), amount).unwrap(),
        reason: Some("requested_by_customer".into()),
        metadata: BTreeMap::from([
            ("auths_action".into(), "exact-refund".into()),
            (
                "auths_connect_account".into(),
                evidence
                    .connect_account_id()
                    .map_or_else(|| "platform".into(), ToString::to_string),
            ),
            ("auths_policy".into(), policy.digest().unwrap().to_string()),
            ("auths_workflow".into(), workflow_id.into()),
        ]),
        refund_application_fee: false,
        reverse_transfer: false,
        expected_charge_amount_minor: evidence.charge_amount_minor(),
        expected_amount_refunded_minor: evidence.amount_refunded_minor(),
        expected_refundable_amount_minor: evidence.refundable_amount_minor(),
        evidence_digest: evidence.digest().unwrap(),
        required_configuration_digest: configuration.digest().unwrap(),
        observed_at: evidence.observed_at(),
        expires_at: evidence.observed_at() + 300,
        nonce: sha256(workflow_id.as_bytes()),
    })
    .unwrap()
}
