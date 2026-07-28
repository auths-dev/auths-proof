use std::collections::BTreeMap;

use crate::{
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
        allowed_metadata_keys: vec!["auths_action".into(), "auths_workflow".into()],
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
        currency: Currency::parse("usd").unwrap(),
        charge_amount_minor: charge_amount,
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
