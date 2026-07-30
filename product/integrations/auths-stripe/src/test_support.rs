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

#[allow(
    clippy::too_many_lines,
    reason = "the shared test policy keeps every bounded dimension explicit"
)]
pub fn merchant_policy(
    operation: crate::merchant::MerchantOperation,
    operation_limit: u64,
    aggregate_limit: u64,
) -> crate::merchant::StripeBoundedMerchantPaymentPolicyV1 {
    use crate::merchant::{
        MerchantAggregateBudget, MerchantBudgetWindow, MerchantConnectAccount,
        StripeBoundedMerchantPaymentPolicyInput, StripeBoundedMerchantPaymentPolicyV1,
    };
    use crate::types::{CustomerId, PaymentMethodId};

    let currency = Currency::parse("usd").unwrap();
    let money_operation = operation != crate::merchant::MerchantOperation::Cancel;
    StripeBoundedMerchantPaymentPolicyV1::new(StripeBoundedMerchantPaymentPolicyInput {
        policy_id: "merchant-payments-v1".into(),
        valid_from: NOW - 60,
        expires_at: NOW + 3_600,
        allowed_operations: vec![operation],
        allowed_test_account_ids: vec![StripeAccountId::parse("acct_authsdemo01").unwrap()],
        allowed_connect_accounts: vec![MerchantConnectAccount::Platform],
        allowed_customer_ids: vec![CustomerId::parse("cus_authsdemo00000001").unwrap()],
        allowed_payment_method_ids: if matches!(
            operation,
            crate::merchant::MerchantOperation::Collect
                | crate::merchant::MerchantOperation::Authorize
        ) {
            vec![PaymentMethodId::parse("pm_authsdemo000000001").unwrap()]
        } else {
            Vec::new()
        },
        allowed_payment_method_types: if matches!(
            operation,
            crate::merchant::MerchantOperation::Collect
                | crate::merchant::MerchantOperation::Authorize
        ) {
            vec!["card".into()]
        } else {
            Vec::new()
        },
        allowed_currencies: money_operation
            .then(|| currency.clone())
            .into_iter()
            .collect(),
        allowed_order_scopes: vec!["order-demo-001".into()],
        allowed_cancellation_reasons: if operation == crate::merchant::MerchantOperation::Cancel {
            vec![
                "abandoned".into(),
                "duplicate".into(),
                "fraudulent".into(),
                "requested_by_customer".into(),
            ]
        } else {
            Vec::new()
        },
        per_operation_absolute_minor_by_currency: if money_operation {
            BTreeMap::from([(
                operation,
                BTreeMap::from([(currency.clone(), operation_limit)]),
            )])
        } else {
            BTreeMap::new()
        },
        per_customer_minor_by_currency: if money_operation {
            BTreeMap::from([(currency.clone(), operation_limit)])
        } else {
            BTreeMap::new()
        },
        per_order_minor_by_currency: if money_operation {
            BTreeMap::from([(currency.clone(), operation_limit)])
        } else {
            BTreeMap::new()
        },
        aggregate_budgets: if money_operation {
            vec![
                MerchantAggregateBudget::new(
                    "merchant-daily",
                    operation,
                    currency,
                    aggregate_limit,
                    MerchantBudgetWindow::Fixed {
                        starts_at: NOW - 3_600,
                        ends_at: NOW + 3_600,
                    },
                    NOW,
                )
                .unwrap(),
            ]
        } else {
            Vec::new()
        },
        maximum_authorization_age_seconds: if matches!(
            operation,
            crate::merchant::MerchantOperation::Authorize
                | crate::merchant::MerchantOperation::Capture
        ) {
            7 * 24 * 60 * 60
        } else {
            0
        },
        minimum_capture_window_seconds: if matches!(
            operation,
            crate::merchant::MerchantOperation::Authorize
                | crate::merchant::MerchantOperation::Capture
        ) {
            60
        } else {
            0
        },
        maximum_evidence_age_seconds: 60,
        maximum_action_lifetime_seconds: 300,
        allowed_api_versions: vec!["2025-04-30.basil".into()],
    })
    .unwrap()
}

pub fn merchant_configuration(
    policy: &crate::merchant::StripeBoundedMerchantPaymentPolicyV1,
) -> crate::merchant::StripeMerchantEvaluatorConfigurationV1 {
    crate::merchant::StripeMerchantEvaluatorConfigurationV1::for_collect_policy(
        policy,
        "auths-stripe-merchant-test-build",
        StripeAccountId::parse("acct_authsdemo01").unwrap(),
        crate::merchant::MerchantConnectAccount::Platform,
        "2025-04-30.basil",
        "https://stripe-collect.auths.dev",
    )
    .unwrap()
}

pub fn merchant_authorize_configuration(
    policy: &crate::merchant::StripeBoundedMerchantPaymentPolicyV1,
) -> crate::merchant::StripeMerchantEvaluatorConfigurationV1 {
    crate::merchant::StripeMerchantEvaluatorConfigurationV1::for_authorize_policy(
        policy,
        "auths-stripe-merchant-test-build",
        StripeAccountId::parse("acct_authsdemo01").unwrap(),
        crate::merchant::MerchantConnectAccount::Platform,
        "2025-04-30.basil",
        "https://stripe-authorize.auths.dev",
    )
    .unwrap()
}

pub fn merchant_capture_configuration(
    policy: &crate::merchant::StripeBoundedMerchantPaymentPolicyV1,
) -> crate::merchant::StripeMerchantEvaluatorConfigurationV1 {
    crate::merchant::StripeMerchantEvaluatorConfigurationV1::for_capture_policy(
        policy,
        "auths-stripe-merchant-test-build",
        StripeAccountId::parse("acct_authsdemo01").unwrap(),
        crate::merchant::MerchantConnectAccount::Platform,
        "2025-04-30.basil",
        "https://stripe-capture.auths.dev",
    )
    .unwrap()
}

pub fn merchant_cancel_configuration(
    policy: &crate::merchant::StripeBoundedMerchantPaymentPolicyV1,
) -> crate::merchant::StripeMerchantEvaluatorConfigurationV1 {
    crate::merchant::StripeMerchantEvaluatorConfigurationV1::for_cancel_policy(
        policy,
        "auths-stripe-merchant-test-build",
        StripeAccountId::parse("acct_authsdemo01").unwrap(),
        crate::merchant::MerchantConnectAccount::Platform,
        "2025-04-30.basil",
        "https://stripe-cancel.auths.dev",
    )
    .unwrap()
}

pub fn merchant_evidence() -> crate::merchant::MerchantPaymentEvidenceV1 {
    use crate::{
        merchant::{
            MerchantConnectAccount, MerchantPaymentEvidenceInput, MerchantPaymentEvidenceV1,
        },
        types::{CustomerId, PaymentMethodId},
    };
    let customer = CustomerId::parse("cus_authsdemo00000001").unwrap();
    MerchantPaymentEvidenceV1::new(MerchantPaymentEvidenceInput {
        stripe_account_id: StripeAccountId::parse("acct_authsdemo01").unwrap(),
        connect_account: MerchantConnectAccount::Platform,
        customer_id: customer.clone(),
        payment_method_id: PaymentMethodId::parse("pm_authsdemo000000001").unwrap(),
        payment_method_type: "card".into(),
        attached_customer_id: customer,
        livemode: false,
        stripe_api_version: "2025-04-30.basil".into(),
        order_scope: "order-demo-001".into(),
        consent_order_commitment: sha256(b"merchant consent order"),
        supports_manual_capture: true,
        prior_payments: Vec::new(),
        observed_at: NOW - 5,
        source: "stripe-api-and-order-store".into(),
        response_commitment: sha256(b"sanitized merchant evidence"),
    })
    .unwrap()
}

pub fn merchant_collect_action(
    workflow_id: &str,
    policy: &crate::merchant::StripeBoundedMerchantPaymentPolicyV1,
    configuration: &crate::merchant::StripeMerchantEvaluatorConfigurationV1,
    amount_minor: u64,
) -> crate::merchant::StripeExactPaymentCollectV1 {
    use crate::{
        merchant::{
            MerchantConnectAccount, StripeExactPaymentCollectInput, StripeExactPaymentCollectV1,
            fixed_merchant_metadata_commitment, merchant_statement_descriptor_commitment,
        },
        types::{CustomerId, PaymentMethodId},
    };
    let policy_digest = policy.digest().unwrap();
    StripeExactPaymentCollectV1::new(StripeExactPaymentCollectInput {
        stripe_account_id: StripeAccountId::parse("acct_authsdemo01").unwrap(),
        connect_account: MerchantConnectAccount::Platform,
        customer_id: CustomerId::parse("cus_authsdemo00000001").unwrap(),
        payment_method_id: PaymentMethodId::parse("pm_authsdemo000000001").unwrap(),
        payment_method_type: "card".into(),
        order_scope: "order-demo-001".into(),
        amount_minor,
        currency: Currency::parse("usd").unwrap(),
        statement_descriptor_commitment: merchant_statement_descriptor_commitment(),
        fixed_metadata_commitment: fixed_merchant_metadata_commitment(
            workflow_id,
            crate::merchant::PAYMENT_COLLECT_PROFILE,
            "order-demo-001",
            &policy_digest,
        )
        .unwrap(),
        stripe_api_version: "2025-04-30.basil".into(),
        required_policy_digest: policy_digest,
        required_configuration_digest: configuration.digest().unwrap(),
        executor_audience: configuration.executor_audience().into(),
        expires_at: NOW + 120,
        nonce: sha256(workflow_id.as_bytes()),
    })
    .unwrap()
}

pub fn merchant_authorize_action(
    workflow_id: &str,
    policy: &crate::merchant::StripeBoundedMerchantPaymentPolicyV1,
    configuration: &crate::merchant::StripeMerchantEvaluatorConfigurationV1,
    amount_minor: u64,
) -> crate::merchant::StripeExactPaymentAuthorizeV1 {
    use crate::{
        merchant::{
            MerchantConnectAccount, StripeExactPaymentAuthorizeInput,
            StripeExactPaymentAuthorizeV1, fixed_merchant_metadata_commitment,
            merchant_statement_descriptor_commitment,
        },
        types::{CustomerId, PaymentMethodId},
    };
    let policy_digest = policy.digest().unwrap();
    StripeExactPaymentAuthorizeV1::new(StripeExactPaymentAuthorizeInput {
        stripe_account_id: StripeAccountId::parse("acct_authsdemo01").unwrap(),
        connect_account: MerchantConnectAccount::Platform,
        customer_id: CustomerId::parse("cus_authsdemo00000001").unwrap(),
        payment_method_id: PaymentMethodId::parse("pm_authsdemo000000001").unwrap(),
        payment_method_type: "card".into(),
        order_scope: "order-demo-001".into(),
        authorized_amount_minor: amount_minor,
        currency: Currency::parse("usd").unwrap(),
        statement_descriptor_commitment: merchant_statement_descriptor_commitment(),
        fixed_metadata_commitment: fixed_merchant_metadata_commitment(
            workflow_id,
            crate::merchant::PAYMENT_AUTHORIZE_PROFILE,
            "order-demo-001",
            &policy_digest,
        )
        .unwrap(),
        stripe_api_version: "2025-04-30.basil".into(),
        required_policy_digest: policy_digest,
        required_configuration_digest: configuration.digest().unwrap(),
        executor_audience: configuration.executor_audience().into(),
        expires_at: NOW + 120,
        nonce: sha256(workflow_id.as_bytes()),
    })
    .unwrap()
}

pub fn merchant_capture_evidence() -> crate::merchant::PaymentCaptureEvidenceV1 {
    use crate::{
        merchant::{
            MerchantConnectAccount, MerchantReservationState, PaymentCaptureEvidenceInput,
            PaymentCaptureEvidenceV1,
        },
        types::{CustomerId, PaymentIntentId},
    };
    PaymentCaptureEvidenceV1::new(PaymentCaptureEvidenceInput {
        stripe_account_id: StripeAccountId::parse("acct_authsdemo01").unwrap(),
        connect_account: MerchantConnectAccount::Platform,
        payment_intent_id: PaymentIntentId::parse("pi_capturedemo00000001").unwrap(),
        latest_charge_id: ChargeId::parse("ch_capturedemo00000001").unwrap(),
        customer_id: CustomerId::parse("cus_authsdemo00000001").unwrap(),
        order_scope: "order-demo-001".into(),
        authorized_amount_minor: 1_000,
        amount_capturable_minor: 1_000,
        amount_captured_minor: 0,
        currency: Currency::parse("usd").unwrap(),
        payment_intent_status: "requires_capture".into(),
        capture_before: NOW + 3_600,
        livemode: false,
        stripe_api_version: "2025-04-30.basil".into(),
        authorization_workflow_id: "merchant-authorization-capture-source".into(),
        authorization_action_digest: sha256(b"capture-authorization-action"),
        authorization_reservation_id: sha256(b"capture-authorization-reservation"),
        authorization_state: MerchantReservationState::Authorized,
        authorization_created_at: NOW - 60,
        observed_at: NOW - 5,
        source: "stripe-api-and-auths-store".into(),
        response_commitment: sha256(b"capture-evidence"),
    })
    .unwrap()
}

pub fn merchant_capture_action(
    workflow_id: &str,
    policy: &crate::merchant::StripeBoundedMerchantPaymentPolicyV1,
    configuration: &crate::merchant::StripeMerchantEvaluatorConfigurationV1,
    amount_minor: u64,
) -> crate::merchant::StripeExactPaymentCaptureV1 {
    use crate::{
        merchant::{
            MerchantConnectAccount, StripeExactPaymentCaptureInput, StripeExactPaymentCaptureV1,
            fixed_merchant_metadata_commitment, merchant_statement_descriptor_commitment,
        },
        types::{CustomerId, PaymentIntentId},
    };
    let evidence = merchant_capture_evidence();
    let policy_digest = policy.digest().unwrap();
    StripeExactPaymentCaptureV1::new(StripeExactPaymentCaptureInput {
        stripe_account_id: StripeAccountId::parse("acct_authsdemo01").unwrap(),
        connect_account: MerchantConnectAccount::Platform,
        payment_intent_id: PaymentIntentId::parse("pi_capturedemo00000001").unwrap(),
        latest_charge_id: ChargeId::parse("ch_capturedemo00000001").unwrap(),
        customer_id: CustomerId::parse("cus_authsdemo00000001").unwrap(),
        order_scope: "order-demo-001".into(),
        authorized_amount_minor: 1_000,
        amount_capturable_before_minor: 1_000,
        amount_to_capture_minor: amount_minor,
        currency: Currency::parse("usd").unwrap(),
        statement_descriptor_commitment: merchant_statement_descriptor_commitment(),
        fixed_metadata_commitment: fixed_merchant_metadata_commitment(
            workflow_id,
            crate::merchant::PAYMENT_CAPTURE_PROFILE,
            "order-demo-001",
            &policy_digest,
        )
        .unwrap(),
        authorization_action_digest: evidence.authorization_action_digest().clone(),
        authorization_reservation_id: evidence.authorization_reservation_id().clone(),
        stripe_api_version: "2025-04-30.basil".into(),
        required_policy_digest: policy_digest,
        required_configuration_digest: configuration.digest().unwrap(),
        executor_audience: configuration.executor_audience().into(),
        expires_at: NOW + 120,
        nonce: sha256(workflow_id.as_bytes()),
    })
    .unwrap()
}
