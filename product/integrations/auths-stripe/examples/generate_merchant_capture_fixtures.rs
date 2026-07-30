use std::{collections::BTreeMap, fs, path::PathBuf};

use auths_stripe::{
    ChargeId, Currency, CustomerId, InMemoryMerchantPaymentStore, MerchantAggregateBudget,
    MerchantAggregateSnapshot, MerchantBudgetWindow, MerchantCaptureDecisionReceipt,
    MerchantCaptureObservationReceipt, MerchantCaptureTransitionReceipt, MerchantConnectAccount,
    MerchantOperation, MerchantPaymentStore, MerchantProviderProjection, MerchantReservationIntent,
    MerchantReservationState, PaymentCaptureEvaluationContext, PaymentCaptureEvidenceInput,
    PaymentCaptureEvidenceV1, PaymentCaptureProviderProjection, PaymentIntentId, PaymentMethodId,
    ReserveMerchantPaymentRequest, ReserveMerchantPaymentResult, ReservePaymentCaptureRequest,
    StripeAccountId, StripeBoundedMerchantPaymentPolicyInput, StripeBoundedMerchantPaymentPolicyV1,
    StripeExactPaymentCaptureInput, StripeExactPaymentCaptureV1,
    StripeMerchantEvaluatorConfigurationV1,
    canonical::{canonical_json, sha256},
    evaluate_payment_capture, fixed_merchant_metadata_commitment,
    merchant_statement_descriptor_commitment,
};
use serde_json::json;

const NOW: u64 = 1_800_000_000;
const AUTHORIZATION_WORKFLOW: &str = "capture-fixture-authorization";
const CAPTURE_WORKFLOW: &str = "capture-fixture-workflow";

#[allow(
    clippy::too_many_lines,
    reason = "the generator writes the complete canonical profile corpus explicitly"
)]
fn main() {
    let output = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/merchant-capture/v1");
    fs::create_dir_all(&output).expect("fixture directory");

    let account = StripeAccountId::parse("acct_capturefixture001").expect("account");
    let customer = CustomerId::parse("cus_capturefixture0000001").expect("customer");
    let payment_intent =
        PaymentIntentId::parse("pi_capturefixture00000001").expect("payment intent");
    let charge = ChargeId::parse("ch_capturefixture00000001").expect("charge");
    let currency = Currency::parse("usd").expect("currency");
    let connect = MerchantConnectAccount::Platform;
    let authorization_action_digest = sha256(b"exact authorization action fixture");

    let authorization_policy = policy(
        MerchantOperation::Authorize,
        &account,
        &customer,
        &currency,
        1_000,
    );
    let authorization_policy_digest = authorization_policy.digest().expect("policy digest");
    let authorization_reservation = InMemoryMerchantPaymentStore::default();
    let authorization_intents =
        reservation_intents(&authorization_policy, MerchantOperation::Authorize, 1_000);
    let authorization = authorization_reservation.reserve(ReserveMerchantPaymentRequest {
        workflow_id: AUTHORIZATION_WORKFLOW.into(),
        operation: MerchantOperation::Authorize,
        exact_action_profile: auths_stripe::PAYMENT_AUTHORIZE_PROFILE.into(),
        action_digest: authorization_action_digest.clone(),
        decision_receipt_digest: sha256(b"authorization decision receipt fixture"),
        policy_digest: authorization_policy_digest,
        evaluator_semantic_id: auths_stripe::MERCHANT_EVALUATOR_ID.into(),
        evaluator_semantic_version: auths_stripe::MERCHANT_EVALUATOR_VERSION,
        evidence_digest: sha256(b"authorization evidence fixture"),
        required_configuration_digest: sha256(b"authorization required configuration"),
        executed_configuration_digest: sha256(b"authorization executed configuration"),
        stripe_account_id: account.clone(),
        connect_account: connect.clone(),
        customer_id: customer.clone(),
        order_scope: "order-capture-fixture-001".into(),
        currency: currency.clone(),
        amount_minor: 1_000,
        intents: authorization_intents,
        idempotency_key_digest: sha256(b"authorization fixture idempotency"),
        now: NOW - 60,
    });
    let ReserveMerchantPaymentResult::Reserved {
        lease: authorization_lease,
        ..
    } = authorization
    else {
        panic!("authorization reservation");
    };
    authorization_reservation
        .claim_authorization(&authorization_lease, NOW - 60)
        .expect("authorization claim");
    authorization_reservation
        .mark_authorization_attempting(&authorization_lease, NOW - 60)
        .expect("authorization attempt");
    let authorization_provider = MerchantProviderProjection {
        payment_intent_id: payment_intent.clone(),
        charge_id: Some(charge.clone()),
        status: "requires_capture".into(),
        amount_minor: 1_000,
        currency: currency.clone(),
        amount_capturable_minor: 1_000,
        amount_received_minor: 0,
        capture_before: Some(NOW + 3_600),
        stripe_request_id: Some("req_capturefixtureauth01".into()),
        response_digest: sha256(b"capture fixture authorization provider"),
        observed_at: NOW - 60,
        source: "retrieve".into(),
    };
    authorization_reservation
        .record_authorization_provider_accepted(
            &authorization_lease,
            authorization_provider,
            NOW - 60,
        )
        .expect("authorization provider");
    let authorization_record = authorization_reservation
        .commit_authorization(&authorization_lease, NOW - 60)
        .expect("authorization commit");

    let evidence = PaymentCaptureEvidenceV1::new(PaymentCaptureEvidenceInput {
        stripe_account_id: account.clone(),
        connect_account: connect.clone(),
        payment_intent_id: payment_intent.clone(),
        latest_charge_id: charge.clone(),
        customer_id: customer.clone(),
        order_scope: "order-capture-fixture-001".into(),
        authorized_amount_minor: 1_000,
        amount_capturable_minor: 1_000,
        amount_captured_minor: 0,
        currency: currency.clone(),
        payment_intent_status: "requires_capture".into(),
        capture_before: NOW + 3_600,
        livemode: false,
        stripe_api_version: "2025-04-30.basil".into(),
        authorization_workflow_id: AUTHORIZATION_WORKFLOW.into(),
        authorization_action_digest: authorization_action_digest.clone(),
        authorization_reservation_id: authorization_record.reservation_id().clone(),
        authorization_state: MerchantReservationState::Authorized,
        authorization_created_at: authorization_record.created_at(),
        observed_at: NOW - 5,
        source: "stripe-api-and-auths-store".into(),
        response_commitment: sha256(b"capture fixture evidence"),
    })
    .expect("evidence");
    let capture_policy = policy(
        MerchantOperation::Capture,
        &account,
        &customer,
        &currency,
        750,
    );
    let configuration = StripeMerchantEvaluatorConfigurationV1::for_capture_policy(
        &capture_policy,
        "capture-fixture-implementation-v1",
        account.clone(),
        connect.clone(),
        "2025-04-30.basil",
        "https://stripe-capture.auths.dev",
    )
    .expect("configuration");
    let policy_digest = capture_policy.digest().expect("policy digest");
    let action = StripeExactPaymentCaptureV1::new(StripeExactPaymentCaptureInput {
        stripe_account_id: account.clone(),
        connect_account: connect.clone(),
        payment_intent_id: payment_intent.clone(),
        latest_charge_id: charge.clone(),
        customer_id: customer.clone(),
        order_scope: "order-capture-fixture-001".into(),
        authorized_amount_minor: 1_000,
        amount_capturable_before_minor: 1_000,
        amount_to_capture_minor: 500,
        currency: currency.clone(),
        statement_descriptor_commitment: merchant_statement_descriptor_commitment(),
        fixed_metadata_commitment: fixed_merchant_metadata_commitment(
            CAPTURE_WORKFLOW,
            auths_stripe::PAYMENT_CAPTURE_PROFILE,
            "order-capture-fixture-001",
            &policy_digest,
        )
        .expect("metadata"),
        authorization_action_digest: authorization_action_digest.clone(),
        authorization_reservation_id: authorization_record.reservation_id().clone(),
        stripe_api_version: "2025-04-30.basil".into(),
        required_policy_digest: policy_digest.clone(),
        required_configuration_digest: configuration.digest().expect("configuration"),
        executor_audience: "https://stripe-capture.auths.dev".into(),
        expires_at: NOW + 120,
        nonce: sha256(b"capture fixture nonce"),
    })
    .expect("action");
    let aggregate = MerchantAggregateSnapshot::default();
    let decision = evaluate_payment_capture(&PaymentCaptureEvaluationContext {
        workflow_id: CAPTURE_WORKFLOW,
        policy: &capture_policy,
        action: &action,
        evidence: &evidence,
        aggregate_snapshot: &aggregate,
        required_configuration: &configuration,
        executed_configuration: &configuration,
        request_audience: "https://stripe-capture.auths.dev",
        now: NOW,
    });
    let action_digest = action.digest().expect("action digest");
    let evidence_digest = evidence.digest().expect("evidence digest");
    let decision_receipt = MerchantCaptureDecisionReceipt {
        schema: "auths.stripe.payment-capture-decision-receipt/1".into(),
        workflow_id: CAPTURE_WORKFLOW.into(),
        policy_provenance: auths_stripe::MERCHANT_POLICY_PROVENANCE.into(),
        policy: capture_policy.clone(),
        policy_digest: policy_digest.clone(),
        exact_action: action.clone(),
        action_digest: action_digest.clone(),
        evidence: evidence.clone(),
        evidence_digest: evidence_digest.clone(),
        aggregate_before: aggregate.clone(),
        required_configuration: configuration.clone(),
        executed_configuration: configuration.clone(),
        configuration_equal: true,
        auths_decision: "authorized".into(),
        auths_code: "authorized".into(),
        authorization_established: true,
        bounded_decision: Some(decision.clone()),
        credential_requested: false,
        stripe_called: false,
        decided_at: NOW,
    };
    let decision_digest = decision_receipt.digest().expect("decision digest");
    let eligibility = decision.eligibility.as_ref().expect("eligibility");
    let reservation = authorization_reservation.reserve_capture(ReservePaymentCaptureRequest::new(
        CAPTURE_WORKFLOW.into(),
        action_digest.clone(),
        decision_digest.clone(),
        policy_digest.clone(),
        auths_stripe::MERCHANT_EVALUATOR_ID.into(),
        auths_stripe::MERCHANT_EVALUATOR_VERSION,
        evidence_digest,
        configuration.digest().expect("configuration"),
        configuration.digest().expect("configuration"),
        account,
        connect,
        customer,
        "order-capture-fixture-001".into(),
        currency,
        500,
        eligibility.settlement_reservations.clone(),
        sha256(b"capture fixture idempotency"),
        AUTHORIZATION_WORKFLOW.into(),
        authorization_action_digest,
        authorization_record.reservation_id().clone(),
        eligibility.authorization_release_minor,
        payment_intent,
        charge,
        NOW,
    ));
    let ReserveMerchantPaymentResult::Reserved {
        lease,
        record: reserved,
    } = reservation
    else {
        panic!("capture reservation");
    };
    let claimed = authorization_reservation
        .claim_capture(&lease, NOW)
        .expect("capture claim");
    let attempting = authorization_reservation
        .mark_capture_attempting(&lease, NOW)
        .expect("capture attempt");
    let provider = PaymentCaptureProviderProjection {
        payment_intent_id: action.payment_intent_id().clone(),
        charge_id: action.latest_charge_id().clone(),
        balance_transaction_id: Some("txn_capturefixture000001".into()),
        status: "succeeded".into(),
        authorized_amount_minor: 1_000,
        captured_amount_minor: 500,
        currency: action.currency().clone(),
        amount_capturable_minor: 0,
        amount_received_minor: 500,
        capture_before: Some(NOW + 3_600),
        stripe_request_id: Some("req_capturefixture0001".into()),
        response_digest: sha256(b"capture fixture provider projection"),
        observed_at: NOW,
        source: "retrieve".into(),
    };
    let accepted = authorization_reservation
        .record_capture_provider_accepted(&lease, provider.clone(), NOW)
        .expect("capture provider");
    let committed = authorization_reservation
        .commit_capture(&lease, NOW)
        .expect("capture commit");
    let released_authorization = authorization_reservation
        .get(AUTHORIZATION_WORKFLOW)
        .expect("authorization read")
        .expect("authorization");
    let transition = MerchantCaptureTransitionReceipt {
        schema: "auths.stripe.payment-capture-transition-receipt/1".into(),
        decision_receipt_digest: decision_digest.clone(),
        exact_action_profile: auths_stripe::PAYMENT_CAPTURE_PROFILE.into(),
        operation: MerchantOperation::Capture,
        action_digest: action_digest.clone(),
        authorization_action_digest: action.authorization_action_digest().clone(),
        authorization_reservation_id: action.authorization_reservation_id().clone(),
        policy_digest: policy_digest.clone(),
        required_configuration_digest: configuration.digest().expect("configuration"),
        executed_configuration_digest: configuration.digest().expect("configuration"),
        semantic_event: "capture-committed-hold-released".into(),
        resulting_state: committed.state(),
        capture_reservation: committed.clone(),
        linked_authorization: Some(released_authorization),
        settlement_amount_minor: 500,
        authorization_release_minor: 1_000,
        atomic_cross_budget_transition: true,
        authorization_established: true,
        execution_attempted: true,
        credential_requested: true,
        stripe_called: true,
        provider_accepted: true,
        reconciled_observation: true,
        recorded_at: NOW,
    };
    let observation = MerchantCaptureObservationReceipt {
        schema: "auths.stripe.payment-capture-observation-receipt/1".into(),
        workflow_id: CAPTURE_WORKFLOW.into(),
        exact_action_profile: auths_stripe::PAYMENT_CAPTURE_PROFILE.into(),
        operation: MerchantOperation::Capture,
        action_digest,
        decision_receipt_digest: decision_digest,
        policy_digest,
        required_configuration_digest: configuration.digest().expect("configuration"),
        executed_configuration_digest: configuration.digest().expect("configuration"),
        reservation_id: committed.reservation_id().clone(),
        authorization_reservation_id: action.authorization_reservation_id().clone(),
        provider,
        exact_provider_equality: true,
        atomic_cross_budget_transition: true,
        reconciled: false,
        residual_assumptions: vec![
            "Stripe test mode is not evidence of live settlement".into(),
            "policy provenance is executor-local trusted configuration".into(),
        ],
        recorded_at: NOW,
    };

    let fixtures = vec![
        (
            "policy.json",
            serde_json::to_value(&capture_policy).unwrap(),
        ),
        ("action.json", serde_json::to_value(&action).unwrap()),
        ("evidence.json", serde_json::to_value(&evidence).unwrap()),
        (
            "configuration.json",
            serde_json::to_value(&configuration).unwrap(),
        ),
        (
            "aggregate-before.json",
            serde_json::to_value(&aggregate).unwrap(),
        ),
        ("eligibility.json", serde_json::to_value(&decision).unwrap()),
        (
            "decision-receipt.json",
            serde_json::to_value(&decision_receipt).unwrap(),
        ),
        ("reservation.json", serde_json::to_value(&reserved).unwrap()),
        ("claimed.json", serde_json::to_value(&claimed).unwrap()),
        (
            "attempting.json",
            serde_json::to_value(&attempting).unwrap(),
        ),
        (
            "provider-accepted.json",
            serde_json::to_value(&accepted).unwrap(),
        ),
        ("committed.json", serde_json::to_value(&committed).unwrap()),
        (
            "transition-receipt.json",
            serde_json::to_value(&transition).unwrap(),
        ),
        (
            "observation-receipt.json",
            serde_json::to_value(&observation).unwrap(),
        ),
    ];
    let mut manifest = BTreeMap::new();
    for (name, value) in fixtures {
        write_value(&output, name, &value, &mut manifest);
    }
    write_value(
        &output,
        "denial-codes.json",
        &json!({
            "schema": "auths.stripe.payment-capture-denial-codes/1",
            "codes": [
                "bounded-account-denied",
                "bounded-action-mismatch",
                "bounded-aggregate-budget-exceeded",
                "bounded-api-version-denied",
                "bounded-arithmetic-overflow",
                "bounded-configuration-mismatch",
                "bounded-currency-denied",
                "bounded-evidence-mismatch",
                "bounded-evidence-stale",
                "bounded-order-denied",
                "bounded-policy-expired",
                "bounded-policy-invalid",
                "bounded-test-mode-required",
                "payment-authorization-link-mismatch",
                "payment-capture-already-executed",
                "payment-capture-amount-exceeded",
                "payment-capture-provider-mismatch",
                "payment-capture-window-expired",
                "payment-customer-denied",
                "payment-intent-not-capturable"
            ]
        }),
        &mut manifest,
    );
    write_value(
        &output,
        "replay.json",
        &json!({
            "schema": "auths.stripe.payment-capture-replay/1",
            "effect": "existing-durable-record",
            "provider_capture_called": false,
            "record": committed,
        }),
        &mut manifest,
    );
    fs::write(
        output.join("manifest.sha256.json"),
        canonical_json(&manifest).expect("canonical manifest"),
    )
    .expect("manifest");
}

fn policy(
    operation: MerchantOperation,
    account: &StripeAccountId,
    customer: &CustomerId,
    currency: &Currency,
    operation_limit: u64,
) -> StripeBoundedMerchantPaymentPolicyV1 {
    StripeBoundedMerchantPaymentPolicyV1::new(StripeBoundedMerchantPaymentPolicyInput {
        policy_id: format!("capture-fixture-{operation:?}").to_lowercase(),
        valid_from: NOW - 120,
        expires_at: NOW + 3_600,
        allowed_operations: vec![operation],
        allowed_test_account_ids: vec![account.clone()],
        allowed_connect_accounts: vec![MerchantConnectAccount::Platform],
        allowed_customer_ids: vec![customer.clone()],
        allowed_payment_method_ids: if operation == MerchantOperation::Authorize {
            vec![PaymentMethodId::parse("pm_capturefixture000000001").unwrap()]
        } else {
            Vec::new()
        },
        allowed_payment_method_types: if operation == MerchantOperation::Authorize {
            vec!["card".into()]
        } else {
            Vec::new()
        },
        allowed_currencies: vec![currency.clone()],
        allowed_order_scopes: vec!["order-capture-fixture-001".into()],
        allowed_cancellation_reasons: Vec::new(),
        per_operation_absolute_minor_by_currency: BTreeMap::from([(
            operation,
            BTreeMap::from([(currency.clone(), operation_limit)]),
        )]),
        per_customer_minor_by_currency: BTreeMap::from([(currency.clone(), 1_500)]),
        per_order_minor_by_currency: BTreeMap::from([(currency.clone(), 1_000)]),
        aggregate_budgets: vec![
            MerchantAggregateBudget::new(
                format!("{operation:?}-fixed").to_lowercase(),
                operation,
                currency.clone(),
                2_000,
                MerchantBudgetWindow::Fixed {
                    starts_at: NOW - 120,
                    ends_at: NOW + 3_600,
                },
                NOW,
            )
            .unwrap(),
            MerchantAggregateBudget::new(
                format!("{operation:?}-rolling").to_lowercase(),
                operation,
                currency.clone(),
                1_500,
                MerchantBudgetWindow::Rolling {
                    duration_seconds: 3_600,
                },
                NOW,
            )
            .unwrap(),
        ],
        maximum_authorization_age_seconds: 300,
        minimum_capture_window_seconds: 60,
        maximum_evidence_age_seconds: 120,
        maximum_action_lifetime_seconds: 300,
        allowed_api_versions: vec!["2025-04-30.basil".into()],
    })
    .expect("policy")
}

fn reservation_intents(
    policy: &StripeBoundedMerchantPaymentPolicyV1,
    operation: MerchantOperation,
    amount_minor: u64,
) -> Vec<MerchantReservationIntent> {
    policy
        .aggregate_budgets()
        .iter()
        .map(|budget| MerchantReservationIntent {
            budget_id: budget.budget_id().into(),
            operation,
            currency: budget.currency().clone(),
            window: budget.window().identity(NOW).expect("window"),
            limit_minor: budget.limit_minor(),
            amount_minor,
            available_before_minor: budget.limit_minor(),
        })
        .collect()
}

fn write_value(
    output: &std::path::Path,
    name: &'static str,
    value: &serde_json::Value,
    manifest: &mut BTreeMap<&'static str, auths_stripe::DigestHex>,
) {
    let bytes = canonical_json(value).expect("canonical fixture");
    fs::write(output.join(name), &bytes).expect("write fixture");
    manifest.insert(name, sha256(&bytes));
}
