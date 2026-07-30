use std::{collections::BTreeMap, fs, path::PathBuf};

use auths_stripe::{
    Currency, CustomerId, InMemoryMerchantPaymentStore, MerchantAggregateBudget,
    MerchantAggregateSnapshot, MerchantBudgetWindow, MerchantCollectionDecisionReceipt,
    MerchantCollectionObservationReceipt, MerchantCollectionTransitionReceipt,
    MerchantConnectAccount, MerchantOperation, MerchantPaymentEvidenceInput,
    MerchantPaymentEvidenceV1, MerchantPaymentStore, MerchantProviderProjection,
    PaymentCollectEvaluationContext, PaymentIntentId, PaymentMethodId,
    ReserveMerchantPaymentRequest, ReserveMerchantPaymentResult, StripeAccountId,
    StripeBoundedMerchantPaymentPolicyInput, StripeBoundedMerchantPaymentPolicyV1,
    StripeExactPaymentCollectInput, StripeExactPaymentCollectV1,
    StripeMerchantEvaluatorConfigurationV1, canonical::canonical_json, evaluate_payment_collect,
    fixed_merchant_metadata_commitment, merchant_statement_descriptor_commitment,
};
use serde_json::json;

const NOW: u64 = 1_800_000_000;
const WORKFLOW: &str = "collect-fixture-workflow";

#[allow(
    clippy::too_many_lines,
    reason = "the generator writes the complete canonical profile corpus explicitly"
)]
fn main() {
    let output = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/merchant-collect/v1");
    fs::create_dir_all(&output).expect("fixture directory");
    let account = StripeAccountId::parse("acct_collectfixture01").expect("account");
    let customer = CustomerId::parse("cus_collectfixture000001").expect("customer");
    let method = PaymentMethodId::parse("pm_collectfixture0000001").expect("method");
    let currency = Currency::parse("usd").expect("currency");
    let connect = MerchantConnectAccount::Platform;
    let evidence = MerchantPaymentEvidenceV1::new(MerchantPaymentEvidenceInput {
        stripe_account_id: account.clone(),
        connect_account: connect.clone(),
        customer_id: customer.clone(),
        payment_method_id: method.clone(),
        payment_method_type: "card".into(),
        attached_customer_id: customer.clone(),
        livemode: false,
        stripe_api_version: "2025-04-30.basil".into(),
        order_scope: "order-fixture-001".into(),
        consent_order_commitment: auths_stripe::canonical::sha256(b"fixture-order-consent"),
        supports_manual_capture: true,
        prior_payments: Vec::new(),
        observed_at: NOW - 5,
        source: "stripe-api-and-order-store".into(),
        response_commitment: auths_stripe::canonical::sha256(b"fixture-sanitized-evidence"),
    })
    .expect("evidence");
    let policy =
        StripeBoundedMerchantPaymentPolicyV1::new(StripeBoundedMerchantPaymentPolicyInput {
            policy_id: "collect-fixture-policy".into(),
            valid_from: NOW - 60,
            expires_at: NOW + 3_600,
            allowed_operations: vec![MerchantOperation::Collect],
            allowed_test_account_ids: vec![account.clone()],
            allowed_connect_accounts: vec![connect.clone()],
            allowed_customer_ids: vec![customer.clone()],
            allowed_payment_method_ids: vec![method.clone()],
            allowed_payment_method_types: vec!["card".into()],
            allowed_currencies: vec![currency.clone()],
            allowed_order_scopes: vec!["order-fixture-001".into()],
            allowed_cancellation_reasons: Vec::new(),
            per_operation_absolute_minor_by_currency: BTreeMap::from([(
                MerchantOperation::Collect,
                BTreeMap::from([(currency.clone(), 1_000)]),
            )]),
            per_customer_minor_by_currency: BTreeMap::from([(currency.clone(), 1_500)]),
            per_order_minor_by_currency: BTreeMap::from([(currency.clone(), 750)]),
            aggregate_budgets: vec![
                MerchantAggregateBudget::new(
                    "collect-fixed",
                    MerchantOperation::Collect,
                    currency.clone(),
                    2_000,
                    MerchantBudgetWindow::Fixed {
                        starts_at: NOW - 60,
                        ends_at: NOW + 3_600,
                    },
                    NOW,
                )
                .expect("fixed budget"),
                MerchantAggregateBudget::new(
                    "collect-rolling",
                    MerchantOperation::Collect,
                    currency.clone(),
                    1_500,
                    MerchantBudgetWindow::Rolling {
                        duration_seconds: 3_600,
                    },
                    NOW,
                )
                .expect("rolling budget"),
            ],
            maximum_authorization_age_seconds: 0,
            minimum_capture_window_seconds: 0,
            maximum_evidence_age_seconds: 60,
            maximum_action_lifetime_seconds: 300,
            allowed_api_versions: vec!["2025-04-30.basil".into()],
        })
        .expect("policy");
    let configuration = StripeMerchantEvaluatorConfigurationV1::for_collect_policy(
        &policy,
        "fixture-implementation-v1",
        account.clone(),
        connect.clone(),
        "2025-04-30.basil",
        "https://stripe-collect.auths.dev",
    )
    .expect("configuration");
    let policy_digest = policy.digest().expect("policy digest");
    let action = StripeExactPaymentCollectV1::new(StripeExactPaymentCollectInput {
        stripe_account_id: account.clone(),
        connect_account: connect.clone(),
        customer_id: customer.clone(),
        payment_method_id: method,
        payment_method_type: "card".into(),
        order_scope: "order-fixture-001".into(),
        amount_minor: 500,
        currency: currency.clone(),
        statement_descriptor_commitment: merchant_statement_descriptor_commitment(),
        fixed_metadata_commitment: fixed_merchant_metadata_commitment(
            WORKFLOW,
            auths_stripe::PAYMENT_COLLECT_PROFILE,
            "order-fixture-001",
            &policy_digest,
        )
        .expect("metadata"),
        stripe_api_version: "2025-04-30.basil".into(),
        required_policy_digest: policy_digest.clone(),
        required_configuration_digest: configuration.digest().expect("configuration digest"),
        executor_audience: "https://stripe-collect.auths.dev".into(),
        expires_at: NOW + 120,
        nonce: auths_stripe::canonical::sha256(b"fixture-collect-nonce"),
    })
    .expect("action");
    let aggregate = MerchantAggregateSnapshot::default();
    let decision = evaluate_payment_collect(&PaymentCollectEvaluationContext {
        workflow_id: WORKFLOW,
        policy: &policy,
        action: &action,
        evidence: &evidence,
        aggregate_snapshot: &aggregate,
        required_configuration: &configuration,
        executed_configuration: &configuration,
        request_audience: "https://stripe-collect.auths.dev",
        now: NOW,
    });
    let decision_receipt = MerchantCollectionDecisionReceipt {
        schema: "auths.stripe.payment-collect-decision-receipt/1".into(),
        workflow_id: WORKFLOW.into(),
        policy_provenance: auths_stripe::MERCHANT_POLICY_PROVENANCE.into(),
        policy: policy.clone(),
        policy_digest: policy_digest.clone(),
        exact_action: action.clone(),
        action_digest: action.digest().expect("action digest"),
        evidence: evidence.clone(),
        evidence_digest: evidence.digest().expect("evidence digest"),
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
    let store = InMemoryMerchantPaymentStore::default();
    let reservation = store.reserve(ReserveMerchantPaymentRequest {
        workflow_id: WORKFLOW.into(),
        operation: MerchantOperation::Collect,
        exact_action_profile: auths_stripe::PAYMENT_COLLECT_PROFILE.into(),
        action_digest: action.digest().expect("action digest"),
        decision_receipt_digest: decision_digest.clone(),
        policy_digest: policy_digest.clone(),
        evaluator_semantic_id: auths_stripe::MERCHANT_EVALUATOR_ID.into(),
        evaluator_semantic_version: auths_stripe::MERCHANT_EVALUATOR_VERSION,
        evidence_digest: evidence.digest().expect("evidence digest"),
        required_configuration_digest: configuration.digest().expect("configuration digest"),
        executed_configuration_digest: configuration.digest().expect("configuration digest"),
        stripe_account_id: account,
        connect_account: connect,
        customer_id: customer,
        order_scope: "order-fixture-001".into(),
        currency,
        amount_minor: 500,
        intents: decision
            .eligibility
            .as_ref()
            .expect("eligible")
            .reservations
            .clone(),
        idempotency_key_digest: auths_stripe::canonical::sha256(b"fixture-idempotency"),
        now: NOW,
    });
    let ReserveMerchantPaymentResult::Reserved {
        lease,
        record: reserved,
    } = reservation
    else {
        panic!("reservation");
    };
    let claimed = store.claim(&lease, NOW).expect("claim");
    let attempting = store.mark_attempting(&lease, NOW).expect("attempt");
    let provider = MerchantProviderProjection {
        payment_intent_id: PaymentIntentId::parse("pi_collectfixture00000001").expect("intent"),
        charge_id: Some(
            auths_stripe::ChargeId::parse("ch_collectfixture00000001").expect("charge"),
        ),
        status: "succeeded".into(),
        amount_minor: 500,
        currency: Currency::parse("usd").expect("currency"),
        amount_capturable_minor: 0,
        amount_received_minor: 500,
        capture_before: None,
        stripe_request_id: Some("req_collectfixture01".into()),
        response_digest: auths_stripe::canonical::sha256(b"fixture-provider-projection"),
        observed_at: NOW,
        source: "retrieve".into(),
    };
    let accepted = store
        .record_provider_accepted(&lease, provider.clone(), NOW)
        .expect("provider acceptance");
    let committed = store
        .commit_collection(&lease, NOW)
        .expect("collection commit");
    let transition = MerchantCollectionTransitionReceipt {
        schema: "auths.stripe.payment-collect-transition-receipt/1".into(),
        decision_receipt_digest: decision_digest.clone(),
        exact_action_profile: auths_stripe::PAYMENT_COLLECT_PROFILE.into(),
        operation: MerchantOperation::Collect,
        action_digest: action.digest().expect("action digest"),
        policy_digest: policy_digest.clone(),
        required_configuration_digest: configuration.digest().expect("configuration"),
        executed_configuration_digest: configuration.digest().expect("configuration"),
        semantic_event: "committed".into(),
        resulting_state: committed.state(),
        reservation: committed.clone(),
        authorization_established: true,
        execution_attempted: true,
        credential_requested: true,
        stripe_called: true,
        provider_accepted: true,
        reconciled_observation: true,
        recorded_at: NOW,
    };
    let observation = MerchantCollectionObservationReceipt {
        schema: "auths.stripe.payment-collect-observation-receipt/1".into(),
        workflow_id: WORKFLOW.into(),
        exact_action_profile: auths_stripe::PAYMENT_COLLECT_PROFILE.into(),
        operation: MerchantOperation::Collect,
        action_digest: action.digest().expect("action digest"),
        decision_receipt_digest: decision_digest,
        policy_digest,
        required_configuration_digest: configuration.digest().expect("configuration"),
        executed_configuration_digest: configuration.digest().expect("configuration"),
        reservation_id: committed.reservation_id().clone(),
        provider,
        exact_provider_equality: true,
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
            serde_json::to_value(&policy).expect("policy"),
        ),
        (
            "action.json",
            serde_json::to_value(&action).expect("action"),
        ),
        (
            "evidence.json",
            serde_json::to_value(&evidence).expect("evidence"),
        ),
        (
            "configuration.json",
            serde_json::to_value(&configuration).expect("configuration"),
        ),
        (
            "aggregate-before.json",
            serde_json::to_value(&aggregate).expect("aggregate"),
        ),
        (
            "eligibility.json",
            serde_json::to_value(&decision).expect("eligibility"),
        ),
        (
            "decision-receipt.json",
            serde_json::to_value(&decision_receipt).expect("decision receipt"),
        ),
        (
            "reservation.json",
            serde_json::to_value(&reserved).expect("reservation"),
        ),
        (
            "claimed.json",
            serde_json::to_value(&claimed).expect("claim"),
        ),
        (
            "attempting.json",
            serde_json::to_value(&attempting).expect("attempt"),
        ),
        (
            "provider-accepted.json",
            serde_json::to_value(&accepted).expect("provider acceptance"),
        ),
        (
            "committed.json",
            serde_json::to_value(&committed).expect("commit"),
        ),
        (
            "transition-receipt.json",
            serde_json::to_value(&transition).expect("transition receipt"),
        ),
        (
            "observation-receipt.json",
            serde_json::to_value(&observation).expect("observation receipt"),
        ),
    ];
    let mut manifest = BTreeMap::new();
    for (name, value) in fixtures {
        let bytes = canonical_json(&value).expect("canonical fixture");
        fs::write(output.join(name), &bytes).expect("write fixture");
        manifest.insert(name, auths_stripe::canonical::sha256(&bytes));
    }
    let denials = json!({
        "schema": "auths.stripe.payment-collect-denial-codes/1",
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
            "payment-collect-limit-exceeded",
            "payment-customer-denied",
            "payment-method-denied",
            "payment-order-conflict"
        ]
    });
    write_value(&output, "denial-codes.json", &denials, &mut manifest);
    let replay = json!({
        "schema": "auths.stripe.payment-collect-replay/1",
        "effect": "existing-durable-record",
        "provider_create_called": false,
        "record": committed,
    });
    write_value(&output, "replay.json", &replay, &mut manifest);
    let manifest_value = serde_json::to_value(manifest).expect("manifest");
    fs::write(
        output.join("manifest.sha256.json"),
        canonical_json(&manifest_value).expect("canonical manifest"),
    )
    .expect("write manifest");
}

fn write_value(
    output: &std::path::Path,
    name: &'static str,
    value: &serde_json::Value,
    manifest: &mut BTreeMap<&'static str, auths_stripe::DigestHex>,
) {
    let bytes = canonical_json(value).expect("canonical fixture");
    fs::write(output.join(name), &bytes).expect("write fixture");
    manifest.insert(name, auths_stripe::canonical::sha256(&bytes));
}
