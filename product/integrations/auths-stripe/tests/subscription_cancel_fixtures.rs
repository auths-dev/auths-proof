use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use auths_profile_api::ActionProfile;
use auths_stripe::{
    StripeBoundedSubscriptionPolicyV1, StripeExactSubscriptionCancelV1,
    StripeSubscriptionCancelConfigurationV1, StripeSubscriptionCancelProfile,
    SubscriptionCancelDecisionClass, SubscriptionCancelDecisionCode,
    SubscriptionCancelEvaluationContext, SubscriptionCancelEvidenceV1, SubscriptionCancelReceipt,
    canonical::{canonical_json, sha256},
    evaluate_subscription_cancel,
};

const NOW: u64 = 2_100_302_700;
const AUDIENCE: &str = "https://stripe-subscription-cancel.auths.dev";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/subscription-cancel/v1")
}

fn load<T: serde::de::DeserializeOwned>(name: &str) -> T {
    serde_json::from_slice(&fs::read(root().join(name)).unwrap()).unwrap()
}

fn inputs() -> (
    StripeExactSubscriptionCancelV1,
    StripeBoundedSubscriptionPolicyV1,
    SubscriptionCancelEvidenceV1,
    StripeSubscriptionCancelConfigurationV1,
) {
    (
        load("action.json"),
        load("policy.json"),
        load("evidence.json"),
        load("configuration.json"),
    )
}

fn evaluate(
    action: &StripeExactSubscriptionCancelV1,
    policy: &StripeBoundedSubscriptionPolicyV1,
    evidence: &SubscriptionCancelEvidenceV1,
    configuration: &StripeSubscriptionCancelConfigurationV1,
    now: u64,
) -> auths_stripe::SubscriptionCancelDecision {
    evaluate_subscription_cancel(&SubscriptionCancelEvaluationContext {
        action,
        policy,
        evidence,
        required_configuration: configuration,
        executed_configuration: configuration,
        request_audience: AUDIENCE,
        now,
    })
}

#[test]
fn canonical_fixture_manifest_is_exact_and_secret_free() {
    let manifest_bytes = fs::read(root().join("manifest.sha256.json")).unwrap();
    let manifest: BTreeMap<String, auths_stripe::DigestHex> =
        serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(canonical_json(&manifest).unwrap(), manifest_bytes);
    for (name, digest) in manifest {
        let bytes = fs::read(root().join(name)).unwrap();
        assert_eq!(sha256(&bytes), digest);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(canonical_json(&value).unwrap(), bytes);
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains("sk_test_"));
        assert!(!text.contains("rk_test_"));
        assert!(!text.contains("\"client_secret\":"));
    }
}

#[test]
fn canonical_cancel_types_round_trip() {
    round_trip::<StripeExactSubscriptionCancelV1>(&root(), "action.json");
    round_trip::<StripeBoundedSubscriptionPolicyV1>(&root(), "policy.json");
    round_trip::<SubscriptionCancelEvidenceV1>(&root(), "evidence.json");
    round_trip::<StripeSubscriptionCancelConfigurationV1>(&root(), "configuration.json");
}

#[test]
fn profile_canonicalizes_only_the_exact_cancellation() {
    let bytes = fs::read(root().join("action.json")).unwrap();
    let canonical = StripeSubscriptionCancelProfile
        .canonicalize(&bytes)
        .unwrap();
    assert_eq!(canonical.body(), bytes);
    assert_eq!(
        canonical.permission().capability().as_str(),
        "stripe.subscription-cancel/execute"
    );
}

#[test]
fn period_end_fixture_is_eligible_and_releases_only_future_liability() {
    let (action, policy, evidence, configuration) = inputs();
    let decision = evaluate(&action, &policy, &evidence, &configuration, NOW);
    assert_eq!(decision.class, SubscriptionCancelDecisionClass::Eligible);
    let eligibility = decision.eligibility.unwrap();
    assert_eq!(eligibility.future_liability_release_minor, 2_400);
    assert_eq!(eligibility.liability_retained_until_terminal_minor, 1_200);
    assert!(!eligibility.invoice_now);
    assert!(!eligibility.prorate);
}

#[test]
fn pending_update_items_and_renewal_race_have_distinct_denials() {
    let (action, policy, evidence, configuration) = inputs();
    let mut pending_update = evidence.clone();
    pending_update.pending_update_digest = Some(sha256(b"pending-update"));
    assert_eq!(
        evaluate(&action, &policy, &pending_update, &configuration, NOW).code,
        SubscriptionCancelDecisionCode::PendingUpdate
    );

    let mut action_value: serde_json::Value =
        serde_json::from_slice(&fs::read(root().join("action.json")).unwrap()).unwrap();
    action_value["mode"] = serde_json::json!("immediate");
    action_value["cancel_at"] = serde_json::json!(NOW);
    let immediate: StripeExactSubscriptionCancelV1 = serde_json::from_value(action_value).unwrap();
    let mut pending_items = evidence.clone();
    pending_items.pending_invoice_item_count = 1;
    pending_items.unhandled_pending_invoice_item_count = 1;
    assert_eq!(
        evaluate(&immediate, &policy, &pending_items, &configuration, NOW).code,
        SubscriptionCancelDecisionCode::PendingInvoiceItems
    );

    let mut racing = evidence;
    racing.renewal_or_modification_pending = true;
    assert_eq!(
        evaluate(&action, &policy, &racing, &configuration, NOW).code,
        SubscriptionCancelDecisionCode::RenewalConflict
    );
}

#[test]
fn scheduled_terminal_and_stale_evidence_fail_closed() {
    let (action, policy, evidence, configuration) = inputs();
    let mut scheduled = evidence.clone();
    scheduled.cancel_at_period_end = true;
    scheduled.cancel_at = Some(scheduled.current_period_end);
    assert_eq!(
        evaluate(&action, &policy, &scheduled, &configuration, NOW).code,
        SubscriptionCancelDecisionCode::AlreadyScheduled
    );
    let mut terminal = evidence.clone();
    terminal.status = "canceled".into();
    terminal.ended_at = Some(NOW);
    assert_eq!(
        evaluate(&action, &policy, &terminal, &configuration, NOW).code,
        SubscriptionCancelDecisionCode::AlreadyTerminal
    );
    let mut stale = evidence;
    stale.observed_at = NOW - 121;
    assert_eq!(
        evaluate(&action, &policy, &stale, &configuration, NOW).code,
        SubscriptionCancelDecisionCode::EvidenceStale
    );
}

#[test]
fn cancel_receipt_family_remains_profile_local() {
    fn kind(receipt: &SubscriptionCancelReceipt) -> &'static str {
        match receipt {
            SubscriptionCancelReceipt::Decision(_) => "decision",
            SubscriptionCancelReceipt::Transition(_) => "transition",
            SubscriptionCancelReceipt::Observation(_) => "observation",
        }
    }
    let _ = kind;
}

fn round_trip<T>(root: &Path, name: &str)
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let bytes = fs::read(root.join(name)).unwrap();
    let value: T = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(canonical_json(&value).unwrap(), bytes);
}
