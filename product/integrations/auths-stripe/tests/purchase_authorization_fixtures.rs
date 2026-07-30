use std::{collections::BTreeMap, fs, path::PathBuf};

use auths_stripe::{
    AgentProcurementIntentV1, DigestHex, PurchaseAggregateSnapshot,
    PurchaseAuthorizationDecisionCode, PurchaseAuthorizationEvaluationContext,
    PurchaseWebhookEvidenceV1, StripeBoundedPurchasePolicyV1, StripeExactPurchaseAuthorizationV1,
    StripePurchaseConfigurationV1, evaluate_purchase_authorization,
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/purchase-authorization/v1")
}

#[test]
fn canonical_purchase_fixture_is_eligible() {
    let policy: StripeBoundedPurchasePolicyV1 =
        serde_json::from_slice(&fs::read(root().join("policy.json")).unwrap()).unwrap();
    let configuration: StripePurchaseConfigurationV1 =
        serde_json::from_slice(&fs::read(root().join("configuration.json")).unwrap()).unwrap();
    let intent: AgentProcurementIntentV1 =
        serde_json::from_slice(&fs::read(root().join("intent.json")).unwrap()).unwrap();
    let action: StripeExactPurchaseAuthorizationV1 =
        serde_json::from_slice(&fs::read(root().join("action.json")).unwrap()).unwrap();
    let evidence: PurchaseWebhookEvidenceV1 =
        serde_json::from_slice(&fs::read(root().join("evidence.json")).unwrap()).unwrap();
    let result = evaluate_purchase_authorization(&PurchaseAuthorizationEvaluationContext {
        policy: &policy,
        action: &action,
        webhook: &evidence,
        intent: Some(&intent),
        aggregate: &PurchaseAggregateSnapshot::default(),
        required_configuration: &configuration,
        executed_configuration: &configuration,
        request_audience: "https://stripe-purchase-authorization.auths.dev",
        now: action.received_at(),
        elapsed_milliseconds: 25,
    });
    assert_eq!(
        result.code,
        PurchaseAuthorizationDecisionCode::PurchaseAuthorized
    );
}

#[test]
fn purchase_fixture_manifest_commits_every_file() {
    let manifest: BTreeMap<String, DigestHex> =
        serde_json::from_slice(&fs::read(root().join("manifest.sha256.json")).unwrap()).unwrap();
    for (name, expected) in manifest {
        assert_eq!(
            auths_stripe::canonical::sha256(&fs::read(root().join(name)).unwrap()),
            expected
        );
    }
}
