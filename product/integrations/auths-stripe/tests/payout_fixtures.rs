use std::{collections::BTreeMap, fs, path::PathBuf};

use auths_stripe::{
    DigestHex, PayoutAggregateSnapshot, PayoutDecisionCode, PayoutEvaluationContext,
    PayoutEvidenceV1, StripeBoundedPayoutPolicyV1, StripeExactPayoutV1,
    StripePayoutConfigurationV1, evaluate_payout,
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/payout/v1")
}

#[test]
fn canonical_payout_fixture_is_eligible() {
    let policy: StripeBoundedPayoutPolicyV1 =
        serde_json::from_slice(&fs::read(root().join("policy.json")).unwrap()).unwrap();
    let configuration: StripePayoutConfigurationV1 =
        serde_json::from_slice(&fs::read(root().join("configuration.json")).unwrap()).unwrap();
    let action: StripeExactPayoutV1 =
        serde_json::from_slice(&fs::read(root().join("action.json")).unwrap()).unwrap();
    let evidence: PayoutEvidenceV1 =
        serde_json::from_slice(&fs::read(root().join("evidence.json")).unwrap()).unwrap();
    let result = evaluate_payout(&PayoutEvaluationContext {
        policy: &policy,
        action: &action,
        evidence: &evidence,
        aggregate: &PayoutAggregateSnapshot::default(),
        required_configuration: &configuration,
        executed_configuration: &configuration,
        request_audience: "https://stripe-payout.auths.dev",
        now: 2_100_600_000,
    });
    assert_eq!(result.code, PayoutDecisionCode::PayoutAuthorized);
}

#[test]
fn payout_fixture_manifest_commits_every_file() {
    let manifest: BTreeMap<String, DigestHex> =
        serde_json::from_slice(&fs::read(root().join("manifest.sha256.json")).unwrap()).unwrap();
    for (name, expected) in manifest {
        assert_eq!(
            auths_stripe::canonical::sha256(&fs::read(root().join(name)).unwrap()),
            expected
        );
    }
}
