use std::{collections::BTreeMap, fs, path::PathBuf};

use auths_stripe::{
    ConnectTransferAggregateSnapshot, ConnectTransferDecisionCode,
    ConnectTransferEvaluationContext, ConnectTransferEvidenceV1, DigestHex,
    StripeBoundedConnectTransferPolicyV1, StripeConnectTransferConfigurationV1,
    StripeExactConnectTransferV1, evaluate_connect_transfer,
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/connect-transfer/v1")
}

#[test]
fn canonical_connect_transfer_fixture_is_eligible() {
    let policy: StripeBoundedConnectTransferPolicyV1 =
        serde_json::from_slice(&fs::read(root().join("policy.json")).unwrap()).unwrap();
    let configuration: StripeConnectTransferConfigurationV1 =
        serde_json::from_slice(&fs::read(root().join("configuration.json")).unwrap()).unwrap();
    let action: StripeExactConnectTransferV1 =
        serde_json::from_slice(&fs::read(root().join("action.json")).unwrap()).unwrap();
    let evidence: ConnectTransferEvidenceV1 =
        serde_json::from_slice(&fs::read(root().join("evidence.json")).unwrap()).unwrap();
    let result = evaluate_connect_transfer(&ConnectTransferEvaluationContext {
        policy: &policy,
        action: &action,
        evidence: &evidence,
        aggregate: &ConnectTransferAggregateSnapshot::default(),
        required_configuration: &configuration,
        executed_configuration: &configuration,
        request_audience: "https://stripe-connect-transfer.auths.dev",
        now: 2_100_500_000,
    });
    assert_eq!(
        result.code,
        ConnectTransferDecisionCode::ConnectTransferAuthorized
    );
}

#[test]
fn connect_transfer_fixture_manifest_commits_every_file() {
    let manifest: BTreeMap<String, DigestHex> =
        serde_json::from_slice(&fs::read(root().join("manifest.sha256.json")).unwrap()).unwrap();
    for (name, expected) in manifest {
        assert_eq!(
            auths_stripe::canonical::sha256(&fs::read(root().join(name)).unwrap()),
            expected
        );
    }
}
