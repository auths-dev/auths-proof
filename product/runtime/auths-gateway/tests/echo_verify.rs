//! `auths-gateway echo-verify` offline: exit 0 only on a match, and every
//! other result or refusal reported with its stable code.

#![cfg(unix)]

use auths_gateway::{
    LogicalOperationId, OperatorNamespace, canonical_action_commitment, echo_token,
};
use auths_profile_api::ActionProfile as _;
use auths_profile_mcp::{McpProfile, McpToolCall};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_auths-gateway");

fn canonical_action() -> Vec<u8> {
    let arguments = serde_json::json!({"operation_id": "refund-1", "amount": 1_500})
        .as_object()
        .expect("object")
        .clone();
    let call = McpToolCall::new("stripe-refunds", "create_refund_v1", arguments).expect("call");
    let bytes = call.canonical_bytes().expect("canonical call");
    let canonical = McpProfile.canonicalize(&bytes).expect("canonical action");
    auths_codec::encode_canonical_action(&canonical).expect("action bytes")
}

fn run(record: &serde_json::Value, pointer: &str, action: &[u8]) -> Output {
    let directory = tempfile::tempdir().expect("tempdir");
    let record_path = directory.path().join("record.json");
    let action_path = directory.path().join("action.cbor");
    std::fs::write(&record_path, record.to_string()).expect("record");
    std::fs::write(&action_path, action).expect("action");
    Command::new(BIN)
        .arg("echo-verify")
        .arg("--record")
        .arg(&record_path)
        .arg("--pointer")
        .arg(pointer)
        .args([
            "--namespace",
            "stripe-refunds",
            "--operation-id",
            "refund-1",
        ])
        .arg("--action")
        .arg(&action_path)
        .output()
        .expect("echo-verify runs")
}

#[test]
fn echo_verify_exits_zero_only_on_a_match() {
    let action = canonical_action();
    let token = echo_token(
        &OperatorNamespace::parse("stripe-refunds").expect("namespace"),
        &LogicalOperationId::parse("refund-1").expect("operation"),
        &canonical_action_commitment(&action).expect("commitment"),
    );
    let record = serde_json::json!({"id": "re_1", "metadata": {"auths_echo": token}});
    let matched = run(&record, "/metadata/auths_echo", &action);
    assert!(
        matched.status.success(),
        "{}",
        String::from_utf8_lossy(&matched.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&matched.stdout).expect("report");
    assert_eq!(report["schema"], "auths.gateway-echo-verification/1");
    assert_eq!(report["result"], "match");
    assert_eq!(report["token"], token);
    assert!(
        report["note"]
            .as_str()
            .expect("note")
            .contains("does not show who wrote it")
    );

    for (pointer, code) in [
        ("/id", "gateway.echo-verify.mismatch"),
        ("/metadata/missing", "gateway.echo-verify.absent"),
    ] {
        let output = run(&record, pointer, &action);
        assert!(!output.status.success(), "{pointer}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report");
        assert_eq!(report["code"], code);
    }
    let refused = run(&record, "metadata", &action);
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("gateway.echo-verify.pointer-invalid"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    let mut noncanonical = action.clone();
    noncanonical.push(0);
    let refused = run(&record, "/id", &noncanonical);
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("gateway.echo-verify.action-invalid")
    );
}
