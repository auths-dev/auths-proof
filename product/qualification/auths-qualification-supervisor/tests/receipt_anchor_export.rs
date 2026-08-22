#![cfg(unix)]

use auths_receipts::{
    ReceiptTrustAnchor, ReceiptTrustAnchorRole, ReceiptTrustAnchors, encode_receipt_trust_anchors,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    process::{Command, Stdio},
};

const CONFIG: &str = r#"[agent]
authority_root = "/var/lib/auths/authorities"

[agent.receipt_signing.decision]
algorithm = "Ed25519"
key_id = "decision-2026-01"
verification_method = "did:key:auths-receipt-decision#decision-2026-01"
public_key_base64url = "1UIH2hlJd9z0atv-wrwudbUtWopCGE_t_cAAJPDj6No"
seed_file = "/var/lib/auths/receipt-decision.key"
not_before_unix_seconds = 1
not_after_unix_seconds = 4102444800

[agent.receipt_signing.execution]
algorithm = "Ed25519"
key_id = "execution-2026-01"
verification_method = "did:key:auths-receipt-execution#execution-2026-01"
public_key_base64url = "URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo"
seed_file = "/var/lib/auths/receipt-execution.key"
not_before_unix_seconds = 1
not_after_unix_seconds = 4102444800

[agent.authority_sources.payments-worker-authority]
kind = "sealed-file-v1"
path = "/var/lib/auths/authorities/payments-worker.cbor"

[[agent.workloads]]
id = "payments-worker"
principal = "did:example:payments-worker"
authority_source = "payments-worker-authority"
allowed_profiles = ["auths.stripe.refund/1"]
connections = [{ provider = "stripe", alias = "merchant-primary", default = true }]

[agent.workloads.selector]
kind = "posix"
uid = 10001
gid = 10001
executable_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
linux_cgroup_prefix = "/payments.slice/"
"#;

fn expected_anchors() -> Vec<u8> {
    let decode = |value: &str| {
        let mut output = [0_u8; 32];
        Base64UrlUnpadded::decode(value, &mut output).unwrap();
        output
    };
    encode_receipt_trust_anchors(
        &ReceiptTrustAnchors::new(vec![
            ReceiptTrustAnchor::new(
                ReceiptTrustAnchorRole::Decision,
                "decision-2026-01",
                "did:key:auths-receipt-decision#decision-2026-01",
                decode("1UIH2hlJd9z0atv-wrwudbUtWopCGE_t_cAAJPDj6No"),
                1,
                4_102_444_800,
            )
            .unwrap(),
            ReceiptTrustAnchor::new(
                ReceiptTrustAnchorRole::Execution,
                "execution-2026-01",
                "did:key:auths-receipt-execution#execution-2026-01",
                decode("URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo"),
                1,
                4_102_444_800,
            )
            .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap()
}

fn invoke(config_output: &str, anchors_output: &str, digest: &str) -> std::process::ExitStatus {
    let mut child = Command::new(env!("CARGO_BIN_EXE_auths-qualification-supervisor"))
        .env_clear()
        .args([
            "export-receipt-anchors",
            "--config-output",
            config_output,
            "--anchors-output",
            anchors_output,
            "--expected-sha256",
            digest,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(Base64UrlUnpadded::encode_string(CONFIG.as_bytes()).as_bytes())
        .unwrap();
    child.wait().unwrap()
}

#[test]
fn public_anchor_export_never_opens_seed_paths_and_is_exactly_idempotent() {
    let root = tempfile::tempdir_in(".").unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let config_parent = root.path().join("agent-config");
    let anchor_parent = root.path().join("anchor-snapshots");
    fs::create_dir(&config_parent).unwrap();
    fs::create_dir(&anchor_parent).unwrap();
    fs::set_permissions(&config_parent, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&anchor_parent, fs::Permissions::from_mode(0o700)).unwrap();
    let config = config_parent.join("agent.toml");
    let anchors = anchor_parent.join("receipt-trust-anchors.json");
    let expected = expected_anchors();
    let digest = hex::encode(Sha256::digest(&expected));

    assert!(invoke(config.to_str().unwrap(), anchors.to_str().unwrap(), &digest).success());
    assert_eq!(fs::read(&config).unwrap(), CONFIG.as_bytes());
    assert_eq!(fs::read(&anchors).unwrap(), expected);
    assert!(invoke(config.to_str().unwrap(), anchors.to_str().unwrap(), &digest).success());
    assert!(
        !invoke(
            config.to_str().unwrap(),
            anchors.to_str().unwrap(),
            &"0".repeat(64)
        )
        .success()
    );
}
