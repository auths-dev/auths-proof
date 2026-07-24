use std::{path::PathBuf, process::Command};

const ROOT: &str = "key:sha256:dn9ZYzD5Wup7QPTK36C8xM2uAKmJNAYXt4-vO9mFkYg";
const CHALLENGE: &str = "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5";

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("apps directory")
        .parent()
        .expect("repository root")
        .to_path_buf()
}

fn verify_command(proof: &str) -> Command {
    let root = repository_root();
    let mut command = Command::new(env!("CARGO_BIN_EXE_auths-proof"));
    command.args([
        "verify",
        "--proof",
        root.join(proof).to_str().expect("UTF-8 proof path"),
        "--body",
        root.join("fixtures/v1/valid/action.json")
            .to_str()
            .expect("UTF-8 body path"),
        "--now",
        "1725000125",
        "--audience",
        "mcp://filesystem",
        "--challenge-hex",
        CHALLENGE,
        "--anchor-principal",
        ROOT,
        "--anchor-capability",
        "mcp.tools.call",
        "--anchor-resource",
        "mcp://filesystem/read_file",
        "--anchor-valid-from",
        "1725000000",
        "--anchor-valid-until",
        "1725000300",
        "--anchor-depth",
        "1",
    ]);
    command
}

#[test]
fn valid_fixture_exits_zero() {
    let output = verify_command("fixtures/v1/valid/mixed-ed25519-p256.cbor")
        .output()
        .expect("run verifier");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("Authorized"));
}

#[test]
fn invalid_signature_exits_two() {
    let output = verify_command("fixtures/v1/invalid/invalid-action-signature.cbor")
        .output()
        .expect("run verifier");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stdout).contains("InvalidSignature"));
}
