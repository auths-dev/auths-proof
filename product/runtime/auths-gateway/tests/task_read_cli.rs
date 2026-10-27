#![cfg(unix)]

use auths_connections::ConnectionId;
use auths_gateway::{CompiledReleaseRecipe, CredentialJournal};
use serde_json::json;
use std::{
    fs,
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    process::{Command, Stdio},
};

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "each CLI install and retry are a single scenario"
)]
fn installed_google_and_airtable_read_connections_keep_independent_private_state() {
    for (recipe, lock, provider, alias) in [
        (
            include_bytes!(
                "../../../../demos/google-employee-delegation/read_reference/recipe.json"
            )
            .as_slice(),
            include_bytes!(
                "../../../../demos/google-employee-delegation/read_reference/profile.lock.json"
            )
            .as_slice(),
            "google",
            "jules-read",
        ),
        (
            include_bytes!("../../../../demos/airtable-gateway/read_reference/recipe.json")
                .as_slice(),
            include_bytes!("../../../../demos/airtable-gateway/read_reference/profile.lock.json")
                .as_slice(),
            "airtable",
            "operator-read",
        ),
    ] {
        check_read_installation(recipe, lock, provider, alias);
    }
}

fn write_installation(root: &std::path::Path, provider: &str) {
    let manifest = json!({
        "schema": "auths.gateway-installation/6",
        "recipe_digest": "write-recipe-is-not-loaded-by-read-connect",
        "profile_lock_sha256": "write-lock-is-not-loaded-by-read-connect",
        "task_companion": null,
        "trusted_context_sha256": "write-trust-is-not-loaded-by-read-connect",
        "provider": provider,
        "alias": "operator-write",
        "deployment": "development",
        "operator_attestation_sha256": null,
        "attempt_store": root.display().to_string(),
        "credential_store": {"kind": "local-file-v1"},
        "qualification": {"policy": "optional"}
    });
    fs::write(
        root.join("installation.json"),
        serde_json_canonicalizer::to_vec(&manifest).expect("canonical manifest"),
    )
    .expect("manifest");
}

fn check_read_installation(recipe_source: &[u8], lock_source: &[u8], provider: &str, alias: &str) {
    let directory = tempfile::tempdir().expect("test directory");
    let root = fs::canonicalize(directory.path()).expect("canonical directory");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private directory");
    write_installation(&root, provider);
    let write_id = ConnectionId::generate().expect("existing write connection ID");
    let write_journal = CredentialJournal::new(root.clone());
    write_journal.initialize(&write_id).expect("write journal");
    let recipe = root.join("read-recipe.input.json");
    let lock = root.join("read-lock.input.json");
    fs::write(&recipe, recipe_source).expect("recipe");
    fs::write(&lock, lock_source).expect("lock");
    let compiled = CompiledReleaseRecipe::compile(
        &fs::read(&recipe).expect("recipe bytes"),
        &fs::read(&lock).expect("lock bytes"),
    )
    .expect("closed GET recipe");
    let command = || {
        let mut process = Command::new(env!("CARGO_BIN_EXE_auths-gateway"));
        process.args([
            "task-read-connect",
            "--state-dir",
            root.to_str().expect("state path"),
            "--recipe",
            recipe.to_str().expect("recipe path"),
            "--profile-lock",
            lock.to_str().expect("lock path"),
            "--approve-digest",
            &compiled.digest_hex(),
            "--provider",
            provider,
            "--alias",
            alias,
            "--account-subject",
            "synthetic-account-subject",
            "--credential-stdin",
        ]);
        process
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = process.spawn().expect("gateway process");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(b"synthetic-demo-token\n")
            .expect("credential input");
        child.wait_with_output().expect("gateway result")
    };
    let first = command();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let response: serde_json::Value = serde_json::from_slice(&first.stdout).expect("redacted JSON");
    assert_eq!(response["outcome"], "read-connection-installed");
    assert_eq!(response["connection_generation"], 1);
    assert_eq!(response["recipe_digest"], compiled.digest_hex());
    assert!(!String::from_utf8_lossy(&first.stdout).contains("synthetic-demo-token"));
    for path in [
        "task-read-installation.json",
        "task-read-recipe.json",
        "task-read-profile.lock.json",
        "task-read-credential-journal/credential-journal.json",
        "task-read-floor/connection-floor.json",
    ] {
        assert!(root.join(path).exists(), "missing {path}");
    }
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join("task-read-installation.json")).expect("read installation"),
    )
    .expect("read installation JSON");
    assert_eq!(manifest["connection_id"], response["connection_id"]);
    assert_eq!(manifest["connection_subject"], "synthetic-account-subject");
    assert_eq!(
        write_journal.generations(&write_id).expect("write journal"),
        vec![]
    );
    let second = command();
    assert!(!second.status.success());
    assert!(
        String::from_utf8_lossy(&second.stderr)
            .contains("gateway.release.already-or-partially-installed")
    );
}
