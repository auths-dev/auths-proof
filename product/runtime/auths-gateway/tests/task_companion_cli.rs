#![cfg(unix)]

use auths_connections::{ConnectionAlias, ProviderKind};
use auths_gateway::{
    CompiledRecipe, FileGatewayAttemptStore, GatewayConnectionDescriptor, SharedConnection,
};
use std::{
    fs,
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    process::{Command, Stdio},
    sync::Arc,
};

const EDIT: &[u8] =
    include_bytes!("../../../../demos/google-employee-delegation/write_reference/recipe.json");
const EDIT_LOCK: &[u8] = include_bytes!(
    "../../../../demos/google-employee-delegation/write_reference/profile.lock.json"
);
const CREATE: &[u8] =
    include_bytes!("../../../../demos/google-employee-delegation/create_reference/recipe.json");
const CREATE_LOCK: &[u8] = include_bytes!(
    "../../../../demos/google-employee-delegation/create_reference/profile.lock.json"
);
const TRUST: &[u8] =
    include_bytes!("../../../../core/fixtures/v1/denied/untrusted-root.context.cbor");

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one installed connection and companion selection form one scenario"
)]
async fn one_development_installation_pins_both_google_task_recipes() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let root = fs::canonicalize(directory.path()).expect("canonical root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
    let state = root.join("gateway");
    let edit = root.join("edit.json");
    let edit_lock = root.join("edit.lock.json");
    let create = root.join("create.json");
    let create_lock = root.join("create.lock.json");
    let trust = root.join("trust.cbor");
    for (path, bytes) in [
        (&edit, EDIT),
        (&edit_lock, EDIT_LOCK),
        (&create, CREATE),
        (&create_lock, CREATE_LOCK),
        (&trust, TRUST),
    ] {
        fs::write(path, bytes).expect("operator input");
    }
    let edit_recipe = CompiledRecipe::compile(EDIT, EDIT_LOCK).expect("edit recipe");
    let create_recipe = CompiledRecipe::compile(CREATE, CREATE_LOCK).expect("create recipe");
    let edit_digest = edit_recipe.digest_hex();
    let create_digest = create_recipe.digest_hex();
    let mut child = Command::new(env!("CARGO_BIN_EXE_auths-gateway"))
        .args([
            "install",
            "--state-dir",
            state.to_str().expect("state path"),
            "--recipe",
            edit.to_str().expect("edit path"),
            "--profile-lock",
            edit_lock.to_str().expect("edit lock path"),
            "--task-companion-recipe",
            create.to_str().expect("create path"),
            "--task-companion-profile-lock",
            create_lock.to_str().expect("create lock path"),
            "--task-companion-approve-digest",
            &create_digest,
            "--trusted-context",
            trust.to_str().expect("trust path"),
            "--approve-digest",
            &edit_digest,
            "--provider",
            "google",
            "--alias",
            "jules-demo",
            "--account-label",
            "synthetic-jules-subject",
            "--credential-stdin",
            "--connection-json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("gateway install");
    child
        .stdin
        .take()
        .expect("credential stdin")
        .write_all(b"synthetic-demo-token\n")
        .expect("credential");
    let installed = child.wait_with_output().expect("install result");
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let response: serde_json::Value =
        serde_json::from_slice(&installed.stdout).expect("redacted install result");
    assert_eq!(response["recipe_digest"], edit_digest);
    assert_eq!(response["task_companion_digest"], create_digest);
    assert!(!String::from_utf8_lossy(&installed.stdout).contains("synthetic-demo-token"));
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(state.join("installation.json")).expect("manifest"))
            .expect("manifest JSON");
    assert_eq!(manifest["schema"], "auths.gateway-installation/6");
    assert_eq!(manifest["task_companion"]["recipe_digest"], create_digest);
    assert_eq!(
        fs::read(state.join("task-companion-recipe.json")).expect("recipe"),
        CREATE
    );
    assert_eq!(
        fs::read(state.join("task-companion-profile.lock.json")).expect("lock"),
        CREATE_LOCK
    );
    let shared = SharedConnection::new(
        Arc::new(FileGatewayAttemptStore::open(state.join("attempts")).expect("store")),
        ProviderKind::parse("google").expect("provider"),
        ConnectionAlias::parse("jules-demo").expect("alias"),
    );
    let loaded = shared
        .load()
        .await
        .expect("connection read")
        .expect("record");
    assert!(GatewayConnectionDescriptor::from_record(loaded.record(), &edit_recipe).is_ok());
    assert!(GatewayConnectionDescriptor::from_record(loaded.record(), &create_recipe).is_ok());

    let submit = |digest: &str| {
        Command::new(env!("CARGO_BIN_EXE_auths-gateway"))
            .args([
                "task-submit",
                "--state-dir",
                state.to_str().expect("state path"),
                "--task-id",
                "synthetic-task",
                "--recipe-digest",
                digest,
                "--agent-proof",
                "missing.proof",
                "--agent-action",
                "missing.action",
            ])
            .output()
            .expect("task submit result")
    };
    let recognized = submit(&create_digest);
    assert!(!recognized.status.success());
    assert!(
        String::from_utf8_lossy(&recognized.stderr)
            .contains("gateway.task.installation-unavailable"),
        "{}",
        String::from_utf8_lossy(&recognized.stderr)
    );
    let unknown = submit(&"f".repeat(64));
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("gateway.task.recipe-not-installed"));
    fs::write(state.join("task-companion-recipe.json"), b"{}")
        .expect("simulate operator file drift");
    let drifted = submit(&create_digest);
    assert!(!drifted.status.success());
    assert!(
        String::from_utf8_lossy(&drifted.stderr).contains("gateway.serve.installation-changed")
    );
}
