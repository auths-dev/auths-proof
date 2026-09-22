//! Hosted-only deployment probe: a distinct application UID can reach only
//! the application socket, not the gateway credential or admin socket.

#![cfg(target_os = "linux")]

use auths_gateway::CompiledRecipe;
use std::{
    fs,
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_auths-gateway");
const RECIPE: &[u8] = include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json");
const LOCK: &[u8] =
    include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json");
const TRUST: &[u8] =
    include_bytes!("../../../../core/fixtures/v1/denied/untrusted-root.context.cbor");

struct RunningGateway(Child);

impl Drop for RunningGateway {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn install(
    state: &Path,
    recipe: &Path,
    lock: &Path,
    context: &Path,
    digest: &str,
) -> std::process::Output {
    let mut child = Command::new(BIN)
        .arg("install")
        .arg("--state-dir")
        .arg(state)
        .arg("--recipe")
        .arg(recipe)
        .arg("--profile-lock")
        .arg(lock)
        .arg("--trusted-context")
        .arg(context)
        .arg("--approve-digest")
        .arg(digest)
        .arg("--provider")
        .arg("airtable")
        .arg("--alias")
        .arg("demo")
        .arg("--account-label")
        .arg("synthetic-account")
        .arg("--credential-header")
        .arg("Authorization")
        .arg("--credential-stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn synthetic install");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"synthetic-token\n")
        .expect("synthetic token");
    child.wait_with_output().expect("install output")
}

#[test]
#[ignore = "requires hosted Linux sudo and a distinct app UID"]
fn distinct_uid_cannot_read_credential_or_reach_admin() {
    let root = tempfile::tempdir().expect("short temporary root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755))
        .expect("app may traverse socket parent");
    let recipe_path = root.path().join("recipe.json");
    let lock_path = root.path().join("profile.lock.json");
    let trust_path = root.path().join("trusted.context.cbor");
    fs::write(&recipe_path, RECIPE).expect("recipe");
    fs::write(&lock_path, LOCK).expect("lock");
    fs::write(&trust_path, TRUST).expect("trust fixture");
    let digest = CompiledRecipe::compile(RECIPE, LOCK)
        .expect("compiled recipe")
        .digest_hex();

    let invalid_context = root.path().join("invalid.context.cbor");
    fs::write(&invalid_context, b"invalid-context").expect("invalid context fixture");
    let invalid_state = root.path().join("invalid-state");
    let rejected = install(
        &invalid_state,
        &recipe_path,
        &lock_path,
        &invalid_context,
        &digest,
    );
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("gateway.install.invalid-trusted-context")
    );
    assert!(
        !invalid_state.exists(),
        "invalid trust must not create credential state"
    );

    let state = root.path().join("state");
    let installed = install(&state, &recipe_path, &lock_path, &trust_path, &digest);
    assert!(
        installed.status.success(),
        "synthetic gateway installation refused"
    );
    let app_socket = root.path().join("app.sock");
    let gateway = Command::new(BIN)
        .arg("serve")
        .arg("--state-dir")
        .arg(&state)
        .arg("--app-socket")
        .arg(&app_socket)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start gateway");
    let _gateway = RunningGateway(gateway);
    let deadline = Instant::now() + Duration::from_secs(5);
    while (!app_socket.exists() || !state.join("admin.sock").exists()) && Instant::now() < deadline
    {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        app_socket.exists() && state.join("admin.sock").exists(),
        "gateway did not bind sockets"
    );

    let group = Command::new("id").arg("-g").output().expect("runner group");
    assert!(group.status.success());
    let group = String::from_utf8(group.stdout).expect("numeric group");
    let doctor = Command::new("sudo")
        .arg("-n")
        .arg(BIN)
        .arg("doctor")
        .arg("--state-dir")
        .arg(&state)
        .arg("--app-socket")
        .arg(&app_socket)
        .arg("--app-uid")
        .arg("65534")
        .arg("--app-gid")
        .arg(group.trim())
        .output()
        .expect("run distinct-UID doctor");
    assert!(
        doctor.status.success(),
        "distinct-UID boundary failed: {}",
        String::from_utf8_lossy(&doctor.stderr)
    );
    assert!(
        String::from_utf8_lossy(&doctor.stdout).contains("gateway state and admin socket denied")
    );
}
