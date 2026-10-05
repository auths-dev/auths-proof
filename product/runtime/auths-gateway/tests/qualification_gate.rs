//! The qualification gate through real gateway processes: what install
//! accepts, what import accepts, and what a served gateway derives from the
//! inputs on its host.

#![cfg(unix)]
#![allow(clippy::too_many_lines, reason = "one journey reads top to bottom")]

use auths_gateway::CompiledRecipe;
use auths_recipe_qualification::QualificationTuple;
use auths_recipe_qualification_issuance::testkit::{self, TestRelease};
use std::{
    fs::{self, File},
    io::{BufRead as _, BufReader, Write as _},
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const BIN: &str = env!("CARGO_BIN_EXE_auths-gateway");
const RECIPE: &[u8] = include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json");
const LOCK: &[u8] =
    include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json");
const TRUST: &[u8] =
    include_bytes!("../../../../core/fixtures/v1/denied/untrusted-root.context.cbor");
const FAMILY: &str = "example-field-update-v1";
const UNAVAILABLE: &str = "gateway.qualification.unavailable";

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn contract() -> String {
    "33".repeat(32)
}

fn private_root() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("temporary root");
    let root = fs::canonicalize(directory.path()).expect("canonical root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
    fs::write(root.join("recipe.json"), RECIPE).expect("recipe");
    fs::write(root.join("profile.lock.json"), LOCK).expect("lock");
    fs::write(root.join("trusted.context.cbor"), TRUST).expect("trust");
    (directory, root)
}

fn run(command: &mut Command, stdin: &[u8]) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gateway command");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin)
        .expect("stdin bytes");
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().expect("poll").is_none() {
        assert!(Instant::now() < deadline, "command did not finish");
        thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().expect("output")
}

fn install(root: &Path, state: &Path, arguments: &[&str]) -> Output {
    let digest = CompiledRecipe::compile(RECIPE, LOCK)
        .expect("compiled recipe")
        .digest_hex();
    run(
        Command::new(BIN)
            .arg("install")
            .arg("--state-dir")
            .arg(state)
            .arg("--recipe")
            .arg(root.join("recipe.json"))
            .arg("--profile-lock")
            .arg(root.join("profile.lock.json"))
            .arg("--trusted-context")
            .arg(root.join("trusted.context.cbor"))
            .arg("--approve-digest")
            .arg(digest)
            .arg("--provider")
            .arg("airtable")
            .arg("--alias")
            .arg("demo")
            .arg("--account-label")
            .arg("synthetic-account")
            .arg("--credential-stdin")
            .args(arguments),
        b"synthetic-token\n",
    )
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn gateway(arguments: &[&str]) -> Output {
    run(Command::new(BIN).args(arguments), b"")
}

/// Starts `serve` and returns it with its readiness line.
fn serve(state: &Path, app_socket: &Path) -> (Running, String) {
    let mut child = Command::new(BIN)
        .arg("serve")
        .arg("--state-dir")
        .arg(state)
        .arg("--app-socket")
        .arg(app_socket)
        .stdout(Stdio::piped())
        .stderr(File::create(state.with_extension("stderr")).expect("stderr"))
        .spawn()
        .expect("serve");
    let mut ready = String::new();
    BufReader::new(child.stdout.take().expect("stdout"))
        .read_line(&mut ready)
        .expect("readiness");
    assert!(ready.starts_with("app socket ready"), "{ready}");
    (Running(child), ready)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

#[test]
fn install_refuses_a_policy_production_does_not_permit() {
    let (_directory, root) = private_root();
    let trust_root = root.join("root.json");
    fs::write(
        &trust_root,
        TestRelease::new(now()).pinned().canonical_bytes(),
    )
    .expect("root");
    let trust_root = trust_root.display().to_string();
    let contract = contract();
    let declared = [
        "--recipe-family",
        FAMILY,
        "--provider-contract-id",
        &contract,
    ];
    let production = [
        "--deployment",
        "production",
        "--credential-store",
        "aws-secrets-manager-v1",
    ];
    let cases: [(&str, Vec<&str>); 7] = [
        (
            "production with the optional policy",
            [&production[..], &["--qualification-policy", "optional"]].concat(),
        ),
        (
            "production with its own trust root",
            [
                &production[..],
                &declared[..],
                &["--qualification-trust-root", &trust_root],
            ]
            .concat(),
        ),
        ("production with no declared family", production.to_vec()),
        (
            "a required policy with no declared contract",
            vec![
                "--qualification-policy",
                "required",
                "--recipe-family",
                FAMILY,
            ],
        ),
        (
            "a policy outside the closed set",
            [&declared[..], &["--qualification-policy", "force"]].concat(),
        ),
        (
            "a family that is not an identifier",
            vec![
                "--recipe-family",
                "Example Refund",
                "--provider-contract-id",
                &contract,
            ],
        ),
        (
            "a contract that is not a digest",
            vec![
                "--recipe-family",
                FAMILY,
                "--provider-contract-id",
                "latest",
            ],
        ),
    ];
    for (name, arguments) in cases {
        if name.starts_with("production") && cfg!(feature = "testkit-production-unqualified") {
            // A build made for tests relaxes production qualification.
            continue;
        }
        let state = root.join("refused");
        let refused = install(&root, &state, &arguments);
        assert!(!refused.status.success(), "{name}");
        assert!(
            text(&refused.stderr).starts_with("gateway.install.qualification-policy"),
            "{name}: {}",
            text(&refused.stderr)
        );
        assert!(!state.join("installation.json").exists(), "{name}");
    }
}

#[test]
fn a_host_qualifies_only_from_a_release_its_root_signed() {
    let (_directory, root) = private_root();
    let at = now();
    let release = TestRelease::new(at);
    let trust_root = root.join("root.json");
    fs::write(&trust_root, release.pinned().canonical_bytes()).expect("root");
    let state = root.join("state");
    let state_text = state.display().to_string();
    let installed = install(
        &root,
        &state,
        &[
            "--qualification-policy",
            "required",
            "--recipe-family",
            FAMILY,
            "--provider-contract-id",
            &contract(),
            "--qualification-trust-root",
            &trust_root.display().to_string(),
        ],
    );
    assert!(installed.status.success(), "{}", text(&installed.stderr));

    let status = || gateway(&["qualification-status", "--state-dir", &state_text]);
    let import = |from: &Path| {
        gateway(&[
            "qualification-import",
            "--state-dir",
            &state_text,
            "--from",
            &from.display().to_string(),
        ])
    };

    // Nothing imported: unqualified, and the status command says why.
    let before = status();
    assert!(!before.status.success());
    assert_eq!(
        text(&before.stdout).trim(),
        format!("policy=required state=unqualified code={UNAVAILABLE}")
    );

    // The tuple is derived from the installed files and this executable.
    let printed = gateway(&[
        "qualification-status",
        "--state-dir",
        &state_text,
        "--tuple",
    ]);
    assert!(printed.status.success(), "{}", text(&printed.stderr));
    let tuple: QualificationTuple =
        serde_json::from_slice(text(&printed.stdout).trim().as_bytes()).expect("tuple");
    assert_eq!(tuple.recipe_family.as_str(), FAMILY);
    assert_eq!(
        tuple.compiled_recipe_sha256.to_hex(),
        CompiledRecipe::compile(RECIPE, LOCK)
            .expect("recipe")
            .digest_hex()
    );
    assert_eq!(
        tuple.gateway_semantic_closure_sha256.to_hex(),
        auths_gateway::GATEWAY_SEMANTIC_CLOSURE_SHA256
    );

    let proposal = testkit::proposal(1, &tuple, at);
    let qualification_id = proposal.record().body().qualification_id.clone();
    let signed = release.release(&[&proposal]);

    // An unsigned proposal, as a pull request could produce, is not imported.
    let mut unsigned = signed.clone();
    unsigned.release_index.clear();
    unsigned.attestations.clear();
    unsigned
        .write_to(&root.join("unsigned"))
        .expect("release directory");
    let refused = import(&root.join("unsigned"));
    assert!(!refused.status.success());
    assert!(
        text(&refused.stderr).starts_with(UNAVAILABLE),
        "{}",
        text(&refused.stderr)
    );
    let mut forged = signed.clone();
    let position = forged.signer_certificate.len() - 3;
    forged.signer_certificate[position] ^= 1;
    forged
        .write_to(&root.join("forged"))
        .expect("release directory");
    assert!(text(&import(&root.join("forged")).stderr).starts_with(UNAVAILABLE));
    assert!(
        !state.join("qualification").exists(),
        "a refused import changes nothing"
    );

    // The signed release qualifies this exact deployment.
    signed
        .write_to(&root.join("release"))
        .expect("release directory");
    let imported = import(&root.join("release"));
    assert!(imported.status.success(), "{}", text(&imported.stderr));
    assert_eq!(
        text(&imported.stdout).trim(),
        "imported qualification inputs: state=qualified code=none"
    );
    assert_eq!(
        text(&status().stdout).trim(),
        "policy=required state=qualified code=none"
    );

    // A served gateway reports the state it derived at startup, and reads a
    // new import through its operator socket.
    let (serving, ready) = serve(&state, &root.join("app.sock"));
    assert!(
        ready.contains("qualification policy=required state=qualified code=none"),
        "{ready}"
    );
    let mut revoking = signed.clone();
    revoking.revocation_list = release.list(2, at, &[&qualification_id]);
    revoking
        .write_to(&root.join("revoking"))
        .expect("release directory");
    let revoked = import(&root.join("revoking"));
    let lines = text(&revoked.stdout);
    let response: serde_json::Value =
        serde_json::from_str(lines.lines().nth(1).expect("admin response")).expect("JSON");
    assert_eq!(
        response["code"], "gateway.admin.qualification-reloaded",
        "{response}"
    );
    assert_eq!(response["qualification"]["state"], "revoked", "{response}");
    assert_eq!(
        response["qualification"]["code"], "gateway.qualification.revoked",
        "{response}"
    );
    drop(serving);

    // The original release is now older than what this host accepted, and a
    // later list that omits the qualification does not restore it.
    assert!(text(&import(&root.join("release")).stderr).starts_with(UNAVAILABLE));
    let mut omitting = signed.clone();
    omitting.revocation_list = release.list(3, at, &[]);
    omitting
        .write_to(&root.join("omitting"))
        .expect("release directory");
    assert!(import(&root.join("omitting")).status.success());
    let after = status();
    assert!(!after.status.success());
    assert_eq!(
        text(&after.stdout).trim(),
        "policy=required state=revoked code=gateway.qualification.revoked"
    );

    // Damage to what the host remembers refuses rather than forgets, and
    // disables the recipe without stopping the gateway.
    fs::write(state.join("qualification-state.json"), b"{}").expect("damage");
    let damaged = status();
    assert!(!damaged.status.success());
    assert_eq!(
        text(&damaged.stdout).trim(),
        format!("policy=required state=unqualified code={UNAVAILABLE}")
    );
    assert!(
        text(&import(&root.join("omitting")).stderr).starts_with(UNAVAILABLE),
        "nothing is imported over a damaged record"
    );
    let (_serving, ready) = serve(&state, &root.join("app.sock"));
    assert!(
        ready.contains(&format!(
            "qualification policy=required state=unqualified code={UNAVAILABLE}"
        )),
        "{ready}"
    );
}

#[test]
fn a_development_installation_defaults_to_the_optional_policy() {
    let (_directory, root) = private_root();
    let state = root.join("state");
    let installed = install(&root, &state, &[]);
    assert!(installed.status.success(), "{}", text(&installed.stderr));
    let status = gateway(&[
        "qualification-status",
        "--state-dir",
        &state.display().to_string(),
    ]);
    assert!(status.status.success(), "{}", text(&status.stderr));
    assert_eq!(
        text(&status.stdout).trim(),
        format!("policy=optional state=unqualified code={UNAVAILABLE}")
    );
}
