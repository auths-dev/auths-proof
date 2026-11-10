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

fn install_command(root: &Path, state: &Path, arguments: &[&str]) -> Command {
    let digest = CompiledRecipe::compile(RECIPE, LOCK)
        .expect("compiled recipe")
        .digest_hex();
    let mut command = Command::new(BIN);
    command
        .arg("install")
        .arg("--effect-policy")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../bindings/fixtures/gateway/effect-policy.json"
        ))
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
        .args([
            "--provider",
            "airtable",
            "--alias",
            "demo",
            "--account-label",
            "synthetic-account",
            "--credential-stdin",
        ])
        .args(arguments);
    command
}

fn install(root: &Path, state: &Path, arguments: &[&str]) -> Output {
    run(
        &mut install_command(root, state, arguments),
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

#[cfg(feature = "testkit-harness")]
mod ap076_recovery {
    use super::*;
    use serde_json::Value;

    fn boundaries(output: &Output) -> Vec<String> {
        text(&output.stderr)
            .lines()
            .filter_map(|line| {
                line.strip_prefix("auths-test-admin-boundary:")
                    .map(str::to_owned)
            })
            .collect()
    }

    fn report(state: &Path) -> (Output, Value) {
        let result = gateway(&[
            "recovery-status",
            "--state-dir",
            &state.display().to_string(),
        ]);
        let value = serde_json::from_slice(&result.stdout)
            .expect("bounded recovery JSON even on an unavailable component");
        (result, value)
    }

    fn import_command(state: &Path, from: &Path) -> Command {
        let mut command = Command::new(BIN);
        command
            .arg("qualification-import")
            .arg("--state-dir")
            .arg(state)
            .arg("--from")
            .arg(from);
        command
    }

    #[test]
    fn installation_recovers_or_explicitly_quarantines_every_interruption_boundary() {
        let (_trace_directory, trace_root) = private_root();
        let trace_state = trace_root.join("state");
        let trace = run(
            install_command(&trace_root, &trace_state, &[]).env("AUTHS_TEST_ADMIN_TRACE", "1"),
            b"synthetic-token\n",
        );
        assert!(trace.status.success(), "{}", text(&trace.stderr));
        let points = boundaries(&trace);
        assert!(
            points
                .iter()
                .any(|point| point.ends_with(":installation.before-custody"))
        );
        assert!(
            points
                .iter()
                .any(|point| point.ends_with(":installation.after-native-publication-ack"))
        );
        for (index, point) in points.iter().enumerate() {
            let (_directory, root) = private_root();
            let state = root.join("state");
            let interrupted = run(
                install_command(&root, &state, &[])
                    .env("AUTHS_TEST_ADMIN_INTERRUPT_AT", (index + 1).to_string()),
                b"synthetic-token\n",
            );
            assert_eq!(
                interrupted.status.code(),
                Some(79),
                "{point}: {}",
                text(&interrupted.stderr)
            );
            let draft = fs::read(state.join("candidate-installation.cbor")).ok();
            let resumed = install(&root, &state, &["--resume"]);
            let (_, facts) = report(&state);
            assert_eq!(facts["schema"], "auths.gateway-recovery/1", "{point}");
            if resumed.status.success() {
                assert_eq!(facts["installation"], "published", "{point}: {facts}");
                let repeated = install(&root, &state, &["--resume"]);
                assert!(
                    repeated.status.success(),
                    "{point}: {}",
                    text(&repeated.stderr)
                );
                let (_, again) = report(&state);
                assert_eq!(
                    again, facts,
                    "acknowledged state must survive immediate process restart: {point}"
                );
            } else {
                assert!(
                    text(&resumed.stderr).contains("credential-operation-unconfirmed"),
                    "{point}: {}",
                    text(&resumed.stderr)
                );
                assert_eq!(
                    facts["native"]["facts"]["cleanup"]["state"], "creation-unconfirmed",
                    "{point}: {facts}"
                );
                assert_ne!(facts["installation"], "published", "{point}");
            }
            if let Some(draft) = draft {
                assert_eq!(
                    fs::read(state.join("candidate-installation.cbor")).expect("retained draft"),
                    draft,
                    "identity/timestamps cannot change: {point}"
                );
            }
        }
    }

    fn qualified_install(root: &Path, state: &Path, release: &TestRelease) -> QualificationTuple {
        let trust_root = root.join("root.json");
        fs::write(&trust_root, release.pinned().canonical_bytes()).expect("root");
        let installed = install(
            root,
            state,
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
        let tuple = gateway(&[
            "qualification-status",
            "--state-dir",
            &state.display().to_string(),
            "--tuple",
        ]);
        assert!(tuple.status.success(), "{}", text(&tuple.stderr));
        serde_json::from_slice(&tuple.stdout).expect("tuple")
    }

    #[test]
    fn qualification_first_import_and_replacement_survive_every_boundary_and_repeat() {
        let at = now();
        let release = TestRelease::new(at);
        for replacement in [false, true] {
            let (_trace_directory, trace_root) = private_root();
            let trace_state = trace_root.join("state");
            let tuple = qualified_install(&trace_root, &trace_state, &release);
            let original = release.release(&[&testkit::proposal(1, &tuple, at)]);
            let successor = release.release(&[&testkit::proposal(2, &tuple, at)]);
            original
                .write_to(&trace_root.join("original"))
                .expect("original bundle");
            if replacement {
                assert!(
                    run(
                        &mut import_command(&trace_state, &trace_root.join("original")),
                        b""
                    )
                    .status
                    .success()
                );
            }
            let bundle = if replacement { &successor } else { &original };
            bundle
                .write_to(&trace_root.join("release"))
                .expect("candidate release");
            let trace = run(
                import_command(&trace_state, &trace_root.join("release"))
                    .env("AUTHS_TEST_ADMIN_TRACE", "1"),
                b"",
            );
            assert!(trace.status.success(), "{}", text(&trace.stderr));
            let points = boundaries(&trace);
            assert!(
                points
                    .iter()
                    .any(|point| point.ends_with(":qualification.after-native-floor"))
            );
            assert!(
                points
                    .iter()
                    .any(|point| point.ends_with(":qualification.after-publication-sync"))
            );
            for (index, point) in points.iter().enumerate() {
                let (_directory, root) = private_root();
                let state = root.join("state");
                let actual_tuple = qualified_install(&root, &state, &release);
                assert_eq!(actual_tuple, tuple, "test tuple excludes host paths");
                original
                    .write_to(&root.join("original"))
                    .expect("original bundle");
                if replacement {
                    assert!(
                        run(&mut import_command(&state, &root.join("original")), b"")
                            .status
                            .success()
                    );
                }
                bundle
                    .write_to(&root.join("release"))
                    .expect("candidate bundle");
                let custody =
                    fs::read(state.join("credentials.cbor")).expect("custody before import");
                let interrupted = run(
                    import_command(&state, &root.join("release"))
                        .env("AUTHS_TEST_ADMIN_INTERRUPT_AT", (index + 1).to_string()),
                    b"",
                );
                assert_eq!(
                    interrupted.status.code(),
                    Some(79),
                    "replacement={replacement}, {point}: {}",
                    text(&interrupted.stderr)
                );
                let imported = run(&mut import_command(&state, &root.join("release")), b"");
                assert!(
                    imported.status.success(),
                    "replacement={replacement}, {point}: {}",
                    text(&imported.stderr)
                );
                for _ in 0..2 {
                    let recovery = gateway(&[
                        "qualification-recover",
                        "--state-dir",
                        &state.display().to_string(),
                    ]);
                    assert!(
                        recovery.status.success(),
                        "replacement={replacement}, {point}: {}",
                        text(&recovery.stderr)
                    );
                }
                assert_eq!(
                    fs::read(state.join("credentials.cbor")).expect("unchanged custody"),
                    custody,
                    "qualification recovery cannot mutate custody"
                );
                let (status, facts) = report(&state);
                assert!(status.status.success(), "{point}: {}", text(&status.stderr));
                assert_eq!(
                    facts["qualification"]["state"], "current-published",
                    "{point}: {facts}"
                );
                assert_eq!(
                    fs::read(
                        state
                            .join("qualification")
                            .join(auths_recipe_qualification::RELEASE_INDEX_FILE)
                    )
                    .expect("published exact index"),
                    bundle.release_index
                );
                assert!(!state.join("qualification.next").exists());
                assert!(!state.join("qualification.previous").exists());
                let (_, restarted) = report(&state);
                assert_eq!(
                    restarted, facts,
                    "acknowledged publication survives restart: {point}"
                );
            }
        }
    }

    #[test]
    fn competing_identical_imports_share_native_truth_and_never_erase_a_floor() {
        let (_directory, root) = private_root();
        let state = root.join("state");
        let at = now();
        let release = TestRelease::new(at);
        let tuple = qualified_install(&root, &state, &release);
        let bundle = release.release(&[&testkit::proposal(1, &tuple, at)]);
        bundle.write_to(&root.join("release")).expect("release");
        let from = root.join("release");
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let state = state.clone();
                let from = from.clone();
                std::thread::spawn(move || run(&mut import_command(&state, &from), b""))
            })
            .collect();
        for handle in handles {
            let output = handle.join().expect("import worker");
            assert!(output.status.success(), "{}", text(&output.stderr));
        }
        let (_, first) = report(&state);
        let repeated = run(&mut import_command(&state, &from), b"");
        assert!(repeated.status.success(), "{}", text(&repeated.stderr));
        let (_, second) = report(&state);
        assert_eq!(first, second);
        assert_eq!(second["qualification"]["state"], "current-published");
    }
}
