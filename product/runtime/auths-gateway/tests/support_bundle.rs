//! The support bundle of a real installation, scanned for every canary the
//! custody fixture plants: the provider credential, the account label, and
//! files and environment variables holding each other excluded source.

#![cfg(unix)]
#![allow(clippy::too_many_lines, reason = "one journey reads top to bottom")]

use auths_gateway::CompiledRecipe;
use auths_recipe_qualification_issuance::stages::{ScanSource, SourceKind, redaction};
use std::{
    fs::{self, File},
    io::{BufRead as _, BufReader, Write as _},
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Child, Command, Output, Stdio},
};

const BIN: &str = env!("CARGO_BIN_EXE_auths-gateway");
const RECIPE: &[u8] = include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json");
const LOCK: &[u8] =
    include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json");
const TRUST: &[u8] =
    include_bytes!("../../../../core/fixtures/v1/denied/untrusted-root.context.cbor");
const CUSTODY: &[u8] = include_bytes!("../../../../bindings/fixtures/gateway/custody-hostile.json");

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Every canary of the fixture, by the source it is planted in.
fn canaries() -> Vec<(String, String)> {
    let fixture: serde_json::Value = serde_json::from_slice(CUSTODY).expect("fixture");
    fixture["redaction"]["canaries"]["sources"]
        .as_array()
        .expect("sources")
        .iter()
        .map(|source| {
            let text = |member: &str| source[member].as_str().expect("text").to_owned();
            (text("source"), text("canary"))
        })
        .collect()
}

fn run(command: &mut Command, stdin: &[u8]) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin)
        .expect("stdin bytes");
    child.wait_with_output().expect("output")
}

fn bundle(state: &Path, planted: &[(String, String)]) -> Vec<u8> {
    let mut command = Command::new(BIN);
    command.arg("support-bundle").arg("--state-dir").arg(state);
    for (source, canary) in planted {
        command.env(
            format!("AUTHS_TEST_{}", source.replace('-', "_").to_uppercase()),
            canary,
        );
    }
    let output = run(&mut command, b"");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

#[test]
fn a_support_bundle_holds_no_planted_canary() {
    let planted = canaries();
    assert_eq!(planted.len(), 11);
    let canary = |source: &str| {
        planted
            .iter()
            .find(|(name, _)| name == source)
            .map(|(_, canary)| canary.clone())
            .expect("canary")
    };
    let directory = tempfile::tempdir().expect("directory");
    let root = fs::canonicalize(directory.path()).expect("root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("mode");
    fs::write(root.join("recipe.json"), RECIPE).expect("recipe");
    fs::write(root.join("profile.lock.json"), LOCK).expect("lock");
    fs::write(root.join("trusted.context.cbor"), TRUST).expect("trust");
    let state = root.join("state");
    let digest = CompiledRecipe::compile(RECIPE, LOCK)
        .expect("recipe")
        .digest_hex();

    // The credential and the provider account label are the two canaries an
    // installation takes in directly.
    let installed = run(
        Command::new(BIN)
            .arg("install")
            .arg("--state-dir")
            .arg(&state)
            .arg("--recipe")
            .arg(root.join("recipe.json"))
            .arg("--profile-lock")
            .arg(root.join("profile.lock.json"))
            .arg("--trusted-context")
            .arg(root.join("trusted.context.cbor"))
            .arg("--approve-digest")
            .arg(&digest)
            .arg("--provider")
            .arg("airtable")
            .arg("--alias")
            .arg("demo")
            .arg("--account-label")
            .arg(canary("provider-account-id"))
            .arg("--credential-stdin"),
        format!("{}\n", canary("credential")).as_bytes(),
    );
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    // Every other excluded source, left where a careless collector would
    // sweep it up: beside the installation and in the environment.
    for (source, canary) in &planted {
        fs::write(state.join(format!("{source}.captured")), canary).expect("planted file");
    }

    let offline = bundle(&state, &planted);
    let archive: serde_json::Value = serde_json::from_slice(&offline).expect("archive");
    assert_eq!(archive["schema"], "auths.gateway-support-bundle/1");
    assert_eq!(archive["recipe_sha256"], digest.as_str());
    assert_eq!(archive["deployment"], "development");
    assert_eq!(archive["attempts"]["listed"], 0);
    assert!(archive["connection"].is_null(), "no gateway is serving");
    assert!(
        archive["codes"]
            .as_array()
            .expect("codes")
            .iter()
            .any(|code| code == "gateway.support.gateway-not-serving")
    );

    let mut child = Command::new(BIN)
        .arg("serve")
        .arg("--state-dir")
        .arg(&state)
        .arg("--app-socket")
        .arg(root.join("app.sock"))
        .stdout(Stdio::piped())
        .stderr(File::create(root.join("serve.stderr")).expect("stderr"))
        .spawn()
        .expect("serve");
    let mut ready = String::new();
    BufReader::new(child.stdout.take().expect("stdout"))
        .read_line(&mut ready)
        .expect("readiness");
    let _serving = Running(child);
    assert!(ready.starts_with("app socket ready"), "{ready}");
    let serving = bundle(&state, &planted);
    let archive: serde_json::Value = serde_json::from_slice(&serving).expect("archive");
    assert_eq!(archive["connection"]["state"], "active");
    assert_eq!(archive["connection"]["credential_held"], true);

    let secrets: Vec<&[u8]> = planted
        .iter()
        .map(|(_, canary)| canary.as_bytes())
        .collect();
    let sources = [
        ScanSource {
            kind: SourceKind::SupportBundle,
            name: "offline",
            bytes: &offline,
        },
        ScanSource {
            kind: SourceKind::SupportBundle,
            name: "serving",
            bytes: &serving,
        },
    ];
    let scanned = redaction(&secrets, &sources).expect("scan");
    assert!(scanned.iter().all(|case| case.passed), "{scanned:?}");

    // The scan is able to find one: the same bytes with a canary appended
    // fail it.
    let leaking = [offline.as_slice(), canary("raw-header").as_bytes()].concat();
    let found = redaction(
        &secrets,
        &[ScanSource {
            kind: SourceKind::SupportBundle,
            name: "leaking",
            bytes: &leaking,
        }],
    )
    .expect("scan");
    assert!(!found[0].passed);
}
