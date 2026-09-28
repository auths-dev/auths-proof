//! The operator plane across real gateway processes: two installations
//! share a store (the development file store, or the production
//! `PostgreSQL` store where the TLS fixture runs), the second joins with the
//! same secret, and a change committed through either process's admin socket
//! is what the other process reports next. A production install names its
//! operator only through a verifying attestation.

#![cfg(unix)]

use auths_gateway::CompiledRecipe;
use base64ct::Encoding as _;
use std::{
    fs::{self, File},
    io::{BufRead as _, BufReader, Write as _},
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_auths-gateway");
const RECIPE: &[u8] = include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json");
const LOCK: &[u8] =
    include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json");
const TRUST: &[u8] =
    include_bytes!("../../../../core/fixtures/v1/denied/untrusted-root.context.cbor");

thread_local! {
    /// The `PostgreSQL` secret slots every gateway command of this test
    /// thread inherits; empty for the development store.
    static POSTGRES: std::cell::RefCell<Vec<(&'static str, String)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
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

fn digest() -> String {
    CompiledRecipe::compile(RECIPE, LOCK)
        .expect("compiled recipe")
        .digest_hex()
}

fn run(command: &mut Command, stdin: &[u8]) -> Output {
    for (name, value) in POSTGRES.with(|slot| slot.borrow().clone()) {
        command.env(name, value);
    }
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

/// `install` with the root's recipe, lock, and trust, plus `arguments`.
fn install(root: &Path, state: &Path, arguments: &[&str], secret: &[u8]) -> Output {
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
            .arg(digest())
            .arg("--provider")
            .arg("airtable")
            .arg("--alias")
            .arg("demo")
            .arg("--credential-stdin")
            .args(arguments),
        secret,
    )
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn serve(state: &Path, app_socket: &Path) -> Running {
    let mut command = Command::new(BIN);
    for (name, value) in POSTGRES.with(|slot| slot.borrow().clone()) {
        command.env(name, value);
    }
    let mut child = command
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
    Running(child)
}

/// One admin command through `state`'s admin socket and its printed
/// response.
fn admin(state: &Path, command: &str, secret: Option<&[u8]>) -> serde_json::Value {
    let mut invocation = Command::new(BIN);
    invocation.arg(command).arg("--state-dir").arg(state);
    if secret.is_some() {
        invocation.arg("--credential-stdin");
    }
    let output = run(&mut invocation, secret.unwrap_or_default());
    let line = output
        .stdout
        .split(|byte| *byte == b'\n')
        .next()
        .expect("response line");
    serde_json::from_slice(line)
        .unwrap_or_else(|_| panic!("{command} printed no response: {}", stderr(&output)))
}

fn status(state: &Path) -> serde_json::Value {
    let response = admin(state, "status", None);
    assert_eq!(response["code"], "gateway.admin.status", "{response}");
    response["status"].clone()
}

#[test]
fn a_joined_process_sees_every_change_committed_through_the_other() {
    let (_directory, root) = private_root();
    let store = root.join("shared-attempts");
    let first = root.join("first");
    let second = root.join("second");
    let store_argument = store.display().to_string();
    let shared = ["--attempt-store", store_argument.as_str()];

    let installed = install(
        &root,
        &first,
        &[&["--account-label", "synthetic-account"], &shared[..]].concat(),
        b"synthetic-token\n",
    );
    assert!(installed.status.success(), "{}", stderr(&installed));
    let refused = install(
        &root,
        &second,
        &[&["--join"], &shared[..]].concat(),
        b"another-token\n",
    );
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("gateway.install.join-commitment-mismatch"),
        "{}",
        stderr(&refused)
    );
    let joined = install(
        &root,
        &second,
        &[&["--join"], &shared[..]].concat(),
        b"synthetic-token\n",
    );
    assert!(joined.status.success(), "{}", stderr(&joined));

    let _first_gateway = serve(&first, &root.join("first.sock"));
    let _second_gateway = serve(&second, &root.join("second.sock"));
    for state in [&first, &second] {
        let current = status(state);
        assert_eq!(current["state"], "active");
        assert_eq!(current["credential_held"], true);
    }

    let disabled = admin(&first, "disable", None);
    assert_eq!(disabled["code"], "gateway.admin.disabled", "{disabled}");
    assert_eq!(status(&second)["state"], "disabled");
    let enabled = admin(&second, "enable", None);
    assert_eq!(enabled["code"], "gateway.admin.enabled", "{enabled}");
    assert_eq!(status(&first)["state"], "active");
    assert_eq!(status(&first)["generation"], 3);
    assert_eq!(status(&first)["credential_generation"], 1);

    let rotated = admin(&first, "rotate", Some(b"synthetic-rotated\n"));
    assert_eq!(rotated["code"], "gateway.admin.rotated", "{rotated}");
    assert_eq!(status(&second)["credential_held"], false);
    let conflict = admin(&second, "rotate", Some(b"synthetic-other\n"));
    assert_eq!(
        conflict["code"], "gateway.admin.generation-conflict",
        "{conflict}"
    );
    let taken = admin(&second, "rotate", Some(b"synthetic-rotated\n"));
    assert_eq!(taken["code"], "gateway.admin.rotated", "{taken}");

    assert_eq!(admin(&first, "disable", None)["ok"], true);
    assert_eq!(admin(&second, "enable", None)["ok"], true);
    for state in [&first, &second] {
        let current = status(state);
        assert_eq!(current["state"], "active");
        assert_eq!(current["generation"], 6);
        assert_eq!(current["credential_generation"], 4);
        assert_eq!(current["credential_held"], true, "{current}");
    }

    let revoked = admin(&first, "revoke", None);
    assert_eq!(revoked["code"], "gateway.admin.revoked", "{revoked}");
    let current = status(&second);
    assert_eq!(current["state"], "revoked");
    assert_eq!(
        current["credential_held"], true,
        "the other process keeps its secret, which the revoked record withholds, until its own revoke"
    );
    let finished = admin(&second, "revoke", None);
    assert_eq!(finished["code"], "gateway.admin.revoked", "{finished}");
    assert_eq!(status(&second)["credential_held"], false);
}

/// A development installation has no operator, so its observer key, made
/// after install, need not be anchored in the trust it installed: `serve`
/// starts, as the north-star journey runs it.
#[test]
fn a_development_gateway_serves_with_an_observer_made_after_install() {
    let (_directory, root) = private_root();
    let state = root.join("state");
    let installed = install(
        &root,
        &state,
        &["--account-label", "synthetic-account"],
        b"synthetic-token\n",
    );
    assert!(installed.status.success(), "{}", stderr(&installed));
    let observer = run(
        Command::new(BIN)
            .arg("observer-init")
            .arg("--state-dir")
            .arg(&state),
        b"",
    );
    assert!(observer.status.success(), "{}", stderr(&observer));
    let _gateway = serve(&state, &root.join("app.sock"));
    assert_eq!(status(&state)["state"], "active");
}

#[test]
fn a_production_install_needs_a_verifying_operator_attestation() {
    let (_directory, root) = private_root();
    let required = install(
        &root,
        &root.join("state"),
        &[
            "--account-label",
            "synthetic-account",
            "--deployment",
            "production",
        ],
        b"synthetic-token\n",
    );
    assert!(!required.status.success());
    assert!(
        stderr(&required).contains("gateway.install.operator-attestation-required"),
        "{}",
        stderr(&required)
    );
    let attestation = root.join("operator-attestation.json");
    fs::write(
        &attestation,
        br#"{"statement":{"schema":"auths.gateway-operator-attestation/1"},"signature_b64":"AA","evidence":[]}"#,
    )
    .expect("attestation");
    fs::set_permissions(&attestation, fs::Permissions::from_mode(0o600)).expect("mode");
    let invalid = install(
        &root,
        &root.join("state"),
        &[
            "--account-label",
            "synthetic-account",
            "--deployment",
            "production",
            "--operator-attestation",
            &attestation.display().to_string(),
        ],
        b"synthetic-token\n",
    );
    assert!(!invalid.status.success());
    assert!(
        stderr(&invalid).contains("gateway.install.operator-attestation-invalid"),
        "{}",
        stderr(&invalid)
    );
    assert!(
        !root.join("state").join("installation.json").exists(),
        "nothing was installed"
    );
}

/// A fresh schema on the TLS fixture, and the secret slots that point a
/// production gateway at it.
fn postgres_slots() -> Vec<(&'static str, String)> {
    use rustls_pki_types::{CertificateDer, pem::PemObject as _};
    let url = std::env::var("AUTHS_POSTGRES_URL").expect("AUTHS_POSTGRES_URL");
    let ca = std::env::var("AUTHS_POSTGRES_CA_PEM").expect("AUTHS_POSTGRES_CA_PEM");
    let server = std::env::var("AUTHS_POSTGRES_SERVER_NAME").expect("server name");
    let mut suffix = [0_u8; 8];
    getrandom::fill(&mut suffix).expect("randomness");
    let schema = format!("gateway_plane_{}", hex::encode(suffix));
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_file_iter(&ca).expect("CA bundle") {
        roots.add(certificate.expect("certificate")).expect("root");
    }
    let tls = tokio_postgres_rustls::MakeRustlsConnect::new(
        rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth(),
    );
    let statement = format!("CREATE SCHEMA {schema}");
    let admin_url = url.clone();
    thread::spawn(move || {
        use std::str::FromStr as _;
        postgres::Config::from_str(&admin_url)
            .expect("connection")
            .connect(tls)
            .expect("admin connection")
            .batch_execute(&statement)
            .expect("create schema");
    })
    .join()
    .expect("schema");
    vec![
        (
            "AUTHS_POSTGRES_URL",
            format!("{url} options='-c search_path={schema}'"),
        ),
        ("AUTHS_POSTGRES_CA_PEM", ca),
        ("AUTHS_POSTGRES_SERVER_NAME", server),
    ]
}

/// Asks `operator-request` for the statement and preimage, signs the
/// preimage with a fixed raw-key operator, and writes the attestation file.
fn operator_attestation(root: &Path) -> PathBuf {
    use ed25519_dalek::Signer as _;
    let request = run(
        Command::new(BIN)
            .arg("operator-request")
            .arg("--recipe")
            .arg(root.join("recipe.json"))
            .arg("--profile-lock")
            .arg(root.join("profile.lock.json"))
            .arg("--trusted-context")
            .arg(root.join("trusted.context.cbor"))
            .arg("--provider")
            .arg("airtable")
            .arg("--alias")
            .arg("demo")
            .arg("--deployment")
            .arg("production")
            .arg("--operator-principal")
            .arg(OPERATOR.with(|operator| operator.1.clone()))
            .arg("--principal-method")
            .arg("raw-key-v1")
            .arg("--verification-method")
            .arg(OPERATOR.with(|operator| operator.1.clone()))
            .arg("--signature-suite")
            .arg("ed25519-v1"),
        b"",
    );
    assert!(request.status.success(), "{}", stderr(&request));
    let printed: serde_json::Value = serde_json::from_slice(&request.stdout).expect("request JSON");
    let preimage = base64ct::Base64UrlUnpadded::decode_vec(
        printed["preimage_b64"].as_str().expect("preimage"),
    )
    .expect("preimage bytes");
    let (signature, evidence) = OPERATOR.with(|operator| {
        (
            operator.0.sign(&preimage).to_bytes().to_vec(),
            operator.2.clone(),
        )
    });
    let attestation = serde_json::json!({
        "statement": printed["statement"],
        "signature_b64": base64ct::Base64UrlUnpadded::encode_string(&signature),
        "evidence": [{
            "evidence_type": "raw-key-v1",
            "media_type": auths_raw_key::RAW_KEY_MEDIA_TYPE,
            "bytes_b64": base64ct::Base64UrlUnpadded::encode_string(&evidence),
        }],
    });
    let path = root.join("operator-attestation.json");
    fs::write(
        &path,
        serde_json::to_vec(&attestation).expect("attestation"),
    )
    .expect("write");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
    path
}

thread_local! {
    /// A fixed raw-key operator: its key, principal, and descriptor bytes.
    static OPERATOR: (ed25519_dalek::SigningKey, String, Vec<u8>) = {
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x44; 32]);
        let raw = auths_raw_key::RawKeyDescriptor::new(
            auths_raw_key::RawKeyType::Ed25519,
            key.verifying_key().to_bytes().to_vec(),
        )
        .expect("raw key");
        let principal = raw.principal().expect("principal").as_str().to_owned();
        (key, principal, raw.encode())
    };
}

#[test]
#[ignore = "needs the TLS PostgreSQL fixture"]
fn postgres_production_processes_share_the_connection() {
    POSTGRES.with(|slot| *slot.borrow_mut() = postgres_slots());
    let (_directory, root) = private_root();
    let first = root.join("first");
    let second = root.join("second");
    let attestation = operator_attestation(&root);
    let attestation_argument = attestation.display().to_string();
    let production = [
        "--deployment",
        "production",
        "--operator-attestation",
        attestation_argument.as_str(),
    ];
    let installed = install(
        &root,
        &first,
        &[&["--account-label", "synthetic-account"], &production[..]].concat(),
        b"synthetic-token\n",
    );
    assert!(installed.status.success(), "{}", stderr(&installed));
    let joined = install(
        &root,
        &second,
        &[&["--join"], &production[..]].concat(),
        b"synthetic-token\n",
    );
    assert!(joined.status.success(), "{}", stderr(&joined));

    let _first_gateway = serve(&first, &root.join("first.sock"));
    let _second_gateway = serve(&second, &root.join("second.sock"));
    assert_eq!(status(&second)["credential_held"], true);
    let disabled = admin(&first, "disable", None);
    assert_eq!(disabled["code"], "gateway.admin.disabled", "{disabled}");
    assert_eq!(status(&second)["state"], "disabled");
    assert_eq!(admin(&second, "enable", None)["ok"], true);
    assert_eq!(status(&first)["state"], "active");
    let revoked = admin(&first, "revoke", None);
    assert_eq!(revoked["code"], "gateway.admin.revoked", "{revoked}");
    assert_eq!(status(&second)["state"], "revoked");
}
