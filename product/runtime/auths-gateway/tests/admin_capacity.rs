//! The application cannot take the operator's admin socket. With idle
//! application connections held at and past the gateway's capacity, every
//! admin command still answers through the admin socket within its
//! deadline; connections past the capacity are closed at accept; idle
//! connections are closed at the frame deadline; and `serve` refuses to
//! start under a descriptor limit that cannot hold both capacities.

#![cfg(unix)]

use auths_gateway::CompiledRecipe;
use auths_gateway::listener::APP_CAPACITY;
use std::{
    fs::{self, File},
    io::{BufRead as _, BufReader, ErrorKind, Read as _, Write as _},
    os::unix::{fs::PermissionsExt as _, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, ChildStdout, Command, Output, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_auths-gateway");
const RECIPE: &[u8] = include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json");
const LOCK: &[u8] =
    include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json");
const TRUST: &[u8] =
    include_bytes!("../../../../core/fixtures/v1/denied/untrusted-root.context.cbor");

/// Both tests hold many descriptors in this process; run them one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

struct Gateway {
    child: Child,
    _stdout: BufReader<ChildStdout>,
    root: PathBuf,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Gateway {
    /// Installs a synthetic development gateway under a fresh private root
    /// and starts `serve`.
    fn start(root: &Path) -> Self {
        let state = root.join("state");
        install(root, &state);
        let mut child = serve_command(root, None, &[])
            .stdout(Stdio::piped())
            .stderr(File::create(root.join("gateway.stderr")).expect("stderr file"))
            .spawn()
            .expect("start gateway");
        let mut stdout = BufReader::new(child.stdout.take().expect("gateway stdout"));
        let mut ready = String::new();
        stdout.read_line(&mut ready).expect("readiness line");
        let gateway = Self {
            child,
            _stdout: stdout,
            root: root.to_owned(),
        };
        assert!(
            ready.starts_with("app socket ready"),
            "gateway did not start: {}",
            gateway.stderr()
        );
        gateway
    }

    fn state(&self) -> PathBuf {
        self.root.join("state")
    }

    fn app_socket(&self) -> PathBuf {
        self.root.join("app.sock")
    }

    fn stderr(&self) -> String {
        fs::read_to_string(self.root.join("gateway.stderr")).unwrap_or_default()
    }

    /// Runs one admin command through the admin socket, as an operator would.
    fn admin(&self, command: &str, arguments: &[&str]) -> Output {
        run_with_deadline(
            Command::new(BIN)
                .arg(command)
                .arg("--state-dir")
                .arg(self.state())
                .args(arguments),
            Duration::from_secs(20),
        )
    }

    /// Rotates to `secret` through the admin socket, the secret on stdin.
    fn rotate(&self, secret: &[u8]) -> Output {
        let mut child = Command::new(BIN)
            .arg("rotate")
            .arg("--state-dir")
            .arg(self.state())
            .arg("--credential-stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn rotate");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(secret)
            .expect("secret");
        child.wait_with_output().expect("rotate output")
    }
}

/// The `serve` command for the installation under `root`, optionally under a
/// lowered descriptor limit.
fn serve_command(root: &Path, descriptor_limit: Option<u32>, arguments: &[&str]) -> Command {
    let mut command = match descriptor_limit {
        Some(limit) => {
            let mut command = Command::new("/bin/sh");
            command
                .arg("-c")
                .arg(format!("ulimit -n {limit} && exec \"$0\" \"$@\""))
                .arg(BIN);
            command
        }
        None => Command::new(BIN),
    };
    command
        .arg("serve")
        .arg("--state-dir")
        .arg(root.join("state"))
        .arg("--app-socket")
        .arg(root.join("app.sock"))
        .args(arguments);
    command
}

/// The admin response an operator command printed.
fn printed(output: &Output) -> serde_json::Value {
    serde_json::from_slice(
        output
            .stdout
            .split(|byte| *byte == b'\n')
            .next()
            .expect("response line"),
    )
    .expect("admin response JSON")
}

fn private_root() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("temporary root");
    let root = fs::canonicalize(directory.path()).expect("canonical root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
    (directory, root)
}

fn install(root: &Path, state: &Path) {
    let recipe = root.join("recipe.json");
    let lock = root.join("profile.lock.json");
    let trust = root.join("trusted.context.cbor");
    fs::write(&recipe, RECIPE).expect("recipe");
    fs::write(&lock, LOCK).expect("lock");
    fs::write(&trust, TRUST).expect("trust");
    let digest = CompiledRecipe::compile(RECIPE, LOCK)
        .expect("compiled recipe")
        .digest_hex();
    let mut child = Command::new(BIN)
        .arg("install")
        .arg("--state-dir")
        .arg(state)
        .arg("--recipe")
        .arg(&recipe)
        .arg("--profile-lock")
        .arg(&lock)
        .arg("--trusted-context")
        .arg(&trust)
        .arg("--approve-digest")
        .arg(digest)
        .arg("--provider")
        .arg("airtable")
        .arg("--alias")
        .arg("demo")
        .arg("--account-label")
        .arg("synthetic-account")
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
    let installed = child.wait_with_output().expect("install output");
    assert!(
        installed.status.success(),
        "synthetic install refused: {}",
        String::from_utf8_lossy(&installed.stderr)
    );
}

fn run_with_deadline(command: &mut Command, limit: Duration) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn command");
    let deadline = Instant::now() + limit;
    while child.try_wait().expect("poll command").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("command did not finish within {limit:?}");
        }
        thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().expect("command output")
}

/// Connects with a read timeout. Some platforms refuse to set one once the
/// peer has closed the connection; a read then returns at once, so the
/// refusal is ignored.
fn connect(path: &Path) -> UnixStream {
    let stream = UnixStream::connect(path).expect("connect");
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    stream
}

/// True when the gateway closes the connection without writing anything.
fn closed_without_response(stream: &mut UnixStream) -> bool {
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => true,
        Ok(_) => false,
        Err(error) => !matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
    }
}

fn read_response(stream: &mut UnixStream) -> serde_json::Value {
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length).expect("response length");
    let mut bytes = vec![0_u8; usize::try_from(u32::from_be_bytes(length)).expect("length")];
    stream.read_exact(&mut bytes).expect("response frame");
    serde_json::from_slice(&bytes).expect("response JSON")
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .expect("socket metadata")
        .permissions()
        .mode()
        & 0o777
}

#[test]
fn every_admin_command_answers_while_idle_application_connections_hold_the_capacity() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_directory, root) = private_root();
    let gateway = Gateway::start(&root);
    assert_eq!(mode(&gateway.state().join("admin.sock")), 0o600);
    assert_eq!(mode(&gateway.app_socket()), 0o660);

    let held_since = Instant::now();
    let mut held: Vec<UnixStream> = (0..APP_CAPACITY)
        .map(|_| connect(&gateway.app_socket()))
        .collect();
    for _ in 0..16 {
        let mut past_capacity = connect(&gateway.app_socket());
        assert!(
            closed_without_response(&mut past_capacity),
            "a connection past the capacity must be closed at accept"
        );
    }

    let answered = |output: &Output, code: &str| {
        let response = printed(output);
        assert_eq!(response["schema"], "auths.gateway-admin-response/1");
        assert_eq!(response["code"], code, "{response}");
        response
    };
    let status = gateway.admin("status", &[]);
    assert!(status.status.success());
    let status = answered(&status, "gateway.admin.status");
    assert_eq!(status["status"]["state"], "active");
    assert_eq!(status["status"]["credential_held"], true);
    assert_eq!(status["status"]["in_flight"], 0);
    let disabled = answered(&gateway.admin("disable", &[]), "gateway.admin.disabled");
    assert_eq!(disabled["drained"], true);
    assert_eq!(disabled["in_flight"], 0);
    answered(&gateway.admin("enable", &[]), "gateway.admin.enabled");
    answered(
        &gateway.rotate(b"synthetic-rotated\n"),
        "gateway.admin.rotated",
    );
    let unknown = gateway.admin("reobserve", &["--operation-id", "op-never-claimed"]);
    assert!(!unknown.status.success());
    answered(&unknown, "gateway.reobserve.not-observable");
    let revoked = gateway.admin("revoke", &[]);
    assert!(
        revoked.status.success(),
        "revoke failed while the application held its capacity: {}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    answered(&revoked, "gateway.admin.revoked");
    let status = answered(&gateway.admin("status", &[]), "gateway.admin.status");
    assert_eq!(status["status"]["state"], "revoked");
    assert_eq!(status["status"]["credential_held"], false);
    let mut still_full = connect(&gateway.app_socket());
    assert!(
        closed_without_response(&mut still_full),
        "the application capacity was still held when every admin command answered"
    );
    assert!(held_since.elapsed() < Duration::from_secs(5));

    for stream in &mut held {
        let response = read_response(stream);
        assert_eq!(response["code"], "gateway.submit.invalid-frame");
        assert!(closed_without_response(stream));
    }
    assert!(
        held_since.elapsed() >= Duration::from_secs(4),
        "idle connections were closed by the frame deadline, not earlier"
    );

    let mut after = connect(&gateway.app_socket());
    after.write_all(&2_u32.to_be_bytes()).expect("length");
    after.write_all(b"{}").expect("frame");
    let response = read_response(&mut after);
    assert_eq!(response["code"], "gateway.submit.invalid-frame");
}

#[test]
fn serve_refuses_a_descriptor_limit_below_both_capacities() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_directory, root) = private_root();
    install(&root, &root.join("state"));
    // One application permit, four admin permits, no store pool, and 32
    // descriptors of slack need 37.
    let refused = run_with_deadline(
        &mut serve_command(&root, Some(36), &["--app-capacity", "1"]),
        Duration::from_secs(20),
    );
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("gateway.serve.descriptor-limit"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    let refused = run_with_deadline(
        &mut serve_command(&root, Some(64), &[]),
        Duration::from_secs(20),
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("gateway.serve.descriptor-limit"),
        "the default capacity of 64 needs 100 descriptors"
    );

    let mut child = serve_command(&root, Some(37), &["--app-capacity", "1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("serve at the bound");
    let mut ready = String::new();
    BufReader::new(child.stdout.take().expect("stdout"))
        .read_line(&mut ready)
        .expect("readiness line");
    let _ = child.kill();
    let _ = child.wait();
    assert!(ready.starts_with("app socket ready"), "{ready}");
}
