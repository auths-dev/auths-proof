//! The application cannot take the operator's admin socket. With idle
//! application connections held at and past the gateway's capacity,
//! `auths-gateway revoke` still answers through the admin socket;
//! connections past the capacity are closed at accept; idle connections are
//! closed at the frame deadline; and a failed accept does not stop the
//! gateway.

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
    /// and starts `serve`, optionally under a lowered descriptor limit.
    fn start(root: &Path, descriptor_limit: Option<u32>) -> Self {
        let state = root.join("state");
        install(root, &state);
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
        let mut child = command
            .arg("serve")
            .arg("--state-dir")
            .arg(&state)
            .arg("--app-socket")
            .arg(root.join("app.sock"))
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

    fn running(&mut self) -> bool {
        self.child.try_wait().expect("poll gateway").is_none()
    }

    /// Runs one admin command through the admin socket, as an operator would.
    fn admin(&self, command: &str) -> Output {
        run_with_deadline(
            Command::new(BIN)
                .arg(command)
                .arg("--state-dir")
                .arg(self.state()),
            Duration::from_secs(20),
        )
    }
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
fn revoke_answers_while_idle_application_connections_hold_the_capacity() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_directory, root) = private_root();
    let gateway = Gateway::start(&root, None);
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

    let revoked = gateway.admin("revoke");
    assert!(
        revoked.status.success(),
        "revoke failed while the application held its capacity: {}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    assert!(String::from_utf8_lossy(&revoked.stdout).contains("gateway.admin.revoked"));
    let mut still_full = connect(&gateway.app_socket());
    assert!(
        closed_without_response(&mut still_full),
        "the application capacity was still held when revoke answered"
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
fn a_failed_accept_does_not_stop_the_gateway() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (_directory, root) = private_root();
    // The descriptor limit sits below the application capacity, so accept
    // fails for lack of descriptors before any permit is refused.
    let mut gateway = Gateway::start(&root, Some(32));

    let opened: Vec<UnixStream> = (0..48).map(|_| connect(&gateway.app_socket())).collect();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !gateway.stderr().contains("gateway.serve.accept-failed") {
        assert!(
            Instant::now() < deadline,
            "no accept failed for lack of descriptors: {}",
            gateway.stderr()
        );
        thread::sleep(Duration::from_millis(20));
    }
    thread::sleep(Duration::from_millis(300));
    assert!(gateway.running(), "an accept error stopped the gateway");

    drop(opened);
    // Let the gateway close the sessions those connections opened.
    thread::sleep(Duration::from_millis(500));
    let disabled = gateway.admin("disable");
    assert!(
        disabled.status.success(),
        "disable failed after accept errors: {}",
        String::from_utf8_lossy(&disabled.stderr)
    );
    assert!(String::from_utf8_lossy(&disabled.stdout).contains("gateway.admin.disabled"));
    assert!(gateway.running());
}
