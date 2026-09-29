//! The gateway's Unix socket paths: the admin socket can move out of a long
//! state directory into another private directory, both paths are checked
//! against the platform's `sun_path` limit before anything binds, a failed
//! start removes every socket it bound, and bind, connect, and state
//! directory failures keep their codes while naming the path and the cause.

#![cfg(unix)]

use auths_gateway::CompiledRecipe;
use auths_gateway::listener::max_socket_path_bytes;
use std::{
    ffi::OsStr,
    fs,
    io::{BufRead as _, BufReader, Write as _},
    os::unix::{
        ffi::OsStrExt as _,
        fs::PermissionsExt as _,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_auths-gateway");
const RECIPE: &[u8] = include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json");
const LOCK: &[u8] =
    include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json");
const TRUST: &[u8] =
    include_bytes!("../../../../core/fixtures/v1/denied/untrusted-root.context.cbor");
const DEADLINE: Duration = Duration::from_secs(20);

/// A private root short enough to pad a socket path to the platform limit:
/// canonical, under `/tmp`, mode 0700.
fn private_root() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::Builder::new()
        .prefix("gw")
        .tempdir_in("/tmp")
        .expect("temporary root");
    let root = fs::canonicalize(directory.path()).expect("canonical root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root");
    (directory, root)
}

fn bytes(path: &Path) -> usize {
    path.as_os_str().as_bytes().len()
}

/// `root/<padding>` such that `<padding>/admin.sock` is exactly `admin_len`
/// bytes.
fn padded_state(root: &Path, admin_len: usize) -> PathBuf {
    let padding = admin_len - bytes(root) - 1 - "/admin.sock".len();
    let state = root.join("p".repeat(padding));
    assert_eq!(bytes(&state.join("admin.sock")), admin_len);
    state
}

/// `root/<padding>` of exactly `len` bytes.
fn padded_path(root: &Path, len: usize) -> PathBuf {
    let path = root.join("a".repeat(len - bytes(root) - 1));
    assert_eq!(bytes(&path), len);
    path
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

/// A gateway that printed its readiness line; killed on drop.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

enum Served {
    Started(Running),
    Exited { status: ExitStatus, stderr: String },
}

impl Served {
    fn started(self) -> Running {
        match self {
            Self::Started(running) => running,
            Self::Exited { status, stderr } => {
                panic!("serve exited with {status}: {stderr}")
            }
        }
    }

    /// Asserts that `serve` exited with status 1 and returns its standard
    /// error.
    fn refused(self) -> String {
        match self {
            Self::Started(_) => panic!("serve started"),
            Self::Exited { status, stderr } => {
                assert_eq!(status.code(), Some(1), "{stderr}");
                assert_eq!(stderr.lines().count(), 1, "one line: {stderr}");
                stderr
            }
        }
    }
}

/// Runs `serve --state-dir <state> --app-socket <app>` with `extra`.
fn serve(state: &Path, app: &Path, extra: &[&OsStr]) -> Served {
    let mut child = Command::new(BIN)
        .arg("serve")
        .arg("--state-dir")
        .arg(state)
        .arg("--app-socket")
        .arg(app)
        .args(extra)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve");
    let stdout = child.stdout.take().expect("serve stdout");
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(stdout).read_line(&mut line);
        let _ = sender.send(line);
    });
    let Ok(line) = receiver.recv_timeout(DEADLINE) else {
        let _ = child.kill();
        let _ = child.wait();
        panic!("serve neither started nor exited within {DEADLINE:?}");
    };
    if line.starts_with("app socket ready") {
        return Served::Started(Running(child));
    }
    let output = run_until_exit(child);
    Served::Exited {
        status: output.status,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn run_until_exit(mut child: Child) -> Output {
    let deadline = Instant::now() + DEADLINE;
    while child.try_wait().expect("poll serve").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("serve closed its output but did not exit");
        }
        thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().expect("serve output")
}

fn revoke(state: &Path, extra: &[&OsStr]) -> Output {
    run_with_deadline(
        Command::new(BIN)
            .arg("revoke")
            .arg("--state-dir")
            .arg(state)
            .args(extra),
        DEADLINE,
    )
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

fn directory(path: &Path, mode: u32) {
    fs::create_dir(path).expect("directory");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("mode");
}

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

fn assert_figures(stderr: &str, path: &Path, length: usize, max: usize) {
    assert!(
        stderr.contains(&format!("path={}:", path.display())),
        "{stderr}"
    );
    assert!(stderr.contains(&format!("{length} bytes")), "{stderr}");
    assert!(stderr.contains(&format!("at most {max}")), "{stderr}");
    assert!(
        stderr.contains(&format!("sun_path is {} bytes", max + 1)),
        "{stderr}"
    );
}

#[test]
fn an_admin_socket_exactly_at_the_limit_serves() {
    let max = max_socket_path_bytes();
    let (_directory, root) = private_root();
    let state = padded_state(&root, max);
    install(&root, &state);
    let _gateway = serve(&state, &root.join("app.sock"), &[]).started();
    assert_eq!(mode(&state.join("admin.sock")), 0o600);
    let revoked = revoke(&state, &[]);
    assert!(
        revoked.status.success(),
        "{}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    assert!(String::from_utf8_lossy(&revoked.stdout).contains("gateway.admin.revoked"));
}

#[test]
fn an_admin_socket_one_byte_over_the_limit_binds_nothing() {
    let max = max_socket_path_bytes();
    let (_directory, root) = private_root();
    let state = padded_state(&root, max + 1);
    install(&root, &state);
    let app = root.join("app.sock");
    let stderr = serve(&state, &app, &[]).refused();
    assert!(
        stderr.starts_with("gateway.serve.admin-socket-too-long "),
        "{stderr}"
    );
    assert_figures(&stderr, &state.join("admin.sock"), max + 1, max);
    assert!(stderr.contains("--admin-socket"), "{stderr}");
    assert!(!exists(&app));
}

#[test]
fn an_admin_socket_moves_out_of_a_long_state_directory() {
    let max = max_socket_path_bytes();
    let (_directory, root) = private_root();
    let state = padded_state(&root, max + 1);
    install(&root, &state);
    directory(&root.join("a"), 0o700);
    let admin = root.join("a").join("admin.sock");
    let relocated = [OsStr::new("--admin-socket"), admin.as_os_str()];
    let _gateway = serve(&state, &root.join("app.sock"), &relocated).started();
    assert_eq!(mode(&admin), 0o600);
    let revoked = revoke(&state, &relocated);
    assert!(
        revoked.status.success(),
        "{}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    assert!(String::from_utf8_lossy(&revoked.stdout).contains("gateway.admin.revoked"));

    let forgotten = revoke(&state, &[]);
    assert_eq!(forgotten.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&forgotten.stderr);
    assert!(
        stderr.starts_with("gateway.admin.socket-unavailable "),
        "{stderr}"
    );
    assert_figures(&stderr, &state.join("admin.sock"), max + 1, max);
}

#[test]
fn an_app_socket_one_byte_over_the_limit_binds_nothing() {
    let max = max_socket_path_bytes();
    let (_directory, root) = private_root();
    let state = root.join("state");
    install(&root, &state);
    let app = padded_path(&root, max + 1);
    let stderr = serve(&state, &app, &[]).refused();
    assert!(
        stderr.starts_with("gateway.serve.app-socket-too-long "),
        "{stderr}"
    );
    assert_figures(&stderr, &app, max + 1, max);
    assert!(!exists(&app));
    assert!(!exists(&state.join("admin.sock")));
}

#[test]
fn an_admin_socket_in_a_shared_directory_is_refused() {
    let (_directory, root) = private_root();
    let state = root.join("state");
    install(&root, &state);
    let shared = root.join("shared");
    directory(&shared, 0o755);
    let admin = shared.join("admin.sock");
    let app = root.join("app.sock");
    let stderr = serve(
        &state,
        &app,
        &[OsStr::new("--admin-socket"), admin.as_os_str()],
    )
    .refused();
    assert!(
        stderr.starts_with(&format!(
            "gateway.serve.unsafe-admin-socket-directory path={}:",
            shared.display()
        )),
        "{stderr}"
    );
    assert!(stderr.contains("0755"), "{stderr}");
    assert!(!exists(&admin));
    assert!(!exists(&app));
}

#[test]
fn an_admin_socket_directory_through_a_symbolic_link_is_refused() {
    let (_directory, root) = private_root();
    let state = root.join("state");
    install(&root, &state);
    let real = root.join("real");
    directory(&real, 0o700);
    let link = root.join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symbolic link");
    let stderr = serve(
        &state,
        &root.join("app.sock"),
        &[
            OsStr::new("--admin-socket"),
            link.join("admin.sock").as_os_str(),
        ],
    )
    .refused();
    assert!(
        stderr.starts_with("gateway.serve.unsafe-admin-socket-directory "),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!("resolves to {}", real.display())),
        "{stderr}"
    );
    assert!(!exists(&real.join("admin.sock")));
}

#[test]
fn a_relative_or_app_socket_admin_path_is_invalid() {
    let (_directory, root) = private_root();
    let state = root.join("state");
    install(&root, &state);
    let app = root.join("app.sock");
    let relative = serve(
        &state,
        &app,
        &[OsStr::new("--admin-socket"), OsStr::new("admin.sock")],
    )
    .refused();
    assert!(
        relative.starts_with("gateway.serve.invalid-admin-socket "),
        "{relative}"
    );
    let same = serve(
        &state,
        &app,
        &[OsStr::new("--admin-socket"), app.as_os_str()],
    )
    .refused();
    assert!(
        same.starts_with("gateway.serve.invalid-admin-socket "),
        "{same}"
    );
    assert!(!exists(&app));
}

#[test]
fn a_bind_failure_carries_the_operating_system_error() {
    if is_root() {
        return;
    }
    let (_directory, root) = private_root();
    let state = root.join("state");
    install(&root, &state);
    let read_only = root.join("ro");
    directory(&read_only, 0o500);
    let admin = read_only.join("admin.sock");
    let stderr = serve(
        &state,
        &root.join("app.sock"),
        &[OsStr::new("--admin-socket"), admin.as_os_str()],
    )
    .refused();
    fs::set_permissions(&read_only, fs::Permissions::from_mode(0o700)).expect("restore");
    assert!(
        stderr.starts_with(&format!(
            "gateway.serve.admin-bind-failed path={}:",
            admin.display()
        )),
        "{stderr}"
    );
    assert!(stderr.contains("(os error 13)"), "{stderr}");
    assert!(!exists(&root.join("app.sock")));
}

#[test]
fn a_failed_second_bind_removes_the_admin_socket_bound_first() {
    if is_root() {
        return;
    }
    let (_directory, root) = private_root();
    let state = root.join("state");
    install(&root, &state);
    let read_only = root.join("ro");
    directory(&read_only, 0o500);
    let app = read_only.join("app.sock");
    let stderr = serve(&state, &app, &[]).refused();
    fs::set_permissions(&read_only, fs::Permissions::from_mode(0o700)).expect("restore");
    assert!(
        stderr.starts_with(&format!(
            "gateway.serve.app-bind-failed path={}:",
            app.display()
        )),
        "{stderr}"
    );
    assert!(stderr.contains("(os error 13)"), "{stderr}");
    assert!(!exists(&state.join("admin.sock")));
}

#[test]
fn a_live_listener_at_the_admin_path_is_named_and_left_alone() {
    let (_directory, root) = private_root();
    let state = root.join("state");
    install(&root, &state);
    let admin = state.join("admin.sock");
    let listener = UnixListener::bind(&admin).expect("test listener");
    let app = root.join("app.sock");
    let stderr = serve(&state, &app, &[]).refused();
    assert!(
        stderr.starts_with(&format!(
            "gateway.serve.admin-bind-failed path={}:",
            admin.display()
        )),
        "{stderr}"
    );
    assert!(stderr.contains("a live listener answers"), "{stderr}");
    assert!(!exists(&app));
    let _client = UnixStream::connect(&admin).expect("the test listener still answers");
    listener.accept().expect("accept");
}

#[test]
fn an_unsafe_state_directory_names_the_mode() {
    let (_directory, root) = private_root();
    let state = root.join("state");
    install(&root, &state);
    fs::set_permissions(&state, fs::Permissions::from_mode(0o755)).expect("shared state");
    let stderr = serve(&state, &root.join("app.sock"), &[]).refused();
    assert!(
        stderr.starts_with(&format!(
            "gateway.state.unsafe-directory path={}:",
            state.display()
        )),
        "{stderr}"
    );
    assert!(stderr.contains("0755"), "{stderr}");
}

#[test]
fn a_state_directory_through_a_symbolic_link_names_the_canonical_path() {
    let (_directory, root) = private_root();
    let state = root.join("state");
    install(&root, &state);
    let link = root.join("state-link");
    std::os::unix::fs::symlink(&state, &link).expect("symbolic link");
    let stderr = serve(&link, &root.join("app.sock"), &[]).refused();
    assert!(
        stderr.starts_with("gateway.state.unsafe-directory "),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!("resolves to {}", state.display())),
        "{stderr}"
    );
}

#[test]
fn a_client_reports_the_length_and_the_connect_error() {
    let max = max_socket_path_bytes();
    let (_directory, root) = private_root();
    let proof = root.join("proof");
    let action = root.join("action");
    fs::write(&proof, b"p").expect("proof");
    fs::write(&action, b"a").expect("action");
    let submit = |socket: &Path| {
        run_with_deadline(
            Command::new(BIN)
                .arg("submit")
                .arg("--app-socket")
                .arg(socket)
                .arg("--proof")
                .arg(&proof)
                .arg("--action")
                .arg(&action),
            DEADLINE,
        )
    };
    let long = padded_path(&root, max + 1);
    let too_long = submit(&long);
    assert_eq!(too_long.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&too_long.stderr);
    assert!(
        stderr.starts_with("gateway.submit.socket-unavailable "),
        "{stderr}"
    );
    assert_figures(&stderr, &long, max + 1, max);

    let missing = root.join("missing.sock");
    let absent = submit(&missing);
    assert_eq!(absent.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&absent.stderr);
    assert!(
        stderr.starts_with(&format!(
            "gateway.submit.socket-unavailable path={}:",
            missing.display()
        )),
        "{stderr}"
    );
    assert!(
        stderr.contains("No such file or directory (os error 2)"),
        "{stderr}"
    );
}
