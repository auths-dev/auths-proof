//! Production daemon and client processes with native proof/approval and a real
//! counting HTTP double. Public fixed keys simulate reviewer/agent/recipient;
//! this is not human-presence, UID isolation, installed-language or `PostgreSQL` evidence.
#![cfg(all(unix, feature = "testkit-harness", feature = "loopback-provider"))]

use auths_gateway::{
    CompiledRecipe,
    app::AppDisclosureTarget,
    effect::{
        CONTENT_READ_TOOL, DISCLOSURE_TOOL, EffectApprovalRequest, EffectPolicy,
        UnixDisclosurePolicy,
    },
    harness::authoring::{tool_fixture, tools_context},
};
use auths_profile_mcp::McpToolCall;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const SECRET: &[u8] = b"pat_public_content_journey_fixture";
const CONTENT: &[u8] = b"PRIVATE-CONTENT-PROCESS-SENTINEL";
const RECORD: &str = "recTEST0000000001";

fn private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("mode");
}
fn path(path: &Path) -> &str {
    path.to_str().expect("path")
}
fn command(name: &str, args: &[(&str, &str)], flags: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_auths-gateway"));
    command.arg(name);
    for (key, value) in args {
        command.arg(key).arg(value);
    }
    command
        .args(flags)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}
fn cli(name: &str, args: &[(&str, &str)], flags: &[&str], input: Option<&[u8]>) -> Output {
    let mut child = command(name, args, flags).spawn().expect("CLI");
    if let Some(bytes) = input {
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(bytes)
            .expect("input");
    } else {
        drop(child.stdin.take());
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().expect("process status").is_none() {
        if Instant::now() >= deadline {
            child.kill().expect("kill timed out CLI");
            let output = child.wait_with_output().expect("output");
            panic!(
                "{name} timeout: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().expect("output")
}
fn success(output: Output) -> Vec<u8> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
fn public(output: Output) -> Value {
    for bytes in [&output.stdout, &output.stderr] {
        for sentinel in [SECRET, CONTENT] {
            assert!(!bytes.windows(sentinel.len()).any(|chunk| chunk == sentinel));
        }
    }
    serde_json::from_slice(&success(output)).expect("public native JSON")
}

struct Provider {
    port: u16,
    calls: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}
impl Provider {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let port = listener.local_addr().expect("address").port();
        listener.set_nonblocking(true).expect("nonblocking");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let captured = calls.clone();
        let finished = stop.clone();
        let join = thread::spawn(move || {
            let mut record = json!({"fields":{"DemoStatus":"Pending"}});
            while !finished.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("accept: {error}"),
                };
                stream
                    .set_nonblocking(false)
                    .expect("blocking accepted socket");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("deadline");
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .expect("deadline");
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    assert!(request.len() < 16_384);
                    let mut byte = [0];
                    stream.read_exact(&mut byte).expect("header");
                    request.push(byte[0]);
                }
                let header = String::from_utf8(request).expect("header");
                assert!(header.to_ascii_lowercase().contains(&format!(
                    "authorization: bearer {}\r\n",
                    String::from_utf8_lossy(SECRET)
                )));
                let line = header.lines().next().expect("request").to_owned();
                let length = header
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("length"))
                    })
                    .unwrap_or(0);
                assert!(length <= 16_384);
                let mut body = vec![0; length];
                stream.read_exact(&mut body).expect("body");
                captured.lock().expect("calls").push(line.clone());
                let (media, response) = if line
                    == format!("GET /documents/{RECORD}?format=text%2Fplain HTTP/1.1")
                {
                    ("text/plain", CONTENT.to_vec())
                } else if line
                    == format!("PATCH /v0/appTEST0000000001/tblTEST0000000001/{RECORD} HTTP/1.1")
                {
                    record = serde_json::from_slice(&body).expect("write JSON");
                    assert_eq!(record["fields"]["DemoStatus"], "Approved");
                    assert_eq!(record["fields"].as_object().expect("fields").len(), 2);
                    assert!(record["fields"]["auths_echo"].is_string());
                    ("application/json", body)
                } else if line
                    == format!("GET /v0/appTEST0000000001/tblTEST0000000001/{RECORD} HTTP/1.1")
                {
                    (
                        "application/json",
                        serde_json::to_vec(&record).expect("record"),
                    )
                } else {
                    panic!("unexpected provider request: {line}");
                };
                let headers = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {media}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                    response.len()
                );
                stream.write_all(headers.as_bytes()).expect("headers");
                stream.write_all(&response).expect("response");
            }
        });
        Self {
            port,
            calls,
            stop,
            join: Some(join),
        }
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("calls").clone()
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let result = join.join();
            if !thread::panicking() {
                result.expect("provider");
            }
        }
    }
}
struct Daemon(Child);
impl Daemon {
    fn start(state: &Path, socket: &Path, port: u16) -> Self {
        Self::start_at_admin(state, socket, &state.join("admin.sock"), port)
    }
    fn start_at_admin(state: &Path, socket: &Path, admin: &Path, port: u16) -> Self {
        let child = command(
            "serve",
            &[
                ("--state-dir", path(state)),
                ("--app-socket", path(socket)),
                ("--admin-socket", path(admin)),
                ("--loopback-provider", &port.to_string()),
            ],
            &[],
        )
        .spawn()
        .expect("daemon");
        let mut daemon = Self(child);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !socket.exists() {
            assert!(
                daemon.0.try_wait().expect("daemon status").is_none(),
                "daemon exited"
            );
            assert!(Instant::now() < deadline, "daemon startup timeout");
            thread::sleep(Duration::from_millis(10));
        }
        daemon
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Approved {
    proof: PathBuf,
    action: PathBuf,
    approval: PathBuf,
    binding: PathBuf,
}
impl Approved {
    fn execute(
        &self,
        name: &str,
        socket: &Path,
        extra: &[(&str, &str)],
        flags: &[&str],
        input: Option<&[u8]>,
    ) -> Output {
        let mut args = vec![
            ("--app-socket", path(socket)),
            ("--proof", path(&self.proof)),
            ("--action", path(&self.action)),
            ("--approval", path(&self.approval)),
        ];
        args.extend_from_slice(extra);
        cli(name, &args, flags, input)
    }
}
#[allow(
    clippy::too_many_arguments,
    reason = "explicit native review inputs in a process fixture"
)]
fn approve(
    state: &Path,
    call: &McpToolCall,
    operation: &str,
    now: u64,
    key: &SigningKey,
    extra: &[(&str, &str)],
    flags: &[&str],
) -> Approved {
    let fixture = tool_fixture(call, now).expect("native signed authority");
    let proof = state.join(format!("{operation}.proof"));
    let action = state.join(format!("{operation}.action"));
    let approval = state.join(format!("{operation}.approval"));
    let binding = state.join(format!("{operation}.binding"));
    let request = state.join(format!("{operation}.request"));
    private(&proof, &fixture.proof);
    private(&action, &fixture.action);
    let start = (now - 1).to_string();
    let end = (now + 300).to_string();
    let mut args = vec![
        ("--state-dir", path(state)),
        ("--proof", path(&proof)),
        ("--action", path(&action)),
        ("--not-before", &start),
        ("--expires-at", &end),
        ("--request-out", path(&request)),
        ("--binding-out", path(&binding)),
    ];
    args.extend_from_slice(extra);
    let review: Value =
        serde_json::from_slice(&success(cli("effect-review", &args, flags, None))).expect("review");
    assert!(
        !review["literal_review"]
            .as_str()
            .expect("literal")
            .is_empty()
    );
    let signing =
        EffectApprovalRequest::from_private_bytes(&std::fs::read(&request).expect("request"))
            .expect("native signing request");
    let message = signing.signing_message().expect("message");
    assert_eq!(review["signing_message_hex"], hex::encode(message));
    private(
        &approval,
        &success(cli(
            "effect-approval",
            &[
                ("--request", path(&request)),
                (
                    "--signature-hex",
                    &hex::encode(key.sign(&message).to_bytes()),
                ),
            ],
            &[],
            None,
        )),
    );
    Approved {
        proof,
        action,
        approval,
        binding,
    }
}
fn call_file(path: &Path) -> McpToolCall {
    assert_eq!(
        std::fs::metadata(path)
            .expect("call metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    McpToolCall::from_canonical_bytes(&std::fs::read(path).expect("call")).expect("native call")
}
fn history(socket: &Path, operation: &str) -> Value {
    public(cli(
        "content-history",
        &[("--app-socket", path(socket)), ("--operation", operation)],
        &[],
        None,
    ))
}

/// Subprocess fixture: uses the shipping native recipient client, retains exact
/// ACK evidence, then waits without sending it so the parent can crash both peers.
#[test]
fn recipient_without_ack_process() {
    let Some(root) = std::env::var_os("AUTHS_CONTENT_RECIPIENT_FIXTURE") else {
        return;
    };
    let root = PathBuf::from(root);
    let state = root.join("state");
    let request = auths_gateway::app::AppDisclosure {
        schema: auths_gateway::app::APP_DISCLOSURE_SCHEMA.to_owned(),
        target: serde_json::from_slice(&std::fs::read(root.join("target.json")).expect("target"))
            .expect("target JSON"),
        submission: auths_gateway::app::AppSubmission {
            schema: auths_gateway::app::APP_REQUEST_SCHEMA.to_owned(),
            proof_b64: Base64UrlUnpadded::encode_string(
                &std::fs::read(state.join("lost-ack.proof")).expect("proof"),
            ),
            action_b64: Base64UrlUnpadded::encode_string(
                &std::fs::read(state.join("lost-ack.action")).expect("action"),
            ),
            approval_b64: Base64UrlUnpadded::encode_string(
                &std::fs::read(state.join("lost-ack.approval")).expect("approval"),
            ),
        },
    };
    let binding = auths_gateway::effect::EffectBinding::from_private_bytes(
        &std::fs::read(state.join("lost-ack.binding")).expect("binding"),
    )
    .expect("native binding");
    tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(async {
            let stream = tokio::net::UnixStream::connect(root.join("app.sock"))
                .await
                .expect("app socket");
            let key = SigningKey::from_bytes(&[31; 32]);
            let received = auths_gateway::app::receive_content_disclosure(
                stream,
                &request,
                &binding,
                CONTENT.len() as u64,
                &key,
            )
            .await
            .expect("native recipient");
            let auths_gateway::app::AppDisclosureReception::Received(received) = received else {
                panic!("expected delivery");
            };
            assert_eq!(received.content(), CONTENT);
            private(&root.join("lost-content"), received.content());
            private(
                &root.join("lost-evidence"),
                &received
                    .acknowledgement(&key)
                    .expect("ACK")
                    .to_private_bytes()
                    .expect("canonical ACK"),
            );
            for name in ["lost-content", "lost-evidence"] {
                std::fs::File::open(root.join(name))
                    .expect("file")
                    .sync_all()
                    .expect("sync");
            }
            std::fs::File::open(&root)
                .expect("directory")
                .sync_all()
                .expect("sync");
            private(
                &root.join("recipient-ready"),
                b"received-and-ack-retained-not-sent",
            );
            tokio::time::sleep(Duration::from_secs(15)).await;
            drop(received);
        });
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "ordered real process journey and evidence assertions"
)]
fn native_content_process_journey_fixture_is_current() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../bindings/fixtures/gateway");
    let corpus: Value = serde_json::from_slice(
        &std::fs::read(fixtures.join("hostile-recipes-v2.json")).expect("recipes"),
    )
    .expect("JSON");
    let mut source = corpus["bases"]["airtable"]["recipe"].clone();
    source["content"] = json!({"schema":"auths.gateway-content-read/1", "resource_field":"record_id",
        "path":[{"kind":"fixed","value":"documents"},{"kind":"field","name":"record_id"}],
        "query":[{"name":"format","value":"text/plain"}], "projection":{"kind":"utf8"},
        "maximum_response_bytes":1024,"maximum_content_bytes":64});
    let source = serde_json::to_vec(&source).expect("source");
    let lock = serde_json::to_vec(&corpus["bases"]["airtable"]["lock"]).expect("lock");
    let recipe = CompiledRecipe::compile(&source, &lock).expect("recipe");
    let service = corpus["bases"]["airtable"]["recipe"]["service"]
        .as_str()
        .expect("service");
    let mutation_tool = corpus["bases"]["airtable"]["recipe"]["tool"]
        .as_str()
        .expect("tool");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let calls = [
        CONTENT_READ_TOOL,
        DISCLOSURE_TOOL,
        mutation_tool,
        "auths_gateway_recovery_read_v1",
    ]
    .map(|tool| McpToolCall::new(service, tool, serde_json::Map::new()).expect("tool"));
    let trust = tools_context(&calls, now).expect("explicit multi-tool test trust");
    let reviewer = SigningKey::from_bytes(&[29; 32]);
    let recipient = SigningKey::from_bytes(&[31; 32]);
    let policy = EffectPolicy::new(
        "content-process-journey".to_owned(),
        1,
        reviewer.verifying_key().to_bytes(),
    )
    .expect("policy");
    let directory = tempfile::Builder::new()
        .prefix("ap74-")
        .tempdir_in("/tmp")
        .expect("directory");
    let root = std::fs::canonicalize(directory.path()).expect("canonical directory");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("mode");
    let state = root.join("state");
    let socket = root.join("app.sock");
    for (name, bytes) in [
        ("recipe", source),
        ("lock", lock),
        ("trust", trust),
        (
            "policy",
            policy.to_private_bytes().expect("policy").to_vec(),
        ),
    ] {
        private(&root.join(name), &bytes);
    }
    let provider = Provider::start();
    success(cli(
        "install",
        &[
            ("--state-dir", path(&state)),
            ("--recipe", path(&root.join("recipe"))),
            ("--profile-lock", path(&root.join("lock"))),
            ("--trusted-context", path(&root.join("trust"))),
            ("--effect-policy", path(&root.join("policy"))),
            ("--approve-digest", &recipe.digest_hex()),
            ("--provider", "airtable"),
            ("--alias", "journey"),
            ("--account-label", "public-fixture"),
        ],
        &["--credential-stdin"],
        Some(SECRET),
    ));
    let args = root.join("resource.json");
    let call = root.join("read.call");
    private(
        &args,
        &serde_json::to_vec(&json!({"record_id":RECORD})).expect("arguments"),
    );
    success(cli(
        "effect-content-call",
        &[
            ("--state-dir", path(&state)),
            ("--resource-arguments", path(&args)),
            ("--operation", "read"),
            ("--call-out", path(&call)),
        ],
        &[],
        None,
    ));
    let read = approve(
        &state,
        &call_file(&call),
        "read",
        now,
        &reviewer,
        &[],
        &["--content"],
    );
    for invalid in [
        format!(r#"{{"record_id":"{RECORD}","record_id":"other"}}"#),
        format!(r#"{{"record_id":"{RECORD}","url":"https://evil.example"}}"#),
        "[]".to_owned(),
        " ".repeat(65_537),
    ] {
        private(&args, invalid.as_bytes());
        let out = root.join("invalid.call");
        assert!(
            !cli(
                "effect-content-call",
                &[
                    ("--state-dir", path(&state)),
                    ("--resource-arguments", path(&args)),
                    ("--operation", "bad"),
                    ("--call-out", path(&out))
                ],
                &[],
                None
            )
            .status
            .success()
        );
        assert!(!out.exists());
    }
    let mut at_limit = serde_json::to_vec(&json!({"record_id":RECORD})).expect("arguments");
    at_limit.resize(65_536, b' ');
    private(&args, &at_limit);
    let boundary_call = root.join("boundary.call");
    success(cli(
        "effect-content-call",
        &[
            ("--state-dir", path(&state)),
            ("--resource-arguments", path(&args)),
            ("--operation", "read"),
            ("--call-out", path(&boundary_call)),
        ],
        &[],
        None,
    ));
    assert_eq!(
        std::fs::read(&boundary_call).expect("boundary call"),
        std::fs::read(&call).expect("original call")
    );
    assert!(
        !cli(
            "effect-content-call",
            &[
                ("--state-dir", path(&state)),
                ("--resource-arguments", path(&args)),
                ("--operation", "replacement"),
                ("--call-out", path(&call))
            ],
            &[],
            None
        )
        .status
        .success()
    );
    assert_eq!(
        std::fs::read(&boundary_call).expect("boundary call"),
        std::fs::read(&call).expect("unchanged call")
    );
    assert!(
        provider.calls().is_empty(),
        "authoring and review have no provider authority"
    );
    let mut daemon = Daemon::start(&state, &socket, provider.port);
    let acquired = public(read.execute("content-acquire", &socket, &[], &[], None));
    assert_eq!(
        acquired["history"]["snapshot"]["stage"], "response-recorded",
        "{acquired}"
    );
    assert_eq!(provider.calls().len(), 1);
    assert_eq!(
        public(read.execute("content-acquire", &socket, &[], &[], None)),
        acquired
    );
    let uid = rustix::process::geteuid().as_raw();
    let target = root.join("target.json");
    private(
        &target,
        &serde_json::to_vec(&AppDisclosureTarget {
            source_operation: "read".to_owned(),
            recipient_key: recipient.verifying_key().to_bytes(),
            channel: UnixDisclosurePolicy::new(uid, uid, [5; 32]),
            delivery_instance: [6; 32],
        })
        .expect("target"),
    );
    let release_call = root.join("release.call");
    success(cli(
        "effect-disclosure-call",
        &[
            ("--state-dir", path(&state)),
            ("--target", path(&target)),
            ("--operation", "release"),
            ("--call-out", path(&release_call)),
        ],
        &[],
        None,
    ));
    let release = approve(
        &state,
        &call_file(&release_call),
        "release",
        now,
        &reviewer,
        &[("--disclosure", path(&target))],
        &[],
    );
    let content = root.join("content");
    let ack = root.join("ack");
    let length = CONTENT.len().to_string();
    let receive = |content: &Path, ack: &Path| {
        release.execute(
            "disclosure-receive",
            &socket,
            &[
                ("--target", path(&target)),
                ("--expected-binding", path(&release.binding)),
                ("--expected-bytes", &length),
                ("--content-out", path(content)),
                ("--acknowledgement-out", path(ack)),
            ],
            &["--recipient-seed-stdin"],
            Some(&[31; 32]),
        )
    };
    assert_eq!(
        public(receive(&content, &ack))["outcome"],
        "recipient-ack-sent"
    );
    assert_eq!(std::fs::read(&content).expect("received bytes"), CONTENT);
    for path in [&content, &ack] {
        assert_eq!(
            std::fs::metadata(path)
                .expect("private file")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let disclosed = loop {
        let value = history(&socket, "release");
        if value["history"]["snapshot"]["stage"] == "acknowledged" {
            break value;
        }
        assert!(
            Instant::now() < deadline,
            "ACK was not durably recorded: {value}"
        );
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(provider.calls().len(), 1, "disclosure never refetches");
    // A real daemon restart must retain both journals and must not remint a send.
    drop(daemon);
    std::fs::remove_file(&socket).expect("old app socket");
    std::fs::remove_file(state.join("admin.sock")).expect("old admin socket");
    daemon = Daemon::start(&state, &socket, provider.port);
    assert_eq!(history(&socket, "read"), acquired);
    assert_eq!(history(&socket, "release"), disclosed);
    let replay_content = root.join("replay-content");
    let replay_ack = root.join("replay-ack");
    assert_eq!(public(receive(&replay_content, &replay_ack)), disclosed);
    assert!(!replay_content.exists() && !replay_ack.exists());
    assert_eq!(
        public(cli(
            "disclosure-acknowledge",
            &[
                ("--app-socket", path(&socket)),
                ("--operation", "release"),
                ("--acknowledgement", path(&ack))
            ],
            &[],
            None
        )),
        disclosed
    );
    // The recipient confirms actual receipt privately but never sends its ACK.
    // Crash the daemon while it waits, then crash the separate recipient process.
    let loss_call = root.join("loss.call");
    success(cli(
        "effect-disclosure-call",
        &[
            ("--state-dir", path(&state)),
            ("--target", path(&target)),
            ("--operation", "lost-ack"),
            ("--call-out", path(&loss_call)),
        ],
        &[],
        None,
    ));
    let lost = approve(
        &state,
        &call_file(&loss_call),
        "lost-ack",
        now,
        &reviewer,
        &[("--disclosure", path(&target))],
        &[],
    );
    let mut receiver = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", "recipient_without_ack_process", "--nocapture"])
        .env("AUTHS_CONTENT_RECIPIENT_FIXTURE", &root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("recipient process");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !root.join("recipient-ready").exists() {
        if receiver.try_wait().expect("recipient status").is_some() || Instant::now() >= deadline {
            let _ = receiver.kill();
            let output = receiver.wait_with_output().expect("recipient output");
            panic!(
                "recipient did not receive: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(5));
    }
    drop(daemon);
    receiver.kill().expect("crash recipient");
    receiver.wait().expect("wait recipient");
    std::fs::remove_file(&socket).expect("old app socket");
    std::fs::remove_file(state.join("admin.sock")).expect("old admin socket");
    daemon = Daemon::start(&state, &socket, provider.port);
    let unknown = history(&socket, "lost-ack");
    assert_eq!(unknown["history"]["snapshot"]["stage"], "unknown");
    assert_eq!(unknown["history"]["snapshot"]["reserved_deliveries"], 1);
    assert_eq!(
        unknown["history"]["snapshot"]["reserved_bytes"],
        CONTENT.len()
    );
    let loss_retry_content = root.join("loss-retry-content");
    let loss_retry_ack = root.join("loss-retry-ack");
    let loss_replay = public(lost.execute(
        "disclosure-receive",
        &socket,
        &[
            ("--target", path(&target)),
            ("--expected-binding", path(&lost.binding)),
            ("--expected-bytes", &length),
            ("--content-out", path(&loss_retry_content)),
            ("--acknowledgement-out", path(&loss_retry_ack)),
        ],
        &["--recipient-seed-stdin"],
        Some(&[31; 32]),
    ));
    assert_eq!(loss_replay, unknown);
    assert!(!loss_retry_content.exists() && !loss_retry_ack.exists());
    let late_ack = public(cli(
        "disclosure-acknowledge",
        &[
            ("--app-socket", path(&socket)),
            ("--operation", "lost-ack"),
            ("--acknowledgement", path(&root.join("lost-evidence"))),
        ],
        &[],
        None,
    ));
    assert_eq!(late_ack["history"]["snapshot"]["stage"], "acknowledged");
    assert_eq!(
        late_ack["history"]["snapshot"]["reserved_bytes"],
        CONTENT.len()
    );
    assert_eq!(
        public(cli(
            "disclosure-acknowledge",
            &[
                ("--app-socket", path(&socket)),
                ("--operation", "lost-ack"),
                ("--acknowledgement", path(&root.join("lost-evidence")))
            ],
            &[],
            None
        )),
        late_ack
    );
    assert_eq!(
        provider.calls().len(),
        1,
        "lost ACK cannot cause source refetch"
    );
    let write_call = McpToolCall::new(
        service,
        mutation_tool,
        json!({"operation_id":"write",
        "operator_namespace":recipe.namespace().as_str(),"recipe_digest":recipe.digest_hex(),
        "record_id":RECORD,"replacement":"Approved"})
        .as_object()
        .expect("arguments")
        .clone(),
    )
    .expect("write call");
    let write = approve(&state, &write_call, "write", now, &reviewer, &[], &[]);
    let written = public(write.execute("submit", &socket, &[], &[], None));
    assert_eq!(written["outcome"], "response-recorded", "{written}");
    assert_eq!(provider.calls().len(), 2);
    let recovery_call = McpToolCall::from_canonical_bytes(&success(cli(
        "effect-recovery-call",
        &[
            ("--state-dir", path(&state)),
            ("--source-operation", "write"),
            ("--recovery-operation", "observe"),
        ],
        &[],
        None,
    )))
    .expect("recovery call");
    let recovery = approve(
        &state,
        &recovery_call,
        "observe",
        now,
        &reviewer,
        &[("--recovery-of", "write")],
        &[],
    );
    let mut observed = public(recovery.execute(
        "app-recover",
        &socket,
        &[("--source-operation", "write")],
        &[],
        None,
    ));
    assert_eq!(observed["outcome"], "recovery-report", "{observed}");
    assert!(
        observed["report"]["source"]["observation_match"].is_null(),
        "{observed}"
    );
    assert_eq!(
        observed["report"]["source"]["provider_linked"], true,
        "{observed}"
    );
    assert_eq!(observed["report"]["disposition"], "recorded");
    assert_eq!(provider.calls().len(), 3);
    public(write.execute("submit", &socket, &[], &[], None));
    public(recovery.execute(
        "app-recover",
        &socket,
        &[("--source-operation", "write")],
        &[],
        None,
    ));
    assert_eq!(
        provider.calls().len(),
        3,
        "history never authorizes resend/refetch"
    );
    // Author one more release before independently committing disable.
    let revoked_call = root.join("revoked.call");
    success(cli(
        "effect-disclosure-call",
        &[
            ("--state-dir", path(&state)),
            ("--target", path(&target)),
            ("--operation", "revoked"),
            ("--call-out", path(&revoked_call)),
        ],
        &[],
        None,
    ));
    let revoked = approve(
        &state,
        &call_file(&revoked_call),
        "revoked",
        now,
        &reviewer,
        &[("--disclosure", path(&target))],
        &[],
    );
    success(cli(
        "disable",
        &[("--state-dir", path(&state))],
        &["--store-only"],
        None,
    ));
    let refused_content = root.join("refused-content");
    let refused_ack = root.join("refused-ack");
    let refused = public(revoked.execute(
        "disclosure-receive",
        &socket,
        &[
            ("--target", path(&target)),
            ("--expected-binding", path(&revoked.binding)),
            ("--expected-bytes", &length),
            ("--content-out", path(&refused_content)),
            ("--acknowledgement-out", path(&refused_ack)),
        ],
        &["--recipient-seed-stdin"],
        Some(&[31; 32]),
    ));
    assert_eq!(refused["outcome"], "refused");
    assert!(!refused_content.exists() && !refused_ack.exists());
    assert_eq!(
        history(&socket, "release"),
        disclosed,
        "disable does not erase legitimate evidence"
    );
    assert_eq!(provider.calls().len(), 3);
    drop(daemon);
    // The real receipt time was checked above; exclude ambient time from the frozen artifact.
    assert!(
        observed["report"]["source"]["recovery_received_at"]
            .as_u64()
            .is_some_and(|time| time >= now)
    );
    observed["report"]["source"]["recovery_received_at"] = json!("actual-runtime-time-checked");
    assert!(
        observed["report"]["acquisition_received_at"]
            .as_u64()
            .is_some_and(|time| time >= now)
    );
    observed["report"]["acquisition_received_at"] = json!("actual-runtime-time-checked");
    let artifact=serde_json::to_vec_pretty(&json!({"schema":"auths.content-process-journey/1",
        "scope":"production CLI and daemon processes, native proofs/exact approval, real file custody/journal and counting loopback HTTP; public fixed signing keys simulate reviewer, actor and recipient; no human presence, UID containment, installed language package, power loss or PostgreSQL claim",
        "provider_requests":provider.calls(),"acquisition":acquired,"disclosure":disclosed,"mutation":written,"observation":observed,
        "revoked_disclosure":refused,"restart_replay_no_redelivery":true, "crash_after_receipt_before_ack":unknown, "late_ack_after_crash":late_ack,"late_ack_idempotent":true,
        "private_recipient_outputs_mode": "0600", "resource_authoring_rejects_duplicate_extra_nonobject_oversize":true, "resource_limit_accepted_and_existing_call_not_overwritten":true,
        "public_results_exclude_sentinel_content_and_credential":true})).expect("artifact");
    let output = fixtures.join("content-process-journey.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&output, &artifact).expect("write fixture");
    }
    assert_eq!(std::fs::read(output).expect("fixture"), artifact);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "read-only installation and external-call assertions"
)]
fn native_read_only_process_journey_fixture_is_current() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../bindings/fixtures/gateway");
    let source = std::fs::read(fixtures.join("content-only/recipe.json")).expect("source");
    let lock = std::fs::read(fixtures.join("content-only/profile.lock.json")).expect("lock");
    let recipe = CompiledRecipe::compile(&source, &lock).expect("read-only recipe");
    assert!(recipe.review().method().is_none());
    assert!(recipe.recovery().is_none());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let tools = [CONTENT_READ_TOOL, DISCLOSURE_TOOL].map(|tool| {
        McpToolCall::new(recipe.review().service(), tool, serde_json::Map::new()).expect("tool")
    });
    let trust = tools_context(&tools, now).expect("read/release-only native trust");
    let reviewer = SigningKey::from_bytes(&[29; 32]);
    let recipient = SigningKey::from_bytes(&[31; 32]);
    let policy = EffectPolicy::new(
        "readonly-process-journey".to_owned(),
        1,
        reviewer.verifying_key().to_bytes(),
    )
    .expect("policy");
    let directory = tempfile::Builder::new()
        .prefix("ap74-ro-")
        .tempdir_in("/tmp")
        .expect("directory");
    let root = std::fs::canonicalize(directory.path()).expect("canonical");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("mode");
    let state = root.join("state");
    let socket = root.join("app.sock");
    for (name, bytes) in [
        ("recipe", source),
        ("lock", lock),
        ("trust", trust),
        (
            "policy",
            policy.to_private_bytes().expect("policy").to_vec(),
        ),
    ] {
        private(&root.join(name), &bytes);
    }
    let provider = Provider::start();
    let review: Value = serde_json::from_slice(&success(cli(
        "review",
        &[
            ("--recipe", path(&root.join("recipe"))),
            ("--profile-lock", path(&root.join("lock"))),
        ],
        &[],
        None,
    )))
    .expect("operator review");
    assert!(review["method"].is_null());
    assert!(review["recovery"].is_null());
    assert_eq!(review["maximum_body_bytes"], 0);
    assert_eq!(review["path"], json!([]));
    assert_eq!(review["content_acquisition"]["method"], "GET");
    success(cli(
        "install",
        &[
            ("--state-dir", path(&state)),
            ("--recipe", path(&root.join("recipe"))),
            ("--profile-lock", path(&root.join("lock"))),
            ("--trusted-context", path(&root.join("trust"))),
            ("--effect-policy", path(&root.join("policy"))),
            ("--approve-digest", &recipe.digest_hex()),
            ("--provider", "airtable"),
            ("--alias", "read-only"),
            ("--account-label", "public-readonly-fixture"),
        ],
        &["--credential-stdin"],
        Some(SECRET),
    ));
    let arguments = root.join("resource.json");
    let call = root.join("read.call");
    private(
        &arguments,
        &serde_json::to_vec(&json!({"record_id":RECORD})).expect("arguments"),
    );
    success(cli(
        "effect-content-call",
        &[
            ("--state-dir", path(&state)),
            ("--resource-arguments", path(&arguments)),
            ("--operation", "read"),
            ("--call-out", path(&call)),
        ],
        &[],
        None,
    ));
    let read = approve(
        &state,
        &call_file(&call),
        "read",
        now,
        &reviewer,
        &[],
        &["--content"],
    );
    let invalid_review = root.join("invalid-review");
    assert!(
        !cli(
            "effect-review",
            &[
                ("--state-dir", path(&state)),
                ("--proof", path(&read.proof)),
                ("--action", path(&read.action)),
                ("--not-before", &(now - 1).to_string()),
                ("--expires-at", &(now + 300).to_string()),
                ("--request-out", path(&invalid_review))
            ],
            &[],
            None
        )
        .status
        .success()
    );
    assert!(!invalid_review.exists());
    assert!(provider.calls().is_empty());
    let daemon = Daemon::start(&state, &socket, provider.port);
    let rejected_mutation = public(read.execute("submit", &socket, &[], &[], None));
    assert_eq!(
        rejected_mutation["outcome"], "not-entered",
        "{rejected_mutation}"
    );
    assert!(
        provider.calls().is_empty(),
        "native read authority and approval cannot enter mutation"
    );
    let acquired = public(read.execute("content-acquire", &socket, &[], &[], None));
    assert_eq!(
        acquired["history"]["snapshot"]["stage"], "response-recorded",
        "{acquired}"
    );
    let uid = rustix::process::geteuid().as_raw();
    let target = root.join("target.json");
    private(
        &target,
        &serde_json::to_vec(&AppDisclosureTarget {
            source_operation: "read".to_owned(),
            recipient_key: recipient.verifying_key().to_bytes(),
            channel: UnixDisclosurePolicy::new(uid, uid, [7; 32]),
            delivery_instance: [8; 32],
        })
        .expect("target"),
    );
    let call = root.join("release.call");
    success(cli(
        "effect-disclosure-call",
        &[
            ("--state-dir", path(&state)),
            ("--target", path(&target)),
            ("--operation", "release"),
            ("--call-out", path(&call)),
        ],
        &[],
        None,
    ));
    let release = approve(
        &state,
        &call_file(&call),
        "release",
        now,
        &reviewer,
        &[("--disclosure", path(&target))],
        &[],
    );
    let received = root.join("content");
    let ack = root.join("ack");
    assert_eq!(
        public(release.execute(
            "disclosure-receive",
            &socket,
            &[
                ("--target", path(&target)),
                ("--expected-binding", path(&release.binding)),
                ("--expected-bytes", &CONTENT.len().to_string()),
                ("--content-out", path(&received)),
                ("--acknowledgement-out", path(&ack))
            ],
            &["--recipient-seed-stdin"],
            Some(&[31; 32])
        ))["outcome"],
        "recipient-ack-sent"
    );
    assert_eq!(std::fs::read(&received).expect("content"), CONTENT);
    let deadline = Instant::now() + Duration::from_secs(5);
    let disclosed = loop {
        let value = history(&socket, "release");
        if value["history"]["snapshot"]["stage"] == "acknowledged" {
            break value;
        }
        assert!(Instant::now() < deadline, "ACK persistence: {value}");
        thread::sleep(Duration::from_millis(10));
    };
    assert!(
        !cli(
            "effect-recovery-call",
            &[
                ("--state-dir", path(&state)),
                ("--source-operation", "read"),
                ("--recovery-operation", "fake-mutation")
            ],
            &[],
            None
        )
        .status
        .success()
    );
    assert_eq!(
        provider.calls(),
        [format!(
            "GET /documents/{RECORD}?format=text%2Fplain HTTP/1.1"
        )]
    );
    drop(daemon);
    let artifact=serde_json::to_vec_pretty(&json!({"schema":"auths.read-only-process-journey/1",
        "scope":"production local CLI/daemon processes, file custody/journal, native read/release-only grants and public fixed test approval keys; no Google metadata, UI, language package, hostile UID isolation or PostgreSQL claim",
        "recipe_digest":recipe.digest_hex(),"operator_review":review,"provider_requests":provider.calls(),
        "mutation_refusal":rejected_mutation,"mutation_review_refused":true,"acquisition":acquired,"disclosure":disclosed,
        "content_source_cannot_be_mutation_recovery_source":true,"no_mutation_permission_or_plan_installed":true})).expect("artifact");
    let output = fixtures.join("read-only-process-journey.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&output, &artifact).expect("write");
    }
    assert_eq!(std::fs::read(output).expect("fixture"), artifact);
}

struct ReadOnlyInstallation {
    _directory: tempfile::TempDir,
    root: PathBuf,
    state: PathBuf,
    now: u64,
    reviewer: SigningKey,
}
impl ReadOnlyInstallation {
    fn create() -> Self {
        let fixtures =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../bindings/fixtures/gateway");
        let source = std::fs::read(fixtures.join("content-only/recipe.json")).expect("source");
        let lock = std::fs::read(fixtures.join("content-only/profile.lock.json")).expect("lock");
        let recipe = CompiledRecipe::compile(&source, &lock).expect("recipe");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let tools = [CONTENT_READ_TOOL, DISCLOSURE_TOOL].map(|tool| {
            McpToolCall::new(recipe.review().service(), tool, serde_json::Map::new()).expect("tool")
        });
        let trust = tools_context(&tools, now).expect("trust");
        let reviewer = SigningKey::from_bytes(&[29; 32]);
        let policy = EffectPolicy::new(
            "process-capacity".to_owned(),
            1,
            reviewer.verifying_key().to_bytes(),
        )
        .expect("policy");
        let directory = tempfile::Builder::new()
            .prefix("ap74-cap-")
            .tempdir_in("/tmp")
            .expect("directory");
        let root = std::fs::canonicalize(directory.path()).expect("canonical");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("mode");
        let state = root.join("state");
        for (name, bytes) in [
            ("recipe", source),
            ("lock", lock),
            ("trust", trust),
            (
                "policy",
                policy.to_private_bytes().expect("policy").to_vec(),
            ),
        ] {
            private(&root.join(name), &bytes);
        }
        success(cli(
            "install",
            &[
                ("--state-dir", path(&state)),
                ("--recipe", path(&root.join("recipe"))),
                ("--profile-lock", path(&root.join("lock"))),
                ("--trusted-context", path(&root.join("trust"))),
                ("--effect-policy", path(&root.join("policy"))),
                ("--approve-digest", &recipe.digest_hex()),
                ("--provider", "airtable"),
                ("--alias", "capacity"),
                ("--account-label", "public-capacity-fixture"),
            ],
            &["--credential-stdin"],
            Some(SECRET),
        ));
        private(
            &root.join("resource.json"),
            &serde_json::to_vec(&json!({"record_id":RECORD})).expect("resource"),
        );
        Self {
            _directory: directory,
            root,
            state,
            now,
            reviewer,
        }
    }
    fn join_peer(&self) -> PathBuf {
        let peer = self.root.join("peer");
        let recipe = CompiledRecipe::compile(
            &std::fs::read(self.root.join("recipe")).expect("recipe"),
            &std::fs::read(self.root.join("lock")).expect("lock"),
        )
        .expect("recipe");
        success(cli(
            "install",
            &[
                ("--state-dir", path(&peer)),
                ("--attempt-store", path(&self.state.join("attempts"))),
                ("--recipe", path(&self.root.join("recipe"))),
                ("--profile-lock", path(&self.root.join("lock"))),
                ("--trusted-context", path(&self.root.join("trust"))),
                ("--effect-policy", path(&self.root.join("policy"))),
                ("--approve-digest", &recipe.digest_hex()),
                ("--provider", "airtable"),
                ("--alias", "capacity"),
            ],
            &["--join", "--credential-stdin"],
            Some(SECRET),
        ));
        peer
    }
    fn approve_read(&self, operation: &str) -> Approved {
        let call = self.root.join(format!("{operation}.call"));
        success(cli(
            "effect-content-call",
            &[
                ("--state-dir", path(&self.state)),
                (
                    "--resource-arguments",
                    path(&self.root.join("resource.json")),
                ),
                ("--operation", operation),
                ("--call-out", path(&call)),
            ],
            &[],
            None,
        ));
        approve(
            &self.state,
            &call_file(&call),
            operation,
            self.now,
            &self.reviewer,
            &[],
            &["--content"],
        )
    }
}

fn private_capacity_records(state: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(state.join("attempts"))
        .expect("journal directory")
        .map(|entry| entry.expect("journal entry").path())
        .filter(|path| {
            path.file_name().is_some_and(|name| {
                let name = name.to_string_lossy();
                name.ends_with(".json")
                    && (name.starts_with("claim-") || name.starts_with("allocation-"))
            })
        })
        .map(|path| {
            (
                path.file_name()
                    .expect("name")
                    .to_string_lossy()
                    .into_owned(),
                std::fs::read(path).expect("private journal"),
            )
        })
        .collect()
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one real two-daemon allocation, replay and restart history"
)]
fn native_content_process_capacity_fixture_is_current() {
    let installation = ReadOnlyInstallation::create();
    let root = &installation.root;
    let provider = Provider::start();
    let left_socket = root.join("left.sock");
    let right_socket = root.join("right.sock");
    let left = Daemon::start_at_admin(
        &installation.state,
        &left_socket,
        &root.join("left-admin.sock"),
        provider.port,
    );
    let peer = installation.join_peer();
    let right = Daemon::start_at_admin(
        &peer,
        &right_socket,
        &root.join("right-admin.sock"),
        provider.port,
    );
    assert_ne!(left.0.id(), right.0.id(), "independent gateway processes");
    let operations: Vec<_> = (0..17).map(|index| format!("capacity-{index}")).collect();
    let approved: Vec<_> = operations
        .iter()
        .map(|operation| installation.approve_read(operation))
        .collect();
    assert!(
        provider.calls().is_empty(),
        "authoring does not acquire capacity or contact provider"
    );
    let mut histories = Vec::new();
    for (index, effect) in approved.iter().enumerate().take(15) {
        let socket = if index % 2 == 0 {
            &left_socket
        } else {
            &right_socket
        };
        let result = public(effect.execute("content-acquire", socket, &[], &[], None));
        assert_eq!(
            result["history"]["snapshot"]["stage"], "response-recorded",
            "{result}"
        );
        histories.push(result);
    }
    assert_eq!(provider.calls().len(), 15);
    let barrier = std::sync::Barrier::new(3);
    let (a, b) = thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            public(approved[15].execute("content-acquire", &left_socket, &[], &[], None))
        });
        let second = scope.spawn(|| {
            barrier.wait();
            public(approved[16].execute("content-acquire", &right_socket, &[], &[], None))
        });
        barrier.wait();
        (
            first.join().expect("first contender"),
            second.join().expect("second contender"),
        )
    });
    let race = [a, b];
    assert_eq!(
        race.iter()
            .filter(|value| value["history"]["snapshot"]["stage"] == "response-recorded")
            .count(),
        1,
        "one final allocation: {race:?}"
    );
    let refused = race
        .iter()
        .find(|value| value["history"]["snapshot"]["stage"] == "not-entered")
        .unwrap_or_else(|| panic!("missing capacity refusal: {race:?}"))
        .clone();
    assert_eq!(refused["history"]["snapshot"]["reserved_calls"], 0);
    assert_eq!(refused["history"]["snapshot"]["reserved_bytes"], 0);
    histories.extend(race);
    let calls: u64 = histories
        .iter()
        .map(|value| {
            value["history"]["snapshot"]["reserved_calls"]
                .as_u64()
                .expect("calls")
        })
        .sum();
    let bytes: u64 = histories
        .iter()
        .map(|value| {
            value["history"]["snapshot"]["reserved_bytes"]
                .as_u64()
                .expect("bytes")
        })
        .sum();
    assert_eq!(
        (calls, bytes),
        (16, 16 * 1024),
        "lifetime count and full response ceiling conserved"
    );
    assert_eq!(
        provider.calls().len(),
        16,
        "one external request per admitted read"
    );
    for (operation, expected) in operations.iter().zip(&histories) {
        assert_eq!(
            &history(&right_socket, operation),
            expected,
            "cross-process history"
        );
    }
    let retained = private_capacity_records(&installation.state);
    let claims: Vec<Value> = retained
        .iter()
        .filter(|(name, _)| name.starts_with("claim-"))
        .map(|(_, bytes)| serde_json::from_slice(bytes).expect("native record"))
        .collect();
    assert_eq!(claims.len(), 17);
    assert_eq!(
        claims
            .iter()
            .filter(|record| !record["entry"].is_null())
            .count(),
        16,
        "one durable grant per provider entry"
    );
    let not_entered = claims
        .iter()
        .find(|record| record["state"]["facts"]["phase"]["stage"] == "not-entered")
        .expect("durable capacity refusal");
    assert_eq!(not_entered["state"]["protocol"], "acquisition");
    assert_eq!(
        not_entered["state"]["facts"]["phase"]["code"],
        "gateway.acquisition.exhausted"
    );
    assert!(not_entered["entry"].is_null());
    assert!(not_entered["state"]["facts"]["allocation"].is_null());
    assert_eq!(not_entered["state"]["facts"]["counters"], json!([]));
    assert_eq!(
        retained
            .keys()
            .filter(|name| name.starts_with("allocation-"))
            .count(),
        16
    );
    drop(left);
    drop(right);
    let reopened_socket = root.join("reopened.sock");
    let reopened = Daemon::start_at_admin(
        &installation.state,
        &reopened_socket,
        &root.join("reopened-admin.sock"),
        provider.port,
    );
    for ((effect, operation), expected) in approved.iter().zip(&operations).zip(&histories) {
        assert_eq!(
            &public(effect.execute("content-acquire", &reopened_socket, &[], &[], None)),
            expected,
            "restart replay {operation}"
        );
    }
    assert_eq!(
        provider.calls().len(),
        16,
        "replays cannot allocate or refetch after restart"
    );
    assert_eq!(
        private_capacity_records(&installation.state),
        retained,
        "replay leaves journal, grants and allocations byte-for-byte unchanged"
    );
    drop(reopened);
    let artifact = serde_json::to_vec_pretty(&json!({"schema":"auths.content-process-capacity/1",
        "scope":"two independent production daemon processes with separate joined local custody and CLI callers; real native proof/approval/fenced file adapter, counting local HTTP; source-lifetime acquisition count/response ceilings only, not managed fixed-window count/sum, PostgreSQL, distributed fencing or power loss",
        "initial_allocations":15,"final_contenders":2,"final_grants":1,"exhausted":1,
        "provider_calls":provider.calls().len(),"retained_calls":calls,"retained_response_bytes":bytes,
        "all_requests_exact":provider.calls().iter().all(|line|line==&format!("GET /documents/{RECORD}?format=text%2Fplain HTTP/1.1")),
        "restart_replay_no_refetch":true,"cross_process_history_matches":true,
        "durable_grants":16,"permanent_allocations":16,"native_refusal_code":"gateway.acquisition.exhausted",
        "journal_and_allocations_unchanged_after_restart_replay":true,
        "successful_read":histories[0],"capacity_refusal":refused})).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/content-process-capacity.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("write artifact");
    }
    assert_eq!(std::fs::read(path).expect("artifact"), artifact);
}
