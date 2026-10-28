//! Real CLI processes, native signatures, file custody/journal and a counting
//! local HTTP provider. Fixed public test keys simulate the external reviewer;
//! this is no human-presence, live-provider, isolation or PostgreSQL claim.
#![cfg(all(unix, feature = "testkit-harness", feature = "loopback-provider"))]

use auths_connections::{ConnectionAlias, ConnectionRecord, ProviderKind};
use auths_gateway::effect::{CANDIDATE_CHECK_TOOL, EffectApprovalRequest, EffectPolicy};
use auths_gateway::harness::authoring::tool_fixture;
use auths_gateway::{CompiledRecipe, FileGatewayAttemptStore, SharedConnection};
use auths_profile_mcp::McpToolCall;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const INITIAL: &[u8] = b"rk_test_public_initial_fixture";
const ROTATED: &[u8] = b"rk_test_public_rotated_fixture";

struct Provider {
    port: u16,
    stop: Arc<AtomicBool>,
    calls: Arc<Mutex<Vec<String>>>,
    join: Option<JoinHandle<()>>,
}

impl Provider {
    fn start(case: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let port = listener.local_addr().expect("address").port();
        listener.set_nonblocking(true).expect("nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let finished = stop.clone();
        let observed = calls.clone();
        let join = thread::spawn(move || {
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
                    .expect("accepted blocking socket");
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("read timeout");
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .expect("write timeout");
                let mut request = Vec::new();
                while request.len() < 16_384 && !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    if stream.read_exact(&mut byte).is_err() {
                        break;
                    }
                    request.push(byte[0]);
                }
                let request = String::from_utf8(request).expect("request UTF-8");
                let line = request.lines().next().expect("request line").to_owned();
                let lowered = request.to_ascii_lowercase();
                assert!(lowered.contains("stripe-version: 2025-03-31.basil\r\n"));
                assert!(!lowered.contains("stripe-account:"));
                assert!(
                    lowered.contains(&format!(
                        "authorization: bearer {}\r\n",
                        String::from_utf8_lossy(INITIAL)
                    )) || lowered.contains(&format!(
                        "authorization: bearer {}\r\n",
                        String::from_utf8_lossy(ROTATED)
                    ))
                );
                observed.lock().expect("calls").push(line.clone());
                let (status, body) = match line.as_str() {
                    "GET /v1/balance HTTP/1.1" => (
                        200,
                        if case == "bad-probe" {
                            r#"{"livemode":true}"#
                        } else {
                            r#"{"livemode":false}"#
                        },
                    ),
                    "GET /v1/account HTTP/1.1" => (
                        200,
                        if case == "wrong-account" {
                            r#"{"id":"acct_TESTOTHER01"}"#
                        } else {
                            r#"{"id":"acct_TESTACCOUNT01"}"#
                        },
                    ),
                    "GET /v1/customers HTTP/1.1" => (403, "{}"),
                    "GET /v1/payouts HTTP/1.1" if case == "unknown-primary" => continue,
                    "GET /v1/payouts HTTP/1.1" => (
                        if case == "excess-capability" {
                            200
                        } else {
                            403
                        },
                        "{}",
                    ),
                    _ => panic!("unexpected external request: {line}"),
                };
                let response = format!(
                    "HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nStripe-Version: 2025-03-31.basil\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).expect("response");
            }
        });
        Self {
            port,
            stop,
            calls,
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
                result.expect("provider thread");
            }
        }
    }
}

fn private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("mode");
}
fn cli(command: &str, arguments: &[(&str, &str)], secret: Option<&[u8]>) -> Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_auths-gateway"));
    process.arg(command);
    for (name, value) in arguments {
        process.arg(name).arg(value);
    }
    if secret.is_some() {
        process.arg("--credential-stdin");
    }
    let mut child = process
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("CLI");
    if let Some(secret) = secret {
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(secret)
            .expect("secret input");
    } else {
        drop(child.stdin.take());
    }
    child.wait_with_output().expect("CLI output")
}
fn success(output: Output) -> Vec<u8> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
fn path(path: &Path) -> &str {
    path.to_str().expect("UTF-8 path")
}

struct Approved {
    proposal: PathBuf,
    proof: PathBuf,
    action: PathBuf,
    approval: PathBuf,
}
impl Approved {
    fn invoke(&self, command: &str, state: &Path, provider: Option<u16>) -> Output {
        let port = provider.map(|port| port.to_string());
        let mut args = vec![
            ("--state-dir", path(state)),
            ("--candidate", path(&self.proposal)),
            ("--proof", path(&self.proof)),
            ("--action", path(&self.action)),
            ("--approval", path(&self.approval)),
        ];
        if let Some(port) = &port {
            args.push(("--loopback-provider", port));
        }
        cli(command, &args, None)
    }
}

fn approve(
    state: &Path,
    proposal: PathBuf,
    operation: &str,
    now: u64,
    key: &SigningKey,
) -> Approved {
    let call_path = state.join(format!("{operation}.call.json"));
    success(cli(
        "effect-candidate-call",
        &[
            ("--state-dir", path(state)),
            ("--candidate", path(&proposal)),
            ("--operation", operation),
            ("--call-out", path(&call_path)),
        ],
        None,
    ));
    let call = McpToolCall::from_canonical_bytes(&std::fs::read(call_path).expect("call"))
        .expect("native call");
    let fixture = tool_fixture(&call, now).expect("native signed authority");
    assert_eq!(
        std::fs::read(state.join("trusted.context.cbor")).expect("installed trust"),
        fixture.context
    );
    let proof = state.join(format!("{operation}.proof.cbor"));
    let action = state.join(format!("{operation}.action.cbor"));
    let request = state.join(format!("{operation}.request.json"));
    private(&proof, &fixture.proof);
    private(&action, &fixture.action);
    let reviewed = success(cli(
        "effect-review",
        &[
            ("--state-dir", path(state)),
            ("--candidate", path(&proposal)),
            ("--proof", path(&proof)),
            ("--action", path(&action)),
            ("--not-before", &(now - 1).to_string()),
            ("--expires-at", &(now + 300).to_string()),
            ("--request-out", path(&request)),
        ],
        None,
    ));
    let review: Value = serde_json::from_slice(&reviewed).expect("private review");
    let signing =
        EffectApprovalRequest::from_private_bytes(&std::fs::read(&request).expect("request"))
            .expect("native request");
    assert_eq!(
        review["signing_message_hex"],
        hex::encode(signing.signing_message().expect("message"))
    );
    let literal = review["literal_review"].as_str().expect("literal review");
    for required in ["/v1/balance", "/v1/account", "/v1/customers", "/v1/payouts"] {
        assert!(literal.contains(required), "missing request {required}");
    }
    let signature = key
        .sign(&signing.signing_message().expect("message"))
        .to_bytes();
    let approval = state.join(format!("{operation}.approval.json"));
    private(
        &approval,
        &success(cli(
            "effect-approval",
            &[
                ("--request", path(&request)),
                ("--signature-hex", &hex::encode(signature)),
            ],
            None,
        )),
    );
    Approved {
        proposal,
        proof,
        action,
        approval,
    }
}

fn retained_journal(state: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(state.join("attempts"))
        .expect("journal directory")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
                && !path
                    .file_name()
                    .expect("name")
                    .to_string_lossy()
                    .starts_with("conn-")
        })
        .map(|path| {
            (
                path.file_name()
                    .expect("name")
                    .to_string_lossy()
                    .into_owned(),
                std::fs::read(&path).expect("journal bytes"),
            )
        })
        .collect()
}

fn current(state: &Path) -> Option<ConnectionRecord> {
    let shared = SharedConnection::new(
        Arc::new(FileGatewayAttemptStore::open(state.join("attempts")).expect("store")),
        ProviderKind::parse("stripe").expect("provider"),
        ConnectionAlias::parse("journey").expect("alias"),
    );
    tokio::runtime::Runtime::new()
        .expect("runtime")
        .block_on(shared.load())
        .expect("load")
        .map(|record| record.record().clone())
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one process journey keeps ordered actions and evidence assertions together"
)]
fn approved_candidate_process_journey_fixture_is_current() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../bindings/fixtures/gateway");
    let corpus: Value = serde_json::from_slice(
        &std::fs::read(fixtures.join("hostile-recipes-v2.json")).expect("recipes"),
    )
    .expect("JSON");
    let source = serde_json::to_vec(&corpus["bases"]["stripe"]["recipe"]).expect("source");
    let lock = serde_json::to_vec(&corpus["bases"]["stripe"]["lock"]).expect("lock");
    let recipe = CompiledRecipe::compile(&source, &lock).expect("recipe");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let bootstrap = tool_fixture(
        &McpToolCall::new(
            "stripe-refunds",
            CANDIDATE_CHECK_TOOL,
            serde_json::Map::new(),
        )
        .expect("tool"),
        now,
    )
    .expect("test trust");
    let key = SigningKey::from_bytes(&[29; 32]);
    let policy = EffectPolicy::new(
        "candidate-process-journey".to_owned(),
        1,
        key.verifying_key().to_bytes(),
    )
    .expect("policy");
    let mut cases = Vec::new();
    for case in [
        "accepted",
        "accepted-disabled",
        "bad-probe",
        "wrong-account",
        "excess-capability",
        "unknown-primary",
    ] {
        let directory = tempfile::tempdir().expect("directory");
        let root = std::fs::canonicalize(directory.path()).expect("canonical");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("mode");
        let state = root.join("state");
        for (name, bytes) in [
            ("recipe.json", source.as_slice()),
            ("lock.json", lock.as_slice()),
            ("trust.cbor", bootstrap.context.as_slice()),
            (
                "policy.json",
                policy.to_private_bytes().expect("policy").as_slice(),
            ),
        ] {
            private(&root.join(name), bytes);
        }
        let provider = Provider::start(case);
        success(cli(
            "install",
            &[
                ("--state-dir", path(&state)),
                ("--recipe", path(&root.join("recipe.json"))),
                ("--profile-lock", path(&root.join("lock.json"))),
                ("--trusted-context", path(&root.join("trust.cbor"))),
                ("--effect-policy", path(&root.join("policy.json"))),
                ("--approve-digest", &recipe.digest_hex()),
                ("--provider", "stripe"),
                ("--alias", "journey"),
                ("--account-label", "acct_TESTACCOUNT01"),
            ],
            Some(INITIAL),
        ));
        assert!(current(&state).is_none());
        assert!(provider.calls().is_empty());
        let approved = approve(
            &state,
            state.join("candidate-installation.json"),
            "initial",
            now,
            &key,
        );
        assert!(
            provider.calls().is_empty(),
            "authoring and review perform no provider I/O"
        );
        assert!(
            !approved
                .invoke("candidate-publish", &state, None)
                .status
                .success(),
            "approval without acquired evidence cannot publish"
        );
        let valid = std::fs::read(&approved.approval).expect("approval");
        let request: Value = serde_json::from_slice(&valid).expect("approval JSON");
        let mut forged = request;
        forged["signature_b64"] = json!("invalid");
        private(
            &approved.approval,
            &serde_json_canonicalizer::to_vec(&forged).expect("forged"),
        );
        assert!(
            !approved
                .invoke("candidate-acquire", &state, Some(provider.port))
                .status
                .success()
        );
        assert!(provider.calls().is_empty());
        private(&approved.approval, &valid);
        if case == "accepted" {
            let substituted = approve(
                &state,
                approved.proposal.clone(),
                "different-operation",
                now,
                &key,
            );
            private(&substituted.approval, &valid);
            assert!(
                !substituted
                    .invoke("candidate-acquire", &state, Some(provider.port))
                    .status
                    .success(),
                "old exact approval cannot authorize a different operation"
            );
            assert!(provider.calls().is_empty());
        }
        let acquired = if case == "accepted" {
            let (first, second) = thread::scope(|scope| {
                let first = scope
                    .spawn(|| approved.invoke("candidate-acquire", &state, Some(provider.port)));
                let second = scope
                    .spawn(|| approved.invoke("candidate-acquire", &state, Some(provider.port)));
                (
                    first.join().expect("first acquirer"),
                    second.join().expect("second acquirer"),
                )
            });
            let first_value: Value =
                serde_json::from_slice(&first.stdout).expect("first concurrent response");
            let second_value: Value =
                serde_json::from_slice(&second.stdout).expect("second concurrent response");
            assert!(
                first_value["stage"] == "response-recorded"
                    || second_value["stage"] == "response-recorded",
                "one process completes: {first_value}, {second_value}"
            );
            if first_value["stage"] == "response-recorded" {
                first
            } else {
                second
            }
        } else {
            approved.invoke("candidate-acquire", &state, Some(provider.port))
        };
        for secret in [
            INITIAL,
            ROTATED,
            b"acct_TESTACCOUNT01".as_slice(),
            b"acct_TESTOTHER01".as_slice(),
        ] {
            assert!(
                !acquired
                    .stdout
                    .windows(secret.len())
                    .any(|window| window == secret)
            );
            assert!(
                !acquired
                    .stderr
                    .windows(secret.len())
                    .any(|window| window == secret)
            );
        }
        let acquired: Value =
            serde_json::from_slice(&acquired.stdout).expect("native acquisition result");
        let calls = provider.calls();
        assert_eq!(
            calls.len(),
            match case {
                "bad-probe" => 1,
                "wrong-account" => 2,
                _ => 4,
            },
            "{case}: {acquired}"
        );
        let journal = retained_journal(&state);
        let replay = approved.invoke("candidate-acquire", &state, Some(provider.port));
        let replay: Value = serde_json::from_slice(&replay.stdout).expect("replay result");
        assert_eq!(
            provider.calls(),
            calls,
            "restart replay cannot reenter provider"
        );
        assert_eq!(
            retained_journal(&state),
            journal,
            "replay preserves every retained journal fact and allocation"
        );
        assert!(current(&state).is_none());
        let mut rotation = Value::Null;
        let publication = approved.invoke("candidate-publish", &state, None);
        assert_eq!(
            retained_journal(&state),
            journal,
            "publication preserves facts and charges"
        );
        if case.starts_with("accepted") {
            assert_eq!(
                serde_json::from_slice::<Value>(&success(publication)).expect("publication"),
                json!("published")
            );
            assert_eq!(acquired["stage"], "response-recorded");
            assert_eq!(replay, acquired);
            assert_eq!(current(&state).expect("published").generation().get(), 1);
            assert_eq!(
                serde_json::from_slice::<Value>(&success(approved.invoke(
                    "candidate-publish",
                    &state,
                    None
                )))
                .expect("replay publication"),
                json!("already-current")
            );
            assert_eq!(provider.calls(), calls);
            if case == "accepted-disabled" {
                let output = Command::new(env!("CARGO_BIN_EXE_auths-gateway"))
                    .args(["disable", "--state-dir", path(&state), "--store-only"])
                    .output()
                    .expect("disable CLI");
                success(output);
            }
            let previous = current(&state).expect("rotation predecessor");
            let proposal = state.join("rotation.json");
            success(cli(
                "candidate-stage-rotation",
                &[
                    ("--state-dir", path(&state)),
                    ("--proposal-out", path(&proposal)),
                ],
                Some(ROTATED),
            ));
            let rotated = approve(&state, proposal, "rotation", now, &key);
            assert_eq!(provider.calls(), calls);
            let read: Value = serde_json::from_slice(&success(rotated.invoke(
                "candidate-acquire",
                &state,
                Some(provider.port),
            )))
            .expect("rotation read");
            assert_eq!(read["stage"], "response-recorded");
            assert_eq!(provider.calls().len(), 8);
            assert_eq!(current(&state).expect("old current"), previous);
            let rotation_journal = retained_journal(&state);
            assert_eq!(
                serde_json::from_slice::<Value>(&success(rotated.invoke(
                    "candidate-publish",
                    &state,
                    None
                )))
                .expect("rotated"),
                json!("published")
            );
            assert_eq!(
                current(&state).expect("new current").generation().get(),
                previous.generation().get() + 1
            );
            assert_eq!(
                current(&state).expect("new current").state(),
                previous.state()
            );
            assert_eq!(provider.calls().len(), 8);
            assert_eq!(retained_journal(&state), rotation_journal);
            rotation = read;
        } else {
            assert!(
                !publication.status.success(),
                "failed checks cannot publish"
            );
            assert!(current(&state).is_none());
            assert_eq!(provider.calls(), calls);
            if case == "unknown-primary" {
                assert_eq!(acquired["stage"], "unknown");
                assert_eq!(replay, acquired);
                assert_eq!(acquired["reserved_calls"], 1);
            }
        }
        cases.push(json!({"case":case,"initial_requests":calls,"acquisition":acquired,"replay":replay,"rotation_acquisition":rotation,"journal_and_allocations_unchanged_on_replay_and_publication":true,"publication":if case.starts_with("accepted") {"published"} else {"refused"},"restart_replay_no_provider_entry":true,"invalid_approval_no_provider_entry":true,"approval_alone_no_publication":true,"rotation_completed":case.starts_with("accepted"),"competing_acquisition_processes":case=="accepted","old_approval_new_operation_refused":case=="accepted","rotation_preserves_disabled_state":case=="accepted-disabled","public_acquisition_excludes_secret_and_account":true}));
    }
    let fixture = serde_json::to_vec_pretty(&json!({"schema":"auths.candidate-process-journey/1","scope":"production CLI processes, native proof/exact approval, real file custody/journal/floor and counting local HTTP transport; fixed public test keys simulate reviewer; no human presence, live provider, isolation, crash injection or PostgreSQL claim","cases":cases})).expect("fixture");
    let output = fixtures.join("candidate-process-journey.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&output, &fixture).expect("write fixture");
    }
    assert_eq!(std::fs::read(output).expect("fixture"), fixture);
}
