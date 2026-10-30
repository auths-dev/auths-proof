//! Independent native recovery after operator withdrawal of the writer's root.
//! Real OS workers, local HTTP, exact approvals and both durable adapters.
use crate::effect::ExactEffectApproval;
use crate::native_crash_tests::Peer;
use crate::native_process_tests::{
    EngineControls, NOW, Setup, load_controlled_engine, private, runtime,
};
use crate::observed_tests::recovery_authoring as author;
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::{
    GatewayAttemptKey, GatewayEngine, GatewayRecordKind, GatewaySubmitResult, LogicalOperationId,
    SharedConnection,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const SOURCE: &str = "retired-writer";
const RECOVERY: &str = "independent-reader";
const PEER_ENV: &str = "AUTHS_AP074_RECOVERY_ACTOR_PEER";
const TARGET: &str = "/v0/appTEST0000000001/tblTEST0000000001/recTEST0000000001";

#[path = "native_recovery_history_tests.rs"]
mod history_tests;
#[path = "native_recovery_limits_tests.rs"]
mod limits_tests;
#[path = "native_public_evidence_tests.rs"]
mod privacy_tests;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Outcome {
    ResponseEcho,
    ResponseState,
    LostEcho,
    LostState,
}
impl Outcome {
    const fn responds(self) -> bool {
        matches!(self, Self::ResponseEcho | Self::ResponseState)
    }
    const fn echo(self) -> bool {
        matches!(self, Self::ResponseEcho | Self::LostEcho)
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecoverySetup {
    installation: Setup,
    outcome: Outcome,
    reader: bool,
}

fn controls(reader: bool) -> EngineControls {
    let mut value = EngineControls::baseline();
    value.trust = Some(author::trust(!reader));
    value.recipe = Some(author::recipe());
    value.clock.set(NOW + u64::from(reader));
    value
}
fn input(root: &Path, name: &str) -> (Vec<u8>, Vec<u8>, ExactEffectApproval) {
    let load = |suffix| std::fs::read(root.join(format!("{name}.{suffix}"))).expect("signed input");
    (
        load("proof"),
        load("action"),
        ExactEffectApproval::from_private_bytes(&load("approval")).expect("approval"),
    )
}
fn retain(
    root: &Path,
    name: &str,
    signed: &crate::harness::authoring::ToolFixture,
    approval: &ExactEffectApproval,
) {
    for (suffix, bytes) in [
        ("proof", signed.proof.as_slice()),
        ("action", signed.action.as_slice()),
        (
            "approval",
            approval.to_private_bytes().expect("approval").as_slice(),
        ),
    ] {
        private(&root.join(format!("{name}.{suffix}")), bytes);
    }
}

#[test]
fn native_recovery_actor_peer() {
    let Some(path) = std::env::var_os(PEER_ENV) else {
        return;
    };
    let setup: RecoverySetup =
        serde_json::from_slice(&std::fs::read(path).expect("setup")).expect("closed setup");
    let store = TestAttempts::attach(
        Backend::parse(&setup.installation.backend),
        &setup.installation.location,
    );
    let runtime = runtime();
    let (engine, _) = runtime.block_on(load_controlled_engine(
        &setup.installation,
        if setup.reader {
            "reader-peer"
        } else {
            "writer-peer"
        },
        store.attempts().clone(),
        controls(setup.reader),
    ));
    let (proof, action, approval) = input(
        &setup.installation.root,
        if setup.reader { RECOVERY } else { SOURCE },
    );
    let result = if setup.reader {
        runtime.block_on(recover_twice(&engine, &store, &proof, &action, approval))
    } else {
        let result = runtime.block_on(engine.submit(&proof, &action, approval));
        assert_eq!(
            result,
            if setup.outcome.responds() {
                GatewaySubmitResult::ResponseRecorded { status: 200 }
            } else {
                GatewaySubmitResult::Unknown
            }
        );
        json!({"result": result, "execution": engine.execution_witness()})
    };
    private(
        &setup.installation.root.join(if setup.reader {
            "reader-result"
        } else {
            "writer-result"
        }),
        &serde_json::to_vec(&result).expect("result"),
    );
}
async fn recover_twice(
    engine: &GatewayEngine,
    store: &TestAttempts,
    proof: &[u8],
    action: &[u8],
    approval: ExactEffectApproval,
) -> Value {
    let first = Box::pin(engine.recover(SOURCE, proof, action, approval.clone()))
        .await
        .expect("independent recovery");
    let before = engine.execution_witness();
    let retained = journals(store).await;
    let replay = Box::pin(engine.recover(SOURCE, proof, action, approval))
        .await
        .expect("recovery replay");
    assert_eq!(first.source, replay.source);
    assert_eq!(first.acquisition, replay.acquisition);
    assert_eq!(
        retained,
        journals(store).await,
        "replay preserves exact source/read journal bytes"
    );
    assert_eq!(
        before,
        engine.execution_witness(),
        "replay adds no lease or HTTP call"
    );
    json!({"first": first.report(), "replay": replay.report(), "execution": before})
}

async fn journals(store: &TestAttempts) -> Vec<Vec<u8>> {
    let raw = store.raw();
    tokio::task::spawn_blocking(move || {
        [SOURCE, RECOVERY]
            .map(|operation| record_from(raw.as_ref(), operation))
            .to_vec()
    })
    .await
    .expect("journal reader")
}

#[derive(Debug, Eq, PartialEq)]
struct Request {
    line: String,
    body: Vec<u8>,
}
struct Provider {
    port: u16,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    read_response: Arc<Mutex<Option<ReadResponse>>>,
    read_pause: Arc<Mutex<Option<ReadPause>>>,
}

struct ReadPause {
    release: std::sync::mpsc::Receiver<()>,
    waiting: Arc<AtomicBool>,
}

/// Fault data for the provider double only; the native transport is unchanged.
struct ReadResponse {
    status: u16,
    body: Vec<u8>,
    declared_length: usize,
}
fn receive(stream: &mut TcpStream) -> (String, Vec<u8>) {
    stream
        .set_nonblocking(false)
        .expect("blocking accepted socket");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("deadline");
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .expect("deadline");
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 16_384);
        let mut byte = [0];
        stream.read_exact(&mut byte).expect("header");
        bytes.push(byte[0]);
    }
    let header = String::from_utf8(bytes).expect("header");
    assert!(
        header
            .to_ascii_lowercase()
            .contains("authorization: bearer public-native-process-fixture\r\n")
    );
    let length = header
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("length"))
        })
        .unwrap_or(0);
    assert!(length <= 65_536);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).expect("body");
    (header.lines().next().expect("request").to_owned(), body)
}
impl Provider {
    fn start(outcome: Outcome) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("provider");
        listener.set_nonblocking(true).expect("poll");
        let port = listener.local_addr().expect("address").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let read_response = Arc::new(Mutex::new(None::<ReadResponse>));
        let scripted = read_response.clone();
        let read_pause = Arc::new(Mutex::new(None::<ReadPause>));
        let paused = read_pause.clone();
        let worker = thread::spawn(move || {
            let mut state = Value::Null;
            while !done.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("provider accept: {error}"),
                };
                let (line, body) = receive(&mut stream);
                captured.lock().expect("capture").push(Request {
                    line: line.clone(),
                    body: body.clone(),
                });
                if line == format!("PATCH {TARGET} HTTP/1.1") {
                    state = serde_json::from_slice(&body).expect("native write JSON");
                    assert_eq!(state["fields"]["DemoStatus"], "Approved");
                    if !outcome.responds() {
                        continue;
                    }
                } else {
                    assert_eq!(line, format!("GET {TARGET} HTTP/1.1"));
                    assert!(body.is_empty());
                    assert!(!state.is_null(), "read follows actual write");
                    if let Some(pause) = paused.lock().expect("pause").take() {
                        pause.waiting.store(true, Ordering::SeqCst);
                        let released = pause.release.recv_timeout(
                            crate::transport::MAX_TRANSPORT_DURATION + Duration::from_secs(15),
                        );
                        pause.waiting.store(false, Ordering::SeqCst);
                        released.expect("native transport must time out before the fallback");
                        continue;
                    }
                }
                let mut response = state.clone();
                if !outcome.echo() {
                    response["fields"]
                        .as_object_mut()
                        .expect("fields")
                        .remove("auths_echo");
                }
                let body = serde_json::to_vec(&response).expect("response");
                let response = if line.starts_with("GET ") {
                    scripted.lock().expect("script").take()
                } else {
                    None
                }
                .unwrap_or(ReadResponse {
                    status: 200,
                    declared_length: body.len(),
                    body,
                });
                stream.write_all(format!("HTTP/1.1 {} Fixture\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n", response.status, response.declared_length).as_bytes()).expect("response header");
                if response.body.len() > 16_384 {
                    // This explicit oversized-response fault permits the
                    // bounded client to close before receiving the body.
                    let _ = stream.write_all(&response.body);
                } else {
                    stream.write_all(&response.body).expect("response body");
                }
            }
        });
        Self {
            port,
            requests,
            stop,
            worker: Some(worker),
            read_response,
            read_pause,
        }
    }

    fn pause_next_read(&self) -> (std::sync::mpsc::Sender<()>, Arc<AtomicBool>) {
        let (release, receive) = std::sync::mpsc::channel();
        let waiting = Arc::new(AtomicBool::new(false));
        *self.read_pause.lock().expect("pause") = Some(ReadPause {
            release: receive,
            waiting: Arc::clone(&waiting),
        });
        (release, waiting)
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.expect("provider");
            }
        }
    }
}

struct Case {
    _directory: tempfile::TempDir,
    store: TestAttempts,
    setup: RecoverySetup,
    provider: Provider,
    signed_source: Vec<Vec<u8>>,
    original: Vec<u8>,
    source_review: Value,
}
fn record(store: &TestAttempts, operation: &str) -> Vec<u8> {
    record_from(store.raw().as_ref(), operation)
}
fn record_from(store: &dyn crate::GatewayAttemptStore, operation: &str) -> Vec<u8> {
    let key = GatewayAttemptKey::for_operation(
        &crate::effect::fixture_policy().expect("policy"),
        author::recipe().namespace(),
        &LogicalOperationId::parse(operation).expect("operation"),
    )
    .expect("key");
    store
        .load(GatewayRecordKind::Attempt, &key)
        .expect("load")
        .expect("retained record")
}
fn signed_bytes(root: &Path, name: &str) -> Vec<Vec<u8>> {
    ["proof", "action", "approval"]
        .map(|suffix| std::fs::read(root.join(format!("{name}.{suffix}"))).expect("input"))
        .to_vec()
}
async fn prepare_negatives(engine: &GatewayEngine, root: &Path) {
    let write = author::signed(&author::write_call("forbidden-new-write"), false);
    let effect = engine
        .compile_effect(&write.proof, &write.action)
        .await
        .expect("writer initially authorized");
    retain(
        root,
        "forbidden-write",
        &write,
        &author::approval(&effect, NOW),
    );
    let call = engine
        .recovery_authorization_call(SOURCE, "forbidden-read")
        .await
        .expect("writer read call");
    let read = author::signed(&call, false);
    let effect = engine
        .compile_recovery_effect(SOURCE, &read.proof, &read.action)
        .await
        .expect("writer read initially authorized");
    retain(
        root,
        "forbidden-read",
        &read,
        &author::approval(&effect, NOW),
    );
}
async fn reject_withdrawn_writer(engine: &GatewayEngine, root: &Path) {
    let denial = GatewaySubmitResult::Denied {
        code: "untrusted-root".to_owned(),
    };
    let (proof, action, approval) = input(root, "forbidden-write");
    assert_eq!(engine.submit(&proof, &action, approval).await, denial);
    let (proof, action, approval) = input(root, "forbidden-read");
    assert_eq!(
        Box::pin(engine.recover(SOURCE, &proof, &action, approval))
            .await
            .expect_err("writer read withdrawn"),
        denial
    );
}
impl Case {
    fn start(backend: Backend, outcome: Outcome) -> Self {
        let directory = tempfile::tempdir().expect("directory");
        let root = std::fs::canonicalize(directory.path()).expect("canonical");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private mode");
        let store = TestAttempts::open(backend);
        let provider = Provider::start(outcome);
        let setup = RecoverySetup {
            installation: Setup {
                backend: backend.label().to_owned(),
                location: store.location(),
                root,
                provider_port: provider.port,
                barrier_port: 0,
            },
            outcome,
            reader: false,
        };
        let runtime = runtime();
        let (engine, connection) = runtime.block_on(load_controlled_engine(
            &setup.installation,
            "parent",
            store.attempts().clone(),
            controls(false),
        ));
        runtime
            .block_on(
                SharedConnection::new(
                    store.raw(),
                    connection.provider_kind().clone(),
                    connection.alias().clone(),
                )
                .insert(&connection),
            )
            .expect("connection");
        engine
            .initialize_effect_configuration()
            .expect("initial configuration");
        let signed = author::signed(&author::write_call(SOURCE), false);
        let original_trust = auths_codec::decode_verifier_context(&signed.context).expect("trust");
        crate::engine::verify_native(&original_trust, NOW + 1, &signed.proof, &signed.action)
            .expect("writer proof remains in time at the later recovery clock");
        let effect = runtime
            .block_on(engine.compile_effect(&signed.proof, &signed.action))
            .expect("source compilation");
        let source_review = serde_json::from_slice(
            &effect
                .private_review()
                .expect("review")
                .to_private_bytes()
                .expect("review bytes"),
        )
        .expect("JSON");
        let body = effect.private_request().expect("mutation").body().to_vec();
        let approval = author::approval(&effect, NOW);
        retain(&setup.installation.root, SOURCE, &signed, &approval);
        effect
            .approve(
                approval,
                crate::effect::fixture_policy().expect("policy").approver(),
                NOW + 1,
            )
            .expect("writer approval remains current at the recovery clock");
        let signed_source = signed_bytes(&setup.installation.root, SOURCE);
        Self::peer(&setup);
        let original = record(&store, SOURCE);
        runtime.block_on(prepare_negatives(&engine, &setup.installation.root));
        assert_eq!(
            provider.requests.lock().expect("capture").as_slice(),
            [Request {
                line: format!("PATCH {TARGET} HTTP/1.1"),
                body
            }]
        );
        Self {
            _directory: directory,
            store,
            setup,
            provider,
            signed_source,
            original,
            source_review,
        }
    }
    fn peer(setup: &RecoverySetup) {
        let path = setup.installation.root.join("peer-setup");
        private(&path, &serde_json::to_vec(setup).expect("setup"));
        Peer::start(
            &path,
            "native_recovery_actor_tests::native_recovery_actor_peer",
            PEER_ENV,
        )
        .finish();
    }
    fn execute(mut self) -> Value {
        let runtime = runtime();
        self.setup.reader = true;
        let (engine, _) = runtime.block_on(load_controlled_engine(
            &self.setup.installation,
            "operator",
            self.store.reopen(),
            controls(true),
        ));
        let review = engine
            .effect_configuration_revision()
            .expect("operator review");
        engine
            .activate_effect_configuration(review)
            .expect("withdraw writer root");
        assert_ne!(
            engine
                .effect_configuration_revision()
                .expect("current revision"),
            review
        );
        runtime.block_on(reject_withdrawn_writer(
            &engine,
            &self.setup.installation.root,
        ));
        assert_eq!(
            self.store
                .raw()
                .attempt_keys(100)
                .expect("attempt keys")
                .len(),
            1,
            "withdrawn writer creates no admission"
        );
        let call = runtime
            .block_on(engine.recovery_authorization_call(SOURCE, RECOVERY))
            .expect("read call");
        let writer_read = author::signed(&call, false);
        assert_eq!(
            runtime
                .block_on(engine.compile_recovery_effect(
                    SOURCE,
                    &writer_read.proof,
                    &writer_read.action
                ))
                .expect_err("withdrawn writer cannot read"),
            GatewaySubmitResult::Denied {
                code: "untrusted-root".to_owned()
            }
        );
        let reader = author::signed(&call, true);
        let effect = runtime
            .block_on(engine.compile_recovery_effect(SOURCE, &reader.proof, &reader.action))
            .expect("different native reader");
        let recovery_review: Value = serde_json::from_slice(
            &effect
                .private_review()
                .expect("review")
                .to_private_bytes()
                .expect("bytes"),
        )
        .expect("JSON");
        assert_eq!(
            self.source_review["native"]["actors"],
            json!([author::actor(false)])
        );
        assert_eq!(
            recovery_review["native"]["actors"],
            json!([author::actor(true)])
        );
        assert_ne!(author::actor(false), author::actor(true));
        assert_eq!(
            recovery_review["native"]["recovery"]["source_effect"],
            self.source_review["effect_id_hex"]
        );
        let approval = author::approval(&effect, NOW + 1);
        retain(&self.setup.installation.root, RECOVERY, &reader, &approval);
        let (_, _, source_approval) = input(&self.setup.installation.root, SOURCE);
        assert!(
            effect
                .approve(
                    source_approval,
                    crate::effect::fixture_policy().expect("policy").approver(),
                    NOW + 1
                )
                .is_err(),
            "writer approval is not independent recovery consent"
        );
        let signed_reader = signed_bytes(&self.setup.installation.root, RECOVERY);
        assert_eq!(
            engine.execution_witness().credential_lease_calls,
            0,
            "operator compilation never leases"
        );
        assert_eq!(self.provider.requests.lock().expect("capture").len(), 1);
        Self::peer(&self.setup);
        assert_eq!(
            signed_bytes(&self.setup.installation.root, RECOVERY),
            signed_reader
        );
        self.verify(&engine, &runtime)
    }
    fn verify(&self, engine: &GatewayEngine, runtime: &tokio::runtime::Runtime) -> Value {
        let load = |name| {
            serde_json::from_slice::<Value>(
                &std::fs::read(self.setup.installation.root.join(name)).expect("result"),
            )
            .expect("JSON")
        };
        let reader = load("reader-result");
        let first = &reader["first"];
        let expected = if self.setup.outcome.echo() {
            "observed-by-provider"
        } else if self.setup.outcome.responds() {
            "observed"
        } else {
            "unknown"
        };
        assert_eq!(first["source"]["stage"], expected);
        assert_eq!(
            first["source"]["provider_linked"],
            self.setup.outcome.echo()
        );
        assert_eq!(
            first["disposition"],
            if self.setup.outcome.echo() || self.setup.outcome.responds() {
                "recorded"
            } else {
                "inconclusive"
            }
        );
        assert_eq!(
            first["source"]["response_status"],
            if self.setup.outcome.responds() {
                json!(200)
            } else {
                Value::Null
            }
        );
        assert_eq!(first["acquisition"]["reserved_calls"], 1);
        assert_eq!(first["acquisition"]["reserved_bytes"], 16_384);
        assert_eq!(reader["execution"]["credential_lease_calls"], 1);
        assert_eq!(reader["execution"]["read_transport_entries"], 1);
        assert_eq!(reader["execution"]["write_transport_entries"], 0);
        {
            let requests = self.provider.requests.lock().expect("capture");
            assert_eq!(requests.len(), 2);
            assert_eq!(
                requests[1],
                Request {
                    line: format!("GET {TARGET} HTTP/1.1"),
                    body: Vec::new()
                }
            );
        }
        let after = record(&self.store, SOURCE);
        assert_fixed_source(&self.original, &after);
        let read = record(&self.store, RECOVERY);
        let (proof, action, approval) = input(&self.setup.installation.root, SOURCE);
        let result = runtime.block_on(engine.submit(&proof, &action, approval));
        match &result {
            GatewaySubmitResult::ObservedByProvider { status, .. } => {
                assert!(self.setup.outcome.echo());
                assert_eq!(*status, self.setup.outcome.responds().then_some(200));
            }
            GatewaySubmitResult::Observed { status, matched } => {
                assert!(self.setup.outcome.responds() && !self.setup.outcome.echo());
                assert_eq!((*status, *matched), (200, true));
            }
            GatewaySubmitResult::Unknown => {
                assert!(!self.setup.outcome.responds() && !self.setup.outcome.echo());
            }
            other => panic!("incorrect historical source projection: {other:?}"),
        }
        assert_eq!(record(&self.store, SOURCE), after);
        assert_eq!(record(&self.store, RECOVERY), read);
        assert_eq!(engine.execution_witness().credential_lease_calls, 0);
        assert_eq!(engine.execution_witness().read_transport_entries, 0);
        assert_eq!(engine.execution_witness().write_transport_entries, 0);
        assert_eq!(self.provider.requests.lock().expect("capture").len(), 2);
        assert_eq!(
            signed_bytes(&self.setup.installation.root, SOURCE),
            self.signed_source
        );
        let original: Value = serde_json::from_slice(&self.original).expect("original source");
        assert_eq!(
            original["state"]["facts"]["stage"],
            if self.setup.outcome.responds() {
                "response-recorded"
            } else {
                "unknown"
            }
        );
        json!({"outcome": self.setup.outcome, "writer_root_withdrawn_by_operator": true,
            "source_stage_before_recovery": original["state"]["facts"]["stage"],
            "writer_current_denial": "untrusted-root", "writer_actor": author::actor(false), "reader_actor": author::actor(true),
            "writer_proof_and_approval_still_in_time": true,
            "exact_reviewed_write_received": true, "provider_writes": 1, "provider_reads": 1,
            "source_identity_entry_charges_unchanged": true, "original_signed_bytes_unchanged": true,
            "recovery": first, "replay": reader["replay"], "historical_writer_replay_stage": expected,
            "replay_journals_and_execution_unchanged": true})
    }
}
fn assert_fixed_source(before: &[u8], after: &[u8]) {
    let decode = |bytes| serde_json::from_slice::<Value>(bytes).expect("record");
    let mut before = decode(before);
    let mut after = decode(after);
    for value in [&mut before, &mut after] {
        value.as_object_mut().expect("record").remove("revision");
        for field in [
            "stage",
            "observation_match",
            "observation_fact",
            "provider_evidence",
            "recovery_evidence",
        ] {
            value["state"]["facts"]
                .as_object_mut()
                .expect("mutation facts")
                .remove(field);
        }
    }
    assert_eq!(
        before, after,
        "only the supported recovery facts/revision may change"
    );
}
fn recovery_matrix(backend: Backend) {
    let cases: Vec<_> = [
        Outcome::ResponseEcho,
        Outcome::ResponseState,
        Outcome::LostEcho,
        Outcome::LostState,
    ]
    .into_iter()
    .map(|outcome| Case::start(backend, outcome).execute())
    .collect();
    let artifact = serde_json::to_vec_pretty(&json!({"schema":"auths.native-independent-recovery/1", "adapter": backend.label(),
        "scope":"real native writer and separate reader OS processes; exact approvals; operator trust activation withdraws writer root while retaining independent reader; maintained durable stores and local actual HTTP",
        "assumptions":["fixed public test keys and maintained clock", "trusted operator/host/stores and same UID", "provider double with no request deduplication"],
        "excluded":["signed principal/grant status service revocation", "production provider or human-presence qualification", "hostile OS containment and whole-store rollback"], "cases":cases})).expect("artifact");
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-independent-recovery-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("fixture");
    }
    assert_eq!(std::fs::read(path).expect("artifact"), artifact);
}
#[test]
fn native_file_independent_recovery_fixture_is_current() {
    recovery_matrix(Backend::File);
}
#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_independent_recovery_fixture_is_current() {
    assert!(postgres_configured());
    recovery_matrix(Backend::Postgres);
}
