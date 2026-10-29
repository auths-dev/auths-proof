//! Real native mutation SIGKILL schedules with both durable adapters. The
//! provider counts every received write; its idempotency header deduplicates
//! nothing, so a replay cannot hide a second native send behind provider logic.
use crate::effect::ExactEffectApproval;
use crate::harness::authoring::{tool_fixture_in_window, tools_context};
use crate::native_crash_tests::{CrashProtocol, PausedStore, Peer, Point, pause_at};
use crate::native_process_tests::{
    EngineControls, NOW, Setup, load_controlled_engine, private, runtime,
};
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::{
    ArgumentCeilingPolicy, CompiledRecipe, GatewayAttemptKey, GatewayAttemptSnapshot,
    GatewayAttempts, GatewayEngine, GatewayRecordKind, GatewaySubmitResult, LogicalOperationId,
    SharedConnection,
};
use auths_profile_mcp::McpToolCall;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const OPERATION: &str = "crash-write";
const RESPONSE: &[u8] = b"{\"id\":\"public-crash-response\"}";
const ENVIRONMENT: &str = "AUTHS_AP074_MUTATION_CRASH_PEER";

#[path = "native_mutation_budget_tests.rs"]
mod window_capacity_tests;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Flavor {
    Airtable,
    StripePlain,
}
impl Flavor {
    const fn label(self) -> &'static str {
        match self {
            Self::Airtable => "airtable",
            Self::StripePlain => "stripe-plain",
        }
    }
    fn recipe(self) -> CompiledRecipe {
        match self {
            Self::Airtable => CompiledRecipe::compile(
                include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json"),
                include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json"),
            )
            .expect("maintained Airtable recipe"),
            Self::StripePlain => {
                let corpus: Value = serde_json::from_slice(include_bytes!(
                    "../../../../bindings/fixtures/gateway/hostile-recipes-v2.json"
                ))
                .expect("maintained recipe corpus");
                let base = &corpus["bases"]["stripe-plain"];
                CompiledRecipe::compile(
                    &serde_json::to_vec(&base["recipe"]).expect("source"),
                    &serde_json::to_vec(&base["lock"]).expect("lock"),
                )
                .expect("closed Stripe recipe")
            }
        }
    }
    fn controls(self) -> EngineControls {
        let recipe = self.recipe();
        let call = McpToolCall::new(
            recipe.review().service(),
            recipe.review().tool(),
            serde_json::Map::new(),
        )
        .expect("tool");
        let mut controls = EngineControls::baseline();
        controls.trust = Some(tools_context(&[call], NOW).expect("native trust"));
        controls.recipe = Some(recipe);
        controls
    }
    fn call(self) -> McpToolCall {
        let recipe = self.recipe();
        let mut arguments = json!({"operation_id":OPERATION, "operator_namespace":recipe.namespace().as_str(), "recipe_digest":recipe.digest_hex()});
        match self {
            Self::Airtable => {
                arguments["record_id"] = json!("recTEST0000000001");
                arguments["replacement"] = json!("Approved");
            }
            Self::StripePlain => {
                arguments["payment_intent"] = json!("pi_public_crash_fixture");
                arguments["amount"] = json!(500);
            }
        }
        McpToolCall::new(
            recipe.review().service(),
            recipe.review().tool(),
            arguments.as_object().expect("arguments").clone(),
        )
        .expect("call")
    }
    fn policy(self) -> Option<ArgumentCeilingPolicy> {
        matches!(self, Self::StripePlain).then(|| {
            ArgumentCeilingPolicy::new("amount", 500, 3600, 2)
                .expect("count policy")
                .with_sum(1000, None)
                .expect("sum policy")
        })
    }
    const fn request_line(self) -> &'static str {
        match self {
            Self::Airtable => {
                "PATCH /v0/appTEST0000000001/tblTEST0000000001/recTEST0000000001 HTTP/1.1"
            }
            Self::StripePlain => "POST /v1/refunds HTTP/1.1",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ResumeGate {
    Current,
    ApprovalExpired,
    AuthorityExpired,
    Revoked,
    ConfigurationReplaced,
}
impl ResumeGate {
    const fn permits(self) -> bool {
        matches!(self, Self::Current)
    }
    const fn clock(self) -> u64 {
        match self {
            Self::ApprovalExpired => NOW + 301,
            Self::AuthorityExpired => NOW + 6,
            _ => NOW,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CrashSetup {
    installation: Setup,
    point: Point,
    flavor: Flavor,
    gate: ResumeGate,
}

#[derive(Debug, Eq, PartialEq)]
struct Request {
    body: Vec<u8>,
    idempotency: Option<String>,
}
struct Provider {
    port: u16,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    task: Option<JoinHandle<()>>,
}
impl Provider {
    fn new(flavor: Flavor, pause: Option<u16>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("provider");
        listener.set_nonblocking(true).expect("poll");
        let port = listener.local_addr().expect("address").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let task = thread::spawn(move || {
            let mut pause = pause;
            while !done.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("accept: {error}"),
                };
                stream.set_nonblocking(false).expect("blocking");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("deadline");
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .expect("deadline");
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    assert!(header.len() < 16384);
                    let mut byte = [0];
                    stream.read_exact(&mut byte).expect("header");
                    header.push(byte[0]);
                }
                let header = String::from_utf8(header).expect("header UTF8");
                assert_eq!(
                    header.lines().next(),
                    Some(flavor.request_line()),
                    "no implicit reads"
                );
                assert!(
                    header
                        .to_ascii_lowercase()
                        .contains("authorization: bearer public-native-process-fixture\r\n")
                );
                let value = |name: &str| {
                    header.lines().find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case(name)
                            .then(|| value.trim().to_owned())
                    })
                };
                let length: usize = value("content-length")
                    .expect("body length")
                    .parse()
                    .expect("length");
                assert!(length <= 65536);
                let mut body = vec![0; length];
                stream.read_exact(&mut body).expect("body");
                captured.lock().expect("requests").push(Request {
                    body,
                    idempotency: value("idempotency-key"),
                });
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",RESPONSE.len()).as_bytes()).expect("response header");
                if let Some(port) = pause.take() {
                    stream.write_all(&RESPONSE[..1]).expect("partial response");
                    pause_at(port);
                    let _ = stream.write_all(&RESPONSE[1..]);
                } else {
                    stream.write_all(RESPONSE).expect("response body");
                }
            }
        });
        Self {
            port,
            requests,
            stop,
            task: Some(task),
        }
    }
    fn calls(&self) -> usize {
        self.requests.lock().expect("requests").len()
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(task) = self.task.take() {
            let result = task.join();
            if !thread::panicking() {
                result.expect("provider task");
            }
        }
    }
}

fn key(flavor: Flavor) -> GatewayAttemptKey {
    GatewayAttemptKey::for_operation(
        &crate::effect::fixture_policy().expect("policy"),
        flavor.recipe().namespace(),
        &LogicalOperationId::parse(OPERATION).expect("operation"),
    )
    .expect("key")
}

async fn submit(engine: &GatewayEngine, root: &Path) -> GatewaySubmitResult {
    let proof = std::fs::read(root.join("write.proof")).expect("proof");
    let action = std::fs::read(root.join("write.action")).expect("action");
    let approval = ExactEffectApproval::from_private_bytes(
        &std::fs::read(root.join("write.approval")).expect("approval"),
    )
    .expect("canonical approval");
    engine.submit(&proof, &action, approval).await
}

#[test]
fn native_mutation_crash_peer() {
    let Some(path) = std::env::var_os(ENVIRONMENT) else {
        return;
    };
    let setup: CrashSetup =
        serde_json::from_slice(&std::fs::read(path).expect("setup")).expect("typed setup");
    let attached = TestAttempts::attach(
        Backend::parse(&setup.installation.backend),
        &setup.installation.location,
    );
    let wrapped = Arc::new(PausedStore::new(
        attached.raw(),
        key(setup.flavor),
        OPERATION,
        CrashProtocol::Mutation,
        Some(setup.point),
        setup.installation.barrier_port,
    ));
    let attempts = GatewayAttempts::new(wrapped, crate::effect::fixture_policy().expect("policy"))
        .expect("attempts");
    let runtime = runtime();
    let (engine, _) = runtime.block_on(load_controlled_engine(
        &setup.installation,
        "mutation-crash-peer",
        attempts,
        setup.flavor.controls(),
    ));
    let result = runtime.block_on(submit(&engine, &setup.installation.root));
    private(
        &setup.installation.root.join("caller-result.json"),
        &serde_json::to_vec(&result).expect("result"),
    );
    panic!("native mutation worker completed before scheduled SIGKILL: {result:?}");
}

struct Authorization {
    request: Request,
    counters: Vec<Counter>,
}
struct Counter {
    kind: GatewayRecordKind,
    digest: [u8; 32],
}
impl Counter {
    fn key(&self, slot: u64) -> GatewayAttemptKey {
        GatewayAttemptKey::from_bytes(match self.kind {
            GatewayRecordKind::CountSlot => crate::bounds::count_slot_key(&self.digest, slot),
            GatewayRecordKind::SumSlot => crate::bounds::sum_slot_key(&self.digest, slot),
            _ => panic!("not a native fixed-window counter"),
        })
    }
}
async fn authorize(engine: &GatewayEngine, setup: &CrashSetup) -> Authorization {
    let signed = tool_fixture_in_window(
        &setup.flavor.call(),
        NOW,
        NOW - 10,
        if matches!(setup.gate, ResumeGate::AuthorityExpired) {
            NOW + 5
        } else {
            NOW + 3600
        },
        setup.flavor.policy().as_ref(),
    )
    .expect("native proof");
    let effect = engine
        .compile_effect(&signed.proof, &signed.action)
        .await
        .expect("native effect");
    let request = effect.private_request().expect("mutation");
    let request = Request {
        body: request.body().to_vec(),
        idempotency: request.idempotency_key().map(str::to_owned),
    };
    let binding: Value =
        serde_json::from_slice(&effect.binding().to_private_bytes().expect("binding"))
            .expect("native binding");
    let counters = binding["reservations"]
        .as_array()
        .expect("native reservations")
        .iter()
        .map(|reservation| {
            let kind = match reservation["unit"].as_str().expect("unit") {
                "mutation-count" => GatewayRecordKind::CountSlot,
                "mutation-sum" => GatewayRecordKind::SumSlot,
                _ => panic!("wrong protocol reservation"),
            };
            Counter {
                kind,
                digest: serde_json::from_value(reservation["key"].clone()).expect("counter digest"),
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        counters.len(),
        if matches!(setup.flavor, Flavor::StripePlain) {
            2
        } else {
            0
        }
    );
    let approval = effect
        .approval_request(NOW, NOW + 300)
        .expect("exact review");
    let signature = SigningKey::from_bytes(&[29; 32])
        .sign(&approval.signing_message().expect("preimage"))
        .to_bytes();
    for (name, bytes) in [
        ("write.proof", signed.proof),
        ("write.action", signed.action),
        (
            "write.approval",
            approval
                .with_signature(signature)
                .to_private_bytes()
                .expect("approval")
                .to_vec(),
        ),
    ] {
        private(&setup.installation.root.join(name), &bytes);
    }
    Authorization { request, counters }
}

struct Case {
    _directory: tempfile::TempDir,
    store: TestAttempts,
    setup: CrashSetup,
    listener: TcpListener,
    provider: Provider,
    runtime: tokio::runtime::Runtime,
    authorization: Authorization,
}
impl Case {
    fn new(backend: Backend, flavor: Flavor, point: Point, gate: ResumeGate) -> Self {
        let directory = tempfile::tempdir().expect("private directory");
        let root = std::fs::canonicalize(directory.path()).expect("canonical");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("private");
        let store = TestAttempts::open(backend);
        let listener = TcpListener::bind("127.0.0.1:0").expect("control");
        listener.set_nonblocking(true).expect("poll");
        let port = listener.local_addr().expect("address").port();
        let provider = Provider::new(
            flavor,
            matches!(point, Point::DuringResponse).then_some(port),
        );
        let setup = CrashSetup {
            flavor,
            point,
            gate,
            installation: Setup {
                backend: backend.label().to_owned(),
                location: store.location(),
                root,
                provider_port: provider.port,
                barrier_port: port,
            },
        };
        let runtime = runtime();
        let (engine, record) = runtime.block_on(load_controlled_engine(
            &setup.installation,
            "parent",
            store.attempts().clone(),
            flavor.controls(),
        ));
        let shared = SharedConnection::new(
            store.raw(),
            record.provider_kind().clone(),
            record.alias().clone(),
        );
        runtime
            .block_on(shared.insert(&record))
            .expect("connection");
        engine
            .initialize_effect_configuration()
            .expect("configuration");
        let authorization = runtime.block_on(authorize(&engine, &setup));
        assert_eq!(provider.calls(), 0);
        Self {
            _directory: directory,
            store,
            setup,
            listener,
            provider,
            runtime,
            authorization,
        }
    }
    fn raw(&self) -> Option<Vec<u8>> {
        self.store
            .raw()
            .load(GatewayRecordKind::Attempt, &key(self.setup.flavor))
            .expect("native record")
    }
    fn crash(&self) {
        let input = self
            .setup
            .installation
            .root
            .join("mutation-crash-setup.json");
        private(&input, &serde_json::to_vec(&self.setup).expect("setup"));
        let mut peer = Peer::start(
            &input,
            "native_mutation_crash_tests::native_mutation_crash_peer",
            ENVIRONMENT,
        );
        let mut paused = peer.await_pause(&self.listener);
        assert!(
            !self
                .setup
                .installation
                .root
                .join("caller-result.json")
                .exists()
        );
        peer.kill();
        if matches!(self.setup.point, Point::DuringResponse) {
            paused
                .write_all(b"G")
                .expect("release provider after SIGKILL");
        }
        assert_eq!(self.provider.calls(), self.setup.point.provider_calls());
    }
    fn history(&self, attempts: &GatewayAttempts) -> Option<GatewayAttemptSnapshot> {
        self.runtime
            .block_on(attempts.read(
                self.setup.flavor.recipe().namespace(),
                &LogicalOperationId::parse(OPERATION).expect("operation"),
            ))
            .expect("history")
    }
    fn slots(&self, present: bool) -> Vec<Vec<u8>> {
        self.authorization
            .counters
            .iter()
            .filter_map(|counter| {
                let raw = self.store.raw();
                let bytes = raw.load(counter.kind, &counter.key(0)).expect("slot");
                assert_eq!(
                    bytes.is_some(),
                    present,
                    "claim and slots commit all-or-none"
                );
                assert!(
                    raw.load(counter.kind, &counter.key(1))
                        .expect("no second charge")
                        .is_none()
                );
                bytes.inspect(|bytes| {
                    let value: Value = serde_json::from_slice(bytes).expect("native slot");
                    assert_eq!(value["operation_id"], OPERATION);
                    assert_eq!(value["slot"], 0);
                    assert_eq!(value["window_seconds"], 3600);
                    assert_eq!(value["window_index"], NOW / 3600);
                    if counter.kind == GatewayRecordKind::SumSlot {
                        assert_eq!(value["amount"], 500);
                        assert_eq!(value["cumulative"], 500);
                    }
                })
            })
            .collect()
    }
    fn before(&self, bytes: Option<&[u8]>) {
        let expected = match self.setup.point {
            Point::BeforeReservationCommit => None,
            Point::AfterReservationCommit | Point::BeforeEntryCommit => Some("reserved"),
            Point::AfterEntryCommit | Point::DuringResponse | Point::BeforeResponseCommit => {
                Some("entry-granted")
            }
            Point::AfterResponseCommit => Some("response-recorded"),
            Point::BeforeAcknowledgementCommit | Point::AfterAcknowledgementCommit => {
                panic!("ACK points are not mutation crash schedules")
            }
        };
        let phase =
            bytes.map(|bytes| PausedStore::phase_for(CrashProtocol::Mutation, OPERATION, bytes));
        assert_eq!(phase.as_deref(), expected);
        assert_eq!(
            self.store.raw().attempt_keys(8).expect("keys").len(),
            usize::from(bytes.is_some())
        );
        if let Some(snapshot) = self.history(&self.store.reopen()) {
            assert_eq!(snapshot.evaluated_at(), NOW);
            assert_eq!(snapshot.counters().len(), self.authorization.counters.len());
            assert!(snapshot.counters().iter().all(|counter| counter.slot == 0));
            assert_eq!(
                crate::engine::stored_result(&snapshot),
                match self.setup.point {
                    Point::AfterReservationCommit | Point::BeforeEntryCommit =>
                        GatewaySubmitResult::Reserved {
                            revision: snapshot.revision()
                        },
                    Point::AfterResponseCommit =>
                        GatewaySubmitResult::ResponseRecorded { status: 200 },
                    _ => GatewaySubmitResult::Unknown,
                }
            );
        } else {
            assert!(bytes.is_none());
        }
    }
    fn reopened_engine(&self) -> GatewayEngine {
        let mut controls = self.setup.flavor.controls();
        controls.clock.set(self.setup.gate.clock());
        if matches!(self.setup.gate, ResumeGate::ConfigurationReplaced) {
            controls.policy = crate::effect::EffectPolicy::new(
                "test-partition".to_owned(),
                1,
                SigningKey::from_bytes(&[30; 32]).verifying_key().to_bytes(),
            )
            .expect("replacement policy");
        }
        let attempts = GatewayAttempts::new(self.store.reopen().store(), controls.policy.clone())
            .expect("reopened policy");
        let (engine, _) = self.runtime.block_on(load_controlled_engine(
            &self.setup.installation,
            "reopened",
            attempts,
            controls,
        ));
        match self.setup.gate {
            ResumeGate::Revoked => {
                self.runtime
                    .block_on(engine.revoke_connection())
                    .expect("native revocation");
            }
            ResumeGate::ConfigurationReplaced => {
                let revision = engine
                    .effect_configuration_revision()
                    .expect("configuration review");
                engine
                    .activate_effect_configuration(revision)
                    .expect("native configuration CAS");
            }
            _ => {}
        }
        engine
    }
    fn expected_result(&self, before: Option<&[u8]>) -> GatewaySubmitResult {
        if !self.setup.gate.permits() {
            assert!(matches!(
                self.setup.point,
                Point::AfterReservationCommit | Point::BeforeEntryCommit
            ));
            let record: Value =
                serde_json::from_slice(before.expect("prior reservation")).expect("journal");
            assert_eq!(record["state"]["facts"]["stage"], "reserved");
            return GatewaySubmitResult::Reserved {
                revision: record["revision"].as_u64().expect("revision"),
            };
        }
        if self.setup.point.resumable() || matches!(self.setup.point, Point::AfterResponseCommit) {
            GatewaySubmitResult::ResponseRecorded { status: 200 }
        } else {
            GatewaySubmitResult::Unknown
        }
    }
    fn may_continue(&self) -> bool {
        self.setup.point.resumable() && self.setup.gate.permits()
    }
    fn reopen(&self) -> Value {
        let before = self.raw();
        self.before(before.as_deref());
        let slots = self.slots(before.is_some());
        let engine = self.reopened_engine();
        let witness = engine.execution_witness();
        let result = self
            .runtime
            .block_on(submit(&engine, &self.setup.installation.root));
        assert_eq!(result, self.expected_result(before.as_deref()));
        let after = self.raw().expect("retained record");
        let after_slots = self.slots(true);
        if before.is_some() {
            assert_eq!(
                slots, after_slots,
                "retained charges are neither refunded nor repeated"
            );
        }
        if self.may_continue() {
            let resumed = engine.execution_witness();
            assert_eq!(
                resumed.credential_lease_calls - witness.credential_lease_calls,
                1
            );
            assert_eq!(
                resumed.write_transport_entries - witness.write_transport_entries,
                1
            );
            assert_eq!(
                resumed.read_transport_entries - witness.read_transport_entries,
                0
            );
        } else {
            assert_eq!(
                engine.execution_witness(),
                witness,
                "lost grant cannot reacquire custody or send"
            );
            assert_eq!(before.as_deref(), Some(after.as_slice()));
        }
        let witness = engine.execution_witness();
        assert_eq!(
            self.runtime
                .block_on(submit(&engine, &self.setup.installation.root)),
            result
        );
        assert_eq!(engine.execution_witness(), witness);
        assert_eq!(self.raw().expect("retained"), after);
        assert_eq!(self.slots(true), after_slots);
        let calls = if self.may_continue() {
            1
        } else {
            self.setup.point.provider_calls()
        };
        assert_eq!(self.provider.calls(), calls);
        assert!(
            self.provider
                .requests
                .lock()
                .expect("requests")
                .iter()
                .all(|request| request == &self.authorization.request),
            "all actual writes match the original native review, including declared idempotency"
        );
        let history = self.history(&self.store.reopen()).expect("history");
        assert_eq!(history.counters().len(), self.authorization.counters.len());
        assert_eq!(history.evaluated_at(), NOW);
        json!({"recipe":self.setup.flavor.label(), "pause":self.setup.point, "sigkill":true, "resume_gate":self.setup.gate,
            "provider_writes_at_kill":self.setup.point.provider_calls(), "native_result_after_reopen":result,
            "prior_grant_absent":self.setup.point.resumable(), "continued_after_fresh_authorization":self.may_continue(), "provider_writes_after_replays":calls,
            "native_count_slots":usize::from(matches!(self.setup.flavor, Flavor::StripePlain)),
            "native_sum_units":if matches!(self.setup.flavor, Flavor::StripePlain) { 500 } else { 0 },
            "same_reviewed_request_and_declared_idempotency":true,
            "subsequent_replays_leave_journal_slots_and_execution_witness_unchanged":true})
    }
}

fn matrix(backend: Backend) {
    let mut cases = Vec::new();
    for flavor in [Flavor::Airtable, Flavor::StripePlain] {
        for point in Point::ALL {
            eprintln!(
                "native mutation SIGKILL: {}/{flavor:?}/{point:?}",
                backend.label()
            );
            let case = Case::new(backend, flavor, point, ResumeGate::Current);
            case.crash();
            cases.push(case.reopen());
        }
        for point in [Point::AfterReservationCommit, Point::BeforeEntryCommit] {
            for gate in [
                ResumeGate::ApprovalExpired,
                ResumeGate::AuthorityExpired,
                ResumeGate::Revoked,
                ResumeGate::ConfigurationReplaced,
            ] {
                eprintln!(
                    "native mutation reserved continuation: {}/{flavor:?}/{point:?}/{gate:?}",
                    backend.label()
                );
                let case = Case::new(backend, flavor, point, gate);
                case.crash();
                cases.push(case.reopen());
            }
        }
    }
    let artifact = serde_json::to_vec_pretty(&json!({"schema":"auths.native-mutation-process-crash/1", "adapter":backend.label(),
        "scope":"full native mutation verification/approval, separate OS workers and custody, maintained Airtable and closed Stripe-plain recipe data, real local HTTP, actual adapter commit boundaries; fixed public keys and maintained clock",
        "excluded":["full Stripe guard/prerequisite schedules", "disclosure schedules", "mid-upload socket/backpressure faults", "device/power failure and whole-store rollback", "live provider qualification and hostile OS/human-presence guarantees"], "cases":cases})).expect("artifact");
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-mutation-process-crash-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("write");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), artifact);
}
#[test]
fn native_file_mutation_process_crash_fixture_is_current() {
    matrix(Backend::File);
}
#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_mutation_process_crash_fixture_is_current() {
    assert!(postgres_configured());
    matrix(Backend::Postgres);
}
