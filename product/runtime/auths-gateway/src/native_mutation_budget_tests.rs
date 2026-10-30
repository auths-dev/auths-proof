//! Native final-unit mutation contention. One prefix and two independent OS
//! workers share actual file/TLS `PostgreSQL` state and a counting HTTP provider.
use super::*;
use crate::GatewayExecutionWitness;
use std::{collections::BTreeMap, net::TcpStream, time::Instant};

const OPERATIONS: [&str; 3] = ["mutation-prefix", "mutation-left", "mutation-right"];
const WORKER: &str = "AUTHS_AP074_MUTATION_WINDOW_PEER";
const WINDOW: u64 = 60;
const AMOUNT: u64 = 500;

#[path = "native_mutation_pg_batch_tests.rs"]
mod postgres_batch_tests;

#[path = "native_mutation_pg_commit_tests.rs"]
mod postgres_commit_tests;

#[derive(Clone, Copy)]
enum Limit {
    Count,
    Sum,
    Both,
}
impl Limit {
    const fn label(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::Sum => "amount-sum",
            Self::Both => "count-and-amount-sum",
        }
    }
    const fn sum(self) -> bool {
        !matches!(self, Self::Count)
    }
    const fn refusal(self) -> &'static str {
        if matches!(self, Self::Sum) {
            "gateway.policy.sum-exhausted"
        } else {
            "gateway.policy.window-exhausted"
        }
    }
    fn policy(self) -> ArgumentCeilingPolicy {
        let policy = ArgumentCeilingPolicy::new(
            "amount",
            AMOUNT,
            WINDOW,
            if matches!(self, Self::Sum) { 16 } else { 2 },
        )
        .expect("native count policy");
        if self.sum() {
            policy
                .with_sum(2 * AMOUNT, None)
                .expect("native amount sum")
        } else {
            policy
        }
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum WorkerMode {
    Contend,
    CrashAfterReservation,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerSetup {
    installation: Setup,
    operation: String,
    mode: WorkerMode,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerResult {
    process: u32,
    result: GatewaySubmitResult,
    witness: GatewayExecutionWitness,
}

async fn inputs(
    engine: &GatewayEngine,
    root: &Path,
    operation: &str,
    limit: Limit,
) -> Vec<Counter> {
    let base = Flavor::StripePlain.call();
    let mut arguments = base.arguments().clone();
    arguments.insert("operation_id".to_owned(), json!(operation));
    arguments.insert(
        "payment_intent".to_owned(),
        json!(format!("pi_{}", operation.replace('-', "_"))),
    );
    let call = McpToolCall::new(base.service(), base.name(), arguments).expect("native call");
    let signed = tool_fixture_in_window(&call, NOW, NOW - 10, NOW + 3600, Some(&limit.policy()))
        .expect("native bounded grant and proof");
    let effect = engine
        .compile_effect(&signed.proof, &signed.action)
        .await
        .expect("native effect");
    let binding: Value =
        serde_json::from_slice(&effect.binding().to_private_bytes().expect("binding"))
            .expect("binding JSON");
    let counters = binding["reservations"]
        .as_array()
        .expect("reservations")
        .iter()
        .map(|wire| {
            let kind = match wire["unit"].as_str().expect("unit") {
                "mutation-count" => GatewayRecordKind::CountSlot,
                "mutation-sum" => GatewayRecordKind::SumSlot,
                _ => panic!("wrong protocol unit"),
            };
            Counter {
                kind,
                digest: serde_json::from_value(wire["key"].clone()).expect("counter key"),
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(counters.len(), 1 + usize::from(limit.sum()));
    let request = effect
        .approval_request(NOW, NOW + 300)
        .expect("exact request");
    let signature = SigningKey::from_bytes(&[29; 32])
        .sign(&request.signing_message().expect("preimage"))
        .to_bytes();
    for (suffix, bytes) in [
        ("proof", signed.proof),
        ("action", signed.action),
        (
            "binding",
            effect
                .binding()
                .to_private_bytes()
                .expect("binding")
                .to_vec(),
        ),
        (
            "approval",
            request
                .with_signature(signature)
                .to_private_bytes()
                .expect("approval")
                .to_vec(),
        ),
    ] {
        private(&root.join(format!("{operation}.{suffix}")), &bytes);
    }
    private(
        &root.join(format!("{operation}.body")),
        effect.private_request().expect("mutation").body(),
    );
    counters
}

async fn execute(engine: &GatewayEngine, root: &Path, operation: &str) -> GatewaySubmitResult {
    let load =
        |suffix: &str| std::fs::read(root.join(format!("{operation}.{suffix}"))).expect("input");
    engine
        .submit(
            &load("proof"),
            &load("action"),
            ExactEffectApproval::from_private_bytes(&load("approval")).expect("native approval"),
        )
        .await
}

#[test]
fn native_mutation_window_peer() {
    let Some(input) = std::env::var_os(WORKER) else {
        return;
    };
    let setup: WorkerSetup =
        serde_json::from_slice(&std::fs::read(input).expect("setup")).expect("typed setup");
    assert!(OPERATIONS.contains(&setup.operation.as_str()));
    let store = TestAttempts::attach(
        Backend::parse(&setup.installation.backend),
        &setup.installation.location,
    );
    let operation = OPERATIONS
        .into_iter()
        .find(|value| *value == setup.operation)
        .expect("closed operation");
    let attempts = match setup.mode {
        WorkerMode::Contend => store.attempts().clone(),
        WorkerMode::CrashAfterReservation => {
            let policy = crate::effect::fixture_policy().expect("policy");
            let key = GatewayAttemptKey::for_operation(
                &policy,
                Flavor::StripePlain.recipe().namespace(),
                &LogicalOperationId::parse(operation).expect("operation"),
            )
            .expect("key");
            GatewayAttempts::new(
                Arc::new(PausedStore::new(
                    store.raw(),
                    key,
                    operation,
                    CrashProtocol::Mutation,
                    Some(Point::AfterReservationCommit),
                    setup.installation.barrier_port,
                )),
                policy,
            )
            .expect("paused owner")
        }
    };
    let runtime = runtime();
    let (engine, _) = runtime.block_on(load_controlled_engine(
        &setup.installation,
        &setup.operation,
        attempts,
        Flavor::StripePlain.controls(),
    ));
    if matches!(setup.mode, WorkerMode::Contend) {
        let mut signal =
            TcpStream::connect(("127.0.0.1", setup.installation.barrier_port)).expect("barrier");
        signal
            .set_read_timeout(Some(Duration::from_secs(15)))
            .expect("deadline");
        signal.write_all(b"R").expect("ready");
        let mut start = [0];
        signal.read_exact(&mut start).expect("release");
        assert_eq!(start, *b"G");
    }
    let result = WorkerResult {
        process: std::process::id(),
        result: runtime.block_on(execute(&engine, &setup.installation.root, &setup.operation)),
        witness: engine.execution_witness(),
    };
    private(
        &setup
            .installation
            .root
            .join(format!("{}.result", setup.operation)),
        &serde_json::to_vec(&result).expect("result"),
    );
}

fn release(barrier: &TcpListener) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut signals = Vec::new();
    while signals.len() < 2 {
        match barrier.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false).expect("blocking");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("deadline");
                let mut ready = [0];
                stream.read_exact(&mut ready).expect("ready");
                assert_eq!(ready, *b"R");
                signals.push(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "native worker readiness timeout");
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("barrier: {error}"),
        }
    }
    for mut signal in signals {
        signal.write_all(b"G").expect("release");
    }
}

fn contend(setup: &Setup, barrier: &TcpListener) -> Vec<WorkerResult> {
    let mut peers = Vec::new();
    for operation in &OPERATIONS[1..] {
        let input = setup.root.join(format!("{operation}.setup"));
        // Test setup is closed and separate from every production protocol.
        let worker: WorkerSetup = serde_json::from_value(
            json!({"installation":setup,"operation":operation,"mode":"contend"}),
        )
        .expect("setup");
        private(&input, &serde_json::to_vec(&worker).expect("setup"));
        peers.push(Peer::start(
            &input,
            "native_mutation_crash_tests::window_capacity_tests::native_mutation_window_peer",
            WORKER,
        ));
    }
    release(barrier);
    for peer in &mut peers {
        peer.finish();
    }
    let results = OPERATIONS[1..]
        .iter()
        .map(|operation| {
            serde_json::from_slice(
                &std::fs::read(setup.root.join(format!("{operation}.result"))).expect("result"),
            )
            .expect("worker result")
        })
        .collect::<Vec<WorkerResult>>();
    assert_ne!(results[0].process, results[1].process);
    assert!(
        results
            .iter()
            .all(|result| result.process != std::process::id())
    );
    assert_eq!(
        results
            .iter()
            .map(|result| result.witness.write_transport_entries)
            .sum::<u64>(),
        1
    );
    assert_eq!(
        results
            .iter()
            .map(|result| result.witness.credential_lease_calls)
            .sum::<u64>(),
        1
    );
    results
}

type Retained = Vec<(GatewayRecordKind, GatewayAttemptKey, Vec<u8>)>;
fn retained(store: &TestAttempts, counters: &[Counter], limit: Limit) -> Retained {
    let raw = store.raw();
    let keys = raw.attempt_keys(8).expect("keys");
    assert_eq!(keys.len(), 3);
    let mut retained = Vec::new();
    let mut grants = 0;
    for key in keys {
        let bytes = raw
            .load(GatewayRecordKind::Attempt, &key)
            .expect("load")
            .expect("record");
        let record: Value = serde_json::from_slice(&bytes).expect("record");
        let facts = &record["state"]["facts"];
        assert_eq!(record["state"]["protocol"], "mutation");
        if record["entry"].is_null() {
            assert_eq!(facts["stage"], "not-entered");
            assert_eq!(facts["refusal"], limit.refusal());
            assert!(facts["counters"].is_null(), "refusal owns no slot");
        } else {
            grants += 1;
            assert_eq!(facts["stage"], "response-recorded");
            assert_eq!(
                facts["counters"].as_array().expect("counters").len(),
                counters.len()
            );
        }
        retained.push((GatewayRecordKind::Attempt, key, bytes));
    }
    assert_eq!(grants, 2);
    for counter in counters {
        for slot in 0..2 {
            let key = counter.key(slot);
            let bytes = raw
                .load(counter.kind, &key)
                .expect("slot")
                .expect("present");
            let value: Value = serde_json::from_slice(&bytes).expect("slot");
            assert_eq!(value["window_seconds"], WINDOW);
            assert_eq!(value["window_index"], NOW / WINDOW);
            assert_eq!(value["window_end"], (NOW / WINDOW + 1) * WINDOW);
            assert_eq!(value["slot"], slot);
            assert!(OPERATIONS.contains(&value["operation_id"].as_str().expect("operation")));
            if counter.kind == GatewayRecordKind::SumSlot {
                assert_eq!(value["amount"], AMOUNT);
                assert_eq!(value["cumulative"], (slot + 1) * AMOUNT);
            }
            retained.push((counter.kind, key, bytes));
        }
        assert!(
            raw.load(counter.kind, &counter.key(2))
                .expect("no overflow")
                .is_none()
        );
    }
    retained
}

fn replay(
    setup: &Setup,
    store: &TestAttempts,
    provider: &Provider,
    results: &[GatewaySubmitResult],
    retained: &Retained,
    now: u64,
    expected_calls: usize,
) {
    let runtime = runtime();
    let controls = Flavor::StripePlain.controls();
    controls.clock.set(now);
    let (engine, _) = runtime.block_on(load_controlled_engine(
        setup,
        &format!("reopened-window-{now}"),
        store.reopen(),
        controls,
    ));
    let witness = engine.execution_witness();
    for (operation, expected) in OPERATIONS.iter().zip(results) {
        assert_eq!(
            &runtime.block_on(execute(&engine, &setup.root, operation)),
            expected
        );
    }
    assert_eq!(engine.execution_witness(), witness);
    assert_eq!(provider.calls(), expected_calls);
    for (kind, key, expected) in retained {
        assert_eq!(
            store.raw().load(*kind, key).expect("retained").as_ref(),
            Some(expected)
        );
    }
}

struct MutationRace {
    _directory: tempfile::TempDir,
    store: TestAttempts,
    provider: Provider,
    barrier: TcpListener,
    setup: Setup,
    runtime: tokio::runtime::Runtime,
    engine: GatewayEngine,
    clock: Arc<crate::FixedClock>,
}
impl MutationRace {
    fn new(backend: Backend) -> Self {
        let directory = tempfile::tempdir().expect("directory");
        let root = std::fs::canonicalize(directory.path()).expect("canonical");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("private");
        let store = TestAttempts::open(backend);
        let provider = Provider::new(Flavor::StripePlain, None);
        let barrier = TcpListener::bind("127.0.0.1:0").expect("barrier");
        barrier.set_nonblocking(true).expect("poll");
        let setup = Setup {
            backend: backend.label().to_owned(),
            location: store.location(),
            root,
            provider_port: provider.port,
            barrier_port: barrier.local_addr().expect("port").port(),
        };
        let runtime = runtime();
        let controls = Flavor::StripePlain.controls();
        let clock = controls.clock.clone();
        let (engine, connection) = runtime.block_on(load_controlled_engine(
            &setup,
            "window-parent",
            store.attempts().clone(),
            controls,
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
        engine.initialize_effect_configuration().expect("control");
        Self {
            _directory: directory,
            store,
            provider,
            barrier,
            setup,
            runtime,
            engine,
            clock,
        }
    }
    fn assert_current_authority_and_new_window(&self, operations: &[&str], expiry: u64) {
        for operation in operations {
            let load = |suffix: &str| {
                std::fs::read(self.setup.root.join(format!("{operation}.{suffix}")))
                    .expect("original input")
            };
            let binding = crate::effect::EffectBinding::from_private_bytes(&load("binding"))
                .expect("binding");
            let approval =
                ExactEffectApproval::from_private_bytes(&load("approval")).expect("approval");
            binding
                .validate_recorded_approval(&approval, expiry)
                .expect("original approval remains time eligible");
            let fresh = self
                .runtime
                .block_on(self.engine.compile_effect(&load("proof"), &load("action")))
                .expect("original native proof still authorized");
            assert_ne!(
                fresh.binding().id(),
                binding.id(),
                "window index is part of exact approval"
            );
            assert!(
                fresh
                    .approve(
                        approval,
                        &SigningKey::from_bytes(&[29; 32]).verifying_key().to_bytes(),
                        expiry
                    )
                    .is_err()
            );
        }
    }
    fn expiry_cleanup(&self, results: &[GatewaySubmitResult], retained: &Retained, limit: Limit) {
        let witness = self.engine.execution_witness();
        let expiry = (NOW / WINDOW + 2) * WINDOW;
        self.clock.set(expiry - 1);
        assert_eq!(
            self.runtime.block_on(self.engine.sweep_expired_slots()),
            Ok(0)
        );
        for (kind, key, bytes) in retained {
            assert_eq!(
                self.store
                    .raw()
                    .load(*kind, key)
                    .expect("before expiry")
                    .as_ref(),
                Some(bytes)
            );
        }
        self.clock.set(expiry);
        assert!(expiry < NOW + 300);
        self.assert_current_authority_and_new_window(&OPERATIONS, expiry);
        assert_eq!(
            self.runtime.block_on(self.engine.sweep_expired_slots()),
            Ok(2 + 2 * usize::from(limit.sum()))
        );
        let mut attempts = Vec::new();
        for (kind, key, bytes) in retained {
            let actual = self.store.raw().load(*kind, key).expect("after expiry");
            if *kind == GatewayRecordKind::Attempt {
                assert_eq!(
                    actual.as_ref(),
                    Some(bytes),
                    "retained full attempts are replay tombstones"
                );
                attempts.push((*kind, *key, bytes.clone()));
            } else {
                assert!(actual.is_none(), "only expired window slots were removed");
            }
        }
        assert_eq!(attempts.len(), 3);
        assert_eq!(
            self.engine.execution_witness(),
            witness,
            "maintenance grants no custody or transport access"
        );
        replay(
            &self.setup,
            &self.store,
            &self.provider,
            results,
            &attempts,
            expiry,
            2,
        );
    }
}

fn one_case(backend: Backend, limit: Limit) -> Value {
    let case = MutationRace::new(backend);
    let (store, provider, barrier, setup, runtime, engine) = (
        &case.store,
        &case.provider,
        &case.barrier,
        &case.setup,
        &case.runtime,
        &case.engine,
    );
    let mut expected = BTreeMap::new();
    let mut counters = Vec::new();
    for operation in OPERATIONS {
        let candidate = runtime.block_on(inputs(engine, &setup.root, operation, limit));
        assert!(
            counters.is_empty()
                || counters
                    .iter()
                    .zip(&candidate)
                    .all(
                        |(left, right): (&Counter, &Counter)| left.kind == right.kind
                            && left.digest == right.digest
                    )
        );
        counters = candidate;
        expected.insert(
            operation,
            std::fs::read(setup.root.join(format!("{operation}.body"))).expect("request"),
        );
    }
    let prefix = runtime.block_on(execute(engine, &setup.root, OPERATIONS[0]));
    assert_eq!(
        prefix,
        GatewaySubmitResult::ResponseRecorded { status: 200 }
    );
    assert_eq!(provider.calls(), 1);
    let contenders = contend(setup, barrier);
    assert_eq!(
        contenders
            .iter()
            .filter(|result| matches!(
                result.result,
                GatewaySubmitResult::ResponseRecorded { status: 200 }
            ))
            .count(),
        1
    );
    assert_eq!(contenders.iter().filter(|result| matches!(&result.result, GatewaySubmitResult::NotEntered { code } if code == limit.refusal())).count(), 1);
    let mut results = vec![prefix];
    results.extend(contenders.into_iter().map(|result| result.result));
    let requests = provider.requests.lock().expect("requests");
    assert_eq!(requests.len(), 2);
    for (operation, result) in OPERATIONS.iter().zip(&results) {
        if matches!(result, GatewaySubmitResult::ResponseRecorded { .. }) {
            assert_eq!(
                requests
                    .iter()
                    .filter(|request| request.body == expected[operation])
                    .count(),
                1,
                "each admitted exact body sent once"
            );
        }
    }
    drop(requests);
    let retained = retained(store, &counters, limit);
    replay(setup, store, provider, &results, &retained, NOW, 2);
    case.expiry_cleanup(&results, &retained, limit);
    json!({"limit":limit.label(), "window_seconds":WINDOW, "prefix":1, "contenders":2,
        "independent_worker_processes":true, "final_winners":1, "refusal_code":limit.refusal(),
        "durable_grants":2, "count_slots":2, "sum_slots":if limit.sum(){2}else{0},
        "amount_per_mutation":AMOUNT, "policy_sum_amount":if limit.sum(){Some(2*AMOUNT)}else{None},
        "actual_http_writes":2, "no_implicit_reads":true, "exact_admitted_bodies_once":true,
        "reopen_replay_preserves_attempt_and_counter_bytes":true,
        "reopen_replay_leases_and_sends_nothing":true,
        "expired_window_slots_removed":2+2*usize::from(limit.sum()),
        "terminal_attempts_unchanged_after_sweep":3, "original_proof_and_approval_time_still_current":true,
        "new_window_binding_requires_new_approval":true, "post_expiry_reopen_cannot_reenter_or_charge":true})
}

fn reserved_rows(case: &MutationRace, counters: &[Counter]) -> Retained {
    let raw = case.store.raw();
    let keys = raw.attempt_keys(4).expect("keys");
    assert_eq!(keys.len(), 1);
    let key = keys[0];
    let bytes = raw
        .load(GatewayRecordKind::Attempt, &key)
        .expect("load")
        .expect("reserved");
    let record: Value = serde_json::from_slice(&bytes).expect("record");
    assert_eq!(record["operation_id"], OPERATIONS[0]);
    assert!(record["entry"].is_null());
    assert_eq!(record["state"]["facts"]["stage"], "reserved");
    assert_eq!(record["revision"], 1);
    assert_eq!(
        record["state"]["facts"]["counters"]
            .as_array()
            .expect("counters")
            .len(),
        counters.len()
    );
    let mut rows = vec![(GatewayRecordKind::Attempt, key, bytes)];
    for counter in counters {
        let bytes = raw
            .load(counter.kind, &counter.key(0))
            .expect("slot")
            .expect("allocated");
        let value: Value = serde_json::from_slice(&bytes).expect("slot");
        assert_eq!(value["operation_id"], OPERATIONS[0]);
        assert_eq!(value["slot"], 0);
        if counter.kind == GatewayRecordKind::SumSlot {
            assert_eq!(value["cumulative"], AMOUNT);
        }
        assert!(
            raw.load(counter.kind, &counter.key(1))
                .expect("no second charge")
                .is_none()
        );
        rows.push((counter.kind, counter.key(0), bytes));
    }
    rows
}

fn reserved_case(backend: Backend, limit: Limit) -> Value {
    let case = MutationRace::new(backend);
    let operation = OPERATIONS[0];
    let counters = case
        .runtime
        .block_on(inputs(&case.engine, &case.setup.root, operation, limit));
    let input = case.setup.root.join("reserved-crash.setup");
    private(
        &input,
        &serde_json::to_vec(&json!({"installation":case.setup,"operation":operation,
        "mode":"crash-after-reservation"}))
        .expect("setup"),
    );
    let mut peer = Peer::start(
        &input,
        "native_mutation_crash_tests::window_capacity_tests::native_mutation_window_peer",
        WORKER,
    );
    let _paused = peer.await_pause(&case.barrier);
    peer.kill();
    assert_eq!(case.provider.calls(), 0);
    let retained = reserved_rows(&case, &counters);
    let permanent = retained
        .iter()
        .filter(|(kind, _, _)| *kind == GatewayRecordKind::Attempt)
        .cloned()
        .collect();
    let expiry = (NOW / WINDOW + 2) * WINDOW;
    let witness = case.engine.execution_witness();
    case.clock.set(expiry - 1);
    assert_eq!(
        case.runtime.block_on(case.engine.sweep_expired_slots()),
        Ok(0)
    );
    for (kind, key, bytes) in &retained {
        assert_eq!(
            case.store
                .raw()
                .load(*kind, key)
                .expect("retained")
                .as_ref(),
            Some(bytes)
        );
    }
    case.clock.set(expiry);
    assert!(expiry < NOW + 300);
    case.assert_current_authority_and_new_window(&[operation], expiry);
    assert_eq!(
        case.runtime.block_on(case.engine.sweep_expired_slots()),
        Ok(counters.len())
    );
    for counter in &counters {
        assert!(
            case.store
                .raw()
                .load(counter.kind, &counter.key(0))
                .expect("expired")
                .is_none()
        );
    }
    assert_eq!(case.engine.execution_witness(), witness);
    replay(
        &case.setup,
        &case.store,
        &case.provider,
        &[GatewaySubmitResult::Reserved { revision: 1 }],
        &permanent,
        expiry,
        0,
    );
    json!({"limit":limit.label(),"window_seconds":WINDOW,"actual_sigkill_after_reservation_ack":true,
        "durable_reservations":1,"entry_grants":0,"actual_http_writes":0,
        "expired_window_slots_removed":counters.len(),"original_proof_and_approval_time_still_current":true,
        "new_window_binding_requires_new_approval":true,"reserved_attempt_bytes_retained":true,
        "reopen_old_reserved_operation_cannot_enter_or_recharge":true})
}

fn matrix(backend: Backend) {
    let cases = [Limit::Count, Limit::Sum, Limit::Both]
        .into_iter()
        .map(|limit| one_case(backend, limit))
        .collect::<Vec<_>>();
    let reserved_cases = [Limit::Count, Limit::Sum, Limit::Both]
        .into_iter()
        .map(|limit| reserved_case(backend, limit))
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec_pretty(&json!({"schema":"auths.native-mutation-window-capacity/1", "adapter":backend.label(), "cases":cases,"reserved_cases":reserved_cases,
        "scope":"maintained plain Stripe native mutation recipe, full proof/exact approval, prefix and two independent OS contenders with separate custody; real file/TLS PostgreSQL transactions and counting HTTP; public fixture keys and controlled maintained clock",
        "excluded":["guarded/prerequisite Stripe", "disclosure contention", "new admission across windows", "unsupported whole-store rollback", "durability faults", "hostile OS and live-provider qualification"]})).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-mutation-window-capacity-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("fixture");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), bytes);
}
#[test]
fn native_file_mutation_window_capacity_fixture_is_current() {
    matrix(Backend::File);
}
#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_mutation_window_capacity_fixture_is_current() {
    assert!(postgres_configured());
    matrix(Backend::Postgres);
}
