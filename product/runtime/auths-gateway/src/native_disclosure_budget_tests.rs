//! Disclosure count/byte contention through actual native grants and local
//! recipient authentication. Each OS contender owns a gateway and recipient task;
//! same-UID sockets establish no hostile-process containment claim.
use super::*;
use crate::effect::ExactEffectApproval;
use crate::harness::authoring::tool_fixture_in_window;
use crate::{ArgumentCeilingPolicy, GatewayExecutionWitness, LogicalOperationId};
use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

const OPERATIONS: [&str; 3] = ["release-prefix", "release-left", "release-right"];
const WORKER: &str = "AUTHS_AP074_DISCLOSURE_WINDOW_PEER";
const WINDOW: u64 = 60;

#[derive(Clone, Copy)]
enum Limit {
    Count,
    Bytes,
    Both,
}
impl Limit {
    const fn label(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::Bytes => "byte-sum",
            Self::Both => "count-and-byte-sum",
        }
    }
    const fn sum(self) -> bool {
        !matches!(self, Self::Count)
    }
    const fn refusal(self) -> &'static str {
        if matches!(self, Self::Bytes) {
            "gateway.policy.sum-exhausted"
        } else {
            "gateway.policy.window-exhausted"
        }
    }
    fn policy(self) -> ArgumentCeilingPolicy {
        let policy = ArgumentCeilingPolicy::new(
            "maximum_disclosure_bytes",
            CONTENT.len() as u64,
            WINDOW,
            if matches!(self, Self::Bytes) { 16 } else { 2 },
        )
        .expect("native count");
        if self.sum() {
            policy
                .with_sum(CONTENT.len() as u64 * 2, None)
                .expect("native bytes")
        } else {
            policy
        }
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerSetup {
    installation: Setup,
    operation: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Delivery {
    snapshot: DisclosureSnapshot,
    recipient_bytes: u64,
    recipient_ack_sent: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerResult {
    process: u32,
    delivery: Delivery,
    witness: GatewayExecutionWitness,
}

fn channel(setup: &Setup) -> UnixDisclosurePolicy {
    let uid = std::fs::metadata(&setup.root).expect("owner").uid();
    UnixDisclosurePolicy::new(uid, uid, [57; 32])
}
async fn target(engine: &GatewayEngine, setup: &Setup, operation: &str) -> DisclosureTarget {
    let index = OPERATIONS
        .iter()
        .position(|value| *value == operation)
        .expect("closed operation");
    engine
        .disclosure_target(
            SOURCE,
            SigningKey::from_bytes(&[47; 32]).verifying_key().to_bytes(),
            channel(setup).commitment().expect("channel"),
            [u8::try_from(71 + index).expect("instance"); 32],
        )
        .await
        .expect("retained native source")
}
async fn inputs(
    engine: &GatewayEngine,
    setup: &Setup,
    operation: &'static str,
    limit: Limit,
) -> Charges {
    let target = target(engine, setup, operation).await;
    let call = target
        .authorization_call(
            &crate::native_process_tests::recipe(),
            &LogicalOperationId::parse(operation).expect("operation"),
        )
        .expect("native release call");
    let signed = tool_fixture_in_window(&call, NOW, NOW - 10, NOW + 3600, Some(&limit.policy()))
        .expect("bounded native proof");
    let effect = engine
        .compile_disclosure_effect(&target, &signed.proof, &signed.action)
        .await
        .expect("native effect");
    let request = effect
        .approval_request(NOW, NOW + 300)
        .expect("exact review");
    let signature = SigningKey::from_bytes(&[29; 32])
        .sign(&request.signing_message().expect("preimage"))
        .to_bytes();
    for (suffix, bytes) in [
        ("proof", signed.proof),
        ("action", signed.action),
        (
            "approval",
            request
                .with_signature(signature)
                .to_private_bytes()
                .expect("approval")
                .to_vec(),
        ),
        (
            "binding",
            effect
                .binding()
                .to_private_bytes()
                .expect("binding")
                .to_vec(),
        ),
    ] {
        private(&setup.root.join(format!("{operation}.{suffix}")), &bytes);
    }
    let charges = Charges::native(
        effect.binding(),
        operation,
        "disclosure-count",
        "disclosure-bytes",
        CONTENT.len() as u64,
    );
    assert_eq!(charges.fixed.len(), 1 + usize::from(limit.sum()));
    charges
}

async fn deliver(engine: &GatewayEngine, setup: &Setup, operation: &str) -> Delivery {
    let target = target(engine, setup, operation).await;
    let load = |suffix: &str| {
        std::fs::read(setup.root.join(format!("{operation}.{suffix}"))).expect("native input")
    };
    let binding = EffectBinding::from_private_bytes(&load("binding")).expect("expected binding");
    let approval =
        ExactEffectApproval::from_private_bytes(&load("approval")).expect("exact approval");
    let policy = channel(setup);
    let recipient = SigningKey::from_bytes(&[47; 32]);
    let (server, client) = UnixStream::pair().expect("actual local channel");
    let receiver = async {
        match crate::disclosure_transport::receive_disclosure(
            DisclosureConnection::new(client, policy.clone()),
            &binding,
            CONTENT.len() as u64,
            &recipient,
        )
        .await
        {
            Ok(received) => {
                assert_eq!(received.content(), CONTENT);
                let bytes = received.content().len() as u64;
                received
                    .acknowledge(&recipient)
                    .await
                    .expect("native exact ACK");
                (bytes, true)
            }
            Err(code) => {
                // Capacity refusal and retained replay close without a delivery.
                // Authentication/frame failures are never accepted as quota loss.
                assert_eq!(code, "gateway.disclosure.read");
                (0, false)
            }
        }
    };
    let proof = load("proof");
    let action = load("action");
    let (result, (recipient_bytes, recipient_ack_sent)) = tokio::join!(
        engine.disclose(
            &target,
            &proof,
            &action,
            approval,
            DisclosureConnection::new(server, policy.clone())
        ),
        receiver
    );
    Delivery {
        snapshot: result.expect("native retained disclosure facts"),
        recipient_bytes,
        recipient_ack_sent,
    }
}

#[test]
fn native_disclosure_window_peer() {
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
    let runtime = runtime();
    let (engine, _) = runtime.block_on(load_controlled_engine(
        &setup.installation,
        &setup.operation,
        store.attempts().clone(),
        controls(Gate::Current),
    ));
    let mut signal =
        TcpStream::connect(("127.0.0.1", setup.installation.barrier_port)).expect("barrier");
    signal
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("deadline");
    signal.write_all(b"R").expect("ready");
    let mut start = [0];
    signal.read_exact(&mut start).expect("release");
    assert_eq!(start, *b"G");
    let result = WorkerResult {
        process: std::process::id(),
        delivery: runtime.block_on(deliver(&engine, &setup.installation, &setup.operation)),
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
    let mut signals = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
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
                assert!(Instant::now() < deadline, "native worker timeout");
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("barrier: {error}"),
        }
    }
    for mut stream in signals {
        stream.write_all(b"G").expect("release");
    }
}
fn contend(setup: &Setup, barrier: &TcpListener) -> Vec<WorkerResult> {
    let mut peers = Vec::new();
    for operation in &OPERATIONS[1..] {
        let input = setup.root.join(format!("{operation}.setup"));
        private(
            &input,
            &serde_json::to_vec(&json!({"installation":setup,"operation":operation}))
                .expect("setup"),
        );
        peers.push(Peer::start(
            &input,
            "native_disclosure_crash_tests::window_capacity_tests::native_disclosure_window_peer",
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
    for result in &results {
        assert_eq!(result.witness.credential_lease_calls, 0);
        assert_eq!(result.witness.write_transport_entries, 0);
        assert_eq!(result.witness.read_transport_entries, 0);
    }
    results
}

type Retained = Vec<(GatewayRecordKind, GatewayAttemptKey, Vec<u8>)>;
fn retained(store: &TestAttempts, source: &Charges, releases: &Charges, limit: Limit) -> Retained {
    let raw = store.raw();
    let keys = raw.attempt_keys(8).expect("keys");
    assert_eq!(keys.len(), 4, "one source plus three release attempts");
    let mut retained = Vec::new();
    let mut acknowledged = 0;
    let mut refused = 0;
    for key in keys {
        let bytes = raw
            .load(GatewayRecordKind::Attempt, &key)
            .expect("load")
            .expect("attempt");
        let record: Value = serde_json::from_slice(&bytes).expect("record");
        if record["operation_id"] != SOURCE {
            assert_eq!(record["state"]["protocol"], "disclosure");
            let facts = &record["state"]["facts"];
            if record["entry"].is_null() {
                assert_eq!(facts["phase"]["stage"], "not-entered");
                assert_eq!(facts["phase"]["code"], limit.refusal());
                assert!(facts["allocation"].is_null());
                assert!(facts["counters"].as_array().expect("counters").is_empty());
                refused += 1;
            } else {
                assert_eq!(facts["phase"]["stage"], "acknowledged");
                assert_eq!(
                    facts["counters"].as_array().expect("counters").len(),
                    releases.fixed.len()
                );
                acknowledged += 1;
            }
        }
        retained.push((GatewayRecordKind::Attempt, key, bytes));
    }
    assert_eq!((acknowledged, refused), (2, 1));
    retained.extend(charge_rows(store, source, releases, 2));
    retained
}

fn charge_rows(
    store: &TestAttempts,
    source: &Charges,
    releases: &Charges,
    deliveries: u64,
) -> Retained {
    let raw = store.raw();
    let mut retained = Vec::new();
    let mut rows = vec![(GatewayRecordKind::EffectAllocation, source.lifetime, 1)];
    rows.push((
        GatewayRecordKind::EffectAllocation,
        releases.lifetime,
        deliveries,
    ));
    rows.extend(
        releases
            .fixed
            .iter()
            .map(|(kind, key)| (*kind, *key, deliveries)),
    );
    for (kind, digest, count) in rows {
        let derive = if kind == GatewayRecordKind::SumSlot {
            crate::bounds::sum_slot_key
        } else {
            crate::bounds::count_slot_key
        };
        for slot in 0..count {
            let key = GatewayAttemptKey::from_bytes(derive(&digest, slot));
            let bytes = raw.load(kind, &key).expect("charge").expect("present");
            let value: Value = serde_json::from_slice(&bytes).expect("charge");
            assert_eq!(value["slot"], slot);
            if kind == GatewayRecordKind::EffectAllocation {
                assert_eq!(value["calls"], 1);
                assert_eq!(
                    value["bytes"],
                    if digest == source.lifetime {
                        1024
                    } else {
                        CONTENT.len() as u64
                    }
                );
            } else {
                assert_eq!(value["window_seconds"], WINDOW);
                assert_eq!(value["window_index"], NOW / WINDOW);
                assert!(OPERATIONS.contains(&value["operation_id"].as_str().expect("operation")));
                if kind == GatewayRecordKind::SumSlot {
                    assert_eq!(value["amount"], CONTENT.len() as u64);
                    assert_eq!(value["cumulative"], (slot + 1) * CONTENT.len() as u64);
                }
            }
            retained.push((kind, key, bytes));
        }
        assert!(
            raw.load(kind, &GatewayAttemptKey::from_bytes(derive(&digest, count)))
                .expect("no overflow")
                .is_none()
        );
    }
    retained
}

struct DisclosureRace {
    _directory: tempfile::TempDir,
    setup: Setup,
    store: TestAttempts,
    provider: Provider,
    barrier: TcpListener,
    runtime: tokio::runtime::Runtime,
    engine: GatewayEngine,
    clock: Arc<crate::FixedClock>,
    source: Charges,
}
impl DisclosureRace {
    fn new(backend: Backend) -> Self {
        let directory = tempfile::tempdir().expect("directory");
        let root = std::fs::canonicalize(directory.path()).expect("canonical");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("private");
        let store = TestAttempts::open(backend);
        let provider = Provider::controlled(None);
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
        let controls = controls(Gate::Current);
        let clock = controls.clock.clone();
        let (engine, connection) = runtime.block_on(load_controlled_engine(
            &setup,
            "release-window-parent",
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
        let binding = runtime.block_on(kit::authorize_source(&engine));
        let source = Charges::native(
            &binding,
            SOURCE,
            "acquisition-count",
            "response-bytes",
            1024,
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        Self {
            _directory: directory,
            setup,
            store,
            provider,
            barrier,
            runtime,
            engine,
            clock,
            source,
        }
    }
    fn replay(&self, results: &[Delivery], retained: &Retained, now: u64) {
        let controls = controls(Gate::Current);
        controls.clock.set(now);
        let (engine, _) = self.runtime.block_on(load_controlled_engine(
            &self.setup,
            &format!("release-reopened-{now}"),
            self.store.reopen(),
            controls,
        ));
        let witness = engine.execution_witness();
        for (operation, expected) in OPERATIONS.iter().zip(results) {
            let actual = self
                .runtime
                .block_on(deliver(&engine, &self.setup, operation));
            assert_eq!(actual.snapshot, expected.snapshot);
            assert_eq!(
                (actual.recipient_bytes, actual.recipient_ack_sent),
                (0, false)
            );
        }
        assert_eq!(engine.execution_witness(), witness);
        assert_eq!(self.provider.calls.load(Ordering::SeqCst), 1);
        for (kind, key, bytes) in retained {
            assert_eq!(
                self.store
                    .raw()
                    .load(*kind, key)
                    .expect("retained")
                    .as_ref(),
                Some(bytes)
            );
        }
    }
    fn assert_current_authority_and_new_window(&self, operations: &[&str], expiry: u64) {
        for operation in operations {
            let load = |suffix: &str| {
                std::fs::read(self.setup.root.join(format!("{operation}.{suffix}")))
                    .expect("original input")
            };
            let binding = EffectBinding::from_private_bytes(&load("binding")).expect("binding");
            let approval =
                ExactEffectApproval::from_private_bytes(&load("approval")).expect("approval");
            binding
                .validate_recorded_approval(&approval, expiry)
                .expect("original approval remains time eligible");
            let target = self
                .runtime
                .block_on(target(&self.engine, &self.setup, operation));
            let fresh = self
                .runtime
                .block_on(self.engine.compile_disclosure_effect(
                    &target,
                    &load("proof"),
                    &load("action"),
                ))
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
    fn expiry_cleanup(&self, results: &[Delivery], retained: &Retained, limit: Limit) {
        let expiry = (NOW / WINDOW + 2) * WINDOW;
        let witness = self.engine.execution_witness();
        self.clock.set(expiry - 1);
        assert_eq!(
            self.runtime.block_on(self.engine.sweep_expired_slots()),
            Ok(0)
        );
        self.clock.set(expiry);
        assert!(expiry < NOW + 300);
        self.assert_current_authority_and_new_window(&OPERATIONS, expiry);
        assert_eq!(
            self.runtime.block_on(self.engine.sweep_expired_slots()),
            Ok(2 + 2 * usize::from(limit.sum()))
        );
        let mut permanent = Vec::new();
        for (kind, key, bytes) in retained {
            let actual = self.store.raw().load(*kind, key).expect("after cleanup");
            if matches!(
                kind,
                GatewayRecordKind::CountSlot | GatewayRecordKind::SumSlot
            ) {
                assert!(actual.is_none());
            } else {
                assert_eq!(actual.as_ref(), Some(bytes));
                permanent.push((*kind, *key, bytes.clone()));
            }
        }
        assert_eq!(self.engine.execution_witness(), witness);
        self.replay(results, &permanent, expiry);
    }
}

fn one_case(backend: Backend, limit: Limit) -> Value {
    let case = DisclosureRace::new(backend);
    let mut charges: Option<Charges> = None;
    for operation in OPERATIONS {
        let next = case
            .runtime
            .block_on(inputs(&case.engine, &case.setup, operation, limit));
        if let Some(previous) = &charges {
            assert_eq!(previous.lifetime, next.lifetime);
            assert_eq!(previous.fixed, next.fixed);
        }
        charges = Some(next);
    }
    let charges = charges.expect("native charges");
    let prefix = case
        .runtime
        .block_on(deliver(&case.engine, &case.setup, OPERATIONS[0]));
    assert_eq!(prefix.snapshot.stage, DisclosureStage::Acknowledged);
    assert_eq!(prefix.recipient_bytes, CONTENT.len() as u64);
    let contenders = contend(&case.setup, &case.barrier);
    assert_eq!(
        contenders
            .iter()
            .filter(|result| result.delivery.snapshot.stage == DisclosureStage::Acknowledged)
            .count(),
        1
    );
    assert_eq!(
        contenders
            .iter()
            .filter(|result| result.delivery.snapshot.stage == DisclosureStage::NotEntered)
            .count(),
        1
    );
    let mut results = vec![prefix];
    results.extend(contenders.into_iter().map(|result| result.delivery));
    assert_eq!(
        results
            .iter()
            .map(|result| result.recipient_bytes)
            .sum::<u64>(),
        CONTENT.len() as u64 * 2
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.recipient_ack_sent)
            .count(),
        2
    );
    assert_eq!(
        results
            .iter()
            .map(|result| result.snapshot.reserved_deliveries)
            .sum::<u64>(),
        2
    );
    assert_eq!(
        results
            .iter()
            .map(|result| result.snapshot.reserved_bytes)
            .sum::<u64>(),
        CONTENT.len() as u64 * 2
    );
    let retained = retained(&case.store, &case.source, &charges, limit);
    case.replay(&results, &retained, NOW);
    case.expiry_cleanup(&results, &retained, limit);
    json!({"limit":limit.label(),"window_seconds":WINDOW,"prefix":1,"contenders":2,"independent_worker_processes":true,
        "final_winners":1,"refusal_code":limit.refusal(),"recorded_acks":2,"reserved_deliveries":2,
        "recipient_released_bytes":CONTENT.len()*2,"reserved_bytes":CONTENT.len()*2,
        "count_slots":2,"sum_slots":if limit.sum(){2}else{0},"source_provider_reads":1,
        "disclosure_performs_no_provider_io_or_credential_lease":true,
        "reopen_replay_preserves_attempts_and_charges":true,"reopen_replay_releases_no_bytes_or_acks":true,
        "expired_window_slots_removed":2+2*usize::from(limit.sum()),
        "permanent_allocations_and_attempts_survive_cleanup":true,
        "original_proof_and_approval_time_still_current":true,"new_window_binding_requires_new_approval":true,"post_expiry_reopen_cannot_redeliver_or_charge":true})
}
fn reserved_rows(case: &DisclosureRace, releases: &Charges) -> Retained {
    let raw = case.store.raw();
    let keys = raw.attempt_keys(4).expect("keys");
    assert_eq!(keys.len(), 2);
    let mut rows = Vec::new();
    for key in keys {
        let bytes = raw
            .load(GatewayRecordKind::Attempt, &key)
            .expect("load")
            .expect("record");
        let record: Value = serde_json::from_slice(&bytes).expect("record");
        if record["operation_id"] != SOURCE {
            assert_eq!(record["operation_id"], OPERATIONS[0]);
            assert!(record["entry"].is_null());
            assert_eq!(record["state"]["facts"]["phase"]["stage"], "reserved");
            assert_eq!(record["state"]["facts"]["allocation"], 0);
            assert_eq!(
                record["state"]["facts"]["counters"]
                    .as_array()
                    .expect("counters")
                    .len(),
                releases.fixed.len()
            );
        }
        rows.push((GatewayRecordKind::Attempt, key, bytes));
    }
    rows.extend(charge_rows(&case.store, &case.source, releases, 1));
    rows
}

fn reserved_case(backend: Backend, limit: Limit) -> Value {
    let case = DisclosureRace::new(backend);
    let operation = OPERATIONS[0];
    let charges = case
        .runtime
        .block_on(inputs(&case.engine, &case.setup, operation, limit));
    let target = case
        .runtime
        .block_on(target(&case.engine, &case.setup, operation));
    let load = |suffix: &str| {
        std::fs::read(case.setup.root.join(format!("{operation}.{suffix}"))).expect("native input")
    };
    let witness = case.engine.execution_witness();
    let snapshot = case
        .runtime
        .block_on(case.engine.admit_disclosure(
            &target,
            &load("proof"),
            &load("action"),
            ExactEffectApproval::from_private_bytes(&load("approval")).expect("approval"),
        ))
        .expect("native admission ACK");
    assert_eq!(snapshot.stage, DisclosureStage::Reserved);
    assert_eq!(
        (snapshot.reserved_deliveries, snapshot.reserved_bytes),
        (1, CONTENT.len() as u64)
    );
    assert_eq!(case.engine.execution_witness(), witness);
    let retained = reserved_rows(&case, &charges);
    let permanent = retained
        .iter()
        .filter(|(kind, _, _)| {
            !matches!(
                kind,
                GatewayRecordKind::CountSlot | GatewayRecordKind::SumSlot
            )
        })
        .cloned()
        .collect();
    let expiry = (NOW / WINDOW + 2) * WINDOW;
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
                .expect("before expiry")
                .as_ref(),
            Some(bytes)
        );
    }
    case.clock.set(expiry);
    assert!(expiry < NOW + 300);
    case.assert_current_authority_and_new_window(&[operation], expiry);
    assert_eq!(
        case.runtime.block_on(case.engine.sweep_expired_slots()),
        Ok(charges.fixed.len())
    );
    for (kind, digest) in &charges.fixed {
        let key = GatewayAttemptKey::from_bytes(if *kind == GatewayRecordKind::CountSlot {
            crate::bounds::count_slot_key(digest, 0)
        } else {
            crate::bounds::sum_slot_key(digest, 0)
        });
        assert!(
            case.store
                .raw()
                .load(*kind, &key)
                .expect("expired")
                .is_none()
        );
    }
    assert_eq!(case.engine.execution_witness(), witness);
    case.replay(
        &[Delivery {
            snapshot,
            recipient_bytes: 0,
            recipient_ack_sent: false,
        }],
        &permanent,
        expiry,
    );
    json!({"limit":limit.label(),"window_seconds":WINDOW,"actual_native_reservation_ack":true,
        "entry_grants":0,"recipient_released_bytes":0,"source_provider_reads":1,
        "expired_window_slots_removed":charges.fixed.len(),"lifetime_rows_retained":2,
        "original_proof_and_approval_time_still_current":true,"new_window_binding_requires_new_approval":true,
        "reserved_attempt_and_allocation_bytes_retained":true,"reopen_cannot_redeliver_or_recharge":true})
}

fn matrix(backend: Backend) {
    let cases = [Limit::Count, Limit::Bytes, Limit::Both]
        .into_iter()
        .map(|limit| one_case(backend, limit))
        .collect::<Vec<_>>();
    let reserved_cases = [Limit::Count, Limit::Bytes, Limit::Both]
        .into_iter()
        .map(|limit| reserved_case(backend, limit))
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec_pretty(&json!({"schema":"auths.native-disclosure-window-capacity/1","adapter":backend.label(),"cases":cases,"reserved_cases":reserved_cases,
        "scope":"actual native proofs/exact approvals; prefix and two independent OS contenders, each hosting gateway and recipient tasks over real same-UID Unix sockets; file/TLS PostgreSQL and one real HTTP acquisition; fixed public test keys and controlled maintained clock",
        "excluded":["hostile recipient/OS containment", "independent gateway and recipient OS processes within each contender", "new admission across windows", "unsupported whole-store rollback", "durability faults", "live-provider qualification"]})).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-disclosure-window-capacity-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("fixture");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), bytes);
}
#[test]
fn native_file_disclosure_window_capacity_fixture_is_current() {
    matrix(Backend::File);
}
#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_disclosure_window_capacity_fixture_is_current() {
    assert!(postgres_configured());
    matrix(Backend::Postgres);
}
