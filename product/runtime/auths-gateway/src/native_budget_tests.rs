//! Native fixed-window acquisition admission over independent processes.
//! Real proof verification, exact approval, adapter transactions and HTTP;
//! public fixture keys and a controlled maintained test clock are explicit.
use crate::native_process_tests::{
    NOW, Provider, Setup, acquire, authorize_policy, finish_peer, load_engine, private, recipe,
    runtime, start_peer,
};
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::{
    AcquisitionSnapshot, AcquisitionStage, ArgumentCeilingPolicy, GatewayAttemptKey,
    GatewayRecordKind, GatewaySubmitResult, LogicalOperationId, SharedConnection,
};
use serde_json::{Value, json};
use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};

const OPERATIONS: [&str; 3] = ["window-prefix", "window-left", "window-right"];
const WINDOW: u64 = 3_600;
const MAXIMUM: u64 = 1_024;
type StoredRecord = (GatewayRecordKind, GatewayAttemptKey, Vec<u8>);

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
    const fn has_sum(self) -> bool {
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
        let bound = ArgumentCeilingPolicy::new(
            "maximum_response_bytes",
            MAXIMUM,
            WINDOW,
            if matches!(self, Self::Bytes) { 16 } else { 2 },
        )
        .expect("native count bound");
        if self.has_sum() {
            bound.with_sum(2 * MAXIMUM, None).expect("native sum bound")
        } else {
            bound
        }
    }
}

fn release(barrier: &TcpListener) {
    let mut signals = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    while signals.len() < 2 {
        match barrier.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false).expect("blocking");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("deadline");
                let mut ready = [0];
                stream.read_exact(&mut ready).expect("native peer ready");
                assert_eq!(ready, *b"R");
                signals.push(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "peer timeout");
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("barrier: {error}"),
        }
    }
    for signal in &mut signals {
        signal.write_all(b"G").expect("release native peer");
    }
}

fn records(store: &TestAttempts) -> Vec<StoredRecord> {
    let raw = store.raw();
    let keys = raw.attempt_keys(8).expect("keys");
    assert_eq!(keys.len(), 3, "one retained record per logical operation");
    keys.into_iter()
        .map(|key| {
            (
                GatewayRecordKind::Attempt,
                key,
                raw.load(GatewayRecordKind::Attempt, &key)
                    .expect("load")
                    .expect("record"),
            )
        })
        .collect()
}

fn check_counters(store: &TestAttempts, limit: Limit) -> Vec<StoredRecord> {
    let mut retained = records(store);
    let mut counts = 0;
    let mut sums = 0;
    let mut grants = 0;
    let mut refusals = 0;
    // Iterate a snapshot; append the actual shared counter records for replay
    // byte checks. All slot keys come from native recorded counter witnesses.
    for (_, _, bytes) in retained.clone() {
        let record: Value = serde_json::from_slice(&bytes).expect("native record");
        let counters = record["state"]["facts"]["counters"]
            .as_array()
            .expect("counter witnesses");
        if record["entry"].is_null() {
            assert_eq!(record["state"]["facts"]["phase"]["stage"], "not-entered");
            assert_eq!(record["state"]["facts"]["phase"]["code"], limit.refusal());
            assert!(counters.is_empty(), "refusal leaks no counter slot");
            assert!(record["state"]["facts"]["allocation"].is_null());
            refusals += 1;
            continue;
        }
        grants += 1;
        assert_eq!(counters.len(), 1 + usize::from(limit.has_sum()));
        for counter in counters {
            let digest: [u8; 32] = hex::decode(counter["counter"].as_str().expect("counter"))
                .expect("digest")
                .try_into()
                .expect("digest length");
            let slot = counter["slot"].as_u64().expect("slot");
            assert!(slot < 2, "only the two admitted slots exist");
            let (kind, key, beyond) = if counter["kind"] == "count" {
                counts += 1;
                (
                    GatewayRecordKind::CountSlot,
                    crate::bounds::count_slot_key(&digest, slot),
                    crate::bounds::count_slot_key(&digest, 2),
                )
            } else {
                assert_eq!(counter["kind"], "sum");
                sums += 1;
                (
                    GatewayRecordKind::SumSlot,
                    crate::bounds::sum_slot_key(&digest, slot),
                    crate::bounds::sum_slot_key(&digest, 2),
                )
            };
            let key = GatewayAttemptKey::from_bytes(key);
            let bytes = store
                .raw()
                .load(kind, &key)
                .expect("slot load")
                .expect("slot");
            let value: Value = serde_json::from_slice(&bytes).expect("native slot");
            assert_eq!(value["window_seconds"], WINDOW);
            assert_eq!(value["window_index"], NOW / WINDOW);
            assert_eq!(value["window_end"], (NOW / WINDOW + 1) * WINDOW);
            assert_eq!(value["operation_id"], record["operation_id"]);
            if kind == GatewayRecordKind::SumSlot {
                assert_eq!(value["amount"], MAXIMUM, "charge the full ceiling");
                assert_eq!(value["cumulative"], (slot + 1) * MAXIMUM);
            }
            assert!(
                store
                    .raw()
                    .load(kind, &GatewayAttemptKey::from_bytes(beyond))
                    .expect("no overflow")
                    .is_none()
            );
            retained.push((kind, key, bytes));
        }
    }
    assert_eq!((grants, refusals), (2, 1));
    assert_eq!((counts, sums), (2, if limit.has_sum() { 2 } else { 0 }));
    retained
}

fn contend(setup: &Setup, barrier: &TcpListener) -> Vec<AcquisitionSnapshot> {
    let input = setup.root.join("setup.json");
    private(&input, &serde_json::to_vec(setup).expect("setup"));
    let mut left = start_peer(&input, OPERATIONS[1]);
    let mut right = start_peer(&input, OPERATIONS[2]);
    assert_ne!(left.id(), right.id());
    release(barrier);
    finish_peer(&mut left);
    finish_peer(&mut right);
    let contenders: Vec<AcquisitionSnapshot> = OPERATIONS[1..]
        .iter()
        .map(|operation| {
            let result: Result<AcquisitionSnapshot, GatewaySubmitResult> = serde_json::from_slice(
                &std::fs::read(setup.root.join(format!("{operation}.result"))).expect("result"),
            )
            .expect("native result");
            result.expect("retained native facts")
        })
        .collect();
    assert_eq!(
        contenders
            .iter()
            .filter(|value| value.stage == AcquisitionStage::ResponseRecorded)
            .count(),
        1
    );
    assert_eq!(
        contenders
            .iter()
            .filter(|value| value.stage == AcquisitionStage::NotEntered)
            .count(),
        1
    );
    contenders
}

fn verify_replay(
    setup: &Setup,
    store: &TestAttempts,
    provider: &Provider,
    snapshots: &[AcquisitionSnapshot],
    retained: &[StoredRecord],
) {
    let runtime = runtime();
    let (reopened, _) = runtime.block_on(load_engine(setup, "reopened", store.reopen()));
    let witness = reopened.execution_witness();
    for (operation, expected) in OPERATIONS.iter().zip(snapshots) {
        assert_eq!(
            &runtime
                .block_on(acquire(&reopened, &setup.root, operation))
                .expect("replay"),
            expected
        );
    }
    assert_eq!(reopened.execution_witness(), witness);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    for (kind, key, expected) in retained {
        assert_eq!(
            &store
                .raw()
                .load(*kind, key)
                .expect("replay record")
                .expect("record"),
            expected
        );
    }
    // Every operation, including the refusal, retains its native replay key.
    let policy = crate::effect::fixture_policy().expect("policy");
    for operation in OPERATIONS {
        let key = GatewayAttemptKey::for_operation(
            &policy,
            recipe().namespace(),
            &LogicalOperationId::parse(operation).expect("operation"),
        )
        .expect("key");
        assert!(
            store
                .raw()
                .load(GatewayRecordKind::Attempt, &key)
                .expect("attempt")
                .is_some()
        );
    }
}

fn one_case(backend: Backend, limit: Limit) -> Value {
    let directory = tempfile::tempdir().expect("directory");
    let root = std::fs::canonicalize(directory.path()).expect("canonical");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("private");
    let store = TestAttempts::open(backend);
    let provider = Provider::controlled(None);
    let barrier = TcpListener::bind("127.0.0.1:0").expect("barrier");
    barrier.set_nonblocking(true).expect("nonblocking");
    let setup = Setup {
        backend: backend.label().to_owned(),
        location: store.location(),
        root: root.clone(),
        provider_port: provider.port,
        barrier_port: barrier.local_addr().expect("address").port(),
    };
    let runtime = runtime();
    let (engine, connection) =
        runtime.block_on(load_engine(&setup, "parent", store.attempts().clone()));
    let shared = SharedConnection::new(
        store.raw(),
        connection.provider_kind().clone(),
        connection.alias().clone(),
    );
    runtime
        .block_on(shared.insert(&connection))
        .expect("connection");
    engine
        .initialize_effect_configuration()
        .expect("configuration");
    for operation in OPERATIONS {
        runtime.block_on(authorize_policy(&engine, &root, operation, &limit.policy()));
    }
    let prefix = runtime
        .block_on(acquire(&engine, &root, OPERATIONS[0]))
        .expect("prefix");
    assert_eq!(prefix.stage, AcquisitionStage::ResponseRecorded);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    let mut contenders = contend(&setup, &barrier);
    contenders.insert(0, prefix);
    assert_eq!(
        contenders
            .iter()
            .map(|value| value.reserved_calls)
            .sum::<u64>(),
        2
    );
    assert_eq!(
        contenders
            .iter()
            .map(|value| value.reserved_bytes)
            .sum::<u64>(),
        2 * MAXIMUM
    );
    let retained = check_counters(&store, limit);
    verify_replay(&setup, &store, &provider, &contenders, &retained);
    json!({"limit":limit.label(),"window_seconds":WINDOW,"window_index":NOW/WINDOW,"prefix":1,"contenders":2,"final_winners":1,"refusal_code":limit.refusal(),"durable_grants":2,"reserved_calls":2,"reserved_bytes":2*MAXIMUM,"count_slots":2,"sum_slots":if limit.has_sum(){2}else{0},"actual_http_reads":2,"reopened_replay_preserves_attempt_and_counter_bytes":true,"reopened_replay_leases_and_sends_nothing":true})
}

fn matrix(backend: Backend) {
    let cases: Vec<_> = [Limit::Count, Limit::Bytes, Limit::Both]
        .into_iter()
        .map(|limit| one_case(backend, limit))
        .collect();
    let artifact = serde_json::to_vec_pretty(&json!({"schema":"auths.native-window-capacity/1","adapter":backend.label(),"scope":"full native acquisition engine; signed bounded grants, exact approval, separate native OS workers and local custody, actual common adapter transactions and HTTP; fixed public fixture keys and maintained test clock","excluded":["mutation/disclosure fixed-window contention","cross-window expiry and clock rollback","partial batch and durability faults","human review UI and hostile OS containment","provider qualification"],"cases":cases})).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-window-capacity-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("write");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), artifact);
}

#[test]
fn native_file_window_capacity_fixture_is_current() {
    matrix(Backend::File);
}
#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_window_capacity_fixture_is_current() {
    assert!(postgres_configured());
    matrix(Backend::Postgres);
}
