//! Real server exceptions in the native `PostgreSQL` admission batch.
//! Trigger/sequence fault controls live only in each owned test schema. The
//! shipping adapter and gateway decide and execute the actual transaction.
use crate::native_process_tests::{
    Provider, Setup, acquire, authorize_policy, finish_peer, load_engine, private, runtime,
    start_peer,
};
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::{
    AcquisitionSnapshot, AcquisitionStage, ArgumentCeilingPolicy, GatewayExecutionWitness,
    GatewaySubmitResult, SharedConnection,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt as _,
    path::Path,
    sync::atomic::Ordering,
    thread,
    time::{Duration, Instant},
};

const OPERATION: &str = "postgres-partial-batch";

pub(crate) fn ready(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match listener.accept() {
            Ok((mut signal, _)) => {
                signal.set_nonblocking(false).expect("blocking");
                signal
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("deadline");
                signal
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .expect("deadline");
                let mut marker = [0];
                signal.read_exact(&mut marker).expect("peer ready");
                assert_eq!(marker, *b"R");
                return signal;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "native peer deadline");
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("barrier: {error}"),
        }
    }
}
fn expected_counts(admitted: bool) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::from([
        ("connection".to_owned(), 1),
        ("effect-configuration".to_owned(), 1),
    ]);
    if admitted {
        for kind in ["attempt", "effect-allocation", "count-slot", "sum-slot"] {
            counts.insert(kind.to_owned(), 1);
        }
    }
    counts
}
fn signed_inputs(root: &Path) -> Vec<Vec<u8>> {
    ["proof", "action", "approval"]
        .map(|suffix| {
            std::fs::read(root.join(format!("{OPERATION}.{suffix}"))).expect("signed inputs")
        })
        .to_vec()
}

struct Case {
    _directory: tempfile::TempDir,
    store: TestAttempts,
    setup: Setup,
    provider: Provider,
    barrier: TcpListener,
    signed: Vec<Vec<u8>>,
}
impl Case {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("directory");
        let root = std::fs::canonicalize(directory.path()).expect("canonical");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("private");
        let store = TestAttempts::open(Backend::Postgres);
        let provider = Provider::controlled(None);
        let barrier = TcpListener::bind("127.0.0.1:0").expect("barrier");
        barrier.set_nonblocking(true).expect("nonblocking");
        let setup = Setup {
            backend: "postgres".to_owned(),
            location: store.location(),
            root,
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
        let policy = ArgumentCeilingPolicy::new("maximum_response_bytes", 1024, 3600, 4)
            .expect("count")
            .with_sum(4096, None)
            .expect("sum");
        runtime.block_on(authorize_policy(&engine, &setup.root, OPERATION, &policy));
        let signed = signed_inputs(&setup.root);
        assert_eq!(
            store.postgres_gateway_record_counts(),
            expected_counts(false)
        );
        Self {
            _directory: directory,
            store,
            setup,
            provider,
            barrier,
            signed,
        }
    }
    fn fail(&self, fail_at: u64) {
        let input = self.setup.root.join("setup.json");
        private(&input, &serde_json::to_vec(&self.setup).expect("setup"));
        let mut peer = start_peer(&input, OPERATION);
        let mut signal = ready(&self.barrier);
        // The child completed installation before the trigger is installed;
        // its next insert is the actual native admission batch.
        self.store.reject_postgres_batch_insert(fail_at);
        signal.write_all(b"G").expect("release peer");
        finish_peer(&mut peer);
        let result: Result<AcquisitionSnapshot, GatewaySubmitResult> = serde_json::from_slice(
            &std::fs::read(self.setup.root.join(format!("{OPERATION}.result"))).expect("result"),
        )
        .expect("native result");
        assert!(
            matches!(result, Err(GatewaySubmitResult::Indeterminate { ref code }) if code == "gateway.attempt.state-unavailable")
        );
        let witness: GatewayExecutionWitness = serde_json::from_slice(
            &std::fs::read(self.setup.root.join(format!("{OPERATION}.witness"))).expect("witness"),
        )
        .expect("native witness");
        assert_eq!(
            (
                witness.credential_lease_calls,
                witness.read_transport_entries,
                witness.write_transport_entries
            ),
            (0, 0, 0)
        );
        assert_eq!(self.provider.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            self.store.clear_postgres_batch_failure(),
            fail_at,
            "nontransactional server sequence proves the failed row prefix"
        );
        assert_eq!(
            self.store.postgres_gateway_record_counts(),
            expected_counts(false),
            "every earlier attempted row rolled back"
        );
        assert!(self.store.raw().attempt_keys(4).expect("keys").is_empty());
        assert_eq!(signed_inputs(&self.setup.root), self.signed);
    }
    fn reopen(&self, fail_at: u64) -> Value {
        let runtime = runtime();
        let (engine, _) =
            runtime.block_on(load_engine(&self.setup, "reopened", self.store.reopen()));
        assert!(
            runtime.block_on(engine.content_history(OPERATION)).is_err(),
            "rolled-back admission has no history"
        );
        let result = runtime
            .block_on(acquire(&engine, &self.setup.root, OPERATION))
            .expect("native reauthorization");
        assert_eq!(result.stage, AcquisitionStage::ResponseRecorded);
        assert_eq!((result.reserved_calls, result.reserved_bytes), (1, 1024));
        assert_eq!(
            (result.policy_count_counters, result.policy_byte_counters),
            (1, 1)
        );
        assert_eq!(self.provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            self.store.postgres_gateway_record_counts(),
            expected_counts(true)
        );
        let keys = self.store.raw().attempt_keys(4).expect("keys");
        assert_eq!(keys.len(), 1);
        let raw = self
            .store
            .raw()
            .load(crate::GatewayRecordKind::Attempt, &keys[0])
            .expect("load")
            .expect("record");
        let record: Value = serde_json::from_slice(&raw).expect("native record");
        assert_eq!(record["state"]["facts"]["allocation"], 0);
        assert!(!record["entry"].is_null());
        let witness = engine.execution_witness();
        for _ in 0..2 {
            assert_eq!(
                runtime
                    .block_on(acquire(&engine, &self.setup.root, OPERATION))
                    .expect("replay"),
                result
            );
        }
        assert_eq!(engine.execution_witness(), witness);
        assert_eq!(self.provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            self.store
                .raw()
                .load(crate::GatewayRecordKind::Attempt, &keys[0])
                .expect("reload")
                .expect("record"),
            raw
        );
        assert_eq!(
            self.store.postgres_gateway_record_counts(),
            expected_counts(true)
        );
        json!({"server_rejected_insert":fail_at,"prior_successful_insert_prefix":fail_at-1,"server_insert_sequence":fail_at,"all_admission_rows_rolled_back":true,"failed_worker_leases_and_transport_entries":0,"same_signed_inputs_reauthorized_after_reopen":true,"native_history":result,"actual_http_reads":1,"allocation_count_slot_and_sum_slot":1,"terminal_replay_preserves_attempt_and_execution_witness":true})
    }
}

#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_partial_batch_fixture_is_current() {
    assert!(postgres_configured());
    let cases: Vec<_> = (1..=4)
        .map(|fail_at| {
            let case = Case::new();
            case.fail(fail_at);
            case.reopen(fail_at)
        })
        .collect();
    let artifact = serde_json::to_vec_pretty(&json!({"schema":"auths.native-postgres-partial-batch/1","scope":"full native acquisition engine in separate worker OS processes, actual TLS PostgreSQL transactions and server-side insert exceptions, nontransactional sequence witnesses, signed bounded authority/exact approval, separate local custody and real local HTTP; fixed public test keys and maintained clock","excluded":["commit acknowledgement or network delivery ambiguity","PostgreSQL server/power failure","mutation/disclosure transaction fault matrices","whole-store rollback or hostile OS containment","human review or provider qualification"],"cases":cases})).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/native-postgres-partial-batch.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("write");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), artifact);
}
