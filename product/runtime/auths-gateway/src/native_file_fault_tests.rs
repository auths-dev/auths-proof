//! Injected errors at file adapter I/O boundaries under actual native decisions.
//! The failed syscall is simulated; real preceding writes, fences, rollback,
//! native verification, custody and HTTP run in independent OS processes.
use crate::native_process_tests::{
    NOW, Provider, Setup, acquire, authorize_policy, load_engine, private, recipe, runtime,
};
use crate::store::{FileIoPoint, GatewayFenceDecision};
use crate::store_testkit::{Backend, TestAttempts};
use crate::{
    AcquisitionSnapshot, AcquisitionStage, ArgumentCeilingPolicy, ContentHistory,
    FileGatewayAttemptStore, GatewayAttemptError, GatewayAttemptKey, GatewayAttemptStore,
    GatewayAttempts, GatewayExecutionWitness, GatewayInsert, GatewayRecordEntry, GatewayRecordKind,
    GatewaySubmitResult, LogicalOperationId, SharedConnection,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::Read as _,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const OPERATION: &str = "file-fault-read";

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    Admission,
    Entry,
    Response,
}
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Schedule {
    phase: Phase,
    point: FileIoPoint,
    skip: usize,
}
impl Schedule {
    fn all() -> Vec<Self> {
        let mut schedules = vec![
            Self {
                phase: Phase::Admission,
                point: FileIoPoint::DataSync,
                skip: 0,
            },
            Self {
                phase: Phase::Admission,
                point: FileIoPoint::InstallBatch,
                skip: 0,
            },
        ];
        for skip in 0..4 {
            schedules.push(Self {
                phase: Phase::Admission,
                point: FileIoPoint::InstallTarget,
                skip,
            });
        }
        for skip in 0..3 {
            schedules.push(Self {
                phase: Phase::Admission,
                point: FileIoPoint::DirectorySync,
                skip,
            });
        }
        for phase in [Phase::Entry, Phase::Response] {
            for point in [
                FileIoPoint::DataSync,
                FileIoPoint::Replace,
                FileIoPoint::DirectorySync,
            ] {
                schedules.push(Self {
                    phase,
                    point,
                    skip: 0,
                });
            }
        }
        assert_eq!(schedules.len(), 15);
        schedules
    }
    const fn decision(self) -> &'static str {
        match self.phase {
            Phase::Admission => "reserved",
            Phase::Entry => "entry-granted",
            Phase::Response => "content-response-recorded",
        }
    }
    const fn retained_phase(self) -> Option<&'static str> {
        match self.phase {
            Phase::Admission => {
                if matches!(self.point, FileIoPoint::DirectorySync) && self.skip == 2 {
                    Some("reserved")
                } else {
                    None
                }
            }
            Phase::Entry => {
                if matches!(self.point, FileIoPoint::DirectorySync) {
                    Some("entry-granted")
                } else {
                    Some("reserved")
                }
            }
            Phase::Response => {
                if matches!(self.point, FileIoPoint::DirectorySync) {
                    Some("content-response-recorded")
                } else {
                    Some("entry-granted")
                }
            }
        }
    }
    fn resumable(self) -> bool {
        matches!(self.retained_phase(), None | Some("reserved"))
    }
    fn requests(self) -> usize {
        usize::from(matches!(self.phase, Phase::Response))
    }
    fn public_stage(self) -> AcquisitionStage {
        match self.retained_phase() {
            Some("reserved") => AcquisitionStage::Reserved,
            Some("content-response-recorded") => AcquisitionStage::ResponseRecorded,
            _ => AcquisitionStage::Unknown,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FaultSetup {
    installation: Setup,
    schedule: Schedule,
}
fn operation_key() -> GatewayAttemptKey {
    GatewayAttemptKey::for_operation(
        &crate::effect::fixture_policy().expect("policy"),
        recipe().namespace(),
        &LogicalOperationId::parse(OPERATION).expect("operation"),
    )
    .expect("key")
}

struct FailureStore {
    inner: Arc<FileGatewayAttemptStore>,
    schedule: Schedule,
    armed: AtomicBool,
}
impl FailureStore {
    fn arm(
        &self,
        kind: GatewayRecordKind,
        key: GatewayAttemptKey,
        bytes: &[u8],
    ) -> Result<(), GatewayAttemptError> {
        if kind == GatewayRecordKind::Attempt && key == operation_key() {
            let value: Value = serde_json::from_slice(bytes).expect("unchanged native decision");
            if value["state"]["facts"]["phase"]["stage"] == self.schedule.decision()
                && !self.armed.swap(true, Ordering::SeqCst)
            {
                self.inner
                    .arm_io_failure(self.schedule.point, self.schedule.skip)?;
            }
        }
        Ok(())
    }
}
impl GatewayAttemptStore for FailureStore {
    fn fenced_insert_all(
        &self,
        entries: &[GatewayRecordEntry],
        dependencies: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut GatewayFenceDecision<'_>,
    ) -> Result<GatewayInsert, GatewayAttemptError> {
        self.inner
            .fenced_insert_all(entries, dependencies, &mut |snapshots| {
                let next = decide(snapshots)?;
                self.arm(entries[0].kind, entries[0].key, &next)?;
                Ok(next)
            })
    }
    fn fenced_replace(
        &self,
        keys: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut GatewayFenceDecision<'_>,
    ) -> Result<(), GatewayAttemptError> {
        self.inner.fenced_replace(keys, &mut |snapshots| {
            let next = decide(snapshots)?;
            self.arm(keys[0].0, keys[0].1, &next)?;
            Ok(next)
        })
    }
    fn replace(
        &self,
        kind: GatewayRecordKind,
        key: &GatewayAttemptKey,
        current: &[u8],
        next: &[u8],
    ) -> Result<(), GatewayAttemptError> {
        self.arm(kind, *key, next)?;
        self.inner.replace(kind, key, current, next)
    }
    fn insert_all(
        &self,
        entries: &[GatewayRecordEntry],
    ) -> Result<GatewayInsert, GatewayAttemptError> {
        self.inner.insert_all(entries)
    }
    fn load(
        &self,
        kind: GatewayRecordKind,
        key: &GatewayAttemptKey,
    ) -> Result<Option<Vec<u8>>, GatewayAttemptError> {
        self.inner.load(kind, key)
    }
    fn sweep_expired(&self, now: u64, limit: usize) -> Result<usize, GatewayAttemptError> {
        self.inner.sweep_expired(now, limit)
    }
    fn attempt_keys(&self, limit: usize) -> Result<Vec<GatewayAttemptKey>, GatewayAttemptError> {
        self.inner.attempt_keys(limit)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerResult {
    injected: usize,
    result: Result<AcquisitionSnapshot, GatewaySubmitResult>,
    witness: GatewayExecutionWitness,
}

#[test]
fn native_file_fault_peer() {
    let Some(input) = std::env::var_os("AUTHS_AP074_FILE_FAULT_PEER") else {
        return;
    };
    let setup: FaultSetup =
        serde_json::from_slice(&std::fs::read(input).expect("setup")).expect("closed setup");
    let store = Arc::new(
        FileGatewayAttemptStore::open(&setup.installation.location).expect("file adapter"),
    );
    let failure = Arc::new(FailureStore {
        inner: store.clone(),
        schedule: setup.schedule,
        armed: AtomicBool::new(false),
    });
    let attempts = GatewayAttempts::new(failure, crate::effect::fixture_policy().expect("policy"))
        .expect("attempts");
    let runtime = runtime();
    let (engine, _) = runtime.block_on(load_engine(&setup.installation, "worker", attempts));
    let result = runtime.block_on(acquire(&engine, &setup.installation.root, OPERATION));
    let answer = WorkerResult {
        injected: store.injected_io_failures().expect("fault witness"),
        result,
        witness: engine.execution_witness(),
    };
    private(
        &setup.installation.root.join("worker-result"),
        &serde_json::to_vec(&answer).expect("result"),
    );
}

struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn execute(setup: &FaultSetup) -> WorkerResult {
    let input = setup.installation.root.join("fault-setup.json");
    private(&input, &serde_json::to_vec(setup).expect("setup"));
    let mut peer = Peer(
        Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "native_file_fault_tests::native_file_fault_peer",
                "--nocapture",
            ])
            .env("AUTHS_AP074_FILE_FAULT_PEER", input)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("native peer"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = peer.0.try_wait().expect("status") {
            let mut diagnostic = String::new();
            peer.0
                .stderr
                .take()
                .expect("stderr")
                .read_to_string(&mut diagnostic)
                .expect("diagnostic");
            assert!(status.success(), "native worker: {diagnostic}");
            break;
        }
        assert!(Instant::now() < deadline, "native worker deadline");
        thread::sleep(Duration::from_millis(2));
    }
    serde_json::from_slice(
        &std::fs::read(setup.installation.root.join("worker-result")).expect("worker result"),
    )
    .expect("native result")
}

fn journal_files(path: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(path)
        .expect("directory")
        .map(|entry| {
            let entry = entry.expect("entry");
            (
                entry.file_name().into_string().expect("file name"),
                entry.path(),
            )
        })
        .filter(|(_, path)| {
            path.extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
        })
        .map(|(name, path)| (name, std::fs::read(path).expect("record bytes")))
        .collect()
}

struct Case {
    _directory: tempfile::TempDir,
    store: TestAttempts,
    setup: FaultSetup,
    provider: Provider,
    signed: Vec<Vec<u8>>,
}
impl Case {
    fn new(schedule: Schedule) -> Self {
        let directory = tempfile::tempdir().expect("directory");
        let root = std::fs::canonicalize(directory.path()).expect("canonical");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private mode");
        let store = TestAttempts::open(Backend::File);
        let provider = Provider::controlled(None);
        let setup = FaultSetup {
            schedule,
            installation: Setup {
                backend: "file".to_owned(),
                location: store.location(),
                root,
                provider_port: provider.port,
                barrier_port: 0,
            },
        };
        let runtime = runtime();
        let (engine, connection) = runtime.block_on(load_engine(
            &setup.installation,
            "parent",
            store.attempts().clone(),
        ));
        let shared = SharedConnection::new(
            store.raw(),
            connection.provider_kind().clone(),
            connection.alias().clone(),
        );
        runtime
            .block_on(shared.insert(&connection))
            .expect("published connection");
        engine
            .initialize_effect_configuration()
            .expect("installed configuration");
        let policy = ArgumentCeilingPolicy::new("maximum_response_bytes", 1024, 3600, 4)
            .expect("count")
            .with_sum(4096, None)
            .expect("sum");
        runtime.block_on(authorize_policy(
            &engine,
            &setup.installation.root,
            OPERATION,
            &policy,
        ));
        let signed = Self::inputs(&setup);
        Self {
            _directory: directory,
            store,
            setup,
            provider,
            signed,
        }
    }
    fn inputs(setup: &FaultSetup) -> Vec<Vec<u8>> {
        ["proof", "action", "approval"]
            .map(|suffix| {
                std::fs::read(
                    setup
                        .installation
                        .root
                        .join(format!("{OPERATION}.{suffix}")),
                )
                .expect("signed inputs")
            })
            .to_vec()
    }
    fn raw(&self) -> Option<Vec<u8>> {
        self.store
            .raw()
            .load(GatewayRecordKind::Attempt, &operation_key())
            .expect("load")
    }
    fn check_initial(&self, worker: &WorkerResult) {
        assert_eq!(
            worker.injected, 1,
            "one actual adapter failure site reached"
        );
        assert_eq!(
            self.provider.calls.load(Ordering::SeqCst),
            self.setup.schedule.requests()
        );
        assert_eq!(
            worker.witness.read_transport_entries,
            self.setup.schedule.requests() as u64
        );
        assert_eq!(worker.witness.write_transport_entries, 0);
        assert_eq!(
            worker.witness.credential_lease_calls,
            u64::from(!matches!(self.setup.schedule.phase, Phase::Admission))
        );
        assert_eq!(Self::inputs(&self.setup), self.signed);
        let raw = self.raw();
        if let Some(phase) = self.setup.schedule.retained_phase() {
            let record: Value = serde_json::from_slice(raw.as_ref().expect("retained record"))
                .expect("native record");
            assert_eq!(record["state"]["facts"]["phase"]["stage"], phase);
            assert_eq!(record["state"]["facts"]["allocation"], 0);
            assert_eq!(
                record["state"]["facts"]["counters"]
                    .as_array()
                    .expect("counters")
                    .len(),
                2
            );
            assert_eq!(record["evaluated_at"], NOW);
            assert_eq!(!record["entry"].is_null(), phase != "reserved");
            let snapshot = worker.result.as_ref().expect("native retained projection");
            assert_eq!(snapshot.stage, self.setup.schedule.public_stage());
            assert_eq!(
                (snapshot.reserved_calls, snapshot.reserved_bytes),
                (1, 1024)
            );
            assert_eq!(
                (
                    snapshot.policy_count_counters,
                    snapshot.policy_byte_counters
                ),
                (1, 1)
            );
        } else {
            assert!(
                raw.is_none(),
                "all unacknowledged batch targets rolled back"
            );
            assert!(
                matches!(&worker.result, Err(GatewaySubmitResult::Indeterminate { code }) if code == "gateway.attempt.state-unavailable")
            );
        }
        let files = journal_files(Path::new(&self.setup.installation.location));
        assert!(
            !files.contains_key(".batch.json"),
            "recovery removes the rollback marker"
        );
        let expected = usize::from(self.setup.schedule.retained_phase().is_some());
        for prefix in ["claim-", "allocation-", "slot-", "sum-"] {
            assert_eq!(
                files.keys().filter(|name| name.starts_with(prefix)).count(),
                expected,
                "all-or-none charge: {prefix}"
            );
        }
    }
    fn reopen(&self) -> Value {
        let before = journal_files(Path::new(&self.setup.installation.location));
        let runtime = runtime();
        let (engine, _) = runtime.block_on(load_engine(
            &self.setup.installation,
            "reopened",
            self.store.reopen(),
        ));
        if self.setup.schedule.retained_phase().is_some() {
            match runtime
                .block_on(engine.content_history(OPERATION))
                .expect("native history")
            {
                ContentHistory::Acquisition(history) => {
                    assert_eq!(history.stage, self.setup.schedule.public_stage());
                }
                ContentHistory::Disclosure(_) => panic!("wrong protocol"),
            }
        }
        let witness = engine.execution_witness();
        let result = runtime
            .block_on(acquire(&engine, &self.setup.installation.root, OPERATION))
            .expect("native replay");
        assert_eq!(
            result.stage,
            if self.setup.schedule.resumable() {
                AcquisitionStage::ResponseRecorded
            } else {
                self.setup.schedule.public_stage()
            }
        );
        assert_eq!((result.reserved_calls, result.reserved_bytes), (1, 1024));
        assert_eq!(
            (result.policy_count_counters, result.policy_byte_counters),
            (1, 1)
        );
        if !self.setup.schedule.resumable() {
            assert_eq!(
                engine.execution_witness(),
                witness,
                "lost acknowledgement cannot grant again"
            );
            assert_eq!(
                journal_files(Path::new(&self.setup.installation.location)),
                before
            );
        }
        let calls = self.setup.schedule.requests() + usize::from(self.setup.schedule.resumable());
        assert_eq!(self.provider.calls.load(Ordering::SeqCst), calls);
        let retained = journal_files(Path::new(&self.setup.installation.location));
        let witness = engine.execution_witness();
        assert_eq!(
            runtime
                .block_on(acquire(&engine, &self.setup.installation.root, OPERATION))
                .expect("second replay"),
            result
        );
        assert_eq!(engine.execution_witness(), witness);
        assert_eq!(self.provider.calls.load(Ordering::SeqCst), calls);
        assert_eq!(
            journal_files(Path::new(&self.setup.installation.location)),
            retained
        );
        for prefix in ["claim-", "allocation-", "slot-", "sum-"] {
            assert_eq!(
                retained
                    .keys()
                    .filter(|name| name.starts_with(prefix))
                    .count(),
                1,
                "no repeated charge"
            );
        }
        json!({"schedule":self.setup.schedule,"injected_io_failures":1,"phase_after_failure":self.setup.schedule.retained_phase(),"actual_reads_before_reopen":self.setup.schedule.requests(),"new_native_execution_permitted":self.setup.schedule.resumable(),"actual_reads_after_reopen":calls,"native_history":result,"one_allocation_count_slot_and_sum_slot":true,"terminal_replay_preserves_journal_and_execution_witness":true,"signed_inputs_unchanged":true})
    }
}

#[test]
fn native_file_io_fault_fixture_is_current() {
    let cases: Vec<_> = Schedule::all()
        .into_iter()
        .map(|schedule| {
            let case = Case::new(schedule);
            let worker = execute(&case.setup);
            case.check_initial(&worker);
            case.reopen()
        })
        .collect();
    let artifact = serde_json::to_vec_pretty(&json!({"schema":"auths.native-file-io-faults/1","scope":"full native acquisition engine in separate worker OS processes; actual maintained file writer fence, four-record admission batches, rollback/reopen, signed bounded grants, fixed-key exact approvals, separate local custody and real HTTP; failed I/O return is simulated at the native adapter call site","excluded":["actual kernel/device EIO or power loss","PostgreSQL partial batches and ambiguous commit delivery","mutation/disclosure fault matrices","whole-store rollback and hostile OS containment","live provider qualification or human review"],"cases":cases})).expect("artifact");
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/native-file-io-faults.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("write");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), artifact);
}
