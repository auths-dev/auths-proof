//! Simulated file syscall errors at actual native mutation persistence sites.
//! All decisions, preceding writes, rollback/reopen and HTTP are maintained code.
use super::*;
use crate::FileGatewayAttemptStore;
use crate::native_dependency_tests::Peer as Process;
use crate::native_file_fault_tests::{FailureStore, journal_files};
use crate::native_postgres_commit_tests::Phase;
use crate::store::FileIoPoint;
use std::process::{Command, Stdio};

const ENVIRONMENT: &str = "AUTHS_AP074_MUTATION_FILE_FAULT_PEER";
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Schedule {
    phase: Phase,
    point: FileIoPoint,
    skip: usize,
}
impl Schedule {
    fn all() -> Vec<Self> {
        let mut cases = vec![
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
        for skip in 0..3 {
            cases.push(Self {
                phase: Phase::Admission,
                point: FileIoPoint::InstallTarget,
                skip,
            });
        }
        for skip in 0..3 {
            cases.push(Self {
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
                cases.push(Self {
                    phase,
                    point,
                    skip: 0,
                });
            }
        }
        assert_eq!(cases.len(), 14);
        cases
    }
    const fn stage(self) -> &'static str {
        match self.phase {
            Phase::Admission => "reserved",
            Phase::Entry => "entry-granted",
            Phase::Response => "response-recorded",
        }
    }
    const fn retained(self) -> Option<&'static str> {
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
                    Some("response-recorded")
                } else {
                    Some("entry-granted")
                }
            }
        }
    }
    fn resumable(self) -> bool {
        matches!(self.retained(), None | Some("reserved"))
    }
    fn writes(self) -> usize {
        usize::from(matches!(self.phase, Phase::Response))
    }
    fn projection(self) -> GatewaySubmitResult {
        match self.retained() {
            Some("reserved") => GatewaySubmitResult::Reserved { revision: 1 },
            Some("response-recorded") => GatewaySubmitResult::ResponseRecorded { status: 200 },
            Some("entry-granted") => GatewaySubmitResult::Unknown,
            _ => panic!("absent operation has no history"),
        }
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FaultSetup {
    installation: Setup,
    schedule: Schedule,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResultData {
    process: u32,
    injected: usize,
    result: GatewaySubmitResult,
    witness: GatewayExecutionWitness,
}
fn operation_key() -> GatewayAttemptKey {
    GatewayAttemptKey::for_operation(
        &crate::effect::fixture_policy().expect("policy"),
        Flavor::StripePlain.recipe().namespace(),
        &LogicalOperationId::parse(OPERATIONS[0]).expect("operation"),
    )
    .expect("key")
}

#[test]
fn native_mutation_file_fault_peer() {
    let Some(path) = std::env::var_os(ENVIRONMENT) else {
        return;
    };
    let setup: FaultSetup =
        serde_json::from_slice(&std::fs::read(path).expect("setup")).expect("closed setup");
    let store = Arc::new(
        FileGatewayAttemptStore::open(&setup.installation.location).expect("file adapter"),
    );
    let failure = Arc::new(FailureStore::new(
        store.clone(),
        operation_key(),
        CrashProtocol::Mutation,
        setup.schedule.stage(),
        setup.schedule.point,
        setup.schedule.skip,
    ));
    let attempts = GatewayAttempts::new(failure, crate::effect::fixture_policy().expect("policy"))
        .expect("attempts");
    let runtime = runtime();
    let (engine, _) = runtime.block_on(load_controlled_engine(
        &setup.installation,
        "file-mutation-worker",
        attempts,
        Flavor::StripePlain.controls(),
    ));
    let result = runtime.block_on(execute(&engine, &setup.installation.root, OPERATIONS[0]));
    private(
        &setup.installation.root.join("file-mutation-result"),
        &serde_json::to_vec(&ResultData {
            process: std::process::id(),
            injected: store.injected_io_failures().expect("fault count"),
            result,
            witness: engine.execution_witness(),
        })
        .expect("result"),
    );
}
fn signed_inputs(case: &MutationRace) -> Vec<Vec<u8>> {
    ["proof", "action", "approval", "binding"]
        .map(|suffix| {
            std::fs::read(case.setup.root.join(format!("{}.{suffix}", OPERATIONS[0])))
                .expect("original input")
        })
        .to_vec()
}
fn fail(case: &MutationRace, schedule: Schedule, counters: &[Counter]) {
    let path = case.setup.root.join("file-mutation.setup");
    private(
        &path,
        &serde_json::to_vec(&json!({"installation":case.setup,"schedule":schedule}))
            .expect("setup"),
    );
    let mut worker=Process(Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact","native_mutation_crash_tests::window_capacity_tests::file_fault_tests::native_mutation_file_fault_peer","--nocapture"])
        .env(ENVIRONMENT,path).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().expect("native worker"));
    worker.finish();
    let result: ResultData = serde_json::from_slice(
        &std::fs::read(case.setup.root.join("file-mutation-result")).expect("result"),
    )
    .expect("native result");
    assert_ne!(result.process, std::process::id());
    assert_eq!(result.injected, 1);
    assert_eq!(
        result.witness.credential_lease_calls,
        u64::from(!matches!(schedule.phase, Phase::Admission))
    );
    assert_eq!(result.witness.read_transport_entries, 0);
    assert_eq!(
        result.witness.write_transport_entries,
        schedule.writes() as u64
    );
    assert_eq!(case.provider.calls(), schedule.writes());
    let raw = case
        .store
        .raw()
        .load(GatewayRecordKind::Attempt, &operation_key())
        .expect("recovered state");
    if let Some(stage) = schedule.retained() {
        let record: Value =
            serde_json::from_slice(raw.as_ref().expect("record")).expect("native record");
        assert_eq!(record["state"]["facts"]["stage"], stage);
        assert_eq!(record["evaluated_at"], NOW);
        assert_eq!(!record["entry"].is_null(), stage != "reserved");
        match &result.result {
            GatewaySubmitResult::Indeterminate { code } => {
                assert_eq!(code, "gateway.attempt.state-unavailable");
            }
            GatewaySubmitResult::Unknown => {
                assert!(matches!(stage, "entry-granted" | "response-recorded"));
            }
            other => assert_eq!(other, &schedule.projection()),
        }
    } else {
        assert!(raw.is_none());
        assert_eq!(
            result.result,
            GatewaySubmitResult::Indeterminate {
                code: "gateway.attempt.state-unavailable".to_owned()
            }
        );
    }
    let files = journal_files(Path::new(&case.setup.location));
    assert!(!files.contains_key(".batch.json"));
    for prefix in ["claim-", "slot-", "sum-"] {
        assert_eq!(
            files.keys().filter(|name| name.starts_with(prefix)).count(),
            usize::from(schedule.retained().is_some())
        );
    }
    assert!(
        !files.keys().any(|name| name.starts_with("allocation-")),
        "mutation has no source lifetime allocation"
    );
    for counter in counters {
        assert_eq!(
            case.store
                .raw()
                .load(counter.kind, &counter.key(0))
                .expect("charge")
                .is_some(),
            schedule.retained().is_some()
        );
        assert!(
            case.store
                .raw()
                .load(counter.kind, &counter.key(1))
                .expect("no extra slot")
                .is_none()
        );
    }
}

fn reopen(case: &MutationRace, schedule: Schedule, counters: &[Counter]) -> Value {
    let before = journal_files(Path::new(&case.setup.location));
    let prior = slot_bytes(case, counters, schedule.retained().is_some());
    let (engine, _) = case.runtime.block_on(load_controlled_engine(
        &case.setup,
        "file-mutation-reopened",
        case.store.reopen(),
        Flavor::StripePlain.controls(),
    ));
    let witness = engine.execution_witness();
    let result = case
        .runtime
        .block_on(execute(&engine, &case.setup.root, OPERATIONS[0]));
    assert_eq!(
        result,
        if schedule.resumable() {
            GatewaySubmitResult::ResponseRecorded { status: 200 }
        } else {
            schedule.projection()
        }
    );
    if !schedule.resumable() {
        assert_eq!(engine.execution_witness(), witness);
        assert_eq!(journal_files(Path::new(&case.setup.location)), before);
    }
    let total = schedule.writes() + usize::from(schedule.resumable());
    assert_eq!(case.provider.calls(), total);
    if total == 1 {
        assert_eq!(
            case.provider.requests.lock().expect("requests")[0].body,
            std::fs::read(case.setup.root.join(format!("{}.body", OPERATIONS[0])))
                .expect("exact native body")
        );
    }
    let slots = slot_bytes(case, counters, true);
    if !prior.is_empty() {
        assert_eq!(slots, prior);
    }
    let rows = journal_files(Path::new(&case.setup.location));
    let witness = engine.execution_witness();
    assert_eq!(
        case.runtime
            .block_on(execute(&engine, &case.setup.root, OPERATIONS[0])),
        result
    );
    assert_eq!(engine.execution_witness(), witness);
    assert_eq!(journal_files(Path::new(&case.setup.location)), rows);
    assert_eq!(case.provider.calls(), total);
    assert_eq!(slot_bytes(case, counters, true), slots);
    json!({"phase":schedule.phase,"point":schedule.point,"skip":schedule.skip,"injected_io_failures":1,
        "retained_phase_after_failure":schedule.retained(),"provider_writes_before_reopen":schedule.writes(),
        "new_native_execution_allowed":schedule.resumable(),"provider_writes_after_reopen":total,"native_result":result,
        "one_count_and_one_amount_sum_slot":true,"no_source_lifetime_allocation_for_mutation":true,
        "terminal_replay_changes_no_journal_bytes_or_execution_witness":true})
}
fn slot_bytes(case: &MutationRace, counters: &[Counter], present: bool) -> Vec<Vec<u8>> {
    counters
        .iter()
        .filter_map(|counter| {
            let value = case
                .store
                .raw()
                .load(counter.kind, &counter.key(0))
                .expect("slot");
            assert_eq!(value.is_some(), present);
            assert!(
                case.store
                    .raw()
                    .load(counter.kind, &counter.key(1))
                    .expect("no duplicate")
                    .is_none()
            );
            value.inspect(|bytes| {
                let data: Value = serde_json::from_slice(bytes).expect("native slot");
                assert_eq!(data["slot"], 0);
                assert_eq!(data["operation_id"], OPERATIONS[0]);
                if counter.kind == GatewayRecordKind::SumSlot {
                    assert_eq!(data["amount"], AMOUNT);
                    assert_eq!(data["cumulative"], AMOUNT);
                }
            })
        })
        .collect()
}

#[test]
fn native_file_mutation_io_fault_fixture_is_current() {
    let cases: Vec<_> = Schedule::all()
        .into_iter()
        .map(|schedule| {
            let case = MutationRace::new(Backend::File);
            let counters = case.runtime.block_on(inputs(
                &case.engine,
                &case.setup.root,
                OPERATIONS[0],
                Limit::Both,
            ));
            let signed = signed_inputs(&case);
            fail(&case, schedule, &counters);
            assert_eq!(signed_inputs(&case), signed);
            let result = reopen(&case, schedule, &counters);
            assert_eq!(signed_inputs(&case), signed);
            result
        })
        .collect();
    let artifact=serde_json::to_vec_pretty(&json!({"schema":"auths.native-mutation-file-io-faults/1","cases":cases,
        "scope":"native Stripe mutation in separate worker processes, actual maintained file writer fence and three-row atomic admission, rollback/reopen, native bounded proof/exact approval and counting local HTTP; I/O failure return simulated at adapter call site, fixed public fixture keys/clock",
        "excluded":["actual kernel/device EIO or power loss","whole-store rollback","hostile OS and live-provider qualification"]})).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/native-mutation-file-io-faults.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("write");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), artifact);
}
