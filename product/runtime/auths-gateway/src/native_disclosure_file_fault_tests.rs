//! Simulated file syscall errors exercise native release persistence, independent
//! recipient processes and exact historical ACKs without fabricating decisions.
use super::*;
use crate::native_dependency_tests::Peer as Process;
use crate::native_file_fault_tests::{FailureStore, journal_files};
use crate::store::FileIoPoint;
use crate::{FileGatewayAttemptStore, GatewayExecutionWitness, GatewaySubmitResult};
use std::{
    process::{Command, Stdio},
    sync::Arc,
};

const ENVIRONMENT: &str = "AUTHS_AP074_DISCLOSURE_FILE_FAULT_PEER";
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    Admission,
    Entry,
    Acknowledgement,
    Unknown,
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
        let mut result = vec![
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
            result.push(Self {
                phase: Phase::Admission,
                point: FileIoPoint::InstallTarget,
                skip,
            });
        }
        for skip in 0..3 {
            result.push(Self {
                phase: Phase::Admission,
                point: FileIoPoint::DirectorySync,
                skip,
            });
        }
        for phase in [Phase::Entry, Phase::Acknowledgement, Phase::Unknown] {
            for point in [
                FileIoPoint::DataSync,
                FileIoPoint::Replace,
                FileIoPoint::DirectorySync,
            ] {
                result.push(Self {
                    phase,
                    point,
                    skip: 0,
                });
            }
        }
        assert_eq!(result.len(), 18);
        result
    }
    const fn stage(self) -> &'static str {
        match self.phase {
            Phase::Admission => "reserved",
            Phase::Entry => "entry-granted",
            Phase::Acknowledgement => "acknowledged",
            Phase::Unknown => "unknown",
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
            Phase::Acknowledgement => {
                if matches!(self.point, FileIoPoint::DirectorySync) {
                    Some("acknowledged")
                } else {
                    Some("unknown")
                }
            }
            Phase::Unknown => {
                if matches!(self.point, FileIoPoint::DirectorySync) {
                    Some("unknown")
                } else {
                    Some("entry-granted")
                }
            }
        }
    }
    fn resumable(self) -> bool {
        matches!(self.retained(), None | Some("reserved"))
    }
    fn delivered(self) -> bool {
        matches!(self.phase, Phase::Acknowledgement | Phase::Unknown)
    }
    fn projection(self) -> DisclosureStage {
        match self.retained() {
            Some("reserved") => DisclosureStage::Reserved,
            Some("acknowledged") => DisclosureStage::Acknowledged,
            _ => DisclosureStage::Unknown,
        }
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FaultSetup {
    fixture: CrashSetup,
    schedule: Schedule,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResultData {
    process: u32,
    injected: usize,
    result: Result<DisclosureSnapshot, GatewaySubmitResult>,
    witness: GatewayExecutionWitness,
    recipient: Value,
    challenge_sent: bool,
    content_wire_bytes: u64,
}

#[test]
fn native_disclosure_file_fault_peer() {
    let Some(path) = std::env::var_os(ENVIRONMENT) else {
        return;
    };
    let setup: FaultSetup =
        serde_json::from_slice(&std::fs::read(path).expect("setup")).expect("closed setup");
    let fixture = &setup.fixture;
    let store = Arc::new(
        FileGatewayAttemptStore::open(&fixture.installation.location).expect("file adapter"),
    );
    let failure = Arc::new(FailureStore::new(
        store.clone(),
        key(RELEASE),
        CrashProtocol::Disclosure,
        setup.schedule.stage(),
        setup.schedule.point,
        setup.schedule.skip,
    ));
    let attempts = GatewayAttempts::new(failure, crate::effect::fixture_policy().expect("policy"))
        .expect("attempts");
    let runtime = runtime();
    let (engine, _) = runtime.block_on(load_controlled_engine(
        &fixture.installation,
        "file-release-worker",
        attempts,
        controls(Gate::Current),
    ));
    let result = runtime.block_on(async {
        let input = Input::read(&fixture.installation.root);
        let target = kit::target(&engine, fixture).await;
        let listener = UnixListener::bind(fixture.installation.root.join("release.sock"))
            .expect("owned native endpoint");
        let mut recipient = if matches!(setup.schedule.phase, Phase::Unknown) {
            Recipient::without_ack(fixture)
        } else {
            Recipient::start(fixture, false)
        };
        let (stream, _) = listener
            .accept()
            .await
            .expect("independent native recipient");
        let (server, recorder) = UnixStream::pair().expect("opaque recorder channel");
        let (result, (challenge_sent, content_wire_bytes)) = tokio::join!(
            engine.disclose(
                &target,
                &input.proof,
                &input.action,
                input.approval,
                DisclosureConnection::new(server, fixture.channel.clone())
            ),
            super::postgres_commit_tests::relay(recorder, stream)
        );
        recipient.finish(false);
        let recipient: Value = serde_json::from_slice(
            &std::fs::read(fixture.installation.root.join("recipient-result.json"))
                .expect("recipient outcome"),
        )
        .expect("native recipient");
        ResultData {
            process: std::process::id(),
            injected: store.injected_io_failures().expect("fault count"),
            result,
            witness: engine.execution_witness(),
            recipient,
            challenge_sent,
            content_wire_bytes,
        }
    });
    private(
        &fixture.installation.root.join("file-release-result"),
        &serde_json::to_vec(&result).expect("result"),
    );
}

fn assert_source(case: &Case) {
    assert_eq!(case.provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        case.store
            .raw()
            .load(GatewayRecordKind::Attempt, &key(SOURCE))
            .expect("load")
            .expect("source"),
        case.source
    );
    for (name, expected) in ["release.proof", "release.action", "release.approval"]
        .iter()
        .zip(&case.signed_inputs)
    {
        assert_eq!(
            &std::fs::read(case.setup.installation.root.join(name)).expect("original signed input"),
            expected
        );
    }
}
fn fail(case: &Case, schedule: Schedule) {
    let source_charges = case.source_charges.records(&case.store, true);
    let path = case.setup.installation.root.join("file-release.setup");
    private(
        &path,
        &serde_json::to_vec(&json!({"fixture":case.setup,"schedule":schedule})).expect("setup"),
    );
    let mut worker=Process(Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact","native_disclosure_crash_tests::file_fault_tests::native_disclosure_file_fault_peer","--nocapture"])
        .env(ENVIRONMENT,path).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().expect("native worker"));
    worker.finish();
    let result: ResultData = serde_json::from_slice(
        &std::fs::read(case.setup.installation.root.join("file-release-result")).expect("result"),
    )
    .expect("native result");
    assert_ne!(result.process, std::process::id());
    assert_eq!(result.injected, 1);
    assert_eq!(
        (
            result.witness.credential_lease_calls,
            result.witness.read_transport_entries,
            result.witness.write_transport_entries
        ),
        (0, 0, 0)
    );
    assert_eq!(result.recipient["received_full"], schedule.delivered());
    if schedule.delivered() {
        assert_eq!(result.recipient["bytes"], CONTENT.len());
    } else {
        assert_eq!(result.recipient["code"], "gateway.disclosure.read");
    }
    assert_eq!(
        case.setup.installation.root.join("recipient.ack").exists(),
        schedule.delivered()
    );
    assert_eq!(
        result.challenge_sent,
        !matches!(schedule.phase, Phase::Admission)
    );
    assert_eq!(
        result.content_wire_bytes,
        if schedule.delivered() {
            (CONTENT.len() + 4) as u64
        } else {
            0
        }
    );
    let raw = case
        .store
        .raw()
        .load(GatewayRecordKind::Attempt, &key(RELEASE))
        .expect("recovered state");
    if let Some(stage) = schedule.retained() {
        let value: Value =
            serde_json::from_slice(raw.as_ref().expect("record")).expect("native record");
        assert_eq!(value["state"]["facts"]["phase"]["stage"], stage);
        assert_eq!(value["evaluated_at"], NOW);
        assert_eq!(value["state"]["facts"]["allocation"], 0);
        assert_eq!(!value["entry"].is_null(), stage != "reserved");
        match result.result {
            Ok(snapshot) => assert_eq!(snapshot.stage, schedule.projection()),
            Err(GatewaySubmitResult::Indeterminate { code }) => {
                assert_eq!(code, "gateway.attempt.state-unavailable");
            }
            other => panic!("unexpected retained projection: {other:?}"),
        }
    } else {
        assert!(raw.is_none());
        assert_eq!(
            result.result,
            Err(GatewaySubmitResult::Indeterminate {
                code: "gateway.attempt.state-unavailable".to_owned()
            })
        );
    }
    let files = journal_files(Path::new(&case.setup.installation.location));
    assert!(!files.contains_key(".batch.json"));
    let admitted = usize::from(schedule.retained().is_some());
    for prefix in ["claim-", "allocation-"] {
        assert_eq!(
            files.keys().filter(|name| name.starts_with(prefix)).count(),
            1 + admitted
        );
    }
    for prefix in ["slot-", "sum-"] {
        assert_eq!(
            files.keys().filter(|name| name.starts_with(prefix)).count(),
            admitted
        );
    }
    case.release_charges
        .records(&case.store, schedule.retained().is_some());
    assert_eq!(
        case.source_charges.records(&case.store, true),
        source_charges
    );
    assert_source(case);
}

fn resume(case: &Case, engine: &GatewayEngine) -> DisclosureSnapshot {
    let (snapshot, mut recipient) = case.runtime.block_on(async {
        let input = Input::read(&case.setup.installation.root);
        let target = kit::target(engine, &case.setup).await;
        let listener = UnixListener::bind(case.setup.installation.root.join("resume.sock"))
            .expect("owned resume endpoint");
        let recipient = Recipient::start(&case.setup, true);
        let (stream, _) = listener
            .accept()
            .await
            .expect("independent native recipient");
        let (server, recorder) = UnixStream::pair().expect("opaque recorder channel");
        let (snapshot, (challenge, wire)) = tokio::join!(
            engine.disclose(
                &target,
                &input.proof,
                &input.action,
                input.approval,
                DisclosureConnection::new(server, case.setup.channel.clone())
            ),
            super::postgres_commit_tests::relay(recorder, stream)
        );
        assert!(challenge);
        assert_eq!(wire, (CONTENT.len() + 4) as u64);
        (snapshot.expect("fresh native reauthorization"), recipient)
    });
    recipient.finish(false);
    assert_eq!(snapshot.stage, DisclosureStage::Acknowledged);
    let received: Value = serde_json::from_slice(
        &std::fs::read(
            case.setup
                .installation
                .root
                .join("resumed-recipient-result.json"),
        )
        .expect("recipient outcome"),
    )
    .expect("recipient");
    assert_eq!(received["received_full"], true);
    assert_eq!(received["bytes"], CONTENT.len());
    snapshot
}
fn replay(case: &Case, engine: &GatewayEngine, expected: &DisclosureSnapshot) {
    let rows = journal_files(Path::new(&case.setup.installation.location));
    let witness = engine.execution_witness();
    case.runtime.block_on(async {
        let input = Input::read(&case.setup.installation.root);
        let target = kit::target(engine, &case.setup).await;
        let (server, mut client) = UnixStream::pair().expect("replay channel");
        let reader = async {
            let mut bytes = Vec::new();
            client.read_to_end(&mut bytes).await.expect("EOF");
            assert!(bytes.is_empty());
        };
        let (actual, ()) = tokio::join!(
            engine.disclose(
                &target,
                &input.proof,
                &input.action,
                input.approval,
                DisclosureConnection::new(server, case.setup.channel.clone())
            ),
            reader
        );
        assert_eq!(&actual.expect("retained facts"), expected);
    });
    assert_eq!(engine.execution_witness(), witness);
    assert_eq!(
        journal_files(Path::new(&case.setup.installation.location)),
        rows
    );
    assert_source(case);
}
fn late_ack(
    case: &Case,
    engine: &GatewayEngine,
    schedule: Schedule,
    snapshot: &DisclosureSnapshot,
) -> bool {
    let prefix = if schedule.resumable() {
        "resumed-recipient"
    } else {
        "recipient"
    };
    let path = case.setup.installation.root.join(format!("{prefix}.ack"));
    if !path.exists() {
        assert!(
            matches!(schedule.phase, Phase::Entry)
                && matches!(schedule.point, FileIoPoint::DirectorySync)
        );
        assert_eq!(snapshot.stage, DisclosureStage::Unknown);
        return false;
    }
    let ack = DisclosureAcknowledgement::from_private_bytes(
        &std::fs::read(path).expect("genuine native ACK"),
    )
    .expect("ACK");
    let charges = case.release_charges.records(&case.store, true);
    let mut before = journal_files(Path::new(&case.setup.installation.location));
    let witness = engine.execution_witness();
    let after = case
        .runtime
        .block_on(engine.acknowledge_disclosure(RELEASE, &ack))
        .expect("historical ACK");
    assert_eq!(after.stage, DisclosureStage::Acknowledged);
    assert_eq!(engine.execution_witness(), witness);
    assert_eq!(case.release_charges.records(&case.store, true), charges);
    let mut retained = journal_files(Path::new(&case.setup.installation.location));
    let file = format!("claim-{}.json", hex::encode(key(RELEASE).as_bytes()));
    assert!(before.remove(&file).is_some());
    assert!(retained.remove(&file).is_some());
    assert_eq!(retained, before);
    replay(case, engine, &after);
    true
}
fn reopen(case: &Case, schedule: Schedule) -> Value {
    let before = journal_files(Path::new(&case.setup.installation.location));
    let source = case.source_charges.records(&case.store, true);
    let prior = schedule
        .retained()
        .map(|_| case.release_charges.records(&case.store, true));
    let (engine, _) = case.runtime.block_on(load_controlled_engine(
        &case.setup.installation,
        "file-release-reopened",
        case.store.reopen(),
        controls(Gate::Current),
    ));
    let history = case.runtime.block_on(engine.content_history(RELEASE));
    if schedule.retained().is_none() {
        assert!(history.is_err());
    } else {
        let ContentHistory::Disclosure(snapshot) = history.expect("history") else {
            panic!("protocol");
        };
        assert_eq!(snapshot.stage, schedule.projection());
    }
    let snapshot = if schedule.resumable() {
        resume(case, &engine)
    } else {
        let ContentHistory::Disclosure(snapshot) = case
            .runtime
            .block_on(engine.content_history(RELEASE))
            .expect("history")
        else {
            panic!("protocol");
        };
        assert_eq!(
            journal_files(Path::new(&case.setup.installation.location)),
            before
        );
        snapshot
    };
    assert_eq!(
        (
            snapshot.reserved_deliveries,
            snapshot.reserved_bytes,
            snapshot.policy_count_counters,
            snapshot.policy_byte_counters
        ),
        (1, CONTENT.len() as u64, 1, 1)
    );
    let charges = case.release_charges.records(&case.store, true);
    assert_eq!(charges.len(), 3);
    if let Some(prior) = prior {
        assert_eq!(charges, prior);
    }
    assert_eq!(case.source_charges.records(&case.store, true), source);
    replay(case, &engine, &snapshot);
    let historical = late_ack(case, &engine, schedule, &snapshot);
    assert_source(case);
    json!({"phase":schedule.phase,"point":schedule.point,"skip":schedule.skip,"injected_io_failures":1,
        "retained_phase_after_failure":schedule.retained(),"new_native_delivery_allowed":schedule.resumable(),
        "recipient_deliveries":usize::from(schedule.delivered()||schedule.resumable()),"native_snapshot_before_historical_ack":snapshot,
        "native_historical_ack_refined_or_replayed":historical,"provider_source_reads":1,"additional_custody_or_provider_calls":0,
        "existing_source_and_charges_preserved":true,"one_lifetime_allocation_count_and_byte_sum_slot":true,
        "terminal_replay_has_no_wire_bytes_or_journal_or_witness_change":true})
}

#[test]
fn native_file_disclosure_io_fault_fixture_is_current() {
    let cases: Vec<_> = Schedule::all()
        .into_iter()
        .map(|schedule| {
            let case = Case::new(Backend::File, Point::BeforeReservationCommit, Gate::Current);
            fail(&case, schedule);
            reopen(&case, schedule)
        })
        .collect();
    let artifact=serde_json::to_vec_pretty(&json!({"schema":"auths.native-disclosure-file-io-faults/1","cases":cases,
        "scope":"native source HTTP acquisition, release gateway and recipient in independent OS processes over same-UID Unix sockets, opaque wire capture, maintained file writer fence and four-row admission; syscall error simulated at actual adapter site, preceding writes/rollback/ACK/replay use maintained code and public fixture keys/clock",
        "excluded":["actual kernel/device EIO or power loss","whole-store rollback","hostile OS or live-provider qualification"]})).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/native-disclosure-file-io-faults.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("write");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), artifact);
}
