//! Real lost mutation COMMIT replies, with an independent TLS observer of the
//! server outcome and an opaque transport that cannot fabricate store decisions.
use super::*;
use crate::native_dependency_tests::Peer as Process;
use crate::native_postgres_commit_tests::{
    Barrier, CommitWitness, Outcome, Phase, Proxy, fixture_url,
};
use crate::native_postgres_fault_tests::ready;
use std::process::{Command, Stdio};

const ENVIRONMENT: &str = "AUTHS_AP074_MUTATION_COMMIT_PEER";

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Schedule {
    phase: Phase,
    outcome: Outcome,
}
impl Schedule {
    const fn stage(self) -> &'static str {
        match self.phase {
            Phase::Admission => "reserved",
            Phase::Entry => "entry-granted",
            Phase::Response => "response-recorded",
        }
    }
    const fn retained(self) -> Option<&'static str> {
        match self.outcome {
            Outcome::Committed => Some(self.stage()),
            Outcome::Aborted => match self.phase {
                Phase::Admission => None,
                Phase::Entry => Some("reserved"),
                Phase::Response => Some("entry-granted"),
            },
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
            _ => panic!("absent operation has no retained projection"),
        }
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CommitSetup {
    installation: Setup,
    schedule: Schedule,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResultData {
    process: u32,
    result: GatewaySubmitResult,
    errors: u64,
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
fn native_mutation_postgres_commit_peer() {
    let Some(path) = std::env::var_os(ENVIRONMENT) else {
        return;
    };
    let setup: CommitSetup =
        serde_json::from_slice(&std::fs::read(path).expect("setup")).expect("closed setup");
    let store = TestAttempts::attach(Backend::Postgres, &setup.installation.location);
    let witness = Arc::new(CommitWitness::new(
        store.raw(),
        operation_key(),
        CrashProtocol::Mutation,
        setup.schedule.stage(),
    ));
    let attempts = GatewayAttempts::new(
        witness.clone(),
        crate::effect::fixture_policy().expect("policy"),
    )
    .expect("attempts");
    let runtime = runtime();
    let (engine, _) = runtime.block_on(load_controlled_engine(
        &setup.installation,
        "commit-mutation-worker",
        attempts,
        Flavor::StripePlain.controls(),
    ));
    let mut signal = crate::native_dependency_tests::connect(setup.installation.barrier_port);
    signal.write_all(b"R").expect("ready");
    let mut marker = [0];
    signal.read_exact(&mut marker).expect("release");
    assert_eq!(marker, *b"G");
    let result = runtime.block_on(execute(&engine, &setup.installation.root, OPERATIONS[0]));
    private(
        &setup.installation.root.join("commit-mutation-result"),
        &serde_json::to_vec(&ResultData {
            process: std::process::id(),
            result,
            errors: witness.errors(),
            witness: engine.execution_witness(),
        })
        .expect("result"),
    );
}

fn spawn(case: &MutationRace, schedule: Schedule, url: &str) -> Process {
    let path = case.setup.root.join("commit-mutation.setup");
    private(
        &path,
        &serde_json::to_vec(&json!({"installation":case.setup,"schedule":schedule}))
            .expect("setup"),
    );
    Process(Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact","native_mutation_crash_tests::window_capacity_tests::postgres_commit_tests::native_mutation_postgres_commit_peer","--nocapture"])
        .env(ENVIRONMENT,path).env("AUTHS_POSTGRES_URL",url)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().expect("native worker"))
}
fn counts(charged: bool) -> BTreeMap<String, u64> {
    let mut result = BTreeMap::from([
        ("connection".to_owned(), 1),
        ("effect-configuration".to_owned(), 1),
    ]);
    if charged {
        for kind in ["attempt", "count-slot", "sum-slot"] {
            result.insert(kind.to_owned(), 1);
        }
    }
    result
}
fn inputs_unchanged(case: &MutationRace) -> Vec<Vec<u8>> {
    ["proof", "action", "approval", "binding"]
        .map(|suffix| {
            std::fs::read(case.setup.root.join(format!("{}.{suffix}", OPERATIONS[0])))
                .expect("signed input")
        })
        .to_vec()
}

fn interrupt(case: &MutationRace, schedule: Schedule, proxy: &Proxy, url: &str) -> Barrier {
    let mut worker = spawn(case, schedule, &proxy.url(url));
    let mut signal = ready(&case.barrier);
    let mut barrier = Barrier::install_target(
        &case.store,
        operation_key(),
        CrashProtocol::Mutation,
        schedule.stage(),
    );
    signal.write_all(b"G").expect("release worker");
    let pid = barrier.waiter();
    proxy.hold_replies();
    match schedule.outcome {
        Outcome::Committed => {
            barrier.release();
            barrier.committed(schedule.retained());
            proxy.wait_for_withheld_reply();
        }
        Outcome::Aborted => {
            barrier.abort(pid);
            barrier.committed(schedule.retained());
        }
    }
    proxy.disconnect_and_resume();
    worker.finish();
    barrier.retire();
    let result: ResultData = serde_json::from_slice(
        &std::fs::read(case.setup.root.join("commit-mutation-result")).expect("result"),
    )
    .expect("native result");
    assert_ne!(result.process, std::process::id());
    assert_eq!(result.errors, 1);
    assert_eq!(
        result.witness.credential_lease_calls,
        u64::from(!matches!(schedule.phase, Phase::Admission))
    );
    assert_eq!(result.witness.read_transport_entries, 0);
    assert_eq!(
        result.witness.write_transport_entries,
        schedule.writes() as u64
    );
    match &result.result {
        GatewaySubmitResult::Indeterminate { code } => {
            assert_eq!(code, "gateway.attempt.state-unavailable");
        }
        GatewaySubmitResult::Unknown => assert!(matches!(
            schedule.retained(),
            Some("entry-granted" | "response-recorded")
        )),
        other => assert_eq!(other, &schedule.projection()),
    }
    assert_eq!(case.provider.calls(), schedule.writes());
    assert_eq!(
        case.store.postgres_gateway_record_counts(),
        counts(schedule.retained().is_some())
    );
    barrier
}

fn charges(case: &MutationRace, counters: &[Counter]) -> BTreeMap<String, Vec<u8>> {
    let mut rows = BTreeMap::new();
    for counter in counters {
        let key = counter.key(0);
        let bytes = case
            .store
            .raw()
            .load(counter.kind, &key)
            .expect("load")
            .expect("first charge");
        let value: Value = serde_json::from_slice(&bytes).expect("native charge");
        assert_eq!(value["slot"], 0);
        assert_eq!(value["operation_id"], OPERATIONS[0]);
        if counter.kind == GatewayRecordKind::SumSlot {
            assert_eq!(value["amount"], AMOUNT);
            assert_eq!(value["cumulative"], AMOUNT);
        }
        assert!(
            case.store
                .raw()
                .load(counter.kind, &counter.key(1))
                .expect("no duplicate")
                .is_none()
        );
        rows.insert(
            format!("{:?}:{}", counter.kind, hex::encode(key.as_bytes())),
            bytes,
        );
    }
    rows
}

fn reopen(
    case: &MutationRace,
    schedule: Schedule,
    counters: &[Counter],
    barrier: &mut Barrier,
) -> Value {
    let before = barrier.records();
    let prior_charges = schedule.retained().map(|_| charges(case, counters));
    let (engine, _) = case.runtime.block_on(load_controlled_engine(
        &case.setup,
        "commit-mutation-reopened",
        case.store.reopen(),
        Flavor::StripePlain.controls(),
    ));
    let operation = LogicalOperationId::parse(OPERATIONS[0]).expect("operation");
    let history = case
        .runtime
        .block_on(
            case.store
                .attempts()
                .read(Flavor::StripePlain.recipe().namespace(), &operation),
        )
        .expect("history");
    if schedule.retained().is_none() {
        assert!(history.is_none());
    } else {
        assert_eq!(
            crate::engine::stored_result(&history.expect("retained facts")),
            schedule.projection()
        );
    }
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
        assert_eq!(barrier.records(), before);
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
    let slots = charges(case, counters);
    assert_eq!(slots.len(), 2);
    if let Some(prior) = prior_charges {
        assert_eq!(slots, prior);
    }
    assert_eq!(case.store.postgres_gateway_record_counts(), counts(true));
    let record = case
        .store
        .raw()
        .load(GatewayRecordKind::Attempt, &operation_key())
        .expect("load")
        .expect("record");
    let value: Value = serde_json::from_slice(&record).expect("record");
    assert_eq!(value["evaluated_at"], NOW);
    let rows = barrier.records();
    let witness = engine.execution_witness();
    assert_eq!(
        case.runtime
            .block_on(execute(&engine, &case.setup.root, OPERATIONS[0])),
        result
    );
    assert_eq!(barrier.records(), rows);
    assert_eq!(engine.execution_witness(), witness);
    assert_eq!(charges(case, counters), slots);
    assert_eq!(case.provider.calls(), total);
    json!({"phase":schedule.phase,"outcome":schedule.outcome,"selected_commit_uses_tls":true,
        "actual_native_adapter_commit_errors":1,"independently_observed_commit_phase":schedule.retained(),
        "provider_writes_before_reopen":schedule.writes(),"new_execution_allowed":schedule.resumable(),
        "provider_writes_after_reopen":total,"native_result":result,
        "exact_native_body_captured_when_sent":true,"one_count_and_one_amount_sum_slot":true,
        "all_terminal_rows_and_execution_witness_unchanged_on_replay":true})
}

#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_mutation_commit_reply_loss_fixture_is_current() {
    assert!(postgres_configured());
    let (url, port) = fixture_url();
    let mut cases = Vec::new();
    for phase in [Phase::Admission, Phase::Entry, Phase::Response] {
        for outcome in [Outcome::Committed, Outcome::Aborted] {
            let schedule = Schedule { phase, outcome };
            let case = MutationRace::new(Backend::Postgres);
            let proxy = Proxy::start(port);
            let counters = case.runtime.block_on(inputs(
                &case.engine,
                &case.setup.root,
                OPERATIONS[0],
                Limit::Both,
            ));
            let signed = inputs_unchanged(&case);
            let mut barrier = interrupt(&case, schedule, &proxy, &url);
            let result = reopen(&case, schedule, &counters, &mut barrier);
            assert_eq!(inputs_unchanged(&case), signed);
            cases.push(result);
        }
    }
    let artifact=serde_json::to_vec_pretty(&json!({"schema":"auths.native-mutation-commit-reply-loss/1","cases":cases,
        "scope":"full native Stripe mutation with native signed bounded proof/exact approval, separate worker OS processes, actual end-to-end TLS COMMIT replies withheld by an opaque proxy, server-deferred barrier and independent TLS transaction-outcome observer, counting local provider without deduplication; fixed public test keys/clock",
        "excluded":["file faults","server or power failure","hostile OS and live-provider qualification"]})).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/native-mutation-commit-reply-loss.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("write");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), artifact);
}
