//! Real TLS COMMIT-reply loss at native release admission, grant, ACK and Unknown
//! persistence. Independent recipients and server observers retain distinct facts.
use super::*;
use crate::native_dependency_tests::Peer as Process;
use crate::native_postgres_commit_tests::{Barrier, CommitWitness, Outcome, Proxy, fixture_url};
use crate::native_postgres_fault_tests::ready;
use crate::{GatewayExecutionWitness, GatewaySubmitResult};
use std::{
    io::{Read as _, Write as _},
    process::{Command, Stdio},
    sync::Arc,
};
use tokio::io::AsyncWriteExt as _;

const ENVIRONMENT: &str = "AUTHS_AP074_DISCLOSURE_COMMIT_PEER";

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
    outcome: Outcome,
}
impl Schedule {
    const fn stage(self) -> &'static str {
        match self.phase {
            Phase::Admission => "reserved",
            Phase::Entry => "entry-granted",
            Phase::Acknowledgement => "acknowledged",
            Phase::Unknown => "unknown",
        }
    }
    const fn retained(self) -> Option<&'static str> {
        match self.outcome {
            Outcome::Committed => Some(self.stage()),
            Outcome::Aborted => match self.phase {
                Phase::Admission => None,
                Phase::Entry => Some("reserved"),
                Phase::Acknowledgement | Phase::Unknown => Some("entry-granted"),
            },
        }
    }
    fn resumable(self) -> bool {
        matches!(self.retained(), None | Some("reserved"))
    }
    fn delivered(self) -> bool {
        matches!(self.phase, Phase::Acknowledgement | Phase::Unknown)
    }
    fn ack_sent(self) -> bool {
        matches!(self.phase, Phase::Acknowledgement)
    }
    fn final_phase(self) -> Option<&'static str> {
        if matches!(
            (self.phase, self.outcome),
            (Phase::Acknowledgement, Outcome::Aborted)
        ) {
            Some("unknown")
        } else {
            self.retained()
        }
    }
    fn projection(self) -> DisclosureStage {
        match self.retained() {
            Some("reserved") => DisclosureStage::Reserved,
            Some("acknowledged") => DisclosureStage::Acknowledged,
            _ => DisclosureStage::Unknown,
        }
    }
}
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Role {
    Gateway,
    Recipient,
}
impl Role {
    const fn label(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::Recipient => "recipient",
        }
    }
}
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Run {
    Worker,
    Reopened,
    ReplayBeforeAck,
    ReplayAfterAck,
}
impl Run {
    const fn label(self) -> &'static str {
        match self {
            Self::Worker => "commit-worker",
            Self::Reopened => "commit-reopened",
            Self::ReplayBeforeAck => "commit-replay-before",
            Self::ReplayAfterAck => "commit-replay-after",
        }
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CommitSetup {
    installation: Setup,
    channel: UnixDisclosurePolicy,
    schedule: Schedule,
    role: Role,
    run: Run,
}
impl CommitSetup {
    fn path(&self, suffix: &str) -> std::path::PathBuf {
        self.installation
            .root
            .join(format!("{}.{suffix}", self.run.label()))
    }
    async fn target(&self, engine: &GatewayEngine) -> DisclosureTarget {
        engine
            .disclosure_target(
                SOURCE,
                SigningKey::from_bytes(&[47; 32]).verifying_key().to_bytes(),
                self.channel.commitment().expect("channel"),
                [52; 32],
            )
            .await
            .expect("retained native source")
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecipientResult {
    process: u32,
    bytes: u64,
    ack_sent: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResultData {
    process: u32,
    result: Result<DisclosureSnapshot, GatewaySubmitResult>,
    errors: u64,
    witness: GatewayExecutionWitness,
    recipient: RecipientResult,
    challenge_sent: bool,
    content_wire_bytes: u64,
}

fn spawn(setup: &CommitSetup, role: Role, url: Option<&str>) -> Process {
    let path = setup.path(&format!("{}.setup", role.label()));
    private(
        &path,
        &serde_json::to_vec(
            &json!({"installation":setup.installation,"channel":setup.channel,
        "schedule":setup.schedule,"role":role,"run":setup.run}),
        )
        .expect("setup"),
    );
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command.args(["--exact","native_disclosure_crash_tests::postgres_commit_tests::native_disclosure_postgres_commit_peer","--nocapture"])
        .env(ENVIRONMENT,path).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    if let Some(url) = url {
        command.env("AUTHS_POSTGRES_URL", url);
    }
    Process(command.spawn().expect("independent native peer"))
}

async fn recipient(setup: &CommitSetup) {
    let stream = UnixStream::connect(setup.path("sock"))
        .await
        .expect("native gateway endpoint");
    let binding = EffectBinding::from_private_bytes(
        &std::fs::read(setup.installation.root.join("release.binding")).expect("reviewed binding"),
    )
    .expect("binding");
    let signer = SigningKey::from_bytes(&[47; 32]);
    let received = crate::disclosure_transport::receive_disclosure(
        DisclosureConnection::new(stream, setup.channel.clone()),
        &binding,
        CONTENT.len() as u64,
        &signer,
    )
    .await;
    let (bytes, ack_sent) = match received {
        Ok(received) => {
            assert_eq!(received.content(), CONTENT);
            let ack = received
                .acknowledgement(&signer)
                .expect("native received ACK");
            private(
                &setup.path("ack"),
                &ack.to_private_bytes().expect("private ACK"),
            );
            if !matches!(setup.schedule.phase, Phase::Unknown) || !matches!(setup.run, Run::Worker)
            {
                received
                    .acknowledge(&signer)
                    .await
                    .expect("native ACK send");
                (CONTENT.len() as u64, true)
            } else {
                drop(received);
                (CONTENT.len() as u64, false)
            }
        }
        Err(code) => {
            assert_eq!(code, "gateway.disclosure.read");
            (0, false)
        }
    };
    private(
        &setup.path("recipient-result"),
        &serde_json::to_vec(&RecipientResult {
            process: std::process::id(),
            bytes,
            ack_sent,
        })
        .expect("result"),
    );
}

async fn relay(gateway: UnixStream, recipient: UnixStream) -> (bool, u64) {
    let (mut from_gateway, mut to_gateway) = gateway.into_split();
    let (mut from_recipient, mut to_recipient) = recipient.into_split();
    let outbound = async {
        let mut captured = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            let count = from_gateway.read(&mut buffer).await.expect("capture read");
            if count == 0 {
                break;
            }
            assert!(captured.len() + count <= 16_384);
            captured.extend_from_slice(&buffer[..count]);
            to_recipient
                .write_all(&buffer[..count])
                .await
                .expect("opaque forwarding");
        }
        to_recipient.shutdown().await.expect("forward EOF");
        if captured.is_empty() {
            return (false, 0);
        }
        let length = u32::from_be_bytes(
            captured
                .get(..4)
                .expect("complete challenge prefix")
                .try_into()
                .expect("four bytes"),
        ) as usize;
        let content = captured
            .get(4 + length..)
            .expect("complete challenge frame");
        if !content.is_empty() {
            assert_eq!(content.len(), 4 + CONTENT.len());
            assert_eq!(
                &content[..4],
                &u32::try_from(CONTENT.len())
                    .expect("bounded content")
                    .to_be_bytes()
            );
            assert_eq!(&content[4..], CONTENT);
        }
        (true, content.len() as u64)
    };
    let inbound = async {
        tokio::io::copy(&mut from_recipient, &mut to_gateway)
            .await
            .expect("opaque ACK forwarding");
        to_gateway.shutdown().await.expect("recipient EOF");
    };
    let (result, ()) = tokio::join!(outbound, inbound);
    result
}

async fn delivery(engine: &GatewayEngine, setup: &CommitSetup, signal: bool) -> ResultData {
    let input = Input::read(&setup.installation.root);
    let target = setup.target(engine).await;
    let listener = UnixListener::bind(setup.path("sock")).expect("owned gateway socket");
    let mut receiver = spawn(setup, Role::Recipient, None);
    let receiver_pid = receiver.0.id();
    let (recipient, _) = listener.accept().await.expect("independent recipient");
    if signal {
        let mut channel = crate::native_dependency_tests::connect(setup.installation.barrier_port);
        channel.write_all(b"R").expect("ready");
        let mut marker = [0];
        channel.read_exact(&mut marker).expect("release");
        assert_eq!(marker, *b"G");
    }
    let (server, recorder) = UnixStream::pair().expect("opaque recorder channel");
    let (result, (challenge_sent, content_wire_bytes)) = tokio::join!(
        engine.disclose(
            &target,
            &input.proof,
            &input.action,
            input.approval,
            DisclosureConnection::new(server, setup.channel.clone())
        ),
        relay(recorder, recipient)
    );
    receiver.finish();
    let recipient: RecipientResult = serde_json::from_slice(
        &std::fs::read(setup.path("recipient-result")).expect("recipient outcome"),
    )
    .expect("result");
    assert_eq!(recipient.process, receiver_pid);
    assert_ne!(recipient.process, std::process::id());
    ResultData {
        process: std::process::id(),
        result,
        errors: 0,
        witness: engine.execution_witness(),
        recipient,
        challenge_sent,
        content_wire_bytes,
    }
}

#[test]
fn native_disclosure_postgres_commit_peer() {
    let Some(path) = std::env::var_os(ENVIRONMENT) else {
        return;
    };
    let setup: CommitSetup =
        serde_json::from_slice(&std::fs::read(path).expect("setup")).expect("closed setup");
    let runtime = runtime();
    match setup.role {
        Role::Recipient => runtime.block_on(recipient(&setup)),
        Role::Gateway => {
            let store = TestAttempts::attach(Backend::Postgres, &setup.installation.location);
            let witness = Arc::new(CommitWitness::new(
                store.raw(),
                key(RELEASE),
                CrashProtocol::Disclosure,
                setup.schedule.stage(),
            ));
            let attempts = GatewayAttempts::new(
                witness.clone(),
                crate::effect::fixture_policy().expect("policy"),
            )
            .expect("attempts");
            let (engine, _) = runtime.block_on(load_controlled_engine(
                &setup.installation,
                "commit-release-worker",
                attempts,
                controls(Gate::Current),
            ));
            let mut result = runtime.block_on(delivery(&engine, &setup, true));
            result.errors = witness.errors();
            private(
                &setup.path("result"),
                &serde_json::to_vec(&result).expect("native result"),
            );
        }
    }
}

fn counts(charged: bool) -> BTreeMap<String, u64> {
    let mut result = BTreeMap::from([
        ("connection".to_owned(), 1),
        ("effect-configuration".to_owned(), 1),
        ("attempt".to_owned(), 1),
        ("effect-allocation".to_owned(), 1),
    ]);
    if charged {
        result.insert("attempt".to_owned(), 2);
        result.insert("effect-allocation".to_owned(), 2);
        result.insert("count-slot".to_owned(), 1);
        result.insert("sum-slot".to_owned(), 1);
    }
    result
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
    for (name, bytes) in ["release.proof", "release.action", "release.approval"]
        .iter()
        .zip(&case.signed_inputs)
    {
        assert_eq!(
            &std::fs::read(case.setup.installation.root.join(name)).expect("original signed input"),
            bytes
        );
    }
}
fn setup(case: &Case, schedule: Schedule, run: Run) -> CommitSetup {
    serde_json::from_value(
        json!({"installation":case.setup.installation,"channel":case.setup.channel,
        "schedule":schedule,"role":Role::Gateway,"run":run}),
    )
    .expect("closed fixture setup")
}

fn interrupt(case: &Case, setup: &CommitSetup, proxy: &Proxy, url: &str) -> Barrier {
    let mut worker = spawn(setup, Role::Gateway, Some(&proxy.url(url)));
    let mut signal = ready(&case.listener);
    let mut barrier = Barrier::install_target(
        &case.store,
        key(RELEASE),
        CrashProtocol::Disclosure,
        setup.schedule.stage(),
    );
    signal.write_all(b"G").expect("release worker");
    let pid = barrier.waiter();
    proxy.hold_replies();
    match setup.schedule.outcome {
        Outcome::Committed => {
            barrier.release();
            barrier.committed(setup.schedule.retained());
            proxy.wait_for_withheld_reply();
        }
        Outcome::Aborted => {
            barrier.abort(pid);
            barrier.committed(setup.schedule.retained());
        }
    }
    proxy.disconnect_and_resume();
    worker.finish();
    barrier.retire();
    let result: ResultData =
        serde_json::from_slice(&std::fs::read(setup.path("result")).expect("result"))
            .expect("native result");
    assert_ne!(result.process, std::process::id());
    assert_ne!(result.process, result.recipient.process);
    assert_eq!(result.errors, 1);
    assert_eq!(
        (
            result.witness.credential_lease_calls,
            result.witness.read_transport_entries,
            result.witness.write_transport_entries
        ),
        (0, 0, 0)
    );
    match result.result {
        Ok(snapshot) => {
            assert!(setup.schedule.retained().is_some());
            assert_eq!(snapshot.stage, setup.schedule.projection());
        }
        Err(GatewaySubmitResult::Indeterminate { code }) => {
            assert_eq!(code, "gateway.attempt.state-unavailable")
        }
        Err(other) => panic!("unexpected projection: {other:?}"),
    }
    assert_eq!(
        result.recipient.bytes,
        if setup.schedule.delivered() {
            CONTENT.len() as u64
        } else {
            0
        }
    );
    assert_eq!(result.recipient.ack_sent, setup.schedule.ack_sent());
    assert_eq!(
        result.content_wire_bytes,
        if setup.schedule.delivered() {
            (CONTENT.len() + 4) as u64
        } else {
            0
        }
    );
    assert_eq!(
        result.challenge_sent,
        !matches!(setup.schedule.phase, Phase::Admission)
    );
    barrier.committed(setup.schedule.final_phase());
    assert_eq!(
        case.store.postgres_gateway_record_counts(),
        counts(setup.schedule.retained().is_some())
    );
    assert_source(case);
    barrier
}

fn assert_replay(
    case: &Case,
    engine: &GatewayEngine,
    control: &CommitSetup,
    expected: &DisclosureSnapshot,
    barrier: &mut Barrier,
    run: Run,
) {
    let rows = barrier.records();
    let witness = engine.execution_witness();
    let replay = setup(case, control.schedule, run);
    let result = case.runtime.block_on(delivery(engine, &replay, false));
    assert_eq!(&result.result.expect("retained facts"), expected);
    assert_eq!(result.recipient.bytes, 0);
    assert!(!result.recipient.ack_sent);
    assert!(!result.challenge_sent);
    assert_eq!(result.content_wire_bytes, 0);
    assert_eq!(engine.execution_witness(), witness);
    assert_eq!(barrier.records(), rows);
    assert_source(case);
}

fn late_ack(
    case: &Case,
    engine: &GatewayEngine,
    control: &CommitSetup,
    snapshot: &DisclosureSnapshot,
    barrier: &mut Barrier,
) -> bool {
    let run = if control.schedule.resumable() {
        Run::Reopened
    } else {
        Run::Worker
    };
    let acknowledged = setup(case, control.schedule, run);
    let path = acknowledged.path("ack");
    if !path.exists() {
        assert!(matches!(
            (control.schedule.phase, control.schedule.outcome),
            (Phase::Entry, Outcome::Committed)
        ));
        assert_eq!(snapshot.stage, DisclosureStage::Unknown);
        return false;
    }
    let ack = DisclosureAcknowledgement::from_private_bytes(
        &std::fs::read(path).expect("actual native ACK"),
    )
    .expect("ACK");
    let mut before = barrier.records();
    let charges = case.release_charges.records(&case.store, true);
    let witness = engine.execution_witness();
    let after = case
        .runtime
        .block_on(engine.acknowledge_disclosure(RELEASE, &ack))
        .expect("genuine historical ACK");
    assert_eq!(after.stage, DisclosureStage::Acknowledged);
    assert_eq!(engine.execution_witness(), witness);
    assert_eq!(case.release_charges.records(&case.store, true), charges);
    let mut retained = barrier.records();
    let release = format!("attempt:{}", hex::encode(key(RELEASE).as_bytes()));
    before.remove(&release);
    retained.remove(&release);
    assert_eq!(retained, before);
    assert_replay(case, engine, control, &after, barrier, Run::ReplayAfterAck);
    true
}

fn reopen(case: &Case, control: &CommitSetup, barrier: &mut Barrier) -> Value {
    let before = barrier.records();
    let source_charges = case.source_charges.records(&case.store, true);
    let prior_release_charges = control
        .schedule
        .retained()
        .map(|_| case.release_charges.records(&case.store, true));
    let (engine, _) = case.runtime.block_on(load_controlled_engine(
        &case.setup.installation,
        "commit-release-reopened",
        case.store.reopen(),
        controls(Gate::Current),
    ));
    let history = case.runtime.block_on(engine.content_history(RELEASE));
    if control.schedule.retained().is_none() {
        assert!(history.is_err());
    } else {
        let ContentHistory::Disclosure(actual) = history.expect("history") else {
            panic!("wrong protocol");
        };
        assert_eq!(actual.stage, control.schedule.projection());
    }
    let snapshot = if control.schedule.resumable() {
        let fresh = setup(case, control.schedule, Run::Reopened);
        let result = case.runtime.block_on(delivery(&engine, &fresh, false));
        assert_eq!(result.recipient.bytes, CONTENT.len() as u64);
        assert!(result.recipient.ack_sent);
        assert!(result.challenge_sent);
        assert_eq!(result.content_wire_bytes, (CONTENT.len() + 4) as u64);
        let result = result.result.expect("native reauthorization");
        assert_eq!(result.stage, DisclosureStage::Acknowledged);
        result
    } else {
        let ContentHistory::Disclosure(snapshot) = case
            .runtime
            .block_on(engine.content_history(RELEASE))
            .expect("history")
        else {
            panic!("protocol");
        };
        assert_eq!(barrier.records(), before);
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
    let release_charges = case.release_charges.records(&case.store, true);
    assert_eq!(release_charges.len(), 3);
    if let Some(prior) = prior_release_charges {
        assert_eq!(release_charges, prior);
    }
    assert_eq!(
        case.source_charges.records(&case.store, true),
        source_charges
    );
    assert_replay(
        case,
        &engine,
        control,
        &snapshot,
        barrier,
        Run::ReplayBeforeAck,
    );
    let historical_ack = late_ack(case, &engine, control, &snapshot, barrier);
    assert_eq!(case.store.postgres_gateway_record_counts(), counts(true));
    assert_source(case);
    json!({"phase":control.schedule.phase,"outcome":control.schedule.outcome,"selected_commit_uses_tls":true,
        "actual_native_adapter_commit_errors":1,"independent_commit_phase":control.schedule.retained(),
        "post_error_native_phase":control.schedule.final_phase(),"new_delivery_allowed":control.schedule.resumable(),
        "recipient_deliveries":usize::from(control.schedule.delivered()||control.schedule.resumable()),
        "native_snapshot_before_historical_ack":snapshot,"native_historical_ack_refined_or_replayed":historical_ack,
        "provider_source_reads":1,"additional_provider_or_custody_calls":0,"one_allocation_count_and_byte_sum_slot":true,
        "existing_source_and_charges_conserved":true,"terminal_replay_has_zero_wire_bytes_and_no_journal_or_witness_change":true})
}

#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_disclosure_commit_reply_loss_fixture_is_current() {
    assert!(postgres_configured());
    let (url, port) = fixture_url();
    let mut cases = Vec::new();
    for phase in [
        Phase::Admission,
        Phase::Entry,
        Phase::Acknowledgement,
        Phase::Unknown,
    ] {
        for outcome in [Outcome::Committed, Outcome::Aborted] {
            let schedule = Schedule { phase, outcome };
            let case = Case::new(
                Backend::Postgres,
                Point::BeforeReservationCommit,
                Gate::Current,
            );
            let control = setup(&case, schedule, Run::Worker);
            let proxy = Proxy::start(port);
            let mut barrier = interrupt(&case, &control, &proxy, &url);
            cases.push(reopen(&case, &control, &mut barrier));
        }
    }
    let artifact=serde_json::to_vec_pretty(&json!({"schema":"auths.native-disclosure-commit-reply-loss/1","cases":cases,
        "scope":"actual native HTTP source acquisition, native release gateway and recipient in independent OS processes, real TLS COMMIT replies withheld by opaque proxy, independently observed committed/aborted outcomes; native Unix authentication, exact received ACKs and opaque gateway wire capture; fixed public fixture keys/clock, same-UID local processes",
        "excluded":["file faults","server or power failure","hostile OS or live-provider qualification"]})).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/native-disclosure-commit-reply-loss.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("write");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), artifact);
}
