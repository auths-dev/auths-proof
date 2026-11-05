//! Actual server exceptions must roll back every release admission row while
//! preserving its independently acquired source and lifetime charges.
use super::*;
use crate::native_postgres_fault_tests::ready;
use crate::{GatewayExecutionWitness, GatewaySubmitResult};
use std::io::{Read as _, Write as _};

const WORKER: &str = "AUTHS_AP074_DISCLOSURE_BATCH_PEER";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerResult {
    process: u32,
    result: Result<DisclosureSnapshot, GatewaySubmitResult>,
    wire_bytes: u64,
    witness: GatewayExecutionWitness,
}

async fn wire_bytes(client: UnixStream) -> u64 {
    let mut bytes = Vec::new();
    client
        .take(16_385)
        .read_to_end(&mut bytes)
        .await
        .expect("gateway EOF");
    assert!(bytes.len() <= 16_384, "bounded local wire capture");
    bytes.len() as u64
}

#[test]
fn native_disclosure_postgres_batch_peer() {
    let Some(path) = std::env::var_os(WORKER) else {
        return;
    };
    let setup: CrashSetup =
        serde_json::from_slice(&std::fs::read(path).expect("setup")).expect("closed setup");
    let store = TestAttempts::attach(
        Backend::parse(&setup.installation.backend),
        &setup.installation.location,
    );
    let runtime = runtime();
    let (engine, _) = runtime.block_on(load_controlled_engine(
        &setup.installation,
        "partial-release-worker",
        store.attempts().clone(),
        controls(Gate::Current),
    ));
    let input = Input::read(&setup.installation.root);
    let target = runtime.block_on(kit::target(&engine, &setup));
    runtime
        .block_on(engine.compile_disclosure_effect(&target, &input.proof, &input.action))
        .expect("genuine native release before failure");
    let mut signal = crate::native_dependency_tests::connect(setup.installation.barrier_port);
    signal.write_all(b"R").expect("ready");
    let mut marker = [0];
    signal.read_exact(&mut marker).expect("release");
    assert_eq!(marker, *b"G");
    let (result, wire_bytes) = runtime.block_on(async {
        let (server, client) = UnixStream::pair().expect("real local channel");
        tokio::join!(
            engine.disclose(
                &target,
                &input.proof,
                &input.action,
                input.approval,
                DisclosureConnection::new(server, setup.channel.clone())
            ),
            wire_bytes(client)
        )
    });
    private(
        &setup.installation.root.join("partial-release-result.json"),
        &serde_json::to_vec(&WorkerResult {
            process: std::process::id(),
            result,
            wire_bytes,
            witness: engine.execution_witness(),
        })
        .expect("result"),
    );
}

fn counts(admitted: bool) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::from([
        ("connection".to_owned(), 1),
        ("effect-configuration".to_owned(), 1),
        ("attempt".to_owned(), 1),
        ("effect-allocation".to_owned(), 1),
    ]);
    if admitted {
        counts.insert("attempt".to_owned(), 2);
        counts.insert("effect-allocation".to_owned(), 2);
        counts.insert("count-slot".to_owned(), 1);
        counts.insert("sum-slot".to_owned(), 1);
    }
    counts
}

fn assert_source(case: &Case) {
    assert_eq!(
        case.store
            .raw()
            .load(GatewayRecordKind::Attempt, &key(SOURCE))
            .expect("load")
            .expect("source"),
        case.source
    );
    assert_eq!(case.provider.calls.load(Ordering::SeqCst), 1);
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

fn fail(case: &Case, fail_at: u64) {
    let before = case.source_charges.records(&case.store, true);
    assert_eq!(case.store.postgres_gateway_record_counts(), counts(false));
    let input = case.setup.installation.root.join("partial-release.setup");
    private(
        &input,
        &serde_json::to_vec(&case.setup).expect("closed setup"),
    );
    let mut peer = Peer::start(
        &input,
        "native_disclosure_crash_tests::postgres_batch_tests::native_disclosure_postgres_batch_peer",
        WORKER,
    );
    let mut signal = ready(&case.listener);
    case.store.reject_postgres_batch_insert(fail_at);
    signal.write_all(b"G").expect("release initialized worker");
    peer.finish();
    let worker: WorkerResult = serde_json::from_slice(
        &std::fs::read(
            case.setup
                .installation
                .root
                .join("partial-release-result.json"),
        )
        .expect("result"),
    )
    .expect("native result");
    assert_ne!(worker.process, std::process::id());
    assert_eq!(
        worker.result,
        Err(GatewaySubmitResult::Indeterminate {
            code: "gateway.attempt.state-unavailable".to_owned()
        })
    );
    assert_eq!(
        worker.wire_bytes, 0,
        "admission failure cannot send even an authentication challenge"
    );
    assert_eq!(
        (
            worker.witness.credential_lease_calls,
            worker.witness.read_transport_entries,
            worker.witness.write_transport_entries
        ),
        (0, 0, 0)
    );
    assert_eq!(
        case.store.clear_postgres_batch_failure(),
        fail_at,
        "server sequence witnesses the rejected prefix"
    );
    assert_eq!(case.store.postgres_gateway_record_counts(), counts(false));
    assert!(
        case.store
            .raw()
            .load(GatewayRecordKind::Attempt, &key(RELEASE))
            .expect("load")
            .is_none()
    );
    assert!(case.release_charges.records(&case.store, false).is_empty());
    assert_eq!(case.source_charges.records(&case.store, true), before);
    assert_source(case);
}

fn reopen(case: &Case) -> DisclosureSnapshot {
    let (engine, _) = case.runtime.block_on(load_controlled_engine(
        &case.setup.installation,
        "partial-release-reopened",
        case.store.reopen(),
        controls(Gate::Current),
    ));
    assert!(
        case.runtime
            .block_on(engine.content_history(RELEASE))
            .is_err()
    );
    let input = Input::read(&case.setup.installation.root);
    let target = case.runtime.block_on(kit::target(&engine, &case.setup));
    let (snapshot, mut recipient) = case.runtime.block_on(async {
        let listener = UnixListener::bind(case.setup.installation.root.join("release.sock"))
            .expect("owned native endpoint");
        let recipient = Recipient::start(&case.setup, false);
        let (stream, _) = listener
            .accept()
            .await
            .expect("independent native recipient");
        let snapshot = engine
            .disclose(
                &target,
                &input.proof,
                &input.action,
                input.approval.clone(),
                DisclosureConnection::new(stream, case.setup.channel.clone()),
            )
            .await
            .expect("fresh native reauthorization");
        (snapshot, recipient)
    });
    recipient.finish(false);
    assert_eq!(snapshot.stage, DisclosureStage::Acknowledged);
    assert_eq!(
        (snapshot.reserved_deliveries, snapshot.reserved_bytes),
        (1, CONTENT.len() as u64)
    );
    assert_eq!(
        (
            snapshot.policy_count_counters,
            snapshot.policy_byte_counters
        ),
        (1, 1)
    );
    let received: Value = serde_json::from_slice(
        &std::fs::read(case.setup.installation.root.join("recipient-result.json"))
            .expect("actual recipient outcome"),
    )
    .expect("recipient");
    assert_eq!(received["received_full"], true);
    assert_eq!(received["bytes"], CONTENT.len());
    assert_replay(case, &engine, &input, &target, &snapshot);
    snapshot
}

fn assert_replay(
    case: &Case,
    engine: &GatewayEngine,
    input: &Input,
    target: &DisclosureTarget,
    snapshot: &DisclosureSnapshot,
) {
    let charges = case.release_charges.records(&case.store, true);
    assert_eq!(charges.len(), 3);
    let raw = case
        .store
        .raw()
        .load(GatewayRecordKind::Attempt, &key(RELEASE))
        .expect("load")
        .expect("release");
    let witness = engine.execution_witness();
    case.runtime.block_on(async {
        let (server, client) = UnixStream::pair().expect("replay channel");
        let (replayed, wire) = tokio::join!(
            engine.disclose(
                target,
                &input.proof,
                &input.action,
                input.approval.clone(),
                DisclosureConnection::new(server, case.setup.channel.clone())
            ),
            wire_bytes(client)
        );
        assert_eq!(&replayed.expect("historical facts"), snapshot);
        assert_eq!(wire, 0);
    });
    assert_eq!(engine.execution_witness(), witness);
    assert_eq!(
        (
            witness.credential_lease_calls,
            witness.read_transport_entries,
            witness.write_transport_entries
        ),
        (0, 0, 0)
    );
    assert_eq!(case.release_charges.records(&case.store, true), charges);
    assert_eq!(
        case.store
            .raw()
            .load(GatewayRecordKind::Attempt, &key(RELEASE))
            .expect("replay")
            .expect("record"),
        raw
    );
    assert_eq!(case.store.postgres_gateway_record_counts(), counts(true));
    assert_source(case);
}

#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_disclosure_partial_batch_fixture_is_current() {
    assert!(postgres_configured());
    let cases:Vec<_>=(1..=4).map(|fail_at| {
        let case=Case::new(Backend::Postgres,Point::BeforeReservationCommit,Gate::Current);
        fail(&case,fail_at);let snapshot=reopen(&case);
        json!({"server_rejected_insert":fail_at,"prior_insert_prefix":fail_at-1,"server_sequence":fail_at,
            "all_release_attempt_allocation_count_and_byte_rows_rolled_back":true,
            "source_attempt_and_allocations_unchanged":true,"failed_worker_has_zero_custody_provider_or_wire_bytes":true,
            "same_signed_inputs_reauthorized_after_reopen":true,"native_snapshot":snapshot,
            "independent_native_recipient_received_exact_content_and_sent_ack":true,"provider_source_reads":1,
            "additional_provider_reads":0,"one_release_allocation_count_and_sum_slot":true,
            "terminal_replay_changes_no_rows_or_witness_and_sends_zero_bytes":true})
    }).collect();
    let artifact=serde_json::to_vec_pretty(&json!({"schema":"auths.native-disclosure-postgres-partial-batch/1",
        "scope":"actual native source HTTP acquisition, independent initialized failure worker, server-side insert exceptions and sequence witnesses over maintained TLS adapter; reopened gateway authenticates a separate native recipient OS process over same-UID Unix sockets and records its exact ACK; public fixture keys and maintained clock",
        "excluded":["ambiguous commit delivery","server/power failure","file I/O faults","hostile OS or live-provider qualification"],"cases":cases})).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/native-disclosure-postgres-partial-batch.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("write");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), artifact);
}
