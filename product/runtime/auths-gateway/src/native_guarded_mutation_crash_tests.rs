//! Full maintained Stripe guards and independently journaled prerequisite reads.
//! All pauses wrap the real adapters or actual HTTP responses; no decision is
//! replaced. Fixed public keys, synthetic credential and clock are explicit.
use super::*;
use std::collections::BTreeMap;
use std::net::TcpStream;

pub(super) fn serve_read(stream: &mut TcpStream, line: &str, header: &str, pause: Option<u16>) {
    assert!(
        header
            .to_ascii_lowercase()
            .contains("stripe-version: 2025-03-31.basil\r\n")
    );
    let (status, body) = match line {
        "GET /v1/account HTTP/1.1" => (200, json!({"id":"acct_TESTHARNESS01"})),
        "GET /v1/customers HTTP/1.1" | "GET /v1/payouts HTTP/1.1" => (403, json!({})),
        "GET /v1/payment_intents/pi_public_crash_fixture HTTP/1.1" => {
            assert!(
                header
                    .to_ascii_lowercase()
                    .contains("stripe-account: acct_testharness01\r\n")
            );
            (200, json!({"amount_received":2000,"currency":"usd"}))
        }
        _ => panic!("undeclared prerequisite request: {line}"),
    };
    let body = serde_json::to_vec(&body).expect("response");
    stream.write_all(format!("HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nStripe-Version: 2025-03-31.basil\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes()).expect("response header");
    if let Some(port) = pause {
        stream.write_all(&body[..1]).expect("response prefix");
        pause_at(port);
        let _ = stream.write_all(&body[1..]);
    } else {
        stream.write_all(&body).expect("response body");
    }
}

fn children(case: &Case) -> BTreeMap<String, Vec<u8>> {
    let raw = case.store.raw();
    raw.attempt_keys(16)
        .expect("bounded inventory")
        .into_iter()
        .filter(|candidate| *candidate != key(Flavor::StripeGuarded))
        .map(|key| {
            (
                hex::encode(key.as_bytes()),
                raw.load(GatewayRecordKind::Attempt, &key)
                    .expect("load")
                    .expect("retained child"),
            )
        })
        .collect()
}

fn parent_case(backend: Backend, point: Point, gate: ResumeGate) -> Value {
    let case = Case::new(backend, Flavor::StripeGuarded, point, gate);
    assert_eq!(case.authorization.prerequisites, vec![0, 1, 2, 3]);
    assert_eq!(case.provider.read_calls(), 0);
    case.crash();
    let before = children(&case);
    let reads_at_kill = case.provider.read_calls();
    let early = matches!(
        point,
        Point::BeforeReservationCommit | Point::AfterReservationCommit
    );
    assert_eq!(reads_at_kill, if early { 0 } else { 4 });
    assert_eq!(before.len(), reads_at_kill);
    let mut result = case.reopen();
    let after = children(&case);
    assert_eq!(
        after.len(),
        if case.may_continue() { 4 } else { before.len() }
    );
    for (key, bytes) in &before {
        assert_eq!(after.get(key), Some(bytes));
    }
    assert_eq!(
        case.provider.read_calls(),
        if case.may_continue() {
            4
        } else {
            reads_at_kill
        }
    );
    result["prerequisite_reads_at_kill"] = json!(reads_at_kill);
    result["prerequisite_reads_after_replay"] = json!(case.provider.read_calls());
    result["retained_prerequisite_records"] = json!(after.len());
    result["prerequisite_evidence_not_refetched_or_retimestamped"] = json!(true);
    result
}

fn unchanged_children(
    case: &Case,
    index: u8,
    point: Point,
    before: &BTreeMap<String, Vec<u8>>,
    after: &BTreeMap<String, Vec<u8>>,
) {
    for (position, plan) in case.authorization.prerequisites.iter().enumerate() {
        let key = hex::encode(
            crate::store::fixture_prerequisite_key(key(Flavor::StripeGuarded), *plan).as_bytes(),
        );
        if position < usize::from(index)
            || matches!(point, Point::AfterResponseCommit) && position == usize::from(index)
        {
            assert_eq!(
                after.get(&key),
                before.get(&key),
                "retained complete evidence is immutable"
            );
        }
    }
}

fn child_case(backend: Backend, index: u8, point: Point) -> Value {
    let mut case = Case::new(backend, Flavor::StripeGuarded, point, ResumeGate::Current);
    case.setup.prerequisite = Some(index);
    assert_eq!(case.authorization.prerequisites, vec![0, 1, 2, 3]);
    if matches!(point, Point::DuringResponse) {
        *case.provider.pause.lock().expect("pause") = Some(ProviderPause::Read {
            index: usize::from(index),
            port: case.setup.installation.barrier_port,
        });
    }
    case.crash();
    let before = children(&case);
    let slots = case.slots(true);
    let parent_before = case.raw().expect("parent reservation");
    assert_eq!(
        PausedStore::phase_for(CrashProtocol::Mutation, OPERATION, &parent_before),
        "reserved"
    );
    let child_key = crate::store::fixture_prerequisite_key(key(Flavor::StripeGuarded), index);
    let selected = case
        .store
        .raw()
        .load(GatewayRecordKind::Attempt, &child_key)
        .expect("child");
    let expected_stage = match point {
        Point::BeforeReservationCommit => None,
        Point::AfterReservationCommit | Point::BeforeEntryCommit => Some("reserved"),
        Point::AfterResponseCommit => Some("response-recorded"),
        _ => Some("entry-granted"),
    };
    assert_eq!(
        selected
            .as_ref()
            .map(|bytes| {
                let value: Value = serde_json::from_slice(bytes).expect("child");
                value["state"]["facts"]["phase"]["stage"]
                    .as_str()
                    .expect("phase")
                    .to_owned()
            })
            .as_deref(),
        expected_stage
    );
    let read_entered = matches!(
        point,
        Point::DuringResponse | Point::BeforeResponseCommit | Point::AfterResponseCommit
    );
    let reads_at_kill = usize::from(index) + usize::from(read_entered);
    assert_eq!(case.provider.read_calls(), reads_at_kill);
    let resumable = point.resumable() || matches!(point, Point::AfterResponseCommit);
    let engine = case.reopened_engine();
    let result = case
        .runtime
        .block_on(submit(&engine, &case.setup.installation.root));
    if resumable {
        assert_eq!(
            result,
            GatewaySubmitResult::ResponseRecorded { status: 200 }
        );
    } else {
        assert!(
            matches!(result, GatewaySubmitResult::Reserved { .. }),
            "unresolved child preserves the parent reservation"
        );
    }
    assert_eq!(case.provider.calls(), usize::from(resumable));
    assert_eq!(
        case.provider.read_calls(),
        if resumable { 4 } else { reads_at_kill }
    );
    assert_eq!(case.slots(true), slots);
    let after = children(&case);
    unchanged_children(&case, index, point, &before, &after);
    let record = case.raw().expect("retained parent");
    let witness = engine.execution_witness();
    assert_eq!(
        case.runtime
            .block_on(submit(&engine, &case.setup.installation.root)),
        result
    );
    let replay_witness = engine.execution_witness();
    assert_eq!(
        replay_witness.read_transport_entries,
        witness.read_transport_entries
    );
    assert_eq!(
        replay_witness.write_transport_entries,
        witness.write_transport_entries
    );
    if resumable {
        assert_eq!(replay_witness, witness);
    }
    assert_eq!(case.raw().expect("parent"), record);
    assert_eq!(children(&case), after);
    assert_eq!(case.slots(true), slots);
    json!({"prerequisite_index":index,"pause":point,"sigkill":true,"child_stage_at_kill":expected_stage,
        "provider_reads_at_kill":reads_at_kill,"provider_reads_after_replays":case.provider.read_calls(),
        "provider_writes_after_replays":case.provider.calls(),"native_result":result,
        "parent_charges_preserved":true,"completed_child_evidence_immutable":true,"replay_creates_no_transport_entry":true,"unresolved_child_preserves_parent_reservation":!resumable})
}

fn matrix(backend: Backend) {
    let mut parents = Vec::new();
    for point in Point::ALL {
        parents.push(parent_case(backend, point, ResumeGate::Current));
    }
    for point in [Point::AfterReservationCommit, Point::BeforeEntryCommit] {
        for gate in [
            ResumeGate::ApprovalExpired,
            ResumeGate::AuthorityExpired,
            ResumeGate::Revoked,
            ResumeGate::ConfigurationReplaced,
        ] {
            parents.push(parent_case(backend, point, gate));
        }
    }
    let mut prerequisites = Vec::new();
    for index in 0..4 {
        for point in Point::ALL {
            prerequisites.push(child_case(backend, index, point));
        }
    }
    let bytes=serde_json::to_vec_pretty(&json!({"schema":"auths.native-guarded-mutation-crash/1","adapter":backend.label(),
        "scope":"maintained full Stripe recipe, real HTTP credential/relative reads and mutation, OS SIGKILL, native proof/approval and durable adapters; synthetic credential/key/clock",
        "parent_cases":parents,"prerequisite_cases":prerequisites,
        "excluded":["live provider qualification","power loss","hostile OS","human presence"]})).expect("artifact");
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-guarded-mutation-crash-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("artifact");
    }
    assert_eq!(std::fs::read(path).expect("artifact"), bytes);
}

#[test]
fn native_file_guarded_mutation_crash_fixture_is_current() {
    matrix(Backend::File);
}
#[test]
#[ignore = "requires maintained TLS PostgreSQL fixture"]
fn postgres_native_guarded_mutation_crash_fixture_is_current() {
    assert!(postgres_configured(), "TLS PostgreSQL fixture is required");
    matrix(Backend::Postgres);
}
