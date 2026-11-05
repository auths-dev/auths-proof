//! Actual server-rejected native mutation admission prefixes. The maintained
//! transaction must roll back its attempt, count and amount-sum rows together.
use super::*;
use crate::native_postgres_fault_tests::ready;

fn counts(admitted: bool) -> BTreeMap<String, u64> {
    let mut result = BTreeMap::from([
        ("connection".to_owned(), 1),
        ("effect-configuration".to_owned(), 1),
    ]);
    if admitted {
        for kind in ["attempt", "count-slot", "sum-slot"] {
            result.insert(kind.to_owned(), 1);
        }
    }
    result
}

fn signed_inputs(case: &MutationRace) -> Vec<Vec<u8>> {
    ["proof", "action", "approval", "binding"]
        .map(|suffix| {
            std::fs::read(case.setup.root.join(format!("{}.{suffix}", OPERATIONS[0])))
                .expect("original native input")
        })
        .to_vec()
}

fn fail(case: &MutationRace, fail_at: u64, counters: &[Counter]) {
    let input = case.setup.root.join("partial-mutation.setup");
    private(
        &input,
        &serde_json::to_vec(&json!({"installation":case.setup,
        "operation":OPERATIONS[0],"mode":WorkerMode::Contend}))
        .expect("closed worker setup"),
    );
    let mut peer = Peer::start(
        &input,
        "native_mutation_crash_tests::window_capacity_tests::native_mutation_window_peer",
        WORKER,
    );
    let mut signal = ready(&case.barrier);
    case.store.reject_postgres_batch_insert(fail_at);
    signal.write_all(b"G").expect("release initialized worker");
    peer.finish();
    let worker: WorkerResult = serde_json::from_slice(
        &std::fs::read(case.setup.root.join(format!("{}.result", OPERATIONS[0])))
            .expect("native result"),
    )
    .expect("result");
    assert_ne!(worker.process, std::process::id());
    assert_eq!(
        worker.result,
        GatewaySubmitResult::Indeterminate {
            code: "gateway.attempt.state-unavailable".to_owned()
        }
    );
    assert_eq!(
        (
            worker.witness.credential_lease_calls,
            worker.witness.write_transport_entries,
            worker.witness.read_transport_entries
        ),
        (0, 0, 0)
    );
    assert_eq!(case.provider.calls(), 0);
    assert_eq!(
        case.store.clear_postgres_batch_failure(),
        fail_at,
        "nontransactional server sequence records the rejected row prefix"
    );
    assert_eq!(case.store.postgres_gateway_record_counts(), counts(false));
    assert!(case.store.raw().attempt_keys(4).expect("keys").is_empty());
    for counter in counters {
        assert!(
            case.store
                .raw()
                .load(counter.kind, &counter.key(0))
                .expect("rolled back first slot")
                .is_none()
        );
        assert!(
            case.store
                .raw()
                .load(counter.kind, &counter.key(1))
                .expect("no hidden charge")
                .is_none()
        );
    }
}

fn reopen(case: &MutationRace, counters: &[Counter]) -> GatewaySubmitResult {
    let (engine, _) = case.runtime.block_on(load_controlled_engine(
        &case.setup,
        "partial-mutation-reopened",
        case.store.reopen(),
        Flavor::StripePlain.controls(),
    ));
    let operation = LogicalOperationId::parse(OPERATIONS[0]).expect("operation");
    assert!(
        case.runtime
            .block_on(
                case.store
                    .attempts()
                    .read(Flavor::StripePlain.recipe().namespace(), &operation)
            )
            .expect("history")
            .is_none()
    );
    let result = case
        .runtime
        .block_on(execute(&engine, &case.setup.root, OPERATIONS[0]));
    assert_eq!(
        result,
        GatewaySubmitResult::ResponseRecorded { status: 200 }
    );
    assert_eq!(case.provider.calls(), 1);
    assert_eq!(
        case.provider.requests.lock().expect("requests")[0].body,
        std::fs::read(case.setup.root.join(format!("{}.body", OPERATIONS[0])))
            .expect("exact native body")
    );
    let raw = case.store.raw();
    let key = GatewayAttemptKey::for_operation(
        &crate::effect::fixture_policy().expect("policy"),
        Flavor::StripePlain.recipe().namespace(),
        &operation,
    )
    .expect("key");
    let mut records = vec![(
        GatewayRecordKind::Attempt,
        key,
        raw.load(GatewayRecordKind::Attempt, &key)
            .expect("load")
            .expect("attempt"),
    )];
    for counter in counters {
        let bytes = raw
            .load(counter.kind, &counter.key(0))
            .expect("load")
            .expect("first slot");
        let value: Value = serde_json::from_slice(&bytes).expect("native slot");
        assert_eq!(value["slot"], 0);
        assert_eq!(value["operation_id"], OPERATIONS[0]);
        assert_eq!(value["window_seconds"], WINDOW);
        assert_eq!(value["window_index"], NOW / WINDOW);
        if counter.kind == GatewayRecordKind::SumSlot {
            assert_eq!(value["amount"], AMOUNT);
            assert_eq!(value["cumulative"], AMOUNT);
        }
        assert!(
            raw.load(counter.kind, &counter.key(1))
                .expect("no duplicate")
                .is_none()
        );
        records.push((counter.kind, counter.key(0), bytes));
    }
    let witness = engine.execution_witness();
    assert_eq!(
        case.runtime
            .block_on(execute(&engine, &case.setup.root, OPERATIONS[0])),
        result
    );
    assert_eq!(engine.execution_witness(), witness);
    assert_eq!(case.provider.calls(), 1);
    for (kind, key, bytes) in records {
        assert_eq!(
            raw.load(kind, &key).expect("replay").expect("record"),
            bytes
        );
    }
    assert_eq!(case.store.postgres_gateway_record_counts(), counts(true));
    result
}

#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_mutation_partial_batch_fixture_is_current() {
    assert!(postgres_configured());
    let cases:Vec<_> = (1..=3).map(|fail_at| {
        let case = MutationRace::new(Backend::Postgres);
        let counters = case.runtime.block_on(inputs(&case.engine,&case.setup.root,OPERATIONS[0],Limit::Both));
        assert_eq!(counters.len(),2);assert_eq!(case.store.postgres_gateway_record_counts(),counts(false));
        let signed = signed_inputs(&case);
        fail(&case,fail_at,&counters);
        assert_eq!(signed_inputs(&case),signed);
        let result = reopen(&case,&counters);
        assert_eq!(signed_inputs(&case),signed);
        json!({"server_rejected_insert":fail_at,"prior_insert_prefix":fail_at-1,
            "server_sequence":fail_at,"failed_native_worker_has_no_custody_or_transport":true,
            "all_attempt_count_and_amount_sum_rows_rolled_back":true,
            "unchanged_signed_inputs_reauthorized_after_reopen":true,"native_result":result,
            "actual_provider_writes":1,"exact_native_body_captured":true,
            "one_count_and_one_amount_sum_slot":true,"replay_changes_no_rows_or_execution_witness":true})
    }).collect();
    let artifact=serde_json::to_vec_pretty(&json!({"schema":"auths.native-mutation-postgres-partial-batch/1",
        "scope":"full native plain Stripe mutation with real TLS adapter transactions, separate initialized worker processes, server-side row-prefix exceptions and nontransactional sequence witnesses; maintained clock/public fixture keys, actual counting HTTP provider without deduplication",
        "excluded":["ambiguous commit delivery","server or power failure","file I/O faults","hostile OS and live-provider qualification"],"cases":cases})).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/native-mutation-postgres-partial-batch.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("write");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), artifact);
}
