//! Generated concurrent native histories. The independent oracle remembers
//! entered operations; real OS workers reopen durable state and use local HTTP.
use super::{Case, Outcome, author, controls, input, record, retain};
use crate::native_crash_tests::{Peer, pause_at};
use crate::native_process_tests::{NOW, Setup, load_controlled_engine, private, runtime};
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::{GatewayAttemptKey, GatewayRecordKind, GatewaySubmitResult, LogicalOperationId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write as _,
    net::TcpListener,
};

const ENVIRONMENT: &str = "AUTHS_AP074_GENERATED_HISTORY_PEER";
const SELECTOR: &str =
    "native_recovery_actor_tests::generated_history_tests::native_generated_history_peer";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Worker {
    installation: Setup,
    operation: String,
    approval_operation: String,
    result: String,
}

#[test]
fn native_generated_history_peer() {
    let Some(path) = std::env::var_os(ENVIRONMENT) else {
        return;
    };
    let worker: Worker = serde_json::from_slice(&std::fs::read(path).expect("private input"))
        .expect("closed worker input");
    let store = TestAttempts::attach(
        Backend::parse(&worker.installation.backend),
        &worker.installation.location,
    );
    let runtime = runtime();
    let (engine, _) = runtime.block_on(load_controlled_engine(
        &worker.installation,
        &worker.result,
        store.attempts().clone(),
        controls(false),
    ));
    let (proof, action, _) = input(&worker.installation.root, &worker.operation);
    let (_, _, approval) = input(&worker.installation.root, &worker.approval_operation);
    pause_at(worker.installation.barrier_port);
    let result = runtime.block_on(engine.submit(&proof, &action, approval));
    private(
        &worker.installation.root.join(&worker.result),
        &serde_json::to_vec(&json!({"pid":std::process::id(),"result":result,
            "witness":engine.execution_witness()}))
        .expect("public result"),
    );
}

fn plan(seed: u32) -> Vec<[u32; 2]> {
    let mut order = [0, 1, 2, 3].map(|index| (index + seed) % 4);
    if seed % 2 == 1 {
        order.reverse();
    }
    let mut rounds = vec![
        [order[0], order[0]],
        [order[1], order[2]],
        [order[3], order[0]],
    ];
    let mut state = seed + 1;
    for _ in 0..5 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        rounds.push([(state >> 16) % 4, (state >> 24) % 4]);
    }
    rounds
}

fn operation(index: u32) -> String {
    format!("generated-{index}")
}

fn workers(case: &Case, round: usize, operations: [&str; 2], approvals: [&str; 2]) -> [Value; 2] {
    let listener = TcpListener::bind("127.0.0.1:0").expect("start barrier");
    listener.set_nonblocking(true).expect("bounded accept");
    let mut peers = Vec::new();
    let mut paths = Vec::new();
    for slot in 0..2 {
        let mut installation = case.setup.installation.clone();
        installation.barrier_port = listener.local_addr().expect("port").port();
        let result = format!("generated-result-{round}-{slot}");
        let path = installation
            .root
            .join(format!("generated-input-{round}-{slot}"));
        paths.push(installation.root.join(&result));
        private(
            &path,
            &serde_json::to_vec(&Worker {
                installation,
                operation: operations[slot].to_owned(),
                approval_operation: approvals[slot].to_owned(),
                result,
            })
            .expect("private setup"),
        );
        peers.push(Peer::start(&path, SELECTOR, ENVIRONMENT));
    }
    let mut first = peers[0].await_pause(&listener);
    let mut second = peers[1].await_pause(&listener);
    first.write_all(b"G").expect("release first");
    second.write_all(b"G").expect("release second");
    for peer in &mut peers {
        peer.finish();
    }
    let results: [Value; 2] = paths
        .into_iter()
        .map(|path| {
            serde_json::from_slice(&std::fs::read(path).expect("worker output")).expect("result")
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("two workers");
    assert_ne!(results[0]["pid"], results[1]["pid"]);
    for result in &results {
        assert_ne!(result["pid"], json!(std::process::id()));
    }
    results
}

fn no_new_record(store: &TestAttempts, operation: &str) {
    let key = GatewayAttemptKey::for_operation(
        &crate::effect::fixture_policy().expect("policy"),
        author::recipe().namespace(),
        &LogicalOperationId::parse(operation).expect("operation"),
    )
    .expect("key");
    assert!(
        store
            .raw()
            .load(GatewayRecordKind::Attempt, &key)
            .expect("native store")
            .is_none()
    );
}

fn prepared(backend: Backend) -> Case {
    let case = Case::start(backend, Outcome::LostEcho);
    let runtime = runtime();
    let (engine, _) = runtime.block_on(load_controlled_engine(
        &case.setup.installation,
        "generated-author",
        case.store.reopen(),
        controls(false),
    ));
    for name in (0..4)
        .map(operation)
        .chain(["generated-approval-mismatch".to_owned()])
    {
        let signed = author::signed(&author::write_call(&name), false);
        let effect = runtime
            .block_on(engine.compile_effect(&signed.proof, &signed.action))
            .expect("native compile");
        retain(
            &case.setup.installation.root,
            &name,
            &signed,
            &author::approval(&effect, NOW),
        );
    }
    case
}

fn check_retained(
    case: &Case,
    entered: &BTreeSet<String>,
    retained: &mut BTreeMap<String, Vec<u8>>,
) {
    for name in entered {
        let bytes = record(&case.store, name);
        let journal: Value = serde_json::from_slice(&bytes).expect("native journal");
        assert_eq!(journal["state"]["facts"]["stage"], "unknown");
        if let Some(original) = retained.get(name) {
            assert_eq!(
                &bytes, original,
                "reopen/replay changes no historical bytes"
            );
        } else {
            retained.insert(name.clone(), bytes);
        }
    }
    assert_eq!(record(&case.store, super::SOURCE), case.original);
}

fn history(backend: Backend, seed: u32) -> Value {
    let case = prepared(backend);
    let mut entered = BTreeSet::new();
    let mut retained = BTreeMap::new();
    let mut rounds = Vec::new();
    for (index, pair) in plan(seed).into_iter().enumerate() {
        let names = pair.map(operation);
        let new_entries = names
            .iter()
            .filter(|name| !entered.contains(*name))
            .collect::<BTreeSet<_>>()
            .len();
        let before = case.provider.requests.lock().expect("HTTP capture").len();
        let results = workers(&case, index, [&names[0], &names[1]], [&names[0], &names[1]]);
        let after = case.provider.requests.lock().expect("HTTP capture").len();
        assert_eq!(
            after - before,
            new_entries,
            "independent single-grant model"
        );
        let write_entries: u64 = results
            .iter()
            .map(|result| {
                result["witness"]["write_transport_entries"]
                    .as_u64()
                    .expect("actual native witness")
            })
            .sum();
        assert_eq!(write_entries, new_entries as u64);
        for result in &results {
            let result: GatewaySubmitResult =
                serde_json::from_value(result["result"].clone()).expect("closed native result");
            assert!(
                matches!(
                    result,
                    GatewaySubmitResult::Unknown | GatewaySubmitResult::Reserved { .. }
                ),
                "a concurrent replay may observe a reservation, never a fabricated response"
            );
        }
        for name in &names {
            entered.insert(name.clone());
        }
        check_retained(&case, &entered, &mut retained);
        rounds.push(json!({"round":index,"operations":names,"expected_new_entries":new_entries,
            "actual_http_entries":after-before,"write_transport_entries":write_entries,
            "native_results":results.iter().map(|value| value["result"].clone()).collect::<Vec<_>>(),
            "distinct_os_workers":true,"historical_bytes_preserved":true}));
    }
    assert_eq!(entered.len(), 4);
    let before = case.provider.requests.lock().expect("HTTP capture").len();
    let refused = workers(
        &case,
        8,
        ["generated-approval-mismatch"; 2],
        ["generated-0"; 2],
    );
    for result in &refused {
        assert_eq!(
            result["result"],
            json!({"outcome":"not-entered","code":"gateway.effect.approval"})
        );
        assert_eq!(result["witness"]["write_transport_entries"], 0);
        assert_eq!(result["witness"]["credential_lease_calls"], 0);
    }
    assert_eq!(
        case.provider.requests.lock().expect("HTTP capture").len(),
        before
    );
    no_new_record(&case.store, "generated-approval-mismatch");
    check_retained(&case, &entered, &mut retained);
    assert_eq!(
        before, 5,
        "one baseline plus four distinct approved effects"
    );
    json!({"seed":seed,"rounds":rounds,"distinct_effect_entries":4,
        "actual_http_entries_including_baseline":before,"fresh_operation_old_approval":refused,
        "refused_operation_absent":true,"original_source_unchanged":true})
}

fn run(backend: Backend) {
    let histories: Vec<_> = (0..4).map(|seed| history(backend, seed)).collect();
    let revision = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("revision");
    assert!(revision.status.success());
    let checkout = String::from_utf8(revision.stdout).expect("revision");
    let source = std::env::var("AUTHS_EVIDENCE_SOURCE_REVISION")
        .unwrap_or_else(|_| checkout.trim().to_owned());
    assert!(source.len() == 40 && source.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let report = json!({"schema":"auths.ap074-generated-native-histories/1","source_revision":source,
        "checkout_revision":checkout.trim(),"backend":backend.label(),
        "gateway_source_closure":crate::semantic_closure::GATEWAY_SEMANTIC_CLOSURE_SHA256,
        "histories":histories,"model":"set of previously entered logical operations; no reducer predicates reused",
        "excluded":["all-protocol transition proof","capacity model","power loss","hostile OS","live provider qualification"]});
    if let Some(path) = std::env::var_os("AUTHS_AP074_HISTORY_DIRECTORY") {
        let path = std::path::PathBuf::from(path);
        std::fs::create_dir_all(&path).expect("artifact directory");
        std::fs::write(
            path.join(format!("generated-history-{}.json", backend.label())),
            serde_json::to_vec_pretty(&report).expect("artifact"),
        )
        .expect("write artifact");
    }
}

#[test]
#[ignore = "explicit process-history evidence cohort"]
fn native_file_generated_concurrent_histories() {
    run(Backend::File);
}

#[test]
#[ignore = "requires the maintained TLS PostgreSQL fixture"]
fn postgres_native_generated_concurrent_histories() {
    assert!(postgres_configured(), "TLS PostgreSQL fixture is required");
    run(Backend::Postgres);
}
