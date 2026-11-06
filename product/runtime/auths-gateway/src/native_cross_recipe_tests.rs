//! Actual gateway processes, native resource suffixes and shared ancestor
//! allocations across two recipes/configurations/connections. Public fixed
//! fixture keys and a trusted control channel; no installed isolation claim.
use crate::effect::{EffectPolicy, EngagementPolicy, ExactEffectApproval};
use crate::native_crash_tests::{CrashProtocol, PausedStore, Peer, Point, pause_at};
use crate::native_process_tests::{
    EngineControls, NOW, Setup, load_controlled_engine, private, runtime,
};
use crate::participant_enrollment::tests::{EffectScopeFixture, cross_recipe_fixture};
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::{
    CompiledRecipe, GatewayAttemptKey, GatewayAttempts, GatewayEngine, GatewayRecordKind,
    GatewaySubmitResult, LogicalOperationId, SharedConnection,
};
use auths_connections::{ConnectionAlias, ConnectionId, ConnectionRecord};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    io::{Read as _, Write as _},
    net::TcpListener,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const ENV: &str = "AUTHS_AP073_CROSS_RECIPE_PEER";
const SECRET: &[u8] = b"pat_public_cross_recipe_fixture";
const RECORD: &str = "recTEST0000000001";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    installation: Setup,
    engagement: [u8; 32],
    index: usize,
    point: Option<Point>,
    ready_barrier: bool,
}

fn recipes() -> [CompiledRecipe; 2] {
    let corpus: Value = serde_json::from_slice(include_bytes!(
        "../../../../bindings/fixtures/gateway/hostile-recipes-v2.json"
    ))
    .unwrap();
    std::array::from_fn(|index| {
        let mut source = corpus["bases"]["airtable"]["recipe"].clone();
        let mut lock = corpus["bases"]["airtable"]["lock"].clone();
        if index == 1 {
            source["service"] = json!("cross-recipe-records");
            lock["service"] = source["service"].clone();
            source["tool"] = json!("set_other_status_v1");
            lock["tool"] = source["tool"].clone();
        }
        CompiledRecipe::compile(
            &serde_json::to_vec(&source).unwrap(),
            &serde_json::to_vec(&lock).unwrap(),
        )
        .unwrap()
    })
}
fn template(recipe: &CompiledRecipe, index: usize) -> ConnectionRecord {
    let record = crate::harness::fixture_connection(recipe).unwrap();
    ConnectionRecord::new(
        record.provider_kind().clone(),
        ConnectionAlias::parse(&format!("cross-{index}")).unwrap(),
        ConnectionId::parse(format!(
            "conn_{}",
            Base64UrlUnpadded::encode_string(&[u8::try_from(index).unwrap(); 16])
        ))
        .unwrap(),
        record.contract().clone(),
        record.descriptor_schema().clone(),
        record.descriptor().to_vec(),
        *record.account_commitment(),
        *record.credential_reference_commitment(),
        record.credential_generation(),
        record.state(),
        record.allowed_workloads().to_vec(),
        record.allowed_profiles().to_vec(),
        record.created_at_unix_seconds(),
        record.updated_at_unix_seconds(),
        None,
    )
    .unwrap()
}
fn policy(root: crate::participant_enrollment::ParentEnrollmentPins, index: usize) -> EffectPolicy {
    let partition = format!(
        "cross-{}-{index}",
        hex::encode(&root.engagement_commitment[..2])
    );
    EffectPolicy::new(
        partition,
        1,
        SigningKey::from_bytes(&[29; 32]).verifying_key().to_bytes(),
    )
    .unwrap()
    .with_engagement(EngagementPolicy::new(root, "gateway".into()).unwrap())
    .unwrap()
}
fn arguments(recipe: &CompiledRecipe, index: usize) -> serde_json::Map<String, Value> {
    json!({"operation_id":format!("cross-write-{index}"),"operator_namespace":recipe.namespace().as_str(),"recipe_digest":recipe.digest_hex(),
        "record_id":RECORD,"replacement":"Approved"}).as_object().unwrap().clone()
}
fn native(
    input: &Input,
) -> (
    EffectScopeFixture,
    [crate::observed_tests::Submission; 2],
    [CompiledRecipe; 2],
    [ConnectionRecord; 2],
) {
    let recipes = recipes();
    let records: [ConnectionRecord; 2] = std::array::from_fn(|index| {
        ConnectionRecord::from_canonical_cbor(
            &std::fs::read(input.installation.root.join(format!("connection-{index}"))).unwrap(),
        )
        .unwrap()
    });
    let arguments: [_; 2] = std::array::from_fn(|index| arguments(&recipes[index], index));
    let (native, actions) = cross_recipe_fixture(
        [&recipes[0], &recipes[1]],
        [&records[0], &records[1]],
        [&arguments[0], &arguments[1]],
        input.engagement,
    );
    (native, actions, recipes, records)
}
fn controls(
    recipe: CompiledRecipe,
    record: ConnectionRecord,
    native: &EffectScopeFixture,
    index: usize,
) -> EngineControls {
    let mut controls = EngineControls::baseline();
    controls.recipe = Some(recipe);
    controls.connection = Some(record);
    controls.trust = Some(auths_codec::encode_verifier_context(&native.context).unwrap());
    controls.policy = policy(native.root.clone(), index);
    controls.credential = Some(SECRET);
    controls
}
fn load_engine(
    input: &Input,
    store: Arc<dyn crate::GatewayAttemptStore>,
) -> (GatewayEngine, crate::observed_tests::Submission) {
    let (native, mut actions, recipes, records) = native(input);
    let controls = controls(
        recipes[input.index].clone(),
        records[input.index].clone(),
        &native,
        input.index,
    );
    let attempts = GatewayAttempts::new(store, controls.policy.clone()).unwrap();
    // Each independently started fixture engine provisions its own private
    // custody copy. Reusing a filename would correctly reject a second install;
    // shared authorization state remains in the one actual adapter store.
    let mut custody_instance = [0_u8; 8];
    getrandom::fill(&mut custody_instance).unwrap();
    let (engine, record) = runtime().block_on(load_controlled_engine(
        &input.installation,
        &format!("worker-{}-{}", input.index, hex::encode(custody_instance)),
        attempts,
        controls,
    ));
    assert_eq!(record, records[input.index]);
    let action = std::mem::replace(
        &mut actions[input.index],
        crate::observed_tests::Submission {
            proof: Vec::new(),
            action: Vec::new(),
            commitment: [0; 32],
        },
    );
    (engine, action)
}
fn approval(
    engine: &GatewayEngine,
    action: &crate::observed_tests::Submission,
) -> ExactEffectApproval {
    let effect = runtime()
        .block_on(engine.compile_effect(&action.proof, &action.action))
        .unwrap();
    let request = effect.approval_request(NOW, NOW + 300).unwrap();
    let signature = SigningKey::from_bytes(&[29; 32])
        .sign(&request.signing_message().unwrap())
        .to_bytes();
    request.with_signature(signature)
}

#[test]
fn native_cross_recipe_peer() {
    let Some(path) = std::env::var_os(ENV) else {
        return;
    };
    let input: Input = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert!(input.index < 2);
    let attached = TestAttempts::attach(
        Backend::parse(&input.installation.backend),
        &input.installation.location,
    );
    let (native, _, recipes, _) = native(&input);
    let policy = policy(native.root, input.index);
    let key = GatewayAttemptKey::for_operation(
        &policy,
        recipes[input.index].namespace(),
        &LogicalOperationId::parse(&format!("cross-write-{}", input.index)).unwrap(),
    )
    .unwrap();
    let store: Arc<dyn crate::GatewayAttemptStore> = match input.point {
        Some(point) => Arc::new(PausedStore::selected(
            attached.raw(),
            key,
            CrashProtocol::Mutation,
            point,
            input.installation.barrier_port,
        )),
        None => attached.raw(),
    };
    let (engine, action) = load_engine(&input, store);
    let approved = approval(&engine, &action);
    if input.ready_barrier {
        pause_at(input.installation.barrier_port);
    }
    let result = runtime().block_on(engine.submit(&action.proof, &action.action, approved));
    private(
        &input
            .installation
            .root
            .join(format!("result-{}", input.index)),
        &serde_json::to_vec(&result).unwrap(),
    );
    private(
        &input
            .installation
            .root
            .join(format!("witness-{}", input.index)),
        &serde_json::to_vec(&engine.execution_witness()).unwrap(),
    );
}

struct Provider {
    port: u16,
    calls: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl Provider {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let stop = Arc::new(AtomicBool::new(false));
        let finished = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !finished.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("provider accept: {error}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(15)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    assert!(header.len() < 16_384);
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    header.push(byte[0]);
                }
                let header = String::from_utf8(header).unwrap();
                assert_eq!(
                    header.lines().next(),
                    Some(
                        "PATCH /v0/appTEST0000000001/tblTEST0000000001/recTEST0000000001 HTTP/1.1"
                    )
                );
                assert!(header.lines().any(|line| line.split_once(':').is_some_and(
                    |(name, value)| name.eq_ignore_ascii_case("authorization")
                        && value.trim()
                            == format!("Bearer {}", std::str::from_utf8(SECRET).unwrap())
                )));
                let length = header
                    .lines()
                    .find_map(|line| {
                        line.split_once(':')
                            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                            .map(|(_, value)| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                assert!(length <= 16_384);
                let mut body = vec![0; length];
                stream.read_exact(&mut body).unwrap();
                let body_json: Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(body_json["fields"]["DemoStatus"], "Approved");
                assert_eq!(body_json["fields"].as_object().unwrap().len(), 2);
                assert!(body_json["fields"]["auths_echo"].is_string());
                observed.fetch_add(1, Ordering::SeqCst);
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",body.len()).as_bytes()).unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        Self {
            port,
            calls,
            stop,
            worker: Some(worker),
        }
    }
    fn count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }
}

struct Case {
    _directory: tempfile::TempDir,
    store: TestAttempts,
    input: Input,
    listener: TcpListener,
    provider: Provider,
    engines: [GatewayEngine; 2],
    native: EffectScopeFixture,
}
impl Case {
    fn new(backend: Backend) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = TestAttempts::open(backend);
        let provider = Provider::start();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let input = Input {
            installation: Setup {
                backend: backend.label().into(),
                location: store.location(),
                root,
                provider_port: provider.port,
                barrier_port: listener.local_addr().unwrap().port(),
            },
            engagement: [0x31; 32],
            index: 0,
            point: None,
            ready_barrier: false,
        };
        let recipes = recipes();
        for (index, recipe) in recipes.iter().enumerate() {
            let mut controls = EngineControls::baseline();
            controls.recipe = Some(recipe.clone());
            controls.connection = Some(template(recipe, index));
            controls.credential = Some(SECRET);
            let (_, record) = runtime().block_on(load_controlled_engine(
                &input.installation,
                &format!("prepare-{index}"),
                store.attempts().clone(),
                controls,
            ));
            runtime()
                .block_on(
                    SharedConnection::new(
                        store.raw(),
                        record.provider_kind().clone(),
                        record.alias().clone(),
                    )
                    .insert(&record),
                )
                .unwrap();
            private(
                &input.installation.root.join(format!("connection-{index}")),
                &record.to_canonical_cbor().unwrap(),
            );
        }
        let (native, _, _, _) = native(&input);
        let engines = std::array::from_fn(|index| {
            let mut input = input.clone();
            input.index = index;
            load_engine(&input, store.raw()).0
        });
        for engine in &engines {
            engine.initialize_effect_configuration().unwrap();
        }
        let controller = engines[0]
            .engagement_configuration(native.root.clone())
            .unwrap();
        native.persist(&controller);
        assert_eq!(
            controller.dependency_key(),
            engines[1]
                .engagement_configuration(native.root.clone())
                .unwrap()
                .dependency_key()
        );
        Self {
            _directory: directory,
            store,
            input,
            listener,
            provider,
            engines,
            native,
        }
    }
    fn action(&self, index: usize) -> crate::observed_tests::Submission {
        let (_, mut actions, _, _) = native(&self.input);
        std::mem::replace(
            &mut actions[index],
            crate::observed_tests::Submission {
                proof: Vec::new(),
                action: Vec::new(),
                commitment: [0; 32],
            },
        )
    }
    fn start(&self, index: usize, point: Option<Point>, ready_barrier: bool) -> Peer {
        let mut input = self.input.clone();
        input.index = index;
        input.point = point;
        input.ready_barrier = ready_barrier;
        let path = input.installation.root.join(format!("input-{index}"));
        private(&path, &serde_json::to_vec(&input).unwrap());
        Peer::start(
            &path,
            "native_cross_recipe_tests::native_cross_recipe_peer",
            ENV,
        )
    }
    fn withdraw(&self) {
        let controller = self.engines[0]
            .engagement_configuration(self.native.root.clone())
            .unwrap();
        self.native.withdraw_root(&controller);
        assert!(
            self.engines[1]
                .engagement_configuration(self.native.root.clone())
                .unwrap()
                .snapshot()
                .unwrap()
                .tree()
                .active_principal_path(self.native.root.principal.as_str(), NOW)
                .is_err()
        );
    }
    fn replay(&self, index: usize) -> GatewaySubmitResult {
        let mut input = self.input.clone();
        input.index = index;
        let (engine, action) = load_engine(&input, self.store.raw());
        // Exact original approved bytes remain historical after withdrawal.
        let approved = ExactEffectApproval::from_private_bytes(
            &std::fs::read(input.installation.root.join(format!("approval-{index}"))).unwrap(),
        )
        .unwrap();
        runtime().block_on(engine.submit(&action.proof, &action.action, approved))
    }
    fn save_approvals(&self) {
        for index in 0..2 {
            let action = self.action(index);
            private(
                &self
                    .input
                    .installation
                    .root
                    .join(format!("approval-{index}")),
                &approval(&self.engines[index], &action)
                    .to_private_bytes()
                    .unwrap(),
            );
        }
    }
    fn record(&self, index: usize) -> Value {
        let (_, _, recipes, _) = native(&self.input);
        let key = GatewayAttemptKey::for_operation(
            &policy(self.native.root.clone(), index),
            recipes[index].namespace(),
            &LogicalOperationId::parse(&format!("cross-write-{index}")).unwrap(),
        )
        .unwrap();
        serde_json::from_slice(
            &self
                .store
                .raw()
                .load(GatewayRecordKind::Attempt, &key)
                .unwrap()
                .unwrap(),
        )
        .unwrap()
    }
    fn allocated_rows(&self) -> usize {
        let mut keys = BTreeSet::new();
        for index in 0..2 {
            let action = self.action(index);
            let (_, _, recipes, records) = native(&self.input);
            let candidate = self.engines[index]
                .effect_configuration_candidate()
                .unwrap();
            let policy = policy(self.native.root.clone(), index);
            let effect = crate::effect::compile_mutation_effect(
                &policy
                    .installation(
                        &recipes[index],
                        &self.native.context,
                        &records[index],
                        crate::QualificationPolicy::Optional,
                        candidate,
                    )
                    .with_enrollment(Some(&self.native.tree)),
                NOW,
                &action.proof,
                &action.action,
            )
            .unwrap();
            for reservation in effect.binding().engagement_reservations() {
                keys.insert(crate::store::fixture_engagement_allocation_key(
                    &reservation.key,
                    0,
                ));
            }
        }
        assert_eq!(
            keys.len(),
            3,
            "two children and one shared root across distinct recipes/configurations"
        );
        keys.into_iter()
            .filter(|key| {
                self.store
                    .raw()
                    .load(GatewayRecordKind::EffectAllocation, key)
                    .unwrap()
                    .is_some()
            })
            .count()
    }
}

fn race(backend: Backend) -> Value {
    let case = Case::new(backend);
    case.save_approvals();
    let wrong = case.action(0);
    let approved = approval(&case.engines[0], &wrong);
    assert!(!matches!(
        runtime().block_on(case.engines[1].submit(&wrong.proof, &wrong.action, approved)),
        GatewaySubmitResult::ResponseRecorded { .. }
    ));
    assert_eq!(case.provider.count(), 0);
    assert_eq!(case.allocated_rows(), 0);
    let mut left = case.start(0, None, true);
    let mut right = case.start(1, None, true);
    let mut a = left.await_pause(&case.listener);
    let mut b = right.await_pause(&case.listener);
    a.write_all(b"G").unwrap();
    b.write_all(b"G").unwrap();
    left.finish();
    right.finish();
    let results: Vec<GatewaySubmitResult> = (0..2)
        .map(|index| {
            serde_json::from_slice(
                &std::fs::read(case.input.installation.root.join(format!("result-{index}")))
                    .unwrap(),
            )
            .unwrap()
        })
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, GatewaySubmitResult::ResponseRecorded { .. }))
            .count(),
        1
    );
    let witnesses: Vec<crate::GatewayExecutionWitness> = (0..2)
        .map(|index| {
            serde_json::from_slice(
                &std::fs::read(
                    case.input
                        .installation
                        .root
                        .join(format!("witness-{index}")),
                )
                .unwrap(),
            )
            .unwrap()
        })
        .collect();
    assert_ne!(witnesses[0].scope, witnesses[1].scope);
    assert_eq!(
        witnesses
            .iter()
            .map(|witness| witness.write_transport_entries)
            .sum::<u64>(),
        1
    );
    assert_eq!(
        witnesses
            .iter()
            .map(|witness| witness.credential_lease_calls)
            .sum::<u64>(),
        1
    );
    assert_eq!(case.provider.count(), 1);
    assert_eq!(case.allocated_rows(), 2);
    for index in 0..2 {
        let replay = case.replay(index);
        assert_eq!(
            matches!(replay, GatewaySubmitResult::ResponseRecorded { .. }),
            matches!(results[index], GatewaySubmitResult::ResponseRecorded { .. })
        );
    }
    assert_eq!(case.provider.count(), 1);
    assert_eq!(case.allocated_rows(), 2);
    json!({"case":"two-recipes-final-shared-unit","gateway_processes":2,"recipe_count":2,"configuration_partitions":2,"connection_count":2,
        "wrong_recipe_submission_provider_calls":0,"provider_writes":1,"allocated_ancestor_rows":2,"reopened_replay_new_writes":0})
}

fn ordered(backend: Backend, after_entry: bool, kill: bool) -> Value {
    let case = Case::new(backend);
    case.save_approvals();
    let point = if after_entry {
        Point::AfterEntryCommit
    } else {
        Point::AfterReservationCommit
    };
    let mut worker = case.start(1, Some(point), false);
    let mut pause = worker.await_pause(&case.listener);
    assert_eq!(case.provider.count(), 0);
    assert_eq!(case.allocated_rows(), 2);
    let before = case.record(1);
    assert_eq!(!before["entry"].is_null(), after_entry);
    case.withdraw();
    if kill {
        worker.kill();
    } else {
        pause.write_all(b"G").unwrap();
        worker.finish();
    }
    let expected = usize::from(after_entry && !kill);
    assert_eq!(case.provider.count(), expected);
    for index in 0..2 {
        let result = case.replay(index);
        assert!(!matches!(result, GatewaySubmitResult::ResponseRecorded { .. }) || expected == 1);
    }
    assert_eq!(case.provider.count(), expected);
    assert_eq!(case.allocated_rows(), 2);
    assert_eq!(
        !case.record(1)["entry"].is_null(),
        after_entry,
        "withdrawal/replay cannot forge or erase durable entry history"
    );
    if after_entry && kill {
        assert!(matches!(case.replay(1), GatewaySubmitResult::Unknown));
    }
    json!({"case":"cross-recipe-root-withdrawal","entry_committed_before_withdrawal":after_entry,"worker_sigkill":kill,
        "withdrawal_published_by_other_recipe":true,"provider_writes":expected,"ancestor_rows_retained":2,"replay_new_writes":0})
}

fn independent_engagement(backend: Backend) -> Value {
    let case = Case::new(backend);
    case.save_approvals();
    let first = case.replay(0);
    assert!(matches!(
        first,
        GatewaySubmitResult::ResponseRecorded { .. }
    ));
    let mut input = case.input.clone();
    input.engagement = [0x32; 32];
    input.index = 1;
    let (other_native, _, _, _) = native(&input);
    let (other, action) = load_engine(&input, case.store.raw());
    other.initialize_effect_configuration().unwrap();
    let controller = other
        .engagement_configuration(other_native.root.clone())
        .unwrap();
    other_native.persist(&controller);
    assert_ne!(
        controller.dependency_key(),
        case.engines[0]
            .engagement_configuration(case.native.root.clone())
            .unwrap()
            .dependency_key()
    );
    let stale = case.action(0);
    let old_approval = approval(&case.engines[0], &stale);
    assert!(!matches!(
        runtime().block_on(other.submit(&stale.proof, &stale.action, old_approval)),
        GatewaySubmitResult::ResponseRecorded { .. }
    ));
    let approved = approval(&other, &action);
    assert!(matches!(
        runtime().block_on(other.submit(&action.proof, &action.action, approved)),
        GatewaySubmitResult::ResponseRecorded { .. }
    ));
    assert_eq!(case.provider.count(), 2);
    assert!(!matches!(
        case.replay(1),
        GatewaySubmitResult::ResponseRecorded { .. }
    ));
    assert_eq!(case.provider.count(), 2);
    json!({"case":"explicit-independent-engagement","shared_store_and_connections":true,"independent_root_capacity":true,
        "old_engagement_proof_refused":true,"provider_writes":2,"spent_first_root_stays_exhausted":true})
}
fn corpus(backend: Backend) -> Value {
    let mut cases = Vec::new();
    let mut failures = Vec::new();
    for index in 0..6 {
        let result = std::panic::catch_unwind(|| match index {
            0 => race(backend),
            1 => independent_engagement(backend),
            _ => ordered(backend, index >= 4, index % 2 == 1),
        });
        match result {
            Ok(value) => cases.push(value),
            Err(_) => failures.push(index),
        }
    }
    assert!(
        failures.is_empty(),
        "cross-recipe process case failures: {failures:?}"
    );
    json!({"schema":"auths.engagement-cross-recipe-process-vectors/1","adapter":backend.label(),"cases":cases,
        "scope":"native verification, exact independent fixed-fixture-key approval, real adapter writer fences and HTTP across independent gateway processes; controlled deployment clock",
        "not_established":["installed-key-containment","live-provider-qualification","human-presence","power-loss-durability","disconnected-escrow","full-AP073-acceptance"]})
}
#[test]
fn native_file_cross_recipe_process_fixture_is_current() {
    let report = corpus(Backend::File);
    let bytes = serde_json::to_vec_pretty(&report).unwrap();
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/engagement/cross-recipe-process.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).unwrap();
    }
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}
#[test]
#[ignore = "requires the TLS PostgreSQL fixture; CI invokes explicitly"]
fn postgres_native_cross_recipe_process_matrix() {
    assert!(postgres_configured());
    corpus(Backend::Postgres);
}
