//! Measured native paths over the maintained adapters and real local HTTP/Unix
//! transport. Timings are observations, not release SLOs or durability proofs.
use super::{Case, Outcome, ReadResponse, author, controls};
use crate::effect::{BoundEffect, EffectBinding, ExactEffectApproval, UnixDisclosurePolicy};
use crate::harness::authoring::{ToolFixture, tool_fixture_until, tools_context};
use crate::native_process_tests::{
    CONTENT, EngineControls, NOW, Provider, Setup, load_controlled_engine, runtime,
};
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::{GatewayAttempts, GatewaySubmitResult, SharedConnection};
use auths_profile_mcp::McpToolCall;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use std::{
    future::Future,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    sync::{Arc, Mutex, atomic::Ordering},
    time::Instant,
};

#[path = "native_cost_store.rs"]
mod meter;
use meter::{AdapterCosts, MeteredStore, nanos};

const SAMPLES: usize = 8;

fn metered(store: &TestAttempts) -> (GatewayAttempts, Arc<Mutex<AdapterCosts>>) {
    let costs = Arc::new(Mutex::new(AdapterCosts::default()));
    let attempts = GatewayAttempts::new(
        Arc::new(MeteredStore {
            inner: store.raw(),
            costs: Arc::clone(&costs),
        }),
        crate::effect::fixture_policy().expect("policy"),
    )
    .expect("native attempts");
    (attempts, costs)
}

fn take(costs: &Mutex<AdapterCosts>) -> AdapterCosts {
    std::mem::take(&mut *costs.lock().expect("cost recorder"))
}

async fn prepare(
    signed: &ToolFixture,
    installed_trust: &[u8],
    now: u64,
    compilation: impl Future<Output = Result<BoundEffect, GatewaySubmitResult>>,
    costs: &Mutex<AdapterCosts>,
) -> (EffectBinding, ExactEffectApproval, Value) {
    take(costs);
    let context = auths_codec::decode_verifier_context(installed_trust).expect("installed trust");
    let started = Instant::now();
    crate::engine::verify_native(&context, now, &signed.proof, &signed.action)
        .expect("real native verification");
    let verification_ns = nanos(started);
    let started = Instant::now();
    let effect = compilation.await.expect("native compilation");
    let compilation_ns = nanos(started);
    let binding = effect.binding().clone();
    let binding_bytes = binding.to_private_bytes().expect("private binding").len();
    let review_bytes = effect
        .private_review()
        .expect("review")
        .to_private_bytes()
        .expect("review encoding")
        .len();
    let approval = author::approval(&effect, now);
    let approval_bytes = approval.to_private_bytes().expect("approval bytes").len();
    assert!(binding_bytes <= crate::effect::MAX_EFFECT_BYTES);
    assert!(review_bytes <= crate::effect::MAX_PRIVATE_EFFECT_REVIEW_BYTES);
    assert!(approval_bytes <= crate::effect::MAX_EFFECT_APPROVAL_BYTES);
    let started = Instant::now();
    effect
        .approve(
            approval.clone(),
            crate::effect::fixture_policy().expect("policy").approver(),
            now,
        )
        .expect("exact approval verification");
    let approval_ns = nanos(started);
    let result = json!({
        "verification_ns":verification_ns, "compilation_including_verification_ns":compilation_ns,
        "approval_verification_ns":approval_ns, "proof_bytes":signed.proof.len(),
        "action_bytes":signed.action.len(), "context_bytes":installed_trust.len(),
        "binding_bytes":binding_bytes, "private_review_bytes":review_bytes,
        "approval_bytes":approval_bytes, "compilation_adapter":take(costs),
    });
    (binding, approval, result)
}

fn executed(sample: &mut Value, started: Instant, costs: &Mutex<AdapterCosts>) {
    sample["execution_ns"] = json!(nanos(started));
    sample["execution_adapter"] = serde_json::to_value(take(costs)).expect("timings");
    sample["process_memory"] = process_memory();
    let calls = sample["execution_adapter"]["calls"]
        .as_array()
        .expect("actual adapter calls");
    assert!(
        calls
            .iter()
            .any(|call| call["operation"] == "fenced-insert")
    );
    assert!(
        calls
            .iter()
            .any(|call| call["operation"] == "fenced-replace")
    );
    let decisions: Vec<_> = calls
        .iter()
        .filter_map(|call| call["decision_elapsed_ns"].as_u64())
        .collect();
    assert!(
        decisions.len() >= 2,
        "actual admission and final-entry decisions"
    );
    assert!(decisions.iter().all(|ns| *ns > 0));
    assert!(
        calls
            .iter()
            .all(|call| call["snapshot_records"].as_u64().expect("count")
                <= auths_stores::MAX_GATEWAY_FENCE_RECORDS as u64)
    );
}

/// Linux process observations include the test runtime and provider task. They
/// are not allocator accounting or an independent peak for each path.
fn process_memory() -> Value {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return json!({"source":"unavailable","rss_kib":null,"cohort_peak_rss_kib":null});
    };
    let kib = |name: &str| {
        status.lines().find_map(|line| {
            line.strip_prefix(name)?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        })
    };
    json!({"source":"linux-proc-self-status","rss_kib":kib("VmRSS:"),
        "cohort_peak_rss_kib":kib("VmHWM:")})
}

async fn scan(attempts: &GatewayAttempts, costs: &Mutex<AdapterCosts>, expected: usize) -> Value {
    take(costs);
    let started = Instant::now();
    let stages = attempts
        .stages(4096)
        .await
        .expect("bounded native inventory decode");
    let elapsed = nanos(started);
    assert_eq!(stages.len(), expected);
    json!({"attempts":stages.len(),"limit":4096,"inventory_and_native_decode_ns":elapsed,
        "adapter":take(costs),"process_memory":process_memory()})
}

#[allow(
    clippy::too_many_lines,
    reason = "one measured native write/read cohort retains its real transport counters"
)]
fn mutation_and_recovery(backend: Backend) -> (Vec<Value>, Vec<Value>, Vec<Value>) {
    let case = Case::start(backend, Outcome::LostEcho);
    let runtime = runtime();
    let (attempts, costs) = metered(&case.store);
    let (writer, _) = runtime.block_on(load_controlled_engine(
        &case.setup.installation,
        "cost-writer",
        attempts.clone(),
        controls(false),
    ));
    let mut mutations = Vec::new();
    let mut recoveries = Vec::new();
    let mut scans = Vec::new();
    for index in 0..SAMPLES {
        writer
            .activate_effect_configuration(
                writer.effect_configuration_revision().expect("revision"),
            )
            .expect("writer configuration");
        let operation = format!("cost-write-{index}");
        let signed = author::signed(&author::write_call(&operation), false);
        let (_, approval, mut measurement) = runtime.block_on(prepare(
            &signed,
            &author::trust(true),
            NOW,
            writer.compile_effect(&signed.proof, &signed.action),
            &costs,
        ));
        let started = Instant::now();
        assert_eq!(
            runtime.block_on(writer.submit(&signed.proof, &signed.action, approval)),
            GatewaySubmitResult::Unknown
        );
        executed(&mut measurement, started, &costs);
        mutations.push(measurement);
        let body = case
            .provider
            .requests
            .lock()
            .expect("request capture")
            .last()
            .expect("actual mutation request")
            .body
            .clone();
        *case.provider.read_response.lock().expect("response") = Some(ReadResponse {
            status: 200,
            declared_length: body.len(),
            body,
        });
        let (reader, _) = runtime.block_on(load_controlled_engine(
            &case.setup.installation,
            &format!("cost-reader-{index}"),
            attempts.clone(),
            controls(true),
        ));
        reader
            .activate_effect_configuration(
                reader.effect_configuration_revision().expect("revision"),
            )
            .expect("independent reader configuration");
        let read = format!("cost-recovery-{index}");
        let call = runtime
            .block_on(reader.recovery_authorization_call(&operation, &read))
            .expect("native bounded recovery call");
        let signed = author::signed(&call, true);
        let (_, approval, mut measurement) = runtime.block_on(prepare(
            &signed,
            &author::trust(false),
            NOW + 1,
            reader.compile_recovery_effect(&operation, &signed.proof, &signed.action),
            &costs,
        ));
        let started = Instant::now();
        let recovered = runtime
            .block_on(Box::pin(reader.recover(
                &operation,
                &signed.proof,
                &signed.action,
                approval,
            )))
            .expect("independently authorized read");
        assert_eq!(
            recovered.source.stage(),
            crate::GatewayAttemptStage::ObservedByProvider
        );
        executed(&mut measurement, started, &costs);
        recoveries.push(measurement);
        scans.push(runtime.block_on(scan(&attempts, &costs, 1 + 2 * (index + 1))));
    }
    let requests = case
        .provider
        .requests
        .lock()
        .expect("real provider counter");
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.line.starts_with("PATCH "))
            .count(),
        SAMPLES + 1
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.line.starts_with("GET "))
            .count(),
        SAMPLES
    );
    (mutations, recoveries, scans)
}

#[allow(
    clippy::too_many_lines,
    reason = "one measured acquisition/recipient cohort retains exact native ACK and HTTP counters"
)]
fn content_and_disclosure(backend: Backend) -> (Vec<Value>, Vec<Value>, Vec<Value>) {
    let directory = tempfile::tempdir().expect("owned directory");
    let root = std::fs::canonicalize(directory.path()).expect("canonical");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("private");
    let store = TestAttempts::open(backend);
    let provider = Provider::controlled(None);
    let setup = Setup {
        backend: backend.label().to_owned(),
        location: store.location(),
        root,
        provider_port: provider.port,
        barrier_port: 0,
    };
    let recipe = crate::native_process_tests::recipe();
    let calls = [
        crate::effect::CONTENT_READ_TOOL,
        crate::effect::DISCLOSURE_TOOL,
    ]
    .map(|tool| {
        McpToolCall::new(recipe.review().service(), tool, serde_json::Map::new()).expect("tool")
    });
    let mut controls = EngineControls::baseline();
    let installed_trust = tools_context(&calls, NOW).expect("native trust");
    controls.trust = Some(installed_trust.clone());
    let (attempts, costs) = metered(&store);
    let runtime = runtime();
    let (engine, connection) = runtime.block_on(load_controlled_engine(
        &setup,
        "cost-content",
        attempts.clone(),
        controls,
    ));
    runtime
        .block_on(
            SharedConnection::new(
                store.raw(),
                connection.provider_kind().clone(),
                connection.alias().clone(),
            )
            .insert(&connection),
        )
        .expect("connection");
    engine
        .initialize_effect_configuration()
        .expect("configuration");
    let uid = std::fs::metadata(&setup.root).expect("owner").uid();
    let channel = UnixDisclosurePolicy::new(uid, uid, [57; 32]);
    let recipient = SigningKey::from_bytes(&[47; 32]);
    let mut acquisitions = Vec::new();
    let mut disclosures = Vec::new();
    let mut scans = Vec::new();
    for index in 0..SAMPLES {
        let source = format!("cost-acquire-{index}");
        let call = runtime
            .block_on(
                engine.content_authorization_call(br#"{"record_id":"recTEST0000000001"}"#, &source),
            )
            .expect("native content call");
        let signed = tool_fixture_until(&call, NOW, NOW + 3600).expect("native signed authority");
        let (_, approval, mut measurement) = runtime.block_on(prepare(
            &signed,
            &installed_trust,
            NOW,
            engine.compile_content_action(&signed.proof, &signed.action),
            &costs,
        ));
        let started = Instant::now();
        let snapshot = runtime
            .block_on(engine.acquire_content_action(&signed.proof, &signed.action, approval))
            .expect("real bounded HTTP acquisition");
        assert_eq!(snapshot.stage, crate::AcquisitionStage::ResponseRecorded);
        executed(&mut measurement, started, &costs);
        acquisitions.push(measurement);
        let target = runtime
            .block_on(engine.disclosure_target(
                &source,
                recipient.verifying_key().to_bytes(),
                channel.commitment().expect("channel"),
                [u8::try_from(index + 1).expect("bounded instance"); 32],
            ))
            .expect("retained source");
        let call = target
            .authorization_call(
                &recipe,
                &crate::LogicalOperationId::parse(&format!("cost-release-{index}"))
                    .expect("operation"),
            )
            .expect("separate disclosure call");
        let signed =
            tool_fixture_until(&call, NOW, NOW + 3600).expect("native disclosure authority");
        let (binding, approval, mut measurement) = runtime.block_on(prepare(
            &signed,
            &installed_trust,
            NOW,
            engine.compile_disclosure_effect(&target, &signed.proof, &signed.action),
            &costs,
        ));
        let started = Instant::now();
        let (delivered, received) = runtime.block_on(async {
            let (server, client) = tokio::net::UnixStream::pair().expect("real local channel");
            let receiver = async {
                let received = crate::disclosure_transport::receive_disclosure(
                    crate::disclosure_transport::DisclosureConnection::new(client, channel.clone()),
                    &binding,
                    CONTENT.len() as u64,
                    &recipient,
                )
                .await
                .expect("authenticated recipient");
                assert_eq!(received.content(), CONTENT);
                received
                    .acknowledge(&recipient)
                    .await
                    .expect("exact native ACK");
                CONTENT.len()
            };
            tokio::join!(
                engine.disclose(
                    &target,
                    &signed.proof,
                    &signed.action,
                    approval,
                    crate::disclosure_transport::DisclosureConnection::new(server, channel.clone())
                ),
                receiver
            )
        });
        assert_eq!(
            delivered.expect("native disclosure").stage,
            crate::DisclosureStage::Acknowledged
        );
        assert_eq!(received, CONTENT.len());
        executed(&mut measurement, started, &costs);
        disclosures.push(measurement);
        scans.push(runtime.block_on(scan(&attempts, &costs, 2 * (index + 1))));
    }
    assert_eq!(provider.calls.load(Ordering::SeqCst), SAMPLES);
    (acquisitions, disclosures, scans)
}

fn run(backend: Backend) {
    let (mutation, recovery, mutation_scans) = mutation_and_recovery(backend);
    let (acquisition, disclosure, information_scans) = content_and_disclosure(backend);
    let revision = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("source revision");
    assert!(revision.status.success());
    let checkout_revision = String::from_utf8(revision.stdout).expect("revision");
    let source_revision = std::env::var("AUTHS_EVIDENCE_SOURCE_REVISION")
        .unwrap_or_else(|_| checkout_revision.trim().to_owned());
    assert!(
        source_revision.len() == 40 && source_revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "exact source revision"
    );
    let report = json!({
        "schema":"auths.ap074-native-cost/1", "source_revision":source_revision,
        "checkout_revision":checkout_revision.trim(),
        "gateway_source_closure":crate::semantic_closure::GATEWAY_SEMANTIC_CLOSURE_SHA256,
        "backend":backend.label(), "samples_per_path":SAMPLES,
        "build":"test-profile; no release latency claim", "clock":"std-monotonic-instant",
        "paths":{"mutation":mutation,"recovery":recovery,"acquisition":acquisition,"disclosure":disclosure},
        "scans":{"mutation_recovery":mutation_scans,"acquisition_disclosure":information_scans},
        "enforced_bounds":{"record_bytes":auths_stores::MAX_GATEWAY_RECORD_BYTES,
            "fence_records":auths_stores::MAX_GATEWAY_FENCE_RECORDS,
            "batch_records":auths_stores::MAX_GATEWAY_BATCH_ENTRIES,
            "lock_wait_ms":auths_stores::GATEWAY_LOCK_TIMEOUT.as_millis(),
            "fence_deadline_ms":auths_stores::GATEWAY_FENCE_DEADLINE.as_millis(),
            "inventory_limit":4096},
        "limitations":["eight small local-fixture samples per path; no production latency SLO",
            "adapter elapsed includes waits and I/O; an upper bound on lock holding, not exact lock duration",
            "fenced decision timing includes native validation and encoding; no provider or custody I/O",
            "buffer sizes are boundary observations, not allocator accounting",
            "Linux RSS and cumulative high-water observations include the entire test process",
            "no power-loss, hostile OS or live-provider qualification"]
    });
    if let Some(directory) = std::env::var_os("AUTHS_AP074_COST_DIRECTORY") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory).expect("cost artifact directory");
        std::fs::write(
            directory.join(format!("native-cost-{}.json", backend.label())),
            serde_json::to_vec_pretty(&report).expect("cost artifact"),
        )
        .expect("write artifact");
    }
}

#[test]
fn native_file_cost_measurements() {
    run(Backend::File);
}

#[test]
#[ignore = "requires the maintained TLS PostgreSQL fixture"]
fn postgres_native_cost_measurements() {
    assert!(postgres_configured(), "TLS PostgreSQL fixture is required");
    run(Backend::Postgres);
}
