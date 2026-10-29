//! Native engine processes over both durable adapters and real local HTTP.
//! Fixed public test keys/clock and a trusted test control channel are explicit;
//! no human-presence, hostile-process isolation or provider qualification claim.
#![cfg(all(unix, feature = "loopback-provider", feature = "testkit-harness"))]

use crate::effect::{CONTENT_READ_TOOL, ExactEffectApproval, fixture_policy};
use crate::harness::authoring::{
    ToolFixture, tool_fixture_until, tool_fixture_using_policy, tools_context,
};
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::{
    AcquisitionSnapshot, AcquisitionStage, CompiledRecipe, GatewayAttempts, GatewayEngine,
    GatewaySubmitResult, QualificationGate, QualificationPolicy, SharedConnection,
};
use auths_connections::{
    ConnectionCredentialStore as _, ConnectionRecord, PersistentCredentialStore, SecretBytes,
};
use auths_profile_mcp::McpToolCall;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub(super) const NOW: u64 = 1_790_000_000;
const SECRET: &[u8] = b"public-native-process-fixture";
pub(super) const CONTENT: &[u8] = b"PUBLIC-NATIVE-CONTENT";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Setup {
    pub(super) backend: String,
    pub(super) location: String,
    pub(super) root: PathBuf,
    pub(super) provider_port: u16,
    pub(super) barrier_port: u16,
}

pub(super) fn private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("private input");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("private mode");
}
pub(super) fn recipe() -> CompiledRecipe {
    CompiledRecipe::compile(
        include_bytes!("../../../../bindings/fixtures/gateway/content-only/recipe.json"),
        include_bytes!("../../../../bindings/fixtures/gateway/content-only/profile.lock.json"),
    )
    .expect("recipe")
}
fn trust(recipe: &CompiledRecipe) -> Vec<u8> {
    let call = McpToolCall::new(
        recipe.review().service(),
        CONTENT_READ_TOOL,
        serde_json::Map::new(),
    )
    .expect("tool");
    tools_context(&[call], NOW).expect("native trust")
}
pub(super) fn runtime() -> tokio::runtime::Runtime {
    // Each case also creates independent OS workers. Bound test executor
    // resources rather than multiplying the host's reported CPU count.
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

pub(super) struct EngineControls {
    pub(super) policy: crate::effect::EffectPolicy,
    pub(super) clock: Arc<crate::FixedClock>,
    pub(super) recipe: Option<CompiledRecipe>,
    pub(super) trust: Option<Vec<u8>>,
}
impl EngineControls {
    pub(super) fn baseline() -> Self {
        Self {
            policy: fixture_policy().expect("policy"),
            clock: Arc::new(crate::FixedClock::at(NOW)),
            recipe: None,
            trust: None,
        }
    }
}

pub(super) async fn load_engine(
    setup: &Setup,
    label: &str,
    attempts: GatewayAttempts,
) -> (GatewayEngine, ConnectionRecord) {
    load_controlled_engine(setup, label, attempts, EngineControls::baseline()).await
}

pub(super) async fn load_controlled_engine(
    setup: &Setup,
    label: &str,
    attempts: GatewayAttempts,
    controls: EngineControls,
) -> (GatewayEngine, ConnectionRecord) {
    let recipe = controls.recipe.unwrap_or_else(recipe);
    let trust = controls.trust.unwrap_or_else(|| trust(&recipe));
    let initial = crate::harness::fixture_connection(&recipe).expect("connection template");
    let credentials = Arc::new(
        PersistentCredentialStore::open(setup.root.join(format!("custody-{label}.cbor")))
            .expect("custody"),
    );
    let reference = credentials
        .install(
            initial.connection_id(),
            initial.credential_generation(),
            SecretBytes::new(SECRET.to_vec()).expect("synthetic credential"),
        )
        .await
        .expect("credential install");
    let record = ConnectionRecord::new(
        initial.provider_kind().clone(),
        initial.alias().clone(),
        initial.connection_id().clone(),
        initial.contract().clone(),
        initial.descriptor_schema().clone(),
        initial.descriptor().to_vec(),
        *initial.account_commitment(),
        *reference.as_bytes(),
        initial.generation(),
        initial.state(),
        initial.allowed_workloads().to_vec(),
        initial.allowed_profiles().to_vec(),
        initial.created_at_unix_seconds(),
        initial.updated_at_unix_seconds(),
        None,
    )
    .expect("record");
    let gate = Arc::new(QualificationGate::new(
        QualificationPolicy::Optional,
        None,
        None,
        Box::new(controls.clock),
        auths_recipe_qualification::VerifierState::default(),
    ));
    gate.load(&crate::QualificationBundle {
        signer_certificate: Vec::new(),
        revocation_list: Vec::new(),
        release_index: Vec::new(),
        records: Vec::new(),
        attestations: Vec::new(),
    });
    let profile = record.allowed_profiles()[0].clone();
    let engine = GatewayEngine::new(
        recipe.clone(),
        *recipe.digest(),
        &trust,
        controls.policy,
        record.provider_kind().clone(),
        record.alias().clone(),
        "gateway".to_owned(),
        profile,
        credentials,
        attempts,
    )
    .expect("engine")
    .with_qualification(gate)
    .with_loopback_provider(setup.provider_port);
    (engine, record)
}

pub(super) async fn authorize(engine: &GatewayEngine, root: &Path, operation: &str) {
    authorize_bounded(engine, root, operation, NOW + 86_400, NOW + 300).await;
}

pub(super) async fn authorize_bounded(
    engine: &GatewayEngine,
    root: &Path,
    operation: &str,
    authority_until: u64,
    approval_until: u64,
) {
    let call = engine
        .content_authorization_call(br#"{"record_id":"recTEST0000000001"}"#, operation)
        .await
        .expect("native call");
    let signed = tool_fixture_until(&call, NOW, authority_until).expect("native authority");
    save_authorization(engine, root, operation, signed, approval_until).await;
}

pub(super) async fn authorize_policy(
    engine: &GatewayEngine,
    root: &Path,
    operation: &str,
    policy: &crate::ArgumentCeilingPolicy,
) {
    let call = engine
        .content_authorization_call(br#"{"record_id":"recTEST0000000001"}"#, operation)
        .await
        .expect("native call");
    let signed = tool_fixture_using_policy(&call, NOW, NOW + 86_400, Some(policy))
        .expect("native bounded authority");
    save_authorization(engine, root, operation, signed, NOW + 300).await;
}

async fn save_authorization(
    engine: &GatewayEngine,
    root: &Path,
    operation: &str,
    signed: ToolFixture,
    approval_until: u64,
) {
    assert_eq!(signed.context, trust(&recipe()));
    let effect = engine
        .compile_content_action(&signed.proof, &signed.action)
        .await
        .expect("native effect");
    let request = effect
        .approval_request(NOW, approval_until)
        .expect("review request");
    let key = SigningKey::from_bytes(&[29; 32]);
    let signature = key
        .sign(&request.signing_message().expect("message"))
        .to_bytes();
    let approval = request.with_signature(signature);
    for (suffix, bytes) in [
        ("proof", signed.proof),
        ("action", signed.action),
        (
            "approval",
            approval.to_private_bytes().expect("approval").to_vec(),
        ),
    ] {
        private(&root.join(format!("{operation}.{suffix}")), &bytes);
    }
}
pub(super) async fn acquire(
    engine: &GatewayEngine,
    root: &Path,
    operation: &str,
) -> Result<AcquisitionSnapshot, GatewaySubmitResult> {
    let load =
        |suffix| std::fs::read(root.join(format!("{operation}.{suffix}"))).expect("native input");
    let approval = ExactEffectApproval::from_private_bytes(&load("approval")).expect("approval");
    engine
        .acquire_content_action(&load("proof"), &load("action"), approval)
        .await
}

pub(super) struct Provider {
    pub(super) port: u16,
    pub(super) calls: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Provider {
    fn start() -> Self {
        Self::controlled(None)
    }
    pub(super) fn controlled(mut pause: Option<Box<dyn FnOnce() + Send>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("provider");
        let port = listener.local_addr().expect("address").port();
        listener.set_nonblocking(true).expect("nonblocking");
        let calls = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let observed = calls.clone();
        let finished = stop.clone();
        let thread = thread::spawn(move || {
            while !finished.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("accept: {error}"),
                };
                stream.set_nonblocking(false).expect("blocking");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("deadline");
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .expect("deadline");
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    assert!(header.len() < 8192);
                    let mut byte = [0];
                    stream.read_exact(&mut byte).expect("header");
                    header.push(byte[0]);
                }
                let header = String::from_utf8(header).expect("header UTF8");
                assert_eq!(
                    header.lines().next(),
                    Some("GET /documents/recTEST0000000001?format=text%2Fplain HTTP/1.1")
                );
                assert!(
                    header
                        .to_ascii_lowercase()
                        .contains("authorization: bearer public-native-process-fixture\r\n")
                );
                observed.fetch_add(1, Ordering::SeqCst);
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",CONTENT.len()).as_bytes()).expect("response headers");
                if let Some(pause) = pause.take() {
                    stream.write_all(&CONTENT[..1]).expect("partial response");
                    pause();
                    // The crash case deliberately kills the receiving process.
                    let _ = stream.write_all(&CONTENT[1..]);
                } else {
                    stream.write_all(CONTENT).expect("response body");
                }
            }
        });
        Self {
            port,
            calls,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !std::thread::panicking() {
                result.expect("provider thread");
            }
        }
    }
}
pub(super) struct Peer(Child);
impl Peer {
    pub(super) fn id(&self) -> u32 {
        self.0.id()
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// This helper is invoked in fresh OS processes by the parent; ordinary test
/// discovery with no private fixture input does no work.
#[test]
fn native_capacity_peer() {
    let Some(input) = std::env::var_os("AUTHS_AP074_CAPACITY_PEER") else {
        return;
    };
    let input = PathBuf::from(input);
    let setup: Setup =
        serde_json::from_slice(&std::fs::read(input).expect("setup")).expect("closed setup");
    let operation = std::env::var("AUTHS_AP074_CAPACITY_OPERATION").expect("operation");
    let store = TestAttempts::attach(Backend::parse(&setup.backend), &setup.location);
    let runtime = runtime();
    let (engine, _) = runtime.block_on(load_engine(&setup, &operation, store.attempts().clone()));
    let mut signal = TcpStream::connect(("127.0.0.1", setup.barrier_port)).expect("parent barrier");
    signal
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("barrier deadline");
    signal.write_all(b"R").expect("ready");
    let mut start = [0];
    signal.read_exact(&mut start).expect("start");
    assert_eq!(start, *b"G");
    let result = runtime.block_on(acquire(&engine, &setup.root, &operation));
    private(
        &setup.root.join(format!("{operation}.witness")),
        &serde_json::to_vec(&engine.execution_witness()).expect("execution witness"),
    );
    private(
        &setup.root.join(format!("{operation}.result")),
        &serde_json::to_vec(&result).expect("native result"),
    );
}

pub(super) fn start_peer(input: &Path, operation: &str) -> Peer {
    Peer(
        Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "native_process_tests::native_capacity_peer",
                "--nocapture",
            ])
            .env("AUTHS_AP074_CAPACITY_PEER", input)
            .env("AUTHS_AP074_CAPACITY_OPERATION", operation)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("peer"),
    )
}
pub(super) fn finish_peer(peer: &mut Peer) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = peer.0.try_wait().expect("peer status") {
            let mut diagnostic = String::new();
            peer.0
                .stderr
                .take()
                .expect("stderr")
                .read_to_string(&mut diagnostic)
                .expect("diagnostic");
            assert!(status.success(), "native process failed: {diagnostic}");
            return;
        }
        assert!(Instant::now() < deadline, "native peer timeout");
        thread::sleep(Duration::from_millis(5));
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one independent-process history with authoritative native record and counter assertions"
)]
fn capacity(backend: Backend) {
    let store = TestAttempts::open(backend);
    let runtime = runtime();
    let directory = tempfile::tempdir().expect("directory");
    let root = std::fs::canonicalize(directory.path()).expect("canonical");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("mode");
    let provider = Provider::start();
    let barrier = TcpListener::bind("127.0.0.1:0").expect("barrier");
    barrier.set_nonblocking(true).expect("nonblocking");
    let setup = Setup {
        backend: backend.label().to_owned(),
        location: store.location(),
        root: root.clone(),
        provider_port: provider.port,
        barrier_port: barrier.local_addr().expect("barrier address").port(),
    };
    let (engine, record) =
        runtime.block_on(load_engine(&setup, "parent", store.attempts().clone()));
    let shared = SharedConnection::new(
        store.attempts().store(),
        record.provider_kind().clone(),
        record.alias().clone(),
    );
    runtime
        .block_on(shared.insert(&record))
        .expect("published connection");
    engine
        .initialize_effect_configuration()
        .expect("installed configuration");
    let operations: Vec<_> = (0..17)
        .map(|index| format!("process-capacity-{index}"))
        .collect();
    for operation in &operations {
        runtime.block_on(authorize(&engine, &root, operation));
    }
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    let mut snapshots = Vec::new();
    for operation in operations.iter().take(15) {
        let result = runtime
            .block_on(acquire(&engine, &root, operation))
            .expect("acquisition");
        assert_eq!(result.stage, AcquisitionStage::ResponseRecorded);
        snapshots.push(result);
    }
    assert_eq!(provider.calls.load(Ordering::SeqCst), 15);
    let input = root.join("setup.json");
    private(&input, &serde_json::to_vec(&setup).expect("setup"));
    let mut left = start_peer(&input, &operations[15]);
    let mut right = start_peer(&input, &operations[16]);
    assert_ne!(left.0.id(), right.0.id());
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut signals = Vec::new();
    while signals.len() < 2 {
        match barrier.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false).expect("blocking");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("deadline");
                let mut ready = [0];
                stream.read_exact(&mut ready).expect("ready");
                assert_eq!(ready, *b"R");
                signals.push(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "peer ready timeout");
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("barrier: {error}"),
        }
    }
    for signal in &mut signals {
        signal.write_all(b"G").expect("release");
    }
    finish_peer(&mut left);
    finish_peer(&mut right);
    let contenders: Vec<AcquisitionSnapshot> = operations
        .iter()
        .skip(15)
        .map(|operation| {
            let value: Result<AcquisitionSnapshot, GatewaySubmitResult> = serde_json::from_slice(
                &std::fs::read(root.join(format!("{operation}.result"))).expect("result"),
            )
            .expect("native result");
            value.expect("native acquisition result")
        })
        .collect();
    assert_eq!(
        contenders
            .iter()
            .filter(|value| value.stage == AcquisitionStage::ResponseRecorded)
            .count(),
        1
    );
    assert_eq!(
        contenders
            .iter()
            .filter(|value| value.stage == AcquisitionStage::NotEntered)
            .count(),
        1
    );
    snapshots.extend(contenders);
    let calls: u64 = snapshots.iter().map(|value| value.reserved_calls).sum();
    let bytes: u64 = snapshots.iter().map(|value| value.reserved_bytes).sum();
    assert_eq!((calls, bytes), (16, 16 * 1024));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 16);
    let mut entries = 0;
    let mut refusals = 0;
    let raw = store.attempts().store();
    for key in raw.attempt_keys(32).expect("keys") {
        let value: serde_json::Value = serde_json::from_slice(
            &raw.load(crate::GatewayRecordKind::Attempt, &key)
                .expect("load")
                .expect("record"),
        )
        .expect("record JSON");
        if !value["entry"].is_null() {
            entries += 1;
        }
        if value["state"]["facts"]["phase"]["stage"] == "not-entered" {
            assert_eq!(
                value["state"]["facts"]["phase"]["code"],
                "gateway.acquisition.exhausted"
            );
            refusals += 1;
        }
    }
    assert_eq!((entries, refusals), (16, 1));
    let (reopened, _) = runtime.block_on(load_engine(&setup, "reopened", store.reopen()));
    for (operation, expected) in operations.iter().zip(&snapshots) {
        assert_eq!(
            &runtime
                .block_on(acquire(&reopened, &root, operation))
                .expect("replay"),
            expected
        );
    }
    assert_eq!(provider.calls.load(Ordering::SeqCst), 16);
    let artifact=serde_json::to_vec_pretty(&json!({"schema":"auths.native-process-capacity/1","adapter":backend.label(),
        "scope":"full native engine compilation, exact fixed-key approval, installed dependency fencing and real HTTP across two independent processes; fixed test deployment clock and separate local custody; source-lifetime acquisition count/response bytes only; no human UI, hostile containment, power-loss or distributed-file claim",
        "prefilled":15,"contenders":2,"winner_count":1,"not_entered":1,"durable_grants":entries,
        "refusal_code":"gateway.acquisition.exhausted","reserved_calls":calls,"reserved_bytes":bytes,
        "provider_calls":provider.calls.load(Ordering::SeqCst),"reopened_replay_no_refetch":true})).expect("artifact");
    let output = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-process-capacity-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&output, &artifact).expect("write");
    }
    assert_eq!(std::fs::read(output).expect("artifact"), artifact);
}

#[test]
fn native_file_process_capacity_fixture_is_current() {
    capacity(Backend::File);
}
#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_process_capacity_fixture_is_current() {
    assert!(postgres_configured());
    capacity(Backend::Postgres);
}
