//! Retained mutation facts outlive current authority and exact approval.
//! Real native compilation, approval, durable adapters and local HTTP; public
//! fixture identities and the maintained test clock remain explicit assumptions.
use crate::harness::authoring::{tool_fixture_until, tools_context};
use crate::native_process_tests::{EngineControls, NOW, Setup, load_controlled_engine, runtime};
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::{
    CompiledRecipe, FixedClock, GatewayAttempts, GatewayEngine, GatewayRecordKind,
    GatewaySubmitResult, LogicalOperationId, SharedConnection,
};
use auths_profile_mcp::McpToolCall;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const OPERATION: &str = "retained-mutation";
const SECRET: &[u8] = b"public-native-process-fixture";

#[path = "native_mutation_entry_tests.rs"]
mod entry_tests;

struct Provider {
    port: u16,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    task: Option<JoinHandle<()>>,
}
impl Provider {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("provider");
        listener.set_nonblocking(true).expect("poll");
        let port = listener.local_addr().expect("address").port();
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let captured = bodies.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let task = thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
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
                    assert!(header.len() < 16_384);
                    let mut byte = [0];
                    stream.read_exact(&mut byte).expect("header");
                    header.push(byte[0]);
                }
                let header = String::from_utf8(header).expect("header UTF-8");
                assert!(header.starts_with(
                    "PATCH /v0/appTEST0000000001/tblTEST0000000001/recTEST0000000001 HTTP/1.1\r\n"
                ));
                assert!(header.to_ascii_lowercase().contains(&format!(
                    "authorization: bearer {}\r\n",
                    String::from_utf8_lossy(SECRET)
                )));
                let length = header
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("length"))
                    })
                    .expect("body length");
                assert!(length <= 65_536);
                let mut body = vec![0; length];
                stream.read_exact(&mut body).expect("body");
                captured.lock().expect("capture").push(body);
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                    )
                    .expect("response");
            }
        });
        Self {
            port,
            bodies,
            stop,
            task: Some(task),
        }
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(task) = self.task.take() {
            let result = task.join();
            if !thread::panicking() {
                result.expect("provider task");
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Change {
    None,
    ApprovalExpiry,
    AuthorityExpiry,
    ConnectionRevoked,
    ConfigurationReplaced,
}
impl Change {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::None => "unchanged",
            Self::ApprovalExpiry => "approval-expired",
            Self::AuthorityExpiry => "resource-authority-expired",
            Self::ConnectionRevoked => "connection-revoked",
            Self::ConfigurationReplaced => "configuration-replaced",
        }
    }
}
fn recipe() -> CompiledRecipe {
    CompiledRecipe::compile(
        include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json"),
        include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json"),
    )
    .expect("mutation recipe")
}
fn controls(clock: Arc<FixedClock>, reviewer: u8) -> EngineControls {
    let recipe = recipe();
    let call = McpToolCall::new(
        recipe.review().service(),
        recipe.review().tool(),
        serde_json::Map::new(),
    )
    .expect("tool");
    let mut controls = EngineControls::baseline();
    controls.recipe = Some(recipe);
    controls.trust = Some(tools_context(&[call], NOW).expect("native trust"));
    controls.clock = clock;
    controls.policy = crate::effect::EffectPolicy::new(
        "test-partition".to_owned(),
        1,
        SigningKey::from_bytes(&[reviewer; 32])
            .verifying_key()
            .to_bytes(),
    )
    .expect("policy");
    controls
}
struct Input {
    proof: Vec<u8>,
    action: Vec<u8>,
    approval: crate::effect::ExactEffectApproval,
    body: Vec<u8>,
    changed: Vec<ChangedInput>,
}
struct ChangedInput {
    signed: crate::harness::authoring::ToolFixture,
    approval: crate::effect::ExactEffectApproval,
}
fn approval(
    effect: &crate::effect::BoundEffect,
    expires: u64,
) -> crate::effect::ExactEffectApproval {
    let request = effect
        .approval_request(NOW, expires)
        .expect("approval request");
    let signature = SigningKey::from_bytes(&[29; 32])
        .sign(&request.signing_message().expect("preimage"))
        .to_bytes();
    request.with_signature(signature)
}
impl Input {
    async fn author(engine: &GatewayEngine, change: Change) -> Self {
        let recipe = recipe();
        let arguments = json!({"operator_namespace":recipe.namespace().as_str(),"recipe_digest":recipe.digest_hex(),"operation_id":OPERATION,"record_id":"recTEST0000000001","replacement":"Approved"});
        let call = McpToolCall::new(
            recipe.review().service(),
            recipe.review().tool(),
            arguments.as_object().expect("arguments").clone(),
        )
        .expect("call");
        let signed = tool_fixture_until(
            &call,
            NOW,
            if matches!(change, Change::AuthorityExpiry) {
                NOW + 5
            } else {
                NOW + 86_400
            },
        )
        .expect("native signed authority");
        let effect = engine
            .compile_effect(&signed.proof, &signed.action)
            .await
            .expect("native effect");
        let mut changed_call = call.arguments().clone();
        changed_call.insert("replacement".to_owned(), json!("Pending"));
        let changed_call = McpToolCall::new(
            recipe.review().service(),
            recipe.review().tool(),
            changed_call,
        )
        .expect("changed call");
        let expires = if matches!(change, Change::ApprovalExpiry) {
            NOW + 5
        } else {
            NOW + 300
        };
        let alternatives = [
            tool_fixture_until(&call, NOW, NOW + 86_399).expect("different valid native proof"),
            tool_fixture_until(&changed_call, NOW, NOW + 86_400)
                .expect("different valid native action"),
        ];
        let mut changed = Vec::new();
        for alternative in alternatives {
            let compiled = engine
                .compile_effect(&alternative.proof, &alternative.action)
                .await
                .expect("positive native changed-input control");
            assert_ne!(compiled.binding().id(), effect.binding().id());
            changed.push(ChangedInput {
                signed: alternative,
                approval: approval(&compiled, expires),
            });
        }
        let body = effect
            .private_request()
            .expect("mutation request")
            .body()
            .to_vec();
        Self {
            proof: signed.proof,
            action: signed.action,
            approval: approval(&effect, expires),
            body,
            changed,
        }
    }
    async fn submit(&self, engine: &GatewayEngine) -> GatewaySubmitResult {
        engine
            .submit(&self.proof, &self.action, self.approval.clone())
            .await
    }
}

fn one_case(backend: Backend, change: Change) -> Value {
    eprintln!("native retained mutation: {}/{change:?}", backend.label());
    let directory = tempfile::tempdir().expect("directory");
    let root = std::fs::canonicalize(directory.path()).expect("canonical");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("private");
    let store = TestAttempts::open(backend);
    let provider = Provider::start();
    let setup = Setup {
        backend: backend.label().to_owned(),
        location: store.location(),
        root,
        provider_port: provider.port,
        barrier_port: 0,
    };
    let clock = Arc::new(FixedClock::at(NOW));
    let runtime = runtime();
    let (engine, connection) = runtime.block_on(load_controlled_engine(
        &setup,
        "original",
        store.attempts().clone(),
        controls(clock.clone(), 29),
    ));
    let shared = SharedConnection::new(
        store.raw(),
        connection.provider_kind().clone(),
        connection.alias().clone(),
    );
    runtime
        .block_on(shared.insert(&connection))
        .expect("connection");
    engine
        .initialize_effect_configuration()
        .expect("configuration");
    let input = runtime.block_on(Input::author(&engine, change));
    let expected = runtime.block_on(input.submit(&engine));
    assert_eq!(
        expected,
        GatewaySubmitResult::ResponseRecorded { status: 200 }
    );
    assert_eq!(
        *provider.bodies.lock().expect("requests"),
        vec![input.body.clone()]
    );
    let operation = LogicalOperationId::parse(OPERATION).expect("operation");
    let key = crate::GatewayAttemptKey::for_operation(
        &crate::effect::fixture_policy().expect("policy"),
        recipe().namespace(),
        &operation,
    )
    .expect("key");
    let stored = store
        .raw()
        .load(GatewayRecordKind::Attempt, &key)
        .expect("record")
        .expect("record");
    let history = runtime
        .block_on(store.attempts().read(recipe().namespace(), &operation))
        .expect("history")
        .expect("history");
    let replacement = changed_engine(change, &runtime, &engine, &setup, &store, &clock);
    let engine = replacement.as_ref().unwrap_or(&engine);
    let result = assert_replay(ReplayCheck {
        runtime: &runtime,
        engine,
        input: &input,
        store: &store,
        provider: &provider,
        key: &key,
        stored: &stored,
        history: &history,
        expected: &expected,
        change,
    });
    let reopened = reopened_engine(change, &runtime, &setup, &store, &clock);
    assert_replay(ReplayCheck {
        runtime: &runtime,
        engine: &reopened,
        input: &input,
        store: &store,
        provider: &provider,
        key: &key,
        stored: &stored,
        history: &history,
        expected: &expected,
        change,
    });
    result
}

fn changed_engine(
    change: Change,
    runtime: &tokio::runtime::Runtime,
    engine: &GatewayEngine,
    setup: &Setup,
    store: &TestAttempts,
    clock: &Arc<FixedClock>,
) -> Option<GatewayEngine> {
    let mut replacement = None;
    match change {
        Change::None => {}
        Change::ApprovalExpiry | Change::AuthorityExpiry => clock.set(NOW + 6),
        Change::ConnectionRevoked => {
            runtime
                .block_on(engine.revoke_connection())
                .expect("native revocation");
        }
        Change::ConfigurationReplaced => {
            let control = controls(clock.clone(), 30);
            let attempts =
                GatewayAttempts::new(store.raw(), control.policy.clone()).expect("new policy");
            let (next, _) = runtime.block_on(load_controlled_engine(
                setup,
                "replacement",
                attempts,
                control,
            ));
            let revision = next
                .effect_configuration_revision()
                .expect("review revision");
            next.activate_effect_configuration(revision)
                .expect("native configuration CAS");
            replacement = Some(next);
        }
    }
    replacement
}

fn reopened_engine(
    change: Change,
    runtime: &tokio::runtime::Runtime,
    setup: &Setup,
    store: &TestAttempts,
    clock: &Arc<FixedClock>,
) -> GatewayEngine {
    let control = controls(
        clock.clone(),
        if matches!(change, Change::ConfigurationReplaced) {
            30
        } else {
            29
        },
    );
    let attempts = GatewayAttempts::new(store.reopen().store(), control.policy.clone())
        .expect("reopened policy");
    let (reopened, _) =
        runtime.block_on(load_controlled_engine(setup, "reopened", attempts, control));
    reopened
}

#[derive(Clone, Copy)]
struct ReplayCheck<'a> {
    runtime: &'a tokio::runtime::Runtime,
    engine: &'a GatewayEngine,
    input: &'a Input,
    store: &'a TestAttempts,
    provider: &'a Provider,
    key: &'a crate::GatewayAttemptKey,
    stored: &'a [u8],
    history: &'a crate::GatewayAttemptSnapshot,
    expected: &'a GatewaySubmitResult,
    change: Change,
}

fn assert_replay(check: ReplayCheck<'_>) -> Value {
    let ReplayCheck {
        runtime,
        engine,
        input,
        store,
        provider,
        key,
        stored,
        history,
        expected,
        change,
    } = check;
    let operation = LogicalOperationId::parse(OPERATION).expect("operation");
    let witness = engine.execution_witness();
    for alternative in &input.changed {
        // Foreign inputs do not retrieve history. The original approval cannot
        // authorize them; their own real approval reaches the durable conflict
        // only while current execution authority is still valid.
        let stale_approval = runtime.block_on(engine.submit(
            &alternative.signed.proof,
            &alternative.signed.action,
            input.approval.clone(),
        ));
        assert_eq!(
            stale_approval,
            GatewaySubmitResult::NotEntered {
                code: if matches!(change, Change::ConnectionRevoked) {
                    "gateway.connection.unavailable"
                } else {
                    "gateway.effect.approval"
                }
                .to_owned()
            }
        );
        let result = runtime.block_on(engine.submit(
            &alternative.signed.proof,
            &alternative.signed.action,
            alternative.approval.clone(),
        ));
        assert_eq!(
            result,
            GatewaySubmitResult::NotEntered {
                code: match change {
                    // These alternative proofs deliberately remain live even
                    // when the original source's authority has expired.
                    Change::None | Change::AuthorityExpiry => "gateway.effect.operation-conflict",
                    Change::ApprovalExpiry | Change::ConfigurationReplaced =>
                        "gateway.effect.approval",
                    Change::ConnectionRevoked => "gateway.connection.unavailable",
                }
                .to_owned()
            }
        );
    }
    let mut invalid: Value =
        serde_json::from_slice(&input.approval.to_private_bytes().expect("approval"))
            .expect("shape");
    let mut signature =
        Base64UrlUnpadded::decode_vec(invalid["signature_b64"].as_str().expect("signature"))
            .expect("base64");
    signature[0] ^= 1;
    invalid["signature_b64"] = json!(Base64UrlUnpadded::encode_string(&signature));
    let invalid = crate::effect::ExactEffectApproval::from_private_bytes(
        &serde_json_canonicalizer::to_vec(&invalid).expect("canonical"),
    )
    .expect("invalid signature is data");
    let refused = runtime.block_on(engine.submit(&input.proof, &input.action, invalid));
    assert_eq!(
        refused,
        GatewaySubmitResult::NotEntered {
            code: "gateway.effect.operation-conflict".to_owned()
        }
    );
    let replay = runtime.block_on(input.submit(engine));
    assert_eq!(
        &replay, expected,
        "retained entered facts cannot become a current non-entry assertion: {change:?}"
    );
    assert_eq!(engine.execution_witness(), witness);
    assert_eq!(
        *provider.bodies.lock().expect("requests"),
        vec![input.body.clone()]
    );
    assert_eq!(
        store
            .raw()
            .load(GatewayRecordKind::Attempt, key)
            .expect("record")
            .expect("record"),
        stored
    );
    assert_eq!(
        runtime
            .block_on(store.attempts().read(recipe().namespace(), &operation))
            .expect("history")
            .expect("history"),
        *history
    );
    json!({"change":change.label(),"native_result":replay,"actual_provider_writes":1,"same_request_body_as_review":true,"retained_journal_and_execution_witness_unchanged":true,"different_valid_proof_action_and_invalid_approval_refused":true})
}

fn matrix(backend: Backend) {
    let cases: Vec<_> = [
        Change::None,
        Change::ApprovalExpiry,
        Change::AuthorityExpiry,
        Change::ConnectionRevoked,
        Change::ConfigurationReplaced,
    ]
    .into_iter()
    .map(|change| one_case(backend, change))
    .collect();
    let artifact = serde_json::to_vec_pretty(&json!({"schema":"auths.native-mutation-retained-replay/1","adapter":backend.label(),"scope":"full native mutation engine, actual exact approval/proof, maintained durable adapter and real local HTTP; fixed public keys and maintained test clock; no current execution authority inferred from retained history","cases":cases})).expect("artifact");
    let output = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-mutation-retained-replay-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&output, &artifact).expect("write");
    }
    assert_eq!(std::fs::read(output).expect("fixture"), artifact);
}
#[test]
fn native_file_mutation_retained_replay_fixture_is_current() {
    matrix(Backend::File);
}
#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_mutation_retained_replay_fixture_is_current() {
    assert!(postgres_configured());
    matrix(Backend::Postgres);
}
