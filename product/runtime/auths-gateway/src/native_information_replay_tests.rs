//! Native retained read/release replay over real HTTP and authenticated Unix
//! sockets. Same-UID tests establish no hostile-process isolation guarantee.
use crate::effect::{
    CONTENT_READ_TOOL, DISCLOSURE_TOOL, ExactEffectApproval, UnixDisclosurePolicy,
};
use crate::harness::authoring::{tool_fixture_until, tools_context};
use crate::native_mutation_replay_tests::Change;
use crate::native_process_tests::{
    CONTENT, EngineControls, NOW, Provider, Setup, load_controlled_engine, recipe, runtime,
};
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::{
    FixedClock, GatewayAttempts, GatewayEngine, GatewayRecordKind, LogicalOperationId,
    SharedConnection,
};
use auths_profile_mcp::McpToolCall;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};
use std::{
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::Path,
    sync::{Arc, atomic::Ordering},
};
use tokio::net::UnixStream;

const SOURCE: &str = "retained-read";
const RELEASE: &str = "retained-release";

#[derive(Clone, Copy, Debug)]
enum Protocol {
    Acquisition,
    Acknowledged,
    LostAcknowledgement,
}
impl Protocol {
    const fn label(self) -> &'static str {
        match self {
            Self::Acquisition => "acquisition-response",
            Self::Acknowledged => "disclosure-acknowledged",
            Self::LostAcknowledgement => "disclosure-unknown",
        }
    }
}

fn controls(clock: Arc<FixedClock>, reviewer: u8) -> EngineControls {
    let recipe = recipe();
    let tools = [CONTENT_READ_TOOL, DISCLOSURE_TOOL].map(|name| {
        McpToolCall::new(recipe.review().service(), name, serde_json::Map::new()).expect("tool")
    });
    let mut controls = EngineControls::baseline();
    controls.trust = Some(tools_context(&tools, NOW).expect("native trust"));
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
    approval: ExactEffectApproval,
}
impl Input {
    fn approval(effect: crate::effect::BoundEffect, change: Change) -> ExactEffectApproval {
        let until = if matches!(change, Change::ApprovalExpiry) {
            NOW + 5
        } else {
            NOW + 300
        };
        let request = effect.approval_request(NOW, until).expect("review request");
        let signature = SigningKey::from_bytes(&[29; 32])
            .sign(&request.signing_message().expect("preimage"))
            .to_bytes();
        request.with_signature(signature)
    }
    fn until(change: Change) -> u64 {
        if matches!(change, Change::AuthorityExpiry) {
            NOW + 5
        } else {
            NOW + 86_400
        }
    }
    async fn content(engine: &GatewayEngine, change: Change) -> Self {
        let call = engine
            .content_authorization_call(br#"{"record_id":"recTEST0000000001"}"#, SOURCE)
            .await
            .expect("native read call");
        let signed =
            tool_fixture_until(&call, NOW, Self::until(change)).expect("native read proof");
        let effect = engine
            .compile_content_action(&signed.proof, &signed.action)
            .await
            .expect("native read effect");
        Self {
            proof: signed.proof,
            action: signed.action,
            approval: Self::approval(effect, change),
        }
    }
    async fn disclosure(
        engine: &GatewayEngine,
        target: &crate::effect::DisclosureTarget,
        change: Change,
    ) -> Self {
        let operation = LogicalOperationId::parse(RELEASE).expect("operation");
        let call = target
            .authorization_call(&recipe(), &operation)
            .expect("native release call");
        let signed =
            tool_fixture_until(&call, NOW, Self::until(change)).expect("independent release proof");
        let effect = engine
            .compile_disclosure_effect(target, &signed.proof, &signed.action)
            .await
            .expect("native release effect");
        Self {
            proof: signed.proof,
            action: signed.action,
            approval: Self::approval(effect, change),
        }
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    setup: Setup,
    store: TestAttempts,
    provider: Provider,
    clock: Arc<FixedClock>,
    runtime: tokio::runtime::Runtime,
    engine: GatewayEngine,
}
impl Fixture {
    fn new(backend: Backend) -> Self {
        let directory = tempfile::tempdir().expect("directory");
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
        Self {
            _directory: directory,
            setup,
            store,
            provider,
            clock,
            runtime,
            engine,
        }
    }
    fn records(&self) -> Vec<Vec<u8>> {
        let raw = self.store.raw();
        raw.attempt_keys(8)
            .expect("keys")
            .iter()
            .map(|key| {
                raw.load(GatewayRecordKind::Attempt, key)
                    .expect("load")
                    .expect("record")
            })
            .collect()
    }
    fn change_and_reopen(&self, change: Change) -> GatewayEngine {
        match change {
            Change::None | Change::ConfigurationReplaced => {}
            Change::ApprovalExpiry | Change::AuthorityExpiry => self.clock.set(NOW + 6),
            Change::ConnectionRevoked => {
                self.runtime
                    .block_on(self.engine.revoke_connection())
                    .expect("native revocation");
            }
        }
        let controls = controls(
            self.clock.clone(),
            if matches!(change, Change::ConfigurationReplaced) {
                30
            } else {
                29
            },
        );
        let attempts = GatewayAttempts::new(self.store.reopen().store(), controls.policy.clone())
            .expect("reopened policy");
        let (engine, _) = self.runtime.block_on(load_controlled_engine(
            &self.setup,
            "reopened",
            attempts,
            controls,
        ));
        if matches!(change, Change::ConfigurationReplaced) {
            let revision = engine
                .effect_configuration_revision()
                .expect("review configuration");
            engine
                .activate_effect_configuration(revision)
                .expect("native configuration CAS");
        }
        engine
    }
}

async fn release(
    engine: &GatewayEngine,
    input: &Input,
    target: &crate::effect::DisclosureTarget,
    policy: &UnixDisclosurePolicy,
    recipient: &SigningKey,
    acknowledge: bool,
) -> crate::DisclosureSnapshot {
    let effect = engine
        .compile_disclosure_effect(target, &input.proof, &input.action)
        .await
        .expect("review");
    let binding = effect.binding().clone();
    let (server, client) = UnixStream::pair().expect("local channel");
    let receiver = async {
        let received = crate::disclosure_transport::receive_disclosure(
            crate::disclosure_transport::DisclosureConnection::new(client, policy.clone()),
            &binding,
            CONTENT.len() as u64,
            recipient,
        )
        .await
        .expect("authenticated exact delivery");
        assert_eq!(received.content(), CONTENT);
        if acknowledge {
            received
                .acknowledge(recipient)
                .await
                .expect("exact native ACK");
        }
    };
    let (result, ()) = tokio::join!(
        engine.disclose(
            target,
            &input.proof,
            &input.action,
            input.approval.clone(),
            crate::disclosure_transport::DisclosureConnection::new(server, policy.clone())
        ),
        receiver,
    );
    let result = result.expect("native release");
    assert_eq!(
        result.stage,
        if acknowledge {
            crate::DisclosureStage::Acknowledged
        } else {
            crate::DisclosureStage::Unknown
        }
    );
    result
}

struct ReleaseHistory {
    input: Input,
    target: crate::effect::DisclosureTarget,
    policy: UnixDisclosurePolicy,
    snapshot: crate::DisclosureSnapshot,
}

fn prepare_release(
    fixture: &Fixture,
    protocol: Protocol,
    change: Change,
) -> Option<ReleaseHistory> {
    if matches!(protocol, Protocol::Acquisition) {
        return None;
    }
    let recipient = SigningKey::from_bytes(&[47; 32]);
    let uid = std::fs::metadata(&fixture.setup.root).expect("owner").uid();
    let policy = UnixDisclosurePolicy::new(uid, uid, [51; 32]);
    let target = fixture
        .runtime
        .block_on(fixture.engine.disclosure_target(
            SOURCE,
            recipient.verifying_key().to_bytes(),
            policy.commitment().expect("channel"),
            [52; 32],
        ))
        .expect("retained source");
    let input = fixture
        .runtime
        .block_on(Input::disclosure(&fixture.engine, &target, change));
    let snapshot = fixture.runtime.block_on(release(
        &fixture.engine,
        &input,
        &target,
        &policy,
        &recipient,
        matches!(protocol, Protocol::Acknowledged),
    ));
    Some(ReleaseHistory {
        input,
        target,
        policy,
        snapshot,
    })
}

async fn replay_content(
    engine: &GatewayEngine,
    input: &Input,
    expected: &crate::AcquisitionSnapshot,
) -> Value {
    let replay = engine
        .acquire_content_action(&input.proof, &input.action, input.approval.clone())
        .await
        .expect("retained read");
    assert_eq!(&replay, expected);
    let changed = json!({"record_id":"recTEST0000000002"})
        .as_object()
        .expect("arguments")
        .clone();
    assert!(
        engine
            .acquire_content(changed, &input.proof, &input.action, input.approval.clone())
            .await
            .is_err()
    );
    serde_json::to_value(replay).expect("snapshot")
}

async fn replay_release(engine: &GatewayEngine, history: &ReleaseHistory) -> Value {
    let ReleaseHistory {
        input,
        target,
        policy,
        snapshot,
    } = history;
    let (server, mut client) = UnixStream::pair().expect("replay channel");
    let replay = engine
        .disclose(
            target,
            &input.proof,
            &input.action,
            input.approval.clone(),
            crate::disclosure_transport::DisclosureConnection::new(server, policy.clone()),
        )
        .await
        .expect("retained release");
    assert_eq!(&replay, snapshot);
    use tokio::io::AsyncReadExt as _;
    let mut byte = [0];
    assert_eq!(
        client.read(&mut byte).await.expect("closed replay"),
        0,
        "history sends neither challenge nor content"
    );
    let changed = engine
        .disclosure_target(
            SOURCE,
            SigningKey::from_bytes(&[48; 32]).verifying_key().to_bytes(),
            policy.commitment().expect("channel"),
            [52; 32],
        )
        .await
        .expect("changed proposal");
    assert!(
        engine
            .admit_disclosure(
                &changed,
                &input.proof,
                &input.action,
                input.approval.clone()
            )
            .await
            .is_err()
    );
    serde_json::to_value(replay).expect("snapshot")
}

fn one_case(backend: Backend, protocol: Protocol, change: Change) -> Value {
    eprintln!(
        "native information replay: {}/{protocol:?}/{change:?}",
        backend.label()
    );
    let fixture = Fixture::new(backend);
    let source = fixture
        .runtime
        .block_on(Input::content(&fixture.engine, change));
    let acquired = fixture
        .runtime
        .block_on(fixture.engine.acquire_content_action(
            &source.proof,
            &source.action,
            source.approval.clone(),
        ))
        .expect("native acquisition");
    assert_eq!(acquired.stage, crate::AcquisitionStage::ResponseRecorded);
    assert_eq!(acquired.reserved_calls, 1);
    assert_eq!(acquired.reserved_bytes, 1024);
    let disclosure = prepare_release(&fixture, protocol, change);
    let retained = fixture.records();
    let reopened = fixture.change_and_reopen(change);
    let witness = reopened.execution_witness();
    let result = fixture.runtime.block_on(async {
        match &disclosure {
            None => replay_content(&reopened, &source, &acquired).await,
            Some(disclosure) => replay_release(&reopened, disclosure).await,
        }
    });
    assert_eq!(reopened.execution_witness(), witness);
    assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.records(), retained);
    json!({"protocol":protocol.label(), "change":change.label(), "native_snapshot":result,
        "provider_reads":1, "reopened_native_engine":true, "no_replay_authentication_or_delivery":true,
        "changed_caller_target_refused":true, "journal_and_execution_witness_unchanged":true})
}

fn matrix(backend: Backend) {
    let mut cases = Vec::new();
    for protocol in [
        Protocol::Acquisition,
        Protocol::Acknowledged,
        Protocol::LostAcknowledgement,
    ] {
        for change in [
            Change::None,
            Change::ApprovalExpiry,
            Change::AuthorityExpiry,
            Change::ConnectionRevoked,
            Change::ConfigurationReplaced,
        ] {
            cases.push(one_case(backend, protocol, change));
        }
    }
    let artifact = serde_json::to_vec_pretty(&json!({"schema":"auths.native-information-retained-replay/1", "adapter":backend.label(),
        "scope":"native proof, independent read/release approvals, real HTTP and authenticated Unix delivery; fixed public keys, same UID and maintained clock; retained facts confer no execution authority", "cases":cases})).expect("artifact");
    let output = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-information-retained-replay-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&output, &artifact).expect("write");
    }
    assert_eq!(std::fs::read(output).expect("fixture"), artifact);
}

#[test]
fn native_file_information_retained_replay_fixture_is_current() {
    matrix(Backend::File);
}
#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_information_retained_replay_fixture_is_current() {
    assert!(postgres_configured());
    matrix(Backend::Postgres);
}
