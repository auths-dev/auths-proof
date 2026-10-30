//! Private setup and real process roles for the native disclosure crash corpus.
use super::{Gate, Point, RELEASE, SOURCE};
use crate::disclosure_transport::{DisclosureConnection, receive_disclosure};
use crate::effect::{
    CONTENT_READ_TOOL, DISCLOSURE_TOOL, DisclosureTarget, EffectBinding, ExactEffectApproval,
    UnixDisclosurePolicy,
};
use crate::harness::authoring::{tool_fixture_in_window, tools_context};
use crate::native_crash_tests::{CrashProtocol, PausedStore, pause_at};
use crate::native_process_tests::{
    CONTENT, EngineControls, NOW, Setup, load_controlled_engine, private, recipe, runtime,
};
use crate::store_testkit::{Backend, TestAttempts};
use crate::{
    ArgumentCeilingPolicy, GatewayAttemptKey, GatewayAttempts, GatewayEngine, LogicalOperationId,
};
use auths_profile_mcp::McpToolCall;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    io::Read as _,
    os::unix::process::ExitStatusExt as _,
    path::Path,
    process::{Child, Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use tokio::net::{UnixListener, UnixStream};

pub(super) const ENVIRONMENT: &str = "AUTHS_AP074_DISCLOSURE_CRASH_PEER";

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Role {
    Gateway,
    Recipient,
    ResumeRecipient,
    RecipientWithoutAck,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CrashSetup {
    pub(super) installation: Setup,
    pub(super) point: Point,
    pub(super) gate: Gate,
    pub(super) channel: UnixDisclosurePolicy,
    pub(super) role: Role,
}

pub(super) fn controls(gate: Gate) -> EngineControls {
    let recipe = recipe();
    let calls = [CONTENT_READ_TOOL, DISCLOSURE_TOOL].map(|name| {
        McpToolCall::new(recipe.review().service(), name, serde_json::Map::new()).expect("tool")
    });
    let mut controls = EngineControls::baseline();
    controls.trust = Some(tools_context(&calls, NOW).expect("native installed trust"));
    controls.clock.set(gate.clock());
    if matches!(gate, Gate::ConfigurationReplaced) {
        controls.policy = crate::effect::EffectPolicy::new(
            "test-partition".to_owned(),
            1,
            SigningKey::from_bytes(&[30; 32]).verifying_key().to_bytes(),
        )
        .expect("replacement policy");
    }
    controls
}

pub(super) fn key(operation: &str) -> GatewayAttemptKey {
    GatewayAttemptKey::for_operation(
        &crate::effect::fixture_policy().expect("policy"),
        recipe().namespace(),
        &LogicalOperationId::parse(operation).expect("operation"),
    )
    .expect("key")
}

pub(super) struct Input {
    pub(super) proof: Vec<u8>,
    pub(super) action: Vec<u8>,
    pub(super) approval: ExactEffectApproval,
}
impl Input {
    pub(super) fn read(root: &Path) -> Self {
        Self {
            proof: std::fs::read(root.join("release.proof")).expect("proof"),
            action: std::fs::read(root.join("release.action")).expect("action"),
            approval: ExactEffectApproval::from_private_bytes(
                &std::fs::read(root.join("release.approval")).expect("approval"),
            )
            .expect("approval data"),
        }
    }
    fn approve(effect: &crate::effect::BoundEffect, until: u64) -> ExactEffectApproval {
        let request = effect.approval_request(NOW, until).expect("native review");
        let signature = SigningKey::from_bytes(&[29; 32])
            .sign(&request.signing_message().expect("preimage"))
            .to_bytes();
        request.with_signature(signature)
    }
}

pub(super) async fn target(engine: &GatewayEngine, setup: &CrashSetup) -> DisclosureTarget {
    engine
        .disclosure_target(
            SOURCE,
            SigningKey::from_bytes(&[47; 32]).verifying_key().to_bytes(),
            setup.channel.commitment().expect("channel"),
            [52; 32],
        )
        .await
        .expect("retained source")
}

pub(super) async fn authorize_source(engine: &GatewayEngine) -> EffectBinding {
    let call = engine
        .content_authorization_call(br#"{"record_id":"recTEST0000000001"}"#, SOURCE)
        .await
        .expect("source call");
    let signed = tool_fixture_in_window(&call, NOW, NOW - 10, NOW + 3600, None)
        .expect("native source authority");
    let effect = engine
        .compile_content_action(&signed.proof, &signed.action)
        .await
        .expect("native source effect");
    let approval = Input::approve(&effect, NOW + 300);
    let binding = effect.binding().clone();
    let snapshot = engine
        .acquire_content_action(&signed.proof, &signed.action, approval)
        .await
        .expect("actual source acquisition");
    assert_eq!(snapshot.stage, crate::AcquisitionStage::ResponseRecorded);
    assert_eq!(
        (snapshot.reserved_calls, snapshot.reserved_bytes),
        (1, 1024)
    );
    binding
}

pub(super) async fn authorize_release(engine: &GatewayEngine, setup: &CrashSetup) -> EffectBinding {
    let target = target(engine, setup).await;
    let call = target
        .authorization_call(
            &recipe(),
            &LogicalOperationId::parse(RELEASE).expect("operation"),
        )
        .expect("independent release call");
    let policy =
        ArgumentCeilingPolicy::new("maximum_disclosure_bytes", CONTENT.len() as u64, 3600, 2)
            .expect("native disclosure count")
            .with_sum(CONTENT.len() as u64 * 2, None)
            .expect("native disclosure bytes");
    let until = if matches!(setup.gate, Gate::AuthorityExpired) {
        NOW + 5
    } else {
        NOW + 3600
    };
    let signed = tool_fixture_in_window(&call, NOW, NOW - 10, until, Some(&policy))
        .expect("independent native release proof");
    let effect = engine
        .compile_disclosure_effect(&target, &signed.proof, &signed.action)
        .await
        .expect("native release effect");
    let until = if matches!(setup.gate, Gate::ApprovalExpired) {
        NOW + 5
    } else {
        NOW + 300
    };
    let approval = Input::approve(&effect, until);
    for (name, bytes) in [
        ("release.proof", signed.proof),
        ("release.action", signed.action),
        (
            "release.approval",
            approval
                .to_private_bytes()
                .expect("approval bytes")
                .to_vec(),
        ),
        (
            "release.binding",
            effect
                .binding()
                .to_private_bytes()
                .expect("private recipient expectation")
                .to_vec(),
        ),
    ] {
        private(&setup.installation.root.join(name), &bytes);
    }
    effect.binding().clone()
}

pub(super) async fn gateway(setup: &CrashSetup) {
    let attached = TestAttempts::attach(
        Backend::parse(&setup.installation.backend),
        &setup.installation.location,
    );
    let wrapped = Arc::new(PausedStore::new(
        attached.raw(),
        key(RELEASE),
        RELEASE,
        CrashProtocol::Disclosure,
        setup.point.store_pause(),
        setup.installation.barrier_port,
    ));
    let attempts = GatewayAttempts::new(wrapped, crate::effect::fixture_policy().expect("policy"))
        .expect("attempts");
    let (engine, _) = load_controlled_engine(
        &setup.installation,
        "disclosure-crash-gateway",
        attempts,
        controls(Gate::Current),
    )
    .await;
    let listener =
        UnixListener::bind(setup.installation.root.join("release.sock")).expect("recipient socket");
    private(&setup.installation.root.join("gateway-ready"), b"ready");
    let (stream, _) = listener.accept().await.expect("recipient");
    if matches!(setup.point, Point::DuringDelivery) {
        crate::disclosure_transport::arm_delivery_prefix_pause(setup.installation.barrier_port);
    }
    let input = Input::read(&setup.installation.root);
    let target = target(&engine, setup).await;
    let result = engine
        .disclose(
            &target,
            &input.proof,
            &input.action,
            input.approval,
            DisclosureConnection::new(stream, setup.channel.clone()),
        )
        .await;
    private(
        &setup.installation.root.join("caller-result.json"),
        &serde_json::to_vec(&result).expect("result"),
    );
    let recipient =
        std::fs::read_to_string(setup.installation.root.join("recipient-result.json")).ok();
    panic!("gateway completed before the selected SIGKILL: {result:?}; recipient {recipient:?}");
}

pub(super) async fn recipient(setup: &CrashSetup, resume: bool) {
    let root = &setup.installation.root;
    let socket = root.join(if resume {
        "resume.sock"
    } else {
        "release.sock"
    });
    let start = Instant::now();
    let stream = loop {
        match UnixStream::connect(&socket).await {
            Ok(stream) => break stream,
            Err(error) if start.elapsed() < Duration::from_secs(10) => {
                assert!(matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ));
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            Err(error) => panic!("recipient connection: {error}"),
        }
    };
    let binding = EffectBinding::from_private_bytes(
        &std::fs::read(root.join("release.binding")).expect("reviewed binding"),
    )
    .expect("binding");
    let key = SigningKey::from_bytes(&[47; 32]);
    let received = receive_disclosure(
        DisclosureConnection::new(stream, setup.channel.clone()),
        &binding,
        CONTENT.len() as u64,
        &key,
    )
    .await;
    let prefix = if resume {
        "resumed-recipient"
    } else {
        "recipient"
    };
    let received = match received {
        Ok(received) => received,
        Err(code) => {
            private(
                &root.join(format!("{prefix}-result.json")),
                &serde_json::to_vec(&json!({"received_full":false,"code":code})).expect("result"),
            );
            return;
        }
    };
    assert_eq!(received.content(), CONTENT);
    let ack = received
        .acknowledgement(&key)
        .expect("actual native received ACK");
    private(
        &root.join(format!("{prefix}.ack")),
        &ack.to_private_bytes().expect("private ACK"),
    );
    private(
        &root.join(format!("{prefix}-result.json")),
        &serde_json::to_vec(&json!({"received_full":true,"bytes":CONTENT.len()})).expect("result"),
    );
    if matches!(setup.role, Role::RecipientWithoutAck) {
        return;
    }
    if !resume && matches!(setup.point, Point::AfterDeliveryBeforeAck) {
        let port = setup.installation.barrier_port;
        tokio::task::spawn_blocking(move || pause_at(port))
            .await
            .expect("controlled recipient pause");
    }
    received.acknowledge(&key).await.expect("native ACK send");
}

pub(super) struct Recipient(Child);
impl Recipient {
    pub(super) fn start(setup: &CrashSetup, resume: bool) -> Self {
        Self::start_mode(setup, resume, true)
    }
    pub(super) fn without_ack(setup: &CrashSetup) -> Self {
        Self::start_mode(setup, false, false)
    }
    fn start_mode(setup: &CrashSetup, resume: bool, acknowledge: bool) -> Self {
        let path = setup.installation.root.join(if resume {
            "resume-recipient-setup.json"
        } else {
            "recipient-setup.json"
        });
        let role = if !acknowledge {
            Role::RecipientWithoutAck
        } else if resume {
            Role::ResumeRecipient
        } else {
            Role::Recipient
        };
        let value = json!({"installation":setup.installation,"point":setup.point,"gate":setup.gate,"channel":setup.channel,"role":role});
        private(&path, &serde_json::to_vec(&value).expect("setup"));
        Self(
            Command::new(std::env::current_exe().expect("native executable"))
                .args([
                    "--exact",
                    "native_disclosure_crash_tests::native_disclosure_crash_peer",
                    "--nocapture",
                ])
                .env(ENVIRONMENT, path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("native recipient process"),
        )
    }
    pub(super) fn finish(&mut self, killed: bool) {
        if killed {
            self.0.kill().expect("recipient SIGKILL");
            assert_eq!(self.0.wait().expect("recipient exit").signal(), Some(9));
            return;
        }
        let start = Instant::now();
        loop {
            if let Some(status) = self.0.try_wait().expect("recipient status") {
                let mut diagnostic = String::new();
                self.0
                    .stderr
                    .take()
                    .expect("stderr")
                    .read_to_string(&mut diagnostic)
                    .expect("diagnostic");
                assert!(status.success(), "recipient: {status}: {diagnostic}");
                return;
            }
            assert!(
                start.elapsed() < Duration::from_secs(12),
                "recipient shutdown"
            );
            thread::sleep(Duration::from_millis(2));
        }
    }
}
impl Drop for Recipient {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(super) fn peer() {
    let Some(path) = std::env::var_os(ENVIRONMENT) else {
        return;
    };
    let setup: CrashSetup =
        serde_json::from_slice(&std::fs::read(path).expect("setup")).expect("typed setup");
    let runtime = runtime();
    runtime.block_on(async {
        match setup.role {
            Role::Gateway => Box::pin(gateway(&setup)).await,
            Role::Recipient => recipient(&setup, false).await,
            Role::ResumeRecipient => recipient(&setup, true).await,
            Role::RecipientWithoutAck => recipient(&setup, false).await,
        }
    });
}
