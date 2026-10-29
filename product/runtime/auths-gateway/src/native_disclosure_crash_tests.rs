//! Native gateway/recipient SIGKILL histories with real authenticated local
//! delivery, original signed inputs and late ACKs over both maintained stores.
use crate::disclosure_transport::DisclosureConnection;
use crate::effect::{
    DisclosureAcknowledgement, DisclosureAcknowledgementRequest, DisclosureTarget, EffectBinding,
    UnixDisclosurePolicy,
};
use crate::native_crash_tests::{CrashProtocol, PausedStore, Peer, Point as StorePoint};
use crate::native_process_tests::{
    CONTENT, NOW, Provider, Setup, load_controlled_engine, private, runtime,
};
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::{
    ContentHistory, DisclosureSnapshot, DisclosureStage, GatewayAttemptKey, GatewayAttempts,
    GatewayEngine, GatewayRecordKind, SharedConnection,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::TcpListener,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::Path,
    sync::atomic::Ordering,
};
use tokio::{
    io::AsyncReadExt as _,
    net::{UnixListener, UnixStream},
};

#[path = "native_disclosure_crash_testkit.rs"]
mod kit;
use kit::{CrashSetup, Input, Recipient, Role, controls, key};

#[path = "native_disclosure_budget_tests.rs"]
mod window_capacity_tests;

const SOURCE: &str = "crash-release-source";
const RELEASE: &str = "crash-release";

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Point {
    BeforeReservationCommit,
    AfterReservationCommit,
    BeforeEntryCommit,
    AfterEntryCommit,
    DuringDelivery,
    AfterDeliveryBeforeAck,
    BeforeAckCommit,
    AfterAckCommit,
}
impl Point {
    const ALL: [Self; 8] = [
        Self::BeforeReservationCommit,
        Self::AfterReservationCommit,
        Self::BeforeEntryCommit,
        Self::AfterEntryCommit,
        Self::DuringDelivery,
        Self::AfterDeliveryBeforeAck,
        Self::BeforeAckCommit,
        Self::AfterAckCommit,
    ];
    const fn store_pause(self) -> Option<StorePoint> {
        match self {
            Self::BeforeReservationCommit => Some(StorePoint::BeforeReservationCommit),
            Self::AfterReservationCommit => Some(StorePoint::AfterReservationCommit),
            Self::BeforeEntryCommit => Some(StorePoint::BeforeEntryCommit),
            Self::AfterEntryCommit => Some(StorePoint::AfterEntryCommit),
            Self::BeforeAckCommit => Some(StorePoint::BeforeAcknowledgementCommit),
            Self::AfterAckCommit => Some(StorePoint::AfterAcknowledgementCommit),
            Self::DuringDelivery | Self::AfterDeliveryBeforeAck => None,
        }
    }
    const fn resumable(self) -> bool {
        matches!(
            self,
            Self::BeforeReservationCommit | Self::AfterReservationCommit | Self::BeforeEntryCommit
        )
    }
    const fn received_full(self) -> bool {
        matches!(
            self,
            Self::AfterDeliveryBeforeAck | Self::BeforeAckCommit | Self::AfterAckCommit
        )
    }
    const fn raw_phase(self) -> Option<&'static str> {
        match self {
            Self::BeforeReservationCommit => None,
            Self::AfterReservationCommit | Self::BeforeEntryCommit => Some("reserved"),
            Self::AfterAckCommit => Some("acknowledged"),
            _ => Some("entry-granted"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Gate {
    Current,
    ApprovalExpired,
    AuthorityExpired,
    Revoked,
    ConfigurationReplaced,
}
impl Gate {
    const CHANGES: [Self; 4] = [
        Self::ApprovalExpired,
        Self::AuthorityExpired,
        Self::Revoked,
        Self::ConfigurationReplaced,
    ];
    const fn current(self) -> bool {
        matches!(self, Self::Current)
    }
    const fn clock(self) -> u64 {
        if matches!(self, Self::ApprovalExpired | Self::AuthorityExpired) {
            NOW + 6
        } else {
            NOW
        }
    }
}

#[test]
fn native_disclosure_crash_peer() {
    kit::peer();
}

struct Charges {
    lifetime: [u8; 32],
    fixed: Vec<(GatewayRecordKind, [u8; 32])>,
    bytes: u64,
    operation: &'static str,
}
impl Charges {
    fn native(
        binding: &EffectBinding,
        operation: &'static str,
        count: &str,
        sum: &str,
        bytes: u64,
    ) -> Self {
        let wire: Value = serde_json::from_slice(&binding.to_private_bytes().expect("binding"))
            .expect("native binding");
        let reservations = wire["reservations"].as_array().expect("reservations");
        let mut lifetime = None;
        let mut fixed = Vec::new();
        for reservation in reservations {
            let unit = reservation["unit"].as_str().expect("unit");
            if reservation["window"]["kind"] == "source-lifetime" && unit == count {
                assert!(lifetime.is_none());
                lifetime =
                    Some(serde_json::from_value(reservation["key"].clone()).expect("count digest"));
            } else if reservation["window"]["kind"] == "fixed" {
                let kind = if unit == count {
                    GatewayRecordKind::CountSlot
                } else {
                    assert_eq!(unit, sum);
                    GatewayRecordKind::SumSlot
                };
                fixed.push((
                    kind,
                    serde_json::from_value(reservation["key"].clone()).expect("counter digest"),
                ));
            }
        }
        Self {
            lifetime: lifetime.expect("native source count"),
            fixed,
            bytes,
            operation,
        }
    }
    fn records(&self, store: &TestAttempts, present: bool) -> BTreeMap<String, Vec<u8>> {
        let raw = store.raw();
        let mut keys = vec![(
            GatewayRecordKind::EffectAllocation,
            GatewayAttemptKey::from_bytes(crate::bounds::count_slot_key(&self.lifetime, 0)),
        )];
        assert!(
            raw.load(
                GatewayRecordKind::EffectAllocation,
                &GatewayAttemptKey::from_bytes(crate::bounds::count_slot_key(&self.lifetime, 1))
            )
            .expect("no duplicate allocation")
            .is_none()
        );
        for (kind, digest) in &self.fixed {
            let derive = if *kind == GatewayRecordKind::CountSlot {
                crate::bounds::count_slot_key
            } else {
                crate::bounds::sum_slot_key
            };
            keys.push((*kind, GatewayAttemptKey::from_bytes(derive(digest, 0))));
            assert!(
                raw.load(*kind, &GatewayAttemptKey::from_bytes(derive(digest, 1)))
                    .expect("no duplicate counter")
                    .is_none()
            );
        }
        keys.into_iter()
            .filter_map(|(kind, row)| {
                let bytes = raw.load(kind, &row).expect("charge row");
                assert_eq!(
                    bytes.is_some(),
                    present,
                    "attempt and all charges commit together"
                );
                bytes.map(|bytes| {
                    let value: Value = serde_json::from_slice(&bytes).expect("charge");
                    assert_eq!(value["slot"], 0);
                    if kind == GatewayRecordKind::EffectAllocation {
                        assert_eq!(value["calls"], 1);
                        assert_eq!(value["bytes"], self.bytes);
                    } else {
                        assert_eq!(value["operation_id"], self.operation);
                        assert_eq!(value["window_seconds"], 3600);
                        assert_eq!(value["window_index"], NOW / 3600);
                        if kind == GatewayRecordKind::SumSlot {
                            assert_eq!(value["amount"], self.bytes);
                            assert_eq!(value["cumulative"], self.bytes);
                        }
                    }
                    (hex::encode(row.as_bytes()), bytes)
                })
            })
            .collect()
    }
}

struct Case {
    _directory: tempfile::TempDir,
    setup: CrashSetup,
    store: TestAttempts,
    provider: Provider,
    listener: TcpListener,
    runtime: tokio::runtime::Runtime,
    source: Vec<u8>,
    source_charges: Charges,
    release_charges: Charges,
    binding: EffectBinding,
    signed_inputs: [Vec<u8>; 3],
}
impl Case {
    fn new(backend: Backend, point: Point, gate: Gate) -> Self {
        let directory = tempfile::tempdir().expect("private directory");
        let root = std::fs::canonicalize(directory.path()).expect("canonical");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("private");
        let uid = std::fs::metadata(&root).expect("UID").uid();
        let store = TestAttempts::open(backend);
        let provider = Provider::controlled(None);
        let listener = TcpListener::bind("127.0.0.1:0").expect("control");
        listener.set_nonblocking(true).expect("poll");
        let setup = CrashSetup {
            point,
            gate,
            role: Role::Gateway,
            channel: UnixDisclosurePolicy::new(uid, uid, [51; 32]),
            installation: Setup {
                backend: backend.label().to_owned(),
                location: store.location(),
                root,
                provider_port: provider.port,
                barrier_port: listener.local_addr().expect("port").port(),
            },
        };
        let runtime = runtime();
        let (engine, connection) = runtime.block_on(load_controlled_engine(
            &setup.installation,
            "source-parent",
            store.attempts().clone(),
            controls(Gate::Current),
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
        let source_binding = runtime.block_on(kit::authorize_source(&engine));
        let binding = runtime.block_on(kit::authorize_release(&engine, &setup));
        let source = store
            .raw()
            .load(GatewayRecordKind::Attempt, &key(SOURCE))
            .expect("source")
            .expect("source");
        let source_charges = Charges::native(
            &source_binding,
            SOURCE,
            "acquisition-count",
            "response-bytes",
            1024,
        );
        let release_charges = Charges::native(
            &binding,
            RELEASE,
            "disclosure-count",
            "disclosure-bytes",
            CONTENT.len() as u64,
        );
        assert_eq!(release_charges.fixed.len(), 2);
        let signed_inputs = ["release.proof", "release.action", "release.approval"].map(|name| {
            std::fs::read(setup.installation.root.join(name)).expect("original signed input")
        });
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        Self {
            _directory: directory,
            setup,
            store,
            provider,
            listener,
            runtime,
            source,
            source_charges,
            release_charges,
            binding,
            signed_inputs,
        }
    }
    fn raw(&self) -> Option<Vec<u8>> {
        self.store
            .raw()
            .load(GatewayRecordKind::Attempt, &key(RELEASE))
            .expect("release record")
    }
    fn crash(&self) -> Value {
        let path = self
            .setup
            .installation
            .root
            .join("gateway-crash-setup.json");
        private(&path, &serde_json::to_vec(&self.setup).expect("setup"));
        let mut gateway = Peer::start(
            &path,
            "native_disclosure_crash_tests::native_disclosure_crash_peer",
            kit::ENVIRONMENT,
        );
        let mut recipient = Recipient::start(&self.setup, false);
        let _paused = gateway.await_pause(&self.listener);
        assert!(
            !self
                .setup
                .installation
                .root
                .join("caller-result.json")
                .exists()
        );
        gateway.kill();
        recipient.finish(matches!(self.setup.point, Point::AfterDeliveryBeforeAck));
        let result: Value = serde_json::from_slice(
            &std::fs::read(self.setup.installation.root.join("recipient-result.json"))
                .expect("recipient outcome"),
        )
        .expect("result");
        assert_eq!(result["received_full"], self.setup.point.received_full());
        assert_eq!(
            self.setup.installation.root.join("recipient.ack").exists(),
            self.setup.point.received_full()
        );
        result
    }
    fn snapshot(&self, engine: &GatewayEngine) -> Option<DisclosureSnapshot> {
        let result = self.runtime.block_on(engine.content_history(RELEASE));
        if self.raw().is_none() {
            assert!(result.is_err());
            return None;
        }
        let ContentHistory::Disclosure(snapshot) = result.expect("retained release") else {
            panic!("wrong protocol")
        };
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
        Some(snapshot)
    }
    fn reopen_engine(&self) -> GatewayEngine {
        let controls = controls(self.setup.gate);
        let attempts = GatewayAttempts::new(self.store.reopen().store(), controls.policy.clone())
            .expect("policy");
        let (engine, _) = self.runtime.block_on(load_controlled_engine(
            &self.setup.installation,
            "reopened",
            attempts,
            controls,
        ));
        match self.setup.gate {
            Gate::Revoked => {
                self.runtime
                    .block_on(engine.revoke_connection())
                    .expect("native revocation");
            }
            Gate::ConfigurationReplaced => {
                let revision = engine.effect_configuration_revision().expect("review");
                engine
                    .activate_effect_configuration(revision)
                    .expect("native activation");
            }
            _ => {}
        }
        engine
    }
    fn replay(
        &self,
        engine: &GatewayEngine,
        target: &DisclosureTarget,
        input: &Input,
    ) -> DisclosureSnapshot {
        self.runtime.block_on(async {
            let (server, mut client) = UnixStream::pair().expect("replay connection");
            let result = engine
                .disclose(
                    target,
                    &input.proof,
                    &input.action,
                    input.approval.clone(),
                    DisclosureConnection::new(server, self.setup.channel.clone()),
                )
                .await
                .expect("native retained projection");
            let mut byte = [0];
            assert_eq!(
                client
                    .read(&mut byte)
                    .await
                    .expect("closed history channel"),
                0,
                "history must send neither authentication challenge nor plaintext"
            );
            result
        })
    }
    fn resume(
        &self,
        engine: &GatewayEngine,
        target: &DisclosureTarget,
        input: &Input,
    ) -> DisclosureSnapshot {
        self.runtime.block_on(async {
            let listener = UnixListener::bind(self.setup.installation.root.join("resume.sock"))
                .expect("resume channel");
            let mut recipient = Recipient::start(&self.setup, true);
            let (server, _) = listener.accept().await.expect("real resumed recipient");
            let result = engine
                .disclose(
                    target,
                    &input.proof,
                    &input.action,
                    input.approval.clone(),
                    DisclosureConnection::new(server, self.setup.channel.clone()),
                )
                .await
                .expect("fresh native continuation");
            tokio::task::spawn_blocking(move || recipient.finish(false))
                .await
                .expect("recipient task");
            result
        })
    }
    fn assert_source(&self, charges: &BTreeMap<String, Vec<u8>>) {
        assert_eq!(
            self.store
                .raw()
                .load(GatewayRecordKind::Attempt, &key(SOURCE))
                .expect("source")
                .as_deref(),
            Some(self.source.as_slice())
        );
        assert_eq!(&self.source_charges.records(&self.store, true), charges);
        assert_eq!(
            self.provider.calls.load(Ordering::SeqCst),
            1,
            "no implicit source refetch"
        );
        for (name, expected) in ["release.proof", "release.action", "release.approval"]
            .iter()
            .zip(&self.signed_inputs)
        {
            assert_eq!(
                &std::fs::read(self.setup.installation.root.join(name)).expect("signed input"),
                expected
            );
        }
    }
    fn before(&self, bytes: Option<&[u8]>, snapshot: Option<&DisclosureSnapshot>) {
        let phase =
            bytes.map(|bytes| PausedStore::phase_for(CrashProtocol::Disclosure, RELEASE, bytes));
        assert_eq!(phase.as_deref(), self.setup.point.raw_phase());
        assert_eq!(
            self.store.raw().attempt_keys(8).expect("keys").len(),
            1 + usize::from(bytes.is_some())
        );
        if let Some(snapshot) = snapshot {
            assert_eq!(
                snapshot.stage,
                match self.setup.point {
                    Point::AfterReservationCommit | Point::BeforeEntryCommit =>
                        DisclosureStage::Reserved,
                    Point::AfterAckCommit => DisclosureStage::Acknowledged,
                    _ => DisclosureStage::Unknown,
                }
            );
        } else {
            assert!(matches!(self.setup.point, Point::BeforeReservationCommit));
        }
    }
    fn unauthorized_ack(&self, engine: &GatewayEngine) {
        let request = DisclosureAcknowledgementRequest::for_delivery(
            &self.binding,
            CONTENT.len() as u64,
            SigningKey::from_bytes(&[47; 32]).verifying_key().to_bytes(),
        )
        .expect("hypothetical assertion");
        let signature = SigningKey::from_bytes(&[47; 32])
            .sign(&request.signing_message().expect("message"))
            .to_bytes();
        assert!(
            self.runtime
                .block_on(
                    engine.acknowledge_disclosure(RELEASE, &request.with_signature(signature))
                )
                .is_err(),
            "a signature without a durable grant cannot manufacture delivery history"
        );
    }
    fn substituted_acks(&self, engine: &GatewayEngine, ack: &DisclosureAcknowledgement) -> usize {
        let original: Value =
            serde_json::from_slice(&ack.to_private_bytes().expect("original ACK"))
                .expect("ACK data");
        let mut statements = Vec::new();
        let signer = SigningKey::from_bytes(&[47; 32]);
        for name in [
            "effect",
            "source_effect",
            "protected_content",
            "channel",
            "delivery_instance",
            "projection",
        ] {
            let mut changed = original["request"].clone();
            changed[name][0] = json!(changed[name][0].as_u64().expect("digest byte") ^ 1);
            statements.push((changed, signer.clone()));
        }
        for (name, value) in [
            ("maximum_bytes", CONTENT.len() + 1),
            ("acknowledged_bytes", CONTENT.len() - 1),
        ] {
            let mut changed = original["request"].clone();
            changed[name] = json!(value);
            statements.push((changed, signer.clone()));
        }
        let other = SigningKey::from_bytes(&[48; 32]);
        let principal = auths_raw_key::RawKeyDescriptor::new(
            auths_raw_key::RawKeyType::Ed25519,
            other.verifying_key().to_bytes().to_vec(),
        )
        .expect("descriptor")
        .principal()
        .expect("recipient");
        let mut changed = original["request"].clone();
        changed["recipient_key"] = json!(other.verifying_key().to_bytes());
        changed["recipient"] = json!(principal.as_str());
        statements.push((changed, other));
        let mut altered = statements
            .into_iter()
            .map(|(value, key)| {
                let request = DisclosureAcknowledgementRequest::from_private_bytes(
                    &serde_json_canonicalizer::to_vec(&value).expect("canonical statement"),
                )
                .expect("well-shaped independent statement");
                let signature = key
                    .sign(&request.signing_message().expect("preimage"))
                    .to_bytes();
                request.with_signature(signature)
            })
            .collect::<Vec<_>>();
        let mut damaged = original;
        let mut signature =
            Base64UrlUnpadded::decode_vec(damaged["signature_b64"].as_str().expect("signature"))
                .expect("base64");
        signature[0] ^= 1;
        damaged["signature_b64"] = json!(Base64UrlUnpadded::encode_string(&signature));
        altered.push(
            DisclosureAcknowledgement::from_private_bytes(
                &serde_json_canonicalizer::to_vec(&damaged).expect("canonical ACK"),
            )
            .expect("signature bytes are data"),
        );
        let count = altered.len();
        assert_eq!(count, 10);
        let before = self.raw();
        let charges = self.release_charges.records(&self.store, true);
        for changed in altered {
            assert!(
                self.runtime
                    .block_on(engine.acknowledge_disclosure(RELEASE, &changed))
                    .is_err(),
                "a substituted assertion cannot refine an actual retained grant"
            );
            assert_eq!(self.raw(), before);
            assert_eq!(self.release_charges.records(&self.store, true), charges);
        }
        count
    }
    fn late_ack(
        &self,
        engine: &GatewayEngine,
        before: &DisclosureSnapshot,
    ) -> (DisclosureSnapshot, usize) {
        let ack = DisclosureAcknowledgement::from_private_bytes(
            &std::fs::read(self.setup.installation.root.join("recipient.ack"))
                .expect("actual received ACK retained before crash"),
        )
        .expect("canonical ACK");
        ack.verify(&self.binding, CONTENT.len() as u64)
            .expect("positive original recipient assertion");
        let substitutions = self.substituted_acks(engine, &ack);
        let result = self
            .runtime
            .block_on(engine.acknowledge_disclosure(RELEASE, &ack))
            .expect("late exact ACK despite current gate");
        assert_eq!(result.stage, DisclosureStage::Acknowledged);
        assert_eq!(
            result.revision,
            before.revision + u64::from(before.stage != DisclosureStage::Acknowledged)
        );
        let bytes = self.raw();
        assert_eq!(
            self.runtime
                .block_on(engine.acknowledge_disclosure(RELEASE, &ack))
                .expect("exact ACK replay"),
            result
        );
        assert_eq!(
            self.raw(),
            bytes,
            "exact repeated ACK does not change revision or journal"
        );
        (result, substitutions)
    }
    fn reopen(&self, recipient: &Value) -> Value {
        let before = self.raw();
        let source_charges = self.source_charges.records(&self.store, true);
        let release_charges = self.release_charges.records(&self.store, before.is_some());
        let engine = self.reopen_engine();
        let snapshot = self.snapshot(&engine);
        self.before(before.as_deref(), snapshot.as_ref());
        let target = self.runtime.block_on(kit::target(&engine, &self.setup));
        let input = Input::read(&self.setup.installation.root);
        let witness = engine.execution_witness();
        if self.setup.point.resumable() {
            self.unauthorized_ack(&engine);
            assert_eq!(self.raw(), before);
        }
        let continued = self.setup.point.resumable() && self.setup.gate.current();
        let result = if continued {
            self.resume(&engine, &target, &input)
        } else {
            self.replay(&engine, &target, &input)
        };
        assert_eq!(
            engine.execution_witness(),
            witness,
            "neither recipient delivery nor history needs provider custody/refetch"
        );
        assert_eq!(
            result.stage,
            if continued {
                DisclosureStage::Acknowledged
            } else {
                snapshot.as_ref().expect("retained reservation/grant").stage
            }
        );
        if !continued {
            assert_eq!(
                self.raw(),
                before,
                "reopening does not change retained facts"
            );
            assert_eq!(Some(&result), snapshot.as_ref());
        }
        let after = self.raw();
        let after_charges = self.release_charges.records(&self.store, true);
        if before.is_some() {
            assert_eq!(after_charges, release_charges);
        }
        assert_eq!(self.replay(&engine, &target, &input), result);
        assert_eq!(self.raw(), after);
        self.assert_source(&source_charges);
        let (late, substitutions) = if self.setup.point.received_full() {
            let (snapshot, count) = self.late_ack(&engine, &result);
            (Some(snapshot), count)
        } else {
            (None, 0)
        };
        assert_eq!(
            self.release_charges.records(&self.store, true),
            after_charges
        );
        self.assert_source(&source_charges);
        assert_eq!(engine.execution_witness(), witness);
        let final_snapshot = self.snapshot(&engine).expect("history");
        let final_bytes = self.raw();
        assert_eq!(self.replay(&engine, &target, &input), final_snapshot);
        assert_eq!(self.raw(), final_bytes);
        json!({"pause":self.setup.point, "current_gate":self.setup.gate, "sigkill_gateway":true,
            "sigkill_recipient":matches!(self.setup.point, Point::AfterDeliveryBeforeAck), "original_recipient":recipient,
            "after_reopen":result, "continued_only_after_fresh_authorization":continued, "late_ack":late, "substituted_ack_fields_and_signature_refused":substitutions,
            "final_history":final_snapshot, "provider_reads":1, "source_allocation_calls":1,"source_allocation_bytes":1024,
            "disclosure_allocation_calls":1,"disclosure_allocation_bytes":CONTENT.len(),"native_policy_count_slots":1,"native_policy_sum_bytes":CONTENT.len(),
            "original_inputs_and_source_journal_unchanged":true,"replays_do_not_authenticate_or_redeliver":true,
            "late_ack_and_exact_ack_replay_preserve_charges":true})
    }
}

fn matrix(backend: Backend) {
    let mut cases = Vec::new();
    for point in Point::ALL {
        eprintln!("native disclosure SIGKILL: {}/{point:?}", backend.label());
        let case = Case::new(backend, point, Gate::Current);
        let receipt = case.crash();
        cases.push(case.reopen(&receipt));
    }
    for gate in Gate::CHANGES {
        for point in [
            Point::AfterReservationCommit,
            Point::BeforeEntryCommit,
            Point::AfterDeliveryBeforeAck,
            Point::BeforeAckCommit,
            Point::AfterAckCommit,
        ] {
            eprintln!(
                "native disclosure SIGKILL and current gate: {}/{point:?}/{gate:?}",
                backend.label()
            );
            let case = Case::new(backend, point, gate);
            let receipt = case.crash();
            cases.push(case.reopen(&receipt));
        }
    }
    let bytes = serde_json::to_vec_pretty(&json!({"schema":"auths.native-disclosure-process-crash/1","adapter":backend.label(),
        "scope":"full native read/release authorities and exact approvals; real HTTP source and separate gateway/recipient OS processes with native authenticated Unix protocol; test-only pause after actual native content prefix write; fixed public keys, maintained clock, same UID and trusted stores",
        "excluded":["distinct UID/hostile OS isolation", "power loss and whole-store rollback", "live-provider qualification and human presence", "all remaining fault/concurrency/differential/performance gates"], "cases":cases})).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-disclosure-process-crash-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &bytes).expect("write");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), bytes);
}
#[test]
fn native_file_disclosure_process_crash_fixture_is_current() {
    matrix(Backend::File);
}
#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_disclosure_process_crash_fixture_is_current() {
    assert!(postgres_configured());
    matrix(Backend::Postgres);
}
