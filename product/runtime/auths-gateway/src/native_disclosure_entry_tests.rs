//! Recipient authentication is not delivery permission. Actual adapter locks
//! order native disclosure grants against independent operator withdrawal/time.
use super::*;
use crate::native_dependency_tests::{
    EntryGate, Order, Peer, Scenario, connect, expect, listener, pending, send,
};
use serde::{Deserialize, Serialize};
use std::{
    io::Write as _,
    net::{TcpListener, TcpStream},
    process::{Command, Stdio},
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Race {
    setup: Setup,
    scenario: Scenario,
    order: Order,
    operator_port: u16,
}
impl Race {
    fn key() -> crate::GatewayAttemptKey {
        crate::GatewayAttemptKey::for_operation(
            &crate::effect::fixture_policy().expect("policy"),
            recipe().namespace(),
            &LogicalOperationId::parse(RELEASE).expect("operation"),
        )
        .expect("key")
    }
    const fn enters(&self) -> bool {
        matches!(self.order, Order::GrantFirst)
            || matches!(
                self.scenario,
                Scenario::ApprovalValid
                    | Scenario::AuthorityValid
                    | Scenario::ObserverValid
                    | Scenario::ThresholdValid
            )
    }
    const fn change(&self) -> Change {
        match self.scenario {
            Scenario::ApprovalValid | Scenario::ApprovalExpired => Change::ApprovalExpiry,
            Scenario::AuthorityValid | Scenario::AuthorityExpired => Change::AuthorityExpiry,
            Scenario::Revoke
            | Scenario::Configuration
            | Scenario::ObserverValid
            | Scenario::ObserverExpired
            | Scenario::ThresholdValid
            | Scenario::ThresholdChanged => Change::None,
        }
    }
    fn peer(&self, role: &str) -> Peer {
        Peer(
            Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--exact",
                    "native_information_replay_tests::entry_tests::native_disclosure_entry_peer",
                    "--nocapture",
                ])
                .env(
                    "AUTHS_AP074_DISCLOSURE_ENTRY_PEER",
                    self.setup.root.join("race.json"),
                )
                .env("AUTHS_AP074_DISCLOSURE_ENTRY_ROLE", role)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("independent peer"),
        )
    }
    fn inputs(&self) -> Vec<Vec<u8>> {
        ["release-proof", "release-action", "release-approval"]
            .map(|name| std::fs::read(self.setup.root.join(name)).expect("original signed input"))
            .to_vec()
    }
    fn policy(&self) -> UnixDisclosurePolicy {
        let uid = std::fs::metadata(&self.setup.root).expect("owner").uid();
        UnixDisclosurePolicy::new(uid, uid, [51; 32])
    }
    async fn target(&self, engine: &GatewayEngine) -> crate::effect::DisclosureTarget {
        engine
            .disclosure_target(
                SOURCE,
                SigningKey::from_bytes(&[47; 32]).verifying_key().to_bytes(),
                self.policy().commitment().expect("channel"),
                [52; 32],
            )
            .await
            .expect("retained source")
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerResult {
    snapshot: crate::DisclosureSnapshot,
    recipient_bytes: u64,
    recipient_ack_sent: bool,
    content_wire_bytes: u64,
    witness: crate::GatewayExecutionWitness,
}

async fn proxy(gateway: UnixStream, recipient: UnixStream) -> u64 {
    use tokio::io::AsyncWriteExt as _;
    let (mut from_gateway, mut to_gateway) = gateway.into_split();
    let (mut from_recipient, mut to_recipient) = recipient.into_split();
    let outbound = async {
        let mut captured = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            let count = from_gateway.read(&mut buffer).await.expect("proxy read");
            if count == 0 {
                break;
            }
            assert!(
                captured.len() + count <= 16_384,
                "bounded local wire capture"
            );
            captured.extend_from_slice(&buffer[..count]);
            to_recipient
                .write_all(&buffer[..count])
                .await
                .expect("opaque forwarding");
        }
        to_recipient.shutdown().await.expect("forward EOF");
        // The first native frame is the authenticated challenge. Independently
        // inspect every following wire byte, including partial length prefixes.
        let length = u32::from_be_bytes(
            captured
                .get(..4)
                .expect("native challenge prefix")
                .try_into()
                .expect("four bytes"),
        ) as usize;
        let following = captured
            .get(4 + length..)
            .expect("complete native challenge");
        if !following.is_empty() {
            assert_eq!(following.len(), 4 + CONTENT.len());
            assert_eq!(
                &following[..4],
                &u32::try_from(CONTENT.len())
                    .expect("bounded content")
                    .to_be_bytes()
            );
            assert_eq!(&following[4..], CONTENT);
        }
        following.len() as u64
    };
    let inbound = async {
        tokio::io::copy(&mut from_recipient, &mut to_gateway)
            .await
            .expect("opaque recipient forwarding");
        to_gateway.shutdown().await.expect("forward recipient EOF");
    };
    let (bytes, ()) = tokio::join!(outbound, inbound);
    bytes
}

async fn receive(
    client: UnixStream,
    policy: UnixDisclosurePolicy,
    binding: &crate::effect::EffectBinding,
    recipient: &SigningKey,
) -> (u64, bool) {
    let received = crate::disclosure_transport::receive_disclosure(
        crate::disclosure_transport::DisclosureConnection::new(client, policy),
        binding,
        CONTENT.len() as u64,
        recipient,
    )
    .await;
    match received {
        Ok(received) => {
            assert_eq!(received.content(), CONTENT);
            let count = received.content().len() as u64;
            received
                .acknowledge(recipient)
                .await
                .expect("native exact ACK");
            (count, true)
        }
        Err(code) => {
            assert_eq!(
                code, "gateway.disclosure.read",
                "only pre-content EOF is expected"
            );
            (0, false)
        }
    }
}

fn worker(race: &Race, store: &TestAttempts) {
    let clock = Arc::new(FixedClock::at(NOW));
    let gate = Arc::new(EntryGate::new(
        store.raw(),
        race.order,
        race.setup.barrier_port,
        clock.clone(),
        Race::key(),
    ));
    let attempts = GatewayAttempts::new(
        gate.clone(),
        crate::effect::fixture_policy().expect("policy"),
    )
    .expect("attempts");
    let runtime = runtime();
    let (engine, _) = runtime.block_on(load_controlled_engine(
        &race.setup,
        "release-worker",
        attempts,
        controls(clock, 29),
    ));
    let inputs = race.inputs();
    let result = runtime.block_on(async {
        let target = race.target(&engine).await;
        let effect = engine
            .compile_disclosure_effect(&target, &inputs[0], &inputs[1])
            .await
            .expect("current release effect");
        let recipient = SigningKey::from_bytes(&[47; 32]);
        let (server, gateway_proxy) = UnixStream::pair().expect("gateway channel");
        let (recipient_proxy, client) = UnixStream::pair().expect("recipient channel");
        let (snapshot, (recipient_bytes, recipient_ack_sent), content_wire_bytes) = tokio::join!(
            engine.disclose(
                &target,
                &inputs[0],
                &inputs[1],
                serde_json::from_slice(&inputs[2]).expect("approval"),
                crate::disclosure_transport::DisclosureConnection::new(server, race.policy())
            ),
            receive(client, race.policy(), effect.binding(), &recipient),
            proxy(gateway_proxy, recipient_proxy),
        );
        WorkerResult {
            snapshot: snapshot.expect("retained native disclosure facts"),
            recipient_bytes,
            recipient_ack_sent,
            content_wire_bytes,
            witness: engine.execution_witness(),
        }
    });
    assert!(
        gate.reached(),
        "worker must reach final native disclosure fence"
    );
    crate::native_process_tests::private(
        &race.setup.root.join("worker-result"),
        &serde_json::to_vec(&result).expect("result"),
    );
}

fn operator(race: &Race, store: &TestAttempts) {
    let runtime = runtime();
    let candidate_controls = controls(
        Arc::new(FixedClock::at(NOW)),
        if matches!(race.scenario, Scenario::Configuration) {
            30
        } else {
            29
        },
    );
    let attempts = GatewayAttempts::new(store.raw(), candidate_controls.policy.clone())
        .expect("candidate policy");
    let (engine, record) = runtime.block_on(load_controlled_engine(
        &race.setup,
        "release-operator",
        attempts,
        candidate_controls,
    ));
    let shared = SharedConnection::new(
        store.raw(),
        record.provider_kind().clone(),
        record.alias().clone(),
    );
    let current = runtime
        .block_on(shared.load())
        .expect("load")
        .expect("connection");
    let reviewed = engine
        .effect_configuration_revision()
        .expect("operator review");
    let mut channel = connect(race.operator_port);
    send(&mut channel, b'S');
    expect(&mut channel, b'G');
    match race.order {
        Order::LockWait => {
            let key = crate::connection::connection_key(record.provider_kind(), record.alias());
            store
                .raw()
                .fenced_replace(&[(GatewayRecordKind::Connection, key)], &mut |rows| {
                    send(&mut channel, b'H');
                    expect(&mut channel, b'G');
                    Ok(rows[0].clone().expect("actual connection bytes"))
                })
                .expect("actual held writer fence");
        }
        _ => match race.scenario {
            Scenario::Revoke => {
                let revoked = current
                    .record()
                    .transition_state(auths_connections::ConnectionState::Revoked, NOW)
                    .expect("native revocation");
                runtime
                    .block_on(shared.replace(&current, &revoked))
                    .expect("operator CAS");
            }
            Scenario::Configuration => {
                engine
                    .activate_effect_configuration(reviewed)
                    .expect("operator activation");
            }
            _ => unreachable!(),
        },
    }
    crate::native_process_tests::private(&race.setup.root.join("operator-result"), b"committed");
    send(&mut channel, b'D');
}

#[test]
fn native_disclosure_entry_peer() {
    let Some(path) = std::env::var_os("AUTHS_AP074_DISCLOSURE_ENTRY_PEER") else {
        return;
    };
    let race: Race =
        serde_json::from_slice(&std::fs::read(path).expect("setup")).expect("closed setup");
    let store = TestAttempts::attach(Backend::parse(&race.setup.backend), &race.setup.location);
    match std::env::var("AUTHS_AP074_DISCLOSURE_ENTRY_ROLE")
        .expect("role")
        .as_str()
    {
        "worker" => worker(&race, &store),
        "operator" => operator(&race, &store),
        _ => panic!("unsupported test role"),
    }
}

struct Case {
    fixture: Fixture,
    race: Race,
    worker_listener: TcpListener,
    operator_listener: TcpListener,
    input: Input,
    target: crate::effect::DisclosureTarget,
    signed_inputs: Vec<Vec<u8>>,
    evidence: Option<Value>,
}
impl Case {
    fn new(backend: Backend, scenario: Scenario, order: Order) -> Self {
        let fixture = Fixture::new(backend);
        let worker_listener = listener();
        let operator_listener = listener();
        let setup = Setup {
            backend: backend.label().to_owned(),
            location: fixture.store.location(),
            root: fixture.setup.root.clone(),
            provider_port: fixture.provider.port,
            barrier_port: worker_listener.local_addr().expect("port").port(),
        };
        let race = Race {
            setup,
            scenario,
            order,
            operator_port: operator_listener.local_addr().expect("port").port(),
        };
        let source = fixture
            .runtime
            .block_on(Input::content(&fixture.engine, Change::None));
        fixture
            .runtime
            .block_on(fixture.engine.acquire_content_action(
                &source.proof,
                &source.action,
                source.approval,
            ))
            .expect("actual original HTTP acquisition");
        let target = fixture.runtime.block_on(race.target(&fixture.engine));
        let mut input =
            fixture
                .runtime
                .block_on(Input::disclosure(&fixture.engine, &target, race.change()));
        let evidence = fixture
            .runtime
            .block_on(selected_evidence(&fixture, &race, &target, &mut input));
        let signed_inputs = vec![
            input.proof.clone(),
            input.action.clone(),
            serde_json::to_vec(&input.approval).expect("approval"),
        ];
        for (name, bytes) in ["release-proof", "release-action", "release-approval"]
            .iter()
            .zip(&signed_inputs)
        {
            crate::native_process_tests::private(&race.setup.root.join(name), bytes);
        }
        crate::native_process_tests::private(
            &race.setup.root.join("race.json"),
            &serde_json::to_vec(&race).expect("setup"),
        );
        Self {
            fixture,
            race,
            worker_listener,
            operator_listener,
            input,
            target,
            signed_inputs,
            evidence,
        }
    }
    fn schedule(
        &self,
        operator: &mut Peer,
        worker: &mut Peer,
        op: &mut TcpStream,
        run: &mut TcpStream,
    ) {
        assert_eq!(self.fixture.provider.calls.load(Ordering::SeqCst), 1);
        match self.race.order {
            Order::ChangeFirst => {
                send(op, b'G');
                expect(op, b'D');
                operator.finish();
                send(run, b'G');
            }
            Order::GrantFirst => {
                send(op, b'G');
                pending(op);
                assert!(!self.race.setup.root.join("operator-result").exists());
                send(run, b'G');
                expect(op, b'D');
                operator.finish();
            }
            Order::LockWait => {
                send(op, b'G');
                expect(op, b'H');
                send(run, b'G');
                expect(run, b'W');
                run.write_all(&(NOW + self.race.scenario.time_shift()).to_be_bytes())
                    .expect("clock advance");
                expect(run, b'A');
                pending(run);
                assert_eq!(self.fixture.provider.calls.load(Ordering::SeqCst), 1);
                send(op, b'G');
                expect(op, b'D');
                operator.finish();
                expect(run, b'D');
            }
        }
        worker.finish();
    }
    fn execute(&self) -> WorkerResult {
        let mut operator = self.race.peer("operator");
        let mut op = operator.accept(&self.operator_listener);
        expect(&mut op, b'S');
        let mut worker = self.race.peer("worker");
        assert_ne!(worker.0.id(), operator.0.id());
        assert_ne!(worker.0.id(), std::process::id());
        let mut run = worker.accept(&self.worker_listener);
        expect(&mut run, b'P');
        self.schedule(&mut operator, &mut worker, &mut op, &mut run);
        serde_json::from_slice(
            &std::fs::read(self.race.setup.root.join("worker-result")).expect("result"),
        )
        .expect("native result")
    }
    fn verify(&self, result: &WorkerResult) -> Value {
        assert_eq!(self.race.inputs(), self.signed_inputs);
        assert_eq!(
            result.snapshot.stage,
            if self.race.enters() {
                crate::DisclosureStage::Acknowledged
            } else {
                crate::DisclosureStage::Reserved
            }
        );
        assert_eq!(
            result.recipient_bytes,
            if self.race.enters() {
                CONTENT.len() as u64
            } else {
                0
            }
        );
        assert_eq!(result.recipient_ack_sent, self.race.enters());
        assert_eq!(
            result.content_wire_bytes,
            if self.race.enters() {
                (CONTENT.len() + 4) as u64
            } else {
                0
            }
        );
        assert_eq!(
            (
                result.snapshot.reserved_deliveries,
                result.snapshot.reserved_bytes
            ),
            (1, CONTENT.len() as u64)
        );
        assert_eq!(result.witness.credential_lease_calls, 0);
        assert_eq!(result.witness.write_transport_entries, 0);
        assert_eq!(result.witness.read_transport_entries, 0);
        assert_eq!(self.fixture.provider.calls.load(Ordering::SeqCst), 1);
        let rows = self.fixture.records();
        assert_eq!(rows.len(), 2);
        let record: Value = serde_json::from_slice(
            &self
                .fixture
                .store
                .raw()
                .load(GatewayRecordKind::Attempt, &Race::key())
                .expect("load")
                .expect("release"),
        )
        .expect("record");
        assert_eq!(record["evaluated_at"], NOW);
        assert_eq!(record["state"]["facts"]["allocation"], 0);
        assert_eq!(!record["entry"].is_null(), self.race.enters());
        if self.race.enters() && matches!(self.race.order, Order::LockWait) {
            assert_eq!(
                record["entry"]["granted_at"],
                NOW + self.race.scenario.time_shift()
            );
        }
        self.reopen(&result.snapshot);
        assert_eq!(self.fixture.records(), rows);
        let mut summary = json!({"scenario":self.race.scenario,"order":self.race.order,"native_snapshot":result.snapshot,
            "separate_worker_operator_processes":true,"signed_inputs_unchanged":true,"original_admission_time":NOW,
            "clock_after_wait":matches!(self.race.order,Order::LockWait).then(||NOW+self.race.scenario.time_shift()),
            "recipient_bytes":result.recipient_bytes,"native_recipient_ack_sent":result.recipient_ack_sent,
            "captured_wire_bytes_after_authentication_challenge":result.content_wire_bytes,
            "provider_reads":1,"additional_provider_reads":0,"credential_leases_at_release":0,
            "reopened_journal_unchanged":true,"historical_replay_sends_nothing":self.race.enters()});
        if let Some(evidence) = &self.evidence {
            summary["selected_native_evidence"] = evidence.clone();
        }
        summary
    }
    fn reopen(&self, snapshot: &crate::DisclosureSnapshot) {
        let (engine, _) = self.fixture.runtime.block_on(load_controlled_engine(
            &self.race.setup,
            "release-reopened",
            self.fixture.store.reopen(),
            controls(
                Arc::new(FixedClock::at(NOW + self.race.scenario.time_shift())),
                29,
            ),
        ));
        match self
            .fixture
            .runtime
            .block_on(engine.content_history(RELEASE))
            .expect("native history")
        {
            crate::ContentHistory::Disclosure(actual) => assert_eq!(&actual, snapshot),
            crate::ContentHistory::Acquisition(_) => panic!("wrong protocol"),
        }
        if !self.race.enters() {
            return;
        }
        let before = engine.execution_witness();
        self.fixture.runtime.block_on(async {
            let (server, mut client) = UnixStream::pair().expect("replay channel");
            let reader = async {
                let mut bytes = Vec::new();
                client.read_to_end(&mut bytes).await.expect("EOF");
                assert!(bytes.is_empty());
            };
            let (actual, ()) = tokio::join!(
                engine.disclose(
                    &self.target,
                    &self.input.proof,
                    &self.input.action,
                    self.input.approval.clone(),
                    crate::disclosure_transport::DisclosureConnection::new(
                        server,
                        self.race.policy()
                    )
                ),
                reader
            );
            assert_eq!(&actual.expect("historical native replay"), snapshot);
        });
        assert_eq!(engine.execution_witness(), before);
    }
}

async fn selected_evidence(
    fixture: &Fixture,
    race: &Race,
    target: &crate::effect::DisclosureTarget,
    input: &mut Input,
) -> Option<Value> {
    if !matches!(
        race.scenario,
        Scenario::ObserverValid
            | Scenario::ObserverExpired
            | Scenario::ThresholdValid
            | Scenario::ThresholdChanged
    ) {
        return None;
    }
    use crate::observed_tests::threshold_testkit as kit;
    let threshold = matches!(
        race.scenario,
        Scenario::ThresholdValid | Scenario::ThresholdChanged
    );
    let after = NOW + race.scenario.time_shift();
    let call = target
        .authorization_call(
            &recipe(),
            &LogicalOperationId::parse(RELEASE).expect("operation"),
        )
        .expect("native release call");
    let signed = kit::signed(&call, threshold);
    let mut witness = kit::selection_witness(&signed, threshold, after);
    let first = fixture
        .engine
        .compile_disclosure_effect(target, &signed.proof, &signed.action)
        .await
        .expect("initial native disclosure");
    let exact = Input::approval(&first, Change::None);
    let before = first.binding().clone();
    first
        .approve(
            exact.clone(),
            &SigningKey::from_bytes(&[29; 32]).verifying_key().to_bytes(),
            after,
        )
        .expect("original approval interval remains current after wait");
    fixture.clock.set(after);
    let fresh = fixture
        .engine
        .compile_disclosure_effect(target, &signed.proof, &signed.action)
        .await;
    fixture.clock.set(NOW);
    kit::verify_binding(&before, fresh, exact.clone(), threshold, after);
    witness["old_approval_accepts_current_effect"] = json!(after <= NOW + 5);
    input.proof = signed.proof;
    input.action = signed.action;
    input.approval = exact;
    Some(witness)
}

fn matrix(backend: Backend) {
    let schedules = [
        (Scenario::Revoke, Order::ChangeFirst),
        (Scenario::Revoke, Order::GrantFirst),
        (Scenario::Configuration, Order::ChangeFirst),
        (Scenario::Configuration, Order::GrantFirst),
        (Scenario::ApprovalValid, Order::LockWait),
        (Scenario::ApprovalExpired, Order::LockWait),
        (Scenario::AuthorityValid, Order::LockWait),
        (Scenario::AuthorityExpired, Order::LockWait),
        (Scenario::ObserverValid, Order::LockWait),
        (Scenario::ObserverExpired, Order::LockWait),
        (Scenario::ThresholdValid, Order::LockWait),
        (Scenario::ThresholdChanged, Order::LockWait),
    ];
    let cases: Vec<_> = schedules
        .into_iter()
        .map(|(scenario, order)| {
            let case = Case::new(backend, scenario, order);
            let result = case.execute();
            case.verify(&result)
        })
        .collect();
    let artifact=serde_json::to_vec_pretty(&json!({"schema":"auths.native-disclosure-entry-order/1","adapter":backend.label(),"cases":cases,
        "scope":"native separate release authority and exact approval, real local HTTP source acquisition, independent worker/operator OS processes, maintained adapter writer fence; gateway/recipient tasks in the worker over same-UID Unix sockets; fixed public keys and controlled maintained clock",
        "excluded":["separate gateway/recipient OS processes in each worker","hostile OS containment","all selected-authority and revocation scopes","installed language framing","whole-store rollback and power loss"]})).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-disclosure-entry-order-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("write");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), artifact);
}
#[test]
fn native_file_disclosure_entry_order_fixture_is_current() {
    matrix(Backend::File);
}
#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_disclosure_entry_order_fixture_is_current() {
    assert!(postgres_configured());
    matrix(Backend::Postgres);
}
