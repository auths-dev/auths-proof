//! Native mutation entry linearizes with actual adapter locks, independent
//! operator processes and the maintained test clock. No decision is fabricated.
use super::*;
use crate::GatewayAttemptKey;
use crate::native_dependency_tests::{
    EntryGate, Order, Peer, Scenario, connect, expect, listener, pending, send,
};
use serde::{Deserialize, Serialize};
use std::{
    net::TcpStream,
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
    fn key() -> GatewayAttemptKey {
        GatewayAttemptKey::for_operation(
            &crate::effect::fixture_policy().expect("policy"),
            recipe().namespace(),
            &LogicalOperationId::parse(OPERATION).expect("operation"),
        )
        .expect("key")
    }
    const fn enters(&self) -> bool {
        matches!(self.order, Order::GrantFirst)
            || matches!(
                self.scenario,
                Scenario::ApprovalValid | Scenario::AuthorityValid
            )
    }
    const fn change(&self) -> Change {
        match self.scenario {
            Scenario::ApprovalValid | Scenario::ApprovalExpired => Change::ApprovalExpiry,
            Scenario::AuthorityValid | Scenario::AuthorityExpired => Change::AuthorityExpiry,
            Scenario::Revoke | Scenario::Configuration => Change::None,
            _ => unreachable!(),
        }
    }
    fn inputs(&self) -> Vec<Vec<u8>> {
        ["proof", "action", "approval"]
            .map(|suffix| {
                std::fs::read(self.setup.root.join(suffix)).expect("original signed input")
            })
            .to_vec()
    }
    fn peer(&self, role: &str) -> Peer {
        Peer(
            Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--exact",
                    "native_mutation_replay_tests::entry_tests::native_mutation_entry_peer",
                    "--nocapture",
                ])
                .env(
                    "AUTHS_AP074_MUTATION_ENTRY_PEER",
                    self.setup.root.join("race.json"),
                )
                .env("AUTHS_AP074_MUTATION_ENTRY_ROLE", role)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("independent peer"),
        )
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
        "entry-worker",
        attempts,
        controls(clock, 29),
    ));
    let inputs = race.inputs();
    let approval = serde_json::from_slice(&inputs[2]).expect("exact approval");
    let result = runtime.block_on(engine.submit(&inputs[0], &inputs[1], approval));
    assert!(
        gate.reached(),
        "native worker must reach final fence: {result:?}"
    );
    crate::native_process_tests::private(
        &race.setup.root.join("worker-result"),
        &serde_json::to_vec(&result).expect("result"),
    );
    crate::native_process_tests::private(
        &race.setup.root.join("worker-witness"),
        &serde_json::to_vec(&engine.execution_witness()).expect("witness"),
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
        .expect("operator candidate policy");
    let (engine, record) = runtime.block_on(load_controlled_engine(
        &race.setup,
        "entry-operator",
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
fn native_mutation_entry_peer() {
    let Some(path) = std::env::var_os("AUTHS_AP074_MUTATION_ENTRY_PEER") else {
        return;
    };
    let race: Race =
        serde_json::from_slice(&std::fs::read(path).expect("setup")).expect("closed setup");
    let store = TestAttempts::attach(Backend::parse(&race.setup.backend), &race.setup.location);
    match std::env::var("AUTHS_AP074_MUTATION_ENTRY_ROLE")
        .expect("role")
        .as_str()
    {
        "worker" => worker(&race, &store),
        "operator" => operator(&race, &store),
        _ => panic!("unsupported test role"),
    }
}

struct Case {
    _directory: tempfile::TempDir,
    store: TestAttempts,
    race: Race,
    worker_listener: TcpListener,
    operator_listener: TcpListener,
    provider: Provider,
    input: Input,
    signed_inputs: Vec<Vec<u8>>,
}
impl Case {
    fn new(backend: Backend, scenario: Scenario, order: Order) -> Self {
        let directory = tempfile::tempdir().expect("directory");
        let root = std::fs::canonicalize(directory.path()).expect("root");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("private");
        let worker_listener = listener();
        let operator_listener = listener();
        let provider = Provider::start();
        let store = TestAttempts::open(backend);
        let race = Race {
            scenario,
            order,
            operator_port: operator_listener.local_addr().expect("port").port(),
            setup: Setup {
                backend: backend.label().to_owned(),
                location: store.location(),
                root,
                provider_port: provider.port,
                barrier_port: worker_listener.local_addr().expect("port").port(),
            },
        };
        let runtime = runtime();
        let (engine, record) = runtime.block_on(load_controlled_engine(
            &race.setup,
            "entry-parent",
            store.attempts().clone(),
            controls(Arc::new(FixedClock::at(NOW)), 29),
        ));
        let shared = SharedConnection::new(
            store.raw(),
            record.provider_kind().clone(),
            record.alias().clone(),
        );
        runtime
            .block_on(shared.insert(&record))
            .expect("connection");
        engine
            .initialize_effect_configuration()
            .expect("configuration");
        let input = runtime.block_on(Input::author(&engine, race.change()));
        let signed_inputs = vec![
            input.proof.clone(),
            input.action.clone(),
            serde_json::to_vec(&input.approval).expect("approval"),
        ];
        for (name, bytes) in ["proof", "action", "approval"].iter().zip(&signed_inputs) {
            crate::native_process_tests::private(&race.setup.root.join(name), bytes);
        }
        crate::native_process_tests::private(
            &race.setup.root.join("race.json"),
            &serde_json::to_vec(&race).expect("setup"),
        );
        Self {
            _directory: directory,
            store,
            race,
            worker_listener,
            operator_listener,
            provider,
            input,
            signed_inputs,
        }
    }
    fn schedule(
        &self,
        operator: &mut Peer,
        worker: &mut Peer,
        op: &mut TcpStream,
        run: &mut TcpStream,
    ) {
        assert!(self.provider.bodies.lock().expect("requests").is_empty());
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
                assert!(self.provider.bodies.lock().expect("requests").is_empty());
                send(op, b'G');
                expect(op, b'D');
                operator.finish();
                expect(run, b'D');
            }
        }
        worker.finish();
    }
    fn execute(&self) -> GatewaySubmitResult {
        let mut operator = self.race.peer("operator");
        let mut op = operator.accept(&self.operator_listener);
        expect(&mut op, b'S');
        let mut worker = self.race.peer("worker");
        assert_ne!(operator.0.id(), worker.0.id());
        assert_ne!(worker.0.id(), std::process::id());
        let mut run = worker.accept(&self.worker_listener);
        expect(&mut run, b'P');
        self.schedule(&mut operator, &mut worker, &mut op, &mut run);
        serde_json::from_slice(
            &std::fs::read(self.race.setup.root.join("worker-result")).expect("result"),
        )
        .expect("native result")
    }
    fn verify(&self, result: &GatewaySubmitResult) -> Value {
        assert_eq!(self.race.inputs(), self.signed_inputs);
        if self.race.enters() {
            assert_eq!(
                *result,
                GatewaySubmitResult::ResponseRecorded { status: 200 }
            );
            assert_eq!(
                *self.provider.bodies.lock().expect("requests"),
                vec![self.input.body.clone()]
            );
        } else {
            assert!(matches!(result, GatewaySubmitResult::Reserved { .. }));
            assert!(self.provider.bodies.lock().expect("requests").is_empty());
        }
        let witness: crate::GatewayExecutionWitness = serde_json::from_slice(
            &std::fs::read(self.race.setup.root.join("worker-witness")).expect("witness"),
        )
        .expect("native witness");
        assert_eq!(
            witness.credential_lease_calls, 1,
            "the pause is after admission/custody"
        );
        assert_eq!(
            witness.write_transport_entries,
            u64::from(self.race.enters())
        );
        assert_eq!(witness.read_transport_entries, 0);
        let raw = self.store.raw();
        let bytes = raw
            .load(GatewayRecordKind::Attempt, &Race::key())
            .expect("load")
            .expect("attempt");
        let record: Value = serde_json::from_slice(&bytes).expect("record");
        assert_eq!(record["evaluated_at"], NOW);
        assert_eq!(!record["entry"].is_null(), self.race.enters());
        if matches!(self.race.order, Order::LockWait) && self.race.enters() {
            assert_eq!(
                record["entry"]["granted_at"],
                NOW + self.race.scenario.time_shift()
            );
        }
        self.reopen(result, &bytes);
        json!({"scenario":self.race.scenario, "order":self.race.order,
            "separate_worker_and_operator_processes":true, "signed_inputs_unchanged":true,
            "native_result":result, "admission_time":NOW,
            "clock_after_wait":matches!(self.race.order, Order::LockWait).then(|| NOW+self.race.scenario.time_shift()),
            "actual_credential_leases":1, "actual_provider_writes":u64::from(self.race.enters()),
            "reopened_history_unchanged":true, "historical_replay_performs_no_io":self.race.enters()})
    }
    fn reopen(&self, result: &GatewaySubmitResult, bytes: &[u8]) {
        let runtime = runtime();
        let (engine, _) = runtime.block_on(load_controlled_engine(
            &self.race.setup,
            "entry-reopened",
            self.store.reopen(),
            controls(
                Arc::new(FixedClock::at(NOW + self.race.scenario.time_shift())),
                29,
            ),
        ));
        let operation = LogicalOperationId::parse(OPERATION).expect("operation");
        let history = runtime
            .block_on(self.store.attempts().read(recipe().namespace(), &operation))
            .expect("history")
            .expect("retained");
        assert_eq!(
            history.stage(),
            if self.race.enters() {
                crate::GatewayAttemptStage::ResponseRecorded
            } else {
                crate::GatewayAttemptStage::Reserved
            }
        );
        if self.race.enters() {
            let before = engine.execution_witness();
            assert_eq!(runtime.block_on(self.input.submit(&engine)), *result);
            assert_eq!(engine.execution_witness(), before);
        }
        assert_eq!(
            self.store
                .raw()
                .load(GatewayRecordKind::Attempt, &Race::key())
                .expect("load")
                .expect("attempt"),
            bytes
        );
    }
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
    ];
    let cases: Vec<_> = schedules
        .into_iter()
        .map(|(scenario, order)| {
            let case = Case::new(backend, scenario, order);
            let result = case.execute();
            case.verify(&result)
        })
        .collect();
    let artifact = serde_json::to_vec_pretty(&json!({"schema":"auths.native-mutation-entry-order/1",
        "adapter":backend.label(), "cases":cases,
        "scope":"actual native mutation, separate worker/operator OS processes, maintained durable writer fence, public fixture keys and controlled maintained test clock, counting local HTTP provider without deduplication",
        "excluded":["disclosure races", "selected observer and threshold expiry", "installed language framing", "hostile OS containment", "whole-store rollback and power loss"]})).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-mutation-entry-order-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("write");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), artifact);
}

#[test]
fn native_file_mutation_entry_order_fixture_is_current() {
    matrix(Backend::File);
}

#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_mutation_entry_order_fixture_is_current() {
    assert!(postgres_configured());
    matrix(Backend::Postgres);
}
