//! Independent native workers and operators race shared dependencies and time.
//! Trusted test control channels schedule real adapter fences; they do not
//! replace native authorization, decisions, record bytes or entry permits.
use crate::native_process_tests::{
    EngineControls, NOW, Provider, Setup, acquire, authorize_bounded, load_controlled_engine,
    load_engine, private, recipe, runtime,
};
use crate::store::GatewayFenceDecision;
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::{
    AcquisitionSnapshot, AcquisitionStage, ContentHistory, FixedClock, GatewayAttemptError,
    GatewayAttemptKey, GatewayAttemptStore, GatewayAttempts, GatewayInsert, GatewayRecordEntry,
    GatewayRecordKind, LogicalOperationId, SharedConnection,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const OPERATION: &str = "dependency-read";

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Scenario {
    Revoke,
    Configuration,
    ApprovalValid,
    ApprovalExpired,
    AuthorityValid,
    AuthorityExpired,
    ObserverValid,
    ObserverExpired,
    ThresholdValid,
    ThresholdChanged,
}
impl Scenario {
    pub(super) const fn time_shift(self) -> u64 {
        match self {
            Self::ApprovalValid | Self::AuthorityValid => 4,
            Self::ObserverValid | Self::ThresholdValid => 5,
            _ => 6,
        }
    }
    const fn authority_until(self) -> u64 {
        if matches!(self, Self::AuthorityValid | Self::AuthorityExpired) {
            NOW + 5
        } else {
            NOW + 86_400
        }
    }
    const fn approval_until(self) -> u64 {
        if matches!(self, Self::ApprovalValid | Self::ApprovalExpired) {
            NOW + 5
        } else {
            NOW + 300
        }
    }
}
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Order {
    ChangeFirst,
    GrantFirst,
    LockWait,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Race {
    installation: Setup,
    operator_port: u16,
    scenario: Scenario,
    order: Order,
}
impl Race {
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
    fn key() -> GatewayAttemptKey {
        GatewayAttemptKey::for_operation(
            &crate::effect::fixture_policy().expect("policy"),
            recipe().namespace(),
            &LogicalOperationId::parse(OPERATION).expect("operation"),
        )
        .expect("key")
    }
}

pub(super) fn connect(port: u16) -> TcpStream {
    let channel = TcpStream::connect(("127.0.0.1", port)).expect("test control");
    channel
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("deadline");
    channel
        .set_write_timeout(Some(Duration::from_secs(3)))
        .expect("deadline");
    channel
}
pub(super) fn send(channel: &mut TcpStream, marker: u8) {
    channel.write_all(&[marker]).expect("marker");
}
pub(super) fn expect(channel: &mut TcpStream, marker: u8) {
    let mut value = [0];
    channel.read_exact(&mut value).expect("control marker");
    assert_eq!(value, [marker]);
}
pub(super) fn pending(channel: &mut TcpStream) {
    channel
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("short observation");
    let mut value = [0];
    let error = channel
        .read(&mut value)
        .expect_err("writer must remain blocked by real fence");
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    channel
        .set_read_timeout(Some(Duration::from_secs(15)))
        .expect("deadline");
}

pub(super) struct EntryGate {
    inner: Arc<dyn GatewayAttemptStore>,
    order: Order,
    port: u16,
    clock: Arc<FixedClock>,
    fired: AtomicBool,
    key: GatewayAttemptKey,
}
impl EntryGate {
    pub(super) fn reached(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }
    pub(super) fn new(
        inner: Arc<dyn GatewayAttemptStore>,
        order: Order,
        port: u16,
        clock: Arc<FixedClock>,
        key: GatewayAttemptKey,
    ) -> Self {
        Self {
            inner,
            order,
            port,
            clock,
            key,
            fired: AtomicBool::new(false),
        }
    }
    fn before_lock(
        &self,
        keys: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut GatewayFenceDecision<'_>,
    ) -> Result<(), GatewayAttemptError> {
        let mut channel = connect(self.port);
        send(&mut channel, b'P');
        expect(&mut channel, b'G');
        match self.order {
            Order::ChangeFirst => self.inner.fenced_replace(keys, decide),
            Order::LockWait => {
                // Clock mutation runs concurrently while this thread waits in
                // the actual adapter. Neither the native decision nor its
                // snapshots are fabricated or pre-evaluated by this wrapper.
                let mut receiver = channel.try_clone().expect("clock control");
                let clock = self.clock.clone();
                let control = thread::spawn(move || {
                    let mut bytes = [0; 8];
                    receiver.read_exact(&mut bytes).expect("clock value");
                    clock.set(u64::from_be_bytes(bytes));
                    send(&mut receiver, b'A');
                });
                send(&mut channel, b'W');
                let result = self.inner.fenced_replace(keys, decide);
                control.join().expect("clock thread");
                send(&mut channel, b'D');
                result
            }
            Order::GrantFirst => unreachable!("this order pauses under the fence"),
        }
    }
}
impl GatewayAttemptStore for EntryGate {
    fn fenced_replace(
        &self,
        keys: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut GatewayFenceDecision<'_>,
    ) -> Result<(), GatewayAttemptError> {
        let target = keys.first() == Some(&(GatewayRecordKind::Attempt, self.key));
        if !target || self.fired.swap(true, Ordering::SeqCst) {
            return self.inner.fenced_replace(keys, decide);
        }
        for kind in [
            GatewayRecordKind::Connection,
            GatewayRecordKind::EffectConfiguration,
        ] {
            let dependencies: Vec<_> = keys.iter().filter(|(found, _)| *found == kind).collect();
            assert_eq!(dependencies.len(), 1, "entry fences its actual dependency");
            assert_ne!(dependencies[0].1, self.key, "physically distinct record");
        }
        if !matches!(self.order, Order::GrantFirst) {
            return self.before_lock(keys, decide);
        }
        self.inner.fenced_replace(keys, &mut |snapshots| {
            let bytes = decide(snapshots)?;
            let value: Value = serde_json::from_slice(&bytes).expect("native decision");
            assert!(
                value["state"]["facts"]["phase"]["stage"] == "entry-granted"
                    || value["state"]["facts"]["stage"] == "entry-granted"
            );
            let mut channel = connect(self.port);
            send(&mut channel, b'P');
            expect(&mut channel, b'G');
            Ok(bytes)
        })
    }
    fn fenced_insert_all(
        &self,
        entries: &[GatewayRecordEntry],
        dependencies: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut GatewayFenceDecision<'_>,
    ) -> Result<GatewayInsert, GatewayAttemptError> {
        self.inner.fenced_insert_all(entries, dependencies, decide)
    }
    fn insert_all(
        &self,
        entries: &[GatewayRecordEntry],
    ) -> Result<GatewayInsert, GatewayAttemptError> {
        self.inner.insert_all(entries)
    }
    fn load(
        &self,
        kind: GatewayRecordKind,
        key: &GatewayAttemptKey,
    ) -> Result<Option<Vec<u8>>, GatewayAttemptError> {
        self.inner.load(kind, key)
    }
    fn replace(
        &self,
        kind: GatewayRecordKind,
        key: &GatewayAttemptKey,
        current: &[u8],
        next: &[u8],
    ) -> Result<(), GatewayAttemptError> {
        self.inner.replace(kind, key, current, next)
    }
    fn sweep_expired(&self, now: u64, limit: usize) -> Result<usize, GatewayAttemptError> {
        self.inner.sweep_expired(now, limit)
    }
    fn attempt_keys(&self, limit: usize) -> Result<Vec<GatewayAttemptKey>, GatewayAttemptError> {
        self.inner.attempt_keys(limit)
    }
}

fn run_worker(race: &Race, store: &TestAttempts) {
    let clock = Arc::new(FixedClock::at(NOW));
    let gate = Arc::new(EntryGate {
        inner: store.raw(),
        order: race.order,
        port: race.installation.barrier_port,
        clock: clock.clone(),
        fired: AtomicBool::new(false),
        key: Race::key(),
    });
    let attempts = GatewayAttempts::new(gate, crate::effect::fixture_policy().expect("policy"))
        .expect("attempts");
    let controls = EngineControls {
        policy: crate::effect::fixture_policy().expect("policy"),
        clock,
        recipe: None,
        trust: None,
    };
    let runtime = runtime();
    let (engine, _) = runtime.block_on(load_controlled_engine(
        &race.installation,
        "worker",
        attempts,
        controls,
    ));
    let result = runtime.block_on(acquire(&engine, &race.installation.root, OPERATION));
    private(
        &race.installation.root.join("worker-result"),
        &serde_json::to_vec(&result).expect("result"),
    );
    private(
        &race.installation.root.join("worker-witness"),
        &serde_json::to_vec(&engine.execution_witness()).expect("witness"),
    );
}
fn hold_connection(race: &Race, store: &TestAttempts, channel: &mut TcpStream) {
    let record = crate::harness::fixture_connection(&recipe()).expect("connection template");
    let key = crate::connection::connection_key(record.provider_kind(), record.alias());
    store
        .raw()
        .fenced_replace(&[(GatewayRecordKind::Connection, key)], &mut |snapshots| {
            send(channel, b'H');
            expect(channel, b'G');
            // A privileged test writer holds a physically distinct real record.
            // Its exact byte-preserving write creates no semantic state change.
            Ok(snapshots[0].clone().expect("connection"))
        })
        .expect("held connection fence");
    assert!(matches!(race.order, Order::LockWait));
}
fn run_operator(race: &Race, store: &TestAttempts) {
    // Prepare custody, current connection and the exact native review token
    // before the competing worker holds a writer fence. The test races
    // publication, not the opening/recovery of a new host's store handle.
    let runtime = runtime();
    let mut controls = EngineControls::baseline();
    if matches!(race.scenario, Scenario::Configuration) {
        use ed25519_dalek::SigningKey;
        controls.policy = crate::effect::EffectPolicy::new(
            "test-partition".to_owned(),
            1,
            SigningKey::from_bytes(&[30; 32]).verifying_key().to_bytes(),
        )
        .expect("new operator policy");
    }
    let operator_attempts = GatewayAttempts::new(store.raw(), controls.policy.clone())
        .expect("operator store policy matches candidate installation");
    let (engine, record) = runtime.block_on(load_controlled_engine(
        &race.installation,
        "operator",
        operator_attempts,
        controls,
    ));
    let shared = SharedConnection::new(
        store.raw(),
        record.provider_kind().clone(),
        record.alias().clone(),
    );
    let current = runtime
        .block_on(shared.load())
        .expect("current connection")
        .expect("connection");
    let reviewed = engine
        .effect_configuration_revision()
        .expect("native operator review");
    let mut channel = connect(race.operator_port);
    send(&mut channel, b'S');
    expect(&mut channel, b'G');
    if matches!(race.order, Order::LockWait) {
        hold_connection(race, store, &mut channel);
    } else {
        match race.scenario {
            Scenario::Revoke => {
                let next = current
                    .record()
                    .transition_state(auths_connections::ConnectionState::Revoked, NOW)
                    .expect("native revocation transition");
                let changed = runtime
                    .block_on(shared.replace(&current, &next))
                    .expect("native revocation CAS");
                assert_eq!(
                    changed.record().state(),
                    auths_connections::ConnectionState::Revoked
                );
            }
            Scenario::Configuration => {
                engine
                    .activate_effect_configuration(reviewed)
                    .expect("native activation");
                assert_ne!(
                    engine
                        .effect_configuration_revision()
                        .expect("active revision"),
                    reviewed
                );
            }
            _ => unreachable!("clock cases hold the fence only"),
        }
    }
    private(
        &race.installation.root.join("operator-result"),
        b"committed",
    );
    send(&mut channel, b'D');
}

#[test]
fn native_dependency_peer() {
    let Some(input) = std::env::var_os("AUTHS_AP074_DEPENDENCY_PEER") else {
        return;
    };
    let race: Race =
        serde_json::from_slice(&std::fs::read(input).expect("setup")).expect("closed setup");
    let store = TestAttempts::attach(
        Backend::parse(&race.installation.backend),
        &race.installation.location,
    );
    match std::env::var("AUTHS_AP074_DEPENDENCY_ROLE")
        .expect("role")
        .as_str()
    {
        "worker" => run_worker(&race, &store),
        "operator" => run_operator(&race, &store),
        _ => panic!("unknown private test role"),
    }
}
pub(super) struct Peer(pub(super) Child);
impl Peer {
    fn start(input: &Path, role: &str) -> Self {
        Self(
            Command::new(std::env::current_exe().expect("test binary"))
                .args([
                    "--exact",
                    "native_dependency_tests::native_dependency_peer",
                    "--nocapture",
                ])
                .env("AUTHS_AP074_DEPENDENCY_PEER", input)
                .env("AUTHS_AP074_DEPENDENCY_ROLE", role)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("peer"),
        )
    }
    fn check_exit(&mut self) -> Option<std::process::ExitStatus> {
        let result = self.0.try_wait().expect("process status");
        if let Some(status) = result {
            let mut diagnostic = String::new();
            self.0
                .stderr
                .take()
                .expect("stderr")
                .read_to_string(&mut diagnostic)
                .expect("diagnostic");
            assert!(status.success(), "peer failed: {diagnostic}");
        }
        result
    }
    pub(super) fn accept(&mut self, listener: &TcpListener) -> TcpStream {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            assert!(
                self.check_exit().is_none(),
                "peer exited before its control marker"
            );
            match listener.accept() {
                Ok((channel, _)) => {
                    channel.set_nonblocking(false).expect("blocking");
                    channel
                        .set_read_timeout(Some(Duration::from_secs(15)))
                        .expect("deadline");
                    channel
                        .set_write_timeout(Some(Duration::from_secs(3)))
                        .expect("deadline");
                    return channel;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "peer control timeout");
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("listener: {error}"),
            }
        }
    }
    pub(super) fn finish(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while self.check_exit().is_none() {
            assert!(Instant::now() < deadline, "peer completion timeout");
            thread::sleep(Duration::from_millis(2));
        }
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        if thread::panicking()
            && let Some(mut stderr) = self.0.stderr.take()
        {
            let mut diagnostic = String::new();
            let _ = stderr.read_to_string(&mut diagnostic);
            eprintln!("private native peer diagnostic: {diagnostic}");
        }
    }
}
pub(super) fn listener() -> TcpListener {
    let value = TcpListener::bind("127.0.0.1:0").expect("listener");
    value.set_nonblocking(true).expect("nonblocking");
    value
}
struct Case {
    _directory: tempfile::TempDir,
    store: TestAttempts,
    race: Race,
    worker_listener: TcpListener,
    operator_listener: TcpListener,
    provider: Provider,
    signed_inputs: Vec<Vec<u8>>,
    evidence: Option<Value>,
}
impl Case {
    fn new(backend: Backend, scenario: Scenario, order: Order) -> Self {
        let directory = tempfile::tempdir().expect("directory");
        let root = std::fs::canonicalize(directory.path()).expect("canonical");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private mode");
        let worker_listener = listener();
        let operator_listener = listener();
        let provider = Provider::controlled(None);
        let store = TestAttempts::open(backend);
        let race = Race {
            scenario,
            order,
            operator_port: operator_listener.local_addr().expect("address").port(),
            installation: Setup {
                backend: backend.label().to_owned(),
                location: store.location(),
                root,
                provider_port: provider.port,
                barrier_port: worker_listener.local_addr().expect("address").port(),
            },
        };
        let runtime = runtime();
        let controls = EngineControls::baseline();
        let clock = controls.clock.clone();
        let (engine, record) = runtime.block_on(load_controlled_engine(
            &race.installation,
            "parent",
            store.attempts().clone(),
            controls,
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
        let evidence = if matches!(
            scenario,
            Scenario::ObserverValid
                | Scenario::ObserverExpired
                | Scenario::ThresholdValid
                | Scenario::ThresholdChanged
        ) {
            Some(
                runtime.block_on(crate::observed_tests::threshold_testkit::authorize(
                    &engine,
                    &clock,
                    &race.installation.root,
                    OPERATION,
                    matches!(
                        scenario,
                        Scenario::ThresholdValid | Scenario::ThresholdChanged
                    ),
                    NOW + scenario.time_shift(),
                )),
            )
        } else {
            runtime.block_on(authorize_bounded(
                &engine,
                &race.installation.root,
                OPERATION,
                scenario.authority_until(),
                scenario.approval_until(),
            ));
            None
        };
        let signed_inputs = Self::inputs(&race);
        Self {
            _directory: directory,
            store,
            race,
            worker_listener,
            operator_listener,
            provider,
            signed_inputs,
            evidence,
        }
    }
    fn inputs(race: &Race) -> Vec<Vec<u8>> {
        ["proof", "action", "approval"]
            .map(|suffix| {
                std::fs::read(race.installation.root.join(format!("{OPERATION}.{suffix}")))
                    .expect("signed input")
            })
            .to_vec()
    }
    fn execute(&self) -> AcquisitionSnapshot {
        let input = self.race.installation.root.join("race-setup.json");
        private(&input, &serde_json::to_vec(&self.race).expect("setup"));
        let mut operator = Peer::start(&input, "operator");
        let mut operator_channel = operator.accept(&self.operator_listener);
        expect(&mut operator_channel, b'S');
        let mut worker = Peer::start(&input, "worker");
        let mut worker_channel = worker.accept(&self.worker_listener);
        expect(&mut worker_channel, b'P');
        assert_eq!(self.provider.calls.load(Ordering::SeqCst), 0);
        match self.race.order {
            Order::ChangeFirst => {
                send(&mut operator_channel, b'G');
                expect(&mut operator_channel, b'D');
                operator.finish();
                assert_eq!(self.provider.calls.load(Ordering::SeqCst), 0);
                send(&mut worker_channel, b'G');
            }
            Order::GrantFirst => {
                send(&mut operator_channel, b'G');
                pending(&mut operator_channel);
                assert!(!self.race.installation.root.join("operator-result").exists());
                send(&mut worker_channel, b'G');
                expect(&mut operator_channel, b'D');
                operator.finish();
            }
            Order::LockWait => {
                send(&mut operator_channel, b'G');
                expect(&mut operator_channel, b'H');
                send(&mut worker_channel, b'G');
                expect(&mut worker_channel, b'W');
                worker_channel
                    .write_all(&(NOW + self.race.scenario.time_shift()).to_be_bytes())
                    .expect("advance clock");
                expect(&mut worker_channel, b'A');
                pending(&mut worker_channel);
                assert_eq!(self.provider.calls.load(Ordering::SeqCst), 0);
                send(&mut operator_channel, b'G');
                expect(&mut operator_channel, b'D');
                operator.finish();
                expect(&mut worker_channel, b'D');
            }
        }
        worker.finish();
        let result: Result<AcquisitionSnapshot, crate::GatewaySubmitResult> =
            serde_json::from_slice(
                &std::fs::read(self.race.installation.root.join("worker-result")).expect("result"),
            )
            .expect("native result");
        result.expect("native retained facts")
    }
    fn verify(&self, snapshot: &AcquisitionSnapshot) -> Value {
        assert_eq!(
            Self::inputs(&self.race),
            self.signed_inputs,
            "signed evidence/event times never refreshed"
        );
        assert_eq!(
            snapshot.stage,
            if self.race.enters() {
                AcquisitionStage::ResponseRecorded
            } else {
                AcquisitionStage::Reserved
            }
        );
        assert_eq!(
            (snapshot.reserved_calls, snapshot.reserved_bytes),
            (1, 1024)
        );
        assert_eq!(
            self.provider.calls.load(Ordering::SeqCst),
            usize::from(self.race.enters())
        );
        let stored = self
            .store
            .raw()
            .load(GatewayRecordKind::Attempt, &Race::key())
            .expect("load")
            .expect("record");
        let record: Value = serde_json::from_slice(&stored).expect("native record");
        assert_eq!(record["evaluated_at"], NOW);
        assert_eq!(record["state"]["facts"]["allocation"], 0);
        assert_eq!(!record["entry"].is_null(), self.race.enters());
        if matches!(self.race.order, Order::LockWait) && self.race.enters() {
            assert_eq!(
                record["entry"]["granted_at"],
                NOW + self.race.scenario.time_shift()
            );
        }
        let runtime = runtime();
        let (inspector, _) = runtime.block_on(load_engine(
            &self.race.installation,
            "inspector",
            self.store.reopen(),
        ));
        match runtime
            .block_on(inspector.content_history(OPERATION))
            .expect("native history")
        {
            ContentHistory::Acquisition(history) => assert_eq!(&history, snapshot),
            ContentHistory::Disclosure(_) => panic!("wrong protocol"),
        }
        assert_eq!(
            stored,
            self.store
                .raw()
                .load(GatewayRecordKind::Attempt, &Race::key())
                .expect("replay")
                .expect("record")
        );
        let mut result = json!({ "scenario": self.race.scenario, "order": self.race.order,
            "actual_provider_reads": self.provider.calls.load(Ordering::SeqCst), "native_history": snapshot,
            "separate_operator_completed": true, "signed_inputs_unchanged": true,
            "admission_time": NOW, "clock_after_wait": matches!(self.race.order, Order::LockWait).then(|| NOW + self.race.scenario.time_shift()),
            "history_inspection_did_not_change_journal": true });
        if let Some(evidence) = &self.evidence {
            let witness: crate::GatewayExecutionWitness = serde_json::from_slice(
                &std::fs::read(self.race.installation.root.join("worker-witness"))
                    .expect("witness"),
            )
            .expect("native witness");
            // This schedule pauses at the final fence after an initially
            // authorized admission and custody lease. Refusing that grant
            // must prevent HTTP entry; it does not undo the earlier lease.
            assert_eq!(witness.credential_lease_calls, 1);
            assert_eq!(
                witness.read_transport_entries,
                u64::from(self.race.enters())
            );
            assert_eq!(witness.write_transport_entries, 0);
            result["evidence_selection"] = evidence.clone();
            result["actual_credential_leases"] = json!(witness.credential_lease_calls);
            result["actual_read_entries"] = json!(witness.read_transport_entries);
        }
        result
    }
}
fn dependency_matrix(backend: Backend) {
    let pairs = [
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
    let cases: Vec<_> = pairs
        .into_iter()
        .map(|(scenario, order)| {
            let case = Case::new(backend, scenario, order);
            let snapshot = case.execute();
            case.verify(&snapshot)
        })
        .collect();
    let artifact = serde_json::to_vec_pretty(&json!({ "schema": "auths.native-dependency-order/1", "adapter": backend.label(),
        "scope": "full native acquisition engine; independent worker/operator OS processes; maintained file or TLS PostgreSQL common writer fence; changed dependencies in physically distinct records; fixed public test trust/keys and controlled maintained test clock; real local HTTP",
        "excluded": ["mutation/disclosure races", "installed language and human UI journeys", "fixed-window budget contention", "production commissioning", "hostile OS containment", "power loss and whole-store rollback"], "cases": cases })).expect("artifact");
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-dependency-order-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("write");
    }
    assert_eq!(std::fs::read(path).expect("artifact"), artifact);
}
#[test]
fn native_file_dependency_order_fixture_is_current() {
    dependency_matrix(Backend::File);
}
#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_dependency_order_fixture_is_current() {
    assert!(postgres_configured());
    dependency_matrix(Backend::Postgres);
}
