//! Real lost COMMIT replies over end-to-end TLS, with independent observation
//! of both possible transaction outcomes. No adapter result is fabricated.
use crate::native_crash_tests::CrashProtocol;
use crate::native_process_tests::{
    NOW, Provider, Setup, acquire, authorize_policy, load_engine, private, recipe, runtime,
};
use crate::store::GatewayFenceDecision;
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::{
    AcquisitionSnapshot, AcquisitionStage, ArgumentCeilingPolicy, ContentHistory,
    GatewayAttemptError, GatewayAttemptKey, GatewayAttemptStore, GatewayAttempts,
    GatewayExecutionWitness, GatewayInsert, GatewayRecordEntry, GatewayRecordKind,
    GatewaySubmitResult, LogicalOperationId, SharedConnection,
};
use postgres::{
    Client, Config,
    config::{Host, SslMode},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Child, Command, Stdio},
    str::FromStr as _,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[path = "native_postgres_commit_proxy.rs"]
pub(crate) mod proxy;
pub(crate) use proxy::Proxy;

const OPERATION: &str = "commit-reply-loss";
const LOCK_GROUP: i32 = 1_095_780_184;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase {
    Admission,
    Entry,
    Response,
}
impl Phase {
    const fn stage(self) -> &'static str {
        match self {
            Self::Admission => "reserved",
            Self::Entry => "entry-granted",
            Self::Response => "content-response-recorded",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Outcome {
    Committed,
    Aborted,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Schedule {
    phase: Phase,
    outcome: Outcome,
}
impl Schedule {
    const fn retained(self) -> Option<&'static str> {
        match self.outcome {
            Outcome::Committed => Some(self.phase.stage()),
            Outcome::Aborted => match self.phase {
                Phase::Admission => None,
                Phase::Entry => Some("reserved"),
                Phase::Response => Some("entry-granted"),
            },
        }
    }
    fn resumable(self) -> bool {
        matches!(self.retained(), None | Some("reserved"))
    }
    fn stage(self) -> AcquisitionStage {
        match self.retained() {
            Some("reserved") => AcquisitionStage::Reserved,
            Some("content-response-recorded") => AcquisitionStage::ResponseRecorded,
            _ => AcquisitionStage::Unknown,
        }
    }
    fn reads(self) -> usize {
        usize::from(matches!(self.phase, Phase::Response))
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CommitSetup {
    installation: Setup,
    schedule: Schedule,
}

fn key() -> GatewayAttemptKey {
    GatewayAttemptKey::for_operation(
        &crate::effect::fixture_policy().expect("policy"),
        recipe().namespace(),
        &LogicalOperationId::parse(OPERATION).expect("operation"),
    )
    .expect("key")
}

/// Records only actual adapter errors after the unchanged native decision.
pub(crate) struct CommitWitness {
    inner: Arc<dyn GatewayAttemptStore>,
    key: GatewayAttemptKey,
    protocol: CrashProtocol,
    stage: &'static str,
    errors: AtomicU64,
}
impl CommitWitness {
    pub(crate) fn new(
        inner: Arc<dyn GatewayAttemptStore>,
        key: GatewayAttemptKey,
        protocol: CrashProtocol,
        stage: &'static str,
    ) -> Self {
        Self {
            inner,
            key,
            protocol,
            stage,
            errors: AtomicU64::new(0),
        }
    }
    pub(crate) fn errors(&self) -> u64 {
        self.errors.load(Ordering::SeqCst)
    }
    fn selected(&self, kind: GatewayRecordKind, target: GatewayAttemptKey, bytes: &[u8]) -> bool {
        if kind != GatewayRecordKind::Attempt || target != self.key {
            return false;
        }
        let record: Value = serde_json::from_slice(bytes).expect("native decision");
        record
            .pointer(self.protocol.stage_pointer())
            .and_then(Value::as_str)
            == Some(self.stage)
    }
    fn observe<T>(
        &self,
        selected: bool,
        result: Result<T, GatewayAttemptError>,
    ) -> Result<T, GatewayAttemptError> {
        if selected && result.is_err() {
            self.errors.fetch_add(1, Ordering::SeqCst);
        }
        result
    }
}
impl GatewayAttemptStore for CommitWitness {
    fn fenced_insert_all(
        &self,
        entries: &[GatewayRecordEntry],
        dependencies: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut GatewayFenceDecision<'_>,
    ) -> Result<GatewayInsert, GatewayAttemptError> {
        let mut selected = false;
        let result = self
            .inner
            .fenced_insert_all(entries, dependencies, &mut |snapshots| {
                let next = decide(snapshots)?;
                selected = self.selected(entries[0].kind, entries[0].key, &next);
                Ok(next)
            });
        self.observe(selected, result)
    }
    fn fenced_replace(
        &self,
        keys: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut GatewayFenceDecision<'_>,
    ) -> Result<(), GatewayAttemptError> {
        let mut selected = false;
        let result = self.inner.fenced_replace(keys, &mut |snapshots| {
            let next = decide(snapshots)?;
            selected = self.selected(keys[0].0, keys[0].1, &next);
            Ok(next)
        });
        self.observe(selected, result)
    }
    fn replace(
        &self,
        kind: GatewayRecordKind,
        target: &GatewayAttemptKey,
        current: &[u8],
        next: &[u8],
    ) -> Result<(), GatewayAttemptError> {
        let selected = self.selected(kind, *target, next);
        self.observe(selected, self.inner.replace(kind, target, current, next))
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
        target: &GatewayAttemptKey,
    ) -> Result<Option<Vec<u8>>, GatewayAttemptError> {
        self.inner.load(kind, target)
    }
    fn sweep_expired(&self, now: u64, limit: usize) -> Result<usize, GatewayAttemptError> {
        self.inner.sweep_expired(now, limit)
    }
    fn attempt_keys(&self, limit: usize) -> Result<Vec<GatewayAttemptKey>, GatewayAttemptError> {
        self.inner.attempt_keys(limit)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerResult {
    errors: u64,
    witness: GatewayExecutionWitness,
    result: Result<AcquisitionSnapshot, GatewaySubmitResult>,
}

#[test]
fn native_postgres_commit_peer() {
    let Some(input) = std::env::var_os("AUTHS_AP074_POSTGRES_COMMIT_PEER") else {
        return;
    };
    let setup: CommitSetup =
        serde_json::from_slice(&std::fs::read(input).expect("setup")).expect("closed setup");
    let store = TestAttempts::attach(Backend::Postgres, &setup.installation.location);
    let witness = Arc::new(CommitWitness::new(
        store.raw(),
        key(),
        CrashProtocol::Acquisition,
        setup.schedule.phase.stage(),
    ));
    let attempts = GatewayAttempts::new(
        witness.clone(),
        crate::effect::fixture_policy().expect("policy"),
    )
    .expect("attempts");
    let runtime = runtime();
    let (engine, _) = runtime.block_on(load_engine(&setup.installation, "worker", attempts));
    let mut signal =
        TcpStream::connect(("127.0.0.1", setup.installation.barrier_port)).expect("control");
    signal
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("deadline");
    signal.write_all(b"R").expect("ready");
    let mut start = [0];
    signal.read_exact(&mut start).expect("release");
    assert_eq!(start, *b"G");
    let result = runtime.block_on(acquire(&engine, &setup.installation.root, OPERATION));
    let result = WorkerResult {
        errors: witness.errors(),
        witness: engine.execution_witness(),
        result,
    };
    private(
        &setup.installation.root.join("worker-result"),
        &serde_json::to_vec(&result).expect("result"),
    );
}

pub(crate) struct Barrier {
    client: Client,
    schema: String,
    lock: i32,
    key: GatewayAttemptKey,
    protocol: CrashProtocol,
}
impl Barrier {
    fn install(store: &TestAttempts, phase: Phase) -> Self {
        Self::install_target(store, key(), CrashProtocol::Acquisition, phase.stage())
    }
    pub(crate) fn install_target(
        store: &TestAttempts,
        key: GatewayAttemptKey,
        protocol: CrashProtocol,
        stage: &'static str,
    ) -> Self {
        assert!(matches!(
            stage,
            "reserved"
                | "entry-granted"
                | "response-recorded"
                | "content-response-recorded"
                | "unknown"
                | "acknowledged"
        ));
        let (schema, mut client) = store.postgres_commit_observer();
        let lock: i32 = client.query_one(&format!("SELECT (('{schema}.auths_gateway_records'::regclass::oid)::bigint - 2147483648)::integer"), &[]).expect("table lock identity").get(0);
        client
            .query_one("SELECT pg_advisory_lock($1, $2)", &[&LOCK_GROUP, &lock])
            .expect("commit barrier");
        let target = hex::encode(key.as_bytes());
        let path = protocol
            .stage_pointer()
            .trim_start_matches('/')
            .replace('/', ",");
        client.batch_execute(&format!(
            "CREATE FUNCTION {schema}.fixture_commit_barrier() RETURNS trigger LANGUAGE plpgsql AS $body$
             BEGIN
               IF convert_from(NEW.record_bytes, 'UTF8')::jsonb #>> '{{{path}}}' = '{stage}' THEN
                 PERFORM pg_advisory_xact_lock({LOCK_GROUP}, {lock});
               END IF;
               RETURN NEW;
             END; $body$;
             CREATE CONSTRAINT TRIGGER fixture_commit_barrier AFTER INSERT OR UPDATE
             ON {schema}.auths_gateway_records DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
             WHEN (NEW.record_kind = 'attempt' AND NEW.record_key = decode('{target}', 'hex'))
             EXECUTE FUNCTION {schema}.fixture_commit_barrier();"
        )).expect("deferred test trigger");
        Self {
            client,
            schema,
            lock,
            key,
            protocol,
        }
    }
    pub(crate) fn waiter(&mut self) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(1);
        let group = i64::from(LOCK_GROUP);
        let object = i64::from(u32::from_ne_bytes(self.lock.to_ne_bytes()));
        loop {
            let rows = self.client.query("SELECT locks.pid, ssl.ssl FROM pg_locks AS locks JOIN pg_stat_ssl AS ssl ON ssl.pid = locks.pid WHERE locktype = 'advisory' AND NOT granted AND classid::bigint = $1 AND objid::bigint = $2 AND objsubid = 2 AND locks.pid IS NOT NULL", &[&group, &object]).expect("commit wait observation");
            if let Some(row) = rows.first() {
                assert_eq!(rows.len(), 1);
                assert!(row.get::<_, bool>(1), "selected native COMMIT uses TLS");
                return row.get(0);
            }
            assert!(
                Instant::now() < deadline,
                "native COMMIT did not reach deferred trigger"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }
    pub(crate) fn release(&mut self) {
        let released: bool = self
            .client
            .query_one(
                "SELECT pg_advisory_unlock($1, $2)",
                &[&LOCK_GROUP, &self.lock],
            )
            .expect("release commit")
            .get(0);
        assert!(released);
    }
    pub(crate) fn abort(&mut self, pid: i32) {
        let terminated: bool = self
            .client
            .query_one("SELECT pg_terminate_backend($1)", &[&pid])
            .expect("terminate blocked fixture backend")
            .get(0);
        assert!(terminated);
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let gone: bool = self
                .client
                .query_one(
                    "SELECT NOT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = $1)",
                    &[&pid],
                )
                .expect("backend exit")
                .get(0);
            if gone {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "blocked backend did not terminate"
            );
            thread::sleep(Duration::from_millis(1));
        }
        self.release();
    }
    pub(crate) fn phase(&mut self) -> Option<String> {
        let path = self
            .protocol
            .stage_pointer()
            .trim_start_matches('/')
            .replace('/', ",");
        self.client.query_opt(&format!("SELECT convert_from(record_bytes, 'UTF8')::jsonb #>> '{{{path}}}' FROM {}.auths_gateway_records WHERE record_kind = 'attempt' AND record_key = $1", self.schema), &[&&self.key.as_bytes()[..]]).expect("committed state").map(|row| row.get(0))
    }
    pub(crate) fn committed(&mut self, expected: Option<&str>) {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if self.phase().as_deref() == expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "independent committed-state observation"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }
    pub(crate) fn retire(&mut self) {
        self.client
            .batch_execute(&format!(
                "DROP TRIGGER fixture_commit_barrier ON {}.auths_gateway_records",
                self.schema
            ))
            .expect("retire trigger");
    }
    pub(crate) fn records(&mut self) -> BTreeMap<String, Vec<u8>> {
        self.client.query(&format!("SELECT record_kind, encode(record_key, 'hex'), record_bytes FROM {}.auths_gateway_records ORDER BY record_kind, record_key", self.schema), &[]).expect("record snapshot").into_iter().map(|row| (format!("{}:{}", row.get::<_,String>(0),row.get::<_,String>(1)), row.get(2))).collect()
    }
}

pub(crate) fn fixture_url() -> (String, u16) {
    let url = std::env::var("AUTHS_POSTGRES_URL").expect("fixture URL");
    let config = Config::from_str(&url).expect("fixture parameters");
    assert_eq!(config.get_ssl_mode(), SslMode::Require);
    assert_eq!(config.get_hosts().len(), 1);
    assert!(
        matches!(&config.get_hosts()[0], Host::Tcp(host) if host == "localhost" || host == "127.0.0.1")
    );
    assert_eq!(config.get_ports().len(), 1);
    (url, config.get_ports()[0])
}
struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Peer {
    fn start(setup: &CommitSetup, url: &str) -> Self {
        let input = setup.installation.root.join("commit-setup.json");
        private(&input, &serde_json::to_vec(setup).expect("setup"));
        Self(
            Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--exact",
                    "native_postgres_commit_tests::native_postgres_commit_peer",
                    "--nocapture",
                ])
                .env("AUTHS_AP074_POSTGRES_COMMIT_PEER", input)
                .env("AUTHS_POSTGRES_URL", url)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("native worker"),
        )
    }
    fn finish(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.0.try_wait().expect("status") {
                let mut diagnostic = String::new();
                self.0
                    .stderr
                    .take()
                    .expect("stderr")
                    .read_to_string(&mut diagnostic)
                    .expect("diagnostic");
                assert!(status.success(), "native worker: {diagnostic}");
                return;
            }
            assert!(Instant::now() < deadline, "native worker completion");
            thread::sleep(Duration::from_millis(2));
        }
    }
}
fn ready(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false).expect("blocking");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("deadline");
                let mut marker = [0];
                stream.read_exact(&mut marker).expect("ready");
                assert_eq!(marker, *b"R");
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "native worker readiness");
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("control: {error}"),
        }
    }
}

struct Case {
    _directory: tempfile::TempDir,
    store: TestAttempts,
    setup: CommitSetup,
    provider: Provider,
    proxy: Proxy,
    url: String,
    control: TcpListener,
    signed: Vec<Vec<u8>>,
}
impl Case {
    fn new(schedule: Schedule) -> Self {
        let (url, port) = fixture_url();
        let directory = tempfile::tempdir().expect("directory");
        let root = std::fs::canonicalize(directory.path()).expect("canonical");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private mode");
        let store = TestAttempts::open(Backend::Postgres);
        let provider = Provider::controlled(None);
        let proxy = Proxy::start(port);
        let control = TcpListener::bind("127.0.0.1:0").expect("control");
        control.set_nonblocking(true).expect("control polling");
        let setup = CommitSetup {
            schedule,
            installation: Setup {
                backend: "postgres".to_owned(),
                location: store.location(),
                root,
                provider_port: provider.port,
                barrier_port: control.local_addr().expect("address").port(),
            },
        };
        let runtime = runtime();
        let (engine, connection) = runtime.block_on(load_engine(
            &setup.installation,
            "parent",
            store.attempts().clone(),
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
        let policy = ArgumentCeilingPolicy::new("maximum_response_bytes", 1024, 3600, 4)
            .expect("count")
            .with_sum(4096, None)
            .expect("sum");
        runtime.block_on(authorize_policy(
            &engine,
            &setup.installation.root,
            OPERATION,
            &policy,
        ));
        let signed = Self::inputs(&setup);
        Self {
            _directory: directory,
            store,
            setup,
            provider,
            proxy,
            url,
            control,
            signed,
        }
    }
    fn inputs(setup: &CommitSetup) -> Vec<Vec<u8>> {
        ["proof", "action", "approval"]
            .map(|suffix| {
                std::fs::read(
                    setup
                        .installation
                        .root
                        .join(format!("{OPERATION}.{suffix}")),
                )
                .expect("signed inputs")
            })
            .to_vec()
    }
    fn interrupt(&self) -> Barrier {
        let mut worker = Peer::start(&self.setup, &self.proxy.url(&self.url));
        let mut signal = ready(&self.control);
        let mut barrier = Barrier::install(&self.store, self.setup.schedule.phase);
        signal.write_all(b"G").expect("release worker");
        let pid = barrier.waiter();
        self.proxy.hold_replies();
        match self.setup.schedule.outcome {
            Outcome::Committed => {
                barrier.release();
                barrier.committed(self.setup.schedule.retained());
                self.proxy.wait_for_withheld_reply();
            }
            Outcome::Aborted => {
                barrier.abort(pid);
                barrier.committed(self.setup.schedule.retained());
            }
        }
        self.proxy.disconnect_and_resume();
        worker.finish();
        barrier.retire();
        let result: WorkerResult = serde_json::from_slice(
            &std::fs::read(self.setup.installation.root.join("worker-result")).expect("result"),
        )
        .expect("native result");
        assert_eq!(
            result.errors, 1,
            "actual native adapter returned an error at the selected commit"
        );
        assert_eq!(result.witness.write_transport_entries, 0);
        assert_eq!(
            result.witness.read_transport_entries,
            u64::try_from(self.setup.schedule.reads()).expect("reads")
        );
        assert_eq!(
            result.witness.credential_lease_calls,
            u64::from(!matches!(self.setup.schedule.phase, Phase::Admission))
        );
        match result.result {
            Ok(history) => {
                assert!(self.setup.schedule.retained().is_some());
                assert_eq!(history.stage, self.setup.schedule.stage());
                assert_eq!((history.reserved_calls, history.reserved_bytes), (1, 1024));
            }
            Err(GatewaySubmitResult::Indeterminate { code }) => {
                assert_eq!(code, "gateway.attempt.state-unavailable");
            }
            Err(other) => panic!("unexpected failure projection: {other:?}"),
        }
        assert_eq!(
            self.provider.calls.load(Ordering::SeqCst),
            self.setup.schedule.reads()
        );
        assert_eq!(Self::inputs(&self.setup), self.signed);
        assert_eq!(
            self.store.postgres_gateway_record_counts(),
            expected_counts(self.setup.schedule.retained().is_some()),
            "the transaction outcome retains either every charge or none"
        );
        barrier
    }
    fn reopen(&self, barrier: &mut Barrier) -> Value {
        let before = barrier.records();
        let runtime = runtime();
        let (engine, _) = runtime.block_on(load_engine(
            &self.setup.installation,
            "reopened",
            self.store.reopen(),
        ));
        let history = runtime.block_on(engine.content_history(OPERATION));
        if self.setup.schedule.retained().is_none() {
            assert!(history.is_err());
        } else {
            match history.expect("retained history") {
                ContentHistory::Acquisition(history) => {
                    assert_eq!(history.stage, self.setup.schedule.stage());
                }
                ContentHistory::Disclosure(_) => panic!("wrong protocol"),
            }
        }
        let witness = engine.execution_witness();
        let result = runtime
            .block_on(acquire(&engine, &self.setup.installation.root, OPERATION))
            .expect("native replay");
        assert_eq!(
            result.stage,
            if self.setup.schedule.resumable() {
                AcquisitionStage::ResponseRecorded
            } else {
                self.setup.schedule.stage()
            }
        );
        assert_eq!((result.reserved_calls, result.reserved_bytes), (1, 1024));
        assert_eq!(
            (result.policy_count_counters, result.policy_byte_counters),
            (1, 1)
        );
        if !self.setup.schedule.resumable() {
            assert_eq!(engine.execution_witness(), witness);
            assert_eq!(barrier.records(), before);
        }
        let total = self.setup.schedule.reads() + usize::from(self.setup.schedule.resumable());
        assert_eq!(self.provider.calls.load(Ordering::SeqCst), total);
        let record = self
            .store
            .raw()
            .load(GatewayRecordKind::Attempt, &key())
            .expect("record")
            .expect("retained record");
        let value: Value = serde_json::from_slice(&record).expect("native record");
        assert_eq!(value["evaluated_at"], NOW);
        assert_eq!(value["state"]["facts"]["allocation"], 0);
        assert_eq!(
            self.store.postgres_gateway_record_counts(),
            expected_counts(true)
        );
        let retained = barrier.records();
        let witness = engine.execution_witness();
        assert_eq!(
            runtime
                .block_on(acquire(&engine, &self.setup.installation.root, OPERATION))
                .expect("terminal replay"),
            result
        );
        assert_eq!(engine.execution_witness(), witness);
        assert_eq!(barrier.records(), retained);
        assert_eq!(self.provider.calls.load(Ordering::SeqCst), total);
        assert_eq!(Self::inputs(&self.setup), self.signed);
        json!({"schedule":self.setup.schedule,"commit_observed_at_server_deferred_trigger":true,"actual_adapter_commit_error":true,"independently_observed_retained_phase":self.setup.schedule.retained(),"end_to_end_tls_preserved":true,"actual_http_reads_before_reopen":self.setup.schedule.reads(),"new_execution_allowed":self.setup.schedule.resumable(),"actual_http_reads_after_reopen":total,"native_history":result,"one_allocation_count_and_sum_slot":true,"terminal_journal_and_execution_witness_unchanged":true,"signed_inputs_unchanged":true})
    }
}

fn expected_counts(charged: bool) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::from([
        ("connection".to_owned(), 1),
        ("effect-configuration".to_owned(), 1),
    ]);
    if charged {
        for kind in ["attempt", "effect-allocation", "count-slot", "sum-slot"] {
            counts.insert(kind.to_owned(), 1);
        }
    }
    counts
}

#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_commit_reply_loss_fixture_is_current() {
    assert!(postgres_configured());
    let mut cases = Vec::new();
    for phase in [Phase::Admission, Phase::Entry, Phase::Response] {
        for outcome in [Outcome::Committed, Outcome::Aborted] {
            eprintln!("native commit reply schedule: {phase:?}/{outcome:?}");
            let case = Case::new(Schedule { phase, outcome });
            let mut barrier = case.interrupt();
            cases.push(case.reopen(&mut barrier));
        }
    }
    let artifact = serde_json::to_vec_pretty(&json!({"schema":"auths.native-postgres-commit-reply-loss/1","scope":"full native acquisition engine in separate OS workers; actual TLS PostgreSQL COMMIT paused by a schema-local deferred trigger, opaque TCP reply suppression/disconnection and independent committed/aborted-state observation; real bounded authority/exact approvals, local custody and HTTP; fixed public test keys and maintained clock","excluded":["TLS decryption or forged adapter error","PostgreSQL power failure or whole-store rollback","mutation/disclosure commit fault matrices","hostile OS containment or human review","live provider qualification"],"cases":cases})).expect("artifact");
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/gateway/native-postgres-commit-reply-loss.json");
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("write");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), artifact);
}
