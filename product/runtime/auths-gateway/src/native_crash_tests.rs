//! Real SIGKILL boundaries around the native engine and maintained adapters.
//! Test-only pass-through storage instrumentation never changes a decision,
//! acknowledgement or record. It cannot be selected in a shipping build.
use crate::native_process_tests::{
    CONTENT, Provider, Setup, acquire, authorize, load_engine, private, recipe, runtime,
};
use crate::store::GatewayFenceDecision;
use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
use crate::{
    AcquisitionSnapshot, AcquisitionStage, ContentHistory, ContentProjectionStatus,
    GatewayAttemptError, GatewayAttemptKey, GatewayAttemptStore, GatewayAttempts, GatewayInsert,
    GatewayRecordEntry, GatewayRecordKind, LogicalOperationId, SharedConnection,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    os::unix::{fs::PermissionsExt as _, process::ExitStatusExt as _},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const OPERATION: &str = "crash-read";

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Point {
    BeforeReservationCommit,
    AfterReservationCommit,
    BeforeEntryCommit,
    AfterEntryCommit,
    DuringResponse,
    BeforeResponseCommit,
    AfterResponseCommit,
    BeforeAcknowledgementCommit,
    AfterAcknowledgementCommit,
}
impl Point {
    pub(super) const ALL: [Self; 7] = [
        Self::BeforeReservationCommit,
        Self::AfterReservationCommit,
        Self::BeforeEntryCommit,
        Self::AfterEntryCommit,
        Self::DuringResponse,
        Self::BeforeResponseCommit,
        Self::AfterResponseCommit,
    ];
    pub(super) const fn resumable(self) -> bool {
        matches!(
            self,
            Self::BeforeReservationCommit | Self::AfterReservationCommit | Self::BeforeEntryCommit
        )
    }
    const fn expected_phase(self) -> Option<&'static str> {
        match self {
            Self::BeforeReservationCommit => None,
            Self::AfterReservationCommit | Self::BeforeEntryCommit => Some("reserved"),
            Self::AfterEntryCommit | Self::DuringResponse | Self::BeforeResponseCommit => {
                Some("entry-granted")
            }
            Self::AfterResponseCommit => Some("content-response-recorded"),
            Self::BeforeAcknowledgementCommit | Self::AfterAcknowledgementCommit => {
                panic!("ACK points require disclosure fixture")
            }
        }
    }
    pub(super) const fn provider_calls(self) -> usize {
        match self {
            Self::DuringResponse | Self::BeforeResponseCommit | Self::AfterResponseCommit => 1,
            _ => 0,
        }
    }
    fn matches(self, after: bool, phase: &str) -> bool {
        matches!(
            (self, after, phase),
            (Self::BeforeReservationCommit, false, "reserved")
                | (Self::AfterReservationCommit, true, "reserved")
                | (Self::BeforeEntryCommit, false, "entry-granted")
                | (Self::AfterEntryCommit, true, "entry-granted")
                | (
                    Self::BeforeResponseCommit,
                    false,
                    "content-response-recorded" | "response-recorded"
                )
                | (
                    Self::AfterResponseCommit,
                    true,
                    "content-response-recorded" | "response-recorded"
                )
                | (Self::BeforeAcknowledgementCommit, false, "acknowledged")
                | (Self::AfterAcknowledgementCommit, true, "acknowledged")
        )
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CrashSetup {
    installation: Setup,
    point: Point,
}

pub(super) fn pause_at(port: u16) {
    let mut channel = TcpStream::connect(("127.0.0.1", port)).expect("crash control");
    channel
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("control deadline");
    channel.write_all(b"P").expect("pause marker");
    let mut release = [0];
    channel
        .read_exact(&mut release)
        .expect("parent release or SIGKILL");
    assert_eq!(release, *b"G");
}

/// A transparent proxy around the actual adapter. Native closures are never
/// replaced or rerun: the adapter invokes them at most once under its fence,
/// and receives their bytes unchanged.
#[derive(Clone, Copy)]
pub(super) enum CrashProtocol {
    Acquisition,
    Mutation,
    Disclosure,
}

pub(super) struct PausedStore {
    operation: &'static str,
    protocol: CrashProtocol,
    inner: Arc<dyn GatewayAttemptStore>,
    key: GatewayAttemptKey,
    point: Option<Point>,
    port: u16,
    fired: AtomicBool,
}
impl PausedStore {
    pub(super) fn new(
        inner: Arc<dyn GatewayAttemptStore>,
        key: GatewayAttemptKey,
        operation: &'static str,
        protocol: CrashProtocol,
        point: Option<Point>,
        port: u16,
    ) -> Self {
        Self {
            inner,
            key,
            operation,
            protocol,
            point,
            port,
            fired: AtomicBool::new(false),
        }
    }

    fn target(&self, kind: GatewayRecordKind, key: GatewayAttemptKey) -> bool {
        kind == GatewayRecordKind::Attempt && key == self.key
    }
    fn phase(&self, bytes: &[u8]) -> String {
        Self::phase_for(self.protocol, self.operation, bytes)
    }
    pub(super) fn phase_for(protocol: CrashProtocol, operation: &str, bytes: &[u8]) -> String {
        let value: Value = serde_json::from_slice(bytes).expect("native record");
        assert_eq!(value["operation_id"], operation);
        let stage = match protocol {
            CrashProtocol::Acquisition => {
                assert_eq!(value["state"]["protocol"], "acquisition");
                &value["state"]["facts"]["phase"]["stage"]
            }
            CrashProtocol::Mutation => {
                assert_eq!(value["state"]["protocol"], "mutation");
                &value["state"]["facts"]["stage"]
            }
            CrashProtocol::Disclosure => {
                assert_eq!(value["state"]["protocol"], "disclosure");
                &value["state"]["facts"]["phase"]["stage"]
            }
        };
        stage.as_str().expect("native phase").to_owned()
    }
    fn pause(&self, after: bool, phase: &str) {
        if self.point.is_some_and(|point| point.matches(after, phase))
            && !self.fired.swap(true, Ordering::SeqCst)
        {
            pause_at(self.port);
        }
    }
}
impl GatewayAttemptStore for PausedStore {
    fn fenced_insert_all(
        &self,
        entries: &[GatewayRecordEntry],
        dependencies: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut GatewayFenceDecision<'_>,
    ) -> Result<GatewayInsert, GatewayAttemptError> {
        if !entries
            .first()
            .is_some_and(|entry| self.target(entry.kind, entry.key))
        {
            return self.inner.fenced_insert_all(entries, dependencies, decide);
        }
        let mut phase = None;
        let result = self
            .inner
            .fenced_insert_all(entries, dependencies, &mut |snapshots| {
                let next = decide(snapshots)?;
                let current = self.phase(&next);
                self.pause(false, &current);
                phase = Some(current);
                Ok(next)
            });
        if matches!(result, Ok(GatewayInsert::Inserted)) {
            self.pause(true, phase.as_deref().expect("native admission decision"));
        }
        result
    }
    fn fenced_replace(
        &self,
        keys: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut GatewayFenceDecision<'_>,
    ) -> Result<(), GatewayAttemptError> {
        if !keys
            .first()
            .is_some_and(|(kind, key)| self.target(*kind, *key))
        {
            return self.inner.fenced_replace(keys, decide);
        }
        let mut phase = None;
        let result = self.inner.fenced_replace(keys, &mut |snapshots| {
            let next = decide(snapshots)?;
            let current = self.phase(&next);
            self.pause(false, &current);
            phase = Some(current);
            Ok(next)
        });
        if result.is_ok() {
            self.pause(true, phase.as_deref().expect("native entry decision"));
        }
        result
    }
    fn replace(
        &self,
        kind: GatewayRecordKind,
        key: &GatewayAttemptKey,
        current: &[u8],
        next: &[u8],
    ) -> Result<(), GatewayAttemptError> {
        if !self.target(kind, *key) {
            return self.inner.replace(kind, key, current, next);
        }
        let phase = self.phase(next);
        self.pause(false, &phase);
        let result = self.inner.replace(kind, key, current, next);
        if result.is_ok() {
            self.pause(true, &phase);
        }
        result
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
    fn sweep_expired(&self, now: u64, limit: usize) -> Result<usize, GatewayAttemptError> {
        self.inner.sweep_expired(now, limit)
    }
    fn attempt_keys(&self, limit: usize) -> Result<Vec<GatewayAttemptKey>, GatewayAttemptError> {
        self.inner.attempt_keys(limit)
    }
}

fn operation_key() -> GatewayAttemptKey {
    GatewayAttemptKey::for_operation(
        &crate::effect::fixture_policy().expect("policy"),
        recipe().namespace(),
        &LogicalOperationId::parse(OPERATION).expect("operation"),
    )
    .expect("key")
}

#[test]
fn native_crash_peer() {
    let Some(path) = std::env::var_os("AUTHS_AP074_CRASH_PEER") else {
        return;
    };
    let setup: CrashSetup =
        serde_json::from_slice(&std::fs::read(path).expect("setup")).expect("closed setup");
    let attached = TestAttempts::attach(
        Backend::parse(&setup.installation.backend),
        &setup.installation.location,
    );
    let wrapped = Arc::new(PausedStore::new(
        attached.raw(),
        operation_key(),
        OPERATION,
        CrashProtocol::Acquisition,
        Some(setup.point),
        setup.installation.barrier_port,
    ));
    let attempts = GatewayAttempts::new(wrapped, crate::effect::fixture_policy().expect("policy"))
        .expect("attempts");
    let runtime = runtime();
    let (engine, _) = runtime.block_on(load_engine(&setup.installation, "crash-peer", attempts));
    let result = runtime.block_on(acquire(&engine, &setup.installation.root, OPERATION));
    private(
        &setup.installation.root.join("caller-result.json"),
        &serde_json::to_vec(&result).expect("result"),
    );
}

pub(super) struct Peer(Child);
impl Peer {
    pub(super) fn start(input: &Path, selector: &str, environment: &str) -> Self {
        Self(
            Command::new(std::env::current_exe().expect("test executable"))
                .args(["--exact", selector, "--nocapture"])
                .env(environment, input)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("native child"),
        )
    }
    pub(super) fn await_pause(&mut self, listener: &TcpListener) -> TcpStream {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.0.try_wait().expect("child status") {
                let mut diagnostic = String::new();
                self.0
                    .stderr
                    .take()
                    .expect("stderr")
                    .read_to_string(&mut diagnostic)
                    .expect("diagnostic");
                panic!("child exited before the exact pause: {status}: {diagnostic}");
            }
            match listener.accept() {
                Ok((mut channel, _)) => {
                    channel.set_nonblocking(false).expect("blocking");
                    channel
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .expect("deadline");
                    let mut marker = [0];
                    channel.read_exact(&mut marker).expect("pause");
                    assert_eq!(marker, *b"P");
                    return channel;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "exact crash pause timed out");
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("control accept: {error}"),
            }
        }
    }
    pub(super) fn kill(&mut self) {
        self.0.kill().expect("SIGKILL");
        assert_eq!(self.0.wait().expect("child exit").signal(), Some(9));
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Case {
    _directory: tempfile::TempDir,
    store: TestAttempts,
    setup: CrashSetup,
    listener: TcpListener,
    provider: Provider,
    runtime: tokio::runtime::Runtime,
}
impl Case {
    fn new(backend: Backend, point: Point) -> Self {
        let store = TestAttempts::open(backend);
        let directory = tempfile::tempdir().expect("private directory");
        let root = std::fs::canonicalize(directory.path()).expect("canonical");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("private mode");
        let listener = TcpListener::bind("127.0.0.1:0").expect("control listener");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("address").port();
        let pause: Option<Box<dyn FnOnce() + Send>> = matches!(point, Point::DuringResponse)
            .then(|| Box::new(move || pause_at(port)) as Box<dyn FnOnce() + Send>);
        let provider = Provider::controlled(pause);
        let setup = CrashSetup {
            point,
            installation: Setup {
                backend: backend.label().to_owned(),
                location: store.location(),
                root,
                provider_port: provider.port,
                barrier_port: port,
            },
        };
        let runtime = runtime();
        let (engine, record) = runtime.block_on(load_engine(
            &setup.installation,
            "parent",
            store.attempts().clone(),
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
        runtime.block_on(authorize(&engine, &setup.installation.root, OPERATION));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        Self {
            _directory: directory,
            store,
            setup,
            listener,
            provider,
            runtime,
        }
    }
    fn crash(&self) {
        let input = self.setup.installation.root.join("crash-setup.json");
        private(&input, &serde_json::to_vec(&self.setup).expect("setup"));
        let mut peer = Peer::start(
            &input,
            "native_crash_tests::native_crash_peer",
            "AUTHS_AP074_CRASH_PEER",
        );
        let mut paused = peer.await_pause(&self.listener);
        assert!(
            !self
                .setup
                .installation
                .root
                .join("caller-result.json")
                .exists()
        );
        peer.kill();
        if matches!(self.setup.point, Point::DuringResponse) {
            paused
                .write_all(b"G")
                .expect("release provider after child death");
        }
        assert_eq!(
            self.provider.calls.load(Ordering::SeqCst),
            self.setup.point.provider_calls()
        );
    }
    fn raw(&self) -> Option<Vec<u8>> {
        self.store
            .raw()
            .load(GatewayRecordKind::Attempt, &operation_key())
            .expect("native record")
    }
    fn pre_crash_phase(&self, bytes: Option<&[u8]>) {
        let phase =
            bytes.map(|bytes| PausedStore::phase_for(CrashProtocol::Acquisition, OPERATION, bytes));
        assert_eq!(phase.as_deref(), self.setup.point.expected_phase());
        if let Some(bytes) = bytes {
            let value: Value = serde_json::from_slice(bytes).expect("native record");
            assert_eq!(value["state"]["facts"]["allocation"], 0);
            assert_eq!(!value["entry"].is_null(), !self.setup.point.resumable());
        }
    }
    fn reopen(&self) -> Value {
        let before = self.raw();
        self.pre_crash_phase(before.as_deref());
        let (engine, _) = self.runtime.block_on(load_engine(
            &self.setup.installation,
            "reopened",
            self.store.reopen(),
        ));
        let history = self.runtime.block_on(engine.content_history(OPERATION));
        if before.is_none() {
            assert!(history.is_err(), "absent admission has no retained history");
        }
        let before_snapshot = before
            .as_ref()
            .map(|_| match history.expect("retained facts") {
                ContentHistory::Acquisition(snapshot) => snapshot,
                ContentHistory::Disclosure(_) => panic!("wrong protocol"),
            });
        if let Some(snapshot) = &before_snapshot {
            let expected = if self.setup.point.resumable() {
                AcquisitionStage::Reserved
            } else if matches!(self.setup.point, Point::AfterResponseCommit) {
                AcquisitionStage::ResponseRecorded
            } else {
                AcquisitionStage::Unknown
            };
            assert_eq!(snapshot.stage, expected, "native recovered projection");
            assert_eq!(
                (snapshot.reserved_calls, snapshot.reserved_bytes),
                (1, 1024)
            );
        }
        let before_boundary = engine.execution_witness();
        let result = self
            .runtime
            .block_on(acquire(&engine, &self.setup.installation.root, OPERATION))
            .expect("native replay");
        self.assert_result(&result);
        let after = self.raw();
        if !self.setup.point.resumable() {
            assert_eq!(
                before_boundary,
                engine.execution_witness(),
                "lost grants cannot lease again"
            );
            assert_eq!(before, after, "lost permits never remint");
        }
        let witness = engine.execution_witness();
        assert_eq!(
            self.runtime
                .block_on(acquire(&engine, &self.setup.installation.root, OPERATION))
                .expect("second replay"),
            result
        );
        assert_eq!(
            witness,
            engine.execution_witness(),
            "terminal replay cannot lease or enter"
        );
        assert_eq!(self.raw(), after, "terminal journal is byte immutable");
        json!({ "pause": self.setup.point, "sigkill": true, "before": before_snapshot,
            "provider_calls_at_kill": self.setup.point.provider_calls(),
            "resumed_only_without_previous_grant": self.setup.point.resumable(),
            "after": result, "provider_calls_after_replays": self.provider.calls.load(Ordering::SeqCst),
            "terminal_replays_leave_journal_and_boundary_counters_unchanged": true })
    }
    fn assert_result(&self, snapshot: &AcquisitionSnapshot) {
        let recorded =
            self.setup.point.resumable() || matches!(self.setup.point, Point::AfterResponseCommit);
        assert_eq!(
            snapshot.stage,
            if recorded {
                AcquisitionStage::ResponseRecorded
            } else {
                AcquisitionStage::Unknown
            }
        );
        assert_eq!(
            (snapshot.reserved_calls, snapshot.reserved_bytes),
            (1, 1024)
        );
        assert_eq!(
            snapshot.response_bytes,
            recorded.then_some(CONTENT.len() as u64)
        );
        assert_eq!(
            snapshot.content_projection,
            recorded.then_some(ContentProjectionStatus::Ready {
                bytes: CONTENT.len() as u64
            }),
            "lost response bytes cannot become retained content"
        );
        let calls = if self.setup.point.resumable() {
            1
        } else {
            self.setup.point.provider_calls()
        };
        assert_eq!(self.provider.calls.load(Ordering::SeqCst), calls);
        let raw: Value =
            serde_json::from_slice(&self.raw().expect("record")).expect("native record");
        assert!(!raw["entry"].is_null());
        assert_eq!(
            raw["state"]["facts"]["allocation"], 0,
            "one original permanent allocation"
        );
    }
}

fn crash_matrix(backend: Backend) {
    let cases: Vec<_> = Point::ALL
        .into_iter()
        .map(|point| {
            let case = Case::new(backend, point);
            case.crash();
            case.reopen()
        })
        .collect();
    let artifact = serde_json::to_vec_pretty(&json!({
        "schema": "auths.native-process-crash/1", "adapter": backend.label(),
        "scope": "full native content acquisition engine, fixed public fixture trust/approval/clock, separate real OS processes/custody and real local HTTP; SIGKILL inside/between actual adapter transactions and after partial response; no native decision or permit replaced",
        "excluded": ["mutation/disclosure boundary schedules", "injected sync/rename/partial-batch/ambiguous-commit faults", "power loss or full-store rollback", "hostile OS isolation", "production commissioning and human approval"],
        "cases": cases
    })).expect("artifact");
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-process-crash-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("artifact write");
    }
    assert_eq!(std::fs::read(path).expect("artifact"), artifact);
}

#[test]
fn native_file_process_crash_fixture_is_current() {
    crash_matrix(Backend::File);
}

#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_process_crash_fixture_is_current() {
    assert!(postgres_configured());
    crash_matrix(Backend::Postgres);
}
