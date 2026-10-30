//! Retained recovery after expiry/withdrawal, actual timeout, and store errors.
use super::*;
use crate::{
    AcquisitionStage, GatewayAttemptError, GatewayAttemptStore, GatewayAttempts,
    GatewayFenceDecision, GatewayInsert, GatewayRecordEntry, RecoveryDisposition as D,
};
use std::{sync::atomic::AtomicUsize, time::Instant};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Fault {
    None,
    LoadUnavailable,
    FenceUnavailable,
    RefuseGrant,
}

/// Controlled adapter-port errors. Healthy calls and every writer fence use the
/// maintained durable adapter; this is not a database-outage qualification.
struct FaultStore {
    inner: Arc<dyn GatewayAttemptStore>,
    grant_key: GatewayAttemptKey,
    fault: Mutex<Fault>,
    failures: AtomicUsize,
}
impl FaultStore {
    fn mode(&self) -> Fault {
        *self.fault.lock().expect("fault")
    }
    fn refuse<T>(&self) -> Result<T, GatewayAttemptError> {
        self.failures.fetch_add(1, Ordering::SeqCst);
        Err(GatewayAttemptError::Unavailable)
    }
}
impl GatewayAttemptStore for FaultStore {
    fn fenced_insert_all(
        &self,
        entries: &[GatewayRecordEntry],
        dependencies: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut GatewayFenceDecision<'_>,
    ) -> Result<GatewayInsert, GatewayAttemptError> {
        self.inner.fenced_insert_all(entries, dependencies, decide)
    }
    fn fenced_replace(
        &self,
        keys: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut GatewayFenceDecision<'_>,
    ) -> Result<(), GatewayAttemptError> {
        self.inner.fenced_replace(keys, &mut |snapshots| {
            if self.mode() == Fault::FenceUnavailable {
                return self.refuse();
            }
            let next = decide(snapshots)?;
            if self.mode() == Fault::RefuseGrant
                && keys.first() == Some(&(GatewayRecordKind::Attempt, self.grant_key))
                && serde_json::from_slice::<Value>(&next)
                    .expect("unchanged native decision")
                    .pointer("/state/facts/phase/stage")
                    .and_then(Value::as_str)
                    == Some("entry-granted")
            {
                return self.refuse();
            }
            Ok(next)
        })
    }
    fn insert_all(
        &self,
        entries: &[GatewayRecordEntry],
    ) -> Result<GatewayInsert, GatewayAttemptError> {
        self.inner.insert_all(entries)
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
    fn load(
        &self,
        kind: GatewayRecordKind,
        key: &GatewayAttemptKey,
    ) -> Result<Option<Vec<u8>>, GatewayAttemptError> {
        if kind == GatewayRecordKind::Attempt && self.mode() == Fault::LoadUnavailable {
            return self.refuse();
        }
        self.inner.load(kind, key)
    }
    fn sweep_expired(&self, now: u64, limit: usize) -> Result<usize, GatewayAttemptError> {
        self.inner.sweep_expired(now, limit)
    }
    fn attempt_keys(&self, limit: usize) -> Result<Vec<GatewayAttemptKey>, GatewayAttemptError> {
        self.inner.attempt_keys(limit)
    }
}

#[derive(Clone, Copy)]
enum Scenario {
    Linked,
    Inconclusive,
    Reserved,
    Timeout,
}
impl Scenario {
    const fn name(self) -> &'static str {
        match self {
            Self::Linked => "linked-response",
            Self::Inconclusive => "inconclusive-response",
            Self::Reserved => "pre-grant-reservation",
            Self::Timeout => "elapsed-native-transport-timeout",
        }
    }
    const fn stage(self) -> AcquisitionStage {
        match self {
            Self::Linked | Self::Inconclusive => AcquisitionStage::ResponseRecorded,
            Self::Reserved => AcquisitionStage::Reserved,
            Self::Timeout => AcquisitionStage::Unknown,
        }
    }
}

struct SignedRead {
    signed: crate::harness::authoring::ToolFixture,
    approval: ExactEffectApproval,
    keys: Vec<(GatewayRecordKind, GatewayAttemptKey)>,
}
fn signed_read(
    engine: &GatewayEngine,
    runtime: &tokio::runtime::Runtime,
    operation: &str,
) -> SignedRead {
    let call = runtime
        .block_on(engine.recovery_authorization_call(SOURCE, operation))
        .expect("native closed call");
    let signed = author::signed(&call, true);
    let effect = runtime
        .block_on(engine.compile_recovery_effect(SOURCE, &signed.proof, &signed.action))
        .expect("native authority before withdrawal");
    let approval = author::approval(&effect, NOW + 1);
    let policy = crate::effect::fixture_policy().expect("policy");
    let approved = effect
        .approve(approval.clone(), policy.approver(), NOW + 1)
        .expect("exact approval");
    let capacity = approved
        .recovery_plan()
        .expect("native plan")
        .capacity()
        .expect("capacity");
    let mut keys: Vec<_> = [SOURCE, operation]
        .into_iter()
        .map(|operation| {
            (
                GatewayRecordKind::Attempt,
                GatewayAttemptKey::for_operation(
                    &policy,
                    author::recipe().namespace(),
                    &LogicalOperationId::parse(operation).expect("operation"),
                )
                .expect("key"),
            )
        })
        .collect();
    keys.extend((0..capacity.attempts).map(|slot| {
        (
            GatewayRecordKind::EffectAllocation,
            GatewayAttemptKey::from_bytes(crate::bounds::count_slot_key(&capacity.count_key, slot)),
        )
    }));
    SignedRead {
        signed,
        approval,
        keys,
    }
}
fn stored(store: &FaultStore, read: &SignedRead) -> Vec<Option<Vec<u8>>> {
    read.keys
        .iter()
        .map(|(kind, key)| store.inner.load(*kind, key).expect("retained row"))
        .collect()
}
fn recover(
    engine: &GatewayEngine,
    runtime: &tokio::runtime::Runtime,
    read: &SignedRead,
) -> Result<crate::RecoverySnapshot, GatewaySubmitResult> {
    runtime.block_on(Box::pin(engine.recover(
        SOURCE,
        &read.signed.proof,
        &read.signed.action,
        read.approval.clone(),
    )))
}

fn unavailable_history(
    engine: &GatewayEngine,
    runtime: &tokio::runtime::Runtime,
    store: &FaultStore,
    read: &SignedRead,
) -> Value {
    let retained = stored(store, read);
    let witness = engine.execution_witness();
    let mut refusals = Vec::new();
    for (fault, code) in [
        (Fault::LoadUnavailable, "gateway.attempt.state-unavailable"),
        (Fault::FenceUnavailable, "gateway.recovery.unavailable"),
    ] {
        let failures = store.failures.load(Ordering::SeqCst);
        *store.fault.lock().expect("fault") = fault;
        let refused = recover(engine, runtime, read).expect_err("no fabricated zero-usage report");
        assert_eq!(
            refused,
            GatewaySubmitResult::Indeterminate {
                code: code.to_owned()
            }
        );
        assert_eq!(store.failures.load(Ordering::SeqCst), failures + 1);
        *store.fault.lock().expect("fault") = Fault::None;
        assert_eq!(stored(store, read), retained);
        assert_eq!(engine.execution_witness(), witness);
        refusals.push(json!(refused));
    }
    json!(refusals)
}

fn substitutions(
    engine: &GatewayEngine,
    runtime: &tokio::runtime::Runtime,
    read: &SignedRead,
    source_approval: ExactEffectApproval,
) {
    let witness = engine.execution_witness();
    let mut proof = read.signed.proof.clone();
    proof[0] ^= 1;
    assert!(
        runtime
            .block_on(Box::pin(engine.recover(
                SOURCE,
                &proof,
                &read.signed.action,
                read.approval.clone()
            )))
            .is_err()
    );
    let mut action = read.signed.action.clone();
    action[0] ^= 1;
    assert!(
        runtime
            .block_on(Box::pin(engine.recover(
                SOURCE,
                &read.signed.proof,
                &action,
                read.approval.clone()
            )))
            .is_err()
    );
    assert!(
        runtime
            .block_on(Box::pin(engine.recover(
                "unrelated-source",
                &read.signed.proof,
                &read.signed.action,
                read.approval.clone()
            )))
            .is_err()
    );
    assert!(
        runtime
            .block_on(Box::pin(engine.recover(
                SOURCE,
                &read.signed.proof,
                &read.signed.action,
                source_approval
            )))
            .is_err()
    );
    assert_eq!(engine.execution_witness(), witness);
}

#[allow(
    clippy::too_many_lines,
    reason = "one native historical recovery schedule preserves source, read, allocation, expiry and withdrawal evidence"
)]
fn history(backend: Backend, scenario: Scenario) -> Value {
    let case = Case::start(
        backend,
        if matches!(scenario, Scenario::Linked) {
            Outcome::LostEcho
        } else {
            Outcome::LostState
        },
    );
    let runtime = runtime();
    let faults = Arc::new(FaultStore {
        inner: case.store.raw(),
        grant_key: GatewayAttemptKey::for_operation(
            &crate::effect::fixture_policy().expect("policy"),
            author::recipe().namespace(),
            &LogicalOperationId::parse(RECOVERY).expect("read operation"),
        )
        .expect("read key"),
        fault: Mutex::new(Fault::None),
        failures: AtomicUsize::new(0),
    });
    let attempts = GatewayAttempts::new(
        faults.clone(),
        crate::effect::fixture_policy().expect("policy"),
    )
    .expect("attempts");
    let reader_controls = controls(true);
    let clock = Arc::clone(&reader_controls.clock);
    let (engine, _) = runtime.block_on(load_controlled_engine(
        &case.setup.installation,
        "history-reader",
        attempts.clone(),
        reader_controls,
    ));
    engine
        .activate_effect_configuration(
            engine
                .effect_configuration_revision()
                .expect("operator revision"),
        )
        .expect("withdraw writer root");
    let read = signed_read(&engine, &runtime, RECOVERY);
    let fresh = signed_read(&engine, &runtime, "never-entered-reader");
    let pause = if matches!(scenario, Scenario::Timeout) {
        Some(case.provider.pause_next_read())
    } else {
        None
    };
    if matches!(scenario, Scenario::Reserved) {
        *faults.fault.lock().expect("fault") = Fault::RefuseGrant;
    }
    let started = Instant::now();
    let first = recover(&engine, &runtime, &read).expect("native recovery");
    let elapsed = started.elapsed();
    *faults.fault.lock().expect("fault") = Fault::None;
    if let Some((release, waiting)) = pause {
        assert!(
            waiting.load(Ordering::SeqCst),
            "provider still withholds every response byte when the native deadline fires"
        );
        assert!(
            elapsed
                >= crate::transport::MAX_TRANSPORT_DURATION.saturating_sub(Duration::from_secs(1))
        );
        assert!(elapsed < crate::transport::MAX_TRANSPORT_DURATION + Duration::from_secs(10));
        release
            .send(())
            .expect("release provider after real timeout");
    }
    if matches!(scenario, Scenario::Reserved) {
        assert_eq!(faults.failures.load(Ordering::SeqCst), 1);
    }
    assert_eq!(first.acquisition.stage, scenario.stage());
    assert_eq!(first.budget.retained_attempts, 1);
    assert_eq!(first.budget.retained_response_bytes, 16_384);
    let retained = stored(&faults, &read);
    let witness = engine.execution_witness();
    let expected_requests = if matches!(scenario, Scenario::Reserved) {
        1
    } else {
        2
    };
    assert_eq!(
        case.provider.requests.lock().expect("requests").len(),
        expected_requests
    );
    clock.set(NOW + 3_601);
    let expired =
        recover(&engine, &runtime, &read).expect("expired reader retains exact historical facts");
    assert_eq!(expired.acquisition, first.acquisition);
    assert_eq!(expired.source, first.source);
    assert_eq!(expired.budget, first.budget);
    assert_eq!(
        expired.acquisition_received_at,
        first.acquisition_received_at
    );
    assert_eq!(
        expired.disposition,
        match scenario {
            Scenario::Linked => D::AlreadyRecorded,
            Scenario::Inconclusive => D::EvidenceStale,
            Scenario::Reserved | Scenario::Timeout => D::AcquisitionIncomplete,
        }
    );
    assert!(
        recover(&engine, &runtime, &fresh).is_err(),
        "expired input with no journal match cannot start a read"
    );
    assert_eq!(stored(&faults, &read), retained);
    assert_eq!(engine.execution_witness(), witness);
    let mut withdrawn_controls = controls(true);
    withdrawn_controls.trust = Some(author::trust_roots(&[0x13]));
    let (withdrawn, _) = runtime.block_on(load_controlled_engine(
        &case.setup.installation,
        "reader-withdrawn",
        attempts,
        withdrawn_controls,
    ));
    withdrawn
        .activate_effect_configuration(
            withdrawn
                .effect_configuration_revision()
                .expect("operator revision"),
        )
        .expect("withdraw reader root too");
    let after_withdrawal =
        recover(&withdrawn, &runtime, &read).expect("withdrawal does not erase exact history");
    assert_eq!(after_withdrawal.source, first.source);
    assert_eq!(after_withdrawal.acquisition, first.acquisition);
    assert_eq!(after_withdrawal.budget, first.budget);
    assert_eq!(
        after_withdrawal.acquisition_received_at,
        first.acquisition_received_at
    );
    assert_eq!(
        recover(&withdrawn, &runtime, &fresh)
            .expect_err("untrusted reader cannot start a new read"),
        GatewaySubmitResult::Denied {
            code: "untrusted-root".to_owned()
        }
    );
    let (_, _, source_approval) = input(&case.setup.installation.root, SOURCE);
    substitutions(&withdrawn, &runtime, &read, source_approval);
    let unavailable = unavailable_history(&withdrawn, &runtime, &faults, &read);
    assert_eq!(stored(&faults, &read), retained);
    assert_eq!(withdrawn.execution_witness().credential_lease_calls, 0);
    runtime
        .block_on(withdrawn.disable_connection())
        .expect("disable connection after delivery");
    let disabled = recover(&withdrawn, &runtime, &read)
        .expect("disabled connection preserves historical recovery");
    assert_eq!(disabled.report(), after_withdrawal.report());
    assert_eq!(stored(&faults, &read), retained);
    assert_eq!(withdrawn.execution_witness().credential_lease_calls, 0);
    assert_eq!(
        case.provider.requests.lock().expect("requests").len(),
        expected_requests
    );
    assert_eq!(
        signed_bytes(&case.setup.installation.root, SOURCE),
        case.signed_source
    );
    assert_fixed_source(&case.original, &record(&case.store, SOURCE));
    json!({"case": scenario.name(), "first":first.report(), "expired":expired.report(),
        "withdrawn":after_withdrawal.report(), "unavailable_store":unavailable,
        "original_attribution_and_charges_preserved":true, "receipt_time_never_refreshed":true,
        "expired_and_withdrawn_new_read_refused":true, "altered_inputs_source_or_approval_refused":true,
        "retained_rows_and_no_io_after_expiry_withdrawal_or_disable":true,
        "elapsed_timeout_checked_against_native_deadline":matches!(scenario, Scenario::Timeout)})
}

fn matrix(backend: Backend) {
    let cases: Vec<_> = [
        Scenario::Linked,
        Scenario::Inconclusive,
        Scenario::Reserved,
        Scenario::Timeout,
    ]
    .into_iter()
    .map(|scenario| history(backend, scenario))
    .collect();
    let artifact = serde_json::to_vec_pretty(&json!({"schema":"auths.native-recovery-history/1", "adapter":backend.label(),
        "scope":"native signed proofs and exact approvals, real local HTTP including elapsed 15-second timeout, maintained durable adapters, operator root withdrawal and connection disable",
        "assumptions":["trusted maintained host and fixed test clock", "public fixed fixture keys"],
        "excluded":["database outage or filesystem-device failure qualification", "live provider and custody", "hostile OS and power failure"],
        "store_error_scope":"controlled load error and error inside the actual adapter writer fence; no synthetic journal facts", "cases":cases})).expect("artifact");
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-recovery-history-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("fixture");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), artifact);
}
#[test]
fn native_file_recovery_history_fixture_is_current() {
    matrix(Backend::File);
}
#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_recovery_history_fixture_is_current() {
    assert!(postgres_configured());
    matrix(Backend::Postgres);
}
