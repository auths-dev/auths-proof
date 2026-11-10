use super::*;
use auths_operations::{
    BuildSemanticId, DeploymentClass, LatencyBucket, OperationalDimensions, OperationalOutcome,
    OperationalReasonCode, OperationalStage, OperationalSubsystem,
};
use std::{
    sync::{
        Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

fn event(name: &str) -> OperationalEventV2 {
    OperationalEventV2::new(
        BuildSemanticId::parse(name).unwrap(),
        None,
        OperationalDimensions::new(
            OperationalStage::ProviderResult,
            OperationalOutcome::OutcomeUnknown,
            OperationalReasonCode::ProviderUnknown,
            LatencyBucket::UnderOneSecond,
            OperationalSubsystem::Provider,
            DeploymentClass::CustomerOperated,
        ),
        None,
    )
}

struct Gate {
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
    batches: Mutex<Vec<Vec<String>>>,
    fail: AtomicBool,
    panic: AtomicBool,
    calls: AtomicUsize,
}

impl OtlpTransport for Arc<Gate> {
    fn export(&self, events: &[OperationalEventV2]) -> Result<(), ExportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.batches.lock().unwrap().push(
            events
                .iter()
                .map(|event| event.build().as_str().to_owned())
                .collect(),
        );
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv().unwrap();
        assert!(
            !self.panic.load(Ordering::SeqCst),
            "injected transport unwind"
        );
        if self.fail.load(Ordering::SeqCst) {
            Err(ExportError::Unavailable)
        } else {
            Ok(())
        }
    }
}

fn gate() -> (Arc<Gate>, mpsc::Receiver<()>, mpsc::Sender<()>) {
    let (entered, observed) = mpsc::channel();
    let (release, proceed) = mpsc::channel();
    (
        Arc::new(Gate {
            entered,
            release: Mutex::new(proceed),
            batches: Mutex::new(Vec::new()),
            fail: AtomicBool::new(false),
            panic: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        }),
        observed,
        release,
    )
}

fn joined<T: OtlpTransport>(exporter: &BoundedOtlpExporter<T>, count: usize) {
    let cohort = {
        let state = exporter.state.lock().unwrap();
        let Phase::Exporting { cohort, .. } = &state.phase else {
            panic!("export not pending");
        };
        Arc::clone(cohort)
    };
    let mut state = cohort.state.lock().unwrap();
    while state.waiters < count {
        let (next, timeout) = cohort
            .changed
            .wait_timeout(state, Duration::from_secs(30))
            .unwrap();
        state = next;
        assert!(!timeout.timed_out(), "flush caller never joined the cohort");
    }
}

#[test]
fn b1_concurrent_success_acknowledges_only_its_snapshot() {
    let (transport, entered, release) = gate();
    let exporter = Arc::new(
        BoundedOtlpExporter::new(Arc::clone(&transport), 2, BackpressurePolicy::DropNewest)
            .unwrap(),
    );
    exporter.record(&event("old"));
    let owner = {
        let e = Arc::clone(&exporter);
        thread::spawn(move || e.flush())
    };
    entered.recv().unwrap();
    let waiter = {
        let e = Arc::clone(&exporter);
        thread::spawn(move || e.flush())
    };
    joined(&exporter, 1);
    exporter.record(&event("new"));
    assert_eq!(exporter.status().buffered, 2);
    release.send(()).unwrap();
    assert_eq!(owner.join().unwrap(), Ok(()));
    assert_eq!(waiter.join().unwrap(), Ok(()));
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    assert_eq!(exporter.status().buffered, 1);
    release.send(()).unwrap();
    assert_eq!(exporter.flush(), Ok(()));
    assert_eq!(
        *transport.batches.lock().unwrap(),
        vec![vec!["old"], vec!["new"]]
    );
    assert_eq!(exporter.status().buffered, 0);
}

#[test]
fn b2_in_flight_events_share_capacity_under_both_policies() {
    for policy in [
        BackpressurePolicy::DropNewest,
        BackpressurePolicy::FailReadiness,
    ] {
        let (transport, entered, release) = gate();
        let exporter = Arc::new(BoundedOtlpExporter::new(transport, 1, policy).unwrap());
        exporter.record(&event("old"));
        let owner = {
            let e = Arc::clone(&exporter);
            thread::spawn(move || e.flush())
        };
        entered.recv().unwrap();
        exporter.record(&event("overflow"));
        let status = exporter.status();
        assert_eq!(status.buffered, 1);
        assert_eq!(status.dropped, 1);
        assert_eq!(status.ready, policy == BackpressurePolicy::DropNewest);
        release.send(()).unwrap();
        assert_eq!(owner.join().unwrap(), Ok(()));
        assert_eq!(exporter.status().buffered, 0);
        assert!(exporter.status().ready);
    }
}

#[test]
fn b3_failure_is_shared_and_only_a_later_call_retries_the_oldest_batch() {
    let (transport, entered, release) = gate();
    transport.fail.store(true, Ordering::SeqCst);
    let exporter = Arc::new(
        BoundedOtlpExporter::new(Arc::clone(&transport), 3, BackpressurePolicy::DropNewest)
            .unwrap(),
    );
    exporter.record(&event("old"));
    let owner = {
        let e = Arc::clone(&exporter);
        thread::spawn(move || e.flush())
    };
    entered.recv().unwrap();
    let waiters: Vec<_> = (0..2)
        .map(|_| {
            let e = Arc::clone(&exporter);
            thread::spawn(move || e.flush())
        })
        .collect();
    joined(&exporter, 2);
    exporter.record(&event("new"));
    release.send(()).unwrap();
    assert_eq!(owner.join().unwrap(), Err(ExportError::Unavailable));
    for waiter in waiters {
        assert_eq!(waiter.join().unwrap(), Err(ExportError::Unavailable));
    }
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    assert_eq!(exporter.status().export_failures, 1);
    assert_eq!(exporter.status().buffered, 2);
    transport.fail.store(false, Ordering::SeqCst);
    release.send(()).unwrap();
    assert_eq!(exporter.flush(), Ok(()));
    assert_eq!(exporter.status().buffered, 1);
    release.send(()).unwrap();
    assert_eq!(exporter.flush(), Ok(()));
    assert_eq!(
        *transport.batches.lock().unwrap(),
        vec![vec!["old"], vec!["old"], vec!["new"]]
    );
}

#[test]
fn b4_unwind_releases_waiters_but_never_claims_delivery_or_retries() {
    let (transport, entered, release) = gate();
    transport.panic.store(true, Ordering::SeqCst);
    let exporter = Arc::new(
        BoundedOtlpExporter::new(Arc::clone(&transport), 2, BackpressurePolicy::DropNewest)
            .unwrap(),
    );
    exporter.record(&event("old"));
    let owner = {
        let e = Arc::clone(&exporter);
        thread::spawn(move || e.flush())
    };
    entered.recv().unwrap();
    let waiter = {
        let e = Arc::clone(&exporter);
        thread::spawn(move || e.flush())
    };
    joined(&exporter, 1);
    release.send(()).unwrap();
    assert!(owner.join().is_err());
    assert_eq!(waiter.join().unwrap(), Err(ExportError::Unavailable));
    exporter.record(&event("refused"));
    assert_eq!(exporter.flush(), Err(ExportError::Unavailable));
    assert_eq!(exporter.status().buffered, 1);
    assert_eq!(exporter.status().dropped, 1);
    assert_eq!(exporter.status().export_failures, 1);
    assert!(!exporter.status().ready);
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
}

struct Reentrant {
    exporter: Mutex<Weak<BoundedOtlpExporter<Arc<Reentrant>>>>,
}

impl OtlpTransport for Arc<Reentrant> {
    fn export(&self, _events: &[OperationalEventV2]) -> Result<(), ExportError> {
        let exporter = self.exporter.lock().unwrap().upgrade().unwrap();
        assert_eq!(exporter.flush(), Err(ExportError::Unavailable));
        exporter.record(&event("during-export"));
        Ok(())
    }
}

#[test]
fn b4_direct_reentry_is_refused_but_recording_from_transport_is_supported() {
    let transport = Arc::new(Reentrant {
        exporter: Mutex::new(Weak::new()),
    });
    let exporter = Arc::new(
        BoundedOtlpExporter::new(Arc::clone(&transport), 2, BackpressurePolicy::DropNewest)
            .unwrap(),
    );
    *transport.exporter.lock().unwrap() = Arc::downgrade(&exporter);
    exporter.record(&event("old"));
    assert_eq!(exporter.flush(), Ok(()));
    assert_eq!(exporter.status().buffered, 1);
    assert_eq!(exporter.status().export_failures, 0);
}

#[test]
fn b4_poisoned_state_is_unavailable_and_retains_its_events() {
    let (transport, _entered, _release) = gate();
    let exporter = BoundedOtlpExporter::new(transport, 1, BackpressurePolicy::DropNewest).unwrap();
    exporter.record(&event("retained"));
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _locked = exporter.state.lock().unwrap();
        panic!("injected state poison");
    }));
    assert!(poisoned.is_err());
    assert_eq!(exporter.flush(), Err(ExportError::Unavailable));
    assert!(!exporter.status().ready);
    assert_eq!(
        exporter.state.lock().err().unwrap().into_inner().buffered(),
        1
    );
}
