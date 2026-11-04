//! Test-only pass-through timing at the real adapter boundary. No decision,
//! bytes, acknowledgement, retry or runtime deadline is changed.
use crate::store::GatewayFenceDecision;
use crate::{
    GatewayAttemptError, GatewayAttemptKey, GatewayAttemptStore, GatewayInsert, GatewayRecordEntry,
    GatewayRecordKind,
};
use serde::Serialize;
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

#[derive(Default, Serialize)]
pub(super) struct AdapterCosts {
    pub(super) calls: Vec<Call>,
}

#[derive(Serialize)]
pub(super) struct Call {
    operation: &'static str,
    /// Includes wait, load, decision, persistence and unlock. This is a
    /// conservative observed upper bound, never an isolated lock-hold time.
    adapter_elapsed_ns: u64,
    decision_elapsed_ns: Option<u64>,
    snapshot_bytes: usize,
    snapshot_records: usize,
    input_bytes: usize,
    output_bytes: usize,
    succeeded: bool,
}

pub(super) struct MeteredStore {
    pub(super) inner: Arc<dyn GatewayAttemptStore>,
    pub(super) costs: Arc<Mutex<AdapterCosts>>,
}

pub(super) fn nanos(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).expect("bounded measurement")
}

impl MeteredStore {
    fn call<T>(
        &self,
        operation: &'static str,
        input_bytes: usize,
        work: impl FnOnce() -> Result<T, GatewayAttemptError>,
        output_size: impl FnOnce(&T) -> usize,
    ) -> Result<T, GatewayAttemptError> {
        let started = Instant::now();
        let result = work();
        let elapsed = nanos(started);
        let output_bytes = result.as_ref().map_or(0, output_size);
        self.costs.lock().expect("cost recorder").calls.push(Call {
            operation,
            adapter_elapsed_ns: elapsed,
            decision_elapsed_ns: None,
            snapshot_bytes: 0,
            snapshot_records: 0,
            input_bytes,
            output_bytes,
            succeeded: result.is_ok(),
        });
        result
    }

    fn fenced<T>(
        &self,
        operation: &'static str,
        input_bytes: usize,
        decide: &mut GatewayFenceDecision<'_>,
        work: impl FnOnce(&mut GatewayFenceDecision<'_>) -> Result<T, GatewayAttemptError>,
    ) -> Result<T, GatewayAttemptError> {
        let mut decision_elapsed_ns = None;
        let mut snapshot_bytes = 0;
        let mut snapshot_records = 0;
        let mut output_bytes = 0;
        let started = Instant::now();
        let result = work(&mut |snapshot| {
            assert!(decision_elapsed_ns.is_none(), "adapter calls decision once");
            snapshot_records = snapshot.len();
            snapshot_bytes = snapshot.iter().flatten().map(Vec::len).sum();
            assert!(snapshot_records <= auths_stores::MAX_GATEWAY_FENCE_RECORDS);
            assert!(
                snapshot
                    .iter()
                    .flatten()
                    .all(|bytes| bytes.len() <= auths_stores::MAX_GATEWAY_RECORD_BYTES)
            );
            let decision_started = Instant::now();
            let result = decide(snapshot);
            decision_elapsed_ns = Some(nanos(decision_started));
            output_bytes = result.as_ref().map_or(0, Vec::len);
            result
        });
        let elapsed = nanos(started);
        self.costs.lock().expect("cost recorder").calls.push(Call {
            operation,
            adapter_elapsed_ns: elapsed,
            decision_elapsed_ns,
            snapshot_bytes,
            snapshot_records,
            input_bytes,
            output_bytes,
            succeeded: result.is_ok(),
        });
        result
    }
}

impl GatewayAttemptStore for MeteredStore {
    fn fenced_insert_all(
        &self,
        entries: &[GatewayRecordEntry],
        dependencies: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut GatewayFenceDecision<'_>,
    ) -> Result<GatewayInsert, GatewayAttemptError> {
        self.fenced(
            "fenced-insert",
            entries.iter().map(|entry| entry.record.len()).sum(),
            decide,
            |decision| {
                self.inner
                    .fenced_insert_all(entries, dependencies, decision)
            },
        )
    }

    fn fenced_replace(
        &self,
        keys: &[(GatewayRecordKind, GatewayAttemptKey)],
        decide: &mut GatewayFenceDecision<'_>,
    ) -> Result<(), GatewayAttemptError> {
        self.fenced("fenced-replace", 0, decide, |decision| {
            self.inner.fenced_replace(keys, decision)
        })
    }

    fn insert_all(
        &self,
        entries: &[GatewayRecordEntry],
    ) -> Result<GatewayInsert, GatewayAttemptError> {
        self.call(
            "insert",
            entries.iter().map(|entry| entry.record.len()).sum(),
            || self.inner.insert_all(entries),
            |_| 0,
        )
    }

    fn load(
        &self,
        kind: GatewayRecordKind,
        key: &GatewayAttemptKey,
    ) -> Result<Option<Vec<u8>>, GatewayAttemptError> {
        self.call(
            "load",
            0,
            || self.inner.load(kind, key),
            |value| value.as_ref().map_or(0, Vec::len),
        )
    }

    fn replace(
        &self,
        kind: GatewayRecordKind,
        key: &GatewayAttemptKey,
        current: &[u8],
        next: &[u8],
    ) -> Result<(), GatewayAttemptError> {
        self.call(
            "replace",
            current.len() + next.len(),
            || self.inner.replace(kind, key, current, next),
            |_| 0,
        )
    }

    fn sweep_expired(&self, now: u64, limit: usize) -> Result<usize, GatewayAttemptError> {
        self.call("sweep", 0, || self.inner.sweep_expired(now, limit), |_| 0)
    }

    fn attempt_keys(&self, limit: usize) -> Result<Vec<GatewayAttemptKey>, GatewayAttemptError> {
        self.call(
            "inventory",
            0,
            || self.inner.attempt_keys(limit),
            |keys| keys.len() * size_of::<GatewayAttemptKey>(),
        )
    }
}
