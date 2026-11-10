//! One exclusive batch owner per export. Concurrent callers observe one cohort.
use crate::{BackpressurePolicy, ExportError, ExporterStatus, MAX_BUFFER_CAPACITY, OtlpTransport};
use auths_operations::{EventSink, OperationalEventV2};
use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex},
    thread::{self, ThreadId},
};

type Batch = Arc<Vec<OperationalEventV2>>;

enum CohortOutcome {
    Pending,
    Complete(Result<(), ExportError>),
}

struct CohortState {
    outcome: CohortOutcome,
    waiters: usize,
}

struct Cohort {
    state: Mutex<CohortState>,
    changed: Condvar,
}

impl Cohort {
    fn new() -> Self {
        Self {
            state: Mutex::new(CohortState {
                outcome: CohortOutcome::Pending,
                waiters: 0,
            }),
            changed: Condvar::new(),
        }
    }

    fn finish(&self, result: Result<(), ExportError>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.outcome = CohortOutcome::Complete(result);
        self.changed.notify_all();
    }

    fn wait(&self) -> Result<(), ExportError> {
        let mut state = self.state.lock().map_err(|_| ExportError::Unavailable)?;
        state.waiters = state.waiters.saturating_add(1);
        self.changed.notify_all();
        loop {
            if let CohortOutcome::Complete(result) = state.outcome {
                return result;
            }
            state = self
                .changed
                .wait(state)
                .map_err(|_| ExportError::Unavailable)?;
        }
    }
}

enum Phase {
    Idle,
    Retryable(Batch),
    Exporting {
        cohort: Arc<Cohort>,
        batch: Batch,
        owner: ThreadId,
    },
    Unavailable {
        retained: Option<Batch>,
    },
}

impl Phase {
    fn retained(&self) -> Option<&Batch> {
        match self {
            Self::Idle => None,
            Self::Retryable(batch) | Self::Exporting { batch, .. } => Some(batch),
            Self::Unavailable { retained } => retained.as_ref(),
        }
    }
}

struct State {
    queue: VecDeque<OperationalEventV2>,
    phase: Phase,
    dropped: u64,
    export_failures: u64,
}

impl State {
    fn buffered(&self) -> usize {
        self.queue.len() + self.phase.retained().map_or(0, |batch| batch.len())
    }
}

/// Bounded volatile exporter with exact batch acknowledgement and exclusive I/O.
pub struct BoundedOtlpExporter<T> {
    transport: T,
    capacity: usize,
    policy: BackpressurePolicy,
    state: Mutex<State>,
}

enum Admission {
    Joined(Arc<Cohort>),
    Owner { cohort: Arc<Cohort>, batch: Batch },
}

impl<T: OtlpTransport> BoundedOtlpExporter<T> {
    /// Creates an event-count-bounded exporter; queued and in-flight events share capacity.
    ///
    /// # Errors
    /// Rejects zero capacity or a capacity above the hard maximum.
    pub fn new(
        transport: T,
        capacity: usize,
        policy: BackpressurePolicy,
    ) -> Result<Self, ExportError> {
        if capacity == 0 || capacity > MAX_BUFFER_CAPACITY {
            return Err(ExportError::InvalidConfiguration);
        }
        Ok(Self {
            transport,
            capacity,
            policy,
            state: Mutex::new(State {
                queue: VecDeque::new(),
                phase: Phase::Idle,
                dropped: 0,
                export_failures: 0,
            }),
        })
    }

    /// Exports one snapshot, or joins the snapshot currently being exported.
    ///
    /// Events recorded after the snapshot remain queued. A failed cohort does
    /// not retry: every joined caller observes its result. A later call may
    /// explicitly retry the retained batch, before any newer queued events.
    ///
    /// # Errors
    /// Returns the transport failure, or unavailable on recursive flush, poisoned
    /// state, or an exporter whose transport previously unwound. A transport panic
    /// continues unwinding for its initiating caller; joined callers are released.
    pub fn flush(&self) -> Result<(), ExportError> {
        let admission = {
            let mut state = self.state.lock().map_err(|_| ExportError::Unavailable)?;
            match &state.phase {
                Phase::Unavailable { .. } => return Err(ExportError::Unavailable),
                Phase::Exporting { owner, .. } if *owner == thread::current().id() => {
                    return Err(ExportError::Unavailable);
                }
                Phase::Exporting { cohort, .. } => Admission::Joined(Arc::clone(cohort)),
                Phase::Idle | Phase::Retryable(_) => {
                    let batch = if let Phase::Retryable(batch) = &state.phase {
                        Arc::clone(batch)
                    } else {
                        if state.queue.is_empty() {
                            return Ok(());
                        }
                        Arc::new(std::mem::take(&mut state.queue).into_iter().collect())
                    };
                    let cohort = Arc::new(Cohort::new());
                    state.phase = Phase::Exporting {
                        cohort: Arc::clone(&cohort),
                        batch: Arc::clone(&batch),
                        owner: thread::current().id(),
                    };
                    Admission::Owner { cohort, batch }
                }
            }
        };
        match admission {
            Admission::Joined(cohort) => cohort.wait(),
            Admission::Owner { cohort, batch } => {
                // Dropping this exact ownership capability handles unwind, not transport success.
                let guard = ExportGuard {
                    exporter: self,
                    owned: Some((cohort, Arc::clone(&batch))),
                };
                let result = self.transport.export(&batch);
                guard.complete(result)
            }
        }
    }

    fn finish(
        &self,
        cohort: &Cohort,
        batch: Batch,
        result: Result<(), ExportError>,
        unwound: bool,
    ) -> Result<(), ExportError> {
        let locked = self.state.lock();
        let unavailable = unwound || locked.is_err();
        let mut state = locked.unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = if unavailable {
            Err(ExportError::Unavailable)
        } else {
            result
        };
        state.phase = if unavailable {
            Phase::Unavailable {
                retained: Some(batch),
            }
        } else if result.is_err() {
            Phase::Retryable(batch)
        } else {
            Phase::Idle
        };
        if result.is_err() {
            state.export_failures = state.export_failures.saturating_add(1);
        }
        // Publish queue ownership before waking callers. Cohort identity survives a later flush.
        cohort.finish(result);
        result
    }

    /// Reports total retained events and readiness without treating failure as delivery.
    #[must_use]
    pub fn status(&self) -> ExporterStatus {
        self.state.lock().map_or(
            ExporterStatus {
                buffered: self.capacity,
                dropped: 0,
                export_failures: 1,
                ready: false,
            },
            |state| ExporterStatus {
                buffered: state.buffered(),
                dropped: state.dropped,
                export_failures: state.export_failures,
                ready: !matches!(state.phase, Phase::Unavailable { .. })
                    && (self.policy == BackpressurePolicy::DropNewest
                        || state.buffered() < self.capacity),
            },
        )
    }
}

impl<T: OtlpTransport> EventSink for BoundedOtlpExporter<T> {
    fn record(&self, event: &OperationalEventV2) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if matches!(state.phase, Phase::Unavailable { .. }) || state.buffered() == self.capacity {
            state.dropped = state.dropped.saturating_add(1);
        } else {
            state.queue.push_back(event.clone());
        }
    }
}

/// A one-use batch capability. Taking it acknowledges completion; drop retains uncertainty.
struct ExportGuard<'a, T: OtlpTransport> {
    exporter: &'a BoundedOtlpExporter<T>,
    owned: Option<(Arc<Cohort>, Batch)>,
}

impl<T: OtlpTransport> ExportGuard<'_, T> {
    fn complete(mut self, result: Result<(), ExportError>) -> Result<(), ExportError> {
        let Some((cohort, batch)) = self.owned.take() else {
            return Err(ExportError::Unavailable);
        };
        self.exporter.finish(&cohort, batch, result, false)
    }
}

impl<T: OtlpTransport> Drop for ExportGuard<'_, T> {
    fn drop(&mut self) {
        if let Some((cohort, batch)) = self.owned.take() {
            let _ = self
                .exporter
                .finish(&cohort, batch, Err(ExportError::Unavailable), true);
        }
    }
}

#[cfg(test)]
mod tests;
