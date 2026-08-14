//! Bounded exporters for the Rust-owned Auths operational vocabulary.

#![forbid(unsafe_code)]

use auths_operations::{
    DeploymentClass, EventSink, LatencyBucket, OperationalEventV2, OperationalOutcome,
    OperationalReasonCode, OperationalStage, OperationalSubsystem,
};
use std::{
    collections::{BTreeMap, VecDeque},
    fmt::Write as _,
    sync::{Arc, Mutex},
};

const MAX_BUFFER_CAPACITY: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackpressurePolicy {
    DropNewest,
    FailReadiness,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportError {
    InvalidConfiguration,
    Unavailable,
}

pub trait OtlpTransport: Send + Sync {
    fn export(&self, events: &[OperationalEventV2]) -> Result<(), ExportError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExporterStatus {
    pub buffered: usize,
    pub dropped: u64,
    pub export_failures: u64,
    pub ready: bool,
}

struct ExportState {
    buffer: VecDeque<OperationalEventV2>,
    dropped: u64,
    export_failures: u64,
}

pub struct BoundedOtlpExporter<T> {
    transport: T,
    capacity: usize,
    policy: BackpressurePolicy,
    state: Mutex<ExportState>,
}

impl<T: OtlpTransport> BoundedOtlpExporter<T> {
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
            state: Mutex::new(ExportState {
                buffer: VecDeque::with_capacity(capacity),
                dropped: 0,
                export_failures: 0,
            }),
        })
    }

    pub fn flush(&self) -> Result<(), ExportError> {
        let batch = {
            let Ok(state) = self.state.lock() else {
                return Err(ExportError::Unavailable);
            };
            state.buffer.iter().cloned().collect::<Vec<_>>()
        };
        if batch.is_empty() {
            return Ok(());
        }
        if let Err(error) = self.transport.export(&batch) {
            if let Ok(mut state) = self.state.lock() {
                state.export_failures = state.export_failures.saturating_add(1);
            }
            return Err(error);
        }
        if let Ok(mut state) = self.state.lock() {
            for _ in 0..batch.len().min(state.buffer.len()) {
                state.buffer.pop_front();
            }
        }
        Ok(())
    }

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
                buffered: state.buffer.len(),
                dropped: state.dropped,
                export_failures: state.export_failures,
                ready: self.policy == BackpressurePolicy::DropNewest
                    || state.buffer.len() < self.capacity,
            },
        )
    }
}

impl<T: OtlpTransport> EventSink for BoundedOtlpExporter<T> {
    fn record(&self, event: &OperationalEventV2) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.buffer.len() == self.capacity {
            state.dropped = state.dropped.saturating_add(1);
            return;
        }
        state.buffer.push_back(event.clone());
    }
}

pub struct CombinedSink<T> {
    otlp: Arc<BoundedOtlpExporter<T>>,
    prometheus: Arc<PrometheusProjection>,
}

impl<T: OtlpTransport> CombinedSink<T> {
    #[must_use]
    pub const fn new(
        otlp: Arc<BoundedOtlpExporter<T>>,
        prometheus: Arc<PrometheusProjection>,
    ) -> Self {
        Self { otlp, prometheus }
    }
}

impl<T: OtlpTransport> EventSink for CombinedSink<T> {
    fn record(&self, event: &OperationalEventV2) {
        self.otlp.record(event);
        self.prometheus.record(event);
    }
}

type PrometheusKey = (
    OperationalStage,
    OperationalOutcome,
    OperationalReasonCode,
    OperationalSubsystem,
    LatencyBucket,
    DeploymentClass,
);

#[derive(Default)]
pub struct PrometheusProjection {
    counters: Mutex<BTreeMap<PrometheusKey, u64>>,
}

impl PrometheusProjection {
    #[must_use]
    pub fn render(&self) -> String {
        let Ok(counters) = self.counters.lock() else {
            return "auths_operations_projection_failures_total 1\n".to_owned();
        };
        let mut output = String::from(
            "# HELP auths_operations_total Bounded Auths operational events\n\
             # TYPE auths_operations_total counter\n",
        );
        for ((stage, outcome, reason, subsystem, latency, deployment), count) in counters.iter() {
            let _ = writeln!(
                output,
                "auths_operations_total{{stage=\"{}\",outcome=\"{}\",reason=\"{}\",subsystem=\"{}\",latency=\"{}\",deployment=\"{}\"}} {}",
                stage_label(*stage),
                outcome_label(*outcome),
                reason_label(*reason),
                subsystem_label(*subsystem),
                latency_label(*latency),
                deployment_label(*deployment),
                count,
            );
        }
        output
    }
}

impl EventSink for PrometheusProjection {
    fn record(&self, event: &OperationalEventV2) {
        let Ok(mut counters) = self.counters.lock() else {
            return;
        };
        let count = counters
            .entry((
                event.stage(),
                event.outcome(),
                event.reason(),
                event.subsystem(),
                event.elapsed(),
                event.deployment(),
            ))
            .or_default();
        *count = count.saturating_add(1);
    }
}

const fn stage_label(value: OperationalStage) -> &'static str {
    match value {
        OperationalStage::Acquisition => "acquisition",
        OperationalStage::Verification => "verification",
        OperationalStage::Policy => "policy",
        OperationalStage::DecisionPersistence => "decision-persistence",
        OperationalStage::Reservation => "reservation",
        OperationalStage::ExecutionIntent => "execution-intent",
        OperationalStage::Credential => "credential",
        OperationalStage::ProviderEntry => "provider-entry",
        OperationalStage::ProviderResult => "provider-result",
        OperationalStage::Observation => "observation",
        OperationalStage::Reconciliation => "reconciliation",
        OperationalStage::Receipt => "receipt",
        OperationalStage::Recovery => "recovery",
    }
}

const fn outcome_label(value: OperationalOutcome) -> &'static str {
    match value {
        OperationalOutcome::Succeeded => "succeeded",
        OperationalOutcome::Denied => "denied",
        OperationalOutcome::Indeterminate => "indeterminate",
        OperationalOutcome::Conflict => "conflict",
        OperationalOutcome::Saturated => "saturated",
        OperationalOutcome::Unavailable => "unavailable",
        OperationalOutcome::Failed => "failed",
        OperationalOutcome::OutcomeUnknown => "outcome-unknown",
    }
}

const fn reason_label(value: OperationalReasonCode) -> &'static str {
    match value {
        OperationalReasonCode::None => "none",
        OperationalReasonCode::Authorized => "authorized",
        OperationalReasonCode::Denied => "denied",
        OperationalReasonCode::EvidenceUnavailable => "evidence-unavailable",
        OperationalReasonCode::ConfigurationMismatch => "configuration-mismatch",
        OperationalReasonCode::StoreConflict => "store-conflict",
        OperationalReasonCode::StoreUnavailable => "store-unavailable",
        OperationalReasonCode::CustodyDenied => "custody-denied",
        OperationalReasonCode::CustodyUnavailable => "custody-unavailable",
        OperationalReasonCode::ProviderFailed => "provider-failed",
        OperationalReasonCode::ProviderUnknown => "provider-unknown",
        OperationalReasonCode::ReceiptUnavailable => "receipt-unavailable",
        OperationalReasonCode::RecoveryPending => "recovery-pending",
        OperationalReasonCode::Recovered => "recovered",
    }
}

const fn subsystem_label(value: OperationalSubsystem) -> &'static str {
    match value {
        OperationalSubsystem::Runtime => "runtime",
        OperationalSubsystem::Store => "store",
        OperationalSubsystem::Custody => "custody",
        OperationalSubsystem::Provider => "provider",
        OperationalSubsystem::Observer => "observer",
        OperationalSubsystem::Receipt => "receipt",
    }
}

const fn latency_label(value: LatencyBucket) -> &'static str {
    match value {
        LatencyBucket::UnderOneMillisecond => "lt-1ms",
        LatencyBucket::UnderTenMilliseconds => "lt-10ms",
        LatencyBucket::UnderOneHundredMilliseconds => "lt-100ms",
        LatencyBucket::UnderOneSecond => "lt-1s",
        LatencyBucket::UnderTenSeconds => "lt-10s",
        LatencyBucket::TenSecondsOrMore => "gte-10s",
    }
}

const fn deployment_label(value: DeploymentClass) -> &'static str {
    match value {
        DeploymentClass::Development => "development",
        DeploymentClass::CustomerOperated => "customer-operated",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_operations::BuildSemanticId;

    struct Unavailable;

    impl OtlpTransport for Unavailable {
        fn export(&self, _events: &[OperationalEventV2]) -> Result<(), ExportError> {
            Err(ExportError::Unavailable)
        }
    }

    fn event() -> OperationalEventV2 {
        OperationalEventV2::new(
            BuildSemanticId::parse("build-1").unwrap(),
            None,
            OperationalStage::ProviderResult,
            OperationalOutcome::OutcomeUnknown,
            OperationalReasonCode::ProviderUnknown,
            LatencyBucket::UnderOneSecond,
            OperationalSubsystem::Provider,
            None,
            DeploymentClass::CustomerOperated,
        )
    }

    #[test]
    fn exporter_failure_is_inert_and_buffer_is_bounded() {
        let exporter =
            BoundedOtlpExporter::new(Unavailable, 1, BackpressurePolicy::DropNewest).unwrap();
        exporter.record(&event());
        exporter.record(&event());
        assert_eq!(exporter.status().buffered, 1);
        assert_eq!(exporter.status().dropped, 1);
        assert_eq!(exporter.flush(), Err(ExportError::Unavailable));
        assert_eq!(exporter.status().buffered, 1);
    }

    #[test]
    fn prometheus_projection_has_only_frozen_dimensions() {
        let projection = PrometheusProjection::default();
        projection.record(&event());
        let rendered = projection.render();
        assert!(rendered.contains("outcome=\"outcome-unknown\""));
        for prohibited in ["principal", "resource", "workflow", "receipt", "token"] {
            assert!(!rendered.contains(prohibited));
        }
    }
}
