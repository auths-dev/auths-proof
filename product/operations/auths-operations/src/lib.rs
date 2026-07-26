//! Deterministic readiness and privacy-preserving operational diagnostics.
//!
//! Events contain only stable stages, outcomes, reasons, and timings. Proof
//! bytes, principals, resources, arguments, and private custody data are
//! deliberately absent.

#![forbid(unsafe_code)]

use auths_config::BoundConfiguration;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Mutex,
};

const MAX_PROBES: usize = 128;
const MAX_LABEL_BYTES: usize = 128;

/// Required startup subsystem.
pub trait ReadinessProbe: Send + Sync {
    /// Returns the stable probe name.
    fn name(&self) -> &str;

    /// Runs one bounded, side-effect-safe health check.
    ///
    /// # Errors
    ///
    /// Returns a stable operational reason when the subsystem is not ready.
    fn check(&self) -> Result<(), OperationalError>;
}

/// One deterministic readiness result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeResult {
    name: String,
    reason: Option<OperationalError>,
}

impl ProbeResult {
    /// Returns the stable subsystem name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns `None` only for a successful probe.
    #[must_use]
    pub const fn reason(&self) -> Option<OperationalError> {
        self.reason
    }
}

/// Complete ordered startup readiness report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadinessReport {
    config_digest_hex: String,
    context_digest_hex: String,
    probes: Vec<ProbeResult>,
}

impl ReadinessReport {
    /// Reports whether every required subsystem is ready.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.probes.iter().all(|probe| probe.reason.is_none())
    }

    /// Returns the public configuration digest.
    #[must_use]
    pub fn config_digest_hex(&self) -> &str {
        &self.config_digest_hex
    }

    /// Returns the public verifier-context digest.
    #[must_use]
    pub fn context_digest_hex(&self) -> &str {
        &self.context_digest_hex
    }

    /// Returns probe results sorted by stable subsystem name.
    #[must_use]
    pub fn probes(&self) -> &[ProbeResult] {
        &self.probes
    }
}

/// Runs all required startup probes after configuration/context binding.
///
/// # Errors
///
/// Returns a configuration failure for duplicate, malformed, missing, or
/// excessive required probes. Individual probe failures remain in the report.
pub fn readiness(
    configuration: &BoundConfiguration,
    required: &[&str],
    probes: &[&dyn ReadinessProbe],
) -> Result<ReadinessReport, OperationalError> {
    if required.is_empty() || required.len() > MAX_PROBES || probes.len() > MAX_PROBES {
        return Err(OperationalError::InvalidConfiguration);
    }
    let required_count = required.len();
    let required = required
        .iter()
        .map(|name| validate_label(name).map(|()| (*name).to_owned()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if required.len() != required_count {
        return Err(OperationalError::InvalidConfiguration);
    }
    let mut implementations = BTreeMap::new();
    for probe in probes {
        validate_label(probe.name())?;
        if implementations.insert(probe.name(), *probe).is_some() {
            return Err(OperationalError::InvalidConfiguration);
        }
    }
    if required
        .iter()
        .any(|name| !implementations.contains_key(name.as_str()))
    {
        return Err(OperationalError::MissingProbe);
    }
    let results = required
        .into_iter()
        .map(|name| {
            let reason = implementations
                .get(name.as_str())
                .and_then(|probe| probe.check().err());
            ProbeResult { name, reason }
        })
        .collect();
    Ok(ReadinessReport {
        config_digest_hex: hex(configuration.config_digest().as_bytes()),
        context_digest_hex: hex(configuration.context_digest().as_bytes()),
        probes: results,
    })
}

/// Stable, low-cardinality runtime stage.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OperationalStage {
    /// Exchange message parsing and binding.
    Exchange,
    /// Pure Auths verification.
    Verification,
    /// Replay challenge claim.
    Replay,
    /// Stateful budget reservation.
    Budget,
    /// Profile decoding and local policy.
    Policy,
    /// Verified command execution.
    Execution,
    /// Receipt or audit persistence.
    Receipt,
}

/// Stable event outcome.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OperationalOutcome {
    /// Stage completed successfully.
    Succeeded,
    /// Stage rejected established input.
    Refused,
    /// Required operational state was unavailable.
    Unavailable,
    /// Authorized execution failed.
    Failed,
}

/// Privacy-preserving event with no subject or request payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalEvent {
    stage: OperationalStage,
    outcome: OperationalOutcome,
    reason: String,
    elapsed_micros: u64,
}

impl OperationalEvent {
    /// Constructs a bounded low-cardinality event.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for malformed or excessive reason labels.
    pub fn new(
        stage: OperationalStage,
        outcome: OperationalOutcome,
        reason: impl Into<String>,
        elapsed_micros: u64,
    ) -> Result<Self, OperationalError> {
        let reason = reason.into();
        validate_label(&reason)?;
        Ok(Self {
            stage,
            outcome,
            reason,
            elapsed_micros,
        })
    }

    /// Returns the runtime stage.
    #[must_use]
    pub const fn stage(&self) -> OperationalStage {
        self.stage
    }

    /// Returns the stage outcome.
    #[must_use]
    pub const fn outcome(&self) -> OperationalOutcome {
        self.outcome
    }

    /// Returns the stable reason dimension.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Returns bounded elapsed microseconds.
    #[must_use]
    pub const fn elapsed_micros(&self) -> u64 {
        self.elapsed_micros
    }
}

/// Sink for metrics, traces, or structured privacy-preserving logs.
pub trait EventSink: Send + Sync {
    /// Records one already-sanitized event.
    fn record(&self, event: &OperationalEvent);
}

/// Event sink for deployments that intentionally disable telemetry.
pub struct NoopEventSink;

impl EventSink for NoopEventSink {
    fn record(&self, _event: &OperationalEvent) {}
}

/// Low-cardinality stage, outcome, and stable reason dimensions.
pub type MetricKey = (OperationalStage, OperationalOutcome, String);
/// Invocation count and cumulative elapsed microseconds for one metric key.
pub type MetricAggregate = (u64, u64);
/// Canonically ordered snapshot entry.
pub type MetricSnapshotEntry = (MetricKey, MetricAggregate);

/// Deterministic in-memory low-cardinality metric collector.
#[derive(Default)]
pub struct InMemoryMetrics {
    state: Mutex<BTreeMap<MetricKey, MetricAggregate>>,
}

impl InMemoryMetrics {
    /// Returns counters and cumulative timings in canonical key order.
    #[must_use]
    pub fn snapshot(&self) -> Vec<MetricSnapshotEntry> {
        self.state.lock().map_or_else(
            |_| Vec::new(),
            |state| {
                state
                    .iter()
                    .map(|(key, value)| (key.clone(), *value))
                    .collect()
            },
        )
    }
}

impl EventSink for InMemoryMetrics {
    fn record(&self, event: &OperationalEvent) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let aggregate = state
            .entry((event.stage, event.outcome, event.reason.clone()))
            .or_default();
        aggregate.0 = aggregate.0.saturating_add(1);
        aggregate.1 = aggregate.1.saturating_add(event.elapsed_micros);
    }
}

fn validate_label(value: &str) -> Result<(), OperationalError> {
    if value.is_empty()
        || value.len() > MAX_LABEL_BYTES
        || value.bytes().any(|byte| {
            !(byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err(OperationalError::InvalidLabel);
    }
    Ok(())
}

fn hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

/// Stable operational/readiness failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationalError {
    /// Required probe list or collection bound is invalid.
    InvalidConfiguration,
    /// A stable diagnostic label is malformed.
    InvalidLabel,
    /// A required subsystem has no probe implementation.
    MissingProbe,
    /// Registry or trust-anchor initialization failed.
    RegistryUnavailable,
    /// Replay storage is unavailable.
    ReplayStoreUnavailable,
    /// Budget storage is unavailable.
    BudgetStoreUnavailable,
    /// Receipt storage is unavailable.
    ReceiptStoreUnavailable,
    /// Cryptographic self-test failed.
    CryptographicSelfTestFailed,
}

impl fmt::Display for OperationalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid readiness configuration",
            Self::InvalidLabel => "invalid operational diagnostic label",
            Self::MissingProbe => "required readiness probe is missing",
            Self::RegistryUnavailable => "registry or trust-anchor initialization failed",
            Self::ReplayStoreUnavailable => "replay store unavailable",
            Self::BudgetStoreUnavailable => "budget store unavailable",
            Self::ReceiptStoreUnavailable => "receipt store unavailable",
            Self::CryptographicSelfTestFailed => "cryptographic self-test failed",
        })
    }
}

impl std::error::Error for OperationalError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_expose_only_stable_dimensions() {
        let metrics = InMemoryMetrics::default();
        let event = OperationalEvent::new(
            OperationalStage::Verification,
            OperationalOutcome::Refused,
            "audience-mismatch",
            17,
        )
        .unwrap();
        metrics.record(&event);
        metrics.record(&event);
        assert_eq!(metrics.snapshot()[0].1, (2, 34));
    }
}
