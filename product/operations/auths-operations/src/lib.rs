//! Deterministic readiness and privacy-preserving operational diagnostics.
//!
//! Events contain only stable stages, outcomes, reasons, and timings. Proof
//! bytes, principals, resources, arguments, and private custody data are
//! deliberately absent.

#![forbid(unsafe_code)]

pub mod explanation;
pub mod render;

use auths_config::BoundConfiguration;
use auths_errors::{EffectState, RecommendedAction};
use auths_model::ProfileRef;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Mutex,
};

const MAX_PROBES: usize = 128;
const MAX_LABEL_BYTES: usize = 128;

pub const PRODUCTION_READINESS_PROBES: &[&str] = &[
    "configuration",
    "custody",
    "lifecycle-store",
    "profiles",
    "receipt-store",
    "recovery-store",
    "registries",
    "verifier-self-test",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LivenessStatus {
    Alive,
}

#[must_use]
pub const fn liveness() -> LivenessStatus {
    LivenessStatus::Alive
}

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
    required_configuration_hex: String,
    executed_configuration_hex: String,
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

    /// Returns the verifier configuration demanded by the trusted context.
    #[must_use]
    pub fn required_configuration_hex(&self) -> &str {
        &self.required_configuration_hex
    }

    /// Returns the verifier configuration installed by this process.
    #[must_use]
    pub fn executed_configuration_hex(&self) -> &str {
        &self.executed_configuration_hex
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
        required_configuration_hex: hex(configuration.required_configuration().as_bytes()),
        executed_configuration_hex: hex(configuration.executed_configuration().as_bytes()),
        probes: results,
    })
}

pub const OPERATIONS_SEMANTIC_ID: &str = "auths.operations/2";

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BuildSemanticId(String);

impl BuildSemanticId {
    pub fn parse(value: &str) -> Result<Self, OperationalError> {
        validate_label(value)?;
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OperationalStage {
    Acquisition,
    Verification,
    Policy,
    DecisionPersistence,
    Reservation,
    ExecutionIntent,
    Credential,
    ProviderEntry,
    ProviderResult,
    Observation,
    Reconciliation,
    Receipt,
    Recovery,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OperationalOutcome {
    Succeeded,
    Denied,
    Indeterminate,
    Conflict,
    Saturated,
    Unavailable,
    Failed,
    OutcomeUnknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OperationalReasonCode {
    None,
    Authorized,
    Denied,
    EvidenceUnavailable,
    ConfigurationMismatch,
    StoreConflict,
    StoreUnavailable,
    CustodyDenied,
    CustodyUnavailable,
    ProviderFailed,
    ProviderUnknown,
    ReceiptUnavailable,
    RecoveryPending,
    Recovered,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LatencyBucket {
    UnderOneMillisecond,
    UnderTenMilliseconds,
    UnderOneHundredMilliseconds,
    UnderOneSecond,
    UnderTenSeconds,
    TenSecondsOrMore,
}

impl LatencyBucket {
    #[must_use]
    pub const fn from_micros(value: u64) -> Self {
        match value {
            0..=999 => Self::UnderOneMillisecond,
            1_000..=9_999 => Self::UnderTenMilliseconds,
            10_000..=99_999 => Self::UnderOneHundredMilliseconds,
            100_000..=999_999 => Self::UnderOneSecond,
            1_000_000..=9_999_999 => Self::UnderTenSeconds,
            _ => Self::TenSecondsOrMore,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OperationalSubsystem {
    Runtime,
    Store,
    Custody,
    Provider,
    Observer,
    Receipt,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SaturationBucket {
    UnderHalf,
    HalfToThreeQuarters,
    ThreeQuartersToNineTenths,
    OverNineTenths,
    Full,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DeploymentClass {
    Development,
    CustomerOperated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalEventV2 {
    build: BuildSemanticId,
    profile: Option<ProfileRef>,
    stage: OperationalStage,
    outcome: OperationalOutcome,
    reason: OperationalReasonCode,
    elapsed: LatencyBucket,
    subsystem: OperationalSubsystem,
    saturation: Option<SaturationBucket>,
    deployment: DeploymentClass,
}

impl OperationalEventV2 {
    pub fn new(
        build: BuildSemanticId,
        profile: Option<ProfileRef>,
        stage: OperationalStage,
        outcome: OperationalOutcome,
        reason: OperationalReasonCode,
        elapsed: LatencyBucket,
        subsystem: OperationalSubsystem,
        saturation: Option<SaturationBucket>,
        deployment: DeploymentClass,
    ) -> Self {
        Self {
            build,
            profile,
            stage,
            outcome,
            reason,
            elapsed,
            subsystem,
            saturation,
            deployment,
        }
    }

    #[must_use]
    pub fn runtime(
        profile: Option<ProfileRef>,
        stage: OperationalStage,
        outcome: OperationalOutcome,
        reason: OperationalReasonCode,
        elapsed_micros: u64,
    ) -> Self {
        Self::new(
            BuildSemanticId("auths-runtime-1".to_owned()),
            profile,
            stage,
            outcome,
            reason,
            LatencyBucket::from_micros(elapsed_micros),
            OperationalSubsystem::Runtime,
            None,
            DeploymentClass::CustomerOperated,
        )
    }

    #[must_use]
    pub const fn build(&self) -> &BuildSemanticId {
        &self.build
    }

    #[must_use]
    pub const fn profile(&self) -> Option<&ProfileRef> {
        self.profile.as_ref()
    }

    #[must_use]
    pub const fn stage(&self) -> OperationalStage {
        self.stage
    }

    #[must_use]
    pub const fn outcome(&self) -> OperationalOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn reason(&self) -> OperationalReasonCode {
        self.reason
    }

    #[must_use]
    pub const fn elapsed(&self) -> LatencyBucket {
        self.elapsed
    }

    #[must_use]
    pub const fn subsystem(&self) -> OperationalSubsystem {
        self.subsystem
    }

    #[must_use]
    pub const fn saturation(&self) -> Option<SaturationBucket> {
        self.saturation
    }

    #[must_use]
    pub const fn deployment(&self) -> DeploymentClass {
        self.deployment
    }
}

pub trait EventSink: Send + Sync {
    fn record(&self, event: &OperationalEventV2);
}

/// Event sink for deployments that intentionally disable telemetry.
pub struct NoopEventSink;

impl EventSink for NoopEventSink {
    fn record(&self, _event: &OperationalEventV2) {}
}

pub type MetricKey = (
    OperationalStage,
    OperationalOutcome,
    OperationalReasonCode,
    OperationalSubsystem,
    LatencyBucket,
    DeploymentClass,
);
pub type MetricAggregate = u64;
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
    fn record(&self, event: &OperationalEventV2) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let aggregate = state
            .entry((
                event.stage,
                event.outcome,
                event.reason,
                event.subsystem,
                event.elapsed,
                event.deployment,
            ))
            .or_default();
        *aggregate = aggregate.saturating_add(1);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicWorkflowReference(String);

impl PublicWorkflowReference {
    pub fn parse(value: &str) -> Result<Self, OperationalError> {
        if !(16..=128).contains(&value.len())
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(OperationalError::InvalidReference);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicWorkflowStage {
    Received,
    Authorized,
    Reserved,
    ProviderPossible,
    Observing,
    Reconciling,
    Committed,
    Released,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationProjection {
    Pending,
    Authorized,
    Denied,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgeBucket {
    UnderOneMinute,
    UnderFiveMinutes,
    UnderOneHour,
    UnderOneDay,
    OneDayOrMore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DependencyHealth {
    Healthy,
    Degraded,
    Unavailable,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptDisclosureLocator(String);

impl ReceiptDisclosureLocator {
    pub fn parse(value: &str) -> Result<Self, OperationalError> {
        PublicWorkflowReference::parse(value)?;
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowStatusProjection {
    reference: PublicWorkflowReference,
    profile: ProfileRef,
    stage: PublicWorkflowStage,
    authorization: AuthorizationProjection,
    effect: EffectState,
    recommended_action: RecommendedAction,
    age: AgeBucket,
    observer: DependencyHealth,
    receipt: Option<ReceiptDisclosureLocator>,
}

impl WorkflowStatusProjection {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        reference: PublicWorkflowReference,
        profile: ProfileRef,
        stage: PublicWorkflowStage,
        authorization: AuthorizationProjection,
        effect: EffectState,
        recommended_action: RecommendedAction,
        age: AgeBucket,
        observer: DependencyHealth,
        receipt: Option<ReceiptDisclosureLocator>,
    ) -> Self {
        Self {
            reference,
            profile,
            stage,
            authorization,
            effect,
            recommended_action,
            age,
            observer,
            receipt,
        }
    }

    #[must_use]
    pub const fn reference(&self) -> &PublicWorkflowReference {
        &self.reference
    }

    #[must_use]
    pub const fn profile(&self) -> &ProfileRef {
        &self.profile
    }

    #[must_use]
    pub const fn stage(&self) -> PublicWorkflowStage {
        self.stage
    }

    #[must_use]
    pub const fn authorization(&self) -> AuthorizationProjection {
        self.authorization
    }

    #[must_use]
    pub const fn effect(&self) -> EffectState {
        self.effect
    }

    #[must_use]
    pub const fn recommended_action(&self) -> RecommendedAction {
        self.recommended_action
    }

    #[must_use]
    pub const fn age(&self) -> AgeBucket {
        self.age
    }

    #[must_use]
    pub const fn observer(&self) -> DependencyHealth {
        self.observer
    }

    #[must_use]
    pub const fn receipt(&self) -> Option<&ReceiptDisclosureLocator> {
        self.receipt.as_ref()
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
    InvalidReference,
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
    LifecycleStoreUnavailable,
    RecoveryStoreUnavailable,
    CustodyUnavailable,
    ProfileUnavailable,
    ExporterBackpressure,
    /// Cryptographic self-test failed.
    CryptographicSelfTestFailed,
}

impl fmt::Display for OperationalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "invalid readiness configuration",
            Self::InvalidLabel => "invalid operational diagnostic label",
            Self::InvalidReference => "invalid opaque workflow reference",
            Self::MissingProbe => "required readiness probe is missing",
            Self::RegistryUnavailable => "registry or trust-anchor initialization failed",
            Self::ReplayStoreUnavailable => "replay store unavailable",
            Self::BudgetStoreUnavailable => "budget store unavailable",
            Self::ReceiptStoreUnavailable => "receipt store unavailable",
            Self::LifecycleStoreUnavailable => "lifecycle store unavailable",
            Self::RecoveryStoreUnavailable => "recovery store unavailable",
            Self::CustodyUnavailable => "custody unavailable",
            Self::ProfileUnavailable => "profile registration unavailable",
            Self::ExporterBackpressure => "required audit exporter is saturated",
            Self::CryptographicSelfTestFailed => "cryptographic self-test failed",
        })
    }
}

impl std::error::Error for OperationalError {}

#[cfg(test)]
mod tests {
    use super::*;

    struct Ready;

    impl ReadinessProbe for Ready {
        fn name(&self) -> &'static str {
            "registry"
        }

        fn check(&self) -> Result<(), OperationalError> {
            Ok(())
        }
    }

    #[test]
    fn metrics_expose_only_stable_dimensions() {
        let metrics = InMemoryMetrics::default();
        let event = OperationalEventV2::new(
            BuildSemanticId::parse("build-1").unwrap(),
            None,
            OperationalStage::Verification,
            OperationalOutcome::Denied,
            OperationalReasonCode::Denied,
            LatencyBucket::UnderOneMillisecond,
            OperationalSubsystem::Runtime,
            None,
            DeploymentClass::CustomerOperated,
        );
        metrics.record(&event);
        metrics.record(&event);
        assert_eq!(metrics.snapshot()[0].1, 2);
    }

    #[test]
    fn readiness_exposes_required_and_executed_configuration_ids() {
        let context = auths_codec::decode_verifier_context(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../core/fixtures/v1/valid/raw-key-chain.context.cbor"
        )))
        .unwrap();
        let config = auths_config::AuthsConfig::from_toml(
            r#"
protocol = 1
profiles = [{ id = "auths.mcp", version = 1 }]
[runtime]
challenge_ttl_seconds = 30
max_body_bytes = 1048576
max_proof_bytes = 16777216
channel_policy = "none"
[stores]
replay_capacity = 4096
verification_cache_capacity = 1024
receipt_policy = "fail-closed"
"#,
        )
        .unwrap()
        .compile()
        .unwrap();
        let configuration = context.configuration();
        let bound = config.bind_context(&context, configuration).unwrap();
        let report = readiness(&bound, &["registry"], &[&Ready]).unwrap();
        let expected = hex(configuration.as_bytes());
        assert!(report.is_ready());
        assert_eq!(report.required_configuration_hex(), expected);
        assert_eq!(report.executed_configuration_hex(), expected);
    }

    #[test]
    fn privacy_registry_matches_the_closed_event_shape() {
        let registry: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../v2/field-registry.json"
        )))
        .unwrap();
        assert_eq!(registry["semanticId"], OPERATIONS_SEMANTIC_ID);
        assert_eq!(registry["eventFields"].as_array().unwrap().len(), 9);
        let encoded = serde_json::to_string(&registry).unwrap();
        for value in ["private-key", "raw-proof", "customer-id", "workflow-id"] {
            assert!(!encoded.contains(value));
        }
    }

    #[test]
    fn workflow_references_are_opaque_and_bounded() {
        assert!(PublicWorkflowReference::parse("A9_xxxxxxxxxxxxxx").is_ok());
        for invalid in ["short", "workflow:123456789", "../../database-row"] {
            assert!(PublicWorkflowReference::parse(invalid).is_err());
        }
    }
}
