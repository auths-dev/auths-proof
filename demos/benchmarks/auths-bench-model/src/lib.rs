//! Reproducible benchmark scenarios, artifacts, and statistics.

#![forbid(unsafe_code)]

use auths_codec::encode_canonical_action;
use auths_testkit::{CorpusFixture, Expected};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Version of deterministic benchmark generation.
pub const GENERATOR_VERSION: u16 = 1;

/// Closed benchmark scenario family.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScenarioFamily {
    Baseline,
    ProofSize,
    GrantChain,
    PlanShape,
    LimitBoundary,
}

/// Closed target V1 principal-method family.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrincipalFamily {
    RawKey,
    DidKey,
    DidKeri,
    DidWeb,
    WebAuthn,
    HsmAttested,
    SpiffeX509,
}

/// Closed signature family.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureFamily {
    Ed25519,
    P256Sha256,
}

/// Closed plan shape.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PlanShape {
    Single,
    AllOf { leaves: u16 },
    AnyOf { leaves: u16, authorized_at: u16 },
    Threshold { k: u16, leaves: u16 },
    Balanced { depth: u16, branching: u16 },
    LeftDeep { depth: u16 },
}

/// Position relative to a target V1 deployment limit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "position", rename_all = "kebab-case")]
pub enum LimitPosition {
    Nominal,
    Below { kind: String, delta: u64 },
    Exact { kind: String },
    Above { kind: String, delta: u64 },
}

/// Exact portable semantic oracle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExpectedResult {
    pub decision: String,
    pub code: String,
}

/// Versioned deterministic scenario.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BenchmarkScenario {
    pub schema: u16,
    pub id: String,
    pub family: ScenarioFamily,
    pub principal: PrincipalFamily,
    pub suite: SignatureFamily,
    pub proof_target_bytes: Option<usize>,
    pub grant_depth: u16,
    pub plan: PlanShape,
    pub evidence_target_bytes: Option<usize>,
    pub limit_position: LimitPosition,
    pub expected: ExpectedResult,
    pub seed: [u8; 32],
}

/// Portable benchmark input shared byte-for-byte by every runner.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BenchmarkInput {
    pub scenario: BenchmarkScenario,
    pub proof_cbor: Vec<u8>,
    pub canonical_action_cbor: Vec<u8>,
    pub trusted_context_cbor: Vec<u8>,
    pub adapter_context: Vec<u8>,
    pub input_digest: [u8; 32],
}

/// Developer or publication run profile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BenchmarkProfile {
    pub name: String,
    pub warmup_ms: u64,
    pub samples: usize,
    pub operations_per_sample: usize,
}

impl BenchmarkProfile {
    /// Fast local profile.
    #[must_use]
    pub fn developer() -> Self {
        Self {
            name: "developer".to_owned(),
            warmup_ms: 50,
            samples: 10,
            operations_per_sample: 1,
        }
    }

    /// Publication profile mandated by AP-SPEC-003.
    #[must_use]
    pub fn paper() -> Self {
        Self {
            name: "paper".to_owned(),
            warmup_ms: 3_000,
            samples: 100,
            operations_per_sample: 10,
        }
    }
}

/// Semantic and size record captured outside timing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SemanticRecord {
    pub decision: String,
    pub code: String,
    pub result_sha256: String,
    pub work_units: u64,
    pub proof_bytes: u64,
    pub context_bytes: u64,
    pub plan_leaves: u64,
    pub plan_depth: u64,
}

/// Complete environment metadata. Unknown values are explicit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Environment {
    pub os: String,
    pub arch: String,
    pub cpu: String,
    pub logical_cores: usize,
    pub memory_bytes: u64,
    pub runtime: String,
    pub runtime_version: String,
    pub rustc: String,
    pub power_mode: String,
    pub virtualized: String,
}

/// Robust summary derived from raw observations.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Statistics {
    pub count: usize,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub mean_ns: f64,
    pub stddev_ns: f64,
    pub median_ci95_ns: [u64; 2],
}

/// One scenario result.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BenchmarkResult {
    pub schema: String,
    pub revision: String,
    pub dirty: bool,
    pub target: String,
    pub environment: Environment,
    pub scenario: String,
    pub input_sha256: String,
    pub semantic: SemanticRecord,
    pub samples_ns: Vec<u64>,
    pub summary: Statistics,
}

/// Complete run artifact.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RunArtifact {
    pub schema: String,
    pub profile: BenchmarkProfile,
    pub results: Vec<BenchmarkResult>,
}

/// Per-scenario revision comparison.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Comparison {
    pub scenario: String,
    pub ratio: f64,
    pub regression: bool,
}

/// Comparison policy.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
pub struct ComparisonPolicy {
    pub regression_ratio: f64,
}

impl Default for ComparisonPolicy {
    fn default() -> Self {
        Self {
            regression_ratio: 1.10,
        }
    }
}

/// Benchmark model failure.
#[derive(Debug)]
pub enum BenchmarkError {
    Codec(String),
    InvalidScenario(String),
    SemanticDrift(String),
    Incomparable(String),
}

impl core::fmt::Display for BenchmarkError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Codec(message)
            | Self::InvalidScenario(message)
            | Self::SemanticDrift(message)
            | Self::Incomparable(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for BenchmarkError {}

fn expected(fixture: &CorpusFixture) -> ExpectedResult {
    match fixture.expected() {
        Expected::Authorized => ExpectedResult {
            decision: "authorized".to_owned(),
            code: "authorized".to_owned(),
        },
        Expected::Denied(reason) => ExpectedResult {
            decision: "denied".to_owned(),
            code: reason.code().to_owned(),
        },
        Expected::Indeterminate(requirement) => ExpectedResult {
            decision: "indeterminate".to_owned(),
            code: requirement.code().to_owned(),
        },
    }
}

fn make_input(
    id: &str,
    family: ScenarioFamily,
    principal: PrincipalFamily,
    suite: SignatureFamily,
    grant_depth: u16,
    plan: PlanShape,
    limit_position: LimitPosition,
    fixture: CorpusFixture,
) -> Result<BenchmarkInput, BenchmarkError> {
    let scenario = BenchmarkScenario {
        schema: GENERATOR_VERSION,
        id: id.to_owned(),
        family,
        principal,
        suite,
        proof_target_bytes: Some(fixture.proof_bytes().len()),
        grant_depth,
        plan,
        evidence_target_bytes: None,
        limit_position,
        expected: expected(&fixture),
        seed: Sha256::digest(id.as_bytes()).into(),
    };
    let canonical_action_cbor = encode_canonical_action(fixture.canonical_action())
        .map_err(|error| BenchmarkError::Codec(error.to_string()))?;
    let adapter_context = auths_testkit::corpus_configuration_id().as_bytes().to_vec();
    let mut input = BenchmarkInput {
        scenario,
        proof_cbor: fixture.proof_bytes().to_vec(),
        canonical_action_cbor,
        trusted_context_cbor: fixture.context_bytes().to_vec(),
        adapter_context,
        input_digest: [0; 32],
    };
    input.input_digest = compute_input_digest(&input)?;
    Ok(input)
}

/// Generates the controlled target V1 scenario suite.
///
/// # Errors
///
/// Returns a typed error if a canonical fixture cannot be encoded.
pub fn generate_suite(_profile: &BenchmarkProfile) -> Result<Vec<BenchmarkInput>, BenchmarkError> {
    use auths_testkit as fixtures;
    let mut suite = vec![
        make_input(
            "baseline/raw-key/ed25519",
            ScenarioFamily::Baseline,
            PrincipalFamily::RawKey,
            SignatureFamily::Ed25519,
            1,
            PlanShape::Single,
            LimitPosition::Nominal,
            fixtures::raw_key_chain(),
        )?,
        make_input(
            "baseline/did-key/ed25519",
            ScenarioFamily::Baseline,
            PrincipalFamily::DidKey,
            SignatureFamily::Ed25519,
            1,
            PlanShape::Single,
            LimitPosition::Nominal,
            fixtures::did_key_root_raw_key_actor(),
        )?,
        make_input(
            "baseline/did-keri/ed25519",
            ScenarioFamily::Baseline,
            PrincipalFamily::DidKeri,
            SignatureFamily::Ed25519,
            1,
            PlanShape::Single,
            LimitPosition::Nominal,
            fixtures::did_keri_root_raw_key_actor(),
        )?,
        make_input(
            "baseline/did-web/ed25519",
            ScenarioFamily::Baseline,
            PrincipalFamily::DidWeb,
            SignatureFamily::Ed25519,
            1,
            PlanShape::Single,
            LimitPosition::Nominal,
            fixtures::did_web_root_raw_key_actor(),
        )?,
        make_input(
            "baseline/webauthn/p256",
            ScenarioFamily::Baseline,
            PrincipalFamily::WebAuthn,
            SignatureFamily::P256Sha256,
            1,
            PlanShape::Single,
            LimitPosition::Nominal,
            fixtures::webauthn_root_raw_key_actor(),
        )?,
        make_input(
            "baseline/hsm-attested/ed25519",
            ScenarioFamily::Baseline,
            PrincipalFamily::HsmAttested,
            SignatureFamily::Ed25519,
            1,
            PlanShape::Single,
            LimitPosition::Nominal,
            fixtures::hsm_root_raw_key_actor(),
        )?,
        make_input(
            "baseline/spiffe-x509/p256",
            ScenarioFamily::Baseline,
            PrincipalFamily::SpiffeX509,
            SignatureFamily::P256Sha256,
            1,
            PlanShape::Single,
            LimitPosition::Nominal,
            fixtures::spiffe_root_raw_key_actor(),
        )?,
        make_input(
            "plan/all-of/two",
            ScenarioFamily::PlanShape,
            PrincipalFamily::RawKey,
            SignatureFamily::Ed25519,
            1,
            PlanShape::AllOf { leaves: 2 },
            LimitPosition::Nominal,
            fixtures::all_of(),
        )?,
        make_input(
            "plan/threshold/two-of-three",
            ScenarioFamily::PlanShape,
            PrincipalFamily::RawKey,
            SignatureFamily::Ed25519,
            1,
            PlanShape::Threshold { k: 2, leaves: 3 },
            LimitPosition::Nominal,
            fixtures::threshold(),
        )?,
        make_input(
            "limit/work/above",
            ScenarioFamily::LimitBoundary,
            PrincipalFamily::RawKey,
            SignatureFamily::Ed25519,
            1,
            PlanShape::Single,
            LimitPosition::Above {
                kind: "work-units".to_owned(),
                delta: 1,
            },
            fixtures::verification_work_limit_exceeded(),
        )?,
    ];
    suite.sort_by(|left, right| left.scenario.id.cmp(&right.scenario.id));
    Ok(suite)
}

/// Computes the domain-separated input commitment.
///
/// # Errors
///
/// Returns a serialization error for an invalid scenario.
pub fn compute_input_digest(input: &BenchmarkInput) -> Result<[u8; 32], BenchmarkError> {
    let scenario = serde_json::to_vec(&input.scenario)
        .map_err(|error| BenchmarkError::InvalidScenario(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(b"AUTHS-BENCH-INPUT\0\x01");
    for bytes in [
        scenario.as_slice(),
        input.proof_cbor.as_slice(),
        input.canonical_action_cbor.as_slice(),
        input.trusted_context_cbor.as_slice(),
        input.adapter_context.as_slice(),
    ] {
        hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(bytes);
    }
    Ok(hasher.finalize().into())
}

/// Computes deterministic summary statistics and a conservative median interval.
#[must_use]
pub fn statistics(samples: &[u64]) -> Statistics {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let count = sorted.len();
    let percentile = |numerator: usize| -> u64 {
        if count == 0 {
            return 0;
        }
        let index = ((count - 1) * numerator).div_ceil(100);
        sorted[index.min(count - 1)]
    };
    let mean = if count == 0 {
        0.0
    } else {
        sorted.iter().map(|value| *value as f64).sum::<f64>() / count as f64
    };
    let variance = if count < 2 {
        0.0
    } else {
        sorted
            .iter()
            .map(|value| {
                let difference = *value as f64 - mean;
                difference * difference
            })
            .sum::<f64>()
            / (count - 1) as f64
    };
    Statistics {
        count,
        p50_ns: percentile(50),
        p95_ns: percentile(95),
        p99_ns: percentile(99),
        mean_ns: mean,
        stddev_ns: variance.sqrt(),
        median_ci95_ns: [percentile(40), percentile(60)],
    }
}

/// Validates input identity and exact semantic preflight/postflight.
///
/// # Errors
///
/// Returns [`BenchmarkError::SemanticDrift`] for any mismatch.
pub fn validate_result(
    input: &BenchmarkInput,
    result: &BenchmarkResult,
) -> Result<(), BenchmarkError> {
    if compute_input_digest(input)? != input.input_digest
        || result.input_sha256 != hex_digest(input.input_digest)
        || result.semantic.decision != input.scenario.expected.decision
        || result.semantic.code != input.scenario.expected.code
        || result.samples_ns.is_empty()
    {
        return Err(BenchmarkError::SemanticDrift(input.scenario.id.clone()));
    }
    Ok(())
}

/// Compares two runs by identical scenario and input digest.
///
/// # Errors
///
/// Returns an incomparable error when scenario inventories or inputs differ.
pub fn compare_runs(
    baseline: &RunArtifact,
    candidate: &RunArtifact,
    policy: &ComparisonPolicy,
) -> Result<Vec<Comparison>, BenchmarkError> {
    if baseline.results.len() != candidate.results.len() {
        return Err(BenchmarkError::Incomparable(
            "scenario counts differ".to_owned(),
        ));
    }
    baseline
        .results
        .iter()
        .zip(&candidate.results)
        .map(|(before, after)| {
            if before.scenario != after.scenario
                || before.input_sha256 != after.input_sha256
                || before.target != after.target
            {
                return Err(BenchmarkError::Incomparable(before.scenario.clone()));
            }
            let ratio = after.summary.p50_ns as f64 / before.summary.p50_ns.max(1) as f64;
            let separated = after.summary.median_ci95_ns[0] > before.summary.median_ci95_ns[1];
            Ok(Comparison {
                scenario: before.scenario.clone(),
                ratio,
                regression: ratio >= policy.regression_ratio && separated,
            })
        })
        .collect()
}

/// Lowercase hexadecimal digest.
#[must_use]
pub fn hex_digest(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_byte_identical() {
        let profile = BenchmarkProfile::developer();
        let first = serde_json::to_vec(&generate_suite(&profile).unwrap()).unwrap();
        let second = serde_json::to_vec(&generate_suite(&profile).unwrap()).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn statistics_preserve_raw_quantiles() {
        let summary = statistics(&[50, 10, 40, 20, 30]);
        assert_eq!(summary.p50_ns, 30);
        assert_eq!(summary.p95_ns, 50);
        assert_eq!(summary.count, 5);
    }
}
