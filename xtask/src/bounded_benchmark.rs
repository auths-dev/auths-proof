#![allow(
    clippy::too_many_lines,
    reason = "the closed seven-domain benchmark inventory stays visible in one tooling module"
)]

use crate::*;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    hint::black_box,
    process::Command,
    time::{Duration, Instant},
};

const DOMAINS: [&str; 7] = [
    "github",
    "kubernetes",
    "opentofu",
    "postgresql",
    "radicle",
    "records-api",
    "stripe",
];

#[derive(Serialize)]
struct BoundedBenchmarkArtifact {
    schema: &'static str,
    revision: String,
    dirty: bool,
    fixture_manifest_sha256: String,
    profile: BoundedBenchmarkProfile,
    environment: BoundedBenchmarkEnvironment,
    results: Vec<BoundedBenchmarkResult>,
}

#[derive(Clone, Copy, Serialize)]
struct BoundedBenchmarkProfile {
    warmup_ms: u64,
    samples: usize,
    operations_per_sample: usize,
}

#[derive(Serialize)]
struct BoundedBenchmarkEnvironment {
    os: &'static str,
    arch: &'static str,
    optimized: bool,
    logical_cores: usize,
    rustc: String,
}

#[derive(Serialize)]
struct BoundedBenchmarkResult {
    domain: &'static str,
    scenario: &'static str,
    fixture_manifest_sha256: String,
    decision_sha256: String,
    samples_ns: Vec<u64>,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
}

pub(crate) fn run_bounded_benchmark(
    profile: &auths_bench_model::BenchmarkProfile,
) -> Result<(), String> {
    if cfg!(debug_assertions) {
        return Err("bounded benchmarks require an optimized harness; run \
             `cargo run --release -p xtask -- bench bounded --profile <profile>`"
            .to_owned());
    }
    let profile = BoundedBenchmarkProfile {
        warmup_ms: profile.warmup_ms.max(100),
        samples: profile.samples.max(20),
        operations_per_sample: profile.operations_per_sample.max(100),
    };
    let artifact = benchmark_artifact(profile)?;
    let output = root().join("benchmark-results/bounded-native.json");
    fs::write(
        &output,
        serde_json::to_vec_pretty(&artifact)
            .map_err(|error| format!("could not encode bounded benchmark: {error}"))?,
    )
    .map_err(|error| format!("could not write {}: {error}", output.display()))?;
    println!(
        "Bounded fixture SHA-256: {}",
        artifact.fixture_manifest_sha256
    );
    println!("Bounded benchmark revision: {}", artifact.revision);
    println!("Bounded benchmark artifact: {}", output.display());
    Ok(())
}

fn benchmark_artifact(
    profile: BoundedBenchmarkProfile,
) -> Result<BoundedBenchmarkArtifact, String> {
    let manifests = fixture_manifests()?;
    let mut results = Vec::with_capacity(8);

    {
        use auths_stripe::{
            AggregateBudgetSnapshot, BoundedEvaluationContext, RefundDenominator,
            evaluate_bounded_refund,
            test_support::{
                NOW, bounded_action, bounded_configuration, bounded_policy, configuration, evidence,
            },
        };
        let exact_configuration = configuration(2_000);
        let evidence = evidence(10_000, 0);
        let policy = bounded_policy(
            &evidence,
            2_000,
            10_000,
            RefundDenominator::OriginalChargeAmount,
            5_000,
        );
        let bounded_configuration = bounded_configuration(&policy);
        let action = bounded_action(
            &exact_configuration,
            &policy,
            &evidence,
            2_000,
            "stripe-bounded-oracle",
        );
        let snapshot = AggregateBudgetSnapshot::default();
        results.push(measure(
            "stripe",
            "authorized-refund",
            manifest(&manifests, "stripe")?,
            oracle("stripe", "authorized-decision.json")?,
            profile,
            || {
                evaluate_bounded_refund(&BoundedEvaluationContext {
                    policy: &policy,
                    action: &action,
                    evidence: &evidence,
                    aggregate_snapshot: &snapshot,
                    required_exact_configuration: &exact_configuration,
                    executed_exact_configuration: &exact_configuration,
                    required_bounded_configuration: &bounded_configuration,
                    executed_bounded_configuration: &bounded_configuration,
                    request_audience: exact_configuration.executor_audience(),
                    now: NOW,
                })
            },
        )?);
    }

    {
        let fixture = auths_kubernetes::test_support::fixture();
        results.push(measure(
            "kubernetes",
            "authorized-rollout",
            manifest(&manifests, "kubernetes")?,
            oracle("kubernetes", "authorized-decision.json")?,
            profile,
            || {
                auths_kubernetes::evaluate(&auths_kubernetes::EvaluationContext {
                    action: &fixture.action,
                    evidence: &fixture.evidence,
                    required_configuration: &fixture.configuration,
                    executed_configuration: &fixture.configuration,
                    request_audience: fixture.configuration.executor_audience(),
                    now: fixture.now,
                })
            },
        )?);
    }

    {
        let fixture = auths_postgresql::test_support::fixture();
        results.push(measure(
            "postgresql",
            "authorized-update",
            manifest(&manifests, "postgresql")?,
            oracle("postgresql", "authorized-decision.json")?,
            profile,
            || auths_postgresql::evaluate(&fixture.context()),
        )?);
    }

    {
        use auths_opentofu::{EvaluationContext, evaluate};
        let fixture = auths_opentofu::test_support::fixture();
        results.push(measure(
            "opentofu",
            "authorized-saved-plan",
            manifest(&manifests, "opentofu")?,
            oracle("opentofu", "authorized-decision.json")?,
            profile,
            || {
                evaluate(&EvaluationContext {
                    action: &fixture.action,
                    projection: &fixture.projection,
                    evidence: &fixture.evidence,
                    required_configuration: &fixture.configuration,
                    executed_configuration: &fixture.configuration,
                    request_audience: fixture.configuration.executor_audience(),
                    now: auths_opentofu::test_support::NOW,
                })
            },
        )?);
    }

    {
        use auths_github::{
            EvaluationContext, ExactGitHubAction, derive_publish_branch_action, evaluate,
        };
        let fixture = auths_github::test_support::fixture();
        let action = ExactGitHubAction::PublishBranch(
            derive_publish_branch_action(&fixture.grant, &fixture.configuration, &fixture.evidence)
                .map_err(|error| format!("could not derive GitHub benchmark action: {error}"))?,
        );
        results.push(measure(
            "github",
            "authorized-publish",
            manifest(&manifests, "github")?,
            oracle("github", "authorized-decision.json")?,
            profile,
            || {
                evaluate(&EvaluationContext {
                    grant: &fixture.grant,
                    action: &action,
                    candidate: &fixture.candidate,
                    evidence: &fixture.evidence,
                    required_configuration: &fixture.configuration,
                    executed_configuration: &fixture.configuration,
                    request_audience: fixture.configuration.executor_audience().as_str(),
                    now: auths_github::test_support::NOW,
                })
            },
        )?);
    }

    {
        use auths_radicle::{EvaluationContext, evaluate, test_support};
        let configuration = test_support::configuration(30);
        let grant = test_support::grant(configuration.clone());
        let submission = test_support::submission();
        let candidate = test_support::candidate(&submission);
        let evidence = test_support::evidence(&grant, test_support::NOW);
        let action =
            test_support::action(&grant, &configuration, &submission, &candidate, &evidence);
        results.push(measure(
            "radicle",
            "authorized-open-patch",
            manifest(&manifests, "radicle")?,
            oracle("radicle", "authorized-decision.json")?,
            profile,
            || {
                evaluate(&EvaluationContext {
                    grant: &grant,
                    action: &action,
                    submission: &submission,
                    candidate: &candidate,
                    evidence: &evidence,
                    required_configuration: &configuration,
                    executed_configuration: &configuration,
                    request_audience: configuration.executor_audience().as_str(),
                    now: test_support::NOW,
                })
            },
        )?);
    }

    {
        use auths_records_api::{
            BoundedRecordApiPolicyV1, CreateEvaluation, CreateRecordV1,
            RecordsApiVerifierConfigurationV1, evaluate_create,
        };
        let action: CreateRecordV1 = fixture("records-api", "create-action.json")?;
        let policy: BoundedRecordApiPolicyV1 = fixture("records-api", "policy.json")?;
        let configuration: RecordsApiVerifierConfigurationV1 =
            fixture("records-api", "configuration.json")?;
        results.push(measure(
            "records-api",
            "authorized-create",
            manifest(&manifests, "records-api")?,
            oracle("records-api", "create-authorized-decision.json")?,
            profile,
            || {
                evaluate_create(&CreateEvaluation {
                    action: &action,
                    policy: &policy,
                    required_configuration: &configuration,
                    executed_configuration: &configuration,
                    now: 200,
                })
            },
        )?);
    }

    {
        use auths_records_api::{
            BoundedRecordApiPolicyV1, ReadEvaluation, ReadRecordV1,
            RecordsApiVerifierConfigurationV1, evaluate_read,
        };
        let action: ReadRecordV1 = fixture("records-api", "read-action.json")?;
        let policy: BoundedRecordApiPolicyV1 = fixture("records-api", "policy.json")?;
        let configuration: RecordsApiVerifierConfigurationV1 =
            fixture("records-api", "configuration.json")?;
        results.push(measure(
            "records-api",
            "authorized-read",
            manifest(&manifests, "records-api")?,
            oracle("records-api", "read-authorized-decision.json")?,
            profile,
            || {
                evaluate_read(&ReadEvaluation {
                    action: &action,
                    policy: &policy,
                    required_configuration: &configuration,
                    executed_configuration: &configuration,
                    now: 200,
                })
            },
        )?);
    }

    results.sort_by(|left, right| {
        left.domain
            .cmp(right.domain)
            .then(left.scenario.cmp(right.scenario))
    });
    Ok(BoundedBenchmarkArtifact {
        schema: "auths-bounded-benchmark-run/1",
        revision: git_output(&["rev-parse", "HEAD"])?,
        dirty: !git_output(&["status", "--porcelain", "--untracked-files=no"])?.is_empty(),
        fixture_manifest_sha256: aggregate_manifest_digest(&manifests),
        profile,
        environment: BoundedBenchmarkEnvironment {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            optimized: !cfg!(debug_assertions),
            logical_cores: std::thread::available_parallelism().map_or(0, usize::from),
            rustc: command_output("rustc", &["--version"])?,
        },
        results,
    })
}

fn measure<R, F>(
    domain: &'static str,
    scenario: &'static str,
    manifest_sha256: String,
    expected: serde_json::Value,
    profile: BoundedBenchmarkProfile,
    mut evaluate: F,
) -> Result<BoundedBenchmarkResult, String>
where
    R: Serialize,
    F: FnMut() -> R,
{
    let preflight =
        serde_json::to_value(evaluate()).map_err(|error| format!("{domain}: {error}"))?;
    if preflight != expected {
        return Err(format!(
            "{domain}/{scenario} differs from its frozen decision oracle: actual={preflight} expected={expected}"
        ));
    }
    let warmup = Instant::now();
    while warmup.elapsed() < Duration::from_millis(profile.warmup_ms) {
        black_box(evaluate());
    }
    let mut samples = Vec::with_capacity(profile.samples);
    for _ in 0..profile.samples {
        let started = Instant::now();
        for _ in 0..profile.operations_per_sample {
            black_box(evaluate());
        }
        let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        samples.push(
            elapsed
                / u64::try_from(profile.operations_per_sample)
                    .unwrap_or(u64::MAX)
                    .max(1),
        );
    }
    let postflight =
        serde_json::to_value(evaluate()).map_err(|error| format!("{domain}: {error}"))?;
    if postflight != preflight {
        return Err(format!("{domain}/{scenario} changed after measurement"));
    }
    let mut sorted = samples.clone();
    sorted.sort_unstable();
    Ok(BoundedBenchmarkResult {
        domain,
        scenario,
        fixture_manifest_sha256: manifest_sha256,
        decision_sha256: sha256_hex(
            &serde_json::to_vec(&preflight).map_err(|error| error.to_string())?,
        ),
        p50_ns: percentile(&sorted, 50),
        p95_ns: percentile(&sorted, 95),
        p99_ns: percentile(&sorted, 99),
        samples_ns: samples,
    })
}

fn percentile(sorted: &[u64], numerator: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() - 1) * numerator).div_ceil(100);
    sorted[index.min(sorted.len() - 1)]
}

fn fixture_manifests() -> Result<BTreeMap<&'static str, Vec<u8>>, String> {
    DOMAINS
        .into_iter()
        .map(|domain| {
            let path = root()
                .join("product/fixtures/v1")
                .join(domain)
                .join("manifest.json");
            fs::read(&path)
                .map(|bytes| (domain, bytes))
                .map_err(|error| format!("could not read {}: {error}", path.display()))
        })
        .collect()
}

fn manifest(manifests: &BTreeMap<&str, Vec<u8>>, domain: &str) -> Result<String, String> {
    manifests
        .get(domain)
        .map(|bytes| sha256_hex(bytes))
        .ok_or_else(|| format!("missing fixture manifest for {domain}"))
}

fn aggregate_manifest_digest(manifests: &BTreeMap<&str, Vec<u8>>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"AUTHS-BOUNDED-BENCHMARK-FIXTURES\0\x01");
    for (domain, bytes) in manifests {
        hasher.update(
            u64::try_from(domain.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(domain.as_bytes());
        hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(bytes);
    }
    hex::encode(hasher.finalize())
}

fn fixture<T: serde::de::DeserializeOwned>(domain: &str, file: &str) -> Result<T, String> {
    let path = root().join("product/fixtures/v1").join(domain).join(file);
    serde_json::from_slice(
        &fs::read(&path).map_err(|error| format!("could not read {}: {error}", path.display()))?,
    )
    .map_err(|error| format!("invalid {}: {error}", path.display()))
}

fn oracle(domain: &str, file: &str) -> Result<serde_json::Value, String> {
    let value: serde_json::Value = fixture(domain, file)?;
    match (
        value.get("class"),
        value
            .get("decision")
            .filter(|decision| decision.get("class").is_some()),
    ) {
        (None, Some(decision)) => Ok(decision.clone()),
        _ => Ok(value),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn git_output(args: &[&str]) -> Result<String, String> {
    command_output("git", args)
}

fn command_output(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .current_dir(root())
        .output()
        .map_err(|error| format!("could not run {program}: {error}"))?;
    if !output.status.success() {
        return Err(format!("{program} failed with status {}", output.status));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("{program} output was not UTF-8: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_domain_fixtures_match_the_frozen_decision_oracles() {
        let artifact = benchmark_artifact(BoundedBenchmarkProfile {
            warmup_ms: 0,
            samples: 1,
            operations_per_sample: 1,
        })
        .unwrap();
        assert_eq!(artifact.results.len(), 8);
        assert!(artifact.results.iter().all(|result| result.p50_ns > 0));
    }
}
