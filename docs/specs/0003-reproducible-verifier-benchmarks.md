# AP-SPEC-003: Reproducible Native and WebAssembly Verifier Benchmarks

**Status:** Proposed
**Intended audience:** systems researchers, performance engineers, release
engineers, adapter authors, and operators sizing Auths-Proof deployments
**Normative language:** the terms **MUST**, **MUST NOT**, **SHOULD**, and
**MAY** define requirements for a result to be published as an Auths-Proof
benchmark
**Scope:** deterministic proof verification across proof size, graph shape,
principal method, signature suite, native and WebAssembly runtimes, and
resource/work-limit boundaries

## Abstract

This specification defines a benchmark methodology that produces comparable,
auditable Auths-Proof performance results without confusing a laptop timing
with a protocol guarantee. It replaces the current single-fixture browser
average with a versioned scenario model, pinned inputs, warm and cold
measurements, raw samples, environment disclosure, semantic checks, and
machine-readable result artifacts.

The benchmark suite measures:

- total portable verification;
- individual staged-verifier costs;
- scaling with proof and context bytes;
- chain and authorization-plan shape;
- all seven target principal methods;
- Ed25519 and P-256 where supported;
- native and WebAssembly execution;
- exact-limit success and limit-exceeded rejection;
- deterministic work-unit consumption independently of wall-clock time.

Every reported number is tied to exact input digests, verifier configuration,
toolchain, runtime, host metadata, and raw observations.

## 1. Current baseline

The repository already contains useful foundations:

| Existing component | Source |
| --- | --- |
| Browser-only raw-key microbenchmark | [`demos/benchmarks/auths-lab-wasm-bench/src/lib.rs`](../../demos/benchmarks/auths-lab-wasm-bench/src/lib.rs) |
| Factorial principal/suite/transport/profile model | [`demos/matrix/auths-lab-matrix/src/lib.rs`](../../demos/matrix/auths-lab-matrix/src/lib.rs) |
| Deterministic canonical fixtures | [`core/testkit/auths-testkit/src/lib.rs`](../../core/testkit/auths-testkit/src/lib.rs) |
| Portable result resource counters | [`core/crates/auths-model/src/lib.rs`](../../core/crates/auths-model/src/lib.rs), `VerificationResources` |
| Staged verifier API | [`core/crates/auths-verifier/src/lib.rs`](../../core/crates/auths-verifier/src/lib.rs), `decode_proof`, `resolve_proof`, `verify_principal_control`, `verify_authority`, and `bind_verified_action` |
| Native facade | [`core/crates/auths-proof/src/lib.rs`](../../core/crates/auths-proof/src/lib.rs) |
| WASM boundary | [`bindings/wasm/auths-proof-wasm/src/lib.rs`](../../bindings/wasm/auths-proof-wasm/src/lib.rs) |
| Benchmark build automation | [`xtask/src/main.rs`](../../xtask/src/main.rs), `wasm` and `matrix` |

The existing browser test:

```rust
let started = js_sys::Date::now();
for _ in 0..ITERATIONS {
    let verdict = verify(proof, action, &context, &registries);
    assert!(matches!(verdict, VerificationOutcome::Authorized(_)));
}
let average = (js_sys::Date::now() - started) / f64::from(ITERATIONS);
```

is retained as a smoke test but MUST NOT be used for publication. It lacks raw
samples, warmup disclosure, environment metadata, scenario coverage, and
quantile or uncertainty reporting.

## 2. Goals and excluded claims

### 2.1 Goals

The benchmark system MUST:

- generate every input deterministically from a versioned scenario;
- verify semantic output before collecting timing samples;
- preserve identical semantic inputs across native and WASM runners;
- record raw samples rather than only averages;
- distinguish startup, cold verification, and steady-state verification;
- record deterministic resource counters alongside elapsed time;
- exercise accepted inputs and fail-closed boundary paths;
- publish sufficient metadata for independent reproduction;
- compare revisions using ratios and uncertainty, not isolated point values.

### 2.2 Excluded claims

Results MUST NOT be presented as:

- a protocol-wide maximum latency;
- evidence of constant-time behavior;
- a denial-of-service proof;
- performance on unmeasured processors or runtimes;
- proof that one principal method is semantically stronger than another;
- evidence that a browser timing is equivalent to a native timing;
- a production service throughput number including networking, storage,
  custody, replay, budget claims, receipts, or execution.

## 3. Architecture

### 3.1 Repository layout

```text
demos/benchmarks/
├── auths-bench-model/
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── scenario.rs
│       ├── generator.rs
│       ├── manifest.rs
│       └── statistics.rs
├── auths-bench-native/
│   ├── Cargo.toml
│   ├── benches/verifier.rs
│   └── src/main.rs
├── auths-bench-wasm/
│   ├── Cargo.toml
│   ├── src/lib.rs
│   └── runner/
│       ├── package.json
│       ├── browser.mjs
│       └── node.mjs
└── profiles/
    ├── developer.toml
    ├── release.toml
    └── paper.toml

benchmark-results/
└── .gitignore
```

`auths-bench-model` is the single owner of scenarios, generation, result
schema, and summary statistics. Native and WASM runners MUST consume the same
serialized `BenchmarkInput` artifacts.

The benchmark crates are non-shipping demo/tooling packages. Core crates MUST
gain no timing, statistics, browser, or operating-system dependency.

### 3.2 Data flow

```text
+---------------------+
| Scenario manifest   |
| seed + dimensions   |
+----------+----------+
           |
           v
+---------------------+       +----------------------+
| Deterministic input | ----> | Semantic preflight   |
| proof/action/context|       | expected exact result|
+----------+----------+       +----------+-----------+
           |                             |
           +---------------+-------------+
                           |
              +------------+-------------+
              |                          |
              v                          v
     +------------------+       +------------------+
     | Native runner    |       | WASM runner      |
     | raw nanoseconds  |       | raw microseconds |
     +--------+---------+       +---------+--------+
              |                           |
              +-------------+-------------+
                            v
                 +----------------------+
                 | Result manifest      |
                 | samples + metadata   |
                 | digests + resources  |
                 +----------------------+
```

## 4. Developer and publication UX

### 4.1 Commands

The operator-facing workflow is:

```text
$ cargo xtask bench prepare --profile paper
Prepared 86 deterministic scenarios
Input manifest: target/auths-bench/inputs/manifest.json
Manifest SHA-256: 6f…

$ cargo xtask bench run --target native --profile paper
Host calibration: stable
Completed: 86/86
Raw result: benchmark-results/<run-id>/native.json

$ cargo xtask bench run --target wasm-node --profile paper
$ cargo xtask bench run --target wasm-browser --browser chromium --profile paper

$ cargo xtask bench report benchmark-results/<run-id>
Semantic agreement: PASS
Environment completeness: PASS
Report: benchmark-results/<run-id>/report.html
```

`prepare` and `report` are deterministic. `run` is necessarily observational
and MUST never modify benchmark inputs or expected semantic results.

### 4.2 Report view

The generated HTML report is static and contains no external resources:

```text
+------------------------------------------------------------------+
| Auths-Proof benchmark · run 2026-07-27T…                          |
| Revision b0ea…  Rust 1.91.0  aarch64-apple-darwin                 |
| [Semantic PASS] [Inputs PINNED] [Environment COMPLETE]            |
+------------------------------------------------------------------+
| Scenario                 p50       p95       p99      work   bytes |
| raw/ed25519/base         0.18 ms   0.21 ms   0.25 ms   27     812 |
| chain/depth-8            0.91 ms   0.98 ms   1.05 ms  203    5408 |
| plan/balanced-16         1.74 ms   1.88 ms   1.97 ms  411   10242 |
+------------------------------------------------------------------+
| Scaling plots | Native/WASM ratios | Limit boundary | Raw samples |
+------------------------------------------------------------------+
```

Values above are illustrative and MUST never appear as repository baselines
until measured.

## 5. Benchmark scenario API

### 5.1 Closed dimensions

```rust
pub struct BenchmarkScenario {
    pub id: ScenarioId,
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

pub enum PlanShape {
    Single,
    AllOf { leaves: u16 },
    AnyOf { leaves: u16, authorized_at: u16 },
    Threshold { k: u16, leaves: u16 },
    Balanced { depth: u16, branching: u16 },
    LeftDeep { depth: u16 },
}

pub enum LimitPosition {
    Nominal,
    Below { kind: LimitKind, delta: u64 },
    Exact { kind: LimitKind },
    Above { kind: LimitKind, delta: u64 },
}
```

Scenario types are closed enums so an unknown dimension cannot silently enter a
published run.

### 5.2 Generated input

```rust
pub struct BenchmarkInput {
    pub scenario: BenchmarkScenario,
    pub proof_cbor: Vec<u8>,
    pub canonical_action_cbor: Vec<u8>,
    pub trusted_context_cbor: Vec<u8>,
    pub adapter_context: AdapterBenchmarkContext,
    pub expected_result_cbor: Vec<u8>,
    pub input_digest: [u8; 32],
}
```

Private signing keys MAY exist transiently inside the deterministic generator
but MUST NOT be serialized. Generated benchmark artifacts contain only public
proof, action, context, adapter trust records, and expected result.

### 5.3 Determinism

`BenchmarkInput::generate(scenario)` MUST be a pure function of:

- scenario schema version;
- scenario fields;
- generator version;
- fixed protocol constants.

The digest is:

```text
SHA-256(
  "AUTHS-BENCH-INPUT\0\1" ||
  len(scenario) || scenario ||
  len(proof) || proof ||
  len(action) || action ||
  len(context) || context ||
  len(adapter_context) || adapter_context
)
```

The generator MUST produce byte-identical inputs on every supported host.

## 6. Required scenario families

The suite uses controlled families rather than an unreviewable full Cartesian
product.

### 6.1 Baseline

One authorized single-branch case for every compatible
principal-method/signature-suite pair:

- raw key: Ed25519, P-256;
- `did:key`: Ed25519, P-256;
- `did:keri`: Ed25519, P-256;
- bundled `did:web`: Ed25519, P-256;
- WebAuthn: P-256;
- HSM-attested: every suite supported by the current adapter;
- SPIFFE X.509: P-256.

Each case records proof, evidence, and context bytes independently.

### 6.2 Proof-size scaling

Authorized raw-key proofs target:

```text
1 KiB, 4 KiB, 16 KiB, 64 KiB, 128 KiB, 256 KiB
```

Padding MUST use semantically validated bounded attachments or evidence, not
ignored trailing bytes. The manifest records requested and actual canonical
sizes. The final point is omitted if the active deployment limit is smaller.

### 6.3 Grant-chain depth

Depth points:

```text
0, 1, 2, 4, 8
```

Every chain uses the same profile, permission, audience, and action body while
validity, depth, and another declared dimension attenuate monotonically.

### 6.4 Authorization-plan shape

Required points:

- `all-of`: 2, 4, 8, and 16 leaves;
- `any-of`: authorized leaf first, middle, and last in canonical order;
- `k-of-n`: `1-of-n`, median threshold, and `n-of-n`;
- balanced and left-deep plans with equal leaf counts where V1 bounds permit;
- authorized, denied, and indeterminate leaf distributions;
- identical node/leaf counts with different shape.

Because the evaluator intentionally visits all leaves, “authorized first” does
not imply short-circuit performance. It detects accidental short-circuiting.

### 6.5 Evidence and context size

For configured adapters, benchmark:

- one local trust record;
- 25%, 50%, and 100% of the deployment record limit;
- selected record first, middle, and last in canonical order;
- status snapshots at analogous sizes;
- assurance policies with 1, 4, 8, and maximum configured requirements.

### 6.6 Limit boundaries

Every `LimitKind` listed in
[`docs/LIMIT_COVERAGE.md`](../LIMIT_COVERAGE.md) receives:

- exact-limit accepted input where semantically possible;
- one-unit-over rejected input;
- exact deterministic work reservation;
- one-unit-below work budget producing
  `Denied(ResourceLimitExceeded)`.

Limit rejection timings are reported separately from successful verification
and MUST NOT be blended into throughput figures.

## 7. Measurement API

### 7.1 Operations

```rust
pub enum BenchmarkOperation {
    VerifyPortable,
    Decode,
    Resolve,
    PrincipalControl,
    Authority,
    ContextDecode,
    RegistryConstruction,
}
```

`VerifyPortable` is the headline operation. Stage measurements explain scaling
but MUST not be summed as a substitute for the end-to-end measurement.

### 7.2 Setup exclusion

For steady-state verification:

- inputs are generated before measurement;
- context and canonical action are decoded before measurement only when the
  benchmark explicitly targets the native typed API;
- registries are constructed before measurement;
- the timed closure receives immutable references;
- the output is consumed by a black box;
- semantic assertions run outside the timed interval.

Example:

```rust
group.bench_function(case.id().as_str(), |bencher| {
    bencher.iter(|| {
        let result = verify_v1(
            black_box(&case.proof_cbor),
            black_box(&case.canonical_action_cbor),
            black_box(&case.trusted_context_cbor),
            black_box(&registries),
        );
        black_box(result)
    });
});
```

Startup benchmarks separately include context decode and registry construction.

### 7.3 Warmup and samples

Publication profile requirements:

- at least 3 seconds of warmup per scenario/runtime;
- at least 100 independent samples;
- at least 10 timed operations per sample when timer resolution requires
  batching;
- randomized scenario execution order from a recorded seed;
- a calibration case before and after the run;
- discard no outlier without preserving it in raw output and recording the
  declared rule.

The native implementation SHOULD use a pinned Criterion release for sampling
and bootstrap estimates. The canonical Auths result schema, not Criterion’s
private directory layout, is the publication interface.

### 7.4 WebAssembly clocks

- browsers MUST use `performance.now()`;
- Node MUST use `process.hrtime.bigint()`;
- `js_sys::Date::now()` is prohibited for publication measurements;
- the browser, engine version, headless/headed state, cross-origin isolation,
  and timer resolution MUST be recorded;
- native and WASM inputs MUST have identical `input_digest`.

## 8. Result schema

Each runner emits canonical JSON:

```json
{
  "schema": "auths-proof-benchmark-result/v1",
  "run_id": "sha256:…",
  "revision": "…",
  "dirty": false,
  "target": "wasm32-unknown-unknown",
  "runtime": {
    "kind": "chromium",
    "version": "…"
  },
  "host": {
    "os": "…",
    "arch": "…",
    "cpu": "…",
    "logical_cores": 0,
    "memory_bytes": 0,
    "power_mode": "…"
  },
  "toolchain": {
    "rustc": "…",
    "cargo": "…",
    "wasm_bindgen": "…"
  },
  "scenario": "plan/threshold/8-of-16/p256",
  "input_sha256": "…",
  "verifier_configuration": "…",
  "registry_manifest": "…",
  "semantic": {
    "decision": "authorized",
    "code": "authorized",
    "result_sha256": "…",
    "work_units": 0,
    "proof_bytes": 0,
    "context_bytes": 0,
    "plan_leaves": 0,
    "plan_depth": 0
  },
  "samples_ns": [0],
  "summary": {
    "count": 100,
    "p50_ns": 0,
    "p95_ns": 0,
    "p99_ns": 0,
    "mean_ns": 0,
    "stddev_ns": 0,
    "median_ci95_ns": [0, 0]
  }
}
```

Published runs MUST use a clean revision. Developer runs MAY be dirty but are
watermarked and cannot become a baseline.

## 9. Statistics and comparison

The report MUST include:

- median;
- arithmetic mean;
- standard deviation;
- p95 and p99;
- 95% bootstrap confidence interval for the median;
- operations per second;
- proof bytes per second for size-scaling scenarios;
- deterministic work units;
- raw sample count.

Revision comparison uses paired scenario ratios:

\[
ratio_s = \frac{median(candidate_s)}{median(baseline_s)}
\]

A regression alert requires:

1. identical scenario and input digests;
2. compatible host/runtime metadata;
3. candidate median at least 10% slower;
4. non-overlapping configured bootstrap intervals; and
5. reproduction in a second complete run.

The default threshold is an operational policy, not a protocol constant, and
is recorded in the report.

## 10. Semantic safeguards

Before timing, every runner MUST:

1. decode the expected portable result;
2. execute the scenario once;
3. compare decision, stage, code, digests, authorized branches, assurance
   records, resources, registry manifest, and configuration IDs;
4. abort the scenario on any difference.

After timing, the runner repeats the semantic comparison. This catches state
leakage or mutation during measurement.

Native and WASM result bytes MUST be identical for portable V1 scenarios. A
semantic mismatch is a correctness failure, not a performance result.

## 11. Environmental controls

Publication runs MUST record:

- host model and processor;
- physical and logical cores;
- memory;
- OS and kernel version;
- compiler and target;
- optimization flags and LTO/codegen-unit settings;
- browser or Node version;
- power source and power mode when discoverable;
- container/virtual-machine status;
- background-load calibration;
- thermal throttling observations when discoverable.

Recommended controls:

- dedicated host;
- fixed performance governor where supported;
- stable mains power;
- no concurrent build;
- disabled automatic updates;
- three complete repetitions after thermal equilibrium.

Unavailable metadata is recorded as `"unknown"`; it MUST NOT be guessed.

## 12. Work-limit experiments

Wall-clock work and protocol work units are separate axes.

For each principal method:

```rust
let reserved = method.maximum_work_units() + suite.work_units();
let exact = context.with_limits(limits.with_work_units(reserved)?)?;
let below = context.with_limits(limits.with_work_units(reserved - 1)?)?;

assert_authorized(verify(case, &exact, registries));
assert_denied(
    verify(case, &below, registries),
    DenialReason::ResourceLimitExceeded,
);
```

The benchmark records:

- declared maximum;
- actual charged work from `VerificationResources`;
- exact-limit latency;
- one-below rejection latency;
- ratio of actual to reserved work.

No adapter may execute before its conservative reservation succeeds.

## 13. Automation and APIs

`xtask` adds:

```text
cargo xtask bench prepare [--profile <name>]
cargo xtask bench run --target <native|wasm-node|wasm-browser>
cargo xtask bench report <run-directory>
cargo xtask bench compare <baseline> <candidate>
cargo xtask bench verify-artifact <run-directory>
```

The reusable library API is:

```rust
pub fn generate_suite(
    profile: &BenchmarkProfile,
) -> Result<BenchmarkSuite, BenchmarkError>;

pub fn validate_result(
    input: &BenchmarkInput,
    result: &BenchmarkResult,
) -> Result<(), BenchmarkError>;

pub fn compare_runs(
    baseline: &RunArtifact,
    candidate: &RunArtifact,
    policy: &ComparisonPolicy,
) -> Result<ComparisonReport, BenchmarkError>;
```

Errors are closed, typed, and distinguish invalid scenarios, semantic drift,
incomplete metadata, timer failure, and incomparable runs.

## 14. Acceptance criteria

The benchmark system is publishable when:

1. every required scenario family in Section 6 exists;
2. all seven principal methods have a baseline case;
3. native, Node WASM, and browser WASM consume identical input artifacts;
4. all published cases pass semantic preflight and postflight;
5. raw samples and environment metadata are present;
6. every `LimitKind` has exact and over-limit coverage where constructible;
7. work reservation is measured for every principal method;
8. repeated input generation is byte-identical;
9. a clean host can reproduce the report from the published source and
   vendored-dependency bundle without network access after toolchain
   installation;
10. the report clearly separates measured observations from protocol
    guarantees.

## 15. Publication artifact

```text
auths-proof-benchmarks-<revision>/
├── METHODOLOGY.md
├── source.tar.zst
├── cargo-vendor.tar.zst
├── Cargo.lock
├── inputs/
│   ├── manifest.json
│   └── *.bench-input
├── results/
│   ├── native.json
│   ├── wasm-node.json
│   └── wasm-browser.json
├── raw/
│   └── *.json
├── report.html
├── report.json
├── environment.json
├── toolchain.json
└── SHA256SUMS
```

The publication MUST include failed calibration or incomplete-run metadata if
those runs informed a decision; unsuccessful runs are not silently deleted
from the research record.
