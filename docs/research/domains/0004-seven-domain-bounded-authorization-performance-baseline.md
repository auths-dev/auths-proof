# Seven-domain bounded-authorization performance baseline

## Status

Milestone 6 evaluator baseline.

Milestone 5 release baseline: `0a34391ce5ffa58ccc11ad7b85c855f0605d81e9`

Benchmark implementation revision:
`74d6b2a3d30787168ec5061fb05a133e7931e8ea`

Aggregate fixture-manifest SHA-256:
`b348f63f10ec61cb9ba023571bca4faa4296544e4221e6ba85cbc6dd1d19b23f`

This report closes the comparable seven-domain evaluator timing gap identified
in
`docs/research/domains/0003-seven-domain-bounded-authorization-semantic-inventory.md`.
It does not authorize an optimization by itself. Internal profiling must still
identify a concrete bottleneck before an optimization branch begins.

## Facts

### Harness contract

The `auths-bounded-benchmark-run/1` harness:

- exercises the frozen authorized oracle for GitHub, Kubernetes, OpenTofu,
  PostgreSQL, Radicle, Stripe, and both records API profiles;
- compares the serialized preflight result with the repository oracle before
  timing;
- compares a postflight result with the preflight result after timing;
- measures the pure domain evaluator only, excluding fixture decoding, process
  startup, provider I/O, durable storage, and receipt delivery;
- requires an optimized Rust harness and rejects accidental debug runs;
- records the exact Git revision, tracked-worktree state, aggregate and
  per-domain fixture digests, decision digests, benchmark profile, toolchain,
  operating system, architecture, and logical-core count;
- writes the raw run to the ignored
  `benchmark-results/bounded-native.json` path.

The command is:

```console
cargo run --release -p xtask -- bench bounded --profile developer
```

The developer profile is bounded below at 100 milliseconds of warmup, 20
samples, and 100 evaluator operations per sample. Each recorded sample is the
integer average nanoseconds per evaluator operation.

The benchmark revision had no tracked changes during measurement. Untracked
owner-authored planning drafts do not affect the recorded dirty flag and were
not benchmark inputs.

### Environment

All three consecutive runs used:

| Field | Value |
| --- | --- |
| Operating system | macOS |
| Architecture | `aarch64` |
| Optimized harness | `true` |
| Logical cores | 10 |
| Rust compiler | `rustc 1.97.1 (8bab26f4f 2026-07-14)` |
| Warmup | 100 ms |
| Samples per run | 20 |
| Operations per sample | 100 |

### Fixture identities

| Domain | Manifest SHA-256 |
| --- | --- |
| GitHub | `4d2b4ad6468a25bf267a7223979e7880d598361fbe9c368d061d2ca75d6a56e8` |
| Kubernetes | `fc2c0f193c687ab664347a516271f98980509a9c5f6c9ff4871b1215d6d44a5a` |
| OpenTofu | `83a7c57fb69660fe04d3702c3e0533d31b8fa25dd38b62356f29ada46e8df36a` |
| PostgreSQL | `ff6bf76a7c054ebd6e16d42b01773138bad92507d0040c2ccabc366898c39d6f` |
| Radicle | `11fa8a12b2e132b04537f1c2916f17011077a7955ecc322152bf97307cb19f06` |
| Records API | `0fd394fa22e598267b251066f6eae80dda8d7296b586be63300d6189f2a55657` |
| Stripe | `36a4460e773e974b6edd8bb7a7123edf58042059932be05b85115cc1d745c88c` |

### Measurements

The table preserves all three consecutive run summaries rather than selecting
the most favorable run. Values are p50/p95 nanoseconds per evaluator
operation.

| Domain scenario | Run 1 | Run 2 | Run 3 |
| --- | ---: | ---: | ---: |
| GitHub authorized publish | 184,655 / 189,993 | 59,882 / 62,702 | 184,090 / 189,432 |
| Kubernetes authorized rollout | 142,645 / 146,962 | 45,710 / 47,725 | 65,838 / 66,405 |
| OpenTofu authorized saved plan | 104,299 / 106,273 | 33,998 / 35,390 | 104,527 / 106,373 |
| PostgreSQL authorized update | 502,233 / 549,102 | 166,722 / 174,759 | 348,393 / 514,364 |
| Radicle authorized open patch | 161,575 / 167,138 | 54,459 / 56,809 | 179,629 / 202,345 |
| Records API authorized create | 101,125 / 102,248 | 43,143 / 50,485 | 127,000 / 143,930 |
| Records API authorized read | 115,152 / 116,161 | 45,076 / 45,430 | 117,176 / 120,020 |
| Stripe authorized refund | 117,777 / 147,133 | 47,194 / 50,908 | 61,898 / 62,966 |

Absolute timings varied materially between consecutive runs on this
non-isolated developer machine. They are not release SLOs and are not suitable
for claiming a specific end-user latency. The ordering is nevertheless stable:
PostgreSQL was the slowest evaluator in every run, with a p50 between 1.9 and
2.8 times the next-slowest scenario in that same run.

### Semantic agreement

All eight scenarios matched their frozen decision oracle before measurement
and remained value-equivalent after measurement. The harness test also passed
all eight oracle comparisons in an unoptimized test build. This PR adds
measurement tooling and documentation; it does not change any domain
evaluator or execution path.

## Recommendations

1. Treat PostgreSQL as the only currently justified profiling target. Its
   stable relative position is evidence for investigation, not yet evidence
   for a code change.
2. Profile the PostgreSQL evaluator at this exact fixture digest and revision,
   separating canonical serialization/digest work, collection scans, checked
   predicates, and decision construction.
3. Start a fresh optimization branch only if profiling attributes a material
   share of evaluator time to one independently changeable mechanism.
4. Compare any candidate against this harness with repeated interleaved
   baseline/candidate runs on the same host. Require a material relative
   improvement while all differential, invalid, mutated, fuzzed, maximum-size,
   native, and WASM evidence remains green.
5. Explicitly accept the evaluator baseline without optimization if profiling
   finds no low-risk mechanism whose improvement is reproducible. Do not turn
   developer-host variance into an optimization mandate.

## Non-claims and remaining measurement gaps

This baseline does not measure:

- allocator counts or peak memory;
- reservation-store operations or durable-write latency;
- provider, transport, credential, reconciliation, or receipt-delivery
  latency;
- maximum-size, denied, or indeterminate-case timing;
- throughput under contention;
- production hardware or tenant-isolation effects.

Those dimensions remain separate performance questions. They must not be
inferred from this evaluator microbenchmark or used to move provider/domain
semantics into shared code.

## Milestone 6 gate decision

The exact benchmark fixtures and baseline-revision entry conditions are met.
The profiling condition is not yet met. Therefore no optimization is approved
by this PR. The next Milestone 6 branch is limited to profiling the PostgreSQL
candidate and either:

- one measured, independently revertible optimization with full equivalence
  evidence; or
- a documented explicit acceptance if no material low-risk bottleneck is
  found.
