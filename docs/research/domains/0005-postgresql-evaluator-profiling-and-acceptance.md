# PostgreSQL evaluator profiling and Milestone 6 acceptance

## Status

Milestone 6 measured-bottleneck disposition.

Benchmark-baseline merge revision:
`55b6b58a59b733c3704918c70b64f743038eb4b3`

Aggregate fixture-manifest SHA-256:
`b348f63f10ec61cb9ba023571bca4faa4296544e4221e6ba85cbc6dd1d19b23f`

PostgreSQL fixture-manifest SHA-256:
`ff6bf76a7c054ebd6e16d42b01773138bad92507d0040c2ccabc366898c39d6f`

Decision: explicitly accept the current PostgreSQL evaluator implementation.
No optimization is merged from this investigation.

## Facts

### Why PostgreSQL was profiled

The three-run seven-domain baseline in
`docs/research/domains/0004-seven-domain-bounded-authorization-performance-baseline.md`
ranked the authorized PostgreSQL update as the slowest pure evaluator in every
run. Its p50 was 1.9 to 2.8 times the next-slowest scenario on that host. That
stable relative ordering justified profiling PostgreSQL and did not justify a
cross-domain abstraction or shared implementation.

### Component probe

A temporary release-mode probe invoked selected components of the exact
three-row authorized fixture 10,000 times each. The probe was diagnostic only,
was removed after measurement, and is not part of the proposed release. The
production source under measurement was revision `55b6b58`; only the ignored
test probe made the worktree dirty.

| Component | Nanoseconds per operation |
| --- | ---: |
| `action.validate()` | 36,998 |
| `evidence.validate()` | 543 |
| `configuration.validate()` | 119 |
| `configuration.digest()` | 25,412 |
| evidence row-set digest | 7,325 |
| evidence before-state digest | 16,734 |
| derived after-state digest | 17,149 |
| trusted statement compilation | 14,927 |
| complete evidence digest | 55,277 |

These component timings are not additive accounting for the whole evaluator:
some routines validate or canonicalize nested material also visited elsewhere.
They identify the largest observed leaf cost, complete-evidence RFC 8785
serialization plus SHA-256, without pretending that leaf is the only cost.

### Candidate tested

The smallest plausible representation change streamed RFC 8785 output
directly into SHA-256 rather than first allocating a canonical byte vector.
The experiment stayed entirely inside the PostgreSQL integration package and
did not change canonical JSON, digest identity, policy meaning, or shared/core
code.

A 20,000-iteration release-mode microprobe measured:

| Complete evidence digest implementation | Nanoseconds per operation |
| --- | ---: |
| Existing canonical bytes, then SHA-256 | 54,538 |
| Candidate canonical stream into SHA-256 | 52,166 |

The one-run leaf improvement was 4.35%, or 2,372 nanoseconds. Because the leaf
is only part of evaluation, this was not by itself a material evaluator
improvement.

### Full-evaluator comparison

The complete seven-domain release harness then ran three consecutive baseline
runs and three consecutive candidate runs on the same developer host. Each run
used the developer profile: 100 ms warmup, 20 samples, and 100 operations per
sample. Values below are PostgreSQL p50/p95 nanoseconds per evaluator
operation.

| Cohort | Run 1 | Run 2 | Run 3 |
| --- | ---: | ---: | ---: |
| Existing implementation | 301,211 / 547,881 | 318,686 / 475,182 | 310,274 / 563,510 |
| Streaming candidate | 331,646 / 716,482 | 378,466 / 549,301 | 170,895 / 176,435 |

The existing p50 median was 310,274 ns. The candidate p50 median was 331,646
ns, 6.9% slower. The existing p95 median was 547,881 ns and the candidate p95
median was 549,301 ns, effectively unchanged. Host variance was again visible,
but the candidate produced no reproducible full-evaluator improvement.

The candidate preserved the frozen decision oracle in every harness preflight
and postflight. Semantic agreement was necessary but not sufficient: the
Milestone 6 plan also requires a reproducible material improvement.

## Recommendations

1. Keep the existing canonical-byte digest implementation for the first
   release. It is simple, directly binds the persisted canonical bytes, and
   the allocation-removal candidate did not improve the complete evaluator.
2. Do not cache evidence or configuration digests across mutable typed values.
   A stale cache would weaken mutation detection unless a future contract
   introduces a closed immutable validated wrapper and proves the binding.
3. Do not weaken action, evidence, configuration, statement-template, or
   before/after-state revalidation to chase this microbenchmark. Those checks
   establish the exact authorized database effect.
4. Reopen optimization only with production-representative maximum-size
   fixtures, an isolated benchmark host, allocation profiling, and a candidate
   whose full-evaluator improvement is material across repeated interleaved
   runs.
5. Measure durable PostgreSQL transaction and reconciliation latency
   separately. Provider latency is domain-owned and is not evidence for moving
   PostgreSQL behavior into shared/core code.

## Explicit Milestone 6 acceptance

The measured PostgreSQL cost is accepted for the first release because:

- its largest observed leaf is required canonical evidence commitment work;
- the lowest-risk allocation reduction preserved semantics but failed the
  reproducible-material-improvement gate;
- more aggressive caching or skipped revalidation would introduce freshness
  and mutation-binding risk disproportionate to an unproven latency benefit;
- the pure evaluator remains sub-millisecond in these non-isolated developer
  measurements, while no product SLO has been declared from this benchmark;
- no other seven-domain evaluator showed a stable relative signal that
  justified a separate optimization investigation.

This disposition satisfies the Milestone 6 requirement that measured
bottlenecks be improved or explicitly accepted. The reference evaluator and
all frozen differential oracles remain unchanged. The authoritative CI suite
for this documentation-only disposition is the release assurance artifact;
it must be terminal and successful before merge.
