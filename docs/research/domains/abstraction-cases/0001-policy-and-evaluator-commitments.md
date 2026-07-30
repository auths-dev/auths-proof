# Case 0001: policy and evaluator commitments

## Decision

Approve a product-layer commitment carrier. Do not share policy payloads or
evaluation logic.

## Consumers

GitHub, Kubernetes, OpenTofu, PostgreSQL, Radicle, records create/read, and
Stripe bounded refund.

## Exact shared contract

A commitment binds a closed policy type/version, canonicalization identifier,
canonical policy digest, and evaluator semantic identifier. Identical
identifiers have immutable meaning. Policy bytes are carried directly or
resolved by immutable digest. Mutable names do not authorize execution.

## Deliberate exclusions

Policy fields, evidence sources, action vocabulary, domain denial codes,
reservation units, provider behavior, and build approval policy.

## Comparison

| Identical | Divergent |
| --- | --- |
| Immutable type/version/canonicalization/evaluator identity | Policy field meaning |
| Canonical digest binds exact bytes | Canonical policy schema |
| Semantic changes require new identity | Domain tightening relation |
| Required evaluator is explicit | Local build provenance and deployment |

## Versioning and compatibility

Identifiers are closed, ASCII, length-bounded, and compared byte-for-byte.
Meaning never changes under an existing identifier. Dual-version operation is
explicit; retirement waits for grants, decisions, reservations, receipts, and
reconciliation state.

## Invariants and evidence

Lean must prove commitment equality/reflexivity and that configuration mismatch
cannot produce eligibility. Rust conformance must reject unknown versions,
unknown fields in canonical policy schemas, digest mismatch, and mutable-name
resolution. The seven generator-owned corpora are migration oracles.

## Migration and rollback

Add the carrier without changing domain policy bytes. Each domain maps its
existing identities into the carrier and differentially compares decisions.
Rollback removes the mapping and leaves vertical identifiers untouched.

## Performance

One fixed-size digest comparison and bounded identifier comparisons are the
expected cost. Benchmark before interning or caching.

## Why smaller composition is insufficient

Independent strings and digests do not enforce that type, version,
canonicalization, and evaluator move together. One closed carrier prevents
partial binding.

## Domain-owned code retained

All policy schemas, evaluators, registries of domain meaning, explanations,
fixtures, and compatibility migrations.
