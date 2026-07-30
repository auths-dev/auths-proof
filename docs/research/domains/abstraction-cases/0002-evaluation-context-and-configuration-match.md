# Case 0002: evaluation context and configuration match

## Decision

Approve explicit commitment carriers and one fail-closed equality gate in the
product layer.

## Consumers

All seven domains and both records profiles.

## Exact shared contract

Pure evaluation receives explicit commitments for exact action, evidence,
state snapshot, verifier time, required configuration, and executed
configuration. Required and executed semantic/configuration identities must
match before an eligible result can authorize durable state or execution.

## Deliberate exclusions

The contents and trustworthiness of evidence, acquisition of state, wall-clock
sources, provider configuration parsing, and domain diagnostic order.

## Comparison

| Identical | Divergent |
| --- | --- |
| Every input is explicit and committed | Evidence and snapshot schema |
| Required/executed mismatch fails before effects | Which local facts compose configuration |
| Time is passed, never read globally | Freshness and validity interpretation |
| Action/evidence/configuration digests reach receipts | Domain decision code and stage |

## Versioning and compatibility

The shared configuration-match semantic identity is versioned. Domains retain
their configuration schemas. A new domain configuration version changes its
digest and executed identity without changing the shared equality law.

## Invariants and evidence

Prove mismatch cannot yield eligible, reservation intent, execution token,
credential event, or provider call. Each domain retains denial-before-
credential tests. Mutation tests change each commitment independently.

## Migration and rollback

Domains initially compute both their existing comparison and the shared gate;
differential tests require exact agreement. The original comparison remains a
test oracle until migration passes. Rollback restores the original call.

## Performance

Bounded fixed-byte comparisons only. Parse and validate executed configuration
once outside evaluation; do not cache verdicts.

## Why smaller composition is insufficient

Loose digest arguments permit callers to omit or reorder a binding. A closed
context makes the complete comparison inventory reviewable and prevents
partial execution authorization.

## Domain-owned code retained

Configuration construction, trusted-context acquisition, evidence freshness,
stable domain diagnostics, and all I/O.
