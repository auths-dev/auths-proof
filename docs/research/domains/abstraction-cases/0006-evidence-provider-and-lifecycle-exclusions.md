# Case 0006: evidence, provider, and lifecycle exclusions

## Decision

Reject generic evidence, verified-command, credential, provider, exact-effect
service, and reconciliation abstractions for Milestone 3.

## Consumers considered

All seven domains, including the two records profiles and additional Stripe
profiles as intra-domain counterexamples.

## Shared invariant

Evidence and exact actions are committed; protected capability is unavailable
before authorization; commands derive from verified actions; possible effects
are retained until proven absent; later observations are separately receipted.

## Deliberate exclusions

Every payload and transition that gives these words provider meaning.

## Comparison

| Surface | Divergence preventing abstraction |
| --- | --- |
| Evidence | Different authorities, conflicts, freshness, normalization and uncertainty |
| Verified command | Git objects, Kubernetes patches, saved plans, typed SQL, Radicle patches, record operations and Stripe requests |
| Credential | GitHub App, Kubernetes, backend/provider, database, signer, no reusable records credential, Stripe scope |
| Outcome unknown | Provider ambiguity, local definitive writes, distributed propagation, or transport replay |
| Reconciliation | Ref/PR lookup, rollout convergence, backend state, transaction ledger, observers, local ledger, refund lookup |
| Runtime | Multi-effect, conditional mutation, artifact apply, transaction, publication, local ledger, monetary mutation |

## Versioning and compatibility

Each excluded surface remains profile/domain versioned. An upstream provider
change is contained by the relevant adapter or new profile version.

## Invariants and evidence

Existing domain denial-before-credential, exact-command, crash, replay,
unknown-outcome, reconciliation, and receipt tests remain authoritative.
Milestone 4 may extract only smaller state primitives after a separate closed
transition specification and formal proof.

## Migration and rollback

There is no Milestone 3 migration for these surfaces. Later proposals require
new case files and must preserve the current verticals as test-only references.

## Performance

No common hot path is inferred from provider latency or similar orchestration.
Measure each stage independently.

## Why composition is preferred

Small commitment, compare-and-swap, checked arithmetic, stage-order, and
receipt-link primitives can compose without making provider behavior a
callback. This preserves type-level domain meaning.

## Domain-owned code retained

All evidence acquisition/interpretation, exact commands, gateways, credentials,
provider retry rules, observation, reconciliation, and lifecycle receipts.
