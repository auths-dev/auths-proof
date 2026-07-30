# Case 0003: eligibility, reservation intents, and obligations

## Decision

Approve the three-way pure result and commitment mechanics. Defer mutable
reservation semantics to Milestone 4.

## Consumers

All seven domains. Stripe and PostgreSQL demonstrate additive capacity;
GitHub, Kubernetes, OpenTofu, and Radicle demonstrate uniqueness/exclusivity;
records demonstrates atomic local create/read capacity.

## Exact shared contract

Evaluation partitions into eligible, denied, or indeterminate. Eligible binds
bounded domain-owned reservation-intent and obligation sets by canonical
digest. Denied and indeterminate carry domain-owned stable codes/stages and
cannot create execution authority.

## Deliberate exclusions

Reservation keys, units, windows, release, expiry, commit, unknown outcomes,
reconciliation, obligation meaning, and store transactions.

## Comparison

| Identical | Divergent |
| --- | --- |
| Three disjoint result classes | Positive class naming in old APIs |
| Eligible is not executable authority | Reservation algebra and capacity |
| Outputs are bounded and committed | Obligation payload and discharge |
| Denied/indeterminate stop protected effects | Domain code and diagnostic order |

## Versioning and compatibility

The envelope schema is versioned independently from domain result versions.
Migration may preserve old result names while mapping them to the three shared
classes. Domain payload schemas remain separately versioned.

## Invariants and evidence

Prove deterministic partition, output commitment completeness, no dropped
obligations, and fixed-context result refinement under policy tightening.
Mutation tests delete or alter each intent/obligation. Domain concurrency and
reconciliation tests remain authoritative for mutable behavior.

## Migration and rollback

Each existing result maps into the envelope and is compared to its original
decision, code, stage, intent, and obligation bytes. No domain store is changed
in Milestone 3. Rollback removes only the mapping.

## Performance

Bounded collections require explicit maximum items and bytes. Hash once after
canonical construction; do not allocate a universal optional-field payload.

## Why smaller composition is insufficient

A Boolean plus unrelated vectors cannot prove that successful outputs are
bound to the exact decision. One closed result binds class and outputs while
leaving their semantics concrete.

## Domain-owned code retained

Every intent/obligation type, mutable state machine, store, stable code,
verified command, and reconciliation path.
