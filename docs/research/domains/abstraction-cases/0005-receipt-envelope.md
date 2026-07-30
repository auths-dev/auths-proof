# Case 0005: receipt envelope

## Decision

Approve commitment and hash-link mechanics. Do not replace canonical domain
receipts with a universal receipt payload.

## Consumers

All seven domains and every demo receipt view.

## Exact shared contract

An envelope binds schema/profile, action, policy/evaluator, evidence,
state/configuration, decision class/code/stage, reservation/obligation
commitments, implementation provenance, domain payload digest, and optional
prior-receipt link.

## Deliberate exclusions

Provider acceptance, observation, propagation, convergence, monetary facts,
transaction facts, disclosed business data, and human explanations.

## Comparison

| Identical | Divergent |
| --- | --- |
| Commitment completeness and hash links | Domain payload schema |
| Required/executed identities are visible | Number and meaning of lifecycle receipts |
| Authorization is separate from effect/observation | Provider truth and reconciliation |
| Canonical JSON can be shown inline | Human-designed receipt language |

## Versioning and compatibility

Envelope and domain payload versions are independent. Changing payload meaning
requires a domain version. Changing commitment coverage requires a new envelope
version. Provenance is never normalized away.

## Invariants and evidence

Prove every evaluator input/output commitment appears exactly once, hash links
open correctly, and envelope construction cannot claim a later stage.
Canonical fixture and browser tests verify inline JSON, machine endpoints, and
dedicated receipt pages.

## Migration and rollback

Wrap existing canonical receipts without changing their bytes. Compare payload
digests and views. Rollback removes the wrapper; domain receipts remain valid.

## Performance

Hash existing canonical bytes once. Avoid duplicating large payloads. Receipt
durability is not best effort.

## Why smaller composition is insufficient

Ad hoc metadata maps cannot prove completeness or stable ordering. A closed
envelope gives portable commitment mechanics while preserving the payload.

## Domain-owned code retained

Canonical receipt payloads, lifecycle meaning, signing policy, observation,
reconciliation, and UI explanation.
