# Phase 7 release owner decision register

## Status

Awaiting owner decisions. This document is a decision packet, not an approval
record. An unresolved row MUST NOT be interpreted as acceptance of its
recommended default.

## Governing specification

[AP-SPEC-032](../specs/0032-reproducible-release-candidate-and-exact-assurance-claim.md)
requires these decisions before Phase 7 release implementation begins.

The read-only
[Phase 7 release readiness audit](PHASE_7_RELEASE_READINESS_AUDIT.md) maps each
decision to the current repository and the implementation it blocks.

The executing agent may maintain specifications, inspect the repository, and
prepare read-only analysis while decisions are unresolved. It MUST NOT change
release automation, freeze package metadata, publish artifacts, create or move
tags, engage external reviewers, accept legal or security risk, or represent
the Phase 7 entry gate as passed.

## Decision register

| ID | Decision | Recommended default | Owner must record | Status |
| --- | --- | --- | --- | --- |
| `P7-OD-001` | Release license | Keep `MIT OR Apache-2.0` through v1 | Exact license expression approved for RC package and release metadata | unresolved |
| `P7-OD-002` | Inbound contribution policy | Choose DCO or CLA with counsel | Selected policy, responsible owner, and effective date | unresolved |
| `P7-OD-003` | Artifact catalogue | Source archive, publishable crates, maintained bindings, WASM/native artifacts, assurance bundle | Exact in-scope and excluded release subjects | unresolved |
| `P7-OD-004` | Registry publication | Prepare all approved subjects; publish only to explicitly approved registries | Registry list and whether the first RC is staged, private, or public in each | unresolved |
| `P7-OD-005` | Supply-chain target | SLSA Build L2 for the first RC | Approved target and any explicitly accepted limitation | unresolved |
| `P7-OD-006` | SBOM baseline | SPDX JSON; retain CycloneDX only as additional evidence | Required SPDX version/profile and optional secondary formats | unresolved |
| `P7-OD-007` | Tag convention | One immutable semver-compatible RC form | Exact tag pattern and initial ordinal policy | unresolved |
| `P7-OD-008` | Release approvers | At least one named human approver distinct from build identity | Named approver or approver role and protected-environment rule | unresolved |
| `P7-OD-009` | Signing identity | GitHub artifact attestation or approved Sigstore identity | Exact issuer, subject, workflow identity, and verification policy | unresolved |
| `P7-OD-010` | Public claim approver | Named technical owner | Approver identity or role and approval-record location | unresolved |
| `P7-OD-011` | Vulnerability and CRA ownership | Name a security contact and obtain counsel review when external EU distribution is in scope | Security contact, disclosure owner, distribution scope, and counsel decision or explicit not-yet-in-scope record | unresolved |

## Owner response format

For each decision, record:

```yaml
decision_id: P7-OD-001
status: approved
decision: bounded exact decision text
owner: named person or repository role
decided_at: YYYY-MM-DD
evidence_or_advice: optional protected or public reference
conditions: []
review_at: optional gate or date
```

Allowed statuses are `approved`, `deferred`, and `rejected`. `deferred` MUST
name the gate it blocks. A recommendation remains non-binding until an owner
records `approved`.

Legal, regulatory, trademark, contribution-rights, and licensing decisions
require qualified advice where applicable. Repository text is not legal
advice.

## Current gate result

```text
Phase 7 entry: BLOCKED
Unresolved owner decisions: 11
Release implementation permitted: no
Artifact publication permitted: no
RC tag creation permitted: no
Phase 8 claim publication permitted: no
```

The gate may change only through an owner-approved update that resolves every
decision required for the affected Phase 7 surface.
