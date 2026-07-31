# Phase 7 release owner decision register

## Status

All 11 decisions were approved by the repository owner on 2026-07-31. This
document records policy approval only. It does not authorize an artifact
publication, RC tag, package upload, claim publication, repository-setting
change, secret upload, or external-review engagement.

## Governing specification

[AP-SPEC-032](../specs/0032-reproducible-release-candidate-and-exact-assurance-claim.md)
requires these decisions before Phase 7 release implementation begins.

The read-only
[Phase 7 release readiness audit](PHASE_7_RELEASE_READINESS_AUDIT.md) maps each
decision to the current repository and the implementation it blocks.

The
[Phase 7 owner decision guide](PHASE_7_OWNER_DECISION_GUIDE.md) explains the
available choices and their tradeoffs without approving them.

The executing agent may maintain specifications, inspect the repository, and
prepare read-only analysis before the full Phase 7 entry gate passes. It MUST
NOT change release automation, freeze package metadata, publish artifacts,
create or move tags, engage external reviewers, accept legal or security risk,
or represent the Phase 7 entry gate as passed.

## Decision register

| ID | Decision | Recommended default | Owner must record | Status |
| --- | --- | --- | --- | --- |
| `P7-OD-001` | Release license | Keep `MIT OR Apache-2.0` through v1 | Exact license expression approved for RC package and release metadata | approved |
| `P7-OD-002` | Inbound contribution policy | Choose DCO or CLA with counsel | Selected policy, responsible owner, and effective date | approved |
| `P7-OD-003` | Artifact catalogue | Source archive, publishable crates, maintained bindings, WASM/native artifacts, assurance bundle | Exact in-scope and excluded release subjects | approved |
| `P7-OD-004` | Registry publication | Prepare all approved subjects; publish only to explicitly approved registries | Registry list and whether the first RC is staged, private, or public in each | approved |
| `P7-OD-005` | Supply-chain target | SLSA Build L3 for the first RC | Approved target and any explicitly accepted limitation | approved |
| `P7-OD-006` | SBOM baseline | SPDX JSON; retain CycloneDX only as additional evidence | Required SPDX version/profile and optional secondary formats | approved |
| `P7-OD-007` | Tag convention | One immutable semver-compatible RC form | Exact tag pattern and initial ordinal policy | approved |
| `P7-OD-008` | Release approvers | At least one named human approver distinct from build identity | Named approver or approver role and protected-environment rule | approved |
| `P7-OD-009` | Signing identity | GitHub artifact attestation backed by public Sigstore | Exact issuer, subject, workflow identity, and verification policy | approved |
| `P7-OD-010` | Public claim approver | Named technical owner | Approver identity or role and approval-record location | approved |
| `P7-OD-011` | Vulnerability and CRA ownership | Name a security contact and obtain counsel review when external EU distribution is in scope | Security contact, disclosure owner, distribution scope, and counsel decision or explicit not-yet-in-scope record | approved interim policy |

## Approved records

All records in this section were approved by the repository owner on
2026-07-31. `owner: repository-owner` means the human repository owner, not a
workflow, build identity, or autonomous agent.

### `P7-OD-001`

```yaml
decision_id: P7-OD-001
status: approved
decision: "Keep MIT OR Apache-2.0 for the open core through v1."
owner: repository-owner
decided_at: 2026-07-31
conditions: []
```

### `P7-OD-002`

```yaml
decision_id: P7-OD-002
status: approved
decision: "Use a Developer Certificate of Origin (DCO) for external contributions."
owner: repository-owner
decided_at: 2026-07-31
conditions:
  - "The policy and sign-off mechanism must be implemented and tested before public contributor recruitment."
```

### `P7-OD-003`

```yaml
decision_id: P7-OD-003
status: approved
decision: "Use the lean SDK-first release surface: auths-proof and auths-proof-sdk as the supported Rust roots, @auths-dev/proof on npm, auths-proof on PyPI, plus the source archive and assurance bundle."
owner: repository-owner
decided_at: 2026-07-31
evidence_or_advice: "https://github.com/auths-dev/auths-proof/issues/51"
conditions:
  - "Generate and verify the exact crates.io normal-dependency closure from the candidate revision; it is currently 27 Rust crates."
  - "Rename the current workspace package auths-sdk to auths-proof-sdk before freezing package metadata; the existing crates.io name auths-sdk is already occupied by the superseded project line."
  - "Registry-visible dependency crates are supporting implementation packages, not separately promised top-level SDKs."
  - "The npm subject owns the prepared WASM boundary and the PyPI subject owns prepared native wheels; their Rust build crates are not additional supported crates.io roots."
  - "Defer auths-profile-kit, auths-proof-exchange and its adapters, domain integrations, demos, benchmarks, testkits, fuzz crates, internal tools, CLIs, and hosted services."
  - "An unexpected dependency-closure expansion blocks the candidate pending review."
```

### `P7-OD-004`

```yaml
decision_id: P7-OD-004
status: approved
decision: "Prepare and verify first. Plan a later GitHub prerelease and publication of the approved catalogue to crates.io, npm, and PyPI."
owner: repository-owner
decided_at: 2026-07-31
evidence_or_advice: "https://github.com/auths-dev/auths-proof/issues/50"
conditions:
  - "Preparation is not publication authorization."
  - "Publication requires a separate owner authorization for the exact release-manifest digest."
  - "No registry outside the recorded matrix receives credentials or artifacts."
```

### `P7-OD-005`

```yaml
decision_id: P7-OD-005
status: approved
decision: "Require SLSA 1.2 Build Level 3 for every first-RC release subject; Level 2 is not an accepted fallback."
owner: repository-owner
decided_at: 2026-07-31
conditions:
  - "A label, environment check, signature, or ordinary GitHub-hosted job does not establish Level 3 by itself."
  - "The implemented builder and provenance path must be assessed against every applicable SLSA 1.2 Build Level 3 producer and build-platform requirement."
  - "Any subject whose official build cannot establish Level 3 blocks the candidate or is removed through a new owner-approved catalogue decision."
  - "SLSA does not establish source correctness, dependency correctness, or artifact security."
```

### `P7-OD-006`

```yaml
decision_id: P7-OD-006
status: approved
decision: "Use SPDX 2.3 JSON as the normative release SBOM and retain CycloneDX 1.5 as supplementary evidence."
owner: repository-owner
decided_at: 2026-07-31
conditions:
  - "Bind SBOM predicates to exact release-subject digests."
  - "A future SPDX migration requires an explicit evidence-schema revision."
```

### `P7-OD-007`

```yaml
decision_id: P7-OD-007
status: approved
decision: "Use immutable tags matching auths-proof-v<semver>-rc.<positive-ordinal>, beginning with auths-proof-v1.0.0-rc.1."
owner: repository-owner
decided_at: 2026-07-31
conditions:
  - "A rejected or withdrawn candidate increments the ordinal; its tag never moves."
```

### `P7-OD-008`

```yaml
decision_id: P7-OD-008
status: approved
decision: "The repository owner is the human release approver, distinct from the hosted build identity."
owner: repository-owner
decided_at: 2026-07-31
conditions:
  - "An executing agent may perform clerical release steps on the owner's behalf only after the owner authorizes the exact manifest digest."
  - "This record is not approval of any not-yet-prepared candidate, tag, or publication."
```

### `P7-OD-009`

```yaml
decision_id: P7-OD-009
status: approved
decision: "Use keyless GitHub Actions OIDC and GitHub artifact attestations backed by the Sigstore Public Good Instance for first-RC build provenance."
owner: repository-owner
decided_at: 2026-07-31
evidence_or_advice:
  - "https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations"
  - "https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline"
conditions:
  - "Issuer: https://token.actions.githubusercontent.com"
  - "Repository owner ID: 260513770; repository ID: 1310728509."
  - "Use the protected release-candidate environment and opt into immutable owner/repository subject identity before relying on the subject policy."
  - "Expected immutable subject context: repo:auths-dev@260513770/auths-proof@1310728509:environment:release-candidate; implementation must fail if the emitted certificate identity differs."
  - "Use a digest-pinned reusable builder workflow whose exact workflow identity is frozen in the release manifest."
  - "Preserve each JSON Sigstore bundle and the contemporaneous trusted-root material for offline verification."
  - "Auths protocol, verifier, SDK, runtime, and proof exchange must not require GitHub, OIDC, Sigstore services, or network access."
  - "Independent reproducible preparation remains a separate evidence path."
```

### `P7-OD-010`

```yaml
decision_id: P7-OD-010
status: approved
decision: "The repository owner approves exact public assurance wording. Strong claims remain prohibited until applicable independent review is complete."
owner: repository-owner
decided_at: 2026-07-31
conditions:
  - "Pre-review wording must identify the candidate as pre-audit and preserve all evidence limitations."
  - "An external reviewer may require narrower wording but cannot supply evidence for a stronger claim."
```

### `P7-OD-011`

```yaml
decision_id: P7-OD-011
status: approved
decision: "Use the repository owner and GitHub Security Advisories as the interim private security channel and withdrawal authority. Make no CRA compliance claim."
owner: repository-owner
decided_at: 2026-07-31
evidence_or_advice: "../../SECURITY.md"
conditions:
  - "External EU distribution requiring a legal role determination remains blocked pending qualified advice."
  - "The first RC is technical prerelease evidence, not a general-availability product."
```

## Auths-native release authorization boundary

Auths MAY produce a separate authorization proof and receipt for the exact
promotion action. That evidence binds the repository owner, candidate commit,
release-manifest digest, tag, destination registry set, expiry, and permitted
operation. It is complementary to, and MUST NOT replace or relabel:

- SLSA provenance from the hardened build platform;
- Sigstore/GitHub artifact identity and integrity evidence;
- SPDX SBOMs;
- reproducibility evidence; or
- protected human approval.

For the first RC, candidate-built Auths code MUST NOT be the sole verifier of
its own release authority. It may run as defense-in-depth and produce
explicitly scoped evidence. A later RC MAY make the Auths authorization check
mandatory only when it uses a previously reviewed, digest-pinned verifier or
another independently qualified non-circular verification path.

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
Owner-decision subgate: PASSED
Approved owner decisions: 11
Unresolved owner decisions: 0
Phase 7 entry: BLOCKED pending merge and entry-revision evidence
Release implementation permitted on this unmerged decision branch: no
Artifact publication permitted: no
RC tag creation permitted: no
Phase 8 claim publication permitted: no
```

The owner-decision subgate does not establish the remaining Phase 7 entry
conditions. Release implementation begins in a separate bounded PR only after
this decision record is on `main` and the candidate entry revision has real,
terminal evidence for the other AP-SPEC-032 Section 5 conditions.
