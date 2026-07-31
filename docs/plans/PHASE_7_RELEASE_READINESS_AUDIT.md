# Phase 7 release readiness audit

## Status and reviewed baseline

Read-only repository audit for AP-SPEC-032. This document records current
implementation facts and gaps; it does not approve owner decisions or
authorize release changes.

> **Historical baseline:** this audit predates issue 54 and AP-SPEC-034. Its
> `auths-proof-sdk`, `@auths-dev/proof`, PyPI `auths-proof`, and
> `auths-proof-v*` references describe the reviewed baseline and the now-
> superseded owner decision. The governing targets are in
> [`release/public-naming.toml`](../../release/public-naming.toml): `auths`,
> `auths-sdk`, `@auths-dev/sdk`, PyPI `auths`, and
> `auths-v1.0.0-rc.1`.

The code and workflow baseline reviewed was `main` at `6f8df76`. The audit was
prepared on the documentation-only specification branch. That branch does not
change release behavior.

## Governing artifacts

- [AP-SPEC-032](../specs/0032-reproducible-release-candidate-and-exact-assurance-claim.md)
- [Phase 7 owner decision register](PHASE_7_RELEASE_OWNER_DECISIONS.md)
- [Post-Milestone 6 Productization and Release Plan](../target-state/POST_MILESTONE_6_PRODUCTIZATION_AND_RELEASE_PLAN.md)

## Current release flow

```text
push tag matching v*
        |
        v
.github/workflows/release.yml
        |
        +-> build and install release toolchains
        +-> cargo xtask release-check
        +-> reproduce Aeneas translation
        +-> upload temporary workflow artifact

release-check
        |
        +-> authoritative CI, formal and compliance checks
        +-> package 60 publishable Rust crates
        +-> smoke-test npm and Python packages
        +-> generate platform/compliance evidence
        +-> emit CycloneDX 1.5, custom provenance and SHA256SUMS
```

This is a strong pre-RC gate, but it builds after the tag event. AP-SPEC-032
requires the inverse: prepare and verify content-addressed subjects first, then
promote those exact bytes without rebuilding.

## Existing strengths

- `.github/workflows/release.yml` pins third-party actions by commit and pins
  Rust, Node, Go, Python, Maturin, WASM, Kani, Aeneas, and Charon inputs.
- `cargo xtask release-check` rejects a dirty CI worktree, runs authoritative
  CI, all-features and no-default-features tests, documentation, packaging,
  formal, architecture, compliance, conformance, binding, and live-demo gates.
- `xtask/src/fixtures.rs::package_check` packages every currently publishable
  workspace crate and rejects publishable demo or tooling packages.
- TypeScript and Python packages are built and installed into clean smoke-test
  environments.
- `xtask/src/release.rs` records the exact Git commit, toolchain, fixture
  manifest, crate subjects, platform artifact, compliance artifacts, and
  checksums.
- The release workflow reproduces the pinned Aeneas translation and preserves
  formal output.
- `docs/audit/REVIEW_SCOPE.md` already states that no independent review has
  been commissioned or completed.

## Artifact inventory facts

At the reviewed baseline:

- the Cargo workspace contains 95 packages;
- 60 packages are publishable by current metadata and 35 declare
  `publish = false`;
- all workspace packages use version `0.1.0` and license expression
  `MIT OR Apache-2.0`;
- the TypeScript package is `@auths-dev/proof` version `0.1.0`;
- the Python build produces an `auths_proof` wheel;
- `release_evidence()` includes publishable `.crate` archives plus platform
  and compliance JSON/text artifacts as checksum and provenance subjects;
- the npm archive, Python wheel, source archive, generated WASM files, formal
  evidence, benchmarks, and documentation are not all represented as release
  subjects in one manifest; and
- the release workflow uploads `.crate`, `target/release-evidence`, and
  `target/formal` paths for 90 days, but does not publish an immutable assurance
  bundle.

The count of publishable packages is a repository fact, not approval to publish
all 60. `P7-OD-003` selects `auths-proof` and the renamed
`auths-proof-sdk` as the supported Rust roots, their generated
normal-dependency closure, the npm and PyPI bindings, the source archive, and
the assurance bundle. The current local `auths-sdk` package name must change
before metadata freeze because crates.io already contains the superseded
project's package under that coordinate. `P7-OD-004` requires preparation and
verification before a separately authorized publication event.

## AP-SPEC-032 gap matrix

| Requirement | Current repository evidence | Gap or decision |
| --- | --- | --- |
| Owner-approved release boundary | All 11 decisions are approved on the documentation-only specification branch | Decision record is not yet on `main`; approval does not itself establish the remaining Phase 7 entry evidence |
| Immutable semantic-freeze inventory | `platform.json`, protocol fixtures, architecture/compliance inventories, bounded-domain and formal manifests | No single schema classifies frozen meaning, frozen bytes, release metadata, and owning paths |
| Drift enforcement | Fixture, architecture, compliance, source-closure, formal, profile, and result-code checks exist | No release-wide rule rejects changed meaning under an unchanged semantic identity |
| Complete artifact catalogue | Owner approved the lean SDK-first roots, current 27-crate normal-dependency closure, binding subjects, source, assurance bundle, and explicit deferrals | No machine-readable candidate catalogue or CI-enforced closure/exclusion inventory |
| Content-addressed release manifest | Per-file checksums and custom provenance subjects exist | No AP-SPEC-032 release manifest binding source, semantic freeze, all subjects, evidence, and reproducibility class |
| SPDX SBOM | CycloneDX 1.5 is generated and validated | No SPDX JSON baseline or unambiguous SPDX relationship coverage for every approved subject |
| Signed hosted provenance | Custom unsigned `provenance.json` records GitHub context | Workflow has only `contents: read`; no OIDC `id-token`, artifact-attestation permission, signature, or hosted-build provenance verification |
| Reproducibility classification | Aeneas translation is reproduced twice; WASM/live-demo checks cover selected deterministic artifacts | No per-subject `byte-identical`, `deterministic-evidence`, `platform-reproducible`, or `provenance-only` declaration and two-run comparison |
| Evidence ordering | `release-check` emits evidence; the workflow then runs pinned Aeneas reproduction | Post-check formal output is uploaded but is not necessarily a subject of the earlier release manifest/checksum graph |
| Prepare before tag | Workflow supports dispatch and tag events | Tag push currently starts the build; verified subjects are not staged before tag creation |
| No-rebuild promotion | No registry publication currently occurs | No protected promotion job that downloads subjects by digest and proves no build step ran |
| RC tag contract | Owner approved `auths-proof-v<semver>-rc.<positive-ordinal>`, beginning with `auths-proof-v1.0.0-rc.1` | The existing `GITHUB_REF_NAME == v<Cargo version>` rule does not implement the approved convention |
| Durable evidence bundle | GitHub workflow artifact retained for 90 days | No immutable public bundle, release attachment, OCI artifact, or offline verification package |
| Exact assurance-claim registry | Formal assurance manifest and prose assurance model exist | No registry entry binds every public claim to release subjects, evidence, assumptions, exclusions, and compatibility |
| Claim synchronization | Formal manifest validation and documentation checks exist | No inventory of public claim locations or CI rule rejecting unregistered/stale wording |
| Independent review handoff | `docs/audit/REVIEW_SCOPE.md` defines a baseline scope | AP-SPEC-033 packet, track reports, structured findings, retest, and gate report do not exist and cannot exist before real reviewers engage |

## Workflow-specific observations

### Tag and promotion

`.github/workflows/release.yml` triggers on `push.tags: ["v*"]`. The workflow
checks out the tag and builds release bytes. This cannot satisfy no-rebuild
promotion. `workflow_dispatch` is useful for preparation, but it currently has
no candidate-commit, catalogue, second-run, or publication-mode inputs.

The workflow does not declare a protected GitHub environment or a distinct
human approval step. Its permission block is read-only, which is safe for the
current non-publishing behavior but insufficient for approved signed
provenance or publication.

### Subject coverage

`release_evidence()` derives its subjects from publishable Cargo archives and
selected platform/compliance files. Package smoke tests produce npm and Python
archives elsewhere under `target`, but the evidence generator does not add
those archives to the same subject graph. Formal and benchmark artifacts also
need explicit subject and evidence roles rather than inclusion only by
directory upload.

### Provenance and SBOM

The custom provenance is useful internal evidence, but it is generated by the
repository process itself and is not signed hosted-build provenance. The
current CycloneDX document may remain useful as additional evidence; it does
not satisfy AP-SPEC-032's recommended SPDX baseline.

### Reproduction

The existing formal translation reproduction is materially stronger than a
single build. AP-SPEC-032 extends this discipline to every approved release
subject. Two isolated preparation runs must start from fresh checkouts and
empty output directories and compare results by the declared class.

## Approved decision-to-implementation constraints

| Decision | Implementation it blocks |
| --- | --- |
| `P7-OD-001` release license | frozen Cargo/npm/Python metadata and release manifest |
| `P7-OD-002` inbound policy | public contributor recruitment and contributor metadata |
| `P7-OD-003` artifact catalogue | release-subject schema, build graph, SBOM coverage, reproduction matrix |
| `P7-OD-004` registries | promotion workflow, credentials, prerelease behavior, withdrawal procedure |
| `P7-OD-005` supply-chain target | provenance schema, runner and builder requirements, verification policy |
| `P7-OD-006` SBOM baseline | generator choice, SPDX schema/profile, relationship validation |
| `P7-OD-007` tag convention | tag parser, workspace-version rules, promotion input validation |
| `P7-OD-008` release approvers | protected environment, approval record, separation of duties |
| `P7-OD-009` signing identity | workflow permissions, issuer/subject constraints, consumer verification |
| `P7-OD-010` claim approver | Phase 8 approval record and claim-publication gate |
| `P7-OD-011` vulnerability/CRA ownership | public RC distribution, security contact, withdrawal and reporting process |

## Bounded follow-up PRs after the full entry gate

The following are plans, not authorization:

1. Add the semantic-freeze schema, generator, committed inventory, and drift
   tests without changing release publication.
2. Add the owner-approved subject catalogue, release-manifest schema, SPDX
   evidence, hosted-provenance contract, and adversarial validators.
3. Add isolated preparation, second-run comparison, content-addressed staging,
   and a preparation-only workflow.
4. Add a separate protected no-rebuild promotion workflow for only the
   approved registries and signing identity.
5. Close candidate evidence defects, run the exact preparations, and propose
   the final candidate revision.
6. Create and promote the immutable RC only through the separately authorized
   external event.
7. Add the Phase 8 claim registry and claim-synchronization enforcement against
   that fixed RC.

Each PR must include the tests, affected claims, exclusions, rollback or
withdrawal behavior, and remaining gate conditions required by AP-SPEC-032.

## Current conclusion

The repository has unusually strong release inputs: broad authoritative CI,
formal reproduction, package smoke tests, conformance, compliance, checksums,
and internal provenance. The missing work is primarily release-subject
selection, semantic freeze, signed provenance, SPDX coverage, isolated
reproduction, immutable staging/promotion, and exact claim binding.

No implementation PR may begin until the approved decision record is on
`main` and the other AP-SPEC-032 Phase 7 entry conditions have terminal
evidence. The current documentation branch does not establish that gate.
