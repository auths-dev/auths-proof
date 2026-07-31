# AP-SPEC-032: Reproducible release candidate and exact assurance claim

**Status:** Specified — owner-decision subgate approved; execution still
requires the remaining Phase 7 entry evidence and separate Phase 7 and Phase 8
pull requests

**Governs:** Phase 7 and Phase 8 of the
[Post-Milestone 6 Productization and Release Plan](../target-state/POST_MILESTONE_6_PRODUCTIZATION_AND_RELEASE_PLAN.md)

**Aligned with:** [Post-Milestone-6 Technical and Go-to-Market
Alignment](../plans/POST_MILESTONE_6_TECHNICAL_AND_GO_TO_MARKET_ALIGNMENT.md)

**Depends on:** AP-SPEC-0011, AP-SPEC-0025, AP-SPEC-0026, the completed
Milestone 6 baseline on `main`, the formal assurance manifest, canonical
fixtures, conformance inventories, benchmark evidence, and the existing
release-check machinery

**Scope:** One immutable, reproducible release candidate containing the
completed formal and bounded-authorization program, followed by one exact
public assurance claim bound to that candidate's source revision, semantic
identities, artifact digests, evidence, trusted components, and residual
assumptions

**Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are
requirements on conforming implementations and release operations.

## 1. Decision

Auths will execute Phase 7 and Phase 8 as one coordinated assurance program
with two sequential gates:

```text
completed Milestone 6 revision
          |
          v
Phase 7: freeze semantics, prepare artifacts, reproduce evidence
          |
          v
immutable release-candidate tag and digest-bound evidence bundle
          |
          v
Phase 8: publish the exact claim for that candidate
          |
          v
fixed review target for Phase 9
```

The phases share one specification because an assurance claim without an exact
artifact subject is not reviewable, while a release candidate without an exact
claim boundary invites unsupported interpretation.

They remain separate gates. Phase 8 MUST NOT change the tagged source,
semantic identities, generated formal evidence, fixtures, or release
artifacts. If claim preparation discovers missing evidence, semantic drift, or
an inaccurate statement, the candidate is rejected and Phase 7 produces a new
candidate ordinal. The claim MUST NOT be weakened or worded ambiguously to hide
an artifact defect.

This specification authorizes neither the Phase 10 TypeScript SDK nor any
hosted, production, certification, compliance, SLA, or commercial claim.

## 2. Current baseline

The repository already contains:

- `cargo xtask release-check`, including authoritative CI, package checks,
  documentation, wire checks, SBOM generation, checksums, and release evidence;
- `.github/workflows/release.yml`, which runs release checks and preserves
  crate archives, formal output, and release evidence;
- `formal/assurance-manifest-v1.toml`, the machine-validated formal claim
  inventory;
- qualified Aeneas translation reproduction;
- canonical fixtures, formal vectors, conformance inventories, compliance
  evidence, and bounded benchmarks;
- `docs/assurance-model.md` and the formal paper.

These are implementation inputs, not evidence that Phase 7 or Phase 8 is
already complete. In particular, the current release path:

- builds after a tag event rather than promoting already verified artifacts;
- emits a custom provenance record rather than signed hosted-build provenance;
- emits CycloneDX 1.5 rather than the alignment's SPDX release baseline;
- preserves workflow artifacts temporarily but does not publish one immutable,
  consumer-verifiable assurance bundle; and
- does not yet bind every public claim to the exact release subjects.

Closing these gaps MUST strengthen the existing checks. It MUST NOT replace or
weaken formal qualification, architecture, compliance, dependency, secret,
fixture, domain, or authoritative CI enforcement.

## 3. Goals

This specification MUST produce:

1. one machine-readable semantic-freeze inventory;
2. one content-addressed release-candidate artifact catalogue;
3. one clean-checkout preparation command;
4. two independent preparation runs with explicitly classified
   reproducibility results;
5. one SPDX SBOM per executable or packaged release subject, or one SPDX
   document whose relationships cover every subject unambiguously;
6. signed hosted-build provenance meeting the approved Phase 7 supply-chain
   target;
7. checksums and consumer verification instructions;
8. one immutable release-candidate tag that promotes, rather than rebuilds,
   the verified subjects;
9. one machine-readable exact assurance-claim registry;
10. one human-readable assurance statement generated from or validated against
    that registry; and
11. one fixed candidate and claim bundle suitable for independent Phase 9
    review.

## 4. Non-goals

Phase 7 and Phase 8 MUST NOT:

- publish a stable v1 or general-availability compatibility promise;
- implement Phase 10 or Phase 11 product/runtime work from AP-SPEC-027 through
  AP-SPEC-030; AP-SPEC-030 recruitment and AP-SPEC-031 discovery MAY proceed
  in parallel without changing the RC or making unsupported claims;
- add a new domain, profile, provider, policy language, custody provider, or
  hosted service;
- use release closure as permission for semantic refactoring or optimization;
- claim that Lean proves Rust, storage, credentials, networks, or providers
  beyond the mechanically established boundary;
- claim that a provider is correct, available, atomic, deterministic, or
  exactly-once unless a separately reviewed provider contract establishes the
  exact narrower statement;
- describe the candidate as independently audited before Phase 9 completes;
- publish SOC 2, ISO/IEC 27001, CRA certification, zero-trust compliance,
  production readiness, SLA, RPO, RTO, or support claims;
- make a hosted service necessary to verify artifacts or Auths proofs;
- rebuild artifacts during tag promotion;
- move, replace, or silently delete an issued release-candidate tag; or
- add compatibility machinery for superseded prelaunch candidates.

## 5. Owner decisions and entry gate

Implementation MUST NOT begin until the owner records decisions for the
surfaces affected by the first external release candidate.

The current decision state is maintained in the
[Phase 7 release owner decision register](../plans/PHASE_7_RELEASE_OWNER_DECISIONS.md).
An unresolved recommendation in that register is not approval.

| Decision | Recommended default | Required before |
| --- | --- | --- |
| Release license | Keep `MIT OR Apache-2.0` through v1 | Freezing package and release metadata |
| Inbound contribution policy | DCO or CLA selected with counsel | Public contributor recruitment |
| Artifact catalogue | Source, publishable crates, maintained bindings, WASM/native artifacts, assurance bundle | Release workflow implementation |
| Registry publication | Prepare all subjects; publish only to approved registries | Any external package publication |
| Supply-chain target | SLSA 1.2 Build Level 3 for every first-RC subject; no Level 2 fallback | Provenance contract implementation |
| SBOM baseline | SPDX JSON; CycloneDX MAY be retained as an additional format | Evidence-schema freeze |
| Tag convention | One immutable semver-compatible RC form | Release-tooling implementation |
| Release approvers | At least one named human approver distinct from the build identity | Protected release environment |
| Signing identity | GitHub artifact attestation or an approved Sigstore identity | Artifact promotion |
| Public claim approver | Named technical owner for exact wording and scope | Phase 8 merge |
| Vulnerability and CRA ownership | Named security contact and counsel-reviewed role when external distribution is in scope | Public RC publication |

The entry revision MUST also satisfy:

- Milestones 0 through 6 are complete on `main`;
- no open branch contains a required semantic or evidence fix;
- all required checks on the candidate revision are terminal and successful;
- the worktree used for preparation is clean;
- tracked semantic inventories have complete CI ownership; and
- provider and domain behavior remains outside shared/core code.

## 6. Terminology and identities

- **Candidate revision:** the exact Git commit proposed for the release
  candidate.
- **Preparation run:** a hosted, isolated build of the candidate revision that
  produces subjects and evidence without publishing or tagging them.
- **Release subject:** one source archive, package, binary, image, WASM module,
  binding archive, evidence bundle, or other artifact identified by digest.
- **Semantic freeze:** the versioned inventory of meanings that the candidate
  promises not to change without a new identity or version.
- **Evidence bundle:** the content-addressed collection of manifests,
  checksums, SBOMs, provenance, formal evidence, conformance results,
  benchmarks, and reproduction instructions.
- **Promotion:** attaching the already prepared subjects to an immutable tag
  and approved distribution locations without rebuilding them.
- **Exact assurance claim:** a versioned set of statements whose subjects,
  evidence, scope, assumptions, and exclusions are explicit.

Every manifest MUST use the full Git commit and SHA-256 artifact digests.
Human-readable names and tags are locators, not identities.

## 7. Phase 7: semantic freeze

### 7.1 Freeze inventory

Phase 7 MUST add or generate one machine-readable freeze inventory containing:

- core protocol versions;
- portable ABI and binding contract versions;
- policy, evaluator, and optimized evaluator semantic IDs;
- canonicalization versions;
- exact-action profile and profile-family versions;
- decision, denial, indeterminate, lifecycle, and reconciliation code sets;
- receipt schema versions and commitment meanings;
- canonical fixture and formal-vector manifest digests;
- bounded-domain and profile-inventory digests;
- persisted reservation, claim, execution, and reconciliation state versions;
- required and executed configuration commitment schemes;
- formal assurance-manifest digest;
- benchmark definition and accepted-baseline digests; and
- every source path or generated artifact that owns the frozen meaning.

The inventory MUST distinguish:

- **frozen meaning**, where an incompatible change requires a new semantic
  identity or major/pre-release version;
- **frozen bytes**, where the exact digest is part of conformance; and
- **release metadata**, which may change only in a new release candidate.

The freeze is not a promise to decode or migrate obsolete prelaunch state.
Later incompatible meaning uses a new version and rejects obsolete disposable
state rather than adding compatibility readers or dual paths.

### 7.2 Drift enforcement

CI MUST reject:

- changed frozen bytes without an updated version and review record;
- changed semantics under an existing semantic ID;
- an inventory entry whose source, fixture, test, or manifest does not exist;
- an unregistered decision, denial, indeterminate, transition, or receipt code;
- a profile/evaluator version mismatch;
- a generated artifact that differs from a clean reproduction; and
- a release subject not covered by the release manifest.

Phase 7 closure MAY fix inventory and evidence defects. It MUST NOT change a
decision, command, transition, provider effect, or receipt meaning merely to
make the freeze easier. A semantic change requires a separately specified and
reviewed pre-RC change before the candidate is prepared.

## 8. Phase 7: release subjects and evidence bundle

### 8.1 Required release manifest

The release manifest MUST contain at least:

```json
{
  "schema": "auths.release-manifest/1",
  "release": {
    "tag": "<approved-rc-tag>",
    "status": "release-candidate"
  },
  "source": {
    "repository": "auths-dev/auths-proof",
    "commit": "<full-git-commit>"
  },
  "semanticFreeze": {
    "path": "semantic-freeze.json",
    "sha256": "<digest>"
  },
  "subjects": [
    {
      "name": "<artifact-name>",
      "mediaType": "<media-type>",
      "platform": "<optional-platform>",
      "size": 0,
      "sha256": "<digest>"
    }
  ],
  "evidence": {
    "spdx": ["<digest-bound-path>"],
    "provenance": ["<digest-bound-path>"],
    "formalManifest": "<digest-bound-path>",
    "conformance": ["<digest-bound-path>"],
    "benchmarks": ["<digest-bound-path>"]
  }
}
```

Unknown fields MAY be allowed for compatible metadata extension. Unknown
schema versions, missing subjects, duplicate artifact names, duplicate
semantic identities, relative-path escape, unsupported digest algorithms, and
digest mismatches MUST fail closed.

### 8.2 Evidence bundle contents

The evidence bundle MUST include:

- the release manifest and semantic-freeze inventory;
- `SHA256SUMS` covering every included file other than an explicitly specified
  detached signature over the checksum manifest;
- SPDX SBOMs with package relationships, licenses, versions, and checksums;
- signed hosted-build provenance whose subjects exactly equal the release
  manifest subjects;
- source archive and exact lockfiles/toolchain records;
- formal assurance manifest, theorem inventory, axioms, external models,
  source-closure report, and qualification results;
- byte-identical Aeneas reproduction evidence;
- canonical fixture, formal-vector, conformance, architecture, compliance,
  and domain-inventory reports;
- reference-versus-extracted and reference-versus-optimized differential
  results;
- exact benchmark inputs, environment, reports, and acceptance records;
- native/binding compatibility and package dry-run results;
- secret-scan and dependency-policy results;
- release notes that say `release candidate` and enumerate unsupported claims;
  and
- offline consumer verification instructions.

Release evidence required to trust open artifacts MUST remain public and MUST
NOT require a commercial account.

### 8.3 Reproducibility classes

Every subject MUST declare one class:

| Class | Requirement |
| --- | --- |
| `byte-identical` | Two isolated preparation runs produce identical bytes and digest. |
| `deterministic-evidence` | Regenerated semantic/formal/fixture evidence is byte-identical after normalized paths and approved deterministic metadata. |
| `platform-reproducible` | The declared platform and toolchain reproduce the artifact; the official hosted-build digest remains the distribution identity. |
| `provenance-only` | Bit reproduction is not established; signed provenance identifies the official artifact and the release makes no reproducibility claim for it. |

Source manifests, semantic inventories, canonical fixtures, formal vectors,
generated Lean, assurance registries, checksums, and deterministic reports MUST
be `byte-identical` or `deterministic-evidence`.

An artifact MUST NOT be called reproducible merely because it has provenance.
Any `provenance-only` subject requires a named limitation in the release notes
and Phase 8 claim registry.

## 9. Phase 7: prepare and promote

### 9.0 Separate build integrity from release authority

The release program has two related but non-interchangeable trust paths:

```text
hardened hosted builder -- SLSA/Sigstore --> exact artifact digest

repository owner -- bounded Auths action --> exact promotion authority
```

SLSA/Sigstore evidence identifies the builder, workflow, inputs, and exact
artifact subjects. An Auths proof or receipt MAY additionally establish that a
repository owner authorized one exact promotion action over a candidate
commit, release-manifest digest, tag, destination registry set, and expiry.

An Auths-native release authorization MUST NOT replace, relabel, or weaken the
required SLSA 1.2 Build Level 3 provenance, Sigstore artifact attestation,
SPDX SBOM, reproducibility comparison, or protected human approval. The Auths
protocol and SDK remain independent of GitHub, OIDC, Sigstore, and hosted
verification services.

For the first RC, an Auths authorization checked by code built from the same
candidate is defense-in-depth only and MUST NOT be its sole authority gate. A
later RC MAY make the check mandatory when verification uses a previously
reviewed, digest-pinned Auths verifier or another independently qualified
non-circular bootstrap. Any Auths denial is terminal for the same inputs; an
operator or agent MUST NOT turn retry into additional authority.

### 9.1 Preparation

One canonical command MUST prepare the complete candidate from a clean
checkout. It MAY orchestrate existing `xtask` commands, but it MUST not require
manual edits between steps.

Preparation MUST:

1. verify the exact candidate commit and clean tree;
2. run the complete required CI and release gates;
3. rebuild all deterministic and generated evidence;
4. package every approved subject;
5. generate SBOMs, provenance subjects, checksums, and the release manifest;
6. validate the evidence graph and semantic-freeze inventory;
7. run a second isolated reproduction;
8. compare results by declared reproducibility class;
9. store the approved subjects in content-addressed staging; and
10. emit the manifest digest for human approval.

The second run MUST start from a fresh checkout and empty build-output
directories. Shared caches MAY accelerate dependency retrieval but MUST NOT be
accepted as release subjects or hide missing declared inputs.

### 9.2 Promotion

After all required checks are terminal and successful, the authorized owner
creates the immutable RC tag at the candidate commit. Promotion MUST:

- verify that the tag, candidate commit, workspace version, semantic freeze,
  staged release manifest, and approval agree;
- retrieve every subject by recorded digest;
- verify checksums, SBOM subject coverage, and signed provenance;
- attach or publish the exact staged bytes;
- attach consumer-verifiable attestations;
- mark the GitHub release and registry versions as prerelease where supported;
- publish the evidence bundle and verification instructions; and
- prove that no build or evidence-generation step ran during promotion.

The current tag-triggered release workflow MUST be changed or wrapped so it
promotes prepared artifacts rather than creating new release bytes.

### 9.3 Failure and withdrawal

Before promotion, any mismatch aborts the candidate and publishes nothing.

After promotion:

- the tag MUST NOT move;
- the artifacts and evidence MUST NOT be overwritten;
- a defective candidate is marked withdrawn with a bounded reason and security
  guidance;
- fixes use a new commit and new RC ordinal; and
- a withdrawal MUST NOT be represented as successful Phase 7 completion.

## 10. Phase 7 exit gate

Phase 7 is complete only when:

- the owner decisions in Section 5 are recorded;
- one clean `main` revision contains the completed Milestone 6 program and all
  release-contract changes;
- every frozen identity and byte set is inventoried and drift-enforced;
- two isolated preparation runs satisfy every declared reproducibility class;
- every release subject is checksum-, SBOM-, and provenance-covered;
- provenance meets the approved supply-chain target;
- consumer verification succeeds without repository write access or an Auths
  service;
- promotion publishes the exact prepared bytes and performs no rebuild;
- the immutable tag resolves to the recorded candidate commit;
- the release is clearly labeled as a candidate, not stable v1; and
- the evidence bundle contains the internal assurance manifest needed by
  Phase 8.

## 11. Phase 8: exact assurance-claim contract

### 11.1 Claim layers

The claim registry MUST preserve these distinct layers:

```text
rich Lean authorization semantics
              |
              v
qualified production Rust refinement
              |
              v
bounded representation and state obligations
              |
              v
tested storage, credential, and execution components
              |
              v
trusted nondeterministic provider boundary
              |
              v
observed and receipted provider outcome
```

A stronger layer MUST NOT be inferred from evidence for a weaker or different
layer. In particular:

- a Lean theorem is not automatically a claim about shipping Rust;
- a mechanically translated pure Rust function is not the networked runtime;
- a Kani harness proves only its bounded model and assumptions;
- a passing integration test is not a theorem;
- provider acceptance is not observed success;
- observed success is not provider atomicity or global exactly-once behavior;
- a signed artifact is not necessarily secure; and
- Phase 8 has no independent-audit evidence until Phase 9 completes.

### 11.2 Claim registry

Every public security claim MUST exist in one machine-readable registry entry
with:

```json
{
  "claimId": "AUTHS-RC-<stable-id>",
  "text": "<exact public wording>",
  "subjects": ["sha256:<artifact-digest>"],
  "classification": "theorem|refinement|bounded-model|test|audit|assumption|exclusion",
  "evidence": ["<digest-bound evidence reference>"],
  "trustedComponents": ["<explicit component or boundary>"],
  "residualAssumptions": ["<explicit assumption>"],
  "exclusions": ["<what the claim does not establish>"],
  "compatibility": "<applicable semantic and artifact versions>"
}
```

The registry MUST reject:

- prose claims without artifact subjects;
- evidence that is absent from or digest-inconsistent with the RC bundle;
- theorem claims without exact declarations and premises;
- refinement claims without production source closure and qualification
  evidence;
- bounded-model claims without limits and representation assumptions;
- test claims without exact suite, revision, and result;
- `audit` classification before a scoped independent report exists;
- empty trusted-component or residual-assumption fields when the evidence has
  such dependencies;
- provider or production claims that exceed recorded evidence; and
- compatibility language broader than the frozen versions.

### 11.3 Human-readable assurance statement

Phase 8 MUST publish one concise assurance statement generated from or
validated against the claim registry. It MUST:

- name the RC tag, commit, release-manifest digest, and claim-registry digest;
- distinguish proved, mechanically connected, model-checked, tested, trusted,
  and excluded surfaces;
- list foundational axioms, external models, toolchains, and runtime trust;
- identify provider behavior outside the proof;
- distinguish authorization, durable execution authorization, provider
  acceptance, unknown outcome, reconciliation, and observed postcondition;
- state that the artifact is a release candidate and has not yet completed
  Phase 9 independent review;
- state version and compatibility limits; and
- link directly to offline verification instructions and evidence subjects.

The paper, release notes, `docs/assurance-model.md`, security documentation,
and later website or sales material MUST use this registry as the source of
claim truth. Separate repositories MUST consume the published claim artifact
or pinned release metadata; they MUST NOT use mutable sibling paths.

### 11.4 Claim synchronization

CI MUST inventory public security-claim locations and fail when:

- public wording has no registry entry;
- wording changes without a claim-registry change;
- a claim references a different RC, semantic identity, or artifact digest;
- excluded provider behavior is described as proved;
- `audited`, `certified`, `production-ready`, `compliant`, or equivalent
  language appears without the separately required evidence; or
- generated claim documentation is stale.

Guidance and explanatory prose MAY summarize claims, but it MUST preserve the
same scope and MUST NOT omit limitations in a way that materially strengthens
the statement.

## 12. Phase 8 exit gate

Phase 8 is complete only when:

- Phase 7 completed for one immutable, non-withdrawn RC;
- every public security claim maps to exact RC subjects and evidence;
- every theorem-backed claim names its declaration, premises, source closure,
  and residual assumptions;
- bounded-model and test-backed claims state their limits;
- trusted runtime, build, storage, credential, operator, and provider
  components are explicit;
- authorization, execution, acceptance, observation, and reconciliation are
  not collapsed into one verdict;
- public-claim synchronization passes;
- the named technical owner approves the exact wording;
- no statement implies independent review has already completed; and
- the claim bundle provides the fixed scope submitted to Phase 9 reviewers.

## 13. Required evidence and adversarial tests

Implementation MUST add tests for:

- dirty-tree and wrong-commit preparation rejection;
- tag, workspace-version, and candidate-commit mismatch;
- missing, duplicate, oversized, malformed, or digest-mismatched subjects;
- incomplete SPDX coverage and license metadata;
- provenance with a wrong repository, workflow, commit, builder, or subject;
- promotion attempting to rebuild or mutate a subject;
- deterministic evidence differing between isolated runs;
- a `provenance-only` artifact presented as bit-reproducible;
- semantic changes under unchanged IDs;
- stale generated formal, fixture, conformance, benchmark, or claim evidence;
- a public claim with no registry entry;
- theorem, refinement, Kani, test, and provider-scope overclaims;
- an audit claim with no Phase 9 report;
- missing assumptions or trusted components;
- provider acceptance presented as observed success;
- withdrawn RC verification; and
- offline verification from a clean environment.

Tests MUST mutate evidence and subjects, not only exercise valid generation.
The implementation MUST prove that a changed byte, digest, source closure,
semantic ID, or claim reference causes a terminal failure.

## 14. Required pull-request and release boundaries

This specification is one semantic contract. Its implementation is not one
large pull request.

The minimum boundaries are:

1. **Decision and specification PR.** Record owner decisions, this
   specification, schemas, and the execution plan. No release implementation.
2. **Semantic-freeze PR.** Add the freeze inventory and drift enforcement.
   No artifact publication or public claim changes.
3. **Release-evidence PR.** Add SPDX, signed provenance subjects, release
   manifest, reproducibility classification, and adversarial validation.
4. **Prepare/promote PR.** Implement isolated preparation, second-run
   comparison, protected approval, immutable tag verification, and no-rebuild
   promotion.
5. **Candidate-closure PR.** Apply only evidence-backed fixes required for the
   candidate, regenerate committed deterministic evidence, and establish the
   final candidate revision. No tag is created until its required checks pass.
6. **Phase 7 promotion event.** Create and promote the immutable RC tag. This
   changes external release state but does not change repository source.
7. **Exact-claim PR.** Add the RC-bound claim registry, public assurance
   statement, and synchronization enforcement. It MUST NOT modify the tagged
   semantics or release subjects.

If the exact-claim PR exposes a Phase 7 defect, stop it, fix the defect through
a new candidate-closure PR, issue a new RC ordinal, and rebind the claim. Do
not combine remediation and claim publication in one review.

Each implementation PR MUST describe its affected claims, frozen identities,
generated artifacts, validation, exclusions, and rollback or withdrawal
behavior. Provider/domain behavior MUST remain profile- or domain-owned.

## 15. Delivery order

1. Record the owner decisions in Section 5.
2. Freeze the semantic and artifact schemas.
3. Implement and validate the semantic-freeze inventory.
4. Upgrade release evidence to the approved SBOM and provenance contract.
5. Implement clean preparation and no-rebuild promotion.
6. Run two isolated preparations and close reproducibility gaps.
7. Merge the final candidate revision after all checks pass.
8. Promote the immutable RC tag and publish its evidence bundle.
9. Build the exact claim registry against those immutable subjects.
10. Publish and synchronize the human-readable assurance statement.
11. Submit the fixed candidate and claim bundle to Phase 9 independent review.

## 16. Completion and handoff

This specification is complete only when both phase exit gates pass.

Completion means:

- a reviewer can retrieve the RC by tag and verify its exact source and
  artifact digests;
- a clean environment can reproduce every artifact according to its declared
  class and can verify official provenance for all subjects;
- semantic meaning cannot drift under the candidate's frozen identities;
- every public security statement has exact evidence, assumptions, exclusions,
  and release subjects;
- the same claim boundary is usable by release notes, documentation, future
  websites, and Phase 9 review without marketing reinterpretation; and
- AP-SPEC-027, AP-SPEC-028, and the provider-neutral implementation portion of
  AP-SPEC-029 remain blocked until AP-SPEC-033 permits an explicitly labeled
  Phase 10 developer preview.

The next technical program after completion is Phase 9 independent review. It
is not SDK implementation by default; reviewer engagement, findings,
remediation, retest, and the no-critical-findings gate still apply.

AP-SPEC-030 recruitment and AP-SPEC-031 problem, buyer, deployment, and
willingness-to-pay discovery may continue alongside this work within their
non-production and evidence-handling boundaries.
