# AP-SPEC-050: Fast and Reproducible Formal CI

**Status:** Proposed
**Intended audience:** formal-method maintainers, CI maintainers, security
reviewers, and contributors changing translated Rust or authored Lean proofs
**Normative language:** the terms **MUST**, **MUST NOT**, **SHOULD**, and
**MAY** are requirements on CI planning, formal jobs, reusable artifacts,
caches, and merge evidence
**Scope:** restructure hosted formal verification so proof defects receive a
fast Lean result before expensive translation qualification; classify changes
by the formal inputs they invalidate; separate translation, Lean, Kani, and
evidence assembly; reuse only content-addressed and provenance-checked work;
and retain clean, byte-identical qualification as required merge and release
evidence
**Depends on:** [AP-SPEC-032](0032-reproducible-release-candidate-and-exact-assurance-claim.md)
for exact-revision assurance claims and the current Aeneas qualification
contract in [`formal/qualification/aeneas/qualification.toml`](../../formal/qualification/aeneas/qualification.toml)

## Abstract

The current formal CI job performs toolchain installation, two clean Aeneas
reproductions, a full Lean build, assurance auditing, Rust refinement tests,
and Kani checks in one serial job. This is correct as a qualification gate but
poor as a development feedback loop. A defect in an authored Lean proof is not
reported until the job has rebuilt or acquired Aeneas, Charon, Lean, and Kani
and reproduced generated sources twice.

This specification creates two deliberately different services:

1. **Fast formal feedback** compiles committed generated sources and affected
   authored Lean modules. It is an early rejection gate, not assurance
   evidence.
2. **Formal qualification** proves that the exact revision is reproducible
   and satisfies the complete Lean, Kani, semantic, and evidence contract.

The complete gate remains authoritative. Speed is obtained by rejecting bad
proofs before it starts, running independent obligations in parallel, and
reusing work only when exact input digests and workflow-produced provenance
show that the work is still applicable. A cache hit never becomes a formal
claim.

The intended contributor experience is:

```text
push
  |
  v
+-----------------------+     actionable Lean diagnostic
| formal proof fast     | -------------------------------> fail (<10 min p95)
+-----------+-----------+
            | pass
            v
+-----------------------+       +------------------------+
| translation evidence  | ----> | authoritative Lean     |
| reproduce or reuse    |       | build + assurance audit|
+-----------------------+       +-----------+------------+
            |                               |
            |        +----------------------+
            |        |
            v        v
       +-------------------+       +----------------------+
       | Kani obligations  | ----> | formal evidence gate |
       +-------------------+       +----------------------+
```

## 1. Current implementation map

| Boundary | Current source |
| --- | --- |
| CI classification | [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml), `ci-plan`; [`xtask/ci-plan`](../../xtask/ci-plan) |
| Formal implementation job | [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml), `formal-translation-run` |
| Lean setup | [`.github/actions/setup-lean/action.yml`](../../.github/actions/setup-lean/action.yml) |
| Rust and Cargo cache setup | [`.github/actions/setup-rust-cache/action.yml`](../../.github/actions/setup-rust-cache/action.yml) |
| Formal orchestration | [`xtask/src/formal.rs`](../../xtask/src/formal.rs), `ci_formal_translation`, `ci_formal_post_qualification`, `build_and_audit_formal` |
| Aeneas qualification | [`xtask/src/formal_qualification.rs`](../../xtask/src/formal_qualification.rs), `qualify` |
| Translation and tool inventory | [`formal/qualification/aeneas/qualification.toml`](../../formal/qualification/aeneas/qualification.toml) |
| Pinned tools | [`formal/translation-toolchain.lock`](../../formal/translation-toolchain.lock), [`formal/lean-toolchain`](../../formal/lean-toolchain) |
| Lean project | [`formal/lakefile.toml`](../../formal/lakefile.toml) |
| Final planned-result gate | [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml), `formal-translation` and `ci-qualified` |

The current pull-request path is effectively:

```text
source-closure preflight
  -> repository preflight
  -> reclaim runner disk
  -> install Nix
  -> build/acquire pinned Aeneas and Charon
  -> install Lean
  -> install and set up Kani
  -> reproduce translation twice
  -> synchronize generated Lean
  -> lake build
  -> assurance audit and qualification cases
  -> semantic vectors and Rust refinement tests
  -> Kani
  -> package evidence
```

The workflow deliberately disables the Rust compiler cache for the formal job
and does not restore a Lean build cache. Independent work is serialized behind
translation even when a change touches only an authored Lean proof.

## 2. Goals and non-goals

### 2.1 Goals

The implementation MUST:

- report an authored Lean proof failure without first running Aeneas, Charon,
  or Kani;
- keep complete formal qualification required whenever the formal contract is
  affected;
- distinguish authored proof inputs, translation inputs, Kani inputs,
  toolchain inputs, and evidence-policy inputs;
- avoid repeating byte-identical translation work after a proof-only retry;
- execute independent Lean and Kani obligations in parallel when their exact
  inputs are available;
- bind every reusable artifact to exact content digests, tool versions,
  workflow identity, and producer run provenance;
- fall back to clean reproduction whenever reuse cannot be proved safe;
- expose phase timings, cache decisions, and the first actionable diagnostic;
- preserve the existing zero-unreviewed-axiom and byte-identical-reproduction
  claims; and
- keep GitHub CI as the authoritative verification environment.

### 2.2 Non-goals

This specification does not:

- weaken, sample, or remove any existing formal claim;
- make a one-reproduction smoke run sufficient merge evidence;
- trust contributor-produced caches or arbitrary uploaded artifacts;
- require contributors or agents to run Lean, Aeneas, Charon, or Kani locally;
- change the Rust-to-Lean semantic boundary;
- change the qualified Rust source inventory or generated Lean format;
- replace the pinned formal toolchain with floating versions;
- make a failed fast job evidence that later jobs would have passed; or
- move formal qualification out of this repository.

## 3. Conformance claims

A passing implementation may claim only the following:

- proof-relevant changes receive an early Lean compilation result before full
  translation qualification starts;
- the planner selects formal work from machine-readable input closures rather
  than an incomplete hand-maintained glob list;
- reusable generated artifacts are accepted only when their exact translation
  and toolchain identities match the consumer;
- the final formal gate covers the same or a stronger set of Lean, assurance,
  qualification, semantic, Rust refinement, and Kani obligations as the
  current gate;
- a reused qualification result identifies its producer run and exact input
  digest, and is independently checked for applicability;
- scheduled and release qualification can force a cache-free, reuse-free
  reproduction; and
- CI records enough timing data to distinguish setup, translation, Lean,
  Kani, and evidence costs.

A passing implementation MUST NOT claim:

- that the fast proof job is formal qualification;
- that a cache entry is evidence of source correctness;
- that matching filenames, timestamps, branch names, or commit ancestry prove
  artifact equivalence;
- that one clean reproduction proves deterministic translation;
- that a successful Lean build proves the Kani obligations;
- that a base-branch attestation applies after any input in its declared
  closure changes; or
- a performance target from a single run.

## 4. Formal input closures

CI planning MUST operate on five versioned closures. Each closure is a sorted,
duplicate-free list of repository-relative files plus a SHA-256 digest over
path and contents. Closure generation belongs to `auths-ci-plan`; workflow YAML
MUST consume its result rather than reimplement path classification.

```rust
pub struct FormalCiPlanV1 {
    pub schema: FormalCiPlanSchema,
    pub head_sha: GitCommitSha,
    pub proof: PlannedFormalPhase,
    pub translation: PlannedFormalPhase,
    pub kani: PlannedFormalPhase,
    pub toolchain: PlannedFormalPhase,
    pub evidence: PlannedFormalPhase,
}

pub struct PlannedFormalPhase {
    pub required: bool,
    pub reason: FormalPlanReason,
    pub base_digest: Option<Sha256Digest>,
    pub head_digest: Sha256Digest,
}
```

`FormalPlanReason` is a closed enumeration rendered to a stable string. It
MUST NOT be an arbitrary diagnostic string used to select workflow behavior.

### 4.1 Proof closure

The proof closure contains:

- authored files under `formal/Auths/`;
- authored Aeneas qualification case modules;
- reviewed external bridge sources or bridge-rendering inputs;
- `formal/lakefile.toml`, `formal/lean-toolchain`, and `formal/lake-manifest.json`;
- generated Lean files as compilation inputs, while recording separately
  whether they were produced by the updater; and
- the assurance manifest and code that selects audited Lean declarations.

A proof-closure change requires the fast proof job and authoritative Lean
build. It does not by itself require Rust translation or Kani.

### 4.2 Translation closure

The translation closure is derived from `source_files`, `translations`, and
the tool records in `formal/qualification/aeneas/qualification.toml`, plus the
code that computes or validates those inventories. It includes every Rust
source, manifest, feature/configuration input, bridge renderer, and extraction
policy capable of changing generated Lean or a translation report.

A translation-closure change requires clean Aeneas/Charon reproduction. The
closure MUST include its own generator and validator code so a PR cannot alter
translation behavior while retaining the old digest.

### 4.3 Kani closure

The Kani closure contains:

- every package and source file containing a gated `#[kani::proof]`;
- the harness inventory and package selection code;
- relevant Cargo manifests, features, and lockfile entries;
- the shipping Rust toolchain and pinned Kani version; and
- code that interprets Kani results.

A Kani-closure change requires the Kani job. An unchanged closure MAY reuse a
successful base-branch Kani attestation under section 8.

### 4.4 Toolchain closure

The toolchain closure contains:

- `formal/translation-toolchain.lock`;
- `formal/lean-toolchain` and `formal/lake-manifest.json`;
- the Nix flake reference or derivation inputs for Aeneas and Charon;
- Kani and Rust pins;
- setup actions; and
- the builder definition for the formal toolchain artifact.

Any toolchain-closure change invalidates every reusable formal artifact and
requires a cold complete qualification.

### 4.5 Evidence closure

The evidence closure contains the CI planner, formal orchestrator,
qualification validator, assurance auditor, workflow jobs, artifact schemas,
and final gate logic. A change to this closure requires a cold complete
qualification and MUST NOT reuse a result produced by the changed evidence
code as the sole justification for its own correctness.

## 5. CI architecture

The workflow is split into explicit jobs with one responsibility each:

```text
                         +----------------------+
                         | ci-plan              |
                         | five input closures  |
                         +----------+-----------+
                                    |
                   +----------------+----------------+
                   |                                 |
                   v                                 v
       +--------------------------+       +-----------------------+
       | formal-update preflight  |       | repository preflight  |
       +------------+-------------+       +-----------+-----------+
                    |                                 |
                    v                                 |
       +--------------------------+                   |
       | formal-proof-fast        |                   |
       | committed generated Lean |                   |
       +------------+-------------+                   |
                    | pass                            |
                    +----------------+----------------+
                                     |
                 +-------------------+-------------------+
                 |                                       |
                 v                                       v
     +---------------------------+           +----------------------+
     | formal-translation        |           | formal-kani          |
     | reproduce or verified     |           | run or verified      |
     | artifact reuse            |           | attestation reuse    |
     +-------------+-------------+           +----------+-----------+
                   |                                    |
                   v                                    |
     +---------------------------+                      |
     | formal-lean-authoritative |                      |
     | clean project outputs     |                      |
     +-------------+-------------+                      |
                   |                                    |
                   +------------------+-----------------+
                                      v
                         +---------------------------+
                         | formal-evidence           |
                         | exact-revision aggregator |
                         +-------------+-------------+
                                       v
                         +---------------------------+
                         | formal-translation gate   |
                         +---------------------------+
```

### 5.1 `formal-proof-fast`

This job is an early rejection gate. It MUST:

1. start after `formal-update-gate` succeeds;
2. use the exact pull-request head;
3. install or restore only the pinned Lean toolchain and Lake dependencies;
4. compile against committed generated Lean after the generated-artifact
   preflight has confirmed that no bounded update is pending;
5. build directly affected authored modules first;
6. build the complete `Auths` and `qualification` Lean libraries after the
   targeted build passes;
7. run without Aeneas, Charon, Kani, semantic vectors, or evidence emission;
8. publish a concise diagnostic summary and the complete Lean log; and
9. be named so the GitHub check clearly says **fast feedback, not
   qualification**.

The first implementation MAY use a conservative fixed target set:

```text
Auths.Refinement.Production
Auths.Product.Refinement
Auths.Lifecycle.Refinement
Auths.Rich.Mutations
qualification
```

Later target selection MAY use the Lean import graph. It MUST fall back to the
complete library build when it cannot prove a narrower dependency set.

The expensive formal jobs MUST depend on this job. A fast-job failure prevents
toolchain-image acquisition and translation reproduction for that revision.

### 5.2 `formal-translation`

This job owns Aeneas/Charon translation only. It MUST either:

- perform two clean reproductions and prove byte identity; or
- accept a reusable `FormalGeneratedArtifactV1` under section 8.

For a translation-closure, toolchain-closure, or evidence-closure change, reuse
is forbidden and two clean reproductions are mandatory. For a proof-only retry
whose translation closure is unchanged, the job SHOULD reuse a successful
translation artifact from an earlier workflow run or the protected base
branch.

If both clean reproductions are byte-identical but differ from the committed
generated inventory, a same-repository pull request MUST package only the
allowlisted generated paths through the bounded formal-update policy. The job
MUST publish that update for the trusted updater, fail before authoritative
Lean or evidence aggregation, and qualify only after the updater's unsigned
commit triggers a new exact-head run. Non-pull-request events fail without
writeback.

The job MUST publish generated Lean, translation reports, the source-closure
record, and a signed workflow attestation. It MUST NOT run the authored Lean
proof build or Kani.

### 5.3 `formal-lean-authoritative`

This job consumes either newly reproduced or verified reusable generated
sources. It MUST:

- verify the generated artifact manifest before extracting files;
- reject files outside the declared generated inventory;
- remove all repository-owned root Lean build outputs before compiling;
- permit caches only for pinned third-party Lake packages and their compiled
  outputs;
- run the full `lake build`;
- run the formal assurance audit;
- build every qualification case module;
- validate warning, generated-file, and external-model inventories; and
- publish the exact declaration and axiom evidence for the consumer head SHA.

Deleting repository-owned `.olean` outputs before this build prevents a
pull-request cache from substituting for compilation evidence.

### 5.4 `formal-kani`

This job runs independently once repository preflight succeeds. It MUST:

- validate the complete harness inventory;
- run every gated package and harness when the Kani closure changed or no
  applicable protected-branch attestation exists;
- use the exact pinned Rust and Kani versions;
- publish a content-addressed result manifest; and
- never treat Lean success as a substitute for Kani success.

Kani installation MUST NOT delay Lean feedback. It runs in its own job or is
provided by the pinned formal toolchain artifact.

### 5.5 `formal-evidence`

This job is the only formal success aggregator. It MUST verify:

- the pull-request head SHA and workflow run attempt;
- the five planned closure digests;
- translation provenance and byte-identical reproduction evidence;
- authoritative Lean build and assurance-audit evidence;
- Kani evidence or an applicable protected-branch attestation;
- Rust refinement tests and semantic-vector stability;
- the absence of a pending generated update; and
- that every consumed artifact was produced by an allowed workflow job for
  exactly the declared inputs.

It emits the existing `formal-translation` planned result consumed by
`ci-qualified`. No implementation job may independently report the final
formal decision.

## 6. Toolchain acquisition

The repository SHOULD publish a formal toolchain artifact or OCI image
containing the exact pinned Aeneas, Charon, Lean/Elan, and Kani installations.
It MUST be rebuilt only when the toolchain closure changes.

The artifact MUST:

- be built by a workflow on the protected default branch;
- be identified by a digest, never a mutable tag alone;
- record the source revisions and binary `--version` outputs;
- carry build provenance produced by GitHub's artifact-attestation mechanism
  or an equivalently verifiable repository-owned attestation;
- be verified before use;
- contain no repository source or generated Auths output; and
- remain replaceable by the current from-source setup as a cold fallback.

Pull requests MUST NOT publish a toolchain artifact eligible for authoritative
reuse. A toolchain-lock change uses the cold path, verifies the new toolchain,
and publishes the replacement only after merge.

The existing disk-reclamation step SHOULD be removed when the toolchain
artifact and decomposed jobs fit within the hosted runner budget. If retained,
its duration and reclaimed space MUST be recorded.

## 7. Cache policy

Caches are performance hints. Artifacts and attestations carry evidence.

### 7.1 Permitted caches

The workflow MAY cache:

- downloaded Cargo crates and installed non-authoritative helper binaries;
- Elan downloads and the pinned Lean toolchain;
- `formal/.lake/packages` source checkouts after revision verification;
- compiled outputs inside pinned third-party Lake packages;
- the Kani installation keyed by exact Rust and Kani versions; and
- fast-job repository-owned Lean outputs under a content-exact key.

### 7.2 Forbidden cache use

The authoritative Lean job MUST NOT accept repository-owned `.olean` files as
proof that current authored or generated sources compiled. It MUST rebuild
those outputs after restoring dependencies.

The evidence gate MUST NOT accept:

- a cache key as a file digest;
- a cache from an untrusted fork as formal evidence;
- a branch name in place of a source-closure digest;
- a partial restore key for repository-owned compiled outputs; or
- any cache after a toolchain- or evidence-closure change.

### 7.3 Cache keys

Every key includes a cache schema version, runner platform, architecture, and
the exact relevant closure digest. Partial restore keys are allowed only for
download or third-party dependency caches.

Example keys:

```text
formal-lean-deps-v1-linux-x86_64-<lean-toolchain>-<lake-manifest-digest>
formal-kani-v1-linux-x86_64-<rust-version>-<kani-version>
formal-fast-v1-linux-x86_64-<proof-digest>-<generated-digest>
```

## 8. Reusable artifacts and attestations

### 8.1 Generated translation artifact

```rust
pub struct FormalGeneratedArtifactV1 {
    pub schema: FormalGeneratedArtifactSchema,
    pub producer_repository: RepositorySlug,
    pub producer_workflow: WorkflowIdentity,
    pub producer_run_id: u64,
    pub producer_run_attempt: u32,
    pub producer_head_sha: GitCommitSha,
    pub translation_closure: Sha256Digest,
    pub toolchain_closure: Sha256Digest,
    pub qualification_manifest: Sha256Digest,
    pub generated_files: BoundedMap<RepoPath, Sha256Digest>,
    pub translation_reports: BoundedMap<RepoPath, Sha256Digest>,
    pub reproduction_count: ReproductionCount,
    pub reproduction_digest: Sha256Digest,
}
```

`reproduction_count` MUST equal two for authoritative reuse. The artifact is
applicable only when the consumer independently computes identical
translation-, toolchain-, and qualification-manifest digests.

An artifact produced by a run that later failed in authored Lean MAY still be
reused when its translation job itself succeeded, both reproductions were
byte-identical, and all applicability checks pass. This is the critical path
for proof-only retries after translation has already succeeded once.

### 8.2 Kani attestation

`FormalKaniAttestationV1` records the Kani closure, Rust and Kani versions,
harness inventory digest, result, producer workflow, and producer commit. Only
a success attestation from the protected default branch or an earlier trusted
job in the same pull-request lineage is reusable.

### 8.3 Trust and applicability rules

The consumer MUST:

1. download by immutable artifact identifier;
2. verify repository and workflow identity;
3. verify GitHub artifact provenance or the repository-owned equivalent;
4. parse a bounded, deny-unknown-fields manifest;
5. independently recompute applicable closure digests;
6. verify every extracted path and content digest;
7. reject symlinks, absolute paths, `..`, duplicates, extra files, and
   oversized archives;
8. record the producer in final evidence; and
9. fall back to a clean run on any mismatch or absence.

Artifact reuse is an optimization decision, not a recoverable warning. An
invalid artifact is rejected; CI does not continue using some of its files.

## 9. Command and planner interfaces

The repository control plane adds these commands:

```text
cargo xtask ci formal-proof-fast
cargo xtask ci formal-translation-reproduce
cargo xtask ci formal-lean-authoritative
cargo xtask ci formal-kani
cargo xtask ci formal-evidence
```

The existing `cargo xtask formal qualify aeneas [--update]` remains the
developer and release entry point for complete qualification. It MUST compose
the same underlying phase functions as hosted CI so the workflow does not
become a second implementation of formal semantics.

`auths-ci-plan plan` adds stable outputs:

```text
formal_proof_required
formal_proof_reason
formal_translation_required
formal_translation_reason
formal_kani_required
formal_kani_reason
formal_cold_required
formal_cold_reason
formal_plan_path
```

The JSON plan is authoritative. Scalar GitHub outputs are projections used for
job conditions and final consistency checks.

The planner MUST reject a file that influences formal behavior but belongs to
none of the five closures. It MUST also reject a file assigned conflicting
roles unless the overlap is explicitly declared; overlap is allowed and means
all affected phases run.

## 10. Developer UX

The GitHub checks MUST make the two service levels unmistakable:

```text
formal proof fast             failed in 4m 12s
  Auths.Refinement.Production:577
  rewrite target uses the underlying vector list
  Full log: <artifact link>

formal translation            skipped: fast proof failed
formal Kani                   cancelled: revision superseded
formal evidence               blocked by formal proof fast
```

On success:

```text
formal proof fast             PASS (cache: dependency hit)
formal translation            REUSED run 12345 (2 identical reproductions)
formal Lean authoritative     PASS (repository outputs rebuilt)
formal Kani                   PASS (executed, 18 harnesses)
formal evidence               PASS for <head-sha>
```

Every failure summary MUST include:

- the failing phase and exact head SHA;
- whether work was executed, restored from cache, or reused by attestation;
- the first actionable source diagnostic, when one exists;
- the complete-log artifact link;
- elapsed time for completed phases; and
- the next required action without suggesting an unsafe bypass.

The updater bot remains responsible for bounded generated changes. A proof
failure MUST NOT be reported as generated drift. Drift detectable from the
lightweight source closure MUST stop before expensive CI; drift discoverable
only by executing the pinned translator MUST stop immediately after the
translation phase and before authoritative Lean or evidence aggregation.

## 11. Security and failure behavior

1. **Fail closed.** Missing, malformed, oversized, stale, or inapplicable
   plans, artifacts, attestations, or caches cause the affected authoritative
   work to execute cold or the job to fail. They never cause a phase to be
   silently skipped.
2. **Exact revision.** Every job verifies the checked-out SHA before doing
   expensive work and records it in its output manifest.
3. **No self-approval.** Evidence-policy or toolchain changes cannot use an
   artifact produced under the changed policy as the sole evidence for that
   change.
4. **Bounded extraction.** Formal artifacts declare maximum file count,
   individual size, total size, and path length. Extraction validates all
   bounds before writing.
5. **No credentials in forks.** Fast feedback works for forks with read-only
   permissions. Reuse that requires unavailable provenance falls back to
   execution; it does not grant write credentials.
6. **Cancellation.** Existing per-ref cancellation remains enabled. Evidence
   from a cancelled job is ineligible unless the producing phase completed,
   uploaded its immutable artifact, and received a successful job conclusion.
7. **Base movement.** A new base SHA does not by itself invalidate an artifact;
   changed closure digests do. Final evidence records both base and head SHAs.
8. **Scheduled cold audit.** At least weekly, CI performs complete
   qualification with translation reuse and repository-owned build caches
   disabled, then compares its outputs with the normal path.
9. **Release cold audit.** Release qualification always performs two clean
   reproductions and rebuilds repository-owned Lean outputs.

## 12. Observability and performance budgets

Each formal phase writes a versioned telemetry record containing start time,
duration, result, runner image, input digests, cache decisions, artifact reuse,
and bounded work counts. It contains no source contents or secrets.

The workflow reports at least:

- runner and disk preparation;
- toolchain acquisition;
- translation reproduction 1;
- translation reproduction 2;
- generated comparison and synchronization;
- third-party Lean dependency build;
- repository Lean build;
- assurance audit;
- Kani installation and execution;
- Rust refinement/semantic checks; and
- evidence validation and upload.

Performance budgets are measured over the most recent 30 qualifying runs:

| Scenario | Budget |
| --- | --- |
| Authored proof failure, warm dependency cache | p95 first diagnostic <= 10 minutes |
| Proof-only retry after applicable translation evidence exists | p95 final formal result <= 20 minutes |
| Translation-changing PR with warm toolchain acquisition | p95 final formal result <= 45 minutes |
| Toolchain acquisition from a published artifact | p95 <= 5 minutes |
| Superseded revision cancellation | p95 <= 2 minutes after replacement run starts |

A budget miss does not weaken or skip verification. It opens or updates one
tracked CI-performance issue with the phase breakdown and regression window.

## 13. Implementation phases

### Phase 1: fast rejection gate

- Add the five-closure planner schema and tests.
- Add `cargo xtask ci formal-proof-fast`.
- Add `formal-proof-fast` after `formal-update-gate`.
- Make all expensive formal work depend on its success.
- Cache only pinned Lean dependencies initially.
- Emit first-diagnostic and phase timing summaries.

This phase is complete when a deliberately broken
`Auths.Refinement.Production` proof fails before Nix, Aeneas, Charon, or Kani
setup begins.

### Phase 2: job decomposition

- Split translation, authoritative Lean, Kani, and evidence aggregation.
- Define bounded versioned phase-result manifests.
- Move Kani installation and execution out of the translation/Lean critical
  path.
- Preserve the existing public `formal-translation` gate name.

This phase is complete when fault-injection tests prove that failure of any
one phase makes the final gate fail and that no sibling result can mask it.

### Phase 3: reusable translation and Kani evidence

- Publish `FormalGeneratedArtifactV1` after byte-identical reproduction, even
  when a later authored Lean job fails.
- Implement exact applicability checks and cold fallback.
- Publish and consume protected-branch Kani attestations.
- Add adversarial archive and provenance tests.

This phase is complete when a proof-only follow-up commit reuses prior
translation evidence while a one-byte translation-closure change forces two
new reproductions.

### Phase 4: pinned toolchain distribution

- Build the formal toolchain artifact on protected `main`.
- Pin consumers to its digest and verify provenance and versions.
- Retain and exercise the cold from-source fallback.
- Remove unconditional `cargo install kani-verifier` from ordinary formal
  runs.

This phase is complete when the published artifact meets the acquisition
budget and a scheduled cold run proves equivalent versions and outputs.

### Phase 5: optimization and enforcement

- Add trusted third-party Lake build caches.
- Add import-graph target selection for fast feedback with full-build fallback.
- Enforce telemetry schemas and performance budgets.
- Add the weekly and release cold-audit comparisons.
- Delete the superseded monolithic orchestration only after differential CI
  runs show identical final decisions and evidence.

No dual formal-decision path remains after cutover. Old workflow jobs and
obsolete commands are removed in the same final change.

## 14. Required tests

### 14.1 Planner tests

- every current formal input belongs to at least one closure;
- adding a qualified Rust source changes the translation digest;
- changing an authored Lean theorem changes the proof digest only;
- changing a Kani harness changes the Kani digest;
- changing setup or evidence code forces a cold run;
- closure order does not change a digest;
- path/content changes do change a digest; and
- unknown formal paths fail planning.

### 14.2 Fast-job tests

- a syntax error produces a source location;
- a failing proof prevents expensive jobs from starting;
- committed generated drift prevents the fast build;
- target-selection uncertainty falls back to a full Lean library build; and
- no fast-job artifact can satisfy the final evidence gate.

### 14.3 Artifact tests

- wrong repository, workflow, run, schema, digest, or toolchain is rejected;
- stale, extra, missing, duplicate, oversized, traversal, absolute, and
  symlink entries are rejected;
- an artifact from a failed translation job is rejected;
- an artifact from successful translation followed by failed Lean is accepted
  only for unchanged translation/toolchain/evidence closures;
- a proof-only retry can reuse translation evidence;
- a translation or evidence change cannot; and
- absent reuse falls back to two clean reproductions.

### 14.4 Final-gate tests

- each missing or failed phase fails the final gate;
- cached dependency outputs never replace repository-owned Lean compilation;
- executed and reused evidence name exact producer and consumer SHAs;
- semantic-vector or Rust-refinement failure fails the gate;
- pending generated updates fail the gate; and
- scheduled cold output matches the optimized path.

## 15. Acceptance criteria

The specification is complete when:

1. a proof-only defect receives a hosted Lean diagnostic within the fast-job
   budget without installing Aeneas, Charon, or Kani;
2. expensive formal work never starts for a revision whose fast proof job
   failed;
3. all formal inputs are classified by machine-generated closures;
4. proof-only retries reuse successful byte-identical translation evidence
   when and only when exact applicability is proven;
5. translation, authoritative Lean, Kani, and final evidence are separately
   visible jobs;
6. the authoritative Lean job rebuilds all repository-owned compiled outputs;
7. the final gate rejects every missing, stale, malformed, or mismatched phase
   result;
8. weekly and release cold runs prove the optimized path has not hidden drift;
9. CI telemetry demonstrates the performance budgets over a 30-run window;
10. the existing formal conformance claims remain intact; and
11. the old monolithic formal-decision path has been removed rather than kept
    as a compatibility implementation.
