# Auths Proof Core Codebase Gap Analysis

**Status:** Implementation-tracked protocol, security, and engineering audit
**Date:** 26 July 2026
**Scope:** `auths-proof` as the offline authorization kernel
**Release posture:** Prelaunch, pre-audit, zero users; no backward-compatibility
obligation

## Executive summary

The implementation is broad, disciplined, and substantially ahead of a typical
pre-audit codebase. It already contains:

- deterministic canonical CBOR;
- signed delegation and authority attenuation;
- proof composition;
- lifecycle and status evidence;
- assurance evaluation;
- attachments and critical-extension handling;
- executable registries;
- bounded verification and resource reporting;
- deterministic portable results;
- multiple principal-control methods;
- native and WASM-compatible verification;
- a substantial language-neutral conformance corpus.

At the time of this review, `cargo xtask ci` passes, including workspace
formatting, compilation, tests, strict Clippy, architecture checks,
specification synchronization, golden-wire verification, target conformance,
fuzz-smoke execution, and `wasm32-unknown-unknown` compilation.

That does **not** mean that only engineering-assurance work remains. The review
found several places where the advertised security contract is stronger or
less ambiguous than the contract currently enforced by the verifier.

The most important conclusions are:

1. An authorization plan is carried by the proof, but the verifier context does
   not state which plan, quorum, participants, or participant-diversity rule the
   verifier requires. If `KOfN`, `AllOf`, or multi-party approval is intended to
   enforce separation of duties, this is a protocol-level gap: a prover can
   choose a weaker valid plan unless the host separately checks it.
2. Some principal adapters depend on decision-affecting configuration held in
   the constructed adapter instance rather than in the three portable inputs.
   The registry manifest identifies the implementation set, not necessarily
   the exact configured trust state. Consequently, equal proof, action, and
   context bytes are not sufficient to imply an equal verdict across engines.
3. Assurance requirements are matched existentially by role. Because multiple
   delegation intermediates share the same `Intermediate` role, one qualifying
   intermediate can satisfy a requirement even when another intermediate does
   not.
4. Deployment limits are not demonstrably enforced over every input and every
   decision-affecting collection. In particular, the detached canonical-action
   decoder uses protocol hard maxima rather than the deployment limits carried
   by `VerifierContext`.
5. Bound evidence and actually consumed evidence are not the same concept in
   the current unused-evidence check. A method can ignore a bound object while
   the verifier still treats it as consumed.
6. The fuzz harnesses prove that targets build and start, but several important
   paths lack useful structured inputs or independent oracles. Some checks are
   tautological, and the scheduled workflow names a nonexistent target.
7. Normative prose, current code, fixture taxonomy, and portable result
   semantics have drifted in several places. The present `spec-sync` check is
   useful but does not establish semantic synchronization.

No obvious bypass of the basic single-chain signature and attenuation path was
identified in this review. The findings above are nevertheless security
significant. The composition issue is fundamental if the product claims
verifier-enforced threshold approval or separation of duties; the assurance
issue can weaken a policy on multi-hop chains; and unbound adapter
configuration undermines reproducibility and audit claims.

The priority order should therefore be:

1. close and test the protocol contract;
2. make hosted gates authoritative;
3. produce meaningful adversarial and independent evidence;
4. make the supported embedding and WASM surfaces real;
5. make releases and external review reproducible.

## Implementation update — 26 July 2026

The findings below are retained as the review record. The in-repository
contract corrections have now been implemented directly, without legacy
decoders or compatibility modes:

| Finding | Implemented disposition |
|---|---|
| Prover-selected composition | `VerifierContext` now carries a canonical `CompositionRequirement`: optional exact plan ID plus minimum authorized branches, distinct actors, and distinct roots. The portable result binds the plan; downgrade and same-actor shortfall tests fail closed. V1 deliberately defines these as its only independence units. |
| Hidden adapter configuration | Every executable port reports an `AdapterConfigurationId`; configured adapters hash exact trust/credential/checkpoint records; `ImmutableRegistries` derives an order-independent `VerifierConfigurationId`; context and result bind it and mismatches deny. |
| Existential role assurance | Every `AssuranceRequirement` encodes an explicit `Any` or `Every` quantifier. Empty selections fail, `Every` audits every selected participant, and satisfactions identify each required participant. |
| Incomplete portable limits | Action and context byte limits are deployment-controlled; detached attachment bytes have a distinct per-input aggregate limit; context collections use decoded deployment limits. `docs/LIMIT_COVERAGE.md` is checked by `spec-sync`. |
| Binding versus consumption | Every successfully verified statement now requires exact equality between its binding and the selected adapter's reported consumed evidence. |
| Provisional/contradictory contract | CDDL, protocol, algorithm, failure taxonomy, assurance/security docs, context/result wire shapes, and all canonical fixtures were replaced together. Historical target-state material is explicitly nonnormative. The unused competing `auths-status` crate was removed. |
| Divergent hosted gates | Pull-request CI invokes `cargo xtask ci`; release automation invokes `cargo xtask release-check`; the scheduled fuzz matrix covers and inventory-checks every target. |
| Weak portable fuzz path | `target_portable_abi` now mutates a deeply valid proof/action/context tuple with real raw-key, DID-key, KERI, Ed25519, and P-256 registries. Tautological registry assertions were replaced with small reference relations, and composition uses an independently expressed flat-plan oracle. |
| Missing integration surfaces | A compiling external consumer calls `auths-proof::Engine`; generated `wasm-bindgen` JS/WASM/TypeScript artifacts are reproducibility-checked and exercised in Node against byte-identical native results. |
| Missing trace/review material | `docs/TRACEABILITY.md`, `docs/LIMIT_COVERAGE.md`, the WASM support matrix, and `docs/audit/REVIEW_SCOPE.md` are checked or packaged with the release process. |
| Incomplete release gate | The workspace now checks on Rust 1.85.1, publishable packages have complete descriptions and repository metadata, the versioned testkit makes fresh-ecosystem packaging resolvable, and `release-check` passes package dry-runs before emitting an SBOM and provenance record. |

The final local validation passed `cargo xtask release-check`, including the
full CI gate, no-default-feature tests, documentation with warnings denied,
all 506 canonical vectors, all seven fuzz-smoke targets, generated Node/WASM
checks, and publication dry-runs for every publishable workspace package.

Two classes of work cannot truthfully be completed by a repository edit:

1. sustained fuzz campaigns and hostile-resource measurements require elapsed
   campaign time and recorded target hardware; smoke and scheduled machinery
   are implemented, but evidence exists only after those jobs run;
2. independent protocol, cryptographic, and implementation review requires
   external reviewers. The scope and immutable-candidate requirements are
   prepared, but no review is claimed.

The first public compatibility freeze remains intentionally gated on those
external results. Until then, the corrected artifacts remain the sole
normative prelaunch candidate and may still change directly.

## Prelaunch change policy

There are no production users, deployed integrations, or persisted customer
artifacts. Backward compatibility is therefore not a constraint for the work
described here.

Until the launch-candidate protocol is frozen:

- correctness, explicit security semantics, and conceptual simplicity take
  precedence over preserving current Rust APIs, CBOR layouts, fixture bytes,
  result shapes, registry manifests, or crate boundaries;
- breaking changes should be made directly rather than hidden behind
  compatibility modes, deprecated aliases, migration layers, or host-side
  workarounds;
- directories and types currently labelled `v1` are provisional implementation
  artifacts, not a public compatibility promise;
- existing golden vectors remain useful for discovering intended behavior and
  regressions, but they may be deliberately replaced when the corrected
  contract changes;
- no semantic-version comparison against the unreleased API is required;
- the first compatibility baseline should be recorded only after the
  launch-candidate contract, wire format, supported API, and configuration
  model have been approved.

This does not relax security, determinism, resource, portability, or
independent-review requirements. It makes them cheaper to satisfy cleanly.
The preferred sequence is:

```text
correct the contract
  -> simplify the implementation around it
  -> regenerate specifications and vectors
  -> adversarially validate it
  -> freeze the first public compatibility baseline
```

## Security posture and boundary

This review does not recommend turning `auths-proof` into a networked policy
service or application runtime.

The following remain outside the kernel:

- networking and transport;
- online status acquisition;
- databases and resolver clients;
- replay storage;
- identity enrollment and key custody;
- deployment orchestration;
- MCP runtime behavior;
- CLI business logic;
- application-specific policy authoring.

The boundary still needs one refinement: every fact that can change a
verification decision must be either:

- represented in the canonical verifier inputs;
- represented by a digest in those inputs and in the portable result; or
- explicitly documented as host-specific configuration that limits the
  portability claim.

A host may acquire status, DID history, certificate anchors, credential
registrations, KERI checkpoints, or other trust facts from any source. Fact
acquisition remains outside the kernel. Passing or committing to the exact
facts used for a decision belongs at the kernel boundary.

Similarly, application policy can remain outside the kernel while the
application passes a decision-specific obligation into verification. Requiring
an expected plan, quorum, signer set, or diversity constraint does not require
putting a general policy engine into `auths-proof`.

## Priority 0 — Close the protocol and security contract

### 1. Make composition a verifier-required obligation

`AuthorizationPlan` is part of the proof bundle. The actions bind to the plan
identifier, so the implementation protects the integrity of the plan selected
by the proof. `VerifierContext`, however, does not express:

- an expected plan or plan identifier;
- a minimum quorum;
- a required participant set;
- distinct-principal, distinct-root, or distinct-method requirements;
- whether multiple leaves may be satisfied by the same authority chain;
- an application-provided composition predicate.

`KOfN` currently counts authorizing leaves. A unique `ProofRef` prevents the
same leaf identifier from occurring twice, but it does not by itself establish
independent people, roots, credentials, methods, or trust domains.

This distinction must be made explicit:

```text
proof integrity:
  "these signed branches satisfy this proof-carried plan"

verifier policy:
  "this action requires this plan/quorum/diversity"
```

Only the first statement is directly enforced today.

The recommended prelaunch design is to add a canonical, verifier-trusted
composition obligation directly to the verification contract. It may be
carried in `VerifierContext` or in a separate bounded policy object whose digest
is bound by the context and portable result. It should express:

- an expected plan identifier or acceptable plan shape;
- quorum requirements;
- the unit of independence being counted;
- required or forbidden participants;
- distinct-principal, distinct-root, distinct-credential, distinct-method, or
  distinct-trust-domain rules where applicable.

Do not preserve the current prover-selected behavior through a legacy mode
solely because it already exists. If the intended product feature is only
prover-selected proof aggregation, rename and document it that way before
launch rather than presenting it as verifier-enforced threshold approval.

Required adversarial tests include:

- replace `KOfN` with a one-leaf `Proof`;
- reduce `k` while keeping all supplied branches valid;
- submit multiple leaves controlled by the same principal;
- submit multiple leaves deriving from the same root;
- clone the same authority chain into distinct `ProofRef` leaves;
- reuse evidence across branches;
- vary branch order without changing semantics;
- prove that a host-required plan or diversity rule cannot be weakened by the
  prover.

**Exit criterion:** An `Authorized` result proves both that the supplied
branches satisfy the plan and that the plan satisfies a verifier-trusted
composition obligation whose independence semantics are explicit.

### 2. Bind all decision-affecting engine and adapter configuration

The public operation is described as a deterministic three-input function over
proof, action, and context. Some adapters, however, are constructed with local
records or trust state, including examples such as:

- bundled DID-web records;
- WebAuthn credential registrations;
- HSM attestation or key records;
- SPIFFE/X.509 trust material and status;
- KERI checkpoints or accepted history.

The exact inventory should be generated from the implementation rather than
maintained only in prose.

`ImmutableRegistries::manifest_id()` identifies the pinned target registry
manifest. It does not currently demonstrate that two instances contain the
same decision-affecting adapter configuration. This permits the following
undesirable condition:

```text
same proof bytes
+ same action bytes
+ same context bytes
+ same registry manifest
+ different adapter configuration
= potentially different result
```

Use the freedom to break the current ABI to adopt one coherent architecture.
The cleanest default is to separate:

- a canonical per-request context containing audience, challenge, evaluation
  time, status snapshots, and the expected composition obligation; and
- a canonical verifier profile/configuration containing exact adapter trust
  records, accepted implementations, policies, and other stable
  decision-affecting state.

Bind both digests into the portable result. A host registry still supplies
executable implementations, but it must prove an exact match to the canonical
profile. If embedding the complete configuration in `VerifierContext` produces
a simpler final model, that is also acceptable.

Do not retain the three-input façade merely to avoid breaking an unreleased
API. Prefer an explicit fourth canonical input or a deliberately redesigned
context over a hidden engine-instance dependency.

Implementation identifiers, versions, and configuration digests serve
different purposes and should not be conflated.

Required tests include:

- the same four inputs produce byte-identical results across process restarts;
- changing any decision-affecting configuration changes a bound digest;
- reordering equivalent configuration does not change its digest;
- omitted, duplicated, or ambiguous trust records fail closed;
- native and WASM consumers can identify the exact configuration commitment
  used for a verdict.

**Exit criterion:** The reproducibility invariant is stated precisely as
`proof + action + context + bound configuration -> result`, with no hidden
decision-affecting state.

### 3. Quantify assurance over every intended participant

`ParticipantRole` contains `Root`, `Intermediate`, `Actor`, and
`ExternalIssuer`. A chain can contain multiple intermediates, all reported with
the same role. `evaluate_with_implications` finds a qualifying
role-and-claim candidate for each requirement. It does not require every
participant with that role to qualify.

For example, a policy requiring a fresh hardware-backed claim for
`Intermediate` may be satisfied by one strong intermediate even when another
intermediate is software-only or stale.

The policy model needs explicit quantification. Suitable options include:

- `AnyParticipantWithRole`;
- `EveryParticipantWithRole`;
- an exact principal or chain-position selector;
- a global per-participant requirement;
- bounded count or quorum requirements.

Change the wire model and result shape directly. Do not add a compatibility
default that silently interprets old role-only requirements as existential.
Every requirement should encode its selector and quantifier. Normative prose
must not say “every principal” when a quantifier is existential.

Required tests include chains with:

- two or more intermediates with unequal assurance;
- one fresh and one stale claim;
- one expected and one unexpected adapter;
- repeated principals in different chain positions;
- no participant for a selected role;
- claim implication satisfied for only a subset of participants.

**Exit criterion:** Every assurance requirement records its selector and
quantifier, and the result identifies all satisfactions necessary to audit that
quantifier.

### 4. Enforce deployment limits over every verifier input and work source

`decode_bundle` receives `VerifierLimits`. `decode_canonical_action` instead
uses protocol hard maxima. This means a deployment can configure a lower
canonical-body limit while the separate canonical-action input is decoded
against only the hard maximum.

Change decoder signatures and portable input shapes where necessary. There is
no reason to preserve an inconsistent unreleased boundary.

The same audit must be performed for context decoding and construction.
Decoding context with hard maxima and validating only selected collections in
`VerifierContext::new` is insufficient unless every configurable limit is
proven to be applied later and before material work or allocation.

Create a generated or reviewed limit-coverage matrix:

| Input/work source | Protocol hard maximum | Deployment limit | Enforcement point | Boundary vectors |
|---|---:|---:|---|---|
| Proof bundle bytes and nesting | Required | Required | Before allocation/recursion | `limit-1`, `limit`, `limit+1` |
| Canonical action body and attachments | Required | Required | Portable boundary | Same |
| Context collections and snapshots | Required | Required | Decode/construction | Same |
| Plan nodes, leaves, and depth | Required | Required | Decode and validation | Same |
| References, bindings, grants, actions, evidence | Required | Required | Decode/resolution | Same |
| Cryptographic and adapter work | Required | Required | Before expensive work | Same |
| Hashing, sorting, and comparison work | Required | Required or bounded rationale | Before amplification | Same |

The final matrix should enumerate every actual `LimitKind`; the table above is
only the minimum shape.

Verifier-reported work units currently cover selected handlers and adapter
operations. Do not imply that they measure all CPU, allocation, parsing,
hashing, sorting, or reference-resolution cost unless those paths are charged.
Keep deterministic logical metering and observed resource measurements as
separate claims.

**Exit criterion:** Every deployment limit has a reachable enforcement point
for every relevant input path, and boundary tests prove that lowering a limit
cannot be bypassed by moving equivalent data to another input.

### 5. Make evidence consumption exact

The verifier rejects evidence objects that are not mentioned by a binding, but
the global consumed set is derived from binding references and status
checkpoints. Principal adapters separately return
`ControlEvidence::consumed_evidence()`.

Those sets are not equivalent. A bound evidence object can count as globally
consumed even if the selected adapter ignored it.

This weakens the meaning of `UnusedCriticalEvidence` and creates an avoidable
malleability/smuggling surface. The invariant should be:

```text
every supplied evidence object is
  required by a validated statement/status binding
  and reported as consumed by the exact selected verifier,
or is represented by an explicit, specified non-critical evidence category
```

The current model should not claim that arbitrary “irrelevant non-critical
evidence” is harmless unless such a category exists in the wire model.
Change the binding or evidence model directly if exact consumption cannot be
expressed with the current shape; do not retain ambiguous evidence semantics
for wire compatibility.

Required tests include:

- bound but adapter-ignored evidence;
- adapter-reported evidence not present in the relevant binding;
- the same evidence consumed by incompatible statements;
- evidence consumed across composition branches;
- extra unbound evidence;
- duplicate semantic evidence under distinct object identifiers.

**Exit criterion:** Evidence liveness is derived from actual verifier
consumption and exact binding rules, not binding membership alone.

### 6. Replace the provisional contract with one normative launch contract

Current documentation and code disagree in security-relevant ways. Examples
found during this review include:

- target-state material refers to bridge modes or bridge-grant behavior that
  is not part of the current implementation;
- planning material promises ordered diagnostics, while the portable result
  exposes one primary stage/code outcome;
- documented verification stages do not consistently match
  `VerificationStage`;
- documented corpus classes do not match the committed manifest directories;
- `docs/assurance-model.md` refers to APIs or limitations that are no longer
  accurate, including `VerificationPolicy`-style profiles and KERI assurance
  behavior;
- `auths-status` implements status evaluation while the active verifier path
  relies on status handlers in `auths-registries`, leaving competing semantic
  implementations or an unused dependency;
- historical target-state and review documents are easy to mistake for the
  current normative contract.

The current `xtask spec-sync` gate checks useful artifacts, including stable
codes and corpus coverage. It does not prove that prose rules and code
semantics agree.

Although current paths and types use the name `v1`, the repository is
prelaunch. Treat that label as provisional. The corrected contract can become
the first public V1; there is no need to preserve known design mistakes and
then launch immediately with a V2 migration problem.

For each divergence, choose exactly one disposition:

- implement it;
- remove it;
- mark it nonnormative/historical;
- defer it with an explicit launch limitation.

Do not build a traceability matrix over a contradictory contract. First freeze
one normative source of truth, then mechanically connect it to types, code,
vectors, and tests. Delete or regenerate obsolete fixtures and golden bytes
after the replacement contract is approved.

**Exit criterion:** A reviewer can identify the one normative launch contract,
and cannot derive a stronger or conflicting guarantee from provisional code,
old vectors, or adjacent historical plans.

## Priority 1 — Correct the required engineering gates

### 7. Make `cargo xtask` authoritative in hosted CI

The local quality gate is stronger than the GitHub Actions gate.
`.github/workflows/ci.yml` manually reproduces only part of `cargo xtask ci`
and omits at least specification synchronization and fuzz-smoke execution.

Hosted CI should invoke:

```text
cargo xtask ci
```

Release automation should invoke:

```text
cargo xtask release-check
```

Jobs may decompose commands for parallelism and diagnostics, but one required
gate must prove that the complete authoritative command passes.

**Exit criterion:** Local, pull-request, protected-branch, and release
definitions cannot silently diverge.

### 8. Repair the scheduled fuzz workflow

`.github/workflows/fuzz.yml` invokes `parse_bundle`, which is not a target in
the current fuzz workspace.

The implemented targets are:

- `target_codec`;
- `target_portable_codecs`;
- `target_model_state`;
- `target_composition`;
- `target_registry_handlers`;
- `target_principal_parsers`;
- `target_portable_abi`.

Derive the scheduled matrix from the fuzz manifest or the same inventory used
by `xtask`. Adding or removing a target should fail CI until the schedule is
synchronized.

**Exit criterion:** Every current target builds in pull requests and receives a
bounded scheduled campaign with retained artifacts.

## Priority 2 — Produce meaningful adversarial evidence

### 9. Replace fuzz smoke with structured campaigns and real oracles

The seven targets are a useful foundation, but the current corpus and smoke
runs are not security evidence:

- each target begins with one five-byte seed;
- pull-request smoke execution performs only eight runs;
- `target_portable_abi` divides arbitrary bytes into thirds, which rarely
  forms a valid proof/action/context tuple;
- that target verifies committed raw-key inputs using empty principal and
  signature registries, so it does not exercise a successful deep path;
- some digest and handler assertions compare an expression with itself;
- repeatability against the same implementation detects nondeterminism but not
  a consistently wrong result.

Keep smoke runs as build/start checks. Add a separate adversarial program:

1. Frame proof, action, context, and bound configuration as a structured tuple.
2. Seed each target from valid and invalid canonical corpus artifacts.
3. Register the real methods and suites required by positive seeds.
4. Mutate one semantic field at a time from a deeply valid input.
5. Track coverage by verifier stage, stable denial reason, requirement, adapter,
   and limit boundary.
6. Retain minimized crash, timeout, excessive-resource, and semantic-mismatch
   artifacts.
7. Promote every high-value artifact to an ordinary regression test.

Useful oracles include:

- a small independent reference model for attenuation and composition;
- differential decoding or adapter verification against an independent
  implementation;
- metamorphic relations whose expected outcome is specified;
- native/WASM byte equality;
- encode/decode canonicality checked through independent paths;
- policy monotonicity properties;
- expected-result vectors reviewed independently of the corpus generator.

The committed corpus is generated by `auths-testkit`, and expected results are
obtained from the same verifier later checked by conformance. This is strong
regression and wire-stability evidence, but it is circular as evidence of
semantic correctness. At least one independent oracle is required for every
critical rule family.

During contract correction, regenerate structured seeds from the approved
schema instead of teaching fuzz targets to accept both old and new formats.
Retain old inputs only when they are valuable malformed-input or downgrade
regressions.

### 10. Expand property and state-machine testing

Add properties covering at least:

- delegation can narrow authority but never expand it;
- a verifier-required composition obligation cannot be weakened by the proof;
- `KOfN` counts the specified unit of independence, not just distinct leaves;
- plan evaluation is deterministic and order-independent where required;
- status sequence numbers cannot roll back;
- every participant selected by an assurance quantifier must qualify;
- changing decision-affecting configuration changes its bound commitment;
- lowering a deployment limit cannot make a previously over-limit input pass
  through another input path;
- resource accounting is deterministic and monotonic over the work it claims
  to cover;
- unknown registry identifiers never fall back to another implementation;
- canonical decode-encode-decode behavior is stable;
- native and portable entry points agree;
- malformed adapter inputs never panic;
- `Authorized` is impossible unless every required stage completes;
- extra unbound evidence is denied;
- every bound evidence object is actually consumed by the selected verifier;
- missing or ignored critical evidence cannot silently authorize;
- `Indeterminate` never becomes `Authorized` through retry, fallback, or host
  coercion without new trusted facts.

State-machine tests are particularly valuable for delegation, composition,
status evolution, registry selection, adapter configuration, and assurance
over changing chain membership.

### 11. Add adapter-specific adversarial and differential suites

Generic parser fuzzing is insufficient for trust-method semantics.

| Adapter area | Minimum adversarial cases |
|---|---|
| KERI | forked history, prefix mismatch, checkpoint equivocation, threshold boundaries, duplicated signers, truncated later events, independent KERI implementation vectors |
| DID-web | duplicate JSON members, percent/port/path normalization, relationship confusion, key-history ambiguity, stale local record |
| WebAuthn | duplicate JSON members, RP ID/origin relationship, flags and counters, credential substitution, DER/raw signature boundaries |
| SPIFFE/X.509 | path ambiguity, critical extensions, name constraints, SAN/EKU confusion, trust-domain crossing, status equivocation, oversized certificates |
| HSM attestation | stale/revoked/exported key state, transaction mismatch, attestation-chain substitution, configuration-record mismatch |
| Raw key and DID-key | algorithm confusion, malformed encodings, noncanonical keys, signature malleability, method/suite mismatch |

For configured adapters, every suite must test both the evidence bytes and the
bound configuration commitment. Where a credible independent implementation
exists, pin its version and retain the exact differential inputs and outputs.

### 12. Measure hostile resource behavior

Add reproducible benchmarks and adversarial tests for:

- a maximum legal proof graph;
- maximum delegation depth;
- maximum composition fan-out;
- large attachment manifests and detached bodies;
- invalid signatures and adversarial key encodings;
- malformed CBOR at every truncation point;
- repeated, duplicate, missing, and cyclic references;
- status-heavy and assurance-heavy proofs;
- maximum unsupported or unknown registry inputs;
- repeated `Indeterminate` outcomes and host retry amplification.

Record:

- exact commit and toolchain;
- target architecture;
- build profile and features;
- hardware and operating system;
- input dimensions;
- wall-clock distribution;
- peak memory or allocation counts;
- stack-depth observations where relevant;
- verifier-reported logical work units.

The host contract must require bounded retries and must forbid fallback from
`Indeterminate` to authorization. An attacker who can cheaply force missing or
stale evidence must not be able to amplify expensive resolution work outside
the kernel.

**Exit criterion:** Maximum legal and minimally illegal inputs have
reproducible CPU, memory, stack, allocation, and logical-meter behavior on
supported targets.

## Priority 3 — Make the supported API genuinely embeddable

### 13. Add a real external integration example

`auths-proof::Engine::verify_cbor` is the intended general façade, but the
repository does not yet demonstrate a fully supported external path:

- workspace doctests contain no executable examples;
- `examples/offline-verification/README.md` references a fixture that does not
  exist;
- the same document refers to `inspect` and `verify` commands that are not
  provided by this repository.

Add an external-crate example that:

1. constructs an exact immutable registry and any bound configuration;
2. loads or embeds a real committed fixture;
3. calls the supported façade;
4. handles `Authorized`, `Denied`, and `Indeterminate` separately;
5. exposes the stable code, stage, digests, and resource report;
6. checks the verifier-required composition obligation;
7. demonstrates that `Indeterminate` is neither authorization nor necessarily
   permanent denial;
8. performs no I/O inside verification.

Use the same path in executable rustdoc examples and run it in the required
gate.

### 14. Test WASM as an actual distribution

The WASM package has a native Rust test around the portable boundary. That
does not exercise generated JavaScript bindings or runtime behavior.

Add Node and, where practical, headless-browser tests for:

- generated `wasm-bindgen` artifacts;
- `Uint8Array` input/output behavior;
- malformed and truncated arrays;
- protocol verdicts versus JavaScript exceptions;
- byte-for-byte native/WASM result equivalence;
- exact configuration commitment behavior;
- package initialization;
- deterministic packaging;
- generated TypeScript declarations.

If some configured native adapters cannot be shipped to WASM, publish an
explicit supported-method/profile matrix and make unsupported combinations
fail closed.

### 15. Minimize the public API, then establish its first baseline

Before the launch-candidate freeze:

- freely rename, move, combine, or remove public items that do not belong in
  the supported façade;
- classify publishable and internal crates;
- exercise the proposed façade from an external crate;
- deny documentation warnings and enforce complete docs on candidate exports;
- avoid compatibility shims, deprecation cycles, and semantic-version checks
  against unreleased snapshots.

At the freeze:

- approve the exact publishable crates and supported exports;
- record the first public API snapshot and initial semantic version;
- enable compatibility checks for every subsequent change;
- complete package metadata and publication dry runs.

The goal is to launch with a small, coherent API rather than freeze today's
surface prematurely.

## Priority 4 — Make releases and reviews reproducible

### 16. Complete the release gate

Extend `release-check` or the surrounding release workflow with:

- Rust 1.85 MSRV verification, not only the current stable toolchain;
- creation of the initial public API baseline;
- creation of the initial canonical-wire and portable-result baseline;
- documentation generation with warnings denied;
- publication dry runs;
- dependency and license reports;
- SBOM generation;
- source and artifact provenance;
- reproducible native and WASM build checks;
- clean-worktree validation;
- corpus, registry, configuration, and specification digest validation;
- release-candidate version and tag consistency.

`cargo deny` already runs separately in hosted automation. Its result should
remain a required release condition and appear in the single release summary.

Do not compare the launch candidate against provisional prelaunch APIs or wire
bytes. The release gate should instead prove that the approved launch artifacts
are internally consistent, reproducible, and recorded as the baseline that
future compatibility checks will protect.

### 17. Generate specification-to-test traceability

After the normative contract is reconciled, generate a matrix of:

```text
normative rule
  -> implementation location
  -> positive vector
  -> negative vector
  -> property/fuzz/differential oracle
  -> native result
  -> WASM result
```

Cover:

- canonical encoding;
- signed fields and domains;
- identifier derivation;
- graph and reference rules;
- attenuation;
- verifier-required composition;
- status;
- assurance selectors and quantifiers;
- evidence consumption;
- registry and configuration selection;
- resource limits;
- portable-result normalization.

This matrix should fail generation when a normative rule exists only in prose,
only in code, or only in an incidental fixture.

### 18. Eliminate documentation and security-policy drift

`SECURITY.md`, the offline-verification example, assurance documentation, and
some target-state material do not accurately describe the present repository.
For a security product, stale boundary documentation can be as harmful as a
missing code comment because integrators may rely on the wrong guarantee.

Generate facts from code, registries, manifests, and package metadata wherever
possible. Clearly label retained plans and implementation reviews as
historical or superseded.

Security documentation must distinguish:

- implemented protocol guarantees;
- guarantees conditional on host-provided obligations;
- host obligations and retry behavior;
- supported adapters and suites;
- exact sources of decision-affecting trust;
- portability limitations;
- pre-audit warnings;
- externally validated claims.

### 19. Commission independent review

Before presenting the kernel as production-grade, commission independent
protocol, cryptographic, and implementation review covering:

- the composition-policy boundary and signer independence;
- canonical decoding and signed-byte construction;
- domain separation and identifier derivation;
- algorithm-confusion resistance;
- delegation attenuation;
- status freshness and sequence rollback;
- assurance quantification;
- evidence binding and actual consumption;
- adapter configuration commitments;
- adapter-specific trust assumptions;
- denial versus indeterminate classification;
- adversarial CPU and memory behavior;
- native and WASM equivalence.

Begin review after the contract, CI, fuzzing, documentation, and supported API
have stabilized. Resolve findings against an immutable launch candidate and
commit safe regression vectors to the public corpus.

## Recommended implementation order

### Immediate contract closure

1. Declare current APIs, `v1` wire artifacts, registries, and fixtures
   provisional and explicitly permit breaking changes.
2. Add verifier-required composition policy and define the counted unit of
   independence.
3. Introduce a canonical bound verifier profile/configuration.
4. Add explicit assurance selectors and quantifiers.
5. Complete the limit-coverage matrix and fix bypassing input paths.
6. Reconcile actual versus bound evidence consumption.
7. Replace competing or unused semantic implementations.
8. Approve one normative launch contract and regenerate its canonical corpus.

### Engineering and adversarial evidence

9. Make `cargo xtask ci` authoritative in hosted automation.
10. Fix the obsolete scheduled fuzz target.
11. Replace arbitrary input splitting and tautological assertions with
    structured seeds and meaningful oracles.
12. Add composition, assurance, evidence, configuration, limit, and adapter
    adversarial suites.
13. Add independent vectors or reference models for critical semantics.
14. Measure hostile maximum-input behavior.

### Integration and release hardening

15. Add the compiling external Rust example and executable façade docs.
16. Test generated WASM artifacts in consumer runtimes.
17. Minimize and approve the supported API.
18. Add MSRV, documentation, packaging, SBOM, provenance, and
    reproducibility gates.
19. Generate specification-to-test traceability.
20. Freeze the first public API/wire baseline.
21. Commission independent review against the fixed release candidate.

## Completion criteria

This gap analysis is satisfied only when:

- a verifier-trusted obligation determines the required composition semantics,
  and prover-selected composition cannot weaken it;
- signer/branch independence is defined and adversarially tested;
- every decision-affecting configuration value is present or committed to at
  the portable boundary and result;
- identical proof, action, context, and configuration produce byte-identical
  results;
- assurance requirements state their selector and quantifier and cover every
  intended participant;
- every deployment limit has complete input-path coverage and boundary vectors;
- every supplied evidence object is exactly bound and actually consumed under
  specified rules;
- the normative launch documents, types, stages, codes, fixtures, and active
  implementations agree;
- GitHub and local development enforce the same authoritative gate;
- every fuzz target receives bounded pull-request execution and sustained
  scheduled campaigns;
- fuzz campaigns use structured valid seeds, real registries, semantic
  mutations, coverage goals, and non-tautological oracles;
- at least one independent oracle covers each critical protocol-rule family;
- hostile maximum-input behavior is measured and reproducible;
- the supported Rust and WASM entry points run from real consumer
  environments;
- a new integrator can compile and run a correct offline verification example;
- documentation accurately separates kernel guarantees from host obligations;
- the launch-candidate public API is deliberately minimized and approved;
- MSRV, packaging, dependency, provenance, and configuration are
  release-gated;
- the corrected wire format, portable result, corpus, and public API are
  recorded as the first compatibility baseline rather than compared with
  provisional prelaunch artifacts;
- independent review findings are resolved against a fixed release candidate.

## Final assessment

The core implementation is broad and promising, but it is not yet accurate to
say that only assurance infrastructure remains.

The most consequential work is protocol-contract closure:

- what composition the verifier requires;
- which exact trust/configuration state the decision commits to;
- which participants assurance policy quantifies over;
- whether deployment limits cover every equivalent input path;
- whether evidence is actually consumed rather than merely referenced.

Once those questions are resolved, the existing architecture, corpus,
deterministic result model, and `xtask` foundation provide a strong base for
serious adversarial testing and independent review.

Because there are no users, fix those contracts directly. Do not carry
prelaunch mistakes forward as compatibility modes or force the first public
release to inherit an avoidable migration burden. The corrected contract
should become the first public V1, and only then should its API and wire format
be treated as compatibility commitments.

Until that freeze, describe the repository conservatively: a capable pre-audit
offline authorization kernel with substantial implemented semantics, but with
composition-policy, configuration-binding, assurance-quantification,
limit-coverage, and evidence-consumption contracts still requiring closure.
