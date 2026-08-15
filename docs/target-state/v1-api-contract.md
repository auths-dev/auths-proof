# Auths v1.0 Frozen API Contract

## Status

**Draft — Phase 1 of the v1.0 API hardening effort. Not yet ratified.**

This document is the single source of truth that all implementation lanes work against. Rust,
TypeScript, Python, and Security agents build to *this file*, not to their own judgment. Where an
implementer believes this contract is wrong, they report it and stop — they do not diverge.

Derived from 139 findings (48 blockers) produced by 15 read-only auditors across two workflow runs
(`wf_4ff587be-0a3`, `wf_f7878425-e97`). Evidence: `docs/target-state/v1-api-review-findings.md`.

Authoritative over this document: `AGENTS.md`, `architecture.toml`, `compliance.toml`, `xtask`.
Where they conflict, they win and this file is corrected.

## 1. Why this document exists

Three implementation lanes will edit Rust, TypeScript, and Python in parallel. Without a frozen
contract they will produce three internally-consistent, mutually-incompatible APIs — a failure that
cannot be repaired in review, because by then each is self-consistent.

The audit proved this is not hypothetical. It is the *current* state:

- `EffectState` — the field that answers "did the real-world effect happen?" — has **five
  incompatible value sets** across three languages.
- `RetryClass` names **three different closed sets**, and both bindings export two of them under the
  same identifier.
- `recover` is a **sixth product operation that both bindings invented independently**, with no Rust
  owner and no registry entry.

In each case the projections agreed with each other and disagreed with the owner. That is the
signature of an ownership failure, and it is what this contract exists to end.

## 2. The three goals and how each is measured

| Goal | Measure | Today | v1.0 target |
|---|---|---|---|
| **Simple** | One canonical name per concept; one entry point per operation | 5 `EffectState` sets, 3 `RetryClass` sets, 2 complete SDKs at the TS root | 1 each |
| **Extensible** | Non-generated files touched outside a new vertical's own package | **28** (single commit) / **36** (union) | **≤ 3** |
| **Secure** | Effect state reaches the caller unflattened in every language | Unreachable in TS and Python public APIs; destroyed at the WASM boundary | Reachable and typed in all three |

Breadth is not the enemy. A large Rust reference surface that is bounded, deterministic, and
documented is correct. A *second definition of meaning* is the enemy, at any size.

## 3. Tier model

| Tier | Audience | Rule |
|---|---|---|
| **T1 — Reference Rust** | Protocol implementers, auditors, advanced embedders | Broad, deterministic, effect-free. Breadth is a feature. Never re-exported from the product facade. |
| **T2 — Rust product facade** | Ordinary Rust developers | Curated safe path. Contains no generic semantic carriers. |
| **T3 — TypeScript / Python** | Application developers | Small, product-shaped. Projects T2. Defines nothing. |
| **T0 — Internal** | Nobody | `pub(crate)` or unpublished. **Default for anything not explicitly listed.** |

Semantic parity across T3 languages is **required**. Identical symbol counts are **not**.

`bindings/wasm/auths-proof-wasm` and `bindings/python/src` (pyo3) are **not tiers**. They are
transport layers that ship *inside* T3 artifacts. They may expose no symbol that T3 does not expose.

## 4. The frozen vocabulary

One concept, one name, one spelling per language. Rust `snake_case`/`PascalCase`, TypeScript
`camelCase`/`PascalCase`, Python `snake_case`/`PascalCase`.

### 4.1 Safety-critical — the effect axis

**`EffectState`** — answers *did the real-world effect happen?*

```
Rust (OWNER):  auths_errors::EffectState { NotApplied, Possible, Applied }
Wire:          "not-applied" | "possible" | "applied"
TypeScript:    type EffectState = "not-applied" | "possible" | "applied"
Python:        class EffectState(str, Enum): NOT_APPLIED / POSSIBLE / APPLIED
Field name:    `effect` in all three.  `effect_state` is DELETED.
```

**Exactly three members. No fourth.** The `"unknown"` value invented at
`bindings/typescript/src/product-errors.ts:8` and `bindings/python/python/auths/_product_errors.py:27`
is deleted, as is the entire alternate vocabulary at `workflow/errors.ts:48` (`none|possible|occurred`)
and `_errors.py:9` (`not-started|in-progress|completed|failed|outcome-unknown`).

> **The fail-closed rule.** An unrecognized error code maps to `effect: "possible"`. Never to a
> fourth value, never to `not-applied`. If a distinct "could not classify" signal is genuinely
> required, Rust adds it first and the fixtures move with it.

**`RetryClass`** — answers *may I retry?*

```
Rust (OWNER):  auths_errors::RetryClass { Never, Safe, Conditional, Unknown }
Wire:          "never" | "safe" | "conditional" | "unknown"
```

**`NextCall`** — answers *what should I call next?* (renamed from the second `RetryClass`)

```
Rust (OWNER):  auths_production_client::NextCall { Never, Backoff, Resume, Reconcile }
Wire:          "never" | "backoff" | "resume" | "reconcile"
```

These are different questions and must never share an identifier again.
`auths_lifecycle::ProviderRetryClass` stays **T1 and is not projected**.

### 4.2 Operations

**Exactly five product verbs.**

```
Rust (OWNER):  ProductVerb { Create, Delegate, Execute, Resume, Verify }
TypeScript:    type ProductVerb = "create" | "delegate" | "execute" | "resume" | "verify"
Python:        class ProductVerb(str, Enum)
Wire field:    `verb`  (the `step` spelling is DELETED)
```

`ProductStep` is deleted in both bindings. `ErrorDefinition.operation` changes from
`&'static str` to `ProductVerb`, which forces two open questions to be answered (§11).

**`recover` is deleted from both bindings.** It has no Rust owner, no registry entry, and its
implementation decides *what identity to recover under* inside the binding. Either Rust gains
`McpExecutionSession::recover` and `ProductVerb::Recover` in one change, or the operation does not
exist.

### 4.3 Nouns

| Concept | Rust (T2) | TypeScript | Python | Notes |
|---|---|---|---|---|
| Product authority | `Authority` | `Authority` | `Authority` | Product noun |
| Signed statement | `SignedGrant` | — | — | **T1 only.** `grant` never appears in a binding |
| Decision+execution pair | `Receipt` | `Receipt` | `Receipt` | One `Receipt`, one subpath |
| Single attested receipt | `AttestedReceipt` | `AttestedReceipt` | `AttestedReceipt` | |
| Receipt signer port | `ReceiptSigner` | `ReceiptSigner` | `ReceiptSigner` | Drop `Application*` prefix |
| Receipt attestor port | `ReceiptAttestor` | `ReceiptAttestor` | `ReceiptAttestor` | |
| Trusted context | `TrustedContext` | `TrustedContext` | `TrustedContext` | **Rename Rust `VerifierContext`** |
| Multi-step plan | `AuthorizationPlan` | `AuthorizationPlan` | `AuthorizationPlan` | Rename Python `ProofPlan*` |
| Threshold combinator | `threshold` | `threshold` | `threshold` | **Rename Rust `k_of_n`** |
| Profile-scoped plan | `ProfilePlan` | `ProfilePlan` | `ProfilePlan` | Rename Python `McpPlan` |
| Resume token | `ExecutionReference` | `ExecutionReference` | `ExecutionReference` | One wire format (§11) |
| Telemetry event | `AuthsEvent` | `AuthsEvent` | `AuthsEvent` | One field set |
| Telemetry port | `TelemetryPort` | `TelemetryPort` | `TelemetryPort` | |
| Metrics | `VerificationMetrics` | `VerificationMetrics` | `VerificationMetrics` | Delete `InspectionMetrics`, `AuthorizationMetrics` |
| Product stage | `Stage` | `Stage` | `Stage` | One Rust enum over the registry's 20 values |
| Kernel phase | `VerificationStage` | `VerificationStage` | `VerificationStage` | Separate, 5 members, already aligned |

**Deleted outright:** `McpAttestedReceipt`, `LinkedAttestedReceipt`, `ApplicationReceiptSigner`,
`ApplicationReceiptAttestor`, `AuthorizationPlanSummary`, `TelemetryStage`, `DecisionTimeline`,
`AuthorizationRequest` (Python), `auths.python-support-bundle/1`, and every `SignedGrant*` name in
either binding.

**Homonyms — banned.** No identifier may name two unrelated types:
- TypeScript exports two `Auths` (product facade + verifier engine) → rename the engine.
- Python ships two `AuthsError` → one is deleted.
- Two `development` values at `/integrations` and `/testkit` → testkit's becomes `fixtures`.
- Two `Receipt` aliases at root and `/verify` → one type, one export.

### 4.4 The `Production*` prefix is deleted

The TypeScript root publishes **two complete unrelated SDKs** — 19 of 41 root symbols are a
`Production*` mirror of the other 14, sharing zero methods and drawing `code` from disjoint spaces.

The remote client moves to a new subpath **`@auths-dev/sdk/service`** / **`auths.service`**, added
to `bindings/public-topology-v1.json`. Types drop the prefix (`ServiceAuthority`, `ServiceReceipt`).
The local product facade keeps no import edge to the remote client.

**Unify the two `code` spaces on the registry before splitting**, or the split merely relocates the
ambiguity.

## 5. The result model

This section is safety-critical. Every rule here has a failing-then-passing test as its acceptance
criterion.

1. **The effect axis must reach the caller.** In every language, from every public entry point, a
   caller can read `effect` on a failed operation. Today it is unreachable from every TypeScript
   public surface and every public Python API.

2. **No error may be flattened to a string.** `bindings/wasm/auths-proof-wasm/src/lib.rs:4927`
   (`js_error` → `JsValue::from_str`) destroys code identity, effect state, and recommended action
   for all 45 codes. It is replaced by a structured envelope.

3. **Transport failure is `possible`, never `not-applied`.** Both production clients currently map
   every transport failure and every non-2xx response to `retry: backoff` with registry codes whose
   declared effect is `not-applied`. That tells a caller a possibly-applied PostgreSQL update is
   safe to blindly retry. This is the single most dangerous defect found.

4. **Bindings mint no error codes.** Python currently mints 25 codes that exist in no registry, on
   the path reachable from public `execute()`. All codes originate in
   `product/errors/v1/registry.json` (45 today) and are generated into both bindings.

5. **Known vs unknown codes must be distinguishable**, so a newer Rust code neither crashes nor is
   silently swallowed by an older binding. Unknown → `effect: "possible"`.

6. **`recommendedAction` is reachable in all three languages.** It is currently Rust-only.

7. **No binding-owned catch may relabel a programmer error or contract violation as an
   authorization outcome.**

## 5A. Launch blockers surfaced after this contract was first drafted

Phase 0's final adjudicated pass produced four findings more severe than anything in §5. All four are
**verified in source by hand**. They are listed here in danger order and take precedence over the
vocabulary work in §4.

### 5A.1 The reference production runtime is a second authorization system

`product/runtime/auths-node` is what `demos/open-production-reference/Dockerfile:4,11` builds and
runs as its entrypoint — the deployment README instructs operators to run three of them behind TLS
with PostgreSQL and an HSM. It is **not** in the 42-crate publishable closure, so no release gate
covers it.

Verified:

- **It depends on no kernel crate.** Its `Cargo.toml` lists `auths-operations`,
  `auths-operations-otel`, `auths-production-client`, `axum`, `ed25519-dalek`, `minicbor`,
  `postgres`, `rustls`. There is no `auths-algebra-kernel`, no `auths-verifier`, no `auths-authority`.
- **`sandbox.rs:95-107` mints root authorities with no authentication of the requester.** `create()`
  builds `Authority { parent: None, subject: digest(request.identity()), .. }` and signs it. `parent:
  None` is a root. The only input is the caller's self-asserted identity.
- It hand-rolls narrowing over **4 dimensions** (`sandbox.rs:123-135`) where the kernel checks **11**
  (`core/crates/auths-algebra-kernel/src/generated.rs:52-75`).
- **8 of the 10 error codes it puts on the wire are unregistered** (`profiles.rs:24-31`).

**Disposition:** requires a human decision (§11.7). Either `auths-node` is rebuilt on the kernel, or
it is removed from the reference deployment and labeled non-production. It cannot ship as-is under
the product's own security claims.

### 5A.2 The formal proof of root preservation is vacuous

`core/crates/auths-authority/src/lib.rs:201` sets `root_preserved: true` as a **literal**.
`AuthorityStateView` carries no root to compare against, so there is nothing the check could compute.
The Kani harness at `core/crates/auths-algebra-kernel/src/lib.rs:43-74` therefore proves an identity
over arbitrary booleans while presenting it as a security invariant.

Root preservation — that a delegated authority still descends from the same root — is one of the
system's central claims. It is currently unproven and unchecked.

**Disposition:** in scope. `AuthorityStateView` gains the root identity; `root_preserved` computes a
real comparison; the Kani harness is re-checked against the non-vacuous version.

### 5A.3 The signed receipt cannot express "unknown"

`product/receipts/auths-receipts/src/lib.rs:299-304`:

```rust
pub enum ExecutionOutcome { Succeeded, Failed }
```

Two variants. `exchange/crates/auths-proof-exchange-model/src/lib.rs:545-554` likewise has no
indeterminate member. So for a provider timeout, the reference runtime signs a durable receipt
asserting **Failed** for an effect that may have applied — and §5's error-model fixes cannot repair
it, because the evidence artifact itself has no way to say "possible".

**Disposition:** adding a third variant changes signed bytes and is therefore a **protocol change**,
out of scope under §10 without separate review. Flagged, scoped, not auto-fixed. This is the highest
priority item for the review that follows this wave.

### 5A.4 A signed "Authorized" receipt is written before the replay check runs

`product/runtime/auths-runtime/src/lib.rs:816-828` writes the decision receipt; `:830` performs the
replay check. Consequences: audit records assert authorization for requests that are then refused,
and an attacker gets unbounded write amplification into the receipt sink.

**Disposition:** in scope. Reorder so the receipt is written only after every check that can refuse.

## 6. Public surface

### 6.1 Rust

42 crates are in the publishable closure and `xtask/src/public_naming.rs:394` already enforces
set-equality against `semantic-freeze.json` with zero drift. **This is the model — hold every other
language to it.**

Two changes:

- **`auths` and `auths-proof` are two crates.io coordinates for one byte-identical API.** Pick one,
  delete the other.
- **Rust has crate-level gates only**, while TypeScript and Python have symbol-level gates. Rust
  gains a symbol-level public-API snapshot, byte-compared in CI.

`auths-sdk` (T2) exports **no** T1 generic machinery. Specifically, `product/sdk/auths-sdk/src/lib.rs:26`
is deleted:

```rust
pub use auths_profile_domains::{DeploymentAction, DomainCommand, DomainProfile};  // DELETE
```

Every downstream break is intended and is fixed by giving the vertical its own owned types.

### 6.2 TypeScript and Python

The seven declared entry points in `bindings/public-topology-v1.json` **stand**, plus `service`:

```
product    @auths-dev/sdk, /identity, /verify   │ auths, auths.identity, auths.verify
service    @auths-dev/sdk/service               │ auths.service            ← NEW
vertical   @auths-dev/sdk/profiles              │ auths.profiles
mechanism  @auths-dev/sdk/integrations          │ auths.integrations
extension  @auths-dev/sdk/framework             │ auths.framework
test       @auths-dev/sdk/testkit               │ auths.testkit
```

`layers` is already byte-enforced in both languages. **`frameworkContracts` and `qualifiedProfiles`
are read by nothing** — they gain gates (§10).

**Framework contracts must be structurally identical, not merely name-identical.** `close?()`
optional in TypeScript versus `aclose()` required in Python currently passes an 11-of-11 name-parity
check. Parity checks compare shape.

**Async parity is required.** Receipt-disclosure protector and store ports are async in TypeScript
and synchronous in Python, making a KMS-backed protector unimplementable in Python.

### 6.3 WASM and pyo3

Neither may export a symbol its host tier does not export.

- WASM: 228 public JS symbols; 38 undeclared by the ABI manifests; ≥22 are generic domain machinery
  including parsers for five **unqualified** reference profiles.
- pyo3: 147 module attributes; 23 exported-and-undeclared; 18 generic reference-vertical symbols
  (`HttpAction`, `EdgeAction`) exposed as typed callable Python symbols.
- **A Python caller can currently define an entire vertical** via `define_profile` +
  `_native.application_action`, with canonicalization in a Python callback. Deleted.
- `__init__.pyi` omits 19 of 35 public symbols in a `py.typed` wheel. Regenerated and gated.

## 7. The extension point

**A new profile vertical touches ≤ 3 non-generated files outside its own package.** Today: 28.

Permitted: workspace `Cargo.toml` members, workspace dependency entry, demo directory.

Everything else becomes **derived from a single vertical-owned Rust descriptor**:
`bounded-domains.toml`, `compliance.toml [packages.*]`, `architecture.toml [layers]`, the
bounded-policy evaluator registry, fixtures, and both bindings' profile registries.

Three findings must be fixed for this to work:

1. `auths-lifecycle` **already contains the correct vertical-owned descriptor, with zero
   implementors.** Adopt it rather than designing a new one.
2. `xtask/src/fixtures.rs` authors each vertical's canonical fixture corpus as Rust literals.
   Verticals own their own corpora.
3. The qualified-profile registry is hand-maintained in three languages with three different failure
   modes, and six mutually-disagreeing copies exist. One generated source.

**Acceptance test:** build a throwaway vertical, count files touched outside its package, report the
number, delete the spike. The number is reported whether or not it is good.

## 8. Stability promises

"Advanced tier" is a documentation label. Users read it as "supported" unless told otherwise.

| Tier | Version at launch | Promise |
|---|---|---|
| T2 product facade, T3 bindings | `1.0.0` | Full semver |
| T1 reference Rust | `0.x` | **No stability promise**, stated in each crate's docs |
| Internal | unpublished | None |

Every publicly promised crate documents: **audience, limits, errors, security properties,
non-goals.** A crate without those five sections is not v1.0-eligible.

Version coherence across Rust, npm, and wheel is a launch gate. The wheel currently advertises three
operating systems and ships one Linux wheel with no sdist.

## 9. Enforcement

A declared contract with no gate drifts silently. `semantic-freeze` is **already red on `main`** —
`auths.product.lifecycle` changed under frozen identity v8 without a version assignment — which
proves the point.

Gates that must exist before v1.0:

1. **Symbol-level ownership gate.** No `product/integrations/**` may name `DomainProfile`,
   `DomainCommand`, or any `auths-profile-domains` type, transitively or via re-export.
   Crate-level checks miss this: `auths-deployment`'s `Cargo.toml` is clean while its source is
   coupled.
2. **`binding_semantics` must scan what it claims to.** It scans only
   `bindings/typescript/src` and `bindings/python/python` — blind to `bindings/wasm/` (5,586 lines)
   and `bindings/python/src/` (6,779 lines). It is also a token grep, not semantic analysis.
3. **`frameworkContracts` and `qualifiedProfiles` gates**, comparing shape not names.
4. **Rust symbol-level public-API snapshot**, byte-compared.
5. **Effect-axis reachability test** per language: assert a caller can read `effect` from every
   public failure path.
6. **Testkit isolation proof.** That a testkit-minted verifier result cannot reach `Auths.execute`
   is currently asserted only in a doc comment.

**Regenerating `semantic-freeze.json` to make a build pass is forbidden.** Drift means a semantic
identity needs a new version — a deliberate decision, not a mechanical regeneration.

## 10. Out of scope

Protocol bytes, canonical CBOR, canonical fixtures, and stable decision codes do not change. They
are test oracles. A refactor that requires changing one is a protocol change and needs separate
review.

Rust reference breadth is not reduced for symmetry. The Go independent implementation
(`bindings/independent/go`, 5,019 lines, zero third-party dependencies, running in CI) is a genuine
strength and is **kept** — only its `compliance.toml:1473` role claim is corrected, since it
currently claims both `independent-semantic-implementation` and `language-binding`.

## 10Z. Execution policy: never block — resolve empirically

**Ratified 2026-08-15. This supersedes every "stop and report" instruction anywhere in this document
or in any wave brief.**

An implementer who hits an open question does **not** stop, does **not** defer to a human, and does
**not** guess. They *determine the answer* and let the determination become a permanent artifact.

### The three routes

| Route | Use it for | How |
|---|---|---|
| **TDD — unit** | "Does this code actually do X?" | Write the test asserting the intended behavior. Run it. **The result is the answer.** Red → the finding is real and you now own its regression test. Green → the finding was a false positive; record that and move on. |
| **TDD — e2e / differential** | "Do two implementations agree?" "Does meaning survive a boundary?" | Drive both sides with identical inputs and assert identical outputs. |
| **Formal — Kani** | Bounded exhaustive questions over small state | Add `#[kani::proof]`; run `cargo xtask formal`. 8 harnesses already exist in `auths-model`, `auths-algebra-kernel`, `auths-lifecycle/src/kernel.rs`. |
| **Formal — Lean** | Invariants that must hold for *all* inputs | `formal/Auths/` — `Attenuation.lean`, `Authority.lean`, `Composition.lean`, `Theorems.lean`, plus `Lifecycle/`, `Product/`, `Rich/`. Run `cargo xtask formal`. |

### Worked mappings for the currently-open questions

- **"Is the budget ceiling inert when the action requests no budget?"** → unit test: ceiling present,
  action requests nothing, assert **deny**. Run it. Whatever happens is the finding, settled.
- **"Can `PeerObservation` be forged?"** → test from *outside* the owning crate that attempts to
  construct the authenticated variant. If it compiles, it is forgeable. Compilation is the proof.
- **"Does `root_preserved` actually hold?"** → Lean. `formal/Auths/Attenuation.lean` and
  `Authority.lean` are where this theorem belongs. A theorem that is true because the hypothesis is a
  literal is not a theorem — make it quantify over a real root and re-check.
- **"Does `auths-node` agree with the kernel?"** → **differential test, and this is the rebuild's
  acceptance criterion.** Feed identical authority/action/context triples to `auths-node`'s narrowing
  and to `auths-algebra-kernel`, and assert identical decisions across all 11 dimensions. Every
  disagreement is a bug in `auths-node` by definition, because the kernel is the owner.
- **"Does the effect axis survive each boundary?"** → e2e. Force each of the 9 `effect: possible`
  codes through Rust → WASM → TypeScript and Rust → pyo3 → Python, and assert `effect` arrives intact
  at the public API. A boundary that cannot pass this does not ship.

### The one thing still forbidden

**Never weaken a test, gate, assertion, or type to make something pass.** That is not empirical
resolution — it is fabricating the answer, and it is the exact failure mode this whole effort exists
to correct. If a test fails because behavior *legitimately* changed, update it **and say so
explicitly in the wave report**, naming the behavior change that justifies it.

Corollary: `root_preserved: true` is what a weakened check looks like after the fact. Do not create
the next one.

### Uncertainty is a work item, not a blocker

If you cannot decide something, you have not yet written the test that decides it. Write it.
An unresolved question at the end of a wave is only acceptable if the report states **what test or
theorem would settle it** and why it could not be written.

## 10A. Decisions ratified by the maintainer

Recorded 2026-08-15. These are settled and implementers follow them without re-asking.

| # | Decision | Ruling |
|---|---|---|
| §11.7 | `auths-node` | **Rebuild on the verified kernel.** It uses `auths-verifier` / `auths-algebra-kernel` for narrowing and authority minting. The hand-rolled 4-dimension check and unauthenticated root minting at `sandbox.rs:95-107` are deleted. |
| §11.8 | Protocol changes | **Authorized before 1.0, both.** `ExecutionOutcome` gains an indeterminate variant so a receipt can record "possible". `ExecutionReference` unifies on one wire format. Canonical fixtures are regenerated **with explicit written justification per fixture**. |
| — | Commit authority | **Commit to `dev-cleanup` at each verified checkpoint. Never push.** |
| — | Deletion authority | **Delete zero-consumer crates** (`auths-deployment`, `auths-cache`, and any other confirmed dead), atomically with `architecture.toml`, `compliance.toml`, and workspace membership. |
| — | `semantic-freeze` | **Investigate first.** Diff what changed in `auths-lifecycle` under PR #109. If the change is deliberate, assign `auths.product.lifecycle` v9, bump `FREEZE_VERSION`, regenerate, and record the evidence. If it looks accidental, stop and report. |

### `auths.product.lifecycle` — investigation result: DELIBERATE, assign v9

Frozen at identity version **8**, classification `FrozenMeaning`, covering the subjects
`reservation-state`, `claim-state`, `execution-state`, `reconciliation-state`, `lifecycle-codes`
(`xtask/src/semantic_freeze.rs:457-476`).

PR #109 made two changes inside that frozen meaning:

1. **New durable state field** — `model.rs` gained
   `recovery_reference_digest: RecoveryReferenceDigest`, documented as an "opaque recovery-reference
   commitment created before durable decision state." That is `execution-state` and
   `reconciliation-state`.
2. **Three new sealed failure variants** — `sealed.rs` gained `PoolExhausted`, `Timeout`, and
   `SchemaMismatch`. That is `lifecycle-codes`.

Both are coherent additions belonging to the open-production epic — recovery commitments, pool
exhaustion, statement timeouts, and schema compatibility are exactly that epic's concerns. This is
**deliberate product work that skipped the version bump**, not an accidental semantic drift.

**Ruling: assign `auths.product.lifecycle` v9 and bump `FREEZE_VERSION` 110 → 111.**

**Sequencing:** the bump happens at the END of the implementation waves, not now. The freeze digests
`product/runtime/auths-lifecycle/src` and five other paths that the waves are actively editing;
regenerating now would only have to be redone. Until then the gate stays red **by design**, and every
gate report names it as the one known-red baseline gate.

**The fixture exception is narrow.** §10 still forbids changing fixtures to make a refactor pass. It
is now permitted *only* where a ratified protocol change (`ExecutionOutcome`, `ExecutionReference`)
requires it, and every such regeneration carries a written justification naming the decision above.

### Defaults taken without escalation

Reversible; each is recorded with rationale in the wave reports.

- **`sign`** — treated as a stage of `create`/`delegate`, not a sixth verb. `ProductVerb` stays five.
- **crates.io coordinate** — `auths` survives; `auths-proof` is dropped.
- **Budget in TypeScript** — projected into TS rather than removed from Python. Removing a caller's
  ability to state a budget ceiling is the worse failure.
- **TS identity tiers** — collapsed to Python's single tier.
- **Go role claim** — `compliance.toml:1473` corrected to `independent-semantic-implementation` only;
  the `language-binding` claim is removed. Go stays.

## 11. Open decisions — remaining

These change the contract's content and cannot be defaulted by an implementer.

1. **`auths.product.lifecycle` v9.** Assigning it asserts the PR #109 lifecycle semantic change was
   intended. Blocks a green `semantic-freeze`.
2. **`sign` — sixth verb or a stage?** The registry declares `operation: "sign"` but has no
   `delegate`. Typing `ErrorDefinition.operation` as `ProductVerb` forces the answer.
3. **`auths` vs `auths-proof`** — which crates.io coordinate survives.
4. **`ExecutionReference` wire format** — two incompatible formats exist and the profile-neutral one
   is MCP-namespaced. Pick one.
5. **Budget in TypeScript** — Python exposes `BudgetCeiling`/`NoBudget`/`InheritBudget`/`BudgetSummary`;
   TypeScript has none. Either project them, or remove them from Python so the bindings agree.
   Related: a grant's budget ceiling is currently **inert whenever the action requests no budget** —
   which every money-moving Stripe profile and the shipped MCP profile mandate.
6. **Identity tiers in TypeScript** — TS ships descriptor-tier *and* packet-tier; Python ships one.
   Collapse TS, or name the descriptor tier explicitly and add it to Python.
7. **`auths-node` (§5A.1) — the launch-blocking decision.** The reference production runtime is a
   second authorization system that never touches the verified kernel and mints root authorities
   from an unauthenticated caller identity. Three options, all of which need your call:
   (a) rebuild it on `auths-verifier` / `auths-algebra-kernel`, deleting the hand-rolled narrowing;
   (b) remove it from `demos/open-production-reference` and label it a non-production sandbox;
   (c) keep it, and publicly scope the security claims to exclude the reference deployment.
   Option (c) is not recommended — the deployment README is what operators will follow.
8. **`ExecutionOutcome` third variant (§5A.3).** Adding `Indeterminate` changes signed receipt bytes.
   That is a protocol change requiring review, but without it no honest receipt can be written for a
   provider timeout. Recommended: accept the protocol change before 1.0, since after 1.0 it becomes
   permanently harder.
