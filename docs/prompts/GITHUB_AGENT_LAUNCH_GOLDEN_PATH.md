# Prompt: Build the GitHub Agent Launch Golden Path Without Rebuilding Auths

You are working in the `auths-dev/auths-proof` repository with no assumed prior context:

```text
/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof
```

Your mission is to turn the existing GitHub issue workflow into the clearest launch-quality Auths
experience: a developer gives an AI agent narrowly bounded authority to address one GitHub issue,
the agent proposes one exact change, and a separate trusted executor may publish one branch and
open one draft pull request. Unsafe changes, widening, replay, and ambiguous remote outcomes must
remain visibly and mechanically bounded.

This is a productization task, not permission to build a second Auths implementation. The repository
already contains a large amount of the required machinery. Your first obligation is to find and
reuse it.

## Product outcome

A new developer should be able to complete the path in under 15 minutes without understanding
Lean, Rust internals, CBOR, proof-bundle bytes, registry manifests, or the distinction between every
internal Auths crate.

The experience should let them:

1. select a repository, issue, base revision, allowed paths, protected paths, expiry, and a budget
   of one branch plus one draft pull request;
2. preview in plain language exactly what the agent may and may not do;
3. delegate that authority to an agent identity;
4. submit an agent-produced candidate without giving the agent a GitHub mutation credential;
5. see the real Auths decision before any mutation credential is requested;
6. publish the authorized branch and draft pull request through the trusted executor;
7. inspect and verify the decision and execution receipts;
8. see a protected-path candidate denied before any GitHub write;
9. see replay or a second pull request denied; and
10. recover or reconcile an ambiguous remote outcome without blindly repeating the mutation.

The user-facing path must use typed domain inputs. Raw `Uint8Array`, `bytes`, CBOR, opaque request
blobs, and hand-built protocol objects are not an acceptable primary developer experience.

## Read before changing anything

Read the whole brief before running commands or editing files. Then read:

1. `AGENTS.md` and every applicable nested repository instruction.
2. `demos/github-issue/docs/architecture.md` and the rest of `demos/github-issue/`.
3. `product/integrations/auths-github/` in full enough to identify its public types, service,
   adapters, lifecycle behavior, receipts, and exact action vocabulary.
4. `bindings/typescript/`, especially its service client, profile exports, workflow surface, tests,
   public API inventory, capability metadata, and installed-package tooling.
5. `bindings/python/`, especially its service client, profile exports, workflow surface, tests,
   public API inventory, capability metadata, and wheel-consumer tooling.
6. `bindings/wasm/auths-proof-wasm/` to understand the Rust-owned encoding and projection boundary.
7. `bindings/customer-journey-matrix-v1.json` and `bindings/public-topology-v1.json`.
8. `demos/open-production-reference/`, particularly its installed TypeScript and Python consumers,
   recovery behavior, deployment boundary, and limitations.
9. `docs/product/PRODUCTION_SDK_QUICKSTART.md` and the binding integration recipes.
10. The relevant repository checks, semantic fixtures, frozen API inventories, and existing CI
    jobs before proposing a new package, command, or public symbol.

Use `rg` and `rg --files` to discover existing owners and call sites. Do not infer a capability is
missing from a filename or from one documentation example.

## Inventory-first gate

Before implementation, produce a concise reuse matrix:

| Needed capability | Existing owner and path | Reuse as-is | Extend existing owner | Genuine gap | Evidence |
| --- | --- | --- | --- | --- | --- |
| GitHub action vocabulary | ... | ... | ... | ... | file:symbol/test |
| Candidate inspection | ... | ... | ... | ... | ... |
| Authority creation and delegation | ... | ... | ... | ... | ... |
| Remote SDK transport | ... | ... | ... | ... | ... |
| Rust-owned canonical encoding | ... | ... | ... | ... | ... |
| Receipt verification | ... | ... | ... | ... | ... |
| Replay and lifecycle state | ... | ... | ... | ... | ... |
| Recovery and reconciliation | ... | ... | ... | ... | ... |
| GitHub credentials and writes | ... | ... | ... | ... | ... |
| Deployment and installed-SDK test | ... | ... | ... | ... | ... |
| Demo UI | ... | ... | ... | ... | ... |

For every proposed new component, name the nearest existing component and explain with code-level
evidence why extending it is insufficient. “Cleaner,” “more modern,” or “easier to understand” is
not sufficient evidence for parallel machinery.

Do not begin implementation until the matrix supports a minimal change set.

## Repository placement decision

Evaluate these choices explicitly:

1. **Extend `demos/github-issue` — default and strongly recommended.** It already owns the exact
   GitHub issue, bounded branch, draft pull request, public fixture, web presentation, deployment,
   receipt, and recovery demonstration. Reuse `product/integrations/auths-github` for reusable
   GitHub product behavior and the existing bindings for user-facing SDK behavior.
2. **Create another directory under `demos/`.** Choose this only if the intended audience or
   execution model is genuinely different and sharing the current demo would create an incoherent
   product. A second name for the same agent-to-draft-PR path is duplication.
3. **Create a new repository.** Do not choose this merely for visual cleanliness or a smaller
   checkout. It is justified only by a demonstrated hard boundary such as independent release
   cadence, separate security/credential ownership, or a requirement that the sample consume only
   published packages with no source-tree coupling. Even then, first prove the full experience as
   an installed-package consumer fixture in this repository; extraction is a later release action.

Score the choices on reuse, semantic-drift risk, installed-package realism, credential isolation,
release independence, maintenance cost, and CI coverage. Unless the evidence disproves it, use:

```text
Placement: extend demos/github-issue
Reusable GitHub semantics: product/integrations/auths-github
Developer APIs: bindings/typescript and bindings/python
Rust-owned cross-language encoding: bindings/wasm/auths-proof-wasm and existing native bindings
Production runtime/deployment patterns: demos/open-production-reference and auths-node
```

Do not create a new repository, a second GitHub demo, or another runtime without stopping and
presenting the evidence that makes the default placement impossible.

## Required design response before code

Report this compact decision block before editing:

```text
Placement:
Why this owner is correct:
Existing components reused:
Existing components extended:
New files proposed:
Public API changes proposed:
Semantic identities affected:
Why no parallel implementation is being created:
```

Then provide a light technical specification with exactly these sections:

- **UX** — the happy path, denial path, recovery path, and what the user sees at each step;
- **Architecture** — component ownership and dependency direction;
- **APIs** — existing public calls reused and the smallest typed additions, if any.

There must be no unanswered design questions when implementation begins. If an unresolved choice
would materially change public APIs, security boundaries, or repository placement, stop and ask.

## Target user experience

Prefer one cohesive quickstart over a catalogue of features. A terminal or existing web experience
may implement it, but do not build a new frontend if the current `demos/github-issue/web` can be
extended cleanly.

The experience should communicate roughly this information:

```text
+------------------------------------------------------------------+
| Auths GitHub Agent · Delegate one bounded task                    |
+------------------------------------------------------------------+
| Repository     auths-dev/example                                 |
| Issue          #123                                               |
| Base           main @ 8a31...                                     |
| Agent          did:key:...                                        |
| Allowed paths  src/**, tests/**                                   |
| Protected      .github/**, Cargo.lock, secrets/**                  |
| Budget         1 branch · 1 draft PR · expires in 30 minutes       |
+------------------------------------------------------------------+
| MAY                                                              |
|  ✓ address issue #123 from the pinned base revision               |
|  ✓ publish auths/issue-123                                        |
|  ✓ open one draft pull request                                    |
| MAY NOT                                                          |
|  ✗ edit protected paths                                           |
|  ✗ push another branch or open a second pull request              |
|  ✗ obtain or reuse the executor's GitHub credential               |
+------------------------------------------------------------------+
| [Delegate authority]                              [Cancel]         |
+------------------------------------------------------------------+

+------------------------------------------------------------------+
| Candidate inspection                                              |
|  ✓ base revision matches       ✓ 4 files / 2.8 KiB                 |
|  ✓ paths permitted             ✓ exact action authorized           |
|  ✓ effect claimed before credential                               |
|                                                                  |
| Result: COMPLETED                                                 |
| Branch: auths/issue-123       Draft PR: #456                      |
| Receipt: verified             [Explain] [Open PR] [Download]      |
+------------------------------------------------------------------+
```

Use plain language first, with exact digests and protocol details available as progressive
disclosure. A denial must identify the failed boundary without leaking secrets or implying that an
external effect occurred. A recoverable result must tell the caller to resume or reconcile, not to
start the action again.

## Required architecture

Preserve this ownership and dependency direction unless the inventory proves the repository has
already moved it:

```text
Developer or AI-agent sample
  |
  | typed TypeScript/Python calls
  v
Existing Auths binding production client
  |
  | canonical Rust-owned request/response contract over HTTPS
  v
Existing auths-node / production runtime boundary
  |
  +--> Auths authorization and lifecycle state
  |      (authority narrowing, replay, recovery, receipts)
  |
  v
product/integrations/auths-github
  |
  +--> hostile candidate inspection
  +--> fresh GitHub evidence
  +--> exact branch and draft-PR actions
  +--> claim-before-credential execution
  +--> postcondition observation and reconciliation
  |
  v
GitHub App credential boundary --> GitHub API / Git transport
```

```text
demos/github-issue
  -> product/integrations/auths-github
      -> stable Auths core/profile APIs

TypeScript/Python examples
  -> published/packed binding APIs
      -> existing service routes

Auths core must never import the demo, GitHub integration, or language bindings.
Language bindings must never acquire an independent copy of GitHub authorization semantics.
The agent process must never receive the GitHub mutation credential.
```

## API guidance

Discover existing names before proposing new ones. In particular, inspect the current remote
service clients and the GitHub profile constructors rather than copying stale quickstart snippets.
The TypeScript production boundary currently lives separately from the local product facade; keep
that separation intact. Apply the equivalent rule in Python.

The likely product gap is a friendly, typed GitHub-authoring surface above the existing opaque
wire contract. Validate that hypothesis from the code. If the gap is real:

- add the smallest profile-specific input types or builders to the existing binding owner;
- keep canonical serialization and validation Rust-owned;
- expose domain values such as repository, issue number, pinned base revision, allowed and denied
  paths, branch/PR budget, expiry, and exact candidate identity;
- return the existing closed completed/denied/indeterminate/recoverable outcome families;
- preserve opaque authority, recovery-reference, and receipt values;
- keep TypeScript and Python behavior and vocabulary in parity;
- add public API, capability, topology, documentation, and frozen-semantic updates required by the
  repository's existing policies.

Do not invent a profile-independent “execute arbitrary JSON” endpoint. Do not move canonical
meaning into TypeScript or Python. Do not make an internal or private API public merely because the
demo needs it. If the desired typed operation cannot be expressed through the public product waist,
treat that as a product API gap and fix its proper owner.

## File structure guidance

First reconcile this suggestion with the files already present in `demos/github-issue`. Add only the
smallest missing pieces; do not reorganize working code for symmetry.

If extending the existing demo, a reasonable end state is:

```text
demos/github-issue/
├── README.md                         # one launch path and prerequisites
├── Cargo.toml                        # existing native demo assembly
├── src/                              # existing Rust service and fixtures
├── web/                              # existing presentation; extend, do not replace
├── docs/
│   ├── architecture.md               # existing ownership and flow
│   ├── about.md                      # existing product explanation
│   ├── quickstart.md                 # only if README would become unwieldy
│   └── operator-boundary.md          # only if not already covered elsewhere
├── examples/                         # add only if installed-SDK examples do not fit tests
│   ├── typescript/
│   │   ├── package.json
│   │   └── src/agent.ts
│   └── python/
│       ├── pyproject.toml
│       └── agent.py
├── fixtures/                         # shared declarative cases, if no current owner exists
│   ├── allowed/
│   ├── denied-protected-path/
│   └── recoverable/
└── tests/
    ├── installed-sdk-e2e.mjs         # packed package, never source imports
    ├── test_installed_sdk.py         # built wheel, never source imports
    ├── denial-and-replay.*
    └── live-github-opt-in.*           # isolated fixture repository only
```

This is a decision aid, not an instruction to create every listed file. Prefer existing tests and
fixtures when they already have the correct owner. Do not copy the production-reference installed
SDK harnesses; extract or parameterize shared test support if reuse is genuinely needed.

If the demo needs no new examples directory because the current web and Rust assembly can exercise
the typed SDK path directly, say so and keep the smaller tree.

## Implementation sequence

### Phase 0 — Establish the reuse and placement contract

1. Complete the reuse matrix.
2. Record the placement decision and dependency direction.
3. Identify every proposed public API or frozen-semantic change.
4. Delete any proposal that duplicates an existing owner.

### Phase 1 — Write the launch acceptance tests first

Create failing tests at the external seam using packed TypeScript and built Python artifacts, not
source-tree shortcuts. Pin the user journey independently of implementation constants so drift is
detectable. The tests should describe developer inputs and public outcomes, not internal CBOR.

### Phase 2 — Close only genuine typed-API gaps

Extend the existing binding/profile owner only where the installed consumer cannot express the
journey. Keep encoding, validation, exact profile semantics, outcome mapping, and error codes bound
to their current Rust-owned contracts.

### Phase 3 — Compose existing runtime and GitHub product code

Connect the public SDK journey to the current runtime and `auths-github` service. Reuse candidate
inspection, fresh evidence, claim-before-credential, replay, recovery, reconciliation, and signed
receipt behavior. Do not write demo-local substitutes.

### Phase 4 — Make the experience legible

Update the existing quickstart and demo presentation. Show the authority preview, the exact denied
boundary, when the credential is requested, effect state, next call, and receipt explanation. Keep
the default path short; put protocol details behind expandable detail.

### Phase 5 — Prove packaging and operations

Run the path from independently packed SDK artifacts against the reviewable runtime shape. Add an
opt-in live GitHub test only against an isolated fixture repository and GitHub App installation.
Never make routine unit tests mutate a maintainer's real repository.

## Acceptance criteria

The work is not complete until all of the following are demonstrated:

- A clean-machine quickstart reaches a verified draft pull request in under 15 minutes, excluding
  deliberate human GitHub App installation approval.
- The primary TypeScript and Python examples contain no user-authored protocol bytes, CBOR, raw
  authority blobs, or copied canonicalization logic.
- The authority is bound to one repository, issue, base revision, target branch derivation, path
  policy, audience, expiry, and a budget of one branch plus one draft pull request.
- The agent can create the candidate while holding no GitHub read or mutation credential.
- A protected-path candidate is denied before a mutation credential is requested and before any
  GitHub write.
- A changed base revision or mismatched repository/issue is denied or indeterminate according to
  the existing contract; it never silently authorizes.
- A replay and an attempt to create a second branch or pull request issue no second write.
- An ambiguous write becomes recoverable/reconcilable and is resolved by observing the exact
  postcondition, not by blindly repeating the write.
- The completed result carries a receipt that the existing verification surface accepts and can
  explain without exposing secret material.
- TypeScript and Python agree on profile ID, typed inputs, result class, stable error code, recovery
  direction, and receipt verification for shared fixtures.
- Installed-package tests use a packed npm artifact and built wheel. Passing through source imports
  does not count.
- The opt-in live test creates only a draft pull request in an isolated fixture repository and has
  deterministic cleanup or a bounded retention policy.
- Existing architecture, binding semantics, SDK vocabulary, customer-journey, public-topology,
  semantic-freeze, and relevant production-contract gates pass.
- No new authorization evaluator, canonical encoder, GitHub provider, lifecycle store, receipt
  schema, recovery protocol, identity system, or runtime was added when an existing owner could be
  extended.

## Required adversarial cases

At minimum, prove the real boundary behavior for:

- `.github/**` or another protected-path mutation;
- candidate based on a stale base revision;
- repository or issue substitution;
- candidate content changed after inspection;
- action submitted by the wrong agent identity or audience;
- expiry before execution;
- widening during delegation;
- second branch, second draft pull request, and receipt replay;
- verifier configuration mismatch;
- GitHub rejection with no effect;
- timeout after a possibly applied GitHub effect;
- recovery on a different runtime replica;
- tampered or wrong-key receipt;
- packed TypeScript/Python vocabulary drift.

Each denial must come from the production Auths/GitHub path, not a frontend-only conditional or a
demo-specific Boolean.

## Things you must not rebuild

Do not add any of the following unless the inventory proves there is no existing owner and you
explicitly justify the new boundary:

- an authorization or attenuation evaluator;
- a proof-bundle or canonical-action encoder in TypeScript/Python;
- another remote Auths client;
- a generic JSON operation endpoint;
- another GitHub App credential broker, REST client, candidate inspector, or write executor;
- another lifecycle/replay/recovery state machine;
- another receipt envelope, signer, or verifier;
- a demo-specific identity or custody model;
- another deployment stack duplicating `demos/open-production-reference`;
- another web application duplicating the existing GitHub demo;
- compatibility aliases, deprecated shims, or old/new APIs in parallel;
- mocks presented as proof that the real GitHub seam works.

Do not hand-edit generated artifacts. Change their source or generator and regenerate them using the
repository's documented process. Do not run or rewrite the full formal toolchain merely because it
exists; determine whether the formal source closure actually changed and follow the repository's
qualification instructions when it did.

## Verification discipline

Determine behavior empirically:

- If you claim an API already supports the journey, prove it with an installed-consumer test.
- If you claim a denial happens before credentials, instrument the credential port and prove it was
  never called.
- If you claim replay is bounded, count external writes.
- If you claim recovery is idempotent across replicas, run it against shared durable lifecycle
  state from a second runtime instance.
- If you claim TypeScript/Python parity, run identical semantic fixtures through both.
- If you claim a gate protects a boundary, deliberately break that boundary and show the gate fails
  before relying on it.

Use the narrowest relevant checks during iteration, followed by every repository-prescribed gate
for the files and semantic identities changed. Do not weaken, skip, rename away, or conditionally
hide a required CI check to make the branch green.

## Deliverables

Deliver all of the following:

1. The reuse matrix with `file:symbol` or test evidence.
2. A placement decision record comparing the three repository options and explaining why the
   chosen owner minimizes drift.
3. The light technical specification with **UX**, **Architecture**, and **APIs** sections.
4. The minimal implementation in the existing owners.
5. A one-path quickstart for TypeScript and Python.
6. Installed-package end-to-end tests, real denial/replay/recovery tests, and an isolated opt-in live
   GitHub test.
7. Updated architecture and security-boundary documentation.
8. A final reuse report listing every existing component reused, every component extended, every
   new file, and why each new file was necessary.
9. Verification output and a residual-risk section that distinguishes what was proved locally,
   what was exercised against GitHub, and what remains an operational assumption.

## Completion standard

The result is done when an external developer can understand the authority they are granting,
delegate it without handling protocol bytes, let an uncredentialed agent propose a change, and see
a separate executor either open exactly one authorized draft pull request or fail closed with a
useful next step—and when the implementation demonstrably composes the Auths machinery already in
this repository instead of rebuilding it under a demo-friendly name.
