# AP-SPEC-036: SDK ergonomics and external-consumer workflow closure

**Status:** Repository-local TypeScript reference implementation complete
through AP36-PR8; AP36-PR9 is partially complete and AP36-PR10 remains blocked
by AP-SPEC-035. Publication, promotion, cross-platform claims, external-review
claims, and Python Full Workflow claims remain blocked on their governing
evidence and owner gates.

**Governs:** The SDK ergonomics work that follows AP-SPEC-027 and
AP-SPEC-035, including reusable workflow composition, approval sessions,
development custody, inspection, profile conformance, and external-consumer
evidence

**Source evidence:** The separate `auths-agent-demo` repository and its
GitHub branch, file-change, and pull-request workflow

**Source strategy:** [Auths Product and Go-to-Market
Strategy](../plans/GO_TO_MARKET_STRATEGY.md)

**Depends on:** AP-SPEC-027, AP-SPEC-035, the profile and domain abstraction
boundary, issue 76 for non-forgeable command minting, issue 85 for the
application-profile kit and development authority bootstrap, and the
applicable release and independent-review gates

**Scope:** Removing protocol-shaped and orchestration-shaped glue from normal
TypeScript and Python SDK use while preserving profile ownership, local
verification, three-valued results, externally held keys, and closed effect
gateways

**Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are
requirements on conforming implementations.

## 0. First implementation unit: contributor filesystem

Before adding another SDK capability, the TypeScript package MUST be
reorganized so a contributor does not need broad knowledge of one or two
monolithic files to make a bounded change. The reorganization MUST preserve
the supported public API unless a later AP36 unit explicitly changes it.

The target filesystem is:

```text
bindings/typescript/
├── CONTRIBUTING.md
├── README.md
├── docs/
│   ├── architecture.md
│   ├── api-contract.md
│   └── threat-model.md
├── examples/
│   ├── verify/
│   ├── attach-agent/
│   └── delegate-and-authorize/
├── src/
│   ├── index.ts                    # exports only
│   ├── verifier/
│   │   ├── client.ts
│   │   ├── result.ts
│   │   ├── explanation.ts
│   │   └── decoder.ts
│   ├── workflow/
│   │   ├── client.ts
│   │   ├── attached-agent.ts
│   │   ├── authority-source.ts
│   │   ├── trusted-context.ts
│   │   ├── approvals.ts
│   │   ├── custody.ts
│   │   ├── errors.ts
│   │   └── types.ts
│   ├── profiles/
│   │   ├── application/
│   │   └── mcp/
│   └── internal/
│       ├── authorization.ts
│       ├── delegation.ts
│       ├── signing.ts
│       └── wasm.ts
├── test/
│   ├── unit/                       # mirrors src/
│   ├── contract/                   # compile-time misuse tests
│   ├── integration/                # real WASM and vectors
│   └── package/                    # packed external consumer
└── wasm/
    ├── README.md
    └── generated artifacts
```

The first implementation unit MUST complete these eight items:

1. Break `workflow.ts` apart without changing the public API.
2. Make `index.ts` an export-only entry point.
3. Separate fast TypeScript tests from WASM/vector integration tests.
4. Mirror the source structure under `test/`.
5. Add compile-time contract tests for non-forgeability and invalid provider
   implementations.
6. Add a package-specific contributor and architecture guide.
7. Move implementation-status material out of the consumer README.
8. Establish a scalable `profiles/` structure before adding more profiles.

## 1. Decision

Auths will treat a real application built from the released SDK as an
ergonomics test, not merely as another demo.

The integration proved that the core workflow is real: an application can use
native Auths profile actions, signed root authority, delegation attenuation,
proof and trusted-context assembly, and local three-valued verification
without hand-authoring protocol CBOR. It also exposed repeated application
code that belongs in supported SDK surfaces.

The next ergonomics work will therefore close seven specific gaps:

1. non-forgeable, profile-owned command and plan handoff;
2. compatible multi-action authority and authorization composition;
3. bounded human-approval sessions tied to exact transactions;
4. safe development and test custody helpers;
5. canonical commitment and configuration builders;
6. stable advanced inspection and receipt projection; and
7. profile conformance and mutation testing.

Auths will not solve these gaps with a generic operation union, a global
executor, a universal policy language, or application-specific semantics in
the shared kernel.

## 2. Evidence from the external integration

### 2.1 What already worked

The application successfully delegated these responsibilities to Auths:

- canonical principal and grant construction;
- signed root-authority preparation;
- parent-to-child attenuation;
- exact profile action construction;
- proof and trusted-context assembly;
- local verification;
- preservation of `authorized`, `denied`, and `indeterminate` outcomes; and
- protocol encoding, including CBOR, on the supported SDK path.

These are evidence that the semantic center is in the correct layer. This
specification MUST preserve them.

### 2.2 Rough-edge inventory

| Finding | Application glue observed | Required ownership |
| --- | --- | --- |
| Sealed command handoff | A private symbol and `WeakMap` were used to emulate a non-forgeable `VerifiedGitHubChangePlan` | profile kit plus verifier-owned minting path |
| Multi-action plan | Branch creation, file modification, and pull-request opening were authorized independently and manually bundled | SDK plan composition over profile-owned actions |
| Authority aggregation | Namespace, audience, validity, budget, and permissions were manually compared and combined | SDK compatibility validator and plan authority summary |
| Human approval | One user click was converted into an auto-approving provider for several later SDK requests | transaction-bound approval session |
| Development signing | PKCS#8 prefixes, raw-key domain separators, descriptor bytes, digests, and evidence media types were copied into app code | explicit development/test custody package |
| Policy configuration | The demo supplied magic configuration-digest bytes | typed, versioned approval-policy builders |
| Inspection | The app manually hashed action bytes, configuration, result CBOR, and other evidence for display | advanced SDK projection with stable fields |
| Profile correctness | A resource initially omitted the changed path, so distinct files mapped to the same authority | profile conformance and semantic-mutation harness |
| Commitments | Application profile code could reach for weak ad hoc hashes for path collections | cryptographic commitment helpers over canonical bytes |
| Cleanup and failures | App code coordinated several resources and translated provider failures itself | deterministic lifetime helpers and typed provider errors |
| Package consumption | The external repository had to prove packed-package and browser behavior separately | maintained external-consumer fixture and scorecard |

### 2.3 Correct boundaries discovered

The following remain application- or profile-owned and MUST NOT move into the
shared SDK kernel:

- GitHub action schemas and canonicalization;
- the meaning of repository, branch, path, and pull-request authority;
- GitHub REST calls and credentials;
- GitHub-specific retry, reconciliation, and receipt semantics;
- application UI, browser run identifiers, and presentation copy; and
- decisions about which GitHub actions constitute one product workflow.

The SDK may provide reusable mechanisms for those owners. It MUST NOT define
their domain meaning.

## 3. Ergonomic success criteria

An external developer SHOULD be able to protect a three-action plan without:

- authoring protocol CBOR;
- copying cryptographic domain separators or key-format prefixes;
- constructing protocol media types or evidence identifiers;
- using magic digest bytes;
- indexing parallel arrays of actions and results;
- writing a capability-branding `WeakMap`;
- collapsing three-valued decisions into booleans;
- hashing result structures for ordinary inspection; or
- implementing their own authority compatibility algorithm.

The supported workflow SHOULD have this conceptual shape:

```ts
const auths = await loadAuths({ signer, trustedAuthority });
const github = defineApplicationProfile(githubDefinition);

await using parent = await auths.attachAgent({
  principal: maintainer,
  authority: github.authority({
    repository: "auths-sandbox",
    branches: ["auths/demo-change"],
    paths: ["docs/demo.md"],
    actions: ["branch.create", "file.modify", "pull-request.open"],
  }),
});

await using child = await parent.delegate({
  authority: parent.authority.narrow({ paths: ["docs/demo.md"] }),
  signer: development.ephemeralSigner(),
});

const plan = github.plan([
  github.branch.create({ name: "auths/demo-change" }),
  github.file.modify({ path: "docs/demo.md", contentDigest }),
  github.pullRequest.open({ base: "main", head: "auths/demo-change" }),
]);

const decision = await child.authorizePlan(plan, {
  approval: approvalSession,
});

if (decision.kind === "authorized") {
  await githubGateway.execute(decision.command);
}
```

Names are illustrative. The security boundaries and absence of application-
minted commands are normative.

## 4. Sealed profile command and plan handoff

### 4.1 Requirement

Only a successful verification path controlled by the supported Rust/WASM
implementation may mint an effect-capable command. Application code MUST NOT
be able to construct, clone, deserialize, rebrand, or recover one from
inspection data.

For application profiles, the profile definition MUST provide a closed
decoder or command factory during profile registration. That factory MUST only
receive verifier-sealed material through an SDK-internal capability path.

```ts
const github = defineApplicationProfile({
  id: "dev.auths.github-change/1",
  actions: githubActionDefinitions,
  decodeVerifiedPlan(sealed, actions) {
    return GitHubChangePlan.fromVerified(sealed, actions);
  },
});
```

`sealed` above is conceptual and MUST be unconstructable from application
code. A caller-selected engine MUST NOT choose the branch that mints it.

### 4.2 Plan atomicity

Authorization atomicity and provider-effect atomicity are different.

The SDK MAY authorize a whole plan only when every constituent exact action is
authorized against the same compatible authority snapshot. The resulting
command MUST bind the ordered action commitments, plan commitment, authority
chain, policy configuration, expiry, and trusted-context version.

The SDK MUST NOT claim that a remote provider executes the plan atomically.
The profile gateway owns sequencing, idempotency, reconciliation, and partial-
effect receipts.

## 5. Multi-action authority composition

The SDK SHOULD provide a plan builder and authority compatibility validator.
It MUST validate at least:

- profile identity and version;
- namespace and audience;
- subject or resource root;
- authority-chain root;
- validity intersection;
- revocation and status snapshot compatibility;
- permission and action constraints;
- budget dimensions and aggregate consumption;
- approval-policy identity and configuration commitment; and
- canonical ordering or explicitly ordered execution semantics.

Incompatible inputs MUST fail with a typed construction error before signing,
approval, verification, or provider work.

```ts
type PlanConstructionError =
  | { kind: "profile-mismatch"; expected: string; actual: string }
  | { kind: "audience-mismatch" }
  | { kind: "no-validity-intersection" }
  | { kind: "budget-exceeded"; dimension: string }
  | { kind: "approval-policy-mismatch" }
  | { kind: "unsupported-plan-shape" };
```

The SDK MUST preserve per-action decisions and the first terminal failure. It
MUST NOT authorize the remaining actions after a denied or indeterminate
constituent unless the application explicitly requests an inspection-only
evaluation mode that cannot mint a command.

## 6. Transaction-bound approval sessions

A human approving one visible plan should not require application code to
install a blanket auto-approver for subsequent SDK calls.

The SDK SHOULD expose a bounded approval session that:

- begins from a displayed, canonical plan summary;
- binds the user response to the exact plan commitment;
- derives permitted child approvals only for named signing transactions;
- has an explicit mode, expiry, use limit, and policy identity;
- cannot approve a transaction added after the user decision;
- cannot be reused for a different principal, authority, action, or plan;
- records whether each required approval was requested, received, or skipped;
- returns typed cancellation, expiry, mismatch, and provider failures; and
- leaves grant-only, action-only, always, and headless modes configurable.

```ts
const approvalSession = await auths.approvals.requestPlan({
  plan,
  policy: approvalPolicy.planOnce({ expiresIn: "5m" }),
  provider: humanApproval,
});

await child.authorizePlan(plan, { approval: approvalSession });
```

An approval session is user-presence evidence and policy execution. It MUST
NOT be described as identity proof unless a separately named identity system
provides that claim.

## 7. Development and test custody

Production custody remains an external, provider-neutral port. The normal SDK
MUST NOT persist raw private keys or silently select insecure custody.

The SDK MAY ship a visibly named development/testkit package that owns:

- ephemeral Ed25519 key generation;
- supported key import and export for fixtures;
- canonical principal descriptors;
- raw-key signing-domain construction;
- signature-evidence identifiers and media types;
- deterministic fixture signers; and
- hostile signer and approval-provider fixtures.

```ts
import { development } from "@auths-dev/sdk/testkit";

const authority = await development.localAuthority({
  algorithm: "ed25519",
  persistence: "memory",
});
```

The package name, documentation, runtime warnings, package exports, and type
names MUST make the non-production status unmistakable. Production examples
MUST continue to accept an injected custody provider.

## 8. Canonical builders and commitment helpers

Normal workflows MUST use typed, versioned builders for approval policies,
trusted configuration, and supported commitments.

Applications MUST NOT need to invent values such as
`new Uint8Array(32).fill(9)` or copy domain separators from Rust tests.

```ts
const policy = approvalPolicy.planOnce({
  provider: "local-user-presence",
  expiresIn: "5m",
  maxUses: 1,
});

const pathSet = github.canonical.paths([
  "docs/demo.md",
  "docs/evidence.json",
]);
const commitment = auths.commitments.fromCanonical(pathSet.bytes);
```

Commitment helpers MUST use a protocol-approved cryptographic algorithm and
domain separation. The SDK MUST NOT expose a convenience API that encourages
FNV, JavaScript object-stringification, or other collision-prone or unstable
hashing for security-relevant authority.

## 9. Advanced inspection and receipt projection

The advanced surface SHOULD project stable, browser-safe evidence without
requiring an application to re-hash internal structures.

It MUST distinguish:

- stable protocol fields from explanatory display text;
- action, plan, proof, context, policy, and result commitments;
- kernel stage and code from SDK guidance;
- authorization decision from provider execution outcome;
- required approval from executed approval; and
- safe-to-log summaries from sensitive raw bytes.

```ts
const view = decision.inspect();

view.decision.kind;
view.kernel.stage;
view.kernel.code;
view.commitments.action;
view.commitments.plan;
view.commitments.policy;
view.metrics.workUnits;
view.approval.executedConfiguration;
```

Inspection values MUST be immutable copies. No inspection or receipt API may
be promoted into an effect-capable command.

## 10. Profile conformance and mutation harness

Application profiles need a supported way to prove that their security-
relevant inputs affect their authority and canonical action as intended.

The SDK testkit SHOULD let a profile author declare mutations for:

- action kind;
- resource identity;
- namespace and audience;
- branch, path, record, amount, or equivalent profile field;
- permissions;
- budget;
- expiry and validity;
- payload commitment; and
- profile version.

```ts
profileConformance(github, {
  baseline: modifyFile,
  mutations: {
    path: ["docs/a.md", "docs/b.md"],
    branch: ["main", "auths/demo-change"],
    contentDigest: [digestA, digestB],
  },
}).mustChange({
  path: ["resource", "canonicalAction"],
  branch: ["resource", "canonicalAction"],
  contentDigest: ["canonicalAction"],
});
```

The harness MUST detect accidental equality and missing authority dimensions.
It MAY offer standard mutation strategies, but the profile author owns the
expected semantic effect. Auths MUST NOT infer GitHub, Stripe, HTTP, database,
or infrastructure semantics generically.

## 11. Lifetimes and typed provider failures

Workflow objects that own WASM resources, ephemeral signers, approval
sessions, or temporary authority MUST support deterministic disposal.
TypeScript SHOULD support `using`/`Symbol.asyncDispose` with an explicit
`dispose` fallback. Python SHOULD support sync or async context managers.

Provider failures MUST be translated into bounded SDK error families without
leaking credentials or provider payloads:

```ts
type CustodyFailure =
  | { kind: "cancelled" }
  | { kind: "unavailable"; retry: "safe" | "unsafe" | "unknown" }
  | { kind: "protocol-violation"; code: string };
```

Authorization denials and indeterminate results remain values, not thrown
provider exceptions.

## 12. Cross-language requirements

The TypeScript SDK is the first ergonomics reference. Python MUST reach the
same semantic capability, though its API should be idiomatic Python rather
than a mechanical TypeScript transcription.

Both SDKs MUST agree on:

- canonical bytes and commitments;
- plan compatibility decisions;
- transaction and approval binding;
- three-valued authorization outcomes;
- stable stages and codes;
- command non-forgeability boundaries; and
- conformance fixtures.

Language-specific resource management, exceptions, unions, and builder style
MAY differ. Rust remains the semantic implementation.

## 13. External-consumer scorecard

A maintained repository outside the Auths source tree MUST exercise packed or
released artifacts. Its scorecard SHOULD record:

| Measure | Target |
| --- | --- |
| Protocol CBOR written by app | zero lines |
| Cryptographic constants copied by app | zero |
| Application capability-branding code | zero |
| Magic configuration digests | zero |
| Manual multi-action compatibility checks | zero |
| Outcome collapsing | zero |
| Time to first local denial | under 15 minutes from install |
| Time to first sandboxed authorized effect | under 45 minutes from install |
| Unsupported glue inventory | explicit and shrinking |

The scorecard MUST distinguish Auths SDK friction from package-manager,
framework, browser, and provider-specific friction.

## 14. Security and architecture invariants

All implementation units MUST preserve these invariants:

- verification is local and effect-free;
- identity and authority remain distinct;
- authority travels with and commits to the action;
- a caller cannot mint a verified command;
- only `authorized` may reach a closed gateway;
- denied and indeterminate outcomes cause no effect;
- unchanged trusted inputs make a denial terminal across retries;
- no generic operation tag selects a profile executor;
- credentials remain profile- and action-scoped;
- profiles own domain semantics and receipt meaning;
- approval execution is committed and reviewable;
- development custody is explicit and cannot masquerade as production;
- the open workflow works without an Auths-hosted service; and
- enterprise services may distribute trusted state but may not replace local
  semantic verification.

## 15. Non-goals

This specification does not authorize:

- a general-purpose CLI;
- a hosted verification dependency;
- a universal policy or workflow language;
- a global receipt union;
- a generic executor or provider credential interface;
- production raw-key custody;
- automatic effects after authorization;
- GitHub semantics in the core SDK;
- framework adapters unsupported by integration evidence;
- stable-v1, production-readiness, compliance, or independent-review claims;
- package publication or release promotion; or
- a breaking change to frozen protocol semantics outside the release-change
  process.

## 16. Evidence and tests

Each implementation unit MUST include, as applicable:

- TypeScript and Python compile-time misuse tests;
- runtime hostile-engine and command-forgery tests;
- plan mismatch and aggregate-budget tests;
- approval replay, expiry, mutation, and overuse tests;
- canonical cross-language fixtures;
- testkit package-content checks excluding persistent private material;
- profile mutation tests proving every declared field has its intended effect;
- browser, Node, macOS, Linux, and Windows tests for supported surfaces;
- packed-package tests from an external repository;
- forbidden-side-effect tests for denied and indeterminate plans;
- deterministic cleanup and provider-failure tests; and
- an updated external-consumer friction scorecard.

Tests MUST assert that required defects are observable, not only that the
happy path works.

## 17. Bounded PR units

1. **`AP36-PR1` — contributor filesystem and fast feedback.** Implement
   Section 0's target tree and eight-item priority list without changing the
   supported public import contract. Separate fast, contract, integration,
   and package tests and document generated WASM ownership.
2. **`AP36-PR2` — evidence freeze and ergonomic contract.** Check in a
   redacted integration diary, glue inventory, scorecard, ownership map, API
   sketches, and exact exclusions. Reconcile overlap with AP-SPEC-027 and
   AP-SPEC-035 before changing code.
3. **`AP36-PR3` — canonical builders and development testkit.** Add typed
   approval/configuration builders, approved commitment helpers, ephemeral
   development custody, canonical fixtures, package warnings, and hostile
   provider fixtures. Do not ship production custody.
4. **`AP36-PR4` — bounded approval sessions.** Bind one visible approval to
   an exact plan and finite set of signing transactions. Add replay, mutation,
   expiry, cancellation, and configuration-mismatch evidence.
5. **`AP36-PR5` — plan and authority composition.** Add compatible plan
   construction, validity intersection, aggregate budgets, typed mismatch
   errors, per-action decisions, and inspection-only failure evaluation.
6. **`AP36-PR6` — sealed application-profile plan command.** Complete the
   non-forgeable application-profile command path, remove demo branding glue,
   and prove that no caller-selected engine, copy, serialization, or advanced
   result can mint a command. This unit MUST reconcile issue 76 and the
   application-profile portion of issue 85.
7. **`AP36-PR7` — inspection, receipts, and lifetimes.** Add stable advanced
   projections, safe-to-log boundaries, deterministic resource management,
   and typed provider failures without creating a global receipt union.
8. **`AP36-PR8` — profile conformance harness.** Add semantic mutation tools,
   profile-owned expectations, canonical fixtures, and examples for at least
   two structurally different profiles.
9. **`AP36-PR9` — external-consumer closure.** Update the independent demo to
   released or packed artifacts, delete replaced glue, run the full scorecard,
   and add maintained Node, browser, macOS, Linux, and Windows evidence.
10. **`AP36-PR10` — Python parity.** Expose idiomatic Python equivalents for
   every semantic capability proven by the TypeScript reference and add
   cross-language differential fixtures. This unit MUST reconcile with
   AP-SPEC-035 rather than duplicate it.

Every PR MUST state its baseline, affected public surfaces, tests, evidence,
claim impact, exclusions, remaining glue, and remaining release gates. A unit
that changes frozen semantics MUST return through the governing release and
review process.

## 18. Exit gate

AP-SPEC-036 is complete only when:

- the external demo uses no hand-authored protocol encoding, cryptographic
  constants, capability brands, magic digests, or manual plan compatibility;
- one bounded human decision cannot authorize a mutated or additional action;
- all authorized plan commands are minted only through the verifier-owned
  capability path;
- the plan API rejects incompatible authority before effectful work;
- profile mutation tests catch the omitted-resource-dimension class of defect;
- inspection exposes stable evidence without allowing command promotion;
- TypeScript and Python agree on the shared semantic corpus;
- packed external-consumer tests pass on every supported platform; and
- all authoritative repository checks pass on the exact revision.

Completion improves developer ergonomics. It does not by itself establish
production readiness, stable-v1 compatibility, independent security review,
or a commercial product claim.

## 19. Repository-local implementation record (2026-08-04)

The TypeScript reference implementation completed AP36-PR1 through AP36-PR8
in the working tree. Its focused evidence comprises the package build,
compile-time contract suite, fast unit suite, package-shape suite, compiled
examples, and 43 real-WASM integration tests. The external consumer has been
rewritten to use the packed SDK's profile plan, bounded approval, development
custody, inspection, and sealed gateway surfaces.

AP36-PR9 is **partially complete**: package creation and the consumer rewrite
are complete, but the consumer dependency reinstall, refreshed browser check,
and macOS/Linux/Windows evidence remain outstanding. AP36-PR10 is **blocked**
by AP-SPEC-035 and issue 73's native non-forgeability requirement. No exit-gate
or cross-language completion claim is made while either unit remains open.

The detailed before/after evidence is recorded in
[`bindings/typescript/docs/external-consumer-scorecard.md`](../../bindings/typescript/docs/external-consumer-scorecard.md).

## 20. Related documents

- [AP-SPEC-027: TypeScript Full Workflow
  SDK](0027-product-grade-typescript-sdk.md)
- [AP-SPEC-035: Python Full Workflow SDK](0035-python-full-workflow-sdk.md)
- [Design-partner integration program](0030-design-partner-integrations.md)
- [Commercial discovery and product selection](0031-commercial-discovery.md)
- [Profile and Domain Abstraction Boundary
  Plan](../target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md)
- [Auths Product and Go-to-Market
  Strategy](../plans/GO_TO_MARKET_STRATEGY.md)
