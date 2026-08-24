# Auths public SDK redesign

Status: proposed target API, decision-ready
Audience: Rust, TypeScript, Python, product-runtime, documentation, release, and security reviewers
Scope: the installed public interfaces of `@auths-dev/sdk` and `auths`
Cutover policy: one prelaunch clean break; no compatibility aliases, deprecated exports, shims, or dual paths

## Executive decision

Replace the current generic-looking `Auths` facade with profile-owned APIs. Ship one npm package and one Python distribution, but make the entry point identify the task:

```text
identity packet ──> identity authentication ──> authenticated identity
                         (never authority)

proof + exact action + trusted context ──> offline verification
                                              (never executable)

profile ──> bounded authority/session ──> exact profile action ──> outcome
                                                            ├── receipt
                                                            └── recovery handle
```

The default developer vocabulary is five nouns:

1. **Identity** says who authenticated. It does not grant authority.
2. **Authority** is permission for one exact profile and can only be narrowed.
3. **Action** is an inert, typed proposal owned by that profile.
4. **Outcome** states what Auths can prove about the decision and real-world effect.
5. **Receipt** is portable evidence, verified independently from execution.

The selected package navigation is:

| Task | TypeScript | Python | Default-path status |
|---|---|---|---|
| Shared errors, receipt handle, runtime facts | `@auths-dev/sdk` | `auths` | default |
| Protect an MCP tool call | `@auths-dev/sdk/mcp` | `auths.mcp` | default development path |
| Durable local MCP development state | `@auths-dev/sdk/mcp/node` | `auths.mcp` | development-only |
| Run the GitHub issue-address workflow | `@auths-dev/sdk/github` | `auths.github` | production profile after route promotion |
| Verify proofs and receipts without effects | `@auths-dev/sdk/verify` | `auths.verify` | default |
| Authenticate identity packets/messages | `@auths-dev/sdk/identity` | `auths.identity` | default |
| Add identity methods or author packets | `/identity/adapters`, `/identity/authoring` | `auths.identity.adapters`, `auths.identity.authoring` | advanced |
| Integrate a bounded remote verifier/transport | `@auths-dev/sdk/protocol` | `auths.protocol` | advanced, effect-free |
| Implement qualified custody or reservation mechanisms | `@auths-dev/sdk/adapters` | `auths.adapters` | advanced |
| Test adapters and profile integrations | `@auths-dev/sdk/testkit` | `auths.testkit` | test-only |

There is no public generic `Auths`, no marker-only `/profiles` barrel, no public `/service`, no generic operation-tag executor, and no fake local `production()` constructor. MCP and GitHub keep separate action, outcome, recovery, and lifecycle types because their workflows are materially different. Shared code may own transport mechanics, error axes, bounded codecs, diagnostics, and opaque envelopes; Rust continues to own canonicalization and all security semantics.

This proposal exposes no OpenTofu or PostgreSQL object until each has an honest typed binding vertical. Calling `{ id: "auths.opentofu.saved-plan-apply/1" }` a profile is removed. Their canonical IDs remain wire-internal rather than becoming SDK navigation.

## 1. Diagnosis of the current API

### 1.1 The root product is generic in name and MCP-specific in fact

The authoritative inventories contain 203 TypeScript symbols and 180 Python exports across eight entry points. The breadth is not the main problem; the public concepts do not describe the products that actually exist.

- TypeScript aliases root `Authority` to `McpToolAuthority`, and `Auths.execute`, `resume`, and `delegate` accept only MCP values (`bindings/typescript/src/product.ts:38-47`, `:163-186`).
- Python does the same (`bindings/python/python/auths/_product.py:61-67`, `:254-360`).
- Root `createAuths`/`create_auths` accepts a sealed configuration that a clean consumer cannot create (`bindings/typescript/src/product.ts:343-368`; `bindings/python/python/auths/_product.py:212-227,418-429`).
- Exported `integrations.production` only accepts that unavailable configuration. The only repository builder hard-codes development (`bindings/typescript/src/integrations.ts:136-142`; `bindings/python/python/auths/integrations.py:361-365,372-467`).

Exact replacement: remove root `Auths`, `Authority`, `createAuths`/`create_auths`, and both integration singletons. MCP becomes `McpSession`/`DevelopmentSession` in the MCP module. GitHub gets its own client. Advanced protocol access is limited to bounded transport and effect-free remote verification; it does not provide a generic execution dispatcher.

### 1.2 Each package currently contains three unrelated client models

The installed surface combines:

1. a local MCP-only root facade;
2. a raw-byte, five-verb remote service which explicitly says it is a different product (`bindings/typescript/src/service.ts:4-12`; `bindings/python/python/auths/_service.py:205-215`); and
3. a GitHub demo client with a third result and error vocabulary.

The raw service accepts `Uint8Array`/`bytes` for identity, authority, action, attenuation, and verification. The maintained server refuses public `create` and `delegate`, and its clean example needs the repository-only `auths-local-authority` tool to manufacture bytes. This is not a first-result path for an installed SDK.

The current result families also disagree:

| Product | Current result words |
|---|---|
| Root MCP | `completed`, `denied`, `indeterminate`, `recoverable`, `exact-replay`, `conflict` |
| Remote service | `completed`, `denied`, `indeterminate`, `recoverable`, `verified`, `rejected` |
| GitHub | `completed`, `denied`, `indeterminate`, `replayed`, `reconciled`, plus `next` |

Exact replacement: each profile owns one exhaustive outcome. Every successful replay/reconciliation is a completed outcome with `completion: "replayed" | "reconciled"`. A possible effect always carries a durable, profile-specific recovery handle. `NextCall` disappears.

### 1.3 “Qualified profile” currently means four different things

`bindings/public-topology-v1.json` lists MCP, GitHub, OpenTofu, and PostgreSQL as qualified profiles. Only MCP is a complete binding vertical. The TypeScript and Python `/profiles` modules implement the other names as `{id}` wrappers (`bindings/typescript/src/profiles.ts:1-16`; `bindings/python/python/auths/profiles/__init__.py:24-45`), while binding runtime contracts and compliance claims cover MCP only.

The missing semantics are not cosmetic:

- OpenTofu must apply the exact saved plan, must never re-plan or shell-dispatch, and must reconcile outcome-unknown without blind re-apply (`demos/opentofu-plan/docs/architecture.md`).
- PostgreSQL must execute a bounded, typed update rather than arbitrary SQL, couple a serializable transaction to the durable ledger, and reconcile ambiguous commit by fresh observation (`demos/postgresql-data-change/docs/architecture.md`).
- GitHub must keep repository credentials server-side, bind a server-owned boundary, separately claim branch and draft-PR effects, and verify linked receipts (`demos/github-issue/docs/architecture.md`).

Exact replacement: delete the marker factories. A public profile module qualifies only when it has typed domain inputs, profile-owned authority/delegation, a closed outcome and recovery model, portable receipts, clean-package examples, and conformance evidence. A wire profile ID alone is not exported as an SDK feature.

### 1.4 The beginner MCP path leaks assembly and weak typing

The current README imports profile, integration, and root symbols separately, constructs a provider separately, and passes that provider on every execution. The root session does not own/close it even though the provider is disposable. In Python the handler shown in the README accepts one argument, but the actual provider invokes two.

MCP arguments are `Record<string, unknown>`/`Mapping[str, object]`; results are `unknown`/`object`. In TypeScript, any handler result object containing an `effect` property is interpreted as SDK control state (`bindings/typescript/src/profiles/mcp/index.ts:901-928`). A legitimate application result such as `{ effect: "applied" }` is therefore ambiguous.

Exact replacement: define typed tools, bind handlers once when opening a development session, require an idempotency key, make the session own the internal provider wrapper, and require explicit `mcp.applied` or `mcp.possible` handler outcomes. A handler cannot claim non-application after entry. The distinct development reconciliation boundary can report only a fresh `observedApplied` result or remain `inconclusive`; only a future profile-owned finality observer may prove non-application.

### 1.5 The GitHub API exposes the wrong boundary

The current application copies repository, issue, base revision, allowed/protected paths, and budgets from `boundary()` back into `delegate()`. Those facts are operator-owned and should not be caller-reasserted. The current API also:

- uses `/v1/demo/...` routes;
- exposes denial fixtures and replay controls in the production client;
- hides Node filesystem I/O behind a generic candidate type;
- catches broad exceptions and invents an unregistered `transport-uncertain` result;
- exposes a separate `GitHubAgentError`; and
- calls a non-empty JSON list “verified receipts” and returns only its count (`bindings/python/python/auths/_github_agent.py:275-311`; `bindings/typescript/src/github-agent.ts:120-257`).

Exact replacement: the client fetches the sealed server boundary and `delegate` accepts only narrowing fields. Inspection accepts bytes and returns a sealed candidate. Repeating the same execute call performs exact replay, so there is no public replay verb. Outcomes include real portable `Receipt` values. Recovery works after process restart from a profile-specific byte handle.

### 1.6 Verification is safe at the kernel and awkward at the wrapper

The verifier is effect-free and fail-closed, but TypeScript accepts three reorderable `Uint8Array` positionals and Python accepts three byte positionals or three-byte tuples in batches. The verification module exports 37 TypeScript and 34 Python symbols, including a cache not accepted by public verifier configuration, a public `VerifiedAction` that must not be effect-capable, and overlapping receipt `verify`/`inspect` functions.

Exact replacement: use a named `VerificationInput`, keep authorized verification inert, return one three-valued result shape, and merge receipt decode/verify/inspect into one bounded `verifyReceipt`/`verify_receipt` operation. Invalid untrusted receipt bytes are a result, not a crash or operational exception.

### 1.7 Identity has useful typestate but no production-shaped first step

The Python staged `decoded -> resolved -> validated -> authenticated` progression is valuable. TypeScript instead requires three loaders and manual adapter plumbing for the common raw-key Ed25519 flow. The maintained Python recipe uses test doubles from `auths.testkit`, which is not a production-shaped authentication example. The two languages currently expose materially different identity tiers.

Exact replacement: both SDKs expose the same staged semantics and a built-in raw-key Ed25519 client/registry. Custom method, resolver, and suite ports move to the advanced identity-adapters module; packet construction moves to identity-authoring. Authentication never returns authority.

### 1.8 Errors, cancellation, and diagnostics are inconsistent

The Rust error registry already has the right axes: stable code, operation, stage, correlation, effect (`not-applied | possible | applied`), retry class, recommended action, and entered boundaries. The wrappers lose or reinvent parts of it:

- Python declares a single `AuthsError` policy but identity raises bare `ValueError` and GitHub has `GitHubAgentError`.
- GitHub collapses unrelated failures into one transport label.
- stateful public methods generally expose no cancellation point;
- Python runs blocking `urllib` in an executor, so task cancellation can abandon an effectful request while the thread continues; and
- `doctor({mode, state})` repeats caller-supplied claims rather than inspecting the installed/runtime state.

Exact replacement: expected security/effect states are values; operational faults use one `AuthsError`; programmer type/value/lifecycle misuse may use host-language `TypeError`/`ValueError`/`RuntimeError` before I/O. Post-entry cancellation cannot escape without a durable recovery locator. `runtimeInfo()`/`runtime_info()` reports observed facts only, and live sessions expose observed diagnostics.

### 1.9 Package evidence is not clean-consumer complete

Specific current gaps include:

- packed READMEs link outside their package;
- the TypeScript packed recipe test omits the restart/recovery recipe;
- browser tests deep-import `dist` files rather than export-map paths;
- Python's clean consumer monkeypatches a private GitHub method;
- topology, package exports, runtime contracts, and API-contract prose disagree about `/service`; and
- current public API gates snapshot names but not signatures, fields, protocol methods, overloads, or typing behavior.

Exact replacement: generate topology, public signature snapshots, runtime contracts, documentation navigation, and package tests from one release manifest. Test the packed tarball/wheel in an empty consumer with no repository and no Rust toolchain.

The packaging foundations worth preserving are concrete: `@auths-dev/sdk` is ESM, targets Node 20+, and bundles its WASM; Python uses a `maturin` ABI3 (`py39`) wheel, declares Python 3.9-3.14, and ships `py.typed`. The redesign keeps one integrity-bound artifact per language and validates every claimed host/platform rather than making a source checkout or Rust compiler part of normal installation.

## 2. Architectural constraints and selected mental model

### 2.1 Non-negotiable repository rules

This design follows `AGENTS.md` and `docs/target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md`:

- prelaunch changes cut directly to one target API; no migration layer;
- bindings are thin projections of Rust-owned semantics;
- verification fails closed and never mints an application-executable command;
- identity is distinct from authority;
- delegation only narrows;
- required and executed configuration mismatch is a failure;
- trust/transport/evidence/signature alone is never authorization;
- replay, budgets, approval challenges, execution, and recovery remain product-state concerns;
- a profile owns its action, evaluator, command, gateway, credential scope, observation, recovery, receipts, codes, and tests; and
- the stateful order remains verification -> profile evaluation -> durable decision -> atomic reservation -> exact-action claim -> least-privilege credential -> fresh reread -> closed provider request -> durable provider result -> observation -> receipt/unknown/reconciliation.

No TypeScript or Python callback is introduced for canonicalization, policy evaluation, exact command construction, credential derivation, or recovery classification.

### 2.2 Ownership diagram

```text
                       effect-free utilities
       +------------------------------------------------+
       | identity                     verify            |
       | decode/resolve/validate      proof + receipt   |
       | authenticate                 three-valued      |
       +----------------------+-------------------------+
                              |
                              | typed inert values only
                              v
  application ------> profile-owned client/session
                      MCP                    GitHub issue address
                      tool call + plan       inspect + branch + draft PR
                      authority narrowing    server-owned boundary
                              |
                              | private ABI / versioned HTTPS protocol
                              v
                  trusted Auths product runtime
       +---------------------------------------------------------+
       | verify -> decide -> persist -> reserve -> exact claim   |
       | -> credential -> fresh reread -> closed provider call   |
       | -> durable provider result -> observe -> receipt /      |
       |    recovery-required / reconcile                        |
       +---------------------------------------------------------+
                         ^                         ^
                         |                         |
               qualified adapters           credentials
               custody/reservation           never enter app

  testkit is a sidecar. Production modules never import it.
```

### 2.3 Public versus private commonality

The following may be shared publicly because their meaning is cross-profile and already Rust-owned:

- error classification axes and the bounded error envelope;
- an opaque portable receipt handle;
- installed/runtime compatibility facts; and
- the fact that a possible effect needs recovery.

The following must remain profile-owned even when implementations share private machinery:

- action and authority types;
- completion/result payloads;
- recovery handle formats;
- provider input and output;
- plan semantics;
- receipt presentation fields; and
- reconciliation operations.

In particular, this proposal does **not** export `ExecutionOutcome<T>` at the package root. A generic union would invite future profiles to inherit MCP's workflow shape. MCP and GitHub intentionally repeat their small result discriminants.

### 2.4 Exact target topology ownership

The regenerated `bindings/public-topology-v1.json` keeps the existing layer vocabulary but replaces its contents atomically with this mapping. Empty `service` is omitted; no old subpath remains as an alias.

| Layer | TypeScript entry points | Python modules |
|---|---|---|
| product | `@auths-dev/sdk`, `/verify`, `/identity`, `/identity/authoring` | `auths`, `auths.verify`, `auths.identity`, `auths.identity.authoring` |
| vertical | `/mcp`, `/mcp/node`, `/github` | `auths.mcp`, `auths.github` |
| mechanism | `/identity/adapters`, `/adapters` | `auths.identity.adapters`, `auths.adapters`, `auths.adapters.custody`, `auths.adapters.reservations` |
| extension | `/protocol` | `auths.protocol` |
| test | `/testkit` | `auths.testkit` |

The manifest's other exact target values are:

```json
{
  "frameworkContracts": [
    "atomic-reservation-store",
    "signer-custody"
  ],
  "qualifiedProfiles": [
    "auths.github.issue-address/2",
    "auths.mcp/2"
  ]
}
```

GitHub appears only in the promoted target manifest generated by implementation unit 8; until that gate passes, the published stable manifest omits the module and qualified profile together. OpenTofu and PostgreSQL are removed from the qualified roster because the present SDK exports only marker IDs, not qualified typed verticals. Identity authoring is product-owned but advanced; adapter contracts are mechanisms. Bounded byte transport remains an integration-owned protocol-extension contract, matching the mechanism catalog's `retain-integrations` disposition; it is deliberately absent from `frameworkContracts`. Remote verification is an extension and never a service/execution waist.

## 3. Alternatives considered

### 3.1 Selected: profile-first clients with effect-free utility modules

This is the only alternative that gives MCP and GitHub honest APIs without forcing OpenTofu and PostgreSQL through an invented universal workflow. It costs a few task-specific imports. The imports are useful navigation, and the package remains one versioned artifact.

### 3.2 Rejected: one `AuthsClient<Profile>`

A generic client looks small on a symbol-count spreadsheet but pushes domain differences into optional methods, opaque type parameters, callbacks, or overloads. GitHub inspection and two-effect reconciliation, MCP handler dispatch, OpenTofu saved-plan identity, and PostgreSQL transaction/observation rules are not the same workflow. The current MCP-only `Auths` is evidence of this failure mode.

### 3.3 Rejected: make the raw five-verb service the public waist

This would provide one transport client but force normal users to construct canonical protocol bytes and understand remote verbs. It also preserves two verbs that the maintained runtime refuses. Raw access remains available under `/protocol`, explicitly advanced and without `create`/`delegate`.

### 3.4 Rejected: universal `createProof()` / `verifyProof()` as the product API

An existing non-authoritative proposal suggests a universal two-call proof facade. It improves naming in isolation but invents a proof-authoring ceremony as the developer's primary task and has no place for durable reservation, provider entry, unknown effects, reconciliation, or profile-specific credential boundaries. Proof verification remains a first-class inert utility; effectful products remain profile verticals.

### 3.5 Rejected: callbacks for “custom profiles”

`defineProfile({ canonicalize, evaluate, command, execute })` would move security semantics into bindings and enable a generic operation-tag executor. New profiles are implemented as Rust-owned vertical slices and appear in the SDK only after qualification.

### 3.6 Rejected: exceptions for all negative results

Denial, indeterminate trust, exact replay, conflict, definite non-application, and possible effect are expected protocol states. Exhaustive values make blind retry harder. Exceptions are reserved for programmer misuse before I/O and operational failures for which no truthful workflow result can be returned.

### 3.7 Rejected: one package per profile at cutover

Separate artifacts give the strongest physical isolation but create version skew, installation choices, and coordinated-release complexity before dependency graphs justify it. One package/wheel with subpaths/modules gives atomic semantic parity now. A future split requires measured artifact-size or release-cadence evidence and must keep a lockstep compatibility manifest.

### 3.8 Rejected: compatibility aliases

The repository is prelaunch and explicitly prohibits deprecated aliases, shims, and dual paths. Removed imports must fail at cutover so documentation and consumers cannot silently remain on an incoherent model.

## 4. Normative shared semantics

This section is normative for both languages. Language-specific declarations follow.

### 4.1 Error and issue envelope

Every Rust-originated issue carries:

```text
schema                 auths.error/1
code                   stable registered string
family                 stable Rust-owned family
operation              stable operation name
stage                  stable stage name
summary                bounded, non-secret operator text
correlation ID         bounded opaque identifier
effect                 not-applied | possible | applied
retry                  never | safe | conditional | unknown
recommended action     one registered action
entered boundaries     approval/signer/state/credential/provider booleans
execution reference    optional redacted operator locator
decision reference     optional redacted operator locator
receipt reference      optional redacted operator locator
bounded causes         category only; never raw provider bodies
```

`auths.error/1` remains registry-bound exactly as the Rust parser is today: an unknown code is not a valid envelope and neither binding invents its effect/retry axes. Client/server capability negotiation includes the error-registry digest and refuses incompatible peers before a new effectful operation. If drift is nevertheless observed while recovering an already-entered GitHub workflow, the profile returns its registered phase-specific outcome-unknown result and durable recovery reference; it does not expose or classify the unknown string. Binding code never authors alternate prose or retryability.

Invariant combinations:

- `denied` always has `effect=not-applied` and never enters credential/provider;
- `retry=safe` implies `effect=not-applied`;
- `effect=possible` implies `retry=unknown` and a recovery handle or operator correlation;
- `effect=applied` never recommends blind execution retry;
- configuration mismatch is a negative value or stable error before credential/provider entry; and
- no error includes proof/action/provider bytes, keys, credentials, signatures, recovery bytes, filesystem contents, or high-cardinality domain values.

Receipt trust and GitHub promotion add the following exact Rust-registry definitions in the same Rust/binding change. `Refs` is `execution/decision/receipt`; `Y` permits that reference and `-` forbids it. `Causes` lists the normalized categories these new implementations emit; it is not a new per-code acceptance allowlist. The immutable `auths.error/1` parser continues to require a registered code and accept at most eight values from the existing closed cause enum. A future per-code allowlist or unknown-code acceptance would require a new error schema/registry version and complete migration table. The generator validates the existing operation/effect/retry/action/reference combinations and emits both language projections—bindings do not recreate them.

| Code | Operation | Family / stage | Allowed effect / retry | Action | Refs | Causes |
|---|---|---|---|---|---|---|
| `core.receipt-malformed` | verify | input / receipt | not-applied / never | correct-input | `-/-/-` | invalid-response, limit-exceeded |
| `core.receipt-signature-invalid` | verify | input / receipt | not-applied / never | inspect-receipt | `-/-/-` | invalid-response |
| `core.receipt-signer-untrusted` | verify | profile / receipt | not-applied / never | correct-configuration | `-/-/-` | unknown |
| `core.receipt-profile-denied` | verify | profile / receipt | not-applied / never | correct-configuration | `-/-/-` | — |
| `core.receipt-expired` | verify | state / receipt | not-applied / never | inspect-receipt | `-/-/-` | — |
| `core.receipt-trust-indeterminate` | verify | runtime / receipt | not-applied / conditional | satisfy-condition | `-/-/-` | unavailable, unknown |
| `mcp.receipt-invalid` | verify | input / receipt-profile-payload | not-applied / never | inspect-receipt | `-/-/-` | invalid-response, limit-exceeded |
| `core.verification-capacity` | verify | runtime / admission | not-applied / safe | retry-execution | `-/-/-` | limit-exceeded |
| `remote.authentication-failed` | verify | configuration / channel-authentication | not-applied / never | correct-configuration | `-/-/-` | invalid-response |
| `remote.response-malformed` | verify | runtime / remote-response | not-applied / never | contact-support | `-/-/-` | invalid-response, limit-exceeded |
| `remote.transport-unavailable` | verify | runtime / transport | not-applied / safe | retry-execution | `-/-/-` | unavailable |
| `remote.timeout` | verify | runtime / transport | not-applied / safe | retry-execution | `-/-/-` | timeout |
| `mcp.admission-capacity` | execute | runtime / admission | not-applied / safe | retry-execution | `-/-/-` | limit-exceeded |
| `mcp.delegation-capacity` | delegate | runtime / admission | not-applied / safe | retry-execution | `-/-/-` | limit-exceeded |
| `mcp.recovery-not-found` | resume | input / lifecycle-store | not-applied / never | correct-input | `-/-/-` | — |
| `mcp.recovery-kind-mismatch` | resume | input / lifecycle-store | not-applied / never | correct-input | `-/-/-` | conflict |
| `github.boundary-invalid` | create | configuration / boundary | not-applied / never | correct-configuration | `-/-/-` | invalid-response |
| `github.attenuation-denied` | delegate | profile / delegation | not-applied / never | correct-input | `-/-/-` | — |
| `github.delegation-outcome-unknown` | delegate | state / delegation | possible / unknown | resume-and-reconcile | `Y/Y/-` | cancelled, timeout, unavailable, unknown |
| `github.workflow-proof-invalid` | execute | input / workflow-proof | not-applied / never | correct-input | `-/Y/-` | invalid-response |
| `github.workflow-expired` | execute | state / expiry | not-applied / never | satisfy-condition | `-/Y/-` | — |
| `github.workflow-cancelled` | execute | state / cancellation | not-applied / never | satisfy-condition | `-/Y/-` | cancelled |
| `github.executor-audience-mismatch` | execute | profile / audience | not-applied / never | correct-configuration | `-/Y/-` | conflict |
| `github.repository-mismatch` | execute | profile / repository-boundary | not-applied / never | correct-input | `-/Y/-` | conflict |
| `github.repository-renamed-or-transferred` | execute | state / repository-boundary | not-applied / never | satisfy-condition | `-/Y/-` | conflict |
| `github.issue-mismatch` | execute | profile / issue-boundary | not-applied / never | correct-input | `-/Y/-` | conflict |
| `github.issue-not-open` | execute | state / issue-boundary | not-applied / never | satisfy-condition | `-/Y/-` | conflict |
| `github.base-revision-mismatch` | execute | state / base-revision | not-applied / never | satisfy-condition | `-/Y/-` | conflict |
| `github.branch-already-exists` | execute | provider / branch-precondition | not-applied / never | correct-input | `Y/Y/-` | conflict |
| `github.pull-request-already-exists` | execute | provider / pull-request-precondition | not-applied / never | correct-input | `Y/Y/-` | conflict |
| `github.candidate-bundle-malformed` | verify | input / candidate-inspection | not-applied / never | correct-input | `-/-/-` | invalid-response |
| `github.candidate-limit-exceeded` | verify | input / candidate-inspection | not-applied / never | correct-input | `-/-/-` | limit-exceeded |
| `github.candidate-not-descendant` | verify | profile / candidate-inspection | not-applied / never | correct-input | `-/-/-` | conflict |
| `github.merge-commit-denied` | verify | profile / candidate-inspection | not-applied / never | correct-input | `-/-/-` | — |
| `github.unsupported-git-object` | verify | input / candidate-inspection | not-applied / never | correct-input | `-/-/-` | invalid-response |
| `github.path-not-allowed` | verify | profile / candidate-inspection | not-applied / never | correct-input | `-/-/-` | — |
| `github.path-explicitly-denied` | verify | profile / candidate-inspection | not-applied / never | correct-input | `-/-/-` | — |
| `github.file-mode-denied` | verify | profile / candidate-inspection | not-applied / never | correct-input | `-/-/-` | — |
| `github.repository-automation-policy-mismatch` | execute | runtime / repository-evidence | not-applied / conditional | satisfy-condition | `-/Y/-` | unavailable, conflict |
| `github.branch-budget-exhausted` | execute | state / branch-reservation | not-applied / never | satisfy-condition | `-/Y/-` | limit-exceeded |
| `github.pull-request-budget-exhausted` | execute | state / pull-request-reservation | not-applied / never | satisfy-condition | `-/Y/-` | limit-exceeded |
| `github.evidence-missing` | execute | runtime / provider-evidence | not-applied / conditional | satisfy-condition | `-/Y/-` | unavailable |
| `github.evidence-stale` | execute | runtime / provider-evidence | not-applied / conditional | satisfy-condition | `-/Y/-` | unavailable |
| `github.verifier-configuration-mismatch` | execute | configuration / required-executed | not-applied / never | correct-configuration | `-/Y/-` | conflict |
| `github.exact-action-mismatch` | execute | input / exact-action | not-applied / never | correct-input | `-/Y/-` | conflict |
| `github.candidate-substituted` | execute | input / exact-candidate-claim | not-applied / never | correct-input | `-/-/-` | conflict |
| `github.credential-boundary-failed` | execute | internal / credential-boundary | not-applied / never | contact-support | `-/Y/-` | invalid-response |
| `github.branch-rejected` | execute | provider / branch-result | not-applied / conditional | satisfy-condition | `Y/Y/Y` | invalid-response |
| `github.pull-request-rejected` | execute | provider / pull-request-result | not-applied / conditional | satisfy-condition | `Y/Y/Y` | invalid-response |
| `github.delegation-capacity` | delegate | runtime / admission | not-applied / safe | retry-execution | `-/-/-` | limit-exceeded |
| `github.execution-capacity` | execute | runtime / admission | not-applied / safe | retry-execution | `-/-/-` | limit-exceeded |
| `github.branch-outcome-unknown` | execute | provider / branch-observation | possible / unknown | resume-and-reconcile | `Y/Y/-` | cancelled, timeout, unavailable, unknown |
| `github.pull-request-outcome-unknown` | execute | provider / pull-request-observation | possible / unknown | resume-and-reconcile | `Y/Y/-` | cancelled, timeout, unavailable, unknown |
| `github.workflow-terminal-applied` | resume | state / recovery | applied / never | inspect-receipt | `Y/Y/Y` | corrupt-state, invalid-response |
| `github.workflow-terminal-not-applied` | resume | state / recovery | not-applied / never | inspect-receipt | `Y/Y/Y` | corrupt-state, invalid-response |
| `github.receipt-invalid` | verify | input / receipt-profile-payload | not-applied / never | inspect-receipt | `-/-/-` | invalid-response |

Identity adds these exact rows; every result has `effect=not-applied` because identity inspection never enters a domain provider:

| Code | Operation | Family / stage | Retry / action | Adapter mapping |
|---|---|---|---|---|
| `identity.packet-malformed` | decode | input / identity-packet | never / correct-input | native decode failure |
| `identity.method-unsupported` | decode | configuration / identity-method | never / correct-configuration | decoded method has no registered method |
| `identity.not-found` | resolve | profile / identity-resolution | never / correct-input | resolver `rejected:not-found` |
| `identity.resolution-rejected` | resolve | profile / identity-resolution | never / correct-input | resolver/method `rejected:malformed|not-permitted|expired|invalid-signature` |
| `identity.resolution-indeterminate` | resolve | runtime / identity-resolution | safe / retry-execution | resolver/method `indeterminate:*` or thrown exception |
| `identity.evidence-expired` | validate | state / identity-evidence | conditional / satisfy-condition | validator `rejected:expired` |
| `identity.validation-rejected` | validate | profile / identity-validation | never / correct-input | other validator rejection |
| `identity.validation-indeterminate` | validate | runtime / identity-validation | safe / retry-execution | validator `indeterminate:*` or thrown exception |
| `identity.relationship-denied` | authenticate | profile / identity-relationship | never / correct-input | missing relationship or authenticator `rejected:not-permitted` |
| `identity.signature-invalid` | authenticate | input / identity-signature | never / correct-input | authenticator `rejected:invalid-signature|malformed` |
| `identity.authentication-indeterminate` | authenticate | runtime / identity-authenticator | safe / retry-execution | authenticator `indeterminate:*` or thrown exception |

For each `indeterminate:*`, the normalized cause is exactly `cancelled`, `timeout`, `unavailable`, or `invalid-response`; arbitrary exceptions map to `unavailable` and their text is redacted. Unsupported rejection reasons at a stage are `identity.*-rejected`, never silently reclassified as signature failure. These rows, summaries, and cause projections are Rust fixtures shared by both bindings.

This adds `delegate` to the registry's closed operation vocabulary without changing `auths.error/1` cause acceptance. The public cause enum does not widen. Registry/reference flags describe the bounded error envelope, while typed recovery and receipt values remain mandatory where their result variant requires them.

The two `github.workflow-terminal-*` codes prevent one registered code from changing effect axes. Persisted workflow state selects exactly one. Neither permits `possible`; unresolved workflows use one of the two outcome-unknown codes and a recovery handle.

### 4.2 Execution result conventions

Each profile defines variants with these semantics:

| Meaning | Required shape |
|---|---|
| Completed | `kind=completed`, `completion=executed|replayed|reconciled`, typed value/domain result, portable receipt(s) |
| Denied | pre-effect authorization/policy refusal and `AuthsIssue(effect=not-applied)` |
| Indeterminate | pre-effect inability to establish a trustworthy decision; never used for possible provider effect |
| Not applied | provider/runtime proved no external effect, with safe/conditional retry classification |
| Conflict | same caller key with different canonical commitments; no provider entry |
| Recovery required | external effect is possible, durable profile recovery handle is mandatory |
| Partial | an earlier profile phase is known applied while a later phase is proved not applied; carries the applied object, later-phase issue, and ordered receipts |
| Failed after application | effect is known applied but the domain operation is terminally unsuccessful; receipt when available |

Exact replay returns the original typed value and receipt with `completion="replayed"`; it is not a failure and does not mint new credentials or re-enter the provider.

### 4.3 Idempotency and concurrency

Every effectful call requires a caller-owned `idempotencyKey`/`idempotency_key`. Auths derives any provider idempotency token from that key plus verified canonical commitments; callers cannot inject a provider key.

The public key grammar is identical in both SDKs: 1–128 ASCII characters, matching `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`. It is an application correlation value, not a secret. Validation and canonical commitment occur before state/provider entry; Unicode normalization, trimming, case folding, empty values, and silent truncation are forbidden.

Where this proposal says “registered token,” the exact grammar is 1–128 ASCII bytes matching `[A-Za-z][A-Za-z0-9._:/-]{0,127}`. It applies to MCP tool/service/delegation/observer/source names, identity method/relationship/authenticator IDs, custody adapter/key-version/suite tokens, and conformance suite/case IDs unless a narrower field rule is stated. Unicode, whitespace, percent-decoding, normalization, empty components created by `//`, and implicit case folding are rejected.

- same key + same commitments + complete: return the original completed value/receipt;
- same key + same commitments + pending/unknown: return the same recovery identity;
- same key + changed commitments: conflict before approval, credential, or provider entry;
- concurrent identical calls: exactly one provider entry;
- concurrent final-capacity calls: at most one reservation winner;
- no hidden retries of approval, signer, store, credential, provider, or reconciliation calls; and
- ordered plans stop before every later member after the first non-completed member.

Each MCP session and GitHub client admits at most 32 concurrent effectful operations; each identity or remote-verification client admits at most 32 concurrent network/resolver operations. Same-key coalesced waiters count as one provider operation and at most 256 may await it in memory. A 257th same-key caller is not misclassified as pre-effect capacity failure: it performs one non-waiting durable lookup and returns the original terminal value, conflict, or the same recovery identity; a still-pending write-ahead record returns that record's same locator rather than asserting non-application. Only a previously unseen key can receive admission-capacity `indeterminate`. There is no internal admission queue. New-key overflow is refused before entry: MCP execute/plan uses `mcp.admission-capacity`, MCP delegation uses `mcp.delegation-capacity`, GitHub uses its phase-specific `github.*-capacity`, remote verification uses `core.verification-capacity`, and identity uses the stage-specific `identity.*-indeterminate` code with normalized `unavailable`. All use their registered safe-retry mapping. `events()` is different: asking one session for a fifth diagnostic subscriber is local programmer/resource misuse and throws `RangeError`/`ValueError` synchronously; it never fabricates an execute-stage issue.

Durable state is cumulatively bounded as well as per call. One MCP development state directory admits at most 16,384 idempotency commitments, 1,024 unresolved attempts, 16,384 receipts, and 1 GiB across records, blobs, receipts, and indices. One GitHub control-plane principal admits at most 1,000,000 compact idempotency commitments, 4,096 unresolved workflows, 100,000 retained terminal workflow records, and 64 GiB of workflow/receipt data, with at most 10 new workflow keys per second and 60 per minute. The final available slot is acquired atomically; concurrent boundary winners cannot exceed a quota. An unresolved/possible-effect record is never garbage-collected. Terminal detail and receipts observe their stated minimum retention, after which the server may compact them to a non-reusable key/commitment tombstone; the tombstone remains charged against the key quota and is never interpreted as non-application. When a fixed quota is full, new work is refused before authority/custody/provider entry with the phase-specific capacity result. There is no public “prune this key and permit reuse” escape hatch; operators archive/rotate an entire development principal or expand a production tenant only through a new versioned server configuration and audit event.

### 4.4 Cancellation

- Before durable provider entry/transmission: ordinary cancellation is allowed and the operation is provably not applied.
- After provider entry/transmission: TypeScript must not reject with a bare `AbortError`, and Python must not propagate `CancelledError`, until the SDK has durably recorded a terminal result or recoverable reference.
- A post-entry disconnect/cancellation returns recovery-required when the caller is still present. If the task is forcibly torn down, the recovery locator was persisted before transmission and is retrievable by the original idempotency key/operator correlation.
- Effect-free identity/verification honors caller cancellation normally: an externally aborted TypeScript signal rejects with the host `AbortError`, and Python caller-task cancellation propagates `CancelledError` without being swallowed. By contrast, an adapter that returns its closed `indeterminate:cancelled` value is projected to the stage-specific identity indeterminate result, and an SDK-owned deadline expiry is the stage-specific `indeterminate:timeout`; arbitrary adapter cancellation cannot be misreported as denial.
- Python network code must use cancellation-aware async transport or explicitly tracked shielded work. Untracked `to_thread(urllib)` is prohibited for effectful calls.

### 4.5 Resource ownership and disposal

- Stateful/network clients are safe for concurrent independent calls.
- `close`/`aclose` is idempotent and rejects new calls after closing.
- Close stops admission, waits until in-flight effectful calls are durable terminal/recoverable, closes delegated children in reverse creation order, then owned provider/transport resources.
- A delegated child may close independently. Closing a parent closes remaining children.
- Default transports are owned. Injected transports are borrowed unless `ownership: "owned"`/`owns_transport=True` is explicit.
- Closing a remote client does not delete durable server workflows.
- Offline verifier values require no disposal after initialization.

An in-process development handler is cooperative, not forcibly cancellable. On timeout/abort the SDK signals it and waits a fixed 5-second drain interval. If it remains unsettled, the durable attempt stays `possible`, the caller receives recovery-required, and the SDK detaches only after installing a bounded rejection sink and a process-local active-attempt guard; a late return is never accepted as a normal completion. Every such borrowed callback remains SDK-tracked, appears in `outstandingBorrowedCallbacks`/`outstanding_borrowed_callbacks`, and continues to consume both its state-directory admission record and one of a process-wide maximum of 32 detached-callback slots until it actually settles; the 33rd is refused before provider entry and no unbounded guard/rejection-sink collection exists. Reopen in the same process sees the guard and keeps recovery inconclusive. A different process cannot prove that the prior callback stopped, so it also cannot release/retry: generic development reconciliation has no non-application result, and only observed application can close the attempt. `close` waits for the five-second drain, persists the unresolved attempt, releases SDK-owned handles/locks, and returns—it does not claim the borrowed application callback stopped. In Python, a coroutine that suppresses cancellation is likewise tracked and may keep its event loop alive after `aclose`; this is an explicit application-owned outstanding callback, not an SDK-owned background task. Production profiles must use a provider boundary with profile-owned termination/finality semantics rather than this cooperative adapter.

### 4.6 Recovery handles

Recovery handles are profile-specific, validated opaque capabilities. They have bounded binary import/export, no JSON or useful string representation, redacted `repr`/inspection, and are documented as secrets. Generic `ExecutionReference` is removed because the current root format is actually MCP-specific.

### 4.7 Sync versus async

- Encoding, bounded decoding, inspection, and offline verification are synchronous once the TypeScript WASM verifier has been loaded.
- TypeScript factories that load WASM are asynchronous; their verification methods are synchronous. Batch verification yields between bounded chunks and accepts `AbortSignal`.
- Python offline verification is synchronous.
- Network, resolver, approval, signer, store, provider, recovery, and session lifecycle operations are asynchronous.
- There are no awaitable/context-manager hybrid objects.
- TypeScript durations name their units (`timeoutMs`, `expiresInMs`). Python uses `datetime.timedelta`. For APIs paired with TypeScript milliseconds, Python accepts only finite, non-negative durations that are exact whole milliseconds and inside the field's stated integer range; sub-millisecond values, negative values, and overflow are rejected before I/O rather than rounded. For wire-second fields, Python accepts only exact whole seconds. Wire timestamps remain exact integers and neither binding floors, ceils, nor silently saturates a duration.

### 4.8 Version and time-unit decisions

The selected lifecycle semantic subject is `auths.product.reservation-execution-contract/2`, matching the shipping runtime contract and lifecycle fixture manifest. The stale lifecycle `/1` specification reference is corrected in implementation unit 7; neither binding accepts or aliases both subjects. This redesign deliberately selects the new MCP profile `auths.mcp/2` and session contract `auths.mcp-session/2`: v1 permits a normal handler to claim `not-applied`, while v2 permits only `applied | possible`; public generic development reconciliation can prove application or remain inconclusive, and only a future profile-owned Rust finality observer may prove non-application. The cutover adds immutable v2 profile/session manifests, specification, fixtures, receipt profile version, and runtime capability entries atomically; it never edits the meaning of either v1 identity or aliases v1 to v2.

Receipt, identity/custody, provider-attempt, and lifecycle reconciliation timestamps are whole Unix seconds because their Rust owners store and sign seconds. Those public fields therefore end in `UnixSeconds`/`unix_seconds`, and age configuration ends in `Seconds`/`seconds`; bindings do not relabel wire seconds as milliseconds. MCP diagnostic events and GitHub boundary/workflow observations remain explicitly Unix milliseconds because those owning contracts use milliseconds. Every cross-language fixture includes a non-round test timestamp that would expose a 1,000× conversion error.

### 4.9 Binary and collection ownership

Every TypeScript `Uint8Array` input is copied synchronously before an asynchronous boundary or native call can retain it; returned arrays are fresh snapshots. Mutating a caller buffer or a returned inspection snapshot cannot change a committed action, trust anchor, candidate, identity, result, recovery reference, or receipt inspector input. Python accepts immutable `bytes` at security boundaries and copies iterable/sequence inputs into bounded tuples. No API retains a caller-owned mutable mapping/list, invokes a getter/serializer, or exposes a mutable view of native memory. Length/depth/work validation happens before allocation proportional to attacker-declared sizes.

### 4.10 Fixed package limits

These values are selected public-contract facts, not implementation suggestions. The core-verification, error-envelope, and base identity rows reproduce current Rust-owned limits. Rows explicitly labeled v2 and every remote-verification limit are new selections that implementation units 3, 8, 9, and 10 must add atomically to Rust contracts, manifests, fixtures, routes, and both bindings before those APIs ship. “Default” is what the no-options local verifier and the remote-verification v1 route enforce. “Hard” is the greatest value a future Rust-owned configuration may select without a new semantic subject; neither SDK exposes a knob that raises a default. All byte counts are canonical bytes, collection counts are cumulative, and boundary+1 is rejected before allocation or work proportional to an attacker-declared size.

| Core verification resource | Default | Hard |
|---|---:|---:|
| proof bundle | 256 KiB | 8 MiB |
| action | 2 MiB | 16 MiB |
| trusted context | 2 MiB | 16 MiB |
| grants / actions / plan leaves | 16 / 16 / 16 | 256 / 128 / 128 |
| plan depth / branching | 8 / 16 | 16 / 128 |
| evidence objects / evidence bytes | 32 / 64 KiB | 512 / 2 MiB |
| bindings / principal statuses / grant statuses | 32 each | 512 each |
| attachments / aggregate attachment bytes | 32 / 1 MiB | 512 / 8 MiB |
| signatures / one signature | 64 / 512 B | 1,024 / 4,096 B |
| permissions / audiences | 64 / 32 | 1,024 / 256 |
| extensions / aggregate extension bytes | 8 / 16 KiB | 32 / 64 KiB |
| body digests / binding evidence | 32 / 8 | 256 / 32 |
| canonical body | 1 MiB | 8 MiB |
| work units | 50,000 | 1,000,000 |
| registry entries / trust anchors | 64 / 32 | 1,024 / 1,024 |

`verifyMany` additionally accepts 1–256 inputs and at most 16 MiB across copied proof/action/context bytes. Rust checks per-input and aggregate limits before canonical traversal; the returned projections are at most 2 MiB aggregate and never echo input bytes. The remote request uses these default per-field limits and has an exact 4,718,592-byte encoded-body ceiling; its response defaults to 8 MiB and may be lowered to 1 KiB or raised only through 16 MiB. Correlation IDs and every `auths.error/1` code/family/operation/stage/reference token are at most 128 UTF-8 bytes, summaries are at most 256 UTF-8 bytes, and causes are at most eight closed categories. The remote server streams/length-checks CBOR fields, so a declared or actual over-limit byte string is rejected before copying it.

A portable receipt input is 1 B–32 MiB, its canonical profile payload is at most 16 MiB, and it contains 1–32 reason tokens of 1–128 UTF-8 bytes each. Profile-owned ceilings may be lower (MCP and GitHub receipts are 1 MiB in this cut). `verifyReceipt` checks the outer length before copying or decoding and then checks declared payload/reason lengths before proportional allocation.

Network configuration is bounded before URL/header construction. An endpoint origin is 1–2,048 ASCII bytes, must canonicalize to `https://host[:port]` with an empty/root path, and has no userinfo, query, fragment, Unicode host, zone identifier, or caller-supplied route; DNS names are already lowercase A-labels, IPv4/IPv6 literals use their canonical parser form, and ports are 1–65,535. A Bearer token is 16–8,192 ASCII bytes matching RFC 6750's `b64token` character set with optional trailing `=` and no whitespace/control byte. Response status is an integer 100–599. Media type is 1–128 lowercase ASCII bytes matching `type/subtype` plus bounded token parameters; duplicate/conflicting content-type headers are rejected. Logs and diagnostics expose only the canonical origin and never token, path, query, header, or response body.

| Identity resource | Exact maximum |
|---|---:|
| method, suite, relationship, purpose ID | 128 UTF-8 bytes |
| identity ID | 512 UTF-8 bytes |
| public key, method material, verification material, signature | 128 KiB each |
| relationships per identity / materials per relationship | 16 / 16 |
| authenticated message | 64 KiB |
| legacy packet / descriptor packet | 328,483 B / 303,397 B |
| resolver `maximumBytes` | default 131,072 B; range 1–328,483 B |
| configured methods / authenticators | 1–32 / 1–32 |
| provenance / history entries | 32 each, 128 UTF-8 bytes each |

Identity packet maxima are the exact formulas from the current Rust field constants, not rounded transport limits. Adapter output is measured cumulatively against the same record/packet ceiling. Extra configured adapters, relationships, materials, provenance, or history fail during client creation/result validation; arbitrary adapter exceptions do not bypass these limits.

The new `signer-custody/2` and `atomic-reservation-store/2` contracts select these exact bounds. They are versioned as `/2` because adding descriptor binding, cancellation, lifecycle, and durability claims changes the v1 mechanism shapes; v1 suites and fixtures retain their original meaning and are not aliases.

| Custody v2 resource | Exact bound |
|---|---:|
| adapter ID, key version, request ID | 1–128 bytes, registered-token grammar |
| principal method, verification method, suite | 1–128 bytes, registered-token grammar |
| principal | 1–512 UTF-8 bytes |
| object ID / transaction digest | exactly 32 B / exactly 32 B |
| signing preimage | 1 B–8 MiB |
| review fields | 0–32; label 1–128 B; value 1–4 KiB; 64 KiB aggregate |
| control evidence | 0–16; type/media type 1–128 B; item 1 B–2 MiB; 8 MiB aggregate |
| signature | 1–4,096 B |

The development signer descriptor further fixes `principalMethod="auths.raw-key/1"` and `verificationMethod="root-v1"`; the principal and Ed25519 key use the Rust raw-key canonical construction from the manifest root seed with domain labels `auths.mcp-development-state/2/principal` and `/custody-ed25519`. Those labels, bytes, and descriptor are golden-fixtured so reopen cannot choose another derivation.

| Reservation v2 resource | Exact bound |
|---|---:|
| store kind | 1–128 bytes, registered-token grammar |
| key | 1–256 UTF-8 bytes |
| commitment | exactly 32 B |
| value | 1 B–256 KiB |
| MCP-encoded lifecycle value (when used by MCP) | 256 KiB; depth 16 |
| MCP intents / attempts / observations / events | 32 / 16 / 32 / 128 |

The reservation store treats `value` as opaque bytes and never claims to parse a lifecycle record. The MCP integration independently uses the narrower lifecycle row and validates it before reservation.

GitHub v2 additionally fixes action/grant bytes at 256 KiB, workflow IDs at 12–96 ASCII bytes, node IDs at 8–128 bytes, owner/repository components at 1–100 bytes, refs at 1–255 bytes, audiences at 256 bytes, and full object IDs at exactly 40 or 64 lowercase hex characters. Recovery references are 1–16 KiB. Provider requests are at most 32 KiB; PR path/title fields 512 bytes, body 16 KiB, and head/base refs 256 bytes. Each Git subprocess output is 4 MiB, GitHub HTTP responses 1 MiB, signed receipts 1 MiB each, per-workflow receipt log 64 MiB, public receipt lists 16 items/8 MiB aggregate, and the candidate/path/object ceilings in section 5.8 remain controlling. `agentLabel`/`agent_label` is a 1–128-byte registered token. An empty selected allow-pattern set is rejected; omission means the complete sealed allow set, while an explicit set must contain 1–128 byte-identical members.

## 5. Exact proposed TypeScript public surface

The declarations in this section are normative. Only `export`ed names are public. Brands are runtime-backed sealed values, not TypeScript-only claims: implementations must reject fabricated objects even after casts, cloning, prototype manipulation, or cross-realm transfer.

### 5.1 `@auths-dev/sdk`

```ts
export type EffectState = "not-applied" | "possible" | "applied";
export type RetryClass = "never" | "safe" | "conditional" | "unknown";
export type RecommendedAction =
  | "correct-input"
  | "correct-configuration"
  | "install-compatible-runtime"
  | "retry-execution"
  | "satisfy-condition"
  | "resume-and-reconcile"
  | "inspect-receipt"
  | "contact-support";

export type KnownAuthsErrorCode =
  | "core.invalid-configuration"
  | "core.unsupported-abi"
  | "core.unsupported-semantic-subject"
  | "core.malformed-input"
  | "core.native-runtime-unavailable"
  | "core.forged-execution-reference"
  | "core.runtime-conflict"
  | "core.runtime-unavailable"
  | "core.runtime-cancelled"
  | "core.outcome-unknown"
  | "core.observation-pending"
  | "core.observation-inconclusive"
  | "core.workflow-terminal"
  | "core.internal-invariant"
  | "core.authorization-denied"
  | "core.authorization-indeterminate"
  | "core.unauthenticated-principal"
  | "identity.packet-malformed"
  | "identity.method-unsupported"
  | "identity.not-found"
  | "identity.resolution-rejected"
  | "identity.resolution-indeterminate"
  | "identity.evidence-expired"
  | "identity.validation-rejected"
  | "identity.validation-indeterminate"
  | "identity.relationship-denied"
  | "identity.signature-invalid"
  | "identity.authentication-indeterminate"
  | "core.receipt-malformed"
  | "core.receipt-signature-invalid"
  | "core.receipt-signer-untrusted"
  | "core.receipt-profile-denied"
  | "core.receipt-expired"
  | "core.receipt-trust-indeterminate"
  | "core.verification-capacity"
  | "remote.authentication-failed"
  | "remote.response-malformed"
  | "remote.transport-unavailable"
  | "remote.timeout"
  | "mcp.invalid-handler-output"
  | "mcp.handler-failed"
  | "mcp.handler-timeout"
  | "mcp.cancelled-before-entry"
  | "mcp.reservation-conflict"
  | "mcp.replay"
  | "mcp.receipt-persist-failed"
  | "mcp.reconciliation-pending"
  | "mcp.receipt-invalid"
  | "mcp.admission-capacity"
  | "mcp.delegation-capacity"
  | "mcp.recovery-not-found"
  | "mcp.recovery-kind-mismatch"
  | "plan.member-interrupted"
  | "plan.member-failed-before-entry"
  | "plan.resume-reference-invalid"
  | "plan.reconciliation-pending"
  | "plan.action-substituted"
  | "custody.denied"
  | "custody.cancelled"
  | "custody.throttled"
  | "custody.unavailable"
  | "custody.revoked-key"
  | "custody.disabled-key"
  | "custody.provider-unknown"
  | "custody.invalid-provider-response"
  | "custody.request-mismatch"
  | "custody.principal-mismatch"
  | "custody.descriptor-mismatch"
  | "custody.key-version-mismatch"
  | "custody.transaction-mismatch"
  | "custody.malformed-signature"
  | "custody.non-canonical-signature"
  | "custody.signature-verification-failed"
  | "custody.evidence-mismatch"
  | "custody.lifecycle-not-permitted"
  | "github.boundary-invalid"
  | "github.attenuation-denied"
  | "github.delegation-outcome-unknown"
  | "github.workflow-proof-invalid"
  | "github.workflow-expired"
  | "github.workflow-cancelled"
  | "github.executor-audience-mismatch"
  | "github.repository-mismatch"
  | "github.repository-renamed-or-transferred"
  | "github.issue-mismatch"
  | "github.issue-not-open"
  | "github.base-revision-mismatch"
  | "github.branch-already-exists"
  | "github.pull-request-already-exists"
  | "github.candidate-bundle-malformed"
  | "github.candidate-limit-exceeded"
  | "github.candidate-not-descendant"
  | "github.merge-commit-denied"
  | "github.unsupported-git-object"
  | "github.path-not-allowed"
  | "github.path-explicitly-denied"
  | "github.file-mode-denied"
  | "github.repository-automation-policy-mismatch"
  | "github.branch-budget-exhausted"
  | "github.pull-request-budget-exhausted"
  | "github.evidence-missing"
  | "github.evidence-stale"
  | "github.verifier-configuration-mismatch"
  | "github.exact-action-mismatch"
  | "github.candidate-substituted"
  | "github.credential-boundary-failed"
  | "github.branch-rejected"
  | "github.pull-request-rejected"
  | "github.delegation-capacity"
  | "github.execution-capacity"
  | "github.branch-outcome-unknown"
  | "github.pull-request-outcome-unknown"
  | "github.workflow-terminal-applied"
  | "github.workflow-terminal-not-applied"
  | "github.receipt-invalid";

export interface AuthsIssue {
  readonly schema: "auths.error/1";
  readonly code: KnownAuthsErrorCode;
  readonly family:
    | "configuration"
    | "input"
    | "runtime"
    | "profile"
    | "provider"
    | "state"
    | "internal";
  readonly operation: string;
  readonly stage: string;
  readonly summary: string;
  readonly correlationId: string;
  readonly effect: EffectState;
  readonly retry: RetryClass;
  readonly recommendedAction: RecommendedAction;
  readonly enteredBoundaries: Readonly<{
    approval: boolean;
    signer: boolean;
    state: boolean;
    credential: boolean;
    provider: boolean;
  }>;
  readonly executionReference?: string;
  readonly decisionReference?: string;
  readonly receiptReference?: string;
  readonly causes: readonly (
    | "cancelled"
    | "conflict"
    | "corrupt-state"
    | "invalid-response"
    | "limit-exceeded"
    | "timeout"
    | "unavailable"
    | "unknown"
  )[];
}

export class AuthsError extends Error {
  private constructor(details: AuthsIssue);
  readonly details: AuthsIssue;
  readonly code: KnownAuthsErrorCode;
  readonly effect: EffectState;
  readonly retry: RetryClass;
  readonly recommendedAction: RecommendedAction;

  static isKnownCode(code: string): code is KnownAuthsErrorCode;
}

export function isAuthsError(value: unknown): value is AuthsError;

declare const receiptBrand: unique symbol;
export interface Receipt {
  readonly [receiptBrand]: true;
  readonly id: string;
  toBytes(): Uint8Array;
  toJSON(): never;
}

export interface RuntimeInfo {
  readonly sdkVersion: string;
  readonly host: "node" | "browser" | "worker";
  readonly hostVersion: string;
  readonly platform: string;
  readonly authoringAbi: number;
  readonly identityAbi: number;
  readonly errorRegistryDigest: string;
  readonly compatible: boolean;
  readonly semanticSubjects: readonly string[];
  readonly profiles: readonly string[];
  readonly capabilities: readonly string[];
  readonly warnings: readonly string[];
}

export function runtimeInfo(): Promise<RuntimeInfo>;
```

Root runtime values are exactly `AuthsError`, `isAuthsError`, and `runtimeInfo`. `Receipt` has no constructor or raw JSON form. `AuthsIssue` is a host projection, not the serialized `auths.error/1` map: `enteredBoundaries` is the idiomatic projection of the wire key `entered`. Native and authenticated protocol decoders validate the exact registered Rust envelope before producing it. There is deliberately no public error JSON/dictionary parser or serializer, so applications cannot mistake the projection for a wire schema or mint classifications.

### 5.2 `@auths-dev/sdk/verify`

```ts
import type { AuthsIssue, Receipt } from "@auths-dev/sdk";

export type VerificationStage =
  | "decode"
  | "resolve"
  | "principal-control"
  | "authority"
  | "complete";

export interface VerificationInput {
  readonly proof: Uint8Array;
  readonly action: Uint8Array;
  readonly trustedContext: Uint8Array;
}

export interface VerificationMetrics {
  readonly proofBytes: bigint;
  readonly actionBytes: bigint;
  readonly contextBytes: bigint;
  readonly objectCount: bigint;
  readonly planLeaves: bigint;
  readonly planDepth: bigint;
  readonly workUnits: bigint;
}

interface VerificationCommon {
  readonly code: string;
  readonly stage: VerificationStage;
  readonly correlationId: string;
  readonly metrics: VerificationMetrics;
  readonly requiredConfiguration?: Uint8Array;
  readonly executedConfiguration: Uint8Array;
  readonly decisionBytes: Uint8Array;
}

export type VerificationResult =
  | (VerificationCommon & Readonly<{ kind: "authorized" }>)
  | (VerificationCommon & Readonly<{
      kind: "denied";
      issue: AuthsIssue & Readonly<{ effect: "not-applied" }>;
    }>)
  | (VerificationCommon & Readonly<{
      kind: "indeterminate";
      issue: AuthsIssue & Readonly<{ effect: "not-applied" }>;
    }>);

export interface VerificationInspection {
  readonly kind: VerificationResult["kind"];
  readonly code: string;
  readonly stage: VerificationStage;
  readonly resultCommitment: Uint8Array;
  readonly actionCommitment?: Uint8Array;
  readonly requiredConfigurationCommitment?: Uint8Array;
  readonly executedConfigurationCommitment: Uint8Array;
  readonly metrics: VerificationMetrics;
  readonly approval?: Readonly<{
    policyId: string;
    evaluatorVersion: string;
    decision: "approved" | "rejected";
    commitment: Uint8Array;
  }>;
}

export interface ReceiptProfile {
  readonly id: string;
  readonly version: number;
}

export interface ReceiptTrustAnchor {
  readonly role: "decision" | "execution";
  readonly principal: string;
  readonly verificationMethod: string;
  readonly suite: "ed25519-v1" | "p256-sha256-v1";
  readonly publicKey: Uint8Array;
}

declare const receiptTrustPolicyBrand: unique symbol;
export interface ReceiptTrustPolicy {
  readonly [receiptTrustPolicyBrand]: true;
  readonly allowedProfiles: readonly ReceiptProfile[];
  readonly anchorCount: number;
}

export function pinnedReceiptTrust(options: Readonly<{
  anchors: readonly ReceiptTrustAnchor[];
  allowedProfiles: readonly ReceiptProfile[];
  /** Fixed test clock; omission samples the trusted clock on each verify. */
  verificationTimeUnixSeconds?: bigint;
  /** Default 86_400; accepted range 1..31_536_000 seconds. */
  maximumReceiptAgeSeconds?: bigint;
}>): Promise<ReceiptTrustPolicy>;

export interface DecisionReceiptDetails {
  readonly kind: "decision";
  readonly receiptId: string;
  readonly profile: ReceiptProfile;
  readonly decision: "authorized" | "denied" | "indeterminate";
  readonly reasons: readonly string[];
  readonly decidedAtUnixSeconds: bigint;
  readonly decisionSigner: Readonly<{
    principal: string;
    verificationMethod: string;
    suite: string;
  }>;
  readonly commitments: Readonly<{
    proof: string;
    action: string;
    context: string;
    principalStatus: string;
    grantStatus: string;
  }>;
  readonly profilePayloadCommitment: string;
}

export interface ExecutionReceiptDetails {
  readonly kind: "execution";
  readonly decisionReceiptId: string;
  readonly executionReceiptId: string;
  readonly profile: ReceiptProfile;
  readonly decision: "authorized" | "denied" | "indeterminate";
  readonly outcome: "succeeded" | "failed" | "indeterminate";
  readonly reasons: readonly string[];
  readonly decidedAtUnixSeconds: bigint;
  readonly completedAtUnixSeconds: bigint;
  readonly decisionSigner: Readonly<{
    principal: string;
    verificationMethod: string;
    suite: string;
  }>;
  readonly executionSigner: Readonly<{
    principal: string;
    verificationMethod: string;
    suite: string;
  }>;
  readonly commitments: Readonly<{
    proof: string;
    action: string;
    context: string;
    principalStatus: string;
    grantStatus: string;
    executionLease: string;
    command: string;
    result?: string;
  }>;
  readonly profilePayloadCommitment: string;
}

export type ReceiptEnvelopeDetails =
  | DecisionReceiptDetails
  | ExecutionReceiptDetails;

declare const verifiedReceiptBrand: unique symbol;
export interface VerifiedReceipt {
  readonly [verifiedReceiptBrand]: true;
  readonly kind: "verified";
  readonly receipt: Receipt;
  readonly details: ReceiptEnvelopeDetails;
}

export type ReceiptVerification =
  | VerifiedReceipt
  | Readonly<{
      kind: "rejected";
      issue: AuthsIssue & Readonly<{ effect: "not-applied" }>;
    }>
  | Readonly<{
      kind: "indeterminate";
      issue: AuthsIssue & Readonly<{ effect: "not-applied" }>;
    }>;

export interface VerificationOptions {
  readonly correlationId?: string;
}

export interface VerificationBatchOptions {
  readonly signal?: AbortSignal;
  readonly chunkSize?: number; // 1..256; default 32
  readonly correlationId?: () => string;
}

export interface ReceiptVerificationInput {
  readonly receipt: Receipt | Uint8Array;
  readonly trust: ReceiptTrustPolicy;
  /** Required for execution receipts; forbidden for decision receipts. */
  readonly linkedDecisionReceipt?: Receipt | Uint8Array;
}

export class Verifier {
  private constructor();
  verify(
    input: VerificationInput,
    options?: VerificationOptions,
  ): VerificationResult;
  verifyMany(
    inputs: readonly VerificationInput[],
    options?: VerificationBatchOptions,
  ): Promise<readonly VerificationResult[]>;
  inspect(result: VerificationResult): VerificationInspection;
  verifyReceipt(input: ReceiptVerificationInput): ReceiptVerification;
}

export function createVerifier(): Promise<Verifier>;
```

`authorized` deliberately contains no `VerifiedAction`, command, callback, provider request, or capability. Input byte limits and the 256-item/16 MiB aggregate batch limit remain Rust/package contract facts; callers may lower a deadline/chunk size but cannot raise security bounds. Invalid proof and receipt data return negative results. ABI corruption or unavailable packaged runtime throws `AuthsError`.

Receipt verification is explicitly local and trust-pinned. The verifier never treats a receipt-carried key or signature possession as trusted issuance. A `decision` receipt requires its pinned decision signer and exact proof/action/context/status commitments and forbids a linked input. An `execution` receipt requires `linkedDecisionReceipt`/`linked_decision_receipt`, pinned execution signer, execution lease/command/result commitments, and the complete two-signature chain; an ID alone is insufficient. This distinction represents pre-provider negatives and GitHub's partial PR decision/provider-rejection evidence without fabricating an execution or provider object. Malformed, bad-signature, untrusted, disallowed-profile, expired, missing/wrong link, or broken-chain receipts are `rejected`; an unavailable suite or unresolved required status is `indeterminate`. The shared details expose only the applicable cryptographic envelope and profile-payload commitment. The sealed result retains the copied canonical payload privately so only the owning profile inspector can decode it.

`ReceiptProfile` mirrors the signed wire `ProfileRef` exactly: `id` is the bounded token such as `auths.mcp` and `version` is a positive bounded integer. It is not the slash-joined SDK semantic-subject string. Trust comparison requires exact equality of both fields; no string splitting, prefix match, latest-version fallback, or version coercion is permitted.

`pinnedReceiptTrust`/`pinned_receipt_trust` requires 1–32 copied anchors, including at least one decision anchor, and 1–16 unique profiles. An execution anchor is optional at policy construction but an execution receipt without a matching one is `rejected` as untrusted. Profile IDs and suites are 1–128-byte registered tokens; principals and verification methods retain the receipt/model v1 grammar and 1–512-byte maximum; versions are `1..=2^31-1`. Ed25519 keys are exactly 32 bytes; `p256-sha256-v1` keys are exactly 33-byte compressed SEC1 points and are validated on construction. Duplicate/conflicting anchors, a missing decision role, negative/fractional time, and maximum ages outside 1–31,536,000 seconds fail before verification. Omitted `maximumReceiptAgeSeconds` uses 86,400 seconds. Omitted verification time samples the trusted clock separately for each `verifyReceipt`; an explicit time is a fixed deterministic test override copied into the policy. A receipt timestamp more than 300 seconds in the future is rejected, and an unavailable trusted clock is `indeterminate`. The TypeScript factory is asynchronous because Rust/WASM owns P-256 and duplicate validation; Python performs the same Rust validation synchronously through its already-loaded native extension. Trust policy values and their debug representations never print key bytes.

### 5.3 `@auths-dev/sdk/identity`

```ts
import type { AuthsIssue } from "@auths-dev/sdk";

declare const decodedIdentityBrand: unique symbol;
declare const resolvedIdentityBrand: unique symbol;
declare const validatedIdentityBrand: unique symbol;
declare const authenticatedIdentityBrand: unique symbol;

export interface DecodedIdentity {
  readonly [decodedIdentityBrand]: true;
  readonly validation: "decoded";
  readonly methodId: string;
  readonly identityId: string;
  /** Immutable bounded method material parsed by Rust from the packet. */
  readonly methodMaterial: Uint8Array;
  readonly relationships: readonly string[];
  toBytes(): Uint8Array;
}

export interface ResolvedIdentity {
  readonly [resolvedIdentityBrand]: true;
  readonly validation: "resolved";
  readonly methodId: string;
  readonly identityId: string;
  readonly evidence: Readonly<{
    source: string;
    observedAtUnixSeconds: bigint;
    expiresAtUnixSeconds: bigint;
    provenance: readonly string[];
  }>;
}

export interface ValidatedIdentity {
  readonly [validatedIdentityBrand]: true;
  readonly validation: "validated";
  readonly methodId: string;
  readonly identityId: string;
  readonly relationships: readonly string[];
  toBytes(): Uint8Array;
}

export interface AuthenticatedIdentityMessage {
  readonly [authenticatedIdentityBrand]: true;
  readonly identity: ValidatedIdentity;
  readonly relationshipId: string;
  readonly message: Uint8Array;
}

export interface IdentityOperationOptions {
  readonly timeoutMs?: number; // 1..300_000; default 10_000
  readonly signal?: AbortSignal;
}

export type IdentityResult<Value> =
  | Readonly<{ kind: "ok"; value: Value }>
  | Readonly<{
      kind: "rejected";
      issue: AuthsIssue & Readonly<{ effect: "not-applied" }>;
    }>
  | Readonly<{
      kind: "indeterminate";
      issue: AuthsIssue & Readonly<{ effect: "not-applied" }>;
    }>;

export interface IdentityClient extends AsyncDisposable {
  decode(packet: Uint8Array): IdentityResult<DecodedIdentity>;
  resolve(
    identity: DecodedIdentity,
    options?: IdentityOperationOptions,
  ): Promise<IdentityResult<ResolvedIdentity>>;
  validate(
    identity: ResolvedIdentity,
    options?: IdentityOperationOptions,
  ): Promise<IdentityResult<ValidatedIdentity>>;
  authenticate(input: Readonly<{
    identity: ValidatedIdentity;
    relationshipId?: string; // default-signing
    message: Uint8Array;
    signature: Uint8Array;
    timeoutMs?: number;
    signal?: AbortSignal;
  }>): Promise<IdentityResult<AuthenticatedIdentityMessage>>;
  authenticateMessage(input: Readonly<{
    identityPacket: Uint8Array;
    relationshipId?: string;
    message: Uint8Array;
    signature: Uint8Array;
    timeoutMs?: number;
    signal?: AbortSignal;
  }>): Promise<IdentityResult<AuthenticatedIdentityMessage>>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

export function createRawKeyEd25519IdentityClient(): Promise<IdentityClient>;
```

`authenticateMessage` is the production-shaped shortcut; it performs the same decode, resolve, validate, and authenticate stages. Malformed/untrusted input, missing or forbidden relationships, expiry, and invalid signatures return `rejected`; unavailable or inconclusive trust material returns `indeterminate`. Neither is thrown as an operational exception. The staged methods expose the same exhaustive result for applications that must inspect resolver evidence between steps. An `ok` value is sealed identity evidence and is never accepted as profile authority without a separate Rust-owned authority flow.

### 5.4 `@auths-dev/sdk/identity/adapters`

```ts
import type { IdentityClient } from "@auths-dev/sdk/identity";

export interface VerificationMaterial {
  readonly id: string;
  readonly bytes: Uint8Array;
}

export interface VerificationRelationship {
  readonly id: string;
  readonly purpose: string;
  readonly suiteId: string;
  readonly verificationMaterial: readonly VerificationMaterial[];
}

export interface DecodedIdentityRecord {
  readonly methodId: string;
  readonly identityId: string;
  readonly methodMaterial: Uint8Array;
  readonly relationships: readonly VerificationRelationship[];
}

export interface ResolutionEvidence {
  readonly source: string;
  readonly observedAtUnixSeconds: bigint;
  readonly expiresAtUnixSeconds: bigint;
  readonly provenance: readonly string[];
  readonly history: readonly string[];
}

export interface ResolvedIdentityRecord {
  readonly methodId: string;
  readonly identityId: string;
  readonly methodMaterial: Uint8Array;
  readonly relationships: readonly VerificationRelationship[];
  readonly evidence: ResolutionEvidence;
}

export interface IdentityResolver {
  resolve(input: Readonly<{
    descriptor: DecodedIdentityRecord;
    maximumBytes: number;
    signal: AbortSignal;
  }>): Promise<IdentityAdapterResult<ResolvedIdentityRecord>>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

export type IdentityAdapterRejection =
  | "not-found"
  | "malformed"
  | "not-permitted"
  | "expired"
  | "invalid-signature";
export type IdentityAdapterUncertainty =
  | "cancelled"
  | "timeout"
  | "unavailable"
  | "invalid-response";
export type IdentityAdapterResult<Value> =
  | Readonly<{ kind: "ok"; value: Value }>
  | Readonly<{ kind: "rejected"; reason: IdentityAdapterRejection }>
  | Readonly<{
      kind: "indeterminate";
      reason: IdentityAdapterUncertainty;
    }>;

export interface IdentityMethod {
  readonly id: string;
  readonly version: number;
  resolve(
    descriptor: DecodedIdentityRecord,
    context: Readonly<{ signal: AbortSignal }>,
  ): Promise<IdentityAdapterResult<ResolvedIdentityRecord>>;
  validate(
    record: ResolvedIdentityRecord,
    context: Readonly<{ signal: AbortSignal }>,
  ): Promise<IdentityAdapterResult<undefined>>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

export interface MessageAuthenticator {
  /** Exact Rust/wire VerificationRelationship.suite_id registry key. */
  readonly suiteId: string;
  readonly version: number;
  verify(input: Readonly<{
    relationship: VerificationRelationship;
    preimage: Uint8Array;
    signature: Uint8Array;
    signal: AbortSignal;
  }>): Promise<IdentityAdapterResult<undefined>>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

export function createIdentityClient(options: Readonly<{
  methods: readonly IdentityMethod[];
  authenticators: readonly MessageAuthenticator[];
  adapterOwnership?: "borrowed" | "owned";
}>): Promise<IdentityClient>;

export function resolverIdentityMethod(options: Readonly<{
  id: string;
  version: number;
  resolver: IdentityResolver;
  resolverOwnership?: "borrowed" | "owned";
  maximumBytes?: number;
}>): IdentityMethod;
```

These callbacks are allowed because they implement the identity resolution/authentication trust boundary; they do not evaluate authority or construct an executable command. Rust creates `DecodedIdentityRecord` from the already-bounded canonical packet and passes defensive copies to the selected resolver/method; an application cannot substitute that record for the sealed `DecodedIdentity` accepted by `IdentityClient`. Resolver output must byte-match the decoded method/identity IDs, and native code rechecks method material, complete relationships/materials, duplicates, bounds, and canonicalizability before sealing. After `resolve`, the client privately retains the complete validated `ResolvedIdentityRecord`; `validate` receives that record so a method never reparses `toBytes()` or uses hidden side state. Authentication selects the retained relationship, computes the preimage in Rust, and gives the complete relationship—not caller-supplied material—to `MessageAuthenticator.verify`. Applications receive only the staged identity projection. `MessageAuthenticator.suiteId` is exactly the serialized Rust `VerificationRelationship.suite_id`, and lookup is byte-for-byte equality; there is no alias registry.

Adapter authors return the closed `ok | rejected | indeterminate` channel: normal hostile-input failures are rejections, availability/cancellation/invalid adapter responses are indeterminate, and an arbitrary thrown exception is mapped to `indeterminate/unavailable` rather than authorization denial. A resolver/resolve method may reject any declared rejection; validation may reject `malformed | not-permitted | expired | invalid-signature`; a message authenticator may reject only `malformed | not-permitted | invalid-signature`. A stage-inapplicable rejection such as authenticator `not-found`/`expired` is an invalid adapter response and maps to `identity.authentication-indeterminate` with cause `invalid-response`. Adapter outputs are revalidated against canonical identity fields, bounded, and covered by cross-language fixtures.

Adapters are borrowed by default. `adapterOwnership: "owned"` transfers all supplied methods/authenticators to the client; `resolverOwnership: "owned"` transfers the resolver to its wrapping method. Ownership transfer is single-consumer, close is idempotent, and owned resources close in reverse registration order after in-flight calls settle. The built-in raw-key client owns its internal resources.

### 5.5 `@auths-dev/sdk/identity/authoring`

```ts
import type { ValidatedIdentity } from "@auths-dev/sdk/identity";
import type { VerificationRelationship }
  from "@auths-dev/sdk/identity/adapters";

declare const preparedIdentityMessageBrand: unique symbol;
export interface PreparedIdentityMessage {
  readonly [preparedIdentityMessageBrand]: true;
  readonly identity: ValidatedIdentity;
  readonly relationshipId: string;
  readonly message: Uint8Array;
  readonly signingPreimage: Uint8Array;
}

export function createRawKeyEd25519Identity(
  publicKey: Uint8Array,
): Promise<ValidatedIdentity>;

export function encodeIdentity(input: Readonly<{
  methodId: string;
  identityId: string;
  methodMaterial?: Uint8Array;
  relationships: readonly VerificationRelationship[];
}>): Promise<Uint8Array>;

export function prepareIdentityMessage(input: Readonly<{
  identity: ValidatedIdentity;
  relationshipId?: string;
  message: Uint8Array;
}>): Promise<PreparedIdentityMessage>;
```

`PreparedIdentityMessage` binds the exact identity, relationship, message, and signing preimage. The caller gives `identity.toBytes()`, `message`, and the resulting detached signature to `IdentityClient.authenticate`/`authenticateMessage`; there is no second signed-packet format with no consumer. This module authors identity packets and authentication preimages only; it does not author grants or proof authority.

### 5.6 `@auths-dev/sdk/mcp`

```ts
import type { AuthsIssue, Receipt } from "@auths-dev/sdk";
import type {
  CustodyKind,
  CustodyLifecycle,
  CustodySigner,
  ReservationStore,
} from "@auths-dev/sdk/adapters";
import type { VerifiedReceipt } from "@auths-dev/sdk/verify";

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | Readonly<{ [key: string]: JsonValue }>;
export type JsonObject = Readonly<{ [key: string]: JsonValue }>;

export type JsonCompatible<T> =
  T extends null | boolean | number | string ? T
  : T extends readonly (infer Item)[] ? readonly JsonCompatible<Item>[]
  : T extends object ? Readonly<{
      [Key in keyof T]-?: JsonCompatible<T[Key]>;
    }>
  : never;

declare const mcpModelBrand: unique symbol;
export interface McpModel<Value> {
  readonly [mcpModelBrand]: (value: Value) => Value;
}
declare const mcpObjectModelBrand: unique symbol;
interface McpObjectModel<Value extends object> extends McpModel<Value> {
  readonly [mcpObjectModelBrand]: true;
}
declare const mcpLiteralModelBrand: unique symbol;
export interface McpLiteralModel<
  Value extends null | boolean | number | string,
> extends McpModel<Value> {
  readonly [mcpLiteralModelBrand]: true;
}
type McpModelValue<Model> = Model extends McpModel<infer Value> ? Value : never;
type FiniteMcpObjectFields<Value extends object> =
  string extends keyof Value ? never
  : number extends keyof Value ? never
  : symbol extends keyof Value ? never
  : Readonly<{ [Key in keyof Value]-?: McpModel<Value[Key]> }>;

declare const mcpToolBrand: unique symbol;
export interface McpTool<
  Input extends object,
  Output extends object,
> {
  readonly [mcpToolBrand]: true;
  readonly input: McpObjectModel<Input>;
  readonly output: McpObjectModel<Output>;
}

export type McpToolset = Readonly<
  // `any` exists only at this heterogeneous type boundary. Runtime models
  // remain mandatory and are validated by Rust.
  Record<string, McpTool<any, any>>
>;

type ToolName<Tools extends McpToolset> = Extract<keyof Tools, string>;
type ToolInput<Tool> = Tool extends McpTool<infer Input, any>
  ? Input
  : never;
type ToolOutput<Tool> = Tool extends McpTool<any, infer Output>
  ? Output
  : never;

declare const mcpActionBrand: unique symbol;
export interface McpAction<
  Tools extends McpToolset,
  Name extends ToolName<Tools>,
> {
  readonly [mcpActionBrand]: (
    tools: Tools,
    name: Name,
  ) => readonly [Tools, Name];
  readonly profile: "auths.mcp/2";
  readonly service: string;
  readonly tool: Name;
  readonly input: JsonCompatible<ToolInput<Tools[Name]>>;
}

declare const mcpAuthorityBrand: unique symbol;
export interface McpAuthority<
  Tools extends McpToolset,
  Allowed extends ToolName<Tools>,
> {
  readonly [mcpAuthorityBrand]: (
    tools: Tools,
    allowed: Allowed,
  ) => readonly [Tools, Allowed];
  readonly profile: "auths.mcp/2";
  readonly service: string;
  readonly allowedTools: readonly Allowed[];
}

export type McpProviderUncertainty =
  | "cancelled"
  | "invalid-output"
  | "limit-exceeded"
  | "timeout"
  | "unavailable"
  | "unknown";

declare const mcpProviderOutcomeBrand: unique symbol;
export type McpProviderOutcome<Output> =
  | Readonly<{
      [mcpProviderOutcomeBrand]: true;
      effect: "applied";
      value: Output;
    }>
  | Readonly<{
      [mcpProviderOutcomeBrand]: true;
      effect: "possible";
      cause: McpProviderUncertainty;
    }>;

declare const mcpReconciliationOutcomeBrand: unique symbol;
export type McpReconciliationOutcome<Output> =
  | Readonly<{
      [mcpReconciliationOutcomeBrand]: true;
      observation: "applied";
      value: Output;
    }>
  | Readonly<{
      [mcpReconciliationOutcomeBrand]: true;
      observation: "inconclusive";
      cause: McpProviderUncertainty;
    }>;

export interface McpInvocationContext<Name extends string = string> {
  readonly executionId: string;
  /** Derived by Rust from caller key + exact commitments; never caller-chosen. */
  readonly providerIdempotencyKey: string;
  readonly service: string;
  readonly tool: Name;
  readonly signal: AbortSignal;
}

export interface McpInvocation<
  Input = JsonObject,
  Name extends string = string,
> {
  readonly input: Input;
  readonly context: McpInvocationContext<Name>;
}

export type McpHandlers<
  Tools extends McpToolset,
  Allowed extends ToolName<Tools>,
> = {
  readonly [Name in Allowed]: (
    invocation: McpInvocation<JsonCompatible<ToolInput<Tools[Name]>>, Name>,
  ) => Promise<McpProviderOutcome<JsonCompatible<ToolOutput<Tools[Name]>>>>;
};

export interface McpProviderAttempt {
  readonly sessionContract: "auths.mcp-session/2";
  readonly executionId: string;
  readonly attemptOrdinal: number;
  readonly requestCommitment: Uint8Array;
  readonly providerIdempotencyKey: string;
  readonly enteredAtUnixSeconds: bigint;
}

export interface McpObservation<Evidence extends JsonValue = JsonValue> {
  readonly observerId: string;
  readonly sourceId: string;
  readonly executionId: string;
  readonly requestCommitment: Uint8Array;
  readonly observedAtUnixSeconds: bigint;
  readonly freshUntilUnixSeconds: bigint;
  readonly evidence: Evidence;
}

export type McpReconcilers<
  Tools extends McpToolset,
  Allowed extends ToolName<Tools>,
> = {
  readonly [Name in Allowed]: (
    invocation: McpInvocation<
      JsonCompatible<ToolInput<Tools[Name]>>,
      Name
    > & Readonly<{ attempt: McpProviderAttempt }>,
  ) => Promise<
    McpReconciliationOutcome<JsonCompatible<ToolOutput<Tools[Name]>>>
  >;
};

export type McpExecutionStage =
  | "verification-started"
  | "verification-completed"
  | "decision-persisted"
  | "reserved"
  | "exact-action-claimed"
  | "credential-issued"
  | "provider-entry-recorded"
  | "provider-call-started"
  | "provider-call-returned"
  | "outcome-unknown-persisted"
  | "reconciliation-observed"
  | "reconciliation-persisted"
  | "receipt-persisted"
  | "reconciling"
  | "terminal-persisted";

type McpExecutionOutcomeKind =
  | "completed"
  | "denied"
  | "indeterminate"
  | "conflict"
  | "recovery-required"
  | "failed";

export interface McpExecutionEvent {
  readonly stage: McpExecutionStage;
  readonly correlationId: string;
  readonly executionId?: string;
  readonly timestampUnixMs: number;
  readonly outcomeKind?: McpExecutionOutcomeKind;
  readonly droppedBefore?: number;
}

export class McpRecoveryReference<Output = JsonValue> {
  private constructor();
  private readonly __mcpRecoveryReferenceBrand: Output;
  static fromBytes(bytes: Uint8Array): McpRecoveryReference<JsonValue>;
  toBytes(): Uint8Array;
  toJSON(): never;
}

export class McpPlanRecoveryReference {
  private constructor();
  private readonly __mcpPlanRecoveryReferenceBrand: void;
  static fromBytes(bytes: Uint8Array): McpPlanRecoveryReference;
  toBytes(): Uint8Array;
  toJSON(): never;
}

export interface McpCompleted<Output> {
  readonly kind: "completed";
  readonly completion: "executed" | "replayed" | "reconciled";
  readonly executionId: string;
  readonly value: Output;
  readonly decisionReceipt: Receipt;
  readonly executionReceipt: Receipt;
}

export interface McpDenied {
  readonly kind: "denied";
  readonly issue: AuthsIssue & Readonly<{
    effect: "not-applied";
    retry: "never";
  }>;
}

export interface McpIndeterminate {
  readonly kind: "indeterminate";
  readonly issue: AuthsIssue & Readonly<{ effect: "not-applied" }>;
}

export interface McpConflict {
  readonly kind: "conflict";
  readonly executionId: string;
  readonly issue: AuthsIssue & Readonly<{ effect: "not-applied" }>;
}

export interface McpRecoveryRequired<Output = JsonValue> {
  readonly kind: "recovery-required";
  readonly executionId: string;
  readonly issue: AuthsIssue & Readonly<{
    effect: "possible";
    retry: "unknown";
    recommendedAction: "resume-and-reconcile";
    executionReference: string;
  }>;
  readonly recovery: McpRecoveryReference<Output>;
}

export interface McpPlanRecoveryRequired {
  readonly kind: "recovery-required";
  readonly executionId: string;
  readonly issue: AuthsIssue & Readonly<{
    effect: "possible";
    retry: "unknown";
    recommendedAction: "resume-and-reconcile";
    executionReference: string;
  }>;
  readonly recovery: McpPlanRecoveryReference;
}

export interface McpFailed {
  readonly kind: "failed";
  readonly executionId: string;
  readonly issue: AuthsIssue & Readonly<{ effect: "applied" }>;
  readonly decisionReceipt: Receipt;
  readonly executionReceipt: Receipt;
}

export type McpOutcome<Output> =
  | McpCompleted<Output>
  | McpDenied
  | McpIndeterminate
  | McpConflict
  | McpRecoveryRequired<Output>
  | McpFailed;

type AnyMcpAction<Tools extends McpToolset> = {
  [Name in ToolName<Tools>]: McpAction<Tools, Name>;
}[ToolName<Tools>];

type AllowedMcpAction<
  Tools extends McpToolset,
  Allowed extends ToolName<Tools>,
> = {
  [Name in Allowed]: McpAction<Tools, Name>;
}[Allowed];

declare const mcpPlanBrand: unique symbol;
export interface McpPlan<
  Tools extends McpToolset,
  Actions extends readonly AnyMcpAction<Tools>[],
> {
  readonly [mcpPlanBrand]: (
    tools: Tools,
    actions: Actions,
  ) => readonly [Tools, Actions];
  readonly profile: "auths.mcp/2";
  readonly service: string;
  readonly length: Actions["length"];
}

export type McpPlanStop =
  | McpDenied
  | McpIndeterminate
  | McpConflict
  | McpPlanRecoveryRequired
  | McpFailed;

export type McpPlanOutcome =
  | Readonly<{
      kind: "completed";
      members: readonly McpCompleted<JsonValue>[];
    }>
  | Readonly<{
      kind: "stopped";
      completedMembers: readonly McpCompleted<JsonValue>[];
      stoppedAt: number;
      outcome: McpPlanStop;
    }>;

export interface McpExecutionOptions {
  readonly idempotencyKey: string;
  readonly signal?: AbortSignal;
}

export interface McpSessionDiagnostics {
  readonly mode: "development";
  readonly stateDurability: "single-machine-development";
  readonly service: string;
  readonly profile: "auths.mcp/2";
  readonly sessionContract: "auths.mcp-session/2";
  readonly authorityTools: readonly string[];
  readonly providerRuntimeOwned: true;
  readonly handlersOwned: false;
  readonly reconcilersOwned: false;
  readonly custody: Readonly<{
    kind: CustodyKind;
    lifecycle: CustodyLifecycle;
    ownership: "borrowed" | "owned";
  }>;
  readonly reservation: Readonly<{
    kind: string;
    durability: "ephemeral" | "single-machine-durable";
    ownership: "borrowed" | "owned";
  }>;
  /** Borrowed application callbacks still running after their five-second drain. */
  readonly outstandingBorrowedCallbacks: number;
  readonly warnings: readonly string[];
}

export type McpDelegationResult<
  Tools extends McpToolset,
  Allowed extends ToolName<Tools>,
> =
  | Readonly<{
      kind: "delegated";
      session: McpSession<Tools, Allowed>;
    }>
  | Readonly<{
      kind: "denied" | "indeterminate" | "conflict";
      issue: AuthsIssue & Readonly<{ effect: "not-applied" }>;
    }>;

declare const mcpSessionBrand: unique symbol;
export interface McpSession<
  Tools extends McpToolset,
  Allowed extends ToolName<Tools>,
> extends AsyncDisposable {
  readonly [mcpSessionBrand]: (
    tools: Tools,
    allowed: Allowed,
  ) => readonly [Tools, Allowed];
  readonly profile: "auths.mcp/2";
  readonly sessionContract: "auths.mcp-session/2";
  readonly service: string;
  readonly principal: string;
  readonly authority: McpAuthority<Tools, Allowed>;

  execute<Name extends Allowed>(
    action: McpAction<Tools, Name>,
    options: McpExecutionOptions,
  ): Promise<McpOutcome<JsonCompatible<ToolOutput<Tools[Name]>>>>;

  executePlan<Actions extends readonly AnyMcpAction<Tools>[]>(
    plan: Actions[number] extends AllowedMcpAction<Tools, Allowed>
      ? McpPlan<Tools, Actions>
      : never,
    options: McpExecutionOptions,
  ): Promise<McpPlanOutcome>;

  recover<Output>(
    recovery: McpRecoveryReference<Output>,
    options?: Readonly<{ signal?: AbortSignal }>,
  ): Promise<McpOutcome<Output>>;

  recoverPlan(
    recovery: McpPlanRecoveryReference,
    options?: Readonly<{ signal?: AbortSignal }>,
  ): Promise<McpPlanOutcome>;

  recoverActionByIdempotencyKey(
    idempotencyKey: string,
    options?: Readonly<{ signal?: AbortSignal }>,
  ): Promise<McpOutcome<JsonValue>>;

  recoverPlanByIdempotencyKey(
    idempotencyKey: string,
    options?: Readonly<{ signal?: AbortSignal }>,
  ): Promise<McpPlanOutcome | McpIndeterminate>;

  events(options?: Readonly<{
    signal?: AbortSignal;
  }>): AsyncIterable<McpExecutionEvent>;

  delegate<Narrower extends Allowed>(options: Readonly<{
    allow: readonly Narrower[];
    idempotencyKey: string;
    /** Registered token; default `delegated-agent`. */
    name?: string;
    /** Default 300_000; 1_000..min(parent remainder, 300_000). */
    expiresInMs?: number;
    signal?: AbortSignal;
  }>): Promise<McpDelegationResult<Tools, Narrower>>;

  diagnostics(): McpSessionDiagnostics;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

export interface McpDevelopmentOptions<
  Tools extends McpToolset,
  Allowed extends ToolName<Tools>,
> {
  readonly allow: readonly Allowed[];
  readonly handlers: McpHandlers<Tools, Allowed>;
  /** 1..300_000; default 30_000. */
  readonly timeoutMs?: number;
  readonly reconcile: McpReconcilers<Tools, Allowed>;
  readonly custody?: Readonly<{
    signer: CustodySigner;
    /** Default `borrowed`. */
    ownership?: "borrowed" | "owned";
  }>;
  readonly reservation?: Readonly<{
    store: ReservationStore;
    /** Default `borrowed`. */
    ownership?: "borrowed" | "owned";
  }>;
}

declare const mcpProfileBrand: unique symbol;
export interface McpProfile<Tools extends McpToolset> {
  readonly [mcpProfileBrand]: (tools: Tools) => Tools;
  readonly id: "auths.mcp/2";
  readonly service: string;

  call<Name extends ToolName<Tools>>(
    tool: Name,
    input: JsonCompatible<ToolInput<Tools[Name]>>,
  ): McpAction<Tools, Name>;

  plan<Actions extends readonly AnyMcpAction<Tools>[]>(
    ...actions: Actions
  ): McpPlan<Tools, Actions>;

}

export interface McpReceiptDetails {
  readonly profile: "auths.mcp/2";
  readonly service: string;
  readonly tool: string;
  readonly actionCommitment: string;
  readonly resultCommitment?: string;
  readonly providerEntered: boolean;
  readonly completion: "executed" | "replayed" | "reconciled";
}

export type McpReceiptInspection =
  | Readonly<{ kind: "inspected"; details: McpReceiptDetails }>
  | Readonly<{
      kind: "rejected";
      issue: AuthsIssue & Readonly<{ effect: "not-applied" }>;
    }>;

export function inspectMcpReceipt(
  receipt: VerifiedReceipt,
): McpReceiptInspection;

export const mcp: Readonly<{
  profile<Tools extends McpToolset>(options: Readonly<{
    service: string;
    tools: Tools;
  }>): McpProfile<Tools>;
  tool<Input extends object, Output extends object>(definition: Readonly<{
    input: McpObjectModel<Input>;
    output: McpObjectModel<Output>;
  }>): McpTool<Input, Output>;
  model: Readonly<{
    string(): McpModel<string>;
    boolean(): McpModel<boolean>;
    integer(): McpModel<number>;
    number(): McpModel<number>;
    literal<const Value extends null | boolean | number | string>(
      value: Value,
    ): McpLiteralModel<Value>;
    oneOf<Models extends readonly [
      McpLiteralModel<any>,
      ...McpLiteralModel<any>[],
    ]>(
      ...models: Models
    ): McpModel<McpModelValue<Models[number]>>;
    nullable<Value>(model: McpModel<Value>): McpModel<Value | null>;
    array<Value>(model: McpModel<Value>): McpModel<readonly Value[]>;
    object<Value extends object>(
      fields: FiniteMcpObjectFields<Value>,
    ): McpObjectModel<Readonly<Value>>;
  }>;
  applied<Output>(
    value: Output,
  ): McpProviderOutcome<JsonCompatible<Output>>;
  possible(
    cause: McpProviderUncertainty,
  ): McpProviderOutcome<never>;
  observedApplied<Output>(
    value: Output,
    observation: McpObservation,
  ): McpReconciliationOutcome<JsonCompatible<Output>>;
  inconclusive(
    cause: McpProviderUncertainty,
    observation?: McpObservation,
  ): McpReconciliationOutcome<never>;
}>;
```

Each tool has mandatory object-root input and output models, matching Python's frozen-dataclass roots; TypeScript generics alone are never trusted. Nested model construction uses the same closed grammar as Python: string, boolean, finite number, safe integer, exact scalar literal/literal-only union, nullable value, bounded homogeneous array, and closed object. Exact literals are limited to null, boolean, string, or safe integer; TypeScript's `number` signature is runtime-rejected when fractional/non-finite/out of safe range because the language has no integer kind, while Python `Literal` cannot contain float. There are deliberately no TypeScript-only field constraint options; v2's fixed Rust byte/depth/item/work limits apply identically in both languages. Objects reject undeclared properties and inherited/accessor properties. Every object field is present in canonical JSON; `undefined` and omitted fields are rejected. Integers must be JavaScript safe integers and ordinary numbers must be finite. Models are immutable, branded, reusable descriptors; no parse/transform/refinement callback runs across the trust boundary. Descriptor construction performs local shape checks only; the descriptors and every value are authoritatively revalidated by Rust when the asynchronous session opens and before commitment/handler return, so synchronous helpers never recreate semantics in JavaScript. Both action input and handler output are copied, validated, and canonically projected by Rust before persistence, replay, or receipts.

All JSON objects must be acyclic plain data. The SDK does not accept arbitrary class instances, symbols, `bigint`, functions, getters, or custom serialization hooks.

The new `auths.mcp-session/2` manifest fixes these limits; neither binding may choose different defaults or units:

| Limit | Exact v2 value |
|---|---:|
| tools per profile | 1–128 |
| model fields per object | 128 |
| exact-literal union alternatives | 1–64, no duplicate canonical literal |
| model field name | 1–64 ASCII bytes, `[A-Za-z][A-Za-z0-9_]{0,63}`, excluding Python keywords |
| tool/service/delegation/observer/source token | 1–128 ASCII bytes, registered-token grammar in section 4.3 |
| model/canonical nesting depth | 32 |
| homogeneous array items | 4,096 |
| canonical input | 256 KiB and 32,768 visited nodes |
| canonical output | 1 MiB and 131,072 visited nodes |
| ordered plan members | 1–128 |
| aggregate canonical plan inputs | 8 MiB and 262,144 visited nodes |
| aggregate canonical plan outputs | 8 MiB and 262,144 visited nodes |
| plan receipts / aggregate receipt bytes | 128 / 8 MiB |
| returned plan result (outputs + receipt envelopes) | 16 MiB |
| reconciliation evidence | 64 KiB, depth 32, 8,192 visited nodes |
| safe error text | 256 UTF-8 bytes |
| execution timeout | default 30,000 ms; range 1–300,000 ms |
| delegated expiry | default 300,000 ms; range 1,000–min(parent remainder, 300,000) ms |
| idempotency key | 1–128 ASCII bytes, grammar in section 4.3 |
| imported recovery handle | 1–16 KiB |
| portable receipt | 1 MiB |
| event subscription queue | 64 events |
| event subscriptions per session | 4 |

String limits are measured in canonical UTF-8 bytes, never JavaScript UTF-16 code units or Python code points. Collection, byte, node, and work limits are cumulative and checked before allocation proportional to attacker claims. Outputs/receipts larger than a 256 KiB lifecycle record are stored in the same bounded, checksummed, content-addressed state blob store; the durable record commits their digest and atomic presence before it advances. Replay resolves and validates those blobs without provider re-entry. `profile`, `tool`, `call`, and `plan` reject zero/boundary+1 values synchronously when possible; Rust repeats every check at session open and the trusted boundary.

The handler boundary is deliberately one-way: once entered, every exception, timeout, cancellation, invalid response, or `mcp.possible(...)` is effect-possible and produces recovery. A normal handler cannot assert `not-applied`. The development reconciler performs a fresh observation without invoking the provider and may report only `observedApplied(...)` or `inconclusive(...)`; it cannot release a reservation or authorize retry by claiming absence. A future production profile may expose a Rust-owned finality observer with profile-specific evidence and a distinct outcome. Runtime branding prevents a handler outcome from being used as a reconciliation outcome or vice versa.

`McpObservation` is mandatory for every conclusive reconciliation. Stable observer/source identity, execution/request bindings, Unix-second observation/freshness bounds, and bounded canonical evidence are committed into lifecycle state and the reconciliation receipt. The session fixes `auths.mcp-session/2`; callers do not reassert a profile or semantic subject. Rust requires supplied execution/request values to equal the sealed attempt, derives the reconciliation identity and evidence digest, takes the conclusion only from the branded reconciliation helper, and persists the result as the existing immutable `auths.product.reconciliation-observation/1` lifecycle envelope. In recoverable development, `observerId` and `sourceId` use the 1–128-byte registered-token grammar, evidence uses the same closed model grammar with a 64 KiB canonical limit, `observedAtUnixSeconds` must be no earlier than 60 seconds before callback invocation and no later than 5 seconds after completion, and `freshUntilUnixSeconds` must cover callback completion without exceeding observation time by 300 seconds. A mismatch is `inconclusive`, never not-applied. These checks detect stale/unrelated/substituted fixtures but do not turn an application assertion into production authority. Reconciliation callbacks exist only on the explicitly development-labeled local profile. A production profile owns an authenticated domain observer, canonical evidence schema, and its stricter freshness window in Rust.

An action recovery reference resolves one action. A plan recovery reference binds the full plan, completed prefix, uncertain member, and next index. `recoverPlan` first reconciles the uncertain member without provider re-entry; if application is observed it commits and continues remaining members in order, and if observation is inconclusive it returns the same logical recovery reference. Generic development recovery never releases the reservation or retries the member on an absence claim. `recover*ByIdempotencyKey` is the crash/cancellation fallback when a response containing the opaque handle was lost. Lookup is scoped to the session authority/profile/service/principal. A never-recorded or wrong-scope key is indistinguishable and returns `McpIndeterminate` with registered `mcp.recovery-not-found`, `effect=not-applied`, without an execution ID; write-ahead ordering proves the local provider was not entered under that key. Looking up a plan key through the action method or vice versa returns `mcp.recovery-kind-mismatch`. Corrupt state prevents session open, not a fabricated lookup result. Key commitments and possible-effect records never expire or disappear automatically; compact terminal values remain non-reusable tombstones under the fixed quota. Re-executing the same key and changed canonical commitments returns `conflict` before entry.

Delegation is a local Auths authority-state transition and never enters an application provider. Its idempotency key is mandatory: after a child is durably minted, the same key plus byte-identical allowed tools, name, and expiry returns that child; changing any committed input under that key returns `conflict`. Names use the 1–128-byte registered-token grammar and default to `delegated-agent`; expiry defaults to 300 seconds and must be 1 second through the lesser of 300 seconds or parent remainder. A non-subset or expired parent returns `denied`. Every negative branch is an ordinary `McpDelegationResult` with `effect:"not-applied"` for the child grant; no child authority has been accepted.

Custody mapping is closed and identical in both SDKs: `CustodyRejected(DENIED|REVOKED_KEY|DISABLED_KEY)` becomes delegation `denied` with the same registered `custody.*` code, `retry=never`, and configuration/condition guidance; proven-no-signature `CustodyRejected(CANCELLED)` becomes `indeterminate` with the existing `custody.cancelled`, `retry=never`, `recommendedAction=satisfy-condition` registry facts; `CustodyIndeterminate(THROTTLED|UNAVAILABLE|PROVIDER_UNKNOWN|INVALID_PROVIDER_RESPONSE)` becomes `indeterminate` with the matching code and registry-defined retry/action. There are no invented timeout or unsupported-suite variants. `PROVIDER_UNKNOWN` may mean the custody transaction signed, so replay under the same delegation key queries the same custody transaction and never starts a second signing attempt. There are no hidden signer retries. A caller may explicitly repeat the identical key/request only when the returned guidance permits it; concurrency admits one custody transaction at a time, and a child once minted always wins exact replay. Before custody/state entry, abort is ordinary pre-effect cancellation. After either boundary is entered, the method defers cancellation until it records/returns a child-not-applied negative or the durable child; after child persistence, the delegated result wins over late cancellation. Python applies the same rule to task cancellation.

`events()` is diagnostic only. A session allows at most four subscriptions; the fifth call is synchronous local resource misuse and throws host `RangeError`/`ValueError` before I/O, exactly as section 4.3 specifies. Each subscription has a fixed capacity of 64 events and is populated only after the corresponding durable transition. Enqueue never awaits application code. When full, the oldest event—including a terminal/recovery event—is evicted and the next delivered event carries the accumulated `droppedBefore`/`dropped_before` count. Four abandoned iterators therefore consume at most 256 bounded events regardless of execution count. Iterator cancellation closes only that subscription; session close closes every subscription after queued delivery has been offered once. `outcomeKind`/`outcome_kind` is present exactly on `outcome-unknown-persisted` and `terminal-persisted`; it is absent on intermediate stages. Authoritative terminal/recovery evidence is the durable signed lifecycle/receipt state and recovery lookup, never this lossy stream.

`inspectMcpReceipt` validates that the trust-verified envelope is exactly profile `{id:"auths.mcp", version:2}`, then bounded-decodes and semantically validates the private profile payload and its envelope bindings. Wrong profile, malformed/oversized payload, unknown payload version, or inconsistent tool/action/result/completion is a `rejected` value with `mcp.receipt-invalid`; it is never a successful details object or an exception.

Every MCP `completed` value carries the authorization `decisionReceipt` and its linked `executionReceipt`; `failed` carries the same pair because that variant is allowed only when an applied effect is durably established. Plan members retain both receipts. Replay returns the identical pair, and reconciliation returns the original decision plus the newly finalized linked execution receipt. Callers verify the decision first and then verify the execution with that exact decision supplied as `linkedDecisionReceipt`/`linked_decision_receipt`; the SDK never asks them to recover a missing companion from hidden state. MCP `denied`/`indeterminate` remain effect-free issue results and do not pretend to expose an execution receipt.

`McpProfile` describes and constructs typed calls; it does not open an effect runtime. The only public development runtime is the Node-specific, explicitly stateful constructor below. There is no local `production()` until a constructor can require complete trust, signed authority, independently operated custody, production lifecycle/receipt storage, required/executed configuration, and profile conformance without exposing transition callbacks.

### 5.7 `@auths-dev/sdk/mcp/node`

```ts
import type {
  McpDevelopmentOptions,
  McpProfile,
  McpSession,
  McpToolset,
} from "@auths-dev/sdk/mcp";

export type DevelopmentOptions<
  Tools extends McpToolset,
  Allowed extends Extract<keyof Tools, string>,
> = McpDevelopmentOptions<Tools, Allowed> & Readonly<{
  /** Development-only, single-machine state; never production durability. */
  readonly stateDirectory: string | URL;
}>;

export function openDevelopment<
  Tools extends McpToolset,
  Allowed extends Extract<keyof Tools, string>,
>(
  profile: McpProfile<Tools>,
  options: DevelopmentOptions<Tools, Allowed>,
): Promise<McpSession<Tools, Allowed>>;
```

This is the only Node-filesystem API. It is absent from browser/worker export conditions. There is deliberately no in-memory effectful session: a handler may have entered a real provider before returning `possible`, throwing, timing out, or observing cancellation, so the idempotency ledger and recovery locator must survive session/process loss. The base MCP module never accepts a path disguised as a portable candidate.

`stateDirectory` is a secret-bearing single-machine development store with manifest `auths.mcp-development-state/2`. On first open, the runtime creates one 32-byte root seed with an exclusive no-follow create and derives the stable local principal, authority signer, receipt signer, handle-protection key, and store-encryption keys through Rust-owned domain-separated derivation; it never creates independent ad-hoc keys. Reopen must reproduce the same principal and recovery scope. When an external custody signer is supplied, its private key is never copied; the store pins the complete `CustodyDescriptor` commitment and reopen rejects any descriptor or provider-key-version substitution before use.

The entire directory contains authority/custody material, receipt and recovery capabilities, lifecycle records, and idempotency commitments and is treated as a secret. POSIX creation requires directory mode `0700`, regular files `0600`, caller ownership, link count one, no symlink traversal, an exclusive process lock, atomic replace, file-and-directory `fsync`, and corruption detection before any key regeneration. An existing group/world-accessible, foreign-owned, hard-linked, unlocked, wrong-version, or partially durable store is rejected fail-closed. Windows uses an owner-only DACL, reparse-point refusal, exclusive sharing mode, replace-through, and flush semantics of equal strength. Concurrent opens fail with the registered `core.runtime-conflict` code; corruption never silently starts a new identity. Paths are absolute after resolution, at most 4,096 UTF-8 bytes, and the implementation never logs them. These rules are part of the development-state contract, not host-language convenience behavior.

When adapters are omitted, the runtime owns two manifest-bound defaults. Custody is `kind=workload`, `adapterId="auths.development.local-ed25519/2"`, suite `ed25519-v1`, lifecycle `durable`, key state `active-current`, and key version `root-v1`; its principal and key are derived from the stored root seed and remain stable on reopen. Reservation is `kind="auths.development.state-reservation/2"`, durability `single-machine-durable`, and uses the same locked lifecycle store. Diagnostics report both as owned. The testkit's `ephemeralEd25519Signer` is different: `adapterId="auths.testkit.ephemeral-ed25519/1"`, `kind=workload`, lifecycle `ephemeral`, key version `ephemeral-v1`, and a new principal per factory call; callers own and close it. No production path silently selects either development signer.

### 5.8 `@auths-dev/sdk/github`

```ts
import type { AuthsIssue, Receipt } from "@auths-dev/sdk";
import type { VerifiedReceipt } from "@auths-dev/sdk/verify";

declare const githubIssueBoundaryBrand: unique symbol;
export interface GitHubCandidatePolicy {
  readonly allowedPatterns: readonly string[];
  readonly deniedPatterns: readonly string[];
  readonly maximumChangedFiles: number;
  readonly maximumAddedBytes: bigint;
  readonly maximumDeletedBytes: bigint;
  readonly maximumCandidateBytes: bigint;
  readonly maximumGitObjects: number;
  readonly maximumCommits: number;
  readonly allowExecutableBitChanges: boolean;
  readonly allowSymlinks: boolean;
  readonly allowSubmodules: boolean;
  readonly allowMergeCommits: boolean;
  readonly allowNonUtf8Paths: false;
  readonly allowGitAttributesChanges: boolean;
  readonly allowGitmodulesChanges: boolean;
  readonly allowRepositoryAutomationChanges: boolean;
}

export interface GitHubIssueBoundary {
  readonly [githubIssueBoundaryBrand]: true;
  readonly boundaryId: string;
  readonly observedAtUnixMs: number;
  readonly expiresAtUnixMs: number;
  readonly repository: string;
  readonly issueNumber: number;
  readonly baseRef: string;
  readonly baseRevision: string;
  readonly objectFormat: "sha1" | "sha256";
  readonly candidatePolicy: GitHubCandidatePolicy;
  readonly expiry: Readonly<{
    minimumMs: number;
    maximumMs: number;
  }>;
  readonly budget: Readonly<{
    branches: 1;
    draftPullRequests: 1;
  }>;
  readonly providerCredential: "executor-only";
}

declare const inspectedGitHubCandidateBrand: unique symbol;
export interface InspectedGitHubCandidate {
  readonly [inspectedGitHubCandidateBrand]: true;
  readonly candidateRevision: string;
}

export type GitHubCandidateInspection =
  | Readonly<{
      kind: "accepted";
      candidate: InspectedGitHubCandidate;
      changedPaths: readonly string[];
      credentialRequested: false;
    }>
  | Readonly<{
      kind: "denied";
      issue: AuthsIssue & Readonly<{ effect: "not-applied" }>;
      changedPaths: readonly string[];
      credentialRequested: false;
    }>;

type GitHubRecoveryKind = "delegation" | "execution";
export class GitHubRecoveryReference<
  Kind extends GitHubRecoveryKind = GitHubRecoveryKind,
> {
  private constructor();
  private readonly __githubRecoveryReferenceBrand: Kind;
  readonly kind: Kind;
  static fromBytes<Kind extends GitHubRecoveryKind>(
    bytes: Uint8Array,
    expectedKind: Kind,
  ): GitHubRecoveryReference<Kind>;
  toBytes(): Uint8Array;
  toJSON(): never;
}

export type GitHubRecoveryLocator<Kind extends GitHubRecoveryKind> =
  | Readonly<{
      kind: "reference";
      reference: GitHubRecoveryReference<Kind>;
    }>
  | Readonly<{
      kind: "idempotency-key";
      idempotencyKey: string;
    }>;

export interface GitHubCompleted {
  readonly kind: "completed";
  readonly completion: "executed" | "replayed" | "reconciled";
  readonly workflowId: string;
  readonly branch: Readonly<{ ref: string; revision: string }>;
  readonly pullRequest: Readonly<{
    number: number;
    url: string;
    draft: true;
  }>;
  readonly receipts: readonly Receipt[];
  readonly newCredentialRequests: number;
  readonly newMutations: number;
}

export interface GitHubPartial {
  readonly kind: "partial";
  readonly completion: "executed" | "replayed" | "reconciled";
  readonly workflowId: string;
  readonly completedPhase: "branch";
  readonly branch: Readonly<{ ref: string; revision: string }>;
  readonly pullRequestDisposition: "denied" | "indeterminate" | "not-applied";
  readonly pullRequestIssue: AuthsIssue & Readonly<{
    effect: "not-applied";
  }>;
  /** Three decision receipts, or four when a provider result proves PR rejection. */
  readonly receipts: readonly Receipt[];
  readonly newCredentialRequests: number;
  readonly newMutations: number;
}

export interface GitHubDenied {
  readonly kind: "denied";
  readonly workflowId: string;
  readonly decisionReceipt: Receipt;
  readonly issue: AuthsIssue & Readonly<{ effect: "not-applied" }>;
}

export interface GitHubIndeterminate {
  readonly kind: "indeterminate";
  readonly workflowId: string;
  readonly decisionReceipt: Receipt;
  readonly issue: AuthsIssue & Readonly<{ effect: "not-applied" }>;
}

export interface GitHubNotApplied {
  readonly kind: "not-applied";
  readonly workflowId: string;
  readonly issue: AuthsIssue & Readonly<{ effect: "not-applied" }>;
  readonly receipts: readonly Receipt[];
}

export interface GitHubConflict {
  readonly kind: "conflict";
  readonly workflowId: string;
  readonly issue: AuthsIssue & Readonly<{ effect: "not-applied" }>;
}

export interface GitHubRecoveryRequired {
  readonly kind: "recovery-required";
  readonly workflowId: string;
  readonly issue: AuthsIssue & Readonly<{
    effect: "possible";
    retry: "unknown";
    recommendedAction: "resume-and-reconcile";
    executionReference: string;
  }>;
  readonly recovery: GitHubRecoveryLocator<"execution">;
  readonly credentialRequests: number | "unknown";
  readonly mutations: number | "unknown";
}

export type GitHubIssueOutcome =
  | GitHubCompleted
  | GitHubPartial
  | GitHubDenied
  | GitHubIndeterminate
  | GitHubNotApplied
  | GitHubConflict
  | GitHubRecoveryRequired;

export type GitHubDelegationResult =
  | Readonly<{ kind: "delegated"; task: GitHubIssueTask }>
  | Readonly<{
      kind: "denied" | "indeterminate" | "conflict";
      issue: AuthsIssue & Readonly<{ effect: "not-applied" }>;
    }>
  | Readonly<{
      kind: "recovery-required";
      issue: AuthsIssue & Readonly<{
        effect: "possible";
        retry: "unknown";
        recommendedAction: "resume-and-reconcile";
        executionReference: string;
      }>;
      idempotencyKey: string;
      recovery: GitHubRecoveryLocator<"delegation">;
    }>;

export interface GitHubIssueTask extends AsyncDisposable {
  readonly workflowId: string;
  readonly boundary: GitHubIssueBoundary;
  readonly agentPrincipal: string;
  readonly expiresAtUnixMs: number;

  inspect(input: Readonly<{
    /** Raw Git bundle v2; bounded by boundary.candidatePolicy. */
    bundle: Uint8Array;
    candidateRevision: string;
    signal?: AbortSignal;
  }>): Promise<GitHubCandidateInspection>;

  execute(
    candidate: InspectedGitHubCandidate,
    options: Readonly<{
      idempotencyKey: string;
      signal?: AbortSignal;
    }>,
  ): Promise<GitHubIssueOutcome>;

  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

export interface GitHubIssueClientDiagnostics {
  readonly endpointOrigin: string;
  readonly protocolVersion: string;
  readonly compatibility: "full" | "recovery-only";
  readonly errorRegistryDigest: string;
  readonly routeSchemaDigest: string;
  readonly durableServerState: true;
  readonly credentialLocation: "executor-only";
  readonly recoveryRetentionSeconds: number;
  readonly receiptRetentionSeconds: number;
  readonly warnings: readonly string[];
}

export interface GitHubIssueClient extends AsyncDisposable {
  boundary(options?: Readonly<{
    signal?: AbortSignal;
  }>): Promise<GitHubIssueBoundary>;

  delegate(options: Readonly<{
    boundary: GitHubIssueBoundary;
    agentLabel: string;
    /** Server-safe default when omitted; otherwise within boundary.expiry. */
    expiresInMs?: number;
    /** Optional byte-identical subset of server-owned allowed patterns. */
    allowPatterns?: readonly string[];
    idempotencyKey: string;
    signal?: AbortSignal;
  }>): Promise<GitHubDelegationResult>;

  recoverDelegation(
    recovery: GitHubRecoveryLocator<"delegation">,
    options?: Readonly<{ signal?: AbortSignal }>,
  ): Promise<GitHubDelegationResult>;

  recoverDelegationByIdempotencyKey(
    idempotencyKey: string,
    options?: Readonly<{ signal?: AbortSignal }>,
  ): Promise<GitHubDelegationResult>;

  recoverExecution(
    recovery: GitHubRecoveryLocator<"execution">,
    options?: Readonly<{ signal?: AbortSignal }>,
  ): Promise<GitHubIssueOutcome>;

  recoverExecutionByIdempotencyKey(
    idempotencyKey: string,
    options?: Readonly<{ signal?: AbortSignal }>,
  ): Promise<GitHubIssueOutcome>;

  receipts(
    workflowId: string,
    options?: Readonly<{ signal?: AbortSignal }>,
  ): Promise<readonly Receipt[]>;

  diagnostics(): GitHubIssueClientDiagnostics;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

export interface GitHubIssueClientOptions {
  readonly endpoint: string | URL;
  /** Bearer credential for the Auths control plane, never a GitHub token. */
  readonly controlPlaneAccessToken: string;
  readonly timeoutMs?: number;
  readonly maximumResponseBytes?: number;
}

export function connectGitHubIssueAddress(
  options: GitHubIssueClientOptions,
): Promise<GitHubIssueClient>;

export type GitHubReceiptDetails =
  | Readonly<{
      kind: "decision";
      profile: "auths.github.issue-address/2";
      workflowId: string;
      phase: "branch" | "draft-pull-request";
      decision: "authorized" | "denied" | "indeterminate";
      repository: string;
      issueNumber: number;
      baseRevision: string;
      candidateRevision: string;
      objectFormat: "sha1" | "sha256";
    }>
  | Readonly<{
      kind: "execution";
      result: "succeeded";
      profile: "auths.github.issue-address/2";
      workflowId: string;
      phase: "branch" | "draft-pull-request";
      repository: string;
      issueNumber: number;
      baseRevision: string;
      candidateRevision: string;
      objectFormat: "sha1" | "sha256";
      providerObjectId: string;
    }>
  | Readonly<{
      kind: "execution";
      result: "not-applied" | "github-rejected" | "reconciliation-required";
      profile: "auths.github.issue-address/2";
      workflowId: string;
      phase: "branch" | "draft-pull-request";
      repository: string;
      issueNumber: number;
      baseRevision: string;
      candidateRevision: string;
      objectFormat: "sha1" | "sha256";
      providerObjectId?: never;
    }>;

export type GitHubReceiptInspection =
  | Readonly<{ kind: "inspected"; details: GitHubReceiptDetails }>
  | Readonly<{
      kind: "rejected";
      issue: AuthsIssue & Readonly<{ effect: "not-applied" }>;
    }>;

export function inspectGitHubReceipt(
  receipt: VerifiedReceipt,
): GitHubReceiptInspection;
```

`delegate` never accepts repository, issue number, base ref/revision, denied patterns, candidate limits/switches, or publication budgets. It consumes the sealed boundary snapshot returned by `boundary`; `allowPatterns` may only select a byte-identical subset of the advertised allowed patterns, and expiry is strict attenuation. The server binds `boundaryId`, observation/expiry, authenticated control-plane principal, and the exact delegation request to the required idempotency key before minting a task. A recovery locator is exact: a decoded server response carries `kind="reference"` and the opaque kind-branded capability; a disconnect, timeout, or cancellation after request transmission carries `kind="idempotency-key"` with the caller-owned key because no client can fabricate a server reference it did not receive. The Rust client produces the matching registered outcome-unknown issue, never a bare transport exception. `recoverDelegation`/`recoverExecution` dispatch either locator safely; the explicit by-key methods are convenience equivalents for restart code that retained only the original key. Changed commitments remain `conflict`. Delegation and execution locators remain type/kind separated, so one phase cannot be substituted for the other. `inspect` never requests a provider credential. The sealed candidate is bound to workflow, boundary, base revision, candidate revision, bundle commitment, and inspection result; it cannot be reused in another task.

`partial` means the branch is already externally published while the draft-PR phase has no possible effect. It therefore cannot be represented as whole-workflow `denied`, `indeterminate`, or `not-applied`. `pullRequestDisposition` says whether the second phase was denied by a trustworthy decision, was indeterminate before provider entry, or received a durable provider result proving rejection/no effect; in every case its issue has `effect="not-applied"` for that phase. The result carries the exact branch and ordered evidence: branch decision/execution plus the PR decision (three receipts), and additionally the PR execution receipt for provider-proven rejection (four). The server retrieves original branch receipts when resuming. `newCredentialRequests`/`newMutations` count only this call; replay and recovery never republish the branch. A possibly created PR remains `recovery-required`, not `partial`.

The Rust-domain-to-SDK outcome mapping is exhaustive for v2:

| Rust/domain state | SDK result |
|---|---|
| authorization `Rejected` before branch | `denied` with `workflowId` and the durable decision receipt returned directly and through `receipts()` |
| authorization `Indeterminate` before branch | `indeterminate` with `workflowId` and the durable decision receipt returned directly and through `receipts()` |
| `Partial` or `ResumedPartial` | normalized `partial` with exact branch, disposition, and three or four ordered receipts |
| `Completed` or `ResumedCompleted` | `completed` (`executed` or `reconciled`) with branch, draft PR, four ordered receipts |
| whole-workflow exact replay | prior `completed`/`partial`/`not-applied` value with `completion="replayed"` where present; zero new credentials/mutations |
| `Reconciled` applied | resume profile orchestration from the observed phase; return normalized `completed`/`partial` or the next `recovery-required` |
| `ReconciledNonEffect` | `not-applied` with the recovery receipt; reservation released only by the Rust-owned GitHub observer |
| `ReconciliationRequired` | `recovery-required` for the exact branch/PR phase |
| branch-phase `ExecutionFailed(GitHubWriteError::Rejected)` | whole-workflow `not-applied` with execution receipt; v2 records the durable provider rejection instead of `MarkOutcomeUnknown` |
| PR-phase `ExecutionFailed(GitHubWriteError::Rejected)` after branch | `partial(pullRequestDisposition="not-applied")` with four ordered receipts |
| `ExecutionFailed(Ambiguous|PostconditionMismatch|Adapter)` | `recovery-required`; never `failed` or `not-applied` |

The v2 projection of the 31 frozen Rust `DecisionCode` values is also total. `B` means before branch provider entry; `P` means the branch is already proven applied and the PR phase has not applied. A decision receipt whose code is paired with another class/result is malformed and rejected. Candidate rows are returned by `inspect`; `ActionReplay` emits no issue, credential, or provider call.

| Rust `DecisionCode` | Registered v2 issue | Exact result |
|---|---|---|
| `Authorized` | — | continue the exact phase |
| `WorkflowProofInvalid` | `github.workflow-proof-invalid` | B `denied`; P `partial(denied)` |
| `WorkflowExpired` | `github.workflow-expired` | B `denied`; P `partial(denied)` |
| `WorkflowCancelled` | `github.workflow-cancelled` | B `denied`; P `partial(denied)` |
| `ExecutorAudienceMismatch` | `github.executor-audience-mismatch` | B `denied`; P `partial(denied)` |
| `RepositoryMismatch` | `github.repository-mismatch` | B `denied`; P `partial(denied)` |
| `RepositoryRenamedOrTransferred` | `github.repository-renamed-or-transferred` | B `denied`; P `partial(denied)` |
| `IssueMismatch` | `github.issue-mismatch` | B `denied`; P `partial(denied)` |
| `IssueNotOpen` | `github.issue-not-open` | B `denied`; P `partial(denied)` |
| `BaseRevisionMismatch` | `github.base-revision-mismatch` | B `denied`; P `partial(denied)` |
| `BranchAlreadyExists` | `github.branch-already-exists` | B `denied` |
| `PullRequestAlreadyExists` | `github.pull-request-already-exists` | P `partial(denied)` |
| `CandidateBundleMalformed` | `github.candidate-bundle-malformed` | `CandidateDenied` |
| `CandidateLimitExceeded` | `github.candidate-limit-exceeded` | `CandidateDenied` |
| `CandidateNotDescendant` | `github.candidate-not-descendant` | `CandidateDenied` |
| `MergeCommitDenied` | `github.merge-commit-denied` | `CandidateDenied` |
| `UnsupportedGitObject` | `github.unsupported-git-object` | `CandidateDenied` |
| `PathNotAllowed` | `github.path-not-allowed` | `CandidateDenied` |
| `PathExplicitlyDenied` | `github.path-explicitly-denied` | `CandidateDenied` |
| `FileModeDenied` | `github.file-mode-denied` | `CandidateDenied` |
| `RepositoryAutomationPolicyMismatch` | `github.repository-automation-policy-mismatch` | B `indeterminate`; P `partial(indeterminate)` |
| `BranchBudgetExhausted` | `github.branch-budget-exhausted` | B `denied` |
| `PullRequestBudgetExhausted` | `github.pull-request-budget-exhausted` | P `partial(denied)` |
| `ActionReplay` | — | hydrate original phase object/receipts; branch replay continues PR orchestration, PR replay normalizes to `completed(replayed)` |
| `EvidenceMissing` | `github.evidence-missing` | B `indeterminate`; P `partial(indeterminate)` |
| `EvidenceStale` | `github.evidence-stale` | B `indeterminate`; P `partial(indeterminate)` |
| `VerifierConfigurationMismatch` | `github.verifier-configuration-mismatch` | B `denied`; P `partial(denied)` |
| `ExactActionMismatch` | `github.exact-action-mismatch` | B `denied`; P `partial(denied)` |
| `GitHubRejected` | phase-specific `github.branch-rejected` / `github.pull-request-rejected` | B `not-applied`; P `partial(not-applied)`, only after a durable provider result proves rejection |
| `ExecutionAmbiguous` | phase-specific outcome-unknown code | `recovery-required`, `effect=possible` |
| `ReconciliationRequired` | phase-specific outcome-unknown code | `recovery-required`; never blind retry or `not-applied` |

There is no generic GitHub `failed` variant because the shipping domain currently has no evidence-proven “effect applied but terminally unsuccessful” state. Adding one later requires a new domain outcome and receipt fixture rather than reclassifying `ExecutionFailed`.

The candidate format is raw Git bundle v2 containing the declared candidate commit and its ancestry to the boundary's exact base revision. `objectFormat` is server-owned; revisions are full lowercase hex of exactly 40 (`sha1`) or 64 (`sha256`) characters. The public policy projection is exactly the new immutable v2 `CandidatePolicy`; the SDK supplies no broader defaults. V2 retains v1's path meaning but adds explicit work ceilings that v1 lacked. It permits 1–128 allow patterns and 0–128 deny patterns. Patterns and tree paths are root-relative UTF-8 already in NFC of 1–1,024 bytes with `/`, no empty/dot/dot-dot component, leading/trailing slash, backslash, control byte, `?`, `[` or `]`; non-NFC input is rejected and never normalized. Within one component `*` matches zero or more bytes; `**` is legal only as a complete component and matches zero or more complete components. Deny matches win, matching is byte-exact and host-independent, and `allowPatterns` only selects byte-identical advertised allow patterns. Non-UTF-8 tree paths are always rejected in v2.

Every numeric candidate-policy field is positive. Hard ceilings are 16 MiB candidate bundle, 20,000 Git objects, 64 commits, 20,000 changed files, 4 MiB aggregate returned changed-path bytes, 64 MiB added bytes, 64 MiB deleted bytes, 1,024 bytes per path, and 64 MiB total expanded object bytes; the boundary may set lower values and inspection enforces the lower of every advertised and hard bound. The sealed candidate does not duplicate the public changed-path list; `GitHubCandidateInspection.changedPaths`/`changed_paths` is its one projection. The eight independent switches shown in `GitHubCandidatePolicy` are enforced exactly, including `.gitattributes`, `.gitmodules`, and repository-automation changes. The selected demo fixture uses 2 changed files, 8 KiB added, 8 KiB deleted, 2 MiB bundle, 1,000 objects, 1 commit, and all switches false, but these are fixture values—not SDK defaults. The server parses in quarantine without checkout, hooks, filters, LFS/network fetch, or candidate-code execution and rejects missing, extra, or substituted revisions. External applications create the bundle with normal Git tooling and pass copied bytes.

The selected v2 client authentication is HTTPS Bearer authentication to the Auths control plane over the exact route family defined below; tokens are redacted and never forwarded to GitHub. `endpoint` is an origin only (no userinfo, query, fragment, or caller-selected route), timeout is 1–300,000 ms (default 30,000), and maximum response is 12–16 MiB (default 12 MiB, sufficient for every valid 8 MiB receipt aggregate plus framing). Every redirect status is refused without resending credentials or body, including same-origin redirects. Plaintext is refused. GitHub App credentials remain executor-only. The stable module must not ship while the server uses `/v1/demo`, or before stable error registration, linked cryptographic receipts, idempotent delegation, durable recovery, and immutable v2 profile/spec/fixture registration exist. Until then, an explicitly named demo package may exist but must not impersonate this API.

The v2 route family and method mapping are fixed:

| SDK operation | HTTP route | Request body |
|---|---|---|
| connect/capabilities | `GET /v2/profiles/github/issue-address/capabilities` | none |
| `boundary` | `GET /v2/profiles/github/issue-address/boundary` | none |
| `delegate` | `POST /v2/profiles/github/issue-address/delegations` | sealed boundary bytes, label, optional expiry/pattern subset; idempotency key in header |
| recover delegation handle | `POST /v2/profiles/github/issue-address/delegations/recover/reference` | opaque reference bytes |
| recover delegation key | `POST /v2/profiles/github/issue-address/delegations/recover/idempotency` | none; idempotency key in header |
| `inspect` | `POST /v2/profiles/github/issue-address/workflows/{workflowId}/candidates/inspect` | bundle, candidate revision |
| `execute` | `POST /v2/profiles/github/issue-address/workflows/{workflowId}/execute` | sealed candidate bytes; idempotency key in header |
| recover execution handle | `POST /v2/profiles/github/issue-address/workflows/recover/reference` | opaque reference bytes |
| recover execution key | `POST /v2/profiles/github/issue-address/workflows/recover/idempotency` | none; idempotency key in header |
| `receipts` | `GET /v2/profiles/github/issue-address/workflows/{workflowId}/receipts` | none |

All bodies and 200 responses use `application/vnd.auths.github.issue-address.v2+cbor`, deterministic CBOR with definite lengths, UTF-8 text map keys, and no tags/floats/duplicate or unknown keys. Every top-level body has `contract: "auths.github.issue-address/2"`. Sealed boundary/candidate/recovery values are canonical Rust-owned `bstr`, never caller-reconstructed maps; other requests use only the route table's named snake-case keys.

The canonical result wire is nested and independent of host presentation: boundary has `candidate_policy`, `expiry:{minimum_ms,maximum_ms}`, and `budget:{branches,draft_pull_requests}`; completed has `branch:{ref,revision}` and `pull_request:{number,url,draft}`; partial has `branch`, `pull_request_disposition`, `pull_request_issue`, and no pull-request object. Receipt lists are ordered `bstr` arrays. Every nested issue is the exact registered Rust `auths.error/1` wire envelope (including wire key `entered`), never the host `AuthsIssue`/`ErrorInfo` projection. TypeScript projects the nested objects directly; Python deliberately flattens its read-only branch/PR and boundary expiry/budget properties without changing canonical bytes. Every other variant maps one-for-one by its declared snake-case fields. Rust owns the closed schema and golden bytes shipped as `protocol/github-issue-address-v2.json`; bindings do no schema authoring.

`Authorization: Bearer …` is mandatory on every route. `Auths-Error-Registry-SHA256` is the 64-lowercase-hex digest returned by `runtimeInfo()`/`runtime_info()` and appears on every request. `Idempotency-Key` uses section 4.3's grammar and appears only on the two mutating calls and their by-key lookups; duplicate body/header values are forbidden. The server derives the control-plane principal from the credential and binds it with profile v2, route operation, boundary/workflow, idempotency key, and canonical body. Body-supplied principals/routes are impossible. Workflow IDs are registered tokens and are percent-encoded as one path segment by the SDK.

The capabilities response contains exactly `contract`, `profile`, `error_registry_sha256`, `route_schema_sha256`, `recovery_compatible_registry_sha256`, `durable_server_state: true`, `credential_location: "executor-only"`, `recovery_retention_seconds`, and `receipt_retention_seconds`. Digests are SHA-256 encoded as 64 lowercase hex. TypeScript `connectGitHubIssueAddress` and Python `IssueClient.__aenter__` authenticate and validate it before exposing normal operations; false/missing durability or another credential location refuses construction. A registry/schema/profile mismatch opens the client only in `recovery-only` mode: `boundary`, `delegate`, `inspect`, and `execute` fail before effect with registered `core.unsupported-abi`, while recovery and receipt lookup remain available. Recovery requests carry the client digest; the server returns only a mutually registered phase outcome or the same locator with the phase's registered outcome-unknown code. It never sends an unregistered error string. Exact-match and recovery-only capability bytes are golden fixtures.

Encoded route ceilings include framing: boundary/delegation/recovery requests are at most 1 MiB and their responses 12 MiB; candidate inspection requests are at most 17 MiB and responses 6 MiB; execute requests are at most 1 MiB and responses 12 MiB; receipt-list responses are 12 MiB; every error response is 64 KiB. The server uses route-specific streaming limits rather than the existing global 1 MiB v1 ingress cap. Client construction rejects `maximumResponseBytes` below 12 MiB or above 16 MiB before any dispatch, so every accepted configuration can receive every valid effectful response and local truncation can never erase phase/effect state.

Expected typed results use HTTP 200, including denial, partial, conflict, and recovery-required. `400/401/403/404/409/413/415/429/503` use bounded `application/vnd.auths.error.v1+cbor`; the SDK never infers effect from status alone. A wrong-principal/wrong-scope lookup is indistinguishable from missing. A by-idempotency lookup with no visible record atomically creates a durable unresolved tombstone and returns recovery-required with a deterministic opaque reference, thereby preventing future blind execution under that key. A same-scope valid reference whose record disappeared returns the phase-specific `github.branch-outcome-unknown` or `github.pull-request-outcome-unknown`, `effect=possible`, with the same locator/operator correlation; it never uses the pre-effect `core.internal-invariant` classification or implies non-application. Unresolved/tombstone records and their idempotency mappings are never automatically deleted. Terminal mappings remain for at least 90 days; receipts remain for at least 365 days and `receipts()` returns an empty tuple/list when none are visible—emptiness is never evidence of non-application. Diagnostics reports the observed retention values and refuses a server below these minima. Responses contain at most 16 receipts and 8 MiB aggregate receipt bytes.

`inspectGitHubReceipt` likewise requires profile `{id:"auths.github.issue-address", version:2}` and validates the bounded phase/workflow/repository/issue/revision/result payload against the signed envelope. `result="succeeded"` requires a provider object; `not-applied | github-rejected | reconciliation-required` forbids one. Wrong profile, malformed/oversized/unknown-version payload, result/object mismatch, or inconsistent fields returns `rejected` with `github.receipt-invalid`; no expected hostile profile-payload state throws.

### 5.9 `@auths-dev/sdk/protocol`

This advanced module is deliberately effect-free. It supports a bounded byte transport and the new authenticated `auths.remote-verification/1` action-authorization protocol. It does not reuse the weaker `/v1/authority/verify` proof-control route and does not expose `create`, `delegate`, generic `execute`, generic recovery, authority import, profile markers, or caller-authored receipt disclosure.

```ts
import type {
  VerificationInput,
  VerificationResult,
} from "@auths-dev/sdk/verify";

export interface BoundedTransportRequest {
  /** Fully resolved by the client; the transport never selects a route. */
  readonly url: URL;
  readonly method: "POST";
  readonly mediaType: "application/vnd.auths.remote-verification.v1+cbor";
  readonly accept: "application/vnd.auths.remote-verification.v1+cbor";
  readonly body: Uint8Array;
  readonly deadlineUnixMs: number;
  readonly signal: AbortSignal;
  readonly maximumResponseBytes: number;
}

export interface BoundedTransportResponse {
  readonly status: number;
  readonly mediaType: string;
  readonly body: Uint8Array;
}

export interface BoundedTransport extends AsyncDisposable {
  readonly contract: "bounded-byte-transport/2";
  send(request: BoundedTransportRequest): Promise<BoundedTransportResponse>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

export interface RemoteVerifier extends AsyncDisposable {
  verify(input: VerificationInput & Readonly<{
    signal?: AbortSignal;
  }>): Promise<VerificationResult>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

interface RemoteVerifierCommonOptions {
  /** Origin only; the client appends `/v2/verification/authorize`. */
  readonly endpoint: string | URL;
  readonly timeoutMs?: number;
  readonly maximumResponseBytes?: number;
  readonly allowInsecureLoopback?: boolean;
}

export type RemoteVerifierOptions = RemoteVerifierCommonOptions & (
  | Readonly<{
      /** Auths control-plane credential; never a domain-provider credential. */
      accessToken: string;
      transport?: never;
      transportOwnership?: never;
    }>
  | Readonly<{
      accessToken?: never;
      transport: BoundedTransport;
      transportOwnership?: "borrowed" | "owned";
    }>
);

export function connectRemoteVerifier(
  options: RemoteVerifierOptions,
): Promise<RemoteVerifier>;
```

`endpoint` is always required so the client—not an injected transport—can resolve the fixed route. Exactly one channel mode is selected: built-in transport plus mandatory `accessToken`, or injected transport with no SDK credential. HTTPS may be relaxed only for an explicitly enabled literal loopback development origin. Redirect mode is `error`: every 301/302/303/307/308 response, same-origin or cross-origin, is refused without resending credentials or body. Timeout is 1–300,000 ms (default 30,000); maximum response is 1 KiB–16 MiB (default 8 MiB). `deadlineUnixMs` is the checked absolute wall-clock deadline derived once by the client and an injected transport may shorten but never extend it. The client resolves `/v2/verification/authorize`, deadline, and media types before transport dispatch; a transport never receives SDK credentials, decodes the body, or chooses profile semantics. In injected mode the application-owned transport performs channel authentication itself. The built-in channel applies and redacts the Auths Bearer credential below this public request type. The SDK validates status, content type, response length, schema, and protocol version before projecting the same `VerificationResult` used locally. Expected proof denial/indeterminacy remains a value because a complete decision exists. Failure to obtain a trustworthy remote decision rejects with `AuthsError`: channel authentication uses `remote.authentication-failed`, timeout/unavailability use `remote.timeout`/`remote.transport-unavailable`, and malformed status/media/schema/over-limit output uses `remote.response-malformed`. All are registered `effect=not-applied` verification faults, never execute/lifecycle codes or binding-authored exceptions. A remote authorized decision remains inert evidence, never an executable command.

The wire contract is immutable `auths.remote-verification/1`, canonical CBOR (RFC 8949 deterministic encoding, definite lengths, integer map keys, no tags/floats/duplicates/unknown keys). Request map keys are exactly `0:1` (contract version), `1:proof bstr`, `2:action bstr`, `3:trusted-context bstr`, `4:correlation-id tstr`, and `5:error-registry-sha256 bstr(32)`; the client creates the bounded correlation ID and uses the generated registry digest. The 200 response keys are exactly `0:1`, `1:kind(0 authorized|1 denied|2 indeterminate)`, `2:code tstr`, `3:stage(0..4 matching VerificationStage)`, `4:correlation-id`, `5:metrics map`, `6:required-configuration bstr|null`, `7:executed-configuration bstr`, `8:decision bstr`, `9:auths.error/1 map|null` (null only when authorized), and `10:error-registry-sha256 bstr(32)`. Byte/count/work limits are the verification limits in section 4.10. A digest mismatch is HTTP 409 with the universally registered `core.unsupported-abi` envelope and no verification work; this effect-free client may reconnect after upgrade. Expected proof denial/indeterminacy is HTTP 200. `400/401/403/409/413/415/429/503` carry a bounded `application/vnd.auths.error.v1+cbor` envelope and become `AuthsError`; redirects, other statuses, media mismatch, digest/correlation mismatch, or malformed bodies become the matching registered remote `AuthsError`. The authenticated control-plane principal and loaded verifier configuration are committed into executed configuration; the request never supplies trust roots or provider authority.

This restriction is intentional. The maintained execution routes are profile-specific, and the repository forbids a universal provider dispatcher. OpenTofu and PostgreSQL execution therefore remain unavailable from these SDKs until their typed verticals meet the qualification gate. Profile-owned receipt disclosure also remains in the owning vertical rather than a generic byte constructor.

### 5.10 `@auths-dev/sdk/adapters`

This module exposes only mechanisms with an evidence-backed contract. It does not allow applications to define profiles or lifecycle transitions.

```ts
export type SigningObjectKind =
  | "grant"
  | "action"
  | "principal-status"
  | "grant-status";
export type CustodyLifecycle = "durable" | "ephemeral";
export type CustodyKind = "webauthn" | "workload" | "kms" | "hsm" | "pkcs11";
export type CustodyKeyState =
  | "enrolled"
  | "ready"
  | "rotation-pending"
  | "active-current"
  | "retiring-previous"
  | "revoked"
  | "disabled"
  | "unavailable"
  | "indeterminate";
export type CustodyFailure =
  | "denied"
  | "cancelled"
  | "throttled"
  | "unavailable"
  | "revoked-key"
  | "disabled-key"
  | "provider-unknown"
  | "invalid-provider-response";

export interface CustodySignatureDescriptor {
  readonly principalMethod: string;
  readonly verificationMethod: string;
  readonly suite: string;
}

export interface CustodyDescriptor {
  readonly contract: "signer-custody/2";
  readonly kind: CustodyKind;
  readonly adapterId: string;
  readonly principal: string;
  readonly signature: CustodySignatureDescriptor;
  readonly keyVersion: string;
  readonly keyState: CustodyKeyState;
  readonly lifecycle: CustodyLifecycle;
}

export interface ReviewField {
  readonly label: string;
  readonly value: string;
}

export interface PublicControlEvidence {
  readonly type: string;
  readonly mediaType: string;
  readonly bytes: Uint8Array;
}

export interface SigningRequest {
  readonly requestId: string;
  readonly objectKind: SigningObjectKind;
  readonly objectId: Uint8Array;
  readonly descriptor: CustodyDescriptor;
  readonly transactionDigest: Uint8Array;
  readonly signingPreimage: Uint8Array;
  readonly expiresAtUnixSeconds: bigint;
  readonly display: readonly ReviewField[];
  readonly signal: AbortSignal;
}

export interface SigningResponse {
  readonly requestId: string;
  readonly objectId: Uint8Array;
  readonly principal: string;
  readonly descriptor: CustodySignatureDescriptor;
  readonly providerKeyVersion: string;
  readonly transactionDigest: Uint8Array;
  readonly signature: Uint8Array;
  readonly evidence: readonly PublicControlEvidence[];
}

export type CustodySignResult =
  | Readonly<{ kind: "signed"; response: SigningResponse }>
  | Readonly<{
      kind: "rejected";
      failure: Extract<
        CustodyFailure,
        "denied" | "cancelled" | "revoked-key" | "disabled-key"
      >;
    }>
  | Readonly<{
      kind: "indeterminate";
      failure: Extract<
        CustodyFailure,
        | "throttled"
        | "unavailable"
        | "provider-unknown"
        | "invalid-provider-response"
      >;
    }>;

export interface CustodySigner extends AsyncDisposable {
  readonly descriptor: CustodyDescriptor;
  sign(request: SigningRequest): Promise<CustodySignResult>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

export interface ReservationRecord {
  readonly key: string;
  readonly commitment: Uint8Array;
  readonly value: Uint8Array;
}

export type ReservationDecision = "acquired" | "exact-replay" | "conflict";

export interface ReservationStore extends AsyncDisposable {
  readonly contract: "atomic-reservation-store/2";
  readonly kind: string;
  readonly durability: "ephemeral" | "single-machine-durable";
  reserve(
    record: ReservationRecord,
    options: Readonly<{ signal: AbortSignal }>,
  ): Promise<ReservationDecision>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}
```

Approval transactions remain internal in this cut. The authoritative mechanism catalog classifies `approval-transaction` as `retain-internal`, and AP-SPEC-029 still requires cancelled/unavailable outcomes, tamper-evident approval records, and exact required/executed policy and rule commitments before a provider-neutral public contract is honest. Current `approval`/`Approval` builders and approval-provider test helpers are therefore internalized, not renamed. A future public approval adapter requires a catalog promotion and conformance suite in the same review unit. MCP's internal handler/provider wrapper is session-owned; application handler and observation callbacks are borrowed.

`CustodySigner.descriptor` is an immutable session-pinned value. This proposal selects new immutable contract/suite `signer-custody/2`; v1 meaning is not edited or aliased. Rust validates adapter/kind/principal/signature/key-version/key-state/lifecycle fields before any request. Only `ready | active-current` keys may sign. Every response must byte-for-byte echo request ID, object ID, principal, signature descriptor, provider key version, and transaction digest; Rust then canonicalizes/verifies the signature and evidence. Descriptor, key-version, object, request, digest, suite, signature, or evidence substitution fails closed. `provider-unknown` is the required result when a helper exits/disconnects after possible signing; an arbitrary adapter exception is mapped to that indeterminate value. No fallback key/kind is selected. Cancellation is `rejected/cancelled` only when the adapter establishes that no signature was produced; otherwise it is `indeterminate/provider-unknown`.

`ReservationStore` is deliberately narrow. It proves atomic reservation of one exact record only. Its client-created abort signal is mandatory; an adapter may acknowledge cancellation only before acquisition, while cancellation after acquisition must settle as `acquired | exact-replay | conflict` before close returns. It is **not** renamed `LifecycleStore` and is not sufficient for production execution state. The lifecycle specification also requires linearizable lookup, revision CAS, atomic multi-intent reservation, state transition plus receipt append, durable acknowledgement, corruption rejection, deterministic history, and crash-safe reconciliation. A production `LifecycleStoreV2` or separately typed durable subtype may be published only when a Rust contract and conformance suite define those additional operations.

### 5.11 `@auths-dev/sdk/testkit`

```ts
import type {
  CustodySigner,
  ReservationStore,
} from "@auths-dev/sdk/adapters";
import type { BoundedTransport } from "@auths-dev/sdk/protocol";

export interface ConformanceCaseResult {
  readonly id: string;
  readonly status: "passed" | "failed";
  readonly detailCode?:
    | "contract-mismatch"
    | "unexpected-exception"
    | "timeout"
    | "resource-leak"
    | "redaction-failed";
  /** Redacted, single-line, at most 256 Unicode scalar values. */
  readonly summary?: string;
}

export interface ConformanceMetadata {
  readonly suite: string;
  readonly contractVersion: string;
  readonly sdkVersion: string;
  readonly generatedAt: string;
  readonly assurance: "test-results-only-not-security-certification";
}

export interface ConformanceReport {
  readonly metadata: ConformanceMetadata;
  readonly passed: boolean;
  readonly cases: readonly ConformanceCaseResult[];
}

export const conformance: Readonly<{
  custodySigner(
    factory: () => CustodySigner | Promise<CustodySigner>,
  ): Promise<ConformanceReport>;
  reservationStore(
    factory: (instanceId: string) =>
      ReservationStore | Promise<ReservationStore>,
  ): Promise<ConformanceReport>;
  boundedTransport(
    factory: () => BoundedTransport | Promise<BoundedTransport>,
  ): Promise<ConformanceReport>;
}>;

export function ephemeralEd25519Signer(): Promise<CustodySigner>;

export const fixtures: Readonly<{
  verification: Readonly<{
    authorized(): Readonly<{
      proof: Uint8Array;
      action: Uint8Array;
      trustedContext: Uint8Array;
    }>;
    denied(): Readonly<{
      proof: Uint8Array;
      action: Uint8Array;
      trustedContext: Uint8Array;
    }>;
  }>;
  github: Readonly<{
    deniedCandidate(reason: "protected-path" | "base-mismatch"): Uint8Array;
  }>;
}>;
```

There is no verdict-selecting `DiagnosticVerifier`, generic `MemoryGateway`, public product-waist manifest runner, or `certify*` wording. `passed` is true only when every mandatory case in the named suite/version passed; there is no caller-selected skip. Adapter exceptions are never copied verbatim: the runner maps them to a closed detail code and a bounded redacted summary, and a redaction failure fails the case with no summary. Tests inject secret-shaped exception text to prove reports, logs, and `repr` do not leak it. The profile-owned MCP lifecycle suite remains repository CI because a handler-only factory cannot drive its authority, concurrency, ambiguity, and reconciliation cases honestly. Testkit fixtures are inert and cannot be promoted to executable commands. Production entry points must have a static dependency test proving they do not import `/testkit`.

The runner-to-catalog mapping is exact:

| Public runner | Rust-owned suite | Mandatory case IDs |
|---|---|---|
| `conformance.custodySigner` / `run_custody_signer_conformance` | `signer-custody/2` | `signer/transaction-binding`, `principal-binding`, `descriptor-binding`, `key-version-binding`, `object-binding`, `request-binding`, `expiry`, `duplicate`, `canonical-signature`, `evidence-binding`, `denied`, `cancelled`, `throttled`, `unavailable`, `revoked-key`, `disabled-key`, `provider-unknown`, `invalid-response`, `concurrent-reordering`, `disposal`, `redaction` |
| `conformance.reservationStore` / `run_reservation_store_conformance` | `atomic-reservation-store/2` | `atomic-store/acquire`, `exact-replay`, `conflict`, `concurrent-single-winner`, `bounded-record`, `isolated-instances`, `reopen-durability-claim`, `cancel-after-acquire`, `disposal` |
| `conformance.boundedTransport` / `run_bounded_transport_conformance` | `bounded-byte-transport/2` | `byte-transport/exact-route-and-bytes`, `bounded-input`, `bounded-output`, `deadline`, `cancellation`, `disposal` |

For reservation conformance the runner supplies bounded registered-token `instanceId` values. Two factory calls with the same ID mean close and reopen the same backing namespace; two different IDs must be isolated. The `reopen-durability-claim` case expects exact replay after same-ID reopen only when `durability="single-machine-durable"`, and expects a fresh acquisition for correctly declared ephemeral storage. This test-only addressing contract removes ambiguity without adding reopen or configuration methods to the production adapter.

Implementation unit 10 registers immutable `signer-custody/2`, `atomic-reservation-store/2`, and `bounded-byte-transport/2` rather than changing v1 suites, updates MCP evidence from v1 to v2, and keeps bounded byte transport integration-owned under the public protocol extension rather than promoting it to `frameworkContracts`. There is no catalog-owned identity-method/authenticator suite, so the prior proposed identity conformance runners/fakes are deliberately absent. There is no separate public durable-reservation subtype or runner: the single atomic suite tests the exact `durability` claim without pretending the narrow store is a production lifecycle store.

### 5.12 TypeScript platform and loading matrix

| Module | Node >=20.6 | Browser | Worker | Loads effect runtime on import? |
|---|---:|---:|---:|---:|
| root | yes | yes | yes | no |
| `/verify` | yes | yes | yes | only from `createVerifier()` or `pinnedReceiptTrust()` |
| `/identity` | yes | yes | yes | only from factory |
| `/identity/adapters` | yes | yes | yes | no |
| `/identity/authoring` | yes | yes | yes | only from called factory |
| `/mcp` | yes | yes | yes | no; descriptors/models only |
| `/mcp/node` | yes | export error | export error | only from function call |
| `/github` | yes, trusted server runtime only | export error | export error | no eager I/O |
| `/protocol` | yes | yes | yes | no eager I/O |
| `/adapters` | yes | yes | yes | no |
| `/testkit` | yes | yes where relevant | yes where relevant | no production dependency |

Every subpath is side-effect-free on import. Node-specific filesystem imports occur only behind the `/mcp/node` export condition. `/github` is server-only in this cut because its control-plane Bearer token is a deployment credential; CORS is not treated as a credential boundary. A future browser entry point requires a separately qualified, short-lived user-bound authentication contract. Normal GitHub server callers perform bounded file reads themselves and pass copied bytes, making I/O and time-of-check/time-of-use ownership explicit.

The clean-consumer TypeScript floor is 5.2 with `ES2022` plus `ESNext.Disposable` library declarations. The tested Node floor is 20.6.0, including the explicit-resource-management symbols used by `AsyncDisposable`. A browser/worker is supported only when it exposes those symbols; explicit `close()` is an operational alternative to `await using`, not a way around the construction-time platform check. CI compiles at the minimum and current TypeScript versions and runs Node 20.6, 22, and the current active LTS.

The normative TypeScript declarations above contain 150 exported names across the eleven supported entry points, down from 203 across eight misleadingly broad entry points. The generated target inventory counts each declaration once; namespace members such as `mcp.model.string` and `conformance.custodySigner` are additionally signature-snapshotted so a small barrel count cannot hide unreviewed callable surface.

## 6. Exact proposed Python public surface

The declarations below describe the runtime API and installed typing surface. Implementations and `.pyi` files remain compatible with Python 3.9. Frozen dataclasses defensively copy byte/sequence inputs during validation. Capability-bearing/staged values (`Receipt`, identity stages, MCP tool/call/authority/plan/recovery, and GitHub candidate/recovery) use `init=False` or private native construction and reject direct construction, subclassing, copying, deep-copying, pickling, and forged state restoration. Plain input/result/error presentation dataclasses remain normally constructible unless stated otherwise.

### 6.1 `auths`

```python
from dataclasses import dataclass
from enum import Enum
from typing import Literal, NoReturn, Optional, Tuple, final

class EffectState(str, Enum):
    NOT_APPLIED = "not-applied"
    POSSIBLE = "possible"
    APPLIED = "applied"

class RetryClass(str, Enum):
    NEVER = "never"
    SAFE = "safe"
    CONDITIONAL = "conditional"
    UNKNOWN = "unknown"

class RecommendedAction(str, Enum):
    CORRECT_INPUT = "correct-input"
    CORRECT_CONFIGURATION = "correct-configuration"
    INSTALL_COMPATIBLE_RUNTIME = "install-compatible-runtime"
    RETRY_EXECUTION = "retry-execution"
    SATISFY_CONDITION = "satisfy-condition"
    RESUME_AND_RECONCILE = "resume-and-reconcile"
    INSPECT_RECEIPT = "inspect-receipt"
    CONTACT_SUPPORT = "contact-support"

class KnownAuthsErrorCode(str, Enum):
    # Generated from the same registry as the TypeScript literal union.
    CORE_INVALID_CONFIGURATION = "core.invalid-configuration"
    CORE_UNSUPPORTED_ABI = "core.unsupported-abi"
    CORE_UNSUPPORTED_SEMANTIC_SUBJECT = "core.unsupported-semantic-subject"
    CORE_MALFORMED_INPUT = "core.malformed-input"
    CORE_NATIVE_RUNTIME_UNAVAILABLE = "core.native-runtime-unavailable"
    CORE_FORGED_EXECUTION_REFERENCE = "core.forged-execution-reference"
    CORE_RUNTIME_CONFLICT = "core.runtime-conflict"
    CORE_RUNTIME_UNAVAILABLE = "core.runtime-unavailable"
    CORE_RUNTIME_CANCELLED = "core.runtime-cancelled"
    CORE_OUTCOME_UNKNOWN = "core.outcome-unknown"
    CORE_OBSERVATION_PENDING = "core.observation-pending"
    CORE_OBSERVATION_INCONCLUSIVE = "core.observation-inconclusive"
    CORE_WORKFLOW_TERMINAL = "core.workflow-terminal"
    CORE_INTERNAL_INVARIANT = "core.internal-invariant"
    CORE_AUTHORIZATION_DENIED = "core.authorization-denied"
    CORE_AUTHORIZATION_INDETERMINATE = "core.authorization-indeterminate"
    CORE_UNAUTHENTICATED_PRINCIPAL = "core.unauthenticated-principal"
    IDENTITY_PACKET_MALFORMED = "identity.packet-malformed"
    IDENTITY_METHOD_UNSUPPORTED = "identity.method-unsupported"
    IDENTITY_NOT_FOUND = "identity.not-found"
    IDENTITY_RESOLUTION_REJECTED = "identity.resolution-rejected"
    IDENTITY_RESOLUTION_INDETERMINATE = "identity.resolution-indeterminate"
    IDENTITY_EVIDENCE_EXPIRED = "identity.evidence-expired"
    IDENTITY_VALIDATION_REJECTED = "identity.validation-rejected"
    IDENTITY_VALIDATION_INDETERMINATE = "identity.validation-indeterminate"
    IDENTITY_RELATIONSHIP_DENIED = "identity.relationship-denied"
    IDENTITY_SIGNATURE_INVALID = "identity.signature-invalid"
    IDENTITY_AUTHENTICATION_INDETERMINATE = "identity.authentication-indeterminate"
    CORE_RECEIPT_MALFORMED = "core.receipt-malformed"
    CORE_RECEIPT_SIGNATURE_INVALID = "core.receipt-signature-invalid"
    CORE_RECEIPT_SIGNER_UNTRUSTED = "core.receipt-signer-untrusted"
    CORE_RECEIPT_PROFILE_DENIED = "core.receipt-profile-denied"
    CORE_RECEIPT_EXPIRED = "core.receipt-expired"
    CORE_RECEIPT_TRUST_INDETERMINATE = "core.receipt-trust-indeterminate"
    CORE_VERIFICATION_CAPACITY = "core.verification-capacity"
    REMOTE_AUTHENTICATION_FAILED = "remote.authentication-failed"
    REMOTE_RESPONSE_MALFORMED = "remote.response-malformed"
    REMOTE_TRANSPORT_UNAVAILABLE = "remote.transport-unavailable"
    REMOTE_TIMEOUT = "remote.timeout"
    MCP_INVALID_HANDLER_OUTPUT = "mcp.invalid-handler-output"
    MCP_HANDLER_FAILED = "mcp.handler-failed"
    MCP_HANDLER_TIMEOUT = "mcp.handler-timeout"
    MCP_CANCELLED_BEFORE_ENTRY = "mcp.cancelled-before-entry"
    MCP_RESERVATION_CONFLICT = "mcp.reservation-conflict"
    MCP_REPLAY = "mcp.replay"
    MCP_RECEIPT_PERSIST_FAILED = "mcp.receipt-persist-failed"
    MCP_RECONCILIATION_PENDING = "mcp.reconciliation-pending"
    MCP_RECEIPT_INVALID = "mcp.receipt-invalid"
    MCP_ADMISSION_CAPACITY = "mcp.admission-capacity"
    MCP_DELEGATION_CAPACITY = "mcp.delegation-capacity"
    MCP_RECOVERY_NOT_FOUND = "mcp.recovery-not-found"
    MCP_RECOVERY_KIND_MISMATCH = "mcp.recovery-kind-mismatch"
    PLAN_MEMBER_INTERRUPTED = "plan.member-interrupted"
    PLAN_MEMBER_FAILED_BEFORE_ENTRY = "plan.member-failed-before-entry"
    PLAN_RESUME_REFERENCE_INVALID = "plan.resume-reference-invalid"
    PLAN_RECONCILIATION_PENDING = "plan.reconciliation-pending"
    PLAN_ACTION_SUBSTITUTED = "plan.action-substituted"
    CUSTODY_DENIED = "custody.denied"
    CUSTODY_CANCELLED = "custody.cancelled"
    CUSTODY_THROTTLED = "custody.throttled"
    CUSTODY_UNAVAILABLE = "custody.unavailable"
    CUSTODY_REVOKED_KEY = "custody.revoked-key"
    CUSTODY_DISABLED_KEY = "custody.disabled-key"
    CUSTODY_PROVIDER_UNKNOWN = "custody.provider-unknown"
    CUSTODY_INVALID_PROVIDER_RESPONSE = "custody.invalid-provider-response"
    CUSTODY_REQUEST_MISMATCH = "custody.request-mismatch"
    CUSTODY_PRINCIPAL_MISMATCH = "custody.principal-mismatch"
    CUSTODY_DESCRIPTOR_MISMATCH = "custody.descriptor-mismatch"
    CUSTODY_KEY_VERSION_MISMATCH = "custody.key-version-mismatch"
    CUSTODY_TRANSACTION_MISMATCH = "custody.transaction-mismatch"
    CUSTODY_MALFORMED_SIGNATURE = "custody.malformed-signature"
    CUSTODY_NON_CANONICAL_SIGNATURE = "custody.non-canonical-signature"
    CUSTODY_SIGNATURE_VERIFICATION_FAILED = "custody.signature-verification-failed"
    CUSTODY_EVIDENCE_MISMATCH = "custody.evidence-mismatch"
    CUSTODY_LIFECYCLE_NOT_PERMITTED = "custody.lifecycle-not-permitted"
    GITHUB_BOUNDARY_INVALID = "github.boundary-invalid"
    GITHUB_ATTENUATION_DENIED = "github.attenuation-denied"
    GITHUB_DELEGATION_OUTCOME_UNKNOWN = "github.delegation-outcome-unknown"
    GITHUB_WORKFLOW_PROOF_INVALID = "github.workflow-proof-invalid"
    GITHUB_WORKFLOW_EXPIRED = "github.workflow-expired"
    GITHUB_WORKFLOW_CANCELLED = "github.workflow-cancelled"
    GITHUB_EXECUTOR_AUDIENCE_MISMATCH = "github.executor-audience-mismatch"
    GITHUB_REPOSITORY_MISMATCH = "github.repository-mismatch"
    GITHUB_REPOSITORY_RENAMED_OR_TRANSFERRED = "github.repository-renamed-or-transferred"
    GITHUB_ISSUE_MISMATCH = "github.issue-mismatch"
    GITHUB_ISSUE_NOT_OPEN = "github.issue-not-open"
    GITHUB_BASE_REVISION_MISMATCH = "github.base-revision-mismatch"
    GITHUB_BRANCH_ALREADY_EXISTS = "github.branch-already-exists"
    GITHUB_PULL_REQUEST_ALREADY_EXISTS = "github.pull-request-already-exists"
    GITHUB_CANDIDATE_BUNDLE_MALFORMED = "github.candidate-bundle-malformed"
    GITHUB_CANDIDATE_LIMIT_EXCEEDED = "github.candidate-limit-exceeded"
    GITHUB_CANDIDATE_NOT_DESCENDANT = "github.candidate-not-descendant"
    GITHUB_MERGE_COMMIT_DENIED = "github.merge-commit-denied"
    GITHUB_UNSUPPORTED_GIT_OBJECT = "github.unsupported-git-object"
    GITHUB_PATH_NOT_ALLOWED = "github.path-not-allowed"
    GITHUB_PATH_EXPLICITLY_DENIED = "github.path-explicitly-denied"
    GITHUB_FILE_MODE_DENIED = "github.file-mode-denied"
    GITHUB_REPOSITORY_AUTOMATION_POLICY_MISMATCH = "github.repository-automation-policy-mismatch"
    GITHUB_BRANCH_BUDGET_EXHAUSTED = "github.branch-budget-exhausted"
    GITHUB_PULL_REQUEST_BUDGET_EXHAUSTED = "github.pull-request-budget-exhausted"
    GITHUB_EVIDENCE_MISSING = "github.evidence-missing"
    GITHUB_EVIDENCE_STALE = "github.evidence-stale"
    GITHUB_VERIFIER_CONFIGURATION_MISMATCH = "github.verifier-configuration-mismatch"
    GITHUB_EXACT_ACTION_MISMATCH = "github.exact-action-mismatch"
    GITHUB_CANDIDATE_SUBSTITUTED = "github.candidate-substituted"
    GITHUB_CREDENTIAL_BOUNDARY_FAILED = "github.credential-boundary-failed"
    GITHUB_BRANCH_REJECTED = "github.branch-rejected"
    GITHUB_PULL_REQUEST_REJECTED = "github.pull-request-rejected"
    GITHUB_DELEGATION_CAPACITY = "github.delegation-capacity"
    GITHUB_EXECUTION_CAPACITY = "github.execution-capacity"
    GITHUB_BRANCH_OUTCOME_UNKNOWN = "github.branch-outcome-unknown"
    GITHUB_PULL_REQUEST_OUTCOME_UNKNOWN = "github.pull-request-outcome-unknown"
    GITHUB_WORKFLOW_TERMINAL_APPLIED = "github.workflow-terminal-applied"
    GITHUB_WORKFLOW_TERMINAL_NOT_APPLIED = "github.workflow-terminal-not-applied"
    GITHUB_RECEIPT_INVALID = "github.receipt-invalid"

    def __str__(self) -> str: ...

ErrorFamily = Literal[
    "configuration", "input", "runtime", "profile",
    "provider", "state", "internal",
]
CauseCategory = Literal[
    "cancelled", "conflict", "corrupt-state", "invalid-response",
    "limit-exceeded", "timeout", "unavailable", "unknown",
]

@dataclass(frozen=True)
class EnteredBoundaries:
    approval: bool
    signer: bool
    state: bool
    credential: bool
    provider: bool

@dataclass(frozen=True)
class ErrorInfo:
    schema: Literal["auths.error/1"]
    code: KnownAuthsErrorCode
    family: ErrorFamily
    operation: str
    stage: str
    summary: str
    correlation_id: str
    effect: EffectState
    retry: RetryClass
    recommended_action: RecommendedAction
    entered_boundaries: EnteredBoundaries
    execution_reference: Optional[str]
    decision_reference: Optional[str]
    receipt_reference: Optional[str]
    causes: Tuple[CauseCategory, ...]

@final
class AuthsError(Exception):
    def __new__(cls, _private: NoReturn, /) -> "AuthsError": ...
    def __init__(self, _private: NoReturn, /) -> None: ...
    info: ErrorInfo

    @property
    def code(self) -> KnownAuthsErrorCode: ...
    @property
    def effect(self) -> EffectState: ...
    @property
    def retry(self) -> RetryClass: ...

@final
class Receipt:
    """Opaque portable receipt. No public constructor; repr is redacted."""
    def __new__(cls, _private: NoReturn, /) -> "Receipt": ...
    @property
    def id(self) -> str: ...
    def to_bytes(self) -> bytes: ...

@dataclass(frozen=True)
class RuntimeInfo:
    sdk_version: str
    python_version: str
    platform: str
    native_abi: int
    identity_abi: int
    error_registry_digest: str
    compatible: bool
    semantic_subjects: Tuple[str, ...]
    profiles: Tuple[str, ...]
    capabilities: Tuple[str, ...]
    warnings: Tuple[str, ...]

def runtime_info() -> RuntimeInfo: ...
```

`AuthsError` cannot be constructed with arbitrary effect/retry combinations; public construction is only through validated native or authenticated-protocol envelopes. `ErrorInfo` is the same host projection described in section 5.1 and is not a serializable `auths.error/1` mapping. An unregistered code is a protocol/registry incompatibility handled by the fail-closed negotiation rule above, not a valid `ErrorInfo`. The runtime implementation of `KnownAuthsErrorCode.__str__` returns `self.value` exactly on every supported Python version, so interpolation, logging, equality, and JSON adapters use the registered string rather than `KnownAuthsErrorCode.MEMBER`; the stub body remains `...`.

### 6.2 `auths.verify`

```python
from dataclasses import dataclass
from typing import Iterable, Literal, NoReturn, Optional, Tuple, Union, final
from auths import ErrorInfo, Receipt

VerificationStage = Literal[
    "decode", "resolve", "principal-control", "authority", "complete"
]
VerificationKind = Literal["authorized", "denied", "indeterminate"]

@dataclass(frozen=True, init=False)
class VerificationInput:
    proof: bytes
    action: bytes
    trusted_context: bytes

    def __init__(
        self, *, proof: bytes, action: bytes, trusted_context: bytes,
    ) -> None: ...

@dataclass(frozen=True)
class VerificationMetrics:
    proof_bytes: int
    action_bytes: int
    context_bytes: int
    object_count: int
    plan_leaves: int
    plan_depth: int
    work_units: int

@dataclass(frozen=True)
class AuthorizedVerification:
    kind: Literal["authorized"]
    code: str
    stage: VerificationStage
    correlation_id: str
    metrics: VerificationMetrics
    required_configuration: Optional[bytes]
    executed_configuration: bytes
    decision_bytes: bytes

@dataclass(frozen=True)
class UnsuccessfulVerification:
    kind: Literal["denied", "indeterminate"]
    code: str
    stage: VerificationStage
    correlation_id: str
    metrics: VerificationMetrics
    required_configuration: Optional[bytes]
    executed_configuration: bytes
    decision_bytes: bytes
    issue: ErrorInfo

VerificationResult = Union[
    AuthorizedVerification, UnsuccessfulVerification,
]

@dataclass(frozen=True)
class ApprovalInspection:
    policy_id: str
    evaluator_version: str
    decision: Literal["approved", "rejected"]
    commitment: bytes

@dataclass(frozen=True)
class VerificationInspection:
    kind: VerificationKind
    code: str
    stage: VerificationStage
    result_commitment: bytes
    action_commitment: Optional[bytes]
    required_configuration_commitment: Optional[bytes]
    executed_configuration_commitment: bytes
    metrics: VerificationMetrics
    approval: Optional[ApprovalInspection]

@dataclass(frozen=True)
class ReceiptSignerInfo:
    principal: str
    verification_method: str
    suite: str

ReceiptSignerRole = Literal["decision", "execution"]

@dataclass(frozen=True)
class ReceiptProfile:
    id: str
    version: int

@dataclass(frozen=True)
class ReceiptTrustAnchor:
    role: ReceiptSignerRole
    principal: str
    verification_method: str
    suite: Literal["ed25519-v1", "p256-sha256-v1"]
    public_key: bytes

@final
class ReceiptTrustPolicy:
    """Sealed, copied trust input; no public constructor."""
    def __new__(cls, _private: NoReturn, /) -> "ReceiptTrustPolicy": ...
    @property
    def allowed_profiles(self) -> Tuple[ReceiptProfile, ...]: ...
    @property
    def anchor_count(self) -> int: ...

def pinned_receipt_trust(
    *, anchors: Iterable[ReceiptTrustAnchor],
    allowed_profiles: Iterable[ReceiptProfile],
    verification_time_unix_seconds: Optional[int] = None,
    maximum_receipt_age_seconds: Optional[int] = None,
) -> ReceiptTrustPolicy: ...

@dataclass(frozen=True)
class DecisionReceiptDetails:
    kind: Literal["decision"]
    receipt_id: str
    profile_id: str
    profile_version: int
    decision: Literal["authorized", "denied", "indeterminate"]
    reasons: Tuple[str, ...]
    decided_at_unix_seconds: int
    decision_signer: ReceiptSignerInfo
    proof_commitment: str
    action_commitment: str
    context_commitment: str
    principal_status_commitment: str
    grant_status_commitment: str
    profile_payload_commitment: str

@dataclass(frozen=True)
class ExecutionReceiptDetails:
    kind: Literal["execution"]
    decision_receipt_id: str
    execution_receipt_id: str
    profile_id: str
    profile_version: int
    decision: Literal["authorized", "denied", "indeterminate"]
    outcome: Literal["succeeded", "failed", "indeterminate"]
    reasons: Tuple[str, ...]
    decided_at_unix_seconds: int
    completed_at_unix_seconds: int
    decision_signer: ReceiptSignerInfo
    execution_signer: ReceiptSignerInfo
    proof_commitment: str
    action_commitment: str
    context_commitment: str
    principal_status_commitment: str
    grant_status_commitment: str
    execution_lease_commitment: str
    command_commitment: str
    result_commitment: Optional[str]
    profile_payload_commitment: str

ReceiptEnvelopeDetails = Union[
    DecisionReceiptDetails, ExecutionReceiptDetails,
]

@final
@dataclass(frozen=True, init=False)
class VerifiedReceipt:
    def __init__(self, _private: NoReturn, /) -> None: ...
    kind: Literal["verified"]
    receipt: Receipt
    details: ReceiptEnvelopeDetails

@dataclass(frozen=True)
class RejectedReceipt:
    kind: Literal["rejected"]
    issue: ErrorInfo

@dataclass(frozen=True)
class IndeterminateReceipt:
    kind: Literal["indeterminate"]
    issue: ErrorInfo

ReceiptVerification = Union[
    VerifiedReceipt, RejectedReceipt, IndeterminateReceipt,
]

def verify(value: VerificationInput, /) -> VerificationResult: ...
def verify_many(
    values: Iterable[VerificationInput], /
) -> Tuple[VerificationResult, ...]: ...
def inspect(value: VerificationResult, /) -> VerificationInspection: ...
def verify_receipt(
    receipt: Union[Receipt, bytes], /, *,
    trust: ReceiptTrustPolicy,
    linked_decision_receipt: Optional[Union[Receipt, bytes]] = None,
) -> ReceiptVerification: ...
```

`VerificationResult` is a true union: `AuthorizedVerification` has no `issue`, while `UnsuccessfulVerification` always has one and retains the exact `denied | indeterminate` tag. Receipt verification uses the exact decision-only versus linked-execution rules above. A decision receipt forbids the linked argument. An execution receipt requires the complete linked decision receipt bytes; the verifier checks its ID, profile, commitments, signer trust, and signature before the execution signature. Supplying no link, the wrong link, or a link to another workflow is `RejectedReceipt`/`rejected`, never an ID-only trust assertion. Receipt-carried keys never establish trust. Definite invalidity is rejected; unavailable suite/status material is indeterminate. `VerifiedReceipt` is native-created and sealed (`init=False`, final, non-pickleable), so a profile inspector cannot accept an object assembled from copied display fields. Native ABI/runtime corruption raises `AuthsError`. Shared details expose the applicable verified envelope and payload commitment; the canonical profile payload stays private inside the sealed result for the owning profile inspector. There is no `VerifiedAction` or receipt decode that turns unverified bytes into a trusted `Receipt`.

### 6.3 `auths.identity`

```python
from dataclasses import dataclass
from datetime import timedelta
from typing import (
    Generic, Literal, NoReturn, Optional, Tuple, TypeVar, Union, final,
)
from auths import ErrorInfo

IdentityT = TypeVar("IdentityT")

@dataclass(frozen=True)
class IdentityOk(Generic[IdentityT]):
    kind: Literal["ok"]
    value: IdentityT

@dataclass(frozen=True)
class IdentityRejected:
    kind: Literal["rejected"]
    issue: ErrorInfo

@dataclass(frozen=True)
class IdentityIndeterminate:
    kind: Literal["indeterminate"]
    issue: ErrorInfo

IdentityResult = Union[
    IdentityOk[IdentityT], IdentityRejected, IdentityIndeterminate,
]

@final
@dataclass(frozen=True, init=False)
class DecodedIdentity:
    def __init__(self, _private: NoReturn, /) -> None: ...
    method_id: str
    identity_id: str
    method_material: bytes
    relationships: Tuple[str, ...]
    def to_bytes(self) -> bytes: ...
    async def resolve(
        self, client: "IdentityClient", *,
        timeout: timedelta = timedelta(seconds=10),
    ) -> IdentityResult["ResolvedIdentity"]: ...

@final
@dataclass(frozen=True, init=False)
class ResolvedIdentity:
    def __init__(self, _private: NoReturn, /) -> None: ...
    method_id: str
    identity_id: str
    evidence_source: str
    observed_at_unix_seconds: int
    expires_at_unix_seconds: int
    provenance: Tuple[str, ...]
    async def validate(
        self, client: "IdentityClient", *,
        timeout: timedelta = timedelta(seconds=10),
    ) -> IdentityResult["ValidatedIdentity"]: ...

@final
@dataclass(frozen=True, init=False)
class ValidatedIdentity:
    def __init__(self, _private: NoReturn, /) -> None: ...
    method_id: str
    identity_id: str
    relationships: Tuple[str, ...]
    def to_bytes(self) -> bytes: ...
    async def authenticate(
        self, client: "IdentityClient", *,
        message: bytes,
        signature: bytes,
        relationship_id: str = "default-signing",
        timeout: timedelta = timedelta(seconds=10),
    ) -> IdentityResult["AuthenticatedIdentityMessage"]: ...

@final
@dataclass(frozen=True, init=False)
class AuthenticatedIdentityMessage:
    def __init__(self, _private: NoReturn, /) -> None: ...
    identity: ValidatedIdentity
    relationship_id: str
    message: bytes

@final
class IdentityClient:
    def __new__(cls, _private: NoReturn, /) -> "IdentityClient": ...
    def decode(self, packet: bytes, /) -> IdentityResult[DecodedIdentity]: ...
    async def resolve(
        self, identity: DecodedIdentity, /, *,
        timeout: timedelta = timedelta(seconds=10),
    ) -> IdentityResult[ResolvedIdentity]: ...
    async def validate(
        self, identity: ResolvedIdentity, /, *,
        timeout: timedelta = timedelta(seconds=10),
    ) -> IdentityResult[ValidatedIdentity]: ...
    async def authenticate(
        self, identity: ValidatedIdentity, /, *,
        relationship_id: str = "default-signing",
        message: bytes,
        signature: bytes,
        timeout: timedelta = timedelta(seconds=10),
    ) -> IdentityResult[AuthenticatedIdentityMessage]: ...
    async def authenticate_message(
        self, identity_packet: bytes, /, *,
        relationship_id: str = "default-signing",
        message: bytes,
        signature: bytes,
        timeout: timedelta = timedelta(seconds=10),
    ) -> IdentityResult[AuthenticatedIdentityMessage]: ...
    async def aclose(self) -> None: ...
    async def __aenter__(self) -> "IdentityClient": ...
    async def __aexit__(self, *exc: object) -> None: ...

def raw_key_ed25519() -> IdentityClient: ...

async def authenticate_message(
    identity_packet: bytes, /, *,
    message: bytes,
    signature: bytes,
    client: Optional[IdentityClient] = None,
    relationship_id: str = "default-signing",
    timeout: timedelta = timedelta(seconds=10),
) -> IdentityResult[AuthenticatedIdentityMessage]: ...
```

The module shortcut defaults to the built-in raw-key Ed25519 client. With `client=None`, it constructs, enters, and closes exactly one owned built-in client in `finally`, including on cancellation and every negative/error path. An explicit client is borrowed, must already be entered, and is never closed by the shortcut. Malformed/untrusted input, forbidden relationships, expiry, and bad signatures return `IdentityRejected`; unavailable or inconclusive trust material returns `IdentityIndeterminate`. Custom identity methods require an explicit client from `auths.identity.adapters`; there is no ambient mutable global registry.

### 6.4 `auths.identity.adapters`

```python
from dataclasses import dataclass
from typing import Generic, Literal, Protocol, Sequence, Tuple, TypeVar, Union
from auths.identity import IdentityClient

@dataclass(frozen=True)
class VerificationMaterial:
    material_id: str
    bytes: bytes

@dataclass(frozen=True)
class VerificationRelationship:
    relationship_id: str
    purpose: str
    suite_id: str
    verification_material: Tuple[VerificationMaterial, ...]

@dataclass(frozen=True)
class DecodedIdentityRecord:
    method_id: str
    identity_id: str
    method_material: bytes
    relationships: Tuple[VerificationRelationship, ...]

@dataclass(frozen=True)
class ResolutionEvidence:
    source: str
    observed_at_unix_seconds: int
    expires_at_unix_seconds: int
    provenance: Tuple[str, ...]
    history: Tuple[str, ...] = ()

@dataclass(frozen=True)
class ResolvedIdentityRecord:
    method_id: str
    identity_id: str
    method_material: bytes
    relationships: Tuple[VerificationRelationship, ...]
    evidence: ResolutionEvidence

AdapterT = TypeVar("AdapterT")
AdapterRejection = Literal[
    "not-found", "malformed", "not-permitted", "expired",
    "invalid-signature",
]
AdapterUncertainty = Literal[
    "cancelled", "timeout", "unavailable", "invalid-response",
]

@dataclass(frozen=True)
class AdapterOk(Generic[AdapterT]):
    kind: Literal["ok"]
    value: AdapterT

@dataclass(frozen=True)
class AdapterRejected:
    kind: Literal["rejected"]
    reason: AdapterRejection

@dataclass(frozen=True)
class AdapterIndeterminate:
    kind: Literal["indeterminate"]
    reason: AdapterUncertainty

AdapterResult = Union[AdapterOk[AdapterT], AdapterRejected, AdapterIndeterminate]

class IdentityResolver(Protocol):
    async def resolve(
        self, descriptor: DecodedIdentityRecord, /, *, maximum_bytes: int
    ) -> AdapterResult[ResolvedIdentityRecord]: ...
    async def aclose(self) -> None: ...

class IdentityMethod(Protocol):
    method_id: str
    version: int
    async def resolve(
        self, descriptor: DecodedIdentityRecord
    ) -> AdapterResult[ResolvedIdentityRecord]: ...
    async def validate(
        self, record: ResolvedIdentityRecord
    ) -> AdapterResult[None]: ...
    async def aclose(self) -> None: ...

class MessageAuthenticator(Protocol):
    suite_id: str
    version: int
    async def verify(
        self, *,
        relationship: VerificationRelationship,
        preimage: bytes,
        signature: bytes,
    ) -> AdapterResult[None]: ...
    async def aclose(self) -> None: ...

def create_client(
    *,
    methods: Sequence[IdentityMethod],
    authenticators: Sequence[MessageAuthenticator],
    owns_adapters: bool = False,
) -> IdentityClient: ...

def resolver_method(
    *, method_id: str, version: int,
    resolver: IdentityResolver, maximum_bytes: int = 131_072,
    owns_resolver: bool = False,
) -> IdentityMethod: ...
```

Adapters are borrowed by default; the two ownership flags transfer single-consumer close responsibility. Rust creates `DecodedIdentityRecord` from the bounded canonical packet and passes defensive copies to the selected resolver/method. Resolver output must preserve method/identity IDs, and native code rechecks method material, relationships/materials, duplicates, bounds, and canonicalizability before sealing. The client privately retains that full `ResolvedIdentityRecord` and passes it to `IdentityMethod.validate`; authentication selects the retained relationship, computes the preimage natively, and gives that complete relationship to the authenticator. No adapter reparses packets, accepts caller-selected verification material, or needs side state. `MessageAuthenticator.suite_id` is exactly the wire relationship `suite_id`, matched byte-for-byte. Arbitrary adapter exceptions map to `AdapterIndeterminate("unavailable")`, task cancellation to `"cancelled"`, and malformed/oversized or stage-inapplicable adapter output to `"invalid-response"`. Resolve may use every declared rejection, validate may use `malformed | not-permitted | expired | invalid-signature`, and message authentication may use only `malformed | not-permitted | invalid-signature`. Only an allowed explicit `AdapterRejected` becomes authentication rejection.

### 6.5 `auths.identity.authoring`

```python
from dataclasses import dataclass
from typing import NoReturn, Sequence, final
from auths.identity import ValidatedIdentity
from auths.identity.adapters import VerificationRelationship

@final
@dataclass(frozen=True, init=False)
class PreparedIdentityMessage:
    def __init__(self, _private: NoReturn, /) -> None: ...
    identity: ValidatedIdentity
    relationship_id: str
    message: bytes
    signing_preimage: bytes

def create_raw_key_ed25519_identity(
    public_key: bytes, /
) -> ValidatedIdentity: ...

def encode_identity(
    *, method_id: str, identity_id: str,
    relationships: Sequence[VerificationRelationship],
    method_material: bytes = b"",
) -> bytes: ...

def prepare_identity_message(
    identity: ValidatedIdentity, /, *,
    message: bytes,
    relationship_id: str = "default-signing",
) -> PreparedIdentityMessage: ...
```

The prepared value is sealed in the implementation despite its readable frozen projection. `dataclasses.replace`, pickling, and direct construction cannot produce an accepted authoring token. Authentication consumes the original identity packet, message, and detached signature; no unused signed-packet encoding is exposed.

### 6.6 `auths.mcp`

```python
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import (
    Any, AsyncIterator, Generic, Literal, NoReturn, Optional, Protocol,
    Sequence, Tuple, Type, TypeVar, Union, final,
)
from auths import ErrorInfo, Receipt
from auths.adapters.custody import CustodyKind, CustodyLifecycle, CustodySigner
from auths.adapters.reservations import ReservationStore
from auths.verify import VerifiedReceipt

ArgumentsT = TypeVar("ArgumentsT")
ResultT = TypeVar("ResultT")

@final
class Tool(Generic[ArgumentsT, ResultT]):
    def __new__(cls, _private: NoReturn, /) -> "Tool[ArgumentsT, ResultT]": ...
    @property
    def name(self) -> str: ...
    @property
    def service(self) -> str: ...
    def call(self, arguments: ArgumentsT, /) -> "Call[ArgumentsT, ResultT]": ...

@final
class Call(Generic[ArgumentsT, ResultT]):
    def __new__(cls, _private: NoReturn, /) -> "Call[ArgumentsT, ResultT]": ...
    @property
    def tool(self) -> Tool[ArgumentsT, ResultT]: ...

@final
class Authority:
    def __new__(cls, _private: NoReturn, /) -> "Authority": ...
    @property
    def service(self) -> str: ...
    @property
    def allowed_tools(self) -> Tuple[str, ...]: ...

@final
class Plan:
    def __new__(cls, _private: NoReturn, /) -> "Plan": ...
    @property
    def service(self) -> str: ...
    @property
    def length(self) -> int: ...

@dataclass(frozen=True)
class InvocationContext:
    execution_id: str
    provider_idempotency_key: str
    service: str
    tool: str

@dataclass(frozen=True)
class Invocation(Generic[ArgumentsT]):
    arguments: ArgumentsT
    context: InvocationContext

ProviderUncertainty = Literal[
    "cancelled", "invalid-output", "limit-exceeded",
    "timeout", "unavailable", "unknown",
]
@dataclass(frozen=True)
@final
class Applied(Generic[ResultT]):
    value: ResultT

@dataclass(frozen=True)
@final
class Possible:
    cause: ProviderUncertainty

ProviderOutcome = Union[Applied[ResultT], Possible]

class Handler(Protocol, Generic[ArgumentsT, ResultT]):
    async def __call__(
        self, invocation: Invocation[ArgumentsT]
    ) -> ProviderOutcome[ResultT]: ...

@final
class HandlerBinding:
    def __new__(cls, _private: NoReturn, /) -> "HandlerBinding": ...
    @property
    def tool_name(self) -> str: ...

def bind(
    tool: Tool[ArgumentsT, ResultT],
    handler: Handler[ArgumentsT, ResultT],
) -> HandlerBinding: ...

@dataclass(frozen=True)
class ProviderAttempt:
    session_contract: Literal["auths.mcp-session/2"]
    execution_id: str
    attempt_ordinal: int
    request_commitment: bytes
    provider_idempotency_key: str
    entered_at_unix_seconds: int

EvidenceT = TypeVar("EvidenceT")

@dataclass(frozen=True)
class Observation(Generic[EvidenceT]):
    observer_id: str
    source_id: str
    execution_id: str
    request_commitment: bytes
    observed_at_unix_seconds: int
    fresh_until_unix_seconds: int
    evidence: EvidenceT

@dataclass(frozen=True)
@final
class ObservedApplied(Generic[ResultT]):
    value: ResultT
    observation: Observation[Any]

@dataclass(frozen=True)
@final
class Inconclusive:
    cause: ProviderUncertainty
    observation: Optional[Observation[Any]] = None

ReconciliationOutcome = Union[
    ObservedApplied[ResultT], Inconclusive,
]

class Reconciler(Protocol, Generic[ArgumentsT, ResultT]):
    async def __call__(
        self, invocation: Invocation[ArgumentsT], attempt: ProviderAttempt,
    ) -> ReconciliationOutcome[ResultT]: ...

@final
class ReconcilerBinding:
    def __new__(cls, _private: NoReturn, /) -> "ReconcilerBinding": ...
    @property
    def tool_name(self) -> str: ...

def observe(
    tool: Tool[ArgumentsT, ResultT],
    reconciler: Reconciler[ArgumentsT, ResultT],
) -> ReconcilerBinding: ...

ExecutionStage = Literal[
    "verification-started", "verification-completed", "decision-persisted",
    "reserved", "exact-action-claimed", "credential-issued",
    "provider-entry-recorded", "provider-call-started",
    "provider-call-returned", "outcome-unknown-persisted", "reconciling",
    "reconciliation-observed", "reconciliation-persisted",
    "receipt-persisted", "terminal-persisted",
]
ExecutionOutcomeKind = Literal[
    "completed", "denied", "indeterminate", "conflict",
    "recovery-required", "failed",
]

@dataclass(frozen=True)
class ExecutionEvent:
    stage: ExecutionStage
    correlation_id: str
    execution_id: Optional[str]
    timestamp_unix_ms: int
    outcome_kind: Optional[ExecutionOutcomeKind] = None
    dropped_before: int = 0

@final
class RecoveryReference(Generic[ResultT]):
    def __new__(
        cls, _private: NoReturn, /
    ) -> "RecoveryReference[ResultT]": ...
    @classmethod
    def from_bytes(cls, data: bytes) -> "RecoveryReference[Any]": ...
    def to_bytes(self) -> bytes: ...

@final
class PlanRecoveryReference:
    def __new__(cls, _private: NoReturn, /) -> "PlanRecoveryReference": ...
    @classmethod
    def from_bytes(cls, data: bytes) -> "PlanRecoveryReference": ...
    def to_bytes(self) -> bytes: ...

@dataclass(frozen=True)
class Completed(Generic[ResultT]):
    kind: Literal["completed"]
    completion: Literal["executed", "replayed", "reconciled"]
    execution_id: str
    value: ResultT
    decision_receipt: Receipt
    execution_receipt: Receipt

@dataclass(frozen=True)
class Denied:
    kind: Literal["denied"]
    issue: ErrorInfo

@dataclass(frozen=True)
class Indeterminate:
    kind: Literal["indeterminate"]
    issue: ErrorInfo

@dataclass(frozen=True)
class Conflict:
    kind: Literal["conflict"]
    execution_id: str
    issue: ErrorInfo

@dataclass(frozen=True)
class RecoveryRequired(Generic[ResultT]):
    kind: Literal["recovery-required"]
    execution_id: str
    issue: ErrorInfo
    recovery: RecoveryReference[ResultT]

@dataclass(frozen=True)
class PlanRecoveryRequired:
    kind: Literal["recovery-required"]
    execution_id: str
    issue: ErrorInfo
    recovery: PlanRecoveryReference

@dataclass(frozen=True)
class Failed:
    kind: Literal["failed"]
    execution_id: str
    issue: ErrorInfo
    decision_receipt: Receipt
    execution_receipt: Receipt

ActionOutcome = Union[
    Completed[ResultT], Denied, Indeterminate, Conflict,
    RecoveryRequired[ResultT], Failed,
]

@dataclass(frozen=True)
class PlanCompleted:
    kind: Literal["completed"]
    members: Tuple[Completed[object], ...]

@dataclass(frozen=True)
class PlanStopped:
    kind: Literal["stopped"]
    completed_members: Tuple[Completed[object], ...]
    stopped_at: int
    outcome: Union[
        Denied, Indeterminate, Conflict, PlanRecoveryRequired, Failed,
    ]

PlanOutcome = Union[PlanCompleted, PlanStopped]

@dataclass(frozen=True)
class DelegatedSession:
    kind: Literal["delegated"]
    session: "DevelopmentSession"

@dataclass(frozen=True)
class DelegationRejected:
    kind: Literal["denied", "indeterminate", "conflict"]
    issue: ErrorInfo

DelegationResult = Union[DelegatedSession, DelegationRejected]

@dataclass(frozen=True)
class SessionDiagnostics:
    mode: Literal["development"]
    state_durability: Literal["single-machine-development"]
    service: str
    profile: Literal["auths.mcp/2"]
    session_contract: Literal["auths.mcp-session/2"]
    authority_tools: Tuple[str, ...]
    provider_runtime_owned: Literal[True]
    handlers_owned: Literal[False]
    reconcilers_owned: Literal[False]
    custody_kind: CustodyKind
    custody_lifecycle: CustodyLifecycle
    custody_owned: bool
    reservation_kind: str
    reservation_durability: Literal[
        "ephemeral", "single-machine-durable",
    ]
    reservation_owned: bool
    outstanding_borrowed_callbacks: int
    warnings: Tuple[str, ...]

@final
class DevelopmentSession:
    def __new__(cls, _private: NoReturn, /) -> "DevelopmentSession": ...
    @property
    def session_contract(self) -> Literal["auths.mcp-session/2"]: ...
    @property
    def principal(self) -> str: ...
    @property
    def authority(self) -> Authority: ...

    async def execute(
        self, call: Call[ArgumentsT, ResultT], /, *,
        idempotency_key: str,
    ) -> ActionOutcome[ResultT]: ...
    async def execute_plan(
        self, plan: Plan, /, *, idempotency_key: str,
    ) -> PlanOutcome: ...
    async def recover(
        self, recovery: RecoveryReference[ResultT], /
    ) -> ActionOutcome[ResultT]: ...
    async def recover_plan(
        self, recovery: PlanRecoveryReference, /
    ) -> PlanOutcome: ...
    async def recover_action_by_idempotency_key(
        self, idempotency_key: str, /
    ) -> ActionOutcome[Any]: ...
    async def recover_plan_by_idempotency_key(
        self, idempotency_key: str, /
    ) -> Union[PlanOutcome, Indeterminate]: ...
    async def delegate(
        self, *, allow: Sequence[Tool[Any, Any]],
        idempotency_key: str,
        name: str = "delegated-agent",
        expires_in: timedelta = timedelta(minutes=5),
    ) -> DelegationResult: ...
    def diagnostics(self) -> SessionDiagnostics: ...
    async def aclose(self) -> None: ...
    async def __aenter__(self) -> "DevelopmentSession": ...
    async def __aexit__(self, *exc: object) -> None: ...
    def events(self) -> AsyncIterator[ExecutionEvent]: ...

@final
class Profile:
    def __init__(self, *, service: str) -> None: ...
    @property
    def id(self) -> Literal["auths.mcp/2"]: ...
    def tool(
        self, name: str, *,
        arguments: Type[ArgumentsT],
        result: Type[ResultT],
    ) -> Tool[ArgumentsT, ResultT]: ...
    def plan(self, *calls: Call[Any, Any]) -> Plan: ...
    def development(
        self, *,
        allow: Sequence[Tool[Any, Any]],
        handlers: Sequence[HandlerBinding],
        reconcilers: Sequence[ReconcilerBinding],
        state_directory: Path,
        timeout: timedelta = timedelta(seconds=30),
        custody_signer: Optional[CustodySigner] = None,
        owns_custody_signer: bool = False,
        reservation_store: Optional[ReservationStore] = None,
        owns_reservation_store: bool = False,
    ) -> DevelopmentSession: ...

@dataclass(frozen=True)
class McpReceiptDetails:
    profile: Literal["auths.mcp/2"]
    service: str
    tool: str
    action_commitment: str
    result_commitment: Optional[str]
    provider_entered: bool
    completion: Literal["executed", "replayed", "reconciled"]

@dataclass(frozen=True)
class ReceiptInspected:
    kind: Literal["inspected"]
    details: McpReceiptDetails

@dataclass(frozen=True)
class ReceiptRejected:
    kind: Literal["rejected"]
    issue: ErrorInfo

ReceiptInspection = Union[ReceiptInspected, ReceiptRejected]

def inspect_receipt(receipt: VerifiedReceipt, /) -> ReceiptInspection: ...
```

`Profile.tool` accepts only a generated `@dataclass(frozen=True)` object-root model class. It rejects a custom metaclass, `__new__`, `__init__`, `__post_init__`, `__getattribute__`, `__getattr__`, `__setattr__`, property/descriptor field, serialization/reduction hook, or dataclass inheritance. This closes both authoring and replay: after Rust validates persisted canonical fields, native replay allocates with `object.__new__` and assigns the declared frozen fields with `object.__setattr__`; it invokes no application constructor, descriptor, getter, post-init, decoder, or serializer. The closed recursive annotation grammar is: `None`, `bool`, `str`, safe-range `int`, finite `float`, `Literal[None | bool | str | safe-int, ...]`, `Optional[T]` (encoded as JSON null, never omission), `Tuple[T, ...]`, and another accepted frozen dataclass. A `Literal` contains 1–64 unique canonical alternatives; duplicates and float literals are unsupported in both SDKs. Field names follow the shared 1–64-byte ASCII identifier grammar in the v2 table and exclude Python keywords; aliases are forbidden. `bool` is never accepted as `int`; `int` must fit JavaScript's exact safe-integer range; NaN and infinities are rejected. `list`, mutable/set/mapping types, fixed heterogeneous tuples, `bytes`, `Decimal`, date/time types, bare `object`/`Any`, arbitrary `Union`, protocols, enums, recursive cycles, variadic field names, and dataclass inheritance are rejected. Every canonical object field is present. An `Optional[T]` field may default to `None` as constructor convenience and still encodes an explicit null; all other defaults/default factories and undeclared input fields are rejected. Postponed annotations are resolved with `typing.get_type_hints` at `Profile.tool`; unresolved/unsupported annotations fail before I/O. `Tool.call` copies and validates immediately. Result decoding validates the same model grammar before `Applied` crosses the provider boundary. Rust owns the canonical JSON projection, and the TS model DSL represents the same grammar and bounds.

`Profile.development()` returns a normal `DevelopmentSession`, not an awaitable. It always requires an explicit secret-bearing `state_directory` and one reconciler for every allowed tool; there is no effectful in-memory variant. Opening occurs in `async with`; using it before `__aenter__` raises a stable pre-effect error. The session owns its internal provider wrapper; application handlers/reconcilers are borrowed. A handler can return only `Applied` or `Possible`; all exceptions, timeouts, cancellation, and invalid output after entry become possible-effect recovery. A development reconciler may return only `ObservedApplied` or `Inconclusive`; generic application code cannot prove non-application or release a reservation. Every conclusive observation is committed and freshness/binding checked. The directory implements the identical `auths.mcp-development-state/2` manifest, stable-key derivation, descriptor pinning, owner-only permissions/ACLs, no-link/no-follow, exclusive-lock, atomic-write/flush, corruption, concurrent-open rules, and exact owned default custody/reservation descriptors specified for TypeScript. It is labeled single-machine development state, not production durability. Action/plan recovery and idempotency-key lookup have the same continuation rules as TypeScript.

Delegation is a local Auths authority-state transition and never enters an application provider. The idempotency key is required: after a child is durably minted, replaying the same key and byte-identical attenuation returns that child; changing allowed tools, name, or expiry under the key returns `conflict`. Invalid/non-subset attenuation or an expired parent returns `denied`. The closed custody mapping is exactly the shared TypeScript table: rejected denial/revoked/disabled are `denied`; proven-no-signature cancellation and every indeterminate throttled/unavailable/provider-unknown/invalid-response state are `indeterminate`, with the matching registered code. There is no timeout or unsupported-suite value. The issue records custody entry and remains `not-applied` for child authority. Same-key replay queries a provider-unknown custody transaction rather than starting a second signing attempt. Those expected states are values, not exceptions, and cancellation is deferred until the durable child or child-not-applied state is recorded.

MCP `ReceiptInspection` is the explicit `ReceiptInspected | ReceiptRejected` union, so impossible details/issue combinations cannot be constructed or returned. Its validation and `mcp.receipt-invalid` semantics are identical to TypeScript.

### 6.7 `auths.github`

```python
from dataclasses import dataclass
from datetime import timedelta
from typing import (
    Generic, Literal, NoReturn, Optional, Sequence, Tuple, TypeVar, Union,
    final,
)
from auths import ErrorInfo, Receipt
from auths.verify import VerifiedReceipt

@dataclass(frozen=True)
class CandidatePolicy:
    allowed_patterns: Tuple[str, ...]
    denied_patterns: Tuple[str, ...]
    maximum_changed_files: int
    maximum_added_bytes: int
    maximum_deleted_bytes: int
    maximum_candidate_bytes: int
    maximum_git_objects: int
    maximum_commits: int
    allow_executable_bit_changes: bool
    allow_symlinks: bool
    allow_submodules: bool
    allow_merge_commits: bool
    allow_non_utf8_paths: Literal[False]
    allow_git_attributes_changes: bool
    allow_gitmodules_changes: bool
    allow_repository_automation_changes: bool

@final
@dataclass(frozen=True, init=False)
class IssueBoundary:
    def __init__(self, _private: NoReturn, /) -> None: ...
    boundary_id: str
    observed_at_unix_ms: int
    expires_at_unix_ms: int
    repository: str
    issue_number: int
    base_ref: str
    base_revision: str
    object_format: Literal["sha1", "sha256"]
    candidate_policy: CandidatePolicy
    minimum_expiry: timedelta
    maximum_expiry: timedelta
    branch_budget: Literal[1]
    draft_pull_request_budget: Literal[1]
    provider_credential: Literal["executor-only"]

@final
class InspectedCandidate:
    def __new__(cls, _private: NoReturn, /) -> "InspectedCandidate": ...
    @property
    def candidate_revision(self) -> str: ...

@dataclass(frozen=True)
class CandidateAccepted:
    kind: Literal["accepted"]
    candidate: InspectedCandidate
    changed_paths: Tuple[str, ...]
    credential_requested: Literal[False]

@dataclass(frozen=True)
class CandidateDenied:
    kind: Literal["denied"]
    issue: ErrorInfo
    changed_paths: Tuple[str, ...]
    credential_requested: Literal[False]

CandidateInspection = Union[CandidateAccepted, CandidateDenied]

RecoveryKindT = TypeVar(
    "RecoveryKindT", bound=Literal["delegation", "execution"]
)

@final
class RecoveryReference(Generic[RecoveryKindT]):
    def __new__(
        cls, _private: NoReturn, /
    ) -> "RecoveryReference[RecoveryKindT]": ...
    @classmethod
    def from_bytes(
        cls, data: bytes, /, *, expected_kind: RecoveryKindT,
    ) -> "RecoveryReference[RecoveryKindT]": ...
    @property
    def kind(self) -> RecoveryKindT: ...
    def to_bytes(self) -> bytes: ...

@final
class ReferenceRecoveryLocator(Generic[RecoveryKindT]):
    def __new__(
        cls, _private: NoReturn, /
    ) -> "ReferenceRecoveryLocator[RecoveryKindT]": ...
    @property
    def kind(self) -> Literal["reference"]: ...
    @property
    def reference(self) -> RecoveryReference[RecoveryKindT]: ...

@final
class IdempotencyKeyRecoveryLocator(Generic[RecoveryKindT]):
    def __new__(
        cls, _private: NoReturn, /
    ) -> "IdempotencyKeyRecoveryLocator[RecoveryKindT]": ...
    @property
    def kind(self) -> Literal["idempotency-key"]: ...
    @property
    def idempotency_key(self) -> str: ...

RecoveryLocator = Union[
    ReferenceRecoveryLocator[RecoveryKindT],
    IdempotencyKeyRecoveryLocator[RecoveryKindT],
]

@dataclass(frozen=True)
class Completed:
    kind: Literal["completed"]
    completion: Literal["executed", "replayed", "reconciled"]
    workflow_id: str
    branch_ref: str
    branch_revision: str
    pull_request_number: int
    pull_request_url: str
    pull_request_draft: Literal[True]
    receipts: Tuple[Receipt, ...]
    new_credential_requests: int
    new_mutations: int

@dataclass(frozen=True)
class Partial:
    kind: Literal["partial"]
    completion: Literal["executed", "replayed", "reconciled"]
    workflow_id: str
    completed_phase: Literal["branch"]
    branch_ref: str
    branch_revision: str
    pull_request_disposition: Literal[
        "denied", "indeterminate", "not-applied",
    ]
    pull_request_issue: ErrorInfo
    receipts: Tuple[Receipt, ...]
    new_credential_requests: int
    new_mutations: int

@dataclass(frozen=True)
class Denied:
    kind: Literal["denied"]
    workflow_id: str
    decision_receipt: Receipt
    issue: ErrorInfo

@dataclass(frozen=True)
class Indeterminate:
    kind: Literal["indeterminate"]
    workflow_id: str
    decision_receipt: Receipt
    issue: ErrorInfo

@dataclass(frozen=True)
class NotApplied:
    kind: Literal["not-applied"]
    workflow_id: str
    issue: ErrorInfo
    receipts: Tuple[Receipt, ...]

@dataclass(frozen=True)
class Conflict:
    kind: Literal["conflict"]
    workflow_id: str
    issue: ErrorInfo

@dataclass(frozen=True)
class RecoveryRequired:
    kind: Literal["recovery-required"]
    workflow_id: str
    issue: ErrorInfo
    recovery: RecoveryLocator[Literal["execution"]]
    credential_requests: Union[int, Literal["unknown"]]
    mutations: Union[int, Literal["unknown"]]

IssueOutcome = Union[
    Completed, Partial, Denied, Indeterminate, NotApplied,
    Conflict, RecoveryRequired,
]

@dataclass(frozen=True)
class Delegated:
    kind: Literal["delegated"]
    task: "IssueTask"

@dataclass(frozen=True)
class DelegationRejected:
    kind: Literal["denied", "indeterminate", "conflict"]
    issue: ErrorInfo

@dataclass(frozen=True)
class DelegationRecoveryRequired:
    kind: Literal["recovery-required"]
    issue: ErrorInfo
    idempotency_key: str
    recovery: RecoveryLocator[Literal["delegation"]]

DelegationResult = Union[
    Delegated, DelegationRejected, DelegationRecoveryRequired,
]

@dataclass(frozen=True)
class ClientDiagnostics:
    endpoint_origin: str
    protocol_version: str
    compatibility: Literal["full", "recovery-only"]
    error_registry_digest: str
    route_schema_digest: str
    durable_server_state: Literal[True]
    credential_location: Literal["executor-only"]
    recovery_retention_seconds: int
    receipt_retention_seconds: int
    warnings: Tuple[str, ...]

@final
class IssueTask:
    def __new__(cls, _private: NoReturn, /) -> "IssueTask": ...
    @property
    def workflow_id(self) -> str: ...
    @property
    def boundary(self) -> IssueBoundary: ...
    @property
    def agent_principal(self) -> str: ...
    @property
    def expires_at_unix_ms(self) -> int: ...
    async def inspect(
        self, *, bundle: bytes, candidate_revision: str,
    ) -> CandidateInspection: ...
    async def execute(
        self, candidate: InspectedCandidate, /, *, idempotency_key: str,
    ) -> IssueOutcome: ...
    async def aclose(self) -> None: ...
    async def __aenter__(self) -> "IssueTask": ...
    async def __aexit__(self, *exc: object) -> None: ...

@final
class IssueClient:
    def __init__(
        self, *, endpoint: str, control_plane_access_token: str,
        timeout: timedelta = timedelta(seconds=30),
        maximum_response_bytes: int = 12 * 1024 * 1024,
    ) -> None: ...
    async def boundary(self) -> IssueBoundary: ...
    async def delegate(
        self, *, boundary: IssueBoundary, agent_label: str,
        idempotency_key: str,
        expires_in: Optional[timedelta] = None,
        allow_patterns: Optional[Sequence[str]] = None,
    ) -> DelegationResult: ...
    async def recover_delegation(
        self, recovery: RecoveryLocator[Literal["delegation"]], /
    ) -> DelegationResult: ...
    async def recover_delegation_by_idempotency_key(
        self, idempotency_key: str, /
    ) -> DelegationResult: ...
    async def recover_execution(
        self, recovery: RecoveryLocator[Literal["execution"]], /
    ) -> IssueOutcome: ...
    async def recover_execution_by_idempotency_key(
        self, idempotency_key: str, /
    ) -> IssueOutcome: ...
    async def receipts(self, workflow_id: str, /) -> Tuple[Receipt, ...]: ...
    def diagnostics(self) -> ClientDiagnostics: ...
    async def aclose(self) -> None: ...
    async def __aenter__(self) -> "IssueClient": ...
    async def __aexit__(self, *exc: object) -> None: ...

@dataclass(frozen=True)
class GitHubDecisionReceiptDetails:
    kind: Literal["decision"]
    profile: Literal["auths.github.issue-address/2"]
    workflow_id: str
    phase: Literal["branch", "draft-pull-request"]
    decision: Literal["authorized", "denied", "indeterminate"]
    repository: str
    issue_number: int
    base_revision: str
    candidate_revision: str
    object_format: Literal["sha1", "sha256"]

@dataclass(frozen=True)
class GitHubSucceededReceiptDetails:
    kind: Literal["execution"]
    result: Literal["succeeded"]
    profile: Literal["auths.github.issue-address/2"]
    workflow_id: str
    phase: Literal["branch", "draft-pull-request"]
    repository: str
    issue_number: int
    base_revision: str
    candidate_revision: str
    object_format: Literal["sha1", "sha256"]
    provider_object_id: str

@dataclass(frozen=True)
class GitHubNonSuccessReceiptDetails:
    kind: Literal["execution"]
    result: Literal[
        "not-applied", "github-rejected", "reconciliation-required",
    ]
    profile: Literal["auths.github.issue-address/2"]
    workflow_id: str
    phase: Literal["branch", "draft-pull-request"]
    repository: str
    issue_number: int
    base_revision: str
    candidate_revision: str
    object_format: Literal["sha1", "sha256"]

GitHubExecutionReceiptDetails = Union[
    GitHubSucceededReceiptDetails, GitHubNonSuccessReceiptDetails,
]

GitHubReceiptDetails = Union[
    GitHubDecisionReceiptDetails,
    GitHubExecutionReceiptDetails,
]

@dataclass(frozen=True)
class ReceiptInspected:
    kind: Literal["inspected"]
    details: GitHubReceiptDetails

@dataclass(frozen=True)
class ReceiptRejected:
    kind: Literal["rejected"]
    issue: ErrorInfo

ReceiptInspection = Union[ReceiptInspected, ReceiptRejected]

def inspect_receipt(receipt: VerifiedReceipt, /) -> ReceiptInspection: ...
```

Callers read a candidate path explicitly before `inspect`; the SDK does no hidden filesystem access. Input is raw Git bundle v2 and is bounded by the sealed `CandidatePolicy`, including every numeric limit and policy switch. The TypeScript section's exact v2 `*`/whole-component `**`, deny-first, byte-matching grammar and hard ceilings are shared; Python does not reinterpret patterns or paths through `pathlib`, `fnmatch`, regex, locale, Unicode normalization, or host globbing. `IssueClient.delegate` consumes the sealed boundary snapshot, requires a caller idempotency key, and only narrows it by selecting byte-identical allowed patterns. Omitted expiry selects a server-safe duration inside the advertised interval. An ambiguous delegation returns a durable kind-bound recovery reference; after restart, the client recovers it by bytes or caller-known idempotency key without reconstructing the boundary. Changed commitments conflict. Execution recovery uses distinct methods and a reference typed as `execution`, so both workflows survive task/process loss without cross-use.

The v2 client sends the supplied Auths control-plane credential as a redacted HTTPS Bearer token to the exact route family below; it is never a GitHub token and is never forwarded to GitHub. As in TypeScript, this stable module is blocked until demo routes, count-only receipt checking, broad exception conversion, idempotent delegation, non-durable recovery, and v1's missing work ceilings are replaced by the production contract.

GitHub `ReceiptInspection` is likewise an explicit two-variant union and returns `github.receipt-invalid` for an invalid profile payload after envelope trust succeeds.

### 6.8 `auths.protocol`

```python
from dataclasses import dataclass
from datetime import timedelta
from typing import Literal, NoReturn, Protocol, final
from auths.verify import VerificationInput, VerificationResult

@dataclass(frozen=True)
class TransportRequest:
    """The client resolves the URL and route; the transport only sends."""
    url: str
    method: Literal["POST"]
    media_type: Literal["application/vnd.auths.remote-verification.v1+cbor"]
    accept: Literal["application/vnd.auths.remote-verification.v1+cbor"]
    body: bytes
    deadline_unix_ms: int
    maximum_response_bytes: int

@dataclass(frozen=True)
class TransportResponse:
    status: int
    media_type: str
    body: bytes

class BoundedTransport(Protocol):
    @property
    def contract(self) -> Literal["bounded-byte-transport/2"]: ...
    async def send(self, request: TransportRequest) -> TransportResponse: ...
    async def aclose(self) -> None: ...

@final
class RemoteVerifier:
    def __new__(cls, _private: NoReturn, /) -> "RemoteVerifier": ...
    async def verify(self, input: VerificationInput, /) -> VerificationResult: ...
    async def aclose(self) -> None: ...
    async def __aenter__(self) -> "RemoteVerifier": ...
    async def __aexit__(self, *exc: object) -> None: ...

def connect_remote_verifier(
    *, endpoint: str, access_token: str,
    timeout: timedelta = timedelta(seconds=30),
    maximum_response_bytes: int = 8 * 1024 * 1024,
    allow_insecure_loopback: bool = False,
) -> RemoteVerifier: ...

def remote_verifier_from_transport(
    endpoint: str, transport: BoundedTransport, /, *,
    owns_transport: bool = False,
    timeout: timedelta = timedelta(seconds=30),
    maximum_response_bytes: int = 8 * 1024 * 1024,
    allow_insecure_loopback: bool = False,
) -> RemoteVerifier: ...
```

Both constructors require an endpoint origin so the client can resolve the fixed route. They make channel mode exclusive: the built-in constructor requires `access_token`, while the injected-transport constructor has no SDK credential. Plaintext is accepted only when `allow_insecure_loopback=True` and the parsed host is a loopback literal. Timeout is 1 ms–5 minutes and maximum response is 1 KiB–16 MiB, with the defaults shown. `TransportRequest.url` is the client-selected `/v2/verification/authorize` route, not a generic operation tag. `deadline_unix_ms` is derived once and cannot be extended by the transport. The injected transport never receives an SDK credential; it owns any channel authentication. The built-in transport applies and redacts the Auths Bearer credential below this public request type. The transport cannot select or decode profile semantics. Request, response, HTTP status, canonical CBOR, authenticated-principal/configuration commitment, and bounds are byte-for-byte the TypeScript `auths.remote-verification/1` contract.

There is intentionally no remote execution, authority import, recovery, profile-ID marker, or receipt-disclosure constructor here. Those operations require a typed, profile-owned public vertical.

### 6.9 `auths.adapters`

The package exports the module namespaces `custody` and `reservations`; it does not duplicate every leaf at `auths.adapters`.

#### `auths.adapters.custody`

```python
from dataclasses import dataclass
from enum import Enum
from typing import Literal, Protocol, Tuple, Union

class SigningObjectKind(str, Enum):
    GRANT = "grant"
    ACTION = "action"
    PRINCIPAL_STATUS = "principal-status"
    GRANT_STATUS = "grant-status"

class CustodyLifecycle(str, Enum):
    DURABLE = "durable"
    EPHEMERAL = "ephemeral"

class CustodyKind(str, Enum):
    WEBAUTHN = "webauthn"
    WORKLOAD = "workload"
    KMS = "kms"
    HSM = "hsm"
    PKCS11 = "pkcs11"

class CustodyKeyState(str, Enum):
    ENROLLED = "enrolled"
    READY = "ready"
    ROTATION_PENDING = "rotation-pending"
    ACTIVE_CURRENT = "active-current"
    RETIRING_PREVIOUS = "retiring-previous"
    REVOKED = "revoked"
    DISABLED = "disabled"
    UNAVAILABLE = "unavailable"
    INDETERMINATE = "indeterminate"

class CustodyFailure(str, Enum):
    DENIED = "denied"
    CANCELLED = "cancelled"
    THROTTLED = "throttled"
    UNAVAILABLE = "unavailable"
    REVOKED_KEY = "revoked-key"
    DISABLED_KEY = "disabled-key"
    PROVIDER_UNKNOWN = "provider-unknown"
    INVALID_PROVIDER_RESPONSE = "invalid-provider-response"

@dataclass(frozen=True)
class CustodySignatureDescriptor:
    principal_method: str
    verification_method: str
    suite: str

@dataclass(frozen=True)
class CustodyDescriptor:
    contract: Literal["signer-custody/2"]
    kind: CustodyKind
    adapter_id: str
    principal: str
    signature: CustodySignatureDescriptor
    key_version: str
    key_state: CustodyKeyState
    lifecycle: CustodyLifecycle

@dataclass(frozen=True)
class ReviewField:
    label: str
    value: str

@dataclass(frozen=True)
class PublicControlEvidence:
    evidence_type: str
    media_type: str
    bytes: bytes

@dataclass(frozen=True)
class SigningRequest:
    request_id: str
    object_kind: SigningObjectKind
    object_id: bytes
    descriptor: CustodyDescriptor
    transaction_digest: bytes
    signing_preimage: bytes
    expires_at_unix_seconds: int
    display: Tuple[ReviewField, ...]

@dataclass(frozen=True)
class SigningResponse:
    request_id: str
    object_id: bytes
    principal: str
    descriptor: CustodySignatureDescriptor
    provider_key_version: str
    transaction_digest: bytes
    signature: bytes
    evidence: Tuple[PublicControlEvidence, ...]

@dataclass(frozen=True)
class CustodySigned:
    kind: Literal["signed"]
    response: SigningResponse

@dataclass(frozen=True)
class CustodyRejected:
    kind: Literal["rejected"]
    failure: Literal[
        CustodyFailure.DENIED, CustodyFailure.CANCELLED,
        CustodyFailure.REVOKED_KEY, CustodyFailure.DISABLED_KEY,
    ]

@dataclass(frozen=True)
class CustodyIndeterminate:
    kind: Literal["indeterminate"]
    failure: Literal[
        CustodyFailure.THROTTLED, CustodyFailure.UNAVAILABLE,
        CustodyFailure.PROVIDER_UNKNOWN,
        CustodyFailure.INVALID_PROVIDER_RESPONSE,
    ]

CustodySignResult = Union[
    CustodySigned, CustodyRejected, CustodyIndeterminate,
]

class CustodySigner(Protocol):
    @property
    def descriptor(self) -> CustodyDescriptor: ...
    async def sign(self, request: SigningRequest) -> CustodySignResult: ...
    async def aclose(self) -> None: ...
```

#### `auths.adapters.reservations`

```python
from dataclasses import dataclass
from typing import Literal, Protocol

@dataclass(frozen=True)
class ReservationRecord:
    key: str
    commitment: bytes
    value: bytes

ReservationDecision = Literal["acquired", "exact-replay", "conflict"]

class ReservationStore(Protocol):
    @property
    def contract(self) -> Literal["atomic-reservation-store/2"]: ...
    @property
    def kind(self) -> str: ...
    @property
    def durability(self) -> Literal[
        "ephemeral", "single-machine-durable",
    ]: ...
    async def reserve(
        self, record: ReservationRecord
    ) -> ReservationDecision: ...
    async def aclose(self) -> None: ...
```

The same internal-approval and narrow-reservation decisions from the TypeScript section apply. Python protocols use structural typing for adapter implementation, but every value is runtime-validated at the trusted boundary and conformance-tested. Structural typing never makes an adapter output authoritative by itself.

### 6.10 `auths.testkit`

```python
from dataclasses import dataclass
from typing import Callable, Literal, NoReturn, Optional, Tuple, final
from auths.adapters.custody import CustodySigner
from auths.adapters.reservations import ReservationStore
from auths.protocol import BoundedTransport
from auths.verify import VerificationInput

@dataclass(frozen=True)
class ConformanceCase:
    id: str
    status: Literal["passed", "failed"]
    detail_code: Optional[Literal[
        "contract-mismatch", "unexpected-exception", "timeout",
        "resource-leak", "redaction-failed",
    ]]
    summary: Optional[str]

@dataclass(frozen=True)
class ConformanceMetadata:
    suite: str
    contract_version: str
    sdk_version: str
    generated_at: str
    assurance: Literal["test-results-only-not-security-certification"]

@dataclass(frozen=True)
class ConformanceReport:
    metadata: ConformanceMetadata
    passed: bool
    cases: Tuple[ConformanceCase, ...]

async def run_custody_signer_conformance(
    factory: Callable[[], CustodySigner], /
) -> ConformanceReport: ...
async def run_reservation_store_conformance(
    factory: Callable[[str], ReservationStore], /
) -> ConformanceReport: ...
async def run_bounded_transport_conformance(
    factory: Callable[[], BoundedTransport], /
) -> ConformanceReport: ...

def ephemeral_ed25519_signer() -> CustodySigner: ...

@final
class fixtures:
    def __new__(cls, _private: NoReturn, /) -> "fixtures": ...
    @staticmethod
    def authorized_verification() -> VerificationInput: ...
    @staticmethod
    def denied_verification() -> VerificationInput: ...
    @staticmethod
    def github_denied_candidate(
        reason: Literal["protected-path", "base-mismatch"]
    ) -> bytes: ...
```

`fixtures` is exactly a non-instantiable final class namespace with static methods, not a module proxy or mutable singleton. It remains test-only. `ConformanceReport.passed` is true only when every mandatory case in its exact suite/version passed; there is no caller-selected skip. Arbitrary adapter exception text is replaced by a closed `detail_code` and an optional redacted single-line summary of at most 256 Unicode scalars. Secret-shaped text and redaction failure produce no summary. The profile-owned MCP lifecycle suite, diagnostic verdict selection, and repository product-waist machinery are internal.

### 6.11 Exact Python `__all__` inventories

The following lists are normative and are installed/snapshotted verbatim. They intentionally use `list`, matching the repository's public-API inventory gate. The declaration blocks use readable metavariable spellings, but installed modules and stubs bind every non-exported helper only under a leading underscore and expose no unprefixed attribute: `ErrorFamily` becomes `_ErrorFamily`, `CauseCategory` becomes `_CauseCategory`, and likewise for `VerificationStage`, `VerificationKind`, `ReceiptSignerRole`, `AdapterRejection`, `AdapterUncertainty`, `ProviderUncertainty`, `ExecutionStage`, `ExecutionOutcomeKind`, `ReservationDecision`, and every shown type variable (`IdentityT`, `AdapterT`, `ArgumentsT`, `ResultT`, `EvidenceT`, `RecoveryKindT`). Exported annotations reference those underscored bindings internally. Imports such as `from auths.mcp import ExecutionStage, ArgumentsT` must fail, as must unprefixed imported helpers such as `dataclass`, `Enum`, `Path`, or `Protocol`. This spelling map is part of the stub-generation snapshot, so implementation does not choose which helpers leak.

```python
# auths
__all__ = [
    "EffectState", "RetryClass", "RecommendedAction", "KnownAuthsErrorCode",
    "EnteredBoundaries", "ErrorInfo", "AuthsError", "Receipt", "RuntimeInfo",
    "runtime_info",
]

# auths.verify
__all__ = [
    "VerificationInput", "VerificationMetrics", "AuthorizedVerification",
    "UnsuccessfulVerification", "VerificationResult", "ApprovalInspection",
    "VerificationInspection", "ReceiptSignerInfo",
    "ReceiptProfile", "ReceiptTrustAnchor", "ReceiptTrustPolicy",
    "pinned_receipt_trust", "DecisionReceiptDetails",
    "ExecutionReceiptDetails", "ReceiptEnvelopeDetails",
    "VerifiedReceipt", "RejectedReceipt", "IndeterminateReceipt",
    "ReceiptVerification", "verify", "verify_many", "inspect",
    "verify_receipt",
]

# auths.identity
__all__ = [
    "IdentityOk", "IdentityRejected", "IdentityIndeterminate",
    "IdentityResult", "DecodedIdentity", "ResolvedIdentity",
    "ValidatedIdentity", "AuthenticatedIdentityMessage", "IdentityClient",
    "raw_key_ed25519", "authenticate_message",
]

# auths.identity.adapters
__all__ = [
    "VerificationMaterial", "VerificationRelationship", "DecodedIdentityRecord",
    "ResolutionEvidence", "ResolvedIdentityRecord", "AdapterOk", "AdapterRejected",
    "AdapterIndeterminate", "AdapterResult", "IdentityResolver",
    "IdentityMethod", "MessageAuthenticator", "create_client",
    "resolver_method",
]

# auths.identity.authoring
__all__ = [
    "PreparedIdentityMessage", "create_raw_key_ed25519_identity",
    "encode_identity", "prepare_identity_message",
]
```

```python
# auths.mcp
__all__ = [
    "Tool", "Call", "Authority", "Plan", "InvocationContext", "Invocation",
    "Applied", "Possible", "ProviderOutcome", "Handler", "HandlerBinding",
    "bind", "ProviderAttempt", "Observation", "ObservedApplied",
    "Inconclusive", "ReconciliationOutcome",
    "Reconciler", "ReconcilerBinding", "observe", "ExecutionEvent",
    "RecoveryReference", "PlanRecoveryReference", "Completed", "Denied",
    "Indeterminate", "Conflict", "RecoveryRequired",
    "PlanRecoveryRequired", "Failed", "ActionOutcome", "PlanCompleted",
    "PlanStopped", "PlanOutcome", "DelegatedSession", "DelegationRejected",
    "DelegationResult", "SessionDiagnostics", "DevelopmentSession", "Profile",
    "McpReceiptDetails", "ReceiptInspected", "ReceiptRejected",
    "ReceiptInspection", "inspect_receipt",
]

# auths.github
__all__ = [
    "CandidatePolicy", "IssueBoundary", "InspectedCandidate", "CandidateAccepted",
    "CandidateDenied", "CandidateInspection", "RecoveryReference",
    "ReferenceRecoveryLocator", "IdempotencyKeyRecoveryLocator",
    "RecoveryLocator", "Completed",
    "Partial",
    "Denied", "Indeterminate", "NotApplied", "Conflict", "RecoveryRequired",
    "IssueOutcome", "Delegated", "DelegationRejected",
    "DelegationRecoveryRequired", "DelegationResult", "ClientDiagnostics",
    "IssueTask", "IssueClient", "GitHubDecisionReceiptDetails",
    "GitHubSucceededReceiptDetails", "GitHubNonSuccessReceiptDetails",
    "GitHubExecutionReceiptDetails", "GitHubReceiptDetails", "ReceiptInspected",
    "ReceiptRejected", "ReceiptInspection", "inspect_receipt",
]

# auths.protocol
__all__ = [
    "TransportRequest", "TransportResponse", "BoundedTransport", "RemoteVerifier",
    "connect_remote_verifier", "remote_verifier_from_transport",
]
```

```python
# auths.adapters exposes only these two module namespaces.
__all__ = ["custody", "reservations"]

# auths.adapters.custody
__all__ = [
    "SigningObjectKind", "CustodyLifecycle", "CustodyKind",
    "CustodyKeyState", "CustodyFailure", "CustodySignatureDescriptor",
    "CustodyDescriptor", "ReviewField", "PublicControlEvidence",
    "SigningRequest", "SigningResponse", "CustodySigned", "CustodyRejected",
    "CustodyIndeterminate", "CustodySignResult", "CustodySigner",
]

# auths.adapters.reservations
__all__ = [
    "ReservationRecord", "ReservationStore",
]

# auths.testkit
__all__ = [
    "ConformanceCase", "ConformanceMetadata", "ConformanceReport",
    "run_custody_signer_conformance", "run_reservation_store_conformance",
    "run_bounded_transport_conformance", "ephemeral_ed25519_signer",
    "fixtures",
]
```

This is 175 exports including the two `auths.adapters` module namespaces, down from 180. The explicit identity descriptor, recovery locators, and GitHub receipt-result variants are intentional declaration closure, not alternate import paths. A generated inventory gate rejects additions, missing names, duplicate canonical paths, or a public annotation that resolves only through a private import.

### 6.12 Python platform and lifecycle notes

- All claimed CPython 3.9-3.14 wheels expose identical `__all__`, signatures, enum values, dataclass fields, and behavior.
- `auths`, `auths.verify`, and `auths.identity` import without starting an event loop, opening files/sockets, or loading effect runtimes.
- `Profile.development`, `IssueClient`, `connect_remote_verifier`, `remote_verifier_from_transport`, `raw_key_ed25519`, and custom identity factories create an inert `new` object. The first `__aenter__` validates configuration, acquires owned resources, performs any authenticated capability handshake, and transitions atomically to `open`; a second enter or any operation/diagnostics call while `new`, `closing`, or `closed` raises `RuntimeError("auths client is not open")` before I/O. If entry fails or is cancelled, every partially owned resource is closed and the object permanently becomes `closed`; retry requires a fresh object. `IssueTask` follows the same rule even though the server workflow already exists. `aclose` is idempotent in every state: on `new` it simply marks closed, and on `open` it stops admission, settles per section 4.5, closes owned children/resources in reverse order, and marks closed. Supplied adapters/transports remain borrowed unless their explicit ownership flag says otherwise, including partial-open and cancellation paths. None of these objects is awaitable.
- The wheel remains `abi3-py39`, contains `py.typed`, and contains exactly one intended native extension. No sdist may be the only artifact for a claimed platform.
- `Path` is accepted only for the explicit development state directory. Domain artifacts and candidate bundles cross security boundaries as copied `bytes`.

## 7. Deliberate TypeScript/Python parity

### 7.1 Semantics that must be identical

The same fixtures and Rust owner must produce identical values for:

- profile IDs and versions;
- canonical action/plan commitments;
- authorized/denied/indeterminate verdict and verification stage;
- registered stable code, effect, retry, recommended action, and entered-boundary flags;
- required and executed configuration commitments;
- idempotency replay/conflict identity;
- reservation and provider-entry ordering;
- recovery reference identity and effect classification;
- receipt bytes, link/signature verification, and disclosure commitments;
- denial-before-credential/provider behavior;
- plan stop member and completed prefix;
- unknown registry-code negotiation refusal before effect, plus recovery-required handling for an already-entered incompatible workflow; and
- close/cancellation guarantees.

TypeScript and Python documentation uses the same words: completed, partial, denied, indeterminate, not applied, conflict, recovery required, failed, executed, replayed, and reconciled.

### 7.2 Deliberate syntax differences

| Concern | TypeScript | Python | Reason |
|---|---|---|---|
| Tool typing | generic `McpTool<Input, Output>` map | frozen dataclass model classes | idiomatic static/runtime model projection |
| Result narrowing | discriminated unions and `switch` | frozen variants and `isinstance` | native exhaustiveness styles |
| Durations | unit-named integer fields | `timedelta` | prevents unit ambiguity in each language |
| Cancellation | `AbortSignal` | task cancellation | native async model |
| Disposal | `await using`, `close`, `Symbol.asyncDispose` | `async with`, `aclose` | native resource model |
| Offline verifier | async factory, then sync methods | sync module functions | TypeScript must initialize packaged WASM; Python native extension is already loaded |
| Filesystem development state | explicit `/mcp/node` subpath | `Path` argument in `auths.mcp` | Python package/runtime is already platform-specific; JS export conditions must separate browser code |
| Adapter organization | one `/adapters` subpath with named types | `auths.adapters.{custody,reservations}` | Python module navigation is clearer than a large re-export barrel |
| Error code discovery | generated closed string-literal union | generated `str` enum used by `ErrorInfo.code` | preserves the registry-bound `auths.error/1` invariant in both languages |

These differences do not change trust, authority, execution, recovery, or receipt semantics.

## 8. Complete before-and-after workflows

All “after” examples use only installed public imports. Development and production configurations are labeled explicitly.

### 8.1 Install and inspect the clean package

TypeScript:

```sh
npm install @auths-dev/sdk
npx --package @auths-dev/sdk auths doctor
```

Python:

```sh
python -m pip install auths
python -m auths doctor
```

The CLI command is intentionally called `doctor`; the library functions are `runtimeInfo()` and `runtime_info()`. The CLI reads observed package/native facts, emits bounded JSON with `--json`, never asks the caller to state mode/durability, and never prints secrets or protocol payloads.

### 8.2 Protect and execute one MCP action

#### Before: TypeScript

The current README requires three concepts to be assembled and leaves provider lifetime separate:

```ts
import { development } from "@auths-dev/sdk/integrations";
import { mcp } from "@auths-dev/sdk/profiles";

const provider = mcp.developmentProvider({
  tools: {
    async publish_report(arguments_) {
      return { published: true, arguments: arguments_ };
    },
  },
});
const auths = await development.createAuths({
  authority: mcp.allowTools(["publish_report"]),
});
const result = await auths.execute({
  action: mcp.callTool({
    name: "publish_report",
    arguments: { period: "weekly" },
  }),
  provider,
});
await auths.close();
```

#### After: TypeScript — development only

```ts
import { mcp } from "@auths-dev/sdk/mcp";
import { openDevelopment } from "@auths-dev/sdk/mcp/node";

interface PublishReportInput {
  readonly period: "daily" | "weekly";
}
interface PublishReportOutput {
  readonly published: boolean;
  readonly reportId: string;
}
const reports = mcp.profile({
  service: "reports.internal",
  tools: {
    publish_report: mcp.tool({
      input: mcp.model.object<PublishReportInput>({
        period: mcp.model.oneOf(
          mcp.model.literal("daily"),
          mcp.model.literal("weekly"),
        ),
      }),
      output: mcp.model.object<PublishReportOutput>({
        published: mcp.model.boolean(),
        reportId: mcp.model.string(),
      }),
    }),
  },
});

await using session = await openDevelopment(reports, {
  stateDirectory: new URL("./.auths-dev-state/", import.meta.url),
  allow: ["publish_report"],
  handlers: {
    async publish_report({ input, context }) {
      const reportId = `${input.period}-${context.executionId}`;
      // Perform the real domain operation here.
      return mcp.applied({ published: true, reportId });
    },
  },
  reconcile: {
    async publish_report() {
      return mcp.inconclusive("unavailable");
    },
  },
});

const outcome = await session.execute(
  reports.call("publish_report", { period: "weekly" }),
  { idempotencyKey: "report-2026-w33" },
);

switch (outcome.kind) {
  case "completed":
    console.log(outcome.completion, outcome.value.reportId);
    break;
  case "recovery-required":
    console.error(
      "reopen .auths-dev-state and recover key report-2026-w33",
    );
    break;
  case "denied":
  case "indeterminate":
  case "conflict":
  case "failed":
    console.error(outcome.issue.code, outcome.issue.recommendedAction);
    break;
}
```

**Development only:** this uses local trust and a secret-bearing single-machine state directory so uncertain effects remain recoverable after process loss. It is not production durability, custody, or identity configuration. The directory must not be committed, shared, or logged.

The meaningful call has one profile import, one typed action, and one required idempotency key. The provider is bound once and owned by the session. An application output may safely contain any field name, including `effect`, because only sealed `mcp.applied`/`mcp.possible` wrappers carry normal-handler control state; development reconciliation is separately branded and can only prove application or remain inconclusive.

#### Before: Python

The current README uses a handler signature that does not match the implementation and passes the provider on every call:

```python
from auths.integrations import development
from auths.profiles import mcp

async def publish_report(arguments: dict[str, object]) -> object:
    return {"published": True, "arguments": arguments}

async def current_readme_flow() -> None:
    provider = mcp.development_provider(
        tools={"publish_report": publish_report}
    )
    async with development.create_auths(
        authority=mcp.allow_tools(("publish_report",)),
    ) as auths:
        await auths.execute(
            action=mcp.call_tool(
                name="publish_report", arguments={"period": "weekly"}
            ),
            provider=provider,
        )
```

#### After: Python — development only

```python
import asyncio
from dataclasses import dataclass
from pathlib import Path

import auths.mcp as mcp

@dataclass(frozen=True)
class PublishReportArguments:
    period: str

@dataclass(frozen=True)
class PublishReportResult:
    published: bool
    report_id: str

reports = mcp.Profile(service="reports.internal")
publish_report = reports.tool(
    "publish_report",
    arguments=PublishReportArguments,
    result=PublishReportResult,
)

async def publish(
    invocation: mcp.Invocation[PublishReportArguments],
) -> mcp.ProviderOutcome[PublishReportResult]:
    report_id = f"{invocation.arguments.period}-{invocation.context.execution_id}"
    return mcp.Applied(PublishReportResult(True, report_id))

async def reconcile_publish(
    invocation: mcp.Invocation[PublishReportArguments],
    attempt: mcp.ProviderAttempt,
) -> mcp.ReconciliationOutcome[PublishReportResult]:
    return mcp.Inconclusive("unavailable")

async def main() -> None:
    async with reports.development(
        allow=(publish_report,),
        handlers=(mcp.bind(publish_report, publish),),
        reconcilers=(mcp.observe(publish_report, reconcile_publish),),
        state_directory=Path(".auths-dev-state"),
    ) as session:
        outcome = await session.execute(
            publish_report.call(PublishReportArguments(period="weekly")),
            idempotency_key="report-2026-w33",
        )

        if isinstance(outcome, mcp.Completed):
            print(outcome.completion, outcome.value.report_id)
        elif isinstance(outcome, mcp.RecoveryRequired):
            print(
                "reopen .auths-dev-state and recover key report-2026-w33"
            )
        else:
            print(outcome.issue.code, outcome.issue.recommended_action.value)

if __name__ == "__main__":
    asyncio.run(main())
```

**Development only:** the same local-trust/single-machine-state warning applies. The frozen dataclass models are checked both by type checkers and at runtime.

### 8.3 Prove an out-of-authority call never reaches the provider

This is an adversarial development test. Normal TypeScript application code cannot pass the excluded tool at compile time; the erased call below proves the runtime still rejects JavaScript, stale bundles, and casted values before provider entry.

TypeScript:

```ts
import { mcp, type McpOutcome } from "@auths-dev/sdk/mcp";
import { openDevelopment } from "@auths-dev/sdk/mcp/node";

const reports = mcp.profile({
  service: "reports.internal",
  tools: {
    publish_report: mcp.tool({
      input: mcp.model.object({ period: mcp.model.string() }),
      output: mcp.model.object({ published: mcp.model.boolean() }),
    }),
    delete_report: mcp.tool({
      input: mcp.model.object({ reportId: mcp.model.string() }),
      output: mcp.model.object({ deleted: mcp.model.boolean() }),
    }),
  },
});
let providerCalls = 0;

await using session = await openDevelopment(reports, {
  stateDirectory: new URL("./.auths-denial-test-state/", import.meta.url),
  allow: ["publish_report"],
  handlers: {
    async publish_report() {
      providerCalls += 1;
      return mcp.applied({ published: true });
    },
  },
  reconcile: {
    async publish_report() {
      return mcp.inconclusive("unavailable");
    },
  },
});

const excluded = reports.call("delete_report", { reportId: "r-1" });
const erased = session as unknown as {
  execute(
    action: unknown,
    options: { idempotencyKey: string },
  ): Promise<McpOutcome<unknown>>;
};
const outcome = await erased.execute(
  excluded,
  { idempotencyKey: "denial-test-1" },
);

if (outcome.kind !== "denied" || providerCalls !== 0) {
  throw new Error("denial crossed the provider boundary");
}
```

Python:

```python
import asyncio
from dataclasses import dataclass
from pathlib import Path

import auths.mcp as mcp

@dataclass(frozen=True)
class Input:
    period: str

@dataclass(frozen=True)
class Output:
    published: bool

reports = mcp.Profile(service="reports.internal")
publish_report = reports.tool("publish_report", arguments=Input, result=Output)
delete_report = reports.tool("delete_report", arguments=Input, result=Output)
provider_calls = 0

async def publish(
    invocation: mcp.Invocation[Input],
) -> mcp.ProviderOutcome[Output]:
    global provider_calls
    provider_calls += 1
    return mcp.Applied(Output(published=True))

async def reconcile_publish(
    invocation: mcp.Invocation[Input],
    attempt: mcp.ProviderAttempt,
) -> mcp.ReconciliationOutcome[Output]:
    return mcp.Inconclusive("unavailable")

async def main() -> None:
    async with reports.development(
        allow=(publish_report,),
        handlers=(mcp.bind(publish_report, publish),),
        reconcilers=(mcp.observe(publish_report, reconcile_publish),),
        state_directory=Path(".auths-denial-test-state"),
    ) as session:
        outcome = await session.execute(
            delete_report.call(Input(period="weekly")),
            idempotency_key="denial-test-1",
        )

    assert isinstance(outcome, mcp.Denied)
    assert provider_calls == 0

if __name__ == "__main__":
    asyncio.run(main())
```

The authoritative tests additionally assert that denial enters no credential boundary, issues no credential, reserves no provider-effect capacity when the profile does not require it, and emits no provider request.

### 8.4 Verify a proof without effects

#### Before

```ts
const verifier = await loadVerifier();
const result = verifier.verify(proof, action, context);
```

```python
result = verify(proof, action, context)
```

Three adjacent byte arguments can be reordered without a type error. The current authorized TypeScript result also exposes `VerifiedAction`, which reads like an executable capability even though this layer must remain inert.

#### After: TypeScript

```ts
import { createVerifier } from "@auths-dev/sdk/verify";

export async function verifyLocal(
  proof: Uint8Array,
  action: Uint8Array,
  trustedContext: Uint8Array,
): Promise<void> {
  const verifier = await createVerifier();
  const result = verifier.verify({ proof, action, trustedContext });
  if (result.kind === "authorized") {
    console.log("verified, but not executable", result.correlationId);
  } else {
    console.error(result.issue.code, result.stage);
  }
}
```

#### After: Python

```python
from auths.verify import AuthorizedVerification, VerificationInput, verify

def verify_local(proof: bytes, action: bytes, trusted_context: bytes) -> None:
    result = verify(VerificationInput(
        proof=proof,
        action=action,
        trusted_context=trusted_context,
    ))

    if isinstance(result, AuthorizedVerification):
        print("verified, but not executable", result.correlation_id)
    else:
        print(result.issue.code, result.stage)
```

The result contains evidence and commitments only. To execute, the caller must enter a profile-owned API with its own authority, exact action, state, and provider boundary.

### 8.5 Authenticate an identity without granting authority

#### Before: TypeScript

The maintained flow requires three independently loaded objects and explicit adapter plumbing:

```ts
const identities = await loadIdentity();
const rawKeys = await loadRawKeyIdentityAdapter();
const ed25519 = await loadEd25519RawKeyAuthentication();
const decoded = identities.decodePublicIdentity(identityPacket);
const validated = identities.parseIdentity(decoded, rawKeys);
const message = identities.decodeSignedMessage(signedPacket);
const authenticated = identities.authenticate(message, validated, ed25519);
```

#### After: TypeScript

```ts
import { createRawKeyEd25519IdentityClient }
  from "@auths-dev/sdk/identity";

export async function authenticateRequest(
  identityPacket: Uint8Array,
  requestBody: Uint8Array,
  signature: Uint8Array,
  signal?: AbortSignal,
): Promise<void> {
  await using identities = await createRawKeyEd25519IdentityClient();
  const result = await identities.authenticateMessage({
    identityPacket,
    message: requestBody,
    signature,
    ...(signal === undefined ? {} : { signal }),
  });

  if (result.kind !== "ok") {
    console.error(result.kind, result.issue.code);
  } else {
    console.log(result.value.identity.identityId);
  }
  // An ok value is identity evidence, not Auths authority.
}
```

This is production-shaped when the incoming packet/signature are provided by the application's authenticated transport and trust policy. For remote/resolver-backed identities, construct an explicit advanced client from `/identity/adapters`.

#### Before: Python

The current first recipe constructs a registry from development identity and signature test doubles. That proves mechanics but is not a copyable production authentication path.

#### After: Python

```python
from datetime import timedelta
from auths.identity import IdentityOk, authenticate_message

async def authenticate_request(
    identity_packet: bytes,
    request_body: bytes,
    signature: bytes,
) -> None:
    result = await authenticate_message(
        identity_packet,
        message=request_body,
        signature=signature,
        timeout=timedelta(seconds=5),
    )

    if isinstance(result, IdentityOk):
        print(result.value.identity.identity_id)
    else:
        print(result.kind, result.issue.code)
    # This value does not carry profile authority.
```

#### Authoring with external custody

Applications that create a signed identity message use the explicit authoring module. The SDK returns the exact preimage; the private key remains in external custody:

```ts
import type { ValidatedIdentity } from "@auths-dev/sdk/identity";
import { prepareIdentityMessage } from "@auths-dev/sdk/identity/authoring";

async function authenticationParts(
  identity: ValidatedIdentity,
  requestBody: Uint8Array,
  signIdentityPreimage: (preimage: Uint8Array) => Promise<Uint8Array>,
) {
  const prepared = await prepareIdentityMessage({ identity, message: requestBody });
  const signature = await signIdentityPreimage(prepared.signingPreimage);
  return {
    identityPacket: prepared.identity.toBytes(),
    message: prepared.message,
    signature,
  } as const;
}
```

```python
from typing import Awaitable, Callable, Tuple
from auths.identity import ValidatedIdentity
from auths.identity.authoring import prepare_identity_message

async def authentication_parts(
    identity: ValidatedIdentity,
    request_body: bytes,
    sign_identity_preimage: Callable[[bytes], Awaitable[bytes]],
) -> Tuple[bytes, bytes, bytes]:
    prepared = prepare_identity_message(identity, message=request_body)
    signature = await sign_identity_preimage(prepared.signing_preimage)
    return identity.to_bytes(), prepared.message, signature
```

The supplied signer must be an application-qualified external key holder for the identity method. It signs only the exact prepared preimage. This is deliberately not `CustodySigner.sign`, whose public contract accepts a Rust-created `SigningRequest` for Auths grant/action custody rather than arbitrary bytes. The three returned values feed `authenticateMessage`/`authenticate_message` directly.

### 8.6 Delegate narrower MCP authority and prove exact replay

#### Before

The current application constructs child authority separately, passes a provider again, and receives replay as a distinct recovery-result vocabulary. The generic root types hide that both authority and replay reference are MCP-specific.

#### After: TypeScript — development only

```ts
import { mcp } from "@auths-dev/sdk/mcp";
import { openDevelopment } from "@auths-dev/sdk/mcp/node";

const reports = mcp.profile({
  service: "reports.internal",
  tools: {
    publish_report: mcp.tool({
      input: mcp.model.object({ period: mcp.model.string() }),
      output: mcp.model.object({ published: mcp.model.boolean() }),
    }),
    delete_report: mcp.tool({
      input: mcp.model.object({ reportId: mcp.model.string() }),
      output: mcp.model.object({ deleted: mcp.model.boolean() }),
    }),
  },
});
let publishes = 0;

await using root = await openDevelopment(reports, {
  stateDirectory: new URL("./.auths-delegation-state/", import.meta.url),
  allow: ["publish_report", "delete_report"],
  handlers: {
    async publish_report() {
      publishes += 1;
      return mcp.applied({ published: true });
    },
    async delete_report() {
      return mcp.applied({ deleted: true });
    },
  },
  reconcile: {
    async publish_report() { return mcp.inconclusive("unavailable"); },
    async delete_report() { return mcp.inconclusive("unavailable"); },
  },
});

const delegation = await root.delegate({
  allow: ["publish_report"],
  idempotencyKey: "delegate-weekly-report-agent-v1",
  name: "weekly-report-agent",
  expiresInMs: 5 * 60_000,
});
if (delegation.kind !== "delegated") {
  throw new Error(`delegation ${delegation.kind}: ${delegation.issue.code}`);
}
await using publisher = delegation.session;

const action = reports.call("publish_report", { period: "weekly" });
const first = await publisher.execute(action, {
  idempotencyKey: "weekly-report-2026-w33",
});
const replay = await publisher.execute(action, {
  idempotencyKey: "weekly-report-2026-w33",
});

if (
  first.kind !== "completed" || first.completion !== "executed" ||
  replay.kind !== "completed" || replay.completion !== "replayed" ||
  first.decisionReceipt.id !== replay.decisionReceipt.id ||
  first.executionReceipt.id !== replay.executionReceipt.id || publishes !== 1
) {
  throw new Error("exact replay invariant failed");
}
```

The narrower session's type excludes `delete_report`, and runtime/native validation still enforces that boundary for JavaScript, erased types, and adversarial values.

#### After: Python — development only

```python
import asyncio
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import auths.mcp as mcp

@dataclass(frozen=True)
class ReportArguments:
    period: str

@dataclass(frozen=True)
class ReportResult:
    published: bool

@dataclass(frozen=True)
class DeleteArguments:
    report_id: str

@dataclass(frozen=True)
class DeleteResult:
    deleted: bool

reports = mcp.Profile(service="reports.internal")
publish_report = reports.tool(
    "publish_report", arguments=ReportArguments, result=ReportResult,
)
delete_report = reports.tool(
    "delete_report", arguments=DeleteArguments, result=DeleteResult,
)
publishes = 0

async def publish(
    invocation: mcp.Invocation[ReportArguments],
) -> mcp.ProviderOutcome[ReportResult]:
    global publishes
    publishes += 1
    return mcp.Applied(ReportResult(published=True))

async def delete(
    invocation: mcp.Invocation[DeleteArguments],
) -> mcp.ProviderOutcome[DeleteResult]:
    return mcp.Applied(DeleteResult(deleted=True))

async def reconcile_publish(
    invocation: mcp.Invocation[ReportArguments],
    attempt: mcp.ProviderAttempt,
) -> mcp.ReconciliationOutcome[ReportResult]:
    return mcp.Inconclusive("unavailable")

async def reconcile_delete(
    invocation: mcp.Invocation[DeleteArguments],
    attempt: mcp.ProviderAttempt,
) -> mcp.ReconciliationOutcome[DeleteResult]:
    return mcp.Inconclusive("unavailable")

async def main() -> None:
    async with reports.development(
        allow=(publish_report, delete_report),
        handlers=(
            mcp.bind(publish_report, publish),
            mcp.bind(delete_report, delete),
        ),
        reconcilers=(
            mcp.observe(publish_report, reconcile_publish),
            mcp.observe(delete_report, reconcile_delete),
        ),
        state_directory=Path(".auths-delegation-state"),
    ) as root:
        delegation = await root.delegate(
            allow=(publish_report,),
            idempotency_key="delegate-weekly-report-agent-v1",
            name="weekly-report-agent",
            expires_in=timedelta(minutes=5),
        )
        if not isinstance(delegation, mcp.DelegatedSession):
            raise RuntimeError(
                f"delegation {delegation.kind}: {delegation.issue.code}"
            )
        async with delegation.session as publisher:
            action = publish_report.call(ReportArguments(period="weekly"))
            first = await publisher.execute(
                action, idempotency_key="weekly-report-2026-w33"
            )
            replay = await publisher.execute(
                action, idempotency_key="weekly-report-2026-w33"
            )

    assert isinstance(first, mcp.Completed)
    assert first.completion == "executed"
    assert isinstance(replay, mcp.Completed)
    assert replay.completion == "replayed"
    assert first.decision_receipt.id == replay.decision_receipt.id
    assert first.execution_receipt.id == replay.execution_receipt.id
    assert publishes == 1

if __name__ == "__main__":
    asyncio.run(main())
```

`delegate` takes allowed tools, not a caller-created child authority. Rust proves they are a subset of the parent service/profile/authority and binds expiry into the grant.

### 8.7 Execute an ordered plan, persist recovery, restart, and reconcile

#### Before

The current plan path needs separate profile resources, provider, action/plan constructors, root recovery references, and manual close. Its TypeScript and Python recipes are 126 and 160 lines. `ExecutionReference` looks generic but accepts the MCP `mcp1...` format only.

#### After: TypeScript — recoverable development only

```ts
import { open } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import {
  McpPlanRecoveryReference,
  mcp,
  type McpInvocation,
  type McpProviderAttempt,
} from "@auths-dev/sdk/mcp";
import { openDevelopment }
  from "@auths-dev/sdk/mcp/node";

const reports = mcp.profile({
  service: "reports.internal",
  tools: {
    publish_report: mcp.tool({
      input: mcp.model.object({ period: mcp.model.string() }),
      output: mcp.model.object({
        published: mcp.model.boolean(),
        period: mcp.model.string(),
      }),
    }),
  },
});
const plan = reports.plan(
  reports.call("publish_report", { period: "daily" }),
  reports.call("publish_report", { period: "weekly" }),
);

async function observeReport(period: string) {
  // Production profiles own this observer. This deterministic function is
  // only for the recoverable-development example.
  return {
    kind: "found" as const,
    observedAtUnixSeconds: BigInt(Math.floor(Date.now() / 1_000)),
    revision: `provider-revision-${period}`,
  };
}

async function reconcileReport(
  { input, attempt }: McpInvocation<
    { readonly period: string },
    "publish_report"
  > & Readonly<{ attempt: McpProviderAttempt }>,
) {
    const observed = await observeReport(input.period);
    const observation = {
      observerId: "reports-api/read-by-period/1",
      sourceId: "reports-api",
      executionId: attempt.executionId,
      requestCommitment: attempt.requestCommitment,
      observedAtUnixSeconds: observed.observedAtUnixSeconds,
      freshUntilUnixSeconds: observed.observedAtUnixSeconds + 60n,
      evidence: { kind: observed.kind, revision: observed.revision },
    };
    return mcp.observedApplied(
      { published: true, period: input.period },
      observation,
    );
}
const reconcilers = { publish_report: reconcileReport };

async function readRecoveryReference(path: string): Promise<Uint8Array> {
  const file = await open(path, "r");
  try {
    const value = new Uint8Array(16 * 1024 + 1);
    let offset = 0;
    while (offset < value.byteLength) {
      const { bytesRead } = await file.read(
        value, offset, value.byteLength - offset, offset,
      );
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > 16 * 1024) {
      throw new Error("recovery reference exceeds 16 KiB");
    }
    return value.slice(0, offset);
  } finally {
    await file.close();
  }
}

const [phase, stateDirectory, recoveryPath] = process.argv.slice(2);
if (!stateDirectory || !recoveryPath ||
    (phase !== "start" && phase !== "recover")) {
  throw new Error("usage: node restart.mjs start|recover STATE_DIR HANDLE");
}

if (phase === "start") {
  // Process 1 confirms the first member and loses certainty on the second.
  await using firstSession = await openDevelopment(reports, {
    stateDirectory,
    allow: ["publish_report"],
    handlers: {
      async publish_report({ input }) {
        if (input.period === "weekly") return mcp.possible("timeout");
        return mcp.applied({ published: true, period: input.period });
      },
    },
    reconcile: reconcilers,
  });
  const stopped = await firstSession.executePlan(plan, {
    idempotencyKey: "reports-2026-08-17",
  });
  if (stopped.kind !== "stopped" ||
      stopped.outcome.kind !== "recovery-required") {
    throw new Error("expected a recoverable second member");
  }
  const recoveryFile = await open(recoveryPath, "wx", 0o600);
  try {
    await recoveryFile.writeFile(stopped.outcome.recovery.toBytes());
    await recoveryFile.sync();
  } finally {
    await recoveryFile.close();
  }
  const recoveryDirectory = await open(
    dirname(resolve(recoveryPath)), "r",
  );
  try {
    await recoveryDirectory.sync();
  } finally {
    await recoveryDirectory.close();
  }
} else {
  // Process 2 reopens state. The normal handler throws to prove recovery
  // observes the domain and never re-enters the provider.
  await using restarted = await openDevelopment(reports, {
    stateDirectory,
    allow: ["publish_report"],
    handlers: {
      async publish_report() {
        throw new Error("provider must not be re-entered during recovery");
      },
    },
    reconcile: reconcilers,
  });
  const recovery = McpPlanRecoveryReference.fromBytes(
    await readRecoveryReference(recoveryPath),
  );
  const recovered = await restarted.recoverPlan(recovery);
  if (recovered.kind !== "completed" || recovered.members.length !== 2) {
    throw new Error("reconciliation did not establish completion");
  }
}
```

Save this as `restart.mts`, compile it with the declared local TypeScript dependency (`npm exec tsc -- --target ES2022 --module NodeNext --moduleResolution NodeNext --lib ES2022,ESNext.Disposable --outDir dist restart.mts`), then run two different processes: `node dist/restart.mjs start .auths-dev-state mcp-plan-recovery.bin`, followed by `node dist/restart.mjs recover .auths-dev-state mcp-plan-recovery.bin`. This works at the Node 20.6 floor and does not rely on newer built-in type stripping. The POSIX example uses exclusive handle creation with mode `0600`, file and containing-directory sync; Windows production code uses an owner-only secret store. If the process dies before receiving/persisting the handle, the second phase uses `recoverPlanByIdempotencyKey("reports-2026-08-17")` instead. It never blindly re-executes the uncertain member.

#### After: Python — recoverable development only

```python
import asyncio
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import auths.mcp as mcp

@dataclass(frozen=True)
class ReportArguments:
    period: str

@dataclass(frozen=True)
class ReportResult:
    published: bool
    report_id: str

reports = mcp.Profile(service="reports.internal")
publish_report = reports.tool(
    "publish_report", arguments=ReportArguments, result=ReportResult,
)
async def publish(
    invocation: mcp.Invocation[ReportArguments],
) -> mcp.ProviderOutcome[ReportResult]:
    if invocation.arguments.period == "weekly":
        return mcp.Possible("timeout")
    return mcp.Applied(ReportResult(
        published=True,
        report_id=invocation.arguments.period,
    ))

@dataclass(frozen=True)
class ReportObservationEvidence:
    kind: str
    revision: str

async def reconcile(
    invocation: mcp.Invocation[ReportArguments],
    attempt: mcp.ProviderAttempt,
) -> mcp.ReconciliationOutcome[ReportResult]:
    observed_at_unix_seconds = int(time.time())
    observation = mcp.Observation(
        observer_id="reports-api/read-by-period/1",
        source_id="reports-api",
        execution_id=attempt.execution_id,
        request_commitment=attempt.request_commitment,
        observed_at_unix_seconds=observed_at_unix_seconds,
        fresh_until_unix_seconds=observed_at_unix_seconds + 60,
        evidence=ReportObservationEvidence(
            kind="found",
            revision=f"provider-revision-{invocation.arguments.period}",
        ),
    )
    return mcp.ObservedApplied(
        value=ReportResult(
            published=True,
            report_id=invocation.arguments.period,
        ),
        observation=observation,
    )

def persist_secret(path: Path, value: bytes) -> None:
    if os.name != "posix":
        raise RuntimeError("use an owner-only Windows secret store")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent,
    )
    try:
        remaining = memoryview(value)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short recovery-reference write")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary_name, path)  # atomic publish; refuses overwrite
        os.unlink(temporary_name)
        temporary_name = ""
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            os.unlink(temporary_name)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)

def read_recovery_reference(path: Path) -> bytes:
    with path.open("rb") as source:
        value = source.read(16 * 1024 + 1)
    if len(value) > 16 * 1024:
        raise RuntimeError("recovery reference exceeds 16 KiB")
    return value

async def main() -> None:
    if len(sys.argv) != 4 or sys.argv[1] not in ("start", "recover"):
        raise SystemExit(
            "usage: python restart.py start|recover STATE_DIR HANDLE"
        )
    phase = sys.argv[1]
    state_directory = Path(sys.argv[2])
    recovery_file = Path(sys.argv[3])
    plan = reports.plan(
        publish_report.call(ReportArguments(period="daily")),
        publish_report.call(ReportArguments(period="weekly")),
    )

    if phase == "start":
        async with reports.development(
            allow=(publish_report,),
            handlers=(mcp.bind(publish_report, publish),),
            reconcilers=(mcp.observe(publish_report, reconcile),),
            state_directory=state_directory,
        ) as first_session:
            stopped = await first_session.execute_plan(
                plan, idempotency_key="reports-2026-08-17"
            )
            assert isinstance(stopped, mcp.PlanStopped)
            assert isinstance(stopped.outcome, mcp.PlanRecoveryRequired)
            persist_secret(
                recovery_file, stopped.outcome.recovery.to_bytes()
            )
    else:
        async def must_not_run(
            invocation: mcp.Invocation[ReportArguments],
        ) -> mcp.ProviderOutcome[ReportResult]:
            raise AssertionError(
                "provider must not be re-entered during recovery"
            )

        async with reports.development(
            allow=(publish_report,),
            handlers=(mcp.bind(publish_report, must_not_run),),
            reconcilers=(mcp.observe(publish_report, reconcile),),
            state_directory=state_directory,
        ) as restarted:
            recovery = mcp.PlanRecoveryReference.from_bytes(
                read_recovery_reference(recovery_file)
            )
            recovered = await restarted.recover_plan(recovery)
            assert isinstance(recovered, mcp.PlanCompleted)
            assert len(recovered.members) == 2

if __name__ == "__main__":
    asyncio.run(main())
```

Save this as `restart.py`, then run two different interpreters: `python restart.py start .auths-dev-state mcp-plan-recovery.bin`, followed by `python restart.py recover .auths-dev-state mcp-plan-recovery.bin`. **Development only:** filesystem persistence demonstrates genuine cross-process restart semantics but is not a production lifecycle store. Production profiles must use the full qualified product runtime and its durable state contract.

### 8.8 Run the GitHub issue-address workflow

#### Before

The current caller copies trusted server policy back into a broad task object:

```ts
const boundary = await auths.boundary();
const task = await auths.delegate({
  repository: boundary.repository,
  issueNumber: boundary.issueNumber,
  baseRef: boundary.baseRef,
  baseRevision: boundary.baseRevision,
  allowedPaths: boundary.allowedPaths,
  protectedPaths: boundary.protectedPaths,
  expiresInSeconds: boundary.maximumExpirySeconds,
  branchBudget: 1,
  draftPullRequestBudget: 1,
  agentLabel: "issue-agent",
});
```

Python has the same copy-back shape through `GitHubAgentTask`. Both APIs expose demo fixtures/replay operations and return only a receipt count.

#### After: TypeScript — production configuration

```ts
import { Buffer } from "node:buffer";
import { open } from "node:fs/promises";
import {
  connectGitHubIssueAddress,
  inspectGitHubReceipt,
} from "@auths-dev/sdk/github";
import {
  createVerifier,
  pinnedReceiptTrust,
} from "@auths-dev/sdk/verify";

function requiredSecret(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`missing deployment secret ${name}`);
  return value;
}

function ed25519Anchor(name: string): Uint8Array {
  const encoded = requiredSecret(name);
  if (!/^(?:[A-Za-z0-9+/]{4}){10}[A-Za-z0-9+/]{3}=$/.test(encoded)) {
    throw new Error(`invalid canonical base64 deployment secret ${name}`);
  }
  const value = new Uint8Array(Buffer.from(encoded, "base64"));
  if (value.byteLength !== 32 || Buffer.from(value).toString("base64") !== encoded) {
    throw new Error(`${name} must canonically decode to 32 bytes`);
  }
  return value;
}

async function readBoundedFile(
  path: string,
  maximumBytes: bigint,
): Promise<Uint8Array> {
  if (maximumBytes < 1n || maximumBytes > 16_777_216n) {
    throw new Error("invalid server candidate-byte boundary");
  }
  const file = await open(path, "r");
  try {
    const bytes = new Uint8Array(Number(maximumBytes) + 1);
    let offset = 0;
    while (offset < bytes.byteLength) {
      const { bytesRead } = await file.read(
        bytes, offset, bytes.byteLength - offset, offset,
      );
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > Number(maximumBytes)) {
      throw new Error("candidate bundle exceeds sealed boundary");
    }
    return bytes.slice(0, offset);
  } finally {
    await file.close();
  }
}

const receiptTrust = await pinnedReceiptTrust({
  allowedProfiles: [{ id: "auths.github.issue-address", version: 2 }],
  anchors: [
    {
      role: "decision",
      principal: "did:key:auths-prod-decision",
      verificationMethod: "did:key:auths-prod-decision#key-2026-08",
      suite: "ed25519-v1",
      publicKey: ed25519Anchor("AUTHS_DECISION_KEY_B64"),
    },
    {
      role: "execution",
      principal: "did:key:auths-prod-executor",
      verificationMethod: "did:key:auths-prod-executor#key-2026-08",
      suite: "ed25519-v1",
      publicKey: ed25519Anchor("AUTHS_EXECUTION_KEY_B64"),
    },
  ],
  maximumReceiptAgeSeconds: 24n * 60n * 60n,
});

await using github = await connectGitHubIssueAddress({
  endpoint: "https://auths-executor.example.com",
  controlPlaneAccessToken: requiredSecret("AUTHS_CONTROL_PLANE_TOKEN"),
  timeoutMs: 30_000,
});

const boundary = await github.boundary();
const delegationRequest = {
  boundary,
  agentLabel: "issue-agent",
  idempotencyKey: `delegate-${boundary.boundaryId}-issue-agent`,
} as const;
let delegated = await github.delegate(delegationRequest);
if (delegated.kind === "recovery-required") {
  delegated = await github.recoverDelegation(delegated.recovery);
}
if (delegated.kind !== "delegated") {
  throw new Error(`delegation failed: ${delegated.issue.code}`);
}

await using task = delegated.task;

const inspection = await task.inspect({
  bundle: await readBoundedFile(
    "./candidate.bundle",
    boundary.candidatePolicy.maximumCandidateBytes,
  ),
  candidateRevision: process.env.CANDIDATE_REVISION!,
});
if (inspection.kind === "denied") {
  throw new Error(`candidate denied: ${inspection.issue.code}`);
}

const executionKey =
  `issue-${boundary.issueNumber}-${inspection.candidate.candidateRevision}`;
let outcome = await task.execute(inspection.candidate, {
  idempotencyKey: executionKey,
});

if (outcome.kind === "recovery-required") {
  // Persist executionKey in the application's ordinary durable job record.
  // The key is correlation data, not a secret capability.
  outcome = await github.recoverExecutionByIdempotencyKey(executionKey);
}

const returnedReceipts =
  outcome.kind === "completed" ||
  outcome.kind === "partial" ||
  outcome.kind === "not-applied"
    ? outcome.receipts
    : outcome.kind === "denied" || outcome.kind === "indeterminate"
      ? [outcome.decisionReceipt]
      : [];

const verifier = await createVerifier();
let linkedDecisionReceipt: (typeof returnedReceipts)[number] | undefined;
for (const receipt of returnedReceipts) {
  const checked = verifier.verifyReceipt({
    receipt,
    trust: receiptTrust,
    ...(linkedDecisionReceipt === undefined
      ? {}
      : { linkedDecisionReceipt }),
  });
  if (checked.kind !== "verified") {
    throw new Error(`untrusted Auths receipt: ${checked.issue.code}`);
  }
  linkedDecisionReceipt =
    checked.details.kind === "decision" ? receipt : undefined;
  const profileInspection = inspectGitHubReceipt(checked);
  if (profileInspection.kind === "rejected") {
    throw new Error(`invalid GitHub receipt payload: ${profileInspection.issue.code}`);
  }
  const details = profileInspection.details;
  console.log(
    details.phase,
    details.kind === "decision"
      ? details.decision
      : details.result === "succeeded"
        ? details.providerObjectId
        : details.result,
  );
}

if (outcome.kind !== "completed" && outcome.kind !== "partial") {
  throw new Error(`workflow did not complete: ${outcome.issue.code}`);
}

if (outcome.kind === "partial") {
  console.error(
    `branch ${outcome.branch.ref} is published; draft PR disposition ` +
      `${outcome.pullRequestDisposition}: ${outcome.pullRequestIssue.code}`,
  );
  process.exitCode = 4;
} else {
  console.log(outcome.pullRequest.url);
}

// A later process uses the same persisted executionKey with
// github.recoverExecutionByIdempotencyKey(executionKey).
```

If a process loses the delegation response before receiving its opaque reference, it calls `recoverDelegationByIdempotencyKey(delegationRequest.idempotencyKey)` (Python: `recover_delegation_by_idempotency_key(delegation_key)`) after restart; it does not need to reconstruct the sealed boundary. This is production configuration only when all of the following are true: the endpoint is the promoted authenticated production route; the control-plane token and receipt anchors come from deployment secret/configuration management (environment variables above represent injection, not committed `.env` files); repository/issue/base/path/budget policy is operator-owned; GitHub credentials exist only in the executor; lifecycle and receipt state are durable; and local trust-pinned receipt verification succeeds. No GitHub token enters this application.

#### After: Python — production configuration

```python
import asyncio
import base64
import binascii
import os
from datetime import timedelta
from pathlib import Path
from typing import Optional

from auths import Receipt
from auths.github import (
    CandidateDenied,
    Completed,
    Delegated,
    DelegationRecoveryRequired,
    Denied as GitHubDenied,
    Indeterminate as GitHubIndeterminate,
    IssueClient,
    GitHubSucceededReceiptDetails,
    Partial,
    NotApplied,
    ReceiptRejected as GitHubReceiptRejected,
    RecoveryRequired,
    inspect_receipt as inspect_github_receipt,
)
from auths.verify import (
    ReceiptTrustAnchor,
    ReceiptProfile,
    VerifiedReceipt,
    pinned_receipt_trust,
    verify_receipt,
)

def required_secret(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing deployment secret {name}")
    return value

def ed25519_anchor(name: str) -> bytes:
    try:
        value = base64.b64decode(required_secret(name), validate=True)
    except (binascii.Error, ValueError) as error:
        raise RuntimeError(f"invalid base64 deployment secret {name}") from error
    if len(value) != 32:
        raise RuntimeError(f"{name} must decode to 32 bytes")
    return value

def read_bounded_file(path: Path, maximum_bytes: int) -> bytes:
    if maximum_bytes < 1 or maximum_bytes > 16_777_216:
        raise RuntimeError("invalid server candidate-byte boundary")
    with path.open("rb") as source:
        value = source.read(maximum_bytes + 1)
    if len(value) > maximum_bytes:
        raise RuntimeError("candidate bundle exceeds sealed boundary")
    return value

async def main() -> None:
    receipt_trust = pinned_receipt_trust(
        allowed_profiles=(
            ReceiptProfile(id="auths.github.issue-address", version=2),
        ),
        anchors=(
            ReceiptTrustAnchor(
                role="decision",
                principal="did:key:auths-prod-decision",
                verification_method="did:key:auths-prod-decision#key-2026-08",
                suite="ed25519-v1",
                public_key=ed25519_anchor("AUTHS_DECISION_KEY_B64"),
            ),
            ReceiptTrustAnchor(
                role="execution",
                principal="did:key:auths-prod-executor",
                verification_method="did:key:auths-prod-executor#key-2026-08",
                suite="ed25519-v1",
                public_key=ed25519_anchor("AUTHS_EXECUTION_KEY_B64"),
            ),
        ),
        maximum_receipt_age_seconds=24 * 60 * 60,
    )

    async with IssueClient(
        endpoint="https://auths-executor.example.com",
        control_plane_access_token=required_secret("AUTHS_CONTROL_PLANE_TOKEN"),
        timeout=timedelta(seconds=30),
    ) as github:
        boundary = await github.boundary()
        delegation_key = f"delegate-{boundary.boundary_id}-issue-agent"
        delegated = await github.delegate(
            boundary=boundary,
            agent_label="issue-agent",
            idempotency_key=delegation_key,
        )
        if isinstance(delegated, DelegationRecoveryRequired):
            delegated = await github.recover_delegation(
                delegated.recovery
            )
        if not isinstance(delegated, Delegated):
            raise RuntimeError(f"delegation failed: {delegated.issue.code}")

        async with delegated.task as task:
            inspection = await task.inspect(
                bundle=read_bounded_file(
                    Path("candidate.bundle"),
                    boundary.candidate_policy.maximum_candidate_bytes,
                ),
                candidate_revision=os.environ["CANDIDATE_REVISION"],
            )
            if isinstance(inspection, CandidateDenied):
                raise RuntimeError(f"candidate denied: {inspection.issue.code}")
            execution_key = (
                f"issue-{boundary.issue_number}-"
                f"{inspection.candidate.candidate_revision}"
            )
            outcome = await task.execute(
                inspection.candidate,
                idempotency_key=execution_key,
            )

        if isinstance(outcome, RecoveryRequired):
            # Persist execution_key in the application's durable job record.
            # It is correlation data, not a secret capability.
            outcome = await github.recover_execution_by_idempotency_key(
                execution_key
            )

        if isinstance(outcome, (Completed, Partial, NotApplied)):
            returned_receipts = outcome.receipts
        elif isinstance(outcome, (GitHubDenied, GitHubIndeterminate)):
            returned_receipts = (outcome.decision_receipt,)
        else:
            returned_receipts = ()

        linked_decision_receipt: Optional[Receipt] = None
        for receipt in returned_receipts:
            checked = verify_receipt(
                receipt,
                trust=receipt_trust,
                linked_decision_receipt=linked_decision_receipt,
            )
            if not isinstance(checked, VerifiedReceipt):
                raise RuntimeError(
                    f"untrusted Auths receipt: {checked.issue.code}"
                )
            linked_decision_receipt = (
                receipt if checked.details.kind == "decision" else None
            )
            profile_inspection = inspect_github_receipt(checked)
            if isinstance(profile_inspection, GitHubReceiptRejected):
                raise RuntimeError(
                    "invalid GitHub receipt payload: "
                    f"{profile_inspection.issue.code}"
                )
            details = profile_inspection.details
            if isinstance(details, GitHubSucceededReceiptDetails):
                print(details.phase, details.provider_object_id)
            elif details.kind == "execution":
                print(details.phase, details.result)
            else:
                print(details.phase, details.decision)

        if not isinstance(outcome, (Completed, Partial)):
            raise RuntimeError(
                f"workflow did not complete: {outcome.issue.code}"
            )

        if isinstance(outcome, Partial):
            print(
                "branch published; draft PR disposition:",
                outcome.branch_ref,
                outcome.pull_request_disposition,
                outcome.pull_request_issue.code,
            )
        else:
            print(outcome.pull_request_url)

if __name__ == "__main__":
    asyncio.run(main())
```

The production preconditions are identical to TypeScript. Reading the file is visibly application-owned, and the bytes are copied before inspection.

### 8.9 Verify remotely without creating a generic execution escape hatch

#### Before

The current `/service` module presents raw bytes alongside the normal product, offers unauthenticated `create`/`delegate` verbs that the maintained server refuses, and also exposes a generic execution verb even though maintained execution routes are profile-specific.

#### After: TypeScript — advanced, production configuration

```ts
import { open } from "node:fs/promises";
import { connectRemoteVerifier }
  from "@auths-dev/sdk/protocol";

const accessToken = process.env.AUTHS_VERIFY_ACCESS_TOKEN;
if (!accessToken) throw new Error("missing AUTHS_VERIFY_ACCESS_TOKEN");

const paths = process.argv.slice(2);
if (paths.length !== 3) {
  throw new Error("usage: node verify.mjs PROOF ACTION TRUSTED_CONTEXT");
}
const [proofPath, actionPath, contextPath] = paths as [string, string, string];

async function readBoundedInput(
  path: string,
  maximumBytes: number,
): Promise<Uint8Array> {
  const source = await open(path, "r");
  try {
    const value = new Uint8Array(maximumBytes + 1);
    let offset = 0;
    while (offset < value.byteLength) {
      const { bytesRead } = await source.read(
        value, offset, value.byteLength - offset, offset,
      );
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > maximumBytes) throw new Error(`input too large: ${path}`);
    return value.slice(0, offset);
  } finally {
    await source.close();
  }
}

await using verifier = await connectRemoteVerifier({
  endpoint: "https://auths-verifier.example.com",
  accessToken,
  timeoutMs: 10_000,
});

const result = await verifier.verify({
  proof: await readBoundedInput(proofPath, 256 * 1024),
  action: await readBoundedInput(actionPath, 2 * 1024 * 1024),
  trustedContext: await readBoundedInput(contextPath, 2 * 1024 * 1024),
});

if (result.kind === "authorized") {
  console.log("authorized evidence; no command was produced");
} else {
  console.error(result.kind, result.issue.code);
  process.exitCode = result.kind === "denied" ? 2 : 3;
}
```

#### After: Python — advanced, production configuration

```python
import asyncio
import os
import sys
from pathlib import Path

import auths.protocol as protocol
from auths.verify import AuthorizedVerification, VerificationInput

def read_bounded_input(path: Path, maximum_bytes: int) -> bytes:
    with path.open("rb") as source:
        value = source.read(maximum_bytes + 1)
    if len(value) > maximum_bytes:
        raise RuntimeError(f"input too large: {path}")
    return value

async def main() -> int:
    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: python verify.py PROOF ACTION TRUSTED_CONTEXT"
        )
    proof_path, action_path, context_path = map(Path, sys.argv[1:])
    access_token = os.environ.get("AUTHS_VERIFY_ACCESS_TOKEN")
    if not access_token:
        raise RuntimeError("missing AUTHS_VERIFY_ACCESS_TOKEN")

    async with protocol.connect_remote_verifier(
        endpoint="https://auths-verifier.example.com",
        access_token=access_token,
    ) as verifier:
        result = await verifier.verify(VerificationInput(
            proof=read_bounded_input(proof_path, 256 * 1024),
            action=read_bounded_input(action_path, 2 * 1024 * 1024),
            trusted_context=read_bounded_input(
                context_path, 2 * 1024 * 1024,
            ),
        ))

    if isinstance(result, AuthorizedVerification):
        print("authorized evidence; no command was produced")
        return 0
    print(result.kind, result.issue.code)
    return 2 if result.kind == "denied" else 3

if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
```

This is intentionally the full advanced protocol capability: bounded, authenticated, effect-free remote verification. It cannot import authority, derive a provider request, execute an action, or recover a workflow. OpenTofu and PostgreSQL execution are absent until each receives a typed profile vertical; applications cannot bypass that qualification gate with bytes and an operation string.

### 8.10 Implement and test an advanced adapter wrapper

The following is deliberately a **development/test** example: it wraps the shipped ephemeral signer so the file is executable without a cloud account. The same wrapper shape can surround a production KMS signer, but production configuration must supply a durable, independently qualified signer and map provider behavior only into the closed `CustodySignResult` variants; it must never silently fall back to the ephemeral signer.

TypeScript custody adapter:

```ts
import {
  type CustodySigner,
  type CustodySignResult,
  type SigningRequest,
} from "@auths-dev/sdk/adapters";
import {
  conformance,
  ephemeralEd25519Signer,
} from "@auths-dev/sdk/testkit";

class AuditedSigner implements CustodySigner {
  constructor(private readonly inner: CustodySigner) {}

  get descriptor() { return this.inner.descriptor; }

  sign(request: SigningRequest): Promise<CustodySignResult> {
    return this.inner.sign(request);
  }

  async close() { await this.inner.close(); }
  async [Symbol.asyncDispose]() { await this.close(); }
}

const report = await conformance.custodySigner(async () =>
  new AuditedSigner(await ephemeralEd25519Signer())
);
if (!report.passed) throw new Error(JSON.stringify(report.cases));
```

Python custody adapter:

```python
import asyncio

from auths.adapters.custody import (
    CustodyDescriptor,
    CustodySignResult,
    CustodySigner,
    SigningRequest,
)
from auths.testkit import (
    ephemeral_ed25519_signer,
    run_custody_signer_conformance,
)

class AuditedSigner:
    def __init__(self, inner: CustodySigner) -> None:
        self._inner = inner

    @property
    def descriptor(self) -> CustodyDescriptor:
        return self._inner.descriptor

    async def sign(self, request: SigningRequest) -> CustodySignResult:
        return await self._inner.sign(request)

    async def aclose(self) -> None:
        await self._inner.aclose()

def create_test_signer() -> CustodySigner:
    return AuditedSigner(ephemeral_ed25519_signer())

async def check_audited_signer() -> None:
    report = await run_custody_signer_conformance(create_test_signer)
    if not report.passed:
        raise RuntimeError(report.cases)

if __name__ == "__main__":
    asyncio.run(check_audited_signer())
```

Passing conformance means only that the observed adapter behavior passed the versioned test suite. It is not a security certification. Production qualification still requires review, operational controls, failure injection, and hosted evidence.

## 9. Progressive disclosure for advanced capabilities

### 9.1 Protocol access

`/protocol` is reachable by an explicit import and has full typing for bounded request/response envelopes, authenticated remote verification, cancellation, transport ownership, and disposal. It is intentionally absent from root autocomplete and the first README screen. Its documentation begins with:

> Advanced, effect-free protocol. Inputs are canonical Auths proof, action, and trusted-context bytes. An authorized response is evidence only. This module cannot create/import/delegate authority, construct a provider command, execute an effect, or recover an execution.

The public transport receives a client-resolved closed verification URL and cannot choose an operation or decode profile semantics. Profile clients may share private transport mechanics, but they do not route effectful work through this public interface. There is no public byte-level fallback for an unqualified execution profile.

### 9.2 Profile qualification gate

A profile identifier may appear in private wire manifests when the runtime supports it. It becomes a public top-level SDK module only in the same review unit that supplies all of the following; there is no public marker-only intermediate state:

1. a Rust-owned profile/version and canonical action;
2. a typed, inert language action model with no arbitrary SQL/shell/provider request;
3. explicit authority and attenuation fields;
4. exact required/executed configuration commitments;
5. profile decision and denial codes in the registry;
6. a closed provider request constructed only after durable exact-action claim;
7. least-privilege credential ordering and a fresh state reread;
8. a profile-specific outcome and recovery reference;
9. profile-owned observation/reconciliation;
10. portable linked receipts and local verification;
11. denial-before-credential and exact-provider-request tests;
12. concurrency, crash, restart, replay, corruption, and reconciliation tests;
13. a clean npm/wheel recipe with no repository/Rust dependency; and
14. TypeScript/Python/Rust semantic-parity fixtures;
15. a complete vertical demonstration with a real native backend and real sandbox/provider effect, Docker-local HTTP, a connected frontend exposing controls/results, inline and dedicated receipt views, browser E2E where the profile is browser-facing, and a safe public deployment when the threat model permits it;
16. exact valid, invalid, boundary+1, stale, mutated, required/executed-configuration mismatch, denial-before-provider, provider-request equality, concurrency, crash, replay, outcome-unknown, and reconciliation scenarios across that vertical;
17. canonical positive/negative fixtures, a mutation corpus, property and arithmetic tests for every budget, secret scans, and redacted deployment evidence; and
18. architecture/compliance registration plus authoritative CI evidence for the exact source revision being promoted.

Items 15–18 are the boundary plan's complete-vertical and evidence-closure phases, not optional SDK polish. In particular, the stable GitHub v2 module remains absent until the native executor, localhost server, connected UI/receipt experience, mutation/fault corpus, scans, redacted hosted evidence, and exact-revision CI all pass together. A package-only green matrix cannot qualify a vertical.

For OpenTofu, the eventual typed action must contain the immutable saved-plan identity/commitment, working context, allowed workspace/backend facts, and required configuration. The provider port exposes `applySavedPlan`, never a command string, shell, or re-plan callback. Recovery observes the exact run; it never blindly reapplies.

For PostgreSQL, the eventual typed action must contain the closed table/update predicate/value model and exact row/budget commitments. It must not contain arbitrary SQL. The provider owns a serializable transaction and shared durable ledger protocol; ambiguous commit is reconciled by fresh database observation, not resubmission.

Until those gates pass, the marker factories stay removed. This is a deliberate honesty improvement, not a loss of runtime access.

### 9.3 Framework and server integration

The core SDK does not depend on Express, Fastify, Next.js, Django, Flask, or FastAPI and does not expose a generic `FrameworkAdapter(callback)`.

Client integration uses ordinary application lifecycle hooks:

- construct one GitHub/protocol client in application startup;
- store it in framework state/dependency injection;
- pass request cancellation (`AbortSignal`) or propagate Python task cancellation;
- call the exact profile method in the route/job handler; and
- close it during graceful shutdown after admission stops.

Documentation ships copyable recipes for Fastify, Next.js route handlers, FastAPI lifespan, Django ASGI lifespan, and a queue worker. Those recipes call the same public profile API; no framework-specific security semantics exist.

The Fastify recipe is a complete singleton-lifecycle integration for the effect-free remote verifier. It validates the HTTP body before decoding, connects once at startup, propagates disconnect cancellation, maps exhaustive security outcomes to HTTP status, and closes on graceful shutdown:

```ts
import { Buffer } from "node:buffer";
import Fastify from "fastify";
import { isAuthsError } from "@auths-dev/sdk";
import { connectRemoteVerifier }
  from "@auths-dev/sdk/protocol";

const token = process.env.AUTHS_VERIFY_ACCESS_TOKEN;
if (!token) throw new Error("missing AUTHS_VERIFY_ACCESS_TOKEN");

const verifier = await connectRemoteVerifier({
  endpoint: "https://auths-verifier.example.com",
  accessToken: token,
  timeoutMs: 10_000,
});
const app = Fastify({ logger: true, bodyLimit: 5_943_000 });
app.addHook("onClose", async () => verifier.close());

interface VerifyBody {
  proof: string;
  action: string;
  trustedContext: string;
}
const encodedBytes = (maximum: number) => ({
  type: "string",
  minLength: 4,
  maxLength: maximum,
  pattern: "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
} as const);

app.post<{ Body: VerifyBody }>("/verify", {
  schema: {
    body: {
      type: "object",
      additionalProperties: false,
      required: ["proof", "action", "trustedContext"],
      properties: {
        proof: encodedBytes(349_528),       // base64(256 KiB)
        action: encodedBytes(2_796_204),    // base64(2 MiB)
        trustedContext: encodedBytes(2_796_204),
      },
    },
  },
}, async (request, reply) => {
  const cancellation = new AbortController();
  request.raw.once("aborted", () => cancellation.abort());
  reply.raw.once("close", () => {
    if (!reply.raw.writableEnded) cancellation.abort();
  });
  try {
    const result = await verifier.verify({
      proof: new Uint8Array(Buffer.from(request.body.proof, "base64")),
      action: new Uint8Array(Buffer.from(request.body.action, "base64")),
      trustedContext: new Uint8Array(
        Buffer.from(request.body.trustedContext, "base64"),
      ),
      signal: cancellation.signal,
    });
    if (result.kind === "authorized") {
      return reply.code(200).send({ kind: result.kind });
    }
    const status = result.kind === "denied" ? 403 : 503;
    return reply.code(status).send({
      kind: result.kind,
      code: result.issue.code,
      correlationId: result.issue.correlationId,
    });
  } catch (error) {
    if (!isAuthsError(error)) throw error;
    return reply.code(503).send({
      kind: "operational-error",
      code: error.code,
      correlationId: error.details.correlationId,
    });
  }
});

await app.listen({ host: "127.0.0.1", port: 3000 });
```

The FastAPI recipe expresses the same ownership and status mapping idiomatically. ASGI task cancellation propagates through the cancellation-aware verifier transport; because verification is inert, disconnect needs no recovery handle:

```python
import base64
import binascii
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, StringConstraints
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from typing_extensions import Annotated

from auths import AuthsError
from auths.protocol import RemoteVerifier, connect_remote_verifier
from auths.verify import AuthorizedVerification, VerificationInput

BASE64_PATTERN = (
    r"^(?:[A-Za-z0-9+/]{4})*"
    r"(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
)
ProofBase64 = Annotated[
    str, StringConstraints(min_length=4, max_length=349_528,
                           pattern=BASE64_PATTERN),
]
LargeBase64 = Annotated[
    str, StringConstraints(min_length=4, max_length=2_796_204,
                           pattern=BASE64_PATTERN),
]

class VerifyBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proof: ProofBase64
    action: LargeBase64
    trusted_context: LargeBase64

class _RequestTooLarge(Exception):
    pass

class RequestBodyLimitMiddleware:
    def __init__(self, app: ASGIApp, maximum_bytes: int) -> None:
        self.app = app
        self.maximum_bytes = maximum_bytes

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        consumed = 0

        async def limited_receive() -> Message:
            nonlocal consumed
            message = await receive()
            if message["type"] == "http.request":
                consumed += len(message.get("body", b""))
                if consumed > self.maximum_bytes:
                    raise _RequestTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _RequestTooLarge:
            await send({
                "type": "http.response.start",
                "status": 413,
                "headers": [(b"content-type", b"application/json")],
            })
            await send({
                "type": "http.response.body",
                "body": b'{"detail":"request body too large"}',
            })

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    token = os.environ.get("AUTHS_VERIFY_ACCESS_TOKEN")
    if not token:
        raise RuntimeError("missing AUTHS_VERIFY_ACCESS_TOKEN")
    async with connect_remote_verifier(
        endpoint="https://auths-verifier.example.com",
        access_token=token,
    ) as verifier:
        app.state.auths_verifier = verifier
        yield

app = FastAPI(lifespan=lifespan)
app.add_middleware(RequestBodyLimitMiddleware, maximum_bytes=5_943_000)

def decode_b64(value: str, maximum_decoded_bytes: int) -> bytes:
    maximum_encoded = 4 * ((maximum_decoded_bytes + 2) // 3)
    if len(value) > maximum_encoded:
        raise HTTPException(413, "encoded field too large")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as cause:
        raise HTTPException(400, "malformed base64") from cause
    if len(decoded) > maximum_decoded_bytes:
        raise HTTPException(413, "decoded field too large")
    return decoded

@app.post("/verify")
async def verify(body: VerifyBody, request: Request) -> dict[str, str]:
    verifier: RemoteVerifier = request.app.state.auths_verifier
    try:
        result = await verifier.verify(VerificationInput(
            proof=decode_b64(body.proof, 256 * 1024),
            action=decode_b64(body.action, 2 * 1024 * 1024),
            trusted_context=decode_b64(
                body.trusted_context, 2 * 1024 * 1024,
            ),
        ))
    except AuthsError as error:
        raise HTTPException(
            503,
            {"code": error.code, "correlation_id": error.info.correlation_id},
        ) from error
    if isinstance(result, AuthorizedVerification):
        return {"kind": "authorized"}
    status = 403 if result.kind == "denied" else 503
    raise HTTPException(
        status,
        {"kind": result.kind, "code": result.issue.code,
         "correlation_id": result.issue.correlation_id},
    )
```

These are production configuration examples only when the HTTPS origin and access token are deployment-managed and the remote verifier is a promoted Auths service. Localhost development must opt in explicitly; neither recipe accepts a provider credential or performs an external effect.

Production server-side effect execution remains in the Rust product runtime/sidecar so canonical commands, credentials, lifecycle transitions, and observation cannot be forged by JS/Python middleware. If a future in-process server binding is required, it must be profile-specific and expose a standard Fetch `Request -> Response` or ASGI callable around a sealed Rust runtime. It must not expose evaluator, command, credential, transition, or generic execution callbacks.

### 9.4 Identity extensions

Normal authentication needs one factory/shortcut. Resolvers, identity methods, message authenticators, packet authoring, and custody signing are accessible in the adjacent advanced modules. The split prevents a first-time user from treating method registration as authority configuration while preserving resolvable enterprise identities.

### 9.5 Adapter contracts

`/adapters` contains only the custody and narrow atomic-reservation contracts that the mechanism catalog marks `publish-framework` and whose output the Rust boundary independently validates. Approval transactions stay internal until AP-SPEC-029 and a catalog-backed conformance suite are complete. Full production lifecycle storage is intentionally absent until its complete specification is represented. External adapters should normally be separate packages named for the provider (for example, a future `@auths-dev/custody-aws-kms` or `auths-custody-aws-kms`) and declare the compatible contract version.

### 9.6 Testkit

Testkit is one deliberate side door, not a shadow SDK. It provides inert verification/GitHub-denial fixtures, one ephemeral custody signer, and versioned custody/reservation/transport conformance reports. Identity/method/authenticator fakes and suites remain internal because the Rust catalog owns no publishable conformance contract for them. Diagnostic event streams are tested through the real profile session; no callback/recorder can delay or influence lifecycle transitions. Deterministic clocks and lifecycle checkpoint faults remain internal harness controls because no public production entry point accepts them. Testkit cannot mint a production-accepted verification capability or generic command. Repository manifest/product-waist checks remain private CI tooling.

## 10. Documentation and discoverability design

### 10.1 First README experience

The root README is short and task-driven. Its first screen is, in order:

1. one-sentence product promise;
2. install command and “no Rust toolchain required”;
3. a boxed heading: **DEVELOPMENT ONLY — local trust and secret-bearing single-machine state; not production durability**;
4. the complete one-action MCP example from section 8.2;
5. the complete outcome table;
6. the production GitHub example link and its production prerequisites; and
7. a task-to-import navigation table.

It does not mention the advanced transport/remote verifier before the navigation table, does not link outside the packed package, and does not claim publication or independent review status from repository-local evidence.

The outcome table is:

| Outcome | Meaning | Application action |
|---|---|---|
| completed / executed | one effect completed | use value and verify/store receipt |
| completed / replayed | prior identical effect returned | use original value/receipt; no new effect |
| completed / reconciled | fresh observation established completion | use reconciled value/receipt |
| partial | an earlier phase applied; a later phase is denied/indeterminate before entry or is proven not applied | verify/store every receipt, surface the applied object plus later-phase disposition/issue, and never repeat the applied phase |
| denied / indeterminate | no provider effect was entered | correct authority/trust/configuration; do not treat as success |
| not applied | this attempt's provider effect is proved absent | follow `retry` and `recommendedAction` |
| conflict | the changed request did not enter; the original same-key workflow may be applied or uncertain | recover the original key; never infer global non-application |
| recovery required | effect may have happened | persist the reference-or-key locator; never repeat blindly; recover/reconcile |
| failed | effect is known applied but terminally unsuccessful | inspect receipt and operator guidance; do not blind retry |

### 10.2 Package-local documentation tree

Both artifacts ship the same conceptual documentation:

```text
README
examples/
  mcp-one-action
  mcp-delegation-replay
  mcp-plan-restart-recovery
  offline-verification
  identity-authentication
  github-production
docs/
  outcomes-and-errors
  lifecycle-cancellation-disposal
  production-checklist
  receipts
  adapters-and-conformance
  remote-verification-and-transports
```

Every README link resolves inside the packed artifact or to a stable public HTTPS page. Each example states whether it is development, test, advanced, or production configuration in its title and first comment.

### 10.3 API reference rules

- Every public type has one canonical import path and one task-oriented page.
- Each method documents effect boundary, idempotency requirement, cancellation after entry, ownership, and possible outcomes.
- Error-code pages are generated from the Rust registry and include code, stage, effect/retry combinations, recommended action, and whether a recovery/decision/receipt reference may appear.
- Profile pages begin with authority and credential boundaries, not method lists.
- Examples construct protocol proof/action/context bytes only under the advanced remote-verification documentation; no example constructs an effect command or authority bytes.
- Search keywords include the old task words (“resume,” “replay,” “service client”) but link to the new concepts; no old symbol is exported.
- TypeScript declaration examples are compiled with `NodeNext`, `Bundler`, `strict`, and `exactOptionalPropertyTypes`.
- Python examples are executed plus checked with strict mypy and Pyright from an installed wheel.

### 10.4 Diagnostics

`auths doctor` remains the npm binary; Python exposes the identical command as `python -m auths doctor`. This cut is deliberately offline-only: it opens no socket, reads no application configuration, and reports only observed installed-package/native facts. Live facts belong to an already-authenticated profile client's `diagnostics()`; the CLI does not invent a generic diagnostics route. The exact CLI is:

```text
auths doctor [--json]
auths doctor --help
auths doctor --version
```

Unknown flags, positional arguments, conflicting `--help`/`--version`, and every removed caller-asserted `--mode`, `--state`, `--durable`, or `--live` option are usage errors. `--help` and `--version` write bounded plain text and exit without loading native/WASM runtime state.

Human output is a bounded table. `--json` emits one canonical UTF-8 object with no ANSI text and this exact versioned shape (camelCase in both binaries):

```json
{
  "schema": "auths.doctor/1",
  "status": "ok",
  "mode": "offline",
  "sdk": {
    "language": "typescript",
    "sdkVersion": "1.0.0",
    "hostVersion": "22.0.0",
    "platform": "darwin-arm64"
  },
  "runtime": {
    "authoringAbi": 1,
    "identityAbi": 1,
    "errorRegistryDigest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "compatible": true,
    "semanticSubjects": [
      "auths.product.reservation-execution-contract/2",
      "auths.mcp-session/2"
    ],
    "profiles": ["auths.mcp/2"],
    "capabilities": ["verify.offline"]
  },
  "checks": [
    {"id": "package-native-abi", "status": "passed", "code": "compatible"}
  ],
  "warnings": []
}
```

For Python, `language` is `python`, `hostVersion` is the CPython version, and `nativeAbi` replaces `authoringAbi`; all other wire keys remain identical. Check IDs and codes are generated bounded tokens; statuses are `passed | failed`. Arrays contain at most 128 entries, tokens at most 128 bytes, warnings at most 32 redacted strings of 256 Unicode scalars, and no environment variable, user path, network endpoint, or caller assertion enters the report.

Exit codes are stable: `0` all checks passed; `2` an observed package/runtime compatibility check failed; `64` invalid CLI usage; `70` unexpected internal failure. JSON is still emitted for exit 2. Logs never contain credentials, proof/action/context bytes, receipt/recovery bytes, filesystem contents, paths outside the package, or environment-variable names. Library `runtimeInfo()`/`runtime_info()` returns the same observed subset; authenticated profile clients/sessions expose profile-specific live `diagnostics()`.

## 11. Measurable adoption and usability acceptance criteria

Cutover is blocked until all of these pass against packed artifacts.

### 11.1 Zero-context study

Run separate TypeScript and Python studies with at least five developers per language who have not worked in this repository. Give only the public package name and README.

- At least four of five per language complete and locally verify one development MCP action within 15 minutes; median is under 10 minutes.
- All participants correctly identify the MCP example as non-production.
- All participants can explain identity versus authority and offline authorization versus execution.
- All participants correctly handle a denied result and a recovery-required result without being told whether blind retry is safe.
- At least four of five find the GitHub production entry point and list its credential/durability prerequisites within five minutes.
- No participant uses a private import, repository path, generic byte executor, or Rust tool.

Record cohort size, anonymized completion time, incorrect turns, questions, and task outcome. A zero-size cohort cannot be reported as time-to-value verified.

### 11.2 Mechanical discoverability budgets

- First meaningful MCP result: one profile import, one session factory/context, one exact action call, at most three required effect-call inputs (`action`, `idempotency key`, optional cancellation).
- No application-orchestrated security transition in the beginner path; the app supplies domain handler and handles outcome only.
- Root has zero effectful client/session factory. TypeScript's callable/value surface is exactly `AuthsError`, `isAuthsError`, and `runtimeInfo`; Python additionally has its idiomatic enum/dataclass classes but only `runtime_info` performs initialization/inspection. `Receipt` has no public constructor in either language.
- Generated target inventories contain exactly 150 TypeScript and 175 Python exports including testkit (from baselines of 203 and 180). Counts include declaration closure, not only barrels. The explicit decision/execution receipts, staged identity descriptor, phase-aware partial, and recovery-locator variants prevent impossible or security-ambiguous states; the usability study, module isolation, and first-path budgets remain the primary measures.
- Every proposed export is consumed by a public signature, a copyable example, or a public conformance contract; an unreferenced export blocks cutover.
- The first MCP example uses at most two canonical import paths and mentions at most twelve public names (currently ten TypeScript names and eleven Python names); the extraction test measures this rather than pretending the explicit outcome/reconciliation variants do not exist.
- Zero marker-only profile exports.
- Zero ambiguous action/plan overloads or mutually exclusive optional action parameters.
- Zero expected security states represented only by exceptions.
- Every possible-effect value contains a durable recovery locator or an explicit operator correlation when no caller recovery is possible.
- Every public profile has typed action, authority/delegation, outcome, recovery, receipt, packed example, and conformance evidence.

### 11.3 Documentation and package criteria

- 100% of proposed declaration blocks parse, and every **After**/packaged-recipe block is extracted into a complete file, executed where effect-free/development fixtures permit, and strict-type-checked. **Before** blocks are frozen regression evidence and are checked against the current package separately rather than mixed into target-package tests.
- 100% of package-local links resolve after `npm pack`/wheel build.
- All six packaged recipe categories in section 10.2 run from each clean artifact, including cross-process restart.
- Normal imports contain no repository-relative paths or deep `dist` imports.
- Install and first example succeed with Cargo/Rust removed from `PATH` and empty package caches except the downloaded artifact.
- `npm install --ignore-scripts` succeeds; the wheel performs no compilation.

### 11.4 Operational criteria

- Every registered error code has an identical Rust/TS/Python projection; an unknown-code fixture is rejected during capability negotiation, never accepted as `auths.error/1`.
- Every session/client reports ownership and durability accurately.
- No normal negative result requires parsing a message string.
- A support engineer can diagnose ABI mismatch, config mismatch, denial, provider not-applied, possible effect, and invalid receipt using only stable fields and correlation/recovery references.

## 12. Required cutover tests

### 12.1 Security and adversarial input

- Differential Rust/TypeScript/Python fixtures for verdict, stage, code, metrics, configuration commitments, action/plan commitments, effect, retry, recovery identity, and receipt bytes.
- MCP v2 contract tests prove profile `{id:"auths.mcp",version:2}` and session subject `auths.mcp-session/2` are emitted everywhere, v1 fixtures retain their original meaning, no v1 value is accepted as v2, and the public API has no alias/coercion between them.
- Mutation tests for every proof, action, context, authority, recovery, and receipt field/signature/link.
- Receipt trust tests for signer role/principal/method/suite/key substitution, untrusted receipt-carried keys, exact `{id, version}` profile matching, profile-version substitution, `p256-sha256-v1`, expired/future timestamps, indeterminate trust material, missing/wrong/cross-workflow linked decision receipts, a forbidden link on decision-only receipts, and non-round Unix-second fixtures that catch 1,000× conversion drift.
- After envelope trust succeeds, MCP/GitHub inspector tests cover wrong profile, unknown payload version, malformed/oversized payload, field/envelope inconsistency, and fabricated/mutated `VerifiedReceipt`; all return profile-specific rejected values and no details.
- Identity/custody timestamp fixtures prove `observed/expires_*_unix_seconds` project Rust seconds exactly; MCP/GitHub/event millisecond fields remain separately named and bounded.
- Unknown version, non-canonical encoding, duplicate/map-order, trailing data, over-depth, oversized collection, aggregate-byte, work-unit, integer-overflow, NaN/infinity, cyclic JS object, hostile Python object, getter/serializer, and malformed UTF-8 tests.
- Capability forgery tests: object literal/cast, prototype replacement, cross-realm value, copy/deepcopy, pickle, subclass, reflection, buffer mutation, and byte promotion.
- Verify that offline authorized results cannot reach any provider/gateway and expose no canonical command or credential request.
- Verify identity authentication cannot be passed as authority without an explicit Rust-owned authority operation.

### 12.2 Ordering and fail-closed behavior

- Denial and required/executed configuration mismatch before approval, signer, credential, and provider entry as applicable.
- Durable decision before reservation; reservation before exact-action claim; exact claim before credential; fresh reread before provider.
- Exact provider request byte/value equality to the Rust-owned closed command, followed by a profile-owned durable provider-result write before any observation or receipt transition.
- Credential scope, expiry, and audience are a subset of exact claimed action and profile boundary.
- No credential on replay, conflict, denial, indeterminate verification, invalid candidate, or substituted action/plan member.
- An unknown registry code fails capability negotiation before a new effect; an already-entered workflow returns its registered phase-specific recovery-required value without dropping the recovery/operator reference.

### 12.3 Concurrency, replay, crash, and recovery

- 100 concurrent same-key/same-action calls: exactly one provider entry; all others receive original completion or same recovery identity.
- With the winning same-key operation already provider-entered, callers 2 through 256 may wait; caller 257 performs the bounded non-waiting durable lookup and receives the winner's terminal value or exact recovery identity, never a pre-effect capacity result.
- Same key/different commitment: conflict, zero provider entry.
- Final-capacity race: one winner under linearizable reservation.
- Crash/fault injection after every required lifecycle checkpoint, including before/after provider transmission, before/after the profile-owned durable provider-result write, before/after fresh observation, and before/after receipt persistence. A crash after provider response but before durable provider result remains possible/recoverable; a durable result is replayed into observation without provider re-entry.
- Restart from packed-package example with no in-memory objects retained.
- Recovery/reconciliation never re-enters the effect provider unless a profile specification explicitly proves a safe operation; MCP and GitHub tests require observation-only reconciliation.
- Ordered plan stops exactly at the first unresolved member and preserves the completed prefix/receipts.
- Corrupt, truncated, swapped-workflow, stale, and cross-profile recovery handles fail closed.

### 12.4 Cancellation and disposal

- Abort/cancel at every pre- and post-entry checkpoint.
- Pre-entry cancellation is provably not applied.
- Post-entry cancellation persists and returns/retrieves recovery; no naked transport/cancellation exception loses effect state.
- Idempotent close, use-after-close, close during open, close during effect, parent-child reverse close order, partial-open cleanup, borrowed versus owned transport/provider behavior.
- Event-stream stress with an abandoned subscriber and more than 10,000 transitions: fixed 64-event memory, oldest-event eviction, exact `droppedBefore` accounting, no lifecycle delay, iterator cancellation isolation, and deterministic session-close termination.
- No leaked SDK-owned or untracked tasks, threads, file descriptors, native handles, temporary files, or filesystem locks. The only allowed outstanding work is the explicitly reported, process-wide-bounded borrowed development callback described in section 4.5; tests keep it charged until settlement and prove the 33rd admission fails before entry.
- Python specifically proves no effectful request continues in an untracked executor thread after `CancelledError`; a cancellation-suppressing borrowed handler remains tracked, counted, and documented as capable of keeping the application event loop alive.

### 12.5 GitHub profile

- Boundary fields are server-owned; caller can only narrow allowed paths/expiry.
- Protected path, base mismatch, uncommitted content, symlink/path traversal, oversized bundle, malformed Git object, and candidate substitution deny before credential.
- SHA-1/SHA-256 revision-length substitution, uppercase/abbreviated IDs, non-UTF-8/non-NFC paths, separator/dot-component tricks, component-`*` and whole-component-`**` positive/negative cases, embedded-`**`/`?`/bracket/regex syntax, deny-first conflicts, and a narrowed rule not present byte-for-byte in the boundary all deny before credential.
- Exactly one branch and one draft PR maximum; direct push is impossible without credential and refused.
- Provider credential is issued only after the corresponding exact effect claim.
- Replay/recovery produce zero new credential requests/mutations unless reconciliation proves an unperformed permitted next effect.
- Every returned receipt is cryptographically verified locally; altering service bytes, signature, link, workflow ID, branch, PR, or commitment fails.
- Auths control-plane Bearer authentication is required on every fixed `/v2/profiles/github/issue-address/...` route, redacted everywhere, never forwarded to GitHub, and refused over plaintext/non-loopback; every redirect is refused.
- `/v1/demo` routes and denial fixtures are absent from production module/package.

### 12.6 OpenTofu and PostgreSQL profile qualification gates

- No public marker or generic byte executor permits either profile before qualification; attempted legacy imports fail.
- OpenTofu typed qualification must prove no re-plan, no shell dispatch, exact saved-plan identity, one apply claim, and observation-based outcome-unknown reconciliation.
- PostgreSQL typed qualification must prove no public SQL, exact bounded rows/values, serializable transaction, shared ledger transition, and ambiguous-commit observation without blind resubmission.

### 12.7 Package, typing, and platform

TypeScript:

- install tarball on Node 20/22 and supported Linux/macOS/Windows matrices;
- import every export-map path and assert removed paths fail;
- normal package specifiers only, no `dist` paths;
- browser Vite ESM and worker bundles for supported modules;
- `/mcp/node` fails clearly outside Node;
- `NodeNext`, `Bundler`, `strict`, `exactOptionalPropertyTypes`, tree-shaking, `sideEffects:false`, and no install scripts;
- package contains intended JS/declarations/WASM/docs/examples/license/provenance only.

Python:

- clean wheel install for every claimed CPython 3.9-3.14/platform family;
- strict mypy, Pyright, `stubtest`, `__all__`, signature, overload, Protocol, enum, and dataclass-field snapshots;
- `py.typed`, intended ABI3 tag, exactly one native extension, no compiler invocation;
- no source tree, repository fixtures, secrets, caches, path dependencies, or private monkeypatching.

Both:

- no Cargo/Rust available to consumer;
- SBOM, artifact checksums/signatures, license, provenance, and semantic-subject manifest verified;
- topology, package exports, runtime contract, API inventory, docs navigation, and capability claims generated from one manifest and compared;
- removed old symbols and subpaths fail to import (no aliases).

## 13. Direct implementation sequence with bounded review units

Each numbered unit should be independently reviewable, should update Rust plus both bindings when semantics are shared, and should not leave a dual public path.

1. **Contract manifest and target declarations.** Add one machine-readable target topology, signature/field snapshots, proposed package exports/`__all__`, and compile-only consumer fixtures. Assert all old paths are scheduled for direct removal. No runtime change.
2. **Shared error/diagnostic root.** Generate closed codes and projections from the Rust registry, add registry-digest mismatch/refusal fixtures, add observed runtime facts, and cut root exports to the proposed set. Remove caller-asserted doctor library options.
3. **Effect-free verification and receipts.** Change to named input, remove public `VerifiedAction`, add pinned signer/profile trust, three-valued receipt verification, exact Unix-second projection, and profile-owned receipt inspectors with rejected payload results. Register the six new core receipt codes plus `mcp.receipt-invalid`. Internalize generic disclosure authoring. Differential-test canonical fixtures and all bounds.
4. **Identity parity.** Implement the shared staged model, built-in raw-key Ed25519 path, one-shot authentication, advanced adapters/authoring split, prepared-message binding, and stable error projection. Delete duplicate/divergent tiers in the same unit.
5. **Typed MCP data edge.** Add TypeScript tool generics/JSON-compatible projection and Python frozen dataclass codecs. Add explicit provider outcomes and eliminate plain-result/effect-field ambiguity. Preserve Rust canonical bytes and verify parity.
6. **MCP session and authority lifecycle.** Move composition into the MCP profile, bind/own handlers, require idempotency keys, split action and plan methods, implement narrowing delegation, cancellation, diagnostics, and disposal. Remove root `Auths` and `/integrations` in the same unit.
7. **MCP durable development/recovery and semantic identities.** Add Node-specific/Python explicit filesystem development state, profile recovery handles, process-restart recipes, exact replay/conflict, checkpoint fault injection, and no-provider-reentry reconciliation. Add immutable `auths.mcp/2` and `auths.mcp-session/2` profile/session manifests, specs, fixtures, receipt version, and capability entries for the applied/possible-only handler contract; map its evidence authoring shape into the existing `auths.product.reconciliation-observation/1` envelope. Select `auths.product.reservation-execution-contract/2`, correct the stale lifecycle `/1` specification reference, preserve v1 meaning without a public compatibility path, and label the feature non-production everywhere.
8. **GitHub production profile.** Implement and qualify the authenticated `/v2/profiles/github/issue-address/...` route family and wire schemas in section 5.8, register the exact GitHub code/mapping tables, seal server boundary/candidate, narrow and idempotently recover delegation, implement typed outcomes/recovery, cancellation/disposal, actual portable receipts and local trust-pinned verification, and move fixtures to testkit. Do not publish the stable module while only `/v1/demo` exists or until every server prerequisite passes.
9. **Advanced protocol cut.** Implement the authenticated `/v2/verification/authorize` server route and immutable `auths.remote-verification/1` CBOR contract with route-specific ingress/response limits, registry-digest negotiation, and the four registered `remote.*` faults; expose only its bounded client-resolved transport/verifier in `/protocol`, then remove generic create/import/delegate/execute/recovery/profile IDs/disclosure and delete `/service`.
10. **Adapters and testkit.** Publish the v2 custody and single narrow reservation protocols with keyed durability conformance, internalize approval until its specification/catalog suite is complete, consolidate the remaining conformance reports/functions, move only the ephemeral signer and denial fixtures, internalize identity/authenticator fakes plus diagnostic/product-waist/MCP-lifecycle machinery, and delete `/framework` and duplicate testkit re-exports.
11. **Docs and framework recipes.** Replace both READMEs, ship all examples/docs inside artifacts, add Fastify/Next/FastAPI/Django/worker lifecycle recipes, extract/compile/execute all snippets, and make development/production labels unmissable.
12. **Atomic contract cutover.** Regenerate topology, inventories, runtime contracts, capability/evidence claims, ABI manifests, package contents, and removed-import assertions. There is one supported API at the end of this unit.
13. **Hosted acceptance and promotion.** Run platform/package/security/parity/fault matrices plus the zero-context study. Promotion/publication remains blocked until independent hosted evidence and all acceptance thresholds pass.

Suggested review size is one semantic boundary per pull request, generally under 800 changed non-generated lines plus generated artifacts. Units 6, 8, and 12 may be split internally by Rust/TS/Python/tests, but must merge behind a single atomic public-surface switch so no dual API is released.

## 14. Tradeoffs and remaining decisions

### 14.1 Accepted tradeoffs

- **More task-named modules, fewer misleading generic nouns.** Users choose MCP or GitHub up front; autocomplete becomes smaller and safer.
- **Explicit provider outcome wrapper.** One extra `mcp.applied(...)`/`mcp.Applied(...)` call removes a security-sensitive output/control ambiguity.
- **Required idempotency key.** This adds one argument to every effect but makes retry/replay semantics explicit and testable.
- **Profile-specific result repetition.** A handful of similar variants prevents a generic result from freezing one vertical's lifecycle into all future profiles.
- **No local production MCP convenience yet.** An honest absence is safer than a factory that cannot require full trust/custody/durability.
- **No OpenTofu/PostgreSQL marker or byte escape hatch.** Execution waits for honest typed verticals; only effect-free proof verification remains generic.
- **One package/wheel.** Atomic versioning outweighs stronger physical profile separation at this stage.

### 14.2 Remaining release-evidence decisions

No API-shape, lifecycle-version, route, authentication, trust, result, or compatibility decision is delegated to implementation. One release-matrix fact remains evidence-dependent and can only remove an unsupported platform, not change the surface:

1. **Published wheel platform set.** Claims must match built ABI3 wheels. A platform without a clean no-compiler wheel is removed from metadata rather than falling back silently to Rust compilation.

Everything else in this document—including names, modules, signatures, result semantics, ownership, and clean-break policy—is the implementation target.

## Appendix A. Disposition of every current TypeScript export

This appendix is keyed to `bindings/typescript/api/public-api.txt`. Grouped names always share the stated disposition; every current export is named explicitly.

### A.1 Root (`@auths-dev/sdk`)

| Current export(s) | Decision | Exact replacement/reason |
|---|---|---|
| `Actor` | Remove | Profile sessions expose `principal`; a generic actor record has no independent semantics. |
| `approval` | Internalize | Approval transactions remain Rust/product-owned until AP-SPEC-029 and a catalog-backed public conformance suite are complete. |
| `ApprovalPolicy` | Internalize | No public application-authored approval policy is accepted in this cut. |
| `Authority` | Move + rename | MCP-specific alias becomes `/mcp` `McpAuthority`; other profiles own their authority. |
| `Auths` | Move + rename | MCP behavior becomes `/mcp` `McpSession`; no generic stateful root facade. |
| `AuthsConfiguration` | Remove | Replaced by exact `McpDevelopmentOptions`, `GitHubIssueClientOptions`, or effect-free `RemoteVerifierOptions`. |
| `AuthsError` | Keep + reshape | Single root operational exception with validated `AuthsIssue` details. |
| `AuthsErrorCode` | Rename + close | `KnownAuthsErrorCode` is the sole generated closed type; registry-digest mismatch is refused before effect. |
| `AuthsErrorDetails` | Merge + remove | Fields move directly into the complete bounded `AuthsIssue`; no second alias is exported. |
| `CauseCategory` | Internalize | Values remain inline in `AuthsIssue.causes`; no standalone navigation noun. |
| `classifyErrorCode` | Merge + narrow | `AuthsError.isKnownCode(code)` answers registry membership; callers consume classification from the validated issue/result rather than performing a second lookup. |
| `CodeClassification` | Remove | Classification is the validated `AuthsIssue`; no detached code-only projection. |
| `Completed` | Move + split | Profile-owned `McpCompleted` and `GitHubCompleted`; the effect-free remote verifier has no execution completion. |
| `createAuths` | Remove + split | MCP uses `/mcp/node` `openDevelopment(profile, DevelopmentOptions)`; GitHub uses `connectGitHubIssueAddress`; advanced protocol supports verification only. |
| `Denied` | Move + split | Profile-owned denied variants. |
| `doctor` | Rename | Library `runtimeInfo()`; the package CLI command remains `auths doctor`. |
| `DoctorMode`, `DoctorOptions`, `DoctorState` | Remove | Caller-asserted diagnostic facts are not accepted. |
| `DoctorReport` | Rename | `RuntimeInfo`, populated from observed package/runtime state. |
| `EffectState` | Keep | Same Rust-owned three values. |
| `EnteredBoundaries` | Internalize | Nested typed field of `AuthsIssue`. |
| `ErrorFamily` | Internalize | Nested typed field of `AuthsIssue`. |
| `ExecutionReference` | Move + split | Profile-specific `McpRecoveryReference`, `McpPlanRecoveryReference`, and `GitHubRecoveryReference`. |
| `ExecutionResult` | Split + move | `McpOutcome`/`McpPlanOutcome` and `GitHubIssueOutcome`; no generic protocol execution result. |
| `Indeterminate` | Move + split | Profile-owned indeterminate variants; always pre-effect. |
| `isProductVerb` | Internalize | Raw operation parsing belongs to the private protocol codec. |
| `Outcome` | Rename | `AuthsIssue`; the name now says it is diagnostic/classification data, not execution success. |
| `ProductStage` | Internalize | Stable string field on `AuthsIssue`; registry-generated docs own vocabulary. |
| `ProductVerb` | Internalize | Fixed clients own operation-specific routes; no public dispatch verb survives. |
| `Receipt` | Keep + reshape | One sealed portable root receipt with `toBytes()` and no public constructor/JSON. |
| `RecommendedAction` | Keep | Same Rust-owned values. |
| `RecoveryResult` | Split + move | Profile recovery-required, completed replay/reconcile, not-applied, and conflict variants. |
| `RetryClass` | Keep | Same Rust-owned values. |

### A.2 `/identity`

| Current export(s) | Decision | Exact replacement/reason |
|---|---|---|
| `AuthenticatedIdentityMessage` | Keep + reshape | Same staged terminal identity evidence; explicitly not authority. |
| `DecodedIdentity` | Keep + reshape | Shared cross-language decoded stage. |
| `DecodedSignedIdentityMessage` | Internalize | `IdentityClient.authenticateMessage` performs bounded decode/binding; advanced authoring uses `PreparedIdentityMessage`. |
| `Ed25519RawKeyAuthentication`, `RawKeyIdentityAdapter` | Merge | Built-in `createRawKeyEd25519IdentityClient`; authoring helper in `/identity/authoring`. |
| `IdentityClient` | Keep + reshape | Staged plus one-shot effect-free identity client; no public constructor. |
| `IdentityMethodAdapter` | Move + rename | `/identity/adapters` `IdentityMethod`. |
| `IdentityMethodParse` | Merge | `ResolvedIdentityRecord` plus canonical field revalidation. |
| `IdentityPrincipal` | Remove | Unused duplicate; authenticated identity remains evidence and profile authority is separate. |
| `loadEd25519RawKeyAuthentication`, `loadRawKeyIdentityAdapter` | Merge + rename | `createRawKeyEd25519IdentityClient()`. |
| `loadIdentity` | Rename + split | Default `createRawKeyEd25519IdentityClient`; custom `createIdentityClient` in `/identity/adapters`. |
| `SignatureSuiteAdapter` | Move + rename | `/identity/adapters` `MessageAuthenticator`. |
| `SignatureSuiteParse` | Merge | Authenticator verification result is validated into `AuthenticatedIdentityMessage`; no loose parse record. |
| `ValidatedIdentity` | Keep + reshape | Shared validated stage; advanced authoring accepts this sealed value. |

### A.3 `/verify`

| Current export(s) | Decision | Exact replacement/reason |
|---|---|---|
| `AuthorizedResult`, `DeniedResult`, `IndeterminateResult` | Merge | Inline branches of `VerificationResult`; authorized branch remains inert. |
| `createReceiptDisclosure` | Internalize | Generic caller-authored disclosure is removed; a qualified profile may expose its own typed presentation later. |
| `DecisionInspection` | Rename | `VerificationInspection`. |
| `decodeReceipt` | Merge | `Verifier.verifyReceipt({receipt: bytes})` performs bounded parse and verification; no trusted decode-only path. |
| `encodeReceipt` | Merge | `Receipt.toBytes()`. |
| `Explanation` | Remove | Binding-authored prose/retryability is replaced by Rust registry issue fields/docs. |
| `ImmutableArtifactCache`, `ImmutableArtifactCacheOptions` | Internalize | Not publicly configurable or independently meaningful; may remain a loader optimization. |
| `inspectDecision` | Move + rename | `Verifier.inspect(result)`. |
| `inspectReceipt`, `verifyReceipt` | Merge + move | `Verifier.verifyReceipt(input)` returns `ReceiptVerification`. |
| `InvalidReceiptInspection` | Merge + split | `ReceiptVerification` has stable `rejected` and `indeterminate` branches. |
| `loadVerifier` | Rename | `createVerifier()`. |
| `ReceiptDisclosureMaterial` | Internalize | No generic disclosure authoring/view remains in the shared verifier. |
| `ReceiptDisclosureProtector`, `ReceiptDisclosureStore` | Internalize | No public composition consumes them; republish only with a managed disclosure product. |
| `ReceiptInspectionCommitments`, `ReceiptInspectionMetadata`, `ReceiptInspectionProfile`, `ReceiptInspectionSigner` | Merge | Exact cryptographic fields of `ReceiptEnvelopeDetails`; profile payload meaning is decoded only by `inspectMcpReceipt`/`inspectGitHubReceipt`. |
| `ReceiptInspectionResult`, `VerifiedDisclosedReceipt`, `VerifiedOpaqueReceipt` | Merge | `ReceiptVerification` with `VerifiedReceipt`, `rejected`, and `indeterminate`; there is no caller-selected view. |
| `ReceiptSummary`, `ReceiptSummaryField` | Remove | Generic stringly presentation is replaced by profile-owned typed receipt details. |
| `ReceiptViewMode` | Remove | Verification always validates the full signed envelope; profile inspectors expose only their fixed typed fields. |
| `VerdictKind` | Internalize | `VerificationResult["kind"]`. |
| `VerificationBatchOptions` | Keep + reshape | Signal/chunk/correlation only; security bounds cannot be raised. |
| `VerificationInput` | Keep + reshape | Named `{proof, action, trustedContext}`. |
| `VerificationMetrics` | Keep | Same native metrics. |
| `VerificationOptions` | Keep + reshape | Correlation only; telemetry becomes an application observer/instrumentation layer, not semantic input. |
| `VerificationResult` | Keep + reshape | Inert three-valued union with issue on negative branches. |
| `VerificationStage` | Keep | Same stable stages. |
| `VerifiedAction` | Internalize | Verification exports no effect-capable/command-like handle. |
| `Verifier` | Keep + reshape | Named input, batch, inspect, and receipt verification methods; private construction. |

### A.4 `/service`

| Current export(s) | Decision | Exact replacement/reason |
|---|---|---|
| `createGitHubAgentClient` | Move + rename | `/github` `connectGitHubIssueAddress`. |
| `createServiceClient` | Split | Its verify use becomes `/protocol` `connectRemoteVerifier`; create/delegate/execute/recover uses are removed until a typed profile exists. |
| `GitHubAgentBoundary` | Move + rename | `/github` `GitHubIssueBoundary`. |
| `GitHubAgentClient` | Move + rename | `/github` `GitHubIssueClient`. |
| `GitHubAgentClientOptions` | Move + rename | `/github` `GitHubIssueClientOptions`. |
| `GitHubAgentError` | Remove | Root `AuthsError` is the only operational hierarchy; expected states are outcome values. |
| `GitHubAgentOutcome` | Move + split | Closed `/github` `GitHubIssueOutcome` variants. |
| `GitHubAgentSession` | Move + rename | `/github` `GitHubIssueTask`, with disposal and bound boundary. |
| `GitHubAgentTask` | Remove | Broad boundary copy-back is replaced by `client.delegate({agentLabel, expiresInMs, allowPatterns?})`. |
| `GitHubCandidateFile` | Merge | Byte fields on `GitHubIssueTask.inspect`; filesystem I/O remains application-owned. |
| `GitHubCandidateInspection` | Move + split | Accepted/denied `/github` union with sealed `InspectedGitHubCandidate`. |
| `GitHubDenialFixture` | Move | `/testkit` `fixtures.github`. |
| `githubIssueAddress` | Remove + replace | Use the typed `/github` client; no public raw profile marker remains. |
| `GitHubVerifiedReceipts` | Remove | Return actual `readonly Receipt[]`; verify locally with `Verifier.verifyReceipt`. |
| `importAuthority` | Remove | Authority import is not exposed without a profile-owned typed trust and attenuation flow. |
| `NextCall` | Remove | Outcome discriminants and explicit profile `recover` methods supersede it. |
| `opentofuSavedPlanApply`, `postgresqlBoundedUpdate` | Remove | No public marker or byte-execution fallback; each returns only with a qualified typed vertical. |
| `ServiceAuthority`, `ServiceAuthorityResult` | Remove | No generic authority import/create/delegate surface. |
| `ServiceClient` | Split | Effect-free verification becomes `RemoteVerifier`; the generic effect client is removed. |
| `ServiceClientOptions` | Split + rename | Verification configuration becomes `RemoteVerifierOptions`; effectful generic options have no replacement. |
| `ServiceCompleted`, `ServiceDenied`, `ServiceIndeterminate`, `ServiceRecoverable`, `ServiceExecutionResult` | Remove | Generic byte execution and recovery are not public; typed profile outcomes supersede supported workflows. |
| `ServiceProfile`, `ServiceProfileId` | Remove | Wire profile identifiers stay private until a typed vertical qualifies. |
| `ServiceReceipt` | Remove duplicate | Supported profile outcomes return root `Receipt`; the remote verifier returns inert decision evidence only. |
| `ServiceRecoveryReference` | Remove | Recovery is profile-owned (`Mcp*RecoveryReference`, `GitHubRecoveryReference`). |
| `ServiceRejected`, `ServiceVerified`, `ServiceVerificationResult` | Merge + move | `RemoteVerifier.verify` returns `/verify` `VerificationResult`; `/protocol` does not duplicate or re-export the result types. |
| `ServiceTransport` | Move + rename | `/protocol` `BoundedTransport` with explicit ownership, cancellation, resolved route, and disposal. |
| `ServiceTransportRequest`, `ServiceTransportResponse` | Move + rename | `/protocol` `BoundedTransportRequest` and `BoundedTransportResponse`. |
| `TransportFailure` | Internalize | Concrete transport failures are classified by Rust/client into `AuthsIssue`/recovery; callers do not forge classification. |

### A.5 `/profiles`

| Current export(s) | Decision | Exact replacement/reason |
|---|---|---|
| `executeMcpClosed` | Internalize | `/mcp` `McpSession.execute`. |
| `executeMcpPlanClosed` | Internalize | `/mcp` `McpSession.executePlan`. |
| `githubIssueAddress` | Remove + replace | Typed `/github` module; no raw public ID. |
| `mcp` | Move + reshape | `/mcp` `mcp` namespace with `profile` and sealed provider-outcome helpers. |
| `McpAction` | Move + reshape | Generic typed `/mcp` `McpAction<Tools, Name>`. |
| `McpAuthority`, `McpToolAuthority` | Merge + move | Sealed `/mcp` `McpAuthority<Tools, Allowed>`. |
| `McpClosedProvider` | Merge + reshape | Typed `McpHandlers` plus mapped `McpReconcilers`, bound at session construction. |
| `McpClosedResult` | Merge + rename | `/mcp` `McpOutcome<Output>`. |
| `McpCommand` | Internalize | Exact commands stay non-forgeable behind Rust/profile gateway. |
| `McpDevelopmentProviderOptions` | Merge + rename | `/mcp` `McpDevelopmentOptions`; session owns provider configuration. |
| `McpExecutionCheckpointEvent` | Move + rename | `/mcp` `McpExecutionEvent`. |
| `McpExecutionCheckpointStage` | Move + rename | `/mcp` `McpExecutionStage`. |
| `McpExecutionObserver` | Remove + replace | Pull from bounded lossy `McpSession.events()`; no callback can delay or re-enter lifecycle transitions. |
| `McpExecutionResources`, `McpExecutionState` | Internalize | Product lifecycle transition/state machinery is not application API. |
| `McpGateway`, `McpGatewayCall` | Internalize | The session binds exact typed handlers; no generic command gateway is exposed. |
| `McpGatewayError` | Remove | Unused duplicate; use explicit provider outcomes and root error envelope. |
| `McpHandlerCause` | Move + rename | `/mcp` `McpProviderUncertainty`. |
| `McpHandlerOutcome` | Split + move | Normal handlers return `McpProviderOutcome` via `mcp.applied`/`mcp.possible`; reconciliation returns distinct `McpReconciliationOutcome`. |
| `McpPlanClosedResult` | Merge + rename | `/mcp` `McpPlanOutcome`. |
| `McpProfile` | Move + reshape | Generic `/mcp` `McpProfile<Tools>`. |
| `McpProfileOptions` | Merge | `mcp.profile({service, tools})`; runtime models are the single tool-definition source. |
| `McpReceipt` | Remove + merge | Root `Receipt`, with typed display through `inspectMcpReceipt`. |
| `McpReceiptSink` | Internalize | Receipt persistence is product lifecycle state, not a beginner callback. |
| `McpRecoveryCheckpoint` | Internalize | Recovery serialization/checkpoint transitions stay native/private; callers get `McpRecoveryReference`. |
| `McpToolContext` | Move + rename | `/mcp` `McpInvocationContext`; handler receives typed `McpInvocation`. |
| `McpToolHandler` | Merge + reshape | Mapped generic `/mcp` `McpHandlers`. |
| `opentofuSavedPlanApply`, `postgresqlBoundedUpdate` | Remove | No raw public ID; typed modules wait for qualification. |
| `resourcesForMcpAuthority` | Internalize | Session construction owns exact resources. |
| `resumeMcpClosed` | Internalize | `/mcp` `McpSession.recover`. |
| `ServiceProfile`, `ServiceProfileId` | Remove | No marker-only profile barrel or protocol enum. |

### A.6 `/integrations`

| Current export(s) | Decision | Exact replacement/reason |
|---|---|---|
| `development`, `DevelopmentAuthsOptions` | Merge + move | `/mcp/node` `openDevelopment(profile, DevelopmentOptions)`; `DevelopmentOptions` incorporates `/mcp` `McpDevelopmentOptions`. |
| `production` | Remove | It is unconstructible today. Use typed `/github`; `/protocol` is effect-free verification, not a generic production executor. |
| `RecoverableAuthsOptions` | Move + rename | `/mcp/node` `DevelopmentOptions`, whose mandatory `stateDirectory` makes the single-machine recovery boundary explicit. |

The `/integrations` subpath is deleted.

### A.7 `/framework`

| Current export(s) | Decision | Exact replacement/reason |
|---|---|---|
| `AtomicReservationRecord` | Move + rename | `/adapters` `ReservationRecord`. |
| `AtomicReservationStore` | Move + reshape | `/adapters` `ReservationStore`; its exact `durability` claim is tested by one keyed conformance harness, with no public durable subtype. |
| `ControlEvidence` | Move + rename | `/adapters` `PublicControlEvidence`. |
| `PrincipalDescriptor` | Move + split/merge | Its principal fields move into `CustodyDescriptor` and its nested `CustodySignatureDescriptor`. |
| `ProviderFailureKind` | Move + rename | `/adapters` `CustodyFailure`. |
| `ProviderOperationError` | Split + remove exception | Expected adapter states are the `rejected`/`indeterminate` branches of `CustodySignResult`; unexpected faults normalize at the trust boundary, while workflow faults use `AuthsError`. |
| `Signer` | Move + rename | `/adapters` `CustodySigner`. |
| `SignerLifecycle` | Move + rename | `/adapters` `CustodyLifecycle`. |
| `SigningObjectKind` | Move + keep | Same name in `/adapters`. |
| `SigningRequest` | Move + keep | Same name in `/adapters`, signal mandatory. |
| `SigningResponse` | Move + keep | Same name in `/adapters`, bounded evidence mandatory (possibly empty). |

The `/framework` subpath is deleted; “adapters” describes what users implement without suggesting a generic application framework.

### A.8 `/testkit`

| Current export(s) | Decision | Exact replacement/reason |
|---|---|---|
| `AtomicReservationRecord` | Remove duplicate | Import `/adapters` `ReservationRecord`. |
| `AtomicReservationStoreCandidate` | Remove alias | Conformance factory returns `/adapters` `ReservationStore`. |
| `BoundedApprovalSession`, `BoundedApprovalSessionOptions` | Internalize | Approval state machine and configuration remain product machinery in this cut. |
| `ByteTransportCandidate`, `ByteTransportFactory` | Rename + merge | Factory input to `conformance.boundedTransport`. |
| `certifyAtomicStore` | Rename | `conformance.reservationStore`, whose keyed factory tests the declared durability and reopen behavior. |
| `certifyByteTransport` | Rename | `conformance.boundedTransport`. |
| `certifyMcpProvider` | Internalize | The catalog MCP suite needs a full session/authority/recovery subject; a handler-only factory cannot satisfy it honestly. |
| `certifySigner`, `custodyConformance` | Merge + rename | `conformance.custodySigner`; no “certify” claim. |
| `CONFORMANCE_CATALOG` | Internalize | Generated CI inventory; each report identifies its suite/version. |
| `ConformanceCaseResult` | Keep | Shared exact case result. |
| `ConformanceMetadata` | Keep + reshape | Includes contract/sdk version and non-certification assurance. |
| `createDiagnosticVerifier` | Internalize | Verdict-selecting differential test engine remains repository-only. |
| `CustodyConformanceCase` | Merge | `ConformanceCaseResult`. |
| `CustodyConformanceOptions` | Merge | `conformance.custodySigner(factory)` signature. |
| `CustodyConformanceReport` | Merge + rename | `ConformanceReport`. |
| `CustodyConformanceResult` | Merge | `ConformanceCaseResult`. |
| `DiagnosticResult`, `DiagnosticVerifier` | Internalize | Cannot appear in clean-consumer testkit because it can simulate verification verdicts. |
| `fixtures` | Keep + reshape | Inert verification and GitHub-denial fixtures under explicit namespaces. |
| `InMemoryApplicationExecutionStore` | Internalize | Hidden repository/application-profile test implementation; not a production contract. |
| `McpProviderFactory` | Internalize | Used only by the internal full MCP lifecycle suite. |
| `MechanismConformanceReport` | Rename + merge | One `ConformanceReport`. |
| `productWaistConformance`, `ProductWaistConformanceCase`, `ProductWaistConformanceReport`, `ProductWaistExpected` | Internalize | Repository manifest/compliance tooling, not an installed consumer adapter contract. |

## Appendix B. Disposition of every current Python export

This appendix is keyed to `bindings/python/api/public-api.txt`. Every current `__all__` name is explicit below.

### B.1 `auths`

| Current export(s) | Decision | Exact replacement/reason |
|---|---|---|
| `Actor` | Remove | Profile sessions expose `principal`; no generic actor value. |
| `Approval` | Internalize | Approval transactions remain Rust/product-owned pending AP-SPEC-029 and catalog-backed conformance. |
| `Authority` | Move + rename | `auths.mcp.Authority`; root alias was MCP-specific. |
| `Auths` | Move + rename | `auths.mcp.DevelopmentSession`; no generic stateful facade. |
| `AuthsError` | Keep + reshape | One root exception with public `ErrorInfo`. |
| `AuthsErrorCode` | Rename + close | `KnownAuthsErrorCode` is the exact enum used by `ErrorInfo.code`; registry-digest mismatch is refused before effect. |
| `Completed` | Move + split | Profile-owned `auths.mcp.Completed` and `auths.github.Completed`; protocol verification has no execution completion. |
| `Denied` | Move + split | Profile-owned denied variants. |
| `DoctorReport` | Rename | `RuntimeInfo`. |
| `EffectState` | Keep | Rust-owned enum. |
| `ExecutionReference` | Move + split | MCP action/plan and GitHub `RecoveryReference` classes. |
| `ExecutionResult` | Split + move | MCP `ActionOutcome`/`PlanOutcome` and GitHub `IssueOutcome`; no generic protocol execution result. |
| `Indeterminate` | Move + split | Profile-owned pre-effect variants. |
| `PlanCompleted` | Move | `auths.mcp.PlanCompleted`. |
| `PlanRecoveryResult` | Split + move | `auths.mcp.PlanStopped` containing explicit stop outcome/recovery. |
| `ProductVerb` | Internalize | Fixed clients own operation-specific routes; no public transport dispatch verb survives. |
| `Receipt` | Keep + reshape | Root sealed portable receipt with `to_bytes`. |
| `RecommendedAction` | Keep | Rust-owned enum. |
| `RecoveryResult` | Split + move | Profile recovery-required, completed replay/reconcile, not-applied, conflict. |
| `RetryClass` | Keep | Rust-owned enum. |
| `create_auths` | Remove | Use exact profile construction/context manager. |
| `doctor` | Rename | Library `runtime_info()`; CLI remains `python -m auths doctor`. |

### B.2 `auths.identity`

| Current export(s) | Decision | Exact replacement/reason |
|---|---|---|
| `AuthenticatedIdentity` | Rename | `AuthenticatedIdentityMessage`, emphasizing exact authenticated message evidence. |
| `DecodedIdentity` | Keep + reshape | Shared staged identity value with safe packet export. |
| `Ed25519SignatureSuite` | Merge + move | Built-in `raw_key_ed25519()` normal path; advanced authenticator implements `MessageAuthenticator`. |
| `IdentityMethod` | Move + keep | `auths.identity.adapters.IdentityMethod`. |
| `IdentityPrincipal` | Remove | Identity evidence is not authority; profile authority conversion remains Rust-owned/private until an exact public flow consumes it. |
| `IdentityRegistry` | Merge + rename | Immutable `IdentityClient`; custom construction is `identity.adapters.create_client`. |
| `IdentityResolver` | Move + keep | `auths.identity.adapters.IdentityResolver`. |
| `RawKeyIdentityMethod` | Internalize | Built into `raw_key_ed25519()`; adapter authors can implement `IdentityMethod`. |
| `ResolutionEvidence` | Move + keep | `auths.identity.adapters.ResolutionEvidence`. |
| `ResolvedIdentity` | Keep + reshape | Shared resolved stage. |
| `ResolvedIdentityRecord` | Move + keep | `auths.identity.adapters.ResolvedIdentityRecord`. |
| `ResolverIdentityMethod` | Move + rename | `auths.identity.adapters.resolver_method`. |
| `SignatureSuite` | Move + rename | `auths.identity.adapters.MessageAuthenticator`. |
| `ValidatedIdentity` | Keep + reshape | Shared validated stage with safe packet export. |
| `VerificationMaterial`, `VerificationRelationship` | Move + keep | `auths.identity.adapters`. |
| `decode_identity` | Merge | `IdentityClient.decode` or one-shot `authenticate_message`. |
| `encode_identity` | Move + keep | `auths.identity.authoring.encode_identity`. |
| `encode_raw_key_identity` | Move + rename | `create_raw_key_ed25519_identity(...).to_bytes()` in identity authoring. |

### B.3 `auths.verify`

| Current export(s) | Decision | Exact replacement/reason |
|---|---|---|
| `ApprovalInspection` | Keep + reshape | Typed nested field of `VerificationInspection`; no generic tuple/dict. |
| `AuthorizedResult`, `DeniedResult`, `IndeterminateResult` | Rename + merge | `AuthorizedResult` becomes `AuthorizedVerification`; negative classes merge into `UnsuccessfulVerification` while preserving `kind`; `VerificationResult` is their union. |
| `DecisionCommitments`, `KernelSummary` | Merge | Flattened exact commitment fields on `VerificationInspection`. |
| `DecisionInspection` | Rename | `VerificationInspection`. |
| `DecisionSummary` | Internalize | Stable code registry/docs provide bounded summaries; commitments remain explicit. |
| `Explanation` | Remove | Binding-authored prose/retryability is removed. |
| `InvalidReceiptInspection` | Rename + split | `RejectedReceipt` and `IndeterminateReceipt` branches of `ReceiptVerification`. |
| `ReceiptDisclosureMaterial` | Internalize | No generic caller-authored disclosure/view remains. |
| `ReceiptDisclosureProtector`, `ReceiptDisclosureStore` | Internalize | No public managed composition consumes them. |
| `ReceiptInspectionCommitments` | Merge + split | Exact fields live directly on `DecisionReceiptDetails` and `ExecutionReceiptDetails`, the two arms of `ReceiptEnvelopeDetails`; there is no wrapper. |
| `ReceiptInspectionMetadata` | Merge | Exact `ReceiptEnvelopeDetails` fields. |
| `ReceiptInspectionProfile` | Merge | Exact profile fields live on both `DecisionReceiptDetails` and `ExecutionReceiptDetails` branches. |
| `ReceiptInspectionResult` | Rename + merge | `ReceiptVerification`. |
| `ReceiptInspectionSigner` | Rename | `ReceiptSignerInfo`. |
| `ReceiptSummary`, `ReceiptSummaryField` | Remove | Stringly generic presentation is replaced by profile-owned `McpReceiptDetails`/`GitHubReceiptDetails`. |
| `ReceiptViewMode` | Remove | Verification has no caller-selected view. |
| `VerificationInput` | Keep + reshape | Named frozen dataclass. |
| `VerificationMetrics` | Keep | Same native metrics. |
| `VerificationResult` | Keep + reshape | Inert `AuthorizedVerification | UnsuccessfulVerification` union with impossible states excluded. |
| `VerifiedDisclosedReceipt`, `VerifiedOpaqueReceipt` | Merge | One trust-pinned `VerifiedReceipt`; profile payload meaning requires a profile inspector. |
| `create_receipt_disclosure` | Internalize | Generic disclosure authoring is removed. |
| `decode_receipt` | Merge | `verify_receipt(bytes)`; no trusted decode-only path. |
| `encode_receipt` | Merge | `Receipt.to_bytes()`. |
| `inspect_decision` | Rename | `inspect`. |
| `inspect_receipt`, `verify_receipt` | Merge + keep | One `verify_receipt` returning verified/rejected/indeterminate; typed inspection moves to profile modules. |
| `verify` | Keep + reshape | Accept one `VerificationInput`. |
| `verify_many` | Keep + reshape | Iterable of named inputs with unchanged bounds. |

### B.4 `auths.service`

| Current export(s) | Decision | Exact replacement/reason |
|---|---|---|
| `AuthsError`, `EffectState`, `RecommendedAction`, `RetryClass` | Remove duplicate re-exports | Import from `auths`. |
| `AuthsErrorCode` | Remove duplicate/bare alias | Use root `KnownAuthsErrorCode` and `ErrorInfo.code`. |
| `GitHubAgentBoundary` | Move + rename | `auths.github.IssueBoundary`. |
| `GitHubAgentClient` | Move + rename | `auths.github.IssueClient`. |
| `GitHubAgentError` | Remove | Root `AuthsError`; expected states are typed outcomes. |
| `GitHubAgentOutcome` | Move + split | `auths.github.IssueOutcome` variants. |
| `GitHubAgentSession` | Move + rename | `auths.github.IssueTask`. |
| `GitHubAgentTask` | Remove | Broad boundary copy-back replaced by narrowing `IssueClient.delegate`. |
| `GitHubCandidateFile` | Merge | `IssueTask.inspect(bundle=bytes, candidate_revision=...)`. |
| `GitHubCandidateInspection` | Split + move | `CandidateAccepted`/`CandidateDenied`. |
| `GitHubDenialFixture` | Move | `auths.testkit.fixtures.github_denied_candidate`. |
| `GitHubVerifiedReceipts` | Remove | Return actual `Tuple[Receipt, ...]`; verify via `auths.verify.verify_receipt`. |
| `NextCall` | Remove | Explicit result kinds and `recover` methods supersede a second retry axis. |
| `ProductVerb` | Internalize | Fixed clients own operation-specific routes; no public dispatch literal remains. |
| `ServiceAuthority`, `ServiceAuthorityResult` | Remove | No generic authority import/create/delegate surface. |
| `ServiceClient` | Split | Effect-free verification becomes `auths.protocol.RemoteVerifier`; generic effect execution is removed. |
| `ServiceCompleted`, `ServiceExecutionResult`, `ServiceRecoverable`, `ServiceRecoveryReference` | Remove | Execution/recovery is profile-owned; `/protocol` is effect-free. |
| `ServiceDenied`, `ServiceIndeterminate`, `ServiceRejected` | Split + move | Remote negatives are `auths.verify.UnsuccessfulVerification`; effectful negatives remain profile-owned outcomes. |
| `ServiceReceipt` | Remove duplicate | Supported profile outcomes return root `Receipt`; remote verification does not execute or receipt an effect. |
| `ServiceTransport` | Move + rename | `auths.protocol.BoundedTransport` with a client-resolved route and `aclose`. |
| `ServiceTransportRequest`, `ServiceTransportResponse` | Move + rename | `auths.protocol.TransportRequest`, `TransportResponse`. |
| `ServiceVerificationResult` | Move + rename | `auths.verify.VerificationResult`, returned by `auths.protocol.RemoteVerifier.verify`; protocol does not re-export it. |
| `ServiceVerified` | Move + rename | `auths.verify.AuthorizedVerification`; there is no `auths.protocol.Authorized`. |
| `create_github_agent_client` | Remove + move | Construct `auths.github.IssueClient`. |
| `create_service_client` | Split | Verification use becomes `connect_remote_verifier`; other generic verbs are removed. |
| `import_authority` | Remove | Authority import requires a typed profile-owned trust/attenuation flow. |

The `auths.service` module is deleted.

### B.5 `auths.profiles`

| Current export(s) | Decision | Exact replacement/reason |
|---|---|---|
| `DevelopmentMcpProvider` | Merge + move | Handler bindings are owned by `auths.mcp.DevelopmentSession`; no separately leaked provider on the beginner path. |
| `McpAction` | Move + rename | Typed `auths.mcp.Call[ArgumentsT, ResultT]`. |
| `McpClosedProvider` | Merge + reshape | Typed `Handler`/`HandlerBinding` and separately bound observation `Reconciler`. |
| `McpCompleted` | Merge | `auths.mcp.Completed`; remove duplicate internal/public result projection. |
| `McpExecutionCheckpointEvent` | Move + rename | `auths.mcp.ExecutionEvent`. |
| `McpExecutionCheckpointStage` | Internalize + merge | Private `_ExecutionStage` annotation backing `ExecutionEvent.stage`; there is no canonical public stage import. |
| `McpExecutionObserver` | Remove + replace | Pull from bounded lossy `DevelopmentSession.events()`; no lifecycle callback. |
| `McpHandlerOutcome` | Split + move | Normal handlers return only `Applied`/`Possible`; development reconciliation has distinct `ObservedApplied`/`Inconclusive` variants and cannot assert absence. |
| `McpPlan` | Move + rename | `auths.mcp.Plan`. |
| `McpPlanCompleted` | Merge | `auths.mcp.PlanCompleted`. |
| `McpPlanRecoveryResult` | Merge + rename | `auths.mcp.PlanStopped`. |
| `McpRecoverable` | Merge + rename | `auths.mcp.RecoveryRequired`. |
| `McpToolAuthority` | Move + rename | `auths.mcp.Authority`. |
| `McpToolContext` | Move + split | `auths.mcp.InvocationContext` inside typed `Invocation`. |
| `ServiceProfile` | Remove | No marker wrapper. |
| `ServiceProfileId` | Remove | No marker-only protocol enum. |
| `github_issue_address` | Remove + replace | Real `auths.github` module; no raw public ID. |
| `mcp` | Remove barrel/singleton | Import the real `auths.mcp` module. |
| `opentofu_saved_plan_apply`, `postgresql_bounded_update` | Remove | No byte-execution marker; each returns only as a qualified typed vertical. |

The `auths.profiles` barrel is deleted. Autocomplete shows real modules, not string factories.

### B.6 `auths.integrations`

| Current export(s) | Decision | Exact replacement/reason |
|---|---|---|
| `FrameworkAdapter` | Remove | Unused semantics-free generic callback; framework lifecycle recipes call exact clients. |
| `IdentityTransport` | Remove | No generic byte transport is consumed by the proposed identity surface; a transport-specific package implements `IdentityResolver` directly. |
| `development` | Remove + move | Only `auths.mcp.Profile.development(...)`; recovery is through `DevelopmentSession.recover*`, with no second factory. |
| `exchange_identity` | Remove | No equivalent operation is invented; use the exact resolver/client authentication flow or a future specified exchange profile. |
| `production` | Remove | Dead/unconstructible API; use exact `auths.github` or a future qualified profile. |

The `auths.integrations` module is deleted.

### B.7 `auths.framework`

| Current export(s) | Decision | Exact replacement/reason |
|---|---|---|
| `AtomicReservationRecord` | Move + rename | `auths.adapters.reservations.ReservationRecord`. |
| `AtomicReservationStore` | Move + reshape | `auths.adapters.reservations.ReservationStore`; one keyed conformance harness verifies its declared durability, with no public durable subtype. |
| `ControlEvidence` | Move + rename | `auths.adapters.custody.PublicControlEvidence`. |
| `PrincipalDescriptor` | Move + split/merge | Principal fields move into `CustodyDescriptor` plus nested `CustodySignatureDescriptor`. |
| `ProviderFailureKind` | Move + rename | `auths.adapters.custody.CustodyFailure`. |
| `ProviderOperationError` | Split + remove exception | Expected states are `CustodyRejected`/`CustodyIndeterminate`; unexpected adapter faults map to `CustodyFailure.PROVIDER_UNKNOWN`; no `CustodyError`. |
| `Signer` | Move + rename | `auths.adapters.custody.CustodySigner`. |
| `SignerLifecycle` | Move + rename | `auths.adapters.custody.CustodyLifecycle`. |
| `SigningObjectKind` | Move + keep | Same name in custody module. |
| `SigningRequest` | Move + keep | Same name in custody module. |
| `SigningResponse` | Move + keep | Same name in custody module. |

The `auths.framework` module is deleted.

### B.8 `auths.testkit`

| Current export(s) | Decision | Exact replacement/reason |
|---|---|---|
| `ADAPTER_CONTRACT_VERSION` | Remove | Each adapter protocol/conformance report carries its own generated contract version. |
| `AtomicReservationRecord` | Remove duplicate | Import `auths.adapters.reservations.ReservationRecord`. |
| `AtomicReservationStoreCandidate` | Remove alias | Use `ReservationStore` protocol as conformance factory return. |
| `ByteTransportCandidate` | Merge + rename | Factory input to `run_bounded_transport_conformance`. |
| `CONFORMANCE_CATALOG` | Internalize | Generated repository CI inventory; reports identify suite/version. |
| `ConformanceCaseResult` | Rename | `ConformanceCase`. |
| `ConformanceMetadata` | Keep + reshape | Includes contract/sdk version and explicit non-certification assurance. |
| `ConformanceReport` | Keep + reshape | One report type for every public suite. |
| `DevelopmentApproval` | Internalize | No public approval adapter or fake in this cut. |
| `DevelopmentEd25519Signer` | Rename | `ephemeral_ed25519_signer`. |
| `DevelopmentIdentityMethod` | Internalize | No public identity fake or catalog-backed identity conformance suite ships in this cut. |
| `DevelopmentReceiptAttestor` | Internalize | No public receipt-attestor adapter contract consumes it. |
| `DevelopmentSignatureSuite` | Internalize | No public authenticator fake or catalog-backed authenticator suite ships in this cut. |
| `DevelopmentSigner` | Remove | Redundant fixed-byte signer; use ephemeral signer or a test-local candidate. |
| `DiagnosticEngine`, `DiagnosticExplanation`, `DiagnosticResult`, `DiagnosticVerifier` | Internalize | Repository differential machinery; verdict selection cannot enter clean-consumer testkit. |
| `FixedClock` | Internalize | No public production/session entry point accepts a clock; deterministic time remains in the native/profile harness. |
| `MemoryGateway` | Remove | Generic callback gateway violates profile ownership; use profile handler fakes. |
| `ProductWaistConformanceReport`, `ProductWaistExpected` | Internalize | Repository manifest/compliance types. |
| `RecordingTelemetry` | Internalize | Consumers test the bounded `events()` iterator directly; no callback recorder is public. |
| `certify_atomic_store` | Rename | `run_reservation_store_conformance`; its keyed factory tests the durability claim. |
| `certify_byte_transport` | Rename | `run_bounded_transport_conformance`. |
| `certify_mcp_provider` | Internalize | The catalog suite requires a full session/authority/recovery subject, not a handler-only factory. |
| `certify_signer` | Rename | `run_custody_signer_conformance`. |
| `check_approval_provider` | Internalize | Approval remains product-owned and has no public conformance suite yet. |
| `check_identity_method` | Internalize | There is no public identity-method conformance runner in this cut. |
| `check_signer` | Remove duplicate | Superseded by `run_custody_signer_conformance`. |
| `check_telemetry` | Internalize | Repository observer checks and `RecordingTelemetry` both remain internal. |
| `create_diagnostic_verifier` | Internalize | No caller-selected verdict engine in public testkit. |
| `product_waist_conformance` | Internalize | Repository CI command, not clean-consumer API. |

## Cutover definition of done

The redesign is complete only when the old inventories no longer resolve, the proposed declarations and examples are the installed artifact, every semantic and package gate in section 12 passes, and the zero-context study meets section 11. A smaller symbol list without profile-owned recovery, real receipt verification, clean-package evidence, and lifecycle tests is not this redesign.
