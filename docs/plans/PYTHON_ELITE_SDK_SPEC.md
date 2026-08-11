# Python Elite SDK Product Specification

**Status:** Python implementation complete; promotion gates remain external
**Baseline:** `61bedef` on 2026-08-11
**Lifecycle:** Prelaunch; no external users or production state require
backward compatibility
**Product ambition:** Make `auths` credible as the “Stripe for identity and
permissions on the internet” for Python applications, services, automation,
data systems, and AI agents
**Semantic owner:** Rust
**Language-product owner:** Python
**Related plans:** [Python safe native waist](PYTHON_SAFE_NATIVE_WAIST_PLAN.md),
[Python attach/delegate Milestone B](PYTHON_ATTACH_DELEGATE_MILESTONE_B.md),
[Python MCP Milestone C](PYTHON_MCP_VERTICAL_MILESTONE_C.md),
[Python Full Workflow Milestone D](PYTHON_FULL_WORKFLOW_MILESTONE_D.md), and
[SDK product surface and Python parity](SDK_PRODUCT_SURFACE_AND_PYTHON_PARITY.md)

## 1. Product decision

The Python package will graduate from one complete MCP workflow into a broad,
production-operable, language-native Auths product. It will expose the same
Rust-owned meaning as TypeScript without copying TypeScript's implementation or
forcing Python developers to think in Rust types.

“Stripe-like” means:

- install a wheel and complete a useful workflow quickly;
- excellent type hints, signatures, errors, examples, test fixtures, and
  operational evidence;
- no Rust compiler, protocol-byte construction, private-key export, hosted
  Auths service, or JavaScript dependency;
- safe async provider coordination and deterministic resource ownership;
- complete identity, trust, lifecycle, authority, profile, enforcement, and
  receipt journeys;
- a small stable API over a powerful native core; and
- replaceable, conformance-tested integrations for the enormous Python
  ecosystem.

The SDK will not chase one-for-one exposure of every Rust symbol. Rust remains
the capability ceiling and semantic owner; Python packages complete customer
journeys.

### 1.1 Prelaunch clean-break policy

This specification governs a prelaunch SDK. Python work targets one
authoritative current API and native contract. It must not create or retain
backward-compatibility shims, deprecated aliases, legacy decoders, migration
helpers, dual import or execution paths, old/new native switches,
version-support windows, or tests whose purpose is to keep superseded wheels
and cores interoperating. When a surface changes, remove the old Python,
native, documentation, typing, fixture, and example paths in the same cutover.

Exact ABI identifiers, semantic identities, wheel/native subject agreement,
current-version differential fixtures, and fail-closed mismatch tests remain
mandatory. They prove that one current release is internally coherent; they
do not establish backward-compatibility obligations.

## 2. Customer promise

Python developers must be able to adopt Auths progressively:

```text
+-------------------+       +-------------------+
| auths.identity    | ----> | auths.authenticate|
| exchange/validate |       | exact signed bytes|
+-------------------+       +---------+---------+
       independent                      |
                                        v
+-------------------+       +-------------------+
| auths.receipts    | <---- | auths.workflow    |
| effect evidence   |       | attach/delegate   |
+---------+---------+       | authorize/plan    |
          ^                 +---------+---------+
          |                           |
+---------+---------+       +---------v---------+
| auths.runtime     | <---- | auths.profiles.*  |
| replay/budget     |       | closed commands   |
+-------------------+       +-------------------+
```

Importing `auths.identity` must not initialize or expose grants, capabilities,
approval, profile, lifecycle, or gateway machinery. A validated identity may
enter authority only through an explicit typed bridge. A transport carries
bounded bytes and never upgrades endpoint identity into application identity
or permission.

The complete workflow promise is:

> From an installed wheel, load trust, attach an agent, delegate narrower
> authority, authorize an exact action or plan, and hand a native-sealed
> command to a closed gateway—without implementing Auths meaning in Python.

## 3. Elite-bar scorecard

| Dimension | Required outcome |
| --- | --- |
| Time to value | A new Python developer completes identity-only exchange in 5 minutes and a locally protected action in 15 minutes from maintained examples. |
| Python fit | Public APIs use protocols, dataclasses/value objects, context managers, iterables, buffers, exceptions, async cancellation, and exhaustive result types idiomatically. |
| Native safety | Python cannot mint, copy, pickle, subclass, reflect, mutate, deserialize, or replay an effect-capable handle. |
| Semantic parity | Python coordinates callbacks; Rust owns all canonicalization, identifiers, commitments, attenuation, authoring, verification, lifecycle, profile, and command meaning. |
| Surface breadth | Identity, authentication, trust, lifecycle, attach, delegation, action, plans, custom profiles, runtime state, receipts, and inspection have supported paths. |
| Production integration | Signer, approval, resolver, clock, status, store, telemetry, gateway, and framework boundaries have executable conformance suites. |
| Operations | Replay, budget, revocation, rotation, retries, concurrency, cancellation, and outcome-unknown states are explicit and tested. |
| Performance | Native work releases the GIL where safe, batch paths preserve single-item semantics, and copies across the native boundary are bounded and measured. |
| Packaging | Exact wheels, types, API snapshot, contents, SBOM, provenance, and external-consumer behavior agree across the supported CPython/OS matrix. |
| Documentation | Every supported layer has a runnable quickstart, failure guide, production recipe, and exact current-surface reference. |

Phase 0 must capture cold import, native initialization, single verification,
plan verification, batch throughput, memory, wheel size, and event-loop impact.
Later work may not regress a p95 runtime baseline by more than 10% or wheel size
by more than 15% without a reviewed exception and release-note entry.

## 4. UX

### 4.1 Identity without authority

```python
from auths.identity import IdentityRegistry, decode_identity

registry = IdentityRegistry(methods=[method_adapter], suites=[suite_adapter])
decoded = decode_identity(packet)
validated = await decoded.validate(registry)
authenticated = await validated.authenticate(message, signature, registry)

route_for(authenticated.identity)
```

Decoded, validated, resolved, and authenticated objects are distinct types.
The identity layer accepts method-owned credential shapes, not just one public
key and one signature. Authentication never creates authority.

### 4.2 Verification without workflow

```python
from auths.verify import Authorized, Denied, Indeterminate, verify

decision = verify(proof_cbor, action_cbor, trusted_context_cbor)

match decision:
    case Authorized():
        record(decision)
    case Denied() | Indeterminate():
        record(decision)
```

`auths.verify` is a first-class product surface for teams that already possess
proof, action, and trusted-context bytes. An authorized verifier result is
inert evidence; it cannot be converted into a gateway command.

Safe decision projection belongs in `auths.inspection`. Caller-supplied or
differential verifier engines belong in `auths.diagnostics`, and their results
remain inert regardless of the bytes the engine returns. Verification,
inspection, and diagnostics do not initialize workflow, approval, custody,
profile, lifecycle, or runtime components.

### 4.3 Full workflow

```python
from auths import Approval, AuthsClient
from auths.profiles import mcp

profile = mcp.profile(service="reports")

async with AuthsClient(
    signer=signer,
    trusted_authority=trusted_authority,
    telemetry=telemetry,
) as client:
    async with await client.attach_agent(
        name="reports-agent",
        profile=profile,
        authority=root_grant,
        approval=Approval.grant_only("approval.reports", approvals),
    ) as agent:
        decision = await agent.authorize(
            profile.call("publish_report", {"month": "august"})
        )

        match decision:
            case mcp.Authorized(command=command):
                await gateway.execute(command, idempotency_key=request_id)
            case mcp.Denied(explanation=explanation):
                report(explanation)
            case mcp.Indeterminate(explanation=explanation):
                await recover_evidence(explanation)
```

Provider orchestration remains async-native. Deterministic local parsing,
construction, and verification may remain synchronous. The SDK will not add a
second blocking workflow facade that hides an event loop, makes cancellation
ambiguous, or creates different semantics.

### 4.4 Custom profiles after a second maintained profile

```python
from auths.profile_kit import Action, ApplicationProfile

billing = ApplicationProfile.define(
    profile_id="com.example.billing/1",
    actions={"refund": Action(input=RefundInput, authority=refund_authority)},
)

refund = billing.action(
    "refund",
    RefundInput(payment_id=payment_id, amount=500, currency="usd"),
)
decision = await agent.authorize(refund)
```

The profile kit may ship only after MCP and one structurally different
maintained Python profile demonstrate the correct abstraction. It owns no
generic executor. Profile-specific commands remain native-sealed and are
accepted only by matching gateways.

### 4.5 Framework integration

Framework helpers must remain thin adapters over the SDK:

```python
@app.post("/reports/{report_id}/publish")
async def publish(report_id: str, request: Request) -> Response:
    decision = await authorizer.authorize(
        reports.publish(report_id=report_id),
        challenge=challenge_from(request),
    )
    return await render_or_execute(decision)
```

They may extract transport facts, manage request lifetime, and translate typed
errors. They may not define identity, authority, profile, retry, or receipt
semantics.

### 4.6 Errors and outcomes

Malformed configuration, provider contract violations, cancellation misuse,
and unsupported capabilities raise a stable `AuthsError` hierarchy.
Authorization returns `Authorized`, `Denied`, or `Indeterminate`; it does not
raise because access was not authorized.

Every error exposes safe structured fields:

- family and code;
- operation, stage, and correlation ID;
- retry class: `never`, `safe`, `conditional`, or `unknown`;
- provider/effect progress;
- bounded remediation; and
- a redacted cause chain.

Raw proof bytes, signatures, private material, credentials, and unbounded
provider responses must never appear in `str(error)`, `repr(error)`, logs,
tracebacks generated by SDK wrappers, or telemetry attributes.

## 5. Architecture

```text
+--------------------------- Python package ----------------------------+
| Python values | Protocol ports | async coordination | context managers|
| identity | trust | authority | profiles | workflow | runtime | testkit |
+--------------------------------|--------------------------------------+
                                 v
+---------------------------- PyO3 waist -------------------------------+
| abi3 | bounded buffers | opaque one-use handles | stable projections |
| exact runtime contract | batch calls | typed native errors            |
+--------------------------------|--------------------------------------+
                                 v
+---------------------------- Rust waist -------------------------------+
| identity states | canonicalization | authoring | attenuation          |
| approval/plan commitments | verification | command decoding          |
| lifecycle/status | replay/budget/receipt state machines               |
+--------------------------------|--------------------------------------+
                                 v
+---------------------- Replaceable Python adapters --------------------+
| custody | identity methods | suites | resolvers | stores | gateways   |
| clocks | approval providers | transports | telemetry | frameworks     |
+------------------------------------------------------------------------+
```

### 5.1 Ownership rules

- Rust owns every semantic fact shared with TypeScript or other languages.
- Python owns callback scheduling, Python-native immutable projections,
  context management, exception mapping, package layout, and adapter protocols.
- The normal API never accepts protocol CBOR where a typed operation exists.
- Native handles are opaque, non-constructible, non-subclassable,
  non-copyable, non-pickleable, mutation-resistant, profile-bound, and one-use.
- Python data returned for display or inspection is inert and cannot be
  promoted back into an effect capability.
- Native calls release the GIL only when they do not call Python and preserve
  object lifetime and cancellation safety.
- Provider I/O never runs in the deterministic verifier.
- Review is independent from approval; approval is independent from identity.
- `Protocol` ports and conformance suites are preferred over base-package
  dependencies on vendors or frameworks.

### 5.2 Rust work that may be required

The Python program may add or widen Rust operations when the shared semantic
owner is missing. It must not implement a Python-only version of the meaning.

| ID | Rust deliverable | Why Python needs it |
| --- | --- | --- |
| CORE-E01 | A binding-oriented workflow kernel with bounded inputs, opaque handles, and stable projections for attach, delegate, authorize, plan, inspect, and dispose | Shrinks Python coordination and keeps semantic workflow transitions native |
| CORE-E02 | Credential-shape-agnostic identity states and versioned method/suite descriptors for embedded, resolved, rotating, threshold, and hybrid credentials | Lets Python support Ed25519, P-256, post-quantum, and external identity methods through one model |
| CORE-E03 | Versioned trust bundles, principal/grant status, rotation, compromise, history, and freshness operations | Supplies production lifecycle semantics without Python-authored protocol data |
| CORE-E04 | One review model plus exact approval-policy/session commitments independent of approval presence | Makes explain, audit, and approval agree without coupling them |
| CORE-E05 | Bounded single and batch verification with identical result meaning and cancellation checkpoints | Enables native throughput and safe GIL release without a weaker fast path |
| CORE-E06 | Stable cross-language error, explanation, inspection, and telemetry event schemas | Keeps operational meaning consistent with Rust and TypeScript |
| CORE-E07 | Versioned profile manifests, authority projections, command decoders, mutation fixtures, and conformance metadata | Enables a sound Python profile kit after the second profile |
| CORE-E08 | Replay, budget reservation, receipt, retry, and outcome-unknown state machines behind storage/effect ports | Enables reliable enforcement under concurrency and crashes |
| CORE-E09 | Cross-language customer-journey corpus covering success, failure, mutation, lifecycle, providers, cancellation, concurrency, and downgrade | Proves workflow parity beyond the current shared happy-path projection |
| CORE-E10 | Exact runtime contracts across Rust, WASM, TypeScript, and Python artifacts | Makes a mismatched wheel or core fail clearly at load time |

These identifiers are shared with the TypeScript elite specification. The
first SDK that needs one lands the Rust implementation and shared fixtures;
the second consumes it. No duplicate Rust operation or semantic identity is
created for language convenience. Formal and semantic-freeze artifacts change
only when the governed meaning changes.

## 6. Public APIs and package topology

The intended Python topology is:

```text
auths                         integrated attach/delegate/authorize path
auths.identity                standalone identity and authentication
auths.integrations            bounded identity transport and framework ports
auths.trust                   trust bundles, evidence, and freshness inputs
auths.authority               grants, delegation, plans, lifecycle links
auths.approvals               approval policies and provider Protocols
auths.custody                 signer descriptors and provider Protocols
auths.profiles.mcp            maintained MCP profile
auths.profiles.<second>       second structurally different profile
auths.profile_kit             application-owned profile construction
auths.runtime                 replay/budget/receipt/executor Protocols
auths.verify                  deterministic, effect-free verification
auths.inspection              safe decision and commitment projection
auths.diagnostics             inert caller-supplied/differential engines
auths.testkit                 deterministic fixtures and conformance
```

Imports must remain cheap and side-effect-free. Importing a submodule must not
load unrelated profiles, start an event loop, open a network connection, read
ambient credentials, or initialize a provider. Native initialization may be
lazy, thread-safe, deterministic, and observable.

There is no `auths.advanced` catch-all. It hides the useful verification-only
product and mixes three different trust boundaries. `auths.verify`,
`auths.inspection`, and `auths.diagnostics` state the exact capability being
imported. None exposes or constructs `VerifiedAction`, a profile command, or a
plan command; only the package-owned full workflow can mint those native
one-use handles after successful verification.

The base wheel owns semantic facades, ports, and conformance—not the Python
ecosystem. A small set of reference adapters may be maintained as separately
versioned extras or packages to prove browser-independent local signing,
remote custody, resolver, durable state, telemetry, and framework integration.
They must not become base dependencies or sources of Auths meaning.

## 7. Delivery program

### PY-E0 — Freeze the elite contract and measurements

- [x] Inventory public Python names, native classes, module topology,
      supported interpreters/platforms, and claims from the installed wheel.
- [x] Record import, initialization, verification, plan, batch, memory,
      event-loop, and wheel-size baselines.
- [x] Freeze the error hierarchy, async policy, typing policy, exact runtime
      contract, prelaunch clean-break policy, threat model, and exact non-goals.
- [x] Make the scorecard in section 3 CI-readable capability metadata.
- [x] Replace the single shared workflow projection with the CORE-E09 scenario
      matrix used by Rust and TypeScript.

**Exit:** implementation, evidence, promoted tier, runtime support, and product
claims are independently versioned and cannot contradict one another.

### PY-E1 — Make the first 15 minutes exceptional

- [x] Provide an installed-wheel identity quickstart and a complete protected
      MCP action quickstart with no source-tree imports.
- [x] Reduce setup to typed Python configuration with no raw protocol bytes,
      copied constants, manual hashes, or direct native-handle management.
- [x] Replace `auths.advanced` with the direct `auths.verify`,
      `auths.inspection`, and `auths.diagnostics` modules, deleting the old
      module and every stale reference in the same prelaunch cutover.
- [x] Add obvious development-only signers, approvals, clocks, stores, and
      gateways under `auths.testkit`.
- [x] Add a diagnostic report for exact wheel/native ABI agreement, native
      capabilities, adapters, trust, profiles, and configuration commitments.
- [x] Execute every documentation snippet and both quickstarts in isolated CI.

**Exit:** a Python developer unfamiliar with Auths completes both journeys
without reading Rust, TypeScript, or the protocol specification.

### PY-E2 — Build the standalone identity product

- [x] Bind CORE-E02 and expose decoded, validated, resolved, and authenticated
      identity states under `auths.identity`.
- [x] Ship raw-key/Ed25519 and one structurally different reference path such
      as P-256 or resolver-backed identity to prove the port.
- [x] Define async-capable method, suite, and resolver `Protocol` contracts
      with exact version, purpose, timeout, and cancellation behavior.
- [x] Add rotation, history, composite, threshold, and hybrid/post-quantum
      conformance fixtures without claiming every adapter is maintained.
- [x] Add one explicit validated-identity-to-authority bridge that preserves
      method, suite, purpose, provenance, and assurance.
- [x] Prove the identity-only wheel import graph contains no authority,
      approval, profile, or runtime dependency.

**Exit:** Python users can adopt Auths identity and authentication alone, then
add permissions without changing identity meaning.

### PY-E3 — Reach full profile and plan breadth

- [x] Add a second maintained profile that differs materially from MCP in
      action shape, resource projection, gateway, and receipt behavior.
- [x] Bind CORE-E07 and implement `auths.profile_kit` only after the second
      profile demonstrates the reusable boundary.
- [x] Give each profile distinct action, authority, command, plan-command,
      gateway, receipt, and error types.
- [x] Add Rust-owned all-of, any-of, and threshold proof plans alongside exact
      ordered profile plans.
- [x] Provide semantic mutation and gateway conformance suites for maintained
      and application profiles.
- [x] Test cross-profile, cross-version, order, duplicate, omission, append,
      substitution, partial failure, and command-forgery attacks.

**Exit:** Python is no longer “the MCP binding”; it is a sound platform for
multiple closed action domains.

### PY-E4 — Productize trust, status, and lifecycle

- [x] Bind CORE-E03 as typed trust bundles, status snapshots, assurance rules,
      rotation, compromise, historical state, and freshness inputs.
- [x] Add resolver and evidence-provider `Protocol` contracts with provenance,
      timeout, cancellation, size, redirect, cache, and SSRF limits.
- [x] Expose principal-status and grant-status authoring without raw bytes or a
      generic signing operation.
- [x] Make missing, stale, contradictory, and unavailable evidence produce
      stable denied or indeterminate results.
- [x] Add offline evidence bundles and lifecycle recipes for delegation
      withdrawal, identity rotation, compromise, and clean prelaunch policy
      replacement.

**Exit:** a production service can explain and change what it trusts without
rotating identity merely to withdraw delegated authority.

### PY-E5 — Perfect authoring, delegation, approval, and cleanup

- [x] Consolidate attach, delegation, action authoring, and plan orchestration
      over CORE-E01 while keeping Python callback scheduling explicit.
- [x] Expose review data independently before any approval request.
- [x] Support no approval, grant-only, every-action, risk-gated, threshold,
      and exact plan-once policies from one immutable committed model.
- [x] Prove non-widening across permission, resource, audience, validity,
      budget, status, assurance, profile, extension, and delegation depth.
- [x] Specify cancellation and cleanup for provider rejection, timeout,
      duplicate callback, task cancellation, exception groups, and process
      shutdown.
- [x] Guarantee that partial workflows expose no reusable native transaction
      or profile command.

**Exit:** async Python failures cannot bypass attenuation, leak reusable
authority, or leave ambiguous cleanup ownership.

### PY-E6 — Close enforcement, replay, budgets, and receipts

- [x] Bind CORE-E08 and expose challenge, replay, budget, receipt, store, and
      closed-executor `Protocol` contracts.
- [x] Model reserved, executing, executed, failed, duplicate, exhausted,
      unavailable, cancelled, and outcome-unknown states exhaustively.
- [x] Require idempotency and reconciliation behavior from effectful gateways;
      never imply remote atomicity or exactly-once execution.
- [x] Ship an in-memory test implementation and one separately packaged
      durable reference store.
- [x] Prove denied, indeterminate, forged, mismatched, expired, replayed, and
      exhausted commands cause no gateway call and no state mutation.
- [x] Bind profile-owned receipts back to exact command, authority, context,
      state claim, and observed provider outcome.

**Exit:** Python services can operate authorized effects safely under retries,
concurrency, crashes, and uncertain remote outcomes.

### PY-E7 — Make Python integrations replaceable and certifiable

- [x] Version signer, approval, identity, suite, resolver, status, clock,
      store, telemetry, gateway, transport, and framework `Protocol` contracts.
- [x] Publish executable sync/async adapter conformance suites where the port
      permits both; security workflows remain async-native.
- [x] Maintain only a small reference set proving local, remote-custody,
      resolver, durable-state, telemetry, and web-framework substitution.
- [x] Provide recipes for one remote KMS/HSM family, one resolver family, one
      durable store, OpenTelemetry, and FastAPI without importing them into the
      base wheel.
- [x] Define third-party adapter qualification metadata, support ownership,
      dependency policy, and security-claim boundaries.

**Exit:** the Python ecosystem can extend Auths without a central adapter team
or semantic plugins.

### PY-E8 — Deliver elite errors, typing, and observability

- [x] Bind CORE-E06 into one stable `AuthsError` hierarchy and immutable
      decision/explanation/inspection types.
- [x] Publish strict mypy and Pyright fixtures for every state transition,
      provider port, result union, profile command, and context manager.
- [x] Make public signatures useful in IDEs without requiring users to import
      private native classes or understand handle lifetimes.
- [x] Add OpenTelemetry-compatible hooks with no required exporter and no raw
      proof, key, credential, signature, or high-cardinality payload fields.
- [x] Add a deterministic, redacted support bundle and decision timeline.
- [x] Test `str`, `repr`, traceback, dataclass projection, logging, telemetry,
      pickle, copy, and introspection for secret and capability leakage.

**Exit:** failures are actionable to Python developers and safe to share with
operators, while types prevent normal misuse before runtime.

### PY-E9 — Add native throughput without changing meaning

- [x] Bind CORE-E05 as bounded `verify_many` and plan/bundle operations that
      preserve input order and per-item three-valued results.
- [x] Release the GIL around pure native work and reacquire it only at explicit
      Python callback boundaries.
- [x] Bound buffer copies, batch size, memory, work, result count, and
      cancellation latency.
- [x] Make sync native calls safe from threads and async workflows safe across
      task cancellation; do not hide thread pools or event loops.
- [x] Benchmark standard CPython versions and operating systems against Phase
      0 budgets.
- [x] Prove batch output equals independent single-item Rust, TypeScript, and
      Python evaluation across CORE-E09; Python exposes no semantic result
      cache.

**Exit:** Python can serve high-volume decisions efficiently without acquiring
a separate fast-path security model.

### PY-E10 — Make wheels and releases boring

- [x] Enforce CORE-E10 exact ABI identities and native/package subject matching
      at import and workflow construction.
- [x] Qualify source distributions only if intentionally supported; otherwise
      fail installation with an accurate wheel-support message.
- [x] Test exact release wheels on every claimed CPython, architecture, and OS
      with Rust and the source tree absent.
- [x] Keep imports side-effect-free and prove package-content, API, type,
      license, SBOM, provenance, and claim manifests agree.
- [x] Add current-wheel/current-native agreement fixtures and fail-closed
      mismatched-artifact tests; support no cross-version runtime window.
- [x] Complete repository fuzzing, hostile native-boundary tests, dependency
      review, and external-consumer qualification.
- [ ] Complete independent external security and consumer review against the
      exact release candidate.
- [x] Remove superseded public surfaces directly, with automated stale-reference,
      API-snapshot, typing, and exact-artifact checks in the same change.

**Exit:** one Python release is internally coherent and installable with no
local compiler, hidden source dependency, legacy path, or claim drift.

## 8. Required test matrix

Every public workflow must cover:

- authorized, denied, and indeterminate outcomes;
- malformed, oversized, non-canonical, unknown-version, and unsupported-suite
  inputs;
- identity method/suite mismatch, downgrade, rotation, compromise, stale
  resolution, composite, threshold, and hybrid credentials;
- widening in every authority dimension;
- native handle construction, subclassing, copying, deep copying, pickling,
  reflection, mutation, serialization, substitution, replay, expiry, and
  double consumption;
- signer, approval, resolver, clock, store, telemetry, and gateway failures at
  every callback boundary;
- coroutine cancellation before, during, and after native and provider work;
- plan reordering, duplication, omission, append, partial failure, retry,
  concurrency, and outcome unknown;
- concurrent replay claims and budget exhaustion;
- GIL release, thread use, interpreter shutdown, and deterministic disposal;
- source and isolated installed-wheel consumers;
- strict mypy and Pyright positive and negative consumers; and
- Rust/TypeScript/Python differential scenarios from CORE-E09.

## 9. Explicit non-goals

This specification does not authorize:

- a mandatory Auths cloud, account, network, registry, wallet, daemon, or
  hosted verifier;
- coupling identity exchange or authentication to capabilities, approvals,
  policy, profiles, or gateways;
- Python implementations of canonicalization, commitments, attenuation,
  verification, lifecycle, or profile-command meaning;
- a generic policy language, action payload, profile executor, or semantic
  plugin system;
- a second blocking workflow facade over the async provider path;
- ownership of every Python framework, identity, suite, custody, resolver,
  transport, storage, or telemetry adapter;
- private-key export or persistence in the base wheel;
- silent fallback between methods, suites, profiles, policies, or providers;
- backward-compatibility shims, deprecated aliases, legacy readers, migration
  helpers, dual paths, version-support windows, or old/new wheel/core fixtures;
- automatic effect execution merely because authorization succeeded;
- collapsing indeterminate into a Boolean;
- hidden retries across signing, approval, state, or provider effects;
- remote atomicity, exactly-once, instant revocation, or current-global-status
  claims; or
- PyPy, free-threaded CPython, stable-V1, production, certification, or review
  claims before exact qualification explicitly adds them.

## 10. Definition of done

The Python SDK earns the elite label only when an external team can, from the
exact installed wheel and public documentation:

1. exchange and authenticate identity without authority dependencies;
2. substitute identity, suite, signer, approval, resolver, store, telemetry,
   and gateway adapters through executable conformance contracts;
3. attach an agent and delegate strictly narrower authority with an exact,
   readable diff;
4. authorize actions and plans across at least two maintained profiles;
5. define a custom profile without raw protocol bytes or Python command
   branding;
6. execute only matching, native-minted, one-use commands;
7. withdraw delegation, rotate identity evidence, refresh trust, reject replay,
   consume budget, and emit an exact receipt;
8. recover safely from timeout, cancellation, retry, concurrency, and unknown
   provider outcomes;
9. diagnose behavior with stable errors, types, redacted events, and support
   evidence;
10. process bounded batches efficiently without changing single-item meaning;
11. produce the same semantic outcomes as Rust and TypeScript across CORE-E09;
12. install and operate on the claimed wheel matrix with exact ABI,
    performance, provenance, and review evidence.

Until all twelve are true, the repository may describe the completed Python
elite surface, but the released cross-SDK product must not claim stable-V1,
production, certification, or independent-review status.

### 10.1 Qualification state

| Gate | State | Evidence or owner |
| --- | --- | --- |
| Python repository implementation | Complete | `bindings/python/sdk-capability.json`, exact public API snapshot, native ABI 2 manifest, and customer-journey matrix |
| Source behavior, strict typing, adapter, and installed-wheel qualification | Enforced in CI | `.github/workflows/python-sdk.yml` |
| Exact CPython 3.9–3.14 Linux/macOS/Windows wheel boundary | Enforced in CI | abi3 wheel matrix with the Rust toolchain removed from consumers |
| Rust/TypeScript/Python current-version parity | Complete | `bindings/customer-journey-matrix-v1.json` and generated differential fixtures |
| Independent external review | Pending | Must review the exact release candidate; implementation code cannot self-attest it |
| Stable-V1 publication and promotion | Blocked | Release owner authorization after exact CI, provenance, and external-review gates |

The implementation may be described as the completed Python elite surface.
Publication, production readiness, and independent review remain separate
release decisions.
