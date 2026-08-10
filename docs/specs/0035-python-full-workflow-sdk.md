# AP-SPEC-035: Python Full Workflow SDK

**Status:** Milestones A and B implemented on the immutable RC baseline as a
repository-local pre-review surface; Full Workflow promotion remains blocked
on the later AP-SPEC-035 exit gates

**Governs:** The Python Full Workflow SDK addition to Phase 10 in the
[Post-Milestone 6 Productization and Release
Plan](../target-state/POST_MILESTONE_6_PRODUCTIZATION_AND_RELEASE_PLAN.md)

**Source strategy:** [Auths Product and Go-to-Market
Strategy](../plans/GO_TO_MARKET_STRATEGY.md)

**Aligned with:** [AP-SPEC-027](0027-product-grade-typescript-sdk.md), the
cross-language capability-tier contract in
[issue 72](https://github.com/auths-dev/auths-proof/issues/72), and the Python
sealed-action finding in [issue 73](https://github.com/auths-dev/auths-proof/issues/73)

**Depends on:** AP-SPEC-027's language-neutral workflow contract,
AP-SPEC-032, AP-SPEC-033, `auths-sdk`, `auths-author`, `auths-custody`, the
selected profile package, the reviewed canonical corpus, and the maintained
Python native-binding toolchain

**Scope:** The `auths` Python distribution and import root for creating or
loading principals, attaching agents, authoring bounded grants and exact
profile actions, delegating narrower authority, assembling trusted inputs,
signing through provider-neutral custody, verifying locally, decoding
non-forgeable profile commands, and returning typed three-valued decisions on
supported CPython versions and operating systems

**Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are
requirements on conforming implementations.

## 1. Decision

Auths will expand the existing `auths` Python package in place from a
**Verifier Binding** to a **Full Workflow SDK**. It will not create a competing
package or make Python a second implementation of Auths semantics.

The normal activation is:

> Attach a Python agent to Auths, give it bounded authority, delegate a
> narrower child, and authorize one exact profile action without hand-authoring
> CBOR, signing preimages, attenuation logic, or verifier context.

The current `verify(proof_cbor, canonical_action_cbor,
trusted_context_cbor)` operation remains available as an explicitly advanced
verifier surface. It is not the Full Workflow API.

Rust owns protocol semantics, authoring, attenuation, canonicalization,
trusted-context construction, verification, and sealed profile decoding.
Python owns idiomatic workflow objects, `Protocol` interfaces, asynchronous
provider coordination, resource lifetime, typed results, exceptions,
documentation, and packaging. Python MUST NOT reproduce these Rust semantics
with dictionaries, dataclasses, handwritten CBOR, or a parallel evaluator.

The package MUST work without an Auths-hosted service. Platform custody and
evidence providers remain optional and explicit.

## 2. Capability tier and claim

Issue 72 defines three tiers:

```text
Verifier Binding
  bytes -> authorized | denied | indeterminate
        |
        v
Authoring SDK
  principals + grants + delegation + actions + signing requests
        |
        v
Full Workflow SDK
  attach + delegate + authorize + explain + sealed profile command
```

The Python package MUST be labeled according to the highest tier whose exit
gate has actually passed. Shipping a class with workflow-shaped names is not
enough: the implementation must traverse supported native Rust authoring and
verification boundaries, and an authorized result must carry a genuinely
non-forgeable command capability.

After this specification closes, the bounded claim is:

> A Python application can create or load an agent through an external signer,
> author and review bounded authority, delegate only narrower authority,
> construct an exact supported profile action, verify locally, and hand a
> native-sealed command to a closed gateway without reconstructing Auths wire
> or policy semantics.

This claim does not include production custody, a hosted control plane,
provider correctness, exactly-once external effects, or stable-v1 API
compatibility.

## 3. Phase placement and entry gate

Implementation begins only after:

- AP-SPEC-032 provides an immutable baseline package and exact assurance
  bundle;
- AP-SPEC-033 permits the explicitly bounded post-review SDK work;
- AP-SPEC-027 freezes the language-neutral workflow vocabulary and security
  boundaries so Python does not invent a competing semantic model;
- issue 73 has an approved native non-forgeability design;
- the threat model identifies new PyO3, Python-object, callback, async,
  serialization, and package-supply-chain surfaces; and
- release automation distinguishes a Full Workflow preview from a stable-v1
  or independently reviewed claim.

A change to frozen Rust semantics returns through the release and review
change classifications. Binding-only ergonomics MAY proceed as bounded Phase
10 work when they do not alter the reviewed semantic closure.

## 4. Existing baseline

The implementation begins from:

- `bindings/python`, which builds the `auths` distribution through PyO3 and
  Maturin;
- the current three-input native verifier and three verdict dataclasses;
- `auths-sdk`, which owns trusted-context construction and sealed profile
  decoding;
- `auths-author`, which plans non-widening grants and creates exact signing
  requests;
- `auths-custody`, which binds external provider output to an exact signing
  transaction; and
- the canonical V1 corpus and binding vectors.

The current Python `VerifiedAction` constructor guard uses an accessible
module-level object. It is conventionally private, not non-forgeable. It MUST
NOT be accepted by a protected gateway or cited as sealed-command evidence.
Issue 73 governs its direct replacement; no compatibility shim is required
because Auths is prelaunch.

## 5. Goals

The Python Full Workflow SDK MUST provide:

- an idiomatic typed API for supported CPython versions;
- a short `attach_agent` workflow;
- safe principal creation/loading through a signer port;
- bounded root-grant and child-grant planning;
- semantic parent-to-child authority diffs and over-granting warnings;
- exact MCP action construction through profile-owned helpers;
- typed trusted-authority and request-context builders;
- local verification through the canonical Rust implementation;
- exhaustive authorized, denied, and indeterminate result types;
- stable kernel stages, codes, commitments, metrics, and safe explanations;
- a native non-forgeable authorized action and profile command;
- deterministic cleanup for ephemeral signers and attached child agents;
- advanced access to raw verifier inputs/results without capability promotion;
- synchronous raw verification and asynchronous provider workflows with clear
  ownership; and
- wheels, type information, examples, and documentation reproducible from a
  clean external consumer environment.

## 6. Non-goals

This specification MUST NOT:

- build a CLI, daemon, hosted service, wallet, identity provider, policy
  language, or arbitrary executor;
- make Python the source of canonical encoding, attenuation, verification, or
  stable result codes;
- require an Auths account or network access for verification;
- expose a general `sign(bytes)` operation;
- store or export private keys;
- silently fall back between custody providers;
- turn an authorized result into an automatic provider effect;
- collapse MCP, HTTP, Stripe, database, or infrastructure actions into one
  dictionary with an operation tag;
- catch denied or indeterminate outcomes and convert them into exceptions,
  retries, or authorization;
- claim Python object privacy, underscores, name mangling, or undocumented
  constructors are a security boundary;
- require native platform providers merely to import the base package; or
- claim stable-v1 compatibility, production readiness, certification, or
  independent review of the new workflow surface.

## 7. Developer experience

### 7.1 First workflow

The supported shape is:

```python
from auths import Approval, Authorized, AuthsClient, Denied, Indeterminate, mcp

async with AuthsClient(
    signer=signer,
    trusted_authority=trusted_authority,
) as auths:
    parent = await auths.attach_agent(
        name="research-agent",
        profile=mcp.profile(service="records"),
        authority=parent_grant,
        approval=Approval.grant_only(policy, approval_provider),
    )

    async with await parent.delegate(
        name="records-child",
        authority=mcp.tools(["update_demo_record"]),
        signer=ephemeral_signer,
    ) as child:
        result = await child.authorize(
            mcp.call("update_demo_record", {"value": "reviewed"})
        )

        if isinstance(result, Authorized):
            await protected_tools.execute(result.command)
        elif isinstance(result, Denied):
            report(result.explanation)
        else:
            assert isinstance(result, Indeterminate)
            request_required_fact(result.explanation)
```

Names MAY improve during API review. The authority stages, three outcomes,
profile ownership, signer boundary, and sealed-command handoff are normative.

The normal path MUST NOT expose or require proof CBOR, canonical action CBOR,
trusted-context CBOR, signature descriptors, registry identifiers, or manual
configuration commitments.

### 7.2 Sync and async rule

Pure native construction, inspection, and raw verification MAY be synchronous.
Any operation that can call a signer, approval provider, evidence provider, or
other application callback MUST be asynchronous.

The SDK MUST NOT run a nested event loop, call `asyncio.run()` inside a public
workflow, or block an event-loop thread while waiting for provider I/O. Sync
convenience wrappers MAY be considered only after an independent use case and
must be separate from the canonical async API.

### 7.3 Errors and verdicts

- Construction, configuration, callback-protocol, disposal, and native ABI
  failures raise closed typed `AuthsError` subclasses.
- Proof evaluation returns `Authorized`, `Denied`, or `Indeterminate` and does
  not throw solely because authority was not established.
- `CancelledError`, timeout, provider unavailable, wrong transaction, wrong
  principal, duplicate response, and disposed-resource use remain distinct.
- Exceptions and representations MUST NOT contain proof bytes, signing bytes,
  signatures, provider credentials, passphrases, private material, or arbitrary
  callback exception objects.
- Safe guidance MAY be added, but stable native stages and codes MUST survive
  unchanged.

## 8. Architecture

```text
+------------------------------ Python application -------------------------+
| attach_agent -> delegate -> profile action -> authorize -> closed gateway |
+---------|-----------|-------------|-------------|-------------------------+
          |           |             |             |
          v           v             v             v
+--------------------------- auths Python SDK -------------------------------+
| async workflow | Protocol ports | typed results | lifetime | explanations |
+----------------------------------|-----------------------------------------+
                                   v
+------------------------- PyO3 native boundary -----------------------------+
| opaque handles | bounded conversion | callback request/response validation |
+----------------------------------|-----------------------------------------+
                                   v
+--------------------------- canonical Rust owners --------------------------+
| auths-author | auths-custody | auths-sdk | profile | verifier | codec       |
+----------------------------------------------------------------------------+

External providers receive exact requests only:

Signer / approval / evidence provider <-> Python protocol adapter
Closed profile gateway              <- native-sealed profile command
```

### 8.1 Ownership

Python owns:

- public naming, type annotations, overloads, protocols, async orchestration,
  context managers, exception projection, safe representations, examples, and
  generated documentation;
- defensive conversion between Python `bytes` and bounded native inputs; and
- provider callback invocation after a native exact request exists.

Rust owns:

- principal and protocol identifiers;
- grant and action statements;
- authority comparison and attenuation;
- canonical encoding and signing preimages;
- trusted-context and request-context construction;
- proof assembly and verification;
- stable stages/codes and configuration commitments; and
- authorized action sealing and profile command decoding.

Profile packages own exact actions and command types. The Python package MAY
expose a profile facade, but MUST NOT translate arbitrary dictionaries into a
generic effect.

### 8.2 Native handles and non-forgeability

Effect-capable objects MUST be native extension types or native-owned opaque
handles whose constructors and payload replacement are unavailable to Python.
Only the successful native verification branch may create the authorized
handle. Only the selected profile's native decoder may derive its command.

The implementation MUST reject or prevent:

- direct construction with arbitrary bytes;
- access to a module-global sentinel;
- subclass-based construction or state injection;
- `copy.copy`, `copy.deepcopy`, `pickle`, `__reduce__`, and dataclass
  reconstruction;
- mutation through a writable buffer or aliased `bytearray`;
- conversion of advanced canonical bytes back into a capability; and
- reuse after consumption or disposal where the command is linear.

A Python wrapper MAY expose a safe summary, but the effect gateway consumes
the native-sealed command—not the summary, original action dictionary,
decision Boolean, or canonical bytes.

### 8.3 Provider boundary

Provider protocols receive immutable semantic summaries plus exact opaque
native requests:

```python
class Signer(Protocol):
    kind: str
    lifecycle: Literal["durable", "ephemeral"]

    async def public_identity(self) -> PrincipalDescriptor: ...
    async def sign(self, request: SigningRequest) -> SigningResponse: ...
    async def aclose(self) -> None: ...

class ApprovalProvider(Protocol):
    async def approve(self, request: ApprovalRequest) -> ApprovalResponse: ...
```

`SigningRequest` MUST expose the object kind, safe review fields, exact
transaction digest, expiry, and read-only signing preimage selected by Rust.
The response MUST bind the same request, transaction, principal, descriptor,
and provider instance. The SDK validates this binding before completing a
signed object.

Agent and profile code MUST never receive a signer handle capable of arbitrary
signing. Cleanup must run on normal exit, exception, cancellation, and partial
child construction.

### 8.4 Trusted context and approval

The normal API accepts typed trust roots, supported profiles, request audience,
challenge, explicit time, evidence/status snapshots, assurance policy, and
bounded limits. Rust compiles these into the exact verifier context.

Approval uses the four modes reserved by AP-SPEC-027: grant-only, risk-based,
every-action, and registered custom. The signed grant or trusted context commits
the policy identifier, evaluator version, and configuration digest.

Required and executed commitments MUST match before approval, signing,
credential acquisition, or effect-capable command release. A missing,
throwing, ambiguous, cancelled, or mismatched evaluator fails closed and
produces no signature or command.

## 9. Public API contract

The exact class names MAY change during implementation review; the ownership
and capability split are normative.

```python
ProfileT = TypeVar("ProfileT", bound=Profile)

class AuthsClient:
    def __init__(
        self,
        *,
        signer: Signer,
        trusted_authority: TrustedAuthority,
    ) -> None: ...

    async def attach_agent(
        self,
        *,
        name: AgentName,
        profile: ProfileT,
        authority: SignedGrantSource,
        approval: ApprovalConfiguration,
    ) -> AttachedAgent[ProfileT]: ...

    def verify_raw(self, input: RawVerificationInput) -> VerificationResult: ...

    async def __aenter__(self) -> AuthsClient: ...
    async def __aexit__(self, *exc: object) -> None: ...

class AttachedAgent(Generic[ProfileT]):
    identity: AgentIdentity
    authority: EffectiveAuthoritySummary

    async def delegate(
        self,
        *,
        name: AgentName,
        authority: AuthorityRequest[ProfileT],
        signer: Signer,
    ) -> AttachedAgent[ProfileT]: ...

    async def authorize(
        self,
        action: ProfileT.Action,
    ) -> AuthorizationResult[ProfileT.Command]: ...
```

Runtime support begins at Python 3.9, matching the current `abi3-py39`
package. Shipping annotations MUST use syntax accepted by every supported
runtime or generated stubs compatible with that floor. Type-system convenience
does not authorize raising the minimum Python version accidentally.

The package MUST ship `py.typed` and complete public stubs or inline
annotations. `mypy` and Pyright consumer fixtures MUST prove that:

- authorized branches expose a command;
- denied and indeterminate branches do not;
- profile command types do not cross profile families;
- raw bytes are not accepted where a command is required; and
- provider request/response types are exact.

## 10. Validation and hard limits

- Every bytes-like input is copied or borrowed immutably under a documented
  PyO3 lifetime and checked before allocation.
- Proof, action, context, evidence, plan, chain, depth, and work limits are the
  smaller of the deployed Rust limits and binding limits.
- Python integers are range-checked before conversion to Rust integer types;
  overflow and negative time/budget values are typed failures.
- Agent/provider identifiers and approval display fields have explicit byte
  and scalar limits.
- Provider evidence count and aggregate bytes follow the core limits.
- Callback concurrency is bounded; cancellation cannot leave a native request
  reusable or a signer undisposed.
- Decoders reject non-canonical, trailing, unknown-version, duplicate,
  over-depth, and oversized data.
- `repr`, exception text, tracing, pickling errors, and generated docs contain
  no raw secret or signing material.
- The binding MUST NOT increase a kernel hard limit or accept a Python value
  the canonical Rust constructor rejects.

## 11. Required evidence

Implementation MUST add:

- unit tests for every public result, protocol, exception, context manager,
  and ownership transition;
- canonical positive and negative attach/delegate/authorize fixtures;
- Python/Rust/TypeScript agreement on the shared Full Workflow fixture
  projection: verdict, stage, code, canonical digests, commitments, metrics,
  authority diff, and command summary;
- widening tests for permission, resource, audience, validity, budget,
  delegation depth, status policy, assurance, profile, and critical extension;
- mutation tests proving one changed action or signing-request byte invalidates
  the workflow;
- issue-73 adversarial construction, copying, pickling, subclassing,
  reflection, buffer-alias, and byte-to-capability tests;
- signer wrong-request, wrong-transaction, wrong-principal, wrong-descriptor,
  duplicate, timeout, cancellation, unavailable, and post-disposal tests;
- approval-policy omission, mismatch, weakening, throwing, ambiguity,
  cancellation, and duplicate-response tests with zero downstream calls;
- async cancellation tests at every provider boundary and cleanup point;
- type-checker fixtures for mypy and Pyright;
- tests against the built wheel, not only the source tree;
- isolated wheel install/import/workflow smoke tests with no Rust toolchain and
  no Auths checkout;
- wheel-content tests proving no private keys, development seeds, source-only
  fixtures, caches, or unintended shared libraries ship;
- CPython 3.9 and current supported-version coverage on Ubuntu, macOS, and
  Windows for every published wheel family;
- `architecture.toml`, `compliance.toml`, release inventory, SBOM, provenance,
  and exact-claim updates; and
- documentation examples compiled, type-checked, and executed in CI.

The shared conformance projection establishes semantic parity, not identical
language syntax or runtime implementation.

## 12. Bounded PR units

1. **`AP35-PR1` — capability contract and Python threat model.** Freeze the
   public workflow, async/sync split, native ownership model, serialization and
   reflection threats, hard limits, supported runtimes, and exact claim
   exclusions. No production behavior changes.
2. **`AP35-PR2` — non-forgeable native result boundary.** Replace the current
   sentinel-protected Python `VerifiedAction` with the approved issue-73 native
   handle; preserve verifier results and add the complete adversarial corpus.
3. **`AP35-PR3` — native authoring ABI.** Bind existing Rust principal,
   grant-planning, delegation, status, trusted-context, and exact-signing
   operations. Add ABI versions and differential fixtures; do not duplicate
   Rust constructors in Python.
4. **`AP35-PR4` — provider protocols and lifecycle.** Implement signer and
   approval protocols, request/response binding, async cancellation, context
   managers, deterministic disposal, and safe exception projection. Ship no
   production custody provider.
5. **`AP35-PR5` — attach and root authority.** Implement `AuthsClient`, typed
   trusted authority, `attach_agent`, root/signed grant inputs, summaries, and
   construction failures without raw normal-path CBOR.
6. **`AP35-PR6` — delegation and attenuation.** Implement child planning,
   semantic diffs, over-granting warnings, approval, signing, and the full
   negative widening matrix.
7. **`AP35-PR7` — MCP authorize and sealed command.** Add the profile-owned MCP
   facade, proof/context assembly, three-valued verification, native profile
   command decoding, and a closed gateway handoff. No generic executor.
8. **`AP35-PR8` — advanced API, typing, and explanations.** Preserve raw
   verification and bounded inspection, add stable explanation/metrics APIs,
   ship type information, and prove raw objects cannot become capabilities.
9. **`AP35-PR9` — wheel and external-consumer closure.** Build the exact wheel
   matrix, install into isolated environments, execute examples and shared
   fixtures, inspect package contents, and close architecture, compliance,
   release, SBOM, provenance, and documentation evidence.

Every implementation PR MUST identify the exact baseline/RC digest, tests and
fixtures, capability tier affected, security invariants, supported and
excluded claims, and remaining gates. A later PR MUST NOT bypass an earlier
native-sealing, semantic-parity, or package-integrity failure.

## 13. Exit gate

The Python Full Workflow SDK gate is complete only when:

- a new Python developer can run attach/delegate/authorize from an installed
  wheel without hand-authoring protocol CBOR or using an Auths checkout;
- the normal path requires no hosted service or provider credential;
- child delegation cannot widen any authority dimension;
- private keys remain within the selected signer provider;
- only native authorized verification can produce a profile command accepted
  by the closed gateway;
- every issue-73 forgery, copy, serialization, reflection, and mutation attack
  fails;
- authorized, denied, and indeterminate remain exhaustive distinct outcomes;
- stable Rust stages, codes, commitments, digests, and metrics survive through
  Python;
- required and executed configuration/approval commitments match before any
  approval, signature, credential, or command release;
- Python, Rust, and TypeScript agree on the shared workflow fixtures;
- async cancellation and disposal tests prove no reusable partial signing or
  command state remains;
- the exact wheel installs and runs on the declared CPython/macOS/Linux/Windows
  matrix without a Rust compiler;
- package content, architecture, compliance, SBOM, provenance, documentation,
  and authoritative repository checks pass on the same revision; and
- the release manifest and issue-72 matrix label Python Full Workflow only
  after all preceding evidence exists.

Passing this gate does not claim stable-v1 compatibility, production custody,
complete MCP provider execution, production readiness, independent review of
the new binding code, or commercial readiness.
