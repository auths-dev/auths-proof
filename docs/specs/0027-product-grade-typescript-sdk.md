# AP-SPEC-027: TypeScript Full Workflow SDK

**Status:** Repository-local implementation authorized before Phase 9 by the
repository owner on 2026-08-04; publication, promotion to the Full Workflow
tier, and reviewed-security claims remain blocked on AP-SPEC-032,
AP-SPEC-033, and issue 74; capability and non-forgeability gaps are tracked in
issues 71, 72, and 76; the broader native critical-extension attenuation gap
discovered during PR5 is tracked in issue 81; PR5 resolves the authoring
semantic-freeze coverage gap tracked in issue 82; PR6 corrects the proof
material and trusted-context contract gap tracked in issue 84; local external-
consumer feedback extended PR6 with a bounded application profile kit and an
explicit raw-key authority bootstrap tracked in issue 85

**Governs:** The TypeScript Full Workflow SDK portion of Phase 10 in the
[Post-Milestone 6 Productization and Release Plan](../target-state/POST_MILESTONE_6_PRODUCTIZATION_AND_RELEASE_PLAN.md)

**Source strategy:** [Auths Product and Go-to-Market Strategy](../plans/GO_TO_MARKET_STRATEGY.md)

**Aligned with:** [Post-Milestone-6 Technical and Go-to-Market
Alignment](../plans/POST_MILESTONE_6_TECHNICAL_AND_GO_TO_MARKET_ALIGNMENT.md)

**Authority:** [Issue 71](https://github.com/auths-dev/auths-proof/issues/71)
and the cross-language capability-tier contract in
[issue 72](https://github.com/auths-dev/auths-proof/issues/72)

**Depends on:** AP-SPEC-032, AP-SPEC-033, the reviewed release candidate and
assurance claim, the `auths-sdk` Rust package, `auths-proof-wasm`,
`auths-profile-mcp`, and the reviewed canonical corpus

**Scope:** An explicitly labeled, cross-platform TypeScript Full Workflow SDK
over the reviewed Rust/WASM implementation for creating or loading principals,
attaching agents, authoring bounded grants and exact profile actions,
delegating narrower authority, assembling trusted inputs, signing through
provider-neutral custody, verifying locally, decoding sealed commands, and
returning structured decisions on macOS, Linux, Windows, and supported browsers

**Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are
requirements on conforming implementations.

## 1. Decision

Auths will make the existing `@auths-dev/sdk` coordinate the first polished
developer-preview SDK.

The package currently exposes the portable three-input verifier and a sealed
`VerifiedAction`. Phase 10 will expand that coherent package in place rather
than create a competing TypeScript SDK. Because Auths is prelaunch, the
implementation MAY make a clean API break. It MUST keep the raw verifier
available as an explicit advanced surface.

The primary activation is:

> Attach an agent to Auths, give it bounded authority, and protect its first
> action without hand-authoring CBOR or verifier context.

Rust remains the semantic implementation. TypeScript owns ergonomic workflow,
resource lifetime, and integration types; it MUST NOT reimplement authority,
attenuation, canonicalization, or verification semantics.

The base SDK MUST run natively on macOS, Linux, and Windows. Platform-specific
custody providers are optional integrations and MUST NOT be required to load,
install, or use the portable authoring and verification surfaces.

The first Full Workflow package MAY remain visibly pre-v1 and
developer-preview quality.
It MUST NOT be represented as independently reviewed merely because its Rust
kernel dependency was reviewed in Phase 9; the new binding, workflow, and API
code requires its own tests and later release evidence.

## 2. Phase placement and implementation gate

The repository owner has authorized the bounded PR units in this specification
to be implemented and merged before Phase 9 so that SDK engineering can
proceed against the prepared baseline. This changes work sequencing, not the
strength of any release claim.

Pre-review implementation MUST satisfy all of these conditions:

- every PR remains repository-local and passes authoritative CI;
- package metadata and documentation continue to label the public surface
  **Verifier Binding** or pre-review implementation, never Full Workflow;
- no package, tag, release artifact, deployment, or reviewed claim is
  published or promoted;
- new Rust/WASM/TypeScript surfaces are added to the future Phase 9 scope;
- any change to frozen semantics, bytes, subjects, or claims returns through
  AP-SPEC-032's candidate-change process; and
- issue 74 remains the explicit release and promotion blocker.

Publication or promotion begins only after:

- AP-SPEC-032 has produced the immutable RC and exact claim bundle;
- AP-SPEC-033 has completed all required review tracks;
- no Phase 9 release block applies to the SDK surfaces or claims;
- the Phase 9 owner approval permits an explicitly labeled developer preview;
- the SDK contract and threat model name every new TypeScript and WASM surface
  not covered by the reviewed RC; and
- the release process can distinguish preview packages from stable-v1
  artifacts and claims.

Opening, merging, or testing an AP27 implementation PR is not evidence that
any external gate passed. This specification does not authorize engaging
reviewers, spending review funds, accepting security risk, publishing a
package, creating a tag, or promoting release artifacts.

Phase 10 MAY fix SDK usability and binding defects. A required change to frozen
Rust semantics or reviewed claims returns through AP-SPEC-032 and AP-SPEC-033
as required by their change classifications.

## 3. Existing baseline

The implementation begins from these maintained surfaces:

- `bindings/typescript` prepares `@auths-dev/sdk`;
- `auths-proof-wasm` exposes the supported portable verification boundary;
- `auths-sdk` owns the embedded Rust verifier and product-facing profile
  decoding;
- `auths-author` creates external signing requests without owning private keys;
- `auths-custody` defines transaction-bound external signing;
- `auths-profile-mcp` owns exact MCP call canonicalization and verified command
  decoding.

Existing independent TypeScript verification under
`bindings/independent/typescript` remains a differential implementation. It
MUST NOT become the product SDK's authoring or execution implementation.

## 4. Capability tier and goals

This specification promotes `@auths-dev/sdk` from **Verifier Binding** to
**Full Workflow SDK** under issue 72. The tiers mean:

```text
Verifier Binding
  proof bytes + action bytes + trusted context -> three verdicts
        |
        v
Authoring SDK
  principals + grants + delegation + exact actions + signing requests
        |
        v
Full Workflow SDK
  attach + delegate + authorize + explain + sealed profile command
```

The package MUST continue to expose the verifier binding as an explicitly
advanced API. It MUST NOT claim the Full Workflow tier until every stage above
uses supported Rust/WASM semantics and the clean external-consumer scenario
passes without hand-authored protocol CBOR.

The TypeScript Full Workflow SDK MUST provide:

- one idiomatic Node 20+ TypeScript package that runs natively on macOS,
  Linux, and Windows, plus its supported browser surface;
- a short `attachAgent` workflow;
- safe parent-agent creation or loading through a signer port;
- bounded grant planning and parent-to-child delegation;
- exact MCP action construction through profile-owned helpers;
- application-owned closed profile construction without a global action or
  executor union;
- optional self-contained raw-key root-authority preparation without
  hand-authored grant or trusted-context CBOR;
- local proof verification through the supported WASM boundary;
- an explicit discriminated union for authorized, denied, and indeterminate
  results;
- stable explanations that preserve the kernel stage and code;
- sealed verified commands that cannot be constructed by application code;
- lifecycle-safe cleanup for ephemeral child signers;
- advanced access to canonical bytes, commitments, metrics, and raw results;
- examples and API documentation reproducible from a clean checkout.

The normal workflow MUST expose no public API that accepts caller-constructed
canonical proof, grant, status, or trusted-context CBOR. Raw byte APIs remain
available only under the advanced verifier/inspection surface.

## 5. Non-goals

The Phase 10 developer preview MUST NOT:

- build a CLI;
- claim stable-v1 compatibility, production readiness, certification,
  compliance, or general availability;
- require an Auths account or hosted service;
- implement a general policy language;
- introduce framework-specific wrappers beyond the MCP adapter needed by the
  reference flow;
- implement macOS Secure Enclave or Touch ID support from AP-SPEC-029;
- require hardware-custody feature parity across operating systems;
- persist private keys in the SDK;
- make JavaScript the source of protocol truth;
- collapse MCP, HTTP, Stripe, database, or infrastructure actions into a
  generic operation payload;
- turn an authorized result into an automatic side effect;
- hide indeterminate outcomes behind retries or treat them as denials;
- accept arbitrary provider URLs, credentials, or commands.

## 6. Developer experience

### 6.1 Installation and first use

The happy path MUST fit this conceptual shape:

```ts
import { loadAuths } from "@auths-dev/sdk";
import { mcp } from "@auths-dev/sdk/mcp";

const profile = mcp.profile({ service: "records" });
const auths = await loadAuths({ signer, trustedAuthority });

const parent = await auths.attachAgent({
  name: "research-agent",
  profile,
  authority: parentGrant,
  approval: { mode: "grant-only", provider: approvalProvider },
});

const child = await parent.delegate({
  name: "records-child",
  authority: narrowerChildGrant,
  signer: ephemeralSigner(),
});

const result = await child.authorize(
  profile.call("update_demo_record", { value: "reviewed" }),
);

switch (result.kind) {
  case "authorized":
    await protectedTools.execute(result.command);
    break;
  case "denied":
  case "indeterminate":
    report(result.explanation);
    break;
}
```

Names are illustrative. Implementation review MAY improve them, but the final
API MUST preserve the same stages and security boundaries.

### 6.2 First-run terminal experience

The reference example SHOULD make the authority chain visible without
requiring a separate inspector:

```text
+--------------------------------------------------------------+
| Auths · attached research-agent                              |
| Root       local-development-root                            |
| Parent     research-agent · durable                          |
| Child      records-child · expires in 10 minutes             |
| Authority  records / update_demo_record                      |
+--------------------------------------------------------------+
| AUTHORIZED  complete / authorized                            |
| Action      update_demo_record(value digest 8f...)           |
| Proof       parent -> child -> exact action                   |
| Work        3 objects · 2 leaves · 41 work units             |
+--------------------------------------------------------------+
```

The SDK MUST expose structured data behind this display. The display MUST NOT
be the only way to recover exact codes or commitments.

### 6.3 Error behavior

Developer errors and authorization outcomes are different:

- invalid SDK construction, malformed configuration, unsupported profile, and
  signer protocol violations throw typed SDK errors;
- proof evaluation returns `authorized`, `denied`, or `indeterminate`;
- an authorization outcome MUST NOT throw merely because it is not
  authorized;
- error messages MUST NOT include proof bytes, credentials, signatures,
  passphrases, or private material;
- explanations MAY add guidance but MUST preserve stable kernel codes exactly.

## 7. Architecture

```text
+----------------------------- TypeScript application ----------------------+
|                                                                           |
|  attachAgent -> delegate -> profile action -> authorize -> closed gateway |
|       |            |             |             |                          |
+-------|------------|-------------|-------------|--------------------------+
        |            |             |             |
        v            v             v             v
+------------------------ @auths-dev/sdk -------------------------+
| workflow API | resource lifetimes | typed results | explanations |
| profile facade | signer port | approval port | advanced raw API  |
+-------------------------------|----------------------------------+
                                v
+------------------------- auths-proof-wasm -----------------------+
| supported three-input portable verification boundary             |
+-------------------------------|----------------------------------+
                                v
+---------------------------- Rust core ----------------------------+
| authoring | canonical model | attenuation | sealed verification   |
+-------------------------------------------------------------------+

External effects:

Signer/approval provider <--- exact requests ---> SDK
Closed profile gateway   <--- verified command -> provider/tool
```

### 7.1 Ownership

`bindings/typescript` owns:

- TypeScript workflow classes and interfaces;
- loading and lifetime management of WASM;
- copying at all mutable byte-array boundaries;
- discriminated result types;
- ergonomic explanation text;
- integration examples and generated API documentation.

Rust product and core packages own:

- canonical protocol and profile representations;
- grant attenuation and exact action meaning;
- signing preimages;
- trusted-context construction;
- verification and sealed command creation;
- stable result stages and codes.

Profile packages own:

- action builders;
- canonicalization;
- verified-command decoders;
- profile-specific denial meaning;
- gateway input types.

The TypeScript SDK MUST call these implementations through supported bindings.
It MUST NOT duplicate their decision rules.

### 7.2 Resource and secret boundary

The SDK MUST define a signer interface that receives only an exact,
domain-separated signing request and returns a signature plus any bound public
evidence. The interface MUST NOT require exporting a private key.

Development signers MAY exist in test and example code. Their names and
documentation MUST identify them as non-production. Secret bytes MUST be
scoped, cleared where the runtime permits, and excluded from serialization,
logging, fixtures, errors, and receipts.

An ephemeral child signer MUST expose deterministic disposal. Operations after
disposal MUST fail with a typed local error.

### 7.3 Sealed execution

An `authorized` result MUST contain a command whose constructor is unavailable
to application code. The command MUST be derived from the exact canonical
action bytes returned by successful verification.

A closed gateway accepts that command type. It MUST NOT accept the original
unverified JavaScript object as a substitute.

### 7.4 Platform portability

The base package MUST use platform-neutral APIs for paths, temporary storage,
process lifecycle, and WASM loading. It MUST NOT assume POSIX path separators,
Unix sockets, executable permission bits, `/tmp`, a particular shell, or Unix
signal behavior.

Native provider packages MUST be optional. Importing the base SDK MUST NOT
load, probe, or require a Swift helper or any other platform-specific binary.
Provider selection and capability detection MUST occur explicitly through the
provider interfaces reserved by this SDK and specified fully in AP-SPEC-029.

Windows support means a native Windows Node process. WSL MAY be supported as a
Linux environment, but it MUST NOT substitute for Windows release evidence.

## 8. APIs

The exact names may change during implementation review. The capability split
is normative.

```ts
export interface AuthsClient {
  attachAgent<P extends Profile>(
    options: AttachAgentOptions<P>,
  ): Promise<AttachedAgent<P>>;

  verifyRaw(input: RawVerificationInput): VerificationResult;
}

export interface AttachAgentOptions<P extends Profile> {
  readonly name: AgentName;
  readonly runtime: RuntimeAdapter<P>;
  readonly authority: SignedGrantSource;
  readonly signer: Signer;
  readonly approval: ApprovalConfiguration;
}

export interface AttachedAgent<P extends Profile> extends AsyncDisposable {
  readonly identity: AgentIdentity;
  readonly authority: EffectiveAuthoritySummary;

  delegate(
    request: DelegationRequest<P>,
  ): Promise<AttachedAgent<P>>;

  authorize(
    action: P["action"],
  ): Promise<AuthorizationResult<P["command"]>>;
}

export interface Signer {
  readonly kind: string;
  readonly lifecycle: "durable" | "ephemeral";
  publicIdentity(): Promise<PrincipalDescriptor>;
  sign(request: SigningRequest): Promise<SigningResponse>;
  dispose?(): Promise<void>;
}

export interface ApprovalProvider {
  approve(request: ApprovalRequest): Promise<ApprovalResponse>;
}
```

`SigningRequest` and `ApprovalRequest` MUST carry an object kind, semantic
display, exact transaction digest, and opaque signing bytes. A provider MUST
not be allowed to substitute a signature descriptor or mutate the request.

`ApprovalConfiguration` MUST reserve the four strategy modes. Application code
selects a committed policy reference; it MUST NOT supply an unversioned
decision callback at action time:

```ts
type ApprovalConfiguration =
  | { readonly mode: "grant-only";
      readonly policy: ApprovalPolicyReference;
      readonly provider: ApprovalProvider }
  | { readonly mode: "risk-based";
      readonly policy: ApprovalPolicyReference;
      readonly provider: ApprovalProvider }
  | { readonly mode: "every-action";
      readonly policy: ApprovalPolicyReference;
      readonly provider: ApprovalProvider }
  | { readonly mode: "custom";
      readonly policy: ApprovalPolicyReference;
      readonly provider: ApprovalProvider };

interface ApprovalPolicyReference {
  readonly policyId: string;
  readonly evaluatorVersion: string;
  readonly configurationDigest: Uint8Array;
}
```

The selected policy identity and configuration digest MUST be committed by the
signed grant or trusted context before action use. The SDK MUST verify the
required and executed approval-policy commitments before requesting approval,
signing an approved object, acquiring credentials, or permitting provider I/O.

The profile or trusted authority MAY impose a minimum supervision requirement.
Host configuration MAY choose an equal or stricter permitted policy before the
grant is committed; it MUST NOT weaken the committed requirement afterward.
A custom policy is a registered, versioned evaluator covered by the committed
reference. Missing, ambiguous, throwing, or mismatched evaluation returns a
typed fail-closed local outcome and produces no signature or effect.

The Phase 10 preview MAY ship only a deterministic development provider while
reserving these interfaces. Deployable platform providers are governed by
AP-SPEC-029 and Phase 11.

## 9. Validation and hard limits

All untrusted inputs MUST be bounded before allocation or WASM invocation.
At minimum:

- proof, action, and context bytes retain the kernel's configured limits;
- agent names and provider identifiers use a documented ASCII subset;
- delegation depth cannot exceed the trusted-context limit;
- approval display text has a hard byte limit;
- signer evidence count and bytes use the core evidence limits;
- decoded results reject non-canonical, trailing, unknown-version, and
  over-depth CBOR;
- mutable `Uint8Array` inputs and outputs are defensively copied.

The SDK MUST not invent larger limits than the underlying Rust surface.

## 10. Required evidence

Implementation MUST add:

- unit tests for every public discriminated union and typed error;
- canonical positive and negative attach/delegate/authorize fixtures;
- TypeScript-to-Rust agreement for authorized, denied, and indeterminate
  outcomes;
- mutation tests proving one changed action byte invalidates authorization;
- tests that application code cannot construct a verified command;
- tests that signer transaction substitution is rejected;
- tests that required and executed approval-policy commitments cannot be
  substituted, weakened, omitted, or evaluated ambiguously;
- tests that a failing custom approval evaluator causes no approval prompt,
  signature, credential acquisition, or provider I/O;
- tests that disposed ephemeral signers cannot sign;
- browser and Node package smoke tests using the precompiled WASM artifact;
- native Node CI on current supported macOS, Ubuntu Linux, and Windows runners;
- cross-platform tests for paths, temporary resources, child-process cleanup,
  optional-provider loading, and unsupported-capability errors;
- package-content tests proving no private fixture or development key ships;
- documentation examples compiled in CI;
- `architecture.toml` and `compliance.toml` updates for every changed consumer.

## 11. Bounded PR units

1. **`AP27-PR1` — capability contract and threat model.** Freeze the public
   Full Workflow API, advanced/raw boundary, ownership map, hard limits,
   non-forgeability model, browser/Node lifecycle, and exact claim exclusions.
   No production behavior changes.
2. **`AP27-PR2` — Rust/WASM authoring ABI.** Expose only the missing
   principal, grant-planning, delegation, action, status, trusted-context, and
   exact-signing operations from their canonical Rust owners. Add ABI versions,
   bounded decoders, canonical fixtures, and Rust/WASM differential tests.
3. **`AP27-PR3` — principals, signers, and trusted authority.** Implement
   `loadAuths`, principal creation/loading, provider-neutral signer and approval
   ports, transaction binding, explicit configuration commitments, cleanup,
   and hostile provider tests. Ship no production custody provider.
4. **`AP27-PR4` — attach and root authority.** Implement `attachAgent`, exact
   root/signed-grant sources, effective-authority summaries, typed construction
   errors, and stable explanation projection without accepting raw protocol
   bytes on the normal path.
5. **`AP27-PR5` — delegation and attenuation.** Implement child grant planning,
   semantic authority diffs, over-granting warnings, approval binding, signing,
   and negative widening tests for every authority dimension.
6. **`AP27-PR6` — profile authorization.** Add the first built-in profile-owned
   action facade, a bounded application-profile kit, optional local raw-key
   authority preparation, proof/context assembly, three-valued local
   verification, and exact cross-language fixtures. Do not add a generic
   operation-tag action, executor, credential provider, or global action
   union.
7. **`AP27-PR7` — sealed command and gateway handoff.** Decode only the
   verifier-sealed action into an MCP command whose constructor is unavailable
   to application code. Add compile-time and runtime construction, mutation,
   copying, serialization, hostile-engine, dynamic-module, and
   denied/indeterminate tests. Issue 76 MUST be resolved by this unit; a
   caller-controlled engine may not select the capability-minting branch.
8. **`AP27-PR8` — advanced inspection and explanation.** Preserve raw
   verification, canonical bytes, commitments, metrics, stable stages/codes,
   and bounded export behind visibly advanced APIs. Prove that inspection data
   cannot be promoted into a command.
9. **`AP27-PR9` — external-consumer and package closure.** Exercise the packed
   npm artifact from a repository with no Auths source checkout; compile every
   example; run Node and browser smoke tests; verify package contents,
   architecture, compliance, provenance subjects, and native macOS/Linux/
   Windows behavior.

Every implementation PR MUST state the exact RC/baseline digest, tests and
fixtures added, capability tier affected, security invariants, supported and
excluded claims, and remaining entry/exit gates. A later PR MUST NOT merge
around a failed earlier semantic or non-forgeability gate.

## 12. Exit gate

The TypeScript Full Workflow SDK gate is complete only when:

- a new developer can run the reference attach/delegate/authorize flow without
  hand-authoring CBOR;
- the normal path requires no hosted service;
- no private key crosses the verifier boundary;
- authorized, denied, and indeterminate remain distinct public outcomes;
- exact Rust stages and stable codes survive through TypeScript;
- required and executed approval-policy identities and configuration digests
  are equal before signing or effectful work;
- TypeScript and Rust agree on all fixtures used by the flow;
- the final package installs and runs from a clean checkout in native Node on
  macOS, Ubuntu Linux, and Windows, and in a supported browser;
- the authoritative repository checks pass on the exact revision.

The release manifest, npm README, generated API documentation, package
metadata, and issue-72 capability matrix MUST all label the package Full
Workflow only after this gate passes. Before that point they MUST say
Verifier Binding or implementation preview, matching the evidence actually
available.

Passing this gate does not claim stable-v1 compatibility, production custody,
complete MCP execution, production readiness, or commercial readiness. Those
belong to later phases.
