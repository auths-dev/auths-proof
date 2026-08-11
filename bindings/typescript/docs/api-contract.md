# TypeScript Full Workflow API contract

This contributor document is maintained under `bindings/typescript/docs`.

## Status and claim boundary

This document defines the repository-local Full Workflow implementation
contract. Publication, capability-tier promotion, stable-v1, production, and
reviewed-security claims remain controlled by release evidence and issue 74.

The target workflow is:

```text
load trusted SDK
  -> create/load principal through signer
  -> attach agent to exact authority
  -> plan strictly non-widening child grant
  -> approve and sign exact transaction
  -> construct one profile-owned action
  -> assemble proof and trusted context in Rust
  -> verify locally through packaged WASM
  -> authorized | denied | indeterminate
  -> decode authorized bytes into one sealed profile command
```

No normal-path operation accepts caller-constructed protocol CBOR.

## Module surface

The package separates semantic roles into explicit entry points:

```text
@auths-dev/sdk                 integrated attach/delegate/authorize workflow
@auths-dev/sdk/identity        decoded, validated, and authenticated identity states
@auths-dev/sdk/trust           typed trusted-context composition
@auths-dev/sdk/authority       authority projection and proof-plan authoring
@auths-dev/sdk/lifecycle       principal/grant status authoring and snapshots
@auths-dev/sdk/profiles        maintained and application profile facades
@auths-dev/sdk/runtime         optional effect-lifecycle ports
@auths-dev/sdk/custody         signer and custody provider contracts
@auths-dev/sdk/testkit         non-production adapters and conformance harnesses
@auths-dev/sdk/verify          packaged deterministic verification
@auths-dev/sdk/inspection      safe commitments and decision projection
@auths-dev/sdk/diagnostics     inert caller-supplied engines and SDK reports
@auths-dev/sdk/observability   redacted event and support-bundle contracts
```

The root does not export protocol constructors, raw registry mutation,
arbitrary engines, generic operations, or provider executors. Profile facades
remain separate exports so adding a profile does not expand a global action,
command, or receipt union.

## Type-driven boundaries

Fallible boundaries parse into narrower types. Decoded identities, validated
identities, authenticated messages, signed status statements, status
snapshots, proof references, authorization plans, and profile commands are
distinct states. Public APIs do not return a Boolean that callers can attach
to their original input, and application code cannot construct a later state
from the fields of an earlier one.

Opaque objects carry package-owned state outside their visible properties.
Discriminated unions make authorization and runtime terminal states exhaustive.
Mutable byte and collection inputs are copied before an asynchronous provider
or loader boundary.

## Independent identity API

`@auths-dev/sdk/identity` loads without authority, grants, approvals, profiles,
or lifecycle configuration. Rust/WASM decodes compact identities and general
credential-shape-neutral descriptors. General identities move through
decoded, resolved, validated, and authenticated states. Exact-version method
and suite registries reject unknown, mismatched, purpose-incompatible, and
deprecated adapters without fallback. The package proves both embedded
raw-key/Ed25519 and resolver-backed compositions without taking ownership of a
vendor adapter catalog.

## Typed trust and lifecycle API

`compileTrustedContext` accepts typed roots, profiles, permissions, registries,
status snapshots, assurance policy, and limits. Rust parses and compiles these
values into a sealed `TrustedContextSource`; the normal builder accepts no
protocol bytes. Principal and grant status requests become signed status types
only after the exact native signing transaction completes. Rust then parses
those types into immutable status snapshots accepted by trust composition.

## General proof plans

`AuthorizationPlanBuilder` owns every plan node. It accepts opaque proof
references and composes native `proof`, `all-of`, `any-of`, and `threshold`
nodes. Rust rejects empty, duplicate, impossible, excessive-depth, and
excessive-work plans during construction. A plan cannot cross builders or
survive builder disposal.

## Optional runtime and custody ports

`@auths-dev/sdk/runtime` coordinates challenge, replay, budget, receipt, and
closed-executor ports only after a matching gateway parses an authorized
profile command. Denied, indeterminate, forged, or mismatched commands claim no
state and invoke no executor. Execution failure distinguishes a known
non-effect from an unknown outcome.

`@auths-dev/sdk/custody` publishes provider-neutral signing contracts. Provider
conformance and in-memory runtime implementations live under `testkit`; no
production custody, replay, budget, receipt, or effect provider is bundled.

## Normal workflow API

Names below are frozen for implementation unless a bounded PR records a
specific usability defect and updates this contract before exporting code.

```ts
export interface LoadAuthsOptions {
  readonly signer: Signer;
  readonly trustedAuthority: TrustedAuthority;
}

export interface TrustedAuthority {
  readonly authorityId: string;
  readonly rootPrincipal: string;
  readonly verifierConfiguration: Uint8Array;
  readonly context: TrustedContextSource;
  readonly requiredApproval: ApprovalPolicyReference;
}

export function loadAuths(options: LoadAuthsOptions): Promise<AuthsClient>;

export interface AuthsClient extends AsyncDisposable {
  attachAgent<P extends Profile>(
    options: AttachAgentOptions<P>,
  ): Promise<AttachedAgent<P>>;
}

export interface AttachAgentOptions<P extends Profile> {
  readonly name: AgentName;
  readonly profile: P;
  readonly authority: SignedGrantSource;
  readonly approval: ApprovalConfiguration;
}

export interface AttachedAgent<P extends Profile> extends AsyncDisposable {
  readonly identity: AgentIdentity;
  readonly authority: EffectiveAuthoritySummary;

  delegate(options: DelegationOptions<P>): Promise<AttachedAgent<P>>;
  authorize(action: P["action"]): Promise<AuthorizationResult<P["command"]>>;
}
```

`attachAgent` does not infer authority from `name`, runtime identity, signer
availability, or a valid signature. It consumes an exact signed authority
source whose profile, principal, audience, validity, status, assurance,
budget, and depth are checked by Rust.

The normal source is created with `signedGrantSource({ sourceId, provider })`.
It is a sealed provider reference, not a byte wrapper: `AttachAgentOptions`
has no raw-CBOR field. The provider response is copied and canonically decoded
by packaged Rust/WASM. Root attachment requires no parent and exact equality
with `TrustedAuthority.rootPrincipal`, the loaded signer principal, and the
selected profile. Its effective-authority explanation remains
`pending-authorization` until the later verification workflow checks the
signature, status, assurance, chain, and request context.

`delegate` first produces a native-planned authority diff and warnings for
approval review, and the attached child exposes the same structured review.
Approval and signing receive that exact plan. Parent linkage and
issuer identity are derived, not supplied independently by TypeScript. A
widened permission, resource, audience, validity window, budget, delegation
depth, status policy, assurance floor, profile, or critical extension fails
before approval or signing.

The implemented delegation request is structured rather than protocol-shaped:
permissions, validity, audiences, action-constraint mode, budget mode, depth,
status mode, and an optional assurance floor are bounded TypeScript values.
The selected profile and critical-extension set are inherited exactly from the
parent by Rust and cannot be supplied in the normal request. Unknown request
fields fail closed. The parent signer signs the native plan; the child signer
only establishes the child principal and is retained for later child actions.

`TrustedContextSource` is a sealed provider reference. It supplies one
canonical immutable template containing trust anchors, registry acceptance,
status snapshots, assurance policy, and limits. Packaged Rust validates the
configured root and executable-verifier commitment at load; authorization
rebinds only the exact plan, audience, challenge, and evaluation time.

For self-contained local and headless deployments, `prepareRawKeyAuthority`
constructs a matching root grant and trusted-context template through Rust,
then submits the unsigned grant to an external raw-key signer and approval
provider. It neither receives nor persists a private key. This is an explicit
raw-key bootstrap, not a universal identity or trust-context builder; other
principal methods retain their deployment-specific context providers.

`SignedGrantProvider` returns a structured signed-grant material containing the
canonical signed grant and typed public control evidence. Delegation retains
the same material from the exact signing response. Evidence carries its
registered evidence type, media type, and copied bytes; JavaScript never
constructs evidence identifiers or control bindings.

`authorize` constructs the selected profile action exactly once, obtains any
required evidence outside verification, assembles the canonical proof/context
through native authoring operations, and returns one of three results. It does
not execute an effect. Only an authorized result includes the matching sealed
profile command. Denied and indeterminate results never contain one.

`profile.plan(actions)` creates an immutable ordered plan, checks compatible
profile authority, aggregates permissions and compatible budgets, and commits
the exact ordered canonical actions. `authorizePlan` stops at the first denied
or indeterminate action and releases a sealed `VerifiedPlanCommand` only after
every member authorizes. Provider sequencing and partial external effects
remain profile-gateway responsibilities; SDK plan authorization does not claim
remote transaction atomicity.

## Identity and custody ports

```ts
export interface Signer extends AsyncDisposable {
  readonly kind: string;
  readonly lifecycle: "durable" | "ephemeral";
  publicIdentity(): Promise<PrincipalDescriptor>;
  sign(request: SigningRequest): Promise<SigningResponse>;
}

export interface SigningRequest {
  readonly requestId: string;
  readonly objectKind: "grant" | "action" | "principal-status" | "grant-status";
  readonly principal: PrincipalDescriptor;
  readonly transactionDigest: Uint8Array;
  readonly signingPreimage: Uint8Array;
  readonly expiresAt: bigint;
  readonly display: readonly ReviewField[];
  readonly signal?: AbortSignal;
}

export interface SigningResponse {
  readonly requestId: string;
  readonly principal: PrincipalDescriptor;
  readonly transactionDigest: Uint8Array;
  readonly signature: Uint8Array;
  readonly evidence?: readonly ControlEvidence[];
}

export interface ControlEvidence {
  readonly evidenceType: string;
  readonly mediaType: string;
  readonly bytes: Uint8Array;
}
```

The SDK supplies copied, read-only-by-contract byte arrays and validates the
response against the exact request, principal, descriptor, transaction,
provider instance, and lifetime. The port is not `sign(bytes)`. Agents and
profiles never receive it directly.

Provider failure, rejection, cancellation, timeout, unsupported capability,
transaction mismatch, duplicate response, and use after disposal are distinct
typed workflow errors. They are not authorization verdicts.

## Approval contract

Approval modes are `grant-only`, `risk-based`, `every-action`, `plan-once`,
`headless`, and registered `custom`. Every mode names a versioned policy and configuration digest already
committed by the grant or trusted context. Local configuration may be equal or
stricter before commitment; it cannot weaken the committed requirement later.

A missing, mismatched, throwing, ambiguous, cancelled, or expired approval
produces no signature, credential request, or command. Approval never expands
underlying authority.

Typed `approvalPolicy` builders derive configuration commitments from bounded
canonical configuration. A plan session is owned by `authorizePlan`, bound to
the immutable plan commitment and exact action count, and disposed immediately
after its terminal result. A substituted provider response cannot activate the
session.

## Profile contract

The first built-in workflow profile is MCP. Its public facade owns closed action
constructors such as:

```ts
const profile = mcp.profile({ service: "records" });
const action = profile.call("update_demo_record", { value: "reviewed" });
```

The profile validates and canonicalizes the complete tool call in its Rust
owner. It does not accept an arbitrary endpoint, transport, callback, raw
canonical bytes, or generic provider operation.

`@auths-dev/sdk/profile-kit` lets an application provide a closed profile
canonicalizer without teaching the SDK kernel the application's operation
vocabulary. The profile returns exact body, media type, permission, optional
budget, resource namespace, audience, and approval display. A sealed action's
read-only `authorityFor` projection lets authority setup reuse those exact
profile-derived fields instead of duplicating strings. Rust/WASM validates and constructs the
protocol objects; the signed grant must still authorize the exact profile and
derived authority. The profile kit registers no global action union, executor,
credential provider, or generic operation-tag dispatcher.

An authorized result contains an `McpCommand` or `ApplicationCommand` created
only after packaged verification and matching profile decoding. A closed
gateway accepts only that profile instance's command. It does not accept the
original JavaScript object, a Boolean, a digest, raw bytes, inspection data, or
a command from another profile. Constructors, factories, serialization,
prototype forgery, and plan-command promotion are tested as hostile paths.

The separate `@auths-dev/sdk/testkit` export supplies an ephemeral Ed25519
raw-key signer, explicit approve/reject fixtures, and profile mutation tooling.
It is non-production, does not persist keys, and is not a custody fallback.

## Results and explanations

```ts
export type AuthorizationResult<C> =
  | Authorized<C>
  | Denied
  | Indeterminate;

export interface Authorized<C> extends ResultCommon {
  readonly kind: "authorized";
  readonly command: C;
}

export interface Denied extends ResultCommon {
  readonly kind: "denied";
}

export interface Indeterminate extends ResultCommon {
  readonly kind: "indeterminate";
}
```

Only `authorized` contains a command. Every result preserves the native stage,
stable code, required and executed configuration commitments, deterministic
metrics, and bounded safe explanation. Denied and indeterminate are values,
not thrown exceptions or implicit retries.

## Verification, inspection, and diagnostics

`@auths-dev/sdk/verify` owns bounded single and batch verification through the
package-owned WASM subject. `@auths-dev/sdk/inspection` owns inert decision and
commitment projection. `@auths-dev/sdk/diagnostics` accepts explicitly
supplied engines only through a result type that is statically and dynamically
incapable of becoming a profile command.

The production workflow loader does not accept `moduleUrl`, a
`PortableWasmEngine`, a verifier callback, or caller-selected result bytes. It
loads the package-owned WASM subject. Test injection uses a separately named
harness that never mints effect-capable objects.

## Lifetime and portability

- `AuthsClient` and attached agents are explicitly disposable.
- Ephemeral child signers are disposed on success, error, cancellation, and
  partial construction.
- Operations after disposal fail locally.
- Mutable input/output bytes are copied at public boundaries.
- The base package uses no POSIX-only path, shell, signal, socket, or temporary
  directory assumption.
- Native custody providers are optional and not loaded by importing the base
  package.
- Supported execution is Node 20+ on native macOS, Linux, and Windows plus the
  documented browser matrix.

## Hard limits

The binding uses the smaller of its declared limit and the deployed native
limit. It never enlarges a Rust limit.

| Input | Binding maximum |
| --- | ---: |
| Result CBOR | 16 MiB |
| Decoder nesting | 64 |
| Agent/provider identifier | 128 UTF-8 bytes |
| Approval display fields | 32 |
| One approval field | 4 KiB |
| Aggregate approval display | 64 KiB |
| Provider callbacks per workflow stage | 1 |

Proof, action, trusted-context, evidence, plan, chain, collection, and work
limits come directly from the exact deployed native configuration and are
reported through inspection.

## Compatibility and evolution

Auths is prelaunch. AP-SPEC-027 makes one clean source cutover; it adds no
legacy workflow reader, compatibility alias, dual loader, or old command
constructor. Raw verifier compatibility is governed independently by its
portable ABI and fixtures.

Profile actions, stable codes, ABI versions, and configuration commitments are
versioned semantic identities. Incompatible meaning receives a new identity;
it is not hidden behind an ergonomic refactor.
