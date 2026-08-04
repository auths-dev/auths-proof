# TypeScript Full Workflow API contract

## Status and claim boundary

This document freezes the AP27-PR1 product contract. It does not describe a
currently shipped Full Workflow SDK. The current package is a **Verifier
Binding**. Repository-local implementation may proceed before Phase 9, while
publication, capability-tier promotion, and reviewed-security claims remain
blocked by issue 74.

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

The package has three explicit surfaces:

```text
@auths-dev/sdk             workflow, results, identity, provider ports
@auths-dev/sdk/mcp         closed MCP profile actions and commands
@auths-dev/sdk/advanced    raw verifier and bounded inspection
```

The root does not export protocol constructors, raw registry mutation,
arbitrary engines, generic operations, or provider executors. Profile facades
remain separate exports so adding a profile does not expand a global action,
command, or receipt union.

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

`authorize` constructs the selected profile action exactly once, obtains any
required evidence outside verification, assembles the canonical proof/context
through native authoring operations, and returns one of three results. It does
not execute an effect.

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

Approval modes are `grant-only`, `risk-based`, `every-action`, and registered
`custom`. Every mode names a versioned policy and configuration digest already
committed by the grant or trusted context. Local configuration may be equal or
stricter before commitment; it cannot weaken the committed requirement later.

A missing, mismatched, throwing, ambiguous, cancelled, or expired approval
produces no signature, credential request, or command. Approval never expands
underlying authority.

## Profile contract

The first workflow profile is MCP. Its public facade owns closed action
constructors such as:

```ts
const profile = mcp.profile({ service: "records" });
const action = mcp.call("update_demo_record", { value: "reviewed" });
```

The profile validates and canonicalizes the complete tool call in its Rust
owner. It does not accept an arbitrary endpoint, transport, callback, raw
canonical bytes, or generic provider operation.

An authorized result contains an `McpCommand` created only by the packaged
trusted verifier and MCP verified decoder. The closed gateway accepts that
command. It does not accept the original JavaScript object, a Boolean, a
digest, raw bytes, or a command from another profile.

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

## Advanced surface

`@auths-dev/sdk/advanced` retains bounded three-input verification and exact
inspection. It may accept explicitly supplied engines for diagnostics and
tests only when the resulting type is statically and dynamically incapable of
becoming a profile command.

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
