# TypeScript Full Workflow SDK threat model

This contributor document is maintained under `bindings/typescript/docs`.

## Scope

This threat model covers the JavaScript/TypeScript wrapper, packaged WASM
loader, public workflow objects, application provider callbacks, profile
facades, and the handoff of a verified profile command. It does not claim that
the host process, browser, operating system, package registry, signer provider,
or external effect provider is honest or uncompromised.

The security objective is narrower:

> Untrusted application proposals and provider outputs cannot cause the SDK to
> release an effect-capable profile command unless the package-owned native
> verifier authorizes the exact canonical action under the exact trusted
> context.

## Trust boundaries

```text
Untrusted / adversarial
  application action objects
  agent names and proposals
  network/evidence/provider responses
  signer and approval callback behavior
  mutable Uint8Array aliases
  serialized/copy/reflection input
             |
             v
TypeScript validation and lifecycle boundary
             |
             v
Packaged integrity-bound WASM authoring/verifier
             |
             v
Native-sealed profile command
             |
             v
Closed application gateway (outside SDK verification claim)
```

Trusted for the bounded claim:

- the exact npm package and JavaScript wrapper digest;
- the exact packaged WASM subject and loader path;
- the Rust compiler/toolchain and dependencies named by release evidence;
- the host's configured trust roots, time, status/evidence snapshots, and
  required/executed configuration inputs; and
- a closed gateway that accepts only the matching profile command type.

Provider callbacks are not trusted to assert authorization. A signer is
trusted only to protect its key and correctly perform the selected exact
signature; its response is still transaction-bound and verified.

## Protected assets and properties

- private keys never enter the SDK workflow object graph;
- signing requests cannot be substituted or reused;
- child authority cannot widen its parent;
- trusted context and approval configuration cannot be weakened;
- only the exact authorized action becomes a command;
- denied and indeterminate results contain no command;
- raw inspection data cannot be promoted into an effect capability;
- disposal prevents reuse of ephemeral signer/agent state; and
- errors, logs, examples, fixtures, and package contents contain no secrets.

## Threats and required controls

### Hostile engine or module injection

The advanced verifier accepts a public `PortableWasmEngine` constructor and an
explicit module URL for diagnostic and differential use. A hostile engine can
produce an advanced `VerifiedAction`, but no advanced result or action is
accepted by a profile gateway or convertible into a command.

The Full Workflow loader uses only package-owned WASM. Effect-capable
`McpCommand`, `ApplicationCommand`, and `VerifiedPlanCommand` values require
the package-owned workflow path, private module tokens, matching profile
state, and successful verification. The wrapper and WASM remain one
integrity-bound release subject set.

### Action substitution

An agent or application may mutate the proposed action after approval or
signing, exchange two actions, or reuse a proof with a different call. Rust
canonicalization and signing/verification bind the complete action. Public
mutable byte arrays are copied. Mutation tests change every relevant field and
one canonical byte at a time.

### Application-owned profile substitution

The profile kit treats the application profile implementation as trusted code
at the same boundary as its closed gateway. An untrusted agent may propose
input, but it must not select or replace the canonicalizer. Actions are sealed
to the exact profile instance that created them; Rust reconstructs the
canonical protocol action and the verifier still requires exact profile,
permission, resource, audience, body, and budget coverage. Defining another
profile does not grant authority and creates no generic executor capability.

The SDK cannot prove that an application canonicalizer gives sensible meaning
to its own bytes or that its gateway decodes them safely. Profiles must test
canonical uniqueness, hostile inputs, approval-display binding, and the sealed
verified-command boundary as one vertical.

### Root-authority substitution

An authority source may return malformed bytes, a non-root grant, or a grant
for another issuer, subject, or profile. The normal API accepts only a sealed
provider-backed `SignedGrantSource`, copies its one response, and passes the
exact bytes to packaged Rust/WASM. Native validation binds parentlessness,
trusted root, attached principal, and exact profile before TypeScript creates
an attached agent. The resulting summary is structural and explicitly says
`pending-authorization`; it is not evidence that cryptographic, status,
assurance, or live verification passed.

The optional raw-key bootstrap prepares the root statement and trust context
in native code and submits the exact grant transaction to an external signer.
It is intentionally restricted to the compiled Ed25519 raw-key method. It does
not silently manufacture trust for DID, hardware, enterprise, or networked
identity methods, and missing public raw-key evidence fails before the
prepared authority can authorize an action.

### Trusted-context or evidence substitution

A configuration digest alone cannot reconstruct trust anchors, accepted
registries, status snapshots, assurance policy, or limits. The normal workflow
therefore loads a canonical context through a sealed `TrustedContextSource`.
Packaged Rust rejects a context whose executable configuration or root anchor
does not match `TrustedAuthority` before signer use.

Every signed grant retains typed public control evidence beside its copied
canonical bytes. Action evidence comes only from the transaction-bound signer
response. Rust derives evidence identifiers, statement bindings, the exact
authorization plan, proof bundle, and per-request context; JavaScript cannot
assert those relationships with a digest, Boolean, or hand-authored CBOR.

The typed trust compiler copies every collection before loading WASM and gives
Rust the complete configuration as structured values. Status snapshots are
accepted only through package-owned objects created by Rust parsing. Raw context
bytes, forged snapshots, unsupported adapters, duplicate registry entries, and
invalid limits cannot enter the normal trust builder.

### Identity-adapter substitution

Identity exchange does not initialize authority. A decoded packet becomes a
validated identity only through an adapter whose method identifier matches the
packet, and an authenticated message only through a suite adapter whose suite
and exact returned fields match the validated identity and message. Caller-owned
adapters are trusted to implement their registered cryptography correctly;
their outputs still cannot create a grant, authorization verdict, or command.

### Delegation widening

A child request may widen permissions, resources, audiences, validity, budget,
depth, status policy, assurance, profile, or extensions. For every
caller-selectable workflow field, Rust grant planning derives issuer/parent
linkage and rejects the first widened dimension before approval or signer
invocation. TypeScript does not implement a second attenuation test.

The normal TypeScript request cannot select a different profile or critical
extension payload: native structured planning inherits both exactly from the
parent. Issue 81 tracks the broader core-protocol requirement to define and
enforce extension attenuation for advanced/native callers that author complete
grant statements.

### Signer substitution and confused deputy

A callback may return a signature for another request, principal, descriptor,
transaction, provider instance, or expired request. The SDK validates every
binding and accepts one response. The callback receives no general signing
method from an agent-controlled object.

### Approval substitution

A callback may approve a different digest, reply twice, throw, hang, or claim a
weaker policy. Required and executed policy identities/configuration digests
must match before callback invocation and again before signing. Timeout,
cancellation, mismatch, and ambiguity release no command.

A plan approval session is private to one `authorizePlan` invocation, binds
the displayed plan commitment and exact member count, accepts one exact
provider response, and is disposed at terminal completion. It cannot approve
an action appended after plan construction or be reused by application code.

### Capability forgery in JavaScript

TypeScript visibility is not a security boundary. Constructors, static
factories, symbols, prototypes, subclassing, reflection, object spread,
structured clone, serialization, monkey-patching, and dynamic imports are
adversarial surfaces.

An effect-capable command must remain closure/native owned, non-serializable,
profile branded, and tied to the trusted production verifier instance. Tests
must attempt each construction path. A forged object with the same fields or
prototype must fail gateway acceptance.

### Raw API promotion

Advanced verification intentionally exposes canonical bytes and diagnostic
results. No advanced type or function can construct, deserialize, or convert
to a profile command. The gateway cannot accept `VerifiedAction` from an
arbitrary engine, raw bytes, or a verdict Boolean.

### Runtime claim or effect substitution

The optional runtime parses a sealed authorized command through its matching
closed executor before issuing a challenge or claiming replay/budget state.
Denied, indeterminate, forged, copied, or cross-profile commands cause no state
claim and no gateway call. Replay and budget results are closed unions, and an
executor error must distinguish known non-execution from an unknown outcome.
An unavailable success receipt is outcome-unknown rather than successful.

### Resource exhaustion

All public strings, bytes, collections, recursion, provider outputs, callback
counts, and WASM results are checked against the contract limits before
unbounded allocation or repeated work. The binding uses the smaller native
limit and reports deterministic metrics.

### Cancellation and disposal races

Cancellation may occur before or after principal lookup, approval, signing, or
native completion. Each workflow stage has one owner and terminal outcome.
Cleanup is idempotent. Cancellation never turns an incomplete operation into a
signed object or command, and disposed child state cannot restart with the
same request.

### Secret and sensitive-data exposure

The SDK uses allowlisted error/explanation fields and never serializes provider
objects generically. Signing preimages and signatures are excluded from logs,
receipts, display summaries, thrown causes, snapshots, and package fixtures.
Development signers are test/example-only and unmistakably labeled.

### Supply-chain substitution

Package contents, wrapper, WASM, types, manifest, SBOM, and provenance subjects
must agree. External-consumer tests install the packed artifact in a clean
repository with no Rust checkout. Redirectable runtime module loading is not a
production feature.

## Security states

```text
local-error
  construction, provider, lifecycle, ABI, or capability failure

denied
  trustworthy available facts establish rejection

indeterminate
  required trustworthy fact or implementation unavailable

authorized(command)
  exact native verification succeeded and matching profile decoded command
```

These states are disjoint. Only the final state carries a command. Execution,
provider acceptance, and observed effect remain later gateway/runtime facts.

## Residual assumptions and exclusions

- A compromised host process can steal or alter values visible to that process.
- A malicious signer can misuse a key it controls outside this API.
- Correct authorization does not prove an external provider executes or
  observes the command correctly.
- JavaScript garbage collection does not prove immediate zeroization.
- Browser origin security, Node module resolution, npm registry operation, and
  operating-system integrity remain trusted environmental assumptions.
- Pre-review implementation is not an independent audit or production claim.

Phase 9 follow-up and promotion remain governed by issue 74.
