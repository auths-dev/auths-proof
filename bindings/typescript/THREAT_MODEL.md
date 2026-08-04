# TypeScript Full Workflow SDK threat model

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

The current verifier binding accepts a public `PortableWasmEngine` constructor
argument and arbitrary `moduleUrl`. A hostile implementation can return forged
authorized-result CBOR and cause the wrapper to mint `VerifiedAction`. Issue 76
tracks this defect.

The Full Workflow loader MUST use only package-owned WASM. Arbitrary engines
belong to an advanced diagnostic/test API whose result cannot become a
command. The JavaScript wrapper and WASM are one integrity-bound release
subject set.

### Action substitution

An agent or application may mutate the proposed action after approval or
signing, exchange two actions, or reuse a proof with a different call. Rust
canonicalization and signing/verification bind the complete action. Public
mutable byte arrays are copied. Mutation tests change every relevant field and
one canonical byte at a time.

### Delegation widening

A child request may widen permissions, resources, audiences, validity, budget,
depth, status policy, assurance, profile, or extensions. Rust grant planning
derives issuer/parent linkage and rejects the first widened dimension before
approval or signer invocation. TypeScript does not implement a second
attenuation test.

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
