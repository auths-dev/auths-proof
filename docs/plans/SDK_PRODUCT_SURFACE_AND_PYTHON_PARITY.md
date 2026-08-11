# Auths SDK product surface and Python parity

**Status:** Rust, TypeScript, and Python repository surfaces mapped after the
Python elite implementation
**Snapshot:** `main` at `61bedef` plus `codex/python-elite-sdk` on 2026-08-11
**Release posture:** Prelaunch; implementation completion does not authorize
publication, stable-V1, production, certification, or independent-review claims
**Semantic owner:** Rust
**Language-product owners:** TypeScript and Python

## 1. Executive assessment

Auths now has three coherent but deliberately different products:

| Surface | Product role | Repository capability | Remaining gate |
| --- | --- | --- | --- |
| Rust | Semantic reference and capability ceiling | Complete protocol, identity, authority, profile, lifecycle, runtime, receipt, and release building blocks | Exact release-candidate review and publication authorization |
| TypeScript | Browser, Node.js, and edge product | Elite Full Workflow implementation with layered identity, verification, workflow, profiles, runtime, adapters, and packed consumers | Exact release CI, independent review, and promotion |
| Python | Service, automation, data, and agent product | Elite Full Workflow implementation with a safe native waist, layered identity, verification, workflow, profiles, runtime, adapters, and abi3 wheels | Exact release CI, independent review, and promotion |

The SDKs target customer-journey parity, not symbol-for-symbol sameness:

> Rust owns shared meaning. TypeScript and Python expose that meaning in the
> idioms of their ecosystems, without reimplementing canonicalization,
> attenuation, verification, lifecycle, profile commands, or runtime state.

## 2. Product tiers

| Tier | Customer can do | Customer never has to do |
| --- | --- | --- |
| Verifier Binding | Submit proof, canonical action, and trusted-context bytes and receive a three-valued decision | Reimplement verification |
| Authoring SDK | Create identity, grants, delegation, status, trust, profiles, plans, and exact signing requests | Hand-author protocol CBOR, commitments, or signing preimages |
| Full Workflow SDK | Attach, delegate, review, approve, authorize, execute a native-sealed command, reconcile, and inspect receipts | Assemble proof objects or mint effect-capable commands |

Rust, TypeScript, and Python all reach the Full Workflow capability ceiling in
the repository. Capability promotion remains blocked until exact artifact and
external-review gates pass.

## 3. Cross-language customer surface

| Product capability | Rust | TypeScript | Python |
| --- | --- | --- | --- |
| Deterministic local verification | Complete | Complete | Complete |
| Authorized, denied, indeterminate | Complete | Complete | Complete |
| Standalone identity and exact-message authentication | Complete | Complete | Complete |
| Credential-shape-agnostic methods and suites | Complete ports and reference adapters | Versioned ports and reference adapters | Versioned async ports, raw-key/Ed25519 and resolver-backed reference paths |
| Explicit identity-to-authority bridge | Complete | Complete | Complete; preserves method, relationship, suite, purpose, provenance, and assurance |
| Typed trust, assurance, evidence, and status | Complete | Complete | Complete |
| Root authority and agent attachment | Complete building blocks | Complete integrated workflow | Complete integrated workflow |
| Strictly narrower delegation and semantic diff | Complete | Complete | Complete |
| Approval policies and provider orchestration | Complete primitives | Complete | Complete; none, grant-only, every-action, risk, threshold, custom, and plan-once |
| Exact signing and custody ports | Complete | Complete | Complete async ports and transaction binding |
| Maintained MCP profile | Complete | Complete | Complete |
| Maintained HTTP profile | Complete | Complete | Complete |
| Application profile kit | Complete profile contract | Complete | Complete; Python owns typed payload conversion while Rust brands commands |
| Ordered profile plans | Complete primitives | Complete | Complete |
| All-of, any-of, and threshold proof plans | Complete | Complete | Complete Rust-owned builder |
| Native-only effect command | Complete | Complete package-owned path | Complete non-constructible, non-copyable, non-pickleable, profile-bound, one-use path |
| Replay, budget, lifecycle, and reconciliation state | Complete | Complete ports and native state | Complete ports and native state |
| Exact execution receipts | Complete canonical receipts | Complete profile receipts | Complete profile receipts bound to action, proof authority, trust context, native state, outcome, and plan membership |
| Batch verification | Complete | Complete | Complete, bounded and GIL-releasing |
| Errors, inspection, telemetry, support bundle | Complete schemas | Complete | Complete and redacted |
| Replaceable adapters and conformance | Complete ports | Complete | Complete contracts, testkit, recipes, and separate SQLite reference package |
| Isolated release artifact consumers | Complete release system | Packed package matrix | abi3 wheel matrix with Rust removed |

## 4. Rust capability surface

Rust remains the only place where cross-language security meaning is defined.
Its principal surfaces are:

- credential-shape-agnostic identity descriptors, method relationships,
  signature suites, signed-message preimages, and explicit authority bridges;
- canonical principals, grants, permissions, resources, audiences, validity,
  budgets, status, assurance, critical extensions, and delegation depth;
- root and child authoring, non-widening attenuation, semantic diffs, signing
  requests, transaction commitments, and proof composition;
- trusted contexts, evidence and status snapshots, freshness and assurance,
  deterministic verification, explanations, metrics, and commitments;
- maintained profiles, review displays, verified-command decoding, ordered
  plan commitments, and closed execution boundaries;
- replay, budget, receipt, retry, reconciliation, and outcome-unknown state
  machines; and
- exact release subjects, SBOMs, provenance, semantic freeze, differential
  fixtures, and formal qualification.

Rust intentionally does not force every language to reproduce its crate graph.
The language SDKs compose its operations around complete application journeys.

## 5. TypeScript product surface

TypeScript is the ergonomic reference for browser, Node.js, and edge adoption.
Its elite specification provides:

- independent identity, authentication, verification, inspection, and
  diagnostics entry points;
- typed authoring, trust, lifecycle, attach, delegation, approval, and plan
  workflows over the packaged Rust/WASM core;
- MCP, maintained domain profiles, and an application profile kit;
- package-owned sealed commands, closed gateways, replay/budget state,
  receipts, observability, testkit, and adapter contracts; and
- packed direct-ESM, browser, worker, runtime, API, content, and hostile-boundary
  qualification.

TypeScript does not own every identity method, cryptographic suite, KMS,
resolver, transport, store, framework, or telemetry implementation. It owns
the port, conformance boundary, and a small reference set.

## 6. Python product surface

Python now exposes the same complete product journey through a Python-native
surface:

```text
auths.identity
  -> auths.verify / auths.inspection / auths.diagnostics
  -> auths.trust + auths.lifecycle + auths.authority
  -> AuthsClient.attach_agent -> delegate -> authorize / authorize_plan
  -> auths.profiles.mcp | auths.profiles.http | auths.profile_kit
  -> native-sealed command -> idempotent gateway -> exact receipt
  -> auths.runtime reconciliation and durable adapter ports
```

Key properties:

- `auths.identity` imports without authority, approval, profile, lifecycle, or
  runtime machinery. Authentication never creates permission.
- Python coordinates callbacks; Rust owns identity descriptor encoding,
  commitments, authoring, attenuation, proof assembly, verification, profile
  command branding, plan membership, and runtime state.
- Public verification results are inert. Only the integrated package-owned
  workflow can turn an authorized native result into a profile command.
- MCP, HTTP, and application profiles expose review before approval and use
  distinct action, authority, command, plan, gateway, receipt, and error types.
- Every effectful gateway requires an application idempotency key. Provider
  failure or cancellation after entry yields typed outcome-unknown evidence
  and completed plan-member receipts for reconciliation.
- Identity methods, suites, resolvers, custody, approval, evidence, clocks,
  stores, telemetry, gateways, transports, and frameworks remain replaceable
  versioned ports.
- `auths-sqlite` is a separately packaged durable reference. Vendor adapters
  are not dependencies of the base wheel.
- The public topology contains no `auths.advanced`, `auths.native`, or
  `auths.mcp` compatibility path.

## 7. Intentional language differences

| Difference | Product reason |
| --- | --- |
| Rust exposes crates and traits; TypeScript and Python expose cohesive clients and modules | Language users should not reconstruct the Rust composition graph |
| TypeScript uses promises, browser workers, and Web APIs; Python uses protocols, dataclasses, async context managers, strict mypy/Pyright, and controlled GIL release | Native ecosystem fit without semantic drift |
| Python distributes abi3 wheels; TypeScript distributes JavaScript plus an exact WASM subject | Each artifact uses its ecosystem's compiler-free consumption model |
| Python's maintained reference store is SQLite; TypeScript proves browser/server storage substitution | Reference adapters prove the port and do not define meaning |
| Adapter breadth differs | Auths owns conformance and selected examples, not the entire integration ecosystem |

These are not parity gaps. A gap exists only when a customer journey loses
meaning, safety, evidence, or operability in one supported SDK.

## 8. Current release gaps

The remaining gaps are evidence and release authority, not missing Python
workflow mechanics:

1. Run the exact branch through authoritative CI and the full installed-wheel
   matrix on Linux, macOS, and Windows for CPython 3.9–3.14.
2. Produce exact candidate SBOM and signed provenance through the existing
   release-control workflow.
3. Complete independent security and external-consumer review against those
   exact artifacts.
4. Reconcile capability promotion and publication only after all gates pass.

No gate should be closed by changing marketing copy or capability metadata
alone.

## 9. Definition of cross-SDK parity

Rust, TypeScript, and Python have product parity when an external team can:

1. exchange and authenticate identity without enabling capabilities;
2. substitute supported adapters without changing Auths meaning;
3. attach exact authority and delegate only narrower authority;
4. review, approve, authorize, and plan across maintained profiles;
5. execute only a native-minted command at a matching closed gateway;
6. reject replay, consume budget, reconcile unknown outcomes, and retain an
   exact receipt;
7. inspect decisions through stable, redacted operational evidence;
8. obtain the same semantic result from shared Rust-owned scenarios; and
9. install the exact ecosystem artifact without another language toolchain.

The repository implements this surface. Stable-V1, production, certification,
independent-review, and publication claims remain blocked until exact release
evidence authorizes them.
