# auths-proof-apps

Effectful applications and control-plane components for Auths Proof Protocol
V1.

Start with the [developer integration guide](docs/developer-integration.md)
for the Rust, TypeScript/WASM, Python, and pure-Go package surfaces.

This workspace owns application profiles, live evidence acquisition, runtime
orchestration, replay and budget ports, canonical decision/execution receipts,
reference applications, and Auths Lab. The proof kernel remains offline in
`auths-proof`; every transport remains in `auths-proof-exchange`.

External custody is transaction-bound and keyless: WebAuthn, workload, KMS,
HSM, and PKCS#11 clients receive an exact Auths signing intent and cannot
return a signed object for a different preimage. Evidence assemblers bind live
SPIFFE/X.509, WebAuthn, and HSM results to content-addressed proof evidence
outside the pure verifier.

The execution invariant is:

```text
canonical profile action
  -> pure Auths verification
  -> sealed VerifiedAction
  -> profile-decoded command
  -> atomic replay/budget claims
  -> ExecutableAction<Command>
  -> executor
```

Executors never receive original request bytes. Authenticated peers are
additional local-policy facts and cannot upgrade a denied or indeterminate
Auths decision.

Implemented profile contracts:

- `auths.mcp/1`;
- `auths.http/1`;
- `auths.git/1`;
- `auths.deploy/1`;
- `auths.supply-chain/1`;
- `auths.edge/1`.

Supported developer surfaces:

- `auths-sdk`: trusted-context, verification, issuance, and custody facade;
- `auths-enforcement`: HTTP, gRPC, CI, MCP, and service-local enforcement
  entry points;
- `auths-deployment`: replay- and blast-radius-safe deployment execution;
- `auths-profile-kit`: deterministic fixtures and hostile-input scaffolding;
- `@auths-dev/proof`: precompiled WASM with an idiomatic TypeScript API;
- `auths-proof`: stable-ABI Python wheels;
- `auths.dev/independent-verifier/auths`: independent pure-Go verifier.

The MCP reference runtime emits content-addressed canonical decision receipts
for authorized, denied, and indeterminate proof evaluations and a separate
execution receipt after an authorized command succeeds or fails. Receipt
storage, replay storage, clocks, challenge randomness, budgets, and execution
remain explicit effects.

The did:web integration performs bounded, SSRF-resistant HTTPS acquisition and
emits immutable content-addressed evidence; it never verifies authority or
chooses trust.

Declarative configuration compiles into an immutable context binding and
registry manifest. Persistent reference challenge and budget stores survive
restart within one service process; deployments with concurrent writers must
use transactional shared implementations. Readiness probes and runtime events
use stable, low-cardinality fields and never include proof bytes, principal
identifiers, resources, tool arguments, or custody data.

Auths Lab enumerates the full 7 principal × 2 mandatory suite × 6 transport ×
6 profile surface (504 nominal points), records cold/warm and path-specific
measurements separately, detects transport-induced semantic divergence, and
stores operator-study notes only as digests.

```sh
cargo run -p auths-mcp-demo -- demo --transport memory
cargo xtask arch
cargo xtask matrix
cargo xtask cross-language
cargo test -p auths-apps-testkit target_flow_is_transport_independent_and_replay_safe
```

The Iroh demo and live transport conformance require local socket access.
The cross-language gate independently audits the proof corpus from Go and
TypeScript, then runs the Rust, Go, and TypeScript semantic verifiers. It
requires exact agreement on artifact digests, decisions, stable reason codes,
proof/context/action/plan identifiers, authorized branches, and role-indexed
assurance reports.
