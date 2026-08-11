# Cross-company incident response: executable implementation specification

Status: implemented

This specification closes the gap between the demo's claims and its effect boundary. It is intentionally a clean prelaunch target: the obsolete browser-authorized ticket path was deleted rather than preserved behind aliases, shims, migration code, or dual receipt formats.

## Product outcome

The trusted Python service authors and verifies an exact two-member `auths.edge/1` plan, obtains two authenticated organizational approvals, receives opaque native command handles, reserves durable execution state, acquires provider credentials, executes the effects, and persists native signed receipts.

The browser is an untrusted proposer and observer. HTTPS and Iroh transport bytes but cannot mint authorization. TypeScript and Python expose equivalent application-profile gateways over Rust-owned canonicalization, authorization, lifecycle, and receipt semantics.

## Scope and exclusions

The implementation must prove the reusable SDK and security boundaries. It does not claim production custody or operations.

Included:

- Rust-owned canonical action, proof, context, plan, lifecycle, and receipt meaning;
- opaque in-process commands in TypeScript and Python;
- matching application execution, credential, state, receipt, and provider ports;
- real local OIDC authorization-code + PKCE approval with P-256 JWT verification;
- signed EdgeShield approval over the exact transaction digest using Ed25519;
- transactional local persistence, replay exclusion, ordered plan execution, unknown outcomes, and reconciliation;
- real HTTPS and Iroh delivery;
- Rust-generated TypeScript/Python differential fixtures;
- adversarial tests that observe the effect boundary.

Excluded:

- HSM/KMS custody and organizational key recovery;
- a production identity-provider tenant or public certificate authority;
- multi-node or multi-region database availability;
- production provider reconciliation jobs, monitoring, retention, and on-call procedures;
- compatibility with any prelaunch ticket, endpoint, or receipt shape.

SQLite with `BEGIN IMMEDIATE`, unique commitments, and native lifecycle transitions is the transactional reference adapter for this single-process demo. A production deployment must implement the same SDK state port with a highly available durable database.

## Non-negotiable invariants

- [x] Rust remains the sole owner of Auths semantic encoding and decisions.
- [x] Arbitrary TypeScript or Python cannot construct an effect-capable command.
- [x] A command is consumed once in the process that minted it and is never serialized.
- [x] Durable reservation succeeds before credential acquisition or provider entry.
- [x] The provider receives the exact canonical command bytes retained by the native handle.
- [x] Approval authenticates a principal and is bound to the exact signing transaction and committed plan.
- [x] Delivery success never becomes authorization.
- [x] Ambiguous provider outcomes cannot become failure, success, or permission to retry.
- [x] Receipts are canonical, signed, Rust-owned artifacts rather than application-authored claims.
- [x] TypeScript and Python agree on canonical bytes, commitments, outcomes, and stable errors.

## Phase A — Shared native waist

- [x] Bind application actions and plans to opaque native command handles in Python.
  - Evidence: `bindings/python/src/application.rs`
- [x] Make command and plan handles single-use and retain proof, canonical action, and trusted context only inside native ownership.
  - Evidence: `bindings/python/src/application.rs`, `bindings/typescript/src/profiles/application/index.ts`
- [x] Remove public raw command extraction from the TypeScript root surface.
  - Evidence: `bindings/typescript/src/index.ts`, package tests
- [x] Keep maintained Edge domain canonicalization in Rust and expose typed Python projections.
  - Evidence: `bindings/python/src/domains.rs`, `bindings/python/python/auths/profiles/domains.py`
- [x] Establish stable native ABI inventory for the added Python functions.
  - Evidence: `bindings/python/native-abi-v2.json`, `bindings/python/python/auths/_native.pyi`

Acceptance:

```sh
cargo check --manifest-path bindings/python/Cargo.toml
cargo check -p auths-proof-wasm
```

## Phase B — TypeScript/Python application-runtime parity

- [x] Define matching state, credential, receipt-attestor, provider, and result-canonicalizer ports.
- [x] Execute one command and an ordered plan through the same lifecycle order.
- [x] Surface exact canonical command bytes only inside the downstream provider context.
- [x] Preserve stable conflict, replay, expiry, order, provider, cancellation, and unknown-outcome identities.
- [x] Consume plan handles once and expose no partial command capability after authorization failure.
- [x] Provide matching development receipt attestors and in-memory application stores.

Evidence:

- `bindings/typescript/src/profiles/application/index.ts`
- `bindings/typescript/src/testkit/index.ts`
- `bindings/python/python/auths/profile_kit.py`
- `bindings/python/python/auths/testkit.py`
- `bindings/python/tests/test_elite_sdk.py`
- `bindings/typescript/test/integration/profiles/mcp.test.js`

Acceptance:

```sh
cd bindings/typescript
npm run test:contract
npm run test:unit
npm run build:vectors
npm run test:integration:built

cd ../..
pytest -q bindings/python/tests
```

## Phase C — Canonical native receipts

- [x] Bind a decision receipt to the proof commitment, full canonical action commitment, trusted context, statuses, profile, decision, time, and signer.
- [x] Bind an execution receipt to the decision, idempotency/plan lease, exact canonical command bytes, outcome, canonical result, time, and signer.
- [x] Expose preparation, attestation, and verification in Python and WASM/TypeScript.
- [x] Reject malformed, non-canonical, mutated, wrongly linked, or wrongly signed receipts.
- [x] Persist only native signed receipt bytes at the demo effect boundary.
- [x] Generate deterministic receipt IDs, canonical bytes, and signing preimages from Rust and assert identical projections in TypeScript and Python.

Evidence:

- `product/receipts/auths-receipts/src/lib.rs`
- `bindings/python/src/receipts.rs`
- `bindings/python/python/auths/receipts.py`
- `bindings/wasm/auths-proof-wasm/src/lib.rs`
- `bindings/wasm/auths-proof-wasm/examples/generate-node-vectors.rs`
- `target/binding-vectors/workflow.projection.json`

Acceptance:

```sh
cargo test -p auths-receipts
cd bindings/typescript && npm run build:vectors && npm run test:integration:built
cd ../.. && pytest -q bindings/python/tests/test_mcp_workflow.py::test_shared_full_workflow_projection_matches_native_python
```

## Phase D — Trusted demo effect boundary

- [x] Delete endpoints that accepted an operation plus ticket, caller-authored approval flags, or serialized command substitutes.
- [x] Make `/api/workflow/execute` the sole plan execution route.
- [x] Hold demo root, agent, and receipt custody at the trusted service for the process lifetime.
- [x] Bootstrap bounded raw-key authority and authorize both plan members inside the trusted service.
- [x] Reserve each ordered member transactionally before credentials and provider I/O.
- [x] Acquire the Northstar bearer token or EdgeShield certificate credential only after reservation.
- [x] Execute only the two exact decoded `EdgeActionInput` values.
- [x] Deliver the cache member's exact canonical command bytes over real Iroh before the gated provider call.
- [x] Persist lifecycle state and native decision/execution receipts in SQLite.

Evidence:

- `demos/cross-company-incident-response/agent-service/auths_incident_agent/incident.py`
- `demos/cross-company-incident-response/agent-service/auths_incident_agent/execution.py`
- `demos/cross-company-incident-response/agent-service/auths_incident_agent/custody.py`
- `demos/cross-company-incident-response/agent-service/auths_incident_agent/server.py`
- `demos/cross-company-incident-response/control-room/src/app.ts`

## Phase E — Authenticated approvals

- [x] Northstar performs authorization code + PKCE and issues an ES256 token.
- [x] The Python adapter verifies JWT algorithm, issuer, audience, subject, expiry, key ID, P-256 key, and signature locally.
- [x] Northstar verifies the bearer token before approving the exact request ID and transaction digest.
- [x] EdgeShield authenticates its closed certificate fingerprint and signs the exact transaction digest with its current Ed25519 key.
- [x] Python verifies the EdgeShield Ed25519 signature before returning approval.
- [x] Native plan approval prompts the 2-of-2 threshold once and binds subsequent member release to the same committed plan.

Evidence:

- `demos/cross-company-incident-response/northstar-service/src/server.ts`
- `demos/cross-company-incident-response/edgeshield-service/src/main.rs`
- `demos/cross-company-incident-response/agent-service/auths_incident_agent/approval_adapters.py`

## Phase F — Replay, ambiguity, and reconciliation

- [x] Atomically reject concurrent ownership of the same idempotency key or command commitment.
- [x] Prove two concurrent full workflow requests produce exactly one winner and two total provider calls, one per plan member.
- [x] Prove replay after completion causes zero additional credential acquisitions and provider calls.
- [x] Exercise a real provider effect followed by a deliberately lost response.
- [x] Persist the member as `outcome-unknown` with no fabricated execution receipt.
- [x] Prove a new authorized attempt cannot reacquire credentials or re-enter the provider for that idempotency key.
- [x] Reconcile the native lifecycle explicitly to `reconciled-committed` after observing the effect.

Evidence:

- `demos/cross-company-incident-response/agent-service/auths_incident_agent/execution.py`
- `demos/cross-company-incident-response/agent-service/auths_incident_agent/server.py`
- `demos/cross-company-incident-response/tests/integration.py`

## Phase G — Effect-oriented attacks

Each pre-effect attack must report zero new credential acquisitions and zero provider calls. Post-effect ambiguity must instead report the exact provider entry, block retry, and require reconciliation.

- [x] delegation widening fails in the native child planner before signing;
- [x] canonical action mutation fails in both Python and TypeScript verification;
- [x] replay and concurrent ownership fail at durable reservation;
- [x] expiry and compromised principal cases fail through native lifecycle semantics;
- [x] unauthorized Iroh delivery succeeds as transport but reaches no effect gateway;
- [x] pre-effect, post-effect, and ambiguous provider outcomes remain distinct;
- [x] approval withdrawal exposes no second plan-member command;
- [x] browser tests wait for receipts to render before reporting authorization.

Acceptance:

```sh
demos/cross-company-incident-response/scripts/test-local.sh
```

This command starts all four services and waits for every readiness endpoint. It then runs Python service tests, the full live integration suite, browser controls, a real Iroh exchange test, and the EdgeShield Rust test.

## Parity contract

| Operation | TypeScript | Python | Source of truth |
| --- | --- | --- | --- |
| Canonical domain action | typed application profile | typed application profile | Rust domain profile |
| Authorize one action or ordered plan | same decisions/codes | same decisions/codes | Rust verifier/author |
| Effect-capable command | opaque, single-use | opaque, single-use | native handle |
| Reserve and enter provider | matching state port | matching state port | Rust lifecycle kernel |
| Credential acquisition point | after reservation | after reservation | gateway contract |
| Provider outcome | matching outcome/error model | matching outcome/error model | gateway + Rust lifecycle |
| Decision/execution receipt | canonical and attested | canonical and attested | Rust receipts |
| Differential fixture | consumes Rust projection | consumes Rust projection | Rust vector generator |

Language syntax may be idiomatic. Accepted bytes, commitments, security boundaries, transition meaning, receipt bytes, and stable failure identities may not differ.

## Completion evidence

The implementation is complete when all commands below pass on one revision:

```sh
cargo test -p auths-receipts
cargo check --manifest-path bindings/python/Cargo.toml
cargo check -p auths-proof-wasm

cd bindings/typescript
npm run test:contract
npm run test:unit
npm run build:vectors
npm run test:integration:built

cd ../..
pytest -q bindings/python/tests
demos/cross-company-incident-response/scripts/test-local.sh
cargo xtask semantic-freeze
```

Repository-wide GitHub CI remains authoritative under `AGENTS.md`.

## Exit outcome

The demo now proves the intended boundary:

> Two organizations can authenticate and approve the same exact, short-lived, ordered authority without sharing an identity provider or provider credential. An agent can execute only the native-authorized commands, once, after durable reservation; transport cannot grant authority; ambiguous effects cannot be retried blindly; and independent verifiers can validate the Rust-owned signed receipts in TypeScript or Python.
