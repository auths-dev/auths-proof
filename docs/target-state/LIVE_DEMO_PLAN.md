# Auths Live Demo Plan

## Objective

Build a public, interactive demonstration that shows how Auths changes a real
authorization and execution flow. The demo must use the actual core verifier,
product runtime, replay/budget gates, proof exchange, and signed receipts. It
must not be a UI that merely animates predetermined verdicts.

The executable demo lives in the monorepo. `auths-proof-site` may link to or
embed the deployed demo but remains a separate repository.

## Current Implementation Boundary

The first executable vertical slice now lives in `demos/live-lab`. It is a
generated static lab, built from repository-owned fixtures and actual Auths
implementations rather than hand-authored verdict JSON.

This slice proves:

- The TypeScript SDK loads the built `auths-proof-wasm` module in the browser.
- A valid MCP `reports/read_report {"name":"q3"}` action produces the same
  canonical portable result bytes in native Rust and WASM.
- Action tampering, proof tampering, and verifier-configuration drift fail
  closed with real stable codes.
- Required and executed verifier configurations are both visible. The valid
  case asserts equality; the drift case asserts inequality and
  `verifier-configuration-mismatch`.
- The real native MCP runtime executes once, persists signed decision and
  execution receipts, and rejects an identical replay as a consumed challenge.
- All experiment inputs are preloaded, so browser verification continues after
  the network disconnects.

The authoritative build is:

```text
cargo xtask live-demo
```

It regenerates `target/live-demo/site`, enforces the exact bundle shape, and
runs byte-for-byte native/WASM parity for all four variants. `cargo xtask ci`,
`cargo xtask demos`, and `cargo xtask compliance` all include this check.

This slice is not yet the public target described below. It has one demo actor,
one raw-key root, no stateful budget, no live session API, and no external
deployment. The native runtime evidence is generated at build time rather than
served by a network service. The two-actor/two-root ceremony, budget behavior,
receipt explorer, public service, and multi-region deployment remain subsequent
phases. The UI must label these boundaries and must not imply they are already
implemented.

## Audience and Story

Primary audience:

- Developers evaluating integration effort.
- Security engineers evaluating authorization guarantees.
- Product and technical leaders evaluating practical value.

Flagship story:

> An AI agent requests an MCP tool call that deploys a service to production.
> Auths proves that the exact deployment was approved by the required people
> and organizations, enforces replay and blast-radius budgets, executes once,
> and produces independently verifiable receipts.

The demo compares transport/session authentication with proof-carrying
authorization without claiming that Auths replaces transport security.

## Core Scenario

Action:

```text
tool: deploy_service
service: payments-api
artifact: sha256:…
environment: production
region: eu-west
blast_radius: 4
```

Required policy:

- Two authorized proof branches.
- Two distinct actors.
- Two distinct roots.
- At least one hardware- or passkey-backed approval.
- Exact action body and artifact digest.
- Production audience.
- Fresh challenge and short validity window.
- Blast-radius budget no greater than five.
- Exact verifier configuration.

The safe executor does not contact a real deployment system. It updates
isolated demo state and increments a visible execution counter.

## User Experience

```text
+----------------------------------------------------------------------------+
| Auths Live Lab         WASM: ready  API: lhr  Release: 8f31c2  Config: match |
+----------------------------------------------------------------------------+
| Agent request                                                              |
| deploy_service payments-api → production / eu-west                         |
| Artifact: 71bc…                  Blast radius: 4                            |
+-----------------------------------+----------------------------------------+
| Required authorization            | Proof graph                            |
| [✓] 2 authorized branches         | Finance Root ─ Alice ─┐                |
| [✓] 2 distinct actors             |                       ├─ all-of         |
| [✓] 2 distinct roots              | Platform Root ─ Bob ──┘                |
| [✓] hardware-backed approval      |                                        |
| [✓] blast radius ≤ 5              | Plan: 82af…                            |
+-----------------------------------+----------------------------------------+
| Experiment                                                                 |
| [Change artifact] [Raise radius] [Reuse Alice] [Share root] [Revoke Bob]   |
| [Expire status]   [Wrong config] [Replay]      [Send concurrently]         |
+----------------------------------------------------------------------------+
| Browser verification: AUTHORIZED                                           |
| Native enforcement:    AUTHORIZED                                           |
| Result digests match:  yes                                                  |
+----------------------------------------------------------------------------+
| Runtime                                                                    |
| ✓ challenge  ✓ verify  ✓ replay claim  ✓ budget  ✓ execute  ✓ receipts     |
| Executor invocation count: 1                                                |
+----------------------------------------------------------------------------+
```

The default guided sequence:

1. Show the exact action and human approval display.
2. Collect two simulated approvals.
3. Assemble and visualize the proof.
4. Verify in browser WASM while offline-capable.
5. Submit the same proof to the native Rust enforcement service.
6. Compare canonical result digests.
7. Execute once and show signed decision/execution receipts.
8. Replay the same request and show that proof verification may remain valid
   while runtime execution is blocked by consumed challenge state.
9. Mutate one field and show the exact stable denial.
10. Introduce configuration drift and show required versus local
    configuration IDs.

## Modes

### Guided Tour

A narrated, deterministic sequence suitable for first-time visitors. Each step
explains one guarantee and provides a single “continue” action.

### Experiment Lab

Visitors freely apply one or more mutations and inspect proof graph, verifier
result, runtime gates, and receipts.

### Developer View

Shows canonical bytes, digests, stable codes, resource counters, request/response
payloads, and minimal integration code.

The default view hides raw CBOR and cryptographic detail.

## Architecture

The diagram in this section is the target public architecture. The current
`demos/live-lab` slice contains the browser and a deterministic native scenario
generator; it does not yet expose the native service over a network boundary.

```text
+--------------------------- Browser --------------------------------+
| Scenario UI                                                        |
|   ├── approval/proof visualization                                 |
|   ├── mutation controller                                          |
|   ├── receipt explorer                                             |
|   └── TypeScript SDK + real Auths WASM verifier                     |
+------------------------------+-------------------------------------+
                               |
                               | bounded demo API / proof exchange
                               v
+------------------------ Native demo service -----------------------+
| Session/challenge service                                          |
| Approval simulator and proof assembler                             |
| Native Auths verifier                                              |
| Atomic replay and budget stores                                    |
| Safe deployment executor                                           |
| Decision/execution receipt attestor                                |
| Privacy-preserving event stream                                    |
+------------------------------+-------------------------------------+
                               |
                               v
+------------------------- Demo state --------------------------------+
| Short-lived sessions | execution counter | immutable receipts      |
+--------------------------------------------------------------------+
```

The browser and backend verify independently. The backend never trusts the
browser verdict.

## Physical Deployment

### Current platform inventory

As verified on 26 July 2026, the authenticated Fly.io account contains:

| App | Region | Current shape |
| --- | --- | --- |
| `auths-network` | London (`lhr`) | One started Machine with passing checks |
| `auths-network-2` | Virginia (`iad`) | One started Machine with passing checks |

These deployments establish the two available GEOs but are separate Fly apps.
They must not become independent authorities over the same replay, budget, or
execution state. The demo should not reuse either app's production authority
or implicitly couple the demo lifecycle to the network services.

### Selected topology

Use four deployment environments:

| Surface | Staging | Production |
| --- | --- | --- |
| Browser UI and WASM | Vercel Preview | Vercel Production |
| Native demo service | `auths-live-demo-staging` | `auths-live-demo` |

Each Fly app contains one Machine in `lhr` and one in `iad`. This is preferable
to maintaining one app per region because Fly Proxy can route a session to its
owning region or Machine inside one deployment and one configuration boundary.

```text
+------------------------- Vercel --------------------------+
| Scenario UI + exact release metadata + real WASM verifier |
+------------------------------+----------------------------+
                               |
                      demo-api.auths.dev
                               |
                      Fly global proxy
                               |
                 +-------------+-------------+
                 |                           |
                 v                           v
+-------------------------------+  +-------------------------------+
| auths-live-demo / lhr         |  | auths-live-demo / iad         |
| Native verifier              |  | Native verifier               |
| Region-owned sessions        |  | Region-owned sessions         |
| Atomic replay/budget store   |  | Atomic replay/budget store    |
| Safe executor + receipts     |  | Safe executor + receipts      |
+-------------------------------+  +-------------------------------+
```

Vercel serves the UI, immutable WASM, and release metadata. It does not own
replay, budget, execution, or receipt state. Fly serves the bounded native API
and event stream.

### Session ownership and failover

The initial `POST /api/v1/sessions` is handled in the nearest healthy Fly
region. The response contains an authenticated opaque session token binding:

- random session ID;
- owner Fly app, region, and Machine;
- release ID;
- absolute expiry; and
- token version.

All later stateful requests are handled by that owner. A request received by a
different Machine is replayed to the owner with Fly dynamic request routing.
The application validates the authenticated ownership claim before issuing a
`fly-replay` response; it never trusts a visitor-supplied region header.

The demo keeps proof and request limits below Fly's 1 MB replay ceiling. If a
future profile legitimately exceeds that ceiling, the client must address the
owner directly or use an explicitly validated preferred-region flow rather
than silently bypass session affinity. See
[Fly dynamic request routing](https://fly.io/docs/networking/dynamic-request-routing/).

Fly Volumes are local and are not automatically replicated. The two regional
stores therefore remain independent and each owns only the sessions it
created. See [Fly Volumes](https://fly.io/docs/volumes/overview/).

If a session's owning Machine or region is unavailable:

- verification and execution fail closed;
- the other region does not reconstruct or continue the session;
- the UI explains that the short-lived session was lost; and
- the visitor may reset and create a new session in a healthy region.

This is an intentional availability boundary. Seamless failover of an active
session would require one authoritative transactional writer or a
consensus-backed global store and is not part of the first public demo.

### State and TTLs

Sessions have a fixed **15-minute absolute TTL** from creation. Activity does
not extend it. The remaining lifetimes are:

| State | Lifetime |
| --- | --- |
| Approval ceremony | No later than session expiry |
| Issued execution challenge | Five minutes and never later than session expiry |
| Event replay buffer | Session lifetime |
| Signed receipt retrieval | One hour |
| Rate-limit counters | Fifteen-minute rolling window |

The owner uses a local transactional store. One atomic transaction:

1. claims the challenge through a uniqueness constraint;
2. reserves the requested budget;
3. records the sealed verified command;
4. increments the safe executor counter; and
5. commits the immutable execution record.

Receipt signing is idempotent over the committed execution record. A retry may
return the same receipt but must never invoke the executor again.

Production Machines remain running in both regions to avoid a cold-start pause
during the guided tour. Use `auto_stop_machines = "off"` in production.
Staging may suspend when idle and auto-start on demand. Fly documents that
`min_machines_running` only applies to the primary region when autostop is
enabled, so it is not sufficient by itself to keep one Machine warm in both
GEOs. See [Fly app configuration](https://fly.io/docs/reference/configuration/).

### Release identity and configuration parity

CI builds one immutable release bundle containing:

```text
release_id
git_commit
native_image_digest
wasm_sha256
protocol_major
verifier_configuration_id
canonical_corpus_digest
```

Both Fly regions receive the same image, demo custody material, trust records,
and verifier configuration. Keys may rotate between releases but not
independently between regions in one release.

`GET /api/v1/meta` returns the public release fields. The frontend embeds its
expected release ID, WASM digest, protocol major, and verifier configuration
ID. It visibly fails closed and disables approval and execution if they do not
match the backend.

### Deployment and promotion

Every candidate follows this path:

1. Run monorepo CI and build native, WASM, frontend, and canonical corpus
   artifacts once.
2. Deploy the native image to `auths-live-demo-staging` in `lhr` and `iad`.
3. Create a Vercel Preview configured with the staging API origin.
4. Run the guided tour and every required experiment against each Fly region,
   including browser/native digest equality, replay, and concurrent duplicate
   execution.
5. Start new production Fly Machines in both regions with the tested image.
6. Stop assigning new sessions to the old Machines, but retain them for at
   least the 15-minute session TTL.
7. Create a staged Vercel production deployment without assigning the public
   domain, run smoke checks, and then promote that exact deployment.
8. Verify the production alias, both Fly regions, stable codes, configuration
   parity, and browser/native digests.
9. Remove drained Fly Machines only after their final sessions expire.

Vercel Preview is always paired with the staging Fly app; Vercel Production is
always paired with the production Fly app. Secrets and origins must not be
shared across those environments. Vercel supports inspecting and testing a
Preview before promoting it to Production; see
[Vercel preview promotion](https://vercel.com/docs/deployments/promote-preview-to-production).

Rollback keeps the previous Vercel deployment and drained Fly Machines
available until the session TTL passes:

- frontend failure: immediately restore the prior Vercel deployment;
- backend failure before new sessions: route new sessions to the prior Fly
  release;
- backend failure after new sessions: fail those sessions closed rather than
  execute against a different release;
- configuration disagreement: disable execution globally until parity is
  restored.

## Frontend Components

- Scenario selector and reset control.
- Exact action editor with bounded fields.
- Human approval display.
- Approval status cards for each actor.
- Proof-plan graph with actor/root identity grouping.
- Policy checklist.
- Mutation controls.
- Browser/native verdict comparison.
- Runtime stage timeline.
- Required/local configuration comparison.
- Receipt and audit-bundle explorer.
- Developer panel for bytes, digests, metrics, and code snippets.

Every displayed claim comes from decoded proof/result/receipt data or explicit
runtime events; no security outcome is inferred from UI state.

## Backend Components

### Session Service

- Creates short-lived isolated demo sessions.
- Issues cryptographically random challenges.
- Applies the fixed 15-minute absolute session TTL.
- Authenticates and enforces Fly app, region, Machine, and release ownership.
- Applies strict request, proof, and session limits.
- Resets all state on expiry.

### Approval Simulator

- Uses clearly labelled demo-only identities and custody.
- Produces real signed approval branches.
- Supports actor/root reuse and revocation scenarios intentionally.
- Never exposes private key material to the browser.

A later enhancement may use real WebAuthn passkeys, but the first release does
not require visitors to enroll credentials.

### Proof Assembler

- Uses production authoring and evidence-assembly APIs.
- Produces the same proof accepted by normal runtime enforcement.
- Exposes a safe structural projection for visualization.

### Enforcement Service

- Uses the production profile, SDK, runtime, exchange, replay, budget, and
  receipt components.
- Executes only the sealed verified command.
- Uses an isolated deterministic executor.
- Emits signed decision and execution receipts.

### Event Stream

- Emits bounded, privacy-safe stage transitions.
- Contains no private keys, proof bytes, principals, or action arguments.
- Supports reconnect and terminal session replay.

## Demo API

All endpoints are versioned and bounded.

```text
POST /api/v1/sessions
GET  /api/v1/sessions/{session_id}
POST /api/v1/sessions/{session_id}/approvals/{actor}
POST /api/v1/sessions/{session_id}/mutations
POST /api/v1/sessions/{session_id}/assemble
POST /api/v1/sessions/{session_id}/verify
POST /api/v1/sessions/{session_id}/execute
POST /api/v1/sessions/{session_id}/replay
GET  /api/v1/sessions/{session_id}/receipts
GET  /api/v1/sessions/{session_id}/events
GET  /api/v1/meta
```

Representative session response:

```json
{
  "state": "ready",
  "policy": {
    "minimum_authorized_branches": 2,
    "minimum_distinct_actors": 2,
    "minimum_distinct_roots": 2
  },
  "browser_verdict": null,
  "native_verdict": null,
  "execution_count": 0,
  "owner_region": "lhr",
  "expires_at": "2026-07-26T12:15:00Z",
  "release_id": "8f31c2"
}
```

Binary proof, context, result, and receipt objects use explicit content types
and are not embedded as unconstrained JSON arrays.

## Required Experiment Scenarios

| Experiment | Expected outcome |
| --- | --- |
| Valid two-actor/two-root proof | Authorized and executed once |
| Same actor used twice | Composition denial |
| Distinct actors under one root | Root-diversity denial |
| Artifact changed after approval | Exact-action denial |
| Blast radius raised above five | Budget/constraint denial |
| Revoked approval | Revocation denial |
| Stale required status | Indeterminate |
| Wrong audience | Audience denial |
| Replayed challenge | Runtime replay rejection, no second execution |
| Concurrent duplicate | Exactly one execution |
| Wrong verifier configuration | Configuration mismatch with both IDs |
| Receipt sink unavailable | Behavior follows selected fail-closed policy |
| Browser disconnected | Local WASM verification still works |

## Security and Abuse Controls

- Demo keys are isolated, labelled, non-production, and rotated during deploy.
- No visitor-controlled URL, resolver host, command, shell, or external network
  target is executed.
- Action fields use typed allowlists and strict size limits.
- Sessions, approvals, and receipts expire.
- Per-IP and per-session rate limits apply.
- Concurrent requests are bounded.
- Backend state is namespaced by unpredictable session ID.
- Session ownership tokens are authenticated, expire absolutely, and cannot
  select an arbitrary Fly region or Machine.
- CORS allows only the exact Vercel Preview or Production origins assigned to
  the corresponding Fly environment.
- Responses never contain private custody material.
- Logs use privacy-preserving operational events.
- The executor performs only sandboxed state transitions.
- Security headers, CSP, dependency pinning, and supply-chain checks are part
  of deployment CI.

## Observability

Track:

- Session and scenario counts.
- Verdict and stable-code counts.
- Verification latency and work units.
- Proof/result byte sizes.
- Replay and concurrent-duplicate rejections.
- Browser/native digest disagreements.
- Receipt persistence failures.
- Sessions, failures, and latency by owner region and release ID.
- Cross-region replay routing, failed owner routing, and session resets.
- Release, WASM, protocol, and verifier-configuration disagreements.

Any browser/native disagreement is a high-severity alert and visibly fails the
demo closed.

## Implementation Phases

### Phase 1: Deterministic Local Lab

- [x] Reuse existing demo fixtures and hostile mutations.
- [x] Build browser UI with real WASM verification.
- [x] Show the proof graph, verdict, required/executed configuration, work
      counters, replay outcome, executor count, and receipt counts.
- [x] Preload all experiment inputs for verification after disconnection.
- [x] Generate a deterministic site with `cargo xtask live-demo`.
- [x] Enforce exact native/WASM portable-result parity in CI.
- [ ] Add guided-tour narration and richer receipt inspection.

### Phase 2: Native Enforcement

- [x] Exercise the native MCP runtime, real challenge ledger, safe executor,
      replay gate, and signed receipt producer during deterministic generation.
- [x] Compare browser/native canonical result bytes in CI.
- [ ] Add a bounded native demo service and session API.
- [ ] Move challenge issuance and execution from build-time evidence to
      per-session requests.
- [ ] Add the real budget gate and independently verify receipt signatures in
      the lab.
- [ ] Fail the interactive service closed on browser/native release or result
      disagreement.

### Phase 3: Approval Ceremony

- Add two simulated approval actors with distinct roots.
- Assemble proof incrementally.
- Show remaining requirements in real time.
- Add actor/root reuse and revocation mutations.

### Phase 4: Public Hardening

- Add abuse controls, deployment isolation, observability, fault injection,
  accessibility, mobile layout, and load tests.
- Create separate staging and production Fly apps, each in `lhr` and `iad`.
- Add region/Machine-bound session routing and fail-closed owner loss.
- Add Vercel Preview-to-staging and Production-to-production environment
  isolation.
- Add immutable release metadata, two-region smoke tests, draining, promotion,
  and rollback automation.
- Publish a stable URL and link/embed it from `auths-proof-site`.

## Acceptance Criteria

- Every verdict is produced by real Auths code.
- Browser and native verification return identical canonical result digests.
- Mutating any signed action field prevents execution.
- Actor and root diversity experiments behave independently.
- Replay and concurrent duplicate experiments execute exactly once.
- Required/local configuration mismatch is visible and actionable.
- Decision and execution receipts verify independently.
- Browser verification works after network disconnection.
- The demo contains no production authority or external execution capability.
- End-to-end tests run in monorepo CI using built WASM and native artifacts.
- New sessions can be created in both `lhr` and `iad`.
- A session remains bound to exactly one Fly owner and cannot execute in the
  other region.
- Loss of the owner fails closed and permits only an explicit session reset.
- Vercel Preview uses only the staging Fly app, and Vercel Production uses only
  the production Fly app.
- The UI refuses execution when release, WASM, protocol, or verifier
  configuration metadata disagree.
- Old Fly Machines remain available for the full 15-minute drain window during
  a deployment.
