# Auths Live Demo Plan

## Objective

Build a public, interactive demonstration that shows how Auths changes a real
authorization and execution flow. The demo must use the actual core verifier,
product runtime, replay/budget gates, proof exchange, and signed receipts. It
must not be a UI that merely animates predetermined verdicts.

The executable demo lives in the monorepo. `auths-proof-site` may link to or
embed the deployed demo but remains a separate repository.

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
| Auths Live Lab                         Browser WASM: ready   Backend: ready  |
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
  "execution_count": 0
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

Any browser/native disagreement is a high-severity alert and visibly fails the
demo closed.

## Implementation Phases

### Phase 1: Deterministic Local Lab

- Reuse existing demo fixtures and hostile mutations.
- Build browser UI with real WASM verification.
- Implement proof graph, verdict, configuration, and receipt visualization.
- Support offline browser verification.

### Phase 2: Native Enforcement

- Add native demo service.
- Issue real challenges.
- Run replay/budget gates and safe executor.
- Generate signed decision and execution receipts.
- Compare browser/native result digests.

### Phase 3: Approval Ceremony

- Add two simulated approval actors with distinct roots.
- Assemble proof incrementally.
- Show remaining requirements in real time.
- Add actor/root reuse and revocation mutations.

### Phase 4: Public Hardening

- Add abuse controls, deployment isolation, observability, fault injection,
  accessibility, mobile layout, and load tests.
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

