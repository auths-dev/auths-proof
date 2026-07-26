# Auths Live Demo Plan

## Objective

Build a public, interactive demonstration that shows how Auths changes a real
authorization and execution flow. The demo must use the actual core verifier,
product runtime, replay/budget gates, proof exchange, and signed receipts. It
must not be a UI that merely animates predetermined verdicts.

The executable demo lives in the monorepo. `auths-proof-site` may link to or
embed the deployed demo but remains a separate repository.

## Current Implementation Boundary

The first public vertical slice now spans:

- `demos/live-lab`: generated browser application and real WASM verifier;
- `demos/live-service`: bounded native Rust session and execution service; and
- `demos/testkit/auths-apps-testkit`: shared challenge-bound fixtures and real
  runtime harness.

It is deployed at:

- browser lab: `https://auths-live-demo.vercel.app`;
- native API: `https://auths-live-demo.fly.dev`; and
- Fly regions: London (`lhr`) and Virginia (`iad`), one always-on Machine in
  each region.

The lab is generated from repository-owned fixtures and actual Auths
implementations rather than hand-authored verdict JSON. A production browser
creates a short-lived native session, verifies its session-specific proof in
WASM, submits only a bounded repository-owned experiment identifier, and
compares the browser result digest with the native result digest.

This slice proves:

- The TypeScript SDK loads the built `auths-proof-wasm` module in the browser.
- A valid MCP `reports/read_report {"name":"q3"}` action produces the same
  canonical portable result bytes in native Rust and WASM.
- Action tampering, proof tampering, and verifier-configuration drift fail
  closed with real stable codes.
- Required and executed verifier configurations are both visible. The valid
  case asserts equality; the drift case asserts inequality and
  `verifier-configuration-mismatch`.
- A fresh production session carries a cryptographically random challenge and
  an authenticated owner token bound to region, session, expiry, and release.
- The real native MCP runtime executes once, persists signed decision and
  execution receipts in the session runtime, and rejects an identical replay
  as a consumed challenge without invoking the executor twice.
- Hostile variants are denied by the portable verifier and never enter the
  runtime executor boundary.
- Cross-region execution requests are replayed by Fly Proxy to the
  authenticated session-owner region.
- The browser fails closed if schema, release ID, protocol, portable ABI,
  verifier configuration, WASM digest, or per-result digest disagrees.
- All experiment inputs are preloaded, so browser verification continues after
  the network disconnects.

The authoritative build is:

```text
cargo xtask live-demo
```

It regenerates `target/live-demo/site`, enforces the exact bundle shape, and
runs byte-for-byte native/WASM parity for all four variants. `cargo xtask ci`,
`cargo xtask demos`, and `cargo xtask compliance` all include this check.

This first public release intentionally remains narrower than the flagship
target below. It has one demo actor, one raw-key root, no stateful budget,
no receipt explorer, no event stream, and no two-actor/two-root approval
ceremony. The safe executor performs no external action. The build-time native
scenario remains as an offline fallback and CI oracle, while live execution
uses per-session challenges and runtime state from the native service.

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

The diagram in this section includes the deployed browser/native boundary. The
approval simulator, budget store, receipt explorer, and event stream remain
target-state components rather than claims about the first public release.

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
| `auths-live-demo` | London (`lhr`) | One always-on 512 MB Machine, check 1/1 |
| `auths-live-demo` | Virginia (`iad`) | One always-on 512 MB Machine, check 1/1 |

The two `auths-network` deployments established the available GEOs but remain
separate Fly apps. The demo does not reuse either app's production authority or
couple its lifecycle to those network services. Both demo Machines live in the
dedicated `auths-live-demo` app and run the same immutable image.

### Selected topology

The target deployment model has four surfaces:

| Surface | Staging | Production |
| --- | --- | --- |
| Browser UI and WASM | Vercel Preview | Vercel Production |
| Native demo service | `auths-live-demo-staging` | `auths-live-demo` |

Each Fly app contains one Machine in `lhr` and one in `iad`. This is preferable
to maintaining one app per region because Fly Proxy can route a session to its
owning region or Machine inside one deployment and one configuration boundary.

The first public release deploys the production pair only:

| Surface | Deployed target |
| --- | --- |
| Browser UI and WASM | Vercel project `auths-live-demo`, Production alias |
| Native demo service | Fly app `auths-live-demo`, `lhr` + `iad` |

`auths-live-demo-staging` and a paired Vercel Preview have not been
provisioned. They remain required before an automated preview-to-production
promotion pipeline can claim full environment isolation.

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
- owner region;
- release ID;
- absolute expiry; and
- token version.

All later stateful requests are handled by that owner. A request received by a
different Machine is replayed to the owner with Fly dynamic request routing.
The application validates the authenticated ownership claim before issuing a
`fly-replay` response; it never trusts a visitor-supplied region header.

The first release deliberately runs exactly one Machine per region. The token
does not encode a Fly Machine ID: the dedicated app/secret boundary identifies
the service, and the authenticated region identifies its sole Machine. Adding
a second Machine to either region without introducing explicit Machine
affinity or shared regional state would violate session ownership. Deployment
checks must therefore continue to assert one healthy Machine in each configured
region.

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

First-release state is deliberately bounded and ephemeral:

| State or limit | Current value |
| --- | --- |
| Session and challenge | 15-minute absolute TTL; activity does not extend it |
| Regional session pool | 2,048 sessions |
| Attempts per session | 16 |
| Session creations | 120 per regional Machine per rolling minute |
| Request body | 4 KiB |
| Receipt lifetime | In-memory session lifetime; no retrieval endpoint yet |
| Event replay buffer | Not implemented |
| Stateful budget | Not implemented |

Each Machine owns an in-memory session map. The production runtime's atomic
challenge ledger guarantees that the exact challenge can drive the safe
executor once. The runtime records one signed decision receipt and one signed
execution receipt; an exact retry is refused as `consumed-challenge` and the
executor count remains one.

Machine restart or replacement intentionally loses its sessions. Those
sessions fail closed and visitors must create a fresh session. Durable receipt
retrieval, an explicit budget transaction, and drain-preserving deployment are
target-state work.

Production Machines remain running in both regions to avoid a cold-start pause
during the guided tour. Use `auto_stop_machines = "off"` in production.
Staging may suspend when idle and auto-start on demand. Fly documents that
`min_machines_running` only applies to the primary region when autostop is
enabled, so it is not sufficient by itself to keep one Machine warm in both
GEOs. See [Fly app configuration](https://fly.io/docs/reference/configuration/).

### Release identity and configuration parity

The first public release binds:

```text
release_id = git commit
wasm_sha256
protocol_major
portable_abi
verifier_configuration_id
```

Fly records the immutable native image reference as deployment metadata. The
image digest and canonical corpus digest are not yet returned by
`GET /api/v1/meta`; adding them remains release-hardening work.

`GET /api/v1/meta` returns the public release fields. The frontend embeds its
expected release ID, WASM digest, protocol major, and verifier configuration
ID. It visibly fails closed and disables approval and execution if they do not
match the backend.

### Deployment and promotion

#### Production deployment record

Deployed and verified on 26 July 2026:

| Field | Value |
| --- | --- |
| Browser alias | `https://auths-live-demo.vercel.app` |
| Immutable browser URL | `https://auths-live-demo-hz1xcssev-bordumbs-projects.vercel.app` |
| Vercel deployment | `dpl_6qUpg93h6TMWiUg4RMeEwM1Rbvnw` |
| Native API | `https://auths-live-demo.fly.dev` |
| Release ID | `40a07c56b87104e2b325e057b2598a3a0044af66` |
| WASM SHA-256 | `2d5b8aa9982f6ee04e107f37727ade56eedd99676c7c1801ed3d9d94f2a2f9c8` |
| Verifier configuration | `df14e85024bf099cef6396b1a3515209625d73a86ed1da92b118dddcf6a486d5` |
| Fly release | Version 3, `rel_v6gwzpglk9r7z9ok` |
| Fly image | `registry.fly.io/auths-live-demo:deployment-01KYG40KWVNCCZRST3Z292WMXB` |
| London Machine | `8d96959be23498`, started, check 1/1 |
| Virginia Machine | `7812615f2201d8`, started, check 1/1 |

Production evidence:

- The complete `cargo xtask ci` gate passed, including workspace tests,
  clippy/docs, MSRV 1.91, no-std boundaries, corpus and transport conformance,
  bindings, packaging, fuzz seeds, live-demo parity, and product compliance.
- `GET /healthz` and `GET /api/v1/meta` succeeded in both `lhr` and `iad`.
- Both regions returned the exact release, WASM, ABI, protocol, and verifier
  configuration expected by the Vercel bundle.
- A session created in `lhr` and submitted with `iad` preferred was routed back
  to `lhr`, executed once, and produced one decision plus one execution receipt.
- Its exact replay returned `refused / consumed-challenge`; executor and receipt
  counts remained one.
- A fresh `iad` session with a tampered proof was denied before entering the
  runtime, with zero executor invocations.
- A real production browser showed `READY / NOT RUN / 0`, then
  `COMPLETED / READY / 1`, then
  `COMPLETED / CONSUMED-CHALLENGE / 1`; the replay control became disabled.
- The production browser surface was visually checked against
  `auths-proof-site` and uses the same canvas, typography, color, evidence-card,
  technical-section, navigation, and footer language.
- The hostile browser flow showed `DENIED / NOT ENTERED / 0` and browser/native
  result-digest parity remained `MATCH`.
- The exact production origin passed CORS. An untrusted origin received the
  fixed production allow-origin value rather than its own origin, so browser
  access fails by origin mismatch.
- A request body larger than 4 KiB returned HTTP 413.
- Vercel returned HTTPS preload, CSP, clickjacking, MIME-sniffing, referrer, and
  permissions headers; the CSP permits network access only to the Fly API.

#### Reproducible production procedure

Run the authoritative repository gates first:

```text
cargo xtask ci
AUTHS_LIVE_RELEASE_ID=<40-character-git-commit> cargo xtask live-demo
```

The Fly token-signing secret is a random 32-byte value and must never be
printed, committed, or passed as a command-line argument. On first provision,
stage it through standard input:

```text
flyctl secrets import -a auths-live-demo --stage
AUTHS_LIVE_TOKEN_KEY=<64-lowercase-hex-characters>
<end standard input>
```

Deploy the native service and assert the two-region shape:

```text
flyctl deploy . -c demos/live-service/fly.toml -a auths-live-demo --ha=false \
  --env AUTHS_LIVE_RELEASE_ID=<40-character-git-commit> \
  --env AUTHS_LIVE_WASM_SHA256=<64-character-wasm-sha256> \
  --env AUTHS_LIVE_ALLOWED_ORIGIN=https://auths-live-demo.vercel.app
flyctl scale count 2 -a auths-live-demo -r lhr,iad --max-per-region 1 -y
flyctl machines list -a auths-live-demo
```

Deploy the exact generated directory, not a separately rebuilt frontend:

```text
npx --yes vercel@latest deploy target/live-demo/site \
  --project auths-live-demo --prod --yes
```

After deployment, verify both preferred regions, the metadata handshake, a
fresh valid submission, its exact replay, every hostile variant, the request
limits, CORS, CSP, and the same transitions in a real browser.

#### Current rollback procedure

The first release updates Machines in place, so active in-memory sessions do
not survive either deployment or rollback. They fail closed and visitors must
reset. There is also a short interval where one surface may reject the other
because release IDs disagree; that is intentional fail-closed behavior.

Rollback the native service to the preceding image and release identity:

```text
flyctl deploy -a auths-live-demo -c demos/live-service/fly.toml --ha=false \
  --image registry.fly.io/auths-live-demo:deployment-01KYG0N6YNQ6CQ3TCTCFPP4H5R \
  --env AUTHS_LIVE_RELEASE_ID=131065f83a951916ec129ccdf3fb43fb7a6047dc \
  --env AUTHS_LIVE_WASM_SHA256=2d5b8aa9982f6ee04e107f37727ade56eedd99676c7c1801ed3d9d94f2a2f9c8 \
  --env AUTHS_LIVE_ALLOWED_ORIGIN=https://auths-live-demo.vercel.app
```

Then restore the paired preceding Vercel deployment:

```text
npx --yes vercel@latest rollback dpl_3xGts3Xuq9XJo2dzGKLhzJYq43f9 --yes
```

Run the complete production smoke suite again after rollback. Do not roll back
only one surface and leave it mismatched.

#### Target promotion path

The mature staging-to-production path is:

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

The drain-preserving blue/green behavior in this target path is not implemented
by the current in-place Fly deployment command.

## Frontend Components

The first release implements the scenario, mutation controls, proof graph,
browser/native comparison, runtime timeline, configuration comparison, bounded
metrics, and developer byte/digest view. The approval ceremony, editable
action, receipt explorer, and reset control remain target work.

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

The first release implements the Session Service and the verifier/replay/safe
executor/receipt portions of the Enforcement Service. The Approval Simulator,
incremental Proof Assembler, stateful budget, receipt retrieval, and Event
Stream are target work.

### Session Service

- Creates short-lived isolated demo sessions.
- Issues cryptographically random challenges.
- Applies the fixed 15-minute absolute session TTL.
- Authenticates and enforces region, session, expiry, token version, and release
  ownership inside the dedicated Fly app.
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

- Uses the production profile, SDK, runtime, exchange, replay, and receipt
  components. The budget component remains target work.
- Executes only the sealed verified command.
- Uses an isolated deterministic executor.
- Emits signed decision and execution receipts.

### Event Stream

- Emits bounded, privacy-safe stage transitions.
- Contains no private keys, proof bytes, principals, or action arguments.
- Supports reconnect and terminal session replay.

## Demo API

The first public release intentionally exposes only:

```text
GET  /healthz
GET  /api/v1/meta
POST /api/v1/sessions
POST /api/v1/sessions/{session_id}/execute
```

`execute` accepts an object containing exactly one bounded `variant` ID:
`valid`, `tampered-action`, `tampered-proof`, or `wrong-configuration`.
It does not accept visitor-supplied proof bytes, commands, URLs, targets, or
executor arguments.

The expanded target API remains:

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

Implemented controls:

- Demo custody is isolated and non-production.
- No visitor-controlled URL, resolver host, command, shell, proof bytes,
  external target, or executor argument is accepted.
- Only four typed experiment identifiers are accepted.
- Requests, sessions, attempts, regional capacity, and creation rate are
  bounded.
- Backend state is namespaced by a random 128-bit session ID.
- Session owner tokens use HMAC-SHA-256, expire absolutely, and bind the
  session, region, and release before any `Fly-Replay` response is emitted.
- CORS always names the exact Vercel Production origin; an untrusted origin
  cannot make it reflect the attacker origin.
- Responses contain no private custody material, and the bearer token remains
  only in browser memory.
- The executor performs only an isolated deterministic state transition.
- Both surfaces emit no-store and security headers; Vercel enforces a strict
  CSP.
- Docker runs the native service as distroless non-root, and CI checks its Fly,
  Docker, Vercel, release-parity, architecture, dependency, and supply-chain
  policy.

Still required for the flagship target:

- per-IP distributed rate limiting rather than the current per-Machine
  creation limiter;
- production operational event logging and alerting;
- automated demo-key/token-key rotation;
- load and fault-injection tests; and
- separate staging origins and secrets.

## Observability

The current release exposes Fly health checks plus public region and release
metadata. It does not yet emit the target operational metrics below.

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
- [x] Add a bounded native demo service and session API.
- [x] Move challenge issuance and execution from build-time evidence to
      per-session requests.
- [ ] Add the real budget gate and independently verify receipt signatures in
      the lab.
- [x] Fail the interactive service closed on browser/native release or result
      disagreement.

### Phase 3: Approval Ceremony

- Add two simulated approval actors with distinct roots.
- Assemble proof incrementally.
- Show remaining requirements in real time.
- Add actor/root reuse and revocation mutations.

### Phase 4: Public Hardening

- [x] Add strict session, attempt, rate, request, CORS, CSP, container, and
      execution controls.
- [x] Deploy production Fly Machines in `lhr` and `iad`.
- [x] Add authenticated region ownership, dynamic owner routing, and
      fail-closed session loss.
- [x] Add immutable release metadata and two-region production smoke tests.
- [x] Publish a stable production URL.
- [ ] Add distributed rate limiting, observability, fault injection,
      accessibility audit, and load tests.
- [ ] Create a separate staging Fly app in `lhr` and `iad`.
- [ ] Add Vercel Preview-to-staging and Production-to-production environment
      isolation.
- [ ] Add drain-preserving blue/green promotion and automated rollback.
- [ ] Link or embed the stable URL from `auths-proof-site`.

## Acceptance Criteria

Current first-release status:

- [x] Every displayed verdict is produced by real Auths code.
- [x] Browser and native verification return identical canonical result
      digests.
- [x] Every shipped signed-action mutation prevents execution.
- [x] Exact replay executes once and returns `consumed-challenge` without a
      second executor invocation.
- [x] Required/local configuration mismatch is visible and actionable.
- [x] The runtime creates signed decision and execution receipts.
- [x] Browser verification continues with inputs already loaded when the native
      service is disconnected.
- [x] The demo contains no production authority or external execution
      capability.
- [x] End-to-end tests run in monorepo CI using built WASM and native artifacts.
- [x] New sessions can be created in both `lhr` and `iad`.
- [x] A session remains bound to one owner region and cross-region requests are
      replayed to it.
- [x] Loss of in-memory owner state fails closed and permits only a fresh
      session.
- [x] The UI refuses execution when release, WASM, protocol, ABI, verifier
      configuration, or result metadata disagree.
- [ ] Actor and root diversity experiments behave independently.
- [ ] The stateful budget experiment enforces blast radius.
- [ ] Concurrent duplicate API requests are exercised by the public smoke
      suite and execute exactly once.
- [ ] Decision and execution receipt signatures are independently verified in
      the browser.
- [ ] Vercel Preview uses only the staging Fly app, while Vercel Production
      uses only the production Fly app.
- [ ] Old Fly Machines remain available for the full 15-minute drain window
      during deployment.
