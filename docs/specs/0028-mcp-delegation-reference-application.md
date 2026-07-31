# AP-SPEC-028: MCP delegation reference application

**Status:** Specified — local and reversible Phase 10 implementation is
blocked on AP-SPEC-027 and the AP-SPEC-033 Phase 9 exit gate

**Governs:** The local MCP reference-vertical portion of Phase 10 in the
[Post-Milestone 6 Productization and Release Plan](../target-state/POST_MILESTONE_6_PRODUCTIZATION_AND_RELEASE_PLAN.md)

**Source strategy:** [Auths Product and Go-to-Market Strategy](../plans/GO_TO_MARKET_STRATEGY.md)

**Aligned with:** [Post-Milestone-6 Technical and Go-to-Market
Alignment](../plans/POST_MILESTONE_6_TECHNICAL_AND_GO_TO_MARKET_ALIGNMENT.md)

**Depends on:** AP-SPEC-032, AP-SPEC-033, AP-SPEC-027,
`auths-profile-mcp`, `auths-proof-exchange`, `auths-enforcement`, and the
existing MCP demo

**Scope:** An explicitly labeled developer-preview reference application in
which a human-authorized parent agent delegates narrower authority to a child
agent, the child invokes a fixed MCP tool backed by a local constrained HTTP
API, and forbidden actions stop before any external side effect

**Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are
requirements on conforming implementations.

## 1. Decision

Auths will make delegation—not identity verification—the central MCP
demonstration.

The application will protect one closed records service with exactly three
public MCP tools:

- `read_demo_record`;
- `update_demo_record`;
- `delete_demo_record`.

The parent grant permits reading and updating the one configured demo record.
The child receives a narrower, short-lived grant permitting only
`update_demo_record`. The authorized update executes. The delete is a visible
negative control and MUST be terminally denied before credential acquisition
or HTTP execution.

The tool names are intentionally fixed. The reference application MUST NOT
accept an arbitrary URL, HTTP method, path, header set, credential, record
identifier, or provider command from the agent.

### 1.1 Phase placement and effect boundary

Implementation begins only after:

- AP-SPEC-033 permits the explicitly labeled Phase 10 developer preview;
- AP-SPEC-027 has a pinned preview package and passing exit evidence for the
  surfaces used here;
- no unresolved Phase 9 release block affects MCP, exchange, enforcement,
  receipt, or binding behavior used by the application; and
- the local record mutation has a deterministic reset and no production data,
  credential, tenant, or provider dependency.

Phase 10 execution is limited to synthetic local state, sandbox state, or
another demonstrably reversible effect approved under AP-SPEC-033. Production
credentials, regulated data, financial effects, infrastructure changes, and
irreversible external mutations are outside this specification.

## 2. Product claim

The demo proves this bounded claim:

> A parent agent can delegate a smaller authority to a child agent; the child
> can exercise the authorized MCP action, cannot exercise a sibling action,
> and cannot gain authority by retrying or restarting.

It does not prove:

- that MCP transport authentication is authorization;
- that all MCP tools share the same policy or gateway semantics;
- that Auths prevents a separately credentialed process from calling the HTTP
  API;
- exactly-once provider execution without the stated local ledger and provider
  precondition;
- production security, independent audit, or universal agent safety.

The application MUST be described as a developer-preview reference vertical,
not the Phase 13 production flagship or evidence that the new TypeScript and
MCP integration code received the Phase 9 review of the earlier RC.

## 3. Goals

The implementation MUST provide:

- a TypeScript reference agent using AP-SPEC-027;
- a maintained Rust MCP profile and closed verified command;
- parent-to-child attenuation visible in the application;
- a native MCP server or adapter that verifies locally;
- a local constrained HTTP records API with observable mutation state;
- an MCP-specific credential port and least-privilege credential;
- a closed HTTP gateway for each effect;
- profile-owned decision, execution, and observation receipts;
- durable replay and execution state sufficient for restart tests;
- allowed, out-of-scope, expired, replayed, wrong-audience, mutated-action, and
  expanded-child scenarios;
- tests proving absence of every forbidden external effect.

## 4. Non-goals

The application MUST NOT:

- become a generic MCP proxy;
- accept arbitrary MCP server definitions or dynamically load tool executors;
- put HTTP execution in `auths-profile-mcp`;
- add MCP variants to a global receipt union;
- use one unscoped `mutation_credential(account)` interface;
- treat tool discovery as authority;
- make a valid signature or authenticated MCP connection sufficient;
- retry an unknown provider outcome as a new action;
- require a hosted Auths service;
- introduce a CLI product surface.

The demo command used by repository tests MAY remain, but it is not the
product CLI proposed and rejected by the strategy.

## 5. User experience

The reference web view or terminal view MUST keep authority, action, execution,
and receipt facts adjacent:

```text
+------------------------------------------------------------------+
| Auths MCP delegation demo                                        |
| Human root -> parent-agent -> records-child                       |
+-------------------------------+----------------------------------+
| Child authority               | Proposed action                  |
| service: records              | tool: update_demo_record         |
| expires: 10 minutes           | value digest: 8f62...            |
| allowed: update only          | audience: mcp://records          |
+-------------------------------+----------------------------------+
| [Run authorized update]  [Try forbidden delete]  [Restart child] |
+------------------------------------------------------------------+
| AUTHORIZED / DENIED / INDETERMINATE                               |
| proof -> policy -> claim -> credential -> HTTP -> observation     |
| credential requested: no/yes · provider calls: 0/1                |
+------------------------------------------------------------------+
| Canonical receipt JSON                         [Receipt details]  |
+------------------------------------------------------------------+
```

The happy path and negative control MUST start from visible, reproducible
state. A user MUST be able to see:

- who delegated to whom;
- what narrowed at each edge;
- the exact MCP tool and argument commitment;
- the required and executed configuration commitments;
- whether a credential was requested;
- whether the HTTP gateway was called;
- whether the record changed;
- the stable denial or indeterminate code;
- the canonical receipt.

The UI MUST distinguish:

1. proof authorization;
2. durable execution authorization;
3. HTTP provider acceptance;
4. observed record state.

These are not one verdict.

## 6. Architecture

```text
+----------------------- browser / TypeScript agent ------------------------+
| human-approved parent -> narrow child -> exact MCP tools/call request      |
+------------------------------------|---------------------------------------+
                                     v
+-------------------------- protected MCP server ----------------------------+
| bounded MCP decode                                                       |
| -> exact auths.mcp/1 canonical action                                    |
| -> local proof verification                                              |
| -> profile-specific policy/effect selection                              |
| -> durable claim                                                         |
| -> profile-scoped credential                                             |
| -> closed verified command                                               |
+-------------------|------------------------------------|------------------+
                    | authorized                          | denied
                    v                                     v
+------------------- HTTP gateway ----------------+   terminal receipt
| fixed origin + fixed route + fixed method       |
| conditional update of configured demo record   |
+-------------------|-----------------------------+
                    v
+---------------- local records API --------------+
| record state | revision | provider call counter |
+-------------------|-----------------------------+
                    v
             observation + receipt
```

### 6.1 Package ownership

`auths-profile-mcp` permanently owns:

- canonical MCP `tools/call` representation;
- MCP service, tool, arguments, audience, and optional channel binding;
- permission derivation;
- verified MCP command decoding.

A new cohesive product package or an extension of an existing coherent MCP
product package MUST own this demo's effect semantics:

- the closed set of records tools;
- the parent and child policy carrier;
- the exact tool-to-effect mapping;
- profile-specific decision codes;
- durable claim and replay behavior;
- the read, update, and delete credential scopes;
- closed HTTP requests;
- observation and reconciliation;
- MCP records receipts.

The demo owns:

- the fixed local HTTP service;
- seeded demo state;
- browser or terminal presentation;
- process orchestration;
- adversarial scenario controls;
- end-to-end tests.

The effect package MUST NOT move MCP or HTTP I/O into `core/`. The demo MUST
not become a dependency of production packages.

### 6.2 Closed tool mapping

The trusted server configuration binds:

| MCP tool | HTTP effect | Resource |
| --- | --- | --- |
| `read_demo_record` | `GET /v1/demo-record` | one configured record |
| `update_demo_record` | `PUT /v1/demo-record` with canonical bounded body | the same record |
| `delete_demo_record` | `DELETE /v1/demo-record` | the same record |

The agent supplies only the bounded update value for
`update_demo_record`. The route, origin, method, record identity, expected
response schema, and credential scope come from trusted configuration and the
verified command.

The update request MUST use a revision precondition. A stale revision is
denied or becomes a typed provider conflict according to the profile contract;
it MUST NOT silently overwrite newer data.

### 6.3 Credential boundary

Credentials MUST be profile- and effect-scoped:

```rust
trait UpdateDemoRecordCredentialProvider {
    fn update_credential(
        &self,
        command: &ClaimedUpdateDemoRecord,
    ) -> Result<UpdateDemoRecordCredential, CredentialError>;
}
```

Read and delete use different interfaces and opaque credential types. The
child's update path MUST NOT be able to obtain a delete credential.

Credential acquisition occurs only after:

1. exact proof verification;
2. required/executed configuration equality;
3. profile evaluation;
4. durable decision;
5. atomic replay/execution claim;
6. fresh critical state validation.

### 6.4 Receipts

The MCP records profile owns distinct receipt payloads:

- authorization decision receipt;
- execution transition receipt;
- HTTP provider result receipt;
- observed-state receipt.

A shared receipt envelope MAY carry stable metadata without erasing these
types. Adding this application MUST NOT require Stripe, GitHub, PostgreSQL, or
other demos to match MCP-specific variants.

## 7. Authority and policy

The human root issues a parent grant with:

- audience `mcp://records`;
- MCP profile V1;
- permission for `read_demo_record` and `update_demo_record`;
- a short bounded validity interval;
- remaining delegation depth at least one;
- an execution budget appropriate to the fixture;
- the committed policy and executed-configuration identity.

The parent delegates to the child:

- only `update_demo_record`;
- the same audience;
- a strictly shorter validity interval;
- strictly smaller remaining delegation depth;
- no more execution budget than the parent;
- the same or tighter approval requirements;
- the exact policy/configuration commitment.

The child MUST be unable to construct a valid expanded grant. Expansion is
rejected by core attenuation before any effect-specific processing.

## 8. APIs

### 8.1 MCP tools

```text
tools/list
  -> read_demo_record
  -> update_demo_record
  -> delete_demo_record

tools/call read_demo_record {}
tools/call update_demo_record {"value": "<bounded UTF-8 value>"}
tools/call delete_demo_record {}
```

The bounded update value MUST:

- be valid UTF-8;
- be non-empty;
- remain below the profile byte limit;
- reject unknown fields and non-canonical argument representations.

### 8.2 Demo HTTP routes

```text
GET  /healthz
GET  /readyz
GET  /api/v1/demo-record
PUT  /api/v1/demo-record
DELETE /api/v1/demo-record

POST /api/v1/scenarios/reset
GET  /api/v1/scenarios/current
GET  /api/v1/receipts/{receipt_id}
GET  /receipts/{receipt_id}
```

Mutation routes MUST require the profile-scoped credential and revision
precondition. Scenario-control routes are local-test controls and MUST be
disabled in any public deployment.

### 8.3 Reference application flow

```ts
const parent = await auths.attachAgent(parentOptions);
const child = await parent.delegate(updateOnlyChildGrant);

const allowed = await child.authorize(
  mcp.call("update_demo_record", { value: "reviewed" }),
);
if (allowed.kind === "authorized") {
  await recordsTools.execute(allowed.command);
}

const forbidden = await child.authorize(
  mcp.call("delete_demo_record", {}),
);
assert(forbidden.kind === "denied");
```

The SDK and gateway MUST make it impossible to pass `forbidden` to
`recordsTools.execute`.

## 9. Failure semantics

At minimum, the profile MUST define stable outcomes for:

- malformed or non-canonical MCP arguments;
- unknown service or tool;
- action digest mismatch;
- expanded child grant;
- expired parent or child grant;
- wrong audience;
- wrong challenge or replay;
- policy commitment mismatch;
- required/executed configuration mismatch;
- stale record revision;
- credential unavailable;
- provider rejection;
- provider outcome unknown;
- observation mismatch;
- duplicate execution claim.

Retry guidance MUST be explicit. Proof or policy denials are terminal for
unchanged inputs. A restart MUST load the same durable grant and execution
state; it MUST NOT mint fresh authority.

Unknown provider outcomes retain the execution claim until reconciliation.
They MUST NOT be retried as a new logical action.

## 10. Test and evidence matrix

| Scenario | Expected decision | Credential calls | HTTP calls | Record change |
| --- | --- | ---: | ---: | --- |
| Valid child update | authorized and committed | 1 update | 1 PUT | exactly once |
| Child delete | denied | 0 delete | 0 DELETE | none |
| Different service | denied | 0 | 0 | none |
| Mutated update value | denied | 0 | 0 | none |
| Expired child grant | denied | 0 | 0 | none |
| Wrong audience | denied | 0 | 0 | none |
| Expanded child grant | denied | 0 | 0 | none |
| Replay after commit | existing committed receipt | 0 additional | 0 additional | none additional |
| Restart then forbidden delete | same terminal denial | 0 delete | 0 DELETE | none |
| Configuration mismatch | denied before persistence | 0 | 0 | none |
| HTTP response lost after delivery | indeterminate | 1 update | 1 PUT | reconcile |

Tests MUST observe gateway and API counters or durable request records. Merely
asserting a denied return value is insufficient evidence of no side effect.

Required coverage:

- unit and property tests for action bounds and policy tightening;
- canonical fixtures and a mutation corpus;
- denial-before-credential tests;
- exact outbound request equality tests;
- replay, crash, restart, and reconciliation tests;
- Node integration tests through the published package;
- browser end-to-end tests if a browser UI ships;
- architecture and compliance registration;
- authoritative CI on the exact revision.

## 11. Delivery order

1. Freeze the MCP records profile and trust claim.
2. Define exact parent and child policies, stable codes, and receipts.
3. Implement the pure profile evaluator and negative corpus.
4. Implement durable claim and restart semantics.
5. Implement separate read, update, and delete credential ports.
6. Implement closed HTTP gateways and the local records service.
7. Integrate the AP-SPEC-027 TypeScript agent flow.
8. Add the adjacent authority/action/receipt presentation.
9. Close adversarial, crash, browser, architecture, compliance, and CI
   evidence.

## 12. Exit gate

The Phase 10 MCP reference-vertical gate is complete only when:

- the full happy path works locally from a clean checkout;
- the parent-to-child attenuation is visible and inspectable;
- the permitted update occurs exactly through a verified command;
- every negative scenario proves zero forbidden credential and provider calls;
- a restarted child retains the same authority and denials;
- unknown outcomes reconcile without a second logical execution;
- MCP receipts and credentials remain profile-scoped;
- adding the application does not force unrelated profiles or demos to
  understand MCP variants;
- all state and effects remain local, synthetic, sandboxed, or demonstrably
  reversible;
- preview labeling and exact reviewed-versus-new code boundaries are visible
  in documentation and release evidence;
- the authoritative repository checks pass on the exact revision.

Passing this gate does not permit consequential customer operation. Phase 11
runtime, recovery, credential, and deployment gates remain separate.
