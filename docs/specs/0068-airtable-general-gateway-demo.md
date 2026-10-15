# AP-SPEC-068: Robust Airtable demo through the general gateway

- **Status:** Implementation in progress. The engineering candidate, including
  native K-of-N approval integration, is implemented on
  `codex/general-gateway-demos`; hosted verification, protected qualification
  and a production deployment remain open.
- **Depends on:** [AP-SPEC-063](0063-generalized-gateway.md),
  [AP-SPEC-066](0066-production-gateway-polish-and-recipe-qualification.md),
  [AP-SPEC-039](0039-enterprise-coordination-and-operations-plane.md),
  [ADR 0012](../adr/0012-declarative-credential-isolated-gateway-boundary.md),
  [ADR 0013](../adr/0013-recipe-capabilities-and-sum-budget.md), and the
  [domain boundary plan](../target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md).
- **Companion:** [Stripe demo](0067-stripe-general-gateway-demo.md).
- **Scope:** One maintained exact-record, fixed-field Airtable demonstration
  using the general gateway, data-only recipe and installed public SDKs.
  No Airtable executor or provider-specific branch is added to core/runtime.
- **Normative language:** MUST, MUST NOT and SHOULD define requirements.

## 1. Decision

Build the maintained Airtable demo on the general gateway application interface.
An installed SDK authors/submits proof and canonical action bytes. A separate
operator installs and approves the recipe, trust and connection. Only the
gateway holds the runtime PAT, claims an operation and constructs its PATCH.

The effect is setting `DemoStatus` on one exact record in one fixed disposable
base/table, with a gateway-derived action echo in `auths_echo`. It is not a
general Airtable client, arbitrary-field editor, provider compare-and-swap,
provider deduplication service or production trust setup through the SDK testkit.

Replace the maintained walkthrough directly with this interface. The existing
app-held-token path may remain a clearly labeled self-hosted SDK reference;
it MUST NOT remain the primary credential-isolated demo or a hidden fallback
when gateway installation/qualification fails. Shared presentation or authoring
helpers may be reused; provider execution remains exclusively in the gateway.

### 1.1 Product interpretation

This demonstration is the cross-provider proof of the product boundary, not the
initial commercial wedge. It establishes that an application can request an
exact third-party write without holding the provider credential and without an
Airtable-specific executor in Auths core or the gateway.

The Stripe companion is the first packaged commercial journey. Airtable proves
that its enforcement mechanics are reusable through a second data-only recipe
while its field, resource, observation and provider-limit semantics remain
explicitly Airtable-owned. The initial product MAY be deployed as a
single-tenant, customer-hosted installation. Multi-tenancy, a public recipe
marketplace and arbitrary Airtable authoring are not requirements of this spec.

The commercial coordination product is not owned by this demo or by the gateway
runtime. AP-SPEC-039 owns its separate implementation and requires it to consume
versioned public Auths interfaces. This repository retains the open enforcement,
SDK, local operations, reference deployment and conformance surfaces.

## 2. Audited starting point and actual gaps

The field-lab checkout was audited at `afa733b` in
`auths-field-lab/prototypes/airtable-cli/`. The requested Auths checkout was
`393edc52`. PR [#206](https://github.com/auths-dev/auths-proof/pull/206), checked
13 October at `096579ad5d41ac34cfd4a424ab64eed6cf14f9ea`, was subsequently
merged as `f68f8b17` under explicit owner authorization.
Its complete release references are additional work, not proof that the older
CLI traverses them. Cross-repository source paths below are audit references,
not authorized runtime dependencies.

| Inspected source | Present behavior | Remaining work/evidence |
| --- | --- | --- |
| `README.md`, `runner.py`, `provider.py` | Local mode uses `auths.execution.run_once` and an app-owned `AirtableHttp` PAT. Native proof verification orders an application adapter, but the token holder can bypass it. | The new app submits only to the general gateway; prove actual process/filesystem/credential isolation rather than merely token-free function arguments. |
| `gateway_cli.py::_prepare/_install/_submit` | Already compiles a data-only recipe and submits proof/action through `GatewayClient`. Installation supplies a PAT on stdin to a development gateway; preparation uses `development_mcp_artifacts`. | Reuse this application-facing shape, replace development setup with explicit operator installation and independently provisioned trust for protected runs. |
| `gateway_profile/recipe.template.json` | Fixes origin, base/table, `DemoStatus`, replacement enum, GET observation and echo. It does not include the local mode's expected-old-value precondition. | State the real operation as an exact set. Do not claim the gateway preserves local mode's preflight behavior. Review and qualify actual substituted recipe bytes. |
| `provider.py::AirtableHttp.update` | Local mode reads `expected`, then PATCHes, then reads back. The read and PATCH are separate requests. | Even local preflight is not atomic compare-and-swap. Require a competing-writer case and explain its limit; do not port arbitrary Python callbacks into the gateway. |
| `gateway_cli.py::_observe` | Operator GET checks the replacement, prints an echo-shaped string and warns about causation. It does not itself verify the expected action echo. | Display the native linked observation and audit verification. A value match or an `auths-e1-` prefix must not become an observed-by-this-action verdict. |
| `runner.py::reconcile` | Local mode reports matching/different values through read-only observation; it does not create a signed gateway outcome. | Keep observation, gateway result and attribution distinct. New reconciliation uses the recipe's declared read-only gateway path, never a second PATCH. |
| `tests/test_signed_end_to_end.py`, `test_demo.py`, `test_adapter_conformance.py` | Real Auths proof checks and adapter tests use mocked Airtable transport. | Retain focused tests, add actual installed-client/native-gateway and protected live adverse cases. Passing mock HTTP is not live evidence. |
| `tests/test_gateway_mode.py` | Checks recipe preparation, token-on-stdin installation and token-free submission, using subprocess/client doubles for key boundaries. | Measure those properties with separate real processes, durable storage and real native outcomes. |
| `run-demo.sh`, `pyproject.toml`, README advanced setup | Builds/uses adjacent Auths checkout and explicitly installs its wheel; the package dependencies do not pin an Auths distribution. Same-user gateway mode explicitly disclaims isolation. | Deliver a digest/version-bound installable kit and clean source-free guide. Measure distinct UID/container isolation. |

PR #206 retains a genuine development live report at
`qualification/simulation/evidence/airtable-live-2026-10-07/report.json`:
two native processes, installed wheel, replay/alteration/restart refusals,
fresh value/echo read-back and record cleanup. Its source is `20837b56` with
`shared-file-v1`, `local-file-v1` and a development clock. It explicitly excludes
production custody/store, complete qualification corpus, independent lease/
entry counters and token restriction to one base. The signature is simulation
trust, not a protected production attestation.

## 3. Architecture and exact semantics

```text
Operator: select disposable table -> approve recipe/trust -> install gateway
Application: installed SDK -> exact proof/action -> general gateway socket
Gateway: durable claim -> PAT lease -> recipe-derived PATCH and linked GET
Independent source oracle/read-back -> evidence; protected signer -> attestation
```

1. The maintained demo SHOULD live under `demos/airtable-gateway/` in the
   monorepo. It MUST run without mutable sibling dependencies. The field-lab
   recipe/reference is input to review, not an executable plugin.
2. Use the shipping general gateway client in both Python and TypeScript.
   The application may send proof and action only; no provider URL, HTTP body,
   headers, token or operator configuration enters the application interface.
3. The recipe fixes `https://api.airtable.com`, Web API v0, base, table,
   `DemoStatus`, permitted `Pending`/`Approved` values, path construction,
   bounded response parsing and linked echo observation. Changing base/table
   or mappings changes the reviewed recipe digest and qualification.
4. The verified action binds recipe digest, namespace, logical operation,
   exact record and replacement. It MUST NOT grow optional arbitrary field,
   formula, table-name, endpoint or batch-write parameters.
5. The approved operation is **set this exact field**, with no expected-old
   value or compare-and-swap claim. If conditional mutation is needed later,
   it requires a separate reviewed capability and provider evidence; this
   demo must not pretend a preflight GET makes PATCH atomic.
6. Replay, admission, budget and recovery are gateway-owned durable state.
   No CLI marker, Python attempt store, frontend lock or queue supplies the
   production boundary. Two gateway processes share the selected real store.
7. A fresh read-back can link the declared value and exact echo under the
   stated external-writer assumptions. It does not prove exclusive causation
   or stop another actor overwriting the record after observation.

Reuse PR #206's `qualification/reference/airtable_record.py`, family plan,
independent request/evidence derivation and retained lifecycle after integration.
No family harness writes its own passing qualification reports. The native
runner derives verdict/counter closure. Existing core/formal checks are retained;
they prove their declared native boundaries, not Airtable's behavior.

## 4. Resource, credential and presentation contract

The operator selects a dedicated disposable table with plain-text `Name`,
`DemoStatus` and `auths_echo`; no customer data or automations with external
effects. Check actual schema/resource access during setup before creating
effects. The new app cannot choose another base/table at submission time.

Use two genuine distinct PATs with the required record read/write permissions
on the reviewed base. Setup/cleanup permissions remain operator-only and their
API entries are counted separately. Do not add metadata permissions unless the
chosen setup actually needs them. Verify required schema through an authorized
setup identity or an operator-supplied reviewed schema record.

For a base-restriction claim, require a genuine excluded disposable base/resource
known to exist and an independently established access control. A guessed
missing ID, 404, malformed token or network error does not prove restriction.
Measure allowed access and excluded access for **both** PATs. The current
recipe has no per-lease account guard; provider-configured PAT scope must not
be described as a gateway-enforced account-binding capability.

Provide a guided CLI and thin Docker-local HTTP workbench backed by the same
installed SDK journey. Show fixed base/table, exact record, field/value,
authority expiry/limits, recipe digest and result together. Closed controls
exercise mutation, enum refusal, replay, race, restart, response loss and
delayed observation. Show verification, write entry, response and linked
observation separately, with canonical result/audit data and an evidence page.

Missing fields, unsupported schema, wrong base scope, stale qualification,
failed doctor checks and unreachable gateway produce actionable refusals.
An unknown write offers bounded observation, never automatic PATCH retry.
Default setup requires no adjacent checkout or compiler. Operator setup reads
secrets privately; app execution has no `.env`, PAT, AWS or signing-key access.

### 4.1 Productization boundary

The current workbench exercises fixed engineering scenarios. It MAY add a
non-privileged local simulator that demonstrates the versioned integration
contracts below, but it MUST NOT become the commercial coordination product.

The open repository owns and tests:

1. Native K-of-N approval proposal, review, signing, collection and gateway
   verification, including insufficient threshold, duplicate signer, wrong
   record/action, expiry and replay cases.
2. Production gateway installation and diagnosis using PostgreSQL/TLS, AWS
   Secrets Manager, qualification inputs and customer-near PAT scope.
3. Bounded local status, recovery and evidence-export interfaces that preserve
   authorization, response recording, linked observation and unresolved outcome.
4. A local approval simulator showing fixed base/table, exact record,
   replacement, recipe digest, authority and expiry. Simulator state alone never
   authorizes an action.

The separately owned AP-SPEC-039 product may provide the real human approval
inbox and routing, guided customer onboarding, fleet operation and searchable
history. It MUST use the public contracts above and MUST NOT receive the PAT,
reinterpret a native result, add an Airtable executor or create a second
authorization implementation. A missing public integration contract discovered
by that product is added to the smallest valid open product layer with
conformance evidence; it is not implemented as a demo-only API.

## 5. Required proof and evidence matrix

All applicable AP-SPEC-066 wall scenarios remain mandatory. Bind each case's
independent expectation and actual measurement to the exact candidate, recipe,
production tuple and protected run. Inapplicability follows absent capabilities,
not test inconvenience.

| Experiment | Required observation |
| --- | --- |
| Request/oracle | Independent reference derives exact fixed-base/table PATCH, `DemoStatus`, action echo, segment encoding, allowed enum, GET subject and bounded pointers. It agrees with the native decision and request commitment. |
| Refusal | Forged/altered proof, wrong recipe/trust, malformed/unknown fields, record substitution, unsupported replacement and expired authority enter no write; hostile path text must never escape the fixed base/table; pre-custody refusals lease nothing. |
| Replay/budget/race | Original and fresh-challenge replays, applicable distinct-operation budget boundaries, two processes sharing the durable store and concurrent final capacity preserve admission without another PATCH. Read-only reconciliation leases are recorded separately. |
| Crash | Real process interruption before entry, after entry and before response persistence retains the actual attempt across restart. No case pre-seeds a successful outcome or edits gateway floors/counters. |
| Response loss/recovery | Lose the real PATCH response and delay visibility. Only fresh matching record, replacement and exact action echo can resolve the declared linked observation. Mismatched/absent echo, unavailable reads and stale evidence remain unresolved; no retry PATCH occurs. |
| Competing writer | Another run-owned actor changes value/echo before observation. The gateway does not claim success from unrelated matching values and does not overwrite that actor through recovery. Explicitly exclude atomic CAS and prevention of later external writes. |
| Scope/schema | Both PATs access the allowed disposable resource and refuse the verified excluded base. Missing `DemoStatus`/echo fields and wrong table are setup refusals, not fabricated successful effects. |
| Rotation/drift | Distinct PAT bytes and actual provider access are established before rotation. Measure successor installation, generation/commitment/external-version/store drift, two-host pinning and retirement. New AWS versions containing the same PAT do not prove provider-key rotation. |
| Isolation/installed clients | Actual app UID cannot read secrets/state, assume custody roles or access the admin socket. Installed Python and TypeScript clients submit without token/source imports and complete ordinary qualified effects. |
| Rate/errors | Transport timeout, 429, 4xx/5xx, malformed/oversized response and delayed visibility return typed outcomes. Reads/setup may use bounded pacing; an entered ambiguous write is never transparently retried. |
| Redaction | Scan real logs, traces, metrics, support bundle, proposal and final evidence against both PATs and all private canaries before publication. Missing categories fail closure. |
| Lifecycle | A durable ownership journal exists before creation. Lost setup response, partial setup and failed stage can discover and delete only this run's records. Unrelated records/table/base remain intact; failed cleanup invalidates final qualification. |

[Airtable's documented API limits](https://support.airtable.com/articles/7735693959-managing-api-call-limits-in-airtable)
currently include five requests/second per base and a 30-second wait following
rate-limit refusal, with separate monthly plan limits. The release harness
must budget setup/read-back/cleanup calls and pace ancillary traffic. It must
not serialize the two-host gateway contenders merely to avoid a rate limit.
A monthly quota failure is a missing prerequisite, not passing evidence.

## 6. Protected live qualification

Use AP-SPEC-066's closed corpus, commissioning authority, evidence wall,
protected signing hierarchy and verifier. No CLI success message, testkit
signature, development report or screenshot satisfies this acceptance stage.

The retained run MUST use PostgreSQL/TLS, synchronized production clock,
actual AWS web identity and version-pinned `aws-secrets-manager-v1`, distinct
admin/read custody identities, isolated application processes and the exact
shipping Linux candidate. Plaintext file custody and static AWS credentials
are development inputs, not production fallbacks.

Prerequisites verified 13 October 2026:

- `gateway-custody-live` has required reviewers but no deployment branch policy;
  establish the reviewed exact `main` policy before credentials are read.
- That environment's secret-name inventory contains only `STRIPE_TEST_KEY`.
  The retained Airtable workflow needs `AIRTABLE_QUALIFICATION_TOKEN` and
  `AIRTABLE_QUALIFICATION_NEXT_TOKEN`, with actual distinct/scope evidence.
- PR #206 was merged to main as `f68f8b17` under explicit owner authorization.
  This closes source landing only; the protected workflow remains manual/main-only
  and Epic 5 still needs actual protected evidence.
- The retained sequence-1 root revocation list expired on 8 October 2026 at
  03:01:16 UTC. Produce current higher-sequence root-signed revocation data
  offline and verify commissioner/release certificates. Never backdate a run
  or treat an expired root list as current.

Before any permit, the independent source expansion binds exact resources,
recipe/lock, actor, contexts and complete action pool. Candidate-generated
answers cannot provide expected request digests. Use finite commissioning
only through the private operator path; ordinary app requests still require
qualification and must measurably refuse until first qualification is imported.

Retain one resource session across commissioning, independently signed first
qualification, ordinary required-gate live execution and cleanup. Execute
every mandatory scenario and declared capability on that actual tuple. Only
after successful cleanup and complete-tree canary scans may the independently
rebuilt release signer issue the final attestation and signed index.

Use the reviewed Airtable maximum 14-day validity, exact recipe/contract/corpus
and candidate semantic closure, current revocation data and protected run/
attempt identity. Publish sanitized resource/evidence digests and exclusions;
not private PATs or unrestricted provider responses. Web API `v0` is not a
promise of an immutable provider implementation. Changed recipe/resource
bindings or provider behavior require renewed review and evidence.

Airtable contributes one provider/family to the launch gate. Both current
Stripe and Airtable attestations must match the final production candidate;
`release-check` derives readiness. A separate human core/provider boundary
review remains outside agent simulation and cryptographic claims.

## 7. Delivery and acceptance

1. Package one general-gateway demo in the monorepo. Make its gateway journey
   the maintained entry point and label the field-lab app-owned-token example
   as a reference with its bypass limit. Do not add compatibility execution paths.
2. Implement the CLI/workbench and independent oracle comparisons. Add actual
   gateway/SDK/browser adverse cases alongside focused reference unit tests.
   Run authoritative hosted checks on the exact candidate, including inventories
   and formal boundaries where applicable.
3. Perform a source-free packaged operator rehearsal, record excluded production
   operations, fix defects and rerun. Agent simulation is not a human adoption
   result. Keep historical live reports with their original tuples.
4. Complete both-key scope verification and the full protected lifecycle; publish
   verified current signing/index artifacts and sanitized inspectable evidence.
   Then download/install the actual GitHub release and repeat the guided journey.

Track **gateway demo implemented**, **development live evidence** and
**protected recipe qualified** separately. A matching cell, passing mocked
PATCH or existing generic gateway implementation alone closes none of the
unmeasured demo/qualification requirements. No exclusive-causation, provider
idempotency, arbitrary-record access or CAS claim is implied.

## 8. Gateway demo engineering candidate

The branch through `605017cd` adds a public installed-SDK
application, separate operator-issued root/actor authority, three native gateway
processes sharing durable operation claims, source-free Docker kit, CLI and
connected workbench/evidence page. CI measures exact request/read-back, enum
and proof/record refusals, replay/fresh challenge/race/restart, real response
loss with delayed visibility, another actual HTTP writer with a mismatched echo,
429/500 and malformed/oversized responses, actual gateway SIGKILL before entry
and after provider effect/before response persistence, process isolation and native audit.

Two source findings refine the engineering expectations. The reviewed profile
has no numeric argument or count-only capability: count/sum budgets are not
applicable, and no dummy spend field is added. Record fields have length bounds
rather than an Airtable-ID regex. Native path construction encodes hostile text
as one segment; a safe encoded nonexistent record may receive an entered 404.
Tests must prove it cannot escape the fixed resource, not claim such text
necessarily refuses before a lease. Record substitution after signing still
must refuse without custody or provider access.

Development `doctor` must retain its production-readiness refusal while its
store/recipe/generation/transport/isolation checks pass. Live preparation checks
actual text-column schema and runtime read access; it does not prove excluded
base access or two-key rotation. The simulation and packaged CI candidate remain
separate from protected full-corpus qualification, development live evidence,
independent human review and actual GitHub-release installation. Those acceptance
items remain open until measured on the required deployment.

The development launcher accepts `--live --env-file` and a single owner-provided
PAT shared by operator preparation and gateway custody, with that credential
model explicitly displayed. The application never receives it. This convenience
is not two-key rotation or provider-key separation evidence and does not change
§6’s protected credential requirements. Real record/view identifiers provide
provider-website links only in live mode.

| Product capability | Current candidate | Remaining gap |
| --- | --- | --- |
| Credential-isolated application | Implemented: the app submits proof/action bytes and cannot read the PAT or private gateway state. | Re-measure on the production custody/deployment tuple. |
| Exact write enforcement | Implemented: the fixed recipe, closed enum, durable replay state, race/restart and read-only ambiguous-outcome recovery use the general gateway. | Close hosted verification and the protected evidence wall. |
| Packaged developer journey | Implemented: source-free Docker handoff, installed Python and TypeScript clients, CLI, browser workbench and evidence view. | Repeat from the actual release artifact and complete independent human use. |
| Real provider effect | Implemented as an explicit development launch against one disposable Airtable table through the shipping gateway. | Run the retained protected sequence with two scoped PATs and current signed inputs. |
| Production operations | Not established: the demo intentionally uses one PAT for setup/runtime, development file custody/store, a software observer and local clock. | Deploy PostgreSQL/TLS, AWS web-identity custody, version-pinned Secrets Manager, two-key rotation and production diagnostics. |
| Approval integration | Implemented: the local simulator uses public native proposal, exact review, 2-of-3 signed-response collection and gateway verification. Insufficient quorum and duplicate response cases enter no provider write, and audit export carries the used responses. | Replace the simulator with a real human inbox only in the separately owned AP-SPEC-039 product; simulator state remains non-authoritative. |
| Protected qualification | Not established. | Complete §6 and publish current verifiable artifacts. |

No further provider-specific production executor is required. The next increment
is to run this exact application path on the production tuple, complete protected
qualification and connect the already exercised public approval contracts to the
commercial inbox and coordination service remain a separate product. Airtable's
business role is evidence that this product shape generalizes; it is not a
reason to turn the first launch into a broad connector catalogue.
