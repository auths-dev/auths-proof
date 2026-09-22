# Case 0007: declarative credential-isolated request construction

## Candidate and owner

A product-layer interpreter for a *closed provider request* derived from one
verified `auths.mcp/v2` command and an immutable, operator-approved recipe.
The candidate is transport construction and stage recording, not a generic
provider adapter, evaluator, status classifier, or reconciliation engine.
ADR 0012 permits design investigation only; AP-SPEC-053 owns later acceptance.

## Consumers compared

| Operation | Candidate closed write | Effect and observation deliberately outside shared meaning |
| --- | --- | --- |
| Airtable fixed-field update | `PATCH` to a pinned base/table and typed record ID at an approved origin; fixed `DemoStatus` key and bounded replacement in a JSON body | The existing demo reads the old field before writing and reads the same record afterward. A current value that differs from the expected old value is a preflight conflict; a later matching value is observation, not proof of exclusive causation. |
| Todoist task creation | `POST` to an approved Sync endpoint; compiler-serialized bounded `item_add` command within a form field, with fixed keys and committed IDs | The demo interprets Sync status and temporary-ID mapping, reads the returned task, and can search paginated tasks for a unique marker. A missing task in one observation does not prove the write absent. |
| GitHub issue creation | `POST` to a pinned repository's `/repos/{owner}/{repo}/issues` at an approved origin; fixed JSON keys such as bounded `title` and `body` | GitHub returns a created issue number and URL, but permissions, validation/spam responses, repository policies, and later issue reads are GitHub semantics. A later title/body match is not by itself unique-effect proof. This is a design recipe, not a live test or qualified integration. |

The first two descriptions come from the field-lab adapters. GitHub's
[official create-issue endpoint](https://docs.github.com/en/rest/issues/issues#create-an-issue)
documents the third request shape; its behavior must be rechecked against a
disposable repository before any live claim.

## Exact shared contract and exclusions

Identical mechanics: native verification precedes typed projection; an
operator-pinned HTTPS origin, method, fixed headers, fixed and typed path
segments, and fixed-shape bounded body produce one closed request; no
credential is available before an atomic logical-operation claim; the
credential-bearing transport is isolated from the submitting application;
response bytes and time are bounded; post-entry ambiguity cannot trigger an
automatic second write. The recipe digest and logical operation ID must be
committed in verified action bytes before the claim.

Excluded: provider account discovery, preconditions and expected-old-value
meaning, OAuth/scopes beyond a pinned connection binding, provider-native
idempotency rules, status-to-effect mapping, pagination, the *provider-effect
meaning* of read-back equality, reconciliation, qualified receipts, and
exactly-once external effects. These cannot be supplied by a universal
response callback or arbitrary JSON rule. A bounded equality comparison is
only an observation of state, not a proof that this write caused it.

## Classification

| Surface | Airtable | Todoist | GitHub | Classification |
| --- | --- | --- | --- | --- |
| Verify exact action and project bounded command | same mechanism | same mechanism | same mechanism | identical; existing SDK owner |
| HTTPS method/origin/path/body template | fixed PATCH/JSON | fixed POST/form carrying bounded JSON | fixed POST/JSON | identical *construction grammar*, different approved literals |
| Credential custody and entry ordering | bearer after claim | bearer after claim | bearer after claim | analogous; reuse connection/stage contracts only after type review |
| Preflight | expected-old-value read | none in current demo | repo/policy eligibility is not a generic read | divergent |
| Response evidence | field read-back | Sync mapping plus task read | created issue response and possible issue read | divergent |
| Retry/unknown | no blind retry | Sync UUID semantics need review | issue POST duplication risk needs review | divergent |
| Receipt claim | app observation | app observation | no trial receipt | divergent; no shared qualified receipt |

## Attempt-state comparison and claim-store decision

The SDK's Python and TypeScript `AttemptStore` contract has `claim_once`,
`read`, and `finish` operations. Its stages are `attempting`, `confirmed`,
`rejected`, and `unknown`; `confirmed` means the *application adapter* reported
acceptance. This is useful local reference behavior, not an effect witness or
a multi-host credential gate. Its file-backed implementation is single-host.

The sealed `auths-lifecycle` `LifecycleStore` instead transacts durable lifecycle
events. Its authorization witnesses require persisted `CredentialAuthorized`
and `ProviderCallEntered` stages, and its `Committed` state follows a recorded
provider-result transition. An SDK `confirmed` cannot be projected into
`Committed`: adapter acceptance is weaker than the effect evidence a lifecycle
commit is meant to represent. Nor does an HTTP response alone establish that
transition. The contracts compare as follows:

| SDK `AttemptStore` | Sealed lifecycle relation | Gateway decision |
| --- | --- | --- |
| `claim_once` → `attempting` | `ExecutionIntentRecorded` and then `Executing` require distinct durable events; `ProviderCallEntered` is another event | Atomic claim is necessary but is not a lifecycle transition projection; record entry separately. |
| `finish(..., confirmed)` | `Committed` requires fresh domain evidence proving the exact effect | No projection; a complete HTTP response is only `response-recorded`. |
| `finish(..., rejected)` | `Released` requires evidence of definite non-effect or permitted pre-attempt cancellation | No projection from an adapter's rejection label; preserve the exact evidence and stage. |
| `finish(..., unknown)` | `OutcomeUnknown` holds reservations and permits domain-specific reconciliation | Analogous ambiguity, but not equivalent lifecycle state or reservation contract; gateway `unknown` forbids automatic retry. |

The gateway therefore retains AP-SPEC-053's own
`not-entered | attempting | response-recorded | unknown | observed` evidence
stages. `response-recorded` means a complete bounded HTTP response was stored
without separate read-back; `observed` requires completed read-back and records
match or mismatch without asserting causation; ambiguity is `unknown`. These
are not aliases for SDK `confirmed` or lifecycle `Committed`. Whether a later
implementation adds a lifecycle event or keeps a distinct gateway stage record
must be decided from an exact transition proof; no silent state projection is
allowed.

The current `PostgresLifecycleStore::transact` takes a singleton metadata-row
`FOR UPDATE` lock and loads the full database snapshot on each transaction.
That is a known serialization and scaling limit, **not** evidence of a
scalable multi-host gateway replay-claim store. Epic 3 needs an atomic durable
`(operator_namespace, logical_operation_id)` uniqueness/claim design with
measured contention and restart behavior before making a scale claim.

## Three closed recipes and expected decisions

These are spec fixtures, not executed gateway operations. Each action includes
the approved recipe digest, operator namespace, and logical operation ID in
verified bytes. The operator pins the origin, connection/account, credential
generation, trust, and every fixed literal. Each write uses only verified
bounded scalar fields; the request compiler supplies framing and encoding.
For every valid first submission, the proof verdict is `authorized`; the
gateway records `attempting` after its durable replay claim and may enter one
write transport. A complete bounded HTTP response produces
`response-recorded`, **regardless of status**. It does not establish effect.

| Fixture | Closed write and verified fields | Optional observation | Expected decision after a complete HTTP response |
| --- | --- | --- | --- |
| Airtable `set_demo_status_v1` | `PATCH https://api.airtable.com/v0/<fixed-base>/<fixed-table>/<record_id>`; JSON `{"fields":{"DemoStatus":<replacement>}}`; bounded `record_id` and `replacement` | One GET of the same fixed record path; project `fields.DemoStatus` and compare to verified `replacement` | `authorized + response-recorded`; after a completed read-back, `observed(match)` or `observed(mismatch)`, never “write succeeded” |
| Todoist `create_task_v1` | `POST https://api.todoist.com/api/v1/sync`; form `commands` is compiler-serialized bounded JSON containing exactly one `item_add` with verified `command_uuid`, `temp_id`, `content`, and `description`; no caller JSON, project, or extra command | None in the first shared recipe; Sync mappings and task lookup remain provider-owned | `authorized + response-recorded`; no `observed` or task-created claim |
| GitHub `create_issue_v1` | `POST https://api.github.com/repos/<fixed-owner>/<fixed-repo>/issues`; JSON with only bounded verified `title` and `body` | None in the first shared recipe; response issue number and later lookup remain provider-owned | `authorized + response-recorded`; no `observed` or issue-created claim |

For the Airtable fixture, an unavailable GET leaves a previously recorded
write response at `response-recorded`, with observation `unavailable`; if the
write entry itself was ambiguous, the attempt remains `unknown`. An exact
read-back match is observation only, not exclusive causation or retry
permission. The Todoist and GitHub fixtures deliberately stop at response
recording because interpreting Sync mappings or response-derived issue IDs
would add provider semantics absent from the first shared AST.

| Hostile fixture (apply to all three unless named) | Expected proof verdict, gateway stage, and provider entries |
| --- | --- |
| Native verifier returns `denied` for altered proof/action, or `indeterminate` for unavailable trust | Preserve that verdict; `not-entered`; zero entries. Never use testkit trust. |
| Valid proof but wrong recipe digest, namespace outside the installed operator binding, inactive connection, or wrong credential generation | Proof remains `authorized`; gateway refuses at `not-entered`; zero entries and no credential lease. |
| Same `(namespace, logical_operation_id)` submitted again with a fresh proof challenge, changed body, changed recipe, or concurrent racing submission | At most the first claim can enter; all later submissions are `not-entered` replay refusals with zero additional entries, regardless of proof challenge or digest. |
| Runtime URL/host, HTTP method, extra header (including `X-*`), raw body, dynamic body key, or unbounded value supplied outside the verified action/approved recipe | Compile or submission refusal at `not-entered`; zero entries. Operator approval cannot widen the first-version header allowlist. |
| Airtable replaces fixed `DemoStatus` key or fixed base/table; Todoist adds a second Sync command or caller-supplied JSON string; GitHub adds labels/assignees or substitutes a repository | Recipe mismatch or compile refusal at `not-entered`; zero entries. A new operator-approved recipe digest and new proof are required for a deliberate change. |
| Crash after claim, with only a constructed request or absent local entry log | `unknown`; no automatic second write. Only a durable checkpoint excluding even in-flight transport entry may establish `not-entered`. |
| Entered transport times out, disconnects, or returns an incomplete response | `unknown`; no automatic retry, including after a read-back mismatch or unavailable observation. |
| Complete bounded 2xx, 4xx, or 5xx response, without completed read-back | `response-recorded`; never `confirmed`, `Committed`, or proof of effect absence/presence; no automatic retry. |

## Versioning, tests, and cutover

The proposed AST and compiler need a versioned canonical representation.
Changing a recipe, mapping, field list, or order-sensitive bound changes its
digest and requires renewed operator approval and a newly authorized action.
An old action must not run against the new recipe. Prelaunch cutover rejects
old disposable recipe state; it adds no legacy reader, dual write, or runtime
rollback path.

Required executable evidence before extraction: three canonical recipes and
hostile substitutions of origin, path, header, body, digest, logical
operation, and credential generation; denial-before-credential; claim races;
crash at every stage; bounded parser/template property tests; cross-language
canonical vectors; and a test proving a changed recipe invalidates the old
action. Retain the existing Airtable and Todoist adapters as provider-semantic
references. GitHub remains an unexecuted design comparison at this gate.

## Performance and composition

No performance measurement exists yet. Before implementation is accepted,
measure parse/compile size and time, template substitution worst-case work,
claim latency, bounded response handling, and the overhead relative to one
provider request. Hard limits must be enforced before allocation or I/O.

Composition of the current verifier, local `AttemptStore`, and developer
adapter cannot isolate a credential from the application that holds it. The
smallest new primitive worth considering is therefore the separate process
with a closed request interpreter and operator binding. Existing verifier,
connection, and lifecycle primitives should be reused where their exact
invariants fit; a second authorization engine is not justified.

## Code that remains operation-owned

The developer or reviewed vertical retains provider-specific request
approval, account/scope choice, precondition meaning, response interpretation,
observation, reconciliation, and any provider-effect claim. The gateway must
not absorb those as executable callbacks. If any of the three examples needs
one to fit, it remains self-hosted or a reviewed vertical.
