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

## AP-SPEC-063 capability comparisons

[AP-SPEC-063](../../../specs/0063-generalized-gateway.md) proposes ten recipe
capabilities and a sum budget; [ADR 0013](../../../adr/0013-recipe-capabilities-and-sum-budget.md)
records the decision under review. This section is the written comparison
the boundary plan requires before each extraction. Each table compares the
existing consumers with the proposed recipe form, field by field, and
classifies each field as identical, analogous, or domain-specific. Only the
identical subset is extracted; the rest stays with the recipe author or the
vertical. "Vertical" means `product/integrations/auths-stripe` unless a row
names another consumer. The vectors for every capability are in
`bindings/fixtures/gateway/` (`hostile-recipes-v2.json`,
`attempt-scenarios-v3.json`, `bounds-aggregate.json`, `outcome-v2.json`,
`key-identity.json`, `codes.json`), and tests in
`product/runtime/auths-gateway/src/pending_vectors/` show that current code
does not satisfy them.

Every capability shares four facts, not repeated below. Its checks run at
the step AP-SPEC-063 §5.5 assigns, and none leases a credential before the
durable claim. Its state, if any, is one value in attempt record `/3` or one
slot, written under the store's compare-and-swap or `insert_all`, so its
concurrency and crash behavior are those of the claim. It never licenses a
second write. Its prelaunch cutover replaces recipe source `/1` with `/2` and
rejects old recipes, with no legacy reader.

### Provider version headers

| Field | Consumers today | Recipe form | Class |
| --- | --- | --- | --- |
| Representation | `Stripe-Version` from the exact action (`auths-stripe`); fixed `X-GitHub-Api-Version: 2022-11-28` (`auths-github` `adapters.rs`) | `provider_headers`, at most two registry names with a value grammar | identical mechanism, different literals |
| Meaning | Which provider API contract applies | The same; the gateway does not know it | domain-specific |
| Denial and indeterminate | Stripe: a missing or different response header makes the write outcome possible, not known (`bounded_provider_result`); GitHub: responses unchecked | A mismatched read is unavailable; a mismatched write is recorded and only its locator is suppressed | analogous: the recipe never turns a write into `unknown` for a header, because the gateway interprets no write body |
| Limits and work | One header per request | At most two headers, 10–64 bytes for Stripe, 10 for GitHub | identical |
| Credential timing | Sent with the credential | Sent on every request to the origin, credential reads included | identical |
| Evidence and UX | Not recorded | Shown in review `/2` | analogous |

### Credential-mode guard

| Field | Consumers today | Recipe form | Class |
| --- | --- | --- | --- |
| Representation | `rk_test_` prefix, 16–256 printable bytes (`valid_static_secret`); `/v1/account` with `object`, `id`, and `livemode` checked together (`verify_account_response`) | `credential.guard`: 1–4 prefixes; an optional probe with one pointer and one literal | identical prefix test; the vertical's combined account and mode read splits into the probe and the account read |
| Meaning | Test mode only | Whatever the author's convention is | domain-specific |
| Denial and indeterminate | Onboarding refused; lease refused on a wrong prefix | Onboarding refused with nothing stored; a lease-time prefix failure records `gateway.credential.mode-guard` | analogous |
| Limits and work | One onboarding read | One probe at onboarding within a 20-second deadline; no probe at lease | identical |
| Credential timing | Onboarding, then prefix at every lease | The same | identical |
| Evidence and UX | Not recorded | Shown in review; codes only | analogous |

### Idempotency declaration

| Field | Consumers today | Recipe form | Class |
| --- | --- | --- | --- |
| Representation | `auths-refund-` plus SHA-256 over the exact action, including its nonce (`IdempotencyPreimage`); the bounded path's key from the operation ID; Todoist's `uuid` equal to the operation ID | `write.idempotency`: #156's derived header, or the location of the verified operation ID in the body, plus a retention | analogous: the gateway key ignores the action commitment, so re-authorizing one logical operation reuses one key; the vertical's primary key changes with the nonce |
| Meaning | The provider de-duplicates within its retention | Declared by the author; unverifiable by the gateway | domain-specific |
| Denial and indeterminate | None | An action whose window plus 60 seconds exceeds the retention is refused before the claim | new, narrower |
| Limits and work | One header | One header, or none; retention 1–2 592 000 seconds | identical |
| Provider effect and observation | Never resolves `unknown` | Never resolves `unknown` or licenses a second entry | identical |
| Evidence and UX | Not shown | Review states that the gateway cannot verify the provider honors it | analogous |

### Response locator

| Field | Consumers today | Recipe form | Class |
| --- | --- | --- | --- |
| Representation | The refund ID from the create response, read back at `/v1/refunds/<id>` (AP-SPEC-012 §14); GitHub's issue `number` (this case, a design only) | A `response-field` observation segment: one pointer, `max_bytes` 1–255, at most two per path | identical: one bounded value in one encoded segment |
| Meaning | The created object's address | Not interpreted | domain-specific |
| Denial and indeterminate | An absent ID leaves the result unobserved | Only a complete 2xx JSON response inside 65 536 bytes yields a locator; otherwise no read-back | identical |
| State | Provider-owned | Only the value is stored, never the body | identical |
| Provider effect and observation | Read-back only after a response | `linked-after-response`: after `unknown` the locator is lost, and the attempt stays `unknown` | identical |
| Evidence and UX | Vertical receipt | Review shows `response-locator` | analogous |

### Form echo

| Field | Consumers today | Recipe form | Class |
| --- | --- | --- | --- |
| Representation | Author-supplied `metadata[<key>]` form fields from the exact action (`local_agent.rs`); AP-SPEC-059's token only in JSON bodies (`echo_token`) | `echo.write` as one new form field, `name` or `name[segment]`, added by the compiler | identical token, new placement |
| Meaning | Vertical metadata is author data, not an action-derived link (settled.md) | The token shows consistency with this action, not authorship | domain-specific for the vertical's metadata; identical to 059 for the token |
| Limits and work | Form fields bounded by the action | At most 16 form fields including the echo | identical |
| Provider effect and observation | None | Observation reads the token at the declared pointer (059) | identical to 059 |
| Evidence and UX | None | 059's disclosure in review | identical to 059 |

### Pre-entry re-read

| Field | Consumers today | Recipe form | Class |
| --- | --- | --- | --- |
| Representation | Evidence read before verification and re-read after the seal, before the credential (AP-SPEC-012 §13); agent-attached gateway read-backs (`observed_tests.rs`) | `pre_entry`: one path, 1–4 pointers | analogous: the re-read moves after the lease, because it needs the credential |
| Meaning | Profile-specific preconditions | The grant's own AP-SPEC-060 requirements, re-evaluated | identical predicates (`observation_conditions_hold`, `requirement_verdict`) |
| Denial and indeterminate | Stale or conflicting evidence refuses | A false condition dominates (`gateway.pre-entry.condition-false`); anything else is `gateway.pre-entry.unavailable` | identical to 060 |
| Credential timing | Before the credential | After the lease, before the write; refused before the claim without an observer key | analogous |
| Provider effect and observation | Not conditional | Not conditional; the window narrows to the re-read-to-write interval | identical |
| Evidence and UX | Vertical evidence digest | Signed observations and `pre-entry-digest` in the outcome | analogous |

### Relative ceiling

| Field | Consumers today | Recipe form | Class |
| --- | --- | --- | --- |
| Representation | `RelativeRefundLimit`: basis points 1–10 000 and a closed denominator enum (charge, captured, remaining refundable) in each policy (`bounded.rs`) | `relative_ceiling`: basis points 1–10 000 in the recipe, a pointer, an optional subtracted pointer, and 0–2 binds | analogous: the enum becomes a declared pointer; the ratio moves from the policy to the recipe |
| Meaning | Share of the payment evidence | The author's; not interpreted | domain-specific |
| Denial and indeterminate | `u64` checked multiplication, `ArithmeticOverflow` denial, floor division, then the minimum of absolute, relative, and refundable ceilings | `u128` comparison that cannot overflow; floor semantics identical; `above`, `binding-mismatch`, or `unavailable`; a negative difference is unavailable | identical boundary semantics; the overflow code has no gateway equivalent |
| Limits and work | One evidence read | One read of at most 65 536 bytes per submission | identical |
| Credential timing | Evidence before the credential | After the lease; a refusal consumes the operation ID and its slots | analogous, narrower (reading 13) |
| Evidence and UX | Vertical receipt | `relative-basis` and its digest in the outcome; audit re-checks the comparison | analogous |

### Account binding at every lease

| Field | Consumers today | Recipe form | Class |
| --- | --- | --- | --- |
| Representation | `/v1/account` `id` equal to the descriptor at onboarding; a local descriptor lookup by `account_commitment` at every lease | `credential.guard.account`: one path and pointer; the value hashed under `auths.gateway-account/1` | identical commitment comparison |
| Meaning | The Stripe account | Not interpreted | domain-specific |
| Denial and indeterminate | `AccountSubstitution` | `account-mismatch` for a valid different value, `account-unavailable` otherwise | identical split |
| Credential timing | Provider read at onboarding only | Provider read at onboarding and at every lease, read-backs included | narrower: stronger check, one read per lease |
| Evidence and UX | Not recorded | Code only; a credential read never enters the attempt record | identical |

### Denied reads

| Field | Consumers today | Recipe form | Class |
| --- | --- | --- | --- |
| Representation | None: `valid_static_secret` and `lease_credential` check only the prefix; AP-SPEC-012 §13 asks for a restricted key without a check | `credential.guard.denied_reads`: 1–4 fixed-path GET or HEAD requests with 1–3 refused 4xx statuses, never 408 or 429 | new mechanism with no vertical implementation |
| Meaning | Least privilege, asserted | Only the refusals observed at that lease | narrower claim |
| Denial and indeterminate | — | `capability-excess` on a 2xx; `capability-unavailable` on anything else, including a version mismatch | new |
| Limits and work | — | Up to four reads per lease; bodies discarded after 16 384 bytes | new |
| Credential timing | — | Onboarding and every lease, after the account read | new |
| Evidence and UX | — | Code only | new |

### Account-scope headers

| Field | Consumers today | Recipe form | Class |
| --- | --- | --- | --- |
| Representation | `ConnectScope` (`PlatformOnly` or listed accounts) in the policy; `MerchantConnectAccount` in merchant actions; the account in the exact action | `account_scope`: one registry header and one profile field; the values in each bounded link's policy `/2` scope | analogous: platform scope needs a recipe without `account_scope` (reading 19) |
| Meaning | Stripe Connect account context | Not interpreted | domain-specific |
| Denial and indeterminate | Account outside the policy denied | `scope-denied`, `account-scope.unbound`, or `invalid-value`, before the claim | identical membership test |
| Credential timing | Every read and the mutation in that context | The write and every action read; never a credential read (reading 20) | analogous |
| Evidence and UX | Vertical receipt | Review shows the header and its field | analogous |

### Sum budget

| Field | Consumers today | Recipe form | Class |
| --- | --- | --- | --- |
| Representation | `AggregateRefundBudget`: budget ID, currency, limit, and a fixed or rolling window, per policy | Policy `/2` members 4–6; one sum counter per link subject, partition value, and fixed window | analogous: per link rather than per policy, so delegates share their ancestors' sums |
| Meaning | Refund amount per currency | Sum of the verified argument per listed partition value | domain-specific meaning, identical arithmetic |
| Denial and indeterminate | Exhausted budget denied | `above-sum-limit` and `partition-denied` before the claim; `sum-exhausted` recorded with the claim | identical |
| Limits and work | Per-policy state | One binary search and one load per sum counter, at most 32 inserts | identical bound shape |
| State | Held while unknown; released on proven non-effect or reconciliation | Never released, even on `not-entered` (reading 17) | narrower |
| Concurrency and crash | Vertical ledger | `insert_all` with the claim, all or none, on both stores | identical to the count slots |
| Evidence and UX | Vertical receipt | `counters-digest` in the outcome; the audit's order-free sum test | analogous |

### What stays operation-owned

The recipe author, or the vertical as a test-only reference under §12 option
A, keeps: which header values, prefixes, probe literals, basis pointers,
refused statuses, ratios, and retentions a provider needs; what each means;
release of sum capacity on provider evidence; rolling windows; and every
provider-effect claim. None of these can be supplied to the gateway as code.
