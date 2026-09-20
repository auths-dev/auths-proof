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
idempotency rules, status-to-effect mapping, pagination, read-back equality,
reconciliation, qualified receipts, and exactly-once external effects. These
cannot be supplied by a universal response callback or arbitrary JSON rule.

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
