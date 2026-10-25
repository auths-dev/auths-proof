# Google Docs populate reference for AP-SPEC-071

This is a synthetic, task-bound request-shape reference. It does not submit a
live Google write or qualify a provider installation. The generated profile
and reviewed recipe close one `POST /v1/documents/{bound-child-ID}:batchUpdate`
with a single `insertText` request at the end of the freshly observed tab and
`writeControl.requiredRevisionId`. The agent signs the task, operation,
recipe digest, child ID, tab ID, exact text and required revision. The compiled
request supplies the URL and JSON structure; no caller can add a second
subrequest or choose a different location through this profile.

The profile limits inserted text to 192 UTF-8 bytes because the native action
profile has a 4 KiB worst-case canonical-argument bound. This is enough for a
short handoff draft, not a general document-authoring limit. Google describes
`insertText`, tab-specific end-of-segment locations, and revision-guarded batch updates in its
[request reference](https://developers.google.com/workspace/docs/api/reference/rest/v1/documents/request#InsertTextRequest)
and [batchUpdate reference](https://developers.google.com/workspace/docs/api/reference/rest/v1/documents/batchUpdate).

demo_co checked that Jules's existing subject-bound `drive.file` grant can
read a revision and single tab from its app-created Project A probe Doc and
has previously used Docs batchUpdate on that probe. For a newly created Auths
child, the Jules-bound broker must freshly call Docs `documents.get` with
`includeTabsContent=true`, require one top-level tab with no children and a
bounded revision and tab ID, and confirm Drive `capabilities.canEdit=true`
for that exact child. A stale revision or unknown populate response requires
reconciliation; no silent retry or rebase is allowed.

The preflight also accepts only a single blank paragraph with one terminal
newline and consistent provider-returned indexes. demo_co did not retain the
probe's pre-insert body structure, so this narrow parser is a fail-closed
assumption for the first live child. If a fresh Jules read returns another
shape, capture only its redacted structural summary and review the parser
before entry. The recipe uses `endOfSegmentLocation` and never assumes a
numeric insertion index.

`google_create_preflight.py` now joins these parsers with the existing
subject-checked Jules token lease and three bounded, redirect-free GETs:
child metadata, exact-child `canEdit`, then Docs tabs/revision. A synthetic
test verifies the request order and refusal when the child leaves the pinned
folder. The result also carries the checked Jules connection ID, generation,
subject and SHA-256 digests of the three exact provider response bodies for
later private evidence binding. These fields are observations, not a signed
gateway preflight or agent authority. The caller still must obtain the child ID from Auths's durable binding
after native admission; this helper neither binds it nor sends a write.

The human-signed task card names the populate recipe digest but contains no
arbitrary child ID. Only a child ID durably bound after the reserved create and
credential-bearing metadata observation can become a one-time edit scope in
the shared task journal. A different ID or digest and a second population
operation are refused before provider entry. The exact human confirmation
for this second action is still required by the current gateway path. The
private task journal can now record a native human effect plan with the
exact initial text commitment and this populate recipe and operation before
create reservation. The exact create can consume that recorded plan without a second signature.
The current submission path does not yet consume the plan for population
admission, so a second exact confirmation remains required. No live provider effect or independent demo_co verdict
has yet been obtained for this reference.
