# Google Docs populate reference for AP-SPEC-071

This is a synthetic, task-bound request-shape reference. It does not submit a
live Google write or qualify a provider installation. The generated profile
and reviewed recipe close one `POST /v1/documents/{bound-child-ID}:batchUpdate`
with a single `insertText` request at the end of the freshly observed tab and
`writeControl.requiredRevisionId`. The agent signs the task, operation,
recipe digest, child ID, tab ID, exact text and required revision. The compiled
request supplies the URL and JSON structure; no caller can add a second
subrequest or choose a different location through this profile.
The recipe's `task_populate` declaration identifies the three fields whose
values must come from the signed content plan and fresh child preflight:
`text`, `tab_id` and `required_revision_id`. The common compiler rejects
another profile field that could affect this planned provider request.

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

The preflight accepts the blank structure observed on the first live child:
one section break ending at index 1, followed by one paragraph at indexes
1–2 containing only a terminal newline. The narrow parser also retains its
single-paragraph synthetic case. It rejects other body elements and text.
This structural check must run on a fresh Jules read before entry; an admin
read is diagnostic evidence only. The recipe uses `endOfSegmentLocation` and
never assumes a numeric insertion index.

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
operation are refused before provider entry. The private task journal can
record a native human effect plan with the exact initial text commitment,
populate recipe and operation before create reservation. Planned population
requires an installed preflight signer pin, a fresh signed Jules child
preflight and a still-valid plan. The first live create reached Google before
an incomplete installation and short plan lifetime were found; the child
remains blank. A fresh authorization for only the remaining effect is
required. No live populate effect or independent populated-child verdict has
yet been obtained for this reference.

Before a **new** paired run, the operator uses
`python -m employee_read_demo.task_populate_setup --base-installation BASE --seed-out PRIVATE_SEED --installation-out PRIVATE_PINS`
on the reviewed two-recipe installation input. The command creates one mode
0600 Ed25519 seed and a canonical installation with its public key and a
digest of the installed Google preflight implementation. Pass `PRIVATE_PINS`
to `auths-gateway task-configure` **before** offering the task card. Keep the
seed in operator custody and pass it only to the private preflight command.
The signer checks that its current code digest matches the installed pin;
code changes require a fresh disposable paired run. The first live task's
missing pin cannot be added retroactively to its already recorded plan.

For the interrupted first run, the development workbench can accept a
private `--task-write-created-child` pin. It prepares a **new** task with one
static edit scope on the already bound child, no create and no read release.
The pin fixes the child metadata and the SHA-256 and byte count of the
previously signed complete draft. During exact review, the broker refreshes
Jules's subject, metadata, `canEdit`, blank tab and revision; it compares the
agent's signed text and target to those pins before asking for a new human
signature. This continuation is a demo recovery path. It neither extends the
expired two-effect plan nor qualifies the original single-plan journey.
