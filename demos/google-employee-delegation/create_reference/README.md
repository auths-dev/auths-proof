# Google Drive create reference for AP-SPEC-071

This is a **synthetic request-shape reference**, not a live create or a
qualified installation. The generated [profile lock](profile.lock.json) and
[recipe](recipe.json) use the same provider-neutral gateway write compiler as
the Google Docs edit and Airtable references. The action signs one Project A
parent ID, title and opaque recovery marker under a task ID and task-card
commitment. The recipe fixes `POST /drive/v3/files`, the
`supportsAllDrives=true` query, Google Docs MIME type, one parent and one
public file property carrying the marker. The agent supplies no URL, query,
JSON shape or credential. The task gate must independently confirm that the
signed parent is the human-approved folder and that the connected Google
subject and generation match the task.

The marker is an opaque run identifier, not a secret or permission. It is
visible to other applications through Drive's `properties` field and can
support an independently checked search after a lost create response. A
matching search is **not** proof that no duplicate exists, and this recipe
contains no idempotency claim. Any ambiguous create remains unknown and is
never retried automatically. Google documents the metadata endpoint,
`supportsAllDrives` parameter and `drive.file` scope in its
[files.create reference](https://developers.google.com/workspace/drive/api/reference/rest/v3/files/create),
and the [property guide](https://developers.google.com/workspace/drive/api/guides/properties)
describes visibility and search.

For the first Atlas run, Auths and demo_co agreed on the exact title
`Auths AP-071 Project A handoff`, property key `auths_operation_marker`, and
a fresh marker value shaped as `ap071_` plus 32 lowercase hex characters.
The profile permits the signed title and marker as arguments so the same
gateway grammar stays provider-neutral; the operator-side Atlas handoff must
enforce this fixture-specific title and marker format before Jules approves.
The [read-only producer observation consumer](../broker/src/employee_read_demo/google_create_handoff.py)
checks demo_co's versioned create observation against exact private run pins.
It reports only provider state; Auths has not yet bound a returned child ID to
the signed create action or authorized population. The producer's inspector
requires a fresh pre-create working-Doc baseline and leaves cleanup explicit.

This reference does not bind a returned file ID to the task, authorize a
follow-up populate action, inspect the create response or verify a provider
effect. Those are required by AP-SPEC-071's create/populate acceptance and
will need reviewed generic response binding plus independent demo_co
inspection. The producer owns the folder and its ACL; Auths owns the task
authority and gateway recipe. The Rust test proves only the exact closed
request body and URL from synthetic signed fields.
