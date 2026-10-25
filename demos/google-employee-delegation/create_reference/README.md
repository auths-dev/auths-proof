# Google Drive create reference for AP-SPEC-071

This is a **synthetic request-shape reference**, not a live create or a
qualified installation. The generated [profile lock](profile.lock.json) and
[recipe](recipe.json) use the same provider-neutral gateway write compiler as
the Google Docs edit and Airtable references. The action signs one Project A
parent ID, title and opaque recovery marker under a task ID and task-card
commitment. The recipe fixes `POST /drive/v3/files`, the
`fields=id` and `supportsAllDrives=true` queries, Google Docs MIME type, one parent and one
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
`prepare_create_inputs` in the broker handoff module checks the pinned parent
and generates a fresh 128-bit marker; the future task ceremony must sign and
persist those values before any provider call.
The gateway recipe now declares one bounded `created_child` mapping for the
complete successful response's `/id`. Its reviewed observation GET uses that
candidate ID and fixed `fields=id,name,mimeType,parents,driveId,properties,trashed,createdTime`
and `supportsAllDrives=true` queries. A recorded response retains the
candidate across a gateway restart. The reviewed metadata checks compare the
GET response's ID, title, sole parent, public marker, MIME type, shared-drive
ID and trash state to the response candidate, verified create fields and
operator-pinned literals. A mismatch cannot become a matched observation.
After a matched credential-bearing observation under the task-write path, the
gateway now commits one immutable child binding in the task journal. It ties
the candidate ID to the reserved create operation, request and response
digests, metadata digest, signed pending-child proposal, and connected subject
and generation. This still grants no populate authority; the second action
must check that binding before provider entry.
The generic `reobserve` path refuses this create recipe after restart because
its stored plan does not retain the native-verified parent, title and marker;
allowing a later name-only match would bypass the metadata checks. The
candidate ID remains in the private attempt journal for a future verified
reconciliation path.
The broker's test-only Google metadata oracle now defines the exact `files.get`
request and rejects mismatched child ID, name, MIME type, sole parent, shared
drive, public marker, trash state or creation time. It does not call Google or
issue Auths authority. The connection's Jules subject must be checked from
the credential broker, not inferred from file metadata.

The [read-only producer observation consumer](../broker/src/employee_read_demo/google_create_handoff.py)
checks demo_co's versioned create observation against exact private run pins.
It reports only provider state; it cannot authorize population or replace the
gateway's own task binding. The producer's inspector
requires a fresh pre-create working-Doc baseline and leaves cleanup explicit.

This reference does not authorize a follow-up populate action or verify a
live provider effect. Those are required by
AP-SPEC-071's create/populate acceptance. The producer owns the folder and
its ACL; Auths owns the task authority and gateway recipe. Rust tests prove
the exact closed request and observation URLs, hostile declaration rejection,
bounded response extraction and durable candidate recording with synthetic
data; they do not establish a live provider effect.
