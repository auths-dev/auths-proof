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

This reference does not bind a returned file ID to the task, authorize a
follow-up populate action, inspect the create response or verify a provider
effect. Those are required by AP-SPEC-071's create/populate acceptance and
will need reviewed generic response binding plus independent demo_co
inspection. The producer owns the folder and its ACL; Auths owns the task
authority and gateway recipe. The Rust test proves only the exact closed
request body and URL from synthetic signed fields.
