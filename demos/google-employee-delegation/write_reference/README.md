# Google Docs edit reference for AP-SPEC-071

This is a **synthetic request-shape reference**, not an installed Google
write or a producer fixture. The generated [profile lock](profile.lock.json)
and [recipe](recipe.json) compile through the existing, provider-neutral
`auths-gateway` write recipe compiler. The focused Rust test constructs the
exact `POST /v1/documents/{document_id}:batchUpdate` request and checks its
bounded JSON body. The recipe has no provider-specific production code.
Its `field-suffix` path segment is a closed, operator-visible mechanism under
[ADR 0018](../../../docs/adr/0018-typed-path-field-suffix.md); a compiled
reference is not production qualification.

The v2 action includes the signed task ID and task-card commitment, then names
one document, one tab, one unique literal marker, replacement text and the
revision Jules observed near confirmation. The recipe fixes a
single, case-sensitive `replaceAllText` request with `searchByRegex: false`
and `writeControl.requiredRevisionId`. Its body admits no second request,
runtime URL, arbitrary JSON object or alternative write control. The signed
Auths task and exact human confirmation must bind these action fields, the
connected Jules subject/generation and the recipe digest before the gateway
may use a credential. A valid recipe by itself grants no access.

The generated action profile's conservative 4 KiB canonical-argument bound
limits document IDs to 64 bytes, tab IDs to 16 bytes, the marker to 48 bytes,
replacement text to 192 bytes and revision ID to 128 bytes. The task and
operation IDs are each limited to 32 bytes. demo_co must export the
**observed** lengths from a new run-owned, single-tab working Doc and refuse
unsupported lengths rather than truncating or substituting an ID. Existing
Atlas Docs have 44-byte file IDs, but that does not establish the future
working Doc or revision lengths.

Google's [batchUpdate reference](https://developers.google.com/workspace/docs/api/reference/rest/v1/documents/batchUpdate)
defines `requiredRevisionId`; its
[request reference](https://developers.google.com/workspace/docs/api/reference/rest/v1/documents/request#ReplaceAllTextRequest)
defines tab-scoped `replaceAllText`. A stale required revision refuses the
write at Google. The present gateway records a complete response status and
digest, but does **not** inspect `replies[0].replaceAllText.occurrencesChanged`.
It also cannot prove the provider honored the write-control semantics from
the JSON shape alone. Before the live edit milestone, a reviewed generic
response assertion must record the count of exactly one without exposing the
private response body, or the installed test must obtain equivalent
provider-signed response evidence. demo_co must independently compare the
working Doc's revision and content after entry and verify that canonical and
excluded Docs did not change. A 2xx response alone is not an observed edit.

The v2 recipe declares a provider-neutral `task_binding` for its document field
and edit verb. The gateway refuses ordinary proof/action submission for this
recipe before any claim or lease. Its crate-internal task-aware path verifies
the signed card, agent action and exact confirmation, charges the durable task
write budget, and binds the loaded connection ID, generation and account
subject before a credential lease. An installed task channel and operator
pins are still required for live use. The broker can privately refresh and
verify Jules's separate `drive.file` grant, but that lease is not yet installed
as a subject-bound Auths gateway write connection. Her saved read-only grant
is insufficient.
demo_co owns the folder, working Doc, ACL, consent probes and versioned export;
Auths owns authority, connection custody, recipe admission and receipts.
The [write handoff shim](../broker/src/employee_read_demo/write_handoff.py)
validates a digest-pinned producer generation and its independent probes but
stays `write_not_configured` until the installed Auths task gate, credential
lease, fresh preflight and independent post-write inspection are wired.
The broker's read-only [Google preflight](../broker/src/employee_read_demo/google_write_preflight.py)
checks the current Jules subject, working Doc ACL, one tab, revision and exact
baseline before an edit proposal; it has passed against the private Atlas
generation and does not perform a write.
