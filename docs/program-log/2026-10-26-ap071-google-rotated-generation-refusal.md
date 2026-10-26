# AP-071 installed Google write-generation refusal, 26 October 2026

This is a live negative run on the source-free Google bundle, manifest SHA-256
`6208d943c0a03999f4881a14449d09cca506c4c095e48eed60561fa6b904da7a`,
with gateway executable SHA-256
`a20fd28c5a7a8c3a96d2bd1a6b3fd9c30dfdcd88466657395cff293a95bf10a7`.
It tests a changed installed **write credential generation** after Jules signs a
task and exact two-effect plan. It does not replace Jules's Google subject or
withdraw her Google access.

demo_co prepared a new disposable scratch run
`ap071-rotate-v2-acfe28787a7ac54f`, folder
`1VsO-rgihON_lXV3h7e6gop-TXcBd2TXx`, marker
`ap071_87cd03fd7bcbf3666abfdf83ac17dd43`. Its setup report was
generation 0058, SHA-256
`3495ef53ba5269c9386fea3da54374b95f21bd685802c762487609d03282a18e`.
The setup created only the run folder, not a child Doc.

Jules signed task `ga0DHCIjX2B3KZnFHvrfVDhA` for the distinct registered
agent; the task-card SHA-256 is
`1e29da817fb5ee7ecb65196e40f6190d6114f28e32a493daf85df0945ab99b6e`.
The installed write connection was `conn_0H7c3kEcAV7xiFiyssYCNQ`, generation
1. The isolated agent signed the selected Project A read operation
`R_8Z83VsOXO9oLrCK5C7-yg6R2`, received and acknowledged the exact 51-byte
source, and signed a source-backed draft and create operation
`dcxv5UsIMXAAwwF-b8YAoAg0`. Jules reviewed and signed its complete
create/populate plan, SHA-256
`0ff83cd082936a13508048001570e08efd4934f934738d1c0df865ddd5925971`.
At that point the task had one charged provider read, one release, 51 released
bytes and **zero writes**.

demo_co took a read-only populated-Doc baseline before the rotation,
generation 0059, SHA-256
`a5e2003860fc90191718017149a807d5ea3b410d2401ef18cb58fd95f4f3e80a`.
Auths then published generation 2 for that same installed write connection
using its existing opaque source reference. The connection floor and credential
journal show generations 1 and 2. Submitting the agent's originally signed
create under the recorded Jules plan returned
`not-entered / gateway.task.connection-changed`. Task counters remained at
one provider read, one release, 51 released bytes and zero writes; the gateway
recorded zero write attempts. The task was revoked after the refusal. The
owner-private redacted Auths report at
`/private/tmp/ap071-rotation-live-20261026/redacted-rotation-result.json` has
SHA-256 `0a5a6c6b93455d0f2dc7e007f6471ad0fc6f8e75c54af48a0b1542e49f62acae`.

demo_co's read-only after inspection returned
`unchanged_after_revocation_attempt`, generation 0060, SHA-256
`e0efe2bbdd7fe75e68123d0f4bdbe98b2a5f45ec9fcf6af033abb1ebc1945e0b`.
It compared the previously populated child, source, siblings and current
inventory to generation 0059; the exact populated export remained 148 bytes
with SHA-256
`a1fb0c3010e622cee1ac5f85bda4c9865194f2e84bba36196267e2886c2fd54d`.
A separate read-only inventory **after** the refused create found zero
children in this task's new run folder and zero complete Drive matches for its
marker. That report reused the producer's `populate-precreate-baseline` schema
but serves here only as a post-refusal empty-folder check: generation 0061,
SHA-256 `ac1a675980698cc21c6b089af9235e610df909f5fe32ab78763d98ca9662a093`.
It does not authorize a later create.

Together, the gateway admission result and independent provider reads show
that a task and exact plan signed for generation 1 did not produce a Google
write after generation 2 became active. The run does not test a changed OAuth
subject or an already entered write. The scratch folder is retained for
review; no cleanup is claimed.
