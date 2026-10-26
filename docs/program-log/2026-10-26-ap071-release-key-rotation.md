# AP-071 development release audit-key rotation — 26 October 2026

The managed read receipt contains a keyed, task/resource/operation-separated
content commitment and a key version. The development gateway now offers
`task-read-commitment-rotate --state-dir ROOT` to change the key used by
future releases. It writes a fresh owner-private versioned key, syncs it,
then atomically publishes the new version in the read runtime. The first
version retains its original file name; later versions have distinct files.
Old keys remain in the private state directory for as long as its task journal
is retained. There is no key-deletion command that could strand a retained
receipt. If publication stops after the candidate key is durable, a later
rotation can validate and use that same candidate. The rotation command is
restricted to the single-host development installation.

`task-release-compare` reads an acknowledged operation's durable key version,
loads only that version's owner-private file, and compares the private source
bytes without returning the commitment or content. It rejects a missing or
unsafe historical key, an unacknowledged operation, a wrong resource or a
version ahead of the installed runtime. New release submissions use the
current version. Concurrent rotation cannot replace a key file that a read
already selected.

Focused local checks passed:

- `cargo test --locked -p auths-gateway --bin auths-gateway rotated_release_audit_key_retains_private_comparison`
- `cargo test --locked -p auths-gateway authenticated_acknowledgement_is_exact_and_durable`
- `cargo test --locked -p auths-gateway --bin auths-gateway task_read_operator_commands_keep_credential_off_argv`

The first test rotates a private installation and confirms that the retained
key still verifies a short-value receipt while the new key does not; it also
reuses a durable, unpublished next-version candidate and rejects a
shared-permission historical file. The release-state test checks
that only an acknowledged operation on the exact resource selects a key
version after ledger restart. These are source-level development checks;
production key-store retention still needs qualification.

The targeted `cargo clippy --locked -p auths-gateway --bin auths-gateway --
-D warnings` attempt failed on ten existing library lints in task activity,
recovery and an unchanged release comparison binding; it reported no new
rotation-function warning. Hosted CI was not inspected for this change.

An installed cross-process Airtable case now runs in the source-free
runner as `--rotate-release-audit-key`. It compares one acknowledged release,
rotates the key through a new gateway process, repeats the private comparison,
requires unchanged task accounting, and continues to one exact write with
independent provider readback. The new development gateway binary has SHA-256
`a20fd28c5a7a8c3a96d2bd1a6b3fd9c30dfdcd88466657395cff293a95bf10a7`.
The 33-wheel bundle at
`/private/tmp/ap071-airtable-release-key-rotation-bundle-v2-20261026`
has manifest SHA-256
`fdab929a4573edfb2d7ac7ab1f9b2ad36aae5f31c2e36e4041dcd0d4c225c477`.
Its independent manifest check covered 50 files, and both wrapper and binary
help expose the rotation command. A run under that pin used one synthetic
human task and separate agent process to acknowledge a seven-byte Airtable
field release, rotate the audit key to version 2, privately match the same
release again, and make one exact-confirmed write. The gateway retained one
provider read call, one release, seven charged bytes and one write; independent
Airtable readback matched the approved value and echo. The run-owned record
was retired. The final redacted receipt is
`/private/tmp/ap071-airtable-release-key-rotation-live-20261026/operator/redacted-result.json`
with SHA-256
`cadd64812d32c074579645b9d8afaf1325221c0c12b384ddac1729b201724625`.
This proves development installed rotation across fresh gateway processes for
one retained receipt; it does not prove production key custody or the Jules
Google connection.
