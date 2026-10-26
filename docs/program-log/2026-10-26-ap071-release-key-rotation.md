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
version after ledger restart. These are source-level development checks. An
installed post-rotation task and production key-store retention are still
needed for qualification.

The targeted `cargo clippy --locked -p auths-gateway --bin auths-gateway --
-D warnings` attempt failed on ten existing library lints in task activity,
recovery and an unchanged release comparison binding; it reported no new
rotation-function warning. Hosted CI was not inspected for this change.
