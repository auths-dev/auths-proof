# AP-071 installed release-entry crash — 26 October 2026

The source-free Airtable bundle at
`/private/tmp/ap071-airtable-crash-entry-bundle-20261026` had externally
recorded manifest SHA-256
`fb1fff54abf1535bea418cd26fa171c3319ce6bc683b5bb56e51be8fc2ebb332`.
It pinned the current development-fault gateway binary, native Auths wheel,
broker and agent wheels, fixed recipes, Airtable custody process and offline
dependencies. The installed launcher checked every bundle file and installed
the wheels without checkout imports. Every agent command ran under the
[macOS OS profile](2026-10-26-ap071-macos-installed-agent-isolation.md), whose
installed probe passed before fixture creation.

The agent signed one allowed read for disposable Airtable record
`rec72etbWhpDZmuTg` under task `Ky1iLK6pAxCKfyd_uk09DmCn`. The gateway made
one provider GET and projected the seven-byte field. A feature-gated
development fault called `process::exit(86)` immediately **after** the
release ledger committed the charged release entry and **before** the
authenticated channel sent a content byte. The process emitted no success
reply. The agent's output file was absent.

A new gateway process reopened the installed state and reported one provider
call, one release, seven charged bytes and `delivery-unknown`. Replaying the
same signed operation from another new process was `not-entered` with
`gateway.release.task-admission`; the ledger and provider count were
unchanged, and the agent received no second content. The redacted result is
`/private/tmp/ap071-airtable-crash-entry-live-20261026/operator/redacted-result.json`.
The separately invoked, manifest-checked cleanup retired the run-owned
record.

A second source-free bundle at
`/private/tmp/ap071-airtable-content-crash-bundle-20261026` had manifest
SHA-256
`5f1b4c204b4de42cebe324e024611d42c715c6c0d5580a0d02b6f5ad368a3705`.
Its separate task `pLhrTCNyQs5s3Lts8YU8Nche` read disposable record
`recX54Z6coZwuPW5A`. The development gateway exited with code 87 after
writing the complete content and acknowledgement challenge to the Unix
channel, but before reading the signed acknowledgement. The isolated agent
durably saved exactly `Pending` (seven bytes). On restart, the gateway
reported one provider call, one release, seven charged bytes and
`delivery-unknown`; same-operation replay was `not-entered` with no second
content. The redacted result is
`/private/tmp/ap071-airtable-content-crash-live-20261026/operator/redacted-result.json`.
The second record was also retired by manifest-checked cleanup.

These are real process-exit/reopen checks at two read journal boundaries,
including the case where the agent saved the content but Auths lost the
acknowledgement. Both read fault switches exist only in the
`loopback-provider` development build; the default gateway build has neither
flag nor process exit.

## Write reservation before attempt claim

A third source-free bundle at
`/private/tmp/ap071-airtable-write-crash-cli-bundle-20261026` had externally
recorded manifest SHA-256
`cd7b4b18cd5a8deab0ef0f96c2de677a73c96bd5cdb857c2cb7df05fa1da1df5`.
It pinned a newly built development gateway, current broker and isolated-agent
wheels, native wheel, recipes, runner and offline dependencies. The manifest
check passed before the offline install; every agent command used the same
macOS OS profile. The launcher used Homebrew Python 3.12 to match its
dependency wheelhouse.

The installed agent and human signed one exact-confirmed change of run-owned
record `recniI92K528iJMv8` under task `7CUnkprvRXoGjEVQ1mbW7hba` and
operation `airtable-write-one`. A changed agent action was refused before the
write budget was spent. The selected development fault called
`process::exit(88)` only after the task ledger durably reserved the approved
operation and before the independent attempt journal was claimed. No write
result was emitted. A new gateway process reported one spent write with stage
`claimed-no-attempt`, no response status and no observation match. Replaying
the identical signed operation from another new process was `not-entered`
with `gateway.task.write-replay`; task activity did not change. An independent
Airtable GET matched the original record, so the provider write did not occur.
The redacted result is
`/private/tmp/ap071-airtable-write-crash-cli-live-20261026/operator/redacted-result.json`.
The manifest-checked cleanup retired the run-owned record.

This closes the installed task-ledger/attempt-journal crash interleaving for
one exact-confirmed Airtable edit. The exit flag is compiled only with
`loopback-provider`; the default gateway refuses it before executing a write.
A Google provider effect and the other §8 hostile
cases remain separate acceptance work.
