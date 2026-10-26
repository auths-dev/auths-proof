# AP-071 installed macOS agent isolation run — 26 October 2026

The source-free Airtable bundle at
`/private/tmp/ap071-airtable-macos-isolated-bundle-v2-20261026` had an
independently recorded manifest SHA-256 of
`bfb1334b029bf3fdb89ce20c022e590dc2e3fbf80f15332d3ad08d5dbd4608ca`.
It included the same generic gateway binary used by the custody process
cutover, the native Auths wheel, broker and agent wheels, fixed read/write
recipes, the Airtable custody sidecar, the installed runner and 30 offline
dependency wheels. The launcher checked the whole manifest before installing
the wheels into a fresh environment. No checkout source path was on the agent
or gateway Python import path.

The installed runner applied one macOS Seatbelt profile to **every agent
command**: signing, release serving and the isolation probe. The profile
denied outbound network access and reads of the exact gateway state,
operator-private directory and operator credential file. It denied all file
writes except beneath the agent's private directory. The gateway and Airtable
custody process ran outside that profile. This is an OS-enforced boundary for
this local fixture, although it does not provide separate users or container
namespaces and is not a production deployment profile.

Before creating the disposable Airtable record, the installed agent probe
reported `auths.ap071-agent-isolation-probe/2` with `passed: true`:
`agent_private`, `channel_private`, `network_isolated` and
`outside_write_denied` were true; opening gateway state, operator private
files and the credential file was denied. Its redacted report is
`/private/tmp/ap071-airtable-macos-isolated-live-v2-20261026/operator/agent-isolation.json`.

Under that same profile, a separate agent signed an admitted read of the
disposable record and acknowledged a seven-byte release over the private
Unix channel. It then signed an exact confirmed write. The installed gateway
recorded one provider read, one release and one write; Airtable independently
returned the expected `approved-with-echo` after-state. The excluded read,
wrong recipe and write replay were `not-entered`. The redacted result is
`/private/tmp/ap071-airtable-macos-isolated-live-v2-20261026/operator/redacted-result.json`.
The run-owned record was retired by the separately invoked, manifest-checked
cleanup command.

This establishes an installed, source-free agent boundary and read/write
mechanism on a second HTTPS provider. The Airtable PAT is an operator
credential, not a human-subject grant. A fresh Jules Google run with the
provider-neutral custody sidecar, the remaining installed crash/negative
matrix and production isolation/qualification remain open.
