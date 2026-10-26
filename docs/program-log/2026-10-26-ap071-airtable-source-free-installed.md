# AP-071 source-free installed Airtable run — 26 October 2026

The current source-free Airtable bundle was built from the AP-071 checkout and
run from `/private/tmp/ap071-airtable-installed-bundle-20261026`. Its externally
recorded `manifest.json` SHA-256 is
`abfd32f358fa58e57104b9b1822d346b9ce22c331dfefeafb60a9a9451a44939`.
The bundle contains the gateway binary, native Auths wheel, broker and agent
wheels, an offline dependency wheelhouse, fixed Airtable recipes and the small
fixture runner. The launcher verifies every file against the pinned manifest,
creates a fresh virtual environment, and installs without an index. The runner
and separate agent subprocess do not import from the source checkout. A wrong
manifest pin and an altered recipe were separately refused before provider
entry.

The live run used one operator-owned disposable Airtable record. The signed
task admitted one seven-byte field release to a distinct agent and one exact
confirmed PATCH. The redacted result reports:

| Check | Outcome |
| --- | --- |
| Read delivery | `agent-acknowledged`; one provider read, seven released bytes |
| Exact write | `observed-by-provider`; one write |
| Independent readback | `approved-with-echo` |
| Excluded resource, wrong recipe, changed post-confirmation action, write replay | Each `not-entered` |
| Wrong agent recipient | `agent-signing-refused` |
| Cleanup | `run-owned-record-retired` |

The private redacted result is at
`/private/tmp/ap071-airtable-sourcefree-live-20261026-1/operator/redacted-result.json`.
The run-owned resource journal was used to retire the record after verification.
The same pinned bundle also completed separate live disposable-record cases for
lost acknowledgement (`delivery-unknown` with no replay), revocation before
both staged actions (zero provider calls and unchanged record), a second upfront
write refused by the one-write budget, and two concurrent final-write claims
with exactly one admitted. Each case has a redacted result under
`/private/tmp/ap071-airtable-sourcefree-<case>-20261026/operator/` and each
run-owned record was retired. The cases are `lost_ack`, `revocation`,
`second_write`, and `concurrent_writes`.

The original packaged gateway did not expose the development-only
`--fail-before-content` switch, so its first no-content invocation refused
before fixture creation. A later [source-free installed rerun](2026-10-26-ap071-installed-no-content.md)
used a pinned fault-enabled gateway. It recorded one provider call, seven
charged bytes at `not-delivered`, no agent content, refused replay and verified
run-owned record retirement.
This run demonstrates the installed shared mechanism on a second HTTPS provider;
the Airtable PAT is operator held and does not establish a second human-bound
employee identity. The remaining hostile and isolation matrix in the
[acceptance audit](2026-10-25-ap071-acceptance-audit.md) is still open.
