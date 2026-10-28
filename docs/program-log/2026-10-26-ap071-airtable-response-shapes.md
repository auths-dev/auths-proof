# AP-071 installed Airtable response-shape refusals, 26 October 2026

Two source-free, live Airtable cases exercised the same reviewed GET recipe,
installed gateway and separate agent release channel. The 33-wheel bundle at
`/private/tmp/ap071-airtable-response-shapes-bundle-20261026` has manifest
SHA-256 `d3e3e2a1b686b7af1c3dfa76934be3f89cb73965272b7ddc335343cf52333f85`.
The PAT stayed in operator custody; it does not prove a human-bound Airtable
employee identity. Each case used its own run-owned disposable record and
signed task. The runner first checked wrong recipient, wrong recipe and
task-excluded record before provider entry, then changed only its own record
after task activation and independently read the fixture back.

| Case | Task | Live provider condition | Gateway and agent | Redacted result SHA-256 |
| --- | --- | --- | --- | --- |
| Missing projected field | `knr1XumUULw9kxnldarrLmEV` | Airtable omitted `DemoStatus` after an operator PATCH cleared it; the task-admitted GET received HTTP 200. | One provider call, `provider-unavailable` with status 200, zero releases/bytes/writes, no agent content. | `215be39896a460afb8ffd4c33b5bb9ecb5a4e9ec09c9d78b89c942fc26047dc0` |
| Oversize provider body | `4zv5y6rX_oCC6m2jAFEZmQX1` | Airtable returned a record whose `DemoStatus` alone was 17,000 bytes, exceeding the recipe's 16,384-byte provider-body ceiling. | One provider call, `provider-unavailable` with no surfaced HTTP status because transport rejected the body, zero releases/bytes/writes, no agent content. | `69639745bff34ef762134ad3b073cfdb397fc88a4cd1023336b4271accb360ea` |

The private results live at
`/private/tmp/ap071-airtable-missing-field-live-20261026/operator/redacted-result.json`
and
`/private/tmp/ap071-airtable-oversize-body-live-20261026/operator/redacted-result.json`.
Independent Airtable GETs confirmed the selected field absent and the
17,000-byte value retained, respectively. Both results now record
`run-owned-record-retired` after separate, ownership-checked cleanup.

The ordinary source-free bundle runner verified the manifest and installed
the wheels offline for the first case. The second case and both cleanups
reverified that same manifest before invoking the already installed bundle
venv directly, without checkout imports or a second wheel installation.
These cases cover missing JSON projection and oversized whole provider body.
Wrong provider status/media type and redirects remain synthetic compiler or
loopback evidence, not live Airtable response substitutions.
