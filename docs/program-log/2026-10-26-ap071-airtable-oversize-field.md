# AP-071 installed Airtable oversize-field refusal, 26 October 2026

This source-free case tests the reviewed Airtable read recipe's 64-byte
projection ceiling against a live provider response. It uses the same reviewed
gateway executable and wheels as the installed two-task case, packaged with a
new pinned runner. The 33-wheel bundle at
`/private/tmp/ap071-airtable-oversize-bundle-20261026` has manifest SHA-256
`b2151a4854f3b0515427094efcd6ddabe5f86d685b86a89ccfa5b24c6dd67298`.
The PAT remained in the operator-held custody process; it does not establish a
human-bound Airtable employee identity.

The runner created one disposable Airtable record, signed and activated task
`EjpWFieK2cWlHc4mlnd7tUYI` for its separate agent, and checked wrong
recipient, wrong recipe and excluded-record requests before provider entry. The
operator then set only that run-owned record's `DemoStatus` to 65 ASCII bytes.
An independently fetched record confirmed the value before the agent submitted
its signed, task-admitted GET.

The gateway made **one provider call** and received HTTP 200, then returned
`provider-unavailable` because the projected field exceeded the reviewed
64-byte limit. Its task status records one provider call, zero releases, zero
released bytes, zero writes, and a `provider-unavailable` read stage. The agent
received no content file. A second independent Airtable GET found the 65-byte
field unchanged. The redacted result is at
`/private/tmp/ap071-airtable-oversize-live-20261026/operator/redacted-result.json`,
SHA-256 `5487c4f9761cc02f4b87f6ea5eaef43d82795996b4158b5e2216c459a3ba366a`.

The separate cleanup command retired the run-owned record; the result now
records `run-owned-record-retired`. This closes the live projected-field-size
case. It does not test an oversized whole HTTP body, a redirect, or a wrong
response media type.
