# AP-071 installed stale-generation refusal — 26 October 2026

This source-free Airtable case tested a valid, separately agent-signed and
exact-confirmed write **after** the operator rotated the installed write
connection. It used the same fixed GET and PATCH recipes as the successful
second-provider runs. The 33-wheel bundle at
`/private/tmp/ap071-airtable-rotate-bundle-20261026` had manifest SHA-256
`695843919d32c003a8f974ee409113a66a6d1704976a75eb8461d5f1d1aebf44`.
Its gateway binary was the previously pinned development build with SHA-256
`bf6a04d70ffd10adcabd3fbaadbec94997d95c1dd1b60ac757e6d0323dd558cb`.
The runner, native, broker, agent, recipes and custody sidecar came from the
checked bundle, without checkout imports.

The synthetic human task `MWq6c1gyHYyCTIsW0UoLI8Zj` allowed one read and
one exact-confirmed write to run-owned record `recs8zwtvbNTtnn7O`. The
registered agent received and acknowledged the bounded read, then signed an
exact write. The human test signer confirmed that write against a fresh
provider baseline. A changed write action was first refused without an
effect. The operator then published the same source reference at the next
credential generation; the already signed task still bound the old
generation. Submitting its otherwise valid exact write returned
`not-entered / gateway.task.connection-changed`. The task retained one
provider read, one release and **zero writes**. An independent Airtable GET
found the record unchanged.

The redacted receipt at
`/private/tmp/ap071-airtable-rotate-live-20261026/operator/redacted-result.json`
has SHA-256 `5734d74ac3dfe9c54216dc64b8765f6163f0fc4c456a0ea5c34ebf77b2c1e0e7`.
A separate manifest-checked cleanup invocation retired the disposable
record; the receipt records `run-owned-record-retired`. The PAT was held by
the operator custody process and has no employee subject. This is an
installed write-generation mismatch result on the second-provider
mechanism, not the still-required changed-Jules-subject or generation run
with the revised Google connection.
