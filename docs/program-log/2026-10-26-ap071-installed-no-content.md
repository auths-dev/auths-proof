# AP-071 installed no-content delivery fault, 26 October 2026

This source-free Airtable run exercised the managed release boundary after a
real permitted provider GET but before the first content byte entered the
authenticated agent channel. It used a gateway built with the development
`loopback-provider` feature, whose `task-read-submit --help` exposed the
`--fail-before-content` fault. The gateway executable SHA-256 was
`bf6a04d70ffd10adcabd3fbaadbec94997d95c1dd1b60ac757e6d0323dd558cb`.
The pinned 33-wheel bundle at
`/private/tmp/ap071-airtable-no-content-bundle-20261026` had manifest SHA-256
`a8a83a63c3b71de60fb0b5dfb03c0f5146016bcf31fde369511c139113ea922a`.
The source-free runner installed the current native, broker and agent wheels
offline and executed the separate agent process outside the checkout.

The disposable task was `E69LhtZcMRxqUG5yNBIXmjla`. Its redacted result
at `/private/tmp/ap071-airtable-no-content-live-20261026/operator/redacted-result.json`
has SHA-256
`1795c22615b746f1ececdb2feee9dee53645e77d917cdb52f7230415b5fc4d9a`.
The gateway reported one provider call, one release, seven charged bytes,
zero writes and read stage `not-delivered`. The agent did not save the source
bytes. Replaying the same read was `not-entered` with
`gateway.release.task-admission`; it did not deliver content a second time.
The separate cleanup command independently retired the run-owned Airtable
record, and the redacted result records `run-owned-record-retired`.

The PAT was held by the installed custody process and does not establish a
human-bound employee connection. This run closes the installed no-content
fault case; it does not replace the fresh Jules Google task or production
isolation evidence.
