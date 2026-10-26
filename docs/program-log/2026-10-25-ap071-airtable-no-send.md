# AP-071 installed Airtable no-content delivery fault

On 25 October 2026, the development operator ran the checked-in installed
Airtable conformance tool with a gateway binary built using the development
`loopback-provider` feature. The binary SHA-256 was
`fcd348eabf4c9d8b72ef9d90352b7fad1bc11b69f5c2ceac9f7bf4d7d7602703`.
The feature exposed an operator-only `--fail-before-content` option on
`task-read-submit`; it does not select a new recipe or provider request.

The fresh run-owned record was `recjJn1B12RiNPuCo`, task
`ViuYmfh2xqbsLN_hqCxLULgW`, read operation `airtable-read-one`. The separate
agent signed the permitted read and authenticated over its Unix socket. The
gateway made one GET, projected the seven-byte field and durably charged one
release and seven bytes. It then closed the channel's write half before
writing the first content byte. The result and durable read stage were both
`not-delivered`; the agent saved no content file. A second authenticated
channel attempted the same signed operation. Native task admission returned
`not-entered` with `gateway.release.task-admission`, made no additional
provider call, delivered no content and left the task counters unchanged.

The private redacted result is
`/private/tmp/ap071-airtable-no-send-20261025-2112/operator/redacted-result.json`.
It records provider calls 1/1, releases 1/1, charged bytes 7/64, writes 0/1,
the terminal read stage, replay refusal and verified retirement of the
run-owned Airtable record. The agent content file and replay content file are
absent; the resource journal has `retired=true`.

An initial fresh run ended before its permitted read, with zero provider calls
and zero releases; its separate disposable record was also retired. The
successful run used a new task and record. This test proves the installed
single-host accounting path under a controlled pre-content fault. It does not
claim multi-host durability or a subject-bound Airtable employee connection.
