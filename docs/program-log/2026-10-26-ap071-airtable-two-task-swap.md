# AP-071 installed two-task binding run — 26 October 2026

The source-free bundle at
`/private/tmp/ap071-airtable-two-task-bundle-20261026` has independent
manifest SHA-256
`f31d3015123a4fab5c9176b5da6862cb239ce9047178fadfb1c36e3d751e2630`.
The launcher verified the bundle before installing its pinned native, broker
and agent wheels offline. It ran every agent command under the macOS OS
isolation profile. The gateway binary is the ordinary build with no
development fault switch.

Two separately human-signed tasks, `epqOlClWl8bfS4bstNor-5r7` and
`u_43CRB5VQ8kIsUjbfvIAETu`, were activated against the same installed
Airtable read and write connections and one disposable record
`recDgErtfzQp2OTKX`. The installed read and write recipes use distinct
operator namespaces. Before either valid read, the separate agent signed
three substituted actions:

| Attempt | Auths result | Gateway provider calls and writes at refusal |
| --- | --- | --- |
| First task's read proof submitted under second task ID | `not-entered`, `gateway.release.task-binding` | 0 calls, 0 writes in both tasks |
| First task's write proof submitted under second task ID | `not-entered`, `gateway.task.card-binding` | 0 calls, 0 writes in both tasks |
| First task's read proof using the write namespace | `not-entered`, `gateway.release.native-proof` | 0 calls, 0 writes in both tasks |

The agent then signed and acknowledged one valid read for **each** task. Each
task's reopened gateway status reported one provider call, one release,
seven charged bytes and zero writes; each agent output contained exactly the
seven-byte status `Pending`. An independent Airtable GET still matched the
original record. The redacted receipt is
`/private/tmp/ap071-airtable-two-task-live-20261026/operator/redacted-result.json`.
The separately invoked manifest-checked cleanup retired the run-owned
record.

This proves two live task IDs cannot borrow one another's signed read or
write action on a shared connection, and the read recipe cannot borrow the
write recipe's namespace in this installed case. It does not exercise
create-child, effect-plan or population-preflight swaps; those require the
Google create/populate vertical or another installed create provider.
