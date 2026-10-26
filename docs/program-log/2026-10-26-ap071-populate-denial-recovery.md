# AP-071 controlled population denial and same-child recovery, 26 October 2026

This local installed run used Jules's existing subject-bound Google connection,
the separately registered agent, and the fixed gateway executable SHA-256
`8c663e4021f3f0469bebf708b1afecde11b5208d82d95f43a959215253415b1d`.
Jules signed task `kbvFncpN3CRb4OuMCNyCHk1k` for one Project A source read
and two exact-confirmed writes in disposable scratch folder
`1tVmlK6mFtt5B9DNO3T01lI4fNqD3WLRx`. She separately signed the exact
create-and-populate plan. The agent received and acknowledged 51 source bytes,
then signed the source-grounded draft. No provider token or human signing key
was given to the agent.

The run used demo_co's setup generation 0033, SHA-256
`ccac976832db2ea962731bbe22e1ba9aba926b0a1ef7f2dfccb8ddb53ad99c52`,
and complete precreate baseline generation 0034, SHA-256
`1fa5c6d491e2310d47fc868c5ee3f2b96ee5a714af6832e1bd40ae723190d6e9`.
The latter observed zero run children and zero marker matches before Google
entry. The gateway submitted one Google Drive create. Its returned child was
`1fW2PdvYJzHSydZPrIwn6JviKUsriTZDr7-ljH6DQOOY`; operation
`uqjYAl59HxjwgLK6qpm1Bj2B` was observed with HTTP 200. demo_co's blank
baseline generation 0035, SHA-256
`4d446134146107e6bfcb1babe1c8e2c519b0c65ae8a3b2491440fb44c59df556`,
independently found exactly this one child under the pinned folder and marker,
with BOM-only raw export SHA-256
`f1945cd6c19e56b3c1c78943ef5ec18116907a4ca1efc40a57d48ab1db7adfc5`.

After a fresh Jules child/revision preflight, the agent's signed population
action was deliberately changed by one byte while retaining its original
proof. The gateway returned `denied` **before provider entry**. The task still
showed one charged write, the create. This was a signature/admission denial,
not a simulated transport drop or a lost Google response. demo_co's separate
denial observation generation 0036, SHA-256
`e815c90a19503755a29af231951b3c1ca5fc92f7c58c79859da987a3dc5811bc`,
found the same blank child and the same Docs revision as generation 0035. Its
provider artifact explicitly does not attest the gateway denial; the Auths
gateway result, task ledger, and absence of a population claim establish that
part of the joined result.

Auths then recorded a new Jules preflight for that same child. The distinct
agent signed a fresh valid action under the original effect plan. The operator
reconciled the one `denied` pre-entry attempt, rather than creating again, and
submitted population operation `populate-RMVrMA3NVIWH3cPr` once. The gateway
recorded HTTP 200. demo_co's final generation 0037, SHA-256
`667480e9afec3790cd7d7307154488fe4530315cb9550dfd2b9fc650939a7fe3`,
found the same child, a changed revision, and the exact expected 148-byte raw
export SHA-256
`a1fb0c3010e622cee1ac5f85bda4c9865194f2e84bba36196267e2886c2fd54d`.
It observed one run child and unchanged original seven Docs and canonical
Project A/B state. Jules revoked the completed task. Its final ledger records
one acknowledged 51-byte read, exactly two write operation IDs, and
`revoked: true`.

Auths pinned the setup, precreate, blank, denial, and final producer schemas
and bytes. Its strict join returned `accepted` for the task, one create
provider entry, zero provider entries for the denied population, and one
successful population entry. The private join is
`/private/tmp/ap071-populate-failure-20261026/strict-join.json`. An extra
response-child reconciliation call returned an uncertainty diagnostic because
the successful create had already bound its child; the gateway's immutable
preflight inputs and the subsequent successful population confirmed that
binding. The operator helper now checks for an already bound child before
calling reconciliation.

The Doc remains as disposable evidence. demo_co prepared a separate
read-only four-run scratch reset plan, generation 0038, SHA-256
`1635721d2876cfdac91c7b212176b449e31ae16bb09bb9d1f8659afa92fe08de`;
it performed no deletion. This run covers the controlled **pre-entry denial**
case only. It does not establish safe retry after an unknown response once a
population request has entered Google. Full AP-SPEC-071 acceptance remains
open for the remaining hostile cases and production qualification.
