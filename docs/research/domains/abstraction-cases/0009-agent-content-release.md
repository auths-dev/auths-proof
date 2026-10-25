# Case 0009: bounded provider content release to a delegated agent

## Candidate and ownership

The candidate is a closed, credential-isolated provider request followed by a
bounded release of selected response bytes to one agent named in a verified
human task. The product layer would own request construction, credential
custody, release accounting and a redacted receipt. It would not interpret the
provider's permission model, decide whether the text is true, or execute
instructions found in that text. [AP-SPEC-071](../../../specs/0071-human-agent-read-write-delegation-demo.md)
owns the product scenario. An ADR is still required before this becomes a
shared production capability; this case is design evidence, not approval.

## Independent consumers

| Domain reference | Closed read and output | Semantics kept in its vertical |
| --- | --- | --- |
| Google Workspace / Atlas | Jules-bound HTTPS Docs or Drive GET of one task-listed document; bounded selected body/text and revision released to her designated agent | Google subject, OAuth scope and ACL, Doc/tab structure, revision validity, Project A membership and independent demo_co source probe |
| Airtable exact-record demo | HTTPS GET of one operator-pinned base/table and task-listed record; bounded `fields.DemoStatus` value released to the designated agent | PAT scope and base access, meaning of `DemoStatus`, record freshness and an independent Airtable read |

The Google journey has a human-bound connection and can test human-to-agent
authority. The current Airtable demo uses an operator PAT, so it tests the
same closed release mechanism and task admission but **does not** establish
that a particular employee owns the Airtable access. These claims must stay
separate. The Airtable read recipe and release execution are proposed here;
its existing observation GET must not be counted as an agent release.

demo_co also has a read-only, person-scoped ClickHouse usage view in another
local instance. It is useful for a third semantic comparison. Its current
loopback HTTP POST with fixed SQL does not fit the production HTTPS request
boundary and is not evidence of a shared installed content-release path.

## Shared mechanism and exclusions

For both HTTPS references, native action verification precedes request
construction. An operator-approved digest fixes origin, method, path grammar,
connection and generation, allowed response type/status, extraction rule,
maximum response bytes, maximum released bytes, recipient and budget. Only
verified typed fields can fill a path segment. The credential-bearing process
charges one provider-call allowance before a provider request and releases no
bytes until a complete bounded response and projection pass. Before the first
agent-channel byte, an atomic claim durably records `release-entered` and
irreversibly charges the projected bytes and one release. A complete,
authenticated agent acknowledgement changes the receipt to
`agent-acknowledged`; a lost acknowledgement leaves `delivery-unknown` and the
budgets spent. An operation ID cannot be sent a second time after claim. A
failure proven before release entry is `not-entered`; a failure after claim
with durable proof that transport did not begin is conservatively charged as
`not-delivered`. A crash without that proof stays `delivery-unknown`. A
deliberate new read needs a new action and budget. A read receipt proves only
its stated delivery stage, not comprehension or truth. Revocation prevents a
new release, not retrieval of bytes already delivered.

The public receipt records task, agent, recipe, request count, projected
length and delivery status. It uses a keyed commitment for response and
released bytes, domain-separated by task, resource, operation and receipt
kind, with the key held in custody and its version in the receipt. It never
exports a raw content hash: the Airtable field may have so few possible values
that a plain digest would reveal it by guessing. A private verifier compares
actual bytes and publishes a verdict without publishing the bytes or a public
dictionary-checkable identifier.

Provider account permission, OAuth refresh behavior, data model, pagination,
content citation, prompt-injection handling, freshness, independent source
matching and provider-specific error meaning stay with the vertical or
operator policy. The gateway's current credential-check, pre-entry and
observation GETs have different recipients and evidence contracts and cannot
be reused as content release by renaming them.

| Surface | Google | Airtable | Classification |
| --- | --- | --- | --- |
| Native agent/task/recipe binding | Signed exact document handle | Signed exact record handle | Shared Auths authority mechanism |
| HTTPS request construction | Fixed Docs/Drive path with typed document ID | Fixed base/table with typed record ID | Shared closed recipe grammar, different data |
| Credential custody | Subject-bound OAuth generation | Pinned PAT generation | Shared isolation and lease ordering; OAuth refresh needs separate review |
| Response projection | Bounded document text/revision | Bounded JSON field | Shared bounded extraction only if the AST expresses both without provider branches |
| Provider permission meaning | Google ACL and scopes | Airtable base/table PAT access | Domain-owned |
| Content meaning and freshness | Project A source text/revision | `DemoStatus` value | Domain-owned |
| Effect of release | Content reaches one agent | Field reaches one agent | Shared delivery receipt; no inference that agent used it correctly |

## Hostile comparisons and promotion gate

Both references must refuse changed recipe digest, resource ID, account or
credential generation, recipient, projection path, response media type,
redirected origin, oversized response, partial body, replay and exhausted
read/byte budget before releasing any bytes. A provider 403 is recorded as a
provider denial; it is not converted into an Auths authorization. A complete
provider response followed by failed delivery records no agent-acknowledged
release; a possibly entered delivery remains charged and unknown. Add
acknowledgement-loss, crash-after-claim, attempted redelivery, low-entropy
content guessing and audit-key rotation cases to both references.

The installed harness must count provider requests and agent-visible bytes
independently for each case.

Promotion requires a closed AST and compiler review, two installed HTTPS
provider references using the *same* interpreter and receipt contract,
differential checks against their domain oracles, hostile fixtures, custody
and crash tests, and an ADR that explains the early shared mechanism under
the domain boundary plan. If Airtable cannot meet this gate with its existing
fixture, use another independently implemented HTTPS provider. A Google-only
broker, a synthetic second response or per-provider production callback is
insufficient.
