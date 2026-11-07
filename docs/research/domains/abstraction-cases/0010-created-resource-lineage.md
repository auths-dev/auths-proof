# Case 0010: Bounded created-resource selection and native provenance

Owner: product gateway, [ADR 0019](../../../adr/0019-created-resource-lineage-and-reconciliation.md).
Status: implementation contract; provider and full F10 evidence pending.

| Existing reference | Evidence actually present | Excluded inference |
| --- | --- | --- |
| Preserved `97163513`, AP071 Google `task_recovery_operator.py` and `google_create_v4_handoff.py` | Application-owned created-child proposals and provider-specific recovery; parent/marker/list completeness are concrete Google concerns | Its SQLite task owner, credentials, receipts and selected IDs cannot become managed permits |
| Stripe subscription create `execution.rs` / `service.rs` | Concrete unknown/reconciliation outcomes, provider projection and liability transitions | `Active`, `Released`, or provider reconciliation labels are not generic gateway stages or permission to release reservations |
| Gateway GitHub issue-create/Todoist fixtures and response locator | Exact bounded create requests and complete response recording; provider-owned IDs/mappings | A response-less create has no response locator; uniqueness or resource existence cannot be inferred from a write or match |
| Gateway Airtable/native recovery | Independent read, exact native approval, bounded duplicate-free JSON, immutable source/read evidence, shared accounting/fence | One matching object at a known URL does not establish uniqueness in a complete list |

These are divergent creation/lifecycle contracts. There are not three completed
managed provider implementations proving a universal create protocol. The only
new extraction is a smaller closed leaf: bounded pointer access, exact string/
boolean comparisons, sole-parent-array shape and exactly-one cardinality.
ADR 0019 records that exception explicitly. Provider-specific URLs, fields,
completeness meaning and marker integrity remain digest-bound data/assumptions.

The native relation selects one resource only if all declared completeness
conditions hold, every relevant candidate is well formed, exactly one candidate
matches the source's native echo and verified parent, and response/work bounds
hold. The three portable response shapes in the corpus exercise a records
envelope with absent pagination, a data envelope with `has_more=false`, and a
files envelope with an absent page token plus `incompleteSearch=false`. They are
synthetic comparison inputs, not live Airtable/Stripe/Google qualification.

The journal then separately establishes provenance: original entered mutation,
independently authorized/current acquisition, full exact approval, original
response receipt time, current source/read fence, permanent capacity and
immutable evidence link. Downstream authority additionally needs the signed
pending-child relation and source/read dependencies in the native final fence.
Data projection, provenance and execution permission are separate contracts.

Retain an independent Python projection oracle and the historical provider
references. Native fixtures must include missing parent containers, duplicate
keys/items, invalid escapes, malformed marker/resource/parent, bounded-work
edges, zero/multiple/unique candidates and incomplete listings. Differential
agreement is evidence only for this parsing relation. Never infer provider
truth, exactly-once effects, no-effect, refund or child authority from it.
