# AP-SPEC-041: Stripe Connection Contract

Status: **moved to the gateway recipe on 28 September 2026.** Under the
owner's decision of 27 September 2026 ([AP-SPEC-063](0063-generalized-gateway.md)
§12, option A) the local-agent profile `auths.stripe.refund/1`, this
connection's onboarding and administration, the protected evidence reader,
and the qualification custody of §4 were removed (AP-SPEC-063 epic 8). The
production Stripe refund is AP-SPEC-063 §3.1's recipe in
`examples/stripe-refund-approval/`. Each requirement below maps to a gateway
capability, narrower where AP-SPEC-063 §6.9 and §14 say:

| This contract | Gateway recipe |
| --- | --- |
| `rk_test_` restricted keys only, refused before network I/O | §5.2 credential-mode guard: a declared prefix allowlist at `install`, `rotate`, and every lease |
| Pinned `Stripe-Version` sent, response header required equal | §5.1 provider version header with the "must echo" response rule |
| `acct_` identity read at onboarding and re-checked before each lease | §5.7 account binding at onboarding and every lease, read from the provider each time |
| The exact `stripe.refunds.write/1` scope | §5.8 denied reads: observed refusals of declared reads, since neither path can read a key's scopes |
| Connect accounts refused in v1 | §5.9 account scope: a grant-listed `Stripe-Account` value; a recipe without `account_scope` writes on the platform |
| Separate runtime-read key and signed evidence reader; pre-entry reread | §5.6 relative-ceiling basis read by the gateway after the lease with the same credential (§13 reading 21), and §5.3 pre-entry re-read where a recipe declares one |
| Workflow-derived idempotency key and metadata marker | §4.1's derived `Idempotency-Key` and §5.4's form echo |
| Paginated reconciliation by marker | §4.4: `unknown` resolves only through a `linked` read-back of the response locator |
| Qualification custody (§4) | None. ADR 0013's qualification rule governs any later qualified claim |

The text below is the record of the local-agent design and is not a current
requirement.

`auths.stripe.connection/1` binds one Auths connection to one Stripe test-mode
account, one pinned Stripe API version, and a closed byte-sorted set of
profile credential scopes. Its descriptor is canonical JCS with schema
`auths.stripe.connection-descriptor/1`. Version 1 accepts only canonical
restricted test keys beginning `rk_test_`; every `sk_test_`, `rk_live_`, and
`sk_live_` key is rejected before network I/O or registry publication. There
is no compatibility key path.

## 1. Mutation connection

The privileged administrator supplies the restricted mutation key through
owner-only protected input, never argv, environment, application IPC,
diagnostics, receipts, or qualification archives. Onboarding uses the pinned
`Stripe-Version` request header, requires the response header to equal it,
reads the exact test account, and commits the `acct_` identity. Registry
publication binds the connection ID, generation, descriptor, account,
credential commitment, supported profile/version set, and the exact
`stripe.refunds.write/1` scope. A connection configured for Connect accounts
is invalid in v1; platform account context is exact across onboarding,
evidence, mutation, and reconciliation.

The common runtime rereads the active generation and all descriptor/account
commitments before each credential lease. The broker returns a non-cloneable,
deadline-bound lease only for the exact registered scope and process. Rotation
creates a new generation; disable or revoke prevents new leases but cannot
erase or reinterpret retained operation truth. Recovery uses the retained
generation and commitment rules from AP-SPEC-040 and never falls back to the
current default connection.

## 2. Protected evidence-read companion

`auths.stripe.refund/1` declares
`contracts.preparationEvidence = "protected-lease"` and uses the generated
companion protocol in AP-SPEC-040 section 13.4.1. This does not add a sixth
profile. Before preparation, the connection runtime verifies a separate
domain-owned `stripe.refund-evidence.read/1` action over the observed
principal, exact profile/runtime/workflow/input commitments, PaymentIntent,
connection generation/account/API commitments, and required configuration.
Only Authorized reaches the provider.

The evidence reader is a separately supervised process under a distinct,
configured non-root UID. It alone receives a second `rk_test_` runtime-read
key restricted to account, PaymentIntent, and charge reads plus an owner-only
Ed25519 signing seed. The mutation process cannot read those secrets; the
reader cannot read agent journal, reservation, connection, credential, or
lease-store roots. Agent and reader authenticate each other with Unix peer
credentials over an owner/mode/type-checked socket whose ancestors are opened
without following symlinks. One total monotonic request deadline covers
framing, all provider reads, and response write.

The reader performs the fixed account, PaymentIntent, and charge reads with
the pinned request API version and exact response-version equality. It
normalizes only bounded security facts, binds workflow, phase, PaymentIntent,
sealed-command commitment when pre-entry, observation time, account, charge,
refundable amount, currency, Connect context, API version, and a raw-response
commitment, then signs canonical bytes. Raw provider bodies and identifiers are
zeroized after normalization and never appear in errors or logs. Preparation
consumes a locally retained signed evidence lease and performs no provider I/O.
After durable command sealing and before mutation credential lease/provider
entry, the profile performs a second command-bound broker reread that is
strictly newer than preparation evidence and exact-compares every critical
fact. Drift releases the reservation and remains not-applied.

## 3. Provider mutation and recovery

The mutation request uses the exact authorized Charge as its target, the
pinned Stripe request version, the stable workflow-derived idempotency key,
and a closed metadata marker tuple. PaymentIntent is corroborating evidence,
never the mutation selector. The response API version and bounded normalized
result are durable before classification. Response loss moves the persistent
reservation and journal profile state to `OutcomeUnknown` before the linked
indeterminate execution receipt is signed.

Reconciliation uses the runtime-read boundary, boundedly exhausts provider
pagination, requires every immutable Auths marker, and accepts exactly one
matching refund. Zero or multiple matches remain possible. A definite match
must equal charge, PaymentIntent, amount, currency, account, API version,
reservation identity, and signed result commitment. Definite non-effect may
release capacity; ambiguity never does.

## 4. Qualification custody

Live qualification uses three distinct restricted test keys: setup/cleanup,
runtime evidence read, and refund mutation. Each is routed only to its fixed
protected role. Provider-read and mutation request/response events are counted
and source-authenticated separately; missing, duplicate, hidden, reordered,
or wrong-version calls fail attestation. Operator validation proves the broker
binary/config digest, process UID separation, socket custody, readiness,
restart cleanup, and secret redaction before advertising Stripe.
