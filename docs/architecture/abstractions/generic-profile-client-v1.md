# Generic profile client v1 abstraction case

## Status

Implementation case file for AP-SPEC-040. The repository is prelaunch; the
cutover is direct and retains no legacy reader, dual route, deprecated alias,
state converter, or runtime rollback path.

## Candidate mechanisms

The candidate shared product mechanisms are the authenticated local session,
profile manifest/runtime digest, bounded generated DTO codec, provider
connection record and generation binding, prepare/execute/recover framing,
idempotency commitment, operation journal, and portable receipt container.

They explicitly exclude canonical action meaning, evaluators, provider request
construction, credential scopes, effect classification, reconciliation, and
profile receipt claims.

## Consumers and comparison

| Concern | OpenTofu saved-plan apply | PostgreSQL bounded update | Stripe refund | Classification |
| --- | --- | --- | --- | --- |
| Local workload session | peer-authenticated | peer-authenticated | peer-authenticated | identical mechanism |
| Connection identity | backend/workspace | database deployment | merchant account | analogous, domain descriptor |
| API input codec | bounded saved plan | bounded row change | bounded refund | identical grammar, different DTO |
| Canonical action | saved plan commitments | SQL predicate/change | payment/amount | profile semantic |
| Credential | backend/provider | database role | restricted API credential | domain semantic |
| Provider entry | subprocess/backend | serializable transaction | HTTP request | profile semantic |
| Recovery evidence | backend state | ledger/row state | provider object/idempotency | profile semantic |
| Receipt container | decision/execution link | decision/execution link | decision/execution link | identical mechanism |

## Exact shared invariants

- One authenticated workload principal selects only configured profiles and
  provider connection aliases.
- Connection ID, generation, descriptor commitment, and account commitment are
  bound before authority verification and provider entry.
- A repeated request commitment returns the original operation; a changed
  commitment cannot enter a provider.
- The effect request is sent at most once by the SDK.
- Possible effects retain their only recovery locator.
- Shared envelopes never classify provider outcomes or construct provider
  requests.

## Evidence and cutover

The mechanism is tested first with synthetic records, then differentially with
PostgreSQL and Stripe connection models. OpenTofu proves the connection-free or
backend-bound branch according to its final vertical review. Reference
evaluators and fixtures remain test-only semantic oracles.

The old production-client dispatcher and bearer-token application examples are
removed in the same cutover that makes the local generated clients
authoritative. Obsolete disposable state is rejected by semantic identity.
