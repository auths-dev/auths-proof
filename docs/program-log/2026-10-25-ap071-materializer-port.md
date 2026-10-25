# AP-071 provider credential materializer port

The gateway library now lets an operator bind a credential materializer to an
exact connection ID. A task read or write asks that adapter for a short-lived
request credential only after its native admission and durable operation
reservation. The adapter receives the task, operation, connection and source
generations, account subject, recipe digest, operation kind and task expiry.
The gateway checks the returned subject, pinned effective-authority digest,
nonempty credential and lease deadline. When a connection has a materializer,
ordinary gateway leasing refuses the committed source reference instead of
sending it as a bearer; adapter failure leaves the reserved operation charged
and sends no provider request.

Focused synthetic checks on 25 October 2026:

- The installed task write loopback test sent `pat-materialized` for the
  provider PATCH and observation GET, while the store still held
  `pat-initial`. Direct non-task leasing was refused.
- The managed read loopback test sent `pat-materialized` only after its
  task-bound reservation. Native and qualification refusals did not invoke the
  adapter.
- A failing read adapter produced a `release-refused` receipt with one
  provider-call budget charged, zero released bytes and no provider request.
- Unit checks refused wrong subjects, wrong authority digests, overlong
  leases and empty credentials.

This is a library port and synthetic evidence. It is not an installed Google
custody adapter, a refreshed Jules grant, or evidence of live post-claim OAuth
renewal. Those remain required by [ADR 0020](../adr/0020-post-admission-provider-credential-lease.md)
and [AP-SPEC-071](../specs/0071-human-agent-read-write-delegation-demo.md).
