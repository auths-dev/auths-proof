# Local SDK resource ownership

AP-SPEC-076 section 7 identifies an identical **local resource mechanism** in
TypeScript workflow clients, identity clients, and remote verifiers, and in their
Python counterparts. This extraction stays within each language binding. It
neither moves into core nor grants provider-entry, authorization, recovery,
receipt, or domain-transition authority.

## Comparison and boundary

| Contract | Workflow client / agent | Identity client / resolver | Remote verifier |
| --- | --- | --- | --- |
| Public operation admission | Only while open | Only while open | Only while open |
| Resource held across awaits | Signer, grant/context bytes | Method, authenticator, resolver | Byte transport |
| Cancellation of one waiter | Detaches; retained operation | Detaches; retained operation | Detaches; retained operation |
| Closing | Stop admission; await active tokens | Same | Same |
| Owned cleanup | Child agents, then signer, then local bytes | Every distinct owned adapter | Owned transport |
| Borrowed cleanup | Never destroy borrowed signer | Never destroy borrowed adapter | Never destroy borrowed transport |
| Cleanup result | One generation, retained result | Same | Same |
| Retry | Explicit; only declared idempotent failures | Same | Same |
| Local deadline | Incomplete; owned work continues | Same | Same |
| Acquiring a child | Invalidate publication and clean late result | Factory initialization | Factory initialization |
| Decision meaning excluded from extraction | Grant/delegation and signing | Descriptor, freshness, relationship, signature | Verification response and transport ambiguity |

These are three existing consumers, not invented verticals. The shared contract
is local lifetime ownership, not an inference that their security semantics are
interchangeable. Cleanup order is an explicit dependency order; deduplication
uses resource identity, not equal-looking values. A wrapper registers ownership
before I/O. Constructor/factory inputs are copied before awaiting loading.

## Mechanism and limits

`ResourceLifecycle` in each binding owns named states, an opening operation,
active-use tokens, publication invalidations, and cleanup obligations. Each
cleanup obligation retains its exact destructor, retry capability, and order.
All settled-generation outcomes belong to their original waiters. Only a new
explicit retry can repeat a failed idempotent destructor. The mechanism makes
no assertion that an adapter exception proves non-effect.

Admission, work registration, state checks and publication are constant work;
shutdown is linear in active work plus distinct resources. The owner adds no
network calls, provider retries, polling loops, background execution engine, or
persisted format. Native bounded timers replace busy waiting. Tests use barriers
and injected monotonic scheduling for operation ordering rather than timing
sleeps. Python shields the owned task, never the caller task. A transport that
owns a thread retains its own token until the thread settles.

## Direct cutover and evidence

Existing booleans and cosmetic closing states are removed in the same source
cutover. No compatibility path, obsolete state reader, runtime switch, or public
protocol authority is introduced. Domain code, canonical bytes and result/receipt
meaning stay in their current owners. The SDK error registry remains the code
authority; local cleanup completion has a bounded reason in addition to it.

The TypeScript lifecycle contract runs unchanged against built modules and the
installed package without repository source. Public identity/remote adapter
contracts cover owned/borrowed cleanup, independent failures, safe retry, and
in-flight transport retention in both locations. Workflow integration tests
exercise cancellation, shared close and attachment racing shutdown. Python
barrier schedules cover C1–C7 and the existing cancellation corpus is updated to
prove cleanup occurs after the last possible use. These tests are written but
not yet verified; final hosted evidence belongs in the AP076 implementation
record. No new cryptographic/formal qualification claim is made.

A reviewer can reject this local extraction without changing the native kernel
or gateway contracts. Composition of promise/task helpers alone is insufficient:
the race being repaired is precisely the missing single owner of their combined
admission, publication, and cleanup transitions.
