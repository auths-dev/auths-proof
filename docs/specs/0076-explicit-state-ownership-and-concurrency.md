# AP-SPEC-076: Explicit state ownership and concurrency

- **Status:** Proposed implementation contract. No fixes, test results, or
  repository-wide compliance are claimed by this document.
- **Readiness:** Sections 5–7 specify the first three implementation contracts.
  Administrative recovery in sections 8.2–8.3 requires the completed follow-on
  protocol design in section 8.4 before its runtime implementation begins.
- **Date:** 10 November 2026.
- **Baseline:** `2fa22cc350956a82fe0e770d456f4455e58b6f6c`, the merged result of
  [PR #216](https://github.com/auths-dev/auths-proof/pull/216).
- **Priority:** Approval concurrency, exporter batch ownership, and SDK client
  lifecycle first; phase-specific payloads and administrative recovery next.
- **Depends on:** [AP074](0074-bound-effects-and-recovery-state-machine.md),
  [AP066](0066-production-gateway-polish-and-recipe-qualification.md),
  [AP075](0075-independent-security-boundary-assessment.md), and the
  [profile/domain boundary plan](../target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md).
- **Terms:** MUST and MUST NOT are acceptance requirements. State names below
  describe required distinctions; they do not assert that those types exist.
- **Implementation evidence:** [Requirement and delivery record](../plans/0076-implementation-status.md).

## 1. Objective and scope

Remove consequential implicit state machines from the maintained paths below.
Legal operations must follow an authoritative state and transition contract,
including competing calls, cancellation, failures, and interruption. Naming an
enum without giving it ownership of those decisions is insufficient.

The first implementation batch covers:

1. Bounded plan approval sessions in the TypeScript SDK.
2. Bounded OTLP exporter batch ownership.
3. SDK client opening, closing, and owned-resource cleanup in Python and
   TypeScript, including attached agents and owned identity/transport adapters.

The second batch covers:

4. Phase-specific submission and mutation-journal payloads.
5. A follow-on protocol design, then implementation, for installation, staged
   credential publication, retirement, and qualification-import recovery.

Implement each owner in its existing architectural layer. Preserve the native
bound-effect, approval, admission, entry, and recovery boundaries established by
AP074. SDK resource management must not become an alternate authorization model.

Writing this specification does not implement its contract, initiate production
operations, close AP075 assurance gaps, or qualify a provider or deployment.

## 2. Meaning of “no implicit state machines”

A state machine is implicit when the legality of an operation depends on
history reconstructed from scattered flags, optional payloads, callbacks, file
existence, or the position of an instruction in a function, without one owner
enforcing the allowed transitions.

Every maintained workflow involving authorization, concurrent calls, external
effects, asynchronous resource ownership, or durable recovery MUST expose:

- Its owner and the boundary at which competing events are ordered.
- Named states or sealed stage types and the data valid in each state.
- Allowed events, guards, effects, and next states.
- Rejection behavior for invalid, repeated, stale, and concurrent events.
- Cancellation, timeout, failure, and terminal-state behavior.
- Persistence and restart interpretation where the workflow is durable.

An explicit representation can be a closed enum with payloads, a discriminated
union, consuming stage types, or a small encapsulated state value with a named
transition contract. No particular framework or library is required.

Independent facts and configuration values may remain booleans. An optional
value may represent actual absence. A two-state resource or one-shot capability
may use a compact representation when its states, transition, and failure
semantics are named and enforced at one boundary. Such representations MUST NOT
conceal an opening, pending, closing, uncertain, or cleanup-failed state that
changes what callers may do. Rust ownership that consumes a capability is
already an explicit lifecycle mechanism.

The requirement applies repository-wide to new or changed workflows. The
bounded batches in this spec do not certify existing unreviewed code. Lower-risk
findings may be recorded for later work; that is deferral, not an assertion of
compliance. Do not mechanically replace every flag, cache, or `Option` merely to
increase an enum count.

## 3. Source findings and evidence boundary

The initiating review was a static source audit against the pinned baseline.
These schedules are source-derived findings, not completed reproductions and
not evidence of a downstream authorization bypass. Implementers MUST first
retain deterministic regressions that demonstrate the relevant current behavior.

| Finding | Baseline source | Consequence to reproduce |
| --- | --- | --- |
| Approval checks precede an await, while use advancement follows it. | [`approvals.ts`](../../bindings/typescript/src/approvals.ts), `BoundedApprovalSession.#approveMember` | Two calls for the same index can pass the same initial use check; a provider response can arrive after disposal or expiry. |
| Export snapshots and queue removal have separate critical sections. | [`auths-operations-otel`](../../product/operations/auths-operations-otel/src/lib.rs), `BoundedOtlpExporter::flush` | Two flushes can export the same old batch; after one removes it and another event arrives, the other can remove the new unexported event. |
| Client opening and closing span awaits without a shared pending-operation owner. | Python [`_workflow.py`](../../bindings/python/python/auths/_workflow.py), TypeScript [`orchestrator.ts`](../../bindings/typescript/src/workflow/internal/orchestrator.ts), and owned adapters | Opening can complete after closure begins; repeated close calls can return while cleanup is pending; partial cleanup failure can leave obligations hidden. |

Other findings are representation and recovery improvements, not demonstrated
vulnerabilities. Existing consistency checks, durable fences, cleanup journals,
restore floors, and conservative unknown outcomes MUST remain effective.

## 4. Common implementation contract

### 4.1 State ownership and effects

A transition consumes the current state, one event, and explicit guard inputs;
it determines the next state and the effects permitted by that transition.
Guard inputs include trusted time, operation identity, and revisions where
applicable. External completions return as events bound to the operation that
started them. An old completion MUST NOT mutate a successor or terminal state.

Publish ownership of a pending operation before invoking an external provider
or crossing an await. A mutex around individual field reads/writes is not
sufficient when the protected operation spans I/O. Do not hold the state-mutation
lock across external I/O; retain exclusive operation ownership instead.

Use exhaustive dispatch over closed states. Required payloads belong in their
state or sealed capability. For external wire formats, retain bounded decoding
and explicit integrity validation; typed in-memory states do not authenticate
persisted bytes.

The owner MUST snapshot mutable decision inputs before publishing pending
state. Keep its private snapshot separate from copies passed to external code;
`readonly`, shallow freezing, and retaining a caller's typed-array reference do
not establish byte ownership. Specify which inputs are bound, when ownership
transfers, and the result each competing caller receives. Waiter cancellation
and cancellation of the underlying operation are separate events.

An operation/state pair not admitted by its transition contract is rejected
without starting I/O or changing state. Internal stale completion events are
ignored as specified; they must not masquerade as new caller operations.

### 4.2 Failure and claim preservation

- Denial and unavailable authority remain fail closed.
- Unknown provider effect remains unknown, with capacity retained according to
  the existing owner. Cancellation is not proof of non-effect.
- Closing a client does not revoke a previously issued signature or durable
  provider-entry grant. It stops new local work under that client.
- Errors retain stable codes and truthful effect/receipt distinctions. Reuse
  existing codes where their meaning applies; specify any new public distinction
  and update its registry, bindings, and fixtures atomically.
- Do not widen accepted proofs, approvals, recipes, credential access, or retry
  rights as a side effect of a state refactor.
- Keep secret-bearing payloads scoped and zeroized only when no permitted
  in-flight operation still needs them.

## 5. Batch A: Bounded approval sessions

The owner remains `BoundedApprovalSession`. Preserve its immutable plan,
ordered member commitments, policy, and approval-response binding checks.

The machine MUST distinguish an unapproved ready session, an approval pending
for one exact member/request, an approved session at its next member, and a
terminal session with a reason such as exhausted, disposed, expired, or refused.
Pending state carries an operation identity and an owned request snapshot.

### 5.1 Cancellation API and ownership

Replace the TypeScript approval port with this direct prelaunch contract:

```typescript
export interface ApprovalOperationContext {
  readonly signal: AbortSignal;
}

export interface ApprovalProvider {
  approve(
    request: ApprovalRequest,
    context: ApprovalOperationContext,
  ): Promise<ApprovalResponse>;
}
```

`providerFor()` returns this same interface. Every maintained approval caller,
provider, threshold/composite provider, signing coordinator, public declaration,
example, and installed-package contract test MUST adopt it in the same batch.
Composite providers propagate the signal and stop starting child calls once
aborted. A caller that needs no cancellation supplies a non-aborted signal.
Remove the superseded interface; add no compatibility overload or legacy path.
This is an SDK operation context, not part of signed approval bytes or a change
to native approval verification. Python approval APIs are not silently given
new semantics: Batch A changes this TypeScript port, and any separately exposed
cross-language adapter must explicitly map cancellation or declare it unsupported.

Before starting work, check the supplied signal. An already-aborted caller
receives `ProviderOperationError("cancelled")` without consuming a member or
terminating an otherwise usable session. Once admitted, create a session-owned
abort controller for the exact pending operation. Caller abort, session disposal,
or observed expiry invalidates that operation and aborts its provider signal.
Settle the caller promptly without waiting for a provider that ignores abort;
consume any eventual rejection and ignore its stale completion. Provider abort
is best effort and does not assert that an external prompt or action was undone.

Pending cancellation terminates this session. It differs intentionally from
cancelling a waiter on a shared SDK opening operation in section 7. Cancellation
after member acceptance does not revoke the accepted approval or undo usage.

### 5.2 Immutable binding snapshot

Copy a member commitment when creating `providerFor()`, not only when invoking
its returned closure. Before pending admission, validate and defensively copy:

- Plan identity, exact member index and commitment, and session policy.
- Request ID, object kind, transaction digest, policy ID, evaluator version,
  configuration digest, request expiry, and every display label/value.
- The session deadline and next-member position that authorize this operation.

The provider receives a separate copy, including separate byte buffers. A
provider must not be able to alter the owner's comparison snapshot. Copy and
validate the returned response before accepting its decision, request ID,
transaction digest, and complete policy reference. Construct the returned
approval from the owner's snapshot, never by rereading caller/provider objects.
Object kind, membership, and displayed context remain retained request facts;
do not claim that the existing response signs fields absent from its protocol.

Shared-memory-backed byte inputs are rejected at this boundary; a copying loop
over concurrently mutable shared memory is not an atomic snapshot. A malformed,
detached, or unsnapshotable byte input raises `TypeError` from `providerFor()`
and `ProviderOperationError("rejected")` from `approve()`, before pending
admission. These ownership rules add no new cryptographic commitment or
alternative wire representation.

### 5.3 Transition and caller-result contract

| Current state / event | Required behavior |
| --- | --- |
| Ready / request for the next exact member | Atomically claim the owned snapshot, enter pending, then invoke the provider once with the operation signal. |
| Pending / another member request, including the same index | Return `ProviderOperationError("rejected")` without changing the pending operation, invoking the provider, or advancing usage. |
| Pending / valid matching approval at or before both deadlines | Accept only the matching operation, advance exactly once, and return approval from the owned snapshot; publish approved or exhausted state. |
| Pending / explicit provider refusal | Return the validated rejected response, terminate as refused, and do not advance usage. |
| Pending / malformed response or provider failure | Terminate without advancing usage; malformed responses return `rejected`, typed provider errors preserve their kind, and untyped provider errors become `unavailable`. No implicit retry. |
| Pending / disposal or caller abort | Terminate as disposed or cancelled, invalidate completion, abort the provider signal, and return `cancelled` to the pending caller. |
| Pending / session or request expiry | Terminate with the distinct expiry reason, invalidate completion, abort the provider signal, and return `timeout`. |
| Approved / next exact member | Check policy, membership, cancellation, and time and atomically advance one use under the retained plan approval. |
| Ready or approved / already expired request, while session remains valid | Reject only this call with `timeout`; keep the same next member and retained approval state. |
| Ready or approved / disposal | Terminate as disposed and return disposal success without provider I/O. |
| Any live state / observed session expiry | Permanently terminate the session; return `timeout`. |
| Any terminal state / request or late completion | No work or usage advancement. New calls receive `cancelled` for disposed/cancelled states, `timeout` for expiry states, otherwise `rejected`; stale completions are ignored. |
| Any terminal state / disposal | Return disposal success idempotently; retain the original terminal reason and do not revive or overwrite a prior outcome. |

Malformed/mismatched membership or policy before pending admission rejects only
that call. On admission and completion, first honor an already committed terminal
state, then caller abort, session expiry, request expiry, and binding/order checks.
Acceptance is the atomic commit after those checks. A later abort cannot win
retroactively. A competing request cannot cancel or time out the pending owner
merely by supplying its own cancelled/expired context.

Time MUST be checked before invocation and immediately before accepting a
response. Equality is valid: `now <= session.expiresAt` and
`now <= request.expiresAt`; expiry means strictly greater. Observing request
expiry after that request entered pending terminates the entire session; an
expired request rejected before admission does not. This conservative choice
requires a fresh session after an interrupted external approval.

Track a nondecreasing effective time using the maximum of samples from the
session's configured clock, including construction. A backward sample cannot
extend validity or revive a terminal session; it does not by itself prove that
an unobserved deadline passed. Caller abort and disposal must wake pending work
without a provider completion. A pending deadline watchdog MUST resample the
configured clock after the earliest inclusive deadline can have elapsed and
settle the call when effective time is strictly greater, even if the provider
never completes. Reschedule bounded timer intervals when necessary; timer
delivery alone is not evidence of expiry. Tests control both clock samples and
scheduler wake-ups. Expiry is also checked at every guarded event. No additional
promise of trusted host-clock synchronization is introduced.

The TypeScript session exposes an optional `ApprovalDeadlineScheduler` paired
with its existing configurable clock for deterministic embedding and tests.
Its `schedule(callback, delayMs)` returns a cancellation function. The production
default uses bounded platform timers. A scheduler wake-up never supplies time or
approval authority; the owner resamples its clock and applies the same guards.

Only successful member acceptance advances usage. No operation may skip an
index, approve twice for one index, or exceed `maxUses`. The retained plan
approval cannot authorize a different plan, member, request binding, or policy.
Disposal must prevent new approvals immediately and describe whether an
uncooperative provider is still pending; it must not claim that external work
was stopped merely because its completion will be ignored.

## 6. Batch B: Exporter batch ownership

The owner remains `BoundedOtlpExporter`; its transport remains an I/O port.
Represent queued events and an optional exclusively owned in-flight batch,
including a batch/cohort identity. Export acknowledgement applies to that batch.
The states are `Idle(queue)`, `Exporting(cohort, batch, queue)`, and
`Unavailable(retainedEvents, cause)`. Completed cohorts retain their result until
their joined callers can observe it, even if a later cohort has already started.

1. A flush atomically takes ownership of one ordered batch before exporting.
2. At most one export is in flight. A call observing `Exporting` atomically joins
   that cohort and waits for its result. It MUST NOT start a second export,
   retry a failed batch, or re-evaluate the newer queue as part of that call.
3. Recording may append events while a batch is exported. A success removes
   only the acknowledged in-flight batch, never a count of arbitrary queue heads.
4. A normal failure restores or retains the batch ahead of newer queued events.
   The initiator and joined callers all receive the same `ExportError`. Retry
   requires a new explicit call admitted after that cohort completed.
5. Capacity and readiness count queued plus in-flight events. Moving a batch out
   of the queue MUST NOT double the configured memory capacity. Preserve bounded
   admission and existing drop accounting under the selected backpressure policy.
6. Export-failure counters and readiness derive from the same authoritative
   state; success cannot acknowledge unrelated events.

An idle flush with no queued events returns success without transport I/O. A
successful cohort acknowledges only its captured batch: events recorded later
remain queued even when joined flush callers return success. Each transport
attempt increments failure accounting at most once, regardless of waiter count.
The API docs must state this snapshot boundary so callers do not interpret flush
success as covering events recorded after their cohort began.

Direct reentrant `flush()` on the exporting thread returns
`ExportError::Unavailable` immediately; it does not join, wait, poison the
owner, or start I/O. Recording from the transport remains supported. The
`OtlpTransport` contract MUST prohibit synchronously waiting for another thread
to flush the same exporter: general cross-thread dependency cycles cannot be
detected by this owner. Include this restriction in adapter conformance notes.

If transport panics with unwinding enabled, an ownership guard retains the
batch, marks the exporter `Unavailable`, and wakes joined callers with
`ExportError::Unavailable`; the initiating caller's panic continues unwinding.
Subsequent flushes return unavailable and do not retry. State-lock poisoning has
the same fail-closed readiness/flush result. An unavailable exporter rejects new
recording with drop accounting where its state remains accessible; it cannot
report an empty healthy queue or discard retained events as acknowledged.
Replacing or destroying it is an explicit operational reset of volatile state,
not delivery confirmation. Process abort/crash cannot run an unwind guard and
may lose this in-memory queue; durability is outside this exporter contract.

Delivery remains subject to transport ambiguity. If the destination accepted a
batch and its acknowledgement was lost, a later retry may duplicate it. This
spec prevents local overlapping ownership and silent local loss; it does not
claim exactly-once remote telemetry delivery or introduce durable telemetry.

## 7. Batch C: SDK opening, closing, and cleanup

Each maintained client/resource owner MUST distinguish the applicable states:
`New`, `Opening(operation)`, `Open(resources)`, `Closing(operation, obligations)`,
`ClosingOverdue(operation, obligations)`, `Closed(reason)`, and
`CleanupFailed(obligations, failure)`. Factory-created open clients need no
artificial `New` state. Represent operation outcomes separately from waiter
outcomes: one caller timing out does not mean the resource stopped operating.

### 7.1 Public wait and retry contract

Existing TypeScript opening factories, attachment calls, and `dispose`/`close`
methods accept per-call `signal?: AbortSignal` and `timeoutMs?: number` options.
Existing no-argument calls remain normal calls without a deadline, not legacy
overloads. `Symbol.asyncDispose()` delegates with no per-waiter cancellation.
Python `open`, `attach_agent`, and `aclose` accept optional keyword-only
`timeout: float | None`; task cancellation is that caller's cancellation event.
Add `retryCleanup(options?)` / `retry_cleanup(*, timeout=None)` to resource owners
that retain failed owned-resource cleanup. Update affected public protocols,
declarations, fixtures, examples, and package tests in the implementation batch.

An already-cancelled/expired waiter does not start or join work. Once started,
opening and cleanup tasks belong to the owner. Cancelling or timing out any open
waiter only detaches that waiter, including when it is the last waiter; the
opening operation continues until it succeeds, fails, or the owner is closed.
Use cancellation shielding in Python and equivalent operation ownership in
TypeScript. A late successful factory result with no accepting waiter MUST be
closed and retained by the factory owner until cleanup settles; it must not
become an unreachable live client.

No implicit default shutdown timeout is introduced. A finite timeout on the
call that starts a close/retry also sets that cleanup generation's monotonic
deadline. Later callers may set shorter deadlines for their own waits but cannot
extend or replace the generation deadline. Timeout values must be finite and
positive; omit them for no deadline. At a generation deadline, unfinished
cleanup becomes `ClosingOverdue`, all current generation waiters receive an
explicit incomplete-cleanup error, and owned work continues. This deadline
neither cancels destructors nor releases their resources. Subsequent close calls
while overdue immediately report incomplete cleanup; they do not start retries.
Late settlement still transitions to `Closed` or `CleanupFailed`.

Python caller cancellation raises `CancelledError` and per-waiter open/attach
timeouts raise `TimeoutError`. TypeScript uses the existing workflow error
boundary with cancellation/timeout in its bounded cause chain. Failed or overdue
cleanup uses Python's `cleanup-failed` / TypeScript's existing `signer-failed`
cleanup boundary, with `cleanup-incomplete` distinguished from a settled failure
in the bounded cause chain. A closed-owner rejection uses the existing disposed
boundary. Do not report any of these as proof that a provider effect was undone.

### 7.2 Lifecycle transition table

| Current state / event | Next state and caller result |
| --- | --- |
| New / open | Publish one `Opening` operation before initialization. Concurrent opens join it. |
| Opening / one waiter cancels or times out | State unchanged; detach only that waiter. Other open waiters remain eligible for the same result. |
| Opening / initialization succeeds, no close committed | Publish `Open` and settle remaining open waiters successfully. |
| Opening / initialization fails | Never retry opening on this instance. Invalidate publication and start one cleanup generation for acquired resources; promptly return the original opening failure to remaining open waiters and retain cleanup progress/failures on the owner. |
| Open / open | Return this open instance without reinitializing. |
| New, Opening, or Open / first close | Atomically enter `Closing`, invalidate opening/attachment publication, reject pending open waiters as disposed, stop new work, and start one cleanup generation. |
| Closing / another close or retryCleanup | Join the same generation and observe the same cleanup result, subject only to this waiter's cancellation/deadline. No duplicate cleanup starts. |
| Closing / one waiter cancels or its earlier private timeout elapses | Detach only that waiter. Shared cleanup and other waiters are unchanged. |
| Closing / generation deadline | Enter `ClosingOverdue`; report incomplete cleanup to its waiters and retain the running operation and obligations. |
| Closing or ClosingOverdue / cleanup settles successfully | Enter `Closed`; cleanup is finished. Late observation after an earlier timeout may report success on a subsequent close. |
| Closing or ClosingOverdue / cleanup settles with failures | Enter `CleanupFailed`; retain only unresolved obligations and the settled failure. |
| CleanupFailed / ordinary close | Return the retained failure; do not implicitly retry. |
| CleanupFailed / explicit retryCleanup | If the adapter contract permits safe retry of the retained obligations, publish one new `Closing` generation. Otherwise return the retained unresolved failure without repeating an ambiguous action. |
| Closed / close or retryCleanup | Return success without repeating cleanup. |
| Opening, Open, New / retryCleanup | Reject invalid lifecycle operation; it does not initiate shutdown. |
| ClosingOverdue / retryCleanup | Return incomplete cleanup; the old generation still owns work. |
| Closing, ClosingOverdue, CleanupFailed, or Closed / open, attach, or new work | Reject as disposed. No reopening or publication. |

A failed opening with no resources to clean reaches `Closed(open-failed)`
directly. Otherwise its opening failure is retained while closure proceeds, so
error handling cannot hide unfinished cleanup. An initialization completion
invalidated by close becomes an event of the closing owner, not an open result.
Only `Open` admits attachment or new resource-using work; `New` and `Opening`
reject those calls as not open through the existing disposed error boundary.

### 7.3 Attachment and in-flight ownership

Register an attachment operation with the client before its first await.
Capture the client's live generation and owned input snapshot. Attachment
success may publish an agent only if that generation is still open at the
publication commit. Close that commits first invalidates publication, rejects
the attachment caller as disposed, and retains any late-created agent, signer,
or material as cleanup obligations. Close cannot finish while a pending
attachment may still return an owned resource. Conversely, an agent published
first is registered before close can snapshot cleanup obligations. There is no
interval in which an agent is live but owned by neither the caller nor client.
Attachment-waiter cancellation/timeout invalidates that attachment's publication
without closing the client; late resources still belong to the client for cleanup.

Existing authorized operations may drain to their recorded result. Stop starting
new work when close commits, but do not reinterpret cancellation as rollback or
mint a new provider-entry right. Retain an operation/resource ownership token
until each active call finishes. Zeroization, signer destruction, and resource-map
removal follow the last permitted use. Failure or overdue status preserves those
obligations rather than freeing resources still in use.

Attempt every independently owned cleanup even if one fails. Borrowed adapters
and signers are never closed by the borrower. A retry includes only retained
unresolved obligations whose adapter contract permits it; successful cleanup
and ambiguous non-idempotent destruction are not automatically repeated.

Apply the contract to `AuthsClient`, attached agents, and the owned adapters
they close. Review the existing Python and TypeScript remote/identity clients
that already name `closing`: a named state alone does not supply a shared close
operation or correct partial-failure behavior. Do not move resource management
into the offline verifier or merge unrelated adapter semantics.

## 8. Batch D: Phase-specific payloads and administrative recovery

### 8.1 Submission and mutation journal

Retain the existing `auths-gateway-kernel` order/transition predicates and
`GatewayAttempts` transaction boundary as the owners. Refactor their consumers
instead of introducing another executor or journal.

For `submit::Run`, describe which phases require an approved effect, claim,
lease, entry permit, or response. Use closed payload variants or sealed stage
values so a provider-write operation cannot be constructed without its required
acknowledged permit. The driver still performs only effects the existing machine
names. Any fallback for an impossible internal combination must be eliminated
by construction or retained as an explicit fail-closed invariant failure.

For mutation records, replace independent optional lifecycle payloads where a
closed phase can own the required refusal, response, observation, or recovery
evidence. Keep independent recipe options independent. Acquisition and disclosure
already use payload-carrying phases: compare their mechanisms without conflating
their different evidence or terminal claims.

Untrusted decoding, canonical bytes, immutable effect identity, revisions,
one-use entry, counters, late evidence, and unknown-effect retention must preserve
their existing meanings. Where a serialized shape intentionally changes, update
schema identities, fixtures, all maintained consumers, formal links, and
obsolete-state rejection together. No compatibility readers or dual journals.

### 8.2 Installation and credential recovery

This subsection sets requirements for a follow-on protocol design. It is not
yet a command/transition contract; section 8.4 is a prerequisite to changing
runtime recovery behavior under this batch.

First map existing facts and owners: installation/draft/proposal files,
`SharedConnection`, credential custody, `CredentialJournal`, generation floors,
and the native candidate-acquisition/publication path. Classify which are
authority, retained evidence, cleanup obligations, and diagnostic projections.

Expose a closed recovery description that distinguishes at least:

- Uninitialized, installation inputs retained, and credential candidate staged.
- Candidate checks incomplete/refused, ready for publication, and published.
- Superseded credential awaiting its retirement deadline, deletion pending,
  deletion incomplete/uncertain, and deletion confirmed.
- Installation unavailable or inconsistent and quarantined for operator action.

These are distinguishable conditions, not necessarily one linear enum. Model
orthogonal installation and retirement lifecycles separately. The description
must derive from current authoritative facts; it MUST NOT become a competing
ledger capable of authorizing entry or overriding custody uncertainty.

Preserve write-ahead cleanup notes, generation/commitment checks, restore floors,
minimum retirement delay, and native approval of credential-bearing reads.
Publication success and cleanup success must remain separate facts. Restart must
not erase an unresolved cleanup obligation or permit deletion earlier than the
existing safety bound. An unreadable journal is unavailable, never empty.

For each partial condition, specify the existing or revised trusted command
that may advance it, exact required evidence, repeat behavior, and possible
failure result. Operators must not have to infer recovery actions from filenames
or mistake manifest presence for a serviceable installation.

### 8.3 Qualification import

This protocol has the same section 8.4 prerequisite. Existing qualification
semantics remain authoritative while its concrete design is being completed.

Specify prepare, retained revocation-memory advancement, bundle publication,
and cleanup as an explicit import protocol using the existing configuration and
qualification owners. Enumerate interruption before and after each durable
write/rename, including first import and replacement of an existing bundle.

The recovery description must distinguish staged inputs, current published
inputs, retired inputs, and an unavailable publication. Revocation memory is
monotonic: recovery cannot restore an older bundle by lowering its accepted
floor. Missing current inputs after interruption must remain fail closed until
a valid explicit completion/import succeeds. Do not add automatic security
rollback, grace periods, or a second qualification authority.

### 8.4 Administrative recovery design gate

Before implementing sections 8.2–8.3, complete and review a protocol amendment
here or a separately numbered specification under `docs/specs`, and link it
from this section. The concrete protocol amendment is [AP-SPEC-077](0077-administrative-recovery-protocol.md), which defines command identities, authority, transition tables, competing writers, durability ordering and the interruption matrix. Runtime completion is tracked separately in the implementation record.
This is an engineering design gate, not a new user-permission workflow. Runtime
work on sections 5–7 and the payload refactor in 8.1 need not wait for it.

The design MUST contain all of the following, with no unresolved behavioral
choices in the selected protocols:

1. **Authority map.** Name each existing owner, record/file, custody generation,
   floor, and evidence object; identify which facts authorize which transitions.
   Explain how the status projection avoids becoming another authority.
2. **Commands and results.** Give exact CLI/API command names, inputs, required
   evidence, authentication boundary, output/error mapping, and repeat behavior.
   A lost acknowledgement must have an explicit inspect/retry rule for the same
   operation identity, including what distinguishes replay from conflict.
3. **Transition tables.** For each state/command, state guards, revision checks,
   durable updates, external effects, successor state, and caller result. Include
   invalid transitions, revoked connections, superseded candidates, conflicting
   staged generations, partial deletion, and unavailable/corrupt authority.
4. **Competing administrators.** Define the ordering boundary for two installs,
   stage/publish, rotate/revoke, enable/disable, retire/rotate, two cleanup calls,
   and two qualification imports. Include live entry racing an admin change.
   State which caller wins, which sees conflict/replay, and which durable facts
   a losing caller must reload. Local file locks alone cannot order hosts
   sharing a native store; preserve its revision/fence authority.
5. **Durability contract.** Define the storage topology and supported crash
   model. Order file contents, file synchronization, atomic replacement/rename,
   affected parent-directory synchronization, journal/floor updates, native
   store commit, and custody acknowledgements. State the exact point at which a
   command may report durable publication. A successful `rename` or transaction
   response alone must not be assumed to persist unrelated filesystem/custody
   facts. State same-filesystem requirements and refuse unsupported layouts or
   durability guarantees rather than silently weakening them.
6. **Interruption matrix.** At every ordered write, synchronization, rename,
   custody mutation, and native commit boundary, record the possible retained
   facts, startup classification, permitted recovery command, and forbidden
   effects. Include a failed/unknown acknowledgement, interruption immediately
   after success was acknowledged, and restart after acknowledged publication.
   Specify process-crash versus storage/power-loss evidence separately. Any
   monotonic-time retirement deadline needs a conservative restart interpretation
   anchored to retained facts, not a freshly reset timer permitting early deletion.
7. **Evidence map.** Map every transition and interrupted condition to its test
   owner, adapter/topology, injected fault, and expected observable result.
   Repeated commands, competing operators, and monotonic revocation/generation
   facts must appear explicitly, not just as generic invariants.

The review must resolve any contradiction between command acknowledgement,
post-restart interpretation, and cleanup obligations before runtime changes.
If the required atomicity is unavailable across current stores, specify
conservative intermediate states and explicit recovery; do not invent a hidden
distributed transaction or claim that multiple independent commits are atomic.

## 9. Required evidence and acceptance

Use controlled completions, barriers, deterministic clocks, and actual durable
fault points. Sleep-based timing tests alone are insufficient. Map tests to
requirements and write each complete implementation/test batch before execution,
following the repository's batch discipline and GitHub-first verification policy.

| Gate | Required evidence |
| --- | --- |
| A1 | Suspend the first provider approval; submit the same index and a later index concurrently. Exactly one provider request starts and no competing call advances usage. |
| A2 | Hold a matching approval response until after disposal, caller cancellation, session expiry, and request expiry in separate cases. No member is approved by the late completion. |
| A3 | Exercise mismatched response, refusal, provider error, last valid member, exhausted session, and replay. Binding and count invariants hold. |
| A4 | Mutate original member commitments after `providerFor`, request/policy digests and display objects while approval is pending, and provider-visible copies before completion. Only the owner's original snapshot controls comparison and returned approval. Reject shared-memory-backed and detached inputs. |
| A5 | Exercise already-aborted callers, in-flight abort with a provider that ignores the signal, threshold propagation, and abort immediately before/after the acceptance commit. Verify prompt caller settlement, no unhandled late rejection, and no retroactive undo. |
| A6 | Test equality at each deadline, strictly later samples, a backward sample before any observed expiry, and rollback after expiry. With no provider completion, drive deadline watchdog wake-ups explicitly. Pre-admission request expiry leaves the session usable; pending request expiry terminates it. Effective time never decreases. |
| B1 | Reproduce two flushes selecting the same old event, then insert a new event between acknowledgements. The corrected implementation neither overlaps local batch ownership nor discards the new event. |
| B2 | Hold export pending while recording to capacity; exercise both backpressure policies, failure, retry, and exporter unavailability. Total retained events stay bounded and accounting remains truthful. |
| B3 | Join several flush callers to a suspended failing export. All receive its error, exactly one failure is counted, and no waiter retries. A later new call may explicitly retry the retained oldest batch. On success, joined callers do not flush later queued events. |
| B4 | Exercise direct reentrant flush, record-during-export, transport panic/unwind, and state-lock poisoning. Reentry returns unavailable without deadlock; unwind releases waiters, retains the batch in unavailable state, and does not allow implicit retry or false readiness. |
| C1 | Interleave two opens, open/close, and two closes with a suspended adapter. Initialization happens once, closure cannot publish a later open, and close waiters share the cleanup outcome. |
| C2 | Cancel a close waiter, fail one owned adapter while another still needs cleanup, and retry retained obligations. Borrowed resources remain untouched and successful cleanup is not repeated. |
| C3 | Hold an active operation through shutdown and its deadline. Verify the documented drain/cancel policy, safe zeroization order, and absence of false `Closed` success. |
| C4 | Cancel/time out one of multiple open waiters, then all waiters. Remaining waiters still observe the same operation; an abandoned factory success is cleaned up rather than leaked. Failed opening cannot be retried on the same instance. |
| C5 | Suspend attachment and race its publication against close, attachment cancellation, and attachment timeout in both event orders. Every late resource remains owned for cleanup; no disposed client publishes an agent. |
| C6 | Reach cleanup failure, call ordinary close again, then start a safe explicit retry while more close/retry callers arrive. Ordinary close never implicitly retries; all retry participants share one generation and only unresolved safe obligations are repeated. |
| C7 | Distinguish an earlier private waiter timeout from the initiating cleanup generation deadline. After the latter, verify `ClosingOverdue`, retained running work, immediate incomplete result for new close/retry calls, and late success/failure settlement. |
| D0 | Before administrative recovery implementation, link the reviewed section 8.4 protocol with complete command/transition tables, durability assumptions, competing-admin outcomes, and interruption-to-test matrix. A prose task list cannot satisfy this gate. |
| D1 | Differentially compare decisions, compiled commands, entry counts, state projections, receipts, and counters before/after payload refactoring using maintained fixtures. Test hostile invalid persisted combinations. |
| D2 | Interrupt installation, staging, publication, retirement, and cleanup at each durable boundary; restart and perform the documented operator action. No new entry right, premature retirement, or forgotten cleanup results. |
| D3 | Interrupt first and replacement qualification imports around every write/rename. Revocation memory never regresses and missing/invalid current authority refuses entry. |
| D4 | Execute the reviewed protocol's repeat/conflict matrix with two administrative actors and live entry where applicable. Restart immediately after acknowledged publication and after lost acknowledgements; confirm the promised durable result or explicit conservative uncertainty under the stated crash model. |
| P1 | Review each affected workflow against the AGENTS.md rules in section 10 and link its authoritative transition implementation and tests. |

Durable native journal changes require applicable file and configured TLS
PostgreSQL coverage, including commit/reply-loss histories where affected. Local
installation filesystem protocols require real file/restart evidence; a database
test is not a substitute. SDK changes require installed-package regression
coverage for the affected language and ownership contract. Extend existing test
owners and retained scenarios rather than creating a parallel assurance system.

Run hosted checks appropriate to each bounded implementation PR and the required
repository gates. Report the exact tested revision, commands/jobs, results, and
remaining limitations. Do not claim a formal proof from an independently written
model or infer whole-repository compliance from this finite matrix. Update
existing translated predicates and proof/semantic manifests when they change;
this spec sets no unrelated formal-coverage target.

## 10. Required AGENTS.md update

This specification proposes the following addition under **Implementation
standards**, as a subsection named **Explicit state ownership**. Implementing
the first batch MUST include this policy update. The proposed text is not an
assertion that AGENTS.md has already changed.

> No implicit state machines are allowed in new or changed workflows. If legal
> next operations depend on history, identify one authoritative state owner and
> enforce its named states, events, guards, required payloads, and transitions.
> This includes asynchronous resource ownership, authorization, concurrency,
> external effects, and durable recovery.
>
> Do not distribute a lifecycle across unrelated flags, optional fields,
> callback-local variables, filesystem markers, or duplicate status records.
> Independent facts may remain booleans and actual absence may remain optional.
> Compact two-state or consuming representations are valid when their named
> transition contract is enforced in one place and hides no consequential
> pending, closing, failed, or uncertain state. Replacing flags with an enum
> without fixing transition ownership does not satisfy this rule.
>
> Claim pending-operation ownership before external I/O or an await. Bind each
> completion to that operation; recheck guards that may change while waiting.
> Snapshot mutable decision inputs into owner-controlled memory before pending
> admission; pass separate copies to external code and validate completions
> against the retained snapshot. Readonly fields and shallow freezing do not
> establish byte ownership. Specify exact bound fields and ownership transfers.
>
> Define what each competing or reentrant caller receives: rejection, a shared
> operation result, or a new operation. Distinguish cancellation/deadlines of an
> individual waiter from cancellation/deadlines of the owned operation. Define
> late-completion, cleanup failure/retry, and resource-publication behavior.
> A terminal flag must not stand in for unfinished cleanup, and an error or
> cancellation must not be treated as proof of non-effect.
>
> Keep one semantic authority for each managed transition. Extend the existing
> kernel, journal, or resource owner; do not add a parallel executor, recovery
> ledger, or universal lifecycle framework. Persist necessary recovery facts
> through the existing durable boundary and derive status from those facts.
> Preserve provider/domain distinctions and the abstraction extraction gates.
>
> Every change to such a workflow must document its states and ownership boundary
> and add deterministic evidence for relevant competing events and failures.
> Durable changes require applicable crash/restart and adapter evidence. Review
> phase-specific payloads and invalid transitions, not just the happy path.
> Before changing a recovery protocol, finish its command/transition tables,
> competing-writer results, durable acknowledgement/synchronization ordering,
> and interruption matrix. Naming those as future design tasks is insufficient.
> Follow AP-SPEC-076 for the initial remediation inventory and acceptance gates.

Also add a short **Stateful change review** checklist to AGENTS.md's testing and
handoff guidance. The PR description or linked spec must answer:

1. What history changes the legality of the next operation, and who owns it?
2. What orders competing/reentrant events, what identifies a completion, and
   which result does each caller observe?
3. What data/capability is required by each phase, who can construct it, and
   which mutable inputs are copied before crossing an asynchronous boundary?
4. How do waiter cancellation and operation cancellation differ? What happens
   on timeout, stale completion, late resource creation, and partial cleanup/retry?
5. Where is durable success acknowledged, which synchronization/commit facts
   support it, and what happens on repeated commands, competing writers, lost
   acknowledgements, and restart immediately after acknowledged success?
6. Which exact tests exercise those schedules and preserve effect/receipt truth?

These are engineering review requirements, not a new user-approval step. A
regex ban on booleans or optional values cannot establish compliance. Start
with transition ownership and focused regressions; any later automated
inventory must supplement review and avoid duplicating executable state facts.

## 11. Delivery order and completion boundary

1. Land the AGENTS.md policy with the first bounded correction. Implement
   approval ownership, exporter ownership, and SDK lifecycle handling as
   independently reviewable changes with their complete regression batches.
2. Refactor submission/journal payloads against the retained native owners and
   differential corpus. Preserve wire semantics unless an explicit direct
   cutover is necessary and fully recorded.
3. Complete and review the section 8.4 follow-on protocol, including commands,
   competing administrators, durability, and interruption tables. Only after D0
   is satisfied, implement administrative recovery using existing journals and
   floors and close its full interruption matrix.
4. Record each gate's evidence and disposition in this spec or a linked
   implementation record. Unimplemented batches and deferred audit findings
   remain visible; none are silently marked compliant.

Completion means all five scoped areas satisfy their applicable gates and the
AGENTS.md guidance is in force. Sections 5–7 may be implemented and accepted
independently while administrative recovery remains explicitly design-blocked;
that does not close the whole initiative. It does not mean every state machine
has been audited, every schedule has been proved, remote telemetry is delivered
exactly once, AP075's independent-review gates are closed, or production
qualification has been granted. Caches, simple one-shot wrappers, and demo UI
rewrites are outside these implementation batches unless they expose a required
failure or participate in an affected owner.
