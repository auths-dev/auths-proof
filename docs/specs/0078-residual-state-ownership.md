# AP-SPEC-078: Residual operation ownership and interrupted publication

- **Status:** Implementation contract; acceptance requires the evidence below.
- **Date:** 11 November 2026.
- **Baseline:** `e40bfdd32e3812ef349bb2db84faada443cb1938`, merged PR #217.
- **Predecessors:** [AP076](0076-explicit-state-ownership-and-concurrency.md),
  [AP077](0077-administrative-recovery-protocol.md), and root AGENTS.md.

## 1. Objective and evidence boundary

Close the consequential residual ownership gaps found by the follow-up static
audit. Preserve useful explicit state machines and existing authorization,
transaction, signature, replay, and native entry authorities. The findings are
source-derived schedules, not a claim that authorization was bypassed. This
bounded remediation does not certify every workflow in the repository.

The implementation includes nine owners: gateway serving sockets; SQLite
reservation workers; TypeScript signing completion; exchange channel failure;
development software-key publication; reference lifecycle file persistence;
Northstar demo state transitions; REST demo request attribution; and incident
viewer refresh publication. Each fix belongs in its existing package. Do not
introduce a universal state-machine framework, duplicate execution ledger, new
provider entry right, compatibility reader, or advisory exception.

## 2. Gateway serving ownership (S)

### 2.1 Existing failure and required owner

The gateway drops listeners before draining admitted sessions. A replacement
process can then recover their refused socket paths; the old process subsequently
unlinks the replacement's live sockets. Stale-path detection and startup cleanup
also operate on pathnames without retaining the identity they own.

One serving claim MUST span `Claimed -> Starting -> Serving -> Draining ->
Cleanup -> Released`, including startup failure. Acquire it before binding or
recovering socket paths; competing starts fail promptly with a bounded diagnostic
and cannot remove sockets. Use the existing private-file/advisory-lock mechanism
with a distinct serving lock so administrative operations remain usable during
service. Do not unlink the lock file when releasing its lock. Endpoint claims
must also serialize competing owners when installation directories differ.
The supported topology uses one fixed serving lock per canonical, protected
socket parent directory, deduplicated and acquired in stable order. Distinct
daemons must use separate socket parent directories even for differently named
sockets. This conservative restriction covers case-insensitive filesystem
aliases without guessing filename collation. Validate parent ownership,
permissions and canonical path before claiming or binding an absent socket.

Socket cleanup retains the identity of the socket actually bound (device/inode
on Unix) and removes only that identity. A mismatched replacement remains intact.
Hold serving/endpoint claims through listener closure, session drain, and owned
socket cleanup. Startup errors release claims only after cleaning resources
created by that startup. Existing private-parent, owner, socket-type and live
listener checks remain. Locks order processes; socket identity prevents a stale
destructor from deleting a successor. Neither mechanism replaces native fences.

### 2.2 Results and interruption contract

| Event | Required result |
| --- | --- |
| Second start while first serves or drains | Explicit busy/start failure; no unlink, bind, or readiness publication. |
| Failure after one socket binds | Remove only that startup's owned inode; release claims afterward. |
| Normal shutdown | Stop admission, drain real admitted work, remove owned sockets, release claims. |
| Process termination | OS releases claims; next start may recover the dead socket under a new claim. |
| Drain deadline expires with work still admitted | Report shutdown incomplete and terminate the process while claims remain held; OS releases them only as the process terminates. Do not drop ownership and continue returning through a live runtime. |
| Foreign/replaced pathname during cleanup | Preserve replacement; do not claim ownership from pathname existence. |

## 3. SQLite reservation worker ownership (Q)

`SQLiteAtomicReservationStore` currently uses `_closed` while `to_thread`
workers may outlive cancelled waiters and successful close. The adapter MUST
retain actual admitted workers until their underlying transaction completes.
Its states are Open, Closing, and Closed, with admitted work owned independently
of each waiter. Register ownership before scheduling foreign/thread work.

Cancellation of one reserve waiter detaches that waiter; it MUST NOT cancel or
forget the worker. Close stops new admission and joins all admitted work before
returning success. Concurrent close calls join one cleanup operation; cancellation
of a close waiter does not cancel cleanup. Worker failure settles the associated
reservation result and is consumed even when no waiter remains. Closed means
quiescence. Reopen creates a new instance; it does not reopen the old owner.

Keep `BEGIN IMMEDIATE`, primary-key uniqueness, exact replay/conflict results,
bounded record validation and per-operation connection ownership unchanged. A
cancelled waiter never certifies rollback. Document these semantics on the
adapter without exporting a new generic lifecycle framework.

Retain an immutable bounded snapshot of the reservation key, commitment and value
before worker admission. A frozen dataclass alone does not establish ownership of
caller-provided byte buffers.

## 4. TypeScript signing acceptance (T)

The existing one-use coordinator remains the signing owner. Retain its exact
transaction deadline and bound request facts before provider entry. Its logical
phases are Prepared, AwaitingApproval, AwaitingSignature and Terminal; a compact
consuming owner is valid if those transitions remain enforced at its boundary.

After the signer await and before native completion, observe trusted operation
time again. Equality at `expiresAt` remains valid; a later observation rejects
with existing `transaction-expired`, never calls native completion and leaves
the transaction consumed. Effective observed time must not move backward within
one operation. Preserve exact signer response/principal/digest validation,
bounded copies and native cleanup on all paths. Do not reinterpret local signing
request expiry as global revocation or undo a signature already released by an
external signer. Existing ResourceLifecycle cancellation and late-publication
ownership remain authoritative; do not introduce a second cancellation owner.

## 5. Exchange channel interruption (E)

The stream, Iroh, memory and HTTPS exchange owners must distinguish a preflight
rejection from an admitted I/O attempt. A binding/size rejection before I/O may
leave the prior phase reusable. Once an operation may have consumed/transmitted
bytes or delivered a submission, cancellation, timeout, transport failure,
malformed response or peer termination MUST NOT silently restore that phase.

Use phase-bearing channel states or a consuming operation guard. Before I/O,
transition to an in-progress/unavailable state. Only a successful complete
operation advances to its specified successor; dropping an admitted operation
leaves the channel unusable for another semantic exchange. New calls return the
existing sequence/transport error without I/O. A fresh connection/channel is
required; this is not permission to replay an external effect automatically.

Apply the same rule to raw Iroh frame reading/writing: a partially transferred
frame cannot be treated as a clean boundary. Retain independent send/receive
capabilities only where their contract supports it; terminal failure must prevent
the affected stream from being reused. Finishing a stream records terminal send
ownership before awaiting acknowledgement. Preserve wire bytes, bounds, peer
observations, challenge binding, and the one-submission port contract.

## 6. Development software-key publication (K)

The final key pathname MUST mean one fully written key. Creation is one owned
operation: Absent -> PrivateStaging -> PublishedUnacknowledged -> Installed.
Stage the full seed in a private same-directory file, synchronize its contents,
publish without replacing an existing key, synchronize the parent directory,
then acknowledge the installed principal. Preserve owner-only mode, exclusive
publication, secret zeroization and exact-length validation. Readers observe
absence or a complete key; they never read an in-progress staging file as the
installed identity. Concurrent creators produce at most one installed key.

| Interruption | Required interpretation/action |
| --- | --- |
| Before final publication | No installed key; staging is private/unpublished and may be cleaned conservatively. |
| After publication but before parent sync/ack | Complete final key may exist; failure does not certify absence. Load/verify that exact installed key; never overwrite or silently create another identity. |
| After acknowledged publication | Reopening under the supported synchronization model yields the same complete key. |
| Existing malformed final key | Reject explicitly; do not replace it or introduce a legacy decoder. |

Tests distinguish injected process interruption from physical power-loss claims.
This is development software custody, not a change to KMS/PKCS#11 custody or
trusted distribution of Git revocation records.

## 7. Reference lifecycle file persistence uncertainty (P)

The file store currently replaces its durable snapshot before updating memory.
An error after replacement leaves the same live instance operating on stale
memory. Add an explicit usable/unavailable owner distinction under its existing
mutex. Once persistence may have replaced the file, an error MUST prevent all
subsequent reads, exact replay acknowledgements, capacity decisions and mutations
from consulting the old snapshot. Conservatively make the instance unavailable
after any persistence error; reopening is the explicit recovery operation.

Reopen validates the existing canonical file and restores one current snapshot.
It must not silently roll back or merge an obsolete memory image. Existing
transition semantics, revision checks, PostgreSQL transactions and wire formats
remain. This owner serves reference/demo callers; the gateway attempt store is
a separate authority. An error before persistence has no external transition,
but uniform poisoning is permitted to keep the contract small and conservative.

## 8. Demo state and view publication

### 8.1 Northstar server (B)

Parse and validate bounded request bodies before entering a state transition.
Then load the current state, check all relevant guards, consume/mutate and
persist as one serialized Northstar-owned operation. Include reset, token-code
consumption, firewall application, counters and timeline publication. No await
may separate state acquisition and commit in the supported single-process
server. Document that topology; if multi-process mutation is supported, require
a real cross-process transaction rather than a process-local queue.

Two token redemptions for one code yield at most one success; two firewall
requests yield one execution; a request admitted before reset must re-evaluate
current state rather than restore a retained pre-reset image. Preserve PKCE,
redirect, expiry, service authentication and closed-field validation. Do not
add another ledger around the incident agent's existing SQLite kernel.

### 8.2 REST demo browser (U)

One view generation owns preparation and execution results. Each admitted
operation retains its session, experiment and transport. Changing selection
invalidates earlier publication; a late result cannot render alongside another
session or set follow-on source IDs using that other session. Busy state belongs
to the current operation/generation, so an older finally cannot release a newer
operation. Follow-on IDs and business-response interpretation come from the
completed operation's captured session. Invalidating a view does not imply the
backend effect was cancelled or rolled back.

### 8.3 Incident viewer scope (V)

Bind each refresh to a viewer-scope generation and captured token. Every viewer
scope change invalidates prior refresh publication and clears protected rendered
evidence immediately, including when the replacement refresh fails. Only a
matching scope/current refresh may publish state or errors. An old auditor
response released after public selection must not restore disclosed evidence.
Server claim-based disclosure remains the authorization boundary.

## 9. Audit dispositions and policy

Existing AP076 owners, native lifecycle/entry fences, immutable cache keys,
bounded quorum evaluation and consuming approval handles remain in force.
Do not mechanically replace independent booleans or optional data.

The Google demo refresh rotation concern remains a **provider-dependent
hypothesis**, not a demonstrated Google credential-loss defect. Keep it visible
for a separate refresh protocol contract with a rotating fake provider; do not
invent production provider semantics in this remediation. Reconciliation lease
expiry is a dormant scheduling contract question, not an authorization finding.
AWS asynchronous physical deletion does not contradict the existing exact
adapter-acknowledgement revocation contract. Git CLI record generation does not
claim immediate global revocation before trusted distribution.

AGENTS.md's existing stateful-change checklist applies to every owner above.
Add a concise clarification: filesystem replacement can precede failure;
same-process continuation after ambiguous persistence needs explicit invalidation
or authoritative reload. Resource admission, publication identity and cleanup
must share ownership through actual completion. This is guidance, not a new
human approval gate or a regex ban.

## 10. Acceptance matrix and verification discipline

Write each complete code/test batch before execution. Do not push intermediate
spec-only or partial implementation revisions. Maintain generated identities and
fixtures atomically using their constructors; do not hand-edit canonical bytes.
Run GitHub CI once on the collected implementation by default. Inspect failures
together, perform only justified bounded local reproductions, and publish one
coherent repair batch. Never weaken or bypass a required gate to reduce cost.

| Gate | Deterministic evidence |
| --- | --- |
| S1 | Hold an admitted session through SIGTERM/drain, attempt replacement startup, then release; verify the defined busy result and winner connectivity. |
| S2 | Competing stale recoveries, startup failure after one bind, process termination/restart, replaced-inode cleanup, protected-parent validation, case-alias/shared-parent exclusion and overdue-drain termination while ownership remains held. |
| Q1 | Thread barrier before commit; concurrent close waits for real completion; rejected post-close admission; reopen exact result. |
| Q2 | Cancel reserve waiter and one close waiter; retained worker still settles, other close waiter succeeds only after quiescence; failure has no unhandled outcome. Mutate caller-owned buffers during blocked worker admission; only the retained snapshot may commit. |
| T1 | Deferred correct signer completes at equality and after expiry; only equality invokes native completion; consumed retry rejects; rollback cannot resurrect observed expiry. |
| E1 | Controlled partial header/body transfer, timeout and dropped future; subsequent semantic calls fail without further I/O. |
| E2 | Cancel memory/HTTPS submission after possible delivery; no new submission on that channel; normal exchange and preflight binding rejection remain conformant. |
| E3 | Iroh send/read/finish failure retains unavailable capability; existing direct/relay and bounded framing evidence remains. |
| K1 | Barrier/injected interruption at staging write, content sync, exclusive publication, parent sync and acknowledgement; readers see absence/complete key, competing creators never overwrite. |
| P1 | Every existing persistence fault followed by same-instance read/replay/unrelated mutation and reopen; no stale acknowledgement or snapshot rewrite after ambiguous failure. |
| B1 | Two held-body code redemptions, firewall calls and reset overlap; one-use results, counters and timelines agree with current committed state. |
| U1 | Deferred A execution and B preparation in both completion orders; receipts and follow-on IDs stay bound to their own sessions; old finally cannot clear current busy. |
| V1 | Hold auditor refresh, select public, release responses in both orders and fail the public response; protected evidence stays cleared. |

Extend existing unit, integration, installed-package and browser test owners.
Use actual storage/process boundaries for durable claims, not sleeps alone.
Record source revision, exact checks, results and any remaining limits in the PR
acceptance attestation. No successful CI, completed fixes or production
qualification are claimed merely by writing this contract.
