# Rust Security Review Feedback

Status: actionable follow-up  
Reviewed baseline: `main` at `2d336da` plus `codex/live-demo` at `28e8880`  
Scope: Rust implementation only

## Purpose

Address the remaining adversarial and failure-atomicity gaps after the monorepo,
product/core compliance, and live-demo work.

Do not treat this document as a request to redesign the proof kernel. The
cryptographic verification pipeline, sealed verified-command boundary,
canonical receipt encodings, and three-way authorization result are sound
foundations. The work below is concentrated in the stateful application
boundary surrounding successful verification.

Every fix must include a regression test that fails against the current
implementation. Do not satisfy an item only by changing documentation or
adding an inventory claim.

## Current strengths to preserve

- `VerifiedAction`, `Authorized<C>`, and `ExecutableAction<C>` prevent an
  executor from being handed the original untrusted request as though it were
  verified.
- Profiles decode the command again from sealed canonical action bytes and
  recheck derived permission and budget meaning.
- Denied and indeterminate verification outcomes do not reach executors.
- Replay and budget mutations are serialized within one ledger instance.
- Persistent state is encoded canonically and written before the in-memory
  state is advanced.
- Receipt identifiers, canonical bytes, signer policy, and signature
  verification are separate concepts rather than being conflated.
- The `did:web` resolver pins the checked DNS result, disables redirects, uses
  an exact host allowlist, and bounds response bytes.
- The live lab is generated from real verifier/runtime outputs. Its focused
  Rust test and complete `cargo xtask live-demo` gate pass on the reviewed
  branch.

## P0: prevent permanent challenge-ledger exhaustion

### Problem

`InMemoryChallengeLedger::issue` rejects all new challenges once
`entries.len() == max_entries`, but no consumed or expired entry is ever
removed:

- `product/runtime/auths-runtime/src/lib.rs:125-182`
- `product/stores/auths-stores/src/lib.rs:105-193`

The persistent implementation retains the exhaustion across restart. Challenge
issuance does not currently use peer identity, so an unauthenticated caller can
fill the ledger without submitting a proof.

The present `ChallengeLedger` interface also stores too little information to
perform robust reclamation or to prove that the `ActionChallenge` later passed
to `handle_action` is exactly the challenge issued by this service.

### Required change

Redesign the challenge state entry and port so the ledger owns the full
server-issued challenge commitment needed at claim time. At minimum bind:

- nonce;
- expiry;
- audience;
- protocol and profile version;
- request size limits;
- any service/channel value that must not be caller-substitutable.

Make issuance/claim expiry-aware. Reclaim expired entries under the same lock or
transaction used to insert a new entry. Keep bounded tombstones only for as long
as needed to prevent a retired nonce from becoming a valid new challenge.

Rate limiting may be added as defense in depth, but it is not a substitute for
bounded reclamation.

### Acceptance tests

1. With capacity two, issue two challenges, advance beyond their expiry, and
   successfully issue a third.
2. Fill a persistent ledger, reopen it after expiry, and successfully issue a
   new challenge without deleting the state file.
3. A consumed but unexpired challenge remains rejected.
4. A challenge with a valid issued nonce but substituted audience, profile,
   expiry, or limits is rejected before proof verification and execution.
5. Concurrent issue/claim/prune operations never execute the same challenge
   twice and never exceed the configured live-entry bound.

## P0: define an execution/receipt atomicity contract

### Problem

The MCP runtime executes the external side effect and only then attempts to
persist the execution receipt:

- executor call: `product/runtime/auths-runtime/src/lib.rs:981-1007`
- successful execution receipt: `product/runtime/auths-runtime/src/lib.rs:1014-1027`

If execution succeeds and receipt persistence fails, the caller receives a
refusal even though the side effect already happened. A retry using a fresh
challenge can repeat the operation unless the application executor happens to
implement idempotency independently.

The deployment integration has a related gap:

- `DeploymentAuditSink::authorized` returns `()`;
- `DeploymentService::execute` cannot detect a failed mandatory audit write;
- the executor is then invoked normally.

See `product/integrations/auths-deployment/src/lib.rs:50-60` and `:138-149`.

This is not fixable by rearranging one `if` statement. Once an external side
effect has happened, returning a fail-closed pre-execution refusal is no longer
truthful.

### Required change

Choose and implement an explicit application transaction model. A suitable
target is:

1. Persist an execution intent keyed by the verified action ID and execution
   lease before invoking application code.
2. Pass that stable idempotency key through the executor boundary.
3. Require the executor integration to return an already-committed result for
   repeated keys rather than performing the side effect twice.
4. Persist the terminal execution receipt through an outbox or transaction
   boundary.
5. Distinguish `not executed`, `executed`, and `execution outcome currently
   unavailable` without reporting that a completed side effect was refused.

If a smaller first step is necessary, make the idempotency contract explicit in
the trait and types, implement it in the reference executor, and make receipt
recovery possible. Do not claim exactly-once behavior from replay-nonce
consumption alone.

Change mandatory audit ports to return a typed `Result`. An audit failure before
execution must prevent executor invocation. Keep an explicitly named best-effort
or no-op policy only when the caller deliberately selects it.

### Acceptance tests

1. Inject execution-receipt persistence failure after a successful side effect;
   retrying the same action under a fresh challenge does not invoke the side
   effect again.
2. Recover the missing terminal receipt after simulated restart.
3. A mandatory deployment audit failure invokes the executor zero times.
4. Concurrent submissions with the same action ID but different challenges
   produce at most one external side effect.
5. Tests distinguish authorization, reservation, side-effect commit, receipt
   commit, and response-delivery failures.

## P1: do not disclose executor errors to remote callers

### Problem

On executor failure, `McpAuthorizationService` passes the executor's arbitrary
error string directly into the exchange refusal:

`product/runtime/auths-runtime/src/lib.rs:982-1005`

The exchange model bounds length and rejects control characters, but it cannot
detect credentials, filesystem paths, database messages, tenant data, or other
sensitive content.

### Required change

Return one static, stable external message and reason code. Send only a
sanitized, policy-approved diagnostic to the internal event sink. Prefer a
typed executor error classification over `Result<Vec<u8>, String>`.

### Acceptance tests

1. An executor error containing a credential-like sentinel is absent from the
   serialized `ActionResponse`.
2. Oversized and control-character-bearing executor errors cannot panic the
   refusal path.
3. The public error code remains stable across different internal failures.

## P1: make trusted-clock failure fail closed

### Problem

`SystemClock::now` maps `SystemTime::duration_since(UNIX_EPOCH)` failure to
timestamp zero:

`product/runtime/auths-runtime/src/lib.rs:46-59`

Timestamp zero is a valid protocol value, not an unavailable-clock signal.
Clock rollback can also extend the apparent life of challenges and validity
windows.

### Required change

Make the clock port return a typed result. Propagate unavailable or invalid
wall-clock state into a non-executing service outcome. Define how the runtime
detects material rollback for a service instance, while keeping protocol
evaluation time explicit.

### Acceptance tests

1. A clock error prevents challenge issuance.
2. A clock error during action handling invokes the verifier and executor zero
   times.
3. A material backward jump is rejected or quarantines the service rather than
   extending an authorization window.

## P1: bound zero-cost and long-lived budget state

### Problem

`BudgetCeiling::new` permits value zero:

`core/crates/auths-model/src/lib.rs:602-627`

Both concrete budget ledgers insert every unique action ID into their permanent
claimed set even when the requested value is zero:

- `product/stores/auths-stores/src/lib.rs:66-90`
- `product/stores/auths-stores/src/lib.rs:233-262`

The persistent implementation clones and rewrites the complete state for each
claim. Its decoder rejects more than one million claimed IDs on reopen, but the
live mutation path does not enforce that limit before writing. This permits
unbounded state growth and increasingly expensive writes without consuming the
aggregate budget.

### Required change

Define zero-cost request semantics explicitly. If zero is meaningful for grant
ceilings but not action requests, represent those concepts with distinct types
or validate them at the action boundary. If zero-cost actions are valid, do not
retain them forever merely for accounting.

Bound retained action IDs during live operation, not only during decoding.
Introduce a safe compaction or epoch policy for finite aggregate ledgers. Do not
use the budget ledger as the sole duplicate-execution defense.

### Acceptance tests

1. Repeated zero-cost unique actions cannot grow ledger state without bound.
2. The live persistent ledger refuses or compacts before producing a state file
   that its own reopen path rejects.
3. Boundary tests cover zero, one, exact ceiling, ceiling plus one, and `u64`
   overflow.
4. Restart preserves the exact accepted/rejected accounting decisions.

## P1: complete persistent-write durability

### Problem

`persist_replace` syncs the temporary file and renames it, but does not sync the
parent directory afterward:

`product/stores/auths-stores/src/lib.rs:475-499`

An atomic rename protects readers from partial files, but without a directory
sync the new directory entry is not guaranteed to survive sudden power loss on
all supported filesystems. The current “crash-persistent” description is
therefore stronger than the implementation.

### Required change

After a successful rename, sync the containing directory on platforms where
that operation is supported. Isolate platform-specific behavior behind a small
tested helper and document the guarantee on unsupported platforms.

Add fault-injection coverage around write, file sync, rename, directory sync,
and reopen.

## P2: harden `did:web` address classification

### Problem

The resolver's IPv6 predicate accepts nearly all of `2000::/3` except the
documentation prefix:

`product/integrations/auths-resolver-did-web/src/lib.rs:331-372`

That broad rule deserves explicit treatment of transition, translation,
benchmark, reserved, and other special-use ranges. The IPv4 list should also be
kept synchronized with the intended definition of globally reachable.

The existing DNS pinning, redirect prohibition, host allowlist, timeout, and
body bound must remain.

### Required change

Use a reviewed global-unicast classification or maintain an explicit
deny-by-default table with tests for every special-use family relevant to the
supported toolchain. Include IPv4-mapped IPv6, NAT64-related, 6to4, Teredo,
multicast, link-local, unique-local, documentation, and unspecified/loopback
cases.

## P2: turn runtime claims into direct failure-injection tests

### Problem

The runtime, generic enforcement crate, and deployment integration have no
direct unit tests. The demo testkit currently exercises:

- one successful memory flow;
- ordinary replay;
- concurrent reuse of one challenge;
- corrupted proof over authenticated transport;
- signed permission mismatch.

Those are useful conformance flows, but they do not exercise the state and
failure boundaries listed above. Several compliance claims point at broad demo
tests rather than a test owned by the package making the claim.

### Required change

Add package-local adversarial tests for each port failure and state transition.
Keep the end-to-end testkit flows, but do not use one successful demo as the
only evidence for runtime, SDK, deployment, and enforcement invariants.

At minimum add deterministic fakes for:

- failing and rolling-back clocks;
- colliding and failing challenge sources;
- full, corrupt, and unavailable replay stores;
- exhausted and unavailable budget stores;
- failing attestors and receipt sinks at each write;
- executors that fail, return oversized results, leak sentinel text, or commit
  before returning an error;
- audit sinks that fail before execution.

## P2: strengthen the live lab's evidence claims

### What the new work gets right

`demos/live-lab/src/main.rs` builds all displayed variants from real repository
fixtures and verifier outputs. It checks exact browser result CBOR against the
generated result bytes, and the demo gate checks replay and receipt counts.
This is materially better than a scripted UI with hand-authored verdicts.

### Remaining gaps

1. The value called the native verifier is
   `auths_proof_wasm::verify_self_contained_v1` compiled for the host
   (`demos/live-lab/src/main.rs:203`). Browser verification uses the same
   wrapper compiled to WASM. This proves cross-target parity for one wrapper,
   but it is not an independent native implementation.
2. The generic tamper assertions require only “not authorized.” They do not pin
   the exact expected stage and code for tampered action and tampered proof
   (`demos/live-lab/src/main.rs:394-416`).
3. “Deterministic” output is not verified by building the complete site twice
   and comparing its file manifest and bytes.
4. `build_site` writes directly into the destination. A missing vendor artifact
   or later failure can leave a partially updated or stale deployable directory
   when the binary is invoked directly.

### Required change

- Generate the native expected result through a direct core verifier/portable
  result path rather than through the WASM wrapper's host build. Continue
  requiring byte-for-byte equality from the browser wrapper.
- Pin the decision, stage, and reason code for every adversarial variant.
- Add wrong audience, wrong challenge, expired validity, wrong permission, and
  signed channel-binding mismatch variants, or explicitly link those claims to
  dedicated runtime tests rather than implying the four UI variants cover
  them.
- Build twice in separate temporary directories and compare a sorted
  path-to-digest manifest.
- Stage the entire site in a temporary sibling directory, validate it, and
  atomically publish the completed directory. A failed build must leave the
  previous good output intact.

### Acceptance tests

1. Direct-core native and WASM results are byte-identical for every displayed
   variant.
2. Each adversarial variant asserts one exact stable code and stage.
3. Two clean builds produce identical file paths and bytes.
4. Injected copy or generation failure leaves no partial new deployment and
   does not damage the previous complete output.

## Completion gate

This feedback is complete only when:

- every P0 and P1 item has an implementation and an adversarial regression
  test;
- package-local runtime, deployment, enforcement, and store tests pass;
- the end-to-end testkit still proves that denied and indeterminate requests
  invoke executors zero times;
- the live lab still passes direct-native/WASM byte parity;
- no public response contains injected secret sentinel text;
- ledger capacity, restart, concurrency, and fault-injection tests pass
  repeatedly;
- the full repository Rust test and lint gates pass.

P2 items may be split into a follow-up only if their residual risk and owner are
recorded explicitly. The challenge-exhaustion and execution/receipt-atomicity
items must not be deferred as documentation-only work.
