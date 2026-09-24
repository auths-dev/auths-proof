# Prompt: execution, crash recovery and exactly-once

Scope: `product/runtime/auths-node` (especially `journal_executor.rs`), `auths-gateway`, `auths-lifecycle`, `auths-profile-runtime`, `product/stores`.

Goal: establish what the system actually guarantees about how many times a side effect happens, under crashes, retries and concurrency.

Answer:
1. **State machine.** Draw the operation states and the transitions between them, with the durable write that makes each transition stick. Is every state reachable only through a compare-and-swap?
2. **Crash points.** For each point between durable writes (before the lease, after the lease, after "provider entered", mid-HTTP, after the response and before it is persisted), state what recovery does. Can recovery ever *create* an effect?
3. **Idempotency.**
   - Which paths send a provider idempotency key?
   - How long does the provider remember keys, and is reconciliation guaranteed to run inside that window?
   - What happens for providers that have neither idempotency nor read-back?
4. **Concurrency.**
   - Two submits of the same action, two different actions sharing a budget, two processes on the same journal file. Trace each.
   - Is locking in-process only, or across processes? Across hosts?
5. **Async hazards.**
   - Look for blocking IO or fsync inside async code without `spawn_blocking`.
   - Look for a `std::Mutex` held across work.
   - Look for locks held across `.await` on provider calls.
6. **Scale.** What does each mutation cost? Look for whole-file rewrites, full reloads and global lock rows. Estimate throughput at 10, 100 and 1000 operations per second.
7. **Budget and reservations.**
   - Is a reservation atomic?
   - Is it kept while the outcome is unknown?
   - Is it released when the action is proven not applied?
   - Is there exactly one source of truth for spend limits?

State the honest guarantee in one sentence, e.g. "at most once plus human reconciliation when X".
