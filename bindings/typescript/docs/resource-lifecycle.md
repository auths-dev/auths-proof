# Resource opening and cleanup

Workflow, identity and remote clients follow AP-SPEC-076 section 7. Closing
stops new admission, waits for active use, then attempts every independent owned
cleanup. Concurrent callers share the result. Borrowed resources are never
closed; successful destruction is never repeated.

An exposed closed/disposed property reports that admission has stopped. Await
close/dispose to learn whether owned cleanup finished successfully; a stopped
client may still retain active work or failed cleanup. Python constructors
retain their owner synchronously; concurrent `open()` waiters share that owner.
Identity construction completes registration synchronously and returns `Open`;
its synchronous decoder is immediately usable. Closing still stops admission.

TypeScript factories, workflow attachment/delegation and close/dispose accept
`{ signal?, timeoutMs? }`. Python open, attach_agent, delegate and aclose accept
keyword-only `timeout` in seconds. Timeouts must be finite and positive. Omit
them for no lifecycle deadline. Cancellation detaches a waiter, leaving owned
opening/cleanup alive. Cancelled attachments cannot publish; late resources are
retained and cleaned up. A factory losing its caller owns its late result until
cleanup settles.

The first close caller's timeout is the cleanup generation's monotonic deadline.
Later callers can wait less time but cannot change that deadline. Expiry reports
incomplete cleanup and retains ongoing work. Subsequent calls report incomplete
until late settlement; a subsequent close may then observe success.

Opening failure returns the original error promptly while cleanup proceeds.
Ordinary close after failed cleanup returns its retained failure. Explicit
`retryCleanup(options?)` / `retry_cleanup(timeout=...)` retries only unresolved
safe obligations. Declare safe destructor repetition with TypeScript
`cleanupRetry: "idempotent"` or Python `cleanup_retry = "idempotent"`.
Absent that capability, an ambiguous failure is retained without repetition.
Nested wrappers use the child's explicit retry method when available. This
capability never authorizes retrying an application/provider mutation.

TypeScript waiter errors use the disposed workflow boundary and bounded
cancelled/timeout cause; cleanup uses signer-failed and cleanup-incomplete or
cleanup-failed. Python waiters use CancelledError/TimeoutError; cleanup retains
the cleanup-failed workflow boundary with a bounded local cause_chain naming
completion. None proves a provider effect was undone.

A destructor must not await the completion of an owner currently awaiting that
destructor, including through another thread or nested adapter. That dependency
cycle cannot finish. Resource ownership changes no authorization, native entry,
recovery, or receipt authority. Written schedules and final hosted evidence are
tracked in the AP076 implementation record.
