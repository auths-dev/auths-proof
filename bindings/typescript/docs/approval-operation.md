# Approval operation ownership

The maintained approval port accepts an exact request and an explicit operation
context: `approve(request, { signal })`. The signal controls that local operation;
it is not added to the native signed approval format. A caller needing no
cancellation supplies a non-aborted `AbortController` signal. Composite approval
providers propagate cancellation and stop starting children after abort.

`BoundedApprovalSession` owns an unapproved, pending, approved-at-next-member, or
terminal state. It claims pending ownership before calling the provider. A
competing call is rejected without consuming a member, cancelling the owner, or
starting another provider call. Acceptance advances one exact member once.

The session copies the plan, policy, member commitments and each request's
binding and display fields. `providerFor` captures its own member commitment.
Providers receive separate copies; responses are compared against the retained
owner snapshot. Caller or provider mutation therefore cannot rewrite the request
being accepted. Shared-memory-backed and detached digest buffers are refused.

Deadline equality is valid. The effective clock is the maximum sample observed
by the session, so a backward sample cannot undo an observed expiry. An expired
request rejected before pending admission does not consume or close the session.
Expiry during its pending provider approval closes the session, requiring a
fresh approval session. Session expiry is always terminal. A deadline watchdog
checks time even if the provider never completes; timer delivery alone does not
establish expiry. The optional scheduler is paired with the configured clock for
deterministic tests and embedding, and cannot supply approval authority.

An already-aborted call is cancelled without closing an otherwise usable
session. Cancellation after pending admission closes the session, aborts the
provider signal, and promptly rejects the caller. Disposal has the same pending
invalidation behavior. Providers may ignore abort: late completions cannot
approve a member, and late rejections are consumed. An accepted approval cannot
be retroactively undone by a later abort or disposal.

Explicit provider refusal returns the validated rejected response and closes the
session. Malformed responses are rejected; typed provider failures preserve
their failure kind, and untyped failures become unavailable. A failed session
never automatically retries. None of these local lifecycle operations revokes an
existing signature or proves that an external provider effect did not occur.

This describes the existing maintained workflow/binding implementation; it does
not add an approval subpath to the SDK's stable package export topology. Public
entrypoints and the native approval authority retain their existing ownership.

Regression evidence is shared by unit and source-free installed-package tests in
`test/helpers/approval-state-contract.mjs`, mapped to AP076 A1–A6.
