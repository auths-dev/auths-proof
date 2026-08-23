# Profile operation recovery runbook

Auths never turns an ambiguous provider effect into a retryable failure. The
durable operation journal distinguishes `not-applied`, `applied`, and
`possible`. Applications retry only when Auths proves non-entry; otherwise they
resume the original operation with its sealed recovery handle.

## Application behavior

1. Call the ordinary generated method once.
2. On a typed recovery-required error, persist the opaque recovery handle in an
   application secret store and keep the operation ID for correlation.
3. Call that generated group's `recover` method with the handle.
4. Do not resubmit the original provider request under a new idempotency key.
5. Treat a repeated recovery-required result as unresolved, not failed.

The root client's operations surface can list pending operations and recover a
handle without knowing provider credentials. Logs may include stable error
code, operation ID, profile, effect state, and receipt IDs; they must not include
the handle bytes, provider secret, request body, or receipt envelope.

## Operator triage

1. Confirm the agent is running against the original state directory and
   recovery key.
2. Inspect the sanitized connection record and its retained generation.
3. Check whether the journal stopped before provider entry, after entry, after a
   durable provider result, or after durable observation.
4. Restore provider connectivity or the retained credential generation when
   safe; do not edit journal/profile-store records manually.
5. Resume recovery. The profile may observe or reconcile the original attempt,
   but it must never repeat a provider mutation blindly.
6. Verify the returned portable decision/execution receipt pair locally and
   confirm the execution receipt links the exact decision ID.

## Interpretation

- **Not applied:** durable evidence proves provider entry did not occur. The
  profile releases its reservation/prepared claim before returning this state.
- **Completed/partial:** a durable provider result and observation support the
  applied facts represented by the receipts.
- **Recovery required / possible:** provider entry occurred or may have
  occurred, but exact truth is not yet established. Capacity pressure,
  credential rotation, disable, or restart must preserve this record.

If external provider drift cannot be attributed to the operation, recovery
stays possible. For example, an OpenTofu state serial advancing is not proof
that Auths' apply caused it; the current implementation deliberately remains
recovery-required until an operation-bound backend marker can establish truth.

## Incident closure

Close an unresolved operation only with profile-owned evidence that proves its
exact outcome. Record the operator decision, stable error code, operation and
receipt IDs, relevant provider-side immutable IDs, and redacted evidence. Never
delete an unresolved record merely to regain quota. Escalate persistent
ambiguity as an incident and preserve the full owner-only state directory.
