# Exact-effect verticals runbook

This runbook covers the GitHub issue-address workflow. Its effects share
durable authorization and recovery mechanics, but never share provider
requests, credentials, observations, or receipt meanings.

On 2026-09-27 (AP-SPEC-063 §12, option A) the OpenTofu saved-plan apply and
PostgreSQL bounded update production paths ended, so their sections were
removed. `auths-opentofu` and `auths-postgresql` remain only as test-only
references: pure evaluators, fixtures, and demos.

## Common first response

1. Stop new submissions when lifecycle storage, trusted time, required
   configuration, or receipt persistence is unhealthy.
2. Keep every `possible-effect` reservation held. A timeout or lost response
   is not evidence that no effect occurred.
3. Use the opaque recovery reference to load the committed workflow. Never
   recover by accepting action bytes, provider identifiers, or a request from
   an operator.
4. Confirm the required and executed configuration commitments match before
   reading credentials or provider state.
5. Claim the recovery lease. Only its holder may perform the read-only
   observation.
6. Append the domain observation and reconciliation receipt before presenting
   the workflow as completed or safely failed.

## GitHub issue-address workflow

This workflow contains two independently authorized effects. Branch
publication must commit before draft-pull-request authorization can be
constructed.

- Reconcile a branch only from the exact repository, target ref, and candidate
  object ID.
- Reconcile a pull request only from repository identity, exact head and base,
  draft state, and Auths body commitment. A similar title or branch is not a
  match.
- A committed branch with an unknown pull-request result is a partial workflow,
  not success. Do not publish a second branch.
- Branch and pull-request credentials have separate scopes and are acquired
  after their respective durable intents.
- Cleanup closes the exact draft pull request and deletes the exact generated
  ref after recording their identities.

## Evidence collection

Evidence must contain only stable reason codes, closed stages, bounded timing
buckets, request and result commitments, receipt locators, and cleanup state.
Do not record GitHub tokens, provider environment, repository contents, or
raw provider responses. Live jobs use disposable resources, explicit effect
and cost ceilings, and cleanup even when the test fails.
