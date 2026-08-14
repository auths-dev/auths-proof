# Exact-effect verticals runbook

This runbook covers the three effect paths qualified by the open production
candidate. They share durable authorization and recovery mechanics, but never
share provider requests, credentials, observations, or receipt meanings.

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

## OpenTofu saved-plan apply

The only write request is the frozen `apply -input=false -auto-approve`
invocation over the protected saved-plan slot. The program, directory,
environment, backend, workspace, flags, and artifact path are startup-owned.

- If execution may have started, pull the backend state and inspect the exact
  resource postconditions committed by the plan.
- Mark effect only when lineage, serial progression, state commitment, and
  provider-object commitment agree.
- Mark non-effect only when the unchanged committed pre-state is freshly
  observed.
- Keep the outcome unknown when the backend is unavailable, the lock is
  ambiguous, or either the before or after identity cannot be established.
- Cleanup destroys only the resource named by the sandbox evidence and then
  proves its absence through a fresh observation.

## PostgreSQL bounded update

The gateway accepts the Rust-compiled statement, typed parameters, fixed
timeouts, and `SERIALIZABLE` isolation. It never accepts SQL or a connection
string from the workflow request.

- Treat a connection loss during commit as possible effect.
- Reconnect with the reconciliation credential and compare the exact primary
  keys, prior row versions, before commitments, and computed after commitment.
- Do not infer non-effect from a missing row, relation, or schema. Those are
  indeterminate identity changes.
- Commit success only when the affected-row count and complete returned state
  match the action.
- Cleanup restores only the synthetic fixture rows and verifies their exact
  versions and values.

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
Do not record saved-plan bytes, SQL parameters, GitHub tokens, database
credentials, provider environment, repository contents, row values, or raw
provider responses.

The checked-in qualification manifest is
`product/qualification/v1/exact-effect-verticals.json`. The production
contract rejects missing evidence paths or provider-contract drift. Live jobs
use disposable resources, explicit effect and cost ceilings, and cleanup even
when the test fails.
