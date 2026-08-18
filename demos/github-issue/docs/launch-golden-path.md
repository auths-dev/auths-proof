# GitHub agent launch golden path decision

## Placement

Extend `demos/github-issue`. Reusable semantics remain in
`product/integrations/auths-github`; TypeScript and Python project the live API.
No new repository, runtime, provider, state machine, receipt schema, or web app
is introduced.

| Choice | Reuse | Drift risk | Installed-package realism | Credential isolation | Maintenance | Decision |
| --- | --- | --- | --- | --- | --- | --- |
| Extend `demos/github-issue` | Highest | Lowest | High | Existing GitHub App boundary | Lowest | Chosen |
| Add another demo | Medium | High | High | Would need to be rebuilt | High | Rejected |
| Add another repository | Low until release | Highest | Potentially high | Would need to be rebuilt | Highest | Rejected |

## Reuse matrix

| Needed capability | Existing owner and evidence | Decision |
| --- | --- | --- |
| Exact GitHub actions | `auths-github/src/types.rs:ExactGitHubAction`; profile digest tests | Reuse |
| Candidate inspection | `candidate.rs:GitCandidateInspector`; demo negative variants | Reuse |
| Authority/delegation | `demos/github-issue/src/fixture.rs:EphemeralAuthsAuthorizer` | Reuse |
| SDK transport | Existing binding packaging, HTTP/error conventions, public topology gates | Extend with one vertical projection |
| Canonical encoding | `types.rs::canonical_bytes` and `profile.rs::canonicalize` | Reuse; never encode in bindings |
| Receipt verification | `Ed25519JsonlReceiptSink::receipts_for_workflow` and persistent receipt route | Reuse |
| Replay/lifecycle | `auths-github/src/lifecycle.rs`, `workflow.rs`, and demo persistent store | Reuse |
| Recovery/reconciliation | `service.rs::reconcile` and `GitHubRecoveryRecordV1` | Reuse |
| Credentials/writes | `GitHubAppCredentialProvider`, `GitHubRestClient` | Reuse |
| Installed SDKs | Existing npm pack and Python wheel policies | Extend tests/examples |
| Demo UI | `demos/github-issue/web` | Extend request shape only |

The genuine gaps were an explicit task request, a bounded external Git bundle
submission, and typed installed-package calls. The old API only selected a
server-owned experiment string.

## UX

Happy path: discover the operator boundary; preview repository, issue, base,
paths, expiry, and 1+1 budget; delegate; load a Git bundle; see inspection and
credential absence; execute; open the draft PR; verify receipts; replay and see
zero writes.

Denial path: submit the protected-path fixture or a hostile bundle. The client
shows the Rust decision code, stage, zero credential requests, and zero
mutations.

Recovery path: an uncertain provider outcome projects `next = reconcile`.
The client observes/reconciles the existing exact effect and never restarts it.
Transport loss after an operation leaves the process projects the same next
step with effect counters explicitly `unknown`, never zero.

## Architecture

```text
installed TypeScript/Python `service` entry point
  -> typed auths-github-agent/v1 API
    -> demos/github-issue native assembly
      -> product/integrations/auths-github
        -> candidate inspector + fresh evidence + Auths authorization
        -> durable lifecycle claim
        -> GitHub App credential boundary
        -> exact GitHub write + observation + signed receipt
```

The submitted agent bundle crosses the untrusted boundary. The App credential
exists only below the durable claim boundary. The language bindings cannot
construct an authorized command or provider request.

## APIs

Both languages expose the same operations:

```text
boundary
delegate(task) -> opaque session
inspectCandidate(session, file) -> inspected | denied
execute(session) -> completed | denied | indeterminate
replay(session) -> original receipt, zero writes
reconcile(session) -> observed exact outcome, zero repeated writes
verifyReceipts(session) -> verified timeline
```

The task has named domain values. Candidate bytes stay behind a file boundary;
session identifiers and receipts stay opaque. The server rejects repository,
issue, base, path, budget, expiry, and configuration widening before candidate
execution.

## Residual operational assumptions

- The operator installs the GitHub App only on an isolated approved repository.
- GitHub availability and postcondition convergence remain external facts;
  ambiguity is retained as recovery state.
- Public deployment capacity and the daily mutation quota remain operator
  policy, not authorization semantics.
- A clean-machine under-fifteen-minute usability cohort and registry-published
  RC exercise remain release evidence, not facts this source change can claim.
