# Production SDK quickstart: one GitHub issue

The launch path gives an agent one bounded GitHub task and keeps the GitHub App
credential inside a separate trusted executor. The SDK accepts named domain
values and a Git bundle file; it does not ask application code to construct
CBOR, proof bytes, canonical actions, or receipt envelopes.

The operator first deploys the existing `demos/github-issue` service for one
isolated repository and issue. Both SDKs then use the same flow.

## TypeScript

```ts
import { createGitHubAgentClient } from "@auths-dev/sdk/service";

const auths = createGitHubAgentClient({ endpoint: "https://executor.example" });
const candidateRevision = "<git-object-id>";
const boundary = await auths.boundary();
const task = await auths.delegate({
  repository: boundary.repository,
  issueNumber: boundary.issueNumber,
  baseRef: boundary.baseRef,
  baseRevision: boundary.baseRevision,
  allowedPaths: boundary.allowedPaths,
  protectedPaths: boundary.protectedPaths,
  expiresInSeconds: boundary.maximumExpirySeconds,
  branchBudget: 1,
  draftPullRequestBudget: 1,
  agentLabel: "issue-agent",
});
const candidate = await auths.inspectCandidate(task, {
  path: "./candidate.bundle",
  baseRevision: boundary.baseRevision,
  candidateRevision,
});
if (candidate.kind !== "inspected") throw new Error(candidate.decisionCode);
let result = await auths.execute(task);
if (result.next === "reconcile") result = await auths.reconcile(task);
if (result.kind !== "completed" && result.kind !== "reconciled") {
  throw new Error(result.code);
}
const receipts = await auths.verifyReceipts(task);
```

## Python

```python
from auths.service import (
    GitHubAgentTask,
    GitHubCandidateFile,
    create_github_agent_client,
)

auths = create_github_agent_client(endpoint="https://executor.example")
candidate_revision = "<git-object-id>"
boundary = await auths.boundary()
task = await auths.delegate(GitHubAgentTask(
    repository=boundary.repository,
    issue_number=boundary.issue_number,
    base_ref=boundary.base_ref,
    base_revision=boundary.base_revision,
    allowed_paths=boundary.allowed_paths,
    protected_paths=boundary.protected_paths,
    expires_in_seconds=boundary.maximum_expiry_seconds,
    branch_budget=1,
    draft_pull_request_budget=1,
    agent_label="issue-agent",
))
candidate = await auths.inspect_candidate(task, GitHubCandidateFile(
    path="candidate.bundle",
    base_revision=boundary.base_revision,
    candidate_revision=candidate_revision,
))
if candidate.kind != "inspected":
    raise RuntimeError(candidate.decision_code)
result = await auths.execute(task)
if result.next == "reconcile":
    result = await auths.reconcile(task)
if result.kind not in ("completed", "reconciled"):
    raise RuntimeError(result.code)
receipts = await auths.verify_receipts(task)
```

## What the boundary guarantees

- The task repeats the operator-approved repository, issue, current base,
  allowed/protected paths, expiry, and fixed one-branch/one-draft-PR budget.
  Any widening is refused before a session is created.
- The agent produces only a Git bundle. It has no GitHub App token.
- Rust performs bounded Git inspection and derives the exact branch and draft
  pull-request commands.
- Each effect is durably claimed before the executor requests its credential.
- A protected path, stale base, repository/issue substitution, or changed
  candidate is denied before a write.
- Replay returns the existing receipt commitment with zero new credentials and
  zero new mutations.
- An ambiguous provider outcome says `reconcile`; it never tells the caller to
  start the action again.
- If an execute response is lost, both SDKs return `indeterminate` with
  credential and mutation counts set to `unknown` and `next = reconcile`.
  They never turn transport loss into a zero-effect claim.
- `verifyReceipts` reads through the existing bounded signed-receipt verifier.

The generic five-verb remote contract remains at `@auths-dev/sdk/service` and
`auths.service`. The GitHub calls live on those existing remote-service entry
points, but their request is deliberately profile-specific
because candidate inspection, fresh GitHub evidence, two ordered effects, and
reconciliation cannot be represented honestly as an arbitrary JSON action.

See the maintained [demo quickstart](../../demos/github-issue/README.md),
[architecture](../../demos/github-issue/docs/architecture.md), and
[failure/recovery guide](recipes/06_PRODUCTION_FAILURES.md).
