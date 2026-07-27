# Auths for GitHub Issue Workflows

## Vertical Product Package and End-to-End Demonstration

**Status:** Proposed

**Initial domain:** GitHub issue resolution

**Product package:** `product/integrations/auths-github`

**Demonstration:** `demos/github-issue`

**Profile identifier:** `auths.github.issue-address/1`

## 1. Decision

Auths will prove that an autonomous agent can address one GitHub issue and open
one constrained draft pull request without receiving repository write
credentials.

The GitHub capability will begin as one cohesive vertical product package:

```text
product/integrations/auths-github
```

The package will contain the GitHub action vocabulary, canonicalization,
candidate inspection, evidence acquisition, workflow state machine, execution
orchestration, GitHub adapter, and credential port.

GitHub-specific code must not be distributed across `product/profiles`,
`product/runtime`, `product/stores`, `product/receipts`, and multiple
integration packages merely because those directories describe related
architectural responsibilities.

Existing shared packages may be consumed through narrow ports:

- `auths-stores` supplies generic atomic claim and compare-and-swap behavior;
- `auths-receipts` supplies generic decision and execution receipt envelopes;
- core and product verification APIs supply portable proof verification;
- product configuration and operations surfaces may supply generic deployment
  configuration and diagnostics.

Those shared packages do not own GitHub resources, workflow states, branch
rules, Git candidate metadata, or GitHub execution results.

The first implementation is a modular product package, not a collection of
prematurely generalized frameworks or microservices.

## 2. Why this product exists

Most coding-agent integrations grant an agent an identity or token with standing
repository permissions. The agent can then exercise any operation allowed by
that credential for as long as the credential remains usable.

Auths changes the authority model:

> The agent may produce arbitrary local candidates, but a trusted executor may
> publish only an exact candidate proven to fit one human-authorized workflow.

A maintainer authorizes a bounded outcome:

```text
Address issue 42 in repository R by publishing at most one new proposal branch
and opening at most one draft pull request from a pinned base revision, within
an explicit path and size policy, before expiry.
```

The agent may then perform unprivileged local work:

- read the issue and repository;
- edit files;
- run tools and tests;
- create, amend, or discard local commits;
- construct a candidate Git bundle.

Authorization is required only when the result crosses into the shared system:

- publishing a branch;
- opening a pull request.

The agent never receives the GitHub credential used for those mutations.

The product claim is deliberately narrow:

> Auths proves that publication was within delegated authority.

Auths does not prove that the code is correct, safe, useful, or semantically
responsive to the issue. Human review, repository policy, GitHub permissions,
and branch protection remain authoritative.

## 3. Goals

The MVP must demonstrate all of the following:

1. A maintainer can authorize one meaningful issue-scoped workflow without
   approving every mechanical step.
2. Each external mutation is still bound to an exact repository, workflow,
   branch, base revision, candidate revision, expected prior state, and
   executor audience.
3. The agent can explore locally without repository write credentials.
4. A trusted executor derives and executes only exact actions contained by the
   workflow grant.
5. Changing a security-relevant candidate or target field changes the action
   and invalidates the authorization.
6. Workflow budgets and replay claims prevent a second branch, second pull
   request, or repeated mutation.
7. Decision receipts record why an action was authorized, denied, or
   indeterminate.
8. Execution receipts record what GitHub actually accepted.
9. Crash recovery can reconcile an external mutation without repeating it.
10. The Auths kernel remains domain-independent and unchanged.

## 4. Non-goals

The MVP will not provide:

- semantic proof that a candidate fixes the issue;
- prompt-injection prevention for issue or repository content;
- autonomous merging;
- branch updates after initial publication;
- force push or history rewriting;
- pull-request comments, reviews, labels, or issue closure;
- arbitrary Git commands;
- arbitrary GitHub API access;
- organization-wide policy management;
- a general workflow engine;
- a universal policy language;
- multiple executors for one workflow;
- global replay coordination;
- symlink, submodule, merge-commit, or non-UTF-8-path support;
- support for GitHub Actions or repository automation changes;
- other Git hosts or GitHub Enterprise in the first deployed demonstration;
- user-defined profiles.

## 5. Trust model

### 5.1 Trusted components

The MVP trusts:

- the configured Auths roots and verifier configuration;
- the workflow controller and executor process;
- the executor's implementation of candidate inspection and GitHub effects;
- the claim store's atomicity;
- the receipt signer;
- GitHub as the authority for GitHub-hosted state;
- TLS and the authenticated GitHub API/Git transport used by the executor.

The executor is an explicit trust boundary. Evidence is trusted because the
executor acquired it under the configured evidence policy, not because API
responses are intrinsically proofs.

### 5.2 Untrusted components

The MVP does not trust:

- the coding agent;
- issue titles, bodies, comments, or linked content;
- repository files;
- the submitted Git object bundle;
- caller-supplied repository coordinates, branch names, revisions, or PR text;
- the agent sandbox's environment, Git configuration, remotes, hooks, or
  credential helpers;
- a previous authorization result presented without its sealed value and
  workflow claim.

### 5.3 Credential boundary

The GitHub App private key and installation token exist only in the executor's
credential boundary.

They must never be:

- mounted into the agent sandbox;
- returned through an API;
- written to receipts;
- logged;
- embedded in Git remotes;
- passed through caller-controlled environment variables;
- exposed to the browser demonstration.

The executor obtains a repository-scoped, short-lived GitHub App installation
token immediately before execution. A long-lived personal access token is not
permitted.

### 5.4 No bypass path

The agent sandbox must not possess another credential, socket, service account,
or integration capable of publishing to the protected repository.

The demonstration must prove this by attempting a direct push from the agent
environment and showing that GitHub rejects it before the Auths-mediated
publication succeeds.

## 6. Architectural boundaries

The system has four logical responsibilities inside one product package:

```text
+-------------------------------------------------------------------+
| product/integrations/auths-github                                 |
|                                                                   |
|  profile  ->  candidate/evidence  ->  workflow  ->  executor      |
|    pure          inspection          state         effects        |
|                                                                   |
|                         service                                   |
|                coordinates the exact flow                         |
+-------------------------+-------------------+---------------------+
                          |                   |
                          v                   v
                    auths-stores        auths-receipts
                    generic claims      generic envelopes
```

Logical separation is enforced with Rust modules, private constructors, typed
state transitions, sealed verified commands, narrow ports, and tests.

Directory or crate separation is not a substitute for a real trust boundary.
Credential isolation is enforced by the executor deployment and process
boundary.

### 6.1 Kernel

The Auths kernel answers:

> Does this proof carry valid authority for this exact canonical action under
> this trusted context?

The kernel does not understand:

- GitHub;
- Git repositories;
- issues;
- branches;
- commits;
- changed paths;
- pull requests;
- workflow state;
- credentials.

Ordinary GitHub feature work must not require kernel changes.

### 6.2 Profile module

The profile module owns pure GitHub-domain meaning:

- resource identifiers;
- workflow grant schema;
- exact action schemas;
- deterministic canonicalization;
- containment and attenuation rules;
- stable profile outcomes;
- profile versioning.

It does not:

- call GitHub;
- read a repository;
- hold credentials;
- persist workflow state;
- claim replay state;
- execute mutations.

### 6.3 Candidate and evidence modules

These modules acquire and normalize facts required to decide a concrete
publication:

- current repository identity;
- issue identity and open state;
- current base ref;
- proposal branch absence;
- submitted Git object structure;
- candidate ancestry;
- changed paths, modes, counts, and sizes.

Evidence is immutable, bounded, timestamped, and digested. The exact action
binds the evidence digest and the security-relevant expected prior state.

### 6.4 Workflow module

The workflow module owns mutable product state:

- current workflow phase;
- expiry and cancellation;
- branch and PR budgets;
- expected previous state;
- action claims;
- pending external effects;
- links to decision and execution receipts;
- reconciliation state.

It does not decide generic proof validity and does not perform GitHub calls.

### 6.5 Executor module

The executor:

1. accepts an untrusted candidate request;
2. acquires fresh evidence;
3. asks the profile and workflow modules to derive an exact action;
4. invokes Auths verification;
5. decodes a sealed verified GitHub command;
6. atomically claims the action and workflow budget;
7. acquires a short-lived GitHub credential;
8. performs only the decoded command;
9. verifies the postcondition;
10. records an execution receipt;
11. reconciles pending work after crashes.

The executor must never verify one set of values and execute caller-supplied
alternates.

Correct:

```text
verified_action = verify(canonical_action)
command = decode_verified(verified_action)
execute(command)
```

Forbidden:

```text
verify(canonical_action)
execute(caller_repository, caller_branch, caller_revision)
```

## 7. Physical package layout

The initial implementation will use:

```text
product/integrations/auths-github/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── profile/
│   │   ├── mod.rs
│   │   ├── resource.rs
│   │   ├── grant.rs
│   │   ├── action.rs
│   │   ├── canonical.rs
│   │   ├── containment.rs
│   │   └── outcome.rs
│   ├── candidate/
│   │   ├── mod.rs
│   │   ├── bundle.rs
│   │   ├── objects.rs
│   │   ├── diff.rs
│   │   └── policy.rs
│   ├── evidence/
│   │   ├── mod.rs
│   │   ├── github.rs
│   │   ├── repository.rs
│   │   └── digest.rs
│   ├── workflow/
│   │   ├── mod.rs
│   │   ├── state.rs
│   │   ├── transition.rs
│   │   ├── budget.rs
│   │   └── claim.rs
│   ├── executor/
│   │   ├── mod.rs
│   │   ├── publish_branch.rs
│   │   ├── open_pull_request.rs
│   │   └── reconcile.rs
│   ├── ports/
│   │   ├── mod.rs
│   │   ├── github.rs
│   │   ├── credentials.rs
│   │   ├── claims.rs
│   │   ├── receipts.rs
│   │   └── clock.rs
│   ├── adapters/
│   │   ├── mod.rs
│   │   ├── github_app.rs
│   │   ├── git_cli.rs
│   │   ├── auths_stores.rs
│   │   └── auths_receipts.rs
│   ├── service.rs
│   └── bin/
│       └── auths-github-executor.rs
└── tests/
    ├── constrained_publication.rs
    ├── hostile_candidates.rs
    ├── replay.rs
    └── recovery.rs
```

The exact module count may be reduced during implementation. The normative
requirements are ownership and dependency direction, not one source file per
box.

GitHub-specific types stay in this package. Shared packages are extended only
when the needed abstraction is genuinely domain-independent.

## 8. Package dependency rules

Internal dependency direction:

```text
profile <- candidate/evidence <- workflow <- service -> executor
                                             |
                                             v
                                            ports
                                             |
                                             v
                                          adapters
```

Rules:

1. `profile` is deterministic and side-effect free.
2. `workflow` depends on profile-owned identifiers and actions, not on GitHub
   clients.
3. `executor` consumes typed commands; it does not construct policy decisions.
4. `adapters` implement ports and remain replaceable in tests.
5. No module may bypass the sealed verified-command constructor.
6. Only the credential adapter can obtain GitHub write credentials.
7. The binary performs composition and configuration only.
8. Production code must not depend on `demos/github-issue`.

## 9. Extraction criteria

The vertical package must not be split merely for conceptual neatness.

A component may become a separate package only when at least one of these is
true:

1. A second domain needs the same workflow controller.
2. The GitHub profile must be published or independently implemented.
3. The pure profile requires a dependency surface materially smaller than the
   executor package.
4. The profile and executor require independent versioning.
5. The controller and executor must run in different trust processes.
6. A package boundary is required to enforce a security-relevant dependency
   rule that modules and visibility cannot enforce.

The likely later split, if justified, is:

```text
auths-profile-github
auths-github-workflow
auths-github-executor
```

That is later work, not MVP structure.

## 10. Resource identity

The MVP supports `github.com` only.

A repository resource contains:

```text
host                 = "github.com"
repository_id        = GitHub immutable numeric repository ID
repository_node_id   = GitHub GraphQL node ID
owner                = display and evidence cross-check
name                 = display and evidence cross-check
```

Authorization binds the immutable identifiers. `owner/name` is retained for
operator comprehension and must match fresh evidence. A rename or transfer
therefore causes an evidence mismatch and requires a new workflow grant in the
MVP.

An issue resource contains:

```text
repository_id
issue_node_id
issue_number
```

The issue must still exist in the bound repository and remain open immediately
before branch publication.

## 11. Workflow grant

The canonical workflow grant is profile-versioned and includes:

```text
profile_id
profile_version
workflow_id
repository
issue
base_ref
base_revision
candidate_policy
publication_policy
executor_audience
issued_at
expires_at
delegation
```

### 11.1 Base policy

The grant binds:

- one base ref;
- one exact base commit SHA-1 or SHA-256, matching the repository object
  format;
- the repository object-format identifier.

At publication time, the base ref must still equal the pinned revision. If it
has advanced, the workflow becomes stale and no mutation occurs. The maintainer
must issue a new grant against the new base.

### 11.2 Candidate policy

The MVP policy includes:

```text
allowed_paths
denied_paths
maximum_changed_files
maximum_added_bytes
maximum_deleted_bytes
maximum_candidate_bytes
maximum_git_objects
maximum_commits
allow_executable_bit_changes = false
allow_symlinks = false
allow_submodules = false
allow_merge_commits = false
allow_non_utf8_paths = false
allow_git_attributes_changes = false
allow_gitmodules_changes = false
allow_repository_automation_changes = false
```

### 11.3 Path grammar

Path constraints use a versioned, repository-root-anchored grammar:

- `/` separates path components;
- `*` matches bytes within one component;
- `**` matches zero or more complete components;
- patterns are case-sensitive;
- paths must be valid UTF-8 for the MVP;
- `.` and `..` components are rejected;
- control characters and backslashes are rejected;
- matching occurs on Git tree paths, never host filesystem paths;
- denied patterns take precedence over allowed patterns;
- rename similarity detection is not used.

A rename is evaluated as deletion of the old path plus addition of the new
path.

The deployed demonstration always denies:

```text
.github/**
.gitattributes
.gitmodules
CODEOWNERS
```

### 11.4 Publication policy

The MVP binds:

```text
maximum_branches       = 1
maximum_pull_requests  = 1
must_be_draft          = true
allow_branch_updates   = false
allow_history_rewrite  = false
allow_merge            = false
```

The executor derives the proposal branch name:

```text
auths/issue-<issue-number>-<workflow-id-prefix>
```

The agent cannot choose the branch name.

The pull-request title is deterministic:

```text
Auths proposal for issue #<issue-number>
```

The body is a fixed template containing:

- the issue reference;
- workflow identifier;
- candidate revision;
- action digest;
- a link to the public decision and execution receipt view.

The agent cannot supply arbitrary PR title or body text in the MVP.

### 11.5 Expiry and audience

The grant binds one executor identity. The demonstration grant expires after
fifteen minutes. Production configuration may choose a different bounded
duration.

## 12. From workflow authority to exact actions

A workflow grant is not itself permission to execute arbitrary future GitHub
mutations.

The derivation model is:

```text
Maintainer authority
    |
    | signs workflow grant
    v
Executor-bound workflow principal
    |
    | after containment and state checks,
    | derives one exact child action
    v
Exact branch or pull-request proof
    |
    | Auths kernel verification
    v
Sealed verified GitHub command
    |
    v
Executor mutation
```

The workflow grant delegates one level of constrained authority to the bound
workflow principal. The workflow principal may derive only actions that:

- reference the workflow-grant digest;
- use the same repository and issue;
- use the configured executor audience;
- fit the profile containment rules;
- fit the remaining workflow budget;
- have no remaining delegation depth;
- bind an exact action digest.

The agent is not the delegated workflow principal and cannot issue child
actions.

### 12.1 Workflow-principal lifecycle

Before grant issuance, the executor creates a fresh workflow signing key and
returns only its public principal descriptor to the maintainer interface.

The maintainer's grant:

- names that public workflow principal as the constrained delegate;
- names the executor audience;
- permits one remaining derivation level;
- binds the workflow ID, profile, constraints, and expiry.

The private workflow key:

- exists only inside the executor trust boundary;
- is encrypted at rest when durable recovery requires persistence;
- is never available to the agent or browser;
- signs only exact child actions produced after containment and workflow-state
  checks;
- is disabled when the workflow is cancelled, expired, or permanently failed;
- is destroyed after successful completion and receipt finalization.

The MVP may use an executor-managed Ed25519 key. Hardware-backed or remote
signing custody is later hardening and must preserve the same public contract.

Each external mutation has a separate exact action and receipt:

1. `github.branch.publish/1`
2. `github.pull-request.open-draft/1`

The workflow API may execute them sequentially in one user operation, but they
remain separately claimed and auditable.

## 13. Exact action schemas

### 13.1 Publish branch

The canonical branch-publication action binds:

```text
capability
profile_id
profile_version
workflow_id
workflow_grant_digest
repository
issue
base_ref
base_revision
target_ref
expected_target_state = absent
candidate_revision
candidate_tree
candidate_bundle_digest
change_set_digest
evidence_digest
verifier_configuration
executor_audience
expires_at
```

### 13.2 Open draft pull request

The canonical PR action binds:

```text
capability
profile_id
profile_version
workflow_id
workflow_grant_digest
repository
issue
base_ref
base_revision
head_ref
head_revision
draft = true
exact_title
exact_body_digest
expected_existing_pull_requests = 0
branch_execution_receipt_digest
evidence_digest
verifier_configuration
executor_audience
expires_at
```

Changing any security-relevant field changes the canonical action digest.

## 14. Candidate transport and inspection

The agent submits a bounded Git bundle containing:

- the candidate ref;
- candidate commits and trees;
- required new blobs;
- the pinned base as a prerequisite.

The executor imports the bundle into a fresh quarantined bare repository.

It must:

1. enforce request byte limits before full buffering;
2. enforce pack/object count and decompression limits;
3. reject unexpected refs;
4. run strict Git object validation;
5. inspect objects without checking out a worktree;
6. ignore repository-local and user-global Git configuration;
7. disable hooks, filters, credential helpers, pagers, and external commands;
8. verify the candidate descends from the exact base;
9. reject merge commits;
10. compute the exact changed-tree set without rename heuristics;
11. inspect file modes and reject unsupported modes;
12. calculate canonical change-set and evidence digests;
13. delete quarantine data after the workflow reaches a terminal state.

The candidate verifier must not execute code from the candidate.

When Git transport is invoked, the adapter must:

- execute Git with an explicit argument vector, never through a shell;
- use an explicit bare repository and remote URL;
- clear inherited Git configuration and credential helpers;
- supply the installation credential through an ephemeral executor-owned
  credential channel, never a command argument or persisted remote URL;
- use an exact `<candidate-sha>:<derived-ref>` refspec;
- prohibit force options;
- capture bounded, redacted subprocess output;
- verify the remote ref after the push.

## 15. Repository automation safety

Publishing a branch can trigger GitHub Actions, bots, previews, or other
repository automation even when `.github/**` is unchanged.

Therefore the MVP requires an explicit repository eligibility policy:

- proposal branches use the `auths/` prefix;
- no workflow triggered by pushes to `auths/**` may receive privileged secrets
  or perform privileged deployment;
- pull-request workflows must treat fork-like proposal content as untrusted;
- repository administrators must confirm this policy before enabling the
  executor;
- the executor configuration binds the digest of the approved repository
  automation policy;
- a policy change makes the workflow indeterminate until configuration is
  re-approved.

The public demonstration repository is purpose-built to satisfy this policy and
contains no privileged push-triggered workflow.

## 16. Workflow state machine

```text
Authorized
    |
    v
CandidateAccepted
    |
    v
BranchClaimed -----> BranchReconciliationRequired
    |                             |
    v                             |
BranchPublished <-----------------+
    |
    v
PullRequestClaimed -----> PullRequestReconciliationRequired
    |                                 |
    v                                 |
Completed <---------------------------+

Authorized ---------> Cancelled
CandidateAccepted --> Cancelled
```

Terminal states:

- `Completed`
- `Cancelled`
- `Expired`
- `Denied`
- `FailedPermanent`

The workflow cannot be cancelled after an external effect has been claimed.
Such workflows must complete or enter reconciliation.

### 16.1 Claims

Before each external mutation, the controller atomically records:

- workflow ID;
- exact action digest;
- claim identifier;
- expected previous workflow state;
- consumed budget;
- `Pending` execution state.

Only one successful compare-and-swap may claim a workflow transition.

### 16.2 Replay

Repeating an already completed exact action returns its recorded execution
receipt. It does not repeat the GitHub mutation.

A different action that attempts to consume an exhausted branch or PR budget is
denied.

### 16.3 Recovery

If the executor crashes after GitHub accepts a mutation but before the receipt
is committed:

1. the pending claim remains durable;
2. a reconciliation worker queries GitHub using the exact bound identifiers;
3. if the exact expected postcondition exists, it records success without
   repeating the mutation;
4. if no mutation occurred, it retries only when the operation is known to be
   safe and idempotent;
5. ambiguous state remains `ReconciliationRequired`;
6. an operator-visible receipt records the reconciliation result.

The MVP does not automatically delete a published branch when PR creation
fails. It retains the branch and reconciles PR creation.

## 17. Evidence

The evidence record contains:

```text
schema_version
workflow_id
repository_identity
issue_identity
issue_state
base_ref
observed_base_revision
target_ref_state
existing_matching_pull_requests
candidate_revision
candidate_tree
commit_count
changed_paths
changed_modes
added_bytes
deleted_bytes
bundle_digest
change_set_digest
repository_policy_digest
acquired_at
source_configuration
```

Critical GitHub evidence must be acquired within thirty seconds of execution.
The executor rechecks:

- repository immutable identity;
- issue open state;
- base ref revision;
- target branch absence or exact expected head;
- absence of an existing matching PR.

Missing or stale evidence produces `Indeterminate`; it is not converted to
authorization.

## 18. Outcomes

Stable profile outcomes include:

```text
authorized
workflow-proof-invalid
workflow-expired
workflow-cancelled
executor-audience-mismatch
repository-mismatch
repository-renamed-or-transferred
issue-mismatch
issue-not-open
base-revision-mismatch
branch-already-exists
pull-request-already-exists
candidate-bundle-malformed
candidate-limit-exceeded
candidate-not-descendant
merge-commit-denied
unsupported-git-object
path-not-allowed
path-explicitly-denied
file-mode-denied
repository-automation-policy-mismatch
branch-budget-exhausted
pull-request-budget-exhausted
action-replay
evidence-missing
evidence-stale
verifier-configuration-mismatch
github-rejected
execution-ambiguous
reconciliation-required
```

Profile denial, missing evidence, cryptographic verification failure, GitHub
rejection, partial execution, and reconciliation are distinct result classes.

## 19. Receipts

### 19.1 Decision receipt

The decision receipt includes:

- workflow-grant digest;
- exact action digest;
- proof digest;
- trusted-context digest;
- required verifier configuration;
- executed verifier configuration;
- evidence digest;
- profile identifier and version;
- decision;
- stable reason code;
- executor identity;
- evaluation time.

### 19.2 Execution receipt

The execution receipt includes:

- decision-receipt digest;
- exact action digest;
- claim identifier;
- expected prior state;
- GitHub operation category;
- observed resulting state;
- repository ID;
- branch ref and exact head, when applicable;
- pull-request node ID, number, URL, base, head, and draft state, when
  applicable;
- execution result;
- execution time;
- reconciliation history, if applicable.

The executor signs receipts. Receipts contain digests and public GitHub
identifiers, never credentials or candidate source contents.

## 20. Rust APIs

The following interfaces are conceptual and may be adjusted to existing Auths
types. Their ownership and invariants are normative.

```rust
pub struct WorkflowGrant;
pub struct VerifiedWorkflowGrant;
pub struct CandidateSubmission;
pub struct CandidateEvidence;
pub struct WorkflowState;
pub struct DecisionReceipt;
pub struct ExecutionReceipt;

pub enum ExactGitHubAction {
    PublishBranch(PublishBranchAction),
    OpenDraftPullRequest(OpenDraftPullRequestAction),
}

pub enum VerifiedGitHubCommand {
    PublishBranch(VerifiedPublishBranch),
    OpenDraftPullRequest(VerifiedOpenDraftPullRequest),
}
```

Only the profile decoder can construct `VerifiedGitHubCommand`, and only from a
sealed successful Auths verification result.

### 20.1 Ports

```rust
pub trait GitHubReadPort {
    fn repository(&self, resource: &RepositoryResource)
        -> Result<RepositoryEvidence, GitHubReadError>;

    fn issue(&self, resource: &IssueResource)
        -> Result<IssueEvidence, GitHubReadError>;

    fn ref_state(&self, repository: &RepositoryResource, ref_name: &RefName)
        -> Result<RefEvidence, GitHubReadError>;

    fn matching_pull_requests(&self, query: &PullRequestQuery)
        -> Result<Vec<PullRequestEvidence>, GitHubReadError>;
}

pub trait GitHubWritePort {
    fn publish_branch(
        &self,
        command: &VerifiedPublishBranch,
        candidate: &QuarantinedCandidate,
    ) -> Result<PublishedBranch, GitHubWriteError>;

    fn open_draft_pull_request(
        &self,
        command: &VerifiedOpenDraftPullRequest,
    ) -> Result<OpenedPullRequest, GitHubWriteError>;
}

pub trait CredentialProvider {
    fn installation_credential(
        &self,
        repository: &RepositoryResource,
        operation: GitHubOperation,
    ) -> Result<ScopedCredential, CredentialError>;
}

pub trait WorkflowStore {
    fn load(&self, id: WorkflowId) -> Result<WorkflowState, StoreError>;

    fn compare_and_swap(
        &self,
        expected: &WorkflowState,
        next: &WorkflowState,
    ) -> Result<ClaimResult, StoreError>;
}

pub trait ReceiptSink {
    fn append_decision(&self, receipt: &DecisionReceipt)
        -> Result<ReceiptId, ReceiptError>;

    fn append_execution(&self, receipt: &ExecutionReceipt)
        -> Result<ReceiptId, ReceiptError>;
}
```

`ScopedCredential` must redact debug and display output and zeroize secret
material on drop.

## 21. Service APIs

The product package exposes transport-neutral service operations:

```text
create_workflow(grant_proof)
submit_candidate(workflow_id, candidate_bundle)
inspect_candidate(workflow_id)
execute_workflow(workflow_id)
workflow_status(workflow_id)
workflow_receipts(workflow_id)
cancel_workflow(workflow_id)
reconcile_workflow(workflow_id)
```

Rules:

- `submit_candidate` performs no external mutation;
- `inspect_candidate` is deterministic for fixed evidence and candidate bytes;
- `execute_workflow` may publish the branch and open the draft PR sequentially;
- every execution call is idempotent by workflow and exact action digest;
- cancellation is available only before an external action claim;
- caller-provided repository, branch, revision, title, and body are never
  accepted by `execute_workflow`.

## 22. End-to-end demonstration

### 22.1 Demonstration claim

The demonstration must prove:

> A credential-less agent can produce a candidate for one GitHub issue, while a
> credential-bearing executor publishes only the exact candidate covered by a
> bounded Auths workflow grant.

The final success state must include a link to a real draft pull request in a
dedicated GitHub repository. A mock GitHub adapter is insufficient for the
public end-to-end claim.

### 22.2 Demonstration repository

Use a dedicated repository:

```text
auths-dev/auths-github-demo
```

It contains:

- one deterministic base commit;
- one open demonstration issue;
- a small source file and test file;
- no privileged push-triggered workflow;
- branch protection on `main`;
- no secrets available to proposal-branch code;
- a GitHub App installed only on this repository.

The GitHub App receives only:

- repository metadata: read;
- issues: read;
- contents: write;
- pull requests: write.

It receives no administration, actions, secrets, environments, deployments, or
organization permissions.

### 22.3 Demonstration components

```text
demos/github-issue/
├── web/
│   ├── grant workbench
│   ├── candidate variants
│   ├── decision/execution timeline
│   └── receipt viewer
├── service/
│   ├── public session API
│   ├── fixed candidate builder
│   ├── executor composition
│   └── GitHub result links
├── fixtures/
│   ├── valid candidate
│   ├── denied-path candidate
│   ├── changed-revision candidate
│   └── malformed candidate
└── tests/
    ├── browser smoke test
    ├── service integration test
    └── real-GitHub gated test
```

The demo imports production behavior from `auths-github`. It must not duplicate
profile, candidate, workflow, or executor logic.

### 22.4 Demonstration deployment

The public deployment uses:

- a static or server-rendered web frontend on Vercel;
- the native Rust executor service on Fly.io;
- one active mutation region;
- durable workflow/claim storage attached to the mutation region;
- exact-origin CORS;
- server-side session rate limits;
- GitHub App credentials stored only as Fly secrets;
- no GitHub, Auths signing, or executor secrets in Vercel browser variables.

A second region may serve health or read-only status, but it must not mutate
workflow state without a shared transactional claim store. The MVP uses one
active writer to keep exactly-once behavior explicit.

The service publishes:

```text
GET  /healthz
POST /v1/demo/sessions
GET  /v1/demo/sessions/{session_id}
POST /v1/demo/sessions/{session_id}/candidate
POST /v1/demo/sessions/{session_id}/execute
POST /v1/demo/sessions/{session_id}/replay
GET  /v1/demo/sessions/{session_id}/receipts
```

Public demo candidate selection is an enum of server-owned fixtures. Arbitrary
Git bundle upload is reserved for authenticated operator testing.

### 22.5 User experience

Configuration and result remain side-by-side so a user can change one fact and
immediately see the authorization consequence:

```text
+--------------------------------------+--------------------------------------+
| Workflow grant                       | Live decision and execution           |
|--------------------------------------|--------------------------------------|
| Repository  auths-github-demo        | CURRENT VERDICT                      |
| Issue       #42                      | AUTHORIZED                           |
| Base        8f34...                  |                                      |
| Paths       src/**, tests/**         | Profile      github.issue-address/1  |
| Denied      .github/**               | Action       branch.publish          |
| Budget      1 branch, 1 draft PR     | Action ID    7ac1...                  |
| Expires     14:32 UTC                | Evidence     current                 |
|                                      |                                      |
| Candidate experiment                 | Execution                            |
| (•) Exact permitted candidate        | Branch       published               |
| ( ) Prohibited path added            | Draft PR     opened                  |
| ( ) Candidate revision changed       | Replay       not attempted           |
| ( ) Repository changed               |                                      |
| ( ) Base revision changed            | [Open real GitHub pull request]      |
|                                      | [View decision receipt]              |
| [Inspect] [Publish through Auths]     | [View execution receipt]             |
+--------------------------------------+--------------------------------------+
```

Controls are visible and enabled on first paint. Loading, verifier readiness,
native-service connectivity, GitHub execution, and terminal failure states are
shown separately. The interface must never remain indefinitely at an
undifferentiated `LOADING` state.

### 22.6 Demonstration sequence

The default valid demonstration performs:

1. Create a short-lived session and signed issue-address workflow grant.
2. Display the exact grant constraints.
3. Show that the agent environment has no GitHub write credential.
4. Attempt a direct push from the agent environment and record GitHub's
   authentication rejection.
5. Build a deterministic candidate commit from the pinned base.
6. Submit its bounded Git bundle to the executor.
7. Inspect and display its exact commit, tree, changed paths, modes, counts, and
   digests.
8. Derive and verify the exact `branch.publish` action.
9. Atomically claim the branch budget.
10. Mint a short-lived GitHub App installation token inside the executor.
11. Push the exact candidate SHA to the executor-derived branch.
12. Confirm the remote branch points to that exact SHA.
13. Record decision and execution receipts.
14. Derive and verify the exact `pull-request.open-draft` action.
15. Atomically claim the PR budget.
16. Open the deterministic draft PR.
17. Confirm its repository, base, head, revision, title, body digest, and draft
    state.
18. Record the PR execution receipt.
19. Display the real GitHub PR URL and linked receipts.
20. Attempt replay and show that no second mutation occurs.

### 22.7 Demonstration experiments

The user can choose exactly one experiment:

| Experiment | Changed fact | Required result |
| --- | --- | --- |
| Exact permitted candidate | Nothing | Branch and draft PR succeed |
| Prohibited path | Add `.github/workflows/ci.yml` | Denied before credential acquisition |
| Candidate revision changed | Change one candidate byte and rebuild commit | Original exact action no longer matches |
| Repository changed | Substitute a different repository identity | `repository-mismatch` |
| Issue changed | Substitute another issue identity | `issue-mismatch` |
| Base advanced | Present a different current base SHA | `base-revision-mismatch`; no mutation |
| Second branch | Consume branch budget, then propose another ref | `branch-budget-exhausted` |
| Second pull request | Consume PR budget, then request another | `pull-request-budget-exhausted` |
| Exact replay | Submit the completed action again | Existing receipt returned; no mutation |
| Malformed bundle | Corrupt bounded candidate bytes | `candidate-bundle-malformed` |

The public UI uses server-owned fixtures so an unauthenticated visitor cannot
turn the demonstration executor into an arbitrary repository write service.

### 22.8 Demo reset

Public sessions use unique workflow-derived branch names. A separate
operator-only maintenance capability removes expired demo branches and closes
expired demo pull requests.

Cleanup authority is not part of the issue-address workflow and uses separate
credentials and receipts.

The public executor never exposes cleanup operations.

## 23. Testing

### 23.1 Unit tests

Required unit coverage:

- canonical resource and action encoding;
- every security-relevant field changes the action digest;
- grant containment cannot widen repository, issue, paths, budgets, expiry, or
  audience;
- path grammar boundary cases;
- deterministic branch and PR metadata;
- state transition legality;
- budget exhaustion;
- stable outcome mapping;
- malformed inputs never panic;
- required and executed verifier configurations are both reported.

### 23.2 Property and adversarial tests

Required property/adversarial coverage:

- arbitrary path bytes never escape root-anchored matching;
- equivalent path encodings cannot alias;
- arbitrary bundle bytes never panic;
- object count and decompression limits are hard boundaries;
- one-byte candidate changes produce a different candidate and action digest;
- action derivation never widens a workflow grant;
- concurrent duplicate claims produce one winner;
- receipt linkage is complete and tamper-evident.

### 23.3 Integration tests

A deterministic in-memory or local GitHub port verifies:

- valid branch and PR flow;
- every denial occurs before write-port invocation;
- exact verified values reach the write port;
- no caller alternates reach execution;
- crash after branch publication reconciles without a second push;
- crash after PR creation reconciles without a second PR;
- GitHub rejection records a distinct execution result;
- replay returns the original receipt.

### 23.4 Real GitHub test

A gated manual or scheduled test uses the dedicated demonstration repository
and real GitHub App:

1. create a fresh workflow;
2. publish one unique branch;
3. open one draft PR;
4. verify remote SHA and PR fields;
5. replay both actions;
6. verify exactly one branch and one PR exist;
7. archive the receipts;
8. invoke separate operator cleanup.

This test is required before claiming that the end-to-end demonstration is
live.

### 23.5 Browser test

The browser smoke test verifies:

- experiment controls are visible on first paint;
- selecting an experiment changes the displayed evidence and decision;
- valid execution reaches a real PR link;
- denials never show an execution attempt;
- loading and connectivity failures terminate with actionable states;
- receipts can be opened and match the displayed action;
- replay visibly leaves mutation counts unchanged.

## 24. Acceptance criteria

The MVP is complete only when:

1. `auths-github` is one vertical product package.
2. GitHub-specific code is not scattered into generic store, receipt, runtime,
   or profile packages.
3. The Auths kernel contains no GitHub or Git concepts.
4. The agent sandbox has no repository write credential.
5. A direct agent push fails.
6. A valid candidate produces one real branch and one real draft PR.
7. The remote branch contains the exact inspected candidate revision.
8. A prohibited path is denied before credential acquisition.
9. Repository, issue, base, and candidate substitutions are denied.
10. A second branch and second PR are denied by atomic budgets.
11. Replay creates no additional GitHub mutation.
12. Required and executed verifier configurations are present in the decision
    receipt.
13. Decision and execution receipts link cryptographic authorization to the
    observed GitHub result.
14. Crash recovery can reconcile a branch or PR created before receipt commit.
15. The live UI makes constraints, changed evidence, decision, execution, and
    receipts visible together.
16. The demo presents a real GitHub pull-request URL.
17. Core architecture, compliance, product conformance, and repository CI
    checks pass.

## 25. Implementation sequence

### Phase 1: Pure profile and schemas

- resource identifiers;
- workflow grant;
- exact actions;
- canonical encoding;
- containment;
- stable outcomes;
- conformance vectors.

### Phase 2: Candidate verifier

- bounded bundle ingestion;
- quarantined object validation;
- ancestry and tree diff;
- path/mode/size policy;
- evidence and change-set digests;
- hostile-candidate corpus.

### Phase 3: Workflow and generic adapters

- state machine;
- budgets and claims;
- `auths-stores` adapter;
- `auths-receipts` adapter;
- exact child-action derivation;
- deterministic fake GitHub adapter;
- crash and replay tests.

### Phase 4: GitHub executor

- GitHub App credential provider;
- exact branch publication;
- exact draft PR creation;
- postcondition verification;
- reconciliation;
- real-GitHub gated test.

### Phase 5: Public demonstration

- fixed candidate fixtures;
- side-by-side workbench;
- native service;
- Vercel and Fly deployment;
- rate limiting and session cleanup;
- browser smoke tests;
- production receipt and PR links.

## 26. Deferred work

After the MVP proves its claim, later versions may add:

- fast-forward-only proposal updates;
- multiple candidate revisions;
- comments and review requests as separate capabilities;
- cancellation after safe checkpoints;
- reusable grant templates;
- organization policy defaults;
- multiple repositories and GitHub Enterprise;
- independent GitHub profile implementations;
- stronger executor isolation;
- approval bound to exact revisions;
- human checkpoints;
- other domain profiles;
- cross-domain workflows linked by receipts.

No deferred feature should be generalized into the MVP until the one-issue,
one-branch, one-draft-PR workflow works against real GitHub with no agent
credential and complete receipts.
