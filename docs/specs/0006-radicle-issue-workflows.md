# 0006: Auths for Radicle Issue Workflows

- Status: Implemented
- Target: MVP
- Profile: `auths.radicle.issue-address/1`
- Product package: `product/integrations/auths-radicle`
- Demonstration: `demos/radicle-issue`

## 1. Summary

This specification defines an Auths product integration that lets an untrusted
agent address one Radicle issue and publish one exact Radicle patch without
receiving a Radicle signing key, writable Radicle storage, a node mutation
interface, or general Git publication authority.

The MVP proves:

> The agent may produce any local candidate it wants. Only one candidate inside
> an explicit human grant can cross the protected signer boundary and become
> signed Radicle state.

This is not a generic permission layer for Radicle. Radicle remains authoritative
for repository identity, signatures, collaborative objects, replication,
delegate thresholds, and canonical repository state. Auths contributes portable
delegation lineage, attenuation, exact-action authorization, replay protection,
and receipts around one Radicle mutation.

The implementation MUST live in one vertical product package:

```text
product/integrations/auths-radicle/
```

Radicle-specific profile vocabulary, evidence acquisition, candidate
inspection, workflow state, executor logic, signer and node adapters, and
Radicle-specific receipt projections belong together in that package. Shared
Auths stores and receipt primitives are consumed through narrow ports; the
integration MUST NOT distribute its domain logic across unrelated shared
packages.

## 2. Product claim

The MVP product claim is:

> A maintainer can authorize an agent to address one Radicle issue, subject to
> precise repository, base, path, size, signer, audience, expiry, and action
> budgets. A protected executor can then publish exactly one matching patch
> under a dedicated Radicle identity without exposing that identity's key or
> writable node access to the agent.

The MVP deliberately does not claim that Auths:

- decides Radicle canonical state;
- replaces Radicle repository delegates;
- establishes a globally latest peer-to-peer view;
- makes peer replication synchronous or globally atomic;
- publishes under a human's Radicle identity;
- safely authorizes arbitrary `git` or `rad` commands;
- merges the patch;
- changes repository identity or delegate configuration.

## 3. Why Radicle is not a server-shaped integration

The integration MUST preserve the following distinctions.

### 3.1 There is no central authoritative API

The executor evaluates a validated local view after a configured synchronization
step. It MUST describe that view precisely and MUST NOT label it “the globally
latest state.”

### 3.2 Publication has multiple observable stages

These stages are different facts:

```text
Auths authorized the exact action
    -> Radicle signer signed the mutation
    -> executor storage accepted it
    -> executor announced it
    -> another peer replicated it
    -> repository canonical state changed
```

The MVP reaches the first five stages. It never requests the sixth.

### 3.3 Peer namespaces are not canonical state

The patch is created under the dedicated executor identity and its signed
namespace. That does not make the candidate the repository's canonical branch.
The execution receipt MUST state:

```text
canonical_transition_requested = false
canonical_transition_observed = false
```

### 3.4 Issues and patches are collaborative objects

Issue and patch state may require history from multiple operations before it can
be materialized. Evidence acquisition MUST detect incomplete histories and
return an indeterminate result instead of silently evaluating partial state.

### 3.5 Patch revisions are semantic immutable revisions

The MVP opens one patch with one revision. It does not model later revisions as
force-pushes and does not authorize them under the original exact action.

## 4. Normative terminology

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
RECOMMENDED, MAY, and OPTIONAL are normative.

- **Authorizer**: the person or authority that issues the workflow grant.
- **Agent**: the untrusted process that reads the issue and produces a candidate.
- **Workflow principal**: an ephemeral Auths principal controlled by the
  workflow controller and delegated only the workflow grant.
- **Executor**: the trusted service that verifies an exact action and performs a
  sealed Radicle mutation.
- **Executor audience**: the Auths audience identifying exactly one executor
  trust domain.
- **Radicle signer**: the dedicated Radicle identity whose key signs the patch
  mutation.
- **Node identity**: the identity of a Radicle node participating in replication.
- **Repository delegate**: a Radicle repository identity delegate. The MVP
  executor is not one.
- **RID**: the Radicle repository identifier.
- **Identity revision**: the exact repository identity revision used during
  evaluation.
- **Canonical head**: the repository's canonical branch head as derived from the
  executor's validated local view.
- **Candidate head**: the Git commit proposed by the agent.
- **Local publication**: successful signing and storage of the patch mutation on
  the executor's Radicle storage.
- **Replication confirmation**: an independent observer node can materialize and
  verify the published patch.
- **Required configuration**: the verifier configuration demanded by the
  profile, grant, and execution context.
- **Executed configuration**: the configuration the verifier actually used.

## 5. Normative MVP decisions

This section resolves the design choices for the MVP.

### 5.1 Signer identity

The executor MUST use a dedicated Radicle identity for the environment or team.
It MUST NOT use a human maintainer's key. The identity MUST NOT be a repository
delegate in the MVP.

Radicle interfaces will therefore show the executor identity as the patch
publisher. Auths receipts preserve the separate authorizer, agent, workflow
principal, executor audience, Radicle signer DID, and node identity.

### 5.2 Issue-to-patch relationship

The normative security binding is the issue ID inside the workflow grant, exact
action, decision receipt, and execution receipt.

The patch description MUST also contain a deterministic human-readable issue
reference generated by the adapter. Its exact bytes are included in the bound
patch-body digest. Parsing that text is not an authorization control.

If a future Radicle protocol version exposes a stable typed issue relation, a
new profile version may make that relation normative.

### 5.3 Evidence completeness

The MVP executor MUST synchronize from at least one configured observation peer,
materialize the full repository identity document and full target issue history,
and record the peer set and synchronization result.

An inability to prove completeness is `indeterminate`, not `denied`.

### 5.4 Base semantics

The workflow is authorized against the exact canonical head observed after the
required synchronization step. The executor MUST re-check that head immediately
before claiming execution. A changed head is denied with
`canonical-head-mismatch`. The MVP has no stale-base escape hatch.

### 5.5 Publication budget

One workflow may create at most:

```text
patches = 1
patch_revisions = 1
comments = 0
reviews = 0
canonical_updates = 0
identity_updates = 0
delegate_updates = 0
```

### 5.6 Receipt location

Auths receipts are stored outside Radicle in the MVP. A public, non-secret
correlation ID MAY appear in patch text. Proofs, capability chains, private
claims, and full receipts MUST NOT be embedded in the Radicle object.

### 5.7 Node ownership

The executor MUST control its signer boundary and writable Radicle storage. A
shared node is not an acceptable MVP trust boundary. The independent observer
MUST use a different identity, storage directory or volume, and process trust
domain.

### 5.8 Profile governance

`auths.radicle.issue-address/1` is specified and versioned in this repository.
Any change to action meaning, evidence meaning, containment, canonicalization,
or required verifier configuration requires a new profile version or an
explicitly compatible revision backed by conformance fixtures.

## 6. User experience

### 6.1 Maintainer

The maintainer chooses:

- repository RID;
- one open issue ID;
- expiry;
- allowed and denied paths;
- file, byte, and commit budgets;
- exact executor audience;
- expected Radicle signer DID;
- one publication and one revision;
- whether tests are required;
- optional patch title and description constraints.

The product shows the resolved identity revision and canonical base head before
the maintainer signs the grant.

### 6.2 Agent

The agent receives:

- a read-only repository checkout;
- the materialized issue;
- the workflow constraints;
- an isolated work directory;
- a submission endpoint for a bounded candidate bundle.

The agent does not receive:

- a Radicle private key;
- a writable Radicle profile;
- a signer socket;
- a writable node socket;
- writable Radicle storage;
- a writable `rad` Git remote;
- a repository delegate key;
- a generic executor shell;
- a credential capable of publishing another candidate.

### 6.3 Maintainer result

The result shows both authorization and publication facts:

```text
Authorization
  Grant lineage       valid
  Candidate            inside grant
  Exact action         authorized
  Replay claim         consumed

Radicle publication
  Signer               did:key:...
  Local storage        stored
  Announcement         announced
  Independent peer     replicated
  Patch ID             ...
  Revision ID          ...
  Candidate OID        ...
  Canonical branch     unchanged / not requested
```

A propagation timeout MUST NOT be rendered as an authorization denial or as
proof that local publication did not happen.

## 7. Vertical package boundary

The production implementation SHALL use this ownership shape:

```text
product/integrations/auths-radicle/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── profile/
│   │   ├── mod.rs
│   │   ├── action.rs
│   │   ├── capability.rs
│   │   ├── canonical.rs
│   │   └── containment.rs
│   ├── candidate/
│   │   ├── mod.rs
│   │   ├── bundle.rs
│   │   ├── git.rs
│   │   └── limits.rs
│   ├── evidence/
│   │   ├── mod.rs
│   │   ├── snapshot.rs
│   │   ├── completeness.rs
│   │   └── sync.rs
│   ├── workflow/
│   │   ├── mod.rs
│   │   ├── controller.rs
│   │   ├── state.rs
│   │   ├── claim.rs
│   │   └── reconcile.rs
│   ├── executor/
│   │   ├── mod.rs
│   │   ├── command.rs
│   │   ├── service.rs
│   │   └── postcondition.rs
│   ├── ports/
│   │   ├── mod.rs
│   │   ├── radicle_read.rs
│   │   ├── radicle_write.rs
│   │   ├── signer.rs
│   │   ├── store.rs
│   │   └── receipts.rs
│   ├── adapters/
│   │   ├── mod.rs
│   │   ├── radicle.rs
│   │   ├── signer.rs
│   │   ├── stores.rs
│   │   └── receipts.rs
│   ├── error.rs
│   └── service.rs
└── src/bin/
    └── auths-radicle-executor.rs
```

This is one package with internal modules, not a mandate for separate crates.
The modules clarify trust boundaries and change reasons while preserving one
product ownership unit.

### 7.1 Allowed dependencies

The package MAY depend on:

- Auths kernel and proof APIs;
- shared stores through the package's store port;
- shared receipt primitives through the package's receipt port;
- bounded Git inspection libraries;
- version-pinned Radicle libraries or a version-pinned adapter process;
- serialization, hashing, time, and service infrastructure.

### 7.2 Forbidden dependencies

- Auths core MUST NOT depend on this package.
- Exchange and bindings MUST NOT acquire Radicle domain knowledge.
- Shared stores MUST NOT define Radicle workflow transitions.
- Shared receipts MUST NOT define Radicle-specific decision meaning.
- Other products MUST NOT import internal modules.
- The demo MUST use the package's public service/API surface.
- The agent runtime and browser code MUST NOT depend on signer or writable-node
  adapters.

### 7.3 Extraction criteria

A submodule becomes a separate package only when at least one of these is true:

1. a second non-Radicle product needs the same domain behavior;
2. profile canonicalization must be independently published as a small
   conformance library;
3. the signer or node adapter must run as a separately deployed trust process;
4. independent versioning is required for compatibility;
5. dependency isolation materially reduces the trusted computing base.

“The file is large” is not sufficient.

## 8. Architecture

```text
+-----------------------+       read-only       +----------------------+
| Untrusted agent       |<---------------------| Synced worktree and  |
| no key, node, remote  |                       | materialized issue   |
+-----------+-----------+                       +----------------------+
            |
            | bounded candidate bundle
            v
+-----------+----------------------------------------------------------+
| auths-radicle vertical product package                              |
|                                                                      |
|  candidate inspector -> evidence acquisition -> profile containment  |
|           |                    |                    |                  |
|           +--------------------+--------------------+                  |
|                                v                                       |
|                     Auths kernel verification                         |
|                                |                                       |
|                       exact action + claim                             |
|                                |                                       |
|                    sealed verified command                            |
+-------------------------------+--------------------------------------+
                                |
                                v
                  +-------------+--------------+
                  | Protected Radicle executor |
                  | signer + writable storage  |
                  +-------------+--------------+
                                |
                   signed patch | announce
                                v
                  +-------------+--------------+
                  | Radicle peer-to-peer       |
                  | replication               |
                  +-------------+--------------+
                                |
                                v
                  +-------------+--------------+
                  | Independent observer node |
                  | read-only verification    |
                  +----------------------------+
```

The Auths kernel verifies proof structure, signatures, audience, expiry,
attenuation, and action binding. It remains Radicle-blind.

The product package establishes all Radicle and Git facts and decides whether
the exact action is contained by the workflow grant.

## 9. Trust and identity model

The following identifiers MUST remain separate in types and receipts:

```text
Auths root authority
Auths authorizer
Auths agent principal
Auths workflow principal
Auths executor audience
Radicle signer DID
Radicle executor node ID
Radicle observer node ID
Radicle repository delegates
Radicle issue authors
Radicle patch publisher
```

No API may accept a generic string where two of these namespaces are possible.

The executor MUST verify:

- the proof audience equals its configured audience;
- the exact action names its configured Radicle signer DID;
- the signer adapter reports the same DID before signing;
- the writable storage belongs to the configured executor node context;
- the executor signer is not a repository delegate;
- the command requests no canonical or identity mutation.

## 10. Resources and capabilities

### 10.1 Resource types

```rust
struct RadicleRepositoryResource {
    rid: Rid,
}

struct RadicleIssueResource {
    rid: Rid,
    issue_id: CobId,
}

struct RadiclePatchResource {
    rid: Rid,
    patch_id: CobId,
}

struct RadiclePatchRevisionResource {
    rid: Rid,
    patch_id: CobId,
    revision_id: CobId,
    candidate_oid: GitOid,
}
```

RIDs, COB IDs, DIDs, node IDs, and Git OIDs MUST be parsed into distinct
validated canonical types before policy evaluation.

### 10.2 Workflow capability

The human-facing capability is:

```text
radicle.issue.address
```

It authorizes constrained preparation of one patch for one issue. It does not
itself authorize a generic Radicle command.

### 10.3 Exact action

The executable action is:

```text
radicle.patch.open/1
```

No `radicle.command.run`, `git.push`, arbitrary ref update, arbitrary COB
operation, or shell-command capability exists.

### 10.4 Explicitly excluded capabilities

The MVP profile cannot express:

- patch revision;
- issue or patch comment;
- review or approval;
- merge or canonical branch update;
- repository identity update;
- delegate update;
- visibility update;
- arbitrary signed-ref update;
- arbitrary COB mutation.

Adding any of these requires a separately named action with its own containment
and executor logic.

## 11. Workflow grant

A workflow grant contains at least:

```rust
struct IssueAddressGrantV1 {
    profile: ProfileId,                 // auths.radicle.issue-address/1
    workflow_id: WorkflowId,
    rid: Rid,
    issue_id: CobId,
    repository_identity_revision: GitOid,
    canonical_base_oid: GitOid,
    allowed_paths: Vec<PathRule>,
    denied_paths: Vec<PathRule>,
    max_changed_files: u32,
    max_changed_bytes: u64,
    max_commits: u32,
    allow_file_modes: Vec<FileMode>,
    require_tests: Option<TestRequirement>,
    patch_title_constraint: TextConstraint,
    patch_body_constraint: TextConstraint,
    expected_signer_did: RadicleDid,
    executor_audience: Audience,
    expires_at: Timestamp,
    max_patches: ExactU32<1>,
    max_revisions: ExactU32<1>,
    allow_canonical_update: ExactBool<false>,
    allow_identity_update: ExactBool<false>,
    allow_delegate_update: ExactBool<false>,
    required_configuration: RadicleVerifierConfiguration,
}
```

Constraints MUST be machine-evaluable. Natural-language instructions may be
shown to the agent but are not security controls.

Path matching MUST operate on normalized repository-relative byte paths. The
profile MUST define behavior for non-UTF-8 names, case sensitivity, path
separators, dot segments, prefix matching, and glob interpretation.

The MVP rejects symlinks, submodules, merge commits, special file modes, and
paths that cannot be represented canonically.

## 12. Two-level authorization

The workflow uses two levels of authority.

### 12.1 Human workflow grant

The authorizer delegates `radicle.issue.address` to a fresh workflow principal.
The grant describes a bounded candidate space, not a yet-unknown candidate OID.

### 12.2 Exact executable child action

After evidence acquisition and candidate inspection, the workflow controller
derives one child proof for one `radicle.patch.open/1` action. The child proof:

- is audience-bound to one executor;
- contains the exact candidate and metadata digests;
- cannot delegate further;
- expires no later than the workflow grant;
- consumes the one-patch and one-revision budget;
- is useless for a changed candidate, repository, issue, base, signer, or
  verifier configuration.

The workflow private key MUST remain inside the workflow controller/executor
trust boundary and MUST be destroyed when the workflow becomes terminal.

## 13. Exact patch action

The exact action MUST bind:

```rust
struct OpenPatchActionV1 {
    profile: ProfileId,
    workflow_id: WorkflowId,
    rid: Rid,
    issue_id: CobId,
    repository_identity_revision: GitOid,
    canonical_base_oid: GitOid,
    candidate_oid: GitOid,
    candidate_bundle_digest: Digest,
    candidate_commit_set_digest: Digest,
    candidate_tree_delta_digest: Digest,
    patch_title_digest: Digest,
    patch_body_digest: Digest,
    issue_reference_digest: Digest,
    draft: bool,
    signer_did: RadicleDid,
    executor_audience: Audience,
    required_configuration_digest: Digest,
    evidence_snapshot_digest: Digest,
    publication_budget_ordinal: ExactU32<1>,
}
```

The action does not bind a patch ID or revision ID because Radicle creates those
as outputs. The executor MUST bind those outputs back to the action in the
execution receipt.

The action's canonical bytes and digest use the existing Auths canonical action
mechanism and digest primitive. The profile MUST NOT introduce a JSON-derived or
adapter-specific hashing scheme.

## 14. Canonicalization

Canonicalization MUST be independent of:

- JSON map order;
- local path separators;
- locale;
- Unicode normalization chosen by a UI;
- Git command output formatting;
- Radicle CLI display output;
- system clock formatting;
- peer observation order;
- hash-map iteration order.

Peer IDs, issue tips, commit IDs, changed paths, and mode changes MUST be sorted
using profile-defined byte ordering before hashing.

Titles and descriptions MUST be converted to canonical UTF-8 under explicit
length, line-ending, and forbidden-control-character rules.

The conformance corpus MUST include positive and negative fixtures for every
canonical field.

## 15. Candidate submission and inspection

### 15.1 Transport

The agent submits:

- a bounded Git bundle or equivalent bounded object package;
- the declared base OID;
- the declared candidate OID;
- the proposed patch title;
- the proposed patch description;
- the workflow session token.

The service MUST NOT accept a filesystem path, arbitrary Git remote URL, shell
fragment, or signer instruction from the agent.

### 15.2 Quarantine

Candidate objects MUST first enter a newly created quarantine repository that is
not the executor's Radicle storage and has:

- no hooks;
- no credential helpers;
- no writable remotes;
- no alternates supplied by the candidate;
- no submodule recursion;
- no worktree execution;
- strict object, pack, file, commit, depth, and decompression limits.

The candidate MUST NOT be imported into writable Radicle storage until after
authorization and the durable replay claim.

### 15.3 Required candidate facts

The inspector derives:

```rust
struct CandidateFacts {
    base_oid: GitOid,
    candidate_oid: GitOid,
    commits: Vec<CommitFact>,
    changed_paths: Vec<PathChange>,
    changed_file_count: u32,
    changed_byte_count: u64,
    tree_delta_digest: Digest,
    commit_set_digest: Digest,
    contains_merge: bool,
    contains_symlink: bool,
    contains_submodule: bool,
    forbidden_refs: Vec<RefName>,
    object_budget: ObjectBudgetResult,
}
```

The verifier MUST establish:

- the declared base and candidate exist;
- the base equals the grant's canonical base;
- the candidate is a descendant of the base;
- the history between them is linear;
- every changed path and file mode is permitted;
- all budgets are satisfied;
- no symlink, submodule, merge, or special mode exists;
- the bundle contains no Radicle COB refs, signed refs, identity refs, peer
  namespace refs, or other forbidden refs;
- the derived facts reproduce the exact-action digests.

### 15.4 Candidate mutability

The agent may submit multiple candidates before execution. Each accepted
replacement invalidates the prior inspection and exact action. Once the action
claim is consumed, no candidate replacement is allowed.

## 16. Radicle evidence

The evidence snapshot MUST contain:

```rust
struct RadicleEvidenceV1 {
    rid: Rid,
    repository_identity_revision: GitOid,
    delegates: Vec<RadicleDid>,
    delegate_threshold: u32,
    default_branch: RefName,
    canonical_head_oid: GitOid,
    canonical_derivation_digest: Digest,
    issue_id: CobId,
    issue_tip_ids: Vec<CobId>,
    issue_materialized_digest: Digest,
    issue_state: IssueState,
    issue_history_complete: bool,
    existing_patch_ids: Vec<CobId>,
    executor_signer_did: RadicleDid,
    executor_node_id: NodeId,
    executor_namespace_digest: Digest,
    synchronized_peers: Vec<NodeId>,
    synchronization_started_at: Timestamp,
    synchronization_completed_at: Timestamp,
    adapter_version: AdapterVersion,
}
```

Evidence is a statement about the executor's validated local storage at a
specific time. Receipts MUST use wording equivalent to:

> Canonical head derived locally after successful synchronization with the
> configured observation set.

They MUST NOT say:

> Latest global Radicle head.

### 16.1 Required synchronization policy

The MVP required configuration specifies:

- an allowlist of observation peer node IDs;
- a minimum of one successful configured peer;
- a maximum evidence age;
- a bounded synchronization timeout;
- identity-history completeness checks;
- issue-history completeness checks;
- canonical-reference derivation version;
- behavior for unreachable or conflicting peers.

Unreachable peers, incomplete histories, or an unverifiable canonical reference
produce an indeterminate outcome. A proven mismatch produces a denial.

## 17. Required and executed verifier configuration

Decision and execution receipts MUST contain both:

```rust
required_configuration: RadicleVerifierConfiguration
executed_configuration: RadicleVerifierConfiguration
```

They normally match because execution is forbidden otherwise. They remain
separate because the first records what the proof and context required, while
the second records what the running verifier actually loaded.

The executor MUST compare their canonical digests before evaluating evidence or
claiming the action:

```text
required_configuration_digest == executed_configuration_digest
```

A mismatch is `verifier-configuration-mismatch`; no Radicle write may occur.

The required configuration includes at least:

- profile version;
- candidate-inspector version;
- Radicle adapter compatibility version;
- canonical-reference derivation version;
- evidence synchronization policy;
- object and decompression hard limits;
- path normalization version;
- accepted Git object and file modes;
- expected signer DID;
- executor audience;
- receipt schema version.

## 18. Containment

`OpenPatchActionV1` is contained by `IssueAddressGrantV1` only if all of these
hold:

1. profile versions are identical and supported;
2. workflow IDs are identical;
3. RIDs and issue IDs are identical;
4. identity revisions are identical;
5. canonical base OIDs are identical;
6. all candidate paths, modes, sizes, and commits satisfy the grant;
7. title and description satisfy their machine constraints;
8. the deterministic issue reference is present and bound;
9. signer DIDs are identical;
10. executor audiences are identical;
11. required configuration digests are identical;
12. the evidence snapshot is fresh and complete;
13. the issue is open;
14. no existing action claim or publication consumed the budget;
15. no canonical, identity, delegate, or unrelated COB mutation is requested.

Containment MUST be a pure deterministic function over canonical grant, action,
candidate facts, and evidence facts.

It MUST NOT:

- invoke Git;
- invoke Radicle;
- access the network;
- read mutable process configuration;
- call a language model;
- parse natural-language policy;
- depend on wall-clock time except through an explicit evaluation timestamp.

## 19. Sealed verified command

Successful verification creates a non-serializable or capability-protected
command:

```rust
struct VerifiedOpenPatchCommand {
    workflow_id: WorkflowId,
    action_digest: Digest,
    exact_action: OpenPatchActionV1,
    verified_candidate: VerifiedCandidateHandle,
    verified_evidence: VerifiedEvidenceHandle,
    claim_token: ExecutionClaimToken,
}
```

Only the verifier may construct this type. The Radicle write adapter accepts
this type and MUST NOT expose a parallel API accepting raw RID, OID, title,
description, refs, or command-line arguments.

The command is single-use. It cannot be cloned, persisted as bearer authority,
or converted into a generic signer request.

## 20. Execution flow

The executor performs this sequence:

1. authenticate the workflow session;
2. load the grant and proof chain;
3. load and compare required and executed configuration;
4. synchronize configured Radicle evidence peers;
5. materialize repository identity, canonical reference, and issue history;
6. inspect the candidate in quarantine;
7. derive candidate and evidence facts;
8. derive the exact patch action;
9. verify the proof, audience, expiry, action binding, and containment;
10. re-check identity revision, canonical base, issue state, and signer DID;
11. durably claim the exact action digest and publication budget;
12. import only the verified candidate objects required for publication;
13. create exactly one Radicle patch with exactly one revision;
14. verify the returned patch ID, revision ID, candidate OID, signer, title, and
    description against the sealed command;
15. persist the local publication result and execution receipt;
16. announce the signed refs;
17. ask the independent observer to synchronize;
18. verify that the observer materializes the same patch and revision;
19. append propagation observations to the receipt stream.

Steps 1–11 MUST complete before the signer or writable node performs a mutation.

The adapter MUST build the mutation from typed fields. It MUST NOT interpolate a
shell command.

## 21. Workflow and propagation state

Mutation state and network observation are separate state machines.

### 21.1 Mutation state

```text
Authorized
    -> CandidateAccepted
    -> Inspected
    -> ActionClaimed
    -> Executing
    -> PublishedLocally
```

Pre-claim failures may become:

```text
Denied
Indeterminate
Expired
Cancelled
```

A crash during execution becomes:

```text
PublicationUnknown
```

It MUST NOT automatically retry.

### 21.2 Propagation observation

```text
NotAttempted
    -> Announcing
    -> Announced
    -> ReplicationPending
    -> Replicated
```

Other observation states are:

```text
AnnouncementFailed
ReplicationTimedOut
ObserverUnavailable
```

These do not reverse `PublishedLocally`.

### 21.3 Completion

The product workflow succeeds when local publication is proven. The live demo
adds a stronger presentation goal: confirmation by at least one independent
observer.

## 22. Replay protection and crash safety

The claim store MUST atomically enforce uniqueness for:

```text
(executor_audience, action_digest)
(workflow_id, publication_budget_ordinal)
```

The claim is consumed before mutation and is never released merely because a
later step times out.

### 22.1 Replay

Submitting the same proof or pressing execute twice MUST return the original
claim/publication status and MUST NOT create another patch.

### 22.2 Crash before mutation

If the durable journal proves no write adapter invocation began, reconciliation
may safely mark the claim failed-before-publication. The MVP still requires a
new workflow action rather than silently reusing the consumed action.

### 22.3 Crash during or after mutation

The reconciler searches executor storage and signed refs for a unique result
matching:

- signer DID;
- RID;
- candidate OID;
- title and description digests;
- issue reference;
- journal time and namespace bounds.

If exactly one result matches, it records success. If none or more than one
matches, it records `publication-ambiguous` and MUST NOT retry automatically.

Safety from duplicate publication takes precedence over automatic liveness.

## 23. Receipts

### 23.1 Decision receipt

The decision receipt includes:

- workflow and action IDs/digests;
- authorizer and agent Auths principals;
- grant lineage digest;
- executor audience;
- required and executed configurations and digests;
- RID, issue ID, identity revision, and canonical base;
- candidate OID and candidate fact digests;
- evidence snapshot digest and synchronization summary;
- containment result;
- stable decision code;
- evaluation timestamp;
- profile and adapter versions.

### 23.2 Execution receipt

The execution receipt includes:

- decision receipt digest;
- action claim ID;
- Radicle signer DID;
- executor node ID;
- patch ID;
- revision ID;
- candidate OID;
- signed/storage postcondition;
- announcement status;
- observer node ID and replication status;
- canonical transition requested and observed flags;
- reconciliation status;
- started and completed timestamps;
- stable execution code.

### 23.3 Receipt invariants

- A decision receipt does not claim execution.
- An execution receipt does not collapse authorization, signing, storage,
  announcement, replication, and canonical state into one boolean.
- A denied or indeterminate decision has no execution receipt.
- A local publication receipt remains valid if later peers are offline.
- Receipt projection may redact proofs and private claims without changing
  digests.

## 24. Stable outcome codes

The MVP defines at least:

### Authorization and configuration

```text
authorized
workflow-proof-invalid
workflow-expired
workflow-cancelled
audience-mismatch
verifier-configuration-mismatch
signer-identity-mismatch
publication-budget-exhausted
action-replayed
```

### Repository and evidence

```text
rid-mismatch
repository-identity-revision-mismatch
canonical-head-mismatch
issue-mismatch
issue-not-open
evidence-stale
evidence-history-incomplete
evidence-sync-unavailable
canonical-state-indeterminate
```

### Candidate

```text
candidate-malformed
candidate-base-mismatch
candidate-not-descendant
candidate-head-mismatch
candidate-digest-mismatch
candidate-limit-exceeded
candidate-merge-forbidden
candidate-symlink-forbidden
candidate-submodule-forbidden
candidate-file-mode-forbidden
candidate-path-forbidden
candidate-ref-forbidden
candidate-cob-ref-forbidden
candidate-signed-ref-forbidden
patch-metadata-mismatch
```

### Execution and propagation

```text
patch-published-locally
patch-postcondition-mismatch
publication-failed-before-write
publication-unknown
publication-ambiguous
announcement-failed
replication-pending
replication-confirmed
replication-timed-out
observer-unavailable
```

Codes are stable API values. Human explanations may evolve.

## 25. Public Rust API

The exact API may evolve during implementation, but the trust shape is
normative.

```rust
pub trait RadicleReadPort {
    fn synchronize(
        &self,
        rid: &Rid,
        policy: &SynchronizationPolicy,
    ) -> Result<SynchronizationReport, EvidenceError>;

    fn evidence(
        &self,
        rid: &Rid,
        issue: &CobId,
    ) -> Result<RadicleEvidenceV1, EvidenceError>;

    fn find_matching_publication(
        &self,
        query: &PublicationReconciliationQuery,
    ) -> Result<Vec<ObservedPatch>, EvidenceError>;
}

pub trait RadicleWritePort {
    fn open_patch(
        &self,
        command: VerifiedOpenPatchCommand,
    ) -> Result<LocalPublication, PublicationError>;

    fn announce(
        &self,
        publication: &LocalPublication,
    ) -> Result<Announcement, PublicationError>;
}

pub trait RadicleSignerPort {
    fn signer_did(&self) -> Result<RadicleDid, SignerError>;
}

pub trait ReplicationObserverPort {
    fn observe(
        &self,
        expected: &ExpectedPublication,
    ) -> Result<ReplicationObservation, ObservationError>;
}

pub trait WorkflowStore {
    fn create(&self, workflow: NewWorkflow) -> Result<Workflow, StoreError>;
    fn claim_action(
        &self,
        workflow: &WorkflowId,
        action: &Digest,
        ordinal: u32,
    ) -> Result<ExecutionClaimToken, ClaimError>;
    fn record_publication(
        &self,
        claim: ExecutionClaimToken,
        result: &LocalPublication,
    ) -> Result<(), StoreError>;
}

pub trait ReceiptSink {
    fn append_decision(&self, receipt: DecisionReceipt) -> Result<(), ReceiptError>;
    fn append_execution(&self, receipt: ExecutionReceipt) -> Result<(), ReceiptError>;
    fn append_observation(
        &self,
        observation: PropagationReceipt,
    ) -> Result<(), ReceiptError>;
}
```

`RadicleWritePort::open_patch` MUST be unreachable without
`VerifiedOpenPatchCommand`.

## 26. Product service API

The vertical package exposes use cases, not adapters:

```rust
pub trait RadicleIssueWorkflowService {
    fn create_workflow(
        &self,
        request: CreateIssueWorkflow,
    ) -> Result<WorkflowView, ServiceError>;

    fn submit_candidate(
        &self,
        workflow: WorkflowId,
        candidate: CandidateSubmission,
    ) -> Result<CandidateView, ServiceError>;

    fn inspect(
        &self,
        workflow: WorkflowId,
    ) -> Result<InspectionView, ServiceError>;

    fn execute(
        &self,
        workflow: WorkflowId,
    ) -> Result<ExecutionView, ServiceError>;

    fn status(
        &self,
        workflow: WorkflowId,
    ) -> Result<WorkflowView, ServiceError>;

    fn receipts(
        &self,
        workflow: WorkflowId,
    ) -> Result<ReceiptView, ServiceError>;

    fn reconcile(
        &self,
        workflow: WorkflowId,
    ) -> Result<ReconciliationView, ServiceError>;

    fn cancel(
        &self,
        workflow: WorkflowId,
    ) -> Result<WorkflowView, ServiceError>;
}
```

Adapters are selected at process startup from trusted configuration. Requests
cannot choose a signer, node storage path, observation peer, profile version, or
hard limit.

## 27. HTTP API for the live demo

The public demo coordinator exposes:

```text
GET  /api/health
POST /api/sessions
GET  /api/sessions/{session_id}
POST /api/sessions/{session_id}/candidate
POST /api/sessions/{session_id}/inspect
POST /api/sessions/{session_id}/execute
POST /api/sessions/{session_id}/replay
GET  /api/sessions/{session_id}/receipts
GET  /api/sessions/{session_id}/replication
```

Candidate requests select a server-defined fixture:

```json
{
  "variant": "valid"
}
```

The public service MUST NOT accept arbitrary Git bytes, repository identifiers,
peer addresses, Radicle commands, or patch text.

Every response includes:

```json
{
  "workflow_state": "PublishedLocally",
  "propagation_state": "Replicated",
  "decision_code": "authorized",
  "execution_code": "patch-published-locally",
  "correlation_id": "...",
  "receipt_urls": []
}
```

The exact JSON schema MUST be generated from shared API types and versioned.

## 28. End-to-end demonstration

### 28.1 What the demo must prove

The demo is successful only if a visitor can observe all of these facts:

1. a human-level grant defines a bounded patch space;
2. an agent without a Radicle key produces a candidate;
3. direct publication from the agent environment fails;
4. the real Auths verifier accepts or rejects the exact candidate;
5. the protected Radicle signer publishes only an accepted candidate;
6. the result is a real Radicle patch and revision, not a mocked record;
7. a second independent node replicates and materializes that patch;
8. the Radicle publisher and Auths authority chain remain distinguishable;
9. the canonical branch is unchanged;
10. replay does not create a second patch.

### 28.2 Demo repository

The deployment provisions:

- one dedicated public Radicle demo repository;
- one persistent RID recorded in deployment configuration;
- one open issue used only for this demo;
- one non-delegate executor Radicle identity;
- one executor node with persistent writable storage;
- one independent observer node with separate identity and storage;
- a bounded set of safe, server-generated candidate fixtures.

Real RIDs, DIDs, node IDs, issue IDs, patch IDs, and revision IDs MUST be
displayed from runtime evidence. The frontend MUST NOT contain invented example
identifiers in the live result.

### 28.3 Demo candidate

Each permitted live session receives a server-generated candidate that changes
only:

```text
demo/runs/<session-id>.txt
```

The file contains public, non-sensitive session data. The candidate is a linear
one-commit descendant of the currently pinned demo base. The grant permits only
the exact demo path prefix and small hard limits.

The candidate is still inspected through the same quarantine and containment
path used by the product package.

### 28.4 Side-by-side interaction

Controls and results MUST be visible together without scrolling on a normal
desktop viewport.

```text
+--------------------------------+  +--------------------------------------+
| CHANGE THE EVIDENCE            |  | LIVE AUTHORIZATION + PUBLICATION     |
|                                |  |                                      |
| (•) Exact candidate            |  | Auths decision      AUTHORIZED       |
| ( ) Candidate byte changed     |  | Stable code         authorized       |
| ( ) Different RID              |  | Signer              did:key:...      |
| ( ) Different issue            |  | Local storage       STORED           |
| ( ) Base moved                 |  | Announcement        ANNOUNCED        |
| ( ) Forbidden path             |  | Observer            REPLICATED       |
| ( ) Verifier config changed    |  | Canonical branch    UNCHANGED        |
|                                |  | Patch / revision    real identifiers |
| [Inspect] [Publish exact patch]|  | [Receipt] [Verify on observer]       |
+--------------------------------+  +--------------------------------------+
```

All experiment selectors MUST look and behave like controls. They MUST be
keyboard accessible. Loading, disabled, connecting, denied, indeterminate,
published, and replication-pending states MUST each have distinct copy.

The page MUST show useful controls on first paint. It MUST NOT present a disabled
“connecting” button as the primary affordance.

### 28.4.1 Auths design language

The Radicle demo MUST look and feel like an interactive part of
`auths-proof-site`, not a standalone developer dashboard or a separately branded
product.

`auths-proof-site` is the visual source of truth for:

- typography and type scale;
- color tokens and contrast;
- spacing and layout rhythm;
- borders, radii, shadows, and surface treatment;
- navigation and page framing;
- eyebrow labels, headings, body copy, and technical metadata;
- buttons, selectors, status badges, cards, and disclosure controls;
- diagrams, code and identifier presentation;
- loading, transition, hover, focus, success, denial, and error motion;
- desktop and mobile responsive behavior.

The implementation SHOULD reuse compatible site tokens and components where
the repository boundary permits. When direct reuse is impractical, the demo
MUST carry an explicitly derived token layer rather than approximate the site by
eye. That layer MUST record:

- the source `auths-proof-site` commit;
- the token or component source paths;
- intentional demo-specific deviations and their rationale;
- the process for checking and adopting later site changes.

The demo MUST preserve the site's editorial character while keeping experiment
controls unmistakably interactive. Brand consistency MUST NOT reduce control
visibility, focus indication, contrast, or status clarity.

The default screen, selected experiment, authorized result, denied result,
indeterminate result, publication progress, replicated result, and mobile layout
MUST have screenshot fixtures reviewed alongside equivalent
`auths-proof-site` reference surfaces.

### 28.5 Real happy-path sequence

The live run performs:

1. create a short-lived workflow and human-level grant;
2. display the resolved RID, issue, identity revision, base, signer, and
   audience;
3. run a publication attempt in the agent sandbox and show that it lacks the
   signer and writable node boundary;
4. generate and submit the bounded candidate;
5. synchronize the executor node from configured peers;
6. inspect candidate and Radicle evidence;
7. derive and verify the exact action;
8. atomically consume the publication budget;
9. open one real patch with the protected Radicle signer;
10. verify local signed storage and show the real patch/revision IDs;
11. announce the result;
12. synchronize the independent observer;
13. materialize the patch on the observer and compare RID, signer, candidate
    OID, patch ID, revision ID, title, and description;
14. show decision, execution, and propagation receipts;
15. replay the same action and show that no second patch was created.

### 28.6 Experiments

The demo MUST include:

| Experiment | Expected result |
| --- | --- |
| Exact candidate | Authorized, published locally, then independently replicated |
| Candidate byte changed after authorization | `candidate-digest-mismatch` |
| Different RID | `rid-mismatch` |
| Different issue | `issue-mismatch` |
| Canonical base moved | `canonical-head-mismatch` |
| Forbidden path | `candidate-path-forbidden` |
| Candidate contains signed or COB ref | `candidate-ref-forbidden` |
| Expected signer changed | `signer-identity-mismatch` |
| Required verifier configuration changed | `verifier-configuration-mismatch` |
| Incomplete issue history | `evidence-history-incomplete` and indeterminate |
| Replay exact action | original result, no second patch |
| Observer unavailable after publication | local success plus `observer-unavailable` |

Tamper and denial experiments are unlimited because they do not mutate Radicle.
Live publication is quota-controlled.

### 28.7 Honest peer-to-peer status

The UI MUST never reduce the result to one “success” badge. It shows:

```text
AUTHORIZED
SIGNED
STORED LOCALLY
ANNOUNCED
REPLICATED BY OBSERVER
CANONICAL: NOT REQUESTED
```

If observation is delayed, the UI keeps the locally published patch visible and
labels replication `PENDING`, `TIMED OUT`, or `OBSERVER UNAVAILABLE`.

### 28.8 Append-only demo policy

Published Radicle data may have replicated to peers and cannot be truthfully
described as deleted by cleaning one deployment volume.

Therefore:

- the demo repository is explicitly disposable and append-only;
- no cleanup job claims to erase previously replicated patches;
- successful public mutations are rate-limited and globally capped per day;
- each session may publish at most one patch;
- users may replay verification and denial cases without mutation;
- repository rotation is an operator action that creates a new RID and preserves
  the old RID in the deployment ledger;
- public receipts contain no secrets or personal data.

### 28.9 Verification artifact

Every successful run exposes:

- real RID;
- issue ID;
- patch ID;
- revision ID;
- candidate OID;
- executor signer DID;
- executor node ID;
- observer node ID;
- signed receipt digests;
- an observer-generated materialization record;
- a copyable version-pinned command or link for independently viewing the patch
  when the deployed Radicle client supports it.

The observer record is generated from observer storage, not echoed from the
executor response.

## 29. Demo deployment

The reference deployment uses three independently deployable surfaces.

### 29.1 Frontend

Deploy the static/browser application to Vercel.

The frontend:

- contains no Radicle key;
- contains no workflow private key;
- calls only the public coordinator API;
- implements the `auths-proof-site`-derived design token and component contract
  defined by this specification;
- records the source `auths-proof-site` commit in build metadata;
- permits only fixed experiment variants;
- uses exact-origin CORS;
- shows a deployment/version identifier;
- treats API and observer unavailability as explicit states.

### 29.2 Executor and coordinator

Deploy the native Rust service to Fly.io in geography A with:

- a persistent volume for Radicle storage;
- a dedicated Radicle signer secret;
- a dedicated node identity;
- durable workflow, claim, and receipt storage;
- private access to the signer and writable node interfaces;
- public TLS only on the bounded coordinator API;
- concurrency and mutation-rate limits;
- startup validation of RID, signer DID, audience, peer set, and profile version;
- health checks that distinguish API health, signer readiness, storage
  readiness, and peer synchronization.

Only one active writer instance may own the signer and writable volume unless a
future design supplies coordinated claims and safe signer sharing.

### 29.3 Independent observer

Deploy a second Fly.io service in geography B with:

- a different node identity;
- a separate persistent volume;
- no executor signer secret;
- no workflow signing key;
- no write route exposed to the public;
- a private, authenticated read-only observation API;
- independent synchronization and materialization logic.

The observer MUST NOT mount, proxy, or query the executor's local storage.

### 29.4 Network path

```text
Browser on Vercel
    -> HTTPS coordinator on Fly geography A
        -> local protected signer and node storage
        -> Radicle announcement / synchronization
            -> observer node on Fly geography B
        <- authenticated observer result
    <- stage-by-stage public response
```

### 29.5 Deployment configuration

Secrets:

- executor Radicle signing key;
- workflow service signing key or root delegation material;
- session-token key;
- observer API authentication secret;
- receipt signing key, if separate.

Non-secret pinned configuration:

- RID;
- issue ID;
- expected repository identity revision policy;
- executor signer DID;
- executor and observer node IDs;
- executor Auths audience;
- observation peer allowlist;
- synchronization policy;
- profile, adapter, and receipt schema versions;
- public origins;
- publication quotas;
- deployed source commit.

The service MUST fail closed on missing or inconsistent configuration.

### 29.6 Deployment gates

A production demo deployment is promoted only after:

1. build artifacts are reproducible from the recorded commit;
2. the executor and observer use different identities and volumes;
3. the executor signer is confirmed non-delegate;
4. the browser has no signer or node credentials;
5. the real two-node smoke test opens and replicates one canary patch;
6. replay produces no second patch;
7. a forced observer outage renders local success correctly;
8. the deployment exposes the expected profile and adapter versions;
9. secret scanning and dependency policy pass;
10. browser automation passes against the production URL;
11. desktop and mobile visual-regression fixtures match the approved
    `auths-proof-site` design-language baseline;
12. the deployed frontend reports the expected `auths-proof-site` source commit.

## 30. Security requirements

### 30.1 Signer boundary

- The agent and browser MUST never receive the Radicle key.
- The signer MUST accept only a sealed verified command.
- Signer identity is checked before and after mutation.
- The signer process or adapter MUST reject generic signing input from product
  API callers.
- Logs MUST not contain key material, proofs, bearer tokens, or unredacted
  secrets.

### 30.2 Node and storage boundary

- Writable storage is mounted only into the executor trust domain.
- The agent checkout is disposable and read-only with respect to publication.
- Radicle CLI configuration from the candidate is ignored.
- Environment variables, Git configuration, hooks, credential helpers,
  alternates, and remotes are supplied from trusted configuration.
- The observer is independently stored and independently synchronized.

### 30.3 Git input

- All candidate input is hostile.
- Hard compressed and expanded byte limits are enforced before expensive work.
- Object count, delta depth, tree depth, path length, commit count, and diff
  limits are hard failures.
- No candidate-controlled program or hook runs.
- No submodule, symlink, merge, special mode, signed ref, identity ref, COB ref,
  or peer namespace ref is accepted.
- A candidate object is not copied to the live store before the execution claim.

### 30.4 Service

- Session IDs are unguessable and expire.
- Mutation endpoints are CSRF-protected where browser credentials apply.
- CORS is an exact allowlist.
- Rate limits apply per IP, session, and global publication budget.
- Request bodies are bounded before parsing.
- Every state transition is authorized server-side.
- Public fixture selection cannot override trusted RID, signer, peer, or
  configuration values.

### 30.5 Failure semantics

- Evidence uncertainty fails indeterminate.
- Proven policy mismatch fails denied.
- Unknown publication state never retries automatically.
- Propagation failure never rewrites local publication as denial.
- Postcondition mismatch isolates the executor and requires operator review.

## 31. Testing and conformance

### 31.1 Unit tests

Unit tests MUST cover:

- canonical resource and action encoding;
- type separation for Auths, Radicle DID, node, RID, COB, and Git identifiers;
- every containment rule;
- path normalization and boundary cases;
- title and description canonicalization;
- issue-reference generation;
- hard file, byte, object, depth, and commit limits;
- required versus executed configuration equality;
- action digest changes for every security-relevant field;
- stable outcome-code mapping;
- mutation and propagation state transitions;
- receipt redaction without digest changes.

One unit test MUST construct different required and executed configurations,
prove that the decision is `verifier-configuration-mismatch`, and assert that
the write adapter and signer were never called.

### 31.2 Property and adversarial tests

Tests MUST generate or mutate:

- candidate bundle bytes;
- object ordering;
- path encodings;
- non-UTF-8 paths;
- nested trees;
- decompression ratios;
- malformed and cyclic-looking object graphs;
- duplicate and conflicting refs;
- Radicle signed refs;
- identity refs;
- COB refs;
- peer namespaces;
- changed issue tips;
- changed identity revisions;
- changed canonical heads;
- changed signer DIDs;
- changed audiences;
- changed verifier versions;
- reordered peer observations.

Any semantically meaningful change MUST either change the exact-action digest or
produce a stable denial/indeterminate outcome.

### 31.3 Integration tests

Integration tests MUST use real Git object handling and version-pinned Radicle
adapters to prove:

- allowed source and test changes pass;
- forbidden changes fail before signing;
- one real patch and revision are created;
- output patch/revision fields match the sealed command;
- executor signer is the visible publisher;
- canonical branch does not change;
- replay creates no second patch;
- crash-before-write and crash-after-write reconcile safely;
- announcement failure preserves local success;
- an independent node can replicate and materialize the patch.

### 31.4 End-to-end tests

The deployment suite MUST run:

1. a real happy path;
2. every demo tamper variant;
3. direct publication from the agent sandbox;
4. double-click and concurrent replay;
5. executor restart during publication;
6. observer outage and recovery;
7. stale evidence and moved-base cases;
8. production browser interaction and accessibility checks;
9. desktop and mobile visual-regression checks against the approved
   `auths-proof-site`-derived fixtures.

### 31.5 Conformance corpus

The package publishes versioned fixtures containing:

- canonical grants;
- canonical exact actions;
- expected action digests;
- valid and invalid candidate facts;
- valid, stale, incomplete, and conflicting evidence;
- required/executed configuration pairs;
- expected containment outcomes and stable codes;
- example decision, execution, and propagation receipts.

Independent implementations MUST produce identical canonical bytes, digests,
and decisions for the corpus.

## 32. CI architecture enforcement

Repository checks MUST enforce:

1. only `product/integrations/auths-radicle` may depend directly on Radicle
   protocol/node libraries in production code;
2. core, exchange, bindings, and unrelated products contain no Radicle-specific
   identifiers or dependencies;
3. the demo depends on the product's public API and cannot import its internal
   adapters;
4. browser and agent packages cannot depend on signer or writable-node crates;
5. all unsafe dependency and feature additions are visible in an allowlisted
   dependency map;
6. the product package has one direction of dependency toward core, stores, and
   receipts, never the reverse;
7. the only write-adapter entry point requires `VerifiedOpenPatchCommand`;
8. profile conformance fixtures are regenerated only through a reviewed command
   and checked for drift;
9. all workspace packages use the repository edition, resolver, and MSRV policy;
10. secret scanning, license policy, vulnerability policy, formatting, linting,
    unit, adversarial, integration, and two-node tests pass.

`xtask` SHOULD provide:

```text
cargo xtask architecture
cargo xtask dependency-map
cargo xtask profile-conformance auths.radicle.issue-address/1
cargo xtask radicle-two-node
cargo xtask demo-smoke
```

The architecture check MUST parse package metadata and source dependency edges;
it MUST NOT rely only on folder naming.

## 33. Observability

Metrics MUST distinguish:

- workflow creation;
- candidate acceptance and denial by stable code;
- evidence synchronization latency and completeness;
- verifier decisions;
- claims and replay hits;
- signer invocations;
- local publication success and ambiguity;
- announcement success and failure;
- replication latency per observer;
- observer timeouts;
- reconciliation outcomes.

Logs use correlation IDs and digests, not raw proofs, candidate contents,
credentials, or private keys.

Alerts SHOULD fire on:

- signer identity mismatch;
- write adapter invocation without a valid claim;
- postcondition mismatch;
- publication ambiguity;
- repeated observer divergence;
- quota bypass;
- unexpected canonical branch movement caused by the executor identity.

## 34. MVP implementation sequence

### Phase 1: Profile and fixtures

- implement canonical types, grant, exact action, configuration, and containment;
- publish conformance fixtures;
- implement stable decision codes;
- prove configuration mismatch prevents writes.

### Phase 2: Candidate boundary

- implement bounded bundle ingestion and quarantine;
- implement Git facts and hard limits;
- reject forbidden refs, COB state, signed refs, symlinks, submodules, and merges;
- add adversarial corpus.

### Phase 3: Radicle evidence

- implement version-pinned read adapter;
- synchronize configured peers;
- materialize identity, canonical reference, and issue;
- prove completeness or return indeterminate.

### Phase 4: Workflow and executor

- implement ephemeral workflow principal and exact child action;
- implement durable claim and one-publication budget;
- implement sealed command and protected signer/write adapter;
- verify postconditions and reconcile unknown execution.

### Phase 5: Two-node propagation

- provision independent executor and observer nodes;
- announce, synchronize, materialize, and compare a real patch;
- emit separate execution and propagation receipts.

### Phase 6: Live demo

- build side-by-side UI and fixed experiments;
- deploy Vercel frontend and two Fly.io services;
- add quotas and append-only disclosure;
- run production browser, replay, outage, and canary tests;
- publish the real demo URL and verification artifacts.

## 35. MVP acceptance criteria

The MVP is complete only when:

1. one human grant is issued for one RID and open issue;
2. the agent environment has no Radicle signer or writable node access;
3. a valid bounded candidate is accepted;
4. an allowed source change and allowed test change are accepted;
5. a forbidden path is denied;
6. a different RID is denied;
7. a different issue is denied;
8. a moved canonical base is denied;
9. a changed candidate byte invalidates the exact action;
10. signed, identity, peer, and COB refs are denied;
11. a verifier-configuration mismatch prevents any signer or write call;
12. one real Radicle patch with one revision is published locally;
13. the returned candidate, patch, revision, metadata, and signer match the
    exact action;
14. the executor identity is visibly the Radicle publisher;
15. the executor is not a repository delegate;
16. the canonical branch is unchanged;
17. an independent node replicates and materializes the same patch;
18. replay and concurrent double execution create no second patch;
19. a propagation outage is shown separately from local publication;
20. receipts preserve Auths authority lineage and distinct Radicle identities;
21. the deployed public demo proves the same path using real services;
22. CI enforces the vertical package and trust-boundary dependency rules;
23. the demo is visually and editorially consistent with the pinned
    `auths-proof-site` design-language baseline.

The final demonstration statement is:

```text
The agent could author arbitrary local Git history.

It could not sign, publish, update Radicle identity, act as a delegate,
or alter canonical state.

The protected executor published exactly one authorized patch.

A separate peer independently observed that exact signed patch.
```

## 36. Deferred work

The following require later profile actions or versions:

- patch revisions;
- issue and patch comments;
- reviews and revision-specific approvals;
- cancellation after partial execution;
- private repositories;
- multiple executors;
- global or replicated replay coordination;
- custom Auths COB transport;
- receipt publication inside Radicle;
- human-identity publication;
- delegate execution;
- merge and canonical-reference updates;
- K-of-N Auths approvals;
- coordination with Radicle delegate thresholds;
- repository identity and delegate changes;
- multi-domain build and deployment workflows.

Patch revision MUST be a new exact action bound to the prior patch ID, prior
revision ID, new candidate OID, and new immutable metadata.

Merge MUST be a separate workflow. Auths authorization and Radicle delegate
threshold satisfaction remain independent, separately receipted conditions.

## 37. Architectural invariants

1. The Auths kernel remains Radicle-blind.
2. Radicle-specific behavior remains in one vertical product package.
3. The agent never receives signer or writable-node authority.
4. The executor accepts only a sealed exact command.
5. The signer DID is not conflated with Auths principals or node identity.
6. The executor is not a repository delegate in the MVP.
7. Evidence describes a synchronized local view, not global truth.
8. Incomplete peer history is indeterminate.
9. The exact canonical base is re-checked immediately before execution.
10. One workflow can publish at most one patch and one revision.
11. Replay safety is durable and local to the executor audience.
12. Unknown publication state never triggers an automatic retry.
13. Local publication, announcement, replication, and canonical state are
    distinct receipt facts.
14. No MVP action changes canonical state, repository identity, or delegates.
15. Required and executed configurations are both recorded and MUST match.
16. Profile semantic changes require explicit version management.
17. The live demo uses real Radicle storage, signing, and independent
    replication.
18. The demo never claims append-only replicated data was globally deleted.

## 38. Final framing

The integration should be described as:

> Auths adds portable, attenuated authorization lineage to Radicle actions and
> creates a sealed boundary between an untrusted agent and a protected Radicle
> signer.

The complete responsibility chain is:

```text
The grant defines the permitted patch space.

The agent produces a candidate Git history.

The candidate verifier establishes the Git facts.

The Radicle evidence layer establishes repository, canonical-reference,
and collaborative-object context from a validated local view.

The Auths kernel verifies the authority chain.

The Radicle profile proves that one exact patch action is inside the grant.

The workflow controller consumes the one-publication budget.

The executor signs and stores only the sealed verified command.

Radicle signs, stores, announces, and replicates the resulting patch.

An independent observer proves peer-to-peer propagation.

Repository delegates and Radicle canonical-reference logic remain responsible
for any later canonical branch transition.

Receipts preserve why the action was authorized and exactly what happened.
```

## 39. Milestone 5 shared-lifecycle cutover contract

The Milestone 5 source cutover replaces the production `WorkflowStore` claim
machine with the shared bounded-policy and durable-lifecycle kernels. It does
not move Radicle identity, Git object inspection, collaborative-object
semantics, synchronized local evidence, signer custody, publication,
announcement, propagation observation, reconciliation interpretation, stable
domain codes, or public receipt meaning into shared code.

The exact patch-open effect has these closed shared-contract identities:

| Concept | Identifier |
| --- | --- |
| shared profile | `auths.radicle.issue-address/1` |
| policy type | `auths.radicle.issue-address-grant/1` |
| evaluator semantic | `auths.radicle.issue-address.evaluate/1` |
| implementation | `auths-radicle/shared-lifecycle-production/1` |
| configuration semantic | `auths.radicle.verifier-configuration/1` |
| evidence schema | `auths.radicle.repository-issue-evidence/1` |
| evidence source | `radicle-synchronized-local-view/1` |
| state schema | `auths.radicle.patch-publication-snapshot/1` |
| workflow-budget intent | `auths.radicle.workflow-publication-budget-intent/1` |
| exact-action intent | `auths.radicle.exact-action-claim-intent/1` |
| reservation algebra | `auths.radicle.patch-open-exclusive-composite/1` |
| obligation schema | `auths.radicle.verified-open-patch-command/1` |
| provider contract | `auths.radicle.local-patch-publication/1` |
| domain | `radicle` |

One authorized patch action projects to two atomic exclusive reservations:

```text
(
  executor audience,
  workflow ID,
  publication budget ordinal
)

(
  executor audience,
  exact action digest
)
```

The first reservation conserves the one-publication workflow budget even when
two different candidate actions race. The second makes the exact action claim
unique for the executor audience. The exact RID, issue, identity revision,
canonical base, candidate and metadata digests, signer DID, configuration, and
fresh evidence remain committed separately by the policy input and sealed
provider command. Neither scope is widened into a generic repository lock or
global Radicle claim.

The migrated production path records, in order:

```text
domain decision receipt
  -> domain recovery record
  -> shared decision
  -> atomic reservation set
  -> execution intent
  -> signer credential authorization
  -> fresh critical Radicle evidence
  -> provider attempt
  -> provider-call entry
  -> committed | failed before effect | outcome unknown
  -> reconciliation observation
  -> reconciled committed | still outcome unknown
```

The signer boundary remains Radicle-owned. It may accept only durable
`ExecutionAuthorizationV1` for the exact execution intent. The local
publication adapter may accept only an operation-specific sealed
`VerifiedOpenPatchCommand` containing durable
`ProviderCallAuthorizationV1`. Neither boundary accepts an unsealed action, a
generic claim token, a boolean authorization result, arbitrary Git ref input,
or a generic Radicle command.

Identity revision, canonical base, issue state, signer DID, executor node, and
required synchronization facts are observed again after signer authorization
and immediately before provider-call entry. Any mismatch stops before
publication and releases both reservations through a durable failed-before-
effect transition.

An error after provider-call entry is conservatively
`publication-unknown` unless the adapter proves that no signer or writable
storage mutation began. Outcome unknown retains both reservations and cannot
be retried. Reconciliation is authorized only from the durable unknown record
and may inspect exact local signed refs and collaborative objects. Exactly one
matching local publication commits the lifecycle without calling the writer.
No match or multiple matches remains `publication-ambiguous` and retains the
reservations, preserving the existing Radicle safety rule. Reconciliation
cannot publish, announce, or retry a patch.

Local publication is the shared lifecycle effect boundary. Announcement and
independent replication remain domain-owned post-commit stages. A replay of a
committed local publication returns the original execution result and may
resume only pending announcement or observation. It never invokes
`open_patch` again. Announcement failure or observer unavailability does not
reverse or release a committed publication.

The domain recovery record binds the exact action, candidate commitments and
inspected facts, planning evidence, decision receipt, claim, and shared
workflow identity. It is durably staged before shared state can retain
capacity, but carries no authority by itself. Restart must revalidate every
commitment against the shared lifecycle record before it may reconcile or
resume post-commit propagation.

Auths-proof is prelaunch and has no production Radicle workflow state. The
prior workflow-store JSON is therefore obsolete and rejected at startup.
There is no legacy reader, state migration, dual write, compatibility shim,
runtime rollback path, or second production execution path. The prior pure
evaluator remains only as the semantic oracle used for differential
qualification.

The cutover is accepted only when:

1. all unchanged decisions, stable codes, exact commands, workflow stages,
   and canonical receipt bytes match the frozen reference fixtures;
2. concurrent different actions for one workflow ordinal permit at most one
   publication, and concurrent exact actions permit at most one publication;
3. configuration mismatch, containment denial, stale evidence, and fresh-
   evidence drift stop before signer access and provider invocation;
4. crash before provider-call entry releases safely, while crash after
   possible publication becomes durable outcome unknown;
5. restart plus an exact local observation commits without a second
   publication, while absent or conflicting observations remain ambiguous;
6. exact replay performs no signer, writer, or duplicate receipt mutation;
7. post-commit announcement and propagation can resume without repeating
   local publication;
8. corrupt or obsolete persisted state is rejected;
9. candidate inspection, Radicle evidence, signer custody, publication,
   announcement, observation, reconciliation, and public receipts remain in
   the Radicle vertical; and
10. the old production claim orchestration is removed after exact
    differential and live behavior pass.
