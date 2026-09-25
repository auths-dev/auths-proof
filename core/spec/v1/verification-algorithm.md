# Verification Algorithm — V1

## Inputs

- encoded `ProofBundle`;
- canonical `CanonicalAction` CBOR, including profile, media type, permission,
  budget request, canonical body, and bounded detached attachment bytes;
- immutable verifier context:
  - exact executable verifier-configuration commitment;
  - verifier-required plan, quorum, actor-diversity, and root-diversity
    obligation;
  - local scoped trust anchors;
  - exact accepted registries;
  - expected audience and challenge;
  - evaluation time;
  - role-indexed assurance policy;
  - principal-status and grant-status snapshots. Principal-status policy
    comes from the selected trust anchor; grant-status policy comes from each
    grant;
  - exact resource-matching algebra;
  - profile policy;
  - observer anchors, separate from trust anchors;
  - resource and work limits.

The proof cannot add a trust anchor or weaken context.

## Stages

Verification runs the stages below in order. Within a stage, checks run in
the order written, and the first check that fails is the result, so every
conforming implementation reports the same class and primary code for an
input with more than one fault. Two rules refine this: a signed statement's
control failure found in stage 3 becomes a result only where stage 5 needs
that statement, and stage 6 combines the results of every branch, each
evaluated in this order.

A portable result names its stage: `decode` for stage 1, `resolve` for
stage 2, `principal-control` for stage 3, `authority` for stages 4 to 6, and
`complete` when authorized. A stage 1 or stage 2 result carries no plan
digest.

A name such as `binding.permission` marks a check site. The conformance
corpus holds, for each one, a vector whose single fault that check rejects
first.

### 1. Bounded decode

The three inputs are decoded in this order. A decode failure is the result
and carries no plan digest.

1. The trusted context, under the protocol hard maximums. Its deployment
   limits then bound the other two inputs.
2. The canonical action, before any proof byte is read:
   1. `decode.action-bytes`: an input longer than the canonical-action input
      limit is `resource-limit-exceeded`, before any byte is read.
   2. Fields are read in key order: profile, media type, body, permission,
      requested budget, detached attachments. An item that cannot be read as
      its field's type (including an indefinite length or a tag), an invalid
      identifier, or a zero profile version is `malformed-proof`. A readable
      map key other than the next expected key is `non-canonical-proof`.
   3. Bounds are checked as each field is read, each failing with
      `resource-limit-exceeded`: an empty body or one longer than the
      canonical-body limit (`decode.action-body-bytes`); more detached
      attachments than the attachment-count limit; and an empty detached
      attachment, one longer than the aggregate detached-attachment limit, or
      detached attachments that together exceed that limit
      (`decode.attachment-bytes`).
   4. Two detached attachments with one digest are `malformed-proof`, and so
      are bytes after the action.
   5. An input that reads completely but is not the canonical encoding of the
      action it decodes to, such as a non-shortest integer or length or
      detached attachments out of digest order, is `non-canonical-proof`.
      This is checked last, so it never hides a failure listed above.
3. The proof bundle. Bytes above the bundle limit are
   `resource-limit-exceeded` before any byte is read. Then strictly decode
   deterministic CBOR, and reject invalid map keys, non-minimal forms, invalid
   UTF-8, duplicate keys, unknown critical fields, unsorted sets, trailing
   bytes, and collection overflow. Produce `DecodedProof`.

A canonical action constructed in process has no input bytes. For it, only
the aggregate detached-attachment limit applies, at action binding.

### 2. Reference resolution

In this order:

1. Recompute the plan identifier. When the trusted context requires an exact
   plan and the identifier differs, the result is
   `composition-requirement-not-met`.
2. Recompute grant identifiers. Two grants with one identifier are
   `duplicate-object`.
3. For each action in proof order, an action bound to another plan
   identifier is `plan-action-mismatch`, and a proof reference an earlier
   action already used is `duplicate-object`. Then two actions with one
   identifier are `duplicate-object`.
4. Every plan `proof-ref` needs exactly one action and every action one
   leaf: `missing-reference`.
5. Two evidence objects with one identifier, or two statements with one
   identifier in either status snapshot, are `duplicate-object`.
6. For each control binding in proof order, a second binding for the same
   statement is `duplicate-object`, and a binding that names an absent
   statement or evidence object is `missing-reference`.
7. For each action in proof order, follow parent references from its terminal
   grant: an absent grant is `missing-reference`. A grant that no action's
   chain reaches is `unused-critical-evidence`.
8. Two proof attachment descriptors with one digest are
   `duplicate-attachment`.
9. A proof-carried status statement older than a snapshot statement about the
   same principal, or the same grant, is `status-sequence-rollback`; one the
   snapshot does not hold is `digest-mismatch`. Only the subject keys this
   comparison, as it keys selection; the method and issuer do not.

Produce `ResolvedProof`.

### 3. Principal control

1. The context's registry-manifest identifier must equal the executable
   registry's: `registry-manifest-mismatch`.
2. The context's verifier-configuration commitment must equal the executable
   adapter and registry configuration: `verifier-configuration-mismatch`.
3. Verify every signed statement, in this order: grants by identifier,
   actions by identifier, then the principal-status and grant-status
   statements of the context snapshots in snapshot order. For each:
   1. select exactly one principal method and signature suite, each accepted
      and installed: otherwise `unsupported-principal-method` or
      `unsupported-signature-suite`;
   2. gather the evidence the statement's control binding names: no binding
      is `missing-principal-evidence`, and an evidence type the context does
      not accept is `unsupported-evidence-type`;
   3. reserve the method's conservative maximum work and the suite's work
      before either implementation is called;
   4. verify method-specific principal and control semantics, which return
      parameterized assurance and the exact evidence identifiers consumed;
   5. reject an implementation that exceeds its reservation;
   6. verify the domain-separated signature: `invalid-signature`.

   A failure is stored on its statement and becomes a result only where
   stage 5 needs that statement: the root statement of a branch, a grant in
   the delegation walk, the action, or a status statement. Resource
   exhaustion is not stored: it ends verification with
   `resource-limit-exceeded`.
4. For every statement whose control succeeded, the evidence its binding
   names must equal the evidence the method consumed:
   `unused-critical-evidence`.
5. Every evidence object must be consumed by a binding or a snapshot
   checkpoint: `unused-critical-evidence`.

Unavailable required capability is `Indeterminate`; invalid supplied evidence
is `Denied`.

Produce `ControlVerifiedProof`.

### 4. Action binding

Runs once, after principal control and before any authority branch:

1. `binding.embedded-body`: when the proof carries a body, it must equal the
   canonical body: `action-body-mismatch`.
2. For each signed action, in proof order:
   1. The envelope must bind the canonical action exactly. In one comparison,
      its profile (`binding.profile`), body media type (`binding.media-type`),
      body digest, which is the SHA-256 of the canonical body
      (`binding.body-digest`), permission (`binding.permission`), and
      requested budget (`binding.requested-budget`) must equal the canonical
      action's: `action-body-mismatch`. This comparison is the only tie
      between the body the proof carries or omits and the signatures.
   2. `binding.profile-accepted`: the context must accept the profile:
      `unsupported-profile`.
   3. `binding.audience`: the audience must equal the expected audience:
      `audience-mismatch`.
   4. `binding.challenge`: the challenge must equal the expected challenge:
      `challenge-mismatch`.
   5. `binding.evaluation-time`: the evaluation time must lie inside the
      action's validity window: `action-outside-validity`. Only this check
      stops an expired action; grant validity bounds the action's window,
      not the evaluation time.
   6. `binding.channel`: the channel-binding requirement must equal the
      context's channel policy: `local-policy-denied`.
   7. `binding.shared-meaning`: the action must bind the same profile, media
      type, body digest, permission, requested budget, audience, challenge,
      validity window, plan, channel binding, attachment descriptors, and
      critical extensions as the first action: `plan-action-mismatch`.
   8. Its critical extensions, in order: an identifier the context does not
      accept is `critical-extension-unknown`
      (`binding.action-extension-accepted`); one without an installed
      handler is `unsupported-critical-extension`
      (`binding.action-extension-handler`); the handler's work is reserved,
      and a handler that rejects the bytes returns `resource-limit-exceeded`
      for a bound and `local-policy-denied` otherwise
      (`binding.action-extension-evaluation`).
   9. `binding.observation-attachments`: more than 32 descriptors with the
      observation media type, or one declaring more than 4096 bytes:
      `resource-limit-exceeded`.
3. Attachments, against the first action's signed descriptors:
   1. `binding.attachment-descriptors`: the proof's descriptor list must
      equal the signed list: `unused-critical-attachment`.
   2. Duplicate descriptor or detached digests are `duplicate-attachment`;
      stages 1 and 2 already reject both.
   3. Detached attachments together must not exceed the aggregate
      detached-attachment limit: `resource-limit-exceeded`. Stage 1 already
      bounds a portable input.
   4. For each descriptor in order: a required one without detached bytes is
      `attachment-missing` (`binding.attachment-missing`), and an optional one
      is skipped; the bytes must have the signed length
      (`binding.attachment-length`): `attachment-length-mismatch`; their
      SHA-256 must be the signed digest (`binding.attachment-digest`):
      `attachment-digest-mismatch`; and encrypted bytes whose descriptor
      requires them to be inspectable are `opaque-attachment-not-allowed`
      (`binding.attachment-opaque`).
   5. `binding.attachment-unused`: detached bytes that no descriptor names
      are `unused-critical-attachment`.
4. `binding.profile-policy`: the context's profile policy must be accepted
   and installed: `unsupported-profile-policy`. Its work is reserved, and a
   policy that rejects the action is `local-policy-denied`.

### 5. Authority branches

Every plan leaf is evaluated in the plan's canonical order (stage 6), whatever
earlier leaves returned. For one leaf:

1. Find the action by `proof-ref` and its grant chain, root to terminal. The
   root principal is the first grant's issuer, or the actor when the action
   names no grant.
2. `branch.root-control`: a stored control failure of the root statement (the
   first grant, or the action when it names no grant) is the branch result.
3. Trust anchors whose principal is the root principal are tried in context
   order. The first that establishes authority decides the branch; when none
   does, the first anchor's failure is the result, and with no such anchor it
   is `untrusted-root` (`branch.untrusted-root`). For one anchor:
   1. The anchor must accept the principal method of the root statement's
      signature, and its assurance policy must be the context's:
      `untrusted-root`.
   2. Status, as Principal status below specifies: the anchor principal's
      status (`branch.anchor-principal-status`); then, for each grant root to
      terminal, that grant's status under its own status policy
      (`branch.grant-status`), followed by its subject's principal status
      (`branch.subject-principal-status`).
   3. `branch.resource-matcher`: the context's resource matcher must be
      accepted and installed: `unsupported-resource-matcher`.
   4. Resource namespaces, under that matcher, reserving its work for each
      namespace tried: the resource of every permission of every grant, root
      to terminal and in each grant's permission order
      (`branch.grant-namespace`), and then the action's resource
      (`branch.action-namespace`), must each lie inside at least one of the
      anchor's namespaces: `resource-namespace-mismatch`.
   5. Budget chain. For each grant root to terminal whose parent ceiling (the
      anchor's, then the previous grant's) is bounded: a grant with no
      ceiling is `delegation-expanded`; the parent ceiling's algebra must be
      accepted and installed (`branch.budget-edge-algebra`):
      `unsupported-budget-algebra`; its work is reserved; that algebra
      rejects a grant ceiling in any other algebra as invalid input
      (`branch.budget-edge-mismatch`): `local-policy-denied`; and a larger
      ceiling is `delegation-expanded` (`branch.budget-edge`). Then, when the
      terminal ceiling (the last grant's, or the anchor's when there is no
      grant) is bounded: an action that requests no budget is
      `budget-ceiling-exceeded` unless the context declares its profile
      budget-free (`branch.budget-absent`); the terminal ceiling's algebra
      must be accepted and installed (`branch.budget-algebra`):
      `unsupported-budget-algebra`; it rejects a request in any other algebra
      (`branch.budget-request-mismatch`): `local-policy-denied`; and a larger
      request is `budget-ceiling-exceeded` (`branch.budget-coverage`). An
      algebra is resolved only where a bounded ceiling is compared, so a
      request under unbounded authority names an algebra that is never
      resolved.
   6. Delegation walk, for each grant root to terminal:
      1. For a grant after the first, `branch.requirement-dropped`: when some
         observation requirement of its parent has no child requirement with
         the same schema and subject, the result is
         `observation-requirement-dropped`. Then the extension laws' work is
         reserved.
      2. The authority kernel applies the edge. Linkage first
         (`branch.delegation-linkage`): the issuer must be the current subject
         and the parent reference the previous grant: `broken-grant-chain`.
         Then every dimension must narrow or preserve, else
         `delegation-expanded`: remaining depth (`branch.delegation-depth`),
         profile (`branch.delegation-profile`), permissions
         (`branch.delegation-permissions`), validity
         (`branch.delegation-validity`), audiences
         (`branch.delegation-audiences`), action constraint
         (`branch.delegation-action-constraint`), budget, status policy
         (`branch.delegation-status`), assurance policy
         (`branch.delegation-assurance`), and critical extensions under each
         identifier's attenuation law in registry.md
         (`branch.delegation-extensions`). The budget dimension repeats a
         comparison the budget chain has already made, so it never decides.
      3. The grant's stored control failure.
      4. `branch.grant-extension`: the grant's critical extensions, checked as
         an action's are in stage 4.

      Then terminal coverage: the actor must be the terminal subject and the
      action must name the terminal grant (`branch.coverage-linkage`):
      `broken-grant-chain`; the action's profile must be the one the chain
      selected, or one of the anchor's profiles when there is no grant
      (`branch.coverage-profile`): `broken-grant-chain`; the permission must
      be granted (`branch.coverage-permission`): `permission-not-granted`;
      the action's validity window must lie inside the authority's
      (`branch.coverage-validity`): `action-outside-validity`; the audience
      must be granted (`branch.coverage-audience`): `audience-mismatch`; and
      the body digest must satisfy the action constraint
      (`branch.coverage-constraint`): `action-constraint-mismatch`. Budget
      coverage repeats the budget chain and never decides.
   7. The action's stored control failure.
   8. Assurance: every claim of every participant must have an accepted
      handler (`branch.assurance-claim`): `unsupported-assurance-claim`. Each
      claim is validated, implications are reserved and applied, and the
      context's requirements must be met (`branch.assurance-requirement`):
      `assurance-requirement-not-met`.
   9. The observation stage below.

Produce one `VerifiedAuthority` per valid branch.

#### Principal status

Principal status applies to every principal in the branch, not only the trust
anchor. By chain linkage these are the trust anchor's principal and the
subject of each grant, which covers every grant issuer and the actor.

The selected trust anchor's status policy governs all of them. A grant's own
status policy governs only that grant's status: it never changes which
principals are checked or how. When the anchor's status policy is
`ExpiryOnly`, no principal status is evaluated.

A statement names no purpose or role, so the principal is its only key: one
evaluation below governs the principal in every position it holds.

Under `SnapshotRequired`, evaluate each principal against the context's
principal-status snapshot:

1. The status method named by the policy must be accepted and installed;
   otherwise `unsupported-status-method`.
2. Every snapshot statement about the principal must have verified control
   from stage 3. A statement whose control failed fails the check with that
   failure; it is never ignored.
3. Reserve the method's declared maximum work for the snapshot's statement
   count before evaluating.
4. If the evaluation time is outside the snapshot's own validity window, the
   result is `stale-status`.
5. If no statement names the principal: for the trust anchor's principal, the
   result is `missing-principal-status`; any other principal is active. For
   delegates and actors the snapshot is a revocation list, and absence from a
   fresh snapshot means not revoked.
6. Otherwise select as follows. If no statement uses the policy's method, the
   result is `status-method-mismatch`. Ignore statements whose issuer the
   snapshot does not trust for that method; if none remain, the result is
   `status-issuer-untrusted`. A trusted statement below its issuer's sequence
   floor gives `status-sequence-rollback`. Among the trusted statements at the
   greatest sequence, any stale statement gives `stale-status`; otherwise any
   `revoked` or `superseded` statement gives `principal-revoked`; otherwise the
   principal is active.

A branch runs its status checks after its trust anchor is selected and before
its resource, budget, and attenuation checks, in this order: the trust
anchor's principal status; then, for each grant from root to terminal, that
grant's status followed by its subject's principal status. The first failure
is the branch result.

A revocation must stay in the snapshot until every grant that names the
principal as subject has expired. While it is stale the result is
`stale-status`; once it is removed, the principal is active again.

### 5a. Observation stage

Runs for each branch after its authority and assurance are established and
before the branch counts as authorized. Collect the distinct requirements
carried by the `observation-requirement-v1` extensions of every grant in the
chain; more than 32 is `resource-limit-exceeded`. With none, the stage
passes.

1. Resolve each requirement's observer anchor by exact ID in the trusted
   context. If any resolved anchor's principal equals the trust anchor, an
   issuer or subject of a chain grant, or the actor, deny with
   `observer-in-authority-chain` (`branch.observer-in-chain`).
2. Decode every attachment whose signed descriptor carries the observation
   media type. Malformed bytes are `malformed-proof`; an over-limit value is
   `resource-limit-exceeded`.
3. For each requirement, in first-appearance order:
   - an unknown observer anchor is `observation-missing`;
   - resolve the subject (a literal, or a text action fact that parses as a
     resource) and every `eq-action` value through the profile policy's
     `action_fact`, reserving the policy's work per call; an undefined fact
     is `observation-action-fact-unavailable`
     (`branch.observation-action-fact`);
   - reserve `conditions × observations + 1` work units;
   - in attachment-digest order, an observation is eligible when its
     observer equals the anchor principal, its schema equals the
     requirement's and the anchor lists it, its subject equals the resolved
     subject exactly and lies inside one of the anchor's subject namespaces
     under the context's resource matcher, `observed_at <= evaluation_time`,
     `evaluation_time − observed_at <= max_age`, the anchor's validity
     contains `observed_at`, the anchor accepts its principal method, and its
     signature verifies. Signature verification uses the registered
     principal method with purpose assertion and the observation's own
     control evidence, which must equal the evidence the method consumes;
     its method and suite work is reserved first. Any verification failure
     other than resource exhaustion makes that observation ignored, not the
     proof denied;
   - the first eligible observation that makes every condition true
     satisfies the requirement. If eligible observations exist and none
     does, the requirement is `observation-condition-false`
     (`branch.observation-condition`); with no eligible observation it is
     `observation-missing` (`branch.observation-missing`).
4. Any denied requirement denies the branch; otherwise the first
   indeterminate requirement makes it indeterminate. Denial dominates.
5. Record, for each requirement, its content identifier and the attachment
   digest of the observation that satisfied it.

### 6. Plan evaluation and composition

1. Evaluate every `Proof`, `AllOf`, `AnyOf`, and `KOfN` child from its local
   authorized, denied, indeterminate, or structurally-invalid result.
2. A denied child dominates an indeterminate child for `AllOf`; an authorized
   child satisfies `AnyOf`; `KOfN` is indeterminate only when unavailable
   children could still satisfy the threshold. Within a class, the
   lexicographically smallest stable code is primary.
3. Never skip a branch for resource accounting after another branch succeeds.
4. Apply plan leaf, depth, branch, signature, and total work limits.
5. When the plan authorizes, the trusted context's minimums must hold:
   authorized branches (`composition.authorized-branches`), distinct actors
   (`composition.distinct-actors`), and distinct roots
   (`composition.distinct-roots`), else `composition-requirement-not-met`.
   The expected plan was checked in stage 2.
6. Sort authorized branches canonically and construct `VerifiedAction`
   through a private constructor.

The portable entry point is:

```text
verify_v1(proof_cbor, canonical_action_cbor, trusted_context_cbor)
    -> verification_result_cbor
```

The result contains the three-way verdict, final stage and stable code, proof,
action, context, plan, self-binding result, and verifier-configuration
digests, authorized branches, assurance reports and exact requirement
satisfactions, resource/work totals, registry manifest, ABI version 3, and
the observation that satisfied each observation requirement. The
native convenience API projects that result to `Authorized(VerifiedAction)`,
`Denied(DenialReason)`, or `Indeterminate(Requirement)`.

## Execution

The outer runtime:

1. evaluates channel policy against `PeerObservation`;
2. atomically claims challenge/action replay state;
3. atomically claims any stateful budget;
4. evaluates local application restrictions;
5. decodes a domain command from `VerifiedAction`;
6. constructs `ExecutableAction<P>`;
7. writes a decision receipt;
8. executes;
9. writes an execution receipt.

No outer fact upgrades a denied or indeterminate Auths result.

## Determinism

Given identical proof bytes, canonical action, trusted context, and executable
registry matching its bound configuration commitment, every conforming
implementation produces identical:

- canonical digests;
- verdict class;
- primary reason code;
- assurance report;
- assurance satisfaction report;
- observation satisfaction report;
- action and context digests;
- resource/work totals;
- canonical portable result bytes and result digest.

Because every check runs in the order the stages specify, an input with
several faults has one primary code in every conforming implementation.

Replay, transport, storage, and execution results are deliberately outside
this invariant.
