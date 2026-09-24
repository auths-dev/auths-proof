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

### 1. Bounded decode

1. Reject bytes above the configured or protocol maximum.
2. Strictly decode deterministic CBOR.
3. Reject invalid map keys, non-minimal forms, invalid UTF-8, duplicate keys,
   unknown critical fields, unsorted sets, trailing bytes, and collection
   overflow.
4. Produce `DecodedProof`.

### 2. Reference resolution

1. Recompute grant, action, plan, evidence, status, and attachment identifiers.
2. Build bounded digest indexes.
3. Reject missing, duplicate, cyclic, mismatched, ambiguous, and
   unused-critical references.
4. Require a unique signed action for every plan `proof-ref`.
5. Produce `ResolvedProof`.

### 3. Principal control

First require both the context registry-manifest identifier and exact
verifier-configuration commitment to match the immutable executable registry.
For every signed grant, action, and accepted status statement:

1. select exactly one principal method and signature suite;
2. reserve the method's conservative maximum work and suite work before either
   implementation is called;
3. gather the bounded evidence bound to that statement;
4. verify the domain-separated signature;
5. verify method-specific principal/control semantics;
6. return parameterized assurance and the exact evidence IDs actually
   consumed;
7. require those IDs to equal the relevant statement binding exactly;
8. reject an implementation that exceeds its reservation.

Unavailable required capability is `Indeterminate`; invalid supplied evidence
is `Denied`. A signed-statement failure is stored on the statement/leaf result;
it does not become a global proof failure unless structural decoding,
reference resolution, or resource safety failed.

Produce `ControlVerifiedProof`.

### 4. Authority branches

For each plan leaf:

1. find the signed action by `proof-ref`;
2. select a local trust anchor by exact principal and scoped ceilings, and
   check its principal's status (see Principal status below);
3. execute the context-selected resource matcher for the action resource and
   every anchor namespace;
4. walk the referenced grant chain root to terminal:
   - issuer equals current subject;
   - parent is exact;
   - profile/version remains exact;
   - permissions, validity, audiences, action constraints, budget, and depth
     attenuate;
   - grant status policy is satisfied;
   - the grant subject's principal status is satisfied under the trust
     anchor's status policy (see Principal status below);
   - role-specific assurance floor is satisfied;
5. require actor equals terminal subject;
6. require exact permission, audience, body constraint, and time coverage;
7. resolve and execute exact budget, status, extension, assurance-claim, and
   implication handlers, reserving their work before invocation;
8. before applying each child grant, deny with
   `observation-requirement-dropped` when some observation requirement of
   its parent grant has no child requirement with the same schema and
   subject; the authority kernel then applies every critical-extension
   attenuation law (registry.md) and denies a widened requirement, a changed
   marker, or an identifier without a law with `delegation-expanded`;
9. run the observation stage below.

Produce one `VerifiedAuthority` per valid branch.

#### Principal status

Principal status applies to every principal in the branch, not only the trust
anchor. By chain linkage these are the trust anchor's principal and the
subject of each grant, which covers every grant issuer and the actor.

The selected trust anchor's status policy governs all of them. A grant's own
status policy governs only that grant's status: it never changes which
principals are checked or how. When the anchor's status policy is
`ExpiryOnly`, no principal status is evaluated.

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

### 4a. Observation stage

Runs for each branch after its authority is established and before the
branch counts as authorized. Collect the distinct requirements carried by the
`observation-requirement-v1` extensions of every grant in the chain; more
than 32 is `resource-limit-exceeded`. With none, the stage passes.

1. Resolve each requirement's observer anchor by exact ID in the trusted
   context. If any resolved anchor's principal equals the trust anchor, an
   issuer or subject of a chain grant, or the actor, deny with
   `observer-in-authority-chain`.
2. Decode every attachment whose signed descriptor carries the observation
   media type. Malformed bytes are `malformed-proof`; an over-limit value is
   `resource-limit-exceeded`.
3. For each requirement, in first-appearance order:
   - an unknown observer anchor is `observation-missing`;
   - resolve the subject (a literal, or a text action fact that parses as a
     resource) and every `eq-action` value through the profile policy's
     `action_fact`, reserving the policy's work per call; an undefined fact
     is `observation-action-fact-unavailable`;
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
     does, the requirement is `observation-condition-false`; with no
     eligible observation it is `observation-missing`.
4. Any denied requirement denies the branch; otherwise the first
   indeterminate requirement makes it indeterminate. Denial dominates.
5. Record, for each requirement, its content identifier and the attachment
   digest of the observation that satisfied it.

### 5. Plan evaluation

1. Recompute the plan ID and compare every action binding.
2. Require all branch actions to bind identical canonical action meaning,
   audience, challenge, and plan.
3. Evaluate every `Proof`, `AllOf`, `AnyOf`, and `KOfN` child from its local
   authorized, denied, indeterminate, or structurally-invalid result.
4. A denied child dominates an indeterminate child for `AllOf`; an authorized
   child satisfies `AnyOf`; `KOfN` is indeterminate only when unavailable
   children could still satisfy the threshold. Within a class, the
   lexicographically smallest stable code is primary.
5. Never skip a branch for resource accounting after another branch succeeds.
6. Apply plan leaf, depth, branch, signature, and total work limits.
7. Enforce the trusted context's expected plan, minimum authorized branches,
   distinct actors, and distinct roots.
8. Sort authorized branches canonically.

### 6. Action binding

1. Select the exact application profile/version.
2. Canonicalize or validate the supplied canonical body.
3. Compare body media type and digest.
4. Compare capability, resource, requested budget, audience, challenge,
   validity, actor, terminal grant, plan, and channel-binding requirement.
5. Deny with `resource-limit-exceeded` an action binding more than 32
   attachments with the observation media type, or one declaring more than
   4096 bytes;
6. Verify the signed attachment descriptor set exactly matches the proof set;
   check required availability, identifier, SHA-256 digest, byte length,
   signed media/disposition/encryption flags, opaque-content permission,
   duplicates, unused detached bytes, and byte limits.
7. Resolve and execute the verifier-local profile policy.
8. Construct `VerifiedAction` through a private constructor.

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

Replay, transport, storage, and execution results are deliberately outside
this invariant.
