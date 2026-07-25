# Verification Algorithm — V1

## Inputs

- encoded `ProofBundle`;
- canonical `CanonicalAction` CBOR, including profile, media type, permission,
  budget request, canonical body, and bounded detached attachment bytes;
- immutable verifier context:
  - local scoped trust anchors;
  - exact accepted registries;
  - expected audience and challenge;
  - evaluation time;
  - role-indexed assurance policy;
  - principal and grant status policy;
  - exact resource-matching algebra;
  - profile policy;
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

First require the context registry-manifest identifier to equal the immutable
implementation registry manifest. For every signed grant, action, and accepted
status statement:

1. select exactly one principal method and signature suite;
2. reserve the method's conservative maximum work and suite work before either
   implementation is called;
3. gather the bounded evidence bound to that statement;
4. verify the domain-separated signature;
5. verify method-specific principal/control semantics;
6. return parameterized assurance and evidence provenance;
7. reject an implementation that exceeds its reservation.

Unavailable required capability is `Indeterminate`; invalid supplied evidence
is `Denied`. A signed-statement failure is stored on the statement/leaf result;
it does not become a global proof failure unless structural decoding,
reference resolution, or resource safety failed.

Produce `ControlVerifiedProof`.

### 4. Authority branches

For each plan leaf:

1. find the signed action by `proof-ref`;
2. select a local trust anchor by exact principal and scoped ceilings;
3. execute the context-selected resource matcher for the action resource and
   every anchor namespace;
4. walk the referenced grant chain root to terminal:
   - issuer equals current subject;
   - parent is exact;
   - profile/version remains exact unless a registered bridge applies;
   - permissions, validity, audiences, action constraints, budget, and depth
     attenuate;
   - grant status policy is satisfied;
   - role-specific assurance floor is satisfied;
5. require actor equals terminal subject;
6. require exact permission, audience, body constraint, and time coverage;
7. resolve and execute exact budget, status, extension, assurance-claim, and
   implication handlers, reserving their work before invocation.

Produce one `VerifiedAuthority` per valid branch.

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
7. Sort authorized branches and diagnostics canonically.

### 6. Action binding

1. Select the exact application profile/version.
2. Canonicalize or validate the supplied canonical body.
3. Compare body media type and digest.
4. Compare capability, resource, requested budget, audience, challenge,
   validity, actor, terminal grant, plan, and channel-binding requirement.
5. Verify the signed attachment descriptor set exactly matches the proof set;
   check required availability, identifier, SHA-256 digest, byte length,
   signed media/disposition/encryption flags, opaque-content permission,
   duplicates, unused detached bytes, and byte limits.
6. Resolve and execute the verifier-local profile policy.
7. Construct `VerifiedAction` through a private constructor.

The portable entry point is:

```text
verify_v1(proof_cbor, canonical_action_cbor, trusted_context_cbor)
    -> verification_result_cbor
```

The result contains the three-way verdict, final stage and stable code, proof,
action, context, plan, and self-binding result digests, authorized branches,
assurance reports and exact requirement satisfactions, resource/work totals,
registry manifest, and ABI version. The native convenience API projects that
result to `Authorized(VerifiedAction)`, `Denied(DenialReason)`, or
`Indeterminate(Requirement)`.

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

Given identical proof bytes, canonical action, registries, and verifier
context, every conforming implementation produces identical:

- canonical digests;
- verdict class;
- primary reason code;
- ordered diagnostic list;
- assurance report;
- assurance satisfaction report;
- action and context digests;
- resource/work totals;
- canonical portable result bytes and result digest.

Replay, transport, storage, and execution results are deliberately outside
this invariant.
