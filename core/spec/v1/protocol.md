# Auths Proof Protocol V1

## Status

This specification defines the prelaunch target contract. Earlier V1
prototype bytes are obsolete. `auths-proof.cddl`, the registry, the
verification algorithm, and the checked-in CBOR corpus are normative together.

## Claim

Given a proof bundle, canonical action, and explicit local verifier context,
Auths answers:

> Did authority flow from a locally scoped trust anchor to every required
> actor without expansion, and does the resulting authority cover this exact
> action?

The pure verifier performs no network, filesystem, environment, clock,
randomness, database, private-key, replay, or execution operation.

## Four planes

### Proof

The proof plane owns deterministic objects, scoped trust anchors,
attenuation, authorization plans, action binding, and verified values.

### Evidence

The evidence plane establishes principal control, signature validity,
principal status, grant status, freshness, and parameterized assurance.
Adapters return facts. They cannot construct authority results.

### Execution

The execution plane owns challenges, transport observations, replay and budget
stores, local application policy, execution leases, verified command decoding,
and execution.

### Control

The control plane owns authoring, signer integrations, configuration,
registries, receipts, audit export, observability, conformance, and
evaluation.

## Authority objects

### Trust anchor

A trust anchor is verifier-local and never proof-carried authority. It
contains:

- principal and accepted control methods;
- allowed profiles and versions;
- exact permission and resource ceilings;
- audience ceiling;
- validity window;
- optional budget ceiling;
- maximum delegation depth;
- assurance predicate;
- status policy.

Adding an unrelated trust anchor cannot authorize a chain anchored elsewhere.

### Grant

A grant transfers a bounded subset of authority from issuer to subject.
Every edge must narrow or preserve:

- exact permissions;
- validity;
- audiences;
- action constraint;
- budget ceiling;
- remaining delegation depth;
- profile and version.

Issuer/subject and parent linkage must be exact. Cross-profile delegation
requires a registered bridge extension.

### Action constraint

V1 has a closed algebra:

```text
ExactBodyDigest(x) <= AllowedBodyDigests(S)  when x is in S
AllowedBodyDigests(A) <= AllowedBodyDigests(B) when A is a subset of B
AllowedBodyDigests(S) <= AnyBody
ExactBodyDigest(x) <= AnyBody
```

No application callback changes this order.

### Authorization plan

V1 supports bounded:

- `Proof`;
- `AllOf`;
- `AnyOf`;
- `KOfN`.

Every satisfied leaf has one signed action envelope with the same canonical
body digest, profile, capability, resource, audience, challenge, validity
context, and plan ID. A `proof-ref` breaks the plan/action identifier cycle and
uniquely names a branch.

Plan depth, leaves, branching, signatures, and total adapter work are bounded.
Evaluation order is canonical so parallel and sequential implementations
produce the same primary outcome.

The proof-carried plan is not the policy. The trusted verifier context carries
an independent `CompositionRequirement` with an optional exact plan ID and
minimum authorized-branch, distinct-actor, and distinct-root counts. An
authorized result proves both that the branches satisfy the signed plan and
that the outcome satisfies this host-required obligation. Distinct proof
references alone never imply independent signers or roots.

### Action envelope

Every signed action binds:

- profile and version;
- body media type and canonical body digest;
- capability and resource;
- optional requested budget under a registered monotonic algebra;
- audience and challenge;
- issue and expiry times;
- actor and terminal grant;
- authorization plan ID and proof reference;
- channel-binding requirement;
- signed attachment descriptors and required/opaque-use policy;
- critical extensions.

Profiles define canonical body bytes and verified command decoding. The
executor consumes the decoded command from `VerifiedAction`, never the
original untrusted request.

## Evidence and status

Evidence is content addressed, bounded, and selected by exact type.
Control bindings associate signed statements with evidence without turning
resolver output into trust. For each successfully verified statement, the
binding must exactly equal the evidence IDs reported consumed by the selected
principal adapter. Extra, ignored, or adapter-invented evidence fails closed.

Principal status and grant status are separate signed facts. Each carries an
exact method, subject, issuer, sequence, and validity boundary. The trusted
snapshot supplies accepted issuers and sequence floors; latest-sequence
selection is deterministic and revoked dominates active at the same sequence.
Historical control, current control, statement existence, revocation, and
freshness are not interchangeable.

Assurance is role-indexed and every requirement explicitly selects `Any` or
`Every` participant with that role. Every claim records the participant, chain role,
parameters, adapter and version, evidence digests, and provenance. A strong
actor cannot satisfy a weak root or intermediate.

## Decisions

The language-neutral pure result is canonical CBOR:

```text
verify_v1(proof_cbor, canonical_action_cbor, trusted_context_cbor)
  -> verification_result_cbor
```

It records `Authorized`, `Denied`, or `Indeterminate`, the final stage and
stable code, all applicable input/plan/result digests, authorized branches,
assurance and satisfaction reports, exact resource totals, work reserved, and
the registry manifest, and the exact executable verifier-configuration
commitment. Native APIs may project an authorized result to a sealed
`VerifiedAction`.

Denied means available facts establish invalidity or insufficient authority.
Indeterminate means a required trustworthy fact was not established.
Neither can execute.

Replay, channel, budget, and application policy are outer gates:

```text
Authorized action
AND status freshness
AND channel policy
AND replay lease
AND budget claim
AND application policy
= ExecutableAction
```

## Deterministic encoding

V1 uses the constrained deterministic CBOR profile in `auths-proof.cddl`:

- definite-length maps, arrays, text, and bytes only;
- shortest integer and length encodings;
- ascending integer map keys;
- no duplicate keys, floats, tags, or trailing bytes;
- canonical strict ordering for every set representation;
- exact critical-field and registry handling.

Semantically similar but byte-distinct application actions are not assumed
equivalent. Signed attachment descriptors are part of action signing bytes.
Detached bytes are part of the portable canonical-action input and are checked
against their signed SHA-256 identifiers and lengths.

## Default and hard limits

| Resource | Default | Hard maximum |
|---|---:|---:|
| Bundle bytes | 256 KiB | 8 MiB |
| Canonical-action input bytes | 2 MiB | 16 MiB |
| Trusted-context input bytes | 2 MiB | 16 MiB |
| Grants | 16 | 256 |
| Actions/plan leaves | 16 | 128 |
| Plan depth | 8 | 16 |
| Evidence objects | 32 | 512 |
| One evidence object | 64 KiB | 2 MiB |
| Control bindings | 32 | 512 |
| Principal status statements | 32 | 512 |
| Grant status statements | 32 | 512 |
| Attachments | 32 | 512 |
| Aggregate detached attachment bytes | 1 MiB | 8 MiB |
| Signatures | 64 | 1,024 |
| One signature | 512 B | 4 KiB |
| Permissions | 64 | 1,024 |
| Audiences | 32 | 256 |
| Critical extensions/object | 8 | 32 |
| One critical extension | 16 KiB | 64 KiB |
| Allowed body digests | 32 | 256 |
| Evidence IDs per binding | 8 | 32 |
| Canonical action body | 1 MiB | 8 MiB protocol ceiling and lower profile limit |
| Accepted entries per registry | 64 | 1,024 |
| Trust anchors | 32 | 1,024 |
| Adapter work units | 50,000 | 1,000,000 |

Deployments may lower limits. Raising a hard maximum requires protocol review.

## Conformance artifacts

`fixtures/v1/manifest.json` indexes every canonical `.cbor` artifact and
records:

- SHA-256 file digest;
- fixture class and source specification;
- expected stage reached;
- verdict and stable reason code;
- expected proof, action, context, plan, and self-binding result digests;
- expected assurance report;
- byte, object, depth, signature, and work-unit counts.

Fixture classes are:

```text
valid/
denied/
indeterminate/
malformed/
maximum/
metamorphic/
```

An explicit reviewed `cargo xtask wire --update` is the only operation allowed
to replace normative bytes. Ordinary tests compare and fail.
