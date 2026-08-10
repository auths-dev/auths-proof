# Make identity credential-shape agnostic

Status: scratch design note

## Goal

Represent raw keys, resolved identities, certificates, rotating key sets, threshold identities, and hybrid post-quantum credentials without pretending every identity is exactly one key and one signature suite.

## Problem

The current neutral identity descriptor requires:

- one method ID;
- one identity ID;
- one suite ID;
- one non-empty public-key byte sequence.

Variable-length bytes remove algorithm-size coupling, but the shape still assumes a single embedded verification key. More complex methods must hide their structure inside opaque bytes and invent adapter-private conventions.

## Target model

Separate stable identity from method-owned verification material:

```text
IdentityDescriptor
  method_id
  identity_id
  method_material: bounded opaque bytes

VerificationRelationship
  purpose
  suite_id
  verification_material: bounded opaque bytes
  relationship_id or key_id
```

An identity may carry zero, one, or a bounded set of verification relationships depending on its method. A resolver-backed method may carry a reference plus freshness evidence rather than a full key.

## Design requirements

1. Stable identity identifiers are not synonymous with individual keys.
2. Methods own the interpretation of method material.
3. Signature suites own the interpretation of verification material.
4. Multiple verification relationships have explicit identifiers and purposes.
5. Hybrid and threshold suites can bind multiple keys without private wire conventions.
6. Resource bounds remain hard and protocol-owned.
7. Resolution, freshness, revocation, and trust policy remain explicit external effects.
8. The simple raw-key case remains concise.

## Compatibility

The current V2 packet can remain a simple profile rather than the universal final shape. A future version may define:

- a compact single-key profile;
- a general method-material profile;
- explicit profile/version negotiation.

Do not force a complex general model into V2 without vectors and a migration strategy.

## Proof cases

The design should be exercised with only a few implementations:

1. Raw Ed25519 key: the compact baseline.
2. A hybrid-shaped test suite with two verification materials.
3. A resolver-shaped identity that contains a stable reference rather than an embedded public key.

Auths does not need to own production adapters for all three categories.

## Acceptance criteria

- A raw key remains easy to encode and verify.
- A key rotation does not necessarily change the stable identity identifier.
- A hybrid signature is represented without concatenation conventions hidden from the protocol.
- Identity methods without embedded keys can be modeled honestly.
- Capability and approval concepts remain absent.
