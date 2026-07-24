# Auths Proof Protocol — V1

## Status

This document and `auths-proof.cddl` define the Milestone 0 V1 protocol
implemented by the Rust workspace. The checked-in golden fixtures are
normative examples. V1 is pre-audit and must not yet be described as a stable
internet standard.

## Claim

Given local trust anchors and local verification context, an Auths proof
establishes that:

1. every signing principal proved control through its selected adapter;
2. authority flowed from a local trust anchor through an unbroken grant chain;
3. every child grant narrowed permission, validity, and delegation depth;
4. the terminal principal signed the exact action statement;
5. the action statement matches the verifier's body, audience, challenge, and
   current time;
6. the evidence satisfies the verifier's explicit assurance policy.

It does not establish that an action is wise, that a root should have been
trusted, or that an executor performed the verified bytes.

## Core objects

### Local trust anchor

A trust anchor is never serialized into a proof bundle. It is local input:

```text
principal
exact permission set
validity window
maximum delegation depth
assurance requirements
```

A proof cannot declare or broaden its own root.

### Permission

V1 permission is the exact ordered pair:

```text
(capability, resource)
```

There are no wildcards, regexes, globs, claims bags, or application callbacks.
A child permission set attenuates its parent only when it is a mathematical
subset under exact string equality.

### Grant

A grant transfers its exact permission set from `issuer` to `subject`. The
issuer signs the grant payload and signature descriptor with the grant domain.

The first grant has a null parent. Every subsequent grant contains the
`GrantId` of the preceding signed grant.

### Action

An action binds:

- terminal actor;
- one exact permission;
- SHA-256 digest of exact application bytes;
- audience;
- signer-asserted issue and expiry times;
- 32-byte verifier challenge.

`issued_at` is not a trusted timestamp. Historical key state alone does not
prove that an action signature existed before key revocation.

### Evidence

Principal evidence is opaque to the core and interpreted only by the exact
adapter named in the signed `SignatureDescriptor`. The bundle maps each
finalized `GrantId` or `ActionId` to one content-addressed evidence entry.

Evidence can be refreshed without changing the signed statement. A verifier
must re-evaluate the assurance of the evidence it actually receives.

### Revocation

V1 defines:

- `ExpiryOnly`: intentionally irrevocable until grant expiry;
- `StatusProofRequired`: requires authority-state evidence and an explicitly
  registered verifier.

Milestone 1 implements `ExpiryOnly`. A status-required grant with no supported
status evidence produces `Indeterminate`, never `Authorized`.

## Deterministic CBOR

V1 uses the closed schema in `auths-proof.cddl`:

- definite-length arrays, maps, text, and bytes only;
- shortest integer and length encodings;
- integer map keys in ascending order;
- no duplicate keys;
- no floats;
- no unregistered tags;
- no unknown fields;
- no trailing bytes;
- permission and evidence collections in canonical strict order.

A decoder must reject a semantically equivalent but non-canonical encoding.

## Resource limits

Default verifier limits:

| Item | Default | Hard V1 ceiling |
|---|---:|---:|
| Bundle | 2 MiB | 16 MiB |
| One evidence entry | 1 MiB | 8 MiB |
| Grant chain | 16 | 32 |
| Permissions per grant | 256 | 1,024 |
| Evidence entries/bindings | 64 | 256 |
| Signature | 1,024 bytes expected | 4,096 bytes |

Implementations apply cheap byte and collection limits before cryptographic
work.

## Raw-key profile

Milestone 1 registers `raw-key-v1`.

```text
principal = "key:sha256:" || base64url_no_pad(SHA-256(KeyDescriptorBytes))

KeyDescriptorBytes =
  UTF8("auths-proof/raw-key/v1\0")
  || key_type_u8
  || public_key_length_u16_be
  || public_key
```

Key types:

| Tag | Type | Public key | Signature |
|---:|---|---|---|
| 1 | Ed25519 | 32 bytes | 64 bytes |
| 2 | P-256 | 33-byte compressed SEC1 | 64-byte low-S `r || s` |

For this adapter the verification method is exactly the principal string.
Raw keys are self-certifying and offline-verifiable, but have no rotation,
revocation, or historical controller state.

## Portability

The verification operation receives the bundle, time, body, audience,
challenge, anchors, policy, and allowlisted adapters explicitly. It performs
no network, filesystem, environment, clock, randomness, database, or process
access.
