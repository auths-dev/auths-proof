# Make identity validation state explicit

Status: scratch design note

## Goal

Prevent canonical identity data from being mistaken for a trusted identity. Data should flow freely, but trust should only flow through an explicit validation transition.

## Problem

`IdentityPacket::decode` validates wire structure and canonical encoding. It does not prove that the claimed identity identifier belongs to the supplied key or that the selected method accepts the descriptor.

That distinction is technically documented, but the type is still named `PublicIdentity` before and after validation. Downstream code can accidentally treat successful decoding as successful authentication.

## Target type-state flow

```text
bytes
  |
  v
DecodedIdentity              safe to store, forward, inspect
  |
  | IdentityMethod::validate
  v
ValidatedIdentity            method/key/id relationship established
  |
  | SignatureVerifier::verify
  v
AuthenticatedMessage         exact message bound to validated identity
```

Each transition is explicit, fallible, and consumes or wraps the prior state. A lower-trust state must never implement an interface that requires a higher-trust state.

## Design requirements

1. Wire decoding returns an unvalidated or structurally validated identity type.
2. Method validation returns a non-forgeable validated wrapper.
3. Signature verification accepts only a validated identity or performs validation internally and returns an authenticated result.
4. Public constructors cannot mint validated wrappers.
5. Forwarding and storage remain possible without installing an adapter.
6. Errors distinguish malformed bytes, unsupported methods, invalid identity relationships, unsupported suites, and failed signatures.
7. Demos label structural exchange as `RECEIVED`, not `VERIFIED` or `AUTHENTICATED`.

## API direction

One possible shape is:

```rust
let packet = IdentityPacket::decode(bytes)?;
let decoded = packet.identity();
let validated = decoded.validate_with(method)?;
let authenticated = packet.verify_with(&validated, suite)?;
```

The exact names can change. The invariant cannot: data parsing must not mint trust.

## Adversarial tests

- Correct method ID with a forged identity ID.
- Correct identity ID with mutated key bytes.
- Unknown method and known suite.
- Known method and unknown suite.
- Canonical public-identity packet with an invalid method relationship.
- Valid signature over an invalid identity descriptor.
- Application attempts to construct a validated wrapper directly.

## Migration

1. Introduce the lower-trust decoded type without removing current APIs.
2. Change packet decoding to return the lower-trust state.
3. Add explicit validation in the Iroh demo and every receiver.
4. Deprecate ambiguous constructors and accessors.
5. Promote the type-state contract into the public API snapshot.

## Acceptance criteria

- Grepping receiver code shows an explicit method-validation call before identity trust is claimed.
- An invalid raw-key identity is transported successfully but cannot become validated.
- Authority bridges require `ValidatedIdentity`.
- Compiler errors prevent accidental trust promotion.
