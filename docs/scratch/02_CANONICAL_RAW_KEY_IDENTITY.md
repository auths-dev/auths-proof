# Establish one canonical raw-key identity

Status: scratch design note

## Goal

Make a raw public key identify the same principal everywhere in Auths, regardless of whether it arrived through identity exchange, a proof bundle, Iroh, HTTPS, a file, or an application-owned transport.

## Problem

Two raw-key schemes currently exist:

- `raw-key-v1` in the proof/authority adapter;
- `raw-key-identity-v1` in the neutral identity adapter.

They use different descriptor domains and encodings. Both emit `key:sha256:` identifiers, so a user can see the same identifier family while the same physical key produces different digests in different layers.

That prevents identity from flowing cleanly into authority and makes provenance difficult to understand.

## Canonical contract

The repository should have one normative raw-key descriptor definition containing:

- descriptor version;
- signature-suite identifier;
- exact public verification material;
- canonical encoding;
- domain-separated identifier derivation;
- maximum key size and identifier size.

Both neutral identity and authority principal-control adapters should consume this definition. Neither should independently reproduce its bytes or hash domain.

```text
canonical raw-key descriptor
        |                 |
        v                 v
identity method      principal-control adapter
        |                 |
        +---- same key:sha256 identifier ----+
```

## Design requirements

1. A descriptor has exactly one canonical byte representation.
2. The suite identifier is committed into the principal identifier.
3. The descriptor permits variable-length keys within explicit resource bounds.
4. Key-shape validation belongs to the selected signature suite, not the raw-key descriptor.
5. The identity and authority adapters share implementation or conformance vectors.
6. The old and new domains cannot silently coexist under the same identifier prefix.
7. A migration rule explicitly handles already-issued `raw-key-v1` principals.

## Compatibility decision

Before changing code, choose one of two paths:

### Preserve the existing authority identifier

Generalize the existing descriptor without changing identifiers already issued for Ed25519 and P-256. This offers the strongest compatibility but may require a versioned extension for arbitrary suites.

### Introduce a clearly distinct identifier family

Adopt a new derivation and a distinguishable prefix or method-qualified identifier. Existing principals remain valid but cannot be confused with the new family.

Using two derivations under the same `key:sha256:` surface is not acceptable.

## Migration

1. Add golden vectors for existing Ed25519 and P-256 principals.
2. Add vectors for at least one variable-length or post-quantum-shaped key.
3. Select the compatibility strategy.
4. Extract the canonical descriptor into the lowest neutral owner.
5. Adapt both identity and authority ports to it.
6. Add a CI search or semantic rule preventing another raw-key digest domain.

## Acceptance criteria

- The same suite and public key produce the same identifier in both layers.
- Every supported language agrees on descriptor bytes and identifier.
- Existing principals either remain byte-identical or have a documented, fail-closed migration path.
- No application code hashes raw-key descriptors itself.
