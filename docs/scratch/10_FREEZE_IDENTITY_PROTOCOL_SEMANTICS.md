# Freeze and version identity protocol semantics

Status: scratch design note

## Goal

Give identity bytes, identifiers, signing preimages, adapter IDs, and compatibility promises the same release discipline already applied to the proof protocol.

## Problem

The identity wire currently embeds version 2 in its magic and signing domain, while surrounding declarations use `auths-identity/v1`, `/auths/identity/1`, `IDENTITY-V1`, and the older `raw-key-v1` family name.

Those values may represent different version dimensions, but the mapping is not explicit. The new identity packages are also absent from the semantic-freeze public Rust closure, so their public bytes and APIs are not protected as a release surface.

## Version dimensions

Define separate names for separate meanings:

- identity model version;
- canonical wire version;
- signing-domain version;
- transport application protocol version;
- identity-method version;
- signature-suite version;
- public crate/API version.

One version changing must not silently imply that every other version changed.

## Required frozen artifacts

1. Public identity descriptor bytes.
2. Public-identity packet bytes.
3. Signed-message packet bytes.
4. Signing preimages.
5. Raw-key identifier derivation vectors.
6. Method and suite identifiers.
7. Decoder rejection corpus.
8. Public Rust declarations and binding entry points.
9. Compliance inventory names.
10. Transport ALPN or equivalent protocol labels.

## Design requirements

1. Every frozen byte family has one owner and semantic identity.
2. Compliance declarations match actual method and suite IDs.
3. Wire-version changes require explicit migration notes and vectors.
4. Independent language verifiers consume the same corpus where applicable.
5. Architecture-only changes do not masquerade as protocol changes.
6. Unpublished experimental surfaces are clearly labelled and excluded intentionally.
7. Promoting identity to public status adds it to release roots and API checks.

## Migration

1. Inventory every current identity-related version label.
2. Document the mapping between V1 product protocol and V2 wire, or rename them.
3. Correct stale compliance principal-family declarations.
4. Add identity vectors and malformed-input corpus.
5. Add identity packages to semantic-freeze roots when they become supported.
6. Require an update command and review note for future drift.

## Acceptance criteria

- A release reviewer can explain every identity version number without reading implementation code.
- CI fails if wire bytes, preimages, raw-key IDs, or public declarations drift.
- Compliance metadata names the actual protocol, method, and suite families.
- A consumer can determine whether two releases interoperate from published metadata.
