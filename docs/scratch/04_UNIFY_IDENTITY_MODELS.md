# Unify the identity and authority identity models

Status: scratch design note

## Goal

Create one neutral identity surface that can carry identity data anywhere, then let callers explicitly promote a validated identity into an authority principal when they need grants, capabilities, approvals, or enforcement.

The desired flow is:

```text
untrusted identity bytes
        |
        v
validated identity
        |
        +--------------------> application data flow
        |
        +-- explicit bridge --> authority principal --> optional authority stack
```

## Problem

The repository currently has two identity vocabularies:

- `auths-identity` defines `PublicIdentity`, `IdentityMethod`, and `SignatureVerifier`.
- The proof stack defines `PrincipalId`, `PrincipalMethod`, `SignatureSuite`, and principal-control evidence.

The new identity path is independent, but independence alone does not make it composable. A caller that begins with a validated `PublicIdentity` has no canonical transition into the proof system. Reimplementing that mapping in each application would create new semantic opinions at every integration boundary.

## Target boundary

`auths-identity` should remain the owner of neutral identity descriptors and validation state. The proof stack should consume a small bridge contract rather than depend on concrete identity adapters.

The bridge should produce a value containing only the facts the authority layer needs, for example:

- canonical principal identifier;
- validated identity-method identifier;
- validated signature-suite identifier;
- verification material or a stable reference to it;
- evidence or assurance claims explicitly produced by the identity method.

The bridge must not create a grant, capability, approval, policy, or authorization decision.

## Design requirements

1. There is one canonical meaning for an identity identifier.
2. Promotion into authority is explicit and fallible.
3. Unvalidated identity data cannot satisfy an authority API.
4. The bridge preserves the identity method and suite; it must not reduce identity to a string.
5. Authority-specific evidence is created by a bridge adapter, not by `auths-identity`.
6. Applications that only exchange or authenticate identity never depend on the authority stack.
7. The bridge is covered by conformance vectors shared with both sides.

## Non-goals

- Moving grants or capabilities into `auths-identity`.
- Making every identity method an Auths-owned adapter.
- Treating network transport authentication as principal control.
- Automatically granting authority to any authenticated identity.

## Migration

1. Define a neutral validated-identity output type.
2. Define an authority-side `PrincipalFromIdentity` port.
3. Implement one raw-key bridge as proof of the contract.
4. Prove that the resulting principal is identical to the existing raw-key principal.
5. Move demos and testkit fixtures onto the bridge.
6. Deprecate parallel application-owned conversions.

## Acceptance criteria

- One raw public key has one principal identifier across identity exchange and proof verification.
- A validated identity can enter the authority stack without reparsing or re-deriving it in application code.
- A structurally decoded but unvalidated identity cannot enter the authority stack.
- Removing the authority packages leaves identity exchange fully functional.
- CI rejects a second identity-to-principal derivation.
