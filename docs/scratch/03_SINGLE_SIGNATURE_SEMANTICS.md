# Establish one implementation of signature semantics

Status: scratch design note

## Goal

Allow many signature adapters while ensuring that one suite identifier always has one implementation meaning across identity, proofs, receipts, bindings, and future products.

## Problem

`ed25519-v1` is currently implemented independently for two ports:

- the proof stack's `SignatureSuite`;
- the identity layer's `SignatureVerifier`.

The implementations agree today, but a security fix, dependency upgrade, strictness change, or error-handling change can make them diverge while both continue advertising the same suite ID.

## Target architecture

```text
              canonical Ed25519 primitive
                 verify(key, message, sig)
                    /              \
                   v                v
       identity SignatureVerifier   proof SignatureSuite
```

The shared primitive should contain only cryptographic semantics. Port-specific concerns remain outside it:

- identity error mapping;
- proof work-unit accounting;
- adapter configuration IDs;
- registry integration;
- protocol-specific signing preimages.

## Design requirements

1. Each suite ID has one normative verification implementation.
2. Ports adapt into that implementation rather than copy it.
3. Protocol-specific preimage construction remains owned by each protocol.
4. Strict verification rules are explicit, including Ed25519 malleability behavior and P-256 low-S requirements.
5. The primitive has no dependency on grants, capabilities, approvals, transport, or product runtime.
6. Dependency versions are aligned where practical.
7. Cross-port conformance vectors test success and every relevant failure class.

## Adapter ownership

Auths should own the suite identifiers and the conformance contract. Auths does not need to own every cryptographic algorithm adapter.

Third parties should be able to implement a suite against the neutral port, but an identifier claimed to be an Auths-defined suite must satisfy Auths vectors.

## Migration

1. Extract or designate the canonical Ed25519 verifier.
2. Make both existing ports delegate to it.
3. Add cross-port tests using identical keys, messages, signatures, and mutations.
4. Repeat the pattern for P-256 only when an identity adapter is needed.
5. Document how external and post-quantum suite IDs are namespaced.

## Acceptance criteria

- There is one `verify_strict` call for the Auths Ed25519 suite in production code.
- Both ports accept and reject the same conformance corpus.
- Updating the cryptographic dependency updates all Auths Ed25519 consumers together.
- A new algorithm can be added without modifying either protocol core.
