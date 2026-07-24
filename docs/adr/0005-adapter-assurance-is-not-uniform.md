# ADR 0005: Adapter Assurance Is Not Uniform

**Status:** Accepted

## Decision

The authority engine depends on `PrincipalControlVerifier`, not KERI or another
identity method. Adapters return typed assurance claims, and policy decides
which claims are required.

## Consequence

A raw key, `did:web`, and `did:keri` may use the same authority protocol
without receiving the same trust verdict under a high-assurance policy.

Unsupported adapters never fall back to another method.
