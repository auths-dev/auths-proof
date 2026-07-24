# ADR 0003: Offline Verifier Boundary

**Status:** Accepted

## Decision

Verification accepts all evidence and context as inputs and performs no
network, filesystem, environment, system-clock, randomness, process, database,
or private-key operation.

## Consequence

Resolvers package untrusted evidence outside the kernel. The same bundle can
be evaluated natively or in WASM under the same explicit policy.
