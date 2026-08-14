# Content Epic 13 — Complete Identity and Trust Documentation

**Depends on:** Content Epics 10–12 and identity/trust release facts.

## Outcome

Readers can use Auths identity surfaces independently of capabilities,
approvals, transport, cryptographic suite, or provider implementation.

## Implementation

- [x] Build every Identity & trust page in the proposed hierarchy.
- [x] Add an identity-source chooser for raw public keys, OIDC, SPIFFE, and
  application resolvers.
- [x] Show standalone public-identity exchange with no authority object.
- [x] Show Ed25519 and P-256 as proof of suite agility and document the custom
  suite port without claiming Auths owns all adapters.
- [x] Explain trust roots, issuers, resolver policy, evidence freshness, and
  explicit trusted context.
- [x] Document rotation with overlap, rollback, negative fixtures, and no
  forced authority migration.
- [x] Add executable verification examples in Rust, TypeScript, and Python.
- [x] Add adversarial examples for unknown suite, mislabelled suite, wrong
  root, stale evidence, and verification-method mismatch.
- [x] Keep authority transitions in a labelled Related topics block.

## Acceptance

- No Identity landing card substitutes `/integrations`, `/architecture`, or
  `/reference` for missing identity content.
- A team can exchange and verify identity bytes without importing authority or
  approval APIs.
- Every suite and identity example names who owns trust policy and adapters.
