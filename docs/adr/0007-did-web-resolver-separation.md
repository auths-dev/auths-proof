# ADR 0007: `did:web` Resolution Is Not Verification

## Status

Accepted.

## Decision

The pure `auths-proof-did-web` adapter verifies a bundled canonical DID
document only when its digest is matched by explicit host trust.

Network retrieval lives in the separate native
`auths-proof-did-web-http` resolver. The resolver may produce a current trust
record after policy-constrained HTTPS retrieval, but it cannot authorize an
action and is never called by the verifier.

Historical document pins are verifier configuration. Accepting a historical
key additionally requires evidence that the exact Auths signing bytes existed
while the pinned document was valid.

## Consequences

- Native and WASM verification execute the same pure adapter code.
- Re-verification never depends on DNS, TLS, endpoint uptime, or ambient
  redirects.
- A bare DID document is insufficient to impersonate a `did:web` principal.
- Trust records must be protected like trust anchors; taking them from an
  untrusted proof would collapse the security boundary.
- Live resolution and archival pinning can evolve independently from the
  authority protocol.
