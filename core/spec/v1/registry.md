# Auths V1 Initial Registries

All lookups are exact. Unknown identifiers return `Indeterminate` when a
required capability is unavailable or `Denied` when an unknown critical field
or contradictory identifier appears. No parser, adapter, or algorithm
fallback is permitted.

The complete executable target-V1 set is bound by the pinned manifest
`33` repeated 32 times. A context carrying any other manifest is denied before
pluggable verification. Every implementation declares a conservative maximum
work cost that is reserved before invocation.

## Pure semantic registries

| Kind | Target V1 ID | Required behavior |
|---|---|---|
| Resource matcher | `uri-namespace-v1` | Exact URI namespace boundary matching |
| Profile policy | `exact-v1` | Effect-free acceptance of already validated canonical action facts |
| Budget algebra | `numeric-ceiling-v1` | Exact-algebra attenuation and coverage using unsigned `<=` |
| Critical extension | `exact-marker-v1` | Requires the exact byte string `h'01'` and otherwise changes no authority |
| Principal status | `auths-principal-status-v1` | Trusted issuer, method, floor, freshness, and revoked-dominant latest selection |
| Grant status | `auths-grant-status-v1` | Same selection rules as principal status |

Critical-extension, assurance-claim, and assurance-implication lookups are
also exact executable lookups. An identifier listed by the context without an
installed handler is indeterminate; an unaccepted signed critical extension is
denied. There is no fallback or version negotiation.

## Principal methods

| ID | Evidence ceiling | Mandatory suites |
|---|---:|---|
| `raw-key-v1` | 512 B | Ed25519, P-256 |
| `did-key-v1` | 2 KiB | Ed25519, P-256 |
| `did-keri-v1` | 64 KiB | registered KERI-compatible suites |
| `did-web-bundled-v1` | 32 KiB | Ed25519, P-256 |
| `spiffe-x509-v1` | 32 KiB | certificate-selected registered suite |
| `webauthn-v1` | 16 KiB | P-256 mandatory |
| `hsm-attested-v1` | 32 KiB | attestation-profile selected suite |

## Signature suites

| ID | Public key | Signature | Rule |
|---|---|---|---|
| `ed25519-v1` | 32-byte compressed point | 64 bytes | RFC 8032 verification of exact preimage |
| `p256-sha256-v1` | 33-byte compressed SEC1 | 64-byte `r || s` | ECDSA/SHA-256, low-S required |

## Status methods

| ID | Meaning |
|---|---|
| `auths-principal-status-v1` | Signed active/revoked/superseded principal state |
| `auths-grant-status-v1` | Signed active/revoked/superseded grant state |
| `keri-checkpoint-v1` | KERI sequence and witness/transparency checkpoint |
| `x509-status-v1` | Certificate validity and revocation evidence |
| `webauthn-credential-status-v1` | Registered authenticator credential state |
| `local-deny-list-v1` | Verifier-local explicit deny facts |

## Budget algebras

| ID | Order |
|---|---|
| `numeric-ceiling-v1` | child value must be less than or equal to parent |

## Composition operators

| ID | Meaning |
|---:|---|
| 0 | `Proof` |
| 1 | `AllOf` |
| 2 | `AnyOf` |
| 3 | `KOfN` |

## Transports

| ID | Peer observation |
|---|---|
| `memory-v1` | none |
| `iroh-v1` | endpoint and session key |
| `https-v1` | TLS peer and exporter binding |
| `tcp-v1` | endpoint only |
| `unix-v1` | socket and OS peer credentials |
| `file-v1` | envelope and sequence metadata |

## Profiles

| Profile ID | Version | Operations |
|---|---:|---|
| `auths.mcp` | 1 | MCP tool calls |
| `auths.http` | 1 | canonical HTTP requests |
| `auths.git` | 1 | commit, tag, ref, merge, release |
| `auths.deploy` | 1 | release and infrastructure deployment |
| `auths.supply-chain` | 1 | build, attest, publish, promote |
| `auths.edge` | 1 | device command and firmware activation |

## Assurance claims

The initial claim registry contains:

- `self-certifying-identifier`;
- `offline-verifiable`;
- `controller-state-current-at`;
- `historical-at`;
- `statement-existence-proven-at`;
- `rotation-aware`;
- `revocation-checked-at`;
- `witness-threshold-met`;
- `pki-chain-validated`;
- `workload-attested`;
- `hardware-attested`;
- `user-verified`;
- `origin-bound`.

Parameterized claims never satisfy unparameterized “high assurance” by name
alone. The assurance registry defines exact implication rules.

## Critical extensions

`exact-marker-v1` is the initial non-authority-changing executable extension.
Its body is exactly `h'01'`; it exists to exercise exact handler selection,
signed-byte validation, work reservation, and portable interoperability.
Unknown critical extensions are denied. New attenuation or composition
semantics require a protocol review, an executable model, and a new manifest.

## Assurance implications

No implication rule is initially registered. Claim names never imply one
another. A future implication must have an exact accepted identifier and a
pure executable handler included in a new registry manifest.
