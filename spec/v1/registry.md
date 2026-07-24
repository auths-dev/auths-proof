# V1 Registry

This registry is closed for Milestone 3. Additions require an ADR, fixtures,
algorithm-confusion tests, and an explicit policy decision.

## Principal adapters

| Adapter ID | Principal prefix | Evidence media type | Assurance |
|---|---|---|---|
| `raw-key-v1` | `key:sha256:` | `application/vnd.auths.raw-key.v1` | Self-certifying, offline-verifiable; no rotation/revocation/history |
| `did-keri-v1` | `did:keri:` | `application/vnd.auths.did-keri-kel.v1` | Self-certifying, offline-verifiable; rotation-aware only with retained next-key commitments; no global-current, historical-time, witness, or existence claim |
| `did-key-v1` | `did:key:` | `application/vnd.auths.did-key.v1` | Self-certifying and offline-verifiable; no rotation, deactivation, or history |
| `did-web-v1` | `did:web:` | `application/vnd.auths.did-web-document.v1` | Offline-verifiable only with explicit digest trust; current or historical claims depend on the trust-record mode |

## Signature algorithms

| Algorithm ID | Key | Signature encoding | Requirements |
|---|---|---|---|
| `ed25519` | 32-byte Ed25519 public key | 64-byte Ed25519 signature | Verify exact Auths signing bytes |
| `p256-sha256` | 33-byte compressed P-256 SEC1 point | 64-byte fixed `r || s` | ECDSA/SHA-256; low-S required |

There is no algorithm auto-detection or fallback. Signature length does not
select an algorithm.

## Protocol digests

| Use | Algorithm |
|---|---|
| `GrantId` | SHA-256 |
| `ActionId` | SHA-256 |
| `EvidenceId` | SHA-256 |
| `BodyDigest` | SHA-256 |
| raw-key principal fingerprint | SHA-256 |

SHA-1 is prohibited.

## Authority-state methods

No grant authority-state method is registered in Milestone 3. Therefore
`StatusProofRequired` grants produce `Indeterminate` until an explicitly
registered method and adapter are added.

## Future adapters

SPIFFE, X.509, SSH, and WebAuthn are not V1 Milestone 3 registry entries.
Their absence must return `UnsupportedAdapter`;
it must not trigger raw-key fallback.
