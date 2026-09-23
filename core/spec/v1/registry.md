# Auths V1 Initial Registries

All lookups are exact. Unknown identifiers return `Indeterminate` when a
required capability is unavailable or `Denied` when an unknown critical field
or contradictory identifier appears. No parser, adapter, or algorithm
fallback is permitted.

The complete executable target-V1 set is bound by the pinned manifest
`34` repeated 32 times. The set grew by the `observation-requirement-v1`
critical extension; a context carrying the earlier `33` manifest, or any other
manifest, is denied before pluggable verification. Every implementation declares a conservative maximum
work cost that is reserved before invocation.

## Pure semantic registries

| Kind | Target V1 ID | Required behavior |
|---|---|---|
| Resource matcher | `uri-namespace-v1` | Exact URI namespace boundary matching |
| Profile policy | `exact-v1` | Effect-free acceptance of already validated canonical action facts |
| Budget algebra | `numeric-ceiling-v1` | Exact-algebra attenuation and coverage using unsigned `<=` |
| Critical extension | `exact-marker-v1` | Requires the exact byte string `h'01'` and otherwise changes no authority |
| Critical extension | `observation-requirement-v1` | Grant-only; bytes are canonical `observation-requirements`; the verifier's observation stage evaluates them |
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

### Observation requirements

`observation-requirement-v1` is carried by grants. Its bytes are the
canonical `observation-requirements` CDDL value: one to eight distinct
requirements, each naming an observer anchor, an observation schema, a
subject (a literal resource or a profile action fact), a maximum age of
1 to 86400 seconds, and a conjunction of one to sixteen conditions. The only
condition atoms are:

| Tag | Atom | Holds when |
|---:|---|---|
| 0 | `eq-literal` | the named observed fact equals the literal, including its type |
| 1 | `eq-action` | the named observed fact equals the named profile action fact |
| 2 | `uint-range` | the named observed fact is an unsigned integer in `lo..=hi` |
| 3 | `member` | the named observed fact equals one of one to sixteen distinct literals |

A missing fact or a type mismatch makes a condition false. There is no
disjunction, negation, arithmetic, pattern, or user-defined function; a need
these atoms cannot express requires a new atom, a protocol review, and a new
manifest.

The handler validates the canonical bytes. It returns a resource-limit
failure above eight requirements, sixteen conditions, or sixteen membership
values, and an invalid-input failure for any other malformed or
non-canonical value, which the verifier reports as `local-policy-denied`,
as for every critical-extension handler. Evaluation needs the action, the
attachments, and the trusted context that a handler never sees, so it runs
in the verifier's observation stage.

A child grant must keep every parent requirement byte-identical. The
authority kernel also requires a child's complete critical-extension set to
equal its parent's, so requirements are chosen by the first grant under a
trust anchor and carried unchanged down the chain.

Signed observations travel as detached attachments whose descriptors carry
the media type `application/vnd.auths.observation.v1+cbor`. Each is at most
4 KiB, an action binds at most 32, and a trusted context carries at most 32
observer anchors.

## Profile-policy action facts

A profile policy may define named action facts derived from the canonical
action body, through the pure, bounded `action_fact` port method covered by
the policy's configuration commitment. `exact-v1` defines none: any
requirement that names an action fact under `exact-v1` is
`observation-action-fact-unavailable`. A profile that wants
observation-conditioned grants registers a new policy ID that defines its
facts.

## Assurance implications

No implication rule is initially registered. Claim names never imply one
another. A future implication must have an exact accepted identifier and a
pure executable handler included in a new registry manifest.
