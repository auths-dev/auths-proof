# Domain Separation and Identifiers — V1

## Signing preimage

Every signed preimage is:

```text
UTF8("AUTHS") ||
u16be(protocol_major) ||
u16be(object_type) ||
u16be(profile_id_length) ||
UTF8(profile_id) ||
u16be(profile_version) ||
u64be(canonical_object_length) ||
deterministic_cbor(canonical_object)
```

The canonical signing object contains the unsigned statement and its
`SignatureDescriptor`. This binds the principal method, verification method,
and signature suite.

Object type identifiers are registered:

| ID | Object |
|---:|---|
| 1 | grant |
| 2 | action |
| 3 | principal status |
| 4 | grant status |
| 5 | decision receipt |
| 6 | execution receipt |
| 7 | registry manifest |
| 8 | bridge grant |

Profile-independent objects use an empty profile ID and version zero.

## Content identifiers

`domain_hash` is:

```text
SHA-256(
  UTF8("AUTHS-ID") ||
  u16be(protocol_major) ||
  u16be(identifier_type) ||
  u64be(canonical_bytes_length) ||
  canonical_bytes
)
```

Identifier type identifiers are fixed:

| ID | Identifier |
|---:|---|
| 1 | grant statement |
| 2 | action envelope |
| 3 | authorization plan |
| 4 | evidence object content |
| 5 | principal-status statement |
| 6 | grant-status statement |
| 7 | decision receipt |
| 8 | execution receipt |
| 9 | public verifier-context projection |
| 10 | registry manifest |

Identifiers:

- `GrantId`: canonical `grant-statement`, excluding signature;
- `ActionId`: canonical `action-envelope`, excluding signature;
- `AuthorizationPlanId`: canonical `authorization-plan`;
- `EvidenceId`: canonical evidence type, media type, and bytes;
- status statement IDs: canonical unsigned status statement;
- attachment digest: raw SHA-256 of exact attachment bytes;
- decision/execution receipt IDs: canonical unsigned receipt;
- context digest: canonical public verifier-context projection;
- canonical body digest: raw SHA-256 of exact profile-canonical body bytes;
- portable canonical action digest: raw SHA-256 of the complete deterministic
  `canonical-action` CBOR input;
- proof digest: raw SHA-256 of exact canonical proof-bundle bytes.

The `proof-ref` is a 32-byte branch identifier generated during authoring and
covered by the action signature. It is not derived from an action containing
the plan ID, avoiding an identifier cycle.

## Algorithms

V1 content identifiers and body digests use SHA-256. The registry contains no
algorithm field for these identifiers.

Ed25519 signs the full domain-separated preimage.
`p256-sha256-v1` uses ECDSA P-256 with SHA-256 and fixed-width 64-byte
`r || s`; high-S signatures are rejected.

SHA-1 is prohibited for every security-bearing identifier.
