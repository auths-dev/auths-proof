# Domain Separation and Content Identifiers — V1

## Signature inputs

Signers sign these exact bytes:

```text
grant signing bytes  = UTF8("auths-proof/grant/v1\0")
                       || deterministic_cbor(grant-signing-input)

action signing bytes = UTF8("auths-proof/action/v1\0")
                       || deterministic_cbor(action-signing-input)
```

The signing input contains the `SignatureDescriptor`, so the adapter,
verification method, and algorithm cannot be substituted after signing.

Ed25519 signs the complete byte string directly. `p256-sha256` uses ECDSA
P-256 with SHA-256 as defined by the selected signature implementation and
encodes signatures as fixed-width 64-byte `r || s`. V1 P-256 signatures MUST
be low-S.

## Content identifiers

For `domain_hash(domain, encoded)`:

```text
SHA-256(domain || uint64_be(len(encoded)) || encoded)
```

V1 identifiers are:

```text
GrantId    = domain_hash("auths-proof/grant-id/v1\0",
                         deterministic_cbor(signed-grant))

ActionId   = domain_hash("auths-proof/action-id/v1\0",
                         deterministic_cbor(signed-action))

EvidenceId = domain_hash("auths-proof/evidence-id/v1\0",
                         deterministic_cbor({
                           0: adapter-or-state-method,
                           1: media-type,
                           2: evidence-bytes
                         }))
```

`BodyDigest` is ordinary SHA-256 over the exact application-supplied body
bytes. Application profiles are responsible for defining which native bytes
are supplied. Auths does not canonicalize JSON, HTTP, MCP, Git, or another
application protocol.

## No algorithm agility for object identifiers

All V1 object and body digests use SHA-256. A future protocol version may
define another algorithm, but V1 decoders do not accept an algorithm field for
these digests. Identity adapters may interpret other secure identifier
formats internally.

SHA-1 is never valid for a security-bearing V1 identifier.
