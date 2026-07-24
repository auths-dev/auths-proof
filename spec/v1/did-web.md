# V1 `did:web` Evidence and Trust Profile

## Boundary

`did:web` retrieval and `did:web` verification are separate operations:

```text
DNS + HTTPS + host policy
          |
          v
auths-proof-did-web-http
          |
          +---- canonical document evidence
          +---- explicit host trust record
                            |
                            v
                 auths-proof-did-web
                 (pure; no resolution)
                            |
                            v
                  authority verifier
```

The proof bundle carries the canonical DID document. A verifier supplies the
trust record as local context, like a trust anchor. An untrusted proof must
never be allowed to choose its own trust record.

The HTTPS mapping follows the
[`did:web` method specification](https://w3c-ccg.github.io/did-method-web/):

```text
did:web:example.com
  -> https://example.com/.well-known/did.json

did:web:example.com:users:alice
  -> https://example.com/users/alice/did.json
```

V1 accepts lowercase ASCII DNS hosts, optional `%3A<port>`, and unreserved
ASCII path components. IP-address DIDs, Unicode hosts, arbitrary percent
encoding, dot segments, and redirects are rejected.

## Registry values

| Field | Value |
| --- | --- |
| Adapter ID | `did-web-v1` |
| Evidence media type | `application/vnd.auths.did-web-document.v1` |
| Principal form | closed V1 `did:web:` form |

## DID document profile

The bundled document is compact insertion-order JSON and is limited to 128
KiB. V1 requires:

- the sole context `https://www.w3.org/ns/did/v1`;
- an `id` exactly equal to the principal;
- absolute verification method IDs under `<principal>#...`;
- `type: "Multikey"`;
- `controller` exactly equal to the principal;
- base58btc Ed25519 or compressed P-256 Multikey material;
- string-reference `capabilityDelegation` and `capabilityInvocation`
  relationships.

For a grant, the selected method must appear in `capabilityDelegation`. For an
action, it must appear in `capabilityInvocation`. Embedded methods, remote
contexts, JWK auto-detection, unsupported curves, and unknown root properties
fail closed.

The evidence envelope is:

```text
"auths-proof/did-web/evidence/v1\0"
u32-be document_length
canonical document bytes
```

## Explicit trust records

A document identifying itself as `did:web:example.com` is not proof that it
came from `example.com`. The adapter therefore requires a host-controlled
record matching the principal and SHA-256 document digest.

### Current resolution

```text
principal
document_digest
observed_at
valid_until
```

The verification time must be within the record window. Successful
verification emits `ControllerStateCurrentAt(observed_at)` and
`RevocationCheckedAt(observed_at)`. Policy can bound its age.

### Historical pin

```text
principal
document_digest
valid_from
valid_until
optional {
    SHA-256(exact Auths signing bytes)
    statement_existed_at
}
```

The asserted signing time must fall within the pinned document interval. This
establishes `ControllerStateHistoricalAt`, but not by itself that the statement
actually existed while that key was authorized.

When the optional exact-statement pin matches, the adapter additionally emits
`StatementExistenceProvenAt`. Default verification policies require that claim
for historical keys. A document-only historical pin therefore produces
`Indeterminate(HistoricalStateUnavailable)`, preventing a removed key from
backdating a newly created grant or action.

## Resolver controls

The reference native resolver:

- requires an exact host allowlist;
- resolves DNS before the request and rejects any non-public address;
- pins the approved addresses into the HTTPS client;
- disables redirects;
- requires an accepted JSON media type;
- enforces response-size and timeout limits;
- validates document identity and the closed profile before returning;
- has no authority-verification API.

The resolver is native-only. The adapter, evidence, trust records, and verifier
remain WASM-compatible.
