# V1 `did:key` Principal Adapter Profile

## Registry values

| Field | Value |
| --- | --- |
| Adapter ID | `did-key-v1` |
| Principal form | `did:key:<multibase-value>` |
| Evidence media type | `application/vnd.auths.did-key.v1` |
| Verification method | `<principal>#<multibase-value>` |

The profile follows the
[`did:key` method](https://w3c-ccg.github.io/did-key-spec/) but deliberately
supports only base58btc (`z`) Multikey values containing:

- Ed25519 multicodec `0xed`, encoded as varint bytes `ed 01`;
- compressed P-256 multicodec `0x1200`, encoded as varint bytes `80 24`.

The key length and curve point are validated. The adapter performs no
algorithm inference or fallback.

## Evidence

```text
"AUTHS-DID-KEY\x00\x01"
u16-be multikey_length
multikey UTF-8 bytes
```

The evidence Multikey must reconstruct the exact principal and verification
method. Signature verification remains in the separately selected exact
signature-suite implementation.

## Assurance

The adapter emits:

```text
self-certifying-identifier
offline-verifiable
```

`did:key` has no rotation, deactivation, or historical controller-state
mechanism. It remains subject to irrevocable-principal policy.
