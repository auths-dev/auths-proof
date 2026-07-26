# V1 HSM-Attested Principal Adapter Profile

## Registry values

| Field | Value |
| --- | --- |
| Principal method and evidence type | `hsm-attested-v1` |
| Evidence media type | `application/vnd.auths.hsm-attested.v1` |
| Principal | `hsm:<base64url-unpadded key-record digest>` |
| Verification method | `<principal>#key` |
| Suites | `ed25519-v1`, `p256-sha256-v1` |

Provider APIs, device-certificate retrieval, and profile-specific chain
validation are outer-layer acquisition concerns. The pure method receives
verifier-local immutable records produced under reviewed profiles for cloud
KMS, PKCS#11, secure-enclave, or dedicated-HSM devices. A record fixes the
suite and key, profile, provider, protection level, key-handle and device-chain
digests, exportability, and observation window.

## Evidence

```text
"AUTHS-HSM-ATTESTED\x00\x01"
u8 profile_length || profile
u8 provider_length || provider
u8 protection_level_length || protection_level
32-byte key_handle_digest
32-byte device_chain_digest
u8 non_exportable
32-byte SHA-256(exact Auths signing preimage)
```

The evidence must exactly match the local record and transaction digest.
Signature verification remains in the exact selected suite. A successful
result emits `hardware-attested` with named profile/provider/level and
exportability parameters, current controller and revocation-check claims, and
`offline-verifiable`.
