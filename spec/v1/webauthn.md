# V1 WebAuthn Principal Adapter Profile

## Registry values

| Field | Value |
| --- | --- |
| Principal method and evidence type | `webauthn-v1` |
| Evidence media type | `application/vnd.auths.webauthn-assertion.v1` |
| Principal | `webauthn:<base64url-unpadded credential ID>` |
| Verification method | `<principal>#credential` |
| Signature suite | `p256-sha256-v1` |

Credential registration, browser ceremony initiation, and signature-counter
updates occur outside the pure kernel. A verifier supplies immutable
registration records containing the credential ID and P-256 key, RP ID,
allowed origins, required flags, prior counter policy, attestation level, and
observation window. A proof cannot supply or weaken those records.

## Evidence

```text
"AUTHS-WEBAUTHN\x00\x01"
u16-be credential_id_length
credential ID bytes
u16-be authenticator_data_length
authenticator data bytes
u32-be client_data_json_length
exact clientDataJSON bytes
```

The adapter verifies:

- `type` is exactly `webauthn.get`;
- the base64url challenge equals `SHA-256(exact Auths signing preimage)`;
- the origin is in the registration record;
- the RP ID hash, user-presence flag, required user-verification flag, and
  counter policy;
- the credential principal, verification method, P-256 key, and current local
  registration window.

The P-256 suite verifies the Auths signature over:

```text
authenticatorData || SHA-256(clientDataJSON)
```

This method-derived signature message is explicit in `ControlEvidence`; it
must cryptographically commit to the exact Auths preimage.

## Assurance

Successful verification emits current controller and revocation-check claims,
`origin-bound`, `user-verified` when the UV flag is present, and
`hardware-attested` only when the local registration record establishes a
named attestation level.
