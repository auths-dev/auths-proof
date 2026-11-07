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

Assurance interpretation revision 2 emits `user-verified` **without an
observation timestamp**. The signed UV flag establishes user verification in the
ceremony; it does not establish when the ceremony occurred. Verifier evaluation
time, the registration observation time and a presenter's asserted signing time
MUST NOT be substituted for ceremony time. Re-verifying identical evidence must
not renew its age. The central assurance evaluator therefore refuses a
maximum-age requirement on this undated claim, while an unaged UV requirement
can still be satisfied.

Other registration-derived claims retain the registration's `observed_at`.
Revision 2 is reported as the adapter version and is committed by the adapter's
configuration domain `webauthn-v1/assurance-v2`. The evidence bytes, principal
method and signature suite identifiers are unchanged. Old verifier configuration
commitments do not authorize the new interpretation.

A future fresh-UV profile needs a trusted ceremony observation bound to the exact
assertion/challenge and a replay-aware ceremony authority. Merely adding a
caller-provided timestamp to this evidence would not establish that guarantee.
