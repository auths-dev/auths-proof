# V1 SPIFFE X.509-SVID Principal Adapter Profile

## Registry values

| Field | Value |
| --- | --- |
| Principal method and evidence type | `spiffe-x509-v1` |
| Evidence media type | `application/vnd.auths.spiffe-x509-svid.v1` |
| Principal | closed `spiffe://<trust-domain>/<workload-path>` URI |
| Verification method | `<principal>#svid-<leaf-digest-prefix>` |
| Suites | certificate-selected `ed25519-v1` or `p256-sha256-v1` |

Workload API access and bundle acquisition are outside the kernel. The
verifier supplies trust-domain bundles and optional leaf-status observations.
Proof bytes cannot provide their own trust root.

## Evidence

```text
"AUTHS-SPIFFE-X509\x00\x01"
u16-be certificate_count
repeat leaf-first, excluding local roots:
    u32-be DER_length
    DER certificate
```

V1 accepts at most eight certificates, 16 KiB per certificate, and 32 KiB for
the chain. The method performs path and signature validation against the
selected local bundle, certificate validity at the explicit evaluation time,
name constraints, client-auth EKU, an exact single SPIFFE URI SAN, trust-domain
matching, and Ed25519/P-256 key extraction. Other leaf keys fail closed.

When the trust-domain policy requires status, a current verifier-local leaf
status record is mandatory; authenticated revocation denies the principal.

## Assurance

A valid path emits `pki-chain-validated` and `workload-attested`, parameterized
by trust domain. A matching current status record additionally emits
`controller-state-current-at` and `revocation-checked-at`.
