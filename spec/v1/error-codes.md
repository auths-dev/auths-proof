# Verdict Reason Codes — V1

Reason enum names are the stable machine identifiers.

## Success

| Code | Meaning |
|---|---|
| `AuthorizedByGrantChain` | All proof, authority, context, and assurance checks passed. |

## Denied

| Code | Meaning |
|---|---|
| `MalformedProof` | Input is not a complete V1 proof object. |
| `NonCanonicalProof` | CBOR or collection ordering is not canonical. |
| `InvalidEvidenceDigest` | Evidence content does not match its identifier or is invalid for its adapter. |
| `DuplicateEvidence` | Evidence identifier is duplicated inconsistently. |
| `DuplicateEvidenceBinding` | A statement has more than one evidence binding. |
| `UnusedEvidence` | Bundle contains unknown bindings or unreferenced evidence. |
| `InvalidSignature` | Cryptographic signature verification failed. |
| `PrincipalAdapterMismatch` | Principal, evidence, and selected adapter disagree. |
| `VerificationMethodMismatch` | Selected verification method is invalid for the principal. |
| `AlgorithmMismatch` | Algorithm and verification key are incompatible. |
| `ActionBodyMismatch` | Exact body SHA-256 differs from the signed action. |
| `AudienceMismatch` | Action audience differs from verifier context. |
| `ChallengeMismatch` | Action challenge differs from verifier context. |
| `ActionOutsideValidity` | Action is not live at verifier-supplied time. |
| `PermissionNotGranted` | Terminal authority lacks the action permission. |
| `DelegationExpanded` | A child expanded permissions, validity, time ordering, or depth. |
| `BrokenGrantChain` | Issuer/subject/parent/actor linkage is broken. |
| `GrantExpired` | A grant is not live at verifier-supplied time. |
| `GrantRevoked` | Valid status evidence says the grant is revoked. |
| `UntrustedRoot` | No local trust anchor covers the root and requested authority. |
| `ResourceLimitExceeded` | Input exceeded configured or hard resource limits. |

## Indeterminate

| Code | Meaning |
|---|---|
| `AssuranceRequirementNotMet` | Valid proof lacks assurance demanded by local policy. |
| `UnsupportedAdapter` | Required adapter is not explicitly registered. |
| `MissingPrincipalEvidence` | A signed statement lacks bound principal evidence. |
| `MissingAuthorityStateEvidence` | A status-required grant lacks usable status evidence. |
| `StaleAuthorityStateEvidence` | Grant status or controller-state evidence is older than policy permits. |
| `HistoricalStateUnavailable` | Historical controller state or required exact-statement existence evidence is absent. |
| `ExpiryOnlyGrantDisallowed` | Policy refuses intentionally irrevocable grants. |
| `IrrevocablePrincipalDisallowed` | Policy refuses a principal without rotation/revocation assurance. |

The Rust enum contains reserved reason names for later grant-status
adapters. Their decision class may not silently change within V1.
