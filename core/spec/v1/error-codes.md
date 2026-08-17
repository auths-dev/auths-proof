# Stable Failure Taxonomy — V1

The enforcement decision is binary: executable or not executable. The proof
verifier retains three diagnostic classes.

## Authorized

| Code | Meaning |
|---|---|
| `authorized` | Every proof, authority, status, assurance, and action-binding check passed |

## Denied

| Code | Stage | Meaning |
|---|---|---|
| `malformed-proof` | decode | Input is not a complete bounded V1 object |
| `non-canonical-proof` | decode | Encoding or set order is not canonical |
| `resource-limit-exceeded` | any | Configured byte, count, depth, signature, or work limit exceeded |
| `digest-mismatch` | resolve | Content does not match its identifier |
| `duplicate-object` | resolve | Duplicate identifier or semantic object |
| `missing-reference` | resolve | Required digest reference is absent |
| `unused-critical-evidence` | resolve | Critical evidence is unconsumed |
| `invalid-signature` | control | Cryptographic signature is invalid |
| `principal-method-mismatch` | control | Principal and selected method disagree |
| `verification-method-mismatch` | control | Verification method is not valid for principal/purpose |
| `signature-suite-mismatch` | control | Suite and key are incompatible |
| `untrusted-root` | authority | No scoped local anchor covers the root |
| `broken-grant-chain` | authority | Issuer, subject, parent, actor, or profile linkage is broken |
| `delegation-expanded` | authority | A child widened an authority dimension |
| `permission-not-granted` | authority | Terminal authority lacks the exact permission |
| `action-constraint-mismatch` | authority | Body digest is outside the granted constraint |
| `budget-ceiling-exceeded` | authority | Requested budget exceeds or mismatches the signed ceiling, or the action declares no budget under a bounded ceiling |
| `composition-requirement-not-met` | authority | Authorized branches do not satisfy the trusted expected plan, quorum, actor-diversity, or root-diversity obligation |
| `plan-action-mismatch` | action | Branches bind different action meaning or plan |
| `action-body-mismatch` | action | Canonical body digest differs |
| `audience-mismatch` | action | Audience differs from verifier context |
| `challenge-mismatch` | action | Challenge differs from verifier context |
| `action-outside-validity` | action | Action is not live |
| `principal-revoked` | status | Accepted status says principal is revoked |
| `grant-revoked` | status | Accepted status says grant or ancestor is revoked |
| `status-sequence-rollback` | status | Status sequence moves backwards |
| `status-method-mismatch` | status | Subject status exists only under another exact method |
| `status-issuer-untrusted` | status | A valid status signature was made by an issuer outside snapshot trust |
| `registry-manifest-mismatch` | control | Context manifest differs from the immutable executable registry |
| `verifier-configuration-mismatch` | control | Context configuration commitment differs from the exact executable adapter and registry configuration |
| `resource-namespace-mismatch` | authority | Selected matcher rejects every root namespace |
| `critical-extension-unknown` | extension | Required extension is not registered |
| `attachment-missing` | action | Required signed attachment bytes are absent |
| `attachment-digest-mismatch` | action | Detached bytes do not hash to the signed identifier |
| `attachment-length-mismatch` | action | Detached byte length differs from the signed length |
| `duplicate-attachment` | resolve/action | An attachment identifier occurs more than once |
| `unused-critical-attachment` | action | Signed descriptors and supplied detached inputs do not correspond |
| `opaque-attachment-not-allowed` | action | Encrypted bytes were supplied where opaque verification was not signed as acceptable |
| `local-policy-denied` | policy | Explicit local policy rejects established facts |

## Indeterminate

| Code | Stage | Meaning |
|---|---|---|
| `unsupported-protocol` | decode | Protocol major is not supported |
| `unsupported-principal-method` | control | Required method is not registered |
| `unsupported-signature-suite` | control | Required suite is not registered |
| `unsupported-evidence-type` | evidence | Evidence verifier is unavailable |
| `unsupported-status-method` | status | Required status verifier is unavailable |
| `unsupported-profile` | action | Required profile/version is unavailable |
| `unsupported-profile-policy` | policy | Accepted profile-policy ID has no exact executable handler |
| `unsupported-resource-matcher` | authority | Accepted resource matcher has no exact executable handler |
| `unsupported-budget-algebra` | authority | Accepted budget algebra has no exact executable handler |
| `unsupported-critical-extension` | extension | Accepted critical extension has no exact executable handler |
| `unsupported-assurance-claim` | assurance | An adapter emitted a claim without an accepted exact handler |
| `missing-principal-evidence` | control | Required control fact cannot be established |
| `missing-principal-status` | status | Required principal status is absent |
| `missing-grant-status` | status | Required grant status is absent |
| `stale-status` | status | Status exists but is not fresh enough |
| `historical-state-unavailable` | evidence | Historical control/existence cannot be established |
| `assurance-requirement-not-met` | assurance | Required parameterized claim is absent |
| `external-fact-unavailable` | evidence | Required bounded external fact was not supplied |

## Outer runtime failures

These are never Auths authorization verdicts:

| Code | Meaning |
|---|---|
| `challenge-unknown` | Challenge was not issued |
| `challenge-expired` | Challenge expired |
| `challenge-consumed` | Challenge was already claimed |
| `replay-store-unavailable` | Atomic replay state unavailable |
| `budget-exhausted` | Stateful budget cannot be claimed |
| `budget-store-unavailable` | Budget state unavailable |
| `channel-policy-failed` | Peer observation does not satisfy local policy |
| `application-policy-failed` | Verified action violates a local restriction |
| `receipt-store-unavailable` | Receipt persistence policy cannot be met |
| `execution-failed` | Authorized command failed during execution |

Reason codes and diagnostic class are normative corpus fields.

## Reserved V1 codes

The following codes remain allocated in the portable enum but are not emitted
by a validly decoded V1 proof:

| Code | Reason reserved |
|---|---|
| `ambiguous-terminal-grant` | Action envelopes carry one explicit terminal grant, so ambiguity is rejected as malformed before authority evaluation |
| `authorization-plan-invalid` | The canonical decoder and model constructors validate plan shape and limits; invalid shapes are `malformed-proof` or `resource-limit-exceeded` before composition |
| `reference-cycle` | V1 grant identifiers are content hashes of statements containing their parent identifiers; a constructible cycle cannot pass content-address validation, so ordinary broken graphs produce `missing-reference` or `digest-mismatch` |

Reserved codes have no corpus vector and MUST NOT be emitted by a conforming V1
portable verifier.
