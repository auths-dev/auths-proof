# Verifier limit coverage

This matrix is normative for the launch candidate. Protocol hard maxima are
enforced by model construction; the lower values encoded at context key `0`
are deployment limits. Context decoding reads that bounded limits object first,
then applies it to the remainder of the context. The complete encoded context
is checked against `ContextBytes` after canonical reconstruction.

| `LimitKind` / work source | Enforcement point | Boundary evidence |
|---|---|---|
| `BundleBytes` | `auths_codec::decode_bundle` before decode | `bundle-byte-limit-exceeded` |
| `ActionBytes` | `auths_codec::decode_canonical_action` before decode | codec boundary test |
| `ContextBytes` | `auths_codec::decode_verifier_context` before returning | codec boundary test |
| `Grants` | bundle array decode | generated maximum/malformed vectors |
| `Actions` | bundle array decode | generated maximum/malformed vectors |
| `PlanLeaves` | plan validation and composition validation | composition properties |
| `PlanDepth` | recursive plan decode before descent | `plan-depth-limit-exceeded` |
| `PlanBranching` | plan child-array decode | composition properties |
| `EvidenceObjects` | bundle/context assurance collection decode | `evidence-count-over-default` |
| `EvidenceBytes` | each evidence byte string before allocation | adapter parser suites |
| `ControlBindings` | binding-array decode | canonical corpus |
| `PrincipalStatusStatements` | bundle and snapshot array decode | status corpus |
| `GrantStatusStatements` | bundle and snapshot array decode | status corpus |
| `Attachments` | descriptor and detached-input array decode | attachment corpus |
| `AttachmentBytes` | each and aggregate detached byte decode | codec boundary test |
| `Signatures` | decoded bundle aggregate before control verification | canonical corpus |
| `SignatureBytes` | signature byte-string decode | suite adversarial tests |
| `Permissions` | permission-set decode and context anchor validation | attenuation properties |
| `Audiences` | audience-set decode and context anchor validation | attenuation properties |
| `CriticalExtensions` | extension/claim-parameter array decode | extension corpus |
| `CriticalExtensionBytes` | extension bytes before allocation | extension corpus |
| `AllowedBodyDigests` | action-constraint digest-array decode | attenuation properties |
| `BindingEvidence` | binding evidence-ID array decode | exact-consumption corpus |
| `CanonicalBodyBytes` | bundle detached body and canonical-action body decode | action boundary tests |
| `RegistryEntries` | every accepted-registry and trust/status rule collection | registry corpus |
| `TrustAnchors` | context anchor-array decode | context boundary tests |
| work units | reserved before signature, adapter, status, matcher, policy, extension, implication, and budget handlers | `verification-work-limit-exceeded` |

Logical work units are deterministic reservations for selected extension and
cryptographic operations. They are not a claim to measure every CPU cycle,
allocation, hash, sort, or host retry. Host retry amplification is outside the
kernel and must be bounded; an `Indeterminate` result never authorizes.
