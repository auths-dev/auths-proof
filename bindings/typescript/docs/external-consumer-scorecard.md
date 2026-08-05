# External-consumer SDK scorecard

**Consumer:** `auths-agent-demo`

**Mode:** locally packed package for repository-local feedback. This is not
release, provenance, independent-review, or clean-clone evidence.

## Before AP-SPEC-036

| Measure | Observed |
| --- | --- |
| Hand-authored protocol CBOR | none |
| Cryptographic constants copied into application | PKCS#8 Ed25519 prefix, raw-key descriptor domain, evidence identifiers |
| Application capability branding | private symbol, constructor token, and `WeakMap` for `VerifiedGitHubChangePlan` |
| Magic configuration digests | one approval configuration filled with a constant byte |
| Manual plan composition | three independent authorization calls, array search for first failure, manual command bundling |
| Manual authority aggregation | parallel `authorityFor` projections and indexed namespace/audience/permission selection |
| Manual receipt projection | SHA-256 projection of configuration and result bytes |
| Profile defect found | file path initially absent from the authorization resource |
| Unsafe application commitment found | FNV-32 fallback for multi-file path sets |

## After the repository-local AP-SPEC-036 implementation

| Measure | Result |
| --- | --- |
| Hand-authored protocol CBOR | zero |
| Cryptographic constants copied into application | removed from the workshop path; owned by `@auths-dev/sdk/testkit` |
| Application capability branding | removed; SDK `ApplicationCommand` and `VerifiedPlanCommand` own the brands |
| Magic configuration digests | removed; `approvalPolicy` commits typed configuration |
| Manual plan composition | replaced by `profile.plan` and `agent.authorizePlan` |
| Manual authority aggregation | replaced by `plan.authority` |
| Manual receipt projection | replaced by `inspectDecision` |
| Profile mutation feedback | supported by `profileConformance` |
| Multi-file commitment | profile uses its canonical cryptographic action digest, not FNV |
| Human approval reuse | SDK-owned plan session, exact action-count bound, disposed after authorization |

## Verification state

- TypeScript build passes.
- Compile-time non-forgeability/provider contract tests pass.
- Fast unit tests pass.
- Existing real-WASM integration tests pass from the current generated WASM.
- New MCP single-command and plan-command integration tests pass.
- The SDK was packed, installed as the declared dependency of
  `auths-agent-demo`, and checked without a TypeScript source-path bypass.
- The complete external TypeScript workspace typecheck passes against the
  refreshed tarball.
- The external `@auths-agent-demo/auths-integration` suite passes all 29 tests
  against that tarball.
- The clean packed-package Node fixture passes locally, including installed
  declarations and real packaged-WASM authorized, denied, and indeterminate
  decisions.
- The clean packed-package Chromium fixture passes locally, including a normal
  workflow, an exact two-action plan, a denied action with no gateway effect,
  disposal, and repeated loading.
- A maintained GitHub Actions matrix now covers the packed Node fixture on
  Linux, macOS, and Windows, plus packed Chromium on Linux. It has not yet run
  on the final revision, so no cross-platform exit claim is made here.

## Remaining gates

- Obtain passing macOS, Linux, and Windows CI evidence on the exact revision.
- Obtain passing packed-Chromium CI evidence on the exact revision.
- Reconcile Python parity with AP-SPEC-035 and issue 73.
- Publish or promote nothing until the governing release and review gates
  permit it.
