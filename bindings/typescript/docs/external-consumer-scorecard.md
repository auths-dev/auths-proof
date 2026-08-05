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
- Repacking the SDK succeeded through the npm package boundary.
- Reinstalling and checking `auths-agent-demo` is currently incomplete because
  the local package store lacked a declared React type package and the
  environment denied the required network install. No external-consumer exit
  claim is made until that install and the demo checks pass.

## Remaining gates

- Run the complete packed-package consumer check after dependency restoration.
- Run browser behavior on the refreshed package.
- Obtain macOS, Linux, and Windows CI evidence.
- Reconcile Python parity with AP-SPEC-035 and issue 73.
- Publish or promote nothing until the governing release and review gates
  permit it.
