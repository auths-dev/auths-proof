# Compatibility and support

This page is generated from the Auths evolution policy and lifecycle registry.

Stable publication: **blocked**

Current blockers: independent-security-review, moderated-recipe-three-cohort, second-qualified-effect-vertical.

## Version axes

| Axis | Owner | Rule | Authoritative artifacts |
| --- | --- | --- | --- |
| `package` | `release-engineering` | `semantic-versioning` | `Cargo.toml`<br>`bindings/typescript/package.json`<br>`bindings/python/pyproject.toml` |
| `abi` | `bindings` | `exact-packaged-coherence` | `bindings/wasm/auths-proof-wasm/authoring-abi-v1.json`<br>`bindings/python/native-abi-v2.json` |
| `semantic-subject` | `rust-core` | `immutable-identity` | `release/semantic-freeze.json` |
| `profile` | `profile-maintainers` | `exact-version-selection` | `product/profiles/auths-profile-mcp/profile-v1.json` |
| `conformance` | `assurance` | `immutable-case-identity` | `product/conformance/v1/mechanism-profile-conformance.json`<br>`product/conformance/v1/simplified-product-waist.json` |

## Stable support windows

- Profile verification: current and next package major, for at least 12 months.
- Profile authoring and execution after a successor: at least 12 months.
- Retirement notice: at least 90 days.
- Stable error removal: major release only.

## Profiles

| Profile | Status | Successor | Verification until | Authoring until |
| --- | --- | --- | --- | --- |
| `auths.mcp/1` | prelaunch | — | — | — |

## Error lifecycle

| Code | Status | Replacement | Final producing version |
| --- | --- | --- | --- |
| `core.forged-execution-reference` | active | — | — |
| `core.internal-invariant` | active | — | — |
| `core.invalid-configuration` | active | — | — |
| `core.malformed-input` | active | — | — |
| `core.native-runtime-unavailable` | active | — | — |
| `core.unsupported-abi` | active | — | — |
| `core.unsupported-semantic-subject` | active | — | — |
| `mcp.cancelled-before-entry` | active | — | — |
| `mcp.handler-failed` | active | — | — |
| `mcp.handler-timeout` | active | — | — |
| `mcp.invalid-handler-output` | active | — | — |
| `mcp.receipt-persist-failed` | active | — | — |
| `mcp.reconciliation-pending` | active | — | — |
| `mcp.replay` | active | — | — |
| `mcp.reservation-conflict` | active | — | — |
| `plan.action-substituted` | active | — | — |
| `plan.member-failed-before-entry` | active | — | — |
| `plan.member-interrupted` | active | — | — |
| `plan.reconciliation-pending` | active | — | — |
| `plan.resume-reference-invalid` | active | — | — |

## Conformance suites

| Suite | Version | Status |
| --- | ---: | --- |
| `auths.mechanism-profile-conformance` | 1 | prelaunch |
| `auths.simplified-product-waist-conformance` | 1 | prelaunch |
