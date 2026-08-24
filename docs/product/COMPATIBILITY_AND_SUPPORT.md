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
| `client.agent-unavailable` | active | — | — |
| `client.profile-contract-mismatch` | active | — | — |
| `client.profile-unavailable` | active | — | — |
| `connection.contract-mismatch` | active | — | — |
| `connection.credential-unavailable` | active | — | — |
| `connection.unavailable` | active | — | — |
| `core.authorization-denied` | active | — | — |
| `core.authorization-indeterminate` | active | — | — |
| `core.forged-execution-reference` | active | — | — |
| `core.internal-invariant` | active | — | — |
| `core.invalid-configuration` | active | — | — |
| `core.malformed-input` | active | — | — |
| `core.native-runtime-unavailable` | active | — | — |
| `core.observation-inconclusive` | active | — | — |
| `core.observation-pending` | active | — | — |
| `core.outcome-unknown` | active | — | — |
| `core.receipt-expired` | active | — | — |
| `core.receipt-malformed` | active | — | — |
| `core.receipt-profile-denied` | active | — | — |
| `core.receipt-signature-invalid` | active | — | — |
| `core.receipt-signer-untrusted` | active | — | — |
| `core.receipt-trust-indeterminate` | active | — | — |
| `core.runtime-cancelled` | active | — | — |
| `core.runtime-conflict` | active | — | — |
| `core.runtime-unavailable` | active | — | — |
| `core.terminal-receipt-integrity-failed` | active | — | — |
| `core.unauthenticated-principal` | active | — | — |
| `core.unsupported-abi` | active | — | — |
| `core.unsupported-semantic-subject` | active | — | — |
| `core.verification-capacity` | active | — | — |
| `core.workflow-terminal` | active | — | — |
| `custody.cancelled` | active | — | — |
| `custody.denied` | active | — | — |
| `custody.descriptor-mismatch` | active | — | — |
| `custody.disabled-key` | active | — | — |
| `custody.evidence-mismatch` | active | — | — |
| `custody.invalid-provider-response` | active | — | — |
| `custody.key-version-mismatch` | active | — | — |
| `custody.lifecycle-not-permitted` | active | — | — |
| `custody.malformed-signature` | active | — | — |
| `custody.non-canonical-signature` | active | — | — |
| `custody.principal-mismatch` | active | — | — |
| `custody.provider-unknown` | active | — | — |
| `custody.request-mismatch` | active | — | — |
| `custody.revoked-key` | active | — | — |
| `custody.signature-verification-failed` | active | — | — |
| `custody.throttled` | active | — | — |
| `custody.transaction-mismatch` | active | — | — |
| `custody.unavailable` | active | — | — |
| `github.attenuation-denied` | active | — | — |
| `github.base-revision-mismatch` | active | — | — |
| `github.boundary-invalid` | active | — | — |
| `github.branch-already-exists` | active | — | — |
| `github.branch-budget-exhausted` | active | — | — |
| `github.branch-outcome-unknown` | active | — | — |
| `github.branch-rejected` | active | — | — |
| `github.candidate-bundle-malformed` | active | — | — |
| `github.candidate-limit-exceeded` | active | — | — |
| `github.candidate-not-descendant` | active | — | — |
| `github.candidate-substituted` | active | — | — |
| `github.credential-boundary-failed` | active | — | — |
| `github.delegation-capacity` | active | — | — |
| `github.delegation-outcome-unknown` | active | — | — |
| `github.evidence-missing` | active | — | — |
| `github.evidence-stale` | active | — | — |
| `github.exact-action-mismatch` | active | — | — |
| `github.execution-capacity` | active | — | — |
| `github.executor-audience-mismatch` | active | — | — |
| `github.file-mode-denied` | active | — | — |
| `github.issue-mismatch` | active | — | — |
| `github.issue-not-open` | active | — | — |
| `github.merge-commit-denied` | active | — | — |
| `github.path-explicitly-denied` | active | — | — |
| `github.path-not-allowed` | active | — | — |
| `github.pull-request-already-exists` | active | — | — |
| `github.pull-request-budget-exhausted` | active | — | — |
| `github.pull-request-outcome-unknown` | active | — | — |
| `github.pull-request-rejected` | active | — | — |
| `github.receipt-invalid` | active | — | — |
| `github.repository-automation-policy-mismatch` | active | — | — |
| `github.repository-mismatch` | active | — | — |
| `github.repository-renamed-or-transferred` | active | — | — |
| `github.unsupported-git-object` | active | — | — |
| `github.verifier-configuration-mismatch` | active | — | — |
| `github.workflow-cancelled` | active | — | — |
| `github.workflow-expired` | active | — | — |
| `github.workflow-proof-invalid` | active | — | — |
| `github.workflow-terminal-applied` | active | — | — |
| `github.workflow-terminal-not-applied` | active | — | — |
| `identity.authentication-indeterminate` | active | — | — |
| `identity.evidence-expired` | active | — | — |
| `identity.method-unsupported` | active | — | — |
| `identity.not-found` | active | — | — |
| `identity.packet-malformed` | active | — | — |
| `identity.relationship-denied` | active | — | — |
| `identity.resolution-indeterminate` | active | — | — |
| `identity.resolution-rejected` | active | — | — |
| `identity.signature-invalid` | active | — | — |
| `identity.validation-indeterminate` | active | — | — |
| `identity.validation-rejected` | active | — | — |
| `mcp.admission-capacity` | active | — | — |
| `mcp.cancelled-before-entry` | active | — | — |
| `mcp.delegation-capacity` | active | — | — |
| `mcp.handler-failed` | active | — | — |
| `mcp.handler-timeout` | active | — | — |
| `mcp.invalid-handler-output` | active | — | — |
| `mcp.receipt-invalid` | active | — | — |
| `mcp.receipt-persist-failed` | active | — | — |
| `mcp.reconciliation-pending` | active | — | — |
| `mcp.recovery-kind-mismatch` | active | — | — |
| `mcp.recovery-not-found` | active | — | — |
| `mcp.replay` | active | — | — |
| `mcp.reservation-conflict` | active | — | — |
| `opentofu.apply-outcome-unknown` | active | — | — |
| `opentofu.plan-preflight-denied` | active | — | — |
| `opentofu.plan-preflight-outcome-unknown` | active | — | — |
| `opentofu.saved-plan-denied` | active | — | — |
| `operation.admission-exhausted` | active | — | — |
| `operation.idempotency-conflict` | active | — | — |
| `operation.outcome-unknown` | active | — | — |
| `operation.recovery-unavailable` | active | — | — |
| `operation.timed-out` | active | — | — |
| `plan.action-substituted` | active | — | — |
| `plan.member-failed-before-entry` | active | — | — |
| `plan.member-interrupted` | active | — | — |
| `plan.reconciliation-pending` | active | — | — |
| `plan.resume-reference-invalid` | active | — | — |
| `postgresql.preflight-denied` | active | — | — |
| `postgresql.preflight-outcome-unknown` | active | — | — |
| `postgresql.update-denied` | active | — | — |
| `postgresql.update-outcome-unknown` | active | — | — |
| `remote.authentication-failed` | active | — | — |
| `remote.response-malformed` | active | — | — |
| `remote.timeout` | active | — | — |
| `remote.transport-unavailable` | active | — | — |
| `stripe.refund-denied` | active | — | — |
| `stripe.refund-outcome-unknown` | active | — | — |

## Conformance suites

| Suite | Version | Status |
| --- | ---: | --- |
| `auths.mechanism-profile-conformance` | 1 | prelaunch |
| `auths.simplified-product-waist-conformance` | 1 | prelaunch |
