# Auths error and recovery registry

Every row is generated from the Rust-owned registry. `possible` effects are never retry-safe.

| Code | Operation | Effect / retry | Recommended action | Meaning |
| --- | --- | --- | --- | --- |
| `core.invalid-configuration` | `create` | notapplied / never | `CorrectConfiguration` | A bounded configuration value is invalid. |
| `core.unsupported-abi` | `create` | notapplied / never | `InstallCompatibleRuntime` | The installed language package and native runtime do not share an ABI. |
| `core.unsupported-semantic-subject` | `create` | notapplied / never | `InstallCompatibleRuntime` | The installed artifacts do not implement the same Auths meaning. |
| `core.malformed-input` | `verify` | notapplied / never | `CorrectInput` | The supplied bounded value could not be parsed. |
| `core.native-runtime-unavailable` | `create` | notapplied / safe | `RetryExecution` | The packaged Auths runtime could not be initialized. |
| `core.forged-execution-reference` | `resume` | notapplied / never | `CorrectInput` | The execution reference is malformed, unauthenticated, or bound to different state. |
| `core.runtime-conflict` | `execute` | notapplied / conditional | `SatisfyCondition` | A concurrent operation changed the exact workflow state. |
| `core.runtime-unavailable` | `execute` | notapplied / safe | `RetryExecution` | The durable runtime could not complete an operation before provider entry. |
| `core.runtime-cancelled` | `execute` | notapplied / safe | `RetryExecution` | The workflow was cancelled with definite non-effect evidence. |
| `core.outcome-unknown` | `execute` | possible / unknown | `ResumeAndReconcile` | The exact effect may have occurred and must be observed before retry. |
| `core.observation-pending` | `resume` | possible / unknown | `ResumeAndReconcile` | The provider has not exposed conclusive evidence for the exact effect. |
| `core.observation-inconclusive` | `resume` | possible / unknown | `ResumeAndReconcile` | Available evidence cannot prove effect or non-effect for the exact request. |
| `core.workflow-terminal` | `resume` | notapplied / never | `InspectReceipt` | The workflow has already reached an immutable terminal state. |
| `core.internal-invariant` | `execute` | notapplied / never | `ContactSupport` | Auths rejected an impossible internal state before an effect. |
| `core.terminal-receipt-integrity-failed` | `resume` | notapplied / never, possible / never, applied / never | `ContactSupport` | The registered Auths contract rejected or classified this bounded operation. |
| `core.authorization-denied` | `verify` | notapplied / never | `SatisfyCondition` | Available facts prove the supplied proof does not authorize the exact action. |
| `core.authorization-indeterminate` | `verify` | notapplied / conditional | `SatisfyCondition` | A required authorization fact was unavailable, so no decision was reached before any effect. |
| `core.unauthenticated-principal` | `create` | notapplied / never | `CorrectInput` | The request asserts a principal the runtime cannot authenticate, so no authority is issued. |
| `client.agent-unavailable` | `connect` | notapplied / conditional | `CorrectConfiguration` | The SDK could not establish an authenticated local-agent session. |
| `client.profile-unavailable` | `connect` | notapplied / never | `InstallCompatibleRuntime` | The local agent did not advertise the required profile and version. |
| `client.profile-contract-mismatch` | `connect` | notapplied / never | `InstallCompatibleRuntime` | The generated client and runtime do not share the same profile contract digest. |
| `connection.contract-mismatch` | `execute` | notapplied / never | `InstallCompatibleRuntime` | The profile runtime and selected provider connection do not share the required immutable connection contract. |
| `connection.credential-unavailable` | `execute` | notapplied / safe | `RetryExecution` | The bound provider credential could not be leased and durable state proves that the provider was not entered. |
| `connection.unavailable` | `execute` | notapplied / never | `CorrectConfiguration` | No active provider connection matching the requested or default alias is authorized for this workload and profile. |
| `operation.admission-exhausted` | `execute` | notapplied / conditional | `RetryExecution` | The bounded operation capacity was exhausted before provider entry. |
| `operation.idempotency-conflict` | `execute` | possible / unknown | `ResumeAndReconcile` | The key names an existing operation with a different commitment; recover that operation. |
| `operation.outcome-unknown` | `execute` | possible / unknown | `ResumeAndReconcile` | The provider may have applied the exact operation; recover it instead of retrying. |
| `operation.recovery-unavailable` | `recover` | possible / unknown | `ResumeAndReconcile` | Recovery could not establish the effect and the original operation remains possible. |
| `operation.timed-out` | `execute` | notapplied / safe | `RetryExecution` | The bounded deadline expired and durable state proves that the provider was not entered. |
| `opentofu.plan-preflight-denied` | `execute` | notapplied / never | `SatisfyCondition` | The OpenTofu plan preflight failed its exact profile evaluation or protected-planner checks. |
| `opentofu.plan-preflight-outcome-unknown` | `execute` | possible / unknown | `ResumeAndReconcile` | Recovery must establish whether the OpenTofu prepared-plan record and artifact became ready. |
| `opentofu.saved-plan-denied` | `execute` | notapplied / never | `SatisfyCondition` | The saved plan failed its exact OpenTofu profile evaluation. |
| `opentofu.apply-outcome-unknown` | `execute` | possible / unknown | `ResumeAndReconcile` | The OpenTofu apply must be reconciled before another execution. |
| `postgresql.preflight-denied` | `execute` | notapplied / never | `SatisfyCondition` | The PostgreSQL update preflight failed its exact profile evaluation or protected discovery checks. |
| `postgresql.preflight-outcome-unknown` | `execute` | possible / unknown | `ResumeAndReconcile` | Recovery must establish whether the PostgreSQL prepared-update record became ready. |
| `postgresql.update-denied` | `execute` | notapplied / never | `SatisfyCondition` | The bounded PostgreSQL update failed its exact profile evaluation. |
| `postgresql.update-outcome-unknown` | `execute` | possible / unknown | `ResumeAndReconcile` | The PostgreSQL transaction outcome must be reconciled before another execution. |
| `stripe.refund-denied` | `execute` | notapplied / never | `SatisfyCondition` | The exact Stripe refund was not authorized by the bounded profile. |
| `stripe.refund-outcome-unknown` | `execute` | possible / unknown | `ResumeAndReconcile` | The Stripe refund outcome requires recovery before another execution. |
| `core.receipt-malformed` | `verify` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `core.receipt-signature-invalid` | `verify` | notapplied / never | `InspectReceipt` | The registered Auths contract rejected or classified this bounded operation. |
| `core.receipt-signer-untrusted` | `verify` | notapplied / never | `CorrectConfiguration` | The registered Auths contract rejected or classified this bounded operation. |
| `core.receipt-profile-denied` | `verify` | notapplied / never | `CorrectConfiguration` | The registered Auths contract rejected or classified this bounded operation. |
| `core.receipt-expired` | `verify` | notapplied / never | `InspectReceipt` | The registered Auths contract rejected or classified this bounded operation. |
| `core.receipt-trust-indeterminate` | `verify` | notapplied / conditional | `SatisfyCondition` | The registered Auths contract rejected or classified this bounded operation. |
| `core.verification-capacity` | `verify` | notapplied / safe | `RetryExecution` | The registered Auths contract rejected or classified this bounded operation. |
| `remote.authentication-failed` | `verify` | notapplied / never | `CorrectConfiguration` | The registered Auths contract rejected or classified this bounded operation. |
| `remote.response-malformed` | `verify` | notapplied / never | `ContactSupport` | The registered Auths contract rejected or classified this bounded operation. |
| `remote.transport-unavailable` | `verify` | notapplied / safe | `RetryExecution` | The registered Auths contract rejected or classified this bounded operation. |
| `remote.timeout` | `verify` | notapplied / safe | `RetryExecution` | The registered Auths contract rejected or classified this bounded operation. |
| `mcp.receipt-invalid` | `verify` | notapplied / never | `InspectReceipt` | The registered Auths contract rejected or classified this bounded operation. |
| `mcp.admission-capacity` | `execute` | notapplied / safe | `RetryExecution` | The registered Auths contract rejected or classified this bounded operation. |
| `mcp.delegation-capacity` | `delegate` | notapplied / safe | `RetryExecution` | The registered Auths contract rejected or classified this bounded operation. |
| `mcp.recovery-not-found` | `resume` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `mcp.recovery-kind-mismatch` | `resume` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `identity.packet-malformed` | `decode` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `identity.method-unsupported` | `decode` | notapplied / never | `CorrectConfiguration` | The registered Auths contract rejected or classified this bounded operation. |
| `identity.not-found` | `resolve` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `identity.resolution-rejected` | `resolve` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `identity.resolution-indeterminate` | `resolve` | notapplied / safe | `RetryExecution` | The registered Auths contract rejected or classified this bounded operation. |
| `identity.evidence-expired` | `validate` | notapplied / conditional | `SatisfyCondition` | The registered Auths contract rejected or classified this bounded operation. |
| `identity.validation-rejected` | `validate` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `identity.validation-indeterminate` | `validate` | notapplied / safe | `RetryExecution` | The registered Auths contract rejected or classified this bounded operation. |
| `identity.relationship-denied` | `authenticate` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `identity.signature-invalid` | `authenticate` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `identity.authentication-indeterminate` | `authenticate` | notapplied / safe | `RetryExecution` | The registered Auths contract rejected or classified this bounded operation. |
| `github.boundary-invalid` | `create` | notapplied / never | `CorrectConfiguration` | The registered Auths contract rejected or classified this bounded operation. |
| `github.attenuation-denied` | `delegate` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `github.delegation-outcome-unknown` | `delegate` | possible / unknown | `ResumeAndReconcile` | The registered Auths contract rejected or classified this bounded operation. |
| `github.workflow-proof-invalid` | `execute` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `github.workflow-expired` | `execute` | notapplied / never | `SatisfyCondition` | The registered Auths contract rejected or classified this bounded operation. |
| `github.workflow-cancelled` | `execute` | notapplied / never | `SatisfyCondition` | The registered Auths contract rejected or classified this bounded operation. |
| `github.executor-audience-mismatch` | `execute` | notapplied / never | `CorrectConfiguration` | The registered Auths contract rejected or classified this bounded operation. |
| `github.repository-mismatch` | `execute` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `github.repository-renamed-or-transferred` | `execute` | notapplied / never | `SatisfyCondition` | The registered Auths contract rejected or classified this bounded operation. |
| `github.issue-mismatch` | `execute` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `github.issue-not-open` | `execute` | notapplied / never | `SatisfyCondition` | The registered Auths contract rejected or classified this bounded operation. |
| `github.base-revision-mismatch` | `execute` | notapplied / never | `SatisfyCondition` | The registered Auths contract rejected or classified this bounded operation. |
| `github.branch-already-exists` | `execute` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `github.pull-request-already-exists` | `execute` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `github.candidate-bundle-malformed` | `verify` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `github.candidate-limit-exceeded` | `verify` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `github.candidate-not-descendant` | `verify` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `github.merge-commit-denied` | `verify` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `github.unsupported-git-object` | `verify` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `github.path-not-allowed` | `verify` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `github.path-explicitly-denied` | `verify` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `github.file-mode-denied` | `verify` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `github.repository-automation-policy-mismatch` | `execute` | notapplied / conditional | `SatisfyCondition` | The registered Auths contract rejected or classified this bounded operation. |
| `github.branch-budget-exhausted` | `execute` | notapplied / never | `SatisfyCondition` | The registered Auths contract rejected or classified this bounded operation. |
| `github.pull-request-budget-exhausted` | `execute` | notapplied / never | `SatisfyCondition` | The registered Auths contract rejected or classified this bounded operation. |
| `github.evidence-missing` | `execute` | notapplied / conditional | `SatisfyCondition` | The registered Auths contract rejected or classified this bounded operation. |
| `github.evidence-stale` | `execute` | notapplied / conditional | `SatisfyCondition` | The registered Auths contract rejected or classified this bounded operation. |
| `github.verifier-configuration-mismatch` | `execute` | notapplied / never | `CorrectConfiguration` | The registered Auths contract rejected or classified this bounded operation. |
| `github.exact-action-mismatch` | `execute` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `github.candidate-substituted` | `execute` | notapplied / never | `CorrectInput` | The registered Auths contract rejected or classified this bounded operation. |
| `github.credential-boundary-failed` | `execute` | notapplied / never | `ContactSupport` | The registered Auths contract rejected or classified this bounded operation. |
| `github.branch-rejected` | `execute` | notapplied / conditional | `SatisfyCondition` | The registered Auths contract rejected or classified this bounded operation. |
| `github.pull-request-rejected` | `execute` | notapplied / conditional | `SatisfyCondition` | The registered Auths contract rejected or classified this bounded operation. |
| `github.delegation-capacity` | `delegate` | notapplied / safe | `RetryExecution` | The registered Auths contract rejected or classified this bounded operation. |
| `github.execution-capacity` | `execute` | notapplied / safe | `RetryExecution` | The registered Auths contract rejected or classified this bounded operation. |
| `github.branch-outcome-unknown` | `execute` | possible / unknown | `ResumeAndReconcile` | The registered Auths contract rejected or classified this bounded operation. |
| `github.pull-request-outcome-unknown` | `execute` | possible / unknown | `ResumeAndReconcile` | The registered Auths contract rejected or classified this bounded operation. |
| `github.workflow-terminal-applied` | `resume` | applied / conditional | `InspectReceipt` | The registered Auths contract rejected or classified this bounded operation. |
| `github.workflow-terminal-not-applied` | `resume` | notapplied / never | `InspectReceipt` | The registered Auths contract rejected or classified this bounded operation. |
| `github.receipt-invalid` | `verify` | notapplied / never | `InspectReceipt` | The registered Auths contract rejected or classified this bounded operation. |
| `mcp.invalid-handler-output` | `execute` | possible / unknown | `ResumeAndReconcile` | The invoked handler returned an invalid or oversized bounded result. |
| `mcp.handler-failed` | `execute` | possible / unknown | `ResumeAndReconcile` | The invoked handler failed without conclusive no-effect evidence. |
| `mcp.handler-timeout` | `execute` | possible / unknown | `ResumeAndReconcile` | The invoked handler did not produce conclusive effect evidence before its deadline. |
| `mcp.cancelled-before-entry` | `execute` | notapplied / safe | `RetryExecution` | Execution was cancelled before the handler was entered. |
| `mcp.reservation-conflict` | `execute` | notapplied / never | `SatisfyCondition` | A different committed request already owns the execution record. |
| `mcp.replay` | `execute` | notapplied / never | `InspectReceipt` | The committed MCP execution has already reached a terminal state. |
| `mcp.receipt-persist-failed` | `execute` | applied / conditional | `ContactSupport` | The effect was observed but its execution receipt was not durably persisted. |
| `mcp.reconciliation-pending` | `resume` | possible / unknown | `ResumeAndReconcile` | The profile still lacks conclusive effect evidence. |
| `plan.member-interrupted` | `execute` | possible / unknown | `ResumeAndReconcile` | The current ordered member may have applied and later members remain blocked. |
| `plan.member-failed-before-entry` | `execute` | notapplied / conditional | `SatisfyCondition` | The current ordered member failed before provider entry. |
| `plan.resume-reference-invalid` | `resume` | notapplied / never | `CorrectInput` | The supplied reference is not bound to this ordered plan execution. |
| `plan.reconciliation-pending` | `resume` | possible / unknown | `ResumeAndReconcile` | The current member remains outcome-unknown and later members remain blocked. |
| `plan.action-substituted` | `execute` | notapplied / never | `CorrectInput` | The current ordered member does not match the approved plan commitment. |
| `custody.denied` | `sign` | notapplied / never | `SatisfyCondition` | The configured custody provider denied the exact signing request. |
| `custody.cancelled` | `sign` | notapplied / never | `SatisfyCondition` | The exact signing request was cancelled before Auths accepted a signature. |
| `custody.throttled` | `sign` | notapplied / conditional | `SatisfyCondition` | The custody provider refused the request under its current rate policy. |
| `custody.unavailable` | `sign` | notapplied / conditional | `SatisfyCondition` | The custody provider could not conclusively service the exact signing request. |
| `custody.revoked-key` | `sign` | notapplied / never | `CorrectConfiguration` | The configured key version is permanently barred from new signing. |
| `custody.disabled-key` | `sign` | notapplied / never | `SatisfyCondition` | The configured key version is not permitted to create new signatures. |
| `custody.provider-unknown` | `sign` | notapplied / conditional | `ContactSupport` | The provider did not prove whether it produced a signature for the exact request. |
| `custody.invalid-provider-response` | `sign` | notapplied / never | `ContactSupport` | The provider response could not be parsed as a bounded signing response. |
| `custody.request-mismatch` | `sign` | notapplied / never | `ContactSupport` | The provider response names a different signing request. |
| `custody.principal-mismatch` | `sign` | notapplied / never | `ContactSupport` | The provider response names a different signing principal. |
| `custody.descriptor-mismatch` | `sign` | notapplied / never | `ContactSupport` | The response signature method or suite differs from the frozen descriptor. |
| `custody.key-version-mismatch` | `sign` | notapplied / never | `ContactSupport` | The provider response names a different key version. |
| `custody.transaction-mismatch` | `sign` | notapplied / never | `ContactSupport` | The provider response is bound to a different Auths transaction. |
| `custody.malformed-signature` | `sign` | notapplied / never | `ContactSupport` | The returned signature is not a bounded encoding accepted by its suite. |
| `custody.non-canonical-signature` | `sign` | notapplied / never | `ContactSupport` | The returned signature has a different canonical representation. |
| `custody.signature-verification-failed` | `sign` | notapplied / never | `ContactSupport` | The returned signature does not verify over the exact Auths preimage. |
| `custody.evidence-mismatch` | `sign` | notapplied / never | `ContactSupport` | The returned evidence does not match the frozen custody descriptor. |
| `custody.lifecycle-not-permitted` | `sign` | notapplied / never | `SatisfyCondition` | The exact key lifecycle state does not permit new signatures. |
