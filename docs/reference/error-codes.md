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
| `core.authorization-denied` | `verify` | notapplied / never | `SatisfyCondition` | Available facts prove the supplied proof does not authorize the exact action. |
| `core.authorization-indeterminate` | `verify` | notapplied / conditional | `SatisfyCondition` | A required authorization fact was unavailable, so no decision was reached before any effect. |
| `core.unauthenticated-principal` | `create` | notapplied / never | `CorrectInput` | The request asserts a principal the runtime cannot authenticate, so no authority is issued. |
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
