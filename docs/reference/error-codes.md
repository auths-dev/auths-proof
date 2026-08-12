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
| `core.internal-invariant` | `execute` | notapplied / never | `ContactSupport` | Auths rejected an impossible internal state before an effect. |
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
