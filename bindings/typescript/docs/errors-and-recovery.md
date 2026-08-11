# Errors and recovery

Security decisions are values: `authorized`, `denied`, or `indeterminate`.
They are not exceptions and must be handled exhaustively. Construction and
provider failures throw `AuthsWorkflowError` or `ProviderOperationError`.

Every SDK error exposes a stable family/code or provider kind, operation,
stage, correlation ID when available, retry class, effect state, bounded
remediation, and a redacted causal-code chain. Provider messages, response
bodies, credentials, signatures, keys, proofs, and protocol bytes are never
copied into an SDK error.

| Retry class | Meaning |
| --- | --- |
| `never` | Change the request, configuration, or adapter before retrying. |
| `safe` | No effect is known to have occurred; retry under the application’s backoff policy. |
| `conditional` | Reconcile provider/idempotency state first. |
| `unknown` | Treat the outcome as ambiguous until a domain gateway reconciles it. |

Signer, approval, store, and gateway calls are never retried secretly.
Cancellation before reservation is effect-free. Cancellation after reservation
is recorded as `cancelled`; after execution begins it may become
`outcome-unknown`. `ClosedRuntime` requires an idempotency key, durable state
transitions, and an optional reconciliation port.

Use `diagnoseSdk()` for runtime/ABI/adapter compatibility and
`createSupportBundle()` for deterministic, inert issue evidence. Telemetry
exporter failure never changes a decision or execution result.
