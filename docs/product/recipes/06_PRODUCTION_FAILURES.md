# Production failures and recovery

The TypeScript and Python SDKs return the same stable outcome kinds and retry
classes. Branch on those fields; never infer authorization from an HTTP status
or provider response.

| Situation | SDK outcome | Retry | Application action |
| --- | --- | --- | --- |
| Authority is too broad, expired, replayed, exhausted, or revoked | `denied` | `never` | Stop and request new authority |
| Trusted evidence or the runtime is temporarily unavailable before a definite effect | `indeterminate` | `backoff` | Retry with bounded backoff |
| Provider entry occurred but the outcome is unknown | `indeterminate` | `reconcile` | Do not repeat the effect; let the operator reconcile |
| A durable workflow can continue safely | `recoverable` | `resume` | Call `resume` with the returned opaque reference |
| Authority or receipt bytes are malformed or cryptographically invalid | `rejected` | `never` | Reject the value and preserve the stable code |

## TypeScript

```ts
const result = await auths.execute(authority, actionBytes);
switch (result.kind) {
  case "completed":
    return result.receipt;
  case "recoverable":
    return (await auths.resume(result.reference));
  case "indeterminate":
    if (result.retry === "reconcile") return queueOperatorReview(result.code);
    return retryWithBackoff(result.code);
  case "denied":
    throw new Error(result.code);
}
```

## Python

```python
result = await auths.execute(authority, action_bytes)
if result.kind == "completed":
    receipt = result.receipt
elif result.kind == "recoverable":
    result = await auths.resume(result.reference)
elif result.kind == "indeterminate" and result.retry == "reconcile":
    queue_operator_review(result.code)
elif result.kind == "indeterminate":
    retry_with_backoff(result.code)
else:
    raise RuntimeError(result.code)
```

Recovery references reveal no workflow identifier, tenant, provider, resource,
or receipt locator. Treat them as bounded secrets: store them durably, disclose
them only to the caller that owns the workflow, and never use their textual
shape as business data.
