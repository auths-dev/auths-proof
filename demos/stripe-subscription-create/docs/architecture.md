# Architecture

```text
browser -> native API -> Stripe catalog + invoice preview + test clock
        -> exact Auths proof -> create-only bounded evaluator
        -> atomic active-slot + finite-term + first-invoice reservation
        -> exact claim -> subscription-create credential
        -> critical re-preview -> one idempotent Subscription create
        -> invoice/subscription observation -> canonical receipts
```

The subscription policy carrier and liability store are family mechanics.
Creation still owns its action, evaluator entry point, verified command,
gateway, transition kernel, credential scope, and receipt union. No operation
tag dispatches modify or cancellation behavior.

Unknown delivery retains every exposure. Reconciliation retrieves a recorded
Subscription ID or finds exactly one Subscription with the fixed
`auths_workflow_id`; it never repeats creation.
