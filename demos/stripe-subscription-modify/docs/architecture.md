# Architecture

```text
browser -> native API -> active test-clock Subscription + exact preview
        -> exact Auths proof -> modify-only before/after evaluator
        -> atomic positive-delta + proration-debit reservation
        -> exact claim -> subscription-modify credential
        -> critical current-state/preview re-read
        -> one idempotent update with pending_if_incomplete
        -> applied or pending-update observation -> canonical receipts
```

The policy carrier is shared family data. Modification owns its action,
evaluator entry point, verified command, store method, gateway, transition
relation, credential scope, and closed receipt union. No operation tag selects
creation, modification, or cancellation behavior.

`pending_payment` and `outcome_unknown` retain the old liability and every new
reservation. Reconciliation retrieves the exact Subscription and never
resubmits the update. Superseded future liability is released only after the
exact after-item set is observed without a pending update.
