# Architecture

The direct-response hot path is:

```text
signed event -> exact action -> Auths proof -> bounded evaluator
             -> atomic reservation -> decision receipt -> {"approved":bool}
```

It requests no Stripe credential and makes no provider call. Reconciliation is
a separate read-only boundary with the
`PurchaseAuthorizationCredentialScope` type. Purchase receipts are a closed
family and do not add variants to the merchant or subscription receipt types.

Unknown response delivery keeps aggregate capacity held until a later captured,
reversed, or expired observation releases or commits it.
