# Auths Decision, Execution, and Audit Receipts V1

Decision receipts record the proof, canonical action, verifier context,
principal-status snapshot, grant-status snapshot, profile, three-valued
decision, stable reason codes, and decision time. Execution receipts are
separate objects that bind a decision receipt ID, non-reusable execution lease,
verified command digest, outcome, optional result digest, and completion time.

The content identifier of either receipt is derived from its canonical
unsigned record. Stored and exported receipts are verifier-attested envelopes:

```text
protocol major
receipt kind
canonical receipt bytes
verifier principal
verification-method identifier
signature-suite identifier
signature bytes
```

The signature preimage has a receipt-kind-specific domain followed by
length-prefixed verifier, method, suite, and canonical receipt bytes. Runtime
signing is an external effect; the runtime never owns the private receipt key.
An unavailable signer produces no partially attested receipt and prevents
execution where receipts are configured fail-closed.

Offline verification has two distinct stages:

1. strict canonical decoding, content-ID checking, and decision/execution
   linkage;
2. signature verification against verifier-local expected identity, key, and
   registered signature suite.

Audit bundles contain the attested decision, linked attested executions, and
sorted disclosed or digest-only artifacts. A redacted artifact retains its
media type and digest. A disclosed artifact must reproduce that digest.
Duplicate identifiers, mutation, non-canonical bytes, excessive collections,
and executions linked to another decision fail closed.

