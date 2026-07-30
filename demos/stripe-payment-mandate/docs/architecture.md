# Architecture

```text
agent exact request ----+
                        v
trusted browser consent -> canonical consent evidence -> mandate evaluator
                                                   -> capability-slot store
                                                   -> exact claim
                                                   -> scoped credential
                                                   -> SetupIntent create+confirm
                                                   -> retrieval/receipt
```

The mandate action, policy, evaluator, credential marker, capability store,
gateway, service, transitions, and receipt union are profile-owned. The
merchant payment reservation store is not used because mandate capacity is a
counted capability, not money.

Configuration inequality returns before decision persistence, consent
consumption, capability reservation, credential acquisition, or Stripe I/O.
Known failures release the capability slot. Processing, customer action, and
transport ambiguity hold it until exact `SetupIntent` retrieval establishes a
terminal result.
