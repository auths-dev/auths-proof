# Auths SQLite atomic reservations

`auths-sqlite` implements the evidence-gated
`auths.adapters.reservations.ReservationStore` v2 contract with SQLite
transactions.
It provides durable first-use, exact-replay, and conflict decisions without
exposing Auths lifecycle or authorization semantics.

An admitted reservation retains its worker until the SQLite transaction settles.
Cancelling the caller only detaches its wait; it does not imply rollback.
`aclose()` stops new reservations and joins all admitted work. Concurrent close
callers share that drain, and cancelling one close waiter does not cancel it.
A successful close means no work from that instance can commit later. `reopen()`
creates a separate instance over the same database.
Admission validates bounded builtin fields and retains immutable copies of
commitment and value bytes before scheduling the worker. Mutating a caller's
bytearray after admission cannot change the reserved record.
