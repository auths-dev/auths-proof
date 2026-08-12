# Auths SQLite atomic reservations

`auths-sqlite` implements the evidence-gated
`auths.framework.AtomicReservationStore` contract with SQLite transactions.
It provides durable first-use, exact-replay, and conflict decisions without
exposing Auths lifecycle or authorization semantics.
