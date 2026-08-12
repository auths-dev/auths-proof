# Python integration recipes

## Custody

Implement `auths.framework.Signer` when keys live in an HSM, KMS or remote
signing service. The signer receives a bounded `SigningRequest`, verifies its
declared object kind and transaction digest, and returns the exact signature
and control evidence. Use `auths.testkit.certify_signer` before composition.

The integration owns I/O and credentials. It does not canonicalize Auths
objects, broaden authority or decide whether execution may proceed.

## Atomic reservation

Implement `auths.framework.AtomicReservationStore` when replay and budget state
must survive processes or machines. A reservation must distinguish a new
record, an exact replay and a conflicting record atomically. Use
`auths.testkit.certify_atomic_store` to exercise the contract. The maintained
SQLite adapter is a single-machine reference, not a distributed production
claim.

## Identity transport

Implement `auths.integrations.IdentityTransport` to carry bounded public
identity packets over HTTPS, Iroh, queues or another transport. Call
`exchange_identity` to enforce byte and time limits. Transport success is not
authentication or authorization; pass received identity data to
`auths.identity` for parsing and authentication.

## Qualified effect profiles

Effect-domain integration belongs to a qualified profile. The profile owns
provider request construction, credential timing, outcome classification,
reconciliation and receipts. Do not model a Cloudflare, Stripe, Kubernetes or
database effect as a generic HTTP callback. A new public profile requires
Rust-owned semantics, TypeScript/Python parity fixtures and its own conformance
suite.

## Composition

Use `auths.integrations.development` only for local work. A production
composition provides durable atomic reservation and real custody, then selects
a qualified profile integration. Provider credentials stay behind the profile
gateway and are acquired only after authorization and reservation.
