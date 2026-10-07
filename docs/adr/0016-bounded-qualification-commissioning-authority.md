# ADR 0016: Bound the first qualification run with explicit commissioning authority

**Status:** Implementing. The closed permit, commissioning-only signer purpose,
offline evidence closure, pure signature/binding verifier, atomic permanent
budget, retained host floors and authenticated private operator commands are
implemented. The first offline root ceremony and separate public signer
certificates are pinned. Protected family references/workflows and actual live
evidence remain required before the bootstrap is resolved.
Ordinary production leases still require qualification.

**Date:** 7 October 2026

## Problem

The shipped gateway requires an exact-tuple qualification before every
production lease. Issuance requires provider effects through that shipped
candidate before it can sign the first qualification. A development file-store
installation or differently compiled test executable changes the tuple, so its
measurements cannot break this cycle. Fabricating an initial qualification,
relaxing ordinary production policy or substituting simulated provider evidence
would invalidate the claim.

## Proposed authority boundary

Introduce a separate, signed, finite qualification-run permit. Its purpose is
authorizing a reviewed commissioning run, not certifying a completed run. The
ordinary application socket continues to require a current qualification.
Only an authenticated private operator session may use commissioning authority;
normal application commands cannot select that session or authority kind.
Both paths must use the same shipped verifier, recipe compiler, reservation,
attempt, credential and provider driver implementations. No test feature,
caller callback, provider module or unverified effect enters the runtime.

The offline qualification root certifies a protected signer with an explicit
commissioning permission. A permit has its own closed schema and signature
domain, reusing the existing canonicalization and Ed25519 implementation. It is
not decoded as a qualification record or listed as a release qualification.
The signer runs separately from the live harness and validates reviewed offline
inputs before signing. The root key never enters a qualification runner.

Every permit must bind:

- the exact candidate commit, executable digest, semantic closure and production
  tuple, including PostgreSQL schema and custody kind;
- the reviewed provider contract, recipe, lock and trusted-context digests;
- one protected workflow run and one ephemeral proof-authoring principal;
- reviewed disposable resource bindings and a precomputed finite set of exact
  canonical action commitments;
- a maximum credential-lease count, stored atomically and durably for the permit
  across both gateway instances and restarts; and
- a signed validity window of at most two hours, current signer certification
  and a current root-signed revocation list.

Resource acquisition, action authoring and independent oracle expansion happen
before permit issuance. Expected request/evidence commitments are derived from
the reviewed reference and bounded resource binding, not candidate answers.
The reference remains test/release code. Runtime permit checks compare closed
identities and commitments; they implement no provider-specific oracle.

A permit never replaces proof verification, grant attenuation, exact approval,
recipe evaluation, critical reads, budget reservation or durable replay claims.
The principal, target, context, action and run must all match. The lease bound
is claimed durably before custody access. Expiry, revocation, exhaustion,
rollback, unavailable shared state or any mismatch refuses before a lease.
Unknown provider outcomes retain ordinary uncertainty and cannot gain a second
write through permit renewal. A denied input is terminal for those inputs.

## Evidence and bootstrap sequence

1. Build and install the exact production candidate with ordinary qualification
   required. Demonstrate that ordinary application requests cannot lease.
2. Acquire only the reviewed disposable resources, author the finite actions,
   expand the independent oracle and finish the candidate's offline evidence.
3. The protected signer validates those inputs and issues commissioning
   authority for that exact run. The authenticated operator imports it.
4. Execute and independently witness the mandatory live cases through the same
   shipped driver, production PostgreSQL and production custody. Persist the
   actual permit, counters, observations, read-backs and redacted evidence.
5. Close and sign a truthful intermediate qualification without claiming
   production readiness. Commissioning authority expires and remains consumed.
6. Import that qualification through the existing verifier. Run ordinary
   production requests and the typed production doctor without commissioning
   authority. Close a fresh final qualification containing those observations.
7. Only verified final qualifications can contribute to stable launch readiness.

The two-hour window is a hard maximum, not a promise that the whole wall fits.
Timeout or incomplete evidence produces no qualification. Cleanup retains
operator authority over its own fixtures and does not create provider evidence.
Renewal cannot reset attempt identities or permit counters.

## Required implementation and rejection evidence

This proposal is incomplete until closed schemas, signer permissions, sealed
runtime authority, durable PostgreSQL accounting, authenticated operator
commands, independent resource/oracle binding and the protected workflow are
implemented together. New state rejects obsolete disposable schemas under the
prelaunch contract; no compatibility reader or hidden policy relaxation is added.

Tests must exercise forged signatures, another root/signer/run/principal,
changed context/action/recipe/target, excessive or empty allowlists, time and
revocation faults, unsupported permissions, exhausted counters, two-host races,
crashes around lease claims, restart/rollback, ordinary application attempts to
use a permit, and failure before credentials. The first actual protected run
must show no ordinary lease before qualification, measured finite commissioned
leases, and ordinary qualified operation after import. CI and the signed evidence
must name the exact shipped candidate. Simulations cannot establish this claim.

The initial artifact implementation keeps its run/family budget key independent
of signature, signer and validity window. Its immutable budget binding commits
to every candidate, principal, context, resource, environment, offline-evidence,
action and ceiling member. A durable registration must refuse a changed binding
at the same key; renewal must consume the original counter. Windows are
half-open, and both the issue-to-expiry and start-to-expiry durations are capped
at two hours. Release certificates carry no commissioning permission;
commissioning certificates carry no attestation or index permission. A
mixed-purpose certificate is refused by the commissioning verifier.

The public synthetic vector is
`bindings/fixtures/qualification/commissioning-v1.json`. Native tests consume
these frozen bytes without issuance code. They cover strict decoding and every
single-bit signature mutation; issuance tests additionally cover purpose/root/
domain separation, exact runtime bindings, time/revocation boundaries, finite
action/lease bounds, evidence omissions and stable renewal identities. These
tests establish the pure artifact boundary only, not durable consumption or a
completed production bootstrap.

The accounting component reuses the existing bounded opaque record store's
insert-once and compare-and-swap operations. `commissioning-budget` is a fifth,
non-expiring record kind in PostgreSQL schema 6. Schema 5 is rejected; disposable
prelaunch databases must be recreated, with no migration or compatibility
reader. The existing lifecycle transition contract remains version 4 because
its transition and receipt semantics are unchanged.

Runtime loading cannot initialize a missing counter. Authenticated fresh setup
registers zero consumption once; a subsequent initialization returns existing
consumption and refuses changed bindings. Every successful claim increments
before custody and is never refunded. The record additionally remembers signer
revocations, the largest accepted revocation sequence and the latest successful
trusted verifier time. A renewed permit cannot reset any of them.

The private session must persist the returned validated snapshot as an
independently retained host floor before custody, including trust updates from
denied attempts. The mechanism refuses database state below that floor. This
does not detect a coordinated rollback of the database and every retained
witness; retaining witnesses outside the restore set is an explicit operator
obligation, as for the existing connection generation floor. Source tests run
the same final-unit race, crash/reopen, renewal, sweep, revocation and restore
cases on file and TLS PostgreSQL stores; the PostgreSQL cases require the
existing protected CI fixture. A property test additionally bounds consumption
over arbitrary accepted/refused input sequences. These tests exercise storage
accounting only and grant no production credential authority.

## Consequences

The private operator interface is `commissioning-init` followed by
`commissioning-submit`. Both require the existing owner-private production
installation and its signed operator attestation. The directory passed with
`--from` contains `commissioning-permit.json`, `signer-certificate.json` and
`revocation-list.json`. `--protected-run` identifies the exact workflow run and
attempt; `--resource-binding` supplies the exact public resource file reviewed
before issuance. A submit additionally names only `--proof` and `--action`.
The root, production tuple, installed context and synchronized clock come from
the installation, with no command-line root or policy override.

The source revision is authenticated by the permit's signature together with
the executable digest that the installation computes from its own running
binary. There is no independently changeable runtime source-commit setting.
The actor commitment is raw SHA-256 of the normalized `PrincipalId` UTF-8
identifier; runtime extracts distinct actors only from the exact action IDs
sealed by native verification and requires exactly one. The action commitment
is the existing `auths.canonical-action.v1` commitment of verified canonical
CBOR; the context and resource commitments are raw SHA-256 of the exact
installed context and reviewed public resource-file bytes respectively.

A host-private lock covers loading the prior witness, the database claim and
atomic witness replacement. Private regular files reject symbolic links,
hard links, different ownership, public modes, oversized bytes and malformed
state. The snapshot and parent directory are synchronized before a claim
returns. A failed acknowledgement burns any database-committed unit. Setup
also records the authenticated revocation sequence without allowing or charging
a credential acquisition. Import persistence merges prior authenticated
revocations under a separate private host lock, so concurrent or stale writers
cannot erase them.

After a capacity/floor commit, the session rechecks current trusted time and
reloads the exact connection generation immediately before custody. Waiting
for storage cannot extend the signed permit window. Ordinary app/admin frames
have no commissioning member or command. The operator's private submission
uses the same translated order driver, native verifier, recipe checks,
reservation, replay, transport and observation implementation; its authority
is selected by the authenticated operator process, never by a proof or frame.

Focused tests use public synthetic authority, frozen native quorum proofs and
counted custody to exercise these boundaries. They establish runtime refusal
and accounting behavior, not protected provider evidence or a completed first
qualification. The first pinned root and public certificates are recorded in
`qualification/trust/ceremony.json`, explicitly as a repository-owner-delegated
technical assessment. Its private root key stays outside the checkout and CI.
No qualification record or release index was issued by this ceremony.

This adds explicit operator commissioning authority and its associated trust
obligation. It does not make the first qualification appear to preexist its own
evidence. Commissioning state remains distinct from `qualified`; readiness
never derives true from a permit. The normal production application gate stays
closed until the existing qualification chain verifies.

## Three-phase corpus and finite first qualification

The installed-client journey exposed a second first-run cycle: an ordinary
client must remain refused until qualification exists. The closed release-only
corpus is therefore version 2, with `offline`, `commissioning` and `live` phases.
The commissioning phase requires PostgreSQL and production custody and cannot
claim production readiness. Its installed-client case must witness a missing
qualification refusal with no lease or provider entry. Private operator effects
still need the complete mandatory wall and fresh read-back.

The resulting first record has a maximum two-hour validity and explicitly
excludes ordinary client success and production readiness. It authorizes the
subsequent ordinary live phase for the same exact tuple. That phase requires
a confirmed installed-client effect and the actual production doctor; a denied
client, a development target or a commissioning doctor cannot substitute.
Assembly reads offline reports and only the selected protected phase. The
contract binds one unchanged manifest containing both phase scopes, so the
first qualification does not require a different recipe, binary or contract.

This sequencing must still be executed by protected jobs and retained as
measured evidence before the first qualification can be claimed complete.
