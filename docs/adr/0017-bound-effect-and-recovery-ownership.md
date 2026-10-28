# ADR 0017: One bound effect and gateway recovery owner

- Date: 28 October 2026
- Status: Implementation decision for AP-SPEC-074; evidence gates remain open

The gateway already owns production provider writes. AP070 separately decides
read admission, release and conservative accounting in Python/SQLite. The
lifecycle package has useful preparation and durable-acknowledgement contracts,
but its profile states include partial effects and proven non-effect with
different recovery semantics. None can be treated as interchangeable merely
because each has a journal.

Keep pure managed transitions in `auths-gateway-kernel::transition`, orchestration
in `auths-gateway::submit`, and the logical journal in `auths-gateway::store`.
Extend those owners; do not introduce a parallel executor or task ledger.
`auths-stores` implements durable PostgreSQL mechanisms. The existing file
adapter stays beside the gateway until moving it has a concrete dependency
benefit. Store adapters never decide provider truth or refund policy.

The gateway owns the canonical bound effect, built from the native sealed action
and closed recipe output. It includes selected branch/evidence identity, trust,
scope, installation, typed charges and protocol. Exact approval signs that
identity after compilation; the signature is not an input to its own identity.
The stored effect is data. Only a successful new durable entry transition yields
a non-cloneable, non-deserializable, consumed transport capability.

Retain lifecycle identity/commitment helpers only where their exact contract
matches. `PreparationBindingV1` is not reused as the effect: its optional
connection/evidence and single principal do not encode disclosure/source/channel,
selected native branches, exact compiler output or typed reservation units.
`ProviderCallAuthorizationV1::from_durable(&DurableTransitionV1)` illustrates
acknowledgement validation but a borrowed acknowledgement can be reused. AP074
must consume the newly applied acknowledgement exactly once. Do not change
reference consumers' lifecycle meaning to make these APIs fit.

The extraction is limited to identity preservation, finite typed reservation
arithmetic, single grant and immutable evidence. This is a domain-independent
product mechanism; the smaller-than-three-production-consumer exception is
justified by these exact properties, not inferred provider similarity. Provider
result interpretation remains in closed reviewed recipe declarations and
independent references. The [comparison case](../research/domains/abstraction-cases/0009-bound-effect-and-recovery.md)
defines divergences and the evidence still required before promotion is complete.

File and PostgreSQL admission must order configuration/revocation with entry.
Read-and-CAS of just the attempt does not fence a concurrently changed connection.
The transaction derives current state, samples the deployment clock after lock
acquisition, validates full native authority and pinned dependencies, and commits
the grant and charges before acknowledgement. A committed revocation blocks later
grants; an earlier grant may still be exercised. Process-local in-flight counters
alone do not establish the multi-process order.

Acquisition, disclosure and mutation are closed typed alternatives. Ancillary
credential/account/preflight/observation reads are linked bounded acquisitions.
Each disclosure has its own recipient authority, source binding and charge.
An ACK records recipient evidence and never creates another delivery grant.
State-match observation may coexist with unknown causation.

Cut over directly and reject obsolete disposable journal formats. No legacy
decoder, conversion, dual-write path or compatibility switch. Preserve rollback
floors and PostgreSQL transaction rollback; these are current safety semantics.
Retain reference implementations and original formal evidence only with accurate
scope. Acceptance requires A01–A22, updated source-linked proofs and hosted CI;
this ADR itself is not evidence that those gates passed.
