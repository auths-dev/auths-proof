# ADR 0006: Networking Is a Proof-Exchange Port

**Status:** Accepted

## Context

Auths proofs will be used across Iroh, HTTPS, TLS/TCP, local sockets, message
buses, and test harnesses. Iroh is particularly attractive because applications
can dial stable public-key endpoint identifiers while Iroh handles discovery,
NAT traversal, encrypted QUIC connections, and relay fallback.

There are two risks:

1. adding Iroh or async networking to the pure verifier would destroy its
   deterministic offline and WASM boundary;
2. treating a transport key as an Auths principal would conflate authenticated
   connectivity with delegated authority.

A generic socket trait would avoid a direct Iroh dependency but would still be
the wrong abstraction. It would reproduce low-level networking concepts
without expressing the challenge, proof submission, replay, and peer
observation semantics that Auths applications actually need.

## Decision

Networking is represented by a semantic proof-exchange port in a separately
versioned integration repository.

```text
auths-proof kernel
        ^
proof-exchange state machine
        ^
Iroh | HTTPS | TLS/TCP | Unix | in-memory
```

The port owns:

- challenge negotiation;
- bounded action-body and `ProofBundle` submission;
- typed transport peer observations;
- exchange framing and sequencing;
- separation of transport, exchange, verdict, and application outcomes.

The port does not own generic sockets, Auths authority semantics, replay
storage, action execution, key custody, relay infrastructure, or application
policy.

Iroh is the first reference network adapter. An in-memory adapter is built
first for deterministic conformance. Other transports are added only for real
consumers.

An Iroh `EndpointId`, TLS certificate, Unix peer credential, or other
transport identity is not automatically an Auths `PrincipalRef`. Applications
that require channel binding commit the relevant endpoint identifier into the
signed action profile and compare it with the peer observed by the transport.

Iroh endpoint keys and Auths signing keys remain separate by default.

The `auths-proof` wire format, verifier, and principal adapter API contain no
Iroh or transport-specific type, branch, feature, or dependency.

## Consequences

### Positive

- `auths-proof` remains deterministic, offline, `no_std`-compatible, and
  independently auditable.
- Iroh can provide key-addressed connectivity without defining authorization.
- The same proof can be exchanged over Iroh, HTTPS, local IPC, or fixtures.
- Transport authentication strength remains visible instead of being flattened
  into a boolean.
- Transport failures cannot be confused with `Denied` or `Indeterminate`.
- Channel binding is explicit, signed, and application-reviewable.

### Negative

- The companion integration requires its own protocol version, fixtures,
  replay store, async runtime, and security review.
- Applications must configure both Auths trust and transport policy.
- Separate transport and Auths keys add operational key-management work.
- Some adapters cannot offer equivalent peer observations, so applications
  cannot assume that all transports are interchangeable for channel policy.

## Rejected alternatives

### Put Iroh in `auths-proof`

Rejected because networking, async execution, discovery, and relay behavior
are outside deterministic authorization verification.

### Define a generic byte-stream port in the kernel

Rejected because it abstracts at the wrong level and encourages networking
dependencies and lifecycle concerns to leak into the verifier.

### Make Iroh mandatory

Rejected because Auths proofs must remain portable and useful in ordinary
HTTPS, offline, browser, local IPC, and audit workflows.

### Treat an authenticated endpoint as authorized

Rejected because proving possession of a transport key does not prove that
authority was delegated for the exact application action.

### Reuse one key for transport and Auths by default

Rejected because the purposes, supported algorithms, custody requirements,
rotation schedules, and compromise consequences differ.

## Follow-up

The companion implementation must follow the versioned
`auths-proof-exchange/spec/v1/protocol.md` specification. The core repository
keeps only a pointer at `spec/v1/networking.md`. The first implementation
contains:

1. a transport-independent exchange state machine;
2. an in-memory conformance adapter;
3. an Iroh adapter using a versioned ALPN;
4. one exact MCP tool-call demonstration in a separate application repository.
