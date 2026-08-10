# Define an opaque bounded-byte transport port

Status: scratch design note

## Goal

Make identity and application data portable across Iroh, HTTPS, IPC, files, memory, and caller-owned transports without rewriting the protocol orchestration or importing authority semantics.

## Problem

`auths-iroh` is semantics-free, but applications still construct Iroh endpoints and call Iroh-specific channel methods. Removing Iroh is possible; swapping it is not plug-compatible.

The existing proof-exchange port is intentionally semantic. It models challenge, submission, and response, so it is not an appropriate dependency for identity or arbitrary data exchange.

## Target port

The neutral port should describe only the minimum behavior needed to move bounded bytes:

```text
identity / application protocol
             |
             v
     bounded byte channel port
       /      |       |      \
    Iroh    HTTPS    IPC    custom
```

Candidate responsibilities:

- send one non-empty bounded frame;
- receive one non-empty bounded frame;
- finish the send side;
- report an opaque authenticated-peer observation when the transport has one;
- report transport, timeout, sequence, and limit failures without inventing application meaning.

## Design requirements

1. The port contains no Iroh, HTTP, identity, proof, capability, or approval types.
2. Resource limits and timeouts are caller-selected and explicit.
3. Peer observations are opaque facts, not Auths identities.
4. Protocol code owns ALPN, routes, media types, and message sequence.
5. Adapters cannot manufacture authentication or authorization results.
6. The port supports transports without mutually authenticated peers.
7. Applications may implement the port locally without publishing an adapter.

## Non-goals

- Creating a universal networking framework.
- Hiding every transport feature behind the lowest common denominator.
- Treating TLS, Iroh endpoint identity, or socket credentials as an Auths principal automatically.
- Replacing the semantic proof-exchange state machine.

## Migration

1. Extract the smallest interface from the identity/Iroh demo's actual exchange.
2. Implement the port for `auths-iroh`.
3. Implement one simple memory or local-stream adapter as proof of substitution.
4. Run the same identity exchange conformance test over both.
5. Let the proof-exchange Iroh adapter consume the same byte transport where it improves reuse.

## Acceptance criteria

- The identity demo selects Iroh through a port rather than importing Iroh types in protocol orchestration.
- The same identity exchange test passes with two transport implementations.
- No generic byte transport crate depends on proof or authority packages.
- Replacing a transport changes construction code, not protocol state or identity code.
