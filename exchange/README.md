# auths-proof-exchange

Transport-neutral exchange for Auths Proof Protocol V1.

This repository owns deterministic exchange messages, exact capability
negotiation, bounded framing, typed peer observations, and the memory, Iroh,
HTTPS, TCP, Unix-socket, and offline-file adapters. It carries canonical
application and proof bytes without interpreting grants, choosing trust
anchors, constructing Auths verdicts, or executing commands.

> Networking carries proof. It never grants authority.

The exchange sequence is challenge → one bound submission → response. A
submission repeats the Auths protocol, profile ID/version, and challenge;
every mismatch fails before proof work. Exact negotiation never selects a
different profile version as a fallback.

Applications can depend on the `auths-proof-exchange` facade, select transport
features, call `exchange_one` on the client, and `serve_one` on the server.
Transport-specific crates remain available for advanced configuration.

Transport support:

- memory: deterministic semantic reference;
- Iroh: authenticated endpoint observations and dedicated ALPN;
- HTTPS: server-authenticated client plus framework-neutral service codec;
- TCP: bounded framing and unauthenticated endpoint observations;
- Unix: bounded framing and OS peer credentials;
- file: immutable atomic envelopes plus a sequence- and message-bound
  integrity acknowledgment. The file adapter does not provide confidentiality;
  use an encrypted medium or an approved encrypted envelope where required.

Focused commands:

```sh
cargo xtask arch
cargo test -p auths-proof-exchange-model -p auths-proof-exchange-codec
cargo test -p auths-proof-exchange-testkit memory_adapter_passes_shared_conformance
cargo test -p auths-proof-exchange-testkit file_adapter_passes_shared_conformance
```

Live Iroh/TCP/Unix conformance requires a host that permits local sockets.
