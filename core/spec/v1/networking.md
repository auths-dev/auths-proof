# Auths Proof Exchange Companion

The detailed proof-exchange wire protocol and transport conformance profile
are versioned independently in this repository's exchange layer:
[`exchange/spec/v1/protocol.md`](../../../exchange/spec/v1/protocol.md).

The core layer retains the architectural rule and authority boundary in
[`docs/adr/0006-networking-port.md`](../../../docs/adr/0006-networking-port.md):

> Networking carries proof. It never grants authority.

The kernel and exchange protocol remain independently versioned. Product and
demo packages compose both (`architecture.toml` enforces the layer
direction):

```text
product/, demos/ -> core/
product/, demos/ -> exchange/

core/     -X-> networking, Iroh, async runtimes
exchange/ -X-> principal methods and authority policy
```

An authenticated transport peer remains a typed observation. It is never
silently promoted into an Auths principal or an `Authorized` verdict.
