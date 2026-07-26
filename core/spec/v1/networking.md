# Auths Proof Exchange Companion

The detailed proof-exchange wire protocol and transport conformance profile
are versioned independently in the companion `auths-proof-exchange`
repository:

```text
https://github.com/auths-dev/auths-proof-exchange
```

`auths-proof` retains the architectural rule and authority boundary in
[`docs/adr/0006-networking-port.md`](../../docs/adr/0006-networking-port.md):

> Networking carries proof. It never grants authority.

The kernel and exchange protocol remain independently versioned. Applications
compose both:

```text
auths-proof-apps -> auths-proof
auths-proof-apps -> auths-proof-exchange

auths-proof          -X-> networking, Iroh, async runtimes
auths-proof-exchange -X-> principal methods and authority policy
```

An authenticated transport peer remains a typed observation. It is never
silently promoted into an Auths principal or an `Authorized` verdict.
