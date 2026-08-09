# Identity-over-Iroh decoupling spec

Issue: #98

## UX

The primary user is a team that already uses Ed25519 and Iroh and wants an
Auths-compatible public identity without adopting authorization concepts.

The demo is a single browser workbench with three experiments:

```text
+------------------------------------------------------------------+
| auths / identity lab                                             |
| Exchange public keys. Sign a message. No capability setup.       |
|------------------------------------------------------------------|
| [Public identity] [Signed message] [Tampered message]             |
|                                                                  |
| Client identity          real local Iroh          Server identity|
| key:sha256:...       ---------------------->       key:sha256:... |
|                                                                  |
| [Run identity exchange]                                          |
|------------------------------------------------------------------|
| Result: IDENTITY EXCHANGED / SIGNATURE VERIFIED / REJECTED       |
| Iroh peer IDs · public keys · signed bytes · verification facts  |
| Authorization evaluated: NO    Approval required: NO             |
+------------------------------------------------------------------+
```

The successful path must foreground the ordinary integration result: the two
public identities and, when present, the verified application message. The UI
must state that an Iroh connection or valid signature authenticates bytes but
does not authorize an application action.

## Architecture

```text
+----------------------------+
| Browser workbench          |
+-------------+--------------+
              | POST /api/v1/exchanges
              v
+----------------------------+
| Native Axum demo           |
| ephemeral Ed25519 keys     |
+-------------+--------------+
              | real loopback Iroh exchange
              v
+----------------------------+
| auths-identity-iroh        |
| bounded identity protocol  |
+------+------+--------------+
       |      |
       v      v
+----------+ +---------------+
| raw key  | | Ed25519 verify|
+----------+ +---------------+

No dependency edge reaches proof grants, capabilities, approvals, product
runtimes, stores, lifecycle services, or governance packages.
```

`auths-identity-iroh` is one vertical exchange adapter. It owns its bounded
wire message and Iroh sequence rather than extracting a speculative generic
identity-exchange framework. Core continues to own raw-key principal derivation
and Ed25519 verification. The demo owns ephemeral signing keys and browser
presentation.

An architecture boundary lists the only workspace packages reachable from the
identity transport. CI checks the complete transitive workspace dependency
closure, so a future capability or approval dependency fails before build and
test fan-out.

## APIs

### Rust library

- `PublicIdentity::from_ed25519([u8; 32])`
- `PublicIdentity::principal()`
- `PublicIdentity::public_key()`
- `SignedIdentityMessage::signing_preimage(identity, message)`
- `SignedIdentityMessage::new(identity, message, [u8; 64])`
- `SignedIdentityMessage::verify()`
- `IdentityPacket::{PublicIdentity, SignedMessage}`
- `IrohIdentityClient::connect(endpoint, target, config)`
- `IrohIdentityClient::exchange(packet)`
- `IrohIdentityServer::accept(endpoint, config)`
- `IrohIdentityServer::receive()`
- `IrohIdentityServer::respond(packet)`

The signing preimage is domain separated and binds the canonical raw-key
descriptor plus the exact message bytes. Message and frame sizes are bounded.
Malformed, oversized, non-canonical, unknown-version, or invalid-signature
input fails with a typed error. Transport endpoint identity is reported
separately from the exchanged Ed25519 identity and never upgrades it into
authorization.

### Demo HTTP API

- `GET /healthz` returns service readiness.
- `GET /api/v1/status` returns the server public identity and Iroh endpoint.
- `POST /api/v1/exchanges` accepts one closed experiment identifier:
  `public-identity`, `signed-message`, or `tampered-message`.

The response reports both identities, both Iroh endpoint IDs, message bytes,
signature verification, the stable result code, and explicit negative facts:
no authorization evaluation, capability, approval, policy, storage, or
lifecycle subsystem participated.
