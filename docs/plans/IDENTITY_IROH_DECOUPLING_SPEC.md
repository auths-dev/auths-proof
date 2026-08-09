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
+---------------------+       +-----------------------+
| auths-identity      |       | auths-iroh            |
| identity bytes      |       | bounded opaque bytes  |
+----------+----------+       +-----------+-----------+
           |                              |
           v                              v
+----------+----------+          +--------------------+
| raw key + signatures|          | Iroh + Tokio       |
+---------------------+          +--------------------+

No dependency edge reaches proof grants, capabilities, approvals, product
runtimes, stores, lifecycle services, or governance packages.
```

`auths-identity` owns the transport-independent identity model, canonical
bytes, signing preimage, and verification. `auths-iroh` owns only caller-bound
ALPN negotiation, framed opaque bytes, timeouts, and peer observations. Neither
package depends on the other. The demo owns their composition, the identity
ALPN, ephemeral signing keys, and browser presentation.

Independent architecture boundaries pin identity to four lower-level core
packages and Iroh transport to zero workspace dependencies. CI checks both
complete transitive closures, so hidden semantic coupling fails before build
and test fan-out.

## APIs

### Rust library

- `PublicIdentity::from_ed25519([u8; 32])`
- `PublicIdentity::principal()`
- `PublicIdentity::public_key()`
- `SignedIdentityMessage::signing_preimage(identity, message)`
- `SignedIdentityMessage::new(identity, message, [u8; 64])`
- `SignedIdentityMessage::verify()`
- `IdentityPacket::{PublicIdentity, SignedMessage}`
- `IdentityPacket::encode()` / `IdentityPacket::decode(bytes)`
- `IrohConfig::new(alpn, max_frame_bytes, timeout, stream_initiator)`
- `IrohChannel::connect(endpoint, target, config)`
- `IrohChannel::accept(endpoint, config)`
- `IrohChannel::send(bytes)` / `IrohChannel::receive()`
- `IrohChannel::finish_send()` / `IrohChannel::finish_send_and_wait()`

The identity signing preimage is domain separated and binds the canonical raw-key
descriptor plus the exact message bytes. Message and frame sizes are bounded.
Malformed, oversized, non-canonical, unknown-version, or invalid-signature
input fails with a typed error. The generic Iroh component never decodes these
bytes and supports either peer initiating a multi-frame exchange. Transport
endpoint identity is reported separately from the exchanged Ed25519 identity
and never upgrades it into authorization.

### Demo HTTP API

- `GET /healthz` returns service readiness.
- `GET /api/v1/status` returns the server public identity and Iroh endpoint.
- `POST /api/v1/exchanges` accepts one closed experiment identifier:
  `public-identity`, `signed-message`, or `tampered-message`.

The response reports both identities, both Iroh endpoint IDs, message bytes,
signature verification, the stable result code, and explicit negative facts:
no authorization evaluation, capability, approval, policy, storage, or
lifecycle subsystem participated.
