# auths-iroh

`auths-iroh` moves bounded opaque byte frames over caller-owned Iroh endpoints
and caller-selected ALPN protocols. It can be used without any Auths identity,
authority, capability, approval, or SDK package.

Security claim: it enforces the selected frame and I/O bounds, checks the
negotiated ALPN, preserves payload bytes, and reports the authenticated Iroh
endpoint only as a transport observation.

It does **not** interpret those bytes, assert that an Iroh endpoint is an Auths
identity, or authorize an application action.

```rust
use auths_iroh::{IrohConfig, StreamInitiator};
use std::{sync::Arc, time::Duration};

let config = IrohConfig::new(
    Arc::<[u8]>::from(&b"/my-team/public-keys/1"[..]),
    64 * 1024,
    Duration::from_secs(5),
    StreamInitiator::ConnectingEndpoint,
)?;
assert_eq!(config.alpn(), b"/my-team/public-keys/1");
# Ok::<(), auths_iroh::IrohError>(())
```

The adapter is versioned `1.0.0-rc.1`, has an MSRV of Rust 1.91, and requires
`std`, Tokio, and Iroh. The application owns the protocol carried in its bytes.
