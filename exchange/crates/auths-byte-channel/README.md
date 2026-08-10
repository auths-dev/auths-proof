# auths-byte-channel

`auths-byte-channel` is a transport-neutral port for moving non-empty, bounded,
opaque byte frames under caller-selected deadlines.

Security claim: implementations must enforce the declared frame and time
bounds, preserve frame bytes, and expose transport peer facts only as opaque
observations.

It does **not** decode identity or proof data, authenticate an Auths identity,
create authority, grant a capability, or approve an action. A transport-
authenticated endpoint is not automatically an application identity.

```rust
use auths_byte_channel::ChannelLimits;
use std::time::Duration;

let limits = ChannelLimits::new(64 * 1024, Duration::from_secs(5))?;
assert_eq!(limits.max_frame_bytes(), 64 * 1024);
# Ok::<(), auths_byte_channel::ChannelConfigurationError>(())
```

The port is versioned `1.0.0-rc.1`, has an MSRV of Rust 1.91, and currently
requires `std` for asynchronous I/O and deadlines.
