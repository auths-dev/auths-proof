# auths-byte-channel-memory

`auths-byte-channel-memory` is the reference in-process adapter for
`auths-byte-channel`. It is useful for application tests and for proving that
protocol orchestration does not depend on a network implementation.

Security claim: it preserves opaque frame bytes and enforces the neutral port's
frame, timeout, and send-sequence contract.

It does **not** authenticate peers, provide durable delivery, cross a process
boundary, interpret identity, or establish authorization.

```rust
use auths_byte_channel::{ChannelLimits, PeerObservation};
use auths_byte_channel_memory::MemoryByteChannel;
use std::time::Duration;

let limits = ChannelLimits::new(1024, Duration::from_secs(1))?;
let (_left, _right) = MemoryByteChannel::pair(
    limits,
    PeerObservation::Unauthenticated,
    PeerObservation::Unauthenticated,
);
# Ok::<(), auths_byte_channel::ChannelConfigurationError>(())
```

The adapter is versioned `1.0.0-rc.1`, has an MSRV of Rust 1.91, and requires
`std` and Tokio.
