# Offline verification example

This is a real external consumer crate, compiled by the workspace gate. It
embeds the committed `raw-key-chain` proof, action, and trusted context; binds
the context to the exact executable registry; and calls only the supported
`auths-proof::Engine` façade.

Run it with:

```console
cargo run -p auths-proof-offline-example
```

The verification call performs no resolver, network, database, filesystem,
clock, or private-key I/O. `Indeterminate` is handled as a non-authorizing
result that may become decidable only after the host supplies new trusted
facts.
