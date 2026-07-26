# Contributing

Read `spec/v1/mcp-tools-call.md` and `docs/architecture.md` first. Keep the
application narrow: one canonical immediate MCP `tools/call` profile.

Run:

```sh
cargo run -p xtask -- release-check
cargo deny check
```

Profile changes require exact canonical fixtures, native/WASM comparison,
replay and permission-confusion negative tests, and a version decision. The
service must depend on the semantic exchange port, never a concrete transport.
Transport authentication must never substitute for an Auths authorization
verdict.
