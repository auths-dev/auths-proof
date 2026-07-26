# Contributing

Read `spec/v1/protocol.md` before changing code. The governing rule is:

> Networking carries proof. It never grants authority.

Run:

```sh
cargo run -p xtask -- release-check
cargo deny check
```

Wire changes require a protocol-version decision, specification update, golden
vectors, negative tests, and cross-adapter review. Do not add application
policy, principal-method logic, key custody, discovery products, or generic
socket abstractions to the exchange crates.
