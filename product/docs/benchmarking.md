# Milestone 4 Measurements

These measurements answer the foundation's initial questions; they are not a
formal benchmark suite or production latency promise.

## Fixture

- canonical MCP body: `reports/read_report` with `{"name":"q3"}`;
- authority: rotated `did:keri` root delegating to a raw P-256 agent;
- proof size: 1,988 bytes;
- successful memory and Iroh runs produce the same request ID and result;
- build: optimized Rust `1.94.0`;
- host: Apple M1 Max, arm64 macOS 27.0;
- browser: Chrome 150.

## Observations

| Path | Total call | Auths verification | Notes |
|---|---:|---:|---|
| In-memory | 543 µs | 454 µs | Challenge, verification, and static execution |
| Iroh direct, local | 30.489 ms | 505 µs | Includes endpoint connection and exchange |
| Browser WASM | n/a | 1.320 ms mean | 100 verification iterations |

Execution rounded below one microsecond in both native demos. The Iroh result
is a local direct path and says nothing about relay or wide-area latency.

## Reproduce

```sh
cargo run -p xtask -- fixtures
cargo run -p auths-mcp-demo --release -- demo --transport memory
cargo run -p auths-mcp-demo --release -- demo --transport iroh
```

The browser benchmark is:

```sh
cargo test \
  -p auths-lab-wasm-bench \
  --release \
  --target wasm32-unknown-unknown \
  -- --nocapture
```

Configure `CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER` with a compatible
`wasm-bindgen-test-runner`, set `WASM_BINDGEN_TEST_ONLY_WEB=1`, and provide a
Chrome-compatible `CHROMEDRIVER`.

The fixture generator is deterministic. Any regenerated fixture diff requires
review because it changes the exact bytes being compared across native and
browser verification.
