# Debugging the identity-over-Iroh demo

- `iroh-unavailable`: the process could not bind or connect a local UDP Iroh endpoint.
- `identity-exchange-failed`: the bounded frame, ALPN, sequence, or codec rejected the exchange.
- `signature-invalid`: expected for the tampered-message experiment; Iroh delivery succeeded but the Ed25519 signature did not cover the received bytes.
- `bad-request`: the browser selected an unknown experiment or sent an empty, control-bearing, or oversized display message.

Run the native service with `cargo run -p auths-identity-iroh-demo` and open
`http://localhost:8080`. The demo requires local UDP sockets.
