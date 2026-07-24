# Offline verification example

The normative Milestone 1 example is
`../../fixtures/v1/valid/mixed-ed25519-p256.cbor`.

It contains:

```text
raw Ed25519 root
  -> exact mcp.tools.call / mcp://filesystem/read_file grant
  -> raw P-256 actor
  -> exact action body, audience, challenge, and time
```

Run the `inspect` and `verify` commands from the repository `README.md`.

No resolver, network, database, system clock, or private key is used during
verification.
