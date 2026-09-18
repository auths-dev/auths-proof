# GitHub Actions OIDC workload journey

The maintained `oidc-workload-live.yml` workflow requests a real GitHub OIDC
token whose audience is derived from an ephemeral Auths raw-key descriptor.
It records only the JOSE member names and claim names; token values and the
ephemeral private key are never persisted.

The deterministic adapter tests exercise the same public construction and
verification boundaries without requiring a GitHub credential. Live evidence
is deliberately acquired outside the effect-free adapter.
