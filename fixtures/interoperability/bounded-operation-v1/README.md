# Bounded operation interoperability fixture V1

This directory defines the Auths-owned contract for one synthetic bounded
operation used by external interoperability research.

It is **not** a second Auths wire corpus. Canonical Proof Protocol V1 CBOR
remains exclusively under [`core/fixtures/v1`](../../../core/fixtures/v1).
Files here describe a system-neutral operation, named mutations, and the Auths
boundary expected to observe each mutation. They do not assign equivalent
semantics to another authorization system.

## Scenario

Two synthetic organizations are responding to an incident. Northstar owns a
cloud firewall. EdgeShield operates a response agent. Northstar delegates one
exact firewall rule update to the EdgeShield agent:

- resource: one named firewall rule in `eu-west-2`;
- operation: upsert one deny rule for the documentation-only network
  `203.0.113.0/24`;
- validity: ten minutes;
- delegation depth: one;
- use count: one;
- budget: one provider write;
- approval: two named synthetic approvers; and
- retry identity: one fixed idempotency key.

The payload is the UTF-8 byte sequence stored in
`operation.payload_canonical_utf8` in [`scenario.json`](scenario.json). Its
SHA-256 digest is part of the scenario. A consumer must compare bytes, not
parse and reserialize the JSON string before checking the digest.

## Files

| File | Purpose |
| --- | --- |
| `scenario.schema.json` | Closed schema for the base scenario |
| `case.schema.json` | Closed schema for named mutations and expected boundary observations |
| `scenario.json` | Synthetic bounded-operation input |
| `cases/*.json` | Happy-path and adversarial cases |
| `manifest.json` | Versioned inventory of the fixture set |

## Interpretation

Each case separates three outcomes:

- `authorization`: the pure Auths verification boundary;
- `runtime`: replay, reservation, approval, budget, and lifecycle handling; and
- `execution`: the provider-facing effect state.

This separation is intentional. A replay can contain a still-valid proof while
the runtime rejects a second reservation. A provider timeout can follow an
authorized and reserved command while execution remains unknown. Neither case
should be rewritten as a verifier denial.

Each mutation names a `target` boundary. `presentation` mutates the material
presented for authorization or approval, `trusted-context` mutates an explicit
verifier input, `runtime` supplies a durable-state event, and `provider`
supplies an execution observation. The mutation `path` is relative to that
boundary, not necessarily a JSON Pointer into `scenario.json`.

The case outcomes are Auths expectations only. The `auths-interop` repository
maps the same logical cases into UCAN, Biscuit, macaroons, OAuth/DPoP, Cedar,
OPA, and provider IAM without treating these files as a universal oracle.

## Stability

The fixture identity is `bounded-operation-v1`. Existing files must not be
silently repurposed. A change to actor roles, payload bytes, resource,
authorization bounds, approval policy, or expected outcome requires either:

1. an explicit compatible fixture revision recorded in the manifest; or
2. a new versioned fixture directory when existing observations would change.

All values are synthetic. The IP network is reserved for documentation, the
cloud resource does not exist, and the principal identifiers are test labels.
