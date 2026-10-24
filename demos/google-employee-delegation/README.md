# Employee-to-agent Google read delegation

Implementation work for [AP-SPEC-070](../../docs/specs/0070-google-employee-agent-delegation-demo.md).

## Current stage

This checkout contains the task/read contracts, native exact MCP verification
bridge, native child-grant planning, durable SQLite admission and release gate,
and a strict `demo_co` artifact importer. OAuth state/validation, encrypted
token custody, key-possession employee enrollment and a closed Drive GET
adapter, generation-checked refresh and employee offboarding are present as
broker components. A broker-signed private read receipt records release observations.
It is **not a runnable Google demo**. There is no HTTP workbench, agent process,
receipt page or packaged install yet. The
`demo_co` has published provisional versioned schemas and local-mode examples,
but no independent live Google probes. The importer validates the exact pinned
schema and operator commitments; a local fixture still produces
`not_configured` and cannot activate provider reads.

The broker requires an installed `auths` wheel with the new `mcp_body_digest`
native API. `versions.lock.json` records the current SDK version and leaves the
released artifact digest empty until a matching wheel is published. The broker
never loads an adjacent source checkout at runtime. The native extension is the only proof
verifier and source of MCP body digests. The broker's SQLite file must be shared
by all broker workers and private to the trusted broker process. It contains
task and challenge state, not Google content or tokens.

```sh
auths-google-read-doctor
```

`demo_co` owns provider provisioning, fixture ACLs, baseline probes and
versioned export production. The checked-in schemas and examples under this
demo are immutable consumer snapshots; update their hashes in
`versions.lock.json` after reviewing any producer change. The Auths importer
does not follow service endpoints or credential references from the bundle.
