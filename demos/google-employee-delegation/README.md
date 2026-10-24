# Employee-to-agent Google read delegation

Implementation work for [AP-SPEC-070](../../docs/specs/0070-google-employee-agent-delegation-demo.md).

## Current stage

This checkout contains the task/read contracts, native exact MCP verification
bridge, native child-grant planning, durable SQLite admission and release gate,
and a strict `demo_co` artifact importer. OAuth state/validation, encrypted
token custody, key-possession employee enrollment and a closed Drive GET
adapter, generation-checked refresh and employee offboarding are present as
broker components. A broker-signed private read receipt records release observations.
A loopback HTTP workbench now provides server-held sessions, CSRF checks,
Google login/consent callbacks and employee key-possession enrollment routes.
It also registers a distinct agent key through its own one-use challenge,
bound to the active employee enrollment.
Identity possession uses the SDK's `raw-key-v2` packet. The same verified
Ed25519 public key is projected through the native SDK into the target-V1
principal and evidence used by the grant verifier. The employee and agent
keys remain distinct.
The employee can prepare a finite task from the imported Google catalog;
the broker checks each selected file's metadata under that employee's
connection before persisting a review-only descriptor. Preparation does not
activate authority or permit an agent read.
It is **not a runnable Google demo**. Task authorization, the agent process,
receipt page and packaged install are still absent. The
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

The loopback workbench can show honest local prerequisite status without
Google credentials. Its state directory must be private (`0700`), and the
database is created with private permissions. With a live accepted export,
pass operator-reviewed `--connections`, `--access-expectations`, `--pins` and
`--scenario-result` paths. The optional `--oauth-config` file contains
`client_id`, `client_secret`, the exact loopback `redirect_uri`, and
`hosted_domain`; `--fernet-key` points to a separate private encryption key
file. Both operator secret files must have mode `0600`. The workbench binds
only to `127.0.0.1`.

```sh
auths-google-read-workbench --state-db /path/to/private/broker.sqlite3
```

`demo_co` owns provider provisioning, fixture ACLs, baseline probes and
versioned export production. The checked-in schemas and examples under this
demo are immutable consumer snapshots; update their hashes in
`versions.lock.json` after reviewing any producer change. The Auths importer
does not follow service endpoints or credential references from the bundle.
