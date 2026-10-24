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
The operator CLI creates a private company root seed and pinned native trust
template, then signs a one-hour company-to-employee grant for an enrolled
employee. Its seed file stays outside the workbench and agent processes.
The employee can prepare a finite task from the imported Google catalog;
the broker checks each selected file's metadata under that employee's
connection before persisting a review-only descriptor. Preparation does not
activate authority or permit an agent read. The workbench can then present
the exact native child-grant signing preimage and accept the employee's
signature once. The signed grant remains pending until the distinct agent signs
an exact activation action and the broker verifies the complete company-rooted
proof under the operator-pinned trust context. The activation challenge is
one-use, and invalid signatures consume it. An active task can now export a
credential-free proof package to the employee. The separate agent package
chooses approved file IDs with a model, authors an exact signed action through
the public Auths API, and sends it to the broker's proof-only read route. The
broker rebuilds the expected proof from its own stored grant chain before the
native verifier admits a read and signs a receipt.
It is **not yet a runnable live Google demo**. The workbench now shows
employee-scoped task status, remaining limits and verified receipt JSON;
deployed broker/agent isolation and the installation kit are still absent. The
`demo_co` has published provisional versioned schemas and local-mode examples,
but no independent live Google probes. The importer validates the exact pinned
schema and operator commitments; a local fixture still produces
`not_configured` and cannot activate provider reads.

The broker and agent require an installed `auths` wheel with the new
`mcp_body_digest`, `mcp_signed_action_from_proof` and raw-key authority APIs.
`versions.lock.json` records the current SDK version and leaves the
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
The browser review flow uses a non-exportable Ed25519 employee key stored in
that browser's IndexedDB, keyed by the signed-in Google subject. Clearing the
browser profile removes access to that key. The workbench returns the native
identity signing preimage for enrollment and agent registration; the agent
CLI signs its preimage outside the browser. The review screen shows the exact
provider file IDs, task commitment, expiry and limits before the employee
signs. Package export, revocation and receipt verification are employee-scoped
routes. Agent execution still happens in the separate process.

```sh
auths-google-read-workbench --state-db /path/to/private/broker.sqlite3
```

After employee enrollment, an operator can create a private directory and run:

```sh
auths-google-read-operator init-root --seed-file /private/operator/root.seed \
  --trust-file /private/operator/trust.json --company atlas-studio
auths-google-read-operator issue-employee --seed-file /private/operator/root.seed \
  --trust-file /private/operator/trust.json \
  --state-db /private/broker.sqlite3 --binding-ref BINDING_REF
```

The trust file is an operator pin. Protect both files with `0600` permissions
inside a `0700` directory. The CLI refuses to overwrite either file.

`demo_co` owns provider provisioning, fixture ACLs, baseline probes and
versioned export production. The checked-in schemas and examples under this
demo are immutable consumer snapshots; update their hashes in
`versions.lock.json` after reviewing any producer change. The Auths importer
does not follow service endpoints or credential references from the bundle.

The agent is installed and run in a separate environment. Its key file is
private (`0600`); `init-key` prints the public principal and identity packet
needed for employee registration. The employee exports an active task package
from `GET /api/v1/tasks/{task_id}/package` using their browser session. That
package has public grants and call descriptors, never Google tokens. The agent
needs a broker loopback origin and its own model API key. Its selected document
text is sent to the configured model provider for summarization, so only
synthetic demo content should be used until that data path is reviewed.

```sh
auths-google-read-operator init-receipt-key --key-file /private/operator/receipt.seed
auths-google-read-agent init-key --key-file /private/agent/agent.seed
auths-google-read-agent run --key-file /private/agent/agent.seed \
  --package-file /private/agent/task.json --broker-origin http://127.0.0.1:8080 \
  --model YOUR_APPROVED_MODEL
```

The workbench receives `--receipt-key /private/operator/receipt.seed` in
live mode. The agent key and model API key must not be mounted into the broker;
the broker vault, receipt key and operator root must not be mounted into the
agent. The current local test injects a fake provider and fake model; it does
not claim live Google or model acceptance.
