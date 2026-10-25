# Employee-to-agent Google read delegation

Implementation work for [AP-SPEC-070](../../docs/specs/0070-google-employee-agent-delegation-demo.md).

## Current stage

This checkout contains the task/read contracts, native exact MCP verification
bridge, native child-grant planning, durable SQLite admission and release gate,
and a strict `demo_co` artifact importer. OAuth state/validation, encrypted
token custody, key-possession employee enrollment and a closed Drive GET
adapter, generation-checked refresh and employee offboarding are present as
broker components. A broker-signed private read receipt records release observations.
The broker reserves the worst-case metadata plus content response bytes for
every admitted call in SQLite, retaining charges on refusal or ambiguous
fetches. A separate-process test checks shared admission limits.
The Drive adapter also measures GETs started and response bytes read for the
signed broker receipt. Each fixed Drive GET also gets a durable SQLite attempt
row before dispatch, updated as bytes arrive. Those observed counts are
distinct from the durable worst-case reservation; a crash can leave a
`started` attempt with an unknown outcome. The workbench holds an exclusive
OS lock on its broker database. On restart, after acquiring that lock, it
marks predecessor claims abandoned and reopens their in-flight slots without
refunding call, attempt or byte charges. The started provider attempt remains
an unknown outcome. Only the lock-holding workbench may dispatch reads from
that database.
Each Drive GET now has a 15-second total deadline, capped by task expiry.
DNS waits use bounded daemon resolver slots; connect, TLS, headers and every
body read use only the time remaining on that deadline. A timed-out read is
refused and retains its conservative admission charges.
Successful release commitment and the signed read receipt share one SQLite
transaction. A failed receipt insert rolls back the release; actual HTTP
delivery remains a separate unknown stage.
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
employee-scoped task status, remaining limits and verified receipt JSON.
Hosted CI has built the installed broker and agent images and exercised their
Compose route, network and mount boundaries; registry publication and live
deployment acceptance remain pending. The
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
pass operator-reviewed `--connections`, `--access-expectations`,
`--google-verification`, `--pins` and `--scenario-result` paths. The pin file
must include the exact `google_verification_sha256` for a live import. The
optional `--oauth-config` file contains
`client_id`, `client_secret`, the exact loopback origin `redirect_uri` (for
example, `http://127.0.0.1:8765` for a Desktop OAuth client), and
`hosted_domain`; `--fernet-key` points to a separate private encryption key
file. Both operator secret files must have mode `0600`. The workbench binds
only to `127.0.0.1`.
An operator can prepare a private pin candidate after copying one immutable
`demo_co` generation. Enter the company, instance, definition, dataset and
Google tenant values from the reviewed setup record, independently of the
export being pinned:

```sh
auths-google-read-operator propose-pins \
  --connections /exports/connections.json \
  --access-expectations /exports/access-expectations.json \
  --google-verification /exports/google-verification.json \
  --scenario-dir /exports/scenarios \
  --company atlas-studio --instance INSTANCE_ID \
  --definition-hash DEFINITION_SHA256 --dataset-version DATASET_VERSION \
  --google-customer-id CUSTOMER_ID --google-primary-domain DOMAIN \
  --out /private/operator/pins.json
```

The output directory must be private (`0700`); the command creates a new
`0600` file and refuses to overwrite one. Review its digest list and source
generation before passing it to the workbench. A local export can produce a
candidate but cannot activate Google; a live candidate requires the pinned
verification file and independent scenario results to pass import checks.
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
auths-google-read-operator offboard-employee --state-db /private/broker.sqlite3 \
  --company atlas-studio --binding-ref BINDING_REF \
  --oauth-config /private/operator/oauth.json \
  --fernet-key /private/operator/fernet.key
```

The trust file is an operator pin. Protect both files with `0600` permissions
inside a `0700` directory. The CLI refuses to overwrite either file.
Offboarding disables the employee binding, all linked tasks and credentials,
and signed-in browser sessions in one broker transaction. A later Google login
for that disabled binding is refused until a deliberate new enrollment policy
is defined. The command makes no Google network call; provider grant revocation
is a separate operator action whose propagation must be measured.

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
The agent prints a JSON result. The employee can load that file in the browser
workbench; it checks each cited source against the employee-scoped broker
receipt, shows the task limits and stages, and displays the summary as
agent-reported text. This import does not turn the summary into signed evidence.

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

## Container isolation layout

`compose.yaml` separates the broker, browser relay, agent relay, model relay
and agent. The browser relay alone publishes `127.0.0.1:8765`. The agent's
only network is `agent_private`, with the agent relay and model relay. The
agent relay forwards only POSTs for challenge issuance and exact proof calls;
it cannot reach browser, session, operator or receipt routes through its
configuration. The model relay forwards only POST `/v1/responses` to
`api.openai.com` with TLS verification. The broker's state mount is absent
from the agent. No container receives the Docker socket or a `demo_co`
administrator mount.

The Compose file requires operator supplied **digest-pinned installed broker
and agent images** (`AP070_BROKER_IMAGE`, `AP070_AGENT_IMAGE`), the host runtime
UID/GID, a private broker state directory, a private agent directory, a model
key file and an approved model ID. The Nginx relay image is pinned in
`versions.lock.json`. CI has built matching broker/agent images from an
installed branch wheel; publish and pin their registry manifests and the
matching SDK artifact before this becomes an installation kit. Compose
validation and relay syntax checks alone do not prove runtime isolation.
The installed-image workflow now uploads a source-free **candidate** operator
kit tarball and the exact Linux SDK wheel built for the same commit, each with
SHA-256 checksums. The kit contains Compose files, relay configuration, the
current lock file, acceptance template and a `REVISION` file. Verify the
downloaded tarball checksum, extract it, then verify its internal `SHA256SUMS`
from inside `google-read-operator-kit/`. Its self-contained
[operator guide](operator-kit.md) is packaged as `README.md`. This candidate is not install-ready:
`versions.lock.json` still has empty SDK artifact and broker/agent registry
digest fields. A fresh operator host must receive reviewed digest-pinned
images and an updated lock file before running Compose; it must not build
the source checkout to fill those fields.
The [synthetic isolation probe](evidence/isolation-synthetic-2026-10-24.md)
records actual Docker network, mount and route observations with a mock broker.
The installed-image probe below supersedes that synthetic result for built
image isolation, while live acceptance remains unrun.
Use the [live acceptance record template](evidence/live-acceptance-template.md)
for the exact-revision operator walkthrough once the dedicated Google tenant
and independent `demo_co` probes are ready. Every unrun case remains pending.

`Dockerfile` is the image recipe. The image builder must place exactly one
Linux-compatible `auths-0.0.1rc1-*.whl` in `artifacts/` and supply its reviewed
SHA-256 as `AUTHS_WHEEL_SHA256`. The Dockerfile verifies that digest, builds
the broker or agent's pure-Python wheel, downloads dependency wheels, then
installs only wheels into the runtime stage. Runtime images contain neither
the demo source tree nor a Rust build toolchain. Build each role separately:

```sh
docker build -f Dockerfile --build-arg AP070_ROLE=broker \
  --build-arg AUTHS_WHEEL_SHA256="$AUTHS_WHEEL_SHA256" -t auths-google-read-broker:local .
docker build -f Dockerfile --build-arg AP070_ROLE=agent \
  --build-arg AUTHS_WHEEL_SHA256="$AUTHS_WHEEL_SHA256" -t auths-google-read-agent:local .
```

The wheel must contain the AP-SPEC-070 native APIs from this branch; the
published version number alone does not establish that. Build/publish the
images from reviewed CI artifacts, record their registry manifest digests in
`versions.lock.json`, and set `AP070_BROKER_IMAGE` and `AP070_AGENT_IMAGE` to
those digest references. The developer image build downloads third-party
dependency wheels; pin and review its resulting image digest before handing
it to an operator. [Hosted CI run 40138190022](https://github.com/auths-dev/auths-proof/actions/runs/40138190022)
built both roles from a matching branch-built Linux SDK wheel and verified
their installed entry points and absent source trees. A later
[installed-container CI probe](evidence/isolation-installed-ci-2026-10-24.md)
also exercised the Compose route, network and mount boundaries with those
images. CI did not publish registry images or run a live Google scenario, so
the registry digest fields remain empty.

The tag-only [publication workflow](../../.github/workflows/google-read-demo-publish.yml)
is prepared for a reviewed `ap070-v*` tag. It rebuilds the matching SDK wheel
and both installed images from that tagged commit, pushes the images to GHCR,
reads back their registry manifest digests, and packages a source-free release
kit with those digest references and the exact wheel hash. A separate job
unpacks the release artifact without a source checkout. No release tag has
been created and this publishing path has not yet run; the current kit is
still a candidate. The release packager is dry-run checked with synthetic
digest references in the installed-image workflow, but those references are
never uploaded as an installable artifact.

For live Google mode, add `compose.live.yaml`. It mounts only the broker's
operator files and accepted export directory. The export directory must hold
`connections.json`, `access-expectations.json`, `google-verification.json`
and a `scenarios/` directory
with `scenario-result-*.json` files in the same order as the operator's digest
pins. The broker's OAuth redirect remains exactly
`http://127.0.0.1:8765`; its all-interface bind is
permitted only inside Docker behind the relays. The agent key and package
remain in its own read-only mount, and its model key is mounted only into the
agent. Model selection and summarization send selected synthetic document
content through the model relay to OpenAI; that data leaves the Mac.
