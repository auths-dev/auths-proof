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

The live Atlas setup currently has a Jules employee grant but no complete
versioned Google export. For a separately labelled local smoke, the trusted
broker can use `ExistingDemoCoConsentLease` from
`employee_read_demo.existing_consent_smoke` as the lease source passed to
`GoogleDriveReader`. This temporary adapter requires an owner-only credential
file, exact Atlas instance/customer/Jules pins, the reviewed OAuth client ID,
Jules's Google `sub`, and the Auths task's employee binding, connection
generation, task ID and exact document set. It verifies Google UserInfo
before releasing an in-memory access token to the closed Drive reader. The
grant is not written to Auths's token
vault, passed to the agent or browser, or copied into the operator kit. The
producer must supply Jules's non-secret subject and independent partial probe
evidence before a live run; neither is currently in the versioned export.
This adapter does not activate the workbench importer or count as the normal
broker-owned OAuth journey. It does not request another Drive consent.

The installed `auths-google-read-partial-smoke` command consumes the producer's
owner-only partial report and an independently reviewed SHA-256 pin, its
Desktop OAuth client configuration, and Jules's existing grant file. It writes
one owner-only redacted result inside an operator-private directory:

```sh
auths-google-read-partial-smoke \
  --producer-report /private/operator/google-partial-report.json \
  --producer-report-sha256 REPORT_SHA256 \
  --oauth-client /private/operator/demo-co-oauth-client.json \
  --employee-grant /private/operator/google-person-jules.json \
  --out /private/operator/auths-partial-consumer-result.json
```

It exercises the Auths fixed Drive reader on project A and refuses project B
before credential resolution. The generated descriptor is diagnostic and has
no native employee or agent signature; the result explicitly records this
limit and cannot be used as full delegation acceptance evidence.

For the minimum human-signature demonstration, the separate installed
`auths-google-read-partial-delegation-lab` command accepts the same five
private inputs and `--out` arguments as `auths-google-read-partial-smoke`.
It serves a one-use review page at `http://127.0.0.1:8870/`. The operator
opens that page in Chrome Incognito and signs in to Google as Jules with only
OpenID and email scopes. The lab validates the signed Google ID token's
issuer, audience, nonce, hosted domain and subject against the producer's
pinned Jules subject. It binds the browser session to the signing key and
does not replace the existing Drive grant. The operator then reviews the
exact Jules account, Project A file, excluded Project B file,
agent principal, expiry and byte/call limits, then signs with a fresh,
non-exportable browser Ed25519 key. The broker verifies that signature on a
native employee-to-agent grant. A distinct agent key signs the exact MCP
action; the broker verifies the proof, uses Jules's existing grant for one
live Project A read, checks the result against the producer's independent
hash, rejects a Project B challenge, verifies the receipt, and rejects a new
challenge after revocation. The redacted result is written only to the
operator-private `--out` path. Run this on a trusted local machine with an
owner-only report, OAuth client file, grant file and output directory.

This remains a diagnostic: the agent uses a distinct principal but runs
inside the broker process. The production importer and token vault remain
closed. It does not count as full AP-SPEC-070 acceptance. A complete demo_co
versioned export and an isolated agent run are still needed for that acceptance.

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
  --trust-file /private/operator/trust.json --company atlas-studio \
  --service google-drive-read
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
The service name is pinned by this trust file and used in every reviewed task,
MCP audience and native body digest; it is not derived from the fixture's
company name or from an agent request. The read operation itself remains a
closed Google Drive contract.
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

The manual [publication workflow](../../.github/workflows/google-read-demo-publish.yml)
is prepared for a reviewed exact commit on `main`. It first requires the
repository `cargo xtask release-check` gate, then rebuilds the matching SDK wheel
and both installed images from that commit, pushes the images to GHCR,
reads back their registry manifest digests, and packages a source-free release
kit with those digest references and the exact wheel hash. A separate job
unpacks the release artifact without a source checkout. This publishing path
has not yet run; the current kit is still a candidate. The release gate is
currently blocked because formal mutation evidence predates the changed
formal sources; the separately paused AP-SPEC-069 work must not be silently
resumed to force this demo release. The release packager is dry-run checked with synthetic
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

## AP-SPEC-071 write handoff

The development workbench supports `--jules-only-evidence` and
`--jules-only-pins` alongside a private Desktop OAuth `--oauth-config`.
These are owner-private snapshots of one pinned demo_co write generation;
they let Jules sign in, enroll her browser key and register a separate agent
while the broader six-person company export is unfinished. The workbench
checks the Google login against the pinned Jules subject and disables the
general AP-SPEC-070 task and Drive-consent controls in this mode. Its status
is `jules_write_only`, never full Google company readiness. After enrollment,
the operator issues the native task authority and restarts the workbench with
the installed task-write inputs for the exact review. The existing Jules
`drive.file` grant remains in protected operator custody; this mode does not
request another Drive consent.

This package's AP-SPEC-070 read export does not authorize a Google write.
demo_co now has a separate versioned AP-SPEC-071 Project A folder, working Doc,
Jules `drive.file` consent and independent probe export. The broker's
`validate_write_handoff` pins that export, and the private Jules credential
shim checks the OAuth client, scopes and current UserInfo subject. A read-only
live preflight confirmed that Jules could see the pinned folder and working
Doc before the first edit; its
[redacted observation](evidence/2026-10-25-jules-readonly-preflight.json)
records the exact producer generation and source revision. The checked-in
`auths-google-write-handoff` command is still a deliberately closed installed
entry point: it reports `write_not_configured` and exits 2. It must only open
after the native task authority, agent proof, exact confirmation, gateway
installation and independent effect observation are joined and qualified.
The separate development task workbench can prepare a paired create/populate
review. After an acknowledged managed read, the isolated agent uses
`auths-google-read-agent author-draft` with its private release file, read
package, operation ID, source handle and signing key. An operator transfers the
resulting owner-private `agent-draft.json` and exact release file (as
`agent-source.bin`) into that task's private review directory. Before Jules
sees the plan, the workbench verifies the registered agent signature, task and
acknowledged read, then asks the gateway to compare the staged source with its
keyed commitment to the exact acknowledged release. The comparison emits no
content or plain hash. An acknowledged byte count alone does not establish
this match. The first live Jules edit and independent post-write inspection
qualified the edit path. The paired create/populate path still needs its own
live run.
For a paired create, the operator obtains demo_co's fresh, private
`google write-inspect` observation after Jules's effect plan is recorded, then
uses `auths-google-planned-create` with its exact file SHA-256. The command
checks the producer generation, Project A and Jules pins, and observation age;
it durably records the baseline in the task's private directory before asking
the gateway to enter one planned create. A second invocation refuses, including
after an uncertain gateway result. Inspect the gateway attempt and retain this
same baseline for child reconciliation and demo_co's `create-inspect`; take no
automatic second create. The command does not populate the child. The separate
Jules child preflight and agent-signed population still follow the gateway's
recorded plan and response-derived child binding.
For the next single-plan run, the earlier Auths child is a preserved third
Project A child. Use demo_co's separate `google-create-v2-baseline.json` taken
within five minutes of entry, plus its historical
`google-preserved-blank-observation.json`. Pass `--preserved-blank` and
`--v2-pins` to `auths-google-planned-create`; the latter is an owner-private
JSON object with the exact `CreateV2BaselinePins` fields. It pins the two
producer SHA-256 values and generations, original baseline digest, Jules and
fixture identities, preserved child and marker. The command validates both
hash-pinned schemas, the current exact three-child inventory, historical blank
state, preserved current state, working Doc commitment and time ordering before
durably recording a v2 baseline. It refuses a v2 export without those pins and
never retries a create after an uncertain outcome. The frozen v1 observation
continues to describe the completed first-child run; it cannot authorize a
second create in the now three-child folder.
The browser retains the canonical `effect-plan.json` beside its native proof.
After the gateway binds the returned child and the Jules preflight is recorded,
the isolated agent runs `auths-google-read-agent sign-planned-populate` with its
companion write package, that plan, the private signed preflight report, its
own signed draft and the reviewed populate recipe. The command forms and signs
the exact child, tab, revision and approved text; the gateway independently
rechecks all of them at planned population submission. No operator edits an
agent action JSON or signs with Jules's key.

```sh
auths-google-planned-create \
  --gateway-bin "$GATEWAY_BIN" --gateway-sha256 "$GATEWAY_SHA256" \
  --gateway-state-dir "$GATEWAY_STATE_DIR" \
  --task-dir "$PRIVATE_TASK_DIR" --task-id "$TASK_ID" \
  --write-evidence "$PINNED_WRITE_EVIDENCE" \
  --credential-pins "$PRIVATE_CREDENTIAL_PINS" \
  --baseline "$PRIVATE_WRITE_OBSERVATION" \
  --baseline-sha256 "$WRITE_OBSERVATION_SHA256"
```

If the gateway recorded a create response, bind that same response-derived
child without issuing another create:

```sh
auths-google-reconcile-child \
  --gateway-bin "$GATEWAY_BIN" --gateway-sha256 "$GATEWAY_SHA256" \
  --gateway-state-dir "$GATEWAY_STATE_DIR" \
  --task-dir "$PRIVATE_TASK_DIR" --task-id "$TASK_ID"
```

Then run `auths-google-populate-preflight`, transfer its owner-private report
and the plan to the isolated agent, and stage the agent's `populate.proof` and
`populate.action` in the private task directory. The final operator handoff is:

```sh
auths-google-planned-populate \
  --gateway-bin "$GATEWAY_BIN" --gateway-sha256 "$GATEWAY_SHA256" \
  --gateway-state-dir "$GATEWAY_STATE_DIR" \
  --task-dir "$PRIVATE_TASK_DIR" --task-id "$TASK_ID" \
  --preflight "$PRIVATE_POPULATE_PREFLIGHT"
```

Both effect submissions are one-shot handoffs. A recorded population
`denied` result can be recovered once with `--recover-pre-entry-denial`, after
a new Jules preflight and agent-signed action are staged. The command requires
its original result file and a gateway journal showing the create operation
but no population write claim, then records an exclusive recovery handoff.
An unknown result, missing result file, or any population claim remains
closed; inspect the durable gateway attempt and independent producer state.
These commands remain a development operator path. One later live Jules plan
created and populated a Project A child after a manually checked pre-entry
denial and gateway repair; the new recovery flag was added afterward. See the
[live create record](../../docs/program-log/2026-10-25-ap071-live-create.md).

For a separately reset bounded-upfront edit test, the operator may supply an
owner-private `--task-upfront-choices` JSON file when starting the Jules
workbench. It has schema `auths.ap071-upfront-choices/1` and a `choices` array
of one to four complete profile argument objects. Each Google edit choice
must fix the same selected `document_id`, tab, revision and marker, and may
vary the reviewed `replacement`. The workbench shows every choice on the
human-signed task card and states that no second confirmation will occur.
After an earlier legitimate edit to the working Doc, pin a fresh private
`google-write-observation.json` and its SHA-256 with
`--task-write-current-baseline` and `--task-write-current-baseline-sha256`.
The original pinned write verification still establishes Jules's capabilities;
the later observation supplies only the current content baseline. The broker
checks its fixture identity and digest, then compares that baseline against a
fresh Jules export before showing or submitting an edit. If either differs,
the edit is refused before gateway entry.
The installed task policy must set `allow_bounded_writes=true`; absent this
file, the workbench defaults to exact confirmation. The agent still signs
one complete action, and the gateway admits at most one listed choice. This
development screen has synthetic ceremony coverage. A clean Jules-signed run
used a separate agent and one listed choice; demo_co independently verified the
complete exact after-state. See the
[clean rerun record](../../docs/program-log/2026-10-25-ap071-clean-upfront-rerun.md).
The off-choice, second-write, and exact-confirmation-only policy refusals
remain separate acceptance cases.

See the [AP-SPEC-071 handoff](../../docs/specs/0071-human-agent-read-write-delegation-demo.md)
for the remaining live acceptance path.
