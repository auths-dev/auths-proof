# Airtable exact record updates through the general gateway

The maintained monorepo demo uses a fixed-table, data-only recipe and installed
public Python/TypeScript SDKs. The application has its own signing key and sends
proof/action/exact-approval bytes to the gateway socket. Only the operator and gateway hold
provider credentials. The older field-lab `airtable-cli` app-owned-PAT mode is a
self-hosted reference; its token holder can bypass enforcement.

Every closed fixture action now traverses the public native approval protocol:
the app constructs an exact typed proposal, two of three operator-held manager
identities sign responses, the app collects those public responses and the
gateway verifies the quorum as part of the proof. Manager keys remain in the
root-private operator directory; the app receives no manager or provider secret.
The workbench shows the native review fields and includes insufficient-quorum
and duplicate-response cases. This local simulator is integration evidence, not
a human approval inbox: simulator state or a UI click never authorizes an action.

The operator additionally requests the complete native exact-effect review and
signs its canonical request. Simulation supplies this signature from a separate
operator-only ephemeral development key. The app forwards the approval unchanged;
it holds neither that key nor the private actor used for candidate/recovery reads.
Credential-checking installs stage a candidate, acquire separately authorized
checks, and publish from retained evidence before peers join. Adding the software
observer requires explicit native configuration review and CAS activation.

A write returns `response-recorded` when its HTTP response is retained. Choose
**Separately approve and observe the exact operation** to authorize a distinct
read. Its native report separates original-write facts, read charges and evidence
disposition. Replaying a mutation returns retained facts without a read or write;
unknown outcomes never cause an automatic read, resend or refund.

Live mode never uses the scripted exact-effect reviewer. Startup and each new
recovery read pause for at most ten minutes on an owner-only consent FIFO. In a
separate trusted operator shell, use `docker exec CONTAINER cat REVIEW_PATH` to
read the **entire** `literal-review.txt` and its `literal-review.json` signing
request at the private paths printed by the operator. After
checking its exact destination, units, consequences and signing request, use
`docker exec CONTAINER sh -c 'printf "approve OPERATION\n" > CONSENT_PATH'` with
the exact operation and consent path printed there. The application UID cannot
read or write this private channel. Missing or different consent fails closed.
This is local Docker-operator development custody, not a remote human approval
inbox, independent-human trial or production signing-custody claim.

## Source-free local demo

Download `airtable-gateway-demo.tgz` and its checksum from the **Airtable gateway
demo** workflow for the reviewed commit. Verify the checksum against its trusted
workflow artifact metadata. The archive contains distinct Linux shipping and
simulation gateways, the Python wheel, npm SDK and compiled TypeScript client.
No adjacent repository or compiler is needed.

```sh
sha256sum -c airtable-gateway-demo.tgz.sha256
tar xzf airtable-gateway-demo.tgz
cd airtable-gateway-demo
docker build --platform linux/amd64 -t auths-airtable-gateway-demo .
docker run --platform linux/amd64 --rm --init --name auths-airtable-gateway-demo \
  -p 127.0.0.1:8081:8081 auths-airtable-gateway-demo
```

Open <http://localhost:8081>. Choose **Set exact record to Approved**, then replay,
approval, unsupported value, swapped record, two-gateway race and response-loss controls.
The UI and CLI show actual native gateway results. Their history is unsigned;
**Inspect the evidence** exposes native signed outcome/pre-entry bytes in the
actual gateway audit-bundle format. Missing evidence remains missing.

Default mode is clearly labeled **simulation**. An independent HTTP double
counts real native reads and PATCH entries; it never reaches Airtable. Two
native processes race through one operation store; a third joins the same
connection, trust and configuration with independent custody. Substituting a
fresh challenge is refused under the unchanged installed trust. The web
app runs as UID 62004/GID 62005; private state/root/observer keys remain root-only.
The source recipe is the reviewed Airtable fixture with exactly the fixed
base/table substitutions authorized by the release reference. The shipping
binary cannot redirect provider traffic; only the separately built simulation
binary has the loopback transport feature.

## Exact semantics and recovery

This sets `DemoStatus` to `Approved` or `Pending` on one exact record and writes
an action-derived `auths_echo`. It has no expected-old-value condition, atomic
compare-and-swap, provider idempotency key or exclusive-causation claim. A later
external writer can overwrite it. Matching value alone, or an echo prefix,
does not establish a linked observation.

**Lose PATCH response** actually drops the socket after the provider applies
the write. The result stays unknown while fresh reads lack its value/echo.
The original proof/action replay returns retained history without another read
or PATCH. The recovery UI explicitly requests a new native bounded read proof
and exact approval from the separate operator channel; its tagged native report
retains the original write stage and the independently charged read facts.
There is no automatic recovery or write retry.

**Competing writer** makes a second actual HTTP actor write the same value with
a different echo. Observation cannot confirm the original action, and recovery
never overwrites the other actor. Simulation faults are disabled in live mode.
429, 500, malformed JSON and oversized responses are also measured, with no
transparent retry of an entered PATCH.

A hostile record value cannot escape the fixed table: the native gateway
encodes it as one path segment. This reviewed profile has length constraints,
not an Airtable-ID regex; a safe encoded nonexistent ID may enter a PATCH that
receives 404. That is not a successful effect. The demo does not claim arbitrary
record grants are restricted by an application dropdown.

Numeric/count budget scenarios are **not applicable** to this existing recipe:
it has no numeric argument or count-only policy capability. No dummy spend field
or app-local counter is introduced. Durable operation replay still applies.
The session authority lasts one hour; a new disposable container creates fresh
state. Restarting the gateway inside that session preserves existing claims.

## CLI and private operator controls

```sh
docker exec --user 62004:62005 auths-airtable-gateway-demo \
  /opt/consumer/bin/python /opt/demo/app.py status
docker exec --user 62004:62005 auths-airtable-gateway-demo \
  /opt/consumer/bin/python /opt/demo/app.py submit --experiment exact
docker exec --user 62004:62005 auths-airtable-gateway-demo \
  /opt/consumer/bin/python /opt/demo/app.py export > audit-bundle.json
```

An IPC failure is unconfirmed, never permission to send another PATCH.
Operator-only recovery uses a separately authorized native read and exact approval;
diagnostics remain available through the shipped CLI:

```sh
docker exec auths-airtable-gateway-demo /opt/demo/bin/auths-gateway-simulation \
  recover --state-dir /run/demo/gateway0 --source-operation lost-response \
  --proof /private/read-proof.cbor --action /private/read-action.cbor \
  --approval /private/read-approval.json
docker exec auths-airtable-gateway-demo /opt/demo/bin/auths-gateway-simulation \
  doctor --state-dir /run/demo/gateway0 --app-socket /run/demo/sockets/app0.sock \
  --app-uid 62004 --app-gid 62005
docker exec auths-airtable-gateway-demo /opt/demo/bin/auths-gateway-simulation \
  support-bundle --state-dir /run/demo/gateway0
```

`doctor` intentionally reports **not production ready**: file custody, software
observer, development clock and absent protected qualification fail production
policy. Store, recipe, generation, transport and process isolation must pass.
Audit offline using independently pinned trust digest and observer principal
from the operator's private `pins.json`. Do not infer signature verification
from UI success.

## Explicit live launch from an existing private `.env`

`--live` is a startup parameter. A browser URL cannot change the gateway’s
provider, trust or credentials. The operator launcher reads the named private
file and sends only the selected credential fields over stdin. It never mounts
that file into the app or exports it into the app environment.

```sh
python3 launch.py --live --env-file /absolute/private/airtable.env
```

The file must contain `PERSONAL_ACCESS_TOKEN` (owner-authorized development PAT). The launcher keeps it owner-private and
requires a local Docker endpoint. Default launch without `--live` is simulation.
Use `--image` for your locally built reviewed image and `--name`/`--port` to run
another instance. A named live journal survives interruption; use the same name
and env file with `--live --cleanup` only after the serving container has stopped.

Live mode shows **Open on Airtable** beside the selected actual provider target.
The link is hidden during simulation. Provider login/account access is still
required. Inspect the selected record’s `DemoStatus` and exact `auths_echo` in the fixed table. Those website observations complement the
native signed evidence; they do not replace audit verification.

## Optional real Airtable mode

Only the owner-authorized dedicated disposable base `appQD3Qf0YFBCW9bV`, table
`tblBx2jwe0IsPYRKT` is supported. They must contain plain-text `Name`, `DemoStatus`
and `auths_echo`, no customer data and no automations with external effects.
Changing these resources requires a new recipe review; the app cannot select
another base/table.

Supply private stdin JSON with exactly `token`. This development run uses one
owner-provided PAT for both operator setup and gateway custody; the app receives
neither. It does not prove provider-key separation or rotation. The operator needs `schema.bases:read` and record read/write for creation/deletion on the
selected disposable table. The PAT also needs `data.records:read` and `data.records:write` there. Setup checks
the [actual metadata schema](https://support.airtable.com/articles/6292134965-getting-started-with-airtable-s-web-api), prepares 16 run-owned records using the reviewed
ownership journal, and verifies fresh runtime read access before serving.
Provider-configured permissions remain external prerequisites: this demo does
not establish write-only restrictions, an excluded-base scope proof or rotation.
The recipe has no per-lease account guard.

```sh
docker run --platform linux/amd64 --rm --init -i --name auths-airtable-gateway-demo \
  -p 127.0.0.1:8081:8081 -v airtable-demo-journal:/run \
  auths-airtable-gateway-demo --live < /absolute/private/airtable-demo-credentials.json
```

Do not put PATs in arguments, chat, source, build inputs or app environment.
Live uses the shipping gateway, pinned `https://api.airtable.com` and development
file custody/store. Setup/read/cleanup traffic uses bounded pacing; native
contenders are not serialized to conceal rate-limit behavior. The gateway does
not silently retry 429 or ambiguous writes. Plan quotas may refuse this run.

Graceful stop deletes only this run's records after fresh ownership checks.
The table/base and unrelated records remain. Preserve the journal volume after
an interruption or failed cleanup, and recover with the same private input:

```sh
docker run --platform linux/amd64 --rm --init -i -v airtable-demo-journal:/run \
  auths-airtable-gateway-demo --live --cleanup \
  < /absolute/private/airtable-demo-credentials.json
```

Remove the disposable volume only after confirmed retirement before a new live
session. Do not overwrite a dirty journal or use forced kill as normal cleanup.

## Evidence boundaries

### Authenticated owner review in local simulation

The optional owner interface withholds all application exact-effect approvals
until a separately authenticated owner reviews and approves the complete native
literal projection. The application keeps its own proposal interface; it cannot
read the owner login file or exact approver key. Native authorization, request
compilation, admission and recovery still run in the gateway.

```sh
python launch.py --name airtable-owner-workbench --port 8181 --owner-ui-port 8182
```

Open the application at `http://localhost:8181` and owner review at
`http://localhost:8182`. Retrieve `/run/demo/private/owner-login` through the
trusted container operator account and enter it only in the owner interface.
Choose a closed application experiment, inspect the entire native review on the
owner page, and approve or decline that exact pending effect. Recovery requires
its own review and approval. A cached approval permits only the same native
effect; replay remains subject to the gateway's conservative history rules.
Each closed mutation label permits one new consent attempt per fresh run. An
identical proof/action may retrieve its original signed approval after a client
restart; this neither refreshes consent nor recreates a native entry permit.

The browser keeps its short-lived owner bearer only in the owner page's memory
and explicit same-origin headers. Cookies are deliberately absent: localhost
cookies cross ports and would reach the untrusted application. The private
credential file and approver key remain in the operator boundary. This assumes
a trusted operator, browser and host, with the application UID unable to read
operator state. Expose both Docker ports on host loopback only, as the launcher
does. This mode is available only for simulation; live consent retains its
existing private operator channel.

Bounds are one pending review, eight HTTP handlers, a 1,024-byte command,
131,072-byte native review envelope, five-second HTTP I/O, fifteen-minute owner
session and ten-minute consent wait. Session/consent limits do not refresh native
proofs, approvals or evidence. Native deadlines and final authority checks still
apply. Initial simulation commissioning and organizational proof approvals stay
explicitly scripted; the owner interface controls application exact effects.

The hosted installed browser test exercises authenticated decline, refusal of a
substituted review, unchanged full native presentation, one exact write,
separately approved recovery and replay without further execution. Browser
actions simulate the owner; no human-attention or production qualification claim
follows. Complete managed content acquisition/disclosure through the installed
UI and the remaining AP074 acceptance evidence are still required.

The workflow packages and verifies exact payload digests outside the checkout,
installs both SDK artifacts, measures native verification/replay/race/recovery,
independent wire/read-back, competing-writer traffic, error bounds, UID isolation,
production-readiness refusal and offline audit. The operator rehearsal also kills the real gateway before submission and after
provider delivery while the response is held, then verifies durable restart and
read-only recovery. These process faults are operator-only, not web controls.
Actual desktop/mobile browser views are retained. These are engineering tests, not completed protected runs.

Protected AWS custody, PostgreSQL/TLS, two genuine rotation PATs, verified excluded
base access, current signed qualification, full crash/canary/lifecycle corpus,
independent security/human review and an actual GitHub-release installation
remain separate gates in AP-SPEC-066 and [AP-SPEC-068](../../docs/specs/0068-airtable-general-gateway-demo.md).

## Managed read, recipient release and write journey

The optional authenticated owner UI selects `managed-recipe.json` for the local
simulation. Its mutation declaration matches the maintained record-update recipe;
an additional bounded GET can retain at most 512 UTF-8 bytes from a response
bounded to 1,024 bytes. `managed-review.json` is the actual native recipe review,
reconstructed and compared by CI. The original recipe remains the live/reference
recipe. This local variant grants no managed Google or live-provider claim.

After logging into the separate owner origin, choose the Python acquisition,
then the TypeScript acquisition. Each installed client submits a separate native
proof and exact approval. Acquisition returns redacted history and leaves content
private. Choose disclosure next: inspect and approve its separate complete native
review, including the exact recipient/channel/instance and source. The native
recipient process runs under the application UID, receives into private `0600`
files and signs the native ACK. The browser displays the gateway's retained ACK
fact after it is recorded; an ACK-send result alone is not displayed as delivery
evidence. History/replay choices never authorize another GET or release.

The same native agent actor acquires, discloses and writes. The development
proposal simulator retains a fixed root-private copy of that actor's development
key before handing application files over, so the operator never loads an
application-writable signer configuration. Exact-effect reviewer keys remain
separate. This is explicit software simulation custody, not exclusive actor-key
custody, independent-human attention or production qualification.

The packaged browser scenario exercises both installed SDKs, real native
HTTP/Unix transport, recipient files, external provider counters, complete
owner review, exact write and independent observation. It also exercises actual
response loss and retained unknown without reentry. Assertions check that
private sentinel content stays out of public HTTP/history. New scenarios remain
authored until their exact-head hosted result is recorded in the AP074 ledger.
