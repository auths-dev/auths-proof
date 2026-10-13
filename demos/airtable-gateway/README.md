# Airtable exact record updates through the general gateway

The maintained monorepo demo uses a fixed-table, data-only recipe and installed
public Python/TypeScript SDKs. The application has its own signing key and sends
proof/action bytes to the gateway socket. Only the operator and gateway hold
provider credentials. The older field-lab `airtable-cli` app-owned-PAT mode is a
self-hosted reference; its token holder can bypass enforcement.

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
unsupported value, swapped record, two-gateway race and response-loss controls.
The UI and CLI show actual native gateway results. Their history is unsigned;
**Inspect the evidence** exposes native signed outcome/pre-entry bytes in the
actual gateway audit-bundle format. Missing evidence remains missing.

Default mode is clearly labeled **simulation**. An independent HTTP double
counts real native reads and PATCH entries; it never reaches Airtable. Two
native processes race through one operation store; a third uses a fresh
challenge. Each installation independently checks its custody setup. The web
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
After three seconds choose **Observe lost operation again**. This submits the
original proof/action to the native replay boundary: it can read again, and
cannot PATCH again. The automated journey measures zero new write entries.
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
Operator-only read-only re-observation and diagnostics use the shipped CLI:

```sh
docker exec auths-airtable-gateway-demo /opt/demo/bin/auths-gateway-simulation \
  reobserve --state-dir /run/demo/gateway0 --operation-id lost-response
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

## Optional real Airtable mode

Only the owner-authorized dedicated disposable base `appQD3Qf0YFBCW9bV`, table
`tblBx2jwe0IsPYRKT` is supported. They must contain plain-text `Name`, `DemoStatus`
and `auths_echo`, no customer data and no automations with external effects.
Changing these resources requires a new recipe review; the app cannot select
another base/table.

Supply private stdin JSON with exactly `setup` and `runtime`, containing
**distinct** PATs. Setup needs schema read plus record creation/deletion on the
selected disposable table. Runtime needs record read/write there. Setup checks
the actual metadata schema, prepares 16 run-owned records using the reviewed
ownership journal, and verifies fresh runtime read access before serving.
Provider-configured permissions remain external prerequisites: this demo does
not establish write-only restrictions, an excluded-base scope proof or rotation.
The recipe has no per-lease account guard.

```sh
docker run --platform linux/amd64 --rm --init -i --name auths-airtable-gateway-demo \
  -p 127.0.0.1:8081:8081 -v airtable-demo-journal:/run \
  auths-airtable-gateway-demo --mode live < /absolute/private/airtable-demo-credentials.json
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
  auths-airtable-gateway-demo --mode live --cleanup \
  < /absolute/private/airtable-demo-credentials.json
```

Remove the disposable volume only after confirmed retirement before a new live
session. Do not overwrite a dirty journal or use forced kill as normal cleanup.

## Evidence boundaries

The workflow packages and verifies exact payload digests outside the checkout,
installs both SDK artifacts, measures native verification/replay/race/recovery,
independent wire/read-back, competing-writer traffic, error bounds, UID isolation,
production-readiness refusal and offline audit. Actual desktop/mobile browser
views are retained. These are engineering tests, not completed protected runs.

Protected AWS custody, PostgreSQL/TLS, two genuine rotation PATs, verified excluded
base access, current signed qualification, full crash/canary/lifecycle corpus,
independent security/human review and an actual GitHub-release installation
remain separate gates in AP-SPEC-066 and [AP-SPEC-068](../../docs/specs/0068-airtable-general-gateway-demo.md).
