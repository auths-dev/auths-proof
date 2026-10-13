# Stripe refunds through the general gateway

The maintained Stripe demo uses a data-only platform-refund recipe and installed
Auths SDKs. The app holds its own scoped signing identity, submits proof/action
bytes over the gateway application socket, and has no Stripe key or private
gateway state. No coupled Stripe vertical service executes this demo.

The web workbench and CLI show the actual gateway result. Verification,
admission, HTTP response and linked provider read-back are separate stages.
The evidence page exports the native audit-bundle format with available signed
outcome/pre-entry observations; its display and history are explicitly unsigned.

## Source-free Docker quick start

Download `stripe-gateway-demo.tgz` and its checksum from the **Stripe gateway demo**
workflow for the exact reviewed commit. The archive includes the Linux gateway,
an installed-wheel input, packed npm SDK and compiled TypeScript client; no Rust
checkout/compiler is needed. Verify the checksum against the workflow's trusted
artifact metadata, then:

```sh
sha256sum -c stripe-gateway-demo.tgz.sha256
tar xzf stripe-gateway-demo.tgz
cd stripe-gateway-demo
docker build --platform linux/amd64 -t auths-stripe-gateway-demo .
docker run --platform linux/amd64 --rm --init --name auths-stripe-gateway-demo \
  -p 127.0.0.1:8080:8080 auths-stripe-gateway-demo
```

Open <http://localhost:8080>. Start with **Exact refund**, then replay, boundary,
altered proof/action, two-gateway race and budget experiments. Each choice has
one fixed operation and payment. Run the count/sum positive before its overflow.
The separate operator starts two native gateway processes for the race and a
third installation for the second challenge. Each installation checks its own
credential and account; all three share the operation/budget store. The web app runs
as UID 62004. Gateway state and root/observer keys remain root-private.

Default mode is clearly labeled **simulation**. A counting Stripe double measures
real gateway requests; no live Stripe or production qualification is claimed.
The source recipe bytes are identical to the reviewed live platform recipe.
Only the separately named `auths-gateway-simulation` binary can redirect its
transport to the loopback double. `bin/auths-gateway` is built without that feature.

The session lasts one hour; new containers create fresh disposable state.
Stopping the container ends all child processes. The operator responds to
interruptions and cleans up run-owned live resources; a forced kill may need
the durable preparation journal for recovery. Do not use `docker kill` to
demonstrate normal cleanup or delete a live journal before confirming retirement.

## CLI and operator diagnosis

The CLI uses the same installed SDK submission code as the workbench:

```sh
docker exec --user 62004:62005 auths-stripe-gateway-demo \
  /opt/consumer/bin/python /opt/demo/app.py status
docker exec --user 62004:62005 auths-stripe-gateway-demo \
  /opt/consumer/bin/python /opt/demo/app.py submit --experiment exact
docker exec --user 62004:62005 auths-stripe-gateway-demo \
  /opt/consumer/bin/python /opt/demo/app.py export > audit-bundle.json
```

An application/gateway IPC error is **unconfirmed**, never a retry signal.
After actual response loss without a retained refund locator the native outcome
stays `unknown`; repeating that operation cannot send another refund. The UI
does not synthesize successful reconciliation. TypeScript uses the packed public
gateway client; its closed experiment replays the same original packet.

Operator-only diagnosis uses the shipped general CLI:

```sh
docker exec auths-stripe-gateway-demo /opt/demo/bin/auths-gateway-simulation \
  doctor --state-dir /run/demo/gateway0 --app-socket /run/demo/sockets/app0.sock \
  --app-uid 62004 --app-gid 62005
docker exec auths-stripe-gateway-demo /opt/demo/bin/auths-gateway-simulation \
  support-bundle --state-dir /run/demo/gateway0
```

Pin trust and observer independently from the operator's `private/pins.json` and
use `auths-gateway audit`. Missing outcomes cannot be treated as verified merely
because the UI says success. Read-back echo attribution assumes other writers
did not copy the action echo; this is not proof of settlement or exclusive causation.

`doctor` intentionally reports **not production ready** for this development
installation: file custody, software observer, local clock and missing protected
qualification do not satisfy production policy. Store, recipe, generation,
transport and operator/application isolation checks must still pass.

## Explicit live launch from an existing private `.env`

`--live` is a startup parameter. A browser URL cannot change the gateway’s
provider, trust or credentials. The operator launcher reads the named private
file and sends only the selected credential fields over stdin. It never mounts
that file into the app or exports it into the app environment.

```sh
python3 launch.py --live --env-file /absolute/private/stripe.env
```

The file must contain `STRIPE_TEST_API_KEY` (setup test key) and `STRIPE_TEST_RESTRICTED_KEY` (restricted test runtime key). The launcher keeps it owner-private and
requires a local Docker endpoint. Default launch without `--live` is simulation.
Use `--image` for your locally built reviewed image and `--name`/`--port` to run
another instance. A named live journal survives interruption; use the same name
and env file with `--live --cleanup` only after the serving container has stopped.

Live mode shows **Open on Stripe** beside the selected actual provider target.
The link is hidden during simulation. Provider login/account access is still
required. Inspect the test payment’s refund and its `auths_echo` metadata. Those website observations complement the
native signed evidence; they do not replace audit verification.

## Real Stripe test mode

Use a disposable test platform account. It needs a setup-only `sk_test_` key
and a restricted `rk_test_` runtime key permitting refunds, selected payment/
refund reads, balance and account guards, but refusing customer and payout reads.
No Connect account or paid onboarding is required. Native install verifies
the declared credential guards; a key name alone does not establish its scope.

Provide a private JSON input on stdin with exactly `setup` and `runtime` fields.
Do not put values in command arguments, chat, source or Docker build arguments.
The example below names a private file rather than embedding any credential:

```sh
docker run --platform linux/amd64 --rm --init -i --name auths-stripe-gateway-demo \
  -p 127.0.0.1:8080:8080 -v stripe-demo-journal:/run \
  auths-stripe-gateway-demo --live < /absolute/private/stripe-demo-credentials.json
```

Live mode uses the **shipping** gateway, reaches only `https://api.stripe.com`,
and prepares 16 run-owned $20.00 **test-mode** payments. It uses the existing
reviewed preparation/cleanup journal and fully refunds remaining fixture
capacity on graceful shutdown. Stripe retains payment/refund records.
Response-loss injection is available only in simulation; the label cannot
manufacture a live fault. Preserve the named journal volume after an interrupted
live run for operator recovery; a dirty session refuses to overwrite it.

After the serving container has stopped, recover an interrupted live session
with the same private credential input and retained journal volume:

```sh
docker run --platform linux/amd64 --rm --init -i -v stripe-demo-journal:/run \
  auths-stripe-gateway-demo --live --cleanup \
  < /absolute/private/stripe-demo-credentials.json
```

Cleanup freshly verifies account, test-mode ownership and remaining charge
capacity. It refuses an unavailable/ambiguous journal and does not enumerate
unrelated payments. Keep the volume if cleanup fails; after confirmed retirement,
remove that disposable demo volume before starting a new live session.

This live demo still uses **development file custody/store and software observer
custody**. It is not production qualification. Application, setup and gateway
keys are separate, but this is a local container deployment, not a multi-host
production claim. Never rename its evidence as AWS/PostgreSQL evidence.

## Automated evidence and remaining production gates

The workflow builds a digest-listed handoff, installs its actual SDK artifacts
outside the checkout and runs the native simulation plus a real browser.
`selftest.py` verifies independent wire mapping/read-back, pre-custody refusals,
post-lease guards, count/sum boundaries, two-process race, fresh-challenge replay,
process restart, actual response drop after effect, UID isolation, doctor and
offline audit. Provider traffic is counted independently of the app display.
Reports and desktop/mobile screenshots are retained as artifacts.

Protected AWS custody, PostgreSQL/TLS, two genuine runtime rotation keys and
current signed qualification require the existing main-only
`recipe-qualification.yml` workflow and its full retained corpus. This demo does
not disable that gate or provision shared environment credentials. The Stripe
family's current report contributes only one of the two required live providers.
Human review and actual GitHub-release installation are separate acceptance gates.
See [AP-SPEC-067](../../docs/specs/0067-stripe-general-gateway-demo.md).
