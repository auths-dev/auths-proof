# Airtable field release reference for AP-SPEC-071

The generated v2 [profile lock](profile.lock.json) and [recipe](recipe.json) use
the same managed read-release compiler as the
[Google reference](../../google-employee-delegation/read_reference/README.md).
The recipe fixes the existing disposable Airtable demo base and table, accepts
one verified record ID, and projects only the JSON string at
`/fields/DemoStatus` from a complete `200` `application/json` response. Its
provider body ceiling is 16 KiB and its released field ceiling is 64 bytes.
The focused compiler test checks the exact URL and projection from this
checked-in source.
The `task_read_cli` integration test also installs this recipe through the
same development `task-read-connect` command used for Google, verifies that
its read credential state is separate from the write installation, and
rejects a second installation. It uses a synthetic credential and sends no
Airtable request.
The broker's `test_task_card_cross_provider.py` signs one mixed Airtable task
with separate human and agent keys using the same AP-071 task-card and child
grant code as the Google demo. It verifies exact-mode limits, the read and
write recipe bindings, and refusal of a task-excluded record. This is a
ceremony test, not a provider effect or an Airtable human-subject claim.

This reference reuses the existing Airtable demo's operator PAT and run-owned
record fixture. The PAT does **not** prove that a particular employee owns
the provider access. The new managed release engine must still admit a
human-reviewed task, bind the exact record and agent, count the GET, charge
release budgets before delivery, require authenticated acknowledgement and
record a keyed content commitment. In particular, the small `DemoStatus`
value must not appear in a public receipt or as an unkeyed hash. A separate
Airtable read must compare the private field in the installed conformance
run. An [operator-only installed run](installed_conformance.py) now exercises
that path against one record in the reviewed disposable base. It creates a
durable ownership journal before the record POST, installs the checked-in GET
and PATCH recipes, signs a mixed task with separate development human and
agent keys, runs the agent in a separate process, requires its acknowledged
release and private source comparison, signs an exact write confirmation,
submits once through the gateway, and independently GETs the result. The
run first submits an agent-signed read for a different record and requires
`not-entered` with zero provider calls and zero releases. The
record is retired in a separate cleanup command, which checks the ownership
journal and verifies its absence. A successful run is installed mechanism
evidence; the PAT still supplies no employee-subject claim or production
credential custody.

For new acceptance evidence, build a source-free bundle from the reviewed
gateway executable, the native Auths wheel, the broker and agent wheels, and
an offline wheelhouse containing all of their Python dependencies. The bundle
copies the runner, fixed read/write recipes and fixture helpers, and pins
every byte in `manifest.json`. Record the printed manifest SHA-256 alongside
the gateway build and recipe digests. `run.py` checks the manifest before
creating a fresh virtual environment and installs only those wheels; it never
prepends checkout paths or inherits `PYTHONPATH`. The private `.env` must
contain only `PERSONAL_ACCESS_TOKEN`; the tool reads it as an owner-only file
and uses it in operator HTTPS requests. The current runner places only an opaque
`auths.materializer-source/1:` reference on gateway stdin, then installs the
bundled, digest-pinned `airtable_custody.py` process for both read and write
connections. That sidecar reads the private PAT after task admission, checks
the exact connection, source, recipe, kind and file digest, and returns a
short-lived bearer to the gateway. The agent never receives the PAT.
On macOS, `--macos-agent-sandbox` applies an OS Seatbelt profile to every
installed agent subprocess. It denies outbound network access, reads of the
gateway state/operator private files/PAT, and writes outside the agent's
private directory. The runner checks those denials from the installed agent
before creating a disposable provider record. This is a local fixture
boundary; production isolation still needs its own deployment qualification.
Choose a fresh owner-private output directory under `/private/tmp` for each
run:

```sh
python demos/airtable-gateway/read_reference/build_installed_bundle.py \
  --output /private/tmp/ap071-airtable-bundle \
  --gateway-bin /absolute/path/to/auths-gateway \
  --auths-wheel /absolute/path/to/auths.whl \
  --broker-wheel /absolute/path/to/broker.whl \
  --agent-wheel /absolute/path/to/agent.whl \
  --dependency-wheelhouse /absolute/path/to/offline-wheels
python3.12 /private/tmp/ap071-airtable-bundle/run.py run \
  --manifest-sha256 PRINTED_MANIFEST_SHA256 \
  --env-file /absolute/private/airtable.env \
  --root /private/tmp/ap071-airtable-run-1
python3.12 /private/tmp/ap071-airtable-bundle/run.py cleanup \
  --manifest-sha256 PRINTED_MANIFEST_SHA256 \
  --env-file /absolute/private/airtable.env \
  --root /private/tmp/ap071-airtable-run-1
```

Use the Python interpreter matching the native wheel's ABI and the dependency
wheelhouse platform. Keep the printed manifest digest outside the bundle;
the runner requires that independent pin on every invocation.

The older 25 October run used checkout imports and remains historical
mechanism evidence. A [26 October source-free run](../../../docs/program-log/2026-10-26-ap071-airtable-source-free-installed.md)
and later [custody process runs](../../../docs/program-log/2026-10-26-ap071-custody-process-cutover.md)
record bundle pins, offline installation, provider counts, task receipts,
independent after-state and run-owned cleanup. The Airtable PAT does not
establish a second human-bound employee account.
An [installed macOS isolation run](../../../docs/program-log/2026-10-26-ap071-macos-installed-agent-isolation.md)
used `--macos-agent-sandbox` for a complete read/write journey.

If a run fails after fixture creation, preserve its private root and execute
`cleanup` once the effect has been inspected. Do not start another run on the
same root. The [25 October live run](../../../docs/program-log/2026-10-25-ap071-airtable-live.md)
records the excluded-resource denial, one acknowledged seven-byte release,
one observed write, a later replay denial and verified record retirement.

For an installed lost-acknowledgement case, add `--drop-ack` to the `run`
command. Its separate agent process receives and saves the exact field bytes,
then deliberately closes the channel without signing the ACK. The operator
verifies a charged `delivery-unknown` receipt and an authenticated
same-operation replay denial before cleaning up the run-owned record.

For a development-only installed no-content case, build the gateway with
`--features loopback-provider` and add `--fail-before-content` to `run`.
The gateway authenticates the separate agent, makes the permitted provider
GET, durably charges the projected bytes, then closes its write half before
the first content-byte write. The operator verifies a charged `not-delivered`
receipt, no agent content file, and same-operation replay refusal before
retiring the disposable record. This fault flag is absent from the ordinary
gateway build.

The same development build also accepts `--exit-after-release-entry`. It
terminates the gateway process after durably charging the release and before
any content byte is sent. The installed runner reopens the task in a new
process, requires `delivery-unknown` with retained byte/call budgets, and
refuses a second delivery under the same operation ID. The
[installed crash run](../../../docs/program-log/2026-10-26-ap071-installed-release-crash.md)
records the manifest pin and redacted result. `--exit-after-content-send`
stops after sending the exact bytes but before reading the signed ACK; its
separate installed run requires the agent's saved bytes, retained
`delivery-unknown` charge after restart and refusal of redelivery.

For the durable write-journal boundary, use a `loopback-provider` build and
add `--exit-after-write-reservation`. The installed gateway exits after
charging an exact-confirmed write in the task ledger and before claiming its
attempt. The runner starts new gateway processes, requires
`claimed-no-attempt` with one spent write, refuses same-operation replay,
and independently checks that Airtable still has its original value. The
[installed crash run](../../../docs/program-log/2026-10-26-ap071-installed-release-crash.md)
records the manifest pin, redacted result and cleanup. This environment
selected fault is a CLI flag only in the development build; an ordinary
gateway refuses the flag before any provider request.

For the concurrent final-write budget case, add `--concurrent-upfront-writes`
to `run`. One synthetic human task lists two complete permitted choices but
allows only one write. Two separately signed agent operations enter the
installed gateway together. The tool requires exactly one observed PATCH,
one pre-entry budget refusal, one durable write operation, and an independent
Airtable readback matching the admitted choice. Run `cleanup` afterward.

For the shared-connection task-binding case, add `--two-task-swap`. The
source-free runner activates two human-signed tasks on the same installed
read/write connection pair, refuses a read and write signed for one task when
presented under the other task, and refuses a read under the write namespace.
Each task then performs one valid acknowledged read. The
[installed run](../../../docs/program-log/2026-10-26-ap071-airtable-two-task-swap.md)
records the bundle pin, redacted outcomes, separate budgets and cleanup.
