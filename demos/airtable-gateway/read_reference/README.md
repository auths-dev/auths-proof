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

Run from the repository root with the local Python dependencies and native
gateway binary available. The private `.env` must contain only the supported
`PERSONAL_ACCESS_TOKEN` field; the tool reads it as an owner-only file and
passes the PAT only on gateway stdin and in operator HTTPS requests. Choose a
fresh owner-private output directory under `/private/tmp` for each run:

```sh
python demos/airtable-gateway/read_reference/installed_conformance.py run \
  --env-file /absolute/private/airtable.env \
  --root /private/tmp/ap071-airtable-run-1 \
  --gateway-bin /absolute/path/to/auths-gateway
python demos/airtable-gateway/read_reference/installed_conformance.py cleanup \
  --env-file /absolute/private/airtable.env \
  --root /private/tmp/ap071-airtable-run-1
```

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
