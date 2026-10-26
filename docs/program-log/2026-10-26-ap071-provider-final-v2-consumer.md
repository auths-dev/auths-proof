# AP-071 provider-final v2 consumer, 26 October 2026

demo_co committed the forward-only producer contract at `139c184` in its
separate repository. Its commands observe Google state; Auths did not run them
in this change and made no Google write. The two reviewed schema pins are:

| Producer artifact | SHA-256 |
| --- | --- |
| `google-populate-provider-inventory-v1.schema.json` | `bf175a3779551d1855e83824794d3c41385c90ed3997e8ff1f0a5e2462169c81` |
| `google-populate-provider-final-v2.schema.json` | `f739432461d11e0872222e837a2a62393595c193b7d4a4305559a3c2745eb237` |

Auths vendored those exact bytes. The new consumer verifies private file and
generation pins, the existing demo_co setup/pre-create/blank lineage, the
measured sorted sibling inventory, the pinned source, one blank child, the
five-minute create window, the changed final revision, and the complete
BOM-prefixed raw export against the human-approved text. It refuses swapped
source, child, inventory, blank baseline, content and any retry claim. Its
result is labeled `provider_state_only`; it neither signs task authority nor
claims that Auths entered Google. Plain document hashes remain inside the
private producer and operator path, not the public activity receipt.

Focused validation used the local pinned Python environment and passed eight
tests: four new consumer tests and four existing post-entry consumer tests.
The new tests also verify the vendored schema SHA-256s, require every schema
field, and reject missing attribution. `py_compile` and `git diff --check`
passed. The tests use synthetic reports; there is no live v2 report yet.
A local wheel build packaged the consumer and both schemas at
`/private/tmp/ap071-provider-v2-wheel-20261026/auths_google_employee_delegation_broker-0.1.0-py3-none-any.whl`
with SHA-256 `9db12446bde90f4383bda07a0f9f2b48db37eda86b024d2d3834b0992c0e2b96`.
This wheel was inspected for those three entries; it has not been used in a
Google task.
Installing that wheel without dependencies into a new private target path and
importing the consumer from that path succeeded; both packaged schema hashes
matched the reviewed pins without a checkout import.

The gateway now exposes owner-only `task-population-lineage`, a redacted read
of the journal-bound effect-plan commitment, child ID and SHA-256 of the
verified preflight signature. A separate Auths join checks that value against
the private preflight report, recomputes the native task and plan commitments,
and matches one acknowledged read, two charged writes, the exact create and
populate attempt stages, and the producer's exact child/content verdict. A
response lost after population stays `unknown` in the joined result; the
independent exact provider state does not convert it into a successful gateway
response or permit retry. The join returns no plain content hash.

Eight focused join tests pass, including task, plan, child, preflight and
attempt swaps, malformed inputs, response-status checks and the private owner
manifest. The gateway's
loopback create/populate test checks the journal-derived preflight signature
hash, and the CLI help exposes the new
read-only command. A final broker wheel containing both the consumer and
join was built at
`/private/tmp/ap071-provider-v2-join-final-wheel-20261026/auths_google_employee_delegation_broker-0.1.0-py3-none-any.whl`
with SHA-256 `d7c11b4d9d5c2e61db539c04dce015e080194aa49a224af69bc1ef71aa70e680`.
It installed and imported from a source-free private target path. Neither
wheel nor gateway command has run against a fresh Google task.

The owner workbench now has a conditional provider-effect row. An operator
places `provider-v2-evidence.json` in the owner-only task directory after
demo_co publishes the fresh reports. The manifest has schema
`auths.ap071-provider-v2-evidence/1`, the exact task ID, three absolute v4
source observation paths, an absolute v4 final-pins path, the pinned source
document ID/raw SHA-256/byte count, the signed preflight basename, and
`{path, sha256}` pairs for `setup`, `inventory`, `precreate`, `blank` and
`final`. Every file and manifest is private to the operator; the producer
reports are never sent to the browser. On each owner activity request, the
broker revalidates those pinned reports, reads the gateway's durable task
activity and population lineage, reruns the private join, and returns only
the redacted exact-state verdict and a link to the checked child. Missing
manifest means no independent effect claim. Invalid evidence refuses the
effect view. The browser labels the provider observation separately from the
gateway outcome and never converts `unknown` into response success or retry
permission. This is a Google demo adapter in the broker; the task and gateway
contracts remain provider-neutral. The source and synthetic tests cover this
path, but a real v2 report has not exercised it yet.

The complete broker suite passed 194 local tests, and its browser workbench
test rendered the independent effect and checked-child link. The updated
source-free wheel contains the consumer, join, owner adapter, two vendored
schemas and workbench JS at
`/private/tmp/ap071-provider-v2-owner-wheel-20261026/auths_google_employee_delegation_broker-0.1.0-py3-none-any.whl`
with SHA-256 `60f2a7da04f69eb1213eac1338ab1ec3f9bdd62466753566ca27faef1f373856`.
It installed without dependencies into a clean private target, and both owner
modules imported from that target outside the checkout.

demo_co confirmed the fresh producer order and output names. Run its CLI from
the demo_co checkout with `PYTHONPATH=src .venv/bin/python -m demo_co.cli google`
and the `atlas-studio --instance live-test-atlas-20261025` arguments. The
subcommands, in order, are:

1. `populate-failure-setup --run-id RUN_ID --marker ap071_HEX32 --v4-baseline-generation 21 --v4-baseline-sha256 ba01c1855c52e28ce403830a9ff3b0f86b84460e6a33df2736474c8e8d22cb19 --v4-final-generation 23 --v4-final-sha256 986ef9f2ab83531cfec6ff1fc972cb99bd936a484715cd8fb025bfc2862b3b54`. This creates one new Google run folder. Start it only when the installed Auths run and Jules browser signing can follow. It emits `google-populate-failure-setup.json` and prints its absolute private path and SHA-256.
2. `populate-provider-inventory --setup-generation N --setup-sha256 PIN` performs read-only sibling and Jules-source checks, emitting `google-populate-provider-inventory.json`.
3. After Jules signs the task and exact plan, immediately before Auths create, `populate-precreate-baseline --setup-generation N --setup-sha256 PIN` emits `google-populate-precreate-baseline.json`. The create must enter within its five-minute window.
4. After Auths binds the exact child, `populate-blank-baseline --setup-generation N --setup-sha256 PIN --child-id BOUND_ID` emits `google-populate-blank-baseline.json`. Use its child/tab facts in Jules's signed v2 preflight before the single population attempt.
5. After that attempt, `populate-provider-final-v2 --inventory-generation N --inventory-sha256 PIN --blank-baseline-generation N --blank-baseline-sha256 PIN --expected-raw-sha256 PRIVATE_PIN --expected-raw-byte-count COUNT` emits `google-populate-provider-final-v2.json`. The expected bytes include Google's text export BOM.

Take every generation and digest from that command's printed
`private_evidence` and `private_evidence_sha256`; generation numbers are shared
across evidence types and must not be predicted. The frozen v4 source trio is
`generation-0021/google-create-v4-baseline.json`,
`generation-0022/google-create-v4-candidate-blank.json`, and
`generation-0023/google-create-observation-v4.json` under demo_co's private
write-evidence directory. Their respective SHA-256s are
`ba01c1855c52e28ce403830a9ff3b0f86b84460e6a33df2736474c8e8d22cb19`,
`30cb3e88995ca1d26bc66a6179bbcdcbd58b44eab4c857b33cc1607dfca19a5f`,
and `986ef9f2ab83531cfec6ff1fc972cb99bd936a484715cd8fb025bfc2862b3b54`.
The frozen source export pin is SHA-256
`605a3d7e0908275e59d53743fc570418b04acbab9f7184bfdb91670656909335`
with 51 bytes. These are private comparison inputs, never public read receipts.
The Auths owner-only
`/private/tmp/ap071-v4-fixed-20261025/v4-final-pins.json` was revalidated
against those three files with `validate_create_v4_observation`; it passed.
The new task's `provider-v2-evidence.json` manifest points to that frozen
trio and pins file, the five new report paths and SHA-256s, the private source
pin, and the signed preflight basename. No new Google action was taken to
prepare this sequence.

The gateway was built and copied to the owner-private
`/private/tmp/ap071-gateway-v2-20261026/auths-gateway` before a live task.
Its SHA-256 is
`707c4ec66188b0ccdb388c298e8262270bae7ae8116e5875a2c364c69ea74c40`;
its installed help exposes `task-activity`, `task-population-lineage` and
`task-submit`. This is a development binary pin, not yet a complete installed
Google task or production qualification.

The next live run needs a new demo_co setup/run folder and marker, a fresh
inventory and pre-create baseline, one Jules-signed task and exact plan using
the current `provider_values` recipe, a blank-child baseline, one population
attempt, and a private final v2 observation. The Auths join must then be run
on the live task, gateway activity and lineage reports and the independent
provider result, before its redacted verdict can appear in the owner view.
The historical generation-0048 observation predates the current recipe and
does not qualify this run.
