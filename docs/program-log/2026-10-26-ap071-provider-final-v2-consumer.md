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

The next live run needs a new demo_co setup/run folder and marker, a fresh
inventory and pre-create baseline, one Jules-signed task and exact plan using
the current `provider_values` recipe, a blank-child baseline, one population
attempt, and a private final v2 observation. The Auths task and gateway
attempt records must then be joined to that independent provider result.
The historical generation-0048 observation predates the current recipe and
does not qualify this run.
