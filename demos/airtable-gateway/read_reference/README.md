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

This reference reuses the existing Airtable demo's operator PAT and run-owned
record fixture. The PAT does **not** prove that a particular employee owns
the provider access. The new managed release engine must still admit a
human-reviewed task, bind the exact record and agent, count the GET, charge
release budgets before delivery, require authenticated acknowledgement and
record a keyed content commitment. In particular, the small `DemoStatus`
value must not appear in a public receipt or as an unkeyed hash. A separate
Airtable read must compare the private field in the installed conformance
run. This checked-in recipe is construction evidence, **not** an installed
read or a cross-provider human-identity claim.
