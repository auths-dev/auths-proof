# Airtable task write reference for AP-SPEC-071

This is a test-only second provider reference for the provider-neutral task
write contract. Its v2 profile adds `task_id` and `task_commitment` to the
existing fixed-table Airtable record update. The recipe declares the same
`task_binding` mechanism as the Google Docs edit reference, with `record_id`
as the reviewed resource field and `edit` as the verb. A focused gateway test
compiles both references and checks their closed methods, URLs, bodies and
task-binding review output without provider-name branches in the interpreter.

The existing Airtable demo uses an operator PAT. This reference does not
establish a human-bound Airtable grant, an installed task write, a provider
effect or a cross-provider delegation claim. Live conformance still needs an
operator-pinned connection, exact human confirmation, the task-aware installed
gateway path, counted provider requests and an independent record readback.

Edit `profile.toml` and regenerate `generated.py`, `vectors.json` and
`profile.lock.json` with Auths's profile generator before changing the recipe
digest or accepting a new action shape. The source recipe remains reviewed
data; Airtable field meaning and PAT scope stay in the demo vertical.
