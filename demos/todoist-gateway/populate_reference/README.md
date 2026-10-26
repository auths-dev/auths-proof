# Todoist created-task population reference

This test-only recipe applies the approved plan text as the description of a
task whose ID was already bound from the companion created-child recipe. The
closed request is `POST /api/v1/tasks/{bound-task-id}` with only
`{"description": approved_text}`. A signed provider preflight must freshly
verify that the bound task still has the expected project, title and recovery
marker and that its description is still the marker before this write. The
preflight signs the metadata response digest and child/connection facts; it
has **no late-bound provider fields**. The common gateway compares its empty
provider-values map against this recipe, the bound child and the exact human
plan. No Todoist version or tab field is invented.

[`preflight_reference.py`](preflight_reference.py) is the independent,
test-only domain oracle for that metadata check. It accepts a bounded raw
`GET /api/v1/tasks/{bound-task-id}` response and pinned child/project/title/
marker, rejects ambiguous or changed responses, and yields an empty
`provider_values` map plus a private metadata digest. Its synthetic hostile
cases run with `python -m unittest discover -s
demos/todoist-gateway/populate_reference -p 'test_*.py'`. A caller must
authenticate the provider GET under the pinned human connection and sign the
gateway's preflight statement separately; this pure reference does neither.

The [official Todoist API v1 reference](https://developer.todoist.com/api/v1/)
specifies the task update endpoint and `description` property. The fixture is
synthetic. It does not establish a live Todoist account, a subject-bound
human grant, a successful provider effect or independent after-state. Its role
is to compare the planned-population mechanism with Google Docs' two fresh
tab/revision values; installed cross-provider acceptance remains separate.
