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

The [official Todoist API v1 reference](https://developer.todoist.com/api/v1/)
specifies the task update endpoint and `description` property. The fixture is
synthetic. It does not establish a live Todoist account, a subject-bound
human grant, a successful provider effect or independent after-state. Its role
is to compare the planned-population mechanism with Google Docs' two fresh
tab/revision values; installed cross-provider acceptance remains separate.
