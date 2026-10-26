# Todoist created-child reference

This test-only recipe exercises the same created-resource binding declaration
as the Google Drive example against a second HTTPS domain. It sends a closed
`POST /api/v1/tasks` with a reviewed project ID, title and opaque recovery
marker. A complete response may nominate one task ID; a credential-bearing
`GET /api/v1/tasks/{id}` must then match that ID, scalar `project_id`, title
and marker before the task ledger may bind the child. These are recipe fields
and comparisons, not Todoist code in the shared gateway.

The request shape follows Todoist's [current API v1 task reference](https://developer.todoist.com/api/v1/).
This fixture has synthetic IDs and responses. It does not establish a live
Todoist connection, token custody, agent release or provider effect, and it
does not satisfy AP-SPEC-071's installed cross-provider acceptance by itself.
