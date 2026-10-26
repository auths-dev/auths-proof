# AP-071: Project B excluded by Auths despite Jules provider access

Jules signed read-only task `2e8lHoFufyRtLOYyPx6OYKgo` for the separate
registered agent. Its only read scope was the Project A probe Doc
`1s4aww3jjyJx1os8irP6rOF8oXMGd-I4i_GWGyizqdZ0`, through read connection
`conn_HXTxG7nK0qjPeHFkMnyJvg` at generation 1 and Jules's Google subject
`113654555744401103740`. The task allowed one provider call, one release of
at most 16 KiB, zero writes and a 30-minute lifetime. The earlier reviewed
card expired before a signature; it created no grant. The active task was
revoked after the two attempts below.

The operator installed that read connection from demo_co's saved Jules
`drive.readonly` grant after checking its exact OAuth client and scope,
refreshing a bearer, and verifying live Google UserInfo. The bearer entered
the fixed gateway through private stdin; neither the agent package nor the
task card contained it. The gateway executable SHA-256 was
`8c663e4021f3f0469bebf708b1afecde11b5208d82d95f43a959215253415b1d`.
demo_co's independent generation 0039 Project B grant observation, SHA-256
`93ebde35040add18ddb2791bf53f07f7d621e2bedd6d157fb20d9bb869a171a0`,
recorded a direct HTTP 200 export and fixture match for Project B Doc
`1XYsmjDhK3ZsFUeVzVUCnYWDg0UjlFarIIbwYC9P_GOE` with that same saved
Jules read-only grant. Its separate `drive.file` grant returned HTTP 403.
The producer observation proves provider access for the read-only grant;
it does not assert an Auths provider request.

1. The agent signed a read action for the excluded Project B Doc under the
   active Project A task. `task-read-submit` returned
   `not-entered` / `gateway.release.scope`. The task journal before and after
   was identical: zero provider calls, zero releases, zero released bytes and
   zero writes. No Google request was admitted for this action.
2. The same agent then signed the permitted Project A read under the same
   task and connection. The gateway returned `agent-acknowledged`; the
   separate agent received 51 bytes whose SHA-256 matched demo_co's pinned
   Project A source (`605a3d7e0908275e59d53743fc570418b04acbab9f7184bfdb91670656909335`).
   The final journal showed exactly one provider call, one 51-byte release,
   zero writes and revocation.

This closes the stronger §8 Project B case: the installed credential had
provider access, yet Auths's narrower task scope stopped the agent before
provider entry. The earlier finance case remains the complementary path:
Auths admitted that file and Google denied it. This run does not prove the
remaining hostile write matrix or production credential custody. Private
task, gateway and agent artifacts are under
`/private/tmp/ap071-project-b-readonly-20261026`; no provider token or Doc
body is included in this log.
