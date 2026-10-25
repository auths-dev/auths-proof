# AP-071 task-excluded Project B read

On 25 October 2026, Auths used Jules's already-signed read-only task
`F5D9NZWPvML5C-KodbQbbPMI` to test an agent action for a **different**
resource. The task listed only the finance Doc. The separate registered agent
signed a new Google read action for demo_co's Project B Doc
`1XYsmjDhK3ZsFUeVzVUCnYWDg0UjlFarIIbwYC9P_GOE`; the action and proof
are retained privately with SHA-256 values
`9edcfb5aa07425f822ed5bfa52219e8ba6b9e076dfa223112caa958cc48d9b89`
and `e5fe75396bc7c17d937b9a676c82e56266e08a6db998e26f611983ea33e769f8`.
The installed gateway returned `not-entered` with code
`gateway.release.scope`. No Google request was made for this action, no agent
content was delivered, and the durable task-status JSON was byte-for-byte
unchanged before and after it (SHA-256
`5554807debe05130e766e39f75662ea20fd952d495e823b3560e7fa202670e74`).
The status retained the prior finance task's one provider call, zero releases,
zero released bytes and zero writes. The negative action added **zero** calls.

demo_co independently probed the same owned Project B Doc. Its immutable
generation-0016 `google-project-b-jules-grants.json`, SHA-256
`adbc0dcf469319c2873d47f69dc082b464ef9da2d679df1ca94bae17aa012f26`,
records admin ownership and a matching fixture export. Jules's separate
`drive.readonly` grant exported the Doc with HTTP 200 and matched the fixture.
The `drive.file` grant used by this Auths gateway task received HTTP 403 for
that export. Both grants belong to Jules, but they have different provider
access. Auths vendored demo_co's schema at SHA-256
`17482aeba82f8dd0be56c57bcfa5ea98b4fe4c73be64d33e683d661b4a558ce4`;
its strict consumer accepted the privately copied generation against the
company, instance, definition, Jules subject, Doc and Drive IDs, digest,
status and no-leak fields. The producer made no fixture, ACL or grant change.
The broker's 137-test suite passed. The branch-built broker wheel SHA-256 is
`03089532cb559daf52e57c162a2adb29d41c81c670e2812114652423fedcb6d2`;
an isolated install loaded the consumer from that wheel and accepted the same
private generation without the repository source path.

This run proves that an agent-signed task-excluded action stops at Auths with
no additional provider call. It does **not** prove that the gateway's installed
`drive.file` grant could have read Project B absent the task restriction. The
stronger same-credential case needs a fresh task bound to Jules's `drive.readonly`
connection and a provider-readable excluded resource; this task cannot be
silently rebound to a different grant or generation.
