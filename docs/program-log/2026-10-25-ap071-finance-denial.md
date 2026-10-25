# AP-071 finance read denial: producer evidence

On 25 October 2026, demo_co ran a focused read-only probe against its
`live-test-atlas-20261025` Atlas instance. It resolved the owned
`doc-finance-budget` resource, confirmed that the admin could read the fixture
and that its content matched, then used Jules's existing read grant and Google
subject `113654555744401103740` for direct metadata and export requests.
Both Jules requests returned HTTP 404. The producer reported no fixture text
in either denied response. It changed no fixture or ACL.

The private generation-0009 `google-finance-denial.json` has SHA-256
`c96abca489ce1a4163c4e6d90666731c12d85463c92b699ffe33f0521db1b9ec`.
Auths copied and pinned the `demo-co/google-finance-denial/v1` schema at
SHA-256 `d2cec86f3f32e22d88f80749671cc21e71842c8acce4e0534be7968975ad84fd`.
Its consumer accepted the exact private generation, digest, company,
instance, definition, customer, Jules subject, finance Doc ID, admin checks,
denial statuses and no-leak flags. This is provider-state evidence only.

The controlled negative run below used a short Jules-signed Auths task listing
that exact finance Doc. A distinct registered agent signed its matching read;
the managed gateway admitted the task before making one credential-bearing
Google request. A task-excluded Project B read remains a separate
zero-provider-call denial.

Auths now has a read-only Jules task ceremony for this test. The operator pins
the fresh, private demo_co observation by SHA-256 and exact finance Doc ID at
startup, installs that ID as the sole permitted read scope, and activates a
card with one provider call, one possible bounded release and **zero writes**.
The browser signs a read child grant and task only; it creates no write agent
package. Synthetic signing and browser tests pass. The live outcome is
recorded below.

The first direct Jules probe used her separate read-only grant. Auths's
gateway instead leases her `drive.file` grant into a GET-only read connection.
demo_co therefore ran a second direct, read-only metadata/export probe with
that **same saved grant** and OAuth client. Both Google requests returned 404;
no fixture title or source excerpt was present in the denied bodies. The
private generation-0012 `google-finance-write-grant-denial.json`, SHA-256
`b9828d5e8a7247968da363152397ee0773464f22e82fb0902f72f4cf9cb2d1bc`,
pins generation-0009 and records the exact granted scope set. Auths vendors
its `demo-co/google-finance-write-grant-denial/v1` schema at SHA-256
`945d45f7f2a4ff7165d6ac168391a19bafb21f0b56136424ab6779ca0b447cb1`.
The consumer requires both fresh, private observations, matching Jules subject
and finance ID, the source digest, same-grant kind/scopes, two denied statuses
and no-leak flags. The live generation passed those checks. No Auths-origin
finance read had been submitted at the time of that producer observation.

## Live Auths-origin denial

In the Chrome Incognito workbench, Jules signed task
`F5D9NZWPvML5C-KodbQbbPMI` for the distinct registered agent, the sole
finance Doc read, at most one provider call and one 16 KiB release, and zero
writes. The installed broker wheel served the task ceremony. The separate
installed agent wheel signed operation `LQdmIo_xnR-tXaSobfiB4Hld` and opened
the authenticated local release channel. The gateway admitted the matching
task and made exactly one GET using Jules's subject-bound read connection.
Google returned HTTP 404. The gateway reported `provider-unavailable` and its
task ledger recorded one provider call, zero releases, zero released bytes,
and zero writes. The operator-private gateway output and task-status JSON are
under `/private/tmp/ap071-jules-local/finance-20261025/`; no finance content
was saved or delivered to the agent.

The initial local attempt could not bind the agent Unix socket under the
command sandbox and made zero provider calls. A second preparation attempt
used a mismatched operation ID, so channel authentication failed before
provider entry and again made zero provider calls. We restored the signed
operation ID from the immutable agent action, verified the task ledger was
unspent, and submitted once with the socket available. The HTTP 404 is the
only provider attempt for this task. The earlier direct same-grant probe is
independent corroboration of the provider access state.
