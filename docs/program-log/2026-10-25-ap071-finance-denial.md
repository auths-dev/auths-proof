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

The remaining controlled negative run needs Jules to sign a short Auths task
listing that exact finance Doc, a separate agent to sign its matching read,
and the managed gateway to admit the task before it makes exactly one
credential-bearing Google request. The expected result is provider denial and
zero released bytes. A task-excluded Project B read remains a separate
zero-provider-call denial.

Auths now has a read-only Jules task ceremony for this test. The operator pins
the fresh, private demo_co observation by SHA-256 and exact finance Doc ID at
startup, installs that ID as the sole permitted read scope, and activates a
card with one provider call, one possible bounded release and **zero writes**.
The browser signs a read child grant and task only; it creates no write agent
package. Synthetic signing and browser tests pass. This does not turn the
provider-state probe into a live Auths denial: the separate agent must still
sign the matching read and the gateway must record one Jules-credential Google
403/404 with zero released bytes.

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
finance read had been submitted at the time of this record.
