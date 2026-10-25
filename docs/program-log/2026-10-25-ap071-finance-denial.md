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
