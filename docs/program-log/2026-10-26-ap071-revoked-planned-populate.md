# AP-071 installed Google planned-population revocation, 26 October 2026

This is a fresh Jules-signed task on the source-free installed Google bundle
(manifest SHA-256
`6208d943c0a03999f4881a14449d09cca506c4c095e48eed60561fa6b904da7a`)
from the [provider-final-v2 run](2026-10-26-ap071-provider-final-v2-live.md).
It exercises revocation after one allowed create and before the planned
population. The target is a disposable blank Doc; the previously completed
positive-path Doc was not modified.

Jules signed task `teRzDBW4QX8Y4k4g4LIa7maz` for the same separate agent in
run `ap071-revoke-v2-96fc7c73104a4b1a`, folder
`1IrphUqBsH2hprQobG_NPtjIPDVzXB4zq`, with recovery marker
`ap071_ea0a7f0bbee22854c1b209895fb60fa5`. The task-card SHA-256 is
`4368e3b01dd0b0dda196c49753436099dea13df5d82acd8f4e286a9b41115495`.
The isolated agent signed the selected Project A read and acknowledged its
51-byte release (`R_QI-C70HNHLnatEQRd_X9XA`). It signed a source-backed
create proposal; Jules signed the exact two-effect plan, SHA-256
`1642811214394b74eba9ea108a63677fedb6c46c4663c7c21294f6bd6ce902f1`.
The plan names one create and one 145-byte initial text population. No
population was approved beyond that plan.

| demo_co report | Generation | SHA-256 | Observed UTC |
| --- | ---: | --- | --- |
| Scratch setup | 0054 | `a308cbdc9a091975b60b4404d55f7fe8747e0661cf40a769a098518b05234baf` | 13:00:28 |
| Zero-match precreate baseline | 0055 | `1678496ab1ec61cc38cb5586c4ccae74eb8d2ac05e3e57fa151f79bbda711347` | 13:08:03 |
| Bound blank-child baseline | 0056 | `22b78de9555f6de2325bed27c84226372ffbff053c822c66c7db9f4fa3d6d3ce` | 13:10:35 |
| After-revocation denial inspection | 0057 | `b959402e1caad62dc7f726a85b8ae8590bf2da73a97c1a8060ff8bed17887801` | 13:15:35 |

Auths submitted create operation `h7RzKvr9d1XDWAYj1ajtspjh` once after the
zero-match baseline. Google returned HTTP 200; the gateway's observation
matched and durably bound child
`1w0XDIJFUnGqhHSCRBF-zobTE1uPAczWycxw34yH_dpg`. A separate explicit
reconcile call returned `gateway.task.reconcile-binding` because this child
was already bound. That call made no create request. demo_co found exactly
one run child and marker match, an unchanged original inventory, tab `t.0`,
and a 3-byte BOM-only export. Its blank admin revision was
`AHj4eMTMeaUuGYuf3stz4VddeOarQLKzGmyMMzW4ykgQFqEDOySsavYSKVZigWyheYzvdFGUVp40YoizdUo0n4UpSvIPf6uhM2nNMxLqHWw`.

Jules's credential-bearing child preflight was checked at 13:12:51 UTC and
valid until 13:13:51 UTC. The gateway recorded its signed report, SHA-256
`3ec1fcf72dd81a0238a1c7f0da8cabe7e9624ba8469159092d38b4f1e7926ba0`.
The isolated agent then signed the matching planned-population action; its
proof SHA-256 is
`8eb5d94f938be1994b4b1f20b3c574b5ac3d7a6bc353c9b1c399e9b5e2aad7e9`.
The action and fresh preflight were staged before revocation. At 13:13:41 UTC,
with the preflight still valid, the gateway durably returned `task-revoked`.
The owner helper subsequently could not fetch child inputs from the inactive
task. A direct gateway submission of the staged agent proof returned
`not-entered / gateway.task.inactive`. The task activity shows one write used
for create, zero population writes, and no durable population provider attempt.

The direct submission's exact wall time was not retained. It occurred before
the 13:15:35 independent inspection and well before the task's 13:33:03
expiry. The gateway's `submit_task_write` checks the durable task's active
state before evaluating the population preflight; an expired preflight has a
different refusal path. Since this activated task was within its time window,
`gateway.task.inactive` isolates the recorded revocation as the cause of the
pre-entry refusal. The preflight may nevertheless have expired by the attempt
instant, so this run does not demonstrate a denial while *both* revocation and
an otherwise fresh preflight were simultaneously present at entry.
The independent generation-0057 inspection returned
`blank_unchanged_after_gateway_denial`: the same child, marker, parent, tab,
admin revision and 3-byte raw export (SHA-256
`f1945cd6c19e56b3c1c78943ef5ec18116907a4ca1efc40a57d48ab1db7adfc5`)
remained unchanged, as did the source, original siblings and canonical Docs.
The blank child and scratch folder are retained for review; cleanup is not
claimed. A later run with a captured gateway attempt time inside the valid
preflight window would test that stronger timing-specific condition, but is
not needed to attribute this refusal to revocation.
