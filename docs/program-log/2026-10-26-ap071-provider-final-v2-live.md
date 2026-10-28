# AP-071 installed Google read, create and populate, 26 October 2026

This is the live positive path for the revised provider-final-v2 contract. Jules
signed task `iUU8lgLhKdzuSRMqYQQT3O2T` in Chrome using a newly enrolled
nonexportable employee key. The original Incognito session had closed, so its
key was unavailable. A **new local broker database** holds the new enrollment;
the prior database and its task history were preserved. The existing distinct
agent key was registered for the new employee binding with a possession proof
signed inside the agent's macOS Seatbelt process. The new human principal is
`key:sha256:n2TzjzvQY7cyC47GA1pH_uXX-cBza4PGn_z13OhPCeM`; the separate
agent remains `key:sha256:ngUKlHElrvbAobws4WACYio2L-BiqqMomEfMMeCK0dk`.
Google login proved subject `113654555744401103740`; the operator's existing
Jules grant has `openid`, `userinfo.email` and `drive.file` scopes. The agent
received neither that grant nor a Google credential.

The run used the source-free installed 33-wheel Google bundle at
`/private/tmp/ap071-google-source-free-bundle-feedback-20261026`, manifest
SHA-256 `6208d943c0a03999f4881a14449d09cca506c4c095e48eed60561fa6b904da7a`,
gateway SHA-256 `a20fd28c5a7a8c3a96d2bd1a6b3fd9c30dfdcd88466657395cff293a95bf10a7`,
and an offline-installed Python environment outside the checkout. The installed
Google custody processes both passed a live subject/credential probe before
task activation. The agent ran under the [tested Seatbelt boundary](2026-10-26-ap071-macos-installed-agent-isolation.md):
it could read its own key and packages, but not the operator database, gateway
state, Google grant or direct network. This is a development-host isolation
claim, not a production container qualification.

Jules's task allowed one read of pinned Project A source
`1s4aww3jjyJx1os8irP6rOF8oXMGd-I4i_GWGyizqdZ0`, one authenticated release
up to 16 KiB, and at most two exact-confirmed writes in scratch folder
`1pm1kYwjwdmv51zAWfs6QPQYihuxMQ-HZ`. The gateway entered one Google GET,
delivered and durably acknowledged 51 bytes to the separate agent, and charged
one provider call and one release. The private source comparison passed against
SHA-256 `605a3d7e0908275e59d53743fc570418b04acbab9f7184bfdb91670656909335`.
The agent signed a source-backed draft and one create proposal. Jules then
signed the complete two-effect plan before either Google write.

| Independent producer report | Generation | SHA-256 | Observed UTC |
| --- | ---: | --- | --- |
| Setup | 0049 | `b84304ed1a1f2014db48bd03370c5007d92642d6ca0989f284fc2e7b0ac9db07` | 11:14:50 |
| Sibling/source inventory | 0050 | `69a6a642c3ea235d3aa93e005cd31724d6787184f0144aa2a9877da2b4a375bd` | 11:15:42 |
| Zero-match precreate baseline | 0051 | `5d0977a3878b900bce6aa3afb4409895003994133f976ed55a3eaaac1fc1e693` | 12:41:49 |
| Bound blank-child baseline | 0052 | `257ba2ee984f1d4899a14c9c0b63a8a2075e2f5372e9ab2a543e6f9bed23c5a4` | 12:43:24 |
| Provider-final-v2 readback | 0053 | `6627b98cc4aa19d484c818c9d2f72732fbdb8be052b4d398375d9cc0dd37d0ea` | 12:45:36 |

All five reports are under demo_co's private
`companies/atlas-studio/write-evidence/generation-NNNN/` folders. The setup
created the disposable run folder; demo_co made **no** create or population
write in this sequence. The precreate report had zero marker matches and zero
run children. Auths submitted exactly one Google Drive create, received HTTP
200, and its metadata reconciliation bound child
`1kffA_d8rxw_-hRm71oG_XYAMW0tWSvuj-4tLy6p1uro` to that task. The blank
report found exactly one run child and one marker match, with tab `t.0`, an
empty 3-byte BOM-only export, and a pinned blank revision. Jules's fresh
credential-bearing preflight checked the same child and recorded a signed
60-second report before the separate agent signed the population action.
Auths submitted that action once; Google returned HTTP 200.

The final independent export is **148 bytes including the BOM**, SHA-256
`a1fb0c3010e622cee1ac5f85bda4c9865194f2e84bba36196267e2886c2fd54d`.
It exactly matches the signed plan's complete text. The child revision changed;
the run has one child and one marker match; the source and all seven original
siblings remain unchanged. The gateway ledger shows `provider_calls=1`,
`releases=1`, `released_bytes=51`, `writes=2/2`; create is `observed` with HTTP
200 and population is `response-recorded` with HTTP 200. The independent
after-state supplies the exact effect evidence that the population response
alone cannot provide.

The owner-only manifest at
`/private/tmp/ap071-provider-v2-live-20261026/renewed-identity/iUU8lgLhKdzuSRMqYQQT3O2T/provider-v2-evidence.json`
has SHA-256 `e44ac6c3d8c518f1d29c8c968fdbf5f3e9279bf7822a98a8fe9be75131632349`.
The installed owner join verified all five report pins, the signed task and
plan, the acknowledged read, both charged write attempts, the bound child, the
signed preflight and the exact provider after-state. Its redacted verdict is
`joined / exact_populated / retry_authorized=false`, SHA-256
`b95b3bb79fe994148ddb85249088961b33fead36b3d2e64c04728c6b31ff1dfa`.
The Doc remains available for Jules to inspect at
`https://docs.google.com/document/d/1kffA_d8rxw_-hRm71oG_XYAMW0tWSvuj-4tLy6p1uro/edit`.
Jules opened the Doc in Chrome and confirmed the agent-written handoff text is
visible. Jules also loaded task `iUU8lgLhKdzuSRMqYQQT3O2T` in the Chrome
workbench's activity view and confirmed that its provider-effect row appears.
The run folder and Doc are retained for review; no cleanup is claimed.

This proves one installed, source-free positive read/create/populate journey.
Full §9 acceptance still requires the remaining installed negative and
restart/concurrency matrix, plus §6's provider-conformance cases. Those
outstanding cases must not inherit this run's positive verdict.
