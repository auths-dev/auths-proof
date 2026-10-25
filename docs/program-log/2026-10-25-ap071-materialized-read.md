# AP-071 source-backed Jules read, 25 October 2026

Jules signed and activated task `0VG6F0UsVsh0tSaw8aMoBYVu` in Chrome
Incognito. It named the separately registered agent
`key:sha256:ngUKlHElrvbAobws4WACYio2L-BiqqMomEfMMeCK0dk`, one pinned Project A
source, one exact-confirmed Working Doc edit, one read call and release of at
most 16 KiB, one write, and a 30-minute expiry. The local read runtime bound
that agent's identity packet and private Unix release socket before provider
entry. The agent signed operation `qVZI1jxNlXl1xb51QNlgC3DN` in its isolated
directory. No Google credential was included in its package.

The installed gateway reached Google using Jules's subject-bound, source-backed
post-reservation credential materializer. Its result was `agent-acknowledged`.
The durable task status records one provider call, one release, 51 bytes
released, and zero writes. The agent's 51-byte private output has SHA-256
`605a3d7e0908275e59d53743fc570418b04acbab9f7184bfdb91670656909335`,
matching the independent source pin and the gateway's acknowledged release
receipt. The private evidence lives under
`/private/tmp/ap071-materializer-live-v2-20261025` and
`/private/tmp/ap071-jules-local/agent/0VG6F0UsVsh0tSaw8aMoBYVu`.

| Artifact | SHA-256 |
| --- | --- |
| Gateway binary used for this run | `f17084b2796ba7deee148814054f1b3f50beeb8af5ab4e401359fe8ee50460a7` |
| Signed task card file | `61902643fbc22e16a35293d6a3874e9650340e979c93b6853d53f9635c1075fc` |
| Read installation | `4b98815a8224d65c1a1b2d89ea37296062ab8f7afd7ad8948dba44d1e047215b` |
| Write installation | `a85889969c82648c65e1a860427e6c5b217f506d6171277c2b1450a1250a0964` |
| Source-backed materializer installation | `637cbd58739e7f6669294054d5bc9f155b68f3ed6923325d2777cef58947db42` |
| Gateway read result | `72909c610e7fdfe6c7fbebe6b9fc7ab92293875d19935646dcb75b233ae2905f` |
| Gateway task status | `b8acf5b509b063388e5ea11debec12ae2d188764e3c50c67dfdd33457db09def` |

The first local submission refused at setup because `task-read-runtime.json`
had not been configured. It made zero Google calls and charged no release. The
operator then configured the registered agent's read runtime and used a new
agent-signed operation. The successful run above is that second operation;
the task status contains only its one provider call.

A subsequent read-only Jules preflight refused an edit to the same task's
Working Doc because the earlier fixture's sole marker is gone. demo_co's
independent generation-0017 observation also found zero original markers.
There was no provider write in this task. The existing positive exact-edit
run remains the AP-071 write evidence; neither Doc was reset or rewritten to
force a repeated success.

The operator then revoked this task. A fresh gateway status has `revoked=true`,
the same one acknowledged 51-byte read, one provider call, zero writes and no
write operation IDs. Its private status file is
`/private/tmp/ap071-materializer-live-v2-20261025/task-status-after-revoke.json`,
SHA-256 `22e789548146b95eb78f85b5c87af1c42691d14892b62773a6e4adcd7842dba9`.
Revocation stops future task activity; it does not retract the 51 bytes the
agent already received.
