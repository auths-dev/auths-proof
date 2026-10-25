# AP-071 acceptance audit, 25 October 2026

This records what the current artifacts prove. A successful live milestone is
not the same as full §8–9 acceptance. Use the linked run logs and task journals
for the exact operation IDs, provider statuses and private evidence pins.

| Gate | Current evidence | Remaining acceptance work |
| --- | --- | --- |
| Jules delegates to a distinct agent; agent reads Project A | The [single-plan run](2026-10-25-ap071-live-create.md) includes a Jules-signed task, a separate agent-signed read and a 51-byte authenticated gateway release. Both configured Google source-backed connections passed a live refresh and UserInfo [readiness probe](2026-10-25-ap071-google-custody-materializer.md). A [fresh installed task](2026-10-25-ap071-materialized-read.md) used the source-backed post-reservation materializer: one Google provider call, one 51-byte `agent-acknowledged` release to the distinct agent, and a gateway receipt matching the independently pinned source digest. | Carry the local artifact pins into the final evidence manifest. The earlier failed materializer task remains a separate fail-closed result. |
| Exact Google edit | A [live edit](2026-10-25-ap071-live-edit.md) reached Docs through the gateway and has independent readback. | Qualify the exact installed artifact and complete the required hostile write cases. |
| One-plan Google create and populate | A [later v2 run](2026-10-25-ap071-live-create.md) completed both effects under one Jules-signed plan. The [v3 response-less run](2026-10-25-ap071-live-response-less-recovery.md) entered one Google create, suppressed its successful response, joined Jules's unique-marker search with demo_co's independent blank-child observation, obtained a new Jules recovery signature, bound only that child after a fresh metadata GET, and populated it once under the original plan. demo_co independently verified the exact final text, six-child inventory and unchanged neighbors. | Run zero-match, multiple-match and incomplete-search lost-response cases under installed unknown-create tasks, plus the remaining hostile matrix and production qualification. |
| Bounded upfront edit | A [clean rerun](2026-10-25-ap071-clean-upfront-rerun.md) matched demo_co's complete precomputed after-state. | Run the off-choice, second-write and exact-confirmation-only policy refusals with provider request counts. |
| Second HTTPS provider | The [installed Airtable runs](2026-10-25-ap071-airtable-live.md) delivered a field to a separate agent and performed an exact confirmed PATCH with independent readback. Task-excluded resource, wrong recipe digest, changed action after exact confirmation, read and write replay, lost acknowledgement, agent-side wrong recipient, a distinct second upfront write refused by budget, and simultaneous final-write claims against one budget also ran. | Complete the remaining installed cross-provider hostile corpus in §6. The Airtable PAT is not a second human-bound employee account. |
| Provider and task denials | The [finance run](2026-10-25-ap071-finance-denial.md) admitted the signed read and recorded Google's 404 with zero released bytes; the [Project B task test](2026-10-25-ap071-project-b-task-denial.md) stopped before provider entry. Airtable's installed concurrent final-write case admitted one operation and refused the competing one by budget. | Run remaining Google §8 negative cases under pinned installed artifacts, including changed OAuth subject/generation, revision/content races, concurrent final write, unknown write response, restart and provider access loss. |
| Delivery accounting and revocation | Airtable's [lost-ACK run](2026-10-25-ap071-airtable-live.md) retained `delivery-unknown`, charged the bytes and refused replay. A separate [pre-content fault run](2026-10-25-ap071-airtable-no-send.md) recorded `not-delivered`, charged bytes, sent none, and refused replay. Task-excluded reads supplied an installed `not-entered` case. A further installed run staged both signed actions, revoked the task, and refused read and write before provider entry with unchanged counters and record. The [materialized Jules read task](2026-10-25-ap071-materialized-read.md) was revoked after its acknowledged release and a failed write preflight; its final status preserves one call, 51 released bytes and zero writes. | Pin the final installed artifacts and exercise a fresh Google read and write challenge after revocation. These delivery stages were tested in separate disposable runs, not one continuous task; production multi-host revocation remains open. |
| Install and cleanup | The live runs used local development artifacts; Airtable run-owned records were retired. The Google created Docs remain as preserved evidence and demo_co's current inventory has five children. | Publish exact build/recipe/producer pins, complete production custody and qualification, inspect effect links and cleanup status, and run the full suite from pinned installed artifacts. |

The native gateway verifies a short-lived, task-bound operator recovery
attestation and a new human recovery action. The [live v3 run](2026-10-25-ap071-live-response-less-recovery.md)
now exercises the complete single-candidate path against Google, including
an original `unknown` attempt with no locator, independent producer blank
observation, fresh Jules signature, metadata recheck, recovered binding,
single population write and final provider inspection. The gateway's
read-only recovery-input command still refuses recorded-response attempts.
Its loopback tests cover altered evidence, changed human candidate and replay.
The single-candidate success does not establish the zero/multiple/incomplete
search refusal cases.

The full spec is **open**. The v3 run proves one live single-candidate recovery;
it does not prove zero, multiple or incomplete search refusals or production
qualification. An earlier source-backed task spent its one read allowance on a
fail-closed materialization refusal, with zero Google requests and zero
released bytes. The later installed task completed the materialized Google
read, but its companion Working Doc edit was not submitted after a read-only
preflight found the pinned marker absent. Those outcomes remain distinct from
the successful edit, create/populate and response-less recovery runs.
