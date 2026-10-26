# AP-071 acceptance audit, 25 October 2026

This records what the current artifacts prove. A successful live milestone is
not the same as full §8–9 acceptance. Use the linked run logs and task journals
for the exact operation IDs, provider statuses and private evidence pins.

| Gate | Current evidence | Remaining acceptance work |
| --- | --- | --- |
| Jules delegates to a distinct agent; agent reads Project A | The [single-plan run](2026-10-25-ap071-live-create.md) includes a Jules-signed task, a separate agent-signed read and a 51-byte authenticated gateway release. Both configured Google source-backed connections passed a live refresh and UserInfo [readiness probe](2026-10-25-ap071-google-custody-materializer.md). A [fresh installed task](2026-10-25-ap071-materialized-read.md) used the source-backed post-reservation materializer: one Google provider call, one 51-byte `agent-acknowledged` release to the distinct agent, and a gateway receipt matching the independently pinned source digest. | Carry the local artifact pins into the final evidence manifest. The earlier failed materializer task remains a separate fail-closed result. |
| Exact Google edit | A [live edit](2026-10-25-ap071-live-edit.md) reached Docs through the gateway and has independent readback. | Qualify the exact installed artifact and complete the required hostile write cases. |
| One-plan Google create and populate | A [later v2 run](2026-10-25-ap071-live-create.md) completed both effects under one Jules-signed plan. The [v3 response-less run](2026-10-25-ap071-live-response-less-recovery.md) proved the single-candidate recovery path, but its gateway binary changed during the run. The [v4 rerun](2026-10-26-ap071-v4-response-less-create.md) used one fixed build and one Jules-signed task for a source-backed read, response-less create, fresh Jules recovery signature, one child binding, one population write and independent exact final readback. | Run zero-match, multiple-match and incomplete-search lost-response cases under installed unknown-create tasks, plus the remaining hostile matrix and production qualification. |
| Bounded upfront edit | A [clean rerun](2026-10-25-ap071-clean-upfront-rerun.md) matched demo_co's complete precomputed after-state. | Run the off-choice, second-write and exact-confirmation-only policy refusals with provider request counts. |
| Second HTTPS provider | The [installed Airtable runs](2026-10-25-ap071-airtable-live.md) delivered a field to a separate agent and performed an exact confirmed PATCH with independent readback. Task-excluded resource, wrong recipe digest, changed action after exact confirmation, read and write replay, lost acknowledgement, agent-side wrong recipient, a distinct second upfront write refused by budget, and simultaneous final-write claims against one budget also ran. | Complete the remaining installed cross-provider hostile corpus in §6. The Airtable PAT is not a second human-bound employee account. |
| Provider and task denials | The [finance run](2026-10-25-ap071-finance-denial.md) admitted the signed read and recorded Google's 404 with zero released bytes; the [Project B task test](2026-10-25-ap071-project-b-task-denial.md) stopped before provider entry. Airtable's installed concurrent final-write case admitted one operation and refused the competing one by budget. | Run remaining Google §8 negative cases under pinned installed artifacts, including changed OAuth subject/generation, revision/content races, concurrent final write, unknown write response, restart and provider access loss. |
| Delivery accounting and revocation | Airtable's [lost-ACK run](2026-10-25-ap071-airtable-live.md) retained `delivery-unknown`, charged the bytes and refused replay. A separate [pre-content fault run](2026-10-25-ap071-airtable-no-send.md) recorded `not-delivered`, charged bytes, sent none, and refused replay. Task-excluded reads supplied an installed `not-entered` case. A further installed run staged both signed actions, revoked the task, and refused read and write before provider entry with unchanged counters and record. The [materialized Jules read task](2026-10-25-ap071-materialized-read.md) was revoked after its acknowledged release and a failed write preflight; its final status preserves one call, 51 released bytes and zero writes. The [v4 completed task](2026-10-26-ap071-v4-response-less-create.md) was revoked; replayed signed read and write actions were refused as inactive with its ledger unchanged. A [fresh zero-use Google task](2026-10-26-ap071-google-unspent-revocation.md) rejected a signed read and create after revocation without spending a call or write. | Stage an otherwise executable **exact-confirmed** Google write, revoke before provider entry, and check the independent unchanged provider state. The zero-use create had no signed effect plan. Production multi-host revocation remains open. |
| Install and cleanup | The live runs used local development artifacts; Airtable run-owned records were retired. The Google created Docs remain as preserved evidence; demo_co's v3 final observation found six Project A children after the response-less recovery run. | Publish exact build/recipe/producer pins, complete production custody and qualification, inspect effect links and cleanup status, and run the full suite from pinned installed artifacts. |

The native gateway verifies a short-lived, task-bound operator recovery
attestation and a new human recovery action. The [live v3 run](2026-10-25-ap071-live-response-less-recovery.md)
now exercises the complete single-candidate path against Google, including
an original `unknown` attempt with no locator, independent producer blank
observation, fresh Jules signature, metadata recheck, recovered binding,
single population write and final provider inspection. The gateway's
read-only recovery-input command still refuses recorded-response attempts.
Its loopback tests cover altered evidence, changed human candidate and replay.
The single-candidate success does not establish the zero/multiple/incomplete
search refusal cases. demo_co's [v4 six-to-seven-child contract](2026-10-26-ap071-v4-producer-contract.md)
was exercised in the [fixed-build live run](2026-10-26-ap071-v4-response-less-create.md):
baseline generation 0021, blank child 0022 and exact final observation 0023
all passed Auths's strict v4 consumer.

The full spec is **open**. The v4 run demonstrates one live single-candidate
recovery with one fixed gateway build; it does not prove zero, multiple or
incomplete search refusals or production qualification. An earlier
source-backed task spent its one read allowance on a
fail-closed materialization refusal, with zero Google requests and zero
released bytes. The later installed task completed the materialized Google
read, but its companion Working Doc edit was not submitted after a read-only
preflight found the pinned marker absent. Those outcomes remain distinct from
the successful edit, create/populate and response-less recovery runs.
