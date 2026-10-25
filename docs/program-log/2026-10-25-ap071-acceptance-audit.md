# AP-071 acceptance audit, 25 October 2026

This records what the current artifacts prove. A successful live milestone is
not the same as full §8–9 acceptance. Use the linked run logs and task journals
for the exact operation IDs, provider statuses and private evidence pins.

| Gate | Current evidence | Remaining acceptance work |
| --- | --- | --- |
| Jules delegates to a distinct agent; agent reads Project A | The [single-plan run](2026-10-25-ap071-live-create.md) includes a Jules-signed task, a separate agent-signed read and a 51-byte authenticated gateway release. Both configured Google source-backed connections now pass a live refresh and UserInfo [readiness probe](2026-10-25-ap071-google-custody-materializer.md) before task signing. | Repeat the installed read with the new source-backed post-reservation OAuth materializer. The first such attempt refused before Google entry because the saved grant's optional account field was empty; the adapter is fixed and synthetically retested, but the spent task cannot be retried. The operator readiness probe does not replace post-admission evidence. |
| Exact Google edit | A [live edit](2026-10-25-ap071-live-edit.md) reached Docs through the gateway and has independent readback. | Qualify the exact installed artifact and complete the required hostile write cases. |
| One-plan Google create and populate | A [later v2 run](2026-10-25-ap071-live-create.md) completed both effects under one Jules-signed plan; demo_co independently verified the populated child and unchanged neighbors. The initial population attempt was denied before entry and manually recovered after a fresh preflight. Auths pins demo_co's v3 baseline/final schemas and its new interim candidate-blank schema; focused consumers test exact pins and tampering. [Read-only live search probes](2026-10-25-ap071-create-search-probes.md) found one existing child by its marker and no child for a never-used marker. The private operator search report requires the original one-create task facts and records distinct zero/one/multiple results without granting authority; one installed smoke on an earlier known create passed. | Capture a live interim producer verdict after a controlled response-less create, implement fresh human-signed recovered-child binding, and run the lost-response cases: one exact match, zero, multiple and incomplete search under an actual unknown-create task. The earlier read-only probes did not simulate response loss or grant recovered-child authority. No further positive create is needed merely to repeat v2. A new create in the now five-child fixture still requires a fresh v3 baseline after plan signing and a live final inspection; neither has run yet. |
| Bounded upfront edit | A [clean rerun](2026-10-25-ap071-clean-upfront-rerun.md) matched demo_co's complete precomputed after-state. | Run the off-choice, second-write and exact-confirmation-only policy refusals with provider request counts. |
| Second HTTPS provider | The [installed Airtable runs](2026-10-25-ap071-airtable-live.md) delivered a field to a separate agent and performed an exact confirmed PATCH with independent readback. Task-excluded resource, wrong recipe digest, changed action after exact confirmation, read and write replay, lost acknowledgement, agent-side wrong recipient, a distinct second upfront write refused by budget, and simultaneous final-write claims against one budget also ran. | Complete the remaining installed cross-provider hostile corpus in §6. The Airtable PAT is not a second human-bound employee account. |
| Provider and task denials | The [finance run](2026-10-25-ap071-finance-denial.md) admitted the signed read and recorded Google's 404 with zero released bytes; the [Project B task test](2026-10-25-ap071-project-b-task-denial.md) stopped before provider entry. Airtable's installed concurrent final-write case admitted one operation and refused the competing one by budget. | Run remaining Google §8 negative cases under pinned installed artifacts, including changed OAuth subject/generation, revision/content races, concurrent final write, unknown write response, restart and provider access loss. |
| Delivery accounting and revocation | Airtable's [lost-ACK run](2026-10-25-ap071-airtable-live.md) retained `delivery-unknown`, charged the bytes and refused replay. A separate [pre-content fault run](2026-10-25-ap071-airtable-no-send.md) recorded `not-delivered`, charged bytes, sent none, and refused replay. Task-excluded reads supplied an installed `not-entered` case. A further installed run staged both signed actions, revoked the task, and refused read and write before provider entry with unchanged counters and record. | Pin the final installed artifacts and exercise the complete Google task activity/revocation journey. These delivery stages were tested in separate disposable runs, not one continuous task; production multi-host revocation remains open. |
| Install and cleanup | The live runs used local development artifacts; Airtable run-owned records were retired. The Google created Docs remain as preserved evidence and demo_co's current inventory has five children. | Publish exact build/recipe/producer pins, complete production custody and qualification, inspect effect links and cleanup status, and run the full suite from pinned installed artifacts. |

The native gateway now verifies the shape and signature of a short-lived,
task-bound operator recovery attestation in a focused synthetic test. The
private operator can generate a distinct recovery signer before task
configuration and sign a joined report from the gateway's original unknown
create facts, Jules's one-candidate search, and demo_co's pinned blank-child
observation. Synthetic tests cover that report and signer setup. No live
operator report, human recovery action, or response-less child binding has
run yet.
The gateway also has a read-only private command that refuses to emit
recovery inputs until the original create is the sole reserved write and its
attempt is `unknown` with no recorded response. The existing recorded-response
loopback test confirms that this command rejects that other path. The same
synthetic fixture now enters one create, drops the response, and accepts only
the original unknown-attempt facts without binding a child. A live unknown
attempt and the signed recovery sequence remain open.
The gateway installation now accepts an optional, separately pinned recovery
signer key and rule digest; the response-less input command requires that pin.
The human recovery confirmation and journal binding are not implemented.

The full spec is **open**. The already verified single-plan Google positive
case must not be reported as missing; conversely, its manual pre-entry recovery
must not be reported as a completed installed recovery workflow. The current
Google source-backed task spent its one read allowance on a fail-closed
materialization refusal, with zero Google requests and zero released bytes.
