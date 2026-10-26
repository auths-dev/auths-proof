# AP-071 acceptance audit, 25 October 2026

This records what the current artifacts prove. A successful live milestone is
not the same as full §8–9 acceptance. Use the linked run logs and task journals
for the exact operation IDs, provider statuses and private evidence pins.

| Gate | Current evidence | Remaining acceptance work |
| --- | --- | --- |
| Jules delegates to a distinct agent; agent reads Project A | The [single-plan run](2026-10-25-ap071-live-create.md) includes a Jules-signed task, a separate agent-signed read and a 51-byte authenticated gateway release. Both configured Google source-backed connections passed a live refresh and UserInfo [readiness probe](2026-10-25-ap071-google-custody-materializer.md). A [fresh installed task](2026-10-25-ap071-materialized-read.md) used the source-backed post-reservation materializer: one Google provider call, one 51-byte `agent-acknowledged` release to the distinct agent, and a gateway receipt matching the independently pinned source digest. | Carry the local artifact pins into the final evidence manifest. The earlier failed materializer task remains a separate fail-closed result. |
| Exact Google edit | A [live edit](2026-10-25-ap071-live-edit.md) reached Docs through the gateway and has independent readback. | Qualify the exact installed artifact and complete the required hostile write cases. |
| One-plan Google create and populate | A [later v2 run](2026-10-25-ap071-live-create.md) completed both effects under one Jules-signed plan. The [v3 response-less run](2026-10-25-ap071-live-response-less-recovery.md) proved the single-candidate recovery path, but its gateway binary changed during the run. The [v4 rerun](2026-10-26-ap071-v4-response-less-create.md) used one fixed build and one Jules-signed task for a source-backed read, response-less create, fresh Jules recovery signature, one child binding, one population write and independent exact final readback. Separate [zero-match](2026-10-26-ap071-zero-match-create-refusal.md), [multiple-match](2026-10-26-ap071-multiple-match-create-refusal.md) and [incomplete-search](2026-10-26-ap071-incomplete-search-create-refusal.md) runs refused recovery, retries and population, with strict independent provider joins. The [population-denial run](2026-10-26-ap071-populate-denial-recovery.md) proved the same child remained blank after Auths rejected a changed signed action before Google entry, then accepted one fresh-preflight recovery with exact independent readback and no second create. The [post-entry response-loss run](2026-10-26-ap071-populate-post-entry-unknown.md) returned `unknown` after one successful Google response; demo_co found the exact content on the same child, and no retry occurred. | Complete the remaining hostile matrix and production qualification. The [fresh provider-final-v2 run](2026-10-26-ap071-provider-final-v2-live.md) now qualifies the revised positive read/create/populate path on a source-free installed bundle. Complete the remaining hostile matrix. Automatic approval review rejected a live replay submission because it could repeat an entered Google write; local one-shot and gateway tests cover refusal. |
| Bounded upfront edit | A [clean rerun](2026-10-25-ap071-clean-upfront-rerun.md) matched demo_co's complete precomputed after-state. A later [one-grant negative run](2026-10-26-ap071-bounded-upfront-negative.md) refused an unlisted option, recorded one listed Google HTTP 200 edit with an independently matched 93-byte complete after-state, and refused a second listed write by budget before provider entry. A separate exact-only policy pin variant refused task-card construction before any grant or provider request. | The policy variant was checked at owner-side construction, not in a second configured gateway deployment. Production qualification remains. |
| Second HTTPS provider | The [Airtable runs](2026-10-25-ap071-airtable-live.md) delivered a field to a separate agent and performed an exact confirmed PATCH with independent readback. Task-excluded resource, wrong recipe digest, changed action after exact confirmation, read and write replay, lost acknowledgement, agent-side wrong recipient, a distinct second upfront write refused by budget, and simultaneous final-write claims against one budget also ran. A source-free [bundle builder and runner](../../demos/airtable-gateway/read_reference/README.md) pin the gateway, wheels, runner and recipes and remove checkout imports. Its 33-wheel bundle installed offline, refused a wrong manifest pin and altered recipe, and completed the initial [five live installed Airtable cases](2026-10-26-ap071-airtable-source-free-installed.md). Four further source-free cases exercised [read and write restart boundaries](2026-10-26-ap071-installed-release-crash.md) and [two-task isolation](2026-10-26-ap071-airtable-two-task-swap.md). A tenth [no-content case](2026-10-26-ap071-installed-no-content.md) charged the release without sending source bytes. An eleventh [rotated-generation case](2026-10-26-ap071-installed-rotation.md) refused an otherwise valid exact write before provider entry after the installed credential generation changed. A twelfth [isolated Linux container case](2026-10-26-ap071-container-read-write.md) completed a source-free managed read and exact write with independent Airtable after-state. A thirteenth [release-key rotation case](2026-10-26-ap071-release-key-rotation.md) privately matched the same acknowledged field after an installed key rotation and completed one independently observed write. All thirteen runs retired their own records and are joined to artifact pins in the [case manifest](2026-10-26-ap071-installed-case-manifest.json). | Complete the remaining installed cross-provider hostile corpus in §6 and the Google create/populate cases. The PAT is not a second human-bound employee account. |
| Provider and task denials | The [finance run](2026-10-25-ap071-finance-denial.md) admitted the signed read and recorded Google's 404 with zero released bytes. The [same-credential Project B test](2026-10-26-ap071-project-b-same-credential-exclusion.md) used a Jules `drive.readonly` connection that independently read Project B, yet Auths refused the agent's excluded request before Google entry; the same task then delivered Project A. Airtable's installed concurrent final-write case admitted one operation and refused the competing one by budget. | Run remaining Google §8 negative cases under pinned installed artifacts, including changed OAuth subject/generation, revision/content races, concurrent final write, restart and provider access loss. |
| Delivery accounting and revocation | Airtable's [lost-ACK run](2026-10-25-ap071-airtable-live.md) retained `delivery-unknown`, charged the bytes and refused replay. A separate [pre-content fault run](2026-10-25-ap071-airtable-no-send.md) recorded `not-delivered`, charged bytes, sent none, and refused replay. A later [source-free rerun](2026-10-26-ap071-installed-no-content.md) repeated that boundary with a pinned fault-enabled gateway and retired its disposable record. Task-excluded reads supplied an installed `not-entered` case. A further installed run staged both signed actions, revoked the task, and refused read and write before provider entry with unchanged counters and record. The [materialized Jules read task](2026-10-25-ap071-materialized-read.md) was revoked after its acknowledged release and a failed write preflight; its final status preserves one call, 51 released bytes and zero writes. The [v4 completed task](2026-10-26-ap071-v4-response-less-create.md) was revoked; replayed signed read and write actions were refused as inactive with its ledger unchanged. A [fresh zero-use Google task](2026-10-26-ap071-google-unspent-revocation.md) rejected a signed read and create after revocation without spending a call or write. The local owner activity view now joins charged writes to matching durable attempt stages, including different recipe namespaces in one task. | Stage an otherwise executable **exact-confirmed** Google write, revoke before provider entry, and check the independent unchanged provider state. The zero-use create had no signed effect plan. Join the activity timeline to independent effect observations and qualify production multi-host revocation. |
| Install and cleanup | The historical Google live runs used local development artifacts; Google created Docs remain as preserved evidence. A [source-free Google bundle](2026-10-26-ap071-google-source-free-prep.md) pins the revised gateway, custody executable, native/broker/agent wheels and recipes, and installed offline without checkout imports; the [refreshed bundle](2026-10-26-ap071-provider-final-v2-live.md) then completed a Jules-signed Google task and independent exact-content inspection. An [AP-071 installed Linux boundary probe](2026-10-26-ap071-container-boundary.md) ran the digest-pinned gateway and agent images, denied agent access to gateway/operator state and provider egress, and passed a cross-container owner-private Unix socket exchange. A later [source-free container case](2026-10-26-ap071-container-read-write.md) ran one managed read and exact-confirmed write in the same topology. Thirteen [source-free Airtable cases](2026-10-26-ap071-installed-case-manifest.json) used pinned gateway, wheels, runner and recipes; all run-owned records were retired. A [macOS installed isolation run](2026-10-26-ap071-macos-installed-agent-isolation.md) denied the agent direct credential, state and network access while its managed read/write completed. | The revised Google task and producer v2 observation passed on the pinned bundle, and Jules opened the created Doc and saw the activity effect row. Run the remaining hostile suite from pinned installed artifacts. Production custody and deployment qualification remain separate. |

The native gateway verifies a short-lived, task-bound operator recovery
attestation and a new human recovery action. The [live v3 run](2026-10-25-ap071-live-response-less-recovery.md)
now exercises the complete single-candidate path against Google, including
an original `unknown` attempt with no locator, independent producer blank
observation, fresh Jules signature, metadata recheck, recovered binding,
single population write and final provider inspection. The gateway's
read-only recovery-input command still refuses recorded-response attempts.
Its loopback tests cover altered evidence, changed human candidate and replay.
The single-candidate success is complemented by separate zero-match,
multiple-match and injected incomplete-search refusal runs.
demo_co's [v4 six-to-seven-child contract](2026-10-26-ap071-v4-producer-contract.md)
was exercised in the [fixed-build live run](2026-10-26-ap071-v4-response-less-create.md):
baseline generation 0021, blank child 0022 and exact final observation 0023
all passed Auths's strict v4 consumer.

The full spec is **open**. The v4 run demonstrates one live single-candidate
recovery with one fixed gateway build. The separate zero-match run dropped the
create before provider entry and proved zero-candidate refusal; the
multiple-match run suppressed one real Google create response and proved
ambiguous-candidate refusal. The incomplete-search run suppressed another
real create response, then injected an Auths search-completeness fault and
refused to bind the independently observed blank child. The controlled
population-denial run completed the distinct pre-entry denial and same-child
recovery case. The separate post-entry response-loss run established Auths
`unknown` and independently observed exact Google content without retry.
These runs do not prove production qualification. An earlier
source-backed task spent its one read allowance on a
fail-closed materialization refusal, with zero Google requests and zero
released bytes. The later installed task completed the materialized Google
read, but its companion Working Doc edit was not submitted after a read-only
preflight found the pinned marker absent. Those outcomes remain distinct from
the successful edit, create/populate and response-less recovery runs.

The development gateway now retains versioned owner-private release audit
keys and selects an acknowledged receipt's recorded version for private
comparison. A focused rotation test covers durable candidate reuse and an
unsafe historical key. A [source-free Airtable case](2026-10-26-ap071-release-key-rotation.md)
now verifies an acknowledged seven-byte release across two gateway processes
and a key rotation, then completes one independently observed exact write and
retires its record. Production key custody and retention remain unqualified.

The 26 October local review fixes reject ordinary application observations and
generic operator reobservation for task-bound recipes before a credential lease.
The application-socket regression uses an excluded Airtable record and checks
that the unsigned request cannot return its value; a revoked task cannot make
the generic reobservation path eligible. Read execution now reloads task state
before credential leasing, after the lease, after materialization and before
provider entry. Local loopback cases revoke during materialization and during
a static credential lease; both retain one spent call, release no bytes and
send no provider request. Recorded create-response reconciliation now checks
the original proof at the durable attempt's evaluated time while requiring the
task to remain active at recovery; both a recorded effect-plan case and an
exact-confirmed case restart and bind the original child after their action
proofs expire, without replaying create. These source and loopback results
do not replace the installed isolation, crash and provider-negative gates above.

The [custody process cutover](2026-10-26-ap071-custody-process-cutover.md)
removes Google OAuth and demo_co producer parsing from the shared gateway
executable. A digest-pinned Google sidecar passed two live Jules identity
probes through the new installed interface in a disposable gateway state.
A separate installed Airtable PAT custody process then completed two live
read/write runs through the same unchanged gateway interface and retired both
records; its first attempt failed before provider entry for an unresolved
reason. A fresh Google task under the new gateway and sidecar remains open.
The [installed macOS isolation run](2026-10-26-ap071-macos-installed-agent-isolation.md)
then applied an OS Seatbelt profile to every source-free agent command. The
agent-side probe denied direct credential/state reads, outbound network and
writes outside agent storage; the same agent completed one provider read and
write through the gateway and its disposable record was retired. This closes
the scoped local isolation evidence gap. Production isolation and multi-host deployment remain unqualified.

A [source-free installed Airtable crash run](2026-10-26-ap071-installed-release-crash.md)
now exits the gateway process at the durable read-release entry before a
content byte. The restarted gateway preserved one provider call, seven
charged bytes and `delivery-unknown`, then refused same-operation redelivery.
The same log records a second source-free process exit after the isolated
agent saved the exact content but before the gateway recorded its ACK. The
restarted gateway retained `delivery-unknown` and refused replay. The
same installed runner then exercised a real exit after a durable
exact-confirmed Airtable write reservation and before attempt claim. On
restart, activity reported one spent write at `claimed-no-attempt`; replay was
refused and an independent provider GET showed no effect. Its disposable
record was retired. This closes that specific write-journal interleaving;
other installed hostile cases remain open.

The [source-free two-task Airtable run](2026-10-26-ap071-airtable-two-task-swap.md)
then activated two independently signed tasks on one installed read/write
connection pair. Swapping a signed read or write across task IDs and using the
write namespace for a read all stopped before gateway provider entry. Both
tasks subsequently delivered their own acknowledged seven-byte read, with
one charged provider call each and zero writes. The independent record
remained unchanged and was retired. Plan, child and preflight swaps remain
unverified in the installed create/populate vertical.

The [redacted installed-case manifest](2026-10-26-ap071-installed-case-manifest.json)
joins thirteen source-free Airtable cases to their bundle-manifest digests, task
IDs, redacted receipt digests and verified cleanup states. Its absolute
`/private/tmp` paths identify evidence on this host; the pin values survive
if those disposable local artifacts are later removed. This manifest does
not include the PAT, released field bytes or private provider responses.

The [provider-final v2 consumer](2026-10-26-ap071-provider-final-v2-consumer.md)
vendors demo_co's forward-only dynamic inventory and final-observation
schemas at reviewed SHA-256 pins. It accepts an exact synthetic final state
and refuses source, child, baseline, content and retry swaps. A new gateway
lineage readout identifies the journal-bound preflight signature; the private
task/provider join checks that signature, native task/plan commitments,
charged reads and writes, and exact attempt stages. This source and loopback
evidence does not prove that Auths entered Google under the revised recipe; a
fresh Jules-signed installed run remains. The owner workbench now conditionally
recomputes the private producer/task join and shows a redacted effect row and
checked-child link, but this path has passed synthetic tests only, not a live
v2 provider observation.

## 26 October provider-final-v2 update

The [fresh installed Google run](2026-10-26-ap071-provider-final-v2-live.md)
supersedes the two historical “fresh run remains” statements above. Jules
enrolled a new browser key after the original Incognito key was lost, signed a
bounded task and exact two-effect plan, and the isolated separate agent read
the 51-byte Project A source, created one Doc, then populated it through the
revised `provider_values` recipe. The owner-side join of the gateway task
journal and demo_co generation-0053 report returned `joined /
exact_populated / retry_authorized=false`. The independent 148-byte export
matched the signed content, and Jules opened the resulting Doc and saw the
handoff text. This closes the revised-recipe **positive** create/populate
case. The remaining hostile matrix, installed cross-provider conformance and
production qualification in §9 remain separate acceptance gates.

### Remaining installed proof, after the revised positive run

| Case | Current proof | Next decisive observation |
| --- | --- | --- |
| Owner activity view | The private owner join returns `joined / exact_populated`; the new Doc's signed content was independently exported and opened by Jules. Jules confirmed that the Chrome workbench displays the provider-effect row for the task. | A production activity service and its deployment controls are a separate qualification claim. |
| Exact-confirmed revocation | The [installed planned-population run](2026-10-26-ap071-revoked-planned-populate.md) staged a signed action and fresh Jules preflight, revoked while that preflight was valid, and got `gateway.task.inactive`; demo_co independently found the bound child still blank with the same revision. | The direct refusal may have occurred just after the 60-second preflight expired. Capture an attempted-entry timestamp inside a valid preflight window to isolate revocation from expiry. |
| Google subject/generation change | Credential parsers reject a wrong subject; an installed Airtable task refused a rotated generation. | Rotate or substitute a disposable Google installation after task signing and show denial before entry under that task, without changing Jules's preserved grant. |
| Google edit races | An earlier live exact edit and clean bounded-upfront edit have independent after-state. Source tests cover changed actions and revision fields. | On a disposable Doc, independently change the revision after exact confirmation; require provider conflict with no approved edit and inspect the final content. Also present a changed content action and require pre-entry refusal. |
| Provider access loss | The finance run proves denial for a file Jules never had; it does not prove loss after task signing. | Use a disposable, previously readable file whose Jules access is withdrawn after task activation; show one admitted provider request, denial, zero release and independent access state. |
| Create/populate substitutions and restart | Gateway reference tests reject wrong child/content/preflight facts; the v4 live run proves unique response-less recovery, and Airtable installed cases prove release/write restart boundaries. | Run the current installed create/populate artifact against crossed task/plan/child/preflight evidence and restart boundaries, recording zero unintended Google effects. |
| Second HTTPS provider corpus | Thirteen source-free Airtable cases cover positive read/write, task exclusion, replay, lost acknowledgement, no-content send, rotation, concurrent final write, process crashes, two-task swaps and isolation. | Complete the remaining installed response-shape, origin, oversize and recipient substitutions under the same read/write contract; retain independent before/after provider checks. |

These are acceptance cases, not invitations to replay the completed Google
create or population. The completed task spent both write slots and its result
must be preserved as evidence. Production deployment qualification remains a
separate claim from completing this dedicated live demo.
