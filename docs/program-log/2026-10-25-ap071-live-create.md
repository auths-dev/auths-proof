# AP-071 live Project A create and populate-only continuation

On 25 October 2026, Jules signed a 30-minute task delegating one bounded
Project A read and at most two writes to a separately registered agent. The
agent signed and acknowledged the source read, signed an exact create
proposal, and signed a short draft derived from the released source. Jules
then signed one exact two-effect plan for a Project A handoff Doc and its
complete initial text. The gateway submitted one Google Drive `files.create`
using Jules's held grant and journaled an observed outcome and a bound child.

The child is `17AyVwNPIaKOlfFbOx7rjt76Fgf7k_M8EnWb_4-Cnhj4`, under the
signed Project A folder `1ZtmuBMypwxDZ_onYgV3tspl-_Mzv_8SA`, titled
`Auths AP-071 Project A handoff`, with recovery marker
`ap071_6c707f5bfed71ae8ea8fdcd045d14a20`. The create operation ID is
`CyzLIqfY0DdJMg08dv8EVNTX`. There was exactly one create submission; do
not retry it. The original demo_co pre-create observation is generation 3,
SHA-256 `49693171eab7f3fdd386ad17f85f1181594943ba94bd0eeaae2ef483f9990a2a`,
at 16:45:58 UTC. Google's `createdTime` is 16:46:27.888 UTC, within that
observation's five-minute window.

demo_co independently read the exact child and found the signed title,
parent, shared drive, marker and Google Docs MIME type, one unique marker
match, an exact three-child folder inventory, and no change to the working or
canonical Project A/B Docs. The new child is still blank. Its Docs body has
one section break followed by one paragraph containing only the terminal
newline; Drive's three-byte plain-text export is solely a UTF-8 BOM.

Population did not enter Google. The live task installation omitted the
mandatory `populate_preflight` signer pin, and the original effect plan
expired at 16:48:33 UTC before the omission was discovered. The gateway
returned `gateway.task.preflight-not-installed`. Its journal does not allow
replacing an effect plan after the create, so this plan cannot be silently
extended or reused. The correct continuation is a new, human-approved,
populate-only task scoped to this exact existing child and exact draft, with
a fresh Jules credential-bearing check of metadata, `canEdit`, tab and
revision. It must issue no second create. After one revision-guarded insert,
demo_co should run `google create-inspect` against the original generation 3
baseline and inspect the working Doc and excluded files again.

The broker now refuses to prepare a paired create/populate card without the
preflight pin, accepts the observed blank Docs structure, and gives a newly
signed effect plan a 15-minute execution window bounded by the task expiry.
The signing challenge itself still expires after five minutes. These changes
were exercised by focused broker tests. They do not retroactively change
the signed plan or the live installed gateway state.

A follow-up private setup command now generates the signer seed and canonical
two-recipe installation before a fresh paired task is offered. Its rule digest
pins the installed Google preflight source revision, and the signer refuses a
later source change. This prepares a future single-plan rerun; it does not
alter the blank child or create another one.

## Populate-only continuation

Jules signed a new populate-only task, `MjEVb8hXTcMf1qAh394IEwBQ`, for the
same registered agent and exact existing child. Its budget is one edit, zero
reads and zero creates. The first activation was rejected with
`challenge-mismatch`: the development gateway installation had inadvertently
copied the previous create task's trust context. The private context and
manifest were corrected to the new issued authority before activation; the
task journal was empty. The second activation succeeded. No provider write
was attempted during this repair.

A fresh Jules read-only preflight observed the signed child metadata, marker,
Project A parent, edit capability, blank Docs body, tab and revision. The
separate agent then signed the original 145-byte draft for a single
revision-guarded `documents.batchUpdate`. The broker's gateway review and
fresh preflight presented the complete request for Jules's separate exact
confirmation. No exact-content approval arrived before this task expired at
17:56:11 UTC. The post-expiry status still shows zero writes and no provider
call. The signed proposal must not be submitted under the expired task; a
fresh, reviewed delegation and confirmation are needed for population.

demo_co confirmed its frozen v1 create observation requires exactly three
direct Project A children. The preserved blank child is already the third.
A second create would fail that independent inventory check, even with a new
marker and baseline. Auths will keep the populate-only continuation as the
minimum recovery example. A future fresh single-plan create/populate run
requires demo_co's separately versioned v2 inspector that pins this blank
child as an expected preserved item; Auths will not issue another v1 create.

At 18:09:14 UTC demo_co saved a read-only historical snapshot of the
preserved blank child as producer generation 0004. Its owner-private artifact
is `google-preserved-blank-observation.json` in that generation and its
SHA-256 is
`646fbd37ce9cf18c62c906bc7b68edde95773cb302cb3f793e113b77f8ab85dc`.
The producer reported the exact child ID, parent, marker and three-child
inventory; a structurally blank Google Docs tab; a three-byte BOM-only Drive
export; unchanged working and canonical documents; and Jules's subject.
This is historical provider-state evidence, not an Auths write authorization.
demo_co later committed a frozen v2 baseline and inspector at
`66de1e69a727cf45c5ca9e0a7ee84b899b08bdcc`. They expect the preserved
child alongside a future new child. The v2 baseline must be captured only
after a new signed task and exact plan are ready, because the new Google
`createdTime` must be within five minutes of that baseline. The
populate-only continuation could proceed without erasing the original
blank-state evidence.

## Observed population under a fresh task

At 18:26 UTC, Jules signed task `rMOM0Hn_1FAoOWQve3hcC3j5` for the same
registered agent, with one exact-confirmed edit to the existing child, zero
reads and zero creates. The earlier review challenge had expired; no grant was
signed from that challenge. The new task activated with the same Jules Google
subject and pinned destination. A fresh Jules-subject preflight checked the
child's metadata, Project A parent and marker, `canEdit`, blank Docs tab and
revision. The separate agent signed the original 145-byte draft (SHA-256
`480f253eaa1267aa3d0ce802ff0703dd2057017774f08af53f1ae555ed725ecb`)
for operation `AboQfNlXiYrqV0vXXn-wYkO7`. Jules signed the exact proposal;
the gateway's durable attempt records one `documents.batchUpdate` with HTTP
200 and `response-recorded` at 18:27 UTC. This continuation did not reuse or
extend the expired two-effect plan and did not issue another create.

demo_co then ran its frozen v1 read-only inspector against the **original**
generation-0003 baseline. Its private generation-0005
`google-create-observation.json` has SHA-256
`33066dbac6ea78eed23b0082e4c952b49d2c60093daf3720ef03c8d1566110ec`
and status `ready`. It verified the exact child ID, title, sole Project A
parent, shared drive and unique marker; the exact three-child folder
inventory; unchanged working and canonical Project A/B Docs; and Jules's
Project B write denial. The current Google export is 148 bytes: a three-byte
UTF-8 BOM followed by exactly the agent-signed 145 bytes. Its export SHA-256
is `a1fb0c3010e622cee1ac5f85bda4c9865194f2e84bba36196267e2886c2fd54d`.
Auths' pinned v1 consumer accepted that producer report as
`provider_state_observed`. The separate signed task, agent proposal, human
confirmation and gateway attempt provide the attribution path; the producer
report alone is only provider-state evidence.

This proves the minimum live example of a human delegating a bounded Google
read to an agent, then having that agent create and populate a Project A Doc
through separately approved tasks. It does **not** prove the required
single-plan create/populate run: the first create plan expired before
population, and a new task supplied the final edit. The preserved historical
blank observation remains generation 0004 for a future v2 run.

## Fresh single-plan preparation

At 18:50 UTC, Auths issued a new one-hour private operator authority and
installed a fresh Jules-subject Google write connection, companion populate
recipe and distinct managed read connection in
`/private/tmp/ap071-jules-local/paired-v2-20261025`. The installation pins a
new preflight signer, the original Project A source and folder, one read of
up to 16 KiB, and two exact-confirmed write effects. The short-lived bearer
was verified against Jules's held grant and Google UserInfo; no task was
signed and no Google file was created by this preparation. The Chrome
Incognito workbench now shows the new task card for Jules's review. A new
human task signature and later exact two-effect plan are still required
before asking demo_co for the fresh v2 baseline or entering either write.

At 19:00 UTC, Jules signed fresh task `Gdj7h8pjYv73RhNN7a9wFecV` in
Chrome Incognito after reviewing the pinned agent, Project A source and
folder, one release capped at 16 KiB, two writes, exact approval mode and
30-minute expiry. The task activated in the local gateway. The separate
registered agent signed read operation `ap071-v2-read-b9eeb4f46471cfd6`;
the managed gateway reported `agent-acknowledged`, 51 released bytes and a
keyed content commitment. The private agent listener acknowledged the same
operation and retained those exact bytes locally. The agent then signed a
145-byte citation-bearing draft derived deterministically from the synthetic
source marker, and signed the create proposal for marker
`ap071_7d5aa6321cf7297a5bf5e592de774a8d`. Auths' exact two-effect
review verified the staged signed draft against the acknowledged release.
At this preparation point, no Google write had occurred in the fresh task.

The configured external model route was rejected by automatic approval
review because it would send the private source to `api.openai.com` without
specific destination and payload authorization. The local deterministic
drafting shim kept the source on this host. This run therefore tests agent
isolation, receipt binding and signatures, but does not establish that a
remote model generated the prose.

## Fresh single-plan create and populate result

Jules subsequently signed one exact two-effect plan under task
`Gdj7h8pjYv73RhNN7a9wFecV`, covering one `files.create` in Project A
and one `documents.batchUpdate` to populate only the returned child. The
plan fixed title `Auths AP-071 Project A handoff`, marker
`ap071_7d5aa6321cf7297a5bf5e592de774a8d`, the complete 145-byte
agent-signed text, and the source citation. The task's one read was already
acknowledged by the separate agent; its two-write budget remained available.
demo_co captured fresh v2 pre-create baseline generation 0006 at 19:17:01 UTC,
SHA-256 `8cc5727683453a489f660cc7980b63a05b55c206945ee3d779cac3e83fbdd9af`.
It pinned the earlier created child and the neighboring working Doc as
preserved state. Auths accepted the baseline against private identity and
generation pins before the create.

The gateway entered one Jules-credentialed Drive create. It observed HTTP
200, bound returned child `17A0l1FkogRupzFXrX3aYAIVivAnc0S_IKX98txCefCM`
to the signed plan and charged the first write. The child's Google
`createdTime` was 19:17:19.169 UTC, 18 seconds after the baseline. A fresh
Jules-credentialed preflight checked the child's exact parent, title,
marker, edit capability, blank Docs tab and revision before population.

The first population submission was denied **before provider entry** with
`audience-mismatch`; the installed verifier context defaulted to the Drive
create audience while the companion recipe required Google Docs. The task
journal still showed only the create write and no population attempt. Auths
fixed gateway verification to derive the exact audience from the installed
recipe, retaining the same multi-profile trust context. An offline review of
the agent-signed population action then passed. After a new read-only child
preflight and a fresh agent signature, a controlled direct gateway recovery
submitted the *same human-approved content* once. The gateway recorded HTTP
200 for the Docs response and charged the second write. The broker's
one-shot wrapper remained closed after its original denied attempt; this
recovery was manually reconciled against the no-entry journal rather than
silently retrying an unknown provider outcome. The live patched binary was
SHA-256 `8f7186def4b2585cdf93161956b6dfbbfbd35cbd5ab589d81ae2f2492eee5218`.

demo_co independently ran its frozen v2 inspector against that original
generation-0006 baseline. Generation 0007
`google-create-observation-v2.json` has SHA-256
`6ddec2c52642fba0c0a09fec83fbd0d0be0aaa43fec699adec63c749fea0b7cb`
and status `ready`. It found one new Project A child and a unique marker,
four direct children, the precise 148-byte Drive export (three-byte BOM
followed by the approved 145-byte text), and SHA-256
`a1fb0c3010e622cee1ac5f85bda4c9865194f2e84bba36196267e2886c2fd54d`.
The preserved child, working Doc and canonical Project A/B Docs matched the
pre-create state, and Jules was still denied Project B write. Auths' pinned
v2 consumer accepted the three independent producer stages as
`provider_state_observed`. The producer's report proves provider state; the
task proof, agent proofs, exact human plan and gateway attempts supply the
separate authorization and action chain.

This passes the live **single-plan Google create/populate example**, with a
documented pre-entry recovery. It remains a local development run. The
manual gateway recovery must be integrated into a reviewed operator flow,
and full AP-SPEC-071 acceptance still requires bounded-upfront execution,
the mandatory negative matrix, cross-provider conformance and pinned
installed artifacts. No cleanup has occurred; demo_co owns run fixture
cleanup.

After the live run, the development planned-population command gained an
explicit `--recover-pre-entry-denial` path. It requires the first command's
durable `denied` result, a different fresh preflight, and a gateway task
status showing exactly the create operation and no population write claim.
It records an exclusive recovery handoff before resubmission. Unknown
results or any existing population claim remain closed. Unit tests cover
both permitted recovery and those refusals. This code did not execute the
live population above; that recovery was manually checked and submitted.
