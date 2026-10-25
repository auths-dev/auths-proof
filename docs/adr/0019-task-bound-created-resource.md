# ADR 0019: Bind a created resource to one human-agent task

**Status:** Proposed for AP-SPEC-071. The gateway can now validate a bounded,
operator-approved connection descriptor containing two to four task-bound
recipe digests and their reviewed HTTPS origins for one credential. Task
activation checks a closed installed recipe set against that connection. A
development installation can load the Google edit and create recipes with one
connection and task journal. The human-signed card can now name a pending
child proposal with the exact create operation, parent, title, marker and
reviewed create/populate digests. Activation requires both digests to be
installed, and create admission compares the signed values; the pending
proposal is not an executable populate scope. A reviewed create declaration now extracts one
bounded child ID from a complete successful response and retains it as a
candidate in the attempt journal across restart. The reviewed observation
path can address that candidate and now compares ID, sole parent, title,
marker and operator-pinned literals from a bounded metadata GET. Generic
re-observation refuses created-child recipes after restart. A dedicated
reconciliation path now re-verifies the original native agent action and exact
human confirmation, compares the recorded attempt commitment and recipe, and
repeats only the credential-bearing metadata GET for a complete recorded
response. A matched, credential-bearing metadata
observation now commits an immutable child binding to the same task journal as
the reserved create. A lost or mismatched observation leaves no binding. The
binding now yields a one-time edit scope for the reviewed populate recipe:
a fresh native agent action and exact human confirmation must still match that
scope before entry. This closes the recorded-response crash gap between the
attempt and task journals in synthetic tests. A response lost before recording
still needs the separate recovered-child flow below. This ADR
authorizes no production claim by itself.

A test-only Todoist create recipe now exercises the same compiler and metadata
comparison with a scalar project parent on a second HTTPS domain. Google Drive
still uses a sole-parent array. No Todoist credential or live child effect has
been tested.

**Date:** 25 October 2026

## Context

AP-SPEC-071 asks one human to approve an agent task that creates an artifact
and then fills it. The human can approve the destination folder, title and
initial content before the new provider ID exists. Google Drive returns an
ID only in a complete create response; after network entry with a lost
response, the artifact might exist while Auths has no ID. ADR 0013's
response locator can feed a read-only observation path, but it does not
authorize a later write to that locator.

The task card can list several write scopes. The development installer can
now load two reviewed write recipes with one connection and task journal.
That closes the installation topology, but not the child-ID authorization
between create and populate. Two independent installations with separate
task journals would still have separate counters and cannot implement one
two-effect task.

## Proposed decision

### A closed created-child declaration

An operator-reviewed create recipe may declare one `created_child` response
mapping. It names a JSON pointer to a bounded provider ID in a **complete
2xx** write response, a maximum ID byte count, and the signed request fields
that named the parent, title and recovery marker. The compiler requires each
request field to be consumed by the closed write body, validates the pointer
and ID grammar, and shows the mapping in recipe review. It binds the mapping
into the recipe digest. The agent cannot choose the pointer, destination
field, provider URL or interpretation at runtime. No declaration means no
created-child authority, even if an ordinary ADR 0013 response locator is
present.

The mapping yields a **candidate** child ID, not a usable task resource. A
credential-bearing, reviewed metadata read must confirm the candidate's
provider subject, parent, title, type and marker against the signed create
request before promotion. This read is a fixed, bounded recipe capability;
Google field names and meaning stay in its vertical. A 2xx create response
alone cannot prove those properties. The independent demo_co inspector then
checks the provider's actual state without becoming an Auths authority
issuer.

### One task ledger and a pending child scope

The human-signed task card names a create scope for an existing parent and a
pending child scope tied to the exact create operation ID and reviewed
populate recipe digest. The pending scope has no arbitrary file ID or
wildcard. All installed recipe engines for this task use the same durable
task journal, write budget, revocation flag, company/agent pins, connection
subject and generation checks. A recipe cannot be added to an already
activated task by an agent or by changing an operator file in place.

The gateway durably reserves the create write before transport entry. After
a complete response, it records the response status/digest and candidate ID
in the attempt journal, then performs the fixed metadata check. Once the
check passes, it commits an immutable child binding in the task journal:
task-card commitment, create operation ID, create recipe digest, request
commitment, response digest, child ID, provider subject/generation and
verification evidence digest. If the process crashes between these journals,
reconciliation re-verifies the original native actions, reads the already
recorded attempt and reruns the metadata check; it never re-enters the create.
This dedicated path is implemented for complete recorded responses, including
a crash after the matching observation but before the task-journal bind. No
binding is inferred from an
unrecorded response or an arbitrary operator-supplied ID.

For population, the fresh agent action may name only the child ID in that
binding. The gateway checks it before reserving the second write, then
derives the exact closed request. The ordinary exact-confirmation path can show the actual child ID and complete initial content. The planned path now consumes one earlier human effect plan with a signed, fresh child preflight in a synthetic loopback test; installed Google execution remains. The shared
task budget charges create and populate separately.
An unsuccessful or unknown populate leaves an incomplete artifact and does
not authorize another create.

**One-ceremony product contract still to implement.** The initial task card
may be signed before the agent has drafted the content, so it cannot pretend
to approve later text. After the draft, a distinct human-signed effect plan
must commit to the exact closed create request, the complete initial text (or
a private commitment to those exact bytes), the one reviewed populate recipe,
the same task/card/agent, the maximum of one create and one population, and a
short expiry. Custody durably records that plan before create entry. The
successor file ID is not a wildcard: it must be the one child subsequently
bound from the response and metadata read above. Before population, a fresh
credential-bearing Docs read under the same Jules subject must supply the
single tab and required revision; the agent action must match that tab,
revision, bound ID, recipe and planned text bytes. This permits one human
confirmation of both effects while preserving the provider's stale-revision
check. A lost create response or ambiguous recovery cannot inherit this plan
as permission to populate an unbound ID. The synthetic gateway path now accepts
one signed effect plan for both writes, while the ordinary separate exact
confirmation path remains available. The installed Google journey has not
exercised the one-ceremony path.

A native verifier and private journal transition now accept one effect-plan signature over the closed create intent, one populate recipe and operation, exact initial text and expiry. The journal records a private content digest and byte length before any write, refuses a changed plan, and accepts identical evidence after restart. The owner-side authority package can issue the separate human grant. The create admission path can now consume the exact recorded plan without a second human confirmation, and recorded-response reconciliation can use that immutable plan after a metadata-read failure. Population now requires a fresh, signed preflight bound to the child and consumes the recorded plan in the synthetic gateway path. The following checks remain the execution contract for installed Google execution.

The reviewed populate recipe now declares its text, tab and revision fields, and the compiler excludes other provider-affecting profile fields from this planned request. A native comparison helper rejects changed content, child, tab, operation or expiry against the plan and proposed preflight facts. The gateway now authenticates an operator-pinned signed report, journals its short-lived facts, and consumes them with the recorded human plan in a synthetic two-effect loopback test. A private operator bridge derives the signer's task, plan and child inputs from the gateway journal. The owner browser can prepare Jules's effect-plan signature from a native-reviewed create action and a private draft envelope signed by the registered agent. Before review, it requires an acknowledged task read and a private gateway comparison of the signed draft's source digest and staged source file against the gateway's keyed commitment to the actual release bytes. Neither the content nor a plain digest enters the redacted status. The later agent-signed populate action must match Jules's approved bytes. Installed key custody, a live Jules run and independent effect inspection remain.

The plan format and commit points are part of that future implementation:

1. A new native `confirm_agent_effect_plan_v1` action signs the task-card
   commitment, verified create action and closed request commitments, create
   operation ID, reviewed create and populate recipe digests, complete initial
   content bytes or a private digest **and length**, one fixed populate
   operation ID, one create plus one population, and an expiry no later than
   the task. The UI renders the actual content and destination before signing.
   Neither the plain digest nor a low-entropy content excerpt enters a public
   receipt. The gateway verifies the human chain and stores the plan durably
   in the shared task journal **before** reserving or entering create. A
   changed plan for that task is refused, including after restart.
2. The operator-reviewed populate recipe declares exactly which profile
   fields are late bound: the task-bound child ID and the fields produced by a
   named, bounded credential-bearing preflight recipe. Every other profile
   argument that can affect the closed request, including the initial text,
   is fixed by the signed plan. The compiler verifies that the declared
   fields are actually consumed by the closed request and that no undeclared
   agent-controlled field can change its method, URL, query, headers or body.
   The agent cannot select the preflight recipe or supply its result.
3. The gateway records the preflight result in the same task journal, bound to
   the immutable child ID, provider subject and generation, recipe digest,
   observed response digest, checked time and a short validity window. The
   Google vertical's preflight rule rejects nonblank or nested Docs content,
   extra tabs and denied `canEdit`, and extracts only the actual Jules tab ID
   and revision. Another provider supplies its own reviewed extraction rule;
   the core only handles typed fields and their provenance. Population
   admission reconstructs the entire closed request from the fresh agent
   action, then compares the fixed fields with the plan and each late-bound
   field with its stored source. It reserves the second write only after all
   comparisons pass. A stale preflight or changed revision fails before
   transport entry; the provider's own revision precondition remains the
   final concurrency check.
4. A recorded create response is not enough if the task-journal child-binding
   commit failed. The implemented dedicated reconciliation command requires
   the original agent proof/action and either the original exact human
   confirmation or the previously recorded effect plan. After restart, it
   re-verifies the agent action and the human authority already in the task
   journal, checks the stored
   attempt and response locator, redoes the reviewed metadata GET under the
   subject-bound connection, and performs the same one-time journal
   transition. It performs **no create**. A lost response
   follows the separate signed recovered-child path below. Neither path can
   use an arbitrary operator-supplied child ID as its proof source.

### Lost response and recovered child

A lost or incomplete create response leaves the attempt `outcome_unknown` and
no child binding. A reviewed, bounded provider search may nominate candidates
by the signed run marker, but an empty search is not proof of non-effect and
does not permit a retry. A recovery read must exhaust its configured pages
and result cap, reject incomplete search, and independently confirm one
candidate's ID, parent, title, type, marker and account. Multiple or zero
candidates remain unknown. demo_co's read-only inspector is independent
provider-state evidence, not authority to populate.

Exactly one fully checked candidate may be presented to the human. A fresh
human signature must bind its ID and evidence digest to the original task,
create operation, title, parent and content commitment. Only then may the
task journal record an immutable `recovered` child binding, distinct from a
`response-derived` binding. Neither path retries create automatically.

The development recovery handoff has two separately pinned observations:
Jules's bounded, complete marker search with a fresh exact-ID metadata GET,
and demo_co's independent blank-candidate observation tied to the original
pre-create baseline. The operator-side join compares the one candidate's ID,
marker, parent, drive, Jules subject/generation, baseline and original task
operation. This join remains evidence, never child permission. Before a
gateway binding is possible, a domain-separated operator attestation must
commit the exact search-report and producer-observation digests, candidate ID,
task/plan/create-operation commitments, connection subject/generation and a
short validity window. The human's **new native recovery action** must commit
that attestation digest, candidate ID, original title/parent and the already
approved initial-content commitment. It cannot reuse the original effect-plan
signature as the recovery signature.

The gateway must verify the operator attestation and native human action,
reload the original task and one claimed create, establish that no response ID
was recorded and no child is already bound, then make a fresh credential-
bearing metadata GET with the same subject/generation and reviewed observation
template. It must compare the returned child against the signed create fields
and the recovered candidate before one atomic task-journal bind with
`source: recovered` and the evidence commitments. It must never synthesize a
response digest from the marker or call create again. If the original task or
effect plan has expired, this same-task binding fails; any later populate
requires a newly signed, exact child-specific task as a separate continuation,
which cannot retroactively make the original two-effect plan successful.

The gateway now has a canonical Ed25519 verifier for the proposed operator
attestation format. It checks the pinned key, task/card and effect-plan
commitments, original create action and request commitments, signed pending
child fields, connection subject/generation, candidate ID, hashes of Jules's
search report and demo_co's blank-candidate observation, baseline and
candidate metadata, and a validity window of at most 90 seconds. Its output
is evidence only. The signer, native human recovery action, fresh metadata
read and task-journal `recovered` transition are still to be implemented; the
verifier alone cannot create a child scope.

The private `task-create-recovery-inputs` command now reads the active task,
immutable plan, one reserved create and durable attempt before the operator
prepares any candidate attestation. It emits the original commitments and
signed parent/title/marker only when the attempt projects to `unknown` and
has no recorded status, response digest or response locator. It labels the
output `authority: none` and makes no provider request. A recorded response
must use the response-derived reconciliation path. This is a prerequisite for
the recovery signer, not a recovery bind. A loopback fixture now sends one
create request, drops its response, and confirms that the durable attempt
projects to `unknown`, the command exposes only the original task facts, and
no child scope appears. It does not establish that any provider effect
occurred, nor does it test live recovered-child population.

The installation can now pin a separate recovery-attestation public key and
reviewed rule digest. The private unknown-create input record includes their
commitments. Existing installations without that pin cannot enter this
recovery handoff. This pin is distinct from the populate-preflight signer;
the operator-side evidence signer still needs implementation.

### Cleanup and receipts

Activity reports separate create entry, response recording, child binding,
population entry, observation and unknown outcomes. A child binding is not a
claim that population happened. The public recovery marker is correlation
metadata, not ownership or deletion authority. Cleanup is a separate
human/operator action after evidence capture and requires an independently
verified exact child ID and provider deletion/trash outcome. The current
demo_co reset deliberately refuses an unregistered Auths child.

## Gates before implementation is accepted

1. The compiler and operator review expose only the bounded declaration;
   hostile recipes reject an arbitrary pointer, extra response fields,
   unconsumed request fields, oversized IDs, redirects and runtime queries.
2. A single durable task ledger enforces the combined create/populate budget,
   replay and revocation across two reviewed write recipes and one provider
   connection. Crash tests cover every response-recording and binding boundary.
3. A response loss yields no child permission and no create retry. Zero,
   multiple, incomplete and mismatched recovery searches never populate.
4. Google and an independent second HTTPS domain exercise the same binding
   code through test-only vertical oracles. Neither adds a provider branch to
   the gateway. Production qualification still follows ADR 0013's evidence
   rule and the accepted domain boundary plan.
5. The live Jules run proves native task approval, agent create, exact human
   confirmation, provider entry, response-derived or separately confirmed
   recovered binding, population and demo_co's independent observation on
   pinned installed artifacts. Failed cleanup remains explicit.

## Alternatives rejected

An agent-supplied file ID after create would turn the second write into an
unreviewed destination. A folder label as a wildcard does the same. A second
gateway state directory with its own task counter can exceed the human's
combined effect budget. A marker search alone cannot prove uniqueness or
non-effect, and a public marker cannot authorize cleanup. A provider-specific
callback in the gateway would make the shared executor depend on Google.
