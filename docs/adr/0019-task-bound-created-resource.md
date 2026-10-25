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
path can address that candidate; its name comparison is not the metadata
verification required below. There is still no child-resource binding or
population authorization. This ADR authorizes no production claim by itself.

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
reconciliation may only read the already recorded attempt and rerun the
metadata check; it never re-enters the create. No binding is inferred from an
unrecorded response or an arbitrary operator-supplied ID.

For population, the fresh agent action may name only the child ID in that
binding. The gateway checks it before reserving the second write, then
derives the exact closed request. In the default mode the human signs a new
exact confirmation showing the actual child ID and complete initial content;
this confirmation must match the signed two-effect proposal's content
commitment. The shared task budget charges create and populate separately.
An unsuccessful or unknown populate leaves an incomplete artifact and does
not authorize another create.

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
