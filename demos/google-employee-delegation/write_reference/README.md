# Google Docs edit reference for AP-SPEC-071

This is a **synthetic request-shape reference**, not an installed Google
write or a producer fixture. The generated [profile lock](profile.lock.json)
and [recipe](recipe.json) compile through the existing, provider-neutral
`auths-gateway` write recipe compiler. The focused Rust test constructs the
exact `POST /v1/documents/{document_id}:batchUpdate` request and checks its
bounded JSON body. The recipe has no provider-specific production code.
Its `field-suffix` path segment is a closed, operator-visible mechanism under
[ADR 0018](../../../docs/adr/0018-typed-path-field-suffix.md); a compiled
reference is not production qualification.

The v2 action includes the signed task ID and task-card commitment, then names
one document, one tab, one unique literal marker, replacement text and the
revision Jules observed near confirmation. The recipe fixes a
single, case-sensitive `replaceAllText` request with `searchByRegex: false`
and `writeControl.requiredRevisionId`. Its body admits no second request,
runtime URL, arbitrary JSON object or alternative write control. The signed
Auths task and exact human confirmation must bind these action fields, the
connected Jules subject/generation and the recipe digest before the gateway
may use a credential. A valid recipe by itself grants no access.

The generated action profile's conservative 4 KiB canonical-argument bound
limits document IDs to 64 bytes, tab IDs to 16 bytes, the marker to 48 bytes,
replacement text to 192 bytes and revision ID to 128 bytes. The task and
operation IDs are each limited to 32 bytes. demo_co must export the
**observed** lengths from a new run-owned, single-tab working Doc and refuse
unsupported lengths rather than truncating or substituting an ID. Existing
Atlas Docs have 44-byte file IDs, but that does not establish the future
working Doc or revision lengths.

Google's [batchUpdate reference](https://developers.google.com/workspace/docs/api/reference/rest/v1/documents/batchUpdate)
defines `requiredRevisionId`; its
[request reference](https://developers.google.com/workspace/docs/api/reference/rest/v1/documents/request#ReplaceAllTextRequest)
defines tab-scoped `replaceAllText`. A stale required revision refuses the
write at Google. The present gateway records a complete response status and
digest, but does **not** inspect `replies[0].replaceAllText.occurrencesChanged`.
It also cannot prove the provider honored the write-control semantics from
the JSON shape alone. Before the live edit milestone, a reviewed generic
response assertion must record the count of exactly one without exposing the
private response body, or the installed test must obtain equivalent
provider-signed response evidence. demo_co must independently compare the
working Doc's revision and content after entry and verify that canonical and
excluded Docs did not change. A 2xx response alone is not an observed edit.

The v2 recipe declares a provider-neutral `task_binding` for its document field
and edit verb. The gateway refuses ordinary proof/action submission for this
recipe before any claim or lease. Its task-aware engine path verifies
the signed card, agent action and exact confirmation, charges the durable task
write budget, and binds the loaded connection ID, generation and account
subject before a credential lease. A development-only, operator-owned CLI
can configure private pins, activate a signed task, and submit its agent and
confirmation proofs; the human task UI and isolated agent path are still
required for live use. The broker can privately refresh and verify Jules's
separate `drive.file` grant. A development-only
[credential shim](../broker/src/employee_read_demo/google_gateway_credential_shim.py)
now pipes a checked, short-lived bearer into a new gateway installation with
the Google UserInfo `sub` as account label. It has synthetic secret-custody
tests; no live gateway installation or edit has run. Her saved read-only grant
is insufficient.
The shim requests the gateway's opt-in, secret-free `--connection-json` install
result and returns its generated connection ID and credential generation. The
operator uses those returned values in the task installation and in the
post-install Jules credential pins used by preflight. A malformed successful
install result is an unknown setup outcome: inspect that gateway state before
trying another installation.
demo_co owns the folder, working Doc, ACL, consent probes and versioned export;
Auths owns authority, connection custody, recipe admission and receipts.
The [write handoff shim](../broker/src/employee_read_demo/write_handoff.py)
validates a digest-pinned producer generation and its independent probes but
stays `write_not_configured` until the installed Auths task gate, credential
lease, fresh preflight and independent post-write inspection are wired.
The broker's read-only [Google preflight](../broker/src/employee_read_demo/google_write_preflight.py)
checks the current Jules subject, working Doc ACL, one tab, revision and exact
baseline before an edit proposal; it has passed against the private Atlas
generation and does not perform a write.

## Operator-side development route

`auths-gateway task-configure --state-dir STATE --from PINS.json` accepts one
canonical JSON object with schema `auths.gateway-task-installation/2`, the
compiled `recipe_digest`, and operator-controlled `pins`: `company_id`,
`human_principal`, `agent_principal`, `agent_key_fingerprint`, `connection_id`,
`connection_generation`, `connection_subject`, `delivery_channel`,
`operator_policy_digest`, `allow_bounded_writes`, and
`permitted_read_scopes`. The current write-only route sets
`permitted_read_scopes` to `[]`. Each signed task scope carries its own
connection ID, generation, subject, and recipe digest; the write scope must
match the installed write connection. The object is installed
once as a mode-0600 file in the owner-private gateway state directory. The
gateway derives the resource field and verb from its already installed recipe;
the agent cannot submit these pins. The Auths connection's account label must
be the provider's stable Jules UserInfo `sub` so its stored account commitment
matches the task subject. demo_co confirmed that `jules_subject`, rather than
email, is the canonical subject in its write evidence.
The installed native trust must admit the recipe's provider action plus both
`auths-agent-task` tools, `approve_agent_task_v1` and
`confirm_agent_write_v1`. The task session refuses missing task-profile trust
before activation or provider entry.
The broker's [task authority builder](../broker/src/employee_read_demo/task_write_authority.py)
now prepares that multi-profile trust and distinct root-to-employee grants
for task approval, exact confirmation and the reviewed write. When the
operator supplies a reviewed release recipe, it adds a separate human-to-agent
read grant under the same trust context. Native synthetic tests cover Google
and Airtable read/write tool pairs. The operator issuance command,
Jules browser signing screens and isolated agent signer are implemented;
their live use still needs the operator to install the matching trust and
credential, then Jules to sign the exact task and edit.
The private `auths-google-task-authority` operator command can now issue an
owner-only package from the current company root seed, its trust manifest,
Jules's enrolled identity and the operator-reviewed recipe profile/digest.
It requires the recipe source and generated profile lock, checks their exact
service, tool, schema digest and task resource field against each other, and
records both file hashes. The compiled recipe digest remains the operator's
reviewed input and is checked again by the gateway at installation. The
operator can obtain the read digest and bounded GET policy offline with
`auths-gateway review-release --recipe ... --profile-lock ...` before supplying
`--read-recipe`, `--read-profile-lock`, `--read-service`, `--read-tool` and
`--read-recipe-digest` together to the authority command. These options issue
a mixed task package; omitting them issues a legitimate write-only task. The
command prints only a redacted summary; the package contains signed native
grants and a trust template, no Google credential or human signing key. The
browser and isolated agent sign through their separate paths. A live Jules
task and agent proposal have not yet been completed.
The [owner-side package loader](../broker/src/employee_read_demo/task_write_package.py)
now checks the private file's exact schema, lifetime, gateway verifier
configuration, provider audience and operator challenge before any browser
preimage is prepared. A changed challenge in the package is refused.
The AP-070 workbench accepts an optional write ceremony only when all seven
operator paths are supplied: `--task-write-authority`,
`--task-write-installation`, `--task-write-recipe`,
`--task-write-profile-lock`, `--task-write-output-dir`,
`--task-write-evidence`, and `--task-write-pins`. The evidence and pins are
private snapshots inside the owner-only output directory, so a live browser
run does not read demo_co's mutable checkout. The pins file is a private JSON
encoding of `WriteHandoffPins`; the evidence remains the producer's exact
versioned export. A mixed task also supplies `--task-read-recipe` and
`--task-read-profile-lock`; its operator installation must pin the separate
Jules-owned `probe_document_id` as the source and the working `document_id` as
the destination. The screen prepares a card from the active Jules enrollment,
registered agent, installed gateway pins and reviewed recipe. It signs the
task and separate read/write child grants in Jules's browser, writes
`task.proof` and `task.action` under a new private task directory, and exports
public agent packages. The isolated agent can use `sign-read` to sign a bounded
read action and `serve-release` to acknowledge delivered content. Managed read
execution still requires an installed read connection, qualification and
operator command; the signed package alone does not release content.
With the optional `--task-write-gateway-state-dir`, the workbench activates
that signed task immediately in the owner-private gateway journal. Without
that option, the operator activates it through `task-activate`. A separate
exact confirmation is still required before any provider write.
For the separate confirmation screen, the operator also supplies
`--task-write-gateway-bin` and its SHA-256 in
`--task-write-gateway-sha256`, plus the private Jules grant and matching
credential pins through `--task-write-grant` and
`--task-write-credential-pins`. After the isolated agent signs, its
`agent.proof` and `agent.action` are staged as mode-0600 files in that task's
owner-private output directory. The screen runs the pinned gateway binary's
`review-submission` command on those files and the pinned recipe and trust,
shows Jules the complete credential-free method, URL and body, then signs the
exact derived intent. The broker runs the pinned, read-only Jules
revision/ACL/baseline preflight both before rendering and when accepting her
signature, and refuses a proposal whose Doc, tab, marker or revision differs.
It saves `confirmation.proof` and `confirmation.action` privately. With the
optional gateway state directory, the screen presents a separate
“Submit this confirmed edit” control. It re-verifies the agent proposal and
Jules’s Google subject, ACL, Doc identity, baseline and revision just before
`task-submit`; Google’s signed `requiredRevisionId` refuses an intervening
revision change. The workbench returns only a redacted gateway outcome and
never retries an uncertain submission. Independent demo_co readback remains
required before claiming the intended edit was observed. Without the optional
state directory, activation and submission remain operator CLI steps.
The [human action helper](../broker/src/employee_read_demo/task_write_proofs.py)
now prepares separate native preimages for a reviewed task card and an exact
closed-write intent. It completes each proof only with a signature from the
enrolled human key, which the browser currently holds. Its card commitment
uses the gateway's domain-separated canonicalization. This is native proof
construction; the served approval screens still need a live Jules run and
installed gateway activation.
The isolated [agent write signer](../agent/src/employee_read_agent/write.py)
can now sign a reviewed profile action under the human's completed child
grant. `auths-google-read-agent sign-write` writes private proof and action
files; its package contains public grant/evidence bytes, operator challenge,
task commitment and recipe digest, with no human key or Google token. The
broker's [child-grant helper](../broker/src/employee_read_demo/task_write_delegation.py)
now verifies Jules's signature against her enrolled public key and produces
that public package. The owner-scoped browser task flow rechecks active
enrollment, registered agent, task card and operator pins at completion.
After the agent signs, `auths-gateway review-submission` can verify its native
proof offline and render the exact credential-free method, URL, headers and
body. The [exact intent projection](../broker/src/employee_read_demo/task_write_intent.py)
binds that review to the signed task card and reviewed recipe, then computes
the same domain-separated closed-request commitment that the gateway checks
on submission. It does not claim or send the request. The optional Jules screen
renders this projection and obtains her separate exact confirmation after the
agent proof is staged. Its live use still needs the preflight repeated at
gateway entry and independent effect evidence.
The private authority package pins a fresh 32-byte operator challenge into
the installed trust context. It pins the gateway's MCP policy verifier
configuration, exposed by the native Python binding; the older self-contained
read context has a different configuration ID and cannot be installed for
this write path. Human and agent actions for that installation
must sign that same challenge; the gateway does not accept an agent-selected
challenge. The operator verifies the human's short-lived task action once
at activation and stores its exact card commitment in the private journal.
Later submissions use that durable activation while checking current task
expiry, revocation and operator pins.
The current browser task lasts at most 30 minutes; each agent proposal and
exact confirmation has at most five minutes and must be renewed if review
runs longer.

`task-activate --state-dir STATE --proof HUMAN.proof --action HUMAN.action`
verifies the human's native signed task and registers its budget once.
`task-submit --task-id TASK_ID` then accepts one fresh native agent
proof/action, and `--confirmation-proof` plus `--confirmation-action` for
exact mode. It prints a redacted gateway result. Bounded-upfront mode must
have been enabled in the operator pins and is the only mode without a separate
confirmation. These commands refuse production installations while the task
journal is single-host. They are a development integration route, not a
substitute for the human review UI, separate agent process or independent
effect verification.
