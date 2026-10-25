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
canonical JSON object with schema `auths.gateway-task-installation/1`, the
compiled `recipe_digest`, and operator-controlled `pins`: `company_id`,
`human_principal`, `agent_principal`, `agent_key_fingerprint`, `connection_id`,
`connection_generation`, `connection_subject`, `delivery_channel`,
`operator_policy_digest`, and `allow_bounded_writes`. The object is installed
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
now prepares that multi-profile trust and three distinct root-to-employee
grants. It also prepares an employee-signed child grant for the selected
agent's provider write tool. Native synthetic tests cover both this Google
Docs profile and the Airtable write profile. The live operator issuance,
Jules browser signatures and separate agent signing flow still need wiring.
The private `auths-google-task-authority` operator command can now issue an
owner-only package from the current company root seed, its trust manifest,
Jules's enrolled identity and the operator-reviewed recipe profile/digest.
It requires the recipe source and generated profile lock, checks their exact
service, tool, schema digest and task resource field against each other, and
records both file hashes. The compiled recipe digest remains the operator's
reviewed input and is checked again by the gateway at installation. The
command prints only a redacted summary; the package contains signed native
grants and a trust template, no Google credential or human signing key. The browser
and isolated agent must still complete their own signatures.
The [human action helper](../broker/src/employee_read_demo/task_write_proofs.py)
now prepares separate native preimages for a reviewed task card and an exact
closed-write intent. It completes each proof only with a signature from the
enrolled human key, which the browser currently holds. Its card commitment
uses the gateway's domain-separated canonicalization. This is native proof
construction, not a served Jules approval screen or an installed gateway
activation.

`task-activate --state-dir STATE --proof HUMAN.proof --action HUMAN.action`
verifies the human's native signed task and registers its budget once.
`task-submit` then accepts the same task proof/action, one native agent
proof/action, and `--confirmation-proof` plus `--confirmation-action` for
exact mode. It prints a redacted gateway result. Bounded-upfront mode must
have been enabled in the operator pins and is the only mode without a separate
confirmation. These commands refuse production installations while the task
journal is single-host. They are a development integration route, not a
substitute for the human review UI, separate agent process or independent
effect verification.
