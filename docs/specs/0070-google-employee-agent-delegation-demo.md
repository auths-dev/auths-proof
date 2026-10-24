# AP-SPEC-070: Employee-to-agent Google read delegation

- **Status:** Design specification; implementation and acceptance evidence are required.
- **Date:** 24 October 2026.
- **Scope:** A customer-hosted Mac + Google Workspace demonstration, backed by the `demo_co` company environment, in which an employee delegates bounded document reads to a distinct agent.
- **Depends on:** [AP-SPEC-051](0051-self-hosted-developer-profiles.md), [AP-SPEC-052](0052-self-hosted-launch-hardening.md), [AP-SPEC-039](0039-enterprise-coordination-and-operations-plane.md), [ADR 0012](../adr/0012-declarative-credential-isolated-gateway-boundary.md), and the [domain boundary plan](../target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md).
- **Environment contract:** `demo_co/docs/specs/0001_initial_spec.md`, `demo-co/connections/v1` and `demo-co/scenario-result/v1`. This is a versioned external contract, not a mutable sibling-repository dependency.
- **Normative language:** MUST, MUST NOT and SHOULD define implementation requirements. Proposed demo API/type names below do not claim existing public APIs.

## 1. Decision and product promise

Build a complete employee-to-agent read journey using real Auths delegation and native verification, actual Google employee OAuth authorization, and an independently provisioned demo company.

The employee signs in with Google, connects their own Drive authorization, registers an employee Auths principal and authorizes a distinct agent to read selected work documents for a short task. The agent receives Auths authority and holds its own signing key. It receives no Google access token, refresh token, employee password, controller key or permission to choose a provider credential.

The effective access boundary is:

```text
Google access of the actual connected employee
  ∩ operator's company policy
  ∩ verified employee-to-agent Auths delegation
  ∩ selected task resources, operations, validity and limits
```

Google remains the authority for its resource ACLs. Auths does not copy a supposedly complete employee ACL into a grant and assume that it stays current. Provider calls use that employee's authorization, so a valid Auths proof cannot confer Google access the employee lacks.

The first useful task is **summarize project A from selected Google Drive documents**. The demonstration must distinguish three outcomes: useful authorized work; refusal of an employee-accessible document outside the task; and refusal by Google after the employee loses access to a document inside an otherwise valid task.

This establishes the supported integration's behavior and measured installation effort. It does not prove universal enterprise adoption, prevent disclosure of information already retrieved, or complete the formal-assurance program in [AP-SPEC-069](0069-authorization-to-execution-formal-assurance.md).

### 1.1 Runtime classification

V1 is an **application-owned read broker using the AP-SPEC-051 exact-action path**, deployed separately from the untrusted agent. The maintained broker application is part of the demo. It uses the real native Auths verifier and sealed command bindings; its provider mapping, OAuth custody, task state and response release are application responsibilities tested here.

This is an explicit process/credential-isolation claim for this deployment. It is not a qualified general-gateway execution claim. Do not put a provider-specific executor into a reference vertical, load a Google callback into the credential-owning write gateway, or portray the gateway's existing observation GETs as a complete employee read product. All production provider writes remain data-only gateway recipes under ADR 0012; this demo exposes none.

Productizing this broker as an Auths-managed credential service is separate work with architecture, custody, compliance and deployment evidence. V1 must be usable with the stated self-hosted boundary rather than depending on that future product.

## 2. Inspected starting point and required additions

The current checkout provides the following reusable mechanisms. Source presence establishes an implementation starting point, not qualification of this new journey.

| Existing source | Reusable behavior | Work required here |
| --- | --- | --- |
| `core/crates/auths-authority/src/lib.rs` | Downward authority attenuation over subject, profile, permissions, audience, validity, depth and action constraints | Construct a real company → employee → agent chain with independently provisioned trust |
| `core/crates/auths-author/src/lib.rs` | Child-grant planning and explicit authority differences | Employee enrollment, task review, key-possession binding and grant authoring through installed SDKs |
| `core/crates/auths-model/src/lib.rs` | `AllowedBodyDigests`, exact actor/challenge binding and bounded authority carriers | Commit a finite reviewed task to exact canonical read calls; no `AnyBody` agent grant |
| `product/profiles/auths-profile-mcp/src/lib.rs` | Canonical `auths.mcp/2` calls, derived tool permission/audience and sealed `McpCommand` projection | One closed Google document-read tool and strict verified-argument decoding |
| `bindings/python/src/mcp.rs` | Native sealed commands and MCP execution/session bindings | Consume the actual command once; integrate durable admission and the application-owned response boundary |
| `product/runtime/auths-connections/` | Credential references, opaque leases and generation mechanisms | Compare contracts before reuse; employee OAuth linking/refresh is an additional integration, not an existing Google connection |
| `product/runtime/auths-gateway/src/transport.rs` | Bounded read primitives for the gateway's declared reads/observations | A reference for limits and transport risks; do not expose its private read port or broaden it into a generic proxy |
| `demo_co` spec 0001 | Company personas, resource handles, real Google ACLs, independent expectations and exported connections | Implement/import the contract and run actual consumer tests; the environment spec is not a running company |

V1 requires no new core profile, generic JSON policy language or global axiom. Missing thin SDK exposure must be added in `bindings/` over the native implementation, rather than reimplementing verification in Python or JavaScript. The commercial coordination plane remains owned by AP-SPEC-039; the demo is a customer-hosted reference journey.

## 3. Scope and explicit exclusions

Required:

- A Mac operator/browser workflow and one dedicated Google Workspace demo company, initially `atlas-studio` from `demo_co`.
- Real Google OIDC login and separate employee-authorized Drive access.
- A company-rooted employee principal, a distinct agent principal, a reviewed task grant and actor-signed exact read actions.
- Up to eight explicitly selected documents per task, with a finite set of approved canonical calls, short expiry and durable aggregate limits.
- A useful agent-generated summary with source references and independently checked facts.
- A guided frontend, CLI/SDK example, dedicated evidence page, real process isolation, revocation and adversarial scenarios.
- A second employee with different permissions and a second locally configured company to exercise namespace/identity isolation. Independent-Google-customer isolation requires a second real tenant before that narrower claim can pass.

Not required in V1: arbitrary Drive search, recursive folder delegation, live discovery after approval, Gmail, Google Calendar, Microsoft 365, native Apple app access, SQL/OLAP agent access, background indexing, subagents, multi-host service operation or writes. `demo_co` SQL/OLAP/OIDC services remain available to other demos but do not silently become extra agent tools here.

Google-connected mode is required for the customer demonstration. Mock/local-provider mode remains useful for development and must label live-provider steps `not_configured` or `skipped`, never passed. A scripted tool exerciser is a test harness; the useful-work acceptance run uses an actual agent that selects its permitted reads and produces the summary.

## 4. Ownership and repository layout

The implementation remains in the Auths monorepo:

```text
auths-proof/
├── demos/google-employee-delegation/
│   ├── README.md
│   ├── compose.yaml
│   ├── versions.lock.json             # Installed SDK/image and external contract identities
│   ├── broker/                       # Application-owned trusted read service
│   │   ├── pyproject.toml
│   │   ├── src/employee_read_demo/
│   │   │   ├── app.py
│   │   │   ├── enrollment.py
│   │   │   ├── google_oauth.py
│   │   │   ├── task_authority.py
│   │   │   ├── read_executor.py
│   │   │   ├── admission.py
│   │   │   ├── receipts.py
│   │   │   └── demo_co_contract.py
│   │   └── tests/
│   ├── agent/                        # Separate untrusted agent process/container
│   ├── web/                          # Employee review, task controls and evidence UI
│   ├── cli/                          # Same installed-SDK journey without the frontend
│   ├── contracts/                    # Task/read/evidence schemas and synthetic vectors
│   ├── scenarios/                    # Independent positive/negative cases
│   └── evidence/                     # Redacted reproducible report templates
├── bindings/                         # Only necessary thin native API additions
├── core/fixtures/                    # Canonical vectors if an existing wire contract changes
├── compliance.toml                   # Register the maintained demo and claimed evidence
└── docs/specs/0070-google-employee-agent-delegation-demo.md
```

The broker uses an installed, version-bound Python SDK with its native extension. The frontend/agent use the public authoring interfaces appropriate to their language. The default setup must not compile Auths from a mutable adjacent checkout. Published/pinned artifacts and explicit developer exports are supported; runtime sibling path dependencies are not.

`demo_co` owns fixture provisioning, baseline provider probes and company reset. Auths owns proof authoring/verification, task delegation, broker isolation and consumer evidence. An imported fixture expectation cannot grant authority or supply the broker with an administrator credential. The demo must not seed data, change employee ACLs or create Google users during normal onboarding.

No new shipping crate is justified merely by this demo. If implementation discovers a reusable production component, move it to the lowest valid product/binding layer only after its contract and extraction evidence satisfy repository policy. Register every package and consumer through the normal architecture/compliance machinery.

## 5. `demo_co` integration contract

### 5.1 Import and operator enrollment

The operator exports a `demo-co/connections/v1` bundle for one instance/company and imports it through a separate operator interface. Import is read-only with respect to company/provider resources.

Validate schema/version, size, definition hash, instance/company IDs, required capability status and resource/identity mappings. The operator explicitly pins the expected Google Workspace tenant domain/customer mapping, approved file catalog, dataset version and bundle digest. Reject duplicate or ambiguous provider bindings.

Treat the bundle as untrusted data until accepted by the operator. It cannot install a trust root, choose an OAuth issuer/JWKS URL, redirect a credential-bearing request, replace verifier configuration or override Google identity verification. Google identity/API/token origins are pinned application configuration, independent of bundle URLs.

The broker imports logical resources, actual Drive IDs and presentation metadata. Existing `credential_refs` are hints for configuration discovery, not permission to resolve `demo_co`'s administrator/provisioner secrets. Each employee completes the broker's own OAuth connection. The employee's actual Google `sub`, Directory ID and fixture person ID remain distinct mapped identifiers.

Required bundle capabilities are `google_workspace` ready, real Drive resource mappings and an independently verified access-matrix version. Local SQL/OIDC readiness is not a substitute. Do not accept a local Keycloak token as a Google employee sign-in.

### 5.2 Contract gap and versioned companion artifact

> **Implementation handoff note (24 October 2026):** `demo_co` is being built in
> its own active session. It has now published versioned connection,
> access-expectation and scenario-result schemas plus local-mode examples; the
> Auths demo pins their schema digests and validates all three artifact types.
> The current exports explicitly report Google as `not_configured` and contain
> no live Google baseline, so the importer refuses activation. The current
> consumer shim accepts operator-pinned JSON exports and independent scenario
> files, then records a closed company import; it does not call `demo_co` at
> runtime or synthesize missing provider IDs. Extend this
> boundary only when the producer supplies live mappings and independent
> provider probes. Do not infer a
> Google Drive ID, identity binding, ACL result or passing live status from
> local fixture definitions. This note is an integration TODO, not an
> acceptance exception.

> **OIDC schema handoff (24 October 2026):** The producer added optional public
> `oidc_clients` metadata to `connections-v1` (schema SHA-256
> `d6bb90825e989e893a26f4a86d1fb17d6f40fa29b72ea0794093eef67686c10d`).
> This consumer pins the revised schema and accepts old exports with the field
> absent. OIDC metadata remains outside Google employee identity and cannot
> activate this read demo. The producer's generation-0013 local export now
> validates against the pinned schema and still reports Google
> `not_configured`; the broker does not synthesize its public client mapping
> or treat ready local PostgreSQL/ClickHouse/OIDC as Google readiness.
> `demo_co` also publishes a `google-verification-v1` schema; its future live
> artifact should be pinned and checked alongside the scenario-result shim
> before replacing that shim with a direct verification import.

> **Agent scenario handoff (24 October 2026):** The producer's revised
> `scenario-result-v1` schema (SHA-256
> `137f92fc1d347df09e047f79a6ea27b0accc6784cbcc3dc7dcb277bc275caba0`)
> now has optional agent, delegation, delegated-resource, action and boundary
> fields. This consumer pins that schema and its local non-ready example. The
> fields describe independent scenario evidence; they never create an Auths
> grant or mark a local Google step passed. The producer still owns actual
> scenario execution and evidence export. The pinned schema also requires a
> passing result to have matching expected/observed allow or deny values and
> nonempty evidence references. Generation-0013's bundle digest is
> `3df1eeadc7c0d3b1520d5d8bcd9ee8d1ae2b091c51641134401c98b9a643a1b2`;
> the consumer validates it but reports Google `not_configured`.

The current `demo_co` local export includes one logical person under both
Google and OIDC mappings. The consumer keys people by provider plus logical
person ID and compares the access matrix only with Google mappings. This
local export validates but still reports Google `not_configured`; its local
PostgreSQL/ClickHouse readiness does not advance the Google acceptance gate.

Spec 0001 names connection/evidence schemas but does not yet specify a byte-exact access-matrix export. Add a companion `demo-co/access-expectations/v1` artifact in `demo_co` before end-to-end implementation acceptance. It contains stable fixture person/resource IDs, provider identity/resource mappings, expected baseline outcomes, dataset version and independent probe evidence references.

Pin both artifact schemas and example vectors in the Auths demo. Unknown/missing versions produce actionable errors, not guessed fields. Changes needed in `demo_co` belong in that repository; this spec records the cross-repository deliverable without introducing a mutable dependency.

### 5.3 Reset and drift

Reset may replace provider IDs or change fixture identity bindings. A changed bundle generation, dataset version or resource map invalidates pending task proposals and requires explicit re-enrollment/review. Old grants must not silently bind to newly created documents, another employee or another company. Existing runtime secrets are never copied into an export to repair drift.

## 6. Google employee identity and OAuth connection

Use the authorization-code flow, exact registered redirect URIs, PKCE where supported by the chosen client, server-held state and a one-use nonce. Use maintained Google/OIDC libraries; do not invent token verification. Validate signature/key, issuer, audience/authorized party as applicable, expiry, nonce and the expected Workspace hosted-domain policy. `hd` is validated from the signed token; a request parameter or email suffix is insufficient.

The durable employee key is `(accepted issuer, sub, enrolled company)`. Email is display/recovery metadata and may change. Match that identity to an operator-enrolled active company member; do not equate Directory IDs with OIDC subjects or trust a client-provided fixture persona. Account-linking must not attach an OAuth grant for a different Google subject to the current employee. [Google OIDC identity validation](https://developers.google.com/identity/openid-connect/openid-connect)

The initial requested scopes are `openid`, `email` and `https://www.googleapis.com/auth/drive.readonly`. The scope is broad over the employee's readable Drive data; the task grant narrows what the agent can request. `drive.readonly` is a restricted Google scope, with applicable verification/security-assessment and organization-policy requirements. Document the dedicated-tenant/internal-app prerequisites and any limitations before external customer installation. Do not advertise zero-admin onboarding without measuring the actual tenant policy. `drive.file` supports selected-file access but also permits writes and is not a silent drop-in for this provider-read-only claim. [Drive scope classifications](https://developers.google.com/workspace/drive/api/guides/api-specific-auth)

OIDC login and Drive consent are separate lifecycle states. An ID token is not a Drive access token. Use only the scopes actually granted by Google and refuse incomplete consent. Offline access is requested explicitly only when the walkthrough needs refresh; handle missing, expired or revoked refresh tokens without borrowing another identity. [Google server-side OAuth](https://developers.google.com/identity/protocols/oauth2/web-server)

Store access/refresh tokens encrypted at rest in the broker's private store; keep the encryption key in operator custody, outside the agent, frontend and database export. Bind records to company, actual employee subject, OAuth client ID, granted scopes, connection ID and generation. Refresh updates occur under that same binding, without extending Auths task validity. Parallel refreshes are serialized and generation-checked so a stale refresh cannot resurrect a disconnected connection.

V1 uses no domain-wide delegation, application-wide service account or Google administrator identity for runtime reads. Setup identities in `demo_co` remain separate. A disabled employee entry or disconnected connection prevents future broker reads independently of whether an old Google token still happens to work.

## 7. Employee principal enrollment and task delegation

### 7.1 Chain and key ownership

The company operator provisions one trusted company Auths root and pins its accepted registry/configuration. The browser creates or selects an employee Auths signing key through the installed SDK. Enrollment binds its principal to the authenticated Google subject and company using an expiring key-possession challenge. A user cannot register a key for an arbitrary employee email/persona.

The operator-controlled enrollment service issues a bounded company → employee grant for the one demo MCP service/read tool. Possession of a Google token alone does not become an Auths trust anchor. Employee signing custody stays outside the agent; a browser-held key is a development custody choice whose protection and persistence are documented.

The separate agent process creates its own signing key. The employee reviews the exact agent principal and task scope and signs an employee → agent child grant. Its terminal subject is the agent, its remaining delegation depth is zero and its validity is contained in the parent and employee session policy. No controller or employee private key is copied to the agent.

Task creation uses the native grant planner and attenuation checks. A signing response, browser click or valid signature alone is not evidence that the chain was accepted by the verifier. Recheck the actual complete proof under the pinned trusted context before enabling the task.

### 7.2 Finite task contract

V1 supports up to eight explicit document IDs, not recursive folders or future search results. The employee-facing catalog contains only the enrolled demo resources the employee can actually inspect, with provider access checked under their own authorization. Unreadable selections fail preparation; catalog lookup must not leak private titles to an unauthorized employee.

Define `auths.google-read-task/v1` as a closed, canonical task descriptor containing:

- Company/instance IDs and imported environment/configuration commitments.
- Employee Auths principal and enrolled identity-binding reference.
- Agent principal and the exact MCP service audience.
- Immutable OAuth connection ID/generation reference, never a token.
- Sorted, duplicate-free Google file IDs and the fixed document-read contract version.
- Fixed supported output formats/fields, per-call limits, aggregate task limits and validity.
- Random task ID and task-purpose text shown for review. Purpose text is descriptive, not executable policy.

Compute its versioned commitment over these fields before generating canonical calls. Exclude signatures, derived grant IDs and generated action-body digests to avoid circular commitments. Use existing canonicalization/hash primitives with a specified domain/version; publish exact vectors.

Generate one canonical `auths.mcp/2` call per approved file. Every call includes the task ID/commitment, company/instance, connection ID/generation, exact file ID, contract version, output selection and response-byte ceiling. A later file addition, format/limit change or connection replacement creates a new reviewed task.

The employee → agent grant uses `AllowedBodyDigests` for exactly these complete canonical call bodies. It MUST NOT use `AnyBody`. The existing MCP permission identifies the tool, not the Google file; the body constraint is therefore essential. Bind the audience to the enrolled broker service and require exact permission derivation from the call. Time, actor and challenge remain separately bound by the signed Auths action envelope.

This avoids a new core resource algebra or unreviewed critical extension. It also means the agent cannot discover new resources and read them under the same approval. A more flexible search/folder task needs a separate semantic contract and acceptance evidence.

### 7.3 Review and action authoring

Show the exact employee/account, agent, documents, output types, time window, limits, broker audience and the broad OAuth scope held by the broker. Show excluded project B and finance examples without leaking their private content. Do not conflate Google consent, employee key enrollment and task delegation into one unexplained approval.

Persist the approved descriptor and signed child grant with its verified linkage. The agent receives the proof material, canonical allowed-call catalog and task expiry, but no provider credentials. It chooses which permitted documents to read and signs each action itself.

For each call the broker issues an unpredictable, expiring challenge bound to task, agent and action-body digest. Claim it atomically at admission. A copied proof/action cannot be replayed for another employee, resource, connection, task, audience or challenge. Auths signatures establish the named actor's authorization; they do not prove that a human understood the review or that the agent's summary is correct.

## 8. Closed read tool and execution gate

The initial tool is `google_drive_document_read` on one configured MCP service. The application accepts proof bytes and canonical action bytes; it does not accept a second unverified arguments object beside them. The illustrated call is schematic; exact field encodings and canonical vectors are required before implementation acceptance:

```json
{
  "profile": "auths.mcp",
  "profile_version": 2,
  "service": "atlas-drive",
  "name": "google_drive_document_read",
  "arguments": {
    "contract": "google-drive-document-read/v1",
    "company_id": "atlas-studio",
    "instance_id": "customer-demo-01",
    "task_id": "<opaque-task-id>",
    "task_commitment": "<versioned-commitment>",
    "connection_id": "<opaque-employee-connection>",
    "connection_generation": 1,
    "file_id": "<exact-google-file-id>",
    "output": "text",
    "max_bytes": 262144
  }
}
```

Unknown fields, tools and operations are rejected. Canonical action/body/profile/permission/audience must all agree under the actual native verifier. Project a sealed `McpCommand`; only its verified arguments are decoded into a private validated read command. A client-supplied `Authorized` boolean, receipt ID or transport session never substitutes for that command.

The broker then checks active company/employee/task state, agent identity, exact approved body membership, connection binding/generation, current policy and durable limits before credential resolution. Match the task's employee grant linkage to the employee connection; a valid company-rooted proof from employee A cannot select employee B's token.

Use bounded metadata lookup to validate the exact file and supported content type, then perform the declared content read. Every credential-bearing operation remains inside this executor. Recheck task/connection validity before each provider dispatch and before releasing results. All retries remain within the same verified command and current task limits.

V1 supports Google Docs exported as plain text and ordinary plain-text Drive files. Metadata fields are explicitly allowlisted and bounded; do not expose permission lists, download URLs, arbitrary JSON fields or unrelated document titles. Reject shortcuts, folder recursion, unsupported types and redirect-based resource substitution. Do not follow links inside documents or automatically fetch embedded content/attachments.

Construct Google Drive API v3 paths from validated IDs and fixed operation templates. The caller supplies no URL, host, query expression, headers, MIME type, OAuth scope or credential selector. Use TLS, pinned allowed origins, bounded response streaming, validated DNS destinations, disabled automatic redirects and no ambient proxy/credential fallback. Honor provider download/export restrictions; browser view access does not necessarily authorize content export. [Drive download/export behavior](https://developers.google.com/workspace/drive/api/guides/manage-downloads), [Drive v3 export](https://developers.google.com/workspace/drive/api/reference/rest/v3/files/export)

Runtime provider content requests use GET only. OAuth token exchange/refresh is a separate trusted authentication operation and may use POST to its fixed token endpoint; it must not become a generic agent POST capability. No Drive mutation endpoint is available. Verify unchanged relevant fixture state after attempted writes; incidental provider read/audit metadata is not a business-write claim.

## 9. Durable admission, limits and response release

Use a real broker-owned store, initially single-host SQLite with transactions and an explicit locking/durability configuration. Do not assume an SDK session object, frontend counter or process-local map supplies cross-process admission. Preserve native MCP session semantics where they fit and test the actual store/driver composition.

Initial hard ceilings, reducible by policy/task:

| Limit | Initial ceiling |
| --- | --- |
| Distinct approved documents | 8 |
| Task validity | 15 minutes; never beyond parent/session/connection policy |
| Challenge validity | 60 seconds; never beyond task expiry |
| Admitted exact calls per task | 16, including repeated reads |
| Content body per call | 256 KiB |
| Metadata response per request | 16 KiB |
| Aggregate content released per task | 4 MiB |
| Aggregate provider response bytes per task | 8 MiB |
| Provider requests per task | 40, including metadata and retry attempts |
| Concurrent reads per task | 2 |
| Provider request duration | 15 seconds, subject to the remaining task deadline |

Before dispatch, atomically claim the challenge and reserve call/byte capacity. Count every provider attempt and streamed byte against the appropriate task-wide bound. Reservation/settlement rules must prevent concurrency from exceeding any ceiling. Ambiguous/crashed operations retain conservative charges; a fresh request ID cannot reset the task's allowance. These are application read budgets; do not claim the current MCP profile's requested-budget algebra already implements them.

> **Current broker accounting:** The closed Drive adapter has one bounded
> metadata GET and one bounded content GET per admitted read, without retries.
> SQLite reserves both maximum response sizes before dispatch and retains the
> charge after failures. This enforces the 8 MiB aggregate ceiling
> conservatively across processes. The Drive adapter now records GETs started
> and response body bytes actually read into signed receipts, including bytes
> read before an oversize refusal. Each fixed Drive GET is also recorded in
> SQLite before dispatch, with streamed bytes and an outcome; a row left
> `started` after a crash remains an unknown outcome. Recovery of abandoned
> in-flight slots and end-to-end crash evidence remain to be added before the
> full claim is made.

> The successful release state and signed read receipt are now inserted in
> one SQLite transaction. A failed receipt write rolls back release commitment;
> transport delivery remains `unknown` because an HTTP write is outside that
> transaction.

Keep the fetched body private to the broker until validation and the final release gate succeed. Record `proof_verified`, `admitted`, `provider_denied`/`content_fetched`, `release_committed` and actual transport delivery/unknown status separately. A successful provider fetch is not proof the agent received its contents.

Task revocation and response-release commitment serialize through the store. The linearization guarantee is **no release commitment after the task's revocation commits**. Bytes committed/queued before revocation may arrive later; already delivered text cannot be recalled. Hold no database transaction open across provider network I/O. A post-fetch gate checks the current revision/generation and drops the body when invalid.

On crash/restart, never replay stored response content to a caller without current authorization. V1 maintains no persistent plaintext content cache or shared vector index. Retrying an authorized read requires a fresh challenge/admission and re-evaluation. Challenge replay returns no previous body or denied-resource metadata.

Disconnecting Google credentials advances the connection generation, disables linked tasks and removes/invalidates token material. Task revocation need not revoke the employee's entire Google OAuth grant. Employee offboarding disables all their broker tasks and authoring sessions. Provider ACL revocation remains enforced by Google and may propagate on Google's schedule; report it separately from immediate broker-state revocation.

## 10. Credential/process isolation and threat model

```text
Operator installation / pinned trust / demo_co import
                         |
Employee browser --Google login/consent--> Trusted read broker
       |                                  | private OAuth/token store
       +--employee key / task grant-------+ native Auths verification
                                          |
Untrusted agent --signed exact call------>+ admission + read + release gate
     own key                              |
     no Google token                      +--> Google API as that employee
                                          |
                                  read evidence + bounded response
```

The trusted boundary includes the broker host/process, operator configuration, employee key custody, native SDK, credential store and Google/OIDC contracts. The agent may alter/replay requests, choose allowed calls adversarially, race reads/revocation, follow malicious document instructions and attempt to steal tokens. The operator and an already compromised broker host are outside this claim.

Run broker and agent under distinct container/OS security boundaries. Only the broker has its secret volume, encryption key, token endpoints and company-root signing capability. The agent has no mount of broker state, shared `.env`, Docker socket, host shell or `demo_co` administrator interface. The frontend has no token-store access. Constrain the agent's network to the broker and the explicitly configured model endpoint; Google API access is not an alternate credential path.

> **Isolation implementation note (24 October 2026):** The Auths demo now has
> a Compose layout with separate browser, agent and model relays. The agent
> joins only an internal network containing its two relays; the agent relay
> exposes only challenge and proof-call POST routes. The broker state and
> operator files have no agent mount. Installed broker/agent images, runtime
> filesystem/API/network inspection and live provider acceptance are still
> required before this is an isolation claim. A synthetic Docker probe recorded
> actual agent network, mount and relay-route behavior in
> `demos/google-employee-delegation/evidence/isolation-synthetic-2026-10-24.md`;
> it used a mock broker and does not qualify the installed live deployment.
> An image recipe now verifies an input Linux SDK wheel digest and installs
> broker/agent wheels into separate runtime images. Hosted CI built both roles
> from a matching branch wheel and checked entry points and source isolation.
> Registry image digests and an installed Compose acceptance run are pending.

Do not call a same-user process split credential isolation if the agent can read its sibling's files/process state or invoke its operator API. Acceptance must exercise the actual filesystem, API and network restrictions. Public broker endpoints still require complete proof/task checks; their reachability alone provides no authority.

Downloaded document content is untrusted data. It must not register tools, change task scope, choose egress targets or trigger hidden fetches. The agent may still disclose permitted content through its model/output channel. Record whether synthetic company text leaves the Mac, the configured model provider and any retention assumptions; read-only access does not itself solve exfiltration.

## 11. UX and application APIs

Provide an HTTP localhost workbench for the Mac demo, using exact registered loopback redirects for local development. Externally reachable deployments require HTTPS and appropriate OAuth configuration. Browser sessions use server-side state, scoped cookies and CSRF protection for account/task operations; operator endpoints are separately authenticated and not exposed to the agent.

```text
+-----------------------------------------------------------------------+
| Atlas Studio · Employee-to-agent delegation · Google live               |
| Employee: Engineer     Google account: connected     Agent: agent-7...  |
|-----------------------------------------------------------------------|
| Task: Summarize project A                                               |
| Approved documents: Brief, Design notes, Status                         |
| Access: read only     Expires: 15 min     Calls: 0/16     Bytes: 0/4 MiB |
| [Review exact scope] [Authorize agent] [Run task] [Revoke]                |
|-----------------------------------------------------------------------|
| Request                  Auths check     Google result    Released      |
| Project A / Brief        authorized      fetched          yes           |
| Project B / Notes        outside task    not contacted    no            |
| Project A / Removed ACL  authorized      denied           no            |
|-----------------------------------------------------------------------|
| Summary + source citations | Delegation chain | Canonical JSON | Audit  |
+-----------------------------------------------------------------------+
```

The review screen shows the real account binding and exact selected IDs behind readable labels. The grant is immutable once signed. Editing a task returns to review; changing a browser dropdown cannot retarget an existing grant. Display transport, proof authorization, provider response and content release as separate stages.

> **Workbench implementation note (24 October 2026):** The current loopback
> workbench uses a browser-held non-exportable employee Ed25519 key and
> explicit prepare/review/sign steps. Agent registration and activation
> require signatures from the separate agent process. Employee-scoped task
> status, revocation, package export and signed receipt JSON routes are
> present. Live provider content and complete result/evidence presentation
> remain pending Google setup and process-isolation acceptance; the local UI
> does not label these stages passed.

Proposed application routes:

```text
POST /operator/v1/companies/import          # Accept pinned demo_co contract
GET  /api/v1/session
GET  /api/v1/google/authorize
GET  /api/v1/google/callback
POST /api/v1/employees/enroll               # Authenticated identity + key possession
POST /api/v1/agents/register                # Distinct agent key possession
POST /api/v1/tasks/prepare                  # Employee review descriptor/canonical calls
POST /api/v1/tasks/{id}/authorize           # Signed child grant, validated natively
POST /api/v1/tasks/{id}/challenges          # Bound challenge; no content read
POST /api/v1/tools/call                     # Proof + canonical action only
POST /api/v1/tasks/{id}/revoke
POST /api/v1/google/disconnect
GET  /api/v1/tasks/{id}
GET  /api/v1/receipts/{id}
GET  /receipts/{id}
```

Endpoint authentication and per-company/person checks apply to task metadata and receipts too. The agent cannot enumerate other employees' sessions/resources through error messages or receipt URLs. Task prepare/authorize is employee-only; imported data and agent requests cannot invoke it as an operator.

The public SDK/CLI example must exercise the same broker routes and native authoring APIs as the frontend. No separate privileged shortcut implements the CLI's successful path. Provide a reproducible browser journey with controls, result, remaining limits and inline canonical receipt JSON visible together.

## 12. Read evidence and disclosure

Use the real native verification/decision receipt where supported and add a separately typed, broker-signed `auths.employee-read-receipt/v1` for execution observations. This is application read evidence, not a general-gateway qualified execution receipt.

Bind at least:

- Company/instance, source/environment/configuration/contract versions and import commitments.
- Employee Auths principal and a privacy-preserving reference to its validated Google subject binding.
- Agent principal, verified grant chain/terminal grant, task ID/commitment and exact action commitment.
- Challenge/admission reference, tool, resource reference, connection generation and requested limits.
- Native verdict, task/connection-state verdict, provider stage/status, retry/count/byte charges and timestamps.
- Content digest, supported format, completeness and release commitment/delivery stage, with no raw document body or token.
- Signer identity, signature and the receipt-verification instructions.

Do not log authorization headers, OAuth codes, raw tokens, signing material, cookies, private document names or bodies. Low-entropy content digests can still reveal information; redact or access-control evidence exports as appropriate. Unauthenticated errors do not expose private resource identifiers. Public synthetic reports may use stable fixture labels with explicit provenance.

Export `demo-co/scenario-result/v1` references alongside Auths read receipts. `demo_co` independently records provider facts; Auths records its own enforcement/release. A single component must not fabricate the other's passing evidence. Missing live steps, provider timeouts and unknown outcomes cannot be reclassified as authorization success.

## 13. Demonstration matrix and independent oracle

| Scenario | Required observation |
| --- | --- |
| Allowed project A summary | Actual agent reads approved real Google documents through Auths, produces a useful cited result matching independent fixture facts |
| Project B, employee allowed/task excluded | Native body/authority check or broker task check denies before provider credential resolution and content access |
| Finance/payroll, employee denied | Independent live probe confirms known existing resource is inaccessible to that employee; task preparation cannot approve it |
| Google ACL removed after task approval | A previously accessible, approved file now produces provider refusal under a still-valid Auths action; no body is released |
| Wrong employee connection | Valid proof for employee A cannot select B's connection, even with the same display name or resource ID |
| Wrong actor/audience/company | Refused by the appropriate native/context/binding check; no token lease or provider call |
| Altered body/limits/file/output | Canonical signed action cannot be replaced by shadow JSON or modified arguments |
| Attempted mutation | Unknown write tool/operation rejected; read token and actual fixture state supply additional independently observed defenses |
| Replay and concurrent reads | One challenge cannot be reused; aggregate limits hold across two broker processes, restart and races |
| Task revoked during fetch | No release commitment after the revocation transaction; in-flight/previously delivered data is reported honestly |
| Google disconnect/offboarding | Old connection generations and employee sessions cannot create new releases or resurrect via refresh |
| Adversarial document | Tool responses/prompts cannot expand exact call bodies, obtain credentials or reach outside-task content |
| Process bypass | Agent cannot read broker files/secrets, call the operator interface or use a different provider identity |
| Local-only environment | UI/report says Google is not configured; no live adoption or provider-permission claim passes |

Do not claim a guessed file ID or isolated 404 proves Google permission enforcement. The independent fixture oracle confirms resource existence and the intended ACL; the employee's valid credential must also succeed on an allowed control resource. Provider errors that conceal existence are recorded faithfully, without leaking the protected resource in the runtime response.

The two principal negative cases need different setups. An outside-task read should be blocked before Google. To exercise a real provider denial after valid Auths authorization, approve an accessible file and then remove employee access. Do not weaken task checks or supply an artificial broad grant merely to make a provider request appear in the demonstration.

Compare source content/versions and relevant provider state before/after attempted writes. A summary alone does not prove tool results were confined; inspect complete tool responses, broker output, model input and redacted logs for synthetic denied-content canaries.

## 14. Acceptance and adoption evidence

This spec is complete only when all required deliverables are implemented and verified on the exact demonstrated revision:

1. `demo_co` supplies a running real Google company, accepted versioned bundles, access-expectation artifact and independent baseline evidence. Contract-only fixtures are insufficient.
2. A new Mac operator installs the pinned demo kit and SDK artifacts without source compilation or sibling dependencies. Required tenant/domain/OAuth setup and any paid prerequisites are documented.
3. Two employees authenticate as actual distinct Google subjects, enroll distinct Auths principals and see the correct connection/resource scopes. The agent uses a third distinct principal and proves key possession.
4. The actual company → employee → agent chain, task body constraints, signed calls, native verification and sealed command projection are visible in evidence. No testkit trust root or hardcoded `Authorized` path powers the customer live run.
5. The positive agent task and every required negative case in §13 pass through real isolated processes. Unit mocks and scripted tool exercisers remain separately labeled.
6. Durable limits, response release, replay, reconnect, two-process races and restart behavior have actual store/driver tests. Delegation validity and provider token validity remain separate checks.
7. Broker/agent filesystem, secret, administrative API and network isolation is inspected and tested in the deployed configuration. No employee Google credential is available to the agent or frontend.
8. The browser journey and CLI use the installed public APIs; the receipt page verifies signatures and distinguishes native authorization, provider response and release. Public reports contain no real credentials/private content.
9. Live provider ACL changes, token revocation/refresh failures and download/export restrictions are exercised where required. Record propagation latency rather than inventing immediate Google behavior.
10. The second-company test establishes the exact tested isolation boundary; independent-Google-tenant claims remain absent until a second actual tenant is exercised.
11. Architecture/compliance/fixture inventories and all required repository/hosted checks pass on the final implementation revision. No existing formal or gateway qualification is borrowed to qualify this new Google read mapping.
12. A second operator reproduces installation and the useful live walkthrough from the documentation and records the measurements below.

Measure hands-on setup time, elapsed provider/admin wait, steps requiring a tenant administrator, scopes/privileges requested, configuration changes, application code changes, time to first useful task and time to effective broker/provider revocation. Report cold install and repeat install separately. The target after tenant/OAuth prerequisites is no existing business-application code changes and a first useful task within 30 minutes; this is an acceptance target to measure, not a current benchmark. Provider review, licensing and consent delays are separate reported prerequisites.

## 15. Implementation sequence

1. **Contract and setup:** implement the `demo_co` importer and versioned companion expectations artifact, operator trust/tenant enrollment, static fixture vectors and an honest prerequisite doctor.
2. **Employee connection:** implement actual Google login/OAuth, subject-to-principal key-possession enrollment, encrypted token custody and connection generations. Verify independent allowed/denied control reads before adding an agent.
3. **Task authority:** implement the canonical descriptor, exact allowed call bodies, employee-signed child grant and native proof/command path. Establish wrong-actor/company/body/connection refusal before credential use.
4. **Read boundary:** implement the closed read executor, durable challenge/limits, retry accounting, final release gate, receipts and revocation/disconnect composition. Add real separate-process isolation and race/restart cases.
5. **Useful UX:** connect the actual agent, frontend, CLI, source citations and evidence pages; exercise the full live matrix against the independent company oracle.
6. **Adoption handoff:** publish the pinned kit and run the fresh-operator exercise, final repository/hosted checks and redacted exact-revision report.

These are implementation steps for this demo, not a request to resume the separately paused AP-SPEC-069 Lean program or to merge the current draft branch. The current implementation branch contains a broker foundation; acceptance in §14 still requires the live company and complete installed application journey.

## 16. Later work

Flexible folder/search delegation, Google Calendar/Gmail, additional SaaS, native Apple tools, long-lived background agents, subdelegation and managed multi-tenant custody each require explicit operation/identity/permission contracts. A general permission-inheritance engine is not assumed from one successful Drive integration.

Before any Auths-managed production read service is proposed, compare its credential, lifecycle, tenant, response-release and provider contracts with existing mechanisms under the domain boundary plan. Record any required ADR and qualification work. Provider writes continue through the existing data-only gateway; this read demo creates no alternate write path.
