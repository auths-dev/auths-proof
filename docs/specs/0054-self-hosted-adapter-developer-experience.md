# AP-SPEC-054: Self-hosted adapter developer experience

- **Status:** Draft; this document specifies work, not a completed SDK claim
- **Audience:** Python and TypeScript SDK maintainers, application developers,
  conformance maintainers, and reviewers
- **Depends on:** [AP-SPEC-051](0051-self-hosted-developer-profiles.md),
  [AP-SPEC-052](0052-self-hosted-launch-hardening.md), and the
  [profile/domain boundary plan](../target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md)
- **Scope:** finish the generalized, application-owned interface for defining
  one exact `auths.mcp/v2` operation and implementing its provider adapter
- **Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** specify
  implementation requirements

## 1. Decision and bounded outcome

Auths will make the *developer-owned adapter path* self-service. A developer
with an existing provider credential can define a closed, bounded command in
their own repository; generate a statically typed Python or TypeScript
contract; authorize and verify its exact action with independently supplied
authority and trust; then implement the provider request and observation using
a small, typed adapter interface. They do not add an Auths-owned profile or
modify Auths source.

This spec has exactly five deliverables:

1. Complete the restricted typed schema and deterministic generator.
2. Make the application-owned adapter contract and generated starter pleasant
   to implement without weakening the exact-action boundary.
3. Ship a reusable local conformance kit for adapter behavior and failure
   handling.
4. Make authoring, version changes, and setup failures diagnosable.
5. Prove self-service adoption with a fresh third adapter built from packaged
   SDKs by a developer unfamiliar with Auths.

These are completion criteria for the 051/052 self-hosted interface, not a new
authorization protocol. [AP-SPEC-053](0053-declarative-credential-isolated-gateway.md)
is a separate, optional credential-isolation project and **is not a dependency
or launch gate for this spec**. The application still owns and can bypass its
own provider credential. No result of this work qualifies third-party
provider semantics or makes the local runner non-bypassable.

Success is not a count of built-in integrations. Success is one repeatable
path for an unfamiliar developer to build a third, distinct adapter with no
Auths repository changes, no Rust helper, no hand-decoding of action bytes,
and no hand-written substitute for the SDK's verification or one-use gate.

## 2. Current baseline and gaps

The existing Python and TypeScript packages expose exact MCP tools, production
authoring inputs, verification, attempt-store contracts, and conservative
`run_once`/`runOnce` ordering. The Airtable and Todoist field-lab demos use
those mechanisms and have made live provider changes. Preserve those working
paths while replacing their SDK-boundary boilerplate.

The packaged `profile init/generate/check/doctor` tools currently generate
flat scalar command fields. They do not yet express the full 051 bounded
object/array/bytes vocabulary, provide a checked contract-version diff, or
produce a complete canonical cross-language action corpus. Adapter authoring
still requires understanding too much runner plumbing. The two field-lab
demos were implemented by people already familiar with Auths, so they do not
establish that a stranger can use the interface unaided.

One decoder invariant needs explicit regression coverage as schema depth
grows: the native MCP path validates canonical action JSON before returning
arguments to Python or TypeScript. The bindings currently parse that native
projection; `JSON.parse` alone would not detect duplicate object keys, so
the implementation MUST preserve the native canonicality check and prove
that duplicate keys at every nesting level are rejected before a typed
command is issued. This applies to Python and native test vectors too.

Because Auths is prelaunch, implementation MAY make one direct source cutover
to a clearer generated format or public API. It MUST NOT add a legacy decoder,
alias, or dual generator merely to preserve disposable prelaunch output.

## 3. UX

The primary flow is CLI plus ordinary application code. Neither `init` nor
`doctor` creates a production signer, grant, trusted context, or provider
credential. The generated adapter contains explicit TODOs for all four.

```text
+-----------------------------------------------------------------------+
| auths profile init --language python --name create-task               |
|  profile.toml       exact action identity + bounded argument schema   |
|  generated.py       immutable CreateTask + CONTRACT                   |
|  adapter.py         typed credential/invoke/observe skeleton          |
|  tests/             fake provider + denial/replay/unknown scenarios    |
|  profile.lock.json  schema/identity digest + canonical vector version |
|                                                                       |
| auths profile check                                                    |
|  PASS  schema and generated files match                               |
|  PASS  canonical/hostile vectors match packaged SDK                   |
|  WARN  provider behavior is application-owned and unqualified         |
|                                                                       |
| auths profile doctor --production                                      |
|  READY signer/grant/trust are structurally compatible                 |
|  MISSING provider credential: configure your adapter                  |
|  NOTE  credential is never read by Auths verification                 |
+-----------------------------------------------------------------------+
```

The TypeScript CLI generates the equivalent `.ts` command, adapter starter,
tests, lock, and vectors. Both CLIs use the same conceptual commands and
diagnostic codes; language-specific invocation syntax is allowed. An
authorized-action preview shows service, tool, version, audience, permission,
bounded argument summary, and action commitment *before* signing. Secret or
sensitive argument values are redacted by default; the commitment remains
visible. The preview is derived from the exact canonical action that will be
signed, not from an editable sidecar.

The happy-path documentation has two explicit modes:

- **Local learning:** an opt-in `auths.testkit` signer/trust pair and fake
  provider, visibly labeled development-only.
- **Real use:** an existing custody signer and grant, independently provisioned
  trusted context, application-owned provider token, and a developer-owned
  attempt store appropriate to the deployment.

Neither mode claims that having a token implies Auths authorization. The CLI
must show a useful next action for each missing input without printing token,
key, grant bytes, proof bytes, or unbounded arguments.

## 4. Architecture and ownership

```text
  profile.toml --parse/validate--> bounded contract AST
        |                              |
        |                              +--> generated Python/TS command
        |                              +--> lock + canonical vectors
        v
  packaged SDK prepare + author -- explicit signer/grant --> proof + action
                                                         |
  independently supplied trusted context ----------------+--> native verify
                                                               |
                                                       strict typed projection
                                                               |
                                              app-owned atomic attempt store
                                                               |
                                                 developer-owned adapter
                                              credential -> request -> observe
                                                               |
                                                        external provider
```

The existing `auths.mcp/v2` action and native verifier remain authoritative.
Generated contracts may validate inputs before authoring, but **only verified
action bytes** may become an `AuthorizedCommand`. The SDK runner owns the
verify/project/claim-before-credential sequence. The application adapter owns
provider URL, method, body, token custody, response classification, read-back,
and reconciliation. The conformance kit tests the developer's declared
adapter behavior; it does not certify actual provider truth.

Reuse the existing `ExactMcpTool`, `AuthorizedCommand`, `RejectedCommand`,
`ProductionAuthoringInputs`, `AttemptStore`, `ProviderAdapter` /
`SelfHostedProviderAdapter`, `ProviderAccepted`, `ProviderRejected`,
`ProviderUnknown`, and observation/result types. Reuse the native MCP action
and proof APIs rather than creating a second `Action`, verifier, or profile
registry. Where the Python and TypeScript names differ, align the generated
workflow conceptually; do not force an unsafe runtime cast for spelling
symmetry. A new type needs a named invariant and owner. In particular, the
schema AST may be new, but provider request/response models remain local to
each adapter.

The bounded schema compiler and canonical argument rules are shared product
mechanisms, not provider semantics. Before changing packages, record a type
inventory and decide whether an existing SDK/package can own them. Python and
TypeScript bindings MUST expose the same contract and decisions without
becoming independent authorization engines. If a native helper is added, it
must be deterministic, bounded, and downward-only in the repository layer
model. Do not add a generic callback dispatcher or move provider HTTP code
into core.

## 5. Contract and generated types

### 5.1 Restricted schema

`profile.toml` remains the only hand-edited contract source. Replace the
scalar mini-language with a versioned declarative schema that supports:

| Node | Required bounds and generated type |
| --- | --- |
| UTF-8 string | minimum/maximum **encoded bytes**; `str` / `string` |
| Bytes | minimum/maximum decoded bytes; `bytes` / `Uint8Array` |
| Integer | inclusive range within the cross-language safe-integer range; `int` / `number` |
| Boolean | `bool` / `boolean` |
| Nullable | one inner node; key remains present and value is either typed value or `null` |
| Object | fixed named fields, no extras, no duplicate names; frozen dataclass / readonly object |
| Array | one item schema and min/max item count; immutable tuple / readonly array |

The root is a fixed object. No free-form maps, arbitrary JSON, floats,
unions, references, executable validators, computed defaults, or permissive
`Any`/`unknown` values are part of the command API. All nodes have a finite
maximum and the entire encoded MCP argument body remains under the effective
native action limit. The first format caps depth at four container levels,
total named fields at 32, each array at 32 items, and canonical argument JSON
at 4 KiB; if a lower native limit applies, the lower limit wins. The compiler
must reject a schema whose worst-case encoding cannot fit, including JSON
escaping and bytes expansion. These limits are explicit contract constants,
not undocumented generator accidents.

Illustrative format (the TOML tables are parsed into one typed AST; their
source order has no effect on canonical bytes):

```toml
[profile]
name = "create-task"
version = 2
service = "todoist"
tool = "create_task"

[arguments]
type = "object"

[arguments.fields.content]
type = "string"
min_bytes = 1
max_bytes = 256

[arguments.fields.labels]
type = "array"
min_items = 0
max_items = 8

[arguments.fields.labels.items]
type = "string"
min_bytes = 1
max_bytes = 64

[arguments.fields.attachment]
type = "nullable"

[arguments.fields.attachment.value]
type = "bytes"
min_bytes = 0
max_bytes = 512
```

Bytes use unpadded base64url in the canonical JSON representation. The
generated Python and TypeScript commands expose bytes, not encoded strings.
Decoding rejects padding, alternative alphabet, whitespace, and noncanonical
encodings. Nullable means a **present key** with explicit `null`; absence is
not another spelling. This keeps prepare, preview, and projection identical.
String length counts UTF-8 bytes, not Unicode code points or JavaScript code
units. Integers reject booleans, fractional values, negative zero, unsafe
JavaScript integers, and out-of-range values.

The compiler produces a normalized schema digest and binds the contract
version in the existing versioned tool name. A `profile.lock.json` records
identity, version, normalized schema digest, generator format, and vector
format. `profile check` rejects a changed identity/schema under the same
version; `profile diff` explains the change and the required version bump.
`profile generate` updates generated source only after the contract version
has advanced, except for a first generation. A version change produces a new
tool identity, so an old proof cannot project under the new contract. Do not
silently rewrite the lock to bless a changed same-version schema.

### 5.2 Strict bytes-to-command path

The generator emits immutable command declarations, the exact tool
constructor, contract identity constants, a typed preparation helper, and
canonical vectors. Python/TypeScript authoring from the same logical command
and the same explicit authority, challenge, and evaluation-time inputs must
produce byte-identical canonical arguments, action bytes, and commitments.
Verification first uses the native verifier and canonical MCP decoder, then
strictly projects the *verified* argument bytes against the compiled schema;
it never decodes the caller's `expected_command` or a preview as authority.
Reject duplicate keys at every depth, unknown/missing keys, invalid
UTF-8/Unicode, noncanonical number or bytes spellings, overlong collections,
and noncanonical JSON bytes. Bindings must not bypass native canonicality by
parsing unverified caller JSON with `JSON.parse` or its Python equivalent.

The vector corpus includes valid scalar/nested/array/bytes actions and each
hostile boundary above, plus changed service/tool/version/permission/audience,
wrong trust, denial, and indeterminate results. Vectors record exact canonical
argument bytes, canonical action bytes, commitment, and expected outcome;
`valid_arguments_json` alone is insufficient. Native Rust, Python, and
TypeScript consume the same corpus in packed-consumer tests.

## 6. Typed adapter authoring

The generated starter implements the existing `ProviderAdapter[Command,
Credential, Result]` (Python) or `SelfHostedProviderAdapter<Command,
Credential, Result>` (TypeScript) shape. It is intentionally a template in the
application's repository, not provider behavior hidden in the SDK. Its three
operations are explicit:

1. `credential`: obtain only the app's provider credential, called after an
   authorized command and successful attempt claim.
2. `invoke`: derive exactly one closed provider write from the typed command
   and return `accepted`, `rejected`, or `unknown`.
3. `observe`: perform read-only, provider-specific observation and return
   `observed`, `not_observed`, or `unavailable`.

`ProviderRejected` is allowed only when the adapter has evidence that no
effect occurred. A timeout, connection loss after possible entry, ambiguous
response, or unsupported error mapping is `ProviderUnknown`. A successful
HTTP response is at most `ProviderAccepted`; `observed` requires the
adapter's read-back. `not_observed` does not authorize a second write.

The runner receives a typed command only after strict verification and one
atomic claim. Its public result keeps authorization, provider entry/outcome,
and observation separate. The generated template must show where to set a
provider-native idempotency key if the provider offers one, but must not
invent one or imply it replaces Auths attempt state. It must include a
read-only reconciliation function that never calls `invoke`.

Representative Python call site (names may be refined before public freeze):

```python
from auths.execution import run_once
from my_adapter.generated import CONTRACT, CreateTask
from my_adapter.provider import TodoAdapter

command = CreateTask(content="Review budget", labels=("finance",))
authored = await author_production_mcp_proof(
    contract=CONTRACT, command=command, inputs=operator_inputs,
)
result = await run_once(
    contract=CONTRACT,
    proof=authored.proof,
    action=authored.action,
    trusted_context=operator_trust,
    attempts=application_store,
    operation_key=operation_key,
    adapter=TodoAdapter(provider_client),
    expected_command=command,
)
```

The TypeScript sample has the same explicit inputs and a discriminated result
that narrows without casting. These samples are interface sketches, not a
claim that the named generated files or methods already exist. If the current
production authoring function can be reused directly, the generated helper
must remain thin. Do not create a new convenience API that mints ephemeral
authority or reads provider tokens for verification.

## 7. Local conformance kit

`auths profile test` runs generated tests against a deterministic fake
provider, fake credential supplier, controllable attempt store, and explicit
clock/failure schedule. The developer supplies a typed adapter factory wired
to the fake provider's transport; the kit drives that factory through the
public adapter interface and verifies its observable calls. A template with
an unwired fake-provider factory cannot pass. The testkit is published with
each SDK. It never needs a real provider token or network access, and it must
not dynamically load untrusted code into an Auths credential-owning process.

Required scenarios and assertions:

| Scenario | Required observation |
| --- | --- |
| Valid exact command | One claim, credential access after claim, one write, optional read-only observation |
| Denied/indeterminate/wrong contract or trust | Zero claims, credentials, and writes |
| Replay and two competing calls | At most one credential access/write for the same claimed operation |
| Credential unavailable before entry | No write; explicit pre-entry result |
| Timeout or crash after possible entry | Durable `unknown`; no automatic second write |
| Definite provider rejection | `rejected` only when adapter supplies no-effect evidence |
| Observation missing or unavailable | Provider outcome remains separate; no blind retry |
| Read-only reconcile | Zero writes, including after restart |
| Mutated canonical action/arguments | No typed authorized command; zero provider entry |

The kit checks order with spies, records state transitions, injects failure
at each durable checkpoint, and outputs a bounded report: case, verdict,
stage, and failed invariant. It includes test-only adapters for HTTP-shaped
responses, but does not prescribe one universal HTTP client or classify
provider-specific status codes for developers. A passing kit means the
adapter obeyed exercised local contract cases. It does **not** prove the
provider request exactly matches the developer's intent or that the live
provider applied an effect.

## 8. Diagnostics and versioning

`init`, `generate`, `check`, `diff`, `doctor`, and `test` expose stable
machine-readable diagnostic codes plus concise human text and a next action.
Diagnostics identify one stage: `contract`, `generated`, `authority`,
`trust`, `verification`, `claim`, `credential`, `provider`, `observation`, or
`recovery`. The same conceptual error uses the same code in Python and
TypeScript. Both CLIs support a bounded JSON output form for CI/editor use.

Examples of required distinctions:

- Unsupported or unbounded schema versus merely missing generated files.
- Same-version schema drift versus intentional version bump, including a
  field-level diff and changed action identity.
- Missing signer, missing grant, wrong grant principal, missing trust anchor,
  and trust/grant mismatch, without implying a provider token fixes any of
  them.
- Authorization denial versus indeterminate verifier result.
- Failure before provider entry versus possible applied effect (`unknown`).
- Provider accepted versus effect observed.

`doctor --production` may report structural readiness only for checks it
actually performs. It cannot infer independent trust provenance from two
different file paths, verify remote signer connectivity without calling the
signer, or attest to a provider credential it does not inspect. Its output
must say so. It must never silently fall back to `auths.testkit`.

Documentation includes a single end-to-end quickstart per language, a short
"who guarantees what" table, a version-change walkthrough, and a troubleshooting
page keyed by diagnostic codes. The quickstart must explicitly supply
credentials and authority; no sample may appear to "just work" in production.

## 9. Implementation epics and acceptance

### Epic 1 — Complete the schema and generator

1. Write the type inventory and normalized contract AST. Freeze the bounded
   grammar and limits in §5; add a schema format identifier.
2. Write failing Rust/Python/TypeScript fixtures for nested/array/bytes
   encoding, strict decoding, duplicate keys, and exact commitments before
   changing generated code.
3. Implement one canonical prepare/projection contract through existing
   native APIs, with thin language bindings and deterministic source output.
4. Add the lock/diff rule and direct-cutover regeneration of both field-lab
   commands, removing superseded scalar-only glue.

**Acceptance:** a clean packed Python and npm consumer each generate and type
check nested commands; the same valid command has byte-identical arguments,
action, and commitment; all hostile vectors fail in every language; a
same-version schema edit cannot pass `check` or `generate` unnoticed.

### Epic 2 — Make adapter implementation small and typed

1. Generate one concrete provider adapter skeleton and application runner
   wiring in each language, using existing public adapter/outcome types.
2. Move only proven shared ordering/attempt boilerplate into the SDK; keep
   provider request, credential, outcome, and observation mapping in each
   consumer.
3. Refactor Airtable and Todoist to the new starter shape without merging
   their provider-specific code or changing their verified action meaning.
4. Add strict type-check examples that reject `Any`, `unknown` casts at the
   public command boundary, missing adapter cases, and forged authorized
   commands.

**Acceptance:** each demo's provider file contains only its own credential,
request, outcome, and observation logic; denial/replay paths call neither
credential nor provider; Python and TypeScript samples compile/type-check
from packaged SDKs with no Rust toolchain in the consumer workspace.

### Epic 3 — Publish adapter conformance

1. Build the fake provider, spies, deterministic failure schedule, and shared
   scenario manifest in §7; expose them through packaged `auths.testkit` and
   the TypeScript testkit surface.
2. Make `profile test` run both generated contract vectors and adapter
   ordering/recovery tests; let a consumer add provider-specific cases without
   weakening mandatory cases.
3. Run the existing Airtable and Todoist adapters against the kit; preserve
   separate live-provider read-back tests outside hosted CI.

**Acceptance:** both demos pass every mandatory synthetic case; deliberately
broken adapters (credential-before-claim, duplicate write, retry-on-timeout,
false definite rejection, write during reconcile) fail with the expected
diagnostic. No live secret or provider call is needed for conformance.

### Epic 4 — Make failures and changes explain themselves

1. Add stable stage-specific diagnostics, JSON output, and `profile diff`.
2. Make `doctor` report exactly which checks ran and distinguish structural
   readiness from trust provenance and live provider qualification.
3. Update generated README and per-language quickstarts using real production
   inputs as explicit placeholders, not implicit testkit defaults.
4. Test first-run failures from an empty workspace: missing SDK artifact,
   unsupported schema, stale generated code, wrong version, absent grant,
   absent trusted context, denied proof, replay, and unknown effect.

**Acceptance:** each failure gives one actionable next step and no secret
output. A schema change displays the precise identity/field delta and
requires a version bump before regeneration. Documentation never labels an
application-owned provider result an Auths-qualified receipt.

### Epic 5 — Independent third-adapter adoption trial

1. Give one participant unfamiliar with this implementation a packaged Python
   or TypeScript SDK, the quickstart, and a fresh provider operation different
   from Airtable field update and Todoist task creation. A zero-context agent
   in a separate task may serve as the engineering clean-room participant if
   no outside human is available; record that distinction and do not present
   it as evidence of market adoption. The participant chooses the request and
   read-back mapping; Auths maintainers do not prebuild its profile.
2. Provide a fake provider for the first pass and, if a disposable credential
   is available, a live write plus independent read-back. The live call is
   useful evidence, not a hidden requirement for a person to buy an API plan.
3. Record elapsed setup time, each intervention, code edits outside the
   consumer repo, confusing diagnostics, missing schema constructs, and
   cases where the developer bypassed SDK helpers. Fix any blocker in this
   spec's five areas; do not convert unrelated product requests into new exit
   criteria.
4. Re-run the trial from a clean packaged-consumer workspace after fixes and
   publish a short, redacted adoption report and claim ledger.

**Acceptance:** the unfamiliar participant completes one authorized write and
read-only observation against the fake provider, from packaged artifacts,
without an Auths source edit, Rust helper, hand-built CBOR/action parser, or
maintainer intervention. The action, proof, exact projected command, one-use
claim, provider result, and observation are individually visible. A live
third-provider call, when available, must be independently read back and
attributed to the developer adapter. The final report says plainly if the
trial required help or used an agent; do not mark the epic complete by
substituting an internal author or just running Airtable/Todoist again.

## 10. Verification and release boundary

Development is type-driven and test-driven: define invalid states and public
type-check failures first, add hostile vectors and fake-provider failures,
then implement the smallest source cutover. Check both packaged consumers,
not only repository-relative imports. Update public API inventories,
architecture/compliance ownership, generated snapshots, and claim text when
their surfaces change. Hosted CI is the default verification gate under the
repository policy; this specification itself does not run checks or assert
their outcome.

The generalized self-hosted interface is complete when all five epics pass
on one reviewed SDK revision and the independent trial succeeds. Remaining
work in [AP-SPEC-053](0053-declarative-credential-isolated-gateway.md), OAuth
credential acquisition, multi-tenancy, broad security review, and
provider-specific qualification are separate product decisions, **not**
automatic follow-on gates for this developer interface. The final claim is
limited to exact authorization and the exercised SDK mechanisms; the
developer remains responsible for their provider adapter and credential.
