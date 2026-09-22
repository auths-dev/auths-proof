# AP-SPEC-053: Developer-defined, credential-isolated exact-action gateway

- **Status:** Draft; proposed architectural extension, not an implemented or
  qualified product claim
- **Depends on:** [AP-SPEC-051](0051-self-hosted-developer-profiles.md),
  [AP-SPEC-052](0052-self-hosted-launch-hardening.md), the existing
  `auths.mcp/v2` exact-tool action, and the
  [profile/domain abstraction boundary plan](../target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md)
- **First scope:** one operator-controlled gateway, HTTPS static credentials
  injected by the gateway into one operator-bound header
  (`Authorization: Bearer` or a named API-key header), bounded JSON/form
  requests, and one
  exact write plus optional read-only observation per developer-defined
  operation; query-string, cookie, and basic-auth credentials are out of scope

## 1. Decision and claim

Auths should provide a reusable **credential-isolated execution mechanism**,
not an Auths-maintained catalog of provider profiles. A developer defines an
exact operation using the existing self-hosted profile contract and a
restricted declarative request recipe. An operator separately approves the
compiled recipe, binds it to a credential and trust configuration, and runs a
gateway that is the only process able to use that credential. The application
submits proof and canonical action bytes; it cannot submit a provider URL,
headers, body, token, or executable callback to the gateway.

This introduces a third, deliberately narrow path:

| Path | Credential owner | Auths claim |
| --- | --- | --- |
| Self-hosted (051–052) | Application | Exact action verified if the application chooses to use the SDK; application can bypass it. |
| Declarative gateway (this spec) | Separately deployed gateway | Exact action verified and one closed request attempted with the gateway-held credential, if the deployment isolation and operator bindings hold. Provider meaning remains unqualified. |
| Qualified managed vertical (040) | Reviewed Auths runtime | Separately qualified provider, recovery, and receipt claims for that exact vertical. |

“Non-bypassable” here is **relative to the credential bound to this gateway**.
It does not prevent an account owner from using another credential or the
provider's own UI. A library called inside the credential-owning application,
an application-readable token file, or a gateway that accepts arbitrary HTTP
cannot make this claim.

The current boundary plan and AP-SPEC-051 prohibit loading third-party
executors or promoting self-hosted adapters into the privileged runtime.
Implementation of this spec therefore **requires an explicit ADR and updates
to those documents before code is shipped**. The approved exception must be
limited to a data-only, operator-approved recipe interpreter whose shared
contract is provider-independent. It must not waive the vertical-first rule
for provider semantics or grant qualified receipts to developer definitions.
If the abstraction case file cannot establish that boundary, keep the first
gateway operation as a reviewed vertical instead.

## 2. UX

The developer uses the packaged Python or TypeScript SDK to create the same
typed exact action as in 051–052. A companion recipe file describes only the
closed outbound request and, optionally, a bounded read-only observation. The
compiler reports the action-to-request mapping and its digest before an
operator approves it. No provider credential or production trust is generated
by `init`, `compile`, or `check`.

Proposed terminal flow; command spelling may be refined before public freeze:

```text
$ auths-profile init --language python --name set-demo-status
$ auths gateway recipe init --profile profile.toml
$ auths gateway recipe check recipe.toml
  action:       airtable.set_demo_status_v1
  write:        PATCH https://api.airtable.com/v0/<fixed-base>/<fixed-table>/<record-id>
  body:         {"fields":{"DemoStatus":<replacement>}}
  credential:   bearer, gateway-held; no token loaded by this command
  digest:       sha256:<immutable compiled-recipe digest>
  claim:        closed transport only; provider effect unqualified

# Separate operator/admin identity and channel:
$ auths gateway install compiled-recipe.bundle --approve-digest sha256:<digest>
$ auths gateway credential bind --connection <connection-id> --recipe sha256:<digest>
  # Secret enters through an operator-only input channel; never an argv value.
$ auths gateway doctor
  action trust: independently provisioned
  recipe: approved and immutable
  connection: active; credential generation pinned
  app access to credential: denied by deployment boundary

# Application channel:
$ my-app-submit proof.cbor action.cbor
  authorized | denied | indeterminate
  not-entered | attempting | response-recorded | unknown | observed
```

The operator preview must show the origin, method, fixed and substituted path
segments, fixed body keys, typed argument sources, credential scope, maximum
request/response sizes, timeout, redirect policy, and observation rule. A
changed recipe produces a new digest and needs a new approval; there is no
silent in-place edit. Diagnostic output and evidence never contain the token,
Authorization header, unbounded response body, or user-supplied secret fields.

## 3. Architecture

```text
 app / agent (no provider credential)       operator/admin channel
       | proof + canonical action             | approved recipe, trust,
       |                                     | connection + secret generation
       v                                     v
 +-------------------------------------------------------------+
 | Separate Auths gateway                                      |
 | native verify -> typed projection -> recipe-digest binding |
 | -> closed request compiler -> durable one-use claim         |
 | -> scoped credential lease -> broker-owned HTTPS transport  |
 | -> durable response classification -> optional read-only GET|
 +-------------------------------+-----------------------------+
                                 |
                     fixed operator-approved origin
                                 v
                           provider API
```

The gateway is a product-layer service. Core remains offline and unchanged
unless a precise missing canonical binding is demonstrated. Python and
TypeScript bindings expose typed client/admin surfaces over the same Rust
behavior; they do not reimplement proof verification or recipe enforcement.
The request compiler and transport may share a bounded mechanism; provider
status meaning, account discovery, postconditions, and safe retry decisions
remain operation-owned. No Python/JavaScript/Rust/WASM recipe code executes in
the gateway, and the gateway never calls an application callback with a
credential lease.

The first deployment is a separate single-host process with distinct OS
identity, private credential storage, a restricted application socket, and a
separate operator/admin socket. The app must not share its environment,
filesystem permissions, or secret-store access. A multi-host claim requires a
transactional shared attempt store and equivalent service/network isolation;
the single-host file store from AP-SPEC-051 does not become one by relabeling.
The release claim records which deployment mode was exercised.

### 3.1 Immutable operation binding

An operation consists of a versioned `ExactMcpTool` contract, a compiled
recipe digest, a connection binding, and operator-approved trust. The
**canonical action bytes themselves** must commit to the recipe digest and a
stable logical operation ID **and its operator-controlled namespace**. The
operator assigns a namespace to the approved connection/account binding; the
gateway validates the verified namespace and bounded ID against that binding.
The namespace is an immutable generated literal, not a caller-selected field;
the application supplies only the logical ID. Both are canonical ASCII tokens
matching `[A-Za-z0-9][A-Za-z0-9._-]*`, with maximums of 64 and 128 bytes
respectively. The gateway rejects empty, noncanonical, or oversized values
before claim. It stores the pair as two typed fields, never an ambiguous
concatenated string. The submitter cannot supply a namespace outside the
verified action. The durable replay key is `(namespace, logical_operation_id)`,
independent of proof challenge, signature, action commitment, recipe digest,
and credential generation. A second action with that key, even if otherwise
valid or re-signed under a new challenge, cannot create another provider
entry; a changed action or recipe under the same key is rejected rather than
treated as an update. Claims remain retained for as long as the namespace can
accept submissions; a retired namespace cannot be reused without preserving
its claim history. A different ID denotes a different requested operation,
not a claim that the provider effect is semantically unique.

The gateway compares verified identity and digest with its installed recipe
and credential binding before claim or credential access. Neither a sidecar
manifest nor a submit-time `recipe_id` may supply a missing binding.

`authorized` has one narrow meaning: native verification accepts the exact
canonical action under independently supplied trusted context. It does not
mean the provider accepted or performed the write. The gateway may enter the
credential-bearing write transport **if and only if** verification is
`authorized`; typed projection of that action succeeds against the installed
versioned `ExactMcpTool`; its verified recipe digest, namespace, and logical ID
match an active immutable operator approval that pins the connection and
credential generation; the closed request compiles solely from approved
literals and verified bounded fields; and an atomic durable claim of the replay
key succeeds before credential access. Failure or indeterminacy of any predicate
means no provider entry. A valid proof can therefore still receive a
`not-entered` refusal (for example, replay or revoked connection); that refusal
must not be mislabeled a proof denial. No testkit trust fallback is permitted.

Prefer adding a required typed literal/digest field to the existing
`auths.mcp/v2` argument contract rather than inventing another action or
verification protocol. If existing canonical fields already supply an
equivalent commitment, document and test that equivalence before adding a
field. A recipe update changes the digest and requires a new authorized
action; an old proof cannot execute under the new mapping.

### 3.2 Restricted recipe language

The source format compiles to a versioned, bounded typed AST. It initially
permits:

- one operator-pinned HTTPS origin and one fixed write method from
  `POST | PUT | PATCH | DELETE`; `GET` is available only for the separately
  declared read-only observation;
- a path of fixed segments and explicitly typed, percent-encoded segments
  derived only from verified command fields;
- fixed literal `Accept` and `Content-Type` headers, plus an optional
  `Idempotency-Key` value derived deterministically from the verified
  namespace and logical operation ID; these are the entire recipe-header
  allowlist in the first version. The gateway alone injects the credential
  header named by the connection binding and protocol-required transport
  headers. A derived recipe records only its credential requirement;
  `recipe check` fails if that requirement and the binding disagree. The recipe
  cannot name or set the injection header as an ordinary header. Operator
  approval cannot widen the recipe-header allowlist; all other recipe headers,
  including custom `X-*` headers, are rejected;
- a fixed-shape JSON or form body of literals and typed field references;
  a form field may contain a compiler-serialized bounded JSON template (needed
  for Todoist's Sync command), never a caller-supplied JSON string;
- an optional separately declared read-only request with bounded response
  projection and exact comparison. A comparison result is an observation of
  provider state only; it never means write success, exclusive causation, or
  permission to retry; and
- hard limits for fields, depth, total bytes, response bytes, redirects (zero),
  DNS/connect/read time, and total work.

Dynamic hosts, schemes, ports, arbitrary paths, arbitrary header names,
caller-supplied Authorization, raw body passthrough, dynamic JSON keys,
conditionals, loops, scripts, external references, and runtime plugin loading
are rejected. A finite operator-approved enum may select among fixed keys or
segments only after its closed mapping is represented in the AST and tested.
For example, the first Airtable recipe may fix `DemoStatus`; it must not accept
an arbitrary field name merely because the previous self-hosted demo did.
Operations that cannot fit this language remain self-hosted or become reviewed
verticals. “Support any API” is not an exit criterion.

The gateway's transport resolves only the approved hostname under its egress
policy, verifies TLS for that name, rejects redirects and private/metadata
destinations unless explicitly operator-approved for a different deployment,
and never exports the injected credential in response data or telemetry.
An untrusted recipe author cannot turn a bound credential into an SSRF or
credential-exfiltration capability by changing an action field.

#### 3.2.1 First-version source and compiled identity

The first source format is a closed JSON object with schema
`auths.gateway-recipe-source/1`: `profile_schema_digest`, versioned MCP
`service`/`tool`, immutable `operator_namespace`, `credential`, `origin`,
`write`, and optional `observation`. It compiles against the SDK-generated
`auths.self-hosted-profile-lock/1` (generator format 2), not a caller-supplied
schema at execution time. The compiler recomputes the lock's schema digest,
matches service/tool/digest, rejects unknown keys, and parses every source
node into a typed AST. Source and lock are bounded at 64 KiB each. The
compiled digest is SHA-256 over `auths.gateway-compiled-recipe/1` followed by
a NUL byte and RFC 8785 canonical serialization of the validated source.
Operator approval commits to that digest and to the exact lock digest; it
does not approve a mutable source file path.

The generated command has required `operator_namespace`, `operation_id`, and
`recipe_digest` fields. The namespace field is a one-variant enum equal to
the operator-approved literal; the ID is a 1–128-byte canonical ASCII token;
the recipe digest is exactly 64 lowercase hexadecimal bytes. The generated
type and runtime compiler both check these. All other fields in the first
version are root-level bounded scalar string, enum, integer, or boolean
nodes. Each must be consumed by the write or observation mapping; an unused
field is refused rather than silently shown in an approval while having no
effect. Nested profile fields, nullable fields, dynamic queries, conditional
omission, runtime-defined header names, and arbitrary JSON passthrough are
out of this first compiler. This is a deliberately smaller language than the
self-hosted SDK's full schema vocabulary, not a promise to interpret unknown
nodes as strings.

`write` has one `POST | PUT | PATCH | DELETE`, 1–16 typed path segments, and
one fixed-shape JSON or form body. A path segment is either a fixed safe
literal or a field reference whose verified bounded bytes are percent
encoded; neither may become a scheme, host, port, query, or extra segment.
Form fields are fixed keys with bounded literals, scalar references, or
compiler-serialized JSON; a top-level form-JSON array in this first version
contains one element, so the Todoist Sync fixture cannot acquire a second
command. The optional observation is one GET to the same pinned origin with
a fixed JSON pointer, a verified comparison value, and a response-byte cap.
It records equality or inequality only, never causation or retry permission.
The canonical Airtable, Todoist, and GitHub sources and hostile mutations are
under `bindings/fixtures/gateway/`; the [type map](../product/DEVELOPER_GATEWAY_TYPE_MAP.md)
states ownership and the deliberately different Airtable self-hosted versus
gateway semantics.

### 3.3 Execution and claim truth

The ordered path is verify/project, compare recipe and trust bindings, compile
the closed request, atomically claim the logical operation, acquire the exact
credential generation, enter transport, durably record the response class,
then optionally observe. Denial, indeterminate, recipe mismatch, replay,
credential unavailability, and request-construction failure must all stop
before provider entry. The durable pre-entry stage is `not-entered`; after a
successful claim but before entry it is `attempting`. A crash after claim is
conservatively `unknown` unless a durable checkpoint **excludes transport
entry**, including any in-flight handoff. Merely constructing the request or
lacking a local entry log is not such a checkpoint. The transport boundary
must make this exclusion durable; otherwise recovery reports `unknown` and
never automatically retries.

After provider entry, a complete bounded HTTP response without separate
read-back is `response-recorded`, **not** `confirmed`, `observed`, or a
provider-effect claim, whatever its status code. A timeout, connection break,
malformed or incomplete response, or any other ambiguous entry is `unknown`
with respect to effect; a 4xx or 5xx cannot by itself establish absence of an
effect or authorize retry. `observed` requires a completed, separately
recorded read-only comparison against the verified expected value and records
`match` or `mismatch`. Unavailable read-back is recorded as such but does not
promote the stage from `response-recorded` (or resolve an `unknown` write).
Even a match is not proof of exclusive causation. A non-match or unavailable
observation never licenses an automatic second write. Provider-native
idempotency supplements the gateway claim; it does not replace it.

The gateway may issue a signed **gateway attempt attestation** containing the
action commitment, recipe digest, credential-reference commitment/generation,
request digest, stage, and bounded observation provenance. It must not call
this a qualified execution receipt or assert provider success beyond observed
facts. Secrets and full provider responses remain absent.

## 4. Type ownership and type-driven development

Before adding a public type or crate, implementation must create a type map
showing which existing contract supplies each invariant. Reuse is semantic,
not a synonym for forcing an incompatible type into a new role:

| Existing owner/type | Reuse or boundary |
| --- | --- |
| `auths.mcp/v2`, `ExactMcpTool`, generated command, `AuthorizedCommand` | Reuse canonical action, closed schema, native verification, and typed projection. No second generic `Action` or Python/TypeScript verifier. |
| Native `TrustedContext` and SDK `ProductionAuthoringInputs` | Reuse independent production authority/trust input contracts; no testkit fallback. |
| `auths-connections` `ConnectionId`, `ConnectionBinding`, `ConnectionState`, `CredentialScope`, `ConnectionCredentialStore`, `SecretBytes`, `CredentialReferenceCommitment`, and secret lease | Reuse connection identity, scope, generation pinning, revocation, and opaque storage where their existing contracts fit. Do not expose `StoredSecretLease` to recipe code or use the qualification-only broker in production. |
| `auths-lifecycle` durable transition/store and `auths-operations` event vocabulary | Compare exact claim, crash, and stage semantics before reuse. Preserve existing types when equivalent; document divergences in the abstraction case file rather than duplicating a near-identical state machine. |
| `auths.execution.AttemptStore` / TypeScript `AttemptStore` | Reuse local reference behavior and test vectors, not its single-host file implementation as a multi-host enforcement store. |

New gateway-only types may include `CompiledRecipe`, `ApprovedRecipe`,
`BoundOperation`, `ClaimedAttempt`, and `ClosedProviderRequest`. The
product-layer gateway contract owns `OperatorNamespace` (approved, immutable
connection/account namespace) and `LogicalOperationId` (canonical bounded
application ID); generated Python and TypeScript commands use their exact
validation. Before creating either type, the required type map must show why
an existing bounded identifier does not already carry that invariant. Each
new type needs a private constructor, a named owning package, a stated
invariant, and a test
that demonstrates why an existing type is insufficient. An unparsed
`serde_json::Value`, Python `dict[str, Any]`, TypeScript `Record<string,
unknown>`, or bag of optional flags may exist only at the input boundary; it
must be parsed once into a closed typed AST before any authority or credential
decision. Impossible stages must be unrepresentable through public APIs:

```text
UntrustedSubmission
  -> VerifiedAction<ExactCommand>
  -> BoundOperation<ApprovedRecipe, ConnectionBinding>
  -> ClaimedAttempt
  -> ClosedProviderRequest
  -> ProviderEntered / NotEntered
  -> RecordedOutcome / RecoverableUnknown
```

Development is test-driven from these types: first add compile-fail/API-misuse
tests and hostile recipe/action fixtures, then the smallest implementation that
passes them. Add property tests for parsing and template substitution; tests
for wrong recipe digest, altered command, origin/path/header injection,
credential timing, claim races, restart at every checkpoint, and never-retry
unknowns. Rust owns the interpreter semantics; Python and TypeScript must
pass the same canonical cross-language corpus. No new generic callback port
may be added solely to make the gateway look extensible.

## 5. APIs

Names below are proposed public concepts, not claims that they exist today.
The package generator produces a typed operation binding alongside the
existing generated `CONTRACT`; the application submits only proof and action
bytes. The gateway derives all command fields and identity from verified bytes.

```python
from auths.authoring import ProductionAuthoringInputs, author_production_mcp_proof
from auths.gateway import GatewayClient, GatewayEndpoint
from my_operation.generated import (
    APPROVED_NAMESPACE, APPROVED_RECIPE_DIGEST, CONTRACT, SetDemoStatus,
)

async def request_status_change(
    *,
    operation_id: str,
    record_id: str,
    operator_inputs: ProductionAuthoringInputs,
    endpoint: GatewayEndpoint,
):
    # The compiled package supplies this immutable digest; no runtime URL.
    command = SetDemoStatus(
        operator_namespace=APPROVED_NAMESPACE,
        operation_id=operation_id,
        recipe_digest=APPROVED_RECIPE_DIGEST,
        record_id=record_id,
        replacement="Approved",
    )
    authored = await author_production_mcp_proof(
        contract=CONTRACT, command=command, inputs=operator_inputs,
    )
    return await GatewayClient(endpoint).submit(
        proof=authored.proof, action=authored.action,
    )
# The caller obtains operator_inputs and endpoint through separate configured
# channels. The result separates denial, provider entry, unknown, and observation.
```

TypeScript exposes the same generated command, proof/action submission, and
discriminated result states. `GatewayClient` has no provider token parameter.
The separate admin API installs an `ApprovedRecipe` and binds a
`ConnectionBinding` to its exact digest and credential generation. The
application identity cannot invoke that API. No public method accepts a URL,
HTTP method, raw provider request, or credential lease at submission time.

## 6. Epics and acceptance

### Epic 1 — Prove the abstraction and compile typed recipes

1. Produce the ADR and abstraction case file required by the boundary plan.
   Compare Airtable fixed-field update, Todoist task creation, and a third
   independent GitHub issue-creation recipe. Identify identical transport
   mechanics versus divergent provider effects and reconciliation. Update
   AP-SPEC-051 and the target-state plan only for the approved data-only path.
2. Specify and implement the bounded recipe AST and deterministic compiler,
   using existing profile schema and canonical action types. Bind its digest
   and logical operation ID in verified action bytes.
3. Generate Python and TypeScript types and hostile/canonical vectors from
   packaged SDKs. Reject any recipe construct the Rust interpreter cannot
   enforce without executing third-party code.

**Acceptance:** all three recipes compile without editing Auths source, a
digest or mapping change invalidates an old action, and no recipe can express
an arbitrary destination or raw credential-bearing request.

### Epic 2 — Isolate and bind credentials

1. Implement the separate gateway process and operator-only install/credential
   channel, reusing `auths-connections` identities, generation and secret-store
   contracts where compatible. Bind one approved digest, connection, scope,
   account commitment, and credential generation.
2. Enforce OS/service separation, private secret storage, TLS/egress policy,
   no redirects, response redaction, and revocation/rotation behavior. Never
   deliver a token or lease to the app or recipe interpreter.
3. Provide a deployment doctor that tests the actual boundary, not merely the
   presence of a configuration file. Refuse the non-bypassable label when app
   and gateway share readable secrets or equivalent credential access.

**Acceptance:** the app can submit an authorized action but cannot read or use
the gateway-held credential; a malicious recipe cannot send it to another
origin. Disabling/revoking the binding stops new writes before provider entry.

### Epic 3 — Enforce one-use closed execution and honest recovery

1. Reuse or narrowly adapt existing lifecycle/attempt types after the written
   state-contract comparison in the abstraction case file. SDK `confirmed`
   means adapter acceptance and must not be reused as gateway effect evidence
   or equated with lifecycle `Committed`. Preserve the gateway's own
   `not-entered | attempting | response-recorded | unknown | observed` stage
   vocabulary; do not claim the existing Postgres lifecycle store is a
   scalable gateway claim store. Atomically claim `(namespace,
   logical_operation_id)` across concurrency and restart before credential
   lease or network entry.
2. Compile the verified command plus approved recipe into a closed request.
   Make transport outcome and effect observation separate typed results.
3. Implement durable unknown-state recovery and read-only observation. Do not
   infer safe retry from timeout, 4xx, 5xx, or non-observation. Record
   stage-specific, bounded, secret-free gateway evidence.

**Acceptance:** denied, substituted, replayed, raced, and malformed actions
produce zero provider entries; a crash cannot produce a second automatic
write; unknown remains unresolved until explicit provider-specific evidence.

### Epic 4 — Demonstrate and qualify the precise claim

1. Migrate the field-lab Airtable and Todoist demos to the gateway path while
   retaining separate self-hosted examples; prove the same actions from
   packaged SDKs and independent production-style trust inputs. The third
   recipe exercises the compiler's claimed generality, not a new Auths-owned
   qualified vertical.
2. Run live calls on disposable provider resources and independently read them
   back. Add adversarial deployment tests for credential access, origin
   substitution, proof/recipe mismatch, replay, process crash, and egress
   escape. Hosted CI uses synthetic credentials and providers only.
3. Give an outside developer the packaged SDK, recipe docs, and a fresh API
   task. Record setup time, interventions, missing types, and failures; fix
   friction before claiming self-service adoption.

**Acceptance:** on one documented isolated deployment, the application cannot
use the bound credential except through an authorized exact recipe; provider
calls and read-back are observed; the outside developer succeeds without an
Auths source edit; CI and claim ledger identify exactly what Auths, the
gateway, and the developer/provider each established. Qualified provider
effect or exactly-once claims remain out of scope until a reviewed vertical
earns them.

## 7. Non-goals and release rule

This spec does not provide universal OAuth, browser automation, arbitrary API
proxying, third-party executable plugins, provider-agnostic postconditions,
automatic safe retry, multi-provider transactions, or a qualified execution
receipt for developer-defined behavior. Initial static credential-in-one-header
scope is not a promise that all APIs fit the recipe language.

The gateway must not ship under a non-bypassable or production-qualified
label until its ADR, type inventory, security isolation, exact-claim tests,
cross-language fixtures, hosted CI, live bounded demonstration, and external
adoption evidence all exist on the same reviewed revision. No count of
Auths-maintained provider profiles is an exit criterion.
