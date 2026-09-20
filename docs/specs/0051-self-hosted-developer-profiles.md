# AP-SPEC-051: Self-hosted developer profiles

- **Status:** Proposed
- **Audience:** Python/TypeScript SDK maintainers, profile contributors, and
  security reviewers
- **Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are
  requirements on the proposed developer interface
- **Scope:** let an application author one exact, proof-authorized external API
  operation with the public Auths SDK, without changing this repository or
  installing a qualified Auths executor
- **Depends on:** [AP-SPEC-040](0040-generic-profile-sdk-and-contributor-system.md),
  the [profile/domain abstraction boundary plan](../target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md),
  and the existing `auths.mcp/v2` exact-tool action contract

## 1. Decision

Auths needs two explicitly different ways to build an integration:

| Path | Who implements and runs the provider effect? | What Auths attests? |
| --- | --- | --- |
| **Self-hosted developer profile** (this spec) | The application; it supplies its own provider credential, exact request mapping, persistence, and observation | Verification of the exact action under the supplied trusted context, plus any separately exercised SDK mechanism guarantees. Not correct provider execution. |
| **Qualified managed profile** (AP-SPEC-040) | A statically linked, reviewed Auths vertical and credential-owning runtime | Its separately qualified execution, recovery, and receipt claims in addition to authorization. |

The first path is a supported product surface, not an unqualified version of
the second path. An application can use it immediately, but passing its tests
does not turn its code or provider behavior into an Auths-qualified vertical.

This spec deliberately **amends the current AP-SPEC-040 contributor rule**
that a third party must build a matching qualified Rust executor before its
effect can be used. That rule remains true for an effect *executed by the
Auths runtime* or sold as a qualified managed profile. It does not apply to
an application's self-hosted effect, which never enters that runtime's static
roster or receives its credentials. Implementation MUST update AP-SPEC-040,
the target-state plan, SDK claim text, and architecture policy together so
neither path silently inherits the other's guarantees.

## 2. User experience and boundaries

The first supported operation shape is one named `auths.mcp/v2` tool call,
with a fixed service, tool, version, closed argument schema, permission,
audience, and size bounds. It is not a general URL/HTTP method/headers
manifest. Further action shapes require separate, reviewed contracts.
Here, "developer profile" means a versioned application-owned contract over
that existing action shape, **not** a newly registered core profile ID or a
runtime-installed Auths integration.

Illustrative terminal flow (command names are normative, output is not):

```text
$ auths profile init --language python --name todoist-create-task
  profile.toml              exact MCP service/tool and schema identity
  src/.../command.py        generated bounded command type
  src/.../provider.py       application-owned TODOs: credential, request, observe
  tests/...                 denial, mutation, replay, uncertain-result fixtures

$ auths profile check
  ✓ schema and canonical action vectors
  ✓ authorized command cannot be projected from denied proof
  ✓ gateway tests: denial before credential lookup
  ! provider effect is developer-owned; no Auths qualification claim

$ auths profile doctor
  signer: configured by application/operator
  trust anchors: loaded from operator-owned configuration
  provider credential: application-owned, not inspected by Auths
  runnable: yes; qualification: self-hosted only
```

The TypeScript CLI (`auths profile init --language typescript`) MUST produce
the same contract and canonical vectors. A developer can implement another
operation by changing the schema and writing its provider adapter, without
forking Auths, authoring a Rust fixture binary, or adding a built-in provider
profile. Neither CLI creates production signing authority, trusted anchors, or
provider credentials automatically.

### 2.1 Trust and data flow

```text
  operator's authority/signing key          independently provisioned trust
              |                                        |
              v                                        v
    public proof-authoring SDK                   trusted context
              |                                        |
              +------ proof + canonical action -------+
                                                      |
                                                      v
                                              Auths verifier (pure)
                                                      |
                                           denied / indeterminate / authorized
                                                      |
                                         strict exact-command projection
                                                      |
                                         application-owned one-use boundary
                                                      |
                                      application-held provider credential
                                                      |
                                                      v
                                             external provider API
                                                      |
                                       app-owned observe/reconcile/result
```

The signer and trusted context are separate inputs even if a local testkit
creates both. A production application MUST NOT implicitly trust a key merely
because that same application generated it. Because the self-hosted process
may also hold the provider token, Auths cannot prevent malicious or buggy
application code from bypassing the gate and calling the provider directly.
This limitation MUST be stated in the SDK docs and CLI output, not buried in
a security appendix.

## 3. Goals and exclusions

The implementation MUST:

1. replace the field-lab demos' duplicate Rust proof-authoring binaries and
   hand-rolled CBOR/JSON action decoders with supported Python and TypeScript
   SDK surfaces;
2. give a typed, bounded, exact-action authoring/verification path with
   unambiguous `denied` and `indeterminate` outcomes;
3. make it possible to keep all provider-specific work in the developer's
   repository, using credentials already obtainable from the provider;
4. supply a reusable local one-use attempt mechanism and honest
   `unknown`/reconciliation vocabulary, without pretending this is a
   provider-qualified execution runtime; and
5. provide conformance fixtures and an executable quickstart in both
   languages, with no Auths repository modifications by a consumer.

This spec does **not** add an arbitrary `invoke(operation, dict)` API, an
untyped callback registry in the privileged Auths gateway, dynamically
downloaded executor plugins, a generic provider URL/header/verb builder, an
Auths-hosted credential vault for custom profiles, or automatic qualification
of third-party provider semantics. It does not promise exactly-once external
effects, provider acceptance, observed success, or formal verification of
application-owned code.

## 4. Architecture: contract and generated types

`profile.toml` declares an immutable namespace, contract version, exact MCP
service and tool, permission, audience constraints, and a *restricted* closed
argument schema. Supported initial schema constructs: bounded UTF-8 strings,
bounded bytes, checked integers, booleans, optional fields, fixed-shape
objects, and bounded homogeneous arrays. Every field and aggregate MUST have
checked size/depth limits. Duplicate keys, unknown keys, noncanonical CBOR,
invalid Unicode, ambiguous numbers, and overlong inputs fail closed. No
`Any`, arbitrary JSON object, external schema `$ref`, user-provided decoder,
or stringly typed profile/effect selector is allowed in an executable command.

Generation produces immutable typed input/command declarations, a canonical
encoder, a strict decoder, schema and action-identity constants, and
cross-language golden vectors. The generator MUST reject a schema it cannot
bound or decode identically in Rust, Python, and TypeScript. It MUST NOT infer
provider request semantics from argument names. `profile.toml` is source
configuration, not a credential/trust-anchor file.

The authored action MUST bind service, tool, profile version, exact arguments,
permission, audience, and any supported expiry/challenge into the existing
canonical `auths.mcp/v2` contract. The projection MUST parse the action bytes
actually submitted to the verifier, check all these bindings against the
compiled contract, and return values only from those bytes. A caller's
sidecar `scope.json`, UI preview, or newly supplied arguments cannot replace
the verified action. The prepared-action preview and resulting commitment
MUST be available before asking for an approval/signature.

## 5. Public APIs

Names below define the intended stable concepts; implementers MAY refine
spelling before freezing the public inventories, but MUST preserve the
security and ownership boundaries. The examples are sketches, not claims
that these APIs already exist.

### 5.1 Python example

```python
from auths.authoring import prepare_proof, sign_proof
from auths.self_hosted import AuthorizedCommand, ExactMcpTool, verify_command
from todoist_create_task.generated import CreateTask, CONTRACT

tool: ExactMcpTool[CreateTask] = CONTRACT
prepared = tool.prepare(
    CreateTask(content="Review budget", command_uuid=run_id),
    audience=operator_selected_audience,
    expires_at=deadline,
)
print(prepared.review_fields, prepared.action_commitment)

# The signing authority and its grant are explicitly supplied; neither is
# inferred from the provider token or minted by verify_command.
unsigned = prepare_proof(action=prepared.action, grant=operator_grant)
proof = await sign_proof(unsigned, signer=operator_custody_signer)

result = verify_command(
    contract=tool,
    proof=proof,
    action=prepared.action,
    trusted_context=operator_trusted_context,
)
if not isinstance(result, AuthorizedCommand):
    raise AuthorizationError(result.kind, result.code)

command: CreateTask = result.command
# The app owns its atomic attempt store, credential, provider request, and
# provider-specific observation. See §6 before making the external call.
```

`operator_grant` represents explicit scoped authority; `sign_proof` invokes
the existing custody signer port, never accepts a raw signing seed in the
production convenience API, and returns portable proof bytes. Exact grant
construction, role binding, and context serialization MUST be implemented
against existing proof semantics, not invented by the Python wrapper. It MUST
not silently replace a missing signer with an ephemeral development key.

### 5.2 TypeScript parity

The TypeScript bindings MUST provide the same three separable operations:

```ts
const prepared = contract.prepare(input, { audience, expiresAt });
const unsigned = prepareProof({ action: prepared.action, grant });
const proof = await signProof(unsigned, { signer });
const result = verifyCommand({ contract, proof, action: prepared.action, trustedContext });
if (result.kind !== "authorized") throw new AuthorizationError(result);
const command: CreateTask = result.command;
```

Python and TypeScript MUST agree byte-for-byte on prepared actions, proof
transport, command projection, and decision classification for the same
fixtures. Generation into a clean consumer workspace MUST work using only
published SDK packages/CLI, not a relative checkout of Auths Rust crates.

### 5.3 Result and authority types

`verify_command` returns a discriminated `authorized | denied |
indeterminate` result; exceptions are reserved for API misuse or transport
faults, never to collapse an indeterminate authorization into permission.
Authorized results carry the verifier's decision, action commitment, contract
identity, and typed command. The command is a derived projection, not a
separately forge-proof credential in Python or TypeScript. The SDK MUST NOT
expose a constructor that takes arbitrary caller-provided arguments and
labels them authorized. Re-encoding or changing fields after verification
invalidates the projection; no method turns a command into a new proof.

The public authoring surface MUST support externally managed signers and
explicit trusted-context provisioning. Development fixtures MAY provide a
single-command ephemeral signer/context pair, but MUST live under
`auths.testkit`, be unmistakably labeled local-only, and never be used by
production `prepare_proof` or `verify_command` defaults.

## 6. Local execution mechanism and developer-owned adapter

The SDK MUST expose a small `AttemptStore` protocol with an atomic
`claim_once(action_commitment, operation_key)` transition before provider
entry and durable `attempting`, `confirmed`, `rejected`, and `unknown` states.
An included file-backed single-host implementation MAY be provided for CLI
demos; it MUST use exclusive creation, private permissions, bounded records,
durable writes, and explicit limitations for NFS/multiple hosts. A production
database adapter is application-owned unless independently qualified.

Successful verification alone does not imply single-use. The reference
runner's sequence is mandatory for consumers of this mechanism:

```text
strict command projection -> atomic claim -> credential access -> exact request
                       -> provider result classification -> durable outcome
                                                      -> optional observation
```

If claim fails, it MUST NOT access the credential or send a request. A crash
after claim but before a known response is `unknown`, not safely retryable.
The SDK MUST NOT automatically retry a possibly applied external write.
Observation outcomes distinguish `confirmed`, `not_observed`, and
`observation_unavailable`; `not_observed` is not proof of non-application.

The application's provider adapter owns exact URL/method/body construction,
credential scope and custody, request idempotency semantics, status mapping,
read-back, and reconciliation. The SDK MUST provide an example adapter port
with exact typed command input and explicit outcome types, **not** a generic
callback dispatcher with access to arbitrary tools or provider credentials.
The application can bypass this local runner because it owns its own token;
the runner provides a good default and testable mechanism, not a sandbox.

When a developer needs non-bypassable gateway enforcement, Auths-held
credentials, multi-host exactly-once claims, or qualified provider effects,
the upgrade path is the AP-SPEC-040 reviewed vertical. Passing `profile check`
MUST NOT automatically promote a self-hosted package to that path.

## 7. Claim boundaries and conformance

The SDK, CLI, examples, and receipts MUST use this vocabulary:

- **Auths authorized this exact action**: proof verified against the supplied
  trusted context and the command was projected from those action bytes.
- **Attempt was claimed**: the specified store reported a one-use claim in
  its documented deployment scope; not proof of provider execution.
- **Provider accepted / effect observed**: the developer adapter's own
  evidence, explicitly attributed to that adapter and observation method.
- **Qualified end-to-end**: reserved for a separately qualified, credential-
  owning Auths vertical with its required evidence.

Never display `verified`, `complete`, or `safe` as an undifferentiated success
state. Do not issue an Auths execution receipt for a self-hosted provider call
that would be mistaken for an Auths-qualified execution receipt. A portable
developer observation record MAY link to the Auths decision commitment if it
identifies its application issuer and unqualified status.

SDK CI and the generated `auths profile check` harness MUST cover:

1. canonical and hostile action/proof vectors across Rust, Python, and
   TypeScript, including altered tool/service/arguments/audience/version,
   duplicate keys, bounds, expired proof, wrong trust anchor, denied and
   indeterminate decisions;
2. no command on denial, and no credential access or provider call in the
   reference runner before an authorized command *and* successful atomic
   claim; the generated adapter contract tests MUST exercise the same
   sequence but do not certify arbitrary application control flow;
3. competing claims, replay after restart, crash at each durable checkpoint,
   unknown effect, unavailable observation, and no blind retry;
4. packed-wheel and npm-tarball consumer tests, generated typings, strict
   Python/TypeScript type checks, and public-surface inventory updates; and
5. an SDK-level negative demonstration showing that application code holding
   the provider token can bypass the self-hosted gate (the documented trust
   limitation).

This conformance suite checks reusable mechanisms and sample adapter
behavior. It cannot establish that an arbitrary developer adapter matches its
declared operation or that its provider will behave as assumed. Lean or other
formal results MAY support a precise shared pure-Rust claim only when tied to
shipping code and its stated assumptions; they MUST NOT be advertised as a
proof of generated Python/TypeScript provider code, token isolation, or live
API effects.

## 8. Implementation ownership and order

1. **Core/exchange:** reuse the existing pure proof and `auths.mcp/v2`
   contracts. Add only necessary bounded canonical helpers. No external
   network, credentials, or mutable replay state in core.
2. **Bindings:** expose authoring and typed verify/project in the public
   Python/TypeScript packages; keep native implementation as the single
   canonical semantics source. Add public API inventories, misuse tests, and
   cross-language vectors.
3. **Tooling:** add the restricted schema, deterministic generator, init,
   check, and doctor. Generated profiles are application-owned packages, not
   runtime-loaded plugins or entries in the Auths qualified roster.
4. **Mechanism:** add the narrow attempt-store contract and local reference
   implementation only after its state semantics are independent of provider
   meaning; leave request/result/observation mapping in each app.
5. **Consumer proof:** migrate the existing Airtable and Todoist field-lab
   demos to published SDK surfaces, remove their Rust authoring helpers and
   duplicate parsers, keep their distinct HTTP adapters, and run the same
   authorized/denied/unknown/reconcile scenarios. A clean third-party
   workspace MUST reproduce at least one example from the docs.

Shared mechanisms MUST satisfy the target-state plan's locality and
cross-consumer evidence rules; this spec is not permission to hoist two
provider-specific implementations into a universal executor. If existing
`auths.mcp/v2` native functions are reused, publicly exposing them requires
review of their supported invariants and misuse surface, not a re-export of
private bindings by fiat.

## 9. Exit criteria

This spec is complete when a new developer can, using only the packaged
Python SDK or, independently, the packaged TypeScript SDK and its CLI, define
and run one exact operation
against an API for which they already have a credential, without editing
Auths, compiling a Rust helper, or manually parsing canonical action bytes;
the two field-lab demos prove that path; hosted CI passes its cross-language,
replay, and negative security cases; and the public docs make the self-hosted
versus qualified claim boundary impossible to miss. No count of built-in
provider profiles is an exit criterion.
