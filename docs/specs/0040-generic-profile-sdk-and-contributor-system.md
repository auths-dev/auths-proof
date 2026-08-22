# AP-SPEC-040: Generic profile SDK and contributor system

## Status

Target-state specification. Not yet implemented.

This document is intentionally self-contained. A new implementation session
with no conversation history must be able to implement the target by reading
this document, `AGENTS.md`, and
`docs/target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md`.

Normative words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** have their RFC
2119 meanings.

If this document conflicts with `AGENTS.md`, `architecture.toml`,
`compliance.toml`, workspace metadata, or executable `xtask` policy, those
repository authorities win. The implementer must update this specification
and the executable policy together rather than work around the conflict.

## 1. Decision

Auths will expose a Stripe-like application API over profile-owned exact
effects without creating a universal semantic executor.

For an application developer, the normal path is:

```python
import auths
from auths_profiles.stripe import Stripe

async with auths.connect() as session:
    stripe = Stripe(session)
    refund = await stripe.refunds.create(
        payment_intent="pi_123",
        amount=5000,
        currency="usd",
    )

print(refund.id)
```

```ts
import { connect } from "@auths-dev/sdk";
import { Stripe } from "@auths-dev/profile-stripe";

await using session = await connect();
const stripe = new Stripe(session);
const refund = await stripe.refunds.create({
  paymentIntent: "pi_123",
  amount: 5000,
  currency: "usd",
});

console.log(refund.id);
```

Those first examples use the deployment-configured default Stripe connection
for the observed workload. They do not create, discover, or implicitly choose
an account.

One Auths session multiplexes every provider and account. A provider connection
is selected on the generated domain client, not by calling `auths.connect()`
again:

```python
from auths_profiles.gmail import Gmail
from auths_profiles.vercel import Vercel

async with auths.connect() as session:
    gmail = Gmail(session, connection="support-inbox")
    vercel = Vercel(session, connection="production-team")

    await gmail.messages.send(to="customer@example.com", subject="Update", body="...")
    await vercel.deployments.create(project="dashboard", source_revision="abc123")
```

`support-inbox` and `production-team` are non-secret deployment connection
aliases. The local agent resolves them to sealed provider-account and
credential bindings authorized for the observed workload. Application code
never receives the Gmail refresh token, Vercel token, provider URL, or secret
store reference.

Application code does not:

- read or forward an Auths bearer token;
- receive a provider credential;
- fetch a boundary;
- delegate manually;
- construct an idempotency key for the ordinary path;
- reserve workflow state;
- retry provider effects;
- verify receipt links manually; or
- coordinate recovery and cleanup.

Those responsibilities belong to the SDK, the local Auths agent, and the
selected profile vertical.

For a profile contributor, the normal path is:

```text
cargo xtask profile new --domain stripe --effect refund --version 1
        |
        +-- implement exact Rust semantics in auths-stripe
        +-- complete generated fixtures and vertical tests
        +-- cargo xtask profile generate --domain stripe
        +-- cargo xtask profile check --domain stripe
```

The generator owns language DTOs, bounded codecs, typed client methods,
profile route constants, API snapshots, and conformance scaffolding. The
contributor owns the exact action, evaluator, verified command, provider
gateway, credential scope, lifecycle transitions, reconciliation, and receipt
meaning.

## 2. Why the system is generic without being a generic executor

The stable application experience is generic in these dimensions:

- one ambient `connect()` operation;
- one session lifecycle;
- one profile-package manifest format;
- one bounded provider-connection registry and alias-selection convention;
- one generated-client convention;
- one prepare/execute/recover route grammar;
- one outer result and error grammar;
- one idempotency and recovery mechanism;
- one linked-receipt envelope;
- one conformance and package-qualification harness; and
- one contributor workflow.

The following remain domain-owned and are never selected by a generic
operation callback. Effect items live in the exact profile vertical;
onboarding/account/refresh items live in the provider connection adapter:

- canonical action meaning;
- policy and evidence evaluation;
- denied versus indeterminate classifications;
- reservation intents and release conditions;
- provider command construction;
- credential scope and acquisition timing;
- provider onboarding, account identity, credential refresh, and revocation;
- provider-entry and irreversibility boundaries;
- partial-effect meaning;
- observation and reconciliation;
- domain error codes; and
- profile receipt claims.

The stable SDK MUST NOT expose either of these shapes:

```python
await client.invoke("stripe.refund", arbitrary_dict)
```

```ts
await client.execute({ profile, operation, providerUrl, parameters });
```

There is no public operation string dispatcher, arbitrary URL, verb, header,
credential, callback registry, or untyped JSON execution body. Generated
profile clients call statically registered, profile-specific routes.

### 2.1 Repository baseline at specification time

The implementation starts from, and must reuse rather than duplicate, these
existing components:

- `product/profiles/auths-profile-api`: `ActionProfile`, canonicalization,
  review display, and verified-command decoding;
- `product/sdk/auths-profile-kit`: deterministic profile fixtures and hostile
  mutations;
- `product/runtime/auths-lifecycle`: bounded durable lifecycle records,
  reservations, provider-entry markers, observations, and transitions;
- `product/receipts/auths-receipts`: decision/execution receipt semantics;
- `product/errors/auths-errors` and `product/errors/v1/registry.json`: closed
  effect, retry, action, cause, and error vocabularies;
- `product/runtime/auths-production-client`: current bounded production client
  protocol;
- `product/runtime/auths-node`: current static profile routes and runtime;
- `product/integrations/auths-opentofu`, `auths-postgresql`, `auths-github`, and
  `auths-stripe`: concrete domain verticals; and
- `bindings/python` and `bindings/typescript`: current root, verification,
  profile, protocol, adapter, and testkit surfaces.

The missing infrastructure this specification adds is:

- an authenticated local agent session with no application bearer token;
- a durable authorized provider-connection registry, privileged onboarding
  plane, and generation-bound credential lease mechanism;
- a profile-package manifest and restricted caller-API schema;
- deterministic generated profile distributions;
- a stable profile-client runtime ABI;
- commitment-bound prepare/execute/recover composition;
- a high-level exception facade over explicit safe outcomes; and
- contributor scaffolding and qualification automation.

Existing vertical semantics and fixtures are evidence inputs. Their current
staged application APIs are not the target common-path UX.

## 3. Goals and measurable success criteria

### 3.1 Application goals

The first successful effect in Python and TypeScript MUST require no more
than:

1. one root SDK import;
2. one generated profile-client import;
3. one `connect()` call;
4. one profile-client construction; and
5. one domain method call.

The first-screen example for a qualified profile MUST be at most 25 nonblank
lines, excluding imports, and MUST contain no security placeholder such as
`TODO configure trust`, a hard-coded secret, or an omitted recovery branch.

The ordinary application API MUST contain no parameter named `token`,
`access_token`, `authorization`, `credential`, `private_key`, `signer`,
`boundary`, `delegation`, `recovery_reference`, or `receipt_trust`.

One open Auths session MUST support calls through multiple generated domain
clients and multiple provider connections. Selecting a second account at an
already-installed provider MUST require only deployment onboarding plus a
different non-secret `connection` alias; it MUST NOT require another SDK,
profile, executor build, or Auths session.

### 3.2 Contributor goals

Adding a profile to an existing domain MUST NOT require handwritten changes to
the root Python or TypeScript SDK. Adding a new connected domain adds one
generated profile distribution, one concrete provider-connection adapter, and
one generated static roster merge, but MUST NOT add handwritten domain
branches to a shared evaluator or executor.

Adding another account for an existing provider MUST be a bounded
administrative data operation and require no code generation or rebuild.
Adding a provider kind for the first time MUST require one statically linked,
versioned provider-connection adapter in addition to the exact profile
verticals that use it. Adding another operation for an existing provider MUST
reuse that provider-connection contract while versioning the new operation's
own profile semantics.

For a new profile, generated output MUST include:

- Rust request and result DTOs from the restricted API schema;
- Python frozen DTOs, typed errors, and a profile client;
- TypeScript readonly DTOs, typed errors, and a profile client;
- canonical CBOR codecs and boundary validators;
- exact route constants;
- manifest and schema digests;
- public-API inventory entries;
- positive, malformed, oversized, and boundary-plus-one fixture skeletons;
- packed-package consumer tests; and
- a documentation quickstart.

No generated file may contain profile policy, provider behavior, or receipt
meaning.

### 3.3 Security goals

The system MUST preserve these properties:

- denied and pre-entry unavailable operations acquire no provider credential;
- only a verifier-sealed profile command may reach a provider gateway;
- the executed command is derived from verified canonical action bytes;
- a lost response after provider entry is never reported as safe to retry;
- the SDK never blindly repeats an effect request;
- exact replay produces no new credential request or provider mutation;
- possible effects remain durably recoverable;
- a profile or registry digest mismatch fails before an effect;
- a client cannot select its Auths principal;
- application code never receives provider credential bytes; and
- the selected provider account, connection generation, and configuration are
  commitment-bound before provider entry;
- profile packages cannot widen authority by changing client-side code.

## 4. Non-goals

This specification does not create:

- a generic policy language;
- a dynamic provider-plugin loader;
- a universal OAuth flow or provider-credential format;
- runtime installation of a provider connector;
- an arbitrary workflow engine;
- a profile marketplace that executes unreviewed code;
- a universal provider request type;
- browser-side effect execution;
- a remote bearer-token mode;
- a split local-agent/remote-executor protocol in version 1;
- compatibility shims for superseded prelaunch SDKs;
- automatic migration of disposable prelaunch state; or
- a guarantee that profile semantics are cheap to implement.

Profiles remain security products. The system makes their surrounding SDK,
transport, packaging, testing, and lifecycle mechanics repeatable; it does not
make domain meaning declarative.

## 5. UX contract

### 5.1 Ordinary success

Generated methods return the profile's success DTO directly. Every generated
success DTO has a reserved `auths` field containing immutable operation
metadata:

```python
@dataclass(frozen=True)
class OperationMetadata:
    operation_id: str
    profile: str
    connection: Optional[str]
    completion: Literal["fresh", "replayed", "reconciled"]
    receipt_ids: tuple[str, ...]
```

```ts
export interface OperationMetadata {
  readonly operationId: string;
  readonly profile: string;
  readonly connection: string | null;
  readonly completion: "fresh" | "replayed" | "reconciled";
  readonly receiptIds: readonly string[];
}
```

`auths` is reserved by the profile API schema and cannot be declared by a
profile author. It is synthesized by the SDK from the verified outer outcome
and is not present in profile result bytes.

### 5.2 Ordinary failures

The high-level facade uses typed exceptions because its purpose is a compact
application path. The advanced profile result API MAY expose explicit result
variants, but generated quickstarts MUST use the facade.

```python
try:
    refund = await stripe.refunds.create(...)
except auths.DeniedError as error:
    # Proven not applied.
    log.info("denied", extra={"code": str(error.issue.code)})
except auths.PartialError as error:
    # A profile-defined subset is already applied.
    alert(error.operation_id, error.details)
except auths.RecoveryRequired as error:
    # Effect is possible. Never issue a new operation blindly.
    alert(error.operation_id, error.recovery)
```

Every effect-related exception MUST expose:

- `operation_id` when one exists;
- `issue` using the negotiated common or profile-specific registry projection;
- `effect` as `not-applied`, `possible`, or `applied`;
- `retry` as the existing closed `never`, `safe`, `conditional`, or `unknown`
  registry value;
- `recommended_action`/`recommendedAction` as the existing closed registry
  action;
- `receipt_ids` already durably available; and
- `recovery` when `effect == possible`; and
- profile-typed `progress` on generated recovery errors when already-applied
  progress exists.

The following stable classes are public at the root:

| Python | TypeScript | Meaning |
| --- | --- | --- |
| `AuthsError` | `AuthsError` | Base operational exception |
| `DeniedError` | `DeniedError` | Profile or authority denial; no effect |
| `UnavailableError` | `UnavailableError` | Pre-entry service failure; no effect |
| `ConflictError` | `ConflictError` | Same key, different commitment; recover original |
| `NotAppliedError` | `NotAppliedError` | Provider evidence proves no effect |
| `PartialError` | `PartialError` | Profile-defined subset applied |
| `RecoveryRequired` | `RecoveryRequiredError` | Effect remains possible or unknown |
| `ClientStateError` | `ClientStateError` | Programmer misuse of client lifecycle |

`AuthsIssue` is one immutable host projection with these fields in both
languages (snake case in Python, lower camel case in TypeScript):

| Field | Type |
| --- | --- |
| `code` | negotiated registry string |
| `family`, `operation`, `stage` | registered token string |
| `summary`, `correlationId` | bounded string |
| `retry` | `never | safe | conditional | unknown` |
| `effect` | `not-applied | possible | applied` |
| `entered` | immutable five-boolean approval/signer/state/credential/provider record |
| `recommendedAction` | existing closed action string |
| execution/decision/receipt reference | optional redacted token |
| `causes` | immutable tuple/list of at most eight closed cause strings |

`AuthsError` is SDK-constructible only. It has readonly `issue`, optional
`operationId`, immutable `receiptIds`, and direct `effect`, `retry`, and
`recommendedAction` accessors that return the corresponding issue fields.
`DeniedError`, `UnavailableError`, and `NotAppliedError` add no fields.
`ConflictError` requires an original operation ID and `recovery`. `PartialError`
requires an operation ID and immutable `details`.
`RecoveryRequired`/`RecoveryRequiredError` requires an operation ID and
`recovery` and has nullable immutable `progress`. The latter two base payloads
are typed as `object`/`unknown`; their generated subclasses narrow them to the
profile schema types. `ClientStateError` is a host
`RuntimeError`/`Error`, not an `AuthsError`, because it carries no registry
envelope and always occurs before I/O.

A profile with a partial result schema also generates a typed subclass, such
as `RolloutPartialError`, whose `details` field has the generated partial DTO.
`PartialError` is terminal: the applied subset is proven and the remainder is
proven not applied or denied. If a subset is applied while a later phase
remains possible, the method raises a generated `RecoveryRequired` subclass
whose `progress` field preserves the profile's bounded progress DTO.

### 5.3 Advanced escape hatch

Advanced users MAY opt into explicit outcomes through the generated profile
package:

```python
outcome = await stripe.refunds.create_outcome(...)
```

The explicit outcome is a sealed union of `Completed`, `Denied`, `Unavailable`,
`Conflict`, `NotApplied`, `Partial`, and `RecoveryRequired`. `Partial` is
generated only when `partialType` is non-null. The high-level `create()` method
is exactly a projection of `create_outcome()`; it MUST NOT perform a different
workflow.

The advanced path does not expose boundaries, credentials, arbitrary routes,
or command construction.

### 5.4 Session, client, connection, and profile

These four concepts are deliberately distinct:

| Concept | Cardinality | Meaning and owner |
| --- | --- | --- |
| Auths session | normally one per application process | Authenticated local channel for the observed workload; root SDK owned |
| Domain client | any number per session | Typed navigation for one generated provider/domain package; generated package owned |
| Provider connection | any authorized number per domain | Deployment-owned account/tenant plus credential binding, selected by a non-secret alias |
| Profile | one immutable version per protected operation | Exact action, authority, effect, recovery, and receipt semantics; Rust vertical owned |

A domain client is bound to at most one provider connection for its complete
lifetime. A method cannot override that binding. For a connected domain its
constructor accepts `connection="<alias>"`; omission requests the workload's
configured default for that provider kind. Omission is rejected before an
operation when no default exists. A domain with no external provider
connection has no connection constructor option.

The alias is caller-visible routing data, not a credential and not an
authority grant. It matches `[a-z][a-z0-9-]{0,63}` and is compared byte for
byte. The agent resolves `(provider kind, alias)` only within the observed
workload's authorized connection set. Missing, disabled, revoked, and
unauthorized aliases have one indistinguishable error projection. The client
cannot enumerate connections it is not authorized to use.

Connection resolution supplies identity and a least-privilege credential
lease to a concrete profile gateway. It never constructs the provider request,
classifies effects, chooses retry, reconciles an operation, or makes receipt
claims. Those decisions remain profile-owned. Therefore:

- a second Gmail inbox or Stripe account is a new connection record;
- a new Gmail operation is a new profile that reuses the Gmail connection
  contract; and
- Gmail or Vercel support for the first time requires a reviewed connection
  adapter, one or more reviewed profile verticals, generated clients, and full
  qualification.

The resulting extension paths are:

| Desired change | Required work | No required work |
| --- | --- | --- |
| Add `billing-secondary` to installed Stripe support | Onboard and authorize one connection record | No Rust, SDK, schema, profile, or build change |
| Add `messages.search` after Gmail is installed | Add/version and qualify the Gmail search profile; regenerate the Gmail package | No new Gmail connection adapter |
| Add Gmail for the first time | Implement/qualify `auths.gmail.connection/1`, exact Gmail profiles, and generated Gmail package | No root-SDK or generic-executor branch |
| Add Vercel for the first time | Implement/qualify `auths.vercel.connection/1`, exact Vercel profiles, and generated Vercel package | No root-SDK or generic-executor branch |

Consequently, Auths has profiles per protected operation, not profiles per
account. Connections are reusable account bindings underneath those profiles.

## 6. Architecture

```text
+------------------------ Application process -------------------------+
|                                                                      |
|  Python/TypeScript root SDK       Generated domain package           |
|  auths.connect()             +--> Gmail / Stripe / Vercel            |
|        |                     |    connection alias + typed methods    |
|        +-- ProfileSession ---+    fixed routes + contract digests     |
|                                                                      |
+-----------------------------|----------------------------------------+
                              | HTTP/1.1 over authenticated local IPC
                              | no bearer token, no provider credential
                              v
+------------------- Local Auths agent/executor -----------------------+
| OS peer identity -> Auths principal -> authority source              |
| profile/registry negotiation; authorized connection registry         |
| durable operation journal, static profile/connection routers         |
|                                                                       |
|  connection alias -> sealed account binding -> credential broker      |
|                              |                                        |
|  Profile A: action -> evaluator -> command -> gateway -> receipt      |
|  Profile B: action -> evaluator -> command -> gateway -> receipt      |
|  Profile C: action -> evaluator -> command -> gateway -> receipt      |
|                                                                       |
| shared leaves: bounded codec, lifecycle store, custody, receipts      |
+-----------------------------|----------------------------------------+
                              | least-privilege credential acquired here
                              v
                        External provider
```

### 6.1 Layer ownership

| Concern | Owning package/layer |
| --- | --- |
| Canonical proof and verification | existing `core/` crates |
| Profile action and command contract | `product/profiles/auths-profile-api` |
| Profile vertical semantics | `product/integrations/auths-<domain>` |
| Durable state transition mechanisms | `product/runtime/auths-lifecycle` |
| Linked receipt envelope | `product/receipts/auths-receipts` |
| Stable error registry | `product/errors/auths-errors` |
| Common operation client protocol | `product/runtime/auths-production-client` |
| Local agent and static route composition | `product/runtime/auths-node` |
| Provider connection records and credential leases | `product/runtime/auths-connections` and `auths-stores` |
| Provider-specific onboarding and account validation | `product/integrations/auths-<domain>/src/connection` |
| Profile scaffolding and fixture generation | `product/sdk/auths-profile-kit` and `xtask` |
| Root language session | `bindings/python` and `bindings/typescript` |
| Generated domain clients | separate generated profile distributions |

No production package depends on `demos/` or `xtask/`.

### 6.2 Static profile registration

Every shipping profile is compiled into the executor. A domain package exports
a concrete router constructor such as:

```rust,ignore
pub fn refund_routes(state: Arc<RefundService>) -> axum::Router;
```

`auths-node` merges that router during startup. The shared node does not call a
public `execute(profile_name, callbacks)` trait, and the domain package does
not register behavior at runtime.

The merge is generated from one closed build-time roster:

```text
product/runtime/auths-node/profile-packages.json
```

Its schema is `auths.profile-roster/2` and it contains a byte-sorted array of
`{domain, rustPackage, manifestPath, profiles}` records. Each byte-sorted
profile row has an exact production `state` (`unqualified` or `qualified`), an
independent `testkitAvailable` boolean, parallel byte-sorted `targets` and
`qualificationIds`, and no unknown fields. `xtask profile new` adds the one
unqualified, non-testkit profile record and the corresponding exact Cargo
dependency. The exact roster shape is:

```json
{
  "schema": "auths.profile-roster/2",
  "packages": [
    {
      "domain": "stripe",
      "rustPackage": "auths-stripe",
      "manifestPath": "product/integrations/auths-stripe/profile-package.json",
      "profiles": [
        {
          "profile": "auths.stripe.refund/1",
          "state": "unqualified",
          "testkitAvailable": true,
          "targets": [],
          "qualificationIds": []
        }
      ]
    }
  ]
}
```

Qualified rows require one unique qualification ID per target. Unqualified
rows require empty target and qualification-ID arrays. The testkit flag is
orthogonal to production state: production never consults it, the disposable
testkit build never treats it as production qualification, and qualification
import never changes it. Roster v1 and unknown fields are rejected.

Generation emits:

```text
product/runtime/auths-node/src/generated/profile_routes.rs
```

That generated module imports each concrete router constructor and merges it
without a string dispatcher. CI regenerates and byte-compares the roster,
Cargo dependency set, and module. Handwritten `auths-node` source never gains a
profile match arm. A custom executor uses its own closed roster at build time;
installing a wheel or npm package cannot mutate it.

The roster contains 1-64 domain packages and expands to at most 256 unique
profile ID/version pairs. Paths obey the repository-relative manifest-path
grammar in section 10.3. Duplicate domains, packages, manifest paths, profile
IDs, or static routes fail generation and agent startup.

Generated route glue may call shared bounded transport and lifecycle leaf
functions. It MUST call concrete profile service methods and MUST NOT contain a
generic match over unrelated profile operations.

Dynamic libraries, WASI plugins, JavaScript callbacks, Python callbacks, and
runtime-downloaded profile code are forbidden in this version.

Provider-connection adapters follow the same static-registration rule. A
domain whose manifest declares a connection contract exports one concrete
adapter/admin-router constructor and the generated roster wires it into
`auths-node`. Installing a language package cannot add an adapter. The shared
registry stores bounded records and returns sealed bindings, but it never
dispatches provider effects through an `execute(provider, operation, input)`
interface.

The distinction between code and data is exact:

- adding an account or tenant for an already-compiled provider kind creates a
  connection record and requires no build;
- changing credentials or account configuration creates a new connection
  generation and requires no profile version when operation semantics are
  unchanged;
- adding or changing a provider connection contract requires a new immutable
  connection-contract version and an executor build; and
- adding or changing an effect requires its own profile semantic version and
  qualification, even when its provider connection is unchanged.

### 6.3 End-to-end deployment workflow

The platform team performs these one-time deployment tasks:

1. build an executor containing the qualified profile verticals;
2. configure durable lifecycle, receipt, and idempotency storage;
3. configure custody and least-privilege provider credential brokers;
4. onboard named provider connections through the privileged administration
   plane and authorize them to workloads and profiles;
5. configure receipt decision/execution signers and public trust anchors;
6. map local workload identities to Auths principals and bounded authority
   sources;
7. run a local Auths agent beside each application workload; and
8. expose no provider credential or Auths bearer token to the application.

The application team then installs the root SDK and the desired generated
profile package, invokes `connect()`, and calls a typed method. In protocol
version 1 the local Auths agent is also the authoritative executor: it obtains
authority for the observed workload and alone obtains provider credentials.

Development uses an explicitly named testkit agent with disposable local state
and synthetic credentials. Development helpers are not accepted by production
configuration and emit no claim of production durability.

### 6.4 Execution ownership

In `auths.local-agent/1`, the local agent and executor are one deployment unit
and own the authoritative lifecycle store, profile services, provider calls,
and recovery state. This removes a second distributed ambiguity boundary from
the first generic-client implementation.

A future split-agent protocol requires its own versioned specification,
authority binding, forwarding wire, replay model, and crash/recovery evidence.
It cannot be introduced behind the version-1 `connect()` contract or by adding
a bearer token.

For a connected profile, the generated concrete route resolves a
`SealedConnectionBinding` and passes its non-secret identity projection to the
profile's concrete canonical-action constructor together with the decoded API
input. That constructor must require the manifest's exact provider kind,
connection contract, and descriptor schema and must place the internal
connection ID, generation, descriptor commitment, and account commitment in
the Rust-owned canonical action. A connection-free profile instead requires a
sealed `NoConnection` marker and rejects any alias. This is a concrete method
on each vertical, not a public callback registry or caller-supplied action
field.

## 7. Trust and credential boundaries

### 7.1 Application-to-agent authentication

The stable `connect()` API talks only to a local Auths agent:

- POSIX uses an HTTP/1.1 connection over a Unix-domain socket.
- Windows uses HTTP/1.1 over a local named pipe.
- TCP, arbitrary URLs, redirects, proxies, and caller-supplied authorization
  headers are not supported by the stable connection API.

The agent derives caller identity from the accepted IPC connection:

- Linux: peer PID, effective UID, and effective GID from `SO_PEERCRED`;
- macOS: effective UID and GID from `getpeereid`, plus audit-token PID where
  available;
- Windows: client SID and PID obtained by named-pipe impersonation with remote
  clients disabled.

The agent maps those observed values to an Auths principal using deployment
configuration. It resolves that principal's profile-scoped authority through a
deployment-owned authority source and builds the exact proof and trusted
context for the profile action. Missing authority is a denial; it never falls
back to agent or provider identity. A request body field that claims a
different principal is malformed. The SDK does not send a principal selector.

### 7.2 Socket discovery

`connect()` resolves the local endpoint in this exact order:

1. `AUTHS_AGENT_SOCKET`, interpreted only as a local socket or named-pipe
   address;
2. on POSIX, `$XDG_RUNTIME_DIR/auths/agent.sock` when `XDG_RUNTIME_DIR` is an
   absolute owner-controlled directory; or
3. on Windows, `\\.\pipe\auths-agent`.

If no safe address is available, `connect()` fails before I/O with a typed
`UnavailableError`. It never falls back to TCP.

An explicit/discovered address is 1-1024 UTF-8 bytes, contains no NUL or
control character, and is validated as a host-native absolute local path/pipe
name before allocation or I/O. Environment-variable expansion is performed
only by the shell before process start; the SDK does not recursively expand an
address value.

Before connecting on POSIX, the SDK rejects a symlink, a non-socket object, an
object not owned by the current user or root, or a socket writable by others.
The agent applies an owner/group DACL equivalent on Windows.

`AUTHS_AGENT_SOCKET` is non-secret configuration. No environment variable
containing an Auths or provider token is part of this contract.

### 7.2.1 Workload mapping configuration

`product/config/auths-config` adds a closed `agent.workloads` configuration.
The canonical TOML projection is:

```toml
[[agent.workloads]]
id = "payments-worker"
principal = "did:example:payments-worker"
authority_source = "payments-worker-authority"
allowed_profiles = ["auths.stripe.refund/1"]
connections = [
  { provider = "stripe", alias = "merchant-primary", default = true },
]

[agent.workloads.selector]
kind = "posix"
uid = 10001
gid = 10001
executable_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
linux_cgroup_prefix = "/payments.slice/"
```

The Windows selector is:

```toml
[agent.workloads.selector]
kind = "windows"
sid = "S-1-5-21-..."
executable_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

For POSIX, `uid` is required; `gid`, `executable_sha256`, and
`linux_cgroup_prefix` are optional additional conjunctions. For Windows, `sid`
is required and `executable_sha256` is optional. macOS rejects a configured
Linux cgroup selector. Hashes are exactly 64 lowercase hexadecimal characters.

The agent validates all selectors at startup and rejects duplicate IDs,
duplicate exact selectors, an empty allowed-profile set, an unknown authority
source, an unregistered profile, or two selectors that can match the same
observed peer. A peer must match exactly one entry. Zero matches is an
authentication denial; multiple matches are a startup configuration error.

Configuration contains 1-4096 workloads and 1-4096 authority sources. Workload
and source IDs are 1-128-byte registered tokens. Each workload lists 1-32
unique, byte-sorted profiles and 0-256 unique connection selections sorted by
`(provider, alias)`. Provider and alias use the lower-token grammar from
section 7.4. There is at most one `default=true` record per provider kind. A
selected connection must exist, be active, declare the same provider kind,
and allow both the workload ID and every profile that will use it. A default
must also appear in the same workload's connection array. The agent validates
these cross-references at startup and on atomic configuration reload.

A cgroup prefix is 1-512 UTF-8 bytes, begins and
ends with `/`, contains no `.` or `..` component, and is compared by path
component rather than raw string prefix. A Windows SID string is 1-184 ASCII
bytes and must round-trip through the platform SID parser. Configuration input
is capped by the existing product-config hard ceiling, and these smaller
collection/string bounds are checked during streaming decode.

The configuration contains principal and custody/authority-source references,
never raw private keys, provider credentials, or bearer tokens. Configuration
and selector limits are added to the existing config schema and hostile-config
tests.

Deployments that require isolation between workloads MUST assign distinct OS
identities. Executable hashes and cgroup selectors are defense in depth and
cannot be the sole identity discriminator. PID values are never treated as a
stable principal. The agent captures optional process evidence from the same
accepted peer before mapping and rejects the connection if that process exits
or the evidence cannot be bound to the accepted peer.

### 7.2.2 Initial authority source

Version 1 ships one production authority source so ambient application
identity is implementable without inventing a credential service. The
configuration is:

```toml
[agent]
authority_root = "/var/lib/auths/authorities"

[agent.authority_sources.payments-worker-authority]
kind = "sealed-file-v1"
path = "/var/lib/auths/authorities/payments-worker.cbor"
```

`authority_root` and `path` are absolute, normalized host paths of 1-1024
UTF-8 bytes. Every source path must be a strict descendant of the root. The
Windows deployment uses an administrator-selected absolute NTFS directory
under `%ProgramData%`; environment-variable expansion is not performed.

The file is a deployment secret/capability. Its semantic identity is
`auths.workload-authority-file/1` and its canonical CBOR shape is:

```cbor-diag
{
  1: 1,
  2: "<expected Auths principal>",
  3: [["<profile id>", <profile version>], ...],
  4: h'<canonical proof bytes>',
  5: h'<canonical trusted-context bytes>',
  6: <not-before unix seconds>,
  7: <expires-at unix seconds>,
  8: "<artifact id>"
}
```

The profile list has 1-32 unique, byte-sorted entries. Proof bytes are
1-262,144 bytes, trusted context is 1-2,097,152 bytes, the entire file is at
most 2,363,392 bytes, and the artifact ID is a 1-128-byte registered token.
Times are nonnegative signed-64-bit whole seconds and expiry is later than
not-before. There are no unknown keys or trailing bytes.

The POSIX loader opens every path component relative to a preopened
deployment-owned root, rejects symlinks and non-regular files, requires one
hard link, requires owner `root` or the dedicated agent UID, and rejects group
or other write/read bits. The Windows loader rejects reparse points and
requires a DACL granting read only to LocalSystem, Administrators, and the
dedicated agent service SID. The agent reads maximum-plus-one bytes, parses
canonical CBOR, copies the bounded values into locked/redacted memory where
available, and never logs or returns them.

At startup or explicit configuration reload, the agent atomically validates
all configured authority files. The workload mapping's allowed profiles must
be a subset of the file's profile list and its principal must byte-match. For
every operation, the agent checks validity time, passes the retained proof,
the exact profile-owned canonical action, and retained trusted context to the
Rust verifier, and requires the verifier's principal to equal the observed
workload principal. A file never bypasses verification and never chooses a
provider command. Reload failure leaves the previous fully validated snapshot
active and fails the reload as a whole.

The product CLI adds an offline deployment command:

```text
auths agent authority pack \
  --principal <principal> \
  --profile <profile-id>/<version> [--profile ...] \
  --proof-file <path> \
  --trusted-context-file <path> \
  --not-before <unix-seconds> \
  --expires-at <unix-seconds> \
  --artifact-id <token> \
  --output <path>
```

It accepts no proof/context bytes on the command line, performs the same
bounds and canonical validation, writes an owner-only temporary file in the
target directory, flushes it, publishes without overwriting, and flushes the
directory. Windows applies the required DACL before publication. It never
creates authority or signs a grant; proof and trusted context still come from
the existing Rust-owned authority authoring/issuance workflow. `auths agent
validate-config` validates the workload map and authority artifacts without
starting a listener or contacting a provider.

The internal authority-source port is limited to this request/result:

```rust,ignore
pub struct AuthorityRequest<'a> {
    pub observed_principal: &'a str,
    pub profile_id: &'a str,
    pub profile_version: u16,
    pub canonical_action: &'a [u8],
    pub now_unix_seconds: i64,
}

pub struct AuthorityMaterial {
    pub proof: BoundedProofBytes,
    pub trusted_context: BoundedContextBytes,
    pub artifact_commitment: [u8; 32],
}

pub trait WorkloadAuthoritySource: Send + Sync {
    fn resolve<'a>(
        &'a self,
        request: AuthorityRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<AuthorityMaterial, AuthoritySourceError>>
                    + Send
                    + 'a>>;
}
```

This is an internal mechanism port, not a language-binding extension point.
It may select already-provisioned authority material only. It cannot return an
authorization decision, profile outcome, command, credential, retry class, or
receipt claim. Any future source kind needs a versioned mechanism contract,
conformance suite, and at least two independent deployments before extraction.

### 7.3 Provider credentials

Provider credentials are acquired only after:

1. bounded profile input decoding;
2. authorized provider-connection metadata resolution, or canonical null;
3. profile input canonicalization binding that connection snapshot;
4. authority verification;
5. profile evaluation;
6. durable decision persistence;
7. atomic reservation;
8. exact command sealing;
9. fresh connection and critical-configuration reread; and
10. required/executed connection and configuration equality.

The credential broker returns an opaque handle to the profile gateway. Neither
the application process nor generated client package can read credential
bytes. Denied and pre-entry unavailable paths request zero credentials.

Credential scope is the intersection of the immutable profile contract, the
connection record, the observed workload authorization, and the provider's
current grant. No one layer may widen another. The broker returns a borrowed,
non-cloneable lease only to the concrete profile gateway for the bounded
operation deadline. It never returns a raw secret through the common local
agent protocol, status, diagnostics, logs, errors, receipts, or generated
bindings.

### 7.4 Provider connection registry

The local agent owns a durable provider-connection registry with semantic
identity `auths.provider-connection/1`. A connection is deployment data that
binds a human-selected alias to one provider account/tenant and one versioned
credential/configuration generation. It is not a profile, an Auths principal,
or a generic executor plugin.

The canonical durable record is this closed canonical-CBOR map:

```cbor-diag
{
  1: 1,                              / auths.provider-connection/1 /
  2: "<provider kind>",
  3: "<connection alias>",
  4: "<internal connection id>",
  5: "<provider connection contract>",
  6: "<descriptor schema>",
  7: h'<bounded sealed descriptor bytes>',
  8: h'<32-byte descriptor commitment>',
  9: h'<32-byte provider-account commitment>',
  10: h'<32-byte credential-reference commitment>',
  11: <positive generation>,
  12: "active" / "disabled" / "revoked",
  13: ["<allowed workload id>", ...],
  14: [["<allowed profile id>", <version>], ...],
  15: <created-at unix seconds>,
  16: <updated-at unix seconds>,
  17: null / <revoked-at unix seconds>
}
```

The record stores no raw credential and no caller-resolvable secret-store
reference. The internal connection ID is `conn_` plus unpadded base64url for
16 CSPRNG bytes. Provider kind and alias match
`[a-z][a-z0-9-]{0,63}`. Contract and descriptor-schema IDs use the manifest
semantic-ID grammar. Generation is a positive unsigned 64-bit integer and
increments for every credential, account, descriptor, or security-relevant
configuration change. Descriptor bytes are 1-65,536 bytes; each workload ID is
1-128 bytes; the workload list has 1-256 unique byte-sorted values; and the
profile list has 1-32 unique byte-sorted ID/version pairs. The complete record
is at most 262,144 bytes and has no unknown keys or trailing bytes.

Aliases are unique by `(provider kind, alias)` within one agent deployment.
The registry admits at most 10,000 live/tombstoned connections and 268,435,456
aggregate encoded record bytes. Revoked records remain tombstoned for at least
315,360,000 seconds and forever while any unresolved operation names their
connection ID/generation. Storage exhaustion refuses a new connection before
credential storage and does not evict a live, revoked, or recovery-relevant
record.

The provider-specific connection adapter parses descriptor bytes and proves
that the descriptor identifies the provider account whose commitment is in
the record. Shared code treats the descriptor as opaque bounded bytes. It may
index the common commitments but cannot interpret an account, OAuth grant,
endpoint, region, tenant, or provider permission.

For each operation, the registry returns an internal sealed
`ConnectionBinding` containing exactly:

```text
provider kind
connection alias and internal connection ID
connection contract and descriptor schema
connection generation
descriptor and provider-account commitments
allowed workload/profile decision
connection state
```

It returns no credential lease at resolution time. Rust creates this binding
from the authenticated workload and validated registry snapshot; caller bytes
cannot construct it. The profile action and operation commitment bind the
internal connection ID, generation, descriptor commitment, and account
commitment. The mutable alias alone is never a security commitment.

Immediately before credential acquisition, the agent rereads the connection
record and requires the bound ID, generation, state, descriptor commitment,
account commitment, workload authorization, profile authorization, and
profile-required credential scope to remain equal. A mismatch before provider
entry is not applied. A change after possible provider entry never changes the
original operation's effect classification or recovery identity.

Disabling a connection rejects new operations but preserves recovery.
Revocation additionally prevents new credential leases. Credential versions
needed by unresolved operations are retained until those operations become
terminal, unless an emergency administrator revokes provider access itself;
in that case recovery that cannot observe the provider remains possible and
operator-actionable rather than becoming not applied. A record cannot be
physically deleted while an operation or unexpired tombstone names it.

#### 7.4.1 Credential-store mechanism

Raw provider credentials are held behind the internal mechanism contract
`auths.connection-credential-store/1`. It has only these semantic operations:

```rust,ignore
pub trait ConnectionCredentialStore: Send + Sync {
    async fn install(
        &self,
        connection_id: &ConnectionId,
        generation: NonZeroU64,
        secret: SecretBytes,
    ) -> Result<CredentialReferenceCommitment, CredentialStoreError>;

    async fn lease_secret(
        &self,
        binding: &SealedConnectionBinding,
        deadline: Instant,
    ) -> Result<StoredSecretLease, CredentialStoreError>;

    async fn replace(
        &self,
        connection_id: &ConnectionId,
        old_generation: NonZeroU64,
        new_generation: NonZeroU64,
        secret: SecretBytes,
    ) -> Result<CredentialReferenceCommitment, CredentialStoreError>;

    async fn revoke(
        &self,
        connection_id: &ConnectionId,
        generation: NonZeroU64,
    ) -> Result<(), CredentialStoreError>;
}
```

`SecretBytes` is 1-65,536 bytes and is accepted only from the privileged
administration plane or a statically registered provider OAuth completion.
`StoredSecretLease` is visible only to the statically registered provider
adapter; it is non-serializable, redacted, non-cloneable, deadline-bound, and
zeroized on drop where the platform permits. The store understands only sealed
connection identity and generation. It MUST NOT interpret a provider scope,
refresh token, endpoint, request, or effect. Store failures before provider
entry project as connection credential unavailability. The mechanism ships
with a conformance suite covering replacement atomicity, generation
substitution, revocation, crash recovery, secret redaction, and concurrent
final capacity. It is internal Rust infrastructure and has no Python or
TypeScript adapter surface.

#### 7.4.2 Provider-specific connection adapter

A connected domain statically registers one immutable contract such as
`auths.gmail.connection/1`, `auths.stripe.connection/1`, or
`auths.vercel.connection/1`. Its Rust adapter owns:

- the exact account/tenant descriptor schema and canonical encoding;
- provider-specific onboarding and credential-refresh flow;
- account identity discovery and substitution checks;
- the closed set of credential scopes that profiles may request;
- credential expiry, rotation, disable, and provider revocation behavior; and
- sanitized diagnostics needed to operate that connection.

It does not own an effect command, effect result, retry classification,
observation, reconciliation, or receipt claim. Those stay in each profile.
The shared registry cannot invoke adapter methods by an arbitrary runtime
string; the build-time roster generates a closed provider-kind match whose
arms call concrete adapters. Dynamic connector downloads and third-party code
in the agent process are forbidden.

The internal adapter boundary is exactly this semantic interface; concrete
providers may use generated enums rather than dynamic trait objects:

```rust,ignore
pub trait ProviderConnectionAdapter: Send + Sync {
    fn provider_kind(&self) -> &'static ProviderKind;
    fn contract_id(&self) -> &'static SemanticId;
    fn descriptor_schema(&self) -> &'static SemanticId;

    fn validate_descriptor(
        &self,
        bytes: BoundedDescriptorBytes,
    ) -> Result<ValidatedConnectionDescriptor, ConnectionAdapterError>;

    fn permits_scope(
        &self,
        descriptor: &ValidatedConnectionDescriptor,
        profile_scope: &CredentialScope,
    ) -> Result<(), ConnectionAdapterError>;

    async fn lease_credential<S: ConnectionCredentialStore + Sync>(
        &self,
        binding: &SealedConnectionBinding,
        profile_scope: &CredentialScope,
        secret_store: &S,
        deadline: Instant,
    ) -> Result<ProviderCredentialLease, ConnectionAdapterError>;
}
```

`ValidatedConnectionDescriptor` and `ProviderCredentialLease` are sealed,
adapter-produced Rust values. `lease_credential` may perform the provider's
exact bounded refresh flow after obtaining a `StoredSecretLease`; it must
byte-match the account identity and scope to the sealed binding before
returning. The returned provider-ready lease is given only to the concrete
profile gateway. The method cannot accept caller parameters, a provider
command, an effect result, or a receipt builder. Onboarding and rotation remain
concrete versioned admin route handlers because their request/response DTOs are
provider-specific rather than members of this runtime port.

Each adapter must expose distinct administrative onboarding and runtime
credential operations. OAuth providers use provider-specific exact endpoints,
PKCE/state/callback validation, scopes, response limits, and account discovery
specified in that provider's connection specification. API-key providers
accept secret bytes through the administration channel, never process argv or
an environment variable. Database/cloud configuration follows its own exact
adapter contract. The generic specification deliberately does not invent a
universal OAuth or credential schema.

#### 7.4.3 Privileged connection administration

Connection onboarding is not available on the application session. The agent
exposes a separate administration listener:

- POSIX: `/run/auths/admin.sock`, or the deployment-configured absolute local
  socket under an owner-controlled directory; and
- Windows: `\\.\pipe\auths-agent-admin` with remote clients disabled.

The listener uses HTTP/1.1 and canonical CBOR but has semantic identity
`auths.provider-connection-admin/1`. POSIX requires the dedicated agent UID or
root and an owner/group policy configured for the administrator group. Windows
requires LocalSystem, Administrators, or an explicitly configured operator
SID. Workload application identities are denied before request decoding. The
application `Client` and generated packages expose no administration method.

The shared bounded routes are:

```text
GET  /v1/admin/connections
GET  /v1/admin/connections/<provider>/<alias>
POST /v1/admin/connections/<provider>/<alias>/disable
POST /v1/admin/connections/<provider>/<alias>/enable
POST /v1/admin/connections/<provider>/<alias>/rotate
POST /v1/admin/connections/<provider>/<alias>/revoke
```

Each statically registered provider adds exact onboarding routes under:

```text
POST /v1/admin/providers/<provider>/connections/start
POST /v1/admin/providers/<provider>/connections/complete
```

`start` and `complete` payloads are provider-specific, versioned, bounded CBOR
defined by that connection contract; they are not an arbitrary map. A
non-interactive secret is read by `auths connections add` from a protected file
descriptor or standard input with terminal echo disabled, never from argv.
OAuth completion receives only the provider-specific bounded authorization
response. The adapter verifies state, PKCE, exact callback, issuer, audience,
account identity, and granted scopes before registry publication.

The product CLI presents these operations:

```text
auths connections add <provider> --alias <alias> \
  --allow-workload <id> [--allow-workload <id> ...] \
  --allow-profile <profile-id>/<version> [--allow-profile ...]
auths connections list
auths connections inspect <provider>/<alias>
auths connections disable <provider>/<alias>
auths connections enable <provider>/<alias>
auths connections rotate <provider>/<alias>
auths connections revoke <provider>/<alias>
```

The repeated allow flags obey the record bounds and are required on `add`.
Changing either allowlist is an audited generation-incrementing administrative
update using the same optimistic-generation precondition as rotation. A
workload must still name the record in `agent.workloads.connections`; neither
side alone grants use.

List and inspect return only alias, internal ID, provider kind, contract,
generation, sanitized account label, commitments, state, allowed
workloads/profiles, and timestamps. They never return credential bytes,
credential references, OAuth codes, refresh tokens, provider responses, or a
reusable provider URL. All mutations use optimistic generation equality and
an append-only administrative audit record. Connection aliases and account
labels are non-secret but are still sanitized and never substituted into a
provider request by shared code.

### 7.5 Trust classification

The application process, generated client package, caller input, provider
response, transport response, and persisted bytes before authenticated decode
are untrusted. The generated client improves ergonomics but is never an
authorization authority.

The Rust verifier, concrete qualified profile semantics, validated deployment
configuration, lifecycle store transaction boundary, custody implementation,
and receipt trust configuration are trusted according to their existing
contracts. A compromised local agent can act with the workload authority it
holds and is therefore part of the trusted computing base; deployment
isolation and least-authority mapping must treat it accordingly.

## 8. Root SDK API

### 8.1 Python

The target root declarations are:

```python
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from os import PathLike
from typing import Literal, Optional, Union

OperationState = Literal[
    "preparing",
    "denied",
    "unavailable",
    "ready",
    "executing",
    "recovery-required",
    "completed",
    "partial",
    "not-applied",
]

@dataclass(frozen=True)
class ClientOptions:
    agent_socket: Optional[Union[str, PathLike[str]]] = None
    connect_timeout: timedelta = timedelta(seconds=5)

@dataclass(frozen=True)
class OperationOptions:
    idempotency_key: Optional[str] = None
    timeout: timedelta = timedelta(seconds=30)
    recovery_wait: timedelta = timedelta(seconds=5)

@dataclass(frozen=True)
class RecoveryOptions:
    timeout: timedelta = timedelta(seconds=30)
    recovery_wait: timedelta = timedelta(seconds=5)

@dataclass(frozen=True)
class OperationMetadata:
    operation_id: str
    profile: str
    connection: Optional[str]
    completion: Literal["fresh", "replayed", "reconciled"]
    receipt_ids: tuple[str, ...]

@dataclass(frozen=True)
class OperationStatus:
    operation_id: str
    profile: str
    connection: Optional[str]
    state: OperationState
    effect: Literal["not-applied", "possible", "applied"]
    terminal: bool
    receipt_ids: tuple[str, ...]
    recovery: Optional["RecoveryHandle"]

class RecoveryHandle:
    def to_bytes(self) -> bytes: ...
    @classmethod
    def from_bytes(cls, value: bytes, /) -> "RecoveryHandle": ...

class PortableReceipt:
    @property
    def id(self) -> str: ...
    def to_bytes(self) -> bytes: ...

class ClientStateError(RuntimeError): ...

class Client:
    async def __aenter__(self) -> "Client": ...
    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None: ...
    async def aclose(self) -> None: ...
    @property
    def operations(self) -> "Operations": ...

class Operations:
    async def recover(
        self,
        recovery: "RecoveryHandle",
        /,
        *,
        options: Optional[RecoveryOptions] = None,
    ) -> OperationStatus: ...
    async def pending(self) -> tuple[OperationStatus, ...]: ...
    async def receipts(self, operation_id: str, /) -> tuple[PortableReceipt, ...]: ...

def connect(*, options: Optional[ClientOptions] = None) -> Client: ...
```

`connect()` is inert. The first `__aenter__` opens and negotiates exactly one
session. Re-entry raises `ClientStateError`. Failed or cancelled entry closes
partial resources and permanently transitions the object to closed. `aclose()`
is idempotent from new, open, closing, and closed states. Operations on new,
closing, or closed clients fail locally before I/O with
`ClientStateError("auths client is not open")`.

Durations must be positive whole milliseconds. Python rejects sub-millisecond,
negative, zero, or overflowing `timedelta` values before I/O.
`connect_timeout` is 1-30,000 milliseconds. Operation `timeout` is 1-300,000
milliseconds. When options are omitted, the generated client uses the lesser
of 30,000 milliseconds and the selected profile's execution limit; an explicit
value above that profile limit is rejected.
`recovery_wait` is 1 millisecond through the operation timeout and cannot
exceed it. `RecoveryOptions` uses the same timeout and recovery-wait rules and
has no idempotency field because recovery cannot create or rename an operation.

### 8.2 TypeScript

The target root declarations are:

```ts
export interface ClientOptions {
  readonly agentSocket?: string;
  readonly connectTimeoutMs?: number;
}

export interface OperationOptions {
  readonly idempotencyKey?: string;
  readonly timeoutMs?: number;
  readonly recoveryWaitMs?: number;
  readonly signal?: AbortSignal;
}

export interface RecoveryOptions {
  readonly timeoutMs?: number;
  readonly recoveryWaitMs?: number;
  readonly signal?: AbortSignal;
}

export interface OperationMetadata {
  readonly operationId: string;
  readonly profile: string;
  readonly connection: string | null;
  readonly completion: "fresh" | "replayed" | "reconciled";
  readonly receiptIds: readonly string[];
}

export type OperationState =
  | "preparing"
  | "denied"
  | "unavailable"
  | "ready"
  | "executing"
  | "recovery-required"
  | "completed"
  | "partial"
  | "not-applied";

export interface OperationStatus {
  readonly operationId: string;
  readonly profile: string;
  readonly connection: string | null;
  readonly state: OperationState;
  readonly effect: "not-applied" | "possible" | "applied";
  readonly terminal: boolean;
  readonly receiptIds: readonly string[];
  readonly recovery?: RecoveryHandle;
}

export interface RecoveryHandle {
  toBytes(): Uint8Array;
}

export interface PortableReceipt {
  readonly id: string;
  toBytes(): Uint8Array;
}

export function recoveryHandleFromBytes(value: Uint8Array): RecoveryHandle;

export class ClientStateError extends Error {}

export interface Client extends AsyncDisposable {
  readonly operations: Operations;
  close(): Promise<void>;
}

export interface Operations {
  recover(recovery: RecoveryHandle, options?: RecoveryOptions): Promise<OperationStatus>;
  pending(options?: { readonly signal?: AbortSignal }): Promise<readonly OperationStatus[]>;
  receipts(
    operationId: string,
    options?: { readonly signal?: AbortSignal },
  ): Promise<readonly PortableReceipt[]>;
}

export function connect(options?: ClientOptions): Promise<Client>;
```

`connect()` returns an already-open client. `close()` is idempotent. Calls after
close reject locally before I/O with `ClientStateError`. The package
requires TypeScript 5.2 or newer, `ESNext.Disposable`, and a Node runtime with
`Symbol.asyncDispose`. The minimum is Node 20.6.0, matching the package engine;
packed-package CI must execute the exact minimum plus every maintained Node
line in the repository support matrix on Linux, macOS, and Windows.

All TypeScript durations are finite safe integers in the same millisecond
ranges as Python. Fractional, `NaN`, infinite, negative, zero, and overflowing
values fail before I/O.

### 8.3 Public root discipline

The root packages expose only session, operation metadata, common errors,
recovery handles, agent-verified portable receipts, and the repository's
separately owned local verification entrypoints.
Profile DTOs and clients live in profile distributions. Adapter, codegen, and
profile-runtime extension APIs use explicit subpackages and never leak through
the root export graph.

### 8.4 Platform boundary

Effectful generated profile clients are server-runtime packages:

- Python supports the repository's declared CPython 3.9-3.14 wheel matrix;
- TypeScript supports compiled JavaScript on Node 20.6 or newer within the
  maintained Node matrix; and
- browser and worker bundles may use local verification but cannot construct
  an effectful `Client` in this protocol version.

TypeScript profile distributions declare Node engines, have no browser export
condition, and are rejected by the clean browser-bundler negative test. The
root SDK remains browser-capable for verification-only entry points. No
browser package accepts an executor credential as a workaround.

## 9. Generated profile-client API

### 9.1 Distribution names

For domain `<domain>`:

- TypeScript package: `@auths-dev/profile-<domain>`;
- Python distribution: `auths-profile-<domain>`;
- Python import: `auths_profiles.<domain>`; and
- Rust implementation: `product/integrations/auths-<domain>`.

One domain distribution may contain multiple profiles from the same domain.
It MUST NOT contain profiles from unrelated domains.

### 9.2 Client construction

Every generated domain package exports one domain client whose constructor
accepts an open or unentered root session but performs no I/O. If the domain
declares a provider connection, the constructor also accepts exactly one
optional connection alias:

```python
stripe = Stripe(session, connection="merchant-primary")
```

```ts
const stripe = new Stripe(session, { connection: "merchant-primary" });
```

Omitting the option asks the agent for the observed workload's one configured
default for the manifest provider kind. It does not choose the first record.
If the domain manifest has `connection: null`, the generator emits only the
one-argument constructor and passing a connection is a static and runtime
error. A domain client never lists connections, changes connection after
construction, or accepts a per-method connection override.

The first profile call verifies that the session advertised the exact profile
ID, profile version, runtime-contract digest, operation-protocol version, and
profile error-registry projection digest. Mismatch fails before preparing an
operation.

### 9.3 Generated method shape

Each profile maps to exactly one generated method. The manifest chooses a
resource group and method token, producing Stripe-like grouping:

```python
await stripe.refunds.create(...)
await opentofu.saved_plans.apply(...)
await postgres.bounded_updates.execute(...)
```

For the manifest in section 10.2, the generated public signatures are exactly
equivalent to:

```python
class Refunds:
    async def create(
        self,
        *,
        payment_intent: str,
        amount: int,
        currency: Currency,
        options: Optional[OperationOptions] = None,
    ) -> Refund: ...

    async def create_outcome(
        self,
        *,
        payment_intent: str,
        amount: int,
        currency: Currency,
        options: Optional[OperationOptions] = None,
    ) -> RefundOutcome: ...

    async def recover(
        self,
        recovery: auths.RecoveryHandle,
        /,
        *,
        options: Optional[RecoveryOptions] = None,
    ) -> Refund: ...

    async def recover_outcome(
        self,
        recovery: auths.RecoveryHandle,
        /,
        *,
        options: Optional[RecoveryOptions] = None,
    ) -> RefundOutcome: ...

class Stripe:
    def __init__(
        self,
        session: auths.Client,
        /,
        *,
        connection: Optional[str] = None,
    ) -> None: ...
    @property
    def refunds(self) -> Refunds: ...
```

```ts
export interface RefundCreateParams {
  readonly paymentIntent: string;
  readonly amount: number;
  readonly currency: Currency;
}

export interface Refunds {
  create(input: RefundCreateParams, options?: OperationOptions): Promise<Refund>;
  createOutcome(
    input: RefundCreateParams,
    options?: OperationOptions,
  ): Promise<RefundOutcome>;
  recover(recovery: RecoveryHandle, options?: RecoveryOptions): Promise<Refund>;
  recoverOutcome(
    recovery: RecoveryHandle,
    options?: RecoveryOptions,
  ): Promise<RefundOutcome>;
}

export class Stripe {
  constructor(session: Client, options?: Readonly<{ connection?: string }>);
  readonly refunds: Refunds;
}
```

`Currency`, `Refund`, `RefundOutcome`, and every outcome branch are generated
from the restricted schema and common outcome grammar. Constructors retain the
root session by borrowing it; closing a domain client is unnecessary and it
never closes the root session. Constructor aliases are checked for the shared
1-64-byte lower-token grammar without I/O. The first call sends that exact
alias or null; the agent performs authorization and default resolution.

The generated recovery methods call only the fixed recover route. They do not
accept input fields or reconstruct an operation. The agent verifies that the
sealed handle names the generated package's exact profile/version and current
principal before the concrete vertical runs reconciliation. The facade and
explicit-outcome recovery methods have the same projection relationship as
their create counterparts. Root `Operations.recover()` remains available for
domain-neutral operations tooling but returns only `OperationStatus`; the
generated method is how application code regains a typed domain result.

Generated outcome branches have these exact immutable fields:

| Branch | Required fields |
| --- | --- |
| `Completed<T>` | `kind=completed`, `value: T` (including synthesized `auths`) |
| `Denied` | `kind=denied`, operation ID, issue, receipt IDs |
| `Unavailable` | `kind=unavailable`, nullable operation ID, issue, receipt IDs |
| `Conflict` | `kind=conflict`, original operation ID, issue, recovery, receipt IDs |
| `NotApplied` | `kind=not-applied`, operation ID, issue, receipt IDs, completion |
| `Partial<P>` | `kind=partial`, operation ID, issue, `details: P`, receipt IDs, completion |
| `RecoveryRequired<G>` | `kind=recovery-required`, operation ID, issue, recovery, receipt IDs, nullable `progress: G` |
| `ReceiptIntegrityFailed` | `kind=receipt-integrity-failed`, operation ID, registered integrity issue, exact durable state, exact effect, terminal bit, empty receipt IDs |

Python generates distinct frozen, SDK-sealed dataclasses so `isinstance`
narrows every branch. TypeScript generates a readonly discriminated union.
Impossible optional-field combinations are not constructible through public
constructors. `create()` returns `Completed.value` and maps the other seven
branches one-for-one to the corresponding root/generated error class.

Top-level input records become keyword-only parameters in Python and one
readonly object argument in TypeScript. Nested records use generated immutable
DTOs. Every method has one final optional `options` argument using the root
`OperationOptions` type.

Generated methods MUST NOT accept arbitrary dictionaries, provider URLs,
HTTP methods, headers, credentials, profile IDs, authority objects, or
principal identifiers.

A non-null `partialType` generates `<Method>PartialError`. A non-null
`progressType` generates `<Method>RecoveryRequired`, derived from the root
recovery error with a strongly typed immutable `progress` field. The generated
method translates only the matching profile/version outcome into those types.

### 9.4 Input ownership

Path-like and stream-like convenience inputs are profile-client concerns only
when the profile manifest declares a bounded byte field with
`sourceConvenience: "file"`. The generated client then reads at most the
field's maximum plus one byte and rejects oversize input before allocating or
dispatching the full body.

The generator never adds an unbounded `read_bytes`, `readFile`, JSON parse, or
base64 decode helper.

### 9.5 Package compatibility

Generated TypeScript packages declare `@auths-dev/sdk` as a peer dependency
with the same supported major and embed `auths.profile-client-runtime/1`.
Generated Python distributions depend on `auths` with the same supported major
and embed the same runtime identity.

The installed-package tests use the packed root SDK and packed profile package
in a clean consumer. Workspace path resolution cannot satisfy this gate.

The Python `auths_profiles` package is an implicit PEP 420 namespace: profile
distributions do not ship a shared `auths_profiles/__init__.py`. Two domain
distributions must install together without overwriting files. TypeScript
domains remain separate package names.

## 10. Profile package manifest

### 10.1 Location and schema

Each domain package contains:

```text
product/integrations/auths-<domain>/profile-package.json
product/integrations/auths-<domain>/api/profile-api.json
```

`profile-package.json` validates against the new canonical schema:

```text
product/spec/v1/profile-package.schema.json
```

Its semantic identity is `auths.profile-package/1`. Generation produces two
digests:

- `packageManifestDigest` hashes canonical compact JSON for the complete
  manifest, including connection, source, and evidence paths, and is used by repository
  inventory checks; and
- `runtimeContractDigest` hashes the runtime contract projection defined below
  and is embedded in the Rust router and generated language packages.

The session handshake compares only `runtimeContractDigest`. Moving a test or
documentation file therefore cannot break a deployed client. The runtime
projection contains the manifest schema identity, profile ID, version,
semantic subject, effect ID, referenced API type schemas, semantic contract
identities, limits, error owner/version, and the canonical profile error
projection digest defined in section 17.1. For a connected domain it also
contains the provider kind, immutable connection contract, and descriptor
schema. It excludes package names, the manifest-owned public client class,
client group/method spelling, source paths, and evidence paths. Both digests use
SHA-256 over canonical compact JSON with recursively sorted keys and no
insignificant whitespace.

The runtime projection semantic identity is
`auths.profile-runtime-contract/1`. For each profile entry it is exactly this
closed JSON object before canonicalization:

```json
{
  "schema": "auths.profile-runtime-contract/1",
  "profile": {
    "id": "auths.stripe.refund",
    "version": 1,
    "semanticSubject": "auths.stripe.refund/1",
    "effectId": "stripe.refund.create"
  },
  "connection": {
    "providerKind": "stripe",
    "contract": "auths.stripe.connection/1",
    "descriptorSchema": "auths.stripe.connection-descriptor/1"
  },
  "operationProtocol": "auths.profile-operation/1",
  "api": {
    "schema": "auths.profile-api/1",
    "inputType": "RefundInput",
    "successType": "Refund",
    "partialType": null,
    "progressType": null,
    "reachableTypes": {}
  },
  "contracts": {
    "canonicalAction": "auths.stripe.refund-action/1",
    "evaluator": "auths.stripe.refund-evaluator/1",
    "lifecycle": "auths.stripe.refund-lifecycle/1",
    "provider": "auths.stripe.refund-provider/1",
    "receipt": "auths.stripe.refund-receipt/1",
    "credentialScope": "stripe.refunds.write/1",
    "errorOwner": "stripe-refund",
    "errorOwnerVersion": 1,
    "errorProjectionDigest": "<64 lowercase hex characters>"
  },
  "limits": {}
}
```

`reachableTypes` is the exact key-sorted subset of `profile-api.json.types`
reachable from the four role types, with their full schema nodes unchanged;
the empty object above is schematic and invalid for this refund profile.
`limits` is the profile's complete limits object unchanged. The projection
rejects unknown keys. The digest string is lowercase hexadecimal SHA-256 of
the canonical profile error projection. The runtime `connection` value is the
three-field object shown or null, matching `domain.connection`. No digest
field hashes itself.

### 10.2 Exact manifest shape

```json
{
  "schema": "auths.profile-package/1",
  "domain": {
    "id": "stripe",
    "clientClass": "Stripe",
    "rustPackage": "auths-stripe",
    "typescriptPackage": "@auths-dev/profile-stripe",
    "pythonDistribution": "auths-profile-stripe",
    "pythonModule": "auths_profiles.stripe",
    "connection": {
      "providerKind": "stripe",
      "contract": "auths.stripe.connection/1",
      "descriptorSchema": "auths.stripe.connection-descriptor/1",
      "sources": {
        "specification": "docs/specs/0041-stripe-connection.md",
        "descriptor": "src/connection/descriptor.rs",
        "onboarding": "src/connection/onboarding.rs",
        "credentials": "src/connection/credentials.rs",
        "adminRoutes": "src/connection/admin_routes.rs"
      },
      "evidence": {
        "fixtures": "fixtures/connection/v1",
        "conformance": "tests/connection_conformance.rs"
      }
    }
  },
  "api": "api/profile-api.json",
  "profiles": [
    {
      "id": "auths.stripe.refund",
      "version": 1,
      "semanticSubject": "auths.stripe.refund/1",
      "effectId": "stripe.refund.create",
      "client": {
        "group": "refunds",
        "method": "create",
        "inputType": "RefundInput",
        "successType": "Refund",
        "partialType": null,
        "progressType": null
      },
      "contracts": {
        "canonicalAction": "auths.stripe.refund-action/1",
        "evaluator": "auths.stripe.refund-evaluator/1",
        "lifecycle": "auths.stripe.refund-lifecycle/1",
        "provider": "auths.stripe.refund-provider/1",
        "receipt": "auths.stripe.refund-receipt/1",
        "credentialScope": "stripe.refunds.write/1",
        "errorOwner": "stripe-refund",
        "errorOwnerVersion": 1
      },
      "limits": {
        "requestBytes": 262144,
        "responseBytes": 262144,
        "receiptCount": 4,
        "receiptBytes": 65536,
        "executionMilliseconds": 30000,
        "admissionsPerMinute": 600,
        "activePerPrincipal": 64,
        "unresolvedPerPrincipal": 16,
        "durableBytesPerPrincipal": 67108864,
        "tombstonesPerPrincipal": 100000,
        "terminalRetentionSeconds": 2592000,
        "idempotencyRetentionSeconds": 2592000
      },
      "sources": {
        "specification": "docs/specs/0012-stripe-bounded-refunds.md",
        "action": "src/refund/action.rs",
        "evaluator": "src/refund/evaluator.rs",
        "command": "src/refund/command.rs",
        "lifecycle": "src/refund/lifecycle.rs",
        "gateway": "src/refund/gateway.rs",
        "reconciliation": "src/refund/reconciliation.rs",
        "receipt": "src/refund/receipt.rs",
        "errors": "errors/refund-v1.json",
        "errorMapping": "src/refund/errors.rs"
      },
      "evidence": {
        "fixtures": "fixtures/refund/v1",
        "mutationCorpus": "tests/refund_mutations.rs",
        "providerRequests": "fixtures/refund/provider-requests",
        "demo": "demos/stripe-refund",
        "liveContract": "demos/stripe-refund/tests/live-contract.mjs"
      }
    }
  ]
}
```

`partialType` is `null` when the effect cannot have a truthful profile-defined
terminal partial result. `progressType` is `null` when a possible-effect
recovery state can never expose already-proven applied progress.

`domain.connection` is either the exact object above or `null`. Every profile
in one domain distribution shares that one provider-connection contract. When
it is non-null, each profile's `credentialScope` is a non-null immutable
semantic ID recognized by that adapter. When it is null,
`credentialScope` must also be null, the generated domain constructor has no
connection option, prepare key 6 is null, and the lifecycle requests no
provider credential. Changing the provider kind, contract, descriptor schema,
or scope changes the affected runtime-contract digest. Source/evidence path
changes affect only the package-manifest digest.

### 10.3 Manifest grammar and limits

| Field | Rule |
| --- | --- |
| Domain, group, method, and effect tokens | `[a-z][a-z0-9-]{0,63}` |
| Public client class | `[A-Z][A-Za-z0-9]{0,63}`; generated unchanged in both languages |
| Provider kind and connection alias | `[a-z][a-z0-9-]{0,63}` |
| Rust package | `auths-[a-z][a-z0-9-]{0,63}` |
| Profile ID | `auths.<domain>.<effect>`, 1-128 ASCII bytes |
| Semantic and contract IDs | `[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}` |
| Error owner | `[a-z][a-z0-9-]{0,63}` and a version in 1-65535 |
| Version | integer 1-65535 |
| Profiles per domain | 1-32 |
| Provider connection per domain | exactly one object or null |
| Source path | repository-relative UTF-8, 1-256 bytes, no `..`, absolute path, or symlink escape |
| Request bytes | 1-25,165,824 |
| Response bytes | 1-16,777,216 |
| Receipts per operation | 1-16 |
| Aggregate receipt bytes | 1-8,388,608 and within the response ceiling |
| Execution duration | 1-300,000 whole milliseconds |
| New-operation admissions per principal/minute | 1-10,000, fixed-window UTC minute |
| Active operations per principal | 1-1024 |
| Unresolved operations per principal | 1-256 and not greater than active limit |
| Durable bytes per principal/profile | 1,048,576-1,073,741,824 |
| Tombstones per principal/profile | 1,024-1,000,000 |
| Terminal retention | 604,800-31,536,000 seconds |
| Idempotency retention | 604,800-315,360,000 seconds and not less than terminal retention or maximum authority validity |

All object schemas reject unknown fields. IDs and paths are byte-exact and are
never Unicode-normalized. Fields whose grammar is ASCII reject non-ASCII before
case conversion.

### 10.4 What the manifest cannot declare

The manifest cannot contain:

- a policy expression;
- provider URL, verb, headers, or arbitrary parameters;
- credential material or secret reference value;
- OAuth endpoints, client secrets, account IDs, connection aliases, or
  deployment connection records;
- a retry decision;
- a mapping from provider errors to effect states;
- a receipt claim template;
- executable code or callback name selected at runtime; or
- an assertion that a profile is qualified without evidence inventory.

Those remain concrete Rust semantics and reviewed evidence.

## 11. Restricted profile API schema

### 11.1 Purpose

`api/profile-api.json` describes only caller-visible input, success, terminal
partial, and nonterminal recovery-progress DTOs. It is not the canonical
authorization action and does not define provider semantics. The profile's
Rust canonicalizer converts the bounded API input into its exact canonical
action and independently revalidates all security-relevant meaning.

The schema identity is `auths.profile-api/1`.

### 11.2 Allowed type grammar

The schema supports these closed forms:

| Form | Required parameters | Wire representation |
| --- | --- | --- |
| `boolean` | none | CBOR boolean |
| `uint` | `bits`, `minimum`, `maximum` | canonical nonnegative CBOR integer |
| `int` | `bits`, `minimum`, `maximum` | canonical CBOR integer |
| `string` | `minimumBytes`, `maximumBytes`, required `alphabet` | UTF-8 CBOR text |
| `bytes` | `minimumBytes`, `maximumBytes`, nullable `sourceConvenience` | CBOR byte string |
| `enum` | 1-64 unique token values | CBOR text |
| `record` | 1-64 named fields | closed CBOR map with lower-camel text keys |
| `option` | one inner type | field always present; CBOR null or inner value |
| `list` | inner type, `minimumItems`, `maximumItems` | bounded CBOR array |
| `union` | discriminator `kind`, 2-16 closed record variants | closed CBOR map |
| `ref` | named nonrecursive type | referenced representation |

The JSON abstract syntax is exact:

```text
Boolean = {"kind":"boolean"}
UInt    = {"kind":"uint","bits":8|16|32|64,"minimum":"decimal","maximum":"decimal"}
Int     = {"kind":"int","bits":8|16|32|64,"minimum":"decimal","maximum":"decimal"}
String  = {"kind":"string","minimumBytes":N,"maximumBytes":N,
           "alphabet":"utf8"|"ascii-graphic"|"registered-token"|
                      "lower-token"|"lower-hex"|"base64url"}
Bytes   = {"kind":"bytes","minimumBytes":N,"maximumBytes":N,
           "sourceConvenience":null|"file"}
Enum    = {"kind":"enum","values":["token", ...]}
Option  = {"kind":"option","value":Type}
List    = {"kind":"list","value":Type,"minimumItems":N,"maximumItems":N}
Ref     = {"kind":"ref","name":"TypeName"}
Record  = {"kind":"record","fields":[
             {"name":"lowerCamel","value":Type,"sensitive":true|false}, ...
           ]}
Union   = {"kind":"union","discriminator":"kind","variants":[
             {"tag":"token","fields":[Field, ...]}, ...
           ]}
```

The file shape is:

```json
{
  "schema": "auths.profile-api/1",
  "types": {
    "Currency": {
      "kind": "enum",
      "values": ["eur", "gbp", "usd"]
    },
    "RefundInput": {
      "kind": "record",
      "fields": [
        {
          "name": "paymentIntent",
          "value": {
            "kind": "string",
            "minimumBytes": 1,
            "maximumBytes": 128,
            "alphabet": "registered-token"
          },
          "sensitive": false
        },
        {
          "name": "amount",
          "value": {
            "kind": "uint",
            "bits": 64,
            "minimum": "1",
            "maximum": "100000000"
          },
          "sensitive": false
        },
        {
          "name": "currency",
          "value": {"kind": "ref", "name": "Currency"},
          "sensitive": false
        }
      ]
    },
    "Refund": {
      "kind": "record",
      "fields": [
        {
          "name": "id",
          "value": {
            "kind": "string",
            "minimumBytes": 1,
            "maximumBytes": 128,
            "alphabet": "registered-token"
          },
          "sensitive": false
        },
        {
          "name": "status",
          "value": {
            "kind": "enum",
            "values": ["pending", "succeeded"]
          },
          "sensitive": false
        }
      ]
    }
  }
}
```

`utf8` accepts valid Unicode scalar values other than NUL and C0/C1 control
characters and performs no normalization. `ascii-graphic` accepts bytes
`0x21..0x7e`. The remaining alphabets are, respectively:

```text
registered-token  [A-Za-z0-9][A-Za-z0-9._:-]*
lower-token       [a-z][a-z0-9-]*
lower-hex         [0-9a-f]+
base64url         [A-Za-z0-9_-]+
```

The byte limits still apply and empty values are permitted only when
`minimumBytes` is zero. The generator emits direct character checks; it does
not evaluate caller-provided regular expressions.

Integer bounds are canonical base-10 strings: `0` or a nonzero digit followed
by digits, with one optional leading `-` for `int`. Leading plus signs and
leading zeroes are rejected. This avoids JSON-number precision differences.

`uint` and `int` support 8, 16, 32, and 64 bits. TypeScript uses `bigint` for
any integer whose permitted range exceeds JavaScript's safe-integer range.
Python uses `int` with generated runtime range checks.

The grammar forbids floating point, decimal fractions, unbounded strings,
unbounded bytes, unbounded lists, maps with caller-selected keys, `any`,
recursive types, aliases with different wire meaning, custom serializers,
custom constructors, getters, descriptors, and default values.

Currency and amounts therefore use an enum or bounded token plus integer minor
units; they never use a floating-point amount.

### 11.3 Schema limits

- schema JSON: at most 262,144 bytes;
- named types: at most 128;
- total fields: at most 1024;
- nesting depth after reference expansion: at most 8;
- list maximum: at most 4096 items;
- string maximum: at most 65,536 bytes;
- byte-string maximum: at most 16,777,216 bytes;
- union variants: at most 16; and
- no reference cycle.

Type names match `[A-Z][A-Za-z0-9]{0,63}`. Enum values and union tags match
the `lower-token` alphabet, are unique byte-for-byte, and are emitted in source
order for documentation while canonical CBOR remains order-independent.

The generator computes worst-case encoded sizes using checked arithmetic and
rejects a type whose maximum cannot fit its profile request or response limit.
For every request, checked `profile_input + operation_envelope_overhead` must
fit `requestBytes` and the absolute frame limit. For every response variant,
checked
`profile_body + receiptBytes + error_envelope_if_present + canonical_overhead`
must be less than or equal to `responseBytes`; a default client can therefore
receive every valid response admitted by the profile.

### 11.4 Binding naming

Canonical field names are lower camel case and match
`[a-z][A-Za-z0-9]{0,63}`. TypeScript preserves them. Python deterministically
converts them to snake case. The generator rejects collisions such as
`itemID` and `itemId` that would map to the same Python name.

Python generated DTOs are frozen, keyword-only dataclasses with inert
construction. TypeScript generated DTOs are readonly interfaces accepted only
through generated validation functions. Both bindings copy mutable byte and
collection inputs before retaining them.

## 12. Profile extension ABI

Generated profile packages use a narrow extension ABI that is public only from
these explicit subpaths:

- TypeScript: `@auths-dev/sdk/profile-runtime`;
- Python: `auths.profile_runtime`.

The extension ABI provides:

- an immutable `ProfileDescriptor` containing exact route and manifest
  digests;
- bounded request encoding and response decoding;
- bounded connection-alias validation and the descriptor's immutable
  connection-contract projection;
- `prepare`, `execute`, `status`, and `recover` transport operations;
- common outcome-to-error projection;
- receipt and operation metadata projection; and
- profile capability negotiation.

It does not provide arbitrary HTTP, a caller-selected route, a credential
field, authority construction, command construction, or provider execution.

The route descriptor constructor is generated as package-private code. At
runtime, the root SDK validates every descriptor against the agent's signed
capability list. Forging a client descriptor cannot create authority; an
unregistered path is rejected before profile input is parsed.

The extension ABI has semantic identity `auths.profile-client-runtime/1` and a
separate generated conformance suite. Changes require a version bump rather
than duck-typing compatibility.

### 12.1 Versioning rules

These identities evolve independently:

| Identity | Governs | Incompatible change |
| --- | --- | --- |
| `auths.profile-package/1` | manifest and evidence inventory shape | bump manifest schema |
| `auths.profile-runtime-contract/1` | one profile's negotiated runtime projection | bump projection schema |
| `auths.profile-api/1` | restricted DTO schema grammar | bump API-schema version |
| `auths.error-registry-fragment/1` | profile-owned registry source shape | bump fragment schema |
| `auths.error-projection/1` | negotiated registry subset shape/digest | bump projection schema |
| `auths.profile-client-runtime/1` | generated-package/root-SDK extension ABI | bump runtime ABI |
| `auths.local-agent/1` | session and local IPC contract | bump agent protocol |
| `auths.provider-connection/1` | shared durable connection record and generation semantics | bump connection-record schema |
| `auths.provider-connection-admin/1` | privileged connection administration framing | bump admin protocol |
| `auths.connection-credential-store/1` | secret storage/lease generation mechanics | bump mechanism contract |
| `auths.profile-operation/1` | prepare/execute/status/recover envelopes | bump operation protocol |
| `auths.recovery-handle/1` | sealed recovery locator bytes | bump handle schema |
| `auths.portable-receipt/1` | linked portable receipt container | bump container schema |
| profile ID/version | exact action, policy, lifecycle, and receipt meaning | create a new profile version |

Changing any API input/output field, field bound, canonical action mapping,
evaluator behavior, effect classification, credential scope, lifecycle rule,
provider command, domain error definition/mapping, reconciliation rule, or
receipt claim requires a new profile version. Changing only client
resource-group/method spelling or repository
source/evidence paths changes the package version and package-manifest digest,
but not the runtime-contract digest or profile version.

Changing a provider connection contract, descriptor meaning, account-binding
rule, scope interpretation, or refresh/revocation semantics requires a new
provider connection-contract version. Every profile that adopts it receives a
new profile version and runtime-contract digest. Because one domain manifest
has one connection contract, a domain upgrade versions every connected
profile it continues to publish. The executor retains the old concrete adapter
in recovery-only registration while any unresolved record or unexpired handle
names it; it admits no new operation through that retired contract. Adding or
rotating a deployment account under unchanged
connection/profile contracts changes only connection generation data and does
not create a package or profile version.

Profile versions and protocol identities are immutable after qualification.
Prelaunch replacement is a direct source cutover: remove the superseded route,
generated package, state, fixtures, and public exports in the same atomic
change. Do not implement dual routes, legacy decoders, or runtime shims.

## 13. Local agent protocol

### 13.1 Transport

The protocol is HTTP/1.1 over the authenticated local IPC channel. Requests
and responses use canonical CBOR and this exact media type:

```text
application/auths+cbor;version=1
```

The agent rejects:

- any TCP connection on the stable listener;
- `Authorization`, `Proxy-Authorization`, or `Cookie` headers;
- transfer encodings other than a known `Content-Length`;
- content negotiation to another media type;
- redirects;
- duplicate security-sensitive headers;
- a frame or header over its limit; and
- trailing bytes after one canonical CBOR value.

Header bytes are limited to 16,384. The absolute request-frame ceiling is
33,554,432 bytes. A profile's smaller declared request limit is enforced before
decoding profile input. The absolute response ceiling is 16,777,216 bytes and
the error-envelope ceiling is 65,536 bytes.

The complete common admission table is:

| Resource | Hard limit |
| --- | --- |
| Request headers | 64 fields and 16,384 aggregate bytes |
| One header name/value | 128/8,192 bytes |
| Request/response frame | 33,554,432 / 16,777,216 bytes |
| Sessions | 4,096 agent-wide; 64 per observed principal |
| IPC connections | 8,192 agent-wide; 32 per session |
| In-flight requests | 4,096 agent-wide; 32 per session |
| SDK queued calls | 256 per client in addition to 32 in flight |
| Advertised profiles | 256 |
| SDK family/version | fixed 2-value family / 1-64 ASCII bytes |
| Client request ID | exactly 16 bytes |
| Pending operations returned | 256, equal to global per-principal cap |
| Portable receipt | 1,048,576 bytes; profile aggregate is smaller/equal |
| Recovery handle | 16,384 bytes |
| Error envelope | 65,536 bytes |

Limits are checked before proportional allocation. Agent-wide capacity
refuses the newly arriving unauthenticated connection or session; it never
evicts an existing session or unresolved operation. A full open client queues
at most 256 ordinary calls in FIFO order. The next new operation fails locally
with common `operation.admission-exhausted`; a same-operation coalesced waiter
follows section 14.5 instead and preserves the original effect state. Safe
status/recovery calls use 410 reserved agent-wide request slots; new prepare
and execute calls may consume only the other 3,686. Effect admission pressure
therefore cannot make recovery unreachable.

### 13.2 Session handshake

`POST /v1/session` accepts:

```cbor-diag
{
  1: 1,                    / auths.local-agent protocol /
  2: h'<16-byte request id>',
  3: "<sdk family>",       / python | typescript /
  4: "<sdk version>",
  5: h'<32-byte common error-registry digest>',
  6: "full" / "recovery-only"
}
```

The response is:

```cbor-diag
{
  1: 1,
  2: h'<same request id>',
  3: "<session id>",
  4: "<observed Auths principal>",
  5: h'<32-byte common error-registry digest>',
  6: [
    {
      1: "auths.stripe.refund",
      2: 1,
      3: h'<32-byte profile runtime-contract digest>',
      4: "auths.profile-operation/1",
      5: h'<32-byte profile error-registry projection digest>',
      6: {
        1: "stripe",
        2: "auths.stripe.connection/1",
        3: "auths.stripe.connection-descriptor/1"
      }
    }
  ],
  7: 32,                   / maximum concurrent requests /
  8: "full" / "recovery-only"
}
```

Session ID and principal use the registered-token and principal grammars owned
by the Rust model. The response advertises at most 256 profiles. A duplicate
profile ID/version or digest is a fatal handshake error.
Inner field 6 is the runtime contract's exact connection projection or null
for a domain with no external connection. Its values are duplicated inside
the runtime-contract digest and must match it byte-for-byte.

SDK family is exactly `python` or `typescript`. SDK version is 1-64 ASCII bytes
matching `[0-9A-Za-z][0-9A-Za-z.+-]{0,63}` and is diagnostic only; protocol and
digest fields, never semver comparison, decide compatibility.

An exact common registry digest permits a `full` root session. A common digest
mismatch permits only `recovery-only`; no prepare or execute route is admitted.
For a new profile operation, the generated package additionally requires its
exact advertised profile error-projection digest and runtime-contract digest.
A mismatch in either profile digest disables only that profile's new effects;
it does not disable compatible profiles in the same session. Root status and
recovery remain usable for an already-entered operation. If recovery encounters
a code or profile result unknown to the client, the SDK does not decode or
expose it. It constructs its own installed common
`operation.recovery-unavailable` issue with
`possible/unknown/resume-and-reconcile`, retains the original operation ID and
recovery handle, and returns/raises only that conservative projection. It never
invents a not-applied classification or exposes an untyped code through the
generated facade. A terminal domain success is returned in recovery-only mode
only when that profile's runtime and error-projection digests still match.

Every later request carries exactly one `Auths-Session` header containing the
returned session ID. The header is routing state, not authority: the agent also
requires the current IPC peer to match the principal bound at handshake. A
missing, unknown, expired, duplicated, or cross-principal session is rejected
before request-body processing.

A logical client session may use up to 32 pooled IPC connections. Each
connection is independently peer-authenticated. Sessions expire after 3,600
seconds of inactivity and have an 86,400-second absolute lifetime. Before any
later request, the SDK transparently negotiates a replacement when required.
A new prepare still requires an exact profile contract match; common status
and recovery remain available for already-entered operations and remain bound
to operation principal rather than old session ID.
`Client.close()` sends `DELETE /v1/session/<session-id>` on a best-effort basis
and always closes local sockets. Agent expiry is authoritative if the close
response is lost.

### 13.3 Profile route family

For profile `auths.<domain>.<effect>/<version>`, the vertical registers these
exact static routes:

```text
POST /v1/profiles/<domain>/<effect>/<version>/operations
POST /v1/profiles/<domain>/<effect>/<version>/operations/<operation-id>/execute
POST /v1/profiles/<domain>/<effect>/<version>/operations/<operation-id>/recover
GET  /v1/profiles/<domain>/<effect>/<version>/operations/<operation-id>
GET  /v1/profiles/<domain>/<effect>/<version>/operations/<operation-id>/receipts
```

A checked manifest may additionally declare
`contracts.preparationEvidence = "protected-lease"`. For only that concrete
profile, generation adds this companion route:

```text
POST /v1/profiles/<domain>/<effect>/<version>/preparation-evidence
```

The companion is connection-owned support for the existing profile, not a
profile, effect, or generic callback. It is absent for every manifest that
does not declare it and is never advertised as another profile. Runtime
dispatch is the generated concrete profile arm; unrelated profiles do not
implement no-op hooks.

There is no generic `/invoke` route. Static route construction rejects
collisions at startup.

Routes are ASCII and matched before percent-decoding. The server rejects a
percent sign, duplicate slash, dot segment, trailing slash, alternate case, or
query parameter on an effect route. `<domain>` and `<effect>` are the exact
lower tokens from the profile ID; `<version>` is canonical decimal with no
leading zero; and `<operation-id>` follows section 15.5.

The local agent additionally exposes two effect-safe operational routes:

```text
GET  /v1/operations/pending
POST /v1/operations/recover
```

`pending` returns at most 256 nonterminal operations owned by the observed IPC
principal, ordered by `(updated_at, operation_id)`, with no profile result
body. The agent enforces 256 as a global per-principal nonterminal-operation
cap across profiles, so a successful `pending` response is complete rather
than silently truncated. `recover` accepts one sealed recovery handle and dispatches only to the
concrete profile/version already stored for that operation. It cannot name a
new profile, action, provider command, or idempotency key. These routes support
the root `Operations` API and are not a generic execution surface.

### 13.4 Prepare request

The operations collection accepts:

```cbor-diag
{
  1: 1,                         / auths.profile-operation/1 /
  2: h'<16-byte client request id>',
  3: null / "<idempotency key>",
  4: h'<32-byte profile runtime-contract digest>',
  5: h'<canonical profile API input bytes>',
  6: null / "<connection alias>",
  7: null / h'<32-byte sealed preparation-evidence handle>'
}
```

For a connected domain, key 6 is the constructor alias or null to request the
observed workload's configured default. For a connection-free domain it must
be null. The alias is bounded before profile input allocation. The agent
resolves it through section 7.4 before canonical action construction and does
not disclose whether a rejected alias is missing, unauthorized, disabled, or
revoked.

Key 7 is null for profiles without a checked `preparationEvidence` contract.
For a profile declaring `protected-lease`, it is the exact live handle issued
by section 13.4.1; null, expired, cross-principal, cross-request,
cross-idempotency, cross-input, cross-connection, cross-configuration, or
cross-authority handles fail before decision persistence, reservation, command
sealing, credential request, or provider mutation.

The client request ID is generated from the host CSPRNG before the first write
and retained for the full method call. An idempotency key is 1-128 ASCII bytes
matching `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`. The server stores only its
SHA-256 commitment and never logs the raw key.

Preparation performs bounded alias/input decoding, authorized connection
resolution, canonicalization, authority verification, profile evaluation,
durable decision persistence, reservation, and command sealing. It performs no
credential request and no provider I/O.

The server durably binds:

```text
observed principal
+ profile ID/version/runtime-contract digest
+ client request ID
+ optional idempotency-key commitment
+ canonical input commitment
+ internal connection ID/generation, descriptor commitment, and account commitment, or null
+ canonical action commitment
+ authority commitment
+ required configuration commitment
```

Repeating preparation with the same principal and client request ID is exact
replay. A different commitment is conflict. Repeating a caller idempotency key
with an identical commitment returns the original operation. A changed
commitment returns `ConflictError` containing the original operation ID and
never creates another workflow.

#### 13.4.1 Protected preparation-evidence companion

The generated SDK hides companion acquisition inside the one public profile
method. It sends the exact future preparation tuple before `/operations`:

```cbor-diag
{
  1: 1,
  2: h'<same 16-byte client request id>',
  3: null / "<same idempotency key>",
  4: h'<same 32-byte runtime-contract digest>',
  5: h'<same canonical profile API input bytes>',
  6: null / "<same connection alias>"
}
```

Before protected provider read I/O, the agent observes the IPC principal,
derives the same stable workflow identity as preparation, resolves the active
sealed connection and required configuration, constructs the domain-owned
bounded evidence-read action, and verifies its authority. Alias possession is
not read authority. Denied, indeterminate, malformed, conflict, and
unavailable requests perform no provider read.

On an exact live lease replay, the agent returns the retained lease without a
provider read. On a miss, the statically linked domain acquisition calls only
the separately credentialed protected read broker. The agent samples trusted
time after that response, validates peer identity, signature, account, pinned
provider API version, freshness, and exact request binding, then atomically
stores an immutable lease before responding. The v1 lease lifetime is 120
seconds and the store has fixed entry, per-record, and aggregate-byte limits.
It stores only bounded signed evidence and commitments, never a provider
credential or mutation capability.

Success is the exact six-key map:

```cbor-diag
{
  1: 1,
  2: h'<same 16-byte client request id>',
  3: "lease",
  4: h'<32-byte opaque handle>',
  5: h'<32-byte evidence commitment>',
  6: <expiry unix seconds>
}
```

When the journal already owns the request or idempotency identity, the
companion does not reacquire evidence. It returns the exact retained ordinary
operation projection in this closed four-key envelope:

```cbor-diag
{1: 1, 2: h'<request id>', 3: "outcome", 4: h'<canonical ordinary outcome>'}
```

The durable lease binds the principal, exact profile/version/runtime digest,
workflow, request identity, optional idempotency commitment, canonical input,
connection ID/generation/descriptor/account commitments, required
configuration, preliminary read action and authority artifact, signed evidence
bytes and commitment, acceptance time, and expiry. Same-request replay may
return immutable journal truth before consulting mutable deployment state. A
fresh request with the same idempotency key recomputes current connection,
configuration, and authority commitments; drift is `Conflict` naming the
original operation and causes no provider read.

The `/operations` route resolves only this already durable local lease and
remains provider-I/O-free. Its `PreparationBindingV1` includes the evidence
commitment. The handle is internal routing state: SDKs never expose it and
zeroize their mutable copy after preparation or cancellation. A possibly
written companion request is exact-retried at most once. A nested `ready` or
`in-progress` outcome re-enters the ordinary installed state machine; it is
not exposed as a new public result. One total method deadline reserves the
configured recovery window for exact replay and safe pre-entry release.

### 13.5 Execute request

The execute body is:

```cbor-diag
{
  1: 1,
  2: h'<16-byte client request id>',
  3: "<operation id>",
  4: h'<32-byte preparation commitment>'
}
```

The profile input and command are not resubmitted.

The SDK sends execute at most once. A connection loss, cancellation, timeout,
or malformed response after the request may have been written causes status
and recovery lookup for the original operation; it never causes a second
execute request.

### 13.6 Recover and status

Status is read-only and never advances provider state. Recover invokes only
the profile's concrete reconciliation path and only when durable state says
reconciliation is permitted. It never reconstructs an original provider call
from client input.

The profile-specific recover body and common operational recover body are both:

```cbor-diag
{1: 1, 2: h'<16-byte client request id>', 3: h'<recovery handle>'}
```

GET status and receipt requests have no body. A GET carrying a body is
malformed.

The common status projection is:

```text
operation ID
profile ID/version
resolved connection alias or null
state
effect: not-applied | possible | applied
terminal: boolean
updated-at
receipt IDs
recovery handle when possible
profile result bytes only when terminal and decodable
```

Unknown caller-selected IDs do not disclose whether another principal owns an
operation. Unknown and unauthorized lookups have the same bounded response.

### 13.7 Outcome envelopes and HTTP status

Registered profile and operation routes return HTTP 200 for every valid Auths
outcome. Prepare, execute, profile status, and either recover route return the
current canonical outcome. The request ID in a GET response is the original
stored client request ID. The body is exactly one of these closed variants:

```cbor-diag
/ prepared; provider has not been entered /
{1:1, 2:"ready", 3:h'<request id>', 4:"<operation id>",
 5:h'<32-byte preparation commitment>', 6:h'<portable decision receipt>',
 7:h'<recovery handle>', 8:null / "<connection alias>"}

/ accepted but not yet terminal; profile result is not exposed /
{1:1, 2:"in-progress", 3:h'<request id>', 4:"<operation id>",
 5:"preparing" / "executing", 6:"not-applied" / "possible",
 7:["<receipt id>", ...], 8:h'<recovery handle>',
 9:null / "<connection alias>"}

/ denied before provider entry /
{1:1, 2:"denied", 3:h'<request id>', 4:"<operation id>",
 5:h'<auths.error/1 envelope>', 6:h'<portable decision receipt>',
 7:null / "<connection alias>"}

/ pre-entry unavailability; operation id is present only if durably allocated /
{1:1, 2:"unavailable", 3:h'<request id>', 4:null / "<operation id>",
 5:h'<auths.error/1 envelope>', 6:[] / [h'<portable decision receipt>'],
 7:null / "<connection alias>"}

/ changed commitment for an existing idempotency key /
{1:1, 2:"conflict", 3:h'<request id>', 4:"<original operation id>",
 5:h'<auths.error/1 envelope>', 6:h'<recovery handle>', 7:[h'<receipt>', ...],
 8:null / "<connection alias>"}

/ terminal success /
{1:1, 2:"completed", 3:h'<request id>', 4:"<operation id>",
 5:h'<profile success bytes>', 6:[h'<receipt>', ...],
 7:"fresh" / "replayed" / "reconciled", 8:null / "<connection alias>"}

/ terminal profile-defined subset /
{1:1, 2:"partial", 3:h'<request id>', 4:"<operation id>",
 5:h'<profile partial bytes>', 6:h'<auths.error/1 envelope>',
 7:[h'<receipt>', ...], 8:"fresh" / "replayed" / "reconciled",
 9:null / "<connection alias>"}

/ provider-proven no effect /
{1:1, 2:"not-applied", 3:h'<request id>', 4:"<operation id>",
 5:h'<auths.error/1 envelope>', 6:[h'<receipt>', ...],
 7:"fresh" / "replayed" / "reconciled", 8:null / "<connection alias>"}

/ possible effect /
{1:1, 2:"recovery-required", 3:h'<request id>', 4:"<operation id>",
 5:h'<auths.error/1 envelope>', 6:h'<recovery handle>',
 7:[h'<receipt>', ...], 8:null / h'<profile progress bytes>',
 9:null / "<connection alias>"}

/ retained receipt or profile-claim integrity failed; no receipt or value bytes /
{1:1, 2:"receipt-integrity-failed", 3:h'<request id>', 4:"<operation id>",
 5:h'<core.terminal-receipt-integrity-failed auths.error/1 envelope>',
 6:"preparing" / "ready" / "executing" / "denied" / "unavailable" /
   "recovery-required" / "completed" / "partial" / "not-applied",
 7:"not-applied" / "possible" / "applied", 8:false / true,
 9:null / "<connection alias>"}
```

The integrity variant accepts only these state/effect/terminal tuples:

| State | Effect | Terminal |
| --- | --- | --- |
| `preparing`, `ready` | `not-applied` | false |
| `executing` | `not-applied` or `possible` | false |
| `denied`, `unavailable`, `not-applied` | `not-applied` | true |
| `recovery-required` | `possible` | false |
| `completed`, `partial` | `applied` | true |

Its issue correlation and execution reference equal key 4, its issue effect
equals key 7, and its entered-provider boundary agrees with the state/effect.
The variant contains no receipt array, recovery handle, progress, partial, or
success value. The SDK projects it as the sealed `ReceiptIntegrityError`,
preserving state, effect, and terminal.

Profile success and partial bytes are canonical values from the restricted
profile API schema. Receipt order is profile-defined but bounded by the
manifest; linked decision precedes execution for each phase. An omitted key,
extra key, wrong key type, impossible effect/error combination, noncanonical
encoding, or trailing byte rejects the response.

The returned alias is the resolved record alias. A connected profile cannot
report null after successful connection resolution. Before resolution,
`unavailable` may report the caller's bounded alias or null without revealing
a default or hidden record. The SDK uses the server-returned value—not the
requested null/default placeholder—to synthesize operation metadata.

The common pending response is:

```cbor-diag
{1:1, 2:[
  {
    1:"<operation id>", 2:"<profile id>", 3:<profile version>,
    4:"preparing" / "ready" / "executing" / "recovery-required",
    5:"not-applied" / "possible", 6:false,
    7:<updated-at unix seconds>, 8:["<receipt id>", ...],
    9:h'<recovery handle>', 10:null / "<connection alias>"
  }, ...
]}
```

The array contains 0-256 records in `(updated-at, operation-id)` order. The
receipt-list response is:

```cbor-diag
{1:1, 2:"<operation id>", 3:[
  {1:"<receipt id>", 2:h'<portable receipt bytes>'}, ...
]}
```

Receipt entries are in profile-defined phase order, decision before linked
execution, and obey the manifest count/aggregate limits. The common pending
route never returns receipt bytes or profile result bytes.

An `auths.error/1` byte string is the canonical CBOR encoding of the existing
Rust `ErrorEnvelope` wire fields. Host-only derived fields such as display
classes or convenience booleans are not serialized into it. The decoded code,
operation, stage, outcome, and reference fields must satisfy the negotiated
registry definition exactly.

The server uses non-200 responses only before a valid Auths outcome envelope
can be formed:

| HTTP status | Meaning |
| --- | --- |
| 400 | malformed route/framing/CBOR |
| 404 | unregistered static route, indistinguishable from disabled profile |
| 413 | declared or absolute request limit exceeded |
| 415 | wrong media type |
| 500 | failure before operation acceptance and before provider entry |

The server closes an unauthenticated IPC connection without processing a
request. HTTP 3xx, 401, 407, and arbitrary provider statuses never cross this
boundary. After an operation is accepted, an internal failure is represented
by a registered outcome envelope; after possible provider entry it must be
`recovery-required`, except that a receipt/profile-claim integrity failure is
the closed `receipt-integrity-failed` variant above and preserves the already
durable state/effect instead of weakening provider truth.

## 14. Operation lifecycle

### 14.1 Required durable order

Every profile vertical implements this order:

```text
bounded API input
  -> authorized connection resolution and sealed metadata snapshot, or null
  -> canonical profile action
  -> exact proof and authority verification
  -> concrete profile evaluation
  -> durable decision
  -> atomic reservation
  -> verifier-sealed exact command
  -> fresh critical evidence/connection/configuration re-read
  -> required/executed connection and configuration equality
  -> least-privilege credential lease for the sealed connection
  -> closed provider command
  -> provider entry marker
  -> provider call
  -> durable provider result
  -> profile observation
  -> commit | release | partial | unknown | reconcile
  -> linked decision/execution receipts
  -> terminal projection
```

The durable provider result MUST be written before observation. This ordering
is crash-tested immediately before and after every arrow.

Connection resolution before canonicalization performs no provider I/O and
acquires no credential. It supplies only the sealed connection identity and
commitments that the concrete canonical action must bind. A connection-free
profile binds a canonical null. The later equality check prevents alias
retargeting, account substitution, generation substitution, or credential
rotation between decision and provider entry.

### 14.2 Shared and profile-owned state

The shared lifecycle package owns bounded identifiers, atomic store mechanics,
common effect axes, event ordering, replay commitments, and durable envelope
integrity. It durably retains the sealed connection ID/generation and common
commitments but does not decode the provider descriptor or credential. It does
not decide:

- whether a provider result proves an effect;
- whether capacity may be released;
- whether a partial result exists;
- what observation is authoritative;
- whether reconciliation is conclusive; or
- what a profile receipt may claim.

Those decisions are concrete functions in the profile vertical and remain
differentially tested against its reference semantics.

The common public state vocabulary is closed:

| State | Terminal | Permitted effect |
| --- | --- | --- |
| `preparing` | no | `not-applied` |
| `denied` | yes | `not-applied` |
| `unavailable` | yes | `not-applied` |
| `ready` | no | `not-applied` |
| `executing` | no | `not-applied` before provider entry, otherwise `possible` |
| `recovery-required` | no | `possible` |
| `completed` | yes | `applied` |
| `partial` | yes | `applied` |
| `not-applied` | yes | `not-applied` |

The effect field is authoritative when `executing`; callers never infer effect
from the state name alone. Profiles may keep additional internal states but
must project them into exactly one row without losing effect truth.

### 14.3 Effect truth table

| Condition | Public effect | SDK behavior |
| --- | --- | --- |
| Rejected before provider entry | `not-applied` | typed denial/unavailable; retry only as issue permits |
| Exact replay of terminal success | `applied` | return original result with `completion=replayed` |
| Provider result proves no effect | `not-applied` | profile-defined not-applied error/result |
| Provider result proves full effect | `applied` | return success |
| Provider result proves a profile-defined subset | `applied` | throw typed partial error with partial details |
| Provider may have entered and evidence is inconclusive | `possible` | automatic bounded recovery, then `RecoveryRequired` |
| Reconciliation proves full or no effect | corresponding state | return with `completion=reconciled` |

Transport success, HTTP status, a provider identifier, or a signed receipt
alone does not prove the effect unless the profile contract says exactly why.

### 14.4 Cancellation

Caller cancellation before the first request write propagates the host
`asyncio.CancelledError` or `AbortError` and creates no operation. If it is
observed after preparation, the SDK sends no execute request, asks the concrete
profile recovery path to release only a durably pre-entry reservation, and
propagates host cancellation once durable state proves not-applied. A
coalesced operation that another caller may have executed is not treated as
pre-entry merely because this waiter was cancelled.

After the execute request may have been written, cancellation cannot erase
work: the SDK shields a status/recovery lookup for at most `recovery_wait` and
returns the established terminal result or raises `RecoveryRequired`. This is
the one intentional point at which Python caller cancellation is converted to
a security result and TypeScript abort is converted to a typed error. A normal
deadline that expires while durable state proves pre-entry raises registered
`operation.timed-out`; a deadline after possible entry is
`operation.outcome-unknown`/`RecoveryRequired`.

Profile gateways and reconcilers must use cancellable, bounded provider ports.
An in-process callback that can ignore cancellation and continue applying an
effect is not a conforming production provider boundary. Such development
callbacks must run in a terminable worker process or remain test-only.

### 14.5 Concurrency

One session admits at most 32 in-flight requests. One operation admits one
effect-advancing request. Duplicate same-key callers observe the original
operation through read-only status; they do not each hold an effect slot.

At most 256 local waiters may await one operation. The 257th waiter receives a
non-waiting projection of the original operation. It is never misclassified as
a new pre-effect failure when the original may have entered the provider.

Deployment and profile quotas may narrow, but never widen, manifest limits.
Quota exhaustion for a previously unseen operation fails before provider entry.
Unresolved possible-effect records continue to consume quota until resolved.

## 15. Idempotency and recovery

### 15.1 Ordinary path

When `OperationOptions.idempotency_key` is omitted, the SDK generates a fresh
16-byte client request ID. The local agent durably records it during prepare.
This makes retry inside the same method invocation safe without making two
identical business operations globally identical.

The returned result and every operational exception expose `operation_id`.
The local agent also exposes bounded pending operations for crash recovery.

### 15.2 Caller-controlled idempotency

Applications that require exact restart behavior supply a stable idempotency
key through `OperationOptions`. This is the only ordinary advanced option. The
key is commitment-bound to the principal, profile, canonical input, action,
resolved connection ID/generation/account commitment, and required
configuration.

Content-derived idempotency is forbidden as the default because two deliberate
identical effects must remain distinguishable.

### 15.3 Automatic recovery

After an ambiguous execute transport result, the SDK:

1. stops sending effect requests;
2. queries status using the original operation ID;
3. follows a server-issued recovery directive only through the recover route;
4. waits up to `recovery_wait` within the total operation timeout;
5. returns the terminal result when established; or
6. raises `RecoveryRequired` with the durable handle.

It never converts recovery timeout into `UnavailableError` and never creates a
new operation.

### 15.4 Retention

Unresolved possible-effect records are never automatically deleted. Terminal
full records use the profile manifest's retention. A compact tombstone holding
principal, profile, idempotency commitment, request commitment, terminal
effect, operation ID, and receipt IDs survives for at least the manifest's
idempotency retention.

`durableBytesPerPrincipal` counts active records, unresolved records, terminal
records, receipts, tombstones, indexes, and retained profile result bytes for
that principal/profile. `tombstonesPerPrincipal` counts retained idempotency
tombstones. The fixed-minute admission counter and all quotas are persisted or
transactionally checked with the operation reservation so concurrent final
capacity has one winner.

Garbage collection is profile-aware and cannot release an unknown reservation
or erase the only recovery locator. Storage capacity exhaustion rejects new
operations before effect and emits operator diagnostics; it does not discard
unresolved records.

### 15.5 Identifiers and recovery handles

Operation IDs are `op_` followed by the unpadded base64url encoding of 16
server-generated CSPRNG bytes. Session IDs use the same construction with the
`ses_` prefix. IDs are compared byte-for-byte and never case-folded.

The recovery-handle semantic identity is `auths.recovery-handle/1`. Its
canonical CBOR payload is:

```cbor-diag
{
  1: 1,
  2: "<operation id>",
  3: "<profile id>",
  4: <profile version>,
  5: h'<32-byte observed-principal commitment>',
  6: <issued-at unix seconds>,
  7: null / <expiry unix seconds>,
  8: h'<32-byte random nonce>',
  9: "Ed25519",
  10: "<recovery signing key id>",
  11: h'<64-byte signature>'
}
```

The agent uses a deployment-managed recovery signing key that survives agent
restart. A handle is additionally authorized against the current IPC peer
principal, so possession alone cannot cross principals. Every accepted
nonterminal operation has a handle. Its expiry is null until the operation is
durably terminal, including while it is ready and provably pre-entry. A
terminal handle expires no earlier than the profile's idempotency retention.

The signature preimage is ASCII `auths.recovery-handle/1`, one NUL byte, then
the canonical CBOR map containing fields 1-10. The key ID is a 1-128-byte
registered token. Key rotation retains verification-only public keys until no
unresolved handle and no unexpired terminal handle can name them. The agent
verifies algorithm, key ID, signature, bounds, principal commitment, and
current durable record before dispatching recovery.

Encoded handles are 1-16,384 bytes and are validated before copying or CBOR
decode. `RecoveryHandle` is sealed, non-subclassable, non-JSON-serializable,
and redacted in `repr`/inspection. `to_bytes()` is the only persistence form.
Encoded bytes are a sensitive recovery capability and production examples send
them only to a deployment secret store; they never write a casual working-tree
file or environment variable. Principal binding limits misuse but does not
make disclosure acceptable.
TypeScript additionally exports:

```ts
export function recoveryHandleFromBytes(value: Uint8Array): RecoveryHandle;
```

Malformed, wrong-principal, wrong-profile, expired, or forged handles are
indistinguishable at the lookup boundary and reveal no operation existence.

## 16. Receipts

Every prepared operation produces a decision receipt. Every provider-entered
operation produces an execution receipt linked to that exact decision receipt.
Partial workflows may produce additional ordered phase receipt pairs as
defined by the profile.

The portable container semantic identity is `auths.portable-receipt/1` and has
exactly two canonical CBOR variants:

```cbor-diag
/ standalone decision /
{1:1, 2:"decision", 3:h'<complete signed decision-receipt envelope>'}

/ execution plus the complete decision it links /
{1:1, 2:"execution", 3:h'<complete signed decision-receipt envelope>',
 4:h'<complete signed execution-receipt envelope>'}
```

There are no other keys or trailing bytes. Each signed inner envelope retains
its existing Rust-owned schema and signature semantics. The execution envelope
must name the embedded decision receipt ID, and verification recomputes both
IDs and requires the link byte-for-byte. A verifier never has to obtain an
unavailable decision envelope by ID alone.

A portable receipt is 1-1,048,576 bytes before copy/decode and additionally
obeys the profile aggregate limit. Its public ID is `rcpt_` followed by the
unpadded base64url encoding of SHA-256 over the complete canonical portable
container. Lists return a standalone decision followed by its execution
container; although the execution container repeats decision bytes, those
bytes count again toward the aggregate response and storage limits. A denied
phase returns only its standalone decision container.

The local agent verifies:

- canonical receipt bytes;
- decision/execution link;
- profile ID and version;
- action, authority, connection ID/generation/account, configuration,
  command, and result commitments;
- signer role, principal, verification method, suite, and key version;
- validity and receipt age; and
- profile-specific payload inspection.

Only then does it return a terminal high-level result. Public receipt keys and
trust configuration are deployment-owned and loaded by the local agent; they
are not application credentials or method parameters.

Generated success metadata contains receipt IDs. `Operations.receipts()` calls
the authenticated receipt route and returns sealed `PortableReceipt` values
only after the agent verifies them. `to_bytes()` returns a defensive copy for
audit export; there is deliberately no root constructor that upgrades arbitrary
bytes to trusted receipt status. Generated profile packages do not decode or
reinterpret receipt payloads in Python or TypeScript. Any future local detail
inspector must be a separate Rust-owned verifier projection. The receipt route
returns portable containers, not naked inner execution envelopes.

## 17. Errors

### 17.1 Common versus profile codes

The shared registry owns connection, negotiation, admission, commitment
conflict, storage, and outcome-unknown codes. Each profile owns its domain
denial, partial, provider, observation, and reconciliation codes.

The authoritative Rust registry remains one closed
`auths.error-registry/1` registry inside an executor build. Its checked-in
`product/errors/v1/registry.json` is now a generated aggregate, not a
hand-edited roster. Inputs are `product/errors/v1/common.json` plus one
`auths.error-registry-fragment/1` file selected by each profile manifest's
`sources.errors`. Language packages consume deterministic projections rather
than one monolithic enum:

- `product/errors/v1/profile-client-common.json` is an
  `auths.error-projection/1` document containing the exact ordered code names
  usable by the root profile-client protocol;
- the root SDK embeds those definitions and their SHA-256 canonical-JSON
  digest and exports `CommonAuthsErrorCode`;
- a profile manifest selects exactly one `errorOwner` and
  `errorOwnerVersion`; generation projects every matching definition, orders
  it by code, embeds its digest in the generated package, and emits a
  profile-specific string enum/union such as `StripeRefundErrorCode`; and
- the executor validates common and profile projections against its full
  registry at startup and advertises their digests in the session handshake.

A profile fragment has the exact shape:

```json
{
  "schema": "auths.error-registry-fragment/1",
  "owner": "stripe-refund",
  "ownerVersion": 1,
  "definitions": [
    {
      "code": "stripe-refund.invalid-input",
      "family": "input",
      "owner": "stripe-refund",
      "ownerVersion": 1,
      "operation": "execute",
      "stages": ["profile-input"],
      "outcomes": [{"retry": "never", "effect": "not-applied"}],
      "recommendedAction": "correct-input",
      "allowsExecutionReference": false,
      "allowsDecisionReference": false,
      "allowsReceiptReference": false,
      "title": "Invalid refund input",
      "explanation": "The bounded refund input is not valid for this profile.",
      "fixtureId": "stripe-refund-invalid-input"
    }
  ]
}
```

`definitions` contains 1-128 complete current `ErrorDefinition` JSON objects;
each object's owner/version must match the fragment and manifest. The empty
array is rejected. Common definitions have the same definition shape under
`auths.error-registry/1` in `common.json`. The
aggregate generator loads only fragments in the closed profile roster, rejects
duplicate codes/fixtures/owner-version ambiguity, orders definitions by code,
emits `registry.json` and Rust constants, and byte-compares them in CI. Runtime
loading or package-installed registry extension is forbidden.

The projection file has this exact closed shape:

```json
{
  "schema": "auths.error-projection/1",
  "id": "profile-client-common",
  "codes": [
    "client.agent-unavailable",
    "client.profile-contract-mismatch",
    "client.profile-unavailable",
    "connection.contract-mismatch",
    "connection.credential-unavailable",
    "connection.unavailable",
    "core.malformed-input",
    "core.runtime-unavailable",
    "operation.admission-exhausted",
    "operation.idempotency-conflict",
    "operation.outcome-unknown",
    "operation.recovery-unavailable",
    "operation.timed-out"
  ]
}
```

Codes are unique and strictly ascending by UTF-8 byte order. The projection
digest is SHA-256 over a canonical compact JSON array containing the complete
selected registry definitions—not merely their names—ordered by code. A
change to any selected operation, stage, outcome, action, reference permission,
title, explanation, or owner changes the digest.

The root `AuthsIssue.code`/`AuthsError.code` runtime value is a string validated
against the negotiated union of the common projection and the selected
profile projection. The root does not publish a global all-profile enum.
Generated profile errors narrow `code` to
`CommonAuthsErrorCode | <Profile>ErrorCode`. Python emits `str, Enum` classes
whose `__str__` returns `.value`; TypeScript emits readonly string unions.
This is what allows a new profile package to add domain codes without a
handwritten root-SDK edit.

A profile owner/version must select at least one definition and is selected by
exactly one profile ID/version. Reuse across profiles is rejected; shared
mechanism failures belong in the common projection instead. The generator
rejects a profile result or
fixture containing a code outside the common projection or its selected owner.
The Rust vertical likewise cannot return an arbitrary string: its closed error
conversion is generated from the same projection.

Every code has one exact operation, stage, effect, retry class, recommended
action, title, explanation, and reference-permission set. Causes remain the
existing global closed category enum with at most eight entries. Unknown codes
and registry digest mismatch are rejected before a new effect. Already-entered
recovery remains available through the common operation protocol and never
reclassifies an unknown code as not applied.

The `auths.error/1` value in section 13.7 is a canonical CBOR map with these
exact lower-camel text keys and the same value vocabulary as Rust
`ErrorEnvelope`:

```cbor-diag
{
  "schema": "auths.error/1",
  "family": "<registered family>",
  "code": "<negotiated code>",
  "operation": "<registered operation>",
  "stage": "<registered stage>",
  "summary": "<sanitized UTF-8 summary>",
  "correlationId": "<registered token>",
  "retry": "never" / "safe" / "conditional" / "unknown",
  "effect": "not-applied" / "possible" / "applied",
  "entered": {
    "approval": false,
    "signer": false,
    "state": true,
    "credential": true,
    "provider": true
  },
  "recommendedAction": "<closed registry action>",
  "executionReference": null / "<registered token>",
  "decisionReference": null / "<registered token>",
  "receiptReference": null / "<registered token>",
  "causes": ["<closed cause category>", ...]
}
```

The map uses canonical CBOR text-key ordering. `entered` has exactly the five
existing Rust `EnteredBoundaries` boolean fields. `causes` preserves the
bounded `ErrorEnvelope` order and contains at most eight values; this local
transport does not silently strengthen the existing `auths.error/1` acceptance
rules. Token fields are 1-128 ASCII bytes and `summary` is 1-256 UTF-8 bytes.
The server builds this map only after `ErrorEnvelope::parse` accepts the exact
definition axes. Bindings decode it only after the negotiated projection and
65,536-byte envelope limit pass.

### 17.2 Required new common codes

Implementation adds these exact definitions atomically to
`product/errors/v1/common.json`, the generated aggregate registry and Rust
constants, generated language projections, documentation, and fixtures. They
use the existing definition shape and closed outcome/action vocabulary:

```json
[
  {
    "code": "client.agent-unavailable",
    "family": "runtime",
    "owner": "profile-client",
    "ownerVersion": 1,
    "operation": "connect",
    "stages": ["local-agent"],
    "outcomes": [{"retry": "conditional", "effect": "not-applied"}],
    "recommendedAction": "correct-configuration",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false,
    "title": "Local Auths agent unavailable",
    "explanation": "The SDK could not establish an authenticated local-agent session.",
    "fixtureId": "client-agent-unavailable"
  },
  {
    "code": "client.profile-unavailable",
    "family": "configuration",
    "owner": "profile-client",
    "ownerVersion": 1,
    "operation": "connect",
    "stages": ["negotiation"],
    "outcomes": [{"retry": "never", "effect": "not-applied"}],
    "recommendedAction": "install-compatible-runtime",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false,
    "title": "Profile unavailable",
    "explanation": "The local agent did not advertise the required profile and version.",
    "fixtureId": "client-profile-unavailable"
  },
  {
    "code": "client.profile-contract-mismatch",
    "family": "configuration",
    "owner": "profile-client",
    "ownerVersion": 1,
    "operation": "connect",
    "stages": ["negotiation"],
    "outcomes": [{"retry": "never", "effect": "not-applied"}],
    "recommendedAction": "install-compatible-runtime",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false,
    "title": "Profile contract mismatch",
    "explanation": "The generated client and runtime do not share the same profile contract digest.",
    "fixtureId": "client-profile-contract-mismatch"
  },
  {
    "code": "connection.contract-mismatch",
    "family": "configuration",
    "owner": "profile-client",
    "ownerVersion": 1,
    "operation": "execute",
    "stages": ["connection-resolution"],
    "outcomes": [{"retry": "never", "effect": "not-applied"}],
    "recommendedAction": "install-compatible-runtime",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false,
    "title": "Provider connection contract mismatch",
    "explanation": "The profile runtime and selected provider connection do not share the required immutable connection contract.",
    "fixtureId": "connection-contract-mismatch"
  },
  {
    "code": "connection.credential-unavailable",
    "family": "runtime",
    "owner": "profile-client",
    "ownerVersion": 1,
    "operation": "execute",
    "stages": ["credential"],
    "outcomes": [{"retry": "safe", "effect": "not-applied"}],
    "recommendedAction": "retry-execution",
    "allowsExecutionReference": true,
    "allowsDecisionReference": true,
    "allowsReceiptReference": true,
    "title": "Provider credential unavailable before entry",
    "explanation": "The bound provider credential could not be leased and durable state proves that the provider was not entered.",
    "fixtureId": "connection-credential-unavailable"
  },
  {
    "code": "connection.unavailable",
    "family": "configuration",
    "owner": "profile-client",
    "ownerVersion": 1,
    "operation": "execute",
    "stages": ["connection-resolution"],
    "outcomes": [{"retry": "never", "effect": "not-applied"}],
    "recommendedAction": "correct-configuration",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false,
    "title": "Provider connection unavailable",
    "explanation": "No active provider connection matching the requested or default alias is authorized for this workload and profile.",
    "fixtureId": "connection-unavailable"
  },
  {
    "code": "operation.admission-exhausted",
    "family": "state",
    "owner": "profile-client",
    "ownerVersion": 1,
    "operation": "execute",
    "stages": ["admission"],
    "outcomes": [{"retry": "conditional", "effect": "not-applied"}],
    "recommendedAction": "retry-execution",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false,
    "title": "Operation admission exhausted",
    "explanation": "The bounded operation capacity was exhausted before provider entry.",
    "fixtureId": "operation-admission-exhausted"
  },
  {
    "code": "operation.idempotency-conflict",
    "family": "state",
    "owner": "profile-client",
    "ownerVersion": 1,
    "operation": "execute",
    "stages": ["reservation"],
    "outcomes": [{"retry": "unknown", "effect": "possible"}],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": true,
    "allowsReceiptReference": true,
    "title": "Idempotency commitment conflict",
    "explanation": "The key names an existing operation with a different commitment; recover that operation.",
    "fixtureId": "operation-idempotency-conflict"
  },
  {
    "code": "operation.outcome-unknown",
    "family": "state",
    "owner": "profile-client",
    "ownerVersion": 1,
    "operation": "execute",
    "stages": ["provider"],
    "outcomes": [{"retry": "unknown", "effect": "possible"}],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": true,
    "allowsReceiptReference": true,
    "title": "Operation outcome unknown",
    "explanation": "The provider may have applied the exact operation; recover it instead of retrying.",
    "fixtureId": "operation-outcome-unknown"
  },
  {
    "code": "operation.recovery-unavailable",
    "family": "state",
    "owner": "profile-client",
    "ownerVersion": 1,
    "operation": "recover",
    "stages": ["reconciliation"],
    "outcomes": [{"retry": "unknown", "effect": "possible"}],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": true,
    "allowsReceiptReference": true,
    "title": "Operation recovery unavailable",
    "explanation": "Recovery could not establish the effect and the original operation remains possible.",
    "fixtureId": "operation-recovery-unavailable"
  },
  {
    "code": "operation.timed-out",
    "family": "runtime",
    "owner": "profile-client",
    "ownerVersion": 1,
    "operation": "execute",
    "stages": ["pre-provider"],
    "outcomes": [{"retry": "safe", "effect": "not-applied"}],
    "recommendedAction": "retry-execution",
    "allowsExecutionReference": true,
    "allowsDecisionReference": true,
    "allowsReceiptReference": true,
    "title": "Operation timed out before provider entry",
    "explanation": "The bounded deadline expired and durable state proves that the provider was not entered.",
    "fixtureId": "operation-timed-out"
  }
]
```

An idempotency conflict conservatively describes the original operation as
possible until its durable state is loaded. Its exception always includes the
original operation ID. It never means the changed request entered the provider.

### 17.3 Redaction

Errors, logs, traces, and receipts never contain:

- raw idempotency keys;
- provider credentials or credential handles;
- credential-store references, OAuth codes, refresh tokens, and raw provider
  account identifiers;
- full proof or authority bytes;
- private input fields marked sensitive by the API schema;
- raw provider response bodies; or
- filesystem paths from the application host.

Profile API fields may declare `sensitive: true`; generated `repr`, inspection,
logging, and telemetry projections replace their value with `<redacted>` while
canonical request processing still receives the bounded value.

## 18. Contributor workflow

A third party contributes either through a reviewed monorepo change or by
building a custom executor from the same layered packages and conformance
tools. Publishing only a Python or npm profile package cannot enable an effect:
the executor must contain the matching qualified Rust vertical and exact
runtime-contract digest.

### 18.1 Scaffold command

`cargo xtask profile new` accepts exactly:

```text
--domain <token>
--effect <token>
--version <1..65535>
[--existing-domain]
[--provider <token> --connection-version <1..65535> | --connectionless]
```

Exactly one of `--provider ...` or `--connectionless` is required for a new
domain and forbidden with `--existing-domain`. An existing-domain profile
inherits the manifest's connection object or null and cannot replace it.

For a new domain it creates:

```text
product/integrations/auths-<domain>/
├── Cargo.toml
├── profile-package.json
├── api/profile-api.json
├── errors/<effect>-v<version>.json
├── src/
│   ├── lib.rs
│   ├── connection/                 # connected new domains only
│   │   ├── mod.rs
│   │   ├── descriptor.rs
│   │   ├── onboarding.rs
│   │   ├── credentials.rs
│   │   └── admin_routes.rs
│   └── <effect>/
│       ├── mod.rs
│       ├── action.rs
│       ├── evaluator.rs
│       ├── command.rs
│       ├── lifecycle.rs
│       ├── gateway.rs
│       ├── reconciliation.rs
│       ├── receipt.rs
│       ├── errors.rs
│       └── routes.rs
├── fixtures/<effect>/v<version>/
└── tests/
    ├── connection_conformance.rs   # connected new domains only
    ├── reference_semantics.rs
    ├── mutations.rs
    ├── lifecycle.rs
    ├── provider_requests.rs
    └── receipts.rs
```

It also creates generated profile-package workspaces under:

```text
bindings/generated/<domain>/typescript/
bindings/generated/<domain>/python/
```

With `--existing-domain`, the command requires exactly one roster entry for the
domain, adds only the new profile manifest entry, API types, error fragment,
effect source subtree, fixtures, and tests, and regenerates the existing two
language distributions. Without the flag, an existing domain is an error; with
the flag, a missing domain is an error. Neither mode overwrites an existing
semantic subject, effect ID, route, source file, or fixture directory.

For a connected new domain, the scaffold creates a draft immutable connection
contract `auths.<provider>.connection/<connection-version>`, descriptor schema,
provider adapter/admin router, connection fixtures, and TODOs for exact
onboarding and credential behavior. For `--connectionless` it writes
`domain.connection: null` and emits none of those files. Adding another account
to an implemented provider never runs this command; it runs `auths connections
add` against a deployment.

The scaffold updates workspace membership, `architecture.toml`, and draft
inventory entries, but marks the profile `specified`, never `qualified`.

### 18.2 Author-owned implementation

The contributor must implement and review:

1. for a newly connected domain, one exact connection descriptor, onboarding,
   account-substitution check, credential rotation/revocation implementation,
   and connection conformance corpus;
2. one bounded canonical API-input decoder;
3. one exact canonical action mapping that binds the sealed connection or
   canonical null;
4. one pure reference evaluator;
5. one verified command decoder from sealed action data;
6. one concrete lifecycle transition relation;
7. one closed provider request builder;
8. one least-privilege credential scope recognized by the connection adapter;
9. one provider result classifier;
10. one observation and reconciliation implementation;
11. one profile receipt payload and inspector;
12. one complete profile-owned error-registry fragment;
13. one closed conversion from domain/provider states to the selected registry
    codes; and
14. all hard limits.

These are never generated from field names.

### 18.3 Generated output

`cargo xtask profile generate --domain <domain>`:

1. validates the manifest and API schema;
2. validates a connected domain's immutable connection contract and evidence;
3. computes checked worst-case sizes;
4. emits Rust DTO/codecs and route constants;
5. emits Python and TypeScript DTOs and connection-bound domain clients;
6. emits common/profile error projections and manifest digest constants;
7. emits public API inventories and package exports;
8. emits fixture encoders/decoders;
9. emits clean-consumer tests and quickstarts; and
10. refuses to overwrite a generated file containing unrecognized edits.

The exact generated locations are:

```text
product/integrations/auths-<domain>/src/generated/profile_api.rs
product/integrations/auths-<domain>/src/generated/profile_routes.rs
bindings/generated/<domain>/typescript/src/generated.ts
bindings/generated/<domain>/typescript/src/index.ts
bindings/generated/<domain>/typescript/package.json
bindings/generated/<domain>/python/src/auths_profiles/<domain>/generated.py
bindings/generated/<domain>/python/src/auths_profiles/<domain>/__init__.py
bindings/generated/<domain>/python/pyproject.toml
bindings/generated/<domain>/fixtures/
```

Handwritten domain-client convenience methods are forbidden in the generated
package. A desired convenience must be represented by the restricted schema or
the manifest's client grouping and regenerated. Domain semantic helpers remain
in the Rust vertical and do not execute in the application process.

Every generated file begins with its generator version, source manifest path,
and source digest. CI regenerates into a temporary directory and requires a
byte-for-byte match.

### 18.4 Check command

`cargo xtask profile check --domain <domain>` runs:

- manifest and API-schema validation;
- source-path and inventory closure;
- Rust unit and property tests;
- canonical and hostile fixture generation;
- provider-request equality tests;
- provider-connection contract, default/explicit alias, account substitution,
  rotation, revocation, and secret-redaction tests for connected domains;
- profile lifecycle and crash corpus;
- receipt mutation tests;
- generated Python strict mypy and Pyright tests;
- generated TypeScript strict declaration and misuse tests;
- packed wheel and npm consumer smoke tests;
- cross-language canonical CBOR comparison;
- secret and redaction fixture checks; and
- architecture and compliance validation.

It is a focused development command. The merge gate remains hosted
`cargo xtask ci` on the exact revision.

## 19. Profile qualification

A generated client may be published only after the profile completes all
phases required by
`docs/target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md`.

The machine-readable qualification entry must include:

- canonical valid and invalid fixtures;
- mutation corpus;
- property and checked-arithmetic tests;
- denial-before-credential proof;
- exact provider-request fixtures;
- concurrent final-capacity tests;
- crash before and after every durable checkpoint;
- replay, partial, possible-effect, and reconciliation tests;
- a real native backend and sandbox provider effect;
- Docker-local HTTP operation;
- a connected frontend with controls and result visible together;
- inline and dedicated receipt views;
- browser end-to-end tests for the demo UI;
- architecture and compliance registration;
- secret scan and redacted deployment evidence; and
- authoritative hosted CI for the exact revision.

The generated language package remains private/experimental until this gate
passes. Generation is not qualification.

## 20. Shared-mechanism extraction rule

The profile system does not waive the abstraction locality ladder.

The local session, canonical API-schema generator, route framing, manifest
negotiation, idempotency commitment mechanics, common recovery envelope, and
linked receipt envelope are candidate mechanisms because their contracts do
not choose domain meaning. The provider-connection record, authorization
lookup, generation commitment, credential-store lease mechanics, and
administrative record lifecycle are also candidate mechanisms. Provider
onboarding, account interpretation, scope meaning, refresh, and revocation
remain domain-owned.

Before extracting behavior from existing verticals into those mechanisms, the
implementation must create an abstraction case file under:

```text
docs/architecture/abstractions/generic-profile-client-v1.md
```

It compares at least OpenTofu saved-plan apply, PostgreSQL bounded update, and
GitHub issue address, while using OpenTofu and PostgreSQL as the first two
client conversions. The comparison explicitly marks evaluator, credential,
provider, partial, reconciliation, and receipt-payload behavior as
domain-specific.

Connection extraction evidence compares at least two independent provider
kinds with materially different credential models before the shared registry
and credential-store contracts qualify. The implementation plan uses
PostgreSQL deployment credentials and Stripe account credentials; a synthetic
adapter alone is insufficient. A Gmail or Vercel contribution then exercises
the new-provider path without changing shared operation semantics.

No shared function may accept a callback that decides effect state, release,
retry, reconciliation truth, or receipt claims.

## 21. Testing requirements

### 21.1 Root SDK tests

Both language SDKs test:

- `connect()` with no token or credential option;
- safe socket ownership and symlink rejection;
- peer-principal substitution rejection;
- handshake registry mismatch;
- profile manifest mismatch;
- one session with two domain clients and two provider connections;
- explicit alias, configured default, and missing-default behavior;
- new/open/closing/closed lifecycle;
- cancellation before any write;
- cancellation after execute write;
- 32-request admission and boundary-plus-one;
- no redirect/proxy/TCP fallback;
- response and error body limits;
- pending-operation listing and redaction; and
- exact public API snapshots.

### 21.2 Generated client tests

Every profile package tests:

- all generated field bounds and boundary-plus-one;
- unknown field and noncanonical CBOR rejection;
- Python/TypeScript naming and value parity;
- file convenience reads maximum plus one only;
- no public arbitrary route or credential input;
- generated connected-domain constructor alias bounds and no per-method
  override;
- success metadata;
- typed denial, unavailable, partial, and recovery errors;
- explicit-outcome/facade equivalence; and
- clean package installation with only declared dependencies.

### 21.3 Effect-safety tests

Every profile tests:

- denied before credential request;
- unauthorized, missing, disabled, revoked, and contract-mismatched connection
  before credential request;
- connection alias retarget, account substitution, and generation change
  between decision and provider entry;
- credential rotation before entry and during unresolved recovery;
- unavailable before provider entry;
- exact command equals verified canonical action;
- changed idempotency commitment returns original conflict;
- concurrent same-key requests create one provider entry;
- response loss immediately before provider entry;
- response loss immediately after provider entry;
- durable provider result before observation;
- exact replay requests zero new credentials and mutations;
- reconciliation cannot release an inconclusive effect;
- partial outcome preserves all already-applied facts;
- unresolved records survive process restart; and
- all returned receipts verify and inspect locally.

### 21.4 Contributor tests

The scaffolder and generator test:

- deterministic output on macOS, Linux, and Windows;
- invalid identifiers, path escapes, and collisions;
- recursive and unbounded schema rejection;
- checked maximum-size arithmetic;
- stale generated output detection;
- no handwritten root-SDK edit for a new profile;
- package naming collision detection;
- manifest/static-router disagreement;
- a synthetic third-party profile compiled in a clean consumer workspace;
- a synthetic new connected provider with a static adapter and two account
  records, compiled in a clean executor workspace;
- adding the second account without regeneration or rebuild; and
- rejection of a dynamic provider adapter or manifest-declared OAuth endpoint.

## 22. Repository implementation plan

Implementation proceeds in this exact order. Each unit is independently
reviewable and leaves the repository coherent.

### Unit 1: contracts and case file

Create:

```text
product/spec/v1/profile-package.schema.json
product/spec/v1/profile-api.schema.json
product/spec/v1/error-projection.schema.json
product/spec/v1/error-registry-fragment.schema.json
product/spec/v1/profile-roster.schema.json
docs/architecture/abstractions/generic-profile-client-v1.md
```

Add the manifest, API-schema, error-projection, and roster parser/model types
to `product/sdk/auths-profile-kit`; add only canonical schema constants to
`product/spec`. `auths-profile-kit` is tooling/test ownership and must not enter
a production runtime dependency graph. Add hostile schema tests and no runtime
behavior.

### Unit 2: local authenticated session protocol

Extend:

```text
product/runtime/auths-production-client
product/runtime/auths-node
product/errors/auths-errors
product/errors/v1/common.json
product/errors/v1/registry.json
```

Implement authenticated local IPC, session handshake, capability negotiation,
common limits, `product/errors/v1/profile-client-common.json`, layered registry
fragment/aggregate/projection generation, and the new error fixtures. Migrate
existing profile-owned definitions from the hand-edited aggregate into their
own roster-selected fragments; `registry.json` becomes generated in this same
atomic unit. Do not expose profile execution yet.

### Unit 3: common operation journal

Extend `auths-lifecycle`, `auths-stores`, and `auths-node` with client request
IDs, commitment-bound prepare replay, pending-operation lookup, common status,
and retention/quota enforcement. Preserve profile-owned transition meaning.

### Unit 4: provider connection and administration mechanisms

Create and register:

```text
product/runtime/auths-connections
product/spec/v1/provider-connection.schema.json
product/spec/v1/provider-connection-admin.schema.json
product/conformance/v1/connection-credential-store.json
```

Extend `auths-stores`, `auths-node`, `product/config/auths-config`, and the
product CLI with the record model, workload authorization/default mapping,
static provider-adapter roster glue, separate privileged administration
listener, generation-safe credential store, audit records, limits, and common
connection error definitions from sections 7 and 17. Implement a synthetic
adapter only for mechanism conformance. Do not expose an effect executor or a
language-binding credential adapter.

### Unit 5: scaffolder and generator

Extend `auths-profile-kit` and add bounded `xtask profile new|generate|check`
commands. Generate into isolated fixture packages first. Prove deterministic
output, profile-specific error projection, and schema bounds before converting
a production profile.

### Unit 6: root Python and TypeScript sessions

Add `connect()`, client lifecycle, common errors, operation options, local IPC,
and the explicit profile-runtime extension subpaths. Freeze installed-package
public APIs and run clean packed consumers.

### Unit 7: first non-GitHub profile conversion

Convert OpenTofu saved-plan apply to the manifest, generated clients, static
route family, common preparation journal, and high-level facade. Retain its
concrete evaluator, command, gateway, lifecycle, reconciliation, and receipt
payload in `auths-opentofu`.

Declare and implement its domain connection object or a reviewed canonical
null according to the actual provider boundary; do not hide a provider
credential behind a connectionless manifest.

The first public quickstart uses OpenTofu or a sandboxed Stripe refund—not
GitHub.

### Unit 8: second independent conversion

Convert PostgreSQL bounded update and its exact deployment connection contract.
Exercise explicit/default aliases and two database-account records.
Differentially compare the two conversions and correct only shared mechanism
contracts. Do not merge their semantics.

### Unit 9: contributor and second-provider proof

Scaffold and implement a bounded Stripe refund profile and exact Stripe
connection adapter using the workflow from this specification. This supplies
the second independent credential model needed to qualify the shared
connection mechanisms. Onboard two Stripe accounts without rebuilding after
the adapter is installed. A contributor unfamiliar with the root bindings must
be able to complete the client integration by editing only the connection
adapter when new, vertical, manifest, API schema, error fragment, fixtures, and
demo, then running the generator. Generated outputs are reviewed but never
hand-edited.

In a clean executor fixture, repeat the new-domain scaffold for a synthetic
mailbox or deployment provider with an OAuth-shaped adapter. This proof must
add its generated Python/TypeScript package and static Rust adapter without a
handwritten root-SDK or shared-executor branch. It is qualification evidence,
not permission to ship synthetic provider semantics.

### Unit 10: direct prelaunch cutover

After the first two qualified conversions and contributor proof:

- make generated profile clients the ordinary documented path;
- remove public bearer-token constructors from effectful profile clients;
- move staged vertical APIs to explicit advanced profile-package subpaths only
  where still justified;
- remove superseded routes, exports, docs, and examples in the same change;
- reject obsolete disposable state; and
- regenerate topology, API inventories, compliance evidence, and semantic
  freeze manifests.

Do not add compatibility aliases, dual routes, or deprecated forwarding
methods.

### Unit 11: full qualification

Run the complete vertical/evidence gates, packed package matrices, architecture
and compliance checks, and hosted `cargo xtask ci`. Publish no stable package
before the exact revision passes.

## 23. Required documentation

The implementation updates:

- root Python and TypeScript READMEs;
- `docs/product/PRODUCTION_SDK_QUICKSTART.md` to be domain-neutral;
- one 25-line quickstart per profile distribution;
- profile authoring documentation generated from this manifest contract;
- local-agent deployment and workload-mapping documentation;
- provider-connection onboarding, default selection, rotation, disable,
  revocation, backup, and recovery runbook;
- one provider-adapter authoring guide distinguishing a new account, new
  operation, and new provider kind;
- error-code reference and recovery runbook;
- `bindings/public-topology-v1.json` or its intentional versioned successor;
- customer journey and package support matrices;
- architecture and compliance inventories; and
- semantic freeze/release evidence.

README order is:

1. one ordinary typed effect;
2. what Auths guarantees;
3. typed errors and recovery;
4. ambient identity and deployment setup;
5. another domain example;
6. advanced outcomes and receipts; and
7. profile contribution.

Raw proof/action/context verification and staged delegation do not appear on
the first screen.

## 24. Acceptance checklist

The target is complete only when every statement below is true.

### Consumer experience

- [ ] Python and TypeScript execute a qualified non-GitHub profile in 25 or
      fewer nonblank first-screen lines.
- [ ] The examples contain no token, credential, boundary, delegation,
      idempotency, receipt-trust, or recovery plumbing.
- [ ] Generated methods return domain success DTOs directly.
- [ ] Typed errors preserve not-applied, applied/partial, and possible effects.
- [ ] A lost effect response never causes a blind retry.
- [ ] Root public APIs are small, snapshotted, and package-tested.
- [ ] One session concurrently uses Gmail/Vercel-shaped or equivalent domain
      clients bound to different authorized connections.
- [ ] Selecting another installed account changes only the deployment alias
      and onboarding record, not the SDK or executor build.

### Generic infrastructure

- [ ] One local session works with at least OpenTofu, PostgreSQL, and Stripe
      profile packages without domain branches in the root SDK.
- [ ] All three use the same session, negotiation, profile-runtime ABI,
      operation journal, recovery envelope, and linked-receipt envelope.
- [ ] Their evaluators, commands, gateways, credentials, transitions,
      reconciliation, and receipt payloads remain profile/domain-owned.
- [ ] No stable generic `invoke(string, dict)` or arbitrary execution route
      exists.
- [ ] Connection records, authorization/default lookup, generation binding,
      and credential leasing are shared without moving provider request or
      effect meaning out of profile verticals.
- [ ] A new provider kind adds one static connection adapter plus its exact
      profiles and generated package, with no root-SDK branch.

### Credential isolation

- [ ] Applications authenticate through local ambient identity.
- [ ] The stable client has no bearer-token parameter or Authorization header.
- [ ] Denied paths acquire zero credentials.
- [ ] Provider credential material never enters the application process.
- [ ] Explicit/default aliases are workload-authorized and missing,
      unauthorized, disabled, and revoked records are indistinguishable to
      applications.
- [ ] Account, descriptor, and credential-generation substitution fail before
      provider entry; unresolved recovery survives rotation and revocation.

### Contributor experience

- [ ] `xtask profile new` creates a complete bounded scaffold.
- [ ] `xtask profile generate` emits both language clients deterministically.
- [ ] Adding a profile requires no handwritten root binding changes.
- [ ] Adding a second account for an installed provider requires no code
      generation or rebuild.
- [ ] New connected domains receive descriptor/onboarding/credential-adapter
      scaffolding and connection conformance tests.
- [ ] Invalid, recursive, unbounded, colliding, or path-escaping schemas fail.
- [ ] Generated packages pass strict typechecking and clean installation.
- [ ] A new contributor can follow only this spec and generated TODOs to reach
      the profile qualification checklist.

### Security and evidence

- [ ] Every effect follows the durable ordering in section 14.1.
- [ ] Crash tests cover both sides of every durable transition.
- [ ] Exact replay creates no credential or provider effect.
- [ ] Unresolved possible effects survive restart and capacity pressure.
- [ ] Every receipt pair verifies, links, and inspects across Rust, Python, and
      TypeScript.
- [ ] Architecture, compliance, fixtures, public APIs, support matrices, and
      semantic freeze manifests agree.
- [ ] Hosted `cargo xtask ci` passes on the exact revision.

## 25. Completion condition

This specification succeeds when Auths feels like a normal typed product SDK
to application developers and like a disciplined vertical framework to
profile contributors:

```text
application developer: connect -> choose named/default account -> call domain method -> receive result

deployment operator: onboard account -> authorize alias -> rotate/revoke safely

profile contributor: scaffold -> implement connection adapter when new -> implement exact effect -> generate -> qualify

Auths platform: authenticate -> resolve connection -> authorize -> reserve -> lease credential -> execute -> recover -> attest
```

The common path is small because the platform owns its mechanics, not because
security states were deleted or domain semantics were weakened.

## 26. Related authoritative documents

- `AGENTS.md` — repository architecture, safety, change, and CI contract.
- `docs/target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md` —
  vertical-first semantic ownership and extraction gates.
- `docs/specs/0036_sdk_ergonomics.md` and
  `docs/specs/0037_sdk_ergonomics_2.md` — sealed commands, SDK ergonomics,
  package closure, and profile conformance.
- `docs/specs/0026-reservation-and-execution-state-semantics.md` — durable
  exact-effect state semantics.
- `docs/specs/0029-human-approval-and-custody.md` — custody and external
  approval boundaries.
- `docs/target-state/STRIPE_PROFILE_FAMILY_IMPLEMENTATION_PLAN.md` — concrete
  profile-family separation used by the reference client example.
- `public_api_chatgpt.md` — the current exact prelaunch public-surface proposal;
  implementation of this specification must update its ordinary effectful path,
  inventories, examples, and cutover units atomically rather than leaving two
  conflicting target APIs.
- `product/conformance/v1/simplified-product-waist.json` and
  `product/conformance/v2/mechanism-profile-conformance.json` — current
  executable cross-language and adapter evidence.

This specification governs the new generic consumer and contributor layer. It
does not replace any profile's exact semantic specification.
