# AP-SPEC-043: OpenTofu connection and protected plan preflight

## 1. Status and authority

Prelaunch normative specification for `auths.opentofu.connection/1`,
`auths.opentofu.plan-preflight/1`, and
`auths.opentofu.saved-plan-apply/1`.

This specification is subordinate to AP-SPEC-040's generic local-agent
protocol and durable ordering and complements AP-SPEC-0008's bounded source,
protected planner, plan projection, apply, reconciliation, and receipt
semantics. This relaunch is a clean break. The apply API accepts no caller plan
bytes, plan file, plan path, plan handle, state evidence, backend credential,
or compatibility form.

## 2. Public workflow

The generated SDK exposes two independently authorized operations:

```text
prepared = opentofu.plans.create({
  sourceFiles,
  variables,
  dependencyLock,
  workspace
})

result = opentofu.savedPlans.apply({
  preparedPlan: prepared.preparedPlan
})
```

Python uses `plans.create(...)` and `saved_plans.apply(...)` with the same
generated role types. The first operation sends bounded source text to an
isolated protected planner. The second sends only an opaque, short-lived
reference to product-owned prepared metadata. `preparedPlan` is not a backend
credential, OpenTofu plan handle, proof of authority, or filesystem path.

Planning and applying have separate profile decisions, operation IDs,
receipts, credential scopes, idempotency keys, and recovery handles. A
successful plan preflight does not authorize apply.

## 3. Connection contract

`auths.opentofu.connection/1` identifies one backend and workspace namespace.
The canonical descriptor identity is
`auths.opentofu.connection-descriptor/1` and binds:

- `backendKind`;
- `backendIdentity`;
- `workspacePrefix`; and
- this exact byte-sorted scope set:

```text
[
  "opentofu.plan-preflight.create/1",
  "opentofu.saved-plan.apply/1"
]
```

Unknown, missing, duplicate, unsorted, or additional scopes invalidate the
descriptor. The account commitment is SHA-256 over a domain separator and
length-delimited backend kind, backend identity, and workspace prefix.

The provider adapter alone interprets protected backend/provider credentials.
The descriptor contains no secret, credential-store locator, CLI environment,
plan handle, prepared token, or caller-resolvable secret reference. Alias
resolution supplies only the connection ID/generation and non-secret
commitments and performs no provider I/O.

Each profile lease re-reads the registry and secret generation and checks the
exact workload and scope. Planning receives only the privileges needed to
initialize, read state, resolve pinned providers, and create a plan.
Apply receives only those needed to recheck state and execute the already
prepared artifact. Deployments may use different underlying credentials for
the two scopes.

### 3.1 Deployment-owned profile configuration

Verifier configuration and pinned planner policy are neither caller input nor
connection metadata. The deployment supplies them through AP-SPEC-040's agent
configuration under this exact closed table shape:

```toml
[agent.profile_configurations."auths.opentofu.plan-preflight/1"]
format = "auths.opentofu.verifier-configuration/1"
path = "/etc/auths/profiles/opentofu-saved-plan-v1.json"
sha256 = "<64 lowercase hexadecimal characters>"
maximum_bytes = 524288

[agent.profile_configurations."auths.opentofu.saved-plan-apply/1"]
format = "auths.opentofu.verifier-configuration/1"
path = "/etc/auths/profiles/opentofu-saved-plan-v1.json"
sha256 = "<the same digest>"
maximum_bytes = 524288
```

Both entries are mandatory and must name the same format, path, digest, and
maximum. The canonical file contains `OpenTofuVerifierConfigurationV1` plus
the launch planner policy: exact OpenTofu binary digest, platform, fixed argv
template, sandbox identity, dependency mirror/source allowlist, exact provider
pin policy, an empty module-pin roster, and prepared-plan lifetime. Module
execution is fail-closed until installed module bytes have a protected
materialization and verification contract. `maximum_bytes` must be in
`1..=524288`.

The path is absolute UTF-8, contains no `.` or `..` component, and is not
beneath the agent's mutable state directory. The table rejects unknown fields,
duplicate or unregistered profile references, relative paths, non-lowercase
digests, and aliases of one path with unequal metadata.

Before binding the local socket, startup opens the path with no-follow
semantics, requires one regular file, rejects group/other-writable files and a
file writable by the local caller identity, reads at most
`maximum_bytes + 1`, checks stable file identity/size across the read, verifies
SHA-256, requires canonical domain bytes, and invokes the statically registered
OpenTofu configuration validator. Any failure aborts startup. The validated
bytes, digest, secure path metadata, and file identity form an immutable
`ProfileConfigurationBinding`; there is no live reload. Changing configuration
requires an agent restart and invalidates prepared plans created under the old
digest or tool policy.

The shared loader validates only file safety, bounds, format identity, and
digest. Build-time static roster dispatch calls the concrete OpenTofu
validator; no trait object, callback, registry plugin, or domain branch is
added to shared lifecycle code. `ProfileOperationContext` receives the exact
immutable binding for its profile. Prepare parses it locally and binds its
digest into the canonical action without provider I/O. After command sealing
and before credential lease, the agent securely re-reads the same path,
repeats the file/digest checks, and requires byte equality with the startup
binding. Inequality is a pre-provider configuration failure and requires
restart; no operation falls back to a connection descriptor, environment
variable, PATH lookup, or caller value.

## 4. Restricted public API

`api/profile-api.json` is the wire authority. Its launch roles are:

```text
SourceFile { path, contents }
Variable { name, value }
PlanPreflightInput {
  sourceFiles: 1..32 SourceFile
  variables: 0..64 Variable
  dependencyLock: bounded UTF-8 lock-file text
  workspace: bounded workspace name
}

PreparedPlan {
  preparedPlan: opaque registered-token
  actionDigest: lowercase SHA-256
  workspace
  priorStateSerial
  creates
  updates
  reads
  noOps
  expiresAt
}

ApplyPreparedPlanInput { preparedPlan }
ApplyResult { workspace, stateSerial }
```

The input is a list representation of AP-SPEC-0008's source-bundle maps.
Canonicalization requires `sourceFiles` byte-sorted by unique path,
and `variables` byte-sorted by unique name. It rejects duplicates rather than applying
last-write-wins semantics.

Paths are relative canonical `.tf` paths with no empty, `.`, `..`, hidden, or
backslash segment. Symlinks and caller filesystem paths cannot appear in this
DTO. Each text field is copied before use. The domain enforces the 2 MiB
aggregate source/variable/lock limit, HCL nesting bound, forbidden-feature
rules, exact provider pins, an empty module closure, and all AP-SPEC-0008 restrictions in addition to
the per-field schema bounds. Variables are sensitive and never enter receipts.

The public apply input deliberately contains no `bytes` type and no
`sourceConvenience: file`. The generated apply clients therefore cannot accept
a `ProfileFile`, `Uint8Array`, Python `bytes`, plan upload, or arbitrary plan
handle.

## 5. Plan-preflight profile

### 5.1 Identity and effect

The profile is `auths.opentofu.plan-preflight/1`, effect
`opentofu.plan-preflight.create`, credential scope
`opentofu.plan-preflight.create/1`, and client method `plans.create`.

It is a provider-reading and product-artifact-writing effect. Its prepare phase
must complete proof verification, profile evaluation, durable decision,
reservation, and sealed command before acquiring a planner/backend credential,
running OpenTofu, contacting the backend, resolving remote dependencies, or
writing a protected plan artifact.

### 5.2 Canonical preflight action

The canonicalizer validates and copies the restricted DTO, constructs
`OpenTofuSourceBundleV1`, resolves only the connection's non-secret snapshot,
loads the installed verifier configuration, and produces
`OpenTofuPlanPreflightActionV1` containing:

- profile identity;
- exact connection ID, generation, account and descriptor commitments;
- backend identity and requested workspace;
- canonical source-bundle digest;
- dependency-lock, module-manifest, and variable commitments;
- verifier-configuration digest and configured plan lifetime; and
- the generic request/session commitments required by AP-SPEC-040.

Source parsing and pure validation are permitted. The canonicalizer performs no
credential request, backend access, provider access, module download,
`tofu init`, `tofu plan`, state refresh, artifact-store write, DNS, or socket
open. Evaluation authorizes the exact proposed bundle, workspace, dependency
commitments, connection generation, and configured planner restrictions.

### 5.3 Sealed planner command

After durable decision and generic reservation, sealing:

1. generates a cryptographically random `pplan_` registered-token with at
   least 256 bits of entropy;
2. durably reserves its SHA-256 prepared-store key for the operation ID;
3. seals and durably records the exact noninteractive planner command,
   including the token hash, bundle/action digests, argv, environment, sandbox,
   pinned tool identity, dependency policy, and all limits;
4. re-reads the reservation, connection snapshot, verifier configuration, and
   pinned tool/dependency policy;
5. proves equality with the evaluated action;
6. leases scope `opentofu.plan-preflight.create/1`; and
7. records the planner/backend entry marker before executing the sealed
   command.

The existing `ProtectedPlanner` is then invoked in a fresh owner-private workspace.
It reads trusted backend state, creates the saved plan, derives and validates
the semantic projection from `tofu show -json`, computes every action and
evidence commitment, and puts the opaque saved-plan bytes into the protected
`PlanArtifactStore`. Raw plan bytes and unredacted show JSON never leave the
protected process.

The provider result is durably recorded before profile observation. A success
is returned only after section 7's prepared metadata and its referenced plan
artifact are atomically committed as `ready`. The returned counts, workspace,
state serial, action digest, and expiry are copied from that record. A plan
with zero changes or any denied feature is not made usable.

## 6. Saved-plan-apply profile

The profile remains `auths.opentofu.saved-plan-apply/1`, effect
`opentofu.saved-plan.apply`, scope `opentofu.saved-plan.apply/1`, and client
method `savedPlans.apply`. Its only public input is
`ApplyPreparedPlanInput`.

During prepare, after connection metadata resolution, the domain performs a
local-only lookup by the token's SHA-256 store key. It rejects missing,
expired, non-ready, already claimed, wrong-principal, wrong-profile,
wrong-connection, wrong-generation, wrong-backend, malformed, or digest-
inconsistent records. It independently decodes and revalidates the stored
`OpenTofuSavedPlanApplyV1`, `SavedPlanProjectionV1`, state evidence, and
configuration. The stored saved-plan action—not the token—is the canonical
authorization action. This phase performs no artifact resolution, OpenTofu
execution, backend/provider I/O, or credential request.

After decision and generic reservation, sealing atomically transitions the
prepared record from `ready` to `claimed(operationId)`. Re-entry by the same
operation is idempotent; every other operation is denied. Sealing re-reads and
checks the prepared metadata, connection, verifier configuration, pinned tool
identity, and `PlanArtifactStore` metadata. It resolves the raw artifact only
after those checks and verifies its opaque digest before provider entry.

The exact apply command is durably sealed before those fresh re-reads. After
equality and artifact-digest checks, the adapter leases only
`opentofu.saved-plan.apply/1`; the backend/provider entry marker is then written
before the state recheck or apply process begins.

After the provider entry marker, the existing gateway rechecks backend,
workspace, state lineage, serial and digest with the leased apply credential.
Any drift denies; the runtime never silently replans. It then runs the fixed
saved-plan apply command and preserves AP-SPEC-0008's result durability,
observation, reconciliation, state truth, and linked receipt rules.

The record becomes `consumed(operationId)` only with terminal success. A
pre-provider terminal denial releases a claim only when durable state proves
OpenTofu/backend entry did not occur. Possible entry retains the claim until
reconciliation is conclusive. No new operation may reuse a claimed token.

## 7. Prepared-plan store and artifact atomicity

The OpenTofu vertical owns a durable `PreparedPlanStore`; it is not a callback,
trait object, or OpenTofu-aware branch in the shared runtime. Build-time static
wiring supplies it only to concrete OpenTofu profile functions.

Each record contains, at minimum:

```text
schema = auths.opentofu.prepared-plan/1
tokenSha256
ownerPrincipalCommitment
preflightOperationId
connectionId
connectionGeneration
accountCommitment
descriptorCommitment
credentialCommitment
canonicalActionBytes
actionDigest
projectionBytes
projectionDigest
stateEvidenceBytes
stateEvidenceDigest
verifierConfigurationBytes
verifierConfigurationDigest
planHandle
opaquePlanDigest
pinnedToolDigest
createdAt
expiresAt
state = reserved | ready | claimed(operationId) | consumed(operationId) | expired
```

Every canonical component is independently decoded, re-encoded, bounded, and
digest-checked at every transition. The prepared store contains neither raw
plan bytes nor credentials; the artifact store contains raw plan bytes but no
caller token or authority. The ready transition is atomic with respect to the
artifact reference: a record cannot become ready until the artifact exists and
matches `opaquePlanDigest`. Failed planning removes or quarantines orphan
artifacts without exposing a token.

Reservation, readiness, claim, release, consumption, and expiry transitions
are durable compare-and-swap operations. Token lookup is constant-time with
respect to stored keys. The default lifetime is 900 seconds and the hard
maximum is 3600 seconds. A record never survives its source connection
generation, configuration version, pinned tool build, or dependency policy.
Cleanup cannot convert an unresolved apply into retry-safe state.

## 8. Recovery, receipts, and stable failures

Preflight recovery first checks the generic journal, then the reserved token
key and referenced artifact. A complete ready pair reconstructs the exact
success. An incomplete pair after possible planner/backend entry remains
recovery-required until domain reconciliation proves whether a ready artifact
was committed. Planning may repeat only the same sealed command and must never
replace an existing ready artifact.

Receipts contain no source contents, variable values, dependency-lock text,
raw plan bytes, unredacted projection, backend credentials, artifact handle, or
plaintext prepared token. They commit the token hash, source/action/projection/
state/config/tool/artifact digests, connection generation, public change
counts, provider-entry truth, and prepared-record transition.

Profile fragments own at least:

- `opentofu.plan-preflight-denied`;
- `opentofu.plan-preflight-outcome-unknown`;
- `opentofu.saved-plan-denied`; and
- `opentofu.apply-outcome-unknown`.

Unknown prepared tokens project through the saved-plan denial family without
revealing whether another principal or connection owns the token.

## 9. Required implementation and qualification

The implementation is incomplete until all of the following exist:

1. the concrete protected planner profile lifecycle and scoped credential path;
2. the durable `PreparedPlanStore` and atomic artifact/metadata behavior above;
3. concrete static local-agent functions `plans_create_*` and
   `saved_plans_apply_*` generated by the roster;
4. `AgentConfig.profile_configurations`, secure startup loading, immutable
   `ProfileConfigurationBinding`, static OpenTofu validation, and pre-entry
   re-read/equality enforcement from section 3.1;
5. descriptor/fixture support for both exact scopes;
6. Rust error-registry definitions matching both profile fragments;
7. crash tests immediately before and after every store, artifact, journal,
   credential, backend, and provider boundary;
8. mutation tests for every token binding, expiry, replay, artifact swap,
   backend/state/config/tool drift, and cross-principal substitution invariant;
   and
9. a live OpenTofu contract proving source preflight, approval, one apply,
   denial, replay behavior, recovery, and receipt verification.

Until those gates pass, both profiles remain statically advertised only as
unavailable; no stub may fabricate a plan token, projection, provider result,
or receipt.
