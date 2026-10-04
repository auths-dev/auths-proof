# AP-SPEC-066: Production gateway polish and recipe qualification

- **Status:** Draft. No implementation or production-qualified recipe is
  claimed by this document.
- **Depends on:** [AP-SPEC-038](0038-production-runtime-custody-observability-and-assurance.md)
  (production trust, custody, stores, and operations),
  [AP-SPEC-053](0053-declarative-credential-isolated-gateway.md) (the
  credential-isolated request boundary),
  [AP-SPEC-056](0056-openapi-derived-operation-contracts.md) (derived recipe
  candidates), [AP-SPEC-059](0059-commitment-bound-provider-evidence.md)
  (provider-held evidence),
  [AP-SPEC-060](0060-evidence-conditioned-authority.md) (observer evidence),
  [AP-SPEC-063](0063-generalized-gateway.md) (the single provider-write path),
  [ADR 0012](../adr/0012-declarative-credential-isolated-gateway-boundary.md),
  [ADR 0013](../adr/0013-recipe-capabilities-and-sum-budget.md), and the
  [profile and domain boundary plan](../target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md).
- **Enables:** a truthful production deployment of the generalized gateway;
  recipe-scoped provider qualification; a maintained production provider-secret
  adapter; maintained observer-key custody; and a finite launch gate without
  adding provider-specific behavior to the Auths core or gateway interpreter.
- **Scope:** product and release layers only: `product/runtime/auths-gateway`,
  `product/runtime/auths-connections`, `product/stores/auths-stores`, the
  existing `auths-custody` integration, a new provider-secret custody port,
  `xtask`, release qualification data, deployment assets, bindings diagnostics,
  tests, and documentation. The default is **no core change**. A missing core
  invariant blocks its epic and requires a separate ADR; this spec does not
  authorize moving provider behavior into core.
- **Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** specify
  implementation requirements.

## 1. Decision and launch claim

The generalized gateway already verifies an exact action, claims a logical
operation once, leases a gateway-held provider credential, constructs a closed
request from an operator-approved recipe, records the provider response, and
can observe provider-held evidence. Its remaining launch gap is operational:

1. development provider credentials are held in a local credential file rather
   than a maintained production secret system;
2. the shipped gateway does not yet use a maintained external-custody client
   for its observer key;
3. a live demonstration is not a durable, expiring qualification of an exact
   recipe against an exact provider contract; and
4. operators do not have one fail-closed view of custody, recipe qualification,
   drift, rotation, recovery, and safe readiness.

This spec closes those gaps while preserving this ownership rule:

> Auths owns exact-action verification, bounded request construction,
> credential isolation, replay/race/recovery behavior, and truthful evidence.
> The recipe author owns the declared mapping. The provider owns its API and
> effect semantics. Qualification is evidence about one pinned recipe and
> provider contract, never provider logic in Auths core.

**Launch claim after every done gate in §14 holds.** For each production-enabled
recipe, the gateway can enter the provider only for an exact action authorized
under supplied Auths trust, while the application has no provider credential.
The gateway resolves the operator-bound credential through a maintained
credential store, constructs only the request committed by the recipe, and
records a bounded outcome. A
recipe shown as `qualified` has an unexpired, signed qualification attestation
for the exact recipe family, compiled digest, gateway semantic closure, target,
custody mode, store mode, and named provider contract. Drift or custody failure
disables that recipe before credential lease or provider entry.

**This launch claim does not say:**

- that the provider performed, settled, or will preserve the business effect;
- that Auths understands provider business meaning;
- that an application which independently holds a provider credential cannot
  bypass the gateway;
- that provider reads are authorized by this write boundary;
- that a provider will behave tomorrow as it behaved during qualification;
- that every third-party recipe is qualified; or
- that a provider secret is non-exportable. Unlike a signing key, an HTTP
  credential must exist briefly in gateway memory to be injected into a header.

## 2. Product boundary

| Layer | Owns | MUST NOT own |
| --- | --- | --- |
| Auths core verifier | exact proof, trust, action, attenuation, approvals, closed policy verdict | URLs, HTTP, credentials, recipe qualification, provider names, business semantics |
| Generic gateway product | closed recipe compiler/interpreter, exact-action admission, logical-operation claim, store transitions, secret lease timing, request transport, evidence and operator gates | provider-specific branches, callbacks, SDK code loaded from a recipe, business-success interpretation |
| Connection credential store | retain one caller-unresolvable credential generation and lease bounded secret bytes for an exact sealed connection binding | select a provider, recipe, action, header, URL, connection, or fallback secret |
| Recipe package | declared provider mapping, closed guards, observation and recovery declarations, corpus and pure oracle | credentials, runtime URLs, executable callbacks, self-declared qualification |
| Qualification plane | differential tests, hostile/live runs, signed expiring attestations, release index | runtime request dispatch, production credential reuse, provider writes outside the named corpus |
| Provider | API contract and actual effect | Auths authorization or qualification claims |
| Operator | connection, credential-store kind, credential generation, recipe digest, trust, deployment, qualification policy, enable/disable | widening a compiled recipe or overriding a failed invariant |

The gateway MUST remain data-only. Adding a provider requires data, fixtures,
an optional pure test oracle, and qualification evidence; it MUST NOT require a
new runtime provider module.

## 3. Operator experience

### 3.1 Installation and readiness

The production path is explicit and has no `.env`, plaintext-file, or
application-token fallback:

```text
$ auths-gateway connection install \
    --connection stripe-refunds \
    --recipe release/recipes/stripe-refund-v1.cbor \
    --credential-store aws-secrets-manager-v1 \
    --credential-input-fd 3 \
    --qualification-policy required

Connection installed but disabled.
Recipe digest:       rcp_...
Credential material: stored by the selected credential store; not retained by CLI
Next: auths-gateway doctor --production --connection stripe-refunds

$ auths-gateway doctor --production --connection stripe-refunds
recipe              qualified until 2026-12-05 (qlf_...)
provider credential aws-secrets-manager-v1, generation 7, ready
observer             aws-kms-p256-v1, ready
store                postgresql-v1, ready
drift                none
writes               disabled (operator enable required)
claim                exact-action authorized; provider effect not claimed
```

Diagnostics MUST show identifiers and commitments, never secret bytes, secret
manager payloads, provider response bodies, account identifiers, or full
resource values. `ready` means every production precondition was checked; it
MUST NOT mean “configured” or “structurally present.”

### 3.2 Architecture

```text
 UNTRUSTED APPLICATION PLANE             OPERATOR / RELEASE PLANE

 agent/app -- proof + exact action --> [generic gateway]
                                         | verify (pure core)
                                         | policy + one-use claim
                                         | reload enabled connection
                                         | check qualification + drift
                                         v
                               [connection credential store] <- sealed generation
                                         | short lease
                                         v
                                  [closed recipe interpreter] ---> provider
                                         |                         |
                                         +---- outcome/store <-----+
                                         |                         |
                                  [observer custody]          read-back evidence

 recipe source + corpus + pure oracle ----> qualification runner ----> signed,
 provider contract + protected credential       (not runtime)          expiring
                                                                      attestation
                                                                          |
                                                    release index <--------+
```

The runtime gateway MUST NOT call the qualification runner. The qualification
runner MUST NOT become a credential broker for runtime traffic. A qualification
credential is environment-scoped, least-privileged, and distinct from every
production connection credential.

## 4. Type and invariant ledger

Every public type below has one owner and one named invariant. Rust owns the
normative type. Python and TypeScript expose thin projections where an operator
or SDK user needs them; bindings MUST NOT reimplement validation.

| Type | Owner | Named invariant |
| --- | --- | --- |
| `ConnectionCredentialStore` | existing `auths-connections` credential module | `identity-and-generation-only`: the store knows only connection identity, credential generation and commitment; never provider, recipe, URL, header or action |
| `CredentialReferenceCommitment` | existing `auths-connections` credential module | `caller-unresolvable-reference`: the connection binds the exact internal secret generation without exposing its location or material |
| `StoredSecretLease` | existing `auths-connections` credential module | `deadline-bound-zeroized`: secret bytes are visible only to the provider adapter before the deadline and zeroized on drop |
| `SecretBytes` | existing `auths-connections` credential module | `bounded-redacted-input`: non-empty bounded operator input, zeroized on drop and redacted under `Debug` |
| `ConnectionBinding` | existing `auths-connections` model | `sealed-generation-binding`: connection ID, credential generation and reference commitment are loaded from durable operator state as one unit |
| `CredentialStoreKind` | `auths-connections` credential module | `closed-store-kind`: exactly the maintained development or production credential-store kinds; unknown values reject |
| `SigningCustodyKind` | existing `auths-custody` | `closed-signing-kind`: existing signing custody classification, never reused for provider secrets |
| `RecipeFamilyId` | qualification model | `declared-family`: stable identifier named by an accepted ADR, not inferred from provider text |
| `ProviderContractId` | qualification model | `pinned-contract`: digest of the bounded contract inputs used by the qualification corpus |
| `QualificationTarget` | qualification model | `exact-target`: operating system, architecture, gateway package/build, store kind and custody kinds are exact |
| `RecipeQualificationState` | qualification model | `closed-derived-state`: exactly `unqualified`, `candidate`, `qualified`, `stale`, or `revoked`; never supplied by a recipe |
| `RecipeQualificationRecord` | qualification model | `evidence-closed`: every accepted claim is backed by named evidence members and their digests |
| `RecipeQualificationAttestation` | release policy | `trusted-expiring-signature`: canonical record, trusted signer, validity window, revocation and target all verify |
| `ProductionReadiness` | gateway operator API | `fail-closed-conjunction`: ready only when every required typed precondition is ready |

Newtype constructors MUST enforce size, grammar, canonicalization, and closed
enumerations. Raw strings MUST NOT cross connection, custody, qualification,
or readiness APIs where one of these types applies.

## 5. Production provider-secret custody

### 5.1 Separate port

Provider API secrets are not signing keys. They MUST keep using the existing
sealed `ConnectionCredentialStore` mechanism rather than stretching
`auths-custody` into secret retrieval or introducing a second overlapping
secret-store abstraction:

```rust
pub trait ConnectionCredentialStore: Send + Sync {
    async fn install(
        &self,
        connection_id: &ConnectionId,
        generation: NonZeroU64,
        secret: SecretBytes,
    ) -> Result<CredentialReferenceCommitment, CredentialStoreError>;
    async fn lease_secret(
        &self,
        binding: &ConnectionBinding,
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

The existing trait, `SecretBytes`, `CredentialReferenceCommitment`,
`StoredSecretLease`, and `ConnectionBinding` remain normative. Implementation
MAY add a closed `kind`/readiness projection without changing the store's
authority. A lease is requested only by the gateway after verification,
policy, one-use claim, capacity reservation, connection reload, and
qualification check. The store receives no URL, method, body, header name,
recipe, proof, provider name, or authority to select another connection.

### 5.2 Maintained adapters

This release has exactly two adapter classes:

- `local-file-v1`: the existing `PersistentCredentialStore`, development only;
  it preserves the current local demo and
  test journey. `--production` MUST refuse it with
  `gateway.credential.production-plaintext-refused`.
- `aws-secrets-manager-v1`: the maintained production reference adapter. It
  implements the existing store trait, uses workload identity, derives an
  internal caller-unresolvable object name from the deployment namespace,
  connection ID and credential generation, reads an exact immutable version,
  applies strict response and secret-size limits, disables client retries
  beyond the gateway's lease deadline, and never writes material or its
  external location to disk or the shared connection store.

Adding Vault, GCP Secret Manager, Azure Key Vault, or another system requires
an adapter-specific conformance entry and threat-model amendment, not a new
gateway recipe feature. An executable plugin or callback adapter is forbidden.

### 5.3 Lease order and containment

The production order is fixed:

1. decode and verify the exact action;
2. evaluate bounded policy and approvals;
3. atomically claim the logical operation and reserve limits;
4. reload the connection and confirm enabled state, recipe digest,
   qualification state, credential generation, and reference commitment;
5. acquire transport capacity;
6. lease the exact secret with a bounded deadline;
7. compare the material commitment in constant time;
8. run declared credential guards and build the request;
9. inject the connection's credential header and enter transport;
10. zeroize the lease immediately after the final request bytes are handed to
    the pinned transport; and
11. record response, observation, or `unknown` under the existing lifecycle.

The gateway MUST NOT lease before a durable claim. It MUST NOT retry with an
unpinned external version, another generation, cached material, an environment
variable, or the local file. Provider-secret material MUST be redacted by
construction: secret types expose no material through display or debug and
implement no serialization, equality output, or binding projection.

### 5.4 Rotation and multi-host behavior

Rotation is two-phase and operator-owned:

1. `connection rotate prepare` accepts new bounded `SecretBytes` only through
   the authenticated operator channel (no argument, environment variable, or
   application API), writes a new immutable external version through
   `ConnectionCredentialStore::replace`, and runs the declared credential
   checks without enabling it;
2. the adapter returns the existing caller-unresolvable
   `CredentialReferenceCommitment`, never an external secret location;
3. `connection rotate commit` atomically replaces the credential generation
   and reference commitment and increments the connection generation in the
   shared store; and
4. every gateway process observes the new generation before its next lease.

There is no automatic fallback. Rollback is another explicit `replace` with
operator-supplied secret bytes; the connection never names an external
location. Revoking the old generation before all in-flight leases finish is an
operator error and MUST leave ambiguous attempts `unknown`, never silently
resubmit them. Two gateway instances racing across a rotation MUST
either use the complete old generation or the complete new generation.

**Rotation between reload and lease.** A `rotate commit` can land after step 4
of §5.3 (reload) and before step 6 (lease). The lease names the generation and
reference commitment loaded at step 4. If the store no longer holds that exact
generation, or the material commitment differs at step 7, the lease fails
before any request byte exists. The attempt is recorded `not-entered` with
`gateway.credential.unavailable`; no provider entry occurred, so the outcome is
never `unknown`. The logical-operation claim keeps that recorded state under
the existing lifecycle. A later submission for a new logical operation uses the
new generation; the gateway never retries the same attempt with it.

## 6. Maintained signing custody

AP-SPEC-038's existing `auths-custody` boundary remains the only signing-key
boundary. This spec finishes product integration rather than defining another
signer:

- the shipped gateway MUST construct its observer through
  `GatewayObserver::from_custody` (or its current typed successor);
- `aws-kms-p256-v1` is the maintained production reference path;
- PKCS#11 remains supported only when its AP-SPEC-038 conformance gate is met;
- software seeds and files remain development-only and are refused by
  `doctor --production`; and
- outcomes state the signing custody kind without exposing key-manager
  resource names.

Signing custody and provider-secret custody MUST have different types,
configuration sections, errors, metrics, and permissions. A workload identity
allowed to read provider secrets SHOULD NOT be allowed to sign observations;
the reference deployment demonstrates separate identities.

## 7. Recipe-scoped provider qualification

### 7.1 Unit and state

Qualification belongs to this tuple:

```text
(recipe family ID,
 compiled recipe digest,
 profile-lock digest,
 provider-contract ID,
 gateway semantic-closure digest,
 target,
 store kind and schema,
 credential-store kind,
 signing-custody kind)
```

It does not belong to “Stripe,” an origin, a tool name, a source recipe, or a
developer account. Changing any tuple member yields `stale` until a protected
run issues a new attestation. `revoked` always dominates `qualified`.

The closed state transitions are:

```text
unqualified -> candidate -> qualified -> stale
                         \-> revoked
qualified ---------------> revoked
stale ------new evidence-> qualified
```

Only the release verifier derives state. A recipe manifest, connection, SDK,
environment variable, or operator flag MUST NOT set it.

### 7.2 Contract ID and provider semantics

`ProviderContractId` is the domain-separated digest of bounded inputs:

- provider and API release identifiers as opaque strings;
- the exact OpenAPI slice when one exists, including all resolved members;
- the recipe's manually reviewed assumptions not expressible by OpenAPI;
- the provider qualification environment class;
- the corpus manifest and pure oracle version; and
- the declared observation, recovery, idempotency, and retention assumptions.

Qualification says only that the named tests held against this contract. It
MUST describe provider-specific conclusions as evidence, for example “the
declared idempotency key suppressed the corpus's duplicate request during the
protected run,” never as a new generic gateway guarantee. The gateway treats
the contract ID as an opaque digest.

### 7.3 Required recipe ADR

Before a recipe family can become `candidate`, a provider-specific ADR MUST:

1. name `RecipeFamilyId` and the digest family;
2. define the pure request/evidence oracle and explain why it is test-only;
3. name every provider assumption and the evidence that tests it;
4. define the supported contract and environment classes;
5. define expiry, revocation triggers, and requalification cadence;
6. publish the hostile and live corpus; and
7. state the claims that remain provider-owned.

This fulfils ADR 0013's qualification rule without inserting the oracle into
the runtime gateway.

### 7.4 Qualification record

The canonical, bounded `auths.recipe-qualification/1` record contains:

- all tuple members from §7.1;
- qualification ID and validity window, no longer than 90 days;
- repository, immutable commit, protected workflow and environment IDs;
- source-closure and generated-artifact digests;
- installed-package digests for gateway and exercised SDK clients;
- exact recipe ADR and corpus-manifest digests;
- conformance, differential, hostile, live, recovery, rotation, restart,
  multi-instance, redaction, and installed-consumer evidence member digests;
- per-member result and bounded counters, including unauthorized provider
  entries, which MUST be zero;
- sanitized provider resource IDs sufficient for a human reviewer to inspect
  disposable effects without exposing credentials or customer data;
- custody and store descriptors; and
- residual assumptions and excluded claims.

The detached `auths.recipe-qualification-attestation/1` signs the canonical
record with a protected release key.

**Qualification signer custody (normative).** The release key is a signing key,
so it lives behind `auths-custody` external signing custody (§6), under a
workload identity used for nothing else: it MUST NOT be the observer identity,
the provider-secret identity, or a repository or root identity. It is created
in the reviewed root ceremony that AP-SPEC-038 §9.3 requires, recorded in that
ceremony's evidence, and listed by key identifier in the release verifier's
trust. Rotating or revoking the signer is itself a signed revocation-list entry;
`revoked` signers invalidate every attestation they issued (§7.1). Pull-request jobs may produce unsigned
proposals but MUST NOT access that key or update the trusted release index.

### 7.5 Required evidence wall

A protected run MUST reject qualification unless all of these pass on the
exact release candidate:

1. source and generated artifacts are clean and the compiled recipe digest
   rederives;
2. recipe compiler/interpreter vectors and closed-enum hostile cases pass;
3. the pure oracle and gateway agree on every accepted and rejected corpus
   member;
4. an application process with no credential cannot read secret material;
5. forge/alter, proof replay, fresh-challenge replay of the same logical
   operation, direct-provider attempt, two-instance race, restart, crash and
   ambiguous-response cases produce zero unauthorized provider entries;
6. credential-store kind, generation, reference-commitment, or pinned external
   version drift fails before provider entry;
7. secret and observer rotations preserve generation atomicity;
8. declared provider guards, version pin, account binding, denied reads,
   ceilings, budgets, idempotency, response locator, echo and observation are
   exercised when present;
9. successful live actions are confirmed by the declared fresh read-back, not
   merely by an HTTP response;
10. response loss and delayed visibility converge only under the recipe's
    declared recovery capability, otherwise remain `unknown`;
11. logs, traces, metrics, support bundles and evidence artifacts pass secret
    and provider-data scans; and
12. an installed Python or TypeScript consumer completes the documented
    journey without importing repository source or receiving a provider token.

A missing capability is `not-applicable`, with a reason fixed by the ADR; it
is never silently skipped. Infrastructure failure produces no candidate.

### 7.6 First qualification targets

The machinery is not accepted using mocks alone. Its release gate requires two
recipe families against two live providers:

- the Stripe refund journey, including a genuinely distinct connected account
  when account-scope support is part of the qualified tuple; and
- one independently authored simple write recipe from the field-lab journey
  (Airtable or Todoist), proving that qualification does not depend on a
  first-party provider module.

Each requires its own ADR and protected evidence. The two recipes share the
qualification mechanism, not provider semantics. Until both attestations
verify, the release metadata MUST say `stable_launch_ready: false`.

## 8. Runtime qualification gate

At startup and before every lease, the gateway checks the stored connection
against the verified release index. A production connection with policy
`required` is enabled only when:

- an attestation exists and is trusted, current, and not revoked;
- every §7.1 tuple member equals the running deployment and connection;
- the recipe digest and profile lock rederive;
- the clock and revocation data are fresh under the bounds below; and
- custody and store readiness match the qualified target.

Failure disables that recipe before secret lease. It does not stop pure proof
verification or unrelated qualified recipes. `qualification-policy optional`
is a development-only setting and `--production` refuses it. There is no
`--force`, grace period after expiry, network fetch of an unknown attestation,
or operator override.

The release index and revocation list are signed, bounded local inputs updated
through the operator plane. Runtime readiness performs no provider call and no
qualification run.

**Freshness bounds (normative).** The signed revocation list and release index
each carry `issued_at`. Under production policy:

- the revocation list MUST be no older than `max_revocation_age`, which
  defaults to 24 hours and MUST NOT be configured above 72 hours; an older list
  disables every `required` recipe with `gateway.qualification.revocation-stale`;
- local time MUST NOT be earlier than either input's `issued_at`, and MUST lie
  inside the attestation's validity window; a clock behind `issued_at`, or an
  operator-declared time-sync check that is not passing, disables `required`
  recipes with `gateway.qualification.clock-untrusted`;
- both bounds are checked at startup, before every lease, and when either input
  is replaced. A disabled recipe re-enables only after a fresh input passes
  verification; there is no grace period.

**Verified-index cache (normative).** The gateway verifies the release index,
revocation list, and attestation signatures once per input version and keeps
the verified result in memory, keyed by the inputs' digests. The per-lease
check is then a constant-time comparison of the connection's §7.1 tuple with
the cached entry, plus the freshness bounds. The cache is replaced atomically
when an input changes or a validity or freshness boundary passes; it is never
filled from an unverified input or a network fetch.

## 9. Recovery, upgrades, and operational polish

### 9.1 Truthful readiness and health

Readiness is the conjunction of typed checks for trust, store, recipe,
qualification, provider-secret custody, observer custody, connection
generation, clock, transport policy, and operator-plane isolation. Liveness
MUST NOT depend on provider, secret manager, KMS, or database reachability.
Readiness reasons use stable codes and contain no secrets.

### 9.2 Kill switch and degraded operation

Disable/revoke is a store-only operator mutation and MUST work when the
provider, secret manager, KMS, or qualification-index input is unavailable. A
disabled connection cannot start a lease. Existing attempts retain their
recorded state; disabling never converts `unknown` into failure or authorizes
automatic replay.

### 9.3 Backup, restore, and restart

The reference deployment documents and tests:

- PostgreSQL backup and point-in-time restore;
- reconciliation of `response-recorded` and `unknown` attempts after restart;
- refusal to serve when connection generation, recipe digest, credential
  generation, or qualification index is older than the restored store;
- observer and provider-secret rotation around a restore; and
- a multi-instance rolling upgrade in which old and new binaries cannot
  disagree about a recipe or connection generation.

Store loss invalidates replay and budget claims as AP-SPEC-063 already states;
this spec does not disguise restore as continuity proof.

### 9.4 Redacted support bundle

`auths-gateway support-bundle` emits a bounded archive containing versions,
digests, closed states, stable codes, metric summaries and attempt identifiers.
It MUST exclude proofs, grants, actions, request/response bodies, credentials,
external credential locations, key-manager resource names, provider
account/resource IDs, and raw headers. A deterministic hostile fixture plants
canary secrets in every excluded source and asserts that none appears in the
archive.

### 9.5 Deployment reference

One maintained reference deployment includes TLS, PostgreSQL, distinct
workload identities for provider-secret read and observation signing, network
egress restricted to the pinned provider and custody endpoints, operator-plane
separation, resource limits, graceful shutdown, migrations, backup/restore,
metrics, alerts and runbooks. It is a reference, not a universal platform
abstraction.

## 10. Stable codes

These new codes are exact public strings. Existing credential-store failures
keep their current public mapping: install and startup use
`gateway.install.credential-store-unavailable` and
`gateway.serve.credential-store-unavailable`; a missing sealed generation uses
`gateway.connection.credential-generation-missing`; and a failed post-claim
lease, including an external-version or commitment mismatch, records
`gateway.credential.unavailable`.

| Code | Meaning |
| --- | --- |
| `gateway.credential.adapter-unsupported` | closed credential-store kind is not supported |
| `gateway.credential.production-plaintext-refused` | development secret source used under production policy |
| `gateway.qualification.missing` | required attestation is absent |
| `gateway.qualification.expired` | validity window ended |
| `gateway.qualification.revoked` | qualification ID or signer is revoked |
| `gateway.qualification.digest-mismatch` | recipe, lock, closure, corpus, or contract digest differs |
| `gateway.qualification.target-mismatch` | binary, platform, store, schema, or custody target differs |
| `gateway.qualification.unavailable` | signed index, clock, or revocation input cannot be checked |
| `gateway.qualification.revocation-stale` | revocation list older than `max_revocation_age` |
| `gateway.qualification.clock-untrusted` | local time is behind a signed input or the declared time-sync check is failing |
| `gateway.readiness.connection-disabled` | operator has not enabled this connection generation |

Errors MUST identify which typed precondition failed without echoing its raw
value. Unknown error codes reject in Python and TypeScript closed unions.

## 11. Fixtures and tests before implementation

Each epic starts with canonical fixtures and a failing test. Fixture roots are
owned by their product model, not copied into bindings.

Required hostile fixtures include:

- action or recipe attempts to choose a credential generation, external secret
  location, injection header or credential-store adapter;
- mutable aliases (`latest`, stages), reference traversal, Unicode confusion,
  oversize secrets, extra fields, unknown enum members and non-canonical data;
- commitment mismatch, adapter timeout, partial response, expired lease,
  redaction canaries and debug/serialization attempts;
- rotation races across two gateway instances and crash at every stage;
- forged, expired, wrong-target, wrong-contract, wrong-custody, wrong-store,
  wrong-recipe and revoked qualification attestations;
- a source recipe that self-declares qualification;
- provider contract drift with unchanged recipe bytes;
- successful HTTP response without read-back, which remains
  `response-recorded`, never qualified success; and
- support-bundle and telemetry scans for all planted secrets and provider data.

The production custody conformance suite runs against a bounded AWS emulator in
ordinary CI and an actual protected AWS account in the release workflow. The
qualification live corpus runs only under protected-environment controls with
disposable provider resources. Testkit adapters MUST NOT occur in production
feature graphs or binaries.

## 12. Public APIs and compatibility

Application APIs do not gain custody or qualification options. Python and
TypeScript clients may read closed diagnostic projections:

```python
status = gateway.connection_status("stripe-refunds")
assert status.credential_material is None
assert status.qualification.state is QualificationState.QUALIFIED
```

```ts
const status = await gateway.connectionStatus("stripe-refunds");
if (status.qualification.state !== QualificationState.Qualified) return;
```

They cannot install credentials, import attestations, weaken policy, or mark a
recipe qualified. Operator mutations remain on the separately authenticated
operator plane and CLI. Public-surface, capability, semantic-freeze,
installed-typing, package, and customer-journey inventories update in the same
commit as each public type.

Because the project is prelaunch, obsolete plaintext production configuration
is removed rather than supported through dual modes. Development demos retain
the explicit `local-file-v1` path and label it development-only.

## 13. Documentation and claims

The implementation updates, together:

- the self-hosted and gateway claim ledgers;
- the production deployment and threat model;
- Python and TypeScript gateway documentation;
- recipe authoring documentation, including the distinction between usable,
  candidate and qualified;
- runbooks for install, enable, rotate, revoke, expire, restore and reconcile;
- the ADR for each first qualification target; and
- status lines in AP-SPEC-038, 044, 053, 056 and 063 where their open work is
  actually closed.

No README, CLI, dashboard, package metadata, example or release note may say
“provider-qualified,” “production-ready,” “non-bypassable,” or equivalent
until the relevant signed evidence and done gate exist. The required wording
for an unqualified custom recipe is: “Auths verifies the exact action and
isolates the configured credential; the recipe mapping and provider behavior
are not qualified by Auths.”

## 14. Epics and done gates

Implementation is five ordered epics. Each epic is one reviewable commit or
pull request unless generated artifacts must accompany its public surface.
Fixture and hostile cases precede implementation inside every epic.

### Epic 1 — Freeze types, threats, and evidence contracts

Tasks:

1. add the abstraction case comparing Stripe, Airtable, Todoist and one
   header-API-key provider for secret custody and qualification;
2. add the §4 Rust types, canonical schemas, bounds, stable-code fixtures and
   hostile vectors;
3. amend the threat model for workload identity, secret-manager compromise,
   qualification signer compromise, contract drift and runtime/qualification
   separation; and
4. write the AWS Secrets Manager and qualification protected-run plans without
   implementation credentials.

Done when all types have named invariants and owners, every ambiguity has a
hostile vector, architecture policy proves no core/provider dependency was
added, and the fixtures fail for the intended missing implementation.

### Epic 2 — Ship production custody and rotation

Tasks:

1. preserve and harden the sealed `ConnectionCredentialStore`, add its closed
   kind/readiness projection, and retain the existing development adapter;
2. implement `aws-secrets-manager-v1` with workload identity and exact version
   pinning;
3. wire the existing external signing-custody path into the shipped gateway;
4. implement prepare/commit rotation and multi-host generation atomicity; and
5. add redaction, feature-graph, package and two-instance conformance tests.

Done when the app and shared store contain no provider secret, the gateway can
complete a real disposable write using the maintained adapter, production mode
refuses every plaintext/testkit path, observer signing uses maintained external
custody, and rotation/crash/race tests show zero unauthorized provider entries.

### Epic 3 — Build reusable recipe qualification

Tasks:

1. implement canonical qualification records, proposals, attestations, trust,
   revocation, index and verifier;
2. implement protected-run evidence assembly and semantic closure;
3. implement oracle differential, hostile, recovery, live, installed-consumer
   and redaction stages; and
4. add runtime matching and per-recipe fail-closed readiness.

Done when every §7.5 row has a bounded evidence member, forged or drifted
records fail before credential lease, pull requests cannot sign/import
qualification, and the runtime cannot distinguish provider names or execute an
oracle.

### Epic 4 — Finish operator and deployment polish

Tasks:

1. implement truthful doctor/readiness and the stable codes;
2. implement the kill switch and redacted support bundle;
3. publish and exercise the production deployment, backup/restore,
   rotation, expiry, revocation, rolling-upgrade and unknown-recovery runbooks;
4. update the binding projections, inventories and claims; and
5. run an unfamiliar operator trial from packaged artifacts.

Done when a clean operator can deploy, diagnose, rotate, disable, restore and
reconcile without source checkout or secret exposure; every diagnostic phrase
corresponds to an actual typed check; and the trial's defects are fixed and
rerun. The implementer MUST NOT simulate the unfamiliar-operator trial.

### Epic 5 — Qualify two recipes and close the launch gate

Tasks:

1. land the provider-specific ADR and protected corpus for Stripe refund;
2. qualify it with a distinct connected account for account-scope claims;
3. land an independent ADR/corpus for Airtable or Todoist and qualify it
   through the same unmodified runtime machinery;
4. exercise packaged Python and TypeScript consumers; and
5. update the signed release index and launch projection.

Done when two current attestations against two live providers verify for the
release candidate, their evidence pages and sanitized provider resources are
human-reviewable, the full hosted matrix is green, independent review confirms
the core/provider boundary, and `stable_launch_ready` derives to `true` rather
than being edited.

**Derivation of `stable_launch_ready` (normative).** `cargo xtask release-check`
computes it; no file stores a hand-written value. It is `true` exactly when, for
the release candidate:

1. the signed release index holds at least two attestations that verify under
   §8, including freshness;
2. they cover at least two distinct `RecipeFamilyId`s, two distinct
   `ProviderContractId`s, and two distinct provider identifiers;
3. none is `stale` or `revoked`, and each records zero unauthorized provider
   entries;
4. each matches the release candidate's gateway semantic-closure digest and
   target; and
5. a signed `independent-boundary-review` record for the candidate's closure
   digest is present, signed by a reviewer key distinct from the qualification
   signer.

Any other state derives `false`.

## 15. Sequencing relative to the north star

This spec is the production launch path. It does not replace the evidence the
north star still lacks (`docs/PROGRAM_BOARD.md` §0): one run against a real
provider and one unfamiliar-developer trial of the existing journey. Those come
first, because they decide which operator polish matters.

1. Before epic 1: a Stripe test-mode run of the north-star journey with the
   owner's own test key, and one unfamiliar-developer trial.
2. Epics 1 and 2 (types, threats, maintained custody and rotation): any real
   deployment needs them.
3. Epic 3 (qualification), then epics 4 and 5: when a design partner or the
   trial shows operators need qualified recipes.

Epics 2, 3, and 5 need new credentials (an AWS account with workload identity,
a protected qualification environment, and disposable provider accounts). That
is an owner decision under the program board's credential rule and is not
granted by this spec.

## 16. Non-goals

- A general secret-management abstraction spanning signing and provider
  credentials.
- Provider-specific runtime modules or built-in recipes for every provider.
- Executable recipe plugins, callbacks, arbitrary HTTP, runtime URL/method/body
  selection, or a general expression language.
- Automatic trust in community recipes or self-attested qualification.
- Provider reads, browser credentials, OAuth refresh-token orchestration,
  cookie/basic/query credentials, or user-interactive login.
- Provider settlement, business truth, legal/compliance certification, or
  proof of humanity.
- A universal deployment platform, multi-cloud release in the first launch,
  or qualification of an entire provider.
- Preventing bypass by software that still holds its own provider credential.

## 17. Rejected alternatives

1. **Put provider semantics in Auths core.** This makes the verifier depend on
   changing external APIs and destroys the boundary this spec exists to close.
2. **Call every compiled recipe qualified.** Compilation proves shape and
   bounds, not mapping correctness or live provider behavior.
3. **Reuse signing custody for static secrets.** Signing can be non-exportable;
   HTTP credential injection cannot. One interface would make a false custody
   claim and broaden signer permissions.
4. **Let recipes name secret locations.** An untrusted author could redirect a
   connection to another secret. Only the selected credential store owns its
   external location; the operator-owned connection binds only its generation
   and caller-unresolvable commitment.
5. **Embed the pure oracle in the gateway.** That is provider code in the
   runtime path. The oracle remains qualification-only.
6. **Use `.env` in production because the app no longer sees it.** Process
   environment and plaintext files lack version pinning, workload-identity
   policy, auditable rotation and a credible multi-host custody boundary.
7. **Make qualification permanent.** Provider contracts drift. Qualification
   expires and exact input drift makes it stale.
8. **Wait for every secret manager and provider.** One maintained production
   custody adapter plus a generic recipe/qualification contract is the narrow
   launch path; further adapters are bounded additions.
