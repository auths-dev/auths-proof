# AP-SPEC-066: Production gateway polish and recipe qualification

- **Status:** Draft. Epic 1 (types, threats, and evidence contracts) is
  implemented; §18 records its status and readings. Epic 2 (production
  custody and rotation) is implemented and has passed live against the
  secret store and against a provider's test mode; §19 records it. Epic 3
  (reusable recipe qualification) is implemented in code and tests: the
  release verifier, issuance tooling, the evidence wall, and the runtime
  gate exist; §20 records it. No protected run has been held, no trust root
  or signer exists, and no recipe is qualified.
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
  adapter; protected software qualification signing with an offline trust
  root; and a finite launch gate without adding provider-specific behavior to
  the Auths core or gateway interpreter. KMS/PKCS#11 signing custody remains
  post-launch hardening under issue #190.
- **Scope:** product and release layers only: `product/runtime/auths-gateway`,
  `product/runtime/auths-connections`, `product/stores/auths-stores`, the
  existing credential-store integration, protected release qualification,
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
2. qualification needs a bounded release-signing trust model that does not
   pretend software-held launch keys have KMS or HSM custody;
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
credential-store mode, store mode, and named provider contract. The attestation
also carries a verified signer certificate, but signer-custody changes do not
change the provider-behavior tuple. Drift or credential-custody failure
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
qualification       protected-software-release-key-v1, current
observer             not configured (signed outcomes unavailable)
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
                                  [optional observer]         read-back evidence

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
| `ConnectionBinding` | existing `auths-connections` model | `sealed-generation-binding`: connection ID, connection generation, explicit credential generation and reference commitment are loaded from durable operator state as one unit; a store reads exactly the named credential generation and never searches for one |
| `CredentialBinding` | `auths-connections` model | `store-view`: the only lease argument a credential store receives: connection ID, both generations and the reference commitment, produced only from a sealed `ConnectionBinding`; it carries no provider kind, alias, contract, descriptor or account |
| `CredentialStoreKind` | `auths-connections` credential module | `closed-store-kind`: exactly the maintained development or production credential-store kinds; unknown values reject |
| `CredentialRetirementDelay` | gateway operator model | `outlives-entered-transport`: a fixed 20 seconds, exceeding the gateway's 15-second maximum transport duration; changing either value requires one invariant test and qualification drift |
| `QualificationTrustRoot` | release policy | `offline-trust-root`: pinned identifier and public key whose private key is absent from pull-request and qualification runners |
| `QualificationSignerCertificate` | release policy | `root-authorized-signer`: bounded signer identity, key, kind and validity window signed by the qualification trust root |
| `QualificationSignerKind` | release policy | `honest-custody-label`: launch permits only `protected-software-release-key-v1`; it makes no hardware or non-exportability claim |
| `QualificationRevocationList` | release policy | `root-signed-freshness`: root-signed signer and qualification revocations with exact `issued_at` and `next_update` |
| `ClockTrustState` | gateway operator API | `closed-clock-readiness`: exactly `trusted` or `untrusted`, supplied only by a maintained deployment adapter |
| `RecipeFamilyId` | qualification model | `declared-family`: stable identifier named by an accepted ADR, not inferred from provider text |
| `ProviderContractId` | qualification model | `pinned-contract`: digest of the bounded contract inputs used by the qualification corpus |
| `QualificationTarget` | qualification model | `exact-target`: operating system, architecture, gateway package/build, store kind and credential-store kind are exact |
| `RecipeQualificationState` | qualification model | `closed-derived-state`: exactly `unqualified`, `candidate`, `qualified`, `stale`, or `revoked`; never supplied by a recipe |
| `RecipeQualificationRecord` | qualification model | `evidence-closed`: every accepted claim is backed by named evidence members and their digests |
| `RecipeQualificationAttestation` | release policy | `trusted-expiring-signature`: canonical record, trusted signer, validity window, revocation and target all verify |
| `ProductionReadiness` | gateway operator API | `fail-closed-conjunction`: ready only when every required typed precondition is ready |

Newtype constructors MUST enforce size, grammar, canonicalization, and closed
enumerations. Raw strings MUST NOT cross connection, custody, qualification,
or readiness APIs where one of these types applies.

The owners are these packages: the credential module and model are
`auths-connections`; the gateway operator model and API are the `readiness`
module of `auths-gateway`; the qualification model and release policy are the
`model` and `release` modules of `auths-recipe-qualification`. Types that
exist only as members of a type above (the qualification tuple, the provider
contract's inputs, evidence members and capabilities, the release index, the
readiness preconditions) share that type's owner and invariant.

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
        binding: &CredentialBinding,
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
authority.

**Explicit credential generation (owner decision, 2026-10-05).** A connection
record has two generations: `generation` advances on every change, and
`credential_generation` is the generation at which the current secret was
installed or rotated in. The sealed `ConnectionBinding` carries both, and
`lease_secret` reads the secret stored at exactly the binding's credential
generation. A store MUST NOT resolve "the newest generation not after" a
connection generation: a secret manager that reads one exact immutable version
cannot do so without listing, and a search is a way to be handed another
generation. The in-repository stores additionally refuse a binding whose
credential generation is not the newest one stored at or before its
connection generation, so a superseded credential never serves a later
generation.

A store does not receive the `ConnectionBinding` itself, which also carries
the provider kind and descriptor for the gateway's own use. It receives the
binding's `CredentialBinding` view, so `identity-and-generation-only` holds
by type and not by convention. A binding for an unresolved older operation is
rebuilt from what that operation recorded; for any generation at or after the
record's credential generation the record refuses a credential generation or
commitment other than its own, so a superseded credential cannot be bound to
a generation the current credential serves. A lease is requested only by the gateway after verification,
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
4. every newly admitted attempt reloads the shared record before lease; an
   attempt already admitted under the old generation follows the retirement
   rule below.

There is no automatic fallback. Rollback is another explicit `replace` with
operator-supplied secret bytes; the connection never names an external
location. Normal rotation retains the old credential generation for at least
20 seconds after the shared commit, which exceeds the gateway's fixed 15-second
transport bound. The admin response's local in-flight count is diagnostic; it
is not treated as a global drain across hosts. Only after the fixed retirement
time may a best-effort collector revoke the old external version. Two gateway
instances racing across a rotation MUST either use the complete old generation
or the complete new generation.

**Rotation between reload and lease.** A `rotate commit` can land after step 4
of §5.3 (reload) and before step 6 (lease). The lease names the generation and
reference commitment loaded at step 4. Because `replace` retains the old
generation, the admitted attempt may lease and enter with that exact old
generation. A later logical operation reloads and uses the new generation; the
gateway never changes generations within one attempt.

**Emergency cutover.** When the old credential may be compromised, the safe
flow is `disable -> wait 20 seconds -> rotate -> revoke old -> enable`.
`disable` prevents every attempt that has not passed its final shared-record
reload. The fixed wait covers entries already past that reload on every host;
the local `drain` result remains useful evidence but is not the safety premise.
If an operator revokes the old generation before the wait completes, an attempt
that has not entered fails before any request byte exists and is recorded
`not-entered` with `gateway.credential.unavailable`; it is never `unknown` and
is never retried with the new generation. An attempt already handed to
transport follows the existing response/`unknown` lifecycle.

## 6. Signing custody is post-launch hardening

AP-SPEC-038's existing `auths-custody` boundary remains the only boundary for
Auths root and observer signing keys. The owner has decided that maintained KMS
and PKCS#11 clients are **not a launch requirement**; issue #190 tracks them.
This spec therefore does not require the shipped gateway to construct a
production observer through external custody, and absence of an observer key
does not make production readiness false.

Until #190 lands:

- a production gateway without an externally held observer key emits no signed
  observer outcome and says so in doctor, audit, package and claim metadata;
- qualification MAY rely on provider read-back and protected-run evidence, but
  MUST NOT relabel an unsigned gateway outcome as observer-signed;
- Auths root, observer and Git-signing software keys retain the exact limits
  already recorded by AP-SPEC-038 and the program board; and
- the qualification release signer uses §7.4's narrower protected software
  mechanism, not `auths-custody`, and claims neither hardware protection nor
  non-exportability.

After launch, `aws-kms-p256-v1` and the qualified PKCS#11 path can replace
software signing storage behind the existing signing interfaces without
changing recipe, qualification-record or application APIs. Signing custody and
provider-secret custody remain different types, configuration, errors,
permissions and claims.

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
 credential-store kind)
```

It does not belong to “Stripe,” an origin, a tool name, a source recipe, a
developer account, or the qualification signer's custody kind. Changing any
tuple member yields `stale` until a protected run issues a new attestation.
Signer rotation re-signs a still-current record only after re-verifying its
complete evidence closure; it does not rerun provider effects merely because
key storage changed. `revoked` always dominates `qualified`.

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
record with a protected release signer.

**Qualification trust and signer (normative).** Qualification has its own
release trust hierarchy; it does not reuse an Auths grant root or observer:

1. The offline `QualificationTrustRoot` signs bounded, canonical
   `QualificationSignerCertificate` records and
   `QualificationRevocationList` records. Its public key and identifier are
   pinned in the release verifier. Its private key is absent from repository,
   pull-request and qualification-runner environments.
2. A `QualificationSignerCertificate` binds one release-signing public key,
   `protected-software-release-key-v1`, its validity window and permitted
   artifact kinds. The private release-signing key is injected only after
   manual approval of the protected release environment, is used for nothing
   else, and is removed when the run ends. This is software custody: the
   product makes no hardware, non-exportability or KMS claim.
3. The release signer signs qualification attestations and the release index.
   It MUST NOT sign its own certificate, revocation, or trust-root rotation.
4. The offline trust root signs signer and qualification revocations. A
   revoked signer invalidates every attestation it issued, regardless of
   issuance time. Root rotation requires a separately reviewed release that
   pins the successor root; it is not a runtime network operation.

The canonical data is closed:

- `QualificationTrustRoot` contains schema, root identifier, signature
  descriptor and public key;
- `QualificationSignerCertificate` contains schema, signer identifier,
  `QualificationSignerKind`, signature descriptor and public key, the exact
  time fields of §8, permitted artifact kinds, root identifier, and root
  signature;
- `QualificationRevocationList` contains schema, monotonically increasing
  sequence, the exact time fields of §8, sorted unique signer identifiers and
  qualification identifiers, root identifier, and root signature; and
- the release index contains schema, `issued_at`, sorted unique qualification
  entries, signer identifier, and signer signature.

Unknown fields, algorithms, signer kinds or artifact kinds reject. Every list
has an explicit parser bound fixed in Epic 1's schema; duplicate or noncanonical
members reject rather than deduplicate.

The qualification signer identity MUST differ from the provider-secret
workload identity, observer, application and Auths grant-root identities.
Pull-request jobs may produce unsigned proposals but MUST NOT access either
private qualification key or update the trusted release index.

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
7. provider-secret and qualification-signer rotations preserve their typed
   generation and trust transitions; observer rotation is required only when
   the qualified target declares an observer;
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
- the clock, signer certificate, release index and revocation data are valid
  under the signed bounds below; and
- credential-store and lifecycle-store readiness match the qualified target.

Failure disables that recipe before secret lease. It does not stop pure proof
verification or unrelated qualified recipes. `qualification-policy optional`
is a development-only setting and `--production` refuses it. There is no
`--force`, grace period after expiry, network fetch of an unknown attestation,
or operator override.

The signer certificate, release index and revocation list are signed, bounded
local inputs updated through the operator plane. Runtime readiness performs no
provider call, network trust fetch or qualification run.

**Freshness bounds (normative).** The artifacts carry these exact signed time
fields and structural limits:

- a signer certificate has `issued_at`, `not_before`, and `not_after`, with a
  validity window of at most 365 days;
- a revocation list has `issued_at` and `next_update`, where `next_update` is
  after `issued_at` and no more than 72 hours later;
- a release index has `issued_at`; it has no independent freshness claim and
  is usable only while its signer certificate, revocation list and referenced
  attestations are current; and
- an attestation has `issued_at`, `not_before`, and `not_after`, with the §7.4
  validity window of at most 90 days.

These signed fields and hard parser bounds, not operator-configurable age
limits, define freshness. Under production policy:

- local time MUST be at or after every applicable `issued_at`, at or before
  every applicable `next_update`/`not_after`, and inside the signer's and
  attestation's validity windows;
- a revocation list past `next_update` disables every `required` recipe with
  `gateway.qualification.revocation-stale`;
- an expired signer certificate or attestation uses
  `gateway.qualification.expired`; an unusable index uses
  `gateway.qualification.unavailable`; no grace period or operator widening
  exists; and
- a closed `ClockTrustState::Untrusted` from the maintained deployment clock
  adapter, or a local clock behind a signed `issued_at`, disables every
  `required` recipe with `gateway.qualification.clock-untrusted`.

The deployment adapter may use the platform's time-synchronization service to
derive `ClockTrustState`; configuration cannot name an executable, callback or
network time source. A recipe, application and SDK cannot supply clock trust.
Only a recipe disabled for stale inputs may re-enable when replacement inputs
verify; a revoked signer or qualification remains revoked.

**Verified-index cache (normative).** The gateway verifies the signer
certificate, release index, revocation list and attestation signatures once per
input digest and keeps the immutable verified result in memory. Before every
lease it applies bounded typed equality between the connection's §7.1 tuple
and the cached entry, then evaluates the signed time bounds and revocation
state. These values are public metadata, so constant-time comparison is not a
requirement. An input change atomically replaces the verified cache; time
boundaries need no cache mutation because per-lease and readiness evaluation
derive the current state from trusted time. The cache is never filled from an
unverified input or network fetch.

## 9. Recovery, upgrades, and operational polish

### 9.1 Truthful readiness and health

Readiness is the conjunction of typed checks for trust, store, recipe,
qualification, provider-secret custody, connection generation, clock,
transport policy, and operator-plane isolation. Observer custody participates
only when the deployment configures signed observer outcomes; its absence is
otherwise reported and does not make readiness false. Liveness MUST NOT depend
on provider, secret manager, KMS, or database reachability. Readiness reasons
use stable codes and contain no secrets.

### 9.2 Kill switch and degraded operation

Disable/revoke is a store-only operator mutation and MUST work when the
provider, secret manager or qualification-index input is unavailable. A
disabled connection cannot start a lease. Existing attempts retain their
recorded state; disabling never converts `unknown` into failure or authorizes
automatic replay.

### 9.3 Backup, restore, and restart

The reference deployment documents and tests:

- PostgreSQL backup and point-in-time restore;
- reconciliation of `response-recorded` and `unknown` attempts after restart;
- refusal to serve when connection generation, recipe digest, credential
  generation, or qualification index is older than the restored store;
- provider-secret and qualification-input rotation around a restore, plus
  observer rotation when one is configured; and
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

One maintained reference deployment includes TLS, PostgreSQL, workload
identity for provider-secret access, network egress restricted to the pinned
provider and secret-manager endpoints, operator-plane separation, resource
limits, graceful shutdown, migrations, backup/restore, metrics, alerts and
runbooks. When an observer is configured, it uses a distinct signing identity
and the deployment adds only that custody endpoint. The qualification signer
exists in the protected release environment, never in the gateway deployment.
This is a reference, not a universal platform abstraction.

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
| `gateway.qualification.target-mismatch` | binary, platform, store, schema, or credential-store target differs |
| `gateway.qualification.unavailable` | signed index, clock, or revocation input cannot be checked |
| `gateway.qualification.revocation-stale` | root-signed revocation list is past its signed `next_update` |
| `gateway.qualification.clock-untrusted` | local time is behind a signed input or the closed deployment clock state is untrusted |
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
- forged, expired, wrong-target, wrong-contract, wrong-credential-store,
  wrong-signer-kind, wrong-store, wrong-recipe and revoked qualification
  attestations;
- a signer certificate or revocation list signed by the release signer rather
  than the offline root; future `issued_at`, elapsed `next_update`, untrusted
  clock state and attempted operator widening of a signed time bound;
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
   qualification trust-root or signer compromise, contract drift and
   runtime/qualification separation; and
4. write the AWS Secrets Manager and qualification protected-run plans without
   implementation credentials.

Done when all types have named invariants and owners, every ambiguity has a
hostile vector, architecture policy proves no core/provider dependency was
added, and the fixtures fail for the intended missing implementation.

Status: implemented; see §18.

### Epic 2 — Ship production custody and rotation

Tasks:

1. preserve and harden the sealed `ConnectionCredentialStore`, add its closed
   kind/readiness projection, and retain the existing development adapter;
2. implement `aws-secrets-manager-v1` with workload identity and exact version
   pinning;
3. implement prepare/commit rotation, retained generations, the explicit
   emergency cutover and multi-host generation atomicity;
4. make doctor and production readiness distinguish provider-secret custody
   from optional observer signing; and
5. add redaction, feature-graph, package and two-instance conformance tests.

Done when the app and shared store contain no provider secret, the gateway can
complete a real disposable write using the maintained adapter, production mode
refuses every plaintext/testkit provider-secret path, absence of a production
observer is reported without blocking readiness, and rotation/crash/race tests
show zero unauthorized provider entries.

### Epic 3 — Build reusable recipe qualification

Tasks:

1. implement the offline-root trust model, signer certificates, canonical
   qualification records, proposals, attestations, revocation, index and
   verifier;
2. implement protected-run evidence assembly and semantic closure;
3. implement oracle differential, hostile, recovery, live, installed-consumer,
   signer-rotation, freshness and redaction stages; and
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
   provider-secret rotation, qualification signer/root rotation, expiry,
   revocation, rolling-upgrade and unknown-recovery runbooks;
4. update the binding projections, inventories and claims; and
5. run an unfamiliar operator trial from packaged artifacts.

Done when a clean operator can deploy, diagnose, rotate, disable, restore and
reconcile without source checkout or secret exposure; every diagnostic phrase
corresponds to an actual typed check; and the trial's defects are fixed and
rerun. The implementer MUST NOT represent a simulated trial as an independent
human result. Owner clarification (2026-10-06): the agent's deliverable is a
labeled operator simulation from packaged artifacts; the owner handles real
users offline. The simulation must fix and rerun its defects and explicitly
report which production/live operations its inputs do not exercise. Human
adoption and production qualification claims still require their own evidence.

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
human-reviewable, the full hosted matrix is green, the separate human release
review confirms the core/provider boundary, and `stable_launch_ready` derives
to `true` rather than being edited.

**Derivation of `stable_launch_ready` (normative).** `cargo xtask release-check`
computes it; no file stores a hand-written value. It is `true` exactly when, for
the release candidate:

1. the signed release index holds at least two attestations that verify under
   §8, including freshness;
2. they cover at least two distinct `RecipeFamilyId`s, two distinct
   `ProviderContractId`s, and two distinct existing `ProviderKind` values;
3. none is `stale` or `revoked`, and each records zero unauthorized provider
   entries;
4. each matches the release candidate's gateway semantic-closure digest and
   target, including PostgreSQL and a production provider-secret
   `CredentialStoreKind`; and
5. the protected evidence for each records passing production readiness,
   rotation, restart, recovery and redaction gates.

Any other state derives `false`.

**Human release gate.** An owner or independent reviewer still reads the
public claims, provider-specific ADRs, sanitized live evidence and
core/provider dependency report before release. That judgment is recorded on
the program board and is not represented as a cryptographically proven or
machine-derived property. A second key alone would not prove an independent
person or organization.

## 15. Sequencing relative to the north star

This spec is the production launch path. It does not replace the evidence the
north star still lacks (`docs/PROGRAM_BOARD.md` §0): one run against a real
provider and one unfamiliar-developer trial of the existing journey. Those come
first, because they decide which operator polish matters.

1. Before epic 1: record a Stripe test-mode run of the north-star journey with
   the owner's own test key and complete one unfamiliar-developer trial.
2. Implement epics 1–5 in order. All five, including Epic 4's human trial and
   the human release gate, are required before launch. The
   `stable_launch_ready` value derives only the technical conditions in §14;
   it does not encode the human judgments. North-star evidence may change epic
   details but does not make qualification optional.
3. After launch, issue #190 may add maintained KMS/PKCS#11 custody for Auths
   root, observer, Git and qualification signing keys without changing the
   gateway recipe or application APIs.

Epics 2, 3, and 5 need new credentials (an AWS account with workload identity,
a protected qualification environment with software release-signing material,
and disposable provider accounts). That is an owner decision under the program
board's credential rule and is not granted by this spec. No KMS or PKCS#11
credential is required for launch.

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
- KMS/PKCS#11 custody for Auths signing keys as a launch prerequisite; issue
  #190 owns that post-launch hardening.
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
9. **Block launch on KMS-backed signing.** Provider-secret custody is required
   because it removes the application credential; hardware custody for Auths
   signing keys improves key protection but does not change the exact-action
   boundary. Launch uses an honestly labelled protected software release
   signer and makes no signed-observer claim when no external observer exists.

## 18. Epic 1 status and readings

Epic 1 is implemented. It adds types, schemas, bounds, fixtures, and
documents. It adds no production credential store, no signature verification,
no qualification state derived from inputs, no runtime gate, no stable code,
and no binding surface.

### 18.1 What exists

| Task | Artifact |
| --- | --- |
| 1 abstraction case | [case 0008](../research/domains/abstraction-cases/0008-provider-secret-custody-and-recipe-qualification.md) |
| 2 types | `auths-connections` (`CredentialStoreKind`, explicit credential generation in `ConnectionBinding`, the `CredentialBinding` store view); `auths-gateway` `readiness` (`CredentialRetirementDelay`, `ClockTrustState`, `ProductionReadiness`); `auths-recipe-qualification` (every qualification-model and release-policy type) |
| 2 schemas and bounds | seven canonical artifacts in `auths-recipe-qualification`, each with a schema identifier, a byte limit, and list and time bounds |
| 2 stable-code fixture | `bindings/fixtures/gateway/production-codes.json`: the 11 new codes of §10 and 5 existing codes the vectors expect |
| 2 hostile vectors | `bindings/fixtures/gateway/custody-hostile.json` (91 cases and 11 redaction canaries); `bindings/fixtures/qualification/schema-vectors.json` (79 structural cases, 8 contract drifts); `bindings/fixtures/qualification/verification-vectors.json` (57 cases) |
| 3 threat model | [threat model](../threat-model.md), "Production gateway: provider-secret custody and recipe qualification" |
| 4 plans | [custody plan](../plans/GATEWAY_AWS_SECRETS_MANAGER_CUSTODY_PLAN.md); [protected-run plan](../plans/RECIPE_QUALIFICATION_PROTECTED_RUN_PLAN.md) |

Done gate:

- **Named invariants and owners.** Each §4 type states its invariant on the
  type; §4 names the owning package.
- **A hostile vector for every ambiguity.** The gateway test
  `every_hostile_class_has_a_vector` requires a case for each of the 34
  classes §11 lists.
- **No core or provider dependency.** `architecture.toml` has two dependency
  boundaries: `auths-connections` reaches no workspace crate, and
  `auths-recipe-qualification` reaches only `auths-connections`.
- **Fixtures fail for the missing implementation.** Vectors that today's types
  decide are driven as tests. For the rest, two tests assert the shortfall.
  `production_codes_await_their_epics` (gateway) requires that no product
  crate defines a new code, a code under `gateway.qualification.` or
  `gateway.readiness.`, or the secret-name derivation, and that the gateway
  has no support bundle under any spelling.
  `verification_vectors_await_the_release_verifier` (qualification) requires
  that the crate has no signature dependency outside its tests and no
  function that verifies. Each fails when its implementing epic lands, in
  whichever crate it lands, and that epic replaces it with the conformance
  test that drives the vectors.

### 18.2 Owner decisions (2026-10-05)

1. The start gate of §15 step 1 is met: the owner states that the Stripe
   test-mode run and the unfamiliar-developer trial are done. This document
   does not hold their artifact links.
2. The sealed binding carries an explicit credential generation (§5.1).
3. Where the qualification and release-policy types live was delegated to the
   implementer; reading 1 is the choice taken.

### 18.3 Readings (PROVISIONAL)

Each was taken unattended as the narrower or fail-closed reading. The owner
may change any of them; the fixtures change with it.

1. **Package.** The qualification model and release policy are one new
   product crate, `auths-recipe-qualification`. It performs no I/O, depends on
   `auths-connections` only (for `CredentialStoreKind` and `ProviderKind`),
   and is what both the gateway and release tooling will use, so neither
   depends on the other.
2. **Encoding.** Every artifact is RFC 8785 canonical JSON, as the operator
   attestation is. A decoder checks the size limit, parses strictly (unknown
   members, unknown enumeration values, repeated members, and wrong types are
   refused), requires the input to equal its own canonical form, and then
   checks structural rules. A signature covers the schema identifier, a NUL
   byte, and the canonical statement.
3. **Signature suite.** The closed set has one member, `ed25519-v1`: a
   32-byte key and a 64-byte signature, base64url without padding.
4. **Identifiers.** `RecipeFamilyId`, signer identifiers, and root identifiers
   are `[a-z][a-z0-9-]{0,63}`. A qualification identifier is `qlf_` and 32
   lowercase hexadecimal characters. A digest is 64 lowercase hexadecimal
   characters. Opaque text is printable ASCII within its bound, so Unicode
   look-alikes are refused.
5. **Bounds.** Trust root 1 KiB; signer certificate 4 KiB; revocation list
   64 KiB with at most 64 signers and 1,024 qualifications; release index
   128 KiB with at most 256 entries; record 64 KiB; attestation 4 KiB;
   provider contract 16 KiB with at most 32 manual assumptions. A record lists
   1 to 8 installed packages, 1 to 32 provider resources, and at most 32
   residual assumptions and 32 excluded claims.
6. **Target.** Operating system (`linux`, `macos`), architecture (`x86_64`,
   `aarch64`), gateway package name, version and build digest, store kind
   (`postgresql-v1`, `shared-file-v1`) and schema, and credential-store kind.
7. **Record.** The record names the connection's existing `ProviderKind`
   outside the tuple, for the launch derivation of §14. It lists the ten
   evidence members of §7.4 in a fixed order; the only representable result is
   `passed`, each with at least one case and zero unauthorized provider
   entries. It lists twelve capabilities in a fixed order (credential guard,
   version pin, account binding, denied reads, ceiling, budget, idempotency,
   response locator, echo, observation, recovery, observer rotation), each
   `exercised`, or `not-applicable` with a reason. `live_effects` requires at
   least one entered write and a read-back for every one, and the observation
   capability must be `exercised`: a record cannot close for a recipe that
   declares no read-back, because nothing would confirm its live writes.
8. **Attestation.** The attestation signs the record's digest and carries its
   own issue time and window of at most 90 days, which must lie within the
   record's window. Re-signing after a signer rotation changes the
   attestation, not the record.
9. **Permitted artifact kinds.** Exactly `qualification-release-index` and
   `recipe-qualification-attestation`. A certificate that names a certificate
   or a revocation list does not decode.
10. **Provider contract.** `auths.provider-contract/1` holds the provider and
    API release as opaque text, an optional OpenAPI slice digest, sorted
    manual assumptions, an environment class (`provider-test-mode` or
    `disposable-live-resources`), the corpus manifest digest, the oracle
    version, and digests of the observation, recovery, idempotency, and
    retention declarations. `ProviderContractId` is SHA-256 of the schema, a
    NUL byte, and the canonical contract.
11. **States.** Using reading 12's definition of a usable attestation, a
    gateway derives exactly one state from its current verified inputs:
    `unqualified` when the signer certificate or release index is unusable,
    or the index lists no closed record for the recipe's family; `candidate`
    when the index lists such a record and no usable attestation exists for
    it; `revoked` when a verified list, now or earlier, names the
    qualification or the signer of its attestation; `stale` when a usable
    attestation exists and a tuple member differs, a window has ended, the
    clock cannot be trusted, or the revocation list is unusable or past its
    next update; and `qualified` otherwise. An unsigned record that the
    signed index does not list changes nothing. The transitions of §7.1 are
    the lifecycle of one qualification as the release process issues,
    expires, and revokes it, with one edge added: `stale` may become
    `revoked`. `revoked` is terminal for that qualification; a new
    attestation by a new signer, or a new qualification, starts its own
    lifecycle. The transitions do not constrain successive values a gateway
    derives: removing an index entry returns a recipe to `unqualified`.
12. **Codes where §10 is silent.** An attestation is *usable* when the
    release index lists it and its record by digest, its signature verifies
    under a signer whose certificate verifies under the pinned root and
    permits attestations, it names that record, its window lies within the
    record's window, and its window has started. Whether a window has *ended*
    is not part of being usable. With no usable attestation for the
    deployment's recipe family the code is `gateway.qualification.missing`:
    this covers a forged, outsider-signed, wrong-signer, wrong-record,
    record-outliving, or not-yet-valid attestation, an index that omits it,
    an absent record, and a family no record names. With a usable attestation
    whose window, or whose signer certificate's window, has ended, the code is
    `gateway.qualification.expired`. A certificate or index that does not
    verify, names another root, or lacks the index artifact kind, and a
    revocation list that does not verify or is older than one already
    accepted, is `gateway.qualification.unavailable`.
13. **Precedence.** When several faults hold a verifier reports the first of
    nine conditions: the certificate or index is unusable (`unavailable`); a
    verified list, now or earlier, names the qualification or its signer
    (`revoked`); the revocation list is unusable or older than one already
    accepted (`unavailable`); the clock is untrusted or local time is before
    a signed issue time (`clock-untrusted`); the revocation list is past its
    next update (`revocation-stale`); no usable attestation exists
    (`missing`); a window has ended (`expired`); a digest member differs
    (`digest-mismatch`); a target member differs (`target-mismatch`). Nothing
    about a recipe is authenticated while the certificate or index is
    unusable, so that comes first. An authenticated revocation comes before
    every later fault, including an unusable or stale list and an untrusted
    clock. One two-fault vector pins each adjacent pair.
14. **Verifier state.** A verifier keeps the highest revocation-list sequence
    it has accepted and every signer and qualification any verified list has
    named. A later list that omits one does not restore it.
15. **Store kind.** The tokens are `local-file-v1` and
    `aws-secrets-manager-v1`. Every other token, including one that differs
    in case, spacing, or version, is `gateway.credential.adapter-unsupported`
    under both policies. `local-file-v1` under production policy is
    `gateway.credential.production-plaintext-refused`.
16. **Readiness.** Nine required preconditions (trust, store, recipe,
    qualification, provider-secret custody, connection generation, clock,
    transport policy, operator-plane isolation) and observer custody, which
    blocks only when an observer is configured and not ready. The type reports
    which precondition failed. Stable codes attach in Epic 4.
17. **External naming.** The custody plan derives the secret name from the
    deployment namespace, connection identifier, and credential generation,
    and the version identifier from the connection identifier, generation,
    and reference commitment. Five derivations are frozen as vectors. The
    plan lists one assumption about the service that the first protected run
    must confirm.
18. **Code inventory.** The new codes have their own inventory,
    `production-codes.json`, because the `epic` field of `codes.json` numbers
    AP-SPEC-063's epics. `gateway.readiness.connection-disabled` has no
    producing vector: it is a readiness reason that Epic 4 produces.
19. **Bindings.** Python and TypeScript projections and closed code unions are
    Epic 4 work, as AP-SPEC-063 epic 1 left its bindings to later epics.
20. **Fourth provider.** The abstraction case compares Postmark as its
    header-API-key provider, on paper only.
21. **Store view.** `lease_secret` takes a `CredentialBinding`, not the
    `ConnectionBinding` §5.1 first showed, so a store cannot read the
    provider kind or descriptor. The record validates a recovery binding as
    §5.1 now states.
22. **Injection header.** §11's "action or recipe attempts to choose an
    injection header" is read as: no action, submission frame, or store
    chooses it. The header is the recipe's own committed declaration under
    the approved digest; a bearer recipe has no header member, and the
    recipe corpus already refuses a provider-reserved header there and
    `Authorization` as a provider header.
23. **Two secret bounds.** A credential store accepts 1 to 65,536 bytes. The
    transport injects at most 4,096 bytes into a header, as it did before
    this work; a stored secret above that is refused at injection and never
    sent. The vectors pin both.
24. **What the binding change reaches today.** The gateway's serving path
    still leases through the local store's record-based lease, which already
    read the record's exact credential generation. The trait's `lease_secret`
    is what the production adapter will implement; moving the engine onto
    the trait is Epic 2 task 1.

### 18.4 A finding for the owner

§8 bounds a revocation list at 72 hours, and §7.4 keeps the root that signs it
offline. Together they require a root ceremony at least every 72 hours for as
long as any production recipe is enabled; a missed one disables every required
recipe. The protected-run plan sets a 48-hour cadence and explains why signing
future-dated lists in advance is not a safe way to relax it: such a list is a
newer list without a later revocation. Reading 14 makes revocation permanent
at each verifier so that a later list cannot undo one. Whether a 48-hour
ceremony is acceptable is the owner's decision; the alternative is to amend
the bound in §8, not to add a configuration that widens it.

## 19. Epic 2 status and readings

Epic 2 is implemented in code and tests, and the store contract has passed
against the live service ([run 37304826956](https://github.com/auths-dev/auths-proof/actions/runs/37304826956), second attempt): real disposable secrets
were written with the operator role, read with the runtime role, rotated,
revoked, and deleted. That confirms the derived version identifier, the
request signing, and the web-identity exchange against the real service.

A gateway using the store has also run live ([run 37328109139](https://github.com/auths-dev/auths-proof/actions/runs/37328109139)): the north-star
refund journey, hostile cases included, with the key installed into Secrets
Manager and leased from it for every write, and the connection revoked at
the end so nothing was left in the store. The offline audit of that run
passed. Its provider was the counting double, so this shows the whole
custody path through a real gateway and not a real provider's behavior.

**A write to a live provider through this path has passed** ([run 37349590113](https://github.com/auths-dev/auths-proof/actions/runs/37349590113)). The
north-star refund journey ran against Stripe test mode on the default gateway
build, with the restricted test key taken into Secrets Manager at install and
leased from it for every request: one 15.00 test refund confirmed by
read-back, one refund the provider rejected, the hostile cases, and the
offline audit. That is the done gate's "real disposable write using the
maintained adapter".

Three things about that run are not what the journey's README describes, and
each narrows what it shows:

- The owner's sandbox cannot use Connect, so the platform account stood in as
  the account the refund is scoped to. The provider accepts its own account
  in that header. Scoping to a genuinely distinct connected account is not
  shown; AP-SPEC-066 §7.6 requires it for the Stripe qualification.
- The job runs a copy of the journey whose operation identifiers carry the
  run number, because the provider's idempotency window refuses the fixed
  identifiers twice within 24 hours on one account.
- Two earlier attempts failed on test data, not on the gateway: a payment of
  1,000.00 where the journey assumes 60.00, and the idempotency window above.

A later run ([run 37331000975](https://github.com/auths-dev/auths-proof/actions/runs/37331000975))
adds two least-privilege facts at the store: the runtime role cannot delete,
and the operator role cannot read what it wrote. The network client is also
tested directly against a loopback service that answers wrongly.

**The gateway's identity needs to write.** Rotation and revocation are
performed by the serving process, so its workload identity needs create and
delete on its own prefix as well as read. The store-level run shows that a
read-only runtime identity and a write-only operator identity are possible
at the store; the gateway does not yet split them, because that requires
moving the store writes of rotation and revocation into the operator
command. The live journey therefore uses a third role with all three
permissions on the gateway's prefix. Splitting them is operator-plane work
for Epic 4.

The first attempts failed for a reason outside the code. This repository
uses the identity provider's immutable subject, so the token's subject is
`repo:auths-dev@260513770/auths-proof@1310728509:environment:gateway-custody-live`
and not the name-only form the roles first trusted. The roles now trust
exactly that subject.

### 19.1 What exists

| Task | Artifact |
| --- | --- |
| 1 sealed store behind the trait | The engine, install, and join hold `dyn ConnectionCredentialStore`. The trait gains `holds`, `confirm`, `retire_superseded`, and `delete_connection`, each answerable by a store private to one process and by one shared by all. One contract test runs against both in-repository stores. |
| 2 `aws-secrets-manager-v1` | Crate `auths-credentials-aws-secrets-manager`: derived secret name and version identifier, the store over three service calls, request signing checked against the service's published vectors, a network client with one attempt per call bounded by the caller's deadline, and three workload-identity sources (web identity token, container endpoint, instance metadata) with no fallback between them. |
| 3 rotation | `rotate-prepare` and `rotate-commit` on the operator socket and CLI; the one-step `rotate` is both. A superseded generation is retired after `CredentialRetirementDelay`, by exact generation. Both phases work on a disabled connection, which is the emergency cutover. |
| 4 doctor and production policy | `install --credential-store`; `credential_store_policy` refuses an unknown kind and, under production policy, the local file. `doctor` reports the provider credential store separately from the observer and does not fail when no observer exists. |
| 5 conformance | The store's tests drive the frozen `secret_names`, `version_references`, `lease`, and `rotation` sections of `custody-hostile.json`; the gateway drives `store_kinds` through the policy function. The live workflow `gateway-custody-live.yml` runs the store contract against the protected account. |

The code inventory marks `gateway.credential.adapter-unsupported` and
`gateway.credential.production-plaintext-refused` implemented. The pending
assertion fired when the name derivation and then the two codes landed, as
§18.1 said it would, and each time the vectors it guarded were given a driver.

### 19.2 Readings (PROVISIONAL)

1. **Client.** The minimal closed client over the existing HTTP and TLS
   stack, as the custody plan recommended. The owner had not chosen; no
   build script or native dependency was added.
2. **Two-phase rotation carries the commitment.** `rotate-prepare` answers
   with the successor's reference commitment and `rotate-commit` takes it. A
   shared store cannot find a prepared secret by search, and the commitment
   names it without revealing it or where it is kept.
3. **A record that changed since the prepare commits nothing.** The
   successor was stored for the generation after the one the prepare saw. A
   state change in between makes the commit answer
   `gateway.admin.rotation-not-prepared`; the operator prepares again.
4. **Retirement is by exact generation.** The gateway remembers the
   generation it superseded and revokes that one when the delay has passed.
   The local stores also delete an unpublished successor the record has
   moved past. That second rule fixes a defect the new tests found: a
   prepared successor followed by a disable made the local store keep the
   orphan and delete the credential that served.
5. **This engine is stricter than §5.4 allows.** An attempt whose record
   changes between its load and its lease is abandoned before the lease, so
   no attempt leases the old generation after a commit. The retained
   generation is therefore not needed by this engine today; it is kept
   because §5.4 requires it and a later engine may rely on it.
6. **The installation manifest is `auths.gateway-installation/4`.** It
   records the credential-store kind and, for the production store, the
   namespace, region, key, and named workload identity. It records no secret
   and no external location. There is no reader for `/3`.
7. **Workload identity is named, not discovered.** `--aws-identity` selects
   exactly one of `web-identity`, `container`, or `instance-metadata`. A
   static access key in the environment is not a source.
8. **Tests of the production store without a secret manager.** The cargo
   feature `testkit-production-plaintext` lets a production installation use
   the local file. The default build lacks it, and a test asserts the shipped
   refusal. The PostgreSQL workflow enables it for one test binary.
9. **Orphaned secrets in the shared store.** A prepare that is never
   committed, or an install that stops before its record is written, leaves a
   secret no record names. Nothing can lease it. The gateway does not yet
   delete it: the store cannot list, and the gateway keeps no durable note of
   what it prepared. The operator-polish epic owns that collector.
10. **Not driven end to end.** The frozen `lease` and `rotation` scenarios
    are driven at the store. Their gateway-level stage and code
    (`not-entered`, `gateway.credential.unavailable`) are the engine's
    existing behavior for a failed lease and are not re-driven per scenario.

## 20. Epic 3 status and readings

Epic 3 is implemented in code and tests. A gateway now refuses every lease
for a recipe that signed release inputs do not qualify, and release tooling
can assemble, sign, and verify a qualification. **Nothing has been
qualified.** No trust root or release signer exists, no family directory
exists, and the protected run has not been started; its first run belongs to
Epic 5. What the tests show is the mechanism under keys made for the tests.

### 20.1 What exists

| Task | Artifact |
| --- | --- |
| 1 trust model, certificates, records, proposals, attestations, revocation, index, verifier | `auths-recipe-qualification`: `VerifiedQualifications` checks every signature once under a pinned root and derives a deployment's state, first refusal, and lease decision; all 57 frozen verification vectors are driven through it. `auths-recipe-qualification-issuance`: `RootSigner` (certificates, revocation lists), `ReleaseSigner` (attestations, the index), `QualificationProposal`, and the `auths-qualification` tool. |
| 2 evidence assembly and semantic closure | `auths.qualification-evidence/1`, one artifact per member listing its passed cases; `verify_evidence_closure`; `QualificationProposal::assemble` and `from_parts`, both of which verify the closure; `auths.gateway-semantic-closure/1` and the gateway's `GATEWAY_SEMANTIC_CLOSURE_SHA256`. |
| 3 stages | `execution::RunCorpus`, `RunCase::execute`, and `auths-qualification run-stage` execute the closed corpus through a reviewed family's operation harness. The runner sequences differential, hostile, replay, race, restart, crash, custody drift/rotation, loss/delayed-visibility recovery, live read-back, and installed-consumer steps; it compares measured observations and derives reports and live-effect counts itself. Redaction, freshness, and signer rotation remain release-tool stages. The executable contract is in `qualification/README.md`. |
| 4 runtime matching and per-recipe readiness | `auths-gateway` `qualification`: `QualificationGate`, the deployment tuple, the policy, and the deployment clock; checked before the claim and again before every lease; `qualification-import`, `qualification-status`, and the operator command `qualification-reload`. |
| Protected run | `.github/workflows/recipe-qualification.yml`, `qualification/run/offline.sh` and `assemble.sh`, and the family contract in `qualification/README.md`. |

Done gate:

- **Every §7.5 row has a bounded evidence member.** Each of the twelve rows
  maps to scenarios, and each scenario to one of the ten members. A record
  closes only when every scenario the wall always requires has a passed case
  in its member. The test `every_required_scenario_is_needed_to_close_the_wall`
  removes each in turn and requires the assembly to fail.
- **Forged or drifted records fail before credential lease.** The gateway
  tests drive the gate in front of the engine's lease: forged, unsigned,
  another root's, revoked, expired, stale, clock-untrusted, digest-drifted,
  and target-drifted inputs each refuse with the frozen code when an entry
  is prepared, which is before the lease call, and a lease attempted after
  the inputs went stale is refused. The tests instrument the credential store and
  require zero lease calls for every refusal, including expiry between
  preparation and lease. All 57 verification vectors decide the
  gate as frozen.
- **Pull requests cannot sign or import.** The workflow test
  `a_pull_request_reaches_no_secret_and_no_signing_job` reads the workflow and
  fails if any job but live evidence and signing reaches a secret or an
  environment, or if anything after offline evidence can run from a pull
  request. `qualification-import` refuses a record no signer indexed. The
  signing environment requires a reviewer and admits only the default branch.
- **The runtime cannot distinguish provider names or execute an oracle.** The
  gate's deployment tuple carries the provider contract as a digest; the gate
  module names no provider kind; and the gateway's build closure contains no
  issuance crate (`a_gateway_build_contains_no_issuance_or_oracle`).

The code inventory marks the eight `gateway.qualification.*` codes
implemented. `gateway.readiness.connection-disabled` and the support bundle
remain pending for Epic 4, and the pending assertion still guards them.

### 20.2 What is not shown

- **No protected run.** The workflow has been linted and its two scripts
  exercised on a development host with a throwaway family. It has never run
  with a real family, a live environment, or a signing key.
- **No production family corpus.** The reusable hostile, recovery, live,
  installed-consumer, differential, and process-transition runners now exist.
  Their subprocess, observation, and script-pipeline tests use explicit test
  doubles at the family port; they establish runner behavior, not a live
  qualification. A production family's reviewed operations, oracle and
  corpus arrive with its decision record in Epic 5.
- **No production qualification.** A production gateway pins no trust root, so
  it finds every recipe unqualified and leases nothing. Existing production
  tests run in a build made for tests that relaxes this.
- **The support-bundle scan has nothing real to scan yet.** The wall requires
  a `support-bundle-scan` case, and the gateway has no support bundle until
  Epic 4. The release runner requires scan evidence; the family must export the actual
  candidate's bundle when that command exists. A record with that case
  before Epic 4 would be claiming a scan of something that does not exist.
- **The production clock adapter covers one synchronization service**
  (reading 12).

### 20.3 Readings (PROVISIONAL)

Each was taken unattended as the narrower or fail-closed reading.

1. **Packages.** Issuance is a second product crate,
   `auths-recipe-qualification-issuance`, that reaches only the model and
   `auths-connections`. A gateway does not depend on it. Its `testkit`
   feature exposes a synthetic candidate under fixed keys for tests.
2. **Evidence artifact.** `auths.qualification-evidence/1` is at most 64 KiB
   and holds a member, the candidate's commit, the digest of the tuple
   (`auths.qualification-tuple/1`), 1 to 256 cases sorted by identifier, and
   live effects exactly for the live member. A case is an identifier, a
   scenario, the capabilities it shows, and an unauthorized-entry count. A
   failed case has no representation: a run with one produces no artifact.
3. **Scenarios.** The closed set, by wall row and member:

   | Row | Scenarios | Member |
   | --- | --- | --- |
   | 1 | `clean-source`, `recipe-digest-rederives` | conformance |
   | 2 | `recipe-vectors`, `closed-enumeration-hostile` | conformance |
   | 3 | `oracle-accepts`, `oracle-rejects` | differential |
   | 4 | `application-cannot-read-secret`, `production-readiness` (launch gate) | hostile |
   | 5 | `forged-proof`, `altered-action`, `proof-replay`, `fresh-challenge-replay`, `direct-provider-attempt`, `ambiguous-response` | hostile |
   | 5 | `two-instance-race` | multi-instance |
   | 5 | `restart`, `crash` | restart |
   | 6 | `store-kind-drift`, `generation-drift`, `commitment-drift`, `external-version-drift` | rotation |
   | 7 | `provider-secret-rotation`, `signer-rotation`, `freshness`, `observer-rotation` | rotation |
   | 8 | `declared-capability` | live |
   | 9 | `read-back-confirms-write` | live |
   | 10 | `response-loss`, `delayed-visibility` | recovery |
   | 11 | `log-scan`, `trace-scan`, `metric-scan`, `support-bundle-scan`, `evidence-scan` | redaction |
   | 12 | `installed-journey`, `no-repository-import`, `no-provider-token` | installed-consumer |

   The closed set has thirty-seven scenarios. Thirty-four are required of every
   record. `production-readiness` is additionally required for the stable launch
   projection: a protected live, read-only doctor probe on the exact PostgreSQL
   and production-custody target, with all required typed rows ready and zero
   leases or provider entries. Its evidence commits to the actual doctor report.
   Intermediate records may omit it but cannot close the stable launch gate.
   `observer-rotation` and
   `declared-capability` are required exactly when a capability they show is
   exercised. `freshness` is placed in row 7 because the signed time bounds
   are part of the trust transitions.
4. **Closure.** A record closes over its evidence when the artifacts are one
   per member in order; each digest, case count, and counter is the
   artifact's; each artifact names the record's commit and tuple; every
   always-required scenario has a case; each capability is `exercised`
   exactly when a case shows it; and the live effects are the live member's.
   The seven faults are `member-set`, `digest`, `counter`, `candidate`,
   `scenario`, `capability`, and `live-effects`.
5. **Proposals.** A proposal is a record with its ten evidence artifacts and
   no signature. A signer accepts only a proposal, so nothing is signed whose
   closure was not re-verified. A pull request cannot assemble one, because
   the live member needs the protected environment; it produces offline
   evidence only. This is narrower than the protected-run plan first said.
6. **Trust stages.** Signer rotation and freshness must be in the rotation
   member before the run's record exists, so they run for the run's tuple on
   a placeholder candidate under a root made for the stage and discarded with
   it. They show that this build's issuance and verification keep each trust
   transition, and that inputs which qualify stop doing so under an untrusted
   clock, behind a signed issue time, and past the list's next update. The
   stage does not step past an attestation's or a certificate's end; the
   verification vectors cover those.
7. **Redaction.** A source fails when it contains a planted canary as raw
   bytes, in either hexadecimal case, or in either base64 alphabet at any of
   the three alignments. A canary shorter than 8 bytes, or a scan with no
   canary or no source, is refused as evidence of nothing.
8. **Semantic closure.** `auths.gateway-semantic-closure/1` lists, by path and
   SHA-256, every file under `src` and the manifest of the gateway crate and
   of each workspace crate it is built from, and the workspace manifest and
   lockfile; at most 4,096 files and 1 MiB. The one excluded file holds the
   digest constant. A gateway test recomputes the closure and fails when it
   changed.
9. **Deployment tuple.** The compiled recipe and profile-lock digests are
   rederived from the installed files. The semantic closure, package,
   version, operating system, and architecture are the build's. The build
   digest is SHA-256 of the running executable. The store kind and schema
   follow the deployment (`postgresql-v1` with `auths.lifecycle.postgresql/5`,
   or `shared-file-v1` with `auths.gateway-attempt/3`). The recipe family and
   the provider contract identifier are declared by the operator at install,
   because a gateway cannot derive them; a wrong declaration matches no
   attestation and refuses.
10. **Policy.** `required` or `optional`. Production requires qualification
    and refuses `optional`, an undeclared family or contract, and a
    caller-supplied trust root, all as
    `gateway.install.qualification-policy`. Development defaults to
    `optional`, which reports the state and never refuses. A build feature
    for tests, `testkit-production-unqualified`, lets a production
    installation run unqualified; no shipped build has it. The policy is
    decided again from the deployment at every start.
11. **Pinned root.** The gateway build pins none yet. A development
    installation may name its own root file at install, recorded by digest.
12. **Clock.** The production adapter reports `trusted` exactly while the
    marker `/run/systemd/timesync/synchronized` exists. A host synchronized
    by another service must provide that marker. Reading the kernel's
    synchronization flag would cover every Linux host and container, and it
    needs a system call the workspace's ban on `unsafe` code does not permit;
    that is an owner decision. An unreadable clock is evaluated as untrusted
    at the latest representable time, so a revocation is still reported
    first.
13. **Where the gate is asked.** Before the claim, so a refusal is recorded
    not-entered with its qualification code, and again inside the lease,
    because time passes between the two.
14. **Inputs.** `qualification-import` verifies a release directory under the
    installation's root, records what the new inputs establish, and then
    replaces the host's inputs by renaming the old directory away and the new
    one in. A failure between those steps leaves no inputs or old inputs
    below the recorded floor, and either way nothing qualifies. It refuses
    when the certificate, index, or revocation list is unusable, the list is
    older than one already accepted, or the index was issued before one
    already accepted; authentic inputs are kept whatever state they derive.
    When a serving gateway cannot read its inputs it drops the ones it held. A serving gateway rereads them through the
    operator socket and verifies only when their digest changed.
15. **Remembered revocations and floors.** A verifier keeps, besides the
    revocation-list sequence of §18.3 reading 14, the latest issue time of a
    release index it has accepted, and refuses an index issued earlier. That
    is what stops a qualification a later index dropped, without revoking
    it, from being restored by presenting the older index. All of it is kept
    per host in the state directory, not in the shared store. A host that has not imported a newer list keeps serving
    under its own list until that list's next update, which is the bound §8
    sets. A missing record means nothing was accepted; a damaged one refuses.
16. **One index per run.** A release signer signs one index listing exactly
    the proposals given to it, so the protected run qualifies every family
    directory together.
17. **Run facts.** The qualification identifier is derived from the family,
    the commit, and the run. The source-closure digest is the digest of the
    commit's tree listing, and the generated-artifacts digest is the digest
    of the candidate's two binaries.
18. **Environments.** One live environment per family,
    `recipe-qualification-live-<family>`, holding that family's disposable
    credential as `QUALIFICATION_PROVIDER_CREDENTIAL`. One signing
    environment, `recipe-qualification-signing`, created on 2026-10-05 with a
    required reviewer and the default branch only; it holds no secret yet.
19. **Manifest and readiness line.** The installation manifest is
    `auths.gateway-installation/5`. The readiness line now states the
    qualification policy, state, and code in place of "no provider-effect
    qualification".

20. **Several attestations for one family.** When more than one usable
    attestation exists for the deployment's family and none qualifies it, the
    refusal reported is that of the attestation nearest to qualifying: one
    that differs only in target is reported before one that has expired.
    §18.3 reading 13 orders the faults of a single attestation; this reading
    covers the case it leaves open. No combination yields `qualified` unless
    one attestation qualifies outright.
21. **What the run trusts.** A family's harness is code on the default
    branch and is trusted as reviewed code: it supplies measured observations of
    provider-specific operations. The candidate gateway authors the tuple,
    and the release runner authors case reports after comparing observations
    with the reviewed corpus. The run does not trust what a harness leaves behind as a
    program. Assembly, signing, and verification each build the release tool
    from the commit; the signer's key is given only to that build; the trust
    stages are rerun at assembly; the candidate's facts are taken from the
    job that ran before any live harness; and a tuple naming another family
    is refused. The redaction scan runs in the live job, the only place the
    canaries exist, and the canaries are deleted before anything is uploaded.

### 20.4 Decisions for the owner

1. **Root ceremony.** Create the root offline with
   `auths-qualification root-init`, commit the three public artifacts to
   `qualification/trust/`, and pin the root in the gateway build. Until then
   production qualifies nothing.
2. **Release signer.** Create its key with `auths-qualification signer-init`,
   certify it in the ceremony, and store the key file's contents as the
   secret `QUALIFICATION_RELEASE_SIGNER_KEY` of the signing environment.
3. **Clock adapter** (reading 12): accept the marker, or approve a reviewed
   exception for the kernel call.
4. **Revocation cadence** (§18.4) is still open.
5. **Remembered revocations** (reading 15): per host, or in the shared store.
6. **Live environments.** Each `recipe-qualification-live-<family>`
   environment must be created with a required reviewer and the default
   branch only before its credential is stored. The workflow's own guard is
   in a file a pull request can change; the environment's rule is not.

### 20.5 Epic 3 completion work (2026-10-06)

The owner rejected the catalogue/report-format-only reading of task 3 and
required executable stages on the Epic 3 branch. The reusable runner now
executes bounded operation sequences, validates exact candidate observations,
compares the pure oracle with the gateway, forbids repeated entry/lease,
requires declared recovery and fresh read-back, and isolates installed
consumers from provider credentials and repository import paths. Corpus
validation requires executable coverage of every harness-owned mandatory
scenario. Reports and live counters are runner-derived; a failed rerun removes
old reports/proposals, including when its corpus is invalid. Assembly accepts
only runner-owned phase reports and release-owned trust/scan outputs; arbitrary
harness reports cannot replace missing execution. The workflow invokes these
stages rather than asking a family to supply passing reports. Its live script
always invokes idempotent resource cleanup, including after partial setup or
failed execution, and refuses a failed cleanup.

Evidence: `tests/execution.rs` covers execution, missing scenarios, candidate
and counter drift, exposure, differential mismatch, recovery without a
capability, invalid ordering, subprocess failures, timeout and consumer
environment isolation. `tests/cli.rs` drives stages through evidence assembly,
signing and verification; `tests/script_pipeline.rs` drives the actual
redaction and assembly scripts, refuses a missing recovery execution even with
an extra harness report, and tests teardown after successful and failed runs.
Gateway qualification tests count calls to `ConnectionCredentialStore`;
`qualification_stages_use_gateway_replay_and_recovery_witnesses` feeds actual
submission-driver, persistent-store, credential-lease and counting-provider
observations into replay and lost-response recovery stages.
Hosted verification of these additions is pending; no live qualification or
owner trust ceremony is claimed.


## 21. Epic 4 implementation and remaining acceptance (2026-10-06)

The operator-polish branch adds a bounded canary-scanned support bundle,
typed production doctor report, store-only emergency disable/revoke, separate
operator-process rotation under its own workload identity, graceful listener
shutdown and a durable host generation floor. The floor rejects an older
restored connection or changed bytes at an accepted generation before lease.
The maintained systemd deployment reference is `deployment/gateway/`; the
operations and independent trial protocol are in
`docs/operations/GATEWAY_PRODUCTION_RUNBOOK.md`. Code at `f1f92c3f` passed
[all main CI jobs](https://github.com/auths-dev/auths-proof/actions/runs/37421643170)
and the six operator-package, isolation, PostgreSQL, recipe and SDK-package
workflows. The downloaded operator archive and all eleven payload digests
were verified against that commit. Protected live custody is still awaiting
environment approval; these automated checks do not close the live or human
acceptance gates below.

The production clock adapter now rejects a synchronization marker older than
fifteen minutes, a future timestamp, a symlink/nonregular file or an unsafe
write mode. Mere existence did not bound trust after synchronization stopped.
The packaged reference caps systemd-timesyncd polling at five minutes. This is
a fixed adapter bound, not an operator override of signed validity windows or
a claim that a compromised time source is trustworthy.

This is not Epic 4 acceptance yet. A live two-host reference exercise of
workload identity, firewall, PostgreSQL point-in-time restore and the runbooks
remains. The owner now assigns the agent a labeled operator simulation and
handles real users offline; no independent human result is claimed. The
source-free packaged simulation passed 47 steps in Docker against the verified
`f1f92c3f` package after fixing development file-rotation and tuple-declaration
friction. The sanitized report is
`deployment/gateway/evidence/operator-simulation-2026-10-06.json`.
The exact `393edc52` candidate subsequently passed all 26 main CI jobs and the
six package/isolation/PostgreSQL/recipe/SDK workflows. Its source-free hosted
rehearsal passed all 47 steps in 0.553 seconds, and the downloaded archive passed
the same 47 steps in Docker in 6.162 seconds. PR #205 merged as `4623d635` on
2026-10-06 under the owner's labeled-simulation deliverable. No live provider,
production AWS rotation or production PostgreSQL PITR is claimed by this run.
Epic 5
also lacks the owner's offline root ceremony, protected signer secret,
two protected provider environments and human release review. On 2026-10-06,
GitHub environment/secret metadata confirmed no qualification signer secret
and neither family live environment. No production recipe is qualified.

## 22. Epic 5 engineering and unresolved qualification inputs (2026-10-06)

The release projection now verifies every signed index entry, exact candidate
identity, production target, time/revocation, evidence closure and production
readiness, requiring independent families, contracts and provider kinds.
Finalization re-evaluates the result and the manifest binds exactly one
projection. Signing publishes the canonical evidence needed to inspect closure.
The current build pins no root and derives false; hosted verification is pending.

[ADR 0014](../adr/0014-stripe-refund-recipe-qualification.md) and
[ADR 0015](../adr/0015-airtable-record-update-recipe-qualification.md) are proposed
provider decisions, not production-qualified families. The owner has directed
the agent to simulate bootstrap and both provider harnesses independently.
`qualification/simulation/run.py` now runs disposable in-memory root/signer
creation, certification, signing, index/revocation publication and required-gate
import. Unsigned and expired inputs cannot lease; verified test import can.
The signed placeholder records explicitly claim no provider run. Separate
Stripe and Airtable harness reports measure actual native driver leases, entries,
fresh read-back, replay, reopen, response loss and response-record crash against
independent wire oracles and mutable doubles. The production pinned root stays
unchanged and stable launch readiness stays false. The rehearsal is a maintained
CI job and needs no external credentials.

The local rehearsal passed 36 measured provider cases (18 per family), plus
the disposable two-family signing/import ceremony. Each race entered one
write; a concurrent contender may additionally use a measured read-only
reconciliation lease. The
candidate kit embeds its fixtures and is run in Docker without checkout,
credentials or network. Hosted verification of that packaged run is pending.

The protected production run still has a first-attestation cycle:
production leases require qualification before the live effects needed to issue
it. A reviewed authority design must resolve this without bypassing the shipped
lease gate. Dynamically created provider identifiers need reviewed oracle/corpus
binding before execution, not expected digests copied from candidate output.
Those real-production prerequisites do not block the owner-directed simulation.
No protected live evidence or production qualification is claimed.
