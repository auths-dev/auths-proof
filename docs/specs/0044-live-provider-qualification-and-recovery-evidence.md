# AP-SPEC-044: Live Provider Qualification and Recovery Evidence

## Status

Implementation contract for qualifying real Stripe, PostgreSQL, and OpenTofu
profiles for production advertisement.

This specification closes the launch gate left intentionally open by
AP-SPEC-040, AP-SPEC-041, AP-SPEC-042, and AP-SPEC-043. It does not change the
application SDK, profile semantics, or provider-connection model. It defines
the exact evidence required before a statically compiled profile route may be
advertised by a production local agent.

Auths is prelaunch. This is a direct source cutover. There are no deprecated
qualification records, legacy evidence readers, dual qualification formats,
runtime overrides, or compatibility aliases. Once this specification is
implemented, obsolete qualification state is rejected and regenerated.

The normative words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD
NOT, and MAY are interpreted as described in RFC 2119.

## 1. Decision

A real provider profile is production-available only when a protected live run
against the real provider or provider engine, on the exact semantic source
closure, proves all of the following:

1. the real provider or provider engine performed the exact effect;
2. denied and malformed requests acquired no mutation credential and performed
   no provider mutation;
3. every durable and provider boundary was crash-tested on both sides;
4. replay produced no second effect;
5. response loss and restart converged through read-only recovery;
6. linked portable receipts verified in Rust, Python, and TypeScript and their
   profile claims matched durable and provider truth;
7. secrets and sensitive provider data were absent from evidence, receipts,
   logs, diagnostics, and generated packages;
8. the protected run produced a signed, bounded qualification attestation; and
9. the checked-in launch inventory names that attestation and matches its
   semantic-closure digest, target, profile versions, and trust key.

Compilation, fixtures, mocks, a synthetic provider, a passing SDK test, or a
manual provider demonstration is not production qualification.

The initial launch state remains:

| Domain | Production state | Testkit state |
| --- | --- | --- |
| Stripe refund | unqualified | synthetic testkit only |
| PostgreSQL update preflight + bounded update | unqualified | unavailable |
| OpenTofu plan preflight + saved-plan apply | unqualified | unavailable |

Until a profile satisfies this specification, the production agent MUST omit
its routes and advertisements. It MUST NOT expose an "experimental" runtime
flag that bypasses qualification.

For SDK v1.0 this decision is finite: the release qualifies exactly the five
profile references, one target, and provider rows listed in section 20.5. The
repository-complete and published finish lines, blocker-admission rule, and
post-v1 boundary in that section prevent implementation findings or desirable
extensions from silently expanding the release.

## 2. Relationship to existing contracts

This specification is subordinate to the domain semantics in:

- AP-SPEC-040 for the local-agent protocol, SDK, lifecycle order, recovery,
  portable receipts, profile manifests, and static registration;
- AP-SPEC-041 for Stripe connection onboarding and credential boundaries;
- AP-SPEC-0012 for bounded Stripe refund policy, evidence, reservation,
  execution, reconciliation, and receipts;
- AP-SPEC-042 for PostgreSQL preflight, prepared updates, transactions, and
  recovery; and
- AP-SPEC-043 for OpenTofu protected planning, prepared plans, apply, and
  recovery.

Qualification MUST exercise those exact contracts. It MUST NOT introduce a
second evaluator, action shape, provider command, state transition, receipt
format, or recovery rule in a test harness.

This specification supersedes only AP-SPEC-040's
`auths.profile-roster/1` launch-state shape. Implementation cuts directly to
the roster-v2 contract in section 9.4 and updates AP-SPEC-040, its schema,
generator, fixtures, and tests atomically. No `/1` reader or migration path
remains.

If live evidence exposes a semantic defect, the domain implementation and its
own specification are corrected first. Qualification is rerun against the new
semantic closure. An attestation cannot waive or reinterpret a profile rule.

## 3. Goals

### 3.1 Launch goals

- Make production availability a machine-verifiable fact, not a manifest
  assertion.
- Prove one real effect, its denial paths, and its recovery behavior for every
  advertised profile version and supported target.
- Make source or configuration drift invalidate qualification automatically.
- Let an operator understand why a profile is unavailable without revealing
  provider credentials or sensitive evidence.
- Preserve the five-line application experience after qualification; ordinary
  application code receives no qualification options.

### 3.2 Security goals

- No provider mutation credential before durable authorization, reservation,
  command sealing, and fresh equality checks.
- No unsafe retry after provider entry or response loss.
- No profile can self-declare qualification from its own package manifest.
- No pull-request code can access qualification signing secrets.
- No checked-in evidence can contain a provider secret, database row value,
  OpenTofu variable value, raw plan, or recovery capability.
- A stale or forged attestation cannot make a route available.
- A target that was not tested cannot inherit another target's qualification.

### 3.3 Contributor goals

A contributor can run one documented command to produce complete preliminary
candidate evidence and diagnose static or live failures. The protected
workflow turns that input into final evidence only after independent installed,
observation, cleanup, scan, and verification stages. A release maintainer can
verify and import the resulting signed record without manually editing digests.
CI explains every missing or mismatched gate.

## 4. Non-goals

This specification does not:

- qualify live Stripe credentials or production-mode Stripe accounts;
- use customer, production, or long-lived business data;
- make PostgreSQL and OpenTofu share provider semantics;
- make the testkit Stripe adapter a production adapter;
- add a generic callback, plugin executor, provider URL, command, SQL, or
  arbitrary environment escape hatch;
- permit a provider's idempotency feature to replace Auths recovery state;
- require raw qualification logs to be committed to Git;
- claim Windows support for the Unix local-agent transport; or
- allow a manual release override when evidence is unavailable.

## 5. Vocabulary

- **Semantic closure**: the deterministic digest of all shipping source,
  manifests, schemas, error fragments, canonical fixtures, generated route
  inputs, and qualification workflow code that can change a qualified
  profile's decision, command, lifecycle, recovery, or receipt behavior. It
  excludes only qualification attestations and their launch-state projection.
- **Candidate revision**: the immutable Git commit tested by protected CI.
- **Qualification target**: one exact operating-system and CPU tuple, such as
  `linux-x86_64`.
- **Provider environment**: an isolated test account, database, backend, or
  sandbox used only by the qualification run.
- **Raw evidence bundle**: bounded logs, redacted traces, receipts, provider
  observations, crash results, and test reports retained as a CI artifact.
- **Qualification record**: the small canonical JSON summary committed to the
  repository.
- **Qualification attestation**: a signed envelope containing one
  qualification record.
- **Profile family gate**: an atomic qualification over profiles that depend on
  each other, such as PostgreSQL preflight plus update.

The closed initial target registry is:

| Qualification target | Rust target triple |
| --- | --- |
| `linux-x86_64` | `x86_64-unknown-linux-gnu` |
| `linux-aarch64` | `aarch64-unknown-linux-gnu` |
| `macos-x86_64` | `x86_64-apple-darwin` |
| `macos-aarch64` | `aarch64-apple-darwin` |

No target alias, wildcard, libc substitution, or compatible-target inference
is allowed. Windows remains outside the local-agent launch contract until its
named-pipe and authority-storage specification is implemented and separately
qualified.

## 6. UX

### 6.1 Contributor flow

The contributor-facing flow is:

```text
$ cargo xtask profile qualification status --domain postgresql

DOMAIN       TARGET        STATE         REASON
postgresql   linux-x86_64  unqualified   no trusted live attestation

$ cargo xtask profile qualification run \
    --domain postgresql \
    --target linux-x86_64 \
    --environment qualification-postgresql

✓ static profile/package checks
✓ live TLS discovery and bounded update
✓ 12 denial and mutation scenarios
✓ 24 crash/restart scenarios
✓ replay and response-loss recovery
✓ Rust/Python/TypeScript receipt verification
✓ redaction and secret scan

preliminary candidate artifact:
target/qualification/postgresql/linux-x86_64/preliminary-evidence.tar.zst
proposal:
target/qualification/postgresql/linux-x86_64/proposal.json
```

The local command produces an unsigned proposal and preliminary candidate
evidence for diagnosis. The preliminary archive is not the raw evidence
container from section 9.6: it has no protected provider observation, cleanup
proof, receipt-anchor export, installed-package report, or final manifest and
cannot be signed or imported. It can never change launch state. Only the
protected workflow in section 12 can create the final container and sign a
record accepted by the repository.

### 6.2 Release-maintainer flow

```text
$ cargo xtask profile qualification import \
    --attestation qualification-postgresql-linux-x86_64.json

✓ signature and trust-key validity
✓ protected workflow identity
✓ artifact digest and bounds
✓ semantic closure matches current tree
✓ profile family and target are exact
✓ every required scenario passed
updated release qualification index and generated launch roster

$ cargo xtask profile qualification check --all
qualified: postgresql update-preflight/update on linux-x86_64
blocked:   stripe refund, opentofu plan/apply
```

Import MUST refuse a dirty tree when any non-projection file in the semantic
closure differs from the tested closure. It MUST write only the attestation,
qualification index, roster production-qualification projection, and
structured launch projection listed in section 12.4. The semantic freeze binds
the immutable qualification contract but is never an import output. No other
semantic source or documentation is an import output.

### 6.3 Operator diagnostics

The production agent reports only safe launch facts:

```text
+------------------------------------------------------------------+
| Auths provider profile status                                    |
+----------------+------------------+---------------+---------------+
| Domain         | Profile          | Target        | State         |
+----------------+------------------+---------------+---------------+
| Stripe         | refund/1         | linux-x86_64  | unavailable   |
| PostgreSQL     | update family/1  | linux-x86_64  | qualified     |
| OpenTofu       | plan/apply/1     | linux-x86_64  | unavailable   |
+----------------+------------------+---------------+---------------+
| PostgreSQL qualification: qlf_...  closure: 31bf04...            |
+------------------------------------------------------------------+
```

Diagnostics MAY expose qualification ID, semantic-closure digest, target, and
qualified profile references. They MUST NOT expose run secrets, provider
resource identifiers, artifact URLs containing credentials, row values,
variable values, recovery handles, or raw evidence.

### 6.4 Application UX

There is no new application API. After qualification, the existing generated
client becomes negotiable through `connect()`:

```python
async with auths.connect() as session:
    postgresql = PostgreSQL(session, connection="warehouse")
    prepared = await postgresql.update_preflights.create(...)
    result = await postgresql.updates.execute(
        prepared_update=prepared.prepared_update,
    )
```

Before qualification, the profile is absent from the session advertisement
and the generated constructor fails as unavailable without provider I/O.

## 7. Architecture

### 7.1 Ownership

```text
+------------------------------ protected release workflow ------------------+
|                                                                            |
|  exact Git revision -> build products -> isolated provider environment     |
|          |                                      |                           |
|          v                                      v                           |
|  qualification runner ----------------> real effect + crash matrix         |
|          |                                      |                           |
|          +------------> raw evidence bundle <---+                           |
|                              |                                             |
|                              v                                             |
|                    signed qualification record                             |
+------------------------------|---------------------------------------------+
                               |
                               v
+------------------------------ repository ----------------------------------+
| trust keys -> attestation verifier -> qualification index -> generator     |
|                                                        |                    |
|                                                        v                    |
|                                              static available routes        |
+--------------------------------------------------------|--------------------+
                                                         |
                                                         v
+------------------------------ production ----------------------------------+
| workload -> local agent -> qualified concrete profile -> provider          |
|                         -> durable recovery -> linked receipts              |
+----------------------------------------------------------------------------+
```

### 7.2 Layer placement

| Component | Location | Ownership |
| --- | --- | --- |
| Domain live runner | `product/integrations/auths-<domain>/tests/qualification/` | domain semantics |
| Common evidence model and verifier | `product/sdk/auths-profile-kit` | bounded qualification mechanism |
| Qualification orchestration and CLI | `xtask` | non-shipping control plane |
| Reusable protected workflow | `.github/workflows/profile-qualification.yml` | release infrastructure |
| Generated domain entrypoints | `.github/workflows/profile-qualification-<domain>.yml` | declarative environment binding |
| Trust keys and checked records | `release/qualification/` | release policy |
| Static route projection | `product/runtime/auths-node/src/generated/` | generated shipping registration |
| Cross-language receipt checks | binding testkits | language projection evidence |

No shipping package depends on `xtask`, GitHub workflow types, raw evidence
artifacts, or qualification secrets.

### 7.3 Static availability

Qualification is a build-time fact. The generated node roster emits a closed
availability predicate for each profile reference and target. Production route
construction includes only profiles whose trusted qualification record matches
the current semantic closure and compilation target.

There is no environment variable, configuration flag, administrative route,
feature flag, or SDK option that changes an unqualified profile to qualified.
The separate synthetic testkit binary may include profiles whose independent
`testkitAvailable` flag is `true`, but that flag never grants production
availability or changes the production state.

### 7.4 Family atomicity

The qualification units are:

| Domain | Atomic profile set |
| --- | --- |
| Stripe | `auths.stripe.refund/1` |
| PostgreSQL | `auths.postgresql.update-preflight/1` and `auths.postgresql.bounded-update/1` |
| OpenTofu | `auths.opentofu.plan-preflight/1` and `auths.opentofu.saved-plan-apply/1` |

PostgreSQL update cannot be qualified without its preflight. OpenTofu apply
cannot be qualified without its plan preflight. A family record is accepted
only when every listed profile passes in one protected run using the same
agent build, connection generation, configuration closure, and receipt trust
root.

### 7.5 Contributor extension contract

Stripe, PostgreSQL, and OpenTofu are instances of one qualification mechanism;
they are not three independent harnesses. The common mechanism owns:

- closure calculation, canonical records, signing, trust verification, import,
  roster projection, and diagnostics;
- production-agent installation, local-agent transport, workload identity,
  connection administration, restart supervision, failpoint sequencing, and
  provider-call counters;
- the common scenario, credential-order, crash, response-loss, cancellation,
  replay, receipt, redaction, and installed-package matrices; and
- artifact bounds, provenance, retention, secret scanning, and release gates.

The shipping implementation for each domain remains real production code under
`product/integrations/auths-<domain>/`: concrete policy evaluation, connection
and credential handling, provider commands, durable state, reconciliation, and
profile-specific receipts. Qualification invokes that production path through
the installed SDK and observes it through separately reviewed protected code.
Neither side may simulate, replace, or contain an alternate implementation of
the effect.

A domain contributes two statically registered, disjoint interfaces:

```text
QualificationCollectionAdapter             QualificationProtectedObserver
  metadata()                 -> family, targets, environment, scenario roster
  vectors(environment)       -> bounded common and domain input material
  invoke_phase(vector, reviewed_phase, client)
                             -> one generated-client operation mismatch hint
                                             open(trusted_run_context)
                                             provider_truth(operation)
                                             validate_receipt_payload(claims)
                                             cleanup(trusted_run_context)
                                             redact(protected_observation)
```

These are qualification-time interfaces in `auths-profile-kit`; neither is a
shipping runtime callback or provider abstraction. Collection code may execute
candidate production clients but cannot author common lifecycle evidence,
provider truth, cleanup evidence, or a signed observation. The protected
common loop owns the immutable phase roster and enters the no-seed controller
before each `invoke_phase`; it exact-checks the single returned role/profile
and requires durable controller completion before entering the next phase.
PostgreSQL and OpenTofu retain their bounded preflight capability only inside
the adapter environment between those two separately gated calls. An adapter
does not receive a lifecycle callback and cannot batch or reorder phases. Before
provider provisioning, the common loop canonically validates the ledger plan,
source registry, receipt anchors, and agent configuration, then checks every
scenario state directory and phase runtime directory against the immutable
UID/GID policy. Each phase has distinct `agent/`, `supervisor/`,
`journal-reader/`, `profile-state-reader/`, and `receipt-verifier/` socket
parents; services with distinct protected UIDs never share a caller-owned
socket parent. The agent directory and shared-reader directories are exact
`0710` directories in the plan's agent group, while scenario/phase traversal
and owner-only signer rules remain closed. Forced controller cleanup first
uses retained no-follow parent and child directory descriptors to kill the exact
delegated phase cgroup before reaping the controller; it never path-resolves an
uncaptured cgroup. The candidate launcher inherits the controller's dedicated
process group, and forced cleanup kills that group as well as the cgroup, which
covers failure before and after cgroup placement. A stalled controller therefore
cannot strand a candidate process or redirect cleanup to another cgroup.

The protected observer is built from the reviewed attester revision, never from
the candidate tree, and receives common ledger projections as read-only inputs.
It may add only domain-owned provider facts and profile-claim validation; shared
code owns common journal, request, receipt, counter, and crash semantics.
Cleanup derives its namespace from trusted repository/run/provider-row identity
and remains callable when candidate evidence is absent or malformed.

The closed collection, observer, and domain-fact-validator rosters are generated
from profile-package manifests. Arbitrary module names, commands, URLs,
callbacks, environment maps, and executable paths are not accepted from
workflow or CLI input.

Each profile-package manifest adds one `qualification` object containing:

```json
{
  "family": ["auths.stripe.refund/1"],
  "adapter": "stripe",
  "targets": ["linux-x86_64"],
  "protectedEnvironment": "qualification-stripe",
  "commonScenarios": "auths.profile-qualification-common/1",
  "domainScenarios": "qualification/scenarios-v1.json"
}
```

The generator validates that the family exactly equals the manifest's
dependent production profiles, the adapter is in the static Rust roster, the
targets are closed values, the domain scenario file is canonical and bounded,
and no scenario shadows a common ID. It then emits:

- separate collection and protected-observer scaffolds, a domain-fact
  validator, and hostile fixtures;
- a thin workflow entrypoint that calls the reusable workflow with a constant
  domain, target set, and protected environment;
- qualification commands, report schemas, and installed-package tests; and
- a contributor checklist naming every required domain-specific proof.

Adding a fourth domain MUST NOT require changes to the common workflow,
qualification schemas, attestation verifier, import logic, roster semantics,
crash supervisor, or SDKs. It requires the manifest declaration, collection
adapter, protected observer and fact validator, domain scenarios/truth probes,
protected environment, and the same qualification evidence as every existing
family. Stripe, PostgreSQL, and OpenTofu are the three real reference
implementations. Generator contract tests prove that their manifests produce
the same common workflow shape and that no domain-specific branch exists in
the workflow, common verifier, roster, crash supervisor, or SDK.

The repository additionally contains a synthetic fourth-provider
qualification proof. It is not production code and cannot become qualified,
but it MUST exercise the complete contributor path: scaffold, manifest and
schema validation, generated static adapter registration, generated protected
workflow entrypoint, installed Python and TypeScript clients, common scenario
and crash-supervisor orchestration, bounded evidence packaging, protected
attestation verification with a test-only trust root, transactional import
into an isolated repository, route projection, drift invalidation, and clean
removal. Immutable sentinels and dependency tests prove that this end-to-end
addition changes none of the common workflow, verifier, import mechanism,
roster semantics, crash supervisor, shipping SDK runtime, or the three real
domain implementations. A scaffold-only or roster-only test does not satisfy
this requirement.

### 7.6 Requirement-to-evidence inventory

Each domain owns canonical
`product/integrations/auths-<domain>/qualification/requirements-v1.json` with
schema `auths.profile-qualification-requirements/1`. Every row contains:

```text
requirementId
profileReferences
authoritativeSpecPath + section
productionSourceOwners
unitTests
mutationTests
liveScenarioIds
crashPointIds
receiptClaimIds
providerTruthReportFields
credentialRole
```

All arrays are non-empty where applicable, byte-sorted, unique, repository
relative, and bounded to 256 rows and 128 values per row. The generator proves
exact equality between prerequisite bullets in sections 13.1, 14.1, and 15.1,
this inventory, domain scenarios, failpoint coverage, receipt registration,
and evidence reports. A prose prerequisite without a row, a stale source/test
path, or a report claim without an owning prerequisite blocks qualification.

Each domain also owns canonical `qualification/provider-matrix-v1.json`. It
selects, rather than merely describes, the supported qualification contract:
Stripe account class, pinned API version, and setup/read/mutation credential
permissions; PostgreSQL minimum/maximum major versions, immutable image
digests, TLS profile, extension set, and setup/audit/preflight/executor roles;
OpenTofu tool digest, exact Linux sandbox mechanism and restrictions, mirror,
provider/module lock closure, encrypted-artifact format/key policy, backend,
and one selected operation-bound recovery record. No `or`, wildcard, mutable
tag, system default, or implementation-chosen alternative is permitted. The
matrix digest participates in the semantic closure, qualification record, and
evidence provenance.

## 8. Semantic closure

### 8.1 Inputs

`cargo xtask profile qualification closure --domain <domain>` computes
SHA-256 over a canonical length-prefixed sequence of normalized repository
paths and file bytes. Paths are sorted by raw UTF-8 bytes. Symlinks, missing
files, duplicates, path escapes, non-UTF-8 paths, and files larger than 16 MiB
are rejected.

The closure includes:

- the applicable AP-SPEC files;
- the domain package's Rust source, manifest, API schema, error fragments,
  canonical fixtures, migrations, and profile-package manifest;
- shared lifecycle, connection, profile-runtime, stores, receipt, errors,
  config, and production-client source used by the vertical;
- node local-agent, journal, receipt, recovery, workload-authority, profile
  configuration, generated route source, and roster generator inputs;
- Python, TypeScript, WASM, generated profile-package source, and their public
  contract metadata;
- PyO3 and WASM native source and manifests, binding build configuration,
  TypeScript compiler configuration and package tools, Python build metadata,
  generated-package tests, and every input used to build an installed wheel,
  npm package, or native extension exercised by qualification;
- installed-consumer, customer-journey, security-evidence, crash, receipt,
  redaction, and provider-truth harnesses whose results are claimed by the
  qualification record;
- `architecture.toml`, `compliance.toml`, workspace manifests, lockfiles, and
  qualification workflow code; and
- qualification schemas, trust policy, and `xtask` verification code.

The closure excludes:

- `release/qualification/v1/attestations/`;
- the qualification state fields in the launch projection;
- build outputs and transient raw evidence; and
- Git metadata other than the candidate revision recorded separately.

The exact include/exclude list is emitted in
`release/qualification/v1/closure-manifest.json` and itself participates in
the closure.

The closure is read from the exact immutable candidate Git tree, not from a
recursive walk of a mutable checkout. Untracked caches and build products are
therefore absent by construction. A tracked cache, bytecode file, generated
build product not declared as a shipping artifact, symlink, or ignored
security-relevant input is a hard error rather than an exclusion escape hatch.

Qualification launch state is normalized as structured data owned by the
roster generator. The closure implementation MUST NOT replace arbitrary bytes
between source-code markers or normalize an executable availability
expression. Authoritative CI runs the deterministic generator in check mode
and includes generated-route behavior tests, so changing route logic,
qualification metadata projection, or marker syntax changes or invalidates the
closure.

### 8.2 Drift behavior

Any closure change invalidates the prior record. CI then requires one of two
explicit actions:

1. rerun protected qualification and import a new attestation; or
2. change the affected launch state to `unqualified` in the same change.

CI MUST NOT bless a new digest automatically. Generated formatting or a client
rename that cannot affect provider semantics still changes the closure because
the installed-package proof is part of qualification.

## 9. Qualification data contracts

### 9.1 Trust-key registry

`release/qualification/v1/trust-keys.json` has schema
`auths.profile-qualification-trust/1`:

```json
{
  "schema": "auths.profile-qualification-trust/1",
  "keys": [
    {
      "keyId": "profile-qualification-2026-01",
      "algorithm": "Ed25519",
      "publicKeyBase64url": "<32-byte unpadded base64url>",
      "allowedDomains": ["postgresql"],
      "notBeforeUnixSeconds": 0,
      "notAfterUnixSeconds": 0
    }
  ]
}
```

Zero `notAfterUnixSeconds` means no scheduled expiry. Keys are byte-sorted by
`keyId`. `allowedDomains` contains 1-64 byte-sorted, unique lowercase domain
tokens. Verification rejects a valid signature when the record's domain is
not listed for that key. Key IDs use the 1-128-byte registered-token grammar.
Duplicate, unknown, expired, not-yet-valid, domain-mismatched, or malformed
keys fail closed.

The private signing key exists only in a protected release environment. Pull
request workflows and repository code cannot read it. Key rotation retains old
public keys while a checked qualification record names them. Removing a trust
key first makes every dependent profile unqualified.

`release/qualification/v1/observer-trust-keys.json` uses the same bounds,
domain scoping, ordering, Ed25519 algorithm, and validity rules under schema
`auths.profile-qualification-observer-trust/1`. Observer and attestation key IDs
and public keys MUST be disjoint. The observer private key is available only to
the protected observation/cleanup job; the final attestation job receives only
the observer public registry from its protected attester revision.

`release/qualification/v1/evidence-source-trust-keys.json` has schema
`auths.profile-qualification-evidence-source-trust/1` and contains the exact
eight source-role key sets from section 11.2.1, including validity intervals,
allowed domains, source identities, and immutable executable digests.
`release/qualification/v1/evidence-ledger-trust-keys.json` has schema
`auths.profile-qualification-evidence-ledger-trust/1` and contains only common
ledger-sealer public keys with the same bounds, domain scoping, ordering, and
validity rules. Key IDs and public keys are globally unique across source,
ledger, observer, attestation, receipt, and recovery roles. Both registries are
semantic closure inputs and their exact canonical SHA-256 digests are protected
workflow policy inputs. No private source or ledger key is checked in.

### 9.2 Qualification record

The canonical record schema is `auths.profile-qualification/1`. It is JCS JSON
with no unknown fields:

```json
{
  "schema": "auths.profile-qualification/1",
  "qualificationId": "qlf_<unpadded-base64url-sha256>",
  "domain": "postgresql",
  "profiles": [
    {"id": "auths.postgresql.update-preflight", "version": 1},
    {"id": "auths.postgresql.bounded-update", "version": 1}
  ],
  "target": "linux-x86_64",
  "candidateRevision": "<40 lowercase hex Git object id>",
  "semanticClosureSha256": "<64 lowercase hex>",
  "packageManifestSha256": "<64 lowercase hex>",
  "profileRuntimeDigests": [
    {
      "profile": "auths.postgresql.bounded-update/1",
      "sha256": "<64 lowercase hex>"
    },
    {
      "profile": "auths.postgresql.update-preflight/1",
      "sha256": "<64 lowercase hex>"
    }
  ],
  "errorRegistrySha256": "<64 lowercase hex>",
  "providerMatrixSha256": "<64 lowercase hex>",
  "proposalSha256": "<64 lowercase hex>",
  "toolchain": {
    "rust": "1.97.1",
    "node": "22.23.1",
    "python": "3.13.5"
  },
  "environmentClass": "disposable-provider-test",
  "startedAtUnixSeconds": 0,
  "completedAtUnixSeconds": 0,
  "workflow": {
    "provider": "github-actions",
    "repositoryId": "<canonical decimal GitHub repository ID>",
    "workflowPath": ".github/workflows/profile-qualification-postgresql.yml",
    "workflowRevision": "<40 lowercase hex protected workflow revision>",
    "attesterRevision": "<40 lowercase hex protected attester revision>",
    "runId": "<decimal token>",
    "runAttempt": 1,
    "protectedEnvironment": "qualification-postgresql"
  },
  "releaseBuild": {
    "provider": "github-actions",
    "repositoryId": "<canonical decimal GitHub repository ID>",
    "workflowPath": ".github/workflows/release-builder.yml",
    "workflowRevision": "<40 lowercase hex protected build-workflow revision>",
    "runId": "<decimal token>",
    "runAttempt": 1,
    "runLabel": "official",
    "qualificationSurfaceSha256": "<closed production/qualification-agent difference proof>",
    "artifacts": [
      {
        "role": "production-agent",
        "artifactId": "<immutable decimal artifact ID>",
        "uploadedArchiveSha256": "<GitHub artifact digest>",
        "memberPath": "<closed canonical member path>",
        "memberSha256": "<64 lowercase hex>",
        "bytes": 1
      },
      {"role": "python-native", "artifactId": "<id>", "uploadedArchiveSha256": "<digest>", "memberPath": "<path>", "memberSha256": "<digest>", "bytes": 1},
      {"role": "python-profile-opentofu", "artifactId": "<id>", "uploadedArchiveSha256": "<digest>", "memberPath": "<path>", "memberSha256": "<digest>", "bytes": 1},
      {"role": "python-profile-postgresql", "artifactId": "<id>", "uploadedArchiveSha256": "<digest>", "memberPath": "<path>", "memberSha256": "<digest>", "bytes": 1},
      {"role": "python-profile-stripe", "artifactId": "<id>", "uploadedArchiveSha256": "<digest>", "memberPath": "<path>", "memberSha256": "<digest>", "bytes": 1},
      {"role": "python-wheel", "artifactId": "<id>", "uploadedArchiveSha256": "<digest>", "memberPath": "<path>", "memberSha256": "<digest>", "bytes": 1},
      {
        "role": "qualification-agent",
        "artifactId": "<immutable decimal artifact ID>",
        "uploadedArchiveSha256": "<GitHub artifact digest>",
        "memberPath": "<closed canonical member path>",
        "memberSha256": "<64 lowercase hex>",
        "bytes": 1
      },
      {"role": "typescript-native", "artifactId": "<id>", "uploadedArchiveSha256": "<digest>", "memberPath": "<path>", "memberSha256": "<digest>", "bytes": 1},
      {"role": "typescript-package", "artifactId": "<id>", "uploadedArchiveSha256": "<digest>", "memberPath": "<path>", "memberSha256": "<digest>", "bytes": 1}
    ]
  },
  "artifact": {
    "evidenceTarSha256": "<64 lowercase hex>",
    "evidenceTarBytes": 1,
    "retentionDays": 90,
    "createdAtUnixSeconds": 0,
    "expiresAtUnixSeconds": 0,
    "redactionReportSha256": "<64 lowercase hex>",
    "storageProvider": "github-actions",
    "artifactId": "<immutable decimal artifact ID>",
    "uploadedArchiveSha256": "<GitHub upload-artifact archive digest>"
  },
  "providerRuns": [
    {
      "id": "postgresql-16",
      "providerVersion": "<observed PostgreSQL 16 patch version>",
      "providerArtifactSha256": "<64 lowercase hex image or executable digest>",
      "scenarioSetSha256": "<64 lowercase hex>",
      "status": "passed"
    },
    {
      "id": "postgresql-17",
      "providerVersion": "<observed PostgreSQL 17 patch version>",
      "providerArtifactSha256": "<64 lowercase hex image or executable digest>",
      "scenarioSetSha256": "<64 lowercase hex>",
      "status": "passed"
    },
    {
      "id": "postgresql-18",
      "providerVersion": "<observed PostgreSQL 18 patch version>",
      "providerArtifactSha256": "<64 lowercase hex image or executable digest>",
      "scenarioSetSha256": "<64 lowercase hex>",
      "status": "passed"
    }
  ],
  "protectedObservation": {
    "schema": "auths.profile-qualification-observation/1",
    "keyId": "postgresql-qualification-observer-2026-01",
    "sha256": "<64 lowercase hex>"
  },
  "scenarios": [
    {
      "id": "happy-path",
      "status": "passed",
      "assertions": 1,
      "reportSha256": "<64 lowercase hex>",
      "providerRunIds": ["postgresql-16", "postgresql-17", "postgresql-18"]
    }
  ],
  "receiptVerification": {
    "rust": "passed",
    "python": "passed",
    "typescript": "passed",
    "portableReceiptSchema": "auths.portable-receipt/1",
    "receiptTrustAnchorSha256": "<64 lowercase hex>",
    "decisionVerificationMethod": "<1-512 byte verification method>",
    "executionVerificationMethod": "<1-512 byte verification method>"
  },
  "secretScan": {
    "tool": "gitleaks-8.28.0",
    "status": "passed",
    "reportSha256": "<64 lowercase hex>"
  }
}
```

Bounds:

| Field | Bound |
| --- | --- |
| Encoded record | 1-262,144 bytes |
| Domain | 1-64 lowercase ASCII `[a-z][a-z0-9-]*` |
| Profiles | 1-8, byte-sorted, unique |
| Profile ID | current semantic-ID bound |
| Target | 1-64 registered token |
| Toolchain value | 1-128 printable ASCII bytes |
| Scenario count | 1-256 |
| Scenario ID | 1-128 registered token |
| Provider runs | 1-16, byte-sorted, unique IDs |
| Release-build artifacts | exactly the 9 v1 roles shown, byte-sorted with unique canonical paths |
| Assertion count | 1-100,000 |
| Raw artifact | 1-536,870,912 bytes |
| Artifact ID | 1-32 canonical decimal bytes |
| Repository ID and workflow run ID | 1-32 canonical decimal bytes |
| Workflow and attester revisions | exactly 40 lowercase hex bytes |
| Retention | 90-365 days |
| Qualification duration | 1 second through 6 hours |

Every required scenario ID in sections 11 through 15 appears exactly once.
Additional domain-owned scenarios are allowed only when declared in the profile
manifest and schema. Every scenario status MUST be `passed`.

`providerRuns` exactly equals the checked domain provider matrix. Each row is a
separate protected matrix job using the same candidate revision, target,
profile family, generated packages, and trust roots. Every row status is
`passed`. Each scenario's `providerRunIds` is the exact byte-sorted set of runs
to which that scenario applies; scenarios required across a version matrix list
every run, while provider-version-specific scenarios list the declared subset.
`scenarioSetSha256` commits the canonical ordered reports for that run. This
keeps the logical scenario roster unique while proving every required provider
version separately.

`releaseBuild` is obtained from GitHub, never from the proposal or a provenance
report. Its workflow path/revision is the protected authoritative no-secret
build policy. `runLabel` is exactly `official`; reproduction builds are
comparison evidence only and are rejected by the durable qualification record.
Each artifact row names the exact immutable hosted object and
the exact member bytes consumed by its owning qualification stage. The root
wheel, generated Python profile distributions, Python native, npm package, and
TypeScript native rows are the exact package bytes later published. The
qualification agent is qualification-only and MUST NOT be published. The
pre-import production agent proves route omission and failpoint absence; after
import the final production agent is deterministically
rebuilt from the same candidate/toolchain with only the allowlisted generated
qualification projection changed, and its final digest is recorded in release
evidence. For v1 the role set is exactly the nine rows shown. The attester
recomputes `qualificationSurfaceSha256` from the protected build graph, closed
feature difference, generated route projection, and production-binary absence
tests; it proves the qualification agent and pre-import production agent come
from the same candidate/toolchain and differ only by the reviewed harness,
failpoint, and qualification-route surface. A candidate provenance report is a
mismatch oracle only. Protected-revision code reads the immutable candidate
Cargo manifests and generated launch projection directly, requires the exact
qualification feature edges and the byte-sorted unqualified five-profile
roster. The shipping `auths` target is an explicit production-only wrapper
whose unconditional compile-time assertions reject the credential-broker,
qualification-journal, and testkit feature sentinels exported by their owning
crates. CI compiles and tests production, qualification, and testkit targets as
separate exact feature profiles; it never treats their invalid additive
all-features union as a shipping target. Protected source binaries are built
only from the separately verified
attester revision and are absent from both candidate archives; their exact
command surfaces are checked by the attester-tool and static-compliance gates.
Candidate-authored surface labels and binary string scans are supplemental
mismatch checks, not authority for that reconstruction.

`protectedObservation.sha256` is SHA-256 over the exact canonical signed
observation envelope defined in section 9.6. Its key is verified through the
domain-scoped observer trust registry at the observation completion time.

`profileRuntimeDigests` is byte-sorted by `profile`, contains exactly one row
for every member of `profiles`, and repeats no profile or digest row.

`qualificationId` is `qlf_` plus unpadded base64url SHA-256 of the canonical
record with `qualificationId` temporarily set to the empty string. The verifier
recomputes it.

`evidenceTarSha256` and `evidenceTarBytes` describe the exact inner
`evidence.tar.zst` produced by the common packager. `uploadedArchiveSha256`
describes the immutable archive object produced by the pinned GitHub artifact
service around the uploaded directory. They are distinct byte domains and MUST
NOT be substituted. `expiresAtUnixSeconds` equals the provider-reported
artifact expiry and is at least `createdAtUnixSeconds + retentionDays * 86400`.

### 9.3 Signed attestation

The attestation schema is `auths.profile-qualification-attestation/1`:

```json
{
  "schema": "auths.profile-qualification-attestation/1",
  "record": {"...": "auths.profile-qualification/1 record"},
  "signing": {
    "algorithm": "Ed25519",
    "keyId": "profile-qualification-2026-01",
    "signatureBase64url": "<64-byte unpadded base64url>"
  }
}
```

The signature preimage is ASCII
`auths.profile-qualification-attestation/1`, one NUL byte, then the canonical
JCS bytes of `record`. The attestation is at most 266,240 bytes. Verification
checks canonical JSON, all bounds, qualification ID, key validity at
`completedAtUnixSeconds`, signature, workflow identity, semantic closure,
profile set, target, scenario roster, artifact metadata, and all result fields.

The protected signer is an independent evidence verifier, not a signing oracle
for candidate-authored JSON. Before signing, trusted code from the protected
attester revision MUST:

1. obtain repository ID, candidate revision, workflow path and protected
   workflow revision, attester revision, run ID, run attempt, protected
   environment, target, immutable artifact ID, upload digest, creation/expiry
   times, configured retention, and the authoritative release-build workflow
   path/revision/run/attempt and immutable artifact IDs directly from
   GitHub-owned context or protected configuration;
2. refuse any candidate-supplied value that disagrees with those trusted
   values;
3. read the exact immutable candidate Git tree and independently recompute the
   semantic closure, package manifest, profile runtime, error registry,
   toolchain, generated-package identities, exact nine-role release-build
   artifact roster, and closed production/qualification-agent surface;
4. download the exact uploaded artifact by immutable ID, verify the hosted
   archive digest and byte bound, and safely extract it without symlinks, hard
   links, special files, path escapes, duplicate paths, decompression bombs, or
   files exceeding declared bounds; separately query GitHub for every
   release-build artifact by immutable ID, verify the pinned authoritative
   build workflow and candidate revision, archive/member digests and lengths,
   and exact equality to the bytes consumed by collection and installed
   verification;
5. verify the retained source-trust snapshot against the protected registry
   digest; verify every retained typed source record signature, run/session
   context, role, executable identity, validity interval, and payload; verify
   the ledger-sealer signature, context, hash chain, phase/event exact sets, and
   closed lifecycle automaton; independently derive every common attempt,
   counter, effect, crash, receipt, and cleanup obligation; then recompute the
   canonical file manifest, scenario roster, report digests, provider-truth
   reports, redaction report, secret-scan report, and aggregate artifact digest
   from extracted bytes;
6. verify the protected observation signature and exact equality between its
   ledger/source-registry, external provider truth, counters, and cleanup
   commitments and every applicable typed report, then independently rerun
   Gitleaks 8.28.0 and the typed forbidden-field scan over the safely extracted
   final evidence;
7. verify the protected receipt-anchor commitment and every linked receipt and
   profile claim with the trusted native verifier, then verify the immutable
   report from the separate no-secret installed-package job that exercised the
   candidate's shipped Rust, Python, and TypeScript artifacts through the
   protected harness and mutation corpus; and
8. construct the final record itself from verified values before computing the
   qualification ID and signature.

Candidate code never receives the attestation seed and cannot choose the
protected attester revision, trust key, workflow identity, environment,
artifact identity, or retention period. Every third-party workflow action is
pinned to an immutable commit and its output shape is tested.

### 9.4 Qualification index and launch roster

Checked attestations live at:

```text
release/qualification/v1/attestations/<domain>/<target>.json
```

`release/qualification/v1/index.json` maps exact profile references and targets
to qualification IDs. It is deterministic generated output and is not edited
by hand.

The package roster becomes `auths.profile-roster/2`. Each package entry contains
an exact `profiles` map:

```json
{
  "profile": "auths.postgresql.bounded-update/1",
  "state": "qualified",
  "testkitAvailable": false,
  "targets": ["linux-x86_64"],
  "qualificationIds": ["qlf_..."]
}
```

Allowed production states are `unqualified` and `qualified`. Every entry also
has a required independent boolean `testkitAvailable`. A qualified entry
requires one trusted record for every target. An unqualified entry has no
production target or production attestation. A profile with
`testkitAvailable: true` is available only through the disposable testkit
binary regardless of its production state; import never changes this flag.
Profile entries exactly equal the package manifest's profile set.

### 9.5 Unsigned qualification proposal

The collector emits canonical JSON schema
`auths.profile-qualification-proposal/1`, at most 262,144 bytes, with exactly
these fields and no unknown fields:

```text
schema
domain
profiles
target
candidateRevision
semanticClosureSha256
packageManifestSha256
profileRuntimeDigests
errorRegistrySha256
providerMatrixSha256
toolchain
candidateArtifacts { role, memberSha256, bytes }
environmentClass
collectionStartedAtUnixSeconds
collectionCompletedAtUnixSeconds
providerRuns
scenarios
receiptVerification { rust, python, typescript, portableReceiptSchema }
secretScan
```

The nested shapes, ordering, and bounds are the corresponding final-record
shapes in section 9.2. `candidateArtifacts` is the exact nine-role stable
role/digest/length projection of `releaseBuild.artifacts`; it contains no
workflow or hosted artifact authority. Provider-run and scenario statuses
remain untrusted candidate claims. The proposal contains no `qualificationId`,
`proposalSha256`, final `startedAtUnixSeconds`/`completedAtUnixSeconds`,
`workflow`, `artifact`, receipt trust-anchor digest, or receipt verification
methods. Its SHA-256 over exact canonical bytes becomes the final record's
`proposalSha256`.

The protected observer and signer treat the proposal only as a mismatch oracle:
they independently reconstruct every final field, fail when a corresponding
proposal claim differs, and never copy an unverified proposal value into the
record. There is no nullable or optional final-record form and no parser that
accepts the proposal as `auths.profile-qualification/1`. The contributor UX
names this file `proposal.json`, never `record.json`.

### 9.6 Raw evidence container

The protected observer's final upload contains exactly two top-level regular
files:

```text
proposal.json
evidence.tar.zst
```

`proposal.json` is the exact canonical, non-authoritative proposal from section
9.5. Candidate code cannot precompute a signable final record.

`evidence.tar.zst` is one deterministic Zstandard-compressed POSIX tar stream.
It contains only byte-sorted, unique, relative UTF-8 regular-file paths with
mode `0400`, uid/gid zero, empty owner/group names, and timestamp zero. It
contains no symlink, hard link, device, FIFO, socket, sparse member, PAX path
override, absolute path, `.`/`..` component, duplicate normalized path, or
trailing archive data. Bounds are 4,096 members, 16 MiB per member, 512 MiB
compressed, and 1 GiB aggregate uncompressed. Extraction validates paths and
bounds before allocation and writes only into a newly created owner-only
directory using no-follow file operations.

The archive has this closed required layout:

```text
manifest.json
ledger/<provider-run-id>/evidence-ledger-trust.json
ledger/<provider-run-id>/evidence-source-trust.json
ledger/<provider-run-id>/ledger.json
ledger/<provider-run-id>/source-records/<source-role>/<canonical-sequence>.json
ledger/<provider-run-id>/supervisor-contexts/<registered-operation-id>.json
ledger/<provider-run-id>/decision-snapshots/<registered-operation-id>.json
ledger/<provider-run-id>/durable-acks/<registered-operation-id>.json
ledger/<provider-run-id>/crash-action-contexts/<registered-operation-id>/failpoint-acknowledged.json
ledger/<provider-run-id>/crash-action-contexts/<registered-operation-id>/process-killed.json
ledger/<provider-run-id>/crash-action-contexts/<registered-operation-id>/process-restarted.json
common-phases/<provider-run-id>/<registered-scenario-id>/<canonical-phase-index>.json
reports/cleanup.json
reports/counters.json
reports/gitleaks.json
reports/installed-packages.json
reports/provider-truth.json
reports/protected-observation.json
reports/provenance.json
reports/receipt-trust-anchors.json
reports/receipts-rust.json
reports/receipts-python.json
reports/receipts-typescript.json
reports/redaction.json
reports/typed-forbidden-fields.json
reports/scenarios/<registered-scenario-id>.json
receipts/<registered-operation-id>/<canonical-sequence>.cbor
receipt-inspection/<registered-operation-id>.json
```

`common-phases/` contains exactly one canonical protected common-phase
projection for every phase commitment in every retained provider-run ledger
and no other member. The provider-run, scenario, and phase path components are
derived from the signed ledger roster. Each file digest is the corresponding
`commonPhaseEvidenceSha256`, and the observer and final attester independently
rerun the shared event-to-attempt/instance/receipt/counter reconciliation over
those exact bytes.

`manifest.json` has schema `auths.profile-qualification-evidence-manifest/1`.
It lists every other archive member exactly once as `{path, bytes, sha256}` in
raw UTF-8 byte order and contains aggregate member count and uncompressed byte
length. It is at most 1 MiB. Every report uses an exact schema under
`product/spec/v1`, rejects unknown fields, and binds repository ID, workflow
run/attempt, candidate revision, domain, target, profile family, operation IDs,
connection generations, scenario IDs, and applicable failpoints. The report
schemas define closed counter names, provider observations, receipt IDs and
verification-method IDs, installed artifact identities, scan tool/version,
redaction counts, cleanup results, bounds, and canonical ordering.

There is exactly one canonical `receipt-inspection` record for every
receipt-bearing operation and no record for a receipt-free operation. Each
record is bounded by the per-member limit, rejects unknown fields, is ordered
by operation ID in the manifest, and contains only fixed common truth and
SHA-256 commitments to the durable journal basis and signed profile-claim bytes
checked by the generated static profile inspector. The corresponding protected
`NativeReceiptVerified` ledger event commits the canonical projection. Raw
profile state, sealed commands, provider results, observations, credentials,
recovery handles, and unredacted provider identifiers are absent.

The archive contains exactly one ledger directory for every `providerRuns` row
and no other directory. Within each row,
`evidence-source-trust.json` and `evidence-ledger-trust.json` are the exact
canonical registry snapshots whose digests match the protected policy inputs
and checked registries in section 9.1. `ledger.json` is that row's signed
canonical ledger from section 11.2.1, with its own run-bound sequence domain.
Every ledger event references exactly one retained canonical typed source
record. Those records appear only under that row's closed source-role path;
their sequence paths are canonical and gap-free; and their signatures, run
context, provider-row identity, role, executable identity, and content
commitments verify exactly. Every `DecisionDurable` event also commits one
canonical supervisor-signed context and one exact canonical public decision
snapshot derived at the revision-one decision boundary. Those two records
appear only under the matching operation-ID paths above; their operation
roster is exactly the ledger's decision roster. The decision snapshot contains
only operation, profile, connection generation, revision, state/decision
class, common preparation commitments, receipt identity/byte/decoded-claim
commitments, and public recovery/receipt-trust identities. It MUST NOT contain
recovery-handle bytes, opaque profile state, issue/value/progress bytes,
provider result or observation data, sealed command bytes, provider payloads,
or raw receipt bytes. Each crash operation also retains exactly three
Supervisor-signed action contexts whose exact event projections are verified
independently by the observer and attester. Those action records bind the
immutable crash plan, control
identity and nonce, exact process start-time/executable/configuration/state and
cgroup commitments, the required `SIGKILL` result and empty cgroup, and the
new-generation restart identity. Their event hashes form the exact
`DecisionDurable -> FailpointAcknowledged -> ProcessKilled -> ProcessRestarted`
chain; missing, extra, reordered, or cross-operation action contexts fail
qualification. The observer and attester also independently verify the
decision supervisor signature, source identities, run/session/provider-row/process/ack
fields, decision-snapshot digest and schema, complete rederivation of the
`DecisionDurable` payload, and the retained decision receipt under the exact
retained anchor document. Ledgers and all source records count toward the
member and byte bounds. A projection report without the complete exact
provider-row ledger set is not evidence and cannot be signed.

`agentStateDirectorySha256` is the domain-separated commitment to the
normalized configured state-directory path and the exact opened directory's
device, inode, owner UID, and complete `0700` permission mode. The protected
launcher opens that directory without following symlinks, verifies the
commitment, and transfers only that read-only directory descriptor to the
qualification agent. The agent rederives the same commitment before opening
any state, and the controller opens the fixed `operations.cbor` journal member
relative to its retained descriptor. No crash evidence path may reopen the
state directory or journal through the mutable configured pathname after this
binding.

The protected signer treats the GitHub-downloaded directory and both files as
untrusted bytes, never executes a member, and independently validates this
entire contract before signing.

`reports/protected-observation.json` is a canonical signed envelope with schema
`auths.profile-qualification-observation/1`. Its record contains repository ID,
workflow path/revision, run ID/attempt, candidate revision, domain, target,
profile family, provider-run IDs and immutable provider artifacts, operation
IDs, connection generations, the exact release-build workflow/artifact roster
digest, the SHA-256 of the immutable hosted eighteen-member attester-tool identity
(repository/workflow/revision/run/attempt, artifact ID/name/archive digest and
size, retention timestamps, manifest and every member digest), external
provider call counts, provider truth, credential/journal
counter commitments, and a byte-sorted exact ledger roster whose rows contain
`providerRunId`, ledger digest, sealer key ID, and exact
source- and ledger-trust registry digests. It also contains the
receipt-trust-anchor digest, cleanup result, observed report digests, and
observation start/completion times. Its signature preimage is ASCII
`auths.profile-qualification-observation/1`, NUL, then canonical record bytes.
It is signed by the domain-scoped protected observer key and verified through
`observer-trust-keys.json`.

The observation also carries the exact recovery key ID and Ed25519 public key
of the exercised agent. Every independently source-signed `decision-durable`
journal-reader event carries that same recovery identity and the exact receipt
trust-anchor digest read from durable agent configuration. The protected
observer and final attester require exact equality across every provider-run
ledger, the signed observation, the exported receipt anchors, and the protected
deployment policy before applying the global key-separation check. A public
policy value without this authenticated exercised-agent binding is not
qualification evidence.

The observer executes only pinned trusted code, verifies the complete retained
source records and ledger, independently rereads durable journal/profile state,
and queries each provider through its independent read/audit credential. It
derives counters from the authenticated ledger and exact-compares them to those
independent rereads and candidate mismatch reports; independently validates and
re-exports the preliminary public receipt-anchor snapshot against the
source-signed exercised-agent trust commitment and the protected environment
digest; destroys all run-scoped resources with the cleanup
credential; signs the observation; and then creates the final evidence
container. Candidate code cannot write or replace the ledger, protected
observation, or cleanup result. Missing source records, an unverifiable ledger,
an inconclusive or mismatched observation, or incomplete cleanup prevents the
final upload and attestation.

`anchor-snapshots/receipt-trust-anchors.json` is a preliminary exact canonical
`auths.receipt-trust-anchors/1` public snapshot exported from the agent used by
the run solely for native receipt and ledger checks. The independently protected
observer verifies those exact bytes against every source-signed durable agent
trust commitment and then publishes the same bytes as
`reports/receipt-trust-anchors.json`; the collect-owned tree cannot author that
final report. `receiptTrustAnchorSha256` is SHA-256 over those exact JCS bytes.
The protected observer and signer compare it to the domain environment's protected
`AUTHS_QUALIFICATION_RECEIPT_TRUST_ANCHOR_SHA256` value before verifying any
receipt.

## 10. Common live environment requirements

Every provider environment is disposable, uniquely named from the workflow run
ID, and destroyed before the final cleanup report, evidence package, and upload
are created. Cleanup failure fails qualification and produces no signable
record. A provider account that cannot be created per run, such as the dedicated
Stripe test account, may persist; every run-scoped object, onboarded connection,
credential, and local durable directory is deleted or rotated, and the cleanup
report independently proves that state.

The runner MUST:

- consume the exact Rust binaries, wheels, and npm packages built from the
  candidate revision and clean lockfile by the authoritative no-secret release
  build, after verifying immutable artifact identity, digest, and provenance;
- use those same generated Python and TypeScript package bytes later published;
- prove the clean pre-import production agent omits every unqualified route and
  contains no failpoint activation path; run all pre-import real-provider
  scenarios through the exact-source qualification agent from the same release
  build; constrain its difference to the reviewed harness/failpoint surface;
  and never rebuild candidate code or use an in-process profile substitute;
- use production local-agent sockets, workload mapping, authority artifacts,
  connection administration, durable stores, receipt signers, and recovery
  keys;
- create provider resources through a bounded setup tool outside the
  application SDK;
- onboard the connection through the privileged Auths administration socket;
- execute generated SDK calls from clean Python and Node consumer projects;
- restart the actual agent process and reopen its persistent stores;
- verify provider truth independently of the Auths result; and
- tear down all provider resources and credentials.

Artifact ownership is split by trust zone. The authoritative no-secret release
build produces the immutable candidate binaries and packages before this
workflow. The collector produces only the unsigned proposal, candidate result
mismatch hints, and bounded preliminary reports. The secret-free installed-package job
produces only its canonical installed report. The protected
observation/cleanup job verifies the authenticated common ledger, independently
creates counter, provider-truth, cleanup, receipt-anchor, redaction, and
observation reports, consumes the installed report, and alone creates the
canonical final manifest and compressed `evidence.tar.zst`. The attester
independently verifies that final archive and signs its reconstructed record;
it does not fill missing reports or trust a candidate-authored success summary.
A run that cannot produce every member exactly once in its owning zone fails
closed.

Setup credentials and mutation credentials are distinct where the provider
supports it. Application processes receive neither. Evidence records only
credential commitments and lease counters.

## 11. Common qualification matrix

### 11.1 Ordinary and boundary scenarios

Every family MUST pass:

| ID | Scenario | Required assertion |
| --- | --- | --- |
| `happy-path` | one authorized effect | exact provider effect once, terminal applied result |
| `exact-boundary` | every numeric/count/byte maximum | inclusive maximum accepted where specified |
| `boundary-plus-one` | each hard maximum + 1 | rejected before credential and provider entry |
| `malformed-input` | noncanonical, unknown, missing, duplicate fields | typed rejection, no operation effect |
| `stale-evidence` | evidence at and beyond freshness edge | exact boundary behavior; stale is fail closed |
| `configuration-mismatch` | required/executed one-byte drift | no credential, provider call, or reservation leak |
| `connection-substitution` | alias/account/generation/scope mutation | indistinguishable denial before credential |
| `principal-substitution` | another IPC principal/token/handle | no existence disclosure or effect |
| `quota-final-capacity` | concurrent final admission/reservation | exactly one winner |
| `replay` | same idempotency and input | original operation/result/receipts, no second effect |
| `changed-input-conflict` | same idempotency, changed input | conflict naming original recovery identity, no second effect |
| `provider-denial` | real provider rejects before effect | exact not-applied classification only with provider proof |

### 11.2 Credential-order evidence

The qualification agent exposes test-only monotonic counters through a
protected harness, not production diagnostics. Every scenario records:

- connection rereads;
- credential lease attempts and successful leases;
- provider-entry markers;
- provider calls;
- durable provider-result writes;
- observation transitions; and
- receipt writes.

Denied, malformed, stale, mismatched, and over-limit cases require zero
successful mutation credential leases. The happy path requires the exact order
from AP-SPEC-040 section 14.1.

Counters are observed by the external supervisor or provider-side test proxy;
they are not accepted solely from the domain adapter under test. The report
binds every counter to run, operation, profile, connection generation, and
failpoint. The supervisor cross-checks counter transitions against durable
journal records and independent provider truth before a scenario can pass.

#### 11.2.1 Protected source-authenticated event ledger

The common harness MUST NOT reconstruct ordering, counters, attempts, or
receipt claims from candidate output or from a terminal journal snapshot. A
protected append-only event ledger is the only input from which those common
facts may be projected. Its exact canonical record binds the repository,
candidate/workflow/attester revisions, run and attempt, domain, target,
protected environment, provider-matrix row, supervisor-minted session nonce,
scenario, operation-plan phase, profile, operation, request, connection
generation, process boot generation, and failpoint.

Every ledger event has a global monotonic sequence, prior-event SHA-256,
source identity and immutable executable digest, journal revision where
applicable, closed event kind, bounded typed public fields, source-record
commitment, and the SHA-256 commitment of its exact canonical
`{sequence,source}` append marker. Publishing and flushing the source record
and that marker MUST complete before the event is acknowledged. Agent decision
and crash acknowledgements are separate retained records committed by their
signed Supervisor contexts; they are not caller-selected event fields.
Appending, flushing, and acknowledging the event MUST complete before a
failpoint can kill the agent.
Every `DecisionDurable` payload additionally carries
`supervisorContextSha256`, the SHA-256 of its retained canonical supervisor
envelope; that envelope in turn commits the exact canonical capability-free
decision snapshot derived from the revision-one private journal record. The
private `JournalRecordV1` and its recovery handle are never retained or
uploaded as evidence.
Every `RecoveryRequiredDurable`, `ReplayObserved`, `StatusObserved`, and
`RecoveryObserved` payload carries the store-derived projection commitment
plus the closed public `{state,effect,terminal,completion}` tuple. Every such
request projection must bind exactly one redacted logical attempt by
operation and request ID; multiple internal status or recovery projections may
belong to that same logical call, and its last projected tuple must equal the
SDK-visible outcome and completion. `Ready`/`Executing` remain nonterminal,
`RecoveryRequired` remains possible/nonterminal, and terminal tuples follow
the common lifecycle truth table.
Missing, duplicate, reordered, unrecognized, orphaned, or noncanonical events
fail closed. The final ledger is signed by a dedicated common ledger sealer
which links no domain adapter and receives its signing key only through a
dedicated non-inherited owner-only handle.

Each event kind has exactly one independently authenticated source:

| Source | Sole authoritative facts |
| --- | --- |
| protected supervisor | scenario/session identity, failpoint acknowledgement, kill, restart |
| protected client proxy | public request ingress, cancellation, and exact public response projection |
| journal reader | independently decoded durable decision, command, entry, result, observation, execution-receipt, recovery-required, terminal, replay, status, and recovery transitions |
| credential broker | fresh connection reread and credential lease attempt, success, and close |
| profile-state reader | reservation acquire, terminal successful disposition/handoff, release, and unresolved retention |
| provider transport proxy | authenticated, journal-bound acceptance into the sole at-most-once provider mutation obligation; real provider response boundaries; and separately typed recovery reconciliation request/observation boundaries |
| native receipt verifier | retained portable receipt bytes, IDs, signature/link/common claims, and profile-claim commitment |
| provider observer | independent redacted provider truth |

`ReservationConsumed` means the current operation reached its successful
terminal disposition. For a reviewed preflight operation this is the durable
handoff of the prepared capability to its paired effect operation even though
the preflight's provider effect is `not-applied`. For every reviewed
preflight/effect pair, the effect's `ReservationDurable` commitment MUST equal
exactly one earlier preflight `ReservationConsumed` commitment. A mutation
owner ending `not-applied` releases its reservation; a possible outcome retains
it. These plan-aware rules narrow, rather than replace, the common per-operation
counter algebra.

Each source runs under a distinct process identity and signing key. Source
seeds, the ledger-sealer seed, observer seed, attestation seed, receipt keys,
and recovery key are pairwise distinct. No process receives more than the one
source/observer/attestation private signing key required for its role;
candidate, installed-package, domain adapter, observer adapter, and attester
verifier processes receive no source or ledger private key. When authoritative
observation requires a provider credential, the credential-bearing reader/
broker/proxy and the minimal source signer are separate protected processes.
The signer receives only its source seed and a bounded canonical record over an
authenticated owner-only channel bound to the exact reader executable,
identity, run, and session; the reader never receives the seed. The protected
source trust registry binds each source role to one or more nonoverlapping key
IDs, public keys, validity intervals, allowed domains, source identities, and
immutable executable digests. Rotation may overlap validity but MUST NOT reuse
a key ID or public key across roles.

No source executable exposes a generic `sign-event`, arbitrary JSON event, or
caller-selected output command. A source role without its dedicated typed
reader-to-signer protocol fails closed before reading a seed and cannot
contribute a ledger event.

Candidate/runtime events are timing hints only. They are never the sole proof
of a journal transition, request, credential operation, provider call,
receipt, or provider effect. The ledger sealer verifies every source signature
and the exact source-role mapping before signing the complete hash chain. The
observer and attester independently repeat that verification.

The qualification-only CredentialBroker reader is the sole owner of the real
credential store and an exact broker-owned public connection snapshot. The
candidate agent receives only the sanitized public snapshot and a distinct
empty credential store. The immutable phase plan commits the exercised
workload-ID digest and the manifest-derived provider, connection contract,
descriptor schema, and credential scope. The broker kernel-authenticates the
agent UID, GID, executable, and process lifetime; exact-matches those phase
facts; independently resolves and rereads the connection; and invokes the
existing statically registered provider adapter. It durably appends and
acknowledges `ConnectionReread`, `CredentialLeaseAttempted`, and
`CredentialLeaseSucceeded` before releasing any deadline-bound credential
bytes. Current v1 adapters must complete their existing async lease future on
its first protected poll; `Pending` fails closed rather than introducing an
unaudited executor.

One operation retains one broker lease across response loss or an at/after-
entry agent restart. EOF without the explicit close frame detaches that lease;
an exact request reattaches it without a second attempt or success event. The
`after-lease` failpoint instead closes on EOF. An explicit close zeroizes the
lease, durably appends `CredentialLeaseClosed`, and returns one framed
acknowledgement. Loss of that acknowledgement uses a distinct read-only close
retry carrying the same canonical request; it can only recover the existing
signed close intent and cannot append or release another credential. Attempt,
success, and close payloads must share one lease commitment and their requested
and effective scope commitments must equal the common operation projection.
Every broker message uses the existing nonempty four-byte big-endian bounded
frame. Agent requests are
`u8(mode) || canonical QualificationCredentialLeaseRequest`, with mode zero for acquire/reattach and
mode one for close-acknowledgement retry. The explicit close and all positive
acknowledgements are the single byte `0x01`; zero, unknown, truncated,
oversized, noncanonical, or trailing messages fail closed.

The qualification-only ClientProxy bridge preserves the original SDK workload
identity without changing the production listener. The protected ClientProxy
reader exclusively owns the accepted SDK socket; candidate code never receives
or duplicates that descriptor. Before forwarding the exact bounded HTTP bytes
on a separate owner-only agent connection, the reader sends one nonempty
four-byte big-endian length-prefixed canonical
`auths.qualification-client-bridge-binding/1` record of at most 4,096 bytes.
That record commits the provider-row source context plus the SDK peer's kernel
UID, GID, PID, process start time, and executable digest. The qualification
agent accepts the bridge only from the exact protected reader UID and artifact,
rechecks that reader before and after the frame, independently re-observes the
live SDK process, and then supplies the rebound kernel identity to the unchanged
production workload authenticator and static router. The complete binding must
arrive within one 30-second monotonic deadline. Missing, zero, oversized,
truncated, noncanonical, stale-process, changed-reader, or policy-mismatched
bindings fail before HTTP dispatch. The backend socket remains `0660`. The
protected workflow installs its shared agent group and the
agent-owned:shared-agent-group `0710` parent; the crash controller independently
verifies that exact ownership, mode, and no-symlink path before launch and
restart. Neither boundary is widened to world access. The production binary has
no bridge selector or forwarded-identity path.

One logical SDK attempt may span preparation, prepare, execute, status, retry,
and recovery exchanges under one request ID. The ClientProxy reader therefore
keeps one bounded request-ID state machine: raw transport close is not a
terminal result. It emits the single terminal ClientProxy event only after the
protected SDK-consumer result boundary exact-binds the final canonical result
to the independently observed transport sequence. That terminal event carries
the bounded ordered roster of `ReplayObserved`, `StatusObserved`, and
`RecoveryObserved` route kinds decoded by the ClientProxy; final verification
requires byte-for-byte equality with the JournalReader projection-kind roster
for the same request. It never derives that event from candidate collection
output or from the first HTTP response.

For every reviewed scenario/operation-plan phase, the signed ledger commits
the canonical common phase projection and an exact contiguous event range.
Each provider-matrix row owns an independent ledger ID, session nonce,
hash-chain sequence domain, source-record namespace, and sealed ledger; rows do
not append to a shared cross-job file or reuse sequences. The aggregate
observer and attester require exact byte-sorted equality between this ledger
roster and `providerRuns` before projecting family-level evidence.
The protected verifier requires exact equality between the reviewed phase
roster and ledger phases; event operation IDs and request IDs and the projected
instances and attempts; native receipt events and retained receipt claims;
and derived reservation, reread, lease, entry, request-write, response,
provider-result, observation, receipt-write, terminal, release/consume, and
lease-close counters. Extra provider requests or resources cannot be hidden in
another phase or omitted from evidence. The supervisor derives the provider
namespace from trusted repository/run/domain/provider-row identity and the
observer independently enumerates that namespace; candidate resource lists
are mismatch hints only.

### 11.3 Crash matrix

A qualification-only build may contain a compile-time closed failpoint enum.
It accepts no arbitrary callback, path, command, or user string. Production
builds contain no failpoint code or route.

The supervisor runs each failpoint with a fresh operation, terminates the agent
at the named point, restarts it with the same durable state, calls status or
recovery, and independently checks provider truth.

The protected launcher accepts exactly one closed startup mode. `ordinary`
installs the qualification profile roster without any failpoint or crash
control arguments. `crash-after-decision` requires the complete generation,
control-operation, nonce, and acknowledgement tuple and installs only that
checkpoint. Mixed, partial, omitted, or unknown mode arguments fail before
candidate execution. Ordinary qualification and crash qualification use the
same protected digest-pinning, UID/GID reduction, sealed configuration, and
state-directory boundary.

The supervisor is an external child-process controller. It invokes installed
generated SDK packages against a qualification binary built from the exact
production source with only the named `qualification-failpoints` feature
enabled. It hard-kills the whole process with `SIGKILL` only after receiving a
durable, operation-bound acknowledgement on an owner-only qualification local
control channel. The selected failpoint is one closed enum value supplied at
startup; it cannot change during the process. Graceful shutdown is not crash
evidence.

Restart uses the same binary digest, UID, configuration digest, local-agent
authority, workload mapping, connection/credential/journal/profile stores,
receipt and recovery keys, and provider environment. Only process identity and
start time may change. The configuration bytes are supplied through a sealed
immutable file descriptor, and each launch receives a no-symlink, read-only
state-directory descriptor resolving to the same inode identity committed by
`agentStateDirectorySha256`. The production binary is separately built without that feature
and contains neither failpoint strings nor a route, environment variable,
callback, signal handler, dynamic dispatch point, or configuration field that
can activate them. CI inspects both binaries and rejects a production binary
that contains qualification failpoint machinery.

Every domain owns a generated `qualification/failpoint-coverage-v1.json` that
maps each durable lifecycle/provider transition to the exact before/after crash
IDs, applied/not-applied applicability, counter assertions, recovery call, and
provider-truth fields. The common runner requires exact set equality between
that manifest, the closed enum, journal transitions, and produced crash
reports; an uninstrumented durable boundary blocks qualification.

The closed crash points are:

| ID | Crash point | Required recovery truth |
| --- | --- | --- |
| `crash-before-decision` | before durable decision | no provider call; safe not-applied |
| `crash-after-decision` | decision durable, before reservation | no provider call; release/not-applied |
| `crash-after-reservation` | reservation durable, before command | no provider call; exact reservation released |
| `crash-after-command` | sealed command durable, before fresh reread | no provider call; release only after equality-safe recovery |
| `crash-after-reread` | equality proved, before credential | no provider call; release/not-applied |
| `crash-after-lease` | credential leased, before provider entry | no provider call; lease closed and state released |
| `crash-after-entry-marker` | provider entry durable, before call | possible until domain reconciliation proves no effect |
| `crash-after-request-write` | request may have reached provider | never blind retry; recover by provider evidence |
| `crash-after-provider-result` | result durable, before observation | observe stored result; no second call |
| `crash-after-observation` | observation durable, before linked execution receipt | mint and durably persist the linked execution receipt from durable truth |
| `crash-after-execution-receipt` | linked execution receipt durable, terminal projection not yet durable | verify and reuse that exact retained receipt, then conclude without reminting or making a second provider call |
| `crash-after-terminal` | terminal durable, response lost | return original result with `replayed` or `reconciled` completion |

For `crash-after-request-write`, "request may have reached provider" begins when
the protected ProviderProxy has authenticated and journal-bound the request,
redeemed its broker-owned lease, durably accepted the exact request into its
single at-most-once transport obligation, and received the source append ACK.
The proxy retains and completes that obligation across candidate death. This is
not a candidate-authored assertion that a socket write completed, and it never
authorizes a second mutation intent. `ProviderResponseObserved` remains strictly
after the real provider call returns a canonical response.

Each row runs once for the profile's applied result and, where the provider can
prove it, once for a not-applied provider rejection. Failpoints after provider
entry must never cause a second provider mutation request.

### 11.4 Response loss and cancellation

The transport proxy deterministically drops the provider response after the
request body is committed. The SDK then performs bounded read-only recovery.
The run asserts:

- no second execute request;
- stable operation and recovery IDs;
- the terminal result when provider evidence is conclusive;
- `RecoveryRequired` when evidence is genuinely inconclusive;
- restart preserves the same classification; and
- caller cancellation after request write does not become `Unavailable` or
  not-applied without proof.

### 11.5 Receipt matrix

For denied, applied, replayed, reconciled, and provider-proven not-applied
outcomes where applicable:

1. the agent verifies each portable receipt before terminal projection;
2. Rust verifies signature, validity, IDs, decision/execution link, profile,
   action, authority, connection, configuration, command, result, and
   profile-specific payload;
3. fresh installed Python and TypeScript packages verify the same portable
   containers and IDs;
4. one-bit mutation of every signed or linked component fails;
5. wrong trust root, expired key, wrong profile, wrong connection generation,
   and swapped decision fail; and
6. receipts reveal none of the domain-sensitive fields prohibited below.

## 12. Protected workflow and provenance

### 12.1 Trigger

`.github/workflows/profile-qualification.yml` contains the single reusable
workflow implementation. A generated, declarative entrypoint exists per
domain so GitHub can bind a constant protected environment and closed target
set without granting a caller control over either. The entrypoint contains no
domain commands or test logic; it calls the reusable workflow with the static
adapter ID generated from the profile-package manifest.

An entrypoint runs only through `workflow_dispatch` from a protected default
or release branch. The workflow definition is taken from that protected branch
and accepts one immutable candidate revision plus the immutable IDs/digests of
its successful authoritative no-secret release-build artifacts. Those
artifacts are built in a separate clean workflow before qualification, with no
protected environment or provider access, and GitHub provenance must bind them
to the candidate revision and pinned build workflow. The qualification
workflow never rebuilds candidate code. Adding a new domain regenerates an
entrypoint but does not copy or modify the common workflow implementation.

Pull requests run static qualification checks but cannot access provider
credentials or the attestation key. `pull_request_target` is forbidden.

Collection, installed-package verification, protected observation/cleanup, and
attestation are the four jobs and trust zones. The collection job may execute
candidate code and uploads only preliminary candidate evidence, but consumes
only the already-built immutable candidate artifacts. Candidate application and
SDK code runs inside an ephemeral workload sandbox/identity with no host
workspace, process namespace, environment, credential handle, or writable path
shared with protected services. It can reach only the authenticated production
local-agent protocol. Protected launchers, the production agent, brokers,
proxies, and one-key source processes run under separate protected identities
with narrow authenticated channels and exact environments; candidate processes
cannot inspect, signal, trace, or outlive them. The supervisor proves the
candidate sandbox and process group are destroyed before packaging or later
secret use. Setup, runtime-read, mutation, observer, cleanup, source-signing,
ledger, and attestation private inputs are never present together in one
process. Candidate build/package scripts and installed SDK consumer processes
receive none of them. Provider credentials are delivered only to their setup,
broker, proxy, or observer reader process; the distinct decision-receipt,
execution-receipt, and recovery seeds are delivered only to the production
agent through separate owner-only configured handles; and evidence-source keys
are delivered only to minimal source-signer processes that receive no provider
credential. The collector cannot author protected provider truth, perform
authoritative cleanup, or sign an observation or attestation.

The installed-package job receives no secret and has no provider or public
network access. It executes a harness checked out at the protected attester
revision against clean candidate-built Rust artifacts, wheels, and npm
packages, using signer-selected receipt fixtures and runtime-generated mutation
cases. It uploads the bounded canonical verification report that the protected
observer binds into final evidence. Candidate build or package scripts never
run anywhere in the qualification workflow, and no package manager, compiler,
build script, or downloaded artifact executes in a secret-bearing step.

The observation/cleanup job executes only prebuilt, digest-checked protected
attester-revision code. It
receives a distinct independent provider-observer credential, cleanup
credential, and observer signing seed; receives no mutation or attestation
seed; queries provider truth and protected counters; exports public receipt
anchors; cleans up; and produces the final evidence artifact and signed
observation from section 9.6. Observation has a shorter step timeout and may
fail without ending the job. A separate idempotent cleanup command runs under
`if: always()` with trusted run identity and enough remaining job time, even
when preliminary evidence is absent, malformed, or rejected. Final packaging
requires both successful observation and an exact per-provider-row cleanup
report. This is a separate step within the third job, not a fifth trust zone.

The final attestation job also executes only prebuilt, digest-checked protected
attester-revision code. A no-secret verifier safely snapshots the uploaded
archive, independently reconstructs one canonical `verified-record.json`, and
emits its digest and protected run binding. A separate minimal signer process
receives only that domain's attestation seed and public key ID, reopens that
exact record without following links, validates the binding and digest, and
signs it. The process parsing attacker-controlled archive data never receives
the attestation seed. Neither process receives provider, receipt, recovery,
source, ledger, cleanup, or observer secrets and neither executes a downloaded
artifact member or candidate script. `secrets: inherit` is forbidden in every
job.

Every action is pinned by full commit SHA. Job permissions are explicitly
minimal, dependency installs use locked repository inputs, the runner label and
GitHub image release are recorded in provenance, and no mutable network
download or `curl | shell` installation occurs. The protected attester revision
is independent of the candidate revision and is reviewed before it is placed
in the environment variable.

### 12.2 Protected environments

Required environments are:

- `qualification-stripe`;
- `qualification-postgresql`; and
- `qualification-opentofu`.

Each requires reviewer approval and restricts permitted branches. Provider
credentials, receipt signing seeds, recovery signing seeds, and qualification
attestation keys are separate secrets. A domain environment cannot sign
another domain's record unless the trust policy explicitly lists that key for
both domains.

Each environment requires at least two reviewers; the dispatching actor cannot
approve its own deployment; administrator bypass is disabled; only the
protected default branch and protected `release/*` branches may deploy; and
workflow dispatch permission is limited to the release-maintainer team. The
workflow records the approval IDs without reviewer names in public evidence.

GitHub environment secrets cannot be forwarded by a caller into a reusable
workflow. Therefore the generated entrypoint passes only constant
domain/adapter/target/environment inputs and no `secrets:` mapping. Each
secret-bearing job in the reusable workflow declares that constant protected
environment and reads the following generic exact slot names stored separately
inside that environment. Every applicable slot is required and no private key
or credential may occupy two roles:

| Role | Exact environment secret |
| --- | --- |
| setup credential | `QUALIFICATION_SETUP_CREDENTIAL` |
| runtime evidence-read credential | `QUALIFICATION_RUNTIME_READ_CREDENTIAL` |
| mutation credential | `QUALIFICATION_MUTATION_CREDENTIAL` |
| independent observer credential | `QUALIFICATION_OBSERVER_CREDENTIAL` |
| cleanup credential | `QUALIFICATION_CLEANUP_CREDENTIAL` |
| decision receipt seed | `QUALIFICATION_DECISION_RECEIPT_SEED` |
| execution receipt seed | `QUALIFICATION_EXECUTION_RECEIPT_SEED` |
| recovery seed | `QUALIFICATION_RECOVERY_SEED` |
| observer signing seed | `QUALIFICATION_OBSERVER_SEED` |
| attestation seed | `QUALIFICATION_ATTESTATION_SEED` |
| supervisor event-source seed | `QUALIFICATION_SOURCE_SUPERVISOR_SEED` |
| client-proxy event-source seed | `QUALIFICATION_SOURCE_CLIENT_PROXY_SEED` |
| journal-reader event-source seed | `QUALIFICATION_SOURCE_JOURNAL_READER_SEED` |
| credential-broker event-source seed | `QUALIFICATION_SOURCE_CREDENTIAL_BROKER_SEED` |
| profile-state-reader event-source seed | `QUALIFICATION_SOURCE_PROFILE_STATE_READER_SEED` |
| provider-transport-proxy event-source seed | `QUALIFICATION_SOURCE_PROVIDER_PROXY_SEED` |
| native-receipt-verifier event-source seed | `QUALIFICATION_SOURCE_RECEIPT_VERIFIER_SEED` |
| provider-observer event-source seed | `QUALIFICATION_SOURCE_PROVIDER_OBSERVER_SEED` |
| common ledger-sealer seed | `QUALIFICATION_LEDGER_SEALER_SEED` |

The same names refer to different environment-owned values in
`qualification-stripe`, `qualification-postgresql`, and
`qualification-opentofu`; repository/org fallbacks and domain-prefixed or
legacy aliases are forbidden. Protected variables are
`AUTHS_QUALIFICATION_ATTESTER_REVISION`,
`AUTHS_QUALIFICATION_AGENT_CONFIG_BASE64URL`,
`AUTHS_QUALIFICATION_ATTESTATION_KEY_ID`,
`AUTHS_QUALIFICATION_OBSERVER_KEY_ID`,
`AUTHS_QUALIFICATION_RECEIPT_TRUST_ANCHOR_SHA256`,
`AUTHS_QUALIFICATION_RECOVERY_KEY_ID`,
`AUTHS_QUALIFICATION_RECOVERY_PUBLIC_KEY_BASE64URL`,
`AUTHS_QUALIFICATION_WORKLOAD_ID_SHA256`, and
`AUTHS_QUALIFICATION_RETENTION_DAYS`,
`AUTHS_QUALIFICATION_EVIDENCE_SOURCE_TRUST_SHA256`, and
`AUTHS_QUALIFICATION_EVIDENCE_LEDGER_TRUST_SHA256`,
`AUTHS_QUALIFICATION_LEDGER_KEY_ID`,
`AUTHS_QUALIFICATION_SUPERVISOR_SOURCE_UID`,
`AUTHS_QUALIFICATION_JOURNAL_READER_UID`,
`AUTHS_QUALIFICATION_AGENT_UID`,
`AUTHS_QUALIFICATION_AGENT_GID`,
`AUTHS_QUALIFICATION_ATTESTER_TOOLS_RUN_ID`,
`AUTHS_QUALIFICATION_ATTESTER_TOOLS_RUN_ATTEMPT`,
`AUTHS_QUALIFICATION_ATTESTER_TOOLS_ARTIFACT_ID`,
`AUTHS_QUALIFICATION_ATTESTER_TOOLS_ARTIFACT_DIGEST`, and
`AUTHS_QUALIFICATION_ATTESTER_TOOLS_MANIFEST_SHA256`. The evidence-source and ledger
trust values are SHA-256
over the exact canonical checked registries at
`release/qualification/v1/evidence-source-trust-keys.json` and
`release/qualification/v1/evidence-ledger-trust-keys.json`. The five attester
tool values select the exact successful run and attempt of
`.github/workflows/qualification-attester-tools.yml`, its attempt-specific
immutable hosted artifact, uploaded archive digest, and canonical manifest digest. That
provider-free no-secret workflow builds the release verifier at the protected
attester revision, snapshots the exact GitHub CLI and trusted root, and
downloads Gitleaks 8.28.0 by its published archive SHA-256; its closed
eighteen-member manifest binds each regular member's path, mode, digest,
attester revision, GitHub CLI version, exact 90-day retention policy, pinned
runner label, and runtime `ImageOS`/`ImageVersion`. Protected jobs safely extract this
artifact, verify the manifest before using any member, and map the three
verification members to `QUALIFICATION_RELEASE_VERIFIER`,
`QUALIFICATION_GH_CLI`, and `QUALIFICATION_GH_TRUSTED_ROOT`, and the fourth to
the sign-only `QUALIFICATION_ATTESTATION_SIGNER`. A separate
`QUALIFICATION_OBSERVATION_SIGNER` receives only the observer seed and one
closed aggregate observation record. The manifest supplies their corresponding
SHA-256 variables. The pinned `gitleaks` member is invoked only by its exact
verified path and digest for protected pre-sign and final evidence scans. The
protected `qualification-crash-controller` independently commits the
supervisor and journal-reader source evidence before sending SIGKILL to the
isolated qualification agent. The protected `qualification-source-supervisor`
and `qualification-source-journal-reader` members each receive only their own
source seed and authenticate the controller over their closed IPC boundary.
The protected `qualification-source-client-proxy`,
`qualification-source-credential-broker`,
`qualification-source-profile-state-reader`,
`qualification-source-provider-proxy`,
`qualification-source-receipt-verifier`, and
`qualification-source-provider-observer` members likewise accept only their
closed role-specific observation record from an authenticated protected reader
and receive only that source's seed after validation. Candidate-built source
binaries are never trusted with any of those keys. The
protected `qualification-agent-launcher` pins and seals the candidate agent
before entering the delegated cgroup; its exact protected member digest and
the pairwise-distinct controller, Supervisor-source, journal-reader, and agent
OS identities are committed in the signed crash context and independently
rebound during final verification. The protected
`auths-qualification-supervisor` seals the common ledger while receiving only
the ledger-sealer seed on standard input; candidate-built copies are never
trusted with that key. The eighteenth
member is the attester-revision `xtask` used only for provider-free
archive and receipt verification. The same identities are rebound in the final verified
release-build handoff. Retention
and trust commitments are protected policy inputs, not workflow-dispatch
inputs.

No command ingests multiple raw secrets merely to compare them. Each
secret-bearing process receives exactly its one allowed private input (or the
one provider credential its role requires), rejects every other known role
name in its environment, and proves that its derived public identity or
domain-separated opaque credential identity commitment matches the frozen role
commitment. A separate no-secret policy step compares only those canonical
public commitments, checked key IDs, provider-issued credential identity
commitments, and environment metadata for global nonoverlap across every
domain and role. Provider credential helper processes must durably copy no
secret and expose no reusable credential value. Legacy combined receipt seeds,
unregistered aliases, a duplicate commitment, or an extra role variable fail
closed. This preserves one-key-per-process isolation while making workflow
misconfiguration detectable.

### 12.3 Artifact production

The collector first uploads bounded preliminary candidate evidence. The
protected observation/cleanup job treats it as untrusted data, independently
observes provider truth, cleans up, and uploads the one final compressed raw
evidence artifact described in section 9.6. Before final upload it:

- enforces the 512 MiB bound;
- scans text and binary metadata for provider secret fingerprints and known
  fixture secrets;
- redacts approved provider identifiers through typed report serializers;
- runs Gitleaks 8.28.0 over the extracted evidence directory;
- writes a canonical file manifest with SHA-256 and byte length; and
- proves that every expected scenario report exists exactly once.

The attestation verifier safely extracts a fresh snapshot of the uploaded
object and independently reruns the pinned Gitleaks 8.28.0 scan and closed
typed forbidden-field/content scan over every member. It recomputes the scan
reports and coverage rather than accepting observer-authored `passed`
booleans. Signing occurs only after those scans pass, final upload succeeds,
and the artifact digest is re-read from the uploaded object.

Collection, installed-package verification, observation/cleanup, and
attestation are separate jobs with the secret exposure in section 12.1. The
attestation job uses the independent
verification procedure in section 9.3 and MUST NOT sign merely because either
earlier job exited zero. Every artifact download path is treated as untrusted
and normalized according to the pinned artifact action's exact versioned
layout.

### 12.4 Import and promotion

Promotion is a separate reviewed commit. `xtask` verifies the attestation and
recomputes the current semantic closure. The import transaction may write only
these generated projections:

- the domain/target attestation under `release/qualification/v1/attestations/`;
- `release/qualification/v1/index.json`;
- the production qualification fields in the roster-v2 projection; and
- `product/runtime/auths-node/src/generated/profile_launch_projection.json`,
  purely regenerated from that roster.

The semantic freeze contains an immutable
`auths.product.profile-qualification-launch` contract entry that binds the
roster/launch schemas, parsers, generation rules, import rules, and production
versus testkit isolation. Dynamic qualification IDs, targets, attestations,
and launch state do not appear in the semantic freeze and import never edits
it. Generated Rust route source is state-independent and is not an import
projection.

It MUST NOT edit normative specifications, profile manifests, runtime/domain
source, workflow source, generator source, package inputs, or any other
semantic closure input. Qualification-only projections are normalized at exact
generator-owned structural sites when computing the pre-import closure, and
the importer proves by pure regeneration that no executable or non-projection
bytes changed. Marker-delimited arbitrary-byte normalization is forbidden. The
closure policy is loaded from the protected attester revision, exact-compared
to the candidate declaration, and always includes itself; a candidate cannot
exclude or omit semantic inputs. Any output outside this allowlist or any
non-projection semantic change invalidates import.

CI rebuilds production and testkit agents and proves:

- the production binary advertises exactly qualified profiles for its target;
- the testkit binary advertises only profiles with `testkitAvailable: true`;
- deleting, mutating, expiring, or swapping an attestation removes the route;
  and
- an unqualified generated client fails before request dispatch.

Import is a crash-resumable repository transaction. Under one repository-wide
advisory lock it durably writes a transaction intent before creating stage
files. The intent embeds and hashes the old and new attestation, index, roster,
and launch-projection bytes, and binds both the immutable candidate revision
and the exact promotion-base revision. Every resume
revalidates the signature, domain/target/family, current immutable revision,
semantic closure, artifact identity, trust policy, and monotonic replacement
rules before promoting any stage. Each stage is same-directory, bounded,
fsynced, and idempotent; directory entries are fsynced after promotion. A crash
before or after every intent, stage, rename, generation, and verification
boundary is tested. Resume either completes the exact transaction or restores
the exact prior state; it never leaves a mixed roster/index/attestation state or
untracked stage files.

Requalification can repair ordinary closure drift even when the previously
checked attestation no longer validates against the new closure, but it cannot
weaken evidence. Replacement is accepted only for the same domain, target, and
atomic family; a later protected completion; an allowed current trust key; an
equal or stronger scenario, target, and retention policy; and a record
independently verified against the current immutable tree. No old record
reader, migration, dual roster, or compatibility state is retained.

### 12.5 Retained evidence verification

The checked record stores an immutable hosted artifact locator and digest, not
an expiring download URL. Hosted release CI authenticates to the artifact
service, fetches that exact artifact ID, verifies repository/workflow/run
ownership, creation and expiry times, configured retention, archive digest,
recorded byte length, and the extracted canonical manifest. Missing, expired,
replaced, truncated, or inaccessible evidence fails release qualification.
Local pull-request checks validate the signed metadata without claiming hosted
retention. Running binaries remain bound to their checked record, but no new
release may advertise evidence that the release gate cannot retrieve and
verify.

## 13. Stripe qualification

### 13.1 Prerequisite implementation closure

The route for `auths.stripe.refund/1` MUST use the existing bounded refund
vertical from AP-SPEC-0012. It MUST NOT authorize directly from only
`paymentIntent`, `amount`, and `currency`.

Before qualification, implementation and tests prove:

- the configured bounded refund policy and its digest are loaded securely;
- fresh Stripe evidence names the exact test account, PaymentIntent, charge,
  refundable amount, currency, and evidence time;
- the AP-SPEC-0012 evaluator runs before durable eligibility;
- per-refund and aggregate budget reservations use the existing domain state;
- the sealed Stripe command is derived only from the authorized canonical
  action;
- fresh account, connection generation, configuration, PaymentIntent, charge,
  and refundable amount are rechecked after sealing and before credential
  lease/provider entry;
- the credential scope is exactly `stripe.refunds.write/1`;
- reconciliation queries a stable Auths-bound idempotency marker and cannot
  confuse another refund; and
- Stripe-specific receipt payloads commit policy, evidence, reservation,
  command, provider result, and reconciliation truth.

The existing five-profile roster is unchanged. `auths.stripe.refund/1` also
depends on the manifest-declared, connection-owned protected preparation
evidence lease from AP-SPEC-040 section 13.4.1 and AP-SPEC-041. Qualification
must exercise the generated companion route through the installed SDK, bind
the broker binary and configuration to release artifacts, and retain exact
source-authenticated request/response counts for both the preliminary and
command-bound evidence reads. The companion is not advertised or attested as
another profile.

The synthetic testkit adapter remains a separate test-only implementation and
is not evidence for this section.

### 13.2 Live environment

Qualification uses a dedicated Stripe test-mode account and pinned Stripe API
version from AP-SPEC-041. `sk_live_` credentials are rejected. Setup creates a
test PaymentIntent, confirms it, captures it, and records only redacted public
identifiers in the harness. The mutation credential is onboarded through the
privileged connection admin socket and is never available to the SDK process.
Setup, evidence-read/audit, and refund-mutation credentials are three distinct
restricted test-mode keys with exactly the permissions selected in the domain
provider matrix; the SDK, client-proxy, evidence-read, and observer processes
never receive the mutation key. Only the production connection/credential
broker may lease it after the common lifecycle gates pass.

### 13.3 Stripe scenarios

In addition to section 11:

| ID | Assertion |
| --- | --- |
| `stripe-account-equality` | descriptor account, live account discovery, evidence account, and response account match |
| `stripe-api-version` | request and response use the pinned API version; drift denies before mutation |
| `stripe-refund-boundary` | exact per-refund limit succeeds; one minor unit over denies |
| `stripe-aggregate-budget` | concurrent final aggregate capacity has one winner |
| `stripe-refundable-drift` | a changed refundable amount after decision denies/releases before provider entry |
| `stripe-existing-refund` | reconciliation distinguishes original Auths refund from unrelated refunds |
| `stripe-timeout-after-write` | dropped HTTP response recovers the exact refund without a second create request |
| `stripe-redaction` | no secret, client secret, card data, or unredacted provider body appears in evidence |
| `stripe-preparation-evidence-lease` | unauthorized, expired, replayed, or cross-binding handles perform no mutation; exact replay performs no second evidence read |
| `stripe-command-bound-reread` | the pre-entry observation is strictly newer, command-bound, and critical-fact equal before credential lease |
| `stripe-evidence-read-count` | the exact account, PaymentIntent, and charge reads occur once in each declared phase with no hidden, duplicate, or reordered provider request |

The provider-truth check queries Stripe independently and requires exactly one
refund with the Auths idempotency marker and exact amount/currency.

## 14. PostgreSQL qualification

### 14.1 Prerequisite implementation closure

Before qualification:

- onboarding binds TLS server name, certificate trust, host/port, database,
  executor role, account commitment, and exact supported scopes;
- connection opening enforces those committed destination facts rather than
  trusting descriptor labels;
- preflight runs the AP-SPEC-042 evaluator, including RLS enabled/forced,
  role/privilege, primary-key, tenant, policy, trigger, schema, configuration,
  evidence-age, row-count, and audience checks;
- update prepare reruns the evaluator over independently stored canonical
  action, evidence, and configuration bytes;
- execute rechecks server identity, database, role, RLS, privilege, primary
  key, policy, trigger, schema, configuration, and exact before-row versions
  inside the serializable transaction;
- the immutable committed execution ledger is sufficient to prove an applied
  operation after response loss; later row drift is supplemental observation
  and cannot erase proven commit truth;
- claim/reservation conflicts release any losing prepared-store reservation;
  and provider results exactly match the sealed command and claimed token; and
- prepared storage satisfies AP-SPEC-042's independent fields, commitments,
  per-principal record/byte quotas, secure file rules, expiry, and GC behavior.

### 14.2 Live environment

The initial closed supported-major registry is `{16, 17, 18}`. Qualification
starts a separate disposable TLS PostgreSQL instance and protected provider run
for every listed major; it does not infer an intermediate major from endpoint
tests. The checked provider matrix pins the current patch-level immutable image
digest for each major. Adding or removing a major changes the semantic closure
and requires a new attestation. Each run creates:

- a database named uniquely for the run;
- a no-login owner/migration role;
- a least-privilege read-only preflight role;
- a separate bounded-update executor role;
- a tenant table with explicit primary key, row-version column, RLS enabled and
  forced, exact policy, and allowlisted trigger; and
- the immutable Auths execution ledger migration.

The runner validates TLS and server identity and connects through the same
adapter used by production. The version numbers, immutable container digests,
TLS profile, extension set, and role grants come only from the checked domain
provider matrix; an unlisted server version or image is not qualification
evidence.

### 14.3 PostgreSQL scenarios

| ID | Assertion |
| --- | --- |
| `postgresql-preflight` | discovery stores one exact prepared update without mutation |
| `postgresql-serializable-update` | exact bounded update commits once with immutable ledger row |
| `postgresql-role-equality` | wrong database, role, TLS identity, or privilege fails before mutation credential use |
| `postgresql-rls-policy` | disabled/unforced RLS or policy/trigger drift fails closed |
| `postgresql-row-drift` | row-version drift between preflight and execute rolls back completely |
| `postgresql-row-boundary` | maximum rows succeeds; maximum + 1 denies before update |
| `postgresql-transaction-kill` | backend termination before commit proves not-applied; after commit recovers applied from ledger |
| `postgresql-response-loss` | lost commit response recovers from immutable ledger without rerunning SQL |
| `postgresql-later-drift` | a later authorized row change does not erase earlier committed operation truth |
| `postgresql-value-redaction` | prepared storage, evidence, receipts, and logs contain no tenant or assignment values |

Independent provider truth reads the ledger and target rows through a separate
audit role. It does not trust the Auths result or executor connection.

## 15. OpenTofu qualification

### 15.1 Prerequisite implementation closure

Before qualification:

- planning and apply run in an OS-enforced sandbox under the configured
  dedicated identity;
- the sandbox has a closed filesystem view, bounded resources, no inherited
  secrets, and network access only to the pinned dependency mirror and backend;
- HCL modules and dependency locks are structurally parsed; substring matching
  is forbidden;
- every provider and module source/version/checksum exactly matches the
  allowlist and lock closure;
- the OpenTofu executable is opened no-follow, hashed, identity-checked, and
  executed without reopening a mutable path;
- raw saved plans are encrypted at rest with deployment-managed keys, stored
  in owner-only no-follow files, quota-bound, expiry-bound, securely removed,
  and never included in evidence;
- prepared metadata and artifact state are atomically coupled and satisfy
  AP-SPEC-043's independent commitments and per-principal quotas;
- apply rechecks backend identity, workspace, state lineage/serial/digest,
  configuration, variables, lockfile, modules, tool build, artifact digest,
  connection generation, and exact plan projection after sealing and before
  credential lease;
- the single operation-bound recovery record selected by the checked provider
  matrix lets reconciliation prove which exact apply committed after response
  loss; and
- result observation exactly matches the sealed plan handle and command.

The v1 target is only `linux-x86_64`. Other targets are post-v1 scope and require
their own OS sandbox and live attestation.

### 15.2 Live environment

Qualification uses:

- a pinned OpenTofu release by SHA-256;
- a pinned provider mirror containing only the allowlisted provider and module
  closure;
- a disposable isolated backend and workspace;
- a deterministic test module whose real provider effect creates or updates
  one sandbox-owned resource; and
- a dedicated unprivileged sandbox identity with no host home-directory or
  repository write access.

The concrete Linux sandbox, namespace, filesystem, egress, resource-limit,
encrypted-artifact, key-rotation, backend, and operation-bound recovery-record
contracts are the exact values in the checked domain provider matrix. An
implementation-chosen sandbox or alternate marker/ledger is forbidden.

The source bundle is read-only. Variables enter through the protected
configuration boundary and never the evidence bundle.

### 15.3 OpenTofu scenarios

| ID | Assertion |
| --- | --- |
| `opentofu-protected-plan` | real plan produces one prepared token and exact non-destructive projection |
| `opentofu-sandbox` | provider cannot read host secrets, write outside output/backend roots, or open forbidden network destinations |
| `opentofu-lock-closure` | unknown provider/module, checksum drift, or widened source fails before planner credential use |
| `opentofu-tool-identity` | executable path swap, digest drift, or version drift fails closed |
| `opentofu-plan-integrity` | raw artifact or prepared metadata mutation is rejected before apply |
| `opentofu-state-drift` | lineage, serial, or state digest drift denies before mutation |
| `opentofu-destructive-denial` | destroy/replacement projection acquires no apply credential |
| `opentofu-response-loss` | lost apply response recovers from operation-bound backend truth without a second apply |
| `opentofu-applied-marker` | unrelated backend state change cannot satisfy reconciliation |
| `opentofu-artifact-redaction` | no source, variable, lock text, raw plan, backend credential, or decrypted artifact enters evidence |

Independent provider truth checks the backend marker, resulting state, and
sandbox-owned resource without trusting the Auths result.

## 16. Receipt and trust closure

The current generic decision/execution envelope is insufficient by itself.
Before any profile qualifies, the static profile registration supplies a
profile-specific receipt builder and inspector. The durable journal stores the
exact commitments needed to rebuild and verify:

- canonical action and authority;
- connection ID, generation, account/destination commitment, and scope;
- required and executed configuration;
- reservation or prepared-token transition;
- sealed command;
- durable provider result;
- observation and reconciliation basis; and
- domain-owned public payload claims.

Every terminal projection re-verifies its persisted receipt pair. A corrupted,
expired, wrong-key, wrong-profile, or claim-mismatched receipt converts the
operation to a registered internal/recovery failure without changing provider
effect truth. It is never returned as a successful terminal projection.

Production receipt signing keys and public trust anchors are deployment-owned.
They are distinct from recovery keys and qualification keys. The operator can
export public anchors through a bounded administrative command; applications
cannot choose or replace them during an operation.

### 16.1 Receipt-key configuration

The agent loads one `auths.receipt-signing-config/1` document at startup. It
contains distinct `decision` and `execution` entries with algorithm `Ed25519`,
1-128-byte registered key ID, 1-512-byte verification-method ID, owner-only
seed-file source, `notBeforeUnixSeconds`, and `notAfterUnixSeconds`. Seed files
are exactly 32 bytes, opened no-follow from an owner-only directory, identity
checked before and after read, copied into zeroizing memory, and never exposed
through diagnostics. Key IDs, methods, validity intervals, or public keys may
not collide across roles. Recovery and qualification key commitments are
compared at startup and equality is rejected.

Rotation supplies the current decision/execution pair plus at most seven prior
decision/execution public pairs, for at most 16 exported anchors. New
operations use the current pair. Historical terminal
projection verifies signatures at receipt issuance time and verifies that the
key remains in the deployment's retained trust set; it does not reject a valid
historical receipt merely because the signing interval later ended. Removing a
still-referenced public key fails startup until retention or durable operations
permit removal.

### 16.2 Static profile receipt contract

Generated profile registration names three concrete, statically linked domain
functions for each profile: build decision claims, build execution claims, and
inspect/verify profile claims. They receive typed profile journal projections
and return bounded canonical claim bytes. They accept no trait object,
callback, operation tag, arbitrary JSON, or dynamically selected module. The
generator checks exact function presence and the domain package owns the claim
schema and fixtures.

Every direct completion, status read, idempotent replay, recovery,
reconciliation, pending-to-terminal transition, and receipt export re-verifies
the linked pair and the profile claims before returning a terminal success.
The verification inputs are the persisted journal, current profile
registration, retained deployment trust set, and persisted canonical profile
commitments; caller input cannot replace them.

A terminal receipt integrity failure uses the newly registered
`core.terminal-receipt-integrity-failed` code with owner `core`, operation
`resume`, stage `receipt`, family `internal`, retry `never`, recommended action
`contact-support`, and the durable operation's truthful `not-applied`, `possible`,
or `applied` effect. The exact nine-key `auths.profile-operation/1`
`receipt-integrity-failed` variant defined by AP-SPEC-040 carries the durable
state, effect, and terminal bit while exposing no receipt, recovery, progress,
partial, or success bytes. Its issue correlation/execution identity and
entered-provider boundary bind that same operation and state. It carries
execution, decision, and execution-receipt references when available; a
decision receipt is never reused as the execution-receipt reference.
It never changes provider truth, permits blind retry, or projects success.

### 16.3 Public trust-anchor export

The privileged command is:

```text
auths agent receipt-anchors export --config <agent.toml> --output <path>
```

It emits canonical JSON schema `auths.receipt-trust-anchors/1`, at most 64 KiB,
with 1-16 byte-sorted anchors containing role, key ID, verification method,
Ed25519 public key, and validity interval. It never emits a seed or recovery or
qualification key. The command requires the same local administrator authority
and secure configuration checks as connection administration, refuses unknown
or repeated options and symlink/non-regular targets, writes a same-directory
owner-controlled temporary file, fsyncs it, atomically publishes without
overwriting an existing file, and fsyncs the parent directory. Anchor rotation
is performed only by replacing the agent configuration and restarting; there
is no runtime mutation route.

## 17. Security and redaction

### 17.1 Forbidden evidence

Raw and checked evidence MUST NOT contain:

- provider mutation credentials, setup credentials, authorization headers, or
  cookies;
- Stripe secrets, client secrets, payment method/card data, or raw provider
  bodies;
- PostgreSQL passwords, row values, tenant values, assignment values, or SQL
  parameters;
- OpenTofu variable values, source contents, dependency-lock text, raw plans,
  backend credentials, or decrypted artifacts;
- recovery handles, receipt signing seeds, authority signing seeds, or
  qualification signing keys; or
- unredacted process environments or home-directory paths.

Typed evidence serializers use allowlists. Arbitrary stdout/stderr capture is
not evidence. Provider tools run with bounded output; rejected output is
discarded after an in-memory secret scan.

### 17.2 Secret scanning

The protected workflow scans:

1. the candidate Git diff through the repository's standard CI policy;
2. generated packages;
3. qualification reports and manifests;
4. bounded process output retained as evidence; and
5. the final compressed artifact after extraction verification.

A finding prevents signing. Broad path or rule allowlists are forbidden.

## 18. APIs and command contracts

The following commands are normative additions:

```text
cargo xtask profile qualification closure --domain <domain>
cargo xtask profile qualification status [--domain <domain>]
cargo xtask profile qualification run --domain <domain> --target <target> \
  --environment <registered-token>
cargo xtask profile qualification collect --domain <domain> --target <target> \
  --environment <registered-token> --provider-run <registered-token> \
  --output <directory>
cargo xtask profile qualification build-cleanup-contexts --domain <domain> \
  --target <target> --environment <registered-token> --output <directory>
auths-qualification-supervisor initialize-ledger --plan <canonical-plan> \
  --common-root <owner-only-common-root> --source-trust <registry> \
  --ledger-trust <registry>
auths-qualification-supervisor prepare-row-runtime --plan <canonical-plan> \
  --source-trust <registry> --receipt-trust <anchors> \
  --runtime-root <new-row-root> --cgroup-root <new-delegated-cgroup-root>
auths-qualification-supervisor export-receipt-anchors \
  --config-output <new-config> --anchors-output <new-anchors> \
  --expected-sha256 <protected-digest>
auths-qualification-supervisor serve-append-session --plan <canonical-plan> \
  --common-root <owner-only-common-root> --source-trust <registry> \
  --socket <new-protected-socket>
auths-qualification-supervisor stage-common-phases --plan <canonical-plan> \
  --candidate-collection <canonical-collection> \
  --common-root <owner-only-common-root> --source-trust <registry> \
  --receipt-trust <anchors>
auths-qualification-supervisor build-event-index --plan <canonical-plan> \
  --common-root <owner-only-common-root> --source-trust <registry>
auths-qualification-supervisor assemble-ledger --plan <canonical-plan> \
  --event-index <canonical-index> --common-root <owner-only-common-root> \
  --source-trust <registry> --output <new-record>
auths-qualification-supervisor seal-ledger --record <canonical-record> \
  --source-trust <registry> --ledger-trust <registry> \
  --output <new-ledger> --key-id <protected-ledger-key-id>
qualification-crash-controller run-phase \
  --admin-socket <path> --agent-socket <path> \
  --agent <candidate-agent> --agent-config <config> \
  --agent-launcher <protected-launcher> \
  --agent-state-directory <protected-state-directory> \
  --agent-uid <protected-distinct-uid> \
  --agent-gid <protected-distinct-gid> \
  --cgroup <new-delegated-cgroup> \
  --decision-supervisor-socket <protected-row-session-socket> \
  --journal-reader-socket <protected-session-socket> \
  --principal <principal> \
  --profile-state-reader-socket <protected-reader-socket> \
  --receipt-trust <anchors> \
  --receipt-verifier-socket <protected-reader-socket> \
  --sequencer-socket <protected-append-socket> \
  --signer-socket <protected-signer-socket> \
  --ledger-plan <canonical-plan> --source-trust <registry> \
  --scenario <id> --phase-index <index>
qualification-source-journal-reader serve-decision \
  --socket <new-protected-socket> --sequencer-socket <protected-append-socket> \
  --append-mode <new|retry> --source-trust <registry> \
  --ledger-plan <canonical-plan>
qualification-source-journal-reader serve-boundary-session \
  --socket <new-protected-socket> --sequencer-socket <protected-append-socket> \
  --source-trust <registry> --ledger-plan <canonical-plan> \
  --receipt-trust <anchors> --scenario <id> --phase-index <index>
qualification-source-<fixed-role> serve-session \
  --socket <new-protected-socket> --source-trust <registry> \
  --ledger-plan <canonical-plan>
qualification-source-supervisor serve-ordinary-row-session \
  --socket <row-source-socket> --ledger-plan <role-owned-plan> \
  --source-trust <role-owned-registry>
qualification-source-journal-reader serve-ordinary-row-session \
  --runtime-root <protected-row-root> --sequencer-socket <append-socket> \
  --source-trust <role-owned-registry> --ledger-plan <role-owned-plan> \
  --receipt-trust <role-owned-anchors>
qualification-source-client-proxy serve-ordinary-row-session \
  --runtime-root <protected-row-root> --signer-socket <source-socket> \
  --sequencer-socket <append-socket> --ledger-plan <role-owned-plan> \
  --source-trust <role-owned-registry>
qualification-source-credential-broker initialize-stores \
  --agent-config <role-owned-config> --connection-store <new-public-store> \
  --credential-store <new-secret-store> --ledger-plan <role-owned-plan> \
  --source-trust <role-owned-registry>
qualification-source-credential-broker serve-ordinary-row-session \
  --runtime-root <protected-row-root> --signer-socket <source-socket> \
  --sequencer-socket <append-socket> --ledger-plan <role-owned-plan> \
  --source-trust <role-owned-registry> --connection-store <public-store> \
  --credential-store <secret-store>
qualification-source-profile-state-reader serve-ordinary-row-session \
  --runtime-root <protected-row-root> --signer-socket <source-socket> \
  --sequencer-socket <append-socket> --ledger-plan <role-owned-plan> \
  --source-trust <role-owned-registry>
qualification-source-receipt-verifier serve-ordinary-row-session \
  --runtime-root <protected-row-root> --signer-socket <source-socket> \
  --sequencer-socket <append-socket> --ledger-plan <role-owned-plan> \
  --source-trust <role-owned-registry> --receipt-trust <role-owned-anchors>
qualification-source-client-proxy serve-reader-session \
  --client-socket <new-sdk-socket> --result-socket <new-result-socket> \
  --control-socket <new-controller-socket> \
  --agent-socket <qualification-agent-socket> \
  --signer-socket <protected-client-proxy-signer-socket> \
  --sequencer-socket <protected-append-socket> \
  --ledger-plan <canonical-plan> --source-trust <registry> \
  --scenario <id> --phase-index <index> \
  --supervisor-generation <generation>
qualification-source-credential-broker serve-reader-session \
  --socket <new-shared-agent-socket> \
  --control-socket <new-controller-socket> \
  --signer-socket <protected-credential-broker-signer-socket> \
  --sequencer-socket <protected-append-socket> \
  --ledger-plan <canonical-plan> --source-trust <registry> \
  --connection-store <broker-owned-public-store> \
  --credential-store <broker-owned-secret-store> \
  --scenario <id> --phase-index <index> \
  --supervisor-generation <generation>
qualification-source-profile-state-reader serve-reader-session \
  --controller-socket <new-protected-socket> \
  --signer-socket <protected-profile-state-reader-signer-socket> \
  --sequencer-socket <protected-append-socket> \
  --ledger-plan <canonical-plan> --source-trust <registry> \
  --scenario <id> --phase-index <index>
qualification-source-receipt-verifier serve-reader-session \
  --controller-socket <new-protected-socket> \
  --signer-socket <protected-receipt-verifier-signer-socket> \
  --sequencer-socket <protected-append-socket> \
  --ledger-plan <canonical-plan> --source-trust <registry> \
  --receipt-trust <anchors> --scenario <id> --phase-index <index>
cargo xtask profile qualification build-proposal --domain <domain> \
  --target <target> --collections <directory> --common-evidence <directory> \
  --release-build <path> --output <proposal.json>
cargo xtask profile qualification installed-verify --proposal <path> \
  --packages <directory> --output <path>
cargo xtask profile qualification observe-row --domain <domain> \
  --target <target> --environment <registered-token> \
  --provider-run <registered-token> --candidate-evidence <directory> \
  --common-evidence <directory> --output <directory>
cargo xtask profile qualification observe --proposal <path> \
  --collections <directory> --common-evidence <directory> \
  --receipt-trust <preliminary-anchor-snapshot> --output <directory>
cargo xtask profile qualification cleanup --domain <domain> --target <target> \
  --run-context <path> --output <path>
cargo xtask profile qualification assemble-evidence --proposal <path> \
  --aggregate <directory> --installed <path> --supplemental <directory> \
  --output <directory>
cargo xtask profile qualification build-observation-record --proposal <path> \
  --evidence <directory> --release-build <path> --output <record.json>
qualification-observation-signer sign-observation --record <record.json> \
  --trust <observer-trust.json> --output <observation.json> --key-id <id>
cargo xtask profile qualification package-observation --proposal <path> \
  --observation <path> --cleanup <path> --output <path>
cargo xtask profile qualification verify-uploaded --artifact <path> \
  --output <verified-record.json>
qualification-attestation-signer sign-verified --record <verified-record.json> \
  --binding <path> --trust <trust.json> --output <attestation.json> --key-id <id>
cargo xtask profile qualification verify --attestation <path>
cargo xtask profile qualification import --attestation <path>
cargo xtask profile qualification check [--domain <domain> | --all]
auths agent receipt-anchors export --config <agent.toml> --output <path>
```

All paths are normalized repository-relative or explicit input files. Commands
reject symlinks, path escapes, duplicate options, unknown domains/targets,
oversized files, dirty semantic closure, and trailing JSON data.

`run` is local diagnostic orchestration and produces only section 6.1
preliminary evidence. The remaining phase commands are workflow-internal trust
boundaries, not compatibility aliases for a combined runner. `collect` is
provider-row scoped. `build-proposal` exact-joins every collected row, signed
common ledger, candidate fact, and verified nine-role release member without a
signing key. `observe-row` performs one independently credentialed provider
observation. `cleanup` is independently callable under `if: always()` for
every row even when collection or observation failed. Only after all rows and
cleanup reports pass does `observe` aggregate the byte-sorted roster and
`assemble-evidence` construct the exact pre-sign tree; it reruns and authors
the scan reports itself and rejects every missing or extra member.
`build-observation-record` natively reverifies retained ledgers, receipts, the
ReceiptVerifier source chain, and every public inspection commitment against
scenario and common-ledger truth before emitting the bounded unsigned record.
The observation signer receives only the observer seed on stdin under an
otherwise empty environment. `package-observation` copies and packs the same
owner-only evidence identity, inserts that signed envelope, and repeats the
native ledger/receipt verification on the packed bytes. It refuses to run
unless every cleanup row passed. `verify-uploaded` receives no signing seed.
The dedicated minimal attestation signer is the only process that receives the
attestation seed and it accepts only the exact bounded verified-record schema,
protected binding, and immutable trust registry—never an evidence archive.

`build-cleanup-contexts` loads the provider matrix from the exact candidate Git
revision, validates its complete byte-sorted row roster, and create-new writes
canonical contexts beneath one fixed owner-only protected root using retained
no-follow directory handles. `initialize-ledger`, `serve-append-session`,
`stage-common-phases`, `build-event-index`, and `assemble-ledger` accept no
secret and run with an empty inherited environment. They share one exclusive
provider-row lock. Initialization retains exact trust snapshots; the append
session kernel-authenticates the protected source process, supplies locked
ordering, verifies the returned source signature, and atomically publishes its
global-sequence record and marker; finalization closes the complete phase automaton and binds
the index/count/last event; staging derives common projections and receipt
claims but assembly accepts them only after exact reconciliation to the signed
chain. Every publication is crash-recoverable and exact-byte idempotent, and
append rejects a finalized row. `seal-ledger` performs complete cryptographic
preflight before reading only the ledger seed from stdin, then atomically
publishes the signed ledger under the selected protected ledger key.
`export-receipt-anchors` reads only the base64url-encoded public agent
configuration on stdin under an empty environment. It validates the Linux
configuration, atomically stages the exact decoded config, derives the
canonical public receipt-anchor document from configured public keys without
opening any seed path, exact-compares the protected digest, and atomically
publishes the preliminary snapshot. Exact-byte retries are idempotent and a
different existing output fails closed.

`serve-append-session` is the direct-cut live ordering path. It admits only a
kernel-authenticated reader process selected by protected source trust, or the
exact Supervisor phase controller committed by the immutable ledger plan.
Each transaction begins with one fixed 33-byte reader frame:
`u8(append-mode) || sha256(semantic-event-intent)`, where mode zero means a
new observation and mode one means an explicit acknowledgement retry. New
mode always allocates a new occurrence even when its public facts equal the
last event. Retry mode scans the bounded retained chain and is admitted only
when exactly one authenticated event has the same source and intent; zero or
multiple matches fail closed. While holding the provider-row lock, new mode
returns the fixed 36-byte `u32(sequence) || previous-event-sha256` prefix,
verifies the returned source signature, process binding and intent, atomically
publishes the event and marker, then returns the exact 32-byte marker digest.
Retry mode returns the original 36-byte prefix followed by the exact retained
signed event and its 32-byte marker digest; it never asks a signer to recreate
durable bytes. Timeout, EOF, peer
change, stale ordering, or invalid source output releases the unpersisted
reservation. `qualification-crash-controller run-phase` is the
no-seed ordinary row controller using this path. It exact-binds its UID and
executable to the immutable ledger plan, owns the launched agent, cgroup and a
retained protected state-directory handle, derives generation one and both
phase-boundary kinds internally, and emits `ScenarioStarted` only after the
agent is ready. It then writes exactly
`AUTHS-QUALIFICATION-PHASE-READY/1 <scenario> <phase-index>\n` to stdout,
accepts exactly one private byte `0x01` on stdin when the live phase workload
has completed followed by EOF on that dedicated pipe, emits
`ScenarioCompleted`, and kills and reaps the owned agent and cgroup. Any
missing, different, or trailing byte fails closed. The caller cannot request
an event kind, generation, or append mode. The protected workflow launches a
crash controller through the same readiness line after the initial agent and
both control sockets are ready but before it waits for the first durable
decision acknowledgement; the SDK call therefore never races controller
startup. The protected workflow launches one isolated, row-scoped
`qualification-source-supervisor serve-ordinary-row-session` process. Each
authenticated request contains exactly one plan-derived phase, decision, or
crash-action record; the signer validates that complete record before reading
its Supervisor seed and never accepts an unsigned batch or a caller-selected
source identity. The seed remains resident only in this role-fixed signer,
which receives no workload bytes, provider credential, journal file, or append
authority and is killed and reaped during exact row cleanup. This is the
executable meaning of one-event Supervisor authorization: one request and one
signature per event, not a source authority shared with the controller or
workload. The same controller executable owns ordinary and crash agent
lifecycle, while `auths-qualification-supervisor` remains the distinct ordered
appender and ledger sealer. JournalReader decisions and Supervisor crash actions
use the same session and return to the row controller only after the marker
acknowledgement proves durable append. There is no one-shot or stdin source-event
append command. If that final source-to-controller
response is lost, a reconnect uses explicit retry mode: it obtains the exact
retained event without signing or appending a second occurrence and
reconstructs the independently committed snapshot or action context before
returning it.

The Supervisor phase session signs only `ScenarioStarted` and
`ScenarioCompleted` for phases in the canonical ledger plan. The plan commits
the no-secret controller UID; the signer requires that exact kernel peer UID,
the exact protected Supervisor executable digest under a distinct signer UID,
and a matching plan phase before it reads its one source seed. The returned
event commits the plan's source context and a domain-separated digest of the
phase and Supervisor artifact. The final attester rederives both commitments.

The ordinary controller requires `operations.cbor` to be absent before the
first phase of each scenario. Later phases reopen the same retained
agent-owned state-directory descriptor and require the journal to be the exact
canonical boundary prefix for earlier reviewed phases in that scenario; this
preserves profile-owned preflight capabilities without copying private records
between journals. Phase profiles are unique within a scenario. Before a later
phase launches, the controller freezes the canonical digest of every retained
operation and boundary; every gate drain rejects a changed or missing prior row,
a new boundary for a prior operation, or a new operation outside the current
phase. Every
qualification-only journal mutation or request projection holds the private
agent gate until the controller fresh-opens the atomically replaced journal
member relative to that descriptor and the persistent JournalReader has
resume-or-appended the complete store-owned boundary prefix in ordinal order.
Decision wakes additionally carry the canonical durable acknowledgement; the
controller obtains the ordinary Supervisor context and retains the exact
context, public decision snapshot, and acknowledgement before releasing the
agent. Every drain request is one bounded canonical frame plus exactly one
read-only `SCM_RIGHTS` journal descriptor. The controller authenticates the
JournalReader, rechecks the candidate PID, start time, executable, credentials,
and delegated cgroup before the snapshot and again before release, and retries
only ambiguous transport loss by resending the same full prefix. A canonical
malformed response, changed peer, changed candidate, or changed durable roster
fails closed. The JournalReader session ends at the immutable ledger deadline,
rejects crash phases, and may complete an all-retained retry without reading
its seed.

Before each JournalReader prefix drain, the same controller invokes the
role-fixed ProfileStateReader while the candidate journal gate remains held.
The request is the exact bounded frame
`AUTHS-QUALIFICATION-PROFILE-STATE/1` plus exactly two read-only
`SCM_RIGHTS` descriptors in order: a fresh `operations.cbor` snapshot and the
fixed profile-owned state-store member selected by the reviewed five-profile
roster. The controller opens both relative to its retained agent-owned state
directory with no-follow/beneath resolution; each state member is a nonempty,
single-link, agent-owned `0600` regular file of at most 64 MiB. The reader
authenticates the controller and phase, independently runs only the statically
bound domain inspector, and resume-or-appends the deterministic reservation
facts before returning a framed one-byte success. The controller rechecks the
reader and candidate before acknowledging. Ambiguous transport loss reconnects
and resumes exact intents; malformed frames, changed identities, private-state
substitution, or contradictory bindings fail closed. The implemented
after-decision controller uses the same protocol at its pre-kill and restarted
agent checks. Every remaining crash row MUST invoke it at the row's actual
checkpoint and again after its protected recovery reaches the durable outcome;
a row without both applicable drains is not qualifiable. No raw capability,
profile state, reservation payload, or provider identifier enters the public
ledger.

After the exact phase-completion byte and EOF, the controller opens the fixed
journal member relative to that same descriptor and transfers one read-only descriptor with
`SCM_RIGHTS`; the accompanying bounded request frame contains exactly
`AUTHS-QUALIFICATION-RECEIPTS/1`. For every deterministic receipt event, the
role-fixed no-seed ReceiptVerifier first performs a read-only exact-intent
lookup and appends only when that event is absent. A restart after any durable
prefix therefore reconstructs the prefix and completes the roster without a
duplicate event or caller-selected retry state.
The controller keeps the same pinned journal descriptor and reconnects under
the original absolute deadline, while complete malformed responses fail hard.
The reader returns one bounded response frame and remains alive until the
controller rechecks its pinned process identity and returns the exact one-byte
acknowledgement frame; both sides then require EOF. This prevents process exit
from racing the protected post-response identity check.
The reader
authenticates the controller UID and executable from the ledger plan, admits
only records from the current or an earlier phase of the same scenario, then
selects a nonempty byte-sorted current-phase roster of at most eight records.
It independently decodes the pinned journal, verifies each selected portable
receipt under the canonical public anchors, exact-binds
decision/execution claims to durable common facts, and invokes only the static
reviewed inspector for the five-profile roster. It then obtains its distinct
ReceiptVerifier source signature through the common append session and emits
one `NativeReceiptVerified` event per durable receipt. Only after all events
are durably acknowledged does it return the canonical bounded
`auths.qualification-receipt-verifier-response/1`; the controller retains the
capability-free inspection commitment projection and receipt bytes under
`receipt-inspection/<operation>.json` and `receipts/<operation>/<0|1>.cbor`.
The final attester reverifies the signed source assertion and every public
cross-source commitment; it does not claim to reconstruct raw domain semantics
whose private inputs are deliberately absent. Neither process reads the
candidate collection artifact or a provider credential.

Each fixed-role source signer has a compile-time evidence role.
`serve-session` authenticates its role-specific reader once and accepts at most
1,024 nonempty four-byte
big-endian length-prefixed canonical records, each at most 64 KiB, under one
monotonic 300-second total deadline. The signer pins the reader's protected UID,
process start time, and executable digest and rechecks the process identity
before every signature. It reads its one source seed only after the first
record is canonical, role-valid, plan-bound, current-key-valid, and accepted by
the source-trust registry. It never chooses or advances the global ledger
sequence; the protected provider-row sequencer supplies the next context and
the locked appender independently rejects stale or equivocated prefixes. Zero,
truncated, oversized, noncanonical, wrong-role, stale-plan, expired-key,
peer-changed, deadline-exceeded, and 1,025th records fail closed without
emitting a signature. No reader derives a context or observation from the
candidate collection artifact.

The ClientProxy reader is a no-seed mode of the existing compile-time
ClientProxy executable under the distinct reader UID. It owns the SDK-facing
socket, kernel-authenticates the real SDK process, and forwards the exact
bounded canonical request through the qualification-only identity-preserving
bridge to the exact agent UID, GID, and executable committed by the ledger
plan. `RequestReceived` is durably appended before the first request with that
request ID can reach the agent. The reader never treats an agent HTTP response
as an SDK-visible terminal result. The protected workflow supplies the same
private `AUTHS_QUALIFICATION_CLIENT_RESULT_SOCKET` to the clean SDK consumer;
this is not a public client option. When that variable is present, the installed
Python and TypeScript clients require Linux, a full local session, and an
unqualified exercised capability, and admit the SDK-facing and result sockets
only as one normalized no-symlink pair under the same nonzero foreign owner,
the current effective group, exact socket mode `0660`, and exact parent mode
`0710`. With the variable absent, ordinary production socket admission is
unchanged.

After a leader, conflict probe, or generated common-recovery call has fully
validated its public outcome, and before returning it to the application, the
same SDK consumer process sends one private result handoff. Coalesced followers
and observers do not send a second handoff. The handoff is
`u8(version=1) || u8(mode) || request-id[16] || u32(result-length) || result`,
followed by write-side EOF; modes zero/one are new response/cancellation and
modes two/three are their explicit acknowledgement retries after an ambiguous
post-EOF acknowledgement. Result length is
bounded by the public attempt-result ceiling. For cancellation, `result` is
exactly `SHA-256("AUTHS-QUALIFICATION-CLIENT-CANCELLATION\0\x01" ||
request-id[16])`; it is not a candidate response or a collection-derived
value. The reader exact-rechecks the
consumer PID, start time, executable and session-bound request, requires a
matching successfully delivered response or observed delivery failure, hashes
the complete result, durably appends the corresponding ClientProxy event, and
only then returns the raw 32-byte marker acknowledgement. A retry can recover
only the last equal result for that request and does not create a second event;
an equal new result remains a distinct occurrence.

An exact cancellation sentinel is valid after an observed delivery failure or
after a successfully delivered terminal response when the generated client has
proved the operation not applied and intentionally propagates the host
cancellation. Response mode always exact-matches the delivered terminal bytes.

Common recovery does not depend on reader-local history. The reader verifies
the caller-presented canonical sealed recovery handle under the exact recovery
key ID and Ed25519 public key committed by the immutable ledger plan, binds its
principal to the authenticated SDK session, and requires the verified profile
to equal the reviewed phase before accepting the handle's operation ID.

No command accepts a provider command, URL, SQL, environment map, callback, or
executable path from CLI input. Those values come from reviewed static domain
configuration and protected environment bindings. Every protected command
runs a prebuilt binary from the protected revision; secret-bearing steps do not
invoke Cargo or package/build scripts.

`import` is the only command that mutates qualification state. It uses atomic
same-directory writes and refuses overwrite when the new record is older,
weaker, differently targeted, or does not match the current closure.

The local-agent session advertisement adds safe fields:

```text
qualificationId: registered token
qualificationTarget: registered token
semanticClosureSha256: 32 bytes
```

They are present only for a qualified production profile. Generated clients
treat them as authenticated local-agent diagnostics and validate their shape,
but do not embed or compare an expected attestation ID or qualification
closure. The trusted local agent and release check enforce qualification.
Clients bind the session only to stable pre-import metadata already generated
into the candidate package: protocol version, exact profile reference, profile
runtime digest, error-registry digest, and package/runtime contract. Therefore
the exact pre-import wheel/npm bytes exercised during qualification are the
bytes published after import; no SDK qualification projection or package
rewrite is an import output.

## 19. Failure behavior

| Failure | Required behavior |
| --- | --- |
| Missing attestation | profile omitted from production advertisement |
| Bad signature or unknown key | profile omitted; startup diagnostic names qualification failure |
| Closure mismatch | build/check fails; production route is not generated |
| Target mismatch | profile unavailable on that target |
| Incomplete family record | every dependent family profile unavailable |
| Expired trust key | profile unavailable until requalified or key policy corrected |
| Missing raw artifact after required retention | release check fails for that release; running binary remains bound to checked record |
| Live scenario inconclusive | no attestation is signed |
| Cleanup failure | no attestation is signed; operator diagnostic points to protected run |
| Receipt mismatch during runtime | never report success; preserve possible/applied effect truth and require operator recovery |

Qualification failure never downgrades a provider-entered operation to
not-applied and never deletes unresolved durable recovery state.

## 20. CI and release gates

### 20.1 Pull-request gates

Every pull request runs without provider secrets:

- qualification schema and attestation parser tests;
- closure determinism and hostile-path tests;
- trust-key and signature fixtures;
- roster/manifest/profile-set equality;
- generated-route availability tests;
- failpoint enum coverage;
- domain unit, mutation, prepared-store, receipt, and recovery tests;
- Python/TypeScript generated-package and receipt-verification tests; and
- a check that no workflow exposes protected secrets to pull-request code.

### 20.2 Protected live gates

Protected qualification runs execute the full matrix for one domain and target.
They are not silently skipped. Missing provider capacity, runner outage, or
rate limiting is a failed/inconclusive run and produces no attestation.

### 20.3 Release gate

`cargo xtask release-check` and authoritative GitHub CI verify:

- every qualified roster entry has a trusted current attestation;
- every attestation has retained raw evidence for the release policy period;
- semantic closure, target, package/runtime/error digests, scenario roster, and
  installed-package versions match;
- production and testkit advertisements are exact; and
- the semantic freeze records the immutable qualification schemas, generation,
  import, and production/testkit isolation contract; dynamic launch-state rows
  remain outside the freeze.

### 20.4 External protected-environment gates

Repository implementation alone cannot produce a production qualification.
For each real domain and target, release owners MUST provision and review:

- a disposable real provider account, database, backend, mirror, and capacity
  matching sections 13 through 15;
- separate setup, runtime-read, mutation, independent-observer, cleanup,
  decision/execution receipt-signing, recovery-signing, observer-signing, and
  domain-scoped qualification-attestation secrets with least privilege;
- eight distinct evidence-source signing identities and seeds plus a distinct
  ledger-sealer identity and seed, delivered only to their separately
  identified protected processes, with exact public keys, validity windows,
  domains, executable digests, and nonoverlap recorded in the protected trust
  registry;
- a GitHub protected environment with required reviewers, permitted protected
  branches, immutable workflow revision policy, and no pull-request access;
- domain trust-key registration, rotation, expiry, compromise, and reviewer
  runbooks;
- hosted artifact retention and authenticated release access for the full
  policy period; and
- an independently reviewed successful hosted run followed by a separate
  attestation-import commit and authoritative CI/release check on that exact
  promotion revision.

Unavailable credentials, missing provider capacity, absent reviewer approval,
unconfigured branch rules, or an unretained artifact are external blockers,
not reasons to replace the run with mocks or to mark a route qualified. The
repository must remain buildable and fail closed while those gates are absent.

`release/qualification/v1/live-environments.json` records only non-secret
external readiness facts: schema, repository ID, environment name, protected
branch patterns, required reviewer count, self-review/admin-bypass policy,
policy verification time, provider account class, populated secret-slot names
without values, public trust-key IDs, latest approved workflow run/artifact
IDs, retention expiry, and cleanup status. It is canonical generated review
evidence, not authorization: an entry without a valid signed qualification
record never enables a route.

### 20.5 Finite SDK v1.0 boundary

SDK v1.0 has a fixed production launch matrix:

| Family | Required profile references | Target | Provider rows |
| --- | --- | --- | --- |
| Stripe refund | `auths.stripe.refund/1` | `linux-x86_64` | the exact protected Stripe account/API row in the checked matrix |
| PostgreSQL bounded update | `auths.postgresql.update-preflight/1`, `auths.postgresql.bounded-update/1` | `linux-x86_64` | PostgreSQL 16, 17, and 18 |
| OpenTofu saved-plan apply | `auths.opentofu.plan-preflight/1`, `auths.opentofu.saved-plan-apply/1` | `linux-x86_64` | the exact binary/provider/module/backend row in the checked matrix |

This table is exhaustive for v1.0. It does not imply another target, profile,
provider version, account mode, backend, SDK language, CI provider, or domain.
Changing the table is an explicit release-scope amendment requiring the same
review as this specification; an implementation task cannot enlarge it.

There are two named finish lines:

1. **Repository-complete release candidate.** Every repository-controlled
   requirement in sections 7 through 18 is implemented for the fixed matrix;
   direct cutover and roster v2 are complete;
   schemas, parsers, semantic closure, authenticated event ledger, protected
   observer/attester, receipt verification, scans, transactional import, all
   three real domain prerequisites, installed Python/TypeScript package and
   public-fixture proof, operator documentation, and the complete synthetic
   fourth-provider protocol proof pass with no protected secrets. All real
   routes remain fail closed until live records are imported. The immutable
   candidate revision is frozen here.
2. **Published SDK v1.0.** The external gates in section 20.4 are configured for
   all three environments; retained signed live artifacts for every row in the
   fixed matrix verify and import in separate reviewed commits; authoritative
   CI and release checks pass on the exact promotion revision; production
   advertises exactly the five profile references above and no others; and
   clean installed Python and TypeScript consumers complete every family,
   including forced-crash/lost-response recovery and portable receipt
   verification. That exact revision is tagged and published.

A newly discovered item blocks v1.0 only when it does at least one of the
following for the fixed matrix:

- demonstrates violation of a normative `MUST` in this specification or an
  authoritative prerequisite it cites;
- permits an unauthorized provider effect, secret disclosure, unsafe retry,
  receipt/evidence forgery, false terminal projection, or advertisement of an
  unqualified route;
- prevents a named production family, installed SDK workflow, declared target,
  provider row, toolchain, or operator recovery path from working; or
- fails a named acceptance, CI, live-environment, import, or release gate.

Severity labels and general hardening value are not sufficient on their own.
When a new blocker is admitted, its change must state the smallest
counterexample, the violated requirement, and the smallest closure; adjacent
improvements do not become part of that fix automatically. After the exact
release revision satisfies section 25 and is published, later findings are
patch/minor-release work under normal severity and withdrawal policy, not a
retroactive expansion of v1.0.

The following are explicitly post-v1 and non-blocking unless they expose one of
the violations above in the fixed matrix: `linux-aarch64`, macOS and Windows
support; additional PostgreSQL majors; additional Stripe APIs, account modes,
or effects; broader OpenTofu providers, modules, mirrors, and backends; new
domains; additional SDK languages and conveniences; CI-provider portability;
dashboards and transparency automation; performance work beyond declared
bounds; and optional HSM/KMS hardening beyond the key custody required here.
The synthetic fourth-provider proof, source/secret isolation, transactional
import, real crash/recovery and receipt evidence, and any of the three listed
families are not deferrable.

## 21. Release Closure Execution Plan

This plan is the implementation handoff for a zero-context agent. Sections 1
through 20 remain the normative requirements; this section orders them and
defines observable exit conditions. A phase may be split into smaller pull
requests, but its exit condition cannot be waived. The first action in every
phase is to inspect the current tree and tests: this plan describes required
end state, not an assertion that every listed item is absent.

```text
fixed v1 scope and declarations
              |
              v
repository/common trust mechanism
              |
              +-------------------+-------------------+
              v                   v                   v
       Stripe closure      PostgreSQL closure    OpenTofu closure
              +-------------------+-------------------+
                                  |
                                  v
                    installed packages + operator proof
                                  |
                                  v
                      synthetic fourth-provider proof
                                  |
                                  v
                         immutable candidate freeze
                                  |
                                  v
                    protected live runs and attestations
                                  |
                                  v
                       transactional promotion + v1.0
```

General execution rules:

- preserve unrelated work and use direct cutover: remove superseded paths in
  the same phase that replaces them;
- use immutable candidate Git objects for semantic inputs and a disjoint
  protected checkout for observer/attester code;
- add the smallest focused tests with each change, then run repository
  architecture/compliance/code-generation checks required for every affected
  package;
- never treat an external credential, provider account, approval, or hosted
  run as a repository implementation substitute;
- never mark a production profile qualified during phases 21.1 through 21.6;
  and
- record deferred work only under the post-v1 rule in section 20.5, with the
  reason it does not meet the blocker-admission test.

### 21.1 Freeze the v1 launch declarations

**Inputs.** Sections 7.4, 7.6, 11, 13 through 16, and 20.5; the three checked
profile-package manifests and their qualification directories.

**Owned paths.** `product/spec/v1/profile-qualification-*.schema.json`,
`product/integrations/auths-{stripe,postgresql,opentofu}/qualification/`, the
three package manifests, `release/qualification/v1/closure-manifest.json`, and
the generator/model code that reads them.

**Work.** Encode the exact five-profile launch set, `linux-x86_64`, PostgreSQL
16/17/18, exact provider artifact/version policy, scenario-to-provider-row
applicability, per-scenario operation/attempt plans, lifecycle/failpoint
coverage, common and domain semantic expectations, credential roles, and the
full requirement-to-evidence inventories. Every declaration is closed,
bounded, canonical, byte-sorted where required, and statically dispatched.
The protected closure policy—not a candidate-editable list—selects all common
and domain semantic inputs and exact projection normalizations.

**Outputs and gates.** Schema/parser parity fixtures cover valid, unknown,
missing, duplicate, reordered, min/max, and max-plus-one cases. Generator drift
checks reproduce all three declarations and static rosters. Requirement,
scenario, operation-plan, failpoint, provider-matrix, receipt-claim, source,
test, and report-field sets are exactly equal. No profile is advertised.

**External prerequisites.** None.

**Exit.** One immutable declaration digest can be recomputed for every row in
the fixed v1 matrix, and deleting or changing any required row fails static CI.

### 21.2 Complete the repository/common trust mechanism

This phase is sequential within itself; 21.2.1 precedes 21.2.2, and both
precede 21.2.3 and 21.2.4.

#### 21.2.1 Runtime, journal, and receipt foundations

**Owned paths.** `product/runtime/auths-node/`,
`product/runtime/auths-lifecycle/`, `product/stores/auths-stores/`,
`product/receipts/auths-receipts/`, generated profile routes, runtime
configuration schemas, and their tests.

**Work.** Finish the single-owner durable journal, exact execute/replay/status/
recover/cancel state machine, crash-safe reservation and lease lifecycle,
response-loss reconciliation, immutable decision/execution receipt state, and
separate decision/execution/recovery keys. Add manifest-generated
profile-specific receipt builders and inspectors; verify every common and
profile claim against the durable record before provider entry, terminal
projection, replay, status, recovery, and export. Project registered receipt
integrity failure without changing truthful effect. Export canonical public
anchors. Remove legacy effect routes, constructors, dispatch, state readers,
and key derivation paths required by section 24.

**Outputs and gates.** Focused state-transition, corruption, concurrency,
restart, idempotency, receipt mutation, key interval, key separation, and
crash-boundary tests pass. Production builds contain no failpoint path and a
second process cannot open the same state directory. Public API and generated
snapshots show only the local-agent v1 operation/session surface.

**Exit.** The production runtime can truthfully persist, recover, and natively
reverify every outcome needed by the section 11 matrix without qualification
code or a provider-specific common-lifecycle implementation.

#### 21.2.2 Independently authenticated evidence ledger

**Owned paths.** `product/sdk/auths-profile-kit/src/qualification_ledger.rs`,
`qualification_harness.rs`, `product/qualification/`, the source-trust
registry, architecture/compliance manifests and dependency snapshots, and
ledger/evidence schemas.

**Work.** Implement separate protected producers for all eight source roles.
Each producer owns one source identity/key and emits canonical typed source
records bound to the entire run/session context. A common sealer executable
links no domain adapter, owns only the ledger key, verifies source signatures,
roles, executable digests, validity over the full run, context, hash chain,
exact phase/operation/request sets, and the closed lifecycle automaton, then
seals the ledger. Shared code derives attempts, outcomes, counters, crash
acknowledgements, reservation/lease closure, receipt claims, and provider-call
ordering from those records. It exact-compares the terminal journal and
provider truth, rejects extras/orphans, and retains only bounded public
commitments. Candidate or domain code can supply mismatch hints but cannot
construct, sign, or choose common evidence.

**Outputs and gates.** Every new package is classified in architecture and
compliance inventories. Hostile tests cover source-role/key reuse, cross-run
replay, canonicalization, signature and validity boundaries, sequence gaps,
duplicates, reordering, wrong operation/request/connection, early/late crash
acknowledgement for every failpoint, process-generation rules, mismatched
receipt bytes/claims, leaked reservation/lease, TOCTOU inputs, and output
no-clobber. Test fixtures use test-only keys. The production registry remains
fail closed until reviewed public key entries are committed before the 21.6
freeze; private keys are never repository inputs.

**Exit.** Given only authenticated source artifacts, immutable declarations,
and protected read access, shared code deterministically reproduces every
common phase field and rejects a one-bit or one-event substitution. No domain
adapter process has access to a source or ledger signing key.

#### 21.2.3 Evidence, verifier, scans, closure, and import

**Owned paths.** `xtask/src/profile_qualification*.rs`, all qualification and
report schemas, `auths-profile-kit` qualification record/observation APIs,
`release/qualification/v1/`, secret-scan policy, and generated roster/routes.

**Work.** Finish exact proposal, preliminary collection, installed report,
protected observation, per-row cleanup, final archive, verified record, and
attestation producers. Safely snapshot every untrusted input once with
no-follow, regular-file, owner/link/mode, size, and replacement checks. Parse
closed typed reports and cross-link every binding, operation, attempt,
provider row, counter, truth commitment, receipt, cleanup row, and digest.
Reconstruct candidate facts only from immutable Git objects. Query GitHub for
and verify the exact authoritative release-build workflow/run and six immutable
artifact rows, then recompute toolchains, packages, the closed production/
qualification-agent surface, provider matrix/artifacts/scenario sets, semantic
closure, and native receipt claims. Independently run pinned Gitleaks 8.28.0 and the
typed forbidden-field scanner over extracted evidence. Split no-secret
verification from the seed-bearing signer. Make import intent-first,
crash-resumable, fully revalidated, all-or-rollback, and limited to section
12.4 projections.

**Outputs and gates.** Hostile archives cover noncanonical tar/zstd structure,
links/special members, long names, duplicates, reordering, padding/trailing
frames, bounds, digest/length mismatch, and path replacement. Report mutation
tests prove schema/parser parity and cross-file mismatch rejection. Scan,
receipt, immutable-tree, closure self-exclusion/normalization, signer isolation,
and every import crash point are tested. Qualification state stays absent when
any input is missing or invalid.

**Exit.** A test-only archive can be independently reconstructed, scanned,
verified, signed, reverified, imported, invalidated by drift, and rolled back
after every simulated crash without executing or trusting archive content.

#### 21.2.4 Four-job workflow and static availability

**Owned paths.** `.github/workflows/profile-qualification.yml`, the three
generated entrypoints, workflow/codegen tests, command dispatch, roster v2,
generated routes, and operator diagnostics.

**Work.** Replace the legacy workflow directly with exactly `collect`,
`installed`, `observe_cleanup`, and `attest`. The collector expands the exact
provider-row matrix, consumes candidate artifacts from the separate
authoritative no-secret release build, and runs candidate consumers only in a
destroyed-after-use workload sandbox disjoint from prebuilt, single-purpose
protected processes. It never builds candidate code. The installed job is
offline and secret-free. One non-matrix
observer job consumes every row, always runs a separate cleanup step, and
signs one aggregate observation. Attestation verifies without a key, then
signs the exact verified record in a minimal process. Jobs bind their constant
environment themselves; entrypoints pass no secrets. Preliminary/final uploads
and downloads use immutable artifact identities and exact digests. Generate
target-scoped availability from trusted imported records and keep testkit state
structurally separate.

**Outputs and gates.** Workflow-policy tests prove pinned actions, minimal
permissions, exact secret allowlists, no `secrets: inherit`, no secret-bearing
build/package command, immutable upstream build provenance, sandbox/process-
group teardown, no shared workspace/process namespace/identity with protected
services, cleanup liveness, absent/malformed-artifact cleanup, and no candidate
execution in observer/attester steps. Generator tests prove all three domains
use the one common shape. Production/testkit route and diagnostic tests prove
fail-closed omission and no runtime override.

**Exit.** The repository can run the complete four-job protocol with test-only
keys and fixtures, while real environments remain unable to qualify until all
external gates are present.

### 21.3 Close the three production domains

These three workstreams may proceed in parallel after 21.2, but 21.4 waits for
all three. Each uses the generated collection/observer/fact-validator boundary,
the common scenario runner, and the declarations frozen in 21.1.

#### 21.3.1 Stripe

Route `auths.stripe.refund/1` through the AP-SPEC-0012 bounded refund service:
fresh account/payment/charge/refundable evidence, authorization policy,
aggregate budget reservation, sealed command, exact idempotency, gateway
request-write observation, reconciliation, redacted provider truth, and static
profile receipt claims. The mutation credential cannot rewrite observer truth
or budget history. Run all focused unit, mutation, prepared-state, response-loss,
receipt, redaction, and protected-adapter fixture tests. Exit when section 13.1
is exactly covered by `requirements-v1.json` and every non-live Stripe gate
passes with the route still unqualified.

#### 21.3.2 PostgreSQL

Complete TLS preflight and bounded update against exact PostgreSQL 16/17/18
rows; destination/extension/role checks, serializable evaluator and execute-time
recheck, database-enforced append/finalize-only operation ledger, race-safe
claims, later-row-drift behavior, reconciliation, redacted truth, and static
profile receipt claims. Mutation credentials cannot alter finalized truth and
observer credentials cannot mutate. Run the exact cross-version unit,
integration-fixture, race, restart, receipt, and adapter tests. Exit when
section 14.1 is exactly covered and both profiles remain atomically
unqualified pending live evidence.

#### 21.3.3 OpenTofu

Complete structural HCL/module/provider/lock closure, immutable binary and
mirror digests, fd-stable executable identity, OS identity/filesystem/egress/
resource sandbox, process-group timeout cleanup, encrypted plan/state artifact
storage, operation-bound markers, protected backend reconciliation, redacted
truth, and static receipt claims for both plan and apply durable operations.
Run bundle mutation, dependency escape, executable replacement, sandbox,
timeout, prepared-state, crash/recovery, receipt, and adapter tests. Exit when
section 15.1 is exactly covered on `linux-x86_64` and both profiles remain
atomically unqualified pending live evidence.

**External prerequisites for 21.3.** Local disposable test fixtures may be used
for implementation tests. Protected accounts, hosted artifacts, and production
attestations are not required and cannot be replaced by mocks.

### 21.4 Prove installed packages and operator recovery

**Inputs.** The repository-complete outputs of 21.2 and all three 21.3
workstreams.

**Owned paths.** Rust/Python/TypeScript package builders and installed tests,
generated examples, operator configuration/receipt-anchor/recovery runbooks,
and public API snapshots.

**Work.** Build the exact release Rust artifacts, wheels, and npm packages in
clean environments at declared minimum runtimes and pinned release toolchains.
Install them into empty consumers. Prove importability, generated signatures,
type/error contracts, unqualified-before-dispatch behavior, recovery-handle
serialization/persistence, and native portable-receipt verification/mutation
behavior using signer-selected public fixtures. Exercise the full local-agent
authorize/execute/denial/replay/conflict/status/recovery protocol only with the
synthetic test-only provider; this proves SDK mechanics, not a real provider
effect or production qualification. Examples use stable per-intended-effect
business idempotency, persist recovery handles before another await, and never
log or expose capabilities. Runbooks cover key/anchor rotation, startup,
cleanup, receipt-integrity failure, and operator recovery. The exact real-family
installed-client effects remain mandatory protected live gates in 21.7 and
post-import release gates in 21.8.

**Gates and exit.** Installed tests use no workspace/source imports or hidden
credentials. Testkit routing is permitted only for the explicit synthetic
protocol suite and remains impossible in production packages. Package
contents, versions, provenance, and API snapshots match candidate declarations.
Documentation commands are executable or explicitly marked integration
fragments. Exit when clean consumers pass every pre-live package/fixture gate,
reject every unqualified real route before dispatch, complete the synthetic
protocol, and every public v1 surface is documented.

### 21.5 Prove the fourth-provider contribution boundary

**Inputs.** The same generator, workflow, common runner, verifier, import, and
SDK artifacts intended for release.

**Work.** In an isolated repository fixture, generate a synthetic fourth
domain from a clean scaffold. Implement only its domain-owned collection,
observer, fact validation, manifests, and fixtures. Exercise common ordinary,
denial, replay, response-loss, crash, ledger, receipt, installed-client,
evidence, test-key observation/attestation, transactional import, route
projection, drift invalidation, and removal paths. Capture immutable sentinels
for the common workflow, schemas, verifier, importer, roster semantics,
supervisor/source processes, SDK runtime, and three real integrations before
and after.

**Gates and exit.** The fixture compiles and installs all generated packages;
passes the full isolated lifecycle; changes none of the sentinels; and cannot
advertise in a production build. A scaffold-only, roster-only, or all-error
adapter does not pass. This phase precedes real live attestations so any common
boundary defect is fixed before the candidate is frozen.

### 21.6 Freeze the repository-complete release candidate

Run all focused suites, architecture/compliance/dependency/codegen/public-API
checks, `cargo xtask ci`, and `cargo xtask release-check` without protected
provider secrets. Resolve every failure that meets section 20.5's blocker rule.
Record the immutable candidate revision, protected workflow/attester revision,
closure policy and per-domain semantic closure digests, package/toolchain
identities, reviewed source/ledger/observer/attestation public trust registries,
and external readiness checklist. Public registration occurs before the freeze
because it is part of verification policy; custody and environment delivery of
the corresponding private keys remain external. Prove the worktree and
generated outputs are clean and every real route is still absent or
unqualified.

**Exit.** This is the repository-complete release-candidate finish line from
section 20.5. After it, a semantic code, manifest, schema, workflow, generator,
or protected-tool change creates a new candidate revision and requires a new
freeze and new live runs. Documentation that changes no normative contract or
semantic closure follows the repository's ordinary release policy.

### 21.7 Configure external environments and run qualification

Release owners configure all section 20.4 gates for the three exact protected
environments, including provider capacity, independent credentials and keys,
source processes, trust registries, reviewers, no-self-review/no-admin-bypass,
protected branches, artifact retention, and immutable workflow revision. They
exact-match deployed public identities to the frozen registries and verify
`live-environments.json` against GitHub/provider state without recording secret
values.

Dispatch the frozen candidate for Stripe, PostgreSQL, and OpenTofu. PostgreSQL
must execute distinct 16/17/18 rows. One aggregate protected observation per
family must cover the exact row/scenario expansion and every cleanup row. The
exact frozen wheel and npm package run as clean isolated consumers against the
qualification agent for each real family and prove the applicable execute,
replay, crash/lost-response recovery, and portable receipt paths; those live
results bind the same package digests later published. The
attester independently verifies immutable candidate facts, source ledger,
provider artifacts/versions, raw receipts/profile claims, typed reports,
scans, cleanup, and uploaded artifact identity before signing. Inconclusive,
missing, expired, skipped, or partially cleaned runs produce no usable record.

**Exit.** Three retained, signed family/target attestations—covering all fixed
matrix rows—verify against the frozen candidate and public trust policy, and
their immutable artifacts remain accessible for the full retention period.

### 21.8 Promote and publish SDK v1.0

Import each family attestation in its own reviewed promotion commit using the
transaction in section 12.4. Reverify evidence and closure on every resume.
After the final import, regenerate only the allowlisted projections and prove
that production advertises exactly the five v1 profile references on
`linux-x86_64`; testkit and every other target/profile remain absent. Run
authoritative hosted CI and, while the protected environments remain active,
run the frozen clean wheel/npm consumers against the final production agent
for every real family, including external process kill/lost-response recovery
without qualification failpoints and native receipt verification. Then run
retained-artifact verification, scans, route tests, `cargo xtask ci`, and
`cargo xtask release-check` on the exact final promotion revision.

Tag and publish only that revision. Record package and binary digests, the five
advertised profile references, the three attestation IDs, provider-row
coverage, and retention expiry in release evidence. Any post-import semantic
change returns to 21.6. Exit only when section 25 is true; that exit is the
finite SDK v1.0 stopping point.

## 22. Acceptance checklist

The repository-complete release candidate requires every repository-controlled
item below. Published SDK v1.0 additionally requires every protected/live item.
No item is satisfied vacuously by leaving the roster empty or qualifying only
one family.

- [ ] qualification records, attestations, trust keys, indexes, and roster v2
      are bounded, canonical, signed, and hostile-tested;
- [ ] exact JSON Schemas and Rust parsers accept and reject the same bounded
      qualification and evidence corpus;
- [ ] semantic closure is deterministic and any semantic drift blocks or
      unqualifies the affected profile;
- [ ] the protected signer independently reconstructs and validates every
      signed claim from immutable GitHub and artifact inputs;
- [ ] protected non-candidate code independently observes provider truth and
      counters before cleanup and signs the exact observation consumed by the
      attester;
- [ ] eight independently keyed source processes and the separate common
      ledger sealer authenticate a complete, exact, replay-resistant lifecycle
      transcript from which every common attempt, counter, effect, crash, and
      receipt claim is derived;
- [ ] the unsigned proposal and final record have distinct exact schemas and a
      deterministic, independently verified conversion;
- [ ] raw evidence packaging is complete, bounded, safely extractable, and
      contains every claimed report exactly once;
- [ ] pull-request code cannot access provider or attestation secrets;
- [ ] the reusable workflow contains exactly the four trust-zone jobs and
      enforces no-secret builds, offline installed verification,
      always-running per-row cleanup, no-secret archive verification, and a
      separate minimal attestation signer;
- [ ] Stripe, PostgreSQL, and OpenTofu use the same reusable workflow and
      common matrix through statically generated domain adapters;
- [ ] generator contract tests prove a future real domain can use the same
      workflow contract without editing the common workflow, qualification
      verifier, roster mechanism, crash supervisor, or SDKs;
- [ ] a synthetic fourth provider passes the complete isolated contributor,
      crash, evidence, attestation, import, route, drift, and removal proof;
- [ ] Stripe refund, PostgreSQL preflight/update, and OpenTofu preflight/apply
      each have one protected aggregate live attestation for `linux-x86_64`;
- [ ] every common and domain scenario appears exactly once and passed;
- [ ] every checked provider-matrix run, including PostgreSQL 16, 17, and 18,
      passed its exact applicable scenario set;
- [ ] every crash boundary proves provider call count and durable recovery;
- [ ] production binaries contain no qualification failpoint activation path;
- [ ] response loss never causes blind retry;
- [ ] denied and malformed paths acquire zero mutation credentials;
- [ ] every terminal receipt pair verifies and its profile claims match
      independent provider truth;
- [ ] the attestation binds the canonical deployment receipt-anchor document
      and its decision/execution verification methods;
- [ ] installed Python and TypeScript packages reproduce replay, recovery, and
      receipt verification;
- [ ] checked evidence passes redaction and secret scanning;
- [ ] transactional import passes crash/resume tests without mixed or orphaned
      qualification state;
- [ ] release CI retrieves and verifies every retained immutable raw artifact;
- [ ] Stripe uses the real bounded-refund vertical, not the synthetic or
      simplified route;
- [ ] PostgreSQL proves real TLS preflight, serializable update, immutable-ledger
      recovery, and later-row-drift behavior;
- [ ] OpenTofu proves a real sandboxed plan/apply, dependency closure, encrypted
      artifact handling, and operation-bound recovery;
- [ ] production advertises exactly the five profile references in section
      20.5 on `linux-x86_64` and zero others;
- [ ] testkit-available routes remain impossible to construct in production;
- [ ] the direct cutover removed obsolete qualification formats, simplified or
      synthetic production effects, remote effect APIs, migration paths,
      fallback readers, and runtime overrides;
- [ ] protected provider accounts, least-privilege secrets, reviewer/branch
      policy, trust keys, artifact retention, and independent hosted review are
      configured for every qualified domain and target; and
- [ ] `cargo xtask ci` and release checks pass on the exact promotion revision.

## 23. Launch ceremony

Qualification and launch occur in this exact order:

1. complete sections 21.1 through 21.5, including the synthetic
   fourth-provider proof, with every real route still `unqualified` in
   production (the Stripe testkit profile remains separately marked
   `testkitAvailable: true`);
2. pass the no-secret repository release gates and freeze the immutable
   candidate and protected workflow/attester revisions;
3. configure and independently review the real provider environments,
   least-privilege secret slots, protected branches, reviewers, runner policy,
   artifact retention, and public trust keys;
4. dispatch one domain/target workflow from a protected branch against one
   immutable candidate revision;
5. execute the four trust zones, including secret-free installed verification,
   independent source-authenticated observation, always-running cleanup,
   bounded final packaging, no-secret verification, and minimal signing;
6. review the signed record and raw retained evidence without exposing secrets;
7. import each domain/target attestation in a separate reviewed promotion
   commit using the crash-resumable transaction;
8. run authoritative CI, production/testkit route checks, installed-package
   checks, retained-artifact verification, secret scanning, and
   `release-check` on that exact promotion revision; and
9. publish only the exact revision that passed those gates.

No single pull request both introduces unqualified semantic code and
self-approves live qualification. No local run, cached artifact, manually
edited roster, or administrator override substitutes for this sequence.

## 24. Direct-cutover closure

Auths is prelaunch. The implementation and each promotion change remove the
superseded path in the same bounded cutover. Completion requires:

- roster-v1 readers, qualification aliases, fallback attestations, migration
  code, dual readers/writers, and runtime qualification overrides removed;
- the simplified Stripe production route and any synthetic production route
  removed rather than retained beside the qualified vertical;
- superseded effectful remote SDK constructors, routes, examples, and package
  exports removed when the local-agent generated profile path replaces them;
- obsolete disposable development state rejected rather than converted;
- generated topology, public API snapshots, schemas, semantic freeze,
  compliance inventory, qualification closure, and release evidence
  regenerated atomically; and
- tests proving removed imports, routes, state formats, and override controls
  fail closed.

Crash recovery for the single current qualification-import transaction is
required safety behavior. It MUST NOT be implemented as compatibility support
for an obsolete qualification or roster format.

## 25. Completion condition

SDK v1.0 is done when one exact published revision satisfies every item in
section 22 and all of the following are simultaneously true:

1. the repository-complete release-candidate finish line in section 20.5 was
   recorded before any live qualification run;
2. trusted current attestations cover Stripe refund, PostgreSQL
   preflight/bounded update on 16/17/18, and OpenTofu preflight/saved-plan apply
   on `linux-x86_64`, all against that frozen semantic candidate;
3. production advertises exactly
   `auths.stripe.refund/1`,
   `auths.postgresql.update-preflight/1`,
   `auths.postgresql.bounded-update/1`,
   `auths.opentofu.plan-preflight/1`, and
   `auths.opentofu.saved-plan-apply/1` on that target and advertises no other
   production profile/target pair;
4. clean generated Python and TypeScript packages, using the published
   production agent and public trust anchors, each complete the applicable
   real provider families, preserve recovery across forced crash and lost
   response without a second effect, and natively verify the retained portable
   receipts;
5. each route is omitted at generation/startup when its checked signature,
   trust interval, target, family membership, provider row, or semantic closure
   is missing or mismatched; missing, expired, or inaccessible hosted evidence
   fails promotion and every new release check as required by section 12.5, but
   does not require runtime network access or mutate an already running binary;
   and
6. the exact promoted revision passes authoritative CI, release checks,
   installed-package checks, retained-artifact verification, and publication,
   and its tag/package/binary/evidence digests are recorded.

At that point work on SDK v1.0 stops. Items outside the fixed matrix and items
that do not satisfy the blocker-admission rule in section 20.5 are not required
to delay or reopen v1.0; they enter the patch/minor roadmap. A later security
finding is handled under the release withdrawal and patch policy, not by
silently redefining what the original v1.0 scope meant.

Passing this gate qualifies only the five listed profile versions on the one
listed target. It is evidence for later mechanism extraction, not permission
to merge Stripe, PostgreSQL, and OpenTofu semantics into a generic executor.
