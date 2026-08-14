# Epic 8 — Ship the Open Reference Production Deployment

Status: implementation specification

Parent: [0038](../0038-production-runtime-custody-observability-and-assurance.md)

Depends on: [Epic 2](epic_2.md), [Epic 3](epic_3.md), [Epic 4](epic_4.md), [Epic 5](epic_5.md), [Epic 6](epic_6.md), and [Epic 7](epic_7.md)

## 1. Outcome

Ship one reproducible, open deployment of Auths that a team can operate on its
own infrastructure. It runs multiple interchangeable Rust runtime instances,
uses a shared PostgreSQL lifecycle store, signs through hardened custody,
exports privacy-safe telemetry, and exposes the three qualified exact-effect
profiles.

This is the deployment used for open-core production claims. It is not a hosted
control plane, fleet manager, tenant administration product, or substitute for
the enterprise boundary in specification 0039.

## 2. Current issue

The repository proves many pieces independently and contains strong live demos,
but a production evaluator still has to infer how to compose them. That leaves
critical choices—TLS, replica safety, probes, custody, recovery, telemetry,
secrets, upgrades, and backup—outside the proof.

A product is not production-shaped merely because its libraries could be
assembled correctly. The open reference deployment must make the safe assembly
obvious and executable.

## 3. Product constraint

The deployment must preserve the Stripe-quality experience at two altitudes:

- a developer reaches a protected sandbox effect in fifteen minutes; and
- an operator can understand readiness, recovery, custody, and data durability
  without reading the Rust crate graph.

Defaults are secure and useful. Every required setting is validated before the
server binds a network port. Optional complexity is grouped behind explicit
production features rather than scattered environment variables.

## 4. UX

The local evaluator journey is:

```text
copy example config -> start stack -> auths doctor -> run quickstart -> see Receipt
```

The operator journey is:

```text
deploy manifest -> readiness green -> inspect SLOs -> reconcile recoverable work
                                      -> rotate custody key -> verify backup restore
```

Provide one `auths doctor` report with four sections:

```text
Configuration  PASS
Lifecycle DB   PASS  TLS / schema current / backup age 00:17
Custody        PASS  aws-kms / p256 / key enabled
Profiles       PASS  opentofu / postgresql / github
```

Failures must identify the component, the safe next action, and whether the
runtime intentionally remains unready. The report must never print credentials,
authorization bytes, raw action payloads, or sensitive receipt disclosures.

## 5. Architecture

```text
SDK clients -> TLS ingress -> [runtime A | runtime B | runtime C]
                                  |          |          |
                                  +---- PostgreSQL -----+
                                  +---- KMS/PKCS#11 ----+
                                  +---- OTLP exporter --+
                                  +---- exact gateways -+
```

All runtime instances are stateless except for bounded local caches. PostgreSQL
owns lifecycle truth and recovery work. Custody keys never enter application
configuration. Profile gateways are explicit Rust modules; the deployment does
not load arbitrary code or route arbitrary operation payloads.

## 6. Repository layout

Add:

```text
product/runtime/auths-node/
  Cargo.toml
  src/
    main.rs
    api.rs
    config.rs
    profiles.rs
    shutdown.rs

demos/open-production-reference/
  README.md
  config/
    local.toml
    production.example.toml
  compose/
    compose.yaml
    postgres/
    otel/
  deploy/kubernetes/
    base/
    overlays/local/
    overlays/aws-kms/
  dashboards/
  runbooks/
  tests/
```

`auths-node` is shipping product code and follows the normal product dependency
policy. Deployment examples, dashboards, and executable proof stay in the demo.
Do not add a generic plugin host.

Update `Cargo.toml`, `architecture.toml`, `compliance.toml`, public dependency
snapshots, release-control inputs, and semantic-freeze inputs for the new
shipping package.

## 7. Runtime APIs

The node serves only:

```text
GET  /live
GET  /ready
GET  /version
POST /v1/authority/create
POST /v1/authority/delegate
POST /v1/profiles/opentofu/saved-plan-apply/execute
POST /v1/profiles/postgresql/bounded-update/execute
POST /v1/profiles/github/issue-address/execute
POST /v1/workflows/resume
GET  /v1/workflows/{opaque-reference}
GET  /v1/receipts/{id}/summary
POST /v1/receipts/{id}/disclose
```

Full receipt disclosure requires a Rust-verified disclosure authorization. The
status endpoint returns an inert bounded projection. Health, metrics, and logs
do not expose the workflow payload.

Requests enforce:

- TLS at ingress and authenticated service identity at the node;
- fixed body and header limits before parsing;
- strict content types and contract versions;
- bounded deadlines;
- no automatic redirect following;
- idempotency and recovery references where the operation requires them; and
- a stable error envelope from Epic 7.

## 8. Deployment implementation

### 8.1 Rust node

1. Assemble the frozen production candidate from Epic 1.
2. Construct the PostgreSQL store, selected custody adapter, operations sink,
   coordinator, and explicitly enabled profiles.
3. Refuse startup on invalid config, incompatible schema, unavailable custody,
   or missing required profile dependencies.
4. Bind only after startup checks pass.
5. Mark readiness false when durable state or custody cannot safely authorize a
   new effect; liveness remains independent.
6. Drain new work on termination, finish bounded in-flight work, release or
   expire leases, and exit within the configured grace period.

### 8.2 Container

1. Produce a pinned, multi-stage image from the repository.
2. Run as a non-root numeric user with a read-only root filesystem.
3. Include no compiler, package manager, source tree, shell credentials, or
   embedded production config in the runtime layer.
4. Publish an SBOM, provenance, digest, and vulnerability assessment through
   the existing release-control machinery.
5. Pin base images by digest and document the refresh process.

### 8.3 Local composition

The local composition runs:

- three Auths node instances;
- PostgreSQL with TLS and a persistent volume;
- a local PKCS#11/SoftHSM custody adapter;
- an OpenTelemetry collector;
- a metrics/dashboard stack; and
- deterministic sandbox providers for each qualified profile.

It must run the same node image and configuration schema as the production
deployment. Development shortcuts may replace external services, but never the
authorization, lifecycle, custody-binding, or receipt semantics.

### 8.4 Kubernetes reference

Provide plain, reviewable Kustomize manifests with:

- three replicas, topology spread, pod disruption budget, and rolling updates;
- startup, readiness, and liveness probes;
- non-root security context, seccomp, dropped capabilities, and read-only root;
- service account with no provider permission by default;
- network policies allowing only ingress, PostgreSQL, custody, telemetry, and
  the explicitly configured profile gateways;
- secrets referenced from the platform, never checked in;
- resource requests and limits based on qualification evidence; and
- separate overlays for local PKCS#11 and AWS KMS custody.

Do not build an enterprise installer or multi-cluster controller here.

## 9. Data and upgrade operations

1. Check one versioned schema bootstrap into `auths-stores` for the candidate.
2. Make the node detect every incompatible schema before readiness.
3. Prove rolling restart of the immutable candidate without changing its schema
   or semantic identities.
4. Provide backup, restore, and point-in-time-recovery procedures for that exact
   candidate schema.
5. Run a restore into a clean environment and verify lifecycle commitments and
   receipts before declaring success.
6. Treat recovery references as secrets: store digests, redact logs, and rotate
   references after successful use where the contract permits.

Because Auths is prelaunch, do not add a migration framework, compatibility
layer, dual reader/writer, shim, or deprecation path. A future changed schema is
a new candidate with an explicit cutover plan; this epic qualifies only the
frozen candidate and makes every mismatch fail before serving traffic.

## 10. Profile gateways

Each gateway has its own configuration block, credentials, egress rule, route,
action parser, reconciler, and receipt evidence. Enabling GitHub must not grant
the process OpenTofu or PostgreSQL access.

Provider credentials are acquired only after a sealed execution authorization
and durable reservation exist. Prefer workload identity or short-lived
credentials. Static credentials are allowed only in the local sandbox and must
be visibly rejected by the production configuration profile.

## 11. Operations assets

Ship:

- dashboards for request outcomes, lifecycle age, recovery backlog, custody
  health, store latency, and profile/provider results;
- alerts and runbooks from Epic 5;
- an incident drill for provider-unknown outcomes;
- a custody-key disable/rotation drill;
- a PostgreSQL failover and restore drill;
- a privacy audit showing the absence of sensitive telemetry; and
- a public limitations document that names what the deployment does not solve.

## 12. End-to-end proof

The reference test harness must:

1. start or deploy three runtime replicas;
2. run installed TypeScript and Python clients;
3. create and delegate authority;
4. execute one effect in each qualified profile;
5. kill the serving node during a provider attempt;
6. resume from another node;
7. verify the resulting receipt offline;
8. prove replay, widening, payload mutation, and unauthorized disclosure fail;
9. restore the database into a clean stack and re-verify the receipts; and
10. compare privacy-safe operational evidence with the expected fixture.

The test consumes built artifacts, not workspace source imports.

## 13. Validation

Run at minimum:

```text
cargo xtask arch
cargo xtask compliance
cargo xtask package
cargo xtask product-conformance
cargo xtask release-contract
docker compose -f demos/open-production-reference/compose/compose.yaml up
```

Add CI jobs for the container, local composition, Kubernetes static policy, and
installed SDK end-to-end tests. The authoritative implementation job must run
the complete reference proof whenever runtime, stores, custody, operations,
bindings, profiles, or deployment assets change.

## 14. Exit gate

- Three nodes safely share one PostgreSQL lifecycle store.
- A node can die mid-work and another can resume without duplicating an effect.
- KMS or PKCS#11 signs without exporting the private key.
- Every qualified profile executes through its explicit gateway and reconciler.
- Installed TypeScript and Python packages complete the same workflows.
- Dashboards and runbooks explain denial, indeterminate, recoverable, and
  provider-unknown outcomes without leaking sensitive data.
- Backup/restore and same-candidate rolling restart pass.
- The container has provenance, SBOM, pinned inputs, and a reviewed hardened
  runtime configuration.
- A new developer reaches a protected sandbox effect in fifteen minutes.
