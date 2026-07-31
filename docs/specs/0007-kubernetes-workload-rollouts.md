# 0007: Auths for Kubernetes workload rollouts

Status: Implemented
Target: MVP plus public end-to-end demonstration  
Profile: `auths.kubernetes.workload-rollout/1`  
Product package: `product/integrations/auths-kubernetes`  
Demo: `demos/kubernetes-rollout`

## 1. Decision

Build one vertical Kubernetes product package that lets an untrusted agent propose a narrowly bounded `Deployment` rollout without possessing Kubernetes credentials.

The first profile authorizes exactly one server-side-apply request against one existing `apps/v1 Deployment`. It may change:

- one container image to an immutable digest;
- replicas within an authorized range; and
- explicitly allowlisted rollout annotations.

The protected executor claims the action, obtains a short-lived or workload-bound Kubernetes credential, submits the exact request, and records the persisted and converged results.

This is not a general `kubectl` gateway and not a manifest approval product.

## 2. Product claim

Ordinary Kubernetes RBAC can say:

> this ServiceAccount may patch Deployments in this namespace.

This Auths profile can say:

> this executor may use its protected Kubernetes credential once to apply these exact canonical patch bytes, to this Deployment UID at this observed state, under this verifier configuration, before this deadline.

The proposing agent receives no kubeconfig, client certificate, ServiceAccount token, cloud credential, or reusable permission.

## 3. Goals

The MVP must:

1. model a workload rollout as a canonical Auths action;
2. bind the authorization to cluster, namespace, object identity, current state, patch, field manager, and dry-run evidence;
3. expose both `required_configuration` and `executed_configuration`;
4. reject any mismatch between those configurations;
5. claim the action before acquiring mutation credentials;
6. execute at most once and reconcile ambiguous outcomes without blind replay;
7. distinguish authorization, API acceptance, persisted state, and rollout convergence;
8. produce portable decision and execution receipts;
9. keep all Kubernetes-specific behavior in one vertical product package; and
10. provide a real, understandable end-to-end demo.

## 4. Non-goals

The MVP does not:

- accept arbitrary Kubernetes resources;
- create Deployments;
- mutate Secrets or ConfigMaps;
- alter RBAC, ServiceAccounts, namespaces, CRDs, admission configuration, or network policy;
- run `kubectl exec`, attach, port-forward, or arbitrary subresources;
- permit mutable image tags;
- change commands, arguments, environment variables, volumes, probes, ports, service accounts, or security context;
- support `force` ownership takeover;
- grant the agent a Kubernetes credential;
- guarantee that Kubernetes controllers will converge successfully; or
- treat dry-run as proof of the eventual persisted state.

## 5. Trust model

### Untrusted

- the agent and its prompt context;
- manifest text supplied by the agent;
- browser inputs;
- network intermediaries;
- human-readable summaries;
- mutable image tags;
- status text returned without cryptographic or API evidence.

### Trusted for the MVP

- Auths core verification and canonicalization;
- the product package’s Kubernetes profile implementation;
- the claim and receipt stores;
- the protected executor process;
- the configured Kubernetes API server identity and trust roots;
- the workload identity or credential broker used by the executor;
- the verifier configuration selected by the relying party; and
- the dedicated demonstration cluster’s control plane.

### Protected secret boundary

Only the native executor may access credentials capable of mutation. Read-only evidence acquisition should use a separate identity where practical. The agent-facing and browser-facing processes must not inherit the mutation credential through environment variables, mounted files, logs, error objects, or subprocess state.

## 6. Vertical package boundary

All Kubernetes-specific vocabulary and behavior belongs under:

```text
product/integrations/auths-kubernetes/
  Cargo.toml
  src/
    lib.rs
    action.rs
    canonical.rs
    profile.rs
    evidence.rs
    dry_run.rs
    executor.rs
    observe.rs
    receipts.rs
    errors.rs
  tests/
    fixtures/
    conformance/
```

The package may depend inward on core proof, policy, store, receipt, and verification crates. Core crates must not depend on Kubernetes types, API clients, resource schemas, or rollout concepts.

The demo belongs under `demos/kubernetes-rollout` and consumes the vertical package. Demo shortcuts must not leak into the product package.

## 7. Action model

The canonical action type is:

```text
KubernetesWorkloadRolloutV1 {
  profile
  cluster_audience
  api_server_identity
  namespace_name
  namespace_uid
  resource_api_version
  resource_kind
  resource_name
  resource_uid
  expected_resource_version
  current_spec_digest
  patch_content_type
  patch_bytes
  patch_digest
  field_manager
  force_conflicts
  field_validation
  dry_run_response_digest
  dry_run_observed_at
  allowed_change_projection
  required_configuration
  expires_at
  nonce
}
```

Normative requirements:

- `profile` must equal `auths.kubernetes.workload-rollout/1`.
- `resource_api_version` must equal `apps/v1`.
- `resource_kind` must equal `Deployment`.
- `patch_content_type` must be the server-side-apply media type.
- `field_manager` must equal the configured Auths manager name.
- `force_conflicts` must be false.
- `field_validation` must be `Strict`.
- names must be DNS-normalized exactly as Kubernetes represents them.
- `patch_bytes` must be deterministic canonical JSON, not YAML.
- `patch_digest` must commit to those exact bytes.
- the action must bind the full required verifier configuration, not only a named policy.

The executor must derive the outbound request only from the verified action. It must not merge browser state, agent state, environment defaults, or a newly rendered template after verification.

## 8. Allowed change projection

The verifier computes a semantic projection from the current object and dry-run response:

```text
AllowedChangeProjectionV1 {
  container_name
  previous_image_digest
  requested_image_digest
  previous_replicas
  requested_replicas
  annotation_changes
  unchanged_fields_digest
}
```

Rules:

- the image reference must include a digest and must not rely on a tag;
- exactly one existing container may change;
- replicas must be within configured lower and upper bounds;
- annotation keys must be in the configuration allowlist;
- deletion of an unspecified field is a change and is denied;
- any change outside the projection is denied;
- defaulted fields are compared using the dry-run object, not guessed client-side; and
- the unchanged-fields digest commits to the security-relevant remainder of the Deployment pod template and strategy.

## 9. Required and executed configuration

The relying party supplies `required_configuration`. The verifier records what it actually used as `executed_configuration`.

Both must include at least:

```text
KubernetesVerifierConfigurationV1 {
  profile
  canonicalization_version
  cluster_audience
  allowed_namespaces
  allowed_deployments
  allowed_container_names
  minimum_replicas
  maximum_replicas
  allowed_annotation_keys
  maximum_evidence_age_seconds
  maximum_authorization_lifetime_seconds
  field_manager
  permitted_api_versions
  permitted_resource_kinds
  admission_mode
  receipt_schema_version
}
```

Authorization fails with `verifier-configuration-mismatch` unless the canonical configurations are byte-for-byte equal.

A unit test must construct a valid authorization under one configuration and execute verification under a configuration differing only in `maximum_replicas`. The result must contain both configurations and deny before claim or credential acquisition. This test exists to make configuration confusion visible to maintainers.

## 10. Evidence

Fresh evidence must include:

- authenticated API server audience and certificate identity;
- namespace name and UID;
- Deployment name, UID, resource version, generation, and deletion timestamp;
- canonical current specification digest;
- relevant `managedFields` ownership;
- current rollout status;
- dry-run request parameters;
- canonical dry-run response digest;
- dry-run warnings;
- observation time; and
- evidence-source configuration.

Evidence is invalid when:

- it exceeds the configured age;
- the namespace or object is terminating;
- the object UID or resource version differs;
- the API server identity or cluster audience differs;
- dry-run reports a conflict or warning forbidden by policy;
- a managed field would require force takeover; or
- the current object contains a feature the MVP profile cannot safely project.

## 11. Dry-run and admission semantics

The executor uses server-side dry-run with the same:

- URL and subresource;
- content type;
- canonical request body;
- field manager;
- `force=false`; and
- strict field validation

that would be used for execution.

Dry-run evidence is an authorization input, not an execution guarantee. Admission webhooks, policy, and cluster state can change between dry-run and persistence, and controllers can mutate or react after persistence.

The profile supports two admission modes:

1. `deterministic-demo`: the target namespace is governed by a pinned, tested admission configuration with no unapproved mutating webhook applicable to the Deployment.
2. `observed-production`: applicable admission configuration is inventoried and committed as evidence, and persisted-state divergence is explicitly handled as an indeterminate execution.

The MVP demo must use `deterministic-demo`. Production support must not be claimed from demo-mode evidence.

## 12. Authorization pipeline

The verifier must perform, in order:

1. decode with hard size and depth limits;
2. enforce the profile and schema version;
3. canonicalize the action and required configuration;
4. verify signatures and proof chain;
5. verify audience, expiry, and nonce;
6. compare required and executed configuration;
7. validate evidence freshness and source;
8. verify cluster, namespace, and resource identity;
9. compare the current-state and resource-version commitments;
10. recompute and compare patch and dry-run digests;
11. compute the semantic change projection;
12. enforce every profile restriction; and
13. emit a decision without acquiring mutation credentials.

Malformed input and authorization denial are distinct outcomes. A denial must identify a stable stage and code without leaking credentials or sensitive cluster data.

## 13. Claim and execution order

The native path is:

```text
verify
  -> claim exact action digest
  -> acquire protected credential
  -> recheck cheap freshness preconditions
  -> submit exact server-side-apply request
  -> read persisted object
  -> observe rollout
  -> write receipts
```

It must never be:

```text
acquire credential -> inspect or modify unverified agent input
```

Only the claimant that transitions an action from `unclaimed` to `claimed` may execute it. Other callers receive the durable replay outcome.

## 14. Kubernetes credential

Preferred production mechanisms are:

- workload identity bound to the executor; or
- a short-lived ServiceAccount token obtained through TokenRequest.

The executor’s Kubernetes identity must have the smallest practical permissions:

- `get`, `patch`, and `watch` on the specific Deployment scope;
- `get`, `list`, and `watch` only for the ReplicaSets and Pods needed to observe that rollout; and
- no Secret read, RBAC write, broad wildcard, impersonation, token creation for other ServiceAccounts, or cluster-admin access.

RBAC remains defense in depth. It is not the exact-action policy.

Credentials must never appear in receipts, browser responses, command lines, panic messages, traces, or fixture snapshots.

## 15. Execution request

The executor submits an HTTP `PATCH` directly through a pinned Kubernetes client library. It must not shell out to `kubectl`.

The request must:

- target the committed cluster, namespace, kind, and name;
- carry the committed canonical bytes;
- use the committed field manager;
- set `force=false`;
- request strict field validation;
- use an API timeout; and
- capture Kubernetes audit correlation identifiers when available.

The executor must not regenerate the patch from `allowed_change_projection`.

## 16. Postconditions

The following states are separate:

1. `authorized`: Auths permitted the action.
2. `api_accepted`: Kubernetes returned a successful mutation response.
3. `persisted_verified`: a subsequent authenticated read matches the authorized security-relevant projection.
4. `rollout_converged`: the Deployment controller observed the new generation and the required availability condition was met.

Persisted verification checks:

- same Deployment UID;
- returned resource version is newer;
- intended image digest, replica count, and annotations match;
- protected fields remain committed to the authorized unchanged-fields digest; and
- no deletion timestamp appeared.

Rollout convergence checks:

- `observedGeneration` reaches the persisted generation;
- updated and available replica counts reach the expected values;
- progress deadline is not exceeded;
- the active ReplicaSet uses the authorized image digest; and
- the public demo workload reports the expected build identity.

Authorization success must never be rewritten as rollout success.

## 17. Ambiguous outcomes and reconciliation

Timeout or connection loss after request submission is not proof that nothing happened.

The executor must:

1. mark the claim `outcome_unknown`;
2. read the named Deployment by UID;
3. compare its persisted projection with the authorized action;
4. inspect resource version, generation, managed fields, and rollout annotations;
5. record `reconciled_applied`, `reconciled_not_applied`, or `indeterminate`; and
6. never automatically re-submit while the outcome is ambiguous.

If the object was deleted and recreated with the same name, UID mismatch prevents reconciliation as the authorized object.

## 18. Receipts

The demo and package produce linked receipts:

### Decision receipt

Contains action digest, proof identity, required and executed configuration, evidence digest and age, verdict, stable code, and final decision stage.

### Claim receipt

Contains action digest, claim ID, state transition, claimant audience, and replay outcome. It contains no credential details.

### Kubernetes API receipt

Contains cluster audience commitment, object identity, request digest, response code, returned UID/resource version/generation, and correlation identifiers.

### Rollout observation receipt

Contains persisted projection digest, convergence state, observed generation, replica counts, workload build identity, timestamps, and any bounded failure reason.

Receipts may expose names from the synthetic demo. Production defaults should support keyed commitments or redaction for private cluster identifiers.

## 19. Stable denial and failure codes

At minimum:

- `malformed-action`
- `unsupported-profile`
- `proof-invalid`
- `action-body-mismatch`
- `verifier-configuration-mismatch`
- `evidence-stale`
- `cluster-audience-mismatch`
- `namespace-identity-mismatch`
- `resource-identity-mismatch`
- `resource-version-mismatch`
- `dry-run-mismatch`
- `managed-field-conflict`
- `mutable-image-reference`
- `change-outside-profile`
- `replica-bound-exceeded`
- `already-claimed`
- `credential-unavailable`
- `kubernetes-request-failed`
- `persisted-state-mismatch`
- `rollout-failed`
- `execution-outcome-unknown`

## 20. Public demo

### Scenario

A synthetic agent proposes updating a small public “color service” from one immutable image digest to another. The visitor can open the current service endpoint and see the active build identity.

The exact-path scenario:

1. the agent proposes the rollout without a kubeconfig;
2. the UI shows the exact permitted change;
3. Auths verifies the proof and fresh cluster evidence;
4. the protected service claims and applies it;
5. the UI streams API acceptance and rollout convergence; and
6. the application visibly changes to the authorized build.

### Experiments

The visitor can select:

- exact rollout;
- image changed after authorization;
- mutable tag substituted for digest;
- replicas exceed the grant;
- forbidden security-context field added;
- target namespace changed;
- resource version made stale;
- required verifier configuration changed; or
- replay the already-executed action.

Every experiment must use the real canonicalization and verifier path. Negative cases may use deterministic fixtures, but the UI must label fixture evidence and live-cluster evidence accurately.

### Layout

The control and result panels are side by side on desktop and adjacent in one vertical flow on mobile. A visitor must not scroll to discover the result of a control they just changed.

The primary view contains:

- the experiment selector;
- the exact before-and-after workload change;
- current authorization verdict and stable code;
- browser/native parity;
- current claim and execution state;
- Kubernetes API and rollout state; and
- a link to inspect receipts.

Copy must explain concrete events. Avoid slogans such as “verification repeats; execution does not.”

### Frontend delivery contract

The frontend is a required part of the implementation, not optional follow-up work. A backend-only implementation, API explorer, static mockup, or page that never reaches the native executor does not satisfy this specification.

Follow the established GitHub and Radicle demo interaction model:

- one primary workbench places selectable experiments beside the current verdict and execution result;
- selecting an experiment immediately updates the exact proposed action and predicted decision;
- executing it calls the deployed native backend and renders its returned stable code, configuration commitments, claim state, provider effect, and receipt links;
- loading, unavailable, denied, indeterminate, authorized, executed, and replay states are visibly distinct;
- the successful path performs the real sandbox rollout, while every denied path proves that no Kubernetes mutation occurred; and
- desktop and mobile layouts keep the control that caused a result adjacent to that result.

### Receipt interface contract

Receipts must be understandable without navigating away from the experiment
that produced them:

- after every attempted execution, the primary workbench exposes the complete,
  pretty-printed machine-readable receipt inline beneath the live result;
- the inline JSON is loaded from the real receipt API and is not reconstructed
  from frontend state;
- the workbench’s receipt link opens a dedicated
  `/receipts/{session-or-workflow-id}` page, not the raw JSON API response;
- the dedicated page summarizes the decision, stable code, action and evidence
  commitments, required/executed configuration relationship, credential or
  provider boundary, and observed effect before offering the complete raw JSON;
- missing, expired, malformed, or unverifiable receipt identifiers render an
  explicit fail-closed receipt page; and
- browser tests cover both the inline viewer and the dedicated receipt route.

Browser-level end-to-end tests must start from the rendered page and exercise readiness, exact execution, at least one material denial, replay, and receipt inspection through the same public API routes used in production. Static DOM assertions and backend-only integration tests are necessary but insufficient.

Completion requires a publicly reachable frontend URL and a publicly reachable native API deployment. Opening `index.html` through `file://`, serving only on localhost, committing Vercel/Fly configuration without deploying it, or deploying a frontend whose API is unavailable does not satisfy this specification. Before handoff, test the public Vercel URL against the public Fly deployment and record the tested URLs and release identifiers.

### Design language

The demo must use the same design system and visual language as `auths-proof-site`: typography, spacing, color tokens, borders, status treatment, interaction density, and voice. It may reuse shared design assets, but the demo remains independently deployable.

### Deployment

The target topology is:

- static or edge frontend on Vercel;
- native Rust verifier/executor on Fly.io;
- a dedicated, non-production Kubernetes or k3s cluster with a single demo namespace;
- an isolated public color-service endpoint; and
- durable claim and receipt storage.

Deployment configuration must document regions, CORS origins, API base URLs, health checks, secrets, rollback, and fixture reset. No browser bundle or Vercel environment variable may contain a Kubernetes credential.

The demo must expose a stable public URL and `/healthz`, `/readyz`, and build-information endpoints.

## 21. API surface

Suggested endpoints:

```text
GET  /api/v1/scenarios
POST /api/v1/authorize
POST /api/v1/execute
GET  /api/v1/executions/{id}
GET  /api/v1/receipts/{id}
GET  /api/v1/workload
GET  /healthz
GET  /readyz
```

`POST /execute` accepts the signed Auths envelope and scenario identifier. It does not accept an arbitrary Kubernetes URL, token, namespace, object kind, or free-form command.

## 22. Testing

### Unit

- canonical JSON and digest stability;
- required/executed configuration mismatch with both values in the result;
- image digest parsing;
- semantic change projection;
- replica bounds;
- unchanged-field commitment;
- evidence expiry;
- stable error mapping;
- hard input limits, including a minimal regression seed for every parser bug fixed.

### Conformance

- golden action, evidence, configuration, and receipt vectors;
- browser WASM/native parity;
- altered patch byte;
- altered object UID, namespace UID, resource version, or cluster audience;
- dry-run/defaulting fixtures;
- managed-field conflict;
- unknown fields and duplicate JSON keys;
- replay and concurrent claim races.

### Integration

- real API server server-side dry-run;
- successful apply and rollout;
- RBAC denial;
- stale object between authorization and execution;
- timeout before send, during response, and after server acceptance;
- deletion and recreation with the same name;
- controller rollout failure;
- admission mutation divergence; and
- reconciliation after process restart.

### Deployment

- Vercel frontend reaches Fly API from every configured origin;
- Fly health and readiness checks;
- browser can select and run every scenario;
- no secrets in static assets, source maps, logs, receipts, or error responses;
- live endpoint reflects the authorized build digest; and
- a clean environment can be deployed from documented commands.

## 23. CI and repository enforcement

CI must enforce:

- the vertical package may depend on core, but core may not depend on it;
- the demo may depend on the vertical package, but neither may depend on another demo;
- no Kubernetes credential-shaped fixture is committed;
- all Rust code uses the workspace edition, resolver, MSRV, lint policy, and dependency policy;
- WASM-safe profile logic remains separated from native credential and network code;
- feature unification cannot accidentally include native Kubernetes clients in browser artifacts;
- fixture manifests pass schema and policy validation; and
- live-provider tests are explicitly separated from deterministic conformance tests.

## 24. Acceptance criteria

The specification is implemented when:

1. an agent with no Kubernetes credential can propose the supported rollout;
2. a valid proof executes the exact committed patch once;
3. each material mutation produces a stable denial;
4. required and executed configuration are both returned and enforced equal;
5. credentials are acquired only after a successful claim;
6. concurrent submissions yield one execution;
7. ambiguous network outcomes are reconciled without blind reapply;
8. API acceptance and rollout convergence are represented separately;
9. receipts commit to the exact request and observations;
10. browser and native decisions match;
11. package-boundary and conformance checks pass; and
12. a public visitor can operate the deployed demo and inspect the live result without credentials;
13. the deployed frontend completes exact, denial, replay, and receipt flows against the deployed native backend; and
14. browser-level end-to-end tests fail if frontend/backend wiring, CORS, readiness, interaction, or result rendering breaks.

## 25. Milestone 5 shared-policy and lifecycle cutover

The implemented profile keeps its Kubernetes action, evidence, decision,
verified command, credential, gateway, reconciliation, and receipt semantics.
Its production orchestration uses the shared bounded-policy and lifecycle
contracts from specifications 0025 and 0026.

This is a prelaunch source cutover. There is one production execution path.
The old claim-file schema is obsolete and must be rejected; local and CI
environments start with empty shared lifecycle state. No legacy reader,
state converter, dual write, compatibility switch, or runtime rollback path
is permitted.

### 25.1 Closed semantic identities

The cutover fixes these identities:

| Meaning | Identity |
| --- | --- |
| Profile | `auths.kubernetes.workload-rollout/1` |
| Policy type | `auths.kubernetes.rollout-policy/1` |
| Evaluator | `auths.kubernetes.workload-rollout.evaluate/1` |
| Evaluator implementation | `auths-kubernetes/shared-lifecycle-production/1` |
| Canonicalization | `rfc8785-sha256-v1` |
| Configuration | `auths.kubernetes.verifier-configuration/1` |
| Evidence | `auths.kubernetes.rollout-evidence/1` |
| Evidence source | `kubernetes-api-deployment-read-dry-run/1` |
| State snapshot | `auths.kubernetes.rollout-state-snapshot/1` |
| Reservation intent | `auths.kubernetes.rollout-exclusive-intent/1` |
| Reservation algebra | `auths.kubernetes.deployment-exclusive/1` |
| Verified-command obligation | `auths.kubernetes.verified-rollout-command/1` |
| Provider contract | `auths.kubernetes.server-side-apply/1` |

Changing any decision boundary, exact-action meaning, evidence freshness rule,
reservation scope, provider retry rule, or receipt claim requires a new
semantic identity.

### 25.2 Pure projection

An authorized domain decision projects to the shared policy contract without
erasing Kubernetes meaning:

- the policy commitment is the canonical verifier-configuration commitment;
- the state snapshot commits the exact Kubernetes evidence used by the
  evaluator;
- one exclusive reservation intent binds cluster audience, namespace name,
  and Deployment name;
- the exact namespace UID, Deployment UID, resource version, patch, and
  dry-run result remain bound by the action and evidence commitments; and
- one command-construction obligation binds the exact canonical action bytes.

The original `evaluate` function remains a test-only semantic oracle. Frozen
inputs must produce identical decision class, stable code, stage, action and
evidence commitments, reservation scope, verified command, and domain receipt
bytes through the production projection.

### 25.3 Durable execution

The production order is:

```text
domain decision
  -> Auths proof verification
  -> durable decision record
  -> atomic exclusive reservation
  -> durable exact execution intent
  -> durable credential authorization
  -> acquire Kubernetes credential
  -> durable provider-attempt and call-entry records
  -> submit the exact verified server-side-apply request
  -> commit, release, or retain outcome-unknown
  -> reconcile from fresh Kubernetes observation when required
```

The exclusive reservation prevents concurrent live workflows from mutating
the same configured Deployment scope. A successful terminal rollout does not
permanently monopolize the Deployment: later independently authorized
workflows may reserve it after the earlier lifecycle is terminal.

The provider retry class is `observe-before-retry`. A timeout after possible
delivery transitions to `outcome_unknown`; capacity remains held and the
request is not blindly resubmitted. Fresh reconciliation may conclude only
exact effect or definite non-effect.

Credential acquisition requires the sealed authorization derived from the
newly durable lifecycle transition. The provider gateway requires the sealed
provider-call authorization derived after attempt and call-entry persistence.
Neither token can be constructed from untrusted request data.

### 25.4 Receipt and state compatibility

The existing Kubernetes decision, claim, API, and rollout receipt schemas
remain the domain-authoritative public receipts. Shared lifecycle receipts add
commitment and ordering evidence without changing those domain receipt bytes.

The new persisted state is canonical shared lifecycle state. Startup must fail
closed on malformed, non-canonical, oversized, unsupported, or obsolete claim
state. The deployment procedure deletes disposable prelaunch
`claims.json` state before starting the cut-over revision.

### 25.5 Cutover acceptance

The source cutover is complete only when:

1. exact differential tests compare the reference evaluator with the
   production projection;
2. concurrent workflows for one Deployment have exactly one live
   reservation winner;
3. configuration mismatch and denial occur before lifecycle state,
   credential acquisition, and provider I/O;
4. credentials and provider calls are possible only through their sealed
   durable-stage authorizations;
5. replay cannot create a second provider attempt;
6. definite pre-effect failure releases the reservation;
7. ambiguous delivery retains the reservation until fresh reconciliation;
8. crash-persistent state reopens canonically and rejects the obsolete claim
   schema;
9. public domain receipt bytes remain unchanged for frozen scenarios;
10. the demo and live tests use the shared production path; and
11. the old production claim store and duplicate orchestration are removed.

## 26. Deferred work

- StatefulSets, DaemonSets, Jobs, and custom resources;
- workload creation and deletion;
- multi-object rollout transactions;
- policy profiles for Helm and Kustomize;
- signed container and SBOM verification;
- generalized admission-webhook inventory proofs;
- multi-cluster federation;
- production SLOs and enterprise private-cluster connectivity; and
- reusable Kubernetes profile tooling extracted only after a second Kubernetes action proves the abstraction.
